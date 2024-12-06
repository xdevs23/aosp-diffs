```diff
diff --git a/app/AndroidManifest.xml b/app/AndroidManifest.xml
index 0acb74bb..50f4d47b 100644
--- a/app/AndroidManifest.xml
+++ b/app/AndroidManifest.xml
@@ -75,6 +75,8 @@
     <uses-permission android:name="android.car.permission.CONTROL_CAR_CLIMATE"/>
     <!-- Permission to read navigation state -->
     <uses-permission android:name="android.car.permission.CAR_MONITOR_CLUSTER_NAVIGATION_STATE"/>
+    <!-- Permission to read notifications -->
+    <uses-permission android:name="android.permission.ACCESS_NOTIFICATIONS"/>
 
     <!-- To connect to media browser services in other apps, media browser clients
     that target Android 11 need to add the following in their manifest -->
@@ -102,6 +104,7 @@
             <intent-filter>
                 <action android:name="android.intent.action.MAIN"/>
                 <category android:name="android.intent.category.HOME"/>
+                <category android:name="android.intent.category.SECONDARY_HOME" />
                 <category android:name="android.intent.category.DEFAULT"/>
                 <category android:name="android.intent.category.LAUNCHER_APP"/>
             </intent-filter>
diff --git a/app/OWNERS b/app/OWNERS
index 9b6c26a6..820a6050 100644
--- a/app/OWNERS
+++ b/app/OWNERS
@@ -7,7 +7,7 @@ nehah@google.com
 babakbo@google.com
 arnaudberry@google.com
 stenning@google.com
-ycheo@google.com  # for TaskView only
+gauravbhola@google.com  # for TaskView only
 
 # Recents
 per-file src/com/android/car/carlauncher/recents/* = jainams@google.com
diff --git a/app/res/color/media_card_panel_button_background_tint_state_list.xml b/app/res/color/media_card_panel_button_background_tint_state_list.xml
index 3cde202d..e75e3bbd 100644
--- a/app/res/color/media_card_panel_button_background_tint_state_list.xml
+++ b/app/res/color/media_card_panel_button_background_tint_state_list.xml
@@ -15,7 +15,7 @@
   -->
 
 <selector xmlns:android="http://schemas.android.com/apk/res/android">
-    <item android:color="@color/car_surface"
+    <item android:color="@color/car_surface_container_highest"
         android:state_selected="false"/>
     <item android:color="@color/car_on_surface"
         android:state_selected="true"/>
diff --git a/app/res/color/car_on_surface_40.xml b/app/res/drawable/button_ripple.xml
similarity index 68%
rename from app/res/color/car_on_surface_40.xml
rename to app/res/drawable/button_ripple.xml
index 96e1682a..8950091e 100644
--- a/app/res/color/car_on_surface_40.xml
+++ b/app/res/drawable/button_ripple.xml
@@ -14,6 +14,11 @@
   ~ limitations under the License.
   -->
 
-<selector xmlns:android="http://schemas.android.com/apk/res/android">
-    <item android:alpha=".4" android:color="@color/car_on_surface" />
-</selector>
+<ripple xmlns:android="http://schemas.android.com/apk/res/android"
+    android:color="@color/car_ui_ripple_color">
+    <item android:id="@android:id/mask">
+        <shape android:shape="oval">
+            <solid android:color="@color/car_ui_ripple_color"/>
+        </shape>
+    </item>
+</ripple>
\ No newline at end of file
diff --git a/app/res/drawable/dark_circle_button_background.xml b/app/res/drawable/circle_button_background.xml
similarity index 67%
rename from app/res/drawable/dark_circle_button_background.xml
rename to app/res/drawable/circle_button_background.xml
index 58ef50ce..64226821 100644
--- a/app/res/drawable/dark_circle_button_background.xml
+++ b/app/res/drawable/circle_button_background.xml
@@ -14,7 +14,12 @@
   ~ limitations under the License.
   -->
 
-<shape xmlns:android="http://schemas.android.com/apk/res/android"
-    android:shape="oval">
-    <solid android:color="@color/car_surface"/>
-</shape>
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
+    <item>
+        <shape
+            android:shape="oval">
+            <solid android:color="@color/car_surface_container_highest"/>
+        </shape>
+    </item>
+    <item android:drawable="@drawable/button_ripple"/>
+</layer-list>
diff --git a/app/res/drawable/ic_history.xml b/app/res/drawable/ic_history.xml
index 0c8431a1..9f16dd8a 100644
--- a/app/res/drawable/ic_history.xml
+++ b/app/res/drawable/ic_history.xml
@@ -20,6 +20,6 @@
     android:viewportWidth="960"
     android:viewportHeight="960">
     <path
-        android:fillColor="@android:color/white"
-        android:pathData="M478,840Q332.67,840 229.17,739.17Q125.67,638.33 120.67,492.67L188,492.67Q192.67,610.67 276.17,692Q359.67,773.33 478,773.33Q601.67,773.33 687.5,686.83Q773.33,600.33 773.33,476.67Q773.33,355 686.83,270.83Q600.33,186.67 478,186.67Q409.67,186.67 350,218Q290.33,249.33 247.33,302L354,302L354,368.67L134.67,368.67L134.67,150L201.33,150L201.33,252Q253,190 325.17,155Q397.33,120 478,120Q553,120 618.83,148.17Q684.67,176.33 733.83,224.83Q783,273.33 811.5,338.5Q840,403.67 840,478.67Q840,553.67 811.5,619.5Q783,685.33 733.83,734.17Q684.67,783 618.83,811.5Q553,840 478,840ZM600.67,644.67L447.33,492.67L447.33,278L514,278L514,465.33L648,597.33L600.67,644.67Z"/>
+        android:fillColor="@color/car_on_surface"
+        android:pathData="M146.67,880Q119.67,880 99.83,860.17Q80,840.33 80,813.33L80,386.67Q80,359.67 99.83,339.83Q119.67,320 146.67,320L813.33,320Q840.33,320 860.17,339.83Q880,359.67 880,386.67L880,813.33Q880,840.33 860.17,860.17Q840.33,880 813.33,880L146.67,880ZM146.67,813.33L813.33,813.33Q813.33,813.33 813.33,813.33Q813.33,813.33 813.33,813.33L813.33,386.67Q813.33,386.67 813.33,386.67Q813.33,386.67 813.33,386.67L146.67,386.67Q146.67,386.67 146.67,386.67Q146.67,386.67 146.67,386.67L146.67,813.33Q146.67,813.33 146.67,813.33Q146.67,813.33 146.67,813.33ZM404.67,752.67L632,600L404.67,448L404.67,752.67ZM152.67,266.67L152.67,200L807.33,200L807.33,266.67L152.67,266.67ZM280,146.67L280,80L680,80L680,146.67L280,146.67ZM146.67,813.33Q146.67,813.33 146.67,813.33Q146.67,813.33 146.67,813.33L146.67,386.67Q146.67,386.67 146.67,386.67Q146.67,386.67 146.67,386.67L146.67,386.67Q146.67,386.67 146.67,386.67Q146.67,386.67 146.67,386.67L146.67,813.33Q146.67,813.33 146.67,813.33Q146.67,813.33 146.67,813.33Z"/>
 </vector>
diff --git a/app/res/drawable/ic_overflow_horizontal.xml b/app/res/drawable/ic_overflow_horizontal.xml
index 8c76a6a0..9cc19e17 100644
--- a/app/res/drawable/ic_overflow_horizontal.xml
+++ b/app/res/drawable/ic_overflow_horizontal.xml
@@ -20,6 +20,6 @@
     android:viewportWidth="960"
     android:viewportHeight="960">
     <path
-        android:fillColor="@android:color/white"
+        android:fillColor="@color/car_on_surface"
         android:pathData="M218.57,538.67Q194.33,538.67 177.17,521.41Q160,504.14 160,479.91Q160,455.67 177.26,438.5Q194.52,421.33 218.76,421.33Q243,421.33 260.17,438.59Q277.33,455.86 277.33,480.09Q277.33,504.33 260.07,521.5Q242.81,538.67 218.57,538.67ZM479.91,538.67Q455.67,538.67 438.5,521.41Q421.33,504.14 421.33,479.91Q421.33,455.67 438.6,438.5Q455.86,421.33 480.09,421.33Q504.33,421.33 521.5,438.59Q538.67,455.86 538.67,480.09Q538.67,504.33 521.41,521.5Q504.14,538.67 479.91,538.67ZM741.24,538.67Q717,538.67 699.83,521.41Q682.67,504.14 682.67,479.91Q682.67,455.67 699.93,438.5Q717.19,421.33 741.43,421.33Q765.67,421.33 782.83,438.59Q800,455.86 800,480.09Q800,504.33 782.74,521.5Q765.48,538.67 741.24,538.67Z"/>
 </vector>
diff --git a/app/res/drawable/ic_play_pause_selector.xml b/app/res/drawable/ic_play_pause_selector.xml
index 9ea36791..142869ab 100644
--- a/app/res/drawable/ic_play_pause_selector.xml
+++ b/app/res/drawable/ic_play_pause_selector.xml
@@ -15,7 +15,7 @@
   -->
 
 <selector xmlns:android="http://schemas.android.com/apk/res/android">
-    <item android:state_selected="true">
+    <item android:state_selected="true" android:state_enabled="true">
         <vector
             android:width="40dp"
             android:height="40dp"
@@ -26,7 +26,7 @@
                 android:pathData="M556.67,760L556.67,200L726.67,200L726.67,760L556.67,760ZM233.33,760L233.33,200L403.33,200L403.33,760L233.33,760Z"/>
         </vector>
     </item>
-    <item android:state_selected="false">
+    <item android:state_selected="false" android:state_enabled="true">
         <vector
             android:width="40dp"
             android:height="40dp"
@@ -37,4 +37,15 @@
                 android:pathData="M320,758L320,198L760,478L320,758Z"/>
         </vector>
     </item>
+    <item android:state_enabled="false">
+        <vector
+            android:width="40dp"
+            android:height="40dp"
+            android:viewportWidth="960"
+            android:viewportHeight="960">
+            <path
+                android:fillColor="@color/car_surface"
+                android:pathData="M642.67,557.33L328,247.33L328,198L768,478L642.67,557.33ZM792,895.33L528,630.67L328,758L328,430.67L65.33,167.33L112,120.67L840,848.67L792,895.33Z"/>
+        </vector>
+    </item>
 </selector>
diff --git a/app/res/drawable/ic_queue.xml b/app/res/drawable/ic_queue.xml
index d60222ff..bd7b6614 100644
--- a/app/res/drawable/ic_queue.xml
+++ b/app/res/drawable/ic_queue.xml
@@ -20,6 +20,6 @@
     android:viewportWidth="960"
     android:viewportHeight="960">
     <path
-        android:fillColor="@android:color/white"
+        android:fillColor="@color/car_on_surface"
         android:pathData="M641.96,800Q593.33,800 559.33,765.96Q525.33,731.92 525.33,683.29Q525.33,634.67 558.78,600.67Q592.22,566.67 640,566.67Q654.31,566.67 667.32,569.17Q680.33,571.67 692,578L692,240L880,240L880,314L758.67,314L758.67,684Q758.67,732.33 724.63,766.17Q690.59,800 641.96,800ZM120,640L120,573.33L430.67,573.33L430.67,640L120,640ZM120,473.33L120,406.67L595.33,406.67L595.33,473.33L120,473.33ZM120,306.67L120,240L595.33,240L595.33,306.67L120,306.67Z"/>
 </vector>
diff --git a/app/res/drawable/media_card_panel_handlebar.xml b/app/res/drawable/media_card_panel_handlebar.xml
index 19e39d6b..e98db817 100644
--- a/app/res/drawable/media_card_panel_handlebar.xml
+++ b/app/res/drawable/media_card_panel_handlebar.xml
@@ -20,7 +20,7 @@
     <item>
         <shape android:shape="rectangle">
             <corners android:radius="16dp"/>
-            <solid android:color="@color/car_on_surface_40"/>
+            <solid android:color="@color/car_on_surface_variant"/>
         </shape>
     </item>
 </ripple>
diff --git a/app/res/drawable/media_card_seekbar_thumb.xml b/app/res/drawable/media_card_seekbar_thumb.xml
index 68b8edb8..b9dee233 100644
--- a/app/res/drawable/media_card_seekbar_thumb.xml
+++ b/app/res/drawable/media_card_seekbar_thumb.xml
@@ -14,30 +14,52 @@
   ~ limitations under the License.
   -->
 
-<vector
-    xmlns:android="http://schemas.android.com/apk/res/android"
-    android:width="12dp"
-    android:height="32dp"
-    android:viewportWidth="12"
-    android:viewportHeight="32"
-    >
-    <group>
-        <clip-path
-            android:pathData="M6 4C7.10457 4 8 4.89543 8 6V26C8 27.1046 7.10457 28 6 28C4.89543 28 4 27.1046 4 26V6C4 4.89543 4.89543 4 6 4Z"
-            />
-        <path
-            android:pathData="M4 4V28H8V4"
-            android:fillColor="@color/media_card_seekbar_thumb_color"
-            />
-    </group>
-    <group>
-        <clip-path
-            android:pathData="M0 0V32H12V0M6 4C7.10457 4 8 4.89543 8 6V26C8 27.1046 7.10457 28 6 28C4.89543 28 4 27.1046 4 26V6C4 4.89543 4.89543 4 6 4Z"
-            />
-        <path
-            android:pathData="M6 4C7.10457 4 8 4.89543 8 6V26C8 27.1046 7.10457 28 6 28C4.89543 28 4 27.1046 4 26V6C4 4.89543 4.89543 4 6 4Z"
-            android:strokeWidth="4"
-            android:strokeColor="@android:color/transparent"
-            />
-    </group>
-</vector>
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_selected="true">
+        <vector
+            android:width="8dp"
+            android:height="32dp"
+            android:viewportWidth="12"
+            android:viewportHeight="32">
+            <group>
+                <clip-path
+                    android:pathData="M6 4C7.10457 4 8 4.89543 8 6V26C8 27.1046 7.10457 28 6 28C4.89543 28 4 27.1046 4 26V6C4 4.89543 4.89543 4 6 4Z" />
+                <path
+                    android:pathData="M4 4V28H8V4"
+                    android:fillColor="@android:color/transparent" />
+            </group>
+            <group>
+                <clip-path
+                    android:pathData="M0 0V32H12V0M6 4C7.10457 4 8 4.89543 8 6V26C8 27.1046 7.10457 28 6 28C4.89543 28 4 27.1046 4 26V6C4 4.89543 4.89543 4 6 4Z" />
+                <path
+                    android:pathData="M6 4C7.10457 4 8 4.89543 8 6V26C8 27.1046 7.10457 28 6 28C4.89543 28 4 27.1046 4 26V6C4 4.89543 4.89543 4 6 4Z"
+                    android:strokeWidth="4"
+                    android:strokeColor="@android:color/transparent" />
+            </group>
+        </vector>
+
+    </item>
+    <item android:state_selected="false">
+        <vector
+            android:width="12dp"
+            android:height="32dp"
+            android:viewportWidth="12"
+            android:viewportHeight="32">
+            <group>
+                <clip-path
+                    android:pathData="M6 4C7.10457 4 8 4.89543 8 6V26C8 27.1046 7.10457 28 6 28C4.89543 28 4 27.1046 4 26V6C4 4.89543 4.89543 4 6 4Z" />
+                <path
+                    android:pathData="M4 4V28H8V4"
+                    android:fillColor="@color/car_on_surface" />
+            </group>
+            <group>
+                <clip-path
+                    android:pathData="M0 0V32H12V0M6 4C7.10457 4 8 4.89543 8 6V26C8 27.1046 7.10457 28 6 28C4.89543 28 4 27.1046 4 26V6C4 4.89543 4.89543 4 6 4Z" />
+                <path
+                    android:pathData="M6 4C7.10457 4 8 4.89543 8 6V26C8 27.1046 7.10457 28 6 28C4.89543 28 4 27.1046 4 26V6C4 4.89543 4.89543 4 6 4Z"
+                    android:strokeWidth="4"
+                    android:strokeColor="@android:color/transparent" />
+            </group>
+        </vector>
+    </item>
+</selector>
diff --git a/app/res/drawable/pill_button_shape.xml b/app/res/drawable/pill_button_shape.xml
index d28b0b77..69342add 100644
--- a/app/res/drawable/pill_button_shape.xml
+++ b/app/res/drawable/pill_button_shape.xml
@@ -14,8 +14,13 @@
   ~ limitations under the License.
   -->
 
-<shape xmlns:android="http://schemas.android.com/apk/res/android"
-    android:shape="rectangle">
-    <corners android:radius="@dimen/media_card_pill_radius" />
-    <solid android:color="@color/car_surface" />
-</shape>
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
+    <item>
+        <shape
+            android:shape="rectangle">
+            <corners android:radius="@dimen/media_card_pill_radius" />
+            <solid android:color="@color/car_surface_container_highest" />
+        </shape>
+    </item>
+    <item android:drawable="@drawable/button_ripple"/>
+</layer-list>
diff --git a/app/res/layout/media_card_fullscreen.xml b/app/res/layout/media_card_fullscreen.xml
index 0772dbfb..10ad76eb 100644
--- a/app/res/layout/media_card_fullscreen.xml
+++ b/app/res/layout/media_card_fullscreen.xml
@@ -19,7 +19,7 @@
     xmlns:app="http://schemas.android.com/apk/res-auto"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
-    app:cardBackgroundColor="@color/car_surface_variant"
+    app:cardBackgroundColor="@color/car_surface_container_high"
     app:cardCornerRadius="@dimen/media_card_card_radius"
     app:cardElevation="0dp">
 
@@ -32,8 +32,9 @@
         <LinearLayout
             android:id="@+id/media_card_panel_content_container"
             android:layout_width="match_parent"
-            android:layout_height="@dimen/media_card_panel_content_height"
-            android:background="@color/car_surface"
+            android:layout_height="match_parent"
+            android:layout_marginTop="@dimen/media_card_panel_content_margin_top"
+            android:background="@color/car_surface_container_highest"
             android:orientation="vertical"
             app:layout_constraintBottom_toBottomOf="parent">
             <FrameLayout
@@ -55,7 +56,7 @@
 
             <androidx.viewpager2.widget.ViewPager2
                 android:id="@+id/view_pager"
-                android:background="@color/car_surface"
+                android:background="@color/car_surface_container_highest"
                 android:layout_width="match_parent"
                 android:layout_height="match_parent" />
         </LinearLayout>
@@ -64,9 +65,25 @@
             android:id="@+id/empty_panel"
             android:layout_width="match_parent"
             android:layout_height="match_parent"
-            android:background="@color/car_surface_variant"
+            android:background="@color/car_surface_container_high"
             app:layout_constraintTop_toTopOf="parent"/>
 
+        <ImageView
+            android:id="@+id/album_art"
+            android:layout_width="wrap_content"
+            android:layout_height="@dimen/media_card_album_art_size"
+            android:scaleType="fitCenter"
+            android:adjustViewBounds="true"
+            android:background="@android:color/transparent"
+            android:layout_marginStart="@dimen/media_card_horizontal_margin"
+            android:layout_marginEnd="@dimen/media_card_album_art_end_margin"
+            android:layout_marginTop="@dimen/media_card_horizontal_margin"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintHorizontal_bias="0"
+            app:layout_constrainedWidth="true"/>
+
         <ImageView
             android:id="@+id/media_widget_app_icon"
             android:layout_width="@dimen/media_card_app_icon_size"
@@ -77,23 +94,19 @@
             app:layout_constraintTop_toTopOf="parent"
             app:layout_constraintEnd_toEndOf="parent" />
 
-        <ImageView
-            android:id="@+id/album_art"
-            android:layout_width="@dimen/media_card_album_art_size"
-            android:layout_height="@dimen/media_card_album_art_size"
-            android:background="@drawable/radius_16_background"
-            android:clipToOutline="true"
-            android:layout_marginStart="@dimen/media_card_horizontal_margin"
-            android:layout_marginTop="@dimen/media_card_horizontal_margin"
-            app:layout_constraintTop_toTopOf="parent"
-            app:layout_constraintStart_toStartOf="parent" />
+        <androidx.constraintlayout.widget.Guideline
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:id="@+id/guideline"
+            app:layout_constraintGuide_begin="@dimen/media_card_text_view_guideline_start"
+            android:orientation="horizontal"/>
 
         <TextView
             android:id="@+id/title"
             android:layout_height="wrap_content"
             android:layout_width="0dp"
             android:text="@string/metadata_default_title"
-            android:textColor="@color/car_on_surface"
+            android:textColor="@color/car_text_primary"
             android:gravity="center_vertical"
             android:maxLines="1"
             android:ellipsize="end"
@@ -101,7 +114,7 @@
             android:layout_marginHorizontal="@dimen/media_card_horizontal_margin"
             app:layout_constraintStart_toStartOf="parent"
             app:layout_constraintEnd_toEndOf="parent"
-            app:layout_constraintTop_toBottomOf="@id/album_art"
+            app:layout_constraintTop_toBottomOf="@id/guideline"
             app:layout_constraintBottom_toBottomOf="parent"
             app:layout_constraintVertical_bias="0"/>
 
@@ -110,7 +123,7 @@
             android:layout_height="wrap_content"
             android:layout_width="0dp"
             style="@style/TextAppearance.Car.Body.Small"
-            android:textColor="@color/media_card_subtitle_color"
+            android:textColor="@color/car_text_secondary"
             android:maxLines="1"
             android:ellipsize="end"
             android:layout_marginTop="@dimen/media_card_artist_top_margin"
@@ -123,12 +136,11 @@
             android:id="@+id/playback_seek_bar"
             android:layout_width="0dp"
             android:layout_height="wrap_content"
-            android:clickable="false"
             android:paddingEnd="0dp"
             android:paddingStart="0dp"
-            android:progressBackgroundTint="@color/car_on_surface_40"
+            android:progressBackgroundTint="@color/car_surface_container_highest"
             android:progressDrawable="@drawable/media_card_seekbar_progress"
-            android:progressTint="@color/car_on_surface"
+            android:progressTint="@color/car_primary"
             android:splitTrack="true"
             android:thumb="@drawable/media_card_seekbar_thumb"
             android:thumbTint="@color/car_on_surface"
@@ -136,6 +148,8 @@
             android:layout_marginTop="@dimen/media_card_view_separation_margin"
             android:layout_marginStart="@dimen/media_card_horizontal_margin"
             android:layout_marginEnd="@dimen/media_card_view_separation_margin"
+            android:clickable="true"
+            android:focusable="true"
             app:layout_goneMarginEnd="@dimen/media_card_horizontal_margin"
             app:layout_constraintStart_toStartOf="parent"
             app:layout_constraintEnd_toStartOf="@id/content_format"
@@ -144,11 +158,11 @@
         <com.android.car.media.common.ContentFormatView
             android:id="@+id/content_format"
             android:layout_width="wrap_content"
-            android:layout_height="@dimen/media_card_small_button_size"
+            android:layout_height="@dimen/media_card_logo_size"
             android:layout_gravity="center_vertical"
             android:adjustViewBounds="true"
             android:scaleType="fitStart"
-            app:logoTint="@color/car_on_surface_40"
+            app:logoTint="@color/car_on_surface_variant"
             app:logoSize="small"
             android:layout_marginEnd="@dimen/media_card_horizontal_margin"
             app:layout_constraintStart_toEndOf="@id/playback_seek_bar"
@@ -162,9 +176,9 @@
             android:layout_height="@dimen/media_card_large_button_size"
             android:src="@drawable/ic_play_pause_selector"
             android:scaleType="center"
-            android:tint="@color/car_surface"
+            android:tint="@color/car_surface_container_high"
             android:background="@drawable/pill_button_shape"
-            android:backgroundTint="@color/car_on_surface"
+            android:backgroundTint="@color/car_primary"
             android:layout_marginBottom="@dimen/media_card_play_button_bottom_margin"
             app:layout_goneMarginEnd="@dimen/media_card_horizontal_margin"
             app:layout_goneMarginStart="@dimen/media_card_horizontal_margin"
@@ -178,11 +192,11 @@
             android:id="@+id/playback_action_id1"
             android:layout_width="@dimen/media_card_large_button_size"
             android:layout_height="@dimen/media_card_large_button_size"
-            android:scaleType="centerInside"
+            android:scaleType="fitCenter"
             android:padding="@dimen/media_card_large_button_icon_padding"
             android:cropToPadding="true"
-            android:tint="@color/playback_control_color"
-            android:background="@drawable/dark_circle_button_background"
+            android:tint="@color/car_on_surface_variant"
+            android:background="@drawable/circle_button_background"
             android:layout_marginStart="@dimen/media_card_horizontal_margin"
             android:layout_marginEnd="@dimen/media_card_play_button_horizontal_margin"
             app:layout_constraintStart_toStartOf="parent"
@@ -195,11 +209,11 @@
             android:id="@+id/playback_action_id2"
             android:layout_width="@dimen/media_card_large_button_size"
             android:layout_height="@dimen/media_card_large_button_size"
-            android:scaleType="centerInside"
+            android:scaleType="fitCenter"
             android:padding="@dimen/media_card_large_button_icon_padding"
             android:cropToPadding="true"
-            android:tint="@color/playback_control_color"
-            android:background="@drawable/dark_circle_button_background"
+            android:tint="@color/car_on_surface_variant"
+            android:background="@drawable/circle_button_background"
             android:layout_marginEnd="@dimen/media_card_horizontal_margin"
             android:layout_marginStart="@dimen/media_card_play_button_horizontal_margin"
             app:layout_constraintStart_toEndOf="@id/play_pause_button"
@@ -213,7 +227,7 @@
             android:layout_width="match_parent"
             android:layout_height="@dimen/media_card_bottom_panel_height"
             android:background="@drawable/media_card_button_panel_background"
-            android:backgroundTint="@color/car_surface"
+            android:backgroundTint="@color/car_surface_container_highest"
             app:layout_constraintStart_toStartOf="parent"
             app:layout_constraintEnd_toEndOf="parent"
             app:layout_constraintTop_toTopOf="parent"
diff --git a/app/res/layout/media_card_history_header_item.xml b/app/res/layout/media_card_history_header_item.xml
index a6028e9f..5b073e37 100644
--- a/app/res/layout/media_card_history_header_item.xml
+++ b/app/res/layout/media_card_history_header_item.xml
@@ -34,5 +34,5 @@
         android:includeFontPadding="false"
         android:text="@string/media_card_history_header_title"
         android:textAppearance="@style/TextAppearance.Car.Body.Small"
-        android:textColor="@color/car_on_surface"/>
+        android:textColor="@color/car_text_primary"/>
 </LinearLayout>
diff --git a/app/res/layout/media_card_history_item.xml b/app/res/layout/media_card_history_item.xml
index 1846ab62..eeb9bb47 100644
--- a/app/res/layout/media_card_history_item.xml
+++ b/app/res/layout/media_card_history_item.xml
@@ -32,7 +32,7 @@
             android:layout_height="wrap_content"
             android:layout_width="0dp"
             android:textAppearance="@style/TextAppearance.Car.Body.Small"
-            android:textColor="@color/car_on_surface"
+            android:textColor="@color/car_text_primary"
             android:maxLines="1"
             android:ellipsize="end"
             android:layout_marginEnd="@dimen/media_card_view_separation_margin"
@@ -46,7 +46,7 @@
             android:layout_height="wrap_content"
             android:layout_width="0dp"
             android:textAppearance="@style/TextAppearance.Car.Body.Small"
-            android:textColor="@color/media_card_subtitle_color"
+            android:textColor="@color/car_text_secondary"
             android:maxLines="1"
             android:ellipsize="end"
             android:layout_marginStart="@dimen/media_card_view_separation_margin"
@@ -86,7 +86,7 @@
             android:layout_height="wrap_content"
             android:layout_width="0dp"
             android:textAppearance="@style/TextAppearance.Car.Body.Small"
-            android:textColor="@color/car_on_surface"
+            android:textColor="@color/car_text_primary"
             android:maxLines="1"
             android:ellipsize="end"
             android:layout_marginEnd="@dimen/media_card_view_separation_margin"
diff --git a/app/res/layout/media_card_panel_content_item.xml b/app/res/layout/media_card_panel_content_item.xml
index dc575cde..1c11c1b1 100644
--- a/app/res/layout/media_card_panel_content_item.xml
+++ b/app/res/layout/media_card_panel_content_item.xml
@@ -24,7 +24,7 @@
         android:visibility="gone"
         android:id="@+id/overflow_grid"
         android:stretchColumns="0,1"
-        android:background="@color/car_surface">
+        android:background="@color/car_surface_container_highest">
         <TableRow
             android:layout_weight="1"
             android:gravity="center">
@@ -92,7 +92,7 @@
         android:layout_height="match_parent"
         android:paddingStart="@dimen/media_card_horizontal_margin"
         android:paddingEnd="@dimen/media_card_horizontal_margin"
-        android:background="@color/car_surface"
+        android:background="@color/car_surface_container_highest"
         android:visibility="gone">
         <com.android.car.apps.common.CarUiRecyclerViewNoScrollbar
             android:id="@+id/queue_list"
@@ -107,7 +107,7 @@
         android:id="@+id/history_list_container"
         android:layout_width="match_parent"
         android:layout_height="match_parent"
-        android:background="@color/car_surface"
+        android:background="@color/car_surface_container_highest"
         android:visibility="gone">
         <com.android.car.apps.common.CarUiRecyclerViewNoScrollbar
             android:id="@+id/history_list"
diff --git a/app/res/layout/media_card_queue_header_item.xml b/app/res/layout/media_card_queue_header_item.xml
index 15096191..e7b11117 100644
--- a/app/res/layout/media_card_queue_header_item.xml
+++ b/app/res/layout/media_card_queue_header_item.xml
@@ -32,5 +32,5 @@
         android:includeFontPadding="false"
         android:text="@string/media_card_queue_header_title"
         android:textAppearance="@style/TextAppearance.Car.Body.Small"
-        android:textColor="@color/car_on_surface"/>
+        android:textColor="@color/car_text_primary"/>
 </LinearLayout>
diff --git a/app/res/layout/media_card_queue_item.xml b/app/res/layout/media_card_queue_item.xml
index 60be3b08..966bb2e8 100644
--- a/app/res/layout/media_card_queue_item.xml
+++ b/app/res/layout/media_card_queue_item.xml
@@ -43,7 +43,7 @@
         android:layout_height="wrap_content"
         android:layout_width="0dp"
         android:textAppearance="@style/TextAppearance.Car.Body.Small"
-        android:textColor="@color/car_on_surface"
+        android:textColor="@color/car_text_primary"
         android:maxLines="1"
         android:ellipsize="end"
         android:layout_marginEnd="@dimen/media_card_view_separation_margin"
@@ -59,7 +59,7 @@
         android:layout_height="wrap_content"
         android:layout_width="0dp"
         android:textAppearance="@style/TextAppearance.Car.Body.Small"
-        android:textColor="@color/media_card_subtitle_color"
+        android:textColor="@color/car_text_secondary"
         android:maxLines="1"
         android:ellipsize="end"
         android:layout_marginEnd="@dimen/media_card_view_separation_margin"
diff --git a/app/res/values-af/strings.xml b/app/res/values-af/strings.xml
index a95f8200..99cd4c67 100644
--- a/app/res/values-af/strings.xml
+++ b/app/res/values-af/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"App is nie beskikbaar nie"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Kalmmodus"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Waglys"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-am/strings.xml b/app/res/values-am/strings.xml
index c1dae570..1106cb86 100644
--- a/app/res/values-am/strings.xml
+++ b/app/res/values-am/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"መተግበሪያ አይገኝም"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"የእርጋታ ሁነታ"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"ሰልፍ"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-ar/strings.xml b/app/res/values-ar/strings.xml
index e30682f5..1eedd067 100644
--- a/app/res/values-ar/strings.xml
+++ b/app/res/values-ar/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"التطبيق غير متاح."</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"وضع الهدوء"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"قائمة المحتوى التالي"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-as/strings.xml b/app/res/values-as/strings.xml
index 382cafd1..a2afc9f9 100644
--- a/app/res/values-as/strings.xml
+++ b/app/res/values-as/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"এপ্‌টো উপলব্ধ নহয়"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"শান্ত ম’ড"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"শাৰী"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-az/strings.xml b/app/res/values-az/strings.xml
index dcdd4f29..d35931b3 100644
--- a/app/res/values-az/strings.xml
+++ b/app/res/values-az/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Tətbiq əlçatan deyil"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Sakit rejim"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Növbə"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-b+sr+Latn/strings.xml b/app/res/values-b+sr+Latn/strings.xml
index f2ee2f9a..b08076ca 100644
--- a/app/res/values-b+sr+Latn/strings.xml
+++ b/app/res/values-b+sr+Latn/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikacija nije dostupna"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Režim opuštanja"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Redosled"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-be/strings.xml b/app/res/values-be/strings.xml
index e6906b53..1029f33f 100644
--- a/app/res/values-be/strings.xml
+++ b/app/res/values-be/strings.xml
@@ -27,15 +27,15 @@
     <string name="projected_launch_text" msgid="5034079820478748609">"Запусціць Android Auto"</string>
     <string name="projected_onclick_launch_error_toast_text" msgid="8853804785626030351">"Не ўдалося запусціць Android Auto. Дзеянні не знойдзены."</string>
     <string name="projection_devices" msgid="2556503818120676439">"{count,plural, =1{# прылада}one{# прылада}few{# прылады}many{# прылад}other{# прылады}}"</string>
-    <string name="weather_app_name" msgid="4356705068077942048">"Надвор\'е"</string>
+    <string name="weather_app_name" msgid="4356705068077942048">"Надвор’е"</string>
     <string name="fake_weather_main_text" msgid="2545755284647327839">"--°, пераважна сонечна"</string>
-    <string name="fake_weather_footer_text" msgid="8640814250285014485">"Маўтын-В\'ю • макс.: --°, мін.: --°"</string>
+    <string name="fake_weather_footer_text" msgid="8640814250285014485">"Маўтын-В’ю • макс.: --°, мін.: --°"</string>
     <string name="times_separator" msgid="1962841895013564645">"/"</string>
     <string name="recents_empty_state_text" msgid="8228569970506899117">"Няма нядаўніх элементаў"</string>
     <string name="recents_clear_all_text" msgid="3594272268167720553">"Ачысціць усё"</string>
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Праграма недаступная"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Рэжым спакою"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Чарга"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-bg/strings.xml b/app/res/values-bg/strings.xml
index 2c32dfc4..37e0d595 100644
--- a/app/res/values-bg/strings.xml
+++ b/app/res/values-bg/strings.xml
@@ -36,6 +36,5 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Приложението не е налично"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Режим на покой"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Опашка"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Източник на мултимедията"</string>
 </resources>
diff --git a/app/res/values-bn/strings.xml b/app/res/values-bn/strings.xml
index fdc1075f..9bfb8c3e 100644
--- a/app/res/values-bn/strings.xml
+++ b/app/res/values-bn/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"অ্যাপ উপলভ্য নেই"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Calm মোড"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"সারি"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-bs/strings.xml b/app/res/values-bs/strings.xml
index 04d5d6ab..0ce67924 100644
--- a/app/res/values-bs/strings.xml
+++ b/app/res/values-bs/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikacija nije dostupna"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Način rada za opuštanje"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Red čekanja"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-ca/strings.xml b/app/res/values-ca/strings.xml
index 9296eaf6..a8c75544 100644
--- a/app/res/values-ca/strings.xml
+++ b/app/res/values-ca/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"L\'aplicació no està disponible"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Mode de calma"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Cua"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-cs/strings.xml b/app/res/values-cs/strings.xml
index 99da6888..aa9dae16 100644
--- a/app/res/values-cs/strings.xml
+++ b/app/res/values-cs/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikace není k dispozici"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Klidný režim"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Fronta"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-da/strings.xml b/app/res/values-da/strings.xml
index a840584c..b3415440 100644
--- a/app/res/values-da/strings.xml
+++ b/app/res/values-da/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Appen er ikke tilgængelig"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Beroligende tilstand"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Kø"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-de/strings.xml b/app/res/values-de/strings.xml
index b7dec742..d74c8807 100644
--- a/app/res/values-de/strings.xml
+++ b/app/res/values-de/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"App nicht verfügbar"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Ruhemodus"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Wiedergabeliste"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-el/strings.xml b/app/res/values-el/strings.xml
index 5d7ffe51..6afdf258 100644
--- a/app/res/values-el/strings.xml
+++ b/app/res/values-el/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Η εφαρμογή δεν είναι διαθέσιμη"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Λειτουργία ηρεμίας"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Ουρά"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-en-rAU/strings.xml b/app/res/values-en-rAU/strings.xml
index 9153df9c..6e93f7a4 100644
--- a/app/res/values-en-rAU/strings.xml
+++ b/app/res/values-en-rAU/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"App isn\'t available"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Calm mode"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Queue"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-en-rCA/strings.xml b/app/res/values-en-rCA/strings.xml
index 3cfda752..f3a023b2 100644
--- a/app/res/values-en-rCA/strings.xml
+++ b/app/res/values-en-rCA/strings.xml
@@ -17,43 +17,24 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <!-- no translation found for app_title (1056886619192068947) -->
-    <skip />
+    <string name="app_title" msgid="1056886619192068947">"Car Launcher"</string>
     <string name="default_media_song_title" msgid="7837564242036091946"></string>
-    <!-- no translation found for tap_for_more_info_text (4240146824238692769) -->
-    <skip />
-    <!-- no translation found for tap_to_launch_text (7150379866796152196) -->
-    <skip />
-    <!-- no translation found for ongoing_call_duration_text_separator (2140398350095052096) -->
-    <skip />
-    <!-- no translation found for ongoing_call_text (7160701768924041827) -->
-    <skip />
-    <!-- no translation found for dialing_call_text (3286036311692512894) -->
-    <skip />
-    <!-- no translation found for projected_launch_text (5034079820478748609) -->
-    <skip />
-    <!-- no translation found for projected_onclick_launch_error_toast_text (8853804785626030351) -->
-    <skip />
-    <!-- no translation found for projection_devices (2556503818120676439) -->
-    <skip />
-    <!-- no translation found for weather_app_name (4356705068077942048) -->
-    <skip />
-    <!-- no translation found for fake_weather_main_text (2545755284647327839) -->
-    <skip />
-    <!-- no translation found for fake_weather_footer_text (8640814250285014485) -->
-    <skip />
-    <!-- no translation found for times_separator (1962841895013564645) -->
-    <skip />
-    <!-- no translation found for recents_empty_state_text (8228569970506899117) -->
-    <skip />
-    <!-- no translation found for recents_clear_all_text (3594272268167720553) -->
-    <skip />
-    <!-- no translation found for failure_opening_recent_task_message (963567570097465902) -->
-    <skip />
-    <!-- no translation found for calm_mode_title (4364804976931157567) -->
-    <skip />
-    <!-- no translation found for media_card_queue_header_title (8801994125708995575) -->
-    <skip />
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
-    <skip />
+    <string name="tap_for_more_info_text" msgid="4240146824238692769">"Tap card for more info"</string>
+    <string name="tap_to_launch_text" msgid="7150379866796152196">"Tap card to launch"</string>
+    <string name="ongoing_call_duration_text_separator" msgid="2140398350095052096">" • "</string>
+    <string name="ongoing_call_text" msgid="7160701768924041827">"Ongoing call"</string>
+    <string name="dialing_call_text" msgid="3286036311692512894">"Dialing…"</string>
+    <string name="projected_launch_text" msgid="5034079820478748609">"Launch Android Auto"</string>
+    <string name="projected_onclick_launch_error_toast_text" msgid="8853804785626030351">"Unable to launch Android Auto. No activity found."</string>
+    <string name="projection_devices" msgid="2556503818120676439">"{count,plural, =1{# device}other{# devices}}"</string>
+    <string name="weather_app_name" msgid="4356705068077942048">"Weather"</string>
+    <string name="fake_weather_main_text" msgid="2545755284647327839">"--° Mostly sunny"</string>
+    <string name="fake_weather_footer_text" msgid="8640814250285014485">"Mountain View • H: --° L: --°"</string>
+    <string name="times_separator" msgid="1962841895013564645">"/"</string>
+    <string name="recents_empty_state_text" msgid="8228569970506899117">"No recent items"</string>
+    <string name="recents_clear_all_text" msgid="3594272268167720553">"Clear All"</string>
+    <string name="failure_opening_recent_task_message" msgid="963567570097465902">"App isn\'t available"</string>
+    <string name="calm_mode_title" msgid="4364804976931157567">"Calm mode"</string>
+    <string name="media_card_queue_header_title" msgid="8801994125708995575">"Queue"</string>
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Media Source"</string>
 </resources>
diff --git a/app/res/values-en-rGB/strings.xml b/app/res/values-en-rGB/strings.xml
index 9153df9c..6e93f7a4 100644
--- a/app/res/values-en-rGB/strings.xml
+++ b/app/res/values-en-rGB/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"App isn\'t available"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Calm mode"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Queue"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-en-rIN/strings.xml b/app/res/values-en-rIN/strings.xml
index 9153df9c..6e93f7a4 100644
--- a/app/res/values-en-rIN/strings.xml
+++ b/app/res/values-en-rIN/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"App isn\'t available"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Calm mode"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Queue"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-en-rXC/strings.xml b/app/res/values-en-rXC/strings.xml
index 5e8c02e2..879e1c57 100644
--- a/app/res/values-en-rXC/strings.xml
+++ b/app/res/values-en-rXC/strings.xml
@@ -36,6 +36,5 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‏‎‎‏‏‎‎‎‎‎‎‏‏‏‏‏‎‎‏‏‎‏‎‏‎‏‏‏‏‏‎‏‎‎‎‏‏‏‏‎‎‏‏‎‎‏‏‎‎‎‏‏‎‎‏‎‏‏‏‏‏‎‏‏‏‎‏‎‏‎‎‎‏‎‏‏‏‎‎App isn\'t available‎‏‎‎‏‎"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‏‎‎‏‏‎‎‎‎‎‎‏‏‏‏‏‏‎‏‏‏‏‎‎‏‎‎‏‎‎‏‎‏‏‏‎‎‏‏‏‎‎‎‎‎‎‎‎‎‎‏‏‎‎‏‏‏‏‎‏‎‏‏‎‏‎‏‏‎‏‏‎‎‎‏‏‏‏‏‏‎Calm mode‎‏‎‎‏‎"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‏‎‎‏‏‎‎‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‎‏‎‎‎‏‎‎‏‏‎‏‏‏‏‎‏‏‏‎‎‎‎‎‏‎‏‏‎‏‏‏‎‎‏‏‏‏‏‎‏‎‏‏‎‏‎‏‎‏‏‏‏‏‏‎‏‏‏‎Queue‎‏‎‎‏‎"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‏‎‎‏‏‎‎‎‎‎‎‏‏‏‏‏‏‏‏‏‏‎‎‏‏‏‎‏‏‎‏‎‎‎‏‏‎‎‎‎‏‏‏‎‎‎‎‏‎‎‏‎‎‎‏‎‎‎‎‏‏‏‎‏‎‎‏‎‎‎‎‎‏‎‏‏‎‎‎‏‏‎Media Source‎‏‎‎‏‎"</string>
 </resources>
diff --git a/app/res/values-es-rUS/strings.xml b/app/res/values-es-rUS/strings.xml
index a8b66b5c..be3e667d 100644
--- a/app/res/values-es-rUS/strings.xml
+++ b/app/res/values-es-rUS/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"La app no está disponible"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modo calma"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Fila"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-es/strings.xml b/app/res/values-es/strings.xml
index e4a7c823..1656039c 100644
--- a/app/res/values-es/strings.xml
+++ b/app/res/values-es/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"La aplicación no está disponible"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modo Calma"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Cola"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-et/strings.xml b/app/res/values-et/strings.xml
index 42e53f70..6188298e 100644
--- a/app/res/values-et/strings.xml
+++ b/app/res/values-et/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Rakendus ei ole saadaval"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Lõõgastusrežiim"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Järjekord"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-eu/strings.xml b/app/res/values-eu/strings.xml
index 83ed744d..f52428f8 100644
--- a/app/res/values-eu/strings.xml
+++ b/app/res/values-eu/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Ez dago erabilgarri aplikazioa"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modu lasaia"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Ilara"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-fa/strings.xml b/app/res/values-fa/strings.xml
index f9c3a8d2..c92cf39e 100644
--- a/app/res/values-fa/strings.xml
+++ b/app/res/values-fa/strings.xml
@@ -19,8 +19,8 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_title" msgid="1056886619192068947">"راه‌انداز خودرو"</string>
     <string name="default_media_song_title" msgid="7837564242036091946"></string>
-    <string name="tap_for_more_info_text" msgid="4240146824238692769">"برای اطلاعات بیشتر، روی کارت ضربه بزنید"</string>
-    <string name="tap_to_launch_text" msgid="7150379866796152196">"برای راه‌اندازی، روی کارت ضربه بزنید"</string>
+    <string name="tap_for_more_info_text" msgid="4240146824238692769">"برای اطلاعات بیشتر، روی کارت تک‌ضرب بزنید"</string>
+    <string name="tap_to_launch_text" msgid="7150379866796152196">"برای راه‌اندازی، روی کارت تک‌ضرب بزنید"</string>
     <string name="ongoing_call_duration_text_separator" msgid="2140398350095052096">" • "</string>
     <string name="ongoing_call_text" msgid="7160701768924041827">"تماس درحال انجام"</string>
     <string name="dialing_call_text" msgid="3286036311692512894">"درحال شماره‌گیری…"</string>
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"برنامه دردسترس نیست"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"حالت «آرام»"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"صف پخش"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-fi/strings.xml b/app/res/values-fi/strings.xml
index f3b1d106..e125de8e 100644
--- a/app/res/values-fi/strings.xml
+++ b/app/res/values-fi/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Sovellus ei ole käytettävissä"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Rauhallinen tila"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Jono"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-fr-rCA/strings.xml b/app/res/values-fr-rCA/strings.xml
index 57d244ec..ce7dc0e5 100644
--- a/app/res/values-fr-rCA/strings.xml
+++ b/app/res/values-fr-rCA/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"L\'application n\'est pas accessible"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Mode Calme"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"File d\'attente"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-fr/strings.xml b/app/res/values-fr/strings.xml
index a3e7271b..da78d0bf 100644
--- a/app/res/values-fr/strings.xml
+++ b/app/res/values-fr/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Appli indisponible"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Mode calme"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"File d\'attente"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-gl/strings.xml b/app/res/values-gl/strings.xml
index d4fcf4c4..070ed1e9 100644
--- a/app/res/values-gl/strings.xml
+++ b/app/res/values-gl/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"A aplicación non está dispoñible"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modo de calma"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Cola"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-gu/strings.xml b/app/res/values-gu/strings.xml
index 08604746..129ad033 100644
--- a/app/res/values-gu/strings.xml
+++ b/app/res/values-gu/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ઍપ ઉપલબ્ધ નથી"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"શાંત મોડ"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"કતાર"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-hi/strings.xml b/app/res/values-hi/strings.xml
index a0aa2c63..5402141a 100644
--- a/app/res/values-hi/strings.xml
+++ b/app/res/values-hi/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ऐप्लिकेशन उपलब्ध नहीं है"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"काम (शांत) मोड"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"सूची"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-hr/strings.xml b/app/res/values-hr/strings.xml
index 557e36f2..3ce008d9 100644
--- a/app/res/values-hr/strings.xml
+++ b/app/res/values-hr/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikacija nije dostupna"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Način opuštanja"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Red čekanja"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-hu/strings.xml b/app/res/values-hu/strings.xml
index 4ed23644..6b626909 100644
--- a/app/res/values-hu/strings.xml
+++ b/app/res/values-hu/strings.xml
@@ -36,6 +36,5 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Az alkalmazás nem áll rendelkezésre"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Nyugalom mód"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Lejátszási sor"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Médiaforrás"</string>
 </resources>
diff --git a/app/res/values-hy/strings.xml b/app/res/values-hy/strings.xml
index 727d1454..eaa87945 100644
--- a/app/res/values-hy/strings.xml
+++ b/app/res/values-hy/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Հավելվածը հասանելի չէ"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Հանգստի ռեժիմ"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Հերթացանկ"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-in/strings.xml b/app/res/values-in/strings.xml
index ae73bc6d..53d121c9 100644
--- a/app/res/values-in/strings.xml
+++ b/app/res/values-in/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikasi tidak tersedia"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Mode tenang"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Antrean"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-is/strings.xml b/app/res/values-is/strings.xml
index ed3bcbb7..a4e628ef 100644
--- a/app/res/values-is/strings.xml
+++ b/app/res/values-is/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Forritið er ekki í boði"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Róleg stilling"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Röð"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-it/strings.xml b/app/res/values-it/strings.xml
index a31e4251..2c21e8ea 100644
--- a/app/res/values-it/strings.xml
+++ b/app/res/values-it/strings.xml
@@ -36,6 +36,5 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"App non disponibile"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modalità Calma"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Coda"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Fonte di contenuti multimediali"</string>
 </resources>
diff --git a/app/res/values-iw/strings.xml b/app/res/values-iw/strings.xml
index 28d44ca8..612cc52a 100644
--- a/app/res/values-iw/strings.xml
+++ b/app/res/values-iw/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"האפליקציה לא זמינה"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"מצב רגיעה"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"הבאים בתור"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-ja/strings.xml b/app/res/values-ja/strings.xml
index bd0b8471..2a37dd90 100644
--- a/app/res/values-ja/strings.xml
+++ b/app/res/values-ja/strings.xml
@@ -36,6 +36,5 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"このアプリは使用できません"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Calm モード"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"キュー"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"メディアソース"</string>
 </resources>
diff --git a/app/res/values-ka/strings.xml b/app/res/values-ka/strings.xml
index a154a888..b8ebc5e9 100644
--- a/app/res/values-ka/strings.xml
+++ b/app/res/values-ka/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"აპი მიუწვდომელია"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"წყნარი რეჟიმი"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"რიგი"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-kk/strings.xml b/app/res/values-kk/strings.xml
index 2ee730b1..a8017a3e 100644
--- a/app/res/values-kk/strings.xml
+++ b/app/res/values-kk/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Қолданба қолжетімді емес."</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Тыныштық режимі"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Кезек"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-km/strings.xml b/app/res/values-km/strings.xml
index 4a5f1f3b..0a7471a8 100644
--- a/app/res/values-km/strings.xml
+++ b/app/res/values-km/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"មិន​មាន​កម្មវិធី"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"មុខងារស្ងាត់"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"ជួរ"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-kn/strings.xml b/app/res/values-kn/strings.xml
index 56c6a8ec..d0df27f9 100644
--- a/app/res/values-kn/strings.xml
+++ b/app/res/values-kn/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ಆ್ಯಪ್ ಲಭ್ಯವಿಲ್ಲ"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"ಶಾಂತ ಮೋಡ್"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"ಸರದಿ"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-ko/strings.xml b/app/res/values-ko/strings.xml
index 1f332d96..4c5bd057 100644
--- a/app/res/values-ko/strings.xml
+++ b/app/res/values-ko/strings.xml
@@ -36,6 +36,5 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"앱을 사용할 수 없음"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"고요 모드"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"현재 재생목록"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"미디어 소스"</string>
 </resources>
diff --git a/app/res/values-ky/strings.xml b/app/res/values-ky/strings.xml
index 8f322149..8b453ede 100644
--- a/app/res/values-ky/strings.xml
+++ b/app/res/values-ky/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Колдонмо жеткиликтүү эмес"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Тынчтык режими"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Кезек"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-lo/strings.xml b/app/res/values-lo/strings.xml
index 9eb4f586..e8dbde1f 100644
--- a/app/res/values-lo/strings.xml
+++ b/app/res/values-lo/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ແອັບບໍ່ພ້ອມໃຫ້ນຳໃຊ້"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"ໂໝດສະຫງົບ"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"ຄິວ"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-lt/strings.xml b/app/res/values-lt/strings.xml
index 580f5720..917f0ec4 100644
--- a/app/res/values-lt/strings.xml
+++ b/app/res/values-lt/strings.xml
@@ -36,6 +36,5 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Programa nepasiekiama"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Ramybės režimas"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Eilė"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Medijos šaltinis"</string>
 </resources>
diff --git a/app/res/values-lv/strings.xml b/app/res/values-lv/strings.xml
index 8eb2c9b3..e9d276ce 100644
--- a/app/res/values-lv/strings.xml
+++ b/app/res/values-lv/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Lietotne nav pieejama"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Miera režīms"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Rinda"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-mk/strings.xml b/app/res/values-mk/strings.xml
index fb01c156..f8e3d06f 100644
--- a/app/res/values-mk/strings.xml
+++ b/app/res/values-mk/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Апликацијата не е достапна"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Режим на мирување"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Редица"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-ml/strings.xml b/app/res/values-ml/strings.xml
index 646e7e83..3c98b43c 100644
--- a/app/res/values-ml/strings.xml
+++ b/app/res/values-ml/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ആപ്പ് ലഭ്യമല്ല"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"\'ശാന്തം\' മോഡ്"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"ക്യൂ"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-mn/strings.xml b/app/res/values-mn/strings.xml
index e7f95725..afc1c3fd 100644
--- a/app/res/values-mn/strings.xml
+++ b/app/res/values-mn/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Апп боломжгүй байна"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Тайван горим"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Дараалал"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-mr/strings.xml b/app/res/values-mr/strings.xml
index 0d027fb2..0801e385 100644
--- a/app/res/values-mr/strings.xml
+++ b/app/res/values-mr/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"अ‍ॅप उपलब्ध नाही"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"शांत मोड"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"क्यू"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-ms/strings.xml b/app/res/values-ms/strings.xml
index 4e876d88..a5c1f393 100644
--- a/app/res/values-ms/strings.xml
+++ b/app/res/values-ms/strings.xml
@@ -36,6 +36,5 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Apl tidak tersedia"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Mod Calm"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Baris gilir"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Sumber Media"</string>
 </resources>
diff --git a/app/res/values-my/strings.xml b/app/res/values-my/strings.xml
index 5b956655..4401c9f7 100644
--- a/app/res/values-my/strings.xml
+++ b/app/res/values-my/strings.xml
@@ -36,6 +36,5 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"အက်ပ် မရနိုင်ပါ"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"အငြိမ်မုဒ်"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"စာရင်းစဉ်"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"မီဒီယာရင်းမြစ်"</string>
 </resources>
diff --git a/app/res/values-nb/strings.xml b/app/res/values-nb/strings.xml
index d4542931..4e25c723 100644
--- a/app/res/values-nb/strings.xml
+++ b/app/res/values-nb/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Appen er ikke tilgjengelig"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Roligmodus"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Kø"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-ne/strings.xml b/app/res/values-ne/strings.xml
index 9cd20b64..d70c2d2e 100644
--- a/app/res/values-ne/strings.xml
+++ b/app/res/values-ne/strings.xml
@@ -36,6 +36,5 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"एप उपलब्ध छैन"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"शान्त मोड"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"लाइन"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"मिडियाको स्रोत"</string>
 </resources>
diff --git a/app/res/values-nl/strings.xml b/app/res/values-nl/strings.xml
index cb662f9a..15535e6e 100644
--- a/app/res/values-nl/strings.xml
+++ b/app/res/values-nl/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"App is niet beschikbaar"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Kalme modus"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Wachtrij"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-or/strings.xml b/app/res/values-or/strings.xml
index aab7628a..1bfdf27d 100644
--- a/app/res/values-or/strings.xml
+++ b/app/res/values-or/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ଆପ ଉପଲବ୍ଧ ନାହିଁ"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"ଶାନ୍ତ ମୋଡ"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"ଧାଡ଼ି"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-pa/strings.xml b/app/res/values-pa/strings.xml
index 72e051bc..5bf3b065 100644
--- a/app/res/values-pa/strings.xml
+++ b/app/res/values-pa/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ਐਪ ਉਪਲਬਧ ਨਹੀਂ ਹੈ"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"ਸ਼ਾਂਤ ਮੋਡ"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"ਕਤਾਰ"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-pl/strings.xml b/app/res/values-pl/strings.xml
index 015060f5..73478c11 100644
--- a/app/res/values-pl/strings.xml
+++ b/app/res/values-pl/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikacja jest niedostępna"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Tryb cichy"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Kolejka"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-pt-rPT/strings.xml b/app/res/values-pt-rPT/strings.xml
index c7f7ae47..a3f7bd26 100644
--- a/app/res/values-pt-rPT/strings.xml
+++ b/app/res/values-pt-rPT/strings.xml
@@ -36,6 +36,5 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"A app não está disponível"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modo Calm"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Fila"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Origem de multimédia"</string>
 </resources>
diff --git a/app/res/values-pt/strings.xml b/app/res/values-pt/strings.xml
index 34b119ff..a4576c88 100644
--- a/app/res/values-pt/strings.xml
+++ b/app/res/values-pt/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"O app não está disponível"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modo foco"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Fila"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-ro/strings.xml b/app/res/values-ro/strings.xml
index e433dbc4..03f63b3a 100644
--- a/app/res/values-ro/strings.xml
+++ b/app/res/values-ro/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplicația nu este disponibilă"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modul Calm"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Coadă"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-ru/strings.xml b/app/res/values-ru/strings.xml
index aa221d91..49af8e88 100644
--- a/app/res/values-ru/strings.xml
+++ b/app/res/values-ru/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Приложение недоступно"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Режим покоя"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Очередь"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-si/strings.xml b/app/res/values-si/strings.xml
index 00656bde..10c106f1 100644
--- a/app/res/values-si/strings.xml
+++ b/app/res/values-si/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"යෙදුම නොතිබේ"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"සන්සුන් ප්‍රකාරය"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"පෝලිම"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-sk/strings.xml b/app/res/values-sk/strings.xml
index 302f4e04..0ead5fad 100644
--- a/app/res/values-sk/strings.xml
+++ b/app/res/values-sk/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikácia nie je k dispozícii"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Pokojný režim"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Poradie"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-sl/strings.xml b/app/res/values-sl/strings.xml
index 6199312f..e26cdffe 100644
--- a/app/res/values-sl/strings.xml
+++ b/app/res/values-sl/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikacija ni na voljo"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Umirjeni način"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Čakalna vrsta"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-sq/strings.xml b/app/res/values-sq/strings.xml
index 570596f1..894da297 100644
--- a/app/res/values-sq/strings.xml
+++ b/app/res/values-sq/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikacioni nuk ofrohet"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modaliteti i qetësisë"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Radha"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-sr/strings.xml b/app/res/values-sr/strings.xml
index 9f62e70a..77a252c3 100644
--- a/app/res/values-sr/strings.xml
+++ b/app/res/values-sr/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Апликација није доступна"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Режим опуштања"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Редослед"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-sv/strings.xml b/app/res/values-sv/strings.xml
index 099ac4a8..5aafac81 100644
--- a/app/res/values-sv/strings.xml
+++ b/app/res/values-sv/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Appen är inte tillgänglig"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Lugnt läge"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Kö"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-sw/strings.xml b/app/res/values-sw/strings.xml
index 1aedfc4a..c150d0ba 100644
--- a/app/res/values-sw/strings.xml
+++ b/app/res/values-sw/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Programu haipatikani"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Hali ya utulivu"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Foleni"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-ta/strings.xml b/app/res/values-ta/strings.xml
index 31388651..487493dc 100644
--- a/app/res/values-ta/strings.xml
+++ b/app/res/values-ta/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ஆப்ஸ் கிடைக்கவில்லை"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"அமைதிப் பயன்முறை"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"வரிசை"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-te/strings.xml b/app/res/values-te/strings.xml
index 5779a559..08b5b895 100644
--- a/app/res/values-te/strings.xml
+++ b/app/res/values-te/strings.xml
@@ -36,6 +36,5 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"యాప్ అందుబాటులో లేదు"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"క్లెయిమ్ మోడ్"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"క్యూ"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"మీడియా సోర్స్"</string>
 </resources>
diff --git a/app/res/values-th/strings.xml b/app/res/values-th/strings.xml
index 3f485873..f3c88edd 100644
--- a/app/res/values-th/strings.xml
+++ b/app/res/values-th/strings.xml
@@ -36,6 +36,5 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"แอปไม่พร้อมใช้งาน"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"โหมด Calm"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"คิว"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"แหล่งที่มาของสื่อ"</string>
 </resources>
diff --git a/app/res/values-tl/strings.xml b/app/res/values-tl/strings.xml
index 711be799..cb390553 100644
--- a/app/res/values-tl/strings.xml
+++ b/app/res/values-tl/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Hindi available ang app"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Calm mode"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Queue"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-tr/strings.xml b/app/res/values-tr/strings.xml
index 80eceb02..02522743 100644
--- a/app/res/values-tr/strings.xml
+++ b/app/res/values-tr/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Uygulama kullanılamıyor"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Sakin mod"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Sıra"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-uk/strings.xml b/app/res/values-uk/strings.xml
index 0ff01e75..7855e2ef 100644
--- a/app/res/values-uk/strings.xml
+++ b/app/res/values-uk/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Додаток недоступний"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Спокійний режим"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Черга"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-ur/strings.xml b/app/res/values-ur/strings.xml
index f5ffbe94..f3510272 100644
--- a/app/res/values-ur/strings.xml
+++ b/app/res/values-ur/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ایپ دستیاب نہیں ہے"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"پُرسکون وضع"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"قطار"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-uz/strings.xml b/app/res/values-uz/strings.xml
index a74969d5..a0930d52 100644
--- a/app/res/values-uz/strings.xml
+++ b/app/res/values-uz/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Ilova mavjud emas"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Dam olish rejimi"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Navbat"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-vi/strings.xml b/app/res/values-vi/strings.xml
index 22441293..1bb9e6e7 100644
--- a/app/res/values-vi/strings.xml
+++ b/app/res/values-vi/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Hiện không có ứng dụng"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Chế độ Tĩnh lặng"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Danh sách chờ"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-zh-rCN/strings.xml b/app/res/values-zh-rCN/strings.xml
index 89c27071..fa238ed9 100644
--- a/app/res/values-zh-rCN/strings.xml
+++ b/app/res/values-zh-rCN/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"应用无法打开"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"平静模式"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"队列"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-zh-rHK/strings.xml b/app/res/values-zh-rHK/strings.xml
index a3118610..b763bdcb 100644
--- a/app/res/values-zh-rHK/strings.xml
+++ b/app/res/values-zh-rHK/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"目前無法使用這個應用程式"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"平靜模式"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"序列"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-zh-rTW/strings.xml b/app/res/values-zh-rTW/strings.xml
index dddd895d..1e55679c 100644
--- a/app/res/values-zh-rTW/strings.xml
+++ b/app/res/values-zh-rTW/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"應用程式目前無法使用"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"平靜模式"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"待播清單"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values-zu/strings.xml b/app/res/values-zu/strings.xml
index d2caa0da..64b13a63 100644
--- a/app/res/values-zu/strings.xml
+++ b/app/res/values-zu/strings.xml
@@ -36,6 +36,6 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"I-app ayitholakali"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Imodi ezolile"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Ulayini"</string>
-    <!-- no translation found for media_card_history_header_title (6753954322481732596) -->
+    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
     <skip />
 </resources>
diff --git a/app/res/values/colors.xml b/app/res/values/colors.xml
index 6c818fc1..d741960b 100644
--- a/app/res/values/colors.xml
+++ b/app/res/values/colors.xml
@@ -24,7 +24,6 @@
     <color name="recents_background_color">@*android:color/car_grey_900</color>
     <color name="default_recents_thumbnail_color">@*android:color/car_grey_846</color>
     <color name="clear_all_recents_text_color">@*android:color/car_accent</color>
-    <color name="media_card_subtitle_color">@color/car_on_surface_40</color>
 
     <!-- CarUiPortraitLauncherReferenceRRO relies on overlaying these values -->
     <color name="media_button_tint">@*android:color/car_tint</color>
diff --git a/app/res/values/config.xml b/app/res/values/config.xml
index fa6872c5..bd4bbbaf 100644
--- a/app/res/values/config.xml
+++ b/app/res/values/config.xml
@@ -61,12 +61,6 @@
     <string-array name="config_taskViewPackages" translatable="false">
     </string-array>
 
-    <!--
-        The Activity to use as a passenger Launcher, if empty, it assumes CarLauncher can do
-        the passenger Launcher role too.
-    -->
-    <string name="config_passengerLauncherComponent">com.android.car.multidisplay/.launcher.LauncherActivity</string>
-
     <!-- Boolean value to indicate if the secondary descriptive text of homescreen cards
          without controls should have multiple lines -->
     <bool name="config_homecard_single_line_secondary_descriptive_text">true</bool>
diff --git a/app/res/values/dimens.xml b/app/res/values/dimens.xml
index 90ee0c76..48c87222 100644
--- a/app/res/values/dimens.xml
+++ b/app/res/values/dimens.xml
@@ -105,6 +105,9 @@
     <dimen name="media_card_view_separation_margin">16dp</dimen>
     <dimen name="media_card_artist_top_margin">4dp</dimen>
     <dimen name="media_card_album_art_size">200dp</dimen>
+    <dimen name="media_card_album_art_end_margin">96dp</dimen>
+    <item name="media_card_album_art_drawable_corner_ratio" format="float" type="dimen">0.08</item>
+    <dimen name="media_card_logo_size">32dp</dimen>
     <dimen name="media_card_small_button_size">40dp</dimen>
     <dimen name="media_card_large_button_size">80dp</dimen>
     <dimen name="media_card_bottom_panel_button_size">56dp</dimen>
@@ -124,7 +127,7 @@
     <dimen name="media_card_panel_handlebar_horizontal_padding">164dp</dimen>
     <dimen name="media_card_queue_header_app_icon_size">26dp</dimen>
     <dimen name="media_card_queue_item_thumbnail_size">80dp</dimen>
-    <dimen name="media_card_panel_content_height">416dp</dimen>
+    <dimen name="media_card_panel_content_margin_top">216dp</dimen>
     <dimen name="media_card_title_animated_line_height">36dp</dimen>
     <dimen name="media_card_title_default_line_height">40dp</dimen>
     <dimen name="media_card_title_animated_text_size">28sp</dimen>
@@ -135,4 +138,5 @@
     <dimen name="media_card_history_item_icon_size">80dp</dimen>
     <dimen name="media_card_history_item_thumbnail_size">32dp</dimen>
     <dimen name="media_card_view_header_icon_size">32dp</dimen>
+    <dimen name="media_card_text_view_guideline_start">248dp</dimen>
 </resources>
diff --git a/app/res/values/overlayable.xml b/app/res/values/overlayable.xml
index 0121c841..d4c72efd 100644
--- a/app/res/values/overlayable.xml
+++ b/app/res/values/overlayable.xml
@@ -41,7 +41,6 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="bool" name="config_launch_most_recent_task_on_recents_dismiss"/>
       <item type="bool" name="show_seek_bar"/>
       <item type="bool" name="use_media_source_color_for_seek_bar"/>
-      <item type="color" name="car_on_surface_40"/>
       <item type="color" name="card_background_scrim"/>
       <item type="color" name="clear_all_recents_text_color"/>
       <item type="color" name="date_divider_bar_color"/>
@@ -54,7 +53,6 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="color" name="media_card_panel_button_background_tint_state_list"/>
       <item type="color" name="media_card_panel_button_tint_state_list"/>
       <item type="color" name="media_card_seekbar_thumb_color"/>
-      <item type="color" name="media_card_subtitle_color"/>
       <item type="color" name="minimized_progress_bar_background"/>
       <item type="color" name="recents_background_color"/>
       <item type="color" name="seek_bar_color"/>
@@ -89,6 +87,8 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="dimen" name="horizontal_border_size"/>
       <item type="dimen" name="launcher_card_corner_radius"/>
       <item type="dimen" name="main_screen_widget_margin"/>
+      <item type="dimen" name="media_card_album_art_drawable_corner_ratio"/>
+      <item type="dimen" name="media_card_album_art_end_margin"/>
       <item type="dimen" name="media_card_album_art_size"/>
       <item type="dimen" name="media_card_app_icon_size"/>
       <item type="dimen" name="media_card_artist_top_margin"/>
@@ -106,9 +106,10 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="dimen" name="media_card_horizontal_margin"/>
       <item type="dimen" name="media_card_large_button_icon_padding"/>
       <item type="dimen" name="media_card_large_button_size"/>
+      <item type="dimen" name="media_card_logo_size"/>
       <item type="dimen" name="media_card_margin_panel_open"/>
       <item type="dimen" name="media_card_panel_button_icon_padding"/>
-      <item type="dimen" name="media_card_panel_content_height"/>
+      <item type="dimen" name="media_card_panel_content_margin_top"/>
       <item type="dimen" name="media_card_panel_handlebar_height"/>
       <item type="dimen" name="media_card_panel_handlebar_horizontal_padding"/>
       <item type="dimen" name="media_card_panel_handlebar_offscreen_start_position"/>
@@ -120,6 +121,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="dimen" name="media_card_queue_item_thumbnail_size"/>
       <item type="dimen" name="media_card_recycler_view_fading_edge_length"/>
       <item type="dimen" name="media_card_small_button_size"/>
+      <item type="dimen" name="media_card_text_view_guideline_start"/>
       <item type="dimen" name="media_card_title_animated_line_height"/>
       <item type="dimen" name="media_card_title_animated_text_size"/>
       <item type="dimen" name="media_card_title_default_line_height"/>
@@ -139,10 +141,11 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="dimen" name="tap_text_margin"/>
       <item type="dimen" name="text_block_top_margin"/>
       <item type="dimen" name="vertical_border_size"/>
+      <item type="drawable" name="button_ripple"/>
       <item type="drawable" name="car_button_background"/>
+      <item type="drawable" name="circle_button_background"/>
       <item type="drawable" name="control_bar_contact_image_background"/>
       <item type="drawable" name="control_bar_image_background"/>
-      <item type="drawable" name="dark_circle_button_background"/>
       <item type="drawable" name="default_audio_background"/>
       <item type="drawable" name="dialer_button_active_state_circle"/>
       <item type="drawable" name="divider"/>
@@ -201,6 +204,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="id" name="empty_state"/>
       <item type="id" name="end_edge"/>
       <item type="id" name="fragment_container_view"/>
+      <item type="id" name="guideline"/>
       <item type="id" name="header_app_icon"/>
       <item type="id" name="history_button"/>
       <item type="id" name="history_card_album_art"/>
@@ -315,7 +319,6 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="string" name="calm_mode_separator"/>
       <item type="string" name="calm_mode_title"/>
       <item type="string" name="config_calmMode_componentName"/>
-      <item type="string" name="config_passengerLauncherComponent"/>
       <item type="string" name="config_smallCanvasOptimizedMapIntent"/>
       <item type="string" name="config_tosMapIntent"/>
       <item type="string" name="default_media_song_title"/>
diff --git a/app/res/values/strings.xml b/app/res/values/strings.xml
index 0bb11de6..bcb5546b 100644
--- a/app/res/values/strings.xml
+++ b/app/res/values/strings.xml
@@ -60,5 +60,5 @@
 
     <!-- Fullscreen media card strings -->
     <string name="media_card_queue_header_title">Queue</string>
-    <string name="media_card_history_header_title">Jump back in</string>
+    <string name="media_card_history_header_title">Media Source</string>
 </resources>
diff --git a/app/res/xml/panel_animation_motion_scene.xml b/app/res/xml/panel_animation_motion_scene.xml
index 94cca966..2ef5eb4a 100644
--- a/app/res/xml/panel_animation_motion_scene.xml
+++ b/app/res/xml/panel_animation_motion_scene.xml
@@ -140,9 +140,9 @@
             android:layout_height="@dimen/media_card_large_button_size"
             android:src="@drawable/ic_play_pause_selector"
             android:scaleType="center"
-            android:tint="@color/car_surface"
+            android:tint="@color/car_surface_container_high"
             android:background="@drawable/pill_button_shape"
-            android:backgroundTint="@color/car_on_surface"
+            android:backgroundTint="@color/car_primary"
             android:layout_marginStart="@dimen/media_card_horizontal_margin"
             android:layout_marginTop="@dimen/media_card_margin_panel_open"
             motion:layout_constraintStart_toStartOf="parent"
@@ -153,7 +153,7 @@
             android:layout_width="match_parent"
             android:layout_height="@dimen/media_card_bottom_panel_animated_size"
             android:background="@drawable/media_card_button_panel_background"
-            android:backgroundTint="@color/car_surface"
+            android:backgroundTint="@color/car_surface_container_highest"
             android:layout_marginStart="@dimen/media_card_horizontal_margin"
             android:layout_marginEnd="@dimen/media_card_horizontal_margin"
             android:layout_marginTop="@dimen/media_card_margin_panel_open"
@@ -165,7 +165,7 @@
             android:id="@+id/empty_panel"
             android:layout_width="match_parent"
             android:layout_height="0dp"
-            android:background="@color/car_surface_variant"
+            android:background="@color/car_surface_container_high"
             motion:layout_constraintTop_toTopOf="parent">
         </Constraint>
         <ConstraintOverride
@@ -179,7 +179,7 @@
             android:layout_height="wrap_content"
             android:layout_width="0dp"
             android:text="@string/metadata_default_title"
-            android:textColor="@color/car_on_surface"
+            android:textColor="@color/car_text_primary"
             android:maxLines="1"
             android:ellipsize="end"
             android:layout_marginStart="@dimen/media_card_margin_panel_open"
@@ -218,19 +218,17 @@
             android:clickable="false"
             android:paddingEnd="0dp"
             android:paddingStart="0dp"
-            android:progressBackgroundTint="@color/car_on_surface_40"
+            android:progressBackgroundTint="@color/car_surface_container_highest"
             android:progressDrawable="@drawable/media_card_seekbar_progress"
-            android:progressTint="@color/car_on_surface"
+            android:progressTint="@color/car_primary"
             android:splitTrack="false"
             android:thumb="@drawable/media_card_seekbar_thumb"
             android:thumbTint="@color/car_on_surface"
             android:thumbOffset="0px"
-            android:layout_marginTop="@dimen/media_card_view_separation_margin"
             android:layout_marginStart="@dimen/media_card_margin_panel_open"
-            android:layout_marginEnd="@dimen/media_card_view_separation_margin"
-            motion:layout_goneMarginEnd="@dimen/media_card_horizontal_margin"
+            android:layout_marginEnd="@dimen/media_card_horizontal_margin"
             motion:layout_constraintStart_toEndOf="@id/play_pause_button"
-            motion:layout_constraintEnd_toStartOf="@id/content_format"
+            motion:layout_constraintEnd_toEndOf="parent"
             motion:layout_constraintBottom_toBottomOf="@id/play_pause_button"
             motion:layout_constraintTop_toBottomOf="@id/title">
             <PropertySet
diff --git a/app/src/com/android/car/carlauncher/CarLauncher.java b/app/src/com/android/car/carlauncher/CarLauncher.java
index 0ff4647f..d256a058 100644
--- a/app/src/com/android/car/carlauncher/CarLauncher.java
+++ b/app/src/com/android/car/carlauncher/CarLauncher.java
@@ -17,16 +17,16 @@
 package com.android.car.carlauncher;
 
 import static android.app.ActivityTaskManager.INVALID_TASK_ID;
-import static android.car.settings.CarSettings.Secure.KEY_USER_TOS_ACCEPTED;
+import static android.car.settings.CarSettings.Secure.KEY_UNACCEPTED_TOS_DISABLED_APPS;
 import static android.view.WindowManager.LayoutParams.PRIVATE_FLAG_TRUSTED_OVERLAY;
 
+import static com.android.car.carlauncher.AppGridFragment.Mode.ALL_APPS;
 import static com.android.car.carlauncher.CarLauncherViewModel.CarLauncherViewModelFactory;
 
 import android.app.ActivityManager;
 import android.app.ActivityOptions;
 import android.app.TaskStackListener;
 import android.car.Car;
-import android.content.ComponentName;
 import android.content.Intent;
 import android.content.res.Configuration;
 import android.database.ContentObserver;
@@ -82,8 +82,9 @@ public class CarLauncher extends FragmentActivity {
     private boolean mIsReadyLogged;
     private boolean mUseSmallCanvasOptimizedMap;
     private ViewGroup mMapsCard;
-    private CarLauncherViewModel mCarLauncherViewModel;
 
+    @VisibleForTesting
+    CarLauncherViewModel mCarLauncherViewModel;
     @VisibleForTesting
     ContentObserver mTosContentObserver;
 
@@ -114,7 +115,6 @@ public class CarLauncher extends FragmentActivity {
         public void handleIntent(Intent intent) {
             if (intent != null) {
                 ActivityOptions options = ActivityOptions.makeBasic();
-                options.setLaunchDisplayId(getDisplay().getDisplayId());
                 startActivity(intent, options.toBundle());
             }
         }
@@ -127,55 +127,13 @@ public class CarLauncher extends FragmentActivity {
         if (DEBUG) {
             Log.d(TAG, "onCreate(" + getUserId() + ") displayId=" + getDisplayId());
         }
-        // Since MUMD is introduced, CarLauncher can be called in the main display of visible users.
-        // In ideal shape, CarLauncher should handle both driver and passengers together.
-        // But, in the mean time, we have separate launchers for driver and passengers, so
-        // CarLauncher needs to reroute the request to Passenger launcher if it is invoked from
-        // the main display of passengers (not driver).
-        // For MUPAND, PassengerLauncher should be the default launcher.
-        // For non-main displays, ATM will invoke SECONDARY_HOME Intent, so the secondary launcher
-        // should handle them.
+        // Since MUMD/MUPAND is introduced, CarLauncher can be called in the main display of
+        // visible background users.
+        // For Passenger scenarios, replace the maps_card with AppGridActivity, as currently
+        // there is no maps use-case for passengers.
         UserManager um = getSystemService(UserManager.class);
         boolean isPassengerDisplay = getDisplayId() != Display.DEFAULT_DISPLAY
                 || um.isVisibleBackgroundUsersOnDefaultDisplaySupported();
-        if (isPassengerDisplay) {
-            String passengerLauncherName = getString(R.string.config_passengerLauncherComponent);
-            Intent passengerHomeIntent;
-            if (!passengerLauncherName.isEmpty()) {
-                ComponentName component = ComponentName.unflattenFromString(passengerLauncherName);
-                if (component == null) {
-                    throw new IllegalStateException(
-                            "Invalid passengerLauncher name=" + passengerLauncherName);
-                }
-                passengerHomeIntent = new Intent(Intent.ACTION_MAIN)
-                        // passenger launcher should be launched in home task in order to
-                        // fix TaskView layering issue
-                        .addCategory(Intent.CATEGORY_HOME)
-                        .setComponent(component);
-            } else {
-                // No passenger launcher is specified, then use AppsGrid as a fallback.
-                passengerHomeIntent = CarLauncherUtils.getAppsGridIntent();
-            }
-            ActivityOptions options = ActivityOptions
-                    // No animation for the trampoline.
-                    .makeCustomAnimation(this, /* enterResId=*/ 0, /* exitResId= */ 0)
-                    .setLaunchDisplayId(getDisplayId());
-            startActivity(passengerHomeIntent, options.toBundle());
-            finish();
-            return;
-        }
-
-        mUseSmallCanvasOptimizedMap =
-                CarLauncherUtils.isSmallCanvasOptimizedMapIntentConfigured(this);
-
-        mActivityManager = getSystemService(ActivityManager.class);
-        mCarLauncherTaskId = getTaskId();
-        TaskStackChangeListeners.getInstance().registerTaskStackListener(mTaskStackListener);
-
-        // Setting as trusted overlay to let touches pass through.
-        getWindow().addPrivateFlags(PRIVATE_FLAG_TRUSTED_OVERLAY);
-        // To pass touches to the underneath task.
-        getWindow().addFlags(WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL);
 
         // Don't show the maps panel in multi window mode.
         // NOTE: CTS tests for split screen are not compatible with activity views on the default
@@ -184,14 +142,37 @@ public class CarLauncher extends FragmentActivity {
             setContentView(R.layout.car_launcher_multiwindow);
         } else {
             setContentView(R.layout.car_launcher);
-            // We don't want to show Map card unnecessarily for the headless user 0.
-            if (!UserHelperLite.isHeadlessSystemUser(getUserId())) {
-                mMapsCard = findViewById(R.id.maps_card);
-                if (mMapsCard != null) {
-                    setupRemoteCarTaskView(mMapsCard);
+            // Passenger displays do not require TaskView Embedding
+            if (!isPassengerDisplay) {
+                mUseSmallCanvasOptimizedMap =
+                        CarLauncherUtils.isSmallCanvasOptimizedMapIntentConfigured(this);
+
+                mActivityManager = getSystemService(ActivityManager.class);
+                mCarLauncherTaskId = getTaskId();
+                TaskStackChangeListeners.getInstance().registerTaskStackListener(
+                        mTaskStackListener);
+
+                // Setting as trusted overlay to let touches pass through.
+                getWindow().addPrivateFlags(PRIVATE_FLAG_TRUSTED_OVERLAY);
+                // To pass touches to the underneath task.
+                getWindow().addFlags(WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL);
+                // We don't want to show Map card unnecessarily for the headless user 0
+                if (!UserHelperLite.isHeadlessSystemUser(getUserId())) {
+                    mMapsCard = findViewById(R.id.maps_card);
+                    if (mMapsCard != null) {
+                        setupRemoteCarTaskView(mMapsCard);
+                    }
                 }
+            } else {
+                // For Passenger display show the AppGridFragment in place of the Maps view.
+                // Also we can skip initializing all the TaskView related objects as they are not
+                // used in this case.
+                getSupportFragmentManager().beginTransaction().replace(R.id.maps_card,
+                        AppGridFragment.newInstance(ALL_APPS)).commit();
+
             }
         }
+
         MediaIntentRouter.getInstance().registerMediaIntentHandler(mMediaIntentHandler);
         initializeCards();
         setupContentObserversForTos();
@@ -199,8 +180,9 @@ public class CarLauncher extends FragmentActivity {
 
     private void setupRemoteCarTaskView(ViewGroup parent) {
         mCarLauncherViewModel = new ViewModelProvider(this,
-                new CarLauncherViewModelFactory(this, getMapsIntent()))
+                new CarLauncherViewModelFactory(this))
                 .get(CarLauncherViewModel.class);
+        mCarLauncherViewModel.initializeRemoteCarTaskView(getMapsIntent());
 
         getLifecycle().addObserver(mCarLauncherViewModel);
         addOnNewIntentListener(mCarLauncherViewModel.getNewIntentListener());
@@ -230,12 +212,16 @@ public class CarLauncher extends FragmentActivity {
     protected void onDestroy() {
         super.onDestroy();
         TaskStackChangeListeners.getInstance().unregisterTaskStackListener(mTaskStackListener);
+        unregisterTosContentObserver();
+        release();
+    }
+
+    private void unregisterTosContentObserver() {
         if (mTosContentObserver != null) {
             Log.i(TAG, "Unregister content observer for tos state");
             getContentResolver().unregisterContentObserver(mTosContentObserver);
             mTosContentObserver = null;
         }
-        release();
     }
 
     private int getTaskViewTaskId() {
@@ -351,21 +337,36 @@ public class CarLauncher extends FragmentActivity {
                 || !AppLauncherUtils.tosAccepted(/* context = */ this)) {
             Log.i(TAG, "TOS not accepted, setting up content observers for TOS state");
         } else {
-            Log.i(TAG, "TOS accepted, state will remain accepted, "
-                    + "don't need to observe this value");
+            Log.i(TAG,
+                    "TOS accepted, state will remain accepted, don't need to observe this value");
             return;
         }
         mTosContentObserver = new ContentObserver(new Handler()) {
             @Override
             public void onChange(boolean selfChange) {
                 super.onChange(selfChange);
-                // TODO (b/280077391): Release the remote task view and recreate the map activity
-                Log.i(TAG, "TOS state updated:" + AppLauncherUtils.tosAccepted(getBaseContext()));
-                recreate();
+                // Release the task view and re-initialize the remote car task view with the new
+                // maps intent whenever an onChange is received. This is because the TOS state
+                // can go from uninitialized to not accepted during which there could be a race
+                // condition in which the maps activity is from the uninitialized state.
+                Set<String> tosDisabledApps = AppLauncherUtils.getTosDisabledPackages(
+                        getBaseContext());
+                boolean tosAccepted = AppLauncherUtils.tosAccepted(getBaseContext());
+                Log.i(TAG, "TOS state updated:" + tosAccepted);
+                if (DEBUG) {
+                    Log.d(TAG, "TOS disabled apps:" + tosDisabledApps);
+                }
+                if (mCarLauncherViewModel.getRemoteCarTaskView().getValue() != null) {
+                    mCarLauncherViewModel.getRemoteCarTaskView().getValue().release();
+                    setupRemoteCarTaskView(mMapsCard);
+                }
+                if (tosAccepted) {
+                    unregisterTosContentObserver();
+                }
             }
         };
         getContentResolver().registerContentObserver(
-                Settings.Secure.getUriFor(KEY_USER_TOS_ACCEPTED),
+                Settings.Secure.getUriFor(KEY_UNACCEPTED_TOS_DISABLED_APPS),
                 /* notifyForDescendants*/ false,
                 mTosContentObserver);
     }
diff --git a/app/src/com/android/car/carlauncher/CarLauncherViewModel.java b/app/src/com/android/car/carlauncher/CarLauncherViewModel.java
index 8ad6d560..3b2b0813 100644
--- a/app/src/com/android/car/carlauncher/CarLauncherViewModel.java
+++ b/app/src/com/android/car/carlauncher/CarLauncherViewModel.java
@@ -58,19 +58,30 @@ public final class CarLauncherViewModel extends ViewModel implements DefaultLife
 
     private final CarActivityManager mCarActivityManager;
     private final Car mCar;
-    private final CarTaskViewControllerHostLifecycle mHostLifecycle;
     @SuppressLint("StaticFieldLeak") // We're not leaking this context as it is the window context.
     private final Context mWindowContext;
-    private final Intent mMapsIntent;
-    private final MutableLiveData<RemoteCarTaskView> mRemoteCarTaskView;
 
-    public CarLauncherViewModel(@UiContext Context context, @NonNull Intent mapsIntent) {
+    // Do not make this final because the maps intent can be changed based on the state of TOS.
+    private Intent mMapsIntent;
+    private CarTaskViewControllerHostLifecycle mHostLifecycle;
+    private MutableLiveData<RemoteCarTaskView> mRemoteCarTaskView;
+
+    public CarLauncherViewModel(@UiContext Context context) {
         mWindowContext = context.createWindowContext(TYPE_APPLICATION_STARTING, /* options */ null);
-        mMapsIntent = mapsIntent;
         mCar = Car.createCar(mWindowContext);
         mCarActivityManager = mCar.getCarManager(CarActivityManager.class);
-        mHostLifecycle = new CarTaskViewControllerHostLifecycle();
+    }
+
+    /**
+     * Initialize the remote car task view with the maps intent.
+     */
+    void initializeRemoteCarTaskView(@NonNull Intent mapsIntent) {
+        if (DEBUG) {
+            Log.d(TAG, "Maps intent in the task view = " + mapsIntent.getComponent());
+        }
+        mMapsIntent = mapsIntent;
         mRemoteCarTaskView = new MutableLiveData<>(null);
+        mHostLifecycle = new CarTaskViewControllerHostLifecycle();
         ControlledRemoteCarTaskViewCallback controlledRemoteCarTaskViewCallback =
                 new ControlledRemoteCarTaskViewCallbackImpl(mRemoteCarTaskView);
 
@@ -102,7 +113,7 @@ public final class CarLauncherViewModel extends ViewModel implements DefaultLife
     @Override
     public void onResume(@NonNull LifecycleOwner owner) {
         DefaultLifecycleObserver.super.onResume(owner);
-        // Do not trigger 'hostAppeared()'}' in onResume.
+        // Do not trigger 'hostAppeared()' in onResume.
         // If the host Activity was hidden by an Activity, the Activity is moved to the other
         // display, what the system expects would be the new moved Activity becomes the top one.
         // But, at the time, the host Activity became visible and 'onResume()' is triggered.
@@ -218,17 +229,15 @@ public final class CarLauncherViewModel extends ViewModel implements DefaultLife
 
     static final class CarLauncherViewModelFactory implements ViewModelProvider.Factory {
         private final Context mContext;
-        private final Intent mMapsIntent;
 
-        CarLauncherViewModelFactory(@UiContext Context context, @NonNull Intent mapsIntent) {
-            mMapsIntent = requireNonNull(mapsIntent);
+        CarLauncherViewModelFactory(@UiContext Context context) {
             mContext = requireNonNull(context);
         }
 
         @NonNull
         @Override
         public <T extends ViewModel> T create(Class<T> modelClass) {
-            return modelClass.cast(new CarLauncherViewModel(mContext, mMapsIntent));
+            return modelClass.cast(new CarLauncherViewModel(mContext));
         }
     }
 }
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/InCallModel.java b/app/src/com/android/car/carlauncher/homescreen/audio/InCallModel.java
index 82508f5e..9f49eca6 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/InCallModel.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/InCallModel.java
@@ -26,7 +26,6 @@ import android.content.Intent;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
 import android.graphics.drawable.Drawable;
-import android.os.Bundle;
 import android.telecom.Call;
 import android.telecom.CallAudioState;
 import android.telecom.PhoneAccountHandle;
@@ -169,24 +168,16 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
     public Intent getIntent() {
         Intent intent = null;
         if (isSelfManagedCall()) {
-            Bundle extras = mCurrentCall.getDetails().getExtras();
-            ComponentName componentName = extras == null ? null : extras.getParcelable(
-                    Intent.EXTRA_COMPONENT_NAME, ComponentName.class);
-            if (componentName != null) {
-                intent = new Intent();
-                intent.setComponent(componentName);
-            } else {
-                String callingAppPackageName = getCallingAppPackageName();
-                if (!TextUtils.isEmpty(callingAppPackageName)) {
-                    if (isCarAppCallingService(callingAppPackageName)) {
-                        intent = new Intent();
-                        intent.setComponent(
-                                new ComponentName(
-                                        callingAppPackageName, CAR_APP_ACTIVITY_INTERFACE));
-                        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-                    } else {
-                        intent = mPackageManager.getLaunchIntentForPackage(callingAppPackageName);
-                    }
+            String callingAppPackageName = getCallingAppPackageName();
+            if (!TextUtils.isEmpty(callingAppPackageName)) {
+                if (isCarAppCallingService(callingAppPackageName)) {
+                    intent = new Intent();
+                    intent.setComponent(
+                             new ComponentName(
+                                    callingAppPackageName, CAR_APP_ACTIVITY_INTERFACE));
+                    intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+                } else {
+                    intent = mPackageManager.getLaunchIntentForPackage(callingAppPackageName);
                 }
             }
         } else {
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/MediaViewModel.java b/app/src/com/android/car/carlauncher/homescreen/audio/MediaViewModel.java
index 8210572d..e320c1cd 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/MediaViewModel.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/MediaViewModel.java
@@ -32,6 +32,7 @@ import androidx.lifecycle.Observer;
 
 import com.android.car.apps.common.imaging.ImageBinder;
 import com.android.car.carlauncher.Flags;
+import com.android.car.carlauncher.MediaSessionUtils;
 import com.android.car.carlauncher.homescreen.HomeCardInterface;
 import com.android.car.carlauncher.homescreen.ui.CardContent;
 import com.android.car.carlauncher.homescreen.ui.CardHeader;
@@ -137,7 +138,7 @@ public class MediaViewModel extends AndroidViewModel implements AudioModel {
     public void onCreate(@NonNull Context context) {
         // Initialize media data with media session sources or mbt sources
         if (Flags.mediaSessionCard()) {
-            MediaModels mediaModels = new MediaModels(context);
+            MediaModels mediaModels = MediaSessionUtils.getMediaModels(context);
             if (mSourceViewModel == null) {
                 mSourceViewModel = mediaModels.getMediaSourceViewModel();
             }
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardController.java b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardController.java
index 0f365a5f..655428a3 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardController.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardController.java
@@ -16,12 +16,17 @@
 
 package com.android.car.carlauncher.homescreen.audio.media;
 
+import static com.android.car.media.common.ui.PlaybackCardControllerUtilities.getFirstCustomActionInSet;
+import static com.android.car.media.common.ui.PlaybackCardControllerUtilities.skipBackStandardActions;
+import static com.android.car.media.common.ui.PlaybackCardControllerUtilities.skipForwardStandardActions;
 import static com.android.car.media.common.ui.PlaybackCardControllerUtilities.updatePlayButtonWithPlaybackState;
 
+import static java.lang.Integer.max;
+
 import android.content.Intent;
-import android.content.res.ColorStateList;
 import android.content.res.Resources;
 import android.graphics.drawable.Drawable;
+import android.net.Uri;
 import android.os.Handler;
 import android.os.Looper;
 import android.view.GestureDetector;
@@ -34,19 +39,23 @@ import android.widget.LinearLayout;
 import androidx.constraintlayout.motion.widget.MotionLayout;
 import androidx.viewpager2.widget.ViewPager2;
 
+import com.android.car.apps.common.RoundedDrawable;
 import com.android.car.apps.common.util.ViewUtils;
 import com.android.car.carlauncher.R;
+import com.android.car.media.common.CustomPlaybackAction;
 import com.android.car.media.common.MediaItemMetadata;
 import com.android.car.media.common.playback.PlaybackProgress;
 import com.android.car.media.common.playback.PlaybackViewModel;
 import com.android.car.media.common.playback.PlaybackViewModel.PlaybackController;
 import com.android.car.media.common.playback.PlaybackViewModel.PlaybackStateWrapper;
 import com.android.car.media.common.source.MediaSource;
-import com.android.car.media.common.source.MediaSourceColors;
 import com.android.car.media.common.ui.PlaybackCardController;
 import com.android.car.media.common.ui.PlaybackHistoryController;
 import com.android.car.media.common.ui.PlaybackQueueController;
 
+import java.util.ArrayList;
+import java.util.List;
+
 public class MediaCardController extends PlaybackCardController implements
         MediaCardPanelViewPagerAdapter.ViewPagerQueueCreator,
         MediaCardPanelViewPagerAdapter.ViewPagerHistoryCreator {
@@ -116,13 +125,10 @@ public class MediaCardController extends PlaybackCardController implements
         mViewResources = mView.getContext().getResources();
 
         mView.setOnClickListener(view -> {
-            if (mCardViewModel.getPanelExpanded()) {
-                animateClosePanel();
-            } else {
-                MediaSource mediaSource = mDataModel.getMediaSource().getValue();
-                Intent intent = mediaSource != null ? mediaSource.getIntent() : null;
-                mMediaIntentRouter.handleMediaIntent(intent);
-            }
+            launchMediaAppOrClosePanel();
+        });
+        mView.findViewById(R.id.empty_panel).setOnClickListener(view -> {
+            launchMediaAppOrClosePanel();
         });
 
         mPager = mView.findViewById(R.id.view_pager);
@@ -166,6 +172,7 @@ public class MediaCardController extends PlaybackCardController implements
                 if (mCardViewModel.getPanelExpanded()) {
                     mSkipPrevButton.setVisibility(View.GONE);
                     mSkipNextButton.setVisibility(View.GONE);
+                    mLogo.setVisibility(View.GONE);
                 }
             }
 
@@ -222,7 +229,10 @@ public class MediaCardController extends PlaybackCardController implements
 
     @Override
     protected void updateAlbumCoverWithDrawable(Drawable drawable) {
-        super.updateAlbumCoverWithDrawable(drawable);
+        RoundedDrawable roundedDrawable = new RoundedDrawable(drawable, mView.getResources()
+                .getFloat(R.dimen.media_card_album_art_drawable_corner_ratio));
+        super.updateAlbumCoverWithDrawable(roundedDrawable);
+
         if (mCardViewModel.getPanelExpanded()) {
             mAlbumCoverVisibility = mAlbumCover.getVisibility();
             mAlbumCover.setVisibility(View.INVISIBLE);
@@ -249,24 +259,14 @@ public class MediaCardController extends PlaybackCardController implements
     @Override
     protected void updateProgress(PlaybackProgress progress) {
         super.updateProgress(progress);
+        ViewUtils.setVisible(mSeekBar, progress != null && progress.hasTime());
         if (progress == null || !progress.hasTime()) {
-            mSeekBar.setVisibility(View.GONE);
             mLogo.setVisibility(View.GONE);
-        }
-    }
-
-    @Override
-    protected void updateViewsWithMediaSourceColors(MediaSourceColors colors) {
-        int defaultColor = mViewResources.getColor(R.color.car_on_surface, /* theme */ null);
-        ColorStateList accentColor = colors != null ? ColorStateList.valueOf(
-                colors.getAccentColor(defaultColor)) :
-                ColorStateList.valueOf(defaultColor);
-
-        if (mPlayPauseButton != null) {
-            mPlayPauseButton.setBackgroundTintList(accentColor);
-        }
-        if (mSeekBar != null) {
-            mSeekBar.setProgressTintList(accentColor);
+        } else if (mDataModel.getMetadata().getValue() != null) {
+            Uri logoUri = mLogo.prepareToDisplay(mDataModel.getMetadata().getValue());
+            if (logoUri != null && !mCardViewModel.getPanelExpanded()) {
+                mLogo.setVisibility(View.VISIBLE);
+            }
         }
     }
 
@@ -275,9 +275,19 @@ public class MediaCardController extends PlaybackCardController implements
         PlaybackController playbackController = mDataModel.getPlaybackController().getValue();
         if (playbackState != null) {
             updatePlayButtonWithPlaybackState(mPlayPauseButton, playbackState, playbackController);
-            updateSkipButtonsWithPlaybackState(playbackState, playbackController);
+            List<PlaybackViewModel.RawCustomPlaybackAction> usedCustomActions =
+                    updateSkipButtonsAndReturnUsedStandardCustomActions(
+                            playbackState, playbackController);
+
+            boolean hasCustomActions = playbackState.getCustomActions().size() != 0;
+            boolean isPreviouslyVisible = ViewUtils.isVisible(mActionOverflowButton);
+            ViewUtils.setVisible(mActionOverflowButton, hasCustomActions);
+            mPagerAdapter.setHasOverflow(hasCustomActions);
+            if (mCardViewModel.getPanelExpanded() && isPreviouslyVisible != hasCustomActions) {
+                animateClosePanel();
+            }
             mPagerAdapter.notifyPlaybackStateChanged(playbackState,
-                    playbackController);
+                    playbackController, usedCustomActions);
         } else {
             mSkipPrevButton.setVisibility(View.GONE);
             mSkipNextButton.setVisibility(View.GONE);
@@ -314,7 +324,7 @@ public class MediaCardController extends PlaybackCardController implements
         super.updateQueueState(hasQueue, isQueueVisible);
         mPagerAdapter.setHasQueue(hasQueue);
         ViewUtils.setVisible(mQueueButton, hasQueue);
-        if (mCardViewModel.getPanelExpanded()) {
+        if (mCardViewModel.getPanelExpanded() && !hasQueue) {
             animateClosePanel();
         }
     }
@@ -428,6 +438,16 @@ public class MediaCardController extends PlaybackCardController implements
         }
     }
 
+    private void launchMediaAppOrClosePanel() {
+        if (mCardViewModel.getPanelExpanded()) {
+            animateClosePanel();
+        } else {
+            MediaSource mediaSource = mDataModel.getMediaSource().getValue();
+            Intent intent = mediaSource != null ? mediaSource.getIntent() : null;
+            mMediaIntentRouter.handleMediaIntent(intent);
+        }
+    }
+
     private void animateClosePanel() {
         mCardViewModel.setPanelExpanded(false);
         mMotionLayout.transitionToStart();
@@ -478,57 +498,130 @@ public class MediaCardController extends PlaybackCardController implements
         mLogo.setVisibility(mLogoVisibility);
     }
 
-    private void updateSkipButtonsWithPlaybackState(PlaybackStateWrapper playbackState,
+    /**
+     * Set the mSkipNextButton and mSkipPrevButton with a skip action Drawable if sent by the
+     * playbackState, otherwise with a skipForwardStandardAction and skipBackStandardAction
+     * respectively. If none exist, hide the button.
+     */
+    private List<PlaybackViewModel.RawCustomPlaybackAction>
+            updateSkipButtonsAndReturnUsedStandardCustomActions(PlaybackStateWrapper playbackState,
             PlaybackController playbackController) {
-        boolean isSkipPrevEnabled = playbackState.isSkipPreviousEnabled();
-        boolean isSkipPrevReserved = playbackState.iSkipPreviousReserved();
+        List<PlaybackViewModel.RawCustomPlaybackAction> usedCustomActions =
+                new ArrayList<PlaybackViewModel.RawCustomPlaybackAction>();
+        updateSkipNextButtonWithSkipOrStandardAction(playbackState, playbackController,
+                usedCustomActions);
+        updateSkipPrevButtonWithSkipOrStandardAction(playbackState, playbackController,
+                usedCustomActions);
+        return usedCustomActions;
+    }
+
+    private void updateSkipNextButtonWithSkipOrStandardAction(
+            PlaybackStateWrapper playbackState, PlaybackController playbackController,
+            List<PlaybackViewModel.RawCustomPlaybackAction> usedCustomActions) {
         boolean isSkipNextEnabled = playbackState.isSkipNextEnabled();
         boolean isSkipNextReserved = playbackState.isSkipNextReserved();
         if ((isSkipNextEnabled || isSkipNextReserved)) {
-            mSkipNextButton.setImageDrawable(mView.getContext().getDrawable(
-                    com.android.car.media.common.R.drawable.ic_skip_next));
-            mSkipNextButton.setBackground(mView.getContext().getDrawable(
-                    R.drawable.dark_circle_button_background));
-            ViewUtils.setVisible(mSkipNextButton, true);
-            mSkipNextButton.setEnabled(isSkipNextEnabled);
-            mSkipNextButton.setOnClickListener(v -> {
+            updateButton(mSkipNextButton, mView.getContext().getDrawable(
+                    com.android.car.media.common.R.drawable.ic_skip_next),
+                    mView.getContext().getDrawable(R.drawable.circle_button_background),
+                    true, isSkipNextEnabled, (v) -> {
                 if (playbackController != null) {
                     playbackController.skipToNext();
                 }
             });
         } else {
-            mSkipNextButton.setBackground(null);
-            mSkipNextButton.setImageDrawable(null);
-            ViewUtils.setVisible(mSkipNextButton, false);
+            PlaybackViewModel.RawCustomPlaybackAction skipForwardCustomAction =
+                    getFirstCustomActionInSet(playbackState.getCustomActions(),
+                            skipForwardStandardActions);
+            if (skipForwardCustomAction != null) {
+                boolean isCustomActionUsed =
+                        updateButtonWithCustomAction(mSkipNextButton, skipForwardCustomAction,
+                                playbackController);
+                if (isCustomActionUsed) {
+                    usedCustomActions.add(skipForwardCustomAction);
+                }
+            } else {
+                updateButton(mSkipNextButton, null, null, false, false, null);
+            }
         }
+    }
+
+    private void updateSkipPrevButtonWithSkipOrStandardAction(
+            PlaybackStateWrapper playbackState, PlaybackController playbackController,
+            List<PlaybackViewModel.RawCustomPlaybackAction> usedCustomActions) {
+        boolean isSkipPrevEnabled = playbackState.isSkipPreviousEnabled();
+        boolean isSkipPrevReserved = playbackState.iSkipPreviousReserved();
         if ((isSkipPrevEnabled || isSkipPrevReserved)) {
-            mSkipPrevButton.setImageDrawable(mView.getContext().getDrawable(
-                    com.android.car.media.common.R.drawable.ic_skip_previous));
-            mSkipPrevButton.setBackground(mView.getContext().getDrawable(
-                    R.drawable.dark_circle_button_background));
-            ViewUtils.setVisible(mSkipPrevButton, true);
-            mSkipPrevButton.setEnabled(isSkipNextEnabled);
-            mSkipPrevButton.setOnClickListener(v -> {
+            updateButton(mSkipPrevButton, mView.getContext().getDrawable(
+                    com.android.car.media.common.R.drawable.ic_skip_previous),
+                    mView.getContext().getDrawable(R.drawable.circle_button_background),
+                    true, isSkipPrevEnabled, (v) -> {
+                    if (playbackController != null) {
+                        playbackController.skipToPrevious();
+                    }
+                });
+        } else {
+            PlaybackViewModel.RawCustomPlaybackAction skipBackCustomAction =
+                    getFirstCustomActionInSet(playbackState.getCustomActions(),
+                            skipBackStandardActions);
+            if (skipBackCustomAction != null) {
+                boolean isCustomActionUsed =
+                        updateButtonWithCustomAction(mSkipPrevButton, skipBackCustomAction,
+                                playbackController);
+                if (isCustomActionUsed) {
+                    usedCustomActions.add(skipBackCustomAction);
+                }
+            } else {
+                updateButton(mSkipPrevButton, null, null, false, false, null);
+            }
+        }
+    }
+
+    private void updateButton(ImageButton button, Drawable imageDrawable,
+            Drawable backgroundDrawable, boolean isVisible, boolean isEnabled,
+            View.OnClickListener listener) {
+        button.setImageDrawable(imageDrawable);
+        button.setBackground(backgroundDrawable);
+        ViewUtils.setVisible(button, isVisible);
+        button.setEnabled(isEnabled);
+        button.setOnClickListener(listener);
+    }
+
+    private boolean updateButtonWithCustomAction(ImageButton button,
+            PlaybackViewModel.RawCustomPlaybackAction rawCustomAction,
+            PlaybackController playbackController) {
+        CustomPlaybackAction customAction = rawCustomAction
+                .fetchDrawable(mView.getContext());
+        if (customAction != null) {
+            updateButton(button, customAction.mIcon, mView.getContext().getDrawable(
+                    R.drawable.circle_button_background), true, true, (v) -> {
                 if (playbackController != null) {
-                    playbackController.skipToPrevious();
+                        playbackController.doCustomAction(
+                                customAction.mAction, customAction.mExtras);
                 }
             });
+            return true;
         } else {
-            mSkipPrevButton.setBackground(null);
-            mSkipPrevButton.setImageDrawable(null);
-            ViewUtils.setVisible(mSkipPrevButton, false);
+            updateButton(button, null, null, false, false, null);
+            return false;
         }
     }
 
     private int getOverflowTabIndex() {
-        return 0;
+        return hasOverflow() ? 0 : -1;
     }
 
     private int getQueueTabIndex() {
-        return getMediaHasQueue() ? 1 : -1;
+        if (!getMediaHasQueue()) return -1;
+        return getOverflowTabIndex() + 1;
     }
 
     private int getHistoryTabIndex() {
-        return getMediaHasQueue() ? 2 : 1;
+        return max(getOverflowTabIndex(), getQueueTabIndex()) + 1;
+    }
+
+    private boolean hasOverflow() {
+        PlaybackStateWrapper playbackState = mDataModel.getPlaybackStateWrapper().getValue();
+        return playbackState != null && playbackState.getCustomActions().size() != 0;
     }
 }
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardFragment.java b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardFragment.java
index 597b886c..e5e3ebe3 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardFragment.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardFragment.java
@@ -41,8 +41,10 @@ import androidx.lifecycle.ViewModelProvider;
 
 import com.android.car.apps.common.BitmapUtils;
 import com.android.car.carlauncher.Flags;
+import com.android.car.carlauncher.MediaSessionUtils;
 import com.android.car.carlauncher.R;
 import com.android.car.carlauncher.homescreen.HomeCardFragment;
+import com.android.car.carlauncher.homescreen.HomeCardInterface;
 import com.android.car.carlauncher.homescreen.audio.MediaViewModel;
 import com.android.car.carlauncher.homescreen.ui.CardContent;
 import com.android.car.carlauncher.homescreen.ui.DescriptiveTextWithControlsView;
@@ -140,7 +142,7 @@ public class MediaCardFragment extends HomeCardFragment {
         } else {
             mViewModel = new ViewModelProvider(requireActivity()).get(MediaCardViewModel.class);
             if (mViewModel.needsInitialization()) {
-                MediaModels models = new MediaModels(getActivity());
+                MediaModels models = MediaSessionUtils.getMediaModels(getContext());
                 mViewModel.init(models);
             }
         }
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardPanelViewPagerAdapter.java b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardPanelViewPagerAdapter.java
index 3cb7b19d..007bbf2e 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardPanelViewPagerAdapter.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardPanelViewPagerAdapter.java
@@ -16,6 +16,10 @@
 
 package com.android.car.carlauncher.homescreen.audio.media;
 
+import static com.android.car.carlauncher.homescreen.audio.media.MediaCardPanelViewPagerAdapter.Tab.HistoryTab;
+import static com.android.car.carlauncher.homescreen.audio.media.MediaCardPanelViewPagerAdapter.Tab.OverflowTab;
+import static com.android.car.carlauncher.homescreen.audio.media.MediaCardPanelViewPagerAdapter.Tab.QueueTab;
+
 import android.content.Context;
 import android.content.res.ColorStateList;
 import android.graphics.Color;
@@ -47,8 +51,14 @@ public class MediaCardPanelViewPagerAdapter extends
     private boolean mHasQueue;
     private ViewPagerQueueCreator mQueueCreator;
     private ViewPagerHistoryCreator mHistoryCreator;
+
+    private boolean mHasOverflow;
     private PlaybackStateWrapper mPlaybackState;
     private PlaybackController mPlaybackController;
+    private List<PlaybackViewModel.RawCustomPlaybackAction> mCustomActionsToExclude =
+            new ArrayList<PlaybackViewModel.RawCustomPlaybackAction>();
+
+    enum Tab { OverflowTab, QueueTab, HistoryTab };
 
     public MediaCardPanelViewPagerAdapter(Context context) {
         this.mContext = context;
@@ -66,53 +76,30 @@ public class MediaCardPanelViewPagerAdapter extends
         TableLayout overflowGrid = holder.itemView.findViewById(R.id.overflow_grid);
         FrameLayout queue = holder.itemView.findViewById(R.id.queue_list_container);
         FrameLayout history = holder.itemView.findViewById(R.id.history_list_container);
-        if (mHasQueue) {
-            switch(position) {
-                case 0: {
-                    updateCustomActionsWithPlaybackState(holder.itemView);
-                    overflowGrid.setVisibility(View.VISIBLE);
-                    queue.setVisibility(View.GONE);
-                    history.setVisibility(View.GONE);
-                    break;
-                }
-                case 1: {
-                    mQueueCreator.createQueueController(queue);
-                    queue.setVisibility(View.VISIBLE);
-                    overflowGrid.setVisibility(View.GONE);
-                    history.setVisibility(View.GONE);
-                    break;
-                }
-                case 2: {
-                    mHistoryCreator.createHistoryController(history);
-                    history.setVisibility(View.VISIBLE);
-                    overflowGrid.setVisibility(View.GONE);
-                    queue.setVisibility(View.GONE);
-                    break;
-                }
+
+        Tab tab = getTab(position);
+        switch (tab) {
+            case OverflowTab: {
+                updateCustomActionsWithPlaybackState(holder.itemView);
+                break;
             }
-        } else {
-            switch(position) {
-                case 0: {
-                    updateCustomActionsWithPlaybackState(holder.itemView);
-                    overflowGrid.setVisibility(View.VISIBLE);
-                    queue.setVisibility(View.GONE);
-                    history.setVisibility(View.GONE);
-                    break;
-                }
-                case 1: {
-                    mHistoryCreator.createHistoryController(history);
-                    history.setVisibility(View.VISIBLE);
-                    overflowGrid.setVisibility(View.GONE);
-                    queue.setVisibility(View.GONE);
-                    break;
-                }
+            case QueueTab: {
+                mQueueCreator.createQueueController(queue);
+                break;
+            }
+            case HistoryTab: {
+                mHistoryCreator.createHistoryController(history);
+                break;
             }
         }
+        overflowGrid.setVisibility(tab == OverflowTab ? View.VISIBLE : View.GONE);
+        queue.setVisibility(tab == QueueTab ? View.VISIBLE : View.GONE);
+        history.setVisibility(tab == HistoryTab ? View.VISIBLE : View.GONE);
     }
 
     @Override
     public int getItemCount() {
-        return mHasQueue ? 3 : 2;
+        return mHasQueue && mHasOverflow ? 3 : (!mHasQueue && !mHasOverflow ? 1 : 2);
     }
 
     /** Notify ViewHolder to rebind when a media source queue status changes */
@@ -129,12 +116,25 @@ public class MediaCardPanelViewPagerAdapter extends
         mHistoryCreator = historyCreator;
     }
 
+    /** Notify ViewHolder to rebind when a media source overflow status changes */
+    public void setHasOverflow(boolean hasOverflow) {
+        if (mHasOverflow != hasOverflow) {
+            mHasOverflow = hasOverflow;
+            notifyDataSetChanged();
+        }
+    }
+
     /** Notify a change in playback state so ViewHolder binds with latest update */
     public void notifyPlaybackStateChanged(PlaybackStateWrapper playbackState,
-            PlaybackController playbackController) {
+            PlaybackController playbackController,
+            List<PlaybackViewModel.RawCustomPlaybackAction> customActionsToExclude) {
         mPlaybackState = playbackState;
         mPlaybackController = playbackController;
-        notifyItemChanged(0);
+        mCustomActionsToExclude.clear();
+        mCustomActionsToExclude.addAll(customActionsToExclude);
+        if (mHasOverflow) {
+            notifyItemChanged(0);
+        }
     }
 
     private void updateCustomActionsWithPlaybackState(View itemView) {
@@ -145,6 +145,7 @@ public class MediaCardPanelViewPagerAdapter extends
         List<PlaybackViewModel.RawCustomPlaybackAction> customActions = mPlaybackState == null
                 ? new ArrayList<PlaybackViewModel.RawCustomPlaybackAction>()
                 : mPlaybackState.getCustomActions();
+        customActions.removeAll(mCustomActionsToExclude);
         List<ImageButton> actionsToFill = new ArrayList<>();
         for (int i = 0; i < actions.size(); i++) {
             ImageButton button = actions.get(i);
@@ -184,6 +185,25 @@ public class MediaCardPanelViewPagerAdapter extends
         }
     }
 
+    private Tab getTab(int index) {
+        if (index == getQueueTabIndex()) {
+            return QueueTab;
+        } else if (index == getOverflowTabIndex()) {
+            return OverflowTab;
+        } else {
+            return HistoryTab;
+        }
+    }
+
+    private int getQueueTabIndex() {
+        if (!mHasQueue) return -1;
+        return getOverflowTabIndex() + 1;
+    }
+
+    private int getOverflowTabIndex() {
+        return mHasOverflow ? 0 : -1;
+    }
+
     static class PanelViewHolder extends RecyclerView.ViewHolder {
 
         PanelViewHolder(@NonNull View itemView) {
diff --git a/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java b/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
index 7458a69a..e5e3c1ba 100644
--- a/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
+++ b/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
@@ -17,7 +17,7 @@
 package com.android.car.carlauncher.recents;
 
 import static com.android.car.carlauncher.recents.CarRecentsActivity.OPEN_RECENT_TASK_ACTION;
-import static com.android.wm.shell.sysui.ShellSharedConstants.KEY_EXTRA_SHELL_RECENT_TASKS;
+import static com.android.wm.shell.shared.ShellSharedConstants.KEY_EXTRA_SHELL_RECENT_TASKS;
 
 import android.app.ActivityManager;
 import android.app.Service;
@@ -31,6 +31,7 @@ import android.os.RemoteException;
 import androidx.annotation.Nullable;
 
 import com.android.systemui.shared.recents.IOverviewProxy;
+import com.android.systemui.shared.statusbar.phone.BarTransitions;
 import com.android.systemui.shared.system.QuickStepContract.SystemUiStateFlags;
 import com.android.wm.shell.recents.IRecentTasks;
 
@@ -160,6 +161,11 @@ public class CarQuickStepService extends Service {
             // no-op
         }
 
+        @Override
+        public void onTransitionModeUpdated(int barMode, boolean checkBarModes) {
+            // no-op
+        }
+
         @Override
         public void onNavButtonsDarkIntensityChanged(float darkIntensity) {
             // no-op
@@ -179,5 +185,36 @@ public class CarQuickStepService extends Service {
         public void onTaskbarToggled() {
             // no-op
         }
+
+        @Override
+        public void updateWallpaperVisibility(int displayId, boolean visible) {
+            // no-op
+        }
+
+        @Override
+        public void checkNavBarModes() {
+            // no-op
+        }
+
+        @Override
+        public void finishBarAnimations() {
+            // no-op
+        }
+
+        @Override
+        public void touchAutoDim(boolean reset) {
+            // no-op
+        }
+
+        @Override
+        public void transitionTo(@BarTransitions.TransitionMode int barMode,
+                boolean animate) {
+            // no-op
+        }
+
+        @Override
+        public void appTransitionPending(boolean pending) {
+            // no-op
+        }
     }
 }
diff --git a/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java b/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java
index 13b9f473..ec1b4af8 100644
--- a/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java
+++ b/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java
@@ -18,9 +18,9 @@ package com.android.car.carlauncher.recents;
 
 import static android.app.ActivityManager.RECENT_IGNORE_UNAVAILABLE;
 
-import static com.android.wm.shell.util.GroupedRecentTaskInfo.TYPE_FREEFORM;
-import static com.android.wm.shell.util.GroupedRecentTaskInfo.TYPE_SINGLE;
-import static com.android.wm.shell.util.GroupedRecentTaskInfo.TYPE_SPLIT;
+import static com.android.wm.shell.shared.GroupedRecentTaskInfo.TYPE_FREEFORM;
+import static com.android.wm.shell.shared.GroupedRecentTaskInfo.TYPE_SINGLE;
+import static com.android.wm.shell.shared.GroupedRecentTaskInfo.TYPE_SPLIT;
 
 import android.app.Activity;
 import android.app.ActivityManager;
@@ -49,7 +49,7 @@ import com.android.systemui.shared.system.PackageManagerWrapper;
 import com.android.systemui.shared.system.TaskStackChangeListener;
 import com.android.systemui.shared.system.TaskStackChangeListeners;
 import com.android.wm.shell.recents.IRecentTasks;
-import com.android.wm.shell.util.GroupedRecentTaskInfo;
+import com.android.wm.shell.shared.GroupedRecentTaskInfo;
 
 import com.google.common.annotations.VisibleForTesting;
 
diff --git a/app/tests/Android.bp b/app/tests/Android.bp
index 8b22cac9..0eb8b297 100644
--- a/app/tests/Android.bp
+++ b/app/tests/Android.bp
@@ -16,6 +16,7 @@
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_system_experience",
 }
 
 android_test {
@@ -27,7 +28,7 @@ android_test {
 
     libs: [
         "android.car",
-        "android.test.base",
+        "android.test.base.stubs.system",
         "android.car-system-stubs",
     ],
 
@@ -54,6 +55,9 @@ android_test {
         "flag-junit",
     ],
 
+    // b/341652226: temporarily disable multi-dex until D8 is fixed
+    no_dex_container: true,
+
     platform_apis: true,
 
     certificate: "platform",
diff --git a/app/tests/res/values-en-rCA/strings.xml b/app/tests/res/values-en-rCA/strings.xml
new file mode 100644
index 00000000..42f3ece2
--- /dev/null
+++ b/app/tests/res/values-en-rCA/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+  ~ Copyright (C) 2023 The Android Open Source Project
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
+   -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_test_title" msgid="5099375056282404070">"CarLauncherTests"</string>
+</resources>
diff --git a/app/tests/src/com/android/car/carlauncher/CarLauncherTest.java b/app/tests/src/com/android/car/carlauncher/CarLauncherTest.java
index e5eb297f..d62d0feb 100644
--- a/app/tests/src/com/android/car/carlauncher/CarLauncherTest.java
+++ b/app/tests/src/com/android/car/carlauncher/CarLauncherTest.java
@@ -16,45 +16,52 @@
 
 package com.android.car.carlauncher;
 
+import static android.car.settings.CarSettings.Secure.KEY_UNACCEPTED_TOS_DISABLED_APPS;
 import static android.car.settings.CarSettings.Secure.KEY_USER_TOS_ACCEPTED;
 
 import static androidx.test.espresso.Espresso.onView;
 import static androidx.test.espresso.assertion.ViewAssertions.matches;
+import static androidx.test.espresso.matcher.RootMatchers.hasWindowLayoutParams;
 import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
 import static androidx.test.espresso.matcher.ViewMatchers.withId;
 
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.hamcrest.CoreMatchers.not;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.mockito.ArgumentMatchers.any;
 
+import android.car.app.RemoteCarTaskView;
 import android.car.test.mocks.AbstractExtendedMockitoTestCase;
-import android.car.user.CarUserManager;
 import android.content.Intent;
+import android.platform.test.annotations.RequiresFlagsDisabled;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
 import android.provider.Settings;
 import android.testing.TestableContext;
 import android.util.ArraySet;
+import android.view.WindowManager;
 
 import androidx.lifecycle.Lifecycle;
 import androidx.test.InstrumentationRegistry;
 import androidx.test.core.app.ActivityScenario;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
-import androidx.test.filters.Suppress;
 
 import org.junit.After;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.mockito.Mock;
 
 import java.net.URISyntaxException;
 import java.util.Set;
 
-@Suppress // To be ignored until b/224978827 is fixed
 @RunWith(AndroidJUnit4.class)
 @SmallTest
 public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
@@ -63,8 +70,9 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
     public TestableContext mContext = new TestableContext(InstrumentationRegistry.getContext());
     private ActivityScenario<CarLauncher> mActivityScenario;
 
-    @Mock
-    private CarUserManager mMockCarUserManager;
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule =
+            DeviceFlagsValueProvider.createCheckFlagsRule();
 
     private static final String TOS_MAP_INTENT = "intent:#Intent;"
             + "component=com.android.car.carlauncher/"
@@ -77,6 +85,11 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
     private static final String CUSTOM_MAP_INTENT = "intent:#Intent;component=com.custom.car.maps/"
             + "com.custom.car.maps.MapActivity;"
             + "action=android.intent.action.MAIN;end";
+    // TOS disabled app list is non empty when TOS is not accepted.
+    private static final String NON_EMPTY_TOS_DISABLED_APPS =
+            "com.test.package1, com.test.package2";
+    // TOS disabled app list is empty when TOS has been accepted or uninitialized.
+    private static final String EMPTY_TOS_DISABLED_APPS = "";
 
     @Override
     protected void onSessionBuilder(CustomMockitoSessionBuilder session) {
@@ -93,26 +106,40 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
 
     @Test
     public void onResume_mapsCard_isVisible() {
-        mActivityScenario = ActivityScenario.launch(CarLauncher.class);
-        mActivityScenario.moveToState(Lifecycle.State.RESUMED);
+        setUpActivityScenario();
 
-        onView(withId(R.id.maps_card)).check(matches(isDisplayed()));
+        onView(withId(R.id.maps_card))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
     }
 
     @Test
+    @RequiresFlagsDisabled(Flags.FLAG_MEDIA_CARD_FULLSCREEN)
     public void onResume_assistiveCard_isVisible() {
-        mActivityScenario = ActivityScenario.launch(CarLauncher.class);
-        mActivityScenario.moveToState(Lifecycle.State.RESUMED);
+        setUpActivityScenario();
+
+        onView(withId(R.id.top_card))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_MEDIA_CARD_FULLSCREEN)
+    public void onResume_fullscreenMediaCard_assistiveCard_isGone() {
+        setUpActivityScenario();
 
-        onView(withId(R.id.top_card)).check(matches(isDisplayed()));
+        onView(withId(R.id.top_card))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
     }
 
     @Test
     public void onResume_audioCard_isVisible() {
-        mActivityScenario = ActivityScenario.launch(CarLauncher.class);
-        mActivityScenario.moveToState(Lifecycle.State.RESUMED);
+        setUpActivityScenario();
 
-        onView(withId(R.id.bottom_card)).check(matches(isDisplayed()));
+        onView(withId(R.id.bottom_card))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
     }
 
     @Test
@@ -181,9 +208,11 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
     }
 
     @Test
-    public void onCreate_tosStateContentObserver_tosAccepted() {
+    public void onCreate_whenTosAccepted_tosContentObserverIsNull() {
         TestableContext mContext = new TestableContext(InstrumentationRegistry.getContext());
         Settings.Secure.putInt(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, 2);
+        Settings.Secure.putString(mContext.getContentResolver(), KEY_UNACCEPTED_TOS_DISABLED_APPS,
+                EMPTY_TOS_DISABLED_APPS);
 
         mActivityScenario = ActivityScenario.launch(new Intent(mContext, CarLauncher.class));
         mActivityScenario.moveToState(Lifecycle.State.RESUMED);
@@ -195,9 +224,11 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
     }
 
     @Test
-    public void onCreate_registerTosStateContentObserver_tosNotAccepted() {
+    public void onCreate_whenTosNotAccepted_tosContentObserverIsNotNull() {
         TestableContext mContext = new TestableContext(InstrumentationRegistry.getContext());
         Settings.Secure.putInt(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, 1);
+        Settings.Secure.putString(mContext.getContentResolver(), KEY_UNACCEPTED_TOS_DISABLED_APPS,
+                NON_EMPTY_TOS_DISABLED_APPS);
 
         mActivityScenario = ActivityScenario.launch(new Intent(mContext, CarLauncher.class));
         mActivityScenario.moveToState(Lifecycle.State.RESUMED);
@@ -209,9 +240,11 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
     }
 
     @Test
-    public void onCreate_registerTosStateContentObserver_tosNotInitialized() {
+    public void onCreate_whenTosNotInitialized_tosContentObserverIsNotNull() {
         TestableContext mContext = new TestableContext(InstrumentationRegistry.getContext());
         Settings.Secure.putInt(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, 0);
+        Settings.Secure.putString(mContext.getContentResolver(), KEY_UNACCEPTED_TOS_DISABLED_APPS,
+                EMPTY_TOS_DISABLED_APPS);
 
         mActivityScenario = ActivityScenario.launch(new Intent(mContext, CarLauncher.class));
         mActivityScenario.moveToState(Lifecycle.State.RESUMED);
@@ -223,9 +256,11 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
     }
 
     @Test
-    public void recreate_tosStateContentObserver_tosNotAccepted() {
+    public void recreate_afterTosIsAccepted_tosStateContentObserverIsNull() {
         TestableContext mContext = new TestableContext(InstrumentationRegistry.getContext());
-        Settings.Secure.putInt(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, 1);
+        Settings.Secure.putInt(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, 0);
+        Settings.Secure.putString(mContext.getContentResolver(), KEY_UNACCEPTED_TOS_DISABLED_APPS,
+                NON_EMPTY_TOS_DISABLED_APPS);
 
         mActivityScenario = ActivityScenario.launch(new Intent(mContext, CarLauncher.class));
 
@@ -234,30 +269,94 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
 
             // Accept TOS
             Settings.Secure.putInt(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, 2);
+            Settings.Secure.putString(mContext.getContentResolver(),
+                    KEY_UNACCEPTED_TOS_DISABLED_APPS, EMPTY_TOS_DISABLED_APPS);
             activity.mTosContentObserver.onChange(true);
         });
+
         // Content observer is null after recreate
         mActivityScenario.onActivity(activity -> assertNull(activity.mTosContentObserver));
     }
 
     @Test
-    public void recreate_tosStateContentObserver_tosNotInitialized() {
+    public void recreate_afterTosIsInitialized_tosStateContentObserverIsNotNull() {
         TestableContext mContext = new TestableContext(InstrumentationRegistry.getContext());
         Settings.Secure.putInt(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, 0);
+        Settings.Secure.putString(mContext.getContentResolver(), KEY_UNACCEPTED_TOS_DISABLED_APPS,
+                EMPTY_TOS_DISABLED_APPS);
 
         mActivityScenario = ActivityScenario.launch(new Intent(mContext, CarLauncher.class));
 
         mActivityScenario.onActivity(activity -> {
             assertNotNull(activity.mTosContentObserver); // Content observer is setup
 
-            // TOS changed to unaccepted
+            // Initialize TOS
             Settings.Secure.putInt(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, 1);
+            Settings.Secure.putString(mContext.getContentResolver(),
+                    KEY_UNACCEPTED_TOS_DISABLED_APPS, NON_EMPTY_TOS_DISABLED_APPS);
             activity.mTosContentObserver.onChange(true);
         });
+
         // Content observer is not null after recreate
         mActivityScenario.onActivity(activity -> assertNotNull(activity.mTosContentObserver));
     }
 
+    @Test
+    public void recreate_afterTosIsInitialized_releaseTaskView() {
+        TestableContext mContext = new TestableContext(InstrumentationRegistry.getContext());
+        Settings.Secure.putInt(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, 0);
+        Settings.Secure.putString(mContext.getContentResolver(), KEY_UNACCEPTED_TOS_DISABLED_APPS,
+                EMPTY_TOS_DISABLED_APPS);
+
+        mActivityScenario = ActivityScenario.launch(new Intent(mContext, CarLauncher.class));
+
+        mActivityScenario.onActivity(activity -> {
+            assertNotNull(activity.mCarLauncherViewModel); // CarLauncherViewModel is setup
+
+            RemoteCarTaskView oldRemoteCarTaskView =
+                    activity.mCarLauncherViewModel.getRemoteCarTaskView().getValue();
+            assertNotNull(oldRemoteCarTaskView);
+
+            // Initialize TOS
+            Settings.Secure.putInt(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, 1);
+            Settings.Secure.putString(mContext.getContentResolver(),
+                    KEY_UNACCEPTED_TOS_DISABLED_APPS, NON_EMPTY_TOS_DISABLED_APPS);
+            activity.mTosContentObserver.onChange(true);
+
+            // Different instance of task view since TOS has gone from uninitialized to initialized
+            assertThat(oldRemoteCarTaskView).isNotSameInstanceAs(
+                    activity.mCarLauncherViewModel.getRemoteCarTaskView().getValue());
+        });
+    }
+
+    @Test
+    public void recreate_afterTosIsAccepted_releaseTaskView() {
+        TestableContext mContext = new TestableContext(InstrumentationRegistry.getContext());
+        Settings.Secure.putInt(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, 1);
+        Settings.Secure.putString(mContext.getContentResolver(), KEY_UNACCEPTED_TOS_DISABLED_APPS,
+                NON_EMPTY_TOS_DISABLED_APPS);
+
+        mActivityScenario = ActivityScenario.launch(new Intent(mContext, CarLauncher.class));
+
+        mActivityScenario.onActivity(activity -> {
+            assertNotNull(activity.mCarLauncherViewModel); // CarLauncherViewModel is setup
+
+            RemoteCarTaskView oldRemoteCarTaskView =
+                    activity.mCarLauncherViewModel.getRemoteCarTaskView().getValue();
+            assertNotNull(oldRemoteCarTaskView);
+
+            // Accept TOS
+            Settings.Secure.putInt(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, 2);
+            Settings.Secure.putString(mContext.getContentResolver(),
+                    KEY_UNACCEPTED_TOS_DISABLED_APPS, EMPTY_TOS_DISABLED_APPS);
+            activity.mTosContentObserver.onChange(true);
+
+            // Different instance of task view since TOS has been accepted
+            assertThat(oldRemoteCarTaskView).isNotSameInstanceAs(
+                    activity.mCarLauncherViewModel.getRemoteCarTaskView().getValue());
+        });
+    }
+
     private Intent createIntentFromString(String intentString) {
         try {
             return Intent.parseUri(intentString, Intent.URI_ANDROID_APP_SCHEME);
@@ -272,4 +371,16 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
         packages.add("com.android.car.assistant");
         return packages;
     }
+
+    private void setUpActivityScenario() {
+        mActivityScenario = ActivityScenario.launch(CarLauncher.class);
+        mActivityScenario.moveToState(Lifecycle.State.RESUMED);
+        mActivityScenario.onActivity(activity -> {
+            activity.runOnUiThread(new Runnable() {
+                public void run() {
+                    activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE);
+                }
+            });
+        });
+    }
 }
diff --git a/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelFactoryTest.java b/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelFactoryTest.java
index a61a0a5e..b11a40fa 100644
--- a/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelFactoryTest.java
+++ b/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelFactoryTest.java
@@ -64,7 +64,7 @@ public class CarLauncherViewModelFactoryTest extends AbstractExtendedMockitoTest
                 .createWindowContext(TYPE_APPLICATION_STARTING, /* options */ null);
         when(mContext.createWindowContext(eq(WindowManager.LayoutParams.TYPE_APPLICATION_STARTING),
                 any())).thenReturn(windowContext);
-        mCarLauncherViewModelFactory = new CarLauncherViewModelFactory(mContext, mIntent);
+        mCarLauncherViewModelFactory = new CarLauncherViewModelFactory(mContext);
     }
 
     @After
diff --git a/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelTest.java b/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelTest.java
index cee9451d..33d1611d 100644
--- a/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelTest.java
+++ b/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelTest.java
@@ -95,7 +95,8 @@ public final class CarLauncherViewModelTest extends AbstractExtendedMockitoTestC
     }
 
     private CarLauncherViewModel createCarLauncherViewModel() {
-        CarLauncherViewModel carLauncherViewModel = new CarLauncherViewModel(mActivity, mIntent);
+        CarLauncherViewModel carLauncherViewModel = new CarLauncherViewModel(mActivity);
+        carLauncherViewModel.initializeRemoteCarTaskView(mIntent);
         runOnMain(() -> carLauncherViewModel.getRemoteCarTaskView().observeForever(
                 remoteCarTaskView -> mRemoteCarTaskView = remoteCarTaskView));
         mInstrumentation.waitForIdleSync();
diff --git a/app/tests/src/com/android/car/carlauncher/homescreen/HomeCardFragmentTest.java b/app/tests/src/com/android/car/carlauncher/homescreen/HomeCardFragmentTest.java
index 0a1afc9d..7866abe3 100644
--- a/app/tests/src/com/android/car/carlauncher/homescreen/HomeCardFragmentTest.java
+++ b/app/tests/src/com/android/car/carlauncher/homescreen/HomeCardFragmentTest.java
@@ -18,6 +18,7 @@ package com.android.car.carlauncher.homescreen;
 
 import static androidx.test.espresso.Espresso.onView;
 import static androidx.test.espresso.assertion.ViewAssertions.matches;
+import static androidx.test.espresso.matcher.RootMatchers.hasWindowLayoutParams;
 import static androidx.test.espresso.matcher.ViewMatchers.isDescendantOfA;
 import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
 import static androidx.test.espresso.matcher.ViewMatchers.withId;
@@ -31,25 +32,30 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.graphics.drawable.Drawable;
+import android.platform.test.annotations.RequiresFlagsDisabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
+import android.view.WindowManager;
 import android.widget.ImageButton;
 
+import androidx.fragment.app.FragmentActivity;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
-import androidx.test.filters.Suppress;
 import androidx.test.platform.app.InstrumentationRegistry;
 import androidx.test.rule.ActivityTestRule;
 
 import com.android.car.carlauncher.CarLauncher;
+import com.android.car.carlauncher.Flags;
 import com.android.car.carlauncher.R;
 import com.android.car.carlauncher.homescreen.ui.CardHeader;
 import com.android.car.carlauncher.homescreen.ui.DescriptiveTextView;
 import com.android.car.carlauncher.homescreen.ui.DescriptiveTextWithControlsView;
 import com.android.car.carlauncher.homescreen.ui.TextBlockView;
 
+import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 
-@Suppress // To be ignored until b/224978827 is fixed
 @RunWith(AndroidJUnit4.class)
 public class HomeCardFragmentTest {
 
@@ -71,90 +77,134 @@ public class HomeCardFragmentTest {
     private static final TextBlockView TEXT_BLOCK_VIEW_NO_FOOTER = new TextBlockView(
             TEXT_BLOCK_CONTENT);
 
+    private FragmentActivity mActivity;
+
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule =
+            DeviceFlagsValueProvider.createCheckFlagsRule();
     @Rule
     public ActivityTestRule<CarLauncher> mActivityTestRule = new ActivityTestRule<CarLauncher>(
             CarLauncher.class);
 
+    @Before
+    public void setUp() {
+        mActivity = mActivityTestRule.getActivity();
+        mActivity.runOnUiThread(new Runnable() {
+            public void run() {
+                mActivity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE);
+            }
+        });
+    }
+
     @Test
+    @RequiresFlagsDisabled(Flags.FLAG_MEDIA_CARD_FULLSCREEN)
     public void updateContentView_descriptiveTextWithFooter_displaysTapForMoreView() {
-        HomeCardFragment fragment = (HomeCardFragment) mActivityTestRule.getActivity()
-                .getSupportFragmentManager().findFragmentById(R.id.top_card);
+        HomeCardFragment fragment = (HomeCardFragment) mActivity.getSupportFragmentManager()
+                .findFragmentById(R.id.top_card);
         fragment.updateHeaderView(CARD_HEADER);
         fragment.updateContentView(DESCRIPTIVE_TEXT_VIEW);
 
         onView(allOf(withId(R.id.descriptive_text_layout),
-                isDescendantOfA(withId(R.id.top_card)))).check(
-                matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.top_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.primary_text), withText(DESCRIPTIVE_TEXT_TITLE),
                 isDescendantOfA(withId(R.id.descriptive_text_layout)),
-                isDescendantOfA(withId(R.id.top_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.top_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.secondary_text), withText(DESCRIPTIVE_TEXT_SUBTITLE),
                 isDescendantOfA(withId(R.id.descriptive_text_layout)),
-                isDescendantOfA(withId(R.id.top_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.top_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.tap_for_more_text), withText(DESCRIPTIVE_TEXT_FOOTER),
                 isDescendantOfA(withId(R.id.descriptive_text_layout)),
-                isDescendantOfA(withId(R.id.top_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.top_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
     }
 
     @Test
+    @RequiresFlagsDisabled(Flags.FLAG_MEDIA_CARD_FULLSCREEN)
     public void updateContentView_descriptiveTextWithNoFooter_hidesTapForMoreView() {
-        HomeCardFragment fragment = (HomeCardFragment) mActivityTestRule.getActivity()
-                .getSupportFragmentManager().findFragmentById(R.id.top_card);
+        HomeCardFragment fragment = (HomeCardFragment) mActivity.getSupportFragmentManager()
+                .findFragmentById(R.id.top_card);
         fragment.updateHeaderView(CARD_HEADER);
         fragment.updateContentView(DESCRIPTIVE_TEXT_VIEW_NO_FOOTER);
 
         onView(allOf(withId(R.id.descriptive_text_layout),
-                isDescendantOfA(withId(R.id.top_card)))).check(
-                matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.top_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.primary_text), withText(DESCRIPTIVE_TEXT_TITLE),
                 isDescendantOfA(withId(R.id.descriptive_text_layout)),
-                isDescendantOfA(withId(R.id.top_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.top_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.secondary_text), withText(DESCRIPTIVE_TEXT_SUBTITLE),
                 isDescendantOfA(withId(R.id.descriptive_text_layout)),
-                isDescendantOfA(withId(R.id.top_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.top_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.tap_for_more_text),
                 isDescendantOfA(withId(R.id.descriptive_text_layout)),
-                isDescendantOfA(withId(R.id.top_card)))).check(matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.top_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
     }
 
     @Test
+    @RequiresFlagsDisabled(Flags.FLAG_MEDIA_CARD_FULLSCREEN)
     public void updateContentView_textBlockWithFooter_displaysTapForMoreView() {
-        HomeCardFragment fragment = (HomeCardFragment) mActivityTestRule.getActivity()
-                .getSupportFragmentManager().findFragmentById(R.id.top_card);
+        HomeCardFragment fragment = (HomeCardFragment) mActivity.getSupportFragmentManager()
+                .findFragmentById(R.id.top_card);
         fragment.updateHeaderView(CARD_HEADER);
         fragment.updateContentView(TEXT_BLOCK_VIEW);
 
-        onView(allOf(withId(R.id.text_block_layout), isDescendantOfA(withId(R.id.top_card)))).check(
-                matches(isDisplayed()));
+        onView(allOf(withId(R.id.text_block_layout), isDescendantOfA(withId(R.id.top_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.text_block), withText(TEXT_BLOCK_CONTENT),
                 isDescendantOfA(withId(R.id.text_block_layout)),
-                isDescendantOfA(withId(R.id.top_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.top_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.tap_for_more_text), withText(TEXT_BLOCK_FOOTER),
                 isDescendantOfA(withId(R.id.text_block_layout)),
-                isDescendantOfA(withId(R.id.top_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.top_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
     }
 
     @Test
+    @RequiresFlagsDisabled(Flags.FLAG_MEDIA_CARD_FULLSCREEN)
     public void updateContentView_textBlockNoFooter_hidesTapForMoreView() {
-        HomeCardFragment fragment = (HomeCardFragment) mActivityTestRule.getActivity()
-                .getSupportFragmentManager().findFragmentById(R.id.top_card);
+        HomeCardFragment fragment = (HomeCardFragment) mActivity.getSupportFragmentManager()
+                .findFragmentById(R.id.top_card);
         fragment.updateHeaderView(CARD_HEADER);
         fragment.updateContentView(TEXT_BLOCK_VIEW_NO_FOOTER);
 
-        onView(allOf(withId(R.id.text_block_layout), isDescendantOfA(withId(R.id.top_card)))).check(
-                matches(isDisplayed()));
+        onView(allOf(withId(R.id.text_block_layout), isDescendantOfA(withId(R.id.top_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.text_block), withText(TEXT_BLOCK_CONTENT),
                 isDescendantOfA(withId(R.id.text_block_layout)),
-                isDescendantOfA(withId(R.id.top_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.top_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.tap_for_more_text),
                 isDescendantOfA(withId(R.id.text_block_layout)),
-                isDescendantOfA(withId(R.id.top_card)))).check(matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.top_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
     }
 
     @Test
+    @RequiresFlagsDisabled(Flags.FLAG_MEDIA_CARD_FULLSCREEN)
     public void updateControlBarButton_updatesButtonSelectedState() {
-        HomeCardFragment fragment = (HomeCardFragment) mActivityTestRule.getActivity()
-                .getSupportFragmentManager().findFragmentById(R.id.top_card);
+        HomeCardFragment fragment = (HomeCardFragment) mActivity.getSupportFragmentManager()
+                .findFragmentById(R.id.top_card);
         assertNotNull(fragment);
 
         ImageButton leftImageButton = mock(ImageButton.class);
diff --git a/app/tests/src/com/android/car/carlauncher/homescreen/audio/AudioCardFragmentTest.java b/app/tests/src/com/android/car/carlauncher/homescreen/audio/AudioCardFragmentTest.java
index 4149add1..a89e2f97 100644
--- a/app/tests/src/com/android/car/carlauncher/homescreen/audio/AudioCardFragmentTest.java
+++ b/app/tests/src/com/android/car/carlauncher/homescreen/audio/AudioCardFragmentTest.java
@@ -18,10 +18,12 @@ package com.android.car.carlauncher.homescreen.audio;
 
 import static androidx.test.espresso.Espresso.onView;
 import static androidx.test.espresso.assertion.ViewAssertions.matches;
+import static androidx.test.espresso.assertion.ViewAssertions.doesNotExist;
 import static androidx.test.espresso.matcher.ViewMatchers.isDescendantOfA;
 import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
 import static androidx.test.espresso.matcher.ViewMatchers.withId;
 import static androidx.test.espresso.matcher.ViewMatchers.withText;
+import static androidx.test.espresso.matcher.RootMatchers.hasWindowLayoutParams;
 
 import static org.hamcrest.CoreMatchers.allOf;
 import static org.hamcrest.CoreMatchers.instanceOf;
@@ -30,13 +32,19 @@ import static org.hamcrest.CoreMatchers.not;
 
 import android.graphics.Bitmap;
 import android.graphics.drawable.BitmapDrawable;
+import android.platform.test.annotations.RequiresFlagsDisabled;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
+import android.view.WindowManager;
 
+import androidx.fragment.app.FragmentActivity;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
-import androidx.test.filters.Suppress;
 import androidx.test.rule.ActivityTestRule;
 
 import com.android.car.apps.common.CrossfadeImageView;
 import com.android.car.carlauncher.CarLauncher;
+import com.android.car.carlauncher.Flags;
 import com.android.car.carlauncher.R;
 import com.android.car.carlauncher.homescreen.audio.dialer.DialerCardFragment;
 import com.android.car.carlauncher.homescreen.audio.media.MediaCardFragment;
@@ -46,11 +54,11 @@ import com.android.car.carlauncher.homescreen.ui.DescriptiveTextView;
 import com.android.car.carlauncher.homescreen.ui.DescriptiveTextWithControlsView;
 import com.android.car.carlauncher.homescreen.ui.TextBlockView;
 
+import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 
-@Suppress // To be ignored until b/224978827 is fixed
 @RunWith(AndroidJUnit4.class)
 public class AudioCardFragmentTest {
 
@@ -79,52 +87,188 @@ public class AudioCardFragmentTest {
             CARD_BACKGROUND_IMAGE, AUDIO_VIEW_TITLE, AUDIO_VIEW_SUBTITLE, AUDIO_START_TIME,
             mControl, mControl, mControl);
 
+    private FragmentActivity mActivity;
+
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule =
+            DeviceFlagsValueProvider.createCheckFlagsRule();
     @Rule
     public ActivityTestRule<CarLauncher> mActivityTestRule =
             new ActivityTestRule<CarLauncher>(CarLauncher.class);
 
+    @Before
+    public void setUp() {
+        mActivity = mActivityTestRule.getActivity();
+        mActivity.runOnUiThread(new Runnable() {
+            public void run() {
+                mActivity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE);
+            }
+        });
+    }
+
     @Test
-    public void updateContentAndHeaderView_audioContentNoControls_showsMediaPlaybackControlsBar() {
-        AudioCardFragment fragment = (AudioCardFragment) mActivityTestRule.getActivity()
-                .getSupportFragmentManager().findFragmentById(R.id.bottom_card);
-        mActivityTestRule.getActivity().runOnUiThread(fragment::hideCard);
+    @RequiresFlagsDisabled(Flags.FLAG_MEDIA_CARD_FULLSCREEN)
+    public void updateContentAndHeaderView_noControls_showsMediaPlaybackControlsBar_hidesDialer() {
+        AudioCardFragment fragment = (AudioCardFragment) mActivity.getSupportFragmentManager()
+                .findFragmentById(R.id.bottom_card);
+        mActivity.runOnUiThread(fragment::showMediaCard);
         MediaCardFragment mediaCardFragment = (MediaCardFragment) fragment.getMediaFragment();
 
+        mediaCardFragment.updateHeaderView(CARD_HEADER);
         mediaCardFragment.updateContentView(mDescriptiveTextWithControlsView);
-        // Card is only made visible when the header is updated
-        // But content should still be updated so it is correct when card is next made visible
-        onView(allOf(withId(R.id.card_view), isDescendantOfA(withId(R.id.bottom_card))))
-                .check(matches(not(isDisplayed())));
 
-        // Now the card is made visible and we verify that content has been updated
-        mediaCardFragment.updateHeaderView(CARD_HEADER);
+        onView(allOf(withId(R.id.card_view),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+        onView(allOf(withId(R.id.card_view),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.card_background),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.card_background),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.card_background_image), is(instanceOf(CrossfadeImageView.class)),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.card_background_image), is(instanceOf(CrossfadeImageView.class)),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.media_layout),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.media_layout),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
         onView(allOf(withId(R.id.primary_text), withText(AUDIO_VIEW_TITLE),
                 isDescendantOfA(withId(R.id.media_layout)),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.secondary_text), withText(AUDIO_VIEW_SUBTITLE),
                 isDescendantOfA(withId(R.id.media_layout)),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(isDisplayed()));
-        onView(allOf(withId(R.id.optional_timer), isDescendantOfA(withId(R.id.bottom_card)),
-                isDescendantOfA(withId(R.id.media_layout)))).check(
-                matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+        onView(allOf(withId(R.id.optional_timer),
+                isDescendantOfA(withId(R.id.media_layout)),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
         onView(allOf(withId(R.id.media_playback_controls_bar),
                 isDescendantOfA(withId(R.id.media_layout)),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+        onView(allOf(withId(R.id.descriptive_text_with_controls_layout),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.descriptive_text_with_controls_layout),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.motion_layout),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(doesNotExist());
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_MEDIA_CARD_FULLSCREEN)
+    public void showMediaCard_showsFullscreenMediaCardLayout_hidesDialerLayout() {
+        AudioCardFragment fragment = (AudioCardFragment) mActivity.getSupportFragmentManager()
+                .findFragmentById(R.id.bottom_card);
+        mActivity.runOnUiThread(fragment::showMediaCard);
+        MediaCardFragment mediaCardFragment = (MediaCardFragment) fragment.getMediaFragment();
+
+        onView(allOf(withId(R.id.motion_layout),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+        onView(allOf(withId(R.id.card_view),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(doesNotExist());
+        onView(allOf(withId(R.id.card_view),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.card_background),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(doesNotExist());
+        onView(allOf(withId(R.id.card_background),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.card_background_image), is(instanceOf(CrossfadeImageView.class)),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(doesNotExist());
+        onView(allOf(withId(R.id.card_background_image), is(instanceOf(CrossfadeImageView.class)),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.media_layout),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(doesNotExist());
+        onView(allOf(withId(R.id.media_layout),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
         onView(allOf(withId(R.id.descriptive_text_with_controls_layout),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(doesNotExist());
+        onView(allOf(withId(R.id.descriptive_text_with_controls_layout),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
     }
 
     @Test
-    public void updateContentAndHeaderView_audioContentWithControls_showsDialerControlBar() {
-        AudioCardFragment fragment = (AudioCardFragment) mActivityTestRule.getActivity()
-                .getSupportFragmentManager().findFragmentById(R.id.bottom_card);
-        mActivityTestRule.getActivity().runOnUiThread(fragment::hideCard);
+    @RequiresFlagsDisabled(Flags.FLAG_MEDIA_CARD_FULLSCREEN)
+    public void updateContentAndHeaderView_showsDialerControlBarControls_hidesMediaCardControls() {
+        AudioCardFragment fragment = (AudioCardFragment) mActivity.getSupportFragmentManager()
+                .findFragmentById(R.id.bottom_card);
+        mActivity.runOnUiThread(fragment::showInCallCard);
         DialerCardFragment dialerCardFragment = (DialerCardFragment) fragment.getInCallFragment();
 
         dialerCardFragment.updateHeaderView(CARD_HEADER);
@@ -132,100 +276,281 @@ public class AudioCardFragmentTest {
 
         onView(allOf(withId(R.id.optional_timer),
                 isDescendantOfA(withId(R.id.descriptive_text_with_controls_layout)),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.button_left),
                 isDescendantOfA(withId(R.id.descriptive_text_with_controls_layout)),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.button_center),
                 isDescendantOfA(withId(R.id.descriptive_text_with_controls_layout)),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.button_right),
                 isDescendantOfA(withId(R.id.descriptive_text_with_controls_layout)),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(isDisplayed()));
-        onView(allOf(withId(R.id.media_playback_controls_bar),
-                isDescendantOfA(withId(R.id.media_layout)),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(not(isDisplayed())));
-        onView(allOf(withId(R.id.media_layout), isDescendantOfA(withId(R.id.bottom_card)))).check(
-                matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+        onView(allOf(withId(R.id.media_layout),
+                isDescendantOfA(withId(R.id.bottom_card)),
+                isDescendantOfA(withId(R.id.in_call_fragment_container))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.media_layout),
+                isDescendantOfA(withId(R.id.bottom_card)),
+                isDescendantOfA(withId(R.id.media_fragment_container))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.descriptive_text_with_controls_layout),
+                isDescendantOfA(withId(R.id.bottom_card)),
+                isDescendantOfA(withId(R.id.in_call_fragment_container))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+        onView(allOf(withId(R.id.descriptive_text_with_controls_layout),
+                isDescendantOfA(withId(R.id.bottom_card)),
+                isDescendantOfA(withId(R.id.media_fragment_container))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_MEDIA_CARD_FULLSCREEN)
+    public void updateContentAndHeaderView_audioContentWithControls_showsDialer_notMediaCard() {
+        AudioCardFragment fragment = (AudioCardFragment) mActivity.getSupportFragmentManager()
+                .findFragmentById(R.id.bottom_card);
+        mActivity.runOnUiThread(fragment::showInCallCard);
+        DialerCardFragment dialerCardFragment = (DialerCardFragment) fragment.getInCallFragment();
+
+        dialerCardFragment.updateHeaderView(CARD_HEADER);
+        dialerCardFragment.updateContentView(mDescriptiveTextWithControlsViewWithButtons);
+
+        onView(allOf(withId(R.id.optional_timer),
+                isDescendantOfA(withId(R.id.descriptive_text_with_controls_layout)),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+        onView(allOf(withId(R.id.button_left),
+                isDescendantOfA(withId(R.id.descriptive_text_with_controls_layout)),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+        onView(allOf(withId(R.id.button_center),
+                isDescendantOfA(withId(R.id.descriptive_text_with_controls_layout)),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+        onView(allOf(withId(R.id.button_right),
+                isDescendantOfA(withId(R.id.descriptive_text_with_controls_layout)),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+        onView(allOf(withId(R.id.card_view),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+        onView(allOf(withId(R.id.card_view),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(doesNotExist());
+        onView(allOf(withId(R.id.card_background),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+        onView(allOf(withId(R.id.card_background),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(doesNotExist());
+        onView(allOf(withId(R.id.card_background_image), is(instanceOf(CrossfadeImageView.class)),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+        onView(allOf(withId(R.id.card_background_image), is(instanceOf(CrossfadeImageView.class)),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(doesNotExist());
+        onView(allOf(withId(R.id.descriptive_text_with_controls_layout),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
+        onView(allOf(withId(R.id.descriptive_text_with_controls_layout),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(doesNotExist());
+        onView(allOf(withId(R.id.media_layout),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.media_layout),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(doesNotExist());
     }
 
     @Test
+    @RequiresFlagsDisabled(Flags.FLAG_MEDIA_CARD_FULLSCREEN)
     public void mediaFragment_updateContentView_descriptiveText_hidesPlaybackControlsBar() {
-        AudioCardFragment fragment = (AudioCardFragment) mActivityTestRule.getActivity()
-                .getSupportFragmentManager().findFragmentById(R.id.bottom_card);
+        AudioCardFragment fragment = (AudioCardFragment) mActivity.getSupportFragmentManager()
+                .findFragmentById(R.id.bottom_card);
         MediaCardFragment mediaCardFragment = (MediaCardFragment) fragment.getMediaFragment();
         mediaCardFragment.updateContentView(mDescriptiveTextWithControlsView);
         mediaCardFragment.updateContentView(DESCRIPTIVE_TEXT_VIEW);
 
         onView(allOf(withId(R.id.card_background),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
         onView(allOf(withId(R.id.card_background_image), is(instanceOf(CrossfadeImageView.class)),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
         onView(allOf(withId(R.id.descriptive_text_layout),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.descriptive_text_with_controls_layout),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(not(isDisplayed())));
-        onView(allOf(withId(R.id.media_layout), isDescendantOfA(withId(R.id.bottom_card)))).check(
-                matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.media_layout),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
     }
 
     @Test
+    @RequiresFlagsDisabled(Flags.FLAG_MEDIA_CARD_FULLSCREEN)
     public void mediaFragment_updateContentView_textBlock_hidesPlaybackControlsBar() {
-        AudioCardFragment fragment = (AudioCardFragment) mActivityTestRule.getActivity()
-                .getSupportFragmentManager().findFragmentById(R.id.bottom_card);
+        AudioCardFragment fragment = (AudioCardFragment) mActivity.getSupportFragmentManager()
+                .findFragmentById(R.id.bottom_card);
         MediaCardFragment mediaCardFragment = (MediaCardFragment) fragment.getMediaFragment();
         mediaCardFragment.updateContentView(mDescriptiveTextWithControlsView);
         mediaCardFragment.updateContentView(TEXT_BLOCK_VIEW);
 
         onView(allOf(withId(R.id.card_background),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
         onView(allOf(withId(R.id.card_background_image), is(instanceOf(CrossfadeImageView.class)),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
         onView(allOf(withId(R.id.text_block_layout),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.descriptive_text_with_controls_layout),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(not(isDisplayed())));
-        onView(allOf(withId(R.id.media_layout), isDescendantOfA(withId(R.id.bottom_card)))).check(
-                matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.media_layout),
+                isDescendantOfA(withId(R.id.media_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
     }
 
     @Test
+    @RequiresFlagsDisabled(Flags.FLAG_MEDIA_CARD_FULLSCREEN)
     public void dialerFragment_updateContentView_descriptiveText_hidesDescriptiveControlsView() {
-        AudioCardFragment fragment = (AudioCardFragment) mActivityTestRule.getActivity()
-                .getSupportFragmentManager().findFragmentById(R.id.bottom_card);
+        AudioCardFragment fragment = (AudioCardFragment) mActivity.getSupportFragmentManager()
+                .findFragmentById(R.id.bottom_card);
+        mActivity.runOnUiThread(fragment::showInCallCard);
         DialerCardFragment dialerCardFragment = (DialerCardFragment) fragment.getInCallFragment();
         dialerCardFragment.updateContentView(mDescriptiveTextWithControlsViewWithButtons);
         dialerCardFragment.updateContentView(DESCRIPTIVE_TEXT_VIEW);
 
+        // card_background is displayed since the onRootLayoutChangeListener sets it visible
         onView(allOf(withId(R.id.card_background),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.card_background_image), is(instanceOf(CrossfadeImageView.class)),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.descriptive_text_layout),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.descriptive_text_with_controls_layout),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(not(isDisplayed())));
-        onView(allOf(withId(R.id.media_layout), isDescendantOfA(withId(R.id.bottom_card)))).check(
-                matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.media_layout),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
     }
 
     @Test
     public void dialerFragment_updateContentView_textBlock_hidesDescriptiveControlsView() {
-        AudioCardFragment fragment = (AudioCardFragment) mActivityTestRule.getActivity()
-                .getSupportFragmentManager().findFragmentById(R.id.bottom_card);
+        AudioCardFragment fragment = (AudioCardFragment) mActivity.getSupportFragmentManager()
+                .findFragmentById(R.id.bottom_card);
+        mActivity.runOnUiThread(fragment::showInCallCard);
         DialerCardFragment dialerCardFragment = (DialerCardFragment) fragment.getInCallFragment();
         dialerCardFragment.updateContentView(mDescriptiveTextWithControlsViewWithButtons);
         dialerCardFragment.updateContentView(TEXT_BLOCK_VIEW);
 
+        // card_background is displayed since the onRootLayoutChangeListener sets it visible
         onView(allOf(withId(R.id.card_background),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.card_background_image), is(instanceOf(CrossfadeImageView.class)),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.text_block_layout),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(isDisplayed()));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(isDisplayed()));
         onView(allOf(withId(R.id.descriptive_text_with_controls_layout),
-                isDescendantOfA(withId(R.id.bottom_card)))).check(matches(not(isDisplayed())));
-        onView(allOf(withId(R.id.media_layout), isDescendantOfA(withId(R.id.bottom_card)))).check(
-                matches(not(isDisplayed())));
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
+        onView(allOf(withId(R.id.media_layout),
+                isDescendantOfA(withId(R.id.in_call_fragment_container)),
+                isDescendantOfA(withId(R.id.bottom_card))))
+                .inRoot(hasWindowLayoutParams())
+                .check(matches(not(isDisplayed())));
     }
 }
diff --git a/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java b/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java
index b03ebe4e..71aa8d84 100644
--- a/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java
+++ b/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java
@@ -18,9 +18,9 @@ package com.android.car.carlauncher.recents;
 
 import static android.app.ActivityManager.RECENT_IGNORE_UNAVAILABLE;
 
-import static com.android.wm.shell.util.GroupedRecentTaskInfo.TYPE_FREEFORM;
-import static com.android.wm.shell.util.GroupedRecentTaskInfo.TYPE_SINGLE;
-import static com.android.wm.shell.util.GroupedRecentTaskInfo.TYPE_SPLIT;
+import static com.android.wm.shell.shared.GroupedRecentTaskInfo.TYPE_FREEFORM;
+import static com.android.wm.shell.shared.GroupedRecentTaskInfo.TYPE_SINGLE;
+import static com.android.wm.shell.shared.GroupedRecentTaskInfo.TYPE_SPLIT;
 
 import static com.google.common.truth.Truth.assertThat;
 
@@ -56,7 +56,7 @@ import com.android.systemui.shared.recents.model.Task;
 import com.android.systemui.shared.system.ActivityManagerWrapper;
 import com.android.systemui.shared.system.PackageManagerWrapper;
 import com.android.wm.shell.recents.IRecentTasks;
-import com.android.wm.shell.util.GroupedRecentTaskInfo;
+import com.android.wm.shell.shared.GroupedRecentTaskInfo;
 
 import com.google.common.util.concurrent.MoreExecutors;
 
diff --git a/build.gradle b/build.gradle
index 4a75340e..2d3cb5dd 100644
--- a/build.gradle
+++ b/build.gradle
@@ -30,7 +30,7 @@ buildscript {
     gradle.ext.lib_car_test_api = gradle.ext.prebuiltSdkPath + gradle.ext.aaosLatestSDK + "/system/android.car.testapi.jar"
     gradle.ext.debugCertPath = gradle.ext.repoRootPath + "/packages/apps/Car/Launcher/libs/appgrid/keys/com_android_car_launcher_test.jks"
     gradle.ext.soongBash = gradle.ext.repoRootPath + "/build/soong/soong_ui.bash"
-    gradle.ext.platformSdkVersion = "34" // Change this to the most recent android API level.
+    gradle.ext.platformSdkVersion = "35" // Change this to the most recent android API level.
 
     if (file(gradle.ext.soongBash).exists()) {
         def soongPlatformSdkVersion = (gradle.ext.soongBash + " --dumpvar-mode PLATFORM_SDK_VERSION").execute().text.trim()
diff --git a/docklib-util/tests/Android.bp b/docklib-util/tests/Android.bp
index b9819635..4832e216 100644
--- a/docklib-util/tests/Android.bp
+++ b/docklib-util/tests/Android.bp
@@ -16,6 +16,7 @@
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_system_experience",
 }
 
 android_test {
@@ -27,7 +28,7 @@ android_test {
     ],
 
     libs: [
-        "android.test.base",
+        "android.test.base.stubs.system",
     ],
 
     optimize: {
diff --git a/docklib/AndroidManifest.xml b/docklib/AndroidManifest.xml
index 7685700f..c3178e5f 100644
--- a/docklib/AndroidManifest.xml
+++ b/docklib/AndroidManifest.xml
@@ -21,6 +21,8 @@
     <uses-permission android:name="android.permission.INTERACT_ACROSS_USERS"/>
     <!-- System permission to query active media sessions -->
     <uses-permission android:name="android.permission.MEDIA_CONTENT_CONTROL"/>
+    <!-- System permission to access notifications -->
+    <uses-permission android:name="android.permission.ACCESS_NOTIFICATIONS"/>
 
     <!-- Permission to allow packages to broadcast events to the dock -->
     <permission
diff --git a/docklib/res/values-en-rCA/strings.xml b/docklib/res/values-en-rCA/strings.xml
new file mode 100644
index 00000000..bafbfdad
--- /dev/null
+++ b/docklib/res/values-en-rCA/strings.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+  ~ Copyright (C) 2023 The Android Open Source Project
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
+   -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="broadcast_sender_permission_label" msgid="5269973644784898827">"Dock broadcast sender"</string>
+    <string name="broadcast_sender_permission_desc" msgid="5052882219053515363">"Permission required for package to broadcast events to the Dock."</string>
+    <string name="broadcast_receiver_permission_label" msgid="6015991948761587466">"Dock broadcast receiver"</string>
+    <string name="broadcast_receiver_permission_desc" msgid="1623002370607914795">"Permission required for package listen to broadcast events for the Dock."</string>
+    <string name="pin_failed_no_spots" msgid="745687732976464502">"No spot available to pin"</string>
+</resources>
diff --git a/docklib/res/values/config.xml b/docklib/res/values/config.xml
index 9e5409a9..e026e7fd 100644
--- a/docklib/res/values/config.xml
+++ b/docklib/res/values/config.xml
@@ -39,6 +39,7 @@
         <item>com.android.car.media/com.android.car.media.MediaDispatcherActivity</item>
         <item>com.android.car.media/com.android.car.media.MediaBlockingActivity</item>
         <item>com.android.systemui/com.android.systemui.car.wm.activity.LaunchOnPrivateDisplayRouterActivity</item>
+        <item>com.android.car.settings/com.android.car.settings.sound.AudioRouteSelectionActivity</item>
     </string-array>
 
     <!--
diff --git a/docklib/src/com/android/car/docklib/DockViewController.kt b/docklib/src/com/android/car/docklib/DockViewController.kt
index a9b59e5b..a3b179e5 100644
--- a/docklib/src/com/android/car/docklib/DockViewController.kt
+++ b/docklib/src/com/android/car/docklib/DockViewController.kt
@@ -18,6 +18,7 @@ package com.android.car.docklib
 
 import android.annotation.CallSuper
 import android.app.ActivityOptions
+import android.app.NotificationManager
 import android.car.Car
 import android.car.content.pm.CarPackageManager
 import android.car.drivingstate.CarUxRestrictionsManager
@@ -28,9 +29,10 @@ import android.content.Intent
 import android.content.pm.LauncherApps
 import android.media.session.MediaController
 import android.media.session.MediaSessionManager
+import android.media.session.PlaybackState
 import android.os.Build
+import android.os.RemoteException
 import android.os.UserHandle
-import android.support.v4.media.session.PlaybackStateCompat
 import android.util.Log
 import androidx.core.content.getSystemService
 import com.android.car.carlauncher.Flags
@@ -46,7 +48,6 @@ import com.android.systemui.shared.system.TaskStackChangeListeners
 import java.io.File
 import java.lang.ref.WeakReference
 import java.util.UUID
-import kotlin.collections.emptyList
 
 /**
  * Create a controller for DockView. It initializes the view with default and persisted icons. Upon
@@ -147,6 +148,7 @@ open class DockViewController(
                 }
             }
         }
+
         mediaSessionManager =
             userContext.getSystemService(MediaSessionManager::class.java) as MediaSessionManager
         if (Flags.mediaSessionCard()) {
@@ -235,13 +237,32 @@ open class DockViewController(
         dockViewModel.getMediaServiceComponents()
 
     private fun handleMediaSessionChange(mediaControllers: List<MediaController>?) {
+        val mediaNotificationPackages = getActiveMediaNotificationPackages()
         val activeMediaSessions = mediaControllers?.filter {
             it.playbackState?.let { playbackState ->
-                (playbackState.isActive ||
-                        playbackState.actions and PlaybackStateCompat.ACTION_PLAY != 0L)
+                (playbackState.isActive || playbackState.state == PlaybackState.STATE_PAUSED)
             } ?: false
-        }?.map { it.packageName } ?: emptyList()
+        }?.map { it.packageName }?.filter { mediaNotificationPackages.contains(it) } ?: emptyList()
 
         adapter.onMediaSessionChange(activeMediaSessions)
     }
+
+    private fun getActiveMediaNotificationPackages(): List<String> {
+        try {
+            // todo(b/312718542): hidden api(NotificationManager.getService()) usage
+            return NotificationManager.getService()
+                .getActiveNotificationsWithAttribution(
+                    userContext.packageName,
+                    null
+                ).toList().filter {
+                    it.notification.extras != null && it.notification.isMediaNotification
+                }.map { it.packageName }
+        } catch (e: RemoteException) {
+            Log.e(
+                TAG,
+                "Exception trying to get active notifications $e"
+            )
+            return listOf()
+        }
+    }
 }
diff --git a/docklib/src/com/android/car/docklib/view/DockItemViewHolder.kt b/docklib/src/com/android/car/docklib/view/DockItemViewHolder.kt
index 96b69fa2..a718265e 100644
--- a/docklib/src/com/android/car/docklib/view/DockItemViewHolder.kt
+++ b/docklib/src/com/android/car/docklib/view/DockItemViewHolder.kt
@@ -206,7 +206,8 @@ class DockItemViewHolder(
         dockItemClickListener = DockItemClickListener(
             dockController,
             dockAppItem,
-            isRestricted = !dockAppItem.isDistractionOptimized && isUxRestrictionEnabled
+            isRestricted = !dockAppItem.isDistractionOptimized && isUxRestrictionEnabled &&
+              !hasActiveMediaSessions
         )
         appIcon.setOnClickListener(dockItemClickListener)
         setUxRestrictions(dockAppItem, isUxRestrictionEnabled)
diff --git a/docklib/tests/Android.bp b/docklib/tests/Android.bp
index ecc2b3b1..49b22724 100644
--- a/docklib/tests/Android.bp
+++ b/docklib/tests/Android.bp
@@ -16,6 +16,7 @@
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_system_experience",
 }
 
 android_test {
@@ -23,12 +24,12 @@ android_test {
 
     srcs: [
         "src/**/*.java",
-        "src/**/*.kt"
+        "src/**/*.kt",
     ],
 
     libs: [
         "android.car",
-        "android.test.base",
+        "android.test.base.stubs.system",
     ],
 
     optimize: {
diff --git a/libs/appgrid/lib/res/layout/app_grid_container_activity.xml b/libs/appgrid/lib/res/layout/app_grid_container_activity.xml
new file mode 100644
index 00000000..aed1ce58
--- /dev/null
+++ b/libs/appgrid/lib/res/layout/app_grid_container_activity.xml
@@ -0,0 +1,27 @@
+<?xml version="1.0" encoding="utf-8"?><!--
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
+<androidx.constraintlayout.widget.ConstraintLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent">
+
+    <androidx.fragment.app.FragmentContainerView
+        android:id="@+id/fragmentContainer"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"/>
+
+</androidx.constraintlayout.widget.ConstraintLayout>
diff --git a/libs/appgrid/lib/res/layout/app_grid_activity.xml b/libs/appgrid/lib/res/layout/app_grid_fragment.xml
similarity index 100%
rename from libs/appgrid/lib/res/layout/app_grid_activity.xml
rename to libs/appgrid/lib/res/layout/app_grid_fragment.xml
diff --git a/libs/appgrid/lib/res/values-en-rCA/strings.xml b/libs/appgrid/lib/res/values-en-rCA/strings.xml
new file mode 100644
index 00000000..09c85fd9
--- /dev/null
+++ b/libs/appgrid/lib/res/values-en-rCA/strings.xml
@@ -0,0 +1,31 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+    Copyright (C) 2018 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+        http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="reset_appgrid_title" msgid="6491348358859198288">"Reset app grid to A-Z order"</string>
+    <string name="reset_appgrid_dialogue_message" msgid="2278301828239327586">"This function will remove all custom ordering. Do you want to continue?"</string>
+    <string name="app_launcher_title_all_apps" msgid="3522783138519460233">"All apps"</string>
+    <string name="app_launcher_title_media_only" msgid="7194631822174015710">"Media apps"</string>
+    <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"App can’t be stopped."</string>
+    <string name="hide_debug_apps" msgid="7140064693464751647">"Hide debug apps"</string>
+    <string name="show_debug_apps" msgid="2748157232151197494">"Show debug apps"</string>
+    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
+    <string name="banner_title_text" msgid="8827498256184464356">"To use user tos disabled apps, agree to User tos"</string>
+    <string name="banner_review_button_text" msgid="369410598918950148">"Review"</string>
+    <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Not Now"</string>
+</resources>
diff --git a/libs/appgrid/lib/res/values/overlayable.xml b/libs/appgrid/lib/res/values/overlayable.xml
index 91dcb285..90f36e65 100644
--- a/libs/appgrid/lib/res/values/overlayable.xml
+++ b/libs/appgrid/lib/res/values/overlayable.xml
@@ -88,6 +88,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="id" name="banner_title"/>
       <item type="id" name="divider"/>
       <item type="id" name="focus_area"/>
+      <item type="id" name="fragmentContainer"/>
       <item type="id" name="page_indicator"/>
       <item type="id" name="page_indicator_container"/>
       <item type="id" name="recent_apps_row"/>
@@ -107,7 +108,8 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="integer" name="ms_scrollbar_appear_animation_duration"/>
       <item type="integer" name="ms_scrollbar_fade_animation_delay"/>
       <item type="integer" name="ms_scrollbar_fade_animation_duration"/>
-      <item type="layout" name="app_grid_activity"/>
+      <item type="layout" name="app_grid_container_activity"/>
+      <item type="layout" name="app_grid_fragment"/>
       <item type="layout" name="app_item"/>
       <item type="layout" name="banner"/>
       <item type="layout" name="recent_apps_row"/>
diff --git a/libs/appgrid/lib/robotests/Android.bp b/libs/appgrid/lib/robotests/Android.bp
index 843e3ef4..b968ba52 100644
--- a/libs/appgrid/lib/robotests/Android.bp
+++ b/libs/appgrid/lib/robotests/Android.bp
@@ -15,6 +15,7 @@
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_system_experience",
 }
 
 android_robolectric_test {
diff --git a/libs/appgrid/lib/robotests/src/com/android/car/carlauncher/datasources/UXRestrictionsDataSourceImplTest.kt b/libs/appgrid/lib/robotests/src/com/android/car/carlauncher/datasources/UXRestrictionsDataSourceImplTest.kt
index 8d911b23..e7d9e64b 100644
--- a/libs/appgrid/lib/robotests/src/com/android/car/carlauncher/datasources/UXRestrictionsDataSourceImplTest.kt
+++ b/libs/appgrid/lib/robotests/src/com/android/car/carlauncher/datasources/UXRestrictionsDataSourceImplTest.kt
@@ -20,6 +20,7 @@ import android.car.content.pm.CarPackageManager
 import android.car.drivingstate.CarUxRestrictions
 import android.car.drivingstate.CarUxRestrictionsManager
 import android.car.testapi.FakeCar
+import android.content.Context
 import android.media.session.MediaSessionManager
 import androidx.test.core.app.ApplicationProvider
 import java.lang.reflect.Field
@@ -51,6 +52,7 @@ class UXRestrictionsDataSourceImplTest {
     private val carUxRestrictionsManager =
         fakeCar.car.getCarManager(Car.CAR_UX_RESTRICTION_SERVICE) as CarUxRestrictionsManager
     private val carUxRestrictionsController = fakeCar.carUxRestrictionController
+    private val context: Context = ApplicationProvider.getApplicationContext()
 
     /**
      * Updates the CarUxRestrictions and notifies any active listeners.
@@ -81,6 +83,7 @@ class UXRestrictionsDataSourceImplTest {
         scope.runTest {
             val uxRestrictionDataSource =
                 UXRestrictionDataSourceImpl(
+                    context,
                     carUxRestrictionsManager,
                     mock(CarPackageManager::class.java),
                     mock(MediaSessionManager::class.java),
@@ -108,6 +111,7 @@ class UXRestrictionsDataSourceImplTest {
     fun requiresDistractionOptimization_sendsNotRequired() = scope.runTest {
         val uxRestrictionDataSource =
             UXRestrictionDataSourceImpl(
+                context,
                 carUxRestrictionsManager,
                 mock(CarPackageManager::class.java),
                 mock(MediaSessionManager::class.java),
@@ -135,6 +139,7 @@ class UXRestrictionsDataSourceImplTest {
     fun requiresDistractionOptimization_scopeClosed_shouldCleanUp() = scope.runTest {
         val uxRestrictionDataSource =
             UXRestrictionDataSourceImpl(
+                context,
                 carUxRestrictionsManager,
                 mock(CarPackageManager::class.java),
                 mock(MediaSessionManager::class.java),
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridActivity.java b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridActivity.java
index 10a61762..4f6827b6 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridActivity.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridActivity.java
@@ -16,193 +16,47 @@
 
 package com.android.car.carlauncher;
 
-import static androidx.lifecycle.FlowLiveDataConversions.asLiveData;
+import static com.android.car.carlauncher.AppGridFragment.MODE_INTENT_EXTRA;
 
-import static com.android.car.carlauncher.AppGridConstants.AppItemBoundDirection;
-import static com.android.car.carlauncher.AppGridConstants.PageOrientation;
-import static com.android.car.hidden.apis.HiddenApiAccess.getDragSurface;
-
-import static java.lang.annotation.RetentionPolicy.SOURCE;
-
-import android.animation.ValueAnimator;
-import android.car.Car;
-import android.car.content.pm.CarPackageManager;
-import android.car.drivingstate.CarUxRestrictionsManager;
-import android.car.media.CarMediaManager;
 import android.content.Intent;
-import android.content.pm.LauncherApps;
-import android.content.pm.PackageManager;
-import android.media.session.MediaSessionManager;
 import android.os.Bundle;
-import android.os.Handler;
-import android.util.Log;
-import android.view.DragEvent;
-import android.view.SurfaceControl;
-import android.view.View;
-import android.view.ViewTreeObserver;
-import android.widget.FrameLayout;
-import android.widget.LinearLayout;
 
-import androidx.annotation.IntDef;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
-import androidx.annotation.StringRes;
-import androidx.annotation.VisibleForTesting;
 import androidx.appcompat.app.AppCompatActivity;
-import androidx.lifecycle.ViewModelProvider;
-import androidx.recyclerview.widget.RecyclerView;
+import androidx.fragment.app.Fragment;
 
-import com.android.car.carlauncher.datasources.AppOrderDataSource;
-import com.android.car.carlauncher.datasources.AppOrderProtoDataSourceImpl;
-import com.android.car.carlauncher.datasources.ControlCenterMirroringDataSource;
-import com.android.car.carlauncher.datasources.ControlCenterMirroringDataSourceImpl;
-import com.android.car.carlauncher.datasources.LauncherActivitiesDataSource;
-import com.android.car.carlauncher.datasources.LauncherActivitiesDataSourceImpl;
-import com.android.car.carlauncher.datasources.MediaTemplateAppsDataSource;
-import com.android.car.carlauncher.datasources.MediaTemplateAppsDataSourceImpl;
-import com.android.car.carlauncher.datasources.UXRestrictionDataSource;
-import com.android.car.carlauncher.datasources.UXRestrictionDataSourceImpl;
-import com.android.car.carlauncher.datasources.restricted.DisabledAppsDataSource;
-import com.android.car.carlauncher.datasources.restricted.DisabledAppsDataSourceImpl;
-import com.android.car.carlauncher.datasources.restricted.TosDataSource;
-import com.android.car.carlauncher.datasources.restricted.TosDataSourceImpl;
-import com.android.car.carlauncher.datastore.launcheritem.LauncherItemListSource;
-import com.android.car.carlauncher.pagination.PageMeasurementHelper;
-import com.android.car.carlauncher.pagination.PaginationController;
-import com.android.car.carlauncher.recyclerview.AppGridAdapter;
-import com.android.car.carlauncher.recyclerview.AppGridItemAnimator;
-import com.android.car.carlauncher.recyclerview.AppGridLayoutManager;
-import com.android.car.carlauncher.recyclerview.AppItemViewHolder;
-import com.android.car.carlauncher.repositories.AppGridRepository;
-import com.android.car.carlauncher.repositories.AppGridRepositoryImpl;
-import com.android.car.carlauncher.repositories.appactions.AppLaunchProviderFactory;
-import com.android.car.carlauncher.repositories.appactions.AppShortcutsFactory;
+import com.android.car.carlauncher.AppGridFragment.Mode;
 import com.android.car.ui.core.CarUi;
-import com.android.car.ui.shortcutspopup.CarUiShortcutsPopup;
 import com.android.car.ui.toolbar.MenuItem;
 import com.android.car.ui.toolbar.NavButtonMode;
 import com.android.car.ui.toolbar.ToolbarController;
 
-import java.lang.annotation.Retention;
 import java.util.Collections;
 
-import kotlin.Unit;
-import kotlinx.coroutines.CoroutineDispatcher;
-import kotlinx.coroutines.Dispatchers;
-
 /**
  * Launcher activity that shows a grid of apps.
  */
-public class AppGridActivity extends AppCompatActivity implements
-        AppGridPageSnapper.PageSnapListener, AppItemViewHolder.AppItemDragListener,
-        PaginationController.DimensionUpdateListener,
-        AppGridAdapter.AppGridAdapterListener {
+public class AppGridActivity extends AppCompatActivity {
     private static final String TAG = "AppGridActivity";
+    boolean mShowToolbar = false;
+    boolean mShowAllApps = true;
     private static final boolean DEBUG_BUILD = false;
-    private static final String MODE_INTENT_EXTRA = "com.android.car.carlauncher.mode";
-    private static CarUiShortcutsPopup sCarUiShortcutsPopup;
-
-    private boolean mShowAllApps = true;
-    private boolean mShowToolbar = true;
-    private Car mCar;
-    private Mode mMode;
-    private AppGridAdapter mAdapter;
-    private AppGridRecyclerView mRecyclerView;
-    private PageIndicator mPageIndicator;
-    private AppGridLayoutManager mLayoutManager;
-    private boolean mIsCurrentlyDragging;
-    private long mOffPageHoverBeforeScrollMs;
-    private Banner mBanner;
-
-    private AppGridDragController mAppGridDragController;
-    private PaginationController mPaginationController;
-
-    private int mNumOfRows;
-    private int mNumOfCols;
-    private int mAppGridMarginHorizontal;
-    private int mAppGridMarginVertical;
-    private int mAppGridWidth;
-    private int mAppGridHeight;
-    @PageOrientation
-    private int mPageOrientation;
-
-    private int mCurrentScrollOffset;
-    private int mCurrentScrollState;
-    private int mNextScrollDestination;
-    private AppGridPageSnapper.AppGridPageSnapCallback mSnapCallback;
-    private AppItemViewHolder.AppItemDragCallback mDragCallback;
-    private BackgroundAnimationHelper mBackgroundAnimationHelper;
-
-    private AppGridViewModel mAppGridViewModel;
-
-    @Retention(SOURCE)
-    @IntDef({APP_TYPE_LAUNCHABLES, APP_TYPE_MEDIA_SERVICES})
-    @interface AppTypes {}
-    static final int APP_TYPE_LAUNCHABLES = 1;
-    static final int APP_TYPE_MEDIA_SERVICES = 2;
-
-    public enum Mode {
-        ALL_APPS(R.string.app_launcher_title_all_apps,
-                APP_TYPE_LAUNCHABLES + APP_TYPE_MEDIA_SERVICES,
-                true),
-        MEDIA_ONLY(R.string.app_launcher_title_media_only,
-                APP_TYPE_MEDIA_SERVICES,
-                true),
-        MEDIA_POPUP(R.string.app_launcher_title_media_only,
-                APP_TYPE_MEDIA_SERVICES,
-                false),
-        ;
-        @StringRes
-        public final int mTitleStringId;
-        @AppTypes
-        public final int mAppTypes;
-        public final boolean mOpenMediaCenter;
-
-        Mode(@StringRes int titleStringId, @AppTypes int appTypes,
-                boolean openMediaCenter) {
-            mTitleStringId = titleStringId;
-            mAppTypes = appTypes;
-            mOpenMediaCenter = openMediaCenter;
-        }
-    }
-
-    /**
-     * Updates the state of the app grid components depending on the driving state.
-     */
-    private void handleDistractionOptimization(boolean requiresDistractionOptimization) {
-        mAdapter.setIsDistractionOptimizationRequired(requiresDistractionOptimization);
-        if (requiresDistractionOptimization) {
-            // if the user start driving while drag is in action, we cancel existing drag operations
-            if (mIsCurrentlyDragging) {
-                mIsCurrentlyDragging = false;
-                mLayoutManager.setShouldLayoutChildren(true);
-                mRecyclerView.cancelDragAndDrop();
-            }
-            dismissShortcutPopup();
-        }
-    }
 
     @Override
     protected void onCreate(@Nullable Bundle savedInstanceState) {
         // TODO (b/267548246) deprecate toolbar and find another way to hide debug apps
-        mShowToolbar = false;
         if (mShowToolbar) {
             setTheme(R.style.Theme_Launcher_AppGridActivity);
         } else {
             setTheme(R.style.Theme_Launcher_AppGridActivity_NoToolbar);
         }
         super.onCreate(savedInstanceState);
-
-        mCar = Car.createCar(this);
-        setContentView(R.layout.app_grid_activity);
-        updateMode();
-        initViewModel();
+        setContentView(R.layout.app_grid_container_activity);
 
         if (mShowToolbar) {
             ToolbarController toolbar = CarUi.requireToolbar(this);
-
             toolbar.setNavButtonMode(NavButtonMode.CLOSE);
-
             if (DEBUG_BUILD) {
                 toolbar.setMenuItems(Collections.singletonList(MenuItem.builder(this)
                         .setDisplayBehavior(MenuItem.DisplayBehavior.NEVER)
@@ -216,204 +70,23 @@ public class AppGridActivity extends AppCompatActivity implements
                         .build()));
             }
         }
-
-        mSnapCallback = new AppGridPageSnapper.AppGridPageSnapCallback(this);
-        mDragCallback = new AppItemViewHolder.AppItemDragCallback(this);
-
-        mNumOfCols = getResources().getInteger(R.integer.car_app_selector_column_number);
-        mNumOfRows = getResources().getInteger(R.integer.car_app_selector_row_number);
-        mAppGridDragController = new AppGridDragController();
-        mOffPageHoverBeforeScrollMs = getResources().getInteger(
-                R.integer.ms_off_page_hover_before_scroll);
-
-        mPageOrientation = getResources().getBoolean(R.bool.use_vertical_app_grid)
-                ? PageOrientation.VERTICAL : PageOrientation.HORIZONTAL;
-
-        mRecyclerView = requireViewById(R.id.apps_grid);
-        mRecyclerView.setFocusable(false);
-        mLayoutManager = new AppGridLayoutManager(this, mNumOfCols, mNumOfRows, mPageOrientation);
-        mRecyclerView.setLayoutManager(mLayoutManager);
-
-        AppGridPageSnapper pageSnapper = new AppGridPageSnapper(
-                this,
-                mNumOfCols,
-                mNumOfRows,
-                mSnapCallback);
-        pageSnapper.attachToRecyclerView(mRecyclerView);
-
-        mRecyclerView.setItemAnimator(new AppGridItemAnimator());
-
-        // hide the default scrollbar and replace it with a visual page indicator
-        mRecyclerView.setVerticalScrollBarEnabled(false);
-        mRecyclerView.setHorizontalScrollBarEnabled(false);
-        mRecyclerView.addOnScrollListener(new AppGridOnScrollListener());
-
-        // TODO: (b/271637411) move this to be contained in a scroll controller
-        mPageIndicator = requireViewById(R.id.page_indicator);
-        FrameLayout pageIndicatorContainer = requireViewById(R.id.page_indicator_container);
-        mPageIndicator.setContainer(pageIndicatorContainer);
-
-        // recycler view is set to LTR to prevent layout manager from reassigning layout direction.
-        // instead, PageIndexinghelper will determine the grid index based on the system layout
-        // direction and provide LTR mapping at adapter level.
-        mRecyclerView.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
-        pageIndicatorContainer.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
-
-        // we create but do not attach the adapter to recyclerview until view tree layout is
-        // complete and the total size of the app grid is measureable.
-        mAdapter = new AppGridAdapter(this, mNumOfCols, mNumOfRows,
-                /* dragCallback */ mDragCallback,
-                /* snapCallback */ mSnapCallback, this, mMode);
-
-        mAdapter.registerAdapterDataObserver(new RecyclerView.AdapterDataObserver() {
-            @Override
-            public void onItemRangeMoved(int fromPosition, int toPosition, int itemCount) {
-                // scroll state will need to be updated after item has been dropped
-                mNextScrollDestination = mSnapCallback.getSnapPosition();
-                updateScrollState();
-            }
-        });
-        mRecyclerView.setAdapter(mAdapter);
-
-        asLiveData(mAppGridViewModel.getAppList()).observe(this,
-                appItems -> {
-                    mAdapter.setLauncherItems(appItems);
-                    mNextScrollDestination = mSnapCallback.getSnapPosition();
-                    updateScrollState();
-                });
-
-        asLiveData(mAppGridViewModel.requiresDistractionOptimization()).observe(this,
-                uxRestrictions -> {
-                    handleDistractionOptimization(uxRestrictions);
-                });
-
-        // set drag listener and global layout listener, which will dynamically adjust app grid
-        // height and width depending on device screen size.
-        if (getResources().getBoolean(R.bool.config_allow_reordering)) {
-            mRecyclerView.setOnDragListener(new AppGridDragListener());
-        }
-
-        // since some measurements for window size may not be available yet during onCreate or may
-        // later change, we add a listener that redraws the app grid when window size changes.
-        LinearLayout windowBackground = requireViewById(R.id.apps_grid_background);
-        windowBackground.setOrientation(
-                isHorizontal() ? LinearLayout.VERTICAL : LinearLayout.HORIZONTAL);
-        PaginationController.DimensionUpdateCallback dimensionUpdateCallback =
-                new PaginationController.DimensionUpdateCallback();
-        dimensionUpdateCallback.addListener(mRecyclerView);
-        dimensionUpdateCallback.addListener(mPageIndicator);
-        dimensionUpdateCallback.addListener(this);
-        mPaginationController = new PaginationController(windowBackground, dimensionUpdateCallback);
-
-        mBanner = requireViewById(R.id.tos_banner);
-
-        mBackgroundAnimationHelper = new BackgroundAnimationHelper(windowBackground, mBanner);
-
-        setupTosBanner();
-    }
-
-    private void initViewModel() {
-        LauncherActivitiesDataSource launcherActivities = new LauncherActivitiesDataSourceImpl(
-                getSystemService(LauncherApps.class),
-                (broadcastReceiver, intentFilter) -> {
-                    registerReceiver(broadcastReceiver, intentFilter);
-                    return Unit.INSTANCE;
-                }, broadcastReceiver -> {
-            unregisterReceiver(broadcastReceiver);
-            return Unit.INSTANCE;
-        },
-                android.os.Process.myUserHandle(),
-                getApplication().getResources(),
-                Dispatchers.getDefault()
-        );
-        MediaTemplateAppsDataSource mediaTemplateApps = new MediaTemplateAppsDataSourceImpl(
-                getPackageManager(),
-                getApplication(),
-                Dispatchers.getDefault()
-        );
-
-        DisabledAppsDataSource disabledApps = new DisabledAppsDataSourceImpl(getContentResolver(),
-                getPackageManager(), Dispatchers.getIO());
-        TosDataSource tosApps = new TosDataSourceImpl(getContentResolver(), getPackageManager(),
-                Dispatchers.getIO());
-        ControlCenterMirroringDataSource controlCenterMirroringDataSource =
-                new ControlCenterMirroringDataSourceImpl(getApplication().getResources(),
-                        (intent, serviceConnection, flags) -> {
-                            bindService(intent, serviceConnection, flags);
-                            return Unit.INSTANCE;
-                        },
-                        (serviceConnection) -> {
-                            unbindService(serviceConnection);
-                            return Unit.INSTANCE;
-                        },
-                        getPackageManager(),
-                        Dispatchers.getIO()
-                );
-        UXRestrictionDataSource uxRestrictionDataSource = new UXRestrictionDataSourceImpl(
-                (CarUxRestrictionsManager) mCar.getCarManager(Car.CAR_UX_RESTRICTION_SERVICE),
-                (CarPackageManager) mCar.getCarManager(Car.PACKAGE_SERVICE),
-                getSystemService(MediaSessionManager.class),
-                getApplication().getResources(),
-                Dispatchers.getDefault()
-        );
-        AppOrderDataSource appOrderDataSource = new AppOrderProtoDataSourceImpl(
-                new LauncherItemListSource(getFilesDir(), "order.data"),
-                Dispatchers.getIO()
-        );
-
-        PackageManager packageManager = getPackageManager();
-        AppLaunchProviderFactory launchProviderFactory = new AppLaunchProviderFactory(
-                (CarMediaManager) mCar.getCarManager(Car.CAR_MEDIA_SERVICE),
-                mMode.mOpenMediaCenter,
-                () -> {
-                    finish();
-                    return Unit.INSTANCE;
-                },
-                getPackageManager());
-        AppShortcutsFactory appShortcutsFactory = new AppShortcutsFactory(
-                (CarMediaManager) mCar.getCarManager(Car.CAR_MEDIA_SERVICE),
-                Collections.emptySet(),
-                this::onShortcutsShow
-        );
-        CoroutineDispatcher bgDispatcher = Dispatchers.getDefault();
-
-        AppGridRepository repo = new AppGridRepositoryImpl(launcherActivities, mediaTemplateApps,
-                disabledApps, tosApps, controlCenterMirroringDataSource, uxRestrictionDataSource,
-                appOrderDataSource, packageManager, launchProviderFactory, appShortcutsFactory,
-                bgDispatcher);
-
-        mAppGridViewModel = new ViewModelProvider(this,
-                AppGridViewModel.Companion.provideFactory(repo, getApplication(), this, null)).get(
-                AppGridViewModel.class);
+        getSupportFragmentManager().beginTransaction().replace(R.id.fragmentContainer,
+                AppGridFragment.newInstance(parseMode(getIntent()))).commit();
     }
 
     @Override
     protected void onNewIntent(Intent intent) {
         super.onNewIntent(intent);
         setIntent(intent);
-        updateMode();
-    }
-
-    @Override
-    protected void onDestroy() {
-        if (mCar.isConnected()) {
-            mCar.disconnect();
-            mCar = null;
-        }
-        super.onDestroy();
-    }
-
-    private void updateMode() {
-        mMode = parseMode(getIntent());
-        setTitle(mMode.mTitleStringId);
+        Mode mode = parseMode(intent);
+        setTitle(mode.getTitleStringId());
         if (mShowToolbar) {
-            CarUi.requireToolbar(this).setTitle(mMode.mTitleStringId);
+            CarUi.requireToolbar(this).setTitle(mode.getTitleStringId());
+        }
+        Fragment fragment = getSupportFragmentManager().findFragmentById(R.id.fragmentContainer);
+        if (fragment instanceof AppGridFragment) {
+            ((AppGridFragment) fragment).updateMode(mode);
         }
-    }
-
-    @VisibleForTesting
-    boolean isHorizontal() {
-        return AppGridConstants.isHorizontal(mPageOrientation);
     }
 
     /**
@@ -430,254 +103,4 @@ public class AppGridActivity extends AppCompatActivity implements
         }
     }
 
-    @Override
-    protected void onResume() {
-        super.onResume();
-        updateScrollState();
-        mAdapter.setLayoutDirection(getResources().getConfiguration().getLayoutDirection());
-        mAppGridViewModel.updateMode(mMode);
-    }
-
-    @Override
-    public void onDimensionsUpdated(PageMeasurementHelper.PageDimensions pageDimens,
-            PageMeasurementHelper.GridDimensions gridDimens) {
-        // TODO(b/271637411): move this method into a scroll controller
-        mAppGridMarginHorizontal = pageDimens.marginHorizontalPx;
-        mAppGridMarginVertical = pageDimens.marginVerticalPx;
-        mAppGridWidth = gridDimens.gridWidthPx;
-        mAppGridHeight = gridDimens.gridHeightPx;
-    }
-
-    /**
-     * Updates the scroll state after receiving data changes, such as new apps being added or
-     * reordered, and when user returns to launcher onResume.
-     *
-     * Additionally, notify page indicator to handle resizing in case new app addition creates a
-     * new page or deleted a page.
-     */
-    void updateScrollState() {
-        // TODO(b/271637411): move this method into a scroll controller
-        // to calculate how many pages we need to offset, we use the scroll offset anchor position
-        // as item count and map to the page which the anchor is on.
-        int offsetPageCount = mAdapter.getPageCount(mNextScrollDestination + 1) - 1;
-        mRecyclerView.suppressLayout(false);
-        mCurrentScrollOffset = offsetPageCount * (isHorizontal()
-                ? (mAppGridWidth + 2 * mAppGridMarginHorizontal)
-                : (mAppGridHeight + 2 * mAppGridMarginVertical));
-        mLayoutManager.scrollToPositionWithOffset(/* position */
-                offsetPageCount * mNumOfRows * mNumOfCols, /* offset */ 0);
-
-        mPageIndicator.updateOffset(mCurrentScrollOffset);
-        mPageIndicator.updatePageCount(mAdapter.getPageCount());
-    }
-
-    @Override
-    protected void onPause() {
-        dismissShortcutPopup();
-        super.onPause();
-    }
-
-    @Override
-    public void onSnapToPosition(int position) {
-        mNextScrollDestination = position;
-    }
-
-    @Override
-    public void onItemLongPressed(boolean isLongPressed) {
-        // after the user long presses the app icon, scrolling should be disabled until long press
-        // is canceled as to allow MotionEvent to be interpreted as attempt to drag the app icon.
-        mRecyclerView.suppressLayout(isLongPressed);
-    }
-
-    @Override
-    public void onItemSelected(int gridPositionFrom) {
-        mIsCurrentlyDragging = true;
-        mLayoutManager.setShouldLayoutChildren(false);
-        mAdapter.setDragStartPoint(gridPositionFrom);
-        dismissShortcutPopup();
-    }
-
-    @Override
-    public void onItemDragged() {
-        mAppGridDragController.cancelDelayedPageFling();
-    }
-
-    @Override
-    public void onDragExited(int gridPosition, @AppItemBoundDirection int exitDirection) {
-        if (mAdapter.getOffsetBoundDirection(gridPosition) == exitDirection) {
-            mAppGridDragController.postDelayedPageFling(exitDirection);
-        }
-    }
-
-    @Override
-    public void onItemDropped(int gridPositionFrom, int gridPositionTo) {
-        mLayoutManager.setShouldLayoutChildren(true);
-        mAdapter.moveAppItem(gridPositionFrom, gridPositionTo);
-    }
-
-    public void onShortcutsShow(CarUiShortcutsPopup carUiShortcutsPopup) {
-        sCarUiShortcutsPopup = carUiShortcutsPopup;
-    }
-
-    private void dismissShortcutPopup() {
-        // TODO (b/268563442): shortcut popup is set to be static since its
-        // sometimes recreated when taskview is present, find out why
-        if (sCarUiShortcutsPopup != null) {
-            sCarUiShortcutsPopup.dismiss();
-            sCarUiShortcutsPopup = null;
-        }
-    }
-
-    @Override
-    public void onAppPositionChanged(int newPosition, AppItem appItem) {
-        mAppGridViewModel.saveAppOrder(newPosition, appItem);
-    }
-
-
-    private class AppGridOnScrollListener extends RecyclerView.OnScrollListener {
-        @Override
-        public void onScrolled(@NonNull RecyclerView recyclerView, int dx, int dy) {
-            mCurrentScrollOffset = mCurrentScrollOffset + (isHorizontal() ? dx : dy);
-            mPageIndicator.updateOffset(mCurrentScrollOffset);
-        }
-
-        @Override
-        public void onScrollStateChanged(@NonNull RecyclerView recyclerView, int newState) {
-            mCurrentScrollState = newState;
-            mSnapCallback.setScrollState(mCurrentScrollState);
-            switch (newState) {
-                case RecyclerView.SCROLL_STATE_DRAGGING:
-                    if (!mIsCurrentlyDragging) {
-                        mDragCallback.cancelDragTasks();
-                    }
-                    dismissShortcutPopup();
-                    mPageIndicator.animateAppearance();
-                    break;
-
-                case RecyclerView.SCROLL_STATE_SETTLING:
-                    mPageIndicator.animateAppearance();
-                    break;
-
-                case RecyclerView.SCROLL_STATE_IDLE:
-                    if (mIsCurrentlyDragging) {
-                        mLayoutManager.setShouldLayoutChildren(false);
-                    }
-                    mPageIndicator.animateFading();
-                    // in case the recyclerview was scrolled by rotary input, we need to handle
-                    // focusing the correct element: either on the first or last element on page
-                    mRecyclerView.maybeHandleRotaryFocus();
-            }
-        }
-    }
-
-    private class AppGridDragController {
-        // TODO: (b/271320404) move DragController to separate directory called dragndrop and
-        // migrate logic this class and AppItemViewHolder there.
-        private final Handler mHandler;
-
-        AppGridDragController() {
-            mHandler = new Handler(getMainLooper());
-        }
-
-        void cancelDelayedPageFling() {
-            mHandler.removeCallbacksAndMessages(null);
-        }
-
-        void postDelayedPageFling(@AppItemBoundDirection int exitDirection) {
-            boolean scrollToNextPage = isHorizontal()
-                    ? exitDirection == AppItemBoundDirection.RIGHT
-                    : exitDirection == AppItemBoundDirection.BOTTOM;
-            mHandler.removeCallbacksAndMessages(null);
-            mHandler.postDelayed(new Runnable() {
-                public void run() {
-                    if (mCurrentScrollState == RecyclerView.SCROLL_STATE_IDLE) {
-                        mAdapter.updatePageScrollDestination(scrollToNextPage);
-                        mNextScrollDestination = mSnapCallback.getSnapPosition();
-
-                        mLayoutManager.setShouldLayoutChildren(true);
-                        mRecyclerView.smoothScrollToPosition(mNextScrollDestination);
-                    }
-                    // another delayed scroll will be queued to enable the user to input multiple
-                    // page scrolls by holding the recyclerview at the app grid margin
-                    postDelayedPageFling(exitDirection);
-                }
-            }, mOffPageHoverBeforeScrollMs);
-        }
-    }
-
-    /**
-     * Private onDragListener for handling dispatching off page scroll event when user holds the app
-     * icon at the page margin.
-     */
-    private class AppGridDragListener implements View.OnDragListener {
-        @Override
-        public boolean onDrag(View v, DragEvent event) {
-            int action = event.getAction();
-            if (action == DragEvent.ACTION_DROP || action == DragEvent.ACTION_DRAG_ENDED) {
-                mIsCurrentlyDragging = false;
-                mAppGridDragController.cancelDelayedPageFling();
-                mDragCallback.resetCallbackState();
-                mLayoutManager.setShouldLayoutChildren(true);
-                if (action == DragEvent.ACTION_DROP) {
-                    return false;
-                } else {
-                    animateDropEnded(getDragSurface(event));
-                }
-            }
-            return true;
-        }
-    }
-
-    private void animateDropEnded(@Nullable SurfaceControl dragSurface) {
-        if (dragSurface == null) {
-            Log.d(TAG, "animateDropEnded, dragSurface unavailable");
-            return;
-        }
-        // update default animation for the drag shadow after user lifts their finger
-        SurfaceControl.Transaction txn = new SurfaceControl.Transaction();
-        // set an animator to animate a delay before clearing the dragSurface
-        ValueAnimator delayedDismissAnimator = ValueAnimator.ofFloat(0f, 1f);
-        delayedDismissAnimator.setStartDelay(
-                getResources().getInteger(R.integer.ms_drop_animation_delay));
-        delayedDismissAnimator.addUpdateListener(
-                new ValueAnimator.AnimatorUpdateListener() {
-                    @Override
-                    public void onAnimationUpdate(ValueAnimator animation) {
-                        txn.setAlpha(dragSurface, 0);
-                        txn.apply();
-                    }
-                });
-        delayedDismissAnimator.start();
-    }
-
-    private void setupTosBanner() {
-        asLiveData(mAppGridViewModel.getShouldShowTosBanner()).observe(AppGridActivity.this,
-                showBanner -> {
-                    if (showBanner) {
-                        mBanner.setVisibility(View.VISIBLE);
-                        // Pre draw is required for animation to work.
-                        mBanner.getViewTreeObserver().addOnPreDrawListener(
-                                new ViewTreeObserver.OnPreDrawListener() {
-                                    @Override
-                                    public boolean onPreDraw() {
-                                        mBanner.getViewTreeObserver().removeOnPreDrawListener(this);
-                                        mBackgroundAnimationHelper.showBanner();
-                                        return true;
-                                    }
-                                });
-                    } else {
-                        mBanner.setVisibility(View.GONE);
-                    }
-                });
-        mBanner.setFirstButtonOnClickListener(v -> {
-            Intent tosIntent = AppLauncherUtils.getIntentForTosAcceptanceFlow(v.getContext());
-            AppLauncherUtils.launchApp(v.getContext(), tosIntent);
-        });
-        mBanner.setSecondButtonOnClickListener(
-                v -> {
-                    mBackgroundAnimationHelper.hideBanner();
-                    mAppGridViewModel.saveTosBannerDismissalTime();
-                });
-    }
-
 }
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt
new file mode 100644
index 00000000..62735c0f
--- /dev/null
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt
@@ -0,0 +1,632 @@
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
+import android.animation.ValueAnimator
+import android.car.Car
+import android.car.content.pm.CarPackageManager
+import android.car.drivingstate.CarUxRestrictionsManager
+import android.car.media.CarMediaManager
+import android.content.BroadcastReceiver
+import android.content.Intent
+import android.content.IntentFilter
+import android.content.pm.LauncherApps
+import android.content.pm.PackageManager
+import android.media.session.MediaSessionManager
+import android.os.Bundle
+import android.os.Handler
+import android.os.Looper.getMainLooper
+import android.os.Process
+import android.os.UserManager
+import android.util.Log
+import android.view.DragEvent
+import android.view.LayoutInflater
+import android.view.SurfaceControl
+import android.view.View
+import android.view.ViewGroup
+import android.view.ViewTreeObserver
+import android.widget.FrameLayout
+import android.widget.LinearLayout
+import androidx.annotation.StringRes
+import androidx.fragment.app.Fragment
+import androidx.lifecycle.ViewModelProvider
+import androidx.lifecycle.asLiveData
+import androidx.recyclerview.widget.RecyclerView
+import com.android.car.carlauncher.AppGridConstants.AppItemBoundDirection
+import com.android.car.carlauncher.AppGridConstants.PageOrientation
+import com.android.car.carlauncher.AppGridConstants.isHorizontal
+import com.android.car.carlauncher.AppGridFragment.AppTypes.Companion.APP_TYPE_LAUNCHABLES
+import com.android.car.carlauncher.AppGridFragment.AppTypes.Companion.APP_TYPE_MEDIA_SERVICES
+import com.android.car.carlauncher.AppGridPageSnapper.AppGridPageSnapCallback
+import com.android.car.carlauncher.AppGridPageSnapper.PageSnapListener
+import com.android.car.carlauncher.AppGridViewModel.Companion.provideFactory
+import com.android.car.carlauncher.datasources.AppOrderDataSource
+import com.android.car.carlauncher.datasources.AppOrderProtoDataSourceImpl
+import com.android.car.carlauncher.datasources.ControlCenterMirroringDataSource
+import com.android.car.carlauncher.datasources.ControlCenterMirroringDataSourceImpl
+import com.android.car.carlauncher.datasources.ControlCenterMirroringDataSourceImpl.MirroringServiceConnection
+import com.android.car.carlauncher.datasources.LauncherActivitiesDataSource
+import com.android.car.carlauncher.datasources.LauncherActivitiesDataSourceImpl
+import com.android.car.carlauncher.datasources.MediaTemplateAppsDataSource
+import com.android.car.carlauncher.datasources.MediaTemplateAppsDataSourceImpl
+import com.android.car.carlauncher.datasources.UXRestrictionDataSource
+import com.android.car.carlauncher.datasources.UXRestrictionDataSourceImpl
+import com.android.car.carlauncher.datasources.restricted.DisabledAppsDataSource
+import com.android.car.carlauncher.datasources.restricted.DisabledAppsDataSourceImpl
+import com.android.car.carlauncher.datasources.restricted.TosDataSource
+import com.android.car.carlauncher.datasources.restricted.TosDataSourceImpl
+import com.android.car.carlauncher.datastore.launcheritem.LauncherItemListSource
+import com.android.car.carlauncher.pagination.PageMeasurementHelper
+import com.android.car.carlauncher.pagination.PaginationController
+import com.android.car.carlauncher.pagination.PaginationController.DimensionUpdateCallback
+import com.android.car.carlauncher.pagination.PaginationController.DimensionUpdateListener
+import com.android.car.carlauncher.recyclerview.AppGridAdapter
+import com.android.car.carlauncher.recyclerview.AppGridAdapter.AppGridAdapterListener
+import com.android.car.carlauncher.recyclerview.AppGridItemAnimator
+import com.android.car.carlauncher.recyclerview.AppGridLayoutManager
+import com.android.car.carlauncher.recyclerview.AppItemViewHolder.AppItemDragCallback
+import com.android.car.carlauncher.recyclerview.AppItemViewHolder.AppItemDragListener
+import com.android.car.carlauncher.repositories.AppGridRepository
+import com.android.car.carlauncher.repositories.AppGridRepositoryImpl
+import com.android.car.carlauncher.repositories.appactions.AppLaunchProviderFactory
+import com.android.car.carlauncher.repositories.appactions.AppShortcutsFactory
+import com.android.car.carlauncher.repositories.appactions.AppShortcutsFactory.ShortcutsListener
+import com.android.car.hidden.apis.HiddenApiAccess
+import com.android.car.ui.shortcutspopup.CarUiShortcutsPopup
+import kotlinx.coroutines.Dispatchers.Default
+import kotlinx.coroutines.Dispatchers.IO
+
+/**
+ * Fragment which renders the Apps based on the [Mode] provided in the [setArguments]
+ *
+ * To create an instance of this Fragment use [newInstance]
+ */
+class AppGridFragment : Fragment(), PageSnapListener, AppItemDragListener, DimensionUpdateListener,
+    AppGridAdapterListener {
+
+    private lateinit var car: Car
+    private lateinit var mode: Mode
+    private lateinit var snapCallback: AppGridPageSnapCallback
+    private lateinit var dragCallback: AppItemDragCallback
+    private lateinit var appGridDragController: AppGridDragController
+    private lateinit var appGridRecyclerView: AppGridRecyclerView
+    private lateinit var layoutManager: AppGridLayoutManager
+    private lateinit var pageIndicator: PageIndicator
+    private lateinit var adapter: AppGridAdapter
+    private lateinit var paginationController: PaginationController
+    private lateinit var backgroundAnimationHelper: BackgroundAnimationHelper
+    private lateinit var appGridViewModel: AppGridViewModel
+    private lateinit var banner: Banner
+
+    private var appGridMarginHorizontal = 0
+    private var appGridMarginVertical = 0
+    private var appGridWidth = 0
+    private var appGridHeight = 0
+    private var offPageHoverBeforeScrollMs = 0L
+    private var numOfCols = 0
+    private var numOfRows = 0
+    private var nextScrollDestination = 0
+    private var currentScrollOffset = 0
+    private var currentScrollState = 0
+    private var isCurrentlyDragging = false
+    private var carUiShortcutsPopup: CarUiShortcutsPopup? = null
+
+    @PageOrientation
+    private var pageOrientation = 0
+
+    override fun onCreateView(
+        inflater: LayoutInflater,
+        container: ViewGroup?,
+        savedInstanceState: Bundle?
+    ): View? {
+        super.onCreateView(inflater, container, savedInstanceState)
+        return inflater.inflate(R.layout.app_grid_fragment, container, false)
+    }
+
+    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
+        super.onViewCreated(view, savedInstanceState)
+        car = Car.createCar(requireContext()) ?: throw IllegalStateException("Car not initialized")
+        mode = Mode.valueOf(requireArguments().getString(MODE_INTENT_EXTRA, Mode.ALL_APPS.name))
+        initViewModel()
+        updateMode(mode)
+
+        snapCallback = AppGridPageSnapCallback(this)
+        dragCallback = AppItemDragCallback(this)
+
+        numOfCols = resources.getInteger(R.integer.car_app_selector_column_number)
+        numOfRows = resources.getInteger(R.integer.car_app_selector_row_number)
+        appGridDragController = AppGridDragController()
+        offPageHoverBeforeScrollMs = resources.getInteger(
+            R.integer.ms_off_page_hover_before_scroll
+        ).toLong()
+
+        pageOrientation =
+            if (resources.getBoolean(R.bool.use_vertical_app_grid)) {
+                PageOrientation.VERTICAL
+            } else {
+                PageOrientation.HORIZONTAL
+            }
+
+        appGridRecyclerView = view.requireViewById(R.id.apps_grid)
+        appGridRecyclerView.isFocusable = false
+        layoutManager =
+            AppGridLayoutManager(requireContext(), numOfCols, numOfRows, pageOrientation)
+        appGridRecyclerView.layoutManager = layoutManager
+
+        val pageSnapper = AppGridPageSnapper(
+            requireContext(),
+            numOfCols,
+            numOfRows,
+            snapCallback
+        )
+        pageSnapper.attachToRecyclerView(appGridRecyclerView)
+
+        appGridRecyclerView.itemAnimator = AppGridItemAnimator()
+
+        // hide the default scrollbar and replace it with a visual page indicator
+        appGridRecyclerView.isVerticalScrollBarEnabled = false
+        appGridRecyclerView.isHorizontalScrollBarEnabled = false
+        appGridRecyclerView.addOnScrollListener(AppGridOnScrollListener())
+
+        // TODO: (b/271637411) move this to be contained in a scroll controller
+        pageIndicator = view.requireViewById(R.id.page_indicator)
+        val pageIndicatorContainer: FrameLayout =
+            view.requireViewById(R.id.page_indicator_container)
+        pageIndicator.setContainer(pageIndicatorContainer)
+
+        // recycler view is set to LTR to prevent layout manager from reassigning layout direction.
+        // instead, PageIndexinghelper will determine the grid index based on the system layout
+        // direction and provide LTR mapping at adapter level.
+        appGridRecyclerView.layoutDirection = View.LAYOUT_DIRECTION_LTR
+        pageIndicatorContainer.layoutDirection = View.LAYOUT_DIRECTION_LTR
+
+        // we create but do not attach the adapter to recyclerview until view tree layout is
+        // complete and the total size of the app grid is measureable.
+        adapter = AppGridAdapter(
+            requireContext(), numOfCols, numOfRows, dragCallback, snapCallback, this, mode
+        )
+
+        adapter.registerAdapterDataObserver(object : RecyclerView.AdapterDataObserver() {
+            override fun onItemRangeMoved(fromPosition: Int, toPosition: Int, itemCount: Int) {
+                // scroll state will need to be updated after item has been dropped
+                nextScrollDestination = snapCallback.snapPosition
+                updateScrollState()
+            }
+        })
+        appGridRecyclerView.adapter = adapter
+
+        appGridViewModel.getAppList().asLiveData().observe(
+            viewLifecycleOwner
+        ) { appItems: List<AppItem?>? ->
+            adapter.setLauncherItems(appItems)
+            nextScrollDestination = snapCallback.snapPosition
+            updateScrollState()
+        }
+
+        appGridViewModel.requiresDistractionOptimization().asLiveData().observe(
+            viewLifecycleOwner
+        ) { uxRestrictions: Boolean ->
+            handleDistractionOptimization(
+                uxRestrictions
+            )
+        }
+
+        // set drag listener and global layout listener, which will dynamically adjust app grid
+        // height and width depending on device screen size. ize.
+        if (resources.getBoolean(R.bool.config_allow_reordering)) {
+            appGridRecyclerView.setOnDragListener(AppGridDragListener())
+        }
+
+        // since some measurements for window size may not be available yet during onCreate or may
+        // later change, we add a listener that redraws the app grid when window size changes.
+        val windowBackground: LinearLayout = view.requireViewById(R.id.apps_grid_background)
+        windowBackground.orientation =
+            if (isHorizontal(pageOrientation)) LinearLayout.VERTICAL else LinearLayout.HORIZONTAL
+        val dimensionUpdateCallback = DimensionUpdateCallback()
+        dimensionUpdateCallback.addListener(appGridRecyclerView)
+        dimensionUpdateCallback.addListener(pageIndicator)
+        dimensionUpdateCallback.addListener(this)
+        paginationController = PaginationController(windowBackground, dimensionUpdateCallback)
+
+        banner = view.requireViewById(R.id.tos_banner)
+
+        backgroundAnimationHelper = BackgroundAnimationHelper(windowBackground, banner)
+
+        setupTosBanner()
+    }
+
+    /**
+     * Updates the state of the app grid components depending on the driving state.
+     */
+    private fun handleDistractionOptimization(requiresDistractionOptimization: Boolean) {
+        adapter.setIsDistractionOptimizationRequired(requiresDistractionOptimization)
+        if (requiresDistractionOptimization) {
+            // if the user start driving while drag is in action, we cancel existing drag operations
+            if (isCurrentlyDragging) {
+                isCurrentlyDragging = false
+                layoutManager.setShouldLayoutChildren(true)
+                appGridRecyclerView.cancelDragAndDrop()
+            }
+            dismissShortcutPopup()
+        }
+    }
+
+    private fun initViewModel() {
+        val launcherActivities: LauncherActivitiesDataSource = LauncherActivitiesDataSourceImpl(
+            requireContext().getSystemService(LauncherApps::class.java),
+            { broadcastReceiver: BroadcastReceiver?, intentFilter: IntentFilter? ->
+                requireContext().registerReceiver(broadcastReceiver, intentFilter)
+            },
+            { broadcastReceiver: BroadcastReceiver? ->
+                requireContext().unregisterReceiver(broadcastReceiver)
+            },
+            Process.myUserHandle(),
+            requireContext().applicationContext.resources,
+            Default
+        )
+        val mediaTemplateApps: MediaTemplateAppsDataSource = MediaTemplateAppsDataSourceImpl(
+            requireContext().packageManager,
+            requireContext().applicationContext,
+            Default
+        )
+        val disabledApps: DisabledAppsDataSource = DisabledAppsDataSourceImpl(
+            requireContext().contentResolver,
+            requireContext().packageManager,
+            IO
+        )
+        val tosApps: TosDataSource = TosDataSourceImpl(
+            requireContext().contentResolver,
+            requireContext().packageManager,
+            IO
+        )
+        val controlCenterMirroringDataSource: ControlCenterMirroringDataSource =
+            ControlCenterMirroringDataSourceImpl(
+                requireContext().applicationContext.resources,
+                { intent: Intent, serviceConnection: MirroringServiceConnection, flags: Int ->
+                    requireContext().bindService(intent, serviceConnection, flags)
+                },
+                { serviceConnection: MirroringServiceConnection ->
+                    requireContext().unbindService(serviceConnection)
+                },
+                requireContext().packageManager,
+                IO
+            )
+        val uxRestrictionDataSource: UXRestrictionDataSource = UXRestrictionDataSourceImpl(
+            requireContext(),
+            requireNotNull(car.getCarManager(CarUxRestrictionsManager::class.java)),
+            requireNotNull(car.getCarManager(CarPackageManager::class.java)),
+            requireContext().getSystemService(MediaSessionManager::class.java),
+            requireContext().applicationContext.resources,
+            Default
+        )
+        val appOrderDataSource: AppOrderDataSource = AppOrderProtoDataSourceImpl(
+            LauncherItemListSource(requireContext().filesDir, "order.data"),
+            IO
+        )
+        val packageManager: PackageManager = requireContext().packageManager
+        val launchProviderFactory = AppLaunchProviderFactory(
+            requireNotNull(car.getCarManager(CarMediaManager::class.java)),
+            mode.openMediaCenter,
+            {
+                activity?.finish()
+            },
+            requireContext().packageManager
+        )
+
+        val appShortcutsFactory = AppShortcutsFactory(
+            requireNotNull(car.getCarManager(CarMediaManager::class.java)),
+            emptySet(),
+            object : ShortcutsListener {
+                override fun onShortcutsShow(carUiShortcutsPopup: CarUiShortcutsPopup) {
+                    this@AppGridFragment.carUiShortcutsPopup = carUiShortcutsPopup
+                }
+            }
+        )
+        val bgDispatcher = Default
+        val repo: AppGridRepository = AppGridRepositoryImpl(
+            launcherActivities, mediaTemplateApps,
+            disabledApps, tosApps, controlCenterMirroringDataSource, uxRestrictionDataSource,
+            appOrderDataSource, packageManager, launchProviderFactory, appShortcutsFactory,
+            requireContext().getSystemService(UserManager::class.java), bgDispatcher
+        )
+
+        appGridViewModel = ViewModelProvider(
+            this,
+            provideFactory(repo, requireActivity().application, this, null)
+        )[AppGridViewModel::class.java]
+    }
+
+    private fun animateDropEnded(dragSurface: SurfaceControl?) {
+        if (dragSurface == null) {
+            if (DEBUG_BUILD) {
+                Log.d(TAG, "animateDropEnded, dragSurface unavailable")
+            }
+            return
+        }
+        // update default animation for the drag shadow after user lifts their finger
+        val txn = SurfaceControl.Transaction()
+        // set an animator to animate a delay before clearing the dragSurface
+        val delayedDismissAnimator = ValueAnimator.ofFloat(0f, 1f)
+        delayedDismissAnimator.startDelay =
+            resources.getInteger(R.integer.ms_drop_animation_delay).toLong()
+        delayedDismissAnimator.addUpdateListener {
+            txn.setAlpha(dragSurface, 0f)
+            txn.apply()
+        }
+        delayedDismissAnimator.start()
+    }
+
+    private fun setupTosBanner() {
+        appGridViewModel.getShouldShowTosBanner().asLiveData()
+            .observe(
+                viewLifecycleOwner
+            ) { showBanner: Boolean ->
+                if (showBanner) {
+                    banner.visibility = View.VISIBLE
+                    // Pre draw is required for animation to work.
+                    banner.viewTreeObserver.addOnPreDrawListener(
+                        object : ViewTreeObserver.OnPreDrawListener {
+                            override fun onPreDraw(): Boolean {
+                                banner.viewTreeObserver.removeOnPreDrawListener(this)
+                                backgroundAnimationHelper.showBanner()
+                                return true
+                            }
+                        }
+                    )
+                } else {
+                    banner.visibility = View.GONE
+                }
+            }
+        banner.setFirstButtonOnClickListener { v: View ->
+            val tosIntent =
+                AppLauncherUtils.getIntentForTosAcceptanceFlow(v.context)
+            AppLauncherUtils.launchApp(v.context, tosIntent)
+        }
+        banner.setSecondButtonOnClickListener { _ ->
+            backgroundAnimationHelper.hideBanner()
+            appGridViewModel.saveTosBannerDismissalTime()
+        }
+    }
+
+    /**
+     * Updates the scroll state after receiving data changes, such as new apps being added or
+     * reordered, and when user returns to launcher onResume.
+     *
+     * Additionally, notify page indicator to handle resizing in case new app addition creates a
+     * new page or deleted a page.
+     */
+    fun updateScrollState() {
+        // TODO(b/271637411): move this method into a scroll controller
+        // to calculate how many pages we need to offset, we use the scroll offset anchor position
+        // as item count and map to the page which the anchor is on.
+        val offsetPageCount = adapter.getPageCount(nextScrollDestination + 1) - 1
+        appGridRecyclerView.suppressLayout(false)
+        currentScrollOffset =
+            offsetPageCount * if (isHorizontal(pageOrientation)) {
+                appGridWidth + 2 * appGridMarginHorizontal
+            } else {
+                appGridHeight + 2 * appGridMarginVertical
+            }
+        layoutManager.scrollToPositionWithOffset(offsetPageCount * numOfRows * numOfCols, 0)
+        pageIndicator.updateOffset(currentScrollOffset)
+        pageIndicator.updatePageCount(adapter.pageCount)
+    }
+
+    /**
+     * Change the mode of the apps shown in the AppGrid
+     * @see [Mode]
+     */
+    fun updateMode(mode: Mode) {
+        this.mode = mode
+        appGridViewModel.updateMode(mode)
+    }
+
+    private inner class AppGridOnScrollListener : RecyclerView.OnScrollListener() {
+        override fun onScrolled(recyclerView: RecyclerView, dx: Int, dy: Int) {
+            currentScrollOffset += if (isHorizontal(pageOrientation)) dx else dy
+            pageIndicator.updateOffset(currentScrollOffset)
+        }
+
+        override fun onScrollStateChanged(recyclerView: RecyclerView, newState: Int) {
+            currentScrollState = newState
+            snapCallback.scrollState = currentScrollState
+            when (newState) {
+                RecyclerView.SCROLL_STATE_DRAGGING -> {
+                    if (!isCurrentlyDragging) {
+                        dragCallback.cancelDragTasks()
+                    }
+                    dismissShortcutPopup()
+                    pageIndicator.animateAppearance()
+                }
+
+                RecyclerView.SCROLL_STATE_SETTLING -> pageIndicator.animateAppearance()
+                RecyclerView.SCROLL_STATE_IDLE -> {
+                    if (isCurrentlyDragging) {
+                        layoutManager.setShouldLayoutChildren(false)
+                    }
+                    pageIndicator.animateFading()
+                    // in case the recyclerview was scrolled by rotary input, we need to handle
+                    // focusing the correct element: either on the first or last element on page
+                    appGridRecyclerView.maybeHandleRotaryFocus()
+                }
+            }
+        }
+    }
+
+    private fun dismissShortcutPopup() {
+        carUiShortcutsPopup?.let {
+            it.dismiss()
+            carUiShortcutsPopup = null
+        }
+    }
+
+    override fun onPause() {
+        dismissShortcutPopup()
+        super.onPause()
+    }
+
+    override fun onDestroy() {
+        if (car.isConnected) {
+            car.disconnect()
+        }
+        super.onDestroy()
+    }
+
+    override fun onSnapToPosition(gridPosition: Int) {
+        nextScrollDestination = gridPosition
+    }
+
+    override fun onDimensionsUpdated(
+        pageDimens: PageMeasurementHelper.PageDimensions,
+        gridDimens: PageMeasurementHelper.GridDimensions
+    ) {
+        // TODO(b/271637411): move this method into a scroll controller
+        appGridMarginHorizontal = pageDimens.marginHorizontalPx
+        appGridMarginVertical = pageDimens.marginVerticalPx
+        appGridWidth = gridDimens.gridWidthPx
+        appGridHeight = gridDimens.gridHeightPx
+    }
+
+    override fun onAppPositionChanged(newPosition: Int, appItem: AppItem) {
+        appGridViewModel.saveAppOrder(newPosition, appItem)
+    }
+
+    override fun onItemLongPressed(longPressed: Boolean) {
+        // after the user long presses the app icon, scrolling should be disabled until long press
+        // is canceled as to allow MotionEvent to be interpreted as attempt to drag the app icon.
+        appGridRecyclerView.suppressLayout(longPressed)
+    }
+
+    override fun onItemSelected(gridPositionFrom: Int) {
+        isCurrentlyDragging = true
+        layoutManager.setShouldLayoutChildren(false)
+        adapter.setDragStartPoint(gridPositionFrom)
+        dismissShortcutPopup()
+    }
+
+    override fun onItemDragged() {
+        appGridDragController.cancelDelayedPageFling()
+    }
+
+    override fun onDragExited(gridPosition: Int, exitDirection: Int) {
+        if (adapter.getOffsetBoundDirection(gridPosition) == exitDirection) {
+            appGridDragController.postDelayedPageFling(exitDirection)
+        }
+    }
+
+    override fun onItemDropped(gridPositionFrom: Int, gridPositionTo: Int) {
+        layoutManager.setShouldLayoutChildren(true)
+        adapter.moveAppItem(gridPositionFrom, gridPositionTo)
+    }
+
+    private inner class AppGridDragController() {
+        // TODO: (b/271320404) move DragController to separate directory called dragndrop and
+        // migrate logic this class and AppItemViewHolder there.
+        private val handler: Handler = Handler(getMainLooper())
+
+        fun cancelDelayedPageFling() {
+            handler.removeCallbacksAndMessages(null)
+        }
+
+        fun postDelayedPageFling(@AppItemBoundDirection exitDirection: Int) {
+            val scrollToNextPage =
+                if (isHorizontal(pageOrientation)) {
+                    exitDirection == AppItemBoundDirection.RIGHT
+                } else {
+                    exitDirection == AppItemBoundDirection.BOTTOM
+                }
+            handler.removeCallbacksAndMessages(null)
+            handler.postDelayed({
+                if (currentScrollState == RecyclerView.SCROLL_STATE_IDLE) {
+                    adapter.updatePageScrollDestination(scrollToNextPage)
+                    nextScrollDestination = snapCallback.snapPosition
+                    layoutManager.setShouldLayoutChildren(true)
+                    appGridRecyclerView.smoothScrollToPosition(nextScrollDestination)
+                }
+                // another delayed scroll will be queued to enable the user to input multiple
+                // page scrolls by holding the recyclerview at the app grid margin
+                postDelayedPageFling(exitDirection)
+            }, offPageHoverBeforeScrollMs)
+        }
+    }
+
+    /**
+     * Private onDragListener for handling dispatching off page scroll event when user holds the app
+     * icon at the page margin.
+     */
+    private inner class AppGridDragListener : View.OnDragListener {
+        override fun onDrag(v: View, event: DragEvent): Boolean {
+            val action = event.action
+            if (action == DragEvent.ACTION_DROP || action == DragEvent.ACTION_DRAG_ENDED) {
+                isCurrentlyDragging = false
+                appGridDragController.cancelDelayedPageFling()
+                dragCallback.resetCallbackState()
+                layoutManager.setShouldLayoutChildren(true)
+                if (action == DragEvent.ACTION_DROP) {
+                    return false
+                } else {
+                    animateDropEnded(HiddenApiAccess.getDragSurface(event))
+                }
+            }
+            return true
+        }
+    }
+
+    annotation class AppTypes {
+        companion object {
+            const val APP_TYPE_LAUNCHABLES = 1
+            const val APP_TYPE_MEDIA_SERVICES = 2
+        }
+    }
+
+    enum class Mode(
+        @field:StringRes @param:StringRes val titleStringId: Int,
+        @field:AppTypes @param:AppTypes val appTypes: Int,
+        val openMediaCenter: Boolean
+    ) {
+        ALL_APPS(
+            R.string.app_launcher_title_all_apps,
+            APP_TYPE_LAUNCHABLES + APP_TYPE_MEDIA_SERVICES,
+            true
+        ),
+        MEDIA_ONLY(
+            R.string.app_launcher_title_media_only,
+            APP_TYPE_MEDIA_SERVICES,
+            true
+        ),
+        MEDIA_POPUP(
+            R.string.app_launcher_title_media_only,
+            APP_TYPE_MEDIA_SERVICES,
+            false
+        )
+    }
+
+    companion object {
+        const val TAG = "AppGridFragment"
+        const val DEBUG_BUILD = false
+        const val MODE_INTENT_EXTRA = "com.android.car.carlauncher.mode"
+
+        @JvmStatic
+        fun newInstance(mode: Mode): AppGridFragment {
+            return AppGridFragment().apply {
+                arguments = Bundle().apply {
+                    putString(MODE_INTENT_EXTRA, mode.name)
+                }
+            }
+        }
+    }
+}
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridViewModel.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridViewModel.kt
index de319776..37871111 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridViewModel.kt
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridViewModel.kt
@@ -26,8 +26,8 @@ import androidx.lifecycle.ViewModel
 import androidx.lifecycle.viewModelScope
 import androidx.preference.PreferenceManager
 import androidx.savedstate.SavedStateRegistryOwner
-import com.android.car.carlauncher.AppGridActivity.APP_TYPE_LAUNCHABLES
-import com.android.car.carlauncher.AppGridActivity.Mode
+import com.android.car.carlauncher.AppGridFragment.AppTypes.Companion.APP_TYPE_LAUNCHABLES
+import com.android.car.carlauncher.AppGridFragment.Mode
 import com.android.car.carlauncher.repositories.AppGridRepository
 import java.time.Clock
 import java.util.concurrent.TimeUnit
@@ -81,7 +81,7 @@ class AppGridViewModel(
     @OptIn(ExperimentalCoroutinesApi::class)
     fun getAppList(): Flow<List<AppItem>> {
         return appMode.transformLatest {
-            val sourceList = if (it.mAppTypes and APP_TYPE_LAUNCHABLES == 1) {
+            val sourceList = if (it.appTypes and APP_TYPE_LAUNCHABLES == 1) {
                 allAppsItemList
             } else {
                 mediaOnlyList
@@ -172,7 +172,6 @@ class AppGridViewModel(
 
     /**
      * Updates the current application display mode. This triggers UI updates in the app grid.
-     *
      * @param mode The new Mode to set for the application grid.
      */
     fun updateMode(mode: Mode) {
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/AppLauncherUtils.java b/libs/appgrid/lib/src/com/android/car/carlauncher/AppLauncherUtils.java
index 07c38bf8..a597ce0e 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/AppLauncherUtils.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/AppLauncherUtils.java
@@ -16,100 +16,40 @@
 
 package com.android.car.carlauncher;
 
-import static android.car.settings.CarSettings.Secure.KEY_PACKAGES_DISABLED_ON_RESOURCE_OVERUSE;
 import static android.car.settings.CarSettings.Secure.KEY_UNACCEPTED_TOS_DISABLED_APPS;
 import static android.car.settings.CarSettings.Secure.KEY_USER_TOS_ACCEPTED;
 
-import static java.lang.annotation.RetentionPolicy.SOURCE;
+import static com.android.car.carlauncher.datasources.restricted.TosDataSourceImpl.TOS_DISABLED_APPS_SEPARATOR;
+import static com.android.car.carlauncher.datasources.restricted.TosDataSourceImpl.TOS_NOT_ACCEPTED;
+import static com.android.car.carlauncher.datasources.restricted.TosDataSourceImpl.TOS_UNINITIALIZED;
 
-import android.app.Activity;
 import android.app.ActivityOptions;
-import android.car.Car;
-import android.car.CarNotConnectedException;
-import android.car.content.pm.CarPackageManager;
-import android.car.media.CarMediaManager;
-import android.content.ComponentName;
 import android.content.ContentResolver;
 import android.content.Context;
 import android.content.Intent;
-import android.content.pm.LauncherActivityInfo;
-import android.content.pm.LauncherApps;
-import android.content.pm.PackageManager;
-import android.content.pm.ResolveInfo;
 import android.os.Process;
 import android.os.UserHandle;
 import android.provider.Settings;
-import android.service.media.MediaBrowserService;
 import android.text.TextUtils;
 import android.util.ArraySet;
 import android.util.Log;
-import android.util.Pair;
-import android.view.View;
 
-import androidx.annotation.IntDef;
-import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
-import com.android.car.carlaunchercommon.shortcuts.AppInfoShortcutItem;
-import com.android.car.carlaunchercommon.shortcuts.ForceStopShortcutItem;
-import com.android.car.carlaunchercommon.shortcuts.PinShortcutItem;
-import com.android.car.dockutil.Flags;
-import com.android.car.dockutil.events.DockEventSenderHelper;
-import com.android.car.media.common.source.MediaSource;
-import com.android.car.ui.shortcutspopup.CarUiShortcutsPopup;
-
-import com.google.common.collect.Sets;
-
-import java.lang.annotation.Retention;
 import java.net.URISyntaxException;
-import java.util.ArrayList;
 import java.util.Arrays;
-import java.util.Collections;
-import java.util.Comparator;
-import java.util.HashMap;
-import java.util.List;
-import java.util.Map;
 import java.util.Objects;
 import java.util.Set;
-import java.util.function.Consumer;
-import java.util.stream.Collectors;
 
 /**
  * Util class that contains helper method used by app launcher classes.
  */
 public class AppLauncherUtils {
     private static final String TAG = "AppLauncherUtils";
-    private static final String ANDROIDX_CAR_APP_LAUNCHABLE = "androidx.car.app.launchable";
-
-    @Retention(SOURCE)
-    @IntDef({APP_TYPE_LAUNCHABLES, APP_TYPE_MEDIA_SERVICES})
-    @interface AppTypes {}
-
-    static final int APP_TYPE_LAUNCHABLES = 1;
-    static final int APP_TYPE_MEDIA_SERVICES = 2;
-
-    // This value indicates if TOS has not been accepted by the user
-    private static final String TOS_NOT_ACCEPTED = "1";
-    // This value indicates if TOS is in uninitialized state
-    private static final String TOS_UNINITIALIZED = "0";
-    static final String TOS_DISABLED_APPS_SEPARATOR = ",";
-    static final String PACKAGES_DISABLED_ON_RESOURCE_OVERUSE_SEPARATOR = ";";
-
-    // Max no. of uses tags in automotiveApp XML. This is an arbitrary limit to be defensive
-    // to bad input.
-    private static final int MAX_APP_TYPES = 64;
-    private static final String PACKAGE_URI_PREFIX = "package:";
 
     private AppLauncherUtils() {
     }
 
-    /**
-     * Comparator for {@link AppMetaData} that sorts the list
-     * by the "displayName" property in ascending order.
-     */
-    static final Comparator<AppMetaData> ALPHABETICAL_COMPARATOR = Comparator
-            .comparing(AppMetaData::getDisplayName, String::compareToIgnoreCase);
-
     /**
      * Helper method that launches the app given the app's AppMetaData.
      */
@@ -119,287 +59,6 @@ public class AppLauncherUtils {
         context.startActivity(intent, options.toBundle());
     }
 
-    /** Bundles application and services info. */
-    static class LauncherAppsInfo {
-        /*
-         * Map of all car launcher components' (including launcher activities and media services)
-         * metadata keyed by ComponentName.
-         */
-        private final Map<ComponentName, AppMetaData> mLaunchables;
-
-        /** Map of all the media services keyed by ComponentName. */
-        private final Map<ComponentName, ResolveInfo> mMediaServices;
-
-        LauncherAppsInfo(@NonNull Map<ComponentName, AppMetaData> launchablesMap,
-                @NonNull Map<ComponentName, ResolveInfo> mediaServices) {
-            mLaunchables = launchablesMap;
-            mMediaServices = mediaServices;
-        }
-
-        /** Returns true if all maps are empty. */
-        boolean isEmpty() {
-            return mLaunchables.isEmpty() && mMediaServices.isEmpty();
-        }
-
-        /**
-         * Returns whether the given componentName is a media service.
-         */
-        boolean isMediaService(ComponentName componentName) {
-            return mMediaServices.containsKey(componentName);
-        }
-
-        /** Returns the {@link AppMetaData} for the given componentName. */
-        @Nullable
-        AppMetaData getAppMetaData(ComponentName componentName) {
-            return mLaunchables.get(componentName);
-        }
-
-        /** Returns a new list of all launchable components' {@link AppMetaData}. */
-        @NonNull
-        List<AppMetaData> getLaunchableComponentsList() {
-            return new ArrayList<>(mLaunchables.values());
-        }
-
-        /** Returns list of Media Services for the launcher **/
-        @NonNull
-        Map<ComponentName, ResolveInfo> getMediaServices() {
-            return mMediaServices;
-        }
-    }
-
-    private static final LauncherAppsInfo EMPTY_APPS_INFO = new LauncherAppsInfo(
-            Collections.emptyMap(), Collections.emptyMap());
-
-    /**
-     * Gets the media source in a given package. If there are multiple sources in the package,
-     * returns the first one.
-     */
-    static ComponentName getMediaSource(@NonNull PackageManager packageManager,
-            @NonNull String packageName) {
-        Intent mediaIntent = new Intent();
-        mediaIntent.setPackage(packageName);
-        mediaIntent.setAction(MediaBrowserService.SERVICE_INTERFACE);
-
-        List<ResolveInfo> mediaServices = packageManager.queryIntentServices(mediaIntent,
-                PackageManager.GET_RESOLVED_FILTER);
-
-        if (mediaServices == null || mediaServices.isEmpty()) {
-            return null;
-        }
-        String defaultService = mediaServices.get(0).serviceInfo.name;
-        if (!TextUtils.isEmpty(defaultService)) {
-            return new ComponentName(packageName, defaultService);
-        }
-        return null;
-    }
-
-    /**
-     * Gets all the components that we want to see in the launcher in unsorted order, including
-     * launcher activities and media services.
-     *
-     * @param appsToHide            A (possibly empty) list of apps (package names) to hide
-     * @param appTypes              Types of apps to show (e.g.: all, or media sources only)
-     * @param openMediaCenter       Whether launcher should navigate to media center when the
-     *                              user selects a media source.
-     * @param launcherApps          The {@link LauncherApps} system service
-     * @param carPackageManager     The {@link CarPackageManager} system service
-     * @param packageManager        The {@link PackageManager} system service
-     *                              of such apps are always excluded.
-     * @param carMediaManager       The {@link CarMediaManager} system service
-     * @return a new {@link LauncherAppsInfo}
-     */
-    @NonNull
-    static LauncherAppsInfo getLauncherApps(
-            Context context,
-            @NonNull Set<String> appsToHide,
-            @AppTypes int appTypes,
-            boolean openMediaCenter,
-            LauncherApps launcherApps,
-            CarPackageManager carPackageManager,
-            PackageManager packageManager,
-            CarMediaManager carMediaManager,
-            ShortcutsListener shortcutsListener,
-            String mirroringAppPkgName,
-            Intent mirroringAppRedirect) {
-
-        if (launcherApps == null || carPackageManager == null || packageManager == null
-                || carMediaManager == null) {
-            return EMPTY_APPS_INFO;
-        }
-
-        // Using new list since we require a mutable list to do removeIf.
-        List<ResolveInfo> mediaServices = new ArrayList<>();
-        mediaServices.addAll(
-                packageManager.queryIntentServices(
-                        new Intent(MediaBrowserService.SERVICE_INTERFACE),
-                        PackageManager.GET_RESOLVED_FILTER));
-
-        List<LauncherActivityInfo> availableActivities =
-                launcherApps.getActivityList(null, Process.myUserHandle());
-
-        int launchablesSize = mediaServices.size() + availableActivities.size();
-        Map<ComponentName, AppMetaData> launchablesMap = new HashMap<>(launchablesSize);
-        Map<ComponentName, ResolveInfo> mediaServicesMap = new HashMap<>(mediaServices.size());
-        Set<String> mEnabledPackages = new ArraySet<>(launchablesSize);
-        Set<String> tosDisabledPackages = getTosDisabledPackages(context);
-        Set<ComponentName> mediaServiceComponents = mediaServices.stream()
-                .map(resolveInfo -> new ComponentName(resolveInfo.serviceInfo.packageName,
-                        resolveInfo.serviceInfo.name))
-                .collect(Collectors.toSet());
-
-        Set<String> customMediaComponents = Sets.newHashSet(
-                context.getResources().getStringArray(
-                        com.android.car.media.common.R.array.custom_media_packages));
-
-        // Process media services
-        if ((appTypes & APP_TYPE_MEDIA_SERVICES) != 0) {
-            for (ResolveInfo info : mediaServices) {
-                String packageName = info.serviceInfo.packageName;
-                String className = info.serviceInfo.name;
-                ComponentName componentName = new ComponentName(packageName, className);
-                mediaServicesMap.put(componentName, info);
-                mEnabledPackages.add(packageName);
-                if (shouldAddToLaunchables(context, componentName, appsToHide,
-                        customMediaComponents, appTypes, APP_TYPE_MEDIA_SERVICES)) {
-                    CharSequence displayName = info.serviceInfo.loadLabel(packageManager);
-                    AppMetaData appMetaData = new AppMetaData(
-                            displayName,
-                            componentName,
-                            info.serviceInfo.loadIcon(packageManager),
-                            /* isDistractionOptimized= */ true,
-                            /* isMirroring = */ false,
-                            /* isDisabledByTos= */ tosDisabledPackages.contains(packageName),
-                            contextArg -> {
-                                if (openMediaCenter) {
-                                    AppLauncherUtils.launchApp(contextArg,
-                                            createMediaLaunchIntent(componentName));
-                                } else {
-                                    selectMediaSourceAndFinish(contextArg, componentName,
-                                            carMediaManager);
-                                }
-                            },
-                            buildShortcuts(componentName, displayName, shortcutsListener,
-                                    carMediaManager, mediaServiceComponents));
-                    launchablesMap.put(componentName, appMetaData);
-                }
-            }
-        }
-
-        // Process activities
-        if ((appTypes & APP_TYPE_LAUNCHABLES) != 0) {
-            for (LauncherActivityInfo info : availableActivities) {
-                ComponentName componentName = info.getComponentName();
-                mEnabledPackages.add(componentName.getPackageName());
-                if (shouldAddToLaunchables(context, componentName, appsToHide,
-                        customMediaComponents, appTypes, APP_TYPE_LAUNCHABLES)) {
-                    boolean isDistractionOptimized =
-                            isActivityDistractionOptimized(carPackageManager,
-                                    componentName.getPackageName(), info.getName());
-                    boolean isDisabledByTos = tosDisabledPackages
-                            .contains(componentName.getPackageName());
-
-                    CharSequence displayName = info.getLabel();
-                    boolean isMirroring = componentName.getPackageName()
-                            .equals(mirroringAppPkgName);
-                    AppMetaData appMetaData = new AppMetaData(
-                            displayName,
-                            componentName,
-                            info.getBadgedIcon(0),
-                            isDistractionOptimized,
-                            isMirroring,
-                            isDisabledByTos,
-                            contextArg -> {
-                                if (componentName.getPackageName().equals(mirroringAppPkgName)) {
-                                    Log.d(TAG, "non-media service package name "
-                                            + "equals mirroring pkg name");
-                                }
-                                AppLauncherUtils.launchApp(contextArg,
-                                        isMirroring ? mirroringAppRedirect :
-                                                createAppLaunchIntent(componentName));
-                            },
-                            buildShortcuts(componentName, displayName, shortcutsListener,
-                                    carMediaManager, mediaServiceComponents));
-                    launchablesMap.put(componentName, appMetaData);
-                }
-            }
-
-            List<ResolveInfo> disabledActivities = getDisabledActivities(context, packageManager,
-                    mEnabledPackages);
-            for (ResolveInfo info : disabledActivities) {
-                String packageName = info.activityInfo.packageName;
-                String className = info.activityInfo.name;
-                ComponentName componentName = new ComponentName(packageName, className);
-                if (!shouldAddToLaunchables(context, componentName, appsToHide,
-                        customMediaComponents, appTypes, APP_TYPE_LAUNCHABLES)) {
-                    continue;
-                }
-                boolean isDistractionOptimized =
-                        isActivityDistractionOptimized(carPackageManager, packageName, className);
-                boolean isDisabledByTos = tosDisabledPackages.contains(packageName);
-
-                CharSequence displayName = info.activityInfo.loadLabel(packageManager);
-                AppMetaData appMetaData = new AppMetaData(
-                        displayName,
-                        componentName,
-                        info.activityInfo.loadIcon(packageManager),
-                        isDistractionOptimized,
-                        /* isMirroring = */ false,
-                        isDisabledByTos,
-                        contextArg -> {
-                            packageManager.setApplicationEnabledSetting(packageName,
-                                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED, 0);
-                            // Fetch the current enabled setting to make sure the setting is synced
-                            // before launching the activity. Otherwise, the activity may not
-                            // launch.
-                            if (packageManager.getApplicationEnabledSetting(packageName)
-                                    != PackageManager.COMPONENT_ENABLED_STATE_ENABLED) {
-                                throw new IllegalStateException(
-                                        "Failed to enable the disabled package [" + packageName
-                                                + "]");
-                            }
-                            Log.i(TAG, "Successfully enabled package [" + packageName + "]");
-                            AppLauncherUtils.launchApp(contextArg,
-                                    createAppLaunchIntent(componentName));
-                        },
-                        buildShortcuts(componentName, displayName, shortcutsListener,
-                                carMediaManager, mediaServiceComponents));
-                launchablesMap.put(componentName, appMetaData);
-            }
-
-            List<ResolveInfo> restrictedActivities = getTosDisabledActivities(
-                    context,
-                    packageManager,
-                    mEnabledPackages
-            );
-            for (ResolveInfo info: restrictedActivities) {
-                String packageName = info.activityInfo.packageName;
-                String className = info.activityInfo.name;
-                ComponentName componentName = new ComponentName(packageName, className);
-
-                boolean isDistractionOptimized =
-                        isActivityDistractionOptimized(carPackageManager, packageName, className);
-                boolean isDisabledByTos = tosDisabledPackages.contains(packageName);
-
-                AppMetaData appMetaData = new AppMetaData(
-                        info.activityInfo.loadLabel(packageManager),
-                        componentName,
-                        info.activityInfo.loadIcon(packageManager),
-                        isDistractionOptimized,
-                        /* isMirroring = */ false,
-                        isDisabledByTos,
-                        contextArg -> {
-                            Intent tosIntent = getIntentForTosAcceptanceFlow(contextArg);
-                            launchApp(contextArg, tosIntent);
-                        },
-                        null
-                );
-                launchablesMap.put(componentName, appMetaData);
-            }
-        }
-
-        return new LauncherAppsInfo(launchablesMap, mediaServicesMap);
-    }
-
     /**
      * Gets the intent for launching the TOS acceptance flow
      *
@@ -418,197 +77,6 @@ public class AppLauncherUtils {
         }
     }
 
-    private static Consumer<Pair<Context, View>> buildShortcuts(
-            ComponentName componentName, CharSequence displayName,
-            ShortcutsListener shortcutsListener, CarMediaManager carMediaManager,
-            Set<ComponentName> mediaServiceComponents) {
-        return pair -> {
-            CarUiShortcutsPopup.Builder carUiShortcutsPopupBuilder =
-                    new CarUiShortcutsPopup.Builder()
-                            .addShortcut(new ForceStopShortcutItem(
-                                    pair.first,
-                                    componentName.getPackageName(),
-                                    displayName,
-                                    carMediaManager,
-                                    mediaServiceComponents
-                            ))
-                            .addShortcut(new AppInfoShortcutItem(pair.first,
-                                    componentName.getPackageName(),
-                                    UserHandle.getUserHandleForUid(Process.myUid())));
-            if (Flags.dockFeature()) {
-                carUiShortcutsPopupBuilder
-                        .addShortcut(buildPinToDockShortcut(componentName, pair.first));
-            }
-            CarUiShortcutsPopup carUiShortcutsPopup = carUiShortcutsPopupBuilder
-                    .build(pair.first, pair.second);
-
-            carUiShortcutsPopup.show();
-            shortcutsListener.onShortcutsShow(carUiShortcutsPopup);
-        };
-    }
-
-    private static CarUiShortcutsPopup.ShortcutItem buildPinToDockShortcut(
-            ComponentName componentName, Context context) {
-        DockEventSenderHelper mHelper = new DockEventSenderHelper(context);
-        return new PinShortcutItem(context.getResources(), /* isItemPinned= */ false,
-                /* pinItemClickDelegate= */ () -> mHelper.sendPinEvent(componentName),
-                /* unpinItemClickDelegate= */ () -> mHelper.sendUnpinEvent(componentName)
-        );
-    }
-
-    private static List<ResolveInfo> getDisabledActivities(Context context,
-            PackageManager packageManager, Set<String> enabledPackages) {
-        return getActivitiesFromSystemPreferences(
-                context,
-                packageManager,
-                enabledPackages,
-                KEY_PACKAGES_DISABLED_ON_RESOURCE_OVERUSE,
-                PackageManager.MATCH_DISABLED_UNTIL_USED_COMPONENTS,
-                PACKAGES_DISABLED_ON_RESOURCE_OVERUSE_SEPARATOR);
-    }
-
-    private static List<ResolveInfo> getTosDisabledActivities(
-            Context context,
-            PackageManager packageManager,
-            Set<String> enabledPackages) {
-        return getActivitiesFromSystemPreferences(
-                context,
-                packageManager,
-                enabledPackages,
-                KEY_UNACCEPTED_TOS_DISABLED_APPS,
-                PackageManager.MATCH_DISABLED_COMPONENTS,
-                TOS_DISABLED_APPS_SEPARATOR);
-    }
-
-    /**
-     * Get a list of activities from packages in system preferences by key
-     * @param context the app context
-     * @param packageManager The PackageManager
-     * @param enabledPackages Set of packages enabled by system
-     * @param settingsKey Key to read from system preferences
-     * @param sep Separator
-     *
-     * @return List of activities read from system preferences
-     */
-    private static List<ResolveInfo> getActivitiesFromSystemPreferences(
-            Context context,
-            PackageManager packageManager,
-            Set<String> enabledPackages,
-            String settingsKey,
-            int filter,
-            String sep) {
-        ContentResolver contentResolverForUser = context.createContextAsUser(
-                        UserHandle.getUserHandleForUid(Process.myUid()), /* flags= */ 0)
-                .getContentResolver();
-        String settingsValue = Settings.Secure.getString(contentResolverForUser, settingsKey);
-        Set<String> packages = TextUtils.isEmpty(settingsValue) ? new ArraySet<>()
-                : new ArraySet<>(Arrays.asList(settingsValue.split(
-                        sep)));
-
-        if (packages.isEmpty()) {
-            return Collections.emptyList();
-        }
-
-        List<ResolveInfo> allActivities = packageManager.queryIntentActivities(
-                new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER),
-                PackageManager.ResolveInfoFlags.of(PackageManager.GET_RESOLVED_FILTER
-                        | filter));
-
-        List<ResolveInfo> activities = new ArrayList<>();
-        for (int i = 0; i < allActivities.size(); ++i) {
-            ResolveInfo info = allActivities.get(i);
-            if (!enabledPackages.contains(info.activityInfo.packageName)
-                    && packages.contains(info.activityInfo.packageName)) {
-                activities.add(info);
-            }
-        }
-        return activities;
-    }
-
-    private static boolean shouldAddToLaunchables(Context context,
-            @NonNull ComponentName componentName,
-            @NonNull Set<String> appsToHide,
-            @NonNull Set<String> customMediaComponents,
-            @AppTypes int appTypesToShow,
-            @AppTypes int componentAppType) {
-        if (appsToHide.contains(componentName.getPackageName())) {
-            return false;
-        }
-        switch (componentAppType) {
-            // Process media services
-            case APP_TYPE_MEDIA_SERVICES:
-                // For a media service in customMediaComponents, if its application's launcher
-                // activity will be shown in the Launcher, don't show the service's icon in the
-                // Launcher.
-                if (customMediaComponents.contains(componentName.flattenToString())) {
-                    if ((appTypesToShow & APP_TYPE_LAUNCHABLES) != 0) {
-                        if (Log.isLoggable(TAG, Log.DEBUG)) {
-                            Log.d(TAG, "MBS for custom media app " + componentName
-                                    + " is skipped in app launcher");
-                        }
-                        return false;
-                    }
-                    // Media switcher use case should still show
-                    if (Log.isLoggable(TAG, Log.DEBUG)) {
-                        Log.d(TAG, "MBS for custom media app " + componentName
-                                + " is included in media switcher");
-                    }
-                    return true;
-                }
-                // Only Keep MBS that is a media template
-                return MediaSource.isMediaTemplate(context, componentName);
-            // Process activities
-            case APP_TYPE_LAUNCHABLES:
-                return true;
-            default:
-                Log.e(TAG, "Invalid componentAppType : " + componentAppType);
-                return false;
-        }
-    }
-
-    private static void selectMediaSourceAndFinish(Context context, ComponentName componentName,
-            CarMediaManager carMediaManager) {
-        try {
-            carMediaManager.setMediaSource(componentName, CarMediaManager.MEDIA_SOURCE_MODE_BROWSE);
-            if (context instanceof Activity) {
-                ((Activity) context).finish();
-            }
-        } catch (CarNotConnectedException e) {
-            Log.e(TAG, "Car not connected", e);
-        }
-    }
-
-    /**
-     * Gets if an activity is distraction optimized.
-     *
-     * @param carPackageManager The {@link CarPackageManager} system service
-     * @param packageName       The package name of the app
-     * @param activityName      The requested activity name
-     * @return true if the supplied activity is distraction optimized
-     */
-    static boolean isActivityDistractionOptimized(
-            CarPackageManager carPackageManager, String packageName, String activityName) {
-        boolean isDistractionOptimized = false;
-        // try getting distraction optimization info
-        try {
-            if (carPackageManager != null) {
-                isDistractionOptimized =
-                        carPackageManager.isActivityDistractionOptimized(packageName, activityName);
-            }
-        } catch (CarNotConnectedException e) {
-            Log.e(TAG, "Car not connected when getting DO info", e);
-        }
-        return isDistractionOptimized;
-    }
-
-    /**
-     * Callback when a ShortcutsPopup View is shown
-     */
-    protected interface ShortcutsListener {
-
-        void onShortcutsShow(CarUiShortcutsPopup carUiShortcutsPopup);
-    }
-
     /**
      * Returns a set of packages that are disabled by tos
      *
@@ -626,18 +94,6 @@ public class AppLauncherUtils {
                         TOS_DISABLED_APPS_SEPARATOR)));
     }
 
-    private static Intent createMediaLaunchIntent(ComponentName componentName) {
-        return new Intent(Car.CAR_INTENT_ACTION_MEDIA_TEMPLATE)
-                .putExtra(Car.CAR_EXTRA_MEDIA_COMPONENT, componentName.flattenToString());
-    }
-
-    private static Intent createAppLaunchIntent(ComponentName componentName) {
-        return new Intent(Intent.ACTION_MAIN)
-                .setComponent(componentName)
-                .addCategory(Intent.CATEGORY_LAUNCHER)
-                .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-    }
-
     /**
      * Check if a user has accepted TOS
      *
@@ -658,7 +114,6 @@ public class AppLauncherUtils {
      * Check if TOS status is uninitialized
      *
      * @param context The application context
-     *
      * @return true if tos is uninitialized, false otherwise
      */
     static boolean tosStatusUninitialized(Context context) {
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/LauncherItemMessageHelper.java b/libs/appgrid/lib/src/com/android/car/carlauncher/LauncherItemMessageHelper.java
deleted file mode 100644
index 65487251..00000000
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/LauncherItemMessageHelper.java
+++ /dev/null
@@ -1,67 +0,0 @@
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
-package com.android.car.carlauncher;
-
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
-
-import com.android.car.carlauncher.LauncherItemProto.LauncherItemListMessage;
-import com.android.car.carlauncher.LauncherItemProto.LauncherItemMessage;
-
-import java.util.ArrayList;
-import java.util.Collections;
-import java.util.Comparator;
-import java.util.List;
-
-/**
- * Helper class that provides method used by LauncherModel
- */
-public class LauncherItemMessageHelper {
-    /**
-     * Convert a List of {@link LauncherItemMessage} to a single {@link LauncherItemListMessage}.
-     */
-    @Nullable
-    public LauncherItemListMessage convertToMessage(List<LauncherItemMessage> msgList) {
-        if (msgList == null) {
-            return null;
-        }
-        LauncherItemListMessage.Builder builder =
-                LauncherItemListMessage.newBuilder().addAllLauncherItemMessage(msgList);
-        return builder.build();
-    }
-
-    /**
-     * Converts {@link LauncherItemListMessage} to a List of {@link LauncherItemMessage},
-     * sorts the LauncherItemList based on their relative order in the file, then return the list.
-     */
-    @NonNull
-    public List<LauncherItemMessage> getSortedList(@Nullable LauncherItemListMessage protoLstMsg) {
-        if (protoLstMsg == null) {
-            return new ArrayList<>();
-        }
-        List<LauncherItemMessage> itemMsgList = protoLstMsg.getLauncherItemMessageList();
-        List<LauncherItemMessage> sortedItemMsgList = new ArrayList<>();
-        if (!itemMsgList.isEmpty() && itemMsgList.size() > 0) {
-            // need to create a new list for sorting purposes since ProtobufArrayList is not mutable
-            sortedItemMsgList.addAll(itemMsgList);
-            Collections.sort(sortedItemMsgList,
-                    Comparator.comparingInt(LauncherItemMessage::getRelativePosition));
-        }
-        return sortedItemMsgList;
-    }
-}
-
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/LauncherViewModel.java b/libs/appgrid/lib/src/com/android/car/carlauncher/LauncherViewModel.java
deleted file mode 100644
index 80602abb..00000000
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/LauncherViewModel.java
+++ /dev/null
@@ -1,100 +0,0 @@
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
-package com.android.car.carlauncher;
-
-import android.content.ComponentName;
-import android.content.Intent;
-
-import androidx.lifecycle.LiveData;
-import androidx.lifecycle.ViewModel;
-
-import com.android.car.carlauncher.apporder.AppOrderController;
-
-import java.io.File;
-import java.util.ArrayList;
-import java.util.Collections;
-import java.util.Comparator;
-import java.util.HashMap;
-import java.util.List;
-import java.util.Map;
-
-/**
- * A launcher model decides how the apps are displayed.
- */
-public class LauncherViewModel extends ViewModel {
-    private final AppOrderController mAppOrderController;
-
-    public LauncherViewModel(File launcherFileDir) {
-        mAppOrderController = new AppOrderController(launcherFileDir);
-    }
-
-    public static final Comparator<LauncherItem> ALPHABETICAL_COMPARATOR = Comparator.comparing(
-            LauncherItem::getDisplayName, String::compareToIgnoreCase);
-
-    public LiveData<List<LauncherItem>> getCurrentLauncher() {
-        return mAppOrderController.getAppOrderObservable();
-    }
-
-    /**
-     * Read in apps order from file if exists, then publish app order to UI if valid.
-     */
-    public void loadAppsOrderFromFile() {
-        mAppOrderController.loadAppOrderFromFile();
-    }
-
-    /**
-     * Populate the apps based on alphabetical order and create mapping from packageName to
-     * LauncherItem. Each item in the current launcher is AppItem.
-     */
-    public void processAppsInfoFromPlatform(AppLauncherUtils.LauncherAppsInfo launcherAppsInfo) {
-        Map<ComponentName, LauncherItem> launcherItemsMap = new HashMap<>();
-        List<LauncherItem> launcherItems = new ArrayList<>();
-        List<AppMetaData> appMetaDataList = launcherAppsInfo.getLaunchableComponentsList();
-        for (AppMetaData appMetaData : appMetaDataList) {
-            LauncherItem nextItem = new AppItem(appMetaData);
-            launcherItems.add(nextItem);
-            launcherItemsMap.put(appMetaData.getComponentName(), nextItem);
-        }
-        Collections.sort(launcherItems, LauncherViewModel.ALPHABETICAL_COMPARATOR);
-        mAppOrderController.loadAppListFromPlatform(launcherItemsMap, launcherItems);
-    }
-
-    /**
-     * Notifies the controller that a change in the data model has been observed by the user
-     * interface (e.g. platform apps list has been updated, user has updated the app order.)
-     *
-     * The controller should ONLY handle writing to disk in this method. This will ensure that all
-     * changes to the data model is consistent with the user interface.
-     */
-    public void handleAppListChange() {
-        mAppOrderController.handleAppListChange();
-    }
-
-    /**
-     * Notifies the controller to move the given AppItem to a new position in the data model.
-     */
-    public void setAppPosition(int position, AppMetaData app) {
-        mAppOrderController.setAppPosition(position, app);
-    }
-
-    /**
-     * Updates the launcher data model when app mirroring intent is received.
-     */
-    public void updateMirroringItem(String packageName, Intent mirroringIntent) {
-        mAppOrderController.updateMirroringItem(packageName, mirroringIntent);
-    }
-}
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/LauncherViewModelFactory.java b/libs/appgrid/lib/src/com/android/car/carlauncher/LauncherViewModelFactory.java
deleted file mode 100644
index 0abd622e..00000000
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/LauncherViewModelFactory.java
+++ /dev/null
@@ -1,36 +0,0 @@
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
-package com.android.car.carlauncher;
-
-import androidx.lifecycle.ViewModel;
-import androidx.lifecycle.ViewModelProvider;
-
-import java.io.File;
-
-/** A factory class to allow creation of LauncherViewModel by ViewModelProvider. */
-public class LauncherViewModelFactory implements ViewModelProvider.Factory{
-    private File mLauncherFileDir;
-
-    public LauncherViewModelFactory(File launcherFileDir) {
-        mLauncherFileDir = launcherFileDir;
-    }
-
-    @Override
-    public <T extends ViewModel> T create(Class<T> modelClass) {
-        return (T) new LauncherViewModel(mLauncherFileDir);
-    }
-}
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/MediaSessionUtils.java b/libs/appgrid/lib/src/com/android/car/carlauncher/MediaSessionUtils.java
new file mode 100644
index 00000000..b296f62f
--- /dev/null
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/MediaSessionUtils.java
@@ -0,0 +1,67 @@
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
+package com.android.car.carlauncher;
+
+import android.app.Notification;
+import android.app.NotificationManager;
+import android.content.Context;
+import android.os.RemoteException;
+import android.service.notification.StatusBarNotification;
+import android.util.Log;
+
+import com.android.car.media.common.source.MediaModels;
+import com.android.car.media.common.source.MediaSessionHelper;
+
+/** Utility class that handles common MediaSession related logic*/
+public class MediaSessionUtils {
+    private static final String TAG = "MediaSessionUtils";
+
+    private MediaSessionUtils() {}
+
+    /** Create a MediaModels object */
+    public static MediaModels getMediaModels(Context context) {
+        return new MediaModels(context.getApplicationContext(),
+                createNotificationProvider(context));
+    }
+
+    /** Create a MediaSessionHelper object */
+    public static MediaSessionHelper getMediaSessionHelper(Context context) {
+        return new MediaSessionHelper(context.getApplicationContext(),
+                createNotificationProvider(context));
+    }
+
+    private static MediaSessionHelper.NotificationProvider createNotificationProvider(
+            Context context) {
+        return new MediaSessionHelper.NotificationProvider() {
+            @Override
+            public StatusBarNotification[] getActiveNotifications() {
+                try {
+                    return NotificationManager.getService()
+                            .getActiveNotificationsWithAttribution(
+                                    context.getPackageName(), null);
+                } catch (RemoteException e) {
+                    Log.e(TAG, "Exception trying to get active notifications " + e);
+                    return new StatusBarNotification[0];
+                }
+            }
+
+            @Override
+            public boolean isMediaNotification(Notification notification) {
+                return notification.isMediaNotification();
+            }
+        };
+    }
+}
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/ResetLauncherActivity.java b/libs/appgrid/lib/src/com/android/car/carlauncher/ResetLauncherActivity.java
index efd098ac..75c51572 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/ResetLauncherActivity.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/ResetLauncherActivity.java
@@ -18,7 +18,6 @@ import android.app.Activity;
 import android.app.AlertDialog;
 import android.os.Bundle;
 
-import com.android.car.carlauncher.apporder.AppOrderController;
 import com.android.car.ui.AlertDialogBuilder;
 
 import java.io.File;
@@ -39,7 +38,7 @@ public class ResetLauncherActivity extends Activity {
                 .setTitle(getString(R.string.reset_appgrid_title))
                 .setMessage(getString(R.string.reset_appgrid_dialogue_message))
                 .setPositiveButton(getString(android.R.string.ok), (dialogInterface, which) -> {
-                    File order = new File(filesDir, AppOrderController.ORDER_FILE_NAME);
+                    File order = new File(filesDir, "order.data");
                     order.delete();
                     finish();
                 })
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/apporder/AppOrderController.java b/libs/appgrid/lib/src/com/android/car/carlauncher/apporder/AppOrderController.java
deleted file mode 100644
index 3306c546..00000000
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/apporder/AppOrderController.java
+++ /dev/null
@@ -1,264 +0,0 @@
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
-package com.android.car.carlauncher.apporder;
-
-import android.content.ComponentName;
-import android.content.Intent;
-
-import androidx.annotation.VisibleForTesting;
-import androidx.lifecycle.MutableLiveData;
-
-import com.android.car.carlauncher.AppItem;
-import com.android.car.carlauncher.AppLauncherUtils;
-import com.android.car.carlauncher.AppMetaData;
-import com.android.car.carlauncher.LauncherItem;
-import com.android.car.carlauncher.LauncherItemMessageHelper;
-import com.android.car.carlauncher.LauncherItemProto.LauncherItemListMessage;
-import com.android.car.carlauncher.LauncherItemProto.LauncherItemMessage;
-import com.android.car.carlauncher.datastore.DataSourceController;
-import com.android.car.carlauncher.datastore.launcheritem.LauncherItemListSource;
-
-import java.io.File;
-import java.util.ArrayList;
-import java.util.Collections;
-import java.util.HashMap;
-import java.util.HashSet;
-import java.util.List;
-import java.util.Map;
-import java.util.Set;
-import java.util.stream.Collectors;
-
-/**
- * Controller that manages the ordering of the app items in app grid.
- */
-public class AppOrderController implements DataSourceController {
-    // file name holding the user customized app order
-    public static final String ORDER_FILE_NAME = "order.data";
-    private final LauncherItemMessageHelper mItemHelper = new LauncherItemMessageHelper();
-    // The app order of launcher items displayed to users
-    private final MutableLiveData<List<LauncherItem>> mCurrentAppList;
-    private final Map<ComponentName, LauncherItem> mLauncherItemMap = new HashMap<>();
-    private final List<ComponentName> mProtoComponentNames = new ArrayList<>();
-    private final List<LauncherItem> mDefaultOrder;
-    private final List<LauncherItem> mCustomizedOrder;
-    private final LauncherItemListSource mDataSource;
-    private boolean mPlatformAppListLoaded;
-    private boolean mCustomAppOrderFetched;
-    private boolean mIsUserCustomized;
-
-    public AppOrderController(File dataFileDirectory) {
-        this(/* dataSource */ new LauncherItemListSource(dataFileDirectory, ORDER_FILE_NAME),
-                /* appList */ new MutableLiveData<>(new ArrayList<>()),
-                /* defaultOrder */ new ArrayList<>(),
-                /* customizedOrder*/ new ArrayList<>());
-    }
-
-    public AppOrderController(LauncherItemListSource dataSource,
-            MutableLiveData<List<LauncherItem>> appList, List<LauncherItem> defaultOrder,
-            List<LauncherItem> customizedOrder) {
-        mDataSource = dataSource;
-        mCurrentAppList = appList;
-        mDefaultOrder = defaultOrder;
-        mCustomizedOrder = customizedOrder;
-    }
-
-    @Override
-    public boolean checkDataSourceExists() {
-        return mDataSource.exists();
-    }
-
-    public MutableLiveData<List<LauncherItem>> getAppOrderObservable() {
-        return mCurrentAppList;
-    }
-
-    /**
-     * Loads the full app list to be displayed in the app grid.
-     */
-    public void loadAppListFromPlatform(Map<ComponentName, LauncherItem> launcherItemsMap,
-            List<LauncherItem> defaultItemOrder) {
-        mDefaultOrder.clear();
-        mDefaultOrder.addAll(defaultItemOrder);
-        mLauncherItemMap.clear();
-        mLauncherItemMap.putAll(launcherItemsMap);
-        mPlatformAppListLoaded = true;
-        maybePublishAppList();
-    }
-
-    /**
-     * Loads any preexisting app order from the proto datastore on disk.
-     */
-    public void loadAppOrderFromFile() {
-        // handle the app order reset case, where the proto file is removed from file system
-        maybeHandleAppOrderReset();
-        mProtoComponentNames.clear();
-        List<LauncherItemMessage> protoItemMessage = mItemHelper.getSortedList(
-                mDataSource.readFromFile());
-        if (!protoItemMessage.isEmpty()) {
-            mIsUserCustomized = true;
-            for (LauncherItemMessage itemMessage : protoItemMessage) {
-                ComponentName itemComponent = new ComponentName(
-                        itemMessage.getPackageName(), itemMessage.getClassName());
-                mProtoComponentNames.add(itemComponent);
-            }
-        }
-        mCustomAppOrderFetched = true;
-        maybePublishAppList();
-    }
-
-    @VisibleForTesting
-    void maybeHandleAppOrderReset() {
-        if (!checkDataSourceExists()) {
-            mIsUserCustomized = false;
-            mCustomizedOrder.clear();
-        }
-    }
-
-    /**
-     * Combine the proto order read from proto with any additional apps read from the platform, then
-     * publish the new list to user interface.
-     *
-     * Prior to publishing the app list to the LiveData (and subsequently to the UI), both (1) the
-     * default platform mapping and (2) user customized order must be read into memory. These
-     * pre-fetch methods may be executed on different threads, so we should only publish the final
-     * ordering when both steps have completed.
-     */
-    @VisibleForTesting
-    void maybePublishAppList() {
-        if (!appsDataLoadingCompleted()) {
-            return;
-        }
-        // app names found in order proto file will be displayed first
-        mCustomizedOrder.clear();
-        List<LauncherItem> customOrder = new ArrayList<>();
-        Set<ComponentName> namesFoundInProto = new HashSet<>();
-        for (ComponentName name: mProtoComponentNames) {
-            if (mLauncherItemMap.containsKey(name)) {
-                customOrder.add(mLauncherItemMap.get(name));
-                namesFoundInProto.add(name);
-            }
-        }
-        mCustomizedOrder.addAll(customOrder);
-        if (shouldUseCustomOrder()) {
-            // new apps from platform not found in proto will be added to the end
-            mCustomizedOrder.clear();
-            List<ComponentName> newPlatformApps = mLauncherItemMap.keySet()
-                    .stream()
-                    .filter(element -> !namesFoundInProto.contains(element))
-                    .collect(Collectors.toList());
-            if (!newPlatformApps.isEmpty()) {
-                Collections.sort(newPlatformApps);
-                for (ComponentName newAppName: newPlatformApps) {
-                    customOrder.add(mLauncherItemMap.get(newAppName));
-                }
-            }
-            mCustomizedOrder.addAll(customOrder);
-            mCurrentAppList.postValue(customOrder);
-        } else {
-            mCurrentAppList.postValue(mDefaultOrder);
-            mCustomizedOrder.clear();
-        }
-        // reset apps data loading flags
-        mPlatformAppListLoaded = mCustomAppOrderFetched = false;
-    }
-
-    @VisibleForTesting
-    boolean appsDataLoadingCompleted() {
-        return mPlatformAppListLoaded && mCustomAppOrderFetched;
-    }
-
-    @VisibleForTesting
-    boolean shouldUseCustomOrder() {
-        return mIsUserCustomized && mCustomizedOrder.size() != 0;
-    }
-
-    /**
-     * Persistently writes the current in memory app order into disk.
-     */
-    public void handleAppListChange() {
-        if (mIsUserCustomized) {
-            List<LauncherItem> currentItems = mCurrentAppList.getValue();
-            List<LauncherItemMessage> msgList = new ArrayList<LauncherItemMessage>();
-            for (int i = 0; i < currentItems.size(); i++) {
-                msgList.add(currentItems.get(i).convertToMessage(i, -1));
-            }
-            LauncherItemListMessage appOrderListMessage = mItemHelper.convertToMessage(msgList);
-            mDataSource.writeToFileInBackgroundThread(appOrderListMessage);
-        }
-    }
-
-    /**
-     * Move an app to a specified index and post the value to LiveData.
-     */
-    public void setAppPosition(int position, AppMetaData app) {
-        List<LauncherItem> current = mCurrentAppList.getValue();
-        LauncherItem item = mLauncherItemMap.get(app.getComponentName());
-        if (current != null && current.size() != 0 && position < current.size() && item != null) {
-            mIsUserCustomized = true;
-            current.remove(item);
-            current.add(position, item);
-            mCurrentAppList.postValue(current);
-        }
-    }
-
-    /**
-     * Handles the incoming mirroring intent from ViewModel.
-     *
-     * Update an AppItem's AppMetaData isMirroring state and its launch callback then post the
-     * updated to LiveData.
-     */
-    public void updateMirroringItem(String packageName, Intent mirroringIntent) {
-        List<LauncherItem> launcherList = mCurrentAppList.getValue();
-        if (launcherList == null) {
-            return;
-        }
-        List<LauncherItem> launcherListCopy = new ArrayList<>();
-        for (LauncherItem item : launcherList) {
-            if (item instanceof AppItem) {
-                // TODO (b/272796126): move deep copying to inside DiffUtil
-                AppMetaData metaData = ((AppItem) item).getAppMetaData();
-                if (item.getPackageName().equals(packageName)) {
-                    launcherListCopy.add(new AppItem(item.getPackageName(), item.getClassName(),
-                            item.getDisplayName(), new AppMetaData(metaData.getDisplayName(),
-                            metaData.getComponentName(), metaData.getIcon(),
-                            metaData.getIsDistractionOptimized(), /* isMirroring= */ true,
-                            metaData.getIsDisabledByTos(),
-                                    contextArg ->
-                                            AppLauncherUtils.launchApp(contextArg, mirroringIntent),
-                            metaData.getAlternateLaunchCallback())));
-                } else if (metaData.getIsMirroring()) {
-                    Intent intent = new Intent(Intent.ACTION_MAIN)
-                            .setComponent(metaData.getComponentName())
-                            .addCategory(Intent.CATEGORY_LAUNCHER)
-                            .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-                    launcherListCopy.add(new AppItem(item.getPackageName(), item.getClassName(),
-                            item.getDisplayName(), new AppMetaData(metaData.getDisplayName(),
-                            metaData.getComponentName(), metaData.getIcon(),
-                            metaData.getIsDistractionOptimized(), /* isMirroring= */ false,
-                            metaData.getIsDisabledByTos(),
-                                    contextArg ->
-                                            AppLauncherUtils.launchApp(contextArg, intent),
-                            metaData.getAlternateLaunchCallback())));
-                } else {
-                    launcherListCopy.add(item);
-                }
-            } else {
-                launcherListCopy.add(item);
-            }
-        }
-        mCurrentAppList.postValue(launcherListCopy);
-    }
-}
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/UXRestrictionDataSource.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/UXRestrictionDataSource.kt
index 6f46cd5c..afb2ff7e 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/UXRestrictionDataSource.kt
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/UXRestrictionDataSource.kt
@@ -19,12 +19,13 @@ package com.android.car.carlauncher.datasources
 import android.car.content.pm.CarPackageManager
 import android.car.drivingstate.CarUxRestrictionsManager
 import android.content.ComponentName
+import android.content.Context
 import android.content.res.Resources
-import android.media.session.MediaController
 import android.media.session.MediaSessionManager
-import android.media.session.MediaSessionManager.OnActiveSessionsChangedListener
 import android.util.Log
+import androidx.lifecycle.asFlow
 import com.android.car.carlauncher.Flags
+import com.android.car.carlauncher.MediaSessionUtils
 import com.android.car.carlauncher.R
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.Dispatchers
@@ -60,11 +61,12 @@ interface UXRestrictionDataSource {
  * @property [bgDispatcher] Executes all the operations on this background coroutine dispatcher.
  */
 class UXRestrictionDataSourceImpl(
+    private val context: Context,
     private val uxRestrictionsManager: CarUxRestrictionsManager,
     private val carPackageManager: CarPackageManager,
     private val mediaSessionManager: MediaSessionManager,
     private val resources: Resources,
-    private val bgDispatcher: CoroutineDispatcher = Dispatchers.Default
+    private val bgDispatcher: CoroutineDispatcher = Dispatchers.Default,
 ) : UXRestrictionDataSource {
 
     /**
@@ -118,30 +120,12 @@ class UXRestrictionDataSourceImpl(
     }
 
     private fun getActiveMediaPlaybackSessions(): Flow<List<String>> {
-        return callbackFlow {
-            val filterActiveMediaPackages: (List<MediaController>) -> List<String> =
-                { mediaControllers ->
-                    mediaControllers.filter {
-                        it.playbackState?.isActive ?: false
-                    }.map { it.packageName }
-                }
-            // Emits the initial list of filtered packages upon subscription
-            trySend(
-                filterActiveMediaPackages(mediaSessionManager.getActiveSessions(null))
-            )
-            val sessionsChangedListener =
-                OnActiveSessionsChangedListener {
-                    if (it != null) {
-                        trySend(filterActiveMediaPackages(it))
-                    }
+        return MediaSessionUtils.getMediaSessionHelper(context).activeOrPausedMediaSources.asFlow()
+            .map { mediaSources ->
+                mediaSources.mapNotNull {
+                    it.packageName
                 }
-            mediaSessionManager.addOnActiveSessionsChangedListener(sessionsChangedListener, null)
-            awaitClose {
-                mediaSessionManager.removeOnActiveSessionsChangedListener(sessionsChangedListener)
             }
-            // Note this flow runs on the Main dispatcher, as the MediaSessionsChangedListener
-            // expects to dispatch updates on the Main looper.
-        }.flowOn(Dispatchers.Main).conflate()
     }
 
     companion object {
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppGridAdapter.java b/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppGridAdapter.java
index 54c46413..66405708 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppGridAdapter.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppGridAdapter.java
@@ -29,12 +29,11 @@ import android.widget.LinearLayout;
 import androidx.recyclerview.widget.DiffUtil;
 import androidx.recyclerview.widget.RecyclerView;
 
-import com.android.car.carlauncher.AppGridActivity.Mode;
+import com.android.car.carlauncher.AppGridFragment.Mode;
 import com.android.car.carlauncher.AppGridPageSnapper;
 import com.android.car.carlauncher.AppItem;
 import com.android.car.carlauncher.LauncherItem;
 import com.android.car.carlauncher.LauncherItemDiffCallback;
-import com.android.car.carlauncher.LauncherViewModel;
 import com.android.car.carlauncher.R;
 import com.android.car.carlauncher.RecentAppsRowViewHolder;
 import com.android.car.carlauncher.pagination.PageIndexingHelper;
@@ -71,41 +70,6 @@ public class AppGridAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder
 
     private AppGridAdapterListener mAppGridAdapterListener;
 
-    public AppGridAdapter(Context context, int numOfCols, int numOfRows,
-            LauncherViewModel launcherViewModel, AppItemViewHolder.AppItemDragCallback dragCallback,
-            AppGridPageSnapper.AppGridPageSnapCallback snapCallback) {
-        this(context, numOfCols, numOfRows,
-                context.getResources().getBoolean(R.bool.use_vertical_app_grid)
-                        ? PageOrientation.VERTICAL : PageOrientation.HORIZONTAL,
-                LayoutInflater.from(context), launcherViewModel, dragCallback, snapCallback);
-    }
-
-    public AppGridAdapter(Context context, int numOfCols, int numOfRows,
-            @PageOrientation int pageOrientation,
-            LayoutInflater layoutInflater, LauncherViewModel launcherViewModel,
-            AppItemViewHolder.AppItemDragCallback dragCallback,
-            AppGridPageSnapper.AppGridPageSnapCallback snapCallback) {
-        this(context, numOfCols, numOfRows, pageOrientation, layoutInflater,
-                launcherViewModel, dragCallback, snapCallback, Mode.ALL_APPS);
-    }
-
-    public AppGridAdapter(Context context, int numOfCols, int numOfRows,
-            @PageOrientation int pageOrientation,
-            LayoutInflater layoutInflater, LauncherViewModel launcherViewModel,
-            AppItemViewHolder.AppItemDragCallback dragCallback,
-            AppGridPageSnapper.AppGridPageSnapCallback snapCallback, Mode mode) {
-        mContext = context;
-        mInflater = layoutInflater;
-        mNumOfCols = numOfCols;
-        mNumOfRows = numOfRows;
-        mDragCallback = dragCallback;
-        mSnapCallback = snapCallback;
-
-        mIndexingHelper = new PageIndexingHelper(numOfCols, numOfRows, pageOrientation);
-        mGridOrderedLauncherItems = new ArrayList<>();
-        mAppGridMode = mode;
-    }
-
     public AppGridAdapter(Context context, int numOfCols, int numOfRows,
             AppItemViewHolder.AppItemDragCallback dragCallback,
             AppGridPageSnapper.AppGridPageSnapCallback snapCallback,
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppItemViewHolder.java b/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppItemViewHolder.java
index 1647ccab..92dc9417 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppItemViewHolder.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppItemViewHolder.java
@@ -47,7 +47,7 @@ import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.recyclerview.widget.RecyclerView;
 
-import com.android.car.carlauncher.AppGridActivity;
+import com.android.car.carlauncher.AppGridFragment;
 import com.android.car.carlauncher.AppGridPageSnapper.AppGridPageSnapCallback;
 import com.android.car.carlauncher.AppItemDragShadowBuilder;
 import com.android.car.carlauncher.AppMetaData;
@@ -98,18 +98,18 @@ public class AppItemViewHolder extends RecyclerView.ViewHolder {
     public static class BindInfo {
         private final boolean mIsDistractionOptimizationRequired;
         private final Rect mPageBound;
-        private final AppGridActivity.Mode mMode;
+        private final AppGridFragment.Mode mMode;
 
         public BindInfo(boolean isDistractionOptimizationRequired,
                 Rect pageBound,
-                AppGridActivity.Mode mode) {
+                AppGridFragment.Mode mode) {
             this.mIsDistractionOptimizationRequired = isDistractionOptimizationRequired;
             this.mPageBound = pageBound;
             this.mMode = mode;
         }
 
         public BindInfo(boolean isDistractionOptimizationRequired, Rect pageBound) {
-            this(isDistractionOptimizationRequired, pageBound, AppGridActivity.Mode.ALL_APPS);
+            this(isDistractionOptimizationRequired, pageBound, AppGridFragment.Mode.ALL_APPS);
         }
     }
 
@@ -160,7 +160,7 @@ public class AppItemViewHolder extends RecyclerView.ViewHolder {
         }
         boolean isDistractionOptimizationRequired = bindInfo.mIsDistractionOptimizationRequired;
         mPageBound = bindInfo.mPageBound;
-        AppGridActivity.Mode mode = bindInfo.mMode;
+        AppGridFragment.Mode mode = bindInfo.mMode;
 
         mHasAppMetadata = true;
         mAppItemView.setFocusable(true);
@@ -374,9 +374,9 @@ public class AppItemViewHolder extends RecyclerView.ViewHolder {
 
 
     private boolean shouldStartDragAndDrop(MotionEvent event, float actionDownX,
-            float actionDownY, AppGridActivity.Mode mode) {
+            float actionDownY, AppGridFragment.Mode mode) {
         // If App Grid is not in all apps mode, we should not allow drag and drop
-        if (mode != AppGridActivity.Mode.ALL_APPS) {
+        if (mode != AppGridFragment.Mode.ALL_APPS) {
             return false;
         }
         // the move event should be with in the bounds of the app icon
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/AppGridRepository.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/AppGridRepository.kt
index f9fddb99..f9376a69 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/AppGridRepository.kt
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/AppGridRepository.kt
@@ -16,11 +16,15 @@
 
 package com.android.car.carlauncher.repositories
 
+import android.Manifest.permission.MANAGE_OWN_CALLS
 import android.content.ComponentName
 import android.content.Intent
 import android.content.pm.PackageManager
+import android.content.pm.PackageManager.NameNotFoundException
 import android.content.pm.ResolveInfo
 import android.graphics.drawable.Drawable
+import android.os.UserManager
+import android.util.Log
 import com.android.car.carlauncher.AppItem
 import com.android.car.carlauncher.AppMetaData
 import com.android.car.carlauncher.datasources.AppOrderDataSource
@@ -111,9 +115,13 @@ class AppGridRepositoryImpl(
     private val packageManager: PackageManager,
     private val appLaunchFactory: AppLaunchProviderFactory,
     private val appShortcutsFactory: AppShortcutsFactory,
+    userManager: UserManager,
     private val bgDispatcher: CoroutineDispatcher
 ) : AppGridRepository {
 
+    private val isVisibleBackgroundUser = !userManager.isUserForeground &&
+        userManager.isUserVisible && !userManager.isProfile
+
     /**
      * Provides a flow of all apps in the app grid.
      * It combines data from multiple sources, filters apps based on restrictions, handles dynamic
@@ -134,6 +142,8 @@ class AppGridRepositoryImpl(
                 it.componentName.packageName in alreadyAddedComponents
             }).sortedWith { a1, a2 ->
                 order.compare(a1.appOrderInfo, a2.appOrderInfo)
+            }.filter {
+                !shouldHideApp(it)
             }.map {
                 if (mirroringSession.packageName == it.componentName.packageName) {
                     it.redirectIntent = mirroringSession.launchIntent
@@ -275,4 +285,25 @@ class AppGridRepositoryImpl(
     private fun List<AppItem>.toAppOrderInfoList(): List<AppOrderInfo> {
         return map { AppOrderInfo(it.packageName, it.className, it.displayName.toString()) }
     }
+
+    private fun shouldHideApp(appInfo: AppInfo): Boolean {
+        // Disable telephony apps for MUMD passenger since accepting a call will
+        // drop the driver's call.
+        if (isVisibleBackgroundUser) {
+            return try {
+                packageManager.getPackageInfo(
+                    appInfo.componentName.packageName, PackageManager.GET_PERMISSIONS)
+                    .requestedPermissions?.any {it == MANAGE_OWN_CALLS} ?: false
+            } catch (e: NameNotFoundException) {
+                Log.e(TAG, "Unable to query app permissions for $appInfo $e")
+                false
+            }
+        }
+
+        return false
+    }
+
+    companion object {
+        const val TAG = "AppGridRepository"
+    }
 }
diff --git a/libs/appgrid/lib/tests/Android.bp b/libs/appgrid/lib/tests/Android.bp
index bcc3f75f..4314dfdc 100644
--- a/libs/appgrid/lib/tests/Android.bp
+++ b/libs/appgrid/lib/tests/Android.bp
@@ -15,6 +15,7 @@
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_system_experience",
 }
 
 android_test {
@@ -26,7 +27,7 @@ android_test {
 
     libs: [
         "android.car",
-        "android.test.base",
+        "android.test.base.stubs.system",
         "android.car-system-stubs",
     ],
 
diff --git a/libs/appgrid/lib/tests/res/values-en-rCA/strings.xml b/libs/appgrid/lib/tests/res/values-en-rCA/strings.xml
new file mode 100644
index 00000000..f7fcedc9
--- /dev/null
+++ b/libs/appgrid/lib/tests/res/values-en-rCA/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+  ~ Copyright (C) 2023 The Android Open Source Project
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
+   -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_test_title" msgid="4167394338298199728">"AppGridTests"</string>
+</resources>
diff --git a/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppGridAdapterTest.java b/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppGridAdapterTest.java
index ab357b0d..b22e9e8d 100644
--- a/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppGridAdapterTest.java
+++ b/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppGridAdapterTest.java
@@ -25,9 +25,10 @@ import static org.mockito.Mockito.when;
 
 import android.content.Context;
 import android.graphics.Rect;
-import android.view.LayoutInflater;
 import android.view.View;
 
+import androidx.test.platform.app.InstrumentationRegistry;
+
 import com.android.car.carlauncher.pagination.PageIndexingHelper;
 import com.android.car.carlauncher.recyclerview.AppGridAdapter;
 import com.android.car.carlauncher.recyclerview.AppItemViewHolder;
@@ -37,18 +38,18 @@ import org.junit.Test;
 import org.mockito.Mock;
 
 public class AppGridAdapterTest {
-
-    @Mock public Context mMockContext;
-    @Mock public LayoutInflater mMockLayoutInflater;
-    @Mock public LauncherViewModel mMockLauncherModel;
-    @Mock public AppItemViewHolder.AppItemDragCallback mMockDragCallback;
-    @Mock public AppGridPageSnapper.AppGridPageSnapCallback mMockSnapCallback;
-    @Mock public Rect mMockPageBound;
+    private final Context mContext =
+            InstrumentationRegistry.getInstrumentation().getTargetContext();
+    @Mock
+    public AppItemViewHolder.AppItemDragCallback mMockDragCallback;
+    @Mock
+    public AppGridPageSnapper.AppGridPageSnapCallback mMockSnapCallback;
+    @Mock
+    public Rect mMockPageBound;
     public AppGridAdapter mTestAppGridAdapter;
 
     @Before
     public void setUp() throws Exception {
-        mMockLauncherModel = mock(LauncherViewModel.class);
         mMockDragCallback = mock(AppItemViewHolder.AppItemDragCallback.class);
         mMockSnapCallback = mock(AppGridPageSnapper.AppGridPageSnapCallback.class);
     }
@@ -57,9 +58,9 @@ public class AppGridAdapterTest {
     public void testPageRounding_getItemCount_getPageCount() {
         int numOfCols = 5;
         int numOfRows = 3;
-        mTestAppGridAdapter = new AppGridAdapter(mMockContext, numOfCols, numOfRows,
-                PageOrientation.HORIZONTAL,
-                mMockLayoutInflater, mMockLauncherModel, mMockDragCallback, mMockSnapCallback);
+        mTestAppGridAdapter = new AppGridAdapter(mContext, numOfCols, numOfRows,
+                mMockDragCallback, mMockSnapCallback,
+                mock(AppGridAdapter.AppGridAdapterListener.class), AppGridFragment.Mode.ALL_APPS);
         mTestAppGridAdapter.updateViewHolderDimensions(mMockPageBound,
                 /* appItemWidth */ 260, /* appItemHeight */ 200);
         mTestAppGridAdapter = spy(mTestAppGridAdapter);
@@ -85,9 +86,9 @@ public class AppGridAdapterTest {
         numOfCols = 4;
         numOfRows = 6;
 
-        mTestAppGridAdapter = new AppGridAdapter(mMockContext, numOfCols, numOfRows,
-                PageOrientation.HORIZONTAL,
-                mMockLayoutInflater, mMockLauncherModel, mMockDragCallback, mMockSnapCallback);
+        mTestAppGridAdapter = new AppGridAdapter(mContext, numOfCols, numOfRows,
+                mMockDragCallback, mMockSnapCallback,
+                mock(AppGridAdapter.AppGridAdapterListener.class), AppGridFragment.Mode.ALL_APPS);
         mTestAppGridAdapter.updateViewHolderDimensions(mMockPageBound,
                 /* appItemWidth */ 260, /* appItemHeight */ 200);
         mTestAppGridAdapter = spy(mTestAppGridAdapter);
@@ -114,9 +115,9 @@ public class AppGridAdapterTest {
         // an adapter with 45 items
         int numOfCols = 5;
         int numOfRows = 3;
-        mTestAppGridAdapter = new AppGridAdapter(mMockContext, numOfCols, numOfRows,
-                PageOrientation.HORIZONTAL,
-                mMockLayoutInflater, mMockLauncherModel, mMockDragCallback, mMockSnapCallback);
+        mTestAppGridAdapter = new AppGridAdapter(mContext, numOfCols, numOfRows,
+                mMockDragCallback, mMockSnapCallback,
+                mock(AppGridAdapter.AppGridAdapterListener.class), AppGridFragment.Mode.ALL_APPS);
         mTestAppGridAdapter.updateViewHolderDimensions(mMockPageBound,
                 /* appItemWidth */ 260, /* appItemHeight */ 200);
         mTestAppGridAdapter = spy(mTestAppGridAdapter);
@@ -149,9 +150,9 @@ public class AppGridAdapterTest {
         // an adapter with 45 items
         int numOfRows = 5;
         int numOfCols = 3;
-        mTestAppGridAdapter = new AppGridAdapter(mMockContext, numOfCols, numOfRows,
-                /* pageOrientation */ PageOrientation.HORIZONTAL,
-                mMockLayoutInflater, mMockLauncherModel, mMockDragCallback, mMockSnapCallback);
+        mTestAppGridAdapter = new AppGridAdapter(mContext, numOfCols, numOfRows,
+                mMockDragCallback, mMockSnapCallback,
+                mock(AppGridAdapter.AppGridAdapterListener.class), AppGridFragment.Mode.ALL_APPS);
         mTestAppGridAdapter.updateViewHolderDimensions(mMockPageBound,
                 /* appItemWidth */ 260, /* appItemHeight */ 200);
         mTestAppGridAdapter = spy(mTestAppGridAdapter);
@@ -192,9 +193,9 @@ public class AppGridAdapterTest {
         // an adapter with 40 items, 3 page, and 5 padded empty items
         int numOfCols = 5;
         int numOfRows = 3;
-        mTestAppGridAdapter = new AppGridAdapter(mMockContext, numOfCols, numOfRows,
-                PageOrientation.HORIZONTAL,
-                mMockLayoutInflater, mMockLauncherModel, mMockDragCallback, mMockSnapCallback);
+        mTestAppGridAdapter = new AppGridAdapter(mContext, numOfCols, numOfRows,
+                mMockDragCallback, mMockSnapCallback,
+                mock(AppGridAdapter.AppGridAdapterListener.class), AppGridFragment.Mode.ALL_APPS);
         mTestAppGridAdapter.updateViewHolderDimensions(mMockPageBound,
                 /* appItemWidth */ 260, /* appItemHeight */ 200);
         mTestAppGridAdapter = spy(mTestAppGridAdapter);
@@ -245,9 +246,9 @@ public class AppGridAdapterTest {
         // an adapter with 44 items, 3 page, and 16 padded empty items
         int numOfCols = 4;
         int numOfRows = 5;
-        mTestAppGridAdapter = new AppGridAdapter(mMockContext, numOfCols, numOfRows,
-                PageOrientation.HORIZONTAL,
-                mMockLayoutInflater, mMockLauncherModel, mMockDragCallback, mMockSnapCallback);
+        mTestAppGridAdapter = new AppGridAdapter(mContext, numOfCols, numOfRows,
+                mMockDragCallback, mMockSnapCallback,
+                mock(AppGridAdapter.AppGridAdapterListener.class), AppGridFragment.Mode.ALL_APPS);
         mTestAppGridAdapter.updateViewHolderDimensions(mMockPageBound,
                 /* appItemWidth */ 260, /* appItemHeight */ 200);
         mTestAppGridAdapter = spy(mTestAppGridAdapter);
diff --git a/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppLauncherUtilsTest.java b/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppLauncherUtilsTest.java
deleted file mode 100644
index 2663d274..00000000
--- a/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppLauncherUtilsTest.java
+++ /dev/null
@@ -1,580 +0,0 @@
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
-package com.android.car.carlauncher;
-
-import static android.car.settings.CarSettings.Secure.KEY_PACKAGES_DISABLED_ON_RESOURCE_OVERUSE;
-import static android.car.settings.CarSettings.Secure.KEY_UNACCEPTED_TOS_DISABLED_APPS;
-import static android.content.pm.ApplicationInfo.CATEGORY_AUDIO;
-import static android.content.pm.ApplicationInfo.CATEGORY_VIDEO;
-import static android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
-import static android.content.pm.PackageManager.MATCH_DISABLED_COMPONENTS;
-import static android.content.pm.PackageManager.MATCH_DISABLED_UNTIL_USED_COMPONENTS;
-
-import static com.android.car.carlauncher.AppLauncherUtils.APP_TYPE_LAUNCHABLES;
-import static com.android.car.carlauncher.AppLauncherUtils.APP_TYPE_MEDIA_SERVICES;
-import static com.android.car.carlauncher.AppLauncherUtils.PACKAGES_DISABLED_ON_RESOURCE_OVERUSE_SEPARATOR;
-import static com.android.car.carlauncher.AppLauncherUtils.TOS_DISABLED_APPS_SEPARATOR;
-import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
-
-import static org.junit.Assert.assertEquals;
-import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.ArgumentMatchers.anyInt;
-import static org.mockito.ArgumentMatchers.argThat;
-import static org.mockito.ArgumentMatchers.eq;
-import static org.mockito.Mockito.mock;
-import static org.mockito.Mockito.never;
-import static org.mockito.Mockito.times;
-import static org.mockito.Mockito.verify;
-import static org.mockito.Mockito.when;
-
-import android.app.ActivityManager;
-import android.car.Car;
-import android.car.content.pm.CarPackageManager;
-import android.car.media.CarMediaManager;
-import android.car.test.mocks.AbstractExtendedMockitoTestCase;
-import android.content.ComponentName;
-import android.content.ContentResolver;
-import android.content.Context;
-import android.content.Intent;
-import android.content.pm.ActivityInfo;
-import android.content.pm.ApplicationInfo;
-import android.content.pm.LauncherActivityInfo;
-import android.content.pm.LauncherApps;
-import android.content.pm.PackageManager;
-import android.content.pm.ResolveInfo;
-import android.content.pm.ServiceInfo;
-import android.content.res.Resources;
-import android.os.Bundle;
-import android.os.UserHandle;
-import android.provider.Settings;
-import android.service.media.MediaBrowserService;
-import android.util.ArraySet;
-
-import androidx.test.ext.junit.runners.AndroidJUnit4;
-import androidx.test.filters.SmallTest;
-
-import org.junit.After;
-import org.junit.Before;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.mockito.ArgumentCaptor;
-import org.mockito.Mock;
-import org.mockito.Mockito;
-
-import java.util.ArrayList;
-import java.util.Arrays;
-import java.util.Collections;
-import java.util.List;
-import java.util.Set;
-import java.util.function.Consumer;
-import java.util.stream.Collectors;
-
-@RunWith(AndroidJUnit4.class)
-@SmallTest
-public final class AppLauncherUtilsTest extends AbstractExtendedMockitoTestCase {
-    private static final String TEST_DISABLED_APP_1 = "com.android.car.test.disabled1";
-    private static final String TEST_DISABLED_APP_2 = "com.android.car.test.disabled2";
-    private static final String TEST_ENABLED_APP = "com.android.car.test.enabled";
-    private static final String TEST_TOS_DISABLED_APP_1 = "com.android.car.test.tosdisabled1";
-    private static final String TEST_TOS_DISABLED_APP_2 = "com.android.car.test.tosdisabled2";
-    private static final String TEST_VIDEO_APP = "com.android.car.test.video";
-    // Default media app
-    private static final String TEST_MEDIA_TEMPLATE_MBS = "com.android.car.test.mbs";
-    // Video app that has a MBS defined but has its own launch activity
-    private static final String TEST_VIDEO_MBS = "com.android.car.test.video.mbs";
-    // NDO App that has opted in its MBS to launch in car
-    private static final String TEST_NDO_MBS_LAUNCHABLE = "com.android.car.test.mbs.launchable";
-    // NDO App that has opted out its MBS to launch in car
-    private static final String TEST_NDO_MBS_NOT_LAUNCHABLE =
-            "com.android.car.test.mbs.notlaunchable";
-
-    private static final String CUSTOM_MEDIA_PACKAGE = "com.android.car.radio";
-    private static final String CUSTOM_MEDIA_CLASS = "com.android.car.radio.service";
-    private static final String CUSTOM_MEDIA_COMPONENT = CUSTOM_MEDIA_PACKAGE
-            + "/" + CUSTOM_MEDIA_CLASS;
-    private static final String TEST_MIRROR_APP_PKG = "com.android.car.test.mirroring";
-    private static final String TOS_INTENT_NAME = "intent:#Intent;action="
-            + "com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=true;"
-            + "S.mini_flow_extra=GTOS_GATED_FLOW;end";
-    private static final String TOS_INTENT_VERIFY = "#Intent;action="
-            + "com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=true;"
-            + "S.mini_flow_extra=GTOS_GATED_FLOW;end";
-
-
-    @Mock private Context mMockContext;
-    @Mock private LauncherApps mMockLauncherApps;
-    @Mock private PackageManager mMockPackageManager;
-    @Mock private AppLauncherUtils.ShortcutsListener mMockShortcutsListener;
-
-    @Mock private Resources mResources;
-
-    @Mock private LauncherActivityInfo mRadioLauncherActivityInfo;
-
-    private CarMediaManager mCarMediaManager;
-    private CarPackageManager mCarPackageManager;
-    private Car mCar;
-
-    @Before
-    public void setUp() throws Exception {
-        // Need for CarMediaManager to get the user from the context.
-        when(mMockContext.getUser()).thenReturn(UserHandle.of(ActivityManager.getCurrentUser()));
-
-        mCar = Car.createCar(mMockContext, /* handler = */ null, Car.CAR_WAIT_TIMEOUT_WAIT_FOREVER,
-                (car, ready) -> {
-                    if (!ready) {
-                        mCarPackageManager = null;
-                        mCarMediaManager = null;
-                        return;
-                    }
-                    mCarPackageManager = (CarPackageManager) car.getCarManager(Car.PACKAGE_SERVICE);
-                    mCarPackageManager = Mockito.spy(mCarPackageManager);
-                    mCarMediaManager = (CarMediaManager) car.getCarManager(Car.CAR_MEDIA_SERVICE);
-                    when(mMockContext.getPackageManager()).thenReturn(mMockPackageManager);
-                });
-    }
-
-    @After
-    public void tearDown() throws Exception {
-        if (mCar != null && mCar.isConnected()) {
-            mCar.disconnect();
-            mCar = null;
-        }
-    }
-
-    @Override
-    protected void onSessionBuilder(CustomMockitoSessionBuilder session) {
-        session.spyStatic(Settings.Secure.class);
-    }
-
-    @Test
-    public void testGetLauncherApps_MediaCenterAppSwitcher() {
-        mockSettingsStringCalls();
-        mockPackageManagerQueries();
-
-        when(mMockContext.getResources()).thenReturn(mResources);
-        when(mResources.getStringArray(eq(
-                com.android.car.media.common.R.array.custom_media_packages)))
-                .thenReturn(new String[]{CUSTOM_MEDIA_COMPONENT});
-
-        // Setup custom media component
-        when(mMockLauncherApps.getActivityList(any(), any()))
-                .thenReturn(List.of(mRadioLauncherActivityInfo));
-        when(mRadioLauncherActivityInfo.getComponentName())
-                .thenReturn(new ComponentName(CUSTOM_MEDIA_PACKAGE, CUSTOM_MEDIA_CLASS));
-        when(mRadioLauncherActivityInfo.getName())
-                .thenReturn(CUSTOM_MEDIA_CLASS);
-
-        AppLauncherUtils.LauncherAppsInfo launcherAppsInfo = AppLauncherUtils.getLauncherApps(
-                mMockContext, /* appsToHide= */ new ArraySet<>(),
-                /* appTypes= */ APP_TYPE_MEDIA_SERVICES,
-                /* openMediaCenter= */ false, mMockLauncherApps, mCarPackageManager,
-                mMockPackageManager, mCarMediaManager, mMockShortcutsListener,
-                TEST_MIRROR_APP_PKG,  /* mirroringAppRedirect= */ null);
-
-        List<AppMetaData> appMetaData = launcherAppsInfo.getLaunchableComponentsList();
-
-        // Only media apps should be present
-        assertEquals(Set.of(
-                        TEST_MEDIA_TEMPLATE_MBS,
-                        TEST_NDO_MBS_LAUNCHABLE,
-                        CUSTOM_MEDIA_PACKAGE),
-                appMetaData.stream()
-                        .map(am -> am.getComponentName().getPackageName())
-                        .collect(Collectors.toSet()));
-
-        // This should include all MBS discovered
-        assertEquals(5, launcherAppsInfo.getMediaServices().size());
-
-        mockPmGetApplicationEnabledSetting(COMPONENT_ENABLED_STATE_ENABLED, TEST_DISABLED_APP_1,
-                TEST_DISABLED_APP_2);
-
-        launchAllApps(appMetaData);
-
-        // Media apps should do only switching and not launch activity
-        verify(mMockContext, never()).startActivity(any(), any());
-    }
-
-    @Test
-    public void testGetLauncherApps_Launcher() {
-        mockSettingsStringCalls();
-        mockPackageManagerQueries();
-
-        when(mMockContext.getResources()).thenReturn(mResources);
-        when(mResources.getStringArray(eq(
-                com.android.car.media.common.R.array.custom_media_packages)))
-                .thenReturn(new String[]{CUSTOM_MEDIA_COMPONENT});
-
-        // Setup custom media component
-        when(mMockLauncherApps.getActivityList(any(), any()))
-                .thenReturn(List.of(mRadioLauncherActivityInfo));
-        when(mRadioLauncherActivityInfo.getComponentName())
-                .thenReturn(new ComponentName(CUSTOM_MEDIA_PACKAGE, CUSTOM_MEDIA_CLASS));
-        when(mRadioLauncherActivityInfo.getName())
-                .thenReturn(CUSTOM_MEDIA_CLASS);
-
-        AppLauncherUtils.LauncherAppsInfo launcherAppsInfo = AppLauncherUtils.getLauncherApps(
-                mMockContext, /* appsToHide= */ new ArraySet<>(),
-                /* appTypes= */ APP_TYPE_LAUNCHABLES + APP_TYPE_MEDIA_SERVICES,
-                /* openMediaCenter= */ true, mMockLauncherApps, mCarPackageManager,
-                mMockPackageManager, mCarMediaManager, mMockShortcutsListener,
-                TEST_MIRROR_APP_PKG,  /* mirroringAppRedirect= */ null);
-
-        List<AppMetaData> appMetaData = launcherAppsInfo.getLaunchableComponentsList();
-        // mMockLauncherApps is never stubbed, only services & disabled activities are expected.
-
-        assertEquals(Set.of(
-                        TEST_MEDIA_TEMPLATE_MBS,
-                        TEST_NDO_MBS_LAUNCHABLE,
-                        CUSTOM_MEDIA_PACKAGE,
-                        TEST_DISABLED_APP_1,
-                        TEST_DISABLED_APP_2),
-                appMetaData.stream()
-                        .map(am -> am.getComponentName().getPackageName())
-                        .collect(Collectors.toSet()));
-
-
-        // This should include all MBS discovered
-        assertEquals(5, launcherAppsInfo.getMediaServices().size());
-
-        mockPmGetApplicationEnabledSetting(COMPONENT_ENABLED_STATE_ENABLED, TEST_DISABLED_APP_1,
-                TEST_DISABLED_APP_2);
-
-        launchAllApps(appMetaData);
-
-        verify(mMockPackageManager).setApplicationEnabledSetting(
-                eq(TEST_DISABLED_APP_1), eq(COMPONENT_ENABLED_STATE_ENABLED), eq(0));
-
-        verify(mMockPackageManager).setApplicationEnabledSetting(
-                eq(TEST_DISABLED_APP_2), eq(COMPONENT_ENABLED_STATE_ENABLED), eq(0));
-
-        verify(mMockContext, times(5)).startActivity(any(), any());
-
-        verify(mMockPackageManager, never()).setApplicationEnabledSetting(
-                eq(TEST_ENABLED_APP), anyInt(), eq(0));
-    }
-
-
-    @Test
-    public void testGetLauncherAppsWithEnableAndTosDisabledApps() {
-        mockSettingsStringCalls();
-        mockTosPackageManagerQueries();
-
-        when(mMockContext.getResources()).thenReturn(mResources);
-        when(mResources.getStringArray(eq(
-                com.android.car.media.common.R.array.custom_media_packages)))
-                .thenReturn(new String[]{CUSTOM_MEDIA_COMPONENT});
-
-        AppLauncherUtils.LauncherAppsInfo launcherAppsInfo = AppLauncherUtils.getLauncherApps(
-                mMockContext, /* appsToHide= */ new ArraySet<>(),
-                /* appTypes= */ APP_TYPE_LAUNCHABLES + APP_TYPE_MEDIA_SERVICES,
-                /* openMediaCenter= */ false, mMockLauncherApps, mCarPackageManager,
-                mMockPackageManager, mCarMediaManager, mMockShortcutsListener,
-                TEST_MIRROR_APP_PKG,  /* mirroringAppRedirect= */ null);
-
-        List<AppMetaData> appMetaData = launcherAppsInfo.getLaunchableComponentsList();
-
-        // mMockLauncherApps is never stubbed, only services & disabled activities are expected.
-        assertEquals(3, appMetaData.size());
-
-        Resources resources = mock(Resources.class);
-        when(mMockContext.getResources()).thenReturn(resources);
-        when(resources.getString(anyInt())).thenReturn(TOS_INTENT_NAME);
-
-        launchAllApps(appMetaData);
-
-        ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
-        verify(mMockContext, times(2)).startActivity(intentCaptor.capture(), any());
-
-        String intentUri = intentCaptor.getAllValues().get(0).toUri(0);
-        assertEquals(TOS_INTENT_VERIFY, intentUri);
-    }
-
-    @Test
-    public void testGetLauncherAppsWithEnableAndTosDisabledDistractionOptimizedApps() {
-        mockSettingsStringCalls();
-        mockTosPackageManagerQueries();
-
-        when(mMockContext.getResources()).thenReturn(mResources);
-        when(mResources.getStringArray(eq(
-                com.android.car.media.common.R.array.custom_media_packages)))
-                .thenReturn(new String[]{CUSTOM_MEDIA_COMPONENT});
-
-        doReturn(true)
-                .when(mCarPackageManager)
-                .isActivityDistractionOptimized(eq(TEST_TOS_DISABLED_APP_1), any());
-        doReturn(true)
-                .when(mCarPackageManager)
-                .isActivityDistractionOptimized(eq(TEST_TOS_DISABLED_APP_2), any());
-
-        AppLauncherUtils.LauncherAppsInfo launcherAppsInfo = AppLauncherUtils.getLauncherApps(
-                mMockContext, /* appsToHide= */ new ArraySet<>(),
-                /* appTypes= */ APP_TYPE_LAUNCHABLES + APP_TYPE_MEDIA_SERVICES,
-                /* openMediaCenter= */ false, mMockLauncherApps, mCarPackageManager,
-                mMockPackageManager, mCarMediaManager, mMockShortcutsListener,
-                TEST_MIRROR_APP_PKG,  /* mirroringAppRedirect= */ null);
-
-        List<AppMetaData> appMetaData = launcherAppsInfo.getLaunchableComponentsList();
-
-        // mMockLauncherApps is never stubbed, only services & disabled activities are expected.
-        assertEquals(3, appMetaData.size());
-
-        Resources resources = mock(Resources.class);
-        when(mMockContext.getResources()).thenReturn(resources);
-        when(resources.getString(anyInt())).thenReturn(TOS_INTENT_NAME);
-
-        launchAllApps(appMetaData);
-
-        ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
-        verify(mMockContext, times(2)).startActivity(intentCaptor.capture(), any());
-
-        String intentUri = intentCaptor.getAllValues().get(0).toUri(0);
-        assertEquals(TOS_INTENT_VERIFY, intentUri);
-    }
-
-    private void mockPackageManagerQueries() {
-        // setup a media template app that uses media service
-        ApplicationInfo mbsAppInfo = new ApplicationInfo();
-        mbsAppInfo.category = CATEGORY_AUDIO;
-        ResolveInfo mbs = constructServiceResolveInfo(TEST_MEDIA_TEMPLATE_MBS);
-
-        try {
-            Intent mbsIntent = new Intent();
-            mbsIntent.setComponent(mbs.getComponentInfo().getComponentName());
-            mbsIntent.setAction(MediaBrowserService.SERVICE_INTERFACE);
-
-            when(mMockPackageManager.getApplicationInfo(mbs.getComponentInfo().packageName, 0))
-                    .thenReturn(mbsAppInfo);
-
-            doReturn(Arrays.asList(mbs)).when(mMockPackageManager).queryIntentServices(
-                    argThat((Intent i) -> i != null
-                            && mbs.getComponentInfo().getComponentName().equals(i.getComponent())),
-                    eq(PackageManager.GET_META_DATA));
-
-            when(mMockPackageManager.getLaunchIntentForPackage(mbs.getComponentInfo().packageName))
-                    .thenReturn(null);
-        } catch (PackageManager.NameNotFoundException e) {
-            throw new RuntimeException(e);
-        }
-
-        // setup a NDO Video app that has MBS but also its own activity, MBS won't be surfaced
-        ApplicationInfo videoAppInfo = new ApplicationInfo();
-        videoAppInfo.category = CATEGORY_VIDEO;
-        ResolveInfo videoApp = constructServiceResolveInfo(TEST_VIDEO_MBS);
-        try {
-            Intent videoMbsIntent = new Intent();
-            videoMbsIntent.setComponent(videoApp.getComponentInfo().getComponentName());
-            videoMbsIntent.setAction(MediaBrowserService.SERVICE_INTERFACE);
-
-            when(mMockPackageManager.getApplicationInfo(videoApp.getComponentInfo().packageName,
-                    0))
-                    .thenReturn(videoAppInfo);
-
-            doReturn(Arrays.asList(videoApp)).when(mMockPackageManager).queryIntentServices(
-                    argThat((Intent i) -> i != null
-                            && videoApp.getComponentInfo().getComponentName()
-                                    .equals(i.getComponent())),
-                    eq(PackageManager.GET_META_DATA));
-
-            when(mMockPackageManager.getLaunchIntentForPackage(
-                    videoApp.getComponentInfo().packageName))
-                    .thenReturn(new Intent());
-        } catch (PackageManager.NameNotFoundException e) {
-            throw new RuntimeException(e);
-        }
-
-        // setup a NDO app that has MBS opted out of launch in car
-        ApplicationInfo notlaunchableMBSInfo = new ApplicationInfo();
-        notlaunchableMBSInfo.category = CATEGORY_VIDEO;
-        ResolveInfo notlaunchableMBSApp = constructServiceResolveInfo(TEST_NDO_MBS_NOT_LAUNCHABLE);
-
-        try {
-            Intent notlaunachableMbsIntent = new Intent();
-            notlaunachableMbsIntent.setComponent(
-                    notlaunchableMBSApp.getComponentInfo().getComponentName());
-            notlaunachableMbsIntent.setAction(MediaBrowserService.SERVICE_INTERFACE);
-
-            when(mMockPackageManager.getApplicationInfo(
-                    notlaunchableMBSApp.getComponentInfo().packageName, 0))
-                    .thenReturn(notlaunchableMBSInfo);
-
-
-            notlaunchableMBSApp.serviceInfo.metaData = new Bundle();
-            notlaunchableMBSApp.serviceInfo.metaData
-                    .putBoolean("androidx.car.app.launchable", false);
-
-            doReturn(Arrays.asList(notlaunchableMBSApp))
-                    .when(mMockPackageManager).queryIntentServices(
-                    argThat((Intent i) -> i != null
-                            && notlaunchableMBSApp.getComponentInfo().getComponentName()
-                                    .equals(i.getComponent())),
-                    eq(PackageManager.GET_META_DATA));
-
-            when(mMockPackageManager.getLaunchIntentForPackage(
-                    notlaunchableMBSApp.getComponentInfo().packageName))
-                    .thenReturn(new Intent());
-        } catch (PackageManager.NameNotFoundException e) {
-            throw new RuntimeException(e);
-        }
-
-
-        // setup a NDO app that has MBS opted in to launch in car
-        ApplicationInfo launchableMBSInfo = new ApplicationInfo();
-        launchableMBSInfo.category = CATEGORY_VIDEO;
-        ResolveInfo launchableMBSApp = constructServiceResolveInfo(TEST_NDO_MBS_LAUNCHABLE);
-        try {
-            Intent mbsIntent = new Intent();
-            mbsIntent.setComponent(launchableMBSApp.getComponentInfo().getComponentName());
-            mbsIntent.setAction(MediaBrowserService.SERVICE_INTERFACE);
-
-            when(mMockPackageManager.getApplicationInfo(
-                    launchableMBSApp.getComponentInfo().packageName,
-                    0))
-                    .thenReturn(launchableMBSInfo);
-
-
-            launchableMBSApp.serviceInfo.metaData = new Bundle();
-            launchableMBSApp.serviceInfo.metaData.putBoolean("androidx.car.app.launchable", true);
-
-            doReturn(Arrays.asList(launchableMBSApp)).when(mMockPackageManager).queryIntentServices(
-                    argThat((Intent i) -> i != null
-                            && launchableMBSApp.getComponentInfo().getComponentName()
-                            .equals(i.getComponent())),
-                    eq(PackageManager.GET_META_DATA));
-
-            when(mMockPackageManager.getLaunchIntentForPackage(
-                    launchableMBSApp.getComponentInfo().packageName))
-                    .thenReturn(new Intent());
-        } catch (PackageManager.NameNotFoundException e) {
-            throw new RuntimeException(e);
-        }
-
-        when(mMockPackageManager.queryIntentServices(any(), eq(PackageManager.GET_RESOLVED_FILTER)))
-                .thenAnswer(args -> {
-            Intent intent = args.getArgument(0);
-            if (intent.getAction().equals(MediaBrowserService.SERVICE_INTERFACE)) {
-                return Arrays.asList(mbs, videoApp, notlaunchableMBSApp, launchableMBSApp,
-                        constructServiceResolveInfo(CUSTOM_MEDIA_PACKAGE));
-            }
-            return new ArrayList<>();
-        });
-
-        // setup activities
-        when(mMockPackageManager.queryIntentActivities(any(), any())).thenAnswer(args -> {
-            Intent intent = args.getArgument(0);
-            PackageManager.ResolveInfoFlags flags = args.getArgument(1);
-            List<ResolveInfo> resolveInfoList = new ArrayList<>();
-            if (intent.getAction().equals(Intent.ACTION_MAIN)) {
-                if ((flags.getValue() & MATCH_DISABLED_UNTIL_USED_COMPONENTS) != 0) {
-                    resolveInfoList.add(constructActivityResolveInfo(TEST_DISABLED_APP_1));
-                    resolveInfoList.add(constructActivityResolveInfo(TEST_DISABLED_APP_2));
-                }
-                // Keep custom media component in both MBS and Activity with Launch Intent
-                resolveInfoList.add(constructActivityResolveInfo(CUSTOM_MEDIA_PACKAGE));
-                // Add apps which will have their own Launcher Activity
-                resolveInfoList.add(constructActivityResolveInfo(TEST_VIDEO_MBS));
-                resolveInfoList.add(constructActivityResolveInfo(TEST_NDO_MBS_LAUNCHABLE));
-                resolveInfoList.add(constructActivityResolveInfo(TEST_NDO_MBS_NOT_LAUNCHABLE));
-            }
-
-            return resolveInfoList;
-        });
-    }
-
-    private void mockTosPackageManagerQueries() {
-        ResolveInfo resolveInfo = constructServiceResolveInfo(TEST_ENABLED_APP);
-        try {
-            when(mMockPackageManager.getServiceInfo(
-                    resolveInfo
-                            .getComponentInfo().getComponentName(),
-                    PackageManager.GET_META_DATA))
-                    .thenReturn(new ServiceInfo());
-        } catch (PackageManager.NameNotFoundException e) {
-            throw new RuntimeException(e);
-        }
-        when(mMockPackageManager.queryIntentServices(any(), anyInt())).thenAnswer(args -> {
-            Intent intent = args.getArgument(0);
-            if (intent.getAction().equals(MediaBrowserService.SERVICE_INTERFACE)) {
-                return Collections.singletonList(resolveInfo);
-            }
-            return new ArrayList<>();
-        });
-        when(mMockPackageManager.queryIntentActivities(any(), any())).thenAnswer(args -> {
-            Intent intent = args.getArgument(0);
-            PackageManager.ResolveInfoFlags flags = args.getArgument(1);
-            List<ResolveInfo> resolveInfoList = new ArrayList<>();
-            if (intent.getAction().equals(Intent.ACTION_MAIN)) {
-                if ((flags.getValue() & MATCH_DISABLED_COMPONENTS) != 0) {
-                    resolveInfoList.add(constructActivityResolveInfo(TEST_TOS_DISABLED_APP_1));
-                    resolveInfoList.add(constructActivityResolveInfo(TEST_TOS_DISABLED_APP_2));
-                }
-                resolveInfoList.add(constructActivityResolveInfo(TEST_ENABLED_APP));
-            }
-            return resolveInfoList;
-        });
-    }
-
-    private void mockPmGetApplicationEnabledSetting(int enabledState, String... packages) {
-        for (String pkg : packages) {
-            when(mMockPackageManager.getApplicationEnabledSetting(pkg)).thenReturn(enabledState);
-        }
-    }
-
-    private void mockSettingsStringCalls() {
-        when(mMockContext.createContextAsUser(any(UserHandle.class), anyInt()))
-                .thenAnswer(args -> {
-                    Context context = mock(Context.class);
-                    ContentResolver contentResolver = mock(ContentResolver.class);
-                    when(context.getContentResolver()).thenReturn(contentResolver);
-                    return context;
-                });
-
-        doReturn(TEST_DISABLED_APP_1 + PACKAGES_DISABLED_ON_RESOURCE_OVERUSE_SEPARATOR
-                + TEST_DISABLED_APP_2)
-                .when(() -> Settings.Secure.getString(any(ContentResolver.class),
-                        eq(KEY_PACKAGES_DISABLED_ON_RESOURCE_OVERUSE)));
-
-        doReturn(TEST_TOS_DISABLED_APP_1 + TOS_DISABLED_APPS_SEPARATOR
-                + TEST_TOS_DISABLED_APP_2)
-                .when(() -> Settings.Secure.getString(any(ContentResolver.class),
-                        eq(KEY_UNACCEPTED_TOS_DISABLED_APPS)));
-    }
-
-    private void launchAllApps(List<AppMetaData> appMetaData) {
-        for (AppMetaData meta : appMetaData) {
-            Consumer<Context> launchCallback = meta.getLaunchCallback();
-            launchCallback.accept(mMockContext);
-        }
-    }
-
-    private static ResolveInfo constructActivityResolveInfo(String packageName) {
-        ResolveInfo info = new ResolveInfo();
-        info.activityInfo = new ActivityInfo();
-        info.activityInfo.packageName = packageName;
-        info.activityInfo.name = packageName + ".activity";
-        info.activityInfo.applicationInfo = new ApplicationInfo();
-        return info;
-    }
-
-    private static ResolveInfo constructServiceResolveInfo(String packageName) {
-        ResolveInfo info = new ResolveInfo();
-        info.serviceInfo = new ServiceInfo();
-        info.serviceInfo.packageName = packageName;
-        info.serviceInfo.name = packageName + ".service";
-        info.serviceInfo.applicationInfo = new ApplicationInfo();
-        return info;
-    }
-}
diff --git a/libs/appgrid/lib/tests/src/com/android/car/carlauncher/LauncherViewModelTest.java b/libs/appgrid/lib/tests/src/com/android/car/carlauncher/LauncherViewModelTest.java
deleted file mode 100644
index 90537c96..00000000
--- a/libs/appgrid/lib/tests/src/com/android/car/carlauncher/LauncherViewModelTest.java
+++ /dev/null
@@ -1,159 +0,0 @@
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
-package com.android.car.carlauncher;
-
-import static org.junit.Assert.assertEquals;
-import static org.mockito.Mockito.mock;
-import static org.mockito.Mockito.when;
-
-import android.car.test.mocks.AbstractExtendedMockitoTestCase;
-import android.content.ComponentName;
-import android.graphics.drawable.Drawable;
-
-import androidx.lifecycle.Observer;
-import androidx.test.runner.AndroidJUnit4;
-
-import org.junit.Before;
-import org.junit.Ignore;
-import org.junit.Rule;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-
-import java.io.File;
-import java.io.IOException;
-import java.util.ArrayList;
-import java.util.List;
-import java.util.concurrent.ExecutorService;
-import java.util.concurrent.Executors;
-import java.util.concurrent.TimeUnit;
-import java.util.function.Consumer;
-
-@RunWith(AndroidJUnit4.class)
-public final class LauncherViewModelTest extends AbstractExtendedMockitoTestCase {
-    @Rule
-    public InstantTaskExecutorRule instantTaskExecutorRule =
-            new InstantTaskExecutorRule();
-    private LauncherViewModel mLauncherModel;
-    private AppLauncherUtils.LauncherAppsInfo mLauncherAppsInfo;
-    private Drawable mDrawable = mock(Drawable.class);
-    private Consumer mConsumer = mock(Consumer.class);
-    private List<LauncherItem> mCustomizedApps;
-    private List<LauncherItem> mAlphabetizedApps;
-    private List<AppMetaData> mApps;
-
-    @Before
-    public void setUp() throws Exception {
-        mLauncherModel = new LauncherViewModel(
-                new File("/data/user/10/com.android.car.carlauncher/files"));
-        mCustomizedApps = new ArrayList<>();
-        mAlphabetizedApps = new ArrayList<>();
-        AppMetaData app1 = createTestAppMetaData("App1", "A");
-        AppMetaData app2 = createTestAppMetaData("App2", "B");
-        AppMetaData app3 = createTestAppMetaData("App3", "C");
-        LauncherItem launcherItem1 = new AppItem(app1);
-        LauncherItem launcherItem2 = new AppItem(app2);
-        LauncherItem launcherItem3 = new AppItem(app3);
-        mApps = new ArrayList<>();
-        mApps.add(app1);
-        mApps.add(app2);
-        mApps.add(app3);
-        mAlphabetizedApps = new ArrayList<>();
-        mAlphabetizedApps.add(launcherItem1);
-        mAlphabetizedApps.add(launcherItem2);
-        mAlphabetizedApps.add(launcherItem3);
-        mCustomizedApps = new ArrayList<>();
-        mCustomizedApps.add(launcherItem2);
-        mCustomizedApps.add(launcherItem3);
-        mCustomizedApps.add(launcherItem1);
-
-        mLauncherAppsInfo = mock(AppLauncherUtils.LauncherAppsInfo.class);
-        when(mLauncherAppsInfo.getLaunchableComponentsList()).thenReturn(mApps);
-    }
-
-    private AppMetaData createTestAppMetaData(String displayName, String componentName) {
-        return new AppMetaData(displayName, new ComponentName(componentName, componentName),
-                mDrawable, true, false, true, mConsumer, mConsumer);
-    }
-
-    @Test
-    @Ignore("b/304484141")
-    public void test_concurrentExecution() throws InterruptedException {
-        ExecutorService pool = Executors.newCachedThreadPool();
-        for (int i = 0; i < 100; i++) {
-            pool.execute(() -> {
-                mLauncherModel.loadAppsOrderFromFile();
-            });
-            pool.execute(() -> {
-                mLauncherModel.processAppsInfoFromPlatform(mLauncherAppsInfo);
-            });
-        }
-        pool.shutdown(); // Disable new tasks from being submitted
-        if (!pool.awaitTermination(30, TimeUnit.SECONDS)) {
-            pool.shutdownNow(); // Cancel currently executing tasks
-        }
-        mLauncherModel.getCurrentLauncher().observeForever(new Observer<>() {
-            @Override
-            public void onChanged(List<LauncherItem> launcherItems) {
-                assertEquals(3, launcherItems.size());
-                assertEquals("A", launcherItems.get(0).getPackageName());
-                assertEquals("B", launcherItems.get(1).getPackageName());
-                assertEquals("C", launcherItems.get(2).getPackageName());
-                //remove observer after assertion
-                mLauncherModel.getCurrentLauncher().removeObserver(this);
-            }
-        });
-    }
-
-    @Test
-    public void loadAppsOrderFromFile_first_noOrderFile() throws IOException {
-        mLauncherModel.loadAppsOrderFromFile();
-        mLauncherModel.processAppsInfoFromPlatform(mLauncherAppsInfo);
-        mLauncherModel.getCurrentLauncher().observeForever(launcherItems -> {
-            assertEquals(3, launcherItems.size());
-            assertEquals("A", launcherItems.get(0).getPackageName());
-            assertEquals("B", launcherItems.get(1).getPackageName());
-            assertEquals("C", launcherItems.get(2).getPackageName());
-        });
-    }
-
-    @Test
-    public void loadAppsOrderFromFile_first_existsOrderFile() {
-        mLauncherModel.processAppsInfoFromPlatform(mLauncherAppsInfo);
-        mLauncherModel.loadAppsOrderFromFile();
-
-        mLauncherModel.setAppPosition(0, mApps.get(2));
-        // normally, the observer would make this call
-        mLauncherModel.handleAppListChange();
-
-        mLauncherModel.loadAppsOrderFromFile();
-        mLauncherModel.getCurrentLauncher().observeForever(it -> {
-            assertEquals("C", mApps.get(2).getPackageName());
-            assertEquals(3, it.size());
-            assertEquals("C", it.get(0).getPackageName());
-        });
-    }
-
-    @Test
-    public void processAppsInfoFromPlatform_first_noCustomOrderFile() {
-        mLauncherModel.processAppsInfoFromPlatform(mLauncherAppsInfo);
-        mLauncherModel.loadAppsOrderFromFile();
-        mLauncherModel.getCurrentLauncher().observeForever(it -> {
-            assertEquals(3, it.size());
-            assertEquals("A", it.get(0).getPackageName());
-        });
-    }
-}
diff --git a/libs/appgrid/lib/tests/src/com/android/car/carlauncher/apporder/AppOrderControllerTest.java b/libs/appgrid/lib/tests/src/com/android/car/carlauncher/apporder/AppOrderControllerTest.java
deleted file mode 100644
index da153fd1..00000000
--- a/libs/appgrid/lib/tests/src/com/android/car/carlauncher/apporder/AppOrderControllerTest.java
+++ /dev/null
@@ -1,174 +0,0 @@
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
-package com.android.car.carlauncher.apporder;
-
-import static com.google.common.truth.Truth.assertThat;
-
-import static org.mockito.Mockito.any;
-import static org.mockito.Mockito.mock;
-import static org.mockito.Mockito.never;
-import static org.mockito.Mockito.spy;
-import static org.mockito.Mockito.times;
-import static org.mockito.Mockito.verify;
-import static org.mockito.Mockito.when;
-
-import android.content.ComponentName;
-
-import androidx.lifecycle.MutableLiveData;
-import androidx.test.ext.junit.runners.AndroidJUnit4;
-
-import com.android.car.carlauncher.AppItem;
-import com.android.car.carlauncher.AppMetaData;
-import com.android.car.carlauncher.LauncherItem;
-import com.android.car.carlauncher.LauncherItemMessageHelper;
-import com.android.car.carlauncher.LauncherItemProto.LauncherItemMessage;
-import com.android.car.carlauncher.datastore.launcheritem.LauncherItemListSource;
-
-import org.junit.Before;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
-
-import java.util.ArrayList;
-import java.util.HashMap;
-import java.util.List;
-import java.util.Map;
-
-@RunWith(AndroidJUnit4.class)
-public class AppOrderControllerTest {
-    private AppOrderController mController;
-    private Map<ComponentName, LauncherItem> mLauncherItemsMap;
-    private List<LauncherItem> mDefaultOrder;
-    private List<LauncherItem> mCustomizedOrder;
-    @Mock
-    private LauncherItemListSource mMockDataSource;
-    private MutableLiveData<List<LauncherItem>> mCurrentAppList;
-
-    @Before
-    public void setUp() throws Exception {
-        MockitoAnnotations.initMocks(this);
-        when(mMockDataSource.exists()).thenReturn(true);
-
-        mLauncherItemsMap = new HashMap<>();
-        mDefaultOrder = spy(new ArrayList<>());
-        mCustomizedOrder = spy(new ArrayList<>());
-        mCurrentAppList = spy(new MutableLiveData<>());
-        mCustomizedOrder.add(null);
-
-        mController = spy(new AppOrderController(mMockDataSource, mCurrentAppList, mDefaultOrder,
-                mCustomizedOrder));
-    }
-
-    @Test
-    public void maybePublishAppList_loadAppListFromPlatform_noPublishing() {
-        // tests that multiple platform connection does not publish app list
-        mController.loadAppListFromPlatform(mLauncherItemsMap, mDefaultOrder);
-        assertThat(mController.appsDataLoadingCompleted()).isFalse();
-
-        mController.loadAppListFromPlatform(mLauncherItemsMap, mDefaultOrder);
-        assertThat(mController.appsDataLoadingCompleted()).isFalse();
-
-        verify(mController, times(2)).maybePublishAppList();
-        verify(mCurrentAppList, never()).postValue(any());
-    }
-
-    @Test
-    public void maybePublishAppList_loadAppListFromFile_noPublishing() {
-        // tests that multiple file read does not publish app list
-        mController.loadAppOrderFromFile();
-        assertThat(mController.appsDataLoadingCompleted()).isFalse();
-
-        mController.loadAppOrderFromFile();
-        assertThat(mController.appsDataLoadingCompleted()).isFalse();
-
-        verify(mController, times(2)).maybePublishAppList();
-        verify(mCurrentAppList, never()).postValue(any());
-    }
-
-    @Test
-    public void maybePublishAppList_publishing_defaultOrder() {
-        when(mController.checkDataSourceExists()).thenReturn(false);
-
-        mController.loadAppOrderFromFile();
-        assertThat(mController.appsDataLoadingCompleted()).isFalse();
-        assertThat(mController.shouldUseCustomOrder()).isFalse();
-
-        mController.loadAppListFromPlatform(mLauncherItemsMap, mDefaultOrder);
-        verify(mController, times(2)).maybePublishAppList();
-        verify(mCurrentAppList, times(1)).postValue(any());
-    }
-
-    @Test
-    public void maybePublishAppList_publishing_customOrder() {
-        when(mController.checkDataSourceExists()).thenReturn(true);
-        // if the data source exists and the list is non-empty, we expect to use custom oder
-        List<LauncherItemMessage> nonEmptyMessageList = new ArrayList<>();
-        LauncherItemMessage emptyAppItemMessage =
-                (new AppItem("packageName", "className", "displayName", null))
-                        .convertToMessage(1, 1);
-        nonEmptyMessageList.add(emptyAppItemMessage);
-        LauncherItemMessageHelper helper = new LauncherItemMessageHelper();
-        when(mMockDataSource.readFromFile()).thenReturn(
-                helper.convertToMessage(nonEmptyMessageList));
-
-        mController.loadAppOrderFromFile();
-        assertThat(mController.appsDataLoadingCompleted()).isFalse();
-        assertThat(mController.shouldUseCustomOrder()).isTrue();
-
-        mController.loadAppListFromPlatform(mLauncherItemsMap, mDefaultOrder);
-        verify(mController, times(2)).maybePublishAppList();
-        verify(mCurrentAppList, times(1)).postValue(any());
-    }
-
-    @Test
-    public void setAppPosition_postValue() {
-        // simulate platform app loading
-        LauncherItem testItem1 = new AppItem("packageName1", "className1", "displayName1", null);
-        LauncherItem testItem2 = new AppItem("packageName2", "className2", "displayName2", null);
-        String packageName3 = "packageName3";
-        LauncherItem testItem3 = new AppItem(packageName3, "className3", "displayName3", null);
-
-        mLauncherItemsMap.put(new ComponentName("componentName1", "componentName1"), testItem1);
-        mLauncherItemsMap.put(new ComponentName("componentName2", "componentName2"), testItem2);
-        ComponentName componentName3 = new ComponentName("componentName3", "componentName3");
-        mLauncherItemsMap.put(componentName3, testItem3);
-        List<LauncherItem> newAppList = new ArrayList<>();
-        newAppList.add(testItem1);
-        newAppList.add(testItem2);
-        newAppList.add(testItem3);
-        when(mCurrentAppList.getValue()).thenReturn(newAppList);
-
-        // simulate launcher cold start - no app list from file
-        mController.loadAppOrderFromFile();
-        assertThat(mController.shouldUseCustomOrder()).isFalse();
-        mController.loadAppListFromPlatform(mLauncherItemsMap, newAppList);
-        verify(mCurrentAppList, times(1)).postValue(any());
-
-        AppMetaData mockApp3MetaData = mock(AppMetaData.class);
-        when(mockApp3MetaData.getComponentName()).thenReturn(componentName3);
-
-        // tests that setAppPosition posts update to the user interface
-        mController.setAppPosition(0, mockApp3MetaData);
-        verify(mCurrentAppList, times(2)).postValue(any());
-
-        // tests that the setAppPosition correctly modifies app position
-        assertThat(mCurrentAppList.getValue()).isNotNull();
-        assertThat(mCurrentAppList.getValue().isEmpty()).isFalse();
-        assertThat(mCurrentAppList.getValue().get(0).getPackageName()).isEqualTo(packageName3);
-    }
-}
diff --git a/libs/car-launcher-common/res/values-en-rCA/strings.xml b/libs/car-launcher-common/res/values-en-rCA/strings.xml
new file mode 100644
index 00000000..eb650c60
--- /dev/null
+++ b/libs/car-launcher-common/res/values-en-rCA/strings.xml
@@ -0,0 +1,28 @@
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
+   -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="dock_pin_shortcut_label" msgid="7319916279393348946">"Pin app"</string>
+    <string name="dock_unpin_shortcut_label" msgid="1657441916649851101">"Unpin app"</string>
+    <string name="stop_app_shortcut_label" msgid="5893149773635675147">"Stop app"</string>
+    <string name="app_info_shortcut_label" msgid="6724408677044314793">"App info"</string>
+    <string name="stop_app_dialog_title" msgid="7027389231920405129">"Stop app?"</string>
+    <string name="stop_app_dialog_text" msgid="4997162043741899166">"If you force stop an app, it may misbehave."</string>
+    <string name="stop_app_success_toast_text" msgid="3740858295088091414">"<xliff:g id="APP_NAME">%1$s</xliff:g> has been stopped."</string>
+    <string name="ndo_launch_fail_toast_text" msgid="633927891331266600">"<xliff:g id="APP_NAME">%1$s</xliff:g> can\'t be used while driving."</string>
+</resources>
diff --git a/libs/car-launcher-common/src/com/android/car/carlaunchercommon/shortcuts/ForceStopShortcutItem.kt b/libs/car-launcher-common/src/com/android/car/carlaunchercommon/shortcuts/ForceStopShortcutItem.kt
index aa39c767..f0cc2a28 100644
--- a/libs/car-launcher-common/src/com/android/car/carlaunchercommon/shortcuts/ForceStopShortcutItem.kt
+++ b/libs/car-launcher-common/src/com/android/car/carlaunchercommon/shortcuts/ForceStopShortcutItem.kt
@@ -18,15 +18,12 @@ package com.android.car.carlaunchercommon.shortcuts
 
 import android.app.Activity
 import android.app.ActivityManager
-import android.app.AlertDialog
-import android.app.Application.ActivityLifecycleCallbacks
 import android.app.admin.DevicePolicyManager
 import android.car.media.CarMediaManager
 import android.content.ComponentName
 import android.content.Context
 import android.content.pm.ApplicationInfo
 import android.content.pm.PackageManager
-import android.os.Bundle
 import android.os.UserHandle
 import android.os.UserManager
 import android.util.Log
@@ -58,44 +55,6 @@ open class ForceStopShortcutItem(
         private val DEBUG = isDebuggable()
     }
 
-    private var forceStopDialog: AlertDialog? = null
-
-    init {
-        // todo(b/323021079): Close alertdialog on Fragment's onPause
-        if (context is Activity) {
-            context.registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
-                override fun onActivityCreated(p0: Activity, p1: Bundle?) {
-                    // no-op
-                }
-
-                override fun onActivityStarted(p0: Activity) {
-                    // no-op
-                }
-
-                override fun onActivityResumed(p0: Activity) {
-                    // no-op
-                }
-
-                override fun onActivityPaused(p0: Activity) {
-                    forceStopDialog?.dismiss()
-                    forceStopDialog = null
-                }
-
-                override fun onActivityStopped(p0: Activity) {
-                    // no-op
-                }
-
-                override fun onActivitySaveInstanceState(p0: Activity, p1: Bundle) {
-                    // no-op
-                }
-
-                override fun onActivityDestroyed(p0: Activity) {
-                    // no-op
-                }
-            })
-        }
-    }
-
     override fun data(): CarUiShortcutsPopup.ItemData {
         return CarUiShortcutsPopup.ItemData(
             R.drawable.ic_force_stop_caution_icon,
@@ -117,8 +76,13 @@ open class ForceStopShortcutItem(
                 null // listener
             )
         builder.create().let {
-            it.window?.setType(WindowManager.LayoutParams.TYPE_SYSTEM_ALERT)
-            forceStopDialog = it
+            if (context !is Activity || context.window.decorView.windowToken == null) {
+                // If the context is not an Activity or lacks a valid window token,
+                // it's likely we're in a non-Activity context (e.g., Service, SystemUI).
+                // To ensure the AlertDialog is displayed properly, we explicitly set its window
+                // type to SYSTEM_ALERT, allowing it to overlay other windows, even from SystemUI.
+                it.window?.setType(WindowManager.LayoutParams.TYPE_SYSTEM_ALERT)
+            }
             it.show()
         }
         return true
diff --git a/libs/car-launcher-common/tests/Android.bp b/libs/car-launcher-common/tests/Android.bp
index b695a8f7..e72cea6f 100644
--- a/libs/car-launcher-common/tests/Android.bp
+++ b/libs/car-launcher-common/tests/Android.bp
@@ -16,6 +16,7 @@
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_system_experience",
 }
 
 android_test {
@@ -27,7 +28,7 @@ android_test {
     ],
 
     libs: [
-        "android.test.base",
+        "android.test.base.stubs.system",
         "android.car",
     ],
 
```

