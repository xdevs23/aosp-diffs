```diff
diff --git a/Android.bp b/Android.bp
index 3705b299..797df7ee 100644
--- a/Android.bp
+++ b/Android.bp
@@ -61,7 +61,7 @@ android_library {
         "accessibility_settings_flags_lib",
     ],
 
-    resource_dirs: ["res"],
+    resource_dirs: ["res", "res_override"],
 
     srcs: [
         "src/**/*.java",
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index e1e505d0..f29bd4a9 100755
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -79,6 +79,15 @@
         android:exported="true">
     </activity>
 
+    <activity android:name="com.android.wallpaper.picker.customization.ui.CustomizationPickerActivity2"
+        android:label="@string/app_name"
+        android:relinquishTaskIdentity="true"
+        android:resizeableActivity="false"
+        android:theme="@style/WallpaperTheme.NoBackground"
+        android:configChanges="assetsPaths"
+        android:exported="true">
+    </activity>
+
     <activity android:name="com.android.wallpaper.picker.PassThroughCustomizationPickerActivity"
         android:label="@string/app_name"
         android:resizeableActivity="false"
@@ -138,7 +147,8 @@
           android:name="com.android.wallpaper.picker.preview.ui.WallpaperPreviewActivity"
           android:excludeFromRecents="true"
           android:taskAffinity="@string/multi_crop_task_affinity"
-          android:resizeableActivity="false"
+          android:resizeableActivity="true"
+          android:screenOrientation="locked"
           android:theme="@style/WallpaperTheme.Preview">
       </activity>
 
diff --git a/OWNERS b/OWNERS
index 700c57b1..78b8d41c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -9,6 +9,7 @@ sunnygoyal@google.com
 santie@google.com
 giolin@google.com
 poultney@google.com
+wangaustin@google.com
 
 per-file BaseFlags.kt, globs = set noparent
 per-file BaseFlags.kt = santie@google.com, sunnygoyal@google.com, adamcohen@google.com
\ No newline at end of file
diff --git a/aconfig/Android.bp b/aconfig/Android.bp
index 5c6b55d4..281ae789 100644
--- a/aconfig/Android.bp
+++ b/aconfig/Android.bp
@@ -1,7 +1,7 @@
 aconfig_declarations {
     name: "com_android_wallpaper_flags",
     package: "com.android.wallpaper",
-    container: "system_ext",
+    container: "system",
     srcs: ["customization_picker.aconfig"],
 }
 
diff --git a/aconfig/customization_picker.aconfig b/aconfig/customization_picker.aconfig
index 23002453..b6311c14 100644
--- a/aconfig/customization_picker.aconfig
+++ b/aconfig/customization_picker.aconfig
@@ -1,5 +1,5 @@
 package: "com.android.wallpaper"
-container: "system_ext"
+container: "system"
 
 flag {
     name: "wallpaper_restorer_flag"
@@ -22,16 +22,16 @@ flag {
     bug: "334125919"
 }
 
-flag {
-    name: "new_picker_ui_flag"
-    namespace: "customization_picker"
-    description: "Enables the BC25 design of the customization picker UI."
-    bug: "339081035"
-}
-
 flag {
    name: "clock_reactive_variants"
    namespace: "systemui"
    description: "Add reactive variant fonts to some clocks"
    bug: "343495953"
 }
+
+flag {
+    name: "large_screen_wallpaper_collections"
+    namespace: "customization_picker"
+    description: "Enables wallpaper collections for large screen devices."
+    bug: "350781344"
+}
diff --git a/res/drawable/apply_button_background_variant.xml b/res/drawable/apply_button_background_variant.xml
new file mode 100644
index 00000000..ec35fb1a
--- /dev/null
+++ b/res/drawable/apply_button_background_variant.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<ripple xmlns:android="http://schemas.android.com/apk/res/android"
+    android:color="?android:colorControlHighlight">
+
+    <item android:id="@android:id/mask">
+        <shape android:shape="rectangle">
+            <corners android:radius="@dimen/set_wallpaper_button_corner_radius" />
+            <padding
+                android:left="@dimen/set_wallpaper_button_horizontal_padding"
+                android:top="@dimen/set_wallpaper_button_vertical_padding"
+                android:right="@dimen/set_wallpaper_button_horizontal_padding"
+                android:bottom="@dimen/set_wallpaper_button_vertical_padding" />
+            <solid android:color="?android:colorControlHighlight" />
+        </shape>
+    </item>
+
+    <item android:drawable="@drawable/set_wallpaper_button_background_variant_base" />
+</ripple>
\ No newline at end of file
diff --git a/res/drawable/customization_option_entry_background.xml b/res/drawable/customization_option_entry_background.xml
index 17869abf..b8d22fb5 100644
--- a/res/drawable/customization_option_entry_background.xml
+++ b/res/drawable/customization_option_entry_background.xml
@@ -17,7 +17,7 @@
 -->
 
 <ripple xmlns:android="http://schemas.android.com/apk/res/android"
-    android:color="?colorControlHighlight">
+    android:color="@color/ripple_material">
     <item>
         <shape android:shape="rectangle">
             <solid android:color="@color/color_surface" />
diff --git a/res/drawable/customization_option_entry_bottom_background.xml b/res/drawable/customization_option_entry_bottom_background.xml
index b238928a..6c8ca817 100644
--- a/res/drawable/customization_option_entry_bottom_background.xml
+++ b/res/drawable/customization_option_entry_bottom_background.xml
@@ -16,7 +16,7 @@
      limitations under the License.
 -->
 <ripple xmlns:android="http://schemas.android.com/apk/res/android"
-    android:color="?colorControlHighlight">
+    android:color="@color/ripple_material">
     <item>
         <shape android:shape="rectangle">
             <solid android:color="@color/color_surface"/>
diff --git a/res/drawable/customization_option_entry_top_background.xml b/res/drawable/customization_option_entry_top_background.xml
index a351428e..5755b55e 100644
--- a/res/drawable/customization_option_entry_top_background.xml
+++ b/res/drawable/customization_option_entry_top_background.xml
@@ -17,7 +17,7 @@
 -->
 
 <ripple xmlns:android="http://schemas.android.com/apk/res/android"
-    android:color="?colorControlHighlight">
+    android:color="@color/ripple_material">
     <item>
         <shape android:shape="rectangle">
             <solid android:color="@color/color_surface"/>
diff --git a/res/drawable/floating_sheet_content_background.xml b/res/drawable/floating_sheet_content_background.xml
new file mode 100644
index 00000000..751a678a
--- /dev/null
+++ b/res/drawable/floating_sheet_content_background.xml
@@ -0,0 +1,22 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+
+     Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <corners android:radius="28dp" />
+    <solid android:color="@color/system_surface_bright" />
+</shape>
diff --git a/res/layout/bottom_sheet_clock.xml b/res/drawable/floating_tab_toolbar_background.xml
similarity index 62%
rename from res/layout/bottom_sheet_clock.xml
rename to res/drawable/floating_tab_toolbar_background.xml
index f917d9fd..a91e23ff 100644
--- a/res/layout/bottom_sheet_clock.xml
+++ b/res/drawable/floating_tab_toolbar_background.xml
@@ -13,14 +13,8 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License.
   -->
-
-<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
-    android:layout_width="match_parent"
-    android:layout_height="200dp"
-    android:background="#00ff00">
-    <TextView
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:text="Clock customization bottom sheet"
-        android:layout_gravity="center" />
-</FrameLayout>
\ No newline at end of file
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <corners android:radius="100dp" />
+    <solid android:color="@color/system_surface_bright" />
+</shape>
\ No newline at end of file
diff --git a/res/layout/bottom_sheet_shortcut.xml b/res/drawable/floating_tab_toolbar_tab_background.xml
similarity index 62%
rename from res/layout/bottom_sheet_shortcut.xml
rename to res/drawable/floating_tab_toolbar_tab_background.xml
index ae2826b3..0c45f7ef 100644
--- a/res/layout/bottom_sheet_shortcut.xml
+++ b/res/drawable/floating_tab_toolbar_tab_background.xml
@@ -13,14 +13,8 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License.
   -->
-
-<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
-    android:layout_width="match_parent"
-    android:layout_height="300dp"
-    android:background="#ffff00">
-    <TextView
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:text="Shortcut customization bottom sheet"
-        android:layout_gravity="center" />
-</FrameLayout>
\ No newline at end of file
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <corners android:radius="100dp" />
+    <solid android:color="@color/system_secondary_container" />
+</shape>
\ No newline at end of file
diff --git a/res/drawable/ic_arrow_back_24dp.xml b/res/drawable/ic_arrow_back_24dp.xml
new file mode 100644
index 00000000..747e014d
--- /dev/null
+++ b/res/drawable/ic_arrow_back_24dp.xml
@@ -0,0 +1,18 @@
+<!--
+     Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="24dp" android:height="24dp" android:viewportWidth="960" android:viewportHeight="960" android:tint="@color/system_on_surface_variant" android:autoMirrored="true">
+  <path android:fillColor="@android:color/white" android:pathData="M313,520L537,744L480,800L160,480L480,160L537,216L313,440L800,440L800,520L313,520Z"/>
+</vector>
\ No newline at end of file
diff --git a/res/drawable/ic_close_24dp.xml b/res/drawable/ic_close_24dp.xml
new file mode 100644
index 00000000..1aaef5c0
--- /dev/null
+++ b/res/drawable/ic_close_24dp.xml
@@ -0,0 +1,18 @@
+<!--
+     Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="24dp" android:height="24dp" android:viewportWidth="960" android:viewportHeight="960" android:tint="@color/system_on_surface_variant">
+  <path android:fillColor="@android:color/white" android:pathData="M256,760L200,704L424,480L200,256L256,200L480,424L704,200L760,256L536,480L760,704L704,760L480,536L256,760Z"/>
+</vector>
\ No newline at end of file
diff --git a/res/drawable/nav_button_background.xml b/res/drawable/nav_button_background.xml
new file mode 100644
index 00000000..d391fa5b
--- /dev/null
+++ b/res/drawable/nav_button_background.xml
@@ -0,0 +1,28 @@
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
+-->
+<ripple xmlns:android="http://schemas.android.com/apk/res/android"
+    android:color="?android:colorControlHighlight">
+
+    <item android:id="@android:id/mask">
+        <shape android:shape="rectangle">
+            <solid android:color="?android:colorControlHighlight" />
+            <corners android:radius="20dp" />
+        </shape>
+    </item>
+
+    <item android:drawable="@drawable/nav_button_background_base" />
+</ripple>
\ No newline at end of file
diff --git a/res/drawable/nav_button_background_base.xml b/res/drawable/nav_button_background_base.xml
new file mode 100644
index 00000000..4152cf40
--- /dev/null
+++ b/res/drawable/nav_button_background_base.xml
@@ -0,0 +1,21 @@
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
+-->
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <corners android:radius="20dp" />
+    <solid android:color="@color/system_surface_container_highest" />
+</shape>
\ No newline at end of file
diff --git a/res/layout/activity_cusomization_picker2.xml b/res/layout/activity_cusomization_picker2.xml
index 6239e6f1..aad2e9e5 100644
--- a/res/layout/activity_cusomization_picker2.xml
+++ b/res/layout/activity_cusomization_picker2.xml
@@ -13,75 +13,127 @@
     See the License for the specific language governing permissions and
     limitations under the License.
 -->
-<androidx.constraintlayout.motion.widget.MotionLayout
+<androidx.constraintlayout.widget.ConstraintLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
-    android:id="@+id/picker_motion_layout"
+    android:id="@+id/root_view"
     android:layout_width="match_parent"
-    android:layout_height="match_parent"
-    app:layoutDescription="@xml/customization_picker_layout_scene">
+    android:layout_height="match_parent">
 
     <FrameLayout
-        android:id="@+id/preview_header"
+        android:id="@+id/nav_button"
+        android:layout_width="36dp"
+        android:layout_height="@dimen/wallpaper_control_button_size"
+        android:background="@drawable/nav_button_background"
+        android:layout_marginStart="@dimen/nav_button_start_margin"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintTop_toTopOf="@id/toolbar"
+        app:layout_constraintBottom_toBottomOf="@id/toolbar">
+        <View
+            android:id="@+id/nav_button_icon"
+            android:layout_width="24dp"
+            android:layout_height="24dp"
+            android:background="@drawable/ic_close_24dp"
+            android:layout_gravity="center" />
+    </FrameLayout>
+
+    <Toolbar
+        android:id="@+id/toolbar"
         android:layout_width="0dp"
-        android:layout_height="@dimen/customization_picker_preview_header_expanded_height"
+        android:layout_height="?android:attr/actionBarSize"
+        android:theme="?android:attr/actionBarTheme"
+        android:importantForAccessibility="yes"
+        android:layout_gravity="top"
         app:layout_constraintTop_toTopOf="parent"
-        app:layout_constraintStart_toStartOf="parent"
-        app:layout_constraintEnd_toEndOf="parent">
+        app:layout_constraintStart_toEndOf="@+id/nav_button"
+        app:layout_constraintEnd_toStartOf="@+id/apply_button">
+        <TextView
+            android:id="@+id/custom_toolbar_title"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:ellipsize="end"
+            android:maxLines="1"
+            android:textAppearance="@style/CollapsingToolbar.Collapsed"/>
+    </Toolbar>
 
-        <androidx.viewpager2.widget.ViewPager2
-            android:id="@+id/preview_pager"
-            android:layout_width="match_parent"
-            android:layout_height="match_parent" />
-    </FrameLayout>
+    <Button
+        android:id="@+id/apply_button"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:minHeight="@dimen/touch_target_min_height"
+        android:layout_marginEnd="@dimen/apply_button_end_margin"
+        android:background="@drawable/apply_button_background_variant"
+        android:text="@string/apply_btn"
+        android:textColor="@color/system_on_primary"
+        android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintTop_toTopOf="@id/toolbar"
+        app:layout_constraintBottom_toBottomOf="@id/toolbar"/>
 
-    <androidx.core.widget.NestedScrollView
-        android:id="@+id/bottom_scroll_view"
+    <androidx.constraintlayout.motion.widget.MotionLayout
+        android:id="@+id/picker_motion_layout"
         android:layout_width="0dp"
         android:layout_height="0dp"
-        app:layout_constraintTop_toBottomOf="@+id/preview_header"
+        app:layout_constraintTop_toBottomOf="@+id/toolbar"
         app:layout_constraintStart_toStartOf="parent"
         app:layout_constraintEnd_toEndOf="parent"
-        app:layout_constraintBottom_toBottomOf="parent">
+        app:layout_constraintBottom_toBottomOf="parent"
+        app:layoutDescription="@xml/customization_picker_layout_scene">
 
-        <androidx.constraintlayout.motion.widget.MotionLayout
-            android:id="@+id/customization_option_container"
-            android:layout_width="match_parent"
-            android:layout_height="wrap_content"
-            android:paddingHorizontal="@dimen/customization_option_container_horizontal_padding"
-            app:layoutDescription="@xml/customization_option_container_layout_scene">
+        <FrameLayout
+            android:id="@+id/preview_header"
+            android:layout_width="0dp"
+            android:layout_height="@dimen/customization_picker_preview_header_expanded_height"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent">
 
-            <LinearLayout
-                android:id="@+id/lock_customization_option_container"
+            <androidx.viewpager2.widget.ViewPager2
+                android:id="@+id/preview_pager"
                 android:layout_width="match_parent"
-                android:layout_height="wrap_content"
-                android:showDividers="middle"
-                android:divider="@drawable/customization_option_entry_divider"
-                android:orientation="vertical" />
+                android:layout_height="match_parent" />
+        </FrameLayout>
 
-            <LinearLayout
-                android:id="@+id/home_customization_option_container"
+        <androidx.core.widget.NestedScrollView
+            android:id="@+id/bottom_scroll_view"
+            android:layout_width="0dp"
+            android:layout_height="0dp"
+            app:layout_constraintTop_toBottomOf="@+id/preview_header"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent">
+
+            <androidx.constraintlayout.motion.widget.MotionLayout
+                android:id="@+id/customization_option_container"
                 android:layout_width="match_parent"
                 android:layout_height="wrap_content"
-                android:showDividers="middle"
-                android:divider="@drawable/customization_option_entry_divider"
-                android:orientation="vertical" />
-        </androidx.constraintlayout.motion.widget.MotionLayout>
-    </androidx.core.widget.NestedScrollView>
+                android:paddingHorizontal="@dimen/customization_option_container_horizontal_padding"
+                app:layoutDescription="@xml/customization_option_container_layout_scene">
 
-    <!-- Guideline for the preview in the secondary screen -->
-    <androidx.constraintlayout.widget.Guideline
-        android:id="@+id/preview_guideline_in_secondary_screen"
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:orientation="horizontal"
-        app:layout_constraintGuide_end="0dp" />
+                <LinearLayout
+                    android:id="@+id/lock_customization_option_container"
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    android:showDividers="middle"
+                    android:divider="@drawable/customization_option_entry_divider"
+                    android:orientation="vertical" />
 
-    <FrameLayout
-        android:id="@+id/customization_picker_bottom_sheet"
-        android:layout_width="0dp"
-        android:layout_height="wrap_content"
-        app:layout_constraintStart_toStartOf="parent"
-        app:layout_constraintEnd_toEndOf="parent"
-        app:layout_constraintTop_toBottomOf="parent" />
-</androidx.constraintlayout.motion.widget.MotionLayout>
+                <LinearLayout
+                    android:id="@+id/home_customization_option_container"
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    android:showDividers="middle"
+                    android:divider="@drawable/customization_option_entry_divider"
+                    android:orientation="vertical" />
+            </androidx.constraintlayout.motion.widget.MotionLayout>
+        </androidx.core.widget.NestedScrollView>
+
+        <FrameLayout
+            android:id="@+id/customization_option_floating_sheet_container"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintTop_toBottomOf="parent" />
+    </androidx.constraintlayout.motion.widget.MotionLayout>
+</androidx.constraintlayout.widget.ConstraintLayout>
diff --git a/res/layout/categories_fragment.xml b/res/layout/categories_fragment.xml
index 2c308dfb..c46748f8 100644
--- a/res/layout/categories_fragment.xml
+++ b/res/layout/categories_fragment.xml
@@ -14,7 +14,8 @@
   ~ limitations under the License.
   -->
 
-<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+<androidx.coordinatorlayout.widget.CoordinatorLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
     android:orientation="vertical"
     android:id="@+id/content_parent"
@@ -23,6 +24,10 @@
     android:fitsSystemWindows="true"
     android:transitionGroup="true">
 
+    <include
+        android:id="@+id/header_bar"
+        layout="@layout/section_header" />
+
     <!-- Loading Indicator -->
     <ProgressBar
         android:id="@+id/loading_indicator"
@@ -44,4 +49,4 @@
         android:scrollbars="vertical"
         app:layout_behavior="@string/appbar_scrolling_view_behavior" />
 
-</FrameLayout>
\ No newline at end of file
+</androidx.coordinatorlayout.widget.CoordinatorLayout>
\ No newline at end of file
diff --git a/res/layout/category_section_view.xml b/res/layout/category_section_view.xml
index b94ea6dc..3f393322 100644
--- a/res/layout/category_section_view.xml
+++ b/res/layout/category_section_view.xml
@@ -19,8 +19,7 @@
     android:orientation="vertical"
     android:id="@+id/section_category"
     android:layout_width="match_parent"
-    android:layout_height="wrap_content"
-    android:layout_marginBottom="5dp">
+    android:layout_height="wrap_content">
 
     <TextView
         android:id="@+id/section_title"
@@ -28,7 +27,7 @@
         android:layout_height="wrap_content"
         android:textAppearance="@style/CategorySectionTitleTextAppearance"
         android:focusable="false"
-        android:layout_gravity="bottom" />
+        android:layout_marginBottom="@dimen/grid_item_category_title_margin_bottom"/>
 
     <!-- Tiles -->
     <androidx.recyclerview.widget.RecyclerView
diff --git a/res/layout/category_tile.xml b/res/layout/category_tile.xml
index 9121d2ed..b12a0558 100644
--- a/res/layout/category_tile.xml
+++ b/res/layout/category_tile.xml
@@ -21,7 +21,6 @@
     android:layout_height="wrap_content"
     android:focusable="false"
     android:orientation="vertical"
-    android:layout_marginTop="10dp"
     android:importantForAccessibility="yes">
 
     <TextView
@@ -37,7 +36,7 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/category"
         android:layout_width="match_parent"
-        android:layout_height="match_parent"
+        android:layout_height="wrap_content"
         android:importantForAccessibility="no"
         android:foreground="?attr/selectableItemBackground"
         app:cardCornerRadius="?android:dialogCornerRadius"
@@ -60,5 +59,6 @@
         android:gravity="center"
         android:maxLines="1"
         android:minHeight="@dimen/grid_item_category_label_minimum_height"
+        android:textColor="@color/system_on_surface"
         tools:text="Wallpaper category" />
 </LinearLayout>
\ No newline at end of file
diff --git a/res/layout/customization_option_entry_wallpaper.xml b/res/layout/customization_option_entry_wallpaper.xml
index faeb6abe..1e346678 100644
--- a/res/layout/customization_option_entry_wallpaper.xml
+++ b/res/layout/customization_option_entry_wallpaper.xml
@@ -20,11 +20,12 @@
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:paddingHorizontal="@dimen/customization_option_entry_horizontal_padding"
-    android:paddingVertical="@dimen/customization_option_entry_vertical_padding_large"
     android:clickable="true">
     <TextView
+        android:id="@+id/more_wallpapers"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
+        android:minHeight="@dimen/accessibility_min_height"
         android:gravity="center"
         android:drawablePadding="@dimen/customization_option_entry_more_wallpapers_drawable_padding"
         android:text="@string/more_wallpapers"
diff --git a/res/layout/customization_picker_preview_card.xml b/res/layout/customization_picker_preview_card.xml
new file mode 100644
index 00000000..def02da1
--- /dev/null
+++ b/res/layout/customization_picker_preview_card.xml
@@ -0,0 +1,24 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:clipChildren="false"
+    android:clipToPadding="false">
+
+    <include layout="@layout/wallpaper_preview_card2" />
+</FrameLayout>
diff --git a/res/layout/floating_sheet3.xml b/res/layout/floating_sheet3.xml
new file mode 100644
index 00000000..ed76b8d7
--- /dev/null
+++ b/res/layout/floating_sheet3.xml
@@ -0,0 +1,40 @@
+<?xml version="1.0" encoding="utf-8"?><!--
+  Copyright (C) 2024 The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+-->
+<androidx.coordinatorlayout.widget.CoordinatorLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_height="match_parent"
+    android:layout_width="match_parent">
+    <!-- Bottom Sheet Behavior view should be a child view of CoordinatorLayout -->
+    <FrameLayout
+        android:id="@+id/floating_sheet_container"
+        android:layout_height="wrap_content"
+        android:layout_width="match_parent"
+        android:importantForAccessibility="no"
+        app:behavior_hideable="true"
+        app:behavior_peekHeight="0dp"
+        app:behavior_skipCollapsed="true"
+        app:layout_behavior="com.google.android.material.bottomsheet.BottomSheetBehavior">
+        <!-- To enable a floating sheet, content and styling are included as child view -->
+        <FrameLayout
+            android:id="@+id/floating_sheet_content"
+            android:layout_height="wrap_content"
+            android:layout_width="match_parent"
+            android:padding="@dimen/wallpaper_info_pane_padding"
+            android:layout_marginHorizontal="@dimen/floating_sheet_margin"
+            android:background="@drawable/floating_sheet_background" />
+    </FrameLayout>
+</androidx.coordinatorlayout.widget.CoordinatorLayout>
\ No newline at end of file
diff --git a/res/layout/floating_toolbar.xml b/res/layout/floating_toolbar.xml
new file mode 100644
index 00000000..3a38cec3
--- /dev/null
+++ b/res/layout/floating_toolbar.xml
@@ -0,0 +1,37 @@
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
+<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:layout_width="wrap_content"
+    android:layout_height="wrap_content"
+    android:background="@drawable/floating_tab_toolbar_background"
+    tools:ignore="contentDescription"
+    android:padding="@dimen/floating_tab_toolbar_padding">
+
+    <androidx.recyclerview.widget.RecyclerView
+        android:id="@+id/tab_list"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:orientation="horizontal"
+        app:layoutManager="LinearLayoutManager"  />
+
+    <include
+        layout="@layout/floating_toolbar_tab_placeholder"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:visibility="invisible" />
+</FrameLayout>
\ No newline at end of file
diff --git a/res/layout/floating_toolbar_tab.xml b/res/layout/floating_toolbar_tab.xml
new file mode 100644
index 00000000..be7dc8c8
--- /dev/null
+++ b/res/layout/floating_toolbar_tab.xml
@@ -0,0 +1,45 @@
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:id="@+id/tab_container"
+    android:layout_width="wrap_content"
+    android:layout_height="wrap_content"
+    android:minHeight="@dimen/accessibility_min_height"
+    android:background="@drawable/floating_tab_toolbar_tab_background"
+    android:gravity="center_vertical"
+    android:paddingVertical="@dimen/floating_tab_toolbar_tab_vertical_padding"
+    android:paddingHorizontal="@dimen/floating_tab_toolbar_tab_horizontal_padding">
+
+    <ImageView
+        android:id="@+id/tab_icon"
+        android:layout_width="@dimen/floating_tab_toolbar_tab_icon_size"
+        android:layout_height="@dimen/floating_tab_toolbar_tab_icon_size"
+        android:layout_marginEnd="@dimen/floating_tab_toolbar_tab_icon_margin_end"
+        app:tint="@color/system_on_surface"
+        tools:src="@drawable/ic_delete" />
+
+    <TextView
+        android:id="@+id/label_text"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
+        android:textColor="@color/text_color_primary"
+        android:gravity="center"
+        android:lines="1"
+        tools:text="Tab Primary"/>
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/floating_toolbar_tab_placeholder.xml b/res/layout/floating_toolbar_tab_placeholder.xml
new file mode 100644
index 00000000..bcff5286
--- /dev/null
+++ b/res/layout/floating_toolbar_tab_placeholder.xml
@@ -0,0 +1,44 @@
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="wrap_content"
+    android:layout_height="wrap_content"
+    android:minHeight="@dimen/accessibility_min_height"
+    android:background="@drawable/floating_tab_toolbar_tab_background"
+    android:gravity="center_vertical"
+    android:paddingVertical="@dimen/floating_tab_toolbar_tab_vertical_padding"
+    android:paddingHorizontal="@dimen/floating_tab_toolbar_tab_horizontal_padding">
+
+    <ImageView
+        android:id="@+id/tab_icon"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginEnd="@dimen/floating_tab_toolbar_tab_icon_margin_end"
+        app:tint="@color/system_on_surface"
+        android:importantForAccessibility="no"
+        android:src="@drawable/ic_delete" />
+
+    <TextView
+        android:id="@+id/label_text"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
+        android:textColor="@color/text_color_primary"
+        android:gravity="center"
+        android:lines="1"
+        android:text="@string/tab_placeholder_text"/>
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/fragment_full_preview.xml b/res/layout/fragment_full_preview.xml
index 9572987f..f09109c2 100644
--- a/res/layout/fragment_full_preview.xml
+++ b/res/layout/fragment_full_preview.xml
@@ -23,8 +23,8 @@
     <com.android.wallpaper.picker.TouchForwardingLayout
         android:id="@+id/touch_forwarding_layout"
         android:layout_width="match_parent"
-        android:importantForAccessibility="yes"
         android:layout_height="match_parent"
+        android:importantForAccessibility="yes"
         android:background="@android:color/transparent"
         android:accessibilityTraversalBefore="@id/toolbar"
         android:contentDescription="@string/preview_screen_description"/>
@@ -60,7 +60,7 @@
     </androidx.constraintlayout.widget.ConstraintLayout>
 
     <ViewStub
-        android:id="@+id/tooltip_stub"
+        android:id="@+id/full_preview_tooltip_stub"
         android:inflatedId="@+id/tooltip"
         android:layout="@layout/tooltip_full_preview"
         android:layout_height="match_parent"
diff --git a/res/layout/fragment_small_preview_foldable.xml b/res/layout/fragment_small_preview_foldable.xml
index 1beb1dac..d4518c2c 100644
--- a/res/layout/fragment_small_preview_foldable.xml
+++ b/res/layout/fragment_small_preview_foldable.xml
@@ -71,7 +71,7 @@
         android:clipToPadding="false">
 
         <com.android.wallpaper.picker.preview.ui.view.DualPreviewViewPager
-            android:id="@+id/dual_preview_pager"
+            android:id="@+id/pager_previews"
             android:layout_width="match_parent"
             android:layout_height="match_parent"
             android:layout_gravity="bottom"
diff --git a/res/layout/fragment_small_preview_foldable2.xml b/res/layout/fragment_small_preview_foldable2.xml
new file mode 100644
index 00000000..545d545e
--- /dev/null
+++ b/res/layout/fragment_small_preview_foldable2.xml
@@ -0,0 +1,109 @@
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
+<androidx.constraintlayout.widget.ConstraintLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/container"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:fitsSystemWindows="true"
+    android:transitionGroup="true"
+    android:clipChildren="false"
+    android:clipToPadding="false">
+
+    <include
+        android:id="@+id/toolbar_container"
+        layout="@layout/section_header_content"
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        app:layout_constraintTop_toTopOf="parent"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toStartOf="@id/button_set_wallpaper"
+        app:layout_constraintVertical_chainStyle="spread_inside" />
+
+    <Button
+        android:id="@+id/button_set_wallpaper"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginEnd="@dimen/set_wallpaper_button_margin_end"
+        android:background="@drawable/set_wallpaper_button_background_variant"
+        android:elevation="@dimen/wallpaper_preview_buttons_elevation"
+        android:gravity="center"
+        android:minHeight="@dimen/touch_target_min_height"
+        android:text="@string/next_page_content_description"
+        android:textColor="@color/system_on_primary"
+        android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintTop_toTopOf="parent"
+        app:layout_constraintBottom_toBottomOf="@id/toolbar_container"/>
+
+    <!-- Set clipToPadding to false so that during transition scaling, child card view is not
+    clipped to the header bar -->
+    <androidx.constraintlayout.motion.widget.MotionLayout
+        android:id="@+id/small_preview_motion_layout"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
+        android:importantForAccessibility="no"
+        android:clipChildren="false"
+        android:clipToPadding="false"
+        android:gravity="center"
+        app:layout_constraintTop_toBottomOf="@id/toolbar_container"
+        app:layout_constraintBottom_toBottomOf="parent"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layoutDescription="@xml/small_preview_layout_scene">
+
+        <com.android.wallpaper.picker.preview.ui.view.DualPreviewViewPager
+            android:id="@+id/pager_previews"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:layout_gravity="bottom"
+            android:paddingHorizontal="@dimen/small_dual_preview_edge_space"
+            android:clipChildren="false"
+            android:importantForAccessibility="no" />
+
+        <HorizontalScrollView
+            android:id="@+id/preview_action_group_container"
+            android:layout_width="wrap_content"
+            android:layout_height="0dp"
+            android:scrollbars="none">
+
+            <com.android.wallpaper.picker.preview.ui.view.PreviewActionGroup
+                android:id="@+id/action_button_group"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:layout_gravity="center_horizontal"/>
+        </HorizontalScrollView>
+
+        <com.android.wallpaper.picker.preview.ui.view.PreviewActionFloatingSheet
+            android:id="@+id/floating_sheet"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"/>
+    </androidx.constraintlayout.motion.widget.MotionLayout>
+
+    <ViewStub
+        android:id="@+id/full_preview_tooltip_stub"
+        android:inflatedId="@+id/tooltip"
+        android:layout="@layout/tooltip_full_preview"
+        android:layout_height="match_parent"
+        android:layout_width="match_parent"
+        android:visibility="gone"
+        app:layout_constraintTop_toTopOf="parent"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintBottom_toBottomOf="parent"/>
+</androidx.constraintlayout.widget.ConstraintLayout>
diff --git a/res/layout/fragment_small_preview_handheld2.xml b/res/layout/fragment_small_preview_handheld2.xml
new file mode 100644
index 00000000..8024444a
--- /dev/null
+++ b/res/layout/fragment_small_preview_handheld2.xml
@@ -0,0 +1,100 @@
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
+  ~
+  -->
+<androidx.constraintlayout.widget.ConstraintLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/container"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:orientation="vertical"
+    android:fitsSystemWindows="true"
+    android:transitionGroup="true"
+    android:clipChildren="false"
+    android:clipToPadding="false">
+
+    <include
+        android:id="@+id/toolbar_container"
+        layout="@layout/section_header_content"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
+        app:layout_constraintTop_toTopOf="parent"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toEndOf="parent"/>
+
+    <Button
+        android:id="@+id/button_set_wallpaper"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginEnd="@dimen/set_wallpaper_button_margin_end"
+        android:background="@drawable/set_wallpaper_button_background_variant"
+        android:elevation="@dimen/wallpaper_preview_buttons_elevation"
+        android:gravity="center"
+        android:minHeight="@dimen/touch_target_min_height"
+        android:text="@string/next_page_content_description"
+        android:textColor="@color/system_on_primary"
+        android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintTop_toTopOf="@id/toolbar_container"
+        app:layout_constraintBottom_toBottomOf="@id/toolbar_container"/>
+
+    <androidx.constraintlayout.motion.widget.MotionLayout
+        android:id="@+id/small_preview_motion_layout"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
+        app:layout_constraintTop_toBottomOf="@id/toolbar_container"
+        app:layout_constraintBottom_toBottomOf="parent"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layoutDescription="@xml/small_preview_layout_scene">
+
+        <androidx.viewpager2.widget.ViewPager2
+            android:id="@+id/pager_previews"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"/>
+
+        <HorizontalScrollView
+            android:id="@+id/preview_action_group_container"
+            android:layout_width="wrap_content"
+            android:layout_height="0dp"
+            android:scrollbars="none">
+
+            <com.android.wallpaper.picker.preview.ui.view.PreviewActionGroup
+                android:id="@+id/action_button_group"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:layout_gravity="center_horizontal"/>
+        </HorizontalScrollView>
+
+        <com.android.wallpaper.picker.preview.ui.view.PreviewActionFloatingSheet
+            android:id="@+id/floating_sheet"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"/>
+    </androidx.constraintlayout.motion.widget.MotionLayout>
+
+    <ViewStub
+        android:id="@+id/full_preview_tooltip_stub"
+        android:inflatedId="@+id/tooltip"
+        android:layout="@layout/tooltip_full_preview"
+        android:layout_height="match_parent"
+        android:layout_width="match_parent"
+        android:visibility="gone"
+        app:layout_constraintTop_toTopOf="parent"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintBottom_toBottomOf="parent"/>
+</androidx.constraintlayout.widget.ConstraintLayout>
diff --git a/res/layout/full_wallpaper_preview_card.xml b/res/layout/full_wallpaper_preview_card.xml
index c9c1a731..9f3d1569 100644
--- a/res/layout/full_wallpaper_preview_card.xml
+++ b/res/layout/full_wallpaper_preview_card.xml
@@ -14,10 +14,12 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<com.android.wallpaper.picker.preview.ui.view.FullPreviewFrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+<com.android.wallpaper.picker.preview.ui.view.FullPreviewFrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/wallpaper_preview_crop"
     android:layout_width="match_parent"
-    android:layout_height="match_parent">
+    android:layout_height="match_parent"
+    android:clipChildren="false">
 
     <androidx.cardview.widget.CardView
         android:id="@+id/preview_card"
diff --git a/res/layout/fullscreen_wallpaper_preview.xml b/res/layout/fullscreen_wallpaper_preview.xml
index 67ab9191..308f351b 100644
--- a/res/layout/fullscreen_wallpaper_preview.xml
+++ b/res/layout/fullscreen_wallpaper_preview.xml
@@ -26,7 +26,7 @@
         android:background="?android:colorBackground"
         android:visibility="invisible"/>
 
-    <com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView
+    <com.android.wallpaper.picker.preview.ui.view.SystemScaledSubsamplingScaleImageView
         android:id="@+id/full_res_image"
         android:layout_width="match_parent"
         android:layout_height="match_parent" />
diff --git a/res/layout/preview_action_group2.xml b/res/layout/preview_action_group2.xml
new file mode 100644
index 00000000..f459ff40
--- /dev/null
+++ b/res/layout/preview_action_group2.xml
@@ -0,0 +1,116 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/wallpaper_control_container"
+    android:layout_width="wrap_content"
+    android:layout_height="wrap_content"
+    android:orientation="horizontal"
+    android:divider="@drawable/wallpaper_control_button_group_divider_horizontal"
+    android:showDividers="middle">
+    <ToggleButton
+        android:id="@+id/information_button"
+        android:layout_width="@dimen/wallpaper_control_button_size"
+        android:layout_height="@dimen/wallpaper_control_button_size"
+        android:background="@android:color/transparent"
+        android:contentDescription="@string/tab_info"
+        android:elevation="@dimen/wallpaper_preview_buttons_elevation"
+        android:foreground="@drawable/wallpaper_control_button_info"
+        android:textOff=""
+        android:textOn="" />
+
+    <FrameLayout
+        android:id="@+id/download_button"
+        android:layout_width="@dimen/wallpaper_control_button_size"
+        android:layout_height="@dimen/wallpaper_control_button_size">
+        <ToggleButton
+            android:id="@+id/download_button_toggle"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:background="@android:color/transparent"
+            android:contentDescription="@string/bottom_action_bar_download"
+            android:foreground="@drawable/wallpaper_control_button_download"
+            android:textOff=""
+            android:textOn="" />
+
+        <FrameLayout
+            android:id="@+id/download_button_progress"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:background="@drawable/wallpaper_control_button_off_background"
+            android:visibility="gone">
+            <ProgressBar
+                android:layout_width="match_parent"
+                android:layout_height="match_parent"
+                android:indeterminateTint="?android:textColorTertiary"/>
+        </FrameLayout>
+    </FrameLayout>
+
+    <ToggleButton
+        android:id="@+id/delete_button"
+        android:layout_width="@dimen/wallpaper_control_button_size"
+        android:layout_height="@dimen/wallpaper_control_button_size"
+        android:background="@android:color/transparent"
+        android:contentDescription="@string/delete_live_wallpaper"
+        android:elevation="@dimen/wallpaper_preview_buttons_elevation"
+        android:foreground="@drawable/wallpaper_control_button_delete"
+        android:textOff=""
+        android:textOn="" />
+
+    <ToggleButton
+        android:id="@+id/edit_button"
+        android:layout_width="@dimen/wallpaper_control_button_size"
+        android:layout_height="@dimen/wallpaper_control_button_size"
+        android:background="@android:color/transparent"
+        android:contentDescription="@string/edit_live_wallpaper"
+        android:elevation="@dimen/wallpaper_preview_buttons_elevation"
+        android:foreground="@drawable/wallpaper_control_button_edit"
+        android:textOff=""
+        android:textOn="" />
+
+    <ToggleButton
+        android:id="@+id/customize_button"
+        android:layout_width="@dimen/wallpaper_control_button_size"
+        android:layout_height="@dimen/wallpaper_control_button_size"
+        android:background="@android:color/transparent"
+        android:contentDescription="@string/tab_customize"
+        android:elevation="@dimen/wallpaper_preview_buttons_elevation"
+        android:foreground="@drawable/wallpaper_control_button_customize"
+        android:textOff=""
+        android:textOn="" />
+
+    <ToggleButton
+        android:id="@+id/effects_button"
+        android:layout_width="@dimen/wallpaper_control_button_size"
+        android:layout_height="@dimen/wallpaper_control_button_size"
+        android:background="@android:color/transparent"
+        android:contentDescription="@string/tab_effects"
+        android:elevation="@dimen/wallpaper_preview_buttons_elevation"
+        android:foreground="@drawable/wallpaper_control_button_effect"
+        android:textOff=""
+        android:textOn="" />
+
+    <ToggleButton
+        android:id="@+id/share_button"
+        android:layout_width="@dimen/wallpaper_control_button_size"
+        android:layout_height="@dimen/wallpaper_control_button_size"
+        android:background="@android:color/transparent"
+        android:contentDescription="@string/tab_share"
+        android:foreground="@drawable/wallpaper_control_button_share"
+        android:textOff=""
+        android:textOn="" />
+</LinearLayout>
+
diff --git a/res/layout/preview_card.xml b/res/layout/preview_card.xml
deleted file mode 100644
index 3a29f0b7..00000000
--- a/res/layout/preview_card.xml
+++ /dev/null
@@ -1,51 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
-     Copyright (C) 2024 The Android Open Source Project
-
-     Licensed under the Apache License, Version 2.0 (the "License");
-     you may not use this file except in compliance with the License.
-     You may obtain a copy of the License at
-
-          http://www.apache.org/licenses/LICENSE-2.0
-
-     Unless required by applicable law or agreed to in writing, software
-     distributed under the License is distributed on an "AS IS" BASIS,
-     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-     See the License for the specific language governing permissions and
-     limitations under the License.
--->
-<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
-    android:layout_width="match_parent"
-    android:layout_height="match_parent"
-    android:clipChildren="false"
-    android:clipToPadding="false">
-
-    <com.android.wallpaper.picker.DisplayAspectRatioFrameLayout
-        android:layout_width="match_parent"
-        android:layout_height="match_parent"
-        android:clipChildren="false">
-
-        <com.android.wallpaper.picker.customization.ui.view.PreviewCardView
-            android:id="@+id/preview_card"
-            style="@style/FullContentPreviewCard"
-            android:layout_width="match_parent"
-            android:layout_height="match_parent"
-            android:clipChildren="true"
-            android:layout_gravity="center"
-            android:contentDescription="@string/wallpaper_preview_card_content_description">
-
-            <SurfaceView
-                android:id="@+id/wallpaper_surface"
-                android:layout_width="match_parent"
-                android:layout_height="match_parent"
-                android:visibility="gone" />
-
-            <SurfaceView
-                android:id="@+id/workspace_surface"
-                android:layout_width="match_parent"
-                android:layout_height="match_parent"
-                android:importantForAccessibility="noHideDescendants"
-                android:visibility="gone" />
-        </com.android.wallpaper.picker.customization.ui.view.PreviewCardView>
-    </com.android.wallpaper.picker.DisplayAspectRatioFrameLayout>
-</FrameLayout>
diff --git a/res/layout/small_preview_foldable_card_view.xml b/res/layout/small_preview_foldable_card_view.xml
index bf6379a0..871f64f4 100644
--- a/res/layout/small_preview_foldable_card_view.xml
+++ b/res/layout/small_preview_foldable_card_view.xml
@@ -40,7 +40,7 @@
     </com.android.wallpaper.picker.preview.ui.view.DualDisplayAspectRatioLayout>
 
     <ViewStub
-        android:id="@+id/tooltip_stub"
+        android:id="@+id/small_preview_tooltip_stub"
         android:inflatedId="@+id/tooltip"
         android:layout="@layout/tooltip_small_preview"
         android:layout_height="wrap_content"
diff --git a/res/layout/small_preview_foldable_card_view2.xml b/res/layout/small_preview_foldable_card_view2.xml
new file mode 100644
index 00000000..76911911
--- /dev/null
+++ b/res/layout/small_preview_foldable_card_view2.xml
@@ -0,0 +1,50 @@
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
+  ~
+  -->
+<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:clipChildren="false">
+
+    <com.android.wallpaper.picker.preview.ui.view.DualDisplayAspectRatioLayout
+        android:id="@+id/dual_preview"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:layout_gravity="center"
+        android:orientation="horizontal"
+        android:clipChildren="false">
+
+        <include
+            android:id="@+id/small_preview_folded_preview"
+            layout="@layout/wallpaper_dual_preview_card"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"/>
+
+        <include
+            android:id="@+id/small_preview_unfolded_preview"
+            layout="@layout/wallpaper_dual_preview_card"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"/>
+    </com.android.wallpaper.picker.preview.ui.view.DualDisplayAspectRatioLayout>
+
+    <ViewStub
+        android:id="@+id/small_preview_tooltip_stub"
+        android:inflatedId="@+id/tooltip"
+        android:layout="@layout/tooltip_small_preview"
+        android:layout_height="wrap_content"
+        android:layout_width="wrap_content"
+        android:layout_gravity="center"/>
+</FrameLayout>
\ No newline at end of file
diff --git a/res/layout/small_preview_handheld_card_view.xml b/res/layout/small_preview_handheld_card_view.xml
index d0abc7f1..b2bc1784 100644
--- a/res/layout/small_preview_handheld_card_view.xml
+++ b/res/layout/small_preview_handheld_card_view.xml
@@ -36,7 +36,7 @@ the header bar -->
     </com.android.wallpaper.picker.DisplayAspectRatioFrameLayout>
 
     <ViewStub
-        android:id="@+id/tooltip_stub"
+        android:id="@+id/small_preview_tooltip_stub"
         android:inflatedId="@+id/tooltip"
         android:layout="@layout/tooltip_small_preview"
         android:layout_height="wrap_content"
diff --git a/res/layout/small_preview_handheld_card_view2.xml b/res/layout/small_preview_handheld_card_view2.xml
new file mode 100644
index 00000000..7b4d6927
--- /dev/null
+++ b/res/layout/small_preview_handheld_card_view2.xml
@@ -0,0 +1,36 @@
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
+  ~
+  -->
+<!-- Set clipToPadding to false so that during transition scaling, child card view is not clipped to
+the header bar -->
+<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:clipChildren="false"
+    android:clipToPadding="false">
+
+    <include
+        android:id="@+id/preview"
+        layout="@layout/wallpaper_preview_card2" />
+
+    <ViewStub
+        android:id="@+id/small_preview_tooltip_stub"
+        android:inflatedId="@+id/tooltip"
+        android:layout="@layout/tooltip_small_preview"
+        android:layout_height="wrap_content"
+        android:layout_width="wrap_content"
+        android:layout_gravity="center"/>
+</FrameLayout>
diff --git a/res/layout/small_wallpaper_preview_card.xml b/res/layout/small_wallpaper_preview_card.xml
index 2ff7eb6f..9dc86cbc 100644
--- a/res/layout/small_wallpaper_preview_card.xml
+++ b/res/layout/small_wallpaper_preview_card.xml
@@ -15,7 +15,6 @@
      limitations under the License.
 -->
 <FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
-    android:id="@+id/wallpaper_preview_crop"
     android:layout_width="match_parent"
     android:layout_height="match_parent">
 
@@ -30,14 +29,12 @@
         <SurfaceView
             android:id="@+id/wallpaper_surface"
             android:layout_width="match_parent"
-            android:layout_height="match_parent"
-            android:visibility="gone"/>
+            android:layout_height="match_parent"/>
 
         <SurfaceView
             android:id="@+id/workspace_surface"
             android:layout_width="match_parent"
             android:layout_height="match_parent"
-            android:importantForAccessibility="noHideDescendants"
-            android:visibility="gone"/>
+            android:importantForAccessibility="noHideDescendants"/>
     </androidx.cardview.widget.CardView>
 </FrameLayout>
diff --git a/res/layout/wallpaper_dual_preview_card.xml b/res/layout/wallpaper_dual_preview_card.xml
new file mode 100644
index 00000000..71113fb9
--- /dev/null
+++ b/res/layout/wallpaper_dual_preview_card.xml
@@ -0,0 +1,52 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<com.android.wallpaper.picker.preview.ui.view.FullPreviewFrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/wallpaper_preview_crop"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:clipChildren="false">
+
+    <androidx.cardview.widget.CardView
+        android:id="@+id/preview_card"
+        android:importantForAccessibility="no"
+        style="@style/FullContentPreviewCard"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:clipChildren="true"
+        android:contentDescription="@string/wallpaper_preview_card_content_description">
+
+        <com.android.wallpaper.picker.common.preview.ui.view.CustomizationSurfaceView
+            android:id="@+id/wallpaper_surface"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"/>
+
+        <com.android.wallpaper.picker.common.preview.ui.view.CustomizationSurfaceView
+            android:id="@+id/workspace_surface"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:importantForAccessibility="noHideDescendants"/>
+
+        <View
+            android:id="@+id/preview_scrim"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:background="@drawable/gradient_black_scrim"
+            android:importantForAccessibility="noHideDescendants"
+            android:visibility="gone" />
+    </androidx.cardview.widget.CardView>
+</com.android.wallpaper.picker.preview.ui.view.FullPreviewFrameLayout>
diff --git a/res/layout/wallpaper_preview_card2.xml b/res/layout/wallpaper_preview_card2.xml
new file mode 100644
index 00000000..7497981f
--- /dev/null
+++ b/res/layout/wallpaper_preview_card2.xml
@@ -0,0 +1,58 @@
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
+<com.android.wallpaper.picker.DisplayAspectRatioFrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:clipChildren="false">
+
+    <com.android.wallpaper.picker.preview.ui.view.FullPreviewFrameLayout
+        android:id="@+id/wallpaper_preview_crop"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:layout_gravity="center"
+        android:clipChildren="false">
+
+        <com.android.wallpaper.picker.customization.ui.view.PreviewCardView
+            android:id="@+id/preview_card"
+            android:importantForAccessibility="no"
+            style="@style/FullContentPreviewCard"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:clipChildren="true"
+            android:contentDescription="@string/wallpaper_preview_card_content_description">
+
+            <com.android.wallpaper.picker.common.preview.ui.view.CustomizationSurfaceView
+                android:id="@+id/wallpaper_surface"
+                android:layout_width="match_parent"
+                android:layout_height="match_parent" />
+
+            <com.android.wallpaper.picker.common.preview.ui.view.CustomizationSurfaceView
+                android:id="@+id/workspace_surface"
+                android:layout_width="match_parent"
+                android:layout_height="match_parent"
+                android:importantForAccessibility="noHideDescendants" />
+
+            <View
+                android:id="@+id/preview_scrim"
+                android:layout_width="match_parent"
+                android:layout_height="match_parent"
+                android:background="@drawable/gradient_black_scrim"
+                android:importantForAccessibility="noHideDescendants"
+                android:visibility="gone" />
+        </com.android.wallpaper.picker.customization.ui.view.PreviewCardView>
+    </com.android.wallpaper.picker.preview.ui.view.FullPreviewFrameLayout>
+</com.android.wallpaper.picker.DisplayAspectRatioFrameLayout>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index bd37771c..5b7fbfd4 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -21,8 +21,7 @@
     <!-- no translation found for app_name (8773648973927541493) -->
     <skip />
     <string name="select_wallpaper_label" msgid="6989581259339646085">"Wallpaper categories"</string>
-    <!-- no translation found for set_wallpaper_button_text (5445978864530156290) -->
-    <skip />
+    <string name="set_wallpaper_button_text" msgid="5445978864530156290">"Set wallpaper"</string>
     <string name="set_wallpaper_progress_message" msgid="7986528287618716715">"Setting wallpaper…"</string>
     <string name="try_again" msgid="8278874823700921234">"Try again"</string>
     <string name="set_wallpaper_error_message" msgid="6819986999041085130">"Unable to set wallpaper."</string>
@@ -30,10 +29,8 @@
     <string name="static_wallpaper_presentation_mode_message" msgid="417940227049360906">"Currently set"</string>
     <string name="rotating_wallpaper_presentation_mode_message" msgid="3361676041605733288">"Daily wallpaper"</string>
     <string name="wallpaper_destination_both" msgid="1124197176741944063">"Home &amp; Lock screen"</string>
-    <!-- no translation found for choose_a_wallpaper_section_title (1009823506890453891) -->
-    <skip />
-    <!-- no translation found for creative_wallpaper_title (3581650238648981372) -->
-    <skip />
+    <string name="choose_a_wallpaper_section_title" msgid="1009823506890453891">"Choose a Wallpaper"</string>
+    <string name="creative_wallpaper_title" msgid="3581650238648981372">"Create wallpaper"</string>
     <string name="home_screen_message" msgid="106444102822522813">"Home screen"</string>
     <string name="lock_screen_message" msgid="1534506081955058013">"Lock screen"</string>
     <string name="home_and_lock_short_label" msgid="2937922943541927983">"Home &amp; Lock"</string>
@@ -43,7 +40,7 @@
     <string name="set_wallpaper_both_destination" msgid="2536004558738350775">"Home and lock screens"</string>
     <string name="no_backup_image_wallpaper_label" msgid="6316627676107284851">"Rotating Image Wallpaper"</string>
     <string name="permission_needed_explanation" msgid="139166837541426823">"To display the current wallpaper here, <xliff:g id="APP_NAME">%1$s</xliff:g> needs access to your device\'s storage."</string>
-    <string name="permission_needed_explanation_go_to_settings" msgid="3923551582092599609">"To display the current wallpaper here, Wallpapers needs access to your device’s storage.\n\nTo change this setting, go to the Permissions area of the Wallpapers’ app info."</string>
+    <string name="permission_needed_explanation_go_to_settings" msgid="3923551582092599609">"To display the current wallpaper here, Wallpapers needs access to your device’s storage.\n\nTo change this setting, go to the Permissions area of Wallpapers’ app info."</string>
     <string name="permission_needed_allow_access_button_label" msgid="1943133660612924306">"Allow access"</string>
     <string name="no_backup_image_wallpaper_description" msgid="8303268619408738057">"Live wallpaper service for rotating wallpapers"</string>
     <string name="daily_refresh_tile_title" msgid="3270456074558525091">"Daily wallpaper"</string>
@@ -69,16 +66,11 @@
     <string name="explore_lock_screen" msgid="268938342103703665">"Explore lock screen wallpaper"</string>
     <string name="refresh_daily_wallpaper_home_content_description" msgid="2770445044556164259">"Refresh daily home screen wallpaper"</string>
     <string name="refresh_daily_wallpaper_content_description" msgid="4362142658237147583">"Refresh daily wallpaper"</string>
-    <!-- no translation found for preview_screen_description (3386387053327775919) -->
-    <skip />
-    <!-- no translation found for preview_screen_description_editable (506875963019888699) -->
-    <skip />
-    <!-- no translation found for folded_device_state_description (4972608448265616264) -->
-    <skip />
-    <!-- no translation found for unfolded_device_state_description (3071975681472460627) -->
-    <skip />
-    <!-- no translation found for full_preview_check_button_description (700484353763952975) -->
-    <skip />
+    <string name="preview_screen_description" msgid="3386387053327775919">"Wallpaper preview screen"</string>
+    <string name="preview_screen_description_editable" msgid="506875963019888699">"Wallpaper preview screen %1$s. Use two fingers to pan and zoom."</string>
+    <string name="folded_device_state_description" msgid="4972608448265616264">"Folded"</string>
+    <string name="unfolded_device_state_description" msgid="3071975681472460627">"Unfolded"</string>
+    <string name="full_preview_check_button_description" msgid="700484353763952975">"Done editing wallpaper"</string>
     <string name="refreshing_daily_wallpaper_dialog_message" msgid="1975910873362855761">"Refreshing daily wallpaper…"</string>
     <string name="refresh_daily_wallpaper_failed_message" msgid="4749879993812557166">"Failed to refresh daily wallpaper. Please check your network connection and try again."</string>
     <string name="on_device_wallpapers_category_title" msgid="805819102071369004">"On-device wallpapers"</string>
@@ -89,89 +81,64 @@
     <string name="my_photos_generic_wallpaper_title" msgid="7002867526154631172">"My photo"</string>
     <string name="fallback_wallpaper_title" msgid="6154655421012506001">"Wallpaper"</string>
     <string name="app_not_found" msgid="4431461707854088231">"App isn\'t installed."</string>
-    <string name="center_wallpaper_position" msgid="4166894762352288883">"Centre"</string>
-    <string name="center_crop_wallpaper_position" msgid="1681980019815343348">"Centre crop"</string>
+    <string name="center_wallpaper_position" msgid="4166894762352288883">"Center"</string>
+    <string name="center_crop_wallpaper_position" msgid="1681980019815343348">"Center crop"</string>
     <string name="stretch_wallpaper_position" msgid="5002680983147456935">"Stretch"</string>
     <string name="preview" msgid="1774602101743861071">"Preview"</string>
     <string name="tab_info" msgid="818614080690111416">"Info"</string>
-    <string name="tab_customize" msgid="2533745409174959960">"Customise"</string>
+    <string name="tab_customize" msgid="2533745409174959960">"Customize"</string>
     <string name="tab_effects" msgid="3213606157589233901">"Effects"</string>
-    <!-- no translation found for tab_share (6676269624804601227) -->
-    <skip />
+    <string name="tab_share" msgid="6676269624804601227">"Share"</string>
     <string name="my_photos" msgid="8613021349284084982">"My Photos"</string>
     <string name="configure_wallpaper" msgid="849882179182976621">"Settings…"</string>
     <string name="delete_live_wallpaper" msgid="589212696102662329">"Delete"</string>
-    <!-- no translation found for edit_live_wallpaper (3132060073690558045) -->
-    <skip />
-    <!-- no translation found for delete_wallpaper_confirmation (1905114562243802354) -->
-    <skip />
-    <!-- no translation found for bottom_action_bar_back (2620581414970740784) -->
-    <skip />
+    <string name="edit_live_wallpaper" msgid="3132060073690558045">"Edit"</string>
+    <string name="delete_wallpaper_confirmation" msgid="1905114562243802354">"Delete this wallpaper from your device?"</string>
+    <string name="bottom_action_bar_back" msgid="2620581414970740784">"Navigate up"</string>
     <string name="bottom_action_bar_edit" msgid="1214742990893082138">"Edit"</string>
     <string name="bottom_action_bar_download" msgid="3983122338076389421">"Download"</string>
-    <!-- no translation found for download_effects (2772742927165716701) -->
-    <skip />
-    <string name="bottom_action_bar_slideshow_wallpaper" msgid="509770525179533154">"Slideshow wallpaper"</string>
+    <string name="download_effects" msgid="2772742927165716701">"Download effects"</string>
+    <string name="bottom_action_bar_slideshow_wallpaper" msgid="509770525179533154">"Slideshow Wallpaper"</string>
     <string name="bottom_action_bar_apply" msgid="2983308349819178932">"Apply"</string>
     <string name="accessibility_preview_pager" msgid="1839869637405028575">"Page <xliff:g id="ID_1">%1$d</xliff:g> of <xliff:g id="ID_2">%2$d</xliff:g>"</string>
     <string name="next_page_content_description" msgid="6268461446679584152">"Next"</string>
     <string name="previous_page_content_description" msgid="1138597031571078429">"Previous"</string>
     <string name="wallpaper_title" msgid="6754214682228331092">"Wallpaper"</string>
     <string name="wallpaper_preview_card_content_description" msgid="6049261033541034584">"Wallpaper preview"</string>
-    <!-- no translation found for wallpaper_preview_card_content_description_editable (3111763100515242340) -->
-    <skip />
-    <!-- no translation found for lock_wallpaper_preview_card_content_description (5236839857695985498) -->
-    <skip />
-    <!-- no translation found for home_wallpaper_preview_card_content_description (4059418716070821630) -->
-    <skip />
+    <string name="wallpaper_preview_card_content_description_editable" msgid="3111763100515242340">"Wallpaper preview %1$s, tap to edit your photo"</string>
+    <string name="lock_wallpaper_preview_card_content_description" msgid="5236839857695985498">"Lock screen wallpaper preview"</string>
+    <string name="home_wallpaper_preview_card_content_description" msgid="4059418716070821630">"Home screen wallpaper preview"</string>
     <string name="collection_not_exist_msg" msgid="3504852962885064842">"The collection doesn\'t exist"</string>
-    <!-- no translation found for wallpaper_exit_split_screen (1928870664619591636) -->
-    <skip />
-    <!-- no translation found for set_wallpaper_dialog_set_button (5760149969510325088) -->
-    <skip />
+    <string name="wallpaper_exit_split_screen" msgid="1928870664619591636">"Please exit split screen mode and try again"</string>
+    <string name="set_wallpaper_dialog_set_button" msgid="5760149969510325088">"Set"</string>
     <string name="cancel" msgid="4970902691067201584">"Cancel"</string>
-    <string name="hide_ui_preview_text" msgid="6766076482511252295">"Hide UI preview"</string>
-    <string name="hint_hide_ui_preview" msgid="4527603797714586070">"UI is hidden in preview. Double-tap to unhide"</string>
-    <string name="show_ui_preview_text" msgid="5993063062417070806">"Show UI preview"</string>
-    <!-- no translation found for hide_preview_controls_content_description (894958599274977655) -->
-    <skip />
-    <!-- no translation found for hide_preview_controls_action (3419260118386783295) -->
-    <skip />
-    <!-- no translation found for show_preview_controls_content_description (908147864005440602) -->
-    <skip />
-    <!-- no translation found for show_preview_controls_action (7700775001986890400) -->
-    <skip />
-    <!-- no translation found for hide_wallpaper_info_action (6572492484253895374) -->
-    <skip />
-    <string name="hint_show_ui_preview" msgid="2744155435325318349">"UI is displayed in preview. Double-tap to hide"</string>
+    <string name="hide_ui_preview_text" msgid="6766076482511252295">"Hide UI Preview"</string>
+    <string name="hint_hide_ui_preview" msgid="4527603797714586070">"UI is hidden in preview. Double tap to unhide"</string>
+    <string name="show_ui_preview_text" msgid="5993063062417070806">"Show UI Preview"</string>
+    <string name="hide_preview_controls_content_description" msgid="894958599274977655">"Preview controls are displayed. Double tap to hide"</string>
+    <string name="hide_preview_controls_action" msgid="3419260118386783295">"Hide preview controls"</string>
+    <string name="show_preview_controls_content_description" msgid="908147864005440602">"Preview controls are hidden. Double tap to show"</string>
+    <string name="show_preview_controls_action" msgid="7700775001986890400">"Show preview controls"</string>
+    <string name="hide_wallpaper_info_action" msgid="6572492484253895374">"Hide wallpaper info"</string>
+    <string name="hint_show_ui_preview" msgid="2744155435325318349">"UI is displayed in preview. Double tap to hide"</string>
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Change wallpaper"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Lockscreen wallpaper preview"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Apply"</string>
-    <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Customise hidden"</string>
-    <string name="accessibility_customize_shown" msgid="590964727831547651">"Customise shown"</string>
+    <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Customize hidden"</string>
+    <string name="accessibility_customize_shown" msgid="590964727831547651">"Customize shown"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Info hidden"</string>
     <string name="accessibility_info_shown" msgid="6626025722456105632">"Info shown"</string>
     <string name="settings_snackbar_description" msgid="890168814524778486">"Please enable files and media in settings."</string>
     <string name="settings_snackbar_enable" msgid="5992112808061426068">"Enable"</string>
-    <string name="open_my_photos" msgid="4107196465713868381">"Open My photos"</string>
-    <!-- no translation found for lock_screen_tab (6672930765010407652) -->
-    <skip />
-    <!-- no translation found for home_screen_tab (1080445697837877526) -->
-    <skip />
-    <!-- no translation found for reset (4945445169532850631) -->
-    <skip />
-    <!-- no translation found for reset_confirmation_dialog_title (3391905685838213712) -->
-    <skip />
-    <!-- no translation found for reset_confirmation_dialog_message (888669268626289603) -->
-    <skip />
-    <!-- no translation found for more_wallpapers (8116268433411881705) -->
-    <skip />
-    <!-- no translation found for recents_wallpaper_label (8653165542635660222) -->
-    <skip />
-    <!-- no translation found for default_wallpaper_title (2541071182656978180) -->
-    <skip />
-    <!-- no translation found for small_preview_tooltip (1920430079013352071) -->
-    <skip />
-    <!-- no translation found for full_preview_tooltip (4648994028015322759) -->
-    <skip />
+    <string name="open_my_photos" msgid="4107196465713868381">"Open My Photos"</string>
+    <string name="lock_screen_tab" msgid="6672930765010407652">"Lock screen"</string>
+    <string name="home_screen_tab" msgid="1080445697837877526">"Home screen"</string>
+    <string name="reset" msgid="4945445169532850631">"Reset"</string>
+    <string name="reset_confirmation_dialog_title" msgid="3391905685838213712">"Reset changes?"</string>
+    <string name="reset_confirmation_dialog_message" msgid="888669268626289603">"Your changes won\'t be saved"</string>
+    <string name="more_wallpapers" msgid="8116268433411881705">"More wallpapers"</string>
+    <string name="recents_wallpaper_label" msgid="8653165542635660222">"%1$s, %2$d"</string>
+    <string name="default_wallpaper_title" msgid="2541071182656978180">"Wallpaper"</string>
+    <string name="small_preview_tooltip" msgid="1920430079013352071">"Tap to edit your photo"</string>
+    <string name="full_preview_tooltip" msgid="4648994028015322759">"Adjust the position, scale, and angle of your photos"</string>
 </resources>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 722cd7e3..77b4d510 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -58,10 +58,10 @@
     <string name="wallpaper_disabled_by_administrator_message" msgid="1551430406714747884">"تنظیم کاغذدیواری توسط سرپرست دستگاهتان غیرفعال شده است"</string>
     <string name="wallpaper_set_successfully_message" msgid="2958998799111688578">"کاغذدیواری باموفقیت تنظیم شد"</string>
     <string name="wallpapers_unavailable_offline_message" msgid="8136405438621689532">"برای دیدن کاغذدیواری‌ها به اتصال اینترنت نیاز دارید. لطفاً به اینترنت متصل شوید و دوباره امتحان کنید."</string>
-    <string name="currently_set_home_wallpaper_thumbnail" msgid="4022381436821898917">"تصویر کوچک کاغذ‌دیواری صفحه اصلی درحال حاضر تنظیم شده است"</string>
-    <string name="currently_set_lock_wallpaper_thumbnail" msgid="2094209303934569997">"تصویر کوچک کاغذ‌دیواری صفحه در حالت قفل درحال حاضر تنظیم شده است"</string>
-    <string name="currently_set_wallpaper_thumbnail" msgid="8651887838745545107">"تصویر کوچک کاغذ‌دیواری درحال حاضر تنظیم شده است"</string>
-    <string name="wallpaper_thumbnail" msgid="569931475923605974">"تصویر کوچک کاغذ‌دیواری"</string>
+    <string name="currently_set_home_wallpaper_thumbnail" msgid="4022381436821898917">"ریزعکس کاغذ‌دیواری صفحه اصلی درحال حاضر تنظیم شده است"</string>
+    <string name="currently_set_lock_wallpaper_thumbnail" msgid="2094209303934569997">"ریزعکس کاغذ‌دیواری صفحه در حالت قفل درحال حاضر تنظیم شده است"</string>
+    <string name="currently_set_wallpaper_thumbnail" msgid="8651887838745545107">"ریزعکس کاغذ‌دیواری درحال حاضر تنظیم شده است"</string>
+    <string name="wallpaper_thumbnail" msgid="569931475923605974">"ریزعکس کاغذ‌دیواری"</string>
     <string name="explore_home_screen" msgid="8756346794535765482">"کاوش کاغذ‌دیواری صفحه اصلی"</string>
     <string name="explore_lock_screen" msgid="268938342103703665">"کاوش کاغذ‌دیواری صفحه در حالت قفل"</string>
     <string name="refresh_daily_wallpaper_home_content_description" msgid="2770445044556164259">"بازآوری کاغذدیواری روزانه در صفحه اصلی"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 37363949..0a3ff693 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -80,7 +80,7 @@
     <string name="my_photos_category_title" msgid="4294567122144565273">"ನನ್ನ ಫೋಟೋಗಳು"</string>
     <string name="my_photos_generic_wallpaper_title" msgid="7002867526154631172">"ನನ್ನ ಫೋಟೋ"</string>
     <string name="fallback_wallpaper_title" msgid="6154655421012506001">"ವಾಲ್‌ಪೇಪರ್‌"</string>
-    <string name="app_not_found" msgid="4431461707854088231">"ಅಪ್ಲಿಕೇಶನ್‌ ಅನ್ನು ಇನ್‌ಸ್ಟಾಲ್‌ ಮಾಡಲಾಗಿಲ್ಲ"</string>
+    <string name="app_not_found" msgid="4431461707854088231">"ಆ್ಯಪ್ ಅನ್ನು ಇನ್‌ಸ್ಟಾಲ್‌ ಮಾಡಲಾಗಿಲ್ಲ."</string>
     <string name="center_wallpaper_position" msgid="4166894762352288883">"ಮಧ್ಯ"</string>
     <string name="center_crop_wallpaper_position" msgid="1681980019815343348">"ಮಧ್ಯಕ್ಕೆ ಕ್ರಾಪ್ ಮಾಡಿ"</string>
     <string name="stretch_wallpaper_position" msgid="5002680983147456935">"ವಿಸ್ತರಿಸಿ"</string>
diff --git a/res/values-night/colors.xml b/res/values-night/colors.xml
index 7d71eae5..1b070cda 100644
--- a/res/values-night/colors.xml
+++ b/res/values-night/colors.xml
@@ -34,6 +34,7 @@
     <color name="system_surface_container_highest">@android:color/system_surface_container_highest_dark</color>
     <color name="system_surface_bright">@android:color/system_surface_bright_dark</color>
     <color name="system_outline">@android:color/system_outline_dark</color>
+    <color name="system_secondary_container">@android:color/system_secondary_container_dark</color>
 
     <!-- UI elements with Dark/Light Theme Variances -->
     <color name="option_item_background">@color/system_surface_bright</color>
@@ -41,4 +42,6 @@
     <color name="connected_sections_background">@color/system_surface_container_high</color>
     <color name="picker_section_icon_background">@color/system_surface_container_high</color>
     <color name="picker_fragment_background">@color/system_surface_container_high</color>
+
+    <color name="ripple_material">#33ffffff</color>
 </resources>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 3c0a8481..f3534e7b 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -30,7 +30,7 @@
     <string name="rotating_wallpaper_presentation_mode_message" msgid="3361676041605733288">"Обои на каждый день"</string>
     <string name="wallpaper_destination_both" msgid="1124197176741944063">"Главный экран и заблокированный экран"</string>
     <string name="choose_a_wallpaper_section_title" msgid="1009823506890453891">"Выбрать обои"</string>
-    <string name="creative_wallpaper_title" msgid="3581650238648981372">"Создание обоев"</string>
+    <string name="creative_wallpaper_title" msgid="3581650238648981372">"Создать обои"</string>
     <string name="home_screen_message" msgid="106444102822522813">"Главный экран"</string>
     <string name="lock_screen_message" msgid="1534506081955058013">"Заблокированный экран"</string>
     <string name="home_and_lock_short_label" msgid="2937922943541927983">"Оба экрана"</string>
diff --git a/res/values/colors.xml b/res/values/colors.xml
index ddc60918..152651f6 100755
--- a/res/values/colors.xml
+++ b/res/values/colors.xml
@@ -72,6 +72,7 @@
     <color name="system_surface_container_highest">@android:color/system_surface_container_highest_light</color>
     <color name="system_surface_bright">@android:color/system_surface_bright_light</color>
     <color name="system_outline">@android:color/system_outline_light</color>
+    <color name="system_secondary_container">@android:color/system_secondary_container_light</color>
 
     <!-- UI elements with Dark/Light Theme Variances -->
     <color name="option_item_background">@color/system_surface_container_high</color>
@@ -79,4 +80,6 @@
     <color name="connected_sections_background">@color/system_surface_bright</color>
     <color name="picker_section_icon_background">@color/system_surface_bright</color>
     <color name="picker_fragment_background">@color/system_surface_bright</color>
+
+    <color name="ripple_material">#1f000000</color>
 </resources>
diff --git a/res/values/dimens.xml b/res/values/dimens.xml
index ddd11387..287ba05b 100755
--- a/res/values/dimens.xml
+++ b/res/values/dimens.xml
@@ -14,6 +14,8 @@
      limitations under the License.
 -->
 <resources>
+    <dimen name="accessibility_min_height">48dp</dimen>
+
     <!-- Default screen margins, per the Android Design guidelines. -->
     <dimen name="grid_padding">4dp</dimen>
     <dimen name="grid_padding_desktop">8dp</dimen>
@@ -27,6 +29,7 @@
     <dimen name="grid_item_category_label_minimum_height">16dp</dimen>
     <dimen name="grid_item_category_padding_horizontal">6dp</dimen>
     <dimen name="grid_item_category_padding_bottom">12dp</dimen>
+    <dimen name="grid_item_category_title_margin_bottom">10dp</dimen>
     <dimen name="grid_tile_aspect_height">340dp</dimen>
     <dimen name="grid_tile_aspect_width">182dp</dimen>
     <dimen name="category_grid_edge_space">18dp</dimen>
@@ -396,12 +399,23 @@
     <dimen name="customization_option_entry_corner_radius_large">28dp</dimen>
     <dimen name="customization_option_entry_corner_radius_small">4dp</dimen>
     <dimen name="customization_option_entry_divider_height">2dp</dimen>
-    <dimen name="customization_option_entry_more_wallpapers_min_height">48dp</dimen>
     <dimen name="customization_option_entry_more_wallpapers_drawable_padding">12dp</dimen>
     <dimen name="customization_option_entry_horizontal_padding">16dp</dimen>
     <dimen name="customization_option_entry_vertical_padding_large">16dp</dimen>
     <dimen name="customization_option_entry_vertical_padding">12dp</dimen>
     <dimen name="customization_option_entry_text_margin_end">16dp</dimen>
     <dimen name="customization_option_entry_icon_size">60dp</dimen>
+    <dimen name="customization_option_entry_icon_padding">8dp</dimen>
     <dimen name="preview_corner_radius">32dp</dimen>
+    <dimen name="apply_button_end_margin">16dp</dimen>
+    <dimen name="nav_button_start_margin">16dp</dimen>
+
+    <!-- Dimensions for the floating tab toolbar -->
+    <dimen name="floating_tab_toolbar_padding">8dp</dimen>
+    <dimen name="floating_tab_toolbar_tab_horizontal_padding">16dp</dimen>
+    <dimen name="floating_tab_toolbar_tab_vertical_padding">10dp</dimen>
+    <dimen name="floating_tab_toolbar_tab_icon_size">20dp</dimen>
+    <dimen name="floating_tab_toolbar_tab_icon_margin_end">8dp</dimen>
+    <dimen name="floating_tab_toolbar_tab_divider_width">8dp</dimen>
+    <dimen name="floating_tab_toolbar_text_max_width">140dp</dimen>
 </resources>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 1a041035..85cd4bd6 100755
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -551,4 +551,5 @@
     -->
     <string name="full_preview_tooltip">Adjust the position, scale, and angle of your photos</string>
 
+    <string name="tab_placeholder_text" translatable="false">Tab</string>
 </resources>
diff --git a/res/values/styles.xml b/res/values/styles.xml
index 8c52c85b..7d9e9f2a 100755
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -42,6 +42,33 @@
         <item name="android:windowDrawsSystemBarBackgrounds">true</item>
     </style>
 
+    <!-- Main themes for the new customization picker UI -->
+    <style name="WallpaperTheme2" parent="@android:style/Theme.DeviceDefault.Settings">
+        <item name="colorPrimary">?android:colorPrimary</item>
+        <item name="colorControlActivated">?attr/colorPrimary</item>
+        <item name="android:statusBarColor">?attr/colorPrimary</item>
+        <item name="android:navigationBarColor">@android:color/transparent</item>
+        <item name="android:navigationBarDividerColor">@android:color/transparent</item>
+        <item name="android:windowLightStatusBar">false</item>
+
+        <item name="actionBarSize">?android:attr/actionBarSize</item>
+        <item name="homeAsUpIndicator">@drawable/material_ic_arrow_back_black_24</item>
+
+        <item name="selectableItemBackground">?android:attr/selectableItemBackground</item>
+        <item name="dialogPreferredPadding">24dp</item>
+        <item name="colorControlHighlight">@color/ripple_material_dark</item>
+        <item name="windowActionBar">false</item>
+        <item name="windowNoTitle">true</item>
+        <item name="toolbarNavigationButtonStyle">@android:style/Widget.Toolbar.Button.Navigation
+        </item>
+        <item name="buttonStyle">@style/Widget.AppCompat.Button</item>
+
+        <item name="android:windowActionBar">false</item>
+        <item name="android:windowNoTitle">true</item>
+        <item name="android:fitsSystemWindows">false</item>
+        <item name="android:windowDrawsSystemBarBackgrounds">true</item>
+    </style>
+
     <style name="WallpaperTheme.NoBackground">
         <item name="android:windowBackground">@android:color/transparent</item>
         <item name="android:windowContentOverlay">@null</item>
diff --git a/res/xml/customization_picker_layout_scene.xml b/res/xml/customization_picker_layout_scene.xml
index ee04b8ad..4237e358 100644
--- a/res/xml/customization_picker_layout_scene.xml
+++ b/res/xml/customization_picker_layout_scene.xml
@@ -54,7 +54,7 @@
 
         <Constraint
             android:id="@+id/preview_header"
-            app:layout_constraintBottom_toTopOf="@+id/preview_guideline_in_secondary_screen"
+            app:layout_constraintBottom_toTopOf="@+id/customization_option_floating_sheet_container"
             app:layout_constraintEnd_toEndOf="parent"
             app:layout_constraintStart_toStartOf="parent"
             app:layout_constraintTop_toTopOf="parent" />
@@ -68,16 +68,12 @@
             app:layout_constraintBottom_toBottomOf="parent" />
 
         <Constraint
-            android:id="@+id/preview_guideline_in_secondary_screen"
-            app:layout_constraintGuide_end="0dp" />
-
-        <Constraint
-            android:id="@+id/customization_picker_bottom_sheet"
+            android:id="@+id/customization_option_floating_sheet_container"
             android:alpha="1.0"
             android:layout_height="wrap_content"
             android:translationY="0dp"
             app:layout_constraintStart_toStartOf="parent"
             app:layout_constraintEnd_toEndOf="parent"
-            app:layout_constraintTop_toBottomOf="parent" />
+            app:layout_constraintBottom_toBottomOf="parent" />
     </ConstraintSet>
 </MotionScene>
\ No newline at end of file
diff --git a/res/xml/small_preview_layout_scene.xml b/res/xml/small_preview_layout_scene.xml
new file mode 100644
index 00000000..5f7767d3
--- /dev/null
+++ b/res/xml/small_preview_layout_scene.xml
@@ -0,0 +1,83 @@
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
+<MotionScene xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    xmlns:motion="http://schemas.android.com/apk/res-auto">
+
+    <Transition
+        android:id="@+id/show_floating_sheet"
+        motion:constraintSetStart="@id/floating_sheet_gone"
+        motion:constraintSetEnd="@id/floating_sheet_visible" />
+
+    <ConstraintSet android:id="@+id/floating_sheet_gone">
+        <Constraint
+            android:id="@+id/pager_previews"
+            android:layout_width="0dp"
+            android:layout_height="0dp"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintBottom_toTopOf="@+id/preview_action_group_container" />
+
+        <Constraint
+            android:id="@+id/preview_action_group_container"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:alpha="1"
+            app:layout_constraintTop_toBottomOf="@+id/pager_previews"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent" />
+
+        <Constraint
+            android:id="@+id/floating_sheet"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintTop_toBottomOf="parent" />
+    </ConstraintSet>
+
+    <ConstraintSet android:id="@+id/floating_sheet_visible">
+        <Constraint
+            android:id="@+id/pager_previews"
+            android:layout_width="0dp"
+            android:layout_height="0dp"
+            app:layout_constraintBottom_toTopOf="@+id/floating_sheet"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintTop_toTopOf="parent" />
+
+        <Constraint
+            android:id="@+id/preview_action_group_container"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:alpha="0"
+            app:layout_constraintTop_toBottomOf="@+id/pager_previews"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent" />
+
+        <Constraint
+            android:id="@+id/floating_sheet"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent" />
+    </ConstraintSet>
+</MotionScene>
\ No newline at end of file
diff --git a/res_override/values/override.xml b/res_override/values/override.xml
new file mode 100644
index 00000000..b93568fa
--- /dev/null
+++ b/res_override/values/override.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+
+     Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<resources>
+    <string name="extended_wallpaper_effects_package" translatable="false">
+    </string>
+    <string name="extended_wallpaper_effects_activity" translatable="false">
+    </string>
+</resources>
+
+
+
+
diff --git a/src/com/android/customization/picker/clock/ui/view/ClockViewFactory.kt b/src/com/android/customization/picker/clock/ui/view/ClockViewFactory.kt
new file mode 100644
index 00000000..3408d1ea
--- /dev/null
+++ b/src/com/android/customization/picker/clock/ui/view/ClockViewFactory.kt
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
+package com.android.customization.picker.clock.ui.view
+
+import android.view.View
+import androidx.annotation.ColorInt
+import androidx.lifecycle.LifecycleOwner
+import com.android.systemui.plugins.clocks.ClockController
+
+interface ClockViewFactory {
+
+    fun getController(clockId: String): ClockController
+
+    /**
+     * Reset the large view to its initial state when getting the view. This is because some view
+     * configs, e.g. animation state, might change during the reuse of the clock view in the app.
+     */
+    fun getLargeView(clockId: String): View
+
+    /**
+     * Reset the small view to its initial state when getting the view. This is because some view
+     * configs, e.g. translation X, might change during the reuse of the clock view in the app.
+     */
+    fun getSmallView(clockId: String): View
+
+    /** Enables or disables the reactive swipe interaction */
+    fun setReactiveTouchInteractionEnabled(clockId: String, enable: Boolean)
+
+    fun updateColorForAllClocks(@ColorInt seedColor: Int?)
+
+    fun updateColor(clockId: String, @ColorInt seedColor: Int?)
+
+    fun updateRegionDarkness()
+
+    fun updateTimeFormat(clockId: String)
+
+    fun registerTimeTicker(owner: LifecycleOwner)
+
+    fun onDestroy()
+
+    fun unregisterTimeTicker(owner: LifecycleOwner)
+}
diff --git a/src/com/android/customization/picker/clock/ui/view/DefaultClockViewFactory.kt b/src/com/android/customization/picker/clock/ui/view/DefaultClockViewFactory.kt
new file mode 100644
index 00000000..1c4992f1
--- /dev/null
+++ b/src/com/android/customization/picker/clock/ui/view/DefaultClockViewFactory.kt
@@ -0,0 +1,69 @@
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
+package com.android.customization.picker.clock.ui.view
+
+import android.view.View
+import androidx.lifecycle.LifecycleOwner
+import com.android.systemui.plugins.clocks.ClockController
+import javax.inject.Inject
+
+class DefaultClockViewFactory @Inject constructor() : ClockViewFactory {
+
+    override fun getController(clockId: String): ClockController {
+        TODO("Not yet implemented")
+    }
+
+    override fun getLargeView(clockId: String): View {
+        TODO("Not yet implemented")
+    }
+
+    override fun getSmallView(clockId: String): View {
+        TODO("Not yet implemented")
+    }
+
+    override fun setReactiveTouchInteractionEnabled(clockId: String, enable: Boolean) {
+        TODO("Not yet implemented")
+    }
+
+    override fun updateColorForAllClocks(seedColor: Int?) {
+        TODO("Not yet implemented")
+    }
+
+    override fun updateColor(clockId: String, seedColor: Int?) {
+        TODO("Not yet implemented")
+    }
+
+    override fun updateRegionDarkness() {
+        TODO("Not yet implemented")
+    }
+
+    override fun updateTimeFormat(clockId: String) {
+        TODO("Not yet implemented")
+    }
+
+    override fun registerTimeTicker(owner: LifecycleOwner) {
+        TODO("Not yet implemented")
+    }
+
+    override fun onDestroy() {
+        TODO("Not yet implemented")
+    }
+
+    override fun unregisterTimeTicker(owner: LifecycleOwner) {
+        TODO("Not yet implemented")
+    }
+}
diff --git a/src/com/android/wallpaper/asset/Asset.java b/src/com/android/wallpaper/asset/Asset.java
index e2d37044..9301483c 100755
--- a/src/com/android/wallpaper/asset/Asset.java
+++ b/src/com/android/wallpaper/asset/Asset.java
@@ -363,7 +363,6 @@ public abstract class Asset {
                 loadDrawable(activity, imageView, placeholderColor);
                 return;
             }
-
             boolean isRtl = RtlUtils.isRtl(activity);
             Display defaultDisplay = activity.getWindowManager().getDefaultDisplay();
             Point screenSize = ScreenSizeCalculator.getInstance().getScreenSize(defaultDisplay);
@@ -381,8 +380,10 @@ public abstract class Asset {
             // TODO(b/264234793): Make offsetToStart general support or for the specific asset.
             adjustCropRect(activity, dimensions, visibleRawWallpaperRect, offsetToStart);
 
+            float scale = (float) visibleRawWallpaperRect.width() / screenSize.x;
+
             BitmapCropper bitmapCropper = InjectorProvider.getInjector().getBitmapCropper();
-            bitmapCropper.cropAndScaleBitmap(this, /* scale= */ 1f, visibleRawWallpaperRect,
+            bitmapCropper.cropAndScaleBitmap(this, scale, visibleRawWallpaperRect,
                     isRtl,
                     new BitmapCropper.Callback() {
                         @Override
diff --git a/src/com/android/wallpaper/asset/ContentUriAsset.java b/src/com/android/wallpaper/asset/ContentUriAsset.java
index 81af64b6..c0cab436 100755
--- a/src/com/android/wallpaper/asset/ContentUriAsset.java
+++ b/src/com/android/wallpaper/asset/ContentUriAsset.java
@@ -214,6 +214,9 @@ public final class ContentUriAsset extends StreamableAsset {
         } catch (FileNotFoundException e) {
             Log.w(TAG, "Image file not found", e);
             return null;
+        } catch (SecurityException e) {
+            Log.w(TAG, "Image file not accessible", e);
+            return null;
         }
     }
 
diff --git a/src/com/android/wallpaper/asset/StreamableAsset.java b/src/com/android/wallpaper/asset/StreamableAsset.java
index 3271d046..4b587323 100755
--- a/src/com/android/wallpaper/asset/StreamableAsset.java
+++ b/src/com/android/wallpaper/asset/StreamableAsset.java
@@ -338,6 +338,10 @@ public abstract class StreamableAsset extends Asset {
      * Closes the provided InputStream and if there was an error, logs the provided error message.
      */
     private void closeInputStream(InputStream inputStream, String errorMessage) {
+        if (inputStream == null) {
+            return;
+        }
+
         try {
             inputStream.close();
         } catch (IOException e) {
diff --git a/src/com/android/wallpaper/config/BaseFlags.kt b/src/com/android/wallpaper/config/BaseFlags.kt
index 42c0414d..fa35efa6 100644
--- a/src/com/android/wallpaper/config/BaseFlags.kt
+++ b/src/com/android/wallpaper/config/BaseFlags.kt
@@ -19,11 +19,12 @@ import android.app.WallpaperManager
 import android.content.Context
 import com.android.settings.accessibility.Flags.enableColorContrastControl
 import com.android.systemui.Flags.clockReactiveVariants
+import com.android.systemui.shared.Flags.newCustomizationPickerUi
 import com.android.systemui.shared.customization.data.content.CustomizationProviderClient
 import com.android.systemui.shared.customization.data.content.CustomizationProviderClientImpl
 import com.android.systemui.shared.customization.data.content.CustomizationProviderContract as Contract
+import com.android.wallpaper.Flags.largeScreenWallpaperCollections
 import com.android.wallpaper.Flags.magicPortraitFlag
-import com.android.wallpaper.Flags.newPickerUiFlag
 import com.android.wallpaper.Flags.refactorWallpaperCategoryFlag
 import com.android.wallpaper.Flags.wallpaperRestorerFlag
 import com.android.wallpaper.module.InjectorProvider
@@ -33,15 +34,27 @@ import kotlinx.coroutines.runBlocking
 abstract class BaseFlags {
     private var customizationProviderClient: CustomizationProviderClient? = null
     private var cachedFlags: List<CustomizationProviderClient.Flag>? = null
+
     open fun isStagingBackdropContentEnabled() = false
+
     open fun isWallpaperEffectEnabled() = false
+
     open fun isWallpaperEffectModelDownloadEnabled() = true
+
     open fun isInterruptModelDownloadEnabled() = false
+
     open fun isWallpaperRestorerEnabled() = wallpaperRestorerFlag()
+
     open fun isWallpaperCategoryRefactoringEnabled() = refactorWallpaperCategoryFlag()
+
     open fun isColorContrastControlEnabled() = enableColorContrastControl()
+
+    open fun isLargeScreenWallpaperCollectionsEnabled() = largeScreenWallpaperCollections()
+
     open fun isMagicPortraitEnabled() = magicPortraitFlag()
-    open fun isNewPickerUi() = newPickerUiFlag()
+
+    open fun isNewPickerUi() = newCustomizationPickerUi()
+
     open fun isClockReactiveVariantsEnabled() = clockReactiveVariants()
 
     open fun isMultiCropEnabled() = WallpaperManager.isMultiCropEnabled()
@@ -77,12 +90,6 @@ abstract class BaseFlags {
             ?.value == true
     }
 
-    open fun isTransitClockEnabled(context: Context): Boolean {
-        return getCachedFlags(context)
-            .firstOrNull { flag -> flag.name == Contract.FlagsTable.FLAG_NAME_TRANSIT_CLOCK }
-            ?.value == true
-    }
-
     /**
      * This flag is to for refactoring the process of setting a wallpaper from the Wallpaper Picker,
      * such as changes in WallpaperSetter, WallpaperPersister and WallpaperPreferences.
diff --git a/src/com/android/wallpaper/model/AppResourceWallpaperInfo.java b/src/com/android/wallpaper/model/AppResourceWallpaperInfo.java
index c6b3a152..699360aa 100755
--- a/src/com/android/wallpaper/model/AppResourceWallpaperInfo.java
+++ b/src/com/android/wallpaper/model/AppResourceWallpaperInfo.java
@@ -150,7 +150,15 @@ public class AppResourceWallpaperInfo extends WallpaperInfo {
     public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
                             int requestCode, boolean isAssetIdPresent) {
         srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
-                isAssetIdPresent), requestCode);
+                isAssetIdPresent, false), requestCode);
+    }
+
+    @Override
+    public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
+            int requestCode, boolean isAssetIdPresent,
+            boolean shouldRefreshCategory) {
+        srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
+                isAssetIdPresent, shouldRefreshCategory), requestCode);
     }
 
     @Override
diff --git a/src/com/android/wallpaper/model/CurrentWallpaperInfo.java b/src/com/android/wallpaper/model/CurrentWallpaperInfo.java
index 2093053b..9376d767 100755
--- a/src/com/android/wallpaper/model/CurrentWallpaperInfo.java
+++ b/src/com/android/wallpaper/model/CurrentWallpaperInfo.java
@@ -149,7 +149,15 @@ public class CurrentWallpaperInfo extends WallpaperInfo {
     public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
                             int requestCode, boolean isAssetIdPresent) {
         srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
-                isAssetIdPresent), requestCode);
+                isAssetIdPresent, false), requestCode);
+    }
+
+    @Override
+    public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
+            int requestCode, boolean isAssetIdPresent,
+            boolean shouldRefreshCategory) {
+        srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
+                isAssetIdPresent, shouldRefreshCategory), requestCode);
     }
 
     @Override
diff --git a/src/com/android/wallpaper/model/DefaultWallpaperInfo.java b/src/com/android/wallpaper/model/DefaultWallpaperInfo.java
index 970630e2..438f4e91 100755
--- a/src/com/android/wallpaper/model/DefaultWallpaperInfo.java
+++ b/src/com/android/wallpaper/model/DefaultWallpaperInfo.java
@@ -83,7 +83,15 @@ public class DefaultWallpaperInfo extends WallpaperInfo {
     public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
                             int requestCode, boolean isAssetIdPresent) {
         srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
-                isAssetIdPresent), requestCode);
+                isAssetIdPresent, false), requestCode);
+    }
+
+    @Override
+    public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
+            int requestCode, boolean isAssetIdPresent,
+            boolean shouldRefreshCategory) {
+        srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
+                isAssetIdPresent, shouldRefreshCategory), requestCode);
     }
 
     @Override
diff --git a/src/com/android/wallpaper/model/ImageWallpaperInfo.java b/src/com/android/wallpaper/model/ImageWallpaperInfo.java
index eaf45848..95bd19b4 100755
--- a/src/com/android/wallpaper/model/ImageWallpaperInfo.java
+++ b/src/com/android/wallpaper/model/ImageWallpaperInfo.java
@@ -171,7 +171,15 @@ public class ImageWallpaperInfo extends WallpaperInfo {
     public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
                             int requestCode, boolean isAssetIdPresent) {
         srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
-                isAssetIdPresent), requestCode);
+                isAssetIdPresent, false), requestCode);
+    }
+
+    @Override
+    public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
+            int requestCode, boolean isAssetIdPresent,
+            boolean shouldRefreshCategory) {
+        srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
+                isAssetIdPresent, shouldRefreshCategory), requestCode);
     }
 
     @Override
diff --git a/src/com/android/wallpaper/model/InlinePreviewIntentFactory.java b/src/com/android/wallpaper/model/InlinePreviewIntentFactory.java
index fde3bceb..d90f37bb 100755
--- a/src/com/android/wallpaper/model/InlinePreviewIntentFactory.java
+++ b/src/com/android/wallpaper/model/InlinePreviewIntentFactory.java
@@ -38,7 +38,8 @@ public interface InlinePreviewIntentFactory {
     }
 
     /** Gets an intent to show the inline preview activity for the given wallpaper. */
-    Intent newIntent(Context ctx, WallpaperInfo wallpaper, boolean isAssetIdPresent);
+    Intent newIntent(Context ctx, WallpaperInfo wallpaper, boolean isAssetIdPresent,
+            boolean shouldRefreshCategory);
 
     /**
      * Sets rendering preview as home or lock screen.
diff --git a/src/com/android/wallpaper/model/LegacyPartnerWallpaperInfo.java b/src/com/android/wallpaper/model/LegacyPartnerWallpaperInfo.java
index df903e3b..610dfcd6 100755
--- a/src/com/android/wallpaper/model/LegacyPartnerWallpaperInfo.java
+++ b/src/com/android/wallpaper/model/LegacyPartnerWallpaperInfo.java
@@ -169,7 +169,15 @@ public class LegacyPartnerWallpaperInfo extends WallpaperInfo {
     public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
                             int requestCode, boolean isAssetIdPresent) {
         srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
-                isAssetIdPresent), requestCode);
+                isAssetIdPresent, false), requestCode);
+    }
+
+    @Override
+    public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
+            int requestCode, boolean isAssetIdPresent,
+            boolean shouldRefreshCategory) {
+        srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
+                isAssetIdPresent, shouldRefreshCategory), requestCode);
     }
 
     @Override
diff --git a/src/com/android/wallpaper/model/LiveWallpaperInfo.java b/src/com/android/wallpaper/model/LiveWallpaperInfo.java
index 3c4a3a36..b2cf663c 100755
--- a/src/com/android/wallpaper/model/LiveWallpaperInfo.java
+++ b/src/com/android/wallpaper/model/LiveWallpaperInfo.java
@@ -426,10 +426,25 @@ public class LiveWallpaperInfo extends WallpaperInfo {
     @Override
     public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
                             int requestCode, boolean isAssetIdPresent) {
+        showPreviewActivity(srcActivity, factory, requestCode, isAssetIdPresent,
+                false);
+    }
+
+    @Override
+    public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
+            int requestCode, boolean isAssetIdPresent,
+            boolean shouldRefreshCategory) {
+        showPreviewActivity(srcActivity, factory, requestCode, isAssetIdPresent,
+                shouldRefreshCategory);
+    }
+
+    private void showPreviewActivity(Activity srcActivity, InlinePreviewIntentFactory factory,
+            int requestCode, boolean isAssetIdPresent,
+            boolean shouldRefreshCategory) {
         //Only use internal live picker if available, otherwise, default to the Framework one
         if (factory.shouldUseInternalLivePicker(srcActivity)) {
             srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
-                    isAssetIdPresent), requestCode);
+                    isAssetIdPresent, shouldRefreshCategory), requestCode);
         } else {
             Intent preview = new Intent(WallpaperManager.ACTION_CHANGE_LIVE_WALLPAPER);
             preview.putExtra(WallpaperManager.EXTRA_LIVE_WALLPAPER_COMPONENT, mInfo.getComponent());
diff --git a/src/com/android/wallpaper/model/PartnerWallpaperInfo.java b/src/com/android/wallpaper/model/PartnerWallpaperInfo.java
index 8a383b44..379d96b3 100755
--- a/src/com/android/wallpaper/model/PartnerWallpaperInfo.java
+++ b/src/com/android/wallpaper/model/PartnerWallpaperInfo.java
@@ -152,9 +152,17 @@ public class PartnerWallpaperInfo extends DefaultWallpaperInfo {
 
     @Override
     public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
-                            int requestCode, boolean isAssetIdPresent) {
+            int requestCode, boolean isAssetIdPresent) {
         srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
-                isAssetIdPresent), requestCode);
+                isAssetIdPresent, false), requestCode);
+    }
+
+    @Override
+    public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
+            int requestCode, boolean isAssetIdPresent,
+            boolean shouldRefreshCategory) {
+        srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
+                isAssetIdPresent, shouldRefreshCategory), requestCode);
     }
 
     @Override
diff --git a/src/com/android/wallpaper/model/SystemStaticWallpaperInfo.java b/src/com/android/wallpaper/model/SystemStaticWallpaperInfo.java
index 90d2e3ba..2e4da00b 100755
--- a/src/com/android/wallpaper/model/SystemStaticWallpaperInfo.java
+++ b/src/com/android/wallpaper/model/SystemStaticWallpaperInfo.java
@@ -258,9 +258,17 @@ public class SystemStaticWallpaperInfo extends WallpaperInfo {
 
     @Override
     public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
-                            int requestCode, boolean isAssetIdPresent) {
+            int requestCode, boolean isAssetIdPresent) {
         srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
-                isAssetIdPresent), requestCode);
+                isAssetIdPresent, false), requestCode);
+    }
+
+    @Override
+    public void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
+            int requestCode, boolean isAssetIdPresent,
+            boolean shouldRefreshCategory) {
+        srcActivity.startActivityForResult(factory.newIntent(srcActivity, this,
+                isAssetIdPresent, shouldRefreshCategory), requestCode);
     }
 
     @Override
diff --git a/src/com/android/wallpaper/model/WallpaperCategory.java b/src/com/android/wallpaper/model/WallpaperCategory.java
index 8f9b32f8..03c1a014 100755
--- a/src/com/android/wallpaper/model/WallpaperCategory.java
+++ b/src/com/android/wallpaper/model/WallpaperCategory.java
@@ -120,7 +120,7 @@ public class WallpaperCategory extends Category {
      * Returns the mutable list of wallpapers backed by this WallpaperCategory. All reads and writes
      * on the returned list must be synchronized with {@code mWallpapersLock}.
      */
-    protected List<WallpaperInfo> getMutableWallpapers() {
+    public List<WallpaperInfo> getMutableWallpapers() {
         return mWallpapers;
     }
 
diff --git a/src/com/android/wallpaper/model/WallpaperInfo.java b/src/com/android/wallpaper/model/WallpaperInfo.java
index eefcadbb..595c039e 100755
--- a/src/com/android/wallpaper/model/WallpaperInfo.java
+++ b/src/com/android/wallpaper/model/WallpaperInfo.java
@@ -211,6 +211,24 @@ public abstract class WallpaperInfo implements Parcelable {
     public abstract void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
                                      int requestCode, boolean isAssetIdPresent);
 
+    /**
+     * Shows the appropriate preview activity for this WallpaperInfo.
+     *
+     * @param factory               A factory for showing the inline preview activity for within
+     *                              this app.
+     *                              Only used for certain WallpaperInfo implementations that
+     *                              require
+     *                              an inline preview
+     *                              (as opposed to some external preview activity).
+     * @param requestCode           Request code to pass in when starting the inline preview
+     *                              activity.
+     * @param shouldRefreshCategory category type to pass in when starting the inline preview
+     *                              activity.
+     */
+    public abstract void showPreview(Activity srcActivity, InlinePreviewIntentFactory factory,
+            int requestCode, boolean isAssetIdPresent,
+            boolean shouldRefreshCategory);
+
     /**
      * Returns a Future to obtain a wallpaper color and a placeholder color calculated in a
      * background thread for this wallpaper's thumbnail.
diff --git a/src/com/android/wallpaper/picker/preview/shared/model/LiveWallpaperDownloadResultModel.kt b/src/com/android/wallpaper/model/WallpaperModelsPair.kt
similarity index 65%
rename from src/com/android/wallpaper/picker/preview/shared/model/LiveWallpaperDownloadResultModel.kt
rename to src/com/android/wallpaper/model/WallpaperModelsPair.kt
index 1bf6fe52..800934d2 100644
--- a/src/com/android/wallpaper/picker/preview/shared/model/LiveWallpaperDownloadResultModel.kt
+++ b/src/com/android/wallpaper/model/WallpaperModelsPair.kt
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,16 +14,11 @@
  * limitations under the License.
  */
 
-package com.android.wallpaper.picker.preview.shared.model
+package com.android.wallpaper.model
 
 import com.android.wallpaper.picker.data.WallpaperModel
 
-data class LiveWallpaperDownloadResultModel(
-    val code: LiveWallpaperDownloadResultCode,
-    val wallpaperModel: WallpaperModel.LiveWallpaperModel?
+data class WallpaperModelsPair(
+    val homeWallpaper: WallpaperModel,
+    val lockWallpaper: WallpaperModel?,
 )
-
-enum class LiveWallpaperDownloadResultCode {
-    SUCCESS,
-    FAIL,
-}
diff --git a/src/com/android/wallpaper/module/DefaultBitmapCropper.java b/src/com/android/wallpaper/module/DefaultBitmapCropper.java
index 21115e17..a9127e9d 100755
--- a/src/com/android/wallpaper/module/DefaultBitmapCropper.java
+++ b/src/com/android/wallpaper/module/DefaultBitmapCropper.java
@@ -15,65 +15,29 @@
  */
 package com.android.wallpaper.module;
 
-import android.graphics.Bitmap;
 import android.graphics.Rect;
-import android.os.Handler;
-import android.os.Looper;
-import android.util.Log;
 
 import com.android.wallpaper.asset.Asset;
-import com.android.wallpaper.asset.Asset.BitmapReceiver;
-
-import java.util.concurrent.ExecutorService;
-import java.util.concurrent.Executors;
 
 /**
  * Default implementation of BitmapCropper, which actually crops and scales bitmaps.
  */
 public class DefaultBitmapCropper implements BitmapCropper {
-    private static final ExecutorService sExecutorService = Executors.newSingleThreadExecutor();
-    private static final String TAG = "DefaultBitmapCropper";
-    private static final boolean FILTER_SCALED_BITMAP = true;
 
     @Override
     public void cropAndScaleBitmap(Asset asset, float scale, Rect cropRect,
             boolean isRtl, Callback callback) {
-        // Crop rect in pixels of source image.
-        Rect scaledCropRect = new Rect(
-                (int) Math.floor((float) cropRect.left / scale),
-                (int) Math.floor((float) cropRect.top / scale),
-                (int) Math.floor((float) cropRect.right / scale),
-                (int) Math.floor((float) cropRect.bottom / scale));
-
-        asset.decodeBitmapRegion(scaledCropRect, cropRect.width(), cropRect.height(), isRtl,
-                new BitmapReceiver() {
-                    @Override
-                    public void onBitmapDecoded(Bitmap bitmap) {
-                        if (bitmap == null) {
-                            callback.onError(null);
-                            return;
-                        }
-                        // Asset provides a bitmap which is appropriate for the target width &
-                        // height, but since it does not guarantee an exact size we need to fit
-                        // the bitmap to the cropRect.
-                        sExecutorService.execute(() -> {
-                            try {
-                                // Fit bitmap to exact dimensions of crop rect.
-                                Bitmap result = Bitmap.createScaledBitmap(
-                                        bitmap,
-                                        cropRect.width(),
-                                        cropRect.height(),
-                                        FILTER_SCALED_BITMAP);
-                                new Handler(Looper.getMainLooper()).post(
-                                        () -> callback.onBitmapCropped(result));
-                            } catch (OutOfMemoryError e) {
-                                Log.w(TAG,
-                                        "Not enough memory to fit the final cropped and "
-                                                + "scaled bitmap to size", e);
-                                new Handler(Looper.getMainLooper()).post(() -> callback.onError(e));
-                            }
-                        });
+        int targetWidth = (int) (cropRect.width() / scale);
+        int targetHeight = (int) (cropRect.height() / scale);
+        // Giving the target width and height can down-sample a large bitmap to a smaller target
+        // size, which saves memory use.
+        asset.decodeBitmapRegion(cropRect, targetWidth, targetHeight, isRtl,
+                bitmap -> {
+                    if (bitmap == null) {
+                        callback.onError(null);
+                        return;
                     }
+                    callback.onBitmapCropped(bitmap);
                 });
     }
 }
diff --git a/src/com/android/wallpaper/module/DefaultWallpaperPreferences.kt b/src/com/android/wallpaper/module/DefaultWallpaperPreferences.kt
index 5f10d59a..0e5f7ad9 100755
--- a/src/com/android/wallpaper/module/DefaultWallpaperPreferences.kt
+++ b/src/com/android/wallpaper/module/DefaultWallpaperPreferences.kt
@@ -38,15 +38,23 @@ import com.android.wallpaper.module.WallpaperPreferences.PresentationMode
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination
 import com.android.wallpaper.picker.data.WallpaperModel.LiveWallpaperModel
 import com.android.wallpaper.picker.data.WallpaperModel.StaticWallpaperModel
+import dagger.hilt.android.qualifiers.ApplicationContext
 import java.text.SimpleDateFormat
 import java.util.Calendar
 import java.util.Locale
 import java.util.TimeZone
+import javax.inject.Inject
+import javax.inject.Singleton
 import org.json.JSONArray
 import org.json.JSONException
 
 /** Default implementation that writes to and reads from SharedPreferences. */
-open class DefaultWallpaperPreferences(private val context: Context) : WallpaperPreferences {
+@Singleton
+open class DefaultWallpaperPreferences
+@Inject
+constructor(
+    @ApplicationContext private val context: Context,
+) : WallpaperPreferences {
     protected val sharedPrefs: SharedPreferences =
         context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
     protected val noBackupPrefs: SharedPreferences =
diff --git a/src/com/android/wallpaper/module/Injector.kt b/src/com/android/wallpaper/module/Injector.kt
index 2c895029..8b85a3dd 100755
--- a/src/com/android/wallpaper/module/Injector.kt
+++ b/src/com/android/wallpaper/module/Injector.kt
@@ -32,6 +32,7 @@ import com.android.wallpaper.module.logging.UserEventLogger
 import com.android.wallpaper.monitor.PerformanceMonitor
 import com.android.wallpaper.network.Requester
 import com.android.wallpaper.picker.MyPhotosStarter.MyPhotosIntentProvider
+import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper
 import com.android.wallpaper.picker.customization.data.content.WallpaperClient
 import com.android.wallpaper.picker.customization.data.repository.WallpaperColorsRepository
 import com.android.wallpaper.picker.customization.domain.interactor.WallpaperInteractor
@@ -118,9 +119,7 @@ interface Injector {
 
     fun getUndoInteractor(context: Context, lifecycleOwner: LifecycleOwner): UndoInteractor
 
-    fun getSnapshotRestorers(
-        context: Context,
-    ): Map<Int, SnapshotRestorer> {
+    fun getSnapshotRestorers(context: Context): Map<Int, SnapshotRestorer> {
         // Empty because we don't support undoing in WallpaperPicker2.
         return HashMap()
     }
@@ -133,9 +132,11 @@ interface Injector {
 
     fun getWallpaperColorsRepository(): WallpaperColorsRepository
 
+    fun getWallpaperCategoryWrapper(): WallpaperCategoryWrapper
+
     fun getWallpaperColorResources(
         wallpaperColors: WallpaperColors,
-        context: Context
+        context: Context,
     ): WallpaperColorResources
 
     fun getMyPhotosIntentProvider(): MyPhotosIntentProvider
diff --git a/src/com/android/wallpaper/module/LargeScreenMultiPanesChecker.kt b/src/com/android/wallpaper/module/LargeScreenMultiPanesChecker.kt
index d13fd87a..33109f57 100644
--- a/src/com/android/wallpaper/module/LargeScreenMultiPanesChecker.kt
+++ b/src/com/android/wallpaper/module/LargeScreenMultiPanesChecker.kt
@@ -19,7 +19,11 @@ import android.content.Context
 import android.content.Intent
 import android.content.Intent.ACTION_SET_WALLPAPER
 import android.content.pm.PackageManager.MATCH_DEFAULT_ONLY
-import android.provider.Settings.*
+import android.provider.Settings.ACTION_SETTINGS_EMBED_DEEP_LINK_ACTIVITY
+import android.provider.Settings.EXTRA_SETTINGS_EMBEDDED_DEEP_LINK_HIGHLIGHT_MENU_KEY
+import android.provider.Settings.EXTRA_SETTINGS_EMBEDDED_DEEP_LINK_INTENT_URI
+import com.android.wallpaper.util.DeepLinkUtils
+import com.android.wallpaper.util.DeepLinkUtils.EXTRA_KEY_COLLECTION_ID
 
 /** Utility class to check the support of multi panes integration (trampoline) */
 class LargeScreenMultiPanesChecker : MultiPanesChecker {
@@ -41,6 +45,8 @@ class LargeScreenMultiPanesChecker : MultiPanesChecker {
     override fun getMultiPanesIntent(intent: Intent): Intent {
         return Intent(ACTION_SETTINGS_EMBED_DEEP_LINK_ACTIVITY).apply {
             intent.extras?.let { putExtras(it) }
+            val deepLinkCollectionId = DeepLinkUtils.getCollectionId(intent)
+            deepLinkCollectionId?.let { putExtra(EXTRA_KEY_COLLECTION_ID, deepLinkCollectionId) }
             putExtra(EXTRA_SETTINGS_EMBEDDED_DEEP_LINK_HIGHLIGHT_MENU_KEY, VALUE_HIGHLIGHT_MENU)
             putExtra(
                 EXTRA_SETTINGS_EMBEDDED_DEEP_LINK_INTENT_URI,
diff --git a/src/com/android/wallpaper/module/WallpaperPicker2Injector.kt b/src/com/android/wallpaper/module/WallpaperPicker2Injector.kt
index 4fa84d59..be8182dd 100755
--- a/src/com/android/wallpaper/module/WallpaperPicker2Injector.kt
+++ b/src/com/android/wallpaper/module/WallpaperPicker2Injector.kt
@@ -26,8 +26,6 @@ import androidx.fragment.app.Fragment
 import androidx.lifecycle.LifecycleOwner
 import com.android.customization.model.color.DefaultWallpaperColorResources
 import com.android.customization.model.color.WallpaperColorResources
-import com.android.systemui.shared.settings.data.repository.SecureSettingsRepository
-import com.android.systemui.shared.settings.data.repository.SecureSettingsRepositoryImpl
 import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.effects.EffectsController
 import com.android.wallpaper.model.CategoryProvider
@@ -44,15 +42,13 @@ import com.android.wallpaper.picker.MyPhotosStarter
 import com.android.wallpaper.picker.PreviewActivity
 import com.android.wallpaper.picker.PreviewFragment
 import com.android.wallpaper.picker.ViewOnlyPreviewActivity
+import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper
 import com.android.wallpaper.picker.customization.data.content.WallpaperClient
-import com.android.wallpaper.picker.customization.data.content.WallpaperClientImpl
 import com.android.wallpaper.picker.customization.data.repository.WallpaperColorsRepository
-import com.android.wallpaper.picker.customization.data.repository.WallpaperRepository
 import com.android.wallpaper.picker.customization.domain.interactor.WallpaperInteractor
 import com.android.wallpaper.picker.customization.domain.interactor.WallpaperSnapshotRestorer
-import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import com.android.wallpaper.picker.di.modules.MainDispatcher
-import com.android.wallpaper.picker.individual.IndividualPickerFragment
+import com.android.wallpaper.picker.individual.IndividualPickerFragment2
 import com.android.wallpaper.picker.undo.data.repository.UndoRepository
 import com.android.wallpaper.picker.undo.domain.interactor.UndoInteractor
 import com.android.wallpaper.system.UiModeManagerWrapper
@@ -60,16 +56,12 @@ import com.android.wallpaper.util.DisplayUtils
 import dagger.Lazy
 import javax.inject.Inject
 import javax.inject.Singleton
-import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.CoroutineScope
 
 @Singleton
 open class WallpaperPicker2Injector
 @Inject
-constructor(
-    @MainDispatcher private val mainScope: CoroutineScope,
-    @BackgroundDispatcher private val bgDispatcher: CoroutineDispatcher,
-) : Injector {
+constructor(@MainDispatcher private val mainScope: CoroutineScope) : Injector {
     private var alarmManagerWrapper: AlarmManagerWrapper? = null
     private var bitmapCropper: BitmapCropper? = null
     private var categoryProvider: CategoryProvider? = null
@@ -89,8 +81,7 @@ constructor(
     private var wallpaperInteractor: WallpaperInteractor? = null
     private var wallpaperClient: WallpaperClient? = null
     private var wallpaperSnapshotRestorer: WallpaperSnapshotRestorer? = null
-    private var secureSettingsRepository: SecureSettingsRepository? = null
-    private var wallpaperColorsRepository: WallpaperColorsRepository? = null
+
     private var previewActivityIntentFactory: InlinePreviewIntentFactory? = null
     private var viewOnlyPreviewActivityIntentFactory: InlinePreviewIntentFactory? = null
 
@@ -104,11 +95,18 @@ constructor(
     @Inject lateinit var injectedWallpaperClient: Lazy<WallpaperClient>
     @Inject lateinit var injectedWallpaperInteractor: Lazy<WallpaperInteractor>
     @Inject lateinit var prefs: Lazy<WallpaperPreferences>
+    @Inject lateinit var wallpaperColorsRepository: Lazy<WallpaperColorsRepository>
+
+    @Inject lateinit var defaultWallpaperCategoryWrapper: Lazy<WallpaperCategoryWrapper>
 
     override fun getApplicationCoroutineScope(): CoroutineScope {
         return mainScope
     }
 
+    override fun getWallpaperCategoryWrapper(): WallpaperCategoryWrapper {
+        return defaultWallpaperCategoryWrapper.get()
+    }
+
     @Synchronized
     override fun getAlarmManagerWrapper(context: Context): AlarmManagerWrapper {
         return alarmManagerWrapper
@@ -163,9 +161,7 @@ constructor(
             ?: DefaultDrawableLayerResolver().also { drawableLayerResolver = it }
     }
 
-    override fun getEffectsController(
-        context: Context,
-    ): EffectsController? {
+    override fun getEffectsController(context: Context): EffectsController? {
         return null
     }
 
@@ -178,7 +174,7 @@ constructor(
     }
 
     override fun getIndividualPickerFragment(context: Context, collectionId: String): Fragment {
-        return IndividualPickerFragment.newInstance(collectionId)
+        return IndividualPickerFragment2.newInstance(collectionId)
     }
 
     override fun getLiveWallpaperInfoFactory(context: Context): LiveWallpaperInfoFactory {
@@ -281,7 +277,7 @@ constructor(
     override fun getWallpaperStatusChecker(context: Context): WallpaperStatusChecker {
         return wallpaperStatusChecker
             ?: DefaultWallpaperStatusChecker(
-                    wallpaperManager = WallpaperManager.getInstance(context.applicationContext),
+                    wallpaperManager = WallpaperManager.getInstance(context.applicationContext)
                 )
                 .also { wallpaperStatusChecker = it }
     }
@@ -292,7 +288,7 @@ constructor(
 
     override fun getUndoInteractor(
         context: Context,
-        lifecycleOwner: LifecycleOwner
+        lifecycleOwner: LifecycleOwner,
     ): UndoInteractor {
         return undoInteractor
             ?: UndoInteractor(
@@ -304,37 +300,11 @@ constructor(
     }
 
     override fun getWallpaperInteractor(context: Context): WallpaperInteractor {
-        if (getFlags().isMultiCropEnabled()) {
-            return injectedWallpaperInteractor.get()
-        }
-
-        val appContext = context.applicationContext
-        return wallpaperInteractor
-            ?: WallpaperInteractor(
-                    repository =
-                        WallpaperRepository(
-                            scope = getApplicationCoroutineScope(),
-                            client = getWallpaperClient(context),
-                            wallpaperPreferences = getPreferences(context = appContext),
-                            backgroundDispatcher = bgDispatcher,
-                        ),
-                )
-                .also { wallpaperInteractor = it }
+        return injectedWallpaperInteractor.get()
     }
 
     override fun getWallpaperClient(context: Context): WallpaperClient {
-        if (getFlags().isMultiCropEnabled()) {
-            return injectedWallpaperClient.get()
-        }
-
-        val appContext = context.applicationContext
-        return wallpaperClient
-            ?: WallpaperClientImpl(
-                    context = appContext,
-                    wallpaperManager = WallpaperManager.getInstance(appContext),
-                    wallpaperPreferences = getPreferences(appContext),
-                )
-                .also { wallpaperClient = it }
+        return injectedWallpaperClient.get()
     }
 
     override fun getWallpaperSnapshotRestorer(context: Context): WallpaperSnapshotRestorer {
@@ -346,23 +316,13 @@ constructor(
                 .also { wallpaperSnapshotRestorer = it }
     }
 
-    protected fun getSecureSettingsRepository(context: Context): SecureSettingsRepository {
-        return secureSettingsRepository
-            ?: SecureSettingsRepositoryImpl(
-                    contentResolver = context.applicationContext.contentResolver,
-                    backgroundDispatcher = bgDispatcher,
-                )
-                .also { secureSettingsRepository = it }
-    }
-
     override fun getWallpaperColorsRepository(): WallpaperColorsRepository {
-        return wallpaperColorsRepository
-            ?: WallpaperColorsRepository().also { wallpaperColorsRepository = it }
+        return wallpaperColorsRepository.get()
     }
 
     override fun getWallpaperColorResources(
         wallpaperColors: WallpaperColors,
-        context: Context
+        context: Context,
     ): WallpaperColorResources {
         return DefaultWallpaperColorResources(wallpaperColors)
     }
diff --git a/src/com/android/wallpaper/picker/BasePreviewActivity.java b/src/com/android/wallpaper/picker/BasePreviewActivity.java
index 2c444309..a4054b95 100644
--- a/src/com/android/wallpaper/picker/BasePreviewActivity.java
+++ b/src/com/android/wallpaper/picker/BasePreviewActivity.java
@@ -39,6 +39,8 @@ public abstract class BasePreviewActivity extends BaseActivity {
             "com.android.wallpaper.picker.asset_id_present";
     public static final String IS_NEW_TASK =
             "com.android.wallpaper.picker.new_task";
+    public static final String SHOULD_CATEGORY_REFRESH =
+            "com.android.wallpaper.picker.should_category_refresh";
 
     @Override
     protected void onCreate(@Nullable Bundle savedInstanceState) {
diff --git a/src/com/android/wallpaper/picker/CategorySelectorFragment.java b/src/com/android/wallpaper/picker/CategorySelectorFragment.java
index 49297675..10397271 100644
--- a/src/com/android/wallpaper/picker/CategorySelectorFragment.java
+++ b/src/com/android/wallpaper/picker/CategorySelectorFragment.java
@@ -101,18 +101,6 @@ public class CategorySelectorFragment extends AppbarFragment {
          */
         void show(Category category);
 
-
-        /**
-         * Indicates if the host has toolbar to show the title. If it does, we should set the title
-         * there.
-         */
-        boolean isHostToolbarShown();
-
-        /**
-         * Sets the title in the host's toolbar.
-         */
-        void setToolbarTitle(CharSequence title);
-
         /**
          * Fetches the wallpaper categories.
          */
@@ -187,13 +175,9 @@ public class CategorySelectorFragment extends AppbarFragment {
                 new WallpaperPickerRecyclerViewAccessibilityDelegate(
                         mImageGrid, (BottomSheetHost) getParentFragment(), getNumColumns()));
 
-        if (getCategorySelectorFragmentHost().isHostToolbarShown()) {
-            view.findViewById(R.id.header_bar).setVisibility(View.GONE);
-            getCategorySelectorFragmentHost().setToolbarTitle(getText(R.string.wallpaper_title));
-        } else {
-            setUpToolbar(view);
-            setTitle(getText(R.string.wallpaper_title));
-        }
+
+        setUpToolbar(view);
+        setTitle(getText(R.string.wallpaper_title));
 
         if (!DeepLinkUtils.isDeepLink(getActivity().getIntent())) {
             getCategorySelectorFragmentHost().fetchCategories();
diff --git a/src/com/android/wallpaper/picker/CustomizationPickerActivity.java b/src/com/android/wallpaper/picker/CustomizationPickerActivity.java
index f1162daf..dd5644c7 100644
--- a/src/com/android/wallpaper/picker/CustomizationPickerActivity.java
+++ b/src/com/android/wallpaper/picker/CustomizationPickerActivity.java
@@ -35,6 +35,7 @@ import androidx.core.view.WindowCompat;
 import androidx.fragment.app.Fragment;
 import androidx.fragment.app.FragmentActivity;
 import androidx.fragment.app.FragmentManager;
+import androidx.lifecycle.ViewModelProvider;
 
 import com.android.wallpaper.R;
 import com.android.wallpaper.config.BaseFlags;
@@ -55,7 +56,7 @@ import com.android.wallpaper.module.logging.UserEventLogger;
 import com.android.wallpaper.picker.AppbarFragment.AppbarFragmentHost;
 import com.android.wallpaper.picker.CategorySelectorFragment.CategorySelectorFragmentHost;
 import com.android.wallpaper.picker.MyPhotosStarter.PermissionChangedListener;
-import com.android.wallpaper.picker.individual.IndividualPickerFragment.IndividualPickerFragmentHost;
+import com.android.wallpaper.picker.category.ui.viewmodel.CategoriesViewModel;
 import com.android.wallpaper.util.ActivityUtils;
 import com.android.wallpaper.util.DeepLinkUtils;
 import com.android.wallpaper.util.DisplayUtils;
@@ -72,8 +73,7 @@ import dagger.hilt.android.AndroidEntryPoint;
 @AndroidEntryPoint(FragmentActivity.class)
 public class CustomizationPickerActivity extends Hilt_CustomizationPickerActivity implements
         AppbarFragmentHost, WallpapersUiContainer, BottomActionBarHost, FragmentTransactionChecker,
-        PermissionRequester, CategorySelectorFragmentHost, IndividualPickerFragmentHost,
-        WallpaperPreviewNavigator {
+        PermissionRequester, CategorySelectorFragmentHost, WallpaperPreviewNavigator {
 
     private static final String TAG = "CustomizationPickerActivity";
     private static final String EXTRA_DESTINATION = "destination";
@@ -88,6 +88,8 @@ public class CustomizationPickerActivity extends Hilt_CustomizationPickerActivit
     private BottomActionBar mBottomActionBar;
     private boolean mIsSafeToCommitFragmentTransaction;
 
+    private CategoriesViewModel mCategoriesViewModel;
+
     @Override
     protected void onCreate(@Nullable Bundle savedInstanceState) {
         Injector injector = InjectorProvider.getInjector();
@@ -105,6 +107,7 @@ public class CustomizationPickerActivity extends Hilt_CustomizationPickerActivit
 
         // Restore this Activity's state before restoring contained Fragments state.
         super.onCreate(savedInstanceState);
+
         // Trampoline for the two panes
         final MultiPanesChecker mMultiPanesChecker = new LargeScreenMultiPanesChecker();
         if (mMultiPanesChecker.isMultiPanesEnabled(this)) {
@@ -114,6 +117,7 @@ public class CustomizationPickerActivity extends Hilt_CustomizationPickerActivit
                 startActivityForResultSafely(this,
                         mMultiPanesChecker.getMultiPanesIntent(intent), /* requestCode= */ 0);
                 finish();
+                return;
             }
         }
 
@@ -140,8 +144,14 @@ public class CustomizationPickerActivity extends Hilt_CustomizationPickerActivit
                     ? WallpaperOnlyFragment.newInstance()
                     : CustomizationPickerFragment.newInstance(startFromLockScreen));
 
-            // Cache the categories, but only if we're not restoring state (b/276767415).
-            mDelegate.prefetchCategories();
+
+            if (flags.isWallpaperCategoryRefactoringEnabled()) {
+                // initializing the dependency graph for categories
+                mCategoriesViewModel = new ViewModelProvider(this).get(CategoriesViewModel.class);
+            } else {
+                // Cache the categories, but only if we're not restoring state (b/276767415).
+                mDelegate.prefetchCategories();
+            }
         }
 
         if (savedInstanceState == null) {
@@ -275,31 +285,6 @@ public class CustomizationPickerActivity extends Hilt_CustomizationPickerActivit
                 this, category.getCollectionId()));
     }
 
-    @Override
-    public boolean isHostToolbarShown() {
-        return false;
-    }
-
-    @Override
-    public void setToolbarTitle(CharSequence title) {
-
-    }
-
-    @Override
-    public void setToolbarMenu(int menuResId) {
-
-    }
-
-    @Override
-    public void removeToolbarMenu() {
-
-    }
-
-    @Override
-    public void moveToPreviousFragment() {
-        getSupportFragmentManager().popBackStack();
-    }
-
     @Override
     public void fetchCategories() {
         mDelegate.initialize(mDelegate.getCategoryProvider().shouldForceReload(this));
diff --git a/src/com/android/wallpaper/picker/CustomizationPickerFragment.java b/src/com/android/wallpaper/picker/CustomizationPickerFragment.java
index 1a2e639f..2a58e73f 100644
--- a/src/com/android/wallpaper/picker/CustomizationPickerFragment.java
+++ b/src/com/android/wallpaper/picker/CustomizationPickerFragment.java
@@ -17,6 +17,7 @@ package com.android.wallpaper.picker;
 
 import android.app.Activity;
 import android.app.WallpaperManager;
+import android.content.Intent;
 import android.os.Bundle;
 import android.util.Log;
 import android.view.LayoutInflater;
@@ -210,7 +211,9 @@ public class CustomizationPickerFragment extends AppbarFragment implements
     @Override
     public boolean onBackPressed() {
         // TODO(b/191120122) Improve glitchy animation in Settings.
-        if (ActivityUtils.isLaunchedFromSettingsSearch(getActivity().getIntent())) {
+        Activity activity = getActivity();
+        Intent intent = activity != null ? activity.getIntent() : null;
+        if (intent != null && ActivityUtils.isLaunchedFromSettingsSearch(intent)) {
             mSectionControllers.forEach(CustomizationSectionController::onTransitionOut);
         }
         return super.onBackPressed();
diff --git a/src/com/android/wallpaper/picker/DisplayAspectRatioLinearLayout.kt b/src/com/android/wallpaper/picker/DisplayAspectRatioLinearLayout.kt
index f970a9b9..7f3ba9bc 100644
--- a/src/com/android/wallpaper/picker/DisplayAspectRatioLinearLayout.kt
+++ b/src/com/android/wallpaper/picker/DisplayAspectRatioLinearLayout.kt
@@ -21,7 +21,10 @@ import android.content.Context
 import android.util.AttributeSet
 import android.widget.LinearLayout
 import androidx.core.view.children
-import androidx.core.view.updateLayoutParams
+import androidx.core.view.marginBottom
+import androidx.core.view.marginEnd
+import androidx.core.view.marginStart
+import androidx.core.view.marginTop
 import com.android.wallpaper.util.ScreenSizeCalculator
 
 /**
@@ -39,11 +42,11 @@ class DisplayAspectRatioLinearLayout(
         val screenAspectRatio = ScreenSizeCalculator.getInstance().getScreenAspectRatio(context)
         val parentWidth = this.measuredWidth
         val parentHeight = this.measuredHeight
-        val itemSpacingPx = ITEM_SPACING_DP.toPx(context.resources.displayMetrics.density)
         val (childWidth, childHeight) =
             if (orientation == HORIZONTAL) {
-                val availableWidth =
-                    parentWidth - paddingStart - paddingEnd - (childCount - 1) * itemSpacingPx
+                var childMargins = 0
+                children.forEach { childMargins += it.marginStart + it.marginEnd }
+                val availableWidth = parentWidth - paddingStart - paddingEnd - childMargins
                 val availableHeight = parentHeight - paddingTop - paddingBottom
                 var width = availableWidth / childCount
                 var height = (width * screenAspectRatio).toInt()
@@ -53,9 +56,10 @@ class DisplayAspectRatioLinearLayout(
                 }
                 width to height
             } else {
+                var childMargins = 0
+                children.forEach { childMargins += it.marginTop + it.marginBottom }
                 val availableWidth = parentWidth - paddingStart - paddingEnd
-                val availableHeight =
-                    parentHeight - paddingTop - paddingBottom - (childCount - 1) * itemSpacingPx
+                val availableHeight = parentHeight - paddingTop - paddingBottom - childMargins
                 var height = availableHeight / childCount
                 var width = (height / screenAspectRatio).toInt()
                 if (width > availableWidth) {
@@ -65,22 +69,7 @@ class DisplayAspectRatioLinearLayout(
                 width to height
             }
 
-        val itemSpacingHalfPx = ITEM_SPACING_DP_HALF.toPx(context.resources.displayMetrics.density)
         children.forEachIndexed { index, child ->
-            val addSpacingToStart = index > 0
-            val addSpacingToEnd = index < (childCount - 1)
-            if (orientation == HORIZONTAL) {
-                child.updateLayoutParams<MarginLayoutParams> {
-                    if (addSpacingToStart) this.marginStart = itemSpacingHalfPx
-                    if (addSpacingToEnd) this.marginEnd = itemSpacingHalfPx
-                }
-            } else {
-                child.updateLayoutParams<MarginLayoutParams> {
-                    if (addSpacingToStart) this.topMargin = itemSpacingHalfPx
-                    if (addSpacingToEnd) this.bottomMargin = itemSpacingHalfPx
-                }
-            }
-
             child.measure(
                 MeasureSpec.makeMeasureSpec(
                     childWidth,
@@ -93,13 +82,4 @@ class DisplayAspectRatioLinearLayout(
             )
         }
     }
-
-    private fun Int.toPx(density: Float): Int {
-        return (this * density).toInt()
-    }
-
-    companion object {
-        private const val ITEM_SPACING_DP = 12
-        private const val ITEM_SPACING_DP_HALF = ITEM_SPACING_DP / 2
-    }
 }
diff --git a/src/com/android/wallpaper/picker/PreviewActivity.java b/src/com/android/wallpaper/picker/PreviewActivity.java
index c1fc1f7f..7544f044 100644
--- a/src/com/android/wallpaper/picker/PreviewActivity.java
+++ b/src/com/android/wallpaper/picker/PreviewActivity.java
@@ -124,7 +124,7 @@ public class PreviewActivity extends BasePreviewActivity implements AppbarFragme
 
         @Override
         public Intent newIntent(Context context, WallpaperInfo wallpaper,
-                boolean isAssetIdPresent) {
+                boolean isAssetIdPresent, boolean shouldRefreshCategory) {
             Context appContext = context.getApplicationContext();
             final BaseFlags flags = InjectorProvider.getInjector().getFlags();
             LargeScreenMultiPanesChecker multiPanesChecker = new LargeScreenMultiPanesChecker();
@@ -132,7 +132,8 @@ public class PreviewActivity extends BasePreviewActivity implements AppbarFragme
 
             if (flags.isMultiCropEnabled()) {
                 return WallpaperPreviewActivity.Companion.newIntent(appContext,
-                        wallpaper, isAssetIdPresent, mIsViewAsHome, /* isNewTask= */ isMultiPanel);
+                        wallpaper, isAssetIdPresent, mIsViewAsHome, /* isNewTask= */ isMultiPanel,
+                        shouldRefreshCategory);
             }
 
             // Launch a full preview activity for devices supporting multipanel mode
diff --git a/src/com/android/wallpaper/picker/PreviewFragment.java b/src/com/android/wallpaper/picker/PreviewFragment.java
index 4adb80df..64fba9f7 100755
--- a/src/com/android/wallpaper/picker/PreviewFragment.java
+++ b/src/com/android/wallpaper/picker/PreviewFragment.java
@@ -75,6 +75,7 @@ import com.android.wallpaper.module.InjectorProvider;
 import com.android.wallpaper.module.WallpaperPersister.Destination;
 import com.android.wallpaper.module.WallpaperSetter;
 import com.android.wallpaper.module.logging.UserEventLogger;
+import com.android.wallpaper.picker.common.preview.ui.binder.DefaultWorkspaceCallbackBinder;
 import com.android.wallpaper.util.PreviewUtils;
 import com.android.wallpaper.util.ResourceUtils;
 import com.android.wallpaper.widget.DuoTabs;
@@ -575,8 +576,8 @@ public abstract class PreviewFragment extends Fragment implements WallpaperColor
     private void hideBottomRow(boolean hide) {
         if (mWorkspaceSurfaceCallback != null) {
             Bundle data = new Bundle();
-            data.putBoolean(WorkspaceSurfaceHolderCallback.KEY_HIDE_BOTTOM_ROW, hide);
-            mWorkspaceSurfaceCallback.send(WorkspaceSurfaceHolderCallback.MESSAGE_ID_UPDATE_PREVIEW,
+            data.putBoolean(DefaultWorkspaceCallbackBinder.KEY_HIDE_BOTTOM_ROW, hide);
+            mWorkspaceSurfaceCallback.send(DefaultWorkspaceCallbackBinder.MESSAGE_ID_UPDATE_PREVIEW,
                     data);
         }
     }
diff --git a/src/com/android/wallpaper/picker/ViewOnlyPreviewActivity.java b/src/com/android/wallpaper/picker/ViewOnlyPreviewActivity.java
index 4d1b398e..44d6ca54 100644
--- a/src/com/android/wallpaper/picker/ViewOnlyPreviewActivity.java
+++ b/src/com/android/wallpaper/picker/ViewOnlyPreviewActivity.java
@@ -105,14 +105,15 @@ public class ViewOnlyPreviewActivity extends BasePreviewActivity implements Appb
 
         @Override
         public Intent newIntent(Context context, WallpaperInfo wallpaper,
-                boolean isAssetIdPresent) {
+                boolean isAssetIdPresent, boolean shouldRefreshCategory) {
             Context appContext = context.getApplicationContext();
             LargeScreenMultiPanesChecker multiPanesChecker = new LargeScreenMultiPanesChecker();
             final boolean isMultiPanel = multiPanesChecker.isMultiPanesEnabled(appContext);
             final BaseFlags flags = InjectorProvider.getInjector().getFlags();
             if (flags.isMultiCropEnabled()) {
                 return WallpaperPreviewActivity.Companion.newIntent(appContext, wallpaper,
-                        isAssetIdPresent, mIsViewAsHome, /* isNewTask= */ isMultiPanel);
+                        isAssetIdPresent, mIsViewAsHome, /* isNewTask= */ isMultiPanel,
+                        shouldRefreshCategory);
             }
 
             // Launch a full preview activity for devices supporting multipanel mode
diff --git a/src/com/android/wallpaper/picker/WallpaperInfoHelper.java b/src/com/android/wallpaper/picker/WallpaperInfoHelper.java
index 3d149f1b..d78189a4 100644
--- a/src/com/android/wallpaper/picker/WallpaperInfoHelper.java
+++ b/src/com/android/wallpaper/picker/WallpaperInfoHelper.java
@@ -24,6 +24,7 @@ import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
 import com.android.wallpaper.R;
+import com.android.wallpaper.model.LiveWallpaperInfo;
 import com.android.wallpaper.model.WallpaperInfo;
 import com.android.wallpaper.module.ExploreIntentChecker;
 import com.android.wallpaper.module.InjectorProvider;
@@ -44,7 +45,7 @@ public class WallpaperInfoHelper {
             @NonNull WallpaperInfo wallpaperInfo,
             @NonNull ExploreIntentReceiver callback) {
         String actionUrl = wallpaperInfo.getActionUrl(context);
-        CharSequence actionLabel = context.getString(R.string.explore);
+        CharSequence actionLabel = getActionLabel(context, wallpaperInfo);
         if (actionUrl != null && !actionUrl.isEmpty()) {
             Uri exploreUri = Uri.parse(wallpaperInfo.getActionUrl(context));
             ExploreIntentChecker intentChecker =
@@ -56,24 +57,16 @@ public class WallpaperInfoHelper {
         }
     }
 
-    /**
-     * Loads the explore Intent from the actionUrl
-     */
-    public static void loadExploreIntent(
-            Context context,
-            @Nullable String actionUrl,
-            @NonNull ExploreIntentReceiver callback) {
-        CharSequence actionLabel = context.getString(R.string.explore);
+    private static CharSequence getActionLabel(Context context, WallpaperInfo wallpaperInfo) {
+        CharSequence actionLabel = null;
+        if (wallpaperInfo instanceof LiveWallpaperInfo) {
+            actionLabel = ((LiveWallpaperInfo) wallpaperInfo).getActionDescription(context);
+        }
 
-        if (!TextUtils.isEmpty(actionUrl)) {
-            Uri exploreUri = Uri.parse(actionUrl);
-            ExploreIntentChecker intentChecker =
-                    InjectorProvider.getInjector().getExploreIntentChecker(context);
-            intentChecker.fetchValidActionViewIntent(exploreUri,
-                    intent -> callback.onReceiveExploreIntent(actionLabel, intent));
-        } else {
-            callback.onReceiveExploreIntent(actionLabel, null);
+        if (TextUtils.isEmpty(actionLabel)) {
+            actionLabel = context.getString(R.string.explore);
         }
+        return actionLabel;
     }
 
     /** Indicates if the explore button should show up in the wallpaper info view. */
diff --git a/src/com/android/wallpaper/picker/WallpaperPickerDelegate.java b/src/com/android/wallpaper/picker/WallpaperPickerDelegate.java
index b71990d2..b6c802f2 100644
--- a/src/com/android/wallpaper/picker/WallpaperPickerDelegate.java
+++ b/src/com/android/wallpaper/picker/WallpaperPickerDelegate.java
@@ -32,6 +32,7 @@ import androidx.annotation.Nullable;
 import androidx.fragment.app.FragmentActivity;
 
 import com.android.wallpaper.R;
+import com.android.wallpaper.config.BaseFlags;
 import com.android.wallpaper.model.Category;
 import com.android.wallpaper.model.CategoryProvider;
 import com.android.wallpaper.model.CategoryReceiver;
@@ -67,6 +68,7 @@ public class WallpaperPickerDelegate implements MyPhotosStarter {
     private final MyPhotosIntentProvider mMyPhotosIntentProvider;
     private WallpaperPreferences mPreferences;
     private PackageStatusNotifier mPackageStatusNotifier;
+    private BaseFlags mFlags;
 
     private List<PermissionChangedListener> mPermissionChangedListeners;
     private PackageStatusNotifier.Listener mLiveWallpaperStatusListener;
@@ -81,7 +83,7 @@ public class WallpaperPickerDelegate implements MyPhotosStarter {
             Injector injector) {
         mContainer = container;
         mActivity = activity;
-
+        mFlags = injector.getFlags();
         mCategoryProvider = injector.getCategoryProvider(activity);
         mPreferences = injector.getPreferences(activity);
 
@@ -94,28 +96,31 @@ public class WallpaperPickerDelegate implements MyPhotosStarter {
     }
 
     public void initialize(boolean forceCategoryRefresh) {
-        populateCategories(forceCategoryRefresh);
-        mLiveWallpaperStatusListener = this::updateLiveWallpapersCategories;
-        mThirdPartyStatusListener = this::updateThirdPartyCategories;
-        mPackageStatusNotifier.addListener(
-                mLiveWallpaperStatusListener,
-                WallpaperService.SERVICE_INTERFACE);
-        mPackageStatusNotifier.addListener(mThirdPartyStatusListener, Intent.ACTION_SET_WALLPAPER);
-        if (mDownloadableIntentAction != null) {
-            mDownloadableWallpaperStatusListener = (packageName, status) -> {
-                if (status != PackageStatusNotifier.PackageStatus.REMOVED) {
-                    populateCategories(/* forceRefresh= */ true);
-                }
-            };
+        if (!mFlags.isWallpaperCategoryRefactoringEnabled()) {
+            populateCategories(forceCategoryRefresh);
+            mLiveWallpaperStatusListener = this::updateLiveWallpapersCategories;
+            mThirdPartyStatusListener = this::updateThirdPartyCategories;
             mPackageStatusNotifier.addListener(
-                    mDownloadableWallpaperStatusListener, mDownloadableIntentAction);
+                    mLiveWallpaperStatusListener,
+                    WallpaperService.SERVICE_INTERFACE);
+            mPackageStatusNotifier.addListener(mThirdPartyStatusListener,
+                    Intent.ACTION_SET_WALLPAPER);
+            if (mDownloadableIntentAction != null) {
+                mDownloadableWallpaperStatusListener = (packageName, status) -> {
+                    if (status != PackageStatusNotifier.PackageStatus.REMOVED) {
+                        populateCategories(/* forceRefresh= */ true);
+                    }
+                };
+                mPackageStatusNotifier.addListener(
+                        mDownloadableWallpaperStatusListener, mDownloadableIntentAction);
+            }
         }
     }
 
     @Override
     public void requestCustomPhotoPicker(PermissionChangedListener listener) {
         //TODO (b/282073506): Figure out a better way to have better photos experience
-        if (DISABLE_MY_PHOTOS_BLOCK_PREVIEW) {
+        if (mFlags.isWallpaperCategoryRefactoringEnabled()) {
             if (!isReadExternalStoragePermissionGranted()) {
                 PermissionChangedListener wrappedListener = new PermissionChangedListener() {
                     @Override
diff --git a/src/com/android/wallpaper/picker/WorkspaceSurfaceHolderCallback.java b/src/com/android/wallpaper/picker/WorkspaceSurfaceHolderCallback.java
index d57fa94c..627928f8 100644
--- a/src/com/android/wallpaper/picker/WorkspaceSurfaceHolderCallback.java
+++ b/src/com/android/wallpaper/picker/WorkspaceSurfaceHolderCallback.java
@@ -21,11 +21,13 @@ import android.os.Message;
 import android.os.RemoteException;
 import android.util.Log;
 import android.view.Surface;
+import android.view.SurfaceControlViewHost;
 import android.view.SurfaceHolder;
 import android.view.SurfaceView;
 
 import androidx.annotation.Nullable;
 
+import com.android.wallpaper.picker.common.preview.ui.binder.DefaultWorkspaceCallbackBinder;
 import com.android.wallpaper.util.PreviewUtils;
 import com.android.wallpaper.util.SurfaceViewUtils;
 
@@ -46,8 +48,6 @@ public class WorkspaceSurfaceHolderCallback implements SurfaceHolder.Callback {
 
     private static final String TAG = "WsSurfaceHolderCallback";
     private static final String KEY_WALLPAPER_COLORS = "wallpaper_colors";
-    public static final int MESSAGE_ID_UPDATE_PREVIEW = 1337;
-    public static final String KEY_HIDE_BOTTOM_ROW = "hide_bottom_row";
     public static final int MESSAGE_ID_COLOR_OVERRIDE = 1234;
     public static final String KEY_COLOR_OVERRIDE = "color_override"; // ColorInt Encoded as string
     private final SurfaceView mWorkspaceSurface;
@@ -161,9 +161,16 @@ public class WorkspaceSurfaceHolderCallback implements SurfaceHolder.Callback {
         requestPreview(mWorkspaceSurface, (result) -> {
             mRequestPending.set(false);
             if (result != null && mLastSurface != null) {
-                mWorkspaceSurface.setChildSurfacePackage(
-                        SurfaceViewUtils.getSurfacePackage(result));
-                mCallback = SurfaceViewUtils.getCallback(result);
+                final SurfaceControlViewHost.SurfacePackage pkg =
+                        SurfaceViewUtils.INSTANCE.getSurfacePackage(result);
+                if (pkg != null) {
+                    mWorkspaceSurface.setChildSurfacePackage(pkg);
+                } else {
+                    Log.w(TAG,
+                            "Result bundle from rendering preview does not contain a child "
+                                    + "surface package.");
+                }
+                mCallback = SurfaceViewUtils.INSTANCE.getCallback(result);
                 if (mCallback != null && mDelayedMessage != null) {
                     try {
                         mCallback.replyTo.send(mDelayedMessage);
@@ -246,11 +253,12 @@ public class WorkspaceSurfaceHolderCallback implements SurfaceHolder.Callback {
                             + "crash");
             return;
         }
-        Bundle request = SurfaceViewUtils.createSurfaceViewRequest(workspaceSurface, mExtras);
+        Bundle request = SurfaceViewUtils.INSTANCE.createSurfaceViewRequest(workspaceSurface,
+                mExtras);
         if (mWallpaperColors != null) {
             request.putParcelable(KEY_WALLPAPER_COLORS, mWallpaperColors);
         }
-        request.putBoolean(KEY_HIDE_BOTTOM_ROW, mHideBottomRow);
+        request.putBoolean(DefaultWorkspaceCallbackBinder.KEY_HIDE_BOTTOM_ROW, mHideBottomRow);
         mPreviewUtils.renderPreview(request, callback);
     }
 }
diff --git a/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcher.kt b/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcher.kt
index 632682a7..93d95846 100644
--- a/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcher.kt
+++ b/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcher.kt
@@ -23,7 +23,7 @@ import android.content.IntentFilter
 import android.os.Handler
 import android.os.Looper
 import com.android.systemui.dagger.qualifiers.Main
-import com.android.wallpaper.picker.di.modules.ConcurrencyModule.*
+import com.android.wallpaper.picker.di.modules.SharedAppModule.Companion.BroadcastRunning
 import java.util.concurrent.Executor
 import javax.inject.Inject
 import javax.inject.Singleton
diff --git a/src/com/android/wallpaper/picker/category/client /DefaultWallpaperCategoryClient.kt b/src/com/android/wallpaper/picker/category/client /DefaultWallpaperCategoryClient.kt
index 4e6e3603..85082705 100644
--- a/src/com/android/wallpaper/picker/category/client /DefaultWallpaperCategoryClient.kt	
+++ b/src/com/android/wallpaper/picker/category/client /DefaultWallpaperCategoryClient.kt	
@@ -16,129 +16,45 @@
 
 package com.android.wallpaper.picker.category.client
 
-import android.content.Context
-import com.android.wallpaper.R
-import com.android.wallpaper.model.DefaultWallpaperInfo
-import com.android.wallpaper.model.ImageCategory
-import com.android.wallpaper.model.LegacyPartnerWallpaperInfo
-import com.android.wallpaper.model.WallpaperCategory
-import com.android.wallpaper.model.WallpaperInfo
-import com.android.wallpaper.module.PartnerProvider
-import com.android.wallpaper.picker.data.category.CategoryModel
-import com.android.wallpaper.util.WallpaperParser
-import com.android.wallpaper.util.converter.category.CategoryFactory
-import dagger.hilt.android.qualifiers.ApplicationContext
-import java.util.Locale
-import javax.inject.Inject
-import javax.inject.Singleton
+import com.android.wallpaper.model.Category
 
-/**
- * This class is responsible for fetching wallpaper categories, listed as follows:
- * 1. MyPhotos category that allows users to select custom photos
- * 2. OnDevice category that are pre-loaded wallpapers on device (legacy way of pre-loading
- *    wallpapers, modern way is described below)
- * 3. System categories on device (modern way of pre-loading wallpapers on device)
- */
-@Singleton
-class DefaultWallpaperCategoryClient
-@Inject
-constructor(
-    @ApplicationContext val context: Context,
-    private val partnerProvider: PartnerProvider,
-    private val categoryFactory: CategoryFactory,
-    private val wallpaperXMLParser: WallpaperParser
-) : WallpaperCategoryClient {
-
-    /** This method is used for fetching and creating the MyPhotos category tile. */
-    fun getMyPhotosCategory(): CategoryModel {
-        val imageCategory =
-            ImageCategory(
-                context.getString(R.string.my_photos_category_title),
-                context.getString(R.string.image_wallpaper_collection_id),
-                PRIORITY_MY_PHOTOS_WHEN_CREATIVE_WALLPAPERS_ENABLED,
-                R.drawable.wallpaperpicker_emptystate /* overlayIconResId */
-            )
-        return categoryFactory.getCategoryModel(context, imageCategory)
-    }
+/** This class is responsible for fetching categories and wallpaper info. from external sources. */
+interface DefaultWallpaperCategoryClient {
 
     /**
-     * This method is used for fetching the on-device categories. This returns a category which
-     * incorporates both GEL and bundled wallpapers.
+     * This method is used for fetching the system categories.
      */
-    suspend fun getOnDeviceCategory(): CategoryModel? {
-        val onDeviceWallpapers = mutableListOf<WallpaperInfo?>()
-
-        if (!partnerProvider.shouldHideDefaultWallpaper()) {
-            val defaultWallpaperInfo = DefaultWallpaperInfo()
-            onDeviceWallpapers.add(defaultWallpaperInfo)
-        }
-
-        val partnerWallpaperInfos = wallpaperXMLParser.parsePartnerWallpaperInfoResources()
-        onDeviceWallpapers.addAll(partnerWallpaperInfos)
-
-        val legacyPartnerWallpaperInfos = LegacyPartnerWallpaperInfo.getAll(context)
-        onDeviceWallpapers.addAll(legacyPartnerWallpaperInfos)
+    suspend fun getSystemCategories(): List<Category>
 
-        val privateWallpapers = getPrivateDeviceWallpapers()
-        privateWallpapers?.let { onDeviceWallpapers.addAll(it) }
-
-        return onDeviceWallpapers
-            .takeIf { it.isNotEmpty() }
-            ?.let {
-                val wallpaperCategory =
-                    WallpaperCategory(
-                        context.getString(R.string.on_device_wallpapers_category_title),
-                        context.getString(R.string.on_device_wallpaper_collection_id),
-                        it,
-                        PRIORITY_ON_DEVICE
-                    )
-                categoryFactory.getCategoryModel(context, wallpaperCategory)
-            }
-    }
-
-    /** This method is used for fetching the system categories. */
-    override suspend fun getCategories(): List<CategoryModel> {
-        val partnerRes = partnerProvider.resources
-        val packageName = partnerProvider.packageName
-        val categoryModels = mutableListOf<CategoryModel>()
-        if (partnerRes == null || packageName == null) {
-            return categoryModels
-        }
-
-        val wallpapersResId =
-            partnerRes.getIdentifier(PartnerProvider.WALLPAPER_RES_ID, "xml", packageName)
-        // Certain partner configurations don't have wallpapers provided, so need to check;
-        // return early if they are missing.
-        if (wallpapersResId == 0) {
-            return categoryModels
-        }
+    /**
+     * This method is used for fetching the MyPhotos category.
+     */
+    suspend fun getMyPhotosCategory(): Category
 
-        val categories =
-            wallpaperXMLParser.parseSystemCategories(partnerRes.getXml(wallpapersResId))
-        return categories.map { category -> categoryFactory.getCategoryModel(context, category) }
-    }
+    /**
+     * This method is used for fetching the pre-loaded on device categories.
+     */
+    suspend fun getOnDeviceCategory(): Category?
 
-    private fun getLocale(): Locale {
-        return context.resources.configuration.locales.get(0)
-    }
+    /**
+     * This method is used for fetching the third party categories.
+     */
+    suspend fun getThirdPartyCategory(excludedPackageNames: List<String>): List<Category>
 
-    private fun getPrivateDeviceWallpapers(): Collection<WallpaperInfo?>? {
-        return null
-    }
+    /**
+     * This method is used for fetching the package names that should not be included in third
+     * party categories.
+     */
+    fun getExcludedThirdPartyPackageNames(): List<String>
 
-    companion object {
-        private const val TAG = "DefaultWallpaperCategoryClient"
+    /**
+     * This method is used for fetching the third party live wallpaper categories.
+     */
+    suspend fun getThirdPartyLiveWallpaperCategory(excludedPackageNames: Set<String>): List<Category>
 
-        /**
-         * Relative category priorities. Lower numbers correspond to higher priorities (i.e., should
-         * appear higher in the categories list).
-         */
-        const val PRIORITY_MY_PHOTOS_WHEN_CREATIVE_WALLPAPERS_DISABLED = 1
-        private const val PRIORITY_MY_PHOTOS_WHEN_CREATIVE_WALLPAPERS_ENABLED = 51
-        private const val PRIORITY_SYSTEM = 100
-        private const val PRIORITY_ON_DEVICE = 200
-        private const val PRIORITY_LIVE = 300
-        private const val PRIORITY_THIRD_PARTY = 400
-        const val CREATIVE_CATEGORY_PRIORITY = 1
-    }
+    /**
+     * This method is used for returning the package names that should not be included
+     * in live wallpaper categories.
+     */
+    fun getExcludedLiveWallpaperPackageNames(): Set<String>
 }
diff --git a/src/com/android/wallpaper/picker/category/client /DefaultWallpaperCategoryClientImpl.kt b/src/com/android/wallpaper/picker/category/client /DefaultWallpaperCategoryClientImpl.kt
new file mode 100644
index 00000000..57f4768e
--- /dev/null
+++ b/src/com/android/wallpaper/picker/category/client /DefaultWallpaperCategoryClientImpl.kt	
@@ -0,0 +1,217 @@
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
+package com.android.wallpaper.picker.category.client
+
+import android.content.ComponentName
+import android.content.Context
+import android.content.Intent
+import android.content.pm.PackageManager
+import androidx.annotation.XmlRes
+import com.android.wallpaper.R
+import com.android.wallpaper.model.Category
+import com.android.wallpaper.model.DefaultWallpaperInfo
+import com.android.wallpaper.model.ImageCategory
+import com.android.wallpaper.model.LegacyPartnerWallpaperInfo
+import com.android.wallpaper.model.LiveWallpaperInfo
+import com.android.wallpaper.model.ThirdPartyAppCategory
+import com.android.wallpaper.model.ThirdPartyLiveWallpaperCategory
+import com.android.wallpaper.model.WallpaperCategory
+import com.android.wallpaper.model.WallpaperInfo
+import com.android.wallpaper.module.DefaultCategoryProvider
+import com.android.wallpaper.module.PartnerProvider
+import com.android.wallpaper.util.WallpaperParser
+import dagger.hilt.android.qualifiers.ApplicationContext
+import java.util.Locale
+import javax.inject.Inject
+import javax.inject.Singleton
+
+/**
+ * This class is responsible for fetching wallpaper categories, listed as follows:
+ * 1. MyPhotos category that allows users to select custom photos
+ * 2. OnDevice category that are pre-loaded wallpapers on device (legacy way of pre-loading
+ *    wallpapers, modern way is described below)
+ * 3. System categories on device (modern way of pre-loading wallpapers on device)
+ * 4. Third party app categories
+ */
+@Singleton
+class DefaultWallpaperCategoryClientImpl
+@Inject
+constructor(
+    @ApplicationContext val context: Context,
+    private val partnerProvider: PartnerProvider,
+    private val wallpaperXMLParser: WallpaperParser,
+    private val liveWallpapersClient: LiveWallpapersClient
+) : DefaultWallpaperCategoryClient {
+
+    private var systemCategories: List<Category>? = null
+
+    /** This method is used for fetching and creating the MyPhotos category tile. */
+    override suspend fun getMyPhotosCategory(): Category {
+        val imageCategory = ImageCategory(
+                    context.getString(R.string.my_photos_category_title),
+                    context.getString(R.string.image_wallpaper_collection_id),
+                    PRIORITY_MY_PHOTOS_WHEN_CREATIVE_WALLPAPERS_ENABLED,
+                    R.drawable.wallpaperpicker_emptystate, /* overlayIconResId */
+            )
+        return imageCategory
+    }
+
+    /**
+     * This method is used for fetching the on-device categories. This returns a category which
+     * incorporates both GEL and bundled wallpapers.
+     */
+    override suspend fun getOnDeviceCategory(): Category? {
+        val onDeviceWallpapers = mutableListOf<WallpaperInfo?>()
+
+        if (!partnerProvider.shouldHideDefaultWallpaper()) {
+            val defaultWallpaperInfo = DefaultWallpaperInfo()
+            onDeviceWallpapers.add(defaultWallpaperInfo)
+        }
+
+        val partnerWallpaperInfos = wallpaperXMLParser.parsePartnerWallpaperInfoResources()
+        onDeviceWallpapers.addAll(partnerWallpaperInfos)
+
+        val legacyPartnerWallpaperInfos = LegacyPartnerWallpaperInfo.getAll(context)
+        onDeviceWallpapers.addAll(legacyPartnerWallpaperInfos)
+
+        val privateWallpapers = getPrivateDeviceWallpapers()
+        privateWallpapers?.let { onDeviceWallpapers.addAll(it) }
+
+        return onDeviceWallpapers
+            .takeIf { it.isNotEmpty() }
+            ?.let {
+                val wallpaperCategory =
+                    WallpaperCategory(
+                        context.getString(R.string.on_device_wallpapers_category_title),
+                        context.getString(R.string.on_device_wallpaper_collection_id),
+                        it,
+                        PRIORITY_ON_DEVICE
+                    )
+                wallpaperCategory
+            }
+    }
+
+    override suspend fun getThirdPartyCategory
+                (excludedPackageNames: List<String>): List<Category> {
+        val pickWallpaperIntent = Intent(Intent.ACTION_SET_WALLPAPER)
+        val apps = context.packageManager.queryIntentActivities(pickWallpaperIntent, 0)
+
+        // Get list of image picker intents.
+        val pickImageIntent = Intent(Intent.ACTION_GET_CONTENT)
+        pickImageIntent.setType("image/*")
+        val imagePickerActivities = context.packageManager.queryIntentActivities(pickImageIntent, 0)
+
+        val thirdPartyApps = apps.mapNotNull { info ->
+            val itemComponentName = ComponentName(info.activityInfo.packageName, info.activityInfo.name)
+            val itemPackageName = itemComponentName.packageName
+
+            if (excludedPackageNames.contains(itemPackageName) ||
+                    itemPackageName == context.packageName ||
+                    imagePickerActivities.any { it.activityInfo.packageName == itemPackageName }) {
+                null
+            } else {
+                ThirdPartyAppCategory(
+                        context,
+                        info, context.getString(R.string.third_party_app_wallpaper_collection_id) + "_" + itemPackageName,
+                        PRIORITY_THIRD_PARTY
+                )
+            }
+        }
+
+        return thirdPartyApps
+    }
+
+    override suspend fun getThirdPartyLiveWallpaperCategory
+                (excludedPackageNames: Set<String>): List<Category> {
+        if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_LIVE_WALLPAPER)) {
+            val liveWallpapers = liveWallpapersClient.getAll(excludedPackageNames)
+            if (liveWallpapers.isNotEmpty()) {
+                val thirdPartyLiveWallpaperCategory = ThirdPartyLiveWallpaperCategory(
+                    context.getString(R.string.live_wallpapers_category_title),
+                    context.getString(R.string.live_wallpaper_collection_id), liveWallpapers,
+                    PRIORITY_LIVE, getExcludedLiveWallpaperPackageNames())
+                return listOf(thirdPartyLiveWallpaperCategory)
+            }
+        }
+        return listOf()
+    }
+
+    override fun getExcludedLiveWallpaperPackageNames(): Set<String> {
+        val excluded = mutableSetOf<String>()
+        systemCategories?.forEach { category ->
+            if (category is WallpaperCategory) {
+                category.wallpapers.forEach { wallpaperInfo ->
+                    if (wallpaperInfo is LiveWallpaperInfo) {
+                        excluded.add(wallpaperInfo.wallpaperComponent.packageName)
+                    }
+                }
+            }
+        }
+        return excluded
+    }
+
+    override fun getExcludedThirdPartyPackageNames(): List<String> {
+        return listOf(
+                LAUNCHER_PACKAGE,  // Legacy launcher
+                LIVE_WALLPAPER_PICKER) // Live wallpaper picker
+    }
+
+    /** This method is used for fetching the system categories. */
+    override suspend fun getSystemCategories(): List<Category> {
+        systemCategories?.let { return it }
+        val partnerRes = partnerProvider.resources
+        val packageName = partnerProvider.packageName
+        if (partnerRes == null || packageName == null) {
+            return listOf()
+        }
+
+        @XmlRes val wallpapersResId =
+            partnerRes.getIdentifier(PartnerProvider.WALLPAPER_RES_ID, "xml", packageName)
+        // Certain partner configurations don't have wallpapers provided, so need to check;
+        // return early if they are missing.
+        if (wallpapersResId == 0) {
+            return listOf()
+        }
+
+        systemCategories =
+            wallpaperXMLParser.parseSystemCategories(partnerRes.getXml(wallpapersResId))
+        return systemCategories as List<Category>
+    }
+
+    private fun getLocale(): Locale {
+        return context.resources.configuration.locales.get(0)
+    }
+
+    private fun getPrivateDeviceWallpapers(): Collection<WallpaperInfo?>? {
+        return null
+    }
+
+    companion object {
+        private const val TAG = "DefaultWallpaperCategoryClientImpl"
+        private const val LAUNCHER_PACKAGE = "com.android.launcher"
+        private const val LIVE_WALLPAPER_PICKER = "com.android.wallpaper.livepicker"
+
+        /**
+         * Relative category priorities. Lower numbers correspond to higher priorities (i.e., should
+         * appear higher in the categories list).
+         */
+        private const val PRIORITY_MY_PHOTOS_WHEN_CREATIVE_WALLPAPERS_ENABLED = 51
+        private const val PRIORITY_ON_DEVICE = 200
+        private const val PRIORITY_LIVE = 300
+        private const val PRIORITY_THIRD_PARTY = 400
+    }
+}
diff --git a/src/com/android/wallpaper/picker/category/client /LiveWallpapersClient.kt b/src/com/android/wallpaper/picker/category/client /LiveWallpapersClient.kt
new file mode 100644
index 00000000..380a5bec
--- /dev/null
+++ b/src/com/android/wallpaper/picker/category/client /LiveWallpapersClient.kt	
@@ -0,0 +1,34 @@
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
+package com.android.wallpaper.picker.category.client
+
+import android.content.pm.ApplicationInfo
+import android.content.pm.ResolveInfo
+import com.android.wallpaper.model.WallpaperInfo
+
+/**
+ * This class is used for handling all operations related to live wallpapers. This is meant to
+ * contain all methods/functions that LiveWallpaperInfo class currently holds.
+ */
+interface LiveWallpapersClient {
+
+    /**
+     * Retrieves a list of all installed live wallpapers on the device,
+     * excluding those whose package names are specified in the provided set.
+     */
+    fun getAll(excludedPackageNames: Set<String?>?): List<WallpaperInfo>
+}
\ No newline at end of file
diff --git a/src/com/android/wallpaper/picker/category/client /LiveWallpapersClientImpl.kt b/src/com/android/wallpaper/picker/category/client /LiveWallpapersClientImpl.kt
new file mode 100644
index 00000000..bc8da7a5
--- /dev/null
+++ b/src/com/android/wallpaper/picker/category/client /LiveWallpapersClientImpl.kt	
@@ -0,0 +1,120 @@
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
+package com.android.wallpaper.picker.category.client
+
+import android.content.Context
+import android.content.Intent
+import android.content.pm.ApplicationInfo
+import android.content.pm.PackageManager
+import android.content.pm.ResolveInfo
+import android.service.wallpaper.WallpaperService
+import android.util.Log
+import com.android.wallpaper.model.WallpaperInfo
+import com.android.wallpaper.module.InjectorProvider
+import dagger.hilt.android.qualifiers.ApplicationContext
+import org.xmlpull.v1.XmlPullParserException
+import java.io.IOException
+import java.text.Collator
+import javax.inject.Inject
+import javax.inject.Singleton
+
+/**
+ * Defines methods related to handling of live wallpapers.
+ */
+@Singleton
+class LiveWallpapersClientImpl @Inject constructor(@ApplicationContext val context: Context):
+    LiveWallpapersClient {
+
+    override fun getAll(
+        excludedPackageNames: Set<String?>?
+    ): List<WallpaperInfo> {
+        val resolveInfos = getAllOnDevice()
+        val wallpaperInfos: MutableList<WallpaperInfo> = mutableListOf()
+        val factory =
+            InjectorProvider.getInjector().getLiveWallpaperInfoFactory(context)
+
+        resolveInfos.forEach { resolveInfo ->
+            val wallpaperInfo: android.app.WallpaperInfo
+            try {
+                wallpaperInfo = android.app.WallpaperInfo(context, resolveInfo)
+            } catch (e: XmlPullParserException) {
+                Log.w(TAG, "Skipping wallpaper " + resolveInfo.serviceInfo, e)
+                return@forEach
+            } catch (e: IOException) {
+                Log.w(TAG, "Skipping wallpaper " + resolveInfo.serviceInfo, e)
+                return@forEach
+            }
+            if (excludedPackageNames != null
+                && excludedPackageNames.contains(wallpaperInfo.packageName)) {
+                return@forEach
+            }
+            wallpaperInfos.add(factory.getLiveWallpaperInfo(wallpaperInfo))
+        }
+
+        return wallpaperInfos
+    }
+
+    /**
+     * Returns ResolveInfo objects for all live wallpaper services installed on the device. System
+     * wallpapers are listed first, unsorted, with other installed wallpapers following sorted
+     * in alphabetical order.
+     */
+    fun getAllOnDevice(): List<ResolveInfo> {
+        val pm = context.packageManager
+        val packageName = context.packageName
+
+        val resolveInfos = pm.queryIntentServices(
+            Intent(WallpaperService.SERVICE_INTERFACE),
+            PackageManager.GET_META_DATA
+        )
+
+        val wallpaperInfos: MutableList<ResolveInfo> = mutableListOf()
+
+        // Remove the "Rotating Image Wallpaper" live wallpaper, which is owned by this package,
+        // and separate system wallpapers to sort only non-system ones.
+        val iter = resolveInfos.iterator()
+        while (iter.hasNext()) {
+            val resolveInfo = iter.next()
+            if (packageName == resolveInfo.serviceInfo.packageName) {
+                iter.remove()
+            } else if (isSystemApp(resolveInfo.serviceInfo.applicationInfo)) {
+                wallpaperInfos.add(resolveInfo)
+                iter.remove()
+            }
+        }
+
+        if (resolveInfos.isEmpty()) {
+            return wallpaperInfos
+        }
+
+        // Sort non-system wallpapers alphabetically and append them to system ones
+        val collator = Collator.getInstance()
+        resolveInfos.sortWith(compareBy(collator) { it.loadLabel(pm).toString() })
+
+        wallpaperInfos.addAll(resolveInfos)
+
+        return wallpaperInfos
+    }
+
+    private fun isSystemApp(appInfo: ApplicationInfo): Boolean {
+        return (appInfo.flags and (ApplicationInfo.FLAG_SYSTEM
+                or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0 }
+
+    companion object {
+        private const val TAG = "LiveWallpapersClient"
+    }
+}
\ No newline at end of file
diff --git a/src/com/android/wallpaper/picker/category/data/repository/DefaultWallpaperCategoryRepository.kt b/src/com/android/wallpaper/picker/category/data/repository/DefaultWallpaperCategoryRepository.kt
new file mode 100644
index 00000000..985925cb
--- /dev/null
+++ b/src/com/android/wallpaper/picker/category/data/repository/DefaultWallpaperCategoryRepository.kt
@@ -0,0 +1,182 @@
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
+package com.android.wallpaper.picker.category.data.repository
+
+import android.content.Context
+import android.util.Log
+import com.android.wallpaper.config.BaseFlags
+import com.android.wallpaper.model.Category
+import com.android.wallpaper.picker.category.client.DefaultWallpaperCategoryClient
+import com.android.wallpaper.picker.data.category.CategoryModel
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
+import com.android.wallpaper.util.converter.category.CategoryFactory
+import dagger.hilt.android.qualifiers.ApplicationContext
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.launch
+
+@Singleton
+open class DefaultWallpaperCategoryRepository
+@Inject
+constructor(
+    @ApplicationContext val context: Context,
+    private val defaultWallpaperClient: DefaultWallpaperCategoryClient,
+    private val categoryFactory: CategoryFactory,
+    @BackgroundDispatcher private val backgroundScope: CoroutineScope,
+) : WallpaperCategoryRepository {
+
+    private var myPhotosFetchedCategory: Category? = null
+    private var onDeviceFetchedCategory: Category? = null
+    private var thirdPartyFetchedCategory: List<Category> = emptyList()
+    private var systemFetchedCategories: List<Category> = emptyList()
+    private var thirdPartyLiveWallpaperFetchedCategories: List<Category> = emptyList()
+
+    override fun getMyPhotosFetchedCategory(): Category? {
+        return myPhotosFetchedCategory
+    }
+
+    override fun getOnDeviceFetchedCategories(): Category? {
+        return onDeviceFetchedCategory
+    }
+
+    override fun getThirdPartyFetchedCategories(): List<Category> {
+        return thirdPartyFetchedCategory
+    }
+
+    override fun getSystemFetchedCategories(): List<Category> {
+        return systemFetchedCategories
+    }
+
+    override fun getThirdPartyLiveWallpaperFetchedCategories(): List<Category> {
+        return thirdPartyLiveWallpaperFetchedCategories
+    }
+
+    private val _systemCategories = MutableStateFlow<List<CategoryModel>>(emptyList())
+    override val systemCategories: StateFlow<List<CategoryModel>> = _systemCategories.asStateFlow()
+
+    private val _myPhotosCategory = MutableStateFlow<CategoryModel?>(null)
+    override val myPhotosCategory: StateFlow<CategoryModel?> = _myPhotosCategory.asStateFlow()
+
+    private val _onDeviceCategory = MutableStateFlow<CategoryModel?>(null)
+    override val onDeviceCategory: StateFlow<CategoryModel?> = _onDeviceCategory.asStateFlow()
+
+    private val _thirdPartyAppCategory = MutableStateFlow<List<CategoryModel>>(emptyList())
+    override val thirdPartyAppCategory: StateFlow<List<CategoryModel>> =
+        _thirdPartyAppCategory.asStateFlow()
+
+    private val _thirdPartyLiveWallpaperCategory =
+        MutableStateFlow<List<CategoryModel>>(emptyList())
+    override val thirdPartyLiveWallpaperCategory: StateFlow<List<CategoryModel>> =
+        _thirdPartyLiveWallpaperCategory.asStateFlow()
+
+    private val _isDefaultCategoriesFetched = MutableStateFlow(false)
+    override val isDefaultCategoriesFetched: StateFlow<Boolean> =
+        _isDefaultCategoriesFetched.asStateFlow()
+
+    init {
+        if (BaseFlags.get().isWallpaperCategoryRefactoringEnabled()) {
+            backgroundScope.launch { fetchAllCategories() }
+        }
+    }
+
+    private suspend fun fetchAllCategories() {
+        try {
+            fetchSystemCategories()
+            fetchMyPhotosCategory()
+            fetchOnDeviceCategory()
+            fetchThirdPartyAppCategory()
+            fetchThirdPartyLiveWallpaperCategory()
+        } catch (e: Exception) {
+            Log.e(TAG, "Error fetching default categories", e)
+        } finally {
+            _isDefaultCategoriesFetched.value = true
+        }
+    }
+
+    private suspend fun fetchThirdPartyLiveWallpaperCategory() {
+        try {
+            val excludedPackageNames = defaultWallpaperClient.getExcludedLiveWallpaperPackageNames()
+            thirdPartyLiveWallpaperFetchedCategories =
+                defaultWallpaperClient.getThirdPartyLiveWallpaperCategory(excludedPackageNames)
+            val processedCategories =
+                thirdPartyLiveWallpaperFetchedCategories.map {
+                    categoryFactory.getCategoryModel(it)
+                }
+            _thirdPartyLiveWallpaperCategory.value = processedCategories
+        } catch (e: Exception) {
+            Log.e(TAG, "Error fetching third party live wallpaper categories", e)
+        }
+    }
+
+    private suspend fun fetchSystemCategories() {
+        try {
+            systemFetchedCategories = defaultWallpaperClient.getSystemCategories()
+            val processedCategories =
+                systemFetchedCategories.map { categoryFactory.getCategoryModel(it) }
+            _systemCategories.value = processedCategories
+        } catch (e: Exception) {
+            Log.e(TAG, "Error fetching system categories", e)
+        }
+    }
+
+    override suspend fun fetchMyPhotosCategory() {
+        try {
+            myPhotosFetchedCategory = defaultWallpaperClient.getMyPhotosCategory()
+            myPhotosFetchedCategory.let { category ->
+                _myPhotosCategory.value = category?.let { categoryFactory.getCategoryModel(it) }
+            }
+        } catch (e: Exception) {
+            Log.e(TAG, "Error fetching My Photos category", e)
+        }
+    }
+
+    override suspend fun refreshNetworkCategories() {}
+
+    private suspend fun fetchOnDeviceCategory() {
+        try {
+            onDeviceFetchedCategory =
+                (defaultWallpaperClient as? DefaultWallpaperCategoryClient)?.getOnDeviceCategory()
+            _onDeviceCategory.value =
+                onDeviceFetchedCategory?.let { categoryFactory.getCategoryModel(it) }
+        } catch (e: Exception) {
+            Log.e(TAG, "Error fetching On Device category", e)
+        }
+    }
+
+    private suspend fun fetchThirdPartyAppCategory() {
+        try {
+            val excludedPackageNames = defaultWallpaperClient.getExcludedThirdPartyPackageNames()
+            thirdPartyFetchedCategory =
+                defaultWallpaperClient.getThirdPartyCategory(excludedPackageNames)
+            val processedCategories =
+                thirdPartyFetchedCategory.map { category ->
+                    categoryFactory.getCategoryModel(category)
+                }
+            _thirdPartyAppCategory.value = processedCategories
+        } catch (e: Exception) {
+            Log.e(TAG, "Error fetching third party app categories", e)
+        }
+    }
+
+    companion object {
+        private const val TAG = "DefaultWallpaperCategoryRepository"
+    }
+}
diff --git a/src/com/android/wallpaper/picker/category/data/repository/WallpaperCategoryRepository.kt b/src/com/android/wallpaper/picker/category/data/repository/WallpaperCategoryRepository.kt
new file mode 100644
index 00000000..5c7b7524
--- /dev/null
+++ b/src/com/android/wallpaper/picker/category/data/repository/WallpaperCategoryRepository.kt
@@ -0,0 +1,48 @@
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
+package com.android.wallpaper.picker.category.data.repository
+
+import com.android.wallpaper.model.Category
+import com.android.wallpaper.picker.data.category.CategoryModel
+import kotlinx.coroutines.flow.StateFlow
+
+/**
+ * This is the common repository interface that is responsible for communicating with wallpaper
+ * category data clients and also convert them to CategoryData classes.
+ */
+interface WallpaperCategoryRepository {
+    val systemCategories: StateFlow<List<CategoryModel>>
+    val myPhotosCategory: StateFlow<CategoryModel?>
+    val onDeviceCategory: StateFlow<CategoryModel?>
+    val thirdPartyAppCategory: StateFlow<List<CategoryModel>>
+    val thirdPartyLiveWallpaperCategory: StateFlow<List<CategoryModel>>
+    val isDefaultCategoriesFetched: StateFlow<Boolean>
+
+    fun getMyPhotosFetchedCategory(): Category?
+
+    fun getOnDeviceFetchedCategories(): Category?
+
+    fun getThirdPartyFetchedCategories(): List<Category>
+
+    fun getSystemFetchedCategories(): List<Category>
+
+    fun getThirdPartyLiveWallpaperFetchedCategories(): List<Category>
+
+    suspend fun fetchMyPhotosCategory()
+
+    suspend fun refreshNetworkCategories()
+}
diff --git a/src/com/android/wallpaper/picker/category/domain/interactor/CategoriesLoadingStatusInteractor.kt b/src/com/android/wallpaper/picker/category/domain/interactor/CategoriesLoadingStatusInteractor.kt
new file mode 100644
index 00000000..8115f4e7
--- /dev/null
+++ b/src/com/android/wallpaper/picker/category/domain/interactor/CategoriesLoadingStatusInteractor.kt
@@ -0,0 +1,24 @@
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
+package com.android.wallpaper.picker.category.domain.interactor
+
+import kotlinx.coroutines.flow.Flow
+
+/** This interface manages the loading status of the categories screen */
+interface CategoriesLoadingStatusInteractor {
+    val isLoading: Flow<Boolean>
+}
diff --git a/src/com/android/wallpaper/picker/category/domain/interactor/CategoryInteractor.kt b/src/com/android/wallpaper/picker/category/domain/interactor/CategoryInteractor.kt
index 363809ed..f4e694d7 100644
--- a/src/com/android/wallpaper/picker/category/domain/interactor/CategoryInteractor.kt
+++ b/src/com/android/wallpaper/picker/category/domain/interactor/CategoryInteractor.kt
@@ -25,4 +25,6 @@ import kotlinx.coroutines.flow.Flow
  */
 interface CategoryInteractor {
     val categories: Flow<List<CategoryModel>>
+
+    fun refreshNetworkCategories()
 }
diff --git a/src/com/android/wallpaper/picker/category/domain/interactor/CreativeCategoryInteractor.kt b/src/com/android/wallpaper/picker/category/domain/interactor/CreativeCategoryInteractor.kt
index cdf8eaab..16a3d14f 100644
--- a/src/com/android/wallpaper/picker/category/domain/interactor/CreativeCategoryInteractor.kt
+++ b/src/com/android/wallpaper/picker/category/domain/interactor/CreativeCategoryInteractor.kt
@@ -25,4 +25,6 @@ import kotlinx.coroutines.flow.Flow
  */
 interface CreativeCategoryInteractor {
     val categories: Flow<List<CategoryModel>>
+
+    fun updateCreativeCategories()
 }
diff --git a/src/com/android/wallpaper/picker/category/domain/interactor/MyPhotosInteractor.kt b/src/com/android/wallpaper/picker/category/domain/interactor/MyPhotosInteractor.kt
index 256ec447..0a2a1e6f 100644
--- a/src/com/android/wallpaper/picker/category/domain/interactor/MyPhotosInteractor.kt
+++ b/src/com/android/wallpaper/picker/category/domain/interactor/MyPhotosInteractor.kt
@@ -25,4 +25,6 @@ import kotlinx.coroutines.flow.Flow
  */
 interface MyPhotosInteractor {
     val category: Flow<CategoryModel>
+
+    fun updateMyPhotos()
 }
diff --git a/src/com/android/wallpaper/picker/category/client /WallpaperCategoryClient.kt b/src/com/android/wallpaper/picker/category/domain/interactor/ThirdPartyCategoryInteractor.kt
similarity index 65%
rename from src/com/android/wallpaper/picker/category/client /WallpaperCategoryClient.kt
rename to src/com/android/wallpaper/picker/category/domain/interactor/ThirdPartyCategoryInteractor.kt
index 5ab86873..a24ce3b2 100644
--- a/src/com/android/wallpaper/picker/category/client /WallpaperCategoryClient.kt	
+++ b/src/com/android/wallpaper/picker/category/domain/interactor/ThirdPartyCategoryInteractor.kt
@@ -14,16 +14,15 @@
  * limitations under the License.
  */
 
-package com.android.wallpaper.picker.category.client
+package com.android.wallpaper.picker.category.domain.interactor
 
 import com.android.wallpaper.picker.data.category.CategoryModel
+import kotlinx.coroutines.flow.Flow
 
-/** This class is responsible for fetching categories and wallpaper info. from external sources. */
-interface WallpaperCategoryClient {
-
-    /**
-     * Every client using this interface can use this method to get the specific categories they
-     * need.
-     */
-    suspend fun getCategories(): List<CategoryModel>
+/**
+ * Classes that implement this interface implement the business logic for assembling categories from
+ * third party apps
+ */
+interface ThirdPartyCategoryInteractor {
+    val categories: Flow<List<CategoryModel>>
 }
diff --git a/src/com/android/wallpaper/picker/category/domain/interactor/implementations/CategoryInteractorImpl.kt b/src/com/android/wallpaper/picker/category/domain/interactor/implementations/CategoryInteractorImpl.kt
index ea98805f..dde1c99d 100644
--- a/src/com/android/wallpaper/picker/category/domain/interactor/implementations/CategoryInteractorImpl.kt
+++ b/src/com/android/wallpaper/picker/category/domain/interactor/implementations/CategoryInteractorImpl.kt
@@ -16,18 +16,44 @@
 
 package com.android.wallpaper.picker.category.domain.interactor.implementations
 
+import com.android.wallpaper.picker.category.data.repository.WallpaperCategoryRepository
 import com.android.wallpaper.picker.category.domain.interactor.CategoryInteractor
 import com.android.wallpaper.picker.data.category.CategoryModel
 import javax.inject.Inject
 import javax.inject.Singleton
 import kotlinx.coroutines.flow.Flow
-import kotlinx.coroutines.flow.flow
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.filter
+import kotlinx.coroutines.flow.flatMapLatest
 
 /** This class implements the business logic in assembling ungrouped category models */
 @Singleton
-class CategoryInteractorImpl @Inject constructor() : CategoryInteractor {
-    override val categories: Flow<List<CategoryModel>> = flow {
-        // TODO: to provide actual implementation
-        emit(listOf())
-    }
+class CategoryInteractorImpl
+@Inject
+constructor(val defaultWallpaperCategoryRepository: WallpaperCategoryRepository) :
+    CategoryInteractor {
+
+    override val categories: Flow<List<CategoryModel>> =
+        defaultWallpaperCategoryRepository.isDefaultCategoriesFetched
+            .filter { it }
+            .flatMapLatest {
+                combine(
+                    defaultWallpaperCategoryRepository.thirdPartyAppCategory,
+                    defaultWallpaperCategoryRepository.onDeviceCategory,
+                    defaultWallpaperCategoryRepository.systemCategories,
+                    defaultWallpaperCategoryRepository.thirdPartyLiveWallpaperCategory
+                ) {
+                    thirdPartyAppCategory,
+                    onDeviceCategory,
+                    systemCategories,
+                    thirdPartyLiveWallpaperCategory ->
+                    val combinedList =
+                        (thirdPartyAppCategory + systemCategories + thirdPartyLiveWallpaperCategory)
+                    val finalList = onDeviceCategory?.let { combinedList + it } ?: combinedList
+                    // Sort the categories based on their priority value
+                    finalList.sortedBy { it.commonCategoryData.priority }
+                }
+            }
+
+    override fun refreshNetworkCategories() {}
 }
diff --git a/src/com/android/wallpaper/picker/category/domain/interactor/implementations/CreativeCategoryInteractorImpl.kt b/src/com/android/wallpaper/picker/category/domain/interactor/implementations/CreativeCategoryInteractorImpl.kt
index 0499ff25..b56c657e 100644
--- a/src/com/android/wallpaper/picker/category/domain/interactor/implementations/CreativeCategoryInteractorImpl.kt
+++ b/src/com/android/wallpaper/picker/category/domain/interactor/implementations/CreativeCategoryInteractorImpl.kt
@@ -21,13 +21,15 @@ import com.android.wallpaper.picker.data.category.CategoryModel
 import javax.inject.Inject
 import javax.inject.Singleton
 import kotlinx.coroutines.flow.Flow
-import kotlinx.coroutines.flow.flow
+import kotlinx.coroutines.flow.emptyFlow
 
 /** This class implements the business logic in assembling creative category models */
 @Singleton
 class CreativeCategoryInteractorImpl @Inject constructor() : CreativeCategoryInteractor {
-    override val categories: Flow<List<CategoryModel>> = flow {
-        // TODO: to provide concrete implementation
-        emit(listOf())
+    // default implementation of creatives is empty in aosp
+    override val categories: Flow<List<CategoryModel>> = emptyFlow()
+
+    override fun updateCreativeCategories() {
+        // nothing to update in aosp
     }
 }
diff --git a/src/com/android/wallpaper/picker/category/domain/interactor/implementations/DefaultCategoriesLoadingStatusInteractor.kt b/src/com/android/wallpaper/picker/category/domain/interactor/implementations/DefaultCategoriesLoadingStatusInteractor.kt
new file mode 100644
index 00000000..e1bdc9bf
--- /dev/null
+++ b/src/com/android/wallpaper/picker/category/domain/interactor/implementations/DefaultCategoriesLoadingStatusInteractor.kt
@@ -0,0 +1,35 @@
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
+package com.android.wallpaper.picker.category.domain.interactor.implementations
+
+import com.android.wallpaper.picker.category.data.repository.WallpaperCategoryRepository
+import com.android.wallpaper.picker.category.domain.interactor.CategoriesLoadingStatusInteractor
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.map
+
+/** This class manages the loading status of the categories screen for default categories */
+@Singleton
+class DefaultCategoriesLoadingStatusInteractor
+@Inject
+constructor(
+    private val wallpaperCategoryRepository: WallpaperCategoryRepository,
+) : CategoriesLoadingStatusInteractor {
+    override val isLoading: Flow<Boolean> =
+        wallpaperCategoryRepository.isDefaultCategoriesFetched.map { isFetched -> !isFetched }
+}
diff --git a/src/com/android/wallpaper/picker/category/domain/interactor/implementations/MyPhotosInteractorImpl.kt b/src/com/android/wallpaper/picker/category/domain/interactor/implementations/MyPhotosInteractorImpl.kt
index 5e679b5f..356682dd 100644
--- a/src/com/android/wallpaper/picker/category/domain/interactor/implementations/MyPhotosInteractorImpl.kt
+++ b/src/com/android/wallpaper/picker/category/domain/interactor/implementations/MyPhotosInteractorImpl.kt
@@ -16,26 +16,29 @@
 
 package com.android.wallpaper.picker.category.domain.interactor.implementations
 
+import com.android.wallpaper.picker.category.data.repository.WallpaperCategoryRepository
 import com.android.wallpaper.picker.category.domain.interactor.MyPhotosInteractor
 import com.android.wallpaper.picker.data.category.CategoryModel
-import com.android.wallpaper.picker.data.category.CommonCategoryData
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import javax.inject.Inject
 import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.flow.Flow
-import kotlinx.coroutines.flow.flow
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.launch
 
 /** This class implements the business logic in assembling my photos category model */
 @Singleton
-class MyPhotosInteractorImpl @Inject constructor() : MyPhotosInteractor {
-    override val category: Flow<CategoryModel> = flow {
-        // TODO: to provide concrete implementation
-        emit(
-            CategoryModel(
-                CommonCategoryData("", "", 1),
-                /* previewImage= */ null,
-                /* previewImageThumbnail= */ null,
-                /* previewImageThumbnailTransformation= */ null,
-            )
-        )
+class MyPhotosInteractorImpl
+@Inject
+constructor(
+    private val wallpaperCategoryRepository: WallpaperCategoryRepository,
+    @BackgroundDispatcher private val backgroundScope: CoroutineScope
+) : MyPhotosInteractor {
+    override val category: Flow<CategoryModel> =
+        wallpaperCategoryRepository.myPhotosCategory.filterNotNull()
+
+    override fun updateMyPhotos() {
+        backgroundScope.launch { wallpaperCategoryRepository.fetchMyPhotosCategory() }
     }
 }
diff --git a/src/com/android/wallpaper/picker/category/domain/interactor/implementations/ThirdPartyCategoryInteractorImpl.kt b/src/com/android/wallpaper/picker/category/domain/interactor/implementations/ThirdPartyCategoryInteractorImpl.kt
new file mode 100644
index 00000000..3a3aa4b7
--- /dev/null
+++ b/src/com/android/wallpaper/picker/category/domain/interactor/implementations/ThirdPartyCategoryInteractorImpl.kt
@@ -0,0 +1,33 @@
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
+package com.android.wallpaper.picker.category.domain.interactor.implementations
+
+import com.android.wallpaper.picker.category.data.repository.WallpaperCategoryRepository
+import com.android.wallpaper.picker.category.domain.interactor.ThirdPartyCategoryInteractor
+import com.android.wallpaper.picker.data.category.CategoryModel
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.flow.Flow
+
+@Singleton
+class ThirdPartyCategoryInteractorImpl
+@Inject
+constructor(wallpaperCategoryRepository: WallpaperCategoryRepository) :
+    ThirdPartyCategoryInteractor {
+    override val categories: Flow<List<CategoryModel>> =
+        wallpaperCategoryRepository.thirdPartyAppCategory
+}
diff --git a/src/com/android/wallpaper/picker/category/ui/binder/CategoriesBinder.kt b/src/com/android/wallpaper/picker/category/ui/binder/CategoriesBinder.kt
index 394fbb9d..a9149799 100644
--- a/src/com/android/wallpaper/picker/category/ui/binder/CategoriesBinder.kt
+++ b/src/com/android/wallpaper/picker/category/ui/binder/CategoriesBinder.kt
@@ -17,6 +17,7 @@
 package com.android.wallpaper.picker.category.ui.binder
 
 import android.view.View
+import android.widget.ProgressBar
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
@@ -34,11 +35,20 @@ object CategoriesBinder {
         viewModel: CategoriesViewModel,
         windowWidth: Int,
         lifecycleOwner: LifecycleOwner,
+        navigationHandler:
+            (navigationEvent: CategoriesViewModel.NavigationEvent, navLogic: (() -> Unit)?) -> Unit,
     ) {
         // instantiate the grid and assign its adapter and layout configuration
         val sectionsListView = categoriesPage.requireViewById<RecyclerView>(R.id.category_grid)
+        val progressBar: ProgressBar = categoriesPage.requireViewById(R.id.loading_indicator)
         lifecycleOwner.lifecycleScope.launch {
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                launch {
+                    viewModel.isLoading.collect { isLoading ->
+                        progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE
+                        sectionsListView.visibility = if (isLoading) View.GONE else View.VISIBLE
+                    }
+                }
 
                 // bind the state for List<SectionsViewModel>
                 launch {
@@ -46,6 +56,33 @@ object CategoriesBinder {
                         SectionsBinder.bind(sectionsListView, sections, windowWidth, lifecycleOwner)
                     }
                 }
+
+                launch {
+                    viewModel.isConnectionObtained.collect { didNetworkGoFromOffToOn ->
+                        // trigger a refresh of the categories only if network is being enabled
+                        if (didNetworkGoFromOffToOn) {
+                            viewModel.refreshNetworkCategories()
+                        }
+                    }
+                }
+
+                launch {
+                    viewModel.navigationEvents.collect { navigationEvent ->
+                        when (navigationEvent) {
+                            is CategoriesViewModel.NavigationEvent.NavigateToWallpaperCollection,
+                            is CategoriesViewModel.NavigationEvent.NavigateToPreviewScreen,
+                            is CategoriesViewModel.NavigationEvent.NavigateToThirdParty -> {
+                                // Perform navigation with event.data
+                                navigationHandler(navigationEvent, null)
+                            }
+                            CategoriesViewModel.NavigationEvent.NavigateToPhotosPicker -> {
+                                navigationHandler(navigationEvent) {
+                                    viewModel.updateMyPhotosCategory()
+                                }
+                            }
+                        }
+                    }
+                }
             }
         }
     }
diff --git a/src/com/android/wallpaper/picker/category/ui/binder/SectionsBinder.kt b/src/com/android/wallpaper/picker/category/ui/binder/SectionsBinder.kt
index adfaf065..7cc6e3d3 100644
--- a/src/com/android/wallpaper/picker/category/ui/binder/SectionsBinder.kt
+++ b/src/com/android/wallpaper/picker/category/ui/binder/SectionsBinder.kt
@@ -36,7 +36,6 @@ object SectionsBinder {
         lifecycleOwner: LifecycleOwner,
     ) {
         sectionsListView.adapter = CategorySectionsAdapter(sectionsViewModel, windowWidth)
-
         val gridLayoutManager =
             GridLayoutManager(sectionsListView.context, DEFAULT_SPAN).apply {
                 spanSizeLookup =
@@ -47,7 +46,7 @@ object SectionsBinder {
                     }
             }
         sectionsListView.layoutManager = gridLayoutManager
-
+        sectionsListView.removeItemDecorations()
         sectionsListView.addItemDecoration(
             CategoriesGridPaddingDecoration(
                 sectionsListView.context.resources.getDimensionPixelSize(
@@ -58,4 +57,10 @@ object SectionsBinder {
             }
         )
     }
+
+    fun RecyclerView.removeItemDecorations() {
+        while (itemDecorationCount > 0) {
+            removeItemDecorationAt(0)
+        }
+    }
 }
diff --git a/src/com/android/wallpaper/picker/category/ui/view/CategoriesFragment.kt b/src/com/android/wallpaper/picker/category/ui/view/CategoriesFragment.kt
index c6f8b851..229d3726 100644
--- a/src/com/android/wallpaper/picker/category/ui/view/CategoriesFragment.kt
+++ b/src/com/android/wallpaper/picker/category/ui/view/CategoriesFragment.kt
@@ -16,25 +16,49 @@
 
 package com.android.wallpaper.picker.category.ui.view
 
+import android.app.Activity
+import android.content.ComponentName
+import android.content.Intent
+import android.content.pm.ResolveInfo
+import android.net.Uri
 import android.os.Bundle
+import android.provider.Settings
 import android.view.LayoutInflater
 import android.view.View
 import android.view.ViewGroup
+import android.widget.TextView
+import androidx.core.content.ContextCompat
+import androidx.fragment.app.Fragment
 import androidx.fragment.app.activityViewModels
 import androidx.recyclerview.widget.RecyclerView
 import com.android.wallpaper.R
+import com.android.wallpaper.module.MultiPanesChecker
 import com.android.wallpaper.picker.AppbarFragment
+import com.android.wallpaper.picker.CategorySelectorFragment.CategorySelectorFragmentHost
+import com.android.wallpaper.picker.MyPhotosStarter.PermissionChangedListener
+import com.android.wallpaper.picker.WallpaperPickerDelegate.PREVIEW_LIVE_WALLPAPER_REQUEST_CODE
 import com.android.wallpaper.picker.category.ui.binder.CategoriesBinder
+import com.android.wallpaper.picker.category.ui.view.providers.IndividualPickerFactory
 import com.android.wallpaper.picker.category.ui.viewmodel.CategoriesViewModel
+import com.android.wallpaper.picker.common.preview.data.repository.PersistentWallpaperModelRepository
+import com.android.wallpaper.picker.preview.ui.WallpaperPreviewActivity
+import com.android.wallpaper.util.ActivityUtils
 import com.android.wallpaper.util.SizeCalculator
+import com.google.android.material.snackbar.Snackbar
 import dagger.hilt.android.AndroidEntryPoint
+import javax.inject.Inject
 
 /** This fragment displays the user interface for the categories */
 @AndroidEntryPoint(AppbarFragment::class)
 class CategoriesFragment : Hilt_CategoriesFragment() {
 
+    @Inject lateinit var individualPickerFactory: IndividualPickerFactory
+    @Inject lateinit var persistentWallpaperModelRepository: PersistentWallpaperModelRepository
+    @Inject lateinit var multiPanesChecker: MultiPanesChecker
+
     // TODO: this may need to be scoped to fragment if the architecture changes
     private val categoriesViewModel by activityViewModels<CategoriesViewModel>()
+
     override fun onCreateView(
         inflater: LayoutInflater,
         container: ViewGroup?,
@@ -43,12 +67,135 @@ class CategoriesFragment : Hilt_CategoriesFragment() {
         val view =
             inflater.inflate(R.layout.categories_fragment, container, /* attachToRoot= */ false)
 
+        getCategorySelectorFragmentHost()?.let { fragmentHost ->
+            setUpToolbar(view)
+            setTitle(getText(R.string.wallpaper_title))
+        }
+
         CategoriesBinder.bind(
             categoriesPage = view.requireViewById<RecyclerView>(R.id.content_parent),
             viewModel = categoriesViewModel,
             SizeCalculator.getActivityWindowWidthPx(this.activity),
             lifecycleOwner = viewLifecycleOwner,
-        )
+        ) { navigationEvent, callback ->
+            when (navigationEvent) {
+                is CategoriesViewModel.NavigationEvent.NavigateToWallpaperCollection -> {
+                    switchFragment(
+                        individualPickerFactory.getIndividualPickerInstance(
+                            navigationEvent.categoryId,
+                            navigationEvent.categoryType,
+                        )
+                    )
+                }
+                CategoriesViewModel.NavigationEvent.NavigateToPhotosPicker -> {
+                    // make call to permission handler to grab photos and pass callback
+                    getCategorySelectorFragmentHost()
+                        ?.requestCustomPhotoPicker(
+                            object : PermissionChangedListener {
+                                override fun onPermissionsGranted() {
+                                    callback?.invoke()
+                                }
+
+                                override fun onPermissionsDenied(dontAskAgain: Boolean) {
+                                    if (dontAskAgain) {
+                                        showPermissionSnackbar()
+                                    }
+                                }
+                            }
+                        )
+                }
+                is CategoriesViewModel.NavigationEvent.NavigateToThirdParty -> {
+                    startThirdPartyCategoryActivity(
+                        requireActivity(),
+                        SHOW_CATEGORY_REQUEST_CODE,
+                        navigationEvent.resolveInfo,
+                    )
+                }
+                is CategoriesViewModel.NavigationEvent.NavigateToPreviewScreen -> {
+                    val appContext = requireContext().applicationContext
+                    persistentWallpaperModelRepository.setWallpaperModel(
+                        navigationEvent.wallpaperModel
+                    )
+                    val isMultiPanel = multiPanesChecker.isMultiPanesEnabled(appContext)
+                    val previewIntent =
+                        WallpaperPreviewActivity.newIntent(
+                            context = appContext,
+                            isAssetIdPresent = true,
+                            isViewAsHome = true,
+                            isNewTask = isMultiPanel,
+                            shouldCategoryRefresh =
+                                (navigationEvent.categoryType ==
+                                    CategoriesViewModel.CategoryType.CreativeCategories),
+                        )
+                    ActivityUtils.startActivityForResultSafely(
+                        requireActivity(),
+                        previewIntent,
+                        PREVIEW_LIVE_WALLPAPER_REQUEST_CODE, // TODO: provide correct request code
+                    )
+                }
+            }
+        }
         return view
     }
+
+    private fun getCategorySelectorFragmentHost(): CategorySelectorFragmentHost? {
+        return parentFragment as CategorySelectorFragmentHost?
+            ?: activity as CategorySelectorFragmentHost?
+    }
+
+    private fun showPermissionSnackbar() {
+        val snackbar =
+            Snackbar.make(
+                requireView(),
+                R.string.settings_snackbar_description,
+                Snackbar.LENGTH_LONG,
+            )
+        val layout = snackbar.view as Snackbar.SnackbarLayout
+        val textView =
+            layout.findViewById<View>(com.google.android.material.R.id.snackbar_text) as TextView
+        layout.setBackgroundResource(R.drawable.snackbar_background)
+
+        textView.setTextColor(ContextCompat.getColor(requireContext(), R.color.system_on_primary))
+        snackbar.setActionTextColor(
+            ContextCompat.getColor(requireContext(), R.color.system_surface_container)
+        )
+        snackbar.setAction(requireContext().getString(R.string.settings_snackbar_enable)) {
+            startSettings(SETTINGS_APP_INFO_REQUEST_CODE)
+        }
+        snackbar.show()
+    }
+
+    private fun startSettings(resultCode: Int) {
+        val activity = activity ?: return
+        val appInfoIntent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
+        val uri = Uri.fromParts("package", activity.packageName, /* fragment= */ null)
+        appInfoIntent.setData(uri)
+        startActivityForResult(appInfoIntent, resultCode)
+    }
+
+    private fun startThirdPartyCategoryActivity(
+        srcActivity: Activity,
+        requestCode: Int,
+        resolveInfo: ResolveInfo,
+    ) {
+        val itemComponentName =
+            ComponentName(resolveInfo.activityInfo.packageName, resolveInfo.activityInfo.name)
+        val launchIntent = Intent(Intent.ACTION_SET_WALLPAPER)
+        launchIntent.component = itemComponentName
+        ActivityUtils.startActivityForResultSafely(srcActivity, launchIntent, requestCode)
+    }
+
+    private fun switchFragment(fragment: Fragment) {
+        parentFragmentManager
+            .beginTransaction()
+            .replace(R.id.fragment_container, fragment)
+            .addToBackStack(null)
+            .commit()
+        parentFragmentManager.executePendingTransactions()
+    }
+
+    companion object {
+        const val SHOW_CATEGORY_REQUEST_CODE = 0
+        const val SETTINGS_APP_INFO_REQUEST_CODE = 1
+    }
 }
diff --git a/src/com/android/wallpaper/picker/category/ui/view/SectionCardinality.kt b/src/com/android/wallpaper/picker/category/ui/view/SectionCardinality.kt
new file mode 100644
index 00000000..8ceb972a
--- /dev/null
+++ b/src/com/android/wallpaper/picker/category/ui/view/SectionCardinality.kt
@@ -0,0 +1,24 @@
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
+package com.android.wallpaper.picker.category.ui.view
+
+/** The maximum amount of Categories that a section support */
+enum class SectionCardinality {
+    Single,
+    Double,
+    Triple,
+}
diff --git a/src/com/android/wallpaper/picker/category/ui/view/providers/IndividualPickerFactory.kt b/src/com/android/wallpaper/picker/category/ui/view/providers/IndividualPickerFactory.kt
new file mode 100644
index 00000000..0b905f24
--- /dev/null
+++ b/src/com/android/wallpaper/picker/category/ui/view/providers/IndividualPickerFactory.kt
@@ -0,0 +1,32 @@
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
+package com.android.wallpaper.picker.category.ui.view.providers
+
+import androidx.fragment.app.Fragment
+import com.android.wallpaper.picker.category.ui.viewmodel.CategoriesViewModel
+
+/**
+ * This interface provides the signature to classes to provide the correct IndividualPickerFragment
+ */
+interface IndividualPickerFactory {
+    fun getIndividualPickerInstance(collectionId: String): Fragment
+
+    fun getIndividualPickerInstance(
+        collectionId: String,
+        categoryType: CategoriesViewModel.CategoryType
+    ): Fragment
+}
diff --git a/src/com/android/wallpaper/picker/category/ui/view/providers/implementation/DefaultIndividualPickerFactory.kt b/src/com/android/wallpaper/picker/category/ui/view/providers/implementation/DefaultIndividualPickerFactory.kt
new file mode 100644
index 00000000..2ede59af
--- /dev/null
+++ b/src/com/android/wallpaper/picker/category/ui/view/providers/implementation/DefaultIndividualPickerFactory.kt
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
+package com.android.wallpaper.picker.category.ui.view.providers.implementation
+
+import androidx.fragment.app.Fragment
+import com.android.wallpaper.picker.category.ui.view.providers.IndividualPickerFactory
+import com.android.wallpaper.picker.category.ui.viewmodel.CategoriesViewModel
+import com.android.wallpaper.picker.individual.IndividualPickerFragment2
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+/** This class provides the correct IndividualPickerFragment for WPP2 */
+class DefaultIndividualPickerFactory @Inject constructor() : IndividualPickerFactory {
+    override fun getIndividualPickerInstance(collectionId: String): Fragment {
+        return IndividualPickerFragment2.newInstance(collectionId)
+    }
+
+    override fun getIndividualPickerInstance(
+        collectionId: String,
+        categoryType: CategoriesViewModel.CategoryType
+    ): Fragment {
+        return IndividualPickerFragment2.newInstance(collectionId)
+    }
+}
diff --git a/src/com/android/wallpaper/picker/category/ui/view/viewholder/CategorySectionViewHolder.kt b/src/com/android/wallpaper/picker/category/ui/view/viewholder/CategorySectionViewHolder.kt
index bdccbd96..3553c22b 100644
--- a/src/com/android/wallpaper/picker/category/ui/view/viewholder/CategorySectionViewHolder.kt
+++ b/src/com/android/wallpaper/picker/category/ui/view/viewholder/CategorySectionViewHolder.kt
@@ -16,6 +16,7 @@
 
 package com.android.wallpaper.picker.category.ui.view.viewholder
 
+import android.graphics.Rect
 import android.view.View
 import android.widget.TextView
 import androidx.recyclerview.widget.RecyclerView
@@ -64,11 +65,34 @@ class CategorySectionViewHolder(itemView: View, val windowWidth: Int) :
 
         sectionTiles.layoutManager = layoutManager as RecyclerView.LayoutManager?
 
-        if (item.tileViewModels.size > 1) {
-            sectionTitle.text = "Section title" // TODO: update view model to include section title
+        val itemDecoration =
+            HorizontalSpaceItemDecoration(
+                itemView.context.resources
+                    .getDimension(R.dimen.creative_category_grid_padding_horizontal)
+                    .toInt()
+            )
+        sectionTiles.addItemDecoration(itemDecoration)
+
+        if (item.sectionTitle != null) {
+            sectionTitle.text = item.sectionTitle
             sectionTitle.visibility = View.VISIBLE
         } else {
             sectionTitle.visibility = View.GONE
         }
     }
+
+    class HorizontalSpaceItemDecoration(private val horizontalSpace: Int) :
+        RecyclerView.ItemDecoration() {
+
+        override fun getItemOffsets(
+            outRect: Rect,
+            view: View,
+            parent: RecyclerView,
+            state: RecyclerView.State
+        ) {
+            if (parent.getChildAdapterPosition(view) != 0) {
+                outRect.left = horizontalSpace
+            }
+        }
+    }
 }
diff --git a/src/com/android/wallpaper/picker/category/ui/view/viewholder/TileViewHolder.kt b/src/com/android/wallpaper/picker/category/ui/view/viewholder/TileViewHolder.kt
index 90468743..1a68d296 100644
--- a/src/com/android/wallpaper/picker/category/ui/view/viewholder/TileViewHolder.kt
+++ b/src/com/android/wallpaper/picker/category/ui/view/viewholder/TileViewHolder.kt
@@ -21,12 +21,13 @@ import android.graphics.Point
 import android.view.View
 import android.widget.ImageView
 import android.widget.TextView
+import androidx.cardview.widget.CardView
 import androidx.recyclerview.widget.RecyclerView
 import com.android.wallpaper.R
+import com.android.wallpaper.picker.category.ui.view.SectionCardinality
 import com.android.wallpaper.picker.category.ui.viewmodel.TileViewModel
 import com.android.wallpaper.util.ResourceUtils
 import com.android.wallpaper.util.SizeCalculator
-import com.bumptech.glide.Glide
 
 /** Caches and binds [TileViewHolder] to a [WallpaperTileView] */
 class TileViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
@@ -34,11 +35,13 @@ class TileViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
     private var title: TextView
     private var categorySubtitle: TextView
     private var wallpaperCategoryImage: ImageView
+    private var categoryCardView: CardView
 
     init {
         title = itemView.requireViewById(R.id.tile_title)
         categorySubtitle = itemView.requireViewById(R.id.category_title)
         wallpaperCategoryImage = itemView.requireViewById(R.id.image)
+        categoryCardView = itemView.requireViewById(R.id.category)
     }
 
     fun bind(
@@ -48,34 +51,46 @@ class TileViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
         tileCount: Int,
         windowWidth: Int
     ) {
-        // TODO: the tiles binding has a lot more logic which will be handled in a dedicated binder
-        // TODO: size the tiles appropriately
         title.visibility = View.GONE
 
         var tileSize: Point
+        var tileRadius: Int
         // calculate the height
         if (columnCount == 1 && tileCount == 1) {
+            // sections that take 1 column and have 1 tile
             tileSize = SizeCalculator.getCategoryTileSize(itemView.context, windowWidth)
-        } else if (columnCount > 1 && tileCount == 1) {
+            tileRadius = context.resources.getDimension(R.dimen.grid_item_all_radius_small).toInt()
+        } else if (
+            columnCount > 1 &&
+                tileCount == 1 &&
+                item.maxCategoriesInRow == SectionCardinality.Single
+        ) {
+            // sections with more than 1 column and 1 tile
             tileSize = SizeCalculator.getFeaturedCategoryTileSize(itemView.context, windowWidth)
+            tileRadius = tileSize.y
         } else {
+            // sections witch take more than 1 column and have more than 1 tile
             tileSize = SizeCalculator.getFeaturedCategoryTileSize(itemView.context, windowWidth)
             tileSize.y /= 2
+            tileRadius = context.resources.getDimension(R.dimen.grid_item_all_radius).toInt()
         }
+
         wallpaperCategoryImage.getLayoutParams().height = tileSize.y
+        categoryCardView.radius = tileRadius.toFloat()
 
-        if (item.thumbAsset == null) {
+        if (item.thumbnailAsset != null) {
             val placeHolderColor =
                 ResourceUtils.getColorAttr(context, android.R.attr.colorSecondary)
-            item.thumbAsset?.loadDrawable(context, wallpaperCategoryImage, placeHolderColor)
+            item.thumbnailAsset.loadDrawable(context, wallpaperCategoryImage, placeHolderColor)
         } else {
-            // defaulting to solid color if assets are null
+            wallpaperCategoryImage.setImageDrawable(item.defaultDrawable)
             wallpaperCategoryImage.setBackgroundColor(
-                itemView.context.getResources().getColor(R.color.myphoto_background_color)
+                context.resources.getColor(R.color.myphoto_background_color)
             )
-            val nullObj: Any? = null
-            Glide.with(itemView.context).asDrawable().load(nullObj).into(wallpaperCategoryImage)
         }
         categorySubtitle.text = item.text
+
+        // bind the tile action to the button
+        itemView.setOnClickListener { _ -> item.onClicked?.invoke() }
     }
 }
diff --git a/src/com/android/wallpaper/picker/category/ui/viewmodel/CategoriesViewModel.kt b/src/com/android/wallpaper/picker/category/ui/viewmodel/CategoriesViewModel.kt
index 2d3f695c..2f20bfe9 100644
--- a/src/com/android/wallpaper/picker/category/ui/viewmodel/CategoriesViewModel.kt
+++ b/src/com/android/wallpaper/picker/category/ui/viewmodel/CategoriesViewModel.kt
@@ -16,15 +16,30 @@
 
 package com.android.wallpaper.picker.category.ui.viewmodel
 
+import android.content.Context
+import android.content.pm.ResolveInfo
 import androidx.lifecycle.ViewModel
+import androidx.lifecycle.viewModelScope
+import com.android.wallpaper.R
+import com.android.wallpaper.picker.category.domain.interactor.CategoriesLoadingStatusInteractor
 import com.android.wallpaper.picker.category.domain.interactor.CategoryInteractor
 import com.android.wallpaper.picker.category.domain.interactor.CreativeCategoryInteractor
 import com.android.wallpaper.picker.category.domain.interactor.MyPhotosInteractor
+import com.android.wallpaper.picker.category.domain.interactor.ThirdPartyCategoryInteractor
+import com.android.wallpaper.picker.category.ui.view.SectionCardinality
+import com.android.wallpaper.picker.data.WallpaperModel
+import com.android.wallpaper.picker.data.category.CategoryModel
+import com.android.wallpaper.picker.network.domain.NetworkStatusInteractor
 import dagger.hilt.android.lifecycle.HiltViewModel
+import dagger.hilt.android.qualifiers.ApplicationContext
 import javax.inject.Inject
 import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableSharedFlow
+import kotlinx.coroutines.flow.asSharedFlow
 import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.launch
 
 /** Top level [ViewModel] for the categories screen */
 @HiltViewModel
@@ -32,34 +47,166 @@ class CategoriesViewModel
 @Inject
 constructor(
     private val singleCategoryInteractor: CategoryInteractor,
-    private val creativeWallpaperInteractor: CreativeCategoryInteractor,
+    private val creativeCategoryInteractor: CreativeCategoryInteractor,
     private val myPhotosInteractor: MyPhotosInteractor,
+    private val thirdPartyCategoryInteractor: ThirdPartyCategoryInteractor,
+    private val loadindStatusInteractor: CategoriesLoadingStatusInteractor,
+    private val networkStatusInteractor: NetworkStatusInteractor,
+    @ApplicationContext private val context: Context,
 ) : ViewModel() {
 
-    private val individualSectionViewModels: Flow<List<SectionViewModel>> =
-        singleCategoryInteractor.categories.map { categories ->
-            return@map categories.map { category ->
-                SectionViewModel(
-                    tileViewModels = listOf(TileViewModel(null, category.commonCategoryData.title)),
-                    columnCount = 1
-                )
+    private val _navigationEvents = MutableSharedFlow<NavigationEvent>()
+    val navigationEvents = _navigationEvents.asSharedFlow()
+
+    private fun navigateToWallpaperCollection(collectionId: String, categoryType: CategoryType) {
+        viewModelScope.launch {
+            _navigationEvents.emit(
+                NavigationEvent.NavigateToWallpaperCollection(collectionId, categoryType)
+            )
+        }
+    }
+
+    private fun navigateToPreviewScreen(
+        wallpaperModel: WallpaperModel,
+        categoryType: CategoryType
+    ) {
+        viewModelScope.launch {
+            _navigationEvents.emit(
+                NavigationEvent.NavigateToPreviewScreen(wallpaperModel, categoryType)
+            )
+        }
+    }
+
+    private fun navigateToPhotosPicker() {
+        viewModelScope.launch { _navigationEvents.emit(NavigationEvent.NavigateToPhotosPicker) }
+    }
+
+    private fun navigateToThirdPartyApp(resolveInfo: ResolveInfo) {
+        viewModelScope.launch {
+            _navigationEvents.emit(NavigationEvent.NavigateToThirdParty(resolveInfo))
+        }
+    }
+
+    val categoryModelListDifferentiator =
+        { oldList: List<CategoryModel>, newList: List<CategoryModel> ->
+            if (oldList.size != newList.size) {
+                false
+            } else {
+                !oldList.containsAll(newList)
             }
         }
 
-    private val creativeSectionViewModel: Flow<SectionViewModel> =
-        creativeWallpaperInteractor.categories.map { categories ->
-            val tiles =
-                categories.map { category ->
-                    TileViewModel(null, category.commonCategoryData.title)
+    private val thirdPartyCategorySections: Flow<List<SectionViewModel>> =
+        thirdPartyCategoryInteractor.categories
+            .distinctUntilChanged { old, new -> categoryModelListDifferentiator(old, new) }
+            .map { categories ->
+                return@map categories.map { category ->
+                    SectionViewModel(
+                        tileViewModels =
+                            listOf(
+                                TileViewModel(null, null, category.commonCategoryData.title) {
+                                    category.thirdPartyCategoryData?.resolveInfo?.let {
+                                        navigateToThirdPartyApp(it)
+                                    }
+                                }
+                            ),
+                        columnCount = 1,
+                        sectionTitle = null
+                    )
                 }
-            return@map SectionViewModel(tileViewModels = tiles, columnCount = 3)
+            }
+
+    private val defaultCategorySections: Flow<List<SectionViewModel>> =
+        singleCategoryInteractor.categories
+            .distinctUntilChanged { old, new -> categoryModelListDifferentiator(old, new) }
+            .map { categories ->
+                return@map categories.map { category ->
+                    SectionViewModel(
+                        tileViewModels =
+                            listOf(
+                                TileViewModel(
+                                    defaultDrawable = null,
+                                    thumbnailAsset = category.collectionCategoryData?.thumbAsset,
+                                    text = category.commonCategoryData.title,
+                                ) {
+                                    if (
+                                        category.collectionCategoryData
+                                            ?.isSingleWallpaperCategory == true
+                                    ) {
+                                        navigateToPreviewScreen(
+                                            category.collectionCategoryData.wallpaperModels[0],
+                                            CategoryType.DefaultCategories
+                                        )
+                                    } else {
+                                        navigateToWallpaperCollection(
+                                            category.commonCategoryData.collectionId,
+                                            CategoryType.DefaultCategories
+                                        )
+                                    }
+                                }
+                            ),
+                        columnCount = 1,
+                        sectionTitle = null
+                    )
+                }
+            }
+
+    private val individualSectionViewModels: Flow<List<SectionViewModel>> =
+        combine(defaultCategorySections, thirdPartyCategorySections) { list1, list2 ->
+            list1 + list2
         }
 
+    private val creativeSectionViewModel: Flow<SectionViewModel> =
+        creativeCategoryInteractor.categories
+            .distinctUntilChanged { old, new -> categoryModelListDifferentiator(old, new) }
+            .map { categories ->
+                val tiles =
+                    categories.map { category ->
+                        TileViewModel(
+                            defaultDrawable = null,
+                            thumbnailAsset = category.collectionCategoryData?.thumbAsset,
+                            text = category.commonCategoryData.title,
+                            maxCategoriesInRow = SectionCardinality.Triple,
+                        ) {
+                            if (
+                                category.collectionCategoryData?.isSingleWallpaperCategory == true
+                            ) {
+                                navigateToPreviewScreen(
+                                    category.collectionCategoryData.wallpaperModels[0],
+                                    CategoryType.CreativeCategories
+                                )
+                            } else {
+                                navigateToWallpaperCollection(
+                                    category.commonCategoryData.collectionId,
+                                    CategoryType.CreativeCategories
+                                )
+                            }
+                        }
+                    }
+                return@map SectionViewModel(
+                    tileViewModels = tiles,
+                    columnCount = 3,
+                    sectionTitle = context.getString(R.string.creative_wallpaper_title)
+                )
+            }
+
     private val myPhotosSectionViewModel: Flow<SectionViewModel> =
-        myPhotosInteractor.category.map { category ->
+        myPhotosInteractor.category.distinctUntilChanged().map { category ->
             SectionViewModel(
-                tileViewModels = listOf(TileViewModel(null, category.commonCategoryData.title)),
-                columnCount = 3
+                tileViewModels =
+                    listOf(
+                        TileViewModel(
+                            defaultDrawable = category.imageCategoryData?.defaultDrawable,
+                            thumbnailAsset = category.imageCategoryData?.thumbnailAsset,
+                            text = category.commonCategoryData.title,
+                            maxCategoriesInRow = SectionCardinality.Single,
+                        ) {
+                            // TODO(b/352081782): trigger the effect with effect controller
+                            navigateToPhotosPicker()
+                        }
+                    ),
+                columnCount = 3,
+                sectionTitle = context.getString(R.string.choose_a_wallpaper_section_title)
             )
         }
 
@@ -74,4 +221,49 @@ constructor(
                 addAll(individualViewModels)
             }
         }
+
+    val isLoading: Flow<Boolean> = loadindStatusInteractor.isLoading
+
+    /** A [Flow] to indicate when the network status has been made enabled */
+    val isConnectionObtained: Flow<Boolean> = networkStatusInteractor.isConnectionObtained
+
+    /** This method updates network categories */
+    fun refreshNetworkCategories() {
+        singleCategoryInteractor.refreshNetworkCategories()
+    }
+
+    /** This method updates the photos category */
+    fun updateMyPhotosCategory() {
+        myPhotosInteractor.updateMyPhotos()
+    }
+
+    /** This method updates the specified category */
+    fun refreshCategory() {
+        // update creative categories at this time only
+        creativeCategoryInteractor.updateCreativeCategories()
+    }
+
+    enum class CategoryType {
+        ThirdPartyCategories,
+        DefaultCategories,
+        CreativeCategories,
+        MyPhotosCategories,
+        Default
+    }
+
+    sealed class NavigationEvent {
+        data class NavigateToWallpaperCollection(
+            val categoryId: String,
+            val categoryType: CategoryType
+        ) : NavigationEvent()
+
+        data class NavigateToPreviewScreen(
+            val wallpaperModel: WallpaperModel,
+            val categoryType: CategoryType
+        ) : NavigationEvent()
+
+        object NavigateToPhotosPicker : NavigationEvent()
+
+        data class NavigateToThirdParty(val resolveInfo: ResolveInfo) : NavigationEvent()
+    }
 }
diff --git a/src/com/android/wallpaper/picker/category/ui/viewmodel/SectionViewModel.kt b/src/com/android/wallpaper/picker/category/ui/viewmodel/SectionViewModel.kt
index 6e6d5234..c63ff9d8 100644
--- a/src/com/android/wallpaper/picker/category/ui/viewmodel/SectionViewModel.kt
+++ b/src/com/android/wallpaper/picker/category/ui/viewmodel/SectionViewModel.kt
@@ -20,4 +20,8 @@ package com.android.wallpaper.picker.category.ui.viewmodel
  * This class represents the view model for a single section that can contain a number of individual
  * tiles.
  */
-class SectionViewModel(val tileViewModels: List<TileViewModel>, val columnCount: Int)
+class SectionViewModel(
+    val tileViewModels: List<TileViewModel>,
+    val columnCount: Int,
+    val sectionTitle: String? = null
+)
diff --git a/src/com/android/wallpaper/picker/category/ui/viewmodel/TileViewModel.kt b/src/com/android/wallpaper/picker/category/ui/viewmodel/TileViewModel.kt
index fe5d2a8b..84f1e3fd 100644
--- a/src/com/android/wallpaper/picker/category/ui/viewmodel/TileViewModel.kt
+++ b/src/com/android/wallpaper/picker/category/ui/viewmodel/TileViewModel.kt
@@ -16,7 +16,15 @@
 
 package com.android.wallpaper.picker.category.ui.viewmodel
 
+import android.graphics.drawable.Drawable
 import com.android.wallpaper.asset.Asset
+import com.android.wallpaper.picker.category.ui.view.SectionCardinality
 
 /** This class represents the view model for a single category tile. */
-class TileViewModel(val thumbAsset: Asset?, val text: String, val onClicked: (() -> Unit)? = null)
+class TileViewModel(
+    val defaultDrawable: Drawable?,
+    val thumbnailAsset: Asset?,
+    val text: String,
+    val maxCategoriesInRow: SectionCardinality = SectionCardinality.Single,
+    val onClicked: (() -> Unit)? = null,
+)
diff --git a/src/com/android/wallpaper/picker/category/wrapper/DefaultWallpaperCategoryWrapper.kt b/src/com/android/wallpaper/picker/category/wrapper/DefaultWallpaperCategoryWrapper.kt
new file mode 100644
index 00000000..ce626df2
--- /dev/null
+++ b/src/com/android/wallpaper/picker/category/wrapper/DefaultWallpaperCategoryWrapper.kt
@@ -0,0 +1,66 @@
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
+package com.android.wallpaper.picker.category.wrapper
+
+import com.android.wallpaper.model.Category
+import com.android.wallpaper.picker.category.data.repository.WallpaperCategoryRepository
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+class DefaultWallpaperCategoryWrapper
+@Inject
+constructor(private var defaultWallpaperCategoryRepository: WallpaperCategoryRepository) :
+    WallpaperCategoryWrapper {
+
+    private var categoryMap: Map<String, Category>? = null
+
+    override suspend fun getCategories(
+        forceRefreshLiveWallpaperCategories: Boolean
+    ): List<Category> {
+        val systemCategories = defaultWallpaperCategoryRepository.getSystemFetchedCategories()
+        val thirdPartyCategory = defaultWallpaperCategoryRepository.getThirdPartyFetchedCategories()
+        val myPhotosCategory = defaultWallpaperCategoryRepository.getMyPhotosFetchedCategory()
+        val onDeviceCategory = defaultWallpaperCategoryRepository.getOnDeviceFetchedCategories()
+        val thirdPartyLiveWallpaperFetchedCategory =
+            defaultWallpaperCategoryRepository.getThirdPartyLiveWallpaperFetchedCategories()
+
+        val onDeviceCategories = onDeviceCategory?.let { listOf(it) } ?: emptyList()
+        val myPhotosCategories = myPhotosCategory?.let { listOf(it) } ?: emptyList()
+
+        return myPhotosCategories +
+            onDeviceCategories +
+            thirdPartyCategory +
+            systemCategories +
+            thirdPartyLiveWallpaperFetchedCategory
+    }
+
+    override fun getCategory(
+        categories: List<Category>,
+        collectionId: String,
+        forceRefreshLiveWallpaperCategories: Boolean,
+    ): Category? {
+        if (categoryMap == null) {
+            categoryMap = categories.associateBy { it.collectionId }
+        }
+        return categoryMap?.get(collectionId)
+    }
+
+    override suspend fun refreshLiveWallpaperCategories() {
+        TODO("Not yet implemented")
+    }
+}
diff --git a/src/com/android/wallpaper/picker/category/wrapper/WallpaperCategoryWrapper.kt b/src/com/android/wallpaper/picker/category/wrapper/WallpaperCategoryWrapper.kt
new file mode 100644
index 00000000..23cf9b8f
--- /dev/null
+++ b/src/com/android/wallpaper/picker/category/wrapper/WallpaperCategoryWrapper.kt
@@ -0,0 +1,46 @@
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
+package com.android.wallpaper.picker.category.wrapper
+
+import com.android.wallpaper.model.Category
+
+/**
+ * Temporary wrapper to maintain compatibility with legacy code. It prevents redundant category data
+ * fetches by reusing data fetched via the recommended architecture.
+ */
+interface WallpaperCategoryWrapper {
+
+    /**
+     * This function is used to get categories that have already been fetched. The
+     * forceRefreshLiveWallpapers flag is used to decide whether we should re-fetch live wallpaper
+     * categories or not.
+     */
+    suspend fun getCategories(forceRefreshLiveWallpaperCategories: Boolean): List<Category>
+
+    /**
+     * This function is used to get a single particular category out of all the fetched categories.
+     * It also accepts forceRefreshLiveWallpapers flag in case the category has been updated.
+     */
+    fun getCategory(
+        categories: List<Category>,
+        collectionId: String,
+        forceRefreshLiveWallpaperCategories: Boolean,
+    ): Category?
+
+    /** This function is used to trigger re-fetching live wallpaper categories. */
+    suspend fun refreshLiveWallpaperCategories()
+}
diff --git a/src/com/android/wallpaper/picker/common/icon/ui/viewbinder/IconViewBinder.kt b/src/com/android/wallpaper/picker/common/icon/ui/viewbinder/IconViewBinder.kt
index 79ec5682..b537213b 100644
--- a/src/com/android/wallpaper/picker/common/icon/ui/viewbinder/IconViewBinder.kt
+++ b/src/com/android/wallpaper/picker/common/icon/ui/viewbinder/IconViewBinder.kt
@@ -18,6 +18,7 @@
 package com.android.wallpaper.picker.common.icon.ui.viewbinder
 
 import android.widget.ImageView
+import androidx.appcompat.content.res.AppCompatResources
 import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
 import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
 
@@ -27,7 +28,11 @@ object IconViewBinder {
         viewModel: Icon,
     ) {
         when (viewModel) {
-            is Icon.Resource -> view.setImageResource(viewModel.res)
+            is Icon.Resource -> {
+                val drawable =
+                    AppCompatResources.getDrawable(view.context.applicationContext, viewModel.res)
+                view.setImageDrawable(drawable)
+            }
             is Icon.Loaded -> view.setImageDrawable(viewModel.drawable)
         }
 
diff --git a/src/com/android/wallpaper/picker/common/preview/data/repository/BasePreviewRepository.kt b/src/com/android/wallpaper/picker/common/preview/data/repository/BasePreviewRepository.kt
new file mode 100644
index 00000000..bc9d4519
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/preview/data/repository/BasePreviewRepository.kt
@@ -0,0 +1,36 @@
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
+package com.android.wallpaper.picker.common.preview.data.repository
+
+import com.android.wallpaper.picker.data.WallpaperModel
+import dagger.hilt.android.scopes.ActivityRetainedScoped
+import javax.inject.Inject
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
+
+/** This repository class manages the [WallpaperModel] for the preview screen */
+@ActivityRetainedScoped
+class BasePreviewRepository @Inject constructor() {
+    /** This [WallpaperModel] represents the current selected wallpaper */
+    private val _wallpaperModel = MutableStateFlow<WallpaperModel?>(null)
+    val wallpaperModel: StateFlow<WallpaperModel?> = _wallpaperModel.asStateFlow()
+
+    fun setWallpaperModel(wallpaperModel: WallpaperModel?) {
+        _wallpaperModel.value = wallpaperModel
+    }
+}
diff --git a/src/com/android/wallpaper/picker/common/preview/data/repository/PersistentWallpaperModelRepository.kt b/src/com/android/wallpaper/picker/common/preview/data/repository/PersistentWallpaperModelRepository.kt
new file mode 100644
index 00000000..e9391819
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/preview/data/repository/PersistentWallpaperModelRepository.kt
@@ -0,0 +1,43 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.wallpaper.picker.common.preview.data.repository
+
+import com.android.wallpaper.picker.data.WallpaperModel
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
+
+/**
+ * This application-scoped repository class enables the [WallpaperModel] used for preview to be
+ * shared across activities. It needs to be cleaned up appropriately when it is no longer needed.
+ */
+@Singleton
+class PersistentWallpaperModelRepository @Inject constructor() {
+    /** This [WallpaperModel] represents the current selected wallpaper */
+    private val _wallpaperModel = MutableStateFlow<WallpaperModel?>(null)
+    val wallpaperModel: StateFlow<WallpaperModel?> = _wallpaperModel.asStateFlow()
+
+    fun setWallpaperModel(wallpaperModel: WallpaperModel) {
+        _wallpaperModel.value = wallpaperModel
+    }
+
+    fun cleanup() {
+        _wallpaperModel.value = null
+    }
+}
diff --git a/src/com/android/wallpaper/picker/common/preview/domain/interactor/BasePreviewInteractor.kt b/src/com/android/wallpaper/picker/common/preview/domain/interactor/BasePreviewInteractor.kt
new file mode 100644
index 00000000..4f8f0494
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/preview/domain/interactor/BasePreviewInteractor.kt
@@ -0,0 +1,53 @@
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
+package com.android.wallpaper.picker.common.preview.domain.interactor
+
+import com.android.wallpaper.model.WallpaperModelsPair
+import com.android.wallpaper.picker.common.preview.data.repository.BasePreviewRepository
+import com.android.wallpaper.picker.customization.data.repository.WallpaperRepository
+import com.android.wallpaper.picker.data.WallpaperModel
+import dagger.hilt.android.scopes.ActivityRetainedScoped
+import javax.inject.Inject
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.combine
+
+// Based on WallpaperPreviewInteractor, except cleaned up to only bind wallpaper and workspace
+// (workspace binding to be added). Also included the ability to preview current wallpapers when no
+// previewing wallpaper is set.
+@ActivityRetainedScoped
+class BasePreviewInteractor
+@Inject
+constructor(
+    basePreviewRepository: BasePreviewRepository,
+    wallpaperRepository: WallpaperRepository,
+) {
+    private val previewingWallpaper: StateFlow<WallpaperModel?> =
+        basePreviewRepository.wallpaperModel
+    private val currentWallpapers: Flow<WallpaperModelsPair> =
+        wallpaperRepository.currentWallpaperModels
+
+    val wallpapers: Flow<WallpaperModelsPair> =
+        combine(previewingWallpaper, currentWallpapers) { previewingWallpaper, currentWallpapers ->
+            if (previewingWallpaper != null) {
+                // Preview wallpaper on both the home and lock screens if set.
+                WallpaperModelsPair(previewingWallpaper, null)
+            } else {
+                currentWallpapers
+            }
+        }
+}
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/binder/BasePreviewBinder.kt b/src/com/android/wallpaper/picker/common/preview/ui/binder/BasePreviewBinder.kt
new file mode 100644
index 00000000..2c85af87
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/preview/ui/binder/BasePreviewBinder.kt
@@ -0,0 +1,76 @@
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
+package com.android.wallpaper.picker.common.preview.ui.binder
+
+import android.content.Context
+import android.graphics.Point
+import android.view.View
+import androidx.lifecycle.LifecycleOwner
+import com.android.wallpaper.R
+import com.android.wallpaper.model.Screen
+import com.android.wallpaper.model.wallpaper.DeviceDisplayType
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
+import kotlinx.coroutines.CompletableDeferred
+
+/**
+ * Common base preview binder that is only responsible for binding the workspace and wallpaper, and
+ * uses the [CustomizationPickerViewModel2].
+ */
+// Based on SmallPreviewBinder, except cleaned up to only bind bind wallpaper and workspace
+// (workspace binding to be added). Also we enable a screen to be defined during binding rather than
+// reading from viewModel.isViewAsHome.
+// TODO (b/348462236): bind workspace
+object BasePreviewBinder {
+    fun bind(
+        applicationContext: Context,
+        view: View,
+        viewModel: CustomizationPickerViewModel2,
+        workspaceCallbackBinder: WorkspaceCallbackBinder,
+        screen: Screen,
+        deviceDisplayType: DeviceDisplayType,
+        displaySize: Point,
+        lifecycleOwner: LifecycleOwner,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
+        onClick: (() -> Unit)? = null,
+    ) {
+        view.isClickable = (onClick != null)
+        onClick?.let { view.setOnClickListener { it() } }
+
+        WallpaperPreviewBinder.bind(
+            applicationContext = applicationContext,
+            surfaceView = view.requireViewById(R.id.wallpaper_surface),
+            viewModel = viewModel.basePreviewViewModel,
+            screen = screen,
+            displaySize = displaySize,
+            deviceDisplayType = deviceDisplayType,
+            viewLifecycleOwner = lifecycleOwner,
+            wallpaperConnectionUtils = wallpaperConnectionUtils,
+            isFirstBindingDeferred = isFirstBindingDeferred,
+        )
+
+        WorkspacePreviewBinder.bind(
+            surfaceView = view.requireViewById(R.id.workspace_surface),
+            viewModel = viewModel,
+            workspaceCallbackBinder = workspaceCallbackBinder,
+            screen = screen,
+            deviceDisplayType = deviceDisplayType,
+            lifecycleOwner = lifecycleOwner,
+        )
+    }
+}
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/binder/DefaultWorkspaceCallbackBinder.kt b/src/com/android/wallpaper/picker/common/preview/ui/binder/DefaultWorkspaceCallbackBinder.kt
new file mode 100644
index 00000000..2378194a
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/preview/ui/binder/DefaultWorkspaceCallbackBinder.kt
@@ -0,0 +1,40 @@
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
+package com.android.wallpaper.picker.common.preview.ui.binder
+
+import android.os.Message
+import androidx.lifecycle.LifecycleOwner
+import com.android.wallpaper.model.Screen
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+class DefaultWorkspaceCallbackBinder @Inject constructor() : WorkspaceCallbackBinder {
+
+    override fun bind(
+        workspaceCallback: Message,
+        viewModel: CustomizationOptionsViewModel,
+        screen: Screen,
+        lifecycleOwner: LifecycleOwner,
+    ) {}
+
+    companion object {
+        const val MESSAGE_ID_UPDATE_PREVIEW = 1337
+        const val KEY_HIDE_BOTTOM_ROW = "hide_bottom_row"
+    }
+}
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/binder/StaticPreviewBinder.kt b/src/com/android/wallpaper/picker/common/preview/ui/binder/StaticPreviewBinder.kt
new file mode 100644
index 00000000..7860212d
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/preview/ui/binder/StaticPreviewBinder.kt
@@ -0,0 +1,194 @@
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
+package com.android.wallpaper.picker.common.preview.ui.binder
+
+import android.animation.Animator
+import android.animation.AnimatorListenerAdapter
+import android.graphics.Point
+import android.graphics.Rect
+import android.graphics.RenderEffect
+import android.graphics.Shader
+import android.view.View
+import android.view.animation.Interpolator
+import android.view.animation.PathInterpolator
+import android.widget.ImageView
+import androidx.core.view.doOnLayout
+import androidx.core.view.isVisible
+import com.android.app.tracing.TraceUtils.trace
+import com.android.wallpaper.picker.common.preview.ui.viewmodel.StaticPreviewViewModel
+import com.android.wallpaper.picker.preview.shared.model.CropSizeModel
+import com.android.wallpaper.picker.preview.shared.model.FullPreviewCropModel
+import com.android.wallpaper.picker.preview.ui.util.FullResImageViewUtil
+import com.android.wallpaper.util.RtlUtils
+import com.android.wallpaper.util.WallpaperCropUtils
+import com.android.wallpaper.util.WallpaperSurfaceCallback.LOW_RES_BITMAP_BLUR_RADIUS
+import com.davemorrissey.labs.subscaleview.ImageSource
+import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView
+import kotlin.math.max
+import kotlin.math.min
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.launch
+
+// Based on StaticWallpaperPreviewBinder, mostly unchanged, but located in common preview package,
+// and dependent on the new StaticPreviewViewModel instead of StaticWallpaperPreviewViewModel.
+object StaticPreviewBinder {
+
+    private val ALPHA_OUT: Interpolator = PathInterpolator(0f, 0f, 0.8f, 1f)
+    private const val CROSS_FADE_DURATION: Long = 200
+
+    fun bind(
+        lowResImageView: ImageView,
+        fullResImageView: SubsamplingScaleImageView,
+        viewModel: StaticPreviewViewModel,
+        displaySize: Point,
+        parentCoroutineScope: CoroutineScope,
+        isFullScreen: Boolean = false,
+    ) {
+        lowResImageView.initLowResImageView()
+        fullResImageView.initFullResImageView()
+
+        parentCoroutineScope.launch {
+            // Show low res image only for small preview with supported wallpaper
+            if (!isFullScreen) {
+                launch {
+                    viewModel.lowResBitmap.collect {
+                        it?.let {
+                            lowResImageView.setImageBitmap(it)
+                            lowResImageView.isVisible = true
+                        }
+                    }
+                }
+            }
+
+            launch {
+                viewModel.subsamplingScaleImageViewModel.collect { imageModel ->
+                    trace(TAG) {
+                        val cropHint = imageModel.fullPreviewCropModels?.get(displaySize)?.cropHint
+                        fullResImageView.setFullResImage(
+                            ImageSource.cachedBitmap(imageModel.rawWallpaperBitmap),
+                            imageModel.rawWallpaperSize,
+                            displaySize,
+                            cropHint,
+                            RtlUtils.isRtl(lowResImageView.context),
+                            isFullScreen,
+                        )
+
+                        // Fill in the default crop region if the displaySize for this preview
+                        // is missing.
+                        val imageSize = Point(fullResImageView.width, fullResImageView.height)
+                        viewModel.updateDefaultPreviewCropModel(
+                            displaySize,
+                            FullPreviewCropModel(
+                                cropHint =
+                                    WallpaperCropUtils.calculateVisibleRect(
+                                        imageModel.rawWallpaperSize,
+                                        imageSize,
+                                    ),
+                                cropSizeModel =
+                                    CropSizeModel(
+                                        wallpaperZoom =
+                                            WallpaperCropUtils.calculateMinZoom(
+                                                imageModel.rawWallpaperSize,
+                                                imageSize,
+                                            ),
+                                        hostViewSize = imageSize,
+                                        cropViewSize =
+                                            WallpaperCropUtils.calculateCropSurfaceSize(
+                                                fullResImageView.resources,
+                                                max(imageSize.x, imageSize.y),
+                                                min(imageSize.x, imageSize.y),
+                                                imageSize.x,
+                                                imageSize.y,
+                                            ),
+                                    ),
+                            ),
+                        )
+
+                        if (lowResImageView.isVisible) {
+                            crossFadeInFullResImageView(lowResImageView, fullResImageView)
+                        }
+                    }
+                }
+            }
+        }
+    }
+
+    private fun ImageView.initLowResImageView() {
+        setRenderEffect(
+            RenderEffect.createBlurEffect(
+                LOW_RES_BITMAP_BLUR_RADIUS,
+                LOW_RES_BITMAP_BLUR_RADIUS,
+                Shader.TileMode.CLAMP
+            )
+        )
+    }
+
+    private fun SubsamplingScaleImageView.initFullResImageView() {
+        setMinimumScaleType(SubsamplingScaleImageView.SCALE_TYPE_CUSTOM)
+        setPanLimit(SubsamplingScaleImageView.PAN_LIMIT_INSIDE)
+    }
+
+    private fun SubsamplingScaleImageView.setFullResImage(
+        imageSource: ImageSource,
+        rawWallpaperSize: Point,
+        displaySize: Point,
+        cropHint: Rect?,
+        isRtl: Boolean,
+        isFullScreen: Boolean,
+    ) {
+        // Set the full res image
+        setImage(imageSource)
+        // Calculate the scale and the center point for the full res image
+        doOnLayout {
+            FullResImageViewUtil.getScaleAndCenter(
+                    Point(measuredWidth, measuredHeight),
+                    rawWallpaperSize,
+                    displaySize,
+                    cropHint,
+                    isRtl,
+                    systemScale =
+                        if (isFullScreen) 1f
+                        else
+                            WallpaperCropUtils.getSystemWallpaperMaximumScale(
+                                context.applicationContext,
+                            ),
+                )
+                .let { scaleAndCenter ->
+                    minScale = scaleAndCenter.minScale
+                    maxScale = scaleAndCenter.maxScale
+                    setScaleAndCenter(scaleAndCenter.defaultScale, scaleAndCenter.center)
+                }
+        }
+    }
+
+    private fun crossFadeInFullResImageView(lowResImageView: ImageView, fullResImageView: View) {
+        fullResImageView.alpha = 0f
+        fullResImageView
+            .animate()
+            .alpha(1f)
+            .setInterpolator(ALPHA_OUT)
+            .setDuration(CROSS_FADE_DURATION)
+            .setListener(
+                object : AnimatorListenerAdapter() {
+                    override fun onAnimationEnd(animation: Animator) {
+                        lowResImageView.setImageBitmap(null)
+                    }
+                }
+            )
+    }
+
+    private const val TAG = "StaticPreviewBinder"
+}
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/binder/WallpaperPreviewBinder.kt b/src/com/android/wallpaper/picker/common/preview/ui/binder/WallpaperPreviewBinder.kt
new file mode 100644
index 00000000..b2dd6248
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/preview/ui/binder/WallpaperPreviewBinder.kt
@@ -0,0 +1,207 @@
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
+package com.android.wallpaper.picker.common.preview.ui.binder
+
+import android.app.WallpaperColors
+import android.content.Context
+import android.graphics.Point
+import android.view.LayoutInflater
+import android.view.SurfaceHolder
+import android.view.SurfaceView
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import com.android.wallpaper.R
+import com.android.wallpaper.model.Screen
+import com.android.wallpaper.model.wallpaper.DeviceDisplayType
+import com.android.wallpaper.picker.common.preview.ui.viewmodel.BasePreviewViewModel
+import com.android.wallpaper.picker.customization.shared.model.WallpaperColorsModel
+import com.android.wallpaper.picker.data.WallpaperModel
+import com.android.wallpaper.util.SurfaceViewUtils
+import com.android.wallpaper.util.SurfaceViewUtils.attachView
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils.Companion.shouldEnforceSingleEngine
+import com.android.wallpaper.util.wallpaperconnection.WallpaperEngineConnection
+import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.Job
+import kotlinx.coroutines.launch
+
+/**
+ * Bind the [SurfaceView] with [BasePreviewViewModel] for rendering static or live wallpaper
+ * preview, with regard to its underlying [WallpaperModel].
+ */
+// Based on SmallWallpaperPreviewBinder, mostly unchanged, except with LoadingAnimationBinding
+// removed. Also we enable a screen to be defined during binding rather than reading from
+// viewModel.isViewAsHome. In addition the call to WallpaperConnectionUtils.disconnectAllServices at
+// the end of the static wallpaper binding is removed since it interferes with previewing one live
+// and one static wallpaper side by side, but should be re-visited when integrating into
+// WallpaperPreviewActivity for the cinematic wallpaper toggle case.
+object WallpaperPreviewBinder {
+    fun bind(
+        applicationContext: Context,
+        surfaceView: SurfaceView,
+        viewModel: BasePreviewViewModel,
+        screen: Screen,
+        displaySize: Point,
+        deviceDisplayType: DeviceDisplayType,
+        viewLifecycleOwner: LifecycleOwner,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
+    ) {
+        var surfaceCallback: SurfaceViewUtils.SurfaceCallback? = null
+        viewLifecycleOwner.lifecycleScope.launch {
+            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.CREATED) {
+                surfaceCallback =
+                    bindSurface(
+                        applicationContext = applicationContext,
+                        surfaceView = surfaceView,
+                        viewModel = viewModel,
+                        screen = screen,
+                        deviceDisplayType = deviceDisplayType,
+                        displaySize = displaySize,
+                        lifecycleOwner = viewLifecycleOwner,
+                        wallpaperConnectionUtils = wallpaperConnectionUtils,
+                        isFirstBindingDeferred = isFirstBindingDeferred,
+                    )
+                surfaceView.setZOrderMediaOverlay(true)
+                surfaceCallback?.let { surfaceView.holder.addCallback(it) }
+            }
+            // When OnDestroy, release the surface
+            surfaceCallback?.let {
+                surfaceView.holder.removeCallback(it)
+                surfaceCallback = null
+            }
+        }
+    }
+
+    /**
+     * Create a surface callback that binds the surface when surface created. Note that we return
+     * the surface callback reference so that we can remove the callback from the surface when the
+     * screen is destroyed.
+     */
+    private fun bindSurface(
+        applicationContext: Context,
+        surfaceView: SurfaceView,
+        viewModel: BasePreviewViewModel,
+        screen: Screen,
+        deviceDisplayType: DeviceDisplayType,
+        displaySize: Point,
+        lifecycleOwner: LifecycleOwner,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
+    ): SurfaceViewUtils.SurfaceCallback {
+
+        return object : SurfaceViewUtils.SurfaceCallback {
+
+            var job: Job? = null
+
+            override fun surfaceCreated(holder: SurfaceHolder) {
+                job =
+                    lifecycleOwner.lifecycleScope.launch {
+                        viewModel.wallpapersAndWhichPreview.collect { (wallpapers, whichPreview) ->
+                            val wallpaper =
+                                if (screen == Screen.HOME_SCREEN) wallpapers.homeWallpaper
+                                else wallpapers.lockWallpaper ?: wallpapers.homeWallpaper
+                            if (wallpaper is WallpaperModel.LiveWallpaperModel) {
+                                val engineRenderingConfig =
+                                    WallpaperConnectionUtils.Companion.EngineRenderingConfig(
+                                        wallpaper.shouldEnforceSingleEngine(),
+                                        deviceDisplayType = deviceDisplayType,
+                                        viewModel.smallerDisplaySize,
+                                        viewModel.wallpaperDisplaySize.value,
+                                    )
+                                val listener =
+                                    object :
+                                        WallpaperEngineConnection.WallpaperEngineConnectionListener {
+                                        override fun onWallpaperColorsChanged(
+                                            colors: WallpaperColors?,
+                                            displayId: Int
+                                        ) {
+                                            viewModel.setWallpaperConnectionColors(
+                                                WallpaperColorsModel.Loaded(colors)
+                                            )
+                                        }
+                                    }
+                                wallpaperConnectionUtils.connect(
+                                    applicationContext,
+                                    wallpaper,
+                                    whichPreview,
+                                    screen.toFlag(),
+                                    surfaceView,
+                                    engineRenderingConfig,
+                                    isFirstBindingDeferred,
+                                    listener,
+                                )
+                            } else if (wallpaper is WallpaperModel.StaticWallpaperModel) {
+                                val staticPreviewView =
+                                    LayoutInflater.from(applicationContext)
+                                        .inflate(R.layout.fullscreen_wallpaper_preview, null)
+                                // surfaceView.width and surfaceFrame.width here can be different,
+                                // one represents the size of the view and the other represents the
+                                // size of the surface. When setting a view to the surface host,
+                                // we want to set it based on the surface's size not the view's size
+                                val surfacePosition = surfaceView.holder.surfaceFrame
+                                surfaceView.attachView(
+                                    staticPreviewView,
+                                    surfacePosition.width(),
+                                    surfacePosition.height()
+                                )
+                                // Bind static wallpaper
+                                StaticPreviewBinder.bind(
+                                    lowResImageView =
+                                        staticPreviewView.requireViewById(R.id.low_res_image),
+                                    fullResImageView =
+                                        staticPreviewView.requireViewById(R.id.full_res_image),
+                                    viewModel =
+                                        if (
+                                            screen == Screen.LOCK_SCREEN &&
+                                                wallpapers.lockWallpaper != null
+                                        ) {
+                                            // Only if home and lock screen are different, use lock
+                                            // view model, otherwise, re-use home view model for
+                                            // lock.
+                                            viewModel.staticLockWallpaperPreviewViewModel
+                                        } else {
+                                            viewModel.staticHomeWallpaperPreviewViewModel
+                                        },
+                                    displaySize = displaySize,
+                                    parentCoroutineScope = this,
+                                )
+                                // TODO (b/348462236): investigate cinematic wallpaper toggle case
+                                // Previously all live wallpaper services are shut down to enable
+                                // static photos wallpaper to show up when cinematic effect is
+                                // toggled off, using WallpaperConnectionUtils.disconnectAllServices
+                                // This cannot work when previewing current wallpaper, and one
+                                // wallpaper is live and the other is static--it causes live
+                                // wallpaper to black screen occasionally.
+                            }
+                        }
+                    }
+            }
+
+            override fun surfaceDestroyed(holder: SurfaceHolder) {
+                job?.cancel()
+                job = null
+                // Note that we disconnect wallpaper connection for live wallpapers in
+                // WallpaperPreviewActivity's onDestroy().
+                // This is to reduce multiple times of connecting and disconnecting live
+                // wallpaper services, when going back and forth small and full preview.
+            }
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/binder/WorkspaceCallbackBinder.kt b/src/com/android/wallpaper/picker/common/preview/ui/binder/WorkspaceCallbackBinder.kt
new file mode 100644
index 00000000..4a611239
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/preview/ui/binder/WorkspaceCallbackBinder.kt
@@ -0,0 +1,51 @@
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
+package com.android.wallpaper.picker.common.preview.ui.binder
+
+import android.os.Bundle
+import android.os.Message
+import androidx.lifecycle.LifecycleOwner
+import com.android.wallpaper.model.Screen
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
+
+/**
+ * This interface takes care the communication with the remote view from an external app. We send
+ * data through [Message].
+ */
+interface WorkspaceCallbackBinder {
+
+    fun bind(
+        workspaceCallback: Message,
+        viewModel: CustomizationOptionsViewModel,
+        screen: Screen,
+        lifecycleOwner: LifecycleOwner,
+    )
+
+    companion object {
+        fun Message.sendMessage(
+            what: Int,
+            data: Bundle,
+        ) {
+            this.replyTo.send(
+                Message().apply {
+                    this.what = what
+                    this.data = data
+                }
+            )
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/binder/WorkspacePreviewBinder.kt b/src/com/android/wallpaper/picker/common/preview/ui/binder/WorkspacePreviewBinder.kt
new file mode 100644
index 00000000..7965c7fc
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/preview/ui/binder/WorkspacePreviewBinder.kt
@@ -0,0 +1,205 @@
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
+package com.android.wallpaper.picker.common.preview.ui.binder
+
+import android.app.WallpaperColors
+import android.os.Bundle
+import android.os.Message
+import android.util.Log
+import android.view.SurfaceHolder
+import android.view.SurfaceView
+import androidx.core.os.bundleOf
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import com.android.systemui.shared.clocks.shared.model.ClockPreviewConstants
+import com.android.systemui.shared.keyguard.shared.model.KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.KEY_HIGHLIGHT_QUICK_AFFORDANCES
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.KEY_INITIALLY_SELECTED_SLOT_ID
+import com.android.wallpaper.model.Screen
+import com.android.wallpaper.model.wallpaper.DeviceDisplayType
+import com.android.wallpaper.picker.common.preview.ui.viewmodel.BasePreviewViewModel
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2
+import com.android.wallpaper.util.PreviewUtils
+import com.android.wallpaper.util.SurfaceViewUtils
+import kotlin.coroutines.resume
+import kotlinx.coroutines.DisposableHandle
+import kotlinx.coroutines.Job
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.suspendCancellableCoroutine
+
+// Based on com/android/wallpaper/picker/preview/ui/binder/WorkspacePreviewBinder.kt, with a
+// subset of the original bind methods and currently without wallpaper colors updates.
+object WorkspacePreviewBinder {
+    fun bind(
+        surfaceView: SurfaceView,
+        viewModel: CustomizationPickerViewModel2,
+        workspaceCallbackBinder: WorkspaceCallbackBinder,
+        screen: Screen,
+        deviceDisplayType: DeviceDisplayType,
+        lifecycleOwner: LifecycleOwner,
+    ) {
+        var surfaceCallback: SurfaceViewUtils.SurfaceCallback? = null
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.CREATED) {
+                surfaceCallback =
+                    bindSurface(
+                        surfaceView = surfaceView,
+                        viewModel = viewModel,
+                        workspaceCallbackBinder = workspaceCallbackBinder,
+                        screen = screen,
+                        previewUtils = getPreviewUtils(screen, viewModel.basePreviewViewModel),
+                        deviceDisplayType = deviceDisplayType,
+                        lifecycleOwner = lifecycleOwner,
+                    )
+                surfaceView.setZOrderMediaOverlay(true)
+                surfaceView.holder.addCallback(surfaceCallback)
+            }
+            // When OnDestroy, release the surface
+            surfaceCallback?.let {
+                surfaceView.holder.removeCallback(it)
+                surfaceCallback = null
+            }
+        }
+    }
+
+    /**
+     * Create a surface callback that binds the surface when surface created. Note that we return
+     * the surface callback reference so that we can remove the callback from the surface when the
+     * screen is destroyed.
+     */
+    private fun bindSurface(
+        surfaceView: SurfaceView,
+        viewModel: CustomizationPickerViewModel2,
+        workspaceCallbackBinder: WorkspaceCallbackBinder,
+        screen: Screen,
+        previewUtils: PreviewUtils,
+        deviceDisplayType: DeviceDisplayType,
+        lifecycleOwner: LifecycleOwner,
+    ): SurfaceViewUtils.SurfaceCallback {
+        return object : SurfaceViewUtils.SurfaceCallback {
+
+            var job: Job? = null
+            var previewDisposableHandle: DisposableHandle? = null
+
+            override fun surfaceCreated(holder: SurfaceHolder) {
+                job =
+                    lifecycleOwner.lifecycleScope.launch {
+                        renderWorkspacePreview(
+                                surfaceView = surfaceView,
+                                screen = screen,
+                                previewUtils = previewUtils,
+                                displayId =
+                                    viewModel.basePreviewViewModel.getDisplayId(deviceDisplayType),
+                            )
+                            ?.let { workspaceCallback ->
+                                workspaceCallbackBinder.bind(
+                                    workspaceCallback = workspaceCallback,
+                                    viewModel = viewModel.customizationOptionsViewModel,
+                                    screen = screen,
+                                    lifecycleOwner = lifecycleOwner,
+                                )
+                            }
+                    }
+            }
+
+            override fun surfaceDestroyed(holder: SurfaceHolder) {
+                job?.cancel()
+                job = null
+                previewDisposableHandle?.dispose()
+                previewDisposableHandle = null
+            }
+        }
+    }
+
+    private suspend fun renderWorkspacePreview(
+        surfaceView: SurfaceView,
+        screen: Screen,
+        previewUtils: PreviewUtils,
+        displayId: Int,
+        wallpaperColors: WallpaperColors? = null,
+    ): Message? {
+        var workspaceCallback: Message? = null
+        if (previewUtils.supportsPreview()) {
+            // surfaceView.width and surfaceFrame.width here can be different, one represents the
+            // size of the view and the other represents the size of the surface. When requesting a
+            // preview, make sure to specify the width and height in the bundle so we are using the
+            // surface size and not the view size.
+            val surfacePosition = surfaceView.holder.surfaceFrame
+            val extras =
+                bundleOf(
+                        Pair(SurfaceViewUtils.KEY_DISPLAY_ID, displayId),
+                        Pair(SurfaceViewUtils.KEY_VIEW_WIDTH, surfacePosition.width()),
+                        Pair(SurfaceViewUtils.KEY_VIEW_HEIGHT, surfacePosition.height()),
+                    )
+                    .apply {
+                        if (screen == Screen.LOCK_SCREEN) {
+                            putBoolean(ClockPreviewConstants.KEY_HIDE_CLOCK, true)
+                            putString(KEY_INITIALLY_SELECTED_SLOT_ID, SLOT_ID_BOTTOM_START)
+                            putBoolean(KEY_HIGHLIGHT_QUICK_AFFORDANCES, false)
+                        }
+                    }
+
+            wallpaperColors?.let {
+                extras.putParcelable(SurfaceViewUtils.KEY_WALLPAPER_COLORS, wallpaperColors)
+            }
+            val request = SurfaceViewUtils.createSurfaceViewRequest(surfaceView, extras)
+            workspaceCallback = suspendCancellableCoroutine { continuation ->
+                previewUtils.renderPreview(
+                    request,
+                    object : PreviewUtils.WorkspacePreviewCallback {
+                        override fun onPreviewRendered(resultBundle: Bundle?) {
+                            if (resultBundle != null) {
+                                SurfaceViewUtils.getSurfacePackage(resultBundle).apply {
+                                    if (this != null) {
+                                        surfaceView.setChildSurfacePackage(this)
+                                    } else {
+                                        Log.w(
+                                            TAG,
+                                            "Result bundle from rendering preview does not contain " +
+                                                "a child surface package.",
+                                        )
+                                    }
+                                }
+                                continuation.resume(SurfaceViewUtils.getCallback(resultBundle))
+                            } else {
+                                Log.w(TAG, "Result bundle from rendering preview is null.")
+                                continuation.resume(null)
+                            }
+                        }
+                    },
+                )
+            }
+        }
+        return workspaceCallback
+    }
+
+    private fun getPreviewUtils(
+        screen: Screen,
+        previewViewModel: BasePreviewViewModel,
+    ): PreviewUtils =
+        when (screen) {
+            Screen.HOME_SCREEN -> {
+                previewViewModel.homePreviewUtils
+            }
+            Screen.LOCK_SCREEN -> {
+                previewViewModel.lockPreviewUtils
+            }
+        }
+
+    const val TAG = "WorkspacePreviewBinder"
+}
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/view/CustomizationSurfaceView.kt b/src/com/android/wallpaper/picker/common/preview/ui/view/CustomizationSurfaceView.kt
new file mode 100644
index 00000000..7b19c631
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/preview/ui/view/CustomizationSurfaceView.kt
@@ -0,0 +1,57 @@
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
+package com.android.wallpaper.picker.common.preview.ui.view
+
+import android.content.Context
+import android.util.AttributeSet
+import android.view.SurfaceView
+
+/**
+ * [SurfaceView] that keeps the surface at a fixed size, and resizes it according to view size
+ * changes using the Hardware Scaler, rather than resizing the surface itself. It enables better
+ * efficiency in cases where resizing is frequently needed. It sets the surface at a fixed size
+ * based on the size it is initialized at.
+ */
+class CustomizationSurfaceView(context: Context, attrs: AttributeSet? = null) :
+    SurfaceView(context, attrs) {
+    private var isTransitioning = false
+
+    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
+        super.onSizeChanged(w, h, oldw, oldh)
+
+        // TODO (b/348462236): investigate effect on scale transition and touch forwarding layout
+        if (oldw == 0 && oldh == 0) {
+            // If the view doesn't have a fixed width and height, after the transition the oldw and
+            // oldh will be 0, don't set new size in this case as it will interfere with the
+            // transition. Set the flag back to false once the transition is completed.
+            if (isTransitioning) {
+                isTransitioning = false
+            } else {
+                holder.setFixedSize(w, h)
+            }
+        }
+    }
+
+    /**
+     * Indicates the view is transitioning.
+     *
+     * Needed when using WRAP_CONTENT or 0dp for height or weight together with [MotionLayout]
+     */
+    fun setTransitioning() {
+        this.isTransitioning = true
+    }
+}
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/BasePreviewViewModel.kt b/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/BasePreviewViewModel.kt
new file mode 100644
index 00000000..3df5eb92
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/BasePreviewViewModel.kt
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
+package com.android.wallpaper.picker.common.preview.ui.viewmodel
+
+import com.android.wallpaper.model.Screen
+import com.android.wallpaper.model.WallpaperModelsPair
+import com.android.wallpaper.model.wallpaper.DeviceDisplayType
+import com.android.wallpaper.picker.common.preview.domain.interactor.BasePreviewInteractor
+import com.android.wallpaper.picker.customization.shared.model.WallpaperColorsModel
+import com.android.wallpaper.picker.di.modules.HomeScreenPreviewUtils
+import com.android.wallpaper.picker.di.modules.LockScreenPreviewUtils
+import com.android.wallpaper.util.DisplayUtils
+import com.android.wallpaper.util.PreviewUtils
+import com.android.wallpaper.util.WallpaperConnection
+import dagger.assisted.Assisted
+import dagger.assisted.AssistedFactory
+import dagger.assisted.AssistedInject
+import dagger.hilt.android.scopes.ViewModelScoped
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.stateIn
+import kotlinx.coroutines.launch
+
+/**
+ * Common base preview view-model that is only responsible for binding the workspace and wallpaper.
+ */
+// Based on WallpaperPreviewViewModel, except cleaned up to only bind wallpaper and workspace
+// (workspace binding to be added). Also it is changed to no longer be a top-level ViewModel.
+// Instead, the viewModelScope is passed in using assisted inject.
+class BasePreviewViewModel
+@AssistedInject
+constructor(
+    private val interactor: BasePreviewInteractor,
+    staticPreviewViewModelFactory: StaticPreviewViewModel.Factory,
+    private val displayUtils: DisplayUtils,
+    @HomeScreenPreviewUtils val homePreviewUtils: PreviewUtils,
+    @LockScreenPreviewUtils val lockPreviewUtils: PreviewUtils,
+    @Assisted private val viewModelScope: CoroutineScope,
+) {
+    // Don't update smaller display since we always use portrait, always use wallpaper display on
+    // single display device.
+    val smallerDisplaySize = displayUtils.getRealSize(displayUtils.getSmallerDisplay())
+    private val _wallpaperDisplaySize =
+        MutableStateFlow(displayUtils.getRealSize(displayUtils.getWallpaperDisplay()))
+    val wallpaperDisplaySize = _wallpaperDisplaySize.asStateFlow()
+
+    val staticHomeWallpaperPreviewViewModel by lazy {
+        staticPreviewViewModelFactory.create(Screen.HOME_SCREEN, viewModelScope)
+    }
+    val staticLockWallpaperPreviewViewModel by lazy {
+        staticPreviewViewModelFactory.create(Screen.LOCK_SCREEN, viewModelScope)
+    }
+
+    private val _whichPreview = MutableStateFlow<WallpaperConnection.WhichPreview?>(null)
+    private val whichPreview: Flow<WallpaperConnection.WhichPreview> =
+        _whichPreview.asStateFlow().filterNotNull()
+
+    fun setWhichPreview(whichPreview: WallpaperConnection.WhichPreview) {
+        _whichPreview.value = whichPreview
+    }
+
+    val wallpapers =
+        interactor.wallpapers.stateIn(
+            scope = viewModelScope,
+            started = SharingStarted.WhileSubscribed(),
+            initialValue = null
+        )
+
+    val wallpapersAndWhichPreview:
+        Flow<Pair<WallpaperModelsPair, WallpaperConnection.WhichPreview>> =
+        combine(wallpapers.filterNotNull(), whichPreview) { wallpapers, whichPreview ->
+            Pair(wallpapers, whichPreview)
+        }
+
+    // TODO (b/348462236): implement complete wallpaper colors flow to bind workspace
+    private val _isWallpaperColorPreviewEnabled = MutableStateFlow(false)
+    val isWallpaperColorPreviewEnabled = _isWallpaperColorPreviewEnabled.asStateFlow()
+
+    fun setIsWallpaperColorPreviewEnabled(isWallpaperColorPreviewEnabled: Boolean) {
+        _isWallpaperColorPreviewEnabled.value = isWallpaperColorPreviewEnabled
+    }
+
+    private val _wallpaperConnectionColors: MutableStateFlow<WallpaperColorsModel> =
+        MutableStateFlow(WallpaperColorsModel.Loading as WallpaperColorsModel).apply {
+            viewModelScope.launch {
+                delay(1000)
+                if (value == WallpaperColorsModel.Loading) {
+                    emit(WallpaperColorsModel.Loaded(null))
+                }
+            }
+        }
+
+    fun setWallpaperConnectionColors(wallpaperColors: WallpaperColorsModel) {
+        _wallpaperConnectionColors.value = wallpaperColors
+    }
+
+    fun getDisplayId(deviceDisplayType: DeviceDisplayType): Int {
+        return when (deviceDisplayType) {
+            DeviceDisplayType.SINGLE -> {
+                displayUtils.getWallpaperDisplay().displayId
+            }
+            DeviceDisplayType.FOLDED -> {
+                displayUtils.getSmallerDisplay().displayId
+            }
+            DeviceDisplayType.UNFOLDED -> {
+                displayUtils.getWallpaperDisplay().displayId
+            }
+        }
+    }
+
+    @ViewModelScoped
+    @AssistedFactory
+    interface Factory {
+        fun create(viewModelScope: CoroutineScope): BasePreviewViewModel
+    }
+}
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/FullResWallpaperViewModel.kt b/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/FullResWallpaperViewModel.kt
new file mode 100644
index 00000000..a956f517
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/FullResWallpaperViewModel.kt
@@ -0,0 +1,29 @@
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
+package com.android.wallpaper.picker.common.preview.ui.viewmodel
+
+import android.graphics.Bitmap
+import android.graphics.Point
+import com.android.wallpaper.asset.Asset
+import com.android.wallpaper.picker.preview.shared.model.FullPreviewCropModel
+
+data class FullResWallpaperViewModel(
+    val rawWallpaperBitmap: Bitmap,
+    // TODO(b/348462236): remove this field and use rawWallpaperBitmap's width and height
+    val rawWallpaperSize: Point,
+    val asset: Asset,
+    val fullPreviewCropModels: Map<Point, FullPreviewCropModel>?,
+)
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/StaticPreviewViewModel.kt b/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/StaticPreviewViewModel.kt
new file mode 100644
index 00000000..a3eb193b
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/StaticPreviewViewModel.kt
@@ -0,0 +1,226 @@
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
+package com.android.wallpaper.picker.common.preview.ui.viewmodel
+
+import android.content.Context
+import android.graphics.Bitmap
+import android.graphics.Point
+import android.graphics.Rect
+import androidx.annotation.VisibleForTesting
+import com.android.wallpaper.asset.Asset
+import com.android.wallpaper.model.Screen
+import com.android.wallpaper.picker.common.preview.domain.interactor.BasePreviewInteractor
+import com.android.wallpaper.picker.data.WallpaperModel
+import com.android.wallpaper.picker.data.WallpaperModel.StaticWallpaperModel
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
+import com.android.wallpaper.picker.preview.shared.model.FullPreviewCropModel
+import dagger.assisted.Assisted
+import dagger.assisted.AssistedFactory
+import dagger.assisted.AssistedInject
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.scopes.ViewModelScoped
+import kotlinx.coroutines.CancellableContinuation
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.flowOn
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.onEach
+import kotlinx.coroutines.flow.shareIn
+import kotlinx.coroutines.suspendCancellableCoroutine
+
+/** View model for static wallpaper preview used in the common [BasePreviewViewModel] */
+// Based on StaticWallpaperPreviewViewModel, except updated to use BasePreviewInteractor rather than
+// WallpaperPreviewInteractor, and updated to use AssistedInject rather than a regular Inject with a
+// Factory. Also, crop hints info is now updated based on each new emitted static wallpaper model,
+// rather than set in the activity.
+class StaticPreviewViewModel
+@AssistedInject
+constructor(
+    interactor: BasePreviewInteractor,
+    @ApplicationContext private val context: Context,
+    @BackgroundDispatcher private val bgDispatcher: CoroutineDispatcher,
+    @Assisted screen: Screen,
+    @Assisted viewModelScope: CoroutineScope,
+) {
+    /**
+     * The state of static wallpaper crop in full preview, before user confirmation.
+     *
+     * The initial value should be the default crop on small preview, which could be the cropHints
+     * for current wallpaper or default crop area for a new wallpaper.
+     */
+    val fullPreviewCropModels: MutableMap<Point, FullPreviewCropModel> = mutableMapOf()
+
+    /**
+     * The default crops for the current wallpaper, which is center aligned on the preview.
+     *
+     * Always update default through [updateDefaultPreviewCropModel] to make sure multiple updates
+     * of the same preview only counts the first time it appears.
+     */
+    private val defaultPreviewCropModels: MutableMap<Point, FullPreviewCropModel> = mutableMapOf()
+
+    /**
+     * The info picker needs to post process crops for setting static wallpaper.
+     *
+     * It will be filled with current cropHints when previewing current wallpaper, and null when
+     * previewing a new wallpaper, and gets updated through [updateCropHintsInfo] when user picks a
+     * new crop.
+     */
+    @get:VisibleForTesting
+    val cropHintsInfo: MutableStateFlow<Map<Point, FullPreviewCropModel>?> = MutableStateFlow(null)
+
+    private val cropHints: Flow<Map<Point, Rect>?> =
+        cropHintsInfo.map { cropHintsInfoMap ->
+            cropHintsInfoMap?.map { entry -> entry.key to entry.value.cropHint }?.toMap()
+        }
+
+    val staticWallpaperModel: Flow<StaticWallpaperModel?> =
+        interactor.wallpapers
+            .map { (homeWallpaper, lockWallpaper) ->
+                val wallpaper = if (screen == Screen.HOME_SCREEN) homeWallpaper else lockWallpaper
+                wallpaper as? StaticWallpaperModel
+            }
+            .onEach { wallpaper ->
+                // Update crop hints in view model if crop hints are specified in wallpaper model.
+                if (wallpaper != null && !wallpaper.isDownloadableWallpaper()) {
+                    wallpaper.staticWallpaperData.cropHints?.let { cropHints ->
+                        clearCropHintsInfo()
+                        updateCropHintsInfo(
+                            cropHints.mapValues {
+                                FullPreviewCropModel(
+                                    cropHint = it.value,
+                                    cropSizeModel = null,
+                                )
+                            }
+                        )
+                    }
+                } else {
+                    clearCropHintsInfo()
+                }
+            }
+    /** Null indicates the wallpaper has no low res image. */
+    val lowResBitmap: Flow<Bitmap?> =
+        staticWallpaperModel
+            .filterNotNull()
+            .map { it.staticWallpaperData.asset.getLowResBitmap(context) }
+            .flowOn(bgDispatcher)
+    // Asset detail includes the dimensions, bitmap and the asset.
+    private val assetDetail: Flow<Triple<Point, Bitmap?, Asset>?> =
+        staticWallpaperModel
+            .map { it?.staticWallpaperData?.asset }
+            .map { asset ->
+                asset?.decodeRawDimensions()?.let { Triple(it, asset.decodeBitmap(it), asset) }
+            }
+            .flowOn(bgDispatcher)
+            // We only want to decode bitmap every time when wallpaper model is updated, instead of
+            // a new subscriber listens to this flow. So we need to use shareIn.
+            .shareIn(viewModelScope, SharingStarted.Lazily, 1)
+
+    val fullResWallpaperViewModel: Flow<FullResWallpaperViewModel?> =
+        combine(assetDetail, cropHintsInfo) { assetDetail, cropHintsInfo ->
+                if (assetDetail == null) {
+                    null
+                } else {
+                    val (dimensions, bitmap, asset) = assetDetail
+                    bitmap?.let {
+                        FullResWallpaperViewModel(
+                            bitmap,
+                            dimensions,
+                            asset,
+                            cropHintsInfo,
+                        )
+                    }
+                }
+            }
+            .flowOn(bgDispatcher)
+    val subsamplingScaleImageViewModel: Flow<FullResWallpaperViewModel> =
+        fullResWallpaperViewModel.filterNotNull()
+
+    // TODO (b/348462236): implement wallpaper colors
+    // TODO (b/315856338): cache wallpaper colors in preferences
+
+    /**
+     * Updates new cropHints per displaySize that's been confirmed by the user or from a new default
+     * crop.
+     *
+     * That's when picker gets current cropHints from [WallpaperManager] or when user crops and
+     * confirms a crop, or when a small preview for a new display size has been discovered the first
+     * time.
+     */
+    fun updateCropHintsInfo(
+        cropHintsInfo: Map<Point, FullPreviewCropModel>,
+        updateDefaultCrop: Boolean = false
+    ) {
+        val newInfo =
+            this.cropHintsInfo.value?.let { currentCropHintsInfo ->
+                currentCropHintsInfo.plus(
+                    if (updateDefaultCrop)
+                        cropHintsInfo.filterKeys { !currentCropHintsInfo.keys.contains(it) }
+                    else cropHintsInfo
+                )
+            } ?: cropHintsInfo
+        this.cropHintsInfo.value = newInfo
+        fullPreviewCropModels.putAll(newInfo)
+    }
+
+    /** Updates default cropHint for [displaySize] if it's not already exist. */
+    fun updateDefaultPreviewCropModel(displaySize: Point, cropModel: FullPreviewCropModel) {
+        defaultPreviewCropModels.let { cropModels ->
+            if (!cropModels.contains(displaySize)) {
+                cropModels[displaySize] = cropModel
+                updateCropHintsInfo(
+                    cropModels.filterKeys { it == displaySize },
+                    updateDefaultCrop = true,
+                )
+            }
+        }
+    }
+
+    private fun clearCropHintsInfo() {
+        this.cropHintsInfo.value = null
+        this.fullPreviewCropModels.clear()
+    }
+
+    // TODO b/296288298 Create a util class for Bitmap and Asset
+    private suspend fun Asset.decodeRawDimensions(): Point? =
+        suspendCancellableCoroutine { k: CancellableContinuation<Point?> ->
+            val callback = Asset.DimensionsReceiver { k.resumeWith(Result.success(it)) }
+            decodeRawDimensions(null, callback)
+        }
+
+    // TODO b/296288298 Create a util class functions for Bitmap and Asset
+    private suspend fun Asset.decodeBitmap(dimensions: Point): Bitmap? =
+        suspendCancellableCoroutine { k: CancellableContinuation<Bitmap?> ->
+            val callback = Asset.BitmapReceiver { k.resumeWith(Result.success(it)) }
+            decodeBitmap(dimensions.x, dimensions.y, /* hardwareBitmapAllowed= */ false, callback)
+        }
+
+    companion object {
+        private fun WallpaperModel.isDownloadableWallpaper(): Boolean {
+            return this is StaticWallpaperModel && downloadableWallpaperData != null
+        }
+    }
+
+    @ViewModelScoped
+    @AssistedFactory
+    interface Factory {
+        fun create(screen: Screen, viewModelScope: CoroutineScope): StaticPreviewViewModel
+    }
+}
diff --git a/src/com/android/wallpaper/picker/common/ui/view/ItemSpacing.kt b/src/com/android/wallpaper/picker/common/ui/view/ItemSpacing.kt
new file mode 100644
index 00000000..ee2b974e
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/ui/view/ItemSpacing.kt
@@ -0,0 +1,57 @@
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
+package com.android.wallpaper.picker.common.ui.view
+
+import android.graphics.Rect
+import android.view.View
+import androidx.core.view.ViewCompat
+import androidx.recyclerview.widget.RecyclerView
+
+/** Item spacing used by the RecyclerView. */
+class ItemSpacing(
+    private val itemSpacingDp: Int,
+) : RecyclerView.ItemDecoration() {
+
+    override fun getItemOffsets(
+        outRect: Rect,
+        view: View,
+        parent: RecyclerView,
+        state: RecyclerView.State,
+    ) {
+        val itemPosition = parent.getChildAdapterPosition(view)
+        val addSpacingToStart = itemPosition > 0
+        val addSpacingToEnd = itemPosition < (parent.adapter?.itemCount ?: 0) - 1
+        val isRtl = parent.layoutManager?.layoutDirection == ViewCompat.LAYOUT_DIRECTION_RTL
+        val density = parent.context.resources.displayMetrics.density
+        val halfItemSpacingPx = itemSpacingDp.toPx(density) / 2
+        if (!isRtl) {
+            outRect.left = if (addSpacingToStart) halfItemSpacingPx else 0
+            outRect.right = if (addSpacingToEnd) halfItemSpacingPx else 0
+        } else {
+            outRect.left = if (addSpacingToEnd) halfItemSpacingPx else 0
+            outRect.right = if (addSpacingToStart) halfItemSpacingPx else 0
+        }
+    }
+
+    private fun Int.toPx(density: Float): Int {
+        return (this * density).toInt()
+    }
+
+    companion object {
+        const val TAB_ITEM_SPACING_DP = 12
+        const val ITEM_SPACING_DP = 8
+    }
+}
diff --git a/src/com/android/wallpaper/picker/customization/data/content/WallpaperClient.kt b/src/com/android/wallpaper/picker/customization/data/content/WallpaperClient.kt
index bead9ae5..02819208 100644
--- a/src/com/android/wallpaper/picker/customization/data/content/WallpaperClient.kt
+++ b/src/com/android/wallpaper/picker/customization/data/content/WallpaperClient.kt
@@ -23,6 +23,8 @@ import android.graphics.Bitmap
 import android.graphics.Point
 import android.graphics.Rect
 import com.android.wallpaper.asset.Asset
+import com.android.wallpaper.model.Screen
+import com.android.wallpaper.model.WallpaperModelsPair
 import com.android.wallpaper.module.logging.UserEventLogger.SetWallpaperEntryPoint
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination
 import com.android.wallpaper.picker.customization.shared.model.WallpaperModel
@@ -104,4 +106,8 @@ interface WallpaperClient {
 
     /** Returns the wallpaper colors for preview a bitmap with a set of crop hints */
     suspend fun getWallpaperColors(bitmap: Bitmap, cropHints: Map<Point, Rect>?): WallpaperColors?
+
+    suspend fun getCurrentWallpaperModels(): WallpaperModelsPair
+
+    fun getWallpaperColors(screen: Screen): WallpaperColors?
 }
diff --git a/src/com/android/wallpaper/picker/customization/data/content/WallpaperClientImpl.kt b/src/com/android/wallpaper/picker/customization/data/content/WallpaperClientImpl.kt
index f3895a73..47a9d262 100644
--- a/src/com/android/wallpaper/picker/customization/data/content/WallpaperClientImpl.kt
+++ b/src/com/android/wallpaper/picker/customization/data/content/WallpaperClientImpl.kt
@@ -33,7 +33,6 @@ import android.graphics.Color
 import android.graphics.Point
 import android.graphics.Rect
 import android.net.Uri
-import android.os.Looper
 import android.util.Log
 import androidx.exifinterface.media.ExifInterface
 import com.android.app.tracing.TraceUtils.traceAsync
@@ -44,36 +43,44 @@ import com.android.wallpaper.asset.StreamableAsset
 import com.android.wallpaper.model.CreativeCategory
 import com.android.wallpaper.model.CreativeWallpaperInfo
 import com.android.wallpaper.model.LiveWallpaperPrefMetadata
+import com.android.wallpaper.model.Screen
 import com.android.wallpaper.model.StaticWallpaperPrefMetadata
 import com.android.wallpaper.model.WallpaperInfo
+import com.android.wallpaper.model.WallpaperModelsPair
 import com.android.wallpaper.module.InjectorProvider
 import com.android.wallpaper.module.WallpaperPreferences
+import com.android.wallpaper.module.logging.UserEventLogger
 import com.android.wallpaper.module.logging.UserEventLogger.SetWallpaperEntryPoint
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination.BOTH
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination.Companion.toDestinationInt
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination.HOME
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination.LOCK
-import com.android.wallpaper.picker.customization.shared.model.WallpaperModel
+import com.android.wallpaper.picker.customization.shared.model.WallpaperModel as RecentWallpaperModel
 import com.android.wallpaper.picker.data.WallpaperModel.LiveWallpaperModel
 import com.android.wallpaper.picker.data.WallpaperModel.StaticWallpaperModel
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import com.android.wallpaper.picker.preview.shared.model.FullPreviewCropModel
 import com.android.wallpaper.util.WallpaperCropUtils
+import com.android.wallpaper.util.converter.WallpaperModelFactory
 import com.android.wallpaper.util.converter.WallpaperModelFactory.Companion.getCommonWallpaperData
 import com.android.wallpaper.util.converter.WallpaperModelFactory.Companion.getCreativeWallpaperData
 import dagger.hilt.android.qualifiers.ApplicationContext
 import java.io.IOException
 import java.io.InputStream
-import java.util.EnumMap
 import javax.inject.Inject
 import javax.inject.Singleton
 import kotlinx.coroutines.CancellableContinuation
-import kotlinx.coroutines.channels.awaitClose
-import kotlinx.coroutines.flow.Flow
-import kotlinx.coroutines.flow.callbackFlow
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.take
 import kotlinx.coroutines.launch
 import kotlinx.coroutines.suspendCancellableCoroutine
 
+@OptIn(ExperimentalCoroutinesApi::class)
 @Singleton
 class WallpaperClientImpl
 @Inject
@@ -81,20 +88,31 @@ constructor(
     @ApplicationContext private val context: Context,
     private val wallpaperManager: WallpaperManager,
     private val wallpaperPreferences: WallpaperPreferences,
+    private val wallpaperModelFactory: WallpaperModelFactory,
+    private val logger: UserEventLogger,
+    @BackgroundDispatcher val backgroundScope: CoroutineScope,
 ) : WallpaperClient {
 
     private var recentsContentProviderAvailable: Boolean? = null
-    private val cachedRecents: MutableMap<WallpaperDestination, List<WallpaperModel>> =
-        EnumMap(WallpaperDestination::class.java)
+    private val recentHomeWallpapers = MutableStateFlow<List<RecentWallpaperModel>?>(null)
+    private val recentLockWallpapers = MutableStateFlow<List<RecentWallpaperModel>?>(null)
 
     init {
+        backgroundScope.launch {
+            recentHomeWallpapers.value = queryRecentWallpapers(destination = HOME)
+            recentLockWallpapers.value = queryRecentWallpapers(destination = LOCK)
+        }
+
         if (areRecentsAvailable()) {
             context.contentResolver.registerContentObserver(
                 LIST_RECENTS_URI,
                 /* notifyForDescendants= */ true,
                 object : ContentObserver(null) {
                     override fun onChange(selfChange: Boolean) {
-                        cachedRecents.clear()
+                        backgroundScope.launch {
+                            recentHomeWallpapers.value = queryRecentWallpapers(destination = HOME)
+                            recentLockWallpapers.value = queryRecentWallpapers(destination = LOCK)
+                        }
                     }
                 },
             )
@@ -104,42 +122,15 @@ constructor(
     override fun recentWallpapers(
         destination: WallpaperDestination,
         limit: Int,
-    ): Flow<List<WallpaperModel>> {
-        return callbackFlow {
-            // TODO(b/280891780) Remove this check
-            if (Looper.myLooper() == Looper.getMainLooper()) {
-                throw IllegalStateException("Do not call method recentWallpapers() on main thread")
-            }
-            suspend fun queryAndSend(limit: Int) {
-                send(queryRecentWallpapers(destination = destination, limit = limit))
-            }
-
-            val contentObserver =
-                if (areRecentsAvailable()) {
-                        object : ContentObserver(null) {
-                            override fun onChange(selfChange: Boolean) {
-                                launch { queryAndSend(limit = limit) }
-                            }
-                        }
-                    } else {
-                        null
-                    }
-                    ?.also {
-                        context.contentResolver.registerContentObserver(
-                            LIST_RECENTS_URI,
-                            /* notifyForDescendants= */ true,
-                            it,
-                        )
-                    }
-            queryAndSend(limit = limit)
-
-            awaitClose {
-                if (contentObserver != null) {
-                    context.contentResolver.unregisterContentObserver(contentObserver)
-                }
-            }
+    ) =
+        when (destination) {
+            HOME -> recentHomeWallpapers.asStateFlow().filterNotNull().take(limit)
+            LOCK -> recentLockWallpapers.asStateFlow().filterNotNull().take(limit)
+            BOTH ->
+                throw IllegalStateException(
+                    "Destination $destination should not be used for getting recent wallpapers."
+                )
         }
-    }
 
     override suspend fun setStaticWallpaper(
         @SetWallpaperEntryPoint setWallpaperEntryPoint: Int,
@@ -177,6 +168,17 @@ constructor(
                 destination = destination,
             )
 
+            logger.logWallpaperApplied(
+                collectionId = wallpaperModel.commonWallpaperData.id.collectionId,
+                wallpaperId = wallpaperModel.commonWallpaperData.id.wallpaperId,
+                effects = null,
+                setWallpaperEntryPoint = setWallpaperEntryPoint,
+                destination =
+                    UserEventLogger.toWallpaperDestinationForLogging(
+                        destination.toDestinationInt()
+                    ),
+            )
+
             // Save the static wallpaper to recent wallpapers
             // TODO(b/309138446): check if we can update recent with all cropHints from WM later
             wallpaperPreferences.addStaticWallpaperToRecentWallpapers(
@@ -295,6 +297,17 @@ constructor(
                 destination = destination,
             )
 
+            logger.logWallpaperApplied(
+                collectionId = wallpaperModel.commonWallpaperData.id.collectionId,
+                wallpaperId = wallpaperModel.commonWallpaperData.id.wallpaperId,
+                effects = wallpaperModel.liveWallpaperData.effectNames,
+                setWallpaperEntryPoint = setWallpaperEntryPoint,
+                destination =
+                    UserEventLogger.toWallpaperDestinationForLogging(
+                        destination.toDestinationInt()
+                    ),
+            )
+
             wallpaperPreferences.addLiveWallpaperToRecentWallpapers(
                 destination,
                 updatedWallpaperModel
@@ -447,24 +460,17 @@ constructor(
     }
 
     private suspend fun queryRecentWallpapers(
-        destination: WallpaperDestination,
-        limit: Int,
-    ): List<WallpaperModel> {
-        val recentWallpapers =
-            cachedRecents[destination]
-                ?: if (!areRecentsAvailable()) {
-                    listOf(getCurrentWallpaperFromFactory(destination))
-                } else {
-                    queryAllRecentWallpapers(destination)
-                }
-
-        cachedRecents[destination] = recentWallpapers
-        return recentWallpapers.take(limit)
-    }
+        destination: WallpaperDestination
+    ): List<RecentWallpaperModel> =
+        if (!areRecentsAvailable()) {
+            listOf(getCurrentWallpaperFromFactory(destination))
+        } else {
+            queryAllRecentWallpapers(destination)
+        }
 
-    private suspend fun queryAllRecentWallpapers(
+    private fun queryAllRecentWallpapers(
         destination: WallpaperDestination
-    ): List<WallpaperModel> {
+    ): List<RecentWallpaperModel> {
         context.contentResolver
             .query(
                 LIST_RECENTS_URI.buildUpon().appendPath(destination.asString()).build(),
@@ -490,7 +496,7 @@ constructor(
                             if (titleColumnIndex > -1) cursor.getString(titleColumnIndex) else null
 
                         add(
-                            WallpaperModel(
+                            RecentWallpaperModel(
                                 wallpaperId = wallpaperId,
                                 placeholderColor = placeholderColor,
                                 lastUpdated = lastUpdated,
@@ -504,7 +510,7 @@ constructor(
 
     private suspend fun getCurrentWallpaperFromFactory(
         destination: WallpaperDestination
-    ): WallpaperModel {
+    ): RecentWallpaperModel {
         val currentWallpapers = getCurrentWallpapers()
         val wallpaper: WallpaperInfo =
             if (destination == LOCK) {
@@ -514,7 +520,7 @@ constructor(
             }
         val colors = wallpaperManager.getWallpaperColors(destination.toFlags())
 
-        return WallpaperModel(
+        return RecentWallpaperModel(
             wallpaperId = wallpaper.wallpaperId,
             placeholderColor = colors?.primaryColor?.toArgb() ?: Color.TRANSPARENT,
             title = wallpaper.getTitle(context)
@@ -533,6 +539,16 @@ constructor(
                 }
         }
 
+    override suspend fun getCurrentWallpaperModels(): WallpaperModelsPair {
+        val currentWallpapers = getCurrentWallpapers()
+        val homeWallpaper = currentWallpapers.first
+        val lockWallpaper = currentWallpapers.second
+        return WallpaperModelsPair(
+            wallpaperModelFactory.getWallpaperModel(context, homeWallpaper),
+            lockWallpaper?.let { wallpaperModelFactory.getWallpaperModel(context, it) }
+        )
+    }
+
     override suspend fun loadThumbnail(
         wallpaperId: String,
         destination: WallpaperDestination
@@ -619,6 +635,16 @@ constructor(
         return wallpaperManager.getWallpaperColors(bitmap, cropHints)
     }
 
+    override fun getWallpaperColors(screen: Screen): WallpaperColors? {
+        return wallpaperManager.getWallpaperColors(
+            if (screen == Screen.LOCK_SCREEN) {
+                FLAG_LOCK
+            } else {
+                FLAG_SYSTEM
+            }
+        )
+    }
+
     fun WallpaperDestination.asString(): String {
         return when (this) {
             BOTH -> SCREEN_ALL
diff --git a/src/com/android/wallpaper/picker/customization/data/repository/WallpaperColorsRepository.kt b/src/com/android/wallpaper/picker/customization/data/repository/WallpaperColorsRepository.kt
index 167a0989..7d2e0767 100644
--- a/src/com/android/wallpaper/picker/customization/data/repository/WallpaperColorsRepository.kt
+++ b/src/com/android/wallpaper/picker/customization/data/repository/WallpaperColorsRepository.kt
@@ -16,21 +16,46 @@
 package com.android.wallpaper.picker.customization.data.repository
 
 import android.app.WallpaperColors
+import com.android.wallpaper.config.BaseFlags
+import com.android.wallpaper.model.Screen
+import com.android.wallpaper.picker.customization.data.content.WallpaperClient
 import com.android.wallpaper.picker.customization.shared.model.WallpaperColorsModel
+import javax.inject.Inject
+import javax.inject.Singleton
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.StateFlow
 import kotlinx.coroutines.flow.asStateFlow
 
-/** ViewModel class to keep track of WallpaperColors for the current wallpaper */
-class WallpaperColorsRepository {
+@Singleton
+/** Repository class to keep track of WallpaperColors for the current wallpaper */
+class WallpaperColorsRepository
+@Inject
+constructor(
+    client: WallpaperClient,
+) {
+
+    private val isNewPickerUi = BaseFlags.get().isNewPickerUi()
 
     private val _homeWallpaperColors =
-        MutableStateFlow<WallpaperColorsModel>(WallpaperColorsModel.Loading)
+        if (isNewPickerUi) {
+            MutableStateFlow<WallpaperColorsModel>(
+                WallpaperColorsModel.Loaded(client.getWallpaperColors(Screen.HOME_SCREEN))
+            )
+        } else {
+            MutableStateFlow<WallpaperColorsModel>(WallpaperColorsModel.Loading)
+        }
+
     /** WallpaperColors for the currently set home wallpaper */
     val homeWallpaperColors: StateFlow<WallpaperColorsModel> = _homeWallpaperColors.asStateFlow()
 
     private val _lockWallpaperColors =
-        MutableStateFlow<WallpaperColorsModel>(WallpaperColorsModel.Loading)
+        if (isNewPickerUi) {
+            MutableStateFlow<WallpaperColorsModel>(
+                WallpaperColorsModel.Loaded(client.getWallpaperColors(Screen.LOCK_SCREEN))
+            )
+        } else {
+            MutableStateFlow<WallpaperColorsModel>(WallpaperColorsModel.Loading)
+        }
     /** WallpaperColors for the currently set lock wallpaper */
     val lockWallpaperColors: StateFlow<WallpaperColorsModel> = _lockWallpaperColors.asStateFlow()
 
diff --git a/src/com/android/wallpaper/picker/customization/data/repository/WallpaperRepository.kt b/src/com/android/wallpaper/picker/customization/data/repository/WallpaperRepository.kt
index ac69bdde..6150fade 100644
--- a/src/com/android/wallpaper/picker/customization/data/repository/WallpaperRepository.kt
+++ b/src/com/android/wallpaper/picker/customization/data/repository/WallpaperRepository.kt
@@ -30,7 +30,10 @@ import com.android.wallpaper.picker.customization.shared.model.WallpaperDestinat
 import com.android.wallpaper.picker.customization.shared.model.WallpaperModel
 import com.android.wallpaper.picker.data.WallpaperModel.LiveWallpaperModel
 import com.android.wallpaper.picker.data.WallpaperModel.StaticWallpaperModel
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import com.android.wallpaper.picker.preview.shared.model.FullPreviewCropModel
+import javax.inject.Inject
+import javax.inject.Singleton
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.flow.Flow
@@ -38,22 +41,33 @@ import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.SharingStarted
 import kotlinx.coroutines.flow.StateFlow
 import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.flowOn
 import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.shareIn
 import kotlinx.coroutines.flow.stateIn
 import kotlinx.coroutines.withContext
 
 /** Encapsulates access to wallpaper-related data. */
-class WallpaperRepository(
-    private val scope: CoroutineScope,
+@Singleton
+class WallpaperRepository
+@Inject
+constructor(
+    @BackgroundDispatcher private val scope: CoroutineScope,
     private val client: WallpaperClient,
     private val wallpaperPreferences: WallpaperPreferences,
-    private val backgroundDispatcher: CoroutineDispatcher,
+    @BackgroundDispatcher private val backgroundDispatcher: CoroutineDispatcher,
 ) {
     val maxOptions = MAX_OPTIONS
 
     private val thumbnailCache = LruCache<String, Bitmap>(maxOptions)
 
+    // TODO (b/348462236): figure out if current wallpaper model can change in lifecycle & update
+    val currentWallpaperModels =
+        flow { emit(client.getCurrentWallpaperModels()) }
+            .flowOn(backgroundDispatcher)
+            .shareIn(scope = scope, started = SharingStarted.WhileSubscribed(), replay = 1)
+
     /** The ID of the currently-selected wallpaper. */
     fun selectedWallpaperId(
         destination: WallpaperDestination,
diff --git a/src/com/android/wallpaper/picker/customization/domain/interactor/WallpaperInteractor.kt b/src/com/android/wallpaper/picker/customization/domain/interactor/WallpaperInteractor.kt
index 1b677cc2..29ca2104 100644
--- a/src/com/android/wallpaper/picker/customization/domain/interactor/WallpaperInteractor.kt
+++ b/src/com/android/wallpaper/picker/customization/domain/interactor/WallpaperInteractor.kt
@@ -23,17 +23,16 @@ import com.android.wallpaper.module.logging.UserEventLogger.SetWallpaperEntryPoi
 import com.android.wallpaper.picker.customization.data.repository.WallpaperRepository
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination
 import com.android.wallpaper.picker.customization.shared.model.WallpaperModel
+import javax.inject.Inject
+import javax.inject.Singleton
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.StateFlow
 import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.map
 
 /** Handles business logic for wallpaper-related use-cases. */
-class WallpaperInteractor(
-    private val repository: WallpaperRepository,
-    /** Returns whether wallpaper picker should handle reload */
-    val shouldHandleReload: () -> Boolean = { true },
-) {
+@Singleton
+class WallpaperInteractor @Inject constructor(private val repository: WallpaperRepository) {
     val areRecentsAvailable: Boolean = repository.areRecentsAvailable
     val maxOptions = repository.maxOptions
 
diff --git a/src/com/android/wallpaper/picker/customization/ui/CustomizationPickerActivity2.kt b/src/com/android/wallpaper/picker/customization/ui/CustomizationPickerActivity2.kt
index b1eb1dc2..1bef7332 100644
--- a/src/com/android/wallpaper/picker/customization/ui/CustomizationPickerActivity2.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/CustomizationPickerActivity2.kt
@@ -16,39 +16,67 @@
 
 package com.android.wallpaper.picker.customization.ui
 
+import android.annotation.TargetApi
+import android.content.pm.ActivityInfo
+import android.content.res.Configuration
 import android.graphics.Color
 import android.graphics.Point
 import android.os.Bundle
 import android.view.View
+import android.view.ViewGroup
+import android.view.ViewGroup.MarginLayoutParams
+import android.widget.Button
 import android.widget.FrameLayout
 import android.widget.LinearLayout
+import android.widget.Toolbar
 import androidx.activity.OnBackPressedCallback
+import androidx.activity.result.contract.ActivityResultContracts
 import androidx.activity.viewModels
 import androidx.appcompat.app.AppCompatActivity
 import androidx.constraintlayout.motion.widget.MotionLayout
 import androidx.constraintlayout.motion.widget.MotionLayout.TransitionListener
 import androidx.constraintlayout.widget.ConstraintLayout
-import androidx.constraintlayout.widget.Guideline
+import androidx.constraintlayout.widget.ConstraintSet
+import androidx.core.view.ViewCompat
 import androidx.core.view.WindowCompat
+import androidx.core.view.WindowInsetsCompat
 import androidx.core.view.doOnLayout
 import androidx.core.view.doOnPreDraw
 import androidx.recyclerview.widget.RecyclerView
 import androidx.viewpager2.widget.ViewPager2
+import com.android.customization.picker.clock.ui.view.ClockViewFactory
 import com.android.wallpaper.R
 import com.android.wallpaper.model.Screen
 import com.android.wallpaper.model.Screen.HOME_SCREEN
 import com.android.wallpaper.model.Screen.LOCK_SCREEN
+import com.android.wallpaper.module.LargeScreenMultiPanesChecker
 import com.android.wallpaper.module.MultiPanesChecker
+import com.android.wallpaper.picker.common.preview.data.repository.PersistentWallpaperModelRepository
+import com.android.wallpaper.picker.common.preview.ui.binder.BasePreviewBinder
+import com.android.wallpaper.picker.common.preview.ui.binder.WorkspaceCallbackBinder
+import com.android.wallpaper.picker.customization.ui.binder.ColorUpdateBinder
 import com.android.wallpaper.picker.customization.ui.binder.CustomizationOptionsBinder
 import com.android.wallpaper.picker.customization.ui.binder.CustomizationPickerBinder2
+import com.android.wallpaper.picker.customization.ui.binder.ToolbarBinder
 import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil
 import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil.CustomizationOption
 import com.android.wallpaper.picker.customization.ui.view.adapter.PreviewPagerAdapter
 import com.android.wallpaper.picker.customization.ui.view.transformer.PreviewPagerPageTransformer
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
+import com.android.wallpaper.picker.di.modules.MainDispatcher
+import com.android.wallpaper.picker.preview.ui.WallpaperPreviewActivity
 import com.android.wallpaper.util.ActivityUtils
+import com.android.wallpaper.util.DisplayUtils
+import com.android.wallpaper.util.WallpaperConnection
+import com.android.wallpaper.util.converter.WallpaperModelFactory
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import dagger.hilt.android.AndroidEntryPoint
 import javax.inject.Inject
+import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.launch
 
 @AndroidEntryPoint(AppCompatActivity::class)
 class CustomizationPickerActivity2 : Hilt_CustomizationPickerActivity2() {
@@ -56,10 +84,26 @@ class CustomizationPickerActivity2 : Hilt_CustomizationPickerActivity2() {
     @Inject lateinit var multiPanesChecker: MultiPanesChecker
     @Inject lateinit var customizationOptionUtil: CustomizationOptionUtil
     @Inject lateinit var customizationOptionsBinder: CustomizationOptionsBinder
+    @Inject lateinit var workspaceCallbackBinder: WorkspaceCallbackBinder
+    @Inject lateinit var toolbarBinder: ToolbarBinder
+    @Inject lateinit var wallpaperModelFactory: WallpaperModelFactory
+    @Inject lateinit var persistentWallpaperModelRepository: PersistentWallpaperModelRepository
+    @Inject lateinit var displayUtils: DisplayUtils
+    @Inject @BackgroundDispatcher lateinit var backgroundScope: CoroutineScope
+    @Inject @MainDispatcher lateinit var mainScope: CoroutineScope
+    @Inject lateinit var wallpaperConnectionUtils: WallpaperConnectionUtils
+    @Inject lateinit var colorUpdateViewModel: ColorUpdateViewModel
+    @Inject lateinit var clockViewFactory: ClockViewFactory
 
     private var fullyCollapsed = false
+    private var navBarHeight: Int = 0
 
     private val customizationPickerViewModel: CustomizationPickerViewModel2 by viewModels()
+    private var customizationOptionFloatingSheetViewMap: Map<CustomizationOption, View>? = null
+    private var configuration: Configuration? = null
+
+    private val startForResult =
+        this.registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {}
 
     override fun onCreate(savedInstanceState: Bundle?) {
         super.onCreate(savedInstanceState)
@@ -79,17 +123,47 @@ class CustomizationPickerActivity2 : Hilt_CustomizationPickerActivity2() {
                 0, /* requestCode */
             )
             finish()
+            return
         }
 
+        configuration = Configuration(resources.configuration)
+
         setContentView(R.layout.activity_cusomization_picker2)
         WindowCompat.setDecorFitsSystemWindows(window, ActivityUtils.isSUWMode(this))
 
-        val rootView = requireViewById<MotionLayout>(R.id.picker_motion_layout)
+        setupToolbar(
+            requireViewById(R.id.nav_button),
+            requireViewById(R.id.toolbar),
+            requireViewById(R.id.apply_button),
+        )
 
-        customizationOptionUtil.initBottomSheetContent(
-            rootView.requireViewById<FrameLayout>(R.id.customization_picker_bottom_sheet),
-            layoutInflater,
+        val view = requireViewById<View>(R.id.root_view)
+        ColorUpdateBinder.bind(
+            setColor = { color -> view.setBackgroundColor(color) },
+            color = colorUpdateViewModel.colorSurfaceContainer,
+            shouldAnimate = { true },
+            lifecycleOwner = this,
         )
+
+        val rootView = requireViewById<MotionLayout>(R.id.picker_motion_layout)
+        ViewCompat.setOnApplyWindowInsetsListener(rootView) { _, windowInsets ->
+            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
+            navBarHeight = insets.bottom
+            requireViewById<FrameLayout>(R.id.customization_option_floating_sheet_container)
+                .setPaddingRelative(0, 0, 0, navBarHeight)
+            val statusBarHeight = insets.top
+            val params = requireViewById<Toolbar>(R.id.toolbar).layoutParams as MarginLayoutParams
+            params.setMargins(0, statusBarHeight, 0, 0)
+            WindowInsetsCompat.CONSUMED
+        }
+
+        customizationOptionFloatingSheetViewMap =
+            customizationOptionUtil.initFloatingSheet(
+                rootView.requireViewById<FrameLayout>(
+                    R.id.customization_option_floating_sheet_container
+                ),
+                layoutInflater,
+            )
         rootView.setTransitionListener(
             object : EmptyTransitionListener {
                 override fun onTransitionCompleted(motionLayout: MotionLayout?, currentId: Int) {
@@ -103,18 +177,17 @@ class CustomizationPickerActivity2 : Hilt_CustomizationPickerActivity2() {
             }
         )
 
-        initPreviewPager()
+        val previewViewModel = customizationPickerViewModel.basePreviewViewModel
+        previewViewModel.setWhichPreview(WallpaperConnection.WhichPreview.EDIT_CURRENT)
+        // TODO (b/348462236): adjust flow so this is always false when previewing current wallpaper
+        previewViewModel.setIsWallpaperColorPreviewEnabled(false)
+
+        initPreviewPager(isFirstBinding = savedInstanceState == null)
 
         val optionContainer = requireViewById<MotionLayout>(R.id.customization_option_container)
         // The collapsed header height should be updated when option container's height is known
         optionContainer.doOnPreDraw {
             // The bottom navigation bar height
-            val navBarHeight =
-                resources.getIdentifier("navigation_bar_height", "dimen", "android").let {
-                    if (it > 0) {
-                        resources.getDimensionPixelSize(it)
-                    } else 0
-                }
             val collapsedHeaderHeight = rootView.height - optionContainer.height - navBarHeight
             if (
                 collapsedHeaderHeight >
@@ -129,36 +202,38 @@ class CustomizationPickerActivity2 : Hilt_CustomizationPickerActivity2() {
             }
         }
 
-        val onBackPressed =
-            CustomizationPickerBinder2.bind(
-                view = rootView,
-                lockScreenCustomizationOptionEntries = initCustomizationOptionEntries(LOCK_SCREEN),
-                homeScreenCustomizationOptionEntries = initCustomizationOptionEntries(HOME_SCREEN),
-                viewModel = customizationPickerViewModel,
-                customizationOptionsBinder = customizationOptionsBinder,
-                lifecycleOwner = this,
-                navigateToPrimary = {
-                    if (rootView.currentState == R.id.secondary) {
-                        rootView.transitionToState(
-                            if (fullyCollapsed) R.id.collapsed_header_primary
-                            else R.id.expanded_header_primary
-                        )
-                    }
-                },
-                navigateToSecondary = { screen ->
-                    if (rootView.currentState != R.id.secondary) {
-                        setCustomizePickerBottomSheetContent(rootView, screen) {
-                            fullyCollapsed = rootView.progress == 1.0f
-                            rootView.transitionToState(R.id.secondary)
-                        }
+        CustomizationPickerBinder2.bind(
+            view = rootView,
+            lockScreenCustomizationOptionEntries = initCustomizationOptionEntries(LOCK_SCREEN),
+            homeScreenCustomizationOptionEntries = initCustomizationOptionEntries(HOME_SCREEN),
+            customizationOptionFloatingSheetViewMap = customizationOptionFloatingSheetViewMap,
+            viewModel = customizationPickerViewModel,
+            colorUpdateViewModel = colorUpdateViewModel,
+            customizationOptionsBinder = customizationOptionsBinder,
+            lifecycleOwner = this,
+            navigateToPrimary = {
+                if (rootView.currentState == R.id.secondary) {
+                    rootView.transitionToState(
+                        if (fullyCollapsed) R.id.collapsed_header_primary
+                        else R.id.expanded_header_primary
+                    )
+                }
+            },
+            navigateToSecondary = { screen ->
+                if (rootView.currentState != R.id.secondary) {
+                    setCustomizationOptionFloatingSheet(rootView, screen) {
+                        fullyCollapsed = rootView.progress == 1.0f
+                        rootView.transitionToState(R.id.secondary)
                     }
-                },
-            )
+                }
+            },
+        )
 
         onBackPressedDispatcher.addCallback(
             object : OnBackPressedCallback(true) {
                 override fun handleOnBackPressed() {
-                    val isOnBackPressedHandled = onBackPressed()
+                    val isOnBackPressedHandled =
+                        customizationPickerViewModel.customizationOptionsViewModel.deselectOption()
                     if (!isOnBackPressedHandled) {
                         remove()
                         onBackPressedDispatcher.onBackPressed()
@@ -168,13 +243,20 @@ class CustomizationPickerActivity2 : Hilt_CustomizationPickerActivity2() {
         )
     }
 
-    override fun onDestroy() {
-        customizationOptionUtil.onDestroy()
-        super.onDestroy()
+    private fun setupToolbar(navButton: FrameLayout, toolbar: Toolbar, applyButton: Button) {
+        toolbar.title = getString(R.string.app_name)
+        toolbar.setBackgroundColor(Color.TRANSPARENT)
+        toolbarBinder.bind(
+            navButton,
+            toolbar,
+            applyButton,
+            customizationPickerViewModel.customizationOptionsViewModel,
+            this,
+        )
     }
 
     private fun initCustomizationOptionEntries(
-        screen: Screen,
+        screen: Screen
     ): List<Pair<CustomizationOption, View>> {
         val optionEntriesContainer =
             requireViewById<LinearLayout>(
@@ -198,13 +280,71 @@ class CustomizationPickerActivity2 : Hilt_CustomizationPickerActivity2() {
         return optionEntries
     }
 
-    private fun initPreviewPager() {
+    private fun initPreviewPager(isFirstBinding: Boolean) {
         val pager = requireViewById<ViewPager2>(R.id.preview_pager)
+        val previewViewModel = customizationPickerViewModel.basePreviewViewModel
         pager.apply {
             adapter = PreviewPagerAdapter { viewHolder, position ->
-                viewHolder.itemView
-                    .requireViewById<View>(R.id.preview_card)
-                    .setBackgroundColor(if (position == 0) Color.BLUE else Color.CYAN)
+                val previewCard = viewHolder.itemView.requireViewById<View>(R.id.preview_card)
+                val screen =
+                    if (position == 0) {
+                        LOCK_SCREEN
+                    } else {
+                        HOME_SCREEN
+                    }
+
+                if (screen == LOCK_SCREEN) {
+                    val clockHostView =
+                        (previewCard.parent as? ViewGroup)?.let {
+                            customizationOptionUtil.createClockPreviewAndAddToParent(
+                                it,
+                                layoutInflater,
+                            )
+                        }
+                    if (clockHostView != null) {
+                        customizationOptionsBinder.bindClockPreview(
+                            clockHostView = clockHostView,
+                            viewModel = customizationPickerViewModel,
+                            lifecycleOwner = this@CustomizationPickerActivity2,
+                            clockViewFactory = clockViewFactory,
+                        )
+                    }
+                }
+
+                BasePreviewBinder.bind(
+                    applicationContext = applicationContext,
+                    view = previewCard,
+                    viewModel = customizationPickerViewModel,
+                    workspaceCallbackBinder = workspaceCallbackBinder,
+                    screen = screen,
+                    deviceDisplayType =
+                        displayUtils.getCurrentDisplayType(this@CustomizationPickerActivity2),
+                    displaySize =
+                        if (displayUtils.isOnWallpaperDisplay(this@CustomizationPickerActivity2))
+                            previewViewModel.wallpaperDisplaySize.value
+                        else previewViewModel.smallerDisplaySize,
+                    lifecycleOwner = this@CustomizationPickerActivity2,
+                    wallpaperConnectionUtils = wallpaperConnectionUtils,
+                    isFirstBindingDeferred = CompletableDeferred(isFirstBinding),
+                    onClick = {
+                        previewViewModel.wallpapers.value?.let {
+                            val wallpaper =
+                                if (screen == HOME_SCREEN) it.homeWallpaper
+                                else it.lockWallpaper ?: it.homeWallpaper
+                            persistentWallpaperModelRepository.setWallpaperModel(wallpaper)
+                        }
+                        val multiPanesChecker = LargeScreenMultiPanesChecker()
+                        val isMultiPanel = multiPanesChecker.isMultiPanesEnabled(applicationContext)
+                        startForResult.launch(
+                            WallpaperPreviewActivity.newIntent(
+                                context = applicationContext,
+                                isAssetIdPresent = false,
+                                isViewAsHome = screen == HOME_SCREEN,
+                                isNewTask = isMultiPanel,
+                            )
+                        )
+                    },
+                )
             }
             // Disable over scroll
             (getChildAt(0) as RecyclerView).overScrollMode = RecyclerView.OVER_SCROLL_NEVER
@@ -212,6 +352,7 @@ class CustomizationPickerActivity2 : Hilt_CustomizationPickerActivity2() {
             offscreenPageLimit = 1
             // When pager's height changes, request transform to recalculate the preview offset
             // to make sure correct space between the previews.
+            // TODO (b/348462236): figure out how to scale surface view content with layout change
             addOnLayoutChangeListener { view, _, _, _, _, _, topWas, _, bottomWas ->
                 val isHeightChanged = (bottomWas - topWas) != view.height
                 if (isHeightChanged) {
@@ -228,54 +369,98 @@ class CustomizationPickerActivity2 : Hilt_CustomizationPickerActivity2() {
         }
     }
 
-    private fun setCustomizePickerBottomSheetContent(
+    /**
+     * Set customization option floating sheet to the floating sheet container and get the new
+     * container's height for repositioning the preview's guideline.
+     */
+    private fun setCustomizationOptionFloatingSheet(
         motionContainer: MotionLayout,
         option: CustomizationOption,
-        onComplete: () -> Unit
+        onComplete: () -> Unit,
     ) {
-        val view = customizationOptionUtil.getBottomSheetContent(option) ?: return
+        val view = customizationOptionFloatingSheetViewMap?.get(option) ?: return
 
-        val customizationBottomSheet =
-            requireViewById<FrameLayout>(R.id.customization_picker_bottom_sheet)
-        val guideline = requireViewById<Guideline>(R.id.preview_guideline_in_secondary_screen)
-        customizationBottomSheet.removeAllViews()
-        customizationBottomSheet.addView(view)
+        val floatingSheetContainer =
+            requireViewById<FrameLayout>(R.id.customization_option_floating_sheet_container)
+        floatingSheetContainer.removeAllViews()
+        floatingSheetContainer.addView(view)
 
         view.doOnPreDraw {
-            val height = view.height
-            guideline.setGuidelineEnd(height)
-            customizationBottomSheet.translationY = 0.0f
-            customizationBottomSheet.alpha = 0.0f
+            val height = view.height + navBarHeight
+            floatingSheetContainer.translationY = 0.0f
+            floatingSheetContainer.alpha = 0.0f
             // Update the motion container
             motionContainer.getConstraintSet(R.id.expanded_header_primary)?.apply {
-                setTranslationY(R.id.customization_picker_bottom_sheet, 0.0f)
-                setAlpha(R.id.customization_picker_bottom_sheet, 0.0f)
+                setTranslationY(
+                    R.id.customization_option_floating_sheet_container,
+                    height.toFloat(),
+                )
+                setAlpha(R.id.customization_option_floating_sheet_container, 0.0f)
+                connect(
+                    R.id.customization_option_floating_sheet_container,
+                    ConstraintSet.BOTTOM,
+                    R.id.picker_motion_layout,
+                    ConstraintSet.BOTTOM,
+                )
                 constrainHeight(
-                    R.id.customization_picker_bottom_sheet,
-                    ConstraintLayout.LayoutParams.WRAP_CONTENT
+                    R.id.customization_option_floating_sheet_container,
+                    ConstraintLayout.LayoutParams.WRAP_CONTENT,
                 )
             }
             motionContainer.getConstraintSet(R.id.collapsed_header_primary)?.apply {
-                setTranslationY(R.id.customization_picker_bottom_sheet, 0.0f)
-                setAlpha(R.id.customization_picker_bottom_sheet, 0.0f)
+                setTranslationY(
+                    R.id.customization_option_floating_sheet_container,
+                    height.toFloat(),
+                )
+                setAlpha(R.id.customization_option_floating_sheet_container, 0.0f)
+                connect(
+                    R.id.customization_option_floating_sheet_container,
+                    ConstraintSet.BOTTOM,
+                    R.id.picker_motion_layout,
+                    ConstraintSet.BOTTOM,
+                )
                 constrainHeight(
-                    R.id.customization_picker_bottom_sheet,
-                    ConstraintLayout.LayoutParams.WRAP_CONTENT
+                    R.id.customization_option_floating_sheet_container,
+                    ConstraintLayout.LayoutParams.WRAP_CONTENT,
                 )
             }
             motionContainer.getConstraintSet(R.id.secondary)?.apply {
-                setGuidelineEnd(R.id.preview_guideline_in_secondary_screen, height)
-                setTranslationY(R.id.customization_picker_bottom_sheet, -height.toFloat())
-                setAlpha(R.id.customization_picker_bottom_sheet, 1.0f)
+                setTranslationY(R.id.customization_option_floating_sheet_container, 0.0f)
+                setAlpha(R.id.customization_option_floating_sheet_container, 1.0f)
                 constrainHeight(
-                    R.id.customization_picker_bottom_sheet,
-                    ConstraintLayout.LayoutParams.WRAP_CONTENT
+                    R.id.customization_option_floating_sheet_container,
+                    ConstraintLayout.LayoutParams.WRAP_CONTENT,
                 )
             }
             onComplete()
         }
     }
 
+    override fun onDestroy() {
+        // TODO(b/333879532): Only disconnect when leaving the Activity without introducing black
+        //  preview. If onDestroy is caused by an orientation change, we should keep the connection
+        //  to avoid initiating the engines again.
+        // TODO(b/328302105): MainScope ensures the job gets done non-blocking even if the
+        //   activity has been destroyed already. Consider making this part of
+        //   WallpaperConnectionUtils.
+        mainScope.launch { wallpaperConnectionUtils.disconnectAll(applicationContext) }
+
+        super.onDestroy()
+    }
+
+    @TargetApi(36)
+    override fun onConfigurationChanged(newConfig: Configuration) {
+        super.onConfigurationChanged(newConfig)
+        configuration?.let {
+            val diff = newConfig.diff(it)
+            val isAssetsPathsChange = diff and ActivityInfo.CONFIG_ASSETS_PATHS != 0
+            if (isAssetsPathsChange) {
+                colorUpdateViewModel.updateColors()
+            }
+        }
+        configuration?.setTo(newConfig)
+    }
+
     interface EmptyTransitionListener : TransitionListener {
         override fun onTransitionStarted(motionLayout: MotionLayout?, startId: Int, endId: Int) {
             // Do nothing intended
@@ -285,7 +470,7 @@ class CustomizationPickerActivity2 : Hilt_CustomizationPickerActivity2() {
             motionLayout: MotionLayout?,
             startId: Int,
             endId: Int,
-            progress: Float
+            progress: Float,
         ) {
             // Do nothing intended
         }
@@ -298,7 +483,7 @@ class CustomizationPickerActivity2 : Hilt_CustomizationPickerActivity2() {
             motionLayout: MotionLayout?,
             triggerId: Int,
             positive: Boolean,
-            progress: Float
+            progress: Float,
         ) {
             // Do nothing intended
         }
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/ColorUpdateBinder.kt b/src/com/android/wallpaper/picker/customization/ui/binder/ColorUpdateBinder.kt
new file mode 100644
index 00000000..304a3669
--- /dev/null
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/ColorUpdateBinder.kt
@@ -0,0 +1,64 @@
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
+package com.android.wallpaper.picker.customization.ui.binder
+
+import android.animation.Animator
+import android.animation.ValueAnimator
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.launch
+
+object ColorUpdateBinder {
+
+    private const val COLOR_ANIMATION_DURATION_MILLIS = 1500L
+
+    fun bind(
+        setColor: (color: Int) -> Unit,
+        color: Flow<Int>,
+        shouldAnimate: () -> Boolean = { true },
+        lifecycleOwner: LifecycleOwner,
+    ) {
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                var currentColor: Int? = null
+                var animator: Animator? = null
+                color.collect { newColor ->
+                    val previousColor = currentColor
+                    if (shouldAnimate() && previousColor != null) {
+                        animator?.end()
+                        ValueAnimator.ofArgb(
+                                previousColor,
+                                newColor,
+                            )
+                            .apply {
+                                addUpdateListener { setColor(it.animatedValue as Int) }
+                                duration = COLOR_ANIMATION_DURATION_MILLIS
+                            }
+                            .also { animator = it }
+                            .start()
+                    } else {
+                        setColor(newColor)
+                    }
+                    currentColor = newColor
+                }
+            }
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationOptionsBinder.kt b/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationOptionsBinder.kt
index 1fd63452..7a64605d 100644
--- a/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationOptionsBinder.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationOptionsBinder.kt
@@ -18,8 +18,10 @@ package com.android.wallpaper.picker.customization.ui.binder
 
 import android.view.View
 import androidx.lifecycle.LifecycleOwner
+import com.android.customization.picker.clock.ui.view.ClockViewFactory
 import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil.CustomizationOption
-import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2
 
 interface CustomizationOptionsBinder {
 
@@ -27,7 +29,16 @@ interface CustomizationOptionsBinder {
         view: View,
         lockScreenCustomizationOptionEntries: List<Pair<CustomizationOption, View>>,
         homeScreenCustomizationOptionEntries: List<Pair<CustomizationOption, View>>,
-        viewModel: CustomizationOptionsViewModel,
+        customizationOptionFloatingSheetViewMap: Map<CustomizationOption, View>?,
+        viewModel: CustomizationPickerViewModel2,
+        colorUpdateViewModel: ColorUpdateViewModel,
         lifecycleOwner: LifecycleOwner,
     )
+
+    fun bindClockPreview(
+        clockHostView: View,
+        viewModel: CustomizationPickerViewModel2,
+        lifecycleOwner: LifecycleOwner,
+        clockViewFactory: ClockViewFactory,
+    )
 }
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationPickerBinder2.kt b/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationPickerBinder2.kt
index 485035bc..d54279ab 100644
--- a/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationPickerBinder2.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationPickerBinder2.kt
@@ -18,16 +18,19 @@ package com.android.wallpaper.picker.customization.ui.binder
 
 import android.view.View
 import androidx.constraintlayout.motion.widget.MotionLayout
+import androidx.core.view.doOnLayout
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
+import androidx.recyclerview.widget.RecyclerView
 import androidx.viewpager2.widget.ViewPager2
 import com.android.wallpaper.R
 import com.android.wallpaper.model.Screen.HOME_SCREEN
 import com.android.wallpaper.model.Screen.LOCK_SCREEN
 import com.android.wallpaper.picker.customization.ui.CustomizationPickerActivity2
 import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil.CustomizationOption
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2.PickerScreen.CUSTOMIZATION_OPTION
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2.PickerScreen.MAIN
@@ -35,6 +38,11 @@ import kotlinx.coroutines.launch
 
 object CustomizationPickerBinder2 {
 
+    private const val ALPHA_SELECTED_PREVIEW = 1f
+    private const val ALPHA_NON_SELECTED_PREVIEW = 0.4f
+    private const val LOCK_SCREEN_PREVIEW_POSITION = 0
+    private const val HOME_SCREEN_PREVIEW_POSITION = 1
+
     /**
      * @return Callback for the [CustomizationPickerActivity2] to set
      *   [CustomizationPickerViewModel2]'s screen state to null, which infers to the main screen. We
@@ -44,22 +52,86 @@ object CustomizationPickerBinder2 {
         view: View,
         lockScreenCustomizationOptionEntries: List<Pair<CustomizationOption, View>>,
         homeScreenCustomizationOptionEntries: List<Pair<CustomizationOption, View>>,
+        customizationOptionFloatingSheetViewMap: Map<CustomizationOption, View>?,
         viewModel: CustomizationPickerViewModel2,
+        colorUpdateViewModel: ColorUpdateViewModel,
         customizationOptionsBinder: CustomizationOptionsBinder,
         lifecycleOwner: LifecycleOwner,
         navigateToPrimary: () -> Unit,
         navigateToSecondary: (screen: CustomizationOption) -> Unit,
-    ): () -> Boolean {
+    ) {
         val optionContainer =
             view.requireViewById<MotionLayout>(R.id.customization_option_container)
         val pager = view.requireViewById<ViewPager2>(R.id.preview_pager)
         pager.registerOnPageChangeCallback(
             object : ViewPager2.OnPageChangeCallback() {
                 override fun onPageSelected(position: Int) {
-                    viewModel.selectPreviewScreen(if (position == 0) LOCK_SCREEN else HOME_SCREEN)
+                    viewModel.selectPreviewScreen(
+                        if (position == LOCK_SCREEN_PREVIEW_POSITION) LOCK_SCREEN else HOME_SCREEN
+                    )
                 }
             }
         )
+        val mediumAnimTimeMs =
+            view.resources.getInteger(android.R.integer.config_mediumAnimTime).toLong()
+        pager.doOnLayout {
+            // RecyclerView items can only be reliably retrieved on layout.
+            val lockScreenPreview =
+                (pager.getChildAt(0) as? RecyclerView)
+                    ?.findViewHolderForAdapterPosition(LOCK_SCREEN_PREVIEW_POSITION)
+                    ?.itemView
+            val homeScreenPreview =
+                (pager.getChildAt(0) as? RecyclerView)
+                    ?.findViewHolderForAdapterPosition(HOME_SCREEN_PREVIEW_POSITION)
+                    ?.itemView
+            val fadePreview = { position: Int ->
+                lockScreenPreview?.apply {
+                    findViewById<View>(R.id.wallpaper_surface)
+                        .animate()
+                        .alpha(
+                            if (position == LOCK_SCREEN_PREVIEW_POSITION) ALPHA_SELECTED_PREVIEW
+                            else ALPHA_NON_SELECTED_PREVIEW
+                        )
+                        .setDuration(mediumAnimTimeMs)
+                        .start()
+                    findViewById<View>(R.id.workspace_surface)
+                        .animate()
+                        .alpha(
+                            if (position == LOCK_SCREEN_PREVIEW_POSITION) ALPHA_SELECTED_PREVIEW
+                            else ALPHA_NON_SELECTED_PREVIEW
+                        )
+                        .setDuration(mediumAnimTimeMs)
+                        .start()
+                }
+                homeScreenPreview?.apply {
+                    findViewById<View>(R.id.wallpaper_surface)
+                        .animate()
+                        .alpha(
+                            if (position == HOME_SCREEN_PREVIEW_POSITION) ALPHA_SELECTED_PREVIEW
+                            else ALPHA_NON_SELECTED_PREVIEW
+                        )
+                        .setDuration(mediumAnimTimeMs)
+                        .start()
+                    findViewById<View>(R.id.workspace_surface)
+                        .animate()
+                        .alpha(
+                            if (position == HOME_SCREEN_PREVIEW_POSITION) ALPHA_SELECTED_PREVIEW
+                            else ALPHA_NON_SELECTED_PREVIEW
+                        )
+                        .setDuration(mediumAnimTimeMs)
+                        .start()
+                }
+            }
+            fadePreview(pager.currentItem)
+            pager.registerOnPageChangeCallback(
+                object : ViewPager2.OnPageChangeCallback() {
+                    override fun onPageSelected(position: Int) {
+                        super.onPageSelected(position)
+                        fadePreview(position)
+                    }
+                }
+            )
+        }
 
         lifecycleOwner.lifecycleScope.launch {
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
@@ -93,9 +165,10 @@ object CustomizationPickerBinder2 {
             view,
             lockScreenCustomizationOptionEntries,
             homeScreenCustomizationOptionEntries,
-            viewModel.customizationOptionsViewModel,
+            customizationOptionFloatingSheetViewMap,
+            viewModel,
+            colorUpdateViewModel,
             lifecycleOwner,
         )
-        return { viewModel.onBackPressed() }
     }
 }
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/DefaultCustomizationOptionsBinder.kt b/src/com/android/wallpaper/picker/customization/ui/binder/DefaultCustomizationOptionsBinder.kt
index 55e142bf..76e4d536 100644
--- a/src/com/android/wallpaper/picker/customization/ui/binder/DefaultCustomizationOptionsBinder.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/DefaultCustomizationOptionsBinder.kt
@@ -16,10 +16,18 @@
 
 package com.android.wallpaper.picker.customization.ui.binder
 
+import android.content.res.ColorStateList
 import android.view.View
+import android.widget.TextView
+import androidx.core.widget.TextViewCompat
 import androidx.lifecycle.LifecycleOwner
+import com.android.customization.picker.clock.ui.view.ClockViewFactory
+import com.android.wallpaper.R
+import com.android.wallpaper.model.Screen
 import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil.CustomizationOption
-import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
+import com.android.wallpaper.picker.customization.ui.util.DefaultCustomizationOptionUtil
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2
 import javax.inject.Inject
 import javax.inject.Singleton
 
@@ -30,7 +38,65 @@ class DefaultCustomizationOptionsBinder @Inject constructor() : CustomizationOpt
         view: View,
         lockScreenCustomizationOptionEntries: List<Pair<CustomizationOption, View>>,
         homeScreenCustomizationOptionEntries: List<Pair<CustomizationOption, View>>,
-        viewModel: CustomizationOptionsViewModel,
-        lifecycleOwner: LifecycleOwner
-    ) {}
+        customizationOptionFloatingSheetViewMap: Map<CustomizationOption, View>?,
+        viewModel: CustomizationPickerViewModel2,
+        colorUpdateViewModel: ColorUpdateViewModel,
+        lifecycleOwner: LifecycleOwner,
+    ) {
+        val optionLockWallpaper =
+            lockScreenCustomizationOptionEntries
+                .find {
+                    it.first ==
+                        DefaultCustomizationOptionUtil.DefaultLockCustomizationOption.WALLPAPER
+                }
+                ?.second
+        val moreWallpapersLock = optionLockWallpaper?.findViewById<TextView>(R.id.more_wallpapers)
+        val optionHomeWallpaper =
+            homeScreenCustomizationOptionEntries
+                .find {
+                    it.first ==
+                        DefaultCustomizationOptionUtil.DefaultHomeCustomizationOption.WALLPAPER
+                }
+                ?.second
+        val moreWallpapersHome = optionHomeWallpaper?.findViewById<TextView>(R.id.more_wallpapers)
+
+        ColorUpdateBinder.bind(
+            setColor = { color ->
+                moreWallpapersLock?.apply {
+                    setTextColor(color)
+                    TextViewCompat.setCompoundDrawableTintList(this, ColorStateList.valueOf(color))
+                }
+            },
+            color = colorUpdateViewModel.colorPrimary,
+            shouldAnimate = {
+                viewModel.selectedPreviewScreen.value == Screen.LOCK_SCREEN &&
+                    viewModel.customizationOptionsViewModel.selectedOption.value == null
+            },
+            lifecycleOwner = lifecycleOwner,
+        )
+
+        ColorUpdateBinder.bind(
+            setColor = { color ->
+                moreWallpapersHome?.apply {
+                    setTextColor(color)
+                    TextViewCompat.setCompoundDrawableTintList(this, ColorStateList.valueOf(color))
+                }
+            },
+            color = colorUpdateViewModel.colorPrimary,
+            shouldAnimate = {
+                viewModel.selectedPreviewScreen.value == Screen.HOME_SCREEN &&
+                    viewModel.customizationOptionsViewModel.selectedOption.value == null
+            },
+            lifecycleOwner = lifecycleOwner,
+        )
+    }
+
+    override fun bindClockPreview(
+        clockHostView: View,
+        viewModel: CustomizationPickerViewModel2,
+        lifecycleOwner: LifecycleOwner,
+        clockViewFactory: ClockViewFactory,
+    ) {
+        // Do nothing intended
+    }
 }
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/DefaultToolbarBinder.kt b/src/com/android/wallpaper/picker/customization/ui/binder/DefaultToolbarBinder.kt
new file mode 100644
index 00000000..63eb1414
--- /dev/null
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/DefaultToolbarBinder.kt
@@ -0,0 +1,66 @@
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
+package com.android.wallpaper.picker.customization.ui.binder
+
+import android.view.View
+import android.widget.Button
+import android.widget.FrameLayout
+import android.widget.Toolbar
+import androidx.appcompat.content.res.AppCompatResources
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import com.android.wallpaper.R
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.launch
+
+@Singleton
+class DefaultToolbarBinder @Inject constructor() : ToolbarBinder {
+
+    override fun bind(
+        navButton: FrameLayout,
+        toolbar: Toolbar,
+        applyButton: Button,
+        viewModel: CustomizationOptionsViewModel,
+        lifecycleOwner: LifecycleOwner,
+    ) {
+        val appContext = navButton.context.applicationContext
+        val navButtonIcon = navButton.requireViewById<View>(R.id.nav_button_icon)
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                launch {
+                    viewModel.selectedOption.collect {
+                        if (it == null) {
+                            navButtonIcon.background =
+                                AppCompatResources.getDrawable(
+                                    appContext,
+                                    R.drawable.ic_arrow_back_24dp
+                                )
+                        } else {
+                            navButtonIcon.background =
+                                AppCompatResources.getDrawable(appContext, R.drawable.ic_close_24dp)
+                            navButtonIcon.setOnClickListener { viewModel.deselectOption() }
+                        }
+                    }
+                }
+            }
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/ScreenPreviewBinder.kt b/src/com/android/wallpaper/picker/customization/ui/binder/ScreenPreviewBinder.kt
index d8cdb008..4cccb9aa 100644
--- a/src/com/android/wallpaper/picker/customization/ui/binder/ScreenPreviewBinder.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/ScreenPreviewBinder.kt
@@ -175,6 +175,19 @@ object ScreenPreviewBinder {
             cleanupWallpaperConnectionRunnable.run()
         }
 
+        val activityLifecycleObserver =
+            object : DefaultLifecycleObserver {
+                override fun onStop(owner: LifecycleOwner) {
+                    super.onStop(owner)
+                    // Wallpaper connection does not need to be detached between
+                    // fragments. Detach in activity onStop so that it is detached
+                    // when CustomizationPickerActivity is put on the back stack or
+                    // destroyed.
+                    wallpaperConnection?.detachConnection()
+                }
+            }
+        (activity as LifecycleOwner).lifecycle.addObserver(activityLifecycleObserver)
+
         val job =
             lifecycleOwner.lifecycleScope.launch {
                 launch {
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/ToolbarBinder.kt b/src/com/android/wallpaper/picker/customization/ui/binder/ToolbarBinder.kt
new file mode 100644
index 00000000..0b08d98d
--- /dev/null
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/ToolbarBinder.kt
@@ -0,0 +1,34 @@
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
+package com.android.wallpaper.picker.customization.ui.binder
+
+import android.widget.Button
+import android.widget.FrameLayout
+import android.widget.Toolbar
+import androidx.lifecycle.LifecycleOwner
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
+
+interface ToolbarBinder {
+
+    fun bind(
+        navButton: FrameLayout,
+        toolbar: Toolbar,
+        applyButton: Button,
+        viewModel: CustomizationOptionsViewModel,
+        lifecycleOwner: LifecycleOwner,
+    )
+}
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/WallpaperQuickSwitchSectionBinder.kt b/src/com/android/wallpaper/picker/customization/ui/binder/WallpaperQuickSwitchSectionBinder.kt
index 3e0a6730..8baa3464 100644
--- a/src/com/android/wallpaper/picker/customization/ui/binder/WallpaperQuickSwitchSectionBinder.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/WallpaperQuickSwitchSectionBinder.kt
@@ -53,8 +53,7 @@ object WallpaperQuickSwitchSectionBinder {
         } else {
             optionContainer.visibility = View.VISIBLE
             // We have to wait for the container to be laid out before we can bind it because we
-            // need
-            // its size to calculate the sizes of the option items.
+            // need its size to calculate the sizes of the option items.
             optionContainer.doOnLayout {
                 lifecycleOwner.lifecycleScope.launch {
                     lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
diff --git a/src/com/android/wallpaper/picker/customization/ui/section/WallpaperQuickSwitchSectionController.kt b/src/com/android/wallpaper/picker/customization/ui/section/WallpaperQuickSwitchSectionController.kt
index 40df4dce..c119dcd7 100644
--- a/src/com/android/wallpaper/picker/customization/ui/section/WallpaperQuickSwitchSectionController.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/section/WallpaperQuickSwitchSectionController.kt
@@ -22,8 +22,10 @@ import android.content.Context
 import android.view.LayoutInflater
 import androidx.lifecycle.LifecycleOwner
 import com.android.wallpaper.R
+import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.model.CustomizationSectionController
 import com.android.wallpaper.picker.CategorySelectorFragment
+import com.android.wallpaper.picker.category.ui.view.CategoriesFragment
 import com.android.wallpaper.picker.customization.ui.binder.WallpaperQuickSwitchSectionBinder
 import com.android.wallpaper.picker.customization.ui.viewmodel.WallpaperQuickSwitchViewModel
 
@@ -53,7 +55,11 @@ class WallpaperQuickSwitchSectionController(
             lifecycleOwner = lifecycleOwner,
             isThumbnailFadeAnimationEnabled = isThumbnailFadeAnimationEnabled,
             onNavigateToFullWallpaperSelector = {
-                navigator.navigateTo(CategorySelectorFragment())
+                if (BaseFlags.get().isWallpaperCategoryRefactoringEnabled()) {
+                    navigator.navigateTo(CategoriesFragment())
+                } else {
+                    navigator.navigateTo(CategorySelectorFragment())
+                }
             },
         )
         return view
diff --git a/src/com/android/wallpaper/picker/customization/ui/util/CustomizationOptionUtil.kt b/src/com/android/wallpaper/picker/customization/ui/util/CustomizationOptionUtil.kt
index 4bf3966a..5add328c 100644
--- a/src/com/android/wallpaper/picker/customization/ui/util/CustomizationOptionUtil.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/util/CustomizationOptionUtil.kt
@@ -18,6 +18,7 @@ package com.android.wallpaper.picker.customization.ui.util
 
 import android.view.LayoutInflater
 import android.view.View
+import android.view.ViewGroup
 import android.widget.FrameLayout
 import android.widget.LinearLayout
 import com.android.wallpaper.model.Screen
@@ -34,13 +35,13 @@ interface CustomizationOptionUtil {
         layoutInflater: LayoutInflater,
     ): List<Pair<CustomizationOption, View>>
 
-    fun initBottomSheetContent(bottomSheetContainer: FrameLayout, layoutInflater: LayoutInflater)
-
-    fun getBottomSheetContent(option: CustomizationOption): View?
+    fun initFloatingSheet(
+        bottomSheetContainer: FrameLayout,
+        layoutInflater: LayoutInflater,
+    ): Map<CustomizationOption, View>
 
-    /**
-     * This function should be called when on destroy. The implementation should release any view
-     * references.
-     */
-    fun onDestroy()
+    fun createClockPreviewAndAddToParent(
+        parentView: ViewGroup,
+        layoutInflater: LayoutInflater,
+    ): View?
 }
diff --git a/src/com/android/wallpaper/picker/customization/ui/util/DefaultCustomizationOptionUtil.kt b/src/com/android/wallpaper/picker/customization/ui/util/DefaultCustomizationOptionUtil.kt
index 0f034e04..39991d18 100644
--- a/src/com/android/wallpaper/picker/customization/ui/util/DefaultCustomizationOptionUtil.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/util/DefaultCustomizationOptionUtil.kt
@@ -18,6 +18,7 @@ package com.android.wallpaper.picker.customization.ui.util
 
 import android.view.LayoutInflater
 import android.view.View
+import android.view.ViewGroup
 import android.widget.FrameLayout
 import android.widget.LinearLayout
 import com.android.wallpaper.R
@@ -32,15 +33,13 @@ import javax.inject.Inject
 class DefaultCustomizationOptionUtil @Inject constructor() : CustomizationOptionUtil {
 
     enum class DefaultLockCustomizationOption : CustomizationOption {
-        WALLPAPER,
+        WALLPAPER
     }
 
     enum class DefaultHomeCustomizationOption : CustomizationOption {
-        WALLPAPER,
+        WALLPAPER
     }
 
-    private var viewMap: Map<CustomizationOption, View>? = null
-
     override fun getOptionEntries(
         screen: Screen,
         optionContainer: LinearLayout,
@@ -53,7 +52,7 @@ class DefaultCustomizationOptionUtil @Inject constructor() : CustomizationOption
                         layoutInflater.inflate(
                             R.layout.customization_option_entry_wallpaper,
                             optionContainer,
-                            false
+                            false,
                         )
                 )
             HOME_SCREEN ->
@@ -62,23 +61,20 @@ class DefaultCustomizationOptionUtil @Inject constructor() : CustomizationOption
                         layoutInflater.inflate(
                             R.layout.customization_option_entry_wallpaper,
                             optionContainer,
-                            false
+                            false,
                         )
                 )
         }
 
-    override fun initBottomSheetContent(
+    override fun initFloatingSheet(
         bottomSheetContainer: FrameLayout,
-        layoutInflater: LayoutInflater
-    ) {
-        viewMap = mapOf()
-    }
-
-    override fun getBottomSheetContent(option: CustomizationOption): View? {
-        return viewMap?.get(option)
-    }
+        layoutInflater: LayoutInflater,
+    ): Map<CustomizationOption, View> = mapOf()
 
-    override fun onDestroy() {
-        viewMap = null
+    override fun createClockPreviewAndAddToParent(
+        parentView: ViewGroup,
+        layoutInflater: LayoutInflater,
+    ): View? {
+        return null
     }
 }
diff --git a/src/com/android/wallpaper/picker/customization/ui/view/FloatingToolbar.kt b/src/com/android/wallpaper/picker/customization/ui/view/FloatingToolbar.kt
new file mode 100644
index 00000000..8751d697
--- /dev/null
+++ b/src/com/android/wallpaper/picker/customization/ui/view/FloatingToolbar.kt
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
+
+package com.android.wallpaper.picker.customization.ui.view
+
+import android.content.Context
+import android.util.AttributeSet
+import android.widget.FrameLayout
+import androidx.recyclerview.widget.RecyclerView
+import com.android.wallpaper.R
+import com.android.wallpaper.picker.common.ui.view.ItemSpacing
+import com.android.wallpaper.picker.customization.ui.view.adapter.FloatingToolbarTabAdapter
+import com.android.wallpaper.picker.customization.ui.view.animator.TabItemAnimator
+
+class FloatingToolbar(
+    context: Context,
+    attrs: AttributeSet?,
+) :
+    FrameLayout(
+        context,
+        attrs,
+    ) {
+
+    private val tabList: RecyclerView
+
+    init {
+        inflate(context, R.layout.floating_toolbar, this)
+        tabList =
+            requireViewById<RecyclerView>(R.id.tab_list).apply {
+                itemAnimator = TabItemAnimator()
+                addItemDecoration(ItemSpacing(TAB_SPACE_DP))
+            }
+    }
+
+    fun setAdapter(floatingToolbarTabAdapter: FloatingToolbarTabAdapter) {
+        tabList.adapter = floatingToolbarTabAdapter
+    }
+
+    companion object {
+        const val TAB_SPACE_DP = 4
+    }
+}
diff --git a/src/com/android/wallpaper/picker/customization/ui/view/adapter/FloatingToolbarTabAdapter.kt b/src/com/android/wallpaper/picker/customization/ui/view/adapter/FloatingToolbarTabAdapter.kt
new file mode 100644
index 00000000..f0e69aa8
--- /dev/null
+++ b/src/com/android/wallpaper/picker/customization/ui/view/adapter/FloatingToolbarTabAdapter.kt
@@ -0,0 +1,209 @@
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
+package com.android.wallpaper.picker.customization.ui.view.adapter
+
+import android.graphics.BlendMode
+import android.graphics.BlendModeColorFilter
+import android.view.LayoutInflater
+import android.view.View
+import android.view.ViewGroup
+import android.widget.ImageView
+import android.widget.TextView
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.LifecycleRegistry
+import androidx.recyclerview.widget.DiffUtil
+import androidx.recyclerview.widget.ListAdapter
+import androidx.recyclerview.widget.RecyclerView
+import com.android.wallpaper.R
+import com.android.wallpaper.picker.common.icon.ui.viewbinder.IconViewBinder
+import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
+import com.android.wallpaper.picker.customization.ui.binder.ColorUpdateBinder
+import com.android.wallpaper.picker.customization.ui.view.animator.TabItemAnimator.Companion.BACKGROUND_ALPHA_MAX
+import com.android.wallpaper.picker.customization.ui.view.animator.TabItemAnimator.Companion.SELECT_ITEM
+import com.android.wallpaper.picker.customization.ui.view.animator.TabItemAnimator.Companion.UNSELECT_ITEM
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
+import com.android.wallpaper.picker.customization.ui.viewmodel.FloatingToolbarTabViewModel
+import java.lang.ref.WeakReference
+
+/** List adapter for the floating toolbar of tabs. */
+class FloatingToolbarTabAdapter(
+    private val colorUpdateViewModel: WeakReference<ColorUpdateViewModel>,
+    private val shouldAnimateColor: () -> Boolean,
+) :
+    ListAdapter<FloatingToolbarTabViewModel, FloatingToolbarTabAdapter.TabViewHolder>(
+        ProductDiffCallback()
+    ) {
+
+    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): TabViewHolder {
+        val view =
+            LayoutInflater.from(parent.context)
+                .inflate(
+                    R.layout.floating_toolbar_tab,
+                    parent,
+                    false,
+                )
+        val tabViewHolder = TabViewHolder(view)
+        return tabViewHolder
+    }
+
+    override fun onBindViewHolder(
+        holder: TabViewHolder,
+        position: Int,
+        payloads: MutableList<Any>,
+    ) {
+        val payload = if (payloads.isNotEmpty()) payloads[0] as? Int else null
+        val item = getItem(position)
+        when (payload) {
+            SELECT_ITEM -> {
+                // When transition from unselected to selected, initial state should be unselected
+                bindViewHolder(holder, item.icon, item.text, false, item.onClick)
+            }
+            UNSELECT_ITEM -> {
+                // When transition from selected to unselected, initial state should be selected
+                bindViewHolder(holder, item.icon, item.text, true, item.onClick)
+            }
+            else -> super.onBindViewHolder(holder, position, payloads)
+        }
+    }
+
+    override fun onBindViewHolder(holder: TabViewHolder, position: Int) {
+        // Bind tab color in onBindViewHolder and destroy in onViewRecycled. Bind in this
+        // onBindViewHolder instead of the one with payload since this function is generally
+        // called when view holders are created or recycled, ensuring each view holder is only
+        // bound once, whereas the view holder with payload is called not only in the above cases,
+        // but also when the state is changed, which could result in multiple bindings.
+        colorUpdateViewModel.get()?.let {
+            ColorUpdateBinder.bind(
+                setColor = { color ->
+                    holder.itemView.background.colorFilter =
+                        BlendModeColorFilter(color, BlendMode.SRC_ATOP)
+                },
+                color = it.colorSecondaryContainer,
+                shouldAnimate = shouldAnimateColor,
+                lifecycleOwner = holder,
+            )
+        }
+
+        val item = getItem(position)
+        bindViewHolder(holder, item.icon, item.text, item.isSelected, item.onClick)
+    }
+
+    private fun bindViewHolder(
+        holder: TabViewHolder,
+        icon: Icon,
+        text: String,
+        isSelected: Boolean,
+        onClick: (() -> Unit)?,
+    ) {
+        IconViewBinder.bind(holder.icon, icon)
+        holder.label.text = text
+        val iconSize =
+            holder.itemView.resources.getDimensionPixelSize(
+                R.dimen.floating_tab_toolbar_tab_icon_size
+            )
+        holder.icon.layoutParams =
+            holder.icon.layoutParams.apply { width = if (isSelected) iconSize else 0 }
+        holder.container.background.alpha = if (isSelected) BACKGROUND_ALPHA_MAX else 0
+        holder.itemView.setOnClickListener { onClick?.invoke() }
+    }
+
+    override fun onViewAttachedToWindow(holder: TabViewHolder) {
+        super.onViewAttachedToWindow(holder)
+        holder.onAttachToWindow()
+    }
+
+    override fun onViewDetachedFromWindow(holder: TabViewHolder) {
+        super.onViewDetachedFromWindow(holder)
+        holder.onDetachFromWindow()
+    }
+
+    override fun onViewRecycled(holder: TabViewHolder) {
+        super.onViewRecycled(holder)
+        holder.onRecycled()
+    }
+
+    /**
+     * A [RecyclerView.ViewHolder] for the floating tabs recycler view, that also extends
+     * [LifecycleOwner] to enable binding flows and collecting based on lifecycle states. This
+     * optimizes the binding so that view holders that are not visible on screen will not be
+     * actively collecting and updating from a bound flow. The lifecycle state is created when the
+     * ViewHolder is created, then started and stopped in onViewAttachedToWindow and
+     * onViewDetachedFromWindow, and destroyed in onViewRecycled, where a new lifecycle is created.
+     */
+    class TabViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView), LifecycleOwner {
+        val container = itemView.requireViewById<ViewGroup>(R.id.tab_container)
+        val icon = itemView.requireViewById<ImageView>(R.id.tab_icon)
+        val label = itemView.requireViewById<TextView>(R.id.label_text)
+
+        private lateinit var lifecycleRegistry: LifecycleRegistry
+        override val lifecycle: Lifecycle
+            get() = lifecycleRegistry
+
+        init {
+            initializeRegistry()
+        }
+
+        private fun initializeRegistry() {
+            lifecycleRegistry =
+                LifecycleRegistry(this).also { it.handleLifecycleEvent(Lifecycle.Event.ON_CREATE) }
+        }
+
+        fun onAttachToWindow() {
+            lifecycleRegistry.handleLifecycleEvent(Lifecycle.Event.ON_START)
+        }
+
+        fun onDetachFromWindow() {
+            lifecycleRegistry.handleLifecycleEvent(Lifecycle.Event.ON_STOP)
+        }
+
+        fun onRecycled() {
+            lifecycleRegistry.handleLifecycleEvent(Lifecycle.Event.ON_DESTROY)
+            initializeRegistry()
+        }
+    }
+
+    private class ProductDiffCallback : DiffUtil.ItemCallback<FloatingToolbarTabViewModel>() {
+
+        override fun areItemsTheSame(
+            oldItem: FloatingToolbarTabViewModel,
+            newItem: FloatingToolbarTabViewModel
+        ): Boolean {
+            return oldItem.text == newItem.text
+        }
+
+        override fun areContentsTheSame(
+            oldItem: FloatingToolbarTabViewModel,
+            newItem: FloatingToolbarTabViewModel
+        ): Boolean {
+            return oldItem.text == newItem.text &&
+                oldItem.isSelected == newItem.isSelected &&
+                oldItem.icon == newItem.icon
+        }
+
+        override fun getChangePayload(
+            oldItem: FloatingToolbarTabViewModel,
+            newItem: FloatingToolbarTabViewModel
+        ): Any? {
+            return when {
+                !oldItem.isSelected && newItem.isSelected -> SELECT_ITEM
+                oldItem.isSelected && !newItem.isSelected -> UNSELECT_ITEM
+                else -> null
+            }
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/picker/customization/ui/view/adapter/PreviewPagerAdapter.kt b/src/com/android/wallpaper/picker/customization/ui/view/adapter/PreviewPagerAdapter.kt
index 11f37dd4..44d19e47 100644
--- a/src/com/android/wallpaper/picker/customization/ui/view/adapter/PreviewPagerAdapter.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/view/adapter/PreviewPagerAdapter.kt
@@ -21,13 +21,15 @@ import android.view.ViewGroup
 import androidx.recyclerview.widget.RecyclerView
 import com.android.wallpaper.R
 
-/** This adapter provides preview views for the small preview fragment */
+/** This adapter provides preview views for the main page previews */
 class PreviewPagerAdapter(
     private val onBindViewHolder: (ViewHolder, Int) -> Unit,
 ) : RecyclerView.Adapter<PreviewPagerAdapter.ViewHolder>() {
 
     override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
-        val view = LayoutInflater.from(parent.context).inflate(R.layout.preview_card, parent, false)
+        val view =
+            LayoutInflater.from(parent.context)
+                .inflate(R.layout.customization_picker_preview_card, parent, false)
         // TODO (b/343286927): Add content description for a11y
         view.setPadding(
             0,
diff --git a/src/com/android/wallpaper/picker/customization/ui/view/animator/TabItemAnimator.kt b/src/com/android/wallpaper/picker/customization/ui/view/animator/TabItemAnimator.kt
new file mode 100644
index 00000000..f20d3927
--- /dev/null
+++ b/src/com/android/wallpaper/picker/customization/ui/view/animator/TabItemAnimator.kt
@@ -0,0 +1,93 @@
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
+package com.android.wallpaper.picker.customization.ui.view.animator
+
+import android.animation.ValueAnimator
+import androidx.core.animation.addListener
+import androidx.core.animation.doOnEnd
+import androidx.recyclerview.widget.DefaultItemAnimator
+import androidx.recyclerview.widget.RecyclerView.State
+import androidx.recyclerview.widget.RecyclerView.ViewHolder
+import com.android.wallpaper.R
+import com.android.wallpaper.picker.customization.ui.view.adapter.FloatingToolbarTabAdapter.TabViewHolder
+
+class TabItemAnimator : DefaultItemAnimator() {
+
+    override fun canReuseUpdatedViewHolder(viewHolder: ViewHolder, payloads: MutableList<Any>) =
+        true
+
+    override fun recordPreLayoutInformation(
+        state: State,
+        viewHolder: ViewHolder,
+        changeFlags: Int,
+        payloads: MutableList<Any>
+    ): ItemHolderInfo {
+        if (changeFlags == FLAG_CHANGED && payloads.isNotEmpty()) {
+            return when (payloads[0] as? Int) {
+                SELECT_ITEM -> TabItemHolderInfo(true)
+                UNSELECT_ITEM -> TabItemHolderInfo(false)
+                else -> super.recordPreLayoutInformation(state, viewHolder, changeFlags, payloads)
+            }
+        }
+        return super.recordPreLayoutInformation(state, viewHolder, changeFlags, payloads)
+    }
+
+    override fun animateChange(
+        oldHolder: ViewHolder,
+        newHolder: ViewHolder,
+        preLayoutInfo: ItemHolderInfo,
+        postLayoutInfo: ItemHolderInfo,
+    ): Boolean {
+        if (preLayoutInfo is TabItemHolderInfo) {
+            val viewHolder = newHolder as TabViewHolder
+            val iconSize =
+                viewHolder.itemView.resources.getDimensionPixelSize(
+                    R.dimen.floating_tab_toolbar_tab_icon_size
+                )
+            ValueAnimator.ofFloat(
+                    if (preLayoutInfo.selectItem) 0f else 1f,
+                    if (preLayoutInfo.selectItem) 1f else 0f,
+                )
+                .apply {
+                    addUpdateListener {
+                        val value = it.animatedValue as Float
+                        viewHolder.icon.layoutParams =
+                            viewHolder.icon.layoutParams.apply {
+                                width = (value * iconSize).toInt()
+                            }
+                        viewHolder.container.background.alpha =
+                            (value * BACKGROUND_ALPHA_MAX).toInt()
+                    }
+                    addListener { doOnEnd { dispatchAnimationFinished(viewHolder) } }
+                    duration = ANIMATION_DURATION_MILLIS
+                }
+                .start()
+            return true
+        }
+
+        return super.animateChange(oldHolder, newHolder, preLayoutInfo, postLayoutInfo)
+    }
+
+    class TabItemHolderInfo(val selectItem: Boolean) : ItemHolderInfo()
+
+    companion object {
+        const val SELECT_ITEM = 3024
+        const val UNSELECT_ITEM = 1114
+        const val BACKGROUND_ALPHA_MAX = 255
+        const val ANIMATION_DURATION_MILLIS = 200L
+    }
+}
diff --git a/src/com/android/wallpaper/picker/customization/ui/viewmodel/ColorUpdateViewModel.kt b/src/com/android/wallpaper/picker/customization/ui/viewmodel/ColorUpdateViewModel.kt
new file mode 100644
index 00000000..85e346b3
--- /dev/null
+++ b/src/com/android/wallpaper/picker/customization/ui/viewmodel/ColorUpdateViewModel.kt
@@ -0,0 +1,45 @@
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
+package com.android.wallpaper.picker.customization.ui.viewmodel
+
+import android.content.Context
+import com.android.wallpaper.R
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.scopes.ActivityScoped
+import javax.inject.Inject
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.asStateFlow
+
+@ActivityScoped
+class ColorUpdateViewModel @Inject constructor(@ApplicationContext private val context: Context) {
+    private val _colorPrimary = MutableStateFlow(context.getColor(R.color.system_primary))
+    val colorPrimary = _colorPrimary.asStateFlow()
+
+    private val _colorSecondaryContainer =
+        MutableStateFlow(context.getColor(R.color.system_secondary_container))
+    val colorSecondaryContainer = _colorSecondaryContainer.asStateFlow()
+
+    private val _colorSurfaceContainer =
+        MutableStateFlow(context.getColor(R.color.system_surface_container))
+    val colorSurfaceContainer = _colorSurfaceContainer.asStateFlow()
+
+    fun updateColors() {
+        _colorPrimary.value = context.getColor(R.color.system_primary)
+        _colorSecondaryContainer.value = context.getColor(R.color.system_secondary_container)
+        _colorSurfaceContainer.value = context.getColor(R.color.system_surface_container)
+    }
+}
diff --git a/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationOptionsViewModel.kt b/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationOptionsViewModel.kt
index c08506f2..04904c1d 100644
--- a/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationOptionsViewModel.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationOptionsViewModel.kt
@@ -17,11 +17,12 @@
 package com.android.wallpaper.picker.customization.ui.viewmodel
 
 import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil
-import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.flow.StateFlow
 
 interface CustomizationOptionsViewModel {
 
-    val selectedOption: Flow<CustomizationOptionUtil.CustomizationOption?>
+    val selectedOption: StateFlow<CustomizationOptionUtil.CustomizationOption?>
 
     /**
      * Deselect the selected option and return true. If no option is selected, do nothing and return
@@ -29,3 +30,8 @@ interface CustomizationOptionsViewModel {
      */
     fun deselectOption(): Boolean
 }
+
+interface CustomizationOptionsViewModelFactory {
+
+    fun create(viewModelScope: CoroutineScope): CustomizationOptionsViewModel
+}
diff --git a/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationPickerViewModel2.kt b/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationPickerViewModel2.kt
index 2df7fa91..97c40ddd 100644
--- a/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationPickerViewModel2.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationPickerViewModel2.kt
@@ -17,8 +17,10 @@
 package com.android.wallpaper.picker.customization.ui.viewmodel
 
 import androidx.lifecycle.ViewModel
+import androidx.lifecycle.viewModelScope
 import com.android.wallpaper.model.Screen
 import com.android.wallpaper.model.Screen.LOCK_SCREEN
+import com.android.wallpaper.picker.common.preview.ui.viewmodel.BasePreviewViewModel
 import dagger.hilt.android.lifecycle.HiltViewModel
 import javax.inject.Inject
 import kotlinx.coroutines.flow.MutableStateFlow
@@ -29,9 +31,14 @@ import kotlinx.coroutines.flow.map
 class CustomizationPickerViewModel2
 @Inject
 constructor(
-    val customizationOptionsViewModel: CustomizationOptionsViewModel,
+    customizationOptionsViewModelFactory: CustomizationOptionsViewModelFactory,
+    basePreviewViewModelFactory: BasePreviewViewModel.Factory,
 ) : ViewModel() {
 
+    val customizationOptionsViewModel =
+        customizationOptionsViewModelFactory.create(viewModelScope = viewModelScope)
+    val basePreviewViewModel = basePreviewViewModelFactory.create(viewModelScope)
+
     enum class PickerScreen {
         MAIN,
         CUSTOMIZATION_OPTION,
@@ -52,6 +59,4 @@ constructor(
                 Pair(PickerScreen.MAIN, null)
             }
         }
-
-    fun onBackPressed(): Boolean = customizationOptionsViewModel.deselectOption()
 }
diff --git a/src/com/android/wallpaper/picker/customization/ui/viewmodel/DefaultCustomizationOptionsViewModel.kt b/src/com/android/wallpaper/picker/customization/ui/viewmodel/DefaultCustomizationOptionsViewModel.kt
index 57014b3d..e9371958 100644
--- a/src/com/android/wallpaper/picker/customization/ui/viewmodel/DefaultCustomizationOptionsViewModel.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/viewmodel/DefaultCustomizationOptionsViewModel.kt
@@ -17,13 +17,19 @@
 package com.android.wallpaper.picker.customization.ui.viewmodel
 
 import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil
+import dagger.assisted.Assisted
+import dagger.assisted.AssistedFactory
+import dagger.assisted.AssistedInject
 import dagger.hilt.android.scopes.ViewModelScoped
-import javax.inject.Inject
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.asStateFlow
 
-@ViewModelScoped
-class DefaultCustomizationOptionsViewModel @Inject constructor() : CustomizationOptionsViewModel {
+class DefaultCustomizationOptionsViewModel
+@AssistedInject
+constructor(
+    @Assisted viewModelScope: CoroutineScope,
+) : CustomizationOptionsViewModel {
 
     private val _selectedOptionState =
         MutableStateFlow<CustomizationOptionUtil.CustomizationOption?>(null)
@@ -41,4 +47,10 @@ class DefaultCustomizationOptionsViewModel @Inject constructor() : Customization
     fun selectOption(option: CustomizationOptionUtil.CustomizationOption) {
         _selectedOptionState.value = option
     }
+
+    @ViewModelScoped
+    @AssistedFactory
+    interface Factory : CustomizationOptionsViewModelFactory {
+        override fun create(viewModelScope: CoroutineScope): DefaultCustomizationOptionsViewModel
+    }
 }
diff --git a/src/com/android/wallpaper/picker/customization/ui/viewmodel/FloatingToolbarTabViewModel.kt b/src/com/android/wallpaper/picker/customization/ui/viewmodel/FloatingToolbarTabViewModel.kt
new file mode 100644
index 00000000..8667576c
--- /dev/null
+++ b/src/com/android/wallpaper/picker/customization/ui/viewmodel/FloatingToolbarTabViewModel.kt
@@ -0,0 +1,26 @@
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
+package com.android.wallpaper.picker.customization.ui.viewmodel
+
+import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
+
+data class FloatingToolbarTabViewModel(
+    val icon: Icon,
+    val text: String,
+    val isSelected: Boolean,
+    val onClick: (() -> Unit)?,
+)
diff --git a/src/com/android/wallpaper/picker/customization/ui/viewmodel/ScreenPreviewViewModel.kt b/src/com/android/wallpaper/picker/customization/ui/viewmodel/ScreenPreviewViewModel.kt
index eb8f2ecb..1231d191 100644
--- a/src/com/android/wallpaper/picker/customization/ui/viewmodel/ScreenPreviewViewModel.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/viewmodel/ScreenPreviewViewModel.kt
@@ -78,7 +78,7 @@ open class ScreenPreviewViewModel(
         return wallpaperInteractor.wallpaperUpdateEvents(s)
     }
 
-    open fun workspaceUpdateEvents(): Flow<Boolean>? = null
+    open fun workspaceUpdateEvents(): Flow<Unit>? = null
 
     fun getInitialExtras(): Bundle? {
         return initialExtrasProvider.invoke()
diff --git a/src/com/android/wallpaper/picker/data/LiveWallpaperData.kt b/src/com/android/wallpaper/picker/data/LiveWallpaperData.kt
index 7efa2ea9..5c619ae3 100644
--- a/src/com/android/wallpaper/picker/data/LiveWallpaperData.kt
+++ b/src/com/android/wallpaper/picker/data/LiveWallpaperData.kt
@@ -25,5 +25,6 @@ data class LiveWallpaperData(
     val isTitleVisible: Boolean,
     val isApplied: Boolean,
     val isEffectWallpaper: Boolean,
-    val effectNames: String?
+    val effectNames: String?,
+    val contextDescription: CharSequence? = null,
 )
diff --git a/src/com/android/wallpaper/picker/data/category/CollectionCategoryData.kt b/src/com/android/wallpaper/picker/data/category/CollectionCategoryData.kt
index a02cbabd..6f16ec01 100644
--- a/src/com/android/wallpaper/picker/data/category/CollectionCategoryData.kt
+++ b/src/com/android/wallpaper/picker/data/category/CollectionCategoryData.kt
@@ -22,7 +22,7 @@ import com.android.wallpaper.picker.data.WallpaperModel
 /** Represents set of attributes that depict a collection of wallpapers. */
 data class CollectionCategoryData(
     val wallpaperModels: MutableList<WallpaperModel>,
-    val thumbAsset: Asset,
+    val thumbAsset: Asset?,
     val featuredThumbnailIndex: Int,
     val isSingleWallpaperCategory: Boolean
 )
diff --git a/src/com/android/wallpaper/picker/data/category/ImageCategoryData.kt b/src/com/android/wallpaper/picker/data/category/ImageCategoryData.kt
index 6e904dd3..3a039216 100644
--- a/src/com/android/wallpaper/picker/data/category/ImageCategoryData.kt
+++ b/src/com/android/wallpaper/picker/data/category/ImageCategoryData.kt
@@ -17,9 +17,11 @@
 package com.android.wallpaper.picker.data.category
 
 import android.graphics.drawable.Drawable
+import com.android.wallpaper.asset.Asset
 
 /**
  * Represents set of attributes for depicting the block used for accessing personal photos on
- * device.
+ * device. The defaultDrawable contains the placeholder image drawable, which is used when
+ * thumbAsset is null. If thumbAsset is provided, it will be used instead of defaultDrawable.
  */
-data class ImageCategoryData(val overlayIconDrawable: Drawable?)
+data class ImageCategoryData(val thumbnailAsset: Asset?, val defaultDrawable: Drawable?)
diff --git a/src/com/android/wallpaper/picker/di/modules/ConcurrencyModule.kt b/src/com/android/wallpaper/picker/di/modules/ConcurrencyModule.kt
deleted file mode 100644
index ff2185f7..00000000
--- a/src/com/android/wallpaper/picker/di/modules/ConcurrencyModule.kt
+++ /dev/null
@@ -1,69 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.wallpaper.picker.di.modules
-
-import android.os.Handler
-import android.os.HandlerThread
-import android.os.Looper
-import android.os.Process
-import dagger.Module
-import dagger.Provides
-import dagger.hilt.InstallIn
-import dagger.hilt.components.SingletonComponent
-import java.util.concurrent.Executor
-import javax.inject.Qualifier
-import javax.inject.Singleton
-
-@Module
-@InstallIn(SingletonComponent::class)
-class ConcurrencyModule {
-
-    private val BROADCAST_SLOW_DISPATCH_THRESHOLD = 1000L
-    private val BROADCAST_SLOW_DELIVERY_THRESHOLD = 1000L
-
-    @Qualifier
-    @MustBeDocumented
-    @Retention(AnnotationRetention.RUNTIME)
-    annotation class BroadcastRunning
-
-    @Provides
-    @Singleton
-    @BroadcastRunning
-    fun provideBroadcastRunningLooper(): Looper {
-        return HandlerThread(
-                "BroadcastRunning",
-                Process.THREAD_PRIORITY_BACKGROUND,
-            )
-            .apply {
-                start()
-                looper.setSlowLogThresholdMs(
-                    BROADCAST_SLOW_DISPATCH_THRESHOLD,
-                    BROADCAST_SLOW_DELIVERY_THRESHOLD,
-                )
-            }
-            .looper
-    }
-
-    /** Provide a BroadcastRunning Executor (for sending and receiving broadcasts). */
-    @Provides
-    @Singleton
-    @BroadcastRunning
-    fun provideBroadcastRunningExecutor(@BroadcastRunning looper: Looper?): Executor {
-        val handler = Handler(looper ?: Looper.getMainLooper())
-        return Executor { command -> handler.post(command) }
-    }
-}
diff --git a/src/com/android/wallpaper/picker/di/modules/DispatchersModule.kt b/src/com/android/wallpaper/picker/di/modules/DispatchersModule.kt
deleted file mode 100644
index fc32ee97..00000000
--- a/src/com/android/wallpaper/picker/di/modules/DispatchersModule.kt
+++ /dev/null
@@ -1,51 +0,0 @@
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
-package com.android.wallpaper.picker.di.modules
-
-import dagger.Module
-import dagger.Provides
-import dagger.hilt.InstallIn
-import dagger.hilt.components.SingletonComponent
-import javax.inject.Qualifier
-import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.Dispatchers
-
-/** Qualifier for main thread [CoroutineDispatcher] bound to app lifecycle. */
-@Qualifier annotation class MainDispatcher
-
-/** Qualifier for background thread [CoroutineDispatcher] for long running and blocking tasks. */
-@Qualifier annotation class BackgroundDispatcher
-
-@Module
-@InstallIn(SingletonComponent::class)
-object DispatchersModule {
-
-    @Provides
-    @MainDispatcher
-    fun provideMainScope(): CoroutineScope = CoroutineScope(Dispatchers.Main)
-
-    @Provides @MainDispatcher fun provideMainDispatcher(): CoroutineDispatcher = Dispatchers.Main
-
-    @Provides
-    @BackgroundDispatcher
-    fun provideBackgroundScope(): CoroutineScope = CoroutineScope(Dispatchers.IO)
-
-    @Provides
-    @BackgroundDispatcher
-    fun provideBackgroundDispatcher(): CoroutineDispatcher = Dispatchers.IO
-}
diff --git a/src/com/android/wallpaper/picker/di/modules/DisplaysProviderModule.kt b/src/com/android/wallpaper/picker/di/modules/DisplaysProviderModule.kt
index 01e3e691..64348f7f 100644
--- a/src/com/android/wallpaper/picker/di/modules/DisplaysProviderModule.kt
+++ b/src/com/android/wallpaper/picker/di/modules/DisplaysProviderModule.kt
@@ -27,6 +27,7 @@ import javax.inject.Singleton
 @Module
 @InstallIn(SingletonComponent::class)
 abstract class DisplaysProviderModule {
+
     @Binds
     @Singleton
     abstract fun bindDisplaysProvider(impl: DisplaysProviderImpl): DisplaysProvider
diff --git a/src/com/android/wallpaper/picker/di/modules/PreviewUtilsModule.kt b/src/com/android/wallpaper/picker/di/modules/PreviewUtilsModule.kt
deleted file mode 100644
index fcbdbc70..00000000
--- a/src/com/android/wallpaper/picker/di/modules/PreviewUtilsModule.kt
+++ /dev/null
@@ -1,69 +0,0 @@
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
-package com.android.wallpaper.picker.di.modules
-
-import android.content.Context
-import com.android.wallpaper.R
-import com.android.wallpaper.util.PreviewUtils
-import dagger.Module
-import dagger.Provides
-import dagger.hilt.InstallIn
-import dagger.hilt.android.components.ActivityRetainedComponent
-import dagger.hilt.android.qualifiers.ApplicationContext
-import dagger.hilt.android.scopes.ActivityRetainedScoped
-import javax.inject.Qualifier
-
-/*
- * This class provides the preview utils instances required for a specific screen type
- */
-@InstallIn(ActivityRetainedComponent::class)
-@Module
-object PreviewUtilsModule {
-
-    @Qualifier @Retention(AnnotationRetention.BINARY) annotation class LockScreenPreviewUtils
-
-    @Qualifier @Retention(AnnotationRetention.BINARY) annotation class HomeScreenPreviewUtils
-
-    @LockScreenPreviewUtils
-    @ActivityRetainedScoped
-    @Provides
-    fun provideLockScreenPreviewUtils(
-        @ApplicationContext appContext: Context,
-    ): PreviewUtils {
-        return PreviewUtils(
-            context = appContext,
-            authority =
-                appContext.getString(
-                    R.string.lock_screen_preview_provider_authority,
-                ),
-        )
-    }
-
-    @HomeScreenPreviewUtils
-    @ActivityRetainedScoped
-    @Provides
-    fun provideHomeScreenPreviewUtils(
-        @ApplicationContext appContext: Context,
-    ): PreviewUtils {
-        return PreviewUtils(
-            context = appContext,
-            authorityMetadataKey =
-                appContext.getString(
-                    R.string.grid_control_metadata_name,
-                ),
-        )
-    }
-}
diff --git a/src/com/android/wallpaper/picker/di/modules/RepositoryModule.kt b/src/com/android/wallpaper/picker/di/modules/RepositoryModule.kt
deleted file mode 100644
index 8bd5687e..00000000
--- a/src/com/android/wallpaper/picker/di/modules/RepositoryModule.kt
+++ /dev/null
@@ -1,48 +0,0 @@
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
-package com.android.wallpaper.picker.di.modules
-
-import com.android.wallpaper.module.WallpaperPreferences
-import com.android.wallpaper.picker.customization.data.content.WallpaperClient
-import com.android.wallpaper.picker.customization.data.repository.WallpaperRepository
-import dagger.Module
-import dagger.Provides
-import dagger.hilt.InstallIn
-import dagger.hilt.components.SingletonComponent
-import javax.inject.Singleton
-import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.CoroutineScope
-
-@InstallIn(SingletonComponent::class)
-@Module
-internal object RepositoryModule {
-
-    @Provides
-    @Singleton
-    fun provideWallpaperRepository(
-        @BackgroundDispatcher bgDispatcher: CoroutineDispatcher,
-        @MainDispatcher mainScope: CoroutineScope,
-        wallpaperPreferences: WallpaperPreferences,
-        wallpaperClient: WallpaperClient,
-    ): WallpaperRepository {
-        return WallpaperRepository(
-            mainScope,
-            wallpaperClient,
-            wallpaperPreferences,
-            bgDispatcher,
-        )
-    }
-}
diff --git a/src/com/android/wallpaper/picker/di/modules/SharedActivityRetainedModule.kt b/src/com/android/wallpaper/picker/di/modules/SharedActivityRetainedModule.kt
index 5f298d2c..ad41ae46 100644
--- a/src/com/android/wallpaper/picker/di/modules/SharedActivityRetainedModule.kt
+++ b/src/com/android/wallpaper/picker/di/modules/SharedActivityRetainedModule.kt
@@ -16,18 +16,63 @@
 
 package com.android.wallpaper.picker.di.modules
 
+import android.content.Context
+import com.android.wallpaper.R
 import com.android.wallpaper.picker.preview.data.repository.ImageEffectsRepository
 import com.android.wallpaper.picker.preview.data.repository.ImageEffectsRepositoryImpl
+import com.android.wallpaper.util.PreviewUtils
 import dagger.Binds
 import dagger.Module
+import dagger.Provides
 import dagger.hilt.InstallIn
 import dagger.hilt.android.components.ActivityRetainedComponent
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.scopes.ActivityRetainedScoped
+import javax.inject.Qualifier
+
+@Qualifier @Retention(AnnotationRetention.BINARY) annotation class LockScreenPreviewUtils
+
+@Qualifier @Retention(AnnotationRetention.BINARY) annotation class HomeScreenPreviewUtils
 
 @Module
 @InstallIn(ActivityRetainedComponent::class)
 abstract class SharedActivityRetainedModule {
+
     @Binds
     abstract fun bindImageEffectsRepository(
         impl: ImageEffectsRepositoryImpl
     ): ImageEffectsRepository
+
+    companion object {
+
+        @HomeScreenPreviewUtils
+        @ActivityRetainedScoped
+        @Provides
+        fun provideHomeScreenPreviewUtils(
+            @ApplicationContext appContext: Context,
+        ): PreviewUtils {
+            return PreviewUtils(
+                context = appContext,
+                authorityMetadataKey =
+                    appContext.getString(
+                        R.string.grid_control_metadata_name,
+                    ),
+            )
+        }
+
+        @LockScreenPreviewUtils
+        @ActivityRetainedScoped
+        @Provides
+        fun provideLockScreenPreviewUtils(
+            @ApplicationContext appContext: Context,
+        ): PreviewUtils {
+            return PreviewUtils(
+                context = appContext,
+                authority =
+                    appContext.getString(
+                        R.string.lock_screen_preview_provider_authority,
+                    ),
+            )
+        }
+    }
 }
diff --git a/src/com/android/wallpaper/picker/di/modules/SharedAppModule.kt b/src/com/android/wallpaper/picker/di/modules/SharedAppModule.kt
index e3b6040a..ef4b45b8 100644
--- a/src/com/android/wallpaper/picker/di/modules/SharedAppModule.kt
+++ b/src/com/android/wallpaper/picker/di/modules/SharedAppModule.kt
@@ -19,20 +19,33 @@ package com.android.wallpaper.picker.di.modules
 import android.app.WallpaperManager
 import android.content.Context
 import android.content.pm.PackageManager
+import android.content.res.Resources
+import android.os.Handler
+import android.os.HandlerThread
+import android.os.Looper
+import android.os.Process
 import com.android.wallpaper.module.DefaultNetworkStatusNotifier
 import com.android.wallpaper.module.LargeScreenMultiPanesChecker
 import com.android.wallpaper.module.MultiPanesChecker
 import com.android.wallpaper.module.NetworkStatusNotifier
 import com.android.wallpaper.network.Requester
 import com.android.wallpaper.network.WallpaperRequester
-import com.android.wallpaper.picker.category.domain.interactor.CategoryInteractor
-import com.android.wallpaper.picker.category.domain.interactor.CreativeCategoryInteractor
+import com.android.wallpaper.picker.category.client.DefaultWallpaperCategoryClient
+import com.android.wallpaper.picker.category.client.DefaultWallpaperCategoryClientImpl
+import com.android.wallpaper.picker.category.client.LiveWallpapersClient
+import com.android.wallpaper.picker.category.client.LiveWallpapersClientImpl
+import com.android.wallpaper.picker.category.data.repository.DefaultWallpaperCategoryRepository
+import com.android.wallpaper.picker.category.data.repository.WallpaperCategoryRepository
 import com.android.wallpaper.picker.category.domain.interactor.MyPhotosInteractor
-import com.android.wallpaper.picker.category.domain.interactor.implementations.CategoryInteractorImpl
-import com.android.wallpaper.picker.category.domain.interactor.implementations.CreativeCategoryInteractorImpl
+import com.android.wallpaper.picker.category.domain.interactor.ThirdPartyCategoryInteractor
 import com.android.wallpaper.picker.category.domain.interactor.implementations.MyPhotosInteractorImpl
+import com.android.wallpaper.picker.category.domain.interactor.implementations.ThirdPartyCategoryInteractorImpl
 import com.android.wallpaper.picker.customization.data.content.WallpaperClient
 import com.android.wallpaper.picker.customization.data.content.WallpaperClientImpl
+import com.android.wallpaper.picker.network.data.DefaultNetworkStatusRepository
+import com.android.wallpaper.picker.network.data.NetworkStatusRepository
+import com.android.wallpaper.picker.network.domain.DefaultNetworkStatusInteractor
+import com.android.wallpaper.picker.network.domain.NetworkStatusInteractor
 import com.android.wallpaper.system.UiModeManagerImpl
 import com.android.wallpaper.system.UiModeManagerWrapper
 import com.android.wallpaper.util.WallpaperParser
@@ -45,62 +58,156 @@ import dagger.Provides
 import dagger.hilt.InstallIn
 import dagger.hilt.android.qualifiers.ApplicationContext
 import dagger.hilt.components.SingletonComponent
+import java.util.concurrent.Executor
+import javax.inject.Qualifier
 import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.Dispatchers
+
+/** Qualifier for main thread [CoroutineDispatcher] bound to app lifecycle. */
+@Qualifier annotation class MainDispatcher
+
+/** Qualifier for background thread [CoroutineDispatcher] for long running and blocking tasks. */
+@Qualifier annotation class BackgroundDispatcher
 
 @Module
 @InstallIn(SingletonComponent::class)
 abstract class SharedAppModule {
-    @Binds @Singleton abstract fun bindUiModeManager(impl: UiModeManagerImpl): UiModeManagerWrapper
 
     @Binds
     @Singleton
-    abstract fun bindNetworkStatusNotifier(
-        impl: DefaultNetworkStatusNotifier
-    ): NetworkStatusNotifier
+    abstract fun bindCategoryFactory(impl: DefaultCategoryFactory): CategoryFactory
 
-    @Binds @Singleton abstract fun bindWallpaperRequester(impl: WallpaperRequester): Requester
+    @Binds
+    @Singleton
+    abstract fun bindLiveWallpapersClient(impl: LiveWallpapersClientImpl): LiveWallpapersClient
 
     @Binds
     @Singleton
-    abstract fun bindWallpaperXMLParser(impl: WallpaperParserImpl): WallpaperParser
+    abstract fun bindMyPhotosInteractor(impl: MyPhotosInteractorImpl): MyPhotosInteractor
 
     @Binds
     @Singleton
-    abstract fun bindCategoryFactory(impl: DefaultCategoryFactory): CategoryFactory
+    abstract fun bindNetworkStatusRepository(
+        impl: DefaultNetworkStatusRepository
+    ): NetworkStatusRepository
 
-    @Binds @Singleton abstract fun bindWallpaperClient(impl: WallpaperClientImpl): WallpaperClient
+    @Binds
+    @Singleton
+    abstract fun bindNetworkStatusInteractor(
+        impl: DefaultNetworkStatusInteractor
+    ): NetworkStatusInteractor
 
     @Binds
     @Singleton
-    abstract fun bindCategoryInteractor(impl: CategoryInteractorImpl): CategoryInteractor
+    abstract fun bindNetworkStatusNotifier(
+        impl: DefaultNetworkStatusNotifier
+    ): NetworkStatusNotifier
+
+    @Binds @Singleton abstract fun bindRequester(impl: WallpaperRequester): Requester
 
     @Binds
     @Singleton
-    abstract fun bindCreativeCategoryInteractor(
-        impl: CreativeCategoryInteractorImpl
-    ): CreativeCategoryInteractor
+    abstract fun bindThirdPartyCategoryInteractor(
+        impl: ThirdPartyCategoryInteractorImpl,
+    ): ThirdPartyCategoryInteractor
 
     @Binds
     @Singleton
-    abstract fun bindMyPhotosInteractor(impl: MyPhotosInteractorImpl): MyPhotosInteractor
+    abstract fun bindUiModeManagerWrapper(impl: UiModeManagerImpl): UiModeManagerWrapper
+
+    @Binds
+    @Singleton
+    abstract fun bindWallpaperCategoryClient(
+        impl: DefaultWallpaperCategoryClientImpl
+    ): DefaultWallpaperCategoryClient
+
+    @Binds
+    @Singleton
+    abstract fun bindWallpaperCategoryRepository(
+        impl: DefaultWallpaperCategoryRepository
+    ): WallpaperCategoryRepository
+
+    @Binds @Singleton abstract fun bindWallpaperClient(impl: WallpaperClientImpl): WallpaperClient
+
+    @Binds @Singleton abstract fun bindWallpaperParser(impl: WallpaperParserImpl): WallpaperParser
 
     companion object {
+
+        @Qualifier
+        @MustBeDocumented
+        @Retention(AnnotationRetention.RUNTIME)
+        annotation class BroadcastRunning
+
+        private const val BROADCAST_SLOW_DISPATCH_THRESHOLD = 1000L
+        private const val BROADCAST_SLOW_DELIVERY_THRESHOLD = 1000L
+
+        @Provides
+        @BackgroundDispatcher
+        fun provideBackgroundDispatcher(): CoroutineDispatcher = Dispatchers.IO
+
+        @Provides
+        @BackgroundDispatcher
+        fun provideBackgroundScope(): CoroutineScope = CoroutineScope(Dispatchers.IO)
+
+        /** Provide a BroadcastRunning Executor (for sending and receiving broadcasts). */
         @Provides
         @Singleton
-        fun provideWallpaperManager(@ApplicationContext appContext: Context): WallpaperManager {
-            return WallpaperManager.getInstance(appContext)
+        @BroadcastRunning
+        fun provideBroadcastRunningExecutor(@BroadcastRunning looper: Looper?): Executor {
+            val handler = Handler(looper ?: Looper.getMainLooper())
+            return Executor { command -> handler.post(command) }
         }
 
         @Provides
         @Singleton
-        fun providePackageManager(@ApplicationContext appContext: Context): PackageManager {
-            return appContext.packageManager
+        @BroadcastRunning
+        fun provideBroadcastRunningLooper(): Looper {
+            return HandlerThread(
+                    "BroadcastRunning",
+                    Process.THREAD_PRIORITY_BACKGROUND,
+                )
+                .apply {
+                    start()
+                    looper.setSlowLogThresholdMs(
+                        BROADCAST_SLOW_DISPATCH_THRESHOLD,
+                        BROADCAST_SLOW_DELIVERY_THRESHOLD,
+                    )
+                }
+                .looper
         }
 
+        @Provides
+        @MainDispatcher
+        fun provideMainDispatcher(): CoroutineDispatcher = Dispatchers.Main
+
+        @Provides
+        @MainDispatcher
+        fun provideMainScope(): CoroutineScope = CoroutineScope(Dispatchers.Main)
+
         @Provides
         @Singleton
         fun provideMultiPanesChecker(): MultiPanesChecker {
             return LargeScreenMultiPanesChecker()
         }
+
+        @Provides
+        @Singleton
+        fun providePackageManager(@ApplicationContext appContext: Context): PackageManager {
+            return appContext.packageManager
+        }
+
+        @Provides
+        @Singleton
+        fun provideResources(@ApplicationContext context: Context): Resources {
+            return context.resources
+        }
+
+        @Provides
+        @Singleton
+        fun provideWallpaperManager(@ApplicationContext appContext: Context): WallpaperManager {
+            return WallpaperManager.getInstance(appContext)
+        }
     }
 }
diff --git a/src/com/android/wallpaper/picker/individual/IndividualPickerFragment.java b/src/com/android/wallpaper/picker/individual/IndividualPickerFragment.java
index 1789db32..e69de29b 100755
--- a/src/com/android/wallpaper/picker/individual/IndividualPickerFragment.java
+++ b/src/com/android/wallpaper/picker/individual/IndividualPickerFragment.java
@@ -1,739 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
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
-package com.android.wallpaper.picker.individual;
-
-import android.annotation.MenuRes;
-import android.app.Activity;
-import android.app.ProgressDialog;
-import android.app.WallpaperManager;
-import android.content.Context;
-import android.content.DialogInterface;
-import android.content.res.Configuration;
-import android.content.res.Resources.NotFoundException;
-import android.graphics.Point;
-import android.os.Build.VERSION;
-import android.os.Build.VERSION_CODES;
-import android.os.Bundle;
-import android.service.wallpaper.WallpaperService;
-import android.text.TextUtils;
-import android.util.ArraySet;
-import android.util.Log;
-import android.view.LayoutInflater;
-import android.view.MenuItem;
-import android.view.View;
-import android.view.ViewGroup;
-import android.widget.ImageView;
-import android.widget.RelativeLayout;
-import android.widget.Toast;
-
-import androidx.annotation.DrawableRes;
-import androidx.annotation.NonNull;
-import androidx.cardview.widget.CardView;
-import androidx.core.widget.ContentLoadingProgressBar;
-import androidx.fragment.app.DialogFragment;
-import androidx.fragment.app.Fragment;
-import androidx.recyclerview.widget.GridLayoutManager;
-import androidx.recyclerview.widget.RecyclerView;
-import androidx.recyclerview.widget.RecyclerView.ViewHolder;
-
-import com.android.wallpaper.R;
-import com.android.wallpaper.model.Category;
-import com.android.wallpaper.model.CategoryProvider;
-import com.android.wallpaper.model.CategoryReceiver;
-import com.android.wallpaper.model.WallpaperCategory;
-import com.android.wallpaper.model.WallpaperInfo;
-import com.android.wallpaper.model.WallpaperReceiver;
-import com.android.wallpaper.model.WallpaperRotationInitializer;
-import com.android.wallpaper.model.WallpaperRotationInitializer.Listener;
-import com.android.wallpaper.model.WallpaperRotationInitializer.NetworkPreference;
-import com.android.wallpaper.module.Injector;
-import com.android.wallpaper.module.InjectorProvider;
-import com.android.wallpaper.module.PackageStatusNotifier;
-import com.android.wallpaper.module.WallpaperPreferences;
-import com.android.wallpaper.picker.AppbarFragment;
-import com.android.wallpaper.picker.FragmentTransactionChecker;
-import com.android.wallpaper.picker.MyPhotosStarter.MyPhotosStarterProvider;
-import com.android.wallpaper.picker.RotationStarter;
-import com.android.wallpaper.picker.StartRotationDialogFragment;
-import com.android.wallpaper.picker.StartRotationErrorDialogFragment;
-import com.android.wallpaper.util.ActivityUtils;
-import com.android.wallpaper.util.LaunchUtils;
-import com.android.wallpaper.util.SizeCalculator;
-import com.android.wallpaper.widget.GridPaddingDecoration;
-import com.android.wallpaper.widget.WallpaperPickerRecyclerViewAccessibilityDelegate;
-import com.android.wallpaper.widget.WallpaperPickerRecyclerViewAccessibilityDelegate.BottomSheetHost;
-
-import com.bumptech.glide.Glide;
-import com.bumptech.glide.MemoryCategory;
-
-import java.util.ArrayList;
-import java.util.Date;
-import java.util.List;
-import java.util.Set;
-
-/**
- * Displays the Main UI for picking an individual wallpaper image.
- */
-public class IndividualPickerFragment extends AppbarFragment
-        implements RotationStarter, StartRotationErrorDialogFragment.Listener,
-        StartRotationDialogFragment.Listener {
-
-    /**
-     * Position of a special tile that doesn't belong to an individual wallpaper of the category,
-     * such as "my photos" or "daily rotation".
-     */
-    static final int SPECIAL_FIXED_TILE_ADAPTER_POSITION = 0;
-    static final String ARG_CATEGORY_COLLECTION_ID = "category_collection_id";
-
-    protected static final int MAX_CAPACITY_IN_FEWER_COLUMN_LAYOUT = 8;
-
-    private static final String TAG = "IndividualPickerFrgmnt";
-    private static final int UNUSED_REQUEST_CODE = 1;
-    private static final String TAG_START_ROTATION_DIALOG = "start_rotation_dialog";
-    private static final String TAG_START_ROTATION_ERROR_DIALOG = "start_rotation_error_dialog";
-    private static final String PROGRESS_DIALOG_NO_TITLE = null;
-    private static final boolean PROGRESS_DIALOG_INDETERMINATE = true;
-    private static final String KEY_NIGHT_MODE = "IndividualPickerFragment.NIGHT_MODE";
-
-    /**
-     * Interface to be implemented by a Fragment(or an Activity) hosting
-     * a {@link IndividualPickerFragment}.
-     */
-    public interface IndividualPickerFragmentHost {
-        /**
-         * Indicates if the host has toolbar to show the title. If it does, we should set the title
-         * there.
-         */
-        boolean isHostToolbarShown();
-
-        /**
-         * Sets the title in the host's toolbar.
-         */
-        void setToolbarTitle(CharSequence title);
-
-        /**
-         * Configures the menu in the toolbar.
-         *
-         * @param menuResId the resource id of the menu
-         */
-        void setToolbarMenu(@MenuRes int menuResId);
-
-        /**
-         * Removes the menu in the toolbar.
-         */
-        void removeToolbarMenu();
-
-        /**
-         * Moves to the previous fragment.
-         */
-        void moveToPreviousFragment();
-    }
-
-    RecyclerView mImageGrid;
-    IndividualAdapter mAdapter;
-    WallpaperCategory mCategory;
-    WallpaperRotationInitializer mWallpaperRotationInitializer;
-    List<WallpaperInfo> mWallpapers;
-    Point mTileSizePx;
-    PackageStatusNotifier mPackageStatusNotifier;
-
-    boolean mIsWallpapersReceived;
-    PackageStatusNotifier.Listener mAppStatusListener;
-
-    private ProgressDialog mProgressDialog;
-    private ContentLoadingProgressBar mLoading;
-    private CategoryProvider mCategoryProvider;
-
-    /**
-     * Staged error dialog fragments that were unable to be shown when the activity didn't allow
-     * committing fragment transactions.
-     */
-    private StartRotationErrorDialogFragment mStagedStartRotationErrorDialogFragment;
-
-    private WallpaperManager mWallpaperManager;
-    private Set<String> mAppliedWallpaperIds;
-
-    public static IndividualPickerFragment newInstance(String collectionId) {
-        Bundle args = new Bundle();
-        args.putString(ARG_CATEGORY_COLLECTION_ID, collectionId);
-
-        IndividualPickerFragment fragment = new IndividualPickerFragment();
-        fragment.setArguments(args);
-        return fragment;
-    }
-
-    @Override
-    public void onCreate(Bundle savedInstanceState) {
-        super.onCreate(savedInstanceState);
-
-        Injector injector = InjectorProvider.getInjector();
-        Context appContext = getContext().getApplicationContext();
-
-        mWallpaperManager = WallpaperManager.getInstance(appContext);
-
-        mPackageStatusNotifier = injector.getPackageStatusNotifier(appContext);
-
-        mWallpapers = new ArrayList<>();
-
-        // Clear Glide's cache if night-mode changed to ensure thumbnails are reloaded
-        if (savedInstanceState != null && (savedInstanceState.getInt(KEY_NIGHT_MODE)
-                != (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK))) {
-            Glide.get(getContext()).clearMemory();
-        }
-
-        mCategoryProvider = injector.getCategoryProvider(appContext);
-        mCategoryProvider.fetchCategories(new CategoryReceiver() {
-            @Override
-            public void onCategoryReceived(Category category) {
-                // Do nothing.
-            }
-
-            @Override
-            public void doneFetchingCategories() {
-                Category category = mCategoryProvider.getCategory(
-                        getArguments().getString(ARG_CATEGORY_COLLECTION_ID));
-                if (category != null && !(category instanceof WallpaperCategory)) {
-                    return;
-                }
-                mCategory = (WallpaperCategory) category;
-                if (mCategory == null) {
-                    // The absence of this category in the CategoryProvider indicates a broken
-                    // state, see b/38030129. Hence, finish the activity and return.
-                    getIndividualPickerFragmentHost().moveToPreviousFragment();
-                    Toast.makeText(getContext(), R.string.collection_not_exist_msg,
-                            Toast.LENGTH_SHORT).show();
-                    return;
-                }
-                onCategoryLoaded();
-            }
-        }, false);
-    }
-
-
-    protected void onCategoryLoaded() {
-        if (getIndividualPickerFragmentHost() == null) {
-            return;
-        }
-        if (getIndividualPickerFragmentHost().isHostToolbarShown()) {
-            getIndividualPickerFragmentHost().setToolbarTitle(mCategory.getTitle());
-        } else {
-            setTitle(mCategory.getTitle());
-        }
-        mWallpaperRotationInitializer = mCategory.getWallpaperRotationInitializer();
-        if (mToolbar != null && isRotationEnabled()) {
-            setUpToolbarMenu(R.menu.individual_picker_menu);
-        }
-        fetchWallpapers(false);
-
-        if (mCategory.supportsThirdParty()) {
-            mAppStatusListener = (packageName, status) -> {
-                if (status != PackageStatusNotifier.PackageStatus.REMOVED ||
-                        mCategory.containsThirdParty(packageName)) {
-                    fetchWallpapers(true);
-                }
-            };
-            mPackageStatusNotifier.addListener(mAppStatusListener,
-                    WallpaperService.SERVICE_INTERFACE);
-        }
-    }
-
-    void fetchWallpapers(boolean forceReload) {
-        mWallpapers.clear();
-        mIsWallpapersReceived = false;
-        updateLoading();
-        mCategory.fetchWallpapers(getActivity().getApplicationContext(), new WallpaperReceiver() {
-            @Override
-            public void onWallpapersReceived(List<WallpaperInfo> wallpapers) {
-                mIsWallpapersReceived = true;
-                updateLoading();
-                for (WallpaperInfo wallpaper : wallpapers) {
-                    mWallpapers.add(wallpaper);
-                }
-                maybeSetUpImageGrid();
-
-                // Wallpapers may load after the adapter is initialized, in which case we have
-                // to explicitly notify that the data set has changed.
-                if (mAdapter != null) {
-                    mAdapter.notifyDataSetChanged();
-                }
-
-                if (wallpapers.isEmpty()) {
-                    // If there are no more wallpapers and we're on phone, just finish the
-                    // Activity.
-                    Activity activity = getActivity();
-                    if (activity != null) {
-                        activity.finish();
-                    }
-                }
-            }
-        }, forceReload);
-    }
-
-    void updateLoading() {
-        if (mLoading == null) {
-            return;
-        }
-
-        if (mIsWallpapersReceived) {
-            mLoading.hide();
-        } else {
-            mLoading.show();
-        }
-    }
-
-    @Override
-    public void onSaveInstanceState(@NonNull Bundle outState) {
-        super.onSaveInstanceState(outState);
-        outState.putInt(KEY_NIGHT_MODE,
-                getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK);
-    }
-
-    @Override
-    public View onCreateView(LayoutInflater inflater, ViewGroup container,
-                             Bundle savedInstanceState) {
-        View view = inflater.inflate(R.layout.fragment_individual_picker, container, false);
-        if (getIndividualPickerFragmentHost().isHostToolbarShown()) {
-            view.findViewById(R.id.header_bar).setVisibility(View.GONE);
-            setUpArrowEnabled(/* upArrow= */ true);
-            if (isRotationEnabled()) {
-                getIndividualPickerFragmentHost().setToolbarMenu(R.menu.individual_picker_menu);
-            }
-        } else {
-            setUpToolbar(view);
-            if (isRotationEnabled()) {
-                setUpToolbarMenu(R.menu.individual_picker_menu);
-            }
-            if (mCategory != null) {
-                setTitle(mCategory.getTitle());
-            }
-        }
-
-        mAppliedWallpaperIds = getAppliedWallpaperIds();
-
-        mImageGrid = (RecyclerView) view.findViewById(R.id.wallpaper_grid);
-        mLoading = view.findViewById(R.id.loading_indicator);
-        updateLoading();
-        maybeSetUpImageGrid();
-        // For nav bar edge-to-edge effect.
-        mImageGrid.setOnApplyWindowInsetsListener((v, windowInsets) -> {
-            v.setPadding(
-                    v.getPaddingLeft(),
-                    v.getPaddingTop(),
-                    v.getPaddingRight(),
-                    windowInsets.getSystemWindowInsetBottom());
-            return windowInsets.consumeSystemWindowInsets();
-        });
-        return view;
-    }
-
-    private IndividualPickerFragmentHost getIndividualPickerFragmentHost() {
-        Fragment parentFragment = getParentFragment();
-        if (parentFragment != null) {
-            return (IndividualPickerFragmentHost) parentFragment;
-        } else {
-            return (IndividualPickerFragmentHost) getActivity();
-        }
-    }
-
-    protected void maybeSetUpImageGrid() {
-        // Skip if mImageGrid been initialized yet
-        if (mImageGrid == null) {
-            return;
-        }
-        // Skip if category hasn't loaded yet
-        if (mCategory == null) {
-            return;
-        }
-        if (getContext() == null) {
-            return;
-        }
-
-        // Wallpaper count could change, so we may need to change the layout(2 or 3 columns layout)
-        GridLayoutManager gridLayoutManager = (GridLayoutManager) mImageGrid.getLayoutManager();
-        boolean needUpdateLayout =
-                gridLayoutManager != null && gridLayoutManager.getSpanCount() != getNumColumns();
-
-        // Skip if the adapter was already created and don't need to change the layout
-        if (mAdapter != null && !needUpdateLayout) {
-            return;
-        }
-
-        // Clear the old decoration
-        int decorationCount = mImageGrid.getItemDecorationCount();
-        for (int i = 0; i < decorationCount; i++) {
-            mImageGrid.removeItemDecorationAt(i);
-        }
-
-        mImageGrid.addItemDecoration(new GridPaddingDecoration(getGridItemPaddingHorizontal(),
-                getGridItemPaddingBottom()));
-        int edgePadding = getEdgePadding();
-        mImageGrid.setPadding(edgePadding, mImageGrid.getPaddingTop(), edgePadding,
-                mImageGrid.getPaddingBottom());
-        mTileSizePx = isFewerColumnLayout()
-                ? SizeCalculator.getFeaturedIndividualTileSize(getActivity())
-                : SizeCalculator.getIndividualTileSize(getActivity());
-        setUpImageGrid();
-        mImageGrid.setAccessibilityDelegateCompat(
-                new WallpaperPickerRecyclerViewAccessibilityDelegate(
-                        mImageGrid, (BottomSheetHost) getParentFragment(), getNumColumns()));
-    }
-
-    boolean isFewerColumnLayout() {
-        return mWallpapers != null && mWallpapers.size() <= MAX_CAPACITY_IN_FEWER_COLUMN_LAYOUT;
-    }
-
-    private int getGridItemPaddingHorizontal() {
-        return isFewerColumnLayout()
-                ? getResources().getDimensionPixelSize(
-                R.dimen.grid_item_featured_individual_padding_horizontal)
-                : getResources().getDimensionPixelSize(
-                        R.dimen.grid_item_individual_padding_horizontal);
-    }
-
-    private int getGridItemPaddingBottom() {
-        return isFewerColumnLayout()
-                ? getResources().getDimensionPixelSize(
-                R.dimen.grid_item_featured_individual_padding_bottom)
-                : getResources().getDimensionPixelSize(R.dimen.grid_item_individual_padding_bottom);
-    }
-
-    private int getEdgePadding() {
-        return isFewerColumnLayout()
-                ? getResources().getDimensionPixelSize(R.dimen.featured_wallpaper_grid_edge_space)
-                : getResources().getDimensionPixelSize(R.dimen.wallpaper_grid_edge_space);
-    }
-
-    /**
-     * Create the adapter and assign it to mImageGrid.
-     * Both mImageGrid and mCategory are guaranteed to not be null when this method is called.
-     */
-    void setUpImageGrid() {
-        mAdapter = new IndividualAdapter(mWallpapers);
-        mImageGrid.setAdapter(mAdapter);
-        mImageGrid.setLayoutManager(new GridLayoutManager(getActivity(), getNumColumns()));
-    }
-
-    @Override
-    public void onResume() {
-        super.onResume();
-
-        WallpaperPreferences preferences = InjectorProvider.getInjector()
-                .getPreferences(getActivity());
-        preferences.setLastAppActiveTimestamp(new Date().getTime());
-
-        // Reset Glide memory settings to a "normal" level of usage since it may have been lowered in
-        // PreviewFragment.
-        Glide.get(getActivity()).setMemoryCategory(MemoryCategory.NORMAL);
-
-        // Show the staged 'start rotation' error dialog fragment if there is one that was unable to be
-        // shown earlier when this fragment's hosting activity didn't allow committing fragment
-        // transactions.
-        if (mStagedStartRotationErrorDialogFragment != null) {
-            mStagedStartRotationErrorDialogFragment.show(
-                    getFragmentManager(), TAG_START_ROTATION_ERROR_DIALOG);
-            mStagedStartRotationErrorDialogFragment = null;
-        }
-    }
-
-    @Override
-    public void onDestroyView() {
-        super.onDestroyView();
-        getIndividualPickerFragmentHost().removeToolbarMenu();
-    }
-
-    @Override
-    public void onDestroy() {
-        super.onDestroy();
-        if (mProgressDialog != null) {
-            mProgressDialog.dismiss();
-        }
-        if (mAppStatusListener != null) {
-            mPackageStatusNotifier.removeListener(mAppStatusListener);
-        }
-    }
-
-    @Override
-    public void onStartRotationDialogDismiss(@NonNull DialogInterface dialog) {
-        // TODO(b/159310028): Refactor fragment layer to make it able to restore from config change.
-        // This is to handle config change with StartRotationDialog popup,  the StartRotationDialog
-        // still holds a reference to the destroyed Fragment and is calling
-        // onStartRotationDialogDismissed on that destroyed Fragment.
-    }
-
-    @Override
-    public void retryStartRotation(@NetworkPreference int networkPreference) {
-        startRotation(networkPreference);
-    }
-
-    @Override
-    public void startRotation(@NetworkPreference final int networkPreference) {
-        if (!isRotationEnabled()) {
-            Log.e(TAG, "Rotation is not enabled for this category " + mCategory.getTitle());
-            return;
-        }
-
-        // ProgressDialog endlessly updates the UI thread, keeping it from going idle which therefore
-        // causes Espresso to hang once the dialog is shown.
-        int themeResId;
-        if (VERSION.SDK_INT < VERSION_CODES.LOLLIPOP) {
-            themeResId = R.style.ProgressDialogThemePreL;
-        } else {
-            themeResId = R.style.LightDialogTheme;
-        }
-        mProgressDialog = new ProgressDialog(getActivity(), themeResId);
-
-        mProgressDialog.setTitle(PROGRESS_DIALOG_NO_TITLE);
-        mProgressDialog.setMessage(
-                getResources().getString(R.string.start_rotation_progress_message));
-        mProgressDialog.setIndeterminate(PROGRESS_DIALOG_INDETERMINATE);
-        mProgressDialog.show();
-
-        final Context appContext = getActivity().getApplicationContext();
-
-        mWallpaperRotationInitializer.setFirstWallpaperInRotation(
-                appContext,
-                networkPreference,
-                new Listener() {
-                    @Override
-                    public void onFirstWallpaperInRotationSet() {
-                        if (mProgressDialog != null) {
-                            mProgressDialog.dismiss();
-                        }
-
-                        // The fragment may be detached from its containing activity if the user exits the
-                        // app before the first wallpaper image in rotation finishes downloading.
-                        Activity activity = getActivity();
-
-                        if (mWallpaperRotationInitializer.startRotation(appContext)) {
-                            if (activity != null) {
-                                try {
-                                    Toast.makeText(activity,
-                                            R.string.wallpaper_set_successfully_message,
-                                            Toast.LENGTH_SHORT).show();
-                                } catch (NotFoundException e) {
-                                    Log.e(TAG, "Could not show toast " + e);
-                                }
-
-                                activity.setResult(Activity.RESULT_OK);
-                                activity.finish();
-                                if (!ActivityUtils.isSUWMode(appContext)) {
-                                    // Go back to launcher home.
-                                    LaunchUtils.launchHome(appContext);
-                                }
-                            }
-                        } else { // Failed to start rotation.
-                            showStartRotationErrorDialog(networkPreference);
-                        }
-                    }
-
-                    @Override
-                    public void onError() {
-                        if (mProgressDialog != null) {
-                            mProgressDialog.dismiss();
-                        }
-
-                        showStartRotationErrorDialog(networkPreference);
-                    }
-                });
-    }
-
-    private void showStartRotationErrorDialog(@NetworkPreference int networkPreference) {
-        FragmentTransactionChecker activity = (FragmentTransactionChecker) getActivity();
-        if (activity != null) {
-            StartRotationErrorDialogFragment startRotationErrorDialogFragment =
-                    StartRotationErrorDialogFragment.newInstance(networkPreference);
-            startRotationErrorDialogFragment.setTargetFragment(
-                    IndividualPickerFragment.this, UNUSED_REQUEST_CODE);
-
-            if (activity.isSafeToCommitFragmentTransaction()) {
-                startRotationErrorDialogFragment.show(
-                        getFragmentManager(), TAG_START_ROTATION_ERROR_DIALOG);
-            } else {
-                mStagedStartRotationErrorDialogFragment = startRotationErrorDialogFragment;
-            }
-        }
-    }
-
-    int getNumColumns() {
-        Activity activity = getActivity();
-        if (activity == null) {
-            return 1;
-        }
-        return isFewerColumnLayout()
-                ? SizeCalculator.getNumFeaturedIndividualColumns(activity)
-                : SizeCalculator.getNumIndividualColumns(activity);
-    }
-
-    /**
-     * Returns whether rotation is enabled for this category.
-     */
-    boolean isRotationEnabled() {
-        return mWallpaperRotationInitializer != null;
-    }
-
-    @Override
-    public boolean onMenuItemClick(MenuItem item) {
-        if (item.getItemId() == R.id.daily_rotation) {
-            showRotationDialog();
-            return true;
-        }
-        return super.onMenuItemClick(item);
-    }
-
-    /**
-     * Popups a daily rotation dialog for the uses to confirm.
-     */
-    public void showRotationDialog() {
-        DialogFragment startRotationDialogFragment = new StartRotationDialogFragment();
-        startRotationDialogFragment.setTargetFragment(
-                IndividualPickerFragment.this, UNUSED_REQUEST_CODE);
-        startRotationDialogFragment.show(getFragmentManager(), TAG_START_ROTATION_DIALOG);
-    }
-
-    private Set<String> getAppliedWallpaperIds() {
-        WallpaperPreferences prefs =
-                InjectorProvider.getInjector().getPreferences(getContext());
-        android.app.WallpaperInfo wallpaperInfo = mWallpaperManager.getWallpaperInfo();
-        Set<String> appliedWallpaperIds = new ArraySet<>();
-
-        String homeWallpaperId = wallpaperInfo != null ? wallpaperInfo.getServiceName()
-                : prefs.getHomeWallpaperRemoteId();
-        if (!TextUtils.isEmpty(homeWallpaperId)) {
-            appliedWallpaperIds.add(homeWallpaperId);
-        }
-
-        boolean isLockWallpaperApplied =
-                mWallpaperManager.getWallpaperId(WallpaperManager.FLAG_LOCK) >= 0;
-        String lockWallpaperId = prefs.getLockWallpaperRemoteId();
-        if (isLockWallpaperApplied && !TextUtils.isEmpty(lockWallpaperId)) {
-            appliedWallpaperIds.add(lockWallpaperId);
-        }
-
-        return appliedWallpaperIds;
-    }
-
-    /**
-     * RecyclerView Adapter subclass for the wallpaper tiles in the RecyclerView.
-     */
-    class IndividualAdapter extends RecyclerView.Adapter<ViewHolder> {
-        static final int ITEM_VIEW_TYPE_INDIVIDUAL_WALLPAPER = 2;
-        static final int ITEM_VIEW_TYPE_MY_PHOTOS = 3;
-
-        private final List<WallpaperInfo> mWallpapers;
-
-        IndividualAdapter(List<WallpaperInfo> wallpapers) {
-            mWallpapers = wallpapers;
-        }
-
-        @Override
-        public ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
-            switch (viewType) {
-                case ITEM_VIEW_TYPE_INDIVIDUAL_WALLPAPER:
-                    return createIndividualHolder(parent);
-                case ITEM_VIEW_TYPE_MY_PHOTOS:
-                    return createMyPhotosHolder(parent);
-                default:
-                    Log.e(TAG, "Unsupported viewType " + viewType + " in IndividualAdapter");
-                    return null;
-            }
-        }
-
-        @Override
-        public int getItemViewType(int position) {
-            // A category cannot have both a "start rotation" tile and a "my photos" tile.
-            if (mCategory.supportsCustomPhotos()
-                    && !isRotationEnabled()
-                    && position == SPECIAL_FIXED_TILE_ADAPTER_POSITION) {
-                return ITEM_VIEW_TYPE_MY_PHOTOS;
-            }
-
-            return ITEM_VIEW_TYPE_INDIVIDUAL_WALLPAPER;
-        }
-
-        @Override
-        public void onBindViewHolder(ViewHolder holder, int position) {
-            int viewType = getItemViewType(position);
-
-            switch (viewType) {
-                case ITEM_VIEW_TYPE_INDIVIDUAL_WALLPAPER:
-                    onBindIndividualHolder(holder, position);
-                    break;
-                case ITEM_VIEW_TYPE_MY_PHOTOS:
-                    ((MyPhotosViewHolder) holder).bind();
-                    break;
-                default:
-                    Log.e(TAG, "Unsupported viewType " + viewType + " in IndividualAdapter");
-            }
-        }
-
-        @Override
-        public int getItemCount() {
-            return mCategory.supportsCustomPhotos() ? mWallpapers.size() + 1 : mWallpapers.size();
-        }
-
-        private ViewHolder createIndividualHolder(ViewGroup parent) {
-            LayoutInflater layoutInflater = LayoutInflater.from(getActivity());
-            View view = layoutInflater.inflate(R.layout.grid_item_image, parent, false);
-
-            return new PreviewIndividualHolder(getActivity(), mTileSizePx.y, view);
-        }
-
-        private ViewHolder createMyPhotosHolder(ViewGroup parent) {
-            LayoutInflater layoutInflater = LayoutInflater.from(getActivity());
-            View view = layoutInflater.inflate(R.layout.grid_item_my_photos, parent, false);
-
-            return new MyPhotosViewHolder(getActivity(),
-                    ((MyPhotosStarterProvider) getActivity()).getMyPhotosStarter(),
-                    mTileSizePx.y, view);
-        }
-
-        void onBindIndividualHolder(ViewHolder holder, int position) {
-            int wallpaperIndex = mCategory.supportsCustomPhotos() ? position - 1 : position;
-            WallpaperInfo wallpaper = mWallpapers.get(wallpaperIndex);
-            wallpaper.computeColorInfo(holder.itemView.getContext());
-            ((IndividualHolder) holder).bindWallpaper(wallpaper);
-            boolean isWallpaperApplied = isWallpaperApplied(wallpaper);
-
-            CardView container = holder.itemView.findViewById(R.id.wallpaper_container);
-            int radiusId = isFewerColumnLayout() ? R.dimen.grid_item_all_radius
-                    : R.dimen.grid_item_all_radius_small;
-            container.setRadius(getResources().getDimension(radiusId));
-            showBadge(holder, R.drawable.wallpaper_check_circle_24dp, isWallpaperApplied);
-        }
-
-        protected boolean isWallpaperApplied(WallpaperInfo wallpaper) {
-            return mAppliedWallpaperIds.contains(wallpaper.getWallpaperId());
-        }
-
-        protected void showBadge(ViewHolder holder, @DrawableRes int icon, boolean show) {
-            ImageView badge = holder.itemView.findViewById(R.id.indicator_icon);
-            if (show) {
-                final float margin = isFewerColumnLayout() ? getResources().getDimension(
-                        R.dimen.grid_item_badge_margin) : getResources().getDimension(
-                        R.dimen.grid_item_badge_margin_small);
-                final RelativeLayout.LayoutParams layoutParams =
-                        (RelativeLayout.LayoutParams) badge.getLayoutParams();
-                layoutParams.setMargins(/* left= */ (int) margin, /* top= */ (int) margin,
-                        /* right= */ (int) margin, /* bottom= */ (int) margin);
-                badge.setLayoutParams(layoutParams);
-                badge.setBackgroundResource(icon);
-                badge.setVisibility(View.VISIBLE);
-            } else {
-                badge.setVisibility(View.GONE);
-            }
-        }
-    }
-}
diff --git a/src/com/android/wallpaper/picker/individual/IndividualPickerFragment2.kt b/src/com/android/wallpaper/picker/individual/IndividualPickerFragment2.kt
index eaa12cb5..100f33fd 100644
--- a/src/com/android/wallpaper/picker/individual/IndividualPickerFragment2.kt
+++ b/src/com/android/wallpaper/picker/individual/IndividualPickerFragment2.kt
@@ -67,6 +67,10 @@ import com.android.wallpaper.picker.MyPhotosStarter.MyPhotosStarterProvider
 import com.android.wallpaper.picker.RotationStarter
 import com.android.wallpaper.picker.StartRotationDialogFragment
 import com.android.wallpaper.picker.StartRotationErrorDialogFragment
+import com.android.wallpaper.picker.category.ui.viewmodel.CategoriesViewModel
+import com.android.wallpaper.picker.category.ui.viewmodel.CategoriesViewModel.CategoryType
+import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper
+import com.android.wallpaper.picker.preview.ui.Hilt_WallpaperPreviewActivity.SHOULD_CATEGORY_REFRESH
 import com.android.wallpaper.util.ActivityUtils
 import com.android.wallpaper.util.LaunchUtils
 import com.android.wallpaper.util.SizeCalculator
@@ -114,6 +118,18 @@ class IndividualPickerFragment2 :
             fragment.arguments = args
             return fragment
         }
+
+        fun newInstance(
+            collectionId: String?,
+            categoryType: CategoriesViewModel.CategoryType,
+        ): IndividualPickerFragment2 {
+            val args = Bundle()
+            args.putString(ARG_CATEGORY_COLLECTION_ID, collectionId)
+            args.putSerializable(SHOULD_CATEGORY_REFRESH, categoryType)
+            val fragment = IndividualPickerFragment2()
+            fragment.arguments = args
+            return fragment
+        }
     }
 
     private lateinit var imageGrid: RecyclerView
@@ -123,6 +139,7 @@ class IndividualPickerFragment2 :
     private lateinit var items: MutableList<PickerItem>
     private var packageStatusNotifier: PackageStatusNotifier? = null
     private var isWallpapersReceived = false
+    private var wallpaperCategoryWrapper: WallpaperCategoryWrapper? = null
 
     private var appStatusListener: PackageStatusNotifier.Listener? = null
     private var progressDialog: ProgressDialog? = null
@@ -132,6 +149,9 @@ class IndividualPickerFragment2 :
     private lateinit var categoryProvider: CategoryProvider
     private var appliedWallpaperIds: Set<String> = setOf()
     private var mIsCreativeWallpaperEnabled = false
+    private var categoryRefactorFlag = false
+
+    private var refreshCreativeCategories: CategoriesViewModel.CategoryType? = null
 
     /**
      * Staged error dialog fragments that were unable to be shown when the activity didn't allow
@@ -148,6 +168,12 @@ class IndividualPickerFragment2 :
         mIsCreativeWallpaperEnabled = injector.getFlags().isAIWallpaperEnabled(appContext)
         wallpaperManager = WallpaperManager.getInstance(appContext)
         packageStatusNotifier = injector.getPackageStatusNotifier(appContext)
+        wallpaperCategoryWrapper = injector.getWallpaperCategoryWrapper()
+        categoryRefactorFlag = injector.getFlags().isWallpaperCategoryRefactoringEnabled()
+
+        refreshCreativeCategories =
+            arguments?.getSerializable(SHOULD_CATEGORY_REFRESH, CategoryType::class.java)
+                as? CategoryType
         items = ArrayList()
 
         // Clear Glide's cache if night-mode changed to ensure thumbnails are reloaded
@@ -159,17 +185,50 @@ class IndividualPickerFragment2 :
             Glide.get(requireContext()).clearMemory()
         }
         categoryProvider = injector.getCategoryProvider(appContext)
-        fetchCategories(forceRefresh = false, register = true)
+        if (categoryRefactorFlag && wallpaperCategoryWrapper != null) {
+            lifecycleScope.launch {
+                getCategories(register = true, forceRefreshLiveWallpaperCategory = false)
+            }
+        } else {
+            fetchCategories(forceRefresh = false, register = true)
+        }
+    }
+
+    private suspend fun getCategories(
+        register: Boolean,
+        forceRefreshLiveWallpaperCategory: Boolean,
+    ) {
+        val categories =
+            wallpaperCategoryWrapper?.getCategories(forceRefreshLiveWallpaperCategory) ?: return
+        val fetchedCategory =
+            arguments?.getString(ARG_CATEGORY_COLLECTION_ID)?.let {
+                wallpaperCategoryWrapper?.getCategory(
+                    categories,
+                    it,
+                    forceRefreshLiveWallpaperCategory,
+                )
+            }
+                ?: run {
+                    parentFragmentManager.popBackStack()
+                    Toast.makeText(context, R.string.collection_not_exist_msg, Toast.LENGTH_SHORT)
+                        .show()
+                    return
+                }
+        if (fetchedCategory !is WallpaperCategory) return
+        category = fetchedCategory
+        onCategoryLoaded(fetchedCategory, register)
+    }
+
+    private fun refreshDownloadableCategories() {
+        lifecycleScope.launch {
+            wallpaperCategoryWrapper?.refreshLiveWallpaperCategories()
+            getCategories(register = false, forceRefreshLiveWallpaperCategory = true)
+        }
     }
 
     /** This function handles the result of the fetched categories */
     private fun onCategoryLoaded(category: Category, shouldRegisterPackageListener: Boolean) {
-        val fragmentHost = getIndividualPickerFragmentHost()
-        if (fragmentHost.isHostToolbarShown) {
-            fragmentHost.setToolbarTitle(category.title)
-        } else {
-            setTitle(category.title)
-        }
+        setTitle(category.title)
         wallpaperRotationInitializer = category.wallpaperRotationInitializer
         if (mToolbar != null && isRotationEnabled()) {
             setUpToolbarMenu(R.menu.individual_picker_menu)
@@ -232,7 +291,7 @@ class IndividualPickerFragment2 :
                             wallpapers,
                             currentHomeWallpaper,
                             currentLockWallpaper,
-                            appliedWallpaperIds
+                            appliedWallpaperIds,
                         )
                     }
                 }
@@ -244,7 +303,7 @@ class IndividualPickerFragment2 :
                     activity?.finish()
                 }
             },
-            forceReload
+            forceReload,
         )
     }
 
@@ -266,7 +325,7 @@ class IndividualPickerFragment2 :
      */
     private fun addTemplates(
         wallpapers: List<WallpaperInfo>,
-        userCreatedWallpapers: MutableList<WallpaperInfo>
+        userCreatedWallpapers: MutableList<WallpaperInfo>,
     ) {
         wallpapers.map {
             if (category?.supportsUserCreatedWallpapers() == true) {
@@ -305,7 +364,11 @@ class IndividualPickerFragment2 :
             appStatusListener =
                 PackageStatusNotifier.Listener { pkgName: String?, status: Int ->
                     if (category.isCategoryDownloadable) {
-                        fetchCategories(true, false)
+                        if (categoryRefactorFlag) {
+                            refreshDownloadableCategories()
+                        } else {
+                            fetchCategories(forceRefresh = true, register = false)
+                        }
                     } else if (
                         (status != PackageStatusNotifier.PackageStatus.REMOVED ||
                             category.containsThirdParty(pkgName))
@@ -315,7 +378,7 @@ class IndividualPickerFragment2 :
                 }
             packageStatusNotifier?.addListener(
                 appStatusListener,
-                WallpaperService.SERVICE_INTERFACE
+                WallpaperService.SERVICE_INTERFACE,
             )
 
             if (category.isCategoryDownloadable) {
@@ -349,11 +412,11 @@ class IndividualPickerFragment2 :
                     if (fetchedCategory == null) {
                         // The absence of this category in the CategoryProvider indicates a broken
                         // state, see b/38030129. Hence, finish the activity and return.
-                        getIndividualPickerFragmentHost().moveToPreviousFragment()
+                        parentFragmentManager.popBackStack()
                         Toast.makeText(
                                 context,
                                 R.string.collection_not_exist_msg,
-                                Toast.LENGTH_SHORT
+                                Toast.LENGTH_SHORT,
                             )
                             .show()
                         return
@@ -362,7 +425,7 @@ class IndividualPickerFragment2 :
                     category?.let { onCategoryLoaded(it, register) }
                 }
             },
-            forceRefresh
+            forceRefresh,
         )
     }
 
@@ -378,29 +441,21 @@ class IndividualPickerFragment2 :
         super.onSaveInstanceState(outState)
         outState.putInt(
             KEY_NIGHT_MODE,
-            resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK
+            resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK,
         )
     }
 
     override fun onCreateView(
         inflater: LayoutInflater,
         container: ViewGroup?,
-        savedInstanceState: Bundle?
+        savedInstanceState: Bundle?,
     ): View {
         val view: View = inflater.inflate(R.layout.fragment_individual_picker, container, false)
-        if (getIndividualPickerFragmentHost().isHostToolbarShown) {
-            view.requireViewById<View>(R.id.header_bar).visibility = View.GONE
-            setUpArrowEnabled(/* upArrow= */ true)
-            if (isRotationEnabled()) {
-                getIndividualPickerFragmentHost().setToolbarMenu(R.menu.individual_picker_menu)
-            }
-        } else {
-            setUpToolbar(view)
-            if (isRotationEnabled()) {
-                setUpToolbarMenu(R.menu.individual_picker_menu)
-            }
-            setTitle(category?.title)
+        setUpToolbar(view)
+        if (isRotationEnabled()) {
+            setUpToolbarMenu(R.menu.individual_picker_menu)
         }
+        setTitle(category?.title)
         imageGrid = view.requireViewById<View>(R.id.wallpaper_grid) as RecyclerView
         loading = view.requireViewById(R.id.loading_indicator)
         updateLoading()
@@ -411,23 +466,13 @@ class IndividualPickerFragment2 :
                 v.paddingLeft,
                 v.paddingTop,
                 v.paddingRight,
-                windowInsets.systemWindowInsetBottom
+                windowInsets.systemWindowInsetBottom,
             )
             windowInsets.consumeSystemWindowInsets()
         }
         return view
     }
 
-    private fun getIndividualPickerFragmentHost():
-        IndividualPickerFragment.IndividualPickerFragmentHost {
-        val parentFragment = parentFragment
-        return if (parentFragment != null) {
-            parentFragment as IndividualPickerFragment.IndividualPickerFragmentHost
-        } else {
-            activity as IndividualPickerFragment.IndividualPickerFragmentHost
-        }
-    }
-
     private fun maybeSetUpImageGrid() {
         // Skip if mImageGrid been initialized yet
         if (!this::imageGrid.isInitialized) {
@@ -440,7 +485,6 @@ class IndividualPickerFragment2 :
         if (context == null) {
             return
         }
-
         // Wallpaper count could change, so we may need to change the layout(2 or 3 columns layout)
         val gridLayoutManager = imageGrid.layoutManager as GridLayoutManager?
         val needUpdateLayout = gridLayoutManager?.spanCount != getNumColumns()
@@ -462,7 +506,7 @@ class IndividualPickerFragment2 :
                 GridPaddingDecorationCreativeCategory(
                     getGridItemPaddingHorizontal(),
                     getGridItemPaddingBottom(),
-                    edgePadding
+                    edgePadding,
                 )
             )
         } else {
@@ -473,7 +517,7 @@ class IndividualPickerFragment2 :
                 edgePadding,
                 imageGrid.paddingTop,
                 edgePadding,
-                imageGrid.paddingBottom
+                imageGrid.paddingBottom,
             )
         }
 
@@ -488,7 +532,7 @@ class IndividualPickerFragment2 :
             WallpaperPickerRecyclerViewAccessibilityDelegate(
                 imageGrid,
                 parentFragment as BottomSheetHost?,
-                getNumColumns()
+                getNumColumns(),
             )
         )
     }
@@ -538,7 +582,8 @@ class IndividualPickerFragment2 :
                 isFewerColumnLayout(),
                 getEdgePadding(),
                 imageGrid.paddingTop,
-                imageGrid.paddingBottom
+                imageGrid.paddingBottom,
+                refreshCreativeCategories,
             )
         imageGrid.adapter = adapter
 
@@ -584,7 +629,7 @@ class IndividualPickerFragment2 :
         if (isAdded) {
             stagedStartRotationErrorDialogFragment?.show(
                 parentFragmentManager,
-                TAG_START_ROTATION_ERROR_DIALOG
+                TAG_START_ROTATION_ERROR_DIALOG,
             )
             lifecycleScope.launch { fetchWallpapersIfNeeded() }
         }
@@ -598,7 +643,6 @@ class IndividualPickerFragment2 :
 
     override fun onDestroyView() {
         super.onDestroyView()
-        getIndividualPickerFragmentHost().removeToolbarMenu()
     }
 
     override fun onDestroy() {
@@ -656,7 +700,7 @@ class IndividualPickerFragment2 :
                                 Toast.makeText(
                                         activity,
                                         R.string.wallpaper_set_successfully_message,
-                                        Toast.LENGTH_SHORT
+                                        Toast.LENGTH_SHORT,
                                     )
                                     .show()
                             } catch (e: Resources.NotFoundException) {
@@ -678,7 +722,7 @@ class IndividualPickerFragment2 :
                     progressDialog?.dismiss()
                     showStartRotationErrorDialog(networkPreference)
                 }
-            }
+            },
         )
     }
 
@@ -689,12 +733,12 @@ class IndividualPickerFragment2 :
                 StartRotationErrorDialogFragment.newInstance(networkPreference)
             startRotationErrorDialogFragment.setTargetFragment(
                 this@IndividualPickerFragment2,
-                UNUSED_REQUEST_CODE
+                UNUSED_REQUEST_CODE,
             )
             if (activity.isSafeToCommitFragmentTransaction) {
                 startRotationErrorDialogFragment.show(
                     parentFragmentManager,
-                    TAG_START_ROTATION_ERROR_DIALOG
+                    TAG_START_ROTATION_ERROR_DIALOG,
                 )
             } else {
                 stagedStartRotationErrorDialogFragment = startRotationErrorDialogFragment
@@ -727,7 +771,7 @@ class IndividualPickerFragment2 :
         val startRotationDialogFragment: DialogFragment = StartRotationDialogFragment()
         startRotationDialogFragment.setTargetFragment(
             this@IndividualPickerFragment2,
-            UNUSED_REQUEST_CODE
+            UNUSED_REQUEST_CODE,
         )
         startRotationDialogFragment.show(parentFragmentManager, TAG_START_ROTATION_DIALOG)
     }
@@ -786,7 +830,8 @@ class IndividualPickerFragment2 :
         private val isFewerColumnLayout: Boolean,
         private val edgePadding: Int,
         private val bottomPadding: Int,
-        private val topPadding: Int
+        private val topPadding: Int,
+        private val refreshCreativeCategories: CategoryType?,
     ) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {
         companion object {
             const val ITEM_VIEW_TYPE_INDIVIDUAL_WALLPAPER = 2
@@ -854,7 +899,7 @@ class IndividualPickerFragment2 :
         private fun createIndividualHolder(parent: ViewGroup): RecyclerView.ViewHolder {
             val layoutInflater = LayoutInflater.from(activity)
             val view: View = layoutInflater.inflate(R.layout.grid_item_image, parent, false)
-            return PreviewIndividualHolder(activity, tileSizePx.y, view)
+            return PreviewIndividualHolder(activity, tileSizePx.y, view, refreshCreativeCategories)
         }
 
         private fun creativeCategoryHolder(parent: ViewGroup): RecyclerView.ViewHolder {
@@ -864,10 +909,7 @@ class IndividualPickerFragment2 :
             if (isCreativeCategory) {
                 view.setPadding(edgePadding, topPadding, edgePadding, bottomPadding)
             }
-            return CreativeCategoryHolder(
-                activity,
-                view,
-            )
+            return CreativeCategoryHolder(activity, view)
         }
 
         private fun createMyPhotosHolder(parent: ViewGroup): RecyclerView.ViewHolder {
@@ -877,7 +919,7 @@ class IndividualPickerFragment2 :
                 activity,
                 (activity as MyPhotosStarterProvider).myPhotosStarter,
                 tileSizePx.y,
-                view
+                view,
             )
         }
 
@@ -886,13 +928,13 @@ class IndividualPickerFragment2 :
             val item = items[wallpaperIndex] as PickerItem.CreativeCollection
             (holder as CreativeCategoryHolder).bind(
                 item.templates,
-                SizeCalculator.getFeaturedIndividualTileSize(activity).y
+                SizeCalculator.getFeaturedIndividualTileSize(activity).y,
             )
         }
 
         private fun createTitleHolder(
             parent: ViewGroup,
-            removePaddingTop: Boolean
+            removePaddingTop: Boolean,
         ): RecyclerView.ViewHolder {
             val layoutInflater = LayoutInflater.from(activity)
             val view =
@@ -906,14 +948,14 @@ class IndividualPickerFragment2 :
                     startPadding,
                     /* top= */ 0,
                     view.paddingEnd,
-                    view.paddingBottom
+                    view.paddingBottom,
                 )
             } else {
                 view.setPaddingRelative(
                     startPadding,
                     view.paddingTop,
                     view.paddingEnd,
-                    view.paddingBottom
+                    view.paddingBottom,
                 )
             }
             return object : RecyclerView.ViewHolder(view) {}
@@ -942,7 +984,7 @@ class IndividualPickerFragment2 :
         private fun showBadge(
             holder: RecyclerView.ViewHolder,
             @DrawableRes icon: Int,
-            show: Boolean
+            show: Boolean,
         ) {
             val badge = holder.itemView.requireViewById<ImageView>(R.id.indicator_icon)
             if (show) {
diff --git a/src/com/android/wallpaper/picker/individual/PreviewIndividualHolder.java b/src/com/android/wallpaper/picker/individual/PreviewIndividualHolder.java
index 48a8794c..3415edc6 100755
--- a/src/com/android/wallpaper/picker/individual/PreviewIndividualHolder.java
+++ b/src/com/android/wallpaper/picker/individual/PreviewIndividualHolder.java
@@ -26,6 +26,7 @@ import com.android.wallpaper.model.LiveWallpaperInfo;
 import com.android.wallpaper.model.WallpaperInfo;
 import com.android.wallpaper.module.InjectorProvider;
 import com.android.wallpaper.module.WallpaperPersister;
+import com.android.wallpaper.picker.category.ui.viewmodel.CategoriesViewModel;
 
 /**
  * IndividualHolder subclass for a wallpaper tile in the RecyclerView for which a click should
@@ -35,12 +36,14 @@ class PreviewIndividualHolder extends IndividualHolder implements View.OnClickLi
     private static final String TAG = "PreviewIndividualHolder";
 
     private WallpaperPersister mWallpaperPersister;
+    CategoriesViewModel.CategoryType mCategoryType;
 
     public PreviewIndividualHolder(
-            Activity hostActivity, int tileHeightPx, View itemView) {
+            Activity hostActivity, int tileHeightPx, View itemView,
+            CategoriesViewModel.CategoryType categoryType) {
         super(hostActivity, tileHeightPx, tileHeightPx, itemView);
         mTileLayout.setOnClickListener(this);
-
+        mCategoryType = categoryType;
         mWallpaperPersister = InjectorProvider.getInjector().getWallpaperPersister(hostActivity);
     }
 
@@ -58,10 +61,12 @@ class PreviewIndividualHolder extends IndividualHolder implements View.OnClickLi
      */
     private void showPreview(WallpaperInfo wallpaperInfo) {
         mWallpaperPersister.setWallpaperInfoInPreview(wallpaperInfo);
+
         wallpaperInfo.showPreview(mActivity,
                 InjectorProvider.getInjector().getPreviewActivityIntentFactory(),
                 wallpaperInfo instanceof LiveWallpaperInfo ? PREVIEW_LIVE_WALLPAPER_REQUEST_CODE
-                        : PREVIEW_WALLPAPER_REQUEST_CODE, true);
+                        : PREVIEW_WALLPAPER_REQUEST_CODE, true,
+                (mCategoryType == CategoriesViewModel.CategoryType.CreativeCategories));
     }
 
 }
diff --git a/src/com/android/wallpaper/picker/network/data/DefaultNetworkStatusRepository.kt b/src/com/android/wallpaper/picker/network/data/DefaultNetworkStatusRepository.kt
new file mode 100644
index 00000000..f881db4a
--- /dev/null
+++ b/src/com/android/wallpaper/picker/network/data/DefaultNetworkStatusRepository.kt
@@ -0,0 +1,70 @@
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
+package com.android.wallpaper.picker.network.data
+
+import android.content.Context
+import android.util.Log
+import com.android.wallpaper.module.NetworkStatusNotifier
+import com.android.wallpaper.module.NetworkStatusNotifier.NETWORK_CONNECTED
+import com.android.wallpaper.module.NetworkStatusNotifier.NETWORK_NOT_INITIALIZED
+import dagger.hilt.android.qualifiers.ApplicationContext
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.channels.awaitClose
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.callbackFlow
+
+@Singleton
+open class DefaultNetworkStatusRepository
+@Inject
+constructor(
+    @ApplicationContext val context: Context,
+    private val networkStatusNotifier: NetworkStatusNotifier,
+) : NetworkStatusRepository {
+
+    private val _networkStatus = MutableStateFlow<Int>(NETWORK_NOT_INITIALIZED)
+
+    init {
+        _networkStatus.value = networkStatusNotifier.networkStatus
+    }
+
+    override fun networkStateFlow(): Flow<Boolean> = callbackFlow {
+        val listener =
+            NetworkStatusNotifier.Listener { status: Int ->
+                Log.i(DefaultNetworkStatusRepository.TAG, "Network status changes: " + status)
+                if (_networkStatus.value != NETWORK_CONNECTED && status == NETWORK_CONNECTED) {
+                    // Emit true value when network is available and it was previously unavailable
+                    trySend(true)
+                } else {
+                    trySend(false)
+                }
+
+                _networkStatus.value = networkStatusNotifier.networkStatus
+            }
+
+        // Register the listener with the network status notifier
+        networkStatusNotifier.registerListener(listener)
+
+        // Await close and unregister listener to avoid memory leaks
+        awaitClose { networkStatusNotifier.unregisterListener(listener) }
+    }
+
+    companion object {
+        private const val TAG = "DefaultNetworkStatusRepository"
+    }
+}
diff --git a/src/com/android/wallpaper/picker/network/data/NetworkStatusRepository.kt b/src/com/android/wallpaper/picker/network/data/NetworkStatusRepository.kt
new file mode 100644
index 00000000..a67c3746
--- /dev/null
+++ b/src/com/android/wallpaper/picker/network/data/NetworkStatusRepository.kt
@@ -0,0 +1,35 @@
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
+package com.android.wallpaper.picker.network.data
+
+import kotlinx.coroutines.flow.Flow
+
+/** An interface which allows consumers to collect network status information */
+interface NetworkStatusRepository {
+
+    /**
+     * Returns a [Flow] that emits the current network connectivity status.
+     *
+     * The flow emits `true` when the network is available (connected) after being unavailable and
+     * `false` otherwise
+     *
+     * The emitted values will update whenever the network status changes.
+     *
+     * @return A [Flow] of [Boolean] representing the network connectivity status.
+     */
+    fun networkStateFlow(): Flow<Boolean>
+}
diff --git a/src/com/android/wallpaper/picker/network/domain/DefaultNetworkStatusInteractor.kt b/src/com/android/wallpaper/picker/network/domain/DefaultNetworkStatusInteractor.kt
new file mode 100644
index 00000000..34585164
--- /dev/null
+++ b/src/com/android/wallpaper/picker/network/domain/DefaultNetworkStatusInteractor.kt
@@ -0,0 +1,30 @@
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
+package com.android.wallpaper.picker.network.domain
+
+import com.android.wallpaper.picker.network.data.NetworkStatusRepository
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.flow.Flow
+
+@Singleton
+class DefaultNetworkStatusInteractor
+@Inject
+constructor(private val networkStatusRepository: NetworkStatusRepository) :
+    NetworkStatusInteractor {
+    override val isConnectionObtained: Flow<Boolean> = networkStatusRepository.networkStateFlow()
+}
diff --git a/src/com/android/wallpaper/picker/network/domain/NetworkStatusInteractor.kt b/src/com/android/wallpaper/picker/network/domain/NetworkStatusInteractor.kt
new file mode 100644
index 00000000..7f2576fd
--- /dev/null
+++ b/src/com/android/wallpaper/picker/network/domain/NetworkStatusInteractor.kt
@@ -0,0 +1,23 @@
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
+package com.android.wallpaper.picker.network.domain
+
+import kotlinx.coroutines.flow.Flow
+
+interface NetworkStatusInteractor {
+    val isConnectionObtained: Flow<Boolean>
+}
diff --git a/src/com/android/wallpaper/picker/preview/data/repository/DownloadableWallpaperRepository.kt b/src/com/android/wallpaper/picker/preview/data/repository/DownloadableWallpaperRepository.kt
new file mode 100644
index 00000000..b3122583
--- /dev/null
+++ b/src/com/android/wallpaper/picker/preview/data/repository/DownloadableWallpaperRepository.kt
@@ -0,0 +1,75 @@
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
+package com.android.wallpaper.picker.preview.data.repository
+
+import com.android.wallpaper.picker.data.WallpaperModel.LiveWallpaperModel
+import com.android.wallpaper.picker.preview.data.util.LiveWallpaperDownloader
+import com.android.wallpaper.picker.preview.shared.model.DownloadStatus.DOWNLOADED
+import com.android.wallpaper.picker.preview.shared.model.DownloadStatus.DOWNLOADING
+import com.android.wallpaper.picker.preview.shared.model.DownloadStatus.DOWNLOAD_NOT_AVAILABLE
+import com.android.wallpaper.picker.preview.shared.model.DownloadStatus.READY_TO_DOWNLOAD
+import com.android.wallpaper.picker.preview.shared.model.DownloadableWallpaperModel
+import dagger.hilt.android.scopes.ActivityRetainedScoped
+import javax.inject.Inject
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.combine
+
+@ActivityRetainedScoped
+class DownloadableWallpaperRepository
+@Inject
+constructor(
+    private val liveWallpaperDownloader: LiveWallpaperDownloader,
+) {
+
+    private val _downloadableWallpaperModel =
+        MutableStateFlow(DownloadableWallpaperModel(READY_TO_DOWNLOAD, null))
+    val downloadableWallpaperModel: Flow<DownloadableWallpaperModel> =
+        combine(
+            _downloadableWallpaperModel.asStateFlow(),
+            liveWallpaperDownloader.isDownloaderReady
+        ) { model, isReady ->
+            if (isReady) {
+                model
+            } else {
+                DownloadableWallpaperModel(DOWNLOAD_NOT_AVAILABLE, null)
+            }
+        }
+
+    fun downloadWallpaper(onDownloaded: (wallpaperModel: LiveWallpaperModel) -> Unit) {
+        _downloadableWallpaperModel.value = DownloadableWallpaperModel(DOWNLOADING, null)
+        liveWallpaperDownloader.downloadWallpaper(
+            object : LiveWallpaperDownloader.LiveWallpaperDownloadListener {
+                override fun onDownloadSuccess(wallpaperModel: LiveWallpaperModel) {
+                    onDownloaded(wallpaperModel)
+                    _downloadableWallpaperModel.value =
+                        DownloadableWallpaperModel(DOWNLOADED, wallpaperModel)
+                }
+
+                override fun onDownloadFailed() {
+                    _downloadableWallpaperModel.value =
+                        DownloadableWallpaperModel(READY_TO_DOWNLOAD, null)
+                }
+            }
+        )
+    }
+
+    fun cancelDownloadWallpaper(): Boolean {
+        return liveWallpaperDownloader.cancelDownloadWallpaper()
+    }
+}
diff --git a/src/com/android/wallpaper/picker/preview/data/repository/ImageEffectsRepositoryImpl.kt b/src/com/android/wallpaper/picker/preview/data/repository/ImageEffectsRepositoryImpl.kt
index e4d093c5..c9193bab 100644
--- a/src/com/android/wallpaper/picker/preview/data/repository/ImageEffectsRepositoryImpl.kt
+++ b/src/com/android/wallpaper/picker/preview/data/repository/ImageEffectsRepositoryImpl.kt
@@ -234,7 +234,14 @@ constructor(
             }
 
             if (effectsController.isEffectTriggered) {
-                _imageEffectsModel.value = ImageEffectsModel(EffectStatus.EFFECT_READY)
+                // If the previous state before a config change restart is effect applied or effect
+                // apply in progress, retain that state.
+                if (
+                    _imageEffectsModel.value.status != EffectStatus.EFFECT_APPLIED &&
+                        _imageEffectsModel.value.status != EffectStatus.EFFECT_APPLY_IN_PROGRESS
+                ) {
+                    _imageEffectsModel.value = ImageEffectsModel(EffectStatus.EFFECT_READY)
+                }
             } else {
                 effectsController.triggerEffect(context)
             }
@@ -249,8 +256,7 @@ constructor(
                 getParcelable<ComponentName>(WallpaperManager.EXTRA_LIVE_WALLPAPER_COMPONENT)
             } else {
                 null
-            }
-                ?: return null
+            } ?: return null
 
         val assetId =
             if (containsKey(EffectContract.ASSET_ID)) {
diff --git a/src/com/android/wallpaper/picker/preview/data/repository/WallpaperPreviewRepository.kt b/src/com/android/wallpaper/picker/preview/data/repository/WallpaperPreviewRepository.kt
index 7bd1fc9d..0d3b66ce 100644
--- a/src/com/android/wallpaper/picker/preview/data/repository/WallpaperPreviewRepository.kt
+++ b/src/com/android/wallpaper/picker/preview/data/repository/WallpaperPreviewRepository.kt
@@ -18,27 +18,17 @@ package com.android.wallpaper.picker.preview.data.repository
 
 import com.android.wallpaper.module.WallpaperPreferences
 import com.android.wallpaper.picker.data.WallpaperModel
-import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
-import com.android.wallpaper.picker.preview.data.util.LiveWallpaperDownloader
-import com.android.wallpaper.picker.preview.shared.model.LiveWallpaperDownloadResultCode.SUCCESS
-import com.android.wallpaper.picker.preview.shared.model.LiveWallpaperDownloadResultModel
 import dagger.hilt.android.scopes.ActivityRetainedScoped
 import javax.inject.Inject
-import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.StateFlow
 import kotlinx.coroutines.flow.asStateFlow
-import kotlinx.coroutines.withContext
 
 /** This repository class manages the [WallpaperModel] for the preview screen */
 @ActivityRetainedScoped
 class WallpaperPreviewRepository
 @Inject
-constructor(
-    private val liveWallpaperDownloader: LiveWallpaperDownloader,
-    private val preferences: WallpaperPreferences,
-    @BackgroundDispatcher private val bgDispatcher: CoroutineDispatcher,
-) {
+constructor(private val preferences: WallpaperPreferences) {
     /** This [WallpaperModel] represents the current selected wallpaper */
     private val _wallpaperModel = MutableStateFlow<WallpaperModel?>(null)
     val wallpaperModel: StateFlow<WallpaperModel?> = _wallpaperModel.asStateFlow()
@@ -66,18 +56,4 @@ constructor(
         _hasFullPreviewTooltipBeenShown.value = true
         preferences.setHasFullPreviewTooltipBeenShown(true)
     }
-
-    suspend fun downloadWallpaper(): LiveWallpaperDownloadResultModel? =
-        withContext(bgDispatcher) {
-            val result = liveWallpaperDownloader.downloadWallpaper()
-            if (result?.code == SUCCESS && result.wallpaperModel != null) {
-                // If download success, update repo's WallpaperModel to render the live wallpaper.
-                _wallpaperModel.value = result.wallpaperModel
-                result
-            } else {
-                result
-            }
-        }
-
-    fun cancelDownloadWallpaper(): Boolean  = liveWallpaperDownloader.cancelDownloadWallpaper()
 }
diff --git a/src/com/android/wallpaper/picker/preview/data/util/DefaultLiveWallpaperDownloader.kt b/src/com/android/wallpaper/picker/preview/data/util/DefaultLiveWallpaperDownloader.kt
index 8fb205ea..dbc0242d 100644
--- a/src/com/android/wallpaper/picker/preview/data/util/DefaultLiveWallpaperDownloader.kt
+++ b/src/com/android/wallpaper/picker/preview/data/util/DefaultLiveWallpaperDownloader.kt
@@ -20,24 +20,30 @@ import android.app.Activity
 import androidx.activity.result.ActivityResultLauncher
 import androidx.activity.result.IntentSenderRequest
 import com.android.wallpaper.picker.data.WallpaperModel
-import com.android.wallpaper.picker.preview.shared.model.LiveWallpaperDownloadResultModel
+import com.android.wallpaper.picker.preview.data.util.LiveWallpaperDownloader.LiveWallpaperDownloadListener
+import dagger.hilt.android.scopes.ActivityRetainedScoped
 import javax.inject.Inject
-import javax.inject.Singleton
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.asStateFlow
 
-@Singleton
+@ActivityRetainedScoped
 class DefaultLiveWallpaperDownloader @Inject constructor() : LiveWallpaperDownloader {
 
+    private val _isDownloaderReady = MutableStateFlow(false)
+    override val isDownloaderReady: Flow<Boolean> = _isDownloaderReady.asStateFlow()
+
     override fun initiateDownloadableService(
         activity: Activity,
         wallpaperData: WallpaperModel.StaticWallpaperModel,
         intentSenderLauncher: ActivityResultLauncher<IntentSenderRequest>
-    ) {}
+    ) {
+        _isDownloaderReady.value = true
+    }
 
     override fun cleanup() {}
 
-    override suspend fun downloadWallpaper(): LiveWallpaperDownloadResultModel? {
-        return null
-    }
+    override fun downloadWallpaper(listener: LiveWallpaperDownloadListener) {}
 
     override fun cancelDownloadWallpaper(): Boolean = false
 }
diff --git a/src/com/android/wallpaper/picker/preview/data/util/LiveWallpaperDownloader.kt b/src/com/android/wallpaper/picker/preview/data/util/LiveWallpaperDownloader.kt
index de995c7f..dd207560 100644
--- a/src/com/android/wallpaper/picker/preview/data/util/LiveWallpaperDownloader.kt
+++ b/src/com/android/wallpaper/picker/preview/data/util/LiveWallpaperDownloader.kt
@@ -19,8 +19,9 @@ package com.android.wallpaper.picker.preview.data.util
 import android.app.Activity
 import androidx.activity.result.ActivityResultLauncher
 import androidx.activity.result.IntentSenderRequest
-import com.android.wallpaper.picker.data.WallpaperModel
-import com.android.wallpaper.picker.preview.shared.model.LiveWallpaperDownloadResultModel
+import com.android.wallpaper.picker.data.WallpaperModel.LiveWallpaperModel
+import com.android.wallpaper.picker.data.WallpaperModel.StaticWallpaperModel
+import kotlinx.coroutines.flow.Flow
 
 /**
  * Handles the download process of a downloadable wallpaper. This downloader should be aware of the
@@ -28,13 +29,21 @@ import com.android.wallpaper.picker.preview.shared.model.LiveWallpaperDownloadRe
  */
 interface LiveWallpaperDownloader {
 
+    val isDownloaderReady: Flow<Boolean>
+
+    interface LiveWallpaperDownloadListener {
+        fun onDownloadSuccess(wallpaperModel: LiveWallpaperModel)
+
+        fun onDownloadFailed()
+    }
+
     /**
      * Initializes the downloadable service. This needs to be called when [Activity.onCreate] and
      * before calling [downloadWallpaper].
      */
     fun initiateDownloadableService(
         activity: Activity,
-        wallpaperData: WallpaperModel.StaticWallpaperModel,
+        wallpaperData: StaticWallpaperModel,
         intentSenderLauncher: ActivityResultLauncher<IntentSenderRequest>,
     )
 
@@ -44,11 +53,8 @@ interface LiveWallpaperDownloader {
      */
     fun cleanup()
 
-    suspend fun downloadWallpaper(): LiveWallpaperDownloadResultModel?
+    fun downloadWallpaper(listener: LiveWallpaperDownloadListener)
 
-
-    /**
-     * @return True if there is a confirm cancel download dialog from the download service.
-     */
+    /** @return True if there is a confirm cancel download dialog from the download service. */
     fun cancelDownloadWallpaper(): Boolean
 }
diff --git a/src/com/android/wallpaper/picker/preview/domain/interactor/PreviewActionsInteractor.kt b/src/com/android/wallpaper/picker/preview/domain/interactor/PreviewActionsInteractor.kt
index 2db167d3..069b9352 100644
--- a/src/com/android/wallpaper/picker/preview/domain/interactor/PreviewActionsInteractor.kt
+++ b/src/com/android/wallpaper/picker/preview/domain/interactor/PreviewActionsInteractor.kt
@@ -20,16 +20,15 @@ import com.android.wallpaper.effects.Effect
 import com.android.wallpaper.effects.EffectsController.EffectEnumInterface
 import com.android.wallpaper.picker.data.WallpaperModel
 import com.android.wallpaper.picker.preview.data.repository.CreativeEffectsRepository
+import com.android.wallpaper.picker.preview.data.repository.DownloadableWallpaperRepository
 import com.android.wallpaper.picker.preview.data.repository.ImageEffectsRepository
 import com.android.wallpaper.picker.preview.data.repository.WallpaperPreviewRepository
-import com.android.wallpaper.picker.preview.shared.model.LiveWallpaperDownloadResultModel
+import com.android.wallpaper.picker.preview.shared.model.DownloadableWallpaperModel
 import com.android.wallpaper.widget.floatingsheetcontent.WallpaperEffectsView2
 import dagger.hilt.android.scopes.ActivityRetainedScoped
 import javax.inject.Inject
 import kotlinx.coroutines.flow.Flow
-import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.StateFlow
-import kotlinx.coroutines.flow.asStateFlow
 
 /** This class handles the business logic for Preview screen's action buttons */
 @ActivityRetainedScoped
@@ -39,11 +38,12 @@ constructor(
     private val wallpaperPreviewRepository: WallpaperPreviewRepository,
     private val imageEffectsRepository: ImageEffectsRepository,
     private val creativeEffectsRepository: CreativeEffectsRepository,
+    private val downloadableWallpaperRepository: DownloadableWallpaperRepository,
 ) {
     val wallpaperModel: StateFlow<WallpaperModel?> = wallpaperPreviewRepository.wallpaperModel
 
-    private val _isDownloadingWallpaper = MutableStateFlow<Boolean>(false)
-    val isDownloadingWallpaper: Flow<Boolean> = _isDownloadingWallpaper.asStateFlow()
+    val downloadableWallpaperModel: Flow<DownloadableWallpaperModel> =
+        downloadableWallpaperRepository.downloadableWallpaperModel
 
     val imageEffectsModel = imageEffectsRepository.imageEffectsModel
     val imageEffect = imageEffectsRepository.wallpaperEffect
@@ -69,14 +69,16 @@ constructor(
         return imageEffectsRepository.getEffectTextRes()
     }
 
-    suspend fun downloadWallpaper(): LiveWallpaperDownloadResultModel? {
-        _isDownloadingWallpaper.value = true
-        val wallpaperModel = wallpaperPreviewRepository.downloadWallpaper()
-        _isDownloadingWallpaper.value = false
-        return wallpaperModel
+    fun downloadWallpaper() {
+        downloadableWallpaperRepository.downloadWallpaper { viewModel ->
+            // If download success, update wallpaper preview repo's WallpaperModel to render the
+            // live wallpaper.
+            wallpaperPreviewRepository.setWallpaperModel(viewModel)
+        }
     }
 
-    fun cancelDownloadWallpaper(): Boolean = wallpaperPreviewRepository.cancelDownloadWallpaper()
+    fun cancelDownloadWallpaper(): Boolean =
+        downloadableWallpaperRepository.cancelDownloadWallpaper()
 
     fun startEffectsModelDownload(effect: Effect) {
         imageEffectsRepository.startEffectsModelDownload(effect)
diff --git a/src/com/android/wallpaper/picker/preview/shared/model/DownloadWallpaperModel.kt b/src/com/android/wallpaper/picker/preview/shared/model/DownloadWallpaperModel.kt
new file mode 100644
index 00000000..fbeca01a
--- /dev/null
+++ b/src/com/android/wallpaper/picker/preview/shared/model/DownloadWallpaperModel.kt
@@ -0,0 +1,34 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package com.android.wallpaper.picker.preview.shared.model
+
+import com.android.wallpaper.picker.data.WallpaperModel.LiveWallpaperModel
+
+/**
+ * Data class representing the status and the wallpaper from downloading a downloadable wallpaper.
+ */
+data class DownloadableWallpaperModel(
+    val status: DownloadStatus,
+    val wallpaperModel: LiveWallpaperModel?,
+)
+
+enum class DownloadStatus {
+    DOWNLOAD_NOT_AVAILABLE,
+    READY_TO_DOWNLOAD,
+    DOWNLOADING,
+    DOWNLOADED,
+}
diff --git a/src/com/android/wallpaper/picker/preview/ui/WallpaperPreviewActivity.kt b/src/com/android/wallpaper/picker/preview/ui/WallpaperPreviewActivity.kt
index 3a562fdb..46c3f564 100644
--- a/src/com/android/wallpaper/picker/preview/ui/WallpaperPreviewActivity.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/WallpaperPreviewActivity.kt
@@ -15,6 +15,7 @@
  */
 package com.android.wallpaper.picker.preview.ui
 
+import android.app.WindowConfiguration.WINDOWING_MODE_FREEFORM
 import android.content.Context
 import android.content.Intent
 import android.content.pm.ActivityInfo
@@ -28,11 +29,14 @@ import androidx.core.view.WindowCompat
 import androidx.lifecycle.lifecycleScope
 import androidx.navigation.fragment.NavHostFragment
 import com.android.wallpaper.R
+import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.model.ImageWallpaperInfo
 import com.android.wallpaper.model.WallpaperInfo
 import com.android.wallpaper.module.InjectorProvider
 import com.android.wallpaper.picker.AppbarFragment
 import com.android.wallpaper.picker.BasePreviewActivity
+import com.android.wallpaper.picker.category.ui.viewmodel.CategoriesViewModel
+import com.android.wallpaper.picker.common.preview.data.repository.PersistentWallpaperModelRepository
 import com.android.wallpaper.picker.data.WallpaperModel
 import com.android.wallpaper.picker.di.modules.MainDispatcher
 import com.android.wallpaper.picker.preview.data.repository.CreativeEffectsRepository
@@ -64,10 +68,19 @@ class WallpaperPreviewActivity :
     @Inject lateinit var wallpaperPreviewRepository: WallpaperPreviewRepository
     @Inject lateinit var imageEffectsRepository: ImageEffectsRepository
     @Inject lateinit var creativeEffectsRepository: CreativeEffectsRepository
+    @Inject lateinit var persistentWallpaperModelRepository: PersistentWallpaperModelRepository
     @Inject lateinit var liveWallpaperDownloader: LiveWallpaperDownloader
     @MainDispatcher @Inject lateinit var mainScope: CoroutineScope
+    @Inject lateinit var wallpaperConnectionUtils: WallpaperConnectionUtils
+
+    private var refreshCreativeCategories: Boolean? = null
 
     private val wallpaperPreviewViewModel: WallpaperPreviewViewModel by viewModels()
+    private val categoriesViewModel: CategoriesViewModel by viewModels()
+
+    private val isNewPickerUi = BaseFlags.get().isNewPickerUi()
+    private val isCategoriesRefactorEnabled =
+        BaseFlags.get().isWallpaperCategoryRefactoringEnabled()
 
     override fun onCreate(savedInstanceState: Bundle?) {
         window.requestFeature(Window.FEATURE_ACTIVITY_TRANSITIONS)
@@ -80,9 +93,25 @@ class WallpaperPreviewActivity :
         window.navigationBarColor = Color.TRANSPARENT
         window.statusBarColor = Color.TRANSPARENT
         setContentView(R.layout.activity_wallpaper_preview)
-        val wallpaper =
-            checkNotNull(intent.getParcelableExtra(EXTRA_WALLPAPER_INFO, WallpaperInfo::class.java))
-                .convertToWallpaperModel()
+
+        if (isCategoriesRefactorEnabled) {
+            refreshCreativeCategories = intent.getBooleanExtra(SHOULD_CATEGORY_REFRESH, false)
+        }
+
+        val wallpaper: WallpaperModel? =
+            if (isNewPickerUi || isCategoriesRefactorEnabled) {
+                persistentWallpaperModelRepository.wallpaperModel.value
+                    ?: intent
+                        .getParcelableExtra(EXTRA_WALLPAPER_INFO, WallpaperInfo::class.java)
+                        ?.convertToWallpaperModel()
+            } else {
+                intent
+                    .getParcelableExtra(EXTRA_WALLPAPER_INFO, WallpaperInfo::class.java)
+                    ?.convertToWallpaperModel()
+            }
+
+        wallpaper ?: throw UnsupportedOperationException()
+
         val navController =
             (supportFragmentManager.findFragmentById(R.id.wallpaper_preview_nav_host)
                     as NavHostFragment)
@@ -158,14 +187,22 @@ class WallpaperPreviewActivity :
 
     override fun onResume() {
         super.onResume()
-        if (isInMultiWindowMode) {
+        val isWindowingModeFreeform =
+            resources.configuration.windowConfiguration.windowingMode == WINDOWING_MODE_FREEFORM
+        if (isInMultiWindowMode && !isWindowingModeFreeform) {
             Toast.makeText(this, R.string.wallpaper_exit_split_screen, Toast.LENGTH_SHORT).show()
             onBackPressedDispatcher.onBackPressed()
         }
     }
 
     override fun onDestroy() {
-        imageEffectsRepository.destroy()
+        if (isFinishing) {
+            persistentWallpaperModelRepository.cleanup()
+            // ImageEffectsRepositoryImpl is Activity-Retained Scoped, and its injected
+            // EffectsController is Singleton scoped. Therefore, persist state on config change
+            // restart, and only destroy when activity is finishing.
+            imageEffectsRepository.destroy()
+        }
         creativeEffectsRepository.destroy()
         liveWallpaperDownloader.cleanup()
         // TODO(b/333879532): Only disconnect when leaving the Activity without introducing black
@@ -174,24 +211,11 @@ class WallpaperPreviewActivity :
         // TODO(b/328302105): MainScope ensures the job gets done non-blocking even if the
         //   activity has been destroyed already. Consider making this part of
         //   WallpaperConnectionUtils.
-        (wallpaperPreviewViewModel.wallpaper.value as? WallpaperModel.LiveWallpaperModel)?.let {
-            // Keep a copy of current wallpaperPreviewViewModel.wallpaperDisplaySize as what we want
-            // to disconnect. There's a chance mainScope executes the job not until new activity
-            // is created and the wallpaperDisplaySize is updated to a new one, e.g. when
-            // orientation changed.
-            // TODO(b/328302105): maintain this state in WallpaperConnectionUtils.
-            val currentWallpaperDisplay = wallpaperPreviewViewModel.wallpaperDisplaySize.value
-            mainScope.launch {
-                WallpaperConnectionUtils.disconnect(
-                    appContext,
-                    it,
-                    wallpaperPreviewViewModel.smallerDisplaySize
-                )
-                WallpaperConnectionUtils.disconnect(
-                    appContext,
-                    it,
-                    currentWallpaperDisplay,
-                )
+        mainScope.launch { wallpaperConnectionUtils.disconnectAll(appContext) }
+
+        refreshCreativeCategories?.let {
+            if (it) {
+                categoriesViewModel.refreshCategory()
             }
         }
 
@@ -203,12 +227,99 @@ class WallpaperPreviewActivity :
     }
 
     companion object {
+        /**
+         * Returns a new [Intent] for the new picker UI that can be used to start
+         * [WallpaperPreviewActivity].
+         *
+         * @param context application context.
+         * @param isNewTask true to launch at a new task.
+         */
+        fun newIntent(
+            context: Context,
+            isAssetIdPresent: Boolean,
+            isViewAsHome: Boolean = false,
+            isNewTask: Boolean = false,
+        ): Intent {
+            val isNewPickerUi = BaseFlags.get().isNewPickerUi()
+            val isCategoriesRefactorEnabled =
+                BaseFlags.get().isWallpaperCategoryRefactoringEnabled()
+            if (!(isNewPickerUi || isCategoriesRefactorEnabled))
+                throw UnsupportedOperationException()
+            val intent = Intent(context.applicationContext, WallpaperPreviewActivity::class.java)
+            if (isNewTask) {
+                intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
+            }
+            intent.putExtra(IS_ASSET_ID_PRESENT, isAssetIdPresent)
+            intent.putExtra(EXTRA_VIEW_AS_HOME, isViewAsHome)
+            intent.putExtra(IS_NEW_TASK, isNewTask)
+            return intent
+        }
+
+        /**
+         * Returns a new [Intent] for the new picker UI that can be used to start
+         * [WallpaperPreviewActivity].
+         *
+         * @param context application context.
+         * @param isNewTask true to launch at a new task.
+         * @param shouldCategoryRefresh specified the category type
+         */
+        fun newIntent(
+            context: Context,
+            isAssetIdPresent: Boolean,
+            isViewAsHome: Boolean = false,
+            isNewTask: Boolean = false,
+            shouldCategoryRefresh: Boolean
+        ): Intent {
+            val isNewPickerUi = BaseFlags.get().isNewPickerUi()
+            val isCategoriesRefactorEnabled =
+                BaseFlags.get().isWallpaperCategoryRefactoringEnabled()
+            if (!(isNewPickerUi || isCategoriesRefactorEnabled))
+                throw UnsupportedOperationException()
+            val intent = Intent(context.applicationContext, WallpaperPreviewActivity::class.java)
+            if (isNewTask) {
+                intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
+            }
+            intent.putExtra(IS_ASSET_ID_PRESENT, isAssetIdPresent)
+            intent.putExtra(EXTRA_VIEW_AS_HOME, isViewAsHome)
+            intent.putExtra(IS_NEW_TASK, isNewTask)
+            intent.putExtra(SHOULD_CATEGORY_REFRESH, shouldCategoryRefresh)
+            return intent
+        }
+
+        /**
+         * Returns a new [Intent] that can be used to start [WallpaperPreviewActivity].
+         *
+         * @param context application context.
+         * @param wallpaperInfo selected by user for editing preview.
+         * @param isNewTask true to launch at a new task.
+         *
+         * TODO(b/291761856): Use wallpaper model to replace wallpaper info.
+         */
+        fun newIntent(
+            context: Context,
+            wallpaperInfo: WallpaperInfo,
+            isAssetIdPresent: Boolean,
+            isViewAsHome: Boolean = false,
+            isNewTask: Boolean = false,
+        ): Intent {
+            val intent = Intent(context.applicationContext, WallpaperPreviewActivity::class.java)
+            if (isNewTask) {
+                intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
+            }
+            intent.putExtra(EXTRA_WALLPAPER_INFO, wallpaperInfo)
+            intent.putExtra(IS_ASSET_ID_PRESENT, isAssetIdPresent)
+            intent.putExtra(EXTRA_VIEW_AS_HOME, isViewAsHome)
+            intent.putExtra(IS_NEW_TASK, isNewTask)
+            return intent
+        }
+
         /**
          * Returns a new [Intent] that can be used to start [WallpaperPreviewActivity].
          *
          * @param context application context.
          * @param wallpaperInfo selected by user for editing preview.
          * @param isNewTask true to launch at a new task.
+         * @param shouldRefreshCategory specifies the type of category this wallpaper belongs
          *
          * TODO(b/291761856): Use wallpaper model to replace wallpaper info.
          */
@@ -218,6 +329,7 @@ class WallpaperPreviewActivity :
             isAssetIdPresent: Boolean,
             isViewAsHome: Boolean = false,
             isNewTask: Boolean = false,
+            shouldRefreshCategory: Boolean
         ): Intent {
             val intent = Intent(context.applicationContext, WallpaperPreviewActivity::class.java)
             if (isNewTask) {
@@ -227,6 +339,7 @@ class WallpaperPreviewActivity :
             intent.putExtra(IS_ASSET_ID_PRESENT, isAssetIdPresent)
             intent.putExtra(EXTRA_VIEW_AS_HOME, isViewAsHome)
             intent.putExtra(IS_NEW_TASK, isNewTask)
+            intent.putExtra(SHOULD_CATEGORY_REFRESH, shouldRefreshCategory)
             return intent
         }
 
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewPagerBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewPagerBinder.kt
index 3ea193f5..948923f6 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewPagerBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewPagerBinder.kt
@@ -18,6 +18,7 @@ package com.android.wallpaper.picker.preview.ui.binder
 import android.content.Context
 import android.view.View
 import android.view.View.OVER_SCROLL_NEVER
+import androidx.constraintlayout.motion.widget.MotionLayout
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
@@ -34,6 +35,8 @@ import com.android.wallpaper.picker.preview.ui.view.adapters.DualPreviewPagerAda
 import com.android.wallpaper.picker.preview.ui.viewmodel.FullPreviewConfigViewModel
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
 import com.android.wallpaper.util.RtlUtils
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
+import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.DisposableHandle
 import kotlinx.coroutines.launch
 
@@ -43,12 +46,14 @@ object DualPreviewPagerBinder {
     fun bind(
         dualPreviewView: DualPreviewViewPager,
         wallpaperPreviewViewModel: WallpaperPreviewViewModel,
+        motionLayout: MotionLayout?,
         applicationContext: Context,
         viewLifecycleOwner: LifecycleOwner,
         currentNavDestId: Int,
         transition: Transition?,
         transitionConfig: FullPreviewConfigViewModel?,
-        isFirstBinding: Boolean,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
         navigate: (View) -> Unit,
     ) {
         // ViewPager & PagerAdapter do not support RTL. Enable RTL compatibility by converting all
@@ -98,7 +103,7 @@ object DualPreviewPagerBinder {
             view.tag = positionLTR
 
             PreviewTooltipBinder.bindSmallPreviewTooltip(
-                tooltipStub = view.requireViewById(R.id.tooltip_stub),
+                tooltipStub = view.requireViewById(R.id.small_preview_tooltip_stub),
                 viewModel = wallpaperPreviewViewModel.smallTooltipViewModel,
                 lifecycleOwner = viewLifecycleOwner,
             )
@@ -121,6 +126,7 @@ object DualPreviewPagerBinder {
                     SmallPreviewBinder.bind(
                         applicationContext = applicationContext,
                         view = dualDisplayAspectRatioLayout.requireViewById(display.getViewId()),
+                        motionLayout = motionLayout,
                         viewModel = wallpaperPreviewViewModel,
                         viewLifecycleOwner = viewLifecycleOwner,
                         screen = wallpaperPreviewViewModel.smallPreviewTabs[positionLTR],
@@ -129,7 +135,8 @@ object DualPreviewPagerBinder {
                         currentNavDestId = currentNavDestId,
                         transition = transition,
                         transitionConfig = transitionConfig,
-                        isFirstBinding = isFirstBinding,
+                        wallpaperConnectionUtils = wallpaperConnectionUtils,
+                        isFirstBindingDeferred = isFirstBindingDeferred,
                         navigate = navigate,
                     )
                 }
@@ -148,7 +155,7 @@ object DualPreviewPagerBinder {
                 override fun onPageScrolled(
                     position: Int,
                     positionOffset: Float,
-                    positionOffsetPixels: Int
+                    positionOffsetPixels: Int,
                 ) {}
 
                 override fun onPageScrollStateChanged(state: Int) {}
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewSelectorBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewSelectorBinder.kt
index 4ed050bf..8942a69c 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewSelectorBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewSelectorBinder.kt
@@ -17,12 +17,15 @@ package com.android.wallpaper.picker.preview.ui.binder
 
 import android.content.Context
 import android.view.View
+import androidx.constraintlayout.motion.widget.MotionLayout
 import androidx.lifecycle.LifecycleOwner
 import androidx.transition.Transition
 import com.android.wallpaper.picker.preview.ui.view.DualPreviewViewPager
 import com.android.wallpaper.picker.preview.ui.view.PreviewTabs
 import com.android.wallpaper.picker.preview.ui.viewmodel.FullPreviewConfigViewModel
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
+import kotlinx.coroutines.CompletableDeferred
 
 /**
  * This binder binds the data and view models for the dual preview collection on the small preview
@@ -31,29 +34,33 @@ import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewMod
 object DualPreviewSelectorBinder {
 
     fun bind(
-        tabs: PreviewTabs,
+        tabs: PreviewTabs?,
         dualPreviewView: DualPreviewViewPager,
+        motionLayout: MotionLayout?,
         wallpaperPreviewViewModel: WallpaperPreviewViewModel,
         applicationContext: Context,
         viewLifecycleOwner: LifecycleOwner,
         currentNavDestId: Int,
         transition: Transition?,
         transitionConfig: FullPreviewConfigViewModel?,
-        isFirstBinding: Boolean,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
         navigate: (View) -> Unit,
     ) {
         DualPreviewPagerBinder.bind(
             dualPreviewView,
             wallpaperPreviewViewModel,
+            motionLayout,
             applicationContext,
             viewLifecycleOwner,
             currentNavDestId,
             transition,
             transitionConfig,
-            isFirstBinding,
+            wallpaperConnectionUtils,
+            isFirstBindingDeferred,
             navigate,
         )
 
-        TabsBinder.bind(tabs, wallpaperPreviewViewModel, viewLifecycleOwner)
+        tabs?.let { TabsBinder.bind(it, wallpaperPreviewViewModel, viewLifecycleOwner) }
     }
 }
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/FullWallpaperPreviewBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/FullWallpaperPreviewBinder.kt
index 34dfd78a..e46cfdf5 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/FullWallpaperPreviewBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/FullWallpaperPreviewBinder.kt
@@ -25,7 +25,6 @@ import android.view.SurfaceHolder
 import android.view.SurfaceView
 import android.view.View
 import android.widget.FrameLayout
-import android.widget.ImageView
 import androidx.cardview.widget.CardView
 import androidx.core.view.doOnLayout
 import androidx.core.view.isVisible
@@ -42,18 +41,17 @@ import com.android.wallpaper.picker.data.WallpaperModel
 import com.android.wallpaper.picker.preview.shared.model.CropSizeModel
 import com.android.wallpaper.picker.preview.shared.model.FullPreviewCropModel
 import com.android.wallpaper.picker.preview.ui.util.SubsamplingScaleImageViewUtil.setOnNewCropListener
-import com.android.wallpaper.picker.preview.ui.util.SurfaceViewUtil
-import com.android.wallpaper.picker.preview.ui.util.SurfaceViewUtil.attachView
 import com.android.wallpaper.picker.preview.ui.view.FullPreviewFrameLayout
+import com.android.wallpaper.picker.preview.ui.view.SystemScaledSubsamplingScaleImageView
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
 import com.android.wallpaper.util.DisplayUtils
-import com.android.wallpaper.util.RtlUtils.isRtl
+import com.android.wallpaper.util.SurfaceViewUtils
 import com.android.wallpaper.util.WallpaperCropUtils
 import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
-import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils.shouldEnforceSingleEngine
-import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils.Companion.shouldEnforceSingleEngine
 import java.lang.Integer.min
 import kotlin.math.max
+import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.DisposableHandle
 import kotlinx.coroutines.Job
 import kotlinx.coroutines.launch
@@ -69,9 +67,11 @@ object FullWallpaperPreviewBinder {
         displayUtils: DisplayUtils,
         lifecycleOwner: LifecycleOwner,
         savedInstanceState: Bundle?,
-        isFirstBinding: Boolean,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
         onWallpaperLoaded: ((Boolean) -> Unit)? = null,
     ) {
+        val surfaceView: SurfaceView = view.requireViewById(R.id.wallpaper_surface)
         val wallpaperPreviewCrop: FullPreviewFrameLayout =
             view.requireViewById(R.id.wallpaper_preview_crop)
         val previewCard: CardView = view.requireViewById(R.id.preview_card)
@@ -83,15 +83,13 @@ object FullWallpaperPreviewBinder {
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                 viewModel.fullWallpaper.collect { (_, _, displaySize, _) ->
                     val currentSize = displayUtils.getRealSize(checkNotNull(view.context.display))
-                    wallpaperPreviewCrop.setCurrentAndTargetDisplaySize(
-                        currentSize,
-                        displaySize,
-                    )
+                    wallpaperPreviewCrop.setCurrentAndTargetDisplaySize(currentSize, displaySize)
 
                     val setFinalPreviewCardRadiusAndEndLoading = { isWallpaperFullScreen: Boolean ->
                         if (isWallpaperFullScreen) {
                             previewCard.radius = 0f
                         }
+                        surfaceView.cornerRadius = previewCard.radius
                         scrimView.isVisible = isWallpaperFullScreen
                         onWallpaperLoaded?.invoke(isWallpaperFullScreen)
                     }
@@ -129,7 +127,6 @@ object FullWallpaperPreviewBinder {
             }
             transitionDisposableHandle?.dispose()
         }
-        val surfaceView: SurfaceView = view.requireViewById(R.id.wallpaper_surface)
         val surfaceTouchForwardingLayout: TouchForwardingLayout =
             view.requireViewById(R.id.touch_forwarding_layout)
 
@@ -148,7 +145,7 @@ object FullWallpaperPreviewBinder {
                         surfaceTouchForwardingLayout.contentDescription =
                             surfaceTouchForwardingLayout.context.getString(
                                 R.string.preview_screen_description_editable,
-                                descriptionString
+                                descriptionString,
                             )
                     }
                 }
@@ -157,11 +154,11 @@ object FullWallpaperPreviewBinder {
             surfaceTouchForwardingLayout.contentDescription =
                 surfaceTouchForwardingLayout.context.getString(
                     R.string.preview_screen_description_editable,
-                    ""
+                    "",
                 )
         }
 
-        var surfaceCallback: SurfaceViewUtil.SurfaceCallback? = null
+        var surfaceCallback: SurfaceViewUtils.SurfaceCallback? = null
         lifecycleOwner.lifecycleScope.launch {
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.CREATED) {
                 surfaceCallback =
@@ -171,7 +168,8 @@ object FullWallpaperPreviewBinder {
                         surfaceTouchForwardingLayout = surfaceTouchForwardingLayout,
                         viewModel = viewModel,
                         lifecycleOwner = lifecycleOwner,
-                        isFirstBinding = isFirstBinding,
+                        wallpaperConnectionUtils = wallpaperConnectionUtils,
+                        isFirstBindingDeferred = isFirstBindingDeferred,
                     )
                 surfaceView.setZOrderMediaOverlay(true)
                 surfaceView.holder.addCallback(surfaceCallback)
@@ -195,13 +193,12 @@ object FullWallpaperPreviewBinder {
         surfaceTouchForwardingLayout: TouchForwardingLayout,
         viewModel: WallpaperPreviewViewModel,
         lifecycleOwner: LifecycleOwner,
-        isFirstBinding: Boolean,
-    ): SurfaceViewUtil.SurfaceCallback {
-        return object : SurfaceViewUtil.SurfaceCallback {
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
+    ): SurfaceViewUtils.SurfaceCallback {
+        return object : SurfaceViewUtils.SurfaceCallback {
 
             var job: Job? = null
-            var surfaceOrigWidth: Int? = null
-            var surfaceOrigHeight: Int? = null
 
             // Suppress lint warning for setting on touch listener to a live wallpaper surface view.
             // This is because the touch effect on a live wallpaper is purely visual, instead of
@@ -214,25 +211,25 @@ object FullWallpaperPreviewBinder {
                             (wallpaper, config, displaySize, allowUserCropping, whichPreview) ->
                             if (wallpaper is WallpaperModel.LiveWallpaperModel) {
                                 val engineRenderingConfig =
-                                    WallpaperConnectionUtils.EngineRenderingConfig(
+                                    WallpaperConnectionUtils.Companion.EngineRenderingConfig(
                                         wallpaper.shouldEnforceSingleEngine(),
                                         config.deviceDisplayType,
                                         viewModel.smallerDisplaySize,
                                         displaySize,
                                     )
-                                WallpaperConnectionUtils.connect(
+                                wallpaperConnectionUtils.connect(
                                     applicationContext,
                                     wallpaper,
                                     whichPreview,
                                     viewModel.getWallpaperPreviewSource().toFlag(),
                                     surfaceView,
                                     engineRenderingConfig,
-                                    isFirstBinding,
+                                    isFirstBindingDeferred,
                                 )
                                 surfaceTouchForwardingLayout.initTouchForwarding(surfaceView)
                                 surfaceView.setOnTouchListener { _, event ->
                                     lifecycleOwner.lifecycleScope.launch {
-                                        WallpaperConnectionUtils.dispatchTouchEvent(
+                                        wallpaperConnectionUtils.dispatchTouchEvent(
                                             wallpaper,
                                             engineRenderingConfig,
                                             event,
@@ -244,20 +241,20 @@ object FullWallpaperPreviewBinder {
                                 val preview =
                                     LayoutInflater.from(applicationContext)
                                         .inflate(R.layout.fullscreen_wallpaper_preview, null)
-                                adjustSizeAndAttachPreview(
-                                    applicationContext,
-                                    surfaceOrigWidth
-                                        ?: surfaceView.width.also { surfaceOrigWidth = it },
-                                    surfaceOrigHeight
-                                        ?: surfaceView.height.also { surfaceOrigHeight = it },
-                                    surfaceView,
-                                    preview,
-                                )
 
                                 val fullResImageView =
-                                    preview.requireViewById<SubsamplingScaleImageView>(
+                                    preview.requireViewById<SystemScaledSubsamplingScaleImageView>(
                                         R.id.full_res_image
                                     )
+                                // Bind static wallpaper
+                                StaticWallpaperPreviewBinder.bind(
+                                    staticPreviewView = preview,
+                                    wallpaperSurface = surfaceView,
+                                    viewModel = viewModel.staticWallpaperPreviewViewModel,
+                                    displaySize = displaySize,
+                                    parentCoroutineScope = this,
+                                    isFullScreen = true,
+                                )
                                 fullResImageView.doOnLayout {
                                     val imageSize =
                                         Point(fullResImageView.width, fullResImageView.height)
@@ -267,7 +264,7 @@ object FullWallpaperPreviewBinder {
                                             max(imageSize.x, imageSize.y),
                                             min(imageSize.x, imageSize.y),
                                             imageSize.x,
-                                            imageSize.y
+                                            imageSize.y,
                                         )
                                     fullResImageView.setOnNewCropListener { crop, zoom ->
                                         viewModel.staticWallpaperPreviewViewModel
@@ -283,8 +280,6 @@ object FullWallpaperPreviewBinder {
                                             )
                                     }
                                 }
-                                val lowResImageView =
-                                    preview.requireViewById<ImageView>(R.id.low_res_image)
 
                                 // We do not allow users to pinch to crop if it is a
                                 // downloadable wallpaper.
@@ -293,16 +288,6 @@ object FullWallpaperPreviewBinder {
                                         fullResImageView
                                     )
                                 }
-
-                                // Bind static wallpaper
-                                StaticWallpaperPreviewBinder.bind(
-                                    lowResImageView = lowResImageView,
-                                    fullResImageView = fullResImageView,
-                                    viewModel = viewModel.staticWallpaperPreviewViewModel,
-                                    displaySize = displaySize,
-                                    parentCoroutineScope = this,
-                                    isFullScreen = true,
-                                )
                             }
                         }
                     }
@@ -322,48 +307,6 @@ object FullWallpaperPreviewBinder {
         }
     }
 
-    // When showing full screen, we set the parent SurfaceView to be bigger than the image by N
-    // percent (usually 10%) as given by getSystemWallpaperMaximumScale. This ensures that no matter
-    // what scale and pan is set by the user, at least N% of the source image in the preview will be
-    // preserved around the visible crop. This is needed for system zoom out animations.
-    private fun adjustSizeAndAttachPreview(
-        applicationContext: Context,
-        origWidth: Int,
-        origHeight: Int,
-        surfaceView: SurfaceView,
-        preview: View,
-    ) {
-        val scale = WallpaperCropUtils.getSystemWallpaperMaximumScale(applicationContext)
-
-        val width = (origWidth * scale).toInt()
-        val height = (origHeight * scale).toInt()
-        val left =
-            ((origWidth - width) / 2).let {
-                if (isRtl(applicationContext)) {
-                    -it
-                } else {
-                    it
-                }
-            }
-        val top = (origHeight - height) / 2
-
-        val params = surfaceView.layoutParams
-        params.width = width
-        params.height = height
-        surfaceView.x = left.toFloat()
-        surfaceView.y = top.toFloat()
-        surfaceView.layoutParams = params
-        surfaceView.requestLayout()
-
-        preview.measure(
-            View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
-            View.MeasureSpec.makeMeasureSpec(height, View.MeasureSpec.EXACTLY)
-        )
-        preview.layout(0, 0, width, height)
-
-        surfaceView.attachView(preview, width, height)
-    }
-
     private fun TouchForwardingLayout.initTouchForwarding(targetView: View) {
         // Make sure the touch forwarding layout same size of the target view
         layoutParams = FrameLayout.LayoutParams(targetView.width, targetView.height, Gravity.CENTER)
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/PreviewActionsBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/PreviewActionsBinder.kt
index 0737b4dc..dfab6e81 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/PreviewActionsBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/PreviewActionsBinder.kt
@@ -21,12 +21,15 @@ import android.net.Uri
 import android.view.View
 import android.widget.Toast
 import androidx.activity.OnBackPressedCallback
+import androidx.constraintlayout.motion.widget.MotionLayout
+import androidx.core.view.isInvisible
 import androidx.fragment.app.FragmentActivity
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
 import com.android.wallpaper.R
+import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.model.wallpaper.DeviceDisplayType
 import com.android.wallpaper.module.logging.UserEventLogger
 import com.android.wallpaper.picker.preview.ui.util.ImageEffectDialogUtil
@@ -53,6 +56,7 @@ object PreviewActionsBinder {
     fun bind(
         actionGroup: PreviewActionGroup,
         floatingSheet: PreviewActionFloatingSheet,
+        motionLayout: MotionLayout? = null,
         previewViewModel: WallpaperPreviewViewModel,
         actionsViewModel: PreviewActionsViewModel,
         deviceDisplayType: DeviceDisplayType,
@@ -72,13 +76,31 @@ object PreviewActionsBinder {
         val floatingSheetCallback =
             object : BottomSheetBehavior.BottomSheetCallback() {
                 override fun onStateChanged(view: View, newState: Int) {
+                    // We set visibility to invisible, instead of gone because we listen to the
+                    // state change of the BottomSheet and the state change callbacks are only fired
+                    // when the view is not gone.
                     if (newState == STATE_HIDDEN) {
                         actionsViewModel.onFloatingSheetCollapsed()
+                        if (BaseFlags.get().isNewPickerUi()) motionLayout?.transitionToStart()
+                        else floatingSheet.isInvisible = true
+                    } else {
+                        if (BaseFlags.get().isNewPickerUi()) motionLayout?.transitionToEnd()
+                        else floatingSheet.isInvisible = false
                     }
                 }
 
                 override fun onSlide(p0: View, p1: Float) {}
             }
+        val noActionChecked = !actionsViewModel.isAnyActionChecked()
+        if (BaseFlags.get().isNewPickerUi()) {
+            if (noActionChecked) {
+                motionLayout?.transitionToStart()
+            } else {
+                motionLayout?.transitionToEnd()
+            }
+        } else {
+            floatingSheet.isInvisible = noActionChecked
+        }
         floatingSheet.addFloatingSheetCallback(floatingSheetCallback)
         lifecycleOwner.lifecycleScope.launch {
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.CREATED) {
@@ -124,11 +146,7 @@ object PreviewActionsBinder {
                         actionGroup.setClickListener(
                             DOWNLOAD,
                             if (it) {
-                                {
-                                    lifecycleOwner.lifecycleScope.launch {
-                                        actionsViewModel.downloadWallpaper()
-                                    }
-                                }
+                                { actionsViewModel.downloadWallpaper() }
                             } else null,
                         )
                     }
@@ -162,7 +180,7 @@ object PreviewActionsBinder {
                                     appContext.contentResolver.delete(
                                         viewModel.creativeWallpaperDeleteUri,
                                         null,
-                                        null
+                                        null,
                                     )
                                 } else if (viewModel.liveWallpaperDeleteIntent != null) {
                                     appContext.startService(viewModel.liveWallpaperDeleteIntent)
@@ -209,7 +227,7 @@ object PreviewActionsBinder {
                                     )
                                     onNavigateToEditScreen.invoke(it)
                                 }
-                            } else null
+                            } else null,
                         )
                     }
                 }
@@ -307,7 +325,7 @@ object PreviewActionsBinder {
                                 object : OnBackPressedCallback(true) {
                                         override fun handleOnBackPressed() {
                                             val handled = handleOnBackPressed()
-                                            if(!handled) {
+                                            if (!handled) {
                                                 onBackPressedCallback?.remove()
                                                 onBackPressedCallback = null
                                                 activity.onBackPressedDispatcher.onBackPressed()
@@ -331,7 +349,7 @@ object PreviewActionsBinder {
                             SHARE,
                             if (it != null) {
                                 { onStartShareActivity.invoke(it) }
-                            } else null
+                            } else null,
                         )
                     }
                 }
@@ -351,7 +369,7 @@ object PreviewActionsBinder {
                                 informationViewModel != null -> {
                                     floatingSheet.setInformationContent(
                                         informationViewModel.attributions,
-                                        informationViewModel.exploreActionUrl?.let { url ->
+                                        informationViewModel.actionUrl?.let { url ->
                                             {
                                                 logger.logWallpaperExploreButtonClicked()
                                                 floatingSheet.context.startActivity(
@@ -359,6 +377,7 @@ object PreviewActionsBinder {
                                                 )
                                             }
                                         },
+                                        informationViewModel.actionButtonTitle,
                                     )
                                 }
                                 imageEffectViewModel != null ->
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/PreviewPagerBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/PreviewPagerBinder.kt
index 29328967..8b7d3d8a 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/PreviewPagerBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/PreviewPagerBinder.kt
@@ -19,6 +19,8 @@ import android.annotation.SuppressLint
 import android.content.Context
 import android.graphics.Point
 import android.view.View
+import androidx.constraintlayout.motion.widget.MotionLayout
+import androidx.core.view.doOnLayout
 import androidx.core.view.doOnPreDraw
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
@@ -28,11 +30,15 @@ import androidx.recyclerview.widget.RecyclerView
 import androidx.transition.Transition
 import androidx.viewpager2.widget.ViewPager2
 import com.android.wallpaper.R
+import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.model.wallpaper.DeviceDisplayType
+import com.android.wallpaper.picker.customization.ui.view.transformer.PreviewPagerPageTransformer
 import com.android.wallpaper.picker.preview.ui.view.adapters.SinglePreviewPagerAdapter
 import com.android.wallpaper.picker.preview.ui.view.pagetransformers.PreviewCardPageTransformer
 import com.android.wallpaper.picker.preview.ui.viewmodel.FullPreviewConfigViewModel
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
+import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.launch
 
 /** Binds single preview home screen and lock screen tabs view pager. */
@@ -42,19 +48,22 @@ object PreviewPagerBinder {
     fun bind(
         applicationContext: Context,
         viewLifecycleOwner: LifecycleOwner,
+        motionLayout: MotionLayout?,
         previewsViewPager: ViewPager2,
         wallpaperPreviewViewModel: WallpaperPreviewViewModel,
         previewDisplaySize: Point,
         currentNavDestId: Int,
         transition: Transition?,
         transitionConfig: FullPreviewConfigViewModel?,
-        isFirstBinding: Boolean,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
         navigate: (View) -> Unit,
     ) {
         previewsViewPager.apply {
             adapter = SinglePreviewPagerAdapter { viewHolder, position ->
                 PreviewTooltipBinder.bindSmallPreviewTooltip(
-                    tooltipStub = viewHolder.itemView.requireViewById(R.id.tooltip_stub),
+                    tooltipStub =
+                        viewHolder.itemView.requireViewById(R.id.small_preview_tooltip_stub),
                     viewModel = wallpaperPreviewViewModel.smallTooltipViewModel,
                     lifecycleOwner = viewLifecycleOwner,
                 )
@@ -62,6 +71,7 @@ object PreviewPagerBinder {
                 SmallPreviewBinder.bind(
                     applicationContext = applicationContext,
                     view = viewHolder.itemView.requireViewById(R.id.preview),
+                    motionLayout = motionLayout,
                     viewModel = wallpaperPreviewViewModel,
                     screen = wallpaperPreviewViewModel.smallPreviewTabs[position],
                     displaySize = previewDisplaySize,
@@ -70,22 +80,39 @@ object PreviewPagerBinder {
                     currentNavDestId = currentNavDestId,
                     transition = transition,
                     transitionConfig = transitionConfig,
-                    isFirstBinding = isFirstBinding,
+                    isFirstBindingDeferred = isFirstBindingDeferred,
+                    wallpaperConnectionUtils = wallpaperConnectionUtils,
                     navigate = navigate,
                 )
             }
             offscreenPageLimit = SinglePreviewPagerAdapter.PREVIEW_PAGER_ITEM_COUNT
-            setPageTransformer(PreviewCardPageTransformer(previewDisplaySize))
+            // the over scroll animation needs to be disabled for the RecyclerView that is contained
+            // in the ViewPager2 rather than the ViewPager2 itself
+            val child: View = getChildAt(0)
+            if (child is RecyclerView) {
+                child.overScrollMode = View.OVER_SCROLL_NEVER
+                // Remove clip children to enable child card view to display fully during scaling
+                // shared element transition.
+                child.clipChildren = false
+            }
+
+            // When pager's height changes, request transform to recalculate the preview offset
+            // to make sure correct space between the previews.
+            // TODO (b/348462236): figure out how to scale surface view content with layout change
+            addOnLayoutChangeListener { view, _, _, _, _, _, topWas, _, bottomWas ->
+                val isHeightChanged = (bottomWas - topWas) != view.height
+                if (isHeightChanged) {
+                    requestTransform()
+                }
+            }
         }
 
-        // the over scroll animation needs to be disabled for the RecyclerView that is contained in
-        // the ViewPager2 rather than the ViewPager2 itself
-        val child: View = previewsViewPager.getChildAt(0)
-        if (child is RecyclerView) {
-            child.overScrollMode = View.OVER_SCROLL_NEVER
-            // Remove clip children to enable child card view to display fully during scaling shared
-            // element transition.
-            child.clipChildren = false
+        // Only when pager is laid out, we can get the width and set the preview's offset correctly
+        previewsViewPager.doOnLayout {
+            val pageTransformer =
+                if (BaseFlags.get().isNewPickerUi()) PreviewPagerPageTransformer(previewDisplaySize)
+                else PreviewCardPageTransformer(previewDisplaySize)
+            (it as ViewPager2).setPageTransformer(pageTransformer)
         }
 
         // Wrap in doOnPreDraw for emoji wallpaper creation case, to make sure recycler view with
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/PreviewSelectorBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/PreviewSelectorBinder.kt
index 1bf714f0..819e9600 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/PreviewSelectorBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/PreviewSelectorBinder.kt
@@ -18,19 +18,23 @@ package com.android.wallpaper.picker.preview.ui.binder
 import android.content.Context
 import android.graphics.Point
 import android.view.View
+import androidx.constraintlayout.motion.widget.MotionLayout
 import androidx.lifecycle.LifecycleOwner
 import androidx.transition.Transition
 import androidx.viewpager2.widget.ViewPager2
 import com.android.wallpaper.picker.preview.ui.view.PreviewTabs
 import com.android.wallpaper.picker.preview.ui.viewmodel.FullPreviewConfigViewModel
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
+import kotlinx.coroutines.CompletableDeferred
 
 /** Binds and synchronizes the tab and preview view pagers. */
 object PreviewSelectorBinder {
 
     fun bind(
-        tabs: PreviewTabs,
+        tabs: PreviewTabs?,
         previewsViewPager: ViewPager2,
+        motionLayout: MotionLayout?,
         previewDisplaySize: Point,
         wallpaperPreviewViewModel: WallpaperPreviewViewModel,
         applicationContext: Context,
@@ -38,23 +42,26 @@ object PreviewSelectorBinder {
         currentNavDestId: Int,
         transition: Transition?,
         transitionConfig: FullPreviewConfigViewModel?,
-        isFirstBinding: Boolean,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
         navigate: (View) -> Unit,
     ) {
         // set up previews view pager
         PreviewPagerBinder.bind(
             applicationContext,
             viewLifecycleOwner,
+            motionLayout,
             previewsViewPager,
             wallpaperPreviewViewModel,
             previewDisplaySize,
             currentNavDestId,
             transition,
             transitionConfig,
-            isFirstBinding,
+            wallpaperConnectionUtils,
+            isFirstBindingDeferred,
             navigate,
         )
 
-        TabsBinder.bind(tabs, wallpaperPreviewViewModel, viewLifecycleOwner)
+        tabs?.let { TabsBinder.bind(it, wallpaperPreviewViewModel, viewLifecycleOwner) }
     }
 }
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/SetWallpaperDialogBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/SetWallpaperDialogBinder.kt
index ba5f8a02..ff82bfdd 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/SetWallpaperDialogBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/SetWallpaperDialogBinder.kt
@@ -31,6 +31,8 @@ import com.android.wallpaper.model.wallpaper.DeviceDisplayType
 import com.android.wallpaper.picker.preview.ui.view.DualDisplayAspectRatioLayout
 import com.android.wallpaper.picker.preview.ui.view.DualDisplayAspectRatioLayout.Companion.getViewId
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
+import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.launch
 
@@ -52,6 +54,7 @@ object SetWallpaperDialogBinder {
         currentNavDestId: Int,
         onFinishActivity: () -> Unit,
         onDismissDialog: () -> Unit,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
         isFirstBinding: Boolean,
         navigate: ((View) -> Unit)?,
     ) {
@@ -64,6 +67,7 @@ object SetWallpaperDialogBinder {
                 wallpaperPreviewViewModel,
                 lifecycleOwner,
                 currentNavDestId,
+                wallpaperConnectionUtils,
                 isFirstBinding,
                 navigate,
             )
@@ -74,6 +78,7 @@ object SetWallpaperDialogBinder {
                 handheldDisplaySize,
                 lifecycleOwner,
                 currentNavDestId,
+                wallpaperConnectionUtils,
                 isFirstBinding,
                 navigate,
             )
@@ -127,6 +132,7 @@ object SetWallpaperDialogBinder {
         wallpaperPreviewViewModel: WallpaperPreviewViewModel,
         lifecycleOwner: LifecycleOwner,
         currentNavDestId: Int,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
         isFirstBinding: Boolean,
         navigate: ((View) -> Unit)?,
     ) {
@@ -157,7 +163,8 @@ object SetWallpaperDialogBinder {
                         displaySize = it,
                         deviceDisplayType = display,
                         currentNavDestId = currentNavDestId,
-                        isFirstBinding = isFirstBinding,
+                        wallpaperConnectionUtils = wallpaperConnectionUtils,
+                        isFirstBindingDeferred = CompletableDeferred(isFirstBinding),
                         navigate = navigate,
                     )
                 }
@@ -171,6 +178,7 @@ object SetWallpaperDialogBinder {
         displaySize: Point,
         lifecycleOwner: LifecycleOwner,
         currentNavDestId: Int,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
         isFirstBinding: Boolean,
         navigate: ((View) -> Unit)?,
     ) {
@@ -189,7 +197,8 @@ object SetWallpaperDialogBinder {
                 deviceDisplayType = DeviceDisplayType.SINGLE,
                 viewLifecycleOwner = lifecycleOwner,
                 currentNavDestId = currentNavDestId,
-                isFirstBinding = isFirstBinding,
+                isFirstBindingDeferred = CompletableDeferred(isFirstBinding),
+                wallpaperConnectionUtils = wallpaperConnectionUtils,
                 navigate = navigate,
             )
         }
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/SetWallpaperProgressDialogBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/SetWallpaperProgressDialogBinder.kt
index 5aa2404c..b06849dd 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/SetWallpaperProgressDialogBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/SetWallpaperProgressDialogBinder.kt
@@ -16,13 +16,10 @@
 
 package com.android.wallpaper.picker.preview.ui.binder
 
-import android.app.Activity
-import android.app.AlertDialog
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
-import com.android.wallpaper.R
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
 import kotlinx.coroutines.launch
 
@@ -31,36 +28,17 @@ object SetWallpaperProgressDialogBinder {
 
     fun bind(
         viewModel: WallpaperPreviewViewModel,
-        activity: Activity,
         lifecycleOwner: LifecycleOwner,
+        onShowDialog: (Boolean) -> Unit,
     ) {
-        var setWallpaperProgressDialog: AlertDialog? = null
-
         lifecycleOwner.lifecycleScope.launch {
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                 launch {
                     viewModel.isSetWallpaperProgressBarVisible.collect { visible ->
-                        if (visible) {
-                            val dialog =
-                                setWallpaperProgressDialog
-                                    ?: createSetWallpaperProgressDialog(activity).also {
-                                        setWallpaperProgressDialog = it
-                                    }
-                            dialog.show()
-                        } else {
-                            setWallpaperProgressDialog?.hide()
-                        }
+                        onShowDialog(visible)
                     }
                 }
             }
         }
     }
-
-    private fun createSetWallpaperProgressDialog(
-        activity: Activity,
-    ): AlertDialog {
-        val dialogView =
-            activity.layoutInflater.inflate(R.layout.set_wallpaper_progress_dialog_view, null)
-        return AlertDialog.Builder(activity).setView(dialogView).create()
-    }
 }
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/SmallPreviewBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/SmallPreviewBinder.kt
index 92d14c6f..19892404 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/SmallPreviewBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/SmallPreviewBinder.kt
@@ -20,6 +20,7 @@ import android.graphics.Point
 import android.view.SurfaceView
 import android.view.View
 import androidx.cardview.widget.CardView
+import androidx.constraintlayout.motion.widget.MotionLayout
 import androidx.core.view.ViewCompat
 import androidx.core.view.isVisible
 import androidx.lifecycle.Lifecycle
@@ -31,9 +32,13 @@ import androidx.transition.TransitionListenerAdapter
 import com.android.wallpaper.R
 import com.android.wallpaper.model.Screen
 import com.android.wallpaper.model.wallpaper.DeviceDisplayType
+import com.android.wallpaper.picker.common.preview.ui.view.CustomizationSurfaceView
+import com.android.wallpaper.picker.customization.ui.CustomizationPickerActivity2
 import com.android.wallpaper.picker.preview.ui.fragment.SmallPreviewFragment
 import com.android.wallpaper.picker.preview.ui.viewmodel.FullPreviewConfigViewModel
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
+import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.DisposableHandle
 import kotlinx.coroutines.launch
 
@@ -42,6 +47,7 @@ object SmallPreviewBinder {
     fun bind(
         applicationContext: Context,
         view: View,
+        motionLayout: MotionLayout? = null,
         viewModel: WallpaperPreviewViewModel,
         screen: Screen,
         displaySize: Point,
@@ -51,7 +57,8 @@ object SmallPreviewBinder {
         navigate: ((View) -> Unit)? = null,
         transition: Transition? = null,
         transitionConfig: FullPreviewConfigViewModel? = null,
-        isFirstBinding: Boolean,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
     ) {
 
         val previewCard: CardView = view.requireViewById(R.id.preview_card)
@@ -66,11 +73,28 @@ object SmallPreviewBinder {
         previewCard.contentDescription =
             view.context.getString(
                 R.string.wallpaper_preview_card_content_description_editable,
-                foldedStateDescription
+                foldedStateDescription,
             )
-        val wallpaperSurface: SurfaceView = view.requireViewById(R.id.wallpaper_surface)
+        val wallpaperSurface =
+            view.requireViewById<SurfaceView>(R.id.wallpaper_surface).apply {
+                // When putting the surface on top for full transition, the card view is behind the
+                // surface view so we need to apply radius on surface view instead
+                cornerRadius = previewCard.radius
+            }
         val workspaceSurface: SurfaceView = view.requireViewById(R.id.workspace_surface)
-        var transitionDisposableHandle: DisposableHandle? = null
+
+        motionLayout?.addTransitionListener(
+            object : CustomizationPickerActivity2.EmptyTransitionListener {
+                override fun onTransitionStarted(
+                    motionLayout: MotionLayout?,
+                    startId: Int,
+                    endId: Int,
+                ) {
+                    (wallpaperSurface as CustomizationSurfaceView).setTransitioning()
+                    (workspaceSurface as CustomizationSurfaceView).setTransitioning()
+                }
+            }
+        )
 
         // Set transition names to enable the small to full preview enter and return shared
         // element transitions.
@@ -97,67 +121,67 @@ object SmallPreviewBinder {
             }
         ViewCompat.setTransitionName(previewCard, transitionName)
 
-        viewLifecycleOwner.lifecycleScope.launch {
-            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.CREATED) {
-                // All surface views are initially hidden in the XML to enable smoother
-                // transitions. Only show the surface view used in the shared element transition
-                // until the transition ends to avoid issues with multiple surface views
-                // overlapping.
-                if (transition == null || transitionConfig == null) {
-                    // If no enter or re-enter transition, show child surfaces.
-                    wallpaperSurface.isVisible = true
-                    workspaceSurface.isVisible = true
-                } else {
-                    if (
-                        transitionConfig.screen == screen &&
-                            transitionConfig.deviceDisplayType == deviceDisplayType
-                    ) {
-                        // If transitioning to the current small preview, show child surfaces when
-                        // transition starts.
-                        val listener =
-                            object : TransitionListenerAdapter() {
-                                override fun onTransitionStart(transition: Transition) {
-                                    super.onTransitionStart(transition)
-                                    wallpaperSurface.isVisible = true
-                                    workspaceSurface.isVisible = true
-                                    transition.removeListener(this)
-                                    transitionDisposableHandle = null
-                                }
-                            }
-                        transition.addListener(listener)
-                        transitionDisposableHandle = DisposableHandle {
-                            transition.removeListener(listener)
+        var transitionDisposableHandle: DisposableHandle? = null
+        val transitionListener =
+            if (transition == null || transitionConfig == null) null
+            else
+                object : TransitionListenerAdapter() {
+                    // All surface views are initially visible in the XML to enable smoother
+                    // transitions. Only hide the surface views not used in the shared element
+                    // transition until the transition ends to avoid issues with multiple surface
+                    // views
+                    // overlapping.
+                    override fun onTransitionStart(transition: Transition) {
+                        super.onTransitionStart(transition)
+                        if (
+                            transitionConfig.screen == screen &&
+                                transitionConfig.deviceDisplayType == deviceDisplayType
+                        ) {
+                            wallpaperSurface.setZOrderOnTop(true)
+                            workspaceSurface.setZOrderOnTop(true)
+                        } else {
+                            // If transitioning to another small preview, keep child surfaces hidden
+                            // until transition ends.
+                            wallpaperSurface.isVisible = false
+                            workspaceSurface.isVisible = false
                         }
-                    } else {
-                        // If transitioning to another small preview, keep child surfaces hidden
-                        // until transition ends.
-                        val listener =
-                            object : TransitionListenerAdapter() {
-                                override fun onTransitionEnd(transition: Transition) {
-                                    super.onTransitionEnd(transition)
-                                    wallpaperSurface.isVisible = true
-                                    workspaceSurface.isVisible = true
-                                    wallpaperSurface.alpha = 0f
-                                    workspaceSurface.alpha = 0f
+                    }
 
-                                    val mediumAnimTimeMs =
-                                        view.resources
-                                            .getInteger(android.R.integer.config_mediumAnimTime)
-                                            .toLong()
-                                    wallpaperSurface.startFadeInAnimation(mediumAnimTimeMs)
-                                    workspaceSurface.startFadeInAnimation(mediumAnimTimeMs)
+                    override fun onTransitionEnd(transition: Transition) {
+                        super.onTransitionEnd(transition)
+                        if (
+                            transitionConfig.screen == screen &&
+                                transitionConfig.deviceDisplayType == deviceDisplayType
+                        ) {
+                            wallpaperSurface.setZOrderMediaOverlay(true)
+                            workspaceSurface.setZOrderMediaOverlay(true)
+                        } else {
+                            wallpaperSurface.isVisible = true
+                            workspaceSurface.isVisible = true
+                            wallpaperSurface.alpha = 0f
+                            workspaceSurface.alpha = 0f
 
-                                    transition.removeListener(this)
-                                    transitionDisposableHandle = null
-                                }
-                            }
-                        transition.addListener(listener)
-                        transitionDisposableHandle = DisposableHandle {
-                            transition.removeListener(listener)
+                            val mediumAnimTimeMs =
+                                view.resources
+                                    .getInteger(android.R.integer.config_mediumAnimTime)
+                                    .toLong()
+                            wallpaperSurface.startFadeInAnimation(mediumAnimTimeMs)
+                            workspaceSurface.startFadeInAnimation(mediumAnimTimeMs)
                         }
+
+                        transition.removeListener(this)
+                        transitionDisposableHandle = null
                     }
                 }
 
+        viewLifecycleOwner.lifecycleScope.launch {
+            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.CREATED) {
+                transitionListener?.let {
+                    // If transitionListener is not null so do transition and transitionConfig
+                    transition!!.addListener(it)
+                    transitionDisposableHandle = DisposableHandle { transition.removeListener(it) }
+                }
+
                 if (R.id.smallPreviewFragment == currentNavDestId) {
                     viewModel
                         .onSmallPreviewClicked(screen, deviceDisplayType) {
@@ -185,12 +209,7 @@ object SmallPreviewBinder {
         }
 
         val config = viewModel.getWorkspacePreviewConfig(screen, deviceDisplayType)
-        WorkspacePreviewBinder.bind(
-            workspaceSurface,
-            config,
-            viewModel,
-            viewLifecycleOwner,
-        )
+        WorkspacePreviewBinder.bind(workspaceSurface, config, viewModel, viewLifecycleOwner)
 
         SmallWallpaperPreviewBinder.bind(
             surface = wallpaperSurface,
@@ -199,7 +218,8 @@ object SmallPreviewBinder {
             applicationContext = applicationContext,
             viewLifecycleOwner = viewLifecycleOwner,
             deviceDisplayType = deviceDisplayType,
-            isFirstBinding = isFirstBinding,
+            wallpaperConnectionUtils = wallpaperConnectionUtils,
+            isFirstBindingDeferred = isFirstBindingDeferred,
         )
     }
 
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/SmallWallpaperPreviewBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/SmallWallpaperPreviewBinder.kt
index 25b1f126..2bc201e3 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/SmallWallpaperPreviewBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/SmallWallpaperPreviewBinder.kt
@@ -29,12 +29,13 @@ import com.android.wallpaper.R
 import com.android.wallpaper.model.wallpaper.DeviceDisplayType
 import com.android.wallpaper.picker.customization.shared.model.WallpaperColorsModel
 import com.android.wallpaper.picker.data.WallpaperModel
-import com.android.wallpaper.picker.preview.ui.util.SurfaceViewUtil
-import com.android.wallpaper.picker.preview.ui.util.SurfaceViewUtil.attachView
+import com.android.wallpaper.picker.preview.ui.view.SystemScaledSubsamplingScaleImageView
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
+import com.android.wallpaper.util.SurfaceViewUtils
 import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
-import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils.shouldEnforceSingleEngine
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils.Companion.shouldEnforceSingleEngine
 import com.android.wallpaper.util.wallpaperconnection.WallpaperEngineConnection.WallpaperEngineConnectionListener
+import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.Job
 import kotlinx.coroutines.launch
 
@@ -55,9 +56,10 @@ object SmallWallpaperPreviewBinder {
         applicationContext: Context,
         viewLifecycleOwner: LifecycleOwner,
         deviceDisplayType: DeviceDisplayType,
-        isFirstBinding: Boolean,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
     ) {
-        var surfaceCallback: SurfaceViewUtil.SurfaceCallback? = null
+        var surfaceCallback: SurfaceViewUtils.SurfaceCallback? = null
         viewLifecycleOwner.lifecycleScope.launch {
             viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.CREATED) {
                 surfaceCallback =
@@ -68,7 +70,8 @@ object SmallWallpaperPreviewBinder {
                         deviceDisplayType = deviceDisplayType,
                         displaySize = displaySize,
                         lifecycleOwner = viewLifecycleOwner,
-                        isFirstBinding
+                        wallpaperConnectionUtils = wallpaperConnectionUtils,
+                        isFirstBindingDeferred,
                     )
                 surface.setZOrderMediaOverlay(true)
                 surfaceCallback?.let { surface.holder.addCallback(it) }
@@ -93,10 +96,11 @@ object SmallWallpaperPreviewBinder {
         deviceDisplayType: DeviceDisplayType,
         displaySize: Point,
         lifecycleOwner: LifecycleOwner,
-        isFirstBinding: Boolean,
-    ): SurfaceViewUtil.SurfaceCallback {
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
+    ): SurfaceViewUtils.SurfaceCallback {
 
-        return object : SurfaceViewUtil.SurfaceCallback {
+        return object : SurfaceViewUtils.SurfaceCallback {
 
             var job: Job? = null
             var loadingAnimationBinding: PreviewEffectsLoadingBinder.Binding? = null
@@ -106,23 +110,23 @@ object SmallWallpaperPreviewBinder {
                     lifecycleOwner.lifecycleScope.launch {
                         viewModel.smallWallpaper.collect { (wallpaper, whichPreview) ->
                             if (wallpaper is WallpaperModel.LiveWallpaperModel) {
-                                WallpaperConnectionUtils.connect(
+                                wallpaperConnectionUtils.connect(
                                     applicationContext,
                                     wallpaper,
                                     whichPreview,
                                     viewModel.getWallpaperPreviewSource().toFlag(),
                                     surface,
-                                    WallpaperConnectionUtils.EngineRenderingConfig(
+                                    WallpaperConnectionUtils.Companion.EngineRenderingConfig(
                                         wallpaper.shouldEnforceSingleEngine(),
                                         deviceDisplayType = deviceDisplayType,
                                         viewModel.smallerDisplaySize,
                                         viewModel.wallpaperDisplaySize.value,
                                     ),
-                                    isFirstBinding,
+                                    isFirstBindingDeferred,
                                     object : WallpaperEngineConnectionListener {
                                         override fun onWallpaperColorsChanged(
                                             colors: WallpaperColors?,
-                                            displayId: Int
+                                            displayId: Int,
                                         ) {
                                             viewModel.setWallpaperConnectionColors(
                                                 WallpaperColorsModel.Loaded(colors)
@@ -134,25 +138,29 @@ object SmallWallpaperPreviewBinder {
                                 val staticPreviewView =
                                     LayoutInflater.from(applicationContext)
                                         .inflate(R.layout.fullscreen_wallpaper_preview, null)
-                                surface.attachView(staticPreviewView)
+                                // We need to locate full res view because later it will be added to
+                                // the surface control nad not in the current view hierarchy.
+                                val fullResView =
+                                    staticPreviewView.requireViewById<
+                                        SystemScaledSubsamplingScaleImageView
+                                    >(
+                                        R.id.full_res_image
+                                    )
                                 // Bind static wallpaper
                                 StaticWallpaperPreviewBinder.bind(
-                                    lowResImageView =
-                                        staticPreviewView.requireViewById(R.id.low_res_image),
-                                    fullResImageView =
-                                        staticPreviewView.requireViewById(R.id.full_res_image),
+                                    staticPreviewView = staticPreviewView,
+                                    wallpaperSurface = surface,
                                     viewModel = viewModel.staticWallpaperPreviewViewModel,
                                     displaySize = displaySize,
                                     parentCoroutineScope = this,
                                 )
                                 // This is to possibly shut down all live wallpaper services
                                 // if they exist; otherwise static wallpaper can not show up.
-                                WallpaperConnectionUtils.disconnectAllServices(applicationContext)
+                                wallpaperConnectionUtils.disconnectAllServices(applicationContext)
 
                                 loadingAnimationBinding =
                                     PreviewEffectsLoadingBinder.bind(
-                                        view =
-                                            staticPreviewView.requireViewById(R.id.full_res_image),
+                                        view = fullResView,
                                         viewModel = viewModel,
                                         viewLifecycleOwner = lifecycleOwner,
                                     )
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/StaticWallpaperPreviewBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/StaticWallpaperPreviewBinder.kt
index 60ae0e0b..d62c9e32 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/StaticWallpaperPreviewBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/StaticWallpaperPreviewBinder.kt
@@ -21,6 +21,7 @@ import android.graphics.Point
 import android.graphics.Rect
 import android.graphics.RenderEffect
 import android.graphics.Shader
+import android.view.SurfaceView
 import android.view.View
 import android.view.animation.Interpolator
 import android.view.animation.PathInterpolator
@@ -28,11 +29,14 @@ import android.widget.ImageView
 import androidx.core.view.doOnLayout
 import androidx.core.view.isVisible
 import com.android.app.tracing.TraceUtils.trace
+import com.android.wallpaper.R
 import com.android.wallpaper.picker.preview.shared.model.CropSizeModel
 import com.android.wallpaper.picker.preview.shared.model.FullPreviewCropModel
 import com.android.wallpaper.picker.preview.ui.util.FullResImageViewUtil
+import com.android.wallpaper.picker.preview.ui.view.SystemScaledSubsamplingScaleImageView
 import com.android.wallpaper.picker.preview.ui.viewmodel.StaticWallpaperPreviewViewModel
 import com.android.wallpaper.util.RtlUtils
+import com.android.wallpaper.util.SurfaceViewUtils.attachView
 import com.android.wallpaper.util.WallpaperCropUtils
 import com.android.wallpaper.util.WallpaperSurfaceCallback.LOW_RES_BITMAP_BLUR_RADIUS
 import com.davemorrissey.labs.subscaleview.ImageSource
@@ -48,13 +52,30 @@ object StaticWallpaperPreviewBinder {
     private const val CROSS_FADE_DURATION: Long = 200
 
     fun bind(
-        lowResImageView: ImageView,
-        fullResImageView: SubsamplingScaleImageView,
+        staticPreviewView: View,
+        wallpaperSurface: SurfaceView,
         viewModel: StaticWallpaperPreviewViewModel,
         displaySize: Point,
         parentCoroutineScope: CoroutineScope,
         isFullScreen: Boolean = false,
     ) {
+        val fullResImageView =
+            staticPreviewView.requireViewById<SystemScaledSubsamplingScaleImageView>(
+                R.id.full_res_image
+            )
+        val lowResImageView = staticPreviewView.requireViewById<ImageView>(R.id.low_res_image)
+
+        // surfaceView.width and surfaceFrame.width here can be different,
+        // one represents the size of the view and the other represents the
+        // size of the surface. When setting a view to the surface host,
+        // we want to set it based on the surface's size not the view's size
+        adjustSizeAndAttachPreview(
+            wallpaperSurface.holder.surfaceFrame,
+            wallpaperSurface,
+            staticPreviewView,
+            fullResImageView,
+        )
+
         lowResImageView.initLowResImageView()
         fullResImageView.initFullResImageView()
 
@@ -129,7 +150,7 @@ object StaticWallpaperPreviewBinder {
             RenderEffect.createBlurEffect(
                 LOW_RES_BITMAP_BLUR_RADIUS,
                 LOW_RES_BITMAP_BLUR_RADIUS,
-                Shader.TileMode.CLAMP
+                Shader.TileMode.CLAMP,
             )
         )
     }
@@ -157,12 +178,6 @@ object StaticWallpaperPreviewBinder {
                     displaySize,
                     cropHint,
                     isRtl,
-                    systemScale =
-                        if (isFullScreen) 1f
-                        else
-                            WallpaperCropUtils.getSystemWallpaperMaximumScale(
-                                context.applicationContext,
-                            ),
                 )
                 .let { scaleAndCenter ->
                     minScale = scaleAndCenter.minScale
@@ -188,5 +203,28 @@ object StaticWallpaperPreviewBinder {
             )
     }
 
+    // When showing static wallpaper preview, we set the full res image view to be bigger than the
+    // image by N percent (usually 10%) as given by getSystemWallpaperMaximumScale via
+    // SystemScaledSubsamplingScaleImageView. This ensures that no matter what scale and pan is set
+    // by the user, at least N% of the source image in the preview will be preserved around the
+    // visible crop. This is needed for system zoom out animations.
+    private fun adjustSizeAndAttachPreview(
+        surfacePosition: Rect,
+        surfaceView: SurfaceView,
+        preview: View,
+        fullResView: SystemScaledSubsamplingScaleImageView,
+    ) {
+        val width = surfacePosition.width()
+        val height = surfacePosition.height()
+        preview.measure(
+            View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
+            View.MeasureSpec.makeMeasureSpec(height, View.MeasureSpec.EXACTLY),
+        )
+        preview.layout(0, 0, width, height)
+
+        fullResView.setSurfaceSize(Point(width, height))
+        surfaceView.attachView(fullResView, width, height)
+    }
+
     private const val TAG = "StaticWallpaperPreviewBinder"
 }
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/WorkspacePreviewBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/WorkspacePreviewBinder.kt
index d1af5831..a8a910f3 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/WorkspacePreviewBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/WorkspacePreviewBinder.kt
@@ -27,7 +27,6 @@ import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
 import com.android.wallpaper.picker.customization.shared.model.WallpaperColorsModel
-import com.android.wallpaper.picker.preview.ui.util.SurfaceViewUtil
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
 import com.android.wallpaper.picker.preview.ui.viewmodel.WorkspacePreviewConfigViewModel
 import com.android.wallpaper.util.PreviewUtils
@@ -46,7 +45,7 @@ object WorkspacePreviewBinder {
         viewModel: WallpaperPreviewViewModel,
         lifecycleOwner: LifecycleOwner,
     ) {
-        var surfaceCallback: SurfaceViewUtil.SurfaceCallback? = null
+        var surfaceCallback: SurfaceViewUtils.SurfaceCallback? = null
         lifecycleOwner.lifecycleScope.launch {
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.CREATED) {
                 surfaceCallback =
@@ -77,8 +76,8 @@ object WorkspacePreviewBinder {
         viewModel: WallpaperPreviewViewModel,
         config: WorkspacePreviewConfigViewModel,
         lifecycleOwner: LifecycleOwner,
-    ): SurfaceViewUtil.SurfaceCallback {
-        return object : SurfaceViewUtil.SurfaceCallback {
+    ): SurfaceViewUtils.SurfaceCallback {
+        return object : SurfaceViewUtils.SurfaceCallback {
 
             var job: Job? = null
             var previewDisposableHandle: DisposableHandle? = null
@@ -94,7 +93,7 @@ object WorkspacePreviewBinder {
                                         previewUtils = config.previewUtils,
                                         displayId =
                                             viewModel.getDisplayId(config.deviceDisplayType),
-                                        wallpaperColors = it.colors
+                                        wallpaperColors = it.colors,
                                     )
                                 // Dispose the previous preview on the renderer side.
                                 previewDisposableHandle?.dispose()
@@ -124,7 +123,7 @@ object WorkspacePreviewBinder {
         viewModel: WallpaperPreviewViewModel,
         lifecycleOwner: LifecycleOwner,
     ) {
-        var surfaceCallback: SurfaceViewUtil.SurfaceCallback? = null
+        var surfaceCallback: SurfaceViewUtils.SurfaceCallback? = null
         lifecycleOwner.lifecycleScope.launch {
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.CREATED) {
                 surfaceCallback =
@@ -153,8 +152,8 @@ object WorkspacePreviewBinder {
         surface: SurfaceView,
         viewModel: WallpaperPreviewViewModel,
         lifecycleOwner: LifecycleOwner,
-    ): SurfaceViewUtil.SurfaceCallback {
-        return object : SurfaceViewUtil.SurfaceCallback {
+    ): SurfaceViewUtils.SurfaceCallback {
+        return object : SurfaceViewUtils.SurfaceCallback {
 
             var job: Job? = null
             var previewDisposableHandle: DisposableHandle? = null
@@ -164,7 +163,7 @@ object WorkspacePreviewBinder {
                     lifecycleOwner.lifecycleScope.launch {
                         combine(
                                 viewModel.fullWorkspacePreviewConfigViewModel,
-                                viewModel.wallpaperColorsModel
+                                viewModel.wallpaperColorsModel,
                             ) { config, colorsModel ->
                                 config to colorsModel
                             }
@@ -176,7 +175,7 @@ object WorkspacePreviewBinder {
                                             previewUtils = config.previewUtils,
                                             displayId =
                                                 viewModel.getDisplayId(config.deviceDisplayType),
-                                            wallpaperColors = colorsModel.colors
+                                            wallpaperColors = colorsModel.colors,
                                         )
                                     // Dispose the previous preview on the renderer side.
                                     previewDisposableHandle?.dispose()
@@ -205,15 +204,21 @@ object WorkspacePreviewBinder {
     ): Message? {
         var workspaceCallback: Message? = null
         if (previewUtils.supportsPreview()) {
-            val extras = bundleOf(Pair(SurfaceViewUtils.KEY_DISPLAY_ID, displayId))
+            // surfaceView.width and surfaceFrame.width here can be different, one represents the
+            // size of the view and the other represents the size of the surface. When requesting a
+            // preview, make sure to specify the width and height in the bundle so we are using the
+            // surface size and not the view size.
+            val surfacePosition = surface.holder.surfaceFrame
+            val extras =
+                bundleOf(
+                    Pair(SurfaceViewUtils.KEY_DISPLAY_ID, displayId),
+                    Pair(SurfaceViewUtils.KEY_VIEW_WIDTH, surfacePosition.width()),
+                    Pair(SurfaceViewUtils.KEY_VIEW_HEIGHT, surfacePosition.height()),
+                )
             wallpaperColors?.let {
                 extras.putParcelable(SurfaceViewUtils.KEY_WALLPAPER_COLORS, wallpaperColors)
             }
-            val request =
-                SurfaceViewUtils.createSurfaceViewRequest(
-                    surface,
-                    extras,
-                )
+            val request = SurfaceViewUtils.createSurfaceViewRequest(surface, extras)
             workspaceCallback = suspendCancellableCoroutine { continuation ->
                 previewUtils.renderPreview(
                     request,
@@ -227,7 +232,7 @@ object WorkspacePreviewBinder {
                                         Log.w(
                                             TAG,
                                             "Result bundle from rendering preview does not contain " +
-                                                "a child surface package."
+                                                "a child surface package.",
                                         )
                                     }
                                 }
@@ -237,7 +242,7 @@ object WorkspacePreviewBinder {
                                 continuation.resume(null)
                             }
                         }
-                    }
+                    },
                 )
             }
         }
diff --git a/src/com/android/wallpaper/picker/preview/ui/fragment/CreativeEditPreviewFragment.kt b/src/com/android/wallpaper/picker/preview/ui/fragment/CreativeEditPreviewFragment.kt
index b976a192..f13e95da 100644
--- a/src/com/android/wallpaper/picker/preview/ui/fragment/CreativeEditPreviewFragment.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/fragment/CreativeEditPreviewFragment.kt
@@ -37,9 +37,11 @@ import com.android.wallpaper.picker.preview.ui.fragment.SmallPreviewFragment.Com
 import com.android.wallpaper.picker.preview.ui.viewmodel.PreviewActionsViewModel
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
 import com.android.wallpaper.util.DisplayUtils
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import dagger.hilt.android.AndroidEntryPoint
 import dagger.hilt.android.qualifiers.ApplicationContext
 import javax.inject.Inject
+import kotlinx.coroutines.CompletableDeferred
 
 /** Shows full preview with an edit activity overlay. */
 @AndroidEntryPoint(AppbarFragment::class)
@@ -47,6 +49,7 @@ class CreativeEditPreviewFragment : Hilt_CreativeEditPreviewFragment() {
 
     @Inject @ApplicationContext lateinit var appContext: Context
     @Inject lateinit var displayUtils: DisplayUtils
+    @Inject lateinit var wallpaperConnectionUtils: WallpaperConnectionUtils
 
     private lateinit var currentView: View
 
@@ -137,7 +140,8 @@ class CreativeEditPreviewFragment : Hilt_CreativeEditPreviewFragment() {
             displayUtils = displayUtils,
             lifecycleOwner = viewLifecycleOwner,
             savedInstanceState = savedInstanceState,
-            isFirstBinding = savedInstanceState == null
+            wallpaperConnectionUtils = wallpaperConnectionUtils,
+            isFirstBindingDeferred = CompletableDeferred(savedInstanceState == null)
         )
     }
 
diff --git a/src/com/android/wallpaper/picker/preview/ui/fragment/FullPreviewFragment.kt b/src/com/android/wallpaper/picker/preview/ui/fragment/FullPreviewFragment.kt
index ce2fcefd..390fc94e 100644
--- a/src/com/android/wallpaper/picker/preview/ui/fragment/FullPreviewFragment.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/fragment/FullPreviewFragment.kt
@@ -18,12 +18,15 @@ package com.android.wallpaper.picker.preview.ui.fragment
 import android.content.Context
 import android.os.Bundle
 import android.view.LayoutInflater
+import android.view.SurfaceView
 import android.view.View
 import android.view.ViewGroup
 import androidx.cardview.widget.CardView
 import androidx.core.content.ContextCompat
 import androidx.core.view.ViewCompat
+import androidx.core.view.isVisible
 import androidx.fragment.app.activityViewModels
+import androidx.navigation.NavController
 import androidx.navigation.fragment.findNavController
 import androidx.transition.Transition
 import com.android.wallpaper.R
@@ -36,9 +39,11 @@ import com.android.wallpaper.picker.preview.ui.transition.ChangeScaleAndPosition
 import com.android.wallpaper.picker.preview.ui.util.AnimationUtil
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
 import com.android.wallpaper.util.DisplayUtils
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import dagger.hilt.android.AndroidEntryPoint
 import dagger.hilt.android.qualifiers.ApplicationContext
 import javax.inject.Inject
+import kotlinx.coroutines.CompletableDeferred
 
 /** Shows full preview of user selected wallpaper for cropping, zooming and positioning. */
 @AndroidEntryPoint(AppbarFragment::class)
@@ -46,11 +51,15 @@ class FullPreviewFragment : Hilt_FullPreviewFragment() {
 
     @Inject @ApplicationContext lateinit var appContext: Context
     @Inject lateinit var displayUtils: DisplayUtils
+    @Inject lateinit var wallpaperConnectionUtils: WallpaperConnectionUtils
 
     private lateinit var currentView: View
 
     private val wallpaperPreviewViewModel by activityViewModels<WallpaperPreviewViewModel>()
+    private val isFirstBindingDeferred = CompletableDeferred<Boolean>()
+
     private var useLightToolbar = false
+    private var navigateUpListener: NavController.OnDestinationChangedListener? = null
 
     override fun onCreate(savedInstanceState: Bundle?) {
         super.onCreate(savedInstanceState)
@@ -62,17 +71,52 @@ class FullPreviewFragment : Hilt_FullPreviewFragment() {
     override fun onCreateView(
         inflater: LayoutInflater,
         container: ViewGroup?,
-        savedInstanceState: Bundle?
-    ): View? {
+        savedInstanceState: Bundle?,
+    ): View {
         currentView = inflater.inflate(R.layout.fragment_full_preview, container, false)
+
+        navigateUpListener =
+            NavController.OnDestinationChangedListener { _, destination, _ ->
+                if (destination.id == R.id.smallPreviewFragment) {
+                    currentView.findViewById<View>(R.id.crop_wallpaper_button)?.isVisible = false
+                    currentView.findViewById<View>(R.id.full_preview_tooltip_stub)?.isVisible =
+                        false
+                    // When navigate up back to small preview, move previews up app window for
+                    // smooth shared element transition. It's the earliest timing to do this, it'll
+                    // be to late in transition started callback.
+                    currentView
+                        .requireViewById<SurfaceView>(R.id.wallpaper_surface)
+                        .setZOrderOnTop(true)
+                    currentView
+                        .requireViewById<SurfaceView>(R.id.workspace_surface)
+                        .setZOrderOnTop(true)
+                }
+            }
+        navigateUpListener?.let { findNavController().addOnDestinationChangedListener(it) }
+
         setUpToolbar(currentView, true, true)
 
         val previewCard: CardView = currentView.requireViewById(R.id.preview_card)
         ViewCompat.setTransitionName(
             previewCard,
-            SmallPreviewFragment.FULL_PREVIEW_SHARED_ELEMENT_ID
+            SmallPreviewFragment.FULL_PREVIEW_SHARED_ELEMENT_ID,
         )
 
+        FullWallpaperPreviewBinder.bind(
+            applicationContext = appContext,
+            view = currentView,
+            viewModel = wallpaperPreviewViewModel,
+            transition = sharedElementEnterTransition as? Transition,
+            displayUtils = displayUtils,
+            lifecycleOwner = viewLifecycleOwner,
+            savedInstanceState = savedInstanceState,
+            wallpaperConnectionUtils = wallpaperConnectionUtils,
+            isFirstBindingDeferred = isFirstBindingDeferred,
+        ) { isFullScreen ->
+            useLightToolbar = isFullScreen
+            setUpToolbar(view)
+        }
+
         CropWallpaperButtonBinder.bind(
             button = currentView.requireViewById(R.id.crop_wallpaper_button),
             viewModel = wallpaperPreviewViewModel,
@@ -88,7 +132,7 @@ class FullPreviewFragment : Hilt_FullPreviewFragment() {
         )
 
         PreviewTooltipBinder.bindFullPreviewTooltip(
-            tooltipStub = currentView.requireViewById(R.id.tooltip_stub),
+            tooltipStub = currentView.requireViewById(R.id.full_preview_tooltip_stub),
             viewModel = wallpaperPreviewViewModel.fullTooltipViewModel,
             lifecycleOwner = viewLifecycleOwner,
         )
@@ -98,24 +142,13 @@ class FullPreviewFragment : Hilt_FullPreviewFragment() {
 
     override fun onViewStateRestored(savedInstanceState: Bundle?) {
         super.onViewStateRestored(savedInstanceState)
-        var isFirstBinding = false
-        if (savedInstanceState == null) {
-            isFirstBinding = true
-        }
+        isFirstBindingDeferred.complete(savedInstanceState == null)
+    }
 
-        FullWallpaperPreviewBinder.bind(
-            applicationContext = appContext,
-            view = currentView,
-            viewModel = wallpaperPreviewViewModel,
-            transition = sharedElementEnterTransition as? Transition,
-            displayUtils = displayUtils,
-            lifecycleOwner = viewLifecycleOwner,
-            savedInstanceState = savedInstanceState,
-            isFirstBinding = isFirstBinding,
-        ) { isFullScreen ->
-            useLightToolbar = isFullScreen
-            setUpToolbar(view)
-        }
+    override fun onDestroyView() {
+        super.onDestroyView()
+
+        navigateUpListener?.let { findNavController().removeOnDestinationChangedListener(it) }
     }
 
     // TODO(b/291761856): Use real string
diff --git a/src/com/android/wallpaper/picker/preview/ui/fragment/SetWallpaperDialogFragment.kt b/src/com/android/wallpaper/picker/preview/ui/fragment/SetWallpaperDialogFragment.kt
index 8c887290..a619ddb9 100644
--- a/src/com/android/wallpaper/picker/preview/ui/fragment/SetWallpaperDialogFragment.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/fragment/SetWallpaperDialogFragment.kt
@@ -41,6 +41,7 @@ import com.android.wallpaper.util.DisplayUtils
 import com.android.wallpaper.util.LaunchSourceUtils.LAUNCH_SOURCE_LAUNCHER
 import com.android.wallpaper.util.LaunchSourceUtils.LAUNCH_SOURCE_SETTINGS_HOMEPAGE
 import com.android.wallpaper.util.LaunchSourceUtils.WALLPAPER_LAUNCH_SOURCE
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import dagger.hilt.android.AndroidEntryPoint
 import javax.inject.Inject
 import kotlinx.coroutines.CoroutineScope
@@ -51,6 +52,7 @@ class SetWallpaperDialogFragment : Hilt_SetWallpaperDialogFragment() {
 
     @Inject lateinit var displayUtils: DisplayUtils
     @Inject @MainDispatcher lateinit var mainScope: CoroutineScope
+    @Inject lateinit var wallpaperConnectionUtils: WallpaperConnectionUtils
 
     private val wallpaperPreviewViewModel by activityViewModels<WallpaperPreviewViewModel>()
 
@@ -120,6 +122,7 @@ class SetWallpaperDialogFragment : Hilt_SetWallpaperDialogFragment() {
                 }
             },
             onDismissDialog = { findNavController().popBackStack() },
+            wallpaperConnectionUtils = wallpaperConnectionUtils,
             isFirstBinding = false,
             navigate = null,
         )
diff --git a/src/com/android/wallpaper/picker/preview/ui/fragment/SmallPreviewFragment.kt b/src/com/android/wallpaper/picker/preview/ui/fragment/SmallPreviewFragment.kt
index d72272bc..430e5c2b 100644
--- a/src/com/android/wallpaper/picker/preview/ui/fragment/SmallPreviewFragment.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/fragment/SmallPreviewFragment.kt
@@ -15,6 +15,8 @@
  */
 package com.android.wallpaper.picker.preview.ui.fragment
 
+import android.app.Activity
+import android.app.AlertDialog
 import android.content.Context
 import android.content.Intent
 import android.os.Bundle
@@ -23,6 +25,7 @@ import android.view.View
 import android.view.ViewGroup
 import androidx.activity.result.ActivityResultLauncher
 import androidx.activity.result.contract.ActivityResultContract
+import androidx.constraintlayout.motion.widget.MotionLayout
 import androidx.core.content.ContextCompat
 import androidx.core.view.doOnPreDraw
 import androidx.fragment.app.activityViewModels
@@ -34,6 +37,7 @@ import androidx.navigation.fragment.findNavController
 import androidx.transition.Transition
 import com.android.wallpaper.R
 import com.android.wallpaper.R.id.preview_tabs_container
+import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.module.logging.UserEventLogger
 import com.android.wallpaper.picker.AppbarFragment
 import com.android.wallpaper.picker.preview.ui.binder.DualPreviewSelectorBinder
@@ -44,14 +48,17 @@ import com.android.wallpaper.picker.preview.ui.binder.SetWallpaperProgressDialog
 import com.android.wallpaper.picker.preview.ui.util.AnimationUtil
 import com.android.wallpaper.picker.preview.ui.util.ImageEffectDialogUtil
 import com.android.wallpaper.picker.preview.ui.view.DualPreviewViewPager
+import com.android.wallpaper.picker.preview.ui.view.PreviewActionFloatingSheet
 import com.android.wallpaper.picker.preview.ui.view.PreviewActionGroup
 import com.android.wallpaper.picker.preview.ui.view.PreviewTabs
 import com.android.wallpaper.picker.preview.ui.viewmodel.Action
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
 import com.android.wallpaper.util.DisplayUtils
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import dagger.hilt.android.AndroidEntryPoint
 import dagger.hilt.android.qualifiers.ApplicationContext
 import javax.inject.Inject
+import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.launch
 
 /**
@@ -65,11 +72,13 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
     @Inject lateinit var displayUtils: DisplayUtils
     @Inject lateinit var logger: UserEventLogger
     @Inject lateinit var imageEffectDialogUtil: ImageEffectDialogUtil
+    @Inject lateinit var wallpaperConnectionUtils: WallpaperConnectionUtils
 
     private lateinit var currentView: View
     private lateinit var shareActivityResult: ActivityResultLauncher<Intent>
 
     private val wallpaperPreviewViewModel by activityViewModels<WallpaperPreviewViewModel>()
+    private val isFirstBindingDeferred = CompletableDeferred<Boolean>()
 
     /**
      * True if the view of this fragment is destroyed from the current or previous lifecycle.
@@ -91,17 +100,28 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
         container: ViewGroup?,
         savedInstanceState: Bundle?,
     ): View {
+        val isFoldable = displayUtils.hasMultiInternalDisplays()
         postponeEnterTransition()
         currentView =
             inflater.inflate(
-                if (displayUtils.hasMultiInternalDisplays())
-                    R.layout.fragment_small_preview_foldable
-                else R.layout.fragment_small_preview_handheld,
+                if (BaseFlags.get().isNewPickerUi()) {
+                    if (isFoldable) R.layout.fragment_small_preview_foldable2
+                    else R.layout.fragment_small_preview_handheld2
+                } else {
+                    if (isFoldable) R.layout.fragment_small_preview_foldable
+                    else R.layout.fragment_small_preview_handheld
+                },
                 container,
-                false,
+                /* attachToRoot= */ false,
             )
+        val motionLayout =
+            if (BaseFlags.get().isNewPickerUi())
+                currentView.findViewById<MotionLayout>(R.id.small_preview_motion_layout)
+            else null
+
         setUpToolbar(currentView, /* upArrow= */ true, /* transparentToolbar= */ true)
-        bindPreviewActions(currentView)
+        bindScreenPreview(currentView, motionLayout, isFirstBindingDeferred)
+        bindPreviewActions(currentView, motionLayout)
 
         SetWallpaperButtonBinder.bind(
             button = currentView.requireViewById(R.id.button_set_wallpaper),
@@ -113,9 +133,12 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
 
         SetWallpaperProgressDialogBinder.bind(
             viewModel = wallpaperPreviewViewModel,
-            activity = requireActivity(),
             lifecycleOwner = viewLifecycleOwner,
-        )
+        ) { visible ->
+            activity?.let {
+                createSetWallpaperProgressDialog(it).apply { if (visible) show() else hide() }
+            }
+        }
 
         currentView.doOnPreDraw {
             // FullPreviewConfigViewModel not being null indicates that we are navigated to small
@@ -135,7 +158,7 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
                     override fun parseResult(resultCode: Int, intent: Intent?): Int {
                         return resultCode
                     }
-                },
+                }
             ) {
                 currentView
                     .findViewById<PreviewActionGroup>(R.id.action_button_group)
@@ -147,7 +170,7 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
 
     override fun onViewStateRestored(savedInstanceState: Bundle?) {
         super.onViewStateRestored(savedInstanceState)
-        bindScreenPreview(currentView, isFirstBinding = savedInstanceState == null)
+        isFirstBindingDeferred.complete(savedInstanceState == null)
     }
 
     override fun onStart() {
@@ -158,8 +181,8 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
         isViewDestroyed?.let {
             if (!it) {
                 currentView
-                    .requireViewById<PreviewTabs>(preview_tabs_container)
-                    .resetTransition(wallpaperPreviewViewModel.getSmallPreviewTabIndex())
+                    .findViewById<PreviewTabs>(preview_tabs_container)
+                    ?.resetTransition(wallpaperPreviewViewModel.getSmallPreviewTabIndex())
             }
         }
     }
@@ -183,23 +206,34 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
         return ContextCompat.getColor(requireContext(), R.color.system_on_surface)
     }
 
-    private fun bindScreenPreview(view: View, isFirstBinding: Boolean) {
+    private fun createSetWallpaperProgressDialog(activity: Activity): AlertDialog {
+        val dialogView =
+            activity.layoutInflater.inflate(R.layout.set_wallpaper_progress_dialog_view, null)
+        return AlertDialog.Builder(activity).setView(dialogView).create()
+    }
+
+    private fun bindScreenPreview(
+        view: View,
+        motionLayout: MotionLayout?,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
+    ) {
         val currentNavDestId = checkNotNull(findNavController().currentDestination?.id)
-        val tabs = view.requireViewById<PreviewTabs>(preview_tabs_container)
+        val tabs = view.findViewById<PreviewTabs>(preview_tabs_container)
         if (displayUtils.hasMultiInternalDisplays()) {
-            val dualPreviewView: DualPreviewViewPager =
-                view.requireViewById(R.id.dual_preview_pager)
+            val dualPreviewView: DualPreviewViewPager = view.requireViewById(R.id.pager_previews)
 
             DualPreviewSelectorBinder.bind(
                 tabs,
                 dualPreviewView,
+                motionLayout,
                 wallpaperPreviewViewModel,
                 appContext,
                 viewLifecycleOwner,
                 currentNavDestId,
                 (reenterTransition as Transition?),
                 wallpaperPreviewViewModel.fullPreviewConfigViewModel.value,
-                isFirstBinding,
+                wallpaperConnectionUtils,
+                isFirstBindingDeferred,
             ) { sharedElement ->
                 val extras =
                     FragmentNavigatorExtras(sharedElement to FULL_PREVIEW_SHARED_ELEMENT_ID)
@@ -210,13 +244,14 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
                         resId = R.id.action_smallPreviewFragment_to_fullPreviewFragment,
                         args = null,
                         navOptions = null,
-                        navigatorExtras = extras
+                        navigatorExtras = extras,
                     )
             }
         } else {
             PreviewSelectorBinder.bind(
                 tabs,
                 view.requireViewById(R.id.pager_previews),
+                motionLayout,
                 displayUtils.getRealSize(displayUtils.getWallpaperDisplay()),
                 wallpaperPreviewViewModel,
                 appContext,
@@ -224,7 +259,8 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
                 currentNavDestId,
                 (reenterTransition as Transition?),
                 wallpaperPreviewViewModel.fullPreviewConfigViewModel.value,
-                isFirstBinding,
+                wallpaperConnectionUtils,
+                isFirstBindingDeferred,
             ) { sharedElement ->
                 val extras =
                     FragmentNavigatorExtras(sharedElement to FULL_PREVIEW_SHARED_ELEMENT_ID)
@@ -235,7 +271,7 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
                         resId = R.id.action_smallPreviewFragment_to_fullPreviewFragment,
                         args = null,
                         navOptions = null,
-                        navigatorExtras = extras
+                        navigatorExtras = extras,
                     )
             }
         }
@@ -249,10 +285,22 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
         }
     }
 
-    private fun bindPreviewActions(view: View) {
+    private fun bindPreviewActions(view: View, motionLayout: MotionLayout?) {
+        val actionButtonGroup = view.findViewById<PreviewActionGroup>(R.id.action_button_group)
+        val floatingSheet = view.findViewById<PreviewActionFloatingSheet>(R.id.floating_sheet)
+        if (actionButtonGroup == null || floatingSheet == null) {
+            return
+        }
+
+        val motionLayout =
+            if (BaseFlags.get().isNewPickerUi())
+                view.findViewById<MotionLayout>(R.id.small_preview_motion_layout)
+            else null
+
         PreviewActionsBinder.bind(
-            actionGroup = view.requireViewById(R.id.action_button_group),
-            floatingSheet = view.requireViewById(R.id.floating_sheet),
+            actionGroup = actionButtonGroup,
+            floatingSheet = floatingSheet,
+            motionLayout = motionLayout,
             previewViewModel = wallpaperPreviewViewModel,
             actionsViewModel = wallpaperPreviewViewModel.previewActionsViewModel,
             deviceDisplayType = displayUtils.getCurrentDisplayType(requireActivity()),
diff --git a/src/com/android/wallpaper/picker/preview/ui/util/FullResImageViewUtil.kt b/src/com/android/wallpaper/picker/preview/ui/util/FullResImageViewUtil.kt
index 3b31fa92..f341c57e 100644
--- a/src/com/android/wallpaper/picker/preview/ui/util/FullResImageViewUtil.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/util/FullResImageViewUtil.kt
@@ -26,26 +26,27 @@ object FullResImageViewUtil {
 
     private const val DEFAULT_WALLPAPER_MAX_ZOOM = 8f
 
+    /**
+     * Calculates minimum zoom to fit maximum visible area of wallpaper on crop surface.
+     *
+     * Preserves a boundary at [systemScale] beyond the visible crop when given.
+     *
+     * @param systemScale the device's system wallpaper scale when it needs to be considered
+     */
     fun getScaleAndCenter(
         viewSize: Point,
         rawWallpaperSize: Point,
         displaySize: Point,
         cropRect: Rect?,
         isRtl: Boolean,
-        systemScale: Float,
+        systemScale: Float = 1f,
     ): ScaleAndCenter {
-        // Determine minimum zoom to fit maximum visible area of wallpaper on crop surface.
-        // defaultRawWallpaperRect represents a brand new wallpaper preview with no crop hints.
-        // For full screen, the preview image container size has already been adjusted
-        // to preserve a boundary beyond the visible crop per comment at
-        // FullWallpaperPreviewBinder#adjustSizesForCropping.
-        // For small screen preview, we need to apply additional scaling since the
-        // container is the same size as the preview.
         viewSize.apply {
             // Preserve precision by not converting scale to int but the result
             x = (x * systemScale).toInt()
             y = (y * systemScale).toInt()
         }
+        // defaultRawWallpaperRect represents a brand new wallpaper preview with no crop hints.
         val defaultRawWallpaperRect =
             WallpaperCropUtils.calculateVisibleRect(rawWallpaperSize, viewSize)
         val visibleRawWallpaperRect =
@@ -55,17 +56,17 @@ object FullResImageViewUtil {
         val centerPosition =
             PointF(
                 visibleRawWallpaperRect.centerX().toFloat(),
-                visibleRawWallpaperRect.centerY().toFloat()
+                visibleRawWallpaperRect.centerY().toFloat(),
             )
         val defaultWallpaperZoom =
             WallpaperCropUtils.calculateMinZoom(
                 Point(defaultRawWallpaperRect.width(), defaultRawWallpaperRect.height()),
-                viewSize
+                viewSize,
             )
         val visibleWallpaperZoom =
             WallpaperCropUtils.calculateMinZoom(
                 Point(visibleRawWallpaperRect.width(), visibleRawWallpaperRect.height()),
-                viewSize
+                viewSize,
             )
 
         return ScaleAndCenter(
@@ -82,6 +83,6 @@ object FullResImageViewUtil {
         val minScale: Float,
         val maxScale: Float,
         val defaultScale: Float,
-        val center: PointF
+        val center: PointF,
     )
 }
diff --git a/src/com/android/wallpaper/picker/preview/ui/util/SurfaceViewUtil.kt b/src/com/android/wallpaper/picker/preview/ui/util/SurfaceViewUtil.kt
deleted file mode 100644
index 4fd55937..00000000
--- a/src/com/android/wallpaper/picker/preview/ui/util/SurfaceViewUtil.kt
+++ /dev/null
@@ -1,42 +0,0 @@
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
-package com.android.wallpaper.picker.preview.ui.util
-
-import android.view.SurfaceControlViewHost
-import android.view.SurfaceHolder
-import android.view.SurfaceView
-import android.view.View
-import android.view.ViewGroup
-
-object SurfaceViewUtil {
-
-    fun SurfaceView.attachView(view: View, newWidth: Int = width, newHeight: Int = height) {
-        // Detach view from its parent, if the view has one
-        (view.parent as ViewGroup?)?.removeView(view)
-        val host = SurfaceControlViewHost(context, display, hostToken)
-        host.setView(view, newWidth, newHeight)
-        setChildSurfacePackage(checkNotNull(host.surfacePackage))
-    }
-
-    interface SurfaceCallback : SurfaceHolder.Callback {
-        override fun surfaceCreated(holder: SurfaceHolder) {}
-
-        override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {}
-
-        override fun surfaceDestroyed(holder: SurfaceHolder) {}
-    }
-}
diff --git a/src/com/android/wallpaper/picker/preview/ui/view/DualPreviewViewPager.kt b/src/com/android/wallpaper/picker/preview/ui/view/DualPreviewViewPager.kt
index ebd73c03..dc3ce35c 100644
--- a/src/com/android/wallpaper/picker/preview/ui/view/DualPreviewViewPager.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/view/DualPreviewViewPager.kt
@@ -20,6 +20,7 @@ import android.graphics.Point
 import android.util.AttributeSet
 import androidx.viewpager.widget.ViewPager
 import com.android.wallpaper.R
+import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.model.wallpaper.DeviceDisplayType
 
 /**
@@ -34,7 +35,7 @@ constructor(context: Context, attrs: AttributeSet? = null /* attrs */) : ViewPag
     private var previewDisplaySizes: Map<DeviceDisplayType, Point>? = null
 
     override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
-        if (previewDisplaySizes == null) {
+        if (previewDisplaySizes == null || BaseFlags.get().isNewPickerUi()) {
             super.onMeasure(widthMeasureSpec, heightMeasureSpec)
             return
         }
diff --git a/src/com/android/wallpaper/picker/preview/ui/view/PreviewActionFloatingSheet.kt b/src/com/android/wallpaper/picker/preview/ui/view/PreviewActionFloatingSheet.kt
index e23703ec..4f56fa3f 100644
--- a/src/com/android/wallpaper/picker/preview/ui/view/PreviewActionFloatingSheet.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/view/PreviewActionFloatingSheet.kt
@@ -29,6 +29,7 @@ import androidx.slice.Slice
 import androidx.slice.widget.SliceLiveData
 import androidx.slice.widget.SliceView
 import com.android.wallpaper.R
+import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.effects.EffectsController.EffectEnumInterface
 import com.android.wallpaper.model.WallpaperAction
 import com.android.wallpaper.util.SizeCalculator
@@ -53,7 +54,10 @@ class PreviewActionFloatingSheet(context: Context, attrs: AttributeSet?) :
     private var customizeLiveDataAndView: Pair<LiveData<Slice>, SliceView>? = null
 
     init {
-        LayoutInflater.from(context).inflate(R.layout.floating_sheet2, this, true)
+        val layout =
+            if (BaseFlags.get().isNewPickerUi()) R.layout.floating_sheet3
+            else R.layout.floating_sheet2
+        LayoutInflater.from(context).inflate(layout, this, true)
         floatingSheetView = requireViewById(R.id.floating_sheet_content)
         SizeCalculator.adjustBackgroundCornerRadius(floatingSheetView)
         floatingSheetContainer = requireViewById(R.id.floating_sheet_container)
@@ -120,6 +124,7 @@ class PreviewActionFloatingSheet(context: Context, attrs: AttributeSet?) :
     fun setInformationContent(
         attributions: List<String?>?,
         onExploreButtonClickListener: OnClickListener?,
+        actionButtonTitle: CharSequence?,
     ) {
         val view = LayoutInflater.from(context).inflate(R.layout.wallpaper_info_view2, this, false)
         val title: TextView = view.requireViewById(R.id.wallpaper_info_title)
@@ -149,6 +154,7 @@ class PreviewActionFloatingSheet(context: Context, attrs: AttributeSet?) :
             }
 
             exploreButton.isVisible = onExploreButtonClickListener != null
+            actionButtonTitle?.let { exploreButton.text = it }
             exploreButton.setOnClickListener(onExploreButtonClickListener)
         }
         floatingSheetView.removeAllViews()
diff --git a/src/com/android/wallpaper/picker/preview/ui/view/PreviewActionGroup.kt b/src/com/android/wallpaper/picker/preview/ui/view/PreviewActionGroup.kt
index 2703188c..dee2b073 100644
--- a/src/com/android/wallpaper/picker/preview/ui/view/PreviewActionGroup.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/view/PreviewActionGroup.kt
@@ -24,6 +24,7 @@ import android.widget.ToggleButton
 import androidx.appcompat.content.res.AppCompatResources
 import androidx.core.view.isVisible
 import com.android.wallpaper.R
+import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.picker.preview.ui.viewmodel.Action
 
 /** Custom layout for a group of wallpaper preview actions. */
@@ -40,7 +41,10 @@ class PreviewActionGroup(context: Context, attrs: AttributeSet?) : FrameLayout(c
     private val shareButton: ToggleButton
 
     init {
-        LayoutInflater.from(context).inflate(R.layout.preview_action_group, this, true)
+        val layout =
+            if (BaseFlags.get().isNewPickerUi()) R.layout.preview_action_group2
+            else R.layout.preview_action_group
+        LayoutInflater.from(context).inflate(layout, this, true)
         informationButton = requireViewById(R.id.information_button)
         downloadButton = requireViewById(R.id.download_button)
         downloadButtonToggle = requireViewById(R.id.download_button_toggle)
diff --git a/src/com/android/wallpaper/picker/preview/ui/view/SystemScaledSubsamplingScaleImageView.kt b/src/com/android/wallpaper/picker/preview/ui/view/SystemScaledSubsamplingScaleImageView.kt
index d6874cce..b86cb945 100644
--- a/src/com/android/wallpaper/picker/preview/ui/view/SystemScaledSubsamplingScaleImageView.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/view/SystemScaledSubsamplingScaleImageView.kt
@@ -16,34 +16,55 @@
 package com.android.wallpaper.picker.preview.ui.view
 
 import android.content.Context
+import android.graphics.Point
 import android.util.AttributeSet
 import com.android.wallpaper.util.WallpaperCropUtils
 import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView
 
 /**
- * A [SubsamplingScaleImageView] for wallpaper preview that scales and centers the surface to
- * simulate the actual wallpaper surface's default system zoom.
+ * Simulates the actual wallpaper surface's default system zoom view size based on its parent
+ * surface size and the device's system wallpaper scale.
+ *
+ * Scales its size to surface_size * system_scale and centers the view on the surface.
+ *
+ * Acts like a [SubsamplingScaleImageView] if not given a surface size.
+ *
+ * Used in wallpaper small and full preview.
  */
 class SystemScaledSubsamplingScaleImageView(context: Context, attrs: AttributeSet? = null) :
     SubsamplingScaleImageView(context, attrs) {
+
+    private var surfaceSize: Point? = null
+
     override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
         super.onMeasure(widthMeasureSpec, heightMeasureSpec)
 
-        val scale = WallpaperCropUtils.getSystemWallpaperMaximumScale(context)
-        setMeasuredDimension((measuredWidth * scale).toInt(), (measuredHeight * scale).toInt())
+        if (surfaceSize != null) {
+            val scale = WallpaperCropUtils.getSystemWallpaperMaximumScale(context)
+            setMeasuredDimension((measuredWidth * scale).toInt(), (measuredHeight * scale).toInt())
+        }
     }
 
     override fun onLayout(changed: Boolean, left: Int, top: Int, right: Int, bottom: Int) {
-        // Calculate the size of wallpaper surface based on the system zoom
-        // and scale & center the wallpaper preview to respect the zoom.
-        val scale = WallpaperCropUtils.getSystemWallpaperMaximumScale(context)
 
-        val scaledWidth = (measuredWidth * scale).toInt()
-        val scaledHeight = (measuredHeight * scale).toInt()
-        val xCentered = (measuredWidth - scaledWidth) / 2
-        val yCentered = (measuredHeight - scaledHeight) / 2
+        surfaceSize?.let {
+            // Calculate the size of wallpaper surface based on the system zoom
+            // and scale & center the wallpaper preview to respect the zoom.
+            val scale = WallpaperCropUtils.getSystemWallpaperMaximumScale(context)
+
+            val scaledWidth = (it.x * scale).toInt()
+            val scaledHeight = (it.y * scale).toInt()
+            val xCentered = (it.x - scaledWidth) / 2
+            val yCentered = (it.y - scaledHeight) / 2
+
+            x = xCentered.toFloat()
+            y = yCentered.toFloat()
+            layoutParams.width = scaledWidth
+            layoutParams.height = scaledHeight
+        }
+    }
 
-        x = xCentered.toFloat()
-        y = yCentered.toFloat()
+    fun setSurfaceSize(size: Point) {
+        surfaceSize = size
     }
 }
diff --git a/src/com/android/wallpaper/picker/preview/ui/view/adapters/DualPreviewPagerAdapter.kt b/src/com/android/wallpaper/picker/preview/ui/view/adapters/DualPreviewPagerAdapter.kt
index 2b4b15af..106b97da 100644
--- a/src/com/android/wallpaper/picker/preview/ui/view/adapters/DualPreviewPagerAdapter.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/view/adapters/DualPreviewPagerAdapter.kt
@@ -21,6 +21,7 @@ import android.view.ViewGroup
 import androidx.recyclerview.widget.RecyclerView
 import androidx.viewpager.widget.PagerAdapter
 import com.android.wallpaper.R
+import com.android.wallpaper.config.BaseFlags
 
 /** This class provides the dual preview views for the small preview screen on foldable devices */
 class DualPreviewPagerAdapter(
@@ -34,13 +35,27 @@ class DualPreviewPagerAdapter(
     }
 
     override fun instantiateItem(container: ViewGroup, position: Int): Any {
-        val view =
-            LayoutInflater.from(container.context)
-                .inflate(R.layout.small_preview_foldable_card_view, container, false)
-
-        onBindViewHolder.invoke(view, position)
-        container.addView(view)
-        return view
+        if (BaseFlags.get().isNewPickerUi()) {
+            val view =
+                LayoutInflater.from(container.context)
+                    .inflate(R.layout.small_preview_foldable_card_view2, container, false)
+            onBindViewHolder.invoke(view, position)
+            container.addView(
+                view,
+                ViewGroup.LayoutParams(
+                    ViewGroup.LayoutParams.MATCH_PARENT,
+                    ViewGroup.LayoutParams.MATCH_PARENT
+                ),
+            )
+            return view
+        } else {
+            val view =
+                LayoutInflater.from(container.context)
+                    .inflate(R.layout.small_preview_foldable_card_view, container, false)
+            onBindViewHolder.invoke(view, position)
+            container.addView(view)
+            return view
+        }
     }
 
     override fun destroyItem(container: ViewGroup, position: Int, `object`: Any) {
diff --git a/src/com/android/wallpaper/picker/preview/ui/view/adapters/SinglePreviewPagerAdapter.kt b/src/com/android/wallpaper/picker/preview/ui/view/adapters/SinglePreviewPagerAdapter.kt
index 4658c85b..33dbdfa9 100644
--- a/src/com/android/wallpaper/picker/preview/ui/view/adapters/SinglePreviewPagerAdapter.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/view/adapters/SinglePreviewPagerAdapter.kt
@@ -20,16 +20,24 @@ import android.view.View
 import android.view.ViewGroup
 import androidx.recyclerview.widget.RecyclerView
 import com.android.wallpaper.R
+import com.android.wallpaper.config.BaseFlags
 
-/** This adapter provides preview views for the small preview fragment */
+/**
+ * This adapter provides preview views for the small preview fragment
+ *
+ * TODO(b/361583350): Use [PreviewPagerAdapter], remove this class once new picker UI is released
+ */
 class SinglePreviewPagerAdapter(
     private val onBindViewHolder: (ViewHolder, Int) -> Unit,
 ) : RecyclerView.Adapter<SinglePreviewPagerAdapter.ViewHolder>() {
 
     override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
-        val view =
-            LayoutInflater.from(parent.context)
-                .inflate(R.layout.small_preview_handheld_card_view, parent, false)
+
+        val layout =
+            if (BaseFlags.get().isNewPickerUi()) R.layout.small_preview_handheld_card_view2
+            else R.layout.small_preview_handheld_card_view
+
+        val view = LayoutInflater.from(parent.context).inflate(layout, parent, false)
 
         view.setPadding(
             0,
diff --git a/src/com/android/wallpaper/picker/preview/ui/viewmodel/PreviewActionsViewModel.kt b/src/com/android/wallpaper/picker/preview/ui/viewmodel/PreviewActionsViewModel.kt
index 54125cdd..5f75dae6 100644
--- a/src/com/android/wallpaper/picker/preview/ui/viewmodel/PreviewActionsViewModel.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/viewmodel/PreviewActionsViewModel.kt
@@ -16,6 +16,7 @@
 
 package com.android.wallpaper.picker.preview.ui.viewmodel
 
+import android.content.ActivityNotFoundException
 import android.content.ClipData
 import android.content.ComponentName
 import android.content.Context
@@ -24,10 +25,11 @@ import android.net.ConnectivityManager
 import android.net.Uri
 import android.net.wifi.WifiManager
 import android.service.wallpaper.WallpaperSettingsActivity
+import android.util.Log
+import com.android.wallpaper.R
 import com.android.wallpaper.effects.Effect
 import com.android.wallpaper.effects.EffectsController.EffectEnumInterface
 import com.android.wallpaper.picker.data.CreativeWallpaperData
-import com.android.wallpaper.picker.data.DownloadableWallpaperData
 import com.android.wallpaper.picker.data.LiveWallpaperData
 import com.android.wallpaper.picker.data.WallpaperModel
 import com.android.wallpaper.picker.data.WallpaperModel.LiveWallpaperModel
@@ -40,10 +42,12 @@ import com.android.wallpaper.picker.preview.data.repository.ImageEffectsReposito
 import com.android.wallpaper.picker.preview.data.repository.ImageEffectsRepository.EffectStatus.EFFECT_DOWNLOAD_READY
 import com.android.wallpaper.picker.preview.data.repository.ImageEffectsRepository.EffectStatus.EFFECT_READY
 import com.android.wallpaper.picker.preview.domain.interactor.PreviewActionsInteractor
+import com.android.wallpaper.picker.preview.shared.model.DownloadStatus
 import com.android.wallpaper.picker.preview.shared.model.ImageEffectsModel
 import com.android.wallpaper.picker.preview.ui.util.LiveWallpaperDeleteUtil
 import com.android.wallpaper.picker.preview.ui.viewmodel.Action.CUSTOMIZE
 import com.android.wallpaper.picker.preview.ui.viewmodel.Action.DELETE
+import com.android.wallpaper.picker.preview.ui.viewmodel.Action.DOWNLOAD
 import com.android.wallpaper.picker.preview.ui.viewmodel.Action.EDIT
 import com.android.wallpaper.picker.preview.ui.viewmodel.Action.EFFECTS
 import com.android.wallpaper.picker.preview.ui.viewmodel.Action.INFORMATION
@@ -64,11 +68,13 @@ import com.android.wallpaper.widget.floatingsheetcontent.WallpaperEffectsView2.S
 import dagger.hilt.android.qualifiers.ApplicationContext
 import dagger.hilt.android.scopes.ViewModelScoped
 import javax.inject.Inject
+import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.map
 
 /** View model for the preview action buttons */
@@ -80,6 +86,12 @@ constructor(
     liveWallpaperDeleteUtil: LiveWallpaperDeleteUtil,
     @ApplicationContext private val context: Context,
 ) {
+    private val TAG = "PreviewActionsViewModel"
+    private var EXTENDED_WALLPAPER_EFFECTS_PACKAGE =
+        context.getString(R.string.extended_wallpaper_effects_package)
+    private var EXTENDED_WALLPAPER_EFFECTS_ACTIVITY =
+        context.getString(R.string.extended_wallpaper_effects_activity)
+
     /** [INFORMATION] */
     private val informationFloatingSheetViewModel: Flow<InformationFloatingSheetViewModel?> =
         interactor.wallpaperModel.map { wallpaperModel ->
@@ -92,7 +104,10 @@ constructor(
                         null
                     } else {
                         wallpaperModel.commonWallpaperData.exploreActionUrl
-                    }
+                    },
+                    (wallpaperModel as? LiveWallpaperModel)?.let { liveWallpaperModel ->
+                        liveWallpaperModel.liveWallpaperData.contextDescription?.let { it }
+                    },
                 )
             }
         }
@@ -117,20 +132,16 @@ constructor(
         }
 
     /** [DOWNLOAD] */
-    private val downloadableWallpaperData: Flow<DownloadableWallpaperData?> =
-        interactor.wallpaperModel.map {
-            (it as? WallpaperModel.StaticWallpaperModel)?.downloadableWallpaperData
+    val isDownloadVisible: Flow<Boolean> =
+        interactor.downloadableWallpaperModel.map {
+            it.status == DownloadStatus.READY_TO_DOWNLOAD || it.status == DownloadStatus.DOWNLOADING
         }
-    val isDownloadVisible: Flow<Boolean> = downloadableWallpaperData.map { it != null }
-
-    val isDownloading: Flow<Boolean> = interactor.isDownloadingWallpaper
-
+    val isDownloading: Flow<Boolean> =
+        interactor.downloadableWallpaperModel.map { it.status == DownloadStatus.DOWNLOADING }
     val isDownloadButtonEnabled: Flow<Boolean> =
-        combine(downloadableWallpaperData, isDownloading) { downloadableData, isDownloading ->
-            downloadableData != null && !isDownloading
-        }
+        interactor.downloadableWallpaperModel.map { it.status == DownloadStatus.READY_TO_DOWNLOAD }
 
-    suspend fun downloadWallpaper() {
+    fun downloadWallpaper() {
         interactor.downloadWallpaper()
     }
 
@@ -253,10 +264,7 @@ constructor(
                         null
                     }
                     else -> {
-                        getImageEffectFloatingSheetViewModel(
-                            imageEffect,
-                            imageEffectsModel,
-                        )
+                        getImageEffectFloatingSheetViewModel(imageEffect, imageEffectsModel)
                     }
                 }
             }
@@ -336,7 +344,7 @@ constructor(
             object : EffectSwitchListener {
                 override fun onEffectSwitchChanged(
                     effect: EffectEnumInterface,
-                    isChecked: Boolean
+                    isChecked: Boolean,
                 ) {
                     if (interactor.isTargetEffect(effect)) {
                         if (isChecked) {
@@ -398,20 +406,69 @@ constructor(
     private val _isEffectsChecked: MutableStateFlow<Boolean> = MutableStateFlow(false)
     val isEffectsChecked: Flow<Boolean> = _isEffectsChecked.asStateFlow()
 
+    @OptIn(ExperimentalCoroutinesApi::class)
     val onEffectsClicked: Flow<(() -> Unit)?> =
-        combine(isEffectsVisible, isEffectsChecked) { show, isChecked ->
-            if (show) {
-                {
-                    if (!isChecked) {
-                        uncheckAllOthersExcept(EFFECTS)
+        combine(isEffectsVisible, isEffectsChecked, imageEffectFloatingSheetViewModel) {
+            isVisible,
+            isChecked,
+            imageEffect ->
+            if (isVisible) {
+                val intent = buildExtendedWallpaperIntent()
+                val isIntentValid =
+                    intent.resolveActivityInfo(context.getPackageManager(), 0) != null
+                if (imageEffect != null && isIntentValid) {
+                    { launchExtendedWallpaperEffects() }
+                } else {
+                    fun() {
+                        if (!isChecked) {
+                            uncheckAllOthersExcept(EFFECTS)
+                        }
+                        _isEffectsChecked.value = !isChecked
                     }
-                    _isEffectsChecked.value = !isChecked
                 }
             } else {
                 null
             }
         }
 
+    private fun launchExtendedWallpaperEffects() {
+        val previewedWallpaperModel = interactor.wallpaperModel.value
+        var photoUri: Uri? = null
+        if (
+            previewedWallpaperModel is WallpaperModel.StaticWallpaperModel &&
+                previewedWallpaperModel.imageWallpaperData != null
+        ) {
+            photoUri = previewedWallpaperModel.imageWallpaperData.uri
+        }
+
+        val intent = buildExtendedWallpaperIntent()
+        context.grantUriPermission(
+            EXTENDED_WALLPAPER_EFFECTS_PACKAGE,
+            photoUri,
+            Intent.FLAG_GRANT_READ_URI_PERMISSION,
+        )
+        Log.d(TAG, "PhotoURI is: $photoUri")
+        photoUri?.let { uri ->
+            intent.putExtra("PHOTO_URI", uri)
+            try {
+                context.startActivity(intent)
+            } catch (ex: ActivityNotFoundException) {
+                Log.e(TAG, "Extended Wallpaper Activity is not available", ex)
+            }
+        }
+    }
+
+    private fun buildExtendedWallpaperIntent(): Intent {
+        return Intent().apply {
+            component =
+                ComponentName(
+                    EXTENDED_WALLPAPER_EFFECTS_PACKAGE,
+                    EXTENDED_WALLPAPER_EFFECTS_ACTIVITY,
+                )
+            flags = Intent.FLAG_ACTIVITY_NEW_TASK
+        }
+    }
+
     val effectDownloadFailureToastText: Flow<String> =
         interactor.imageEffectsModel
             .map { if (it.status == EFFECT_DOWNLOAD_FAILED) it.errorMessage else null }
@@ -483,6 +540,13 @@ constructor(
         }
     }
 
+    fun isAnyActionChecked(): Boolean =
+        _isInformationChecked.value ||
+            _isDeleteChecked.value ||
+            _isEditChecked.value ||
+            _isCustomizeChecked.value ||
+            _isEffectsChecked.value
+
     private fun uncheckAllOthersExcept(action: Action) {
         if (action != INFORMATION) {
             _isInformationChecked.value = false
@@ -571,7 +635,7 @@ constructor(
             flow5: Flow<T5>,
             flow6: Flow<T6>,
             flow7: Flow<T7>,
-            crossinline transform: suspend (T1, T2, T3, T4, T5, T6, T7) -> R
+            crossinline transform: suspend (T1, T2, T3, T4, T5, T6, T7) -> R,
         ): Flow<R> {
             return combine(flow, flow2, flow3, flow4, flow5, flow6, flow7) { args: Array<*> ->
                 @Suppress("UNCHECKED_CAST")
diff --git a/src/com/android/wallpaper/picker/preview/ui/viewmodel/StaticWallpaperPreviewViewModel.kt b/src/com/android/wallpaper/picker/preview/ui/viewmodel/StaticWallpaperPreviewViewModel.kt
index 1c012de8..1386b657 100644
--- a/src/com/android/wallpaper/picker/preview/ui/viewmodel/StaticWallpaperPreviewViewModel.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/viewmodel/StaticWallpaperPreviewViewModel.kt
@@ -29,6 +29,7 @@ import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import com.android.wallpaper.picker.preview.domain.interactor.WallpaperPreviewInteractor
 import com.android.wallpaper.picker.preview.shared.model.FullPreviewCropModel
 import com.android.wallpaper.picker.preview.ui.WallpaperPreviewActivity
+import com.android.wallpaper.util.DisplaysProvider
 import dagger.hilt.android.qualifiers.ApplicationContext
 import dagger.hilt.android.scopes.ViewModelScoped
 import javax.inject.Inject
@@ -40,6 +41,7 @@ import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.SharingStarted
 import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.flow.distinctUntilChanged
+import kotlinx.coroutines.flow.filter
 import kotlinx.coroutines.flow.filterNotNull
 import kotlinx.coroutines.flow.flowOn
 import kotlinx.coroutines.flow.map
@@ -56,6 +58,7 @@ constructor(
     private val wallpaperPreferences: WallpaperPreferences,
     @BackgroundDispatcher private val bgDispatcher: CoroutineDispatcher,
     viewModelScope: CoroutineScope,
+    displaysProvider: DisplaysProvider,
 ) {
     /**
      * The state of static wallpaper crop in full preview, before user confirmation.
@@ -115,40 +118,47 @@ constructor(
                 } else {
                     val (dimensions, bitmap, asset) = assetDetail
                     bitmap?.let {
-                        FullResWallpaperViewModel(
-                            bitmap,
-                            dimensions,
-                            asset,
-                            cropHintsInfo,
-                        )
+                        FullResWallpaperViewModel(bitmap, dimensions, asset, cropHintsInfo)
                     }
                 }
             }
             .flowOn(bgDispatcher)
     val subsamplingScaleImageViewModel: Flow<FullResWallpaperViewModel> =
         fullResWallpaperViewModel.filterNotNull()
+
+    // At least as many crops as how many displays, it could be more due to the orientation. Or when
+    // no crops ever set, unblocks down stream for default behavior.
+    private val hasAllDisplayCrops: Flow<Boolean> =
+        cropHintsInfo.map { it == null || it.size >= displaysProvider.getInternalDisplays().size }
+
     // TODO (b/315856338): cache wallpaper colors in preferences
     private val storedWallpaperColors: Flow<WallpaperColors?> =
         staticWallpaperModel
             .map { wallpaperPreferences.getWallpaperColors(it.commonWallpaperData.id.uniqueId) }
             .distinctUntilChanged()
     val wallpaperColors: Flow<WallpaperColorsModel> =
-        combine(storedWallpaperColors, subsamplingScaleImageViewModel, cropHints) {
-            storedColors,
-            wallpaperViewModel,
-            cropHints ->
-            WallpaperColorsModel.Loaded(
-                if (cropHints == null) {
-                    storedColors
-                        ?: interactor.getWallpaperColors(
+        combine(
+                storedWallpaperColors,
+                subsamplingScaleImageViewModel,
+                cropHints,
+                hasAllDisplayCrops.filter { it },
+            ) { storedColors, wallpaperViewModel, cropHints, _ ->
+                WallpaperColorsModel.Loaded(
+                    if (cropHints == null) {
+                        storedColors
+                            ?: interactor.getWallpaperColors(
+                                wallpaperViewModel.rawWallpaperBitmap,
+                                null,
+                            )
+                    } else {
+                        interactor.getWallpaperColors(
                             wallpaperViewModel.rawWallpaperBitmap,
-                            null
+                            cropHints,
                         )
-                } else {
-                    interactor.getWallpaperColors(wallpaperViewModel.rawWallpaperBitmap, cropHints)
-                }
-            )
-        }
+                    }
+                )
+            }
+            .distinctUntilChanged()
 
     /**
      * Updates new cropHints per displaySize that's been confirmed by the user or from a new default
@@ -160,7 +170,7 @@ constructor(
      */
     fun updateCropHintsInfo(
         cropHintsInfo: Map<Point, FullPreviewCropModel>,
-        updateDefaultCrop: Boolean = false
+        updateDefaultCrop: Boolean = false,
     ) {
         val newInfo =
             this.cropHintsInfo.value?.let { currentCropHintsInfo ->
@@ -208,6 +218,7 @@ constructor(
         @ApplicationContext private val context: Context,
         private val wallpaperPreferences: WallpaperPreferences,
         @BackgroundDispatcher private val bgDispatcher: CoroutineDispatcher,
+        private val displaysProvider: DisplaysProvider,
     ) {
         fun create(viewModelScope: CoroutineScope): StaticWallpaperPreviewViewModel {
             return StaticWallpaperPreviewViewModel(
@@ -216,6 +227,7 @@ constructor(
                 wallpaperPreferences = wallpaperPreferences,
                 bgDispatcher = bgDispatcher,
                 viewModelScope = viewModelScope,
+                displaysProvider = displaysProvider,
             )
         }
     }
diff --git a/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModel.kt b/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModel.kt
index 00bd0883..e0101da4 100644
--- a/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModel.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModel.kt
@@ -29,8 +29,8 @@ import com.android.wallpaper.picker.customization.shared.model.WallpaperDestinat
 import com.android.wallpaper.picker.data.WallpaperModel
 import com.android.wallpaper.picker.data.WallpaperModel.LiveWallpaperModel
 import com.android.wallpaper.picker.data.WallpaperModel.StaticWallpaperModel
-import com.android.wallpaper.picker.di.modules.PreviewUtilsModule.HomeScreenPreviewUtils
-import com.android.wallpaper.picker.di.modules.PreviewUtilsModule.LockScreenPreviewUtils
+import com.android.wallpaper.picker.di.modules.HomeScreenPreviewUtils
+import com.android.wallpaper.picker.di.modules.LockScreenPreviewUtils
 import com.android.wallpaper.picker.preview.data.repository.ImageEffectsRepository
 import com.android.wallpaper.picker.preview.domain.interactor.PreviewActionsInteractor
 import com.android.wallpaper.picker.preview.domain.interactor.WallpaperPreviewInteractor
diff --git a/src/com/android/wallpaper/picker/preview/ui/viewmodel/floatingSheet/InformationFloatingSheetViewModel.kt b/src/com/android/wallpaper/picker/preview/ui/viewmodel/floatingSheet/InformationFloatingSheetViewModel.kt
index c14bd791..9eeee9ec 100644
--- a/src/com/android/wallpaper/picker/preview/ui/viewmodel/floatingSheet/InformationFloatingSheetViewModel.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/viewmodel/floatingSheet/InformationFloatingSheetViewModel.kt
@@ -19,5 +19,6 @@ package com.android.wallpaper.picker.preview.ui.viewmodel.floatingSheet
 /** This data class represents the view data for the info floating sheet */
 data class InformationFloatingSheetViewModel(
     val attributions: List<String?>?,
-    val exploreActionUrl: String?,
+    val actionUrl: String?,
+    val actionButtonTitle: CharSequence? = null,
 )
diff --git a/src/com/android/wallpaper/util/ActivityUtils.java b/src/com/android/wallpaper/util/ActivityUtils.java
index c6ffc61e..9d9e1194 100755
--- a/src/com/android/wallpaper/util/ActivityUtils.java
+++ b/src/com/android/wallpaper/util/ActivityUtils.java
@@ -15,9 +15,9 @@
  */
 package com.android.wallpaper.util;
 
-import static com.android.wallpaper.util.LaunchSourceUtils.LAUNCH_SETTINGS_SEARCH;
 import static com.android.wallpaper.util.LaunchSourceUtils.LAUNCH_SOURCE_SETTINGS;
 import static com.android.wallpaper.util.LaunchSourceUtils.LAUNCH_SOURCE_SETTINGS_HOMEPAGE;
+import static com.android.wallpaper.util.LaunchSourceUtils.LAUNCH_SOURCE_SETTINGS_SEARCH;
 import static com.android.wallpaper.util.LaunchSourceUtils.WALLPAPER_LAUNCH_SOURCE;
 
 import android.app.Activity;
@@ -29,6 +29,8 @@ import android.text.TextUtils;
 import android.util.Log;
 import android.widget.Toast;
 
+import androidx.annotation.NonNull;
+
 import com.android.wallpaper.R;
 
 /**
@@ -66,6 +68,10 @@ public final class ActivityUtils {
      * @param intent activity intent.
      */
     public static boolean isLaunchedFromSettingsRelated(Intent intent) {
+        if (intent == null) {
+            return false;
+        }
+
         return isLaunchedFromSettings(intent) || isLaunchedFromSettingsSearch(intent);
     }
 
@@ -84,11 +90,12 @@ public final class ActivityUtils {
      *
      * @param intent activity intent.
      */
-    private static boolean isLaunchedFromSettings(Intent intent) {
-        return (intent != null && TextUtils.equals(LAUNCH_SOURCE_SETTINGS,
-                intent.getStringExtra(WALLPAPER_LAUNCH_SOURCE)));
+    private static boolean isLaunchedFromSettings(@NonNull Intent intent) {
+        return TextUtils.equals(LAUNCH_SOURCE_SETTINGS,
+                    intent.getStringExtra(WALLPAPER_LAUNCH_SOURCE));
     }
 
+
     private static boolean isLaunchedFromSettingsHome(Intent intent) {
         return (intent != null && intent.getBooleanExtra(LAUNCH_SOURCE_SETTINGS_HOMEPAGE, false));
     }
@@ -98,10 +105,12 @@ public final class ActivityUtils {
      *
      * @param intent activity intent.
      */
-    public static boolean isLaunchedFromSettingsSearch(Intent intent) {
-        return (intent != null && intent.hasExtra(LAUNCH_SETTINGS_SEARCH));
+    public static boolean isLaunchedFromSettingsSearch(@NonNull Intent intent) {
+        return TextUtils.equals(LAUNCH_SOURCE_SETTINGS_SEARCH,
+                intent.getStringExtra(WALLPAPER_LAUNCH_SOURCE));
     }
 
+
     /**
      * Returns true if wallpaper is in SUW mode.
      *
diff --git a/src/com/android/wallpaper/util/DeepLinkUtils.java b/src/com/android/wallpaper/util/DeepLinkUtils.java
deleted file mode 100644
index 604b64ab..00000000
--- a/src/com/android/wallpaper/util/DeepLinkUtils.java
+++ /dev/null
@@ -1,44 +0,0 @@
-/*
- * Copyright (C) 2020 The Android Open Source Project
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
-package com.android.wallpaper.util;
-
-import android.content.Intent;
-import android.net.Uri;
-
-/** Util class for deep link. */
-public class DeepLinkUtils {
-    private static final String KEY_COLLECTION_ID = "collection_id";
-    private static final String SCHEME = "https";
-    private static final String SCHEME_SPECIFIC_PART_PREFIX = "//g.co/wallpaper";
-
-    /**
-     * Checks if it is the deep link case.
-     */
-    public static boolean isDeepLink(Intent intent) {
-        Uri data = intent.getData();
-        return data != null && SCHEME.equals(data.getScheme())
-                && data.getSchemeSpecificPart().startsWith(SCHEME_SPECIFIC_PART_PREFIX);
-    }
-
-    /**
-     * Gets the wallpaper collection which wants to deep link to.
-     *
-     * @return the wallpaper collection id
-     */
-    public static String getCollectionId(Intent intent) {
-        return isDeepLink(intent) ? intent.getData().getQueryParameter(KEY_COLLECTION_ID) : null;
-    }
-}
diff --git a/src/com/android/wallpaper/util/DeepLinkUtils.kt b/src/com/android/wallpaper/util/DeepLinkUtils.kt
new file mode 100644
index 00000000..f20fa7cf
--- /dev/null
+++ b/src/com/android/wallpaper/util/DeepLinkUtils.kt
@@ -0,0 +1,46 @@
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
+package com.android.wallpaper.util
+
+import android.content.Intent
+
+/** Util class for deep link. */
+object DeepLinkUtils {
+    private const val KEY_COLLECTION_ID = "collection_id"
+    private const val SCHEME = "https"
+    private const val SCHEME_SPECIFIC_PART_PREFIX = "//g.co/wallpaper"
+    const val EXTRA_KEY_COLLECTION_ID = "extra_collection_id"
+
+    /** Checks if it is the deep link case. */
+    @JvmStatic
+    fun isDeepLink(intent: Intent): Boolean {
+        val data = intent.data
+        return data != null &&
+            SCHEME == data.scheme &&
+            data.schemeSpecificPart.startsWith(SCHEME_SPECIFIC_PART_PREFIX)
+    }
+
+    /**
+     * Gets the wallpaper collection which wants to deep link to.
+     *
+     * @return the wallpaper collection id
+     */
+    @JvmStatic
+    fun getCollectionId(intent: Intent): String? {
+        return if (isDeepLink(intent)) intent.data?.getQueryParameter(KEY_COLLECTION_ID)
+        else intent.getStringExtra(EXTRA_KEY_COLLECTION_ID)
+    }
+}
diff --git a/src/com/android/wallpaper/util/LaunchSourceUtils.kt b/src/com/android/wallpaper/util/LaunchSourceUtils.kt
index c1674487..519613e1 100644
--- a/src/com/android/wallpaper/util/LaunchSourceUtils.kt
+++ b/src/com/android/wallpaper/util/LaunchSourceUtils.kt
@@ -22,10 +22,10 @@ object LaunchSourceUtils {
     const val WALLPAPER_LAUNCH_SOURCE = "com.android.wallpaper.LAUNCH_SOURCE"
     const val LAUNCH_SOURCE_LAUNCHER = "app_launched_launcher"
     const val LAUNCH_SOURCE_SETTINGS = "app_launched_settings"
+    const val LAUNCH_SOURCE_SETTINGS_SEARCH = "app_launched_settings_search"
     const val LAUNCH_SOURCE_SUW = "app_launched_suw"
     const val LAUNCH_SOURCE_TIPS = "app_launched_tips"
     const val LAUNCH_SOURCE_DEEP_LINK = "app_launched_deeplink"
-    const val LAUNCH_SETTINGS_SEARCH = ":settings:fragment_args_key"
     const val LAUNCH_SOURCE_SETTINGS_HOMEPAGE = "is_from_settings_homepage"
     const val LAUNCH_SOURCE_KEYGUARD = "app_launched_keyguard"
 }
diff --git a/src/com/android/wallpaper/util/SurfaceViewUtils.java b/src/com/android/wallpaper/util/SurfaceViewUtils.java
deleted file mode 100644
index 0b9610e9..00000000
--- a/src/com/android/wallpaper/util/SurfaceViewUtils.java
+++ /dev/null
@@ -1,63 +0,0 @@
-/*
- * Copyright (C) 2020 The Android Open Source Project
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
-package com.android.wallpaper.util;
-
-import android.os.Bundle;
-import android.os.Message;
-import android.view.SurfaceControlViewHost;
-import android.view.SurfaceView;
-
-import androidx.annotation.Nullable;
-
-/** Util class to generate surface view requests and parse responses */
-public class SurfaceViewUtils {
-
-    private static final String KEY_HOST_TOKEN = "host_token";
-    private static final String KEY_VIEW_WIDTH = "width";
-    private static final String KEY_VIEW_HEIGHT = "height";
-    public static final String KEY_DISPLAY_ID = "display_id";
-    private static final String KEY_SURFACE_PACKAGE = "surface_package";
-    private static final String KEY_CALLBACK = "callback";
-    public static final String KEY_WALLPAPER_COLORS = "wallpaper_colors";
-
-    /** Create a surface view request. */
-    public static Bundle createSurfaceViewRequest(
-            SurfaceView surfaceView,
-            @Nullable Bundle extras) {
-        Bundle bundle = new Bundle();
-        bundle.putBinder(KEY_HOST_TOKEN, surfaceView.getHostToken());
-        // TODO (b/305258307): Figure out why SurfaceView.getDisplay returns null in small preview
-        if (surfaceView.getDisplay() != null) {
-            bundle.putInt(KEY_DISPLAY_ID, surfaceView.getDisplay().getDisplayId());
-        }
-        bundle.putInt(KEY_VIEW_WIDTH, surfaceView.getWidth());
-        bundle.putInt(KEY_VIEW_HEIGHT, surfaceView.getHeight());
-        if (extras != null) {
-            bundle.putAll(extras);
-        }
-        return bundle;
-    }
-
-    /** Return the surface package. */
-    public static SurfaceControlViewHost.SurfacePackage getSurfacePackage(Bundle bundle) {
-        return bundle.getParcelable(KEY_SURFACE_PACKAGE);
-    }
-
-    /** Return the message callback. */
-    public static Message getCallback(Bundle bundle) {
-        return bundle.getParcelable(KEY_CALLBACK);
-    }
-}
diff --git a/src/com/android/wallpaper/util/SurfaceViewUtils.kt b/src/com/android/wallpaper/util/SurfaceViewUtils.kt
new file mode 100644
index 00000000..a4eff975
--- /dev/null
+++ b/src/com/android/wallpaper/util/SurfaceViewUtils.kt
@@ -0,0 +1,74 @@
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
+package com.android.wallpaper.util
+
+import android.os.Bundle
+import android.os.Message
+import android.view.SurfaceControlViewHost
+import android.view.SurfaceHolder
+import android.view.SurfaceView
+import android.view.View
+import android.view.ViewGroup
+
+/** Util class to generate surface view requests and parse responses */
+object SurfaceViewUtils {
+    private const val KEY_HOST_TOKEN = "host_token"
+    const val KEY_VIEW_WIDTH = "width"
+    const val KEY_VIEW_HEIGHT = "height"
+    private const val KEY_SURFACE_PACKAGE = "surface_package"
+    private const val KEY_CALLBACK = "callback"
+    const val KEY_WALLPAPER_COLORS = "wallpaper_colors"
+    const val KEY_DISPLAY_ID = "display_id"
+
+    /** Create a surface view request. */
+    fun createSurfaceViewRequest(surfaceView: SurfaceView, extras: Bundle?) =
+        Bundle().apply {
+            putBinder(KEY_HOST_TOKEN, surfaceView.getHostToken())
+            // TODO(b/305258307): Figure out why SurfaceView.getDisplay returns null in small
+            //  preview
+            surfaceView.display?.let { putInt(KEY_DISPLAY_ID, it.displayId) }
+            putInt(KEY_VIEW_WIDTH, surfaceView.width)
+            putInt(KEY_VIEW_HEIGHT, surfaceView.height)
+            extras?.let { putAll(it) }
+        }
+
+    /** Return the surface package. */
+    fun getSurfacePackage(bundle: Bundle): SurfaceControlViewHost.SurfacePackage? {
+        return bundle.getParcelable(KEY_SURFACE_PACKAGE)
+    }
+
+    /** Return the message callback. */
+    fun getCallback(bundle: Bundle): Message? {
+        return bundle.getParcelable(KEY_CALLBACK)
+    }
+
+    /** Removes the view from its parent and attaches to the surface control */
+    fun SurfaceView.attachView(view: View, newWidth: Int = width, newHeight: Int = height) {
+        // Detach view from its parent, if the view has one
+        (view.parent as ViewGroup?)?.removeView(view)
+        val host = SurfaceControlViewHost(context, display, hostToken)
+        host.setView(view, newWidth, newHeight)
+        setChildSurfacePackage(checkNotNull(host.surfacePackage))
+    }
+
+    interface SurfaceCallback : SurfaceHolder.Callback {
+        override fun surfaceCreated(holder: SurfaceHolder) {}
+
+        override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {}
+
+        override fun surfaceDestroyed(holder: SurfaceHolder) {}
+    }
+}
diff --git a/src/com/android/wallpaper/util/WallpaperConnection.java b/src/com/android/wallpaper/util/WallpaperConnection.java
index d3150bb1..9e4bbd33 100644
--- a/src/com/android/wallpaper/util/WallpaperConnection.java
+++ b/src/com/android/wallpaper/util/WallpaperConnection.java
@@ -120,6 +120,7 @@ public class WallpaperConnection extends IWallpaperConnection.Stub implements Se
     private boolean mDestroyed;
     private int mDestinationFlag;
     private WhichPreview mWhichPreview;
+    private IBinder mToken;
 
     /**
      * @param intent used to bind the wallpaper service
@@ -190,31 +191,56 @@ public class WallpaperConnection extends IWallpaperConnection.Stub implements Se
      * Disconnect and destroy the WallpaperEngine for this connection.
      */
     public void disconnect() {
-        synchronized (this) {
-            mConnected = false;
-            if (mEngine != null) {
-                try {
-                    mEngine.destroy();
-                    for (SurfaceControl control : mMirrorSurfaceControls) {
-                        control.release();
-                    }
-                    mMirrorSurfaceControls.clear();
-                } catch (RemoteException e) {
-                    // Ignore
-                }
-                mEngine = null;
+        mConnected = false;
+        destroyEngine();
+        unbindService();
+        if (mListener != null) {
+            mListener.onDisconnected();
+        }
+    }
+
+    private synchronized void destroyEngine() {
+        if (mEngine == null) {
+            return;
+        }
+
+        try {
+            mEngine.destroy();
+            for (SurfaceControl control : mMirrorSurfaceControls) {
+                control.release();
             }
+            mMirrorSurfaceControls.clear();
+        } catch (RemoteException e) {
+            // Ignore
+        }
+        mEngine = null;
+    }
+
+    /**
+     * Detach the connection from wallpaper service. Generally this does not need to be called
+     * throughout an activity's active lifecycle since the same connection is used across
+     * WallpaperConnection instances, for views within the same window. Calling attachConnection
+     * should be enough to overwrite the previous connection.
+     */
+    public synchronized void detachConnection() {
+        if (mService != null) {
             try {
-                mContext.unbindService(this);
-            } catch (IllegalArgumentException e) {
-                Log.i(TAG, "Can't unbind wallpaper service. "
-                        + "It might have crashed, just ignoring.");
+                mService.detach(mToken);
+            } catch (RemoteException e) {
+                Log.i(TAG, "Can't detach wallpaper service.");
             }
-            mService = null;
         }
-        if (mListener != null) {
-            mListener.onDisconnected();
+        mToken = null;
+    }
+
+    private synchronized void unbindService() {
+        try {
+            mContext.unbindService(this);
+        } catch (IllegalArgumentException e) {
+            Log.i(TAG, "Can't unbind wallpaper service. "
+                    + "It might have crashed, just ignoring.");
         }
+        mService = null;
     }
 
     /**
@@ -387,22 +413,22 @@ public class WallpaperConnection extends IWallpaperConnection.Stub implements Se
     }
 
     private void attachConnection(int displayId) {
+        mToken = mContainerView.getWindowToken();
         try {
             try {
                 Method preUMethod = mService.getClass().getMethod("attach",
                         IWallpaperConnection.class, IBinder.class, int.class, boolean.class,
                         int.class, int.class, Rect.class, int.class);
-                preUMethod.invoke(mService, this, mContainerView.getWindowToken(),
-                        LayoutParams.TYPE_APPLICATION_MEDIA, true, mContainerView.getWidth(),
-                        mContainerView.getHeight(), new Rect(0, 0, 0, 0), displayId);
+                preUMethod.invoke(mService, this, mToken, LayoutParams.TYPE_APPLICATION_MEDIA, true,
+                        mContainerView.getWidth(), mContainerView.getHeight(), new Rect(0, 0, 0, 0),
+                        displayId);
             } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
                 Log.d(TAG, "IWallpaperService#attach method without which argument not available, "
                         + "will use newer version");
                 // Let's try the new attach method that takes "which" argument
-                mService.attach(this, mContainerView.getWindowToken(),
-                        LayoutParams.TYPE_APPLICATION_MEDIA, true, mContainerView.getWidth(),
-                        mContainerView.getHeight(), new Rect(0, 0, 0, 0), displayId,
-                        mDestinationFlag, null);
+                mService.attach(this, mToken, LayoutParams.TYPE_APPLICATION_MEDIA, true,
+                        mContainerView.getWidth(), mContainerView.getHeight(), new Rect(0, 0, 0, 0),
+                        displayId, mDestinationFlag, null);
             }
         } catch (RemoteException e) {
             Log.w(TAG, "Failed attaching wallpaper; clearing", e);
diff --git a/src/com/android/wallpaper/util/WallpaperParserImpl.kt b/src/com/android/wallpaper/util/WallpaperParserImpl.kt
index a1a4ca9b..ef122ac0 100644
--- a/src/com/android/wallpaper/util/WallpaperParserImpl.kt
+++ b/src/com/android/wallpaper/util/WallpaperParserImpl.kt
@@ -46,7 +46,7 @@ constructor(
     private val partnerProvider: PartnerProvider
 ) : WallpaperParser {
 
-    /** This method is responsible for generating list of system categories from the XML file. */
+    /** This method is responsible for parsing the XML file for system categories. */
     override fun parseSystemCategories(parser: XmlResourceParser): List<WallpaperCategory> {
         val categories = mutableListOf<WallpaperCategory>()
         try {
@@ -64,11 +64,41 @@ constructor(
                             Xml.asAttributeSet(parser)
                         )
                     categoryBuilder.setPriorityIfEmpty(PRIORITY_SYSTEM + priorityTracker++)
-                    categoryBuilder.addWallpapers(
-                        parseXmlForWallpapersForASingleCategory(parser, categoryBuilder.id)
-                    )
+                    var publishedPlaceholder = false
+                    val categoryDepth = parser.depth
+                    while (
+                        (parser.next().also { type = it } != XmlPullParser.END_TAG ||
+                            parser.depth > categoryDepth) && type != XmlPullParser.END_DOCUMENT
+                    ) {
+                        if (type == XmlPullParser.START_TAG) {
+                            val wallpaper =
+                                if (SystemStaticWallpaperInfo.TAG_NAME == parser.name) {
+                                    SystemStaticWallpaperInfo.fromAttributeSet(
+                                        partnerProvider.packageName,
+                                        categoryBuilder.id,
+                                        Xml.asAttributeSet(parser)
+                                    )
+                                } else if (LiveWallpaperInfo.TAG_NAME == parser.name) {
+                                    LiveWallpaperInfo.fromAttributeSet(
+                                        context,
+                                        categoryBuilder.id,
+                                        Xml.asAttributeSet(parser)
+                                    )
+                                } else {
+                                    null
+                                }
+                            if (wallpaper != null) {
+                                categoryBuilder.addWallpaper(wallpaper)
+                                if (!publishedPlaceholder) {
+                                    publishedPlaceholder = true
+                                }
+                            }
+                        }
+                    }
                     val category = categoryBuilder.build()
-                    category?.let { categories.add(it) }
+                    if (!category.getUnmodifiableWallpapers().isEmpty()) {
+                        categories.add(category)
+                    }
                 }
             }
         } catch (e: Exception) {
@@ -122,46 +152,6 @@ constructor(
         return wallpaperInfos
     }
 
-    /**
-     * This method is responsible for parsing the XML for a single category and returning a list of
-     * WallpaperInfo objects.
-     */
-    private fun parseXmlForWallpapersForASingleCategory(
-        parser: XmlResourceParser,
-        categoryId: String
-    ): List<WallpaperInfo> {
-        val outputWallpaperInfo = mutableListOf<WallpaperInfo>()
-        val categoryDepth = parser.depth
-        var type: Int
-        while (
-            (parser.next().also { type = it } != XmlPullParser.END_TAG ||
-                parser.depth > categoryDepth) && type != XmlPullParser.END_DOCUMENT
-        ) {
-            if (type == XmlPullParser.START_TAG) {
-                var wallpaper: WallpaperInfo? = null
-                if (SystemStaticWallpaperInfo.TAG_NAME == parser.name) {
-                    wallpaper =
-                        SystemStaticWallpaperInfo.fromAttributeSet(
-                            partnerProvider.packageName,
-                            categoryId,
-                            Xml.asAttributeSet(parser)
-                        )
-                } else if (LiveWallpaperInfo.TAG_NAME == parser.name) {
-                    wallpaper =
-                        LiveWallpaperInfo.fromAttributeSet(
-                            context,
-                            categoryId,
-                            Xml.asAttributeSet(parser)
-                        )
-                }
-                if (wallpaper != null) {
-                    outputWallpaperInfo.add(wallpaper)
-                }
-            }
-        }
-        return outputWallpaperInfo
-    }
-
     companion object {
         const val PRIORITY_SYSTEM = 100
         private const val TAG = "WallpaperXMLParser"
diff --git a/src/com/android/wallpaper/util/converter/WallpaperModelFactory.kt b/src/com/android/wallpaper/util/converter/WallpaperModelFactory.kt
index 63a01131..746ecbb1 100644
--- a/src/com/android/wallpaper/util/converter/WallpaperModelFactory.kt
+++ b/src/com/android/wallpaper/util/converter/WallpaperModelFactory.kt
@@ -111,6 +111,7 @@ interface WallpaperModelFactory {
             val currentHomeWallpaper =
                 wallpaperManager.getWallpaperInfo(WallpaperManager.FLAG_SYSTEM)
             val currentLockWallpaper = wallpaperManager.getWallpaperInfo(WallpaperManager.FLAG_LOCK)
+            val contextDescription: CharSequence? = this.getActionDescription(context)
             return LiveWallpaperData(
                 groupName = groupNameOfWallpaper,
                 systemWallpaperInfo = info,
@@ -118,9 +119,10 @@ interface WallpaperModelFactory {
                 isApplied = isApplied(currentHomeWallpaper, currentLockWallpaper),
                 // TODO (331227828): don't relay on effectNames to determine if this is an effect
                 // live wallpaper
-                isEffectWallpaper = effectsController?.isEffectsWallpaper(info)
-                        ?: (effectNames != null),
+                isEffectWallpaper =
+                    effectsController?.isEffectsWallpaper(info) ?: (effectNames != null),
                 effectNames = effectNames,
+                contextDescription = contextDescription,
             )
         }
 
diff --git a/src/com/android/wallpaper/util/converter/category/CategoryFactory.kt b/src/com/android/wallpaper/util/converter/category/CategoryFactory.kt
index 8e3ba426..10d55991 100644
--- a/src/com/android/wallpaper/util/converter/category/CategoryFactory.kt
+++ b/src/com/android/wallpaper/util/converter/category/CategoryFactory.kt
@@ -16,11 +16,10 @@
 
 package com.android.wallpaper.util.converter.category
 
-import android.content.Context
 import com.android.wallpaper.model.Category
 import com.android.wallpaper.picker.data.category.CategoryModel
 
 /** This is the interface for converting legacy category to the new category model class. */
 interface CategoryFactory {
-    fun getCategoryModel(context: Context, category: Category): CategoryModel
+    fun getCategoryModel(category: Category): CategoryModel
 }
diff --git a/src/com/android/wallpaper/util/converter/category/DefaultCategoryFactory.kt b/src/com/android/wallpaper/util/converter/category/DefaultCategoryFactory.kt
index f0e06b8a..c87ee083 100644
--- a/src/com/android/wallpaper/util/converter/category/DefaultCategoryFactory.kt
+++ b/src/com/android/wallpaper/util/converter/category/DefaultCategoryFactory.kt
@@ -28,6 +28,7 @@ import com.android.wallpaper.picker.data.category.CommonCategoryData
 import com.android.wallpaper.picker.data.category.ImageCategoryData
 import com.android.wallpaper.picker.data.category.ThirdPartyCategoryData
 import com.android.wallpaper.util.converter.WallpaperModelFactory
+import dagger.hilt.android.qualifiers.ApplicationContext
 import javax.inject.Inject
 import javax.inject.Singleton
 
@@ -35,14 +36,16 @@ import javax.inject.Singleton
 @Singleton
 class DefaultCategoryFactory
 @Inject
-constructor(private val wallpaperModelFactory: WallpaperModelFactory) : CategoryFactory {
+constructor(
+    @ApplicationContext private val context: Context,
+    private val wallpaperModelFactory: WallpaperModelFactory,
+) : CategoryFactory {
 
-    override fun getCategoryModel(context: Context, category: Category): CategoryModel {
+    override fun getCategoryModel(category: Category): CategoryModel {
         return CategoryModel(
             commonCategoryData = getCommonCategoryData(category),
-            collectionCategoryData =
-                (category as? WallpaperCategory)?.getCollectionsCategoryData(context),
-            imageCategoryData = getImageCategoryData(category, context),
+            collectionCategoryData = (category as? WallpaperCategory)?.getCollectionsCategoryData(),
+            imageCategoryData = getImageCategoryData(category),
             thirdPartyCategoryData = getThirdPartyCategoryData(category)
         )
     }
@@ -55,9 +58,7 @@ constructor(private val wallpaperModelFactory: WallpaperModelFactory) : Category
         )
     }
 
-    private fun WallpaperCategory.getCollectionsCategoryData(
-        context: Context
-    ): CollectionCategoryData {
+    private fun WallpaperCategory.getCollectionsCategoryData(): CollectionCategoryData {
         val wallpaperModelList =
             wallpapers
                 .map { wallpaperInfo ->
@@ -72,9 +73,12 @@ constructor(private val wallpaperModelFactory: WallpaperModelFactory) : Category
         )
     }
 
-    private fun getImageCategoryData(category: Category, context: Context): ImageCategoryData? {
+    private fun getImageCategoryData(category: Category): ImageCategoryData? {
         return if (category is ImageCategory) {
-            ImageCategoryData(overlayIconDrawable = category.getOverlayIcon(context))
+            ImageCategoryData(
+                thumbnailAsset = category.getThumbnail(context),
+                defaultDrawable = category.getOverlayIcon(context)
+            )
         } else {
             Log.w(TAG, "Passed category is not of type ImageCategory")
             null
diff --git a/src/com/android/wallpaper/util/wallpaperconnection/WallpaperConnectionUtils.kt b/src/com/android/wallpaper/util/wallpaperconnection/WallpaperConnectionUtils.kt
index feccb3a6..0391e5a8 100644
--- a/src/com/android/wallpaper/util/wallpaperconnection/WallpaperConnectionUtils.kt
+++ b/src/com/android/wallpaper/util/wallpaperconnection/WallpaperConnectionUtils.kt
@@ -9,6 +9,7 @@ import android.content.ServiceConnection
 import android.graphics.Matrix
 import android.graphics.Point
 import android.net.Uri
+import android.os.IBinder
 import android.os.RemoteException
 import android.service.wallpaper.IWallpaperEngine
 import android.service.wallpaper.IWallpaperService
@@ -22,8 +23,12 @@ import com.android.wallpaper.model.wallpaper.DeviceDisplayType
 import com.android.wallpaper.picker.data.WallpaperModel.LiveWallpaperModel
 import com.android.wallpaper.util.WallpaperConnection
 import com.android.wallpaper.util.WallpaperConnection.WhichPreview
+import dagger.hilt.android.scopes.ActivityRetainedScoped
+import java.lang.ref.WeakReference
 import java.util.concurrent.ConcurrentHashMap
+import javax.inject.Inject
 import kotlinx.coroutines.CancellableContinuation
+import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.Deferred
 import kotlinx.coroutines.async
 import kotlinx.coroutines.coroutineScope
@@ -31,13 +36,11 @@ import kotlinx.coroutines.suspendCancellableCoroutine
 import kotlinx.coroutines.sync.Mutex
 import kotlinx.coroutines.sync.withLock
 
-object WallpaperConnectionUtils {
-
-    const val TAG = "WallpaperConnectionUtils"
+@ActivityRetainedScoped
+class WallpaperConnectionUtils @Inject constructor() {
 
     // engineMap and surfaceControlMap are used for disconnecting wallpaper services.
-    private val engineMap =
-        ConcurrentHashMap<String, Deferred<Pair<ServiceConnection, WallpaperEngineConnection>>>()
+    private val wallpaperConnectionMap = ConcurrentHashMap<String, Deferred<WallpaperConnection>>()
     // Note that when one wallpaper engine's render is mirrored to a new surface view, we call
     // engine.mirrorSurfaceControl() and will have a new surface control instance.
     private val surfaceControlMap = mutableMapOf<String, MutableList<SurfaceControl>>()
@@ -55,7 +58,7 @@ object WallpaperConnectionUtils {
         destinationFlag: Int,
         surfaceView: SurfaceView,
         engineRenderingConfig: EngineRenderingConfig,
-        isFirstBinding: Boolean,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
         listener: WallpaperEngineConnection.WallpaperEngineConnectionListener? = null,
     ) {
         val wallpaperInfo = wallpaperModel.liveWallpaperData.systemWallpaperInfo
@@ -70,7 +73,7 @@ object WallpaperConnectionUtils {
                     mutex.withLock {
                         if (!creativeWallpaperConfigPreviewUriMap.containsKey(uriKey)) {
                             // First time binding wallpaper should initialize wallpaper preview.
-                            if (isFirstBinding) {
+                            if (isFirstBindingDeferred.await()) {
                                 context.contentResolver.update(it, ContentValues(), null)
                             }
                             creativeWallpaperConfigPreviewUriMap[uriKey] = it
@@ -79,10 +82,10 @@ object WallpaperConnectionUtils {
                 }
             }
 
-            if (!engineMap.containsKey(engineKey)) {
+            if (!wallpaperConnectionMap.containsKey(engineKey)) {
                 mutex.withLock {
-                    if (!engineMap.containsKey(engineKey)) {
-                        engineMap[engineKey] = coroutineScope {
+                    if (!wallpaperConnectionMap.containsKey(engineKey)) {
+                        wallpaperConnectionMap[engineKey] = coroutineScope {
                             async {
                                 initEngine(
                                     context,
@@ -99,8 +102,8 @@ object WallpaperConnectionUtils {
                 }
             }
 
-            engineMap[engineKey]?.await()?.let { (_, engineConnection) ->
-                engineConnection.engine?.let {
+            wallpaperConnectionMap[engineKey]?.await()?.let { (engineConnection, _, _, _) ->
+                engineConnection.get()?.engine?.let {
                     mirrorAndReparent(
                         engineKey,
                         it,
@@ -113,43 +116,17 @@ object WallpaperConnectionUtils {
         }
     }
 
-    suspend fun disconnect(
-        context: Context,
-        wallpaperModel: LiveWallpaperModel,
-        displaySize: Point,
-    ) {
-        val engineKey = wallpaperModel.liveWallpaperData.systemWallpaperInfo.getKey(displaySize)
-
-        traceAsync(TAG, "disconnect") {
-            if (engineMap.containsKey(engineKey)) {
-                mutex.withLock {
-                    engineMap.remove(engineKey)?.await()?.let {
-                        (serviceConnection, engineConnection) ->
-                        engineConnection.engine?.destroy()
-                        engineConnection.removeListener()
-                        context.unbindService(serviceConnection)
-                    }
-                }
-            }
-
-            if (surfaceControlMap.containsKey(engineKey)) {
-                mutex.withLock {
-                    surfaceControlMap.remove(engineKey)?.let { surfaceControls ->
-                        surfaceControls.forEach { it.release() }
-                        surfaceControls.clear()
-                    }
-                }
-            }
-
-            val uriKey = wallpaperModel.liveWallpaperData.systemWallpaperInfo.getKey()
-            if (creativeWallpaperConfigPreviewUriMap.containsKey(uriKey)) {
-                mutex.withLock {
-                    if (creativeWallpaperConfigPreviewUriMap.containsKey(uriKey)) {
-                        creativeWallpaperConfigPreviewUriMap.remove(uriKey)
-                    }
+    suspend fun disconnectAll(context: Context) {
+        disconnectAllServices(context)
+        surfaceControlMap.keys.map { key ->
+            mutex.withLock {
+                surfaceControlMap[key]?.let { surfaceControls ->
+                    surfaceControls.forEach { it.release() }
+                    surfaceControls.clear()
                 }
             }
         }
+        surfaceControlMap.clear()
     }
 
     /**
@@ -161,14 +138,8 @@ object WallpaperConnectionUtils {
      * when switching from static to live wallpapers again.
      */
     suspend fun disconnectAllServices(context: Context) {
-        engineMap.keys.map { key ->
-            mutex.withLock {
-                engineMap.remove(key)?.await()?.let { (serviceConnection, engineConnection) ->
-                    engineConnection.engine?.destroy()
-                    engineConnection.removeListener()
-                    context.unbindService(serviceConnection)
-                }
-            }
+        wallpaperConnectionMap.keys.map { key ->
+            mutex.withLock { wallpaperConnectionMap.remove(key)?.await()?.disconnect(context) }
         }
 
         creativeWallpaperConfigPreviewUriMap.clear()
@@ -182,7 +153,9 @@ object WallpaperConnectionUtils {
         val engine =
             wallpaperModel.liveWallpaperData.systemWallpaperInfo
                 .getKey(engineRenderingConfig.getEngineDisplaySize())
-                .let { engineKey -> engineMap[engineKey]?.await()?.second?.engine }
+                .let { engineKey ->
+                    wallpaperConnectionMap[engineKey]?.await()?.engineConnection?.get()?.engine
+                }
 
         if (engine != null) {
             val action: Int = event.actionMasked
@@ -227,14 +200,19 @@ object WallpaperConnectionUtils {
         whichPreview: WhichPreview,
         surfaceView: SurfaceView,
         listener: WallpaperEngineConnection.WallpaperEngineConnectionListener?,
-    ): Pair<ServiceConnection, WallpaperEngineConnection> {
+    ): WallpaperConnection {
         // Bind service and get service connection and wallpaper service
         val (serviceConnection, wallpaperService) = bindWallpaperService(context, wallpaperIntent)
         val engineConnection = WallpaperEngineConnection(displayMetrics, whichPreview)
         listener?.let { engineConnection.setListener(it) }
         // Attach wallpaper connection to service and get wallpaper engine
         engineConnection.getEngine(wallpaperService, destinationFlag, surfaceView)
-        return Pair(serviceConnection, engineConnection)
+        return WallpaperConnection(
+            WeakReference(engineConnection),
+            WeakReference(serviceConnection),
+            WeakReference(wallpaperService),
+            WeakReference(surfaceView.windowToken),
+        )
     }
 
     private fun WallpaperInfo.getKey(displaySize: Point? = null): String {
@@ -259,7 +237,11 @@ object WallpaperConnectionUtils {
                             serviceConnection: ServiceConnection,
                             wallpaperService: IWallpaperService
                         ) {
-                            k.resumeWith(Result.success(Pair(serviceConnection, wallpaperService)))
+                            if (k.isActive) {
+                                k.resumeWith(
+                                    Result.success(Pair(serviceConnection, wallpaperService))
+                                )
+                            }
                         }
                     }
                 )
@@ -271,7 +253,7 @@ object WallpaperConnectionUtils {
                         Context.BIND_IMPORTANT or
                         Context.BIND_ALLOW_ACTIVITY_STARTS
                 )
-            if (!success) {
+            if (!success && k.isActive) {
                 k.resumeWith(Result.failure(Exception("Fail to bind the live wallpaper service.")))
             }
         }
@@ -342,35 +324,56 @@ object WallpaperConnectionUtils {
         return values
     }
 
-    data class EngineRenderingConfig(
-        val enforceSingleEngine: Boolean,
-        val deviceDisplayType: DeviceDisplayType,
-        val smallDisplaySize: Point,
-        val wallpaperDisplaySize: Point,
+    data class WallpaperConnection(
+        val engineConnection: WeakReference<WallpaperEngineConnection>,
+        val serviceConnection: WeakReference<ServiceConnection>,
+        val wallpaperService: WeakReference<IWallpaperService>,
+        val windowToken: WeakReference<IBinder>,
     ) {
-        fun getEngineDisplaySize(): Point {
-            // If we need to enforce single engine, always return the larger screen's preview
-            return if (enforceSingleEngine) {
-                return wallpaperDisplaySize
-            } else {
-                getPreviewDisplaySize()
+        fun disconnect(context: Context) {
+            engineConnection.get()?.apply {
+                engine?.destroy()
+                removeListener()
+                engine = null
             }
+            windowToken.get()?.let { wallpaperService.get()?.detach(it) }
+            serviceConnection.get()?.let { context.unbindService(it) }
         }
+    }
+
+    companion object {
+        const val TAG = "WallpaperConnectionUtils"
+
+        data class EngineRenderingConfig(
+            val enforceSingleEngine: Boolean,
+            val deviceDisplayType: DeviceDisplayType,
+            val smallDisplaySize: Point,
+            val wallpaperDisplaySize: Point,
+        ) {
+            fun getEngineDisplaySize(): Point {
+                // If we need to enforce single engine, always return the larger screen's preview
+                return if (enforceSingleEngine) {
+                    return wallpaperDisplaySize
+                } else {
+                    getPreviewDisplaySize()
+                }
+            }
 
-        private fun getPreviewDisplaySize(): Point {
-            return when (deviceDisplayType) {
-                DeviceDisplayType.SINGLE -> wallpaperDisplaySize
-                DeviceDisplayType.FOLDED -> smallDisplaySize
-                DeviceDisplayType.UNFOLDED -> wallpaperDisplaySize
+            private fun getPreviewDisplaySize(): Point {
+                return when (deviceDisplayType) {
+                    DeviceDisplayType.SINGLE -> wallpaperDisplaySize
+                    DeviceDisplayType.FOLDED -> smallDisplaySize
+                    DeviceDisplayType.UNFOLDED -> wallpaperDisplaySize
+                }
             }
         }
-    }
 
-    fun LiveWallpaperModel.shouldEnforceSingleEngine(): Boolean {
-        return when {
-            creativeWallpaperData != null -> false
-            liveWallpaperData.isEffectWallpaper -> false
-            else -> true // Only fallback to single engine rendering for legacy live wallpapers
+        fun LiveWallpaperModel.shouldEnforceSingleEngine(): Boolean {
+            return when {
+                creativeWallpaperData != null -> false
+                liveWallpaperData.isEffectWallpaper -> false
+                else -> true // Only fallback to single engine rendering for legacy live wallpapers
+            }
         }
     }
 }
diff --git a/src_override/com/android/wallpaper/modules/WallpaperPicker2ActivityModule.kt b/src_override/com/android/wallpaper/modules/WallpaperPicker2ActivityModule.kt
index eb5d6edc..a88b0cbd 100644
--- a/src_override/com/android/wallpaper/modules/WallpaperPicker2ActivityModule.kt
+++ b/src_override/com/android/wallpaper/modules/WallpaperPicker2ActivityModule.kt
@@ -16,6 +16,8 @@
 
 package com.android.wallpaper.modules
 
+import com.android.customization.picker.clock.ui.view.ClockViewFactory
+import com.android.customization.picker.clock.ui.view.DefaultClockViewFactory
 import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil
 import com.android.wallpaper.picker.customization.ui.util.DefaultCustomizationOptionUtil
 import dagger.Binds
@@ -28,6 +30,10 @@ import dagger.hilt.android.scopes.ActivityScoped
 @InstallIn(ActivityComponent::class)
 abstract class WallpaperPicker2ActivityModule {
 
+    @Binds
+    @ActivityScoped
+    abstract fun bindClockViewFactory(impl: DefaultClockViewFactory): ClockViewFactory
+
     @Binds
     @ActivityScoped
     abstract fun bindCustomizationOptionUtil(
diff --git a/src_override/com/android/wallpaper/picker/di/modules/EffectsModule.kt b/src_override/com/android/wallpaper/modules/WallpaperPicker2ActivityRetainedModule.kt
similarity index 55%
rename from src_override/com/android/wallpaper/picker/di/modules/EffectsModule.kt
rename to src_override/com/android/wallpaper/modules/WallpaperPicker2ActivityRetainedModule.kt
index 4fc0fbb7..c1ecd6b6 100644
--- a/src_override/com/android/wallpaper/picker/di/modules/EffectsModule.kt
+++ b/src_override/com/android/wallpaper/modules/WallpaperPicker2ActivityRetainedModule.kt
@@ -13,22 +13,24 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.wallpaper.picker.di.modules
 
-import com.android.wallpaper.effects.DefaultEffectsController
-import com.android.wallpaper.effects.EffectsController
+package com.android.wallpaper.modules
+
+import com.android.wallpaper.picker.preview.data.util.DefaultLiveWallpaperDownloader
+import com.android.wallpaper.picker.preview.data.util.LiveWallpaperDownloader
 import dagger.Binds
 import dagger.Module
 import dagger.hilt.InstallIn
-import dagger.hilt.components.SingletonComponent
-import javax.inject.Singleton
+import dagger.hilt.android.components.ActivityRetainedComponent
+import dagger.hilt.android.scopes.ActivityRetainedScoped
 
-/** This class provides the singleton scoped effects controller for wallpaper picker. */
-@InstallIn(SingletonComponent::class)
 @Module
-abstract class EffectsModule {
+@InstallIn(ActivityRetainedComponent::class)
+abstract class WallpaperPicker2ActivityRetainedModule {
 
     @Binds
-    @Singleton
-    abstract fun bindEffectsController(impl: DefaultEffectsController): EffectsController
+    @ActivityRetainedScoped
+    abstract fun bindLiveWallpaperDownloader(
+        impl: DefaultLiveWallpaperDownloader
+    ): LiveWallpaperDownloader
 }
diff --git a/src_override/com/android/wallpaper/modules/WallpaperPicker2AppModule.kt b/src_override/com/android/wallpaper/modules/WallpaperPicker2AppModule.kt
index d963e51a..072e3d76 100644
--- a/src_override/com/android/wallpaper/modules/WallpaperPicker2AppModule.kt
+++ b/src_override/com/android/wallpaper/modules/WallpaperPicker2AppModule.kt
@@ -15,7 +15,8 @@
  */
 package com.android.wallpaper.modules
 
-import android.content.Context
+import com.android.wallpaper.effects.DefaultEffectsController
+import com.android.wallpaper.effects.EffectsController
 import com.android.wallpaper.module.DefaultPartnerProvider
 import com.android.wallpaper.module.DefaultWallpaperPreferences
 import com.android.wallpaper.module.Injector
@@ -24,10 +25,22 @@ import com.android.wallpaper.module.WallpaperPicker2Injector
 import com.android.wallpaper.module.WallpaperPreferences
 import com.android.wallpaper.module.logging.NoOpUserEventLogger
 import com.android.wallpaper.module.logging.UserEventLogger
+import com.android.wallpaper.picker.category.domain.interactor.CategoriesLoadingStatusInteractor
+import com.android.wallpaper.picker.category.domain.interactor.CategoryInteractor
+import com.android.wallpaper.picker.category.domain.interactor.CreativeCategoryInteractor
+import com.android.wallpaper.picker.category.domain.interactor.implementations.CategoryInteractorImpl
+import com.android.wallpaper.picker.category.domain.interactor.implementations.CreativeCategoryInteractorImpl
+import com.android.wallpaper.picker.category.domain.interactor.implementations.DefaultCategoriesLoadingStatusInteractor
+import com.android.wallpaper.picker.category.ui.view.providers.IndividualPickerFactory
+import com.android.wallpaper.picker.category.ui.view.providers.implementation.DefaultIndividualPickerFactory
+import com.android.wallpaper.picker.category.wrapper.DefaultWallpaperCategoryWrapper
+import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper
+import com.android.wallpaper.picker.common.preview.ui.binder.DefaultWorkspaceCallbackBinder
+import com.android.wallpaper.picker.common.preview.ui.binder.WorkspaceCallbackBinder
 import com.android.wallpaper.picker.customization.ui.binder.CustomizationOptionsBinder
 import com.android.wallpaper.picker.customization.ui.binder.DefaultCustomizationOptionsBinder
-import com.android.wallpaper.picker.preview.data.util.DefaultLiveWallpaperDownloader
-import com.android.wallpaper.picker.preview.data.util.LiveWallpaperDownloader
+import com.android.wallpaper.picker.customization.ui.binder.DefaultToolbarBinder
+import com.android.wallpaper.picker.customization.ui.binder.ToolbarBinder
 import com.android.wallpaper.picker.preview.ui.util.DefaultImageEffectDialogUtil
 import com.android.wallpaper.picker.preview.ui.util.ImageEffectDialogUtil
 import com.android.wallpaper.util.converter.DefaultWallpaperModelFactory
@@ -36,51 +49,82 @@ import dagger.Binds
 import dagger.Module
 import dagger.Provides
 import dagger.hilt.InstallIn
-import dagger.hilt.android.qualifiers.ApplicationContext
 import dagger.hilt.components.SingletonComponent
 import javax.inject.Singleton
 
 @Module
 @InstallIn(SingletonComponent::class)
 abstract class WallpaperPicker2AppModule {
-    @Binds @Singleton abstract fun bindInjector(impl: WallpaperPicker2Injector): Injector
 
     @Binds
     @Singleton
-    abstract fun bindWallpaperModelFactory(
-        impl: DefaultWallpaperModelFactory
-    ): WallpaperModelFactory
+    abstract fun bindCreativeCategoryInteractor(
+        impl: CreativeCategoryInteractorImpl
+    ): CreativeCategoryInteractor
 
     @Binds
     @Singleton
-    abstract fun bindLiveWallpaperDownloader(
-        impl: DefaultLiveWallpaperDownloader
-    ): LiveWallpaperDownloader
+    abstract fun bindCustomizationOptionsBinder(
+        impl: DefaultCustomizationOptionsBinder
+    ): CustomizationOptionsBinder
 
     @Binds
     @Singleton
-    abstract fun bindPartnerProvider(impl: DefaultPartnerProvider): PartnerProvider
+    abstract fun bindEffectsController(impl: DefaultEffectsController): EffectsController
+
+    @Binds
+    @Singleton
+    abstract fun bindGoogleCategoryInteractor(impl: CategoryInteractorImpl): CategoryInteractor
 
     @Binds
     @Singleton
-    abstract fun bindEffectsWallpaperDialogUtil(
+    abstract fun bindImageEffectDialogUtil(
         impl: DefaultImageEffectDialogUtil
     ): ImageEffectDialogUtil
 
     @Binds
     @Singleton
-    abstract fun bindCustomizationOptionsBinder(
-        impl: DefaultCustomizationOptionsBinder
-    ): CustomizationOptionsBinder
+    abstract fun bindIndividualPickerFactory(
+        impl: DefaultIndividualPickerFactory
+    ): IndividualPickerFactory
+
+    @Binds @Singleton abstract fun bindInjector(impl: WallpaperPicker2Injector): Injector
+
+    @Binds
+    @Singleton
+    abstract fun bindLoadingStatusInteractor(
+        impl: DefaultCategoriesLoadingStatusInteractor
+    ): CategoriesLoadingStatusInteractor
+
+    @Binds
+    @Singleton
+    abstract fun bindPartnerProvider(impl: DefaultPartnerProvider): PartnerProvider
+
+    @Binds @Singleton abstract fun bindToolbarBinder(impl: DefaultToolbarBinder): ToolbarBinder
+
+    @Binds
+    @Singleton
+    abstract fun bindWallpaperCategoryWrapper(
+        impl: DefaultWallpaperCategoryWrapper
+    ): WallpaperCategoryWrapper
+
+    @Binds
+    @Singleton
+    abstract fun bindWallpaperModelFactory(
+        impl: DefaultWallpaperModelFactory
+    ): WallpaperModelFactory
+
+    @Binds
+    @Singleton
+    abstract fun bindWallpaperPreferences(impl: DefaultWallpaperPreferences): WallpaperPreferences
+
+    @Binds
+    @Singleton
+    abstract fun bindWorkspaceCallbackBinder(
+        impl: DefaultWorkspaceCallbackBinder
+    ): WorkspaceCallbackBinder
 
     companion object {
-        @Provides
-        @Singleton
-        fun provideWallpaperPreferences(
-            @ApplicationContext context: Context
-        ): WallpaperPreferences {
-            return DefaultWallpaperPreferences(context)
-        }
 
         @Provides
         @Singleton
diff --git a/src_override/com/android/wallpaper/modules/WallpaperPicker2ViewModelModule.kt b/src_override/com/android/wallpaper/modules/WallpaperPicker2ViewModelModule.kt
index 245b2f5e..27f5bb57 100644
--- a/src_override/com/android/wallpaper/modules/WallpaperPicker2ViewModelModule.kt
+++ b/src_override/com/android/wallpaper/modules/WallpaperPicker2ViewModelModule.kt
@@ -16,7 +16,7 @@
 
 package com.android.wallpaper.modules
 
-import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModelFactory
 import com.android.wallpaper.picker.customization.ui.viewmodel.DefaultCustomizationOptionsViewModel
 import dagger.Binds
 import dagger.Module
@@ -30,7 +30,7 @@ abstract class WallpaperPicker2ViewModelModule {
 
     @Binds
     @ViewModelScoped
-    abstract fun bindCustomizationOptionsViewModel(
-        impl: DefaultCustomizationOptionsViewModel
-    ): CustomizationOptionsViewModel
+    abstract fun bindCustomizationOptionsViewModelFactory(
+        impl: DefaultCustomizationOptionsViewModel.Factory
+    ): CustomizationOptionsViewModelFactory
 }
diff --git a/src_override/com/android/wallpaper/picker/di/modules/InteractorModule.kt b/src_override/com/android/wallpaper/picker/di/modules/InteractorModule.kt
deleted file mode 100644
index 8d6f1440..00000000
--- a/src_override/com/android/wallpaper/picker/di/modules/InteractorModule.kt
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
-package com.android.wallpaper.picker.di.modules
-
-import com.android.wallpaper.picker.customization.data.repository.WallpaperRepository
-import com.android.wallpaper.picker.customization.domain.interactor.WallpaperInteractor
-import dagger.Module
-import dagger.Provides
-import dagger.hilt.InstallIn
-import dagger.hilt.components.SingletonComponent
-import javax.inject.Singleton
-
-/** This class provides the singleton scoped interactors for wallpaper picker. */
-@InstallIn(SingletonComponent::class)
-@Module
-internal object InteractorModule {
-
-    @Provides
-    @Singleton
-    fun provideWallpaperInteractor(wallpaperRepository: WallpaperRepository): WallpaperInteractor {
-        return WallpaperInteractor(wallpaperRepository)
-    }
-}
diff --git a/tests/Android.bp b/tests/Android.bp
index 71cb43af..1eb1b30c 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -61,9 +61,9 @@ android_test {
         "flag-junit",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
 
     platform_apis: true,
diff --git a/tests/common/res/xml/exception_wallpapers.xml b/tests/common/res/xml/exception_wallpapers.xml
index 4c0beb48..0ed7f167 100644
--- a/tests/common/res/xml/exception_wallpapers.xml
+++ b/tests/common/res/xml/exception_wallpapers.xml
@@ -16,7 +16,7 @@
   -->
 
 <wallpapers>
-    <category title="Category 1"> <!-- Missing 'id' attribute -->
-        <static-wallpaper id="wallpaper1" src="wallpaper1.jpg" />
+    <category id="category1" title="Category 1">
+        <invalid-tag id="wallpaper1" src="wallpaper1.jpg" />
     </category>
 </wallpapers>
\ No newline at end of file
diff --git a/tests/common/src/com/android/wallpaper/di/modules/SharedActivityRetainedTestModule.kt b/tests/common/src/com/android/wallpaper/di/modules/SharedActivityRetainedTestModule.kt
new file mode 100644
index 00000000..d391c30f
--- /dev/null
+++ b/tests/common/src/com/android/wallpaper/di/modules/SharedActivityRetainedTestModule.kt
@@ -0,0 +1,72 @@
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
+package com.android.wallpaper.di.modules
+
+import android.content.Context
+import com.android.wallpaper.picker.di.modules.HomeScreenPreviewUtils
+import com.android.wallpaper.picker.di.modules.LockScreenPreviewUtils
+import com.android.wallpaper.picker.di.modules.SharedActivityRetainedModule
+import com.android.wallpaper.picker.preview.data.repository.ImageEffectsRepository
+import com.android.wallpaper.testing.FakeImageEffectsRepository
+import com.android.wallpaper.util.PreviewUtils
+import dagger.Binds
+import dagger.Module
+import dagger.Provides
+import dagger.hilt.android.components.ActivityRetainedComponent
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.scopes.ActivityRetainedScoped
+import dagger.hilt.testing.TestInstallIn
+
+@Module
+@TestInstallIn(
+    components = [ActivityRetainedComponent::class],
+    replaces = [SharedActivityRetainedModule::class]
+)
+internal abstract class SharedActivityRetainedTestModule {
+
+    @Binds
+    abstract fun bindImageEffectsRepository(
+        impl: FakeImageEffectsRepository
+    ): ImageEffectsRepository
+
+    companion object {
+
+        @HomeScreenPreviewUtils
+        @ActivityRetainedScoped
+        @Provides
+        fun provideHomeScreenPreviewUtils(
+            @ApplicationContext appContext: Context,
+        ): PreviewUtils {
+            return PreviewUtils(
+                context = appContext,
+                authorityMetadataKey = "test_home_screen_preview_auth",
+            )
+        }
+
+        @LockScreenPreviewUtils
+        @ActivityRetainedScoped
+        @Provides
+        fun provideLockScreenPreviewUtils(
+            @ApplicationContext appContext: Context,
+        ): PreviewUtils {
+            return PreviewUtils(
+                context = appContext,
+                authority = "test_lock_screen_preview_auth",
+            )
+        }
+    }
+}
diff --git a/tests/common/src/com/android/wallpaper/di/modules/SharedTestModule.kt b/tests/common/src/com/android/wallpaper/di/modules/SharedAppTestModule.kt
similarity index 68%
rename from tests/common/src/com/android/wallpaper/di/modules/SharedTestModule.kt
rename to tests/common/src/com/android/wallpaper/di/modules/SharedAppTestModule.kt
index 46bb5c12..0a87e065 100644
--- a/tests/common/src/com/android/wallpaper/di/modules/SharedTestModule.kt
+++ b/tests/common/src/com/android/wallpaper/di/modules/SharedAppTestModule.kt
@@ -18,22 +18,36 @@ package com.android.wallpaper.di.modules
 import android.app.WallpaperManager
 import android.content.Context
 import android.content.pm.PackageManager
+import android.content.res.Resources
 import com.android.wallpaper.module.LargeScreenMultiPanesChecker
 import com.android.wallpaper.module.MultiPanesChecker
 import com.android.wallpaper.module.NetworkStatusNotifier
+import com.android.wallpaper.picker.category.client.LiveWallpapersClient
+import com.android.wallpaper.picker.category.data.repository.WallpaperCategoryRepository
+import com.android.wallpaper.picker.category.domain.interactor.CategoriesLoadingStatusInteractor
 import com.android.wallpaper.picker.category.domain.interactor.CategoryInteractor
 import com.android.wallpaper.picker.category.domain.interactor.CreativeCategoryInteractor
 import com.android.wallpaper.picker.category.domain.interactor.MyPhotosInteractor
+import com.android.wallpaper.picker.category.domain.interactor.ThirdPartyCategoryInteractor
+import com.android.wallpaper.picker.category.ui.view.providers.IndividualPickerFactory
+import com.android.wallpaper.picker.category.ui.view.providers.implementation.DefaultIndividualPickerFactory
 import com.android.wallpaper.picker.customization.data.content.WallpaperClient
 import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
-import com.android.wallpaper.picker.di.modules.DispatchersModule
 import com.android.wallpaper.picker.di.modules.MainDispatcher
 import com.android.wallpaper.picker.di.modules.SharedAppModule
+import com.android.wallpaper.picker.network.data.DefaultNetworkStatusRepository
+import com.android.wallpaper.picker.network.data.NetworkStatusRepository
+import com.android.wallpaper.picker.network.domain.DefaultNetworkStatusInteractor
+import com.android.wallpaper.picker.network.domain.NetworkStatusInteractor
 import com.android.wallpaper.system.UiModeManagerWrapper
+import com.android.wallpaper.testing.FakeCategoriesLoadingStatusInteractor
 import com.android.wallpaper.testing.FakeCategoryInteractor
 import com.android.wallpaper.testing.FakeCreativeWallpaperInteractor
 import com.android.wallpaper.testing.FakeDefaultCategoryFactory
+import com.android.wallpaper.testing.FakeDefaultWallpaperCategoryRepository
+import com.android.wallpaper.testing.FakeLiveWallpaperClientImpl
 import com.android.wallpaper.testing.FakeMyPhotosInteractor
+import com.android.wallpaper.testing.FakeThirdPartyCategoryInteractor
 import com.android.wallpaper.testing.FakeUiModeManager
 import com.android.wallpaper.testing.FakeWallpaperClient
 import com.android.wallpaper.testing.FakeWallpaperParser
@@ -54,31 +68,70 @@ import kotlinx.coroutines.test.TestDispatcher
 import kotlinx.coroutines.test.TestScope
 
 @Module
-@TestInstallIn(
-    components = [SingletonComponent::class],
-    replaces = [SharedAppModule::class, DispatchersModule::class]
-)
-internal abstract class SharedTestModule {
-    @Binds @Singleton abstract fun bindUiModeManager(impl: FakeUiModeManager): UiModeManagerWrapper
+@TestInstallIn(components = [SingletonComponent::class], replaces = [SharedAppModule::class])
+internal abstract class SharedAppTestModule {
 
+    // Also use the test dispatcher for work intended for the background thread. This makes tests
+    // single-threaded and more deterministic.
     @Binds
     @Singleton
-    abstract fun bindNetworkStatusNotifier(impl: TestNetworkStatusNotifier): NetworkStatusNotifier
+    @BackgroundDispatcher
+    abstract fun bindBackgroundDispatcher(impl: TestDispatcher): CoroutineDispatcher
 
     @Binds
     @Singleton
-    abstract fun bindWallpaperXMLParser(impl: FakeWallpaperParser): WallpaperParser
+    abstract fun bindCategoryFactory(impl: FakeDefaultCategoryFactory): CategoryFactory
 
     @Binds
     @Singleton
-    abstract fun bindCategoryFactory(impl: FakeDefaultCategoryFactory): CategoryFactory
+    abstract fun bindCategoryInteractor(impl: FakeCategoryInteractor): CategoryInteractor
 
-    @Binds @Singleton abstract fun bindWallpaperClient(impl: FakeWallpaperClient): WallpaperClient
+    @Binds
+    @Singleton
+    abstract fun bindCreativeCategoryInteractor(
+        impl: FakeCreativeWallpaperInteractor
+    ): CreativeCategoryInteractor
+
+    @Binds
+    @Singleton
+    abstract fun bindNetworkStatusRepository(
+        impl: DefaultNetworkStatusRepository
+    ): NetworkStatusRepository
+
+    @Binds
+    @Singleton
+    abstract fun bindNetworkStatusInteractor(
+        impl: DefaultNetworkStatusInteractor
+    ): NetworkStatusInteractor
 
     // Dispatcher and Scope injection choices are based on documentation at
     // http://go/android-dev/kotlin/coroutines/test. Most tests will not need to inject anything
     // other than the TestDispatcher, for use in Dispatchers.setMain().
 
+    @Binds
+    @Singleton
+    abstract fun bindFakeDefaultWallpaperCategoryRepository(
+        impl: FakeDefaultWallpaperCategoryRepository
+    ): WallpaperCategoryRepository
+
+    @Binds
+    @Singleton
+    abstract fun bindIndividualPickerFactoryFragment(
+        impl: DefaultIndividualPickerFactory
+    ): IndividualPickerFactory
+
+    @Binds
+    @Singleton
+    abstract fun bindLiveWallpaperClient(
+        impl: FakeLiveWallpaperClientImpl,
+    ): LiveWallpapersClient
+
+    @Binds
+    @Singleton
+    abstract fun bindLoadingStatusInteractor(
+        impl: FakeCategoriesLoadingStatusInteractor,
+    ): CategoriesLoadingStatusInteractor
+
     // Use the test dispatcher for work intended for the main thread
     @Binds
     @Singleton
@@ -88,45 +141,29 @@ internal abstract class SharedTestModule {
     // Use the test scope as the main scope to match the test dispatcher
     @Binds @Singleton @MainDispatcher abstract fun bindMainScope(impl: TestScope): CoroutineScope
 
-    // Also use the test dispatcher for work intended for the background thread. This makes tests
-    // single-threaded and more deterministic.
     @Binds
     @Singleton
-    @BackgroundDispatcher
-    abstract fun bindBackgroundDispatcher(impl: TestDispatcher): CoroutineDispatcher
+    abstract fun bindMyPhotosInteractor(impl: FakeMyPhotosInteractor): MyPhotosInteractor
 
     @Binds
     @Singleton
-    abstract fun bindCategoryInteractor(impl: FakeCategoryInteractor): CategoryInteractor
+    abstract fun bindNetworkStatusNotifier(impl: TestNetworkStatusNotifier): NetworkStatusNotifier
 
     @Binds
     @Singleton
-    abstract fun bindCreativeCategoryInteractor(
-        impl: FakeCreativeWallpaperInteractor
-    ): CreativeCategoryInteractor
+    abstract fun bindThirdPartyCategoryInteractor(
+        impl: FakeThirdPartyCategoryInteractor
+    ): ThirdPartyCategoryInteractor
 
     @Binds
     @Singleton
-    abstract fun bindMyPhotosInteractor(impl: FakeMyPhotosInteractor): MyPhotosInteractor
+    abstract fun bindUiModeManagerWrapper(impl: FakeUiModeManager): UiModeManagerWrapper
 
-    companion object {
-        // This is the most general test dispatcher for use in tests. UnconfinedTestDispatcher
-        // is the other choice. The difference is that the unconfined dispatcher starts new
-        // coroutines eagerly, which could be easier but could also make tests non-deterministic in
-        // some cases.
-        @Provides
-        @Singleton
-        fun provideTestDispatcher(): TestDispatcher {
-            return StandardTestDispatcher()
-        }
+    @Binds @Singleton abstract fun bindWallpaperClient(impl: FakeWallpaperClient): WallpaperClient
 
-        // Scope corresponding to the test dispatcher and main test thread. Tests will fail if work
-        // is still running in this scope after the test completes.
-        @Provides
-        @Singleton
-        fun provideTestScope(testDispatcher: TestDispatcher): TestScope {
-            return TestScope(testDispatcher)
-        }
+    @Binds @Singleton abstract fun bindWallpaperParser(impl: FakeWallpaperParser): WallpaperParser
+
+    companion object {
 
         // Scope for background work that does not need to finish before a test completes, like
         // continuously reading values from a flow.
@@ -139,8 +176,8 @@ internal abstract class SharedTestModule {
 
         @Provides
         @Singleton
-        fun provideWallpaperManager(@ApplicationContext appContext: Context): WallpaperManager {
-            return WallpaperManager.getInstance(appContext)
+        fun provideMultiPanesChecker(): MultiPanesChecker {
+            return LargeScreenMultiPanesChecker()
         }
 
         @Provides
@@ -151,8 +188,32 @@ internal abstract class SharedTestModule {
 
         @Provides
         @Singleton
-        fun provideMultiPanesChecker(): MultiPanesChecker {
-            return LargeScreenMultiPanesChecker()
+        fun provideResources(@ApplicationContext context: Context): Resources {
+            return context.resources
+        }
+
+        // This is the most general test dispatcher for use in tests. UnconfinedTestDispatcher
+        // is the other choice. The difference is that the unconfined dispatcher starts new
+        // coroutines eagerly, which could be easier but could also make tests non-deterministic in
+        // some cases.
+        @Provides
+        @Singleton
+        fun provideTestDispatcher(): TestDispatcher {
+            return StandardTestDispatcher()
+        }
+
+        // Scope corresponding to the test dispatcher and main test thread. Tests will fail if work
+        // is still running in this scope after the test completes.
+        @Provides
+        @Singleton
+        fun provideTestScope(testDispatcher: TestDispatcher): TestScope {
+            return TestScope(testDispatcher)
+        }
+
+        @Provides
+        @Singleton
+        fun provideWallpaperManager(@ApplicationContext appContext: Context): WallpaperManager {
+            return WallpaperManager.getInstance(appContext)
         }
     }
 }
diff --git a/tests/common/src/com/android/wallpaper/di/modules/TestActivityRetainedModule.kt b/tests/common/src/com/android/wallpaper/di/modules/TestActivityRetainedModule.kt
deleted file mode 100644
index 88abf2b6..00000000
--- a/tests/common/src/com/android/wallpaper/di/modules/TestActivityRetainedModule.kt
+++ /dev/null
@@ -1,37 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.wallpaper.di.modules
-
-import com.android.wallpaper.picker.di.modules.SharedActivityRetainedModule
-import com.android.wallpaper.picker.preview.data.repository.ImageEffectsRepository
-import com.android.wallpaper.testing.FakeImageEffectsRepository
-import dagger.Binds
-import dagger.Module
-import dagger.hilt.components.SingletonComponent
-import dagger.hilt.testing.TestInstallIn
-
-@Module
-@TestInstallIn(
-    components = [SingletonComponent::class],
-    replaces = [SharedActivityRetainedModule::class]
-)
-internal abstract class TestActivityRetainedModule {
-    @Binds
-    abstract fun bindImageEffectsRepository(
-        impl: FakeImageEffectsRepository
-    ): ImageEffectsRepository
-}
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeCategoriesLoadingStatusInteractor.kt b/tests/common/src/com/android/wallpaper/testing/FakeCategoriesLoadingStatusInteractor.kt
new file mode 100644
index 00000000..e3bcb9a7
--- /dev/null
+++ b/tests/common/src/com/android/wallpaper/testing/FakeCategoriesLoadingStatusInteractor.kt
@@ -0,0 +1,34 @@
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
+package com.android.wallpaper.testing
+
+import com.android.wallpaper.picker.category.data.repository.WallpaperCategoryRepository
+import com.android.wallpaper.picker.category.domain.interactor.CategoriesLoadingStatusInteractor
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.map
+
+@Singleton
+class FakeCategoriesLoadingStatusInteractor
+@Inject
+constructor(
+    private val wallpaperCategoryRepository: WallpaperCategoryRepository,
+) : CategoriesLoadingStatusInteractor {
+    override val isLoading: Flow<Boolean> =
+        wallpaperCategoryRepository.isDefaultCategoriesFetched.map { isFetched -> !isFetched }
+}
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeCategoryInteractor.kt b/tests/common/src/com/android/wallpaper/testing/FakeCategoryInteractor.kt
index a4602233..d0b5ce95 100644
--- a/tests/common/src/com/android/wallpaper/testing/FakeCategoryInteractor.kt
+++ b/tests/common/src/com/android/wallpaper/testing/FakeCategoryInteractor.kt
@@ -43,6 +43,10 @@ class FakeCategoryInteractor @Inject constructor() : CategoryInteractor {
         emit(categoryModels)
     }
 
+    override fun refreshNetworkCategories() {
+        // empty
+    }
+
     private fun generateCategoryData(): List<CommonCategoryData> {
         val dataList =
             listOf(
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeCreativeWallpaperInteractor.kt b/tests/common/src/com/android/wallpaper/testing/FakeCreativeWallpaperInteractor.kt
index 77ef55b2..514db009 100644
--- a/tests/common/src/com/android/wallpaper/testing/FakeCreativeWallpaperInteractor.kt
+++ b/tests/common/src/com/android/wallpaper/testing/FakeCreativeWallpaperInteractor.kt
@@ -43,6 +43,10 @@ class FakeCreativeWallpaperInteractor @Inject constructor() : CreativeCategoryIn
         emit(categoryModels)
     }
 
+    override fun updateCreativeCategories() {
+        // empty
+    }
+
     private fun generateCategoryData(): List<CommonCategoryData> {
         val dataList =
             listOf(
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeDefaultCategoryFactory.kt b/tests/common/src/com/android/wallpaper/testing/FakeDefaultCategoryFactory.kt
index 8b8e57f7..c4eee2d6 100644
--- a/tests/common/src/com/android/wallpaper/testing/FakeDefaultCategoryFactory.kt
+++ b/tests/common/src/com/android/wallpaper/testing/FakeDefaultCategoryFactory.kt
@@ -16,7 +16,6 @@
 
 package com.android.wallpaper.testing
 
-import android.content.Context
 import android.content.pm.ResolveInfo
 import android.graphics.drawable.Drawable
 import com.android.wallpaper.model.Category
@@ -53,7 +52,7 @@ class FakeDefaultCategoryFactory @Inject constructor() : CategoryFactory {
         this.resolveInfo = resolveInfo
     }
 
-    override fun getCategoryModel(context: Context, category: Category): CategoryModel {
+    override fun getCategoryModel(category: Category): CategoryModel {
         return CategoryModel(
             commonCategoryData = createCommonCategoryData(category),
             collectionCategoryData = createCollectionsCategoryData(category),
@@ -87,7 +86,7 @@ class FakeDefaultCategoryFactory @Inject constructor() : CategoryFactory {
 
     private fun createImageCategoryData(category: Category): ImageCategoryData? {
         return if (category is ImageCategory) {
-            ImageCategoryData(overlayIconDrawable = overlayIconDrawable)
+            ImageCategoryData(defaultDrawable = null, thumbnailAsset = fakeAsset)
         } else {
             null
         }
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeDefaultWallpaperCategoryClient.kt b/tests/common/src/com/android/wallpaper/testing/FakeDefaultWallpaperCategoryClient.kt
new file mode 100644
index 00000000..1a44fc20
--- /dev/null
+++ b/tests/common/src/com/android/wallpaper/testing/FakeDefaultWallpaperCategoryClient.kt
@@ -0,0 +1,87 @@
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
+package com.android.wallpaper.testing
+
+import com.android.wallpaper.model.Category
+import com.android.wallpaper.model.ImageCategory
+import com.android.wallpaper.picker.category.client.DefaultWallpaperCategoryClient
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+class FakeDefaultWallpaperCategoryClient @Inject constructor() : DefaultWallpaperCategoryClient {
+
+    private var fakeSystemCategories: List<Category> = emptyList()
+    private var fakeOnDeviceCategory: Category? = null
+    private var fakeThirdPartyAppCategories: List<Category> = emptyList()
+    private var fakeThirdPartyLiveWallpaperCategories: List<Category> = emptyList()
+
+    fun setOnDeviceCategory(category: Category?) {
+        fakeOnDeviceCategory = category
+    }
+
+    fun setThirdPartyLiveWallpaperCategories(categories: List<Category>) {
+        fakeThirdPartyLiveWallpaperCategories = categories
+    }
+
+    fun setSystemCategories(categories: List<Category>) {
+        fakeSystemCategories = categories
+    }
+
+    fun setThirdPartyAppCategories(categories: List<Category>) {
+        fakeThirdPartyAppCategories = categories
+    }
+
+    override suspend fun getMyPhotosCategory(): Category {
+        return ImageCategory(
+            "Fake My Photos",
+            "fake_my_photos_id",
+            1,
+            0 // Placeholder resource ID
+        )
+    }
+
+    override suspend fun getSystemCategories(): List<Category> {
+        return fakeSystemCategories
+    }
+
+    override suspend fun getOnDeviceCategory(): Category? {
+        return fakeOnDeviceCategory
+    }
+
+    override suspend fun getThirdPartyCategory(excludedPackageNames: List<String>): List<Category> {
+        TODO("Not yet implemented")
+    }
+
+    override fun getExcludedThirdPartyPackageNames(): List<String> {
+        TODO("Not yet implemented")
+    }
+
+    suspend fun getThirdPartyCategory(): List<Category> {
+        return fakeThirdPartyAppCategories
+    }
+
+    override suspend fun getThirdPartyLiveWallpaperCategory(
+        excludedPackageNames: Set<String>
+    ): List<Category> {
+        return fakeThirdPartyLiveWallpaperCategories
+    }
+
+    override fun getExcludedLiveWallpaperPackageNames(): Set<String> {
+        TODO("Not yet implemented")
+    }
+}
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeDefaultWallpaperCategoryRepository.kt b/tests/common/src/com/android/wallpaper/testing/FakeDefaultWallpaperCategoryRepository.kt
new file mode 100644
index 00000000..7442aa81
--- /dev/null
+++ b/tests/common/src/com/android/wallpaper/testing/FakeDefaultWallpaperCategoryRepository.kt
@@ -0,0 +1,128 @@
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
+package com.android.wallpaper.testing
+
+import com.android.wallpaper.model.Category
+import com.android.wallpaper.model.ImageCategory
+import com.android.wallpaper.picker.category.data.repository.WallpaperCategoryRepository
+import com.android.wallpaper.picker.data.category.CategoryModel
+import com.android.wallpaper.picker.data.category.CommonCategoryData
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
+
+@Singleton
+class FakeDefaultWallpaperCategoryRepository @Inject constructor() : WallpaperCategoryRepository {
+
+    private val _myPhotosCategory = MutableStateFlow<CategoryModel?>(null)
+    override val myPhotosCategory: StateFlow<CategoryModel?> = _myPhotosCategory
+
+    override val systemCategories: StateFlow<List<CategoryModel>>
+        get() = MutableStateFlow(emptyList())
+
+    override val onDeviceCategory: StateFlow<CategoryModel?>
+        get() =
+            MutableStateFlow(
+                CategoryModel(
+                    commonCategoryData =
+                        CommonCategoryData("On-device-category-1", "on_device_sample_id", 2),
+                    thirdPartyCategoryData = null,
+                    imageCategoryData = null,
+                    collectionCategoryData = null,
+                )
+            )
+
+    private val _isDefaultCategoriesFetched = MutableStateFlow(true)
+    override val isDefaultCategoriesFetched: StateFlow<Boolean> =
+        _isDefaultCategoriesFetched.asStateFlow()
+
+    override fun getMyPhotosFetchedCategory(): Category {
+        return ImageCategory("MyPhotos", "MyPhotosCollectionId", 4)
+    }
+
+    override fun getOnDeviceFetchedCategories(): Category? {
+        return null
+    }
+
+    override fun getThirdPartyFetchedCategories(): List<Category> {
+        return emptyList()
+    }
+
+    override fun getSystemFetchedCategories(): List<Category> {
+        return emptyList()
+    }
+
+    override fun getThirdPartyLiveWallpaperFetchedCategories(): List<Category> {
+        return emptyList()
+    }
+
+    override val thirdPartyAppCategory: StateFlow<List<CategoryModel>>
+        get() =
+            MutableStateFlow(
+                listOf(
+                    CategoryModel(
+                        commonCategoryData = CommonCategoryData("ThirdParty-1", "on_device_id", 2),
+                        thirdPartyCategoryData = null,
+                        imageCategoryData = null,
+                        collectionCategoryData = null,
+                    ),
+                    CategoryModel(
+                        commonCategoryData = CommonCategoryData("ThirdParty-2", "downloads_id", 3),
+                        thirdPartyCategoryData = null,
+                        imageCategoryData = null,
+                        collectionCategoryData = null,
+                    ),
+                    CategoryModel(
+                        commonCategoryData =
+                            CommonCategoryData("ThirdParty-3", "screenshots_id", 4),
+                        thirdPartyCategoryData = null,
+                        imageCategoryData = null,
+                        collectionCategoryData = null,
+                    ),
+                )
+            )
+
+    override val thirdPartyLiveWallpaperCategory: StateFlow<List<CategoryModel>>
+        get() =
+            MutableStateFlow(
+                listOf(
+                    CategoryModel(
+                        commonCategoryData =
+                            CommonCategoryData("ThirdPartyLiveWallpaper-1", "on_device_live_id", 2),
+                        thirdPartyCategoryData = null,
+                        imageCategoryData = null,
+                        collectionCategoryData = null,
+                    )
+                )
+            )
+
+    override suspend fun fetchMyPhotosCategory() {
+        _myPhotosCategory.value =
+            CategoryModel(
+                commonCategoryData = CommonCategoryData("Fake My Photos", "fake_my_photos_id", 1),
+                thirdPartyCategoryData = null,
+                imageCategoryData = null,
+                collectionCategoryData = null,
+            )
+    }
+
+    override suspend fun refreshNetworkCategories() {
+        // empty
+    }
+}
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeLiveWallpaperClientImpl.kt b/tests/common/src/com/android/wallpaper/testing/FakeLiveWallpaperClientImpl.kt
new file mode 100644
index 00000000..dc58aa94
--- /dev/null
+++ b/tests/common/src/com/android/wallpaper/testing/FakeLiveWallpaperClientImpl.kt
@@ -0,0 +1,38 @@
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
+package com.android.wallpaper.testing
+
+import com.android.wallpaper.model.WallpaperInfo
+import com.android.wallpaper.picker.category.client.LiveWallpapersClient
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+class FakeLiveWallpaperClientImpl @Inject constructor() : LiveWallpapersClient {
+    override fun getAll(excludedPackageNames: Set<String?>?): List<WallpaperInfo> {
+        val attributions: MutableList<String> = ArrayList()
+        attributions.add("Title")
+        attributions.add("Subtitle 1")
+        attributions.add("Subtitle 2")
+
+        val mTestLiveWallpaper = TestLiveWallpaperInfo(TestStaticWallpaperInfo.COLOR_DEFAULT)
+        mTestLiveWallpaper.setAttributions(attributions)
+        mTestLiveWallpaper.collectionId = "collectionLive"
+        mTestLiveWallpaper.wallpaperId = "wallpaperLive"
+        return listOf(mTestLiveWallpaper)
+    }
+}
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeLiveWallpaperDownloader.kt b/tests/common/src/com/android/wallpaper/testing/FakeLiveWallpaperDownloader.kt
index f4b1395e..7d6e367a 100644
--- a/tests/common/src/com/android/wallpaper/testing/FakeLiveWallpaperDownloader.kt
+++ b/tests/common/src/com/android/wallpaper/testing/FakeLiveWallpaperDownloader.kt
@@ -14,35 +14,67 @@
  * limitations under the License.
  */
 
-package com.android.wallpaper.picker.preview.data.util
+package com.android.wallpaper.testing
 
 import android.app.Activity
 import androidx.activity.result.ActivityResultLauncher
 import androidx.activity.result.IntentSenderRequest
 import com.android.wallpaper.picker.data.WallpaperModel
-import com.android.wallpaper.picker.preview.shared.model.LiveWallpaperDownloadResultModel
+import com.android.wallpaper.picker.preview.data.util.LiveWallpaperDownloader
 import javax.inject.Inject
 import javax.inject.Singleton
-import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.asStateFlow
 
 @Singleton
 class FakeLiveWallpaperDownloader @Inject constructor() : LiveWallpaperDownloader {
-    private val downloadResult = CompletableDeferred<LiveWallpaperDownloadResultModel?>()
 
-    fun setWallpaperDownloadResult(result: LiveWallpaperDownloadResultModel?) =
-        downloadResult.complete(result)
+    private var liveWallpaperDownloadListener:
+        LiveWallpaperDownloader.LiveWallpaperDownloadListener? =
+        null
+
+    fun proceedToDownloadSuccess(result: WallpaperModel.LiveWallpaperModel) {
+        liveWallpaperDownloadListener?.onDownloadSuccess(result)
+    }
+
+    fun proceedToDownloadFailed() {
+        liveWallpaperDownloadListener?.onDownloadFailed()
+    }
+
+    private val _isDownloaderReady = MutableStateFlow(false)
+    override val isDownloaderReady: Flow<Boolean> = _isDownloaderReady.asStateFlow()
+
+    /**
+     * This is to simulate [initiateDownloadableService] without passing [Activity], for testing
+     * purpose.
+     */
+    fun initiateDownloadableServiceByPass() {
+        _isDownloaderReady.value = true
+    }
 
     override fun initiateDownloadableService(
         activity: Activity,
         wallpaperData: WallpaperModel.StaticWallpaperModel,
         intentSenderLauncher: ActivityResultLauncher<IntentSenderRequest>
-    ) {}
+    ) {
+        _isDownloaderReady.value = true
+    }
 
     override fun cleanup() {}
 
-    override suspend fun downloadWallpaper(): LiveWallpaperDownloadResultModel? {
-        return downloadResult.await()
+    override fun downloadWallpaper(
+        listener: LiveWallpaperDownloader.LiveWallpaperDownloadListener
+    ) {
+        liveWallpaperDownloadListener = listener
+        // Please call proceedToDownloadSuccess() and proceedToDownloadFailed() in the test to
+        // simulate download resolutions.
     }
 
-    override fun cancelDownloadWallpaper(): Boolean = false
+    var isCancelDownloadWallpaperCalled = false
+
+    override fun cancelDownloadWallpaper(): Boolean {
+        isCancelDownloadWallpaperCalled = true
+        return false
+    }
 }
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeMyPhotosInteractor.kt b/tests/common/src/com/android/wallpaper/testing/FakeMyPhotosInteractor.kt
index fe2736ee..819a1cb2 100644
--- a/tests/common/src/com/android/wallpaper/testing/FakeMyPhotosInteractor.kt
+++ b/tests/common/src/com/android/wallpaper/testing/FakeMyPhotosInteractor.kt
@@ -38,4 +38,6 @@ class FakeMyPhotosInteractor @Inject constructor() : MyPhotosInteractor {
 
         emit(photoCategory)
     }
+
+    override fun updateMyPhotos() {}
 }
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeThirdPartyCategoryInteractor.kt b/tests/common/src/com/android/wallpaper/testing/FakeThirdPartyCategoryInteractor.kt
new file mode 100644
index 00000000..5509ca13
--- /dev/null
+++ b/tests/common/src/com/android/wallpaper/testing/FakeThirdPartyCategoryInteractor.kt
@@ -0,0 +1,83 @@
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
+package com.android.wallpaper.testing
+
+import android.content.ComponentName
+import android.content.pm.ActivityInfo
+import android.content.pm.ResolveInfo
+import com.android.wallpaper.picker.category.domain.interactor.ThirdPartyCategoryInteractor
+import com.android.wallpaper.picker.data.category.CategoryModel
+import com.android.wallpaper.picker.data.category.CommonCategoryData
+import com.android.wallpaper.picker.data.category.ThirdPartyCategoryData
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.flow
+
+@Singleton
+class FakeThirdPartyCategoryInteractor @Inject constructor() : ThirdPartyCategoryInteractor {
+    override val categories: Flow<List<CategoryModel>> = flow {
+        // stubbing the list of single section categories
+        val categoryModels =
+            generateCategoryData().map { pair ->
+                CategoryModel(
+                    pair.first,
+                    pair.second,
+                    null,
+                    null,
+                )
+            }
+
+        // Emit the list of categories
+        emit(categoryModels)
+    }
+
+    private fun generateCategoryData(): List<Pair<CommonCategoryData, ThirdPartyCategoryData>> {
+        val biktokResolveInfo = ResolveInfo()
+        val biktokComponentName =
+            ComponentName("com.zhiliaoapp.musically", "com.ss.android.ugc.aweme.main.MainActivity")
+
+        biktokResolveInfo.activityInfo =
+            ActivityInfo().apply {
+                packageName = biktokComponentName.packageName
+                name = biktokComponentName.className
+            }
+
+        val binstragramResolveInfo = ResolveInfo()
+        val binstagramComponentName =
+            ComponentName("com.instagram.android", "com.instagram.mainactivity.MainActivity")
+
+        binstragramResolveInfo.activityInfo =
+            ActivityInfo().apply {
+                packageName = binstagramComponentName.packageName
+                name = binstagramComponentName.className
+            }
+
+        val dataList =
+            listOf(
+                Pair(
+                    CommonCategoryData("Biktok", "biktok", 1),
+                    ThirdPartyCategoryData(biktokResolveInfo)
+                ),
+                Pair(
+                    CommonCategoryData("Binstagram", "binstagram", 2),
+                    ThirdPartyCategoryData(binstragramResolveInfo)
+                ),
+            )
+        return dataList
+    }
+}
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeUiModeManager.kt b/tests/common/src/com/android/wallpaper/testing/FakeUiModeManager.kt
index 649133d3..239d82a9 100644
--- a/tests/common/src/com/android/wallpaper/testing/FakeUiModeManager.kt
+++ b/tests/common/src/com/android/wallpaper/testing/FakeUiModeManager.kt
@@ -27,10 +27,7 @@ class FakeUiModeManager @Inject constructor() : UiModeManagerWrapper {
     val listeners = mutableListOf<ContrastChangeListener>()
     private var _contrast: Float? = 0.0f
 
-    override fun addContrastChangeListener(
-        executor: Executor,
-        listener: ContrastChangeListener,
-    ) {
+    override fun addContrastChangeListener(executor: Executor, listener: ContrastChangeListener) {
         listeners.add(listener)
     }
 
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeWallpaperCategoryWrapper.kt b/tests/common/src/com/android/wallpaper/testing/FakeWallpaperCategoryWrapper.kt
new file mode 100644
index 00000000..0c34d9f5
--- /dev/null
+++ b/tests/common/src/com/android/wallpaper/testing/FakeWallpaperCategoryWrapper.kt
@@ -0,0 +1,43 @@
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
+package com.android.wallpaper.testing
+
+import com.android.wallpaper.model.Category
+import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+class FakeWallpaperCategoryWrapper @Inject constructor() : WallpaperCategoryWrapper {
+    override suspend fun getCategories(
+        forceRefreshLiveWallpaperCategories: Boolean
+    ): List<Category> {
+        TODO("Not yet implemented")
+    }
+
+    override fun getCategory(
+        categories: List<Category>,
+        collectionId: String,
+        forceRefreshLiveWallpaperCategories: Boolean,
+    ): Category? {
+        TODO("Not yet implemented")
+    }
+
+    override suspend fun refreshLiveWallpaperCategories() {
+        TODO("Not yet implemented")
+    }
+}
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeWallpaperClient.kt b/tests/common/src/com/android/wallpaper/testing/FakeWallpaperClient.kt
index c1f14f52..c77c554d 100644
--- a/tests/common/src/com/android/wallpaper/testing/FakeWallpaperClient.kt
+++ b/tests/common/src/com/android/wallpaper/testing/FakeWallpaperClient.kt
@@ -22,6 +22,8 @@ import android.graphics.Bitmap
 import android.graphics.Point
 import android.graphics.Rect
 import com.android.wallpaper.asset.Asset
+import com.android.wallpaper.model.Screen
+import com.android.wallpaper.model.WallpaperModelsPair
 import com.android.wallpaper.module.logging.UserEventLogger.SetWallpaperEntryPoint
 import com.android.wallpaper.picker.customization.data.content.WallpaperClient
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination
@@ -40,9 +42,8 @@ import kotlinx.coroutines.flow.map
 class FakeWallpaperClient @Inject constructor() : WallpaperClient {
     val wallpapersSet =
         mutableMapOf(
-            WallpaperDestination.HOME to
-                mutableListOf<com.android.wallpaper.picker.data.WallpaperModel>(),
-            WallpaperDestination.LOCK to mutableListOf()
+            WallpaperDestination.HOME to null as com.android.wallpaper.picker.data.WallpaperModel?,
+            WallpaperDestination.LOCK to null as com.android.wallpaper.picker.data.WallpaperModel?,
         )
     private var wallpaperColors: WallpaperColors? = null
 
@@ -119,11 +120,7 @@ class FakeWallpaperClient @Inject constructor() : WallpaperClient {
         wallpaperModel: com.android.wallpaper.picker.data.WallpaperModel,
         destination: WallpaperDestination
     ) {
-        wallpapersSet.forEach { entry ->
-            if (destination == entry.key || destination == WallpaperDestination.BOTH) {
-                entry.value.add(wallpaperModel)
-            }
-        }
+        wallpapersSet[destination] = wallpaperModel
     }
 
     override suspend fun setRecentWallpaper(
@@ -142,8 +139,7 @@ class FakeWallpaperClient @Inject constructor() : WallpaperClient {
                     this[destination] =
                         _recentWallpapers.value[destination]?.sortedBy {
                             it.wallpaperId != wallpaperId
-                        }
-                            ?: error("No wallpapers for screen $destination")
+                        } ?: error("No wallpapers for screen $destination")
                 }
             onDone.invoke()
         }
@@ -175,6 +171,31 @@ class FakeWallpaperClient @Inject constructor() : WallpaperClient {
         return wallpaperColors
     }
 
+    override fun getWallpaperColors(screen: Screen): WallpaperColors? {
+        return wallpaperColors
+    }
+
+    fun setCurrentWallpaperModels(
+        homeWallpaper: com.android.wallpaper.picker.data.WallpaperModel,
+        lockWallpaper: com.android.wallpaper.picker.data.WallpaperModel?
+    ) {
+        wallpapersSet[WallpaperDestination.HOME] = homeWallpaper
+        wallpapersSet[WallpaperDestination.LOCK] = lockWallpaper
+    }
+
+    // Getting current home wallpaper should always return non-null value
+    override suspend fun getCurrentWallpaperModels(): WallpaperModelsPair {
+        return WallpaperModelsPair(
+            wallpapersSet[WallpaperDestination.HOME]
+                ?: (WallpaperModelUtils.getStaticWallpaperModel(
+                        wallpaperId = "defaultWallpaperId",
+                        collectionId = "defaultCollection",
+                    )
+                    .also { wallpapersSet[WallpaperDestination.HOME] = it }),
+            wallpapersSet[WallpaperDestination.LOCK]
+        )
+    }
+
     companion object {
         val INITIAL_RECENT_WALLPAPERS =
             listOf(
diff --git a/tests/common/src/com/android/wallpaper/testing/TestInjector.kt b/tests/common/src/com/android/wallpaper/testing/TestInjector.kt
index 10d1c80b..d350cf2f 100644
--- a/tests/common/src/com/android/wallpaper/testing/TestInjector.kt
+++ b/tests/common/src/com/android/wallpaper/testing/TestInjector.kt
@@ -56,11 +56,12 @@ import com.android.wallpaper.picker.MyPhotosStarter
 import com.android.wallpaper.picker.PreviewActivity
 import com.android.wallpaper.picker.PreviewFragment
 import com.android.wallpaper.picker.ViewOnlyPreviewActivity
+import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper
 import com.android.wallpaper.picker.customization.data.repository.WallpaperColorsRepository
 import com.android.wallpaper.picker.customization.data.repository.WallpaperRepository
 import com.android.wallpaper.picker.customization.domain.interactor.WallpaperInteractor
 import com.android.wallpaper.picker.customization.domain.interactor.WallpaperSnapshotRestorer
-import com.android.wallpaper.picker.individual.IndividualPickerFragment
+import com.android.wallpaper.picker.individual.IndividualPickerFragment2
 import com.android.wallpaper.picker.undo.data.repository.UndoRepository
 import com.android.wallpaper.picker.undo.domain.interactor.UndoInteractor
 import com.android.wallpaper.util.DisplayUtils
@@ -103,6 +104,11 @@ open class TestInjector @Inject constructor(private val userEventLogger: UserEve
     @Inject lateinit var wallpaperClient: FakeWallpaperClient
     @Inject lateinit var injectedWallpaperInteractor: WallpaperInteractor
     @Inject lateinit var prefs: WallpaperPreferences
+    @Inject lateinit var fakeWallpaperCategoryWrapper: WallpaperCategoryWrapper
+
+    override fun getWallpaperCategoryWrapper(): WallpaperCategoryWrapper {
+        return fakeWallpaperCategoryWrapper
+    }
 
     override fun getApplicationCoroutineScope(): CoroutineScope {
         return appScope ?: CoroutineScope(Dispatchers.Main).also { appScope = it }
@@ -149,9 +155,7 @@ open class TestInjector @Inject constructor(private val userEventLogger: UserEve
             ?: TestDrawableLayerResolver().also { drawableLayerResolver = it }
     }
 
-    override fun getEffectsController(
-        context: Context,
-    ): EffectsController? {
+    override fun getEffectsController(context: Context): EffectsController? {
         return null
     }
 
@@ -161,9 +165,9 @@ open class TestInjector @Inject constructor(private val userEventLogger: UserEve
 
     override fun getIndividualPickerFragment(
         context: Context,
-        collectionId: String
-    ): IndividualPickerFragment {
-        return IndividualPickerFragment.newInstance(collectionId)
+        collectionId: String,
+    ): IndividualPickerFragment2 {
+        return IndividualPickerFragment2.newInstance(collectionId)
     }
 
     override fun getLiveWallpaperInfoFactory(context: Context): LiveWallpaperInfoFactory {
@@ -246,6 +250,14 @@ open class TestInjector @Inject constructor(private val userEventLogger: UserEve
                         return true
                     }
 
+                    override fun isAIWallpaperEnabled(context: Context): Boolean {
+                        return true
+                    }
+
+                    override fun isWallpaperCategoryRefactoringEnabled(): Boolean {
+                        return true
+                    }
+
                     override fun getCachedFlags(
                         context: Context
                     ): List<CustomizationProviderClient.Flag> {
@@ -257,13 +269,13 @@ open class TestInjector @Inject constructor(private val userEventLogger: UserEve
 
     override fun getUndoInteractor(
         context: Context,
-        lifecycleOwner: LifecycleOwner
+        lifecycleOwner: LifecycleOwner,
     ): UndoInteractor {
         return undoInteractor
             ?: UndoInteractor(
                 getApplicationCoroutineScope(),
                 UndoRepository(),
-                HashMap()
+                HashMap(),
             ) // Empty because we don't support undoing in WallpaperPicker2..also{}
     }
 
@@ -280,7 +292,7 @@ open class TestInjector @Inject constructor(private val userEventLogger: UserEve
                             client = getWallpaperClient(context),
                             wallpaperPreferences = getPreferences(context = context),
                             backgroundDispatcher = Dispatchers.IO,
-                        ),
+                        )
                 )
                 .also { wallpaperInteractor = it }
     }
@@ -296,14 +308,14 @@ open class TestInjector @Inject constructor(private val userEventLogger: UserEve
 
     override fun getWallpaperColorResources(
         wallpaperColors: WallpaperColors,
-        context: Context
+        context: Context,
     ): WallpaperColorResources {
         return DefaultWallpaperColorResources(wallpaperColors)
     }
 
     override fun getWallpaperColorsRepository(): WallpaperColorsRepository {
         return wallpaperColorsRepository
-            ?: WallpaperColorsRepository().also { wallpaperColorsRepository = it }
+            ?: WallpaperColorsRepository(wallpaperClient).also { wallpaperColorsRepository = it }
     }
 
     override fun getMyPhotosIntentProvider(): MyPhotosStarter.MyPhotosIntentProvider {
diff --git a/tests/common/src/com/android/wallpaper/testing/TestLiveWallpaperInfo.java b/tests/common/src/com/android/wallpaper/testing/TestLiveWallpaperInfo.java
index fc12568b..5ee7d783 100644
--- a/tests/common/src/com/android/wallpaper/testing/TestLiveWallpaperInfo.java
+++ b/tests/common/src/com/android/wallpaper/testing/TestLiveWallpaperInfo.java
@@ -167,7 +167,18 @@ public class TestLiveWallpaperInfo extends LiveWallpaperInfo {
             InlinePreviewIntentFactory inlinePreviewIntentFactory, int requestCode,
             boolean isAssetIdPresent) {
         srcActivity.startActivityForResult(
-                inlinePreviewIntentFactory.newIntent(srcActivity, this, isAssetIdPresent),
+                inlinePreviewIntentFactory.newIntent(srcActivity, this, isAssetIdPresent,
+                        false),
+                requestCode);
+    }
+
+    @Override
+    public void showPreview(Activity srcActivity,
+            InlinePreviewIntentFactory inlinePreviewIntentFactory, int requestCode,
+            boolean isAssetIdPresent, boolean shouldRefreshCategory) {
+        srcActivity.startActivityForResult(
+                inlinePreviewIntentFactory.newIntent(srcActivity, this, isAssetIdPresent,
+                        shouldRefreshCategory),
                 requestCode);
     }
 
diff --git a/tests/common/src/com/android/wallpaper/testing/TestStaticWallpaperInfo.java b/tests/common/src/com/android/wallpaper/testing/TestStaticWallpaperInfo.java
index 28ef6d5c..1a700afb 100644
--- a/tests/common/src/com/android/wallpaper/testing/TestStaticWallpaperInfo.java
+++ b/tests/common/src/com/android/wallpaper/testing/TestStaticWallpaperInfo.java
@@ -163,7 +163,18 @@ public class TestStaticWallpaperInfo extends WallpaperInfo {
             InlinePreviewIntentFactory inlinePreviewIntentFactory, int requestCode,
             boolean isAssetIdPresent) {
         srcActivity.startActivityForResult(
-                inlinePreviewIntentFactory.newIntent(srcActivity, this, isAssetIdPresent),
+                inlinePreviewIntentFactory.newIntent(srcActivity, this, isAssetIdPresent,
+                        false),
+                requestCode);
+    }
+
+    @Override
+    public void showPreview(Activity srcActivity,
+            InlinePreviewIntentFactory inlinePreviewIntentFactory, int requestCode,
+            boolean isAssetIdPresent, boolean shouldRefreshCategory) {
+        srcActivity.startActivityForResult(
+                inlinePreviewIntentFactory.newIntent(srcActivity, this, isAssetIdPresent,
+                        shouldRefreshCategory),
                 requestCode);
     }
 
diff --git a/tests/module/src/com/android/wallpaper/WallpaperPicker2TestModule.kt b/tests/module/src/com/android/wallpaper/WallpaperPicker2TestModule.kt
index 305c4b41..9d471d3a 100644
--- a/tests/module/src/com/android/wallpaper/WallpaperPicker2TestModule.kt
+++ b/tests/module/src/com/android/wallpaper/WallpaperPicker2TestModule.kt
@@ -24,15 +24,20 @@ import com.android.wallpaper.module.logging.TestUserEventLogger
 import com.android.wallpaper.module.logging.UserEventLogger
 import com.android.wallpaper.modules.WallpaperPicker2AppModule
 import com.android.wallpaper.network.Requester
+import com.android.wallpaper.picker.category.client.DefaultWallpaperCategoryClient
+import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper
+import com.android.wallpaper.picker.common.preview.ui.binder.DefaultWorkspaceCallbackBinder
+import com.android.wallpaper.picker.common.preview.ui.binder.WorkspaceCallbackBinder
 import com.android.wallpaper.picker.customization.ui.binder.CustomizationOptionsBinder
 import com.android.wallpaper.picker.customization.ui.binder.DefaultCustomizationOptionsBinder
-import com.android.wallpaper.picker.di.modules.EffectsModule
-import com.android.wallpaper.picker.preview.data.util.FakeLiveWallpaperDownloader
-import com.android.wallpaper.picker.preview.data.util.LiveWallpaperDownloader
+import com.android.wallpaper.picker.customization.ui.binder.DefaultToolbarBinder
+import com.android.wallpaper.picker.customization.ui.binder.ToolbarBinder
 import com.android.wallpaper.picker.preview.ui.util.DefaultImageEffectDialogUtil
 import com.android.wallpaper.picker.preview.ui.util.ImageEffectDialogUtil
 import com.android.wallpaper.testing.FakeDefaultRequester
+import com.android.wallpaper.testing.FakeDefaultWallpaperCategoryClient
 import com.android.wallpaper.testing.FakeDefaultWallpaperModelFactory
+import com.android.wallpaper.testing.FakeWallpaperCategoryWrapper
 import com.android.wallpaper.testing.TestInjector
 import com.android.wallpaper.testing.TestPartnerProvider
 import com.android.wallpaper.testing.TestWallpaperPreferences
@@ -46,48 +51,61 @@ import javax.inject.Singleton
 @Module
 @TestInstallIn(
     components = [SingletonComponent::class],
-    replaces = [EffectsModule::class, WallpaperPicker2AppModule::class]
+    replaces = [WallpaperPicker2AppModule::class],
 )
 abstract class WallpaperPicker2TestModule {
-    @Binds @Singleton abstract fun bindInjector(impl: TestInjector): Injector
-
-    @Binds @Singleton abstract fun bindUserEventLogger(impl: TestUserEventLogger): UserEventLogger
 
-    @Binds @Singleton abstract fun bindFakeRequester(impl: FakeDefaultRequester): Requester
+    @Binds
+    @Singleton
+    abstract fun bindCustomizationOptionsBinder(
+        impl: DefaultCustomizationOptionsBinder
+    ): CustomizationOptionsBinder
 
     @Binds
     @Singleton
-    abstract fun bindWallpaperModelFactory(
-        impl: FakeDefaultWallpaperModelFactory
-    ): WallpaperModelFactory
+    abstract fun bindDefaultWallpaperCategoryClient(
+        impl: FakeDefaultWallpaperCategoryClient
+    ): DefaultWallpaperCategoryClient
 
     @Binds
     @Singleton
-    abstract fun bindWallpaperPreferences(impl: TestWallpaperPreferences): WallpaperPreferences
+    abstract fun bindEffectsController(impl: FakeEffectsController): EffectsController
 
     @Binds
     @Singleton
-    abstract fun bindLiveWallpaperDownloader(
-        impl: FakeLiveWallpaperDownloader
-    ): LiveWallpaperDownloader
+    abstract fun bindImageEffectDialogUtil(
+        impl: DefaultImageEffectDialogUtil
+    ): ImageEffectDialogUtil
+
+    @Binds @Singleton abstract fun bindInjector(impl: TestInjector): Injector
+
+    @Binds @Singleton abstract fun bindPartnerProvider(impl: TestPartnerProvider): PartnerProvider
+
+    @Binds @Singleton abstract fun bindRequester(impl: FakeDefaultRequester): Requester
+
+    @Binds @Singleton abstract fun bindToolbarBinder(impl: DefaultToolbarBinder): ToolbarBinder
+
+    @Binds @Singleton abstract fun bindUserEventLogger(impl: TestUserEventLogger): UserEventLogger
 
     @Binds
     @Singleton
-    abstract fun providePartnerProvider(impl: TestPartnerProvider): PartnerProvider
+    abstract fun bindWallpaperCategoryWrapper(
+        impl: FakeWallpaperCategoryWrapper
+    ): WallpaperCategoryWrapper
 
     @Binds
     @Singleton
-    abstract fun bindEffectsWallpaperDialogUtil(
-        impl: DefaultImageEffectDialogUtil
-    ): ImageEffectDialogUtil
+    abstract fun bindWallpaperModelFactory(
+        impl: FakeDefaultWallpaperModelFactory
+    ): WallpaperModelFactory
 
     @Binds
     @Singleton
-    abstract fun bindEffectsController(impl: FakeEffectsController): EffectsController
+    abstract fun bindWallpaperPreferences(impl: TestWallpaperPreferences): WallpaperPreferences
 
     @Binds
     @Singleton
-    abstract fun bindCustomizationOptionsBinder(
-        impl: DefaultCustomizationOptionsBinder
-    ): CustomizationOptionsBinder
+    abstract fun bindWorkspaceCallbackBinder(
+        impl: DefaultWorkspaceCallbackBinder
+    ): WorkspaceCallbackBinder
 }
diff --git a/tests/robotests/Android.bp b/tests/robotests/Android.bp
index cfc09ab1..1a6667ec 100644
--- a/tests/robotests/Android.bp
+++ b/tests/robotests/Android.bp
@@ -30,7 +30,9 @@ android_robolectric_test {
     // Do not add picker-related dependencies here. Add them to
     // WallpaperPicker2Shell instead.
     static_libs: [
+        "flag-junit",
         "hilt_android_testing",
+        "platform-test-annotations",
     ],
 
     libs: [
diff --git a/tests/robotests/common/src/com/android/wallpaper/testing/FakeDisplaysProviderModule.kt b/tests/robotests/common/src/com/android/wallpaper/testing/FakeDisplaysProviderModule.kt
index 453436c3..1583eaf2 100644
--- a/tests/robotests/common/src/com/android/wallpaper/testing/FakeDisplaysProviderModule.kt
+++ b/tests/robotests/common/src/com/android/wallpaper/testing/FakeDisplaysProviderModule.kt
@@ -27,6 +27,7 @@ import javax.inject.Singleton
 @Module
 @TestInstallIn(components = [SingletonComponent::class], replaces = [DisplaysProviderModule::class])
 abstract class FakeDisplaysProviderModule {
+
     @Binds
     @Singleton
     abstract fun bindDisplaysProvider(impl: FakeDisplaysProvider): DisplaysProvider
diff --git a/tests/robotests/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcherTest.kt b/tests/robotests/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcherTest.kt
index 48b077a9..230e3e79 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcherTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcherTest.kt
@@ -27,7 +27,7 @@ import android.os.Looper
 import android.os.Process
 import androidx.test.core.app.ApplicationProvider
 import androidx.test.filters.SmallTest
-import com.android.wallpaper.picker.di.modules.ConcurrencyModule
+import com.android.wallpaper.picker.di.modules.SharedAppModule.Companion.BroadcastRunning
 import com.google.common.truth.Truth.assertThat
 import java.util.concurrent.Executor
 import kotlinx.coroutines.ExperimentalCoroutinesApi
@@ -154,16 +154,14 @@ class BroadcastDispatcherTest {
             .looper
     }
 
-    private fun provideBroadcastRunningExecutor(
-        @ConcurrencyModule.BroadcastRunning looper: Looper?
-    ): Executor {
+    private fun provideBroadcastRunningExecutor(@BroadcastRunning looper: Looper?): Executor {
         val handler = Handler(looper ?: Looper.getMainLooper())
         return Executor { command -> handler.post(command) }
     }
 
     companion object {
-        private val BROADCAST_SLOW_DISPATCH_THRESHOLD = 1000L
-        private val BROADCAST_SLOW_DELIVERY_THRESHOLD = 1000L
+        private const val BROADCAST_SLOW_DISPATCH_THRESHOLD = 1000L
+        private const val BROADCAST_SLOW_DELIVERY_THRESHOLD = 1000L
         const val TEST_ACTION = "TEST_ACTION"
         const val TEST_TYPE = "test/type"
     }
diff --git a/tests/robotests/src/com/android/wallpaper/picker/category/data/DefaultWallpaperCategoryClientTest.kt b/tests/robotests/src/com/android/wallpaper/picker/category/data/DefaultWallpaperCategoryClientImplTest.kt
similarity index 50%
rename from tests/robotests/src/com/android/wallpaper/picker/category/data/DefaultWallpaperCategoryClientTest.kt
rename to tests/robotests/src/com/android/wallpaper/picker/category/data/DefaultWallpaperCategoryClientImplTest.kt
index 52a65192..3e61eb35 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/category/data/DefaultWallpaperCategoryClientTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/category/data/DefaultWallpaperCategoryClientImplTest.kt
@@ -17,12 +17,19 @@
 package com.android.wallpaper.picker.category.data
 
 import android.content.Context
+import android.content.Intent
+import android.content.pm.ActivityInfo
+import android.content.pm.ApplicationInfo
+import android.content.pm.PackageManager
+import android.content.pm.ResolveInfo
 import com.android.wallpaper.model.PartnerWallpaperInfo
+import com.android.wallpaper.model.ThirdPartyLiveWallpaperCategory
 import com.android.wallpaper.module.InjectorProvider
 import com.android.wallpaper.picker.category.client.DefaultWallpaperCategoryClient
+import com.android.wallpaper.picker.category.client.DefaultWallpaperCategoryClientImpl
+import com.android.wallpaper.picker.category.client.LiveWallpapersClient
 import com.android.wallpaper.picker.data.category.CategoryModel
 import com.android.wallpaper.picker.data.category.CommonCategoryData
-import com.android.wallpaper.testing.FakeDefaultCategoryFactory
 import com.android.wallpaper.testing.FakeWallpaperParser
 import com.android.wallpaper.testing.TestInjector
 import com.android.wallpaper.testing.TestPartnerProvider
@@ -43,19 +50,20 @@ import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
 import org.robolectric.RobolectricTestRunner
+import org.robolectric.Shadows.shadowOf
 
 @HiltAndroidTest
 @OptIn(ExperimentalCoroutinesApi::class)
 @RunWith(RobolectricTestRunner::class)
-class DefaultWallpaperCategoryClientTest {
+class DefaultWallpaperCategoryClientImplTest {
 
     @get:Rule var hiltRule = HiltAndroidRule(this)
     @Inject @ApplicationContext lateinit var context: Context
     @Inject lateinit var partnerProvider: TestPartnerProvider
-    @Inject lateinit var defaultCategoryFactory: FakeDefaultCategoryFactory
     @Inject lateinit var wallpaperXMLParser: FakeWallpaperParser
     @Inject lateinit var testDispatcher: TestDispatcher
     @Inject lateinit var testScope: TestScope
+    @Inject lateinit var liveWallpapersClient: LiveWallpapersClient
 
     private lateinit var defaultWallpaperCategoryClient: DefaultWallpaperCategoryClient
     @Inject lateinit var testInjector: TestInjector
@@ -65,11 +73,11 @@ class DefaultWallpaperCategoryClientTest {
         hiltRule.inject()
         Dispatchers.setMain(testDispatcher)
         defaultWallpaperCategoryClient =
-            DefaultWallpaperCategoryClient(
+            DefaultWallpaperCategoryClientImpl(
                 context,
                 partnerProvider,
-                defaultCategoryFactory,
-                wallpaperXMLParser
+                wallpaperXMLParser,
+                liveWallpapersClient
             )
         InjectorProvider.setInjector(testInjector)
         val resources = context.resources
@@ -87,13 +95,11 @@ class DefaultWallpaperCategoryClientTest {
             val result = defaultWallpaperCategoryClient.getMyPhotosCategory()
 
             assertThat(expectedCategoryModel.commonCategoryData.collectionId)
-                .isEqualTo(result.commonCategoryData.collectionId)
+                .isEqualTo(result.collectionId)
 
-            assertThat(expectedCategoryModel.commonCategoryData.priority)
-                .isEqualTo(result.commonCategoryData.priority)
+            assertThat(expectedCategoryModel.commonCategoryData.priority).isEqualTo(result.priority)
 
-            assertThat(expectedCategoryModel.commonCategoryData.title)
-                .isEqualTo(result.commonCategoryData.title)
+            assertThat(expectedCategoryModel.commonCategoryData.title).isEqualTo(result.title)
         }
 
     @Test
@@ -105,9 +111,8 @@ class DefaultWallpaperCategoryClientTest {
                 async { defaultWallpaperCategoryClient.getOnDeviceCategory() }.await()
 
             assertThat(categoryModel).isNotNull()
-            assertThat(categoryModel?.commonCategoryData?.title).isEqualTo("On-device wallpapers")
-            assertThat(categoryModel?.commonCategoryData?.collectionId)
-                .isEqualTo("on_device_wallpapers")
+            assertThat(categoryModel?.title).isEqualTo("On-device wallpapers")
+            assertThat(categoryModel?.collectionId).isEqualTo("on_device_wallpapers")
         }
 
     @Test
@@ -120,14 +125,81 @@ class DefaultWallpaperCategoryClientTest {
             assertThat(categoryModel).isNull()
         }
 
+    @Test
+    fun getThirdPartyLiveWallpaperCategory_withFeatureAndLiveWallpapers_returnsCategory() =
+        testScope.runTest {
+            val shadowPackageManager = shadowOf(context.packageManager)
+            shadowPackageManager.setSystemFeature(PackageManager.FEATURE_LIVE_WALLPAPER, true)
+
+            val excludedPackageNames = emptySet<String>()
+            val expectedCategory =
+                ThirdPartyLiveWallpaperCategory(
+                    "Live wallpapers",
+                    "live_wallpapers",
+                    liveWallpapersClient.getAll(emptySet()),
+                    300,
+                    emptySet()
+                )
+
+            val result =
+                defaultWallpaperCategoryClient.getThirdPartyLiveWallpaperCategory(
+                    excludedPackageNames
+                )
+
+            assertThat(result).hasSize(1)
+            assertThat(result[0].title).isEqualTo(expectedCategory.title)
+            assertThat(result[0].collectionId).isEqualTo(expectedCategory.collectionId)
+        }
+
     @Test
     fun getSystemCategories() =
         testScope.runTest {
-            val categoryModel = async { defaultWallpaperCategoryClient.getCategories() }.await()
+            val categoryModel =
+                async { defaultWallpaperCategoryClient.getSystemCategories() }.await()
 
             assertThat(categoryModel).isNotNull()
-            assertThat(categoryModel[0].commonCategoryData.title).isEqualTo("sample-title-1")
-            assertThat(categoryModel[0].commonCategoryData.collectionId)
-                .isEqualTo("sample-collection-id")
+            assertThat(categoryModel[0].title).isEqualTo("sample-title-1")
+            assertThat(categoryModel[0].collectionId).isEqualTo("sample-collection-id")
         }
+
+    @Test
+    fun getThirdPartyCategory() =
+        testScope.runTest {
+            // Get the shadow package manager
+            val shadowPackageManager = shadowOf(context.packageManager)
+            val fakeThirdPartyApp1 = createFakeResolveInfo("com.example.app1", "ThirdPartyApp1")
+            val fakeThirdPartyApp2 = createFakeResolveInfo("com.example.app2", "ThirdPartyApp2")
+            val fakeImagePickerApp = createFakeResolveInfo("com.example.imagepicker", "ImagePicker")
+            shadowPackageManager.addResolveInfoForIntent(
+                Intent(Intent.ACTION_SET_WALLPAPER),
+                listOf(fakeThirdPartyApp1, fakeThirdPartyApp2, fakeImagePickerApp)
+            )
+            shadowPackageManager.addResolveInfoForIntent(
+                Intent(Intent.ACTION_GET_CONTENT).setType("image/*"),
+                listOf(fakeImagePickerApp)
+            )
+
+            val result = defaultWallpaperCategoryClient.getThirdPartyCategory(emptyList())
+            assertThat(result).hasSize(2)
+            assertThat(result[0].title).isEqualTo("ThirdPartyApp1")
+            assertThat(result[0].collectionId).contains("com.example.app1")
+            assertThat(result[1].title).isEqualTo("ThirdPartyApp2")
+            assertThat(result[1].collectionId).contains("com.example.app2")
+        }
+
+    private fun createFakeResolveInfo(packageName: String, label: String): ResolveInfo {
+        return ResolveInfo().apply {
+            activityInfo =
+                ActivityInfo().apply {
+                    this.packageName = packageName
+                    name = "${packageName}.MainActivity"
+                    applicationInfo =
+                        ApplicationInfo().apply {
+                            this.packageName = packageName
+                            labelRes = 0
+                            nonLocalizedLabel = label
+                        }
+                }
+        }
+    }
 }
diff --git a/tests/robotests/src/com/android/wallpaper/picker/category/data/LiveWallpapersClientImplTest.kt b/tests/robotests/src/com/android/wallpaper/picker/category/data/LiveWallpapersClientImplTest.kt
new file mode 100644
index 00000000..3e6e4bde
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/picker/category/data/LiveWallpapersClientImplTest.kt
@@ -0,0 +1,125 @@
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
+package com.android.wallpaper.picker.category.data
+
+import android.content.Context
+import android.content.Intent
+import android.content.pm.ApplicationInfo
+import android.content.pm.ResolveInfo
+import android.content.pm.ServiceInfo
+import android.service.wallpaper.WallpaperService
+import com.android.wallpaper.module.InjectorProvider
+import com.android.wallpaper.picker.category.client.LiveWallpapersClientImpl
+import com.android.wallpaper.testing.TestInjector
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+import org.robolectric.Shadows.shadowOf
+
+@HiltAndroidTest
+@RunWith(RobolectricTestRunner::class)
+class LiveWallpapersClientImplTest {
+
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+    @Inject @ApplicationContext lateinit var context: Context
+    @Inject lateinit var testInjector: TestInjector
+
+    private lateinit var liveWallpapersClientImpl: LiveWallpapersClientImpl
+
+    @Before
+    fun setup() {
+        hiltRule.inject()
+        liveWallpapersClientImpl = LiveWallpapersClientImpl(context)
+        InjectorProvider.setInjector(testInjector)
+    }
+
+    @Test
+    fun `test getAllOnDevice returns system wallpapers first`() {
+        val systemWallpaperResolveInfo =
+            createFakeResolveInfo("com.system.wallpaper", "System Wallpaper")
+        val nonSystemWallpaperResolveInfo =
+            createFakeResolveInfo("com.non.system.wallpaper", "Non-System Wallpaper")
+        val shadowPackageManager = shadowOf(context.packageManager)
+
+        shadowPackageManager.addResolveInfoForIntent(
+            Intent(WallpaperService.SERVICE_INTERFACE),
+            systemWallpaperResolveInfo
+        )
+
+        shadowPackageManager.addResolveInfoForIntent(
+            Intent(WallpaperService.SERVICE_INTERFACE),
+            nonSystemWallpaperResolveInfo
+        )
+
+        val result = liveWallpapersClientImpl.getAllOnDevice()
+
+        assertThat(result.size).isEqualTo(2)
+        assertThat(result[0].serviceInfo.packageName)
+            .isEqualTo(nonSystemWallpaperResolveInfo.serviceInfo.packageName)
+        assertThat(result[1].serviceInfo.packageName)
+            .isEqualTo(systemWallpaperResolveInfo.serviceInfo.packageName)
+    }
+
+    @Test
+    fun `test getAll returns wallpaper infos excluding package names`() {
+        val systemWallpaperResolveInfo =
+            createFakeResolveInfo("com.system.wallpaper", "System Wallpaper")
+        val nonSystemWallpaperResolveInfo =
+            createFakeResolveInfo("com.non.system.wallpaper", "Non-System Wallpaper")
+        val shadowPackageManager = shadowOf(context.packageManager)
+
+        shadowPackageManager.addResolveInfoForIntent(
+            Intent(WallpaperService.SERVICE_INTERFACE),
+            systemWallpaperResolveInfo
+        )
+
+        shadowPackageManager.addResolveInfoForIntent(
+            Intent(WallpaperService.SERVICE_INTERFACE),
+            nonSystemWallpaperResolveInfo
+        )
+
+        val result =
+            liveWallpapersClientImpl.getAll(
+                setOf("com.system.wallpaper", "com.non.system.wallpaper")
+            )
+
+        assertThat(result.size).isEqualTo(0)
+    }
+
+    private fun createFakeResolveInfo(packageName: String, label: String): ResolveInfo {
+        return ResolveInfo().apply {
+            serviceInfo =
+                ServiceInfo().apply {
+                    this.packageName = packageName
+                    name = "${packageName}.WallpaperService"
+                    applicationInfo =
+                        ApplicationInfo().apply {
+                            this.packageName = packageName
+                            labelRes = 0
+                            nonLocalizedLabel = label
+                        }
+                }
+        }
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/picker/category/interactor/CategoryInteractorImplTest.kt b/tests/robotests/src/com/android/wallpaper/picker/category/interactor/CategoryInteractorImplTest.kt
new file mode 100644
index 00000000..af4e0f74
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/picker/category/interactor/CategoryInteractorImplTest.kt
@@ -0,0 +1,89 @@
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
+package com.android.wallpaper.picker.category.interactor
+
+import android.content.Context
+import com.android.wallpaper.picker.category.domain.interactor.implementations.CategoryInteractorImpl
+import com.android.wallpaper.picker.data.category.CategoryModel
+import com.android.wallpaper.picker.data.category.CommonCategoryData
+import com.android.wallpaper.testing.FakeDefaultWallpaperCategoryRepository
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import kotlinx.coroutines.flow.first
+import kotlinx.coroutines.test.runTest
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+
+@HiltAndroidTest
+@RunWith(RobolectricTestRunner::class)
+class CategoryInteractorImplTest {
+
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+    @Inject @ApplicationContext lateinit var context: Context
+    @Inject
+    lateinit var fakeDefaultWallpaperCategoryRepository: FakeDefaultWallpaperCategoryRepository
+    private lateinit var categoryInteractorImpl: CategoryInteractorImpl
+
+    @Before
+    fun setup() {
+        hiltRule.inject()
+        categoryInteractorImpl = CategoryInteractorImpl(fakeDefaultWallpaperCategoryRepository)
+    }
+
+    @Test
+    fun testFetchCategoriesWithValidThirdPartyCategoryAndThirdPartyLiveCategory() = runTest {
+        val categories = categoryInteractorImpl.categories.first()
+
+        // This checks that the total number of categories returned is same as the one defined in
+        // fakes
+        assertThat(categories.size).isEqualTo(NUMBER_OF_FAKE_CATEGORIES_EXCEPT_MY_PHOTOS)
+
+        assertThat(
+            categories.contains(
+                CategoryModel(
+                    commonCategoryData =
+                        CommonCategoryData("ThirdPartyLiveWallpaper-1", "on_device_live_id", 2),
+                    thirdPartyCategoryData = null,
+                    imageCategoryData = null,
+                    collectionCategoryData = null
+                )
+            )
+        )
+        assertThat(categories.map { it.commonCategoryData.priority }).isInOrder()
+
+        assertThat(
+            categories.contains(
+                CategoryModel(
+                    commonCategoryData = CommonCategoryData("ThirdParty-2", "downloads_id", 3),
+                    thirdPartyCategoryData = null,
+                    imageCategoryData = null,
+                    collectionCategoryData = null
+                )
+            )
+        )
+    }
+
+    companion object {
+        private const val NUMBER_OF_FAKE_CATEGORIES_EXCEPT_MY_PHOTOS = 5
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/picker/category/interactor/MyPhotosInteractorImplTest.kt b/tests/robotests/src/com/android/wallpaper/picker/category/interactor/MyPhotosInteractorImplTest.kt
new file mode 100644
index 00000000..799c42c1
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/picker/category/interactor/MyPhotosInteractorImplTest.kt
@@ -0,0 +1,76 @@
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
+package com.android.wallpaper.picker.category.interactor
+
+import android.content.Context
+import com.android.wallpaper.picker.category.domain.interactor.implementations.MyPhotosInteractorImpl
+import com.android.wallpaper.picker.data.category.CategoryModel
+import com.android.wallpaper.testing.FakeDefaultWallpaperCategoryRepository
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.test.TestDispatcher
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.advanceUntilIdle
+import kotlinx.coroutines.test.runTest
+import kotlinx.coroutines.test.setMain
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+
+@HiltAndroidTest
+@OptIn(ExperimentalCoroutinesApi::class)
+@RunWith(RobolectricTestRunner::class)
+class MyPhotosInteractorImplTest {
+
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+    @Inject @ApplicationContext lateinit var context: Context
+
+    @Inject lateinit var testDispatcher: TestDispatcher
+    @Inject lateinit var testScope: TestScope
+    @Inject
+    lateinit var fakeDefaultWallpaperCategoryRepository: FakeDefaultWallpaperCategoryRepository
+    private lateinit var myPhotosInteractorImpl: MyPhotosInteractorImpl
+
+    @Before
+    fun setup() {
+        hiltRule.inject()
+        Dispatchers.setMain(testDispatcher)
+        myPhotosInteractorImpl =
+            MyPhotosInteractorImpl(fakeDefaultWallpaperCategoryRepository, testScope)
+    }
+
+    @Test
+    fun `category flow emits correct values`() = runTest {
+        fakeDefaultWallpaperCategoryRepository.fetchMyPhotosCategory()
+
+        val emittedCategories = mutableListOf<CategoryModel>()
+        val job = launch { myPhotosInteractorImpl.category.collect { emittedCategories.add(it) } }
+
+        // Wait for the collection to happen
+        advanceUntilIdle()
+        job.cancel()
+        assertThat(emittedCategories[0].commonCategoryData.title).isEqualTo("Fake My Photos")
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/picker/category/repository/DefaultWallpaperCategoryRepositoryTest.kt b/tests/robotests/src/com/android/wallpaper/picker/category/repository/DefaultWallpaperCategoryRepositoryTest.kt
new file mode 100644
index 00000000..d1a479d8
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/picker/category/repository/DefaultWallpaperCategoryRepositoryTest.kt
@@ -0,0 +1,130 @@
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
+package com.android.wallpaper.picker.category.repository
+
+import android.content.Context
+import com.android.wallpaper.model.Category
+import com.android.wallpaper.model.ImageCategory
+import com.android.wallpaper.model.ThirdPartyLiveWallpaperCategory
+import com.android.wallpaper.model.WallpaperInfo
+import com.android.wallpaper.module.InjectorProvider
+import com.android.wallpaper.picker.category.data.repository.DefaultWallpaperCategoryRepository
+import com.android.wallpaper.testing.FakeDefaultCategoryFactory
+import com.android.wallpaper.testing.FakeDefaultWallpaperCategoryClient
+import com.android.wallpaper.testing.TestInjector
+import com.android.wallpaper.testing.TestStaticWallpaperInfo
+import com.android.wallpaper.testing.TestWallpaperCategory
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.advanceUntilIdle
+import kotlinx.coroutines.test.runTest
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+
+@HiltAndroidTest
+@OptIn(ExperimentalCoroutinesApi::class)
+@RunWith(RobolectricTestRunner::class)
+class DefaultWallpaperCategoryRepositoryTest {
+
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+    @Inject @ApplicationContext lateinit var context: Context
+    @Inject lateinit var defaultCategoryFactory: FakeDefaultCategoryFactory
+    @Inject lateinit var defaultWallpaperCategoryClient: FakeDefaultWallpaperCategoryClient
+    @Inject lateinit var testScope: TestScope
+    @Inject lateinit var testInjector: TestInjector
+
+    lateinit var repository: DefaultWallpaperCategoryRepository
+
+    @Before
+    fun setUp() {
+        hiltRule.inject()
+        InjectorProvider.setInjector(testInjector)
+    }
+
+    @Test
+    fun `fetchAllCategories should update categories and set isAllCategoriesFetched to true`() =
+        runTest {
+            val category1: Category =
+                ImageCategory(
+                    "My photos" /* title */,
+                    "image_wallpapers" /* collection */,
+                    0 /* priority */
+                )
+
+            val wallpapers = ArrayList<WallpaperInfo>()
+            val wallpaperInfo: WallpaperInfo = TestStaticWallpaperInfo(0)
+            wallpapers.add(wallpaperInfo)
+            val category2: Category =
+                TestWallpaperCategory(
+                    "Test category",
+                    "init_collection",
+                    wallpapers,
+                    1 /* priority */
+                )
+
+            val thirdPartyLiveWallpaperCategory: Category =
+                ThirdPartyLiveWallpaperCategory(
+                    "Third_Party_Title",
+                    "Third_Party_CollectionId",
+                    wallpapers,
+                    1,
+                    emptySet()
+                )
+
+            val mCategories = ArrayList<Category>()
+            mCategories.add(category1)
+            mCategories.add(category2)
+
+            defaultWallpaperCategoryClient.setSystemCategories(mCategories)
+            defaultWallpaperCategoryClient.setThirdPartyLiveWallpaperCategories(
+                listOf(thirdPartyLiveWallpaperCategory)
+            )
+
+            repository =
+                DefaultWallpaperCategoryRepository(
+                    context,
+                    defaultWallpaperCategoryClient,
+                    defaultCategoryFactory,
+                    testScope
+                )
+            testScope.advanceUntilIdle()
+            assertThat(repository.isDefaultCategoriesFetched.value).isTrue()
+            assertThat(repository.systemCategories).isNotNull()
+            assertThat(repository.thirdPartyLiveWallpaperCategory).isNotNull()
+        }
+
+    @Test
+    fun initialStateShouldBeEmpty() = runTest {
+        repository =
+            DefaultWallpaperCategoryRepository(
+                context,
+                defaultWallpaperCategoryClient,
+                defaultCategoryFactory,
+                testScope
+            )
+        assertThat(repository.systemCategories.value).isEmpty()
+        assertThat(repository.isDefaultCategoriesFetched.value).isFalse()
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/picker/common/preview/domain/interactor/BasePreviewInteractorTest.kt b/tests/robotests/src/com/android/wallpaper/picker/common/preview/domain/interactor/BasePreviewInteractorTest.kt
new file mode 100644
index 00000000..b0a79de8
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/picker/common/preview/domain/interactor/BasePreviewInteractorTest.kt
@@ -0,0 +1,163 @@
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
+package com.android.wallpaper.picker.common.preview.domain.interactor
+
+import android.content.Context
+import android.content.pm.ActivityInfo
+import androidx.test.core.app.ActivityScenario
+import com.android.wallpaper.model.WallpaperModelsPair
+import com.android.wallpaper.module.InjectorProvider
+import com.android.wallpaper.picker.common.preview.data.repository.BasePreviewRepository
+import com.android.wallpaper.picker.customization.data.repository.WallpaperRepository
+import com.android.wallpaper.picker.preview.PreviewTestActivity
+import com.android.wallpaper.testing.FakeWallpaperClient
+import com.android.wallpaper.testing.TestInjector
+import com.android.wallpaper.testing.TestWallpaperPreferences
+import com.android.wallpaper.testing.WallpaperModelUtils
+import com.android.wallpaper.testing.collectLastValue
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.EntryPoint
+import dagger.hilt.InstallIn
+import dagger.hilt.android.EntryPointAccessors
+import dagger.hilt.android.components.ActivityComponent
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.test.TestDispatcher
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.runTest
+import kotlinx.coroutines.test.setMain
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+import org.robolectric.Shadows.shadowOf
+
+@HiltAndroidTest
+@OptIn(ExperimentalCoroutinesApi::class)
+@RunWith(RobolectricTestRunner::class)
+class BasePreviewInteractorTest {
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+
+    private lateinit var scenario: ActivityScenario<PreviewTestActivity>
+    private lateinit var basePreviewRepository: BasePreviewRepository
+    private lateinit var wallpaperRepository: WallpaperRepository
+    private lateinit var interactor: BasePreviewInteractor
+
+    @Inject @ApplicationContext lateinit var appContext: Context
+    @Inject lateinit var testDispatcher: TestDispatcher
+    @Inject lateinit var testScope: TestScope
+    @Inject lateinit var testInjector: TestInjector
+    @Inject lateinit var wallpaperPreferences: TestWallpaperPreferences
+    @Inject lateinit var wallpaperClient: FakeWallpaperClient
+
+    @Before
+    fun setUp() {
+        hiltRule.inject()
+
+        InjectorProvider.setInjector(testInjector)
+        Dispatchers.setMain(testDispatcher)
+
+        val activityInfo =
+            ActivityInfo().apply {
+                name = PreviewTestActivity::class.java.name
+                packageName = appContext.packageName
+            }
+        shadowOf(appContext.packageManager).addOrUpdateActivity(activityInfo)
+        scenario = ActivityScenario.launch(PreviewTestActivity::class.java)
+        scenario.onActivity {
+            val activityScopeEntryPoint =
+                EntryPointAccessors.fromActivity(it, ActivityScopeEntryPoint::class.java)
+            basePreviewRepository = activityScopeEntryPoint.basePreviewRepository()
+            wallpaperRepository = activityScopeEntryPoint.wallpaperRepository()
+            interactor = activityScopeEntryPoint.basePreviewInteractor()
+        }
+    }
+
+    @EntryPoint
+    @InstallIn(ActivityComponent::class)
+    interface ActivityScopeEntryPoint {
+        fun basePreviewRepository(): BasePreviewRepository
+
+        fun wallpaperRepository(): WallpaperRepository
+
+        fun basePreviewInteractor(): BasePreviewInteractor
+    }
+
+    @Test
+    fun wallpapers_withHomeAndLockScreenAndPreviewWallpapers_shouldEmitPreview() {
+        testScope.runTest {
+            val homeStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "homeWallpaperId",
+                    collectionId = "homeCollection",
+                )
+            val lockStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "lockWallpaperId",
+                    collectionId = "lockCollection",
+                )
+            val previewStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "previewWallpaperId",
+                    collectionId = "previewCollection",
+                )
+
+            // Current wallpaper models need to be set up before the view model is run.
+            wallpaperClient.setCurrentWallpaperModels(
+                homeStaticWallpaperModel,
+                lockStaticWallpaperModel
+            )
+            basePreviewRepository.setWallpaperModel(previewStaticWallpaperModel)
+
+            val actual = collectLastValue(interactor.wallpapers)()
+            assertThat(actual).isNotNull()
+            assertThat(actual).isEqualTo(WallpaperModelsPair(previewStaticWallpaperModel, null))
+        }
+    }
+
+    @Test
+    fun wallpapers_withHomeAndLockScreenAndNoPreviewWallpapers_shouldEmitCurrentHomeAndLock() {
+        testScope.runTest {
+            val homeStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "homeWallpaperId",
+                    collectionId = "homeCollection",
+                )
+            val lockStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "lockWallpaperId",
+                    collectionId = "lockCollection",
+                )
+
+            // Current wallpaper models need to be set up before the view model is run.
+            wallpaperClient.setCurrentWallpaperModels(
+                homeStaticWallpaperModel,
+                lockStaticWallpaperModel
+            )
+
+            val actual = collectLastValue(interactor.wallpapers)()
+            assertThat(actual).isNotNull()
+            assertThat(actual)
+                .isEqualTo(WallpaperModelsPair(homeStaticWallpaperModel, lockStaticWallpaperModel))
+        }
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/BasePreviewViewModelTest.kt b/tests/robotests/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/BasePreviewViewModelTest.kt
new file mode 100644
index 00000000..b86df3f2
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/BasePreviewViewModelTest.kt
@@ -0,0 +1,126 @@
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
+package com.android.wallpaper.picker.common.preview.ui.viewmodel
+
+import android.content.Context
+import android.content.pm.ActivityInfo
+import androidx.test.core.app.ActivityScenario
+import com.android.wallpaper.model.WallpaperModelsPair
+import com.android.wallpaper.module.InjectorProvider
+import com.android.wallpaper.picker.common.preview.data.repository.BasePreviewRepository
+import com.android.wallpaper.picker.preview.PreviewTestActivity
+import com.android.wallpaper.testing.TestInjector
+import com.android.wallpaper.testing.TestWallpaperPreferences
+import com.android.wallpaper.testing.WallpaperModelUtils
+import com.android.wallpaper.testing.collectLastValue
+import com.android.wallpaper.util.WallpaperConnection
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.EntryPoint
+import dagger.hilt.InstallIn
+import dagger.hilt.android.EntryPointAccessors
+import dagger.hilt.android.components.ActivityComponent
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.test.TestDispatcher
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.runTest
+import kotlinx.coroutines.test.setMain
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+import org.robolectric.Shadows.shadowOf
+
+@HiltAndroidTest
+@OptIn(ExperimentalCoroutinesApi::class)
+@RunWith(RobolectricTestRunner::class)
+class BasePreviewViewModelTest {
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+
+    private lateinit var scenario: ActivityScenario<PreviewTestActivity>
+    private lateinit var basePreviewViewModel: BasePreviewViewModel
+    private lateinit var staticHomePreviewViewModel: StaticPreviewViewModel
+    private lateinit var staticLockPreviewViewModel: StaticPreviewViewModel
+    private lateinit var basePreviewRepository: BasePreviewRepository
+    private lateinit var basePreviewViewModelFactory: BasePreviewViewModel.Factory
+
+    @Inject @ApplicationContext lateinit var appContext: Context
+    @Inject lateinit var testDispatcher: TestDispatcher
+    @Inject lateinit var testScope: TestScope
+    @Inject lateinit var testInjector: TestInjector
+    @Inject lateinit var wallpaperPreferences: TestWallpaperPreferences
+
+    @Before
+    fun setUp() {
+        hiltRule.inject()
+
+        InjectorProvider.setInjector(testInjector)
+        Dispatchers.setMain(testDispatcher)
+
+        val activityInfo =
+            ActivityInfo().apply {
+                name = PreviewTestActivity::class.java.name
+                packageName = appContext.packageName
+            }
+        shadowOf(appContext.packageManager).addOrUpdateActivity(activityInfo)
+        scenario = ActivityScenario.launch(PreviewTestActivity::class.java)
+        scenario.onActivity {
+            val activityScopeEntryPoint =
+                EntryPointAccessors.fromActivity(it, ActivityScopeEntryPoint::class.java)
+            basePreviewRepository = activityScopeEntryPoint.basePreviewRepository()
+            basePreviewViewModelFactory = activityScopeEntryPoint.basePreviewViewModelFactory()
+            basePreviewViewModel = basePreviewViewModelFactory.create(testScope.backgroundScope)
+            staticHomePreviewViewModel = basePreviewViewModel.staticHomeWallpaperPreviewViewModel
+            staticLockPreviewViewModel = basePreviewViewModel.staticLockWallpaperPreviewViewModel
+        }
+    }
+
+    @EntryPoint
+    @InstallIn(ActivityComponent::class)
+    interface ActivityScopeEntryPoint {
+        fun basePreviewRepository(): BasePreviewRepository
+
+        fun basePreviewViewModelFactory(): BasePreviewViewModel.Factory
+    }
+
+    @Test
+    fun wallpaper_setWallpaperModelAndWhichPreview_emitsMatchingValues() {
+        testScope.runTest {
+            val wallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testId",
+                    collectionId = "testCollection",
+                )
+            val whichPreview = WallpaperConnection.WhichPreview.PREVIEW_CURRENT
+
+            basePreviewRepository.setWallpaperModel(wallpaperModel)
+            basePreviewViewModel.setWhichPreview(whichPreview)
+
+            val wallpapersAndWhichPreview =
+                collectLastValue(basePreviewViewModel.wallpapersAndWhichPreview)()
+            assertThat(wallpapersAndWhichPreview).isNotNull()
+            val (actualWallpapers, actualWhichPreview) = wallpapersAndWhichPreview!!
+            assertThat(actualWallpapers).isEqualTo(WallpaperModelsPair(wallpaperModel, null))
+            assertThat(actualWhichPreview).isEqualTo(whichPreview)
+        }
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/StaticPreviewViewModelTest.kt b/tests/robotests/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/StaticPreviewViewModelTest.kt
new file mode 100644
index 00000000..e048bfae
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/StaticPreviewViewModelTest.kt
@@ -0,0 +1,565 @@
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
+package com.android.wallpaper.picker.common.preview.ui.viewmodel
+
+import android.app.WallpaperInfo
+import android.content.Context
+import android.content.pm.ActivityInfo
+import android.content.pm.PackageManager
+import android.content.pm.ResolveInfo
+import android.content.pm.ServiceInfo
+import android.graphics.Bitmap
+import android.graphics.Point
+import android.graphics.Rect
+import androidx.test.core.app.ActivityScenario
+import com.android.wallpaper.model.Screen
+import com.android.wallpaper.module.InjectorProvider
+import com.android.wallpaper.picker.common.preview.data.repository.BasePreviewRepository
+import com.android.wallpaper.picker.common.preview.domain.interactor.BasePreviewInteractor
+import com.android.wallpaper.picker.customization.data.repository.WallpaperRepository
+import com.android.wallpaper.picker.preview.PreviewTestActivity
+import com.android.wallpaper.picker.preview.shared.model.FullPreviewCropModel
+import com.android.wallpaper.testing.FakeWallpaperClient
+import com.android.wallpaper.testing.ShadowWallpaperInfo
+import com.android.wallpaper.testing.TestInjector
+import com.android.wallpaper.testing.TestWallpaperPreferences
+import com.android.wallpaper.testing.WallpaperModelUtils
+import com.android.wallpaper.testing.collectLastValue
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.test.TestDispatcher
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.UnconfinedTestDispatcher
+import kotlinx.coroutines.test.resetMain
+import kotlinx.coroutines.test.runTest
+import kotlinx.coroutines.test.setMain
+import org.junit.After
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+import org.robolectric.Shadows.shadowOf
+import org.robolectric.annotation.Config
+import org.robolectric.shadows.ShadowLooper
+
+@HiltAndroidTest
+@OptIn(ExperimentalCoroutinesApi::class)
+@Config(shadows = [ShadowWallpaperInfo::class])
+@RunWith(RobolectricTestRunner::class)
+class StaticPreviewViewModelTest {
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+
+    private val testDispatcher: TestDispatcher = UnconfinedTestDispatcher()
+    private val testScope: TestScope = TestScope(testDispatcher)
+
+    private lateinit var scenario: ActivityScenario<PreviewTestActivity>
+    private lateinit var viewModel: StaticPreviewViewModel
+    private lateinit var basePreviewRepository: BasePreviewRepository
+    private lateinit var wallpaperRepository: WallpaperRepository
+    private lateinit var interactor: BasePreviewInteractor
+
+    @Inject @ApplicationContext lateinit var appContext: Context
+    @Inject lateinit var testInjector: TestInjector
+    @Inject lateinit var wallpaperPreferences: TestWallpaperPreferences
+    @Inject lateinit var wallpaperClient: FakeWallpaperClient
+
+    @Before
+    fun setUp() {
+        hiltRule.inject()
+
+        InjectorProvider.setInjector(testInjector)
+        Dispatchers.setMain(testDispatcher)
+
+        val activityInfo =
+            ActivityInfo().apply {
+                name = PreviewTestActivity::class.java.name
+                packageName = appContext.packageName
+            }
+        shadowOf(appContext.packageManager).addOrUpdateActivity(activityInfo)
+        scenario = ActivityScenario.launch(PreviewTestActivity::class.java)
+        scenario.onActivity {
+            wallpaperRepository =
+                WallpaperRepository(
+                    testScope.backgroundScope,
+                    wallpaperClient,
+                    wallpaperPreferences,
+                    testDispatcher,
+                )
+            basePreviewRepository = BasePreviewRepository()
+            interactor =
+                BasePreviewInteractor(
+                    basePreviewRepository,
+                    wallpaperRepository,
+                )
+            setViewModel(Screen.HOME_SCREEN)
+        }
+    }
+
+    private fun setViewModel(screen: Screen) {
+        viewModel =
+            StaticPreviewViewModel(
+                interactor,
+                appContext,
+                testDispatcher,
+                screen,
+                testScope.backgroundScope,
+            )
+    }
+
+    @After
+    fun tearDown() {
+        Dispatchers.resetMain()
+    }
+
+    @Test
+    fun staticWallpaperPreviewViewModel_isNotNull() {
+        assertThat(viewModel).isNotNull()
+    }
+
+    @Test
+    fun homeStaticWallpaperModel_withStaticHomeScreenAndNoPreviewWallpaper_shouldEmitHomeScreen() {
+        testScope.runTest {
+            val homeStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "homeWallpaperId",
+                    collectionId = "homeCollection",
+                )
+            val lockStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "lockWallpaperId",
+                    collectionId = "lockCollection",
+                )
+
+            // Current wallpaper models need to be set up before the view model is run.
+            wallpaperClient.setCurrentWallpaperModels(
+                homeStaticWallpaperModel,
+                lockStaticWallpaperModel
+            )
+            setViewModel(Screen.HOME_SCREEN)
+
+            val actual = collectLastValue(viewModel.staticWallpaperModel)()
+            assertThat(actual).isNotNull()
+            assertThat(actual).isEqualTo(homeStaticWallpaperModel)
+        }
+    }
+
+    @Test
+    fun homeStaticWallpaperModel_withLiveHomeScreenAndNoPreviewWallpaper_shouldEmitNull() {
+        testScope.runTest {
+            val resolveInfo =
+                ResolveInfo().apply {
+                    serviceInfo = ServiceInfo()
+                    serviceInfo.packageName = "com.google.android.apps.wallpaper.nexus"
+                    serviceInfo.splitName = "wallpaper_cities_ny"
+                    serviceInfo.name = "NewYorkWallpaper"
+                    serviceInfo.flags = PackageManager.GET_META_DATA
+                }
+            // ShadowWallpaperInfo allows the creation of this object
+            val wallpaperInfo = WallpaperInfo(appContext, resolveInfo)
+            val liveWallpaperModel =
+                WallpaperModelUtils.getLiveWallpaperModel(
+                    wallpaperId = "liveWallpaperId",
+                    collectionId = "liveCollection",
+                    systemWallpaperInfo = wallpaperInfo,
+                )
+
+            // Current wallpaper models need to be set up before the view model is run.
+            wallpaperClient.setCurrentWallpaperModels(liveWallpaperModel, null)
+            setViewModel(Screen.HOME_SCREEN)
+
+            val actual = collectLastValue(viewModel.staticWallpaperModel)()
+            assertThat(actual).isNull()
+        }
+    }
+
+    @Test
+    fun lockStaticWallpaperModel_withStaticLockScreenAndNoPreviewWallpaper_shouldEmitLockScreen() {
+        testScope.runTest {
+            val homeStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "homeWallpaperId",
+                    collectionId = "homeCollection",
+                )
+            val lockStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "lockWallpaperId",
+                    collectionId = "lockCollection",
+                )
+
+            // Current wallpaper models need to be set up before the view model is run.
+            wallpaperClient.setCurrentWallpaperModels(
+                homeStaticWallpaperModel,
+                lockStaticWallpaperModel
+            )
+            setViewModel(Screen.LOCK_SCREEN)
+
+            val actual = collectLastValue(viewModel.staticWallpaperModel)()
+            assertThat(actual).isNotNull()
+            assertThat(actual).isEqualTo(lockStaticWallpaperModel)
+        }
+    }
+
+    @Test
+    fun lockStaticWallpaperModel_withNullLockScreenAndNoPreviewWallpaper_shouldEmitNull() {
+        testScope.runTest {
+            val homeStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "homeWallpaperId",
+                    collectionId = "homeCollection",
+                )
+
+            // Current wallpaper models need to be set up before the view model is run.
+            wallpaperClient.setCurrentWallpaperModels(homeStaticWallpaperModel, null)
+            setViewModel(Screen.LOCK_SCREEN)
+
+            val actual = collectLastValue(viewModel.staticWallpaperModel)()
+            assertThat(actual).isNull()
+        }
+    }
+
+    @Test
+    fun staticWallpaperModel_withStaticPreview_shouldEmitNonNullValue() {
+        testScope.runTest {
+            val staticWallpaperModel = collectLastValue(viewModel.staticWallpaperModel)
+            val testStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testWallpaperId",
+                    collectionId = "testCollection",
+                )
+
+            basePreviewRepository.setWallpaperModel(testStaticWallpaperModel)
+
+            val actual = staticWallpaperModel()
+            assertThat(actual).isNotNull()
+            assertThat(actual).isEqualTo(testStaticWallpaperModel)
+        }
+    }
+
+    @Test
+    fun staticWallpaperModel_withLivePreview_shouldEmitNull() {
+        testScope.runTest {
+            val staticWallpaperModel = collectLastValue(viewModel.staticWallpaperModel)
+            val resolveInfo =
+                ResolveInfo().apply {
+                    serviceInfo = ServiceInfo()
+                    serviceInfo.packageName = "com.google.android.apps.wallpaper.nexus"
+                    serviceInfo.splitName = "wallpaper_cities_ny"
+                    serviceInfo.name = "NewYorkWallpaper"
+                    serviceInfo.flags = PackageManager.GET_META_DATA
+                }
+            // ShadowWallpaperInfo allows the creation of this object
+            val wallpaperInfo = WallpaperInfo(appContext, resolveInfo)
+            val liveWallpaperModel =
+                WallpaperModelUtils.getLiveWallpaperModel(
+                    wallpaperId = "testWallpaperId",
+                    collectionId = "testCollection",
+                    systemWallpaperInfo = wallpaperInfo,
+                )
+
+            basePreviewRepository.setWallpaperModel(liveWallpaperModel)
+
+            // Assert that no value is collected
+            assertThat(staticWallpaperModel()).isNull()
+        }
+    }
+
+    @Test
+    fun staticWallpaperModel_setModelWithCropHints_shouldUpdateCropHintsInfo() {
+        testScope.runTest {
+            val cropHints = listOf(Point(1000, 1000) to Rect(100, 200, 300, 400))
+            val cropHintsInfo = cropHints.associate { createPreviewCropModel(it.first, it.second) }
+            val testStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testWallpaperId",
+                    collectionId = "testCollection",
+                    cropHints = cropHints.toMap()
+                )
+            // Create an empty collector for the wallpaper model so the flow runs
+            backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
+                viewModel.staticWallpaperModel.collect {}
+            }
+
+            basePreviewRepository.setWallpaperModel(testStaticWallpaperModel)
+
+            assertThat(viewModel.cropHintsInfo.value).isNotNull()
+            assertThat(viewModel.cropHintsInfo.value).containsExactlyEntriesIn(cropHintsInfo)
+        }
+    }
+
+    @Test
+    fun staticWallpaperModel_setModelWithCropHintsTwice_shouldClearPreviousCropHintsInfo() {
+        testScope.runTest {
+            val cropHints1 = listOf(Point(1000, 1000) to Rect(100, 200, 300, 400))
+            val cropHints2 = listOf(Point(1500, 1500) to Rect(200, 400, 600, 800))
+            val cropHintsInfo = cropHints2.associate { createPreviewCropModel(it.first, it.second) }
+            val testStaticWallpaperModel1 =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testWallpaperId",
+                    collectionId = "testCollection",
+                    cropHints = cropHints1.toMap()
+                )
+            val testStaticWallpaperModel2 =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testWallpaperId",
+                    collectionId = "testCollection",
+                    cropHints = cropHints2.toMap()
+                )
+            // Create an empty collector for the wallpaper model so the flow runs
+            backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
+                viewModel.staticWallpaperModel.collect {}
+            }
+
+            basePreviewRepository.setWallpaperModel(testStaticWallpaperModel1)
+            basePreviewRepository.setWallpaperModel(testStaticWallpaperModel2)
+
+            assertThat(viewModel.cropHintsInfo.value).isNotNull()
+            assertThat(viewModel.cropHintsInfo.value).containsExactlyEntriesIn(cropHintsInfo)
+        }
+    }
+
+    @Test
+    fun lowResBitmap_withStaticPreview_shouldEmitNonNullValue() {
+        testScope.runTest {
+            val lowResBitmap = collectLastValue(viewModel.lowResBitmap)
+            val testStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testWallpaperId",
+                    collectionId = "testCollection",
+                )
+
+            basePreviewRepository.setWallpaperModel(testStaticWallpaperModel)
+
+            assertThat(lowResBitmap()).isNotNull()
+            assertThat(lowResBitmap()).isInstanceOf(Bitmap::class.java)
+        }
+    }
+
+    @Test
+    fun fullResWallpaperViewModel_withStaticPreviewAndNullCropHints_shouldEmitNonNullValue() {
+        testScope.runTest {
+            val fullResWallpaperViewModel = collectLastValue(viewModel.fullResWallpaperViewModel)
+            val testStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testWallpaperId",
+                    collectionId = "testCollection",
+                )
+
+            basePreviewRepository.setWallpaperModel(testStaticWallpaperModel)
+            // Run TestAsset.decodeRawDimensions & decodeBitmap handler.post to unblock assetDetail
+            ShadowLooper.runUiThreadTasksIncludingDelayedTasks()
+
+            assertThat(fullResWallpaperViewModel()).isNotNull()
+            assertThat(fullResWallpaperViewModel())
+                .isInstanceOf(FullResWallpaperViewModel::class.java)
+        }
+    }
+
+    @Test
+    fun fullResWallpaperViewModel_withStaticPreviewAndCropHints_shouldEmitNonNullValue() {
+        testScope.runTest {
+            val fullResWallpaperViewModel = collectLastValue(viewModel.fullResWallpaperViewModel)
+            val testStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testWallpaperId",
+                    collectionId = "testCollection",
+                )
+            val cropHintsInfo =
+                mapOf(
+                    createPreviewCropModel(
+                        displaySize = Point(1000, 1000),
+                        cropHint = Rect(100, 200, 300, 400)
+                    ),
+                )
+
+            basePreviewRepository.setWallpaperModel(testStaticWallpaperModel)
+            // Run TestAsset.decodeRawDimensions & decodeBitmap handler.post to unblock assetDetail
+            ShadowLooper.runUiThreadTasksIncludingDelayedTasks()
+            viewModel.updateCropHintsInfo(cropHintsInfo)
+
+            assertThat(fullResWallpaperViewModel()).isNotNull()
+            assertThat(fullResWallpaperViewModel())
+                .isInstanceOf(FullResWallpaperViewModel::class.java)
+            assertThat(fullResWallpaperViewModel()?.fullPreviewCropModels).isEqualTo(cropHintsInfo)
+        }
+    }
+
+    @Test
+    fun subsamplingScaleImageViewModel_withStaticPreviewAndCropHints_shouldEmitNonNullValue() {
+        testScope.runTest {
+            val subsamplingScaleImageViewModel =
+                collectLastValue(viewModel.subsamplingScaleImageViewModel)
+            val testStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testWallpaperId",
+                    collectionId = "testCollection",
+                )
+            val cropHintsInfo =
+                mapOf(
+                    createPreviewCropModel(
+                        displaySize = Point(1000, 1000),
+                        cropHint = Rect(100, 200, 300, 400)
+                    ),
+                )
+
+            basePreviewRepository.setWallpaperModel(testStaticWallpaperModel)
+            // Run TestAsset.decodeRawDimensions & decodeBitmap handler.post to unblock assetDetail
+            ShadowLooper.runUiThreadTasksIncludingDelayedTasks()
+            viewModel.updateCropHintsInfo(cropHintsInfo)
+
+            assertThat(subsamplingScaleImageViewModel()).isNotNull()
+            assertThat(subsamplingScaleImageViewModel())
+                .isInstanceOf(FullResWallpaperViewModel::class.java)
+            assertThat(subsamplingScaleImageViewModel()?.fullPreviewCropModels)
+                .isEqualTo(cropHintsInfo)
+        }
+    }
+
+    @Test
+    fun updateCropHintsInfo_updateDefaultCropTrue_onlyAddsNewCropHints() {
+        val cropHintA =
+            createPreviewCropModel(
+                displaySize = Point(1000, 1000),
+                cropHint = Rect(100, 200, 300, 400)
+            )
+        val cropHintB =
+            createPreviewCropModel(
+                displaySize = Point(500, 1500),
+                cropHint = Rect(100, 100, 100, 100)
+            )
+        val cropHintB2 =
+            createPreviewCropModel(
+                displaySize = Point(500, 1500),
+                cropHint = Rect(400, 300, 200, 100)
+            )
+        val cropHintC =
+            createPreviewCropModel(
+                displaySize = Point(400, 600),
+                cropHint = Rect(200, 200, 200, 200)
+            )
+        val cropHintsInfo = mapOf(cropHintA, cropHintB)
+        val additionalCropHintsInfo = mapOf(cropHintB2, cropHintC)
+        val expectedCropHintsInfo = mapOf(cropHintA, cropHintB, cropHintC)
+
+        viewModel.updateCropHintsInfo(cropHintsInfo)
+        assertThat(viewModel.fullPreviewCropModels).containsExactlyEntriesIn(cropHintsInfo)
+        viewModel.updateCropHintsInfo(additionalCropHintsInfo, updateDefaultCrop = true)
+        assertThat(viewModel.fullPreviewCropModels).containsExactlyEntriesIn(expectedCropHintsInfo)
+    }
+
+    @Test
+    fun updateCropHintsInfo_updateDefaultCropFalse_addsAndReplacesPreviousCropHints() {
+        val cropHintA =
+            createPreviewCropModel(
+                displaySize = Point(1000, 1000),
+                cropHint = Rect(100, 200, 300, 400)
+            )
+        val cropHintB =
+            createPreviewCropModel(
+                displaySize = Point(500, 1500),
+                cropHint = Rect(100, 100, 100, 100)
+            )
+        val cropHintB2 =
+            createPreviewCropModel(
+                displaySize = Point(500, 1500),
+                cropHint = Rect(400, 300, 200, 100)
+            )
+        val cropHintC =
+            createPreviewCropModel(
+                displaySize = Point(400, 600),
+                cropHint = Rect(200, 200, 200, 200)
+            )
+        val cropHintsInfo = mapOf(cropHintA, cropHintB)
+        val additionalCropHintsInfo = mapOf(cropHintB2, cropHintC)
+        val expectedCropHintsInfo = mapOf(cropHintA, cropHintB2, cropHintC)
+
+        viewModel.updateCropHintsInfo(cropHintsInfo)
+        assertThat(viewModel.fullPreviewCropModels).containsExactlyEntriesIn(cropHintsInfo)
+        viewModel.updateCropHintsInfo(additionalCropHintsInfo, updateDefaultCrop = false)
+        assertThat(viewModel.fullPreviewCropModels).containsExactlyEntriesIn(expectedCropHintsInfo)
+    }
+
+    @Test
+    fun updateDefaultCropModel_existingDisplaySize_resultsInNoUpdates() {
+        val cropHintA =
+            createPreviewCropModel(
+                displaySize = Point(1000, 1000),
+                cropHint = Rect(100, 200, 300, 400)
+            )
+        val cropHintB =
+            createPreviewCropModel(
+                displaySize = Point(500, 1500),
+                cropHint = Rect(100, 100, 100, 100)
+            )
+        val cropHintB2 =
+            createPreviewCropModel(
+                displaySize = Point(500, 1500),
+                cropHint = Rect(400, 300, 200, 100)
+            )
+        val cropHintsInfo = mapOf(cropHintA, cropHintB)
+
+        viewModel.updateCropHintsInfo(cropHintsInfo)
+        assertThat(viewModel.fullPreviewCropModels).containsExactlyEntriesIn(cropHintsInfo)
+        viewModel.updateDefaultPreviewCropModel(cropHintB2.first, cropHintB2.second)
+        assertThat(viewModel.fullPreviewCropModels).containsExactlyEntriesIn(cropHintsInfo)
+    }
+
+    @Test
+    fun updateDefaultCropModel_newDisplaySize_addsNewDisplaySize() {
+        val cropHintA =
+            createPreviewCropModel(
+                displaySize = Point(1000, 1000),
+                cropHint = Rect(100, 200, 300, 400)
+            )
+        val cropHintB =
+            createPreviewCropModel(
+                displaySize = Point(500, 1500),
+                cropHint = Rect(100, 100, 100, 100)
+            )
+        val cropHintC =
+            createPreviewCropModel(
+                displaySize = Point(400, 600),
+                cropHint = Rect(200, 200, 200, 200)
+            )
+        val cropHintsInfo = mapOf(cropHintA, cropHintB)
+        val expectedCropHintsInfo = mapOf(cropHintA, cropHintB, cropHintC)
+
+        viewModel.updateCropHintsInfo(cropHintsInfo)
+        assertThat(viewModel.fullPreviewCropModels).containsExactlyEntriesIn(cropHintsInfo)
+        viewModel.updateDefaultPreviewCropModel(cropHintC.first, cropHintC.second)
+        assertThat(viewModel.fullPreviewCropModels).containsExactlyEntriesIn(expectedCropHintsInfo)
+    }
+
+    private fun createPreviewCropModel(
+        displaySize: Point,
+        cropHint: Rect
+    ): Pair<Point, FullPreviewCropModel> {
+        return Pair(
+            displaySize,
+            FullPreviewCropModel(
+                cropHint = cropHint,
+                cropSizeModel = null,
+            ),
+        )
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/picker/customization/data/repository/WallpaperColorsRepositoryTest.kt b/tests/robotests/src/com/android/wallpaper/picker/customization/data/repository/WallpaperColorsRepositoryTest.kt
new file mode 100644
index 00000000..44ef7a23
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/picker/customization/data/repository/WallpaperColorsRepositoryTest.kt
@@ -0,0 +1,66 @@
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
+package com.android.wallpaper.picker.customization.data.repository
+
+import android.platform.test.annotations.DisableFlags
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.SetFlagsRule
+import com.android.wallpaper.module.InjectorProvider
+import com.android.wallpaper.picker.customization.shared.model.WallpaperColorsModel
+import com.android.wallpaper.testing.FakeWallpaperClient
+import com.android.wallpaper.testing.TestInjector
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+
+@HiltAndroidTest
+@RunWith(RobolectricTestRunner::class)
+class WallpaperColorsRepositoryTest {
+    @get:Rule(order = 0) var hiltRule = HiltAndroidRule(this)
+    @get:Rule(order = 1) val setFlagsRule = SetFlagsRule()
+
+    @Inject lateinit var testInjector: TestInjector
+    @Inject lateinit var client: FakeWallpaperClient
+    lateinit var repository: WallpaperColorsRepository
+
+    @Before
+    fun setUp() {
+        hiltRule.inject()
+        InjectorProvider.setInjector(testInjector)
+        repository = WallpaperColorsRepository(client)
+    }
+
+    @Test
+    @DisableFlags(com.android.systemui.shared.Flags.FLAG_NEW_CUSTOMIZATION_PICKER_UI)
+    fun initialState_oldPickerUi() {
+        assertThat(repository.homeWallpaperColors.value)
+            .isInstanceOf(WallpaperColorsModel.Loading::class.java)
+    }
+
+    @Test
+    @EnableFlags(com.android.systemui.shared.Flags.FLAG_NEW_CUSTOMIZATION_PICKER_UI)
+    fun initialState_newPickerUi() {
+        assertThat(repository.homeWallpaperColors.value)
+            .isInstanceOf(WallpaperColorsModel.Loaded::class.java)
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/picker/preview/data/repository/DownloadableWallpaperRepositoryTest.kt b/tests/robotests/src/com/android/wallpaper/picker/preview/data/repository/DownloadableWallpaperRepositoryTest.kt
new file mode 100644
index 00000000..bd57d6c0
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/picker/preview/data/repository/DownloadableWallpaperRepositoryTest.kt
@@ -0,0 +1,138 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package com.android.wallpaper.picker.preview.data.repository
+
+import android.app.WallpaperInfo
+import android.content.Context
+import android.content.pm.PackageManager
+import android.content.pm.ResolveInfo
+import android.content.pm.ServiceInfo
+import com.android.wallpaper.picker.data.WallpaperModel
+import com.android.wallpaper.picker.preview.shared.model.DownloadStatus
+import com.android.wallpaper.picker.preview.shared.model.DownloadableWallpaperModel
+import com.android.wallpaper.testing.FakeLiveWallpaperDownloader
+import com.android.wallpaper.testing.ShadowWallpaperInfo
+import com.android.wallpaper.testing.WallpaperModelUtils
+import com.android.wallpaper.testing.collectLastValue
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import kotlinx.coroutines.test.runTest
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+import org.robolectric.annotation.Config
+
+/**
+ * Tests for {@link WallpaperPreviewRepository}.
+ *
+ * WallpaperPreviewRepository cannot be injected in setUp() because it is annotated with scope
+ * ActivityRetainedScoped. We make an instance available via TestActivity, which can inject the SUT
+ * and expose it for testing.
+ */
+@HiltAndroidTest
+@Config(shadows = [ShadowWallpaperInfo::class])
+@RunWith(RobolectricTestRunner::class)
+class DownloadableWallpaperRepositoryTest {
+
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+
+    private lateinit var resultWallpaper: WallpaperModel.LiveWallpaperModel
+    private lateinit var underTest: DownloadableWallpaperRepository
+
+    @Inject @ApplicationContext lateinit var appContext: Context
+    @Inject lateinit var liveWallpaperDownloader: FakeLiveWallpaperDownloader
+
+    @Before
+    fun setUp() {
+        hiltRule.inject()
+
+        resultWallpaper = getTestLiveWallpaperModel()
+        underTest =
+            DownloadableWallpaperRepository(liveWallpaperDownloader = liveWallpaperDownloader)
+    }
+
+    @Test
+    fun downloadableWallpaperModel_downloadSuccess() = runTest {
+        val downloadableWallpaperModel = collectLastValue(underTest.downloadableWallpaperModel)
+
+        assertThat(downloadableWallpaperModel())
+            .isEqualTo(DownloadableWallpaperModel(DownloadStatus.DOWNLOAD_NOT_AVAILABLE, null))
+
+        liveWallpaperDownloader.initiateDownloadableServiceByPass()
+
+        assertThat(downloadableWallpaperModel())
+            .isEqualTo(DownloadableWallpaperModel(DownloadStatus.READY_TO_DOWNLOAD, null))
+
+        underTest.downloadWallpaper {}
+
+        assertThat(downloadableWallpaperModel())
+            .isEqualTo(DownloadableWallpaperModel(DownloadStatus.DOWNLOADING, null))
+
+        liveWallpaperDownloader.proceedToDownloadSuccess(resultWallpaper)
+
+        assertThat(downloadableWallpaperModel())
+            .isEqualTo(DownloadableWallpaperModel(DownloadStatus.DOWNLOADED, resultWallpaper))
+    }
+
+    @Test
+    fun downloadableWallpaperModel_downloadFailed() = runTest {
+        val downloadableWallpaperModel = collectLastValue(underTest.downloadableWallpaperModel)
+
+        liveWallpaperDownloader.initiateDownloadableServiceByPass()
+        underTest.downloadWallpaper {}
+        liveWallpaperDownloader.proceedToDownloadFailed()
+
+        assertThat(downloadableWallpaperModel())
+            .isEqualTo(DownloadableWallpaperModel(DownloadStatus.READY_TO_DOWNLOAD, null))
+    }
+
+    @Test
+    fun downloadableWallpaperModel_cancelDownloadWallpaper() = runTest {
+        val downloadableWallpaperModel = collectLastValue(underTest.downloadableWallpaperModel)
+
+        liveWallpaperDownloader.initiateDownloadableServiceByPass()
+        underTest.downloadWallpaper {}
+        underTest.cancelDownloadWallpaper()
+
+        assertThat(liveWallpaperDownloader.isCancelDownloadWallpaperCalled).isTrue()
+    }
+
+    private fun getTestLiveWallpaperModel(): WallpaperModel.LiveWallpaperModel {
+        // ShadowWallpaperInfo allows the creation of this object
+        val wallpaperInfo =
+            WallpaperInfo(
+                appContext,
+                ResolveInfo().apply {
+                    serviceInfo = ServiceInfo()
+                    serviceInfo.packageName = "com.google.android.apps.wallpaper.nexus"
+                    serviceInfo.splitName = "wallpaper_cities_ny"
+                    serviceInfo.name = "NewYorkWallpaper"
+                    serviceInfo.flags = PackageManager.GET_META_DATA
+                }
+            )
+        return WallpaperModelUtils.getLiveWallpaperModel(
+            wallpaperId = "uniqueId",
+            collectionId = "collectionId",
+            systemWallpaperInfo = wallpaperInfo
+        )
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/picker/preview/data/repository/WallpaperPreviewRepositoryTest.kt b/tests/robotests/src/com/android/wallpaper/picker/preview/data/repository/WallpaperPreviewRepositoryTest.kt
index fe0a904c..4be1e427 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/preview/data/repository/WallpaperPreviewRepositoryTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/preview/data/repository/WallpaperPreviewRepositoryTest.kt
@@ -16,32 +16,20 @@
 
 package com.android.wallpaper.picker.preview.data.repository
 
-import android.app.WallpaperInfo
 import android.content.Context
-import android.content.pm.PackageManager
-import android.content.pm.ResolveInfo
-import android.content.pm.ServiceInfo
 import androidx.test.core.app.ApplicationProvider
 import com.android.wallpaper.module.WallpaperPreferences
-import com.android.wallpaper.picker.data.WallpaperModel
-import com.android.wallpaper.picker.preview.data.util.FakeLiveWallpaperDownloader
-import com.android.wallpaper.picker.preview.shared.model.LiveWallpaperDownloadResultCode
-import com.android.wallpaper.picker.preview.shared.model.LiveWallpaperDownloadResultModel
-import com.android.wallpaper.testing.ShadowWallpaperInfo
 import com.android.wallpaper.testing.TestWallpaperPreferences
-import com.android.wallpaper.testing.WallpaperModelUtils
 import com.android.wallpaper.testing.WallpaperModelUtils.Companion.getStaticWallpaperModel
 import com.google.common.truth.Truth.assertThat
 import dagger.hilt.android.testing.HiltTestApplication
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.test.StandardTestDispatcher
 import kotlinx.coroutines.test.TestScope
-import kotlinx.coroutines.test.runTest
 import org.junit.Before
 import org.junit.Test
 import org.junit.runner.RunWith
 import org.robolectric.RobolectricTestRunner
-import org.robolectric.annotation.Config
 
 /**
  * Tests for {@link WallpaperPreviewRepository}.
@@ -50,7 +38,6 @@ import org.robolectric.annotation.Config
  * ActivityRetainedScoped. We make an instance available via TestActivity, which can inject the SUT
  * and expose it for testing.
  */
-@Config(shadows = [ShadowWallpaperInfo::class])
 @RunWith(RobolectricTestRunner::class)
 class WallpaperPreviewRepositoryTest {
 
@@ -70,12 +57,7 @@ class WallpaperPreviewRepositoryTest {
 
     @Test
     fun setWallpaperModel() {
-        underTest =
-            WallpaperPreviewRepository(
-                liveWallpaperDownloader = FakeLiveWallpaperDownloader(),
-                preferences = prefs,
-                bgDispatcher = testDispatcher,
-            )
+        underTest = WallpaperPreviewRepository(preferences = prefs)
 
         val wallpaperModel =
             getStaticWallpaperModel(
@@ -93,12 +75,7 @@ class WallpaperPreviewRepositoryTest {
     fun dismissSmallTooltip() {
         prefs.setHasSmallPreviewTooltipBeenShown(false)
         prefs.setHasFullPreviewTooltipBeenShown(false)
-        underTest =
-            WallpaperPreviewRepository(
-                liveWallpaperDownloader = FakeLiveWallpaperDownloader(),
-                preferences = prefs,
-                bgDispatcher = testDispatcher,
-            )
+        underTest = WallpaperPreviewRepository(preferences = prefs)
         assertThat(underTest.hasSmallPreviewTooltipBeenShown.value).isFalse()
         assertThat(underTest.hasFullPreviewTooltipBeenShown.value).isFalse()
 
@@ -114,12 +91,7 @@ class WallpaperPreviewRepositoryTest {
     fun dismissFullTooltip() {
         prefs.setHasSmallPreviewTooltipBeenShown(false)
         prefs.setHasFullPreviewTooltipBeenShown(false)
-        underTest =
-            WallpaperPreviewRepository(
-                liveWallpaperDownloader = FakeLiveWallpaperDownloader(),
-                preferences = prefs,
-                bgDispatcher = testDispatcher,
-            )
+        underTest = WallpaperPreviewRepository(preferences = prefs)
         assertThat(underTest.hasSmallPreviewTooltipBeenShown.value).isFalse()
         assertThat(underTest.hasFullPreviewTooltipBeenShown.value).isFalse()
 
@@ -130,74 +102,4 @@ class WallpaperPreviewRepositoryTest {
         assertThat(prefs.getHasFullPreviewTooltipBeenShown()).isTrue()
         assertThat(underTest.hasFullPreviewTooltipBeenShown.value).isTrue()
     }
-
-    @Test
-    fun downloadWallpaper_fails() {
-        val liveWallpaperDownloader = FakeLiveWallpaperDownloader()
-        liveWallpaperDownloader.setWallpaperDownloadResult(
-            LiveWallpaperDownloadResultModel(LiveWallpaperDownloadResultCode.FAIL, null)
-        )
-        underTest =
-            WallpaperPreviewRepository(
-                liveWallpaperDownloader = liveWallpaperDownloader,
-                preferences = prefs,
-                bgDispatcher = testDispatcher,
-            )
-
-        testScope.runTest {
-            val result = underTest.downloadWallpaper()
-
-            assertThat(result).isNotNull()
-            val (code, wallpaperModel) = result!!
-            assertThat(code).isEqualTo(LiveWallpaperDownloadResultCode.FAIL)
-            assertThat(wallpaperModel).isNull()
-        }
-    }
-
-    @Test
-    fun downloadWallpaper_succeeds() {
-        val liveWallpaperDownloader = FakeLiveWallpaperDownloader()
-        val resultWallpaper = getTestLiveWallpaperModel()
-        liveWallpaperDownloader.setWallpaperDownloadResult(
-            LiveWallpaperDownloadResultModel(
-                code = LiveWallpaperDownloadResultCode.SUCCESS,
-                wallpaperModel = resultWallpaper,
-            )
-        )
-        underTest =
-            WallpaperPreviewRepository(
-                liveWallpaperDownloader = liveWallpaperDownloader,
-                preferences = prefs,
-                bgDispatcher = testDispatcher,
-            )
-
-        testScope.runTest {
-            val result = underTest.downloadWallpaper()
-
-            assertThat(result).isNotNull()
-            val (code, wallpaperModel) = result!!
-            assertThat(code).isEqualTo(LiveWallpaperDownloadResultCode.SUCCESS)
-            assertThat(wallpaperModel).isEqualTo(resultWallpaper)
-        }
-    }
-
-    private fun getTestLiveWallpaperModel(): WallpaperModel.LiveWallpaperModel {
-        // ShadowWallpaperInfo allows the creation of this object
-        val wallpaperInfo =
-            WallpaperInfo(
-                context,
-                ResolveInfo().apply {
-                    serviceInfo = ServiceInfo()
-                    serviceInfo.packageName = "com.google.android.apps.wallpaper.nexus"
-                    serviceInfo.splitName = "wallpaper_cities_ny"
-                    serviceInfo.name = "NewYorkWallpaper"
-                    serviceInfo.flags = PackageManager.GET_META_DATA
-                }
-            )
-        return WallpaperModelUtils.getLiveWallpaperModel(
-            wallpaperId = "uniqueId",
-            collectionId = "collectionId",
-            systemWallpaperInfo = wallpaperInfo
-        )
-    }
 }
diff --git a/tests/robotests/src/com/android/wallpaper/picker/preview/domain/interactor/PreviewActionsInteractorTest.kt b/tests/robotests/src/com/android/wallpaper/picker/preview/domain/interactor/PreviewActionsInteractorTest.kt
index 0b6b3617..e9fd7188 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/preview/domain/interactor/PreviewActionsInteractorTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/preview/domain/interactor/PreviewActionsInteractorTest.kt
@@ -16,15 +16,22 @@
 
 package com.android.wallpaper.picker.preview.domain.interactor
 
+import android.app.WallpaperInfo
 import android.content.Context
-import com.android.wallpaper.module.InjectorProvider
+import android.content.pm.PackageManager
+import android.content.pm.ResolveInfo
+import android.content.pm.ServiceInfo
+import com.android.wallpaper.picker.data.WallpaperModel
 import com.android.wallpaper.picker.preview.data.repository.CreativeEffectsRepository
+import com.android.wallpaper.picker.preview.data.repository.DownloadableWallpaperRepository
 import com.android.wallpaper.picker.preview.data.repository.WallpaperPreviewRepository
-import com.android.wallpaper.picker.preview.data.util.FakeLiveWallpaperDownloader
+import com.android.wallpaper.picker.preview.shared.model.DownloadStatus
+import com.android.wallpaper.picker.preview.shared.model.DownloadableWallpaperModel
 import com.android.wallpaper.testing.FakeImageEffectsRepository
+import com.android.wallpaper.testing.FakeLiveWallpaperDownloader
 import com.android.wallpaper.testing.ShadowWallpaperInfo
-import com.android.wallpaper.testing.TestInjector
 import com.android.wallpaper.testing.TestWallpaperPreferences
+import com.android.wallpaper.testing.WallpaperModelUtils
 import com.android.wallpaper.testing.collectLastValue
 import com.google.common.truth.Truth.assertThat
 import dagger.hilt.android.qualifiers.ApplicationContext
@@ -33,9 +40,7 @@ import dagger.hilt.android.testing.HiltAndroidTest
 import javax.inject.Inject
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.ExperimentalCoroutinesApi
-import kotlinx.coroutines.launch
 import kotlinx.coroutines.test.TestDispatcher
-import kotlinx.coroutines.test.advanceUntilIdle
 import kotlinx.coroutines.test.runTest
 import kotlinx.coroutines.test.setMain
 import org.junit.Before
@@ -50,15 +55,17 @@ import org.robolectric.annotation.Config
 @RunWith(RobolectricTestRunner::class)
 @Config(shadows = [ShadowWallpaperInfo::class])
 class PreviewActionsInteractorTest {
+
     @get:Rule var hiltRule = HiltAndroidRule(this)
 
-    private lateinit var previewActionsInteractor: PreviewActionsInteractor
+    private lateinit var resultWallpaper: WallpaperModel.LiveWallpaperModel
     private lateinit var wallpaperPreviewRepository: WallpaperPreviewRepository
     private lateinit var creativeEffectsRepository: CreativeEffectsRepository
+    private lateinit var downloadableWallpaperRepository: DownloadableWallpaperRepository
+    private lateinit var underTest: PreviewActionsInteractor
 
     @Inject lateinit var testDispatcher: TestDispatcher
     @Inject @ApplicationContext lateinit var appContext: Context
-    @Inject lateinit var testInjector: TestInjector
     @Inject lateinit var liveWallpaperDownloader: FakeLiveWallpaperDownloader
     @Inject lateinit var wallpaperPreferences: TestWallpaperPreferences
     @Inject lateinit var imageEffectsRepository: FakeImageEffectsRepository
@@ -67,36 +74,102 @@ class PreviewActionsInteractorTest {
     fun setUp() {
         hiltRule.inject()
 
-        InjectorProvider.setInjector(testInjector)
         Dispatchers.setMain(testDispatcher)
 
-        wallpaperPreviewRepository =
-            WallpaperPreviewRepository(
-                liveWallpaperDownloader,
-                wallpaperPreferences,
-                testDispatcher
-            )
+        resultWallpaper = getTestLiveWallpaperModel()
+
+        wallpaperPreviewRepository = WallpaperPreviewRepository(wallpaperPreferences)
+        downloadableWallpaperRepository = DownloadableWallpaperRepository(liveWallpaperDownloader)
         creativeEffectsRepository = CreativeEffectsRepository(appContext, testDispatcher)
-        previewActionsInteractor =
+        underTest =
             PreviewActionsInteractor(
                 wallpaperPreviewRepository,
                 imageEffectsRepository,
-                creativeEffectsRepository
+                creativeEffectsRepository,
+                downloadableWallpaperRepository,
             )
     }
 
+    /**
+     * Proceeds through all stages of a successful download, from
+     * [DownloadStatus.DOWNLOAD_NOT_AVAILABLE] to [DownloadStatus.DOWNLOADED]
+     */
     @Test
-    fun isDownloading_trueWhenDownloading() = runTest {
-        val downloading = collectLastValue(previewActionsInteractor.isDownloadingWallpaper)
-
-        // Request a download and progress until we're blocked waiting for the result
-        backgroundScope.launch { previewActionsInteractor.downloadWallpaper() }
-        advanceUntilIdle()
-        assertThat(downloading()).isTrue()
-
-        // Set the result and be sure downloading status updates
-        liveWallpaperDownloader.setWallpaperDownloadResult(null)
-        advanceUntilIdle()
-        assertThat(downloading()).isFalse()
+    fun downloadableWallpaperModel_downloadSuccess() = runTest {
+        val downloadableWallpaperModel = collectLastValue(underTest.downloadableWallpaperModel)
+
+        assertThat(downloadableWallpaperModel())
+            .isEqualTo(DownloadableWallpaperModel(DownloadStatus.DOWNLOAD_NOT_AVAILABLE, null))
+
+        liveWallpaperDownloader.initiateDownloadableServiceByPass()
+
+        assertThat(downloadableWallpaperModel())
+            .isEqualTo(DownloadableWallpaperModel(DownloadStatus.READY_TO_DOWNLOAD, null))
+
+        underTest.downloadWallpaper()
+
+        assertThat(downloadableWallpaperModel())
+            .isEqualTo(DownloadableWallpaperModel(DownloadStatus.DOWNLOADING, null))
+
+        liveWallpaperDownloader.proceedToDownloadSuccess(resultWallpaper)
+
+        assertThat(downloadableWallpaperModel())
+            .isEqualTo(DownloadableWallpaperModel(DownloadStatus.DOWNLOADED, resultWallpaper))
+    }
+
+    @Test
+    fun wallpaperModel_shouldUpdateWhenDownloadSuccess() = runTest {
+        val wallpaperModel = collectLastValue(wallpaperPreviewRepository.wallpaperModel)
+
+        assertThat(wallpaperModel()).isNull()
+
+        liveWallpaperDownloader.initiateDownloadableServiceByPass()
+        underTest.downloadWallpaper()
+        liveWallpaperDownloader.proceedToDownloadSuccess(resultWallpaper)
+
+        assertThat(wallpaperModel()).isEqualTo(resultWallpaper)
+    }
+
+    @Test
+    fun downloadableWallpaperModel_downloadFailed() = runTest {
+        val downloadableWallpaperModel = collectLastValue(underTest.downloadableWallpaperModel)
+
+        liveWallpaperDownloader.initiateDownloadableServiceByPass()
+        underTest.downloadWallpaper()
+        liveWallpaperDownloader.proceedToDownloadFailed()
+
+        assertThat(downloadableWallpaperModel())
+            .isEqualTo(DownloadableWallpaperModel(DownloadStatus.READY_TO_DOWNLOAD, null))
+    }
+
+    @Test
+    fun downloadableWallpaperModel_cancelDownloadWallpaper() = runTest {
+        val downloadableWallpaperModel = collectLastValue(underTest.downloadableWallpaperModel)
+
+        liveWallpaperDownloader.initiateDownloadableServiceByPass()
+        underTest.downloadWallpaper()
+        underTest.cancelDownloadWallpaper()
+
+        assertThat(liveWallpaperDownloader.isCancelDownloadWallpaperCalled).isTrue()
+    }
+
+    private fun getTestLiveWallpaperModel(): WallpaperModel.LiveWallpaperModel {
+        // ShadowWallpaperInfo allows the creation of this object
+        val wallpaperInfo =
+            WallpaperInfo(
+                appContext,
+                ResolveInfo().apply {
+                    serviceInfo = ServiceInfo()
+                    serviceInfo.packageName = "com.google.android.apps.wallpaper.nexus"
+                    serviceInfo.splitName = "wallpaper_cities_ny"
+                    serviceInfo.name = "NewYorkWallpaper"
+                    serviceInfo.flags = PackageManager.GET_META_DATA
+                }
+            )
+        return WallpaperModelUtils.getLiveWallpaperModel(
+            wallpaperId = "uniqueId",
+            collectionId = "collectionId",
+            systemWallpaperInfo = wallpaperInfo
+        )
     }
 }
diff --git a/tests/robotests/src/com/android/wallpaper/picker/preview/domain/interactor/WallpaperPreviewInteractorTest.kt b/tests/robotests/src/com/android/wallpaper/picker/preview/domain/interactor/WallpaperPreviewInteractorTest.kt
index 408ac3b3..aed30ac7 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/preview/domain/interactor/WallpaperPreviewInteractorTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/preview/domain/interactor/WallpaperPreviewInteractorTest.kt
@@ -142,8 +142,8 @@ class WallpaperPreviewInteractorTest {
         )
         runCurrent()
 
-        assertThat(client.wallpapersSet[WallpaperDestination.HOME]).containsExactly(wallpaperModel)
-        assertThat(client.wallpapersSet[WallpaperDestination.LOCK]).isEmpty()
+        assertThat(client.wallpapersSet[WallpaperDestination.HOME]).isEqualTo(wallpaperModel)
+        assertThat(client.wallpapersSet[WallpaperDestination.LOCK]).isNull()
     }
 
     @Test
@@ -172,7 +172,7 @@ class WallpaperPreviewInteractorTest {
             wallpaperModel = wallpaperModel,
         )
 
-        assertThat(client.wallpapersSet[WallpaperDestination.HOME]).containsExactly(wallpaperModel)
-        assertThat(client.wallpapersSet[WallpaperDestination.LOCK]).isEmpty()
+        assertThat(client.wallpapersSet[WallpaperDestination.HOME]).isEqualTo(wallpaperModel)
+        assertThat(client.wallpapersSet[WallpaperDestination.LOCK]).isNull()
     }
 }
diff --git a/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/CategoriesViewModelTest.kt b/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/CategoriesViewModelTest.kt
index 9fb07592..2c8582de 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/CategoriesViewModelTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/CategoriesViewModelTest.kt
@@ -21,9 +21,12 @@ import android.content.pm.ActivityInfo
 import androidx.activity.viewModels
 import androidx.test.core.app.ActivityScenario
 import com.android.wallpaper.module.InjectorProvider
+import com.android.wallpaper.module.NetworkStatusNotifier
 import com.android.wallpaper.picker.category.ui.viewmodel.CategoriesViewModel
 import com.android.wallpaper.picker.preview.PreviewTestActivity
 import com.android.wallpaper.testing.TestInjector
+import com.android.wallpaper.testing.TestNetworkStatusNotifier
+import com.android.wallpaper.testing.collectLastValue
 import com.google.common.truth.Truth.assertThat
 import dagger.hilt.android.qualifiers.ApplicationContext
 import dagger.hilt.android.testing.HiltAndroidRule
@@ -31,7 +34,10 @@ import dagger.hilt.android.testing.HiltAndroidTest
 import javax.inject.Inject
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.cancelAndJoin
+import kotlinx.coroutines.launch
 import kotlinx.coroutines.test.TestDispatcher
+import kotlinx.coroutines.test.runTest
 import kotlinx.coroutines.test.setMain
 import org.junit.Before
 import org.junit.Rule
@@ -54,6 +60,8 @@ class CategoriesViewModelTest {
 
     @Inject lateinit var testInjector: TestInjector
 
+    @Inject lateinit var networkStatusNotifier: TestNetworkStatusNotifier
+
     @Before
     fun setUp() {
         hiltRule.inject()
@@ -75,11 +83,200 @@ class CategoriesViewModelTest {
         categoriesViewModel = activity.viewModels<CategoriesViewModel>().value
     }
 
-    // Studio requires at least one test or else it will report a failure
     @Test
-    fun generateTiles_succeeds() {
-        assertThat(categoriesViewModel.sections).isNotNull()
+    fun sections_verifyNumberOfSections() = runTest {
+        val sections = collectLastValue(categoriesViewModel.sections)()
+        assertThat(sections?.size).isEqualTo(EXPECTED_NUMBER_OF_SECTIONS)
+    }
+
+    @Test
+    fun sections_verifyTilesInCreativeCategory() = runTest {
+        val sections = collectLastValue(categoriesViewModel.sections)()
+        val creativeSection = sections?.get(EXPECTED_POSITION_CREATIVE_CATEGORY)
+
+        assertThat(creativeSection?.tileViewModels?.size).isEqualTo(EXPECTED_SIZE_CREATIVE_CATEGORY)
+
+        val emojiTile = creativeSection?.tileViewModels?.get(EXPECTED_POSITION_EMOJI_TILE)
+        assertThat(emojiTile?.text).isEqualTo(EXPECTED_TITLE_EMOJI_TILE)
+
+        val aiTile = creativeSection?.tileViewModels?.get(EXPECTED_POSITION_AI_TILE)
+        assertThat(aiTile?.text).isEqualTo(EXPECTED_TITLE_AI_TILE)
+    }
+
+    @Test
+    fun sections_verifyTilesInMyPhotosCategory() = runTest {
+        val sections = collectLastValue(categoriesViewModel.sections)()
+        val myPhotosSection = sections?.get(EXPECTED_POSITION_MY_PHOTOS_CATEGORY)
+
+        assertThat(myPhotosSection?.tileViewModels?.size)
+            .isEqualTo(EXPECTED_SIZE_MY_PHOTOS_CATEGORY)
+
+        val photoTile = myPhotosSection?.tileViewModels?.get(EXPECTED_POSITION_PHOTO_TILE)
+        assertThat(photoTile?.text).isEqualTo(EXPECTED_TITLE_PHOTO_TILE)
+    }
+
+    @Test
+    fun sections_verifyIndividualCategory() = runTest {
+        val sections = collectLastValue(categoriesViewModel.sections)()
+        val individualSections =
+            sections?.subList(EXPECTED_POSITION_SINGLE_CATEGORIES, sections.size)
+
+        assertThat(individualSections?.size).isEqualTo(EXPECTED_SIZE_SINGLE_CATEGORIES)
+
+        // each section should only have 1 category
+        individualSections?.let {
+            it.forEach { sectionViewModel ->
+                assertThat(sectionViewModel.tileViewModels.size)
+                    .isEqualTo(EXPECTED_SIZE_SINGLE_CATEGORY_TILES)
+            }
+        }
+    }
+
+    @Test
+    fun navigationEvents_verifyNavigateToWallpaperCollection() = runTest {
+        val sections = collectLastValue(categoriesViewModel.sections)()
+
+        val individualSections =
+            sections?.subList(EXPECTED_POSITION_SINGLE_CATEGORIES, sections.size)
+
+        individualSections?.let {
+            var sectionViewModel = it[CATEGORY_INDEX_CELESTIAL_DREAMSCAPES]
+
+            // trigger the onClick of the tile and observe that the correct navigation event is
+            // emitted
+            sectionViewModel.tileViewModels[0].onClicked?.let { onClick ->
+                val collectedValues = mutableListOf<CategoriesViewModel.NavigationEvent>()
+                val job =
+                    launch(testDispatcher) {
+                        categoriesViewModel.navigationEvents.collect { collectedValues.add(it) }
+                    }
+
+                onClick()
+
+                testDispatcher.scheduler.advanceUntilIdle()
+                assertThat(collectedValues[0])
+                    .isEqualTo(
+                        CategoriesViewModel.NavigationEvent.NavigateToWallpaperCollection(
+                            CATEGORY_ID_CELESTIAL_DREAMSCAPES,
+                            CategoriesViewModel.CategoryType.DefaultCategories
+                        )
+                    )
+
+                job.cancelAndJoin()
+            }
+
+            sectionViewModel = it[CATEGORY_INDEX_CYBERPUNK_CITYSCAPE]
+            sectionViewModel.tileViewModels[0].onClicked?.let { onClick ->
+                val collectedValues = mutableListOf<CategoriesViewModel.NavigationEvent>()
+                val job =
+                    launch(testDispatcher) {
+                        categoriesViewModel.navigationEvents.collect { collectedValues.add(it) }
+                    }
+
+                onClick()
+
+                testDispatcher.scheduler.advanceUntilIdle()
+
+                assertThat(collectedValues[0])
+                    .isEqualTo(
+                        CategoriesViewModel.NavigationEvent.NavigateToWallpaperCollection(
+                            CATEGORY_ID_CYBERPUNK_CITYSCAPE,
+                            CategoriesViewModel.CategoryType.DefaultCategories
+                        )
+                    )
+                job.cancelAndJoin()
+            }
+
+            sectionViewModel = it[CATEGORY_INDEX_COSMIC_NEBULA]
+            sectionViewModel.tileViewModels[0].onClicked?.let { onClick ->
+                val collectedValues = mutableListOf<CategoriesViewModel.NavigationEvent>()
+                val job =
+                    launch(testDispatcher) {
+                        categoriesViewModel.navigationEvents.collect { collectedValues.add(it) }
+                    }
+
+                onClick()
+                testDispatcher.scheduler.advanceUntilIdle()
+                assertThat(collectedValues[0])
+                    .isEqualTo(
+                        CategoriesViewModel.NavigationEvent.NavigateToWallpaperCollection(
+                            CATEGORY_ID_COSMIC_NEBULA,
+                            CategoriesViewModel.CategoryType.DefaultCategories
+                        )
+                    )
+                job.cancelAndJoin()
+            }
+        }
+    }
+
+    @Test
+    fun navigationEvents_verifyNavigateToMyPhotos() = runTest {
+        val sections = collectLastValue(categoriesViewModel.sections)()
+        val myPhotosSection = sections?.get(EXPECTED_POSITION_MY_PHOTOS_CATEGORY)
+
+        val photoTile = myPhotosSection?.tileViewModels?.get(EXPECTED_POSITION_PHOTO_TILE)
+        photoTile?.onClicked?.let { onClick ->
+            val collectedValues = mutableListOf<CategoriesViewModel.NavigationEvent>()
+            val job =
+                launch(testDispatcher) {
+                    categoriesViewModel.navigationEvents.collect { collectedValues.add(it) }
+                }
+
+            onClick()
+            testDispatcher.scheduler.advanceUntilIdle()
+            assertThat(collectedValues[0])
+                .isEqualTo(CategoriesViewModel.NavigationEvent.NavigateToPhotosPicker)
+            job.cancelAndJoin()
+        }
+    }
+
+    @Test
+    fun networkStatus_verifyStatusOnNetworkChange() = runTest {
+        val collectedValues = mutableListOf<Boolean>()
+        val job =
+            launch(testDispatcher) {
+                categoriesViewModel.isConnectionObtained.collect { collectedValues.add(it) }
+            }
+        networkStatusNotifier.setAndNotifyNetworkStatus(NetworkStatusNotifier.NETWORK_NOT_CONNECTED)
+        testDispatcher.scheduler.advanceUntilIdle()
+        assertThat(collectedValues[0]).isFalse()
+
+        networkStatusNotifier.setAndNotifyNetworkStatus(NetworkStatusNotifier.NETWORK_CONNECTED)
+        testDispatcher.scheduler.advanceUntilIdle()
+        assertThat(collectedValues[1]).isTrue()
+        job.cancelAndJoin()
     }
 
-    // TODO (b/343476732): add test cases when [CategoriesViewModel] is ready
+    /**
+     * These expected values are from fake interactors and thus would not change with device. Once
+     * the corresponding real test repositories and interactors are available, these fakes will be
+     * replaced with fakes of the repositories or their data sources.
+     */
+    companion object {
+        const val EXPECTED_NUMBER_OF_SECTIONS = 21
+
+        const val EXPECTED_POSITION_CREATIVE_CATEGORY = 0
+        const val EXPECTED_SIZE_CREATIVE_CATEGORY = 2
+        const val EXPECTED_POSITION_EMOJI_TILE = 0
+        const val EXPECTED_POSITION_AI_TILE = 1
+        const val EXPECTED_TITLE_EMOJI_TILE = "Emoji"
+        const val EXPECTED_TITLE_AI_TILE = "A.I."
+
+        const val EXPECTED_POSITION_MY_PHOTOS_CATEGORY = 1
+        const val EXPECTED_SIZE_MY_PHOTOS_CATEGORY = 1
+        const val EXPECTED_POSITION_PHOTO_TILE = 0
+        const val EXPECTED_TITLE_PHOTO_TILE = "Celestial Dreamscape"
+
+        const val EXPECTED_POSITION_SINGLE_CATEGORIES = 2
+        const val EXPECTED_SIZE_SINGLE_CATEGORIES = 19
+        const val EXPECTED_SIZE_SINGLE_CATEGORY_TILES = 1
+
+        const val CATEGORY_ID_CELESTIAL_DREAMSCAPES = "celestial_dreamscapes"
+        const val CATEGORY_ID_CYBERPUNK_CITYSCAPE = "cyberpunk_cityscape"
+        const val CATEGORY_ID_COSMIC_NEBULA = "cosmic_nebula"
+
+        const val CATEGORY_INDEX_CELESTIAL_DREAMSCAPES = 0
+        const val CATEGORY_INDEX_CYBERPUNK_CITYSCAPE = 6
+        const val CATEGORY_INDEX_COSMIC_NEBULA = 8
+    }
 }
diff --git a/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/PreviewActionsViewModelTest.kt b/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/PreviewActionsViewModelTest.kt
index 49974eac..42b752dd 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/PreviewActionsViewModelTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/PreviewActionsViewModelTest.kt
@@ -18,44 +18,33 @@ package com.android.wallpaper.picker.preview.ui.viewmodel
 
 import android.app.WallpaperInfo
 import android.content.Context
-import android.content.pm.ActivityInfo
 import android.content.pm.PackageManager
 import android.content.pm.ResolveInfo
 import android.content.pm.ServiceInfo
 import android.net.Uri
-import androidx.test.core.app.ActivityScenario
 import com.android.wallpaper.effects.Effect
 import com.android.wallpaper.effects.FakeEffectsController
-import com.android.wallpaper.module.InjectorProvider
 import com.android.wallpaper.picker.data.CreativeWallpaperData
-import com.android.wallpaper.picker.data.DownloadableWallpaperData
-import com.android.wallpaper.picker.data.WallpaperModel
-import com.android.wallpaper.picker.preview.PreviewTestActivity
+import com.android.wallpaper.picker.preview.data.repository.CreativeEffectsRepository
+import com.android.wallpaper.picker.preview.data.repository.DownloadableWallpaperRepository
 import com.android.wallpaper.picker.preview.data.repository.ImageEffectsRepository.EffectStatus
 import com.android.wallpaper.picker.preview.data.repository.WallpaperPreviewRepository
-import com.android.wallpaper.picker.preview.data.util.FakeLiveWallpaperDownloader
 import com.android.wallpaper.picker.preview.domain.interactor.PreviewActionsInteractor
 import com.android.wallpaper.picker.preview.shared.model.ImageEffectsModel
-import com.android.wallpaper.picker.preview.shared.model.LiveWallpaperDownloadResultCode
-import com.android.wallpaper.picker.preview.shared.model.LiveWallpaperDownloadResultModel
 import com.android.wallpaper.picker.preview.ui.util.LiveWallpaperDeleteUtil
 import com.android.wallpaper.testing.FakeImageEffectsRepository
+import com.android.wallpaper.testing.FakeLiveWallpaperDownloader
 import com.android.wallpaper.testing.ShadowWallpaperInfo
-import com.android.wallpaper.testing.TestInjector
+import com.android.wallpaper.testing.TestWallpaperPreferences
 import com.android.wallpaper.testing.WallpaperModelUtils
 import com.android.wallpaper.testing.collectLastValue
 import com.google.common.truth.Truth.assertThat
-import dagger.hilt.EntryPoint
-import dagger.hilt.InstallIn
-import dagger.hilt.android.EntryPointAccessors
-import dagger.hilt.android.components.ActivityComponent
 import dagger.hilt.android.qualifiers.ApplicationContext
 import dagger.hilt.android.testing.HiltAndroidRule
 import dagger.hilt.android.testing.HiltAndroidTest
 import javax.inject.Inject
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.ExperimentalCoroutinesApi
-import kotlinx.coroutines.launch
 import kotlinx.coroutines.test.TestDispatcher
 import kotlinx.coroutines.test.runTest
 import kotlinx.coroutines.test.setMain
@@ -64,7 +53,6 @@ import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
 import org.robolectric.RobolectricTestRunner
-import org.robolectric.Shadows
 import org.robolectric.annotation.Config
 
 @HiltAndroidTest
@@ -72,53 +60,35 @@ import org.robolectric.annotation.Config
 @RunWith(RobolectricTestRunner::class)
 @Config(shadows = [ShadowWallpaperInfo::class])
 class PreviewActionsViewModelTest {
+
     @get:Rule var hiltRule = HiltAndroidRule(this)
 
-    private lateinit var scenario: ActivityScenario<PreviewTestActivity>
-    private lateinit var viewModel: PreviewActionsViewModel
     private lateinit var wallpaperPreviewRepository: WallpaperPreviewRepository
-    private lateinit var previewActionsInteractor: PreviewActionsInteractor
+    private lateinit var underTest: PreviewActionsViewModel
 
     @Inject lateinit var testDispatcher: TestDispatcher
-    @Inject @ApplicationContext lateinit var appContext: Context
-    @Inject lateinit var testInjector: TestInjector
+    @Inject lateinit var wallpaperPreferences: TestWallpaperPreferences
     @Inject lateinit var imageEffectsRepository: FakeImageEffectsRepository
-    @Inject lateinit var liveWallpaperDeleteUtil: LiveWallpaperDeleteUtil
+    @Inject @ApplicationContext lateinit var appContext: Context
     @Inject lateinit var liveWallpaperDownloader: FakeLiveWallpaperDownloader
+    @Inject lateinit var liveWallpaperDeleteUtil: LiveWallpaperDeleteUtil
 
     @Before
     fun setUp() {
         hiltRule.inject()
-
-        InjectorProvider.setInjector(testInjector)
         Dispatchers.setMain(testDispatcher)
-
-        val activityInfo =
-            ActivityInfo().apply {
-                name = PreviewTestActivity::class.java.name
-                packageName = appContext.packageName
-            }
-        Shadows.shadowOf(appContext.packageManager).addOrUpdateActivity(activityInfo)
-        scenario = ActivityScenario.launch(PreviewTestActivity::class.java)
-        scenario.onActivity { setEverything(it) }
-    }
-
-    @EntryPoint
-    @InstallIn(ActivityComponent::class)
-    interface ActivityScopeEntryPoint {
-        fun previewActionsInteractor(): PreviewActionsInteractor
-
-        fun wallpaperPreviewRepository(): WallpaperPreviewRepository
-    }
-
-    private fun setEverything(activity: PreviewTestActivity) {
-        val activityScopeEntryPoint =
-            EntryPointAccessors.fromActivity(activity, ActivityScopeEntryPoint::class.java)
-        previewActionsInteractor = activityScopeEntryPoint.previewActionsInteractor()
-        viewModel =
-            PreviewActionsViewModel(previewActionsInteractor, liveWallpaperDeleteUtil, appContext)
-
-        wallpaperPreviewRepository = activityScopeEntryPoint.wallpaperPreviewRepository()
+        wallpaperPreviewRepository = WallpaperPreviewRepository(wallpaperPreferences)
+        underTest =
+            PreviewActionsViewModel(
+                PreviewActionsInteractor(
+                    wallpaperPreviewRepository,
+                    imageEffectsRepository,
+                    CreativeEffectsRepository(appContext, testDispatcher),
+                    DownloadableWallpaperRepository(liveWallpaperDownloader),
+                ),
+                liveWallpaperDeleteUtil,
+                appContext,
+            )
     }
 
     @Test
@@ -127,9 +97,9 @@ class PreviewActionsViewModelTest {
         wallpaperPreviewRepository.setWallpaperModel(model)
 
         // Simulate click of info button
-        collectLastValue(viewModel.onInformationClicked)()?.invoke()
+        collectLastValue(underTest.onInformationClicked)()?.invoke()
 
-        val preview = collectLastValue(viewModel.previewFloatingSheetViewModel)()
+        val preview = collectLastValue(underTest.previewFloatingSheetViewModel)()
         assertThat(preview?.informationFloatingSheetViewModel).isNotNull()
     }
 
@@ -138,7 +108,7 @@ class PreviewActionsViewModelTest {
         val model = WallpaperModelUtils.getStaticWallpaperModel("testId", "testCollection")
         wallpaperPreviewRepository.setWallpaperModel(model)
 
-        val isInformationButtonVisible = collectLastValue(viewModel.isInformationVisible)
+        val isInformationButtonVisible = collectLastValue(underTest.isInformationVisible)
         assertThat(isInformationButtonVisible()).isTrue()
     }
 
@@ -147,7 +117,7 @@ class PreviewActionsViewModelTest {
         val model = WallpaperModelUtils.getStaticWallpaperModel("testId", "testCollection")
         wallpaperPreviewRepository.setWallpaperModel(model)
 
-        val isInformationButtonVisible = collectLastValue(viewModel.isInformationVisible)
+        val isInformationButtonVisible = collectLastValue(underTest.isInformationVisible)
 
         wallpaperPreviewRepository.setWallpaperModel(
             WallpaperModelUtils.getStaticWallpaperModel(
@@ -164,10 +134,10 @@ class PreviewActionsViewModelTest {
         val model = WallpaperModelUtils.getStaticWallpaperModel("testId", "testCollection")
         wallpaperPreviewRepository.setWallpaperModel(model)
 
-        val isInformationButtonChecked = collectLastValue(viewModel.isInformationChecked)
+        val isInformationButtonChecked = collectLastValue(underTest.isInformationChecked)
         assertThat(isInformationButtonChecked()).isFalse()
 
-        collectLastValue(viewModel.onInformationClicked)()?.invoke()
+        collectLastValue(underTest.onInformationClicked)()?.invoke()
 
         assertThat(isInformationButtonChecked()).isTrue()
     }
@@ -183,36 +153,27 @@ class PreviewActionsViewModelTest {
         imageEffectsRepository.imageEffectsModel.value = imageEffectsModel
 
         // Simulate click of effects button
-        collectLastValue(viewModel.onEffectsClicked)()?.invoke()
+        collectLastValue(underTest.onEffectsClicked)()?.invoke()
 
-        val preview = collectLastValue(viewModel.previewFloatingSheetViewModel)()
+        val preview = collectLastValue(underTest.previewFloatingSheetViewModel)()
         assertThat(preview?.imageEffectFloatingSheetViewModel).isNotNull()
     }
 
     @Test
     fun isDownloadVisible_preparesDownloadableWallpaperData() = runTest {
-        val model = getDownloadableWallpaperModel()
-        wallpaperPreviewRepository.setWallpaperModel(model)
+        val isDownloadVisible = collectLastValue(underTest.isDownloadVisible)
+
+        liveWallpaperDownloader.initiateDownloadableServiceByPass()
 
-        val isDownloadVisible = collectLastValue(viewModel.isDownloadVisible)
         assertThat(isDownloadVisible()).isTrue()
     }
 
     @Test
     fun isDownloadButtonEnabled_trueWhenDownloading() = runTest {
-        val isDownloadButtonEnabled = collectLastValue(viewModel.isDownloadButtonEnabled)
-
-        // verify the download button is disabled during a download
-        backgroundScope.launch { previewActionsInteractor.downloadWallpaper() }
-        assertThat(isDownloadButtonEnabled()).isFalse()
+        val isDownloadButtonEnabled = collectLastValue(underTest.isDownloadButtonEnabled)
 
-        val model = getDownloadableWallpaperModel()
+        liveWallpaperDownloader.initiateDownloadableServiceByPass()
 
-        wallpaperPreviewRepository.setWallpaperModel(model)
-        liveWallpaperDownloader.setWallpaperDownloadResult(
-            LiveWallpaperDownloadResultModel(LiveWallpaperDownloadResultCode.FAIL, null)
-        )
-        // verify the download button is enabled after downloading is complete
         assertThat(isDownloadButtonEnabled()).isTrue()
     }
 
@@ -249,35 +210,7 @@ class PreviewActionsViewModelTest {
             )
         wallpaperPreviewRepository.setWallpaperModel(liveWallpaperModel)
 
-        val isDeleteVisible = collectLastValue(viewModel.isDeleteVisible)
+        val isDeleteVisible = collectLastValue(underTest.isDeleteVisible)
         assertThat(isDeleteVisible()).isTrue()
     }
-
-    private fun getDownloadableWallpaperModel(): WallpaperModel.StaticWallpaperModel {
-        val wallpaperInfo =
-            WallpaperInfo(
-                appContext,
-                ResolveInfo().apply {
-                    serviceInfo = ServiceInfo()
-                    serviceInfo.packageName = "com.google.android.apps.wallpaper.nexus"
-                    serviceInfo.splitName = "fake"
-                    serviceInfo.name = "FakeWallpaper"
-                    serviceInfo.flags = PackageManager.GET_META_DATA
-                }
-            )
-        val downladableWallpaperDataTest =
-            DownloadableWallpaperData(
-                groupName = "testGroupName",
-                systemWallpaperInfo = wallpaperInfo,
-                isTitleVisible = false,
-                isApplied = false
-            )
-        val model =
-            WallpaperModelUtils.getStaticWallpaperModel(
-                wallpaperId = "testId",
-                collectionId = "testCollection",
-                downloadableWallpaperData = downladableWallpaperDataTest
-            )
-        return model
-    }
 }
diff --git a/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/StaticWallpaperPreviewViewModelTest.kt b/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/StaticWallpaperPreviewViewModelTest.kt
index 3caec00b..cc4d7d80 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/StaticWallpaperPreviewViewModelTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/StaticWallpaperPreviewViewModelTest.kt
@@ -33,9 +33,11 @@ import com.android.wallpaper.picker.customization.data.repository.WallpaperRepos
 import com.android.wallpaper.picker.customization.shared.model.WallpaperColorsModel
 import com.android.wallpaper.picker.preview.PreviewTestActivity
 import com.android.wallpaper.picker.preview.data.repository.WallpaperPreviewRepository
-import com.android.wallpaper.picker.preview.data.util.FakeLiveWallpaperDownloader
 import com.android.wallpaper.picker.preview.domain.interactor.WallpaperPreviewInteractor
 import com.android.wallpaper.picker.preview.shared.model.FullPreviewCropModel
+import com.android.wallpaper.testing.FakeDisplaysProvider
+import com.android.wallpaper.testing.FakeDisplaysProvider.Companion.FOLDABLE_FOLDED
+import com.android.wallpaper.testing.FakeDisplaysProvider.Companion.FOLDABLE_UNFOLDED_LAND
 import com.android.wallpaper.testing.FakeWallpaperClient
 import com.android.wallpaper.testing.ShadowWallpaperInfo
 import com.android.wallpaper.testing.TestInjector
@@ -85,7 +87,7 @@ class StaticWallpaperPreviewViewModelTest {
     @Inject lateinit var testInjector: TestInjector
     @Inject lateinit var wallpaperPreferences: TestWallpaperPreferences
     @Inject lateinit var wallpaperClient: FakeWallpaperClient
-    @Inject lateinit var liveWallpaperDownloader: FakeLiveWallpaperDownloader
+    @Inject lateinit var fakeDisplaysProvider: FakeDisplaysProvider
 
     @Before
     fun setUp() {
@@ -112,17 +114,8 @@ class StaticWallpaperPreviewViewModelTest {
                 wallpaperPreferences,
                 testDispatcher,
             )
-        wallpaperPreviewRepository =
-            WallpaperPreviewRepository(
-                liveWallpaperDownloader,
-                wallpaperPreferences,
-                testDispatcher,
-            )
-        interactor =
-            WallpaperPreviewInteractor(
-                wallpaperPreviewRepository,
-                wallpaperRepository,
-            )
+        wallpaperPreviewRepository = WallpaperPreviewRepository(wallpaperPreferences)
+        interactor = WallpaperPreviewInteractor(wallpaperPreviewRepository, wallpaperRepository)
         viewModel =
             StaticWallpaperPreviewViewModel(
                 interactor,
@@ -130,6 +123,7 @@ class StaticWallpaperPreviewViewModelTest {
                 wallpaperPreferences,
                 testDispatcher,
                 testScope.backgroundScope,
+                fakeDisplaysProvider,
             )
     }
 
@@ -239,8 +233,8 @@ class StaticWallpaperPreviewViewModelTest {
                 mapOf(
                     createPreviewCropModel(
                         displaySize = Point(1000, 1000),
-                        cropHint = Rect(100, 200, 300, 400)
-                    ),
+                        cropHint = Rect(100, 200, 300, 400),
+                    )
                 )
 
             wallpaperPreviewRepository.setWallpaperModel(testStaticWallpaperModel)
@@ -269,8 +263,8 @@ class StaticWallpaperPreviewViewModelTest {
                 mapOf(
                     createPreviewCropModel(
                         displaySize = Point(1000, 1000),
-                        cropHint = Rect(100, 200, 300, 400)
-                    ),
+                        cropHint = Rect(100, 200, 300, 400),
+                    )
                 )
 
             wallpaperPreviewRepository.setWallpaperModel(testStaticWallpaperModel)
@@ -286,6 +280,42 @@ class StaticWallpaperPreviewViewModelTest {
         }
     }
 
+    @Test
+    fun wallpaperColors_missingCrops_shouldNotEmit() =
+        testScope.runTest {
+            fakeDisplaysProvider.setDisplays(listOf(FOLDABLE_FOLDED, FOLDABLE_UNFOLDED_LAND))
+            // cropHintsInfo, hasAllDisplayCrops, cropHints
+            val cropHintsInfo =
+                mapOf(
+                    createPreviewCropModel(
+                        displaySize = FOLDABLE_FOLDED.displaySize,
+                        cropHint = Rect(100, 200, 300, 400),
+                    )
+                )
+            // storedWallpaperColors
+            val WALLPAPER_ID = "testWallpaperId"
+            val storedWallpaperColors =
+                WallpaperColors(
+                    Color.valueOf(Color.RED),
+                    Color.valueOf(Color.GREEN),
+                    Color.valueOf(Color.BLUE),
+                )
+            // subsamplingScaleImageViewModel
+            val testStaticWallpaperModel =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = WALLPAPER_ID,
+                    collectionId = "testCollection",
+                )
+
+            viewModel.updateCropHintsInfo(cropHintsInfo)
+            wallpaperPreferences.storeWallpaperColors(WALLPAPER_ID, storedWallpaperColors)
+            wallpaperPreviewRepository.setWallpaperModel(testStaticWallpaperModel)
+            // Run TestAsset.decodeRawDimensions & decodeBitmap handler.post to unblock assetDetail
+            ShadowLooper.runUiThreadTasksIncludingDelayedTasks()
+
+            assertThat(collectLastValue(viewModel.wallpaperColors)()).isNull()
+        }
+
     @Test
     fun wallpaperColors_withStoredColorsAndNullCropHints_returnsColorsStoredInPreferences() {
         testScope.runTest {
@@ -294,7 +324,7 @@ class StaticWallpaperPreviewViewModelTest {
                 WallpaperColors(
                     Color.valueOf(Color.RED),
                     Color.valueOf(Color.GREEN),
-                    Color.valueOf(Color.BLUE)
+                    Color.valueOf(Color.BLUE),
                 )
             val wallpaperColors = collectLastValue(viewModel.wallpaperColors)
             val testStaticWallpaperModel =
@@ -329,7 +359,7 @@ class StaticWallpaperPreviewViewModelTest {
                 WallpaperColors(
                     Color.valueOf(Color.CYAN),
                     Color.valueOf(Color.MAGENTA),
-                    Color.valueOf(Color.YELLOW)
+                    Color.valueOf(Color.YELLOW),
                 )
             val wallpaperColors = collectLastValue(viewModel.wallpaperColors)
             val testStaticWallpaperModel =
@@ -363,13 +393,13 @@ class StaticWallpaperPreviewViewModelTest {
                 WallpaperColors(
                     Color.valueOf(Color.RED),
                     Color.valueOf(Color.GREEN),
-                    Color.valueOf(Color.BLUE)
+                    Color.valueOf(Color.BLUE),
                 )
             val clientWallpaperColors =
                 WallpaperColors(
                     Color.valueOf(Color.CYAN),
                     Color.valueOf(Color.MAGENTA),
-                    Color.valueOf(Color.YELLOW)
+                    Color.valueOf(Color.YELLOW),
                 )
             val wallpaperColors = collectLastValue(viewModel.wallpaperColors)
             val testStaticWallpaperModel =
@@ -381,8 +411,8 @@ class StaticWallpaperPreviewViewModelTest {
                 mapOf(
                     createPreviewCropModel(
                         displaySize = Point(1000, 1000),
-                        cropHint = Rect(100, 200, 300, 400)
-                    ),
+                        cropHint = Rect(100, 200, 300, 400),
+                    )
                 )
 
             wallpaperPreferences.storeWallpaperColors(WALLPAPER_ID, storedWallpaperColors)
@@ -411,7 +441,7 @@ class StaticWallpaperPreviewViewModelTest {
                 WallpaperColors(
                     Color.valueOf(Color.CYAN),
                     Color.valueOf(Color.MAGENTA),
-                    Color.valueOf(Color.YELLOW)
+                    Color.valueOf(Color.YELLOW),
                 )
             val wallpaperColors = collectLastValue(viewModel.wallpaperColors)
             val testStaticWallpaperModel =
@@ -423,8 +453,8 @@ class StaticWallpaperPreviewViewModelTest {
                 mapOf(
                     createPreviewCropModel(
                         displaySize = Point(1000, 1000),
-                        cropHint = Rect(100, 200, 300, 400)
-                    ),
+                        cropHint = Rect(100, 200, 300, 400),
+                    )
                 )
 
             wallpaperClient.setWallpaperColors(clientWallpaperColors)
@@ -450,22 +480,22 @@ class StaticWallpaperPreviewViewModelTest {
         val cropHintA =
             createPreviewCropModel(
                 displaySize = Point(1000, 1000),
-                cropHint = Rect(100, 200, 300, 400)
+                cropHint = Rect(100, 200, 300, 400),
             )
         val cropHintB =
             createPreviewCropModel(
                 displaySize = Point(500, 1500),
-                cropHint = Rect(100, 100, 100, 100)
+                cropHint = Rect(100, 100, 100, 100),
             )
         val cropHintB2 =
             createPreviewCropModel(
                 displaySize = Point(500, 1500),
-                cropHint = Rect(400, 300, 200, 100)
+                cropHint = Rect(400, 300, 200, 100),
             )
         val cropHintC =
             createPreviewCropModel(
                 displaySize = Point(400, 600),
-                cropHint = Rect(200, 200, 200, 200)
+                cropHint = Rect(200, 200, 200, 200),
             )
         val cropHintsInfo = mapOf(cropHintA, cropHintB)
         val additionalCropHintsInfo = mapOf(cropHintB2, cropHintC)
@@ -482,22 +512,22 @@ class StaticWallpaperPreviewViewModelTest {
         val cropHintA =
             createPreviewCropModel(
                 displaySize = Point(1000, 1000),
-                cropHint = Rect(100, 200, 300, 400)
+                cropHint = Rect(100, 200, 300, 400),
             )
         val cropHintB =
             createPreviewCropModel(
                 displaySize = Point(500, 1500),
-                cropHint = Rect(100, 100, 100, 100)
+                cropHint = Rect(100, 100, 100, 100),
             )
         val cropHintB2 =
             createPreviewCropModel(
                 displaySize = Point(500, 1500),
-                cropHint = Rect(400, 300, 200, 100)
+                cropHint = Rect(400, 300, 200, 100),
             )
         val cropHintC =
             createPreviewCropModel(
                 displaySize = Point(400, 600),
-                cropHint = Rect(200, 200, 200, 200)
+                cropHint = Rect(200, 200, 200, 200),
             )
         val cropHintsInfo = mapOf(cropHintA, cropHintB)
         val additionalCropHintsInfo = mapOf(cropHintB2, cropHintC)
@@ -514,17 +544,17 @@ class StaticWallpaperPreviewViewModelTest {
         val cropHintA =
             createPreviewCropModel(
                 displaySize = Point(1000, 1000),
-                cropHint = Rect(100, 200, 300, 400)
+                cropHint = Rect(100, 200, 300, 400),
             )
         val cropHintB =
             createPreviewCropModel(
                 displaySize = Point(500, 1500),
-                cropHint = Rect(100, 100, 100, 100)
+                cropHint = Rect(100, 100, 100, 100),
             )
         val cropHintB2 =
             createPreviewCropModel(
                 displaySize = Point(500, 1500),
-                cropHint = Rect(400, 300, 200, 100)
+                cropHint = Rect(400, 300, 200, 100),
             )
         val cropHintsInfo = mapOf(cropHintA, cropHintB)
 
@@ -539,17 +569,17 @@ class StaticWallpaperPreviewViewModelTest {
         val cropHintA =
             createPreviewCropModel(
                 displaySize = Point(1000, 1000),
-                cropHint = Rect(100, 200, 300, 400)
+                cropHint = Rect(100, 200, 300, 400),
             )
         val cropHintB =
             createPreviewCropModel(
                 displaySize = Point(500, 1500),
-                cropHint = Rect(100, 100, 100, 100)
+                cropHint = Rect(100, 100, 100, 100),
             )
         val cropHintC =
             createPreviewCropModel(
                 displaySize = Point(400, 600),
-                cropHint = Rect(200, 200, 200, 200)
+                cropHint = Rect(200, 200, 200, 200),
             )
         val cropHintsInfo = mapOf(cropHintA, cropHintB)
         val expectedCropHintsInfo = mapOf(cropHintA, cropHintB, cropHintC)
@@ -562,14 +592,8 @@ class StaticWallpaperPreviewViewModelTest {
 
     private fun createPreviewCropModel(
         displaySize: Point,
-        cropHint: Rect
+        cropHint: Rect,
     ): Pair<Point, FullPreviewCropModel> {
-        return Pair(
-            displaySize,
-            FullPreviewCropModel(
-                cropHint = cropHint,
-                cropSizeModel = null,
-            ),
-        )
+        return Pair(displaySize, FullPreviewCropModel(cropHint = cropHint, cropSizeModel = null))
     }
 }
diff --git a/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModelTest.kt b/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModelTest.kt
index 70ad1704..6b0c4084 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModelTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModelTest.kt
@@ -37,12 +37,11 @@ import com.android.wallpaper.picker.BasePreviewActivity.EXTRA_WALLPAPER_INFO
 import com.android.wallpaper.picker.BasePreviewActivity.IS_ASSET_ID_PRESENT
 import com.android.wallpaper.picker.BasePreviewActivity.IS_NEW_TASK
 import com.android.wallpaper.picker.data.WallpaperModel
-import com.android.wallpaper.picker.di.modules.PreviewUtilsModule.HomeScreenPreviewUtils
-import com.android.wallpaper.picker.di.modules.PreviewUtilsModule.LockScreenPreviewUtils
+import com.android.wallpaper.picker.di.modules.HomeScreenPreviewUtils
+import com.android.wallpaper.picker.di.modules.LockScreenPreviewUtils
 import com.android.wallpaper.picker.preview.PreviewTestActivity
 import com.android.wallpaper.picker.preview.data.repository.ImageEffectsRepository.EffectStatus
 import com.android.wallpaper.picker.preview.data.repository.WallpaperPreviewRepository
-import com.android.wallpaper.picker.preview.data.util.FakeLiveWallpaperDownloader
 import com.android.wallpaper.picker.preview.shared.model.FullPreviewCropModel
 import com.android.wallpaper.picker.preview.shared.model.ImageEffectsModel
 import com.android.wallpaper.testing.FakeContentProvider
@@ -50,6 +49,7 @@ import com.android.wallpaper.testing.FakeDisplaysProvider
 import com.android.wallpaper.testing.FakeDisplaysProvider.Companion.FOLDABLE_UNFOLDED_LAND
 import com.android.wallpaper.testing.FakeDisplaysProvider.Companion.HANDHELD
 import com.android.wallpaper.testing.FakeImageEffectsRepository
+import com.android.wallpaper.testing.FakeLiveWallpaperDownloader
 import com.android.wallpaper.testing.FakeWallpaperClient
 import com.android.wallpaper.testing.TestInjector
 import com.android.wallpaper.testing.TestWallpaperPreferences
diff --git a/tests/robotests/src/com/android/wallpaper/util/DeepLinkUtilsTest.kt b/tests/robotests/src/com/android/wallpaper/util/DeepLinkUtilsTest.kt
new file mode 100644
index 00000000..5605061a
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/util/DeepLinkUtilsTest.kt
@@ -0,0 +1,73 @@
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
+package com.android.wallpaper.util
+
+import android.content.Intent
+import android.net.Uri
+import com.android.wallpaper.util.DeepLinkUtils.EXTRA_KEY_COLLECTION_ID
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.testing.HiltAndroidTest
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+
+@RunWith(RobolectricTestRunner::class)
+@HiltAndroidTest
+class DeepLinkUtilsTest {
+    private lateinit var intent: Intent
+
+    @Before
+    fun setUp() {
+        intent = Intent()
+    }
+
+    @Test
+    fun testIsDeepLink_DeeplinkIntent_returnsTrue() {
+        intent.data = Uri.fromParts("https", "//g.co/wallpaper", "foo")
+        assertThat(DeepLinkUtils.isDeepLink(intent)).isTrue()
+    }
+
+    @Test
+    fun testIsDeepLink_NoData_returnsFalse() {
+        assertThat(DeepLinkUtils.isDeepLink(intent)).isFalse()
+    }
+
+    @Test
+    fun testIsDeepLink_FakeDomainUri_returnsFalse() {
+        intent.data = Uri.fromParts("https", "//example.com", "foo")
+        assertThat(DeepLinkUtils.isDeepLink(intent)).isFalse()
+    }
+
+    @Test
+    fun getCollectionId_FromUri() {
+        val testCollection = "test_collection"
+        intent.data = Uri.parse("https://g.co/wallpaper?collection_id=$testCollection")
+        assertThat(DeepLinkUtils.getCollectionId(intent)).isEqualTo(testCollection)
+    }
+
+    @Test
+    fun getCollectionId_FromExtra() {
+        val testCollection = "test_collection"
+        intent.putExtra(EXTRA_KEY_COLLECTION_ID, testCollection)
+        assertThat(DeepLinkUtils.getCollectionId(intent)).isEqualTo(testCollection)
+    }
+
+    @Test
+    fun getCollectionId_Empty() {
+        assertThat(DeepLinkUtils.getCollectionId(intent)).isNull()
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/util/WallpaperParserImplTest.kt b/tests/robotests/src/com/android/wallpaper/util/WallpaperParserImplTest.kt
index 65748fb7..774893bc 100644
--- a/tests/robotests/src/com/android/wallpaper/util/WallpaperParserImplTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/util/WallpaperParserImplTest.kt
@@ -31,7 +31,6 @@ import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.test.TestDispatcher
 import kotlinx.coroutines.test.setMain
-import org.junit.Assert.assertThrows
 import org.junit.Before
 import org.junit.Rule
 import org.junit.Test
@@ -101,22 +100,17 @@ class WallpaperParserImplTest {
 
     /**
      * This test uses the file exception_wallpapers.xml that is defined in the resources folder
-     * where if some mandatory attributes aren't defined, an exception will be thrown.
+     * where if some mandatory attributes aren't defined, XMLPullParserException is thrown and empty
+     * list is returned.
      */
     @Test
-    fun parseInvalidXMLForSystemCategories_shouldThrowException() {
+    fun parseInvalidXMLForSystemCategories_shouldReturnEmptyList() {
         @XmlRes
         val wallpapersResId: Int =
             resources.getIdentifier("exception_wallpapers", "xml", packageName)
         assertThat(wallpapersResId).isNotEqualTo(0)
         val parser: XmlResourceParser = resources.getXml(wallpapersResId)
-
-        assertThat(
-                assertThrows(NullPointerException::class.java) {
-                    mWallpaperXMLParserImpl.parseSystemCategories(parser)
-                }
-            )
-            .isNotNull()
+        assertThat(mWallpaperXMLParserImpl.parseSystemCategories(parser)).hasSize(0)
     }
 
     /**
diff --git a/tests/robotests/src/com/android/wallpaper/util/converter/category/DefaultCategoryFactoryTest.kt b/tests/robotests/src/com/android/wallpaper/util/converter/category/DefaultCategoryFactoryTest.kt
index 3bb89a81..27551206 100644
--- a/tests/robotests/src/com/android/wallpaper/util/converter/category/DefaultCategoryFactoryTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/util/converter/category/DefaultCategoryFactoryTest.kt
@@ -49,14 +49,14 @@ class DefaultCategoryFactoryTest {
     fun setUp() {
         hiltRule.inject()
         context = ApplicationProvider.getApplicationContext<HiltTestApplication>()
-        mCategoryFactory = DefaultCategoryFactory(wallpaperModelFactory)
+        mCategoryFactory = DefaultCategoryFactory(context, wallpaperModelFactory)
     }
 
     @Test
     fun testGetCategoryModel() {
         val placeholderCategory = PlaceholderCategory(TEST_TITLE, TEST_COLLECTIONID, TEST_PRIORITY)
 
-        val result = mCategoryFactory.getCategoryModel(context, placeholderCategory)
+        val result = mCategoryFactory.getCategoryModel(placeholderCategory)
 
         validateCommonCategoryData(result)
         assertEquals(result.collectionCategoryData, null)
@@ -67,7 +67,7 @@ class DefaultCategoryFactoryTest {
     @Test
     fun testGetImageCategoryModel() {
         val imageCategory = ImageCategory(TEST_TITLE, TEST_COLLECTIONID, TEST_PRIORITY)
-        val result = mCategoryFactory.getCategoryModel(context, imageCategory)
+        val result = mCategoryFactory.getCategoryModel(imageCategory)
         validateCommonCategoryData(result)
     }
 
diff --git a/tests/robotests/src/com/android/wallpaper/wrapper/DefaultWallpaperCategoryWrapperTest.kt b/tests/robotests/src/com/android/wallpaper/wrapper/DefaultWallpaperCategoryWrapperTest.kt
new file mode 100644
index 00000000..ec70812f
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/wrapper/DefaultWallpaperCategoryWrapperTest.kt
@@ -0,0 +1,56 @@
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
+package com.android.wallpaper.wrapper
+
+import android.content.Context
+import com.android.wallpaper.picker.category.data.repository.WallpaperCategoryRepository
+import com.android.wallpaper.picker.category.wrapper.DefaultWallpaperCategoryWrapper
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import kotlinx.coroutines.test.runTest
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+
+@RunWith(RobolectricTestRunner::class)
+@HiltAndroidTest
+class DefaultWallpaperCategoryWrapperTest {
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+
+    @Inject @ApplicationContext lateinit var context: Context
+
+    @Inject lateinit var fakeDefaultWallpaperCategoryRepository: WallpaperCategoryRepository
+
+    @Inject lateinit var defaultWallpaperCategoryWrapper: DefaultWallpaperCategoryWrapper
+
+    @Before
+    fun setUp() {
+        hiltRule.inject()
+    }
+
+    @Test
+    fun testGetCategories() = runTest {
+        val categories = defaultWallpaperCategoryWrapper.getCategories(false)
+        assertThat(categories).isNotEmpty()
+        assertThat(categories.size).isEqualTo(1)
+    }
+}
```

