```diff
diff --git a/aconfig/customization_picker.aconfig b/aconfig/customization_picker.aconfig
index b6311c14..860f4ac6 100644
--- a/aconfig/customization_picker.aconfig
+++ b/aconfig/customization_picker.aconfig
@@ -27,11 +27,4 @@ flag {
    namespace: "systemui"
    description: "Add reactive variant fonts to some clocks"
    bug: "343495953"
-}
-
-flag {
-    name: "large_screen_wallpaper_collections"
-    namespace: "customization_picker"
-    description: "Enables wallpaper collections for large screen devices."
-    bug: "350781344"
-}
+}
\ No newline at end of file
diff --git a/res/drawable/apply_button_background.xml b/res/drawable/apply_button_background.xml
new file mode 100644
index 00000000..f08df19b
--- /dev/null
+++ b/res/drawable/apply_button_background.xml
@@ -0,0 +1,23 @@
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:state_enabled="false"
+        android:drawable="@drawable/apply_button_background_disabled" />
+    <item
+        android:drawable="@drawable/apply_button_background_variant" />
+</selector>
\ No newline at end of file
diff --git a/res/drawable/apply_button_background_disabled.xml b/res/drawable/apply_button_background_disabled.xml
new file mode 100644
index 00000000..81c95562
--- /dev/null
+++ b/res/drawable/apply_button_background_disabled.xml
@@ -0,0 +1,23 @@
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
+<!-- Note that there is no good way to define an alpha value to a shape. We adjust the alpha of the
+ background in the code -->
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <corners android:radius="@dimen/apply_button_corner_radius" />
+    <solid  android:color="@color/system_on_surface" />
+</shape>
diff --git a/res/drawable/apply_button_background_variant.xml b/res/drawable/apply_button_background_variant.xml
index ec35fb1a..0e47d792 100644
--- a/res/drawable/apply_button_background_variant.xml
+++ b/res/drawable/apply_button_background_variant.xml
@@ -19,15 +19,10 @@
 
     <item android:id="@android:id/mask">
         <shape android:shape="rectangle">
-            <corners android:radius="@dimen/set_wallpaper_button_corner_radius" />
-            <padding
-                android:left="@dimen/set_wallpaper_button_horizontal_padding"
-                android:top="@dimen/set_wallpaper_button_vertical_padding"
-                android:right="@dimen/set_wallpaper_button_horizontal_padding"
-                android:bottom="@dimen/set_wallpaper_button_vertical_padding" />
+            <corners android:radius="@dimen/apply_button_corner_radius" />
             <solid android:color="?android:colorControlHighlight" />
         </shape>
     </item>
 
-    <item android:drawable="@drawable/set_wallpaper_button_background_variant_base" />
+    <item android:drawable="@drawable/apply_button_background_variant_base" />
 </ripple>
\ No newline at end of file
diff --git a/res/drawable/apply_button_background_variant_base.xml b/res/drawable/apply_button_background_variant_base.xml
new file mode 100644
index 00000000..06ea3460
--- /dev/null
+++ b/res/drawable/apply_button_background_variant_base.xml
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
+  -->
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <corners android:radius="@dimen/apply_button_corner_radius" />
+    <solid  android:color="@color/system_primary" />
+</shape>
\ No newline at end of file
diff --git a/res/drawable/cancel_button_background_variant.xml b/res/drawable/cancel_button_background_variant.xml
new file mode 100644
index 00000000..254eb2d9
--- /dev/null
+++ b/res/drawable/cancel_button_background_variant.xml
@@ -0,0 +1,28 @@
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
+            <corners android:radius="@dimen/apply_button_corner_radius" />
+            <stroke android:color="?android:colorControlHighlight" />
+        </shape>
+    </item>
+
+    <item android:drawable="@drawable/cancel_button_background_variant_base" />
+</ripple>
\ No newline at end of file
diff --git a/res/drawable/cancel_button_background_variant_base.xml b/res/drawable/cancel_button_background_variant_base.xml
new file mode 100644
index 00000000..622be5d1
--- /dev/null
+++ b/res/drawable/cancel_button_background_variant_base.xml
@@ -0,0 +1,23 @@
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
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <corners android:radius="@dimen/apply_button_corner_radius" />
+    <stroke
+        android:width="1dp"
+        android:color="@color/system_outline_variant" />
+</shape>
\ No newline at end of file
diff --git a/res/drawable/checkbox_circle_shape.xml b/res/drawable/checkbox_circle_shape.xml
new file mode 100644
index 00000000..5440865e
--- /dev/null
+++ b/res/drawable/checkbox_circle_shape.xml
@@ -0,0 +1,31 @@
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
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:bottom="12dp"
+        android:end="12dp"
+        android:top="12dp">
+        <selector>
+            <item
+                android:drawable="@drawable/ic_check_circle_filled_24dp"
+                android:state_checked="true" />
+            <item
+                android:drawable="@drawable/ic_circle_outline_24dp"
+                android:state_checked="false" />
+        </selector>
+    </item>
+</layer-list>
diff --git a/res/drawable/floating_tab_toolbar_tab_background.xml b/res/drawable/floating_tab_toolbar_tab_background.xml
index 0c45f7ef..fcce7fd7 100644
--- a/res/drawable/floating_tab_toolbar_tab_background.xml
+++ b/res/drawable/floating_tab_toolbar_tab_background.xml
@@ -13,7 +13,8 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License.
   -->
-<shape xmlns:android="http://schemas.android.com/apk/res/android"
+<shape
+    xmlns:android="http://schemas.android.com/apk/res/android"
     android:shape="rectangle">
     <corners android:radius="100dp" />
     <solid android:color="@color/system_secondary_container" />
diff --git a/res/drawable/ic_check_circle_filled_24dp.xml b/res/drawable/ic_check_circle_filled_24dp.xml
new file mode 100644
index 00000000..08880112
--- /dev/null
+++ b/res/drawable/ic_check_circle_filled_24dp.xml
@@ -0,0 +1,26 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:tint="@android:color/system_primary_light"
+    android:viewportHeight="24"
+    android:viewportWidth="24">
+    <path
+        android:fillColor="@android:color/white"
+        android:pathData="M12,2C6.48,2 2,6.48 2,12s4.48,10 10,10c5.52,0 10,-4.48 10,-10S17.52,2 12,2zM10.59,16.6l-4.24,-4.24l1.41,-1.41l2.83,2.83l5.66,-5.66l1.41,1.41L10.59,16.6z" />
+</vector>
diff --git a/res/drawable/ic_circle_outline_24dp.xml b/res/drawable/ic_circle_outline_24dp.xml
new file mode 100644
index 00000000..2c35da72
--- /dev/null
+++ b/res/drawable/ic_circle_outline_24dp.xml
@@ -0,0 +1,26 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:tint="@android:color/system_primary_light"
+    android:viewportHeight="24"
+    android:viewportWidth="24">
+    <path
+        android:fillColor="@android:color/white"
+        android:pathData="M12,2C6.48,2 2,6.48 2,12s4.48,10 10,10 10,-4.48 10,-10S17.52,2 12,2zM12,20c-4.42,0 -8,-3.58 -8,-8s3.58,-8 8,-8 8,3.58 8,8 -3.58,8 -8,8z" />
+</vector>
diff --git a/res/layout/activity_cusomization_picker2.xml b/res/layout/activity_cusomization_picker2.xml
index aad2e9e5..303eef08 100644
--- a/res/layout/activity_cusomization_picker2.xml
+++ b/res/layout/activity_cusomization_picker2.xml
@@ -13,127 +13,12 @@
     See the License for the specific language governing permissions and
     limitations under the License.
 -->
-<androidx.constraintlayout.widget.ConstraintLayout
+<FrameLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:app="http://schemas.android.com/apk/res-auto"
-    android:id="@+id/root_view"
     android:layout_width="match_parent"
     android:layout_height="match_parent">
-
     <FrameLayout
-        android:id="@+id/nav_button"
-        android:layout_width="36dp"
-        android:layout_height="@dimen/wallpaper_control_button_size"
-        android:background="@drawable/nav_button_background"
-        android:layout_marginStart="@dimen/nav_button_start_margin"
-        app:layout_constraintStart_toStartOf="parent"
-        app:layout_constraintTop_toTopOf="@id/toolbar"
-        app:layout_constraintBottom_toBottomOf="@id/toolbar">
-        <View
-            android:id="@+id/nav_button_icon"
-            android:layout_width="24dp"
-            android:layout_height="24dp"
-            android:background="@drawable/ic_close_24dp"
-            android:layout_gravity="center" />
-    </FrameLayout>
-
-    <Toolbar
-        android:id="@+id/toolbar"
-        android:layout_width="0dp"
-        android:layout_height="?android:attr/actionBarSize"
-        android:theme="?android:attr/actionBarTheme"
-        android:importantForAccessibility="yes"
-        android:layout_gravity="top"
-        app:layout_constraintTop_toTopOf="parent"
-        app:layout_constraintStart_toEndOf="@+id/nav_button"
-        app:layout_constraintEnd_toStartOf="@+id/apply_button">
-        <TextView
-            android:id="@+id/custom_toolbar_title"
-            android:layout_width="wrap_content"
-            android:layout_height="wrap_content"
-            android:ellipsize="end"
-            android:maxLines="1"
-            android:textAppearance="@style/CollapsingToolbar.Collapsed"/>
-    </Toolbar>
-
-    <Button
-        android:id="@+id/apply_button"
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:minHeight="@dimen/touch_target_min_height"
-        android:layout_marginEnd="@dimen/apply_button_end_margin"
-        android:background="@drawable/apply_button_background_variant"
-        android:text="@string/apply_btn"
-        android:textColor="@color/system_on_primary"
-        android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
-        app:layout_constraintEnd_toEndOf="parent"
-        app:layout_constraintTop_toTopOf="@id/toolbar"
-        app:layout_constraintBottom_toBottomOf="@id/toolbar"/>
-
-    <androidx.constraintlayout.motion.widget.MotionLayout
-        android:id="@+id/picker_motion_layout"
-        android:layout_width="0dp"
-        android:layout_height="0dp"
-        app:layout_constraintTop_toBottomOf="@+id/toolbar"
-        app:layout_constraintStart_toStartOf="parent"
-        app:layout_constraintEnd_toEndOf="parent"
-        app:layout_constraintBottom_toBottomOf="parent"
-        app:layoutDescription="@xml/customization_picker_layout_scene">
-
-        <FrameLayout
-            android:id="@+id/preview_header"
-            android:layout_width="0dp"
-            android:layout_height="@dimen/customization_picker_preview_header_expanded_height"
-            app:layout_constraintTop_toTopOf="parent"
-            app:layout_constraintStart_toStartOf="parent"
-            app:layout_constraintEnd_toEndOf="parent">
-
-            <androidx.viewpager2.widget.ViewPager2
-                android:id="@+id/preview_pager"
-                android:layout_width="match_parent"
-                android:layout_height="match_parent" />
-        </FrameLayout>
-
-        <androidx.core.widget.NestedScrollView
-            android:id="@+id/bottom_scroll_view"
-            android:layout_width="0dp"
-            android:layout_height="0dp"
-            app:layout_constraintTop_toBottomOf="@+id/preview_header"
-            app:layout_constraintStart_toStartOf="parent"
-            app:layout_constraintEnd_toEndOf="parent"
-            app:layout_constraintBottom_toBottomOf="parent">
-
-            <androidx.constraintlayout.motion.widget.MotionLayout
-                android:id="@+id/customization_option_container"
-                android:layout_width="match_parent"
-                android:layout_height="wrap_content"
-                android:paddingHorizontal="@dimen/customization_option_container_horizontal_padding"
-                app:layoutDescription="@xml/customization_option_container_layout_scene">
-
-                <LinearLayout
-                    android:id="@+id/lock_customization_option_container"
-                    android:layout_width="match_parent"
-                    android:layout_height="wrap_content"
-                    android:showDividers="middle"
-                    android:divider="@drawable/customization_option_entry_divider"
-                    android:orientation="vertical" />
-
-                <LinearLayout
-                    android:id="@+id/home_customization_option_container"
-                    android:layout_width="match_parent"
-                    android:layout_height="wrap_content"
-                    android:showDividers="middle"
-                    android:divider="@drawable/customization_option_entry_divider"
-                    android:orientation="vertical" />
-            </androidx.constraintlayout.motion.widget.MotionLayout>
-        </androidx.core.widget.NestedScrollView>
-
-        <FrameLayout
-            android:id="@+id/customization_option_floating_sheet_container"
-            android:layout_width="0dp"
-            android:layout_height="wrap_content"
-            app:layout_constraintStart_toStartOf="parent"
-            app:layout_constraintEnd_toEndOf="parent"
-            app:layout_constraintTop_toBottomOf="parent" />
-    </androidx.constraintlayout.motion.widget.MotionLayout>
-</androidx.constraintlayout.widget.ConstraintLayout>
+        android:id="@+id/fragment_container"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"/>
+</FrameLayout>
diff --git a/res/layout/floating_toolbar.xml b/res/layout/floating_toolbar.xml
index 3a38cec3..0f5b225a 100644
--- a/res/layout/floating_toolbar.xml
+++ b/res/layout/floating_toolbar.xml
@@ -20,7 +20,8 @@
     android:layout_height="wrap_content"
     android:background="@drawable/floating_tab_toolbar_background"
     tools:ignore="contentDescription"
-    android:padding="@dimen/floating_tab_toolbar_padding">
+    android:paddingVertical="@dimen/floating_tab_toolbar_padding_vertical"
+    android:paddingHorizontal="@dimen/floating_tab_toolbar_padding_horizontal">
 
     <androidx.recyclerview.widget.RecyclerView
         android:id="@+id/tab_list"
@@ -30,7 +31,7 @@
         app:layoutManager="LinearLayoutManager"  />
 
     <include
-        layout="@layout/floating_toolbar_tab_placeholder"
+        layout="@layout/floating_toolbar_tab"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:visibility="invisible" />
diff --git a/res/layout/floating_toolbar_tab.xml b/res/layout/floating_toolbar_tab.xml
index be7dc8c8..2525161c 100644
--- a/res/layout/floating_toolbar_tab.xml
+++ b/res/layout/floating_toolbar_tab.xml
@@ -13,33 +13,46 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License.
   -->
-<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
     xmlns:tools="http://schemas.android.com/tools"
-    android:id="@+id/tab_container"
     android:layout_width="wrap_content"
     android:layout_height="wrap_content"
-    android:minHeight="@dimen/accessibility_min_height"
-    android:background="@drawable/floating_tab_toolbar_tab_background"
-    android:gravity="center_vertical"
-    android:paddingVertical="@dimen/floating_tab_toolbar_tab_vertical_padding"
-    android:paddingHorizontal="@dimen/floating_tab_toolbar_tab_horizontal_padding">
+    android:minHeight="@dimen/accessibility_min_height">
 
-    <ImageView
-        android:id="@+id/tab_icon"
-        android:layout_width="@dimen/floating_tab_toolbar_tab_icon_size"
-        android:layout_height="@dimen/floating_tab_toolbar_tab_icon_size"
-        android:layout_marginEnd="@dimen/floating_tab_toolbar_tab_icon_margin_end"
-        app:tint="@color/system_on_surface"
-        tools:src="@drawable/ic_delete" />
 
-    <TextView
-        android:id="@+id/label_text"
+    <!-- We intentionally wrap this linear layout with a frame layout to implement a shorter visual
+       height while maintaining a larger tap area height of at least 48 dp for a11y -->
+    <LinearLayout
+        android:id="@+id/tab_container"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
-        android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
-        android:textColor="@color/text_color_primary"
-        android:gravity="center"
-        android:lines="1"
-        tools:text="Tab Primary"/>
-</LinearLayout>
\ No newline at end of file
+        android:minHeight="@dimen/floating_tab_toolbar_tab_min_height"
+        android:background="@drawable/floating_tab_toolbar_tab_background"
+        android:layout_gravity="center"
+        android:gravity="center_vertical"
+        android:paddingVertical="@dimen/floating_tab_toolbar_tab_vertical_padding"
+        android:paddingHorizontal="@dimen/floating_tab_toolbar_tab_horizontal_padding"
+        tools:ignore="UselessParent">
+
+        <ImageView
+            android:id="@+id/tab_icon"
+            android:layout_width="@dimen/floating_tab_toolbar_tab_icon_size"
+            android:layout_height="@dimen/floating_tab_toolbar_tab_icon_size"
+            android:layout_marginEnd="@dimen/floating_tab_toolbar_tab_icon_margin_end"
+            app:tint="@color/system_on_surface"
+            android:src="@drawable/ic_delete"
+            android:importantForAccessibility="no" />
+
+        <TextView
+            android:id="@+id/label_text"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
+            android:textColor="@color/text_color_primary"
+            android:gravity="center"
+            android:lines="1"
+            android:text="@string/tab_placeholder_text"/>
+
+    </LinearLayout>
+</FrameLayout>
\ No newline at end of file
diff --git a/res/layout/floating_toolbar_tab_placeholder.xml b/res/layout/floating_toolbar_tab_placeholder.xml
deleted file mode 100644
index bcff5286..00000000
--- a/res/layout/floating_toolbar_tab_placeholder.xml
+++ /dev/null
@@ -1,44 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?><!--
-  ~ Copyright (C) 2024 The Android Open Source Project
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
-<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:app="http://schemas.android.com/apk/res-auto"
-    android:layout_width="wrap_content"
-    android:layout_height="wrap_content"
-    android:minHeight="@dimen/accessibility_min_height"
-    android:background="@drawable/floating_tab_toolbar_tab_background"
-    android:gravity="center_vertical"
-    android:paddingVertical="@dimen/floating_tab_toolbar_tab_vertical_padding"
-    android:paddingHorizontal="@dimen/floating_tab_toolbar_tab_horizontal_padding">
-
-    <ImageView
-        android:id="@+id/tab_icon"
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:layout_marginEnd="@dimen/floating_tab_toolbar_tab_icon_margin_end"
-        app:tint="@color/system_on_surface"
-        android:importantForAccessibility="no"
-        android:src="@drawable/ic_delete" />
-
-    <TextView
-        android:id="@+id/label_text"
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
-        android:textColor="@color/text_color_primary"
-        android:gravity="center"
-        android:lines="1"
-        android:text="@string/tab_placeholder_text"/>
-</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/fragment_customization_picker2.xml b/res/layout/fragment_customization_picker2.xml
new file mode 100755
index 00000000..d6d50e63
--- /dev/null
+++ b/res/layout/fragment_customization_picker2.xml
@@ -0,0 +1,147 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<androidx.constraintlayout.widget.ConstraintLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/root_view"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent">
+
+    <FrameLayout
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
+        android:layout_width="0dp"
+        android:layout_height="?android:attr/actionBarSize"
+        android:theme="?android:attr/actionBarTheme"
+        android:importantForAccessibility="yes"
+        android:layout_gravity="top"
+        app:layout_constraintTop_toTopOf="parent"
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
+
+    <Button
+        android:id="@+id/apply_button"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:minHeight="@dimen/touch_target_min_height"
+        android:layout_marginEnd="@dimen/apply_button_end_margin"
+        android:background="@drawable/apply_button_background"
+        android:text="@string/apply_btn"
+        android:textColor="@color/system_on_primary"
+        android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintTop_toTopOf="@id/toolbar"
+        app:layout_constraintBottom_toBottomOf="@id/toolbar"/>
+
+    <androidx.constraintlayout.motion.widget.MotionLayout
+        android:id="@+id/picker_motion_layout"
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        app:layout_constraintTop_toBottomOf="@+id/toolbar"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintBottom_toBottomOf="parent"
+        app:layoutDescription="@xml/customization_picker_layout_scene">
+
+        <FrameLayout
+            android:id="@+id/preview_header"
+            android:layout_width="0dp"
+            android:layout_height="@dimen/customization_picker_preview_header_expanded_height"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent">
+
+            <androidx.viewpager2.widget.ViewPager2
+                android:id="@+id/preview_pager"
+                android:layout_width="match_parent"
+                android:layout_height="match_parent" />
+
+            <View
+                android:id="@+id/pager_touch_interceptor"
+                android:layout_width="match_parent"
+                android:layout_height="match_parent"
+                android:visibility="gone"
+                android:clickable="true" />
+        </FrameLayout>
+
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
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:paddingHorizontal="@dimen/customization_option_container_horizontal_padding"
+                app:layoutDescription="@xml/customization_option_container_layout_scene">
+
+                <LinearLayout
+                    android:id="@+id/lock_customization_option_container"
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    android:showDividers="middle"
+                    android:divider="@drawable/customization_option_entry_divider"
+                    android:orientation="vertical" />
+
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
+
diff --git a/res/layout/fragment_small_preview_foldable.xml b/res/layout/fragment_small_preview_foldable.xml
index d4518c2c..b40909a0 100644
--- a/res/layout/fragment_small_preview_foldable.xml
+++ b/res/layout/fragment_small_preview_foldable.xml
@@ -18,7 +18,7 @@
 <androidx.constraintlayout.widget.ConstraintLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
-    android:id="@+id/container"
+    android:id="@+id/small_preview_screen"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:fitsSystemWindows="true"
diff --git a/res/layout/fragment_small_preview_foldable2.xml b/res/layout/fragment_small_preview_foldable2.xml
index 545d545e..9f32218b 100644
--- a/res/layout/fragment_small_preview_foldable2.xml
+++ b/res/layout/fragment_small_preview_foldable2.xml
@@ -14,67 +14,58 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License.
   -->
-<androidx.constraintlayout.widget.ConstraintLayout
+<androidx.constraintlayout.motion.widget.MotionLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
-    android:id="@+id/container"
+    android:id="@+id/small_preview_screen"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
+    android:orientation="vertical"
     android:fitsSystemWindows="true"
     android:transitionGroup="true"
     android:clipChildren="false"
-    android:clipToPadding="false">
+    android:clipToPadding="false"
+    app:layoutDescription="@xml/small_preview_fragment_layout_scene">
 
     <include
         android:id="@+id/toolbar_container"
         layout="@layout/section_header_content"
-        android:layout_width="0dp"
-        android:layout_height="wrap_content"
+        android:layout_width="match_parent"
+        android:layout_height="0dp"
         app:layout_constraintTop_toTopOf="parent"
         app:layout_constraintStart_toStartOf="parent"
-        app:layout_constraintEnd_toStartOf="@id/button_set_wallpaper"
-        app:layout_constraintVertical_chainStyle="spread_inside" />
+        app:layout_constraintEnd_toEndOf="parent"/>
 
     <Button
-        android:id="@+id/button_set_wallpaper"
+        android:id="@+id/button_next"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:layout_marginEnd="@dimen/set_wallpaper_button_margin_end"
-        android:background="@drawable/set_wallpaper_button_background_variant"
+        android:background="@drawable/apply_button_background_variant"
         android:elevation="@dimen/wallpaper_preview_buttons_elevation"
         android:gravity="center"
+        android:minWidth="@dimen/apply_button_width"
         android:minHeight="@dimen/touch_target_min_height"
         android:text="@string/next_page_content_description"
         android:textColor="@color/system_on_primary"
         android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
         app:layout_constraintEnd_toEndOf="parent"
-        app:layout_constraintTop_toTopOf="parent"
+        app:layout_constraintTop_toTopOf="@id/toolbar_container"
         app:layout_constraintBottom_toBottomOf="@id/toolbar_container"/>
 
-    <!-- Set clipToPadding to false so that during transition scaling, child card view is not
-    clipped to the header bar -->
+    <!-- TODO: Create a new layout xml for reusing for both handheld and foldable -->
     <androidx.constraintlayout.motion.widget.MotionLayout
-        android:id="@+id/small_preview_motion_layout"
+        android:id="@+id/small_preview_container"
         android:layout_width="match_parent"
         android:layout_height="0dp"
-        android:importantForAccessibility="no"
-        android:clipChildren="false"
-        android:clipToPadding="false"
-        android:gravity="center"
         app:layout_constraintTop_toBottomOf="@id/toolbar_container"
         app:layout_constraintBottom_toBottomOf="parent"
         app:layout_constraintStart_toStartOf="parent"
         app:layout_constraintEnd_toEndOf="parent"
-        app:layoutDescription="@xml/small_preview_layout_scene">
+        app:layoutDescription="@xml/small_preview_container_layout_scene">
 
-        <com.android.wallpaper.picker.preview.ui.view.DualPreviewViewPager
-            android:id="@+id/pager_previews"
-            android:layout_width="match_parent"
-            android:layout_height="match_parent"
-            android:layout_gravity="bottom"
-            android:paddingHorizontal="@dimen/small_dual_preview_edge_space"
-            android:clipChildren="false"
-            android:importantForAccessibility="no" />
+        <include layout="@layout/small_preview_pager_foldable"
+            android:id="@+id/preview_pager"/>
 
         <HorizontalScrollView
             android:id="@+id/preview_action_group_container"
@@ -106,4 +97,4 @@
         app:layout_constraintStart_toStartOf="parent"
         app:layout_constraintEnd_toEndOf="parent"
         app:layout_constraintBottom_toBottomOf="parent"/>
-</androidx.constraintlayout.widget.ConstraintLayout>
+</androidx.constraintlayout.motion.widget.MotionLayout>
diff --git a/res/layout/fragment_small_preview_handheld.xml b/res/layout/fragment_small_preview_handheld.xml
index 995bdf0d..348937ad 100644
--- a/res/layout/fragment_small_preview_handheld.xml
+++ b/res/layout/fragment_small_preview_handheld.xml
@@ -18,7 +18,7 @@
 <androidx.constraintlayout.widget.ConstraintLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
-    android:id="@+id/container"
+    android:id="@+id/small_preview_screen"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:orientation="vertical"
diff --git a/res/layout/fragment_small_preview_handheld2.xml b/res/layout/fragment_small_preview_handheld2.xml
index 8024444a..f751a186 100644
--- a/res/layout/fragment_small_preview_handheld2.xml
+++ b/res/layout/fragment_small_preview_handheld2.xml
@@ -15,17 +15,18 @@
   ~ limitations under the License.
   ~
   -->
-<androidx.constraintlayout.widget.ConstraintLayout
+<androidx.constraintlayout.motion.widget.MotionLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
-    android:id="@+id/container"
+    android:id="@+id/small_preview_screen"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:orientation="vertical"
     android:fitsSystemWindows="true"
     android:transitionGroup="true"
     android:clipChildren="false"
-    android:clipToPadding="false">
+    android:clipToPadding="false"
+    app:layoutDescription="@xml/small_preview_fragment_layout_scene">
 
     <include
         android:id="@+id/toolbar_container"
@@ -37,13 +38,14 @@
         app:layout_constraintEnd_toEndOf="parent"/>
 
     <Button
-        android:id="@+id/button_set_wallpaper"
+        android:id="@+id/button_next"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:layout_marginEnd="@dimen/set_wallpaper_button_margin_end"
-        android:background="@drawable/set_wallpaper_button_background_variant"
+        android:background="@drawable/apply_button_background_variant"
         android:elevation="@dimen/wallpaper_preview_buttons_elevation"
         android:gravity="center"
+        android:minWidth="@dimen/apply_button_width"
         android:minHeight="@dimen/touch_target_min_height"
         android:text="@string/next_page_content_description"
         android:textColor="@color/system_on_primary"
@@ -53,19 +55,17 @@
         app:layout_constraintBottom_toBottomOf="@id/toolbar_container"/>
 
     <androidx.constraintlayout.motion.widget.MotionLayout
-        android:id="@+id/small_preview_motion_layout"
+        android:id="@+id/small_preview_container"
         android:layout_width="match_parent"
         android:layout_height="0dp"
         app:layout_constraintTop_toBottomOf="@id/toolbar_container"
         app:layout_constraintBottom_toBottomOf="parent"
         app:layout_constraintStart_toStartOf="parent"
         app:layout_constraintEnd_toEndOf="parent"
-        app:layoutDescription="@xml/small_preview_layout_scene">
+        app:layoutDescription="@xml/small_preview_container_layout_scene">
 
-        <androidx.viewpager2.widget.ViewPager2
-            android:id="@+id/pager_previews"
-            android:layout_width="match_parent"
-            android:layout_height="match_parent"/>
+        <include layout="@layout/small_preview_pager_handheld"
+            android:id="@+id/preview_pager"/>
 
         <HorizontalScrollView
             android:id="@+id/preview_action_group_container"
@@ -97,4 +97,4 @@
         app:layout_constraintStart_toStartOf="parent"
         app:layout_constraintEnd_toEndOf="parent"
         app:layout_constraintBottom_toBottomOf="parent"/>
-</androidx.constraintlayout.widget.ConstraintLayout>
+</androidx.constraintlayout.motion.widget.MotionLayout>
diff --git a/res/layout/small_preview_foldable_card_view2.xml b/res/layout/small_preview_foldable_card_view2.xml
index 76911911..a86cbede 100644
--- a/res/layout/small_preview_foldable_card_view2.xml
+++ b/res/layout/small_preview_foldable_card_view2.xml
@@ -19,7 +19,7 @@
     android:layout_height="match_parent"
     android:clipChildren="false">
 
-    <com.android.wallpaper.picker.preview.ui.view.DualDisplayAspectRatioLayout
+    <com.android.wallpaper.picker.preview.ui.view.DualDisplayAspectRatioLayout2
         android:id="@+id/dual_preview"
         android:layout_width="match_parent"
         android:layout_height="match_parent"
@@ -38,7 +38,7 @@
             layout="@layout/wallpaper_dual_preview_card"
             android:layout_width="match_parent"
             android:layout_height="match_parent"/>
-    </com.android.wallpaper.picker.preview.ui.view.DualDisplayAspectRatioLayout>
+    </com.android.wallpaper.picker.preview.ui.view.DualDisplayAspectRatioLayout2>
 
     <ViewStub
         android:id="@+id/small_preview_tooltip_stub"
diff --git a/res/layout/small_preview_foldable_card_view_selector.xml b/res/layout/small_preview_foldable_card_view_selector.xml
index 0793c1d7..1f39c5d8 100644
--- a/res/layout/small_preview_foldable_card_view_selector.xml
+++ b/res/layout/small_preview_foldable_card_view_selector.xml
@@ -16,18 +16,19 @@
   -->
 <FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
-    android:layout_height="match_parent">
+    android:layout_height="match_parent"
+    android:contentDescription="@string/wallpaper_preview_card_content_description">
 
     <com.android.wallpaper.picker.preview.ui.view.DualDisplayAspectRatioLayout
         android:id="@+id/dual_preview"
         android:layout_width="match_parent"
         android:layout_height="wrap_content"
-        android:orientation="horizontal">
+        android:orientation="horizontal"
+        android:importantForAccessibility="noHideDescendants">
 
         <FrameLayout
             android:layout_width="wrap_content"
-            android:layout_height="wrap_content"
-            android:importantForAccessibility="noHideDescendants">
+            android:layout_height="wrap_content">
             <include
                 android:id="@+id/small_preview_folded_preview"
                 layout="@layout/small_wallpaper_preview_card"
diff --git a/res/layout/small_preview_pager_foldable.xml b/res/layout/small_preview_pager_foldable.xml
new file mode 100644
index 00000000..8220f2b1
--- /dev/null
+++ b/res/layout/small_preview_pager_foldable.xml
@@ -0,0 +1,110 @@
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
+<com.android.wallpaper.picker.preview.ui.view.ClickableMotionLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/preview_pager"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    app:layoutDescription="@xml/preview_pager_motion_scene_foldable">
+
+    <LinearLayout
+        android:id="@+id/apply_wallpaper_header"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:gravity="center"
+        android:visibility="gone"
+        android:orientation="vertical">
+
+        <TextView
+            android:id="@+id/apply_wallpaper_title"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/foldable_apply_wallpaper_preview_title_margin_bottom"
+            android:text="@string/apply_wallpaper_title_text"
+            android:textAppearance="@style/SettingsLibTextAppearance.Primary.Headline.Large"  />
+
+        <TextView
+            android:id="@+id/apply_wallpaper_description"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:textAppearance="@style/SettingsLibTextAppearance.Primary.Title.Small" />
+    </LinearLayout>
+
+    <include layout="@layout/small_preview_foldable_card_view2"
+        android:id="@+id/lock_preview" />
+
+    <CheckBox
+        android:id="@+id/lock_checkbox"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:gravity="center_vertical"
+        android:button="@drawable/checkbox_circle_shape"
+        android:singleLine="true"
+        android:ellipsize="end"
+        android:scrollHorizontally="true"
+        android:text="@string/set_wallpaper_lock_screen_destination"
+        android:visibility="gone"/>
+
+    <include layout="@layout/small_preview_foldable_card_view2"
+        android:id="@+id/home_preview" />
+
+    <CheckBox
+        android:id="@+id/home_checkbox"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:gravity="center_vertical"
+        android:button="@drawable/checkbox_circle_shape"
+        android:singleLine="true"
+        android:ellipsize="end"
+        android:scrollHorizontally="true"
+        android:text="@string/set_wallpaper_home_screen_destination"
+        android:visibility="gone"/>
+
+    <Button
+        android:id="@+id/apply_button"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:background="@drawable/apply_button_background_variant"
+        android:gravity="center"
+        android:minWidth="@dimen/foldable_apply_wallpaper_preview_button_min_width"
+        android:minHeight="@dimen/foldable_apply_wallpaper_preview_button_min_height"
+        android:text="@string/apply_btn"
+        android:textColor="@color/system_on_primary"
+        android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
+        android:visibility="gone" />
+
+    <Button
+        android:id="@+id/cancel_button"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:background="@drawable/cancel_button_background_variant"
+        android:gravity="center"
+        android:minWidth="@dimen/foldable_apply_wallpaper_preview_button_min_width"
+        android:minHeight="@dimen/foldable_apply_wallpaper_preview_button_min_height"
+        android:text="@string/cancel"
+        android:textColor="@color/system_primary"
+        android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
+        android:visibility="gone" />
+
+    <androidx.constraintlayout.widget.Guideline
+        android:id="@+id/guideline_center"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:orientation="vertical"
+        app:layout_constraintGuide_percent="0.5" />
+</com.android.wallpaper.picker.preview.ui.view.ClickableMotionLayout>
diff --git a/res/layout/small_preview_pager_handheld.xml b/res/layout/small_preview_pager_handheld.xml
new file mode 100644
index 00000000..5ebf591a
--- /dev/null
+++ b/res/layout/small_preview_pager_handheld.xml
@@ -0,0 +1,108 @@
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
+<com.android.wallpaper.picker.preview.ui.view.ClickableMotionLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/preview_pager"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    app:layoutDescription="@xml/preview_pager_motion_scene_handheld">
+
+    <LinearLayout
+        android:id="@+id/apply_wallpaper_header"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:gravity="center"
+        android:visibility="gone"
+        android:orientation="vertical">
+
+        <TextView
+            android:id="@+id/apply_wallpaper_title"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_preview_title_margin_bottom"
+            android:text="@string/apply_wallpaper_title_text"
+            android:textAppearance="@style/SettingsLibTextAppearance.Primary.Headline.Large"  />
+
+        <TextView
+            android:id="@+id/apply_wallpaper_description"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:textAppearance="@style/SettingsLibTextAppearance.Primary.Title.Small" />
+    </LinearLayout>
+
+    <include layout="@layout/small_preview_handheld_card_view2"
+        android:id="@+id/lock_preview" />
+
+    <CheckBox
+        android:id="@+id/lock_checkbox"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:gravity="center_vertical"
+        android:button="@drawable/checkbox_circle_shape"
+        android:text="@string/set_wallpaper_lock_screen_destination"
+        android:singleLine="true"
+        android:ellipsize="end"
+        android:scrollHorizontally="true"
+        android:visibility="gone"/>
+
+    <include layout="@layout/small_preview_handheld_card_view2"
+        android:id="@+id/home_preview" />
+
+    <CheckBox
+        android:id="@+id/home_checkbox"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:gravity="center_vertical"
+        android:button="@drawable/checkbox_circle_shape"
+        android:text="@string/set_wallpaper_home_screen_destination"
+        android:singleLine="true"
+        android:ellipsize="end"
+        android:scrollHorizontally="true"
+        android:visibility="gone"/>
+
+    <Button
+        android:id="@+id/apply_button"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:background="@drawable/apply_button_background_variant"
+        android:gravity="center"
+        android:minHeight="@dimen/handheld_apply_wallpaper_preview_button_min_height"
+        android:text="@string/apply_btn"
+        android:textColor="@color/system_on_primary"
+        android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
+        android:visibility="gone" />
+
+    <Button
+        android:id="@+id/cancel_button"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:background="@drawable/cancel_button_background_variant"
+        android:gravity="center"
+        android:minHeight="@dimen/handheld_apply_wallpaper_preview_button_min_height"
+        android:text="@string/cancel"
+        android:textColor="@color/system_primary"
+        android:textAppearance="@style/WallpaperPicker.Preview.TextAppearance.NoAllCaps"
+        android:visibility="gone" />
+
+    <androidx.constraintlayout.widget.Guideline
+        android:id="@+id/guideline_center"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:orientation="vertical"
+        app:layout_constraintGuide_percent="0.5" />
+</com.android.wallpaper.picker.preview.ui.view.ClickableMotionLayout>
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 05ac08d5..a15f9e20 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Verander muurpapier"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Voorskou van sluitskerm se muurpapier"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Pas toe"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Pas muurpapier toe?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Pasmaak word versteek"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Pasmaak word gewys"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Inligting word versteek"</string>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index 23532bb1..becf3e6f 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"ልጣፍን ይቀይሩ"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"የማያ ገፅ ቁልፍ ልጣፍ ቅድመ-ዕይታ"</string>
     <string name="apply_btn" msgid="5764555565943538528">"ተግብር"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"ልጣፍ ይተግበር?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"ማበጀት ተደብቋል"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"ማበጀት ታይቷል"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"መረጃ ተደብቋል"</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 4118969c..15079002 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"تغيير الخلفية"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"معاينة خلفية شاشة القفل"</string>
     <string name="apply_btn" msgid="5764555565943538528">"تنفيذ"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"هل تريد تطبيق الخلفية؟"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"تم إخفاء لوحة التخصيص."</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"تم عرض لوحة التخصيص."</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"تم إخفاء لوحة المعلومات."</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index c42575e5..fa07633f 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"ৱালপেপাৰ সলনি কৰক"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"লকস্ক্ৰীনৰ ৱালপেপাৰৰ পূৰ্বদৰ্শন"</string>
     <string name="apply_btn" msgid="5764555565943538528">"প্ৰয়োগ কৰক"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"ৱালপেপাৰ প্ৰয়োগ কৰিবনে?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"কাষ্টমাইজ কৰাৰ পেনেল লুকুওৱা হৈছে"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"কাষ্টমাইজ কৰাৰ পেনেল দেখুওৱা হৈছে"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"তথ্য লুকুওৱা হৈছে"</string>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 5139f873..cde6a271 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Divar kağızını dəyişin"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Kilid ekranında divar kağızı önizləməsi"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Tətbiq edin"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Divar kağızı tətbiq olunsun?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Fərdiləşdirmə paneli gizlədilib"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Fərdiləşdirmə paneli göstərilir"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Məlumat gizlədilib"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 2a108c49..1a3de84c 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Promenite pozadinu"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Pregled pozadine zaključanog ekrana"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Primeni"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Želite da primenite pozadinu?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Okno za prilagođavanje je sakriveno"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Okno za prilagođavanje je prikazano"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Informacije su sakrivene"</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 58e6880d..93ed8997 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Змяніць шпалеры"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Перадпрагляд шпалер экрана блакіроўкі"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Прымяніць"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Прымяніць шпалеры?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Панэль наладкі схавана"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Панэль наладкі бачная"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Панэль інфармацыі схавана"</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 8cafd02a..f82b2235 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Промяна на тапета"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Визуализация на тапета на закл. екран"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Прилагане"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Да се приложи ли тапетът?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Панелът за персонализиране е скрит"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Показан е панелът за персонализиране"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Информационният панел е скрит"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 940da7cc..5d5efd9c 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"ওয়ালপেপার পরিবর্তন করুন"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"লকস্ক্রিন ওয়ালপেপার প্রিভিউ"</string>
     <string name="apply_btn" msgid="5764555565943538528">"প্রয়োগ করুন"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"ওয়ালপেপার প্রয়োগ করবেন?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"কাস্টমাইজ প্যানেল লুকানো হয়েছে"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"কাস্টমাইজ প্যানেল দেখানো হয়েছে"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"তথ্য লুকানো হয়েছে"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 1f5f6643..badcc4f3 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Promijenite pozadinsku sliku"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Pregled pozadinske slike zaključanog ekrana"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Primijeni"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Primijeniti pozadinsku sliku?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Prilagođavanje je skriveno"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Prilagođavanje je prikazano"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Informacije su skrivene"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index a38860d2..923f23df 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Canvia el fons de pantalla"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Previsual. fons de pantalla de bloqueig"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Aplica"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Vols aplicar el fons de pantalla?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"El tauler Personalitza està amagat"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"El tauler Personalitza es mostra"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"El tauler Informació està amagat"</string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index 01330863..6884be40 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Změnit tapetu"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Náhled tapety na obrazovce uzamčení"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Použít"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Použít tapetu?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Panel přizpůsobení je skryt"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Panel přizpůsobení je zobrazen"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Informace jsou skryty"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index c06e3042..7e1c61fc 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Skift baggrund"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Forhåndsvisning af låseskærmens baggrund"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Anvend"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Vil du anvende baggrunden?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Tilpasning er skjult"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Tilpasning er synlig"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Oplysninger er skjult"</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index 648db75f..e7221612 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Hintergrund ändern"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Vorschau für Sperrbildschirmhintergrund"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Anwenden"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Hintergrund anwenden?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Bereich zum Anpassen ausgeblendet"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Bereich zum Anpassen eingeblendet"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Informationen ausgeblendet"</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index 9f14e859..4b16e540 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -30,7 +30,7 @@
     <string name="rotating_wallpaper_presentation_mode_message" msgid="3361676041605733288">"Ημερήσια ταπετσαρία"</string>
     <string name="wallpaper_destination_both" msgid="1124197176741944063">"Αρχική οθόνη και οθόνη κλειδώματος"</string>
     <string name="choose_a_wallpaper_section_title" msgid="1009823506890453891">"Επιλέξτε μια ταπετσαρία"</string>
-    <string name="creative_wallpaper_title" msgid="3581650238648981372">"Δημιουργία ταπετσαρίας"</string>
+    <string name="creative_wallpaper_title" msgid="3581650238648981372">"Δημιουργήστε μια ταπετσαρία"</string>
     <string name="home_screen_message" msgid="106444102822522813">"Αρχική οθόνη"</string>
     <string name="lock_screen_message" msgid="1534506081955058013">"Οθόνη κλειδώματος"</string>
     <string name="home_and_lock_short_label" msgid="2937922943541927983">"Αρχική και κλειδώματος"</string>
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Αλλαγή ταπετσαρίας"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Προεπ/ση ταπετσαρίας οθόνης κλειδώματος"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Εφαρμογή"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Να εφαρμοστεί η ταπετσαρία;"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Το πλαίσιο Προσαρμογή είναι κρυφό."</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Το πλαίσιο Προσαρμογή είναι ορατό."</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Το πλαίσιο Πληροφορίες είναι κρυφό."</string>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index a78b9801..df914f71 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Change wallpaper"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Lockscreen wallpaper preview"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Apply"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Apply wallpaper?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Customise hidden"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Customise shown"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Info hidden"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 5b7fbfd4..69ce12cd 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Change wallpaper"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Lockscreen wallpaper preview"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Apply"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Apply wallpaper?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Customize hidden"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Customize shown"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Info hidden"</string>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index a78b9801..df914f71 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Change wallpaper"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Lockscreen wallpaper preview"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Apply"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Apply wallpaper?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Customise hidden"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Customise shown"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Info hidden"</string>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index a78b9801..df914f71 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Change wallpaper"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Lockscreen wallpaper preview"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Apply"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Apply wallpaper?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Customise hidden"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Customise shown"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Info hidden"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index c481c3e6..af03f8ee 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Cambiar fondo de pantalla"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Vista del fondo de pantalla de bloqueo"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Aplicar"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"¿Deseas aplicar un fondo de pantalla?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Panel Personalizar oculto"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Panel Personalizar visible"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Panel Información oculto"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index f163ef82..8ed98633 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Cambiar fondo de pantalla"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Vista del fondo de pantalla de bloqueo"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Aplicar"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"¿Aplicar fondo de pantalla?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Personalizar oculto"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Personalizar mostrado"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Información oculto"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 76803f1f..f552515e 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Taustapildi muutmine"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Lukustuskuva taustapildi eelvaade"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Rakenda"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Kas rakendada taustapilt?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Kohandamispaneel on peidetud"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Kohandamispaneel on kuvatud"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Teabepaneel on peidetud"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index e84eb25b..1ab7ba09 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -40,7 +40,7 @@
     <string name="set_wallpaper_both_destination" msgid="2536004558738350775">"Hasierako pantaila eta pantaila blokeatua"</string>
     <string name="no_backup_image_wallpaper_label" msgid="6316627676107284851">"Txandakako irudidun horma-papera"</string>
     <string name="permission_needed_explanation" msgid="139166837541426823">"Oraingo horma-papera hemen bistaratzeko, zure gailuaren memoria atzitu behar du <xliff:g id="APP_NAME">%1$s</xliff:g> aplikazioak."</string>
-    <string name="permission_needed_explanation_go_to_settings" msgid="3923551582092599609">"Oraingo horma-papera hemen ager dadin, gailuaren memoriarako sarbidea behar du Horma-paperak aplikazioak.\n\nEzarpena aldatzeko, joan Horma-paperak aplikazioaren informazioko Baimenak atalera."</string>
+    <string name="permission_needed_explanation_go_to_settings" msgid="3923551582092599609">"Oraingo horma-papera hemen ager dadin, gailuaren memoriarako sarbidea behar du Horma-paperak aplikazioak.\n\nEzarpena aldatzeko, joan Horma-paperak aplikazioari buruzko informazioko Baimenak atalera."</string>
     <string name="permission_needed_allow_access_button_label" msgid="1943133660612924306">"Eman baimena"</string>
     <string name="no_backup_image_wallpaper_description" msgid="8303268619408738057">"Txandakako irudietarako horma-paper dinamikoen zerbitzua"</string>
     <string name="daily_refresh_tile_title" msgid="3270456074558525091">"Eguneko horma-papera"</string>
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Aldatu horma-papera"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Pantaila blokeatuko horma-paperaren aurrebista"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Aplikatu"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Horma-papera aplikatu nahi duzu?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Pertsonalizatzeko panela ezkutatuta dago"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Pertsonalizatzeko panela ikusgai dago"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Informazio-panela ezkutatuta dago"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 77b4d510..84594a35 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -45,7 +45,7 @@
     <string name="no_backup_image_wallpaper_description" msgid="8303268619408738057">"سرویس کاغذ‌دیواری پویا برای کاغذدیواری‌های چرخشی"</string>
     <string name="daily_refresh_tile_title" msgid="3270456074558525091">"کاغذ‌دیواری روزانه"</string>
     <string name="daily_refresh_tile_subtitle" msgid="3976682014885446443">"برای روشن کردن، تک‌ضرب بزنید"</string>
-    <string name="start_rotation_dialog_body_live_wallpaper_needed" msgid="5132580257563846082">"‏کاغذ‌دیواری هر روز به‌طور خودکار تغییر خواهد کرد. برای اتمام راه‌اندازی، روی &lt;strong&gt;تنظیم کاغذدیواری &lt;/strong&gt; در صفحه بعد تک‌ضرب بزنید."</string>
+    <string name="start_rotation_dialog_body_live_wallpaper_needed" msgid="5132580257563846082">"‏کاغذ‌دیواری هر روز به‌طور خودکار تغییر خواهد کرد. برای تمام کردن راه‌اندازی، روی &lt;strong&gt;تنظیم کاغذدیواری &lt;/strong&gt; در صفحه بعد تک‌ضرب بزنید."</string>
     <string name="start_rotation_dialog_wifi_only_option_message" msgid="3126269859713666225">"‏کاغذ‌دیواری‌های بعدی فقط ازطریق Wi-Fi بارگیری شود"</string>
     <string name="start_rotation_dialog_continue" msgid="276678987852274872">"ادامه"</string>
     <string name="start_rotation_progress_message" msgid="7872623873682262083">"درحال بارگیری اولین کاغذ‌دیواری..."</string>
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"تغییر کاغذدیواری"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"پیش‌نمای کاغذدیواری صفحه قفل"</string>
     <string name="apply_btn" msgid="5764555565943538528">"اعمال کردن"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"کاغذدیواری اعمال شود؟"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"پانل سفارشی‌سازی پنهان است"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"پانل سفارشی‌سازی نمایان است"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"پانل اطلاعات پنهان است"</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index c8b747a2..14e23abb 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Vaihda taustakuva"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Lukitusnäytön taustakuvan esikatselu"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Käytä"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Otetaanko taustakuva käyttöön?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Yksilöinti piilotettu"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Yksilöinti näkyvissä"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Tiedot piilotettu"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index b7c72d6d..2b78176c 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Modifier le fond d\'écran"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Aperçu du fond d\'écran de verrouillage"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Appliquer"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Appliquer le fond d\'écran?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Personnalisez le contenu masqué"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Personnalisez le contenu affiché"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Renseignements masqués"</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index 2ab6cc25..5fe7deb0 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Changer de fond d\'écran"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Aperçu du fond d\'écran de verrouillage"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Appliquer"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Appliquer le fond d\'écran ?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Panneau de personnalisation masqué"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Panneau de personnalisation affiché"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Panneau d\'information masqué"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index c5cd7b36..7800a5aa 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Cambiar fondo de pantalla"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Vista previa do fondo de pantalla"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Aplicar"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Queres aplicar un fondo de pantalla?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Ocultouse o panel Personalizar"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Mostrouse o panel Personalizar"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Ocultouse o panel Información"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index b946da6a..c7c7dd83 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"વૉલપેપર બદલો"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"લૉકસ્ક્રીન વૉલપેપરનો પ્રીવ્યૂ"</string>
     <string name="apply_btn" msgid="5764555565943538528">"લાગુ કરો"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"વૉલપેપર લાગુ કરીએ?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"કસ્ટમાઇઝ પૅનલ છુપાવવામાં આવી છે"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"કસ્ટમાઇઝ પૅનલ બતાવવામાં આવી છે"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"માહિતી પૅનલ છુપાવવામાં આવી છે"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 9d60dc40..cc8576eb 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"वॉलपेपर बदलें"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"लॉकस्क्रीन पर दिखने वाले वॉलपेपर की झलक"</string>
     <string name="apply_btn" msgid="5764555565943538528">"लागू करें"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"क्या वॉलपेपर लगाना है?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"पसंद के मुताबिक बनाने वाले पैनल को छिपाया गया"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"पसंद के मुताबिक बनाने वाले पैनल को दिखाया गया"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"जानकारी देने वाले पैनल को छिपाया गया"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index bedbdcbe..89c8da19 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Promijenite pozadinu"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Pregled pozadine zaključanog zaslona"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Primijeni"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Želite li primijeniti pozadinu?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Ploča Prilagodi je skrivena"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Ploča Prilagodi je prikazana"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Informacije su skrivene"</string>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index b9d2b03a..0d65dd70 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Háttérkép megváltoztatása"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Lezárási képernyő háttérképének előnézete"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Alkalmaz"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Beállítja a háttérképet?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Személyre szabási panel elrejtve"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Személyre szabási panel megjelenítve"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Információs panel elrejtve"</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 6cd263d5..723a3f80 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Փոխել պաստառը"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Կողպէկրանի պաստառի նախադիտում"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Կիրառել"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Կիրառե՞լ պաստառը"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Կարգավորման վահանակը թաքցված է"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Կարգավորման վահանակը ցուցադրված է"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Տեղեկությունները թաքցված են"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 0e99e502..ccf8e93d 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Ubah wallpaper"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Pratinjau wallpaper layar kunci"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Terapkan"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Terapkan wallpaper?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Panel Sesuaikan disembunyikan"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Panel Sesuaikan ditampilkan"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Panel Info disembunyikan"</string>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index da791a59..beab5761 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Skipta um veggfóður"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Forskoðun veggfóðurs á lásskjá"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Nota"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Nota veggfóður?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Sérsnið falið"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Sérsnið sýnt"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Upplýsingar faldar"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index f227a9fe..02127dad 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Cambia sfondo"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Anteprima sfondo schermata di blocco"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Applica"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Applicare lo sfondo?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Riquadro Personalizza nascosto"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Riquadro Personalizza mostrato"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Riquadro Informazioni nascosto"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 8a913701..5ad0bbfa 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"החלפת הטפט"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"תצוגה מקדימה של הטפט במסך הנעילה"</string>
     <string name="apply_btn" msgid="5764555565943538528">"אישור"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"להחיל את הטפט?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"חלונית ההתאמה אישית מוסתרת"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"חלונית ההתאמה אישית מוצגת"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"חלונית המידע מוסתרת"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 5c4a4d9a..6804209f 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"壁紙の変更"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"ロック画面の壁紙のプレビュー"</string>
     <string name="apply_btn" msgid="5764555565943538528">"適用"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"壁紙を適用しますか？"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"カスタマイズ パネルを非表示にしました"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"カスタマイズ パネルを表示しました"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"情報パネルを非表示にしました"</string>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index 109c2ab7..73596297 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"ფონის შეცვლა"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"ჩაკეტილი ეკრანის ფონის გადახედვა"</string>
     <string name="apply_btn" msgid="5764555565943538528">"გამოყენება"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"გსურთ ფონის გამოყენება?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"მორგება დამალულია"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"მორგება ნაჩვენებია"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"ინფორმაცია დამალულია"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 5e59ad8b..7a1760d1 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Тұсқағазды өзгерту"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Құлып экраны тұсқағазын алдын ала көру"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Қолдану"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Түсқағаз қолданғыңыз келе ме?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Реттеу панелі жасырылған."</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Реттеу панелі көрсетілген."</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Ақпарат жасырылған."</string>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index 69ae0fe0..c1d38b94 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"ប្ដូរផ្ទាំងរូបភាព"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"ការមើល​ផ្ទាំងរូបភាព​អេក្រង់ចាក់សោសាកល្បង"</string>
     <string name="apply_btn" msgid="5764555565943538528">"អនុវត្ត"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"ប្រើផ្ទាំង​រូបភាពឬ?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"បានលាក់​ផ្ទាំងប្ដូរតាម​បំណង"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"បានបង្ហាញ​ផ្ទាំងប្ដូរតាម​បំណង"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"បានលាក់​ផ្ទាំងព័ត៌មាន"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 0a3ff693..c6a892e3 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -34,7 +34,7 @@
     <string name="home_screen_message" msgid="106444102822522813">"ಹೋಮ್ ಸ್ಕ್ರೀನ್"</string>
     <string name="lock_screen_message" msgid="1534506081955058013">"ಲಾಕ್ ಸ್ಕ್ರೀನ್"</string>
     <string name="home_and_lock_short_label" msgid="2937922943541927983">"ಮುಖಪುಟ ಮತ್ತು ಲಾಕ್‌"</string>
-    <string name="set_wallpaper_dialog_message" msgid="2110475703996853076">"ವಾಲ್‌ಪೇಪರ್ ಅನ್ನು ಆನ್‌ಗೆ ಹೊಂದಿಸಿ"</string>
+    <string name="set_wallpaper_dialog_message" msgid="2110475703996853076">"ವಾಲ್‌ಪೇಪರ್ ಅನ್ನು ಆನ್‌ಗೆ ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="set_wallpaper_home_screen_destination" msgid="7315594722013109354">"ಹೋಮ್ ಸ್ಕ್ರೀನ್"</string>
     <string name="set_wallpaper_lock_screen_destination" msgid="6224685559375417945">"ಲಾಕ್ ಸ್ಕ್ರೀನ್"</string>
     <string name="set_wallpaper_both_destination" msgid="2536004558738350775">"ಹೋಮ್ ಮತ್ತು ಲಾಕ್ ಸ್ಕ್ರೀನ್‌ಗಳು"</string>
@@ -66,7 +66,7 @@
     <string name="explore_lock_screen" msgid="268938342103703665">"ಲಾಕ್ ಪರದೆಯ ವಾಲ್‌ಪೇಪರ್ ಎಕ್ಸ್‌ಪ್ಲೋರ್ ಮಾಡಿ"</string>
     <string name="refresh_daily_wallpaper_home_content_description" msgid="2770445044556164259">"ದೈನಂದಿನ ಮುಖಪುಟ ಪರದೆಯ ವಾಲ್‌ಪೇಪರ್ ರಿಫ್ರೆಶ್ ಮಾಡಿ"</string>
     <string name="refresh_daily_wallpaper_content_description" msgid="4362142658237147583">"ದಿನನಿತ್ಯದ ವಾಲ್‌ಪೇಪರ್ ಅನ್ನು ರಿಫ್ರೆಶ್ ಮಾಡಿ"</string>
-    <string name="preview_screen_description" msgid="3386387053327775919">"ವಾಲ್‌ಪೇಪರ್ ಪೂರ್ವವೀಕ್ಷಣೆಯ ಪರದೆ"</string>
+    <string name="preview_screen_description" msgid="3386387053327775919">"ವಾಲ್‌ಪೇಪರ್ ಪೂರ್ವವೀಕ್ಷಣೆಯ ಸ್ಕ್ರೀನ್"</string>
     <string name="preview_screen_description_editable" msgid="506875963019888699">"ವಾಲ್‌ಪೇಪರ್ ಪೂರ್ವವೀಕ್ಷಣೆ ಸ್ಕ್ರೀನ್ %1$s. ಪ್ಯಾನ್ ಮಾಡಲು ಮತ್ತು ಜೂಮ್ ಮಾಡಲು ಎರಡು ಬೆರಳುಗಳನ್ನು ಬಳಸಿ."</string>
     <string name="folded_device_state_description" msgid="4972608448265616264">"ಫೋಲ್ಡ್ ಆಗಿದೆ"</string>
     <string name="unfolded_device_state_description" msgid="3071975681472460627">"ಅನ್‌ಫೋಲ್ಡ್ ಆಗಿದೆ"</string>
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"ವಾಲ್‌ಪೇಪರ್ ಬದಲಿಸಿ"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"ಲಾಕ್‌ಸ್ಕ್ರೀನ್ ವಾಲ್‌ಪೇಪರ್ ಪೂರ್ವವೀಕ್ಷಣೆ."</string>
     <string name="apply_btn" msgid="5764555565943538528">"ಅನ್ವಯಿಸಿ"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"ವಾಲ್‌ಪೇಪರ್ ಅನ್ವಯಿಸಬೇಕೆ?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"ಕಸ್ಟಮೈಸ್ ಪ್ಯಾನೆಲ್ ಅನ್ನು ಮರೆಮಾಡಲಾಗಿದೆ"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"ಕಸ್ಟಮೈಸ್ ಪ್ಯಾನೆಲ್ ಅನ್ನು ಪ್ರದರ್ಶಿಸಲಾಗಿದೆ"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"ಮಾಹಿತಿಯನ್ನು ಮರೆಮಾಡಲಾಗಿದೆ"</string>
@@ -140,5 +141,5 @@
     <string name="recents_wallpaper_label" msgid="8653165542635660222">"%1$s, %2$d"</string>
     <string name="default_wallpaper_title" msgid="2541071182656978180">"ವಾಲ್‌ಪೇಪರ್"</string>
     <string name="small_preview_tooltip" msgid="1920430079013352071">"ನಿಮ್ಮ ಫೋಟೋ ಎಡಿಟ್ ಮಾಡಲು ಟ್ಯಾಪ್ ಮಾಡಿ"</string>
-    <string name="full_preview_tooltip" msgid="4648994028015322759">"ನಿಮ್ಮ ಫೋಟೋಗಳ ಸ್ಥಾನ, ಅಳತೆ ಮತ್ತು ಕೋನವನ್ನು ಹೊಂದಿಸಿ"</string>
+    <string name="full_preview_tooltip" msgid="4648994028015322759">"ನಿಮ್ಮ ಫೋಟೋಗಳ ಸ್ಥಾನ, ಅಳತೆ ಮತ್ತು ಕೋನವನ್ನು ಅಡ್ಜಸ್ಟ್ ಮಾಡಿ"</string>
 </resources>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index 75b897c1..f9dd9f04 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"배경화면 변경"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"잠금 화면 배경화면 미리보기"</string>
     <string name="apply_btn" msgid="5764555565943538528">"적용"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"배경화면을 적용하시겠어요?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"맞춤설정 숨김"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"맞춤설정 표시"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"정보 숨김"</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index 4258cd91..b99a3c63 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Тушкагазды өзгөртүү"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Кулпуланган экрандын тушкагазын көрүү"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Колдонуу"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Тушкагаз колдонулсунбу?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Ыңгайлаштыруу тактасы жашырылды"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Ыңгайлаштыруу тактасы көрсөтүлдү"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Маалымат жашырылды"</string>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index 9d934e93..e59df952 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"ປ່ຽນຮູບພື້ນຫຼັງ"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"ຕົວຢ່າງຮູບພື້ນຫຼັງໜ້າຈໍລັອກ"</string>
     <string name="apply_btn" msgid="5764555565943538528">"ນຳໃຊ້"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"ນຳໃຊ້ຮູບພື້ນຫຼັງບໍ?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"ເຊື່ອງແຜງປັບແຕ່ງແລ້ວ"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"ສະແດງແຜງປັບແຕ່ງແລ້ວ"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"ເຊື່ອງແຜງຂໍ້ມູນແລ້ວ"</string>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index 60fa1bf6..3d2c126d 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Ekrano fono keitimas"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Užrakinimo ekrano fono peržiūra"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Taikyti"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Taikyti ekrano foną?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Tinkinimo skydelis paslėptas"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Tinkinimo skydelis rodomas"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Informacijos skydelis paslėptas"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 0bd42d9a..23c861a6 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Fona tapetes maiņa"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Bloķēšanas ekrāna fona tapetes priekšsk."</string>
     <string name="apply_btn" msgid="5764555565943538528">"Lietot"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Vai lietot fona tapeti?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Pielāgotais panelis paslēpts"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Pielāgotais panelis tiek rādīts"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Informācija paslēpta"</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index d8cbf823..565700ca 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Сменете го тапетот"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Преглед на тапетот за заклучен екран"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Примени"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Да се примени тапетот?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Приспособувањето е скриено"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Приспособувањето е прикажано"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Скриени информации"</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 96c31bf6..26a33175 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"വാൾപേപ്പർ മാറ്റുക"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"ലോക്ക്‌സ്ക്രീൻ വാൾപേപ്പറിന്റെ പ്രിവ്യൂ"</string>
     <string name="apply_btn" msgid="5764555565943538528">"ബാധകമാക്കുക"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"വാൾപേപ്പർ പ്രയോഗിക്കട്ടെ?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"ഇഷ്ടാനുസൃതമാക്കൽ പാനൽ മറച്ചിരിക്കുന്നു"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"ഇഷ്ടാനുസൃതമാക്കൽ പാനൽ കാണിച്ചിരിക്കുന്നു"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"വിവരങ്ങൾ പാനൽ മറച്ചിരിക്കുന്നു"</string>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 38daca81..f4bcc31f 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Дэлгэцийн зургийг өөрчлөх"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Түгжигдсэн дэлгэцийн зургийг урьдчилан үзэх"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Ашиглах"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Дэлгэцийн зураг ашиглах уу?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Өөрчлөлтийн самбарыг нуусан"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Өөрчлөлтийн самбарыг харуулсан"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Мэдээллийн самбарыг нуусан"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 0acc890f..deb7f371 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"वॉलपेपर बदला"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"लॉकस्क्रीनच्या वॉलपेपरचे पूर्वावलोकन"</string>
     <string name="apply_btn" msgid="5764555565943538528">"अर्ज करा"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"वॉलपेपर लागू करायचा आहे का?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"कस्टमाइझ पॅनल लपवले आहे"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"कस्टमाइझ पॅनल दाखवले आहे"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"माहिती पॅनल लपवले आहे"</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 8f04439d..0a63d831 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Tukar kertas dinding"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Pratonton kertas dinding skrin kunci"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Gunakan"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Gunakan hiasan latar?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Sesuaikan disembunyikan"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Sesuaikan ditunjukkan"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Maklumat disembunyikan"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index 3cdd3465..decc4665 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"နောက်ခံပုံပြောင်းရန်"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"လော့ခ်မျက်နှာပြင်နောက်ခံ အစမ်းကြည့်ခြင်း"</string>
     <string name="apply_btn" msgid="5764555565943538528">"အသုံးပြုရန်"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"နောက်ခံသုံးမလား။"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"ဝှက်ထားသော စိတ်ကြိုက်လုပ်မှု"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"ပြထားသော စိတ်ကြိုက်လုပ်မှု"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"ဝှက်ထားသော အချက်အလက်"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index b3f9111b..cf0006a9 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Endre bakgrunn"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Forhåndsvisning av låseskjermbakgrunn"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Bruk"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Vil du bruke bakgrunnen?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Tilpasning er skjult"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Tilpasning vises"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Informasjon er skjult"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 8defd1a3..f9513d04 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -25,7 +25,7 @@
     <string name="set_wallpaper_progress_message" msgid="7986528287618716715">"वालपेपर सेट गर्दै…"</string>
     <string name="try_again" msgid="8278874823700921234">"फेरि प्रयास गर्नुहोस्‌"</string>
     <string name="set_wallpaper_error_message" msgid="6819986999041085130">"वालपेपर सेट गर्न सकिएन।"</string>
-    <string name="load_wallpaper_error_message" msgid="7913278480467707374">"वालपेपर लोड गर्न सकिएन। छवि या त त्रुटिपूर्ण छ वा उपलब्ध छैन।"</string>
+    <string name="load_wallpaper_error_message" msgid="7913278480467707374">"वालपेपर लोड गर्न सकिएन। फोटो या त त्रुटिपूर्ण छ वा उपलब्ध छैन।"</string>
     <string name="static_wallpaper_presentation_mode_message" msgid="417940227049360906">"हाल सेट गरिएको"</string>
     <string name="rotating_wallpaper_presentation_mode_message" msgid="3361676041605733288">"दैनिक वालपेपर"</string>
     <string name="wallpaper_destination_both" msgid="1124197176741944063">"होम तथा लक स्क्रिन"</string>
@@ -38,7 +38,7 @@
     <string name="set_wallpaper_home_screen_destination" msgid="7315594722013109354">"होम स्क्रिन"</string>
     <string name="set_wallpaper_lock_screen_destination" msgid="6224685559375417945">"लक स्क्रिन"</string>
     <string name="set_wallpaper_both_destination" msgid="2536004558738350775">"होम र लक स्क्रिन"</string>
-    <string name="no_backup_image_wallpaper_label" msgid="6316627676107284851">"छवि परिवर्तन हुने वालपेपर"</string>
+    <string name="no_backup_image_wallpaper_label" msgid="6316627676107284851">"फोटो परिवर्तन हुने वालपेपर"</string>
     <string name="permission_needed_explanation" msgid="139166837541426823">"यहाँ हालको वालपेपर देखाउन <xliff:g id="APP_NAME">%1$s</xliff:g> लाई तपाईंको डिभाइसको भण्डारणमाथिको पहुँच अनिवार्य हुन्छ।"</string>
     <string name="permission_needed_explanation_go_to_settings" msgid="3923551582092599609">"यहाँ हालैको वालपेपर देखाउन वालपेपरहरूलाई तपाईंको डिभाइसको भण्डारणमाथिको पहुँच अनिवार्य हुन्छ।\n\nयो सेटिङ बदल्न वालपेपरहरूको एपसम्बन्धी जानकारीमा रहेको अनुमति क्षेत्रमा जानुहोस्।"</string>
     <string name="permission_needed_allow_access_button_label" msgid="1943133660612924306">"पहुँच राख्न दिनुहोस्"</string>
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"वालपेपर बदल्नुहोस्"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"लकस्क्रिनमा देखिने वालपेपरको प्रिभ्यू"</string>
     <string name="apply_btn" msgid="5764555565943538528">"लागू गर्नुहोस्"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"वालपेपर लागू गर्ने हो?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"कस्टमाइज गर्नेसम्बन्धी प्यानल लुकाइएको छ"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"कस्टमाइज गर्नेसम्बन्धी प्यानल देखाइएको छ"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"जानकारीसम्बन्धी प्यानल लुकाइएको छ"</string>
diff --git a/res/values-night/colors.xml b/res/values-night/colors.xml
index 1b070cda..5ed99888 100644
--- a/res/values-night/colors.xml
+++ b/res/values-night/colors.xml
@@ -26,7 +26,9 @@
     <color name="system_secondary">@android:color/system_secondary_dark</color>
     <color name="system_tertiary">@android:color/system_tertiary_dark</color>
     <color name="system_on_primary">@android:color/system_on_primary_dark</color>
+    <color name="system_on_primary_fixed_variant">@android:color/system_on_primary_fixed_variant</color>
     <color name="system_on_secondary">@android:color/system_on_secondary_dark</color>
+    <color name="system_on_secondary_container">@android:color/system_on_secondary_container_dark</color>
     <color name="system_on_surface">@android:color/system_on_surface_dark</color>
     <color name="system_on_surface_variant">@android:color/system_on_surface_variant_dark</color>
     <color name="system_surface_container">@android:color/system_surface_container_dark</color>
@@ -34,6 +36,7 @@
     <color name="system_surface_container_highest">@android:color/system_surface_container_highest_dark</color>
     <color name="system_surface_bright">@android:color/system_surface_bright_dark</color>
     <color name="system_outline">@android:color/system_outline_dark</color>
+    <color name="system_outline_variant">@android:color/system_outline_variant_dark</color>
     <color name="system_secondary_container">@android:color/system_secondary_container_dark</color>
 
     <!-- UI elements with Dark/Light Theme Variances -->
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index 03f2a20f..cbdc91dd 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Achtergrond wijzigen"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Voorbeeld achtergrond vergrendelscherm"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Toepassen"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Achtergrond toepassen?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Aanpassen verborgen"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Aanpassen getoond"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Informatie verborgen"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 3a8f423f..e02fed77 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"ୱାଲପେପର୍ ପରିବର୍ତ୍ତନ କରନ୍ତୁ"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"ଲକସ୍କ୍ରିନ୍ ୱାଲପେପର୍ ପ୍ରିଭ୍ୟୁ"</string>
     <string name="apply_btn" msgid="5764555565943538528">"ଲାଗୁ କରନ୍ତୁ"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"ୱାଲପେପର ଲାଗୁ କରିବେ?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"କଷ୍ଟମାଇଜେସନ ପ୍ୟାନେଲ ଲୁଚାଯାଇଛି"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"କଷ୍ଟମାଇଜେସନ ପ୍ୟାନେଲ ଦେଖାଯାଇଛି"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"ସୂଚନା ପ୍ୟାନେଲ ଲୁଚାଯାଇଛି"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 7a60bfdc..cd60a5fe 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"ਵਾਲਪੇਪਰ ਬਦਲੋ"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"ਲਾਕਸਕ੍ਰੀਨ ਵਾਲਪੇਪਰ ਦੀ ਪੂਰਵ-ਝਲਕ"</string>
     <string name="apply_btn" msgid="5764555565943538528">"ਲਾਗੂ ਕਰੋ"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"ਕੀ ਵਾਲਪੇਪਰ ਲਾਗੂ ਕਰਨਾ ਹੈ?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"\'ਵਿਉਂਤਬੱਧ ਕਰੋ\' ਨੂੰ ਲੁਕਾਇਆ ਗਿਆ"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"\'ਵਿਉਂਤਬੱਧ ਕਰੋ\' ਨੂੰ ਦਿਖਾਇਆ ਗਿਆ"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"ਜਾਣਕਾਰੀ ਨੂੰ ਲੁਕਾਇਆ ਗਿਆ"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 6ab5da7f..e8f9c48b 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Zmień tapetę"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Podgląd tapety na ekranie blokady"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Zastosuj"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Zastosować tapetę?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Panel dostosowywania jest ukryty"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Panel dostosowywania jest widoczny"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Panel informacyjny jest ukryty"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index c0c6a32d..ff8e78da 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Alterar imagem de fundo"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Pré-vis. imag. de fundo do ecrã de bloq."</string>
     <string name="apply_btn" msgid="5764555565943538528">"Aplicar"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Aplicar imagem de fundo?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Painel Personalizar oculto"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Painel Personalizar mostrado"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Painel Informações oculto"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index e507558a..7d046eb3 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Mudar plano de fundo"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Plano de fundo da tela de bloqueio"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Aplicar"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Aplicar plano de fundo?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"O painel \"Personalizar\" foi ocultado"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"O painel \"Personalizar\" está em exibição"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"O painel \"Informações\" foi ocultado"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 2d50cb51..a64bf6c7 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Schimbă imaginea de fundal"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Fundal pentru ecranul de blocare"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Aplică"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Aplici imaginea de fundal?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Panoul Personalizează ascuns"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Panoul Personalizează afișat"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Panoul Informații ascuns"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index f3534e7b..cc3a6144 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Сменить обои"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Предпросмотр обоев для заблок. экрана"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Применить"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Применить обои?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Панель настроек скрыта"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Панель настроек показана"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Панель с информацией скрыта"</string>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index 3e07579f..889e4038 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"වෝල්පේපරය වෙනස් කරන්න"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"අගුලු තිර වෝල්පේපර පෙරදසුන"</string>
     <string name="apply_btn" msgid="5764555565943538528">"යොදන්න"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"වෝල්පේපරය යොදන්න ද?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"අභිරුචිකරණය සඟවා ඇත"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"අභිරුචිකරණය පෙන්වා ඇත"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"තොරතුරු සඟවා ඇත"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index 5a4bfc63..e4761822 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Zmeniť tapetu"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Ukážka tapety na uzamknutej obrazovke"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Použiť"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Chcete použiť tapetu?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Panel prispôsobenia je skrytý"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Panel prispôsobenia je zobrazený"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Informácie sú skryté"</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index 6dd23475..58612458 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Zamenjava zaslonskega ozadja"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Predogled zaslon. ozadja zaklen. zaslona"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Uporabi"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Želite uporabiti zaslonsko ozadje?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Prilagajanje je skrito."</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Prilagajanje je prikazano."</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Informacije so skrite."</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 66a3d58e..f72937e6 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Ndrysho imazhin e sfondit"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Pamja paraprake e imazhit të sfondit të ekranit të kyçjes"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Zbato"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Të zbatohet imazhi i sfondit?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Paneli i personalizimit është i fshehur"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Paneli i personalizimit po shfaqet"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Informacionet janë të fshehura"</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 7de3daff..386dabb6 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Промените позадину"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Преглед позадине закључаног екрана"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Примени"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Желите да примените позадину?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Окно за прилагођавање је сакривено"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Окно за прилагођавање је приказано"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Информације су сакривене"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index 7e7bdeab..6892440c 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Ändra bakgrund"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Förhandsgranskning av låsskärmsbakgrund"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Tillämpa"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Vill du använda bakgrunden?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Anpassa har dolts"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Anpassa visas"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Informationspanelen har dolts"</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 06b6e0d5..650e826d 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Badilisha mandhari"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Onyesho la kukagua mandhari kwenye skrini iliyofungwa"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Tumia"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Ungependa kutumia kama mandhari?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Kidirisha cha kuweka mapendeleo kimefichwa"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Kidirisha cha kuweka mapendeleo kinaonyeshwa"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Maelezo yamefichwa"</string>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 297e3f45..fd40ab1c 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"வால்பேப்பரை மாற்றுதல்"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"லாக்ஸ்கிரீன் வால்பேப்பர் மாதிரிக்காட்சி"</string>
     <string name="apply_btn" msgid="5764555565943538528">"பயன்படுத்து"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"வால்பேப்பரைப் பயன்படுத்தவா?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"பிரத்தியேகமாக்குதலை மறைக்கிறது"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"பிரத்தியேகமாக்குதலைக் காட்டுகிறது"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"தகவலை மறைக்கிறது"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 091004a4..37eb9aba 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"వాల్‌పేపర్‌ను మార్చండి"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"లాక్‌స్క్రీన్ వాల్‌పేపర్ ప్రివ్యూ"</string>
     <string name="apply_btn" msgid="5764555565943538528">"వర్తింపజేయి"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"వాల్‌పేపర్ వర్తింపజేయాలా?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"అనుకూలీకరణ ప్యానెల్ దాచబడింది"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"అనుకూలీకరణ ప్యానెల్ చూపబడింది"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"సమాచార ప్యానెల్ దాచబడింది"</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index 4d0b09ad..2664238a 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"เปลี่ยนวอลเปเปอร์"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"ตัวอย่างวอลเปเปอร์ของหน้าจอล็อก"</string>
     <string name="apply_btn" msgid="5764555565943538528">"ใช้"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"ใช้วอลเปเปอร์ไหม"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"การปรับแต่งที่ซ่อน"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"การปรับแต่งที่แสดง"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"ข้อมูลที่ซ่อน"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 33087eeb..e088e1b5 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Palitan ang wallpaper"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Preview ng wallpaper ng lockscreen"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Ilapat"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Mag-apply ng wallpaper?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Nakatago ang mag-customize"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Ipinapakita ang mag-customize"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Nakatago ang impormasyon"</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index cdf0da07..e6da26a8 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Duvar kağıdını değiştir"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Kilit ekranı duvar kağıdı önizlemesi"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Uygula"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Duvar kağıdı uygulansın mı?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Özelleştirme gizlenmiş"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Özelleştirme gösteriliyor"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Bilgi gizlenmiş"</string>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index f50e1493..d99deb57 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Змінити фоновий малюнок"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Перегляд фону екрана блокування"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Застосувати"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Застосувати фоновий малюнок?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Панель налаштувань приховано"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Панель налаштувань показано"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Інформацію приховано"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 7855f57e..0b054f63 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"وال پیپر تبدیل کریں"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"لاک اسکرین وال پیپر کا پیش منظر"</string>
     <string name="apply_btn" msgid="5764555565943538528">"لاگو کریں"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"وال پیپر لاگو کریں؟"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"پوشیدہ کو حسب ضرورت بنائیں"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"دکھایا گیا کو حسب ضرورت بنائیں"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"معلومات پوشیدہ ہے"</string>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index a0875149..bfe78e35 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Fon rasmini almashtirish"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Ekran qulfida fon rasmini koʻrish"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Tatbiq qilish"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Fon rasmi ishlatilsinmi?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Moslashtirish berkitilgan"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Moslashtirish chiqarilgan"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Axborot berkitilgan"</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 0b5aee20..7e68b530 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Thay đổi hình nền"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Xem trước hình nền trên màn hình khóa"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Áp dụng"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Bạn muốn áp dụng hình nền?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Bảng điều khiển tuỳ chỉnh đang ẩn"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Bảng điều khiển tuỳ chỉnh đang hiển thị"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Bảng điều khiển thông tin đang ẩn"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 4969bde1..a93f170c 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"更换壁纸"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"锁定屏幕壁纸预览"</string>
     <string name="apply_btn" msgid="5764555565943538528">"应用"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"要应用壁纸吗？"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"“自定义”面板处于隐藏状态"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"“自定义”面板处于显示状态"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"“信息”面板处于隐藏状态"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index c4213b8a..7b4097fd 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"變更桌布"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"上鎖畫面桌布預覽"</string>
     <string name="apply_btn" msgid="5764555565943538528">"套用"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"套用桌布？"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"自訂隱藏"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"自訂顯示"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"資料已隱藏"</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index b44cce66..39b4253a 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"變更桌布"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"螢幕鎖定畫面桌布預覽"</string>
     <string name="apply_btn" msgid="5764555565943538528">"套用"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"要套用桌布嗎？"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"已隱藏「自訂」面板"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"已顯示「自訂」面板"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"已隱藏「資訊」面板"</string>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index 8238b0a0..a5e2c269 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -124,6 +124,7 @@
     <string name="wallpaper_picker_entry_title" msgid="5185793991582084891">"Shintsha isithombe sangemuva"</string>
     <string name="lockscreen_wallpaper_preview_card_content_description" msgid="2244890820627302245">"Ukubuka kuqala kwesithombe sangemuva sokukhiya isikrini"</string>
     <string name="apply_btn" msgid="5764555565943538528">"Sebenzisa"</string>
+    <string name="apply_wallpaper_title_text" msgid="2100301064316744087">"Sebenzisa isithombe sangemuva?"</string>
     <string name="accessibility_customize_hidden" msgid="6320568529768181691">"Ukwenza ngendlela oyifisayo kufihliwe"</string>
     <string name="accessibility_customize_shown" msgid="590964727831547651">"Ukwenza ngendlela oyifisayo kubonisiwe"</string>
     <string name="accessibility_info_hidden" msgid="2288603712350168107">"Ulwazi lufihliwe"</string>
diff --git a/res/values/colors.xml b/res/values/colors.xml
index 152651f6..8dd8c548 100755
--- a/res/values/colors.xml
+++ b/res/values/colors.xml
@@ -64,7 +64,9 @@
     <color name="system_secondary">@android:color/system_secondary_light</color>
     <color name="system_tertiary">@android:color/system_tertiary_light</color>
     <color name="system_on_primary">@android:color/system_on_primary_light</color>
+    <color name="system_on_primary_fixed_variant">@android:color/system_on_primary_fixed_variant</color>
     <color name="system_on_secondary">@android:color/system_on_secondary_light</color>
+    <color name="system_on_secondary_container">@android:color/system_on_secondary_container_light</color>
     <color name="system_on_surface">@android:color/system_on_surface_light</color>
     <color name="system_on_surface_variant">@android:color/system_on_surface_variant_light</color>
     <color name="system_surface_container">@android:color/system_surface_container_light</color>
@@ -72,6 +74,7 @@
     <color name="system_surface_container_highest">@android:color/system_surface_container_highest_light</color>
     <color name="system_surface_bright">@android:color/system_surface_bright_light</color>
     <color name="system_outline">@android:color/system_outline_light</color>
+    <color name="system_outline_variant">@android:color/system_outline_variant_light</color>
     <color name="system_secondary_container">@android:color/system_secondary_container_light</color>
 
     <!-- UI elements with Dark/Light Theme Variances -->
diff --git a/res/values/dimens.xml b/res/values/dimens.xml
index 287ba05b..e8022006 100755
--- a/res/values/dimens.xml
+++ b/res/values/dimens.xml
@@ -263,6 +263,10 @@
     <dimen name="home_screen_overlay_top_clipping">90dp</dimen>
     <dimen name="home_screen_overlay_bottom_clipping">40dp</dimen>
 
+    <!-- Apply button -->
+    <dimen name="apply_button_corner_radius">100dp</dimen>
+    <dimen name="apply_button_width">70dp</dimen>
+
     <!-- Set wallpaper button -->
     <dimen name="set_wallpaper_button_horizontal_padding">18dp</dimen>
     <dimen name="set_wallpaper_button_vertical_padding">10dp</dimen>
@@ -411,11 +415,34 @@
     <dimen name="nav_button_start_margin">16dp</dimen>
 
     <!-- Dimensions for the floating tab toolbar -->
-    <dimen name="floating_tab_toolbar_padding">8dp</dimen>
+    <dimen name="floating_tab_toolbar_padding_vertical">8dp</dimen>
+    <dimen name="floating_tab_toolbar_padding_horizontal">12dp</dimen>
+    <dimen name="floating_tab_toolbar_tab_min_height">40dp</dimen>
     <dimen name="floating_tab_toolbar_tab_horizontal_padding">16dp</dimen>
     <dimen name="floating_tab_toolbar_tab_vertical_padding">10dp</dimen>
     <dimen name="floating_tab_toolbar_tab_icon_size">20dp</dimen>
     <dimen name="floating_tab_toolbar_tab_icon_margin_end">8dp</dimen>
     <dimen name="floating_tab_toolbar_tab_divider_width">8dp</dimen>
-    <dimen name="floating_tab_toolbar_text_max_width">140dp</dimen>
+    <dimen name="floating_tab_toolbar_tab_background_vertical_margin">4dp</dimen>
+
+    <!-- Dimensions for multi-crop handheld small preview -->
+    <dimen name="handheld_small_preview_pager_margin_top">12dp</dimen>
+    <dimen name="handheld_small_preview_pager_margin_bottom">26dp</dimen>
+    <dimen name="handheld_small_preview_action_group_margin_bottom">12dp</dimen>
+    <dimen name="handheld_small_preview_pager_margin_start">16dp</dimen>
+    <dimen name="handheld_small_preview_pager_margin_end">16dp</dimen>
+    <dimen name="handheld_small_preview_space_between_preview">16dp</dimen>
+    <dimen name="handheld_apply_wallpaper_screen_margin_horizontal">24dp</dimen>
+    <dimen name="handheld_apply_wallpaper_screen_margin_bottom">34dp</dimen>
+    <dimen name="handheld_apply_wallpaper_screen_button_space">8dp</dimen>
+    <dimen name="handheld_apply_wallpaper_screen_header_margin_vertical">16dp</dimen>
+    <dimen name="handheld_apply_wallpaper_preview_title_margin_bottom">16dp</dimen>
+    <dimen name="handheld_apply_wallpaper_preview_button_margin_bottom">28dp</dimen>
+    <dimen name="handheld_apply_wallpaper_preview_button_min_height">56dp</dimen>
+
+    <!-- Dimensions for multi-crop foldable small preview -->
+    <dimen name="foldable_small_preview_space_between_preview">8dp</dimen>
+    <dimen name="foldable_apply_wallpaper_preview_title_margin_bottom">@dimen/handheld_apply_wallpaper_preview_title_margin_bottom</dimen>
+    <dimen name="foldable_apply_wallpaper_preview_button_min_height">@dimen/handheld_apply_wallpaper_preview_button_min_height</dimen>
+    <dimen name="foldable_apply_wallpaper_preview_button_min_width">178dp</dimen>
 </resources>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 85cd4bd6..6bc1b5ce 100755
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -447,6 +447,9 @@
     <!-- Label for a button / menu item that allows the user to apply the currently selected customization option. [CHAR LIMIT=20] -->
     <string name="apply_btn" msgid="7965877231041987336">Apply</string>
 
+    <!-- The title of a wallpaper picker screen letting user to apply a new wallpaper -->
+    <string name="apply_wallpaper_title_text">Apply wallpaper\?</string>
+
     <!-- Content description for customize panel is hidden. [CHAR_LIMIT=50] -->
     <string name="accessibility_customize_hidden">Customize hidden</string>
 
diff --git a/res/xml/preview_pager_motion_scene_foldable.xml b/res/xml/preview_pager_motion_scene_foldable.xml
new file mode 100644
index 00000000..32573cf7
--- /dev/null
+++ b/res/xml/preview_pager_motion_scene_foldable.xml
@@ -0,0 +1,347 @@
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
+<MotionScene xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto">
+
+    <Transition
+        app:constraintSetStart="@id/lock_preview_selected"
+        app:constraintSetEnd="@id/home_preview_selected"
+        app:duration="200">
+        <OnSwipe
+            app:touchRegionId="@id/lock_preview"
+            app:touchAnchorId="@id/lock_preview"
+            app:dragDirection="dragStart"
+            app:maxAcceleration="50"/>
+    </Transition>
+
+    <Transition
+        app:constraintSetStart="@id/home_preview_selected"
+        app:constraintSetEnd="@id/lock_preview_selected"
+        app:duration="200">
+        <OnSwipe
+            app:touchRegionId="@id/home_preview"
+            app:touchAnchorId="@id/home_preview"
+            app:dragDirection="dragEnd"
+            app:maxAcceleration="50"/>
+    </Transition>
+
+    <Transition
+        app:constraintSetStart="@id/apply_wallpaper_lock_preview_selected"
+        app:constraintSetEnd="@id/apply_wallpaper_home_preview_selected"
+        app:duration="200">
+        <OnSwipe
+            app:touchRegionId="@id/lock_preview"
+            app:touchAnchorId="@id/lock_preview"
+            app:dragDirection="dragStart"
+            app:maxAcceleration="50"/>
+    </Transition>
+
+    <Transition
+        app:constraintSetStart="@id/apply_wallpaper_home_preview_selected"
+        app:constraintSetEnd="@id/apply_wallpaper_lock_preview_selected"
+        app:duration="200">
+        <OnSwipe
+            app:touchRegionId="@id/home_preview"
+            app:touchAnchorId="@id/home_preview"
+            app:dragDirection="dragEnd"
+            app:maxAcceleration="50"/>
+    </Transition>
+
+    <ConstraintSet android:id="@+id/lock_preview_selected">
+        <Constraint
+            android:id="@+id/apply_wallpaper_header"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintTop_toTopOf="parent" />
+
+        <Constraint
+            android:id="@+id/lock_preview"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent"
+            app:layout_constraintStart_toStartOf="@+id/guideline_center"
+            app:layout_constraintEnd_toEndOf="@+id/guideline_center" />
+
+        <Constraint
+            android:id="@+id/lock_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="@+id/lock_preview"
+            app:layout_constraintEnd_toEndOf="@+id/lock_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/home_preview"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="@dimen/foldable_small_preview_space_between_preview"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent"
+            app:layout_constraintStart_toEndOf="@+id/lock_preview" />
+
+        <Constraint
+            android:id="@+id/home_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="@+id/home_preview"
+            app:layout_constraintEnd_toEndOf="@+id/home_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/apply_button"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toTopOf="@+id/cancel_button" />
+
+        <Constraint
+            android:id="@+id/cancel_button"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent" />
+    </ConstraintSet>
+
+    <ConstraintSet android:id="@+id/home_preview_selected">
+        <Constraint
+            android:id="@+id/apply_wallpaper_header"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintTop_toTopOf="parent" />
+
+        <Constraint
+            android:id="@+id/lock_preview"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginEnd="@dimen/foldable_small_preview_space_between_preview"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent"
+            app:layout_constraintEnd_toStartOf="@+id/home_preview" />
+
+        <Constraint
+            android:id="@+id/lock_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="@+id/lock_preview"
+            app:layout_constraintEnd_toEndOf="@+id/lock_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/home_preview"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent"
+            app:layout_constraintStart_toStartOf="@+id/guideline_center"
+            app:layout_constraintEnd_toEndOf="@+id/guideline_center" />
+
+        <Constraint
+            android:id="@+id/home_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="@+id/home_preview"
+            app:layout_constraintEnd_toEndOf="@+id/home_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/apply_button"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toTopOf="@+id/cancel_button" />
+
+        <Constraint
+            android:id="@+id/cancel_button"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent" />
+    </ConstraintSet>
+
+    <ConstraintSet android:id="@+id/apply_wallpaper_lock_preview_selected">
+        <Constraint
+            android:id="@+id/apply_wallpaper_header"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginEnd="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginTop="@dimen/handheld_apply_wallpaper_screen_header_margin_vertical"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_screen_header_margin_vertical"
+            android:alpha="1"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintTop_toTopOf="parent" />
+
+        <Constraint
+            android:id="@+id/lock_preview"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            app:layout_constraintVertical_chainStyle="packed"
+            app:layout_constraintTop_toBottomOf="@+id/apply_wallpaper_header"
+            app:layout_constraintBottom_toTopOf="@+id/lock_checkbox"
+            app:layout_constraintStart_toStartOf="@+id/guideline_center"
+            app:layout_constraintEnd_toEndOf="@+id/guideline_center" />
+
+        <Constraint
+            android:id="@+id/lock_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_preview_button_margin_bottom"
+            android:alpha="1"
+            app:layout_constraintStart_toStartOf="@+id/lock_preview"
+            app:layout_constraintEnd_toEndOf="@+id/lock_preview"
+            app:layout_constraintTop_toBottomOf="@+id/lock_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/home_preview"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="@dimen/foldable_small_preview_space_between_preview"
+            app:layout_constraintVertical_chainStyle="packed"
+            app:layout_constraintTop_toBottomOf="@+id/apply_wallpaper_header"
+            app:layout_constraintBottom_toTopOf="@+id/home_checkbox"
+            app:layout_constraintStart_toEndOf="@+id/lock_preview" />
+
+        <Constraint
+            android:id="@+id/home_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_preview_button_margin_bottom"
+            android:alpha="1"
+            app:layout_constraintStart_toStartOf="@+id/home_preview"
+            app:layout_constraintEnd_toEndOf="@+id/home_preview"
+            app:layout_constraintTop_toBottomOf="@+id/home_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/apply_button"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="4dp"
+            android:layout_marginEnd="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:alpha="1"
+            app:layout_constraintStart_toEndOf="@+id/guideline_center"
+            app:layout_constraintBottom_toBottomOf="parent" />
+
+        <Constraint
+            android:id="@+id/cancel_button"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginEnd="4dp"
+            android:alpha="1"
+            app:layout_constraintEnd_toStartOf="@+id/guideline_center"
+            app:layout_constraintBottom_toBottomOf="parent" />
+    </ConstraintSet>
+
+    <ConstraintSet android:id="@+id/apply_wallpaper_home_preview_selected">
+        <Constraint
+            android:id="@+id/apply_wallpaper_header"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginEnd="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginTop="@dimen/handheld_apply_wallpaper_screen_header_margin_vertical"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_screen_header_margin_vertical"
+            android:alpha="1"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintTop_toTopOf="parent" />
+
+        <Constraint
+            android:id="@+id/lock_preview"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginEnd="@dimen/foldable_small_preview_space_between_preview"
+            app:layout_constraintVertical_chainStyle="packed"
+            app:layout_constraintTop_toBottomOf="@+id/apply_wallpaper_header"
+            app:layout_constraintBottom_toTopOf="@+id/lock_checkbox"
+            app:layout_constraintEnd_toStartOf="@+id/home_preview" />
+
+        <Constraint
+            android:id="@+id/lock_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_preview_button_margin_bottom"
+            android:alpha="1"
+            app:layout_constraintStart_toStartOf="@+id/lock_preview"
+            app:layout_constraintEnd_toEndOf="@+id/lock_preview"
+            app:layout_constraintTop_toBottomOf="@+id/lock_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/home_preview"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            app:layout_constraintVertical_chainStyle="packed"
+            app:layout_constraintTop_toBottomOf="@+id/apply_wallpaper_header"
+            app:layout_constraintBottom_toTopOf="@+id/home_checkbox"
+            app:layout_constraintStart_toStartOf="@+id/guideline_center"
+            app:layout_constraintEnd_toEndOf="@+id/guideline_center" />
+
+        <Constraint
+            android:id="@+id/home_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_preview_button_margin_bottom"
+            android:alpha="1"
+            app:layout_constraintStart_toStartOf="@+id/home_preview"
+            app:layout_constraintEnd_toEndOf="@+id/home_preview"
+            app:layout_constraintTop_toBottomOf="@+id/home_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/apply_button"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="4dp"
+            android:layout_marginEnd="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:alpha="1"
+            app:layout_constraintStart_toEndOf="@+id/guideline_center"
+            app:layout_constraintBottom_toBottomOf="parent" />
+
+        <Constraint
+            android:id="@+id/cancel_button"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginEnd="4dp"
+            android:alpha="1"
+            app:layout_constraintEnd_toStartOf="@+id/guideline_center"
+            app:layout_constraintBottom_toBottomOf="parent" />
+    </ConstraintSet>
+</MotionScene>
\ No newline at end of file
diff --git a/res/xml/preview_pager_motion_scene_handheld.xml b/res/xml/preview_pager_motion_scene_handheld.xml
new file mode 100644
index 00000000..d6e726bb
--- /dev/null
+++ b/res/xml/preview_pager_motion_scene_handheld.xml
@@ -0,0 +1,318 @@
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
+<MotionScene xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto">
+
+    <Transition
+        app:constraintSetStart="@id/lock_preview_selected"
+        app:constraintSetEnd="@id/home_preview_selected"
+        app:duration="200">
+        <OnSwipe
+            app:dragDirection="dragStart"
+            app:maxAcceleration="50"/>
+    </Transition>
+
+    <ConstraintSet android:id="@+id/lock_preview_selected">
+        <Constraint
+            android:id="@+id/apply_wallpaper_header"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintTop_toTopOf="parent" />
+
+        <Constraint
+            android:id="@+id/lock_preview"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent"
+            app:layout_constraintStart_toStartOf="@+id/guideline_center"
+            app:layout_constraintEnd_toEndOf="@+id/guideline_center" />
+
+        <Constraint
+            android:id="@+id/lock_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="@+id/lock_preview"
+            app:layout_constraintEnd_toEndOf="@+id/lock_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/home_preview"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="@dimen/handheld_small_preview_space_between_preview"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent"
+            app:layout_constraintStart_toEndOf="@+id/lock_preview" />
+
+        <Constraint
+            android:id="@+id/home_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="@+id/home_preview"
+            app:layout_constraintEnd_toEndOf="@+id/home_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/apply_button"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toTopOf="@+id/cancel_button" />
+
+        <Constraint
+            android:id="@+id/cancel_button"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent" />
+    </ConstraintSet>
+
+    <ConstraintSet android:id="@+id/home_preview_selected">
+        <Constraint
+            android:id="@+id/apply_wallpaper_header"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintTop_toTopOf="parent" />
+
+        <Constraint
+            android:id="@+id/lock_preview"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginEnd="@dimen/handheld_small_preview_space_between_preview"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent"
+            app:layout_constraintEnd_toStartOf="@+id/home_preview" />
+
+        <Constraint
+            android:id="@+id/lock_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="@+id/lock_preview"
+            app:layout_constraintEnd_toEndOf="@+id/lock_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/home_preview"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent"
+            app:layout_constraintStart_toStartOf="@+id/guideline_center"
+            app:layout_constraintEnd_toEndOf="@+id/guideline_center" />
+
+        <Constraint
+            android:id="@+id/home_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="@+id/home_preview"
+            app:layout_constraintEnd_toEndOf="@+id/home_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/apply_button"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toTopOf="@+id/cancel_button" />
+
+        <Constraint
+            android:id="@+id/cancel_button"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent" />
+    </ConstraintSet>
+
+    <ConstraintSet android:id="@+id/apply_wallpaper_preview_only">
+        <Constraint
+            android:id="@+id/apply_wallpaper_header"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginEnd="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginTop="@dimen/handheld_apply_wallpaper_screen_header_margin_vertical"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_screen_header_margin_vertical"
+            android:alpha="0"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintTop_toTopOf="parent" />
+
+        <Constraint
+            android:id="@+id/lock_preview"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_screen_button_space"
+            android:layout_marginEnd="@dimen/handheld_small_preview_space_between_preview"
+            android:layout_marginStart="@dimen/handheld_small_preview_pager_margin_start"
+            app:layout_constraintBottom_toTopOf="@+id/lock_checkbox"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toStartOf="@+id/home_preview" />
+
+        <Constraint
+            android:id="@+id/lock_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_preview_button_margin_bottom"
+            android:alpha="0"
+            app:layout_constraintStart_toStartOf="@+id/lock_preview"
+            app:layout_constraintEnd_toEndOf="@+id/lock_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/home_preview"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_screen_button_space"
+            android:layout_marginEnd="@dimen/handheld_small_preview_pager_margin_end"
+            app:layout_constraintBottom_toTopOf="@+id/home_checkbox"
+            app:layout_constraintStart_toEndOf="@+id/lock_preview"
+            app:layout_constraintEnd_toEndOf="parent" />
+
+        <Constraint
+            android:id="@+id/home_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_preview_button_margin_bottom"
+            android:alpha="0"
+            app:layout_constraintStart_toStartOf="@+id/home_preview"
+            app:layout_constraintEnd_toEndOf="@+id/home_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/apply_button"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginEnd="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_screen_button_space"
+            android:alpha="0"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toTopOf="@+id/cancel_button" />
+
+        <Constraint
+            android:id="@+id/cancel_button"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginEnd="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:alpha="0"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_screen_margin_bottom"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent" />
+    </ConstraintSet>
+
+    <ConstraintSet android:id="@+id/apply_wallpaper_all">
+        <Constraint
+            android:id="@+id/apply_wallpaper_header"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginEnd="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginTop="@dimen/handheld_apply_wallpaper_screen_header_margin_vertical"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_screen_header_margin_vertical"
+            android:alpha="1"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintTop_toTopOf="parent" />
+
+        <Constraint
+            android:id="@+id/lock_preview"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_screen_button_space"
+            android:layout_marginEnd="@dimen/handheld_small_preview_space_between_preview"
+            android:layout_marginStart="@dimen/handheld_small_preview_pager_margin_start"
+            app:layout_constraintBottom_toTopOf="@+id/lock_checkbox"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toStartOf="@+id/home_preview" />
+
+        <Constraint
+            android:id="@+id/lock_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_preview_button_margin_bottom"
+            android:alpha="1"
+            app:layout_constraintStart_toStartOf="@+id/lock_preview"
+            app:layout_constraintEnd_toEndOf="@+id/lock_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/home_preview"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_screen_button_space"
+            android:layout_marginEnd="@dimen/handheld_small_preview_pager_margin_end"
+            app:layout_constraintBottom_toTopOf="@+id/home_checkbox"
+            app:layout_constraintStart_toEndOf="@+id/lock_preview"
+            app:layout_constraintEnd_toEndOf="parent" />
+
+        <Constraint
+            android:id="@+id/home_checkbox"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_preview_button_margin_bottom"
+            android:alpha="1"
+            app:layout_constraintStart_toStartOf="@+id/home_preview"
+            app:layout_constraintEnd_toEndOf="@+id/home_preview"
+            app:layout_constraintBottom_toTopOf="@+id/apply_button" />
+
+        <Constraint
+            android:id="@+id/apply_button"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginEnd="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_screen_button_space"
+            android:alpha="1"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toTopOf="@+id/cancel_button" />
+
+        <Constraint
+            android:id="@+id/cancel_button"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:layout_marginEnd="@dimen/handheld_apply_wallpaper_screen_margin_horizontal"
+            android:alpha="1"
+            android:layout_marginBottom="@dimen/handheld_apply_wallpaper_screen_margin_bottom"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent" />
+    </ConstraintSet>
+</MotionScene>
\ No newline at end of file
diff --git a/res/xml/small_preview_layout_scene.xml b/res/xml/small_preview_container_layout_scene.xml
similarity index 55%
rename from res/xml/small_preview_layout_scene.xml
rename to res/xml/small_preview_container_layout_scene.xml
index 5f7767d3..b73bf8d8 100644
--- a/res/xml/small_preview_layout_scene.xml
+++ b/res/xml/small_preview_container_layout_scene.xml
@@ -15,19 +15,20 @@
   -->
 
 <MotionScene xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:app="http://schemas.android.com/apk/res-auto"
-    xmlns:motion="http://schemas.android.com/apk/res-auto">
+    xmlns:app="http://schemas.android.com/apk/res-auto">
 
     <Transition
         android:id="@+id/show_floating_sheet"
-        motion:constraintSetStart="@id/floating_sheet_gone"
-        motion:constraintSetEnd="@id/floating_sheet_visible" />
+        app:constraintSetStart="@id/floating_sheet_gone"
+        app:constraintSetEnd="@id/floating_sheet_visible" />
 
     <ConstraintSet android:id="@+id/floating_sheet_gone">
         <Constraint
-            android:id="@+id/pager_previews"
+            android:id="@+id/preview_pager"
             android:layout_width="0dp"
             android:layout_height="0dp"
+            android:layout_marginTop="@dimen/handheld_small_preview_pager_margin_top"
+            android:layout_marginBottom="@dimen/handheld_small_preview_pager_margin_bottom"
             app:layout_constraintEnd_toEndOf="parent"
             app:layout_constraintStart_toStartOf="parent"
             app:layout_constraintTop_toTopOf="parent"
@@ -38,7 +39,8 @@
             android:layout_width="0dp"
             android:layout_height="wrap_content"
             android:alpha="1"
-            app:layout_constraintTop_toBottomOf="@+id/pager_previews"
+            android:layout_marginBottom="@dimen/handheld_small_preview_action_group_margin_bottom"
+            app:layout_constraintTop_toBottomOf="@+id/preview_pager"
             app:layout_constraintStart_toStartOf="parent"
             app:layout_constraintEnd_toEndOf="parent"
             app:layout_constraintBottom_toBottomOf="parent" />
@@ -47,6 +49,7 @@
             android:id="@+id/floating_sheet"
             android:layout_width="0dp"
             android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_small_preview_action_group_margin_bottom"
             app:layout_constraintStart_toStartOf="parent"
             app:layout_constraintEnd_toEndOf="parent"
             app:layout_constraintTop_toBottomOf="parent" />
@@ -54,9 +57,11 @@
 
     <ConstraintSet android:id="@+id/floating_sheet_visible">
         <Constraint
-            android:id="@+id/pager_previews"
+            android:id="@+id/preview_pager"
             android:layout_width="0dp"
             android:layout_height="0dp"
+            android:layout_marginTop="@dimen/handheld_small_preview_pager_margin_top"
+            android:layout_marginBottom="@dimen/handheld_small_preview_pager_margin_bottom"
             app:layout_constraintBottom_toTopOf="@+id/floating_sheet"
             app:layout_constraintEnd_toEndOf="parent"
             app:layout_constraintStart_toStartOf="parent"
@@ -67,7 +72,8 @@
             android:layout_width="0dp"
             android:layout_height="wrap_content"
             android:alpha="0"
-            app:layout_constraintTop_toBottomOf="@+id/pager_previews"
+            android:layout_marginBottom="@dimen/handheld_small_preview_action_group_margin_bottom"
+            app:layout_constraintTop_toBottomOf="@+id/preview_pager"
             app:layout_constraintStart_toStartOf="parent"
             app:layout_constraintEnd_toEndOf="parent"
             app:layout_constraintBottom_toBottomOf="parent" />
@@ -76,8 +82,39 @@
             android:id="@+id/floating_sheet"
             android:layout_width="0dp"
             android:layout_height="wrap_content"
+            android:layout_marginBottom="@dimen/handheld_small_preview_action_group_margin_bottom"
             app:layout_constraintStart_toStartOf="parent"
             app:layout_constraintEnd_toEndOf="parent"
             app:layout_constraintBottom_toBottomOf="parent" />
     </ConstraintSet>
+
+    <ConstraintSet android:id="@+id/show_apply_wallpaper">
+        <Constraint
+            android:id="@+id/preview_pager"
+            android:layout_width="0dp"
+            android:layout_height="match_parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintBottom_toTopOf="@+id/preview_action_group_container" />
+
+        <Constraint
+            android:id="@+id/preview_action_group_container"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintTop_toBottomOf="@+id/preview_pager"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent" />
+
+        <Constraint
+            android:id="@+id/floating_sheet"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintTop_toBottomOf="parent" />
+    </ConstraintSet>
 </MotionScene>
\ No newline at end of file
diff --git a/res/xml/small_preview_fragment_layout_scene.xml b/res/xml/small_preview_fragment_layout_scene.xml
new file mode 100644
index 00000000..a96fdf21
--- /dev/null
+++ b/res/xml/small_preview_fragment_layout_scene.xml
@@ -0,0 +1,84 @@
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
+    xmlns:app="http://schemas.android.com/apk/res-auto">
+
+    <Transition
+        android:id="@+id/show_apply_wallpaper_screen"
+        app:constraintSetStart="@id/show_full_page"
+        app:constraintSetEnd="@id/hide_page_header" />
+
+    <ConstraintSet android:id="@+id/show_full_page">
+        <Constraint
+            android:id="@+id/toolbar_container"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:visibility="visible"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent" />
+
+        <Constraint
+            android:id="@+id/button_next"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginEnd="@dimen/set_wallpaper_button_margin_end"
+            android:alpha="1"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintTop_toTopOf="@id/toolbar_container"
+            app:layout_constraintBottom_toBottomOf="@id/toolbar_container" />
+
+        <Constraint
+            android:id="@+id/small_preview_container"
+            android:layout_width="match_parent"
+            android:layout_height="0dp"
+            app:layout_constraintTop_toBottomOf="@id/toolbar_container"
+            app:layout_constraintBottom_toBottomOf="parent"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent" />
+    </ConstraintSet>
+
+    <ConstraintSet android:id="@+id/hide_page_header">
+        <Constraint
+            android:id="@+id/toolbar_container"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:visibility="gone"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent" />
+
+        <Constraint
+            android:id="@+id/button_next"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginEnd="@dimen/set_wallpaper_button_margin_end"
+            android:alpha="0"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintTop_toTopOf="@id/toolbar_container"
+            app:layout_constraintBottom_toBottomOf="@id/toolbar_container" />
+
+        <Constraint
+            android:id="@+id/small_preview_container"
+            android:layout_width="match_parent"
+            android:layout_height="0dp"
+            app:layout_constraintTop_toBottomOf="@+id/toolbar_container"
+            app:layout_constraintBottom_toBottomOf="parent"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintEnd_toEndOf="parent" />
+    </ConstraintSet>
+</MotionScene>
\ No newline at end of file
diff --git a/src/com/android/customization/picker/clock/ui/view/ClockViewFactory.kt b/src/com/android/customization/picker/clock/ui/view/ClockViewFactory.kt
index 3408d1ea..8453e5dc 100644
--- a/src/com/android/customization/picker/clock/ui/view/ClockViewFactory.kt
+++ b/src/com/android/customization/picker/clock/ui/view/ClockViewFactory.kt
@@ -19,6 +19,7 @@ import android.view.View
 import androidx.annotation.ColorInt
 import androidx.lifecycle.LifecycleOwner
 import com.android.systemui.plugins.clocks.ClockController
+import com.android.systemui.plugins.clocks.ClockFontAxisSetting
 
 interface ClockViewFactory {
 
@@ -36,13 +37,12 @@ interface ClockViewFactory {
      */
     fun getSmallView(clockId: String): View
 
-    /** Enables or disables the reactive swipe interaction */
-    fun setReactiveTouchInteractionEnabled(clockId: String, enable: Boolean)
-
     fun updateColorForAllClocks(@ColorInt seedColor: Int?)
 
     fun updateColor(clockId: String, @ColorInt seedColor: Int?)
 
+    fun updateFontAxes(clockId: String, settings: List<ClockFontAxisSetting>)
+
     fun updateRegionDarkness()
 
     fun updateTimeFormat(clockId: String)
diff --git a/src/com/android/customization/picker/clock/ui/view/DefaultClockViewFactory.kt b/src/com/android/customization/picker/clock/ui/view/DefaultClockViewFactory.kt
index 1c4992f1..e79f00b1 100644
--- a/src/com/android/customization/picker/clock/ui/view/DefaultClockViewFactory.kt
+++ b/src/com/android/customization/picker/clock/ui/view/DefaultClockViewFactory.kt
@@ -19,6 +19,7 @@ package com.android.customization.picker.clock.ui.view
 import android.view.View
 import androidx.lifecycle.LifecycleOwner
 import com.android.systemui.plugins.clocks.ClockController
+import com.android.systemui.plugins.clocks.ClockFontAxisSetting
 import javax.inject.Inject
 
 class DefaultClockViewFactory @Inject constructor() : ClockViewFactory {
@@ -35,15 +36,15 @@ class DefaultClockViewFactory @Inject constructor() : ClockViewFactory {
         TODO("Not yet implemented")
     }
 
-    override fun setReactiveTouchInteractionEnabled(clockId: String, enable: Boolean) {
+    override fun updateColorForAllClocks(seedColor: Int?) {
         TODO("Not yet implemented")
     }
 
-    override fun updateColorForAllClocks(seedColor: Int?) {
+    override fun updateColor(clockId: String, seedColor: Int?) {
         TODO("Not yet implemented")
     }
 
-    override fun updateColor(clockId: String, seedColor: Int?) {
+    override fun updateFontAxes(clockId: String, settings: List<ClockFontAxisSetting>) {
         TODO("Not yet implemented")
     }
 
diff --git a/src/com/android/wallpaper/config/BaseFlags.kt b/src/com/android/wallpaper/config/BaseFlags.kt
index fa35efa6..998cd4d0 100644
--- a/src/com/android/wallpaper/config/BaseFlags.kt
+++ b/src/com/android/wallpaper/config/BaseFlags.kt
@@ -23,7 +23,6 @@ import com.android.systemui.shared.Flags.newCustomizationPickerUi
 import com.android.systemui.shared.customization.data.content.CustomizationProviderClient
 import com.android.systemui.shared.customization.data.content.CustomizationProviderClientImpl
 import com.android.systemui.shared.customization.data.content.CustomizationProviderContract as Contract
-import com.android.wallpaper.Flags.largeScreenWallpaperCollections
 import com.android.wallpaper.Flags.magicPortraitFlag
 import com.android.wallpaper.Flags.refactorWallpaperCategoryFlag
 import com.android.wallpaper.Flags.wallpaperRestorerFlag
@@ -49,8 +48,6 @@ abstract class BaseFlags {
 
     open fun isColorContrastControlEnabled() = enableColorContrastControl()
 
-    open fun isLargeScreenWallpaperCollectionsEnabled() = largeScreenWallpaperCollections()
-
     open fun isMagicPortraitEnabled() = magicPortraitFlag()
 
     open fun isNewPickerUi() = newCustomizationPickerUi()
diff --git a/src/com/android/wallpaper/model/CreativeWallpaperInfo.java b/src/com/android/wallpaper/model/CreativeWallpaperInfo.java
index 71ddbcd8..f506bb87 100644
--- a/src/com/android/wallpaper/model/CreativeWallpaperInfo.java
+++ b/src/com/android/wallpaper/model/CreativeWallpaperInfo.java
@@ -15,10 +15,13 @@
  */
 package com.android.wallpaper.model;
 
+import static android.app.Flags.liveWallpaperContentHandling;
+
 import static com.android.wallpaper.model.CreativeCategory.KEY_WALLPAPER_SAVE_CREATIVE_CATEGORY_WALLPAPER;
 
 import android.annotation.Nullable;
 import android.app.WallpaperInfo;
+import android.app.wallpaper.WallpaperDescription;
 import android.content.ClipData;
 import android.content.ContentProviderClient;
 import android.content.ContentValues;
@@ -83,8 +86,8 @@ public class CreativeWallpaperInfo extends LiveWallpaperInfo {
     public CreativeWallpaperInfo(WallpaperInfo info, String title, @Nullable String author,
             @Nullable String description, String contentDescription, Uri configPreviewUri,
             Uri cleanPreviewUri, Uri deleteUri, Uri thumbnailUri, Uri shareUri, String groupName,
-            boolean isCurrent) {
-        this(info, /* visibleTitle= */ false, /* collectionId= */ null);
+            boolean isCurrent, @NonNull WallpaperDescription wallpaperDescription) {
+        this(info, /* visibleTitle= */ false, info.getPackageName());
         mTitle = title;
         mAuthor = author;
         mDescription = description;
@@ -96,10 +99,11 @@ public class CreativeWallpaperInfo extends LiveWallpaperInfo {
         mShareUri = shareUri;
         mIsCurrent = isCurrent;
         mGroupName = groupName;
+        mWallpaperDescription = wallpaperDescription;
     }
 
     public CreativeWallpaperInfo(WallpaperInfo info, boolean isCurrent) {
-        this(info, false, null);
+        this(info, false, info.getPackageName());
         mIsCurrent = isCurrent;
     }
 
@@ -444,11 +448,36 @@ public class CreativeWallpaperInfo extends LiveWallpaperInfo {
                 cursor.getColumnIndex(WallpaperInfoContract.WALLPAPER_GROUP_NAME));
         int isCurrentApplied = cursor.getInt(
                 cursor.getColumnIndex(WallpaperInfoContract.WALLPAPER_IS_APPLIED));
+        WallpaperDescription descriptionContentHandling =
+                new WallpaperDescription.Builder().setComponent(
+                        wallpaperInfo.getComponent()).build();
+        if (liveWallpaperContentHandling()) {
+            int descriptionContentHandlingIndex = cursor.getColumnIndex(
+                    WallpaperInfoContract.WALLPAPER_DESCRIPTION_CONTENT_HANDLING);
+            if (descriptionContentHandlingIndex >= 0) {
+                descriptionContentHandling = descriptionFromBytes(
+                    cursor.getBlob(descriptionContentHandlingIndex));
+                if (descriptionContentHandling.getComponent() == null) {
+                    descriptionContentHandling =
+                        descriptionContentHandling.toBuilder().setComponent(
+                            wallpaperInfo.getComponent()).build();
+                }
+            }
+        }
 
         return new CreativeWallpaperInfo(wallpaperInfo, wallpaperTitle, wallpaperAuthor,
                 wallpaperDescription, wallpaperContentDescription, configPreviewUri,
                 cleanPreviewUri, deleteUri, thumbnailUri, shareUri, groupName, /* isCurrent= */
-                (isCurrentApplied == 1));
+                (isCurrentApplied == 1), descriptionContentHandling);
+    }
+
+    private static WallpaperDescription descriptionFromBytes(byte[] bytes) {
+        Parcel parcel = Parcel.obtain();
+        parcel.unmarshall(bytes, 0, bytes.length);
+        parcel.setDataPosition(0);
+        WallpaperDescription desc = WallpaperDescription.CREATOR.createFromParcel(parcel);
+        parcel.recycle();
+        return desc;
     }
 
     /**
diff --git a/src/com/android/wallpaper/model/LiveWallpaperInfo.java b/src/com/android/wallpaper/model/LiveWallpaperInfo.java
index b2cf663c..3fbd30e8 100755
--- a/src/com/android/wallpaper/model/LiveWallpaperInfo.java
+++ b/src/com/android/wallpaper/model/LiveWallpaperInfo.java
@@ -17,6 +17,7 @@ package com.android.wallpaper.model;
 
 import android.app.Activity;
 import android.app.WallpaperManager;
+import android.app.wallpaper.WallpaperDescription;
 import android.content.Context;
 import android.content.Intent;
 import android.content.pm.ApplicationInfo;
@@ -30,6 +31,7 @@ import android.text.TextUtils;
 import android.util.AttributeSet;
 import android.util.Log;
 
+import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
 import com.android.wallpaper.R;
@@ -159,6 +161,7 @@ public class LiveWallpaperInfo extends WallpaperInfo {
     protected LiveWallpaperThumbAsset mThumbAsset;
     protected boolean mVisibleTitle;
     @Nullable private final String mCollectionId;
+    @NonNull protected WallpaperDescription mWallpaperDescription;
 
     /**
      * Constructs a LiveWallpaperInfo wrapping the given system WallpaperInfo object, representing
@@ -176,9 +179,18 @@ public class LiveWallpaperInfo extends WallpaperInfo {
      */
     public LiveWallpaperInfo(android.app.WallpaperInfo info, boolean visibleTitle,
             @Nullable String collectionId) {
+        // TODO (b/373890500) Make info @NonNull and remove null info logic below
+        this(info, visibleTitle, collectionId,
+            new WallpaperDescription.Builder().setComponent(
+                (info != null) ? info.getComponent() : null).build());
+    }
+
+    public LiveWallpaperInfo(android.app.WallpaperInfo info, boolean visibleTitle,
+            @Nullable String collectionId, @NonNull WallpaperDescription description) {
         mInfo = info;
         mVisibleTitle = visibleTitle;
         mCollectionId = collectionId;
+        mWallpaperDescription = description;
     }
 
     protected LiveWallpaperInfo(Parcel in) {
@@ -186,6 +198,8 @@ public class LiveWallpaperInfo extends WallpaperInfo {
         mInfo = in.readParcelable(android.app.WallpaperInfo.class.getClassLoader());
         mVisibleTitle = in.readInt() == 1;
         mCollectionId = in.readString();
+        mWallpaperDescription = in.readParcelable(WallpaperDescription.class.getClassLoader(),
+                WallpaperDescription.class);
     }
 
     /**
@@ -458,6 +472,7 @@ public class LiveWallpaperInfo extends WallpaperInfo {
         parcel.writeParcelable(mInfo, 0 /* flags */);
         parcel.writeInt(mVisibleTitle ? 1 : 0);
         parcel.writeString(mCollectionId);
+        parcel.writeParcelable(mWallpaperDescription, 0 /* flags */);
     }
 
     @Override
@@ -494,6 +509,15 @@ public class LiveWallpaperInfo extends WallpaperInfo {
         return isAppliedToHome || isAppliedToLock;
     }
 
+    @NonNull
+    public WallpaperDescription getWallpaperDescription() {
+        return mWallpaperDescription;
+    }
+
+    public void setWallpaperDescription(@NonNull WallpaperDescription description) {
+        mWallpaperDescription = description;
+    }
+
     /**
      * Saves a wallpaper of type LiveWallpaperInfo at a particular destination.
      * The default implementation simply returns the current wallpaper, but this can be overridden
diff --git a/src/com/android/wallpaper/model/LiveWallpaperMetadata.java b/src/com/android/wallpaper/model/LiveWallpaperMetadata.java
index 28a7fdef..983441d4 100644
--- a/src/com/android/wallpaper/model/LiveWallpaperMetadata.java
+++ b/src/com/android/wallpaper/model/LiveWallpaperMetadata.java
@@ -16,10 +16,12 @@
 package com.android.wallpaper.model;
 
 import android.app.WallpaperInfo;
+import android.app.wallpaper.WallpaperDescription;
 import android.graphics.Point;
 import android.graphics.Rect;
 import android.net.Uri;
 
+import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
 import java.util.List;
@@ -30,11 +32,20 @@ import java.util.Map;
  */
 public class LiveWallpaperMetadata extends WallpaperMetadata {
     @Nullable private final Uri mPreviewUri;
+    @NonNull private final WallpaperDescription mDescription;
 
     public LiveWallpaperMetadata(android.app.WallpaperInfo wallpaperComponent,
             @Nullable Uri previewUri) {
+        this(wallpaperComponent, previewUri,
+                new WallpaperDescription.Builder().setComponent(
+                        wallpaperComponent.getComponent()).build());
+    }
+
+    public LiveWallpaperMetadata(android.app.WallpaperInfo wallpaperComponent,
+            @Nullable Uri previewUri, @NonNull WallpaperDescription description) {
         super(null, null, null, wallpaperComponent, null);
         mPreviewUri = previewUri;
+        mDescription = description;
     }
 
     @Override
@@ -67,4 +78,9 @@ public class LiveWallpaperMetadata extends WallpaperMetadata {
     public Uri getPreviewUri() {
         return mPreviewUri;
     }
+
+    @NonNull
+    public WallpaperDescription getDescription() {
+        return mDescription;
+    }
 }
diff --git a/src/com/android/wallpaper/model/LiveWallpaperPrefMetadata.kt b/src/com/android/wallpaper/model/LiveWallpaperPrefMetadata.kt
index 033c46be..6eea8a58 100755
--- a/src/com/android/wallpaper/model/LiveWallpaperPrefMetadata.kt
+++ b/src/com/android/wallpaper/model/LiveWallpaperPrefMetadata.kt
@@ -17,7 +17,7 @@ package com.android.wallpaper.model
 
 /** Metadata for the live wallpaper to be saved to the system preferences. */
 data class LiveWallpaperPrefMetadata(
-    val attributions: List<String?>?,
+    val attributions: List<String>?,
     val serviceName: String,
     val effectName: String?,
     val collectionId: String?,
diff --git a/src/com/android/wallpaper/model/StaticWallpaperPrefMetadata.kt b/src/com/android/wallpaper/model/StaticWallpaperPrefMetadata.kt
index 8a29b27b..b131adc2 100755
--- a/src/com/android/wallpaper/model/StaticWallpaperPrefMetadata.kt
+++ b/src/com/android/wallpaper/model/StaticWallpaperPrefMetadata.kt
@@ -17,7 +17,7 @@ package com.android.wallpaper.model
 
 /** Metadata for the static image wallpaper to be saved to the system preferences. */
 data class StaticWallpaperPrefMetadata(
-    val attributions: List<String?>?,
+    val attributions: List<String>?,
     val actionUrl: String?,
     val collectionId: String?,
     val hashCode: Long?,
diff --git a/src/com/android/wallpaper/model/WallpaperInfoContract.java b/src/com/android/wallpaper/model/WallpaperInfoContract.java
index 41bd92cd..47024bd8 100644
--- a/src/com/android/wallpaper/model/WallpaperInfoContract.java
+++ b/src/com/android/wallpaper/model/WallpaperInfoContract.java
@@ -27,6 +27,8 @@ public final class WallpaperInfoContract {
     public static final String WALLPAPER_TITLE = "wallpaper_title";
     public static final String WALLPAPER_AUTHOR = "wallpaper_author";
     public static final String WALLPAPER_DESCRIPTION = "wallpaper_description";
+    public static final String WALLPAPER_DESCRIPTION_CONTENT_HANDLING =
+            "wallpaper_description_content_handling";
     public static final String WALLPAPER_CONTENT_DESCRIPTION = "wallpaper_content_description";
     public static final String WALLPAPER_THUMBNAIL = "wallpaper_thumbnail";
     public static final String WALLPAPER_CONFIG_PREVIEW_URI = "wallpaper_config_preview_uri";
diff --git a/src/com/android/wallpaper/module/DefaultCurrentWallpaperInfoFactory.java b/src/com/android/wallpaper/module/DefaultCurrentWallpaperInfoFactory.java
index a50f6f5a..f2b601c0 100755
--- a/src/com/android/wallpaper/module/DefaultCurrentWallpaperInfoFactory.java
+++ b/src/com/android/wallpaper/module/DefaultCurrentWallpaperInfoFactory.java
@@ -15,6 +15,8 @@
  */
 package com.android.wallpaper.module;
 
+import static android.app.Flags.liveWallpaperContentHandling;
+
 import android.app.WallpaperManager;
 import android.content.ComponentName;
 import android.content.Context;
@@ -26,6 +28,7 @@ import com.android.wallpaper.config.BaseFlags;
 import com.android.wallpaper.model.CreativeWallpaperInfo;
 import com.android.wallpaper.model.CurrentWallpaperInfo;
 import com.android.wallpaper.model.DefaultWallpaperInfo;
+import com.android.wallpaper.model.LiveWallpaperInfo;
 import com.android.wallpaper.model.LiveWallpaperMetadata;
 import com.android.wallpaper.model.WallpaperInfo;
 import com.android.wallpaper.model.WallpaperMetadata;
@@ -121,6 +124,11 @@ public class DefaultCurrentWallpaperInfoFactory implements CurrentWallpaperInfoF
                     if (homeWallpaperMetadata instanceof LiveWallpaperMetadata) {
                         homeWallpaper = mLiveWallpaperInfoFactory.getLiveWallpaperInfo(
                                 homeWallpaperMetadata.getWallpaperComponent());
+                        if (liveWallpaperContentHandling()) {
+                            ((LiveWallpaperInfo) homeWallpaper).setWallpaperDescription(
+                                    ((LiveWallpaperMetadata) homeWallpaperMetadata)
+                                            .getDescription());
+                        }
                         updateIfCreative(homeWallpaper, homeWallpaperMetadata);
                     } else {
                         homeWallpaper = new CurrentWallpaperInfo(
@@ -141,6 +149,11 @@ public class DefaultCurrentWallpaperInfoFactory implements CurrentWallpaperInfoF
                         if (lockWallpaperMetadata instanceof LiveWallpaperMetadata) {
                             lockWallpaper = mLiveWallpaperInfoFactory.getLiveWallpaperInfo(
                                     lockWallpaperMetadata.getWallpaperComponent());
+                            if (liveWallpaperContentHandling()) {
+                                ((LiveWallpaperInfo) lockWallpaper).setWallpaperDescription(
+                                        ((LiveWallpaperMetadata) lockWallpaperMetadata)
+                                                .getDescription());
+                            }
                             updateIfCreative(lockWallpaper, lockWallpaperMetadata);
                         } else {
                             if (isLockWallpaperBuiltIn(context)) {
diff --git a/src/com/android/wallpaper/module/DefaultPackageStatusNotifier.java b/src/com/android/wallpaper/module/DefaultPackageStatusNotifier.java
index 6f7117fa..1e3b0842 100644
--- a/src/com/android/wallpaper/module/DefaultPackageStatusNotifier.java
+++ b/src/com/android/wallpaper/module/DefaultPackageStatusNotifier.java
@@ -21,21 +21,28 @@ import android.content.pm.LauncherApps;
 import android.content.pm.PackageManager;
 import android.os.UserHandle;
 
+import dagger.hilt.android.qualifiers.ApplicationContext;
+
 import java.util.HashMap;
 import java.util.Map;
 
+import javax.inject.Inject;
+import javax.inject.Singleton;
+
+
 /**
  * Default version of {@link PackageStatusNotifier} that uses {@link LauncherApps}
  */
+@Singleton
 public class DefaultPackageStatusNotifier implements PackageStatusNotifier {
 
     private final Map<Listener, ListenerWrapper> mListeners = new HashMap<>();
     private final Context mAppContext;
     private final LauncherApps mLauncherApps;
 
-
-    public DefaultPackageStatusNotifier(Context context) {
-        mAppContext = context.getApplicationContext();
+    @Inject
+    public DefaultPackageStatusNotifier(@ApplicationContext Context context) {
+        mAppContext = context;
         mLauncherApps = (LauncherApps) context.getSystemService(Context.LAUNCHER_APPS_SERVICE);
     }
 
diff --git a/src/com/android/wallpaper/module/DefaultWallpaperPersister.java b/src/com/android/wallpaper/module/DefaultWallpaperPersister.java
index 4e98df80..098ce22b 100755
--- a/src/com/android/wallpaper/module/DefaultWallpaperPersister.java
+++ b/src/com/android/wallpaper/module/DefaultWallpaperPersister.java
@@ -752,7 +752,9 @@ public class DefaultWallpaperPersister implements WallpaperPersister {
             saveStaticWallpaperToPreferences(
                     destination,
                     new StaticWallpaperPrefMetadata(
-                            mWallpaper.getAttributions(mAppContext),
+                            mWallpaper.getAttributions(mAppContext).stream()
+                                    .map((entry) -> (entry != null) ? entry : "")
+                                    .toList(),
                             mWallpaper.getActionUrl(mAppContext),
                             mWallpaper.getCollectionId(mAppContext),
                             bitmapHash,
diff --git a/src/com/android/wallpaper/module/DefaultWallpaperRefresher.java b/src/com/android/wallpaper/module/DefaultWallpaperRefresher.java
index 4ce88fb1..a9a7054b 100755
--- a/src/com/android/wallpaper/module/DefaultWallpaperRefresher.java
+++ b/src/com/android/wallpaper/module/DefaultWallpaperRefresher.java
@@ -15,12 +15,15 @@
  */
 package com.android.wallpaper.module;
 
+import static android.app.Flags.liveWallpaperContentHandling;
 import static android.app.WallpaperManager.FLAG_LOCK;
 import static android.app.WallpaperManager.FLAG_SYSTEM;
 
 import android.annotation.Nullable;
 import android.annotation.SuppressLint;
+import android.app.WallpaperInfo;
 import android.app.WallpaperManager;
+import android.app.wallpaper.WallpaperInstance;
 import android.content.ContentProviderClient;
 import android.content.Context;
 import android.database.Cursor;
@@ -122,8 +125,9 @@ public class DefaultWallpaperRefresher implements WallpaperRefresher {
         @Override
         protected List<WallpaperMetadata> doInBackground(Void... unused) {
             List<WallpaperMetadata> wallpaperMetadatas = new ArrayList<>();
+            WallpaperInfo homeInfo = mWallpaperManager.getWallpaperInfo(FLAG_SYSTEM);
 
-            boolean isHomeScreenStatic = mWallpaperManager.getWallpaperInfo(FLAG_SYSTEM) == null;
+            boolean isHomeScreenStatic = (homeInfo == null);
             if (!isHomeScreenMetadataCurrent() || (isHomeScreenStatic
                     && isHomeScreenAttributionsEmpty())) {
                 mWallpaperPreferences.clearHomeWallpaperMetadata();
@@ -133,7 +137,7 @@ public class DefaultWallpaperRefresher implements WallpaperRefresher {
             boolean isLockScreenWallpaperCurrentlySet =
                     mWallpaperStatusChecker.isLockWallpaperSet();
 
-            if (mWallpaperManager.getWallpaperInfo() == null) {
+            if (isHomeScreenStatic) {
                 wallpaperMetadatas.add(new WallpaperMetadata(
                         mWallpaperPreferences.getHomeWallpaperAttributions(),
                         mWallpaperPreferences.getHomeWallpaperActionUrl(),
@@ -141,10 +145,16 @@ public class DefaultWallpaperRefresher implements WallpaperRefresher {
                         /* wallpaperComponent= */ null,
                         getCurrentWallpaperCropHints(FLAG_SYSTEM)));
             } else {
-                android.app.WallpaperInfo info = mWallpaperManager.getWallpaperInfo();
-                Uri previewUri = getCreativePreviewUri(mAppContext, info,
-                        WallpaperDestination.HOME);
-                wallpaperMetadatas.add(new LiveWallpaperMetadata(info, previewUri));
+                if (liveWallpaperContentHandling()) {
+                    WallpaperInstance instance = mWallpaperManager.getWallpaperInstance(
+                            FLAG_SYSTEM);
+                    wallpaperMetadatas.add(
+                            new LiveWallpaperMetadata(homeInfo, null, instance.getDescription()));
+                } else {
+                    Uri previewUri = getCreativePreviewUri(mAppContext, homeInfo,
+                            WallpaperDestination.HOME);
+                    wallpaperMetadatas.add(new LiveWallpaperMetadata(homeInfo, previewUri));
+                }
             }
 
             // Return only home metadata if pre-N device or lock screen wallpaper is not explicitly
@@ -153,7 +163,9 @@ public class DefaultWallpaperRefresher implements WallpaperRefresher {
                 return wallpaperMetadatas;
             }
 
-            boolean isLockScreenStatic = mWallpaperManager.getWallpaperInfo(FLAG_LOCK) == null;
+            WallpaperInfo lockInfo = mWallpaperManager.getWallpaperInfo(FLAG_LOCK);
+
+            boolean isLockScreenStatic = (lockInfo == null);
             if (!isLockScreenMetadataCurrent() || (isLockScreenStatic
                     && isLockScreenAttributionsEmpty())) {
                 mWallpaperPreferences.clearLockWallpaperMetadata();
@@ -168,10 +180,15 @@ public class DefaultWallpaperRefresher implements WallpaperRefresher {
                         /* wallpaperComponent= */ null,
                         getCurrentWallpaperCropHints(FLAG_LOCK)));
             } else {
-                android.app.WallpaperInfo info = mWallpaperManager.getWallpaperInfo(FLAG_LOCK);
-                Uri previewUri = getCreativePreviewUri(mAppContext, info,
-                        WallpaperDestination.LOCK);
-                wallpaperMetadatas.add(new LiveWallpaperMetadata(info, previewUri));
+                if (liveWallpaperContentHandling()) {
+                    WallpaperInstance instance = mWallpaperManager.getWallpaperInstance(FLAG_LOCK);
+                    wallpaperMetadatas.add(
+                            new LiveWallpaperMetadata(lockInfo, null, instance.getDescription()));
+                } else {
+                    Uri previewUri = getCreativePreviewUri(mAppContext, lockInfo,
+                            WallpaperDestination.LOCK);
+                    wallpaperMetadatas.add(new LiveWallpaperMetadata(lockInfo, previewUri));
+                }
             }
 
             return wallpaperMetadatas;
diff --git a/src/com/android/wallpaper/module/WallpaperPicker2Injector.kt b/src/com/android/wallpaper/module/WallpaperPicker2Injector.kt
index be8182dd..e4c29644 100755
--- a/src/com/android/wallpaper/module/WallpaperPicker2Injector.kt
+++ b/src/com/android/wallpaper/module/WallpaperPicker2Injector.kt
@@ -61,7 +61,21 @@ import kotlinx.coroutines.CoroutineScope
 @Singleton
 open class WallpaperPicker2Injector
 @Inject
-constructor(@MainDispatcher private val mainScope: CoroutineScope) : Injector {
+constructor(
+    @MainDispatcher private val mainScope: CoroutineScope,
+    private val displayUtils: Lazy<DisplayUtils>,
+    private val requester: Lazy<Requester>,
+    private val networkStatusNotifier: Lazy<NetworkStatusNotifier>,
+    private val partnerProvider: Lazy<PartnerProvider>,
+    private val uiModeManager: Lazy<UiModeManagerWrapper>,
+    private val userEventLogger: Lazy<UserEventLogger>,
+    private val injectedWallpaperClient: Lazy<WallpaperClient>,
+    private val injectedWallpaperInteractor: Lazy<WallpaperInteractor>,
+    private val prefs: Lazy<WallpaperPreferences>,
+    private val wallpaperColorsRepository: Lazy<WallpaperColorsRepository>,
+    private val defaultWallpaperCategoryWrapper: Lazy<WallpaperCategoryWrapper>,
+    private val packageNotifier: Lazy<PackageStatusNotifier>,
+) : Injector {
     private var alarmManagerWrapper: AlarmManagerWrapper? = null
     private var bitmapCropper: BitmapCropper? = null
     private var categoryProvider: CategoryProvider? = null
@@ -70,7 +84,6 @@ constructor(@MainDispatcher private val mainScope: CoroutineScope) : Injector {
     private var drawableLayerResolver: DrawableLayerResolver? = null
     private var exploreIntentChecker: ExploreIntentChecker? = null
     private var liveWallpaperInfoFactory: LiveWallpaperInfoFactory? = null
-    private var packageStatusNotifier: PackageStatusNotifier? = null
     private var performanceMonitor: PerformanceMonitor? = null
     private var systemFeatureChecker: SystemFeatureChecker? = null
     private var wallpaperPersister: WallpaperPersister? = null
@@ -85,20 +98,6 @@ constructor(@MainDispatcher private val mainScope: CoroutineScope) : Injector {
     private var previewActivityIntentFactory: InlinePreviewIntentFactory? = null
     private var viewOnlyPreviewActivityIntentFactory: InlinePreviewIntentFactory? = null
 
-    // Injected objects, sorted by alphabetical order on the type of object
-    @Inject lateinit var displayUtils: Lazy<DisplayUtils>
-    @Inject lateinit var requester: Lazy<Requester>
-    @Inject lateinit var networkStatusNotifier: Lazy<NetworkStatusNotifier>
-    @Inject lateinit var partnerProvider: Lazy<PartnerProvider>
-    @Inject lateinit var uiModeManager: Lazy<UiModeManagerWrapper>
-    @Inject lateinit var userEventLogger: Lazy<UserEventLogger>
-    @Inject lateinit var injectedWallpaperClient: Lazy<WallpaperClient>
-    @Inject lateinit var injectedWallpaperInteractor: Lazy<WallpaperInteractor>
-    @Inject lateinit var prefs: Lazy<WallpaperPreferences>
-    @Inject lateinit var wallpaperColorsRepository: Lazy<WallpaperColorsRepository>
-
-    @Inject lateinit var defaultWallpaperCategoryWrapper: Lazy<WallpaperCategoryWrapper>
-
     override fun getApplicationCoroutineScope(): CoroutineScope {
         return mainScope
     }
@@ -189,10 +188,7 @@ constructor(@MainDispatcher private val mainScope: CoroutineScope) : Injector {
 
     @Synchronized
     override fun getPackageStatusNotifier(context: Context): PackageStatusNotifier {
-        return packageStatusNotifier
-            ?: DefaultPackageStatusNotifier(context.applicationContext).also {
-                packageStatusNotifier = it
-            }
+        return packageNotifier.get()
     }
 
     @Synchronized
diff --git a/src/com/android/wallpaper/picker/CategorySelectorFragment.java b/src/com/android/wallpaper/picker/CategorySelectorFragment.java
index 10397271..347190a5 100644
--- a/src/com/android/wallpaper/picker/CategorySelectorFragment.java
+++ b/src/com/android/wallpaper/picker/CategorySelectorFragment.java
@@ -448,12 +448,13 @@ public class CategorySelectorFragment extends AppbarFragment {
                 com.google.android.material.R.id.snackbar_text);
         layout.setBackgroundResource(R.drawable.snackbar_background);
         TypedArray typedArray = getContext().obtainStyledAttributes(
-                new int[]{android.R.attr.textColorPrimary,
-                        com.android.internal.R.attr.materialColorPrimaryContainer});
+                new int[]{android.R.attr.textColorPrimary});
         textView.setTextColor(typedArray.getColor(0, Color.TRANSPARENT));
-        snackbar.setActionTextColor(typedArray.getColor(1, Color.TRANSPARENT));
         typedArray.recycle();
 
+        snackbar.setActionTextColor(
+                getContext().getColor(com.android.internal.R.color.materialColorPrimaryContainer));
+
         snackbar.setAction(getContext().getString(R.string.settings_snackbar_enable),
                 new View.OnClickListener() {
                     @Override
diff --git a/src/com/android/wallpaper/picker/DisplayAspectRatioFrameLayout.kt b/src/com/android/wallpaper/picker/DisplayAspectRatioFrameLayout.kt
index 5069b6fe..7d07b146 100644
--- a/src/com/android/wallpaper/picker/DisplayAspectRatioFrameLayout.kt
+++ b/src/com/android/wallpaper/picker/DisplayAspectRatioFrameLayout.kt
@@ -21,16 +21,20 @@ import android.content.Context
 import android.util.AttributeSet
 import android.widget.FrameLayout
 import androidx.core.view.children
+import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.util.ScreenSizeCalculator
+import kotlin.math.max
 
 /**
  * [FrameLayout] that sizes its children using a fixed aspect ratio that is the same as that of the
  * display.
+ *
+ * Uses the initial height to calculate width based on the display ratio, then use the new width to
+ * get the new height, this will wrap the child view inside like wrap content for both width and
+ * height, for this to work the width must be wrap_content or 0dp and the height cannot be 0dp.
  */
-class DisplayAspectRatioFrameLayout(
-    context: Context,
-    attrs: AttributeSet?,
-) : FrameLayout(context, attrs) {
+class DisplayAspectRatioFrameLayout(context: Context, attrs: AttributeSet?) :
+    FrameLayout(context, attrs) {
 
     override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
         super.onMeasure(widthMeasureSpec, heightMeasureSpec)
@@ -43,20 +47,34 @@ class DisplayAspectRatioFrameLayout(
         //
         // If you need to use this class to force the height dimension based on the width instead,
         // you will need to flip the logic below.
+        var maxWidth = 0
         children.forEach { child ->
+            // Calculate child width from height based on display ratio, max at parent width.
             val childWidth =
                 (child.measuredHeight / screenAspectRatio).toInt().coerceAtMost(measuredWidth)
             child.measure(
                 MeasureSpec.makeMeasureSpec(childWidth, MeasureSpec.EXACTLY),
                 MeasureSpec.makeMeasureSpec(
                     if (childWidth < measuredWidth) {
+                        // Child width not capped, height is the same.
                         child.measuredHeight
                     } else {
+                        // Child width capped at parent width, recalculates height based on ratio.
                         (childWidth * screenAspectRatio).toInt()
                     },
                     MeasureSpec.EXACTLY,
                 ),
             )
+            // Find max width among all children.
+            maxWidth = max(maxWidth, child.measuredWidth)
+        }
+
+        if (BaseFlags.get().isNewPickerUi()) {
+            // New height based on the new width
+            val newHeight = (maxWidth * screenAspectRatio).toInt()
+
+            // Makes width wrap content
+            setMeasuredDimension(resolveSize(maxWidth, widthMeasureSpec), newHeight)
         }
     }
 }
diff --git a/src/com/android/wallpaper/picker/LivePreviewFragment.java b/src/com/android/wallpaper/picker/LivePreviewFragment.java
index 4c09e6fe..91faaea4 100644
--- a/src/com/android/wallpaper/picker/LivePreviewFragment.java
+++ b/src/com/android/wallpaper/picker/LivePreviewFragment.java
@@ -30,6 +30,7 @@ import android.app.AlertDialog;
 import android.app.WallpaperColors;
 import android.app.WallpaperInfo;
 import android.app.WallpaperManager;
+import android.app.wallpaper.WallpaperDescription;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
@@ -605,7 +606,8 @@ public class LivePreviewFragment extends PreviewFragment {
                     null,
                     mIsViewAsHome ? FLAG_SYSTEM : FLAG_LOCK,
                     mIsAssetIdPresent ? WallpaperConnection.WhichPreview.EDIT_NON_CURRENT
-                            : WallpaperConnection.WhichPreview.EDIT_CURRENT);
+                            : WallpaperConnection.WhichPreview.EDIT_CURRENT,
+                    new WallpaperDescription.Builder().setComponent(info.getComponent()).build());
             mWallpaperConnection.setVisibility(true);
         } else {
             WallpaperColorsLoader.getWallpaperColors(
diff --git a/src/com/android/wallpaper/picker/MyPhotosStarter.java b/src/com/android/wallpaper/picker/MyPhotosStarter.java
index fc192265..f41198eb 100755
--- a/src/com/android/wallpaper/picker/MyPhotosStarter.java
+++ b/src/com/android/wallpaper/picker/MyPhotosStarter.java
@@ -16,9 +16,11 @@
 package com.android.wallpaper.picker;
 
 import android.annotation.Nullable;
-import android.content.Context;
+import android.app.Activity;
 import android.content.Intent;
 
+import androidx.activity.result.ActivityResultLauncher;
+
 /**
  * Interface for activities that launch an Android custom image picker.
  */
@@ -30,6 +32,15 @@ public interface MyPhotosStarter {
      */
     void requestCustomPhotoPicker(PermissionChangedListener listener);
 
+    /**
+     * Displays the Android custom photo picker within this Activity to select an image for
+     * setting as the device’s wallpaper. This implementation enables launching the photo picker
+     * from a specified custom Activity, allowing greater flexibility in initiating the photo
+     * selection process.
+     */
+    void requestCustomPhotoPicker(PermissionChangedListener listener, Activity activity,
+            ActivityResultLauncher<Intent> photoPickerLauncher);
+
     /**
      * Interface for clients to implement in order to be notified of permissions grant status changes.
      */
@@ -62,14 +73,14 @@ public interface MyPhotosStarter {
         /**
          * @return the Intent to use to start the "My Photos" picker.
          */
-        default Intent getMyPhotosIntent(Context context) {
+        default Intent getMyPhotosIntent() {
             Intent intent = new Intent(Intent.ACTION_PICK);
             intent.setType("image/*");
             return intent;
         }
 
         @Nullable
-        default Intent getFallbackIntent(Context context) {
+        default Intent getFallbackIntent() {
             return null;
         }
     }
diff --git a/src/com/android/wallpaper/picker/WallpaperPickerDelegate.java b/src/com/android/wallpaper/picker/WallpaperPickerDelegate.java
index b6c802f2..ab862181 100644
--- a/src/com/android/wallpaper/picker/WallpaperPickerDelegate.java
+++ b/src/com/android/wallpaper/picker/WallpaperPickerDelegate.java
@@ -27,6 +27,7 @@ import android.os.Build.VERSION_CODES;
 import android.service.wallpaper.WallpaperService;
 import android.util.Log;
 
+import androidx.activity.result.ActivityResultLauncher;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.fragment.app.FragmentActivity;
@@ -143,6 +144,12 @@ public class WallpaperPickerDelegate implements MyPhotosStarter {
         showCustomPhotoPicker();
     }
 
+    @Override
+    public void requestCustomPhotoPicker(PermissionChangedListener listener, Activity activity,
+            ActivityResultLauncher<Intent> photoPickerLauncher) {
+        requestCustomPhotoPicker(listener);
+    }
+
     /**
      * Requests to show the Android custom photo picker for the sake of picking a
      * photo to set as the device's wallpaper.
@@ -165,10 +172,10 @@ public class WallpaperPickerDelegate implements MyPhotosStarter {
 
     private void showCustomPhotoPicker() {
         try {
-            Intent intent = mMyPhotosIntentProvider.getMyPhotosIntent(mActivity);
+            Intent intent = mMyPhotosIntentProvider.getMyPhotosIntent();
             mActivity.startActivityForResult(intent, SHOW_CATEGORY_REQUEST_CODE);
         } catch (ActivityNotFoundException e) {
-            Intent fallback = mMyPhotosIntentProvider.getFallbackIntent(mActivity);
+            Intent fallback = mMyPhotosIntentProvider.getFallbackIntent();
             if (fallback != null) {
                 Log.i(TAG, "Couldn't launch photo picker with main intent, trying with fallback");
                 mActivity.startActivityForResult(fallback, SHOW_CATEGORY_REQUEST_CODE);
diff --git a/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcher.kt b/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcher.kt
index 93d95846..34ef4a20 100644
--- a/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcher.kt
+++ b/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcher.kt
@@ -22,9 +22,8 @@ import android.content.Intent
 import android.content.IntentFilter
 import android.os.Handler
 import android.os.Looper
-import com.android.systemui.dagger.qualifiers.Main
 import com.android.wallpaper.picker.di.modules.SharedAppModule.Companion.BroadcastRunning
-import java.util.concurrent.Executor
+import dagger.hilt.android.qualifiers.ApplicationContext
 import javax.inject.Inject
 import javax.inject.Singleton
 import kotlinx.coroutines.channels.awaitClose
@@ -47,10 +46,8 @@ import kotlinx.coroutines.flow.callbackFlow
 open class BroadcastDispatcher
 @Inject
 constructor(
-    private val context: Context,
-    @Main private val mainExecutor: Executor,
+    @ApplicationContext private val context: Context,
     @BroadcastRunning private val broadcastLooper: Looper,
-    @BroadcastRunning private val broadcastExecutor: Executor,
 ) {
     /**
      * Register a receiver for broadcast with the dispatcher
@@ -70,12 +67,17 @@ constructor(
     open fun registerReceiver(
         receiver: BroadcastReceiver,
         filter: IntentFilter,
-        executor: Executor = mainExecutor,
         @Context.RegisterReceiverFlags flags: Int = Context.RECEIVER_EXPORTED,
-        permission: String? = null
+        permission: String? = null,
     ) {
         checkFilter(filter)
-        context.registerReceiver(receiver, filter, permission, Handler(broadcastLooper), flags)
+        context.registerReceiver(
+            receiver,
+            filter,
+            permission,
+            Handler(Looper.getMainLooper()),
+            flags,
+        )
     }
 
     /**
@@ -99,13 +101,7 @@ constructor(
                 }
             }
 
-        registerReceiver(
-            receiver,
-            filter,
-            broadcastExecutor,
-            flags,
-            permission,
-        )
+        registerReceiver(receiver, filter, flags, permission)
 
         awaitClose { unregisterReceiver(receiver) }
     }
diff --git a/src/com/android/wallpaper/picker/category/client /DefaultWallpaperCategoryClientImpl.kt b/src/com/android/wallpaper/picker/category/client /DefaultWallpaperCategoryClientImpl.kt
index 57f4768e..a6b2ff46 100644
--- a/src/com/android/wallpaper/picker/category/client /DefaultWallpaperCategoryClientImpl.kt	
+++ b/src/com/android/wallpaper/picker/category/client /DefaultWallpaperCategoryClientImpl.kt	
@@ -143,7 +143,8 @@ constructor(
                 val thirdPartyLiveWallpaperCategory = ThirdPartyLiveWallpaperCategory(
                     context.getString(R.string.live_wallpapers_category_title),
                     context.getString(R.string.live_wallpaper_collection_id), liveWallpapers,
-                    PRIORITY_LIVE, getExcludedLiveWallpaperPackageNames())
+                    PRIORITY_LIVE,
+                    getExcludedLiveWallpaperPackageNames() + excludedPackageNames)
                 return listOf(thirdPartyLiveWallpaperCategory)
             }
         }
diff --git a/src/com/android/wallpaper/picker/category/data/repository/DefaultWallpaperCategoryRepository.kt b/src/com/android/wallpaper/picker/category/data/repository/DefaultWallpaperCategoryRepository.kt
index 985925cb..d014529f 100644
--- a/src/com/android/wallpaper/picker/category/data/repository/DefaultWallpaperCategoryRepository.kt
+++ b/src/com/android/wallpaper/picker/category/data/repository/DefaultWallpaperCategoryRepository.kt
@@ -150,6 +150,18 @@ constructor(
 
     override suspend fun refreshNetworkCategories() {}
 
+    override suspend fun refreshThirdPartyAppCategories() {
+        _isDefaultCategoriesFetched.value = false
+        fetchThirdPartyAppCategory()
+        _isDefaultCategoriesFetched.value = true
+    }
+
+    override suspend fun refreshThirdPartyLiveWallpaperCategories() {
+        _isDefaultCategoriesFetched.value = false
+        fetchThirdPartyLiveWallpaperCategory()
+        _isDefaultCategoriesFetched.value = true
+    }
+
     private suspend fun fetchOnDeviceCategory() {
         try {
             onDeviceFetchedCategory =
diff --git a/src/com/android/wallpaper/picker/category/data/repository/WallpaperCategoryRepository.kt b/src/com/android/wallpaper/picker/category/data/repository/WallpaperCategoryRepository.kt
index 5c7b7524..b3937fa1 100644
--- a/src/com/android/wallpaper/picker/category/data/repository/WallpaperCategoryRepository.kt
+++ b/src/com/android/wallpaper/picker/category/data/repository/WallpaperCategoryRepository.kt
@@ -45,4 +45,16 @@ interface WallpaperCategoryRepository {
     suspend fun fetchMyPhotosCategory()
 
     suspend fun refreshNetworkCategories()
+
+    /**
+     * ThirdPartyAppCategories represent third-party apps that offer static wallpapers which users
+     * can set as their wallpapers.
+     */
+    suspend fun refreshThirdPartyAppCategories()
+
+    /**
+     * ThirdPartyLiveWallpaperCategories represent third-party apps that offer live wallpapers which
+     * users can set as their wallpapers.
+     */
+    suspend fun refreshThirdPartyLiveWallpaperCategories()
 }
diff --git a/src/com/android/wallpaper/picker/category/domain/interactor/CategoryInteractor.kt b/src/com/android/wallpaper/picker/category/domain/interactor/CategoryInteractor.kt
index f4e694d7..29c7789d 100644
--- a/src/com/android/wallpaper/picker/category/domain/interactor/CategoryInteractor.kt
+++ b/src/com/android/wallpaper/picker/category/domain/interactor/CategoryInteractor.kt
@@ -27,4 +27,6 @@ interface CategoryInteractor {
     val categories: Flow<List<CategoryModel>>
 
     fun refreshNetworkCategories()
+
+    fun refreshThirdPartyLiveWallpaperCategories()
 }
diff --git a/src/com/android/wallpaper/picker/category/domain/interactor/ThirdPartyCategoryInteractor.kt b/src/com/android/wallpaper/picker/category/domain/interactor/ThirdPartyCategoryInteractor.kt
index a24ce3b2..1fde9e74 100644
--- a/src/com/android/wallpaper/picker/category/domain/interactor/ThirdPartyCategoryInteractor.kt
+++ b/src/com/android/wallpaper/picker/category/domain/interactor/ThirdPartyCategoryInteractor.kt
@@ -25,4 +25,6 @@ import kotlinx.coroutines.flow.Flow
  */
 interface ThirdPartyCategoryInteractor {
     val categories: Flow<List<CategoryModel>>
+
+    fun refreshThirdPartyAppCategories()
 }
diff --git a/src/com/android/wallpaper/picker/category/domain/interactor/implementations/CategoryInteractorImpl.kt b/src/com/android/wallpaper/picker/category/domain/interactor/implementations/CategoryInteractorImpl.kt
index dde1c99d..1193c8fc 100644
--- a/src/com/android/wallpaper/picker/category/domain/interactor/implementations/CategoryInteractorImpl.kt
+++ b/src/com/android/wallpaper/picker/category/domain/interactor/implementations/CategoryInteractorImpl.kt
@@ -19,36 +19,35 @@ package com.android.wallpaper.picker.category.domain.interactor.implementations
 import com.android.wallpaper.picker.category.data.repository.WallpaperCategoryRepository
 import com.android.wallpaper.picker.category.domain.interactor.CategoryInteractor
 import com.android.wallpaper.picker.data.category.CategoryModel
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import javax.inject.Inject
 import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.flow.filter
 import kotlinx.coroutines.flow.flatMapLatest
+import kotlinx.coroutines.launch
 
 /** This class implements the business logic in assembling ungrouped category models */
 @Singleton
 class CategoryInteractorImpl
 @Inject
-constructor(val defaultWallpaperCategoryRepository: WallpaperCategoryRepository) :
-    CategoryInteractor {
+constructor(
+    private val defaultWallpaperCategoryRepository: WallpaperCategoryRepository,
+    @BackgroundDispatcher private val backgroundScope: CoroutineScope,
+) : CategoryInteractor {
 
     override val categories: Flow<List<CategoryModel>> =
         defaultWallpaperCategoryRepository.isDefaultCategoriesFetched
             .filter { it }
             .flatMapLatest {
                 combine(
-                    defaultWallpaperCategoryRepository.thirdPartyAppCategory,
                     defaultWallpaperCategoryRepository.onDeviceCategory,
                     defaultWallpaperCategoryRepository.systemCategories,
-                    defaultWallpaperCategoryRepository.thirdPartyLiveWallpaperCategory
-                ) {
-                    thirdPartyAppCategory,
-                    onDeviceCategory,
-                    systemCategories,
-                    thirdPartyLiveWallpaperCategory ->
-                    val combinedList =
-                        (thirdPartyAppCategory + systemCategories + thirdPartyLiveWallpaperCategory)
+                    defaultWallpaperCategoryRepository.thirdPartyLiveWallpaperCategory,
+                ) { onDeviceCategory, systemCategories, thirdPartyLiveWallpaperCategory ->
+                    val combinedList = (systemCategories + thirdPartyLiveWallpaperCategory)
                     val finalList = onDeviceCategory?.let { combinedList + it } ?: combinedList
                     // Sort the categories based on their priority value
                     finalList.sortedBy { it.commonCategoryData.priority }
@@ -56,4 +55,10 @@ constructor(val defaultWallpaperCategoryRepository: WallpaperCategoryRepository)
             }
 
     override fun refreshNetworkCategories() {}
+
+    override fun refreshThirdPartyLiveWallpaperCategories() {
+        backgroundScope.launch {
+            defaultWallpaperCategoryRepository.refreshThirdPartyLiveWallpaperCategories()
+        }
+    }
 }
diff --git a/src/com/android/wallpaper/picker/category/domain/interactor/implementations/ThirdPartyCategoryInteractorImpl.kt b/src/com/android/wallpaper/picker/category/domain/interactor/implementations/ThirdPartyCategoryInteractorImpl.kt
index 3a3aa4b7..303ca378 100644
--- a/src/com/android/wallpaper/picker/category/domain/interactor/implementations/ThirdPartyCategoryInteractorImpl.kt
+++ b/src/com/android/wallpaper/picker/category/domain/interactor/implementations/ThirdPartyCategoryInteractorImpl.kt
@@ -19,15 +19,25 @@ package com.android.wallpaper.picker.category.domain.interactor.implementations
 import com.android.wallpaper.picker.category.data.repository.WallpaperCategoryRepository
 import com.android.wallpaper.picker.category.domain.interactor.ThirdPartyCategoryInteractor
 import com.android.wallpaper.picker.data.category.CategoryModel
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import javax.inject.Inject
 import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.launch
 
 @Singleton
 class ThirdPartyCategoryInteractorImpl
 @Inject
-constructor(wallpaperCategoryRepository: WallpaperCategoryRepository) :
-    ThirdPartyCategoryInteractor {
+constructor(
+    private val wallpaperCategoryRepository: WallpaperCategoryRepository,
+    @BackgroundDispatcher private val backgroundScope: CoroutineScope,
+) : ThirdPartyCategoryInteractor {
+
     override val categories: Flow<List<CategoryModel>> =
         wallpaperCategoryRepository.thirdPartyAppCategory
+
+    override fun refreshThirdPartyAppCategories() {
+        backgroundScope.launch { wallpaperCategoryRepository.refreshThirdPartyAppCategories() }
+    }
 }
diff --git a/src/com/android/wallpaper/picker/category/ui/binder/CategoriesBinder.kt b/src/com/android/wallpaper/picker/category/ui/binder/CategoriesBinder.kt
index a9149799..fd2159db 100644
--- a/src/com/android/wallpaper/picker/category/ui/binder/CategoriesBinder.kt
+++ b/src/com/android/wallpaper/picker/category/ui/binder/CategoriesBinder.kt
@@ -25,6 +25,7 @@ import androidx.lifecycle.repeatOnLifecycle
 import androidx.recyclerview.widget.RecyclerView
 import com.android.wallpaper.R
 import com.android.wallpaper.picker.category.ui.viewmodel.CategoriesViewModel
+import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.launch
 
 /** Binds the wallpaper categories and its meta data to the category screen */
@@ -58,11 +59,9 @@ object CategoriesBinder {
                 }
 
                 launch {
-                    viewModel.isConnectionObtained.collect { didNetworkGoFromOffToOn ->
-                        // trigger a refresh of the categories only if network is being enabled
-                        if (didNetworkGoFromOffToOn) {
-                            viewModel.refreshNetworkCategories()
-                        }
+                    viewModel.isConnectionObtained.distinctUntilChanged().collect { _ ->
+                        // Trigger a refresh of the categories every time the network status changes
+                        viewModel.refreshNetworkCategories()
                     }
                 }
 
@@ -75,7 +74,7 @@ object CategoriesBinder {
                                 // Perform navigation with event.data
                                 navigationHandler(navigationEvent, null)
                             }
-                            CategoriesViewModel.NavigationEvent.NavigateToPhotosPicker -> {
+                            is CategoriesViewModel.NavigationEvent.NavigateToPhotosPicker -> {
                                 navigationHandler(navigationEvent) {
                                     viewModel.updateMyPhotosCategory()
                                 }
diff --git a/src/com/android/wallpaper/picker/category/ui/view/CategoriesFragment.kt b/src/com/android/wallpaper/picker/category/ui/view/CategoriesFragment.kt
index 229d3726..34a85285 100644
--- a/src/com/android/wallpaper/picker/category/ui/view/CategoriesFragment.kt
+++ b/src/com/android/wallpaper/picker/category/ui/view/CategoriesFragment.kt
@@ -16,6 +16,7 @@
 
 package com.android.wallpaper.picker.category.ui.view
 
+import android.Manifest
 import android.app.Activity
 import android.content.ComponentName
 import android.content.Intent
@@ -27,23 +28,27 @@ import android.view.LayoutInflater
 import android.view.View
 import android.view.ViewGroup
 import android.widget.TextView
+import androidx.activity.result.ActivityResultLauncher
+import androidx.activity.result.contract.ActivityResultContracts
 import androidx.core.content.ContextCompat
 import androidx.fragment.app.Fragment
 import androidx.fragment.app.activityViewModels
 import androidx.recyclerview.widget.RecyclerView
 import com.android.wallpaper.R
+import com.android.wallpaper.model.ImageWallpaperInfo
 import com.android.wallpaper.module.MultiPanesChecker
 import com.android.wallpaper.picker.AppbarFragment
-import com.android.wallpaper.picker.CategorySelectorFragment.CategorySelectorFragmentHost
 import com.android.wallpaper.picker.MyPhotosStarter.PermissionChangedListener
-import com.android.wallpaper.picker.WallpaperPickerDelegate.PREVIEW_LIVE_WALLPAPER_REQUEST_CODE
+import com.android.wallpaper.picker.WallpaperPickerDelegate.VIEW_ONLY_PREVIEW_WALLPAPER_REQUEST_CODE
 import com.android.wallpaper.picker.category.ui.binder.CategoriesBinder
 import com.android.wallpaper.picker.category.ui.view.providers.IndividualPickerFactory
 import com.android.wallpaper.picker.category.ui.viewmodel.CategoriesViewModel
 import com.android.wallpaper.picker.common.preview.data.repository.PersistentWallpaperModelRepository
+import com.android.wallpaper.picker.data.WallpaperModel
 import com.android.wallpaper.picker.preview.ui.WallpaperPreviewActivity
 import com.android.wallpaper.util.ActivityUtils
 import com.android.wallpaper.util.SizeCalculator
+import com.android.wallpaper.util.converter.WallpaperModelFactory
 import com.google.android.material.snackbar.Snackbar
 import dagger.hilt.android.AndroidEntryPoint
 import javax.inject.Inject
@@ -55,10 +60,32 @@ class CategoriesFragment : Hilt_CategoriesFragment() {
     @Inject lateinit var individualPickerFactory: IndividualPickerFactory
     @Inject lateinit var persistentWallpaperModelRepository: PersistentWallpaperModelRepository
     @Inject lateinit var multiPanesChecker: MultiPanesChecker
+    @Inject lateinit var myPhotosStarterImpl: MyPhotosStarterImpl
+    @Inject lateinit var wallpaperModelFactory: WallpaperModelFactory
+
+    private lateinit var photoPickerLauncher: ActivityResultLauncher<Intent>
 
     // TODO: this may need to be scoped to fragment if the architecture changes
     private val categoriesViewModel by activityViewModels<CategoriesViewModel>()
 
+    override fun onCreate(savedInstanceState: Bundle?) {
+        super.onCreate(savedInstanceState)
+        photoPickerLauncher =
+            registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
+                if (result.resultCode != Activity.RESULT_OK) {
+                    return@registerForActivityResult
+                }
+
+                val data: Intent? = result.data
+                val imageUri: Uri = data?.data ?: return@registerForActivityResult
+                val imageWallpaperInfo = ImageWallpaperInfo(imageUri)
+                val context = context ?: return@registerForActivityResult
+                val wallpaperModel =
+                    wallpaperModelFactory.getWallpaperModel(context, imageWallpaperInfo)
+                startWallpaperPreviewActivity(wallpaperModel, false)
+            }
+    }
+
     override fun onCreateView(
         inflater: LayoutInflater,
         container: ViewGroup?,
@@ -67,10 +94,8 @@ class CategoriesFragment : Hilt_CategoriesFragment() {
         val view =
             inflater.inflate(R.layout.categories_fragment, container, /* attachToRoot= */ false)
 
-        getCategorySelectorFragmentHost()?.let { fragmentHost ->
-            setUpToolbar(view)
-            setTitle(getText(R.string.wallpaper_title))
-        }
+        setUpToolbar(view)
+        setTitle(getText(R.string.wallpaper_title))
 
         CategoriesBinder.bind(
             categoriesPage = view.requireViewById<RecyclerView>(R.id.content_parent),
@@ -87,22 +112,23 @@ class CategoriesFragment : Hilt_CategoriesFragment() {
                         )
                     )
                 }
-                CategoriesViewModel.NavigationEvent.NavigateToPhotosPicker -> {
+                is CategoriesViewModel.NavigationEvent.NavigateToPhotosPicker -> {
                     // make call to permission handler to grab photos and pass callback
-                    getCategorySelectorFragmentHost()
-                        ?.requestCustomPhotoPicker(
-                            object : PermissionChangedListener {
-                                override fun onPermissionsGranted() {
-                                    callback?.invoke()
-                                }
+                    myPhotosStarterImpl.requestCustomPhotoPicker(
+                        object : PermissionChangedListener {
+                            override fun onPermissionsGranted() {
+                                callback?.invoke()
+                            }
 
-                                override fun onPermissionsDenied(dontAskAgain: Boolean) {
-                                    if (dontAskAgain) {
-                                        showPermissionSnackbar()
-                                    }
+                            override fun onPermissionsDenied(dontAskAgain: Boolean) {
+                                if (dontAskAgain) {
+                                    showPermissionSnackbar()
                                 }
                             }
-                        )
+                        },
+                        requireActivity(),
+                        photoPickerLauncher,
+                    )
                 }
                 is CategoriesViewModel.NavigationEvent.NavigateToThirdParty -> {
                     startThirdPartyCategoryActivity(
@@ -112,25 +138,10 @@ class CategoriesFragment : Hilt_CategoriesFragment() {
                     )
                 }
                 is CategoriesViewModel.NavigationEvent.NavigateToPreviewScreen -> {
-                    val appContext = requireContext().applicationContext
-                    persistentWallpaperModelRepository.setWallpaperModel(
-                        navigationEvent.wallpaperModel
-                    )
-                    val isMultiPanel = multiPanesChecker.isMultiPanesEnabled(appContext)
-                    val previewIntent =
-                        WallpaperPreviewActivity.newIntent(
-                            context = appContext,
-                            isAssetIdPresent = true,
-                            isViewAsHome = true,
-                            isNewTask = isMultiPanel,
-                            shouldCategoryRefresh =
-                                (navigationEvent.categoryType ==
-                                    CategoriesViewModel.CategoryType.CreativeCategories),
-                        )
-                    ActivityUtils.startActivityForResultSafely(
-                        requireActivity(),
-                        previewIntent,
-                        PREVIEW_LIVE_WALLPAPER_REQUEST_CODE, // TODO: provide correct request code
+                    startWallpaperPreviewActivity(
+                        navigationEvent.wallpaperModel,
+                        navigationEvent.categoryType ==
+                            CategoriesViewModel.CategoryType.CreativeCategories,
                     )
                 }
             }
@@ -138,9 +149,27 @@ class CategoriesFragment : Hilt_CategoriesFragment() {
         return view
     }
 
-    private fun getCategorySelectorFragmentHost(): CategorySelectorFragmentHost? {
-        return parentFragment as CategorySelectorFragmentHost?
-            ?: activity as CategorySelectorFragmentHost?
+    private fun startWallpaperPreviewActivity(
+        wallpaperModel: WallpaperModel,
+        isCreativeCategories: Boolean,
+    ) {
+        val appContext = requireContext()
+        val activity = requireActivity()
+        persistentWallpaperModelRepository.setWallpaperModel(wallpaperModel)
+        val isMultiPanel = multiPanesChecker.isMultiPanesEnabled(appContext)
+        val previewIntent =
+            WallpaperPreviewActivity.newIntent(
+                context = appContext,
+                isAssetIdPresent = true,
+                isViewAsHome = true,
+                isNewTask = isMultiPanel,
+                shouldCategoryRefresh = isCreativeCategories,
+            )
+        ActivityUtils.startActivityForResultSafely(
+            activity,
+            previewIntent,
+            VIEW_ONLY_PREVIEW_WALLPAPER_REQUEST_CODE, // TODO: provide correct request code
+        )
     }
 
     private fun showPermissionSnackbar() {
@@ -197,5 +226,6 @@ class CategoriesFragment : Hilt_CategoriesFragment() {
     companion object {
         const val SHOW_CATEGORY_REQUEST_CODE = 0
         const val SETTINGS_APP_INFO_REQUEST_CODE = 1
+        const val READ_IMAGE_PERMISSION: String = Manifest.permission.READ_MEDIA_IMAGES
     }
 }
diff --git a/src/com/android/wallpaper/picker/category/ui/view/MyPhotosStarterImpl.kt b/src/com/android/wallpaper/picker/category/ui/view/MyPhotosStarterImpl.kt
new file mode 100644
index 00000000..4391de8e
--- /dev/null
+++ b/src/com/android/wallpaper/picker/category/ui/view/MyPhotosStarterImpl.kt
@@ -0,0 +1,122 @@
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
+import android.Manifest
+import android.app.Activity
+import android.content.ActivityNotFoundException
+import android.content.Intent
+import android.content.pm.PackageManager
+import android.util.Log
+import androidx.activity.result.ActivityResultLauncher
+import com.android.wallpaper.module.InjectorProvider
+import com.android.wallpaper.picker.MyPhotosStarter
+import com.android.wallpaper.picker.MyPhotosStarter.PermissionChangedListener
+import com.android.wallpaper.picker.WallpaperPickerDelegate
+import com.android.wallpaper.picker.category.ui.view.CategoriesFragment.Companion.READ_IMAGE_PERMISSION
+import javax.inject.Inject
+import javax.inject.Singleton
+
+/**
+ * This class handles all the operations related to photo picker and MyPhotos tile in the category
+ * page.
+ */
+@Singleton
+class MyPhotosStarterImpl @Inject constructor() : MyPhotosStarter {
+
+    private val permissionChangedListeners: MutableList<PermissionChangedListener> = mutableListOf()
+
+    override fun requestCustomPhotoPicker(
+        listener: PermissionChangedListener,
+        activity: Activity,
+        photoPickerLauncher: ActivityResultLauncher<Intent>,
+    ) {
+        // TODO (b/282073506): Figure out a better way to have better photos experience
+        if (!isReadExternalStoragePermissionGranted(activity)) {
+            val wrappedListener: PermissionChangedListener =
+                object : PermissionChangedListener {
+                    override fun onPermissionsGranted() {
+                        listener.onPermissionsGranted()
+                        showCustomPhotoPicker(photoPickerLauncher)
+                    }
+
+                    override fun onPermissionsDenied(dontAskAgain: Boolean) {
+                        listener.onPermissionsDenied(dontAskAgain)
+                    }
+                }
+            requestExternalStoragePermission(wrappedListener, activity)
+            return
+        }
+
+        showCustomPhotoPicker(photoPickerLauncher)
+    }
+
+    private fun isReadExternalStoragePermissionGranted(activity: Activity): Boolean {
+        return activity.packageManager.checkPermission(
+            Manifest.permission.READ_MEDIA_IMAGES,
+            activity.packageName,
+        ) == PackageManager.PERMISSION_GRANTED
+    }
+
+    private fun requestExternalStoragePermission(
+        listener: PermissionChangedListener?,
+        activity: Activity,
+    ) {
+        if (listener != null) {
+            permissionChangedListeners.add(listener)
+        }
+        activity.requestPermissions(
+            arrayOf<String>(READ_IMAGE_PERMISSION),
+            WallpaperPickerDelegate.READ_EXTERNAL_STORAGE_PERMISSION_REQUEST_CODE,
+        )
+    }
+
+    private fun showCustomPhotoPicker(photoPickerLauncher: ActivityResultLauncher<Intent>) {
+        val injector = InjectorProvider.getInjector()
+        try {
+            val intent: Intent = injector.getMyPhotosIntentProvider().getMyPhotosIntent()
+            photoPickerLauncher.launch(intent)
+        } catch (e: ActivityNotFoundException) {
+            val fallback: Intent? = injector.getMyPhotosIntentProvider().fallbackIntent
+            if (fallback != null) {
+                Log.i(TAG, "Couldn't launch photo picker with main intent, trying with fallback")
+                photoPickerLauncher.launch(fallback)
+            } else {
+                Log.e(
+                    TAG,
+                    "Couldn't launch photo picker with main intent and no fallback is " +
+                        "available",
+                )
+                throw e
+            }
+        }
+    }
+
+    /**
+     * This method is not implemented on purpose since the other method that allows specifying a
+     * custom activity is already implemented which achieves the main purpose of requesting the
+     * photo picker. This method is only added for backward compatibility purposes so we can
+     * continue to use the same interface as earlier.
+     */
+    override fun requestCustomPhotoPicker(listener: PermissionChangedListener?) {
+        TODO("Not yet implemented")
+    }
+
+    companion object {
+        private const val TAG = "WallpaperPickerDelegate2"
+    }
+}
diff --git a/src/com/android/wallpaper/picker/category/ui/viewmodel/CategoriesViewModel.kt b/src/com/android/wallpaper/picker/category/ui/viewmodel/CategoriesViewModel.kt
index 2f20bfe9..2411f8dc 100644
--- a/src/com/android/wallpaper/picker/category/ui/viewmodel/CategoriesViewModel.kt
+++ b/src/com/android/wallpaper/picker/category/ui/viewmodel/CategoriesViewModel.kt
@@ -17,10 +17,14 @@
 package com.android.wallpaper.picker.category.ui.viewmodel
 
 import android.content.Context
+import android.content.Intent
 import android.content.pm.ResolveInfo
+import android.service.wallpaper.WallpaperService
 import androidx.lifecycle.ViewModel
 import androidx.lifecycle.viewModelScope
 import com.android.wallpaper.R
+import com.android.wallpaper.module.PackageStatusNotifier
+import com.android.wallpaper.module.PackageStatusNotifier.PackageStatus
 import com.android.wallpaper.picker.category.domain.interactor.CategoriesLoadingStatusInteractor
 import com.android.wallpaper.picker.category.domain.interactor.CategoryInteractor
 import com.android.wallpaper.picker.category.domain.interactor.CreativeCategoryInteractor
@@ -52,12 +56,57 @@ constructor(
     private val thirdPartyCategoryInteractor: ThirdPartyCategoryInteractor,
     private val loadindStatusInteractor: CategoriesLoadingStatusInteractor,
     private val networkStatusInteractor: NetworkStatusInteractor,
+    private val packageStatusNotifier: PackageStatusNotifier,
     @ApplicationContext private val context: Context,
 ) : ViewModel() {
 
     private val _navigationEvents = MutableSharedFlow<NavigationEvent>()
     val navigationEvents = _navigationEvents.asSharedFlow()
 
+    init {
+        registerLiveWallpaperReceiver()
+        registerThirdPartyWallpaperCategories()
+    }
+
+    // TODO: b/379138560: Add tests for this method and method below
+    private fun registerLiveWallpaperReceiver() {
+        packageStatusNotifier.addListener(
+            { packageName, status ->
+                if (packageName != null) {
+                    updateLiveWallpapersCategories(packageName, status)
+                }
+            },
+            WallpaperService.SERVICE_INTERFACE,
+        )
+    }
+
+    private fun registerThirdPartyWallpaperCategories() {
+        packageStatusNotifier.addListener(
+            { packageName, status ->
+                if (packageName != null) {
+                    updateThirdPartyAppCategories(packageName, status)
+                }
+            },
+            Intent.ACTION_SET_WALLPAPER,
+        )
+    }
+
+    private fun updateLiveWallpapersCategories(packageName: String, @PackageStatus status: Int) {
+        refreshThirdPartyLiveWallpaperCategories()
+    }
+
+    private fun updateThirdPartyAppCategories(packageName: String, @PackageStatus status: Int) {
+        refreshThirdPartyCategories()
+    }
+
+    private fun refreshThirdPartyLiveWallpaperCategories() {
+        singleCategoryInteractor.refreshThirdPartyLiveWallpaperCategories()
+    }
+
+    private fun refreshThirdPartyCategories() {
+        thirdPartyCategoryInteractor.refreshThirdPartyAppCategories()
+    }
+
     private fun navigateToWallpaperCollection(collectionId: String, categoryType: CategoryType) {
         viewModelScope.launch {
             _navigationEvents.emit(
@@ -68,7 +117,7 @@ constructor(
 
     private fun navigateToPreviewScreen(
         wallpaperModel: WallpaperModel,
-        categoryType: CategoryType
+        categoryType: CategoryType,
     ) {
         viewModelScope.launch {
             _navigationEvents.emit(
@@ -77,8 +126,10 @@ constructor(
         }
     }
 
-    private fun navigateToPhotosPicker() {
-        viewModelScope.launch { _navigationEvents.emit(NavigationEvent.NavigateToPhotosPicker) }
+    private fun navigateToPhotosPicker(wallpaperModel: WallpaperModel?) {
+        viewModelScope.launch {
+            _navigationEvents.emit(NavigationEvent.NavigateToPhotosPicker(wallpaperModel))
+        }
     }
 
     private fun navigateToThirdPartyApp(resolveInfo: ResolveInfo) {
@@ -96,6 +147,10 @@ constructor(
             }
         }
 
+    /**
+     * This section is only for third party category apps, and not third party live wallpaper
+     * category apps which are handled as part of default category sections.
+     */
     private val thirdPartyCategorySections: Flow<List<SectionViewModel>> =
         thirdPartyCategoryInteractor.categories
             .distinctUntilChanged { old, new -> categoryModelListDifferentiator(old, new) }
@@ -104,14 +159,19 @@ constructor(
                     SectionViewModel(
                         tileViewModels =
                             listOf(
-                                TileViewModel(null, null, category.commonCategoryData.title) {
+                                TileViewModel(
+                                    /* defaultDrawable = */ category.thirdPartyCategoryData
+                                        ?.defaultDrawable,
+                                    /* thumbnailAsset = */ null,
+                                    /* text = */ category.commonCategoryData.title,
+                                ) {
                                     category.thirdPartyCategoryData?.resolveInfo?.let {
                                         navigateToThirdPartyApp(it)
                                     }
                                 }
                             ),
                         columnCount = 1,
-                        sectionTitle = null
+                        sectionTitle = null,
                     )
                 }
             }
@@ -135,18 +195,18 @@ constructor(
                                     ) {
                                         navigateToPreviewScreen(
                                             category.collectionCategoryData.wallpaperModels[0],
-                                            CategoryType.DefaultCategories
+                                            CategoryType.DefaultCategories,
                                         )
                                     } else {
                                         navigateToWallpaperCollection(
                                             category.commonCategoryData.collectionId,
-                                            CategoryType.DefaultCategories
+                                            CategoryType.DefaultCategories,
                                         )
                                     }
                                 }
                             ),
                         columnCount = 1,
-                        sectionTitle = null
+                        sectionTitle = null,
                     )
                 }
             }
@@ -173,12 +233,12 @@ constructor(
                             ) {
                                 navigateToPreviewScreen(
                                     category.collectionCategoryData.wallpaperModels[0],
-                                    CategoryType.CreativeCategories
+                                    CategoryType.CreativeCategories,
                                 )
                             } else {
                                 navigateToWallpaperCollection(
                                     category.commonCategoryData.collectionId,
-                                    CategoryType.CreativeCategories
+                                    CategoryType.CreativeCategories,
                                 )
                             }
                         }
@@ -186,7 +246,7 @@ constructor(
                 return@map SectionViewModel(
                     tileViewModels = tiles,
                     columnCount = 3,
-                    sectionTitle = context.getString(R.string.creative_wallpaper_title)
+                    sectionTitle = context.getString(R.string.creative_wallpaper_title),
                 )
             }
 
@@ -202,11 +262,11 @@ constructor(
                             maxCategoriesInRow = SectionCardinality.Single,
                         ) {
                             // TODO(b/352081782): trigger the effect with effect controller
-                            navigateToPhotosPicker()
+                            navigateToPhotosPicker(null)
                         }
                     ),
                 columnCount = 3,
-                sectionTitle = context.getString(R.string.choose_a_wallpaper_section_title)
+                sectionTitle = context.getString(R.string.choose_a_wallpaper_section_title),
             )
         }
 
@@ -248,21 +308,21 @@ constructor(
         DefaultCategories,
         CreativeCategories,
         MyPhotosCategories,
-        Default
+        Default,
     }
 
     sealed class NavigationEvent {
         data class NavigateToWallpaperCollection(
             val categoryId: String,
-            val categoryType: CategoryType
+            val categoryType: CategoryType,
         ) : NavigationEvent()
 
         data class NavigateToPreviewScreen(
             val wallpaperModel: WallpaperModel,
-            val categoryType: CategoryType
+            val categoryType: CategoryType,
         ) : NavigationEvent()
 
-        object NavigateToPhotosPicker : NavigationEvent()
+        data class NavigateToPhotosPicker(val wallpaperModel: WallpaperModel?) : NavigationEvent()
 
         data class NavigateToThirdParty(val resolveInfo: ResolveInfo) : NavigationEvent()
     }
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/binder/BasePreviewBinder.kt b/src/com/android/wallpaper/picker/common/preview/ui/binder/BasePreviewBinder.kt
index 2c85af87..51e8f5c5 100644
--- a/src/com/android/wallpaper/picker/common/preview/ui/binder/BasePreviewBinder.kt
+++ b/src/com/android/wallpaper/picker/common/preview/ui/binder/BasePreviewBinder.kt
@@ -19,13 +19,24 @@ package com.android.wallpaper.picker.common.preview.ui.binder
 import android.content.Context
 import android.graphics.Point
 import android.view.View
+import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import com.android.customization.picker.clock.ui.view.ClockViewFactory
 import com.android.wallpaper.R
 import com.android.wallpaper.model.Screen
+import com.android.wallpaper.model.Screen.HOME_SCREEN
 import com.android.wallpaper.model.wallpaper.DeviceDisplayType
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2
+import com.android.wallpaper.picker.data.WallpaperModel
 import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.launch
 
 /**
  * Common base preview binder that is only responsible for binding the workspace and wallpaper, and
@@ -40,17 +51,37 @@ object BasePreviewBinder {
         applicationContext: Context,
         view: View,
         viewModel: CustomizationPickerViewModel2,
+        colorUpdateViewModel: ColorUpdateViewModel,
         workspaceCallbackBinder: WorkspaceCallbackBinder,
         screen: Screen,
         deviceDisplayType: DeviceDisplayType,
         displaySize: Point,
+        mainScope: CoroutineScope,
         lifecycleOwner: LifecycleOwner,
         wallpaperConnectionUtils: WallpaperConnectionUtils,
         isFirstBindingDeferred: CompletableDeferred<Boolean>,
-        onClick: (() -> Unit)? = null,
+        onLaunchPreview: ((WallpaperModel) -> Unit)? = null,
+        clockViewFactory: ClockViewFactory,
     ) {
-        view.isClickable = (onClick != null)
-        onClick?.let { view.setOnClickListener { it() } }
+        if (onLaunchPreview != null) {
+            lifecycleOwner.lifecycleScope.launch {
+                lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                    launch { viewModel.isPreviewClickable.collect { view.isClickable = it } }
+
+                    launch {
+                        viewModel.basePreviewViewModel.wallpapers
+                            .filterNotNull()
+                            .map {
+                                if (screen == HOME_SCREEN) it.homeWallpaper
+                                else it.lockWallpaper ?: it.homeWallpaper
+                            }
+                            .collect { wallpaper ->
+                                view.setOnClickListener { onLaunchPreview.invoke(wallpaper) }
+                            }
+                    }
+                }
+            }
+        }
 
         WallpaperPreviewBinder.bind(
             applicationContext = applicationContext,
@@ -59,6 +90,7 @@ object BasePreviewBinder {
             screen = screen,
             displaySize = displaySize,
             deviceDisplayType = deviceDisplayType,
+            mainScope = mainScope,
             viewLifecycleOwner = lifecycleOwner,
             wallpaperConnectionUtils = wallpaperConnectionUtils,
             isFirstBindingDeferred = isFirstBindingDeferred,
@@ -67,10 +99,12 @@ object BasePreviewBinder {
         WorkspacePreviewBinder.bind(
             surfaceView = view.requireViewById(R.id.workspace_surface),
             viewModel = viewModel,
+            colorUpdateViewModel = colorUpdateViewModel,
             workspaceCallbackBinder = workspaceCallbackBinder,
             screen = screen,
             deviceDisplayType = deviceDisplayType,
             lifecycleOwner = lifecycleOwner,
+            clockViewFactory = clockViewFactory,
         )
     }
 }
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/binder/DefaultWorkspaceCallbackBinder.kt b/src/com/android/wallpaper/picker/common/preview/ui/binder/DefaultWorkspaceCallbackBinder.kt
index 2378194a..88e64cf7 100644
--- a/src/com/android/wallpaper/picker/common/preview/ui/binder/DefaultWorkspaceCallbackBinder.kt
+++ b/src/com/android/wallpaper/picker/common/preview/ui/binder/DefaultWorkspaceCallbackBinder.kt
@@ -18,7 +18,9 @@ package com.android.wallpaper.picker.common.preview.ui.binder
 
 import android.os.Message
 import androidx.lifecycle.LifecycleOwner
+import com.android.customization.picker.clock.ui.view.ClockViewFactory
 import com.android.wallpaper.model.Screen
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
 import javax.inject.Inject
 import javax.inject.Singleton
@@ -29,8 +31,10 @@ class DefaultWorkspaceCallbackBinder @Inject constructor() : WorkspaceCallbackBi
     override fun bind(
         workspaceCallback: Message,
         viewModel: CustomizationOptionsViewModel,
+        colorUpdateViewModel: ColorUpdateViewModel,
         screen: Screen,
         lifecycleOwner: LifecycleOwner,
+        clockViewFactory: ClockViewFactory,
     ) {}
 
     companion object {
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/binder/WallpaperPreviewBinder.kt b/src/com/android/wallpaper/picker/common/preview/ui/binder/WallpaperPreviewBinder.kt
index b2dd6248..6571da44 100644
--- a/src/com/android/wallpaper/picker/common/preview/ui/binder/WallpaperPreviewBinder.kt
+++ b/src/com/android/wallpaper/picker/common/preview/ui/binder/WallpaperPreviewBinder.kt
@@ -38,6 +38,7 @@ import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils.Companion.shouldEnforceSingleEngine
 import com.android.wallpaper.util.wallpaperconnection.WallpaperEngineConnection
 import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.Job
 import kotlinx.coroutines.launch
 
@@ -59,6 +60,7 @@ object WallpaperPreviewBinder {
         screen: Screen,
         displaySize: Point,
         deviceDisplayType: DeviceDisplayType,
+        mainScope: CoroutineScope,
         viewLifecycleOwner: LifecycleOwner,
         wallpaperConnectionUtils: WallpaperConnectionUtils,
         isFirstBindingDeferred: CompletableDeferred<Boolean>,
@@ -74,6 +76,7 @@ object WallpaperPreviewBinder {
                         screen = screen,
                         deviceDisplayType = deviceDisplayType,
                         displaySize = displaySize,
+                        mainScope = mainScope,
                         lifecycleOwner = viewLifecycleOwner,
                         wallpaperConnectionUtils = wallpaperConnectionUtils,
                         isFirstBindingDeferred = isFirstBindingDeferred,
@@ -101,6 +104,7 @@ object WallpaperPreviewBinder {
         screen: Screen,
         deviceDisplayType: DeviceDisplayType,
         displaySize: Point,
+        mainScope: CoroutineScope,
         lifecycleOwner: LifecycleOwner,
         wallpaperConnectionUtils: WallpaperConnectionUtils,
         isFirstBindingDeferred: CompletableDeferred<Boolean>,
@@ -112,7 +116,8 @@ object WallpaperPreviewBinder {
 
             override fun surfaceCreated(holder: SurfaceHolder) {
                 job =
-                    lifecycleOwner.lifecycleScope.launch {
+                    // Ensure the wallpaper connection is connected / disconnected in [mainScope].
+                    mainScope.launch {
                         viewModel.wallpapersAndWhichPreview.collect { (wallpapers, whichPreview) ->
                             val wallpaper =
                                 if (screen == Screen.HOME_SCREEN) wallpapers.homeWallpaper
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/binder/WorkspaceCallbackBinder.kt b/src/com/android/wallpaper/picker/common/preview/ui/binder/WorkspaceCallbackBinder.kt
index 4a611239..18d6ef10 100644
--- a/src/com/android/wallpaper/picker/common/preview/ui/binder/WorkspaceCallbackBinder.kt
+++ b/src/com/android/wallpaper/picker/common/preview/ui/binder/WorkspaceCallbackBinder.kt
@@ -19,7 +19,9 @@ package com.android.wallpaper.picker.common.preview.ui.binder
 import android.os.Bundle
 import android.os.Message
 import androidx.lifecycle.LifecycleOwner
+import com.android.customization.picker.clock.ui.view.ClockViewFactory
 import com.android.wallpaper.model.Screen
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
 
 /**
@@ -31,15 +33,14 @@ interface WorkspaceCallbackBinder {
     fun bind(
         workspaceCallback: Message,
         viewModel: CustomizationOptionsViewModel,
+        colorUpdateViewModel: ColorUpdateViewModel,
         screen: Screen,
         lifecycleOwner: LifecycleOwner,
+        clockViewFactory: ClockViewFactory,
     )
 
     companion object {
-        fun Message.sendMessage(
-            what: Int,
-            data: Bundle,
-        ) {
+        fun Message.sendMessage(what: Int, data: Bundle) {
             this.replyTo.send(
                 Message().apply {
                     this.what = what
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/binder/WorkspacePreviewBinder.kt b/src/com/android/wallpaper/picker/common/preview/ui/binder/WorkspacePreviewBinder.kt
index 7965c7fc..832cdfef 100644
--- a/src/com/android/wallpaper/picker/common/preview/ui/binder/WorkspacePreviewBinder.kt
+++ b/src/com/android/wallpaper/picker/common/preview/ui/binder/WorkspacePreviewBinder.kt
@@ -26,6 +26,7 @@ import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
+import com.android.customization.picker.clock.ui.view.ClockViewFactory
 import com.android.systemui.shared.clocks.shared.model.ClockPreviewConstants
 import com.android.systemui.shared.keyguard.shared.model.KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START
 import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.KEY_HIGHLIGHT_QUICK_AFFORDANCES
@@ -33,6 +34,7 @@ import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewC
 import com.android.wallpaper.model.Screen
 import com.android.wallpaper.model.wallpaper.DeviceDisplayType
 import com.android.wallpaper.picker.common.preview.ui.viewmodel.BasePreviewViewModel
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2
 import com.android.wallpaper.util.PreviewUtils
 import com.android.wallpaper.util.SurfaceViewUtils
@@ -48,10 +50,12 @@ object WorkspacePreviewBinder {
     fun bind(
         surfaceView: SurfaceView,
         viewModel: CustomizationPickerViewModel2,
+        colorUpdateViewModel: ColorUpdateViewModel,
         workspaceCallbackBinder: WorkspaceCallbackBinder,
         screen: Screen,
         deviceDisplayType: DeviceDisplayType,
         lifecycleOwner: LifecycleOwner,
+        clockViewFactory: ClockViewFactory,
     ) {
         var surfaceCallback: SurfaceViewUtils.SurfaceCallback? = null
         lifecycleOwner.lifecycleScope.launch {
@@ -60,11 +64,13 @@ object WorkspacePreviewBinder {
                     bindSurface(
                         surfaceView = surfaceView,
                         viewModel = viewModel,
+                        colorUpdateViewModel = colorUpdateViewModel,
                         workspaceCallbackBinder = workspaceCallbackBinder,
                         screen = screen,
                         previewUtils = getPreviewUtils(screen, viewModel.basePreviewViewModel),
                         deviceDisplayType = deviceDisplayType,
                         lifecycleOwner = lifecycleOwner,
+                        clockViewFactory = clockViewFactory,
                     )
                 surfaceView.setZOrderMediaOverlay(true)
                 surfaceView.holder.addCallback(surfaceCallback)
@@ -85,11 +91,13 @@ object WorkspacePreviewBinder {
     private fun bindSurface(
         surfaceView: SurfaceView,
         viewModel: CustomizationPickerViewModel2,
+        colorUpdateViewModel: ColorUpdateViewModel,
         workspaceCallbackBinder: WorkspaceCallbackBinder,
         screen: Screen,
         previewUtils: PreviewUtils,
         deviceDisplayType: DeviceDisplayType,
         lifecycleOwner: LifecycleOwner,
+        clockViewFactory: ClockViewFactory,
     ): SurfaceViewUtils.SurfaceCallback {
         return object : SurfaceViewUtils.SurfaceCallback {
 
@@ -110,8 +118,10 @@ object WorkspacePreviewBinder {
                                 workspaceCallbackBinder.bind(
                                     workspaceCallback = workspaceCallback,
                                     viewModel = viewModel.customizationOptionsViewModel,
+                                    colorUpdateViewModel = colorUpdateViewModel,
                                     screen = screen,
                                     lifecycleOwner = lifecycleOwner,
+                                    clockViewFactory = clockViewFactory,
                                 )
                             }
                     }
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/view/CustomizationSurfaceView.kt b/src/com/android/wallpaper/picker/common/preview/ui/view/CustomizationSurfaceView.kt
index 7b19c631..c1e240ba 100644
--- a/src/com/android/wallpaper/picker/common/preview/ui/view/CustomizationSurfaceView.kt
+++ b/src/com/android/wallpaper/picker/common/preview/ui/view/CustomizationSurfaceView.kt
@@ -28,30 +28,16 @@ import android.view.SurfaceView
  */
 class CustomizationSurfaceView(context: Context, attrs: AttributeSet? = null) :
     SurfaceView(context, attrs) {
-    private var isTransitioning = false
 
     override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
         super.onSizeChanged(w, h, oldw, oldh)
 
         // TODO (b/348462236): investigate effect on scale transition and touch forwarding layout
         if (oldw == 0 && oldh == 0) {
-            // If the view doesn't have a fixed width and height, after the transition the oldw and
-            // oldh will be 0, don't set new size in this case as it will interfere with the
-            // transition. Set the flag back to false once the transition is completed.
-            if (isTransitioning) {
-                isTransitioning = false
-            } else {
-                holder.setFixedSize(w, h)
+            holder.surfaceFrame.let {
+                if (it.isEmpty) holder.setFixedSize(width, height)
+                else holder.setFixedSize(it.width(), it.height())
             }
         }
     }
-
-    /**
-     * Indicates the view is transitioning.
-     *
-     * Needed when using WRAP_CONTENT or 0dp for height or weight together with [MotionLayout]
-     */
-    fun setTransitioning() {
-        this.isTransitioning = true
-    }
 }
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/BasePreviewViewModel.kt b/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/BasePreviewViewModel.kt
index 3df5eb92..3d79bbf9 100644
--- a/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/BasePreviewViewModel.kt
+++ b/src/com/android/wallpaper/picker/common/preview/ui/viewmodel/BasePreviewViewModel.kt
@@ -83,7 +83,7 @@ constructor(
         interactor.wallpapers.stateIn(
             scope = viewModelScope,
             started = SharingStarted.WhileSubscribed(),
-            initialValue = null
+            initialValue = null,
         )
 
     val wallpapersAndWhichPreview:
diff --git a/src/com/android/wallpaper/picker/customization/data/content/WallpaperClient.kt b/src/com/android/wallpaper/picker/customization/data/content/WallpaperClient.kt
index 02819208..387a0b75 100644
--- a/src/com/android/wallpaper/picker/customization/data/content/WallpaperClient.kt
+++ b/src/com/android/wallpaper/picker/customization/data/content/WallpaperClient.kt
@@ -37,10 +37,7 @@ import kotlinx.coroutines.flow.Flow
 interface WallpaperClient {
 
     /** Lists the most recent wallpapers. The first one is the most recent (current) wallpaper. */
-    fun recentWallpapers(
-        destination: WallpaperDestination,
-        limit: Int,
-    ): Flow<List<WallpaperModel>>
+    fun recentWallpapers(destination: WallpaperDestination, limit: Int): Flow<List<WallpaperModel>>
 
     /**
      * Asynchronously sets a static wallpaper.
@@ -101,7 +98,7 @@ interface WallpaperClient {
 
     fun getCurrentCropHints(
         displaySizes: List<Point>,
-        @WallpaperManager.SetWallpaperFlags which: Int
+        @WallpaperManager.SetWallpaperFlags which: Int,
     ): Map<Point, Rect>?
 
     /** Returns the wallpaper colors for preview a bitmap with a set of crop hints */
diff --git a/src/com/android/wallpaper/picker/customization/data/content/WallpaperClientImpl.kt b/src/com/android/wallpaper/picker/customization/data/content/WallpaperClientImpl.kt
index 47a9d262..e7403d77 100644
--- a/src/com/android/wallpaper/picker/customization/data/content/WallpaperClientImpl.kt
+++ b/src/com/android/wallpaper/picker/customization/data/content/WallpaperClientImpl.kt
@@ -17,11 +17,13 @@
 
 package com.android.wallpaper.picker.customization.data.content
 
+import android.app.Flags.liveWallpaperContentHandling
 import android.app.WallpaperColors
 import android.app.WallpaperManager
 import android.app.WallpaperManager.FLAG_LOCK
 import android.app.WallpaperManager.FLAG_SYSTEM
 import android.app.WallpaperManager.SetWallpaperFlags
+import android.app.wallpaper.WallpaperDescription
 import android.content.ComponentName
 import android.content.ContentResolver
 import android.content.ContentValues
@@ -40,8 +42,6 @@ import com.android.wallpaper.asset.Asset
 import com.android.wallpaper.asset.BitmapUtils
 import com.android.wallpaper.asset.CurrentWallpaperAsset
 import com.android.wallpaper.asset.StreamableAsset
-import com.android.wallpaper.model.CreativeCategory
-import com.android.wallpaper.model.CreativeWallpaperInfo
 import com.android.wallpaper.model.LiveWallpaperPrefMetadata
 import com.android.wallpaper.model.Screen
 import com.android.wallpaper.model.StaticWallpaperPrefMetadata
@@ -54,6 +54,7 @@ import com.android.wallpaper.module.logging.UserEventLogger.SetWallpaperEntryPoi
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination.BOTH
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination.Companion.toDestinationInt
+import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination.Companion.toSetWallpaperFlags
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination.HOME
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination.LOCK
 import com.android.wallpaper.picker.customization.shared.model.WallpaperModel as RecentWallpaperModel
@@ -63,8 +64,6 @@ import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import com.android.wallpaper.picker.preview.shared.model.FullPreviewCropModel
 import com.android.wallpaper.util.WallpaperCropUtils
 import com.android.wallpaper.util.converter.WallpaperModelFactory
-import com.android.wallpaper.util.converter.WallpaperModelFactory.Companion.getCommonWallpaperData
-import com.android.wallpaper.util.converter.WallpaperModelFactory.Companion.getCreativeWallpaperData
 import dagger.hilt.android.qualifiers.ApplicationContext
 import java.io.IOException
 import java.io.InputStream
@@ -119,10 +118,7 @@ constructor(
         }
     }
 
-    override fun recentWallpapers(
-        destination: WallpaperDestination,
-        limit: Int,
-    ) =
+    override fun recentWallpapers(destination: WallpaperDestination, limit: Int) =
         when (destination) {
             HOME -> recentHomeWallpapers.asStateFlow().filterNotNull().take(limit)
             LOCK -> recentLockWallpapers.asStateFlow().filterNotNull().take(limit)
@@ -174,9 +170,7 @@ constructor(
                 effects = null,
                 setWallpaperEntryPoint = setWallpaperEntryPoint,
                 destination =
-                    UserEventLogger.toWallpaperDestinationForLogging(
-                        destination.toDestinationInt()
-                    ),
+                    UserEventLogger.toWallpaperDestinationForLogging(destination.toDestinationInt()),
             )
 
             // Save the static wallpaper to recent wallpapers
@@ -216,14 +210,14 @@ constructor(
                 inputStream,
                 cropHints,
                 /* allowBackup= */ true,
-                destination.toFlags(),
+                destination.toSetWallpaperFlags(),
             )
         } else {
             setBitmapWithCrops(
                 bitmap,
                 cropHints,
                 /* allowBackup= */ true,
-                destination.toFlags(),
+                destination.toSetWallpaperFlags(),
             )
         }
     }
@@ -250,7 +244,7 @@ constructor(
      */
     private fun WallpaperPreferences.setStaticWallpaperMetadata(
         metadata: StaticWallpaperPrefMetadata,
-        destination: WallpaperDestination
+        destination: WallpaperDestination,
     ) {
         when (destination) {
             HOME -> {
@@ -284,16 +278,10 @@ constructor(
         }
 
         traceAsync(TAG, "setLiveWallpaper") {
-            val updatedWallpaperModel =
-                wallpaperModel.creativeWallpaperData?.let {
-                    saveCreativeWallpaperAtExternal(wallpaperModel, destination)
-                } ?: wallpaperModel
-
-            val managerId =
-                wallpaperManager.setLiveWallpaperToSystem(updatedWallpaperModel, destination)
+            val managerId = wallpaperManager.setLiveWallpaperToSystem(wallpaperModel, destination)
 
             wallpaperPreferences.setLiveWallpaperMetadata(
-                metadata = updatedWallpaperModel.getMetadata(managerId),
+                metadata = wallpaperModel.getMetadata(managerId),
                 destination = destination,
             )
 
@@ -303,56 +291,61 @@ constructor(
                 effects = wallpaperModel.liveWallpaperData.effectNames,
                 setWallpaperEntryPoint = setWallpaperEntryPoint,
                 destination =
-                    UserEventLogger.toWallpaperDestinationForLogging(
-                        destination.toDestinationInt()
-                    ),
+                    UserEventLogger.toWallpaperDestinationForLogging(destination.toDestinationInt()),
             )
 
-            wallpaperPreferences.addLiveWallpaperToRecentWallpapers(
-                destination,
-                updatedWallpaperModel
+            wallpaperPreferences.addLiveWallpaperToRecentWallpapers(destination, wallpaperModel)
+        }
+    }
+
+    private fun tryAndroidBSetComponent(
+        wallpaperModel: LiveWallpaperModel,
+        destination: WallpaperDestination,
+    ): Boolean {
+        try {
+            val method =
+                wallpaperManager.javaClass.getMethod(
+                    "setWallpaperComponentWithDescription",
+                    WallpaperDescription::class.java,
+                    Int::class.javaPrimitiveType,
+                )
+            method.invoke(
+                wallpaperManager,
+                wallpaperModel.liveWallpaperData.description,
+                destination.toSetWallpaperFlags(),
             )
+            return true
+        } catch (e: NoSuchMethodException) {
+            return false
         }
     }
 
-    /**
-     * Call the external app to save the creative wallpaper, and return an updated model based on
-     * the response.
-     */
-    private fun saveCreativeWallpaperAtExternal(
+    private fun tryAndroidUSetComponent(
         wallpaperModel: LiveWallpaperModel,
         destination: WallpaperDestination,
-    ): LiveWallpaperModel? {
-        wallpaperModel.getSaveWallpaperUriAndAuthority(destination)?.let { (uri, authority) ->
-            try {
-                context.contentResolver.acquireContentProviderClient(authority).use { client ->
-                    val cursor =
-                        client?.query(
-                            /* url= */ uri,
-                            /* projection= */ null,
-                            /* selection= */ null,
-                            /* selectionArgs= */ null,
-                            /* sortOrder= */ null,
-                        )
-                    if (cursor == null || !cursor.moveToFirst()) return null
-                    val info =
-                        CreativeWallpaperInfo.buildFromCursor(
-                            wallpaperModel.liveWallpaperData.systemWallpaperInfo,
-                            cursor
-                        )
-                    // NB: need to regenerate common data to update the thumbnail asset
-                    return LiveWallpaperModel(
-                        info.getCommonWallpaperData(context),
-                        wallpaperModel.liveWallpaperData,
-                        info.getCreativeWallpaperData(),
-                        wallpaperModel.internalLiveWallpaperData
-                    )
-                }
-            } catch (e: Exception) {
-                Log.e(TAG, "Failed updating creative live wallpaper at external.")
+    ): Boolean {
+        try {
+            val method =
+                wallpaperManager.javaClass.getMethod(
+                    "setWallpaperComponentWithFlags",
+                    ComponentName::class.java,
+                    Int::class.javaPrimitiveType,
+                )
+            method.invoke(
+                wallpaperManager,
+                wallpaperModel.commonWallpaperData.id.componentName,
+                destination.toSetWallpaperFlags(),
+            )
+            if (liveWallpaperContentHandling()) {
+                Log.w(
+                    TAG,
+                    "live wallpaper content handling enabled, but Android U setWallpaperComponentWithFlags called",
+                )
             }
+            return true
+        } catch (e: NoSuchMethodException) {
+            return false
         }
-        return null
     }
 
     /**
@@ -362,19 +355,14 @@ constructor(
      */
     private fun WallpaperManager.setLiveWallpaperToSystem(
         wallpaperModel: LiveWallpaperModel,
-        destination: WallpaperDestination
+        destination: WallpaperDestination,
     ): Int {
-        val componentName = wallpaperModel.commonWallpaperData.id.componentName
-        try {
-            // Probe if the function setWallpaperComponentWithFlags exists
-            javaClass.getMethod(
-                "setWallpaperComponentWithFlags",
-                ComponentName::class.java,
-                Int::class.javaPrimitiveType
-            )
-            setWallpaperComponentWithFlags(componentName, destination.toFlags())
-        } catch (e: NoSuchMethodException) {
-            setWallpaperComponent(componentName)
+        if (tryAndroidBSetComponent(wallpaperModel, destination)) {
+            // intentional no-op
+        } else if (tryAndroidUSetComponent(wallpaperModel, destination)) {
+            // intentional no-op
+        } else {
+            setWallpaperComponent(wallpaperModel.commonWallpaperData.id.componentName)
         }
 
         // Be careful that WallpaperManager.getWallpaperId can only accept either
@@ -402,7 +390,7 @@ constructor(
      */
     private fun WallpaperPreferences.setLiveWallpaperMetadata(
         metadata: LiveWallpaperPrefMetadata,
-        destination: WallpaperDestination
+        destination: WallpaperDestination,
     ) {
         when (destination) {
             HOME -> {
@@ -422,23 +410,6 @@ constructor(
         }
     }
 
-    /** Get the URI to call the external app to save the creative wallpaper. */
-    private fun LiveWallpaperModel.getSaveWallpaperUriAndAuthority(
-        destination: WallpaperDestination
-    ): Pair<Uri, String>? {
-        val uriString =
-            liveWallpaperData.systemWallpaperInfo.serviceInfo.metaData.getString(
-                CreativeCategory.KEY_WALLPAPER_SAVE_CREATIVE_CATEGORY_WALLPAPER
-            ) ?: return null
-        val uri =
-            Uri.parse(uriString)
-                ?.buildUpon()
-                ?.appendQueryParameter("destination", destination.toDestinationInt().toString())
-                ?.build() ?: return null
-        val authority = uri.authority ?: return null
-        return Pair(uri, authority)
-    }
-
     override suspend fun setRecentWallpaper(
         @SetWallpaperEntryPoint setWallpaperEntryPoint: Int,
         destination: WallpaperDestination,
@@ -518,12 +489,12 @@ constructor(
             } else {
                 currentWallpapers.first
             }
-        val colors = wallpaperManager.getWallpaperColors(destination.toFlags())
+        val colors = wallpaperManager.getWallpaperColors(destination.toSetWallpaperFlags())
 
         return RecentWallpaperModel(
             wallpaperId = wallpaper.wallpaperId,
             placeholderColor = colors?.primaryColor?.toArgb() ?: Color.TRANSPARENT,
-            title = wallpaper.getTitle(context)
+            title = wallpaper.getTitle(context),
         )
     }
 
@@ -531,10 +502,10 @@ constructor(
         suspendCancellableCoroutine { continuation ->
             InjectorProvider.getInjector()
                 .getCurrentWallpaperInfoFactory(context)
-                .createCurrentWallpaperInfos(
-                    context,
-                    /* forceRefresh= */ false,
-                ) { homeWallpaper, lockWallpaper, _ ->
+                .createCurrentWallpaperInfos(context, /* forceRefresh= */ false) {
+                    homeWallpaper,
+                    lockWallpaper,
+                    _ ->
                     continuation.resume(Pair(homeWallpaper, lockWallpaper), null)
                 }
         }
@@ -545,13 +516,13 @@ constructor(
         val lockWallpaper = currentWallpapers.second
         return WallpaperModelsPair(
             wallpaperModelFactory.getWallpaperModel(context, homeWallpaper),
-            lockWallpaper?.let { wallpaperModelFactory.getWallpaperModel(context, it) }
+            lockWallpaper?.let { wallpaperModelFactory.getWallpaperModel(context, it) },
         )
     }
 
     override suspend fun loadThumbnail(
         wallpaperId: String,
-        destination: WallpaperDestination
+        destination: WallpaperDestination,
     ): Bitmap? {
         if (areRecentsAvailable()) {
             try {
@@ -577,7 +548,7 @@ constructor(
                 Log.e(
                     TAG,
                     "Error getting wallpaper preview: $wallpaperId, destination: ${destination.asString()}",
-                    e
+                    e,
                 )
             }
         } else {
@@ -598,15 +569,12 @@ constructor(
         if (recentsContentProviderAvailable == null) {
             recentsContentProviderAvailable =
                 try {
-                    context.packageManager.resolveContentProvider(
-                        AUTHORITY,
-                        0,
-                    ) != null
+                    context.packageManager.resolveContentProvider(AUTHORITY, 0) != null
                 } catch (e: Exception) {
                     Log.w(
                         TAG,
                         "Exception trying to resolve recents content provider, skipping it",
-                        e
+                        e,
                     )
                     false
                 }
@@ -616,7 +584,7 @@ constructor(
 
     override fun getCurrentCropHints(
         displaySizes: List<Point>,
-        @SetWallpaperFlags which: Int
+        @SetWallpaperFlags which: Int,
     ): Map<Point, Rect>? {
         val flags = InjectorProvider.getInjector().getFlags()
         if (!flags.isMultiCropEnabled()) {
@@ -630,7 +598,7 @@ constructor(
 
     override suspend fun getWallpaperColors(
         bitmap: Bitmap,
-        cropHints: Map<Point, Rect>?
+        cropHints: Map<Point, Rect>?,
     ): WallpaperColors? {
         return wallpaperManager.getWallpaperColors(bitmap, cropHints)
     }
@@ -653,14 +621,6 @@ constructor(
         }
     }
 
-    private fun WallpaperDestination.toFlags(): Int {
-        return when (this) {
-            BOTH -> FLAG_LOCK or FLAG_SYSTEM
-            HOME -> FLAG_SYSTEM
-            LOCK -> FLAG_LOCK
-        }
-    }
-
     /**
      * Adjusts cropHints for parallax effect.
      *
@@ -672,9 +632,7 @@ constructor(
      *
      * @param wallpaperSize full wallpaper image size.
      */
-    private fun FullPreviewCropModel.adjustCropForParallax(
-        wallpaperSize: Point,
-    ): Rect {
+    private fun FullPreviewCropModel.adjustCropForParallax(wallpaperSize: Point): Rect {
         return cropSizeModel?.let {
             WallpaperCropUtils.calculateCropRect(
                     context,
diff --git a/src/com/android/wallpaper/picker/customization/data/repository/CustomizationRuntimeValuesRepository.kt b/src/com/android/wallpaper/picker/customization/data/repository/CustomizationRuntimeValuesRepository.kt
new file mode 100644
index 00000000..33f71d5b
--- /dev/null
+++ b/src/com/android/wallpaper/picker/customization/data/repository/CustomizationRuntimeValuesRepository.kt
@@ -0,0 +1,58 @@
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
+import android.os.Bundle
+import com.android.systemui.shared.customization.data.content.CustomizationProviderClient
+import com.android.systemui.shared.customization.data.content.CustomizationProviderContract
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.shareIn
+
+@Singleton
+class CustomizationRuntimeValuesRepository
+@Inject
+constructor(
+    @BackgroundDispatcher private val scope: CoroutineScope,
+    client: CustomizationProviderClient,
+) {
+
+    private val runtimeValues: Flow<Bundle> =
+        client
+            .observeRuntimeValues()
+            .shareIn(scope = scope, started = SharingStarted.WhileSubscribed(), replay = 1)
+
+    /**
+     * Whether the shade layout should be wide (true) or narrow (false).
+     *
+     * In a wide layout, notifications and quick settings each take up only half the screen width
+     * (whether they are shown at the same time or not). In a narrow layout, they can each be as
+     * wide as the entire screen.
+     */
+    val isShadeLayoutWide: Flow<Boolean> =
+        runtimeValues.map {
+            it.getBoolean(
+                CustomizationProviderContract.RuntimeValuesTable.KEY_IS_SHADE_LAYOUT_WIDE,
+                false,
+            )
+        }
+}
diff --git a/src/com/android/wallpaper/picker/customization/data/repository/WallpaperRepository.kt b/src/com/android/wallpaper/picker/customization/data/repository/WallpaperRepository.kt
index 6150fade..6631752d 100644
--- a/src/com/android/wallpaper/picker/customization/data/repository/WallpaperRepository.kt
+++ b/src/com/android/wallpaper/picker/customization/data/repository/WallpaperRepository.kt
@@ -69,9 +69,7 @@ constructor(
             .shareIn(scope = scope, started = SharingStarted.WhileSubscribed(), replay = 1)
 
     /** The ID of the currently-selected wallpaper. */
-    fun selectedWallpaperId(
-        destination: WallpaperDestination,
-    ): StateFlow<String> {
+    fun selectedWallpaperId(destination: WallpaperDestination): StateFlow<String> {
         return client
             .recentWallpapers(destination = destination, limit = 1)
             .map { previews -> currentWallpaperKey(destination, previews) }
@@ -79,7 +77,7 @@ constructor(
             .stateIn(
                 scope = scope,
                 started = SharingStarted.WhileSubscribed(),
-                initialValue = currentWallpaperKey(destination, null)
+                initialValue = currentWallpaperKey(destination, null),
             )
     }
 
@@ -121,7 +119,7 @@ constructor(
     suspend fun loadThumbnail(
         wallpaperId: String,
         lastUpdatedTimestamp: Long,
-        destination: WallpaperDestination
+        destination: WallpaperDestination,
     ): Bitmap? {
         val cacheKey = "$wallpaperId-$lastUpdatedTimestamp"
         return thumbnailCache[cacheKey]
@@ -163,11 +161,7 @@ constructor(
         wallpaperModel: LiveWallpaperModel,
     ) {
         withContext(backgroundDispatcher) {
-            client.setLiveWallpaper(
-                setWallpaperEntryPoint,
-                destination,
-                wallpaperModel,
-            )
+            client.setLiveWallpaper(setWallpaperEntryPoint, destination, wallpaperModel)
         }
     }
 
diff --git a/src/com/android/wallpaper/picker/customization/shared/model/WallpaperDestination.kt b/src/com/android/wallpaper/picker/customization/shared/model/WallpaperDestination.kt
index 4b8c6806..d9a56641 100644
--- a/src/com/android/wallpaper/picker/customization/shared/model/WallpaperDestination.kt
+++ b/src/com/android/wallpaper/picker/customization/shared/model/WallpaperDestination.kt
@@ -52,5 +52,14 @@ enum class WallpaperDestination {
                 LOCK -> DEST_LOCK_SCREEN
             }
         }
+
+        @SetWallpaperFlags
+        fun WallpaperDestination.toSetWallpaperFlags(): Int {
+            return when (this) {
+                BOTH -> FLAG_LOCK or FLAG_SYSTEM
+                HOME -> FLAG_SYSTEM
+                LOCK -> FLAG_LOCK
+            }
+        }
     }
 }
diff --git a/src/com/android/wallpaper/picker/customization/ui/CustomizationPickerActivity2.kt b/src/com/android/wallpaper/picker/customization/ui/CustomizationPickerActivity2.kt
index 1bef7332..9e25ebdc 100644
--- a/src/com/android/wallpaper/picker/customization/ui/CustomizationPickerActivity2.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/CustomizationPickerActivity2.kt
@@ -16,70 +16,32 @@
 
 package com.android.wallpaper.picker.customization.ui
 
-import android.annotation.TargetApi
-import android.content.pm.ActivityInfo
-import android.content.res.Configuration
-import android.graphics.Color
-import android.graphics.Point
 import android.os.Bundle
-import android.view.View
-import android.view.ViewGroup
-import android.view.ViewGroup.MarginLayoutParams
-import android.widget.Button
-import android.widget.FrameLayout
-import android.widget.LinearLayout
-import android.widget.Toolbar
-import androidx.activity.OnBackPressedCallback
-import androidx.activity.result.contract.ActivityResultContracts
-import androidx.activity.viewModels
 import androidx.appcompat.app.AppCompatActivity
-import androidx.constraintlayout.motion.widget.MotionLayout
-import androidx.constraintlayout.motion.widget.MotionLayout.TransitionListener
-import androidx.constraintlayout.widget.ConstraintLayout
-import androidx.constraintlayout.widget.ConstraintSet
-import androidx.core.view.ViewCompat
 import androidx.core.view.WindowCompat
-import androidx.core.view.WindowInsetsCompat
-import androidx.core.view.doOnLayout
-import androidx.core.view.doOnPreDraw
-import androidx.recyclerview.widget.RecyclerView
-import androidx.viewpager2.widget.ViewPager2
 import com.android.customization.picker.clock.ui.view.ClockViewFactory
 import com.android.wallpaper.R
-import com.android.wallpaper.model.Screen
-import com.android.wallpaper.model.Screen.HOME_SCREEN
-import com.android.wallpaper.model.Screen.LOCK_SCREEN
-import com.android.wallpaper.module.LargeScreenMultiPanesChecker
 import com.android.wallpaper.module.MultiPanesChecker
+import com.android.wallpaper.picker.AppbarFragment
 import com.android.wallpaper.picker.common.preview.data.repository.PersistentWallpaperModelRepository
-import com.android.wallpaper.picker.common.preview.ui.binder.BasePreviewBinder
 import com.android.wallpaper.picker.common.preview.ui.binder.WorkspaceCallbackBinder
-import com.android.wallpaper.picker.customization.ui.binder.ColorUpdateBinder
 import com.android.wallpaper.picker.customization.ui.binder.CustomizationOptionsBinder
-import com.android.wallpaper.picker.customization.ui.binder.CustomizationPickerBinder2
 import com.android.wallpaper.picker.customization.ui.binder.ToolbarBinder
 import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil
-import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil.CustomizationOption
-import com.android.wallpaper.picker.customization.ui.view.adapter.PreviewPagerAdapter
-import com.android.wallpaper.picker.customization.ui.view.transformer.PreviewPagerPageTransformer
 import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
-import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2
 import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import com.android.wallpaper.picker.di.modules.MainDispatcher
-import com.android.wallpaper.picker.preview.ui.WallpaperPreviewActivity
 import com.android.wallpaper.util.ActivityUtils
 import com.android.wallpaper.util.DisplayUtils
-import com.android.wallpaper.util.WallpaperConnection
 import com.android.wallpaper.util.converter.WallpaperModelFactory
 import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import dagger.hilt.android.AndroidEntryPoint
 import javax.inject.Inject
-import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.launch
 
 @AndroidEntryPoint(AppCompatActivity::class)
-class CustomizationPickerActivity2 : Hilt_CustomizationPickerActivity2() {
+class CustomizationPickerActivity2 :
+    Hilt_CustomizationPickerActivity2(), AppbarFragment.AppbarFragmentHost {
 
     @Inject lateinit var multiPanesChecker: MultiPanesChecker
     @Inject lateinit var customizationOptionUtil: CustomizationOptionUtil
@@ -95,16 +57,6 @@ class CustomizationPickerActivity2 : Hilt_CustomizationPickerActivity2() {
     @Inject lateinit var colorUpdateViewModel: ColorUpdateViewModel
     @Inject lateinit var clockViewFactory: ClockViewFactory
 
-    private var fullyCollapsed = false
-    private var navBarHeight: Int = 0
-
-    private val customizationPickerViewModel: CustomizationPickerViewModel2 by viewModels()
-    private var customizationOptionFloatingSheetViewMap: Map<CustomizationOption, View>? = null
-    private var configuration: Configuration? = null
-
-    private val startForResult =
-        this.registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {}
-
     override fun onCreate(savedInstanceState: Bundle?) {
         super.onCreate(savedInstanceState)
         if (
@@ -126,366 +78,18 @@ class CustomizationPickerActivity2 : Hilt_CustomizationPickerActivity2() {
             return
         }
 
-        configuration = Configuration(resources.configuration)
-
         setContentView(R.layout.activity_cusomization_picker2)
         WindowCompat.setDecorFitsSystemWindows(window, ActivityUtils.isSUWMode(this))
 
-        setupToolbar(
-            requireViewById(R.id.nav_button),
-            requireViewById(R.id.toolbar),
-            requireViewById(R.id.apply_button),
-        )
-
-        val view = requireViewById<View>(R.id.root_view)
-        ColorUpdateBinder.bind(
-            setColor = { color -> view.setBackgroundColor(color) },
-            color = colorUpdateViewModel.colorSurfaceContainer,
-            shouldAnimate = { true },
-            lifecycleOwner = this,
-        )
-
-        val rootView = requireViewById<MotionLayout>(R.id.picker_motion_layout)
-        ViewCompat.setOnApplyWindowInsetsListener(rootView) { _, windowInsets ->
-            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
-            navBarHeight = insets.bottom
-            requireViewById<FrameLayout>(R.id.customization_option_floating_sheet_container)
-                .setPaddingRelative(0, 0, 0, navBarHeight)
-            val statusBarHeight = insets.top
-            val params = requireViewById<Toolbar>(R.id.toolbar).layoutParams as MarginLayoutParams
-            params.setMargins(0, statusBarHeight, 0, 0)
-            WindowInsetsCompat.CONSUMED
-        }
-
-        customizationOptionFloatingSheetViewMap =
-            customizationOptionUtil.initFloatingSheet(
-                rootView.requireViewById<FrameLayout>(
-                    R.id.customization_option_floating_sheet_container
-                ),
-                layoutInflater,
-            )
-        rootView.setTransitionListener(
-            object : EmptyTransitionListener {
-                override fun onTransitionCompleted(motionLayout: MotionLayout?, currentId: Int) {
-                    if (
-                        currentId == R.id.expanded_header_primary ||
-                            currentId == R.id.collapsed_header_primary
-                    ) {
-                        rootView.setTransition(R.id.transition_primary)
-                    }
-                }
-            }
-        )
-
-        val previewViewModel = customizationPickerViewModel.basePreviewViewModel
-        previewViewModel.setWhichPreview(WallpaperConnection.WhichPreview.EDIT_CURRENT)
-        // TODO (b/348462236): adjust flow so this is always false when previewing current wallpaper
-        previewViewModel.setIsWallpaperColorPreviewEnabled(false)
-
-        initPreviewPager(isFirstBinding = savedInstanceState == null)
-
-        val optionContainer = requireViewById<MotionLayout>(R.id.customization_option_container)
-        // The collapsed header height should be updated when option container's height is known
-        optionContainer.doOnPreDraw {
-            // The bottom navigation bar height
-            val collapsedHeaderHeight = rootView.height - optionContainer.height - navBarHeight
-            if (
-                collapsedHeaderHeight >
-                    resources.getDimensionPixelSize(
-                        R.dimen.customization_picker_preview_header_collapsed_height
-                    )
-            ) {
-                rootView
-                    .getConstraintSet(R.id.collapsed_header_primary)
-                    ?.constrainHeight(R.id.preview_header, collapsedHeaderHeight)
-                rootView.setTransition(R.id.transition_primary)
-            }
-        }
-
-        CustomizationPickerBinder2.bind(
-            view = rootView,
-            lockScreenCustomizationOptionEntries = initCustomizationOptionEntries(LOCK_SCREEN),
-            homeScreenCustomizationOptionEntries = initCustomizationOptionEntries(HOME_SCREEN),
-            customizationOptionFloatingSheetViewMap = customizationOptionFloatingSheetViewMap,
-            viewModel = customizationPickerViewModel,
-            colorUpdateViewModel = colorUpdateViewModel,
-            customizationOptionsBinder = customizationOptionsBinder,
-            lifecycleOwner = this,
-            navigateToPrimary = {
-                if (rootView.currentState == R.id.secondary) {
-                    rootView.transitionToState(
-                        if (fullyCollapsed) R.id.collapsed_header_primary
-                        else R.id.expanded_header_primary
-                    )
-                }
-            },
-            navigateToSecondary = { screen ->
-                if (rootView.currentState != R.id.secondary) {
-                    setCustomizationOptionFloatingSheet(rootView, screen) {
-                        fullyCollapsed = rootView.progress == 1.0f
-                        rootView.transitionToState(R.id.secondary)
-                    }
-                }
-            },
-        )
-
-        onBackPressedDispatcher.addCallback(
-            object : OnBackPressedCallback(true) {
-                override fun handleOnBackPressed() {
-                    val isOnBackPressedHandled =
-                        customizationPickerViewModel.customizationOptionsViewModel.deselectOption()
-                    if (!isOnBackPressedHandled) {
-                        remove()
-                        onBackPressedDispatcher.onBackPressed()
-                    }
-                }
-            }
-        )
+        val fragment = CustomizationPickerFragment2()
+        supportFragmentManager.beginTransaction().add(R.id.fragment_container, fragment).commit()
     }
 
-    private fun setupToolbar(navButton: FrameLayout, toolbar: Toolbar, applyButton: Button) {
-        toolbar.title = getString(R.string.app_name)
-        toolbar.setBackgroundColor(Color.TRANSPARENT)
-        toolbarBinder.bind(
-            navButton,
-            toolbar,
-            applyButton,
-            customizationPickerViewModel.customizationOptionsViewModel,
-            this,
-        )
-    }
-
-    private fun initCustomizationOptionEntries(
-        screen: Screen
-    ): List<Pair<CustomizationOption, View>> {
-        val optionEntriesContainer =
-            requireViewById<LinearLayout>(
-                when (screen) {
-                    LOCK_SCREEN -> R.id.lock_customization_option_container
-                    HOME_SCREEN -> R.id.home_customization_option_container
-                }
-            )
-        val optionEntries =
-            customizationOptionUtil.getOptionEntries(screen, optionEntriesContainer, layoutInflater)
-        optionEntries.onEachIndexed { index, (option, view) ->
-            val isFirst = index == 0
-            val isLast = index == optionEntries.size - 1
-            view.setBackgroundResource(
-                if (isFirst) R.drawable.customization_option_entry_top_background
-                else if (isLast) R.drawable.customization_option_entry_bottom_background
-                else R.drawable.customization_option_entry_background
-            )
-            optionEntriesContainer.addView(view)
-        }
-        return optionEntries
+    override fun onUpArrowPressed() {
+        onBackPressedDispatcher.onBackPressed()
     }
 
-    private fun initPreviewPager(isFirstBinding: Boolean) {
-        val pager = requireViewById<ViewPager2>(R.id.preview_pager)
-        val previewViewModel = customizationPickerViewModel.basePreviewViewModel
-        pager.apply {
-            adapter = PreviewPagerAdapter { viewHolder, position ->
-                val previewCard = viewHolder.itemView.requireViewById<View>(R.id.preview_card)
-                val screen =
-                    if (position == 0) {
-                        LOCK_SCREEN
-                    } else {
-                        HOME_SCREEN
-                    }
-
-                if (screen == LOCK_SCREEN) {
-                    val clockHostView =
-                        (previewCard.parent as? ViewGroup)?.let {
-                            customizationOptionUtil.createClockPreviewAndAddToParent(
-                                it,
-                                layoutInflater,
-                            )
-                        }
-                    if (clockHostView != null) {
-                        customizationOptionsBinder.bindClockPreview(
-                            clockHostView = clockHostView,
-                            viewModel = customizationPickerViewModel,
-                            lifecycleOwner = this@CustomizationPickerActivity2,
-                            clockViewFactory = clockViewFactory,
-                        )
-                    }
-                }
-
-                BasePreviewBinder.bind(
-                    applicationContext = applicationContext,
-                    view = previewCard,
-                    viewModel = customizationPickerViewModel,
-                    workspaceCallbackBinder = workspaceCallbackBinder,
-                    screen = screen,
-                    deviceDisplayType =
-                        displayUtils.getCurrentDisplayType(this@CustomizationPickerActivity2),
-                    displaySize =
-                        if (displayUtils.isOnWallpaperDisplay(this@CustomizationPickerActivity2))
-                            previewViewModel.wallpaperDisplaySize.value
-                        else previewViewModel.smallerDisplaySize,
-                    lifecycleOwner = this@CustomizationPickerActivity2,
-                    wallpaperConnectionUtils = wallpaperConnectionUtils,
-                    isFirstBindingDeferred = CompletableDeferred(isFirstBinding),
-                    onClick = {
-                        previewViewModel.wallpapers.value?.let {
-                            val wallpaper =
-                                if (screen == HOME_SCREEN) it.homeWallpaper
-                                else it.lockWallpaper ?: it.homeWallpaper
-                            persistentWallpaperModelRepository.setWallpaperModel(wallpaper)
-                        }
-                        val multiPanesChecker = LargeScreenMultiPanesChecker()
-                        val isMultiPanel = multiPanesChecker.isMultiPanesEnabled(applicationContext)
-                        startForResult.launch(
-                            WallpaperPreviewActivity.newIntent(
-                                context = applicationContext,
-                                isAssetIdPresent = false,
-                                isViewAsHome = screen == HOME_SCREEN,
-                                isNewTask = isMultiPanel,
-                            )
-                        )
-                    },
-                )
-            }
-            // Disable over scroll
-            (getChildAt(0) as RecyclerView).overScrollMode = RecyclerView.OVER_SCROLL_NEVER
-            // The neighboring view should be inflated when pager is rendered
-            offscreenPageLimit = 1
-            // When pager's height changes, request transform to recalculate the preview offset
-            // to make sure correct space between the previews.
-            // TODO (b/348462236): figure out how to scale surface view content with layout change
-            addOnLayoutChangeListener { view, _, _, _, _, _, topWas, _, bottomWas ->
-                val isHeightChanged = (bottomWas - topWas) != view.height
-                if (isHeightChanged) {
-                    pager.requestTransform()
-                }
-            }
-        }
-
-        // Only when pager is laid out, we can get the width and set the preview's offset correctly
-        pager.doOnLayout {
-            (it as ViewPager2).apply {
-                setPageTransformer(PreviewPagerPageTransformer(Point(width, height)))
-            }
-        }
-    }
-
-    /**
-     * Set customization option floating sheet to the floating sheet container and get the new
-     * container's height for repositioning the preview's guideline.
-     */
-    private fun setCustomizationOptionFloatingSheet(
-        motionContainer: MotionLayout,
-        option: CustomizationOption,
-        onComplete: () -> Unit,
-    ) {
-        val view = customizationOptionFloatingSheetViewMap?.get(option) ?: return
-
-        val floatingSheetContainer =
-            requireViewById<FrameLayout>(R.id.customization_option_floating_sheet_container)
-        floatingSheetContainer.removeAllViews()
-        floatingSheetContainer.addView(view)
-
-        view.doOnPreDraw {
-            val height = view.height + navBarHeight
-            floatingSheetContainer.translationY = 0.0f
-            floatingSheetContainer.alpha = 0.0f
-            // Update the motion container
-            motionContainer.getConstraintSet(R.id.expanded_header_primary)?.apply {
-                setTranslationY(
-                    R.id.customization_option_floating_sheet_container,
-                    height.toFloat(),
-                )
-                setAlpha(R.id.customization_option_floating_sheet_container, 0.0f)
-                connect(
-                    R.id.customization_option_floating_sheet_container,
-                    ConstraintSet.BOTTOM,
-                    R.id.picker_motion_layout,
-                    ConstraintSet.BOTTOM,
-                )
-                constrainHeight(
-                    R.id.customization_option_floating_sheet_container,
-                    ConstraintLayout.LayoutParams.WRAP_CONTENT,
-                )
-            }
-            motionContainer.getConstraintSet(R.id.collapsed_header_primary)?.apply {
-                setTranslationY(
-                    R.id.customization_option_floating_sheet_container,
-                    height.toFloat(),
-                )
-                setAlpha(R.id.customization_option_floating_sheet_container, 0.0f)
-                connect(
-                    R.id.customization_option_floating_sheet_container,
-                    ConstraintSet.BOTTOM,
-                    R.id.picker_motion_layout,
-                    ConstraintSet.BOTTOM,
-                )
-                constrainHeight(
-                    R.id.customization_option_floating_sheet_container,
-                    ConstraintLayout.LayoutParams.WRAP_CONTENT,
-                )
-            }
-            motionContainer.getConstraintSet(R.id.secondary)?.apply {
-                setTranslationY(R.id.customization_option_floating_sheet_container, 0.0f)
-                setAlpha(R.id.customization_option_floating_sheet_container, 1.0f)
-                constrainHeight(
-                    R.id.customization_option_floating_sheet_container,
-                    ConstraintLayout.LayoutParams.WRAP_CONTENT,
-                )
-            }
-            onComplete()
-        }
-    }
-
-    override fun onDestroy() {
-        // TODO(b/333879532): Only disconnect when leaving the Activity without introducing black
-        //  preview. If onDestroy is caused by an orientation change, we should keep the connection
-        //  to avoid initiating the engines again.
-        // TODO(b/328302105): MainScope ensures the job gets done non-blocking even if the
-        //   activity has been destroyed already. Consider making this part of
-        //   WallpaperConnectionUtils.
-        mainScope.launch { wallpaperConnectionUtils.disconnectAll(applicationContext) }
-
-        super.onDestroy()
-    }
-
-    @TargetApi(36)
-    override fun onConfigurationChanged(newConfig: Configuration) {
-        super.onConfigurationChanged(newConfig)
-        configuration?.let {
-            val diff = newConfig.diff(it)
-            val isAssetsPathsChange = diff and ActivityInfo.CONFIG_ASSETS_PATHS != 0
-            if (isAssetsPathsChange) {
-                colorUpdateViewModel.updateColors()
-            }
-        }
-        configuration?.setTo(newConfig)
-    }
-
-    interface EmptyTransitionListener : TransitionListener {
-        override fun onTransitionStarted(motionLayout: MotionLayout?, startId: Int, endId: Int) {
-            // Do nothing intended
-        }
-
-        override fun onTransitionChange(
-            motionLayout: MotionLayout?,
-            startId: Int,
-            endId: Int,
-            progress: Float,
-        ) {
-            // Do nothing intended
-        }
-
-        override fun onTransitionCompleted(motionLayout: MotionLayout?, currentId: Int) {
-            // Do nothing intended
-        }
-
-        override fun onTransitionTrigger(
-            motionLayout: MotionLayout?,
-            triggerId: Int,
-            positive: Boolean,
-            progress: Float,
-        ) {
-            // Do nothing intended
-        }
+    override fun isUpArrowSupported(): Boolean {
+        return !ActivityUtils.isSUWMode(baseContext)
     }
 }
diff --git a/src/com/android/wallpaper/picker/customization/ui/CustomizationPickerFragment2.kt b/src/com/android/wallpaper/picker/customization/ui/CustomizationPickerFragment2.kt
new file mode 100644
index 00000000..389706da
--- /dev/null
+++ b/src/com/android/wallpaper/picker/customization/ui/CustomizationPickerFragment2.kt
@@ -0,0 +1,526 @@
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
+package com.android.wallpaper.picker.customization.ui
+
+import android.annotation.TargetApi
+import android.content.pm.ActivityInfo
+import android.content.res.Configuration
+import android.graphics.Color
+import android.graphics.Point
+import android.os.Bundle
+import android.view.LayoutInflater
+import android.view.View
+import android.view.ViewGroup
+import android.view.ViewGroup.MarginLayoutParams
+import android.widget.Button
+import android.widget.FrameLayout
+import android.widget.LinearLayout
+import android.widget.Toolbar
+import androidx.activity.OnBackPressedCallback
+import androidx.activity.addCallback
+import androidx.activity.result.contract.ActivityResultContracts
+import androidx.constraintlayout.motion.widget.MotionLayout
+import androidx.constraintlayout.motion.widget.MotionLayout.TransitionListener
+import androidx.constraintlayout.widget.ConstraintLayout
+import androidx.constraintlayout.widget.ConstraintSet
+import androidx.core.view.ViewCompat
+import androidx.core.view.WindowInsetsCompat
+import androidx.core.view.doOnLayout
+import androidx.core.view.doOnPreDraw
+import androidx.fragment.app.Fragment
+import androidx.fragment.app.commit
+import androidx.fragment.app.replace
+import androidx.fragment.app.viewModels
+import androidx.recyclerview.widget.RecyclerView
+import androidx.viewpager2.widget.ViewPager2
+import com.android.customization.picker.clock.ui.view.ClockViewFactory
+import com.android.wallpaper.R
+import com.android.wallpaper.model.Screen
+import com.android.wallpaper.model.Screen.HOME_SCREEN
+import com.android.wallpaper.model.Screen.LOCK_SCREEN
+import com.android.wallpaper.module.LargeScreenMultiPanesChecker
+import com.android.wallpaper.picker.category.ui.view.CategoriesFragment
+import com.android.wallpaper.picker.common.preview.data.repository.PersistentWallpaperModelRepository
+import com.android.wallpaper.picker.common.preview.ui.binder.BasePreviewBinder
+import com.android.wallpaper.picker.common.preview.ui.binder.WorkspaceCallbackBinder
+import com.android.wallpaper.picker.customization.ui.binder.ColorUpdateBinder
+import com.android.wallpaper.picker.customization.ui.binder.CustomizationOptionsBinder
+import com.android.wallpaper.picker.customization.ui.binder.CustomizationPickerBinder2
+import com.android.wallpaper.picker.customization.ui.binder.PagerTouchInterceptorBinder
+import com.android.wallpaper.picker.customization.ui.binder.ToolbarBinder
+import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil
+import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil.CustomizationOption
+import com.android.wallpaper.picker.customization.ui.view.adapter.PreviewPagerAdapter
+import com.android.wallpaper.picker.customization.ui.view.transformer.PreviewPagerPageTransformer
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2
+import com.android.wallpaper.picker.di.modules.MainDispatcher
+import com.android.wallpaper.picker.preview.ui.WallpaperPreviewActivity
+import com.android.wallpaper.util.ActivityUtils
+import com.android.wallpaper.util.DisplayUtils
+import com.android.wallpaper.util.WallpaperConnection
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
+import dagger.hilt.android.AndroidEntryPoint
+import javax.inject.Inject
+import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.launch
+
+@AndroidEntryPoint(Fragment::class)
+class CustomizationPickerFragment2 : Hilt_CustomizationPickerFragment2() {
+
+    @Inject lateinit var customizationOptionUtil: CustomizationOptionUtil
+    @Inject lateinit var customizationOptionsBinder: CustomizationOptionsBinder
+    @Inject lateinit var toolbarBinder: ToolbarBinder
+    @Inject lateinit var colorUpdateViewModel: ColorUpdateViewModel
+    @Inject lateinit var clockViewFactory: ClockViewFactory
+    @Inject lateinit var workspaceCallbackBinder: WorkspaceCallbackBinder
+    @Inject lateinit var displayUtils: DisplayUtils
+    @Inject lateinit var wallpaperConnectionUtils: WallpaperConnectionUtils
+    @Inject lateinit var persistentWallpaperModelRepository: PersistentWallpaperModelRepository
+    @Inject @MainDispatcher lateinit var mainScope: CoroutineScope
+
+    private val customizationPickerViewModel: CustomizationPickerViewModel2 by viewModels()
+
+    private var fullyCollapsed = false
+    private var navBarHeight: Int = 0
+    private var configuration: Configuration? = null
+
+    private var onBackPressedCallback: OnBackPressedCallback? = null
+
+    private var customizationOptionFloatingSheetViewMap: Map<CustomizationOption, View>? = null
+
+    private val startForResult =
+        this.registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {}
+
+    override fun onCreateView(
+        inflater: LayoutInflater,
+        container: ViewGroup?,
+        savedInstanceState: Bundle?,
+    ): View? {
+        configuration = Configuration(resources.configuration)
+
+        val isFromLauncher =
+            activity?.intent?.let { ActivityUtils.isLaunchedFromLauncher(it) } ?: false
+        if (isFromLauncher) {
+            customizationPickerViewModel.selectPreviewScreen(HOME_SCREEN)
+        }
+
+        val view = inflater.inflate(R.layout.fragment_customization_picker2, container, false)
+
+        setupToolbar(
+            view.requireViewById(R.id.nav_button),
+            view.requireViewById(R.id.toolbar),
+            view.requireViewById(R.id.apply_button),
+        )
+
+        val rootView = view.requireViewById<View>(R.id.root_view)
+        ColorUpdateBinder.bind(
+            setColor = { color -> rootView.setBackgroundColor(color) },
+            color = colorUpdateViewModel.colorSurfaceContainer,
+            shouldAnimate = { true },
+            lifecycleOwner = viewLifecycleOwner,
+        )
+
+        val pickerMotionContainer = view.requireViewById<MotionLayout>(R.id.picker_motion_layout)
+        ViewCompat.setOnApplyWindowInsetsListener(pickerMotionContainer) { _, windowInsets ->
+            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
+            navBarHeight = insets.bottom
+            view
+                .requireViewById<FrameLayout>(R.id.customization_option_floating_sheet_container)
+                .setPaddingRelative(0, 0, 0, navBarHeight)
+            val statusBarHeight = insets.top
+            val params =
+                view.requireViewById<Toolbar>(R.id.toolbar).layoutParams as MarginLayoutParams
+            params.setMargins(0, statusBarHeight, 0, 0)
+            WindowInsetsCompat.CONSUMED
+        }
+
+        customizationOptionFloatingSheetViewMap =
+            customizationOptionUtil.initFloatingSheet(
+                pickerMotionContainer.requireViewById(
+                    R.id.customization_option_floating_sheet_container
+                ),
+                layoutInflater,
+            )
+
+        pickerMotionContainer.setTransitionListener(
+            object : EmptyTransitionListener {
+                override fun onTransitionCompleted(motionLayout: MotionLayout?, currentId: Int) {
+                    if (
+                        currentId == R.id.expanded_header_primary ||
+                            currentId == R.id.collapsed_header_primary
+                    ) {
+                        pickerMotionContainer.setTransition(R.id.transition_primary)
+                    }
+                }
+            }
+        )
+
+        val previewViewModel = customizationPickerViewModel.basePreviewViewModel
+        previewViewModel.setWhichPreview(WallpaperConnection.WhichPreview.EDIT_CURRENT)
+        // TODO (b/348462236): adjust flow so this is always false when previewing current wallpaper
+        previewViewModel.setIsWallpaperColorPreviewEnabled(false)
+
+        initPreviewPager(
+            view = view,
+            isFirstBinding = savedInstanceState == null,
+            initialScreen = if (isFromLauncher) HOME_SCREEN else LOCK_SCREEN,
+        )
+
+        val optionContainer =
+            view.requireViewById<MotionLayout>(R.id.customization_option_container)
+        // The collapsed header height should be updated when option container's height is known
+        optionContainer.doOnPreDraw {
+            // The bottom navigation bar height
+            val collapsedHeaderHeight =
+                pickerMotionContainer.height - optionContainer.height - navBarHeight
+            if (
+                collapsedHeaderHeight >
+                    resources.getDimensionPixelSize(
+                        R.dimen.customization_picker_preview_header_collapsed_height
+                    )
+            ) {
+                pickerMotionContainer
+                    .getConstraintSet(R.id.collapsed_header_primary)
+                    ?.constrainHeight(R.id.preview_header, collapsedHeaderHeight)
+                pickerMotionContainer.setTransition(R.id.transition_primary)
+            }
+        }
+
+        CustomizationPickerBinder2.bind(
+            view = pickerMotionContainer,
+            lockScreenCustomizationOptionEntries =
+                initCustomizationOptionEntries(view, LOCK_SCREEN),
+            homeScreenCustomizationOptionEntries =
+                initCustomizationOptionEntries(view, HOME_SCREEN),
+            customizationOptionFloatingSheetViewMap = customizationOptionFloatingSheetViewMap,
+            viewModel = customizationPickerViewModel,
+            colorUpdateViewModel = colorUpdateViewModel,
+            customizationOptionsBinder = customizationOptionsBinder,
+            lifecycleOwner = this,
+            navigateToPrimary = {
+                if (pickerMotionContainer.currentState == R.id.secondary) {
+                    pickerMotionContainer.transitionToState(
+                        if (fullyCollapsed) R.id.collapsed_header_primary
+                        else R.id.expanded_header_primary
+                    )
+                }
+            },
+            navigateToSecondary = { screen ->
+                if (pickerMotionContainer.currentState != R.id.secondary) {
+                    setCustomizationOptionFloatingSheet(view, pickerMotionContainer, screen) {
+                        fullyCollapsed = pickerMotionContainer.progress == 1.0f
+                        pickerMotionContainer.transitionToState(R.id.secondary)
+                    }
+                }
+            },
+            navigateToCategoriesScreen = { _ ->
+                if (isAdded) {
+                    parentFragmentManager.commit {
+                        replace<CategoriesFragment>(R.id.fragment_container)
+                        addToBackStack(null)
+                    }
+                }
+            },
+        )
+
+        activity?.onBackPressedDispatcher?.let {
+            it.addCallback {
+                    isEnabled =
+                        customizationPickerViewModel.customizationOptionsViewModel
+                            .handleBackPressed()
+                    if (!isEnabled) it.onBackPressed()
+                }
+                .also { callback -> onBackPressedCallback = callback }
+        }
+
+        return view
+    }
+
+    override fun onDestroyView() {
+        context?.applicationContext?.let { appContext ->
+            // TODO(b/333879532): Only disconnect when leaving the Activity without introducing
+            // black
+            //  preview. If onDestroy is caused by an orientation change, we should keep the
+            // connection
+            //  to avoid initiating the engines again.
+            // TODO(b/328302105): MainScope ensures the job gets done non-blocking even if the
+            //   activity has been destroyed already. Consider making this part of
+            //   WallpaperConnectionUtils.
+            mainScope.launch { wallpaperConnectionUtils.disconnectAll(appContext) }
+        }
+
+        super.onDestroyView()
+        onBackPressedCallback?.remove()
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
+    private fun setupToolbar(navButton: FrameLayout, toolbar: Toolbar, applyButton: Button) {
+        toolbar.title = getString(R.string.app_name)
+        toolbar.setBackgroundColor(Color.TRANSPARENT)
+        toolbarBinder.bind(
+            navButton,
+            toolbar,
+            applyButton,
+            customizationPickerViewModel.customizationOptionsViewModel,
+            colorUpdateViewModel,
+            this,
+        ) {
+            activity?.onBackPressedDispatcher?.onBackPressed()
+        }
+    }
+
+    private fun initPreviewPager(view: View, isFirstBinding: Boolean, initialScreen: Screen) {
+        val appContext = context?.applicationContext ?: return
+        val activity = activity ?: return
+
+        PagerTouchInterceptorBinder.bind(
+            view.requireViewById(R.id.pager_touch_interceptor),
+            customizationPickerViewModel,
+            viewLifecycleOwner,
+        )
+
+        val pager = view.requireViewById<ViewPager2>(R.id.preview_pager)
+        val previewViewModel = customizationPickerViewModel.basePreviewViewModel
+        pager.apply {
+            adapter = PreviewPagerAdapter { viewHolder, position ->
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
+                            context = context,
+                            clockHostView = clockHostView,
+                            viewModel = customizationPickerViewModel,
+                            colorUpdateViewModel = colorUpdateViewModel,
+                            lifecycleOwner = this@CustomizationPickerFragment2,
+                            clockViewFactory = clockViewFactory,
+                        )
+                    }
+                }
+
+                BasePreviewBinder.bind(
+                    applicationContext = appContext,
+                    view = previewCard,
+                    viewModel = customizationPickerViewModel,
+                    colorUpdateViewModel = colorUpdateViewModel,
+                    workspaceCallbackBinder = workspaceCallbackBinder,
+                    screen = screen,
+                    deviceDisplayType = displayUtils.getCurrentDisplayType(activity),
+                    displaySize =
+                        if (displayUtils.isOnWallpaperDisplay(activity))
+                            previewViewModel.wallpaperDisplaySize.value
+                        else previewViewModel.smallerDisplaySize,
+                    mainScope = mainScope,
+                    lifecycleOwner = this@CustomizationPickerFragment2,
+                    wallpaperConnectionUtils = wallpaperConnectionUtils,
+                    isFirstBindingDeferred = CompletableDeferred(isFirstBinding),
+                    onLaunchPreview = { wallpaperModel ->
+                        persistentWallpaperModelRepository.setWallpaperModel(wallpaperModel)
+                        val multiPanesChecker = LargeScreenMultiPanesChecker()
+                        val isMultiPanel = multiPanesChecker.isMultiPanesEnabled(appContext)
+                        startForResult.launch(
+                            WallpaperPreviewActivity.newIntent(
+                                context = appContext,
+                                isAssetIdPresent = false,
+                                isViewAsHome = screen == HOME_SCREEN,
+                                isNewTask = isMultiPanel,
+                            )
+                        )
+                    },
+                    clockViewFactory = clockViewFactory,
+                )
+            }
+            setCurrentItem(
+                when (initialScreen) {
+                    LOCK_SCREEN -> 0
+                    HOME_SCREEN -> 1
+                },
+                false,
+            )
+            // Disable over scroll
+            (getChildAt(0) as RecyclerView).overScrollMode = RecyclerView.OVER_SCROLL_NEVER
+            // The neighboring view should be inflated when pager is rendered
+            offscreenPageLimit = 1
+            // When pager's height changes, request transform to recalculate the preview offset
+            // to make sure correct space between the previews.
+            // TODO (b/348462236): figure out how to scale surface view content with layout change
+            addOnLayoutChangeListener { view, _, _, _, _, _, topWas, _, bottomWas ->
+                val isHeightChanged = (bottomWas - topWas) != view.height
+                if (isHeightChanged) {
+                    pager.requestTransform()
+                }
+            }
+        }
+
+        // Only when pager is laid out, we can get the width and set the preview's offset correctly
+        pager.doOnLayout {
+            (it as ViewPager2).apply {
+                setPageTransformer(PreviewPagerPageTransformer(Point(width, height)))
+            }
+        }
+    }
+
+    private fun initCustomizationOptionEntries(
+        view: View,
+        screen: Screen,
+    ): List<Pair<CustomizationOption, View>> {
+        val optionEntriesContainer =
+            view.requireViewById<LinearLayout>(
+                when (screen) {
+                    LOCK_SCREEN -> R.id.lock_customization_option_container
+                    HOME_SCREEN -> R.id.home_customization_option_container
+                }
+            )
+        val optionEntries =
+            customizationOptionUtil.getOptionEntries(screen, optionEntriesContainer, layoutInflater)
+        optionEntries.onEachIndexed { index, (_, view) ->
+            val isFirst = index == 0
+            val isLast = index == optionEntries.size - 1
+            view.setBackgroundResource(
+                if (isFirst) R.drawable.customization_option_entry_top_background
+                else if (isLast) R.drawable.customization_option_entry_bottom_background
+                else R.drawable.customization_option_entry_background
+            )
+            optionEntriesContainer.addView(view)
+        }
+        return optionEntries
+    }
+
+    /**
+     * Set customization option floating sheet to the floating sheet container and get the new
+     * container's height for repositioning the preview's guideline.
+     */
+    private fun setCustomizationOptionFloatingSheet(
+        view: View,
+        motionContainer: MotionLayout,
+        option: CustomizationOption,
+        onComplete: () -> Unit,
+    ) {
+        val floatingSheetViewContent =
+            customizationOptionFloatingSheetViewMap?.get(option) ?: return
+
+        val floatingSheetContainer =
+            view.requireViewById<FrameLayout>(R.id.customization_option_floating_sheet_container)
+        floatingSheetContainer.removeAllViews()
+        floatingSheetContainer.addView(floatingSheetViewContent)
+
+        floatingSheetViewContent.doOnPreDraw {
+            val height = floatingSheetViewContent.height + navBarHeight
+            floatingSheetContainer.translationY = 0.0f
+            floatingSheetContainer.alpha = 0.0f
+            // Update the motion container
+            motionContainer.getConstraintSet(R.id.expanded_header_primary)?.apply {
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
+                constrainHeight(
+                    R.id.customization_option_floating_sheet_container,
+                    ConstraintLayout.LayoutParams.WRAP_CONTENT,
+                )
+            }
+            motionContainer.getConstraintSet(R.id.collapsed_header_primary)?.apply {
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
+                constrainHeight(
+                    R.id.customization_option_floating_sheet_container,
+                    ConstraintLayout.LayoutParams.WRAP_CONTENT,
+                )
+            }
+            motionContainer.getConstraintSet(R.id.secondary)?.apply {
+                setTranslationY(R.id.customization_option_floating_sheet_container, 0.0f)
+                setAlpha(R.id.customization_option_floating_sheet_container, 1.0f)
+                constrainHeight(
+                    R.id.customization_option_floating_sheet_container,
+                    ConstraintLayout.LayoutParams.WRAP_CONTENT,
+                )
+            }
+            onComplete()
+        }
+    }
+
+    interface EmptyTransitionListener : TransitionListener {
+        override fun onTransitionStarted(motionLayout: MotionLayout?, startId: Int, endId: Int) {
+            // Do nothing intended
+        }
+
+        override fun onTransitionChange(
+            motionLayout: MotionLayout?,
+            startId: Int,
+            endId: Int,
+            progress: Float,
+        ) {
+            // Do nothing intended
+        }
+
+        override fun onTransitionCompleted(motionLayout: MotionLayout?, currentId: Int) {
+            // Do nothing intended
+        }
+
+        override fun onTransitionTrigger(
+            motionLayout: MotionLayout?,
+            triggerId: Int,
+            positive: Boolean,
+            progress: Float,
+        ) {
+            // Do nothing intended
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationOptionsBinder.kt b/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationOptionsBinder.kt
index 7a64605d..dc12295f 100644
--- a/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationOptionsBinder.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationOptionsBinder.kt
@@ -16,15 +16,23 @@
 
 package com.android.wallpaper.picker.customization.ui.binder
 
+import android.content.Context
 import android.view.View
 import androidx.lifecycle.LifecycleOwner
 import com.android.customization.picker.clock.ui.view.ClockViewFactory
+import com.android.wallpaper.model.Screen
 import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil.CustomizationOption
 import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2
 
 interface CustomizationOptionsBinder {
 
+    /**
+     * @param navigateToWallpaperCategoriesScreen This is a callback that should be implemented by
+     *   the hosting Fragment or Activity. This callback should navigate to the wallpaper categories
+     *   screen. The input [Screen] of this callback indicate the entrypoint to the wallpaper
+     *   categories screen.
+     */
     fun bind(
         view: View,
         lockScreenCustomizationOptionEntries: List<Pair<CustomizationOption, View>>,
@@ -33,11 +41,14 @@ interface CustomizationOptionsBinder {
         viewModel: CustomizationPickerViewModel2,
         colorUpdateViewModel: ColorUpdateViewModel,
         lifecycleOwner: LifecycleOwner,
+        navigateToWallpaperCategoriesScreen: (screen: Screen) -> Unit,
     )
 
     fun bindClockPreview(
+        context: Context,
         clockHostView: View,
         viewModel: CustomizationPickerViewModel2,
+        colorUpdateViewModel: ColorUpdateViewModel,
         lifecycleOwner: LifecycleOwner,
         clockViewFactory: ClockViewFactory,
     )
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationPickerBinder2.kt b/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationPickerBinder2.kt
index d54279ab..e3227a86 100644
--- a/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationPickerBinder2.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/CustomizationPickerBinder2.kt
@@ -26,6 +26,7 @@ import androidx.lifecycle.repeatOnLifecycle
 import androidx.recyclerview.widget.RecyclerView
 import androidx.viewpager2.widget.ViewPager2
 import com.android.wallpaper.R
+import com.android.wallpaper.model.Screen
 import com.android.wallpaper.model.Screen.HOME_SCREEN
 import com.android.wallpaper.model.Screen.LOCK_SCREEN
 import com.android.wallpaper.picker.customization.ui.CustomizationPickerActivity2
@@ -59,6 +60,7 @@ object CustomizationPickerBinder2 {
         lifecycleOwner: LifecycleOwner,
         navigateToPrimary: () -> Unit,
         navigateToSecondary: (screen: CustomizationOption) -> Unit,
+        navigateToCategoriesScreen: (screen: Screen) -> Unit,
     ) {
         val optionContainer =
             view.requireViewById<MotionLayout>(R.id.customization_option_container)
@@ -169,6 +171,7 @@ object CustomizationPickerBinder2 {
             viewModel,
             colorUpdateViewModel,
             lifecycleOwner,
+            navigateToCategoriesScreen,
         )
     }
 }
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/DefaultCustomizationOptionsBinder.kt b/src/com/android/wallpaper/picker/customization/ui/binder/DefaultCustomizationOptionsBinder.kt
index 76e4d536..1420ab29 100644
--- a/src/com/android/wallpaper/picker/customization/ui/binder/DefaultCustomizationOptionsBinder.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/DefaultCustomizationOptionsBinder.kt
@@ -16,6 +16,7 @@
 
 package com.android.wallpaper.picker.customization.ui.binder
 
+import android.content.Context
 import android.content.res.ColorStateList
 import android.view.View
 import android.widget.TextView
@@ -42,23 +43,32 @@ class DefaultCustomizationOptionsBinder @Inject constructor() : CustomizationOpt
         viewModel: CustomizationPickerViewModel2,
         colorUpdateViewModel: ColorUpdateViewModel,
         lifecycleOwner: LifecycleOwner,
+        navigateToWallpaperCategoriesScreen: (screen: Screen) -> Unit,
     ) {
-        val optionLockWallpaper =
+        val moreWallpapersLock =
             lockScreenCustomizationOptionEntries
                 .find {
                     it.first ==
                         DefaultCustomizationOptionUtil.DefaultLockCustomizationOption.WALLPAPER
                 }
                 ?.second
-        val moreWallpapersLock = optionLockWallpaper?.findViewById<TextView>(R.id.more_wallpapers)
-        val optionHomeWallpaper =
+                ?.findViewById<TextView>(R.id.more_wallpapers)
+        val moreWallpapersHome =
             homeScreenCustomizationOptionEntries
                 .find {
                     it.first ==
                         DefaultCustomizationOptionUtil.DefaultHomeCustomizationOption.WALLPAPER
                 }
                 ?.second
-        val moreWallpapersHome = optionHomeWallpaper?.findViewById<TextView>(R.id.more_wallpapers)
+                ?.findViewById<TextView>(R.id.more_wallpapers)
+
+        moreWallpapersLock?.setOnClickListener {
+            navigateToWallpaperCategoriesScreen.invoke(Screen.LOCK_SCREEN)
+        }
+
+        moreWallpapersHome?.setOnClickListener {
+            navigateToWallpaperCategoriesScreen.invoke(Screen.HOME_SCREEN)
+        }
 
         ColorUpdateBinder.bind(
             setColor = { color ->
@@ -92,8 +102,10 @@ class DefaultCustomizationOptionsBinder @Inject constructor() : CustomizationOpt
     }
 
     override fun bindClockPreview(
+        context: Context,
         clockHostView: View,
         viewModel: CustomizationPickerViewModel2,
+        colorUpdateViewModel: ColorUpdateViewModel,
         lifecycleOwner: LifecycleOwner,
         clockViewFactory: ClockViewFactory,
     ) {
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/DefaultToolbarBinder.kt b/src/com/android/wallpaper/picker/customization/ui/binder/DefaultToolbarBinder.kt
index 63eb1414..7422f18d 100644
--- a/src/com/android/wallpaper/picker/customization/ui/binder/DefaultToolbarBinder.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/DefaultToolbarBinder.kt
@@ -21,11 +21,13 @@ import android.widget.Button
 import android.widget.FrameLayout
 import android.widget.Toolbar
 import androidx.appcompat.content.res.AppCompatResources
+import androidx.core.graphics.drawable.DrawableCompat
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
 import com.android.wallpaper.R
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
 import javax.inject.Inject
 import javax.inject.Singleton
@@ -39,10 +41,40 @@ class DefaultToolbarBinder @Inject constructor() : ToolbarBinder {
         toolbar: Toolbar,
         applyButton: Button,
         viewModel: CustomizationOptionsViewModel,
+        colorUpdateViewModel: ColorUpdateViewModel,
         lifecycleOwner: LifecycleOwner,
+        onNavBack: () -> Unit,
     ) {
         val appContext = navButton.context.applicationContext
         val navButtonIcon = navButton.requireViewById<View>(R.id.nav_button_icon)
+
+        navButton.setOnClickListener { onNavBack.invoke() }
+
+        ColorUpdateBinder.bind(
+            setColor = { color -> toolbar.setTitleTextColor(color) },
+            color = colorUpdateViewModel.colorOnSurface,
+            shouldAnimate = { true },
+            lifecycleOwner = lifecycleOwner,
+        )
+
+        ColorUpdateBinder.bind(
+            setColor = { color ->
+                DrawableCompat.setTint(DrawableCompat.wrap(navButton.background), color)
+            },
+            color = colorUpdateViewModel.colorSurfaceContainerHighest,
+            shouldAnimate = { true },
+            lifecycleOwner = lifecycleOwner,
+        )
+
+        ColorUpdateBinder.bind(
+            setColor = { color ->
+                DrawableCompat.setTint(DrawableCompat.wrap(navButtonIcon.background), color)
+            },
+            color = colorUpdateViewModel.colorOnSurfaceVariant,
+            shouldAnimate = { true },
+            lifecycleOwner = lifecycleOwner,
+        )
+
         lifecycleOwner.lifecycleScope.launch {
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                 launch {
@@ -51,12 +83,11 @@ class DefaultToolbarBinder @Inject constructor() : ToolbarBinder {
                             navButtonIcon.background =
                                 AppCompatResources.getDrawable(
                                     appContext,
-                                    R.drawable.ic_arrow_back_24dp
+                                    R.drawable.ic_arrow_back_24dp,
                                 )
                         } else {
                             navButtonIcon.background =
                                 AppCompatResources.getDrawable(appContext, R.drawable.ic_close_24dp)
-                            navButtonIcon.setOnClickListener { viewModel.deselectOption() }
                         }
                     }
                 }
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/PagerTouchInterceptorBinder.kt b/src/com/android/wallpaper/picker/customization/ui/binder/PagerTouchInterceptorBinder.kt
new file mode 100644
index 00000000..944b7b34
--- /dev/null
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/PagerTouchInterceptorBinder.kt
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
+package com.android.wallpaper.picker.customization.ui.binder
+
+import android.view.View
+import androidx.core.view.isVisible
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2
+import kotlinx.coroutines.launch
+
+object PagerTouchInterceptorBinder {
+
+    fun bind(
+        pagerTouchInterceptor: View,
+        viewModel: CustomizationPickerViewModel2,
+        lifecycleOwner: LifecycleOwner,
+    ) {
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                launch {
+                    viewModel.isPagerInteractable.collect { pagerTouchInterceptor.isVisible = !it }
+                }
+            }
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/ScreenPreviewBinder.kt b/src/com/android/wallpaper/picker/customization/ui/binder/ScreenPreviewBinder.kt
index 4cccb9aa..1613cec3 100644
--- a/src/com/android/wallpaper/picker/customization/ui/binder/ScreenPreviewBinder.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/ScreenPreviewBinder.kt
@@ -71,10 +71,7 @@ import kotlinx.coroutines.launch
  */
 object ScreenPreviewBinder {
     interface Binding {
-        fun sendMessage(
-            id: Int,
-            args: Bundle = Bundle.EMPTY,
-        )
+        fun sendMessage(id: Int, args: Bundle = Bundle.EMPTY)
 
         fun destroy()
 
@@ -130,7 +127,8 @@ object ScreenPreviewBinder {
             wallpaperSurface.setBackgroundColor(Color.TRANSPARENT)
             workspaceSurface.visibility = View.VISIBLE
         }
-        wallpaperSurface.setZOrderOnTop(false)
+        wallpaperSurface.setZOrderMediaOverlay(true)
+        workspaceSurface.setZOrderMediaOverlay(true)
 
         val flags = BaseFlags.get()
         val isPageTransitionsFeatureEnabled = flags.isPageTransitionsFeatureEnabled(activity)
@@ -221,7 +219,7 @@ object ScreenPreviewBinder {
                                                 LoadingAnimation(
                                                     loadingView,
                                                     LoadingAnimation.RevealType.CIRCULAR,
-                                                    LoadingAnimation.TIME_OUT_DURATION_MS
+                                                    LoadingAnimation.TIME_OUT_DURATION_MS,
                                                 )
                                         }
                                     }
@@ -266,7 +264,7 @@ object ScreenPreviewBinder {
                                             animationTransitionProgress,
                                             animationColorToRestore,
                                         )
-                                    } else null
+                                    } else null,
                                 )
                                 wallpaperIsReadyForReveal = false
                                 if (isPageTransitionsFeatureEnabled) {
@@ -292,9 +290,6 @@ object ScreenPreviewBinder {
                                 viewModel.getInitialExtras(),
                             )
                         workspaceSurface.holder.addCallback(previewSurfaceCallback)
-                        if (!dimWallpaper) {
-                            workspaceSurface.setZOrderMediaOverlay(true)
-                        }
 
                         wallpaperSurfaceCallback =
                             WallpaperSurfaceCallback(
@@ -307,7 +302,7 @@ object ScreenPreviewBinder {
                                         ResourceUtils.getColorAttr(
                                             previewView.context,
                                             android.R.attr.colorSecondary,
-                                        )
+                                        ),
                                     )
                                 ),
                             ) {
@@ -318,14 +313,14 @@ object ScreenPreviewBinder {
                                     offsetToStart =
                                         if (isMultiCropEnabled) false else offsetToStart,
                                     onSurfaceViewsReady = surfaceViewsReady,
-                                    thumbnailRequested = thumbnailRequested
+                                    thumbnailRequested = thumbnailRequested,
                                 )
                                 if (showLoadingAnimation) {
                                     val colorAccent =
                                         animationColorToRestore
                                             ?: ResourceUtils.getColorAttr(
                                                 activity,
-                                                android.R.attr.colorAccent
+                                                android.R.attr.colorAccent,
                                             )
                                     val night =
                                         (previewView.resources.configuration.uiMode and
@@ -334,7 +329,7 @@ object ScreenPreviewBinder {
                                     loadingAnimation?.updateColor(ColorScheme(colorAccent, night))
                                     loadingAnimation?.setupRevealAnimation(
                                         animationTimeToRestore,
-                                        animationTransitionProgress
+                                        animationTransitionProgress,
                                     )
                                     val isStaticWallpaper =
                                         wallpaperInfo != null && wallpaperInfo !is LiveWallpaperInfo
@@ -346,9 +341,6 @@ object ScreenPreviewBinder {
                                 }
                             }
                         wallpaperSurface.holder.addCallback(wallpaperSurfaceCallback)
-                        if (!dimWallpaper) {
-                            wallpaperSurface.setZOrderMediaOverlay(true)
-                        }
 
                         if (!isWallpaperAlwaysVisible) {
                             wallpaperSurface.visibilityCallback = { visible: Boolean ->
@@ -439,14 +431,14 @@ object ScreenPreviewBinder {
                                             LoadingAnimation(
                                                 loadingView,
                                                 LoadingAnimation.RevealType.CIRCULAR,
-                                                LoadingAnimation.TIME_OUT_DURATION_MS
+                                                LoadingAnimation.TIME_OUT_DURATION_MS,
                                             )
                                     }
                                     loadingImageDrawable = animationBackground
                                     val colorAccent =
                                         ResourceUtils.getColorAttr(
                                             activity,
-                                            android.R.attr.colorAccent
+                                            android.R.attr.colorAccent,
                                         )
                                     val night =
                                         (previewView.resources.configuration.uiMode and
@@ -477,7 +469,7 @@ object ScreenPreviewBinder {
                                 surfaceCallback = wallpaperSurfaceCallback,
                                 offsetToStart = if (isMultiCropEnabled) false else offsetToStart,
                                 onSurfaceViewsReady = surfaceViewsReady,
-                                thumbnailRequested = thumbnailRequested
+                                thumbnailRequested = thumbnailRequested,
                             )
                             if (showLoadingAnimation && wallpaperInfo !is LiveWallpaperInfo) {
                                 loadingAnimation?.playRevealAnimation()
@@ -494,7 +486,7 @@ object ScreenPreviewBinder {
                                                 viewModel,
                                                 wallpaperSurface,
                                                 mirrorSurface,
-                                                viewModel.screen
+                                                viewModel.screen,
                                             ) {
                                                 surfaceViewsReady()
                                                 if (showLoadingAnimation) {
@@ -560,13 +552,13 @@ object ScreenPreviewBinder {
         wallpaperSurface: SurfaceView,
         mirrorSurface: SurfaceView?,
         screen: Screen,
-        onEngineShown: () -> Unit
+        onEngineShown: () -> Unit,
     ) =
         WallpaperConnection(
             Intent(WallpaperService.SERVICE_INTERFACE).apply {
                 setClassName(
                     liveWallpaperInfo.wallpaperComponent.packageName,
-                    liveWallpaperInfo.wallpaperComponent.serviceName
+                    liveWallpaperInfo.wallpaperComponent.serviceName,
                 )
             },
             previewView.context,
@@ -582,7 +574,8 @@ object ScreenPreviewBinder {
             wallpaperSurface,
             mirrorSurface,
             screen.toFlag(),
-            WallpaperConnection.WhichPreview.PREVIEW_CURRENT
+            WallpaperConnection.WhichPreview.PREVIEW_CURRENT,
+            liveWallpaperInfo.wallpaperDescription,
         )
 
     private fun removeAndReadd(view: View) {
@@ -601,7 +594,7 @@ object ScreenPreviewBinder {
         surfaceCallback: WallpaperSurfaceCallback?,
         offsetToStart: Boolean,
         onSurfaceViewsReady: () -> Unit,
-        thumbnailRequested: AtomicBoolean
+        thumbnailRequested: AtomicBoolean,
     ) {
         if (wallpaperInfo == null || surfaceCallback == null) {
             return
@@ -620,7 +613,7 @@ object ScreenPreviewBinder {
                     imageView,
                     ResourceUtils.getColorAttr(activity, android.R.attr.colorSecondary),
                     /* offsetToStart= */ thumbAsset !is CurrentWallpaperAsset || offsetToStart,
-                    wallpaperInfo.wallpaperCropHints
+                    wallpaperInfo.wallpaperCropHints,
                 )
             if (wallpaperInfo !is LiveWallpaperInfo) {
                 imageView.addOnLayoutChangeListener(
@@ -634,7 +627,7 @@ object ScreenPreviewBinder {
                             oldLeft: Int,
                             oldTop: Int,
                             oldRight: Int,
-                            oldBottom: Int
+                            oldBottom: Int,
                         ) {
                             v?.removeOnLayoutChangeListener(this)
                             onSurfaceViewsReady()
diff --git a/src/com/android/wallpaper/picker/customization/ui/binder/ToolbarBinder.kt b/src/com/android/wallpaper/picker/customization/ui/binder/ToolbarBinder.kt
index 0b08d98d..73599040 100644
--- a/src/com/android/wallpaper/picker/customization/ui/binder/ToolbarBinder.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/binder/ToolbarBinder.kt
@@ -20,6 +20,7 @@ import android.widget.Button
 import android.widget.FrameLayout
 import android.widget.Toolbar
 import androidx.lifecycle.LifecycleOwner
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
 
 interface ToolbarBinder {
@@ -29,6 +30,8 @@ interface ToolbarBinder {
         toolbar: Toolbar,
         applyButton: Button,
         viewModel: CustomizationOptionsViewModel,
+        colorUpdateViewModel: ColorUpdateViewModel,
         lifecycleOwner: LifecycleOwner,
+        onNavBack: () -> Unit,
     )
 }
diff --git a/src/com/android/wallpaper/picker/customization/ui/section/ScreenPreviewSectionController.kt b/src/com/android/wallpaper/picker/customization/ui/section/ScreenPreviewSectionController.kt
index 1704af76..575aa675 100644
--- a/src/com/android/wallpaper/picker/customization/ui/section/ScreenPreviewSectionController.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/section/ScreenPreviewSectionController.kt
@@ -143,7 +143,7 @@ open class ScreenPreviewSectionController(
                             )
                         }
                     }
-                }
+                },
             )
     }
 
diff --git a/src/com/android/wallpaper/picker/customization/ui/view/adapter/FloatingToolbarTabAdapter.kt b/src/com/android/wallpaper/picker/customization/ui/view/adapter/FloatingToolbarTabAdapter.kt
index f0e69aa8..1e557fb9 100644
--- a/src/com/android/wallpaper/picker/customization/ui/view/adapter/FloatingToolbarTabAdapter.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/view/adapter/FloatingToolbarTabAdapter.kt
@@ -52,11 +52,7 @@ class FloatingToolbarTabAdapter(
     override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): TabViewHolder {
         val view =
             LayoutInflater.from(parent.context)
-                .inflate(
-                    R.layout.floating_toolbar_tab,
-                    parent,
-                    false,
-                )
+                .inflate(R.layout.floating_toolbar_tab, parent, false)
         val tabViewHolder = TabViewHolder(view)
         return tabViewHolder
     }
@@ -90,7 +86,7 @@ class FloatingToolbarTabAdapter(
         colorUpdateViewModel.get()?.let {
             ColorUpdateBinder.bind(
                 setColor = { color ->
-                    holder.itemView.background.colorFilter =
+                    holder.container.background.colorFilter =
                         BlendModeColorFilter(color, BlendMode.SRC_ATOP)
                 },
                 color = it.colorSecondaryContainer,
@@ -181,14 +177,14 @@ class FloatingToolbarTabAdapter(
 
         override fun areItemsTheSame(
             oldItem: FloatingToolbarTabViewModel,
-            newItem: FloatingToolbarTabViewModel
+            newItem: FloatingToolbarTabViewModel,
         ): Boolean {
             return oldItem.text == newItem.text
         }
 
         override fun areContentsTheSame(
             oldItem: FloatingToolbarTabViewModel,
-            newItem: FloatingToolbarTabViewModel
+            newItem: FloatingToolbarTabViewModel,
         ): Boolean {
             return oldItem.text == newItem.text &&
                 oldItem.isSelected == newItem.isSelected &&
@@ -197,7 +193,7 @@ class FloatingToolbarTabAdapter(
 
         override fun getChangePayload(
             oldItem: FloatingToolbarTabViewModel,
-            newItem: FloatingToolbarTabViewModel
+            newItem: FloatingToolbarTabViewModel,
         ): Any? {
             return when {
                 !oldItem.isSelected && newItem.isSelected -> SELECT_ITEM
diff --git a/src/com/android/wallpaper/picker/customization/ui/view/animator/TabItemAnimator.kt b/src/com/android/wallpaper/picker/customization/ui/view/animator/TabItemAnimator.kt
index f20d3927..8aa247a4 100644
--- a/src/com/android/wallpaper/picker/customization/ui/view/animator/TabItemAnimator.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/view/animator/TabItemAnimator.kt
@@ -34,7 +34,7 @@ class TabItemAnimator : DefaultItemAnimator() {
         state: State,
         viewHolder: ViewHolder,
         changeFlags: Int,
-        payloads: MutableList<Any>
+        payloads: MutableList<Any>,
     ): ItemHolderInfo {
         if (changeFlags == FLAG_CHANGED && payloads.isNotEmpty()) {
             return when (payloads[0] as? Int) {
diff --git a/src/com/android/wallpaper/picker/customization/ui/viewmodel/ColorUpdateViewModel.kt b/src/com/android/wallpaper/picker/customization/ui/viewmodel/ColorUpdateViewModel.kt
index 85e346b3..64c1a27f 100644
--- a/src/com/android/wallpaper/picker/customization/ui/viewmodel/ColorUpdateViewModel.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/viewmodel/ColorUpdateViewModel.kt
@@ -17,29 +17,91 @@
 package com.android.wallpaper.picker.customization.ui.viewmodel
 
 import android.content.Context
+import android.content.res.Configuration
+import com.android.systemui.monet.ColorScheme
+import com.android.systemui.monet.Style
 import com.android.wallpaper.R
+import com.google.ux.material.libmonet.dynamiccolor.DynamicColor
+import com.google.ux.material.libmonet.dynamiccolor.DynamicScheme
+import com.google.ux.material.libmonet.dynamiccolor.MaterialDynamicColors
 import dagger.hilt.android.qualifiers.ApplicationContext
 import dagger.hilt.android.scopes.ActivityScoped
 import javax.inject.Inject
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableSharedFlow
 import kotlinx.coroutines.flow.MutableStateFlow
-import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.asSharedFlow
+import kotlinx.coroutines.flow.combine
 
 @ActivityScoped
 class ColorUpdateViewModel @Inject constructor(@ApplicationContext private val context: Context) {
-    private val _colorPrimary = MutableStateFlow(context.getColor(R.color.system_primary))
-    val colorPrimary = _colorPrimary.asStateFlow()
+    private val _systemColorsUpdated: MutableSharedFlow<Unit> =
+        MutableSharedFlow<Unit>(replay = 1).also { it.tryEmit(Unit) }
+    val systemColorsUpdated = _systemColorsUpdated.asSharedFlow()
 
-    private val _colorSecondaryContainer =
-        MutableStateFlow(context.getColor(R.color.system_secondary_container))
-    val colorSecondaryContainer = _colorSecondaryContainer.asStateFlow()
+    private val previewingColorScheme: MutableStateFlow<DynamicScheme?> = MutableStateFlow(null)
 
-    private val _colorSurfaceContainer =
-        MutableStateFlow(context.getColor(R.color.system_surface_container))
-    val colorSurfaceContainer = _colorSurfaceContainer.asStateFlow()
+    private val colors: MutableList<Color> = mutableListOf()
+
+    private inner class Color(private val colorResId: Int, dynamicColor: DynamicColor) {
+        private val color = MutableStateFlow(context.getColor(colorResId))
+        val colorFlow =
+            combine(color, previewingColorScheme) { systemColor, previewScheme ->
+                if (previewScheme != null) {
+                    previewScheme.getArgb(dynamicColor)
+                } else systemColor
+            }
+
+        fun update() {
+            color.value = context.getColor(colorResId)
+        }
+    }
+
+    private fun createColorFlow(colorResId: Int, dynamicColor: DynamicColor): Flow<Int> {
+        val color = Color(colorResId, dynamicColor)
+        colors.add(color)
+        return color.colorFlow
+    }
+
+    val colorPrimary = createColorFlow(R.color.system_primary, MaterialDynamicColors().primary())
+    val colorOnPrimary =
+        createColorFlow(R.color.system_on_primary, MaterialDynamicColors().onPrimary())
+    val colorSecondaryContainer =
+        createColorFlow(
+            R.color.system_secondary_container,
+            MaterialDynamicColors().secondaryContainer(),
+        )
+    val colorSurfaceContainer =
+        createColorFlow(
+            R.color.system_surface_container,
+            MaterialDynamicColors().surfaceContainer(),
+        )
+    val colorOnSurface =
+        createColorFlow(R.color.system_on_surface, MaterialDynamicColors().onSurface())
+    val colorOnSurfaceVariant =
+        createColorFlow(
+            R.color.system_on_surface_variant,
+            MaterialDynamicColors().onSurfaceVariant(),
+        )
+    val colorSurfaceContainerHighest =
+        createColorFlow(
+            R.color.system_surface_container_highest,
+            MaterialDynamicColors().surfaceContainerHighest(),
+        )
+
+    fun previewColors(colorSeed: Int, @Style.Type style: Int) {
+        val isDarkMode =
+            (context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
+                Configuration.UI_MODE_NIGHT_YES
+        previewingColorScheme.value = ColorScheme(colorSeed, isDarkMode, style).materialScheme
+    }
+
+    fun resetPreview() {
+        previewingColorScheme.value = null
+    }
 
     fun updateColors() {
-        _colorPrimary.value = context.getColor(R.color.system_primary)
-        _colorSecondaryContainer.value = context.getColor(R.color.system_secondary_container)
-        _colorSurfaceContainer.value = context.getColor(R.color.system_surface_container)
+        _systemColorsUpdated.tryEmit(Unit)
+        colors.forEach { it.update() }
     }
 }
diff --git a/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationOptionsViewModel.kt b/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationOptionsViewModel.kt
index 04904c1d..901cf6b0 100644
--- a/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationOptionsViewModel.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationOptionsViewModel.kt
@@ -25,10 +25,12 @@ interface CustomizationOptionsViewModel {
     val selectedOption: StateFlow<CustomizationOptionUtil.CustomizationOption?>
 
     /**
-     * Deselect the selected option and return true. If no option is selected, do nothing and return
-     * false.
+     * Handle back pressed. [CustomizationOptionsViewModel] should deselect the selected option and
+     * return true. If no option is selected, do nothing and return false.
+     *
+     * @return True if back pressed is handled by [CustomizationOptionsViewModel]
      */
-    fun deselectOption(): Boolean
+    fun handleBackPressed(): Boolean
 }
 
 interface CustomizationOptionsViewModelFactory {
diff --git a/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationPickerViewModel2.kt b/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationPickerViewModel2.kt
index 97c40ddd..fb7333e3 100644
--- a/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationPickerViewModel2.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/viewmodel/CustomizationPickerViewModel2.kt
@@ -23,6 +23,7 @@ import com.android.wallpaper.model.Screen.LOCK_SCREEN
 import com.android.wallpaper.picker.common.preview.ui.viewmodel.BasePreviewViewModel
 import dagger.hilt.android.lifecycle.HiltViewModel
 import javax.inject.Inject
+import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.map
@@ -59,4 +60,9 @@ constructor(
                 Pair(PickerScreen.MAIN, null)
             }
         }
+
+    val isPreviewClickable: Flow<Boolean> = basePreviewViewModel.wallpapers.map { it != null }
+
+    val isPagerInteractable: Flow<Boolean> =
+        customizationOptionsViewModel.selectedOption.map { it == null }
 }
diff --git a/src/com/android/wallpaper/picker/customization/ui/viewmodel/DefaultCustomizationOptionsViewModel.kt b/src/com/android/wallpaper/picker/customization/ui/viewmodel/DefaultCustomizationOptionsViewModel.kt
index e9371958..37b48a2e 100644
--- a/src/com/android/wallpaper/picker/customization/ui/viewmodel/DefaultCustomizationOptionsViewModel.kt
+++ b/src/com/android/wallpaper/picker/customization/ui/viewmodel/DefaultCustomizationOptionsViewModel.kt
@@ -27,15 +27,13 @@ import kotlinx.coroutines.flow.asStateFlow
 
 class DefaultCustomizationOptionsViewModel
 @AssistedInject
-constructor(
-    @Assisted viewModelScope: CoroutineScope,
-) : CustomizationOptionsViewModel {
+constructor(@Assisted viewModelScope: CoroutineScope) : CustomizationOptionsViewModel {
 
     private val _selectedOptionState =
         MutableStateFlow<CustomizationOptionUtil.CustomizationOption?>(null)
     override val selectedOption = _selectedOptionState.asStateFlow()
 
-    override fun deselectOption(): Boolean {
+    override fun handleBackPressed(): Boolean {
         return if (_selectedOptionState.value != null) {
             _selectedOptionState.value = null
             true
diff --git a/src/com/android/wallpaper/picker/data/CommonWallpaperData.kt b/src/com/android/wallpaper/picker/data/CommonWallpaperData.kt
index 13d8d11b..de8eba67 100644
--- a/src/com/android/wallpaper/picker/data/CommonWallpaperData.kt
+++ b/src/com/android/wallpaper/picker/data/CommonWallpaperData.kt
@@ -22,7 +22,7 @@ import com.android.wallpaper.asset.Asset
 data class CommonWallpaperData(
     val id: WallpaperId,
     val title: String?,
-    val attributions: List<String?>?,
+    val attributions: List<String>?,
     val exploreActionUrl: String?,
     val thumbAsset: Asset,
     val placeholderColorInfo: ColorInfo,
diff --git a/src/com/android/wallpaper/picker/data/LiveWallpaperData.kt b/src/com/android/wallpaper/picker/data/LiveWallpaperData.kt
index 5c619ae3..10ff1441 100644
--- a/src/com/android/wallpaper/picker/data/LiveWallpaperData.kt
+++ b/src/com/android/wallpaper/picker/data/LiveWallpaperData.kt
@@ -17,6 +17,7 @@
 package com.android.wallpaper.picker.data
 
 import android.app.WallpaperInfo
+import android.app.wallpaper.WallpaperDescription
 
 /** Represents set of attributes that are specific to live wallpapers. */
 data class LiveWallpaperData(
@@ -27,4 +28,6 @@ data class LiveWallpaperData(
     val isEffectWallpaper: Boolean,
     val effectNames: String?,
     val contextDescription: CharSequence? = null,
+    val description: WallpaperDescription =
+        WallpaperDescription.Builder().setComponent(systemWallpaperInfo.component).build(),
 )
diff --git a/src/com/android/wallpaper/picker/data/category/ThirdPartyCategoryData.kt b/src/com/android/wallpaper/picker/data/category/ThirdPartyCategoryData.kt
index 4fb160ef..09d93249 100644
--- a/src/com/android/wallpaper/picker/data/category/ThirdPartyCategoryData.kt
+++ b/src/com/android/wallpaper/picker/data/category/ThirdPartyCategoryData.kt
@@ -17,9 +17,10 @@
 package com.android.wallpaper.picker.data.category
 
 import android.content.pm.ResolveInfo
+import android.graphics.drawable.Drawable
 
 /**
  * Represents set of attributes required for displaying a 3rd party wallpaper app installed on
  * device.
  */
-data class ThirdPartyCategoryData(val resolveInfo: ResolveInfo)
+data class ThirdPartyCategoryData(val resolveInfo: ResolveInfo, val defaultDrawable: Drawable?)
diff --git a/src/com/android/wallpaper/picker/di/modules/SharedAppModule.kt b/src/com/android/wallpaper/picker/di/modules/SharedAppModule.kt
index ef4b45b8..9d1d78f8 100644
--- a/src/com/android/wallpaper/picker/di/modules/SharedAppModule.kt
+++ b/src/com/android/wallpaper/picker/di/modules/SharedAppModule.kt
@@ -25,11 +25,14 @@ import android.os.HandlerThread
 import android.os.Looper
 import android.os.Process
 import com.android.wallpaper.module.DefaultNetworkStatusNotifier
+import com.android.wallpaper.module.DefaultPackageStatusNotifier
 import com.android.wallpaper.module.LargeScreenMultiPanesChecker
 import com.android.wallpaper.module.MultiPanesChecker
 import com.android.wallpaper.module.NetworkStatusNotifier
+import com.android.wallpaper.module.PackageStatusNotifier
 import com.android.wallpaper.network.Requester
 import com.android.wallpaper.network.WallpaperRequester
+import com.android.wallpaper.picker.MyPhotosStarter
 import com.android.wallpaper.picker.category.client.DefaultWallpaperCategoryClient
 import com.android.wallpaper.picker.category.client.DefaultWallpaperCategoryClientImpl
 import com.android.wallpaper.picker.category.client.LiveWallpapersClient
@@ -37,15 +40,16 @@ import com.android.wallpaper.picker.category.client.LiveWallpapersClientImpl
 import com.android.wallpaper.picker.category.data.repository.DefaultWallpaperCategoryRepository
 import com.android.wallpaper.picker.category.data.repository.WallpaperCategoryRepository
 import com.android.wallpaper.picker.category.domain.interactor.MyPhotosInteractor
-import com.android.wallpaper.picker.category.domain.interactor.ThirdPartyCategoryInteractor
 import com.android.wallpaper.picker.category.domain.interactor.implementations.MyPhotosInteractorImpl
-import com.android.wallpaper.picker.category.domain.interactor.implementations.ThirdPartyCategoryInteractorImpl
+import com.android.wallpaper.picker.category.ui.view.MyPhotosStarterImpl
 import com.android.wallpaper.picker.customization.data.content.WallpaperClient
 import com.android.wallpaper.picker.customization.data.content.WallpaperClientImpl
 import com.android.wallpaper.picker.network.data.DefaultNetworkStatusRepository
 import com.android.wallpaper.picker.network.data.NetworkStatusRepository
 import com.android.wallpaper.picker.network.domain.DefaultNetworkStatusInteractor
 import com.android.wallpaper.picker.network.domain.NetworkStatusInteractor
+import com.android.wallpaper.system.PowerManagerImpl
+import com.android.wallpaper.system.PowerManagerWrapper
 import com.android.wallpaper.system.UiModeManagerImpl
 import com.android.wallpaper.system.UiModeManagerWrapper
 import com.android.wallpaper.util.WallpaperParser
@@ -109,13 +113,11 @@ abstract class SharedAppModule {
 
     @Binds
     @Singleton
-    abstract fun bindThirdPartyCategoryInteractor(
-        impl: ThirdPartyCategoryInteractorImpl,
-    ): ThirdPartyCategoryInteractor
+    abstract fun bindUiModeManagerWrapper(impl: UiModeManagerImpl): UiModeManagerWrapper
 
     @Binds
     @Singleton
-    abstract fun bindUiModeManagerWrapper(impl: UiModeManagerImpl): UiModeManagerWrapper
+    abstract fun bindPowerManagerWrapper(impl: PowerManagerImpl): PowerManagerWrapper
 
     @Binds
     @Singleton
@@ -123,6 +125,10 @@ abstract class SharedAppModule {
         impl: DefaultWallpaperCategoryClientImpl
     ): DefaultWallpaperCategoryClient
 
+    @Binds
+    @Singleton
+    abstract fun bindPackageNotifier(impl: DefaultPackageStatusNotifier): PackageStatusNotifier
+
     @Binds
     @Singleton
     abstract fun bindWallpaperCategoryRepository(
@@ -133,6 +139,10 @@ abstract class SharedAppModule {
 
     @Binds @Singleton abstract fun bindWallpaperParser(impl: WallpaperParserImpl): WallpaperParser
 
+    @Binds
+    @Singleton
+    abstract fun bindWallpaperPickerDelegate2(impl: MyPhotosStarterImpl): MyPhotosStarter
+
     companion object {
 
         @Qualifier
@@ -164,10 +174,7 @@ abstract class SharedAppModule {
         @Singleton
         @BroadcastRunning
         fun provideBroadcastRunningLooper(): Looper {
-            return HandlerThread(
-                    "BroadcastRunning",
-                    Process.THREAD_PRIORITY_BACKGROUND,
-                )
+            return HandlerThread("BroadcastRunning", Process.THREAD_PRIORITY_BACKGROUND)
                 .apply {
                     start()
                     looper.setSlowLogThresholdMs(
diff --git a/src/com/android/wallpaper/picker/individual/IndividualPickerFragment2.kt b/src/com/android/wallpaper/picker/individual/IndividualPickerFragment2.kt
index 100f33fd..35791fcb 100644
--- a/src/com/android/wallpaper/picker/individual/IndividualPickerFragment2.kt
+++ b/src/com/android/wallpaper/picker/individual/IndividualPickerFragment2.kt
@@ -409,7 +409,7 @@ class IndividualPickerFragment2 :
                         return
                     }
 
-                    if (fetchedCategory == null) {
+                    if (fetchedCategory == null && !parentFragmentManager.isStateSaved) {
                         // The absence of this category in the CategoryProvider indicates a broken
                         // state, see b/38030129. Hence, finish the activity and return.
                         parentFragmentManager.popBackStack()
diff --git a/src/com/android/wallpaper/picker/network/data/DefaultNetworkStatusRepository.kt b/src/com/android/wallpaper/picker/network/data/DefaultNetworkStatusRepository.kt
index f881db4a..988ce201 100644
--- a/src/com/android/wallpaper/picker/network/data/DefaultNetworkStatusRepository.kt
+++ b/src/com/android/wallpaper/picker/network/data/DefaultNetworkStatusRepository.kt
@@ -46,14 +46,9 @@ constructor(
     override fun networkStateFlow(): Flow<Boolean> = callbackFlow {
         val listener =
             NetworkStatusNotifier.Listener { status: Int ->
-                Log.i(DefaultNetworkStatusRepository.TAG, "Network status changes: " + status)
-                if (_networkStatus.value != NETWORK_CONNECTED && status == NETWORK_CONNECTED) {
-                    // Emit true value when network is available and it was previously unavailable
-                    trySend(true)
-                } else {
-                    trySend(false)
-                }
-
+                Log.i(TAG, "Network status changes: $status")
+                val isConnected = (status == NETWORK_CONNECTED)
+                trySend(isConnected)
                 _networkStatus.value = networkStatusNotifier.networkStatus
             }
 
diff --git a/src/com/android/wallpaper/picker/option/ui/adapter/OptionItemAdapter2.kt b/src/com/android/wallpaper/picker/option/ui/adapter/OptionItemAdapter2.kt
new file mode 100644
index 00000000..32f854bb
--- /dev/null
+++ b/src/com/android/wallpaper/picker/option/ui/adapter/OptionItemAdapter2.kt
@@ -0,0 +1,121 @@
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
+ *
+ */
+
+package com.android.wallpaper.picker.option.ui.adapter
+
+import android.view.LayoutInflater
+import android.view.View
+import android.view.ViewGroup
+import androidx.annotation.LayoutRes
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.recyclerview.widget.DiffUtil
+import androidx.recyclerview.widget.RecyclerView
+import com.android.wallpaper.picker.option.ui.binder.OptionItemBinder2
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel2
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.DisposableHandle
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.withContext
+
+/** Adapts between option items and their views. */
+class OptionItemAdapter2<T>(
+    @LayoutRes private val layoutResourceId: Int,
+    private val lifecycleOwner: LifecycleOwner,
+    private val backgroundDispatcher: CoroutineDispatcher = Dispatchers.IO,
+    private val bindPayload: (View, T) -> DisposableHandle?,
+) : RecyclerView.Adapter<OptionItemAdapter2.ViewHolder>() {
+
+    private val items = mutableListOf<OptionItemViewModel2<T>>()
+
+    fun setItems(items: List<OptionItemViewModel2<T>>, callback: (() -> Unit)? = null) {
+        lifecycleOwner.lifecycleScope.launch {
+            val oldItems = this@OptionItemAdapter2.items
+            val newItems = items
+            val diffResult =
+                withContext(backgroundDispatcher) {
+                    DiffUtil.calculateDiff(
+                        object : DiffUtil.Callback() {
+                            override fun getOldListSize(): Int {
+                                return oldItems.size
+                            }
+
+                            override fun getNewListSize(): Int {
+                                return newItems.size
+                            }
+
+                            override fun areItemsTheSame(
+                                oldItemPosition: Int,
+                                newItemPosition: Int,
+                            ): Boolean {
+                                val oldItem = oldItems[oldItemPosition]
+                                val newItem = newItems[newItemPosition]
+                                return oldItem.key.value == newItem.key.value
+                            }
+
+                            override fun areContentsTheSame(
+                                oldItemPosition: Int,
+                                newItemPosition: Int,
+                            ): Boolean {
+                                val oldItem = oldItems[oldItemPosition]
+                                val newItem = newItems[newItemPosition]
+                                return oldItem == newItem
+                            }
+                        },
+                        /* detectMoves= */ false,
+                    )
+                }
+
+            oldItems.clear()
+            oldItems.addAll(items)
+            diffResult.dispatchUpdatesTo(this@OptionItemAdapter2)
+            if (callback != null) {
+                callback()
+            }
+        }
+    }
+
+    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
+        var disposableHandle: DisposableHandle? = null
+        var payloadDisposableHandle: DisposableHandle? = null
+    }
+
+    override fun getItemCount(): Int {
+        return items.size
+    }
+
+    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
+        return ViewHolder(
+            LayoutInflater.from(parent.context).inflate(layoutResourceId, parent, false)
+        )
+    }
+
+    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
+        holder.disposableHandle?.dispose()
+        holder.payloadDisposableHandle?.dispose()
+        val item = items[position]
+        holder.payloadDisposableHandle =
+            item.payload?.let { bindPayload(holder.itemView, item.payload) }
+        holder.disposableHandle =
+            OptionItemBinder2.bind(
+                view = holder.itemView,
+                viewModel = item,
+                lifecycleOwner = lifecycleOwner,
+            )
+    }
+}
diff --git a/src/com/android/wallpaper/picker/option/ui/binder/OptionItemBinder.kt b/src/com/android/wallpaper/picker/option/ui/binder/OptionItemBinder.kt
index 6c405fe2..a1cfeb07 100644
--- a/src/com/android/wallpaper/picker/option/ui/binder/OptionItemBinder.kt
+++ b/src/com/android/wallpaper/picker/option/ui/binder/OptionItemBinder.kt
@@ -81,17 +81,11 @@ object OptionItemBinder {
         val textView: TextView? = view.findViewById(R.id.text)
 
         if (textView != null && viewModel.isTextUserVisible) {
-            TextViewBinder.bind(
-                view = textView,
-                viewModel = viewModel.text,
-            )
+            TextViewBinder.bind(view = textView, viewModel = viewModel.text)
         } else {
             // Use the text as the content description of the foreground if we don't have a TextView
             // dedicated to for the text.
-            ContentDescriptionViewBinder.bind(
-                view = foregroundView,
-                viewModel = viewModel.text,
-            )
+            ContentDescriptionViewBinder.bind(view = foregroundView, viewModel = viewModel.text)
         }
         textView?.isVisible = viewModel.isTextUserVisible
 
@@ -141,10 +135,9 @@ object OptionItemBinder {
                             .flatMapLatest {
                                 // If the key changed, then it means that this binding is no longer
                                 // rendering the UI for the same option as before, we nullify the
-                                // last
-                                // selected value to "forget" that we've ever seen a value for
-                                // isSelected,
-                                // effectively starting anew so the first update doesn't animate.
+                                // last  selected value to "forget" that we've ever seen a value for
+                                // isSelected, effectively starting a new so the first update
+                                // doesn't animate.
                                 lastSelected = null
                                 viewModel.isSelected
                             }
@@ -311,10 +304,7 @@ object OptionItemBinder {
         val durationMs: Long = 333L,
     )
 
-    data class TintSpec(
-        @ColorInt val selectedColor: Int,
-        @ColorInt val unselectedColor: Int,
-    )
+    data class TintSpec(@ColorInt val selectedColor: Int, @ColorInt val unselectedColor: Int)
 
     private fun View.scale(scale: Float) {
         scaleX = scale
diff --git a/src/com/android/wallpaper/picker/option/ui/binder/OptionItemBinder2.kt b/src/com/android/wallpaper/picker/option/ui/binder/OptionItemBinder2.kt
new file mode 100644
index 00000000..741d09d2
--- /dev/null
+++ b/src/com/android/wallpaper/picker/option/ui/binder/OptionItemBinder2.kt
@@ -0,0 +1,242 @@
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
+ *
+ */
+
+@file:OptIn(ExperimentalCoroutinesApi::class)
+
+package com.android.wallpaper.picker.option.ui.binder
+
+import android.animation.ValueAnimator
+import android.view.View
+import android.widget.ImageView
+import android.widget.TextView
+import androidx.core.view.isVisible
+import androidx.dynamicanimation.animation.SpringAnimation
+import androidx.dynamicanimation.animation.SpringForce
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import com.android.wallpaper.R
+import com.android.wallpaper.picker.common.icon.ui.viewbinder.ContentDescriptionViewBinder
+import com.android.wallpaper.picker.common.text.ui.viewbinder.TextViewBinder
+import com.android.wallpaper.picker.option.ui.view.OptionItemBackground
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel2
+import kotlinx.coroutines.DisposableHandle
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.flow.flatMapLatest
+import kotlinx.coroutines.launch
+
+object OptionItemBinder2 {
+    /**
+     * Binds the given [View] to the given [OptionItemViewModel].
+     *
+     * The child views of [view] must be named and arranged in the following manner, from top of the
+     * z-axis to the bottom:
+     * - [R.id.foreground] is the foreground drawable ([ImageView]).
+     * - [R.id.background] is the view in the background ([OptionItemBackground]).
+     *
+     * In order to show the animation when an option item is selected, you may need to disable the
+     * clipping of child views across the view-tree using:
+     * ```
+     * android:clipChildren="false"
+     * ```
+     *
+     * Optionally, there may be an [R.id.text] [TextView] to show the text from the view-model. If
+     * one is not supplied, the text will be used as the content description of the icon.
+     *
+     * @param view The view; it must contain the child views described above.
+     * @param viewModel The view-model.
+     * @param lifecycleOwner The [LifecycleOwner].
+     * @param animationfSpec The specification for the animation.
+     * @return A [DisposableHandle] that must be invoked when the view is recycled.
+     */
+    fun bind(
+        view: View,
+        viewModel: OptionItemViewModel2<*>,
+        lifecycleOwner: LifecycleOwner,
+        animationSpec: AnimationSpec = AnimationSpec(),
+    ): DisposableHandle {
+        val backgroundView: OptionItemBackground = view.requireViewById(R.id.background)
+        val foregroundView: ImageView? = view.findViewById(R.id.foreground)
+        val textView: TextView? = view.findViewById(R.id.text)
+
+        if (textView != null && viewModel.isTextUserVisible) {
+            TextViewBinder.bind(view = textView, viewModel = viewModel.text)
+        } else {
+            // Use the text as the content description of the foreground if we don't have a TextView
+            // dedicated to for the text.
+            ContentDescriptionViewBinder.bind(
+                view = foregroundView ?: backgroundView,
+                viewModel = viewModel.text,
+            )
+        }
+        textView?.isVisible = viewModel.isTextUserVisible
+
+        textView?.alpha =
+            if (viewModel.isEnabled) {
+                animationSpec.enabledAlpha
+            } else {
+                animationSpec.disabledTextAlpha
+            }
+
+        backgroundView.alpha =
+            if (viewModel.isEnabled) {
+                animationSpec.enabledAlpha
+            } else {
+                animationSpec.disabledBackgroundAlpha
+            }
+
+        foregroundView?.alpha =
+            if (viewModel.isEnabled) {
+                animationSpec.enabledAlpha
+            } else {
+                animationSpec.disabledForegroundAlpha
+            }
+
+        view.onLongClickListener =
+            if (viewModel.onLongClicked != null) {
+                View.OnLongClickListener {
+                    viewModel.onLongClicked.invoke()
+                    true
+                }
+            } else {
+                null
+            }
+        view.isLongClickable = viewModel.onLongClicked != null
+
+        val job =
+            lifecycleOwner.lifecycleScope.launch {
+                lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                    launch {
+                        // We only want to animate if the view-model is updating in response to a
+                        // selection or deselection of the same exact option. For that, we save the
+                        // last value of isSelected.
+                        var lastSelected: Boolean? = null
+
+                        viewModel.key
+                            .flatMapLatest {
+                                // If the key changed, then it means that this binding is no longer
+                                // rendering the UI for the same option as before, we nullify the
+                                // last  selected value to "forget" that we've ever seen a value for
+                                // isSelected, effectively starting a new so the first update
+                                // doesn't animate.
+                                lastSelected = null
+                                viewModel.isSelected
+                            }
+                            .collect { isSelected ->
+                                val shouldAnimate =
+                                    lastSelected != null && lastSelected != isSelected
+                                if (shouldAnimate) {
+                                    animatedSelection(
+                                        backgroundView = backgroundView,
+                                        isSelected = isSelected,
+                                        animationSpec = animationSpec,
+                                    )
+                                } else {
+                                    backgroundView.setProgress(if (isSelected) 1f else 0f)
+                                }
+
+                                foregroundView?.setColorFilter(
+                                    if (isSelected) view.context.getColor(R.color.system_on_primary)
+                                    else view.context.getColor(R.color.system_on_surface)
+                                )
+
+                                view.isSelected = isSelected
+                                lastSelected = isSelected
+                            }
+                    }
+
+                    launch {
+                        viewModel.onClicked.collect { onClicked ->
+                            view.setOnClickListener(
+                                if (onClicked != null) {
+                                    View.OnClickListener { onClicked.invoke() }
+                                } else {
+                                    null
+                                }
+                            )
+                        }
+                    }
+                }
+            }
+
+        return DisposableHandle { job.cancel() }
+    }
+
+    private fun animatedSelection(
+        backgroundView: OptionItemBackground,
+        isSelected: Boolean,
+        animationSpec: AnimationSpec,
+    ) {
+        if (isSelected) {
+            val springForce =
+                SpringForce().apply {
+                    stiffness = SpringForce.STIFFNESS_MEDIUM
+                    dampingRatio = SpringForce.DAMPING_RATIO_HIGH_BOUNCY
+                    finalPosition = 1f
+                }
+
+            SpringAnimation(backgroundView, SpringAnimation.SCALE_X, 1f)
+                .apply {
+                    setStartVelocity(5f)
+                    spring = springForce
+                }
+                .start()
+
+            SpringAnimation(backgroundView, SpringAnimation.SCALE_Y, 1f)
+                .apply {
+                    setStartVelocity(5f)
+                    spring = springForce
+                }
+                .start()
+
+            ValueAnimator.ofFloat(0f, 1f)
+                .apply {
+                    duration = animationSpec.durationMs
+                    addUpdateListener {
+                        val progress = it.animatedValue as Float
+                        backgroundView.setProgress(progress)
+                    }
+                }
+                .start()
+        } else {
+            ValueAnimator.ofFloat(1f, 0f)
+                .apply {
+                    duration = animationSpec.durationMs
+                    addUpdateListener {
+                        val progress = it.animatedValue as Float
+                        backgroundView.setProgress(progress)
+                    }
+                }
+                .start()
+        }
+    }
+
+    data class AnimationSpec(
+        /** Opacity of the option when it's enabled. */
+        val enabledAlpha: Float = 1f,
+        /** Opacity of the option background when it's disabled. */
+        val disabledBackgroundAlpha: Float = 0.5f,
+        /** Opacity of the option foreground when it's disabled. */
+        val disabledForegroundAlpha: Float = 0.5f,
+        /** Opacity of the option text when it's disabled. */
+        val disabledTextAlpha: Float = 0.61f,
+        /** Duration of the animation, in milliseconds. */
+        val durationMs: Long = 333L,
+    )
+}
diff --git a/src/com/android/wallpaper/picker/option/ui/view/OptionItemBackground.kt b/src/com/android/wallpaper/picker/option/ui/view/OptionItemBackground.kt
new file mode 100644
index 00000000..bb57904c
--- /dev/null
+++ b/src/com/android/wallpaper/picker/option/ui/view/OptionItemBackground.kt
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
+package com.android.wallpaper.picker.option.ui.view
+
+import android.animation.ArgbEvaluator
+import android.content.Context
+import android.graphics.Canvas
+import android.graphics.Paint
+import android.util.AttributeSet
+import android.view.View
+import com.android.wallpaper.R
+
+open class OptionItemBackground
+@JvmOverloads
+constructor(context: Context, attrs: AttributeSet? = null, defStyleAttr: Int = 0) :
+    View(context, attrs, defStyleAttr) {
+
+    private val colorUnselected =
+        context.resources.getColor(R.color.system_surface_container_high, null)
+    private val colorSelected = context.resources.getColor(R.color.system_primary, null)
+    private val argbEvaluator = ArgbEvaluator()
+    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
+
+    // progress 0 is unselected and 1 is selected
+    var progress = 0f
+        private set
+
+    fun setProgress(progress: Float) {
+        this.progress = progress
+        invalidate()
+    }
+
+    override fun onDraw(canvas: Canvas) {
+        super.onDraw(canvas)
+
+        val width = width.toFloat()
+        val height = height.toFloat()
+        val cornerRadius = (width / 2) * (1f - 0.25f * progress)
+        paint.color = argbEvaluator.evaluate(progress, colorUnselected, colorSelected) as Int
+
+        canvas.drawRoundRect(0f, 0f, width, height, cornerRadius, cornerRadius, paint)
+    }
+}
diff --git a/src/com/android/wallpaper/picker/option/ui/viewmodel/OptionItemViewModel2.kt b/src/com/android/wallpaper/picker/option/ui/viewmodel/OptionItemViewModel2.kt
new file mode 100644
index 00000000..9b2c5615
--- /dev/null
+++ b/src/com/android/wallpaper/picker/option/ui/viewmodel/OptionItemViewModel2.kt
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
+ *
+ */
+
+package com.android.wallpaper.picker.option.ui.viewmodel
+
+import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.StateFlow
+
+/** Models UI state for an item in a list of selectable options. */
+data class OptionItemViewModel2<Payload>(
+    /**
+     * A stable key that uniquely identifies this option amongst all other options in the same list
+     * of options.
+     */
+    val key: StateFlow<String>,
+
+    /**
+     * The view model representing additional details needed for binding the icon of an option item
+     */
+    val payload: Payload? = null,
+
+    /**
+     * A text to show to the user (or attach as content description on the icon, if there's no
+     * dedicated view for it).
+     */
+    val text: Text,
+
+    /** Hides text and places the provided text in the content description instead */
+    val isTextUserVisible: Boolean = true,
+
+    /** Whether this option is selected. */
+    val isSelected: StateFlow<Boolean>,
+
+    /** Whether this option is enabled. */
+    val isEnabled: Boolean = true,
+
+    /** Notifies that the option has been clicked by the user. */
+    val onClicked: Flow<(() -> Unit)?>,
+
+    /** Notifies that the option has been long-clicked by the user. */
+    val onLongClicked: (() -> Unit)? = null,
+)
diff --git a/src/com/android/wallpaper/picker/preview/data/repository/CreativeEffectsRepository.kt b/src/com/android/wallpaper/picker/preview/data/repository/CreativeEffectsRepository.kt
index 1b520c65..f31d9b43 100644
--- a/src/com/android/wallpaper/picker/preview/data/repository/CreativeEffectsRepository.kt
+++ b/src/com/android/wallpaper/picker/preview/data/repository/CreativeEffectsRepository.kt
@@ -46,6 +46,12 @@ constructor(
 
     private var clearActionUri: Uri? = null
 
+    fun isEffectInitialized() = _creativeEffectsModel.value != null
+
+    // TODO (b/372890403): After either isNewPickerUi or isWallpaperCategoryRefactoringEnabled is
+    //  turned on and PersistentWallpaperModelRepository is used, we should inject
+    //  PersistentWallpaperModelRepository and listen to the view model data flow, instead of have
+    //  the WallpaperPreviewActivity calling initializeEffect when onCreate().
     suspend fun initializeEffect(data: CreativeWallpaperEffectsData) {
         withContext(bgDispatcher) {
             clearActionUri = data.clearActionUri
diff --git a/src/com/android/wallpaper/picker/preview/domain/interactor/WallpaperPreviewInteractor.kt b/src/com/android/wallpaper/picker/preview/domain/interactor/WallpaperPreviewInteractor.kt
index da6b835a..022507bc 100644
--- a/src/com/android/wallpaper/picker/preview/domain/interactor/WallpaperPreviewInteractor.kt
+++ b/src/com/android/wallpaper/picker/preview/domain/interactor/WallpaperPreviewInteractor.kt
@@ -16,18 +16,31 @@
 
 package com.android.wallpaper.picker.preview.domain.interactor
 
+import android.app.Flags.liveWallpaperContentHandling
 import android.app.WallpaperColors
+import android.content.Context
 import android.graphics.Bitmap
 import android.graphics.Point
 import android.graphics.Rect
+import android.net.Uri
+import android.util.Log
 import com.android.wallpaper.asset.Asset
+import com.android.wallpaper.model.CreativeCategory
+import com.android.wallpaper.model.CreativeWallpaperInfo
 import com.android.wallpaper.module.logging.UserEventLogger
 import com.android.wallpaper.picker.customization.data.repository.WallpaperRepository
 import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination
+import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination.Companion.toDestinationInt
+import com.android.wallpaper.picker.data.LiveWallpaperData
 import com.android.wallpaper.picker.data.WallpaperModel
+import com.android.wallpaper.picker.data.WallpaperModel.LiveWallpaperModel
 import com.android.wallpaper.picker.data.WallpaperModel.StaticWallpaperModel
 import com.android.wallpaper.picker.preview.data.repository.WallpaperPreviewRepository
 import com.android.wallpaper.picker.preview.shared.model.FullPreviewCropModel
+import com.android.wallpaper.util.converter.WallpaperModelFactory.Companion.getCommonWallpaperData
+import com.android.wallpaper.util.converter.WallpaperModelFactory.Companion.getCreativeWallpaperData
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
+import dagger.hilt.android.qualifiers.ApplicationContext
 import dagger.hilt.android.scopes.ActivityRetainedScoped
 import javax.inject.Inject
 import kotlinx.coroutines.flow.StateFlow
@@ -36,17 +49,21 @@ import kotlinx.coroutines.flow.StateFlow
 class WallpaperPreviewInteractor
 @Inject
 constructor(
+    @ApplicationContext private val context: Context,
     private val wallpaperPreviewRepository: WallpaperPreviewRepository,
     private val wallpaperRepository: WallpaperRepository,
+    private val wallpaperConnectionUtils: WallpaperConnectionUtils,
 ) {
     val wallpaperModel: StateFlow<WallpaperModel?> = wallpaperPreviewRepository.wallpaperModel
 
     val hasSmallPreviewTooltipBeenShown: StateFlow<Boolean> =
         wallpaperPreviewRepository.hasSmallPreviewTooltipBeenShown
+
     fun hideSmallPreviewTooltip() = wallpaperPreviewRepository.hideSmallPreviewTooltip()
 
     val hasFullPreviewTooltipBeenShown: StateFlow<Boolean> =
         wallpaperPreviewRepository.hasFullPreviewTooltipBeenShown
+
     fun hideFullPreviewTooltip() = wallpaperPreviewRepository.hideFullPreviewTooltip()
 
     suspend fun setStaticWallpaper(
@@ -72,15 +89,128 @@ constructor(
     suspend fun setLiveWallpaper(
         @UserEventLogger.SetWallpaperEntryPoint setWallpaperEntryPoint: Int,
         destination: WallpaperDestination,
-        wallpaperModel: WallpaperModel.LiveWallpaperModel,
+        wallpaperModel: LiveWallpaperModel,
     ) {
+        // TODO(b/376846928) Move these calls to a separate injected component
+        val updatedWallpaperModel =
+            applyAndUpdateLiveWallpaper(destination, wallpaperModel, wallpaperConnectionUtils)
+                ?: wallpaperModel
+
         wallpaperRepository.setLiveWallpaper(
             setWallpaperEntryPoint,
             destination,
-            wallpaperModel,
+            updatedWallpaperModel,
         )
     }
 
     suspend fun getWallpaperColors(bitmap: Bitmap, cropHints: Map<Point, Rect>?): WallpaperColors? =
         wallpaperRepository.getWallpaperColors(bitmap, cropHints)
+
+    private suspend fun applyAndUpdateLiveWallpaper(
+        destination: WallpaperDestination,
+        wallpaperModel: LiveWallpaperModel,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+    ): LiveWallpaperModel? {
+        if (liveWallpaperContentHandling()) {
+            try {
+                wallpaperConnectionUtils.applyWallpaper(destination, wallpaperModel)?.let {
+                    val description =
+                        if (it.component != null) {
+                            it
+                        } else {
+                            it.toBuilder()
+                                .setComponent(
+                                    wallpaperModel.liveWallpaperData.systemWallpaperInfo.component
+                                )
+                                .build()
+                        }
+                    val sourceLiveData = wallpaperModel.liveWallpaperData
+                    val updatedLiveData =
+                        LiveWallpaperData(
+                            sourceLiveData.groupName,
+                            sourceLiveData.systemWallpaperInfo,
+                            sourceLiveData.isTitleVisible,
+                            sourceLiveData.isApplied,
+                            sourceLiveData.isEffectWallpaper,
+                            sourceLiveData.effectNames,
+                            sourceLiveData.contextDescription,
+                            description,
+                        )
+                    return LiveWallpaperModel(
+                        wallpaperModel.commonWallpaperData,
+                        updatedLiveData,
+                        wallpaperModel.creativeWallpaperData,
+                        wallpaperModel.internalLiveWallpaperData,
+                    )
+                }
+            } catch (e: NoSuchMethodException) {
+                // Deliberate no-op, this means the apply function was not found
+            }
+        }
+
+        return wallpaperModel.creativeWallpaperData?.let {
+            saveCreativeWallpaperAtExternal(wallpaperModel, destination)
+        }
+    }
+
+    /**
+     * Call the external app to save the creative wallpaper, and return an updated model based on
+     * the response.
+     */
+    private fun saveCreativeWallpaperAtExternal(
+        wallpaperModel: LiveWallpaperModel,
+        destination: WallpaperDestination,
+    ): LiveWallpaperModel? {
+        wallpaperModel.getSaveWallpaperUriAndAuthority(destination)?.let { (uri, authority) ->
+            try {
+                context.contentResolver.acquireContentProviderClient(authority).use { client ->
+                    val cursor =
+                        client?.query(
+                            /* url= */ uri,
+                            /* projection= */ null,
+                            /* selection= */ null,
+                            /* selectionArgs= */ null,
+                            /* sortOrder= */ null,
+                        )
+                    if (cursor == null || !cursor.moveToFirst()) return null
+                    val info =
+                        CreativeWallpaperInfo.buildFromCursor(
+                            wallpaperModel.liveWallpaperData.systemWallpaperInfo,
+                            cursor,
+                        )
+                    // NB: need to regenerate common data to update the thumbnail asset
+                    return LiveWallpaperModel(
+                        info.getCommonWallpaperData(context),
+                        wallpaperModel.liveWallpaperData,
+                        info.getCreativeWallpaperData(),
+                        wallpaperModel.internalLiveWallpaperData,
+                    )
+                }
+            } catch (e: Exception) {
+                Log.e(TAG, "Failed updating creative live wallpaper at external.")
+            }
+        }
+        return null
+    }
+
+    /** Get the URI to call the external app to save the creative wallpaper. */
+    private fun LiveWallpaperModel.getSaveWallpaperUriAndAuthority(
+        destination: WallpaperDestination
+    ): Pair<Uri, String>? {
+        val uriString =
+            liveWallpaperData.systemWallpaperInfo.serviceInfo.metaData.getString(
+                CreativeCategory.KEY_WALLPAPER_SAVE_CREATIVE_CATEGORY_WALLPAPER
+            ) ?: return null
+        val uri =
+            Uri.parse(uriString)
+                ?.buildUpon()
+                ?.appendQueryParameter("destination", destination.toDestinationInt().toString())
+                ?.build() ?: return null
+        val authority = uri.authority ?: return null
+        return Pair(uri, authority)
+    }
+
+    companion object {
+        const val TAG = "WallpaperPreviewInteractor"
+    }
 }
diff --git a/src/com/android/wallpaper/picker/preview/ui/WallpaperPreviewActivity.kt b/src/com/android/wallpaper/picker/preview/ui/WallpaperPreviewActivity.kt
index 46c3f564..ef6ffeab 100644
--- a/src/com/android/wallpaper/picker/preview/ui/WallpaperPreviewActivity.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/WallpaperPreviewActivity.kt
@@ -98,19 +98,27 @@ class WallpaperPreviewActivity :
             refreshCreativeCategories = intent.getBooleanExtra(SHOULD_CATEGORY_REFRESH, false)
         }
 
-        val wallpaper: WallpaperModel? =
+        val wallpaper: WallpaperModel =
             if (isNewPickerUi || isCategoriesRefactorEnabled) {
-                persistentWallpaperModelRepository.wallpaperModel.value
-                    ?: intent
-                        .getParcelableExtra(EXTRA_WALLPAPER_INFO, WallpaperInfo::class.java)
-                        ?.convertToWallpaperModel()
+                val model =
+                    if (savedInstanceState != null) {
+                        wallpaperPreviewViewModel.wallpaper.value
+                    } else {
+                        persistentWallpaperModelRepository.wallpaperModel.value
+                            ?: intent
+                                .getParcelableExtra(EXTRA_WALLPAPER_INFO, WallpaperInfo::class.java)
+                                ?.convertToWallpaperModel()
+                    }
+                persistentWallpaperModelRepository.cleanup()
+                model
             } else {
                 intent
                     .getParcelableExtra(EXTRA_WALLPAPER_INFO, WallpaperInfo::class.java)
                     ?.convertToWallpaperModel()
-            }
-
-        wallpaper ?: throw UnsupportedOperationException()
+            } ?: throw IllegalStateException("No wallpaper for previewing")
+        if (savedInstanceState == null) {
+            wallpaperPreviewRepository.setWallpaperModel(wallpaper)
+        }
 
         val navController =
             (supportFragmentManager.findFragmentById(R.id.wallpaper_preview_nav_host)
@@ -132,9 +140,6 @@ class WallpaperPreviewActivity :
         WindowCompat.setDecorFitsSystemWindows(window, ActivityUtils.isSUWMode(this))
         val isAssetIdPresent = intent.getBooleanExtra(IS_ASSET_ID_PRESENT, false)
         wallpaperPreviewViewModel.isNewTask = intent.getBooleanExtra(IS_NEW_TASK, false)
-        if (savedInstanceState == null) {
-            wallpaperPreviewRepository.setWallpaperModel(wallpaper)
-        }
         val whichPreview =
             if (isAssetIdPresent) WallpaperConnection.WhichPreview.EDIT_NON_CURRENT
             else WallpaperConnection.WhichPreview.EDIT_CURRENT
@@ -150,7 +155,7 @@ class WallpaperPreviewActivity :
             liveWallpaperDownloader.initiateDownloadableService(
                 this,
                 wallpaper,
-                registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) {}
+                registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) {},
             )
         }
 
@@ -158,7 +163,9 @@ class WallpaperPreviewActivity :
             (wallpaper as? WallpaperModel.LiveWallpaperModel)
                 ?.creativeWallpaperData
                 ?.creativeWallpaperEffectsData
-        if (creativeWallpaperEffectData != null) {
+        if (
+            creativeWallpaperEffectData != null && !creativeEffectsRepository.isEffectInitialized()
+        ) {
             lifecycleScope.launch {
                 creativeEffectsRepository.initializeEffect(creativeWallpaperEffectData)
             }
@@ -195,15 +202,27 @@ class WallpaperPreviewActivity :
         }
     }
 
-    override fun onDestroy() {
+    override fun onPause() {
+        super.onPause()
+
+        // When back to main screen user could launch preview again before it's fully destroyed and
+        // it could clean up the repo set by the new launching call, move it earlier to on pause.
         if (isFinishing) {
             persistentWallpaperModelRepository.cleanup()
+        }
+    }
+
+    override fun onDestroy() {
+        if (isFinishing) {
             // ImageEffectsRepositoryImpl is Activity-Retained Scoped, and its injected
             // EffectsController is Singleton scoped. Therefore, persist state on config change
             // restart, and only destroy when activity is finishing.
             imageEffectsRepository.destroy()
+            // CreativeEffectsRepository is Activity-Retained Scoped, and its injected
+            // EffectsController is Singleton scoped. Therefore, persist state on config change
+            // restart, and only destroy when activity is finishing.
+            creativeEffectsRepository.destroy()
         }
-        creativeEffectsRepository.destroy()
         liveWallpaperDownloader.cleanup()
         // TODO(b/333879532): Only disconnect when leaving the Activity without introducing black
         //  preview. If onDestroy is caused by an orientation change, we should keep the connection
@@ -268,7 +287,7 @@ class WallpaperPreviewActivity :
             isAssetIdPresent: Boolean,
             isViewAsHome: Boolean = false,
             isNewTask: Boolean = false,
-            shouldCategoryRefresh: Boolean
+            shouldCategoryRefresh: Boolean,
         ): Intent {
             val isNewPickerUi = BaseFlags.get().isNewPickerUi()
             val isCategoriesRefactorEnabled =
@@ -329,7 +348,7 @@ class WallpaperPreviewActivity :
             isAssetIdPresent: Boolean,
             isViewAsHome: Boolean = false,
             isNewTask: Boolean = false,
-            shouldRefreshCategory: Boolean
+            shouldRefreshCategory: Boolean,
         ): Intent {
             val intent = Intent(context.applicationContext, WallpaperPreviewActivity::class.java)
             if (isNewTask) {
@@ -367,7 +386,7 @@ class WallpaperPreviewActivity :
                     ImageWallpaperInfo(data),
                     isAssetIdPresent,
                     isViewAsHome,
-                    isNewTask
+                    isNewTask,
                 )
             // Both these lines are required for permission propagation
             intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/ApplyWallpaperScreenBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/ApplyWallpaperScreenBinder.kt
new file mode 100644
index 00000000..cdb06a7e
--- /dev/null
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/ApplyWallpaperScreenBinder.kt
@@ -0,0 +1,82 @@
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
+package com.android.wallpaper.picker.preview.ui.binder
+
+import android.widget.Button
+import android.widget.CheckBox
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import com.android.wallpaper.picker.di.modules.MainDispatcher
+import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.launch
+
+/** Binds the set wallpaper button on small preview. */
+object ApplyWallpaperScreenBinder {
+
+    fun bind(
+        applyButton: Button,
+        cancelButton: Button,
+        homeCheckbox: CheckBox,
+        lockCheckbox: CheckBox,
+        viewModel: WallpaperPreviewViewModel,
+        lifecycleOwner: LifecycleOwner,
+        @MainDispatcher mainScope: CoroutineScope,
+        onWallpaperSet: () -> Unit,
+    ) {
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                launch {
+                    viewModel.onCancelButtonClicked.collect { onClicked ->
+                        cancelButton.setOnClickListener { onClicked() }
+                    }
+                }
+
+                launch { viewModel.isApplyButtonEnabled.collect { applyButton.isEnabled = it } }
+
+                launch { viewModel.isHomeCheckBoxChecked.collect { homeCheckbox.isChecked = it } }
+
+                launch { viewModel.isLockCheckBoxChecked.collect { lockCheckbox.isChecked = it } }
+
+                launch {
+                    viewModel.onHomeCheckBoxChecked.collect {
+                        homeCheckbox.setOnClickListener { it() }
+                    }
+                }
+
+                launch {
+                    viewModel.onLockCheckBoxChecked.collect {
+                        lockCheckbox.setOnClickListener { it() }
+                    }
+                }
+
+                launch {
+                    viewModel.setWallpaperDialogOnConfirmButtonClicked.collect { onClicked ->
+                        applyButton.setOnClickListener {
+                            mainScope.launch {
+                                onClicked()
+                                onWallpaperSet()
+                            }
+                        }
+                    }
+                }
+            }
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewPagerBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewPagerBinder.kt
index 948923f6..4db45268 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewPagerBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewPagerBinder.kt
@@ -18,7 +18,6 @@ package com.android.wallpaper.picker.preview.ui.binder
 import android.content.Context
 import android.view.View
 import android.view.View.OVER_SCROLL_NEVER
-import androidx.constraintlayout.motion.widget.MotionLayout
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
@@ -37,6 +36,7 @@ import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewMod
 import com.android.wallpaper.util.RtlUtils
 import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.DisposableHandle
 import kotlinx.coroutines.launch
 
@@ -46,10 +46,9 @@ object DualPreviewPagerBinder {
     fun bind(
         dualPreviewView: DualPreviewViewPager,
         wallpaperPreviewViewModel: WallpaperPreviewViewModel,
-        motionLayout: MotionLayout?,
         applicationContext: Context,
+        mainScope: CoroutineScope,
         viewLifecycleOwner: LifecycleOwner,
-        currentNavDestId: Int,
         transition: Transition?,
         transitionConfig: FullPreviewConfigViewModel?,
         wallpaperConnectionUtils: WallpaperConnectionUtils,
@@ -126,13 +125,13 @@ object DualPreviewPagerBinder {
                     SmallPreviewBinder.bind(
                         applicationContext = applicationContext,
                         view = dualDisplayAspectRatioLayout.requireViewById(display.getViewId()),
-                        motionLayout = motionLayout,
                         viewModel = wallpaperPreviewViewModel,
+                        mainScope = mainScope,
                         viewLifecycleOwner = viewLifecycleOwner,
                         screen = wallpaperPreviewViewModel.smallPreviewTabs[positionLTR],
                         displaySize = it,
                         deviceDisplayType = display,
-                        currentNavDestId = currentNavDestId,
+                        currentNavDestId = R.id.smallPreviewFragment,
                         transition = transition,
                         transitionConfig = transitionConfig,
                         wallpaperConnectionUtils = wallpaperConnectionUtils,
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewSelectorBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewSelectorBinder.kt
index 8942a69c..7809a7b0 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewSelectorBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/DualPreviewSelectorBinder.kt
@@ -17,7 +17,6 @@ package com.android.wallpaper.picker.preview.ui.binder
 
 import android.content.Context
 import android.view.View
-import androidx.constraintlayout.motion.widget.MotionLayout
 import androidx.lifecycle.LifecycleOwner
 import androidx.transition.Transition
 import com.android.wallpaper.picker.preview.ui.view.DualPreviewViewPager
@@ -26,6 +25,7 @@ import com.android.wallpaper.picker.preview.ui.viewmodel.FullPreviewConfigViewMo
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
 import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
 
 /**
  * This binder binds the data and view models for the dual preview collection on the small preview
@@ -36,11 +36,10 @@ object DualPreviewSelectorBinder {
     fun bind(
         tabs: PreviewTabs?,
         dualPreviewView: DualPreviewViewPager,
-        motionLayout: MotionLayout?,
         wallpaperPreviewViewModel: WallpaperPreviewViewModel,
         applicationContext: Context,
+        mainScope: CoroutineScope,
         viewLifecycleOwner: LifecycleOwner,
-        currentNavDestId: Int,
         transition: Transition?,
         transitionConfig: FullPreviewConfigViewModel?,
         wallpaperConnectionUtils: WallpaperConnectionUtils,
@@ -50,10 +49,9 @@ object DualPreviewSelectorBinder {
         DualPreviewPagerBinder.bind(
             dualPreviewView,
             wallpaperPreviewViewModel,
-            motionLayout,
             applicationContext,
+            mainScope,
             viewLifecycleOwner,
-            currentNavDestId,
             transition,
             transitionConfig,
             wallpaperConnectionUtils,
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/FullWallpaperPreviewBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/FullWallpaperPreviewBinder.kt
index e46cfdf5..9074ac60 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/FullWallpaperPreviewBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/FullWallpaperPreviewBinder.kt
@@ -52,6 +52,7 @@ import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils.C
 import java.lang.Integer.min
 import kotlin.math.max
 import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.DisposableHandle
 import kotlinx.coroutines.Job
 import kotlinx.coroutines.launch
@@ -65,6 +66,7 @@ object FullWallpaperPreviewBinder {
         viewModel: WallpaperPreviewViewModel,
         transition: Transition?,
         displayUtils: DisplayUtils,
+        mainScope: CoroutineScope,
         lifecycleOwner: LifecycleOwner,
         savedInstanceState: Bundle?,
         wallpaperConnectionUtils: WallpaperConnectionUtils,
@@ -79,20 +81,20 @@ object FullWallpaperPreviewBinder {
         var transitionDisposableHandle: DisposableHandle? = null
         val mediumAnimTimeMs =
             view.resources.getInteger(android.R.integer.config_mediumAnimTime).toLong()
+        val setFinalPreviewCardRadiusAndEndLoading = { isWallpaperFullScreen: Boolean ->
+            if (isWallpaperFullScreen) {
+                previewCard.radius = 0f
+            }
+            surfaceView.cornerRadius = previewCard.radius
+            scrimView.isVisible = isWallpaperFullScreen
+            onWallpaperLoaded?.invoke(isWallpaperFullScreen)
+        }
+
         lifecycleOwner.lifecycleScope.launch {
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                 viewModel.fullWallpaper.collect { (_, _, displaySize, _) ->
                     val currentSize = displayUtils.getRealSize(checkNotNull(view.context.display))
                     wallpaperPreviewCrop.setCurrentAndTargetDisplaySize(currentSize, displaySize)
-
-                    val setFinalPreviewCardRadiusAndEndLoading = { isWallpaperFullScreen: Boolean ->
-                        if (isWallpaperFullScreen) {
-                            previewCard.radius = 0f
-                        }
-                        surfaceView.cornerRadius = previewCard.radius
-                        scrimView.isVisible = isWallpaperFullScreen
-                        onWallpaperLoaded?.invoke(isWallpaperFullScreen)
-                    }
                     val isPreviewingFullScreen = displaySize == currentSize
                     if (transition == null || savedInstanceState != null) {
                         setFinalPreviewCardRadiusAndEndLoading(isPreviewingFullScreen)
@@ -116,6 +118,8 @@ object FullWallpaperPreviewBinder {
                                 override fun onTransitionEnd(transition: Transition) {
                                     super.onTransitionEnd(transition)
                                     setFinalPreviewCardRadiusAndEndLoading(isPreviewingFullScreen)
+                                    transitionDisposableHandle?.dispose()
+                                    transitionDisposableHandle = null
                                 }
                             }
                         transition.addListener(listener)
@@ -125,7 +129,9 @@ object FullWallpaperPreviewBinder {
                     }
                 }
             }
+            setFinalPreviewCardRadiusAndEndLoading(false)
             transitionDisposableHandle?.dispose()
+            transitionDisposableHandle = null
         }
         val surfaceTouchForwardingLayout: TouchForwardingLayout =
             view.requireViewById(R.id.touch_forwarding_layout)
@@ -167,6 +173,7 @@ object FullWallpaperPreviewBinder {
                         surfaceView = surfaceView,
                         surfaceTouchForwardingLayout = surfaceTouchForwardingLayout,
                         viewModel = viewModel,
+                        mainScope = mainScope,
                         lifecycleOwner = lifecycleOwner,
                         wallpaperConnectionUtils = wallpaperConnectionUtils,
                         isFirstBindingDeferred = isFirstBindingDeferred,
@@ -192,6 +199,7 @@ object FullWallpaperPreviewBinder {
         surfaceView: SurfaceView,
         surfaceTouchForwardingLayout: TouchForwardingLayout,
         viewModel: WallpaperPreviewViewModel,
+        mainScope: CoroutineScope,
         lifecycleOwner: LifecycleOwner,
         wallpaperConnectionUtils: WallpaperConnectionUtils,
         isFirstBindingDeferred: CompletableDeferred<Boolean>,
@@ -206,7 +214,8 @@ object FullWallpaperPreviewBinder {
             @SuppressLint("ClickableViewAccessibility")
             override fun surfaceCreated(holder: SurfaceHolder) {
                 job =
-                    lifecycleOwner.lifecycleScope.launch {
+                    // Ensure the wallpaper connection is connected / disconnected in [mainScope].
+                    mainScope.launch {
                         viewModel.fullWallpaper.collect {
                             (wallpaper, config, displaySize, allowUserCropping, whichPreview) ->
                             if (wallpaper is WallpaperModel.LiveWallpaperModel) {
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/PreviewActionsBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/PreviewActionsBinder.kt
index dfab6e81..ea829ef0 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/PreviewActionsBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/PreviewActionsBinder.kt
@@ -16,6 +16,7 @@
 package com.android.wallpaper.picker.preview.ui.binder
 
 import android.app.AlertDialog
+import android.app.Flags.liveWallpaperContentHandling
 import android.content.Intent
 import android.net.Uri
 import android.view.View
@@ -56,7 +57,7 @@ object PreviewActionsBinder {
     fun bind(
         actionGroup: PreviewActionGroup,
         floatingSheet: PreviewActionFloatingSheet,
-        motionLayout: MotionLayout? = null,
+        smallPreview: MotionLayout? = null,
         previewViewModel: WallpaperPreviewViewModel,
         actionsViewModel: PreviewActionsViewModel,
         deviceDisplayType: DeviceDisplayType,
@@ -81,10 +82,12 @@ object PreviewActionsBinder {
                     // when the view is not gone.
                     if (newState == STATE_HIDDEN) {
                         actionsViewModel.onFloatingSheetCollapsed()
-                        if (BaseFlags.get().isNewPickerUi()) motionLayout?.transitionToStart()
+                        if (BaseFlags.get().isNewPickerUi())
+                            smallPreview?.transitionToState(R.id.floating_sheet_gone)
                         else floatingSheet.isInvisible = true
                     } else {
-                        if (BaseFlags.get().isNewPickerUi()) motionLayout?.transitionToEnd()
+                        if (BaseFlags.get().isNewPickerUi())
+                            smallPreview?.transitionToState(R.id.floating_sheet_visible)
                         else floatingSheet.isInvisible = false
                     }
                 }
@@ -94,9 +97,9 @@ object PreviewActionsBinder {
         val noActionChecked = !actionsViewModel.isAnyActionChecked()
         if (BaseFlags.get().isNewPickerUi()) {
             if (noActionChecked) {
-                motionLayout?.transitionToStart()
+                smallPreview?.transitionToState(R.id.floating_sheet_gone)
             } else {
-                motionLayout?.transitionToEnd()
+                smallPreview?.transitionToState(R.id.floating_sheet_visible)
             }
         } else {
             floatingSheet.isInvisible = noActionChecked
@@ -367,18 +370,48 @@ object PreviewActionsBinder {
                             ) = floatingSheetViewModel
                             when {
                                 informationViewModel != null -> {
-                                    floatingSheet.setInformationContent(
-                                        informationViewModel.attributions,
-                                        informationViewModel.actionUrl?.let { url ->
-                                            {
-                                                logger.logWallpaperExploreButtonClicked()
-                                                floatingSheet.context.startActivity(
-                                                    Intent(Intent.ACTION_VIEW, Uri.parse(url))
-                                                )
-                                            }
-                                        },
-                                        informationViewModel.actionButtonTitle,
-                                    )
+                                    if (liveWallpaperContentHandling()) {
+                                        floatingSheet.setInformationContent(
+                                            description = informationViewModel.description,
+                                            attributions = informationViewModel.attributions,
+                                            onExploreButtonClickListener =
+                                                (informationViewModel.description?.contextUri
+                                                        ?: informationViewModel.actionUrl?.let {
+                                                            Uri.parse(it)
+                                                        })
+                                                    ?.let { uri ->
+                                                        {
+                                                            logger
+                                                                .logWallpaperExploreButtonClicked()
+                                                            floatingSheet.context.startActivity(
+                                                                Intent(Intent.ACTION_VIEW, uri)
+                                                            )
+                                                        }
+                                                    },
+                                            actionButtonTitle =
+                                                informationViewModel.description?.contextDescription
+                                                    ?: informationViewModel.actionButtonTitle,
+                                        )
+                                    } else {
+                                        floatingSheet.setInformationContent(
+                                            description = null,
+                                            attributions = informationViewModel.attributions,
+                                            onExploreButtonClickListener =
+                                                informationViewModel.actionUrl?.let { url ->
+                                                    {
+                                                        logger.logWallpaperExploreButtonClicked()
+                                                        floatingSheet.context.startActivity(
+                                                            Intent(
+                                                                Intent.ACTION_VIEW,
+                                                                Uri.parse(url),
+                                                            )
+                                                        )
+                                                    }
+                                                },
+                                            actionButtonTitle =
+                                                informationViewModel.actionButtonTitle,
+                                        )
+                                    }
                                 }
                                 imageEffectViewModel != null ->
                                     floatingSheet.setImageEffectContent(
@@ -422,4 +455,9 @@ object PreviewActionsBinder {
             }
         }
     }
+
+    private fun getActionUri(actionUrl: String?, contextUri: Uri?): Uri? {
+        val actionUri = actionUrl?.let { Uri.parse(actionUrl) }
+        return contextUri ?: actionUri
+    }
 }
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/PreviewPagerBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/PreviewPagerBinder.kt
index 8b7d3d8a..16139dc7 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/PreviewPagerBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/PreviewPagerBinder.kt
@@ -19,7 +19,6 @@ import android.annotation.SuppressLint
 import android.content.Context
 import android.graphics.Point
 import android.view.View
-import androidx.constraintlayout.motion.widget.MotionLayout
 import androidx.core.view.doOnLayout
 import androidx.core.view.doOnPreDraw
 import androidx.lifecycle.Lifecycle
@@ -39,6 +38,7 @@ import com.android.wallpaper.picker.preview.ui.viewmodel.FullPreviewConfigViewMo
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
 import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.launch
 
 /** Binds single preview home screen and lock screen tabs view pager. */
@@ -47,12 +47,11 @@ object PreviewPagerBinder {
     @SuppressLint("WrongConstant")
     fun bind(
         applicationContext: Context,
+        mainScope: CoroutineScope,
         viewLifecycleOwner: LifecycleOwner,
-        motionLayout: MotionLayout?,
         previewsViewPager: ViewPager2,
         wallpaperPreviewViewModel: WallpaperPreviewViewModel,
         previewDisplaySize: Point,
-        currentNavDestId: Int,
         transition: Transition?,
         transitionConfig: FullPreviewConfigViewModel?,
         wallpaperConnectionUtils: WallpaperConnectionUtils,
@@ -71,13 +70,13 @@ object PreviewPagerBinder {
                 SmallPreviewBinder.bind(
                     applicationContext = applicationContext,
                     view = viewHolder.itemView.requireViewById(R.id.preview),
-                    motionLayout = motionLayout,
                     viewModel = wallpaperPreviewViewModel,
                     screen = wallpaperPreviewViewModel.smallPreviewTabs[position],
                     displaySize = previewDisplaySize,
                     deviceDisplayType = DeviceDisplayType.SINGLE,
+                    mainScope = mainScope,
                     viewLifecycleOwner = viewLifecycleOwner,
-                    currentNavDestId = currentNavDestId,
+                    currentNavDestId = R.id.smallPreviewFragment,
                     transition = transition,
                     transitionConfig = transitionConfig,
                     isFirstBindingDeferred = isFirstBindingDeferred,
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/PreviewPagerBinder2.kt b/src/com/android/wallpaper/picker/preview/ui/binder/PreviewPagerBinder2.kt
new file mode 100644
index 00000000..cb212b17
--- /dev/null
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/PreviewPagerBinder2.kt
@@ -0,0 +1,122 @@
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
+package com.android.wallpaper.picker.preview.ui.binder
+
+import android.content.Context
+import android.graphics.Point
+import android.view.View
+import androidx.constraintlayout.motion.widget.MotionLayout
+import androidx.lifecycle.LifecycleOwner
+import androidx.transition.Transition
+import com.android.wallpaper.R
+import com.android.wallpaper.model.wallpaper.DeviceDisplayType
+import com.android.wallpaper.picker.preview.ui.view.ClickableMotionLayout
+import com.android.wallpaper.picker.preview.ui.view.DualDisplayAspectRatioLayout.Companion.getViewId
+import com.android.wallpaper.picker.preview.ui.view.DualDisplayAspectRatioLayout2
+import com.android.wallpaper.picker.preview.ui.viewmodel.FullPreviewConfigViewModel
+import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
+import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
+
+/** Binds single preview home screen and lock screen tabs view pager. */
+object PreviewPagerBinder2 {
+
+    private val pagerItems = linkedSetOf(R.id.lock_preview, R.id.home_preview)
+    private val commonClickableViewIds =
+        listOf(R.id.apply_button, R.id.cancel_button, R.id.home_checkbox, R.id.lock_checkbox)
+
+    fun bind(
+        applicationContext: Context,
+        mainScope: CoroutineScope,
+        lifecycleOwner: LifecycleOwner,
+        smallPreview: MotionLayout,
+        viewModel: WallpaperPreviewViewModel,
+        previewDisplaySize: Point,
+        transition: Transition?,
+        transitionConfig: FullPreviewConfigViewModel?,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
+        isFoldable: Boolean,
+        navigate: (View) -> Unit,
+    ) {
+        val previewPager = smallPreview.requireViewById<ClickableMotionLayout>(R.id.preview_pager)
+        pagerItems.forEach { item ->
+            val container = previewPager.requireViewById<View>(item)
+            PreviewTooltipBinder.bindSmallPreviewTooltip(
+                tooltipStub = container.requireViewById(R.id.small_preview_tooltip_stub),
+                viewModel = viewModel.smallTooltipViewModel,
+                lifecycleOwner = lifecycleOwner,
+            )
+
+            if (isFoldable) {
+                val dualDisplayAspectRatioLayout: DualDisplayAspectRatioLayout2 =
+                    container.requireViewById(R.id.dual_preview)
+                val displaySizes =
+                    mapOf(
+                        DeviceDisplayType.FOLDED to viewModel.smallerDisplaySize,
+                        DeviceDisplayType.UNFOLDED to viewModel.wallpaperDisplaySize.value,
+                    )
+                dualDisplayAspectRatioLayout.setDisplaySizes(displaySizes)
+                previewPager.setClickableViewIds(
+                    commonClickableViewIds.toList() +
+                        DeviceDisplayType.FOLDABLE_DISPLAY_TYPES.map { it.getViewId() }
+                )
+                DeviceDisplayType.FOLDABLE_DISPLAY_TYPES.forEach { display ->
+                    dualDisplayAspectRatioLayout.getPreviewDisplaySize(display)?.let { displaySize
+                        ->
+                        SmallPreviewBinder.bind(
+                            applicationContext = applicationContext,
+                            view =
+                                dualDisplayAspectRatioLayout.requireViewById(display.getViewId()),
+                            viewModel = viewModel,
+                            screen = viewModel.smallPreviewTabs[pagerItems.indexOf(item)],
+                            displaySize = displaySize,
+                            deviceDisplayType = display,
+                            mainScope = mainScope,
+                            viewLifecycleOwner = lifecycleOwner,
+                            currentNavDestId = R.id.smallPreviewFragment,
+                            transition = transition,
+                            transitionConfig = transitionConfig,
+                            wallpaperConnectionUtils = wallpaperConnectionUtils,
+                            isFirstBindingDeferred = isFirstBindingDeferred,
+                            navigate = navigate,
+                        )
+                    }
+                }
+            } else {
+                val previewViewId = R.id.preview
+                previewPager.setClickableViewIds(commonClickableViewIds.toList() + previewViewId)
+                SmallPreviewBinder.bind(
+                    applicationContext = applicationContext,
+                    view = container.requireViewById(previewViewId),
+                    viewModel = viewModel,
+                    screen = viewModel.smallPreviewTabs[pagerItems.indexOf(item)],
+                    displaySize = previewDisplaySize,
+                    deviceDisplayType = DeviceDisplayType.SINGLE,
+                    mainScope = mainScope,
+                    viewLifecycleOwner = lifecycleOwner,
+                    currentNavDestId = R.id.smallPreviewFragment,
+                    transition = transition,
+                    transitionConfig = transitionConfig,
+                    wallpaperConnectionUtils = wallpaperConnectionUtils,
+                    isFirstBindingDeferred = isFirstBindingDeferred,
+                    navigate = navigate,
+                )
+            }
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/PreviewSelectorBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/PreviewSelectorBinder.kt
index 819e9600..89a52396 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/PreviewSelectorBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/PreviewSelectorBinder.kt
@@ -18,7 +18,6 @@ package com.android.wallpaper.picker.preview.ui.binder
 import android.content.Context
 import android.graphics.Point
 import android.view.View
-import androidx.constraintlayout.motion.widget.MotionLayout
 import androidx.lifecycle.LifecycleOwner
 import androidx.transition.Transition
 import androidx.viewpager2.widget.ViewPager2
@@ -27,41 +26,37 @@ import com.android.wallpaper.picker.preview.ui.viewmodel.FullPreviewConfigViewMo
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
 import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
 
 /** Binds and synchronizes the tab and preview view pagers. */
 object PreviewSelectorBinder {
-
     fun bind(
         tabs: PreviewTabs?,
-        previewsViewPager: ViewPager2,
-        motionLayout: MotionLayout?,
+        previewsViewPager: ViewPager2?,
         previewDisplaySize: Point,
         wallpaperPreviewViewModel: WallpaperPreviewViewModel,
         applicationContext: Context,
+        mainScope: CoroutineScope,
         viewLifecycleOwner: LifecycleOwner,
-        currentNavDestId: Int,
         transition: Transition?,
         transitionConfig: FullPreviewConfigViewModel?,
         wallpaperConnectionUtils: WallpaperConnectionUtils,
         isFirstBindingDeferred: CompletableDeferred<Boolean>,
         navigate: (View) -> Unit,
     ) {
-        // set up previews view pager
         PreviewPagerBinder.bind(
             applicationContext,
+            mainScope,
             viewLifecycleOwner,
-            motionLayout,
-            previewsViewPager,
+            checkNotNull(previewsViewPager),
             wallpaperPreviewViewModel,
             previewDisplaySize,
-            currentNavDestId,
             transition,
             transitionConfig,
             wallpaperConnectionUtils,
             isFirstBindingDeferred,
             navigate,
         )
-
         tabs?.let { TabsBinder.bind(it, wallpaperPreviewViewModel, viewLifecycleOwner) }
     }
 }
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/SetWallpaperDialogBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/SetWallpaperDialogBinder.kt
index ff82bfdd..26a5364f 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/SetWallpaperDialogBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/SetWallpaperDialogBinder.kt
@@ -41,7 +41,7 @@ object SetWallpaperDialogBinder {
     private val PreviewScreenIds =
         mapOf(
             Screen.LOCK_SCREEN to R.id.lock_preview_selector,
-            Screen.HOME_SCREEN to R.id.home_preview_selector
+            Screen.HOME_SCREEN to R.id.home_preview_selector,
         )
 
     fun bind(
@@ -51,7 +51,6 @@ object SetWallpaperDialogBinder {
         handheldDisplaySize: Point,
         lifecycleOwner: LifecycleOwner,
         mainScope: CoroutineScope,
-        currentNavDestId: Int,
         onFinishActivity: () -> Unit,
         onDismissDialog: () -> Unit,
         wallpaperConnectionUtils: WallpaperConnectionUtils,
@@ -65,8 +64,8 @@ object SetWallpaperDialogBinder {
             bindFoldablePreview(
                 previewLayout,
                 wallpaperPreviewViewModel,
+                mainScope,
                 lifecycleOwner,
-                currentNavDestId,
                 wallpaperConnectionUtils,
                 isFirstBinding,
                 navigate,
@@ -76,8 +75,8 @@ object SetWallpaperDialogBinder {
                 previewLayout,
                 wallpaperPreviewViewModel,
                 handheldDisplaySize,
+                mainScope,
                 lifecycleOwner,
-                currentNavDestId,
                 wallpaperConnectionUtils,
                 isFirstBinding,
                 navigate,
@@ -130,8 +129,8 @@ object SetWallpaperDialogBinder {
     private fun bindFoldablePreview(
         previewLayout: View,
         wallpaperPreviewViewModel: WallpaperPreviewViewModel,
+        mainScope: CoroutineScope,
         lifecycleOwner: LifecycleOwner,
-        currentNavDestId: Int,
         wallpaperConnectionUtils: WallpaperConnectionUtils,
         isFirstBinding: Boolean,
         navigate: ((View) -> Unit)?,
@@ -158,11 +157,12 @@ object SetWallpaperDialogBinder {
                         applicationContext = previewLayout.context.applicationContext,
                         view = view,
                         viewModel = wallpaperPreviewViewModel,
+                        mainScope = mainScope,
                         viewLifecycleOwner = lifecycleOwner,
                         screen = screenId.key,
                         displaySize = it,
                         deviceDisplayType = display,
-                        currentNavDestId = currentNavDestId,
+                        currentNavDestId = R.id.setWallpaperDialog,
                         wallpaperConnectionUtils = wallpaperConnectionUtils,
                         isFirstBindingDeferred = CompletableDeferred(isFirstBinding),
                         navigate = navigate,
@@ -176,8 +176,8 @@ object SetWallpaperDialogBinder {
         previewLayout: View,
         wallpaperPreviewViewModel: WallpaperPreviewViewModel,
         displaySize: Point,
+        mainScope: CoroutineScope,
         lifecycleOwner: LifecycleOwner,
-        currentNavDestId: Int,
         wallpaperConnectionUtils: WallpaperConnectionUtils,
         isFirstBinding: Boolean,
         navigate: ((View) -> Unit)?,
@@ -195,8 +195,9 @@ object SetWallpaperDialogBinder {
                 screen = screenId.key,
                 displaySize = displaySize,
                 deviceDisplayType = DeviceDisplayType.SINGLE,
+                mainScope = mainScope,
                 viewLifecycleOwner = lifecycleOwner,
-                currentNavDestId = currentNavDestId,
+                currentNavDestId = R.id.setWallpaperDialog,
                 isFirstBindingDeferred = CompletableDeferred(isFirstBinding),
                 wallpaperConnectionUtils = wallpaperConnectionUtils,
                 navigate = navigate,
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/SmallPreviewBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/SmallPreviewBinder.kt
index 19892404..d30f64cd 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/SmallPreviewBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/SmallPreviewBinder.kt
@@ -20,7 +20,6 @@ import android.graphics.Point
 import android.view.SurfaceView
 import android.view.View
 import androidx.cardview.widget.CardView
-import androidx.constraintlayout.motion.widget.MotionLayout
 import androidx.core.view.ViewCompat
 import androidx.core.view.isVisible
 import androidx.lifecycle.Lifecycle
@@ -30,16 +29,18 @@ import androidx.lifecycle.repeatOnLifecycle
 import androidx.transition.Transition
 import androidx.transition.TransitionListenerAdapter
 import com.android.wallpaper.R
+import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.model.Screen
 import com.android.wallpaper.model.wallpaper.DeviceDisplayType
-import com.android.wallpaper.picker.common.preview.ui.view.CustomizationSurfaceView
-import com.android.wallpaper.picker.customization.ui.CustomizationPickerActivity2
 import com.android.wallpaper.picker.preview.ui.fragment.SmallPreviewFragment
 import com.android.wallpaper.picker.preview.ui.viewmodel.FullPreviewConfigViewModel
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
+import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel.Companion.PreviewScreen
 import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.DisposableHandle
+import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.launch
 
 object SmallPreviewBinder {
@@ -47,11 +48,11 @@ object SmallPreviewBinder {
     fun bind(
         applicationContext: Context,
         view: View,
-        motionLayout: MotionLayout? = null,
         viewModel: WallpaperPreviewViewModel,
         screen: Screen,
         displaySize: Point,
         deviceDisplayType: DeviceDisplayType,
+        mainScope: CoroutineScope,
         viewLifecycleOwner: LifecycleOwner,
         currentNavDestId: Int,
         navigate: ((View) -> Unit)? = null,
@@ -75,26 +76,15 @@ object SmallPreviewBinder {
                 R.string.wallpaper_preview_card_content_description_editable,
                 foldedStateDescription,
             )
-        val wallpaperSurface =
-            view.requireViewById<SurfaceView>(R.id.wallpaper_surface).apply {
-                // When putting the surface on top for full transition, the card view is behind the
-                // surface view so we need to apply radius on surface view instead
-                cornerRadius = previewCard.radius
-            }
-        val workspaceSurface: SurfaceView = view.requireViewById(R.id.workspace_surface)
+        val wallpaperSurface = view.requireViewById<SurfaceView>(R.id.wallpaper_surface)
 
-        motionLayout?.addTransitionListener(
-            object : CustomizationPickerActivity2.EmptyTransitionListener {
-                override fun onTransitionStarted(
-                    motionLayout: MotionLayout?,
-                    startId: Int,
-                    endId: Int,
-                ) {
-                    (wallpaperSurface as CustomizationSurfaceView).setTransitioning()
-                    (workspaceSurface as CustomizationSurfaceView).setTransitioning()
-                }
-            }
-        )
+        // Don't set radius for set wallpaper dialog
+        if (!viewModel.showSetWallpaperDialog.value) {
+            // When putting the surface on top for full transition, the card view is behind the
+            // surface view so we need to apply radius on surface view instead
+            wallpaperSurface.cornerRadius = previewCard.radius
+        }
+        val workspaceSurface: SurfaceView = view.requireViewById(R.id.workspace_surface)
 
         // Set transition names to enable the small to full preview enter and return shared
         // element transitions.
@@ -183,15 +173,24 @@ object SmallPreviewBinder {
                 }
 
                 if (R.id.smallPreviewFragment == currentNavDestId) {
-                    viewModel
-                        .onSmallPreviewClicked(screen, deviceDisplayType) {
-                            navigate?.invoke(previewCard)
+                    combine(
+                            viewModel.onSmallPreviewClicked(screen, deviceDisplayType) {
+                                navigate?.invoke(previewCard)
+                            },
+                            viewModel.currentPreviewScreen,
+                            viewModel.smallPreviewSelectedTab,
+                        ) { onClick, previewScreen, tab ->
+                            Triple(onClick, previewScreen, tab)
                         }
-                        .collect { onClick ->
-                            if (onClick != null) {
-                                view.setOnClickListener { onClick() }
-                            } else {
+                        .collect { (onClick, previewScreen, tab) ->
+                            if (
+                                BaseFlags.get().isNewPickerUi() &&
+                                    previewScreen != PreviewScreen.SMALL_PREVIEW
+                            ) {
                                 view.setOnClickListener(null)
+                            } else {
+                                onClick?.let { view.setOnClickListener { it() } }
+                                    ?: view.setOnClickListener(null)
                             }
                         }
                 } else if (R.id.setWallpaperDialog == currentNavDestId) {
@@ -216,6 +215,7 @@ object SmallPreviewBinder {
             viewModel = viewModel,
             displaySize = displaySize,
             applicationContext = applicationContext,
+            mainScope = mainScope,
             viewLifecycleOwner = viewLifecycleOwner,
             deviceDisplayType = deviceDisplayType,
             wallpaperConnectionUtils = wallpaperConnectionUtils,
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/SmallPreviewScreenBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/SmallPreviewScreenBinder.kt
new file mode 100644
index 00000000..6bd47e36
--- /dev/null
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/SmallPreviewScreenBinder.kt
@@ -0,0 +1,148 @@
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
+package com.android.wallpaper.picker.preview.ui.binder
+
+import android.content.Context
+import android.graphics.Point
+import android.view.View
+import android.widget.Button
+import androidx.constraintlayout.motion.widget.MotionLayout
+import androidx.core.view.isVisible
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import androidx.transition.Transition
+import com.android.wallpaper.R
+import com.android.wallpaper.model.Screen
+import com.android.wallpaper.picker.preview.ui.view.ClickableMotionLayout
+import com.android.wallpaper.picker.preview.ui.viewmodel.FullPreviewConfigViewModel
+import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
+import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel.Companion.PreviewScreen
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
+import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.launch
+
+object SmallPreviewScreenBinder {
+    fun bind(
+        applicationContext: Context,
+        mainScope: CoroutineScope,
+        lifecycleOwner: LifecycleOwner,
+        fragmentLayout: MotionLayout,
+        viewModel: WallpaperPreviewViewModel,
+        previewDisplaySize: Point,
+        transition: Transition?,
+        transitionConfig: FullPreviewConfigViewModel?,
+        wallpaperConnectionUtils: WallpaperConnectionUtils,
+        isFirstBindingDeferred: CompletableDeferred<Boolean>,
+        isFoldable: Boolean,
+        navigate: (View) -> Unit,
+    ) {
+        val previewPager = fragmentLayout.requireViewById<ClickableMotionLayout>(R.id.preview_pager)
+        val previewPagerContainer =
+            fragmentLayout.requireViewById<MotionLayout>(R.id.small_preview_container)
+        val nextButton = fragmentLayout.requireViewById<Button>(R.id.button_next)
+
+        PreviewPagerBinder2.bind(
+            applicationContext,
+            mainScope,
+            lifecycleOwner,
+            previewPagerContainer,
+            viewModel,
+            previewDisplaySize,
+            transition,
+            transitionConfig,
+            wallpaperConnectionUtils,
+            isFirstBindingDeferred,
+            isFoldable,
+            navigate,
+        )
+
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                launch {
+                    combine(
+                            viewModel.currentPreviewScreen,
+                            viewModel.smallPreviewSelectedTab,
+                            viewModel.previewActionsViewModel.isActionChecked,
+                        ) { screen, tab, actionChecked ->
+                            Triple(screen, tab, actionChecked)
+                        }
+                        .collect { (screen, tab, isActionChecked) ->
+                            when (screen) {
+                                PreviewScreen.SMALL_PREVIEW -> {
+                                    fragmentLayout.transitionToState(R.id.show_full_page)
+                                    previewPagerContainer.transitionToState(
+                                        if (isActionChecked) R.id.floating_sheet_visible
+                                        else R.id.floating_sheet_gone
+                                    )
+                                    // TODO(b/367374790): Use jumpToState for shared element
+                                    //  transition back from PreviewScreen.FULL_PREVIEW, until full
+                                    //  preview fragment is removed.
+                                    previewPager.transitionToState(
+                                        if (tab == Screen.LOCK_SCREEN) R.id.lock_preview_selected
+                                        else R.id.home_preview_selected
+                                    )
+                                }
+                                PreviewScreen.FULL_PREVIEW -> {
+                                    // TODO(b/367374790): Transition to full preview
+                                }
+                                PreviewScreen.APPLY_WALLPAPER -> {
+                                    fragmentLayout.transitionToState(R.id.hide_page_header)
+                                    previewPagerContainer.transitionToState(
+                                        R.id.show_apply_wallpaper
+                                    )
+                                    previewPager.transitionToState(
+                                        if (isFoldable) R.id.apply_wallpaper_lock_preview_selected
+                                        else R.id.apply_wallpaper_preview_only
+                                    )
+                                }
+                            }
+                        }
+                }
+
+                launch {
+                    viewModel.shouldEnableClickOnPager.collect {
+                        previewPager.shouldInterceptTouch = it
+                    }
+                }
+
+                launch {
+                    viewModel.isSetWallpaperButtonVisible.collect { nextButton.isVisible = it }
+                }
+
+                launch {
+                    viewModel.isSetWallpaperButtonEnabled.collect { nextButton.isEnabled = it }
+                }
+
+                launch {
+                    viewModel.onNextButtonClicked.collect { onClicked ->
+                        nextButton.setOnClickListener(
+                            if (onClicked != null) {
+                                { onClicked() }
+                            } else {
+                                null
+                            }
+                        )
+                    }
+                }
+            }
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/SmallWallpaperPreviewBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/SmallWallpaperPreviewBinder.kt
index 2bc201e3..cdd3e505 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/SmallWallpaperPreviewBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/SmallWallpaperPreviewBinder.kt
@@ -36,6 +36,7 @@ import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils.Companion.shouldEnforceSingleEngine
 import com.android.wallpaper.util.wallpaperconnection.WallpaperEngineConnection.WallpaperEngineConnectionListener
 import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.Job
 import kotlinx.coroutines.launch
 
@@ -54,6 +55,7 @@ object SmallWallpaperPreviewBinder {
         viewModel: WallpaperPreviewViewModel,
         displaySize: Point,
         applicationContext: Context,
+        mainScope: CoroutineScope,
         viewLifecycleOwner: LifecycleOwner,
         deviceDisplayType: DeviceDisplayType,
         wallpaperConnectionUtils: WallpaperConnectionUtils,
@@ -69,6 +71,7 @@ object SmallWallpaperPreviewBinder {
                         viewModel = viewModel,
                         deviceDisplayType = deviceDisplayType,
                         displaySize = displaySize,
+                        mainScope = mainScope,
                         lifecycleOwner = viewLifecycleOwner,
                         wallpaperConnectionUtils = wallpaperConnectionUtils,
                         isFirstBindingDeferred,
@@ -95,6 +98,7 @@ object SmallWallpaperPreviewBinder {
         viewModel: WallpaperPreviewViewModel,
         deviceDisplayType: DeviceDisplayType,
         displaySize: Point,
+        mainScope: CoroutineScope,
         lifecycleOwner: LifecycleOwner,
         wallpaperConnectionUtils: WallpaperConnectionUtils,
         isFirstBindingDeferred: CompletableDeferred<Boolean>,
@@ -107,7 +111,8 @@ object SmallWallpaperPreviewBinder {
 
             override fun surfaceCreated(holder: SurfaceHolder) {
                 job =
-                    lifecycleOwner.lifecycleScope.launch {
+                    // Ensure the wallpaper connection is connected / disconnected in [mainScope].
+                    mainScope.launch {
                         viewModel.smallWallpaper.collect { (wallpaper, whichPreview) ->
                             if (wallpaper is WallpaperModel.LiveWallpaperModel) {
                                 wallpaperConnectionUtils.connect(
diff --git a/src/com/android/wallpaper/picker/preview/ui/binder/StaticWallpaperPreviewBinder.kt b/src/com/android/wallpaper/picker/preview/ui/binder/StaticWallpaperPreviewBinder.kt
index d62c9e32..0c8f78dc 100644
--- a/src/com/android/wallpaper/picker/preview/ui/binder/StaticWallpaperPreviewBinder.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/binder/StaticWallpaperPreviewBinder.kt
@@ -223,7 +223,7 @@ object StaticWallpaperPreviewBinder {
         preview.layout(0, 0, width, height)
 
         fullResView.setSurfaceSize(Point(width, height))
-        surfaceView.attachView(fullResView, width, height)
+        surfaceView.attachView(preview, width, height)
     }
 
     private const val TAG = "StaticWallpaperPreviewBinder"
diff --git a/src/com/android/wallpaper/picker/preview/ui/fragment/CreativeEditPreviewFragment.kt b/src/com/android/wallpaper/picker/preview/ui/fragment/CreativeEditPreviewFragment.kt
index f13e95da..3b45e411 100644
--- a/src/com/android/wallpaper/picker/preview/ui/fragment/CreativeEditPreviewFragment.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/fragment/CreativeEditPreviewFragment.kt
@@ -16,6 +16,8 @@
 package com.android.wallpaper.picker.preview.ui.fragment
 
 import android.app.Activity.RESULT_OK
+import android.app.Flags.liveWallpaperContentHandling
+import android.app.wallpaper.WallpaperDescription
 import android.content.Context
 import android.content.Intent
 import android.os.Bundle
@@ -31,7 +33,12 @@ import androidx.core.view.isVisible
 import androidx.fragment.app.activityViewModels
 import androidx.navigation.fragment.findNavController
 import com.android.wallpaper.R
+import com.android.wallpaper.model.WallpaperInfoContract
 import com.android.wallpaper.picker.AppbarFragment
+import com.android.wallpaper.picker.data.LiveWallpaperData
+import com.android.wallpaper.picker.data.WallpaperModel.LiveWallpaperModel
+import com.android.wallpaper.picker.di.modules.MainDispatcher
+import com.android.wallpaper.picker.preview.data.repository.WallpaperPreviewRepository
 import com.android.wallpaper.picker.preview.ui.binder.FullWallpaperPreviewBinder
 import com.android.wallpaper.picker.preview.ui.fragment.SmallPreviewFragment.Companion.ARG_EDIT_INTENT
 import com.android.wallpaper.picker.preview.ui.viewmodel.PreviewActionsViewModel
@@ -42,13 +49,17 @@ import dagger.hilt.android.AndroidEntryPoint
 import dagger.hilt.android.qualifiers.ApplicationContext
 import javax.inject.Inject
 import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.runBlocking
 
 /** Shows full preview with an edit activity overlay. */
 @AndroidEntryPoint(AppbarFragment::class)
 class CreativeEditPreviewFragment : Hilt_CreativeEditPreviewFragment() {
 
     @Inject @ApplicationContext lateinit var appContext: Context
+    @Inject @MainDispatcher lateinit var mainScope: CoroutineScope
     @Inject lateinit var displayUtils: DisplayUtils
+    @Inject lateinit var previewRepository: WallpaperPreviewRepository
     @Inject lateinit var wallpaperConnectionUtils: WallpaperConnectionUtils
 
     private lateinit var currentView: View
@@ -58,13 +69,13 @@ class CreativeEditPreviewFragment : Hilt_CreativeEditPreviewFragment() {
     override fun onCreateView(
         inflater: LayoutInflater,
         container: ViewGroup?,
-        savedInstanceState: Bundle?
+        savedInstanceState: Bundle?,
     ): View? {
         currentView = inflater.inflate(R.layout.fragment_full_preview, container, false)
         setUpToolbar(currentView, true, true)
 
         wallpaperPreviewViewModel.setDefaultFullPreviewConfigViewModel(
-            deviceDisplayType = displayUtils.getCurrentDisplayType(requireActivity()),
+            deviceDisplayType = displayUtils.getCurrentDisplayType(requireActivity())
         )
 
         currentView.requireViewById<Toolbar>(R.id.toolbar).isVisible = false
@@ -82,7 +93,7 @@ class CreativeEditPreviewFragment : Hilt_CreativeEditPreviewFragment() {
             if (isCreateNew) {
                 requireActivity().activityResultRegistry.register(
                     CREATIVE_RESULT_REGISTRY,
-                    ActivityResultContracts.StartActivityForResult()
+                    ActivityResultContracts.StartActivityForResult(),
                 ) {
                     // Reset full preview view model to disable full to small preview transition
                     wallpaperPreviewViewModel.resetFullPreviewConfigViewModel()
@@ -91,6 +102,9 @@ class CreativeEditPreviewFragment : Hilt_CreativeEditPreviewFragment() {
                     // RESULT_OK means the user clicked on the check button; RESULT_CANCELED
                     // otherwise.
                     if (it.resultCode == RESULT_OK) {
+                        if (liveWallpaperContentHandling()) {
+                            updatePreview(it.resultCode, it.data)
+                        }
                         // When clicking on the check button, navigate to the small preview
                         // fragment.
                         findNavController()
@@ -111,6 +125,9 @@ class CreativeEditPreviewFragment : Hilt_CreativeEditPreviewFragment() {
 
                         override fun parseResult(resultCode: Int, intent: Intent?): Int {
                             wallpaperPreviewViewModel.isCurrentlyEditingCreativeWallpaper = false
+                            if (liveWallpaperContentHandling()) {
+                                updatePreview(resultCode, intent)
+                            }
                             return resultCode
                         }
                     },
@@ -129,6 +146,57 @@ class CreativeEditPreviewFragment : Hilt_CreativeEditPreviewFragment() {
         return currentView
     }
 
+    // Updates the current preview using the WallpaperDescription returned with the Intent if any
+    private fun updatePreview(resultCode: Int, intent: Intent?) {
+        if (!liveWallpaperContentHandling()) return
+        if (resultCode == RESULT_OK) {
+            val component =
+                (previewRepository.wallpaperModel.value as LiveWallpaperModel)
+                    .liveWallpaperData
+                    .systemWallpaperInfo
+                    .component
+            intent
+                ?.extras
+                ?.getParcelable(
+                    WallpaperInfoContract.WALLPAPER_DESCRIPTION_CONTENT_HANDLING,
+                    WallpaperDescription::class.java,
+                )
+                ?.let {
+                    if (it.component != null) {
+                        it
+                    } else {
+                        // Live wallpaper services can't provide their component name, so
+                        // set it here
+                        it.toBuilder().setComponent(component).build()
+                    }
+                }
+                ?.let { description ->
+                    (previewRepository.wallpaperModel.value as LiveWallpaperModel).let {
+                        val sourceLiveData = it.liveWallpaperData
+                        val updatedLiveData =
+                            LiveWallpaperData(
+                                sourceLiveData.groupName,
+                                sourceLiveData.systemWallpaperInfo,
+                                sourceLiveData.isTitleVisible,
+                                sourceLiveData.isApplied,
+                                sourceLiveData.isEffectWallpaper,
+                                sourceLiveData.effectNames,
+                                sourceLiveData.contextDescription,
+                                description,
+                            )
+                        val updatedWallpaper =
+                            LiveWallpaperModel(
+                                it.commonWallpaperData,
+                                updatedLiveData,
+                                it.creativeWallpaperData,
+                                it.internalLiveWallpaperData,
+                            )
+                        runBlocking { previewRepository.setWallpaperModel(updatedWallpaper) }
+                    }
+                }
+        }
+    }
+
     override fun onViewStateRestored(savedInstanceState: Bundle?) {
         super.onViewStateRestored(savedInstanceState)
 
@@ -138,10 +206,11 @@ class CreativeEditPreviewFragment : Hilt_CreativeEditPreviewFragment() {
             viewModel = wallpaperPreviewViewModel,
             transition = null,
             displayUtils = displayUtils,
+            mainScope = mainScope,
             lifecycleOwner = viewLifecycleOwner,
             savedInstanceState = savedInstanceState,
             wallpaperConnectionUtils = wallpaperConnectionUtils,
-            isFirstBindingDeferred = CompletableDeferred(savedInstanceState == null)
+            isFirstBindingDeferred = CompletableDeferred(savedInstanceState == null),
         )
     }
 
diff --git a/src/com/android/wallpaper/picker/preview/ui/fragment/FullPreviewFragment.kt b/src/com/android/wallpaper/picker/preview/ui/fragment/FullPreviewFragment.kt
index 390fc94e..50a75303 100644
--- a/src/com/android/wallpaper/picker/preview/ui/fragment/FullPreviewFragment.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/fragment/FullPreviewFragment.kt
@@ -31,6 +31,7 @@ import androidx.navigation.fragment.findNavController
 import androidx.transition.Transition
 import com.android.wallpaper.R
 import com.android.wallpaper.picker.AppbarFragment
+import com.android.wallpaper.picker.di.modules.MainDispatcher
 import com.android.wallpaper.picker.preview.ui.binder.CropWallpaperButtonBinder
 import com.android.wallpaper.picker.preview.ui.binder.FullWallpaperPreviewBinder
 import com.android.wallpaper.picker.preview.ui.binder.PreviewTooltipBinder
@@ -44,12 +45,14 @@ import dagger.hilt.android.AndroidEntryPoint
 import dagger.hilt.android.qualifiers.ApplicationContext
 import javax.inject.Inject
 import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
 
 /** Shows full preview of user selected wallpaper for cropping, zooming and positioning. */
 @AndroidEntryPoint(AppbarFragment::class)
 class FullPreviewFragment : Hilt_FullPreviewFragment() {
 
     @Inject @ApplicationContext lateinit var appContext: Context
+    @Inject @MainDispatcher lateinit var mainScope: CoroutineScope
     @Inject lateinit var displayUtils: DisplayUtils
     @Inject lateinit var wallpaperConnectionUtils: WallpaperConnectionUtils
 
@@ -58,7 +61,7 @@ class FullPreviewFragment : Hilt_FullPreviewFragment() {
     private val wallpaperPreviewViewModel by activityViewModels<WallpaperPreviewViewModel>()
     private val isFirstBindingDeferred = CompletableDeferred<Boolean>()
 
-    private var useLightToolbar = false
+    private var useLightToolbarOverride = false
     private var navigateUpListener: NavController.OnDestinationChangedListener? = null
 
     override fun onCreate(savedInstanceState: Bundle?) {
@@ -78,6 +81,7 @@ class FullPreviewFragment : Hilt_FullPreviewFragment() {
         navigateUpListener =
             NavController.OnDestinationChangedListener { _, destination, _ ->
                 if (destination.id == R.id.smallPreviewFragment) {
+                    wallpaperPreviewViewModel.handleBackPressed()
                     currentView.findViewById<View>(R.id.crop_wallpaper_button)?.isVisible = false
                     currentView.findViewById<View>(R.id.full_preview_tooltip_stub)?.isVisible =
                         false
@@ -108,12 +112,13 @@ class FullPreviewFragment : Hilt_FullPreviewFragment() {
             viewModel = wallpaperPreviewViewModel,
             transition = sharedElementEnterTransition as? Transition,
             displayUtils = displayUtils,
+            mainScope = mainScope,
             lifecycleOwner = viewLifecycleOwner,
             savedInstanceState = savedInstanceState,
             wallpaperConnectionUtils = wallpaperConnectionUtils,
             isFirstBindingDeferred = isFirstBindingDeferred,
         ) { isFullScreen ->
-            useLightToolbar = isFullScreen
+            useLightToolbarOverride = isFullScreen
             setUpToolbar(view)
         }
 
@@ -122,6 +127,7 @@ class FullPreviewFragment : Hilt_FullPreviewFragment() {
             viewModel = wallpaperPreviewViewModel,
             lifecycleOwner = viewLifecycleOwner,
         ) {
+            wallpaperPreviewViewModel.handleBackPressed()
             findNavController().popBackStack()
         }
 
@@ -147,7 +153,6 @@ class FullPreviewFragment : Hilt_FullPreviewFragment() {
 
     override fun onDestroyView() {
         super.onDestroyView()
-
         navigateUpListener?.let { findNavController().removeOnDestinationChangedListener(it) }
     }
 
@@ -157,7 +162,7 @@ class FullPreviewFragment : Hilt_FullPreviewFragment() {
     }
 
     override fun getToolbarTextColor(): Int {
-        return if (useLightToolbar) {
+        return if (useLightToolbarOverride) {
             ContextCompat.getColor(requireContext(), android.R.color.system_on_primary_light)
         } else {
             ContextCompat.getColor(requireContext(), R.color.system_on_surface)
@@ -166,6 +171,6 @@ class FullPreviewFragment : Hilt_FullPreviewFragment() {
 
     override fun isStatusBarLightText(): Boolean {
         return requireContext().resources.getBoolean(R.bool.isFragmentStatusBarLightText) or
-            useLightToolbar
+            useLightToolbarOverride
     }
 }
diff --git a/src/com/android/wallpaper/picker/preview/ui/fragment/SetWallpaperDialogFragment.kt b/src/com/android/wallpaper/picker/preview/ui/fragment/SetWallpaperDialogFragment.kt
index a619ddb9..0eff8423 100644
--- a/src/com/android/wallpaper/picker/preview/ui/fragment/SetWallpaperDialogFragment.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/fragment/SetWallpaperDialogFragment.kt
@@ -84,18 +84,17 @@ class SetWallpaperDialogFragment : Hilt_SetWallpaperDialogFragment() {
          */
         val activityReference = activity
         SetWallpaperDialogBinder.bind(
-            layout,
-            wallpaperPreviewViewModel,
-            displayUtils.hasMultiInternalDisplays(),
-            displayUtils.getRealSize(displayUtils.getWallpaperDisplay()),
+            dialogContent = layout,
+            wallpaperPreviewViewModel = wallpaperPreviewViewModel,
+            isFoldable = displayUtils.hasMultiInternalDisplays(),
+            handheldDisplaySize = displayUtils.getRealSize(displayUtils.getWallpaperDisplay()),
             lifecycleOwner = this,
-            mainScope,
-            checkNotNull(findNavController().currentDestination?.id),
+            mainScope = mainScope,
             onFinishActivity = {
                 Toast.makeText(
                         context,
                         R.string.wallpaper_set_successfully_message,
-                        Toast.LENGTH_SHORT
+                        Toast.LENGTH_SHORT,
                     )
                     .show()
                 if (activityReference != null) {
@@ -108,12 +107,12 @@ class SetWallpaperDialogFragment : Hilt_SetWallpaperDialogFragment() {
                         intent.putExtra(
                             WALLPAPER_LAUNCH_SOURCE,
                             if (wallpaperPreviewViewModel.isViewAsHome) LAUNCH_SOURCE_LAUNCHER
-                            else LAUNCH_SOURCE_SETTINGS_HOMEPAGE
+                            else LAUNCH_SOURCE_SETTINGS_HOMEPAGE,
                         )
                         activityReference.startActivity(
                             intent,
                             ActivityOptions.makeSceneTransitionAnimation(activityReference)
-                                .toBundle()
+                                .toBundle(),
                         )
                     } else {
                         activityReference.setResult(Activity.RESULT_OK)
@@ -134,4 +133,8 @@ class SetWallpaperDialogFragment : Hilt_SetWallpaperDialogFragment() {
         super.onDismiss(dialog)
         wallpaperPreviewViewModel.dismissSetWallpaperDialog()
     }
+
+    override fun onDestroyView() {
+        super.onDestroyView()
+    }
 }
diff --git a/src/com/android/wallpaper/picker/preview/ui/fragment/SmallPreviewFragment.kt b/src/com/android/wallpaper/picker/preview/ui/fragment/SmallPreviewFragment.kt
index 430e5c2b..ac6a32b2 100644
--- a/src/com/android/wallpaper/picker/preview/ui/fragment/SmallPreviewFragment.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/fragment/SmallPreviewFragment.kt
@@ -16,13 +16,18 @@
 package com.android.wallpaper.picker.preview.ui.fragment
 
 import android.app.Activity
+import android.app.ActivityOptions
 import android.app.AlertDialog
 import android.content.Context
 import android.content.Intent
 import android.os.Bundle
+import android.transition.Slide
+import android.view.Gravity
 import android.view.LayoutInflater
 import android.view.View
 import android.view.ViewGroup
+import android.widget.Toast
+import androidx.activity.addCallback
 import androidx.activity.result.ActivityResultLauncher
 import androidx.activity.result.contract.ActivityResultContract
 import androidx.constraintlayout.motion.widget.MotionLayout
@@ -36,15 +41,21 @@ import androidx.navigation.fragment.FragmentNavigatorExtras
 import androidx.navigation.fragment.findNavController
 import androidx.transition.Transition
 import com.android.wallpaper.R
-import com.android.wallpaper.R.id.preview_tabs_container
 import com.android.wallpaper.config.BaseFlags
+import com.android.wallpaper.model.Screen
 import com.android.wallpaper.module.logging.UserEventLogger
 import com.android.wallpaper.picker.AppbarFragment
+import com.android.wallpaper.picker.TrampolinePickerActivity
+import com.android.wallpaper.picker.customization.ui.CustomizationPickerFragment2
+import com.android.wallpaper.picker.di.modules.MainDispatcher
+import com.android.wallpaper.picker.preview.ui.WallpaperPreviewActivity
+import com.android.wallpaper.picker.preview.ui.binder.ApplyWallpaperScreenBinder
 import com.android.wallpaper.picker.preview.ui.binder.DualPreviewSelectorBinder
 import com.android.wallpaper.picker.preview.ui.binder.PreviewActionsBinder
 import com.android.wallpaper.picker.preview.ui.binder.PreviewSelectorBinder
 import com.android.wallpaper.picker.preview.ui.binder.SetWallpaperButtonBinder
 import com.android.wallpaper.picker.preview.ui.binder.SetWallpaperProgressDialogBinder
+import com.android.wallpaper.picker.preview.ui.binder.SmallPreviewScreenBinder
 import com.android.wallpaper.picker.preview.ui.util.AnimationUtil
 import com.android.wallpaper.picker.preview.ui.util.ImageEffectDialogUtil
 import com.android.wallpaper.picker.preview.ui.view.DualPreviewViewPager
@@ -54,11 +65,15 @@ import com.android.wallpaper.picker.preview.ui.view.PreviewTabs
 import com.android.wallpaper.picker.preview.ui.viewmodel.Action
 import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel
 import com.android.wallpaper.util.DisplayUtils
+import com.android.wallpaper.util.LaunchSourceUtils.LAUNCH_SOURCE_LAUNCHER
+import com.android.wallpaper.util.LaunchSourceUtils.LAUNCH_SOURCE_SETTINGS_HOMEPAGE
+import com.android.wallpaper.util.LaunchSourceUtils.WALLPAPER_LAUNCH_SOURCE
 import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import dagger.hilt.android.AndroidEntryPoint
 import dagger.hilt.android.qualifiers.ApplicationContext
 import javax.inject.Inject
 import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.launch
 
 /**
@@ -69,6 +84,7 @@ import kotlinx.coroutines.launch
 class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
 
     @Inject @ApplicationContext lateinit var appContext: Context
+    @Inject @MainDispatcher lateinit var mainScope: CoroutineScope
     @Inject lateinit var displayUtils: DisplayUtils
     @Inject lateinit var logger: UserEventLogger
     @Inject lateinit var imageEffectDialogUtil: ImageEffectDialogUtil
@@ -89,6 +105,8 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
      */
     private var isViewDestroyed: Boolean? = null
 
+    private var setWallpaperProgressDialog: AlertDialog? = null
+
     override fun onCreate(savedInstanceState: Bundle?) {
         super.onCreate(savedInstanceState)
         exitTransition = AnimationUtil.getFastFadeOutTransition()
@@ -100,11 +118,12 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
         container: ViewGroup?,
         savedInstanceState: Bundle?,
     ): View {
+        val isNewPickerUi = BaseFlags.get().isNewPickerUi()
         val isFoldable = displayUtils.hasMultiInternalDisplays()
         postponeEnterTransition()
         currentView =
             inflater.inflate(
-                if (BaseFlags.get().isNewPickerUi()) {
+                if (isNewPickerUi) {
                     if (isFoldable) R.layout.fragment_small_preview_foldable2
                     else R.layout.fragment_small_preview_handheld2
                 } else {
@@ -114,30 +133,89 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
                 container,
                 /* attachToRoot= */ false,
             )
-        val motionLayout =
-            if (BaseFlags.get().isNewPickerUi())
-                currentView.findViewById<MotionLayout>(R.id.small_preview_motion_layout)
+        val smallPreview =
+            if (isNewPickerUi) currentView.findViewById<MotionLayout>(R.id.small_preview_container)
             else null
+        val previewPager =
+            if (isNewPickerUi) currentView.findViewById<MotionLayout>(R.id.preview_pager) else null
+        previewPager?.let { setUpTransitionListener(it) }
+        if (isNewPickerUi) {
+            requireActivity().onBackPressedDispatcher.let {
+                it.addCallback {
+                    isEnabled = wallpaperPreviewViewModel.handleBackPressed()
+                    if (!isEnabled) it.onBackPressed()
+                }
+            }
+        }
 
         setUpToolbar(currentView, /* upArrow= */ true, /* transparentToolbar= */ true)
-        bindScreenPreview(currentView, motionLayout, isFirstBindingDeferred)
-        bindPreviewActions(currentView, motionLayout)
+        bindScreenPreview(currentView, isFirstBindingDeferred, isFoldable, isNewPickerUi)
+        bindPreviewActions(currentView, smallPreview)
 
-        SetWallpaperButtonBinder.bind(
-            button = currentView.requireViewById(R.id.button_set_wallpaper),
-            viewModel = wallpaperPreviewViewModel,
-            lifecycleOwner = viewLifecycleOwner,
-        ) {
-            findNavController().navigate(R.id.setWallpaperDialog)
+        if (isNewPickerUi) {
+            /**
+             * We need to keep the reference shortly, because the activity will be forced to restart
+             * due to the theme color update from the system wallpaper change. The activityReference
+             * is used to kill [WallpaperPreviewActivity].
+             */
+            val activityReference = activity
+            checkNotNull(previewPager)
+            ApplyWallpaperScreenBinder.bind(
+                applyButton = previewPager.requireViewById(R.id.apply_button),
+                cancelButton = previewPager.requireViewById(R.id.cancel_button),
+                homeCheckbox = previewPager.requireViewById(R.id.home_checkbox),
+                lockCheckbox = previewPager.requireViewById(R.id.lock_checkbox),
+                viewModel = wallpaperPreviewViewModel,
+                lifecycleOwner = viewLifecycleOwner,
+                mainScope = mainScope,
+            ) {
+                Toast.makeText(
+                        context,
+                        R.string.wallpaper_set_successfully_message,
+                        Toast.LENGTH_SHORT,
+                    )
+                    .show()
+                if (activityReference != null) {
+                    if (wallpaperPreviewViewModel.isNewTask) {
+                        activityReference.window?.exitTransition = Slide(Gravity.END)
+                        val intent = Intent(activityReference, TrampolinePickerActivity::class.java)
+                        intent.setFlags(
+                            Intent.FLAG_ACTIVITY_CLEAR_TASK or Intent.FLAG_ACTIVITY_NEW_TASK
+                        )
+                        intent.putExtra(
+                            WALLPAPER_LAUNCH_SOURCE,
+                            if (wallpaperPreviewViewModel.isViewAsHome) LAUNCH_SOURCE_LAUNCHER
+                            else LAUNCH_SOURCE_SETTINGS_HOMEPAGE,
+                        )
+                        activityReference.startActivity(
+                            intent,
+                            ActivityOptions.makeSceneTransitionAnimation(activityReference)
+                                .toBundle(),
+                        )
+                    } else {
+                        activityReference.setResult(Activity.RESULT_OK)
+                    }
+                    activityReference.finish()
+                }
+            }
+        } else {
+            SetWallpaperButtonBinder.bind(
+                button = currentView.requireViewById(R.id.button_set_wallpaper),
+                viewModel = wallpaperPreviewViewModel,
+                lifecycleOwner = viewLifecycleOwner,
+            ) {
+                findNavController().navigate(R.id.setWallpaperDialog)
+            }
         }
 
+        val dialogView = inflater.inflate(R.layout.set_wallpaper_progress_dialog_view, null)
+        setWallpaperProgressDialog =
+            AlertDialog.Builder(requireActivity()).setView(dialogView).create()
         SetWallpaperProgressDialogBinder.bind(
             viewModel = wallpaperPreviewViewModel,
             lifecycleOwner = viewLifecycleOwner,
         ) { visible ->
-            activity?.let {
-                createSetWallpaperProgressDialog(it).apply { if (visible) show() else hide() }
-            }
+            setWallpaperProgressDialog?.let { if (visible) it.show() else it.dismiss() }
         }
 
         currentView.doOnPreDraw {
@@ -181,7 +259,7 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
         isViewDestroyed?.let {
             if (!it) {
                 currentView
-                    .findViewById<PreviewTabs>(preview_tabs_container)
+                    .findViewById<PreviewTabs>(R.id.preview_tabs_container)
                     ?.resetTransition(wallpaperPreviewViewModel.getSmallPreviewTabIndex())
             }
         }
@@ -195,6 +273,7 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
 
     override fun onDestroyView() {
         super.onDestroyView()
+        setWallpaperProgressDialog?.dismiss()
         isViewDestroyed = true
     }
 
@@ -206,73 +285,126 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
         return ContextCompat.getColor(requireContext(), R.color.system_on_surface)
     }
 
-    private fun createSetWallpaperProgressDialog(activity: Activity): AlertDialog {
-        val dialogView =
-            activity.layoutInflater.inflate(R.layout.set_wallpaper_progress_dialog_view, null)
-        return AlertDialog.Builder(activity).setView(dialogView).create()
+    private fun setUpTransitionListener(previewPager: MotionLayout) {
+        previewPager.addTransitionListener(
+            object : CustomizationPickerFragment2.EmptyTransitionListener {
+                override fun onTransitionCompleted(motionLayout: MotionLayout?, currentId: Int) {
+                    if (
+                        currentId == R.id.lock_preview_selected ||
+                            currentId == R.id.home_preview_selected
+                    ) {
+                        // When user swipes to lock or home screen, we need to update the state of
+                        // the selected tab in the view model
+                        wallpaperPreviewViewModel.setSmallPreviewSelectedTab(
+                            if (currentId == R.id.lock_preview_selected) Screen.LOCK_SCREEN
+                            else Screen.HOME_SCREEN
+                        )
+                    } else if (currentId == R.id.apply_wallpaper_preview_only) {
+                        // When transition to state of apply wallpaper preview only, it should
+                        // always proceed to transition to the apply wallpaper all state to also
+                        // fade in the action buttons at the bottom.
+                        previewPager.transitionToState(R.id.apply_wallpaper_all)
+                    }
+                }
+            }
+        )
     }
 
     private fun bindScreenPreview(
         view: View,
-        motionLayout: MotionLayout?,
         isFirstBindingDeferred: CompletableDeferred<Boolean>,
+        isFoldable: Boolean,
+        isNewPickerUi: Boolean,
     ) {
-        val currentNavDestId = checkNotNull(findNavController().currentDestination?.id)
-        val tabs = view.findViewById<PreviewTabs>(preview_tabs_container)
-        if (displayUtils.hasMultiInternalDisplays()) {
-            val dualPreviewView: DualPreviewViewPager = view.requireViewById(R.id.pager_previews)
+        val tabs = view.findViewById<PreviewTabs>(R.id.preview_tabs_container)
 
-            DualPreviewSelectorBinder.bind(
-                tabs,
-                dualPreviewView,
-                motionLayout,
-                wallpaperPreviewViewModel,
-                appContext,
-                viewLifecycleOwner,
-                currentNavDestId,
-                (reenterTransition as Transition?),
-                wallpaperPreviewViewModel.fullPreviewConfigViewModel.value,
-                wallpaperConnectionUtils,
-                isFirstBindingDeferred,
+        if (isNewPickerUi) {
+            SmallPreviewScreenBinder.bind(
+                applicationContext = appContext,
+                mainScope = mainScope,
+                lifecycleOwner = viewLifecycleOwner,
+                fragmentLayout = view as MotionLayout,
+                viewModel = wallpaperPreviewViewModel,
+                previewDisplaySize = displayUtils.getRealSize(displayUtils.getWallpaperDisplay()),
+                transition = (reenterTransition as Transition?),
+                transitionConfig = wallpaperPreviewViewModel.fullPreviewConfigViewModel.value,
+                wallpaperConnectionUtils = wallpaperConnectionUtils,
+                isFirstBindingDeferred = isFirstBindingDeferred,
+                isFoldable = isFoldable,
             ) { sharedElement ->
                 val extras =
                     FragmentNavigatorExtras(sharedElement to FULL_PREVIEW_SHARED_ELEMENT_ID)
                 // Set to false on small-to-full preview transition to remove surfaceView jank.
                 (view as ViewGroup).isTransitionGroup = false
-                findNavController()
-                    .navigate(
-                        resId = R.id.action_smallPreviewFragment_to_fullPreviewFragment,
-                        args = null,
-                        navOptions = null,
-                        navigatorExtras = extras,
-                    )
+                findNavController().let {
+                    if (it.currentDestination?.id == R.id.smallPreviewFragment) {
+                        it.navigate(
+                            resId = R.id.action_smallPreviewFragment_to_fullPreviewFragment,
+                            args = null,
+                            navOptions = null,
+                            navigatorExtras = extras,
+                        )
+                    }
+                }
             }
         } else {
-            PreviewSelectorBinder.bind(
-                tabs,
-                view.requireViewById(R.id.pager_previews),
-                motionLayout,
-                displayUtils.getRealSize(displayUtils.getWallpaperDisplay()),
-                wallpaperPreviewViewModel,
-                appContext,
-                viewLifecycleOwner,
-                currentNavDestId,
-                (reenterTransition as Transition?),
-                wallpaperPreviewViewModel.fullPreviewConfigViewModel.value,
-                wallpaperConnectionUtils,
-                isFirstBindingDeferred,
-            ) { sharedElement ->
-                val extras =
-                    FragmentNavigatorExtras(sharedElement to FULL_PREVIEW_SHARED_ELEMENT_ID)
-                // Set to false on small-to-full preview transition to remove surfaceView jank.
-                (view as ViewGroup).isTransitionGroup = false
-                findNavController()
-                    .navigate(
-                        resId = R.id.action_smallPreviewFragment_to_fullPreviewFragment,
-                        args = null,
-                        navOptions = null,
-                        navigatorExtras = extras,
-                    )
+            if (isFoldable) {
+                val dualPreviewView: DualPreviewViewPager =
+                    view.requireViewById(R.id.pager_previews)
+
+                DualPreviewSelectorBinder.bind(
+                    tabs,
+                    dualPreviewView,
+                    wallpaperPreviewViewModel,
+                    appContext,
+                    mainScope,
+                    viewLifecycleOwner,
+                    (reenterTransition as Transition?),
+                    wallpaperPreviewViewModel.fullPreviewConfigViewModel.value,
+                    wallpaperConnectionUtils,
+                    isFirstBindingDeferred,
+                ) { sharedElement ->
+                    val extras =
+                        FragmentNavigatorExtras(sharedElement to FULL_PREVIEW_SHARED_ELEMENT_ID)
+                    // Set to false on small-to-full preview transition to remove surfaceView jank.
+                    (view as ViewGroup).isTransitionGroup = false
+                    findNavController()
+                        .navigate(
+                            resId = R.id.action_smallPreviewFragment_to_fullPreviewFragment,
+                            args = null,
+                            navOptions = null,
+                            navigatorExtras = extras,
+                        )
+                }
+            } else {
+                PreviewSelectorBinder.bind(
+                    tabs,
+                    view.findViewById(R.id.pager_previews),
+                    displayUtils.getRealSize(displayUtils.getWallpaperDisplay()),
+                    wallpaperPreviewViewModel,
+                    appContext,
+                    mainScope,
+                    viewLifecycleOwner,
+                    (reenterTransition as Transition?),
+                    wallpaperPreviewViewModel.fullPreviewConfigViewModel.value,
+                    wallpaperConnectionUtils,
+                    isFirstBindingDeferred,
+                ) { sharedElement ->
+                    val extras =
+                        FragmentNavigatorExtras(sharedElement to FULL_PREVIEW_SHARED_ELEMENT_ID)
+                    // Set to false on small-to-full preview transition to remove surfaceView jank.
+                    (view as ViewGroup).isTransitionGroup = false
+                    findNavController().let {
+                        if (it.currentDestination?.id == R.id.smallPreviewFragment) {
+                            it.navigate(
+                                resId = R.id.action_smallPreviewFragment_to_fullPreviewFragment,
+                                args = null,
+                                navOptions = null,
+                                navigatorExtras = extras,
+                            )
+                        }
+                    }
+                }
             }
         }
 
@@ -285,22 +417,17 @@ class SmallPreviewFragment : Hilt_SmallPreviewFragment() {
         }
     }
 
-    private fun bindPreviewActions(view: View, motionLayout: MotionLayout?) {
+    private fun bindPreviewActions(view: View, smallPreview: MotionLayout?) {
         val actionButtonGroup = view.findViewById<PreviewActionGroup>(R.id.action_button_group)
         val floatingSheet = view.findViewById<PreviewActionFloatingSheet>(R.id.floating_sheet)
         if (actionButtonGroup == null || floatingSheet == null) {
             return
         }
 
-        val motionLayout =
-            if (BaseFlags.get().isNewPickerUi())
-                view.findViewById<MotionLayout>(R.id.small_preview_motion_layout)
-            else null
-
         PreviewActionsBinder.bind(
             actionGroup = actionButtonGroup,
             floatingSheet = floatingSheet,
-            motionLayout = motionLayout,
+            smallPreview = smallPreview,
             previewViewModel = wallpaperPreviewViewModel,
             actionsViewModel = wallpaperPreviewViewModel.previewActionsViewModel,
             deviceDisplayType = displayUtils.getCurrentDisplayType(requireActivity()),
diff --git a/src/com/android/wallpaper/picker/preview/ui/view/ClickableMotionLayout.kt b/src/com/android/wallpaper/picker/preview/ui/view/ClickableMotionLayout.kt
new file mode 100644
index 00000000..c377358a
--- /dev/null
+++ b/src/com/android/wallpaper/picker/preview/ui/view/ClickableMotionLayout.kt
@@ -0,0 +1,118 @@
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
+package com.android.wallpaper.picker.preview.ui.view
+
+import android.content.Context
+import android.graphics.Rect
+import android.util.AttributeSet
+import android.view.GestureDetector
+import android.view.GestureDetector.SimpleOnGestureListener
+import android.view.MotionEvent
+import android.view.ViewGroup
+import android.view.ViewParent
+import androidx.constraintlayout.motion.widget.MotionLayout
+import androidx.core.view.ancestors
+import androidx.core.view.children
+
+/** A [MotionLayout] that performs click on one of its child if it is the recipient. */
+class ClickableMotionLayout(context: Context, attrs: AttributeSet?) : MotionLayout(context, attrs) {
+
+    /** True for this view to intercept all motion events. */
+    var shouldInterceptTouch = true
+
+    private val clickableViewIds = mutableListOf<Int>()
+    private val singleTapDetector =
+        GestureDetector(
+            context,
+            object : SimpleOnGestureListener() {
+                override fun onSingleTapUp(event: MotionEvent): Boolean {
+                    // Check if any immediate child view is clicked
+                    children
+                        .find {
+                            isEventPointerInRect(event, Rect(it.left, it.top, it.right, it.bottom))
+                        }
+                        ?.let { child ->
+                            // Find all the clickable ids in the hierarchy of the clicked view and
+                            // perform click on the exact view that should be clicked.
+                            clickableViewIds
+                                .mapNotNull { child.findViewById(it) }
+                                .find { clickableView ->
+                                    if (clickableView == child) {
+                                        true
+                                    } else {
+                                        // Find ancestors of this clickable view up until this
+                                        // layout and transform coordinates to align with motion
+                                        // event.
+                                        val ancestors = clickableView.ancestors
+                                        var ancestorsLeft = 0
+                                        var ancestorsTop = 0
+                                        ancestors
+                                            .filter {
+                                                ancestors.indexOf(it) <=
+                                                    ancestors.indexOf(child as ViewParent)
+                                            }
+                                            .forEach {
+                                                it as ViewGroup
+                                                ancestorsLeft += it.left
+                                                ancestorsTop += it.top
+                                            }
+                                        isEventPointerInRect(
+                                            event,
+                                            Rect(
+                                                /* left= */ ancestorsLeft + clickableView.left,
+                                                /* top= */ ancestorsTop + clickableView.top,
+                                                /* right= */ ancestorsLeft + clickableView.right,
+                                                /* bottom= */ ancestorsTop + clickableView.bottom,
+                                            ),
+                                        )
+                                    }
+                                }
+                                ?.performClick()
+                        }
+
+                    return true
+                }
+            },
+        )
+
+    override fun onInterceptTouchEvent(event: MotionEvent): Boolean {
+        // MotionEvent.ACTION_DOWN is the first MotionEvent received and is necessary to detect
+        // various gesture, returns true to intercept all event so they are forwarded into
+        // onTouchEvent.
+        return shouldInterceptTouch
+    }
+
+    override fun onTouchEvent(event: MotionEvent): Boolean {
+        super.onTouchEvent(event)
+
+        // Handle single tap
+        singleTapDetector.onTouchEvent(event)
+
+        return true
+    }
+
+    fun setClickableViewIds(ids: List<Int>) {
+        clickableViewIds.apply {
+            clear()
+            addAll(ids)
+        }
+    }
+
+    private fun isEventPointerInRect(e: MotionEvent, rect: Rect): Boolean {
+        return e.x >= rect.left && e.x <= rect.right && e.y >= rect.top && e.y <= rect.bottom
+    }
+}
diff --git a/src/com/android/wallpaper/picker/preview/ui/view/DualDisplayAspectRatioLayout.kt b/src/com/android/wallpaper/picker/preview/ui/view/DualDisplayAspectRatioLayout.kt
index 5c806ef4..1495b04c 100644
--- a/src/com/android/wallpaper/picker/preview/ui/view/DualDisplayAspectRatioLayout.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/view/DualDisplayAspectRatioLayout.kt
@@ -20,17 +20,15 @@ import android.graphics.Point
 import android.util.AttributeSet
 import android.widget.LinearLayout
 import com.android.wallpaper.R
+import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.model.wallpaper.DeviceDisplayType
-import kotlin.math.max
 
 /**
  * This LinearLayout view group implements the dual preview view for the small preview screen for
  * foldable devices.
  */
-class DualDisplayAspectRatioLayout(
-    context: Context,
-    attrs: AttributeSet?,
-) : LinearLayout(context, attrs) {
+class DualDisplayAspectRatioLayout(context: Context, attrs: AttributeSet?) :
+    LinearLayout(context, attrs) {
 
     private var previewDisplaySizes: Map<DeviceDisplayType, Point>? = null
 
@@ -65,35 +63,27 @@ class DualDisplayAspectRatioLayout(
         // calculate the aspect ratio of the unfolded display
         val largeDisplayAR = largeDisplaySize.x.toFloat() / largeDisplaySize.y
 
-        val sizeMultiplier = parentWidth / (largeDisplayAR + smallDisplayAR)
-        val widthFolded = (sizeMultiplier * smallDisplayAR).toInt()
-        val heightFolded = (widthFolded / smallDisplayAR).toInt()
+        // Width based calculation
+        var newHeight = parentWidth / (largeDisplayAR + smallDisplayAR)
+        if (newHeight > this.measuredHeight && BaseFlags.get().isNewPickerUi()) {
+            // If new height derived from width is larger than original height, use height based
+            // calculation.
+            newHeight = this.measuredHeight.toFloat()
+        }
 
-        val widthUnfolded = (sizeMultiplier * largeDisplayAR).toInt()
-        val heightUnfolded = (widthUnfolded / largeDisplayAR).toInt()
+        val widthFolded = newHeight * smallDisplayAR
+        val widthUnfolded = newHeight * largeDisplayAR
 
         val foldedView = getChildAt(0)
         foldedView.measure(
-            MeasureSpec.makeMeasureSpec(
-                widthFolded,
-                MeasureSpec.EXACTLY,
-            ),
-            MeasureSpec.makeMeasureSpec(
-                heightFolded,
-                MeasureSpec.EXACTLY,
-            ),
+            MeasureSpec.makeMeasureSpec(widthFolded.toInt(), MeasureSpec.EXACTLY),
+            MeasureSpec.makeMeasureSpec(newHeight.toInt(), MeasureSpec.EXACTLY),
         )
 
         val unfoldedView = getChildAt(1)
         unfoldedView.measure(
-            MeasureSpec.makeMeasureSpec(
-                widthUnfolded,
-                MeasureSpec.EXACTLY,
-            ),
-            MeasureSpec.makeMeasureSpec(
-                heightUnfolded,
-                MeasureSpec.EXACTLY,
-            ),
+            MeasureSpec.makeMeasureSpec(widthUnfolded.toInt(), MeasureSpec.EXACTLY),
+            MeasureSpec.makeMeasureSpec(newHeight.toInt(), MeasureSpec.EXACTLY),
         )
 
         val marginPixels =
@@ -101,13 +91,10 @@ class DualDisplayAspectRatioLayout(
 
         setMeasuredDimension(
             MeasureSpec.makeMeasureSpec(
-                widthFolded + widthUnfolded + 2 * marginPixels,
+                (widthFolded + widthUnfolded + 2 * marginPixels).toInt(),
                 MeasureSpec.EXACTLY,
             ),
-            MeasureSpec.makeMeasureSpec(
-                max(heightFolded, heightUnfolded),
-                MeasureSpec.EXACTLY,
-            )
+            MeasureSpec.makeMeasureSpec(newHeight.toInt(), MeasureSpec.EXACTLY),
         )
     }
 
@@ -130,7 +117,7 @@ class DualDisplayAspectRatioLayout(
             foldedViewWidth + 2 * marginPixels,
             0,
             unfoldedViewWidth + foldedViewWidth + 2 * marginPixels,
-            unfoldedViewHeight
+            unfoldedViewHeight,
         )
     }
 
diff --git a/src/com/android/wallpaper/picker/preview/ui/view/DualDisplayAspectRatioLayout2.kt b/src/com/android/wallpaper/picker/preview/ui/view/DualDisplayAspectRatioLayout2.kt
new file mode 100644
index 00000000..0074f943
--- /dev/null
+++ b/src/com/android/wallpaper/picker/preview/ui/view/DualDisplayAspectRatioLayout2.kt
@@ -0,0 +1,154 @@
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
+package com.android.wallpaper.picker.preview.ui.view
+
+import android.content.Context
+import android.graphics.Point
+import android.util.AttributeSet
+import android.view.View
+import android.widget.LinearLayout
+import com.android.wallpaper.R
+import com.android.wallpaper.model.wallpaper.DeviceDisplayType
+import com.android.wallpaper.picker.preview.ui.view.DualDisplayAspectRatioLayout.Companion.getViewId
+
+/**
+ * This LinearLayout view group implements the dual preview view for the small preview screen for
+ * foldable devices.
+ */
+class DualDisplayAspectRatioLayout2(context: Context, attrs: AttributeSet?) :
+    LinearLayout(context, attrs) {
+
+    private var previewDisplaySizes: Map<DeviceDisplayType, Point>? = null
+    private var firstMeasuredWidth = 0
+
+    /**
+     * This measures the desired size of the preview views for both of foldable device's displays.
+     * Each preview view respects the aspect ratio of the display it corresponds to while trying to
+     * have the maximum possible height.
+     */
+    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
+        super.onMeasure(widthMeasureSpec, heightMeasureSpec)
+
+        if (previewDisplaySizes == null) {
+            setMeasuredDimension(widthMeasureSpec, heightMeasureSpec)
+            return
+        }
+        if (firstMeasuredWidth == 0) {
+            firstMeasuredWidth = measuredWidth
+        }
+
+        // there are three spaces to consider
+        // the margin before the folded preview, the margin in between the folded and unfolded and
+        // the margin after the unfolded view
+        val spaceBetweenPreviews =
+            resources.getDimension(R.dimen.foldable_small_preview_space_between_preview)
+
+        val ratio = 1.0 - SCREEN_WIDTH_RATIO_FOR_NEXT_PAGE
+        val singlePageWidth = (firstMeasuredWidth * ratio).toFloat()
+        val parentWidth = singlePageWidth - spaceBetweenPreviews
+
+        val smallDisplaySize = checkNotNull(getPreviewDisplaySize(DeviceDisplayType.FOLDED))
+        val largeDisplaySize = checkNotNull(getPreviewDisplaySize(DeviceDisplayType.UNFOLDED))
+
+        // calculate the aspect ratio (ar) of the folded display
+        val smallDisplayAR = smallDisplaySize.x.toFloat() / smallDisplaySize.y
+
+        // calculate the aspect ratio of the unfolded display
+        val largeDisplayAR = largeDisplaySize.x.toFloat() / largeDisplaySize.y
+
+        // Width based calculation
+        var newHeight = parentWidth / (largeDisplayAR + smallDisplayAR)
+        if (newHeight > measuredHeight) {
+            // If new height derived from width is larger than original height, use height based
+            // calculation.
+            newHeight = measuredHeight.toFloat()
+        }
+
+        val widthFolded = newHeight * smallDisplayAR
+        val widthUnfolded = newHeight * largeDisplayAR
+
+        val foldedView = findViewById<View>(DeviceDisplayType.FOLDED.getViewId())
+        foldedView?.measure(
+            MeasureSpec.makeMeasureSpec(widthFolded.toInt(), MeasureSpec.EXACTLY),
+            MeasureSpec.makeMeasureSpec(newHeight.toInt(), MeasureSpec.EXACTLY),
+        )
+
+        val unfoldedView = findViewById<View>(DeviceDisplayType.UNFOLDED.getViewId())
+        unfoldedView?.measure(
+            MeasureSpec.makeMeasureSpec(widthUnfolded.toInt(), MeasureSpec.EXACTLY),
+            MeasureSpec.makeMeasureSpec(newHeight.toInt(), MeasureSpec.EXACTLY),
+        )
+
+        val marginPixels =
+            context.resources.getDimension(R.dimen.small_preview_inter_preview_margin).toInt()
+
+        setMeasuredDimension(
+            MeasureSpec.makeMeasureSpec(
+                (widthFolded + widthUnfolded + 2 * marginPixels).toInt(),
+                MeasureSpec.EXACTLY,
+            ),
+            MeasureSpec.makeMeasureSpec(newHeight.toInt(), MeasureSpec.EXACTLY),
+        )
+    }
+
+    override fun onLayout(changed: Boolean, left: Int, top: Int, right: Int, bottom: Int) {
+        // margins
+        val spaceBetweenPreviews =
+            resources.getDimension(R.dimen.foldable_small_preview_space_between_preview).toInt()
+
+        // the handheld preview will be position first
+        val foldedView = getChildAt(0)
+        val foldedViewWidth = foldedView.measuredWidth
+        val foldedViewHeight = foldedView.measuredHeight
+        foldedView.layout(0, 0, foldedViewWidth, foldedViewHeight)
+
+        // the unfolded view will be position after
+        val unfoldedView = getChildAt(1)
+        val unfoldedViewWidth = unfoldedView.measuredWidth
+        val unfoldedViewHeight = unfoldedView.measuredHeight
+        unfoldedView.layout(
+            foldedViewWidth + spaceBetweenPreviews,
+            0,
+            unfoldedViewWidth + foldedViewWidth + spaceBetweenPreviews,
+            unfoldedViewHeight,
+        )
+    }
+
+    fun setDisplaySizes(displaySizes: Map<DeviceDisplayType, Point>) {
+        previewDisplaySizes = displaySizes
+    }
+
+    fun getPreviewDisplaySize(display: DeviceDisplayType): Point? {
+        return previewDisplaySizes?.get(display)
+    }
+
+    companion object {
+        /** Defines percentage of the screen width is used for showing part of the next page. */
+        private const val SCREEN_WIDTH_RATIO_FOR_NEXT_PAGE = 0.1
+
+        /** Defines children view ids for [DualDisplayAspectRatioLayout2]. */
+        fun DeviceDisplayType.getViewId(): Int {
+            return when (this) {
+                DeviceDisplayType.SINGLE ->
+                    throw IllegalStateException(
+                        "DualDisplayAspectRatioLayout does not supper handheld DeviceDisplayType"
+                    )
+                DeviceDisplayType.FOLDED -> R.id.small_preview_folded_preview
+                DeviceDisplayType.UNFOLDED -> R.id.small_preview_unfolded_preview
+            }
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/picker/preview/ui/view/PreviewActionFloatingSheet.kt b/src/com/android/wallpaper/picker/preview/ui/view/PreviewActionFloatingSheet.kt
index 4f56fa3f..71f26f14 100644
--- a/src/com/android/wallpaper/picker/preview/ui/view/PreviewActionFloatingSheet.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/view/PreviewActionFloatingSheet.kt
@@ -15,6 +15,8 @@
  */
 package com.android.wallpaper.picker.preview.ui.view
 
+import android.app.Flags.liveWallpaperContentHandling
+import android.app.wallpaper.WallpaperDescription
 import android.content.Context
 import android.net.Uri
 import android.util.AttributeSet
@@ -85,12 +87,7 @@ class PreviewActionFloatingSheet(context: Context, attrs: AttributeSet?) :
         view.setCollapseFloatingSheetListener(collapseFloatingSheetListener)
         view.addEffectSwitchListener(effectSwitchListener)
         view.setEffectDownloadClickListener(effectDownloadClickListener)
-        view.updateEffectStatus(
-            effect,
-            status,
-            resultCode,
-            errorMessage,
-        )
+        view.updateEffectStatus(effect, status, resultCode, errorMessage)
         view.updateEffectTitle(title)
         floatingSheetView.removeAllViews()
         floatingSheetView.addView(view)
@@ -122,7 +119,8 @@ class PreviewActionFloatingSheet(context: Context, attrs: AttributeSet?) :
     }
 
     fun setInformationContent(
-        attributions: List<String?>?,
+        description: WallpaperDescription?,
+        attributions: List<String>?,
         onExploreButtonClickListener: OnClickListener?,
         actionButtonTitle: CharSequence?,
     ) {
@@ -131,32 +129,48 @@ class PreviewActionFloatingSheet(context: Context, attrs: AttributeSet?) :
         val subtitle1: TextView = view.requireViewById(R.id.wallpaper_info_subtitle1)
         val subtitle2: TextView = view.requireViewById(R.id.wallpaper_info_subtitle2)
         val exploreButton: Button = view.requireViewById(R.id.wallpaper_info_explore_button)
-        attributions?.forEachIndexed { index, text ->
+
+        val combinedAttributions = attributions?.toMutableList() ?: mutableListOf()
+        if (liveWallpaperContentHandling() && description != null) {
+            description.title.let {
+                if (!it.isNullOrEmpty()) {
+                    combinedAttributions[0] = it.toString()
+                }
+            }
+            description.description.forEachIndexed { index, char ->
+                if (!char.isNullOrEmpty()) {
+                    combinedAttributions[index + 1] = char.toString()
+                }
+            }
+        }
+
+        combinedAttributions.forEachIndexed { index, text ->
             when (index) {
                 0 -> {
-                    if (!text.isNullOrEmpty()) {
+                    if (text.isNotEmpty()) {
                         title.text = text
                         title.isVisible = true
                     }
                 }
                 1 -> {
-                    if (!text.isNullOrEmpty()) {
+                    if (text.isNotEmpty()) {
                         subtitle1.text = text
                         subtitle1.isVisible = true
                     }
                 }
                 2 -> {
-                    if (!text.isNullOrEmpty()) {
+                    if (text.isNotEmpty()) {
                         subtitle2.text = text
                         subtitle2.isVisible = true
                     }
                 }
             }
-
-            exploreButton.isVisible = onExploreButtonClickListener != null
-            actionButtonTitle?.let { exploreButton.text = it }
-            exploreButton.setOnClickListener(onExploreButtonClickListener)
         }
+
+        exploreButton.isVisible = onExploreButtonClickListener != null
+        actionButtonTitle?.let { exploreButton.text = it }
+        exploreButton.setOnClickListener(onExploreButtonClickListener)
+
         floatingSheetView.removeAllViews()
         floatingSheetView.addView(view)
     }
diff --git a/src/com/android/wallpaper/picker/preview/ui/view/PreviewTabs.kt b/src/com/android/wallpaper/picker/preview/ui/view/PreviewTabs.kt
index 9689d2b5..3a267235 100644
--- a/src/com/android/wallpaper/picker/preview/ui/view/PreviewTabs.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/view/PreviewTabs.kt
@@ -36,18 +36,12 @@ import com.android.wallpaper.R
 import kotlin.math.pow
 import kotlin.math.sqrt
 
-class PreviewTabs(
-    context: Context,
-    attrs: AttributeSet?,
-) :
-    FrameLayout(
-        context,
-        attrs,
-    ) {
+class PreviewTabs(context: Context, attrs: AttributeSet?) : FrameLayout(context, attrs) {
 
     private val argbEvaluator = ArgbEvaluator()
     private val selectedTextColor = ContextCompat.getColor(context, R.color.system_on_primary)
     private val unSelectedTextColor = ContextCompat.getColor(context, R.color.system_secondary)
+    private val viewConfiguration = ViewConfiguration.get(context)
 
     private val motionLayout: MotionLayout
     private val primaryTabText: TextView
@@ -70,7 +64,7 @@ class PreviewTabs(
                 override fun onTransitionStarted(
                     motionLayout: MotionLayout?,
                     startId: Int,
-                    endId: Int
+                    endId: Int,
                 ) {
                     // Do nothing intended
                 }
@@ -79,7 +73,7 @@ class PreviewTabs(
                     motionLayout: MotionLayout?,
                     startId: Int,
                     endId: Int,
-                    progress: Float
+                    progress: Float,
                 ) {
                     updateTabText(progress)
                 }
@@ -102,7 +96,7 @@ class PreviewTabs(
                     motionLayout: MotionLayout?,
                     triggerId: Int,
                     positive: Boolean,
-                    progress: Float
+                    progress: Float,
                 ) {
                     // Do nothing intended
                 }
@@ -119,7 +113,7 @@ class PreviewTabs(
         // We have to use this method to manually intercept a click event, rather than setting the
         // onClickListener to the individual tabs. This is because, when setting the onClickListener
         // to the individual tabs, the swipe gesture of the tabs will be overridden.
-        if (isClick(event, downX, downY)) {
+        if (isClick(viewConfiguration, event, downX, downY)) {
             val primaryTabRect = requireViewById<FrameLayout>(R.id.primary_tab).getViewRect()
             val secondaryTabRect = requireViewById<FrameLayout>(R.id.secondary_tab).getViewRect()
             if (primaryTabRect.contains(downX.toInt(), downY.toInt())) {
@@ -200,7 +194,7 @@ class PreviewTabs(
             object : AccessibilityDelegateCompat() {
                 override fun onInitializeAccessibilityNodeInfo(
                     host: View,
-                    info: AccessibilityNodeInfoCompat
+                    info: AccessibilityNodeInfoCompat,
                 ) {
                     super.onInitializeAccessibilityNodeInfo(host, info)
                     info.addAction(
@@ -211,7 +205,7 @@ class PreviewTabs(
                 override fun performAccessibilityAction(
                     host: View,
                     action: Int,
-                    args: Bundle?
+                    args: Bundle?,
                 ): Boolean {
                     if (
                         action ==
@@ -222,7 +216,7 @@ class PreviewTabs(
                     }
                     return super.performAccessibilityAction(host, action, args)
                 }
-            }
+            },
         )
 
         ViewCompat.setAccessibilityDelegate(
@@ -230,7 +224,7 @@ class PreviewTabs(
             object : AccessibilityDelegateCompat() {
                 override fun onInitializeAccessibilityNodeInfo(
                     host: View,
-                    info: AccessibilityNodeInfoCompat
+                    info: AccessibilityNodeInfoCompat,
                 ) {
                     super.onInitializeAccessibilityNodeInfo(host, info)
                     info.addAction(
@@ -241,7 +235,7 @@ class PreviewTabs(
                 override fun performAccessibilityAction(
                     host: View,
                     action: Int,
-                    args: Bundle?
+                    args: Bundle?,
                 ): Boolean {
                     if (
                         action ==
@@ -252,7 +246,7 @@ class PreviewTabs(
                     }
                     return super.performAccessibilityAction(host, action, args)
                 }
-            }
+            },
         )
     }
 
@@ -260,7 +254,12 @@ class PreviewTabs(
 
         const val TRANSITION_DURATION = 200
 
-        private fun isClick(event: MotionEvent, downX: Float, downY: Float): Boolean {
+        private fun isClick(
+            viewConfiguration: ViewConfiguration,
+            event: MotionEvent,
+            downX: Float,
+            downY: Float,
+        ): Boolean {
             return when {
                 // It's not a click if the event is not an UP action (though it may become one
                 // later, when/if an UP is received).
@@ -269,7 +268,7 @@ class PreviewTabs(
                 // event.
                 gestureElapsedTime(event) > ViewConfiguration.getTapTimeout() -> false
                 // It's not a click if the touch traveled too far.
-                distanceMoved(event, downX, downY) > ViewConfiguration.getTouchSlop() -> false
+                distanceMoved(event, downX, downY) > viewConfiguration.scaledTouchSlop -> false
                 // Otherwise, this is a click!
                 else -> true
             }
diff --git a/src/com/android/wallpaper/picker/preview/ui/viewmodel/PreviewActionsViewModel.kt b/src/com/android/wallpaper/picker/preview/ui/viewmodel/PreviewActionsViewModel.kt
index 5f75dae6..160aaada 100644
--- a/src/com/android/wallpaper/picker/preview/ui/viewmodel/PreviewActionsViewModel.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/viewmodel/PreviewActionsViewModel.kt
@@ -16,6 +16,7 @@
 
 package com.android.wallpaper.picker.preview.ui.viewmodel
 
+import android.app.Flags.liveWallpaperContentHandling
 import android.content.ActivityNotFoundException
 import android.content.ClipData
 import android.content.ComponentName
@@ -74,7 +75,6 @@ import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.flow.filterNotNull
-import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.map
 
 /** View model for the preview action buttons */
@@ -99,15 +99,19 @@ constructor(
                 null
             } else {
                 InformationFloatingSheetViewModel(
-                    wallpaperModel.commonWallpaperData.attributions,
-                    if (wallpaperModel.commonWallpaperData.exploreActionUrl.isNullOrEmpty()) {
-                        null
-                    } else {
-                        wallpaperModel.commonWallpaperData.exploreActionUrl
-                    },
-                    (wallpaperModel as? LiveWallpaperModel)?.let { liveWallpaperModel ->
-                        liveWallpaperModel.liveWallpaperData.contextDescription?.let { it }
-                    },
+                    description =
+                        (wallpaperModel as? LiveWallpaperModel)?.liveWallpaperData?.description,
+                    attributions = wallpaperModel.commonWallpaperData.attributions,
+                    actionUrl =
+                        if (wallpaperModel.commonWallpaperData.exploreActionUrl.isNullOrEmpty()) {
+                            null
+                        } else {
+                            wallpaperModel.commonWallpaperData.exploreActionUrl
+                        },
+                    actionButtonTitle =
+                        (wallpaperModel as? LiveWallpaperModel)
+                            ?.liveWallpaperData
+                            ?.contextDescription,
                 )
             }
         }
@@ -302,7 +306,9 @@ constructor(
                     title = it.title,
                     subtitle = it.subtitle,
                     wallpaperActions = it.actions,
-                    wallpaperEffectSwitchListener = { interactor.turnOnCreativeEffect(it) },
+                    wallpaperEffectSwitchListener = { actionPosition ->
+                        interactor.turnOnCreativeEffect(actionPosition)
+                    },
                 )
             }
         }
@@ -547,6 +553,26 @@ constructor(
             _isCustomizeChecked.value ||
             _isEffectsChecked.value
 
+    val isActionChecked: Flow<Boolean> =
+        combine(
+            isInformationChecked,
+            isDeleteChecked,
+            isEditChecked,
+            isCustomizeChecked,
+            isEffectsChecked,
+        ) {
+            isInformationChecked,
+            isDeleteChecked,
+            isEditChecked,
+            isCustomizeChecked,
+            isEffectsChecked ->
+            isInformationChecked ||
+                isDeleteChecked ||
+                isEditChecked ||
+                isCustomizeChecked ||
+                isEffectsChecked
+        }
+
     private fun uncheckAllOthersExcept(action: Action) {
         if (action != INFORMATION) {
             _isInformationChecked.value = false
@@ -567,6 +593,7 @@ constructor(
 
     companion object {
         const val EXTRA_KEY_IS_CREATE_NEW = "is_create_new"
+        const val EXTRA_WALLPAPER_DESCRIPTION = "wp_description"
 
         private fun WallpaperModel.shouldShowInformationFloatingSheet(): Boolean {
             if (
@@ -578,11 +605,19 @@ constructor(
                 return false
             }
             val attributions = commonWallpaperData.attributions
+            val description = (this as? LiveWallpaperModel)?.liveWallpaperData?.description
+            val hasDescription =
+                liveWallpaperContentHandling() &&
+                    description != null &&
+                    (description.description.isNotEmpty() ||
+                        !description.title.isNullOrEmpty() ||
+                        description.contextUri != null)
             // Show information floating sheet when any of the following contents exists
-            // 1. Attributions: Any of the list values is not null nor empty
+            // 1. Attributions/Description: Any of the list values is not null nor empty
             // 2. Explore action URL
-            return (!attributions.isNullOrEmpty() && attributions.any { !it.isNullOrEmpty() }) ||
-                !commonWallpaperData.exploreActionUrl.isNullOrEmpty()
+            return (!attributions.isNullOrEmpty() && attributions.any { it.isNotEmpty() }) ||
+                !commonWallpaperData.exploreActionUrl.isNullOrEmpty() ||
+                hasDescription
         }
 
         private fun CreativeWallpaperData.getShareIntent(): Intent {
@@ -618,6 +653,7 @@ constructor(
                     component = ComponentName(systemWallpaperInfo.packageName, settingsActivity)
                     putExtra(WallpaperSettingsActivity.EXTRA_PREVIEW_MODE, true)
                     putExtra(EXTRA_KEY_IS_CREATE_NEW, isCreateNew)
+                    description.content.let { putExtra(EXTRA_WALLPAPER_DESCRIPTION, it) }
                 }
             return intent
         }
diff --git a/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModel.kt b/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModel.kt
index e0101da4..73f4e910 100644
--- a/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModel.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModel.kt
@@ -21,6 +21,7 @@ import android.stats.style.StyleEnums
 import androidx.lifecycle.SavedStateHandle
 import androidx.lifecycle.ViewModel
 import androidx.lifecycle.viewModelScope
+import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.model.Screen
 import com.android.wallpaper.model.wallpaper.DeviceDisplayType
 import com.android.wallpaper.picker.BasePreviewActivity.EXTRA_VIEW_AS_HOME
@@ -52,6 +53,7 @@ import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.filter
 import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.flowOf
 import kotlinx.coroutines.flow.map
 import kotlinx.coroutines.flow.merge
 import kotlinx.coroutines.launch
@@ -97,12 +99,34 @@ constructor(
     // On orientation change, the fragment's onCreateView will be called again.
     var isCurrentlyEditingCreativeWallpaper = false
 
+    private val _currentPreviewScreen = MutableStateFlow(PreviewScreen.SMALL_PREVIEW)
+    val currentPreviewScreen = _currentPreviewScreen.asStateFlow()
+
+    val shouldEnableClickOnPager: Flow<Boolean> =
+        _currentPreviewScreen.map { it != PreviewScreen.FULL_PREVIEW }
+
     val smallPreviewTabs = Screen.entries.toList()
 
     private val _smallPreviewSelectedTab = MutableStateFlow(getWallpaperPreviewSource())
     val smallPreviewSelectedTab = _smallPreviewSelectedTab.asStateFlow()
+
     val smallPreviewSelectedTabIndex = smallPreviewSelectedTab.map { smallPreviewTabs.indexOf(it) }
 
+    /**
+     * Returns true if back pressed is handled due to conditions like users at a secondary screen.
+     */
+    fun handleBackPressed(): Boolean {
+        if (_currentPreviewScreen.value == PreviewScreen.APPLY_WALLPAPER) {
+            _currentPreviewScreen.value = PreviewScreen.SMALL_PREVIEW
+            return true
+        } else if (_currentPreviewScreen.value == PreviewScreen.FULL_PREVIEW) {
+            _currentPreviewScreen.value = PreviewScreen.SMALL_PREVIEW
+            // TODO(b/367374790): Returns true when shared element transition is removed
+            return false
+        }
+        return false
+    }
+
     fun getSmallPreviewTabIndex(): Int {
         return smallPreviewTabs.indexOf(smallPreviewSelectedTab.value)
     }
@@ -164,10 +188,7 @@ constructor(
             if (model is StaticWallpaperModel && !model.isDownloadableWallpaper()) {
                 staticWallpaperPreviewViewModel.updateCropHintsInfo(
                     cropHints.mapValues {
-                        FullPreviewCropModel(
-                            cropHint = it.value,
-                            cropSizeModel = null,
-                        )
+                        FullPreviewCropModel(cropHint = it.value, cropSizeModel = null)
                     }
                 )
             }
@@ -230,11 +251,7 @@ constructor(
                 }
             FullWallpaperPreviewViewModel(
                 wallpaper = wallpaper,
-                config =
-                    FullPreviewConfigViewModel(
-                        config.screen,
-                        config.deviceDisplayType,
-                    ),
+                config = FullPreviewConfigViewModel(config.screen, config.deviceDisplayType),
                 displaySize = displaySize,
                 allowUserCropping =
                     wallpaper is StaticWallpaperModel && !wallpaper.isDownloadableWallpaper(),
@@ -292,6 +309,17 @@ constructor(
             } else null
         }
 
+    val onNextButtonClicked: Flow<(() -> Unit)?> =
+        isSetWallpaperButtonEnabled.map {
+            if (it) {
+                { _currentPreviewScreen.value = PreviewScreen.APPLY_WALLPAPER }
+            } else null
+        }
+
+    val onCancelButtonClicked: Flow<() -> Unit> = flowOf {
+        _currentPreviewScreen.value = PreviewScreen.SMALL_PREVIEW
+    }
+
     private val _showSetWallpaperDialog = MutableStateFlow(false)
     val showSetWallpaperDialog = _showSetWallpaperDialog.asStateFlow()
 
@@ -300,10 +328,30 @@ constructor(
     val setWallpaperDialogSelectedScreens: StateFlow<Set<Screen>> =
         _setWallpaperDialogSelectedScreens.asStateFlow()
 
+    val isApplyButtonEnabled: Flow<Boolean> =
+        setWallpaperDialogSelectedScreens.map { it.isNotEmpty() }
+
+    val isHomeCheckBoxChecked: Flow<Boolean> =
+        setWallpaperDialogSelectedScreens.map { it.contains(Screen.HOME_SCREEN) }
+
+    val isLockCheckBoxChecked: Flow<Boolean> =
+        setWallpaperDialogSelectedScreens.map { it.contains(Screen.LOCK_SCREEN) }
+
+    val onHomeCheckBoxChecked: Flow<() -> Unit> = flowOf {
+        onSetWallpaperDialogScreenSelected(Screen.HOME_SCREEN)
+    }
+
+    val onLockCheckBoxChecked: Flow<() -> Unit> = flowOf {
+        onSetWallpaperDialogScreenSelected(Screen.LOCK_SCREEN)
+    }
+
     fun onSetWallpaperDialogScreenSelected(screen: Screen) {
         val previousSelection = _setWallpaperDialogSelectedScreens.value
         _setWallpaperDialogSelectedScreens.value =
-            if (previousSelection.contains(screen) && previousSelection.size > 1) {
+            if (
+                previousSelection.contains(screen) &&
+                    (previousSelection.size > 1 || BaseFlags.get().isNewPickerUi())
+            ) {
                 previousSelection.minus(screen)
             } else {
                 previousSelection.plus(screen)
@@ -440,14 +488,9 @@ constructor(
             }
         }
 
-    fun setDefaultFullPreviewConfigViewModel(
-        deviceDisplayType: DeviceDisplayType,
-    ) {
+    fun setDefaultFullPreviewConfigViewModel(deviceDisplayType: DeviceDisplayType) {
         _fullPreviewConfigViewModel.value =
-            FullPreviewConfigViewModel(
-                Screen.HOME_SCREEN,
-                deviceDisplayType,
-            )
+            FullPreviewConfigViewModel(Screen.HOME_SCREEN, deviceDisplayType)
     }
 
     fun resetFullPreviewConfigViewModel() {
@@ -458,5 +501,12 @@ constructor(
         private fun WallpaperModel.isDownloadableWallpaper(): Boolean {
             return this is StaticWallpaperModel && downloadableWallpaperData != null
         }
+
+        /** The current preview screen or the screen being transition to. */
+        enum class PreviewScreen {
+            SMALL_PREVIEW,
+            FULL_PREVIEW,
+            APPLY_WALLPAPER,
+        }
     }
 }
diff --git a/src/com/android/wallpaper/picker/preview/ui/viewmodel/floatingSheet/InformationFloatingSheetViewModel.kt b/src/com/android/wallpaper/picker/preview/ui/viewmodel/floatingSheet/InformationFloatingSheetViewModel.kt
index 9eeee9ec..fc81041f 100644
--- a/src/com/android/wallpaper/picker/preview/ui/viewmodel/floatingSheet/InformationFloatingSheetViewModel.kt
+++ b/src/com/android/wallpaper/picker/preview/ui/viewmodel/floatingSheet/InformationFloatingSheetViewModel.kt
@@ -16,9 +16,12 @@
 
 package com.android.wallpaper.picker.preview.ui.viewmodel.floatingSheet
 
+import android.app.wallpaper.WallpaperDescription
+
 /** This data class represents the view data for the info floating sheet */
 data class InformationFloatingSheetViewModel(
-    val attributions: List<String?>?,
+    val description: WallpaperDescription?,
+    val attributions: List<String>?,
     val actionUrl: String?,
     val actionButtonTitle: CharSequence? = null,
 )
diff --git a/src/com/android/wallpaper/system/PowerManagerImpl.kt b/src/com/android/wallpaper/system/PowerManagerImpl.kt
new file mode 100644
index 00000000..7edb5372
--- /dev/null
+++ b/src/com/android/wallpaper/system/PowerManagerImpl.kt
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
+package com.android.wallpaper.system
+
+import android.content.Context
+import android.os.PowerManager
+import dagger.hilt.android.qualifiers.ApplicationContext
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+class PowerManagerImpl @Inject constructor(@ApplicationContext private val context: Context) :
+    PowerManagerWrapper {
+    private val powerManager = context.getSystemService(PowerManager::class.java)
+
+    override fun getIsPowerSaveMode(): Boolean? {
+        return powerManager?.isPowerSaveMode
+    }
+}
diff --git a/src/com/android/wallpaper/system/PowerManagerWrapper.kt b/src/com/android/wallpaper/system/PowerManagerWrapper.kt
new file mode 100644
index 00000000..2d991ece
--- /dev/null
+++ b/src/com/android/wallpaper/system/PowerManagerWrapper.kt
@@ -0,0 +1,21 @@
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
+package com.android.wallpaper.system
+
+interface PowerManagerWrapper {
+    fun getIsPowerSaveMode(): Boolean?
+}
diff --git a/src/com/android/wallpaper/system/UiModeManagerImpl.kt b/src/com/android/wallpaper/system/UiModeManagerImpl.kt
index 4fe55f0e..6cbb94ed 100644
--- a/src/com/android/wallpaper/system/UiModeManagerImpl.kt
+++ b/src/com/android/wallpaper/system/UiModeManagerImpl.kt
@@ -18,15 +18,18 @@ package com.android.wallpaper.system
 
 import android.app.UiModeManager
 import android.content.Context
+import android.content.res.Configuration.UI_MODE_NIGHT_MASK
+import android.content.res.Configuration.UI_MODE_NIGHT_YES
 import dagger.hilt.android.qualifiers.ApplicationContext
 import java.util.concurrent.Executor
 import javax.inject.Inject
 import javax.inject.Singleton
 
 @Singleton
-class UiModeManagerImpl @Inject constructor(@ApplicationContext context: Context) :
+class UiModeManagerImpl @Inject constructor(@ApplicationContext private val context: Context) :
     UiModeManagerWrapper {
     val uiModeManager = context.getSystemService(Context.UI_MODE_SERVICE) as UiModeManager?
+
     override fun addContrastChangeListener(
         executor: Executor,
         listener: UiModeManager.ContrastChangeListener,
@@ -42,6 +45,10 @@ class UiModeManagerImpl @Inject constructor(@ApplicationContext context: Context
         return uiModeManager?.contrast
     }
 
+    override fun getIsNightModeActivated(): Boolean {
+        return context.resources.configuration.uiMode and UI_MODE_NIGHT_MASK == UI_MODE_NIGHT_YES
+    }
+
     override fun setNightModeActivated(isActive: Boolean) {
         uiModeManager?.setNightModeActivated(isActive)
     }
diff --git a/src/com/android/wallpaper/system/UiModeManagerWrapper.kt b/src/com/android/wallpaper/system/UiModeManagerWrapper.kt
index 8dd419ca..15e596d7 100644
--- a/src/com/android/wallpaper/system/UiModeManagerWrapper.kt
+++ b/src/com/android/wallpaper/system/UiModeManagerWrapper.kt
@@ -27,5 +27,7 @@ interface UiModeManagerWrapper {
 
     fun getContrast(): Float?
 
+    fun getIsNightModeActivated(): Boolean
+
     fun setNightModeActivated(isActive: Boolean)
 }
diff --git a/src/com/android/wallpaper/util/WallpaperConnection.java b/src/com/android/wallpaper/util/WallpaperConnection.java
index 9e4bbd33..36867f8b 100644
--- a/src/com/android/wallpaper/util/WallpaperConnection.java
+++ b/src/com/android/wallpaper/util/WallpaperConnection.java
@@ -15,13 +15,16 @@
  */
 package com.android.wallpaper.util;
 
+import static android.app.Flags.liveWallpaperContentHandling;
 import static android.graphics.Matrix.MSCALE_X;
 import static android.graphics.Matrix.MSCALE_Y;
 import static android.graphics.Matrix.MSKEW_X;
 import static android.graphics.Matrix.MSKEW_Y;
 
 import android.app.WallpaperColors;
+import android.app.WallpaperInfo;
 import android.app.WallpaperManager;
+import android.app.wallpaper.WallpaperDescription;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
@@ -120,6 +123,7 @@ public class WallpaperConnection extends IWallpaperConnection.Stub implements Se
     private boolean mDestroyed;
     private int mDestinationFlag;
     private WhichPreview mWhichPreview;
+    @NonNull private final WallpaperDescription mDescription;
     private IBinder mToken;
 
     /**
@@ -132,7 +136,7 @@ public class WallpaperConnection extends IWallpaperConnection.Stub implements Se
             @Nullable WallpaperConnectionListener listener, @NonNull SurfaceView containerView,
             WhichPreview preview) {
         this(intent, context, listener, containerView, null, null,
-                preview);
+                preview, new WallpaperDescription.Builder().build());
     }
 
     /**
@@ -145,12 +149,15 @@ public class WallpaperConnection extends IWallpaperConnection.Stub implements Se
      * @param destinationFlag one of WallpaperManager.FLAG_SYSTEM, WallpaperManager.FLAG_LOCK
      *                        indicating for which screen we're previewing the wallpaper, or null if
      *                        unknown
+     * @param preview describes type of preview being shown
+     * @param description optional content to pass to wallpaper engine
+     *
      */
     public WallpaperConnection(Intent intent, Context context,
             @Nullable WallpaperConnectionListener listener, @NonNull SurfaceView containerView,
             @Nullable SurfaceView secondaryContainerView,
             @Nullable @WallpaperManager.SetWallpaperFlags Integer destinationFlag,
-            WhichPreview preview) {
+            WhichPreview preview, @NonNull WallpaperDescription description) {
         mContext = context.getApplicationContext();
         mIntent = intent;
         mListener = listener;
@@ -158,6 +165,7 @@ public class WallpaperConnection extends IWallpaperConnection.Stub implements Se
         mSecondContainerView = secondaryContainerView;
         mDestinationFlag = destinationFlag == null ? WallpaperManager.FLAG_SYSTEM : destinationFlag;
         mWhichPreview = preview;
+        mDescription = description;
     }
 
     /**
@@ -412,24 +420,68 @@ public class WallpaperConnection extends IWallpaperConnection.Stub implements Se
         }
     }
 
+    /*
+     * Tries to call the attach method used in Android 14(U) and earlier, returning true on success
+     * otherwise false.
+     */
+    private boolean tryPreUAttach(int displayId) {
+        try {
+            Method preUMethod = mService.getClass().getMethod("attach",
+                    IWallpaperConnection.class, IBinder.class, int.class, boolean.class,
+                    int.class, int.class, Rect.class, int.class);
+            preUMethod.invoke(mService, this, mToken, LayoutParams.TYPE_APPLICATION_MEDIA, true,
+                    mContainerView.getWidth(), mContainerView.getHeight(), new Rect(0, 0, 0, 0),
+                    displayId);
+            Log.d(TAG, "Using pre-U version of IWallpaperService#attach");
+            if (liveWallpaperContentHandling()) {
+                Log.w(TAG,
+                        "live wallpaper content handling enabled, but pre-U attach method called");
+            }
+            return true;
+        } catch (NoSuchMethodException | NoSuchMethodError | InvocationTargetException
+                 | IllegalAccessException e) {
+            return false;
+        }
+    }
+
+    /*
+     * Tries to call the attach method used in Android 16(B) and earlier, returning true on success
+     * otherwise false.
+     */
+    private boolean tryPreBAttach(int displayId) {
+        try {
+            Method preBMethod = mService.getClass().getMethod("attach",
+                    IWallpaperConnection.class, IBinder.class, int.class, boolean.class,
+                    int.class, int.class, Rect.class, int.class, WallpaperInfo.class);
+            preBMethod.invoke(mService, this, mToken, LayoutParams.TYPE_APPLICATION_MEDIA, true,
+                    mContainerView.getWidth(), mContainerView.getHeight(), new Rect(0, 0, 0, 0),
+                    displayId, mDestinationFlag, null);
+            if (liveWallpaperContentHandling()) {
+                Log.w(TAG,
+                        "live wallpaper content handling enabled, but pre-B attach method called");
+            }
+            return true;
+        } catch (NoSuchMethodException | NoSuchMethodError | InvocationTargetException
+                 | IllegalAccessException e) {
+            return false;
+        }
+    }
+
+    /*
+     * This method tries to call historical versions of IWallpaperService#attach since this code
+     * may be running against older versions of Android. We have no control over what versions of
+     * Android third party users of this code will be running.
+     */
     private void attachConnection(int displayId) {
         mToken = mContainerView.getWindowToken();
+
         try {
-            try {
-                Method preUMethod = mService.getClass().getMethod("attach",
-                        IWallpaperConnection.class, IBinder.class, int.class, boolean.class,
-                        int.class, int.class, Rect.class, int.class);
-                preUMethod.invoke(mService, this, mToken, LayoutParams.TYPE_APPLICATION_MEDIA, true,
-                        mContainerView.getWidth(), mContainerView.getHeight(), new Rect(0, 0, 0, 0),
-                        displayId);
-            } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
-                Log.d(TAG, "IWallpaperService#attach method without which argument not available, "
-                        + "will use newer version");
-                // Let's try the new attach method that takes "which" argument
-                mService.attach(this, mToken, LayoutParams.TYPE_APPLICATION_MEDIA, true,
-                        mContainerView.getWidth(), mContainerView.getHeight(), new Rect(0, 0, 0, 0),
-                        displayId, mDestinationFlag, null);
-            }
+            if (tryPreUAttach(displayId)) return;
+            if (tryPreBAttach(displayId)) return;
+
+            mService.attach(this, mToken, LayoutParams.TYPE_APPLICATION_MEDIA, true,
+                    mContainerView.getWidth(), mContainerView.getHeight(), new Rect(0, 0, 0, 0),
+                    displayId, mDestinationFlag, null, mDescription);
         } catch (RemoteException e) {
             Log.w(TAG, "Failed attaching wallpaper; clearing", e);
         }
diff --git a/src/com/android/wallpaper/util/converter/WallpaperModelFactory.kt b/src/com/android/wallpaper/util/converter/WallpaperModelFactory.kt
index 746ecbb1..f8cc1a3a 100644
--- a/src/com/android/wallpaper/util/converter/WallpaperModelFactory.kt
+++ b/src/com/android/wallpaper/util/converter/WallpaperModelFactory.kt
@@ -61,7 +61,7 @@ interface WallpaperModelFactory {
                         else -> {
                             Log.w(
                                 TAG,
-                                "Invalid value for wallpaperManagerFlag: $wallpaperManagerFlag"
+                                "Invalid value for wallpaperManagerFlag: $wallpaperManagerFlag",
                             )
                             Destination.NOT_APPLIED
                         }
@@ -94,7 +94,7 @@ interface WallpaperModelFactory {
             return CommonWallpaperData(
                 id = wallpaperId,
                 title = getTitle(context),
-                attributions = getAttributions(context),
+                attributions = getAttributions(context).map { it ?: "" },
                 exploreActionUrl = getActionUrl(context),
                 thumbAsset = getThumbAsset(context),
                 placeholderColorInfo = colorInfoOfWallpaper,
@@ -104,7 +104,7 @@ interface WallpaperModelFactory {
 
         fun LiveWallpaperInfo.getLiveWallpaperData(
             context: Context,
-            effectsController: EffectsController? = null
+            effectsController: EffectsController? = null,
         ): LiveWallpaperData {
             val groupNameOfWallpaper = (this as? CreativeWallpaperInfo)?.groupName ?: ""
             val wallpaperManager = WallpaperManager.getInstance(context)
@@ -123,6 +123,7 @@ interface WallpaperModelFactory {
                     effectsController?.isEffectsWallpaper(info) ?: (effectNames != null),
                 effectNames = effectNames,
                 contextDescription = contextDescription,
+                description = wallpaperDescription,
             )
         }
 
diff --git a/src/com/android/wallpaper/util/converter/category/DefaultCategoryFactory.kt b/src/com/android/wallpaper/util/converter/category/DefaultCategoryFactory.kt
index c87ee083..e817d329 100644
--- a/src/com/android/wallpaper/util/converter/category/DefaultCategoryFactory.kt
+++ b/src/com/android/wallpaper/util/converter/category/DefaultCategoryFactory.kt
@@ -46,7 +46,7 @@ constructor(
             commonCategoryData = getCommonCategoryData(category),
             collectionCategoryData = (category as? WallpaperCategory)?.getCollectionsCategoryData(),
             imageCategoryData = getImageCategoryData(category),
-            thirdPartyCategoryData = getThirdPartyCategoryData(category)
+            thirdPartyCategoryData = getThirdPartyCategoryData(category),
         )
     }
 
@@ -54,7 +54,7 @@ constructor(
         return CommonCategoryData(
             title = category.title,
             collectionId = category.collectionId,
-            priority = category.priority
+            priority = category.priority,
         )
     }
 
@@ -77,7 +77,7 @@ constructor(
         return if (category is ImageCategory) {
             ImageCategoryData(
                 thumbnailAsset = category.getThumbnail(context),
-                defaultDrawable = category.getOverlayIcon(context)
+                defaultDrawable = category.getOverlayIcon(context),
             )
         } else {
             Log.w(TAG, "Passed category is not of type ImageCategory")
@@ -87,7 +87,10 @@ constructor(
 
     private fun getThirdPartyCategoryData(category: Category): ThirdPartyCategoryData? {
         return if (category is ThirdPartyAppCategory) {
-            ThirdPartyCategoryData(resolveInfo = category.resolveInfo)
+            ThirdPartyCategoryData(
+                resolveInfo = category.resolveInfo,
+                defaultDrawable = category.getOverlayIcon(context),
+            )
         } else {
             Log.w(TAG, "Passed category is not of type ThirdPartyAppCategory")
             null
diff --git a/src/com/android/wallpaper/util/wallpaperconnection/WallpaperConnectionUtils.kt b/src/com/android/wallpaper/util/wallpaperconnection/WallpaperConnectionUtils.kt
index 0391e5a8..2a9fdff7 100644
--- a/src/com/android/wallpaper/util/wallpaperconnection/WallpaperConnectionUtils.kt
+++ b/src/com/android/wallpaper/util/wallpaperconnection/WallpaperConnectionUtils.kt
@@ -2,6 +2,7 @@ package com.android.wallpaper.util.wallpaperconnection
 
 import android.app.WallpaperInfo
 import android.app.WallpaperManager
+import android.app.wallpaper.WallpaperDescription
 import android.content.ContentValues
 import android.content.Context
 import android.content.Intent
@@ -20,8 +21,9 @@ import android.view.SurfaceControl
 import android.view.SurfaceView
 import com.android.app.tracing.TraceUtils.traceAsync
 import com.android.wallpaper.model.wallpaper.DeviceDisplayType
+import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination
+import com.android.wallpaper.picker.customization.shared.model.WallpaperDestination.Companion.toSetWallpaperFlags
 import com.android.wallpaper.picker.data.WallpaperModel.LiveWallpaperModel
-import com.android.wallpaper.util.WallpaperConnection
 import com.android.wallpaper.util.WallpaperConnection.WhichPreview
 import dagger.hilt.android.scopes.ActivityRetainedScoped
 import java.lang.ref.WeakReference
@@ -39,8 +41,10 @@ import kotlinx.coroutines.sync.withLock
 @ActivityRetainedScoped
 class WallpaperConnectionUtils @Inject constructor() {
 
-    // engineMap and surfaceControlMap are used for disconnecting wallpaper services.
+    // The engineMap and the surfaceControlMap are used for disconnecting wallpaper services.
     private val wallpaperConnectionMap = ConcurrentHashMap<String, Deferred<WallpaperConnection>>()
+    // Stores the latest connection for a service for later use like calling Engine methods.
+    private val latestConnectionMap = ConcurrentHashMap<String, Deferred<WallpaperConnection>>()
     // Note that when one wallpaper engine's render is mirrored to a new surface view, we call
     // engine.mirrorSurfaceControl() and will have a new surface control instance.
     private val surfaceControlMap = mutableMapOf<String, MutableList<SurfaceControl>>()
@@ -63,12 +67,16 @@ class WallpaperConnectionUtils @Inject constructor() {
     ) {
         val wallpaperInfo = wallpaperModel.liveWallpaperData.systemWallpaperInfo
         val engineDisplaySize = engineRenderingConfig.getEngineDisplaySize()
-        val engineKey = wallpaperInfo.getKey(engineDisplaySize)
+        val engineKey =
+            wallpaperInfo.getKey(engineDisplaySize, wallpaperModel.liveWallpaperData.description)
 
         traceAsync(TAG, "connect") {
             // Update the creative wallpaper uri before starting the service.
+            // We call this regardless of liveWallpaperContentHandling() because it's possible that
+            // the flag is true here but false in the code we're calling.
             wallpaperModel.creativeWallpaperData?.configPreviewUri?.let {
-                val uriKey = wallpaperInfo.getKey()
+                val uriKey =
+                    wallpaperInfo.getKey(description = wallpaperModel.liveWallpaperData.description)
                 if (!creativeWallpaperConfigPreviewUriMap.containsKey(uriKey)) {
                     mutex.withLock {
                         if (!creativeWallpaperConfigPreviewUriMap.containsKey(uriKey)) {
@@ -95,6 +103,7 @@ class WallpaperConnectionUtils @Inject constructor() {
                                     whichPreview,
                                     surfaceView,
                                     listener,
+                                    wallpaperModel.liveWallpaperData.description,
                                 )
                             }
                         }
@@ -102,6 +111,11 @@ class WallpaperConnectionUtils @Inject constructor() {
                 }
             }
 
+            val engineKeyNoSize =
+                wallpaperInfo.getKey(null, wallpaperModel.liveWallpaperData.description)
+            latestConnectionMap[engineKeyNoSize] =
+                wallpaperConnectionMap[engineKey] as Deferred<WallpaperConnection>
+
             wallpaperConnectionMap[engineKey]?.await()?.let { (engineConnection, _, _, _) ->
                 engineConnection.get()?.engine?.let {
                     mirrorAndReparent(
@@ -117,7 +131,6 @@ class WallpaperConnectionUtils @Inject constructor() {
     }
 
     suspend fun disconnectAll(context: Context) {
-        disconnectAllServices(context)
         surfaceControlMap.keys.map { key ->
             mutex.withLock {
                 surfaceControlMap[key]?.let { surfaceControls ->
@@ -127,12 +140,13 @@ class WallpaperConnectionUtils @Inject constructor() {
             }
         }
         surfaceControlMap.clear()
+        disconnectAllServices(context)
     }
 
     /**
      * Disconnect all live wallpaper services without releasing and clear surface controls. This
      * function is called before binding static wallpapers. We have cases that user switch between
-     * live wan static wallpapers. When switching from live to static wallpapers, we need to
+     * live and static wallpapers. When switching from live to static wallpapers, we need to
      * disconnect the live wallpaper services to have the static wallpapers show up. But we can not
      * clear the surface controls yet, because we will need them to render the live wallpapers again
      * when switching from static to live wallpapers again.
@@ -143,6 +157,7 @@ class WallpaperConnectionUtils @Inject constructor() {
         }
 
         creativeWallpaperConfigPreviewUriMap.clear()
+        latestConnectionMap.clear()
     }
 
     suspend fun dispatchTouchEvent(
@@ -152,7 +167,10 @@ class WallpaperConnectionUtils @Inject constructor() {
     ) {
         val engine =
             wallpaperModel.liveWallpaperData.systemWallpaperInfo
-                .getKey(engineRenderingConfig.getEngineDisplaySize())
+                .getKey(
+                    engineRenderingConfig.getEngineDisplaySize(),
+                    wallpaperModel.liveWallpaperData.description,
+                )
                 .let { engineKey ->
                     wallpaperConnectionMap[engineKey]?.await()?.engineConnection?.get()?.engine
                 }
@@ -169,7 +187,7 @@ class WallpaperConnectionUtils @Inject constructor() {
                         event.x.toInt(),
                         event.y.toInt(),
                         0,
-                        null
+                        null,
                     )
                 } else if (action == MotionEvent.ACTION_POINTER_UP) {
                     engine.dispatchWallpaperCommand(
@@ -177,7 +195,7 @@ class WallpaperConnectionUtils @Inject constructor() {
                         event.getX(pointerIndex).toInt(),
                         event.getY(pointerIndex).toInt(),
                         0,
-                        null
+                        null,
                     )
                 }
             } catch (e: RemoteException) {
@@ -186,6 +204,23 @@ class WallpaperConnectionUtils @Inject constructor() {
         }
     }
 
+    // Calls IWallpaperEngine#apply(which). Throws NoSuchMethodException if that method is not
+    // defined, null if the Engine is not available, otherwise the result (which could also be
+    // null).
+    suspend fun applyWallpaper(
+        destination: WallpaperDestination,
+        wallpaperModel: LiveWallpaperModel,
+    ): WallpaperDescription? {
+        val wallpaperInfo = wallpaperModel.liveWallpaperData.systemWallpaperInfo
+        val engineKey = wallpaperInfo.getKey(null, wallpaperModel.liveWallpaperData.description)
+        latestConnectionMap[engineKey]?.await()?.engineConnection?.get()?.engine?.let {
+            return it.javaClass
+                .getMethod("onApplyWallpaper", Int::class.javaPrimitiveType)
+                .invoke(it, destination.toSetWallpaperFlags()) as WallpaperDescription?
+        }
+        return null
+    }
+
     private fun LiveWallpaperModel.getWallpaperServiceIntent(): Intent {
         return liveWallpaperData.systemWallpaperInfo.let {
             Intent(WallpaperService.SERVICE_INTERFACE).setClassName(it.packageName, it.serviceName)
@@ -200,13 +235,14 @@ class WallpaperConnectionUtils @Inject constructor() {
         whichPreview: WhichPreview,
         surfaceView: SurfaceView,
         listener: WallpaperEngineConnection.WallpaperEngineConnectionListener?,
+        description: WallpaperDescription,
     ): WallpaperConnection {
         // Bind service and get service connection and wallpaper service
         val (serviceConnection, wallpaperService) = bindWallpaperService(context, wallpaperIntent)
         val engineConnection = WallpaperEngineConnection(displayMetrics, whichPreview)
         listener?.let { engineConnection.setListener(it) }
         // Attach wallpaper connection to service and get wallpaper engine
-        engineConnection.getEngine(wallpaperService, destinationFlag, surfaceView)
+        engineConnection.getEngine(wallpaperService, destinationFlag, surfaceView, description)
         return WallpaperConnection(
             WeakReference(engineConnection),
             WeakReference(serviceConnection),
@@ -215,8 +251,13 @@ class WallpaperConnectionUtils @Inject constructor() {
         )
     }
 
-    private fun WallpaperInfo.getKey(displaySize: Point? = null): String {
-        val keyWithoutSizeInformation = this.packageName.plus(":").plus(this.serviceName)
+    // Calculates a unique key for the wallpaper engine instance
+    private fun WallpaperInfo.getKey(
+        displaySize: Point? = null,
+        description: WallpaperDescription,
+    ): String {
+        val keyWithoutSizeInformation =
+            this.packageName.plus(":").plus(this.serviceName).plus(description.let { ":$it.id" })
         return if (displaySize != null) {
             keyWithoutSizeInformation.plus(":").plus("${displaySize.x}x${displaySize.y}")
         } else {
@@ -226,7 +267,7 @@ class WallpaperConnectionUtils @Inject constructor() {
 
     private suspend fun bindWallpaperService(
         context: Context,
-        intent: Intent
+        intent: Intent,
     ): Pair<ServiceConnection, IWallpaperService> =
         suspendCancellableCoroutine {
             k: CancellableContinuation<Pair<ServiceConnection, IWallpaperService>> ->
@@ -235,7 +276,7 @@ class WallpaperConnectionUtils @Inject constructor() {
                     object : WallpaperServiceConnection.WallpaperServiceConnectionListener {
                         override fun onWallpaperServiceConnected(
                             serviceConnection: ServiceConnection,
-                            wallpaperService: IWallpaperService
+                            wallpaperService: IWallpaperService,
                         ) {
                             if (k.isActive) {
                                 k.resumeWith(
@@ -251,7 +292,7 @@ class WallpaperConnectionUtils @Inject constructor() {
                     serviceConnection,
                     Context.BIND_AUTO_CREATE or
                         Context.BIND_IMPORTANT or
-                        Context.BIND_ALLOW_ACTIVITY_STARTS
+                        Context.BIND_ALLOW_ACTIVITY_STARTS,
                 )
             if (!success && k.isActive) {
                 k.resumeWith(Result.failure(Exception("Fail to bind the live wallpaper service.")))
@@ -318,7 +359,7 @@ class WallpaperConnectionUtils @Inject constructor() {
         val surfacePosition = parentSurface.holder.surfaceFrame
         metrics.postScale(
             surfacePosition.width().toFloat() / displayMetrics.x,
-            surfacePosition.height().toFloat() / displayMetrics.y
+            surfacePosition.height().toFloat() / displayMetrics.y,
         )
         metrics.getValues(values)
         return values
diff --git a/src/com/android/wallpaper/util/wallpaperconnection/WallpaperEngineConnection.kt b/src/com/android/wallpaper/util/wallpaperconnection/WallpaperEngineConnection.kt
index 05f2c925..adef201b 100644
--- a/src/com/android/wallpaper/util/wallpaperconnection/WallpaperEngineConnection.kt
+++ b/src/com/android/wallpaper/util/wallpaperconnection/WallpaperEngineConnection.kt
@@ -1,6 +1,9 @@
 package com.android.wallpaper.util.wallpaperconnection
 
+import android.app.Flags.liveWallpaperContentHandling
 import android.app.WallpaperColors
+import android.app.WallpaperInfo
+import android.app.wallpaper.WallpaperDescription
 import android.graphics.Point
 import android.graphics.Rect
 import android.graphics.RectF
@@ -17,7 +20,6 @@ import android.view.WindowManager
 import com.android.wallpaper.util.WallpaperConnection
 import com.android.wallpaper.util.WallpaperConnection.WhichPreview
 import java.lang.reflect.InvocationTargetException
-import java.lang.reflect.Method
 import kotlinx.coroutines.CancellableContinuation
 import kotlinx.coroutines.suspendCancellableCoroutine
 
@@ -34,6 +36,7 @@ class WallpaperEngineConnection(
         wallpaperService: IWallpaperService,
         destinationFlag: Int,
         surfaceView: SurfaceView,
+        description: WallpaperDescription,
     ): IWallpaperEngine {
         return engine
             ?: suspendCancellableCoroutine { k: CancellableContinuation<IWallpaperEngine> ->
@@ -43,6 +46,7 @@ class WallpaperEngineConnection(
                     wallpaperService = wallpaperService,
                     destinationFlag = destinationFlag,
                     surfaceView = surfaceView,
+                    description = description,
                 )
             }
     }
@@ -81,7 +85,7 @@ class WallpaperEngineConnection(
     override fun onLocalWallpaperColorsChanged(
         area: RectF?,
         colors: WallpaperColors?,
-        displayId: Int
+        displayId: Int,
     ) {
         // Do nothing intended.
     }
@@ -108,19 +112,74 @@ class WallpaperEngineConnection(
         const val COMMAND_PREVIEW_INFO = "android.wallpaper.previewinfo"
         const val WHICH_PREVIEW = "which_preview"
 
-        /**
-         * Before Android U, [IWallpaperService.attach] has no input of destinationFlag. We do
-         * method reflection to probe if the service from the external app is using a pre-U API;
-         * otherwise, we use the new one.
+        /*
+         * Tries to call the attach method used in Android 14(U) and earlier, returning true on
+         * success otherwise false.
          */
-        private fun attachEngineConnection(
+        private fun tryPreUAttach(
             wallpaperEngineConnection: WallpaperEngineConnection,
             wallpaperService: IWallpaperService,
             destinationFlag: Int,
             surfaceView: SurfaceView,
-        ) {
+        ): Boolean {
+            try {
+                val method =
+                    wallpaperService.javaClass.getMethod(
+                        "attach",
+                        IWallpaperConnection::class.java,
+                        IBinder::class.java,
+                        Int::class.javaPrimitiveType,
+                        Boolean::class.javaPrimitiveType,
+                        Int::class.javaPrimitiveType,
+                        Int::class.javaPrimitiveType,
+                        Rect::class.java,
+                        Int::class.javaPrimitiveType,
+                        Int::class.javaPrimitiveType,
+                    )
+                method.invoke(
+                    wallpaperService,
+                    wallpaperEngineConnection,
+                    surfaceView.windowToken,
+                    WindowManager.LayoutParams.TYPE_APPLICATION_MEDIA,
+                    true,
+                    surfaceView.width,
+                    surfaceView.height,
+                    Rect(0, 0, 0, 0),
+                    surfaceView.display.displayId,
+                    destinationFlag,
+                )
+                return true
+            } catch (e: Exception) {
+                when (e) {
+                    is NoSuchMethodException,
+                    is InvocationTargetException,
+                    is IllegalAccessException -> {
+                        if (liveWallpaperContentHandling()) {
+                            Log.w(
+                                TAG,
+                                "live wallpaper content handling enabled, but pre-U attach method called",
+                            )
+                        }
+                        return false
+                    }
+
+                    else -> throw e
+                }
+            }
+        }
+
+        /*
+         * Tries to call the attach method used in Android 16(B) and earlier, returning true on
+         * success otherwise false.
+         */
+        private fun tryPreBAttach(
+            wallpaperEngineConnection: WallpaperEngineConnection,
+            wallpaperService: IWallpaperService,
+            destinationFlag: Int,
+            surfaceView: SurfaceView,
+        ): Boolean {
             try {
-                val preUMethod: Method =
+                val method =
                     wallpaperService.javaClass.getMethod(
                         "attach",
                         IWallpaperConnection::class.java,
@@ -130,9 +189,11 @@ class WallpaperEngineConnection(
                         Int::class.javaPrimitiveType,
                         Int::class.javaPrimitiveType,
                         Rect::class.java,
-                        Int::class.javaPrimitiveType
+                        Int::class.javaPrimitiveType,
+                        Int::class.javaPrimitiveType,
+                        WallpaperInfo::class.java,
                     )
-                preUMethod.invoke(
+                method.invoke(
                     wallpaperService,
                     wallpaperEngineConnection,
                     surfaceView.windowToken,
@@ -141,29 +202,77 @@ class WallpaperEngineConnection(
                     surfaceView.width,
                     surfaceView.height,
                     Rect(0, 0, 0, 0),
-                    surfaceView.display.displayId
+                    surfaceView.display.displayId,
+                    destinationFlag,
+                    null,
                 )
+                return true
             } catch (e: Exception) {
                 when (e) {
                     is NoSuchMethodException,
                     is InvocationTargetException,
-                    is IllegalAccessException ->
-                        wallpaperService.attach(
-                            wallpaperEngineConnection,
-                            surfaceView.windowToken,
-                            WindowManager.LayoutParams.TYPE_APPLICATION_MEDIA,
-                            true,
-                            surfaceView.width,
-                            surfaceView.height,
-                            Rect(0, 0, 0, 0),
-                            surfaceView.display.displayId,
-                            destinationFlag,
-                            null,
-                        )
+                    is IllegalAccessException -> {
+                        if (liveWallpaperContentHandling()) {
+                            Log.w(
+                                TAG,
+                                "live wallpaper content handling enabled, but pre-B attach method called",
+                            )
+                        }
+                        return false
+                    }
+
                     else -> throw e
                 }
             }
         }
+
+        /*
+         * This method tries to call historical versions of IWallpaperService#attach since this code
+         * may be running against older versions of Android. We have no control over what versions
+         * of Android third party users of this code will be running.
+         */
+        private fun attachEngineConnection(
+            wallpaperEngineConnection: WallpaperEngineConnection,
+            wallpaperService: IWallpaperService,
+            destinationFlag: Int,
+            surfaceView: SurfaceView,
+            description: WallpaperDescription,
+        ) {
+            if (
+                tryPreUAttach(
+                    wallpaperEngineConnection,
+                    wallpaperService,
+                    destinationFlag,
+                    surfaceView,
+                )
+            ) {
+                return
+            }
+            if (
+                tryPreBAttach(
+                    wallpaperEngineConnection,
+                    wallpaperService,
+                    destinationFlag,
+                    surfaceView,
+                )
+            ) {
+                return
+            }
+
+            wallpaperService.attach(
+                wallpaperEngineConnection,
+                surfaceView.windowToken,
+                WindowManager.LayoutParams.TYPE_APPLICATION_MEDIA,
+                true,
+                surfaceView.width,
+                surfaceView.height,
+                Rect(0, 0, 0, 0),
+                surfaceView.display.displayId,
+                destinationFlag,
+                null,
+                description,
+            )
+        }
     }
 
     /** Interface to be notified of connect/disconnect events from [WallpaperConnection] */
diff --git a/src_override/com/android/wallpaper/modules/WallpaperPicker2AppModule.kt b/src_override/com/android/wallpaper/modules/WallpaperPicker2AppModule.kt
index 072e3d76..dd590037 100644
--- a/src_override/com/android/wallpaper/modules/WallpaperPicker2AppModule.kt
+++ b/src_override/com/android/wallpaper/modules/WallpaperPicker2AppModule.kt
@@ -28,9 +28,11 @@ import com.android.wallpaper.module.logging.UserEventLogger
 import com.android.wallpaper.picker.category.domain.interactor.CategoriesLoadingStatusInteractor
 import com.android.wallpaper.picker.category.domain.interactor.CategoryInteractor
 import com.android.wallpaper.picker.category.domain.interactor.CreativeCategoryInteractor
+import com.android.wallpaper.picker.category.domain.interactor.ThirdPartyCategoryInteractor
 import com.android.wallpaper.picker.category.domain.interactor.implementations.CategoryInteractorImpl
 import com.android.wallpaper.picker.category.domain.interactor.implementations.CreativeCategoryInteractorImpl
 import com.android.wallpaper.picker.category.domain.interactor.implementations.DefaultCategoriesLoadingStatusInteractor
+import com.android.wallpaper.picker.category.domain.interactor.implementations.ThirdPartyCategoryInteractorImpl
 import com.android.wallpaper.picker.category.ui.view.providers.IndividualPickerFactory
 import com.android.wallpaper.picker.category.ui.view.providers.implementation.DefaultIndividualPickerFactory
 import com.android.wallpaper.picker.category.wrapper.DefaultWallpaperCategoryWrapper
@@ -82,6 +84,12 @@ abstract class WallpaperPicker2AppModule {
         impl: DefaultImageEffectDialogUtil
     ): ImageEffectDialogUtil
 
+    @Binds
+    @Singleton
+    abstract fun bindThirdPartyCategoryInteractor(
+        impl: ThirdPartyCategoryInteractorImpl
+    ): ThirdPartyCategoryInteractor
+
     @Binds
     @Singleton
     abstract fun bindIndividualPickerFactory(
diff --git a/tests/common/src/com/android/wallpaper/di/modules/SharedAppTestModule.kt b/tests/common/src/com/android/wallpaper/di/modules/SharedAppTestModule.kt
index 0a87e065..b3eefc11 100644
--- a/tests/common/src/com/android/wallpaper/di/modules/SharedAppTestModule.kt
+++ b/tests/common/src/com/android/wallpaper/di/modules/SharedAppTestModule.kt
@@ -22,15 +22,12 @@ import android.content.res.Resources
 import com.android.wallpaper.module.LargeScreenMultiPanesChecker
 import com.android.wallpaper.module.MultiPanesChecker
 import com.android.wallpaper.module.NetworkStatusNotifier
+import com.android.wallpaper.module.PackageStatusNotifier
 import com.android.wallpaper.picker.category.client.LiveWallpapersClient
 import com.android.wallpaper.picker.category.data.repository.WallpaperCategoryRepository
 import com.android.wallpaper.picker.category.domain.interactor.CategoriesLoadingStatusInteractor
-import com.android.wallpaper.picker.category.domain.interactor.CategoryInteractor
 import com.android.wallpaper.picker.category.domain.interactor.CreativeCategoryInteractor
 import com.android.wallpaper.picker.category.domain.interactor.MyPhotosInteractor
-import com.android.wallpaper.picker.category.domain.interactor.ThirdPartyCategoryInteractor
-import com.android.wallpaper.picker.category.ui.view.providers.IndividualPickerFactory
-import com.android.wallpaper.picker.category.ui.view.providers.implementation.DefaultIndividualPickerFactory
 import com.android.wallpaper.picker.customization.data.content.WallpaperClient
 import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import com.android.wallpaper.picker.di.modules.MainDispatcher
@@ -39,19 +36,20 @@ import com.android.wallpaper.picker.network.data.DefaultNetworkStatusRepository
 import com.android.wallpaper.picker.network.data.NetworkStatusRepository
 import com.android.wallpaper.picker.network.domain.DefaultNetworkStatusInteractor
 import com.android.wallpaper.picker.network.domain.NetworkStatusInteractor
+import com.android.wallpaper.system.PowerManagerWrapper
 import com.android.wallpaper.system.UiModeManagerWrapper
 import com.android.wallpaper.testing.FakeCategoriesLoadingStatusInteractor
-import com.android.wallpaper.testing.FakeCategoryInteractor
 import com.android.wallpaper.testing.FakeCreativeWallpaperInteractor
 import com.android.wallpaper.testing.FakeDefaultCategoryFactory
 import com.android.wallpaper.testing.FakeDefaultWallpaperCategoryRepository
 import com.android.wallpaper.testing.FakeLiveWallpaperClientImpl
 import com.android.wallpaper.testing.FakeMyPhotosInteractor
-import com.android.wallpaper.testing.FakeThirdPartyCategoryInteractor
+import com.android.wallpaper.testing.FakePowerManager
 import com.android.wallpaper.testing.FakeUiModeManager
 import com.android.wallpaper.testing.FakeWallpaperClient
 import com.android.wallpaper.testing.FakeWallpaperParser
 import com.android.wallpaper.testing.TestNetworkStatusNotifier
+import com.android.wallpaper.testing.TestPackageStatusNotifier
 import com.android.wallpaper.util.WallpaperParser
 import com.android.wallpaper.util.converter.category.CategoryFactory
 import dagger.Binds
@@ -84,7 +82,7 @@ internal abstract class SharedAppTestModule {
 
     @Binds
     @Singleton
-    abstract fun bindCategoryInteractor(impl: FakeCategoryInteractor): CategoryInteractor
+    abstract fun bindPackageNotifier(impl: TestPackageStatusNotifier): PackageStatusNotifier
 
     @Binds
     @Singleton
@@ -116,20 +114,12 @@ internal abstract class SharedAppTestModule {
 
     @Binds
     @Singleton
-    abstract fun bindIndividualPickerFactoryFragment(
-        impl: DefaultIndividualPickerFactory
-    ): IndividualPickerFactory
-
-    @Binds
-    @Singleton
-    abstract fun bindLiveWallpaperClient(
-        impl: FakeLiveWallpaperClientImpl,
-    ): LiveWallpapersClient
+    abstract fun bindLiveWallpaperClient(impl: FakeLiveWallpaperClientImpl): LiveWallpapersClient
 
     @Binds
     @Singleton
     abstract fun bindLoadingStatusInteractor(
-        impl: FakeCategoriesLoadingStatusInteractor,
+        impl: FakeCategoriesLoadingStatusInteractor
     ): CategoriesLoadingStatusInteractor
 
     // Use the test dispatcher for work intended for the main thread
@@ -151,13 +141,11 @@ internal abstract class SharedAppTestModule {
 
     @Binds
     @Singleton
-    abstract fun bindThirdPartyCategoryInteractor(
-        impl: FakeThirdPartyCategoryInteractor
-    ): ThirdPartyCategoryInteractor
+    abstract fun bindUiModeManagerWrapper(impl: FakeUiModeManager): UiModeManagerWrapper
 
     @Binds
     @Singleton
-    abstract fun bindUiModeManagerWrapper(impl: FakeUiModeManager): UiModeManagerWrapper
+    abstract fun bindPowerManagerWrapper(impl: FakePowerManager): PowerManagerWrapper
 
     @Binds @Singleton abstract fun bindWallpaperClient(impl: FakeWallpaperClient): WallpaperClient
 
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeCategoryInteractor.kt b/tests/common/src/com/android/wallpaper/testing/FakeCategoryInteractor.kt
index d0b5ce95..ff77b289 100644
--- a/tests/common/src/com/android/wallpaper/testing/FakeCategoryInteractor.kt
+++ b/tests/common/src/com/android/wallpaper/testing/FakeCategoryInteractor.kt
@@ -31,12 +31,7 @@ class FakeCategoryInteractor @Inject constructor() : CategoryInteractor {
         // stubbing the list of single section categories
         val categoryModels =
             generateCategoryData().map { commonCategoryData ->
-                CategoryModel(
-                    commonCategoryData,
-                    null,
-                    null,
-                    null,
-                )
+                CategoryModel(commonCategoryData, null, null, null)
             }
 
         // Emit the list of categories
@@ -47,6 +42,10 @@ class FakeCategoryInteractor @Inject constructor() : CategoryInteractor {
         // empty
     }
 
+    override fun refreshThirdPartyLiveWallpaperCategories() {
+        TODO("Not yet implemented")
+    }
+
     private fun generateCategoryData(): List<CommonCategoryData> {
         val dataList =
             listOf(
@@ -66,7 +65,7 @@ class FakeCategoryInteractor @Inject constructor() : CategoryInteractor {
                 CommonCategoryData("Pastel Dreams", "pastel_dreams", 14),
                 CommonCategoryData("Polygonal Paradise", "polygonal_paradise", 15),
                 CommonCategoryData("Oceanic Depths", "oceanic_depths", 16),
-                CommonCategoryData("Fractal Fantasia", "fractal_fantasia", 17)
+                CommonCategoryData("Fractal Fantasia", "fractal_fantasia", 17),
             )
         return dataList
     }
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeDefaultCategoryFactory.kt b/tests/common/src/com/android/wallpaper/testing/FakeDefaultCategoryFactory.kt
index c4eee2d6..1a1cabe8 100644
--- a/tests/common/src/com/android/wallpaper/testing/FakeDefaultCategoryFactory.kt
+++ b/tests/common/src/com/android/wallpaper/testing/FakeDefaultCategoryFactory.kt
@@ -57,7 +57,7 @@ class FakeDefaultCategoryFactory @Inject constructor() : CategoryFactory {
             commonCategoryData = createCommonCategoryData(category),
             collectionCategoryData = createCollectionsCategoryData(category),
             imageCategoryData = createImageCategoryData(category),
-            thirdPartyCategoryData = createThirdPartyCategoryData(category)
+            thirdPartyCategoryData = createThirdPartyCategoryData(category),
         )
     }
 
@@ -65,19 +65,17 @@ class FakeDefaultCategoryFactory @Inject constructor() : CategoryFactory {
         return CommonCategoryData(
             title = category.title,
             collectionId = category.collectionId,
-            priority = category.priority
+            priority = category.priority,
         )
     }
 
-    private fun createCollectionsCategoryData(
-        category: Category,
-    ): CollectionCategoryData? {
+    private fun createCollectionsCategoryData(category: Category): CollectionCategoryData? {
         return if (category is WallpaperCategory) {
             CollectionCategoryData(
                 wallpaperModels = wallpaperModels,
                 thumbAsset = fakeAsset,
                 featuredThumbnailIndex = category.featuredThumbnailIndex,
-                isSingleWallpaperCategory = category.isSingleWallpaperCategory
+                isSingleWallpaperCategory = category.isSingleWallpaperCategory,
             )
         } else {
             null
@@ -94,7 +92,7 @@ class FakeDefaultCategoryFactory @Inject constructor() : CategoryFactory {
 
     private fun createThirdPartyCategoryData(category: Category): ThirdPartyCategoryData? {
         return if (category is ThirdPartyAppCategory) {
-            resolveInfo?.let { ThirdPartyCategoryData(resolveInfo = it) }
+            resolveInfo?.let { ThirdPartyCategoryData(resolveInfo = it, defaultDrawable = null) }
         } else {
             null
         }
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeDefaultWallpaperCategoryClient.kt b/tests/common/src/com/android/wallpaper/testing/FakeDefaultWallpaperCategoryClient.kt
index 1a44fc20..8fd625ee 100644
--- a/tests/common/src/com/android/wallpaper/testing/FakeDefaultWallpaperCategoryClient.kt
+++ b/tests/common/src/com/android/wallpaper/testing/FakeDefaultWallpaperCategoryClient.kt
@@ -51,7 +51,7 @@ class FakeDefaultWallpaperCategoryClient @Inject constructor() : DefaultWallpape
             "Fake My Photos",
             "fake_my_photos_id",
             1,
-            0 // Placeholder resource ID
+            0, // Placeholder resource ID
         )
     }
 
@@ -64,15 +64,11 @@ class FakeDefaultWallpaperCategoryClient @Inject constructor() : DefaultWallpape
     }
 
     override suspend fun getThirdPartyCategory(excludedPackageNames: List<String>): List<Category> {
-        TODO("Not yet implemented")
+        return fakeThirdPartyAppCategories
     }
 
     override fun getExcludedThirdPartyPackageNames(): List<String> {
-        TODO("Not yet implemented")
-    }
-
-    suspend fun getThirdPartyCategory(): List<Category> {
-        return fakeThirdPartyAppCategories
+        return emptyList()
     }
 
     override suspend fun getThirdPartyLiveWallpaperCategory(
@@ -82,6 +78,6 @@ class FakeDefaultWallpaperCategoryClient @Inject constructor() : DefaultWallpape
     }
 
     override fun getExcludedLiveWallpaperPackageNames(): Set<String> {
-        TODO("Not yet implemented")
+        return emptySet()
     }
 }
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeDefaultWallpaperCategoryRepository.kt b/tests/common/src/com/android/wallpaper/testing/FakeDefaultWallpaperCategoryRepository.kt
index 7442aa81..af47c834 100644
--- a/tests/common/src/com/android/wallpaper/testing/FakeDefaultWallpaperCategoryRepository.kt
+++ b/tests/common/src/com/android/wallpaper/testing/FakeDefaultWallpaperCategoryRepository.kt
@@ -125,4 +125,12 @@ class FakeDefaultWallpaperCategoryRepository @Inject constructor() : WallpaperCa
     override suspend fun refreshNetworkCategories() {
         // empty
     }
+
+    override suspend fun refreshThirdPartyAppCategories() {
+        TODO("Not yet implemented")
+    }
+
+    override suspend fun refreshThirdPartyLiveWallpaperCategories() {
+        TODO("Not yet implemented")
+    }
 }
diff --git a/tests/common/src/com/android/wallpaper/testing/FakePowerManager.kt b/tests/common/src/com/android/wallpaper/testing/FakePowerManager.kt
new file mode 100644
index 00000000..05a6469a
--- /dev/null
+++ b/tests/common/src/com/android/wallpaper/testing/FakePowerManager.kt
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
+import com.android.wallpaper.system.PowerManagerWrapper
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+class FakePowerManager @Inject constructor() : PowerManagerWrapper {
+    private var isPowerSaveMode = false
+
+    override fun getIsPowerSaveMode(): Boolean {
+        return isPowerSaveMode
+    }
+
+    fun setIsPowerSaveMode(isActive: Boolean) {
+        isPowerSaveMode = isActive
+    }
+}
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeSecureSettingsRepository.kt b/tests/common/src/com/android/wallpaper/testing/FakeSecureSettingsRepository.kt
deleted file mode 100644
index 325f9c9f..00000000
--- a/tests/common/src/com/android/wallpaper/testing/FakeSecureSettingsRepository.kt
+++ /dev/null
@@ -1,44 +0,0 @@
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
- *
- */
-
-package com.android.wallpaper.testing
-
-import com.android.systemui.shared.settings.data.repository.SecureSettingsRepository
-import kotlinx.coroutines.flow.Flow
-import kotlinx.coroutines.flow.MutableStateFlow
-import kotlinx.coroutines.flow.map
-
-class FakeSecureSettingsRepository : SecureSettingsRepository {
-
-    private val settings = MutableStateFlow<Map<String, String>>(mutableMapOf())
-
-    override fun intSetting(name: String, defaultValue: Int): Flow<Int> {
-        return settings.map { it.getOrDefault(name, defaultValue.toString()) }.map { it.toInt() }
-    }
-
-    override suspend fun setInt(name: String, value: Int) {
-        settings.value = settings.value.toMutableMap().apply { this[name] = value.toString() }
-    }
-
-    override suspend fun getInt(name: String, defaultValue: Int): Int {
-        return settings.value[name]?.toInt() ?: defaultValue
-    }
-
-    override suspend fun getString(name: String): String? {
-        return settings.value[name]
-    }
-}
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeThirdPartyCategoryInteractor.kt b/tests/common/src/com/android/wallpaper/testing/FakeThirdPartyCategoryInteractor.kt
index 5509ca13..a9019ac8 100644
--- a/tests/common/src/com/android/wallpaper/testing/FakeThirdPartyCategoryInteractor.kt
+++ b/tests/common/src/com/android/wallpaper/testing/FakeThirdPartyCategoryInteractor.kt
@@ -35,10 +35,10 @@ class FakeThirdPartyCategoryInteractor @Inject constructor() : ThirdPartyCategor
         val categoryModels =
             generateCategoryData().map { pair ->
                 CategoryModel(
-                    pair.first,
-                    pair.second,
-                    null,
-                    null,
+                    /* commonCategoryData = */ pair.first,
+                    /* thirdPartyCategoryData = */ pair.second,
+                    /* imageCategoryData = */ null,
+                    /* collectionCategoryData = */ null,
                 )
             }
 
@@ -46,6 +46,10 @@ class FakeThirdPartyCategoryInteractor @Inject constructor() : ThirdPartyCategor
         emit(categoryModels)
     }
 
+    override fun refreshThirdPartyAppCategories() {
+        TODO("Not yet implemented")
+    }
+
     private fun generateCategoryData(): List<Pair<CommonCategoryData, ThirdPartyCategoryData>> {
         val biktokResolveInfo = ResolveInfo()
         val biktokComponentName =
@@ -71,11 +75,17 @@ class FakeThirdPartyCategoryInteractor @Inject constructor() : ThirdPartyCategor
             listOf(
                 Pair(
                     CommonCategoryData("Biktok", "biktok", 1),
-                    ThirdPartyCategoryData(biktokResolveInfo)
+                    ThirdPartyCategoryData(
+                        /* resolveInfo = */ biktokResolveInfo,
+                        /* defaultDrawable = */ null,
+                    ),
                 ),
                 Pair(
                     CommonCategoryData("Binstagram", "binstagram", 2),
-                    ThirdPartyCategoryData(binstragramResolveInfo)
+                    ThirdPartyCategoryData(
+                        /* resolveInfo = */ binstragramResolveInfo,
+                        /* defaultDrawable = */ null,
+                    ),
                 ),
             )
         return dataList
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeUiModeManager.kt b/tests/common/src/com/android/wallpaper/testing/FakeUiModeManager.kt
index 239d82a9..a9425eaf 100644
--- a/tests/common/src/com/android/wallpaper/testing/FakeUiModeManager.kt
+++ b/tests/common/src/com/android/wallpaper/testing/FakeUiModeManager.kt
@@ -25,7 +25,8 @@ import javax.inject.Singleton
 @Singleton
 class FakeUiModeManager @Inject constructor() : UiModeManagerWrapper {
     val listeners = mutableListOf<ContrastChangeListener>()
-    private var _contrast: Float? = 0.0f
+    private var contrast: Float? = 0.0f
+    private var isNightModeActivated: Boolean = false
 
     override fun addContrastChangeListener(executor: Executor, listener: ContrastChangeListener) {
         listeners.add(listener)
@@ -36,15 +37,19 @@ class FakeUiModeManager @Inject constructor() : UiModeManagerWrapper {
     }
 
     override fun getContrast(): Float? {
-        return _contrast
+        return contrast
     }
 
     fun setContrast(contrast: Float?) {
-        _contrast = contrast
+        this.contrast = contrast
         contrast?.let { v -> listeners.forEach { it.onContrastChanged(v) } }
     }
 
+    override fun getIsNightModeActivated(): Boolean {
+        return isNightModeActivated
+    }
+
     override fun setNightModeActivated(isActive: Boolean) {
-        // no-op
+        isNightModeActivated = isActive
     }
 }
diff --git a/tests/common/src/com/android/wallpaper/testing/FakeWallpaperClient.kt b/tests/common/src/com/android/wallpaper/testing/FakeWallpaperClient.kt
index c77c554d..d6033ade 100644
--- a/tests/common/src/com/android/wallpaper/testing/FakeWallpaperClient.kt
+++ b/tests/common/src/com/android/wallpaper/testing/FakeWallpaperClient.kt
@@ -59,7 +59,7 @@ class FakeWallpaperClient @Inject constructor() : WallpaperClient {
     private var deferred = mutableListOf<(suspend () -> Unit)>()
 
     fun setRecentWallpapers(
-        recentWallpapersByDestination: Map<WallpaperDestination, List<WallpaperModel>>,
+        recentWallpapersByDestination: Map<WallpaperDestination, List<WallpaperModel>>
     ) {
         _recentWallpapers.value = recentWallpapersByDestination
     }
@@ -89,9 +89,7 @@ class FakeWallpaperClient @Inject constructor() : WallpaperClient {
         }
     }
 
-    fun getCurrentWallpaper(
-        destination: WallpaperDestination,
-    ): WallpaperModel {
+    fun getCurrentWallpaper(destination: WallpaperDestination): WallpaperModel {
         return _recentWallpapers.value[destination]?.get(0)
             ?: error("No wallpapers for screen $destination")
     }
@@ -118,7 +116,7 @@ class FakeWallpaperClient @Inject constructor() : WallpaperClient {
 
     private fun addToWallpapersSet(
         wallpaperModel: com.android.wallpaper.picker.data.WallpaperModel,
-        destination: WallpaperDestination
+        destination: WallpaperDestination,
     ) {
         wallpapersSet[destination] = wallpaperModel
     }
@@ -127,7 +125,7 @@ class FakeWallpaperClient @Inject constructor() : WallpaperClient {
         @SetWallpaperEntryPoint setWallpaperEntryPoint: Int,
         destination: WallpaperDestination,
         wallpaperId: String,
-        onDone: () -> Unit
+        onDone: () -> Unit,
     ) {
         if (isPaused) {
             deferred.add {
@@ -147,7 +145,7 @@ class FakeWallpaperClient @Inject constructor() : WallpaperClient {
 
     override suspend fun loadThumbnail(
         wallpaperId: String,
-        destination: WallpaperDestination
+        destination: WallpaperDestination,
     ): Bitmap? {
         return Bitmap.createBitmap(1, 1, Bitmap.Config.ARGB_8888)
     }
@@ -166,7 +164,7 @@ class FakeWallpaperClient @Inject constructor() : WallpaperClient {
 
     override suspend fun getWallpaperColors(
         bitmap: Bitmap,
-        cropHints: Map<Point, Rect>?
+        cropHints: Map<Point, Rect>?,
     ): WallpaperColors? {
         return wallpaperColors
     }
@@ -177,7 +175,7 @@ class FakeWallpaperClient @Inject constructor() : WallpaperClient {
 
     fun setCurrentWallpaperModels(
         homeWallpaper: com.android.wallpaper.picker.data.WallpaperModel,
-        lockWallpaper: com.android.wallpaper.picker.data.WallpaperModel?
+        lockWallpaper: com.android.wallpaper.picker.data.WallpaperModel?,
     ) {
         wallpapersSet[WallpaperDestination.HOME] = homeWallpaper
         wallpapersSet[WallpaperDestination.LOCK] = lockWallpaper
@@ -192,7 +190,7 @@ class FakeWallpaperClient @Inject constructor() : WallpaperClient {
                         collectionId = "defaultCollection",
                     )
                     .also { wallpapersSet[WallpaperDestination.HOME] = it }),
-            wallpapersSet[WallpaperDestination.LOCK]
+            wallpapersSet[WallpaperDestination.LOCK],
         )
     }
 
diff --git a/tests/common/src/com/android/wallpaper/testing/TestInjector.kt b/tests/common/src/com/android/wallpaper/testing/TestInjector.kt
index d350cf2f..2d36c1b3 100644
--- a/tests/common/src/com/android/wallpaper/testing/TestInjector.kt
+++ b/tests/common/src/com/android/wallpaper/testing/TestInjector.kt
@@ -72,8 +72,20 @@ import kotlinx.coroutines.Dispatchers
 
 /** Test implementation of [Injector] */
 @Singleton
-open class TestInjector @Inject constructor(private val userEventLogger: UserEventLogger) :
-    Injector {
+open class TestInjector
+@Inject
+constructor(
+    private val userEventLogger: UserEventLogger,
+    private val displayUtils: DisplayUtils,
+    private val requester: Requester,
+    private val networkStatusNotifier: NetworkStatusNotifier,
+    private val partnerProvider: PartnerProvider,
+    private val wallpaperClient: FakeWallpaperClient,
+    private val injectedWallpaperInteractor: WallpaperInteractor,
+    private val prefs: WallpaperPreferences,
+    private val fakeWallpaperCategoryWrapper: WallpaperCategoryWrapper,
+    private val testStatusNotifier: TestPackageStatusNotifier,
+) : Injector {
     private var appScope: CoroutineScope? = null
     private var alarmManagerWrapper: AlarmManagerWrapper? = null
     private var bitmapCropper: BitmapCropper? = null
@@ -82,7 +94,6 @@ open class TestInjector @Inject constructor(private val userEventLogger: UserEve
     private var customizationSections: CustomizationSections? = null
     private var drawableLayerResolver: DrawableLayerResolver? = null
     private var exploreIntentChecker: ExploreIntentChecker? = null
-    private var packageStatusNotifier: PackageStatusNotifier? = null
     private var performanceMonitor: PerformanceMonitor? = null
     private var systemFeatureChecker: SystemFeatureChecker? = null
     private var wallpaperPersister: WallpaperPersister? = null
@@ -97,14 +108,6 @@ open class TestInjector @Inject constructor(private val userEventLogger: UserEve
     private var viewOnlyPreviewActivityIntentFactory: InlinePreviewIntentFactory? = null
 
     // Injected objects, sorted by alphabetical order of the type of object
-    @Inject lateinit var displayUtils: DisplayUtils
-    @Inject lateinit var requester: Requester
-    @Inject lateinit var networkStatusNotifier: NetworkStatusNotifier
-    @Inject lateinit var partnerProvider: PartnerProvider
-    @Inject lateinit var wallpaperClient: FakeWallpaperClient
-    @Inject lateinit var injectedWallpaperInteractor: WallpaperInteractor
-    @Inject lateinit var prefs: WallpaperPreferences
-    @Inject lateinit var fakeWallpaperCategoryWrapper: WallpaperCategoryWrapper
 
     override fun getWallpaperCategoryWrapper(): WallpaperCategoryWrapper {
         return fakeWallpaperCategoryWrapper
@@ -179,8 +182,7 @@ open class TestInjector @Inject constructor(private val userEventLogger: UserEve
     }
 
     override fun getPackageStatusNotifier(context: Context): PackageStatusNotifier {
-        return packageStatusNotifier
-            ?: TestPackageStatusNotifier().also { packageStatusNotifier = it }
+        return testStatusNotifier
     }
 
     override fun getPartnerProvider(context: Context): PartnerProvider {
diff --git a/tests/common/src/com/android/wallpaper/testing/TestPackageStatusNotifier.kt b/tests/common/src/com/android/wallpaper/testing/TestPackageStatusNotifier.kt
index fad86524..44ee3cbf 100644
--- a/tests/common/src/com/android/wallpaper/testing/TestPackageStatusNotifier.kt
+++ b/tests/common/src/com/android/wallpaper/testing/TestPackageStatusNotifier.kt
@@ -1,9 +1,12 @@
 package com.android.wallpaper.testing
 
 import com.android.wallpaper.module.PackageStatusNotifier
+import javax.inject.Inject
+import javax.inject.Singleton
 
 /** Test implementation of [PackageStatusNotifier] */
-class TestPackageStatusNotifier : PackageStatusNotifier {
+@Singleton
+class TestPackageStatusNotifier @Inject constructor() : PackageStatusNotifier {
     override fun addListener(listener: PackageStatusNotifier.Listener?, action: String?) {
         // Do nothing intended
     }
diff --git a/tests/common/src/com/android/wallpaper/testing/WallpaperModelUtils.kt b/tests/common/src/com/android/wallpaper/testing/WallpaperModelUtils.kt
index 5210e21f..7b9fb971 100644
--- a/tests/common/src/com/android/wallpaper/testing/WallpaperModelUtils.kt
+++ b/tests/common/src/com/android/wallpaper/testing/WallpaperModelUtils.kt
@@ -18,6 +18,7 @@ package com.android.wallpaper.testing
 
 import android.app.WallpaperColors
 import android.app.WallpaperInfo
+import android.app.wallpaper.WallpaperDescription
 import android.content.ComponentName
 import android.graphics.Color
 import android.graphics.Point
@@ -46,7 +47,7 @@ class WallpaperModelUtils {
             WallpaperColors(
                 Color.valueOf(Color.RED),
                 Color.valueOf(Color.GREEN),
-                Color.valueOf(Color.BLUE)
+                Color.valueOf(Color.BLUE),
             )
         val DEFAULT_ASSET = TestAsset(TestStaticWallpaperInfo.COLOR_DEFAULT, false)
         const val DEFAULT_GROUP_NAME = "group name"
@@ -70,7 +71,7 @@ class WallpaperModelUtils {
                             WallpaperId(
                                 ComponentName(
                                     WallpaperModelFactory.STATIC_WALLPAPER_PACKAGE,
-                                    WallpaperModelFactory.STATIC_WALLPAPER_CLASS
+                                    WallpaperModelFactory.STATIC_WALLPAPER_CLASS,
                                 ),
                                 wallpaperId,
                                 collectionId,
@@ -79,18 +80,10 @@ class WallpaperModelUtils {
                         attributions = attribution,
                         exploreActionUrl = actionUrl,
                         thumbAsset = asset,
-                        placeholderColorInfo =
-                            ColorInfo(
-                                colors,
-                                placeholderColor,
-                            ),
+                        placeholderColorInfo = ColorInfo(colors, placeholderColor),
                         destination = Destination.NOT_APPLIED,
                     ),
-                staticWallpaperData =
-                    StaticWallpaperData(
-                        asset,
-                        cropHints,
-                    ),
+                staticWallpaperData = StaticWallpaperData(asset, cropHints),
                 imageWallpaperData = ImageWallpaperData(imageWallpaperUri),
                 networkWallpaperData = null,
                 downloadableWallpaperData = downloadableWallpaperData,
@@ -111,35 +104,29 @@ class WallpaperModelUtils {
             isApplied: Boolean = true,
             effectNames: String? = null,
             creativeWallpaperData: CreativeWallpaperData? = null,
+            description: WallpaperDescription =
+                WallpaperDescription.Builder().setComponent(systemWallpaperInfo.component).build(),
         ): WallpaperModel.LiveWallpaperModel {
             return WallpaperModel.LiveWallpaperModel(
                 commonWallpaperData =
                     CommonWallpaperData(
-                        id =
-                            WallpaperId(
-                                systemWallpaperInfo.component,
-                                wallpaperId,
-                                collectionId,
-                            ),
+                        id = WallpaperId(systemWallpaperInfo.component, wallpaperId, collectionId),
                         title = SAMPLE_TITLE2,
                         attributions = attribution,
                         exploreActionUrl = actionUrl,
                         thumbAsset = asset,
-                        placeholderColorInfo =
-                            ColorInfo(
-                                colors,
-                                placeholderColor,
-                            ),
+                        placeholderColorInfo = ColorInfo(colors, placeholderColor),
                         destination = Destination.NOT_APPLIED,
                     ),
                 liveWallpaperData =
                     LiveWallpaperData(
-                        groupName,
-                        systemWallpaperInfo,
-                        isTitleVisible,
-                        isApplied,
-                        effectNames != null,
-                        effectNames
+                        groupName = groupName,
+                        systemWallpaperInfo = systemWallpaperInfo,
+                        isTitleVisible = isTitleVisible,
+                        isApplied = isApplied,
+                        isEffectWallpaper = effectNames != null,
+                        effectNames = effectNames,
+                        description = description,
                     ),
                 creativeWallpaperData = creativeWallpaperData,
                 internalLiveWallpaperData = null,
diff --git a/tests/module/src/com/android/wallpaper/WallpaperPicker2TestModule.kt b/tests/module/src/com/android/wallpaper/WallpaperPicker2TestModule.kt
index 9d471d3a..90e757d1 100644
--- a/tests/module/src/com/android/wallpaper/WallpaperPicker2TestModule.kt
+++ b/tests/module/src/com/android/wallpaper/WallpaperPicker2TestModule.kt
@@ -25,6 +25,10 @@ import com.android.wallpaper.module.logging.UserEventLogger
 import com.android.wallpaper.modules.WallpaperPicker2AppModule
 import com.android.wallpaper.network.Requester
 import com.android.wallpaper.picker.category.client.DefaultWallpaperCategoryClient
+import com.android.wallpaper.picker.category.domain.interactor.CategoryInteractor
+import com.android.wallpaper.picker.category.domain.interactor.ThirdPartyCategoryInteractor
+import com.android.wallpaper.picker.category.ui.view.providers.IndividualPickerFactory
+import com.android.wallpaper.picker.category.ui.view.providers.implementation.DefaultIndividualPickerFactory
 import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper
 import com.android.wallpaper.picker.common.preview.ui.binder.DefaultWorkspaceCallbackBinder
 import com.android.wallpaper.picker.common.preview.ui.binder.WorkspaceCallbackBinder
@@ -34,9 +38,11 @@ import com.android.wallpaper.picker.customization.ui.binder.DefaultToolbarBinder
 import com.android.wallpaper.picker.customization.ui.binder.ToolbarBinder
 import com.android.wallpaper.picker.preview.ui.util.DefaultImageEffectDialogUtil
 import com.android.wallpaper.picker.preview.ui.util.ImageEffectDialogUtil
+import com.android.wallpaper.testing.FakeCategoryInteractor
 import com.android.wallpaper.testing.FakeDefaultRequester
 import com.android.wallpaper.testing.FakeDefaultWallpaperCategoryClient
 import com.android.wallpaper.testing.FakeDefaultWallpaperModelFactory
+import com.android.wallpaper.testing.FakeThirdPartyCategoryInteractor
 import com.android.wallpaper.testing.FakeWallpaperCategoryWrapper
 import com.android.wallpaper.testing.TestInjector
 import com.android.wallpaper.testing.TestPartnerProvider
@@ -67,10 +73,26 @@ abstract class WallpaperPicker2TestModule {
         impl: FakeDefaultWallpaperCategoryClient
     ): DefaultWallpaperCategoryClient
 
+    @Binds
+    @Singleton
+    abstract fun bindThirdPartyCategoryInteractor(
+        impl: FakeThirdPartyCategoryInteractor
+    ): ThirdPartyCategoryInteractor
+
     @Binds
     @Singleton
     abstract fun bindEffectsController(impl: FakeEffectsController): EffectsController
 
+    @Binds
+    @Singleton
+    abstract fun bindIndividualPickerFactoryFragment(
+        impl: DefaultIndividualPickerFactory
+    ): IndividualPickerFactory
+
+    @Binds
+    @Singleton
+    abstract fun bindCategoryInteractor(impl: FakeCategoryInteractor): CategoryInteractor
+
     @Binds
     @Singleton
     abstract fun bindImageEffectDialogUtil(
diff --git a/tests/robotests/common/src/com/android/wallpaper/testing/WallpaperInfoUtils.kt b/tests/robotests/common/src/com/android/wallpaper/testing/WallpaperInfoUtils.kt
new file mode 100644
index 00000000..f3c78779
--- /dev/null
+++ b/tests/robotests/common/src/com/android/wallpaper/testing/WallpaperInfoUtils.kt
@@ -0,0 +1,71 @@
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
+package com.android.wallpaper.testing
+
+import android.app.WallpaperInfo
+import android.content.Context
+import android.content.Intent
+import android.content.pm.PackageManager
+import android.content.pm.ResolveInfo
+import android.content.pm.ServiceInfo
+import android.service.wallpaper.WallpaperService
+import org.robolectric.Shadows.shadowOf
+
+/** Utility methods for writing Robolectric tests using [android.app.WallpaperInfo]. */
+class WallpaperInfoUtils {
+    companion object {
+        const val STUB_PACKAGE = "com.google.android.apps.wallpaper.nexus"
+        const val WALLPAPER_SPLIT = "wallpaper_cities_ny"
+        const val WALLPAPER_CLASS = "NewYorkWallpaper"
+
+        /**
+         * Creates an instance of [android.app.WallpaperInfo], and optionally registers the
+         * associated service so that it will resolve if necessary.
+         *
+         * This method must be called from a test that uses
+         * [com.android.wallpaper.testing.ShadowWallpaperInfo].
+         */
+        fun createWallpaperInfo(
+            context: Context,
+            stubPackage: String = STUB_PACKAGE,
+            wallpaperSplit: String = WALLPAPER_SPLIT,
+            wallpaperClass: String = WALLPAPER_CLASS,
+            configureService: Boolean = true,
+        ): WallpaperInfo {
+            val resolveInfo =
+                ResolveInfo().apply {
+                    serviceInfo = ServiceInfo()
+                    serviceInfo.packageName = stubPackage
+                    serviceInfo.splitName = wallpaperSplit
+                    serviceInfo.name = wallpaperClass
+                    serviceInfo.flags = PackageManager.GET_META_DATA
+                }
+            // ShadowWallpaperInfo allows the creation of this object
+            val wallpaperInfo = WallpaperInfo(context, resolveInfo)
+            if (configureService) {
+                // For live wallpapers, we need the call to PackageManager#resolveService in
+                // RecentWallpaperUtils#cleanUpRecentsArray to return non-null so that our test
+                // entry isn't removed from the recents list.
+                val pm = shadowOf(context.packageManager)
+                val intent =
+                    Intent(WallpaperService.SERVICE_INTERFACE)
+                        .setClassName(stubPackage, wallpaperClass)
+                pm.addResolveInfoForIntent(intent, resolveInfo)
+            }
+            return wallpaperInfo
+        }
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/module/DefaultWallpaperPersisterTest.java b/tests/robotests/src/com/android/wallpaper/module/DefaultWallpaperPersisterTest.java
index ab233969..4d16acfa 100644
--- a/tests/robotests/src/com/android/wallpaper/module/DefaultWallpaperPersisterTest.java
+++ b/tests/robotests/src/com/android/wallpaper/module/DefaultWallpaperPersisterTest.java
@@ -22,7 +22,10 @@ import static com.android.wallpaper.module.WallpaperPersister.DEST_BOTH;
 
 import static com.google.common.truth.Truth.assertThat;
 
+import static kotlinx.coroutines.test.TestCoroutineDispatchersKt.StandardTestDispatcher;
+
 import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.spy;
 import static org.robolectric.shadows.ShadowLooper.shadowMainLooper;
 
@@ -38,15 +41,26 @@ import com.android.wallpaper.model.WallpaperInfo;
 import com.android.wallpaper.module.DefaultWallpaperPersisterTest.TestSetWallpaperCallback.SetWallpaperStatus;
 import com.android.wallpaper.module.WallpaperPersister.SetWallpaperCallback;
 import com.android.wallpaper.module.logging.TestUserEventLogger;
+import com.android.wallpaper.network.Requester;
+import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper;
+import com.android.wallpaper.picker.customization.data.repository.WallpaperRepository;
+import com.android.wallpaper.picker.customization.domain.interactor.WallpaperInteractor;
 import com.android.wallpaper.testing.FakeDisplaysProvider;
+import com.android.wallpaper.testing.FakeWallpaperClient;
 import com.android.wallpaper.testing.TestAsset;
 import com.android.wallpaper.testing.TestBitmapCropper;
 import com.android.wallpaper.testing.TestCurrentWallpaperInfoFactory;
 import com.android.wallpaper.testing.TestInjector;
+import com.android.wallpaper.testing.TestPackageStatusNotifier;
 import com.android.wallpaper.testing.TestStaticWallpaperInfo;
 import com.android.wallpaper.testing.TestWallpaperPreferences;
 import com.android.wallpaper.testing.TestWallpaperStatusChecker;
 import com.android.wallpaper.util.DisplayUtils;
+import com.android.wallpaper.util.DisplaysProvider;
+
+import kotlinx.coroutines.test.TestDispatcher;
+import kotlinx.coroutines.test.TestScope;
+import kotlinx.coroutines.test.TestScopeKt;
 
 import org.junit.Before;
 import org.junit.Test;
@@ -58,6 +72,7 @@ import org.robolectric.shadows.ShadowPausedAsyncTask;
 import java.util.ArrayList;
 import java.util.List;
 
+
 @RunWith(RobolectricTestRunner.class)
 public class DefaultWallpaperPersisterTest {
     private static final String TAG = "DefaultWallpaperPersisterTest";
@@ -73,16 +88,44 @@ public class DefaultWallpaperPersisterTest {
     /** Executor to use for AsyncTask */
     private final PausedExecutorService mPausedExecutor = new PausedExecutorService();
 
+    private TestPackageStatusNotifier mTestPackageStatusNotifier;
+
     @Before
     public void setUp() {
-        InjectorProvider.setInjector(new TestInjector(new TestUserEventLogger()));
         mContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
+
         mManager = spy(WallpaperManager.getInstance(mContext));
         mPrefs = new TestWallpaperPreferences();
         WallpaperChangedNotifier changedNotifier = spy(WallpaperChangedNotifier.getInstance());
         DisplayUtils displayUtils = new DisplayUtils(mContext, new FakeDisplaysProvider(mContext));
         TestBitmapCropper cropper = new TestBitmapCropper();
         TestWallpaperStatusChecker statusChecker = new TestWallpaperStatusChecker();
+        TestDispatcher testDispatcher = StandardTestDispatcher(null, null);
+        TestScope testScope = TestScopeKt.TestScope(testDispatcher);
+        mTestPackageStatusNotifier = new TestPackageStatusNotifier();
+        WallpaperInteractor wallpaperInteractor =
+                new WallpaperInteractor(
+                        new WallpaperRepository(
+                                testScope.getBackgroundScope(),
+                                new FakeWallpaperClient(),
+                                new TestWallpaperPreferences(),
+                                testDispatcher
+                        )
+                );
+
+        InjectorProvider.setInjector(new TestInjector(
+                new TestUserEventLogger(),
+                new DisplayUtils(mContext, mock(DisplaysProvider.class)),
+                mock(Requester.class),
+                mock(NetworkStatusNotifier.class),
+                mock(PartnerProvider.class),
+                new FakeWallpaperClient(),
+                wallpaperInteractor,
+                mock(WallpaperPreferences.class),
+                mock(WallpaperCategoryWrapper.class),
+                mTestPackageStatusNotifier
+        ));
+
         TestCurrentWallpaperInfoFactory wallpaperInfoFactory =
                 new TestCurrentWallpaperInfoFactory(mContext);
 
diff --git a/tests/robotests/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcherTest.kt b/tests/robotests/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcherTest.kt
index 230e3e79..117c5e71 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcherTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/broadcast/BroadcastDispatcherTest.kt
@@ -62,8 +62,7 @@ class BroadcastDispatcherTest {
             object : BroadcastReceiver() {
                 override fun onReceive(context: Context?, intent: Intent?) {}
             }
-        broadcastDispatcher =
-            BroadcastDispatcher(mContext, mainExecutor, backgroundRunningLooper, mainExecutor)
+        broadcastDispatcher = BroadcastDispatcher(mContext, backgroundRunningLooper)
     }
 
     @Test
@@ -140,10 +139,7 @@ class BroadcastDispatcherTest {
     }
 
     private fun provideBroadcastRunningLooper(): Looper {
-        return HandlerThread(
-                "BroadcastRunning",
-                Process.THREAD_PRIORITY_BACKGROUND,
-            )
+        return HandlerThread("BroadcastRunning", Process.THREAD_PRIORITY_BACKGROUND)
             .apply {
                 start()
                 looper.setSlowLogThresholdMs(
diff --git a/tests/robotests/src/com/android/wallpaper/picker/category/interactor/CategoryInteractorImplTest.kt b/tests/robotests/src/com/android/wallpaper/picker/category/interactor/CategoryInteractorImplTest.kt
index af4e0f74..a6f5ef11 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/category/interactor/CategoryInteractorImplTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/category/interactor/CategoryInteractorImplTest.kt
@@ -20,12 +20,14 @@ import android.content.Context
 import com.android.wallpaper.picker.category.domain.interactor.implementations.CategoryInteractorImpl
 import com.android.wallpaper.picker.data.category.CategoryModel
 import com.android.wallpaper.picker.data.category.CommonCategoryData
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import com.android.wallpaper.testing.FakeDefaultWallpaperCategoryRepository
 import com.google.common.truth.Truth.assertThat
 import dagger.hilt.android.qualifiers.ApplicationContext
 import dagger.hilt.android.testing.HiltAndroidRule
 import dagger.hilt.android.testing.HiltAndroidTest
 import javax.inject.Inject
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.flow.first
 import kotlinx.coroutines.test.runTest
 import org.junit.Before
@@ -43,11 +45,13 @@ class CategoryInteractorImplTest {
     @Inject
     lateinit var fakeDefaultWallpaperCategoryRepository: FakeDefaultWallpaperCategoryRepository
     private lateinit var categoryInteractorImpl: CategoryInteractorImpl
+    @Inject @BackgroundDispatcher lateinit var backgroundScope: CoroutineScope
 
     @Before
     fun setup() {
         hiltRule.inject()
-        categoryInteractorImpl = CategoryInteractorImpl(fakeDefaultWallpaperCategoryRepository)
+        categoryInteractorImpl =
+            CategoryInteractorImpl(fakeDefaultWallpaperCategoryRepository, backgroundScope)
     }
 
     @Test
@@ -65,7 +69,7 @@ class CategoryInteractorImplTest {
                         CommonCategoryData("ThirdPartyLiveWallpaper-1", "on_device_live_id", 2),
                     thirdPartyCategoryData = null,
                     imageCategoryData = null,
-                    collectionCategoryData = null
+                    collectionCategoryData = null,
                 )
             )
         )
@@ -77,13 +81,13 @@ class CategoryInteractorImplTest {
                     commonCategoryData = CommonCategoryData("ThirdParty-2", "downloads_id", 3),
                     thirdPartyCategoryData = null,
                     imageCategoryData = null,
-                    collectionCategoryData = null
+                    collectionCategoryData = null,
                 )
             )
         )
     }
 
     companion object {
-        private const val NUMBER_OF_FAKE_CATEGORIES_EXCEPT_MY_PHOTOS = 5
+        private const val NUMBER_OF_FAKE_CATEGORIES_EXCEPT_MY_PHOTOS = 2
     }
 }
diff --git a/tests/robotests/src/com/android/wallpaper/picker/category/repository/DefaultWallpaperCategoryRepositoryTest.kt b/tests/robotests/src/com/android/wallpaper/picker/category/repository/DefaultWallpaperCategoryRepositoryTest.kt
index d1a479d8..e1a9d2d9 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/category/repository/DefaultWallpaperCategoryRepositoryTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/category/repository/DefaultWallpaperCategoryRepositoryTest.kt
@@ -34,6 +34,7 @@ import dagger.hilt.android.testing.HiltAndroidRule
 import dagger.hilt.android.testing.HiltAndroidTest
 import javax.inject.Inject
 import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.launch
 import kotlinx.coroutines.test.TestScope
 import kotlinx.coroutines.test.advanceUntilIdle
 import kotlinx.coroutines.test.runTest
@@ -70,7 +71,7 @@ class DefaultWallpaperCategoryRepositoryTest {
                 ImageCategory(
                     "My photos" /* title */,
                     "image_wallpapers" /* collection */,
-                    0 /* priority */
+                    0, /* priority */
                 )
 
             val wallpapers = ArrayList<WallpaperInfo>()
@@ -81,7 +82,7 @@ class DefaultWallpaperCategoryRepositoryTest {
                     "Test category",
                     "init_collection",
                     wallpapers,
-                    1 /* priority */
+                    1, /* priority */
                 )
 
             val thirdPartyLiveWallpaperCategory: Category =
@@ -90,7 +91,7 @@ class DefaultWallpaperCategoryRepositoryTest {
                     "Third_Party_CollectionId",
                     wallpapers,
                     1,
-                    emptySet()
+                    emptySet(),
                 )
 
             val mCategories = ArrayList<Category>()
@@ -107,7 +108,7 @@ class DefaultWallpaperCategoryRepositoryTest {
                     context,
                     defaultWallpaperCategoryClient,
                     defaultCategoryFactory,
-                    testScope
+                    testScope,
                 )
             testScope.advanceUntilIdle()
             assertThat(repository.isDefaultCategoriesFetched.value).isTrue()
@@ -122,9 +123,43 @@ class DefaultWallpaperCategoryRepositoryTest {
                 context,
                 defaultWallpaperCategoryClient,
                 defaultCategoryFactory,
-                testScope
+                testScope,
             )
         assertThat(repository.systemCategories.value).isEmpty()
         assertThat(repository.isDefaultCategoriesFetched.value).isFalse()
     }
+
+    @Test
+    fun refreshThirdPartyLiveWallpaperCategoriesShouldUpdateStateCorrectly() = runTest {
+        repository =
+            DefaultWallpaperCategoryRepository(
+                context,
+                defaultWallpaperCategoryClient,
+                defaultCategoryFactory,
+                testScope,
+            )
+
+        val job = launch { repository.refreshThirdPartyLiveWallpaperCategories() }
+        assertThat(repository.isDefaultCategoriesFetched.value).isFalse()
+        testScope.advanceUntilIdle()
+        job.join()
+        assertThat(repository.isDefaultCategoriesFetched.value).isTrue()
+    }
+
+    @Test
+    fun refreshThirdPartyAppCategoriesShouldUpdateStateCorrectly() = runTest {
+        repository =
+            DefaultWallpaperCategoryRepository(
+                context,
+                defaultWallpaperCategoryClient,
+                defaultCategoryFactory,
+                testScope,
+            )
+
+        val job = launch { repository.refreshThirdPartyAppCategories() }
+        assertThat(repository.isDefaultCategoriesFetched.value).isFalse()
+        testScope.advanceUntilIdle()
+        job.join()
+        assertThat(repository.isDefaultCategoriesFetched.value).isTrue()
+    }
 }
diff --git a/tests/robotests/src/com/android/wallpaper/picker/customization/data/repository/CustomizationRuntimeValuesRepositoryTest.kt b/tests/robotests/src/com/android/wallpaper/picker/customization/data/repository/CustomizationRuntimeValuesRepositoryTest.kt
new file mode 100644
index 00000000..5bb4995c
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/picker/customization/data/repository/CustomizationRuntimeValuesRepositoryTest.kt
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
+
+package com.android.wallpaper.picker.customization.data.repository
+
+import android.os.Bundle
+import com.android.systemui.shared.customization.data.content.CustomizationProviderContract
+import com.android.systemui.shared.customization.data.content.FakeCustomizationProviderClient
+import com.android.wallpaper.testing.collectLastValue
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.runTest
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+
+@HiltAndroidTest
+@RunWith(RobolectricTestRunner::class)
+class CustomizationRuntimeValuesRepositoryTest {
+    @get:Rule(order = 0) var hiltRule = HiltAndroidRule(this)
+
+    @Inject lateinit var testScope: TestScope
+
+    private val customizationProviderClient = FakeCustomizationProviderClient()
+    lateinit var underTest: CustomizationRuntimeValuesRepository
+
+    @Before
+    fun setUp() {
+        hiltRule.inject()
+        underTest =
+            CustomizationRuntimeValuesRepository(
+                testScope.backgroundScope,
+                customizationProviderClient,
+            )
+    }
+
+    @Test
+    fun isShadeLayoutWideUpdatesUpdatesWhenClientUpdates() =
+        testScope.runTest {
+            val isShadeLayoutWide = collectLastValue(underTest.isShadeLayoutWide)
+
+            assertThat(isShadeLayoutWide()).isFalse()
+
+            customizationProviderClient.setRuntimeValues(
+                Bundle().apply {
+                    putBoolean(
+                        CustomizationProviderContract.RuntimeValuesTable.KEY_IS_SHADE_LAYOUT_WIDE,
+                        true,
+                    )
+                }
+            )
+
+            assertThat(isShadeLayoutWide()).isTrue()
+        }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/picker/customization/data/repository/ImageEffectsRepositoryImplTest.kt b/tests/robotests/src/com/android/wallpaper/picker/customization/data/repository/ImageEffectsRepositoryImplTest.kt
index 39aebeca..f144b42b 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/customization/data/repository/ImageEffectsRepositoryImplTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/customization/data/repository/ImageEffectsRepositoryImplTest.kt
@@ -17,12 +17,7 @@
 package com.android.wallpaper.picker.customization.data.repository
 
 import android.content.Context
-import android.content.Intent
-import android.content.pm.PackageManager
-import android.content.pm.ResolveInfo
-import android.content.pm.ServiceInfo
 import android.net.Uri
-import android.service.wallpaper.WallpaperService
 import com.android.wallpaper.effects.Effect
 import com.android.wallpaper.effects.EffectsController
 import com.android.wallpaper.effects.EffectsController.RESULT_PROBE_SUCCESS
@@ -37,6 +32,7 @@ import com.android.wallpaper.testing.FakeContentProvider
 import com.android.wallpaper.testing.FakeContentProvider.Companion.FAKE_EFFECT_ID
 import com.android.wallpaper.testing.FakeContentProvider.Companion.FAKE_EFFECT_TITLE
 import com.android.wallpaper.testing.ShadowWallpaperInfo
+import com.android.wallpaper.testing.WallpaperInfoUtils
 import com.android.wallpaper.testing.WallpaperModelUtils.Companion.getStaticWallpaperModel
 import com.android.wallpaper.testing.collectLastValue
 import com.android.wallpaper.widget.floatingsheetcontent.WallpaperEffectsView2
@@ -53,7 +49,6 @@ import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
 import org.robolectric.RobolectricTestRunner
-import org.robolectric.Shadows.shadowOf
 import org.robolectric.annotation.Config
 import org.robolectric.shadows.ShadowContentResolver
 
@@ -73,7 +68,7 @@ class ImageEffectsRepositoryImplTest {
         getStaticWallpaperModel(
             wallpaperId = "testWallpaperId",
             collectionId = "testCollection",
-            imageWallpaperUri = Uri.parse("content://com.test/image")
+            imageWallpaperUri = Uri.parse("content://com.test/image"),
         )
 
     @Before
@@ -84,38 +79,24 @@ class ImageEffectsRepositoryImplTest {
             FakeEffectsController.AUTHORITY,
             contentProvider,
         )
-        // Make a shadow of package manager
-        val pm = shadowOf(context.packageManager)
-        val packageName = LIVE_WALLPAPER_COMPONENT_PKG_NAME
-        val className = LIVE_WALLPAPER_COMPONENT_CLASS_NAME
-        val resolveInfo =
-            ResolveInfo().apply {
-                serviceInfo = ServiceInfo()
-                serviceInfo.packageName = packageName
-                serviceInfo.splitName = "effectsWallpaper"
-                serviceInfo.name = className
-                serviceInfo.flags = PackageManager.GET_META_DATA
-            }
-        val intent = Intent(WallpaperService.SERVICE_INTERFACE).setClassName(packageName, className)
-        pm.addResolveInfoForIntent(intent, resolveInfo)
+        WallpaperInfoUtils.createWallpaperInfo(
+            context = context,
+            stubPackage = LIVE_WALLPAPER_COMPONENT_PKG_NAME,
+            wallpaperSplit = "effectsWallpaper",
+            wallpaperClass = LIVE_WALLPAPER_COMPONENT_CLASS_NAME,
+        )
     }
 
     @Test
     fun areEffectsAvailableTrue() {
-        val underTest =
-            getImageEffectsRepositoryForTesting(
-                areEffectsAvailable = true,
-            )
+        val underTest = getImageEffectsRepositoryForTesting(areEffectsAvailable = true)
 
         assertThat(underTest.areEffectsAvailable()).isTrue()
     }
 
     @Test
     fun areEffectsAvailableFalse() {
-        val underTest =
-            getImageEffectsRepositoryForTesting(
-                areEffectsAvailable = false,
-            )
+        val underTest = getImageEffectsRepositoryForTesting(areEffectsAvailable = false)
 
         assertThat(underTest.areEffectsAvailable()).isFalse()
     }
@@ -144,10 +125,7 @@ class ImageEffectsRepositoryImplTest {
     @Test
     fun initializeEffect_isEffectTriggeredTrue() =
         testScope.runTest {
-            val underTest =
-                getImageEffectsRepositoryForTesting(
-                    isEffectTriggered = true,
-                )
+            val underTest = getImageEffectsRepositoryForTesting(isEffectTriggered = true)
             val imageEffectsModel = collectLastValue(underTest.imageEffectsModel)
 
             underTest.initializeEffect(
@@ -162,10 +140,7 @@ class ImageEffectsRepositoryImplTest {
     @Test
     fun initializeEffect_isEffectTriggeredFalse() =
         testScope.runTest {
-            val underTest =
-                getImageEffectsRepositoryForTesting(
-                    isEffectTriggered = false,
-                )
+            val underTest = getImageEffectsRepositoryForTesting(isEffectTriggered = false)
             val imageEffectsModel = collectLastValue(underTest.imageEffectsModel)
 
             underTest.initializeEffect(
@@ -177,7 +152,7 @@ class ImageEffectsRepositoryImplTest {
                 .isEqualTo(
                     ImageEffectsModel(
                         ImageEffectsRepository.EffectStatus.EFFECT_READY,
-                        RESULT_PROBE_SUCCESS
+                        RESULT_PROBE_SUCCESS,
                     )
                 )
         }
@@ -281,18 +256,14 @@ class ImageEffectsRepositoryImplTest {
                 onWallpaperModelUpdated = { _ -> },
             )
             underTest.startEffectsModelDownload(
-                Effect(
-                    FAKE_EFFECT_ID,
-                    FAKE_EFFECT_TITLE,
-                    FakeEffectsController.Effect.FAKE_EFFECT,
-                )
+                Effect(FAKE_EFFECT_ID, FAKE_EFFECT_TITLE, FakeEffectsController.Effect.FAKE_EFFECT)
             )
 
             assertThat(imageEffectsModel())
                 .isEqualTo(
                     ImageEffectsModel(
                         ImageEffectsRepository.EffectStatus.EFFECT_READY,
-                        EffectsController.RESULT_FOREGROUND_DOWNLOAD_SUCCEEDED
+                        EffectsController.RESULT_FOREGROUND_DOWNLOAD_SUCCEEDED,
                     )
                 )
         }
diff --git a/tests/robotests/src/com/android/wallpaper/picker/customization/ui/viewmodel/ColorUpdateViewModelTest.kt b/tests/robotests/src/com/android/wallpaper/picker/customization/ui/viewmodel/ColorUpdateViewModelTest.kt
new file mode 100644
index 00000000..b2dfbfbd
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/picker/customization/ui/viewmodel/ColorUpdateViewModelTest.kt
@@ -0,0 +1,119 @@
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
+import android.util.SparseIntArray
+import android.widget.RemoteViews.ColorResources
+import androidx.test.filters.SmallTest
+import androidx.test.platform.app.InstrumentationRegistry
+import com.android.systemui.monet.Style
+import com.android.wallpaper.testing.collectLastValue
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.runTest
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+
+@HiltAndroidTest
+@SmallTest
+@RunWith(RobolectricTestRunner::class)
+class ColorUpdateViewModelTest {
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+
+    private lateinit var context: Context
+    private lateinit var underTest: ColorUpdateViewModel
+    @Inject lateinit var testScope: TestScope
+
+    @Before
+    fun setUp() {
+        hiltRule.inject()
+
+        context = InstrumentationRegistry.getInstrumentation().targetContext
+        underTest = ColorUpdateViewModel(context)
+    }
+
+    private fun overlayColors(context: Context, colorMapping: SparseIntArray) {
+        ColorResources.create(context, colorMapping)?.apply(context)
+    }
+
+    @Test
+    fun updateColors() {
+        testScope.runTest {
+            val colorPrimary = collectLastValue(underTest.colorPrimary)
+            assertThat(colorPrimary()).isNotEqualTo(12345)
+
+            overlayColors(
+                context,
+                SparseIntArray().apply {
+                    put(android.R.color.system_primary_light, 12345)
+                    put(android.R.color.system_primary_dark, 12345)
+                },
+            )
+            underTest.updateColors()
+
+            assertThat(colorPrimary()).isEqualTo(12345)
+        }
+    }
+
+    @Test
+    fun previewColors() {
+        testScope.runTest {
+            val colorPrimary = collectLastValue(underTest.colorPrimary)
+            overlayColors(
+                context,
+                SparseIntArray().apply {
+                    put(android.R.color.system_primary_light, 12345)
+                    put(android.R.color.system_primary_dark, 12345)
+                },
+            )
+            underTest.updateColors()
+            assertThat(colorPrimary()).isEqualTo(12345)
+
+            underTest.previewColors(54321, Style.VIBRANT)
+
+            assertThat(colorPrimary()).isNotEqualTo(12345)
+        }
+    }
+
+    @Test
+    fun resetPreview() {
+        testScope.runTest {
+            val colorPrimary = collectLastValue(underTest.colorPrimary)
+            overlayColors(
+                context,
+                SparseIntArray().apply {
+                    put(android.R.color.system_primary_light, 12345)
+                    put(android.R.color.system_primary_dark, 12345)
+                },
+            )
+            underTest.updateColors()
+            assertThat(colorPrimary()).isEqualTo(12345)
+
+            underTest.previewColors(54321, Style.VIBRANT)
+            underTest.resetPreview()
+
+            assertThat(colorPrimary()).isEqualTo(12345)
+        }
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/picker/preview/domain/interactor/WallpaperPreviewInteractorTest.kt b/tests/robotests/src/com/android/wallpaper/picker/preview/domain/interactor/WallpaperPreviewInteractorTest.kt
index aed30ac7..4819dac6 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/preview/domain/interactor/WallpaperPreviewInteractorTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/preview/domain/interactor/WallpaperPreviewInteractorTest.kt
@@ -157,7 +157,7 @@ class WallpaperPreviewInteractorTest {
                     serviceInfo.splitName = "wallpaper_cities_ny"
                     serviceInfo.name = "NewYorkWallpaper"
                     serviceInfo.flags = PackageManager.GET_META_DATA
-                }
+                },
             )
         val wallpaperModel =
             WallpaperModelUtils.getLiveWallpaperModel(
diff --git a/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/CategoriesViewModelTest.kt b/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/CategoriesViewModelTest.kt
index 2c8582de..ee192e9c 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/CategoriesViewModelTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/CategoriesViewModelTest.kt
@@ -158,7 +158,7 @@ class CategoriesViewModelTest {
                     .isEqualTo(
                         CategoriesViewModel.NavigationEvent.NavigateToWallpaperCollection(
                             CATEGORY_ID_CELESTIAL_DREAMSCAPES,
-                            CategoriesViewModel.CategoryType.DefaultCategories
+                            CategoriesViewModel.CategoryType.DefaultCategories,
                         )
                     )
 
@@ -181,7 +181,7 @@ class CategoriesViewModelTest {
                     .isEqualTo(
                         CategoriesViewModel.NavigationEvent.NavigateToWallpaperCollection(
                             CATEGORY_ID_CYBERPUNK_CITYSCAPE,
-                            CategoriesViewModel.CategoryType.DefaultCategories
+                            CategoriesViewModel.CategoryType.DefaultCategories,
                         )
                     )
                 job.cancelAndJoin()
@@ -201,7 +201,7 @@ class CategoriesViewModelTest {
                     .isEqualTo(
                         CategoriesViewModel.NavigationEvent.NavigateToWallpaperCollection(
                             CATEGORY_ID_COSMIC_NEBULA,
-                            CategoriesViewModel.CategoryType.DefaultCategories
+                            CategoriesViewModel.CategoryType.DefaultCategories,
                         )
                     )
                 job.cancelAndJoin()
@@ -224,8 +224,9 @@ class CategoriesViewModelTest {
 
             onClick()
             testDispatcher.scheduler.advanceUntilIdle()
-            assertThat(collectedValues[0])
-                .isEqualTo(CategoriesViewModel.NavigationEvent.NavigateToPhotosPicker)
+            val navigateToPhotosPicker =
+                CategoriesViewModel.NavigationEvent.NavigateToPhotosPicker(null)
+            assertThat(collectedValues[0]).isEqualTo(navigateToPhotosPicker)
             job.cancelAndJoin()
         }
     }
diff --git a/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/StaticWallpaperPreviewViewModelTest.kt b/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/StaticWallpaperPreviewViewModelTest.kt
index cc4d7d80..39d72d78 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/StaticWallpaperPreviewViewModelTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/StaticWallpaperPreviewViewModelTest.kt
@@ -44,7 +44,12 @@ import com.android.wallpaper.testing.TestInjector
 import com.android.wallpaper.testing.TestWallpaperPreferences
 import com.android.wallpaper.testing.WallpaperModelUtils
 import com.android.wallpaper.testing.collectLastValue
+import com.android.wallpaper.util.wallpaperconnection.WallpaperConnectionUtils
 import com.google.common.truth.Truth.assertThat
+import dagger.hilt.EntryPoint
+import dagger.hilt.InstallIn
+import dagger.hilt.android.EntryPointAccessors
+import dagger.hilt.android.components.ActivityComponent
 import dagger.hilt.android.qualifiers.ApplicationContext
 import dagger.hilt.android.testing.HiltAndroidRule
 import dagger.hilt.android.testing.HiltAndroidTest
@@ -106,7 +111,15 @@ class StaticWallpaperPreviewViewModelTest {
         scenario.onActivity { setEverything(it) }
     }
 
+    @EntryPoint
+    @InstallIn(ActivityComponent::class)
+    interface ActivityScopeEntryPoint {
+        fun connectionUtils(): WallpaperConnectionUtils
+    }
+
     private fun setEverything(activity: PreviewTestActivity) {
+        val activityScopeEntryPoint =
+            EntryPointAccessors.fromActivity(activity, ActivityScopeEntryPoint::class.java)
         wallpaperRepository =
             WallpaperRepository(
                 testScope.backgroundScope,
@@ -115,7 +128,13 @@ class StaticWallpaperPreviewViewModelTest {
                 testDispatcher,
             )
         wallpaperPreviewRepository = WallpaperPreviewRepository(wallpaperPreferences)
-        interactor = WallpaperPreviewInteractor(wallpaperPreviewRepository, wallpaperRepository)
+        interactor =
+            WallpaperPreviewInteractor(
+                appContext,
+                wallpaperPreviewRepository,
+                wallpaperRepository,
+                activityScopeEntryPoint.connectionUtils(),
+            )
         viewModel =
             StaticWallpaperPreviewViewModel(
                 interactor,
diff --git a/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModelTest.kt b/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModelTest.kt
index 6b0c4084..eae79c46 100644
--- a/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModelTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/picker/preview/ui/viewmodel/WallpaperPreviewViewModelTest.kt
@@ -21,11 +21,7 @@ import android.content.ComponentName
 import android.content.Context
 import android.content.Intent
 import android.content.pm.ActivityInfo
-import android.content.pm.PackageManager
-import android.content.pm.ResolveInfo
-import android.content.pm.ServiceInfo
 import android.graphics.Rect
-import android.service.wallpaper.WallpaperService
 import androidx.activity.viewModels
 import androidx.test.core.app.ActivityScenario
 import com.android.wallpaper.effects.FakeEffectsController
@@ -44,6 +40,7 @@ import com.android.wallpaper.picker.preview.data.repository.ImageEffectsReposito
 import com.android.wallpaper.picker.preview.data.repository.WallpaperPreviewRepository
 import com.android.wallpaper.picker.preview.shared.model.FullPreviewCropModel
 import com.android.wallpaper.picker.preview.shared.model.ImageEffectsModel
+import com.android.wallpaper.picker.preview.ui.viewmodel.WallpaperPreviewViewModel.Companion.PreviewScreen
 import com.android.wallpaper.testing.FakeContentProvider
 import com.android.wallpaper.testing.FakeDisplaysProvider
 import com.android.wallpaper.testing.FakeDisplaysProvider.Companion.FOLDABLE_UNFOLDED_LAND
@@ -51,8 +48,10 @@ import com.android.wallpaper.testing.FakeDisplaysProvider.Companion.HANDHELD
 import com.android.wallpaper.testing.FakeImageEffectsRepository
 import com.android.wallpaper.testing.FakeLiveWallpaperDownloader
 import com.android.wallpaper.testing.FakeWallpaperClient
+import com.android.wallpaper.testing.ShadowWallpaperInfo
 import com.android.wallpaper.testing.TestInjector
 import com.android.wallpaper.testing.TestWallpaperPreferences
+import com.android.wallpaper.testing.WallpaperInfoUtils
 import com.android.wallpaper.testing.WallpaperModelUtils
 import com.android.wallpaper.testing.collectLastValue
 import com.android.wallpaper.util.PreviewUtils
@@ -70,18 +69,23 @@ import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.test.TestDispatcher
 import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.runCurrent
 import kotlinx.coroutines.test.runTest
 import kotlinx.coroutines.test.setMain
 import org.junit.Before
+import org.junit.Ignore
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
 import org.robolectric.RobolectricTestRunner
 import org.robolectric.Shadows
+import org.robolectric.annotation.Config
 import org.robolectric.shadows.ShadowContentResolver
+import org.robolectric.shadows.ShadowLooper
 
 @HiltAndroidTest
 @OptIn(ExperimentalCoroutinesApi::class)
+@Config(shadows = [ShadowWallpaperInfo::class])
 @RunWith(RobolectricTestRunner::class)
 class WallpaperPreviewViewModelTest {
     @get:Rule var hiltRule = HiltAndroidRule(this)
@@ -91,12 +95,12 @@ class WallpaperPreviewViewModelTest {
     private lateinit var staticWallpapaperPreviewViewModel: StaticWallpaperPreviewViewModel
     private lateinit var wallpaperPreviewRepository: WallpaperPreviewRepository
     private lateinit var startActivityIntent: Intent
+    private lateinit var effectsWallpaperInfo: WallpaperInfo
     @HomeScreenPreviewUtils private lateinit var homePreviewUtils: PreviewUtils
     @LockScreenPreviewUtils private lateinit var lockPreviewUtils: PreviewUtils
-
-    @Inject @ApplicationContext lateinit var appContext: Context
     @Inject lateinit var testDispatcher: TestDispatcher
     @Inject lateinit var testScope: TestScope
+    @Inject @ApplicationContext lateinit var appContext: Context
     @Inject lateinit var testInjector: TestInjector
     @Inject lateinit var wallpaperDownloader: FakeLiveWallpaperDownloader
     @Inject lateinit var wallpaperPreferences: TestWallpaperPreferences
@@ -127,19 +131,13 @@ class WallpaperPreviewViewModelTest {
             contentProvider,
         )
 
-        // Provide resolution info for our fake content provider
-        val packageName = FakeEffectsController.LIVE_WALLPAPER_COMPONENT_PKG_NAME
-        val className = FakeEffectsController.LIVE_WALLPAPER_COMPONENT_CLASS_NAME
-        val resolveInfo =
-            ResolveInfo().apply {
-                serviceInfo = ServiceInfo()
-                serviceInfo.packageName = packageName
-                serviceInfo.splitName = "effectsWallpaper"
-                serviceInfo.name = className
-                serviceInfo.flags = PackageManager.GET_META_DATA
-            }
-        val intent = Intent(WallpaperService.SERVICE_INTERFACE).setClassName(packageName, className)
-        pm.addResolveInfoForIntent(intent, resolveInfo)
+        effectsWallpaperInfo =
+            WallpaperInfoUtils.createWallpaperInfo(
+                context = appContext,
+                stubPackage = FakeEffectsController.LIVE_WALLPAPER_COMPONENT_PKG_NAME,
+                wallpaperSplit = "effectsWallpaper",
+                wallpaperClass = FakeEffectsController.LIVE_WALLPAPER_COMPONENT_CLASS_NAME,
+            )
 
         startActivityIntent =
             Intent.makeMainActivity(ComponentName(appContext, PreviewTestActivity::class.java))
@@ -168,6 +166,129 @@ class WallpaperPreviewViewModelTest {
             wallpaperPreviewViewModel.staticWallpaperPreviewViewModel
     }
 
+    @Test
+    fun testBackPress_onFullPreviewScreen() =
+        testScope.runTest {
+            val currentPreviewScreen =
+                collectLastValue(wallpaperPreviewViewModel.currentPreviewScreen)
+
+            val handled = wallpaperPreviewViewModel.handleBackPressed()
+
+            assertThat(handled).isFalse()
+            assertThat(currentPreviewScreen()).isEqualTo(PreviewScreen.SMALL_PREVIEW)
+        }
+
+    @Test
+    fun testBackPress_onApplyWallpaperScreen() =
+        testScope.runTest {
+            val currentPreviewScreen =
+                collectLastValue(wallpaperPreviewViewModel.currentPreviewScreen)
+            val onNextButtonClicked =
+                collectLastValue(wallpaperPreviewViewModel.onNextButtonClicked)
+            val model =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testId",
+                    collectionId = "testCollection",
+                )
+            wallpaperPreviewRepository.setWallpaperModel(model)
+            executePendingWork(this)
+            // Navigates to apply wallpaper screen
+            onNextButtonClicked()?.invoke()
+
+            val handled = wallpaperPreviewViewModel.handleBackPressed()
+
+            assertThat(handled).isTrue()
+            assertThat(currentPreviewScreen()).isEqualTo(PreviewScreen.SMALL_PREVIEW)
+        }
+
+    @Test
+    fun onApplyWallpaperScreen_shouldEnableClickOnPager() =
+        testScope.runTest {
+            val shouldEnableClickOnPager =
+                collectLastValue(wallpaperPreviewViewModel.shouldEnableClickOnPager)
+            val onNextButtonClicked =
+                collectLastValue(wallpaperPreviewViewModel.onNextButtonClicked)
+            val model =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testId",
+                    collectionId = "testCollection",
+                )
+            wallpaperPreviewRepository.setWallpaperModel(model)
+            executePendingWork(this)
+            // Navigates to apply wallpaper screen
+            onNextButtonClicked()?.invoke()
+
+            assertThat(shouldEnableClickOnPager()).isTrue()
+        }
+
+    @Ignore("b/367372434: test shouldEnableClickOnPager when implementing full preview")
+    @Test
+    fun onFullPreviewScreen_shouldNotEnableClickOnPager() = testScope.runTest {}
+
+    @Test
+    fun clickNextButton_setsApplyWallpaperScreen() =
+        testScope.runTest {
+            val onNextButtonClicked =
+                collectLastValue(wallpaperPreviewViewModel.onNextButtonClicked)
+            val model =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testId",
+                    collectionId = "testCollection",
+                )
+            wallpaperPreviewRepository.setWallpaperModel(model)
+            executePendingWork(this)
+
+            onNextButtonClicked()?.invoke()
+
+            assertThat(wallpaperPreviewViewModel.currentPreviewScreen.value)
+                .isEqualTo(PreviewScreen.APPLY_WALLPAPER)
+        }
+
+    @Test
+    fun clickCancelButton_setsSmallPreviewScreen() =
+        testScope.runTest {
+            val onCancelButtonClicked =
+                collectLastValue(wallpaperPreviewViewModel.onCancelButtonClicked)
+            val onNextButtonClicked =
+                collectLastValue(wallpaperPreviewViewModel.onNextButtonClicked)
+            val model =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testId",
+                    collectionId = "testCollection",
+                )
+            wallpaperPreviewRepository.setWallpaperModel(model)
+            executePendingWork(this)
+            // Navigates to apply wallpaper screen
+            onNextButtonClicked()?.invoke()
+
+            onCancelButtonClicked()?.invoke()
+
+            assertThat(wallpaperPreviewViewModel.currentPreviewScreen.value)
+                .isEqualTo(PreviewScreen.SMALL_PREVIEW)
+        }
+
+    @Test
+    fun navigatesUpOnApplyWallpaperScreen_setsSmallPreviewScreen() =
+        testScope.runTest {
+            val onNextButtonClicked =
+                collectLastValue(wallpaperPreviewViewModel.onNextButtonClicked)
+            val model =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testId",
+                    collectionId = "testCollection",
+                )
+            wallpaperPreviewRepository.setWallpaperModel(model)
+            executePendingWork(this)
+            // Navigates to apply wallpaper screen
+            onNextButtonClicked()?.invoke()
+
+            val shouldHandleBackPress = wallpaperPreviewViewModel.handleBackPressed()
+
+            assertThat(shouldHandleBackPress).isTrue()
+            assertThat(wallpaperPreviewViewModel.currentPreviewScreen.value)
+                .isEqualTo(PreviewScreen.SMALL_PREVIEW)
+        }
+
     @Test
     fun startActivity_withViewAsHome_setsToViewModel() {
         startActivityForTesting(isViewAsHome = true)
@@ -218,17 +339,13 @@ class WallpaperPreviewViewModelTest {
     fun clickSmallPreview_isSelectedPreview_updatesFullWallpaperPreviewConfig() =
         testScope.runTest {
             val model = WallpaperModelUtils.getStaticWallpaperModel("testId", "testCollection")
-            updateFullWallpaperFlow(
-                model,
-                WhichPreview.PREVIEW_CURRENT,
-                listOf(HANDHELD),
-            )
+            updateFullWallpaperFlow(model, WhichPreview.PREVIEW_CURRENT, listOf(HANDHELD))
             wallpaperPreviewViewModel.setSmallPreviewSelectedTab(Screen.LOCK_SCREEN)
             val onLockPreviewClicked =
                 collectLastValue(
                     wallpaperPreviewViewModel.onSmallPreviewClicked(
                         Screen.LOCK_SCREEN,
-                        DeviceDisplayType.SINGLE
+                        DeviceDisplayType.SINGLE,
                     ) {}
                 )
 
@@ -287,10 +404,7 @@ class WallpaperPreviewViewModelTest {
             // Set a crop and confirm via clicking button
             wallpaperPreviewViewModel.staticWallpaperPreviewViewModel.fullPreviewCropModels[
                     FOLDABLE_UNFOLDED_LAND.displaySize] =
-                FullPreviewCropModel(
-                    cropHint = newCropRect,
-                    cropSizeModel = null,
-                )
+                FullPreviewCropModel(cropHint = newCropRect, cropSizeModel = null)
             collectLastValue(wallpaperPreviewViewModel.onCropButtonClick)()?.invoke()
 
             val cropHintsInfo =
@@ -300,6 +414,52 @@ class WallpaperPreviewViewModelTest {
                 .isEqualTo(newCropRect)
         }
 
+    @Test
+    fun previewLiveWallpaper_disablesCropping() =
+        testScope.runTest {
+            val model =
+                WallpaperModelUtils.getLiveWallpaperModel(
+                    wallpaperId = "testWallpaperId",
+                    collectionId = "testCollectionId",
+                    systemWallpaperInfo = effectsWallpaperInfo,
+                )
+            updateFullWallpaperFlow(model, WhichPreview.PREVIEW_CURRENT, listOf(HANDHELD))
+
+            wallpaperPreviewViewModel.onSmallPreviewClicked(
+                Screen.HOME_SCREEN,
+                DeviceDisplayType.SINGLE,
+            ) {}
+
+            val onCropButtonClick = collectLastValue(wallpaperPreviewViewModel.onCropButtonClick)()
+            assertThat(onCropButtonClick).isNull()
+        }
+
+    @Test
+    fun clickSetWallpaperButton_showsSetWallpaperDialog() =
+        testScope.runTest {
+            val onSetWallpaperButtonClicked =
+                collectLastValue(wallpaperPreviewViewModel.onSetWallpaperButtonClicked)
+            val newCropRect = Rect(10, 10, 10, 10)
+            val model =
+                WallpaperModelUtils.getStaticWallpaperModel(
+                    wallpaperId = "testId",
+                    collectionId = "testCollection",
+                )
+            wallpaperPreviewRepository.setWallpaperModel(model)
+            wallpaperPreviewViewModel.staticWallpaperPreviewViewModel.updateCropHintsInfo(
+                mapOf(
+                    FOLDABLE_UNFOLDED_LAND.displaySize to
+                        FullPreviewCropModel(cropHint = newCropRect, cropSizeModel = null)
+                )
+            )
+            executePendingWork(this)
+
+            onSetWallpaperButtonClicked()?.invoke()
+
+            val showDialog = collectLastValue(wallpaperPreviewViewModel.showSetWallpaperDialog)()
+            assertThat(showDialog).isTrue()
+        }
+
     /**
      * Updates all upstream flows of [WallpaperPreviewViewModel.fullWallpaper] except
      * [WallpaperPreviewViewModel.fullPreviewConfigViewModel].
@@ -337,4 +497,15 @@ class WallpaperPreviewViewModelTest {
             )
         scenario.onActivity { setEverything(it) }
     }
+
+    private fun executePendingWork(testScope: TestScope) {
+        // Run suspendCancellableCoroutine in assetDetail's decodeRawDimensions
+        testScope.runCurrent()
+        // Run handler.post in TestAsset.decodeRawDimensions
+        ShadowLooper.runUiThreadTasksIncludingDelayedTasks()
+        // Run suspendCancellableCoroutine in assetDetail's decodeBitmap
+        testScope.runCurrent()
+        // Run handler.post in TestAsset.decodeBitmap
+        ShadowLooper.runUiThreadTasksIncludingDelayedTasks()
+    }
 }
diff --git a/tests/src/com/android/wallpaper/picker/preview/ui/fragment/SmallPreviewFragmentTest.kt b/tests/src/com/android/wallpaper/picker/preview/ui/fragment/SmallPreviewFragmentTest.kt
deleted file mode 100644
index c661931e..00000000
--- a/tests/src/com/android/wallpaper/picker/preview/ui/fragment/SmallPreviewFragmentTest.kt
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
-package com.android.wallpaper.picker.preview.ui.fragment
-
-import androidx.test.filters.MediumTest
-import androidx.test.runner.AndroidJUnit4
-import com.android.wallpaper.model.WallpaperInfo
-import com.android.wallpaper.module.InjectorProvider
-import com.android.wallpaper.module.logging.TestUserEventLogger
-import com.android.wallpaper.testing.TestInjector
-import com.android.wallpaper.testing.TestStaticWallpaperInfo
-import org.junit.Before
-import org.junit.Ignore
-import org.junit.Test
-import org.junit.runner.RunWith
-
-@MediumTest
-@RunWith(AndroidJUnit4::class)
-class SmallPreviewFragmentTest {
-    private val testStaticWallpaper =
-        TestStaticWallpaperInfo(TestStaticWallpaperInfo.COLOR_DEFAULT).setWallpaperAttributions()
-    private val testUserEventLogger = TestUserEventLogger()
-
-    @Before
-    fun setUp() {
-        InjectorProvider.setInjector(TestInjector(testUserEventLogger))
-    }
-
-    @Test @Ignore("b/295958495") fun testWallpaperInfoIsNotNull() {}
-
-    private fun TestStaticWallpaperInfo.setWallpaperAttributions(): WallpaperInfo {
-        setAttributions(listOf("Title", "Subtitle 1", "Subtitle 2"))
-        setCollectionId("collectionStatic")
-        setWallpaperId("wallpaperStatic")
-        setActionUrl("http://google.com")
-        return this
-    }
-}
```

