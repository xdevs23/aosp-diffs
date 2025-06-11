```diff
diff --git a/car-assist-client-lib/OWNERS b/car-assist-client-lib/OWNERS
index 7638574..0b1066a 100644
--- a/car-assist-client-lib/OWNERS
+++ b/car-assist-client-lib/OWNERS
@@ -1,2 +1 @@
 # People who can approve changes for submission.
-uokoye@google.com
diff --git a/car-qc-lib/Android.bp b/car-qc-lib/Android.bp
index 76c8991..fa4032f 100644
--- a/car-qc-lib/Android.bp
+++ b/car-qc-lib/Android.bp
@@ -39,6 +39,12 @@ android_library {
     static_libs: [
         "androidx.annotation_annotation",
         "car-ui-lib-no-overlayable",
-        "car-resource-common",
+        "oem-token-lib",
     ],
+
+    libs: [
+        "token-shared-lib-prebuilt",
+    ],
+
+    enforce_uses_libs: false,
 }
diff --git a/car-qc-lib/res/color/divider_color.xml b/car-qc-lib/res/color/divider_color.xml
new file mode 100644
index 0000000..ddbbf3f
--- /dev/null
+++ b/car-qc-lib/res/color/divider_color.xml
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
+    <item android:color="?oemColorSurfaceContainerHighest"/>
+</selector>
diff --git a/car-qc-lib/res/color/qc_seekbar_thumb.xml b/car-qc-lib/res/color/qc_seekbar_thumb.xml
new file mode 100644
index 0000000..8549442
--- /dev/null
+++ b/car-qc-lib/res/color/qc_seekbar_thumb.xml
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
diff --git a/car-qc-lib/res/color/qc_seekbar_thumb_disabled_on_dark.xml b/car-qc-lib/res/color/qc_seekbar_thumb_disabled_on_dark.xml
new file mode 100644
index 0000000..43032ba
--- /dev/null
+++ b/car-qc-lib/res/color/qc_seekbar_thumb_disabled_on_dark.xml
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
+    <item android:color="?oemColorOnSurfaceInverse"/>
+</selector>
diff --git a/car-qc-lib/res/color/qc_start_icon_color.xml b/car-qc-lib/res/color/qc_start_icon_color.xml
new file mode 100644
index 0000000..8549442
--- /dev/null
+++ b/car-qc-lib/res/color/qc_start_icon_color.xml
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
diff --git a/car-qc-lib/res/color/qc_switch_thumb_color.xml b/car-qc-lib/res/color/qc_switch_thumb_color.xml
new file mode 100644
index 0000000..8549442
--- /dev/null
+++ b/car-qc-lib/res/color/qc_switch_thumb_color.xml
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
diff --git a/car-qc-lib/res/color/qc_switch_thumb_color_disabled_on_dark.xml b/car-qc-lib/res/color/qc_switch_thumb_color_disabled_on_dark.xml
new file mode 100644
index 0000000..43032ba
--- /dev/null
+++ b/car-qc-lib/res/color/qc_switch_thumb_color_disabled_on_dark.xml
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
+    <item android:color="?oemColorOnSurfaceInverse"/>
+</selector>
diff --git a/car-qc-lib/res/color/qc_toggle_background_color.xml b/car-qc-lib/res/color/qc_toggle_background_color.xml
index 15253ad..407ba29 100644
--- a/car-qc-lib/res/color/qc_toggle_background_color.xml
+++ b/car-qc-lib/res/color/qc_toggle_background_color.xml
@@ -22,6 +22,6 @@
           android:color="@color/qc_toggle_off_background_color"/>
     <item android:state_enabled="false"
           android:alpha="?android:attr/disabledAlpha"
-          android:color="?android:attr/colorAccent"/>
-    <item android:color="?android:attr/colorAccent"/>
+          android:color="?oemColorPrimary"/>
+    <item android:color="?oemColorPrimary"/>
 </selector>
diff --git a/car-qc-lib/res/color/qc_toggle_icon_fill_color.xml b/car-qc-lib/res/color/qc_toggle_icon_fill_color.xml
index bdb5433..1134ffc 100644
--- a/car-qc-lib/res/color/qc_toggle_icon_fill_color.xml
+++ b/car-qc-lib/res/color/qc_toggle_icon_fill_color.xml
@@ -17,11 +17,11 @@
 <selector xmlns:android="http://schemas.android.com/apk/res/android">
     <item android:state_checked="false" android:state_enabled="false"
           android:alpha="?android:attr/disabledAlpha"
-          android:color="@android:color/white"/>
+          android:color="?oemColorOnBackground"/>
     <item android:state_checked="false"
-          android:color="@android:color/white"/>
+          android:color="?oemColorOnBackground"/>
     <item android:state_enabled="false"
           android:alpha="?android:attr/disabledAlpha"
-          android:color="@android:color/black"/>
-    <item android:color="@android:color/black"/>
+          android:color="?oemColorBackground"/>
+    <item android:color="?oemColorBackground"/>
 </selector>
diff --git a/car-qc-lib/res/color/qc_toggle_off_background_color.xml b/car-qc-lib/res/color/qc_toggle_off_background_color.xml
new file mode 100644
index 0000000..ddbbf3f
--- /dev/null
+++ b/car-qc-lib/res/color/qc_toggle_off_background_color.xml
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
+    <item android:color="?oemColorSurfaceContainerHighest"/>
+</selector>
diff --git a/car-qc-lib/res/color/qc_toggle_rotary_shadow_color.xml b/car-qc-lib/res/color/qc_toggle_rotary_shadow_color.xml
new file mode 100644
index 0000000..86b2007
--- /dev/null
+++ b/car-qc-lib/res/color/qc_toggle_rotary_shadow_color.xml
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
+    <item android:color="?oemColorShadow"/>
+</selector>
diff --git a/car-qc-lib/res/color/qc_toggle_unavailable_color.xml b/car-qc-lib/res/color/qc_toggle_unavailable_color.xml
new file mode 100644
index 0000000..ddbbf3f
--- /dev/null
+++ b/car-qc-lib/res/color/qc_toggle_unavailable_color.xml
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
+    <item android:color="?oemColorSurfaceContainerHighest"/>
+</selector>
diff --git a/car-qc-lib/res/color/qc_warning_text_color.xml b/car-qc-lib/res/color/qc_warning_text_color.xml
new file mode 100644
index 0000000..fdf2bd8
--- /dev/null
+++ b/car-qc-lib/res/color/qc_warning_text_color.xml
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
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF Aqc_toggle_background_radiusNY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorYellow"/>
+</selector>
diff --git a/car-qc-lib/res/drawable/qc_row_chevron.xml b/car-qc-lib/res/drawable/qc_row_chevron.xml
new file mode 100644
index 0000000..b126d03
--- /dev/null
+++ b/car-qc-lib/res/drawable/qc_row_chevron.xml
@@ -0,0 +1,24 @@
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
+        android:width="40dp"
+        android:height="40dp"
+        android:viewportWidth="36"
+        android:viewportHeight="36">
+    <path
+        android:fillColor="@color/qc_chevron_color"
+        android:pathData="M14.9999 9L12.8774 11.1225L19.7549 18L12.8774 24.8775L14.9999 27L23.9999 18L14.9999 9Z"/>
+</vector>
\ No newline at end of file
diff --git a/car-qc-lib/res/drawable/qc_toggle_button_background.xml b/car-qc-lib/res/drawable/qc_toggle_button_background.xml
index f42ebf8..5dc1277 100644
--- a/car-qc-lib/res/drawable/qc_toggle_button_background.xml
+++ b/car-qc-lib/res/drawable/qc_toggle_button_background.xml
@@ -22,13 +22,13 @@
             <solid android:color="@color/qc_toggle_unavailable_background_color" />
             <stroke android:color="@color/qc_toggle_unavailable_color"
                 android:width="@dimen/qc_toggle_unavailable_outline_width" />
-            <corners android:radius="@dimen/qc_toggle_background_radius" />
+            <corners android:radius="?qcToggleBackgroundRadius" />
         </shape>
     </item>
     <item>
         <shape android:shape="rectangle">
             <solid android:color="@color/qc_toggle_background_color" />
-            <corners android:radius="@dimen/qc_toggle_background_radius" />
+            <corners android:radius="?qcToggleBackgroundRadius" />
         </shape>
     </item>
 </selector>
\ No newline at end of file
diff --git a/car-qc-lib/res/drawable/qc_toggle_rotary_highlight.xml b/car-qc-lib/res/drawable/qc_toggle_rotary_highlight.xml
index 5894a8f..20913d9 100644
--- a/car-qc-lib/res/drawable/qc_toggle_rotary_highlight.xml
+++ b/car-qc-lib/res/drawable/qc_toggle_rotary_highlight.xml
@@ -20,7 +20,7 @@
             <solid android:color="@color/car_ui_rotary_focus_pressed_fill_secondary_color"/>
             <stroke android:width="@dimen/car_ui_rotary_focus_pressed_stroke_width"
                 android:color="@color/car_ui_rotary_focus_stroke_color"/>
-            <corners android:radius="@dimen/qc_toggle_rotary_highlight_radius" />
+            <corners android:radius="?qcToggleRotaryHighlightRadius" />
         </shape>
     </item>
     <item android:state_focused="true">
@@ -28,7 +28,7 @@
             <solid android:color="@color/car_ui_rotary_focus_fill_color"/>
             <stroke android:width="@dimen/car_ui_rotary_focus_stroke_width"
                 android:color="@color/car_ui_rotary_focus_stroke_color"/>
-            <corners android:radius="@dimen/qc_toggle_rotary_highlight_radius" />
+            <corners android:radius="?qcToggleRotaryHighlightRadius" />
         </shape>
     </item>
 </selector>
\ No newline at end of file
diff --git a/car-qc-lib/res/drawable/qc_toggle_rotary_shadow.xml b/car-qc-lib/res/drawable/qc_toggle_rotary_shadow.xml
index 2717321..ba5ce5b 100644
--- a/car-qc-lib/res/drawable/qc_toggle_rotary_shadow.xml
+++ b/car-qc-lib/res/drawable/qc_toggle_rotary_shadow.xml
@@ -19,7 +19,7 @@
         <shape android:shape="rectangle">
             <stroke android:width="@dimen/qc_toggle_rotary_shadow_width"
                 android:color="@color/qc_toggle_rotary_shadow_color"/>
-            <corners android:radius="@dimen/qc_toggle_rotary_shadow_radius" />
+            <corners android:radius="?qcToggleRotaryShadowRadius" />
         </shape>
     </item>
 </selector>
\ No newline at end of file
diff --git a/car-qc-lib/res/drawable/qc_toggle_unavailable_background.xml b/car-qc-lib/res/drawable/qc_toggle_unavailable_background.xml
index 185b801..f188d2e 100644
--- a/car-qc-lib/res/drawable/qc_toggle_unavailable_background.xml
+++ b/car-qc-lib/res/drawable/qc_toggle_unavailable_background.xml
@@ -24,7 +24,7 @@
             <solid android:color="@color/qc_toggle_unavailable_background_color" />
             <stroke android:color="@color/qc_toggle_unavailable_color"
                 android:width="@dimen/qc_toggle_unavailable_outline_width" />
-            <corners android:radius="@dimen/qc_toggle_background_radius" />
+            <corners android:radius="?qcToggleBackgroundRadius" />
         </shape>
     </item>
     <item android:width="@dimen/qc_toggle_rotary_highlight_size"
diff --git a/car-qc-lib/res/layout/qc_row_view.xml b/car-qc-lib/res/layout/qc_row_view.xml
index 9977cc7..9226162 100644
--- a/car-qc-lib/res/layout/qc_row_view.xml
+++ b/car-qc-lib/res/layout/qc_row_view.xml
@@ -19,136 +19,184 @@
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
     android:layout_width="match_parent"
-    android:layout_height="wrap_content"
-    android:layout_centerVertical="true"
-    android:layout_marginVertical="@dimen/qc_row_margin_vertical"
-    android:clipToPadding="false"
-    android:minHeight="@dimen/qc_row_min_height"
-    android:paddingEnd="@dimen/qc_row_padding_end"
-    android:paddingStart="@dimen/qc_row_padding_start">
-
-    <LinearLayout
-        android:id="@+id/qc_row_start_items"
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:layout_marginEnd="@dimen/qc_action_items_horizontal_margin"
-        android:orientation="horizontal"
-        android:divider="@drawable/qc_row_action_divider"
-        android:showDividers="middle"
-        app:layout_constraintStart_toStartOf="parent"
+    android:layout_height="wrap_content">
+
+    <View
+        android:id="@+id/top_divider"
+        android:layout_width="match_parent"
+        android:layout_height="@dimen/qc_row_horizontal_divider_height"
+        android:layout_marginVertical="@dimen/qc_row_margin_vertical"
+        android:background="@color/divider_color"
         app:layout_constraintTop_toTopOf="parent"
-        app:layout_constraintBottom_toBottomOf="parent"
-        app:layout_constraintEnd_toStartOf="@+id/qc_row_content"
-        app:layout_constraintHorizontal_chainStyle="spread_inside"/>
+        app:layout_constraintBottom_toTopOf="@id/row_content_container"/>
+
+    <View
+        android:id="@+id/bottom_divider"
+        android:layout_width="match_parent"
+        android:layout_height="@dimen/qc_row_horizontal_divider_height"
+        android:layout_marginTop="@dimen/qc_row_bottom_divider_margin_top"
+        android:layout_marginBottom="@dimen/qc_row_margin_vertical"
+        android:background="@color/divider_color"
+        app:layout_constraintTop_toBottomOf="@id/row_content_container"
+        app:layout_constraintBottom_toBottomOf="parent"/>
 
     <com.android.car.ui.uxr.DrawableStateConstraintLayout
-        android:id="@+id/qc_row_content"
-        android:layout_width="0dp"
-        android:layout_height="0dp"
-        android:background="?android:attr/selectableItemBackground"
-        app:layout_constraintStart_toEndOf="@+id/qc_row_start_items"
-        app:layout_constraintEnd_toStartOf="@+id/qc_row_end_items"
-        app:layout_constraintTop_toTopOf="parent"
-        app:layout_constraintBottom_toBottomOf="parent"
-        app:layout_constraintHeight_default="wrap"
-        app:layout_constraintHeight_min="@dimen/qc_row_min_height">
-
-        <com.android.car.ui.uxr.DrawableStateImageView
-            android:id="@+id/qc_icon"
-            android:layout_width="@dimen/qc_row_icon_size"
-            android:layout_height="@dimen/qc_row_icon_size"
-            android:layout_marginEnd="@dimen/qc_row_icon_margin_end"
-            android:scaleType="fitCenter"
-            app:layout_constraintStart_toStartOf="parent"
-            app:layout_constraintEnd_toStartOf="@+id/barrier1"
-            app:layout_constraintTop_toTopOf="parent"
-            app:layout_constraintBottom_toTopOf="@+id/barrier2"/>
+        android:id="@+id/row_content_container"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_centerVertical="true"
+        android:layout_marginVertical="@dimen/qc_row_margin_vertical"
+        android:clipToPadding="false"
+        android:minHeight="@dimen/qc_row_min_height"
+        android:paddingEnd="@dimen/qc_row_padding_end"
+        android:paddingStart="@dimen/qc_row_padding_start"
+        app:layout_constraintTop_toBottomOf="@id/top_divider"
+        app:layout_constraintBottom_toTopOf="@+id/bottom_divider">
 
-        <androidx.constraintlayout.widget.Barrier
-            android:id="@+id/barrier1"
+        <LinearLayout
+            android:id="@+id/qc_row_start_items"
             android:layout_width="wrap_content"
             android:layout_height="wrap_content"
-            app:barrierDirection="end"
-            app:barrierAllowsGoneWidgets="false"/>
+            android:layout_marginEnd="@dimen/qc_action_items_horizontal_margin"
+            android:orientation="horizontal"
+            android:divider="@drawable/qc_row_action_divider"
+            android:showDividers="middle"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent"
+            app:layout_constraintEnd_toStartOf="@+id/qc_row_content"
+            app:layout_constraintHorizontal_chainStyle="spread_inside"/>
 
-        <com.android.car.ui.uxr.DrawableStateTextView
-            android:id="@+id/qc_title"
+        <com.android.car.ui.uxr.DrawableStateConstraintLayout
+            android:id="@+id/qc_row_content"
             android:layout_width="0dp"
-            android:layout_height="wrap_content"
-            android:layout_centerVertical="true"
-            android:singleLine="true"
-            style="@style/TextAppearance.QC.Title"
-            app:layout_constraintStart_toEndOf="@+id/barrier1"
+            android:layout_height="0dp"
+            android:background="?android:attr/selectableItemBackground"
+            app:layout_constraintStart_toEndOf="@+id/qc_row_start_items"
+            app:layout_constraintEnd_toStartOf="@+id/qc_row_end_items"
             app:layout_constraintTop_toTopOf="parent"
-            app:layout_constraintBottom_toTopOf="@+id/qc_summary"
-            app:layout_constraintEnd_toEndOf="parent"
-            app:layout_constraintVertical_chainStyle="packed"/>
+            app:layout_constraintBottom_toBottomOf="parent"
+            app:layout_constraintHeight_default="wrap"
+            app:layout_constraintHeight_min="@dimen/qc_row_min_height">
 
-        <com.android.car.ui.uxr.DrawableStateTextView
-            android:id="@+id/qc_summary"
-            android:layout_width="0dp"
-            android:layout_height="wrap_content"
-            android:layout_centerVertical="true"
-            style="@style/TextAppearance.QC.Subtitle"
-            app:layout_constraintStart_toEndOf="@+id/barrier1"
-            app:layout_constraintEnd_toEndOf="parent"
-            app:layout_constraintTop_toBottomOf="@+id/qc_title"
-            app:layout_constraintBottom_toTopOf="@+id/qc_action_text"/>
+            <com.android.car.ui.uxr.DrawableStateImageView
+                android:id="@+id/qc_icon"
+                android:layout_width="@dimen/qc_row_icon_size"
+                android:layout_height="@dimen/qc_row_icon_size"
+                android:layout_marginEnd="@dimen/qc_row_icon_margin_end"
+                android:scaleType="fitCenter"
+                app:layout_constraintStart_toStartOf="parent"
+                app:layout_constraintEnd_toStartOf="@+id/barrier1"
+                app:layout_constraintTop_toTopOf="parent"
+                app:layout_constraintBottom_toTopOf="@+id/barrier2"/>
 
-        <com.android.car.ui.uxr.DrawableStateTextView
-            android:id="@+id/qc_action_text"
-            android:layout_width="0dp"
-            android:layout_height="wrap_content"
-            android:layout_centerVertical="true"
-            style="@style/TextAppearance.QC.Subtitle"
-            app:layout_constraintStart_toEndOf="@+id/barrier1"
-            app:layout_constraintEnd_toEndOf="parent"
-            app:layout_constraintTop_toBottomOf="@+id/qc_summary"
-            app:layout_constraintBottom_toTopOf="@+id/barrier2"/>
+            <androidx.constraintlayout.widget.Barrier
+                android:id="@+id/barrier1"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                app:barrierDirection="end"
+                app:barrierAllowsGoneWidgets="false"/>
 
-        <androidx.constraintlayout.widget.Barrier
-            android:id="@+id/barrier2"
-            android:layout_width="wrap_content"
-            android:layout_height="wrap_content"
-            app:barrierDirection="top"
-            app:constraint_referenced_ids="qc_seekbar_wrapper"/>
+            <com.android.car.ui.uxr.DrawableStateTextView
+                android:id="@+id/qc_title"
+                android:layout_width="0dp"
+                android:layout_height="wrap_content"
+                android:layout_centerVertical="true"
+                android:singleLine="true"
+                android:textColor="?oemColorOnSurface"
+                android:textAppearance="?oemTextAppearanceBodyLarge"
+                app:layout_constraintStart_toEndOf="@+id/barrier1"
+                app:layout_constraintTop_toTopOf="parent"
+                app:layout_constraintBottom_toTopOf="@+id/qc_summary"
+                app:layout_constraintEnd_toStartOf="@+id/barrier3"
+                app:layout_constraintVertical_chainStyle="packed"/>
 
-        <androidx.preference.UnPressableLinearLayout
-            android:id="@+id/qc_seekbar_wrapper"
-            android:layout_width="0dp"
-            android:layout_height="wrap_content"
-            android:paddingTop="@dimen/qc_seekbar_padding_top"
-            android:focusable="true"
-            android:background="@drawable/qc_seekbar_wrapper_background"
-            android:clipChildren="false"
-            android:clipToPadding="false"
-            android:layout_centerVertical="true"
-            android:orientation="vertical"
-            android:visibility="gone"
-            app:layout_constraintStart_toEndOf="@+id/barrier1"
-            app:layout_constraintEnd_toEndOf="parent"
-            app:layout_constraintTop_toBottomOf="@+id/barrier2"
-            app:layout_constraintBottom_toBottomOf="parent">
-            <com.android.car.qc.view.QCSeekBarView
-                android:id="@+id/qc_seekbar"
-                android:layout_width="match_parent"
+            <com.android.car.ui.uxr.DrawableStateTextView
+                android:id="@+id/qc_summary"
+                android:layout_width="0dp"
                 android:layout_height="wrap_content"
-                style="@style/Widget.QC.SeekBar"/>
-        </androidx.preference.UnPressableLinearLayout>
+                android:layout_centerVertical="true"
+                android:textColor="?oemColorOnSurfaceVariant"
+                android:textAppearance="?oemTextAppearanceBodySmall"
+                app:layout_constraintStart_toEndOf="@+id/barrier1"
+                app:layout_constraintEnd_toStartOf="@+id/barrier3"
+                app:layout_constraintTop_toBottomOf="@+id/qc_title"
+                app:layout_constraintBottom_toTopOf="@+id/qc_action_text"/>
 
-    </com.android.car.ui.uxr.DrawableStateConstraintLayout>
+            <com.android.car.ui.uxr.DrawableStateTextView
+                android:id="@+id/qc_action_text"
+                android:layout_width="0dp"
+                android:layout_height="wrap_content"
+                android:layout_centerVertical="true"
+                android:textColor="?oemColorOnSurfaceVariant"
+                android:textAppearance="?oemTextAppearanceBodySmall"
+                app:layout_constraintStart_toEndOf="@+id/barrier1"
+                app:layout_constraintEnd_toStartOf="@+id/barrier3"
+                app:layout_constraintTop_toBottomOf="@+id/qc_summary"
+                app:layout_constraintBottom_toTopOf="@+id/barrier2"/>
 
-    <LinearLayout
-        android:id="@+id/qc_row_end_items"
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:layout_marginStart="@dimen/qc_action_items_horizontal_margin"
-        android:orientation="horizontal"
-        android:divider="@drawable/qc_row_action_divider"
-        android:showDividers="middle"
-        app:layout_constraintStart_toEndOf="@+id/qc_row_content"
-        app:layout_constraintEnd_toEndOf="parent"
-        app:layout_constraintTop_toTopOf="parent"
-        app:layout_constraintBottom_toBottomOf="parent"/>
+            <androidx.constraintlayout.widget.Barrier
+                android:id="@+id/barrier2"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                app:barrierDirection="top"
+                app:constraint_referenced_ids="qc_seekbar_wrapper"/>
 
-</com.android.car.ui.uxr.DrawableStateConstraintLayout>
+            <androidx.preference.UnPressableLinearLayout
+                android:id="@+id/qc_seekbar_wrapper"
+                android:layout_width="0dp"
+                android:layout_height="wrap_content"
+                android:paddingTop="@dimen/qc_seekbar_padding_top"
+                android:focusable="true"
+                android:background="@drawable/qc_seekbar_wrapper_background"
+                android:clipChildren="false"
+                android:clipToPadding="false"
+                android:layout_centerVertical="true"
+                android:orientation="vertical"
+                android:visibility="gone"
+                app:layout_constraintStart_toEndOf="@+id/barrier1"
+                app:layout_constraintEnd_toStartOf="@+id/barrier3"
+                app:layout_constraintTop_toBottomOf="@+id/barrier2"
+                app:layout_constraintBottom_toBottomOf="parent">
+                <com.android.car.qc.view.QCSeekBarView
+                    android:id="@+id/qc_seekbar"
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    style="@style/Widget.QC.SeekBar"/>
+            </androidx.preference.UnPressableLinearLayout>
+
+            <ImageView
+                android:id="@+id/chevron_end"
+                android:layout_width="@dimen/qc_row_icon_size"
+                android:layout_height="@dimen/qc_row_icon_size"
+                android:src="@drawable/qc_row_chevron"
+                android:scaleType="fitCenter"
+                app:layout_constraintDimensionRatio="1:1"
+                app:layout_constraintStart_toEndOf="@+id/barrier3"
+                app:layout_constraintEnd_toEndOf="parent"
+                app:layout_constraintTop_toTopOf="parent"
+                app:layout_constraintBottom_toBottomOf="parent"/>
+
+            <androidx.constraintlayout.widget.Barrier
+                android:id="@+id/barrier3"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                app:barrierDirection="start"
+                app:barrierAllowsGoneWidgets="false"/>
+        </com.android.car.ui.uxr.DrawableStateConstraintLayout>
+
+        <LinearLayout
+            android:id="@+id/qc_row_end_items"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="@dimen/qc_action_items_horizontal_margin"
+            android:orientation="horizontal"
+            android:divider="@drawable/qc_row_action_divider"
+            android:showDividers="middle"
+            app:layout_constraintStart_toEndOf="@id/qc_row_content"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintTop_toTopOf="parent"
+            app:layout_constraintBottom_toBottomOf="parent"/>
+
+    </com.android.car.ui.uxr.DrawableStateConstraintLayout>
+</com.android.car.ui.uxr.DrawableStateConstraintLayout>
\ No newline at end of file
diff --git a/car-qc-lib/res/layout/qc_tile_view.xml b/car-qc-lib/res/layout/qc_tile_view.xml
index c7b7511..12f1c37 100644
--- a/car-qc-lib/res/layout/qc_tile_view.xml
+++ b/car-qc-lib/res/layout/qc_tile_view.xml
@@ -37,5 +37,6 @@
         android:id="@android:id/summary"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
-        style="@style/TextAppearance.QC.Subtitle"/>
+        android:textColor="?oemColorOnSurfaceVariant"
+        android:textAppearance="?oemTextAppearanceBodySmall"/>
 </com.android.car.ui.uxr.DrawableStateLinearLayout>
\ No newline at end of file
diff --git a/car-qc-lib/res/values/attrs.xml b/car-qc-lib/res/values/attrs.xml
index 94613b9..5e30381 100644
--- a/car-qc-lib/res/values/attrs.xml
+++ b/car-qc-lib/res/values/attrs.xml
@@ -16,4 +16,7 @@
 
 <resources>
     <attr name="state_toggle_unavailable"/>
+    <attr name="qcToggleBackgroundRadius" format="dimension"/>
+    <attr name="qcToggleRotaryHighlightRadius" format="dimension"/>
+    <attr name="qcToggleRotaryShadowRadius" format="dimension"/>
 </resources>
\ No newline at end of file
diff --git a/car-qc-lib/res/values/colors.xml b/car-qc-lib/res/values/colors.xml
index 8f28391..4e7e06c 100644
--- a/car-qc-lib/res/values/colors.xml
+++ b/car-qc-lib/res/values/colors.xml
@@ -15,19 +15,6 @@
   -->
 
 <resources>
-    <color name="qc_start_icon_color">@android:color/white</color>
-    <color name="qc_toggle_off_background_color">#626262</color>
     <color name="qc_toggle_unavailable_background_color">@android:color/transparent</color>
-    <color name="qc_toggle_unavailable_color">#37FFFFFF</color>
-    <color name="qc_toggle_rotary_shadow_color">#C7000000</color>
-    <!-- The SeekBar thumb color. -->
-    <color name="qc_seekbar_thumb">#FFFFFF</color>
-    <!-- The SeekBar thumb color when disabled. Use for the dark theme. -->
-    <color name="qc_seekbar_thumb_disabled_on_dark">#757575</color>
-    <!-- The Switch thumb color. -->
-    <color name="qc_switch_thumb_color">#FFFFFF</color>
-    <!-- The Switch thumb color when disabled. Use for the dark theme. -->
-    <color name="qc_switch_thumb_color_disabled_on_dark">#757575</color>
-    <!-- The color for warning text in QC. -->
-    <color name="qc_warning_text_color">@color/car_yellow_color</color>
+    <color name="qc_chevron_color">@color/car_ui_text_color_primary</color>
 </resources>
diff --git a/car-qc-lib/res/values/dimens.xml b/car-qc-lib/res/values/dimens.xml
index 912891f..27cfa04 100644
--- a/car-qc-lib/res/values/dimens.xml
+++ b/car-qc-lib/res/values/dimens.xml
@@ -22,21 +22,20 @@
     <dimen name="qc_row_icon_size">44dp</dimen>
     <dimen name="qc_row_icon_margin_end">32dp</dimen>
     <dimen name="qc_row_content_margin">16dp</dimen>
+    <dimen name="qc_row_horizontal_divider_height">2dp</dimen>
+    <dimen name="qc_row_bottom_divider_margin_top">20dp</dimen>
 
     <dimen name="qc_action_items_horizontal_margin">32dp</dimen>
     <dimen name="qc_toggle_size">80dp</dimen>
     <dimen name="qc_toggle_background_size">72dp</dimen>
     <dimen name="qc_toggle_margin">12dp</dimen>
     <dimen name="qc_row_horizontal_margin">16dp</dimen>
-    <dimen name="qc_toggle_background_radius">16dp</dimen>
     <dimen name="qc_toggle_background_padding">4dp</dimen>
     <dimen name="qc_toggle_foreground_icon_inset">18dp</dimen>
     <dimen name="qc_toggle_unavailable_outline_width">2dp</dimen>
     <dimen name="qc_toggle_rotary_highlight_size">80dp</dimen>
-    <dimen name="qc_toggle_rotary_highlight_radius">20dp</dimen>
     <dimen name="qc_toggle_rotary_shadow_size">64dp</dimen>
     <dimen name="qc_toggle_rotary_shadow_width">4dp</dimen>
-    <dimen name="qc_toggle_rotary_shadow_radius">16dp</dimen>
     <dimen name="qc_toggle_rotary_shadow_padding">8dp</dimen>
 
 
diff --git a/car-qc-lib/res/values/styles.xml b/car-qc-lib/res/values/styles.xml
index 51a7d35..e9788b0 100644
--- a/car-qc-lib/res/values/styles.xml
+++ b/car-qc-lib/res/values/styles.xml
@@ -15,18 +15,6 @@
   -->
 
 <resources>
-    <style name="TextAppearance.QC" parent="android:TextAppearance.DeviceDefault">
-        <item name="android:textColor">@color/car_on_surface</item>
-    </style>
-
-    <style name="TextAppearance.QC.Title" parent="android:TextAppearance.DeviceDefault.Large">
-        <item name="android:textColor">@color/car_on_surface</item>
-    </style>
-
-    <style name="TextAppearance.QC.Subtitle" parent="android:TextAppearance.DeviceDefault.Small">
-        <item name="android:textColor">@color/car_on_surface_variant</item>
-    </style>
-
     <style name="Widget.QC" parent="android:Widget.DeviceDefault"/>
 
     <style name="Widget.QC.SeekBar">
@@ -35,4 +23,10 @@
         <item name="android:focusable">false</item>
         <item name="android:splitTrack">false</item>
     </style>
+
+    <style name="CarQcLibThemeOverlay">
+        <item name="qcToggleBackgroundRadius">?oemShapeCornerSmall</item>
+        <item name="qcToggleRotaryHighlightRadius">?oemShapeCornerMedium</item>
+        <item name="qcToggleRotaryShadowRadius">?oemShapeCornerSmall</item>
+    </style>
 </resources>
diff --git a/car-qc-lib/src/com/android/car/qc/QCRow.java b/car-qc-lib/src/com/android/car/qc/QCRow.java
index cc13d4a..ca567ac 100644
--- a/car-qc-lib/src/com/android/car/qc/QCRow.java
+++ b/car-qc-lib/src/com/android/car/qc/QCRow.java
@@ -29,12 +29,12 @@ import java.util.List;
 
 /**
  * Quick Control Row Element
- * ---------------------------------------
- * |            | Title       |          |
- * | StartItems | Subtitle    | EndItems |
- * |            | ActionText  |          |
- * |            | Sliders     |          |
- * ---------------------------------------
+ * --------------------------------------------------
+ * |            | Title       |          |          |
+ * | StartItems | Subtitle    | Chevron  | EndItems |
+ * |            | ActionText  |          |          |
+ * |            | Sliders     |          |          |
+ * --------------------------------------------------
  */
 public class QCRow extends QCItem {
     private final String mTitle;
@@ -44,18 +44,22 @@ public class QCRow extends QCItem {
     private final int mCategory;
     private final Icon mStartIcon;
     private final boolean mIsStartIconTintable;
+    private final boolean mShowChevron;
+    private final boolean mShowBottomDivider;
+    private final boolean mShowTopDivider;
     private final QCSlider mSlider;
     private final List<QCActionItem> mStartItems;
     private final List<QCActionItem> mEndItems;
     private final PendingIntent mPrimaryAction;
     private PendingIntent mDisabledClickAction;
+
     public QCRow(@Nullable String title, @Nullable String subtitle,
             @Nullable String actionText, @QCCategory int category,
             boolean isEnabled, boolean isClickableWhileDisabled,
-            @Nullable PendingIntent primaryAction,
-            @Nullable PendingIntent disabledClickAction, @Nullable Icon startIcon,
-            boolean isIconTintable, @Nullable QCSlider slider,
-            @NonNull List<QCActionItem> startItems, @NonNull List<QCActionItem> endItems) {
+            @Nullable PendingIntent primaryAction, @Nullable PendingIntent disabledClickAction,
+            @Nullable Icon startIcon, boolean isIconTintable, @Nullable QCSlider slider,
+            @NonNull List<QCActionItem> startItems, @NonNull List<QCActionItem> endItems,
+            boolean showChevron, boolean showTopDivider, boolean showBottomDivider) {
         super(QC_TYPE_ROW, isEnabled, isClickableWhileDisabled);
         mTitle = title;
         mSubtitle = subtitle;
@@ -68,6 +72,9 @@ public class QCRow extends QCItem {
         mSlider = slider;
         mStartItems = Collections.unmodifiableList(startItems);
         mEndItems = Collections.unmodifiableList(endItems);
+        mShowChevron = showChevron;
+        mShowTopDivider = showTopDivider;
+        mShowBottomDivider = showBottomDivider;
     }
 
     public QCRow(@NonNull Parcel in) {
@@ -113,6 +120,10 @@ public class QCRow extends QCItem {
         } else {
             mDisabledClickAction = null;
         }
+
+        mShowChevron = in.readBoolean();
+        mShowTopDivider = in.readBoolean();
+        mShowBottomDivider = in.readBoolean();
     }
 
     @Override
@@ -151,6 +162,10 @@ public class QCRow extends QCItem {
         if (hasDisabledClickAction) {
             mDisabledClickAction.writeToParcel(dest, flags);
         }
+
+        dest.writeBoolean(mShowChevron);
+        dest.writeBoolean(mShowTopDivider);
+        dest.writeBoolean(mShowBottomDivider);
     }
 
     @Override
@@ -207,6 +222,18 @@ public class QCRow extends QCItem {
         return mEndItems;
     }
 
+    public boolean showTopDivider() {
+        return mShowTopDivider;
+    }
+
+    public boolean showBottomDivider() {
+        return mShowBottomDivider;
+    }
+
+    public boolean showChevron() {
+        return mShowChevron;
+    }
+
     public static Creator<QCRow> CREATOR = new Creator<QCRow>() {
         @Override
         public QCRow createFromParcel(Parcel source) {
@@ -233,6 +260,9 @@ public class QCRow extends QCItem {
         private int mCategory = QCCategory.NORMAL;
         private boolean mIsEnabled = true;
         private boolean mIsClickableWhileDisabled = false;
+        private boolean mShowChevron = false;
+        private boolean mShowTopDivider = false;
+        private boolean mShowBottomDivider = false;
         private QCSlider mSlider;
         private PendingIntent mPrimaryAction;
         private PendingIntent mDisabledClickAction;
@@ -302,6 +332,30 @@ public class QCRow extends QCItem {
             return this;
         }
 
+        /**
+         * Sets whether to show the chevron or not.
+         */
+        public Builder showChevron(boolean showChevron) {
+            mShowChevron = showChevron;
+            return this;
+        }
+
+        /**
+         * Sets whether to show the divider on the bottom or not.
+         */
+        public Builder showBottomDivider(boolean showBottomDivider) {
+            mShowBottomDivider = showBottomDivider;
+            return this;
+        }
+
+        /**
+         * Sets whether to show the divider on the top or not.
+         */
+        public Builder showTopDivider(boolean showTopDivider) {
+            mShowTopDivider = showTopDivider;
+            return this;
+        }
+
         /**
          * Adds a {@link QCSlider} to the slider area.
          */
@@ -348,7 +402,8 @@ public class QCRow extends QCItem {
         public QCRow build() {
             return new QCRow(mTitle, mSubtitle, mActionText, mCategory, mIsEnabled,
                     mIsClickableWhileDisabled, mPrimaryAction, mDisabledClickAction, mStartIcon,
-                    mIsStartIconTintable, mSlider, mStartItems, mEndItems);
+                    mIsStartIconTintable, mSlider, mStartItems, mEndItems,
+                    mShowChevron, mShowTopDivider, mShowBottomDivider);
         }
     }
 }
diff --git a/car-qc-lib/src/com/android/car/qc/view/QCListView.java b/car-qc-lib/src/com/android/car/qc/view/QCListView.java
index 9aba976..1063024 100644
--- a/car-qc-lib/src/com/android/car/qc/view/QCListView.java
+++ b/car-qc-lib/src/com/android/car/qc/view/QCListView.java
@@ -26,6 +26,7 @@ import androidx.lifecycle.Observer;
 
 import com.android.car.qc.QCItem;
 import com.android.car.qc.QCList;
+import com.android.car.qc.R;
 
 /**
  * Quick Controls view for {@link QCList} instances.
@@ -56,6 +57,7 @@ public class QCListView extends LinearLayout implements Observer<QCItem> {
 
     private void init() {
         setOrientation(VERTICAL);
+        getContext().getTheme().applyStyle(R.style.CarQcLibThemeOverlay, true);
     }
 
     /**
diff --git a/car-qc-lib/src/com/android/car/qc/view/QCRowView.java b/car-qc-lib/src/com/android/car/qc/view/QCRowView.java
index efbb7f5..464dd13 100644
--- a/car-qc-lib/src/com/android/car/qc/view/QCRowView.java
+++ b/car-qc-lib/src/com/android/car/qc/view/QCRowView.java
@@ -49,6 +49,7 @@ import androidx.annotation.LayoutRes;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
+import com.android.car.oem.tokens.Token;
 import com.android.car.qc.QCActionItem;
 import com.android.car.qc.QCCategory;
 import com.android.car.qc.QCItem;
@@ -69,10 +70,13 @@ public class QCRowView extends FrameLayout {
     private LayoutInflater mLayoutInflater;
     private BidiFormatter mBidiFormatter;
     private View mContentView;
+    private View mTopDivider;
+    private View mBottomDivider;
     private TextView mTitle;
     private TextView mSubtitle;
     private TextView mActionText;
     private ImageView mStartIcon;
+    private ImageView mEndChevron;
     @ColorInt
     private int mStartIconTint;
     private LinearLayout mStartItemsContainer;
@@ -187,6 +191,7 @@ public class QCRowView extends FrameLayout {
     }
 
     private void init(Context context) {
+        context.getTheme().applyStyle(R.style.CarQcLibThemeOverlay, true);
         mLayoutInflater = LayoutInflater.from(context);
         mBidiFormatter = BidiFormatter.getInstance();
         mLayoutInflater.inflate(R.layout.qc_row_view, /* root= */ this);
@@ -199,6 +204,9 @@ public class QCRowView extends FrameLayout {
         mEndItemsContainer = findViewById(R.id.qc_row_end_items);
         mSeekBarContainer = findViewById(R.id.qc_seekbar_wrapper);
         mSeekBar = findViewById(R.id.qc_seekbar);
+        mTopDivider = findViewById(R.id.top_divider);
+        mBottomDivider = findViewById(R.id.bottom_divider);
+        mEndChevron = findViewById(R.id.chevron_end);
     }
 
     void setActionListener(QCActionListener listener) {
@@ -248,12 +256,12 @@ public class QCRowView extends FrameLayout {
                     mBidiFormatter.unicodeWrap(row.getActionText(),
                             TextDirectionHeuristics.LOCALE));
             if (row.getCategory() == QCCategory.WARNING) {
-                mActionText.setTextColor(
-                        getResources().getColor(R.color.qc_warning_text_color));
+                mActionText.setTextColor(getResources().getColor(
+                        R.color.qc_warning_text_color, mContentView.getContext().getTheme()));
             } else {
                 mActionText.setTextColor(
-                        getResources().getColor(
-                                com.android.car.resource.common.R.color.car_on_surface_variant));
+                        Token.getColor(mContentView.getContext(),
+                                com.android.car.oem.tokens.R.attr.oemColorSurfaceVariant));
             }
         } else {
             mActionText.setVisibility(GONE);
@@ -263,7 +271,8 @@ public class QCRowView extends FrameLayout {
             Drawable drawable = row.getStartIcon().loadDrawable(getContext());
             if (drawable != null && row.isStartIconTintable()) {
                 if (mStartIconTint == 0) {
-                    mStartIconTint = getContext().getColor(R.color.qc_start_icon_color);
+                    mStartIconTint = getContext().getResources().getColor(
+                            R.color.qc_start_icon_color, getContext().getTheme());
                 }
                 drawable.setTint(mStartIconTint);
             }
@@ -312,6 +321,16 @@ public class QCRowView extends FrameLayout {
         } else {
             mEndItemsContainer.setVisibility(View.VISIBLE);
         }
+
+        if (mTopDivider != null) {
+            mTopDivider.setVisibility(row.showTopDivider() ? VISIBLE : GONE);
+        }
+        if (mBottomDivider != null) {
+            mBottomDivider.setVisibility(row.showBottomDivider() ? VISIBLE : GONE);
+        }
+        if (mEndChevron != null) {
+            mEndChevron.setVisibility(row.showChevron() ? VISIBLE : GONE);
+        }
     }
 
     private void initActionItem(@NonNull ViewGroup root, @Nullable View actionView,
diff --git a/car-qc-lib/src/com/android/car/qc/view/QCViewUtils.java b/car-qc-lib/src/com/android/car/qc/view/QCViewUtils.java
index ca0f877..ca43816 100644
--- a/car-qc-lib/src/com/android/car/qc/view/QCViewUtils.java
+++ b/car-qc-lib/src/com/android/car/qc/view/QCViewUtils.java
@@ -56,7 +56,8 @@ public class QCViewUtils {
         }
 
         if (!available) {
-            int unavailableToggleIconTint = context.getColor(R.color.qc_toggle_unavailable_color);
+            int unavailableToggleIconTint = context.getResources().getColor(
+                    R.color.qc_toggle_unavailable_color, context.getTheme());
             iconDrawable.setTint(unavailableToggleIconTint);
         } else {
             ColorStateList defaultToggleIconTint = context.getColorStateList(
diff --git a/car-qc-lib/tests/unit/Android.bp b/car-qc-lib/tests/unit/Android.bp
index 2dc78e3..8cf7cd5 100644
--- a/car-qc-lib/tests/unit/Android.bp
+++ b/car-qc-lib/tests/unit/Android.bp
@@ -30,8 +30,11 @@ android_test {
         "android.test.runner.stubs.system",
         "android.test.base.stubs.system",
         "android.test.mock.stubs.system",
+        "token-shared-lib-prebuilt",
     ],
 
+    enforce_uses_libs: false,
+
     static_libs: [
         "car-qc-lib",
         "androidx.test.core",
@@ -42,6 +45,7 @@ android_test {
         "platform-test-annotations",
         "truth",
         "testng",
+        "oem-token-lib",
     ],
 
     jni_libs: [
diff --git a/car-qc-lib/tests/unit/AndroidManifest.xml b/car-qc-lib/tests/unit/AndroidManifest.xml
index e500c4d..810db8c 100644
--- a/car-qc-lib/tests/unit/AndroidManifest.xml
+++ b/car-qc-lib/tests/unit/AndroidManifest.xml
@@ -19,8 +19,11 @@
     xmlns:android="http://schemas.android.com/apk/res/android"
     package="com.android.car.qc.tests.unit">
 
-    <application android:debuggable="true">
+    <application
+        android:name=".CarQcLibTestApplication"
+        android:debuggable="true">
         <uses-library android:name="android.test.runner" />
+        <uses-library android:name="com.android.oem.tokens" android:required="false"/>
 
         <provider
             android:name="com.android.car.qc.testutils.AllowedTestQCProvider"
diff --git a/car-qc-lib/tests/unit/src/CarQcLibTestApplication.java b/car-qc-lib/tests/unit/src/CarQcLibTestApplication.java
new file mode 100644
index 0000000..1c6fd1a
--- /dev/null
+++ b/car-qc-lib/tests/unit/src/CarQcLibTestApplication.java
@@ -0,0 +1,30 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+package com.android.car.qc.tests.unit;
+
+import android.app.Application;
+import android.content.Context;
+
+import com.android.car.oem.tokens.Token;
+
+public class CarQcLibTestApplication extends Application {
+    @Override
+    public void attachBaseContext(Context base) {
+        Context context = Token.createOemStyledContext(base);
+        super.attachBaseContext(context);
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/loader/xml/PanelStateXmlParser.java b/car-scalable-ui-lib/src/com/android/car/scalableui/loader/xml/PanelStateXmlParser.java
new file mode 100644
index 0000000..08c65e1
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/loader/xml/PanelStateXmlParser.java
@@ -0,0 +1,511 @@
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
+package com.android.car.scalableui.loader.xml;
+
+import static android.view.Display.DEFAULT_DISPLAY;
+
+import static com.android.car.scalableui.model.Alpha.DEFAULT_ALPHA;
+import static com.android.car.scalableui.model.Layer.DEFAULT_LAYER;
+import static com.android.car.scalableui.model.Transition.DEFAULT_DURATION;
+import static com.android.car.scalableui.model.Visibility.DEFAULT_VISIBILITY;
+
+import android.animation.Animator;
+import android.animation.AnimatorInflater;
+import android.content.Context;
+import android.content.res.Resources;
+import android.graphics.Insets;
+import android.util.AttributeSet;
+import android.util.DisplayMetrics;
+import android.util.Xml;
+import android.view.animation.AnimationUtils;
+import android.view.animation.Interpolator;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import com.android.car.scalableui.model.Alpha;
+import com.android.car.scalableui.model.Bounds;
+import com.android.car.scalableui.model.Corner;
+import com.android.car.scalableui.model.KeyFrameVariant;
+import com.android.car.scalableui.model.Layer;
+import com.android.car.scalableui.model.PanelState;
+import com.android.car.scalableui.model.Role;
+import com.android.car.scalableui.model.Transition;
+import com.android.car.scalableui.model.Variant;
+import com.android.car.scalableui.model.Visibility;
+
+import org.xmlpull.v1.XmlPullParser;
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+import java.util.ArrayList;
+import java.util.List;
+import java.util.Locale;
+
+/**
+ * A utility class that uses a {@link XmlPullParser} to create a {@link PanelState} object.
+ */
+public class PanelStateXmlParser {
+    private static final String TAG = PanelStateXmlParser.class.getSimpleName();
+
+    // --- Panel Tags ---
+    public static final String PANEL_TAG = "Panel";
+    public static final String ID_ATTRIBUTE = "id";
+    public static final String DEFAULT_VARIANT_ATTRIBUTE = "defaultVariant";
+    public static final String ROLE_ATTRIBUTE = "role";
+    public static final String DISPLAY_ID = "displayId";
+    public static final String DEFAULT_LAYER_ATTRIBUTE = "defaultLayer";
+
+    // --- Transitions Tags ---
+    public static final String TRANSITIONS_TAG = "Transitions";
+    public static final String DEFAULT_DURATION_ATTRIBUTE = "defaultDuration";
+    public static final String DEFAULT_INTERPOLATOR_ATTRIBUTE = "defaultInterpolator";
+
+    // --- Transition Tags ---
+    public static final String TRANSITION_TAG = "Transition";
+    public static final String FROM_VARIANT_ATTRIBUTE = "fromVariant";
+    public static final String TO_VARIANT_ATTRIBUTE = "toVariant";
+    public static final String ON_EVENT_ATTRIBUTE = "onEvent";
+    public static final String ON_EVENT_TOKENS_ATTRIBUTE = "onEventTokens";
+    public static final String ANIMATOR_ATTRIBUTE = "animator";
+    public static final String DURATION_ATTRIBUTE = "duration";
+    public static final String INTERPOLATOR_ATTRIBUTE = "interpolator";
+
+    // --- Variant Tags ---
+    public static final String VARIANT_TAG = "Variant";
+    public static final String PARENT_ATTRIBUTE = "parent";
+
+    // --- KeyFrameVariant Tags ---
+    static final String KEY_FRAME_VARIANT_TAG = "KeyFrameVariant";
+    private static final String KEY_FRAME_TAG = "KeyFrame";
+    private static final String FRAME_ATTRIBUTE = "frame";
+    private static final String VARIANT_ATTRIBUTE = "variant";
+
+    // --- Visibility Tags ---
+    public static final String VISIBILITY_TAG = "Visibility";
+    public static final String IS_VISIBLE_ATTRIBUTE = "isVisible";
+
+    // --- Alpha Tags ---
+    public static final String ALPHA_TAG = "Alpha";
+    public static final String ALPHA_VALUE_ATTRIBUTE = "alpha";
+
+    // --- Layer Tags ---
+    public static final String LAYER_TAG = "Layer";
+    public static final String LAYER_VALUE_ATTRIBUTE = "layer";
+
+    // --- Bounds Tags ---
+    public static final String BOUNDS_TAG = "Bounds";
+    public static final String LEFT_ATTRIBUTE = "left";
+    public static final String RIGHT_ATTRIBUTE = "right";
+    public static final String TOP_ATTRIBUTE = "top";
+    public static final String BOTTOM_ATTRIBUTE = "bottom";
+    public static final String WIDTH_ATTRIBUTE = "width";
+    public static final String HEIGHT_ATTRIBUTE = "height";
+
+    // --- Corner Tags ---
+    public static final String CORNER_TAG = "Corner";
+    public static final String RADIUS_ATTRIBUTE = "radius";
+
+    // --- Insets Tags ---
+    public static final String INSETS_TAG = "Insets";
+
+    public static final String DIP = "dip";
+    public static final String DP = "dp";
+    public static final String PERCENT = "%";
+
+    @NonNull
+    static PanelState parse(@NonNull Context context, @NonNull XmlPullParser parser)
+            throws XmlPullParserException, IOException {
+
+        // Consume any START_DOCUMENT or whitespace events
+        int eventType = parser.getEventType();
+        while (eventType == XmlPullParser.START_DOCUMENT
+                || (eventType == XmlPullParser.TEXT && parser.isWhitespace())) {
+            eventType = parser.next();
+        }
+        if (eventType != XmlPullParser.START_TAG || !parser.getName().equals("Panel")) {
+            throw new XmlPullParserException("Expected <Panel> tag at the beginning but "
+                    + parser.getName());
+        }
+
+        parser.require(XmlPullParser.START_TAG, null, PANEL_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        String id = attrs.getAttributeValue(null, ID_ATTRIBUTE);
+        String displayIdStr = attrs.getAttributeValue(null, DISPLAY_ID);
+        int displayId = (displayIdStr == null) ? DEFAULT_DISPLAY : Integer.parseInt(displayIdStr);
+        String defaultVariant = attrs.getAttributeValue(null, DEFAULT_VARIANT_ATTRIBUTE);
+        int roleValue = attrs.getAttributeResourceValue(null, ROLE_ATTRIBUTE, 0);
+
+        Integer defaultLayer = null;
+        if (attrs.getAttributeValue(null, DEFAULT_LAYER_ATTRIBUTE) != null) {
+            int resId = attrs.getAttributeResourceValue(null, DEFAULT_LAYER_ATTRIBUTE, 0);
+            if (resId != 0) {
+                defaultLayer = context.getResources().getInteger(resId);
+            } else {
+                defaultLayer =
+                        attrs.getAttributeIntValue(null, DEFAULT_LAYER_ATTRIBUTE, DEFAULT_LAYER);
+            }
+        }
+
+        PanelState.Builder builder = new PanelState.Builder(id, new Role(roleValue));
+        builder.setDisplayId(displayId);
+        builder.setDefaultVariant(defaultVariant);
+        PanelState panelState = builder.build();
+
+        while (parser.next() != XmlPullParser.END_TAG) {
+            if (parser.getEventType() != XmlPullParser.START_TAG) continue;
+            String name = parser.getName();
+            switch (name) {
+                case VARIANT_TAG:
+                    panelState.addVariant(
+                            parseVariant(context, panelState, defaultLayer, parser));
+                    break;
+                case KEY_FRAME_VARIANT_TAG:
+                    panelState.addVariant(parseKeyFrameVariant(panelState, parser));
+                    break;
+                case TRANSITIONS_TAG:
+                    List<Transition> transitions = parseTransitions(context, panelState, parser);
+                    for (Transition transition : transitions) {
+                        panelState.addTransition(transition);
+                    }
+                    break;
+                default:
+                    XmlPullParserHelper.skip(parser);
+            }
+        }
+        panelState.setVariant(defaultVariant); // Set the initial variant
+        return panelState;
+    }
+
+    @NonNull
+    private static Variant parseKeyFrameVariant(
+            @NonNull PanelState panelState,
+            @NonNull XmlPullParser parser) throws IOException, XmlPullParserException {
+        parser.require(XmlPullParser.START_TAG, null, KEY_FRAME_VARIANT_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        String id = attrs.getAttributeValue(null, ID_ATTRIBUTE);
+        String parentStr = attrs.getAttributeValue(null, PARENT_ATTRIBUTE);
+        Variant parent = panelState.getVariant(parentStr);
+        KeyFrameVariant.Builder builder = new KeyFrameVariant.Builder(id);
+        if (parent != null) {
+            builder.setParent(parent);
+        }
+        while (parser.next() != XmlPullParser.END_TAG) {
+            if (parser.getEventType() != XmlPullParser.START_TAG) continue;
+            String name = parser.getName();
+            if (name.equals(KEY_FRAME_TAG)) {
+                builder.addKeyFrame(parseKeyFrame(panelState, parser));
+            } else {
+                XmlPullParserHelper.skip(parser);
+            }
+        }
+        return builder.build();
+    }
+
+    private static KeyFrameVariant.KeyFrame parseKeyFrame(
+            @NonNull PanelState panelState,
+            @NonNull XmlPullParser parser) throws XmlPullParserException, IOException {
+        parser.require(XmlPullParser.START_TAG, null, KEY_FRAME_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        int frame = attrs.getAttributeIntValue(null, FRAME_ATTRIBUTE, 0);
+        String variant = attrs.getAttributeValue(null, VARIANT_ATTRIBUTE);
+        parser.nextTag();
+        parser.require(XmlPullParser.END_TAG, null, KEY_FRAME_TAG);
+        Variant panelVariant = panelState.getVariant(variant);
+        if (panelVariant == null) {
+            throw new XmlPullParserException("Variant not found: " + variant);
+        }
+        return new KeyFrameVariant.KeyFrame.Builder(frame, panelVariant).build();
+    }
+
+    @NonNull
+    private static Variant parseVariant(
+            @NonNull Context context,
+            @NonNull PanelState panelState,
+            @Nullable Integer defaultLayer,
+            @NonNull XmlPullParser parser)
+            throws IOException, XmlPullParserException {
+        parser.require(XmlPullParser.START_TAG, null, VARIANT_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+
+        String id = attrs.getAttributeValue(null, ID_ATTRIBUTE);
+        String parentVariantId = attrs.getAttributeValue(null, PARENT_ATTRIBUTE);
+        Variant parentVariant = panelState.getVariant(parentVariantId);
+
+        Variant.Builder variantBuilder = new Variant.Builder(id);
+        variantBuilder.setLayer(defaultLayer);
+        variantBuilder.setParent(parentVariant);
+        while (parser.next() != XmlPullParser.END_TAG) {
+            if (parser.getEventType() != XmlPullParser.START_TAG) continue;
+            String name = parser.getName();
+            switch (name) {
+                case VISIBILITY_TAG:
+                    variantBuilder.setVisibility(parseVisibility(parser).isVisible());
+                    break;
+                case ALPHA_TAG:
+                    variantBuilder.setAlpha(parseAlpha(context, parser).getAlpha());
+                    break;
+                case LAYER_TAG:
+                    variantBuilder.setLayer(parseLayer(context, parser).getLayer());
+                    break;
+                case BOUNDS_TAG:
+                    variantBuilder.setBounds(parseBounds(context, parser).getRect());
+                    break;
+                case CORNER_TAG:
+                    variantBuilder.setCornerRadius(parseCorner(context, parser).getRadius());
+                    break;
+                case INSETS_TAG:
+                    variantBuilder.setInsets(parseInsets(context, parser));
+                    break;
+                default:
+                    XmlPullParserHelper.skip(parser); // Skip other nested tags
+            }
+        }
+        return variantBuilder.build();
+    }
+
+    @NonNull
+    private static Visibility parseVisibility(@NonNull XmlPullParser parser)
+            throws IOException, XmlPullParserException {
+        parser.require(XmlPullParser.START_TAG, null, VISIBILITY_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        boolean isVisible =
+                attrs.getAttributeBooleanValue(null, IS_VISIBLE_ATTRIBUTE, DEFAULT_VISIBILITY);
+
+        while (parser.next() != XmlPullParser.END_TAG) {
+            XmlPullParserHelper.skip(parser); // Skip any nested tags
+        }
+
+        return new Visibility.Builder().setIsVisible(isVisible).build();
+    }
+
+    @NonNull
+    private static Alpha parseAlpha(@NonNull Context context, @NonNull XmlPullParser parser)
+            throws IOException, XmlPullParserException {
+        parser.require(XmlPullParser.START_TAG, null, ALPHA_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        float alpha = DEFAULT_ALPHA;
+        int resId = attrs.getAttributeResourceValue(null, ALPHA_VALUE_ATTRIBUTE, 0);
+        if (resId != 0) {
+            alpha = context.getResources().getFloat(resId);
+        } else {
+            alpha = attrs.getAttributeFloatValue(null, ALPHA_VALUE_ATTRIBUTE, DEFAULT_ALPHA);
+        }
+
+        while (parser.next() != XmlPullParser.END_TAG) {
+            XmlPullParserHelper.skip(parser); // Skip any nested tags
+        }
+
+        return new Alpha.Builder().setAlpha(alpha).build();
+    }
+
+    @NonNull
+    private static Layer parseLayer(@NonNull Context context, @NonNull XmlPullParser parser)
+            throws IOException, XmlPullParserException {
+        parser.require(XmlPullParser.START_TAG, null, LAYER_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+
+        int layer = DEFAULT_LAYER;
+        int resId = attrs.getAttributeResourceValue(null, LAYER_VALUE_ATTRIBUTE, 0);
+        if (resId != 0) {
+            layer = context.getResources().getInteger(resId);
+        } else {
+            layer = attrs.getAttributeIntValue(null, LAYER_VALUE_ATTRIBUTE, DEFAULT_LAYER);
+        }
+
+        while (parser.next() != XmlPullParser.END_TAG) {
+            XmlPullParserHelper.skip(parser); // Skip any nested tags
+        }
+
+        return new Layer.Builder().setLayer(layer).build();
+    }
+
+    @NonNull
+    private static Bounds parseBounds(@NonNull Context context, @NonNull XmlPullParser parser)
+            throws IOException, XmlPullParserException {
+
+        parser.require(XmlPullParser.START_TAG, null, BOUNDS_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+
+        Integer left = getDimensionPixelSize(context, attrs, LEFT_ATTRIBUTE, true);
+        Integer top = getDimensionPixelSize(context, attrs, TOP_ATTRIBUTE, false);
+        Integer right = getDimensionPixelSize(context, attrs, RIGHT_ATTRIBUTE, true);
+        Integer bottom = getDimensionPixelSize(context, attrs, BOTTOM_ATTRIBUTE, false);
+
+        Integer width = getDimensionPixelSize(context, attrs, WIDTH_ATTRIBUTE, true);
+        Integer height = getDimensionPixelSize(context, attrs, HEIGHT_ATTRIBUTE, false);
+
+        while (parser.next() != XmlPullParser.END_TAG) {
+            XmlPullParserHelper.skip(parser); // Skip any nested tags
+        }
+
+        return new Bounds.Builder()
+                .setLeft(left)
+                .setTop(top)
+                .setRight(right)
+                .setBottom(bottom)
+                .setWidth(width)
+                .setHeight(height)
+                .build();
+    }
+
+    @NonNull
+    private static Corner parseCorner(Context context, XmlPullParser parser)
+            throws IOException, XmlPullParserException {
+        parser.require(XmlPullParser.START_TAG, null, CORNER_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        Integer radius = getDimensionPixelSize(context, attrs, RADIUS_ATTRIBUTE, false);
+
+        while (parser.next() != XmlPullParser.END_TAG) {
+            XmlPullParserHelper.skip(parser); // Skip any nested tags
+        }
+
+        return new Corner.Builder()
+                .setRadius(radius)
+                .build();
+    }
+
+    private static Insets parseInsets(@NonNull Context context, @NonNull XmlPullParser parser)
+            throws IOException, XmlPullParserException {
+
+        parser.require(XmlPullParser.START_TAG, null, INSETS_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+
+        Integer left = getDimensionPixelSize(context, attrs, LEFT_ATTRIBUTE, true);
+        Integer top = getDimensionPixelSize(context, attrs, TOP_ATTRIBUTE, false);
+        Integer right = getDimensionPixelSize(context, attrs, RIGHT_ATTRIBUTE, true);
+        Integer bottom = getDimensionPixelSize(context, attrs, BOTTOM_ATTRIBUTE, false);
+
+        while (parser.next() != XmlPullParser.END_TAG) {
+            XmlPullParserHelper.skip(parser); // Skip any nested tags
+        }
+
+        return Insets.of(left, top, right, bottom);
+    }
+
+    @NonNull
+    private static List<Transition> parseTransitions(
+            @NonNull Context context, @NonNull PanelState panelState, @NonNull XmlPullParser parser)
+            throws XmlPullParserException, IOException {
+        parser.require(XmlPullParser.START_TAG, null, TRANSITIONS_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+        // possible lossy conversion from long to int. we're assuming the default duration can be
+        // convereted to int safely.
+        int duration = attrs.getAttributeIntValue(null, DEFAULT_DURATION_ATTRIBUTE,
+                (int) DEFAULT_DURATION);
+        int interpolatorRef =
+                attrs.getAttributeResourceValue(null, DEFAULT_INTERPOLATOR_ATTRIBUTE, 0);
+        Interpolator interpolator =
+                interpolatorRef == 0
+                        ? null
+                        : AnimationUtils.loadInterpolator(context, interpolatorRef);
+
+        List<Transition> result = new ArrayList<>();
+        while (parser.next() != XmlPullParser.END_TAG) {
+            if (parser.getEventType() != XmlPullParser.START_TAG) continue;
+
+            if (parser.getName().equals(TRANSITION_TAG)) {
+                result.add(
+                        parseTransition(context, panelState, duration, interpolator, parser));
+            } else {
+                XmlPullParserHelper.skip(parser);
+            }
+        }
+        return result;
+    }
+
+    @NonNull
+    private static Transition parseTransition(
+            @NonNull Context context,
+            @NonNull PanelState panelState,
+            long defaultDuration,
+            @Nullable Interpolator defaultInterpolator,
+            @NonNull XmlPullParser parser)
+            throws IOException, XmlPullParserException {
+        parser.require(XmlPullParser.START_TAG, null, TRANSITION_TAG);
+        AttributeSet attrs = Xml.asAttributeSet(parser);
+
+        String from = attrs.getAttributeValue(null, FROM_VARIANT_ATTRIBUTE);
+        String to = attrs.getAttributeValue(null, TO_VARIANT_ATTRIBUTE);
+        String onEvent = attrs.getAttributeValue(null, ON_EVENT_ATTRIBUTE);
+        String onEventTokens = attrs.getAttributeValue(null, ON_EVENT_TOKENS_ATTRIBUTE);
+        int animatorId = attrs.getAttributeResourceValue(null, ANIMATOR_ATTRIBUTE, 0);
+        Animator animator =
+                animatorId == 0 ? null : AnimatorInflater.loadAnimator(context, animatorId);
+        int duration = attrs.getAttributeIntValue(null, DURATION_ATTRIBUTE, (int) defaultDuration);
+        int interpolatorRef = attrs.getAttributeResourceValue(null, INTERPOLATOR_ATTRIBUTE, 0);
+        Interpolator interpolator =
+                interpolatorRef == 0
+                        ? defaultInterpolator
+                        : AnimationUtils.loadInterpolator(context, interpolatorRef);
+        Variant fromVariant = panelState.getVariant(from);
+        Variant toVariant = panelState.getVariant(to);
+
+        while (parser.next() != XmlPullParser.END_TAG) {
+            XmlPullParserHelper.skip(parser); // Should be no nested tags.
+        }
+
+        return new Transition.Builder(fromVariant, toVariant)
+                .setOnEvent(onEvent, onEventTokens)
+                .setAnimator(animator)
+                .setDefaultDuration(duration)
+                .setDefaultInterpolator(interpolator)
+                .build();
+    }
+
+    /**
+     * Helper method to get a dimension pixel size from an attribute set.
+     *
+     * @param context      The application context.
+     * @param attrs        The attribute set.
+     * @param name         The name of the attribute.
+     * @param isHorizontal Whether the dimension is horizontal (width) or vertical (height).
+     * @return The dimension pixel size.
+     */
+    @Nullable
+    private static Integer getDimensionPixelSize(@NonNull Context context,
+            @NonNull AttributeSet attrs, @NonNull String name, boolean isHorizontal) {
+        int resId = attrs.getAttributeResourceValue(null, name, 0);
+        if (resId != 0) {
+            return context.getResources().getDimensionPixelSize(resId);
+        }
+        String dimenStr = attrs.getAttributeValue(null, name);
+        if (dimenStr == null) {
+            return null;
+        }
+        if (dimenStr.toLowerCase(Locale.ROOT).endsWith(DP)) {
+            String valueStr = dimenStr.substring(0, dimenStr.length() - DP.length());
+            float value = Float.parseFloat(valueStr);
+            return (int) (value * Resources.getSystem().getDisplayMetrics().density);
+        } else if (dimenStr.toLowerCase(Locale.ROOT).endsWith(DIP)) {
+            String valueStr = dimenStr.substring(0, dimenStr.length() - DIP.length());
+            float value = Float.parseFloat(valueStr);
+            return (int) (value * Resources.getSystem().getDisplayMetrics().density);
+        } else if (dimenStr.toLowerCase(Locale.ROOT).endsWith(PERCENT)) {
+            String valueStr = dimenStr.substring(0, dimenStr.length() - PERCENT.length());
+            float value = Float.parseFloat(valueStr);
+            DisplayMetrics displayMetrics = Resources.getSystem().getDisplayMetrics();
+            if (isHorizontal) {
+                return (int) (value * displayMetrics.widthPixels / 100);
+            } else {
+                return (int) (value * displayMetrics.heightPixels / 100);
+            }
+        } else {
+            // The default value is never returned because `attrs.getAttributeValue` is not null.
+            return attrs.getAttributeIntValue(null, name, 0);
+        }
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/loader/xml/XmlModelLoader.java b/car-scalable-ui-lib/src/com/android/car/scalableui/loader/xml/XmlModelLoader.java
new file mode 100644
index 0000000..c2ea1c6
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/loader/xml/XmlModelLoader.java
@@ -0,0 +1,50 @@
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
+package com.android.car.scalableui.loader.xml;
+
+import android.content.Context;
+import android.content.res.XmlResourceParser;
+import android.util.Log;
+
+import com.android.car.scalableui.model.PanelState;
+
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+
+/**
+ * Loads {@link PanelState} from an xml resource.
+ */
+public class XmlModelLoader {
+    private static final String TAG = XmlModelLoader.class.getSimpleName();
+
+    private Context mContext;
+
+    public XmlModelLoader(Context context) {
+        mContext = context;
+    }
+
+    /** Creates a {@link PanelState} using the given xml resource */
+    public PanelState createPanelState(int resourceId) {
+        try (XmlResourceParser parser = mContext.getResources().getXml(resourceId)) {
+            PanelState ps = PanelStateXmlParser.parse(mContext, parser);
+            return ps;
+        } catch (XmlPullParserException | IOException e) {
+            Log.e(TAG, "Error parsing xml", e);
+            return null;
+        }
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/XmlPullParserHelper.java b/car-scalable-ui-lib/src/com/android/car/scalableui/loader/xml/XmlPullParserHelper.java
similarity index 97%
rename from car-scalable-ui-lib/src/com/android/car/scalableui/model/XmlPullParserHelper.java
rename to car-scalable-ui-lib/src/com/android/car/scalableui/loader/xml/XmlPullParserHelper.java
index a1141e5..27f8300 100644
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/model/XmlPullParserHelper.java
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/loader/xml/XmlPullParserHelper.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.car.scalableui.model;
+package com.android.car.scalableui.loader.xml;
 
 import org.xmlpull.v1.XmlPullParser;
 import org.xmlpull.v1.XmlPullParserException;
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/manager/Event.java b/car-scalable-ui-lib/src/com/android/car/scalableui/manager/Event.java
deleted file mode 100644
index 6c40986..0000000
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/manager/Event.java
+++ /dev/null
@@ -1,63 +0,0 @@
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
-package com.android.car.scalableui.manager;
-
-/**
- * Describes an event in the system. An event can optionally carry a payload object.
- */
-public class Event {
-    private final String mId;
-    private final Object mPayload;
-
-    /**
-     * Constructs an Event without a payload.
-     *
-     * @param id A unique identifier associated with this event.
-     */
-    public Event(String id) {
-        this(id, null);
-    }
-
-    /**
-     * Constructs an Event with an optional payload.
-     *
-     * @param id A unique identifier associated with this event.
-     * @param payload An optional payload associated with this event.
-     */
-    public Event(String id, Object payload) {
-        mId = id;
-        mPayload = payload;
-    }
-
-    /**
-     * Returns the event identifier.
-     *
-     * @return The event identifier.
-     */
-    public String getId() {
-        return mId;
-    }
-
-    /**
-     * Returns the payload associated with this event.
-     *
-     * @return The payload of the event, or null if no payload is associated.
-     */
-    public Object getPayload() {
-        return mPayload;
-    }
-}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/manager/EventDispatcher.java b/car-scalable-ui-lib/src/com/android/car/scalableui/manager/EventDispatcher.java
deleted file mode 100644
index 9543939..0000000
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/manager/EventDispatcher.java
+++ /dev/null
@@ -1,52 +0,0 @@
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
-package com.android.car.scalableui.manager;
-
-/**
- * A utility class for dispatching events. This class provides methods for dispatching events with
- * or without payloads. All events are handled by the {@link StateManager}.
- */
-public class EventDispatcher {
-
-    /**
-     * Dispatches an event without a payload.
-     *
-     * @param eventId The id of the event that needs to be dispatched.
-     */
-    public static void dispatch(String eventId) {
-        dispatch(eventId, null);
-    }
-
-    /**
-     * Dispatches an event with a given payload.
-     *
-     * @param eventId The id of the event that needs to be dispatched.
-     * @param payload The payload associated with the event. Can be any Java object.
-     */
-    public static void dispatch(String eventId, Object payload) {
-        dispatch(new Event(eventId, payload));
-    }
-
-    /**
-     * Dispatches a given event.
-     *
-     * @param event The event object to be dispatched.
-     */
-    public static void dispatch(Event event) {
-        StateManager.handleEvent(event);
-    }
-}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/manager/StateManager.java b/car-scalable-ui-lib/src/com/android/car/scalableui/manager/StateManager.java
index e3f6626..a99287c 100644
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/manager/StateManager.java
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/manager/StateManager.java
@@ -13,20 +13,38 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 package com.android.car.scalableui.manager;
 
 import android.animation.Animator;
 import android.animation.AnimatorListenerAdapter;
+import android.content.Context;
+import android.os.Build;
+import android.util.ArraySet;
+import android.util.Log;
+
+import androidx.annotation.Nullable;
+import androidx.annotation.VisibleForTesting;
 
+import com.android.car.scalableui.loader.xml.XmlModelLoader;
+import com.android.car.scalableui.model.Event;
 import com.android.car.scalableui.model.PanelState;
+import com.android.car.scalableui.model.PanelTransaction;
 import com.android.car.scalableui.model.Transition;
 import com.android.car.scalableui.model.Variant;
 import com.android.car.scalableui.panel.Panel;
 import com.android.car.scalableui.panel.PanelPool;
 
-import java.util.ArrayList;
-import java.util.List;
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+import java.util.Arrays;
+import java.util.Collections;
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.Map;
+import java.util.Set;
+import java.util.concurrent.ExecutorService;
+import java.util.concurrent.Executors;
 
 /**
  * Manages the state of UI panels. This class is responsible for loading panel definitions,
@@ -34,28 +52,56 @@ import java.util.List;
  * based on their current state.
  */
 public class StateManager {
+    private static final String TAG = StateManager.class.getSimpleName();
+    private static final boolean DEBUG = Build.IS_DEBUGGABLE;
 
     private static final StateManager sInstance = new StateManager();
 
-    private StateManager() {}
+    private final Map<String, PanelState> mPanelStates;
+    private final ArraySet<PanelStateObserverData> mObservers = new ArraySet<>();
+
+    private StateManager() {
+        mPanelStates = new HashMap<>();
+    }
 
-    private final List<PanelState> mPanels = new ArrayList<>();
+    /** Clear all panel states. */
+    public static void clearStates() {
+        sInstance.mPanelStates.clear();
+    }
 
     /**
-     * Adds a new panel state definition.
+     * Returns the singleton instance of the StateManager.
      *
-     * @param panel The panel state to be added.
+     * @return The singleton instance of the StateManager.
      */
-    public static void addState(PanelState panel) {
-        sInstance.mPanels.add(panel);
-        applyState(panel);
+    public static StateManager getInstance() {
+        return sInstance;
     }
 
     /**
-     * Resets the state manager by clearing all panel definitions.
+     * Adds a new panel state definition.
      */
-    public static void reset() {
-        sInstance.mPanels.clear();
+    public static void addState(Context context, int stateResId)
+            throws XmlPullParserException, IOException {
+        if (DEBUG) {
+            Log.d(TAG, "addState: stateResId " + stateResId);
+        }
+        XmlModelLoader loader = new XmlModelLoader(context);
+        addState(loader.createPanelState(stateResId));
+    }
+
+    /**
+     * Adds a new panel state definition.
+     */
+    public static void addState(PanelState panelState) {
+        if (sInstance.mPanelStates.put(panelState.getId(), panelState) != null) {
+            if (DEBUG) {
+                Log.w(TAG, "Previous PanelState with id=" + panelState.getId() + " got replaced");
+            }
+        }
+        applyState(panelState);
+        Panel panel = PanelPool.getInstance().getPanel(panelState.getId());
+        panel.init();
     }
 
     /**
@@ -65,21 +111,42 @@ public class StateManager {
      *
      * @param event The event to be handled.
      */
-    static void handleEvent(Event event) {
-        for (PanelState panelState : sInstance.mPanels) {
+    public static PanelTransaction handleEvent(Event event) {
+        logIfDebuggable("handleEvent " + event);
+        PanelTransaction.Builder panelTransactionBuilder = new PanelTransaction.Builder();
+        HashSet<String> changedPanelIds = new HashSet<>();
+        for (PanelState panelState : sInstance.mPanelStates.values()) {
+            if (panelState == null) {
+                Log.e(TAG, "panel state is null");
+                continue;
+            }
             Transition transition = panelState.getTransition(event);
             if (transition == null) {
+                Log.e(TAG, "transition is null for " + panelState.getId());
                 continue;
             }
-
             Panel panel = PanelPool.getInstance().getPanel(panelState.getId());
+
+            Variant toVariant = transition.getToVariant();
+            Variant fromVariant = panelState.getCurrentVariant();
+
+            if (fromVariant == null) {
+                logIfDebuggable("fromVariant is null");
+                continue;
+            }
+
             Animator animator = transition.getAnimator(panel, panelState.getCurrentVariant());
             if (animator != null) {
                 // Update the internal state to the new variant and show the transition animation
                 panelState.onAnimationStart(animator);
-                panelState.setVariant(transition.getToVariant().getId(), event.getPayload());
                 animator.removeAllListeners();
+                panelState.setVariant(toVariant.getId(), event);
                 animator.addListener(new AnimatorListenerAdapter() {
+                    @Override
+                    public void onAnimationStart(Animator animation) {
+                        super.onAnimationStart(animation);
+                    }
+
                     @Override
                     public void onAnimationEnd(Animator animation) {
                         super.onAnimationEnd(animation);
@@ -87,14 +154,27 @@ public class StateManager {
                         applyState(panelState);
                     }
                 });
-                animator.start();
+                logIfDebuggable("add animator for " + panelState.getId());
+                panelTransactionBuilder.addAnimator(panelState.getId(), animator);
+                changedPanelIds.add(panelState.getId());
             } else if (!panelState.isAnimating()) {
                 // Force apply the new state if there is no on going animation.
-                Variant toVariant = transition.getToVariant();
-                panelState.setVariant(toVariant.getId(), event.getPayload());
+                logIfDebuggable("No animator for " + panelState.getId());
+                panelState.setVariant(toVariant.getId(), event);
                 applyState(panelState);
             }
+            logIfDebuggable("add transition for " + panelState.getId());
+            panelTransactionBuilder.addPanelTransaction(panelState.getId(), transition);
         }
+        if (!changedPanelIds.isEmpty()) {
+            // Store copy of existing panel state in case it changes prior to callback
+            Map<String, PanelState> panelStatesCopy = sInstance.createPanelStateCopy();
+            panelTransactionBuilder.setAnimationStartCallbackRunnable(
+                    sInstance.getBeforePanelStateChangeRunnable(changedPanelIds, panelStatesCopy));
+            panelTransactionBuilder.setAnimationEndCallbackRunnable(
+                    sInstance.getAfterPanelStateChangeRunnable(changedPanelIds, panelStatesCopy));
+        }
+        return panelTransactionBuilder.build();
     }
 
     /**
@@ -103,7 +183,7 @@ public class StateManager {
      *
      * @param panelState The panel data containing the current state information.
      */
-    private static void applyState(PanelState panelState) {
+    public static void applyState(PanelState panelState) {
         Variant variant = panelState.getCurrentVariant();
         String panelId = panelState.getId();
         Panel panel = PanelPool.getInstance().getPanel(panelId);
@@ -112,5 +192,142 @@ public class StateManager {
         panel.setVisibility(variant.isVisible());
         panel.setAlpha(variant.getAlpha());
         panel.setLayer(variant.getLayer());
+        panel.setDisplayId(panelState.getDisplayId());
+        panel.setInsets(variant.getInsets());
+        panel.setCornerRadius(variant.getCornerRadius());
+    }
+
+    //TODO(b/390006880): make this part of configuration.
+
+    /**
+     * Resets all the panels.
+     */
+    public static void handlePanelReset() {
+        for (PanelState panelState : getInstance().mPanelStates.values()) {
+            PanelPool.getInstance().getPanel(panelState.getId()).reset();
+        }
+    }
+
+    /**
+     * Retrieves a {@link PanelState} with the given id, or null if none is found.
+     */
+    @Nullable
+    public static PanelState getPanelState(String id) {
+        return getInstance().mPanelStates.getOrDefault(id, null);
+    }
+
+    @VisibleForTesting
+    Map<String, PanelState> getPanelStates() {
+        return mPanelStates;
+    }
+
+    private static void logIfDebuggable(String msg) {
+        if (DEBUG) {
+            Log.d(TAG, msg);
+        }
+    }
+
+    /**
+     * Add an observer to the panel state
+     * @param observer the observer
+     * @param panelIds the panel ids to observe
+     */
+    public void addPanelStateObserver(PanelStateObserver observer, String... panelIds) {
+        synchronized (mObservers) {
+            removePanelStateObserver(observer);
+            mObservers.add(new PanelStateObserverData(observer, panelIds));
+        }
+    }
+
+    /**
+     * Remove a panel state observer
+     */
+    public void removePanelStateObserver(PanelStateObserver observer) {
+        synchronized (mObservers) {
+            mObservers.removeIf(element -> element.mObserver == observer);
+        }
+    }
+
+    private Runnable getBeforePanelStateChangeRunnable(Set<String> changedPanelIds,
+            Map<String, PanelState> panelStates) {
+        return () -> notifyPanelStateChange(changedPanelIds, panelStates, /* before= */ true);
+    }
+
+    private Runnable getAfterPanelStateChangeRunnable(Set<String> changedPanelIds,
+            Map<String, PanelState> panelStates) {
+        return () -> notifyPanelStateChange(changedPanelIds, panelStates, /* before= */ false);
+    }
+
+    private void notifyPanelStateChange(Set<String> changedPanelIds,
+            Map<String, PanelState> panelStates, boolean before) {
+        try (ExecutorService executorService =  Executors.newSingleThreadExecutor()) {
+            executorService.execute(() -> {
+                synchronized (mObservers) {
+                    for (PanelStateObserverData data : mObservers) {
+                        if (data.observesPanel(changedPanelIds)) {
+                            if (before) {
+                                data.mObserver.onBeforePanelStateChanged(changedPanelIds,
+                                        panelStates);
+                            } else {
+                                data.mObserver.onPanelStateChanged(changedPanelIds,
+                                        panelStates);
+                            }
+                        }
+                    }
+                }
+            });
+        }
+    }
+
+    private Map<String, PanelState> createPanelStateCopy() {
+        Map<String, PanelState> panelStatesCopy = new HashMap<>();
+        mPanelStates.forEach((key, value) -> {
+            panelStatesCopy.put(key, new PanelState(value));
+        });
+        return panelStatesCopy;
+    }
+
+    @VisibleForTesting
+    void clearPanelStateObservers() {
+        synchronized (mObservers) {
+            mObservers.clear();
+        }
+    }
+
+    public interface PanelStateObserver {
+        /**
+         * Notify of a panel state change that has just started
+         * @param changedPanelIds the panelIds that are changing
+         * @param toPanelStates the panel states from after the change
+         */
+        void onBeforePanelStateChanged(Set<String> changedPanelIds,
+                Map<String, PanelState> toPanelStates);
+        /**
+         * Notify of a panel state change that has finished
+         * @param changedPanelIds the panelIds that have changed
+         * @param toPanelStates the panel states from after the change
+         */
+        void onPanelStateChanged(Set<String> changedPanelIds,
+                Map<String, PanelState> toPanelStates);
+    }
+
+    private static class PanelStateObserverData {
+        final PanelStateObserver mObserver;
+        final ArraySet<String> mPanelIds = new ArraySet<>();
+
+        PanelStateObserverData(PanelStateObserver observer, String... panelIds) {
+            mObserver = observer;
+            mPanelIds.addAll(Arrays.asList(panelIds));
+        }
+
+        boolean observesPanel(Set<String> changedPanelIds) {
+            if (mPanelIds.isEmpty()) {
+                return true;
+            }
+            if (changedPanelIds.isEmpty()) {
+                return false;
+            }
+            return !Collections.disjoint(mPanelIds, changedPanelIds);
+        }
     }
 }
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Alpha.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Alpha.java
index ab70d3d..38dac22 100644
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Alpha.java
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Alpha.java
@@ -13,30 +13,23 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 package com.android.car.scalableui.model;
 
-import android.util.AttributeSet;
-import android.util.Xml;
-
-import org.xmlpull.v1.XmlPullParser;
-import org.xmlpull.v1.XmlPullParserException;
-
-import java.io.IOException;
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
 
 /**
  * Represents the alpha (transparency) value of a UI element. This class provides methods for
  * creating an Alpha object from an XML definition and retrieving the alpha value.
  */
-class Alpha {
-    static final String ALPHA_TAG = "Alpha";
-    private static final String ALPHA_ATTRIBUTE = "alpha";
-    static final float DEFAULT_ALPHA = 1;
+public class Alpha {
+    public static final float DEFAULT_ALPHA = 1;
 
     private final float mAlpha;
 
     /**
-     * Constructs an Alpha object with the specified alpha value.
+     * Constructs an Alpha object with the specified alpha value. Package-private constructor; use
+     * the Builder.
      *
      * @param alpha The alpha value, between 0 (fully transparent) and 1 (fully opaque).
      */
@@ -53,23 +46,30 @@ class Alpha {
         return mAlpha;
     }
 
-    /**
-     * Creates an Alpha object from an XML parser.
-     *
-     * This method parses an XML element with the tag "Alpha" and extracts the "alpha" attribute
-     * to create an Alpha object. If the "alpha" attribute is not specified, it defaults to 1.0.
-     *
-     * @param parser The XML parser.
-     * @return An Alpha object with the parsed alpha value.
-     * @throws XmlPullParserException If an error occurs during XML parsing.
-     * @throws IOException If an I/O error occurs while reading the XML.
-     */
-    static Alpha create(XmlPullParser parser) throws XmlPullParserException, IOException {
-        parser.require(XmlPullParser.START_TAG, null, ALPHA_TAG);
-        AttributeSet attrs = Xml.asAttributeSet(parser);
-        float alpha = attrs.getAttributeFloatValue(null, ALPHA_ATTRIBUTE, DEFAULT_ALPHA);
-        parser.nextTag();
-        parser.require(XmlPullParser.END_TAG, null, ALPHA_TAG);
-        return new Alpha(alpha);
+    /** Builder for {@link Alpha} objects. */
+    public static class Builder {
+        @Nullable private Float mAlpha;
+
+        public Builder() {}
+
+        /** Sets alpha */
+        public Builder setAlpha(float alpha) {
+            if (alpha > 1) {
+                alpha = 1f;
+            } else if (alpha < 0) {
+                alpha = 0f;
+            } else {
+                mAlpha = alpha;
+            }
+            return this;
+        }
+
+        /** Returns the {@link Alpha} instance */
+        @NonNull
+        public Alpha build() {
+            // Use the default if alpha wasn't set explicitly
+            float alphaValue = (mAlpha != null) ? mAlpha : DEFAULT_ALPHA;
+            return new Alpha(alphaValue);
+        }
     }
 }
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Bounds.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Bounds.java
index 13041b0..10f54ed 100644
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Bounds.java
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Bounds.java
@@ -16,57 +16,40 @@
 
 package com.android.car.scalableui.model;
 
-import android.content.Context;
-import android.content.res.Resources;
 import android.graphics.Rect;
-import android.util.AttributeSet;
-import android.util.DisplayMetrics;
-import android.util.Xml;
-
-import org.xmlpull.v1.XmlPullParser;
-import org.xmlpull.v1.XmlPullParserException;
-
-import java.io.IOException;
 
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
 
 /**
  * Represents the bounds of a UI element. This class provides methods for creating a Bounds object
  * from an XML definition and retrieving the bounds as a {@link Rect}.
  *
  * <p>The Bounds class supports defining dimensions in the following formats:
+ *
  * <ul>
- *     <li><b>Absolute pixels:</b> e.g., <code>left="100"</code></li>
- *     <li><b>Density-independent pixels (dp):</b> e.g., <code>top="50dip"</code></li>
- *     <li><b>Percentage of screen width/height:</b> e.g., <code>right="80%"</code></li>
- *     <li><b>Resource references:</b> e.g., <code>bottom="@dimen/my_bottom_margin"</code></li>
+ *   <li><b>Absolute pixels:</b> e.g., <code>left="100"</code></li>
+ *   <li><b>Density-independent pixels (dp):</b> e.g., <code>top="50dip"</code></li>
+ *   <li><b>Percentage of screen width/height:</b> e.g., <code>right="80%"</code></li>
+ *   <li><b>Resource references:</b> e.g., <code>bottom="@dimen/my_bottom_margin"</code></li>
  * </ul>
  *
  * <p>It also allows defining either the left and right positions, or the left position and width.
  * Similarly, it allows defining either the top and bottom positions, or the top position and
  * height.
  */
-class Bounds {
-    static final String BOUNDS_TAG = "Bounds";
-    private static final String LEFT_ATTRIBUTE = "left";
-    private static final String RIGHT_ATTRIBUTE = "right";
-    private static final String TOP_ATTRIBUTE = "top";
-    private static final String BOTTOM_ATTRIBUTE = "bottom";
-    private static final String WIDTH_ATTRIBUTE = "width";
-    private static final String HEIGHT_ATTRIBUTE = "height";
-    private static final String DIP = "dip";
-    private static final String DP = "dp";
-    private static final String PERCENT = "%";
+public class Bounds {
     private final int mLeft;
     private final int mTop;
     private final int mRight;
     private final int mBottom;
 
     /**
-     * Constructs a Bounds object with the specified left, top, right, and bottom positions.
+     * Constructs a Bounds object. Package-private constructor; use the Builder.
      *
-     * @param left The left position in pixels.
-     * @param top The top position in pixels.
-     * @param right The right position in pixels.
+     * @param left   The left position in pixels.
+     * @param top    The top position in pixels.
+     * @param right  The right position in pixels.
      * @param bottom The bottom position in pixels.
      */
     Bounds(int left, int top, int right, int bottom) {
@@ -81,88 +64,91 @@ class Bounds {
      *
      * @return A Rect object representing the bounds.
      */
+    @NonNull
     public Rect getRect() {
         return new Rect(mLeft, mTop, mRight, mBottom);
     }
 
-    /**
-     * Creates a Bounds object from an XML parser.
-     *
-     * <p>This method parses an XML element with the tag "Bounds" and extracts the "left", "top",
-     * "right", and "bottom" attributes (or equivalent width/height combinations) to create a
-     * Bounds object.
-     *
-     * @param context The application context.
-     * @param parser The XML parser.
-     * @return A Bounds object with the parsed bounds.
-     * @throws XmlPullParserException If an error occurs during XML parsing.
-     * @throws IOException If an I/O error occurs while reading the XML.
-     */
-    static Bounds create(Context context, XmlPullParser parser) throws XmlPullParserException,
-            IOException {
-        parser.require(XmlPullParser.START_TAG, null, BOUNDS_TAG);
-        AttributeSet attrs = Xml.asAttributeSet(parser);
-        int left = getDimensionPixelSize(context, attrs, LEFT_ATTRIBUTE, true);
-        int top = getDimensionPixelSize(context, attrs,  TOP_ATTRIBUTE, false);
-        int right = getDimensionPixelSize(context, attrs, RIGHT_ATTRIBUTE, true);
-        int bottom = getDimensionPixelSize(context, attrs, BOTTOM_ATTRIBUTE, false);
-
-        int width = getDimensionPixelSize(context, attrs, WIDTH_ATTRIBUTE, true);
-        int height = getDimensionPixelSize(context, attrs, HEIGHT_ATTRIBUTE, false);
-        if (attrs.getAttributeValue(null, RIGHT_ATTRIBUTE) == null) {
-            right = left + width;
-        } else if (attrs.getAttributeValue(null, LEFT_ATTRIBUTE) == null) {
-            left = right - width;
+    /** Builder for {@link Bounds} objects. */
+    public static class Builder {
+        @Nullable private Integer mLeft;
+        @Nullable private Integer mTop;
+        @Nullable private Integer mRight;
+        @Nullable private Integer mBottom;
+        @Nullable private Integer mWidth;
+        @Nullable private Integer mHeight;
+
+        public Builder() {}
+
+        /** Sets left */
+        public Builder setLeft(@Nullable Integer left) {
+            mLeft = left;
+            return this;
         }
-        if (attrs.getAttributeValue(null, BOTTOM_ATTRIBUTE) == null) {
-            bottom = top + height;
-        } else if (attrs.getAttributeValue(null, TOP_ATTRIBUTE) == null) {
-            top = bottom - height;
+
+        /** Sets top */
+        public Builder setTop(@Nullable Integer top) {
+            mTop = top;
+            return this;
         }
 
-        parser.nextTag();
-        parser.require(XmlPullParser.END_TAG, null, BOUNDS_TAG);
-        return new Bounds(left, top, right, bottom);
-    }
+        /** Sets right */
+        public Builder setRight(@Nullable Integer right) {
+            mRight = right;
+            return this;
+        }
 
-    /**
-     * Helper method to get a dimension pixel size from an attribute set.
-     *
-     * @param context The application context.
-     * @param attrs The attribute set.
-     * @param name The name of the attribute.
-     * @param isHorizontal Whether the dimension is horizontal (width) or vertical (height).
-     * @return The dimension pixel size.
-     */
-    private static int getDimensionPixelSize(Context context, AttributeSet attrs, String name,
-            boolean isHorizontal) {
-        int resId = attrs.getAttributeResourceValue(null, name, 0);
-        if (resId != 0) {
-            return context.getResources().getDimensionPixelSize(resId);
+        /** Sets bottom */
+        public Builder setBottom(@Nullable Integer bottom) {
+            mBottom = bottom;
+            return this;
+        }
+
+        /** Sets width */
+        public Builder setWidth(@Nullable Integer width) {
+            mWidth = width;
+            return this;
+        }
+
+        /** Sets height */
+        public Builder setHeight(@Nullable Integer height) {
+            mHeight = height;
+            return this;
         }
-        String dimenStr = attrs.getAttributeValue(null, name);
-        if (dimenStr == null) {
-            return 0;
+
+        /** Sets rect */
+        public Builder setRect(@NonNull Rect rect) {
+            mLeft = rect.left;
+            mTop = rect.top;
+            mRight = rect.right;
+            mBottom = rect.bottom;
+            return this;
         }
-        if (dimenStr.toLowerCase().endsWith(DP)) {
-            String valueStr = dimenStr.substring(0, dimenStr.length() - DP.length());
-            float value = Float.parseFloat(valueStr);
-            return (int) (value * Resources.getSystem().getDisplayMetrics().density);
-        } else if (dimenStr.toLowerCase().endsWith(DIP)) {
-            String valueStr = dimenStr.substring(0, dimenStr.length() - DIP.length());
-            float value = Float.parseFloat(valueStr);
-            return (int) (value * Resources.getSystem().getDisplayMetrics().density);
-        } else if (dimenStr.toLowerCase().endsWith(PERCENT)) {
-            String valueStr = dimenStr.substring(0, dimenStr.length() - PERCENT.length());
-            float value = Float.parseFloat(valueStr);
-            DisplayMetrics displayMetrics = Resources.getSystem().getDisplayMetrics();
-            if (isHorizontal) {
-                return (int) (value * displayMetrics.widthPixels / 100);
-            } else {
-                return (int) (value * displayMetrics.heightPixels / 100);
+
+        /** Returns the {@link Bounds} instance */
+        @NonNull
+        public Bounds build() {
+            // Default values and logic to ensure a valid Rect.
+            int left = (mLeft != null) ? mLeft : 0;
+            int top = (mTop != null) ? mTop : 0;
+            int right = (mRight != null) ? mRight : 0;
+            int bottom = (mBottom != null) ? mBottom : 0;
+            int width = (mWidth != null) ? mWidth : 0;
+            int height = (mHeight != null) ? mHeight : 0;
+
+            // Handle width/height combinations, prioritizing explicit left/right/top/bottom
+            if (mRight == null && mWidth != null) {
+                right = left + width;
+            } else if (mLeft == null && mWidth != null) {
+                left = right - width;
+            }
+            if (mBottom == null && mHeight != null) {
+                bottom = top + height;
+            } else if (mTop == null && mHeight != null) {
+                top = bottom - height;
             }
-        } else {
-            return attrs.getAttributeIntValue(null, name, 0);
+
+            return new Bounds(left, top, right, bottom);
         }
     }
 }
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Corner.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Corner.java
new file mode 100644
index 0000000..8db88e5
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Corner.java
@@ -0,0 +1,76 @@
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
+package com.android.car.scalableui.model;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+/**
+ * Represents the corner of a {@code Panel}. This class provides methods for creating a Corner
+ * object from an XML definition and retrieving the radius value.
+ *
+ * <p>The Corner class supports defining dimensions in the following formats:
+ * <ul>
+ *     <li><b>Absolute pixels:</b> e.g., <code>left="100"</code></li>
+ *     <li><b>Density-independent pixels (dp):</b> e.g., <code>top="50dip"</code></li>
+ *     <li><b>Resource references:</b> e.g., <code>bottom="@dimen/my_bottom_margin"</code></li>
+ * </ul>
+ */
+public class Corner {
+    static final int DEFAULT_RADIUS = 0;
+
+    private final int mRadius;
+
+    /**
+     * Constructs a Corner object with the specified radius value.
+     *
+     * @param radius The radius value. 0 indicates a sharp corner.
+     */
+    Corner(int radius) {
+        mRadius = radius;
+    }
+
+    /**
+     * Returns the radius value.
+     *
+     * @return The Corner's radius value.
+     */
+    public int getRadius() {
+        return mRadius;
+    }
+
+    /** Builder for {@link Corner} objects. */
+    public static class Builder {
+        @Nullable private Integer mRadius;
+
+        public Builder() {}
+
+        /** Sets layer */
+        public Builder setRadius(int radius) {
+            mRadius = radius;
+            return this;
+        }
+
+        /** Returns the {@link Corner} instance */
+        @NonNull
+        public Corner build() {
+            // Use default if not explicitly set
+            int cornerValue = (mRadius != null) ? mRadius : DEFAULT_RADIUS;
+            return new Corner(cornerValue);
+        }
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Event.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Event.java
new file mode 100644
index 0000000..daae21e
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Event.java
@@ -0,0 +1,159 @@
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
+package com.android.car.scalableui.model;
+
+import android.text.TextUtils;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import java.util.HashMap;
+import java.util.Map;
+import java.util.StringTokenizer;
+
+/**
+ * Describes an event in the system. An event has an id and optionally tokens to match against
+ * transitions.
+ */
+public class Event {
+
+    /** Id string associated with this event. */
+    @NonNull
+    protected final String mId;
+
+    /**
+     * Token map for this event to be matched against. These tokens are in the format of key:value
+     * strings.
+     */
+    protected final Map<String, String> mTokens = new HashMap<>();
+
+    /**
+     * Constructs an Event.  Package-private; use the Builder.
+     *
+     * @param id A unique identifier associated with this event.
+     */
+    Event(@NonNull String id) {
+        mId = id;
+    }
+
+    protected Event(@NonNull String id, @NonNull Map<String, String> tokens) {
+        mId = id;
+        mTokens.putAll(tokens); // Defensive copy
+    }
+
+    /** Adds a token to this event to be matched against. */
+    public final Event addToken(String tokenId, String tokenValue) {
+        mTokens.put(tokenId, tokenValue);
+        return this;
+    }
+
+    /** Returns the id associated with this event. */
+    @NonNull
+    public String getId() {
+        return mId;
+    }
+
+    /** Return the tokens associated with this event. */
+    @NonNull
+    public Map<String, String> getTokens() {
+        // Return a copy to prevent external modification
+        return new HashMap<>(mTokens);
+    }
+
+    /**
+     * Whether the passed in parameters match this event.
+     *
+     * @param transitionEvent the event from the transition to match against
+     * @return true if this event matches the passed in parameters.
+     */
+    public boolean isMatch(@Nullable Event transitionEvent) {
+        if (transitionEvent == null) {
+            return false;
+        }
+
+        if (!TextUtils.equals(mId, transitionEvent.getId())) {
+            // ids don't match
+            return false;
+        }
+
+        Map<String, String> transitionTokens = transitionEvent.getTokens();
+        if (transitionTokens == null || transitionTokens.isEmpty()) {
+            // ids match and transition doesn't specify and additional tokens to match
+            return true;
+        }
+
+        if (mTokens.isEmpty()) {
+            // transition has tokens but event does not - not a match
+            return false;
+        }
+
+        for (String key : transitionTokens.keySet()) {
+            if (!mTokens.containsKey(key)
+                    || !TextUtils.equals(mTokens.get(key), transitionTokens.get(key))) {
+                // tokens don't match - not a match
+                return false;
+            }
+        }
+        // all specified transition tokens match the event
+        return true;
+    }
+
+    @Override
+    @NonNull
+    public String toString() {
+        return "Event{" + "mId='" + mId + "' mTokens='" + mTokens + "'}";
+    }
+
+    /** Builder for {@link Event} objects. */
+    public static class Builder {
+        protected String mId;
+        protected Map<String, String> mTokens = new HashMap<>();
+
+        public Builder(@NonNull String id) {
+            mId = id;
+        }
+
+        /** Adds token */
+        public Builder addToken(String key, String value) {
+            mTokens.put(key, value);
+            return this;
+        }
+
+        /** Sets token */
+        public Builder addTokensFromString(@Nullable String eventTokens) {
+            if (!TextUtils.isEmpty(eventTokens)) {
+                StringTokenizer tokenizer = new StringTokenizer(eventTokens, ";");
+                while (tokenizer.hasMoreTokens()) {
+                    String pair = tokenizer.nextToken();
+                    String[] keyValue = pair.split("=");
+                    if (keyValue.length == 2) {
+                        mTokens.put(keyValue[0], keyValue[1]);
+                    } // else:  Ignore malformed tokens.
+                }
+            }
+            return this;
+        }
+
+        /** Returns the {@link Event} instance */
+        @NonNull
+        public Event build() {
+            if (mId == null) {
+                throw new IllegalStateException("Event ID must be set.");
+            }
+            return new Event(mId, mTokens);
+        }
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/KeyFrameEvent.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/KeyFrameEvent.java
new file mode 100644
index 0000000..c791d55
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/KeyFrameEvent.java
@@ -0,0 +1,90 @@
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
+package com.android.car.scalableui.model;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import java.util.Map;
+
+/**
+ * Describes a KeyframeEvent in the system. This is the same as a standard {@link Event} but
+ * includes a fraction value that represents the keyframe event progress.
+ */
+public class KeyFrameEvent extends Event {
+    private final float mFraction;
+
+    /**
+     * Constructs a KeyframeEvent.
+     *
+     * @param id       A unique identifier associated with this event.
+     * @param fraction A fraction value (between 0 and 1).
+     */
+    public KeyFrameEvent(@NonNull String id, float fraction, @NonNull Map<String, String> tokens) {
+        super(id, tokens);
+        mFraction = fraction;
+    }
+
+    @NonNull
+    @Override
+    public String toString() {
+        return "KeyFrameEvent{" + "mId=" + mId + ", mTokens=" + mTokens + ", mFraction="
+                + mFraction + "}";
+    }
+
+    /**
+     * Returns the fraction associated with this event.
+     *
+     * @return The fraction progress value of this event (between 0 and 1).
+     */
+    public float getFraction() {
+        return mFraction;
+    }
+
+    /** Builder for {@link Event} objects. */
+    public static class Builder extends Event.Builder {
+        private final float mFraction;
+
+        public Builder(@NonNull String id, float fraction) {
+            super(id);
+            mFraction = fraction;
+        }
+
+        @Override
+        public Builder addTokensFromString(@Nullable String eventTokens) {
+            super.addTokensFromString(eventTokens);
+            return this;
+        }
+
+        @Override
+        public Builder addToken(String key, String value) {
+            super.addToken(key, value);
+            return this;
+        }
+
+        /** Returns the {@link Event} instance */
+        @Override
+        @NonNull
+        public KeyFrameEvent build() {
+            if (mFraction < 0 || mFraction > 1) {
+                throw new IllegalStateException(
+                        "KeyFrameEvent ID must be set with valid fraction." + mId + " "
+                                + mFraction);
+            }
+            return new KeyFrameEvent(mId, mFraction, mTokens);
+        }
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/KeyFrameVariant.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/KeyFrameVariant.java
index de961fc..412775a 100644
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/model/KeyFrameVariant.java
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/KeyFrameVariant.java
@@ -13,19 +13,16 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 package com.android.car.scalableui.model;
 
 import android.animation.FloatEvaluator;
 import android.animation.RectEvaluator;
+import android.graphics.Insets;
 import android.graphics.Rect;
-import android.util.AttributeSet;
-import android.util.Xml;
 
-import org.xmlpull.v1.XmlPullParser;
-import org.xmlpull.v1.XmlPullParserException;
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
 
-import java.io.IOException;
 import java.util.ArrayList;
 import java.util.Comparator;
 import java.util.List;
@@ -35,27 +32,19 @@ import java.util.Objects;
  * A {@link Variant} that interpolates between different variants based on a fraction value.
  *
  * <p>This class defines a series of keyframes, each associated with a {@link Variant} and a frame
- * position. The {@link #setFraction(float)} method sets the current fraction, which determines
- * the interpolation between keyframes.</p>
+ * position. The {@link #setFraction(float)} method sets the current fraction, which determines the
+ * interpolation between keyframes.</p>
  *
  * <p>KeyFrameVariant allows for smooth transitions between different panel states by interpolating
  * properties such as bounds, visibility, and alpha.
  */
 public class KeyFrameVariant extends Variant {
-    static final String KEY_FRAME_VARIANT_TAG = "KeyFrameVariant";
-    private static final String ID_ATTRIBUTE = "id";
-    private static final String PARENT_ATTRIBUTE = "parent";
-    private static final String KEY_FRAME_TAG = "KeyFrame";
-    private static final String FRAME_ATTRIBUTE = "frame";
-    private static final String VARIANT_ATTRIBUTE = "variant";
-
+    private static final String TAG = KeyFrameVariant.class.getSimpleName();
     private float mFraction;
     private final RectEvaluator mRectEvaluator = new RectEvaluator();
     private final FloatEvaluator mFloatEvaluator = new FloatEvaluator();
 
-    /**
-     * Represents a single keyframe in a {@link KeyFrameVariant}.
-     */
+    /** Represents a single keyframe in a {@link KeyFrameVariant}. */
     public static class KeyFrame {
         int mFramePosition;
         Variant mVariant;
@@ -66,51 +55,66 @@ public class KeyFrameVariant extends Variant {
          * @param framePosition The position of the keyframe (0-100).
          * @param variant       The variant associated with this keyframe.
          */
-        public KeyFrame(int framePosition, Variant variant) {
+        public KeyFrame(int framePosition, @NonNull Variant variant) {
             mFramePosition = framePosition;
             mVariant = variant;
         }
 
-        /**
-         * Reads a {@link KeyFrame} from an XMLPullParser.
-         *
-         * @param panelState The current panel state.
-         * @param parser     The XML parser.
-         * @return The created KeyFrame.
-         * @throws XmlPullParserException If an error occurs during XML parsing.
-         * @throws IOException            If an I/O error occurs while reading the XML.
-         */
-        private static KeyFrame create(PanelState panelState, XmlPullParser parser)
-                throws XmlPullParserException, IOException {
-            parser.require(XmlPullParser.START_TAG, null, KEY_FRAME_TAG);
-            AttributeSet attrs = Xml.asAttributeSet(parser);
-            int frame = attrs.getAttributeIntValue(null, FRAME_ATTRIBUTE, 0);
-            String variant = attrs.getAttributeValue(null, VARIANT_ATTRIBUTE);
-            parser.nextTag();
-            parser.require(XmlPullParser.END_TAG, null, KEY_FRAME_TAG);
-            Variant panelVariant = panelState.getVariant(variant);
-            return new KeyFrameVariant.KeyFrame(frame, panelVariant);
+        /** Builder for {@link KeyFrameVariant} objects. */
+        public static class Builder {
+            private final int mFramePosition;
+            private final Variant mVariant;
+
+            public Builder(int framePosition, @NonNull Variant variant) {
+                mVariant = variant;
+                mFramePosition = framePosition;
+            }
+
+            /** Returns the {@link KeyFrameVariant} instance */
+            public KeyFrame build() {
+                if (mVariant == null) {
+                    throw new IllegalStateException("Variant must be set for KeyFrame");
+                }
+                return new KeyFrame(mFramePosition, mVariant);
+            }
+        }
+
+        @Override
+        public String toString() {
+            return "KeyFrame{"
+                    + "mFramePosition=" + mFramePosition
+                    + ", mVariant=" + mVariant
+                    + '}';
         }
     }
 
     private final List<KeyFrame> mKeyFrames = new ArrayList<>();
 
     /**
-     * Constructor for KeyFrameVariant.
+     * Constructor for KeyFrameVariant. Package-private, use the Builder.
      *
-     * @param id     The ID of this variant.
+     * @param id   The ID of this variant.
      * @param base The base variant to inherit properties from.
      */
-    public KeyFrameVariant(String id, Variant base) {
+    KeyFrameVariant(@NonNull String id, @NonNull Variant base) {
         super(id, base);
     }
 
+    /**
+     * Constructor for KeyFrameVariant. Package-private, use the Builder.
+     *
+     * @param id The ID of this variant.
+     */
+    KeyFrameVariant(@NonNull String id) {
+        super(id);
+    }
+
     /**
      * Adds a keyframe to this variant.
      *
      * @param keyFrame The keyframe to add.
      */
-    public void addKeyFrame(KeyFrame keyFrame) {
+    public void addKeyFrame(@NonNull KeyFrame keyFrame) {
         mKeyFrames.add(keyFrame);
         mKeyFrames.sort(Comparator.comparingInt(o -> o.mFramePosition));
     }
@@ -129,6 +133,8 @@ public class KeyFrameVariant extends Variant {
      *
      * @return The interpolated bounds.
      */
+    @Override
+    @NonNull
     public Rect getBounds() {
         return getBounds(mFraction);
     }
@@ -138,6 +144,7 @@ public class KeyFrameVariant extends Variant {
      *
      * @return The interpolated visibility.
      */
+    @Override
     public boolean isVisible() {
         return getVisibility(mFraction);
     }
@@ -147,19 +154,16 @@ public class KeyFrameVariant extends Variant {
      *
      * @return The interpolated alpha.
      */
+    @Override
     public float getAlpha() {
         return getAlpha(mFraction);
     }
 
-    /**
-     * Sets the payload for this variant.
-     *
-     * <p>The payload is expected to be a float value representing the fraction.
-     *
-     * @param payload The payload object.
-     */
-    public void setPayload(Object payload) {
-        setFraction((float) payload);
+    @Override
+    public void updateFromEvent(@Nullable Event event) {
+        if (event instanceof KeyFrameEvent keyFrameEvent) {
+            setFraction(keyFrameEvent.getFraction());
+        }
     }
 
     /**
@@ -173,9 +177,10 @@ public class KeyFrameVariant extends Variant {
      * @param fraction The fraction value (between 0 and 1).
      * @return The keyframe before the given fraction, or null if there are no keyframes.
      */
+    @Nullable
     private KeyFrame before(float fraction) {
         if (mKeyFrames.isEmpty()) return null;
-        KeyFrame current = mKeyFrames.get(0);
+        KeyFrame current = mKeyFrames.getFirst();
         for (KeyFrame keyFrame : mKeyFrames) {
             if (keyFrame.mFramePosition >= fraction * 100) {
                 return current;
@@ -187,9 +192,11 @@ public class KeyFrameVariant extends Variant {
 
     /**
      * Returns the key frame after the fraction
+     *
      * @param fraction The fraction value (between 0 and 1).
      * @return The key frame
      */
+    @Nullable
     private KeyFrame after(float fraction) {
         if (mKeyFrames.isEmpty()) return null;
         for (KeyFrame keyFrame : mKeyFrames) {
@@ -207,8 +214,8 @@ public class KeyFrameVariant extends Variant {
      * value (between 0 and 1). It calculates the fraction between the two keyframes, effectively
      * normalizing the overall fraction to the range between the keyframes.
      *
-     * <p>For example, if framePosition1 is 20, framePosition2 is 80, and fraction is 0.5, the
-     * result will be 0.75, because 0.5 lies at 75% of the range between 20 and 80.
+     * <p>For example, if framePosition1 is 0, framePosition2 is 80, and fraction is 0.5, the
+     * result will be 0.75, because 0.5 lies at 62.5% of the range between 0 and 80.
      *
      * @param framePosition1 The position of the first keyframe (0-100).
      * @param framePosition2 The position of the second keyframe (0-100).
@@ -222,25 +229,42 @@ public class KeyFrameVariant extends Variant {
         return (fraction - framePosition1) / (framePosition2 - framePosition1);
     }
 
-
     /**
      * Returns the interpolated bounds for the given fraction.
      *
      * @param fraction The fraction value (between 0 and 1).
      * @return The interpolated bounds.
      */
+    @NonNull
     private Rect getBounds(float fraction) {
         if (mKeyFrames.isEmpty()) return new Rect();
         KeyFrame keyFrame1 = before(fraction);
         Rect bounds1 = Objects.requireNonNull(keyFrame1).mVariant.getBounds();
         KeyFrame keyFrame2 = after(fraction);
         Rect bounds2 = Objects.requireNonNull(keyFrame2).mVariant.getBounds();
-        float fractionInBetween = getKeyFrameFraction(keyFrame1.mFramePosition,
-                keyFrame2.mFramePosition, fraction);
+        float fractionInBetween =
+                getKeyFrameFraction(
+                        keyFrame1.mFramePosition, keyFrame2.mFramePosition, fraction);
         Rect rect = mRectEvaluator.evaluate(fractionInBetween, bounds1, bounds2);
         return new Rect(rect.left, rect.top, rect.right, rect.bottom);
     }
 
+    @NonNull
+    @Override
+    public String toString() {
+        StringBuilder sb = new StringBuilder("KeyFrameVariant{ mid=")
+                .append(mId)
+                .append(", mFraction=")
+                .append(mFraction);
+        for (KeyFrame keyFrame : mKeyFrames) {
+            sb.append(", keyFrame=").append(keyFrame);
+        }
+        sb.append(", layer=").append(getLayer());
+        sb.append(", visibility=").append(isVisible());
+        sb.append("}");
+        return sb.toString();
+    }
+
     /**
      * Returns the interpolated visibility for the given fraction.
      *
@@ -271,32 +295,63 @@ public class KeyFrameVariant extends Variant {
         return mFloatEvaluator.evaluate(fraction, alpha1, alpha2);
     }
 
-    /**
-     * Creates a {@link KeyFrameVariant} from an XMLPullParser.
-     *
-     * @param panelState The current panel state.
-     * @param parser     The XML parser.
-     * @return The created KeyFrameVariant.
-     * @throws XmlPullParserException If an error occurs during XML parsing.
-     * @throws IOException            If an I/O error occurs while reading the XML.
-     */
-    static KeyFrameVariant create(PanelState panelState, XmlPullParser parser)
-            throws XmlPullParserException, IOException {
-        parser.require(XmlPullParser.START_TAG, null, KEY_FRAME_VARIANT_TAG);
-        AttributeSet attrs = Xml.asAttributeSet(parser);
-        String id = attrs.getAttributeValue(null, ID_ATTRIBUTE);
-        String parentStr = attrs.getAttributeValue(null, PARENT_ATTRIBUTE);
-        Variant parent = panelState.getVariant(parentStr);
-        KeyFrameVariant result = new KeyFrameVariant(id, parent);
-        while (parser.next() != XmlPullParser.END_TAG) {
-            if (parser.getEventType() != XmlPullParser.START_TAG) continue;
-            String name = parser.getName();
-            if (name.equals(KEY_FRAME_TAG)) {
-                result.addKeyFrame(KeyFrame.create(panelState, parser));
+    /** Builder for {@link KeyFrameVariant} objects. */
+    public static class Builder extends Variant.Builder {
+        private List<KeyFrame> mKeyFrames = new ArrayList<>();
+
+        public Builder(@NonNull String id) {
+            super(id);
+        }
+
+        /** Adds keyframe */
+        public Builder addKeyFrame(@NonNull KeyFrame keyFrame) {
+            mKeyFrames.add(keyFrame);
+            return this;
+        }
+
+        /** Sets keyframes */
+        public Builder setKeyFrames(@NonNull List<KeyFrame> keyFrames) {
+            mKeyFrames = new ArrayList<>(keyFrames); // Defensive copy
+            return this;
+        }
+
+        /** Returns the {@link KeyFrameVariant} instance */
+        @Override
+        @NonNull
+        public KeyFrameVariant build() {
+            KeyFrameVariant variant;
+            if (mParent != null) {
+                variant = new KeyFrameVariant(mId, mParent);
             } else {
-                XmlPullParserHelper.skip(parser);
+                variant = new KeyFrameVariant(mId);
+            }
+
+            if (mAlpha != null) {
+                variant.setAlpha(mAlpha);
+            }
+            if (mIsVisible != null) {
+                variant.setVisibility(mIsVisible);
+            }
+            if (mLayer != null) {
+                variant.setLayer(mLayer);
+            }
+            if (mBounds != null) {
+                variant.setBounds(new Rect(mBounds)); // Defensive copy
+            }
+            if (mCornerRadius != null) {
+                variant.setCornerRadius(mCornerRadius);
+            }
+            if (mInsets != null) {
+                variant.setInsets(
+                        Insets.of(mInsets.left, mInsets.top, mInsets.right, mInsets.bottom));
+            }
+
+            // Sort keyframes by frame position after adding them all.
+            mKeyFrames.sort(Comparator.comparingInt(o -> o.mFramePosition));
+            for (KeyFrame keyFrame : mKeyFrames) {
+                variant.addKeyFrame(keyFrame);
             }
+            return variant;
         }
-        return result;
     }
 }
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Layer.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Layer.java
index e587728..d7a38b5 100644
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Layer.java
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Layer.java
@@ -16,31 +16,23 @@
 
 package com.android.car.scalableui.model;
 
-import android.util.AttributeSet;
-import android.util.Xml;
-
-import org.xmlpull.v1.XmlPullParser;
-import org.xmlpull.v1.XmlPullParserException;
-
-import java.io.IOException;
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
 
 /**
  * Represents the layer of a {@code Panel}. This class provides methods for creating a Layer object
  * from an XML definition and retrieving the layer value.
  */
-class Layer {
-    static final String LAYER_TAG = "Layer";
-    private static final String LAYER_ATTRIBUTE = "layer";
+public class Layer {
 
-    static final int DEFAULT_LAYER = 0;
+    public static final int DEFAULT_LAYER = 0;
 
     private final int mLayer;
 
     /**
-     * Constructs a Layer object with the specified layer value.
+     * Constructs a Layer object. Package-private; use the Builder.
      *
-     * @param layer The layer value. Higher values indicate that the element should be drawn on top
-     *              of elements with lower layer values.
+     * @param layer The layer value.
      */
     Layer(int layer) {
         mLayer = layer;
@@ -55,23 +47,24 @@ class Layer {
         return mLayer;
     }
 
-    /**
-     * Creates a Layer object from an XML parser.
-     *
-     * <p>This method parses an XML element with the tag "Layer" and extracts the "layer" attribute
-     * to create a Layer object. If the "layer" attribute is not specified, it defaults to 0.
-     *
-     * @param parser The XML parser.
-     * @return A Layer object with the parsed layer value.
-     * @throws XmlPullParserException If an error occurs during XML parsing.
-     * @throws IOException If an I/O error occurs while reading the XML.
-     */
-    static Layer create(XmlPullParser parser) throws XmlPullParserException, IOException {
-        parser.require(XmlPullParser.START_TAG, null, LAYER_TAG);
-        AttributeSet attrs = Xml.asAttributeSet(parser);
-        int layer = attrs.getAttributeIntValue(null, LAYER_ATTRIBUTE, DEFAULT_LAYER);
-        parser.nextTag();
-        parser.require(XmlPullParser.END_TAG, null, LAYER_TAG);
-        return new Layer(layer);
+    /** Builder for {@link Layer} objects. */
+    public static class Builder {
+        @Nullable private Integer mLayer;
+
+        public Builder() {}
+
+        /** Sets layer */
+        public Builder setLayer(int layer) {
+            mLayer = layer;
+            return this;
+        }
+
+        /** Returns the {@link Layer} instance */
+        @NonNull
+        public Layer build() {
+            // Use default if not explicitly set
+            int layerValue = (mLayer != null) ? mLayer : DEFAULT_LAYER;
+            return new Layer(layerValue);
+        }
     }
 }
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/PanelState.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/PanelState.java
index d8ac257..bd9eb57 100644
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/model/PanelState.java
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/PanelState.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2024 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project.
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,29 +13,18 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 package com.android.car.scalableui.model;
 
-import static com.android.car.scalableui.model.KeyFrameVariant.KEY_FRAME_VARIANT_TAG;
-import static com.android.car.scalableui.model.Transition.TRANSITION_TAG;
-import static com.android.car.scalableui.model.Variant.VARIANT_TAG;
+import static android.view.Display.DEFAULT_DISPLAY;
 
 import android.animation.Animator;
-import android.content.Context;
-import android.content.res.XmlResourceParser;
-import android.util.AttributeSet;
-import android.util.Xml;
-import android.view.animation.AnimationUtils;
-import android.view.animation.Interpolator;
-
-import com.android.car.scalableui.manager.Event;
 
-import org.xmlpull.v1.XmlPullParser;
-import org.xmlpull.v1.XmlPullParserException;
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
 
-import java.io.IOException;
 import java.util.ArrayList;
 import java.util.List;
+import java.util.stream.Collectors;
 
 /**
  * Represents the state of a panel in the Scalable UI system.
@@ -45,40 +34,21 @@ import java.util.List;
  * animations.
  */
 public class PanelState {
-    private static final String PANEL_TAG = "Panel";
-    private static final String ID_TAG = "id";
-    private static final String DEFAULT_VARIANT_ATTRIBUTE = "defaultVariant";
-    private static final String ROLE_ATTRIBUTE = "role";
-    private static final String TRANSITIONS_TAG = "Transitions";
-    private static final String DEFAULT_DURATION_ATTRIBUTE = "defaultDuration";
-    private static final String DEFAULT_INTERPOLATOR_ATTRIBUTE = "defaultInterpolator";
-    private static final int DEFAULT_TRANSITION_DURATION = 300;
+    private static final String TAG = PanelState.class.getSimpleName();
 
-    /**
-     * Loads a PanelState from an XML resource.
-     *
-     * @param context    The context to use.
-     * @param resourceId The ID of the XML resource.
-     * @return The loaded PanelState.
-     * @throws XmlPullParserException If an error occurs during XML parsing.
-     * @throws IOException If an I/O error occurs while reading the XML.
-     */
-    public static PanelState load(Context context, int resourceId) throws XmlPullParserException,
-            IOException {
-        XmlResourceParser parser = context.getResources().getXml(resourceId);
-        while (true) {
-            if (parser.next() == XmlPullParser.START_TAG) break;
-        }
-        return PanelState.create(context, parser);
-    }
+    public static final String DEFAULT_ROLE = "DEFAULT";
+    public static final String DECOR_PANEL_ID_PREFIX = "decor";
+
+    private String mDefaultVariant;
+    private int mDisplayId;
 
     private final String mId;
     private final Role mRole;
     private final List<Variant> mVariants = new ArrayList<>();
     private final List<Transition> mTransitions = new ArrayList<>();
 
-    private Animator mRunningAnimator;
-    private Variant mCurrentVariant;
+    @Nullable private Animator mRunningAnimator;
+    @Nullable private Variant mCurrentVariant;
 
     /**
      * Constructor for PanelState.
@@ -86,57 +56,57 @@ public class PanelState {
      * @param id The ID of the panel.
      * @param role The role of the panel.
      */
-    public PanelState(String id, Role role) {
+    public PanelState(@NonNull String id, @NonNull Role role) {
         mId = id;
         mRole = role;
+        mDisplayId = DEFAULT_DISPLAY;
     }
 
     /**
-     * Returns the ID of the panel.
-     *
-     * @return The ID of the panel.
+     * Constructor to copy a PanelState
      */
+    public PanelState(@NonNull PanelState other) {
+        mId = other.mId;
+        mRole = other.mRole;
+        mDisplayId = other.mDisplayId;
+        mDefaultVariant = other.mDefaultVariant;
+        mVariants.addAll(other.mVariants);
+        mTransitions.addAll(other.mTransitions);
+        mRunningAnimator = other.mRunningAnimator;
+        mCurrentVariant = other.mCurrentVariant;
+    }
+
+    /** Returns id */
+    @NonNull
     public String getId() {
         return mId;
     }
 
-    /**
-     * Adds a variant to the panel.
-     *
-     * @param variant The variant to add.
-     */
-    public void addVariant(Variant variant) {
+    /** Adds variant */
+    public void addVariant(@NonNull Variant variant) {
         mVariants.add(variant);
     }
 
-    /**
-     * Adds a transition to the panel.
-     *
-     * @param transition The transition to add.
-     */
-    public void addTransition(Transition transition) {
+    /** Adds transition */
+    public void addTransition(@NonNull Transition transition) {
         mTransitions.add(transition);
     }
 
-    /**
-     * Returns the current variant of the panel.
-     *
-     * @return The current variant of the panel.
-     */
+    /** Returns current variant */
+    @Nullable
     public Variant getCurrentVariant() {
         if (mCurrentVariant == null) {
-            mCurrentVariant = mVariants.get(0);
+            // Ensure mVariants is not empty before accessing
+            if (!mVariants.isEmpty()) {
+                mCurrentVariant = mVariants.get(0);
+            }
         }
         return mCurrentVariant;
     }
 
-    /**
-     * Returns the variant with the given ID.
-     *
-     * @param id The ID of the variant.
-     * @return The variant with the given ID, or null if not found.
-     */
-    public Variant getVariant(String id) {
+    /** Returns variant with the given id */
+    @Nullable
+    public Variant getVariant(@NonNull String id) {
         for (Variant variant : mVariants) {
             if (variant.getId().equals(id)) {
                 return variant;
@@ -145,57 +115,47 @@ public class PanelState {
         return null;
     }
 
-    /**
-     * Sets the current variant to the variant with the given ID.
-     *
-     * @param id The ID of the variant.
-     */
-    public void setVariant(String id) {
+    /** Sets variant with the given id */
+    public void setVariant(@NonNull String id) {
         setVariant(id, null);
     }
 
+    /** Resets to the default variant */
+    public void resetVariant() {
+        setVariant(mDefaultVariant);
+    }
+
     /**
-     * Sets the current variant to the variant with the given ID and payload.
+     * Sets variant
      *
-     * @param id      The ID of the variant.
-     * @param payload The payload to pass to the variant.
+     * @param id The ID of the variant to set.
+     * @param event The event that triggered the variant change.
      */
-    public void setVariant(String id, Object payload) {
+    public void setVariant(@NonNull String id, @Nullable Event event) {
         for (Variant variant : mVariants) {
-            if (variant.getId().equals(id)) {
+            if (variant != null && variant.getId().equals(id)) {
                 mCurrentVariant = variant;
-                if (mCurrentVariant instanceof KeyFrameVariant) {
-                    ((KeyFrameVariant) mCurrentVariant).setPayload(payload);
+                if (event != null) {
+                    mCurrentVariant.updateFromEvent(event);
                 }
                 return;
             }
         }
     }
 
-    /**
-     * Returns the role of the panel.
-     *
-     * @return The role of the panel.
-     */
+    /** Returns the role */
+    @NonNull
     public Role getRole() {
         return mRole;
     }
 
-    /**
-     * Returns true if the panel is currently animating.
-     *
-     * @return True if the panel is currently animating.
-     */
+    /** Returns true if animating */
     public boolean isAnimating() {
         return mRunningAnimator != null && mRunningAnimator.isRunning();
     }
 
-    /**
-     * Should be called when an animation starts.
-     *
-     * @param animator The animator that started.
-     */
-    public void onAnimationStart(Animator animator) {
+    /** Called on animation start */
+    public void onAnimationStart(@NonNull Animator animator) {
         if (mRunningAnimator != null) {
             mRunningAnimator.pause();
             mRunningAnimator.removeAllListeners();
@@ -203,39 +163,33 @@ public class PanelState {
         mRunningAnimator = animator;
     }
 
-    /**
-     * Should be Called when an animation ends.
-     */
+    /** Called on animation end */
     public void onAnimationEnd() {
         mRunningAnimator = null;
     }
 
-    /**
-     * Returns the transition for the given event.
-     *
-     * @param event The event.
-     * @return The transition for the given event, or null if not found.
-     */
-    public Transition getTransition(Event event) {
+    /** Returns transition for the given event */
+    @Nullable
+    public Transition getTransition(@Nullable Event event) {
+        if (event == null) {
+            return null;
+        }
         // If both onEvent and fromVariant matches
-        Transition result = getTransition(event.getId(), getCurrentVariant().getId());
+        String currentVariantId =
+                (getCurrentVariant() != null) ? getCurrentVariant().getId() : null;
+        Transition result = getTransitionInternal(event, currentVariantId);
+
         if (result != null) {
             return result;
         }
         // If only onEvent matches
-        return getTransition(event.getId());
+        return getTransitionInternal(event);
     }
 
-    /**
-     * Returns a transition that matches the given event ID and "from" variant.
-     *
-     * @param eventId The ID of the event to find a transition for.
-     * @param fromVariant The ID of the variant the transition should start from.
-     * @return The matching transition, or null if no such transition is found.
-     */
-    private Transition getTransition(String eventId, String fromVariant) {
+    @Nullable
+    private Transition getTransitionInternal(@NonNull Event event, @Nullable String fromVariant) {
         for (Transition transition : mTransitions) {
-            if (eventId.equals(transition.getOnEvent())
+            if (event.isMatch(transition.getOnEvent())
                     && transition.getFromVariant() != null
                     && transition.getFromVariant().getId().equals(fromVariant)) {
                 return transition;
@@ -244,16 +198,10 @@ public class PanelState {
         return null;
     }
 
-    /**
-     * Returns a transition that matches the given event ID and has no "from" variant specified.
-     *
-     * @param eventId The ID of the event to find a transition for.
-     * @return The matching transition, or null if no such transition is found.
-     */
-    private Transition getTransition(String eventId) {
+    @Nullable
+    private Transition getTransitionInternal(@NonNull Event event) {
         for (Transition transition : mTransitions) {
-            if (eventId.equals(transition.getOnEvent())
-                    && transition.getFromVariant() == null) {
+            if (event.isMatch(transition.getOnEvent()) && transition.getFromVariant() == null) {
                 return transition;
             }
         }
@@ -261,86 +209,113 @@ public class PanelState {
     }
 
     /**
-     * Creates a PanelState object from an XML parser.
-     *
-     * <p>This method parses an XML element with the tag "Panel" and extracts its attributes
-     * and child elements to create a Panel object.
+     * Returns the ID of the display the panel is associated with.
      *
-     * @param context The application context.
-     * @param parser The XML parser.
-     * @return A PanelState object with the parsed properties.
-     * @throws XmlPullParserException If an error occurs during XML parsing.
-     * @throws IOException If an I/O error occurs while reading the XML.
+     * @return The display ID.
      */
-    private static PanelState create(Context context, XmlPullParser parser) throws
-            XmlPullParserException, IOException {
-        parser.require(XmlPullParser.START_TAG, null, PANEL_TAG);
-        AttributeSet attrs = Xml.asAttributeSet(parser);
-        String id = attrs.getAttributeValue(null, ID_TAG);
-        String defaultVariant = attrs.getAttributeValue(null, DEFAULT_VARIANT_ATTRIBUTE);
-        int roleValue = attrs.getAttributeResourceValue(null, ROLE_ATTRIBUTE, 0);
-        PanelState result = new PanelState(id, new Role(roleValue));
-        while (parser.next() != XmlPullParser.END_TAG) {
-            if (parser.getEventType() != XmlPullParser.START_TAG) continue;
-            String name = parser.getName();
-            switch (name) {
-                case VARIANT_TAG:
-                    Variant variant = Variant.create(context, result, parser);
-                    result.addVariant(variant);
-                    break;
-                case KEY_FRAME_VARIANT_TAG:
-                    KeyFrameVariant keyFrameVariant = KeyFrameVariant.create(result, parser);
-                    result.addVariant(keyFrameVariant);
-                    break;
-                case TRANSITIONS_TAG:
-                    List<Transition> transitions = readTransitions(context, result, parser);
-                    for (Transition transition : transitions) {
-                        result.addTransition(transition);
-                    }
-                    break;
-                default:
-                    XmlPullParserHelper.skip(parser);
-                    break;
-            }
-        }
-        result.setVariant(defaultVariant);
-        return result;
+    public int getDisplayId() {
+        return mDisplayId;
     }
 
-    /**
-     * Reads a list of Transition objects from an XML parser.
-     *
-     * <p>This method parses an XML element with the tag "Transitions" and extracts its attributes
-     * and child transition elements.
-     *
-     * @param context The application context.
-     * @param parser The XML parser.
-     * @return A list of Transition objects with the parsed properties.
-     * @throws XmlPullParserException If an error occurs during XML parsing.
-     * @throws IOException If an I/O error occurs while reading the XML.
-     */
-    private static List<Transition> readTransitions(Context context, PanelState panelState,
-                                                    XmlPullParser parser)
-            throws XmlPullParserException, IOException {
-        parser.require(XmlPullParser.START_TAG, null, TRANSITIONS_TAG);
-        AttributeSet attrs = Xml.asAttributeSet(parser);
-        int duration = attrs.getAttributeIntValue(null,
-                DEFAULT_DURATION_ATTRIBUTE, DEFAULT_TRANSITION_DURATION);
-        int interpolatorRef = attrs.getAttributeResourceValue(null,
-                DEFAULT_INTERPOLATOR_ATTRIBUTE, 0);
-        Interpolator interpolator = interpolatorRef == 0 ? null :
-                AnimationUtils.loadInterpolator(context, interpolatorRef);
-
-        List<Transition> result = new ArrayList<>();
-        while (parser.next() != XmlPullParser.END_TAG) {
-            if (parser.getEventType() != XmlPullParser.START_TAG) continue;
-
-            if (parser.getName().equals(TRANSITION_TAG)) {
-                result.add(Transition.create(context, panelState, duration, interpolator, parser));
-            } else {
-                XmlPullParserHelper.skip(parser);
+    void setDefaultVariant(@Nullable String defaultVariant) {
+        mDefaultVariant = defaultVariant;
+    }
+
+    void setDisplayId(int displayId) {
+        mDisplayId = displayId;
+    }
+
+    void setVariants(@NonNull List<Variant> variants) {
+        mVariants.clear();
+        mVariants.addAll(variants);
+    }
+
+    void setTransitions(@NonNull List<Transition> transitions) {
+        mTransitions.clear();
+        mTransitions.addAll(transitions);
+    }
+
+    @Override
+    @NonNull
+    public String toString() {
+        return "PanelState{"
+                + "mId='" + mId + '\''
+                + ", mRole=" + mRole
+                + ", mDefaultVariant='" + mDefaultVariant + '\''
+                + ", mDisplayId=" + mDisplayId
+                + ", mVariants=" + mVariants.stream()
+                    .map(Variant::toString)
+                    .collect(Collectors.joining(", ", "[", "]"))
+                + ", mTransitions=" + mTransitions.stream()
+                    .map(Transition::toString)
+                    .collect(Collectors.joining(", ", "[", "]"))
+                + ", mRunningAnimator=" + mRunningAnimator
+                + ", mCurrentVariant="
+                + (mCurrentVariant != null ? mCurrentVariant.getId() : "null")
+                + '}';
+    }
+
+    /** Builder for {@link PanelState} objects. */
+    public static class Builder {
+        private String mId;
+        private Role mRole;
+        private String mDefaultVariant;
+        private Integer mDisplayId;
+        private List<Variant> mVariants = new ArrayList<>();
+        private List<Transition> mTransitions = new ArrayList<>();
+
+        public Builder(@NonNull String id, @NonNull Role role) {
+            mId = id;
+            mRole = role;
+        }
+
+        /** Sets default variant */
+        public Builder setDefaultVariant(@Nullable String defaultVariant) {
+            mDefaultVariant = defaultVariant;
+            return this;
+        }
+
+        /** Sets display id */
+        public Builder setDisplayId(int displayId) {
+            mDisplayId = displayId;
+            return this;
+        }
+
+        /** Adds a variant */
+        public Builder addVariant(@NonNull Variant variant) {
+            mVariants.add(variant);
+            return this;
+        }
+
+        /** Adds a transitions */
+        public Builder addTransition(@NonNull Transition transition) {
+            mTransitions.add(transition);
+            return this;
+        }
+
+        /** Sets variants */
+        public Builder setVariants(@NonNull List<Variant> variants) {
+            mVariants = new ArrayList<>(variants); // Defensive copy
+            return this;
+        }
+
+        /** Sets transitions */
+        public Builder setTransitions(@NonNull List<Transition> transitions) {
+            mTransitions = new ArrayList<>(transitions); // Defensive copy
+            return this;
+        }
+
+        /** Returns the {@link PanelState} instance */
+        @NonNull
+        public PanelState build() {
+            PanelState panelState = new PanelState(mId, mRole);
+            panelState.setDefaultVariant(mDefaultVariant);
+            if (mDisplayId != null) {
+                panelState.setDisplayId(mDisplayId);
             }
+            panelState.setVariants(mVariants);
+            panelState.setTransitions(mTransitions);
+            return panelState;
         }
-        return result;
     }
 }
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/PanelTransaction.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/PanelTransaction.java
new file mode 100644
index 0000000..94e3f4f
--- /dev/null
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/PanelTransaction.java
@@ -0,0 +1,199 @@
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
+package com.android.car.scalableui.model;
+
+import android.animation.Animator;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import java.util.HashMap;
+import java.util.Map;
+import java.util.Set;
+
+/** Represents a set of transactions to be applied to panels. */
+public class PanelTransaction {
+
+    /** A map of panel IDs to panel {@link Transition}s. */
+    private final HashMap<String, Transition> mTransactionMap;
+
+    /** A map of panel IDs to panel {@link Animator}s. */
+    private final HashMap<String, Animator> mAnimatorMap;
+
+    private Runnable mAnimationStartCallbackRunnable;
+    private Runnable mAnimationEndCallbackRunnable;
+
+    public PanelTransaction() {
+        mTransactionMap = new HashMap<>();
+        mAnimatorMap = new HashMap<>();
+    }
+
+    /**
+     * Adds a {@link Transition} for the panel with the specified ID.
+     *
+     * @param id         The ID of the panel.
+     * @param transition The transition to apply to the panel.
+     */
+    void addPanelTransaction(@NonNull String id, @NonNull Transition transition) {
+        mTransactionMap.put(id, transition);
+    }
+
+    /** Returns a set of entries representing the transactions in this object. */
+    @NonNull
+    public Set<Map.Entry<String, Transition>> getPanelTransactionStates() {
+        return mTransactionMap.entrySet();
+    }
+
+    /**
+     * Adds a {@link Animator} for the panel with the specified ID.
+     *
+     * @param id       The ID of the panel.
+     * @param animator The animator to apply to the panel.
+     */
+    void addAnimator(@NonNull String id, @Nullable Animator animator) {
+        mAnimatorMap.put(id, animator);
+    }
+
+    /** Returns a set of entries representing the Animation for given panel. */
+    @NonNull
+    public Set<Map.Entry<String, Animator>> getAnimators() {
+        return mAnimatorMap.entrySet();
+    }
+
+    /**
+     * Adds a {@link Runnable} to be executed when the animations are starting for this
+     * transaction.
+     */
+    void setAnimationStartCallbackRunnable(@NonNull Runnable runnable) {
+        mAnimationStartCallbackRunnable = runnable;
+    }
+
+    /**
+     * Adds a {@link Runnable} to be executed when the animations have finished for this
+     * transaction.
+     */
+    void setAnimationEndCallbackRunnable(@NonNull Runnable runnable) {
+        mAnimationEndCallbackRunnable = runnable;
+    }
+
+    /**
+     * Get the {@link Runnable} to be executed when the animations are starting for this
+     * transaction.
+     */
+    @Nullable
+    public Runnable getAnimationStartCallbackRunnable() {
+        return mAnimationStartCallbackRunnable;
+    }
+
+    /**
+     * Get the {@link Runnable} to be executed when the animations have finished for this
+     * transaction.
+     */
+    @Nullable
+    public Runnable getAnimationEndCallbackRunnable() {
+        return mAnimationEndCallbackRunnable;
+    }
+
+
+    /**
+     * Retrieves the {@link Transition} state associated with the given panel ID.
+     *
+     * @param id The ID of the panel.
+     */
+    @Nullable
+    public Transition getPanelTransactionState(@NonNull String id) {
+        return mTransactionMap.get(id);
+    }
+
+    /** Builder for {@link PanelTransaction}. */
+    public static class Builder {
+        private final PanelTransaction mPanelTransaction;
+
+        public Builder() {
+            mPanelTransaction = new PanelTransaction();
+        }
+
+        /**
+         * Adds a {@link Transition} for the panel with the specified ID.
+         *
+         * @param id         The ID of the panel.
+         * @param transition The transition to apply to the panel.
+         * @return The builder instance.
+         */
+        @NonNull
+        public Builder addPanelTransaction(@NonNull String id, @NonNull Transition transition) {
+            mPanelTransaction.addPanelTransaction(id, transition);
+            return this;
+        }
+
+        /**
+         * Adds a {@link Animator} for the panel with the specified ID.
+         *
+         * @param id       The ID of the panel.
+         * @param animator The animator to apply to the panel.
+         * @return The builder instance.
+         */
+        @NonNull
+        public Builder addAnimator(@NonNull String id, @Nullable Animator animator) {
+            mPanelTransaction.addAnimator(id, animator);
+            return this;
+        }
+
+        /**
+         * Adds a {@link Runnable} to be executed when the animations are starting for this
+         * transaction.
+         */
+        @NonNull
+        public Builder setAnimationStartCallbackRunnable(@NonNull Runnable runnable) {
+            mPanelTransaction.setAnimationStartCallbackRunnable(runnable);
+            return this;
+        }
+
+        /**
+         * Adds a {@link Runnable} to be executed when the animations have finished for this
+         * transaction.
+         */
+        @NonNull
+        public Builder setAnimationEndCallbackRunnable(@NonNull Runnable runnable) {
+            mPanelTransaction.setAnimationEndCallbackRunnable(runnable);
+            return this;
+        }
+
+        /**
+         * Builds the {@link PanelTransaction} object.
+         *
+         * @return The built {@link PanelTransaction} object.
+         */
+        @NonNull
+        public PanelTransaction build() {
+            return mPanelTransaction;
+        }
+    }
+
+    @Override
+    public String toString() {
+        StringBuilder sb = new StringBuilder("[ PanelTransaction:");
+        for (Map.Entry<String, Transition> entry : mTransactionMap.entrySet()) {
+            sb.append(" Transition: ").append(entry.getKey()).append("=").append(
+                    entry.getValue()).append(", ");
+        }
+        for (Map.Entry<String, Animator> entry : mAnimatorMap.entrySet()) {
+            sb.append(" Animator: ").append(entry.getKey()).append("=").append(
+                    entry.getValue()).append(", ");
+        }
+        return sb.append("]").toString();
+    }
+}
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Role.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Role.java
index c2d4ef7..a78382a 100644
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Role.java
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Role.java
@@ -19,8 +19,8 @@ package com.android.car.scalableui.model;
 /**
  * Represents the role of a {@code Panel} within the system.
  *
- * <p>This class encapsulates an integer value that signifies the role of a UI element.
- * The specific meaning of the role value is determined by the system using it.
+ * <p>This class encapsulates an integer value that signifies the role of a UI element. The
+ * specific meaning of the role value is determined by the system using it.
  */
 public class Role {
     private final int mValue;
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Transition.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Transition.java
index d8dd997..91e656d 100644
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Transition.java
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Transition.java
@@ -17,22 +17,14 @@
 package com.android.car.scalableui.model;
 
 import android.animation.Animator;
-import android.animation.AnimatorInflater;
-import android.content.Context;
-import android.util.AttributeSet;
-import android.util.Xml;
 import android.view.animation.AccelerateDecelerateInterpolator;
 import android.view.animation.Interpolator;
 
 import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
 
 import com.android.car.scalableui.panel.Panel;
 
-import org.xmlpull.v1.XmlPullParser;
-import org.xmlpull.v1.XmlPullParserException;
-
-import java.io.IOException;
-
 /**
  * Represents a transition between two {@link Variant}s in the Scalable UI system.
  *
@@ -41,23 +33,17 @@ import java.io.IOException;
  * variant, an event trigger, and a custom animator.
  */
 public class Transition {
-    public static final String TRANSITION_TAG = "Transition";
-    private static final String FROM_VARIANT_ATTRIBUTE = "fromVariant";
-    private static final String TO_VARIANT_ATTRIBUTE = "toVariant";
-    private static final String ON_EVENT_ATTRIBUTE = "onEvent";
-    private static final String ANIMATOR_ATTRIBUTE = "animator";
-    private static final long DEFAULT_DURATION = 300;
-
-    private final Variant mFromVariant;
-    @NonNull
-    private final Variant mToVariant;
-    private final String mOnEvent;
-    private final Animator mAnimator;
-    private final Interpolator mDefaultInterpolator;
+    public static final long DEFAULT_DURATION = 300;
+
+    @Nullable private final Variant mFromVariant;
+    @NonNull private final Variant mToVariant;
+    @Nullable private final Event mOnEvent;
+    @Nullable private final Animator mAnimator;
+    @NonNull private final Interpolator mDefaultInterpolator;
     private final long mDefaultDuration;
 
     /**
-     * Constructor for Transition.
+     * Constructor for Transition. Package-private; use the Builder.
      *
      * @param fromVariant The variant to transition from (can be null).
      * @param toVariant The variant to transition to.
@@ -66,16 +52,22 @@ public class Transition {
      * @param defaultDuration The default duration of the transition.
      * @param defaultInterpolator The default interpolator to use for the transition.
      */
-    public Transition(Variant fromVariant, @NonNull Variant toVariant, String onEvent,
-            Animator animator, long defaultDuration, Interpolator defaultInterpolator) {
+    Transition(
+            @Nullable Variant fromVariant,
+            @NonNull Variant toVariant,
+            @Nullable Event onEvent,
+            @Nullable Animator animator,
+            long defaultDuration,
+            @Nullable Interpolator defaultInterpolator) {
         mFromVariant = fromVariant;
         mToVariant = toVariant;
         mAnimator = animator;
         mOnEvent = onEvent;
         mDefaultDuration = defaultDuration >= 0 ? defaultDuration : DEFAULT_DURATION;
-        mDefaultInterpolator = defaultInterpolator != null
-                ? defaultInterpolator
-                : new AccelerateDecelerateInterpolator();
+        mDefaultInterpolator =
+                defaultInterpolator != null
+                        ? defaultInterpolator
+                        : new AccelerateDecelerateInterpolator();
     }
 
     /**
@@ -83,6 +75,7 @@ public class Transition {
      *
      * @return The "from" variant, or null if not specified.
      */
+    @Nullable
     public Variant getFromVariant() {
         return mFromVariant;
     }
@@ -92,7 +85,8 @@ public class Transition {
      *
      * @return The "to" variant.
      */
-    public @NonNull Variant getToVariant() {
+    @NonNull
+    public Variant getToVariant() {
         return mToVariant;
     }
 
@@ -107,7 +101,8 @@ public class Transition {
      * @param fromVariant The actual "from" variant of the transition.
      * @return The animator for the transition.
      */
-    public Animator getAnimator(Panel panel, @NonNull Variant fromVariant) {
+    @Nullable
+    public Animator getAnimator(@NonNull Panel panel, @NonNull Variant fromVariant) {
         if (fromVariant.getId().equals(mToVariant.getId())) {
             return null;
         }
@@ -117,7 +112,8 @@ public class Transition {
             animator.setTarget(panel);
             return animator;
         }
-        return fromVariant.getAnimator(panel, mToVariant, mDefaultDuration, mDefaultInterpolator);
+        return fromVariant.getAnimator(
+                panel, mToVariant, mDefaultDuration, mDefaultInterpolator);
     }
 
     /**
@@ -125,41 +121,90 @@ public class Transition {
      *
      * @return The event that triggers the transition.
      */
-    public String getOnEvent() {
+    @Nullable
+    public Event getOnEvent() {
         return mOnEvent;
     }
 
-    /**
-     * Creates a Transition object from an XML parser.
-     *
-     * @param context The context to use.
-     * @param panelState The panel state that this transition belongs to.
-     * @param defaultDuration The default duration to use if not specified in the XML.
-     * @param defaultInterpolator The default interpolator to use if not specified in the XML.
-     * @param parser The XML parser.
-     * @return The created Transition object.
-     * @throws XmlPullParserException If an error occurs during XML parsing.
-     * @throws IOException If an I/O error occurs while reading the XML.
-     */
-    public static Transition create(Context context, PanelState panelState, long defaultDuration,
-                                    Interpolator defaultInterpolator, XmlPullParser parser)
-            throws XmlPullParserException, IOException {
-        parser.require(XmlPullParser.START_TAG, null, TRANSITION_TAG);
-        AttributeSet attrs = Xml.asAttributeSet(parser);
-
-        String from = attrs.getAttributeValue(null, FROM_VARIANT_ATTRIBUTE);
-        String to = attrs.getAttributeValue(null, TO_VARIANT_ATTRIBUTE);
-        String onEvent = attrs.getAttributeValue(null, ON_EVENT_ATTRIBUTE);
-        int animatorId = attrs.getAttributeResourceValue(null, ANIMATOR_ATTRIBUTE, 0);
-        Animator animator = animatorId == 0
-                ? null
-                : AnimatorInflater.loadAnimator(context, animatorId);
-        Variant fromVariant = panelState.getVariant(from);
-        Variant toVariant = panelState.getVariant(to);
-        Transition result = new Transition(fromVariant, toVariant, onEvent, animator,
-                defaultDuration, defaultInterpolator);
-        parser.nextTag();
-        parser.require(XmlPullParser.END_TAG, null, TRANSITION_TAG);
-        return result;
+    @Override
+    @NonNull
+    public String toString() {
+        return "Transition{"
+                + "mFromVariant=" + (mFromVariant != null ? mFromVariant : "null")
+                + ", mToVariant=" + (mToVariant != null ? mToVariant : "null")
+                + ", mOnEvent=" + mOnEvent
+                + ", mAnimator=" + mAnimator
+                + ", mDefaultInterpolator=" + mDefaultInterpolator
+                + ", mDefaultDuration=" + mDefaultDuration
+                + '}';
+    }
+
+    /** Builder for {@link Transition} objects. */
+    public static class Builder {
+        @Nullable private Variant mFromVariant; // Now nullable
+        @NonNull private Variant mToVariant;
+        @Nullable private Event mOnEvent;
+        @Nullable private Animator mAnimator;
+        @Nullable private Interpolator mDefaultInterpolator;
+        @Nullable private Long mDefaultDuration; // Use boxed type Long
+
+        public Builder(@Nullable Variant fromVariant, @NonNull Variant toVariant) {
+            mFromVariant = fromVariant;
+            mToVariant = toVariant;
+        }
+
+        /** Sets from variant */
+        public Builder setFromVariant(@Nullable Variant fromVariant) {
+            mFromVariant = fromVariant; // Accept null
+            return this;
+        }
+
+        /** Sets to variant */
+        public Builder setToVariant(@NonNull Variant toVariant) {
+            mToVariant = toVariant;
+            return this;
+        }
+
+        /** Sets onEvent */
+        public Builder setOnEvent(@Nullable String eventId, @Nullable String eventTokens) {
+            if (eventId == null) {
+                mOnEvent = null;
+            } else {
+                mOnEvent = new Event.Builder(eventId)
+                        .addTokensFromString(eventTokens)
+                        .build();
+            }
+            return this;
+        }
+
+        /** Sets animator */
+        public Builder setAnimator(@Nullable Animator animator) {
+            mAnimator = animator;
+            return this;
+        }
+
+        /** Sets default duration */
+        public Builder setDefaultDuration(long duration) {
+            mDefaultDuration = duration;
+            return this;
+        }
+
+        /** Sets default interpolator */
+        public Builder setDefaultInterpolator(@Nullable Interpolator interpolator) {
+            mDefaultInterpolator = interpolator;
+            return this;
+        }
+
+        /** Returns the {@link Transition} instance */
+        @NonNull
+        public Transition build() {
+            return new Transition(
+                    mFromVariant,
+                    mToVariant,
+                    mOnEvent,
+                    mAnimator,
+                    mDefaultDuration != null ? mDefaultDuration : DEFAULT_DURATION,
+                    mDefaultInterpolator);
+        }
     }
 }
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Variant.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Variant.java
index ba2e1b5..ed0f0e3 100644
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Variant.java
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Variant.java
@@ -13,68 +13,82 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 package com.android.car.scalableui.model;
 
 import android.animation.Animator;
 import android.animation.FloatEvaluator;
+import android.animation.IntEvaluator;
 import android.animation.RectEvaluator;
 import android.animation.ValueAnimator;
-import android.content.Context;
+import android.graphics.Insets;
 import android.graphics.Rect;
-import android.util.AttributeSet;
-import android.util.Xml;
+import android.os.Build;
+import android.util.Log;
 import android.view.animation.Interpolator;
 
-import com.android.car.scalableui.panel.Panel;
-
-import org.xmlpull.v1.XmlPullParser;
-import org.xmlpull.v1.XmlPullParserException;
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
 
-import java.io.IOException;
+import com.android.car.scalableui.panel.Panel;
 
 /**
  * Represents a specific visual state or variant of a {@code Panel}.
  *
- * <p>This class defines the visual properties of a {@code Panel}, such as its bounds,
- * visibility, layer, and alpha. It also provides methods for creating animations
- * to transition between different variants.
+ * <p>This class defines the visual properties of a {@code Panel}, such as its bounds, visibility,
+ * layer, and alpha. It also provides methods for creating animations to transition between
+ * different variants.
  */
 public class Variant {
-    static final String VARIANT_TAG = "Variant";
-    private static final String ID_ATTRIBUTE = "id";
-    private static final String PARENT_ATTRIBUTE = "parent";
+    private static final String TAG = Variant.class.getSimpleName();
+    private static final boolean DEBUG = Build.IS_DEBUGGABLE;
 
     private final FloatEvaluator mFloatEvaluator = new FloatEvaluator();
     private final RectEvaluator mRectEvaluator = new RectEvaluator();
+    private final IntEvaluator mIntEvaluator = new IntEvaluator();
 
-    private final String mId;
+    @NonNull protected final String mId;
     private float mAlpha;
     private boolean mIsVisible;
     private int mLayer;
-    private Rect mBounds;
+    private int mCornerRadius;
+    @NonNull private Rect mBounds;
+    @NonNull private Insets mInsets;
+
+    /**
+     * Constructs a Variant object with the specified ID. This constructor is package-private and is
+     * intended to be used by the VariantBuilder.
+     *
+     * @param id The ID of the variant.
+     */
+    Variant(@NonNull String id) {
+        this.mId = id;
+
+        // Initialize with default values
+        mBounds = new Rect();
+        mIsVisible = Visibility.DEFAULT_VISIBILITY;
+        mLayer = Layer.DEFAULT_LAYER;
+        mAlpha = Alpha.DEFAULT_ALPHA;
+        mCornerRadius = Corner.DEFAULT_RADIUS;
+        mInsets = Insets.NONE;
+    }
 
     /**
-     * Constructs a Variant object with the specified ID and optional base variant.
+     * Constructs a Variant object with the specified ID and base variant. Package private
+     * constructor, designed to be invoked by the builder.
      *
      * <p>If a base variant is provided, the new variant inherits its visual properties.
      *
      * @param id The ID of the variant.
      * @param base The optional base variant to inherit properties from.
      */
-    public Variant(String id, Variant base) {
-        this.mId = id;
-        if (base != null) {
-            mBounds = base.getBounds();
-            mIsVisible = base.isVisible();
-            mLayer = base.getLayer();
-            mAlpha = base.getAlpha();
-        } else {
-            mBounds = new Rect();
-            mIsVisible = Visibility.DEFAULT_VISIBILITY;
-            mLayer = Layer.DEFAULT_LAYER;
-            mAlpha = Alpha.DEFAULT_ALPHA;
-        }
+    Variant(@NonNull String id, @NonNull Variant base) {
+        this(id);
+        mBounds = new Rect(base.getBounds());
+        mIsVisible = base.isVisible();
+        mLayer = base.getLayer();
+        mAlpha = base.getAlpha();
+        mCornerRadius = base.getCornerRadius();
+        mInsets = base.getInsets();
     }
 
     /**
@@ -82,6 +96,7 @@ public class Variant {
      *
      * @return The ID of the variant.
      */
+    @NonNull
     public String getId() {
         return mId;
     }
@@ -95,29 +110,47 @@ public class Variant {
      * @param interpolator The interpolator to use for the animation.
      * @return An animator that animates the panel's properties to the target variant.
      */
-    public Animator getAnimator(Panel panel, Variant toVariant, long duration,
-            Interpolator interpolator) {
+    @Nullable
+    public Animator getAnimator(
+            @NonNull Panel panel,
+            @NonNull Variant toVariant,
+            long duration,
+            @Nullable Interpolator interpolator) {
         if (toVariant instanceof KeyFrameVariant) {
             return null;
         } else {
             float fromAlpha = panel.getAlpha();
             float toAlpha = toVariant.getAlpha();
-            Rect fromBounds = panel.getBounds();
-            Rect toBounds = toVariant.getBounds();
+            int fromCornerRadius = panel.getCornerRadius();
+            int toCornerRadius = toVariant.getCornerRadius();
+            Rect fromBounds = new Rect(panel.getBounds());
+            Rect toBounds = new Rect(toVariant.getBounds());
             boolean isVisible = panel.isVisible() || toVariant.isVisible();
             int layer = toVariant.getLayer();
+            Rect fromInsets = panel.getInsets().toRect();
+            Rect toInsets = toVariant.getInsets().toRect();
             ValueAnimator valueAnimator = ValueAnimator.ofFloat(0, 1);
             valueAnimator.setDuration(duration);
             valueAnimator.setInterpolator(interpolator);
-            valueAnimator.addUpdateListener(animator -> {
-                panel.setVisibility(isVisible);
-                panel.setLayer(layer);
-                float fraction = animator.getAnimatedFraction();
-                Rect bounds = mRectEvaluator.evaluate(fraction, fromBounds, toBounds);
-                panel.setBounds(bounds);
-                float alpha = mFloatEvaluator.evaluate(fraction, fromAlpha, toAlpha);
-                panel.setAlpha(alpha);
-            });
+            valueAnimator.addUpdateListener(
+                    animator -> {
+                        panel.setVisibility(isVisible);
+                        panel.setLayer(layer);
+                        float fraction = animator.getAnimatedFraction();
+                        Rect bounds = mRectEvaluator.evaluate(fraction, fromBounds, toBounds);
+                        panel.setBounds(bounds);
+                        float alpha = mFloatEvaluator.evaluate(fraction, fromAlpha, toAlpha);
+                        panel.setAlpha(alpha);
+                        int radius = mIntEvaluator.evaluate(fraction, fromCornerRadius,
+                                toCornerRadius);
+                        panel.setCornerRadius(radius);
+                        Rect insets = mRectEvaluator.evaluate(fraction, fromInsets,
+                                toInsets);
+                        panel.setInsets(Insets.of(insets));
+                        if (DEBUG) {
+                            Log.d(TAG, "Panel updated: " + panel);
+                        }
+                    });
             return valueAnimator;
         }
     }
@@ -136,7 +169,7 @@ public class Variant {
      *
      * @param isVisible True if the variant should be visible, false otherwise.
      */
-    public void setVisibility(boolean isVisible) {
+    protected void setVisibility(boolean isVisible) {
         this.mIsVisible = isVisible;
     }
 
@@ -149,6 +182,15 @@ public class Variant {
         return mLayer;
     }
 
+    /**
+     * Sets the layer of the variant.
+     *
+     * @param layer The layer value to set.
+     */
+    protected void setLayer(int layer) {
+        mLayer = layer;
+    }
+
     /**
      * Returns the alpha of the variant.
      *
@@ -163,24 +205,16 @@ public class Variant {
      *
      * @param alpha The alpha value to set.
      */
-    public void setAlpha(float alpha) {
+    protected void setAlpha(float alpha) {
         mAlpha = alpha;
     }
 
-    /**
-     * Sets the layer of the variant.
-     *
-     * @param layer The layer value to set.
-     */
-    public void setLayer(int layer) {
-        mLayer = layer;
-    }
-
     /**
      * Returns the bounds of the variant.
      *
      * @return The bounds of the variant.
      */
+    @NonNull
     public Rect getBounds() {
         return mBounds;
     }
@@ -190,52 +224,163 @@ public class Variant {
      *
      * @param bounds The bounds to set.
      */
-    public void setBounds(Rect bounds) {
+    protected void setBounds(@NonNull Rect bounds) {
         mBounds = bounds;
     }
 
     /**
-     * Creates a Variant object from an XML parser.
-     *
-     * <p>This method parses an XML element with the tag "Variant" and extracts its attributes
-     * and child elements to create a Variant object.
-     *
-     * @param context The application context.
-     * @param panelState The panel data associated with this variant.
-     * @param parser The XML parser.
-     * @return A Variant object with the parsed properties.
-     * @throws XmlPullParserException If an error occurs during XML parsing.
-     * @throws IOException If an I/O error occurs while reading the XML.
-     */
-    static Variant create(Context context, PanelState panelState, XmlPullParser parser) throws
-            XmlPullParserException, IOException {
-        parser.require(XmlPullParser.START_TAG, null, VARIANT_TAG);
-        AttributeSet attrs = Xml.asAttributeSet(parser);
-        String id = attrs.getAttributeValue(null, ID_ATTRIBUTE);
-        String parentStr = attrs.getAttributeValue(null, PARENT_ATTRIBUTE);
-        Variant parent = panelState.getVariant(parentStr);
-        Variant result = new Variant(id, parent);
-        while (parser.next() != XmlPullParser.END_TAG) {
-            if (parser.getEventType() != XmlPullParser.START_TAG) continue;
-            String name = parser.getName();
-            switch (name) {
-                case Visibility.VISIBILITY_TAG:
-                    result.setVisibility(Visibility.create(parser).isVisible());
-                    break;
-                case Alpha.ALPHA_TAG:
-                    result.setAlpha(Alpha.create(parser).getAlpha());
-                    break;
-                case Layer.LAYER_TAG:
-                    result.setLayer(Layer.create(parser).getLayer());
-                    break;
-                case Bounds.BOUNDS_TAG:
-                    result.setBounds(Bounds.create(context, parser).getRect());
-                    break;
-                default:
-                    XmlPullParserHelper.skip(parser);
-                    break;
+     * Returns the corner radius of the variant.
+     *
+     * @return The corner radius of the variant.
+     */
+    public int getCornerRadius() {
+        return mCornerRadius;
+    }
+
+    /**
+     * Sets the corner radius of the variant.
+     *
+     * @param radius The corner radius to set.
+     */
+    protected void setCornerRadius(int radius) {
+        mCornerRadius = radius;
+    }
+
+    /**
+     * Update the variant with data from an event.
+     *
+     * @param event the event that was executed.
+     */
+    protected void updateFromEvent(@Nullable Event event) {
+        // no-op
+    }
+
+    /**
+     * @return {@link Insets}.
+     */
+    @Nullable
+    public Insets getInsets() {
+        return mInsets;
+    }
+
+    /**
+     * Sets insets.
+     * This is essentially the panle's safe rectangle.
+     */
+    protected void setInsets(@NonNull Insets insets) {
+        mInsets = insets;
+    }
+
+    @Override
+    @NonNull
+    public String toString() {
+        return "Variant{"
+                + "mId='"
+                + mId
+                + '\''
+                + ", mAlpha="
+                + mAlpha
+                + ", mIsVisible="
+                + mIsVisible
+                + ", mLayer="
+                + mLayer
+                + ", mBounds="
+                + mBounds
+                + ", mCornerRadius="
+                + mCornerRadius
+                + ", mInsets="
+                + mInsets
+                + '}';
+    }
+
+    /** Builder for {@link Variant} objects. */
+    public static class Builder {
+        @NonNull protected String mId;
+        @Nullable protected Float mAlpha;
+        @Nullable protected Boolean mIsVisible;
+        @Nullable protected Integer mLayer;
+        @Nullable protected Rect mBounds;
+        @Nullable protected Integer mCornerRadius;
+        @Nullable protected Insets mInsets;
+        @Nullable protected Variant mParent;
+
+        public Builder(@NonNull String id) {
+            mId = id;
+        }
+
+        /** Sets alpha */
+        public Builder setAlpha(@Nullable Float alpha) {
+            mAlpha = alpha;
+            return this;
+        }
+
+        /** Sets visibility */
+        public Builder setVisibility(@Nullable Boolean isVisible) {
+            mIsVisible = isVisible;
+            return this;
+        }
+
+        /** Sets layer */
+        public Builder setLayer(@Nullable Integer layer) {
+            mLayer = layer;
+            return this;
+        }
+
+        /** Sets bounds */
+        public Builder setBounds(@NonNull Rect bounds) {
+            mBounds = bounds;
+            return this;
+        }
+
+        /** Sets corner radius */
+        public Builder setCornerRadius(@NonNull Integer cornerRadius) {
+            mCornerRadius = cornerRadius;
+            return this;
+        }
+
+        /** Sets insets */
+        public Builder setInsets(@NonNull Insets insets) {
+            mInsets = insets;
+            return this;
+        }
+
+        /** Sets parent */
+        public Builder setParent(@Nullable Variant parent) {
+            mParent = parent;
+            return this;
+        }
+
+        /** Returns the {@link Variant} instance */
+        @NonNull
+        public Variant build() {
+            Variant variant;
+            if (mParent != null) {
+                variant = new Variant(mId, mParent);
+            } else {
+                variant = new Variant(mId);
+            }
+
+            if (mAlpha != null) {
+                variant.setAlpha(mAlpha);
+            }
+            if (mIsVisible != null) {
+                variant.setVisibility(mIsVisible);
             }
+            if (mLayer != null) {
+                variant.setLayer(mLayer);
+            }
+            if (mBounds != null) {
+                variant.setBounds(new Rect(mBounds)); // Defensive copy
+            }
+            if (mCornerRadius != null) {
+                variant.setCornerRadius(mCornerRadius);
+            }
+            if (mInsets != null) {
+                variant.setInsets(
+                        Insets.of(mInsets.left, mInsets.top, mInsets.right, mInsets.bottom));
+            }
+
+            return variant;
         }
-        return result;
     }
 }
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Visibility.java b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Visibility.java
index 06ac811..673cf2e 100644
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/model/Visibility.java
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/model/Visibility.java
@@ -16,43 +16,31 @@
 
 package com.android.car.scalableui.model;
 
-import android.util.AttributeSet;
-import android.util.Xml;
-
-import org.xmlpull.v1.XmlPullParser;
-import org.xmlpull.v1.XmlPullParserException;
-
-import java.io.IOException;
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
 
 /**
  * Represents the visibility of a Panel in the Scalable UI system.
  *
- * <p>This class encapsulates a boolean value indicating whether a panel is visible or not.
- * It can be created from an XML definition or directly using a boolean value.
+ * <p>This class encapsulates a boolean value indicating whether a panel is visible or not. It can
+ * be created from an XML definition or directly using a boolean value.
  */
 public class Visibility {
-    static final String VISIBILITY_TAG = "Visibility";
-    private static final String IS_VISIBLE_ATTRIBUTE = "isVisible";
-    static final boolean DEFAULT_VISIBILITY = true;
+    public static final boolean DEFAULT_VISIBILITY = true;
 
     private final boolean mIsVisible;
 
     /**
-     * Constructor for Visibility.
+     * Constructor for Visibility. Package-private; use the Builder.
      *
      * @param isVisible Whether the element is visible.
      */
-    public Visibility(boolean isVisible) {
+    Visibility(boolean isVisible) {
         this.mIsVisible = isVisible;
     }
 
-    /**
-     * Copy constructor for Visibility.
-     *
-     * @param visibility The Visibility object to copy from.
-     */
-    public Visibility(Visibility visibility) {
-        this(visibility.mIsVisible);
+    public Visibility(Visibility original) {
+        this.mIsVisible = original.isVisible();
     }
 
     /**
@@ -64,22 +52,24 @@ public class Visibility {
         return mIsVisible;
     }
 
-    /**
-     * Creates a Visibility object from an XML parser.
-     *
-     * @param parser The XML parser.
-     * @return The created Visibility object.
-     * @throws XmlPullParserException If an error occurs during XML parsing.
-     * @throws IOException If an I/O error occurs while reading the XML.
-     */
-    public static Visibility create(XmlPullParser parser) throws XmlPullParserException,
-            IOException {
-        parser.require(XmlPullParser.START_TAG, null, VISIBILITY_TAG);
-        AttributeSet attrs = Xml.asAttributeSet(parser);
-        boolean isVisible = attrs.getAttributeBooleanValue(null, IS_VISIBLE_ATTRIBUTE,
-                DEFAULT_VISIBILITY);
-        parser.nextTag();
-        parser.require(XmlPullParser.END_TAG, null, VISIBILITY_TAG);
-        return new Visibility(isVisible);
+    /** Builder for {@link Visibility} objects. */
+    public static class Builder {
+        @Nullable private Boolean mIsVisible; // Use boxed type
+
+        public Builder() {}
+
+        /** Set visibility*/
+        public Builder setIsVisible(boolean isVisible) {
+            mIsVisible = isVisible;
+            return this;
+        }
+
+        /** Returns the {@link Visibility} instance */
+        @NonNull
+        public Visibility build() {
+            // Use default if not explicitly set
+            boolean visible = (mIsVisible != null) ? mIsVisible : DEFAULT_VISIBILITY;
+            return new Visibility(visible);
+        }
     }
 }
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/panel/Panel.java b/car-scalable-ui-lib/src/com/android/car/scalableui/panel/Panel.java
index 38aace1..009389f 100644
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/panel/Panel.java
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/panel/Panel.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2024 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project.
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,11 +13,13 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 package com.android.car.scalableui.panel;
 
+import android.graphics.Insets;
 import android.graphics.Rect;
 
+import androidx.annotation.NonNull;
+
 /**
  * Represents a rectangular panel that can be displayed on the screen.
  * Panels have properties such as bounds, layer, visibility, and alpha.
@@ -144,4 +146,56 @@ public interface Panel {
      * @param role The new role of this panel.
      */
     void setRole(int role);
+
+    /**
+     * Sets the display ID of the panel.
+     * TODO(b/388021504):This api should move to role
+     */
+    void setDisplayId(int displayId);
+
+    /**
+     * Gets the display ID of the panel.
+     */
+    int getDisplayId();
+
+    /**
+     * Initializes the panel.
+     */
+    void init();
+
+    /**
+     * Reset the panel.
+     */
+    void reset();
+
+    /**
+     * Sets the radius for all four corners of this panel.
+     *
+     * @param radius The corner radius
+     */
+    void setCornerRadius(int radius);
+
+    /**
+     * Gets the radius for all four corners of this panel.
+     *
+     * @return The corner radius
+     */
+    int getCornerRadius();
+
+    /**
+     * Returns the ID of the panel.
+     */
+    @NonNull
+    String getPanelId();
+
+    /**
+     * Sets the {@link Insets}
+     */
+    void setInsets(@NonNull Insets insets);
+
+    /**
+     * @return The {@link Insets}
+     */
+    @NonNull
+    Insets getInsets();
 }
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/panel/PanelPool.java b/car-scalable-ui-lib/src/com/android/car/scalableui/panel/PanelPool.java
index aa643fe..df75e0e 100644
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/panel/PanelPool.java
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/panel/PanelPool.java
@@ -16,7 +16,10 @@
 
 package com.android.car.scalableui.panel;
 
+import androidx.annotation.Nullable;
+
 import java.util.HashMap;
+import java.util.function.Predicate;
 
 /**
  * A pool for managing {@link Panel} instances.
@@ -28,6 +31,9 @@ import java.util.HashMap;
 public class PanelPool {
     private static final PanelPool sInstance = new PanelPool();
 
+    private final HashMap<String, Panel> mPanels = new HashMap<>();
+    private PanelCreatorDelegate mDelegate;
+
     /**
      * An instance of the {@link PanelPool}.
      */
@@ -47,8 +53,6 @@ public class PanelPool {
         Panel createPanel(String id);
     }
 
-    private final HashMap<String, Panel> mPanels = new HashMap<>();
-    private PanelCreatorDelegate mDelegate;
 
     private PanelPool() {}
 
@@ -85,4 +89,18 @@ public class PanelPool {
         }
         return mPanels.get(id);
     }
+
+    /**
+     * Retrieves a panel with the given {@link Predicate}.
+     *
+     * @param predicate A predicate that defines the criteria for selecting a panel.
+     * @return The first panel matching the predicate, or null if none is found.
+     */
+    @Nullable
+    public Panel getPanel(Predicate<Panel> predicate) {
+        for (Panel panel : mPanels.values()) {
+            if (predicate.test(panel)) return panel;
+        }
+        return null;
+    }
 }
diff --git a/car-scalable-ui-lib/src/com/android/car/scalableui/panel/PanelView.java b/car-scalable-ui-lib/src/com/android/car/scalableui/panel/PanelView.java
index 6ef93ae..b81b3de 100644
--- a/car-scalable-ui-lib/src/com/android/car/scalableui/panel/PanelView.java
+++ b/car-scalable-ui-lib/src/com/android/car/scalableui/panel/PanelView.java
@@ -17,8 +17,10 @@
 package com.android.car.scalableui.panel;
 
 import android.content.Context;
+import android.graphics.Insets;
 import android.graphics.Rect;
 import android.util.AttributeSet;
+import android.view.Display;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
@@ -37,6 +39,7 @@ public class PanelView extends FrameLayout implements Panel {
 
     private int mLayer = -1;
     private int mRole = 0;
+    private String mId = "";
 
     private int mImageHolderLayoutId;
     private int mImageId;
@@ -103,18 +106,22 @@ public class PanelView extends FrameLayout implements Panel {
         }
     }
 
+    @Override
     public int getX1() {
         return getLeft();
     }
 
+    @Override
     public int getX2() {
         return getRight();
     }
 
+    @Override
     public int getY1() {
         return getTop();
     }
 
+    @Override
     public int getY2() {
         return getBottom();
     }
@@ -208,6 +215,46 @@ public class PanelView extends FrameLayout implements Panel {
         }
     }
 
+    @Override
+    public void setDisplayId(int displayId) {
+        // no-op
+    }
+
+    @Override
+    public int getDisplayId() {
+        return Display.INVALID_DISPLAY;
+    }
+
+    @Override
+    public void init() {
+        // no-op
+    }
+
+    @Override
+    public void reset() {
+        // no-op
+    }
+
+    @Override
+    public void setInsets(Insets insets) {
+        setPadding(insets.left, insets.top, insets.right, insets.bottom);
+    }
+
+    @Override
+    public Insets getInsets() {
+        return Insets.of(getPaddingLeft(), getPaddingTop(), getPaddingRight(), getPaddingBottom());
+    }
+
+    @Override
+    public void setCornerRadius(int radius) {
+        // no-op
+    }
+
+    @Override
+    public int getCornerRadius() {
+        return 0;
+    }
+
     private boolean isDrawableRole(int role) {
         String resourceTypeName = getContext().getResources().getResourceTypeName(role);
         return DRAWABLE_RESOURCE_TYPE.equals(resourceTypeName);
@@ -217,4 +264,10 @@ public class PanelView extends FrameLayout implements Panel {
         String resourceTypeName = getContext().getResources().getResourceTypeName(role);
         return LAYOUT_RESOURCE_TYPE.equals(resourceTypeName);
     }
+
+    @Override
+    @NonNull
+    public String getPanelId() {
+        return mId;
+    }
 }
diff --git a/car-scalable-ui-lib/test/unit/Android.bp b/car-scalable-ui-lib/test/unit/Android.bp
new file mode 100644
index 0000000..70e9c8f
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/Android.bp
@@ -0,0 +1,51 @@
+//
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
+package {
+    default_team: "trendy_team_system_experience",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_test {
+    name: "CarScalableUIUnitTests",
+
+    certificate: "platform",
+    privileged: true,
+    resource_dirs: ["res"],
+    srcs: ["src/**/*.java"],
+
+    libs: [
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
+    ],
+
+    static_libs: [
+        "car-scalable-ui-lib",
+        "androidx.test.core",
+        "androidx.test.rules",
+        "androidx.test.ext.junit",
+        "androidx.test.ext.truth",
+        "mockito-target-extended-minus-junit4",
+        "platform-test-annotations",
+        "truth",
+        "testng",
+    ],
+
+    jni_libs: [
+        "libdexmakerjvmtiagent",
+        "libstaticjvmtiagent",
+    ],
+}
diff --git a/car-scalable-ui-lib/test/unit/AndroidManifest.xml b/car-scalable-ui-lib/test/unit/AndroidManifest.xml
new file mode 100644
index 0000000..f7fe6c2
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/AndroidManifest.xml
@@ -0,0 +1,29 @@
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
+
+<manifest
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.car.scalableui.unit">
+
+    <application android:debuggable="true">
+        <uses-library android:name="android.test.runner" />
+    </application>
+
+    <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
+                     android:targetPackage="com.android.car.scalableui.unit"
+                     android:label="Scalable UI Library Unit Tests"/>
+</manifest>
diff --git a/car-scalable-ui-lib/test/unit/res/values/strings.xml b/car-scalable-ui-lib/test/unit/res/values/strings.xml
new file mode 100644
index 0000000..01921b2
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/res/values/strings.xml
@@ -0,0 +1,18 @@
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
+<resources>
+    <string name="default_config">DEFAULT</string>
+</resources>
\ No newline at end of file
diff --git a/car-scalable-ui-lib/test/unit/res/values/values.xml b/car-scalable-ui-lib/test/unit/res/values/values.xml
new file mode 100644
index 0000000..9febe4e
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/res/values/values.xml
@@ -0,0 +1,19 @@
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
+<resources>
+  <integer name="app_grid_panel_layer">100</integer>
+  <item name="app_grid_panel_alpha" type="integer" format="float">0.8</item>
+</resources>
\ No newline at end of file
diff --git a/car-scalable-ui-lib/test/unit/res/xml/panel_test.xml b/car-scalable-ui-lib/test/unit/res/xml/panel_test.xml
new file mode 100644
index 0000000..9586fea
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/res/xml/panel_test.xml
@@ -0,0 +1,40 @@
+<?xml version="1.0" encoding="UTF-8"?>
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
+<Panel id="panel_id" defaultVariant="variant1" role="@string/default_config">
+    <Variant id="base">
+        <Layer layer="2"/>
+    </Variant>
+    <Variant id="variant1" parent="base">
+        <Visibility isVisible="true"/>
+        <Alpha alpha="0.8" />
+        <Bounds left="0" top="10" width="20" height="30" />
+        <Corner radius="10dp" />
+    </Variant>
+
+    <Variant id="variant2" parent="base">
+        <Visibility isVisible="false"/>
+        <Alpha alpha="@integer/app_grid_panel_alpha" />
+        <Bounds left="0" top="0" width="20" height="30" />
+        <Insets left="0" top="0" right="20" bottom="30" />
+        <Layer layer="@integer/app_grid_panel_layer" />
+    </Variant>
+
+    <Transitions>
+        <Transition onEvent="event1" toVariant="variant1"/>
+        <Transition onEvent="event1" toVariant="variant2"/>
+    </Transitions>
+</Panel>
diff --git a/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/manager/StateManagerTest.java b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/manager/StateManagerTest.java
new file mode 100644
index 0000000..f313d5a
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/manager/StateManagerTest.java
@@ -0,0 +1,276 @@
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
+package com.android.car.scalableui.manager;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.spy;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.animation.Animator;
+import android.animation.AnimatorListenerAdapter;
+import android.graphics.Rect;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.car.scalableui.model.Event;
+import com.android.car.scalableui.model.PanelState;
+import com.android.car.scalableui.model.PanelTransaction;
+import com.android.car.scalableui.model.Role;
+import com.android.car.scalableui.model.Transition;
+import com.android.car.scalableui.model.Variant;
+import com.android.car.scalableui.panel.Panel;
+import com.android.car.scalableui.panel.PanelPool;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+import java.util.Map;
+import java.util.Set;
+
+@RunWith(AndroidJUnit4.class)
+public class StateManagerTest {
+    private static final String TEST_PANEL_ID = "panel_id";
+    private static final String TO_VARIANT_ID = "TO_VARIANT_ID";
+    private static final Event TEST_EVENT = new Event.Builder("TEST_EVENT").build();
+
+    @Before
+    public void setUp() {
+        StateManager.clearStates();
+        StateManager.getInstance().clearPanelStateObservers();
+    }
+
+    @Test
+    public void testHandleEvent_withTransition() {
+        PanelState panelState = spy(new PanelState(TEST_PANEL_ID, new Role(0)));
+        when(panelState.getTransition(any(Event.class))).thenReturn(mock(Transition.class));
+        Variant mockVariant = mock(Variant.class);
+        when(mockVariant.getId()).thenReturn(TO_VARIANT_ID);
+        panelState.addVariant(mockVariant);
+        StateManager.getInstance().getPanelStates().put(TEST_PANEL_ID, panelState);
+
+        Panel mockPanel = mock(Panel.class);
+        PanelPool.PanelCreatorDelegate delegate = mock(PanelPool.PanelCreatorDelegate.class);
+        PanelPool.getInstance().setDelegate(delegate);
+        when(delegate.createPanel(any())).thenReturn(mockPanel);
+        Transition mockTransition = mock(Transition.class);
+        when(mockTransition.getToVariant()).thenReturn(new Variant.Builder(TO_VARIANT_ID).build());
+        when(panelState.getTransition(any(Event.class))).thenReturn(mockTransition);
+        Animator mockAnimator = mock(Animator.class);
+        when(mockTransition.getAnimator(any(Panel.class), any(Variant.class))).thenReturn(
+                mockAnimator);
+
+        PanelTransaction panelTransaction = StateManager.handleEvent(TEST_EVENT);
+
+        verify(panelState).setVariant(TO_VARIANT_ID, TEST_EVENT);
+        verify(panelState).onAnimationStart(mockAnimator);
+        verify(mockAnimator).removeAllListeners();
+        verify(mockAnimator).addListener(any(AnimatorListenerAdapter.class));
+        assertThat(panelTransaction.getAnimators()).hasSize(/* expectedSize= */ 1);
+        assertThat(panelTransaction.getPanelTransactionStates()).hasSize(/* expectedSize= */ 1);
+    }
+
+    @Test
+    public void testHandleEvent_withoutTransition() {
+        PanelState panelState = spy(new PanelState(TEST_PANEL_ID, new Role(0)));
+        when(panelState.getTransition(any(Event.class))).thenReturn(null);
+        StateManager.getInstance().getPanelStates().put(TEST_PANEL_ID, panelState);
+
+        Panel mockPanel = mock(Panel.class);
+        PanelPool.PanelCreatorDelegate delegate = mock(PanelPool.PanelCreatorDelegate.class);
+        PanelPool.getInstance().setDelegate(delegate);
+        when(delegate.createPanel(any())).thenReturn(mockPanel);
+
+        StateManager.handleEvent(TEST_EVENT);
+
+        // Verify that no state changes or animations are applied
+        verify(panelState, never()).setVariant(any(String.class), any(Event.class));
+        verify(mockPanel, never()).setBounds(any(Rect.class));
+        verify(mockPanel, never()).setVisibility(any(Boolean.class));
+        verify(mockPanel, never()).setAlpha(any(Float.class));
+        verify(mockPanel, never()).setLayer(any(Integer.class));
+    }
+
+    @Test
+    public void testHandleEvent_withTransitionWithoutAnimation() {
+        PanelState panelState = spy(new PanelState(TEST_PANEL_ID, new Role(0)));
+        when(panelState.getTransition(any(Event.class))).thenReturn(mock(Transition.class));
+        Variant mockVariant = mock(Variant.class);
+        when(mockVariant.getId()).thenReturn(TO_VARIANT_ID);
+        panelState.addVariant(mockVariant);
+        StateManager.getInstance().getPanelStates().put(TEST_PANEL_ID, panelState);
+
+        Panel mockPanel = mock(Panel.class);
+        PanelPool.PanelCreatorDelegate delegate = mock(PanelPool.PanelCreatorDelegate.class);
+        PanelPool.getInstance().setDelegate(delegate);
+        when(delegate.createPanel(any())).thenReturn(mockPanel);
+        when(PanelPool.getInstance().getPanel(anyString())).thenReturn(mockPanel);
+        Transition mockTransition = mock(Transition.class);
+        when(mockTransition.getToVariant()).thenReturn(new Variant.Builder(TO_VARIANT_ID).build());
+        when(panelState.getTransition(any(Event.class))).thenReturn(mockTransition);
+        when(mockTransition.getAnimator(any(Panel.class), any(Variant.class))).thenReturn(null);
+
+        StateManager.handleEvent(TEST_EVENT);
+
+        verify(panelState).setVariant(TO_VARIANT_ID, TEST_EVENT);
+    }
+
+    @Test
+    public void testApplyState() {
+        int roleValue = 1;
+        PanelState panelState = spy(new PanelState(TEST_PANEL_ID, new Role(roleValue)));
+        Variant mockVariant = mock(Variant.class);
+        when(mockVariant.getId()).thenReturn(TO_VARIANT_ID);
+        panelState.addVariant(mockVariant);
+        StateManager.getInstance().getPanelStates().put(TEST_PANEL_ID, panelState);
+        PanelPool.PanelCreatorDelegate delegate = mock(PanelPool.PanelCreatorDelegate.class);
+        PanelPool.getInstance().setDelegate(delegate);
+        Panel mockPanel = mock(Panel.class);
+        when(delegate.createPanel(any())).thenReturn(mockPanel);
+        when(PanelPool.getInstance().getPanel(TEST_PANEL_ID)).thenReturn(mockPanel);
+
+        StateManager.applyState(panelState);
+
+        verify(mockPanel).setRole(roleValue);
+        verify(mockPanel).setBounds(mockVariant.getBounds());
+        verify(mockPanel).setVisibility(mockVariant.isVisible());
+        verify(mockPanel).setAlpha(mockVariant.getAlpha());
+        verify(mockPanel).setLayer(mockVariant.getLayer());
+        verify(mockPanel).setDisplayId(0);
+        verify(mockPanel).setCornerRadius(mockVariant.getCornerRadius());
+    }
+
+    @Test
+    public void testHandlePanelReset() {
+        final String testPanel1 = "testPanel1";
+        final String testPanel2 = "testPanel2";
+
+        PanelState panelState1 = spy(new PanelState(testPanel1, new Role(0)));
+        PanelState panelState2 = spy(new PanelState(testPanel2, new Role(0)));
+        StateManager.getInstance().getPanelStates().put(testPanel1, panelState1);
+        StateManager.getInstance().getPanelStates().put(testPanel2, panelState2);
+
+        Panel mockPanel1 = mock(Panel.class);
+        Panel mockPanel2 = mock(Panel.class);
+        PanelPool.PanelCreatorDelegate delegate = mock(PanelPool.PanelCreatorDelegate.class);
+        PanelPool.getInstance().setDelegate(delegate);
+        when(delegate.createPanel(testPanel1)).thenReturn(mockPanel1);
+        when(delegate.createPanel(testPanel2)).thenReturn(mockPanel2);
+        when(PanelPool.getInstance().getPanel(testPanel1)).thenReturn(mockPanel1);
+        when(PanelPool.getInstance().getPanel(testPanel2)).thenReturn(mockPanel2);
+
+        StateManager.handlePanelReset();
+
+        verify(mockPanel1, times(/*wantedNumberOfInvocations=*/ 1)).reset();
+        verify(mockPanel2, times(/*wantedNumberOfInvocations=*/ 1)).reset();
+    }
+
+    @Test
+    public void testGetPanelState() {
+        PanelState panelState = spy(new PanelState(TEST_PANEL_ID, new Role(0)));
+        StateManager.getInstance().getPanelStates().put(TEST_PANEL_ID, panelState);
+
+        PanelState retrievedPanelState = StateManager.getPanelState(TEST_PANEL_ID);
+
+        assertThat(retrievedPanelState).isEqualTo(panelState);
+    }
+
+    @Test
+    public void testPanelStateListener_withAnimation() {
+        TestPanelStateObserver observer = new TestPanelStateObserver();
+        StateManager.getInstance().addPanelStateObserver(observer);
+        PanelState panelState = spy(new PanelState(TEST_PANEL_ID, new Role(0)));
+        when(panelState.getTransition(any(Event.class))).thenReturn(mock(Transition.class));
+        Variant mockVariant = mock(Variant.class);
+        when(mockVariant.getId()).thenReturn(TO_VARIANT_ID);
+        panelState.addVariant(mockVariant);
+        StateManager.getInstance().getPanelStates().put(TEST_PANEL_ID, panelState);
+
+        Panel mockPanel = mock(Panel.class);
+        PanelPool.PanelCreatorDelegate delegate = mock(PanelPool.PanelCreatorDelegate.class);
+        PanelPool.getInstance().setDelegate(delegate);
+        when(delegate.createPanel(any())).thenReturn(mockPanel);
+        Transition mockTransition = mock(Transition.class);
+        when(mockTransition.getToVariant()).thenReturn(new Variant.Builder(TO_VARIANT_ID).build());
+        when(panelState.getTransition(any(Event.class))).thenReturn(mockTransition);
+        Animator mockAnimator = mock(Animator.class);
+        when(mockTransition.getAnimator(any(Panel.class), any(Variant.class))).thenReturn(
+                mockAnimator);
+
+        PanelTransaction panelTransaction = StateManager.handleEvent(TEST_EVENT);
+        assertThat(panelTransaction.getAnimationStartCallbackRunnable()).isNotNull();
+        assertThat(panelTransaction.getAnimationEndCallbackRunnable()).isNotNull();
+
+        panelTransaction.getAnimationStartCallbackRunnable().run();
+        assertThat(observer.mOnBeforePanelStateChangedCalled).isTrue();
+        assertThat(observer.mOnPanelStateChangedCalled).isFalse();
+
+        panelTransaction.getAnimationEndCallbackRunnable().run();
+        assertThat(observer.mOnPanelStateChangedCalled).isTrue();
+    }
+
+    @Test
+    public void testPanelStateListener_withoutAnimation() {
+        TestPanelStateObserver observer = new TestPanelStateObserver();
+        StateManager.getInstance().addPanelStateObserver(observer);
+        PanelState panelState = spy(new PanelState(TEST_PANEL_ID, new Role(0)));
+        when(panelState.getTransition(any(Event.class))).thenReturn(mock(Transition.class));
+        Variant mockVariant = mock(Variant.class);
+        when(mockVariant.getId()).thenReturn(TO_VARIANT_ID);
+        panelState.addVariant(mockVariant);
+        StateManager.getInstance().getPanelStates().put(TEST_PANEL_ID, panelState);
+
+        Panel mockPanel = mock(Panel.class);
+        PanelPool.PanelCreatorDelegate delegate = mock(PanelPool.PanelCreatorDelegate.class);
+        PanelPool.getInstance().setDelegate(delegate);
+        when(delegate.createPanel(any())).thenReturn(mockPanel);
+        when(PanelPool.getInstance().getPanel(anyString())).thenReturn(mockPanel);
+        Transition mockTransition = mock(Transition.class);
+        when(mockTransition.getToVariant()).thenReturn(new Variant.Builder(TO_VARIANT_ID).build());
+        when(panelState.getTransition(any(Event.class))).thenReturn(mockTransition);
+        when(mockTransition.getAnimator(any(Panel.class), any(Variant.class))).thenReturn(null);
+
+        PanelTransaction panelTransaction = StateManager.handleEvent(TEST_EVENT);
+
+        assertThat(panelTransaction.getAnimationStartCallbackRunnable()).isNull();
+        assertThat(panelTransaction.getAnimationEndCallbackRunnable()).isNull();
+    }
+
+    private static class TestPanelStateObserver implements StateManager.PanelStateObserver {
+        private boolean mOnBeforePanelStateChangedCalled = false;
+        private boolean mOnPanelStateChangedCalled = false;
+
+        @Override
+        public void onBeforePanelStateChanged(Set<String> changedPanelIds,
+                Map<String, PanelState> panelStates) {
+            mOnBeforePanelStateChangedCalled = true;
+        }
+
+        @Override
+        public void onPanelStateChanged(Set<String> changedPanelIds,
+                Map<String, PanelState> panelStates) {
+            mOnPanelStateChangedCalled = true;
+        }
+    }
+}
diff --git a/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/AlphaTest.java b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/AlphaTest.java
new file mode 100644
index 0000000..b9bb255
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/AlphaTest.java
@@ -0,0 +1,43 @@
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
+package com.android.car.scalableui.model;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.car.scalableui.loader.xml.PanelStateXmlParser;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+@RunWith(AndroidJUnit4.class)
+public class AlphaTest {
+
+    @Test
+    public void testAlphaCreation() {
+        final float testAlpha = 0.5f;
+        Alpha alpha = new Alpha(testAlpha);
+        assertThat(alpha.getAlpha()).isEqualTo(testAlpha);
+    }
+
+    @Test
+    public void testAlphaConstants() {
+        assertThat(PanelStateXmlParser.ALPHA_TAG).isEqualTo("Alpha");
+        assertThat(PanelStateXmlParser.ALPHA_VALUE_ATTRIBUTE).isEqualTo("alpha");
+        assertThat(Alpha.DEFAULT_ALPHA).isEqualTo(1f);
+    }
+}
diff --git a/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/BoundsTest.java b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/BoundsTest.java
new file mode 100644
index 0000000..778fcf4
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/BoundsTest.java
@@ -0,0 +1,39 @@
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
+package com.android.car.scalableui.model;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import android.graphics.Rect;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+@RunWith(AndroidJUnit4.class)
+public class BoundsTest {
+
+    @Test
+    public void testBoundsCreation() {
+        Bounds bounds = new Bounds(10, 20, 30, 40);
+        Rect rect = bounds.getRect();
+        assertThat(rect.left).isEqualTo(10);
+        assertThat(rect.top).isEqualTo(20);
+        assertThat(rect.right).isEqualTo(30);
+        assertThat(rect.bottom).isEqualTo(40);
+    }
+}
diff --git a/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/CornerTest.java b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/CornerTest.java
new file mode 100644
index 0000000..1884ead
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/CornerTest.java
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project.
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
+package com.android.car.scalableui.model;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.car.scalableui.loader.xml.PanelStateXmlParser;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+@RunWith(AndroidJUnit4.class)
+public class CornerTest {
+
+    @Test
+    public void testCornerCreation() {
+        final int expectedRadius = 2;
+        Corner corner = new Corner(expectedRadius);
+        assertThat(corner.getRadius()).isEqualTo(expectedRadius);
+    }
+
+    @Test
+    public void testCornerConstants() {
+        assertThat(PanelStateXmlParser.CORNER_TAG).isEqualTo("Corner");
+        assertThat(Corner.DEFAULT_RADIUS).isEqualTo(0);
+    }
+}
diff --git a/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/EventTest.java b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/EventTest.java
new file mode 100644
index 0000000..5734d38
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/EventTest.java
@@ -0,0 +1,68 @@
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
+package com.android.car.scalableui.model;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import org.junit.Test;
+
+public class EventTest {
+
+    private static final String TEST_EVENT_ID = "TEST_EVENT_ID";
+    private static final String TEST_TOKEN_ID = "TEST_TOKEN_ID";
+    private static final String TEST_TOKEN_VALUE = "TEST_TOKEN_VALUE";
+
+    @Test
+    public void testEventCreation_withoutTokens() {
+        Event event = new Event(TEST_EVENT_ID);
+        assertThat(event.getId()).isEqualTo(TEST_EVENT_ID);
+        assertThat(event.getTokens()).isEmpty();
+    }
+
+    @Test
+    public void testEventCreation_withTokens() {
+        Event event = new Event(TEST_EVENT_ID);
+        event.addToken(TEST_TOKEN_ID, TEST_TOKEN_VALUE);
+        assertThat(event.getId()).isEqualTo(TEST_EVENT_ID);
+        assertThat(event.getTokens()).isNotEmpty();
+        assertThat(event.getTokens().get(TEST_TOKEN_ID)).isEqualTo(TEST_TOKEN_VALUE);
+    }
+
+    @Test
+    public void testMatching_noIdMatch_isNotMatch() {
+        Event event = new Event(TEST_EVENT_ID);
+        Event event2 = new Event("OTHER_EVENT_ID");
+        assertThat(event.isMatch(event2)).isFalse();
+    }
+
+    @Test
+    public void testMatching_noTokenMatch_isNotMatch() {
+        Event event = new Event(TEST_EVENT_ID);
+        Event event2 = new Event(TEST_EVENT_ID);
+        event2.addToken(TEST_TOKEN_ID, TEST_TOKEN_VALUE);
+        assertThat(event.isMatch(event2)).isFalse();
+    }
+
+    @Test
+    public void testMatching_isMatch() {
+        Event event = new Event(TEST_EVENT_ID);
+        event.addToken(TEST_TOKEN_ID, TEST_TOKEN_VALUE);
+        Event event2 = new Event(TEST_EVENT_ID);
+        event2.addToken(TEST_TOKEN_ID, TEST_TOKEN_VALUE);
+        assertThat(event.isMatch(event2)).isTrue();
+    }
+}
diff --git a/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/KeyFrameEventTest.java b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/KeyFrameEventTest.java
new file mode 100644
index 0000000..70d7eeb
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/KeyFrameEventTest.java
@@ -0,0 +1,101 @@
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
+package com.android.car.scalableui.model;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+import java.util.HashMap;
+import java.util.Map;
+
+@RunWith(AndroidJUnit4.class)
+public class KeyFrameEventTest {
+
+    @Test
+    public void keyFrameEvent_toString_returnsCorrectFormat() {
+        Map<String, String> tokens = new HashMap<>();
+        tokens.put("key1", "value1");
+        KeyFrameEvent keyFrameEvent = new KeyFrameEvent("testEvent", 0.5f, tokens);
+        String expectedString =
+                "KeyFrameEvent{mId=testEvent, mTokens={key1=value1}, mFraction=0.5}";
+        assertThat(keyFrameEvent.toString()).isEqualTo(expectedString);
+    }
+
+    @Test
+    public void keyFrameEvent_getFraction_returnsCorrectValue() {
+        KeyFrameEvent keyFrameEvent = new KeyFrameEvent("testEvent", 0.75f, new HashMap<>());
+        assertThat(keyFrameEvent.getFraction()).isEqualTo(0.75f);
+    }
+
+    @Test
+    public void keyFrameEventBuilder_addToken_addsTokenCorrectly() {
+        KeyFrameEvent keyFrameEvent = new KeyFrameEvent.Builder("testEvent", 0.25f)
+                .addToken("tokenKey", "tokenValue")
+                .build();
+
+        assertThat(keyFrameEvent.getTokens()).containsExactly("tokenKey", "tokenValue");
+    }
+
+    @Test
+    public void keyFrameEventBuilder_addTokensFromString_addsMultipleTokensCorrectly() {
+        KeyFrameEvent keyFrameEvent = new KeyFrameEvent.Builder("testEvent", 0.25f)
+                .addTokensFromString("key1=value1;key2=value2")
+                .build();
+
+        assertThat(keyFrameEvent.getTokens()).containsExactly("key1", "value1", "key2", "value2");
+    }
+
+    @Test
+    public void keyFrameEventBuilder_addTokensFromString_withEmptyString_addsNoToken() {
+        KeyFrameEvent keyFrameEvent = new KeyFrameEvent.Builder("testEvent", 0.25f)
+                .addTokensFromString("")
+                .build();
+
+        assertThat(keyFrameEvent.getTokens()).isEmpty();
+    }
+
+    @Test
+    public void keyFrameEventBuilder_addTokensFromString_withNullString_addsNoToken() {
+        KeyFrameEvent keyFrameEvent = new KeyFrameEvent.Builder("testEvent", 0.25f)
+                .addTokensFromString(null)
+                .build();
+
+        assertThat(keyFrameEvent.getTokens()).isEmpty();
+    }
+
+    @Test
+    public void keyFrameEventBuilder_addTokensFromString_withMalformedString_onlyAddsValidToken() {
+        KeyFrameEvent keyFrameEvent = new KeyFrameEvent.Builder("testEvent", 0.25f)
+                .addTokensFromString("key1=value1;key2;key3=value3")
+                .build();
+
+        assertThat(keyFrameEvent.getTokens()).containsExactly("key1", "value1", "key3", "value3");
+    }
+
+    @Test(expected = IllegalStateException.class)
+    public void keyFrameEventBuilder_build_withInvalidFraction_throwsException() {
+        new KeyFrameEvent.Builder("testEvent", -0.1f).build();
+    }
+
+    @Test(expected = IllegalStateException.class)
+    public void keyFrameEventBuilder_build_withInvalidFraction_aboveOne_throwsException() {
+        new KeyFrameEvent.Builder("testEvent", 1.1f).build();
+    }
+}
diff --git a/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/KeyFrameVariantTest.java b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/KeyFrameVariantTest.java
new file mode 100644
index 0000000..9a4cbb5
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/KeyFrameVariantTest.java
@@ -0,0 +1,78 @@
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
+package com.android.car.scalableui.model;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import android.graphics.Rect;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+@RunWith(AndroidJUnit4.class)
+public class KeyFrameVariantTest {
+    @Test
+    public void testGetBounds() {
+        KeyFrameVariant variant = createKeyFrameVariant();
+        variant.setFraction(0.5f); // Interpolate halfway
+
+        Rect bounds = variant.getBounds();
+
+        // Expected bounds are the average of the two keyframe bounds
+        assertThat(bounds).isEqualTo(new Rect(5, 10, 15, 20));
+    }
+
+    @Test
+    public void testGetVisibility() {
+        KeyFrameVariant variant = createKeyFrameVariant();
+
+        variant.setFraction(0.25f); // Before the visible keyframe
+        assertThat(variant.isVisible()).isFalse();
+
+        variant.setFraction(0.75f); // After the visible keyframe
+        assertThat(variant.isVisible()).isTrue();
+    }
+
+    @Test
+    public void testGetAlpha() {
+        KeyFrameVariant variant = createKeyFrameVariant();
+        variant.setFraction(0.5f); // Interpolate halfway
+        assertThat(variant.getAlpha()).isEqualTo(0.5f); // Expected alpha is the average
+    }
+
+    private KeyFrameVariant createKeyFrameVariant() {
+        final String keyFrameVariantId = "keyFrameVariantId";
+        final String variantId1 = "variantId1";
+        final String variantId2 = "variantId2";
+
+        KeyFrameVariant variant = new KeyFrameVariant(keyFrameVariantId);
+        Variant variant1 = new Variant(variantId1);
+        variant1.setBounds(new Rect(0, 0, 10, 10));
+        variant1.setVisibility(false);
+        variant1.setAlpha(0.0f);
+
+        Variant variant2 = new Variant(variantId2);
+        variant2.setBounds(new Rect(10, 20, 20, 30));
+        variant2.setVisibility(true);
+        variant2.setAlpha(1.0f);
+
+        variant.addKeyFrame(new KeyFrameVariant.KeyFrame(25, variant1));
+        variant.addKeyFrame(new KeyFrameVariant.KeyFrame(75, variant2));
+        return variant;
+    }
+}
diff --git a/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/LayerTest.java b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/LayerTest.java
new file mode 100644
index 0000000..2bf6cb0
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/LayerTest.java
@@ -0,0 +1,43 @@
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
+package com.android.car.scalableui.model;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.car.scalableui.loader.xml.PanelStateXmlParser;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+@RunWith(AndroidJUnit4.class)
+public class LayerTest {
+
+    @Test
+    public void testGetLayer() {
+        Layer layer = new Layer(10);
+        assertThat(layer.getLayer()).isEqualTo(10);
+    }
+
+
+    @Test
+    public void testLayerConstants() {
+        assertThat(PanelStateXmlParser.LAYER_TAG).isEqualTo("Layer");
+        assertThat(PanelStateXmlParser.LAYER_VALUE_ATTRIBUTE).isEqualTo("layer");
+        assertThat(Layer.DEFAULT_LAYER).isEqualTo(0);
+    }
+}
diff --git a/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/PanelStateTest.java b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/PanelStateTest.java
new file mode 100644
index 0000000..45e6093
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/PanelStateTest.java
@@ -0,0 +1,119 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project.
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
+package com.android.car.scalableui.model;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import android.content.Context;
+
+import androidx.test.core.app.ApplicationProvider;
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.car.scalableui.loader.xml.XmlModelLoader;
+import com.android.car.scalableui.unit.R;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.xmlpull.v1.XmlPullParserException;
+
+import java.io.IOException;
+
+@RunWith(AndroidJUnit4.class)
+public class PanelStateTest {
+    private static final String TEST_PANEL_ID = "TEST_PANEL_ID";
+    private static final String VARIANT1 = "variant1";
+    private static final String VARIANT2 = "variant2";
+    private static final Event TEST_EVENT = new Event("TEST_EVENT");
+
+    private Context mContext;
+
+    @Before
+    public void setUp() {
+        mContext = ApplicationProvider.getApplicationContext();
+    }
+
+    @Test
+    public void testPanelStateCreation() {
+        PanelState panelState = new PanelState(TEST_PANEL_ID, new Role(1));
+        assertThat(panelState.getId()).isEqualTo(TEST_PANEL_ID);
+        assertThat(panelState.getRole().getValue()).isEqualTo(1);
+    }
+
+    @Test
+    public void testLoadFromXmlResource() throws XmlPullParserException, IOException {
+        XmlModelLoader loader = new XmlModelLoader(mContext);
+        PanelState panelState = loader.createPanelState(R.xml.panel_test);
+
+        assertThat(panelState.getId()).isEqualTo("panel_id");
+        assertThat(panelState.getRole().getValue()).isEqualTo(
+                R.string.default_config);
+        assertThat(panelState.getCurrentVariant().getId()).isEqualTo(VARIANT1);
+        Variant variant2 = panelState.getVariant(VARIANT2);
+        assertThat(variant2.getLayer()).isEqualTo(100);
+        assertThat(variant2.getAlpha()).isEqualTo(0.8f);
+        assertThat(variant2.getInsets()).isNotNull();
+    }
+
+    @Test
+    public void testAddVariant() {
+        PanelState panelState = new PanelState(TEST_PANEL_ID, new Role(1));
+        Variant variant = new Variant(VARIANT1);
+        panelState.addVariant(variant);
+        assertThat(panelState.getVariant(VARIANT1)).isEqualTo(variant);
+    }
+
+    @Test
+    public void testAddTransition() {
+        PanelState panelState = new PanelState(TEST_PANEL_ID, new Role(1));
+        Variant variant1 = new Variant(VARIANT1);
+        Variant variant2 = new Variant(VARIANT2);
+        Transition transition = new Transition(variant1, variant2, TEST_EVENT, null, 0,
+                null);
+        panelState.addTransition(transition);
+        panelState.addVariant(variant1);
+        panelState.addVariant(variant2);
+        panelState.setVariant(variant1.getId());
+
+        assertThat(panelState.getTransition(TEST_EVENT)).isEqualTo(transition);
+    }
+
+    @Test
+    public void testSetVariant() {
+        PanelState panelState = new PanelState(TEST_PANEL_ID, new Role(1));
+        Variant variant1 = new Variant(VARIANT1);
+        Variant variant2 = new Variant(VARIANT2);
+        panelState.addVariant(variant1);
+        panelState.addVariant(variant2);
+
+        panelState.setVariant(VARIANT2);
+        assertThat(panelState.getCurrentVariant()).isEqualTo(variant2);
+    }
+
+    @Test
+    public void testResetVariant() {
+        PanelState panelState = new PanelState(TEST_PANEL_ID, new Role(1));
+        Variant variant1 = new Variant(VARIANT1);
+        Variant variant2 = new Variant(VARIANT2);
+        panelState.addVariant(variant1);
+        panelState.addVariant(variant2);
+        panelState.setDefaultVariant(VARIANT1);
+
+        panelState.setVariant(VARIANT2);
+        panelState.resetVariant();
+        assertThat(panelState.getCurrentVariant()).isEqualTo(variant1);
+    }
+}
diff --git a/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/PanelTransactionTest.java b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/PanelTransactionTest.java
new file mode 100644
index 0000000..c412c84
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/PanelTransactionTest.java
@@ -0,0 +1,95 @@
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
+package com.android.car.scalableui.model;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.Mockito.mock;
+
+import android.animation.Animator;
+
+import org.junit.Test;
+
+import java.util.Map;
+
+public class PanelTransactionTest {
+
+    private static final String TEST_PANEL_ID = "TEST_PANEL_ID";
+    private static final String TEST_PANEL_ID_2 = "TEST_PANEL_ID_2";
+
+    @Test
+    public void testSetPanelTransaction() {
+        PanelTransaction transaction = new PanelTransaction();
+        Transition mockTransition = mock(Transition.class);
+        transaction.addPanelTransaction(TEST_PANEL_ID, mockTransition);
+
+        // Check if the transaction is added correctly
+        assertThat(transaction.getPanelTransactionStates()).hasSize(1);
+        Map.Entry<String, Transition> entry =
+                transaction.getPanelTransactionStates().iterator().next();
+        assertThat(entry.getKey()).isEqualTo(TEST_PANEL_ID);
+        assertThat(entry.getValue()).isEqualTo(mockTransition);
+    }
+
+    @Test
+    public void testGetPanelTransactionStates() {
+        PanelTransaction transaction = new PanelTransaction();
+        transaction.addPanelTransaction(TEST_PANEL_ID, mock(Transition.class));
+        transaction.addPanelTransaction(TEST_PANEL_ID_2, mock(Transition.class));
+
+        // Check if the correct number of transactions are returned
+        assertThat(transaction.getPanelTransactionStates()).hasSize(/* expectedSize= */ 2);
+    }
+
+    @Test
+    public void testSetAnimator() {
+        PanelTransaction transaction = new PanelTransaction();
+        Animator mockAnimator = mock(Animator.class);
+        transaction.addAnimator(TEST_PANEL_ID, mockAnimator);
+
+        // Check if the animator is added correctly
+        assertThat(transaction.getAnimators()).hasSize(/* expectedSize= */ 1);
+        Map.Entry<String, Animator> entry = transaction.getAnimators().iterator().next();
+        assertThat(entry.getKey()).isEqualTo(TEST_PANEL_ID);
+        assertThat(entry.getValue()).isEqualTo(mockAnimator);
+    }
+
+    @Test
+    public void testGetAnimators() {
+        PanelTransaction transaction = new PanelTransaction();
+        transaction.addAnimator(TEST_PANEL_ID, mock(Animator.class));
+        transaction.addAnimator(TEST_PANEL_ID_2, mock(Animator.class));
+
+        // Check if the correct number of animators are returned
+        assertThat(transaction.getAnimators()).hasSize(/* expectedSize= */ 2);
+    }
+
+    @Test
+    public void testGetPanelTransactionState_existingId() {
+        PanelTransaction transaction = new PanelTransaction();
+        Transition mockTransition = mock(Transition.class);
+        transaction.addPanelTransaction(TEST_PANEL_ID, mockTransition);
+
+        assertThat(transaction.getPanelTransactionState(TEST_PANEL_ID)).isEqualTo(mockTransition);
+    }
+
+    @Test
+    public void testGetPanelTransactionState_nonExistingId() {
+        PanelTransaction transaction = new PanelTransaction();
+        assertThat(transaction.getPanelTransactionState("NON_EXISTING_ID")).isNull();
+    }
+}
diff --git a/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/RoleTest.java b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/RoleTest.java
new file mode 100644
index 0000000..529e562
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/RoleTest.java
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
+package com.android.car.scalableui.model;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+@RunWith(AndroidJUnit4.class)
+public class RoleTest {
+    @Test
+    public void testGetValue() {
+        int expectedValue = 25;
+        Role role = new Role(expectedValue);
+        int actualValue = role.getValue();
+        assertThat(actualValue).isEqualTo(expectedValue);
+    }
+}
diff --git a/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/TransitionTest.java b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/TransitionTest.java
new file mode 100644
index 0000000..2dedf9a
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/TransitionTest.java
@@ -0,0 +1,77 @@
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
+package com.android.car.scalableui.model;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.Mockito.mock;
+
+import android.animation.Animator;
+import android.animation.ValueAnimator;
+import android.view.animation.AccelerateDecelerateInterpolator;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.car.scalableui.panel.Panel;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+@RunWith(AndroidJUnit4.class)
+public class TransitionTest {
+
+    private static final String TO_VARIANT_ID = "TO_VARIANT_ID";
+    private static final String FROM_VARIANT_ID = "FROM_VARIANT_ID";
+    private static final Event TEST_EVENT = new Event("TEST_EVENT");
+
+    @Test
+    public void testTransitionCreation() {
+        Variant fromVariant = new Variant(FROM_VARIANT_ID);
+        Variant toVariant = new Variant(TO_VARIANT_ID);
+        Transition transition = new Transition(fromVariant, toVariant, TEST_EVENT, null, 500,
+                new AccelerateDecelerateInterpolator());
+
+        assertThat(transition.getFromVariant()).isEqualTo(fromVariant);
+        assertThat(transition.getToVariant()).isEqualTo(toVariant);
+        assertThat(transition.getOnEvent()).isNotNull();
+        assertThat(transition.getOnEvent().getId()).isEqualTo(TEST_EVENT.getId());
+    }
+
+    @Test
+    public void testGetAnimator_defaultAnimator() {
+        Panel panel = mock(Panel.class);
+        Variant fromVariant = new Variant(FROM_VARIANT_ID);
+        Variant toVariant = new Variant(TO_VARIANT_ID);
+        Transition transition = new Transition(fromVariant, toVariant, TEST_EVENT, null, 500,
+                new AccelerateDecelerateInterpolator());
+
+        Animator animator = transition.getAnimator(panel, fromVariant);
+
+        assertThat(animator).isInstanceOf(ValueAnimator.class);
+    }
+
+    @Test
+    public void testGetAnimator_sameFromAndToVariant() {
+        Panel panel = mock(Panel.class);
+        Variant variant = new Variant(FROM_VARIANT_ID);
+        Transition transition = new Transition(variant, variant, TEST_EVENT, null, 500,
+                new AccelerateDecelerateInterpolator());
+
+        Animator animator = transition.getAnimator(panel, variant);
+
+        assertThat(animator).isNull();
+    }
+}
diff --git a/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/VariantTest.java b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/VariantTest.java
new file mode 100644
index 0000000..1223fe8
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/VariantTest.java
@@ -0,0 +1,81 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project.
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
+package com.android.car.scalableui.model;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.Mockito.mock;
+
+import android.animation.Animator;
+import android.graphics.Rect;
+import android.view.animation.Interpolator;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.car.scalableui.panel.Panel;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+@RunWith(AndroidJUnit4.class)
+public class VariantTest {
+    private static final String VARIANT_ID = "VARIANT_ID";
+
+    @Test
+    public void testVariantCreation_withBaseVariant() {
+        Variant base = new Variant(VARIANT_ID);
+        base.setBounds(new Rect(10, 20, 30, 40));
+        base.setVisibility(false);
+        base.setLayer(5);
+        base.setAlpha(0.5f);
+        base.setCornerRadius(2);
+
+        Variant variant = new Variant(VARIANT_ID, base);
+
+        assertThat(variant.getId()).isEqualTo(VARIANT_ID);
+        assertThat(variant.getBounds()).isEqualTo(new Rect(10, 20, 30, 40));
+        assertThat(variant.isVisible()).isFalse();
+        assertThat(variant.getLayer()).isEqualTo(5);
+        assertThat(variant.getAlpha()).isEqualTo(0.5f);
+        assertThat(variant.getCornerRadius()).isEqualTo(2);
+    }
+
+    @Test
+    public void testVariantCreation_withoutBaseVariant() {
+        Variant variant = new Variant(VARIANT_ID);
+
+        assertThat(variant.getId()).isEqualTo(VARIANT_ID);
+        assertThat(variant.getBounds()).isEqualTo(new Rect()); // Default Rect
+        assertThat(variant.isVisible()).isTrue(); // Default Visibility
+        assertThat(variant.getLayer()).isEqualTo(0); // Default Layer
+        assertThat(variant.getAlpha()).isEqualTo(1.0f); // Default Alpha
+        assertThat(variant.getCornerRadius()).isEqualTo(0); // Default Alpha
+    }
+
+    @Test
+    public void testGetAnimator() {
+        final String toVariantId = "toVariantId";
+        final String fromVariantId = "fromVariantId";
+        Panel panel = mock(Panel.class);
+        Variant fromVariant = new Variant(fromVariantId);
+        Variant toVariant = new Variant(toVariantId);
+        Interpolator interpolator = mock(Interpolator.class);
+
+        Animator animator = fromVariant.getAnimator(panel, toVariant, 1000, interpolator);
+
+        assertThat(animator).isNotNull();
+    }
+}
diff --git a/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/VisibilityTest.java b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/VisibilityTest.java
new file mode 100644
index 0000000..5699b16
--- /dev/null
+++ b/car-scalable-ui-lib/test/unit/src/com/android/car/scalableui/model/VisibilityTest.java
@@ -0,0 +1,54 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project.
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
+package com.android.car.scalableui.model;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.car.scalableui.loader.xml.PanelStateXmlParser;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+@RunWith(AndroidJUnit4.class)
+public class VisibilityTest {
+
+    @Test
+    public void testVisibilityCreation_true() {
+        Visibility visibility = new Visibility(true);
+        assertThat(visibility.isVisible()).isTrue();
+    }
+
+    @Test
+    public void testVisibilityCreation_false() {
+        Visibility visibility = new Visibility(false);
+        assertThat(visibility.isVisible()).isFalse();
+    }
+
+    @Test
+    public void testVisibilityCopyConstructor() {
+        Visibility original = new Visibility(true);
+        Visibility copy = new Visibility(original);
+        assertThat(copy.isVisible()).isTrue();
+    }
+
+    @Test
+    public void testVisibilityConstants() {
+        assertThat(PanelStateXmlParser.VISIBILITY_TAG).isEqualTo("Visibility");
+        assertThat(Visibility.DEFAULT_VISIBILITY).isTrue();
+    }
+}
diff --git a/car-tos-lib/Android.bp b/car-tos-lib/Android.bp
new file mode 100644
index 0000000..75f6637
--- /dev/null
+++ b/car-tos-lib/Android.bp
@@ -0,0 +1,31 @@
+//
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_library {
+    name: "car-tos-lib",
+    srcs: ["src/**/*.kt"],
+    optimize: {
+        enabled: true,
+    },
+    static_libs: [
+        "androidx.annotation_annotation",
+    ],
+
+    libs: ["android.car"],
+}
diff --git a/car-tos-lib/AndroidManifest.xml b/car-tos-lib/AndroidManifest.xml
new file mode 100644
index 0000000..9fef445
--- /dev/null
+++ b/car-tos-lib/AndroidManifest.xml
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.car.tos">
+</manifest>
diff --git a/car-tos-lib/OWNERS b/car-tos-lib/OWNERS
new file mode 100644
index 0000000..14353dd
--- /dev/null
+++ b/car-tos-lib/OWNERS
@@ -0,0 +1,7 @@
+# People who can approve changes for submission.
+
+# Primary
+vagoyal@google.com
+
+# Secondary (only if people in Primary are unreachable)
+ankiit@google.com
diff --git a/car-tos-lib/PREUPLOAD.cfg b/car-tos-lib/PREUPLOAD.cfg
new file mode 100644
index 0000000..38f9800
--- /dev/null
+++ b/car-tos-lib/PREUPLOAD.cfg
@@ -0,0 +1,7 @@
+[Hook Scripts]
+checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
+ktlint_hook = ${REPO_ROOT}/prebuilts/ktlint/ktlint.py -f ${PREUPLOAD_FILES}
+
+[Builtin Hooks]
+commit_msg_changeid_field = true
+commit_msg_test_field = true
diff --git a/car-tos-lib/src/com/android/car/tos/TosHelper.kt b/car-tos-lib/src/com/android/car/tos/TosHelper.kt
new file mode 100644
index 0000000..85f9b1f
--- /dev/null
+++ b/car-tos-lib/src/com/android/car/tos/TosHelper.kt
@@ -0,0 +1,138 @@
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
+package com.android.car.tos
+
+import android.car.settings.CarSettings.Secure.KEY_UNACCEPTED_TOS_DISABLED_APPS
+import android.car.settings.CarSettings.Secure.KEY_USER_TOS_ACCEPTED
+import android.content.Context
+import android.content.Intent
+import android.os.UserHandle
+import android.provider.Settings
+import android.util.Log
+import java.net.URISyntaxException
+import java.util.Objects
+
+/** Helper methods for terms of services (tos) restrictions **/
+object TosHelper {
+    private const val TAG = "TosHelper"
+
+    // This value indicates if TOS is in uninitialized state
+    const val TOS_UNINITIALIZED = "0"
+
+    // This value indicates if TOS has not been accepted by the user
+    const val TOS_NOT_ACCEPTED = "1"
+
+    // This value indicates if TOS has been accepted by the user
+    const val TOS_ACCEPTED = "2"
+    private const val TOS_DISABLED_APPS_SEPARATOR = ","
+
+    /**
+     * Returns a set of packages that are disabled when terms of services are not accepted.
+     *
+     * @param context The application context
+     * @param uid A user id for a particular user
+     *
+     * @return Set of packages disabled by tos
+     */
+    @JvmStatic
+    @JvmOverloads
+    fun getTosDisabledPackages(context: Context, uid: Int = UserHandle.myUserId()): Set<String> {
+        val settingsValue = Settings.Secure.getStringForUser(
+            context.contentResolver,
+            KEY_UNACCEPTED_TOS_DISABLED_APPS,
+            uid
+        )
+        return settingsValue?.split(TOS_DISABLED_APPS_SEPARATOR)?.toSet() ?: emptySet()
+    }
+
+    /**
+     * Gets the intent for launching the terms of service acceptance flow.
+     *
+     * @param context The app context
+     * @param id The desired resource identifier
+     *
+     * @return TOS intent, or null
+     */
+    @JvmStatic
+    fun getIntentForTosAcceptanceFlow(context: Context, id: Int): Intent? {
+        val tosIntentName = context.resources.getString(id)
+        return try {
+            Intent.parseUri(tosIntentName, Intent.URI_ANDROID_APP_SCHEME)
+        } catch (e: URISyntaxException) {
+            Log.e(TAG, "Invalid intent URI in user_tos_activity_intent", e)
+            null
+        }
+    }
+
+    /**
+     * Replaces the [mapIntent] with an intent defined in the resources with [id] if terms of
+     * services have not been accepted and the app defined by [mapIntent] is disabled.
+     */
+    @JvmStatic
+    @JvmOverloads
+    fun maybeReplaceWithTosMapIntent(
+         context: Context,
+         mapIntent: Intent,
+         id: Int,
+         uid: Int = UserHandle.myUserId()
+     ): Intent {
+         val packageName = mapIntent.component?.packageName
+         val tosDisabledPackages = getTosDisabledPackages(context, uid)
+
+        Log.i(TAG, "TOS disabled packages:$tosDisabledPackages")
+        Log.i(TAG, "TOS accepted:" + tosAccepted(context))
+
+        // Launch tos map intent when the user has not accepted tos and when the
+        // default maps package is not available to package manager, or it's disabled by tos
+        if (!tosAccepted(context) &&
+            (packageName == null || tosDisabledPackages.contains(packageName))
+        ) {
+            Log.i(TAG, "Replacing default maps intent with tos map intent")
+            return getIntentForTosAcceptanceFlow(context, id) ?: mapIntent
+        }
+        return mapIntent
+    }
+
+    /**
+     * Returns true if tos is accepted or uninitialized, false otherwise.
+     */
+    @JvmStatic
+    @JvmOverloads
+    fun tosAccepted(context: Context, uid: Int = UserHandle.myUserId()): Boolean {
+        val settingsValue = Settings.Secure.getStringForUser(
+            context.contentResolver,
+            KEY_USER_TOS_ACCEPTED,
+            uid
+        )
+        // We consider an uninitialized state to be TOS accepted.
+        return Objects.equals(settingsValue, TOS_ACCEPTED) || tosStatusUninitialized(context, uid)
+    }
+
+    /**
+     * Returns true if tos is uninitialized, false otherwise.
+     */
+    @JvmStatic
+    @JvmOverloads
+    fun tosStatusUninitialized(context: Context, uid: Int = UserHandle.myUserId()): Boolean {
+        val settingsValue = Settings.Secure.getStringForUser(
+            context.contentResolver,
+            KEY_USER_TOS_ACCEPTED,
+            uid
+        )
+        return settingsValue == null || Objects.equals(settingsValue, TOS_UNINITIALIZED)
+    }
+}
```

