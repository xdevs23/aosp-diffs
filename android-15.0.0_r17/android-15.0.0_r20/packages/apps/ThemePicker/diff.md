```diff
diff --git a/res/drawable/clock_font_apply.xml b/res/drawable/clock_font_apply.xml
new file mode 100644
index 00000000..11c6f06f
--- /dev/null
+++ b/res/drawable/clock_font_apply.xml
@@ -0,0 +1,24 @@
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="72dp"
+    android:height="56dp"
+    android:viewportWidth="72"
+    android:viewportHeight="56">
+  <group>
+    <clip-path
+        android:pathData="M0,0h72v56h-72z"/>
+    <group>
+      <clip-path
+          android:pathData="M0,28C0,12.536 12.536,0 28,0H44C59.464,0 72,12.536 72,28C72,43.464 59.464,56 44,56H28C12.536,56 0,43.464 0,28Z"/>
+      <path
+          android:pathData="M0,28C0,12.536 12.536,0 28,0H44C59.464,0 72,12.536 72,28C72,43.464 59.464,56 44,56H28C12.536,56 0,43.464 0,28Z"
+          android:fillColor="@color/system_on_primary"/>
+      <group>
+        <clip-path
+            android:pathData="M24,16h24v24h-24z"/>
+        <path
+            android:pathData="M33.55,34L27.85,28.3L29.275,26.875L33.55,31.15L42.725,21.975L44.15,23.4L33.55,34Z"
+            android:fillColor="@color/system_primary"/>
+      </group>
+    </group>
+  </group>
+</vector>
diff --git a/res/drawable/clock_font_revert.xml b/res/drawable/clock_font_revert.xml
new file mode 100644
index 00000000..10a46ad1
--- /dev/null
+++ b/res/drawable/clock_font_revert.xml
@@ -0,0 +1,24 @@
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="72dp"
+    android:height="56dp"
+    android:viewportWidth="72"
+    android:viewportHeight="56">
+  <group>
+    <clip-path
+        android:pathData="M0,0h72v56h-72z"/>
+    <group>
+      <clip-path
+          android:pathData="M0,28C0,12.536 12.536,0 28,0H44C59.464,0 72,12.536 72,28C72,43.464 59.464,56 44,56H28C12.536,56 0,43.464 0,28Z"/>
+      <path
+          android:pathData="M0,28C0,12.536 12.536,0 28,0H44C59.464,0 72,12.536 72,28C72,43.464 59.464,56 44,56H28C12.536,56 0,43.464 0,28Z"
+          android:fillColor="@color/system_secondary_container"/>
+      <group>
+        <clip-path
+            android:pathData="M24,16h24v24h-24z"/>
+        <path
+            android:pathData="M30.4,35L29,33.6L34.6,28L29,22.4L30.4,21L36,26.6L41.6,21L43,22.4L37.4,28L43,33.6L41.6,35L36,29.4L30.4,35Z"
+            android:fillColor="@color/system_on_secondary_container"/>
+      </group>
+    </group>
+  </group>
+</vector>
diff --git a/res/drawable/clock_font_switch_divider.xml b/res/drawable/clock_font_switch_divider.xml
new file mode 100644
index 00000000..abaee245
--- /dev/null
+++ b/res/drawable/clock_font_switch_divider.xml
@@ -0,0 +1,25 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="6dp"
+    android:height="48dp"
+    android:viewportWidth="6"
+    android:viewportHeight="48">
+  <path
+      android:pathData="M2,11C2,10.448 2.448,10 3,10C3.552,10 4,10.448 4,11V37C4,37.552 3.552,38 3,38C2.448,38 2,37.552 2,37V11Z"
+      android:fillColor="@color/system_outline"/>
+</vector>
diff --git a/res/drawable/edit_icon.xml b/res/drawable/edit_icon.xml
new file mode 100644
index 00000000..9690d176
--- /dev/null
+++ b/res/drawable/edit_icon.xml
@@ -0,0 +1,20 @@
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="48dp"
+    android:height="48dp"
+    android:viewportWidth="48"
+    android:viewportHeight="48">
+  <group>
+    <clip-path
+        android:pathData="M8,24C8,15.163 15.163,8 24,8C32.837,8 40,15.163 40,24C40,32.837 32.837,40 24,40C15.163,40 8,32.837 8,24Z"/>
+    <path
+        android:pathData="M8,24C8,15.163 15.163,8 24,8C32.837,8 40,15.163 40,24C40,32.837 32.837,40 24,40C15.163,40 8,32.837 8,24Z"
+        android:fillColor="@color/system_on_primary_fixed_variant"/>
+    <group>
+      <clip-path
+          android:pathData="M14,14h20v20h-20z"/>
+      <path
+          android:pathData="M17,31V27.813L27.375,17.438C27.528,17.285 27.694,17.174 27.875,17.104C28.056,17.035 28.243,17 28.438,17C28.632,17 28.819,17.035 29,17.104C29.181,17.174 29.347,17.285 29.5,17.438L30.563,18.5C30.715,18.653 30.826,18.819 30.896,19C30.965,19.181 31,19.368 31,19.563C31,19.757 30.965,19.944 30.896,20.125C30.826,20.306 30.715,20.472 30.563,20.625L20.188,31H17ZM28.438,20.625L29.5,19.563L28.438,18.5L27.375,19.563L28.438,20.625Z"
+          android:fillColor="#ffffff"/>
+    </group>
+  </group>
+</vector>
diff --git a/res/drawable/ic_apps_filled_24px.xml b/res/drawable/ic_apps_filled_24px.xml
new file mode 100644
index 00000000..af6fcefd
--- /dev/null
+++ b/res/drawable/ic_apps_filled_24px.xml
@@ -0,0 +1,20 @@
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
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="24dp" android:height="24dp" android:viewportWidth="960" android:viewportHeight="960" android:tint="?attr/colorControlNormal">
+    <path android:fillColor="@android:color/white" android:pathData="M240,800Q207,800 183.5,776.5Q160,753 160,720Q160,687 183.5,663.5Q207,640 240,640Q273,640 296.5,663.5Q320,687 320,720Q320,753 296.5,776.5Q273,800 240,800ZM480,800Q447,800 423.5,776.5Q400,753 400,720Q400,687 423.5,663.5Q447,640 480,640Q513,640 536.5,663.5Q560,687 560,720Q560,753 536.5,776.5Q513,800 480,800ZM720,800Q687,800 663.5,776.5Q640,753 640,720Q640,687 663.5,663.5Q687,640 720,640Q753,640 776.5,663.5Q800,687 800,720Q800,753 776.5,776.5Q753,800 720,800ZM240,560Q207,560 183.5,536.5Q160,513 160,480Q160,447 183.5,423.5Q207,400 240,400Q273,400 296.5,423.5Q320,447 320,480Q320,513 296.5,536.5Q273,560 240,560ZM480,560Q447,560 423.5,536.5Q400,513 400,480Q400,447 423.5,423.5Q447,400 480,400Q513,400 536.5,423.5Q560,447 560,480Q560,513 536.5,536.5Q513,560 480,560ZM720,560Q687,560 663.5,536.5Q640,513 640,480Q640,447 663.5,423.5Q687,400 720,400Q753,400 776.5,423.5Q800,447 800,480Q800,513 776.5,536.5Q753,560 720,560ZM240,320Q207,320 183.5,296.5Q160,273 160,240Q160,207 183.5,183.5Q207,160 240,160Q273,160 296.5,183.5Q320,207 320,240Q320,273 296.5,296.5Q273,320 240,320ZM480,320Q447,320 423.5,296.5Q400,273 400,240Q400,207 423.5,183.5Q447,160 480,160Q513,160 536.5,183.5Q560,207 560,240Q560,273 536.5,296.5Q513,320 480,320ZM720,320Q687,320 663.5,296.5Q640,273 640,240Q640,207 663.5,183.5Q687,160 720,160Q753,160 776.5,183.5Q800,207 800,240Q800,273 776.5,296.5Q753,320 720,320Z"/>
+</vector>
\ No newline at end of file
diff --git a/res/drawable/ic_style_filled_24px.xml b/res/drawable/ic_category_filled_24px.xml
similarity index 65%
rename from res/drawable/ic_style_filled_24px.xml
rename to res/drawable/ic_category_filled_24px.xml
index 0b9ec324..ae87e033 100644
--- a/res/drawable/ic_style_filled_24px.xml
+++ b/res/drawable/ic_category_filled_24px.xml
@@ -16,5 +16,5 @@
   -->
 
 <vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="24dp" android:height="24dp" android:viewportWidth="960" android:viewportHeight="960" android:tint="?attr/colorControlNormal">
-    <path android:fillColor="@android:color/white" android:pathData="M159,792L125,778Q94,765 83.5,733Q73,701 87,670L159,514L159,792ZM319,880Q286,880 262.5,856.5Q239,833 239,800L239,560L345,854Q348,861 351,867.5Q354,874 359,880L319,880ZM525,876Q493,888 463,873Q433,858 421,826L243,338Q231,306 245,275.5Q259,245 291,234L593,124Q625,112 655,127Q685,142 697,174L875,662Q887,694 873,724.5Q859,755 827,766L525,876ZM439,400Q456,400 467.5,388.5Q479,377 479,360Q479,343 467.5,331.5Q456,320 439,320Q422,320 410.5,331.5Q399,343 399,360Q399,377 410.5,388.5Q422,400 439,400Z"/>
+    <path android:fillColor="@android:color/white" android:pathData="M260,440L480,80L700,440L260,440ZM700,880Q625,880 572.5,827.5Q520,775 520,700Q520,625 572.5,572.5Q625,520 700,520Q775,520 827.5,572.5Q880,625 880,700Q880,775 827.5,827.5Q775,880 700,880ZM120,860L120,540L440,540L440,860L120,860Z"/>
 </vector>
\ No newline at end of file
diff --git a/res/drawable/ic_clock_filled_24px.xml b/res/drawable/ic_clock_filled_24px.xml
new file mode 100644
index 00000000..0d587d7b
--- /dev/null
+++ b/res/drawable/ic_clock_filled_24px.xml
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="24dp" android:height="24dp" android:viewportWidth="960" android:viewportHeight="960" android:tint="?attr/colorControlNormal">
+    <path android:fillColor="@android:color/white" android:pathData="M612,668L668,612L520,464L520,280L440,280L440,496L612,668ZM480,880Q397,880 324,848.5Q251,817 197,763Q143,709 111.5,636Q80,563 80,480Q80,397 111.5,324Q143,251 197,197Q251,143 324,111.5Q397,80 480,80Q563,80 636,111.5Q709,143 763,197Q817,251 848.5,324Q880,397 880,480Q880,563 848.5,636Q817,709 763,763Q709,817 636,848.5Q563,880 480,880Z"/>
+</vector>
\ No newline at end of file
diff --git a/res/layout/clock_color_list_placeholder.xml b/res/layout/clock_color_list_placeholder.xml
deleted file mode 100644
index d7912c14..00000000
--- a/res/layout/clock_color_list_placeholder.xml
+++ /dev/null
@@ -1,37 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?><!--
-     Copyright (C) 2023 The Android Open Source Project
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
-<LinearLayout
-    xmlns:android="http://schemas.android.com/apk/res/android"
-    android:layout_width="wrap_content"
-    android:layout_height="wrap_content"
-    android:visibility="invisible"
-    android:orientation="vertical">
-
-    <include
-        layout="@layout/color_option"
-        android:layout_width="@dimen/option_item_size"
-        android:layout_height="@dimen/option_item_size" />
-
-    <View
-        android:layout_width="match_parent"
-        android:layout_height="@dimen/floating_sheet_list_item_vertical_space"/>
-
-    <include
-        layout="@layout/color_option"
-        android:layout_width="@dimen/option_item_size"
-        android:layout_height="@dimen/option_item_size" />
-</LinearLayout>
-
diff --git a/res/layout/clock_host_view.xml b/res/layout/clock_host_view.xml
index 33cca019..d6f52758 100644
--- a/res/layout/clock_host_view.xml
+++ b/res/layout/clock_host_view.xml
@@ -13,7 +13,7 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License.
   -->
-<com.android.customization.picker.clock.ui.view.ClockHostView2
+<com.android.customization.picker.clock.ui.view.ClockConstraintLayoutHostView
     xmlns:android="http://schemas.android.com/apk/res/android"
     android:id="@+id/clock_host_view"
     android:importantForAccessibility="noHideDescendants"
diff --git a/res/layout/clock_style_list_placeholder.xml b/res/layout/clock_style_list_placeholder.xml
deleted file mode 100644
index 48ef9a8d..00000000
--- a/res/layout/clock_style_list_placeholder.xml
+++ /dev/null
@@ -1,37 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?><!--
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
-<LinearLayout
-    xmlns:android="http://schemas.android.com/apk/res/android"
-    android:layout_width="wrap_content"
-    android:layout_height="wrap_content"
-    android:visibility="invisible"
-    android:orientation="vertical">
-
-    <include
-        layout="@layout/clock_style_option"
-        android:layout_width="@dimen/floating_sheet_clock_style_option_size"
-        android:layout_height="@dimen/floating_sheet_clock_style_option_size" />
-
-    <View
-        android:layout_width="match_parent"
-        android:layout_height="@dimen/floating_sheet_list_item_vertical_space"/>
-
-    <include
-        layout="@layout/clock_style_option"
-        android:layout_width="@dimen/floating_sheet_clock_style_option_size"
-        android:layout_height="@dimen/floating_sheet_clock_style_option_size" />
-</LinearLayout>
-
diff --git a/res/layout/clock_style_option.xml b/res/layout/clock_style_option.xml
index fd72e85c..e251c4a6 100644
--- a/res/layout/clock_style_option.xml
+++ b/res/layout/clock_style_option.xml
@@ -14,30 +14,43 @@
      limitations under the License.
 -->
 <!-- Content description is set programmatically on the parent FrameLayout -->
-<FrameLayout
-    xmlns:android="http://schemas.android.com/apk/res/android"
-    android:layout_width="@dimen/floating_sheet_clock_style_option_size"
-    android:layout_height="@dimen/floating_sheet_clock_style_option_size">
+<androidx.constraintlayout.widget.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="@dimen/floating_sheet_clock_style_option_width"
+    android:layout_height="@dimen/floating_sheet_clock_style_option_height"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:clipToPadding="false"
+    android:clipChildren="false">
 
-    <ImageView
-        android:id="@id/selection_border"
-        android:layout_width="match_parent"
-        android:layout_height="match_parent"
-        android:background="@drawable/option_item_border"
-        android:alpha="0"
-        android:importantForAccessibility="no" />
-
-    <ImageView
+    <com.android.wallpaper.picker.option.ui.view.OptionItemBackground
         android:id="@id/background"
-        android:layout_width="match_parent"
-        android:layout_height="match_parent"
-        android:background="@drawable/option_item_background"
-        android:importantForAccessibility="no" />
+        android:layout_width="@dimen/floating_sheet_clock_style_option_background_size"
+        android:layout_height="@dimen/floating_sheet_clock_style_option_background_size"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintBottom_toBottomOf="parent"
+        android:importantForAccessibility="no"
+        android:layout_gravity="bottom" />
+
 
     <ImageView
         android:id="@+id/foreground"
-        android:layout_width="match_parent"
-        android:layout_height="match_parent"
-        android:layout_margin="@dimen/floating_sheet_clock_style_thumbnail_margin" />
-</FrameLayout>
+        android:layout_width="@dimen/floating_sheet_clock_style_option_thumbnail_size"
+        android:layout_height="@dimen/floating_sheet_clock_style_option_thumbnail_size"
+        android:layout_marginBottom="@dimen/floating_sheet_clock_style_thumbnail_margin_bottom"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintBottom_toBottomOf="parent"
+        android:src="@drawable/ic_clock_24px" />
+
+    <ImageView
+        android:id="@+id/edit_icon"
+        android:layout_width="@dimen/floating_sheet_clock_edit_icon_size"
+        android:layout_height="@dimen/floating_sheet_clock_edit_icon_size"
+        android:layout_marginTop="@dimen/floating_sheet_clock_edit_icon_margin"
+        android:layout_marginEnd="@dimen/floating_sheet_clock_edit_icon_margin"
+        android:src="@drawable/edit_icon"
+        app:layout_constraintEnd_toEndOf="@+id/background"
+        app:layout_constraintTop_toTopOf="@+id/background"
+        android:importantForAccessibility="no" />
+</androidx.constraintlayout.widget.ConstraintLayout>
 
diff --git a/res/layout/color_option2.xml b/res/layout/color_option2.xml
new file mode 100644
index 00000000..2605da9c
--- /dev/null
+++ b/res/layout/color_option2.xml
@@ -0,0 +1,22 @@
+<?xml version="1.0" encoding="utf-8"?><!--
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
+<!-- Content description is set programmatically on the parent FrameLayout -->
+<com.android.customization.picker.color.ui.view.ColorOptionIconView2
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@id/background"
+    android:layout_width="@dimen/floating_sheet_color_option_size"
+    android:layout_height="@dimen/floating_sheet_color_option_size"/>
+
diff --git a/res/layout/customization_option_entry_app_shape_and_grid.xml b/res/layout/customization_option_entry_app_shape_grid.xml
similarity index 91%
rename from res/layout/customization_option_entry_app_shape_and_grid.xml
rename to res/layout/customization_option_entry_app_shape_grid.xml
index ea6da465..8d18e7c5 100644
--- a/res/layout/customization_option_entry_app_shape_and_grid.xml
+++ b/res/layout/customization_option_entry_app_shape_grid.xml
@@ -24,20 +24,20 @@
     android:clickable="true">
 
     <TextView
-        android:id="@+id/option_entry_app_grid_title"
+        android:id="@+id/option_entry_app_shape_grid_title"
         style="@style/CustomizationOptionEntryTitleTextStyle"
         android:layout_width="0dp"
         android:layout_height="wrap_content"
-        android:text="@string/grid_title"
+        android:text="@string/shape_and_grid_title"
         android:layout_marginEnd="@dimen/customization_option_entry_text_margin_end"
         app:layout_constraintStart_toStartOf="parent"
         app:layout_constraintEnd_toStartOf="@+id/option_entry_app_grid_icon_container"
-        app:layout_constraintBottom_toTopOf="@+id/option_entry_app_grid_description"
+        app:layout_constraintBottom_toTopOf="@+id/option_entry_app_shape_grid_description"
         app:layout_constraintTop_toTopOf="parent"
         app:layout_constraintVertical_chainStyle="packed" />
 
     <TextView
-        android:id="@+id/option_entry_app_grid_description"
+        android:id="@+id/option_entry_app_shape_grid_description"
         style="@style/CustomizationOptionEntrySubtitleTextStyle"
         android:layout_width="0dp"
         android:layout_height="wrap_content"
@@ -45,7 +45,7 @@
         app:layout_constraintBottom_toBottomOf="parent"
         app:layout_constraintEnd_toStartOf="@+id/option_entry_app_grid_icon_container"
         app:layout_constraintStart_toStartOf="parent"
-        app:layout_constraintTop_toBottomOf="@+id/option_entry_app_grid_title" />
+        app:layout_constraintTop_toBottomOf="@+id/option_entry_app_shape_grid_title" />
 
     <FrameLayout
         android:id="@+id/option_entry_app_grid_icon_container"
@@ -58,7 +58,7 @@
         app:layout_constraintBottom_toBottomOf="parent">
 
         <ImageView
-            android:id="@+id/option_entry_app_grid_icon"
+            android:id="@+id/option_entry_app_shape_grid_icon"
             android:layout_width="match_parent"
             android:layout_height="match_parent"
             android:contentDescription="@string/grid_preview_card_content_description" />
diff --git a/res/layout/customization_option_entry_clock.xml b/res/layout/customization_option_entry_clock.xml
index c302965d..f677a1e6 100644
--- a/res/layout/customization_option_entry_clock.xml
+++ b/res/layout/customization_option_entry_clock.xml
@@ -30,18 +30,24 @@
         android:text="@string/clock_title"
         android:layout_marginEnd="@dimen/customization_option_entry_text_margin_end"
         app:layout_constraintStart_toStartOf="parent"
-        app:layout_constraintEnd_toStartOf="@+id/option_entry_clock_icon"
+        app:layout_constraintEnd_toStartOf="@+id/option_entry_clock_icon_container"
         app:layout_constraintBottom_toBottomOf="parent"
         app:layout_constraintTop_toTopOf="parent"
         app:layout_constraintVertical_chainStyle="packed" />
 
     <FrameLayout
-        android:id="@+id/option_entry_clock_icon"
+        android:id="@+id/option_entry_clock_icon_container"
         android:layout_width="@dimen/customization_option_entry_icon_size"
         android:layout_height="@dimen/customization_option_entry_icon_size"
-        android:orientation="horizontal"
         android:background="@drawable/customization_option_entry_icon_background"
         app:layout_constraintEnd_toEndOf="parent"
         app:layout_constraintTop_toTopOf="parent"
-        app:layout_constraintBottom_toBottomOf="parent" />
+        app:layout_constraintBottom_toBottomOf="parent">
+
+        <ImageView
+            android:id="@+id/option_entry_clock_icon"
+            android:layout_width="@dimen/customization_option_entry_clock_icon_size"
+            android:layout_height="@dimen/customization_option_entry_clock_icon_size"
+            android:layout_gravity="center"/>
+    </FrameLayout>
 </androidx.constraintlayout.widget.ConstraintLayout>
diff --git a/res/layout/floating_sheet_clock.xml b/res/layout/floating_sheet_clock.xml
index 9ca8f1a3..93cf24b6 100644
--- a/res/layout/floating_sheet_clock.xml
+++ b/res/layout/floating_sheet_clock.xml
@@ -24,164 +24,70 @@
         android:id="@+id/clock_floating_sheet_content_container"
         android:layout_width="match_parent"
         android:layout_height="wrap_content"
-        android:paddingVertical="@dimen/floating_sheet_content_vertical_padding"
         android:background="@drawable/floating_sheet_content_background"
         android:clipToPadding="false"
         android:clipChildren="false">
 
-        <FrameLayout
+        <include
+            layout="@layout/floating_sheet_clock_style_content"
             android:id="@+id/clock_floating_sheet_style_content"
             android:layout_width="match_parent"
-            android:layout_height="wrap_content"
-            android:clipToPadding="false"
-            android:clipChildren="false">
-
-            <!--
-            This is an invisible placeholder put in place so that the parent keeps its height
-            stable as the RecyclerView updates from 0 items to N items. Keeping it stable allows
-            the layout logic to keep the size of the preview container stable as well, which
-            bodes well for setting up the SurfaceView for remote rendering without changing its
-            size after the content is loaded into the RecyclerView.
-
-            It's critical for any TextViews inside the included layout to have text.
-            -->
-            <include
-                layout="@layout/clock_style_list_placeholder"
-                android:layout_width="wrap_content"
-                android:layout_height="wrap_content"
-                android:visibility="invisible" />
-
-            <androidx.recyclerview.widget.RecyclerView
-                android:id="@+id/clock_style_list"
-                android:layout_width="match_parent"
-                android:layout_height="wrap_content"
-                android:clipChildren="false"
-                android:clipToPadding="false"/>
-        </FrameLayout>
+            android:layout_height="wrap_content" />
 
-
-        <LinearLayout
+        <include
+            layout="@layout/floating_sheet_clock_color_content"
             android:id="@+id/clock_floating_sheet_color_content"
             android:layout_width="match_parent"
-            android:layout_height="wrap_content"
-            android:orientation="vertical"
-            android:clipToPadding="false"
-            android:clipChildren="false">
+            android:layout_height="wrap_content" />
 
-            <FrameLayout
-                android:layout_width="match_parent"
-                android:layout_height="wrap_content"
-                android:clipToPadding="false"
-                android:clipChildren="false"
-                android:layout_marginBottom="12dp">
-
-                <!--
-                This is an invisible placeholder put in place so that the parent keeps its height
-                stable as the RecyclerView updates from 0 items to N items. Keeping it stable allows
-                the layout logic to keep the size of the preview container stable as well, which
-                bodes well for setting up the SurfaceView for remote rendering without changing its
-                size after the content is loaded into the RecyclerView.
-
-                It's critical for any TextViews inside the included layout to have text.
-                -->
-                <include
-                    layout="@layout/clock_color_list_placeholder"
-                    android:layout_width="wrap_content"
-                    android:layout_height="wrap_content"
-                    android:visibility="invisible" />
+        <include
+            layout="@layout/floating_sheet_clock_font_content"
+            android:id="@+id/clock_floating_sheet_font_content"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content" />
+    </FrameLayout>
 
-                <androidx.recyclerview.widget.RecyclerView
-                    android:id="@+id/clock_color_list"
-                    android:layout_width="match_parent"
-                    android:layout_height="wrap_content"
-                    android:clipChildren="false"
-                    android:clipToPadding="false" />
-            </FrameLayout>
+    <FrameLayout
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_marginVertical="@dimen/floating_sheet_tab_toolbar_vertical_margin">
 
+        <!-- Invisible placeholder to make sure the view does not shrink in height when the floating
+         toolbar visibility is gone -->
+        <include
+            layout="@layout/floating_toolbar_tab"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginVertical="@dimen/floating_tab_toolbar_padding_vertical"
+            android:visibility="invisible" />
 
-            <SeekBar
-                android:id="@+id/clock_color_slider"
-                android:layout_width="match_parent"
-                android:layout_height="wrap_content"
-                android:layout_gravity="center_vertical"
-                android:paddingHorizontal="@dimen/floating_sheet_content_horizontal_padding"
-                android:minHeight="@dimen/touch_target_min_height"
-                android:thumb="@null"
-                android:contentDescription="@string/accessibility_clock_slider_description"
-                android:background="@null"
-                android:progressDrawable="@drawable/saturation_progress_drawable"
-                android:splitTrack="false" />
-        </LinearLayout>
+        <com.android.wallpaper.picker.customization.ui.view.FloatingToolbar
+            android:id="@+id/floating_toolbar"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_gravity="center" />
 
         <LinearLayout
-            android:id="@+id/clock_floating_sheet_size_content"
-            android:layout_width="match_parent"
+            android:id="@+id/clock_font_toolbar"
+            android:layout_width="wrap_content"
             android:layout_height="wrap_content"
             android:orientation="horizontal"
-            android:showDividers="middle"
-            android:baselineAligned="false"
-            android:divider="@drawable/horizontal_divider_16dp"
-            android:paddingVertical="@dimen/floating_sheet_content_vertical_padding"
-            android:paddingHorizontal="@dimen/floating_sheet_content_horizontal_padding">
+            android:layout_gravity="center_horizontal">
 
-            <LinearLayout
-                android:id="@+id/clock_size_option_dynamic"
-                android:layout_width="0dp"
+            <ImageView
+                android:id="@+id/clock_font_revert"
+                android:layout_width="wrap_content"
                 android:layout_height="wrap_content"
-                android:layout_weight="1"
-                android:orientation="vertical"
-                android:gravity="center_horizontal">
-                <ImageView
-                    android:layout_width="@dimen/floating_sheet_clock_size_icon_size"
-                    android:layout_height="@dimen/floating_sheet_clock_size_icon_size"
-                    android:background="#ff00ff"
-                    android:layout_marginBottom="@dimen/floating_sheet_clock_size_icon_margin_bottom" />
-                <TextView
-                    android:layout_width="wrap_content"
-                    android:layout_height="wrap_content"
-                    android:textAppearance="@style/SectionTitleTextStyle"
-                    android:gravity="center"
-                    android:text="@string/clock_size_dynamic"/>
-                <TextView
-                    android:layout_width="wrap_content"
-                    android:layout_height="wrap_content"
-                    android:textAppearance="@style/SectionSubtitleTextStyle"
-                    android:gravity="center"
-                    android:text="@string/clock_size_dynamic_description"/>
-            </LinearLayout>
+                android:src="@drawable/clock_font_revert"
+                android:contentDescription="@string/clock_font_editor_revert" />
 
-            <LinearLayout
-                android:id="@+id/clock_size_option_small"
-                android:layout_width="0dp"
+            <ImageView
+                android:id="@+id/clock_font_apply"
+                android:layout_width="wrap_content"
                 android:layout_height="wrap_content"
-                android:layout_weight="1"
-                android:orientation="vertical"
-                android:gravity="center_horizontal">
-                <ImageView
-                    android:layout_width="@dimen/floating_sheet_clock_size_icon_size"
-                    android:layout_height="@dimen/floating_sheet_clock_size_icon_size"
-                    android:background="#ff00ff"
-                    android:layout_marginBottom="@dimen/floating_sheet_clock_size_icon_margin_bottom" />
-                <TextView
-                    android:layout_width="wrap_content"
-                    android:layout_height="wrap_content"
-                    android:textAppearance="@style/SectionTitleTextStyle"
-                    android:gravity="center"
-                    android:text="@string/clock_size_small"/>
-                <TextView
-                    android:layout_width="wrap_content"
-                    android:layout_height="wrap_content"
-                    android:textAppearance="@style/SectionSubtitleTextStyle"
-                    android:gravity="center"
-                    android:text="@string/clock_size_small_description"/>
-            </LinearLayout>
+                android:paddingStart="@dimen/clock_font_apply_padding_start"
+                android:src="@drawable/clock_font_apply"
+                android:contentDescription="@string/clock_font_editor_apply" />
         </LinearLayout>
     </FrameLayout>
-
-    <com.android.wallpaper.picker.customization.ui.view.FloatingToolbar
-        android:id="@+id/floating_toolbar"
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:layout_gravity="center_horizontal"
-        android:layout_marginVertical="@dimen/floating_sheet_tab_toolbar_vertical_margin" />
 </LinearLayout>
diff --git a/res/layout/floating_sheet_clock_color_content.xml b/res/layout/floating_sheet_clock_color_content.xml
new file mode 100644
index 00000000..fd218c66
--- /dev/null
+++ b/res/layout/floating_sheet_clock_color_content.xml
@@ -0,0 +1,68 @@
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
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:paddingVertical="@dimen/floating_sheet_content_vertical_padding"
+    android:orientation="vertical"
+    android:clipToPadding="false"
+    android:clipChildren="false">
+
+    <FrameLayout
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:clipToPadding="false"
+        android:clipChildren="false"
+        android:layout_marginBottom="@dimen/floating_sheet_clock_color_option_list_bottom_margin">
+
+        <!--
+        This is an invisible placeholder put in place so that the parent keeps its height
+        stable as the RecyclerView updates from 0 items to N items. Keeping it stable allows
+        the layout logic to keep the size of the preview container stable as well, which
+        bodes well for setting up the SurfaceView for remote rendering without changing its
+        size after the content is loaded into the RecyclerView.
+
+        It's critical for any TextViews inside the included layout to have text.
+        -->
+        <include
+            layout="@layout/color_option"
+            android:layout_width="@dimen/option_item_size"
+            android:layout_height="@dimen/option_item_size"
+            android:visibility="invisible" />
+
+        <androidx.recyclerview.widget.RecyclerView
+            android:id="@+id/clock_color_list"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:clipChildren="false"
+            android:clipToPadding="false" />
+    </FrameLayout>
+
+    <SeekBar
+        android:id="@+id/clock_color_slider"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_gravity="center_vertical"
+        android:paddingHorizontal="@dimen/floating_sheet_content_horizontal_padding"
+        android:minHeight="@dimen/touch_target_min_height"
+        android:thumb="@null"
+        android:contentDescription="@string/accessibility_clock_slider_description"
+        android:background="@null"
+        android:progressDrawable="@drawable/saturation_progress_drawable"
+        android:splitTrack="false" />
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/floating_sheet_clock_font_content.xml b/res/layout/floating_sheet_clock_font_content.xml
new file mode 100644
index 00000000..3ce65e44
--- /dev/null
+++ b/res/layout/floating_sheet_clock_font_content.xml
@@ -0,0 +1,161 @@
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
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/clock_floating_sheet_font_content"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:paddingVertical="@dimen/floating_sheet_content_vertical_padding"
+    android:paddingHorizontal="@dimen/floating_sheet_content_horizontal_padding"
+    android:clipChildren="false"
+    android:clipToPadding="false">
+
+    <TextView
+        android:id="@+id/clock_axis_slider_name1"
+        android:layout_width="@dimen/clock_font_axis_name_width"
+        android:layout_height="wrap_content"
+        app:layout_constraintTop_toTopOf="parent"
+        app:layout_constraintBottom_toTopOf="@+id/barrier1"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toStartOf="@+id/clock_axis_slider1"
+        android:layout_marginVertical="@dimen/clock_axis_control_slider_row_margin_vertical"
+        android:layout_marginEnd="@dimen/clock_axis_control_text_margin_end"
+        android:lines="1"
+        android:ellipsize="end"
+        style="@style/CustomizationOptionEntryTitleTextStyle"
+        android:text="@string/tab_placeholder_text" />
+
+    <SeekBar
+        android:id="@+id/clock_axis_slider1"
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:minHeight="@dimen/accessibility_min_height"
+        app:layout_constraintTop_toTopOf="parent"
+        app:layout_constraintBottom_toTopOf="@+id/barrier1"
+        app:layout_constraintStart_toEndOf="@+id/clock_axis_slider_name1"
+        app:layout_constraintEnd_toEndOf="parent"
+        android:layout_marginVertical="@dimen/clock_axis_control_slider_row_margin_vertical"
+        android:background="@null"
+        android:progressDrawable="@drawable/saturation_progress_drawable"
+        android:splitTrack="false"
+        android:thumb="@null" />
+
+    <androidx.constraintlayout.widget.Barrier
+        android:id="@+id/barrier1"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        app:barrierDirection="bottom"
+        app:constraint_referenced_ids="clock_axis_slider1,clock_axis_slider_name1" />
+
+    <TextView
+        android:id="@+id/clock_axis_slider_name2"
+        android:layout_width="@dimen/clock_font_axis_name_width"
+        android:layout_height="wrap_content"
+        app:layout_constraintTop_toBottomOf="@+id/barrier1"
+        app:layout_constraintBottom_toTopOf="@+id/barrier2"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toStartOf="@+id/clock_axis_slider2"
+        android:layout_marginVertical="@dimen/clock_axis_control_slider_row_margin_vertical"
+        android:layout_marginEnd="@dimen/clock_axis_control_text_margin_end"
+        android:lines="1"
+        android:ellipsize="end"
+        style="@style/CustomizationOptionEntryTitleTextStyle"
+        android:text="@string/tab_placeholder_text" />
+
+    <SeekBar
+        android:id="@+id/clock_axis_slider2"
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:minHeight="@dimen/accessibility_min_height"
+        app:layout_constraintTop_toBottomOf="@+id/barrier1"
+        app:layout_constraintBottom_toTopOf="@+id/barrier2"
+        app:layout_constraintStart_toEndOf="@+id/clock_axis_slider_name2"
+        app:layout_constraintEnd_toEndOf="parent"
+        android:layout_marginVertical="@dimen/clock_axis_control_slider_row_margin_vertical"
+        android:background="@null"
+        android:progressDrawable="@drawable/saturation_progress_drawable"
+        android:splitTrack="false"
+        android:thumb="@null" />
+
+    <androidx.constraintlayout.widget.Barrier
+        android:id="@+id/barrier2"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        app:barrierDirection="bottom"
+        app:constraint_referenced_ids="clock_axis_slider2,clock_axis_slider_name2" />
+
+    <TextView
+        android:id="@+id/clock_axis_switch_name1"
+        android:layout_width="@dimen/clock_font_axis_name_width"
+        android:layout_height="wrap_content"
+        app:layout_constraintTop_toBottomOf="@+id/barrier2"
+        app:layout_constraintBottom_toBottomOf="parent"
+        app:layout_constraintStart_toStartOf="parent"
+        android:layout_marginVertical="@dimen/clock_axis_control_switch_row_margin_vertical"
+        android:lines="1"
+        android:ellipsize="end"
+        style="@style/CustomizationOptionEntryTitleTextStyle"
+        android:text="@string/tab_placeholder_text" />
+
+    <Switch
+        android:id="@+id/clock_axis_switch1"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        app:layout_constraintTop_toBottomOf="@+id/barrier2"
+        app:layout_constraintBottom_toBottomOf="parent"
+        app:layout_constraintStart_toEndOf="@+id/clock_axis_switch_name1"
+        android:layout_marginVertical="@dimen/clock_axis_control_switch_row_margin_vertical"
+        android:layout_marginStart="@dimen/clock_axis_control_text_margin_end"
+        style="@style/Switch.SettingsLib" />
+
+    <ImageView
+        android:id="@+id/divider"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        app:layout_constraintTop_toBottomOf="@+id/barrier2"
+        app:layout_constraintBottom_toBottomOf="parent"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintHorizontal_bias="0.5"
+        android:src="@drawable/clock_font_switch_divider"
+        android:importantForAccessibility="no" />
+
+    <TextView
+        android:id="@+id/clock_axis_switch_name2"
+        android:layout_width="@dimen/clock_font_axis_name_width"
+        android:layout_height="wrap_content"
+        app:layout_constraintTop_toBottomOf="@+id/barrier2"
+        app:layout_constraintBottom_toBottomOf="parent"
+        app:layout_constraintEnd_toStartOf="@+id/clock_axis_switch2"
+        android:layout_marginVertical="@dimen/clock_axis_control_switch_row_margin_vertical"
+        android:layout_marginEnd="@dimen/clock_axis_control_text_margin_end"
+        android:lines="1"
+        android:ellipsize="end"
+        style="@style/CustomizationOptionEntryTitleTextStyle"
+        android:text="@string/tab_placeholder_text" />
+
+    <Switch
+        android:id="@+id/clock_axis_switch2"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        app:layout_constraintTop_toBottomOf="@+id/barrier2"
+        app:layout_constraintBottom_toBottomOf="parent"
+        app:layout_constraintEnd_toEndOf="parent"
+        android:layout_marginVertical="@dimen/clock_axis_control_switch_row_margin_vertical"
+        style="@style/Switch.SettingsLib" />
+</androidx.constraintlayout.widget.ConstraintLayout>
\ No newline at end of file
diff --git a/res/layout/floating_sheet_clock_style_content.xml b/res/layout/floating_sheet_clock_style_content.xml
new file mode 100644
index 00000000..5b39776a
--- /dev/null
+++ b/res/layout/floating_sheet_clock_style_content.xml
@@ -0,0 +1,99 @@
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
+<androidx.constraintlayout.widget.ConstraintLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:paddingTop="@dimen/floating_sheet_clock_style_content_top_padding"
+    android:paddingBottom="@dimen/floating_sheet_clock_style_content_bottom_padding"
+    android:clipToPadding="false"
+    android:clipChildren="false">
+
+    <FrameLayout
+        android:id="@+id/clock_style_list_container"
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintTop_toTopOf="parent"
+        app:layout_constraintBottom_toTopOf="@+id/clock_style_clock_size_title"
+        android:layout_marginBottom="@dimen/floating_sheet_clock_style_option_list_margin_bottom"
+        android:clipToPadding="false"
+        android:clipChildren="false">
+
+        <!--
+        This is an invisible placeholder put in place so that the parent keeps its height
+        stable as the RecyclerView updates from 0 items to N items. Keeping it stable allows
+        the layout logic to keep the size of the preview container stable as well, which
+        bodes well for setting up the SurfaceView for remote rendering without changing its
+        size after the content is loaded into the RecyclerView.
+
+        It's critical for any TextViews inside the included layout to have text.
+        -->
+        <include
+            layout="@layout/clock_style_option"
+            android:layout_width="@dimen/floating_sheet_clock_style_option_width"
+            android:layout_height="@dimen/floating_sheet_clock_style_option_height"
+            android:visibility="invisible" />
+
+        <androidx.recyclerview.widget.RecyclerView
+            android:id="@+id/clock_style_list"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:clipChildren="false"
+            android:clipToPadding="false"/>
+    </FrameLayout>
+
+    <TextView
+        android:id="@+id/clock_style_clock_size_title"
+        style="@style/CustomizationOptionEntryTitleTextStyle"
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:text="@string/clock_size_large"
+        android:layout_marginTop="8dp"
+        android:layout_marginStart="@dimen/floating_sheet_content_horizontal_padding"
+        android:layout_marginEnd="@dimen/floating_sheet_clock_style_clock_size_text_margin_end"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toStartOf="@+id/clock_style_clock_size_switch"
+        app:layout_constraintTop_toBottomOf="@+id/clock_style_list_container"
+        app:layout_constraintBottom_toTopOf="@+id/clock_style_clock_size_description" />
+
+    <TextView
+        android:id="@+id/clock_style_clock_size_description"
+        style="@style/CustomizationOptionEntrySubtitleTextStyle"
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:layout_marginStart="@dimen/floating_sheet_content_horizontal_padding"
+        android:layout_marginEnd="@dimen/floating_sheet_clock_style_clock_size_text_margin_end"
+        android:text="@string/clock_size_dynamic_description"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toStartOf="@+id/clock_style_clock_size_switch"
+        app:layout_constraintTop_toBottomOf="@+id/clock_style_clock_size_title"
+        app:layout_constraintBottom_toBottomOf="parent" />
+
+    <Switch
+        android:id="@+id/clock_style_clock_size_switch"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginEnd="@dimen/floating_sheet_content_horizontal_padding"
+        app:layout_constraintTop_toTopOf="@+id/clock_style_clock_size_title"
+        app:layout_constraintBottom_toBottomOf="@+id/clock_style_clock_size_description"
+        app:layout_constraintEnd_toEndOf="parent"
+        style="@style/Switch.SettingsLib"
+        tools:ignore="UseSwitchCompatOrMaterialXml" />
+</androidx.constraintlayout.widget.ConstraintLayout>
diff --git a/res/layout/floating_sheet_colors.xml b/res/layout/floating_sheet_colors.xml
index a22b2644..f8cfc986 100644
--- a/res/layout/floating_sheet_colors.xml
+++ b/res/layout/floating_sheet_colors.xml
@@ -25,7 +25,8 @@
         android:layout_height="wrap_content"
         android:background="@drawable/floating_sheet_content_background"
         android:paddingVertical="@dimen/floating_sheet_content_vertical_padding"
-        android:orientation="vertical">
+        android:orientation="vertical"
+        android:clipChildren="false">
 
         <TextView
             android:id="@+id/color_type_tab_subhead"
@@ -68,7 +69,6 @@
                 android:layout_width="wrap_content"
                 android:layout_height="wrap_content"
                 android:background="@null"
-                android:clickable="false"
                 android:focusable="false"
                 android:minHeight="0dp" />
         </LinearLayout>
diff --git a/res/layout/floating_sheet_shape_and_grid.xml b/res/layout/floating_sheet_shape_and_grid.xml
deleted file mode 100644
index 01a7a89e..00000000
--- a/res/layout/floating_sheet_shape_and_grid.xml
+++ /dev/null
@@ -1,54 +0,0 @@
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
-
-<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
-    android:layout_width="match_parent"
-    android:layout_height="wrap_content"
-    android:paddingHorizontal="@dimen/floating_sheet_horizontal_padding"
-    android:orientation="vertical">
-
-    <FrameLayout
-        android:layout_width="match_parent"
-        android:layout_height="wrap_content"
-        android:paddingVertical="@dimen/floating_sheet_content_vertical_padding"
-        android:background="@drawable/floating_sheet_content_background"
-        android:clipToPadding="false"
-        android:clipChildren="false">
-
-        <!--
-        This is just an invisible placeholder put in place so that the parent keeps its height
-        stable as the RecyclerView updates from 0 items to N items. Keeping it stable allows the
-        layout logic to keep the size of the preview container stable as well, which bodes well
-        for setting up the SurfaceView for remote rendering without changing its size after the
-        content is loaded into the RecyclerView.
-
-        It's critical for any TextViews inside the included layout to have text.
-        -->
-        <include
-            layout="@layout/grid_option"
-            android:layout_width="wrap_content"
-            android:layout_height="wrap_content"
-            android:visibility="invisible" />
-
-        <androidx.recyclerview.widget.RecyclerView
-            android:id="@id/options"
-            android:layout_width="wrap_content"
-            android:layout_height="wrap_content"
-            android:layout_gravity="center_horizontal"
-            android:clipToPadding="false"
-            android:clipChildren="false" />
-    </FrameLayout>
-</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/floating_sheet_shape_grid.xml b/res/layout/floating_sheet_shape_grid.xml
new file mode 100644
index 00000000..4e2409bb
--- /dev/null
+++ b/res/layout/floating_sheet_shape_grid.xml
@@ -0,0 +1,103 @@
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:paddingHorizontal="@dimen/floating_sheet_horizontal_padding"
+    android:orientation="vertical">
+
+    <FrameLayout
+        android:id="@+id/shape_grid_floating_sheet_content_container"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:background="@drawable/floating_sheet_content_background"
+        android:paddingVertical="@dimen/floating_sheet_content_vertical_padding"
+        android:orientation="vertical"
+        android:clipToPadding="false"
+        android:clipChildren="false">
+
+        <FrameLayout
+            android:id="@+id/app_shape_container"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:clipToPadding="false"
+            android:clipChildren="false">
+
+            <!--
+            This is just an invisible placeholder put in place so that the parent keeps its height
+            stable as the RecyclerView updates from 0 items to N items. Keeping it stable allows the
+            layout logic to keep the size of the preview container stable as well, which bodes well
+            for setting up the SurfaceView for remote rendering without changing its size after the
+            content is loaded into the RecyclerView.
+
+            It's critical for any TextViews inside the included layout to have text.
+            -->
+            <include
+                layout="@layout/shape_option"
+                android:layout_width="64dp"
+                android:layout_height="64dp"
+                android:visibility="invisible" />
+
+            <androidx.recyclerview.widget.RecyclerView
+                android:id="@+id/shape_options"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:layout_gravity="center_horizontal"
+                android:clipToPadding="false"
+                android:clipChildren="false" />
+        </FrameLayout>
+
+        <FrameLayout
+            android:id="@+id/app_grid_container"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:clipToPadding="false"
+            android:clipChildren="false">
+
+            <!--
+            This is just an invisible placeholder put in place so that the parent keeps its height
+            stable as the RecyclerView updates from 0 items to N items. Keeping it stable allows the
+            layout logic to keep the size of the preview container stable as well, which bodes well
+            for setting up the SurfaceView for remote rendering without changing its size after the
+            content is loaded into the RecyclerView.
+
+            It's critical for any TextViews inside the included layout to have text.
+            -->
+            <include
+                layout="@layout/grid_option"
+                android:id="@+id/invisible_grid_option"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:visibility="invisible"/>
+
+            <androidx.recyclerview.widget.RecyclerView
+                android:id="@+id/grid_options"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:clipToPadding="false"
+                android:clipChildren="false"
+                android:layout_gravity="center_horizontal" />
+        </FrameLayout>
+    </FrameLayout>
+
+    <com.android.wallpaper.picker.customization.ui.view.FloatingToolbar
+        android:id="@+id/floating_toolbar"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_gravity="center_horizontal"
+        android:layout_marginVertical="@dimen/floating_sheet_tab_toolbar_vertical_margin" />
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/fragment_clock_picker.xml b/res/layout/fragment_clock_picker.xml
index 8ca48631..ee4a24d7 100644
--- a/res/layout/fragment_clock_picker.xml
+++ b/res/layout/fragment_clock_picker.xml
@@ -62,10 +62,10 @@
             <Space
                 android:id="@+id/placeholder"
                 android:layout_width="match_parent"
-                android:layout_height="@dimen/min_taptarget_height"
+                android:layout_height="@dimen/accessibility_min_height"
                 app:layout_constraintBottom_toTopOf="@id/apply_button"
                 app:layout_constraintEnd_toEndOf="parent"
-                app:layout_constraintHeight_min="@dimen/min_taptarget_height"
+                app:layout_constraintHeight_min="@dimen/accessibility_min_height"
                 app:layout_constraintHorizontal_bias="0.0"
                 app:layout_constraintStart_toStartOf="parent"
                 app:layout_constraintTop_toBottomOf="@id/options_container"
diff --git a/res/layout/fragment_clock_settings.xml b/res/layout/fragment_clock_settings.xml
index 75dae7e8..d6ccaba7 100644
--- a/res/layout/fragment_clock_settings.xml
+++ b/res/layout/fragment_clock_settings.xml
@@ -150,7 +150,7 @@
                     android:layout_width="match_parent"
                     android:layout_height="wrap_content"
                     android:layout_gravity="center_vertical"
-                    android:minHeight="48dp"
+                    android:minHeight="@dimen/accessibility_min_height"
                     android:thumb="@null"
                     android:contentDescription="@string/accessibility_clock_slider_description"
                     android:background="@null"
@@ -169,6 +169,7 @@
                 <RadioButton android:id="@+id/radio_dynamic"
                     android:layout_width="wrap_content"
                     android:layout_height="wrap_content"
+                    android:minHeight="@dimen/accessibility_min_height"
                     android:paddingStart="8dp"
                     android:maxLines="3"
                     android:ellipsize="end"
@@ -178,6 +179,7 @@
                 <RadioButton android:id="@+id/radio_small"
                     android:layout_width="wrap_content"
                     android:layout_height="wrap_content"
+                    android:minHeight="@dimen/accessibility_min_height"
                     android:paddingStart="8dp"
                     android:maxLines="3"
                     android:ellipsize="end"
diff --git a/res/layout/grid_option2.xml b/res/layout/grid_option2.xml
new file mode 100644
index 00000000..437b95bd
--- /dev/null
+++ b/res/layout/grid_option2.xml
@@ -0,0 +1,63 @@
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
+
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:layout_width="@dimen/option_item_size"
+    android:layout_height="wrap_content"
+    android:orientation="vertical"
+    android:gravity="center_horizontal"
+    android:clipChildren="false">
+
+    <FrameLayout
+        android:layout_width="@dimen/option_item_size"
+        android:layout_height="@dimen/option_item_size"
+        android:clipChildren="false">
+
+        <com.android.wallpaper.picker.option.ui.view.OptionItemBackground
+            android:id="@id/background"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:background="@drawable/option_item_background"
+            android:importantForAccessibility="no" />
+
+        <ImageView
+            android:id="@id/foreground"
+            android:layout_width="48dp"
+            android:layout_height="48dp"
+            android:layout_gravity="center" />
+
+    </FrameLayout>
+
+    <View
+        android:layout_width="0dp"
+        android:layout_height="8dp" />
+
+    <TextView
+        android:id="@id/text"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:textColor="@color/system_on_surface"
+        android:singleLine="true"
+        android:ellipsize="end"
+        android:textSize="12sp"
+        android:text="Placeholder for stable size calculation, please do not remove."
+        tools:ignore="HardcodedText" />
+
+</LinearLayout>
diff --git a/res/layout/quick_affordance_list_item2.xml b/res/layout/quick_affordance_list_item2.xml
new file mode 100644
index 00000000..9dd75576
--- /dev/null
+++ b/res/layout/quick_affordance_list_item2.xml
@@ -0,0 +1,58 @@
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
+<androidx.constraintlayout.widget.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="@dimen/keyguard_quick_affordance_background_size"
+    android:layout_height="wrap_content"
+    android:clipChildren="false">
+
+    <com.android.wallpaper.picker.option.ui.view.OptionItemBackground
+        android:id="@id/background"
+        android:layout_width="0dp"
+        android:layout_height="@dimen/keyguard_quick_affordance_background_size"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintTop_toTopOf="parent"
+        app:layout_constraintBottom_toTopOf="@id/text"
+        android:layout_marginBottom="@dimen/keyguard_quick_affordance_background_margin_bottom"
+        android:importantForAccessibility="no" />
+
+    <ImageView
+        android:id="@id/foreground"
+        android:layout_width="@dimen/keyguard_quick_affordance_icon_size"
+        android:layout_height="@dimen/keyguard_quick_affordance_icon_size"
+        app:layout_constraintStart_toStartOf="@id/background"
+        app:layout_constraintEnd_toEndOf="@id/background"
+        app:layout_constraintTop_toTopOf="@id/background"
+        app:layout_constraintBottom_toBottomOf="@id/background"
+        android:tint="@color/system_on_surface"
+        android:importantForAccessibility="no" />
+
+    <TextView
+        android:id="@id/text"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintTop_toBottomOf="@id/background"
+        app:layout_constraintBottom_toBottomOf="parent"
+        android:gravity="center_horizontal"
+        android:textColor="@color/system_on_surface"
+        android:lines="2"
+        android:hyphenationFrequency="normal"
+        android:ellipsize="end" />
+</androidx.constraintlayout.widget.ConstraintLayout>
\ No newline at end of file
diff --git a/res/layout/shape_option.xml b/res/layout/shape_option.xml
new file mode 100644
index 00000000..d2eb2f2a
--- /dev/null
+++ b/res/layout/shape_option.xml
@@ -0,0 +1,44 @@
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
+<FrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="64dp"
+    android:layout_height="64dp"
+    android:clipChildren="false">
+
+    <ImageView
+        android:id="@id/selection_border"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:background="@drawable/option_item_border"
+        android:alpha="0"
+        android:importantForAccessibility="no" />
+
+    <ImageView
+        android:id="@id/background"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:background="@drawable/option_item_background"
+        android:importantForAccessibility="no" />
+
+    <ImageView
+        android:id="@id/foreground"
+        android:layout_width="40dp"
+        android:layout_height="40dp"
+        android:layout_gravity="center" />
+</FrameLayout>
diff --git a/res/layout/themed_icon_section_view.xml b/res/layout/themed_icon_section_view.xml
index 84ef3e84..b6e745b0 100644
--- a/res/layout/themed_icon_section_view.xml
+++ b/res/layout/themed_icon_section_view.xml
@@ -50,19 +50,4 @@
             style="@style/Switch.SettingsLib"/>
 
     </LinearLayout>
-
-    <Space
-        android:layout_width="0dp"
-        android:layout_height="8dp" />
-
-    <TextView
-        android:id="@+id/beta_tag"
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:paddingHorizontal="8dp"
-        android:paddingVertical="4dp"
-        android:text="@string/beta_title"
-        android:textColor="@color/text_color_on_accent"
-        style="@style/BetaTagTextStyle" />
-
 </com.android.customization.picker.themedicon.ThemedIconSectionView>
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 0f14a04f..40b79d99 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Groot"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Klein"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"’n Klein horlosie word in die hoek van jou skerm gewys"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Pas horlosiefontveranderinge toe"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Ontdoen horlosiefontveranderinge"</string>
     <string name="grid_title" msgid="1688173478777254123">"Approoster"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Appvorm &amp; uitleg"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Uitleg"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Pas toe"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Tik om te wysig"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Hou huidige muurpapier"</string>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index 2eaab87f..34e22a56 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"ትልቅ"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"ትንሽ"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"በእርስዎ ማያ ገፅ ጥግ ላይ ትንሽ ሰዓት ይታያል"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"የሰዓት ቅርጸ-ቁምፊ ለውጦችን ተግብር"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"የሰዓት ቅርጸ-ቁምፊ ለውጦችን ቀልብስ"</string>
     <string name="grid_title" msgid="1688173478777254123">"የመተግበሪያ ፍርግርግ"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"የመተግበሪያ ቅርጽ እና አቀማመጥ"</string>
+    <string name="grid_layout" msgid="370175667652663686">"አቀማመጥ"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"ተግብር"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"ለማርትዕ መታ ያድርጉ"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"የአሁኑን ልጣፍ ያቆዩት"</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 6056defd..188564c6 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"كبير"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"صغير"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"تظهر ساعة صغيرة في زاوية الشاشة"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"تطبيق التغييرات على خط الساعة"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"التراجع عن التغييرات على خط الساعة"</string>
     <string name="grid_title" msgid="1688173478777254123">"شبكة التطبيقات"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"شكل التطبيق وتصميمه"</string>
+    <string name="grid_layout" msgid="370175667652663686">"التصميم"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"تطبيق"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"انقُر للتعديل."</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"الاحتفاظ بالخلفية الحالية"</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index e4418d57..0091ff38 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"ডাঙৰ"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"সৰু"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"আপোনাৰ স্ক্ৰীনখনৰ চুকত এটা সৰু ঘড়ীয়ে দেখুৱায়"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"ঘড়ীৰ ফণ্টত কৰা সালসলনি প্ৰয়োগ কৰক"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"ঘড়ীৰ ফণ্টত কৰা সালসলনি আনডু কৰক"</string>
     <string name="grid_title" msgid="1688173478777254123">"এপৰ গ্ৰিড"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"এপৰ আকৃতি আৰু লে’আউট"</string>
+    <string name="grid_layout" msgid="370175667652663686">"লে’আউট"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"প্ৰয়োগ কৰক"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"সম্পাদনা কৰিবলৈ টিপক"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"বৰ্তমানৰ ৱালপেপাৰখন ৰাখক"</string>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 76c2725c..e64868da 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Böyük"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Kiçik"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Ekranın mərkəzində kiçik saat görünür"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Saat şrifti dəyişikliklərini tətbiq edin"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Saat şrifti dəyişikliklərini geri qaytarın"</string>
     <string name="grid_title" msgid="1688173478777254123">"Tətbiq toru"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Tətbiq forması və düzən"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Düzən"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Tətbiq edin"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Redaktə etmək üçün klikləyin"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Cari divar kağızını saxlayın"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 59ef2592..b52cbf2a 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Veliko"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Mali"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Mali sat se prikazuje u uglu ekrana"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Primenite promene fonta sata"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Opozovite promene fonta sata"</string>
     <string name="grid_title" msgid="1688173478777254123">"Mreža apl."</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Oblik i izgled"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Izgled"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Primeni"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Dodirnite da biste izmenili"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Zadrži aktuelnu pozadinu"</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 1005abf8..324a0a3b 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Вялікі"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Дробны"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Невялікі гадзіннік у вугле экрана"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Прымяніць змяненні шрыфту гадзінніка"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Адрабіць змяненні шрыфту гадзінніка"</string>
     <string name="grid_title" msgid="1688173478777254123">"Сетка праграм"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Форма і кампаноўка праграмы"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Макет"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Ужыць"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Дакраніцеся, каб рэдагаваць"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Захаваць бягучыя шпалеры"</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index f64a0181..78046ebb 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Голям"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Малък"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"В ъгъла на екрана се показва малък часовник"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Прилагане на промените на шрифта на часовника"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Отмяна на промените на шрифта на часовника"</string>
     <string name="grid_title" msgid="1688173478777254123">"Решетка с прил."</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Оформление и форма"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Оформление"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Прилагане"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Докоснете, за да редактирате"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Запазване на текущия тапет"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 8ef1f377..bc15b9ae 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"বড়"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"ছোট করুন"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"স্ক্রিনের কোনায় একটি ছোট ঘড়ি দেখানো হয়"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"ঘড়ির ফন্ট পরিবর্তন প্রয়োগ করুন"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"ঘড়ির ফন্ট পরিবর্তনকে আগের অবস্থায় ফিরিয়ে আনুন"</string>
     <string name="grid_title" msgid="1688173478777254123">"অ্যাপ গ্রিড"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"অ্যাপ শেপ ও লেআউট"</string>
+    <string name="grid_layout" msgid="370175667652663686">"লেআউট"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"প্রয়োগ করুন"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"এডিট করতে ট্যাপ করুন"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"এখন যে ওয়ালপেপার আছে সেটি রাখুন"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 9bd52e2c..fae80c23 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Veliko"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Malo"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Mali sat se prikazuje u uglu vašeg ekrana"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Primjena promjena fonta na satu"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Poništavanje promjena fonta na satu"</string>
     <string name="grid_title" msgid="1688173478777254123">"Mreža aplikacija"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Oblik i raspored apl."</string>
+    <string name="grid_layout" msgid="370175667652663686">"Raspored"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Primijeni"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Dodirnite da uredite"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Zadrži trenutnu pozadinsku sliku"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 94ec7587..c9f1d4ef 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Gran"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Petit"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Es mostra un rellotge petit a l\'extrem de la pantalla"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Aplica els canvis de font del rellotge"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Desfés els canvis de font del rellotge"</string>
     <string name="grid_title" msgid="1688173478777254123">"Quadrícula d\'apps"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Forma i disseny d\'app"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Disseny"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Aplica"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Toca per editar"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Mantén el fons de pantalla actual"</string>
@@ -74,7 +78,7 @@
     <string name="applied_theme_msg" msgid="3749018706366796244">"L\'estil s\'ha definit correctament"</string>
     <string name="applied_clock_msg" msgid="1303338016701443767">"El rellotge s\'ha definit correctament"</string>
     <string name="applied_grid_msg" msgid="3250499654436933034">"La quadrícula s\'ha definit correctament"</string>
-    <string name="apply_theme_error_msg" msgid="791364062636538317">"S\'ha produït un error en aplicar l\'estil"</string>
+    <string name="apply_theme_error_msg" msgid="791364062636538317">"Hi ha hagut un error en aplicar l\'estil"</string>
     <string name="custom_theme_next" msgid="6235420097213197301">"Següent"</string>
     <string name="custom_theme_previous" msgid="4941132112640503022">"Anterior"</string>
     <string name="custom_theme" msgid="1618351922263478163">"Personalitzat"</string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index aa174004..9dd309f7 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Velká"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Malá"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"V rohu obrazovky se zobrazují malé hodiny"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Použít změny písma hodin"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Vrátit změny písma hodin zpět"</string>
     <string name="grid_title" msgid="1688173478777254123">"Mřížka aplikací"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Tvar a rovrž."</string>
+    <string name="grid_layout" msgid="370175667652663686">"Rozvržení"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Použít"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Klepnutím upravte"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Zachovat stávající tapetu"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index 42a87602..ed25013a 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Stor"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Lille"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Et lille ur vises i hjørnet af skærmen"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Anvend ændringerne af urets skrifttype"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Fortryd ændringerne af urets skrifttype"</string>
     <string name="grid_title" msgid="1688173478777254123">"Appgitter"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Appform og layout"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Layout"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Anvend"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Tryk for at redigere"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Behold den aktuelle baggrund"</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index 07f05dc2..6a07aaf2 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Groß"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Klein"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Eine kleine Uhr wird in der Ecke des Displays angezeigt"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Uhr-Schriftart ändern"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Änderungen an Uhr-Schriftart rückgängig machen"</string>
     <string name="grid_title" msgid="1688173478777254123">"App-Raster"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Formen &amp; Layouts"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Layout"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Anwenden"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Zum Bearbeiten tippen"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Aktuellen Hintergrund behalten"</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index a4eb1b94..a746f7c5 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Μεγάλο"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Μικρό"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Ένα μικρό ρολόι εμφανίζεται στη γωνία της οθόνης"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Εφαρμογή αλλαγών στη γραμματοσειρά ρολογιού"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Αναίρεση αλλαγών στη γραμματοσειρά ρολογιού"</string>
     <string name="grid_title" msgid="1688173478777254123">"Πλέγμα εφαρμ."</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Σχήμα, διάταξη"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Διάταξη"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Εφαρμογή"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Πατήστε για επεξεργασία"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Διατήρηση τρέχουσας ταπετσαρίας"</string>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index d280efdf..7ac89393 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Large"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Small"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"A small clock shows in the corner of your screen"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Apply clock font changes"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Undo clock font changes"</string>
     <string name="grid_title" msgid="1688173478777254123">"App grid"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"App shape and layout"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Layout"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Apply"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Tap to edit"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Keep current wallpaper"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index dbfbe94a..06b00ac6 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Large"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Small"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"A small clock shows in the corner of your screen"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Apply clock font changes"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Undo clock font changes"</string>
     <string name="grid_title" msgid="1688173478777254123">"App grid"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"App shape &amp; layout"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Layout"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Apply"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Tap to edit"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Keep current wallpaper"</string>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index d280efdf..7ac89393 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Large"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Small"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"A small clock shows in the corner of your screen"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Apply clock font changes"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Undo clock font changes"</string>
     <string name="grid_title" msgid="1688173478777254123">"App grid"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"App shape and layout"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Layout"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Apply"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Tap to edit"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Keep current wallpaper"</string>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index d280efdf..7ac89393 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Large"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Small"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"A small clock shows in the corner of your screen"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Apply clock font changes"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Undo clock font changes"</string>
     <string name="grid_title" msgid="1688173478777254123">"App grid"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"App shape and layout"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Layout"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Apply"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Tap to edit"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Keep current wallpaper"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 25546011..64e3d258 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Grande"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Pequeño"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Aparece un reloj pequeño en la esquina de tu pantalla"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Aplica cambios a la fuente del reloj"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Deshace cambios a la fuente del reloj"</string>
     <string name="grid_title" msgid="1688173478777254123">"Cuadrícula de apps"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Forma y diseño"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Diseño"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Aplicar"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Presiona para editar"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Conservar fondo de pantalla actual"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 753d3a75..b6190249 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Grande"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Pequeño"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Se muestra un pequeño reloj en la esquina de la pantalla"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Aplicar cambios de fuente del reloj"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Deshacer cambios de fuente del reloj"</string>
     <string name="grid_title" msgid="1688173478777254123">"Cuadrícula de apps"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Forma y diseño"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Diseño"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Aplicar"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Toca para editar"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Mantener fondo de pantalla actual"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 3275eed7..e25e35cd 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Suur"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Väike"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Ekraaninurgas kuvatakse väike kell"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Kella fondi muudatuste rakendamine"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Kella fondi muudatuste tagasivõtmine"</string>
     <string name="grid_title" msgid="1688173478777254123">"Rak. ruudustik"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Rakenduse kuju ja paigutus"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Paigutus"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Rakenda"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Puudutage muutmiseks"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Säilita praegune taustapilt"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 1599ae17..aa172a25 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Handia"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Txikia"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Erloju txiki bat agertzen da pantailaren izkinan"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Aplikatu erlojuaren letrari dagozkion aldaketak"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Desegin erlojuaren letrari dagozkion aldaketak"</string>
     <string name="grid_title" msgid="1688173478777254123">"Aplikazioen sareta"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Aplikazioaren forma eta diseinua"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Diseinua"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Aplikatu"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Sakatu editatzeko"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Utzi bere horretan horma-papera"</string>
@@ -96,7 +100,7 @@
     <string name="use_style_button" msgid="1754493078383627019">"Erabili <xliff:g id="ID_1">%1$s</xliff:g> estiloa"</string>
     <string name="no_thanks" msgid="7286616980115687627">"Ez"</string>
     <string name="clock_preview_content_description" msgid="5460561185905717460">"<xliff:g id="ID_1">%1$s</xliff:g> erlojuaren aurrebista"</string>
-    <string name="something_went_wrong" msgid="529840112449799117">"Arazo bat izan da."</string>
+    <string name="something_went_wrong" msgid="529840112449799117">"Arazoren bat izan da."</string>
     <string name="theme_preview_icons_section_title" msgid="7064768910744000643">"Koloreak / Ikonoak"</string>
     <string name="style_info_description" msgid="2612473574431003251">"Letra-tipoen, ikonoen, aplikazio-formen eta koloreen aurrebista"</string>
     <string name="accessibility_custom_font_title" msgid="966867359157303705">"Letra pertsonalizatua"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index de42d861..b9f48b97 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"بزرگ"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"کوچک"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"ساعت کوچکی در گوشه صفحه‌نمایش شما نشان داده می‌شود"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"اعمال تغییرات قلم ساعت"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"واگرد کردن تغییرات قلم ساعت"</string>
     <string name="grid_title" msgid="1688173478777254123">"شبکه برنامه‌ها"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"شکل و چیدمان برنامه"</string>
+    <string name="grid_layout" msgid="370175667652663686">"چیدمان"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"اعمال"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"برای ویرایش تک‌ضرب بزنید"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"حفظ کاغذدیواری فعلی"</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index fb506490..c936538b 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Suuri"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Pieni"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Näytön reunassa näkyy pieni kello"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Ota kellon fontin muutokset käyttöön"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Kumoa kellon fontin muutokset"</string>
     <string name="grid_title" msgid="1688173478777254123">"Ruudukko"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Muoto ja asettelu"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Asettelu"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Käytä"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Muokkaa napauttamalla"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Säilytä nykyinen taustakuva"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 250eba4c..48cdef36 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Grande"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Petite"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Une petite horloge s\'affiche dans le coin de votre écran"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Appliquer les modifications de la police de l\'horloge"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Annuler les modifications de la police de l\'horloge"</string>
     <string name="grid_title" msgid="1688173478777254123">"Grille d\'applis"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Mise en page"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Mise en page"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Appliquer"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Toucher pour modifier"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Garder le fond d\'écran actuel"</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index b191e3b9..612101c5 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Grande"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Petite"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Une petite horloge s\'affiche dans le coin de votre écran"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Appliquer les modifications de police de l\'horloge"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Annuler les modifications de police de l\'horloge"</string>
     <string name="grid_title" msgid="1688173478777254123">"Grille d\'applis"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Forme et mise en page de l\'appli"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Mise en page"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Appliquer"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Appuyer pour modifier"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Conserver le fond d\'écran actuel"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index f35bc564..91fdb1ac 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Grande"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Pequeno"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Un pequeno reloxo móstrase na esquina da pantalla"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Aplicar os cambios ao tipo de letra do reloxo"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Desfacer os cambios no tipo de letra do reloxo"</string>
     <string name="grid_title" msgid="1688173478777254123">"Grade de apps"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Deseño e forma"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Deseño"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Aplicar"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Toca para editar"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Conservar fondo de pantalla actual"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 2102a73c..20430ad6 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"મોટું"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"નાનું"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"તમારી સ્ક્રીનના ખૂણામાં એક નાની ઘડિયાળ દેખાય છે"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Clockના ફૉન્ટમાં કરેલા ફેરફારો લાગુ કરો"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Clockના ફૉન્ટમાં છેલ્લે કરેલા ફેરફારો રદ કરો"</string>
     <string name="grid_title" msgid="1688173478777254123">"ઍપ ગ્રિડ"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"ઍપનો આકાર+લેઆઉટ"</string>
+    <string name="grid_layout" msgid="370175667652663686">"લેઆઉટ"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"લાગુ કરો"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"ફેરફાર કરવા માટે ટૅપ કરો"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"હાલનું વૉલપેપર રાખો"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 1457fc5b..ffcb1088 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"बड़ा"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"छोटा"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"आपके डिवाइस की स्क्रीन के कोने में एक छोटी घड़ी दिखती है"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"घड़ी के फ़ॉन्ट में किए गए बदलावों को लागू करें"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"घड़ी के फ़ॉन्ट में किए गए बदलावों को पहले जैसा करें"</string>
     <string name="grid_title" msgid="1688173478777254123">"ऐप्लिकेशन ग्रिड"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"ऐप का शेप और लेआउट"</string>
+    <string name="grid_layout" msgid="370175667652663686">"लेआउट"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"लागू करें"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"बदलाव करने के लिए टैप करें"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"मौजूदा वॉलपेपर बनाए रखें"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 4a7b0bda..dea03bc7 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Velik"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Mali sat"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"U kutu zaslona prikazuje se mali sat"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Primijeni izmjene fonta sata"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Poništi izmjene fonta sata"</string>
     <string name="grid_title" msgid="1688173478777254123">"Rešetka aplikacija"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Oblik i izgled aplikacije"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Izgled"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Primijeni"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Dodirnite da biste uredili"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Zadrži trenutačnu pozadinu"</string>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index 84e2d809..65fb8a1f 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Nagy"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Kicsi"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Megjelenik egy kis óra a képernyő sarkában."</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Az óra betűtípusára vonatkozó módosítások alkalmazása"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Az óra betűtípusára vonatkozó módosítások visszavonása"</string>
     <string name="grid_title" msgid="1688173478777254123">"Alkalmazásrács"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Forma és elrendezés"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Elrendezés"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Alkalmaz"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Koppintson a szerkesztéshez"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Jelenlegi háttérkép megtartása"</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 86cbf9dd..245afa9d 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Մեծ"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Փոքր"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Էկրանի անկյունում ցուցադրվում է փոքրիկ ժամացույց"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Ժամացույցի տառատեսակի փոփոխության կիրառում"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Ժամացույցի տառատեսակի փոփոխության հետարկում"</string>
     <string name="grid_title" msgid="1688173478777254123">"Հավելվածների ցանց"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Ձև և դասավորություն"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Դասավորություն"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Կիրառել"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Հպեք՝ փոփոխելու համար"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Պահպանել ընթացիկ պաստառը"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 60672e57..1ccf8f92 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Besar"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Kecil"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Jam kecil ditampilkan di sudut layar"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Terapkan perubahan font jam"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Urungkan perubahan font jam"</string>
     <string name="grid_title" msgid="1688173478777254123">"Petak aplikasi"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Bentuk &amp; tata letak aplikasi"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Tata letak"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Terapkan"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Ketuk untuk mengedit"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Pertahankan wallpaper saat ini"</string>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index b4fc13e2..649244e0 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Stór"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Lítil"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Lítil klukka birtist í horni skjásins"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Breyta leturgerð klukku"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Afturkalla breytingar á leturgerð klukku"</string>
     <string name="grid_title" msgid="1688173478777254123">"Forritatafla"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Lögun forrits og uppsetning"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Útlit"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Nota"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Ýttu til að breyta"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Halda núverandi veggfóðri"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 37e8b759..016075e3 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Grandi"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Piccole"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Un piccolo orologio visualizzato nell\'angolo dello schermo"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Applica le modifiche al carattere dell\'orologio"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Annulla le modifiche al carattere dell\'orologio"</string>
     <string name="grid_title" msgid="1688173478777254123">"Griglia di app"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Layout/Forma app"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Layout"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Applica"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Tocca per modificare"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Mantieni lo sfondo corrente"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index b8e1c5fd..def91e97 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -43,9 +43,13 @@
     <string name="clock_size_large" msgid="3143248715744138979">"גדול"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"קטן"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"שעון קטן מופיע בפינת המסך"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"אישור של שינויי הגופן בשעון"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"ביטול של שינויי הגופן בשעון"</string>
     <string name="grid_title" msgid="1688173478777254123">"תצוגת האפליקציות"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"הצורה והפריסה של האפליקציה"</string>
+    <string name="grid_layout" msgid="370175667652663686">"פריסה"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"אישור"</string>
-    <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"יש להקיש כדי לערוך"</string>
+    <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"יש ללחוץ כדי לערוך"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"שמירת הטפט הנוכחי"</string>
     <string name="theme_preview_card_content_description" msgid="5989222908619535533">"תצוגה מקדימה של הסגנון"</string>
     <string name="grid_preview_card_content_description" msgid="8449383777584714842">"תצוגה מקדימה של הרשת"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 6f6e0452..9463a32e 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"大"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"小"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"画面の隅に小さい時計を表示します"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"時計のフォント変更を適用"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"時計のフォント変更を元に戻す"</string>
     <string name="grid_title" msgid="1688173478777254123">"アプリグリッド"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"アプリの形状とレイアウト"</string>
+    <string name="grid_layout" msgid="370175667652663686">"レイアウト"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"適用"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"タップして編集"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"現在の壁紙を保持"</string>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index 4a82186d..d4fee279 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"დიდი"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"პატარა"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"პატარა საათი მოთავსებულია თქვენი ეკრანის კუთხეში"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"საათის შრიფტის ცვლილებების გამოყენება"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"საათის შრიფტის ცვლილებების გაუქმება"</string>
     <string name="grid_title" msgid="1688173478777254123">"აპების ბადე"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"აპის ფორმა და განლაგება"</string>
+    <string name="grid_layout" msgid="370175667652663686">"განლაგება"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"მისადაგება"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"შეეხეთ რედაქტირებისთვის"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"ამჟამინდელი ფონის შენარჩუნება"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index b57b8da1..25f424e7 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Үлкен"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Кішi"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Экранның бұрышында шағын сағат көрсетіледі."</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Сағат қаріпі өзгерістерін қолдану"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Сағат қаріпі өзгерістерінен бас тарту"</string>
     <string name="grid_title" msgid="1688173478777254123">"Қолданбалар торы"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Пішін, формат"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Формат"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Қолдану"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Өзгерту үшін түртіңіз"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Қазіргі тұсқағазды қалдыру"</string>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index fbd03b9e..187a2eb8 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"ធំ"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"តូច"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"នាឡិកា​តូចមួយ​បង្ហាញ​នៅជ្រុងនៃ​អេក្រង់​របស់អ្នក"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"អនុវត្តការផ្លាស់ប្ដូរពុម្ពអក្សរនាឡិកា"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"ត្រឡប់ការផ្លាស់ប្ដូរពុម្ពអក្សរនាឡិកាវិញ"</string>
     <string name="grid_title" msgid="1688173478777254123">"ក្រឡា​កម្មវិធី"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"រូបរាង និងប្លង់កម្មវិធី"</string>
+    <string name="grid_layout" msgid="370175667652663686">"ប្លង់"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"ប្រើ"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"ចុច ដើម្បី​កែ"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"រក្សាទុក​ផ្ទាំងរូបភាព​បច្ចុប្បន្ន"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 32d0e487..f5ad7f10 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"ದೊಡ್ಡದು"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"ಚಿಕ್ಕದು"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"ನಿಮ್ಮ ಸ್ಕ್ರೀನ್‌ನ ಮೂಲೆಯಲ್ಲಿ ಸಣ್ಣ ಗಡಿಯಾರವೊಂದು ಕಾಣಿಸುತ್ತದೆ"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"ಕ್ಲಾಕ್ ಫಾಂಟ್ ಬದಲಾವಣೆಗಳನ್ನು ಅನ್ವಯಿಸಿ"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"ಕ್ಲಾಕ್ ಫಾಂಟ್ ಬದಲಾವಣೆಗಳನ್ನು ರದ್ದುಗೊಳಿಸಿ"</string>
     <string name="grid_title" msgid="1688173478777254123">"ಆ್ಯಪ್ ಗ್ರಿಡ್"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"ಆ್ಯಪ್ ಆಕಾರ, ಲೇಔಟ್"</string>
+    <string name="grid_layout" msgid="370175667652663686">"ಲೇಔಟ್"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"ಅನ್ವಯಿಸಿ"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"ಎಡಿಟ್ ಮಾಡಲು ಟ್ಯಾಪ್ ಮಾಡಿ"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"ಪ್ರಸ್ತುತ ವಾಲ್‌ಪೇಪರ್ ಅನ್ನು ಉಳಿಸಿ"</string>
@@ -90,7 +94,7 @@
     <string name="delete_custom_theme_confirmation" msgid="4452137183628769394">"ಕಸ್ಟಮ್ ಶೈಲಿಯನ್ನು ಅಳಿಸುವುದೇ?"</string>
     <string name="delete_custom_theme_button" msgid="5102462988130208824">"ಅಳಿಸಿ"</string>
     <string name="cancel" msgid="4651030493668562067">"ರದ್ದುಗೊಳಿಸಿ"</string>
-    <string name="set_theme_wallpaper_dialog_message" msgid="2179661027350908003">"ಶೈಲಿ ವಾಲ್‌ಪೇಪರ್ ಹೊಂದಿಸಿ"</string>
+    <string name="set_theme_wallpaper_dialog_message" msgid="2179661027350908003">"ಶೈಲಿ ವಾಲ್‌ಪೇಪರ್ ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="use_style_instead_title" msgid="1578754995763917502">"ಬದಲಿಗೆ <xliff:g id="ID_1">%1$s</xliff:g> ಬಳಸಬೇಕೆ?"</string>
     <string name="use_style_instead_body" msgid="3051937045807471496">"ನೀವು ಆಯ್ಕೆ ಮಾಡುವ ಘಟಕಗಳು <xliff:g id="ID_1">%1$s</xliff:g> ಶೈಲಿಗೆ ಹೊಂದಿಕೆಯಾಗಬೇಕು. ಬದಲಿಗೆ ನೀವು <xliff:g id="ID_2">%1$s</xliff:g> ಬಳಸಲು ಬಯಸುವಿರಾ?"</string>
     <string name="use_style_button" msgid="1754493078383627019">"<xliff:g id="ID_1">%1$s</xliff:g> ಅನ್ನು ಬಳಸಿ"</string>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index 8e869d05..3e454815 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"크게"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"작게"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"작은 시계가 화면 모서리에 표시됩니다."</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"시계 글꼴 변경사항 적용"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"시계 글꼴 변경사항 실행취소"</string>
     <string name="grid_title" msgid="1688173478777254123">"앱 그리드"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"앱 모양 및 레이아웃"</string>
+    <string name="grid_layout" msgid="370175667652663686">"레이아웃"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"적용"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"탭하여 수정"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"현재 배경화면 유지"</string>
@@ -127,8 +131,8 @@
     <string name="keyguard_affordance_enablement_dialog_action_template" msgid="8117011931337357438">"<xliff:g id="APPNAME">%1$s</xliff:g> 열기"</string>
     <string name="keyguard_affordance_enablement_dialog_message" msgid="6136286758939253570">"<xliff:g id="APPNAME">%1$s</xliff:g> 앱을 바로가기로 추가하려면 다음을 확인하세요."</string>
     <string name="keyguard_affordance_enablement_dialog_dismiss_button" msgid="629754625264422508">"완료"</string>
-    <string name="keyguard_quick_affordance_title" msgid="4242813186995735584">"단축키"</string>
-    <string name="keyguard_quick_affordance_section_title" msgid="2806304242671717309">"단축키"</string>
+    <string name="keyguard_quick_affordance_title" msgid="4242813186995735584">"바로가기"</string>
+    <string name="keyguard_quick_affordance_section_title" msgid="2806304242671717309">"바로가기"</string>
     <string name="color_contrast_section_title" msgid="7194809124718896091">"색상 대비"</string>
     <string name="color_contrast_default_title" msgid="7954235103549276978">"기본값"</string>
     <string name="color_contrast_medium_title" msgid="8071574793250090215">"중간"</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index fd070ffd..1b153e50 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Чоң"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Кичине"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Кичинекей саат экрандын бурчунда көрүнүп турат"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Саат арибине өзгөртүү киргизүү"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Саат арибинин өзгөртүүсүн кайтаруу"</string>
     <string name="grid_title" msgid="1688173478777254123">"Колдонмолор торчосу"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Формасы, калыбы"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Калып"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Колдонуу"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Өзгөртүү үчүн таптап коюңуз"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Учурдагы тушкагаз калсын"</string>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index 8e44623e..f5064e54 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"ໃຫຍ່"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"ນ້ອຍ"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"ໂມງນ້ອຍທີ່ສະແດງຢູ່ໃນມຸມຂອງໜ້າຈໍທ່ານ"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"ນຳໃຊ້ການປ່ຽນແປງຟອນໂມງ"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"ຍົກເລີກການປ່ຽນແປງຟອນໂມງ"</string>
     <string name="grid_title" msgid="1688173478777254123">"ຕາຕະລາງແອັບ"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"ຮູບຮ່າງ ແລະ ໂຄງຮ່າງແອັບ"</string>
+    <string name="grid_layout" msgid="370175667652663686">"ໂຄງຮ່າງ"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"ນຳໃຊ້"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"ແຕະເພື່ອແກ້ໄຂ"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"ໃຊ້ຮູບພື້ນຫຼັງປັດຈຸບັນ"</string>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index e0c8ffdd..0c5e7cf9 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Didelis"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Mažas"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Ekrano kampe rodomas nedidelis laikrodis"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Taikyti laikrodžio šrifto pakeitimus"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Anuliuoti laikrodžio šrifto pakeitimus"</string>
     <string name="grid_title" msgid="1688173478777254123">"Pr. tinklelis"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Progr. forma ir išd."</string>
+    <string name="grid_layout" msgid="370175667652663686">"Išdėstymas"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Taikyti"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Palieskite ir redaguokite"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Palikti dabartinį ekrano foną"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 68a6d4b2..207138ff 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Liels"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Mazs"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Jūsu ekrāna stūrī tiek rādīts neliels pulkstenis."</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Lietot pulksteņa fonta izmaiņas"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Atsaukt pulksteņa fonta izmaiņas"</string>
     <string name="grid_title" msgid="1688173478777254123">"Lietotņu režģis"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Lietotnes forma un izkārtojums"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Izkārtojums"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Lietot"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Pieskarieties, lai rediģētu"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Paturēt pašreizējo fona tapeti"</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index cd9690b3..8ec9cafb 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Голема"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Мала"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Во аголот на екранот се прикажува мал часовник"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Примени ги промените на фонтот на часовникот"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Врати ги промените на фонтот на часовникот"</string>
     <string name="grid_title" msgid="1688173478777254123">"Мрежа"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Распоред и форма"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Распоред"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Примени"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Допрете за да измените"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Задржи тековен тапет"</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 191c0661..466c1845 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"വലുത്"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"ചെറുത്"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"സ്ക്രീനിന്റെ മൂലയിൽ ഒരു ചെറിയ ക്ലോക്ക് കാണിക്കുന്നു"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"ക്ലോക്ക് ഫോണ്ട് മാറ്റങ്ങൾ ബാധകമാക്കുക"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"ക്ലോക്ക് ഫോണ്ട് മാറ്റങ്ങൾ പഴയപടിയാക്കുക"</string>
     <string name="grid_title" msgid="1688173478777254123">"ആപ്പ് ഗ്രിഡ്"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"ആപ്പ് രൂപവും ലേഔട്ടും"</string>
+    <string name="grid_layout" msgid="370175667652663686">"ലേഔട്ട്"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"പ്രയോഗിക്കുക"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"എഡിറ്റ് ചെയ്യാൻ ടാപ്പ് ചെയ്യുക"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"നിലവിലെ വാൾപേപ്പർ നിലനിർത്തുക"</string>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 2353a9d5..e059399a 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Том"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Жижиг"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Таны дэлгэцийн буланд жижиг цаг харуулдаг"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Цагны фонтын өөрчлөлтүүдийг оруулах"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Цагны фонтын өөрчлөлтүүдийг болих"</string>
     <string name="grid_title" msgid="1688173478777254123">"Аппын хүснэгт"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Аппын хэлбэр, бүдүүвч"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Бүдүүвч"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Ашиглах"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Засахын тулд товшино уу"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Одоогийн дэлгэцийн зургийг хадгалах"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index c5315142..10815028 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"मोठा"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"छोटे"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"तुमच्या स्क्रीनच्या कोपऱ्यामध्ये एक लहान घड्याळ दिसते"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"घड्याळाच्या फॉंटमध्ये बदल लागू करा"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"घड्याळाच्या फॉंटमध्ये केलेले बदल पहिल्यासारखे करा"</string>
     <string name="grid_title" msgid="1688173478777254123">"ॲप ग्रिड"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"अ‍ॅप आकार व लेआउट"</string>
+    <string name="grid_layout" msgid="370175667652663686">"लेआउट"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"लागू करा"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"संपादित करण्‍यासाठी टॅप करा"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"सध्याचा वॉलपेपर ठेवा"</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index fb6a237f..65fe52fc 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Besar"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Kecil"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Jam kecil dipaparkan di penjuru skrin"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Gunakan perubahan fon jam"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Buat asal perubahan fon jam"</string>
     <string name="grid_title" msgid="1688173478777254123">"Grid apl"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Bentuk &amp; reka letak apl"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Reka letak"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Gunakan"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Ketik untuk edit"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Kekalkan kertas dinding semasa"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index 3be7e0bd..a2352eed 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"ကြီး"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"သေး"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"သင့်ဖန်သားပြင်ထောင့်တွင် ပြသထားသော နာရီအသေးတစ်ခု"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"နာရီဖောင့်အပြောင်းအလဲများ သုံးရန်"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"နာရီဖောင့် အပြောင်းအလဲများ နောက်ပြန်ရန်"</string>
     <string name="grid_title" msgid="1688173478777254123">"အက်ပ်ဇယား"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"အက်ပ်ပုံစံ၊ အပြင်အဆင်"</string>
+    <string name="grid_layout" msgid="370175667652663686">"အပြင်အဆင်"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"အသုံးပြုရန်"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"တည်းဖြတ်ရန် တို့ပါ"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"လက်ရှိနောက်ခံပုံ ဆက်ထားရန်"</string>
@@ -132,7 +136,7 @@
     <string name="color_contrast_section_title" msgid="7194809124718896091">"အရောင်ခြားနားမှု"</string>
     <string name="color_contrast_default_title" msgid="7954235103549276978">"မူရင်း"</string>
     <string name="color_contrast_medium_title" msgid="8071574793250090215">"အသင့်အတင့်"</string>
-    <string name="color_contrast_high_title" msgid="5554685752479470200">"များ"</string>
+    <string name="color_contrast_high_title" msgid="5554685752479470200">"မြင့်"</string>
     <string name="keyguard_quick_affordance_two_selected_template" msgid="1757099194522296363">"<xliff:g id="FIRST">%1$s</xliff:g>၊ <xliff:g id="SECOND">%2$s</xliff:g>"</string>
     <string name="keyguard_quick_affordance_none_selected" msgid="8494127020144112003">"မရှိ"</string>
     <string name="show_notifications_on_lock_screen" msgid="4157744243084646720">"အကြောင်းကြားချက်များကို လော့ခ်မျက်နှာပြင်တွင် ပြပါ"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index f4cd48db..e7a6f180 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Stor"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Liten"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"En liten klokke vises i hjørnet av skjermen"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Bruk endringene i klokkeskrifttypen"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Angre endringene i klokkeskrifttypen"</string>
     <string name="grid_title" msgid="1688173478777254123">"Apprutenett"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Appform/-layout"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Oppsett"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Bruk"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Trykk for å endre"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Behold den nåværende bakgrunnen"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 9669e016..95b0a6cf 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"ठुलो"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"सानो"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"तपाईंको स्क्रिनको कुनामा सानो घडी देखा पर्छ"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"घडीको फन्टमा गरिएका परिवर्तनहरू लागू गर्नुहोस्"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"घडीको फन्टमा गरिएका परिवर्तनहरू अन्डू गर्नुहोस्"</string>
     <string name="grid_title" msgid="1688173478777254123">"एप ग्रिड"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"एपको आकार र लेआउट"</string>
+    <string name="grid_layout" msgid="370175667652663686">"लेआउट"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"लागू गर्नुहोस्"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"सम्पादन गर्न ट्याप गर्नुहोस्"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"अहिले कै वालपेपर राख्नुहोस्"</string>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index f8962ba8..1d96ab2d 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Groot"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Klein"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Er wordt een kleine klok weergegeven in de hoek van het scherm"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Wijzigingen in lettertype van klok toepassen"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Wijzigingen in lettertype van klok ongedaan maken"</string>
     <string name="grid_title" msgid="1688173478777254123">"App-raster"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Vorm en indeling van app"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Indeling"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Toepassen"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Tik om te bewerken"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Huidige achtergrond behouden"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index d66efeed..4265f892 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"ବଡ଼"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"ଛୋଟ"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"ଆପଣଙ୍କ ସ୍କ୍ରିନର କୋଣରେ ଏକ ଛୋଟ ଘଣ୍ଟା ଦେଖାଯାଏ"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"ଘଡ଼ିର ଫଣ୍ଟରେ କରାଯାଇଥିବା ପରିବର୍ତ୍ତନକୁ ଲାଗୁ କରନ୍ତୁ"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"ଘଡ଼ିର ଫଣ୍ଟରେ କରାଯାଇଥିବା ପରିବର୍ତ୍ତନକୁ ଅନଡୁ କରନ୍ତୁ"</string>
     <string name="grid_title" msgid="1688173478777254123">"ଆପ ଗ୍ରିଡ"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"ଆପ ଆକାର ଓ ଲେଆଉଟ"</string>
+    <string name="grid_layout" msgid="370175667652663686">"ଲେଆଉଟ"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"ପ୍ରୟୋଗ କରନ୍ତୁ"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"ଏଡିଟ କରିବା ପାଇଁ ଟାପ କରନ୍ତୁ"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"ବର୍ତ୍ତମାନର ୱାଲ୍‌ପେପର୍‌କୁ ରଖନ୍ତୁ"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 66d127b3..05a7823b 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"ਵੱਡਾ"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"ਛੋਟਾ"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"ਤੁਹਾਡੀ ਸਕ੍ਰੀਨ ਦੇ ਕੋਨੇ \'ਤੇ ਇੱਕ ਛੋਟੀ ਘੜੀ ਦਿਖਾਈ ਦਿੰਦੀ ਹੈ"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"ਘੜੀ ਦੇ ਫ਼ੌਟਾਂ ਵਿੱਚ ਕੀਤੀਆਂ ਤਬਦੀਲੀਆਂ ਲਾਗੂ ਕਰੋ"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"ਘੜੀ ਦੇ ਫ਼ੌਟਾਂ ਵਿੱਚ ਕੀਤੀਆਂ ਤਬਦੀਲੀਆਂ ਨੂੰ ਅਣਕੀਤਾ ਕਰੋ"</string>
     <string name="grid_title" msgid="1688173478777254123">"ਐਪ ਗ੍ਰਿਡ"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"ਐਪ ਦੀ ਆਕ੍ਰਿਤੀ ਅਤੇ ਖਾਕਾ"</string>
+    <string name="grid_layout" msgid="370175667652663686">"ਖਾਕਾ"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"ਲਾਗੂ ਕਰੋ"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"ਸੰਪਾਦਨ ਕਰਨ ਲਈ ਟੈਪ ਕਰੋ"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"ਮੌਜੂਦਾ ਵਾਲਪੇਪਰ ਬਰਕਰਾਰ ਰੱਖੋ"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index ea5e4892..45ebcaca 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Duży"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Mały"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Mały zegar wyświetlany w rogu ekranu"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Zastosuj zmiany czcionki zegara"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Cofnij zmiany czcionki zegara"</string>
     <string name="grid_title" msgid="1688173478777254123">"Siatka aplikacji"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Kształt i układ aplikacji"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Układ"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Zastosuj"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Kliknij, by edytować"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Pozostaw bieżącą tapetę"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 57c397c7..c448b7e9 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Grande"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Pequeno"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Um pequeno relógio é apresentado no canto do ecrã"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Aplicar alterações ao tipo de letra do relógio"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Anular alterações ao tipo de letra do relógio"</string>
     <string name="grid_title" msgid="1688173478777254123">"Grelha de apps"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Esquema/forma das apps"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Esquema"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Aplicar"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Toque para editar"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Manter a imagem de fundo atual"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index 4f4dc1ef..ea3b7b79 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Grande"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Pequeno"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Um relógio pequeno aparece no canto da tela"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Aplicar mudanças na fonte do relógio"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Desfazer mudanças na fonte do relógio"</string>
     <string name="grid_title" msgid="1688173478777254123">"Grade de apps"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Formato e layout do app"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Layout"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Aplicar"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Toque para editar"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Manter o plano de fundo atual"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 9e873223..9ec58025 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Mare"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Mică"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Un ceas mic apare în colțul ecranului"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Aplică modificările fontului ceasului"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Anulează modificările fontului ceasului"</string>
     <string name="grid_title" msgid="1688173478777254123">"Grilă aplicații"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Formă și aspect"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Aspect"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Aplică"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Atinge pentru a modifica"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Păstrează imaginea de fundal actuală"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 61ac300a..525e6853 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Большой"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Маленький"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Небольшие часы в углу экрана"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Применить изменения в шрифтах часов"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Отменить изменения в шрифтах часов"</string>
     <string name="grid_title" msgid="1688173478777254123">"Сетка приложений"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Форма прил., макет"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Макет"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Применить"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Нажмите, чтобы изменить"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Использовать текущие обои"</string>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index 84ad1f8b..a651011f 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"විශාල"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"කුඩා"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"ඔබේ තිරයේ කෙළවරේ කුඩා ඔරලෝසුවක් පෙන්වයි"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"ඔරලෝසු අකුරු වෙනස් කිරීම් යොදන්න"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"ඔරලෝසු අකුරු වෙනස් කිරීම් අහෝසි කරන්න"</string>
     <string name="grid_title" msgid="1688173478777254123">"යෙදුම් ජාලකය"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"යෙදුම් හැඩය සහ පිරිසැලසුම"</string>
+    <string name="grid_layout" msgid="370175667652663686">"පිරිසැලසුම"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"යොදන්න"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"සංස්කරණයට තට්ටු කරන්න"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"වත්මන් බිතුපත තබා ගන්න"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index adc03233..71552ae4 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Veľké"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Malé"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"V rohu obrazovky sa zobrazujú malé hodiny"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Použiť zmeny písma ciferníka"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Vrátiť zmeny písma ciferníka"</string>
     <string name="grid_title" msgid="1688173478777254123">"Mriežka aplikácií"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Tvar a rozloženie"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Rozloženie"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Použiť"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Klepnutím upravte"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Ponechať aktuálnu tapetu"</string>
@@ -108,7 +112,7 @@
     <string name="mode_title" msgid="2394873501427436055">"Tmavý motív"</string>
     <string name="mode_disabled_msg" msgid="9196245518435936512">"Dočasne vypnuté šetričom batérie"</string>
     <string name="mode_changed" msgid="2243581369395418584">"Motív bol zmenený"</string>
-    <string name="themed_icon_title" msgid="7312460430471956558">"Prefarbené ikony"</string>
+    <string name="themed_icon_title" msgid="7312460430471956558">"Ikony s motívom"</string>
     <string name="beta_title" msgid="8703819523760746458">"Beta"</string>
     <string name="gird_picker_entry_content_description" msgid="9087651470212293439">"Zmeniť mriežku aplikácií"</string>
     <string name="wallpaper_color_tab" msgid="1447926591721403840">"Farby tapety"</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index b53b7429..decab8ce 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Velika"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Majhna"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"V kotu zaslona je prikazana majhna ura."</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Uporabi spremembe pisave ure"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Razveljavi spremembe pisave ure"</string>
     <string name="grid_title" msgid="1688173478777254123">"Mreža aplikacij"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Oblika in postavitev aplikacije"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Postavitev"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Uporabi"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Dotaknite se za urejanje"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Obdrži trenutno ozadje"</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index b7f21116..71fb5fb3 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"E madhe"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"E vogël"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Në këndin e ekranit shfaqet një orë e vogël"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Zbato ndryshimet e fontit të orës"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Zhbëj ndryshimet e fontit të orës"</string>
     <string name="grid_title" msgid="1688173478777254123">"Rrjeta e aplikacioneve"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Forma e struktura e aplikacionit"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Struktura"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Zbato"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Trokit për të modifikuar"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Mbaj imazhin aktual të sfondit"</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 6824fd93..4ee4b2d9 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Велико"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Мали"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Мали сат се приказује у углу екрана"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Примените промене фонта сата"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Опозовите промене фонта сата"</string>
     <string name="grid_title" msgid="1688173478777254123">"Мрежа апл."</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Облик и изглед"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Изглед"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Примени"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Додирните да бисте изменили"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Задржи актуелну позадину"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index 4326de91..51c8058e 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Stor"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Liten"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"En liten klockas visas i skärmens hörn"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Tillämpa ändringar av klockans teckensnitt"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Ångra ändringar av klockans teckensnitt"</string>
     <string name="grid_title" msgid="1688173478777254123">"Apprutnät"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Form och layout"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Layout"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Använd"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Tryck för att redigera"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Behåll befintlig bakgrund"</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 40a426ba..6fd1b01c 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Kubwa"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Ndogo"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Saa ndogo inaonekana kwenye kona ya skrini yako"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Tumia mabadiliko ya fonti ya saa"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Tendua mabadiliko ya fonti ya saa"</string>
     <string name="grid_title" msgid="1688173478777254123">"Gridi ya programu"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Muundo na umbo la programu"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Muundo"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Tumia"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Gusa ili ubadilishe"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Tumia mandhari ya sasa"</string>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index a3427842..d8012b3e 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"பெரியது"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"சிறியது"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"உங்கள் திரையின் மூலையில் ஒரு சிறிய கடிகாரம் காட்டப்படும்"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"கடிகார எழுத்து வடிவ மாற்றங்களைப் பயன்படுத்தும்"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"கடிகார எழுத்து வடிவ மாற்றங்களைச் செயல்தவிர்க்கும்"</string>
     <string name="grid_title" msgid="1688173478777254123">"ஆப்ஸ் கட்டம்"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"ஆப்ஸ் வடிவம் &amp; தளவமைப்பு"</string>
+    <string name="grid_layout" msgid="370175667652663686">"தளவமைப்பு"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"பயன்படுத்து"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"\'தீமைத்\' திருத்த தட்டவும்"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"தற்போதைய வால்பேப்பரே இருக்கட்டும்"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index d292914b..6e984a4a 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"పెద్దది"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"చిన్నది"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"మీ స్క్రీన్ మూలన ఒక చిన్న గడియారం కనిపిస్తుంది"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"క్లాక్ ఫాంట్ మార్పులను వర్తింపజేయండి"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"క్లాక్ ఫాంట్ మార్పులను చర్య రద్దు చేయండి"</string>
     <string name="grid_title" msgid="1688173478777254123">"యాప్ గ్రిడ్"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"యాప్ షేప్ &amp; లేఅవుట్"</string>
+    <string name="grid_layout" msgid="370175667652663686">"లేఅవుట్"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"వర్తింపజేయి"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"ఎడిట్ చేయడానికి నొక్కండి"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"ప్రస్తుత వాల్‌పేపర్‌ను అలాగే ఉంచండి"</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index b0e70460..75986a9f 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"ใหญ่"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"เล็ก"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"นาฬิกาขนาดเล็กจะแสดงที่มุมของหน้าจอ"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"ใช้การเปลี่ยนแปลงแบบอักษรของนาฬิกา"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"เลิกทำการเปลี่ยนแปลงแบบอักษรของนาฬิกา"</string>
     <string name="grid_title" msgid="1688173478777254123">"ตารางกริดแอป"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"รูปร่างและเลย์เอาต์แอป"</string>
+    <string name="grid_layout" msgid="370175667652663686">"เลย์เอาต์"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"ใช้"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"แตะเพื่อแก้ไข"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"ใช้วอลเปเปอร์ปัจจุบัน"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 00778e5e..35c6a8b8 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Malaki"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Maliit"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"May makikitang maliit na orasan sa sulok ng iyong screen"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Ilapat ang mga pagbabago sa font ng orasan"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"I-undo ang mga pagbabago sa font ng orasan"</string>
     <string name="grid_title" msgid="1688173478777254123">"Grid ng app"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Shape ng app at layout"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Layout"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Ilapat"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"I-tap para ma-edit"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Gamitin ang kasalukuyang wallpaper"</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 7852cdd5..7d446908 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Büyük"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Küçük"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Ekranınızın köşesinde küçük bir saat görünür"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Saat yazı tipi değişikliklerini uygula"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Saat yazı tipi değişikliklerini geri al"</string>
     <string name="grid_title" msgid="1688173478777254123">"Uygulama tablosu"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Uygulama şekli ve düzeni"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Düzen"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Uygula"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Düzenlemek için dokunun"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Geçerli duvar kağıdını sakla"</string>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index 486a51d3..a675883c 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Великий"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Малий"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"У куті екрана відображається маленький годинник"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Застосувати зміни шрифту годинника"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Скасувати зміни шрифту годинника"</string>
     <string name="grid_title" msgid="1688173478777254123">"Сітка додатків"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Форма й макет додатка"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Макет"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Застосувати"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Торкніться, щоб змінити"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Зберегти поточний фоновий малюнок"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 019de1f7..8f5bb64b 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"بڑا"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"چھوٹا"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"آپ کی اسکرین کے کونے میں ایک چھوٹی گھڑی دکھائی دیتی ہے"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"گھڑی کے فونٹ کی تبدیلیاں لاگو کریں"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"گھڑی کے فونٹ کی تبدیلیاں کالعدم کریں"</string>
     <string name="grid_title" msgid="1688173478777254123">"ایپ گرڈ"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"ایپ شیپ و لے آؤٹ"</string>
+    <string name="grid_layout" msgid="370175667652663686">"لے آؤٹ"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"لاگو کریں"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"ترمیم کرنے کے لیے تھپتھپائيں"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"حالیہ وال پیپر رکھیں"</string>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index 4f3cb774..2f882658 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -40,10 +40,14 @@
     <string name="clock_size" msgid="5028923902364418263">"Hajmi"</string>
     <string name="clock_size_dynamic" msgid="1023930312455061642">"Dinamik"</string>
     <string name="clock_size_dynamic_description" msgid="2776620745774561662">"Soat hajmi ekran qulfidagi kontent asosida oʻzgaradi"</string>
-    <string name="clock_size_large" msgid="3143248715744138979">"Yirik"</string>
+    <string name="clock_size_large" msgid="3143248715744138979">"Katta"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Kichik"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Ekran chekkasida kichik soat chiqishi"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Soat shrifti oʻzgarishlarini qoʻllash"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Soat shrifti oʻzgarishlarini bekor qilish"</string>
     <string name="grid_title" msgid="1688173478777254123">"Ilovalar jadvali"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Ilova shakli va maketi"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Maket"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Tatbiq etish"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Tahrirlash uchun tegining"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Joriy fon rasmini saqlab qolish"</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index f775f3db..060152cd 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Lớn"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Nhỏ"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Một chiếc đồng hồ nhỏ hiển thị ở góc màn hình"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Áp dụng các thay đổi về phông chữ đồng hồ"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Huỷ các thay đổi về phông chữ đồng hồ"</string>
     <string name="grid_title" msgid="1688173478777254123">"Lưới ứng dụng"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Hình dạng ứng dụng và bố cục"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Bố cục"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Áp dụng"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Nhấn để chỉnh sửa"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Giữ hình nền hiện tại"</string>
diff --git a/res/values-w800dp/dimens.xml b/res/values-w800dp/dimens.xml
index d5032b6a..5673be45 100644
--- a/res/values-w800dp/dimens.xml
+++ b/res/values-w800dp/dimens.xml
@@ -23,4 +23,5 @@
     <dimen name="clock_carousel_item_card_width">114dp</dimen>
     <dimen name="clock_carousel_item_card_height">124dp</dimen>
     <dimen name="clock_carousel_guideline_margin">320dp</dimen>
+    <item name="clock_carousel_scale" format="float" type="dimen">0.35</item>
 </resources>
\ No newline at end of file
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 9502ceff..1e5278bf 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"大"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"小"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"一个小型时钟显示在界面一角"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"应用时钟字体更改"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"撤消时钟字体更改"</string>
     <string name="grid_title" msgid="1688173478777254123">"应用网格"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"应用形状和布局"</string>
+    <string name="grid_layout" msgid="370175667652663686">"布局"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"应用"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"点按即可修改"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"保留当前壁纸"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 6ebc6da1..0fb72662 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"大"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"小"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"在螢幕角落顯示小時鐘"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"套用時鐘字型變更"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"復原時鐘字型變更"</string>
     <string name="grid_title" msgid="1688173478777254123">"應用程式網格"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"應用程式形狀與版面配置"</string>
+    <string name="grid_layout" msgid="370175667652663686">"版面配置"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"套用"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"輕按即可編輯"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"保留目前桌布"</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index cf0a4ed5..93df262b 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"大"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"小"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"在畫面角落顯示小型時鐘"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"套用時鐘字型變更"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"取消時鐘字型變更"</string>
     <string name="grid_title" msgid="1688173478777254123">"應用程式排列顯示"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"應用程式的形狀和版面配置"</string>
+    <string name="grid_layout" msgid="370175667652663686">"版面配置"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"套用"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"輕觸這裡即可編輯"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"繼續使用目前的桌布"</string>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index 4056a719..9ef934c4 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -43,7 +43,11 @@
     <string name="clock_size_large" msgid="3143248715744138979">"Obukhulu"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Esincane"</string>
     <string name="clock_size_small_description" msgid="4089511196955732480">"Iwashi elincane livela ekhoneni lesikrini sakho"</string>
+    <string name="clock_font_editor_apply" msgid="5965611025879105293">"Faka izinguquko zefonti yewashi"</string>
+    <string name="clock_font_editor_revert" msgid="5307491447405753061">"Hlehlisa ushintsho lwefonti yewashi"</string>
     <string name="grid_title" msgid="1688173478777254123">"Igridi ye-app"</string>
+    <string name="shape_and_grid_title" msgid="9092477491363761054">"Umumo we-app nesakhiwo"</string>
+    <string name="grid_layout" msgid="370175667652663686">"Isakhiwo"</string>
     <string name="apply_theme_btn" msgid="6293081192321303991">"Faka"</string>
     <string name="edit_custom_theme_lbl" msgid="5211377705710775224">"Thepha ukuze uhlele"</string>
     <string name="keep_my_wallpaper" msgid="8012385376769568517">"Gcina isithombe sangemuva samanje"</string>
diff --git a/res/values/dimens.xml b/res/values/dimens.xml
index 6a923d9a..4f1062fa 100644
--- a/res/values/dimens.xml
+++ b/res/values/dimens.xml
@@ -122,8 +122,6 @@
     <!-- For a corner radius of this size or larger, we'll preview a rounded qsb widget. -->
     <dimen name="roundCornerThreshold">16dp</dimen>
 
-    <dimen name="min_taptarget_height">48dp</dimen>
-
     <!--  For the style info preview sheet. -->
     <dimen name="theme_info_margin">12dp</dimen>
     <dimen name="theme_info_icon_size">24dp</dimen>
@@ -159,6 +157,8 @@
     <dimen name="keyguard_quick_affordance_icon_container_size">74dp</dimen>
     <!-- Size for the icon of a quick affordance for the lock screen in the picker experience. -->
     <dimen name="keyguard_quick_affordance_icon_size">24dp</dimen>
+    <dimen name="keyguard_quick_affordance_background_size">64dp</dimen>
+    <dimen name="keyguard_quick_affordance_background_margin_bottom">8dp</dimen>
 
     <dimen name="clock_carousel_item_width">190dp</dimen>
     <dimen name="clock_carousel_item_margin">16dp</dimen>
@@ -166,6 +166,7 @@
     <dimen name="clock_carousel_item_card_width">100dp</dimen>
     <dimen name="clock_carousel_item_card_height">108dp</dimen>
     <dimen name="clock_carousel_guideline_margin_for_2_pane_small_width">122dp</dimen>
+    <item name="clock_carousel_scale" format="float" type="dimen">0.5</item>
 
     <!-- Clock color and size button -->
     <dimen name="clock_color_size_button_min_height">32dp</dimen>
@@ -181,13 +182,34 @@
     <!-- Floating sheet dimensions -->
     <dimen name="floating_sheet_content_vertical_padding">20dp</dimen>
     <dimen name="floating_sheet_content_horizontal_padding">20dp</dimen>
+    <dimen name="floating_sheet_clock_style_content_top_padding">2dp</dimen>
+    <dimen name="floating_sheet_clock_style_content_bottom_padding">20dp</dimen>
     <dimen name="floating_sheet_horizontal_padding">16dp</dimen>
     <dimen name="floating_sheet_tab_toolbar_vertical_margin">8dp</dimen>
+    <dimen name="floating_sheet_tab_clock_font_toolbar_top_margin">16dp</dimen>
+    <dimen name="floating_sheet_tab_clock_font_toolbar_bottom_margin">8dp</dimen>
     <dimen name="floating_sheet_list_item_horizontal_space">4dp</dimen>
+    <dimen name="floating_sheet_grid_list_item_horizontal_space">10dp</dimen>
     <dimen name="floating_sheet_list_item_vertical_space">4dp</dimen>
-    <dimen name="floating_sheet_clock_size_icon_size">80dp</dimen>
-    <dimen name="floating_sheet_clock_size_icon_margin_bottom">8dp</dimen>
-    <dimen name="floating_sheet_clock_style_option_size">82dp</dimen>
-    <dimen name="floating_sheet_clock_style_thumbnail_margin">12dp</dimen>
+    <dimen name="floating_sheet_clock_style_option_list_margin_bottom">8dp</dimen>
+    <dimen name="floating_sheet_clock_style_option_width">80dp</dimen>
+    <dimen name="floating_sheet_clock_style_option_height">98dp</dimen>
+    <dimen name="floating_sheet_clock_style_option_background_size">80dp</dimen>
+    <dimen name="floating_sheet_clock_style_option_thumbnail_size">56dp</dimen>
+    <dimen name="floating_sheet_clock_edit_icon_size">48dp</dimen>
+    <dimen name="floating_sheet_clock_edit_icon_margin">-18dp</dimen>
+    <dimen name="floating_sheet_clock_style_thumbnail_margin_bottom">12dp</dimen>
+    <dimen name="floating_sheet_clock_style_clock_size_text_margin_end">16dp</dimen>
+    <dimen name="floating_sheet_clock_color_option_list_bottom_margin">12dp</dimen>
+    <dimen name="floating_sheet_color_option_size">54dp</dimen>
+    <dimen name="floating_sheet_color_option_stroke_width">3dp</dimen>
     <dimen name="customization_option_entry_shortcut_icon_size">20dp</dimen>
+    <dimen name="customization_option_entry_clock_icon_size">44dp</dimen>
+
+    <!-- Clock font control dimensions -->
+    <dimen name="clock_font_axis_name_width">64dp</dimen>
+    <dimen name="clock_axis_control_text_margin_end">16dp</dimen>
+    <dimen name="clock_axis_control_slider_row_margin_vertical">10dp</dimen>
+    <dimen name="clock_axis_control_switch_row_margin_vertical">8dp</dimen>
+    <dimen name="clock_font_apply_padding_start">8dp</dimen>
 </resources>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index aee23939..586117f1 100755
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -96,10 +96,24 @@
     <!-- Description of a radio button to apply clock size small. [CHAR LIMIT=NONE] -->
     <string name="clock_size_small_description">A small clock shows in the corner of your screen</string>
 
+    <!-- Description for clock font editor axis apply button. [CHAR LIMIT=NONE] -->
+    <string name="clock_font_editor_apply">Apply clock font changes</string>
+
+    <!-- Description for clock font editor axis revert button. [CHAR LIMIT=NONE] -->
+    <string name="clock_font_editor_revert">Undo clock font changes</string>
+
     <!-- Title of a section of the customization picker where the user can select a Grid size for
         the home screen. [CHAR LIMIT=15] -->
     <string name="grid_title">App grid</string>
 
+    <!-- Title of a section of the customization picker where the user can select app shapes and
+        grid layouts for the home screen. [CHAR LIMIT=32] -->
+    <string name="shape_and_grid_title">App shape &amp; layout</string>
+
+    <!-- Tab title that switch to app grid customization section, where people can customization
+        the grid layout of the apps -->
+    <string name="grid_layout">Layout</string>
+
     <!-- Label for a button that allows the user to apply the currently selected Theme.
         [CHAR LIMIT=20] -->
     <string name="apply_theme_btn">Apply</string>
diff --git a/src/com/android/customization/model/color/ColorCustomizationManager.java b/src/com/android/customization/model/color/ColorCustomizationManager.java
index 9acbc4fb..61a79671 100644
--- a/src/com/android/customization/model/color/ColorCustomizationManager.java
+++ b/src/com/android/customization/model/color/ColorCustomizationManager.java
@@ -48,6 +48,7 @@ import com.android.customization.model.ResourceConstants;
 import com.android.customization.model.color.ColorOptionsProvider.ColorSource;
 import com.android.customization.model.theme.OverlayManagerCompat;
 import com.android.customization.module.logging.ThemesUserEventLogger;
+import com.android.systemui.monet.Style;
 import com.android.themepicker.R;
 
 import org.json.JSONArray;
@@ -164,7 +165,7 @@ public class ColorCustomizationManager implements CustomizationManager<ColorOpti
                 overlaysJson.put(OVERLAY_COLOR_SOURCE, colorOption.getSource());
                 overlaysJson.put(OVERLAY_COLOR_INDEX, String.valueOf(colorOption.getIndex()));
                 overlaysJson.put(OVERLAY_THEME_STYLE,
-                        String.valueOf(colorOption.getStyle().toString()));
+                        String.valueOf(Style.toString(colorOption.getStyle())));
 
                 // OVERLAY_COLOR_BOTH is only for wallpaper color case, not preset.
                 if (!COLOR_SOURCE_PRESET.equals(colorOption.getSource())) {
diff --git a/src/com/android/customization/model/color/ColorOption.java b/src/com/android/customization/model/color/ColorOption.java
index ae695dd8..a62756f8 100644
--- a/src/com/android/customization/model/color/ColorOption.java
+++ b/src/com/android/customization/model/color/ColorOption.java
@@ -19,10 +19,10 @@ import static com.android.customization.model.ResourceConstants.OVERLAY_CATEGORY
 import static com.android.customization.model.ResourceConstants.OVERLAY_CATEGORY_SYSTEM_PALETTE;
 
 import android.content.Context;
-import android.graphics.Color;
 import android.text.TextUtils;
 import android.util.Log;
 
+import androidx.annotation.ColorInt;
 import androidx.annotation.VisibleForTesting;
 
 import com.android.customization.model.CustomizationManager;
@@ -39,6 +39,7 @@ import java.util.Collections;
 import java.util.HashSet;
 import java.util.Iterator;
 import java.util.Map;
+import java.util.Objects;
 import java.util.Set;
 import java.util.stream.Collectors;
 
@@ -56,14 +57,17 @@ public abstract class ColorOption implements CustomizationOption<ColorOption> {
     protected final Map<String, String> mPackagesByCategory;
     private final String mTitle;
     private final boolean mIsDefault;
-    private final Style mStyle;
+    @Style.Type
+    private final Integer mStyle;
     private final int mIndex;
     private CharSequence mContentDescription;
+    private final @ColorInt int mSeedColor;
 
     protected ColorOption(String title, Map<String, String> overlayPackages, boolean isDefault,
-            Style style, int index) {
+            int seedColor, @Style.Type Integer style, int index) {
         mTitle = title;
         mIsDefault = isDefault;
+        mSeedColor = seedColor;
         mStyle = style;
         mIndex = index;
         mPackagesByCategory = Collections.unmodifiableMap(removeNullValues(overlayPackages));
@@ -80,9 +84,9 @@ public abstract class ColorOption implements CustomizationOption<ColorOption> {
 
         String currentStyle = colorManager.getCurrentStyle();
         if (TextUtils.isEmpty(currentStyle)) {
-            currentStyle = Style.TONAL_SPOT.toString();
+            currentStyle = Style.toString(Style.TONAL_SPOT);
         }
-        boolean isCurrentStyle = TextUtils.equals(getStyle().toString(), currentStyle);
+        boolean isCurrentStyle = TextUtils.equals(Style.toString(getStyle()), currentStyle);
 
         if (mIsDefault) {
             String serializedOverlays = colorManager.getStoredOverlays();
@@ -102,20 +106,8 @@ public abstract class ColorOption implements CustomizationOption<ColorOption> {
         }
     }
 
-    /**
-     * Gets the seed color from the overlay packages for logging.
-     *
-     * @return an int representing the seed color, or NULL_SEED_COLOR
-     */
-    public int getSeedColorForLogging() {
-        String seedColor = mPackagesByCategory.get(OVERLAY_CATEGORY_SYSTEM_PALETTE);
-        if (seedColor == null || seedColor.isEmpty()) {
-            return ThemesUserEventLogger.NULL_SEED_COLOR;
-        }
-        if (!seedColor.startsWith("#")) {
-            seedColor = "#" + seedColor;
-        }
-        return Color.parseColor(seedColor);
+    public @ColorInt int getSeedColor() {
+        return mSeedColor;
     }
 
     /**
@@ -126,7 +118,7 @@ public abstract class ColorOption implements CustomizationOption<ColorOption> {
         if (other == null) {
             return false;
         }
-        if (mStyle != other.getStyle()) {
+        if (!Objects.equals(mStyle, other.getStyle())) {
             return false;
         }
         String thisSerializedPackages = getSerializedPackages();
@@ -235,7 +227,8 @@ public abstract class ColorOption implements CustomizationOption<ColorOption> {
     /**
      * @return the style of this color option
      */
-    public Style getStyle() {
+    @Style.Type
+    public Integer getStyle() {
         return mStyle;
     }
 
diff --git a/src/com/android/customization/model/color/ColorOptionImpl.kt b/src/com/android/customization/model/color/ColorOptionImpl.kt
index ecef2a71..d8d562dc 100644
--- a/src/com/android/customization/model/color/ColorOptionImpl.kt
+++ b/src/com/android/customization/model/color/ColorOptionImpl.kt
@@ -33,16 +33,15 @@ class ColorOptionImpl(
     overlayPackages: Map<String, String?>,
     isDefault: Boolean,
     private val source: String?,
-    style: Style,
+    seedColor: Int,
+    @Style.Type style: Int,
     index: Int,
     private val previewInfo: PreviewInfo,
     val type: ColorType,
-) : ColorOption(title, overlayPackages, isDefault, style, index) {
+) : ColorOption(title, overlayPackages, isDefault, seedColor, style, index) {
 
-    class PreviewInfo(
-        @ColorInt val lightColors: IntArray,
-        @ColorInt val darkColors: IntArray,
-    ) : ColorOption.PreviewInfo {
+    class PreviewInfo(@ColorInt val lightColors: IntArray, @ColorInt val darkColors: IntArray) :
+        ColorOption.PreviewInfo {
         @ColorInt
         fun resolveColors(darkTheme: Boolean): IntArray {
             return if (darkTheme) darkColors else lightColors
@@ -78,7 +77,7 @@ class ColorOptionImpl(
         }
     }
 
-    override fun getStyleForLogging(): Int = style.toString().hashCode()
+    override fun getStyleForLogging(): Int = Style.toString(style).hashCode()
 
     class Builder {
         var title: String? = null
@@ -89,7 +88,8 @@ class ColorOptionImpl(
 
         @ColorSource var source: String? = null
         var isDefault = false
-        var style = Style.TONAL_SPOT
+        @ColorInt var seedColor = 0
+        @Style.Type var style = Style.TONAL_SPOT
         var index = 0
         var packages: MutableMap<String, String?> = HashMap()
         var type = ColorType.WALLPAPER_COLOR
@@ -100,10 +100,11 @@ class ColorOptionImpl(
                 packages,
                 isDefault,
                 source,
+                seedColor,
                 style,
                 index,
                 createPreviewInfo(),
-                type
+                type,
             )
         }
 
diff --git a/src/com/android/customization/model/color/ColorProvider.kt b/src/com/android/customization/model/color/ColorProvider.kt
index 2d7037e8..74da5c2b 100644
--- a/src/com/android/customization/model/color/ColorProvider.kt
+++ b/src/com/android/customization/model/color/ColorProvider.kt
@@ -39,6 +39,7 @@ import com.android.customization.picker.color.shared.model.ColorType
 import com.android.systemui.monet.ColorScheme
 import com.android.systemui.monet.Style
 import com.android.themepicker.R
+import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.module.InjectorProvider
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.Dispatchers
@@ -66,6 +67,7 @@ class ColorProvider(private val context: Context, stubPackageName: String) :
     private var loaderJob: Job? = null
     private val monetEnabled = ColorUtils.isMonetEnabled(context)
     // TODO(b/202145216): Use style method to fetch the list of style.
+    @Style.Type
     private var styleList =
         if (themeStyleEnabled)
             arrayOf(Style.TONAL_SPOT, Style.SPRITZ, Style.VIBRANT, Style.EXPRESSIVE)
@@ -96,16 +98,22 @@ class ColorProvider(private val context: Context, stubPackageName: String) :
         homeWallpaperColors: WallpaperColors?,
         lockWallpaperColors: WallpaperColors?,
     ) {
-        val wallpaperColorsChanged =
-            this.homeWallpaperColors != homeWallpaperColors ||
-                this.lockWallpaperColors != lockWallpaperColors
-        if (wallpaperColorsChanged || reload) {
-            loadSeedColors(
-                homeWallpaperColors,
-                lockWallpaperColors,
-            )
-            this.homeWallpaperColors = homeWallpaperColors
-            this.lockWallpaperColors = lockWallpaperColors
+        val isNewPickerUi = BaseFlags.get().isNewPickerUi()
+        if (isNewPickerUi) {
+            val wallpaperColorsChanged = this.homeWallpaperColors != homeWallpaperColors
+            if (wallpaperColorsChanged || reload) {
+                loadSeedColors(homeWallpaperColors)
+                this.homeWallpaperColors = homeWallpaperColors
+            }
+        } else {
+            val wallpaperColorsChanged =
+                this.homeWallpaperColors != homeWallpaperColors ||
+                    this.lockWallpaperColors != lockWallpaperColors
+            if (wallpaperColorsChanged || reload) {
+                loadSeedColors(homeWallpaperColors, lockWallpaperColors)
+                this.homeWallpaperColors = homeWallpaperColors
+                this.lockWallpaperColors = lockWallpaperColors
+            }
         }
 
         scope.launch {
@@ -135,7 +143,7 @@ class ColorProvider(private val context: Context, stubPackageName: String) :
 
     private fun loadSeedColors(
         homeWallpaperColors: WallpaperColors?,
-        lockWallpaperColors: WallpaperColors?,
+        lockWallpaperColors: WallpaperColors? = null,
     ) {
         if (homeWallpaperColors == null) return
 
@@ -166,13 +174,7 @@ class ColorProvider(private val context: Context, stubPackageName: String) :
                 bundles,
             )
         } else {
-            buildColorSeeds(
-                homeWallpaperColors,
-                colorsPerSource,
-                COLOR_SOURCE_HOME,
-                true,
-                bundles,
-            )
+            buildColorSeeds(homeWallpaperColors, colorsPerSource, COLOR_SOURCE_HOME, true, bundles)
         }
         wallpaperColorBundles = bundles
     }
@@ -206,9 +208,10 @@ class ColorProvider(private val context: Context, stubPackageName: String) :
             val builder = ColorOptionImpl.Builder()
             builder.lightColors = getLightColorPreview(lightColorScheme)
             builder.darkColors = getDarkColorPreview(darkColorScheme)
+            builder.seedColor = colorInt
             builder.addOverlayPackage(
                 OVERLAY_CATEGORY_SYSTEM_PALETTE,
-                if (isDefault) "" else toColorString(colorInt)
+                if (isDefault) "" else toColorString(colorInt),
             )
             builder.title =
                 when (style) {
@@ -312,12 +315,7 @@ class ColorProvider(private val context: Context, stubPackageName: String) :
                 Style.RAINBOW -> intArrayOf(colorScheme.accent1.s200, colorScheme.accent1.s200)
                 else -> intArrayOf(colorScheme.accent1.s100, colorScheme.accent1.s100)
             }
-        return intArrayOf(
-            colors[0],
-            colors[1],
-            colors[0],
-            colors[1],
-        )
+        return intArrayOf(colors[0], colors[1], colors[0], colors[1])
     }
 
     private suspend fun loadPreset() =
@@ -341,6 +339,7 @@ class ColorProvider(private val context: Context, stubPackageName: String) :
                         } catch (e: Resources.NotFoundException) {
                             null
                         }
+                    @Style.Type
                     val style =
                         try {
                             if (styleName != null) Style.valueOf(styleName) else Style.TONAL_SPOT
@@ -377,7 +376,7 @@ class ColorProvider(private val context: Context, stubPackageName: String) :
     private fun buildPreset(
         bundleName: String,
         index: Int,
-        style: Style? = null,
+        @Style.Type style: Int? = null,
         type: ColorType = ColorType.PRESET_COLOR,
     ): ColorOptionImpl {
         val builder = ColorOptionImpl.Builder()
@@ -392,6 +391,7 @@ class ColorProvider(private val context: Context, stubPackageName: String) :
         val darkColor = darkColorScheme.accentColor
         var lightColors = intArrayOf(lightColor, lightColor, lightColor, lightColor)
         var darkColors = intArrayOf(darkColor, darkColor, darkColor, darkColor)
+        builder.seedColor = colorFromStub
         builder.addOverlayPackage(OVERLAY_CATEGORY_COLOR, toColorString(colorFromStub))
         builder.addOverlayPackage(OVERLAY_CATEGORY_SYSTEM_PALETTE, toColorString(colorFromStub))
         if (style != null) {
@@ -426,7 +426,7 @@ class ColorProvider(private val context: Context, stubPackageName: String) :
                 if (wallpaperColors.isNotEmpty()) {
                     wallpaperColors.add(
                         1,
-                        buildPreset(it, -1, Style.MONOCHROMATIC, ColorType.WALLPAPER_COLOR)
+                        buildPreset(it, -1, Style.MONOCHROMATIC, ColorType.WALLPAPER_COLOR),
                     )
                 }
             }
diff --git a/src/com/android/customization/model/color/ThemedWallpaperColorResources.kt b/src/com/android/customization/model/color/ThemedWallpaperColorResources.kt
index c426f9d8..ee0f6196 100644
--- a/src/com/android/customization/model/color/ThemedWallpaperColorResources.kt
+++ b/src/com/android/customization/model/color/ThemedWallpaperColorResources.kt
@@ -38,11 +38,7 @@ class ThemedWallpaperColorResources(
     override suspend fun apply(context: Context, callback: () -> Unit) {
         withContext(Dispatchers.IO) {
             val wallpaperColorScheme =
-                ColorScheme(
-                    wallpaperColors,
-                    false,
-                    fetchThemeStyleFromSetting(),
-                )
+                ColorScheme(wallpaperColors, false, fetchThemeStyleFromSetting())
             with<ColorScheme, Unit>(wallpaperColorScheme) {
                 addOverlayColor(neutral1, R.color.system_neutral1_10)
                 addOverlayColor(neutral2, R.color.system_neutral2_10)
@@ -55,7 +51,8 @@ class ThemedWallpaperColorResources(
         }
     }
 
-    private suspend fun fetchThemeStyleFromSetting(): Style {
+    @Style.Type
+    private suspend fun fetchThemeStyleFromSetting(): Int {
         val overlayPackageJson =
             secureSettingsRepository.getString(Settings.Secure.THEME_CUSTOMIZATION_OVERLAY_PACKAGES)
         return if (!overlayPackageJson.isNullOrEmpty()) {
diff --git a/src/com/android/customization/model/grid/DefaultGridOptionsManager.kt b/src/com/android/customization/model/grid/DefaultGridOptionsManager.kt
deleted file mode 100644
index bc862fd8..00000000
--- a/src/com/android/customization/model/grid/DefaultGridOptionsManager.kt
+++ /dev/null
@@ -1,94 +0,0 @@
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
-package com.android.customization.model.grid
-
-import android.content.ContentValues
-import android.content.Context
-import com.android.wallpaper.R
-import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
-import com.android.wallpaper.util.PreviewUtils
-import dagger.hilt.android.qualifiers.ApplicationContext
-import javax.inject.Inject
-import javax.inject.Singleton
-import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.withContext
-
-@Singleton
-class DefaultGridOptionsManager
-@Inject
-constructor(
-    @ApplicationContext private val context: Context,
-    @BackgroundDispatcher private val bgDispatcher: CoroutineDispatcher,
-) : GridOptionsManager2 {
-
-    private val authorityMetadataKey: String =
-        context.getString(R.string.grid_control_metadata_name)
-    private val previewUtils: PreviewUtils = PreviewUtils(context, authorityMetadataKey)
-
-    override suspend fun isGridOptionAvailable(): Boolean {
-        return previewUtils.supportsPreview() && (getGridOptions()?.size ?: 0) > 1
-    }
-
-    override suspend fun getGridOptions(): List<GridOptionModel>? =
-        withContext(bgDispatcher) {
-            context.contentResolver
-                .query(previewUtils.getUri(LIST_OPTIONS), null, null, null, null)
-                ?.use { cursor ->
-                    buildList {
-                        while (cursor.moveToNext()) {
-                            val rows = cursor.getInt(cursor.getColumnIndex(COL_ROWS))
-                            val cols = cursor.getInt(cursor.getColumnIndex(COL_COLS))
-                            add(
-                                GridOptionModel(
-                                    key = cursor.getString(cursor.getColumnIndex(COL_NAME)),
-                                    title =
-                                        context.getString(
-                                            com.android.themepicker.R.string.grid_title_pattern,
-                                            cols,
-                                            rows
-                                        ),
-                                    isCurrent =
-                                        cursor
-                                            .getString(cursor.getColumnIndex(COL_IS_DEFAULT))
-                                            .toBoolean(),
-                                    rows = rows,
-                                    cols = cols,
-                                )
-                            )
-                        }
-                    }
-                }
-        }
-
-    override fun applyGridOption(gridName: String): Int {
-        return context.contentResolver.update(
-            previewUtils.getUri(DEFAULT_GRID),
-            ContentValues().apply { put("name", gridName) },
-            null,
-            null,
-        )
-    }
-
-    companion object {
-        const val LIST_OPTIONS: String = "list_options"
-        const val DEFAULT_GRID: String = "default_grid"
-        const val COL_NAME: String = "name"
-        const val COL_ROWS: String = "rows"
-        const val COL_COLS: String = "cols"
-        const val COL_IS_DEFAULT: String = "is_default"
-    }
-}
diff --git a/src/com/android/customization/model/grid/DefaultShapeGridManager.kt b/src/com/android/customization/model/grid/DefaultShapeGridManager.kt
new file mode 100644
index 00000000..966f68ef
--- /dev/null
+++ b/src/com/android/customization/model/grid/DefaultShapeGridManager.kt
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
+package com.android.customization.model.grid
+
+import android.content.ContentValues
+import android.content.Context
+import com.android.wallpaper.R
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
+import com.android.wallpaper.util.PreviewUtils
+import dagger.hilt.android.qualifiers.ApplicationContext
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.withContext
+
+@Singleton
+class DefaultShapeGridManager
+@Inject
+constructor(
+    @ApplicationContext private val context: Context,
+    @BackgroundDispatcher private val bgDispatcher: CoroutineDispatcher,
+) : ShapeGridManager {
+
+    private val authorityMetadataKey: String =
+        context.getString(R.string.grid_control_metadata_name)
+    private val previewUtils: PreviewUtils = PreviewUtils(context, authorityMetadataKey)
+
+    override suspend fun getGridOptions(): List<GridOptionModel>? =
+        withContext(bgDispatcher) {
+            if (previewUtils.supportsPreview()) {
+                context.contentResolver
+                    .query(previewUtils.getUri(GRID_OPTIONS), null, null, null, null)
+                    ?.use { cursor ->
+                        buildList {
+                            while (cursor.moveToNext()) {
+                                val rows = cursor.getInt(cursor.getColumnIndex(COL_ROWS))
+                                val cols = cursor.getInt(cursor.getColumnIndex(COL_COLS))
+                                val title =
+                                    cursor.getString(cursor.getColumnIndex(COL_GRID_TITLE))
+                                        ?: context.getString(
+                                            com.android.themepicker.R.string.grid_title_pattern,
+                                            cols,
+                                            rows,
+                                        )
+                                add(
+                                    GridOptionModel(
+                                        key = cursor.getString(cursor.getColumnIndex(COL_GRID_KEY)),
+                                        title = title,
+                                        isCurrent =
+                                            cursor
+                                                .getString(cursor.getColumnIndex(COL_IS_DEFAULT))
+                                                .toBoolean(),
+                                        rows = rows,
+                                        cols = cols,
+                                    )
+                                )
+                            }
+                        }
+                    }
+            } else {
+                null
+            }
+        }
+
+    override suspend fun getShapeOptions(): List<ShapeOptionModel>? =
+        withContext(bgDispatcher) {
+            if (previewUtils.supportsPreview()) {
+                context.contentResolver
+                    .query(previewUtils.getUri(SHAPE_OPTIONS), null, null, null, null)
+                    ?.use { cursor ->
+                        buildList {
+                            while (cursor.moveToNext()) {
+                                add(
+                                    ShapeOptionModel(
+                                        key =
+                                            cursor.getString(cursor.getColumnIndex(COL_SHAPE_KEY)),
+                                        title =
+                                            cursor.getString(
+                                                cursor.getColumnIndex(COL_SHAPE_TITLE)
+                                            ),
+                                        path = cursor.getString(cursor.getColumnIndex(COL_PATH)),
+                                        isCurrent =
+                                            cursor
+                                                .getString(cursor.getColumnIndex(COL_IS_DEFAULT))
+                                                .toBoolean(),
+                                    )
+                                )
+                            }
+                        }
+                    }
+            } else {
+                null
+            }
+        }
+
+    override fun applyShapeGridOption(shapeKey: String, gridKey: String): Int {
+        return context.contentResolver.update(
+            previewUtils.getUri(SHAPE_GRID),
+            ContentValues().apply {
+                put(COL_SHAPE_KEY, shapeKey)
+                put(COL_GRID_KEY, gridKey)
+            },
+            null,
+            null,
+        )
+    }
+
+    companion object {
+        const val SHAPE_OPTIONS: String = "shape_options"
+        const val GRID_OPTIONS: String = "list_options"
+        const val SHAPE_GRID: String = "default_grid"
+        const val COL_SHAPE_KEY: String = "shape_key"
+        const val COL_GRID_KEY: String = "name"
+        const val COL_GRID_NAME: String = "grid_name"
+        const val COL_GRID_TITLE: String = "grid_title"
+        const val COL_SHAPE_TITLE: String = "shape_title"
+        const val COL_ROWS: String = "rows"
+        const val COL_COLS: String = "cols"
+        const val COL_IS_DEFAULT: String = "is_default"
+        const val COL_PATH: String = "path"
+    }
+}
diff --git a/src/com/android/customization/model/grid/LauncherGridOptionsProvider.java b/src/com/android/customization/model/grid/LauncherGridOptionsProvider.java
index 83502488..f08acc91 100644
--- a/src/com/android/customization/model/grid/LauncherGridOptionsProvider.java
+++ b/src/com/android/customization/model/grid/LauncherGridOptionsProvider.java
@@ -47,6 +47,7 @@ public class LauncherGridOptionsProvider {
     private static final String DEFAULT_GRID = "default_grid";
 
     private static final String COL_NAME = "name";
+    private static final String COL_GRID_TITLE = "grid_title";
     private static final String COL_ROWS = "rows";
     private static final String COL_COLS = "cols";
     private static final String COL_PREVIEW_COUNT = "preview_count";
@@ -91,11 +92,15 @@ public class LauncherGridOptionsProvider {
             mOptions = new ArrayList<>();
             while(c.moveToNext()) {
                 String name = c.getString(c.getColumnIndex(COL_NAME));
+                String title = c.getString(c.getColumnIndex(COL_GRID_TITLE));
+
                 int rows = c.getInt(c.getColumnIndex(COL_ROWS));
                 int cols = c.getInt(c.getColumnIndex(COL_COLS));
                 int previewCount = c.getInt(c.getColumnIndex(COL_PREVIEW_COUNT));
                 boolean isSet = Boolean.parseBoolean(c.getString(c.getColumnIndex(COL_IS_DEFAULT)));
-                String title = mContext.getString(R.string.grid_title_pattern, cols, rows);
+                if (title == null) {
+                    title = mContext.getString(R.string.grid_title_pattern, cols, rows);
+                }
                 mOptions.add(new GridOption(title, name, isSet, rows, cols,
                         mPreviewUtils.getUri(PREVIEW), previewCount, iconPath));
             }
diff --git a/src/com/android/customization/model/grid/GridOptionsManager2.kt b/src/com/android/customization/model/grid/ShapeGridManager.kt
similarity index 82%
rename from src/com/android/customization/model/grid/GridOptionsManager2.kt
rename to src/com/android/customization/model/grid/ShapeGridManager.kt
index ce8500ab..0a23346b 100644
--- a/src/com/android/customization/model/grid/GridOptionsManager2.kt
+++ b/src/com/android/customization/model/grid/ShapeGridManager.kt
@@ -16,11 +16,11 @@
 
 package com.android.customization.model.grid
 
-interface GridOptionsManager2 {
-
-    suspend fun isGridOptionAvailable(): Boolean
+interface ShapeGridManager {
 
     suspend fun getGridOptions(): List<GridOptionModel>?
 
-    fun applyGridOption(gridName: String): Int
+    suspend fun getShapeOptions(): List<ShapeOptionModel>?
+
+    fun applyShapeGridOption(shapeKey: String, gridKey: String): Int
 }
diff --git a/src/com/android/customization/model/grid/ShapeOptionModel.kt b/src/com/android/customization/model/grid/ShapeOptionModel.kt
new file mode 100644
index 00000000..c3ed1920
--- /dev/null
+++ b/src/com/android/customization/model/grid/ShapeOptionModel.kt
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
+package com.android.customization.model.grid
+
+data class ShapeOptionModel(
+    val key: String,
+    val title: String,
+    val path: String,
+    val isCurrent: Boolean,
+)
diff --git a/src/com/android/customization/module/ThemePickerInjector.kt b/src/com/android/customization/module/ThemePickerInjector.kt
index b634df01..ae412ede 100644
--- a/src/com/android/customization/module/ThemePickerInjector.kt
+++ b/src/com/android/customization/module/ThemePickerInjector.kt
@@ -65,13 +65,23 @@ import com.android.systemui.shared.settings.data.repository.SystemSettingsReposi
 import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.module.CustomizationSections
 import com.android.wallpaper.module.FragmentFactory
+import com.android.wallpaper.module.NetworkStatusNotifier
+import com.android.wallpaper.module.PackageStatusNotifier
+import com.android.wallpaper.module.PartnerProvider
 import com.android.wallpaper.module.WallpaperPicker2Injector
+import com.android.wallpaper.module.WallpaperPreferences
+import com.android.wallpaper.module.logging.UserEventLogger
+import com.android.wallpaper.network.Requester
 import com.android.wallpaper.picker.CustomizationPickerActivity
+import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper
+import com.android.wallpaper.picker.customization.data.content.WallpaperClient
 import com.android.wallpaper.picker.customization.data.repository.WallpaperColorsRepository
 import com.android.wallpaper.picker.customization.domain.interactor.WallpaperInteractor
 import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import com.android.wallpaper.picker.di.modules.MainDispatcher
 import com.android.wallpaper.picker.undo.domain.interactor.SnapshotRestorer
+import com.android.wallpaper.system.UiModeManagerWrapper
+import com.android.wallpaper.util.DisplayUtils
 import dagger.Lazy
 import javax.inject.Inject
 import javax.inject.Singleton
@@ -85,7 +95,48 @@ constructor(
     @MainDispatcher private val mainScope: CoroutineScope,
     @BackgroundDispatcher private val bgScope: CoroutineScope,
     @BackgroundDispatcher private val bgDispatcher: CoroutineDispatcher,
-) : WallpaperPicker2Injector(mainScope), CustomizationInjector {
+    private val colorContrastSectionViewModelFactory: Lazy<ColorContrastSectionViewModel.Factory>,
+    private val keyguardQuickAffordancePickerInteractor:
+        Lazy<KeyguardQuickAffordancePickerInteractor>,
+    private val keyguardQuickAffordanceSnapshotRestorer:
+        Lazy<KeyguardQuickAffordanceSnapshotRestorer>,
+    private val themesUserEventLogger: Lazy<ThemesUserEventLogger>,
+    private val colorPickerInteractor: Lazy<ColorPickerInteractor>,
+    private val colorPickerSnapshotRestorer: Lazy<ColorPickerSnapshotRestorer>,
+    private val clockRegistry: Lazy<ClockRegistry>,
+    private val secureSettingsRepository: Lazy<SecureSettingsRepository>,
+    private val systemSettingsRepository: Lazy<SystemSettingsRepository>,
+    private val clockPickerInteractor: Lazy<ClockPickerInteractor>,
+    private val clockPickerSnapshotRestorer: Lazy<ClockPickerSnapshotRestorer>,
+    displayUtils: Lazy<DisplayUtils>,
+    requester: Lazy<Requester>,
+    networkStatusNotifier: Lazy<NetworkStatusNotifier>,
+    partnerProvider: Lazy<PartnerProvider>,
+    val uiModeManager: Lazy<UiModeManagerWrapper>,
+    userEventLogger: Lazy<UserEventLogger>,
+    injectedWallpaperClient: Lazy<WallpaperClient>,
+    private val injectedWallpaperInteractor: Lazy<WallpaperInteractor>,
+    prefs: Lazy<WallpaperPreferences>,
+    wallpaperColorsRepository: Lazy<WallpaperColorsRepository>,
+    defaultWallpaperCategoryWrapper: Lazy<WallpaperCategoryWrapper>,
+    packageNotifier: Lazy<PackageStatusNotifier>,
+) :
+    WallpaperPicker2Injector(
+        mainScope,
+        displayUtils,
+        requester,
+        networkStatusNotifier,
+        partnerProvider,
+        uiModeManager,
+        userEventLogger,
+        injectedWallpaperClient,
+        injectedWallpaperInteractor,
+        prefs,
+        wallpaperColorsRepository,
+        defaultWallpaperCategoryWrapper,
+        packageNotifier,
+    ),
+    CustomizationInjector {
     private var customizationSections: CustomizationSections? = null
     private var keyguardQuickAffordancePickerViewModelFactory:
         KeyguardQuickAffordancePickerViewModel.Factory? =
@@ -106,24 +157,6 @@ constructor(
     private var gridSnapshotRestorer: GridSnapshotRestorer? = null
     private var gridScreenViewModelFactory: GridScreenViewModel.Factory? = null
 
-    // Injected objects, sorted by type
-    @Inject
-    lateinit var colorContrastSectionViewModelFactory: Lazy<ColorContrastSectionViewModel.Factory>
-    @Inject
-    lateinit var keyguardQuickAffordancePickerInteractor:
-        Lazy<KeyguardQuickAffordancePickerInteractor>
-    @Inject
-    lateinit var keyguardQuickAffordanceSnapshotRestorer:
-        Lazy<KeyguardQuickAffordanceSnapshotRestorer>
-    @Inject lateinit var themesUserEventLogger: Lazy<ThemesUserEventLogger>
-    @Inject lateinit var colorPickerInteractor: Lazy<ColorPickerInteractor>
-    @Inject lateinit var colorPickerSnapshotRestorer: Lazy<ColorPickerSnapshotRestorer>
-    @Inject lateinit var clockRegistry: Lazy<ClockRegistry>
-    @Inject lateinit var secureSettingsRepository: Lazy<SecureSettingsRepository>
-    @Inject lateinit var systemSettingsRepository: Lazy<SystemSettingsRepository>
-    @Inject lateinit var clockPickerInteractor: Lazy<ClockPickerInteractor>
-    @Inject lateinit var clockPickerSnapshotRestorer: Lazy<ClockPickerSnapshotRestorer>
-
     override fun getCustomizationSections(activity: ComponentActivity): CustomizationSections {
         val appContext = activity.applicationContext
         val clockViewFactory = getClockViewFactory(activity)
diff --git a/src/com/android/customization/picker/clock/data/repository/ClockPickerRepository.kt b/src/com/android/customization/picker/clock/data/repository/ClockPickerRepository.kt
index 57f77b01..710a1daa 100644
--- a/src/com/android/customization/picker/clock/data/repository/ClockPickerRepository.kt
+++ b/src/com/android/customization/picker/clock/data/repository/ClockPickerRepository.kt
@@ -20,6 +20,7 @@ import androidx.annotation.ColorInt
 import androidx.annotation.IntRange
 import com.android.customization.picker.clock.shared.ClockSize
 import com.android.customization.picker.clock.shared.model.ClockMetadataModel
+import com.android.systemui.plugins.clocks.ClockFontAxisSetting
 import kotlinx.coroutines.flow.Flow
 
 /**
@@ -49,4 +50,6 @@ interface ClockPickerRepository {
     )
 
     suspend fun setClockSize(size: ClockSize)
+
+    suspend fun setClockFontAxes(axisSettings: List<ClockFontAxisSetting>)
 }
diff --git a/src/com/android/customization/picker/clock/data/repository/ClockPickerRepositoryImpl.kt b/src/com/android/customization/picker/clock/data/repository/ClockPickerRepositoryImpl.kt
index c0a1446a..90bb6e6d 100644
--- a/src/com/android/customization/picker/clock/data/repository/ClockPickerRepositoryImpl.kt
+++ b/src/com/android/customization/picker/clock/data/repository/ClockPickerRepositoryImpl.kt
@@ -22,6 +22,8 @@ import androidx.annotation.ColorInt
 import androidx.annotation.IntRange
 import com.android.customization.picker.clock.shared.ClockSize
 import com.android.customization.picker.clock.shared.model.ClockMetadataModel
+import com.android.systemui.plugins.clocks.ClockFontAxis
+import com.android.systemui.plugins.clocks.ClockFontAxisSetting
 import com.android.systemui.plugins.clocks.ClockMetadata
 import com.android.systemui.shared.clocks.ClockRegistry
 import com.android.systemui.shared.settings.data.repository.SecureSettingsRepository
@@ -70,6 +72,7 @@ constructor(
                                     description = clockConfig.description,
                                     thumbnail = clockConfig.thumbnail,
                                     isReactiveToTone = clockConfig.isReactiveToTone,
+                                    fontAxes = clockConfig.axes,
                                 )
                             } else {
                                 null
@@ -115,6 +118,7 @@ constructor(
                                     description = it.description,
                                     thumbnail = it.thumbnail,
                                     isReactiveToTone = it.isReactiveToTone,
+                                    fontAxes = it.axes,
                                     selectedColorId = metadata?.getSelectedColorId(),
                                     colorTone =
                                         metadata?.getColorTone()
@@ -174,11 +178,7 @@ constructor(
             .map { setting -> setting == 1 }
             .map { isDynamic -> if (isDynamic) ClockSize.DYNAMIC else ClockSize.SMALL }
             .distinctUntilChanged()
-            .shareIn(
-                scope = mainScope,
-                started = SharingStarted.Eagerly,
-                replay = 1,
-            )
+            .shareIn(scope = mainScope, started = SharingStarted.Eagerly, replay = 1)
 
     override suspend fun setClockSize(size: ClockSize) {
         secureSettingsRepository.setInt(
@@ -187,6 +187,14 @@ constructor(
         )
     }
 
+    override suspend fun setClockFontAxes(axisSettings: List<ClockFontAxisSetting>) {
+        registry.mutateSetting { oldSettings ->
+            val newSettings = oldSettings.copy(axes = axisSettings)
+            newSettings.metadata = oldSettings.metadata
+            newSettings
+        }
+    }
+
     private fun JSONObject.getSelectedColorId(): String? {
         return if (this.isNull(KEY_METADATA_SELECTED_COLOR_ID)) {
             null
@@ -198,7 +206,7 @@ constructor(
     private fun JSONObject.getColorTone(): Int {
         return this.optInt(
             KEY_METADATA_COLOR_TONE_PROGRESS,
-            ClockMetadataModel.DEFAULT_COLOR_TONE_PROGRESS
+            ClockMetadataModel.DEFAULT_COLOR_TONE_PROGRESS,
         )
     }
 
@@ -208,6 +216,7 @@ constructor(
         description: String,
         thumbnail: Drawable,
         isReactiveToTone: Boolean,
+        fontAxes: List<ClockFontAxis>,
         selectedColorId: String? = null,
         @IntRange(from = 0, to = 100) colorTone: Int = 0,
         @ColorInt seedColor: Int? = null,
@@ -218,6 +227,7 @@ constructor(
             description = description,
             thumbnail = thumbnail,
             isReactiveToTone = isReactiveToTone,
+            fontAxes = fontAxes,
             selectedColorId = selectedColorId,
             colorToneProgress = colorTone,
             seedColor = seedColor,
diff --git a/src/com/android/customization/picker/clock/data/repository/ClockRegistryProvider.kt b/src/com/android/customization/picker/clock/data/repository/ClockRegistryProvider.kt
index 652ffdd2..15d90881 100644
--- a/src/com/android/customization/picker/clock/data/repository/ClockRegistryProvider.kt
+++ b/src/com/android/customization/picker/clock/data/repository/ClockRegistryProvider.kt
@@ -19,6 +19,7 @@ import android.app.NotificationManager
 import android.content.ComponentName
 import android.content.Context
 import android.view.LayoutInflater
+import com.android.systemui.Flags
 import com.android.systemui.plugins.Plugin
 import com.android.systemui.plugins.PluginManager
 import com.android.systemui.shared.clocks.ClockRegistry
@@ -52,7 +53,12 @@ class ClockRegistryProvider(
             backgroundDispatcher,
             isEnabled = true,
             handleAllUsers = false,
-            DefaultClockProvider(context, LayoutInflater.from(context), context.resources),
+            DefaultClockProvider(
+                ctx = context,
+                layoutInflater = LayoutInflater.from(context),
+                resources = context.resources,
+                isClockReactiveVariantsEnabled = Flags.clockReactiveVariants(),
+            ),
             keepAllLoaded = true,
             subTag = "Picker",
         )
diff --git a/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractor.kt b/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractor.kt
index 42eed34b..678de5e1 100644
--- a/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractor.kt
+++ b/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractor.kt
@@ -23,6 +23,7 @@ import com.android.customization.picker.clock.data.repository.ClockPickerReposit
 import com.android.customization.picker.clock.shared.ClockSize
 import com.android.customization.picker.clock.shared.model.ClockMetadataModel
 import com.android.customization.picker.clock.shared.model.ClockSnapshotModel
+import com.android.systemui.plugins.clocks.ClockFontAxisSetting
 import javax.inject.Inject
 import javax.inject.Singleton
 import kotlinx.coroutines.flow.Flow
@@ -57,6 +58,9 @@ constructor(
 
     val seedColor: Flow<Int?> = repository.selectedClock.map { clock -> clock.seedColor }
 
+    val axisSettings: Flow<List<ClockFontAxisSetting>?> =
+        repository.selectedClock.map { clock -> clock.fontAxes.map { it.toSetting() } }
+
     val selectedClockSize: Flow<ClockSize> = repository.selectedClockSize
 
     suspend fun setSelectedClock(clockId: String) {
@@ -84,12 +88,17 @@ constructor(
         setClockOption(ClockSnapshotModel(clockSize = size))
     }
 
+    suspend fun setClockFontAxes(axisSettings: List<ClockFontAxisSetting>) {
+        setClockOption(ClockSnapshotModel(axisSettings = axisSettings))
+    }
+
     suspend fun applyClock(
         clockId: String?,
         size: ClockSize?,
         selectedColorId: String?,
         @IntRange(from = 0, to = 100) colorToneProgress: Int?,
         @ColorInt seedColor: Int?,
+        axisSettings: List<ClockFontAxisSetting>,
     ) {
         setClockOption(
             ClockSnapshotModel(
@@ -98,6 +107,7 @@ constructor(
                 selectedColorId = selectedColorId,
                 colorToneProgress = colorToneProgress,
                 seedColor = seedColor,
+                axisSettings = axisSettings,
             )
         )
     }
@@ -116,6 +126,7 @@ constructor(
             )
         }
         clockSnapshotModel.clockId?.let { repository.setSelectedClock(it) }
+        clockSnapshotModel.axisSettings?.let { repository.setClockFontAxes(it) }
     }
 
     private suspend fun storeCurrentClockOption(clockSnapshotModel: ClockSnapshotModel) {
@@ -143,5 +154,6 @@ constructor(
             seedColor =
                 latestOption.colorToneProgress?.let { latestOption.seedColor }
                     ?: seedColor.firstOrNull(),
+            axisSettings = latestOption.axisSettings ?: axisSettings.firstOrNull(),
         )
 }
diff --git a/src/com/android/customization/picker/clock/domain/interactor/ClockPickerSnapshotRestorer.kt b/src/com/android/customization/picker/clock/domain/interactor/ClockPickerSnapshotRestorer.kt
index 322c7242..2a74276a 100644
--- a/src/com/android/customization/picker/clock/domain/interactor/ClockPickerSnapshotRestorer.kt
+++ b/src/com/android/customization/picker/clock/domain/interactor/ClockPickerSnapshotRestorer.kt
@@ -21,6 +21,7 @@ import android.text.TextUtils
 import android.util.Log
 import com.android.customization.picker.clock.data.repository.ClockPickerRepository
 import com.android.customization.picker.clock.shared.model.ClockSnapshotModel
+import com.android.systemui.plugins.clocks.ClockFontAxisSetting
 import com.android.wallpaper.picker.undo.domain.interactor.SnapshotRestorer
 import com.android.wallpaper.picker.undo.domain.interactor.SnapshotStore
 import com.android.wallpaper.picker.undo.shared.model.RestorableSnapshot
@@ -29,6 +30,7 @@ import javax.inject.Singleton
 import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.firstOrNull
 import kotlinx.coroutines.flow.map
+import org.json.JSONArray
 
 /** Handles state restoration for clocks. */
 @Singleton
@@ -38,9 +40,7 @@ constructor(private val repository: ClockPickerRepository) : SnapshotRestorer {
     private var snapshotStore: SnapshotStore = SnapshotStore.NOOP
     private var originalOption: ClockSnapshotModel? = null
 
-    override suspend fun setUpSnapshotRestorer(
-        store: SnapshotStore,
-    ): RestorableSnapshot {
+    override suspend fun setUpSnapshotRestorer(store: SnapshotStore): RestorableSnapshot {
         snapshotStore = store
         originalOption =
             ClockSnapshotModel(
@@ -58,6 +58,10 @@ constructor(private val repository: ClockPickerRepository) : SnapshotRestorer {
                         .distinctUntilChanged()
                         .firstOrNull(),
                 seedColor = repository.selectedClock.map { clock -> clock.seedColor }.firstOrNull(),
+                axisSettings =
+                    repository.selectedClock
+                        .map { clock -> clock.fontAxes.map { it.toSetting() } }
+                        .firstOrNull(),
             )
         return snapshot(originalOption)
     }
@@ -71,7 +75,9 @@ constructor(private val repository: ClockPickerRepository) : SnapshotRestorer {
                     optionToRestore.colorToneProgress?.toString() !=
                         snapshot.args[KEY_COLOR_TONE_PROGRESS] ||
                     optionToRestore.seedColor?.toString() != snapshot.args[KEY_SEED_COLOR] ||
-                    optionToRestore.selectedColorId != snapshot.args[KEY_COLOR_ID]
+                    optionToRestore.selectedColorId != snapshot.args[KEY_COLOR_ID] ||
+                    (optionToRestore.axisSettings ?: listOf()) !=
+                        ClockFontAxisSetting.fromJson(JSONArray(snapshot.args[KEY_FONT_AXES]))
             ) {
                 Log.wtf(
                     TAG,
@@ -87,10 +93,11 @@ constructor(private val repository: ClockPickerRepository) : SnapshotRestorer {
                 repository.setClockColor(
                     selectedColorId = optionToRestore.selectedColorId,
                     colorToneProgress = optionToRestore.colorToneProgress,
-                    seedColor = optionToRestore.seedColor
+                    seedColor = optionToRestore.seedColor,
                 )
             }
             optionToRestore.clockId?.let { repository.setSelectedClock(it) }
+            optionToRestore.axisSettings?.let { repository.setClockFontAxes(it) }
         }
     }
 
@@ -101,7 +108,7 @@ constructor(private val repository: ClockPickerRepository) : SnapshotRestorer {
     private fun snapshot(clockSnapshotModel: ClockSnapshotModel? = null): RestorableSnapshot {
         val options =
             if (clockSnapshotModel == null) emptyMap()
-            else
+            else {
                 buildMap {
                     clockSnapshotModel.clockId?.let { put(KEY_CLOCK_ID, it) }
                     clockSnapshotModel.clockSize?.let { put(KEY_CLOCK_SIZE, it.toString()) }
@@ -110,7 +117,11 @@ constructor(private val repository: ClockPickerRepository) : SnapshotRestorer {
                         put(KEY_COLOR_TONE_PROGRESS, it.toString())
                     }
                     clockSnapshotModel.seedColor?.let { put(KEY_SEED_COLOR, it.toString()) }
+                    clockSnapshotModel.axisSettings?.let {
+                        put(KEY_FONT_AXES, ClockFontAxisSetting.toJson(it).toString())
+                    }
                 }
+            }
 
         return RestorableSnapshot(options)
     }
@@ -122,5 +133,6 @@ constructor(private val repository: ClockPickerRepository) : SnapshotRestorer {
         private const val KEY_COLOR_ID = "color_id"
         private const val KEY_COLOR_TONE_PROGRESS = "color_tone_progress"
         private const val KEY_SEED_COLOR = "seed_color"
+        private const val KEY_FONT_AXES = "font_axes"
     }
 }
diff --git a/src/com/android/customization/picker/clock/shared/model/ClockMetadataModel.kt b/src/com/android/customization/picker/clock/shared/model/ClockMetadataModel.kt
index 3c8e7259..8a2edfbf 100644
--- a/src/com/android/customization/picker/clock/shared/model/ClockMetadataModel.kt
+++ b/src/com/android/customization/picker/clock/shared/model/ClockMetadataModel.kt
@@ -20,6 +20,7 @@ package com.android.customization.picker.clock.shared.model
 import android.graphics.drawable.Drawable
 import androidx.annotation.ColorInt
 import androidx.annotation.IntRange
+import com.android.systemui.plugins.clocks.ClockFontAxis
 
 /** Model for clock metadata. */
 data class ClockMetadataModel(
@@ -28,6 +29,7 @@ data class ClockMetadataModel(
     val description: String,
     val thumbnail: Drawable,
     val isReactiveToTone: Boolean,
+    val fontAxes: List<ClockFontAxis>,
     val selectedColorId: String?,
     @IntRange(from = 0, to = 100) val colorToneProgress: Int,
     @ColorInt val seedColor: Int?,
diff --git a/src/com/android/customization/picker/clock/shared/model/ClockSnapshotModel.kt b/src/com/android/customization/picker/clock/shared/model/ClockSnapshotModel.kt
index 942cc59e..6817ec1c 100644
--- a/src/com/android/customization/picker/clock/shared/model/ClockSnapshotModel.kt
+++ b/src/com/android/customization/picker/clock/shared/model/ClockSnapshotModel.kt
@@ -20,6 +20,7 @@ package com.android.customization.picker.clock.shared.model
 import androidx.annotation.ColorInt
 import androidx.annotation.IntRange
 import com.android.customization.picker.clock.shared.ClockSize
+import com.android.systemui.plugins.clocks.ClockFontAxisSetting
 
 /** Models application state for a clock option in a picker experience. */
 data class ClockSnapshotModel(
@@ -28,4 +29,5 @@ data class ClockSnapshotModel(
     val selectedColorId: String? = null,
     @IntRange(from = 0, to = 100) val colorToneProgress: Int? = null,
     @ColorInt val seedColor: Int? = null,
+    val axisSettings: List<ClockFontAxisSetting>? = null,
 )
diff --git a/src/com/android/customization/picker/clock/ui/binder/ClockSettingsBinder.kt b/src/com/android/customization/picker/clock/ui/binder/ClockSettingsBinder.kt
index 616640c3..764c6716 100644
--- a/src/com/android/customization/picker/clock/ui/binder/ClockSettingsBinder.kt
+++ b/src/com/android/customization/picker/clock/ui/binder/ClockSettingsBinder.kt
@@ -41,12 +41,11 @@ import androidx.recyclerview.widget.RecyclerView
 import com.android.customization.picker.clock.shared.ClockSize
 import com.android.customization.picker.clock.ui.adapter.ClockSettingsTabAdapter
 import com.android.customization.picker.clock.ui.view.ClockCarouselView
-import com.android.customization.picker.clock.ui.view.ClockHostView
 import com.android.customization.picker.clock.ui.view.ClockViewFactory
 import com.android.customization.picker.clock.ui.viewmodel.ClockSettingsViewModel
 import com.android.customization.picker.color.ui.binder.ColorOptionIconBinder
+import com.android.systemui.shared.Flags
 import com.android.themepicker.R
-import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.picker.common.ui.view.ItemSpacing
 import com.android.wallpaper.picker.option.ui.binder.OptionItemBinder
 import kotlinx.coroutines.flow.combine
@@ -65,7 +64,10 @@ object ClockSettingsBinder {
         clockViewFactory: ClockViewFactory,
         lifecycleOwner: LifecycleOwner,
     ) {
-        val clockHostView: ClockHostView = view.requireViewById(R.id.clock_host_view)
+        if (Flags.newCustomizationPickerUi()) {
+            return
+        }
+        val clockHostView: ViewGroup = view.requireViewById(R.id.clock_host_view)
         val tabView: RecyclerView = view.requireViewById(R.id.tabs)
         val tabAdapter = ClockSettingsTabAdapter()
         tabView.adapter = tabAdapter
@@ -104,13 +106,13 @@ object ClockSettingsBinder {
             getRadioText(
                 view.context.applicationContext,
                 view.resources.getString(R.string.clock_size_dynamic),
-                view.resources.getString(R.string.clock_size_dynamic_description)
+                view.resources.getString(R.string.clock_size_dynamic_description),
             )
         view.requireViewById<RadioButton>(R.id.radio_small).text =
             getRadioText(
                 view.context.applicationContext,
                 view.resources.getString(R.string.clock_size_small),
-                view.resources.getString(R.string.clock_size_small_description)
+                view.resources.getString(R.string.clock_size_small_description),
             )
 
         val colorOptionContainer = view.requireViewById<View>(R.id.color_picker_container)
@@ -160,7 +162,7 @@ object ClockSettingsBinder {
                                 ColorOptionIconBinder.bind(
                                     item.requireViewById(R.id.foreground),
                                     payload,
-                                    darkMode
+                                    darkMode,
                                 )
                                 OptionItemBinder.bind(
                                     view = item,
@@ -200,18 +202,16 @@ object ClockSettingsBinder {
                         )
                         .collect { (clockId, size) ->
                             clockHostView.removeAllViews()
-                            if (BaseFlags.get().isClockReactiveVariantsEnabled()) {
-                                clockViewFactory.setReactiveTouchInteractionEnabled(clockId, true)
-                            }
                             val clockView =
                                 when (size) {
                                     ClockSize.DYNAMIC -> clockViewFactory.getLargeView(clockId)
                                     ClockSize.SMALL -> clockViewFactory.getSmallView(clockId)
                                 }
-                            // The clock view might still be attached to an existing parent. Detach
-                            // before adding to another parent.
+                            // The clock view might still be attached to an existing parent.
+                            // Detach before adding to another parent.
                             (clockView.parent as? ViewGroup)?.removeView(clockView)
                             clockHostView.addView(clockView)
+
                             when (size) {
                                 ClockSize.DYNAMIC -> {
                                     // When clock size data flow emits clock size signal, we want
@@ -279,20 +279,20 @@ object ClockSettingsBinder {
     private fun getRadioText(
         context: Context,
         title: String,
-        description: String
+        description: String,
     ): SpannableString {
         val text = SpannableString(title + "\n" + description)
         text.setSpan(
             TextAppearanceSpan(context, R.style.SectionTitleTextStyle),
             0,
             title.length,
-            Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
+            Spannable.SPAN_EXCLUSIVE_EXCLUSIVE,
         )
         text.setSpan(
             TextAppearanceSpan(context, R.style.SectionSubtitleTextStyle),
             title.length + 1,
             title.length + 1 + description.length,
-            Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
+            Spannable.SPAN_EXCLUSIVE_EXCLUSIVE,
         )
         return text
     }
diff --git a/src/com/android/customization/picker/clock/ui/view/ClockCarouselView.kt b/src/com/android/customization/picker/clock/ui/view/ClockCarouselView.kt
index 1d2f5956..0ed03629 100644
--- a/src/com/android/customization/picker/clock/ui/view/ClockCarouselView.kt
+++ b/src/com/android/customization/picker/clock/ui/view/ClockCarouselView.kt
@@ -19,6 +19,7 @@ import android.content.Context
 import android.content.res.ColorStateList
 import android.content.res.Resources
 import android.util.AttributeSet
+import android.util.TypedValue
 import android.view.LayoutInflater
 import android.view.View
 import android.view.ViewGroup
@@ -33,21 +34,14 @@ import com.android.customization.picker.clock.shared.ClockSize
 import com.android.customization.picker.clock.ui.viewmodel.ClockCarouselItemViewModel
 import com.android.systemui.plugins.clocks.ClockController
 import com.android.themepicker.R
-import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.picker.FixedWidthDisplayRatioFrameLayout
 import java.lang.Float.max
 
-class ClockCarouselView(
-    context: Context,
-    attrs: AttributeSet,
-) :
-    FrameLayout(
-        context,
-        attrs,
-    ) {
+class ClockCarouselView(context: Context, attrs: AttributeSet) : FrameLayout(context, attrs) {
 
     val carousel: Carousel
     private val motionLayout: MotionLayout
+    private val clockViewScale: Float
     private lateinit var adapter: ClockCarouselAdapter
     private lateinit var clockViewFactory: ClockViewFactory
     private var toCenterClockController: ClockController? = null
@@ -64,6 +58,11 @@ class ClockCarouselView(
         carousel = clockCarousel.requireViewById(R.id.carousel)
         motionLayout = clockCarousel.requireViewById(R.id.motion_container)
         motionLayout.contentDescription = context.getString(R.string.custom_clocks_label)
+        clockViewScale =
+            TypedValue().let {
+                resources.getValue(R.dimen.clock_carousel_scale, it, true)
+                it.float
+            }
     }
 
     /**
@@ -138,7 +137,14 @@ class ClockCarouselView(
             overrideScreenPreviewWidth()
         }
 
-        adapter = ClockCarouselAdapter(clockSize, clocks, clockViewFactory, onClockSelected)
+        adapter =
+            ClockCarouselAdapter(
+                clockViewScale,
+                clockSize,
+                clocks,
+                clockViewFactory,
+                onClockSelected,
+            )
         carousel.isInfinite = clocks.size >= MIN_CLOCKS_TO_ENABLE_INFINITE_CAROUSEL
         carousel.setAdapter(adapter)
         val indexOfSelectedClock =
@@ -153,7 +159,7 @@ class ClockCarouselView(
                 override fun onTransitionStarted(
                     motionLayout: MotionLayout?,
                     startId: Int,
-                    endId: Int
+                    endId: Int,
                 ) {
                     if (motionLayout == null) {
                         return
@@ -230,8 +236,8 @@ class ClockCarouselView(
                         ?.largeClock
                         ?.animations
                         ?.onPickerCarouselSwiping(progress)
-                    val scalingDownScale = getScalingDownScale(progress)
-                    val scalingUpScale = getScalingUpScale(progress)
+                    val scalingDownScale = getScalingDownScale(progress, clockViewScale)
+                    val scalingUpScale = getScalingUpScale(progress, clockViewScale)
                     offCenterClockScaleView?.scaleX = scalingDownScale
                     offCenterClockScaleView?.scaleY = scalingDownScale
                     toCenterClockScaleView?.scaleX = scalingUpScale
@@ -301,15 +307,13 @@ class ClockCarouselView(
                     motionLayout: MotionLayout?,
                     triggerId: Int,
                     positive: Boolean,
-                    progress: Float
+                    progress: Float,
                 ) {}
             }
         )
     }
 
-    fun setSelectedClockIndex(
-        index: Int,
-    ) {
+    fun setSelectedClockIndex(index: Int) {
         // 1. setUpClockCarouselView() can possibly not be called before setSelectedClockIndex().
         //    We need to check if index out of bound.
         // 2. jumpToIndex() to the same position can cause the views unnecessarily populate again.
@@ -379,10 +383,11 @@ class ClockCarouselView(
     }
 
     private class ClockCarouselAdapter(
+        val clockViewScale: Float,
         val clockSize: ClockSize,
         val clocks: List<ClockCarouselItemViewModel>,
         private val clockViewFactory: ClockViewFactory,
-        private val onClockSelected: (clock: ClockCarouselItemViewModel) -> Unit
+        private val onClockSelected: (clock: ClockCarouselItemViewModel) -> Unit,
     ) : Carousel.Adapter {
 
         // This map is used to eagerly save the translation X and Y of each small clock view, so
@@ -418,9 +423,6 @@ class ClockCarouselView(
 
             // Add the clock view to the clock host view
             clockHostView.removeAllViews()
-            if (BaseFlags.get().isClockReactiveVariantsEnabled()) {
-                clockViewFactory.setReactiveTouchInteractionEnabled(clockId, false)
-            }
             val clockView =
                 when (clockSize) {
                     ClockSize.DYNAMIC -> clockViewFactory.getLargeView(clockId)
@@ -439,19 +441,9 @@ class ClockCarouselView(
 
             when (clockSize) {
                 ClockSize.DYNAMIC ->
-                    initializeDynamicClockView(
-                        isMiddleView,
-                        clockScaleView,
-                        clockId,
-                        clockHostView,
-                    )
+                    initializeDynamicClockView(isMiddleView, clockScaleView, clockId, clockHostView)
                 ClockSize.SMALL ->
-                    initializeSmallClockView(
-                        clockId,
-                        isMiddleView,
-                        clockHostView,
-                        clockView,
-                    )
+                    initializeSmallClockView(clockId, isMiddleView, clockHostView, clockView)
             }
             cardView.alpha = if (isMiddleView) 0f else 1f
         }
@@ -473,8 +465,8 @@ class ClockCarouselView(
                 clockScaleView.scaleY = 1f
                 controller.largeClock.animations.onPickerCarouselSwiping(1F)
             } else {
-                clockScaleView.scaleX = CLOCK_CAROUSEL_VIEW_SCALE
-                clockScaleView.scaleY = CLOCK_CAROUSEL_VIEW_SCALE
+                clockScaleView.scaleX = clockViewScale
+                clockScaleView.scaleY = clockViewScale
                 controller.largeClock.animations.onPickerCarouselSwiping(0F)
             }
         }
@@ -502,11 +494,7 @@ class ClockCarouselView(
                     it.pivotX = it.width / 2F
                     it.pivotY = it.height / 2F
                     val translationX =
-                        getTranslationDistance(
-                            clockHostView.width,
-                            clockView.width,
-                            clockView.left,
-                        )
+                        getTranslationDistance(clockHostView.width, clockView.width, clockView.left)
                     val translationY =
                         getTranslationDistance(
                             clockHostView.height,
@@ -528,7 +516,6 @@ class ClockCarouselView(
     companion object {
         // The carousel needs to have at least 5 different clock faces to be infinite
         const val MIN_CLOCKS_TO_ENABLE_INFINITE_CAROUSEL = 5
-        const val CLOCK_CAROUSEL_VIEW_SCALE = 0.5f
         const val TRANSITION_DURATION = 250
 
         val itemViewIds =
@@ -537,13 +524,14 @@ class ClockCarouselView(
                 R.id.item_view_1,
                 R.id.item_view_2,
                 R.id.item_view_3,
-                R.id.item_view_4
+                R.id.item_view_4,
             )
 
-        fun getScalingUpScale(progress: Float) =
-            CLOCK_CAROUSEL_VIEW_SCALE + progress * (1f - CLOCK_CAROUSEL_VIEW_SCALE)
+        fun getScalingUpScale(progress: Float, clockViewScale: Float) =
+            clockViewScale + progress * (1f - clockViewScale)
 
-        fun getScalingDownScale(progress: Float) = 1f - progress * (1f - CLOCK_CAROUSEL_VIEW_SCALE)
+        fun getScalingDownScale(progress: Float, clockViewScale: Float) =
+            1f - progress * (1f - clockViewScale)
 
         // This makes the card only starts to reveal in the last quarter of the trip so
         // the card won't overlap the preview.
diff --git a/src/com/android/customization/picker/clock/ui/view/ClockConstraintLayoutHostView.kt b/src/com/android/customization/picker/clock/ui/view/ClockConstraintLayoutHostView.kt
new file mode 100644
index 00000000..de5fbd55
--- /dev/null
+++ b/src/com/android/customization/picker/clock/ui/view/ClockConstraintLayoutHostView.kt
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
+package com.android.customization.picker.clock.ui.view
+
+import android.content.Context
+import android.util.AttributeSet
+import android.view.View
+import android.view.View.MeasureSpec.EXACTLY
+import android.view.ViewGroup
+import androidx.constraintlayout.widget.ConstraintLayout
+import com.android.customization.picker.clock.shared.ClockSize
+import com.android.systemui.plugins.clocks.ClockController
+import com.android.wallpaper.util.ScreenSizeCalculator
+
+/**
+ * Parent view for the clock view. We will calculate the current display size and the preview size
+ * and scale down the clock view to fit in the preview.
+ */
+class ClockConstraintLayoutHostView(context: Context, attrs: AttributeSet?) :
+    ConstraintLayout(context, attrs) {
+    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
+        val screenSize = ScreenSizeCalculator.getInstance().getScreenSize(display)
+        super.onMeasure(
+            MeasureSpec.makeMeasureSpec(screenSize.x, EXACTLY),
+            MeasureSpec.makeMeasureSpec(screenSize.y, EXACTLY),
+        )
+        val ratio = MeasureSpec.getSize(widthMeasureSpec) / screenSize.x.toFloat()
+        scaleX = ratio
+        scaleY = ratio
+    }
+
+    companion object {
+        fun addClockViews(
+            clockController: ClockController,
+            rootView: ClockConstraintLayoutHostView,
+            size: ClockSize,
+        ) {
+            clockController.let { clock ->
+                when (size) {
+                    ClockSize.DYNAMIC -> {
+                        clock.largeClock.layout.views.forEach {
+                            if (it.parent != null) {
+                                (it.parent as ViewGroup).removeView(it)
+                            }
+                            rootView.addView(it).apply { it.visibility = View.VISIBLE }
+                        }
+                    }
+
+                    ClockSize.SMALL -> {
+                        clock.smallClock.layout.views.forEach {
+                            if (it.parent != null) {
+                                (it.parent as ViewGroup).removeView(it)
+                            }
+                            rootView.addView(it).apply { it.visibility = View.VISIBLE }
+                        }
+                    }
+                }
+            }
+        }
+    }
+}
diff --git a/src/com/android/customization/picker/clock/ui/view/ClockHostView.kt b/src/com/android/customization/picker/clock/ui/view/ClockHostView.kt
index 512fcd1e..2db52f13 100644
--- a/src/com/android/customization/picker/clock/ui/view/ClockHostView.kt
+++ b/src/com/android/customization/picker/clock/ui/view/ClockHostView.kt
@@ -12,10 +12,7 @@ import com.android.wallpaper.util.ScreenSizeCalculator
  * same size of lockscreen to layout clock and scale down it to the size in picker carousel
  * according to ratio of preview to LS
  */
-class ClockHostView(
-    context: Context,
-    attrs: AttributeSet?,
-) : FrameLayout(context, attrs) {
+class ClockHostView(context: Context, attrs: AttributeSet?) : FrameLayout(context, attrs) {
     private var previewRatio: Float = 1F
         set(value) {
             if (field != value) {
@@ -41,15 +38,16 @@ class ClockHostView(
         parentWidthMeasureSpec: Int,
         widthUsed: Int,
         parentHeightMeasureSpec: Int,
-        heightUsed: Int
+        heightUsed: Int,
     ) {
+
         val screenSize = ScreenSizeCalculator.getInstance().getScreenSize(display)
         super.measureChildWithMargins(
             child,
             MeasureSpec.makeMeasureSpec(screenSize.x, EXACTLY),
             widthUsed,
             MeasureSpec.makeMeasureSpec(screenSize.y, EXACTLY),
-            heightUsed
+            heightUsed,
         )
     }
 }
diff --git a/src/com/android/customization/picker/clock/ui/view/ClockHostView2.kt b/src/com/android/customization/picker/clock/ui/view/ClockHostView2.kt
deleted file mode 100644
index be2e53d3..00000000
--- a/src/com/android/customization/picker/clock/ui/view/ClockHostView2.kt
+++ /dev/null
@@ -1,84 +0,0 @@
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
-package com.android.customization.picker.clock.ui.view
-
-import android.content.Context
-import android.util.AttributeSet
-import android.view.View
-import android.view.View.MeasureSpec.EXACTLY
-import android.widget.FrameLayout
-import com.android.customization.picker.clock.shared.ClockSize
-import com.android.wallpaper.util.ScreenSizeCalculator
-
-/**
- * Parent view for the clock view. We will calculate the current display size and the preview size
- * and scale down the clock view to fit in the preview.
- */
-class ClockHostView2(context: Context, attrs: AttributeSet?) : FrameLayout(context, attrs) {
-
-    var clockSize: ClockSize = ClockSize.DYNAMIC
-        set(value) {
-            if (field != value) {
-                field = value
-                updatePivotAndScale()
-                invalidate()
-            }
-        }
-
-    override fun onLayout(changed: Boolean, left: Int, top: Int, right: Int, bottom: Int) {
-        super.onLayout(changed, left, top, right, bottom)
-        updatePivotAndScale()
-    }
-
-    override fun measureChildWithMargins(
-        child: View?,
-        parentWidthMeasureSpec: Int,
-        widthUsed: Int,
-        parentHeightMeasureSpec: Int,
-        heightUsed: Int,
-    ) {
-        val screenSize = ScreenSizeCalculator.getInstance().getScreenSize(display)
-        super.measureChildWithMargins(
-            child,
-            MeasureSpec.makeMeasureSpec(screenSize.x, EXACTLY),
-            widthUsed,
-            MeasureSpec.makeMeasureSpec(screenSize.y, EXACTLY),
-            heightUsed,
-        )
-    }
-
-    private fun updatePivotAndScale() {
-        when (clockSize) {
-            ClockSize.DYNAMIC -> {
-                resetPivot()
-            }
-            ClockSize.SMALL -> {
-                pivotX = getCenteredHostViewPivotX(this)
-                pivotY = 0F
-            }
-        }
-        val screenSize = ScreenSizeCalculator.getInstance().getScreenSize(display)
-        val ratio = measuredWidth / screenSize.x.toFloat()
-        scaleX = ratio
-        scaleY = ratio
-    }
-
-    companion object {
-        fun getCenteredHostViewPivotX(hostView: View): Float {
-            return if (hostView.isLayoutRtl) hostView.width.toFloat() else 0F
-        }
-    }
-}
diff --git a/src/com/android/customization/picker/clock/ui/view/ThemePickerClockViewFactory.kt b/src/com/android/customization/picker/clock/ui/view/ThemePickerClockViewFactory.kt
index 1f73727c..73ebb0f6 100644
--- a/src/com/android/customization/picker/clock/ui/view/ThemePickerClockViewFactory.kt
+++ b/src/com/android/customization/picker/clock/ui/view/ThemePickerClockViewFactory.kt
@@ -26,9 +26,10 @@ import androidx.annotation.ColorInt
 import androidx.lifecycle.LifecycleOwner
 import com.android.internal.policy.SystemBarUtils
 import com.android.systemui.plugins.clocks.ClockController
+import com.android.systemui.plugins.clocks.ClockFontAxisSetting
 import com.android.systemui.plugins.clocks.WeatherData
+import com.android.systemui.shared.Flags
 import com.android.systemui.shared.clocks.ClockRegistry
-import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.util.ScreenSizeCalculator
 import com.android.wallpaper.util.TimeUtils.TimeTicker
 import java.util.concurrent.ConcurrentHashMap
@@ -64,6 +65,7 @@ constructor(
      * configs, e.g. animation state, might change during the reuse of the clock view in the app.
      */
     override fun getLargeView(clockId: String): View {
+        assert(!Flags.newCustomizationPickerUi())
         return getController(clockId).largeClock.let {
             it.animations.onPickerCarouselSwiping(1F)
             it.view
@@ -75,8 +77,12 @@ constructor(
      * configs, e.g. translation X, might change during the reuse of the clock view in the app.
      */
     override fun getSmallView(clockId: String): View {
+        assert(!Flags.newCustomizationPickerUi())
         val smallClockFrame =
-            smallClockFrames[clockId]
+            smallClockFrames[clockId]?.apply {
+                (layoutParams as FrameLayout.LayoutParams).topMargin = getSmallClockTopMargin()
+                (layoutParams as FrameLayout.LayoutParams).marginStart = getSmallClockStartPadding()
+            }
                 ?: createSmallClockFrame().also {
                     it.addView(getController(clockId).smallClock.view)
                     smallClockFrames[clockId] = it
@@ -86,14 +92,6 @@ constructor(
         return smallClockFrame
     }
 
-    /** Enables or disables the reactive swipe interaction */
-    override fun setReactiveTouchInteractionEnabled(clockId: String, enable: Boolean) {
-        check(BaseFlags.get().isClockReactiveVariantsEnabled()) {
-            "isClockReactiveVariantsEnabled is disabled"
-        }
-        getController(clockId).events.isReactiveTouchInteractionEnabled = enable
-    }
-
     private fun createSmallClockFrame(): FrameLayout {
         val smallClockFrame = FrameLayout(appContext)
         val layoutParams =
@@ -119,21 +117,34 @@ constructor(
     private fun getSmallClockStartPadding() =
         appContext.resources.getDimensionPixelSize(
             com.android.systemui.customization.R.dimen.clock_padding_start
-        )
+        ) +
+            appContext.resources.getDimensionPixelSize(
+                com.android.systemui.customization.R.dimen.status_view_margin_horizontal
+            )
 
     override fun updateColorForAllClocks(@ColorInt seedColor: Int?) {
-        clockControllers.values.forEach { it.events.onSeedColorChanged(seedColor = seedColor) }
+        clockControllers.values.forEach {
+            it.largeClock.run { events.onThemeChanged(theme.copy(seedColor = seedColor)) }
+            it.smallClock.run { events.onThemeChanged(theme.copy(seedColor = seedColor)) }
+        }
     }
 
     override fun updateColor(clockId: String, @ColorInt seedColor: Int?) {
-        getController(clockId).events.onSeedColorChanged(seedColor)
+        getController(clockId).let {
+            it.largeClock.run { events.onThemeChanged(theme.copy(seedColor = seedColor)) }
+            it.smallClock.run { events.onThemeChanged(theme.copy(seedColor = seedColor)) }
+        }
+    }
+
+    override fun updateFontAxes(clockId: String, settings: List<ClockFontAxisSetting>) {
+        getController(clockId).let { it.events.onFontAxesChanged(settings) }
     }
 
     override fun updateRegionDarkness() {
         val isRegionDark = isLockscreenWallpaperDark()
         clockControllers.values.forEach {
-            it.largeClock.events.onRegionDarknessChanged(isRegionDark)
-            it.smallClock.events.onRegionDarknessChanged(isRegionDark)
+            it.largeClock.run { events.onThemeChanged(theme.copy(isDarkTheme = isRegionDark)) }
+            it.smallClock.run { events.onThemeChanged(theme.copy(isDarkTheme = isRegionDark)) }
         }
     }
 
@@ -180,13 +191,12 @@ constructor(
     }
 
     private fun initClockController(clockId: String): ClockController {
+        val isWallpaperDark = isLockscreenWallpaperDark()
         val controller =
-            registry.createExampleClock(clockId).also { it?.initialize(resources, 0f, 0f) }
+            registry.createExampleClock(clockId).also { it?.initialize(isWallpaperDark, 0f, 0f) }
         checkNotNull(controller)
 
-        val isWallpaperDark = isLockscreenWallpaperDark()
         // Initialize large clock
-        controller.largeClock.events.onRegionDarknessChanged(isWallpaperDark)
         controller.largeClock.events.onFontSettingChanged(
             resources
                 .getDimensionPixelSize(
@@ -197,7 +207,6 @@ constructor(
         controller.largeClock.events.onTargetRegionChanged(getLargeClockRegion())
 
         // Initialize small clock
-        controller.smallClock.events.onRegionDarknessChanged(isWallpaperDark)
         controller.smallClock.events.onFontSettingChanged(
             resources
                 .getDimensionPixelSize(
diff --git a/src/com/android/customization/picker/color/data/repository/ColorPickerRepositoryImpl.kt b/src/com/android/customization/picker/color/data/repository/ColorPickerRepositoryImpl.kt
index f5b4ac54..f393880e 100644
--- a/src/com/android/customization/picker/color/data/repository/ColorPickerRepositoryImpl.kt
+++ b/src/com/android/customization/picker/color/data/repository/ColorPickerRepositoryImpl.kt
@@ -24,6 +24,7 @@ import com.android.customization.model.color.ColorOptionImpl
 import com.android.customization.picker.color.shared.model.ColorOptionModel
 import com.android.customization.picker.color.shared.model.ColorType
 import com.android.systemui.monet.Style
+import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.picker.customization.data.repository.WallpaperColorsRepository
 import com.android.wallpaper.picker.customization.shared.model.WallpaperColorsModel
 import javax.inject.Inject
@@ -46,6 +47,8 @@ constructor(
     private val colorManager: ColorCustomizationManager,
 ) : ColorPickerRepository {
 
+    private val isNewPickerUi = BaseFlags.get().isNewPickerUi()
+
     private val homeWallpaperColors: StateFlow<WallpaperColorsModel?> =
         wallpaperColorsRepository.homeWallpaperColors
     private val lockWallpaperColors: StateFlow<WallpaperColorsModel?> =
@@ -56,8 +59,7 @@ constructor(
     private val _isApplyingSystemColor = MutableStateFlow(false)
     override val isApplyingSystemColor = _isApplyingSystemColor.asStateFlow()
 
-    // TODO (b/299510645): update color options on selected option change after restart is disabled
-    override val colorOptions: Flow<Map<ColorType, List<ColorOptionModel>>> =
+    private val generatedColorOptions: Flow<Map<ColorType, List<ColorOptionImpl>>> =
         combine(homeWallpaperColors, lockWallpaperColors) { homeColors, lockColors ->
                 homeColors to lockColors
             }
@@ -71,7 +73,7 @@ constructor(
                             Result.success(
                                 mapOf(
                                     ColorType.WALLPAPER_COLOR to listOf(),
-                                    ColorType.PRESET_COLOR to listOf()
+                                    ColorType.PRESET_COLOR to listOf(),
                                 )
                             )
                         )
@@ -81,28 +83,27 @@ constructor(
                     val lockColorsLoaded = lockColors as WallpaperColorsModel.Loaded
                     colorManager.setWallpaperColors(
                         homeColorsLoaded.colors,
-                        lockColorsLoaded.colors
+                        lockColorsLoaded.colors,
                     )
                     colorManager.fetchOptions(
                         object : CustomizationManager.OptionsFetchedListener<ColorOption?> {
                             override fun onOptionsLoaded(options: MutableList<ColorOption?>?) {
-                                val wallpaperColorOptions: MutableList<ColorOptionModel> =
+                                val wallpaperColorOptions: MutableList<ColorOptionImpl> =
                                     mutableListOf()
-                                val presetColorOptions: MutableList<ColorOptionModel> =
+                                val presetColorOptions: MutableList<ColorOptionImpl> =
                                     mutableListOf()
                                 options?.forEach { option ->
                                     when ((option as ColorOptionImpl).type) {
                                         ColorType.WALLPAPER_COLOR ->
-                                            wallpaperColorOptions.add(option.toModel())
-                                        ColorType.PRESET_COLOR ->
-                                            presetColorOptions.add(option.toModel())
+                                            wallpaperColorOptions.add(option)
+                                        ColorType.PRESET_COLOR -> presetColorOptions.add(option)
                                     }
                                 }
                                 continuation.resumeWith(
                                     Result.success(
                                         mapOf(
                                             ColorType.WALLPAPER_COLOR to wallpaperColorOptions,
-                                            ColorType.PRESET_COLOR to presetColorOptions
+                                            ColorType.PRESET_COLOR to presetColorOptions,
                                         )
                                     )
                                 )
@@ -117,11 +118,88 @@ constructor(
                                 )
                             }
                         },
-                        /* reload= */ false
+                        /* reload= */ false,
                     )
                 }
             }
 
+    override val colorOptions: Flow<Map<ColorType, List<ColorOptionModel>>> =
+        if (isNewPickerUi) {
+            // Convert to ColorOptionModel. When the selected color option changes, update each
+            // ColorOptionModel's isSelected by calling toModel again.
+            combine(generatedColorOptions, selectedColorOption) { generatedColorOptions, _ ->
+                generatedColorOptions
+                    .map { entry ->
+                        entry.key to entry.value.map { colorOption -> colorOption.toModel() }
+                    }
+                    .toMap()
+            }
+        } else {
+            combine(homeWallpaperColors, lockWallpaperColors) { homeColors, lockColors ->
+                    homeColors to lockColors
+                }
+                .map { (homeColors, lockColors) ->
+                    suspendCancellableCoroutine { continuation ->
+                        if (
+                            homeColors is WallpaperColorsModel.Loading ||
+                                lockColors is WallpaperColorsModel.Loading
+                        ) {
+                            continuation.resumeWith(
+                                Result.success(
+                                    mapOf(
+                                        ColorType.WALLPAPER_COLOR to listOf(),
+                                        ColorType.PRESET_COLOR to listOf(),
+                                    )
+                                )
+                            )
+                            return@suspendCancellableCoroutine
+                        }
+                        val homeColorsLoaded = homeColors as WallpaperColorsModel.Loaded
+                        val lockColorsLoaded = lockColors as WallpaperColorsModel.Loaded
+                        colorManager.setWallpaperColors(
+                            homeColorsLoaded.colors,
+                            lockColorsLoaded.colors,
+                        )
+                        colorManager.fetchOptions(
+                            object : CustomizationManager.OptionsFetchedListener<ColorOption?> {
+                                override fun onOptionsLoaded(options: MutableList<ColorOption?>?) {
+                                    val wallpaperColorOptions: MutableList<ColorOptionModel> =
+                                        mutableListOf()
+                                    val presetColorOptions: MutableList<ColorOptionModel> =
+                                        mutableListOf()
+                                    options?.forEach { option ->
+                                        when ((option as ColorOptionImpl).type) {
+                                            ColorType.WALLPAPER_COLOR ->
+                                                wallpaperColorOptions.add(option.toModel())
+                                            ColorType.PRESET_COLOR ->
+                                                presetColorOptions.add(option.toModel())
+                                        }
+                                    }
+                                    continuation.resumeWith(
+                                        Result.success(
+                                            mapOf(
+                                                ColorType.WALLPAPER_COLOR to wallpaperColorOptions,
+                                                ColorType.PRESET_COLOR to presetColorOptions,
+                                            )
+                                        )
+                                    )
+                                }
+
+                                override fun onError(throwable: Throwable?) {
+                                    Log.e(TAG, "Error loading theme bundles", throwable)
+                                    continuation.resumeWith(
+                                        Result.failure(
+                                            throwable ?: Throwable("Error loading theme bundles")
+                                        )
+                                    )
+                                }
+                            },
+                            /* reload= */ false,
+                        )
+                    }
+                }
+        }
+
     override suspend fun select(colorOptionModel: ColorOptionModel) {
         _isApplyingSystemColor.value = true
         suspendCancellableCoroutine { continuation ->
@@ -141,7 +219,7 @@ constructor(
                             Result.failure(throwable ?: Throwable("Error loading theme bundles"))
                         )
                     }
-                }
+                },
             )
         }
     }
@@ -158,11 +236,7 @@ constructor(
             colorOptionBuilder.addOverlayPackage(overlay.key, overlay.value)
         }
         val colorOption = colorOptionBuilder.build()
-        return ColorOptionModel(
-            key = "",
-            colorOption = colorOption,
-            isSelected = false,
-        )
+        return ColorOptionModel(key = "", colorOption = colorOption, isSelected = false)
     }
 
     override fun getCurrentColorSource(): String? {
@@ -173,6 +247,8 @@ constructor(
         return ColorOptionModel(
             key = "${this.type}::${this.style}::${this.serializedPackages}",
             colorOption = this,
+            // Instead of using the selectedColorOption flow to determine isSelected, we check the
+            // source of truth, which is the settings, using ColorOption::isActive
             isSelected = isActive(colorManager),
         )
     }
diff --git a/src/com/android/customization/picker/color/data/repository/FakeColorPickerRepository.kt b/src/com/android/customization/picker/color/data/repository/FakeColorPickerRepository.kt
index f35d934d..b4265166 100644
--- a/src/com/android/customization/picker/color/data/repository/FakeColorPickerRepository.kt
+++ b/src/com/android/customization/picker/color/data/repository/FakeColorPickerRepository.kt
@@ -22,6 +22,7 @@ import android.text.TextUtils
 import com.android.customization.model.ResourceConstants
 import com.android.customization.model.color.ColorOptionImpl
 import com.android.customization.model.color.ColorOptionsProvider
+import com.android.customization.model.color.ColorUtils.toColorString
 import com.android.customization.picker.color.shared.model.ColorOptionModel
 import com.android.customization.picker.color.shared.model.ColorType
 import com.android.systemui.monet.Style
@@ -40,7 +41,7 @@ class FakeColorPickerRepository(private val context: Context) : ColorPickerRepos
         MutableStateFlow(
             mapOf<ColorType, List<ColorOptionModel>>(
                 ColorType.WALLPAPER_COLOR to listOf(),
-                ColorType.PRESET_COLOR to listOf()
+                ColorType.PRESET_COLOR to listOf(),
             )
         )
     override val colorOptions: StateFlow<Map<ColorType, List<ColorOptionModel>>> =
@@ -54,7 +55,7 @@ class FakeColorPickerRepository(private val context: Context) : ColorPickerRepos
         wallpaperOptions: List<ColorOptionImpl>,
         presetOptions: List<ColorOptionImpl>,
         selectedColorOptionType: ColorType,
-        selectedColorOptionIndex: Int
+        selectedColorOptionIndex: Int,
     ) {
         _colorOptions.value =
             mapOf(
@@ -68,7 +69,7 @@ class FakeColorPickerRepository(private val context: Context) : ColorPickerRepos
                                 ColorOptionModel(
                                     key = "${ColorType.WALLPAPER_COLOR}::$index",
                                     colorOption = colorOption,
-                                    isSelected = isSelected
+                                    isSelected = isSelected,
                                 )
                             if (isSelected) {
                                 selectedColorOption = colorOptionModel
@@ -86,7 +87,7 @@ class FakeColorPickerRepository(private val context: Context) : ColorPickerRepos
                                 ColorOptionModel(
                                     key = "${ColorType.PRESET_COLOR}::$index",
                                     colorOption = colorOption,
-                                    isSelected = isSelected
+                                    isSelected = isSelected,
                                 )
                             if (isSelected) {
                                 selectedColorOption = colorOptionModel
@@ -101,7 +102,7 @@ class FakeColorPickerRepository(private val context: Context) : ColorPickerRepos
         numWallpaperOptions: Int,
         numPresetOptions: Int,
         selectedColorOptionType: ColorType,
-        selectedColorOptionIndex: Int
+        selectedColorOptionIndex: Int,
     ) {
         _colorOptions.value =
             mapOf(
@@ -140,7 +141,7 @@ class FakeColorPickerRepository(private val context: Context) : ColorPickerRepos
                             }
                             add(colorOption)
                         }
-                    }
+                    },
             )
     }
 
@@ -160,7 +161,7 @@ class FakeColorPickerRepository(private val context: Context) : ColorPickerRepos
         return builder.build()
     }
 
-    fun buildPresetOption(style: Style, seedColor: String): ColorOptionImpl {
+    fun buildPresetOption(@Style.Type style: Int, seedColor: Int): ColorOptionImpl {
         val builder = ColorOptionImpl.Builder()
         builder.lightColors =
             intArrayOf(Color.TRANSPARENT, Color.TRANSPARENT, Color.TRANSPARENT, Color.TRANSPARENT)
@@ -170,9 +171,13 @@ class FakeColorPickerRepository(private val context: Context) : ColorPickerRepos
         builder.source = ColorOptionsProvider.COLOR_SOURCE_PRESET
         builder.style = style
         builder.title = "Preset"
+        builder.seedColor = seedColor
         builder
             .addOverlayPackage("TEST_PACKAGE_TYPE", "preset_color")
-            .addOverlayPackage(ResourceConstants.OVERLAY_CATEGORY_SYSTEM_PALETTE, seedColor)
+            .addOverlayPackage(
+                ResourceConstants.OVERLAY_CATEGORY_SYSTEM_PALETTE,
+                toColorString(seedColor),
+            )
         return builder.build()
     }
 
@@ -192,7 +197,11 @@ class FakeColorPickerRepository(private val context: Context) : ColorPickerRepos
         return builder.build()
     }
 
-    fun buildWallpaperOption(source: String, style: Style, seedColor: String): ColorOptionImpl {
+    fun buildWallpaperOption(
+        source: String,
+        @Style.Type style: Int,
+        seedColor: Int,
+    ): ColorOptionImpl {
         val builder = ColorOptionImpl.Builder()
         builder.lightColors =
             intArrayOf(Color.TRANSPARENT, Color.TRANSPARENT, Color.TRANSPARENT, Color.TRANSPARENT)
@@ -202,9 +211,13 @@ class FakeColorPickerRepository(private val context: Context) : ColorPickerRepos
         builder.source = source
         builder.style = style
         builder.title = "Dynamic"
+        builder.seedColor = seedColor
         builder
             .addOverlayPackage("TEST_PACKAGE_TYPE", "wallpaper_color")
-            .addOverlayPackage(ResourceConstants.OVERLAY_CATEGORY_SYSTEM_PALETTE, seedColor)
+            .addOverlayPackage(
+                ResourceConstants.OVERLAY_CATEGORY_SYSTEM_PALETTE,
+                toColorString(seedColor),
+            )
         return builder.build()
     }
 
@@ -237,7 +250,7 @@ class FakeColorPickerRepository(private val context: Context) : ColorPickerRepos
         _colorOptions.value =
             mapOf(
                 ColorType.WALLPAPER_COLOR to newWallpaperColorOptions,
-                ColorType.PRESET_COLOR to newBasicColorOptions
+                ColorType.PRESET_COLOR to newBasicColorOptions,
             )
     }
 
diff --git a/src/com/android/customization/picker/color/data/util/MaterialColorsGenerator.kt b/src/com/android/customization/picker/color/data/util/MaterialColorsGenerator.kt
new file mode 100644
index 00000000..a1cc8ffe
--- /dev/null
+++ b/src/com/android/customization/picker/color/data/util/MaterialColorsGenerator.kt
@@ -0,0 +1,192 @@
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
+package com.android.customization.picker.color.data.util
+
+import android.app.WallpaperColors
+import android.content.Context
+import android.content.res.Configuration
+import android.provider.Settings
+import android.util.Log
+import android.util.SparseIntArray
+import com.android.customization.model.ResourceConstants
+import com.android.systemui.monet.ColorScheme
+import com.android.systemui.monet.Style
+import com.android.systemui.shared.settings.data.repository.SecureSettingsRepository
+import dagger.hilt.android.qualifiers.ApplicationContext
+import javax.inject.Inject
+import javax.inject.Singleton
+import org.json.JSONException
+import org.json.JSONObject
+
+/**
+ * Extract material next colors from wallpaper colors. Based on Nexus Launcher's
+ * MaterialColorsGenerator, nexuslauncher/widget/MaterialColorsGenerator.java
+ */
+@Singleton
+class MaterialColorsGenerator
+@Inject
+constructor(
+    @ApplicationContext private val applicationContext: Context,
+    private val secureSettingsRepository: SecureSettingsRepository,
+) {
+    private fun addShades(shades: List<Int>, resources: IntArray, output: SparseIntArray) {
+        if (shades.size != resources.size) {
+            Log.e(TAG, "The number of shades computed doesn't match the number of resources.")
+            return
+        }
+        for (i in resources.indices) {
+            output.put(resources[i], 0xff000000.toInt() or shades[i])
+        }
+    }
+
+    /**
+     * Generates the mapping from system color resources to values from wallpaper colors.
+     *
+     * @return a list of color resource IDs and a corresponding list of their color values
+     */
+    suspend fun generate(colors: WallpaperColors): Pair<IntArray, IntArray> {
+        val isDarkMode =
+            (applicationContext.resources.configuration.uiMode and
+                Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
+        val colorScheme = ColorScheme(colors, isDarkMode, fetchThemeStyleFromSetting())
+        return generate(colorScheme)
+    }
+
+    /**
+     * Generates the mapping from system color resources to values from color seed and style.
+     *
+     * @return a list of color resource IDs and a corresponding list of their color values
+     */
+    fun generate(colorSeed: Int, @Style.Type style: Int): Pair<IntArray, IntArray> {
+        val isDarkMode =
+            (applicationContext.resources.configuration.uiMode and
+                Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
+        val colorScheme = ColorScheme(colorSeed, isDarkMode, style)
+        return generate(colorScheme)
+    }
+
+    private fun generate(colorScheme: ColorScheme): Pair<IntArray, IntArray> {
+        val allNeutralColors: MutableList<Int> = ArrayList()
+        allNeutralColors.addAll(colorScheme.neutral1.allShades)
+        allNeutralColors.addAll(colorScheme.neutral2.allShades)
+
+        val allAccentColors: MutableList<Int> = ArrayList()
+        allAccentColors.addAll(colorScheme.accent1.allShades)
+        allAccentColors.addAll(colorScheme.accent2.allShades)
+        allAccentColors.addAll(colorScheme.accent3.allShades)
+
+        return Pair(
+            NEUTRAL_RESOURCES + ACCENT_RESOURCES,
+            (allNeutralColors + allAccentColors).toIntArray(),
+        )
+    }
+
+    @Style.Type
+    private suspend fun fetchThemeStyleFromSetting(): Int {
+        val overlayPackageJson =
+            secureSettingsRepository.getString(Settings.Secure.THEME_CUSTOMIZATION_OVERLAY_PACKAGES)
+        return if (!overlayPackageJson.isNullOrEmpty()) {
+            try {
+                val jsonObject = JSONObject(overlayPackageJson)
+                Style.valueOf(jsonObject.getString(ResourceConstants.OVERLAY_CATEGORY_THEME_STYLE))
+            } catch (e: (JSONException)) {
+                Log.i(TAG, "Failed to parse THEME_CUSTOMIZATION_OVERLAY_PACKAGES.", e)
+                Style.TONAL_SPOT
+            } catch (e: IllegalArgumentException) {
+                Log.i(TAG, "Failed to parse THEME_CUSTOMIZATION_OVERLAY_PACKAGES.", e)
+                Style.TONAL_SPOT
+            }
+        } else {
+            Style.TONAL_SPOT
+        }
+    }
+
+    companion object {
+        private const val TAG = "MaterialColorsGenerator"
+
+        private val ACCENT_RESOURCES =
+            intArrayOf(
+                android.R.color.system_accent1_0,
+                android.R.color.system_accent1_10,
+                android.R.color.system_accent1_50,
+                android.R.color.system_accent1_100,
+                android.R.color.system_accent1_200,
+                android.R.color.system_accent1_300,
+                android.R.color.system_accent1_400,
+                android.R.color.system_accent1_500,
+                android.R.color.system_accent1_600,
+                android.R.color.system_accent1_700,
+                android.R.color.system_accent1_800,
+                android.R.color.system_accent1_900,
+                android.R.color.system_accent1_1000,
+                android.R.color.system_accent2_0,
+                android.R.color.system_accent2_10,
+                android.R.color.system_accent2_50,
+                android.R.color.system_accent2_100,
+                android.R.color.system_accent2_200,
+                android.R.color.system_accent2_300,
+                android.R.color.system_accent2_400,
+                android.R.color.system_accent2_500,
+                android.R.color.system_accent2_600,
+                android.R.color.system_accent2_700,
+                android.R.color.system_accent2_800,
+                android.R.color.system_accent2_900,
+                android.R.color.system_accent2_1000,
+                android.R.color.system_accent3_0,
+                android.R.color.system_accent3_10,
+                android.R.color.system_accent3_50,
+                android.R.color.system_accent3_100,
+                android.R.color.system_accent3_200,
+                android.R.color.system_accent3_300,
+                android.R.color.system_accent3_400,
+                android.R.color.system_accent3_500,
+                android.R.color.system_accent3_600,
+                android.R.color.system_accent3_700,
+                android.R.color.system_accent3_800,
+                android.R.color.system_accent3_900,
+                android.R.color.system_accent3_1000,
+            )
+        private val NEUTRAL_RESOURCES =
+            intArrayOf(
+                android.R.color.system_neutral1_0,
+                android.R.color.system_neutral1_10,
+                android.R.color.system_neutral1_50,
+                android.R.color.system_neutral1_100,
+                android.R.color.system_neutral1_200,
+                android.R.color.system_neutral1_300,
+                android.R.color.system_neutral1_400,
+                android.R.color.system_neutral1_500,
+                android.R.color.system_neutral1_600,
+                android.R.color.system_neutral1_700,
+                android.R.color.system_neutral1_800,
+                android.R.color.system_neutral1_900,
+                android.R.color.system_neutral1_1000,
+                android.R.color.system_neutral2_0,
+                android.R.color.system_neutral2_10,
+                android.R.color.system_neutral2_50,
+                android.R.color.system_neutral2_100,
+                android.R.color.system_neutral2_200,
+                android.R.color.system_neutral2_300,
+                android.R.color.system_neutral2_400,
+                android.R.color.system_neutral2_500,
+                android.R.color.system_neutral2_600,
+                android.R.color.system_neutral2_700,
+                android.R.color.system_neutral2_800,
+                android.R.color.system_neutral2_900,
+                android.R.color.system_neutral2_1000,
+            )
+    }
+}
diff --git a/src/com/android/customization/picker/color/domain/interactor/ColorPickerInteractor.kt b/src/com/android/customization/picker/color/domain/interactor/ColorPickerInteractor.kt
index aebc6c2f..4f779f8b 100644
--- a/src/com/android/customization/picker/color/domain/interactor/ColorPickerInteractor.kt
+++ b/src/com/android/customization/picker/color/domain/interactor/ColorPickerInteractor.kt
@@ -60,6 +60,4 @@ constructor(
             _selectingColorOption.value = null
         }
     }
-
-    fun getCurrentColorOption(): ColorOptionModel = repository.getCurrentColorOption()
 }
diff --git a/src/com/android/customization/picker/color/shared/model/ColorOptionModel.kt b/src/com/android/customization/picker/color/shared/model/ColorOptionModel.kt
index 5fde08e4..ba477bc7 100644
--- a/src/com/android/customization/picker/color/shared/model/ColorOptionModel.kt
+++ b/src/com/android/customization/picker/color/shared/model/ColorOptionModel.kt
@@ -27,5 +27,5 @@ data class ColorOptionModel(
     val colorOption: ColorOption,
 
     /** Whether this color option is selected. */
-    var isSelected: Boolean,
+    val isSelected: Boolean,
 )
diff --git a/src/com/android/customization/picker/color/ui/binder/ColorOptionIconBinder2.kt b/src/com/android/customization/picker/color/ui/binder/ColorOptionIconBinder2.kt
new file mode 100644
index 00000000..2c197ad8
--- /dev/null
+++ b/src/com/android/customization/picker/color/ui/binder/ColorOptionIconBinder2.kt
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
+ *
+ */
+
+package com.android.customization.picker.color.ui.binder
+
+import com.android.customization.picker.color.ui.view.ColorOptionIconView2
+import com.android.customization.picker.color.ui.viewmodel.ColorOptionIconViewModel
+
+object ColorOptionIconBinder2 {
+    fun bind(view: ColorOptionIconView2, viewModel: ColorOptionIconViewModel, darkTheme: Boolean) {
+        if (darkTheme) {
+            view.bindColor(
+                view.resources.getColor(android.R.color.system_primary_dark, view.context.theme),
+                viewModel.darkThemeColor0,
+                viewModel.darkThemeColor1,
+                viewModel.darkThemeColor2,
+                viewModel.darkThemeColor3,
+            )
+        } else {
+            view.bindColor(
+                view.resources.getColor(android.R.color.system_primary_light, view.context.theme),
+                viewModel.lightThemeColor0,
+                viewModel.lightThemeColor1,
+                viewModel.lightThemeColor2,
+                viewModel.lightThemeColor3,
+            )
+        }
+    }
+}
diff --git a/src/com/android/customization/picker/color/ui/view/ColorOptionIconView2.kt b/src/com/android/customization/picker/color/ui/view/ColorOptionIconView2.kt
new file mode 100644
index 00000000..3fc6324e
--- /dev/null
+++ b/src/com/android/customization/picker/color/ui/view/ColorOptionIconView2.kt
@@ -0,0 +1,139 @@
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
+package com.android.customization.picker.color.ui.view
+
+import android.annotation.ColorInt
+import android.content.Context
+import android.graphics.Canvas
+import android.graphics.Color
+import android.graphics.Paint
+import android.graphics.Path
+import android.util.AttributeSet
+import com.android.themepicker.R
+import com.android.wallpaper.picker.option.ui.view.OptionItemBackground
+
+/**
+ * Draw a color option icon, which is a quadrant circle that can show at most 4 different colors.
+ */
+class ColorOptionIconView2(context: Context, attrs: AttributeSet) :
+    OptionItemBackground(context, attrs) {
+
+    private val paint = Paint().apply { style = Paint.Style.FILL }
+
+    private val path = Path()
+
+    private var color0 = DEFAULT_PLACEHOLDER_COLOR
+    private var color1 = DEFAULT_PLACEHOLDER_COLOR
+    private var color2 = DEFAULT_PLACEHOLDER_COLOR
+    private var color3 = DEFAULT_PLACEHOLDER_COLOR
+    private var strokeColor = DEFAULT_PLACEHOLDER_COLOR
+    private val strokeWidth =
+        context.resources
+            .getDimensionPixelSize(R.dimen.floating_sheet_color_option_stroke_width)
+            .toFloat()
+
+    private var w = 0
+    private var h = 0
+
+    /**
+     * @param color0 the color in the top left quadrant
+     * @param color1 the color in the top right quadrant
+     * @param color2 the color in the bottom left quadrant
+     * @param color3 the color in the bottom right quadrant
+     */
+    fun bindColor(
+        @ColorInt strokeColor: Int,
+        @ColorInt color0: Int,
+        @ColorInt color1: Int,
+        @ColorInt color2: Int,
+        @ColorInt color3: Int,
+    ) {
+        this.strokeColor = strokeColor
+        this.color0 = color0
+        this.color1 = color1
+        this.color2 = color2
+        this.color3 = color3
+        invalidate()
+    }
+
+    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
+        this.w = w
+        this.h = h
+        super.onSizeChanged(w, h, oldw, oldh)
+    }
+
+    override fun onDraw(canvas: Canvas) {
+        // The w and h need to be an even number to avoid tiny pixel-level gaps between the pies
+        w = w.roundDownToEven()
+        h = h.roundDownToEven()
+
+        val width = w.toFloat()
+        val height = h.toFloat()
+
+        val left = 2 * strokeWidth
+        val right = width - 2 * strokeWidth
+        val top = 2 * strokeWidth
+        val bottom = height - 2 * strokeWidth
+        val cornerRadius = ((right - left) / 2) * (1f - 0.25f * progress)
+        val save = canvas.save()
+        path.reset()
+        path.addRoundRect(left, top, right, bottom, cornerRadius, cornerRadius, Path.Direction.CW)
+        path.close()
+        canvas.clipPath(path)
+
+        canvas.apply {
+            paint.style = Paint.Style.FILL
+            // top left
+            paint.color = color0
+            drawRect(0f, 0f, width / 2, height / 2, paint)
+            // top right
+            paint.color = color1
+            drawRect(width / 2, 0f, width, height / 2, paint)
+            // bottom left
+            paint.color = color2
+            drawRect(0f, height / 2, width / 2, height, paint)
+            // bottom right
+            paint.color = color3
+            drawRect(width / 2, height / 2, width, height, paint)
+        }
+
+        canvas.restoreToCount(save)
+        paint.style = Paint.Style.STROKE
+        paint.color = strokeColor
+        paint.alpha = (255 * progress).toInt()
+        paint.strokeWidth = this.strokeWidth
+        val strokeCornerRadius = ((width - strokeWidth) / 2) * (1f - 0.25f * progress)
+        val halfStrokeWidth = 0.5f * strokeWidth
+        // Stroke is centered along the path, so account for half strokeWidth to stay within View
+        canvas.drawRoundRect(
+            halfStrokeWidth,
+            halfStrokeWidth,
+            width - halfStrokeWidth,
+            height - halfStrokeWidth,
+            strokeCornerRadius,
+            strokeCornerRadius,
+            paint,
+        )
+    }
+
+    companion object {
+        const val DEFAULT_PLACEHOLDER_COLOR = Color.BLACK
+
+        fun Int.roundDownToEven(): Int {
+            return if (this % 2 == 0) this else this - 1
+        }
+    }
+}
diff --git a/src/com/android/customization/picker/color/ui/viewmodel/ColorPickerViewModel.kt b/src/com/android/customization/picker/color/ui/viewmodel/ColorPickerViewModel.kt
index 61a648fe..9dba4bb5 100644
--- a/src/com/android/customization/picker/color/ui/viewmodel/ColorPickerViewModel.kt
+++ b/src/com/android/customization/picker/color/ui/viewmodel/ColorPickerViewModel.kt
@@ -49,10 +49,9 @@ private constructor(
 
     /** View-models for each color tab. */
     val colorTypeTabs: Flow<Map<ColorType, ColorTypeTabViewModel>> =
-        combine(
-            interactor.colorOptions,
-            selectedColorTypeTabId,
-        ) { colorOptions, selectedColorTypeIdOrNull ->
+        combine(interactor.colorOptions, selectedColorTypeTabId) {
+            colorOptions,
+            selectedColorTypeIdOrNull ->
             colorOptions.keys
                 .mapIndexed { index, colorType ->
                     val isSelected =
@@ -143,8 +142,7 @@ private constructor(
                                                             .sourceForLogging,
                                                         colorOptionModel.colorOption
                                                             .styleForLogging,
-                                                        colorOptionModel.colorOption
-                                                            .seedColorForLogging,
+                                                        colorOptionModel.colorOption.seedColor,
                                                     )
                                                 }
                                             }
@@ -180,7 +178,7 @@ private constructor(
                     min(
                         max(0, COLOR_SECTION_OPTION_SIZE - wallpaperOptions.size),
                         presetOptions.size,
-                    )
+                    ),
                 )
             subOptions + additionalSubOptions
         }
@@ -192,11 +190,7 @@ private constructor(
     ) : ViewModelProvider.Factory {
         override fun <T : ViewModel> create(modelClass: Class<T>): T {
             @Suppress("UNCHECKED_CAST")
-            return ColorPickerViewModel(
-                context = context,
-                interactor = interactor,
-                logger = logger,
-            )
+            return ColorPickerViewModel(context = context, interactor = interactor, logger = logger)
                 as T
         }
     }
diff --git a/src/com/android/customization/picker/grid/data/repository/GridRepository2.kt b/src/com/android/customization/picker/grid/data/repository/ShapeGridRepository.kt
similarity index 67%
rename from src/com/android/customization/picker/grid/data/repository/GridRepository2.kt
rename to src/com/android/customization/picker/grid/data/repository/ShapeGridRepository.kt
index 8ce4374c..86c455e2 100644
--- a/src/com/android/customization/picker/grid/data/repository/GridRepository2.kt
+++ b/src/com/android/customization/picker/grid/data/repository/ShapeGridRepository.kt
@@ -18,7 +18,8 @@
 package com.android.customization.picker.grid.data.repository
 
 import com.android.customization.model.grid.GridOptionModel
-import com.android.customization.model.grid.GridOptionsManager2
+import com.android.customization.model.grid.ShapeGridManager
+import com.android.customization.model.grid.ShapeOptionModel
 import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import javax.inject.Inject
 import javax.inject.Singleton
@@ -33,35 +34,39 @@ import kotlinx.coroutines.launch
 import kotlinx.coroutines.withContext
 
 @Singleton
-class GridRepository2
+class ShapeGridRepository
 @Inject
 constructor(
-    private val manager: GridOptionsManager2,
+    private val manager: ShapeGridManager,
     @BackgroundDispatcher private val bgScope: CoroutineScope,
     @BackgroundDispatcher private val bgDispatcher: CoroutineDispatcher,
 ) {
 
-    suspend fun isGridOptionAvailable(): Boolean =
-        withContext(bgDispatcher) { manager.isGridOptionAvailable() }
-
+    private val _shapeOptions = MutableStateFlow<List<ShapeOptionModel>?>(null)
     private val _gridOptions = MutableStateFlow<List<GridOptionModel>?>(null)
 
     init {
         bgScope.launch {
-            val options = manager.getGridOptions()
-            _gridOptions.value = options
+            _gridOptions.value = manager.getGridOptions()
+            _shapeOptions.value = manager.getShapeOptions()
         }
     }
 
+    val shapeOptions: StateFlow<List<ShapeOptionModel>?> = _shapeOptions.asStateFlow()
+
+    val selectedShapeOption: Flow<ShapeOptionModel?> =
+        shapeOptions.map { shapeOptions -> shapeOptions?.firstOrNull { it.isCurrent } }
+
     val gridOptions: StateFlow<List<GridOptionModel>?> = _gridOptions.asStateFlow()
 
     val selectedGridOption: Flow<GridOptionModel?> =
         gridOptions.map { gridOptions -> gridOptions?.firstOrNull { it.isCurrent } }
 
-    suspend fun applySelectedOption(key: String) =
+    suspend fun applySelectedOption(shapeKey: String, gridKey: String) =
         withContext(bgDispatcher) {
-            manager.applyGridOption(key)
-            // After applying new grid option, we should query and update the grid options again.
+            manager.applyShapeGridOption(shapeKey, gridKey)
+            // After applying, we should query and update shape and grid options again.
             _gridOptions.value = manager.getGridOptions()
+            _shapeOptions.value = manager.getShapeOptions()
         }
 }
diff --git a/src/com/android/customization/picker/grid/domain/interactor/GridInteractor2.kt b/src/com/android/customization/picker/grid/domain/interactor/ShapeGridInteractor.kt
similarity index 67%
rename from src/com/android/customization/picker/grid/domain/interactor/GridInteractor2.kt
rename to src/com/android/customization/picker/grid/domain/interactor/ShapeGridInteractor.kt
index 30c87d8d..8c4522e5 100644
--- a/src/com/android/customization/picker/grid/domain/interactor/GridInteractor2.kt
+++ b/src/com/android/customization/picker/grid/domain/interactor/ShapeGridInteractor.kt
@@ -17,21 +17,21 @@
 
 package com.android.customization.picker.grid.domain.interactor
 
-import com.android.customization.picker.grid.data.repository.GridRepository2
+import com.android.customization.picker.grid.data.repository.ShapeGridRepository
 import javax.inject.Inject
 import javax.inject.Singleton
 
 @Singleton
-class GridInteractor2
-@Inject
-constructor(
-    private val repository: GridRepository2,
-) {
-    suspend fun isGridOptionAvailable(): Boolean = repository.isGridOptionAvailable()
+class ShapeGridInteractor @Inject constructor(private val repository: ShapeGridRepository) {
+
+    val shapeOptions = repository.shapeOptions
+
+    val selectedShapeOption = repository.selectedShapeOption
 
     val gridOptions = repository.gridOptions
 
     val selectedGridOption = repository.selectedGridOption
 
-    suspend fun applySelectedOption(key: String) = repository.applySelectedOption(key)
+    suspend fun applySelectedOption(shapeKey: String, gridKey: String) =
+        repository.applySelectedOption(shapeKey, gridKey)
 }
diff --git a/src/com/android/customization/picker/grid/ui/viewmodel/ShapeIconViewModel.kt b/src/com/android/customization/picker/grid/ui/viewmodel/ShapeIconViewModel.kt
new file mode 100644
index 00000000..12836034
--- /dev/null
+++ b/src/com/android/customization/picker/grid/ui/viewmodel/ShapeIconViewModel.kt
@@ -0,0 +1,19 @@
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
+package com.android.customization.picker.grid.ui.viewmodel
+
+data class ShapeIconViewModel(val key: String, val path: String)
diff --git a/src/com/android/customization/picker/mode/data/repository/DarkModeRepository.kt b/src/com/android/customization/picker/mode/data/repository/DarkModeRepository.kt
new file mode 100644
index 00000000..28f5017f
--- /dev/null
+++ b/src/com/android/customization/picker/mode/data/repository/DarkModeRepository.kt
@@ -0,0 +1,61 @@
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
+package com.android.customization.picker.mode.data.repository
+
+import com.android.customization.picker.mode.shared.util.DarkModeUtil
+import com.android.wallpaper.system.PowerManagerWrapper
+import com.android.wallpaper.system.UiModeManagerWrapper
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.flowOf
+import kotlinx.coroutines.flow.map
+
+@Singleton
+class DarkModeRepository
+@Inject
+constructor(
+    darkModeUtil: DarkModeUtil,
+    private val uiModeManager: UiModeManagerWrapper,
+    private val powerManager: PowerManagerWrapper,
+) {
+    private val isPowerSaveMode = MutableStateFlow(powerManager.getIsPowerSaveMode() ?: false)
+
+    private val isAvailable = darkModeUtil.isAvailable()
+
+    val isEnabled =
+        if (isAvailable) {
+            isPowerSaveMode.map { !it }
+        } else flowOf(false)
+
+    private val _isDarkMode = MutableStateFlow(uiModeManager.getIsNightModeActivated())
+    val isDarkMode = _isDarkMode.asStateFlow()
+
+    fun setDarkModeActivated(isActive: Boolean) {
+        uiModeManager.setNightModeActivated(isActive)
+        refreshIsDarkModeActivated()
+    }
+
+    fun refreshIsDarkModeActivated() {
+        _isDarkMode.value = uiModeManager.getIsNightModeActivated()
+    }
+
+    fun refreshIsPowerSaveModeActivated() {
+        powerManager.getIsPowerSaveMode()?.let { isPowerSaveMode.value = it }
+    }
+}
diff --git a/src/com/android/customization/picker/mode/domain/interactor/DarkModeInteractor.kt b/src/com/android/customization/picker/mode/domain/interactor/DarkModeInteractor.kt
new file mode 100644
index 00000000..1b74e33b
--- /dev/null
+++ b/src/com/android/customization/picker/mode/domain/interactor/DarkModeInteractor.kt
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
+
+package com.android.customization.picker.mode.domain.interactor
+
+import com.android.customization.picker.mode.data.repository.DarkModeRepository
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+class DarkModeInteractor @Inject constructor(private val repository: DarkModeRepository) {
+    val isEnabled = repository.isEnabled
+    val isDarkMode = repository.isDarkMode
+
+    fun setDarkModeActivated(isActive: Boolean) = repository.setDarkModeActivated(isActive)
+}
diff --git a/src/com/android/customization/picker/mode/shared/util/DarkModeLifecycleUtil.kt b/src/com/android/customization/picker/mode/shared/util/DarkModeLifecycleUtil.kt
new file mode 100644
index 00000000..749ac2ee
--- /dev/null
+++ b/src/com/android/customization/picker/mode/shared/util/DarkModeLifecycleUtil.kt
@@ -0,0 +1,88 @@
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
+package com.android.customization.picker.mode.shared.util
+
+import android.content.BroadcastReceiver
+import android.content.Context
+import android.content.Intent
+import android.content.IntentFilter
+import android.os.PowerManager
+import android.text.TextUtils
+import androidx.lifecycle.DefaultLifecycleObserver
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import com.android.customization.picker.mode.data.repository.DarkModeRepository
+import dagger.hilt.android.qualifiers.ActivityContext
+import dagger.hilt.android.scopes.ActivityScoped
+import javax.inject.Inject
+
+/**
+ * This class observes the activity lifecycle and updates the DarkModeRepositoryImpl based on
+ * lifecycle phases.
+ */
+@ActivityScoped
+class DarkModeLifecycleUtil
+@Inject
+constructor(
+    @ActivityContext private val activityContext: Context,
+    private val darkModeRepository: DarkModeRepository,
+) {
+    private val lifecycleOwner = activityContext as LifecycleOwner
+
+    private val batterySaverStateReceiver =
+        object : BroadcastReceiver() {
+            override fun onReceive(context: Context?, intent: Intent?) {
+                if (
+                    intent != null &&
+                        TextUtils.equals(intent.action, PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
+                ) {
+                    darkModeRepository.refreshIsPowerSaveModeActivated()
+                }
+            }
+        }
+    private val lifecycleObserver =
+        object : DefaultLifecycleObserver {
+            @Synchronized
+            override fun onStart(owner: LifecycleOwner) {
+                super.onStart(owner)
+                darkModeRepository.refreshIsDarkModeActivated()
+                darkModeRepository.refreshIsPowerSaveModeActivated()
+                if (lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
+                    activityContext.registerReceiver(
+                        batterySaverStateReceiver,
+                        IntentFilter(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED),
+                    )
+                }
+            }
+
+            @Synchronized
+            override fun onStop(owner: LifecycleOwner) {
+                super.onStop(owner)
+                activityContext.unregisterReceiver(batterySaverStateReceiver)
+            }
+
+            @Synchronized
+            override fun onDestroy(owner: LifecycleOwner) {
+                super.onDestroy(owner)
+                lifecycleOwner.lifecycle.removeObserver(this)
+            }
+        }
+
+    init {
+        lifecycleOwner.lifecycle.addObserver(lifecycleObserver)
+    }
+}
diff --git a/src/com/android/customization/picker/mode/shared/util/DarkModeUtil.kt b/src/com/android/customization/picker/mode/shared/util/DarkModeUtil.kt
new file mode 100644
index 00000000..9ad514df
--- /dev/null
+++ b/src/com/android/customization/picker/mode/shared/util/DarkModeUtil.kt
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
+package com.android.customization.picker.mode.shared.util
+
+interface DarkModeUtil {
+    fun isAvailable(): Boolean
+}
diff --git a/src/com/android/customization/picker/mode/shared/util/DarkModeUtilImpl.kt b/src/com/android/customization/picker/mode/shared/util/DarkModeUtilImpl.kt
new file mode 100644
index 00000000..a8e85352
--- /dev/null
+++ b/src/com/android/customization/picker/mode/shared/util/DarkModeUtilImpl.kt
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
+package com.android.customization.picker.mode.shared.util
+
+import android.Manifest
+import android.content.Context
+import android.content.pm.PackageManager
+import androidx.core.content.ContextCompat
+import dagger.hilt.android.qualifiers.ApplicationContext
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+class DarkModeUtilImpl @Inject constructor(@ApplicationContext private val context: Context) :
+    DarkModeUtil {
+    override fun isAvailable(): Boolean {
+        return (ContextCompat.checkSelfPermission(
+            context,
+            Manifest.permission.MODIFY_DAY_NIGHT_MODE,
+        ) == PackageManager.PERMISSION_GRANTED)
+    }
+}
diff --git a/src/com/android/customization/picker/mode/shared/util/FakeDarkModeUtil.kt b/src/com/android/customization/picker/mode/shared/util/FakeDarkModeUtil.kt
new file mode 100644
index 00000000..f0225ef1
--- /dev/null
+++ b/src/com/android/customization/picker/mode/shared/util/FakeDarkModeUtil.kt
@@ -0,0 +1,27 @@
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
+package com.android.customization.picker.mode.shared.util
+
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+class FakeDarkModeUtil @Inject constructor() : DarkModeUtil {
+    override fun isAvailable(): Boolean {
+        return true
+    }
+}
diff --git a/src/com/android/customization/picker/mode/ui/binder/DarkModeBinder.kt b/src/com/android/customization/picker/mode/ui/binder/DarkModeBinder.kt
new file mode 100644
index 00000000..b9c70418
--- /dev/null
+++ b/src/com/android/customization/picker/mode/ui/binder/DarkModeBinder.kt
@@ -0,0 +1,41 @@
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
+package com.android.customization.picker.mode.ui.binder
+
+import android.widget.Switch
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import com.android.customization.picker.mode.ui.viewmodel.DarkModeViewModel
+import kotlinx.coroutines.launch
+
+object DarkModeBinder {
+    fun bind(darkModeToggle: Switch, viewModel: DarkModeViewModel, lifecycleOwner: LifecycleOwner) {
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                launch { viewModel.isEnabled.collect { darkModeToggle.isEnabled = it } }
+                launch { viewModel.previewingIsDarkMode.collect { darkModeToggle.isChecked = it } }
+                launch {
+                    viewModel.toggleDarkMode.collect {
+                        darkModeToggle.setOnCheckedChangeListener { _, _ -> it.invoke() }
+                    }
+                }
+            }
+        }
+    }
+}
diff --git a/src/com/android/customization/picker/mode/ui/viewmodel/DarkModeViewModel.kt b/src/com/android/customization/picker/mode/ui/viewmodel/DarkModeViewModel.kt
new file mode 100644
index 00000000..f51d9669
--- /dev/null
+++ b/src/com/android/customization/picker/mode/ui/viewmodel/DarkModeViewModel.kt
@@ -0,0 +1,63 @@
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
+package com.android.customization.picker.mode.ui.viewmodel
+
+import com.android.customization.module.logging.ThemesUserEventLogger
+import com.android.customization.picker.mode.domain.interactor.DarkModeInteractor
+import dagger.hilt.android.scopes.ViewModelScoped
+import javax.inject.Inject
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.combine
+
+@ViewModelScoped
+class DarkModeViewModel
+@Inject
+constructor(private val interactor: DarkModeInteractor, private val logger: ThemesUserEventLogger) {
+    private val isDarkMode = interactor.isDarkMode
+    val isEnabled = interactor.isEnabled
+
+    private val _overridingIsDarkMode = MutableStateFlow<Boolean?>(null)
+    val overridingIsDarkMode = _overridingIsDarkMode.asStateFlow()
+    val previewingIsDarkMode =
+        combine(overridingIsDarkMode, isDarkMode, isEnabled) { override, current, isEnabled ->
+            if (isEnabled) {
+                override ?: current
+            } else current
+        }
+
+    val toggleDarkMode =
+        combine(overridingIsDarkMode, isDarkMode) { override, current ->
+            // Only set override if its value is different from current, else set to null
+            { _overridingIsDarkMode.value = if (override == null) !current else null }
+        }
+
+    val onApply: Flow<(suspend () -> Unit)?> =
+        combine(overridingIsDarkMode, isDarkMode, isEnabled) { override, current, isEnabled ->
+            if (override != null && override != current && isEnabled) {
+                {
+                    interactor.setDarkModeActivated(override)
+                    logger.logDarkThemeApplied(override)
+                }
+            } else null
+        }
+
+    fun resetPreview() {
+        _overridingIsDarkMode.value = null
+    }
+}
diff --git a/src/com/android/customization/picker/preview/ui/section/PreviewWithClockCarouselSectionController.kt b/src/com/android/customization/picker/preview/ui/section/PreviewWithClockCarouselSectionController.kt
index db43f4b5..32b28adf 100644
--- a/src/com/android/customization/picker/preview/ui/section/PreviewWithClockCarouselSectionController.kt
+++ b/src/com/android/customization/picker/preview/ui/section/PreviewWithClockCarouselSectionController.kt
@@ -97,11 +97,7 @@ class PreviewWithClockCarouselSectionController(
     ) {
 
     private val viewModel =
-        ViewModelProvider(
-                activity,
-                clockCarouselViewModelFactory,
-            )
-            .get() as ClockCarouselViewModel
+        ViewModelProvider(activity, clockCarouselViewModelFactory).get() as ClockCarouselViewModel
 
     private var clockColorAndSizeButton: View? = null
 
@@ -184,7 +180,7 @@ class PreviewWithClockCarouselSectionController(
                                 )
                                 if (onAttachStateChangeListener != null) {
                                     carouselView.carousel.removeOnAttachStateChangeListener(
-                                        onAttachStateChangeListener,
+                                        onAttachStateChangeListener
                                     )
                                 }
                             }
diff --git a/src/com/android/wallpaper/customization/ui/binder/ClockFloatingSheetBinder.kt b/src/com/android/wallpaper/customization/ui/binder/ClockFloatingSheetBinder.kt
index a8d06a59..86b2d789 100644
--- a/src/com/android/wallpaper/customization/ui/binder/ClockFloatingSheetBinder.kt
+++ b/src/com/android/wallpaper/customization/ui/binder/ClockFloatingSheetBinder.kt
@@ -16,45 +16,52 @@
 
 package com.android.wallpaper.customization.ui.binder
 
+import android.animation.Animator
+import android.animation.AnimatorListenerAdapter
 import android.animation.ValueAnimator
-import android.annotation.DrawableRes
 import android.content.Context
 import android.content.res.Configuration
-import android.graphics.drawable.Drawable
 import android.view.View
 import android.view.ViewGroup
+import android.view.ViewTreeObserver.OnGlobalLayoutListener
+import android.widget.FrameLayout
 import android.widget.ImageView
 import android.widget.SeekBar
-import androidx.core.content.res.ResourcesCompat
-import androidx.core.view.doOnLayout
+import android.widget.Switch
 import androidx.core.view.isVisible
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
-import androidx.recyclerview.widget.GridLayoutManager
+import androidx.recyclerview.widget.LinearLayoutManager
 import androidx.recyclerview.widget.RecyclerView
 import com.android.customization.picker.clock.shared.ClockSize
 import com.android.customization.picker.color.ui.binder.ColorOptionIconBinder
 import com.android.customization.picker.color.ui.view.ColorOptionIconView
 import com.android.customization.picker.color.ui.viewmodel.ColorOptionIconViewModel
-import com.android.customization.picker.common.ui.view.DoubleRowListItemSpacing
+import com.android.customization.picker.common.ui.view.SingleRowListItemSpacing
+import com.android.systemui.plugins.clocks.AxisType
 import com.android.themepicker.R
 import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptionUtil.ThemePickerLockCustomizationOption.CLOCK
+import com.android.wallpaper.customization.ui.view.ClockFontSliderViewHolder
+import com.android.wallpaper.customization.ui.view.ClockFontSwitchViewHolder
 import com.android.wallpaper.customization.ui.viewmodel.ClockFloatingSheetHeightsViewModel
-import com.android.wallpaper.customization.ui.viewmodel.ClockPickerViewModel.Tab.COLOR
-import com.android.wallpaper.customization.ui.viewmodel.ClockPickerViewModel.Tab.SIZE
-import com.android.wallpaper.customization.ui.viewmodel.ClockPickerViewModel.Tab.STYLE
+import com.android.wallpaper.customization.ui.viewmodel.ClockPickerViewModel
+import com.android.wallpaper.customization.ui.viewmodel.ClockPickerViewModel.ClockStyleModel
+import com.android.wallpaper.customization.ui.viewmodel.ClockPickerViewModel.Tab
 import com.android.wallpaper.customization.ui.viewmodel.ThemePickerCustomizationOptionsViewModel
 import com.android.wallpaper.picker.customization.ui.view.FloatingToolbar
 import com.android.wallpaper.picker.customization.ui.view.adapter.FloatingToolbarTabAdapter
 import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
 import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter
+import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter2
 import java.lang.ref.WeakReference
+import kotlinx.coroutines.DisposableHandle
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.filterNotNull
 import kotlinx.coroutines.launch
 
 object ClockFloatingSheetBinder {
@@ -62,10 +69,10 @@ object ClockFloatingSheetBinder {
     private const val SLIDER_DISABLED_ALPHA = .3f
     private const val ANIMATION_DURATION = 200L
 
-    private val _clockFloatingSheetHeights: MutableStateFlow<ClockFloatingSheetHeightsViewModel?> =
-        MutableStateFlow(null)
-    private val clockFloatingSheetHeights: Flow<ClockFloatingSheetHeightsViewModel?> =
-        _clockFloatingSheetHeights.asStateFlow()
+    private val _clockFloatingSheetHeights: MutableStateFlow<ClockFloatingSheetHeightsViewModel> =
+        MutableStateFlow(ClockFloatingSheetHeightsViewModel())
+    private val clockFloatingSheetHeights: Flow<ClockFloatingSheetHeightsViewModel> =
+        _clockFloatingSheetHeights.asStateFlow().filterNotNull()
 
     fun bind(
         view: View,
@@ -86,7 +93,7 @@ object ClockFloatingSheetBinder {
                 .also { tabs.setAdapter(it) }
 
         val floatingSheetContainer =
-            view.requireViewById<ViewGroup>(R.id.clock_floating_sheet_content_container)
+            view.requireViewById<FrameLayout>(R.id.clock_floating_sheet_content_container)
 
         // Clock style
         val clockStyleContent = view.requireViewById<View>(R.id.clock_floating_sheet_style_content)
@@ -96,6 +103,17 @@ object ClockFloatingSheetBinder {
                 initStyleList(appContext, clockStyleAdapter)
             }
 
+        // Clock font editor
+        val clockFontContent =
+            view.requireViewById<ViewGroup>(R.id.clock_floating_sheet_font_content)
+        val clockFontToolbar = view.requireViewById<ViewGroup>(R.id.clock_font_toolbar)
+        clockFontToolbar.requireViewById<View>(R.id.clock_font_revert).setOnClickListener {
+            viewModel.cancelFontAxes()
+        }
+        clockFontToolbar.requireViewById<View>(R.id.clock_font_apply).setOnClickListener {
+            viewModel.confirmFontAxes()
+        }
+
         // Clock color
         val clockColorContent = view.requireViewById<View>(R.id.clock_floating_sheet_color_content)
         val clockColorAdapter =
@@ -119,57 +137,119 @@ object ClockFloatingSheetBinder {
             }
         )
 
-        // Clock size
-        val clockSizeContent = view.requireViewById<View>(R.id.clock_floating_sheet_size_content)
-        val clockSizeOptionDynamic = view.requireViewById<View>(R.id.clock_size_option_dynamic)
-        val clockSizeOptionSmall = view.requireViewById<View>(R.id.clock_size_option_small)
-
-        view.doOnLayout {
-            if (_clockFloatingSheetHeights.value == null) {
-                _clockFloatingSheetHeights.value =
-                    ClockFloatingSheetHeightsViewModel(
-                        clockStyleContentHeight = clockStyleContent.height,
-                        clockColorContentHeight = clockColorContent.height,
-                        clockSizeContentHeight = clockSizeContent.height,
-                    )
+        // Clock size switch
+        val clockSizeSwitch = view.requireViewById<Switch>(R.id.clock_style_clock_size_switch)
+
+        clockStyleContent.viewTreeObserver.addOnGlobalLayoutListener(
+            object : OnGlobalLayoutListener {
+                override fun onGlobalLayout() {
+                    if (
+                        clockStyleContent.height != 0 &&
+                            _clockFloatingSheetHeights.value.clockStyleContentHeight == null
+                    ) {
+                        _clockFloatingSheetHeights.value =
+                            _clockFloatingSheetHeights.value.copy(
+                                clockStyleContentHeight = clockStyleContent.height
+                            )
+                        clockStyleContent.viewTreeObserver.removeOnGlobalLayoutListener(this)
+                    }
+                }
             }
-        }
+        )
+
+        clockColorContent.viewTreeObserver.addOnGlobalLayoutListener(
+            object : OnGlobalLayoutListener {
+                override fun onGlobalLayout() {
+                    if (
+                        clockColorContent.height != 0 &&
+                            _clockFloatingSheetHeights.value.clockColorContentHeight == null
+                    ) {
+                        _clockFloatingSheetHeights.value =
+                            _clockFloatingSheetHeights.value.copy(
+                                clockColorContentHeight = clockColorContent.height
+                            )
+                        clockColorContent.viewTreeObserver.removeOnGlobalLayoutListener(this)
+                    }
+                }
+            }
+        )
+
+        clockFontContent.viewTreeObserver.addOnGlobalLayoutListener(
+            object : OnGlobalLayoutListener {
+                override fun onGlobalLayout() {
+                    if (
+                        clockFontContent.height != 0 &&
+                            _clockFloatingSheetHeights.value.clockFontContentHeight == null
+                    ) {
+                        _clockFloatingSheetHeights.value =
+                            _clockFloatingSheetHeights.value.copy(
+                                clockFontContentHeight = clockFontContent.height
+                            )
+                        clockColorContent.viewTreeObserver.removeOnGlobalLayoutListener(this)
+                    }
+                }
+            }
+        )
 
         lifecycleOwner.lifecycleScope.launch {
+            var currentContent: View = clockStyleContent
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                 launch { viewModel.tabs.collect { tabAdapter.submitList(it) } }
 
                 launch {
-                    combine(clockFloatingSheetHeights, viewModel.selectedTab) { heights, selectedTab
-                            ->
-                            heights to selectedTab
-                        }
-                        .collect { (heights, selectedTab) ->
-                            heights ?: return@collect
-                            val targetHeight =
-                                when (selectedTab) {
-                                    STYLE -> heights.clockStyleContentHeight
-                                    COLOR -> heights.clockColorContentHeight
-                                    SIZE -> heights.clockSizeContentHeight
-                                } +
-                                    view.resources.getDimensionPixelSize(
-                                        R.dimen.floating_sheet_content_vertical_padding
-                                    ) * 2
-
-                            val animationFloatingSheet =
-                                ValueAnimator.ofInt(floatingSheetContainer.height, targetHeight)
-                            animationFloatingSheet.addUpdateListener { valueAnimator ->
-                                val value = valueAnimator.animatedValue as Int
-                                floatingSheetContainer.layoutParams =
-                                    floatingSheetContainer.layoutParams.apply { height = value }
-                            }
-                            animationFloatingSheet.setDuration(ANIMATION_DURATION)
-                            animationFloatingSheet.start()
+                    combine(clockFloatingSheetHeights, viewModel.selectedTab, ::Pair).collect {
+                        (heights, selectedTab) ->
+                        val (
+                            clockStyleContentHeight,
+                            clockColorContentHeight,
+                            clockFontContentHeight) =
+                            heights
+                        clockStyleContentHeight ?: return@collect
+                        clockColorContentHeight ?: return@collect
+                        clockFontContentHeight ?: return@collect
 
-                            clockStyleContent.isVisible = selectedTab == STYLE
-                            clockColorContent.isVisible = selectedTab == COLOR
-                            clockSizeContent.isVisible = selectedTab == SIZE
-                        }
+                        val fromHeight = floatingSheetContainer.height
+                        val toHeight =
+                            when (selectedTab) {
+                                Tab.STYLE -> clockStyleContentHeight
+                                Tab.COLOR -> clockColorContentHeight
+                                Tab.FONT -> clockFontContentHeight
+                            }
+                        // Start to animate the content height
+                        ValueAnimator.ofInt(fromHeight, toHeight)
+                            .apply {
+                                addUpdateListener { valueAnimator ->
+                                    val value = valueAnimator.animatedValue as Int
+                                    floatingSheetContainer.layoutParams =
+                                        floatingSheetContainer.layoutParams.apply { height = value }
+                                    currentContent.alpha = getAlpha(fromHeight, toHeight, value)
+                                }
+                                duration = ANIMATION_DURATION
+                                addListener(
+                                    object : AnimatorListenerAdapter() {
+                                        override fun onAnimationEnd(animation: Animator) {
+                                            clockStyleContent.isVisible = selectedTab == Tab.STYLE
+                                            clockStyleContent.alpha = 1f
+                                            clockColorContent.isVisible = selectedTab == Tab.COLOR
+                                            clockColorContent.alpha = 1f
+                                            clockFontContent.isVisible = selectedTab == Tab.FONT
+                                            clockFontContent.alpha = 1f
+                                            currentContent =
+                                                when (selectedTab) {
+                                                    Tab.STYLE -> clockStyleContent
+                                                    Tab.COLOR -> clockColorContent
+                                                    Tab.FONT -> clockFontContent
+                                                }
+                                            // Also update the floating toolbar when the height
+                                            // animation ends.
+                                            tabs.isVisible = selectedTab != Tab.FONT
+                                            clockFontToolbar.isVisible = selectedTab == Tab.FONT
+                                        }
+                                    }
+                                )
+                            }
+                            .start()
+                    }
                 }
 
                 launch {
@@ -177,7 +257,7 @@ object ClockFloatingSheetBinder {
                         clockStyleAdapter.setItems(styleOptions) {
                             var indexToFocus = styleOptions.indexOfFirst { it.isSelected.value }
                             indexToFocus = if (indexToFocus < 0) 0 else indexToFocus
-                            (clockStyleList.layoutManager as GridLayoutManager)
+                            (clockStyleList.layoutManager as LinearLayoutManager)
                                 .scrollToPositionWithOffset(indexToFocus, 0)
                         }
                     }
@@ -188,7 +268,7 @@ object ClockFloatingSheetBinder {
                         clockColorAdapter.setItems(colorOptions) {
                             var indexToFocus = colorOptions.indexOfFirst { it.isSelected.value }
                             indexToFocus = if (indexToFocus < 0) 0 else indexToFocus
-                            (clockColorList.layoutManager as GridLayoutManager)
+                            (clockColorList.layoutManager as LinearLayoutManager)
                                 .scrollToPositionWithOffset(indexToFocus, 0)
                         }
                     }
@@ -209,27 +289,106 @@ object ClockFloatingSheetBinder {
                 }
 
                 launch {
-                    viewModel.sizeOptions.collect { sizeOptions ->
-                        sizeOptions.forEach { option ->
-                            lifecycleOwner.lifecycleScope.launch {
-                                lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
-                                    launch {
-                                        option.onClicked.collect { onClicked ->
-                                            when (option.size) {
-                                                ClockSize.DYNAMIC ->
-                                                    clockSizeOptionDynamic.setOnClickListener {
-                                                        onClicked?.invoke()
-                                                    }
-                                                ClockSize.SMALL ->
-                                                    clockSizeOptionSmall.setOnClickListener {
-                                                        onClicked?.invoke()
-                                                    }
-                                            }
-                                        }
-                                    }
+                    viewModel.previewingClockSize.collect { size ->
+                        when (size) {
+                            ClockSize.DYNAMIC -> clockSizeSwitch.isChecked = true
+                            ClockSize.SMALL -> clockSizeSwitch.isChecked = false
+                        }
+                    }
+                }
+
+                launch {
+                    viewModel.onClockSizeSwitchCheckedChange.collect { onCheckedChange ->
+                        clockSizeSwitch.setOnCheckedChangeListener { _, _ ->
+                            onCheckedChange.invoke()
+                        }
+                    }
+                }
+            }
+        }
+
+        bindClockFontContent(
+            clockFontContent = clockFontContent,
+            viewModel = viewModel,
+            lifecycleOwner = lifecycleOwner,
+        )
+    }
+
+    private fun bindClockFontContent(
+        clockFontContent: View,
+        viewModel: ClockPickerViewModel,
+        lifecycleOwner: LifecycleOwner,
+    ) {
+        val sliderViewList =
+            listOf(
+                ClockFontSliderViewHolder(
+                    name = clockFontContent.requireViewById(R.id.clock_axis_slider_name1),
+                    slider = clockFontContent.requireViewById(R.id.clock_axis_slider1),
+                ),
+                ClockFontSliderViewHolder(
+                    name = clockFontContent.requireViewById(R.id.clock_axis_slider_name2),
+                    slider = clockFontContent.requireViewById(R.id.clock_axis_slider2),
+                ),
+            )
+        val switchViewList =
+            listOf(
+                ClockFontSwitchViewHolder(
+                    name = clockFontContent.requireViewById(R.id.clock_axis_switch_name1),
+                    switch = clockFontContent.requireViewById(R.id.clock_axis_switch1),
+                ),
+                ClockFontSwitchViewHolder(
+                    name = clockFontContent.requireViewById(R.id.clock_axis_switch_name2),
+                    switch = clockFontContent.requireViewById(R.id.clock_axis_switch2),
+                ),
+            )
+        val sliderViewMap: MutableMap<String, ClockFontSliderViewHolder> = mutableMapOf()
+        val switchViewMap: MutableMap<String, ClockFontSwitchViewHolder> = mutableMapOf()
+
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                launch {
+                    viewModel.selectedClockFontAxes.filterNotNull().collect { fontAxes ->
+                        // This data flow updates only when a new clock style is selected. We
+                        // initiate the clock font content with regard to that clock style.
+                        sliderViewMap.clear()
+                        switchViewMap.clear()
+
+                        // Initiate the slider views
+                        val floatAxisList = fontAxes.filter { it.type == AxisType.Float }
+                        sliderViewList.forEachIndexed { i, viewHolder ->
+                            val floatAxis = floatAxisList.getOrNull(i)
+                            viewHolder.setIsVisible(floatAxis != null)
+                            floatAxis?.let {
+                                sliderViewMap[floatAxis.key] = viewHolder
+                                viewHolder.initView(it) { value ->
+                                    viewModel.updatePreviewFontAxis(floatAxis.key, value)
                                 }
                             }
                         }
+
+                        // Initiate the switch views
+                        val booleanAxisList = fontAxes.filter { it.type == AxisType.Boolean }
+                        switchViewList.forEachIndexed { i, viewHolder ->
+                            val booleanAxis = booleanAxisList.getOrNull(i)
+                            viewHolder.setIsVisible(booleanAxis != null)
+                            booleanAxis?.let {
+                                switchViewMap[it.key] = viewHolder
+                                viewHolder.initView(booleanAxis) { value ->
+                                    viewModel.updatePreviewFontAxis(booleanAxis.key, value)
+                                }
+                            }
+                        }
+                    }
+                }
+
+                launch {
+                    viewModel.previewingClockFontAxisMap.collect { axisMap ->
+                        // This data flow updates when user configures the sliders and switches
+                        // in the clock font content.
+                        axisMap.forEach { (key, value) ->
+                            sliderViewMap[key]?.setValue(value)
+                            switchViewMap[key]?.setValue(value)
+                        }
                     }
                 }
             }
@@ -238,33 +397,42 @@ object ClockFloatingSheetBinder {
 
     private fun createClockStyleOptionItemAdapter(
         lifecycleOwner: LifecycleOwner
-    ): OptionItemAdapter<Drawable> =
-        OptionItemAdapter(
+    ): OptionItemAdapter2<ClockStyleModel> =
+        OptionItemAdapter2(
             layoutResourceId = R.layout.clock_style_option,
             lifecycleOwner = lifecycleOwner,
-            bindIcon = { foregroundView: View, drawable: Drawable ->
-                (foregroundView as ImageView).setImageDrawable(drawable)
+            bindPayload = { view: View, styleModel: ClockStyleModel ->
+                view
+                    .findViewById<ImageView>(R.id.foreground)
+                    ?.setImageDrawable(styleModel.thumbnail)
+                val job =
+                    lifecycleOwner.lifecycleScope.launch {
+                        lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                            styleModel.showEditButton.collect {
+                                view.findViewById<ImageView>(R.id.edit_icon)?.isVisible = it
+                            }
+                        }
+                    }
+                return@OptionItemAdapter2 DisposableHandle { job.cancel() }
             },
         )
 
-    private fun RecyclerView.initStyleList(context: Context, adapter: OptionItemAdapter<Drawable>) {
-        apply {
-            this.adapter = adapter
-            layoutManager = GridLayoutManager(context, 2, GridLayoutManager.HORIZONTAL, false)
-            addItemDecoration(
-                DoubleRowListItemSpacing(
-                    context.resources.getDimensionPixelSize(
-                        R.dimen.floating_sheet_content_horizontal_padding
-                    ),
-                    context.resources.getDimensionPixelSize(
-                        R.dimen.floating_sheet_list_item_horizontal_space
-                    ),
-                    context.resources.getDimensionPixelSize(
-                        R.dimen.floating_sheet_list_item_vertical_space
-                    ),
-                )
+    private fun RecyclerView.initStyleList(
+        context: Context,
+        adapter: OptionItemAdapter2<ClockStyleModel>,
+    ) {
+        this.adapter = adapter
+        layoutManager = LinearLayoutManager(context, LinearLayoutManager.HORIZONTAL, false)
+        addItemDecoration(
+            SingleRowListItemSpacing(
+                context.resources.getDimensionPixelSize(
+                    R.dimen.floating_sheet_content_horizontal_padding
+                ),
+                context.resources.getDimensionPixelSize(
+                    R.dimen.floating_sheet_list_item_horizontal_space
+                ),
             )
-        }
+        )
     }
 
     private fun createClockColorOptionItemAdapter(
@@ -288,24 +456,21 @@ object ClockFloatingSheetBinder {
     ) {
         apply {
             this.adapter = adapter
-            layoutManager = GridLayoutManager(context, 2, GridLayoutManager.HORIZONTAL, false)
+            layoutManager = LinearLayoutManager(context, LinearLayoutManager.HORIZONTAL, false)
             addItemDecoration(
-                DoubleRowListItemSpacing(
+                SingleRowListItemSpacing(
                     context.resources.getDimensionPixelSize(
                         R.dimen.floating_sheet_content_horizontal_padding
                     ),
                     context.resources.getDimensionPixelSize(
                         R.dimen.floating_sheet_list_item_horizontal_space
                     ),
-                    context.resources.getDimensionPixelSize(
-                        R.dimen.floating_sheet_list_item_vertical_space
-                    ),
                 )
             )
         }
     }
 
-    private fun getDrawable(context: Context, @DrawableRes res: Int): Drawable? {
-        return ResourcesCompat.getDrawable(context.resources, res, null)
-    }
+    // Alpha is 1 when current height is from height, and 0 when current height is to height.
+    private fun getAlpha(fromHeight: Int, toHeight: Int, currentHeight: Int): Float =
+        (1 - (currentHeight - fromHeight).toFloat() / (toHeight - fromHeight).toFloat())
 }
diff --git a/src/com/android/wallpaper/customization/ui/binder/ColorsFloatingSheetBinder.kt b/src/com/android/wallpaper/customization/ui/binder/ColorsFloatingSheetBinder.kt
index b06748ad..7ddcb015 100644
--- a/src/com/android/wallpaper/customization/ui/binder/ColorsFloatingSheetBinder.kt
+++ b/src/com/android/wallpaper/customization/ui/binder/ColorsFloatingSheetBinder.kt
@@ -25,20 +25,20 @@ import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
-import androidx.recyclerview.widget.GridLayoutManager
 import androidx.recyclerview.widget.LinearLayoutManager
 import androidx.recyclerview.widget.RecyclerView
-import com.android.customization.picker.color.ui.binder.ColorOptionIconBinder
-import com.android.customization.picker.color.ui.view.ColorOptionIconView
+import com.android.customization.picker.color.ui.binder.ColorOptionIconBinder2
+import com.android.customization.picker.color.ui.view.ColorOptionIconView2
 import com.android.customization.picker.color.ui.viewmodel.ColorOptionIconViewModel
-import com.android.customization.picker.common.ui.view.DoubleRowListItemSpacing
+import com.android.customization.picker.common.ui.view.SingleRowListItemSpacing
+import com.android.customization.picker.mode.ui.binder.DarkModeBinder
 import com.android.themepicker.R
 import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptionUtil.ThemePickerHomeCustomizationOption.COLORS
 import com.android.wallpaper.customization.ui.viewmodel.ThemePickerCustomizationOptionsViewModel
 import com.android.wallpaper.picker.customization.ui.view.FloatingToolbar
 import com.android.wallpaper.picker.customization.ui.view.adapter.FloatingToolbarTabAdapter
 import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
-import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter
+import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter2
 import java.lang.ref.WeakReference
 import kotlinx.coroutines.launch
 
@@ -65,10 +65,16 @@ object ColorsFloatingSheetBinder {
         val tabAdapter =
             FloatingToolbarTabAdapter(
                     colorUpdateViewModel = WeakReference(colorUpdateViewModel),
-                    shouldAnimateColor = { optionsViewModel.selectedOption.value == COLORS }
+                    shouldAnimateColor = { optionsViewModel.selectedOption.value == COLORS },
                 )
                 .also { tabs.setAdapter(it) }
 
+        DarkModeBinder.bind(
+            darkModeToggle = view.findViewById(R.id.dark_mode_toggle),
+            viewModel = optionsViewModel.darkModeViewModel,
+            lifecycleOwner = lifecycleOwner,
+        )
+
         lifecycleOwner.lifecycleScope.launch {
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                 launch { viewModel.colorTypeTabs.collect { tabAdapter.submitList(it) } }
@@ -85,48 +91,54 @@ object ColorsFloatingSheetBinder {
                         }
                     }
                 }
+
+                launch {
+                    viewModel.previewingColorOption.collect { colorModel ->
+                        if (colorModel != null) {
+                            colorUpdateViewModel.previewColors(
+                                colorModel.colorOption.seedColor,
+                                colorModel.colorOption.style,
+                            )
+                        } else colorUpdateViewModel.resetPreview()
+                    }
+                }
             }
         }
     }
 
     private fun createOptionItemAdapter(
         uiMode: Int,
-        lifecycleOwner: LifecycleOwner
-    ): OptionItemAdapter<ColorOptionIconViewModel> =
-        OptionItemAdapter(
-            layoutResourceId = R.layout.color_option,
+        lifecycleOwner: LifecycleOwner,
+    ): OptionItemAdapter2<ColorOptionIconViewModel> =
+        OptionItemAdapter2(
+            layoutResourceId = R.layout.color_option2,
             lifecycleOwner = lifecycleOwner,
-            bindIcon = { foregroundView: View, colorIcon: ColorOptionIconViewModel ->
-                val colorOptionIconView = foregroundView as? ColorOptionIconView
+            bindPayload = { itemView: View, colorIcon: ColorOptionIconViewModel ->
+                val colorOptionIconView =
+                    itemView.requireViewById<ColorOptionIconView2>(
+                        com.android.wallpaper.R.id.background
+                    )
                 val night = uiMode and UI_MODE_NIGHT_MASK == UI_MODE_NIGHT_YES
-                colorOptionIconView?.let { ColorOptionIconBinder.bind(it, colorIcon, night) }
-            }
+                ColorOptionIconBinder2.bind(colorOptionIconView, colorIcon, night)
+                // Return null since it does not need the lifecycleOwner to launch any job for later
+                // disposal when rebind.
+                return@OptionItemAdapter2 null
+            },
         )
 
     private fun RecyclerView.initColorsList(
         context: Context,
-        adapter: OptionItemAdapter<ColorOptionIconViewModel>,
+        adapter: OptionItemAdapter2<ColorOptionIconViewModel>,
     ) {
         apply {
             this.adapter = adapter
-            layoutManager =
-                GridLayoutManager(
-                    context,
-                    2,
-                    GridLayoutManager.HORIZONTAL,
-                    false,
-                )
+            layoutManager = LinearLayoutManager(context, LinearLayoutManager.HORIZONTAL, false)
             addItemDecoration(
-                DoubleRowListItemSpacing(
+                SingleRowListItemSpacing(
                     context.resources.getDimensionPixelSize(
                         R.dimen.floating_sheet_content_horizontal_padding
                     ),
-                    context.resources.getDimensionPixelSize(
-                        R.dimen.floating_sheet_list_item_horizontal_space
-                    ),
-                    context.resources.getDimensionPixelSize(
-                        R.dimen.floating_sheet_list_item_vertical_space
-                    ),
+                    0,
                 )
             )
         }
diff --git a/src/com/android/wallpaper/customization/ui/binder/ShapeAndGridFloatingSheetBinder.kt b/src/com/android/wallpaper/customization/ui/binder/ShapeAndGridFloatingSheetBinder.kt
deleted file mode 100644
index 7217f619..00000000
--- a/src/com/android/wallpaper/customization/ui/binder/ShapeAndGridFloatingSheetBinder.kt
+++ /dev/null
@@ -1,117 +0,0 @@
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
-package com.android.wallpaper.customization.ui.binder
-
-import android.content.Context
-import android.view.View
-import android.widget.ImageView
-import androidx.lifecycle.Lifecycle
-import androidx.lifecycle.LifecycleOwner
-import androidx.lifecycle.lifecycleScope
-import androidx.lifecycle.repeatOnLifecycle
-import androidx.recyclerview.widget.LinearLayoutManager
-import androidx.recyclerview.widget.RecyclerView
-import com.android.customization.picker.common.ui.view.SingleRowListItemSpacing
-import com.android.customization.picker.grid.ui.binder.GridIconViewBinder
-import com.android.customization.picker.grid.ui.viewmodel.GridIconViewModel
-import com.android.wallpaper.R
-import com.android.wallpaper.customization.ui.viewmodel.ShapeAndGridPickerViewModel
-import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter
-import com.android.wallpaper.picker.option.ui.binder.OptionItemBinder
-import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.launch
-
-object ShapeAndGridFloatingSheetBinder {
-
-    fun bind(
-        view: View,
-        viewModel: ShapeAndGridPickerViewModel,
-        lifecycleOwner: LifecycleOwner,
-        backgroundDispatcher: CoroutineDispatcher,
-    ) {
-        val adapter = createOptionItemAdapter(view.context, lifecycleOwner, backgroundDispatcher)
-        val gridOptionList =
-            view.requireViewById<RecyclerView>(R.id.options).also {
-                it.initGridOptionList(view.context, adapter)
-            }
-
-        lifecycleOwner.lifecycleScope.launch {
-            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
-                launch {
-                    viewModel.optionItems.collect { options ->
-                        adapter.setItems(options) {
-                            val indexToFocus =
-                                options.indexOfFirst { it.isSelected.value }.coerceAtLeast(0)
-                            (gridOptionList.layoutManager as LinearLayoutManager).scrollToPosition(
-                                indexToFocus
-                            )
-                        }
-                    }
-                }
-            }
-        }
-    }
-
-    private fun createOptionItemAdapter(
-        context: Context,
-        lifecycleOwner: LifecycleOwner,
-        backgroundDispatcher: CoroutineDispatcher,
-    ): OptionItemAdapter<GridIconViewModel> =
-        OptionItemAdapter(
-            layoutResourceId = com.android.themepicker.R.layout.grid_option,
-            lifecycleOwner = lifecycleOwner,
-            backgroundDispatcher = backgroundDispatcher,
-            foregroundTintSpec =
-                OptionItemBinder.TintSpec(
-                    selectedColor = context.getColor(R.color.system_on_surface),
-                    unselectedColor = context.getColor(R.color.system_on_surface),
-                ),
-            bindIcon = { foregroundView: View, gridIcon: GridIconViewModel ->
-                val imageView = foregroundView as? ImageView
-                imageView?.let { GridIconViewBinder.bind(imageView, gridIcon) }
-            }
-        )
-
-    private fun RecyclerView.initGridOptionList(
-        context: Context,
-        adapter: OptionItemAdapter<GridIconViewModel>,
-    ) {
-        apply {
-            this.layoutManager =
-                LinearLayoutManager(
-                    context,
-                    RecyclerView.HORIZONTAL,
-                    false,
-                )
-            addItemDecoration(
-                SingleRowListItemSpacing(
-                    edgeItemSpacePx =
-                        context.resources.getDimensionPixelSize(
-                            com.android.themepicker.R.dimen
-                                .floating_sheet_content_horizontal_padding
-                        ),
-                    itemHorizontalSpacePx =
-                        context.resources.getDimensionPixelSize(
-                            com.android.themepicker.R.dimen
-                                .floating_sheet_list_item_horizontal_space
-                        ),
-                )
-            )
-            this.adapter = adapter
-        }
-    }
-}
diff --git a/src/com/android/wallpaper/customization/ui/binder/ShapeGridFloatingSheetBinder.kt b/src/com/android/wallpaper/customization/ui/binder/ShapeGridFloatingSheetBinder.kt
new file mode 100644
index 00000000..138a2534
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/binder/ShapeGridFloatingSheetBinder.kt
@@ -0,0 +1,291 @@
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
+package com.android.wallpaper.customization.ui.binder
+
+import android.animation.ValueAnimator
+import android.content.Context
+import android.view.View
+import android.view.ViewGroup
+import android.view.ViewTreeObserver.OnGlobalLayoutListener
+import android.widget.ImageView
+import androidx.core.view.isVisible
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import androidx.recyclerview.widget.LinearLayoutManager
+import androidx.recyclerview.widget.RecyclerView
+import com.android.customization.picker.common.ui.view.SingleRowListItemSpacing
+import com.android.customization.picker.grid.ui.binder.GridIconViewBinder
+import com.android.customization.picker.grid.ui.viewmodel.GridIconViewModel
+import com.android.customization.picker.grid.ui.viewmodel.ShapeIconViewModel
+import com.android.themepicker.R
+import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptionUtil.ThemePickerHomeCustomizationOption.APP_SHAPE_GRID
+import com.android.wallpaper.customization.ui.viewmodel.ShapeGridFloatingSheetHeightsViewModel
+import com.android.wallpaper.customization.ui.viewmodel.ShapeGridPickerViewModel.Tab.GRID
+import com.android.wallpaper.customization.ui.viewmodel.ShapeGridPickerViewModel.Tab.SHAPE
+import com.android.wallpaper.customization.ui.viewmodel.ThemePickerCustomizationOptionsViewModel
+import com.android.wallpaper.picker.customization.ui.view.FloatingToolbar
+import com.android.wallpaper.picker.customization.ui.view.adapter.FloatingToolbarTabAdapter
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
+import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter
+import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter2
+import com.android.wallpaper.picker.option.ui.binder.OptionItemBinder
+import java.lang.ref.WeakReference
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.filter
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.launch
+
+object ShapeGridFloatingSheetBinder {
+    private const val ANIMATION_DURATION = 200L
+
+    private val _shapeGridFloatingSheetHeights:
+        MutableStateFlow<ShapeGridFloatingSheetHeightsViewModel?> =
+        MutableStateFlow(null)
+    private val shapeGridFloatingSheetHeights: Flow<ShapeGridFloatingSheetHeightsViewModel> =
+        _shapeGridFloatingSheetHeights.asStateFlow().filterNotNull().filter {
+            it.shapeContentHeight != null && it.gridContentHeight != null
+        }
+
+    fun bind(
+        view: View,
+        optionsViewModel: ThemePickerCustomizationOptionsViewModel,
+        colorUpdateViewModel: ColorUpdateViewModel,
+        lifecycleOwner: LifecycleOwner,
+        backgroundDispatcher: CoroutineDispatcher,
+    ) {
+        val floatingSheetContentVerticalPadding =
+            view.resources.getDimensionPixelSize(R.dimen.floating_sheet_content_vertical_padding)
+        val viewModel = optionsViewModel.shapeGridPickerViewModel
+
+        val tabs = view.requireViewById<FloatingToolbar>(R.id.floating_toolbar)
+        val tabAdapter =
+            FloatingToolbarTabAdapter(
+                    colorUpdateViewModel = WeakReference(colorUpdateViewModel),
+                    shouldAnimateColor = { optionsViewModel.selectedOption.value == APP_SHAPE_GRID },
+                )
+                .also { tabs.setAdapter(it) }
+
+        val floatingSheetContainer =
+            view.requireViewById<ViewGroup>(R.id.shape_grid_floating_sheet_content_container)
+
+        val shapeContent = view.requireViewById<View>(R.id.app_shape_container)
+        val shapeOptionListAdapter =
+            createShapeOptionItemAdapter(view.context, lifecycleOwner, backgroundDispatcher)
+        val shapeOptionList =
+            view.requireViewById<RecyclerView>(R.id.shape_options).also {
+                it.initShapeOptionList(view.context, shapeOptionListAdapter)
+            }
+
+        val gridContent = view.requireViewById<View>(R.id.app_grid_container)
+        val gridOptionListAdapter =
+            createGridOptionItemAdapter(lifecycleOwner, backgroundDispatcher)
+        val gridOptionList =
+            view.requireViewById<RecyclerView>(R.id.grid_options).also {
+                it.initGridOptionList(view.context, gridOptionListAdapter)
+            }
+
+        // Get the shape content height when it is ready
+        shapeContent.viewTreeObserver.addOnGlobalLayoutListener(
+            object : OnGlobalLayoutListener {
+                override fun onGlobalLayout() {
+                    if (shapeContent.height != 0) {
+                        _shapeGridFloatingSheetHeights.value =
+                            _shapeGridFloatingSheetHeights.value?.copy(
+                                shapeContentHeight = shapeContent.height
+                            )
+                                ?: ShapeGridFloatingSheetHeightsViewModel(
+                                    shapeContentHeight = shapeContent.height
+                                )
+                    }
+                    shapeContent.viewTreeObserver.removeOnGlobalLayoutListener(this)
+                }
+            }
+        )
+        // Get the grid content height when it is ready
+        gridContent.viewTreeObserver.addOnGlobalLayoutListener(
+            object : OnGlobalLayoutListener {
+                override fun onGlobalLayout() {
+                    if (gridContent.height != 0) {
+                        _shapeGridFloatingSheetHeights.value =
+                            _shapeGridFloatingSheetHeights.value?.copy(
+                                gridContentHeight = gridContent.height
+                            )
+                                ?: ShapeGridFloatingSheetHeightsViewModel(
+                                    gridContentHeight = shapeContent.height
+                                )
+                    }
+                    shapeContent.viewTreeObserver.removeOnGlobalLayoutListener(this)
+                }
+            }
+        )
+
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                launch { viewModel.tabs.collect { tabAdapter.submitList(it) } }
+
+                launch {
+                    combine(shapeGridFloatingSheetHeights, viewModel.selectedTab) {
+                            heights,
+                            selectedTab ->
+                            heights to selectedTab
+                        }
+                        .collect { (heights, selectedTab) ->
+                            val (shapeContentHeight, gridContentHeight) = heights
+                            shapeContentHeight ?: return@collect
+                            gridContentHeight ?: return@collect
+                            // Make sure the recycler view height is the same as its parent. It's
+                            // possible that the recycler view is shorter than expected.
+                            gridOptionList.layoutParams =
+                                gridOptionList.layoutParams.apply { height = gridContentHeight }
+                            val targetHeight =
+                                when (selectedTab) {
+                                    SHAPE -> shapeContentHeight
+                                    GRID -> gridContentHeight
+                                } + floatingSheetContentVerticalPadding * 2
+
+                            ValueAnimator.ofInt(floatingSheetContainer.height, targetHeight)
+                                .apply {
+                                    addUpdateListener { valueAnimator ->
+                                        val value = valueAnimator.animatedValue as Int
+                                        floatingSheetContainer.layoutParams =
+                                            floatingSheetContainer.layoutParams.apply {
+                                                height = value
+                                            }
+                                    }
+                                    duration = ANIMATION_DURATION
+                                }
+                                .start()
+
+                            shapeContent.isVisible = selectedTab == SHAPE
+                            gridContent.isVisible = selectedTab == GRID
+                        }
+                }
+
+                launch {
+                    viewModel.gridOptions.collect { options ->
+                        gridOptionListAdapter.setItems(options) {
+                            val indexToFocus =
+                                options.indexOfFirst { it.isSelected.value }.coerceAtLeast(0)
+                            (gridOptionList.layoutManager as LinearLayoutManager).scrollToPosition(
+                                indexToFocus
+                            )
+                        }
+                    }
+                }
+
+                launch {
+                    viewModel.shapeOptions.collect { options ->
+                        shapeOptionListAdapter.setItems(options) {
+                            val indexToFocus =
+                                options.indexOfFirst { it.isSelected.value }.coerceAtLeast(0)
+                            (shapeOptionList.layoutManager as LinearLayoutManager).scrollToPosition(
+                                indexToFocus
+                            )
+                        }
+                    }
+                }
+            }
+        }
+    }
+
+    private fun createShapeOptionItemAdapter(
+        context: Context,
+        lifecycleOwner: LifecycleOwner,
+        backgroundDispatcher: CoroutineDispatcher,
+    ): OptionItemAdapter<ShapeIconViewModel> =
+        OptionItemAdapter(
+            layoutResourceId = R.layout.shape_option,
+            lifecycleOwner = lifecycleOwner,
+            backgroundDispatcher = backgroundDispatcher,
+            foregroundTintSpec =
+                OptionItemBinder.TintSpec(
+                    selectedColor =
+                        context.getColor(com.android.wallpaper.R.color.system_on_surface),
+                    unselectedColor =
+                        context.getColor(com.android.wallpaper.R.color.system_on_surface),
+                ),
+            bindIcon = { foregroundView: View, shapeIcon: ShapeIconViewModel ->
+                val imageView = foregroundView as? ImageView
+                imageView?.let { ShapeIconViewBinder.bind(imageView, shapeIcon) }
+            },
+        )
+
+    private fun RecyclerView.initShapeOptionList(
+        context: Context,
+        adapter: OptionItemAdapter<ShapeIconViewModel>,
+    ) {
+        apply {
+            this.layoutManager = LinearLayoutManager(context, RecyclerView.HORIZONTAL, false)
+            addItemDecoration(
+                SingleRowListItemSpacing(
+                    edgeItemSpacePx =
+                        context.resources.getDimensionPixelSize(
+                            R.dimen.floating_sheet_content_horizontal_padding
+                        ),
+                    itemHorizontalSpacePx =
+                        context.resources.getDimensionPixelSize(
+                            R.dimen.floating_sheet_list_item_horizontal_space
+                        ),
+                )
+            )
+            this.adapter = adapter
+        }
+    }
+
+    private fun createGridOptionItemAdapter(
+        lifecycleOwner: LifecycleOwner,
+        backgroundDispatcher: CoroutineDispatcher,
+    ): OptionItemAdapter2<GridIconViewModel> =
+        OptionItemAdapter2(
+            layoutResourceId = R.layout.grid_option2,
+            lifecycleOwner = lifecycleOwner,
+            backgroundDispatcher = backgroundDispatcher,
+            bindPayload = { view: View, gridIcon: GridIconViewModel ->
+                val imageView = view.findViewById(R.id.foreground) as? ImageView
+                imageView?.let { GridIconViewBinder.bind(imageView, gridIcon) }
+                return@OptionItemAdapter2 null
+            },
+        )
+
+    private fun RecyclerView.initGridOptionList(
+        context: Context,
+        adapter: OptionItemAdapter2<GridIconViewModel>,
+    ) {
+        apply {
+            this.layoutManager = LinearLayoutManager(context, RecyclerView.HORIZONTAL, false)
+            addItemDecoration(
+                SingleRowListItemSpacing(
+                    edgeItemSpacePx =
+                        context.resources.getDimensionPixelSize(
+                            R.dimen.floating_sheet_content_horizontal_padding
+                        ),
+                    itemHorizontalSpacePx =
+                        context.resources.getDimensionPixelSize(
+                            R.dimen.floating_sheet_grid_list_item_horizontal_space
+                        ),
+                )
+            )
+            this.adapter = adapter
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/binder/ShapeIconViewBinder.kt b/src/com/android/wallpaper/customization/ui/binder/ShapeIconViewBinder.kt
new file mode 100644
index 00000000..550038d4
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/binder/ShapeIconViewBinder.kt
@@ -0,0 +1,27 @@
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
+package com.android.wallpaper.customization.ui.binder
+
+import android.widget.ImageView
+import com.android.customization.picker.grid.ui.viewmodel.ShapeIconViewModel
+import com.android.wallpaper.customization.ui.view.ShapeTileDrawable
+
+object ShapeIconViewBinder {
+    fun bind(view: ImageView, shapeIcon: ShapeIconViewModel) {
+        view.setImageDrawable(ShapeTileDrawable(shapeIcon.path))
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/binder/ShortcutFloatingSheetBinder.kt b/src/com/android/wallpaper/customization/ui/binder/ShortcutFloatingSheetBinder.kt
index bc8ff967..838ef87f 100644
--- a/src/com/android/wallpaper/customization/ui/binder/ShortcutFloatingSheetBinder.kt
+++ b/src/com/android/wallpaper/customization/ui/binder/ShortcutFloatingSheetBinder.kt
@@ -37,7 +37,7 @@ import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
 import com.android.wallpaper.picker.customization.ui.view.FloatingToolbar
 import com.android.wallpaper.picker.customization.ui.view.adapter.FloatingToolbarTabAdapter
 import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
-import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter
+import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter2
 import java.lang.ref.WeakReference
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.flow.collectIndexed
@@ -67,7 +67,7 @@ object ShortcutFloatingSheetBinder {
         val tabAdapter =
             FloatingToolbarTabAdapter(
                     colorUpdateViewModel = WeakReference(colorUpdateViewModel),
-                    shouldAnimateColor = { optionsViewModel.selectedOption.value == SHORTCUTS }
+                    shouldAnimateColor = { optionsViewModel.selectedOption.value == SHORTCUTS },
                 )
                 .also { tabs.setAdapter(it) }
 
@@ -116,7 +116,7 @@ object ShortcutFloatingSheetBinder {
                                 showDialog(
                                     context = view.context,
                                     request = dialogRequest,
-                                    onDismissed = viewModel::onDialogDismissed
+                                    onDismissed = viewModel::onDialogDismissed,
                                 )
                             } else {
                                 null
@@ -148,29 +148,27 @@ object ShortcutFloatingSheetBinder {
         )
     }
 
-    private fun createOptionItemAdapter(lifecycleOwner: LifecycleOwner): OptionItemAdapter<Icon> =
-        OptionItemAdapter(
-            layoutResourceId = R.layout.quick_affordance_list_item,
+    private fun createOptionItemAdapter(lifecycleOwner: LifecycleOwner): OptionItemAdapter2<Icon> =
+        OptionItemAdapter2(
+            layoutResourceId = R.layout.quick_affordance_list_item2,
             lifecycleOwner = lifecycleOwner,
-            bindIcon = { foregroundView: View, gridIcon: Icon ->
-                val imageView = foregroundView as? ImageView
-                imageView?.let { IconViewBinder.bind(imageView, gridIcon) }
+            bindPayload = { itemView: View, gridIcon: Icon ->
+                val imageView =
+                    itemView.requireViewById<ImageView>(com.android.wallpaper.R.id.foreground)
+                IconViewBinder.bind(imageView, gridIcon)
+                // Return null since it does not need the lifecycleOwner to launch any job for later
+                // disposal when rebind.
+                return@OptionItemAdapter2 null
             },
         )
 
     private fun RecyclerView.initQuickAffordanceList(
         context: Context,
-        adapter: OptionItemAdapter<Icon>
+        adapter: OptionItemAdapter2<Icon>,
     ) {
         apply {
             this.adapter = adapter
-            layoutManager =
-                GridLayoutManager(
-                    context,
-                    2,
-                    GridLayoutManager.HORIZONTAL,
-                    false,
-                )
+            layoutManager = GridLayoutManager(context, 2, GridLayoutManager.HORIZONTAL, false)
             addItemDecoration(
                 DoubleRowListItemSpacing(
                     context.resources.getDimensionPixelSize(
diff --git a/src/com/android/wallpaper/customization/ui/binder/ThemePickerCustomizationOptionBinder.kt b/src/com/android/wallpaper/customization/ui/binder/ThemePickerCustomizationOptionBinder.kt
index e223ebc7..46d0346e 100644
--- a/src/com/android/wallpaper/customization/ui/binder/ThemePickerCustomizationOptionBinder.kt
+++ b/src/com/android/wallpaper/customization/ui/binder/ThemePickerCustomizationOptionBinder.kt
@@ -16,10 +16,12 @@
 
 package com.android.wallpaper.customization.ui.binder
 
+import android.content.Context
 import android.view.View
 import android.view.ViewGroup
 import android.widget.ImageView
 import android.widget.TextView
+import androidx.constraintlayout.widget.ConstraintSet
 import androidx.core.content.ContextCompat
 import androidx.core.view.isVisible
 import androidx.lifecycle.Lifecycle
@@ -27,14 +29,18 @@ import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
 import com.android.customization.picker.clock.shared.ClockSize
-import com.android.customization.picker.clock.ui.view.ClockHostView2
+import com.android.customization.picker.clock.ui.view.ClockConstraintLayoutHostView
+import com.android.customization.picker.clock.ui.view.ClockConstraintLayoutHostView.Companion.addClockViews
 import com.android.customization.picker.clock.ui.view.ClockViewFactory
 import com.android.customization.picker.grid.ui.binder.GridIconViewBinder
+import com.android.systemui.plugins.clocks.ClockFontAxisSetting
+import com.android.systemui.plugins.clocks.ClockPreviewConfig
+import com.android.systemui.shared.Flags
 import com.android.themepicker.R
-import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptionUtil.ThemePickerHomeCustomizationOption
 import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptionUtil.ThemePickerLockCustomizationOption
 import com.android.wallpaper.customization.ui.viewmodel.ThemePickerCustomizationOptionsViewModel
+import com.android.wallpaper.model.Screen
 import com.android.wallpaper.picker.common.icon.ui.viewbinder.IconViewBinder
 import com.android.wallpaper.picker.common.text.ui.viewbinder.TextViewBinder
 import com.android.wallpaper.picker.customization.ui.binder.CustomizationOptionsBinder
@@ -46,7 +52,6 @@ import javax.inject.Inject
 import javax.inject.Singleton
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.flow.combine
-import kotlinx.coroutines.flow.filterNotNull
 import kotlinx.coroutines.launch
 
 @Singleton
@@ -63,6 +68,7 @@ constructor(private val defaultCustomizationOptionsBinder: DefaultCustomizationO
         viewModel: CustomizationPickerViewModel2,
         colorUpdateViewModel: ColorUpdateViewModel,
         lifecycleOwner: LifecycleOwner,
+        navigateToWallpaperCategoriesScreen: (screen: Screen) -> Unit,
     ) {
         defaultCustomizationOptionsBinder.bind(
             view,
@@ -72,12 +78,14 @@ constructor(private val defaultCustomizationOptionsBinder: DefaultCustomizationO
             viewModel,
             colorUpdateViewModel,
             lifecycleOwner,
+            navigateToWallpaperCategoriesScreen,
         )
 
         val optionClock =
             lockScreenCustomizationOptionEntries
                 .find { it.first == ThemePickerLockCustomizationOption.CLOCK }
                 ?.second
+        val optionClockIcon = optionClock?.findViewById<ImageView>(R.id.option_entry_clock_icon)
 
         val optionShortcut =
             lockScreenCustomizationOptionEntries
@@ -101,14 +109,14 @@ constructor(private val defaultCustomizationOptionsBinder: DefaultCustomizationO
                 .find { it.first == ThemePickerHomeCustomizationOption.COLORS }
                 ?.second
 
-        val optionShapeAndGrid =
+        val optionShapeGrid =
             homeScreenCustomizationOptionEntries
-                .find { it.first == ThemePickerHomeCustomizationOption.APP_SHAPE_AND_GRID }
+                .find { it.first == ThemePickerHomeCustomizationOption.APP_SHAPE_GRID }
                 ?.second
-        val optionShapeAndGridDescription =
-            optionShapeAndGrid?.findViewById<TextView>(R.id.option_entry_app_grid_description)
-        val optionShapeAndGridIcon =
-            optionShapeAndGrid?.findViewById<ImageView>(R.id.option_entry_app_grid_icon)
+        val optionShapeGridDescription =
+            optionShapeGrid?.findViewById<TextView>(R.id.option_entry_app_shape_grid_description)
+        val optionShapeGridIcon =
+            optionShapeGrid?.findViewById<ImageView>(R.id.option_entry_app_shape_grid_icon)
 
         val optionsViewModel =
             viewModel.customizationOptionsViewModel as ThemePickerCustomizationOptionsViewModel
@@ -120,6 +128,12 @@ constructor(private val defaultCustomizationOptionsBinder: DefaultCustomizationO
                     }
                 }
 
+                launch {
+                    optionsViewModel.clockPickerViewModel.selectedClock.collect {
+                        optionClockIcon?.setImageDrawable(it.thumbnail)
+                    }
+                }
+
                 launch {
                     optionsViewModel.onCustomizeShortcutClicked.collect {
                         optionShortcut?.setOnClickListener { _ -> it?.invoke() }
@@ -155,23 +169,21 @@ constructor(private val defaultCustomizationOptionsBinder: DefaultCustomizationO
                 }
 
                 launch {
-                    optionsViewModel.onCustomizeShapeAndGridClicked.collect {
-                        optionShapeAndGrid?.setOnClickListener { _ -> it?.invoke() }
+                    optionsViewModel.onCustomizeShapeGridClicked.collect {
+                        optionShapeGrid?.setOnClickListener { _ -> it?.invoke() }
                     }
                 }
 
                 launch {
-                    optionsViewModel.shapeAndGridPickerViewModel.selectedGridOption.collect {
+                    optionsViewModel.shapeGridPickerViewModel.selectedGridOption.collect {
                         gridOption ->
-                        optionShapeAndGridDescription?.let {
-                            TextViewBinder.bind(it, gridOption.text)
-                        }
+                        optionShapeGridDescription?.let { TextViewBinder.bind(it, gridOption.text) }
                         gridOption.payload?.let { gridIconViewModel ->
-                            optionShapeAndGridIcon?.let {
+                            optionShapeGridIcon?.let {
                                 GridIconViewBinder.bind(view = it, viewModel = gridIconViewModel)
                             }
                             // TODO(b/363018910): Use ColorUpdateBinder to update color
-                            optionShapeAndGridIcon?.setColorFilter(
+                            optionShapeGridIcon?.setColorFilter(
                                 ContextCompat.getColor(
                                     view.context,
                                     com.android.wallpaper.R.color.system_on_surface_variant,
@@ -217,11 +229,12 @@ constructor(private val defaultCustomizationOptionsBinder: DefaultCustomizationO
             }
 
         customizationOptionFloatingSheetViewMap
-            ?.get(ThemePickerHomeCustomizationOption.APP_SHAPE_AND_GRID)
+            ?.get(ThemePickerHomeCustomizationOption.APP_SHAPE_GRID)
             ?.let {
-                ShapeAndGridFloatingSheetBinder.bind(
+                ShapeGridFloatingSheetBinder.bind(
                     it,
-                    optionsViewModel.shapeAndGridPickerViewModel,
+                    optionsViewModel,
+                    colorUpdateViewModel,
                     lifecycleOwner,
                     Dispatchers.IO,
                 )
@@ -229,12 +242,14 @@ constructor(private val defaultCustomizationOptionsBinder: DefaultCustomizationO
     }
 
     override fun bindClockPreview(
+        context: Context,
         clockHostView: View,
         viewModel: CustomizationPickerViewModel2,
+        colorUpdateViewModel: ColorUpdateViewModel,
         lifecycleOwner: LifecycleOwner,
         clockViewFactory: ClockViewFactory,
     ) {
-        clockHostView as ClockHostView2
+        clockHostView as ClockConstraintLayoutHostView
         val clockPickerViewModel =
             (viewModel.customizationOptionsViewModel as ThemePickerCustomizationOptionsViewModel)
                 .clockPickerViewModel
@@ -243,30 +258,52 @@ constructor(private val defaultCustomizationOptionsBinder: DefaultCustomizationO
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                 launch {
                     combine(
-                            clockPickerViewModel.previewingClock.filterNotNull(),
+                            clockPickerViewModel.previewingClock,
                             clockPickerViewModel.previewingClockSize,
                         ) { clock, size ->
                             clock to size
                         }
                         .collect { (clock, size) ->
                             clockHostView.removeAllViews()
-                            if (BaseFlags.get().isClockReactiveVariantsEnabled()) {
-                                clockViewFactory.setReactiveTouchInteractionEnabled(
-                                    clock.clockId,
-                                    true,
-                                )
-                            }
-                            val clockView =
-                                when (size) {
-                                    ClockSize.DYNAMIC ->
-                                        clockViewFactory.getLargeView(clock.clockId)
-                                    ClockSize.SMALL -> clockViewFactory.getSmallView(clock.clockId)
+                            // For new customization picker, we should get views from clocklayout
+                            if (Flags.newCustomizationPickerUi()) {
+                                clockViewFactory.getController(clock.clockId).let { clockController
+                                    ->
+                                    addClockViews(clockController, clockHostView, size)
+                                    val cs = ConstraintSet()
+                                    // TODO(b/379348167): get correct isShadeLayoutWide from picker
+                                    clockController.largeClock.layout.applyPreviewConstraints(
+                                        ClockPreviewConfig(
+                                            previewContext = context,
+                                            isShadeLayoutWide = false,
+                                            isSceneContainerFlagEnabled = false,
+                                        ),
+                                        cs,
+                                    )
+                                    clockController.smallClock.layout.applyPreviewConstraints(
+                                        ClockPreviewConfig(
+                                            previewContext = context,
+                                            isShadeLayoutWide = false,
+                                            isSceneContainerFlagEnabled = false,
+                                        ),
+                                        cs,
+                                    )
+                                    cs.applyTo(clockHostView)
                                 }
-                            // The clock view might still be attached to an existing parent. Detach
-                            // before adding to another parent.
-                            (clockView.parent as? ViewGroup)?.removeView(clockView)
-                            clockHostView.addView(clockView)
-                            clockHostView.clockSize = size
+                            } else {
+                                val clockView =
+                                    when (size) {
+                                        ClockSize.DYNAMIC ->
+                                            clockViewFactory.getLargeView(clock.clockId)
+                                        ClockSize.SMALL ->
+                                            clockViewFactory.getSmallView(clock.clockId)
+                                    }
+                                // The clock view might still be attached to an existing parent.
+                                // Detach
+                                // before adding to another parent.
+                                (clockView.parent as? ViewGroup)?.removeView(clockView)
+                                clockHostView.addView(clockView)
+                            }
                         }
                 }
 
@@ -274,14 +311,20 @@ constructor(private val defaultCustomizationOptionsBinder: DefaultCustomizationO
                     combine(
                             clockPickerViewModel.previewingSeedColor,
                             clockPickerViewModel.previewingClock,
-                        ) { color, clock ->
-                            color to clock
-                        }
-                        .collect { (color, clock) ->
+                            clockPickerViewModel.previewingClockFontAxisMap,
+                            colorUpdateViewModel.systemColorsUpdated,
+                            ::Quadruple,
+                        )
+                        .collect { quadruple ->
+                            val (color, clock, axisMap, _) = quadruple
                             clockViewFactory.updateColor(clock.clockId, color)
+                            val axisList = axisMap.map { ClockFontAxisSetting(it.key, it.value) }
+                            clockViewFactory.updateFontAxes(clock.clockId, axisList)
                         }
                 }
             }
         }
     }
+
+    data class Quadruple<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)
 }
diff --git a/src/com/android/wallpaper/customization/ui/binder/ThemePickerToolbarBinder.kt b/src/com/android/wallpaper/customization/ui/binder/ThemePickerToolbarBinder.kt
index 91705dc5..c17775a8 100644
--- a/src/com/android/wallpaper/customization/ui/binder/ThemePickerToolbarBinder.kt
+++ b/src/com/android/wallpaper/customization/ui/binder/ThemePickerToolbarBinder.kt
@@ -16,20 +16,32 @@
 
 package com.android.wallpaper.customization.ui.binder
 
+import android.animation.ValueAnimator
+import android.view.ViewTreeObserver.OnGlobalLayoutListener
 import android.widget.Button
 import android.widget.FrameLayout
 import android.widget.Toolbar
-import androidx.core.view.isVisible
+import androidx.core.graphics.ColorUtils
+import androidx.core.graphics.drawable.DrawableCompat
+import androidx.core.view.isInvisible
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
 import com.android.wallpaper.customization.ui.viewmodel.ThemePickerCustomizationOptionsViewModel
+import com.android.wallpaper.customization.ui.viewmodel.ToolbarHeightsViewModel
+import com.android.wallpaper.picker.customization.ui.binder.ColorUpdateBinder
 import com.android.wallpaper.picker.customization.ui.binder.DefaultToolbarBinder
 import com.android.wallpaper.picker.customization.ui.binder.ToolbarBinder
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
 import javax.inject.Inject
 import javax.inject.Singleton
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.map
 import kotlinx.coroutines.launch
 
 @Singleton
@@ -37,14 +49,27 @@ class ThemePickerToolbarBinder
 @Inject
 constructor(private val defaultToolbarBinder: DefaultToolbarBinder) : ToolbarBinder {
 
+    private val _toolbarHeights: MutableStateFlow<ToolbarHeightsViewModel?> = MutableStateFlow(null)
+    private val toolbarHeights = _toolbarHeights.asStateFlow().filterNotNull()
+
     override fun bind(
         navButton: FrameLayout,
         toolbar: Toolbar,
         applyButton: Button,
         viewModel: CustomizationOptionsViewModel,
+        colorUpdateViewModel: ColorUpdateViewModel,
         lifecycleOwner: LifecycleOwner,
+        onNavBack: () -> Unit,
     ) {
-        defaultToolbarBinder.bind(navButton, toolbar, applyButton, viewModel, lifecycleOwner)
+        defaultToolbarBinder.bind(
+            navButton,
+            toolbar,
+            applyButton,
+            viewModel,
+            colorUpdateViewModel,
+            lifecycleOwner,
+            onNavBack,
+        )
 
         if (viewModel !is ThemePickerCustomizationOptionsViewModel) {
             throw IllegalArgumentException(
@@ -52,18 +77,138 @@ constructor(private val defaultToolbarBinder: DefaultToolbarBinder) : ToolbarBin
             )
         }
 
+        navButton.viewTreeObserver.addOnGlobalLayoutListener(
+            object : OnGlobalLayoutListener {
+                override fun onGlobalLayout() {
+                    if (navButton.height != 0) {
+                        _toolbarHeights.value =
+                            _toolbarHeights.value?.copy(navButtonHeight = navButton.height)
+                                ?: ToolbarHeightsViewModel(navButtonHeight = navButton.height)
+                    }
+                    navButton.viewTreeObserver.removeOnGlobalLayoutListener(this)
+                }
+            }
+        )
+
+        toolbar.viewTreeObserver.addOnGlobalLayoutListener(
+            object : OnGlobalLayoutListener {
+                override fun onGlobalLayout() {
+                    if (toolbar.height != 0) {
+                        _toolbarHeights.value =
+                            _toolbarHeights.value?.copy(toolbarHeight = toolbar.height)
+                                ?: ToolbarHeightsViewModel(toolbarHeight = toolbar.height)
+                    }
+                    navButton.viewTreeObserver.removeOnGlobalLayoutListener(this)
+                }
+            }
+        )
+
+        applyButton.viewTreeObserver.addOnGlobalLayoutListener(
+            object : OnGlobalLayoutListener {
+                override fun onGlobalLayout() {
+                    if (applyButton.height != 0) {
+                        _toolbarHeights.value =
+                            _toolbarHeights.value?.copy(applyButtonHeight = applyButton.height)
+                                ?: ToolbarHeightsViewModel(applyButtonHeight = applyButton.height)
+                    }
+                    applyButton.viewTreeObserver.removeOnGlobalLayoutListener(this)
+                }
+            }
+        )
+
+        ColorUpdateBinder.bind(
+            setColor = { color ->
+                DrawableCompat.setTint(DrawableCompat.wrap(applyButton.background), color)
+            },
+            color = colorUpdateViewModel.colorPrimary,
+            shouldAnimate = { true },
+            lifecycleOwner = lifecycleOwner,
+        )
+
         lifecycleOwner.lifecycleScope.launch {
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                 launch {
                     viewModel.onApplyButtonClicked.collect { onApplyButtonClicked ->
-                        applyButton.setOnClickListener { onApplyButtonClicked?.invoke() }
+                        applyButton.setOnClickListener { onApplyButtonClicked?.invoke(onNavBack) }
                     }
                 }
 
-                launch { viewModel.isOnApplyVisible.collect { applyButton.isVisible = it } }
+                launch { viewModel.isApplyButtonVisible.collect { applyButton.isInvisible = !it } }
+
+                launch {
+                    viewModel.isApplyButtonEnabled.collect {
+                        applyButton.isEnabled = it
+                        applyButton.background.alpha =
+                            if (it) 255 else 31 // 255 for 100%, 31 for 12% transparent
+                        ColorUpdateBinder.bind(
+                            setColor = { color -> applyButton.setTextColor(color) },
+                            color =
+                                if (it) {
+                                    colorUpdateViewModel.colorOnPrimary
+                                } else {
+                                    colorUpdateViewModel.colorOnSurface.map { color: Int ->
+                                        ColorUtils.setAlphaComponent(
+                                            color,
+                                            97,
+                                        ) // 97 for 38% transparent
+                                    }
+                                },
+                            shouldAnimate = { true },
+                            lifecycleOwner = lifecycleOwner,
+                        )
+                    }
+                }
+
+                launch {
+                    combine(toolbarHeights, viewModel.isToolbarCollapsed, ::Pair).collect {
+                        (toolbarHeights, isToolbarCollapsed) ->
+                        val (navButtonHeight, toolbarHeight, applyButtonHeight) = toolbarHeights
+                        navButtonHeight ?: return@collect
+                        toolbarHeight ?: return@collect
+                        applyButtonHeight ?: return@collect
 
-                launch { viewModel.isOnApplyEnabled.collect { applyButton.isEnabled = it } }
+                        val navButtonToHeight = if (isToolbarCollapsed) 0 else navButtonHeight
+                        val toolbarToHeight = if (isToolbarCollapsed) 0 else toolbarHeight
+                        val applyButtonToHeight = if (isToolbarCollapsed) 0 else applyButtonHeight
+                        ValueAnimator.ofInt(navButton.height, navButtonToHeight)
+                            .apply {
+                                addUpdateListener { valueAnimator ->
+                                    val value = valueAnimator.animatedValue as Int
+                                    navButton.layoutParams =
+                                        navButton.layoutParams.apply { height = value }
+                                }
+                                duration = ANIMATION_DURATION
+                            }
+                            .start()
+
+                        ValueAnimator.ofInt(toolbar.height, toolbarToHeight)
+                            .apply {
+                                addUpdateListener { valueAnimator ->
+                                    val value = valueAnimator.animatedValue as Int
+                                    toolbar.layoutParams =
+                                        toolbar.layoutParams.apply { height = value }
+                                }
+                                duration = ANIMATION_DURATION
+                            }
+                            .start()
+
+                        ValueAnimator.ofInt(applyButton.height, applyButtonToHeight)
+                            .apply {
+                                addUpdateListener { valueAnimator ->
+                                    val value = valueAnimator.animatedValue as Int
+                                    applyButton.layoutParams =
+                                        applyButton.layoutParams.apply { height = value }
+                                }
+                                duration = ANIMATION_DURATION
+                            }
+                            .start()
+                    }
+                }
             }
         }
     }
+
+    companion object {
+        private const val ANIMATION_DURATION = 200L
+    }
 }
diff --git a/src/com/android/wallpaper/customization/ui/util/ThemePickerCustomizationOptionUtil.kt b/src/com/android/wallpaper/customization/ui/util/ThemePickerCustomizationOptionUtil.kt
index 7a73b7d8..60063273 100644
--- a/src/com/android/wallpaper/customization/ui/util/ThemePickerCustomizationOptionUtil.kt
+++ b/src/com/android/wallpaper/customization/ui/util/ThemePickerCustomizationOptionUtil.kt
@@ -21,6 +21,7 @@ import android.view.View
 import android.view.ViewGroup
 import android.widget.FrameLayout
 import android.widget.LinearLayout
+import com.android.customization.picker.mode.shared.util.DarkModeLifecycleUtil
 import com.android.themepicker.R
 import com.android.wallpaper.model.Screen
 import com.android.wallpaper.model.Screen.HOME_SCREEN
@@ -36,6 +37,9 @@ class ThemePickerCustomizationOptionUtil
 constructor(private val defaultCustomizationOptionUtil: DefaultCustomizationOptionUtil) :
     CustomizationOptionUtil {
 
+    // Instantiate DarkModeLifecycleUtil for it to observe lifecycle and update DarkModeRepository
+    @Inject lateinit var darkModeLifecycleUtil: DarkModeLifecycleUtil
+
     enum class ThemePickerLockCustomizationOption : CustomizationOptionUtil.CustomizationOption {
         CLOCK,
         SHORTCUTS,
@@ -45,7 +49,7 @@ constructor(private val defaultCustomizationOptionUtil: DefaultCustomizationOpti
 
     enum class ThemePickerHomeCustomizationOption : CustomizationOptionUtil.CustomizationOption {
         COLORS,
-        APP_SHAPE_AND_GRID,
+        APP_SHAPE_GRID,
         THEMED_ICONS,
     }
 
@@ -105,9 +109,9 @@ constructor(private val defaultCustomizationOptionUtil: DefaultCustomizationOpti
                             )
                     )
                     add(
-                        ThemePickerHomeCustomizationOption.APP_SHAPE_AND_GRID to
+                        ThemePickerHomeCustomizationOption.APP_SHAPE_GRID to
                             layoutInflater.inflate(
-                                R.layout.customization_option_entry_app_shape_and_grid,
+                                R.layout.customization_option_entry_app_shape_grid,
                                 optionContainer,
                                 false,
                             )
@@ -160,9 +164,9 @@ constructor(private val defaultCustomizationOptionUtil: DefaultCustomizationOpti
                     .also { bottomSheetContainer.addView(it) },
             )
             put(
-                ThemePickerHomeCustomizationOption.APP_SHAPE_AND_GRID,
+                ThemePickerHomeCustomizationOption.APP_SHAPE_GRID,
                 inflateFloatingSheet(
-                        ThemePickerHomeCustomizationOption.APP_SHAPE_AND_GRID,
+                        ThemePickerHomeCustomizationOption.APP_SHAPE_GRID,
                         bottomSheetContainer,
                         layoutInflater,
                     )
@@ -189,8 +193,7 @@ constructor(private val defaultCustomizationOptionUtil: DefaultCustomizationOpti
             ThemePickerLockCustomizationOption.CLOCK -> R.layout.floating_sheet_clock
             ThemePickerLockCustomizationOption.SHORTCUTS -> R.layout.floating_sheet_shortcut
             ThemePickerHomeCustomizationOption.COLORS -> R.layout.floating_sheet_colors
-            ThemePickerHomeCustomizationOption.APP_SHAPE_AND_GRID ->
-                R.layout.floating_sheet_shape_and_grid
+            ThemePickerHomeCustomizationOption.APP_SHAPE_GRID -> R.layout.floating_sheet_shape_grid
             else ->
                 throw IllegalStateException(
                     "Customization option $option does not have a bottom sheet view"
diff --git a/src/com/android/wallpaper/customization/ui/view/ClockFontSliderViewHolder.kt b/src/com/android/wallpaper/customization/ui/view/ClockFontSliderViewHolder.kt
new file mode 100644
index 00000000..8bdf073b
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/view/ClockFontSliderViewHolder.kt
@@ -0,0 +1,60 @@
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
+package com.android.wallpaper.customization.ui.view
+
+import android.widget.SeekBar
+import android.widget.TextView
+import androidx.core.view.isInvisible
+import com.android.systemui.plugins.clocks.ClockFontAxis
+
+class ClockFontSliderViewHolder(val name: TextView, val slider: SeekBar) {
+
+    fun setIsVisible(isVisible: Boolean) {
+        name.isInvisible = !isVisible
+        slider.isInvisible = !isVisible
+    }
+
+    fun initView(clockFontAxis: ClockFontAxis, onFontAxisValueUpdated: (value: Float) -> Unit) {
+        name.text = clockFontAxis.name
+        slider.apply {
+            max = clockFontAxis.maxValue.toInt()
+            min = clockFontAxis.minValue.toInt()
+            progress = clockFontAxis.currentValue.toInt()
+            setOnSeekBarChangeListener(
+                object : SeekBar.OnSeekBarChangeListener {
+                    override fun onProgressChanged(
+                        seekBar: SeekBar?,
+                        progress: Int,
+                        fromUser: Boolean,
+                    ) {
+                        if (fromUser) {
+                            onFontAxisValueUpdated.invoke(progress.toFloat())
+                        }
+                    }
+
+                    override fun onStartTrackingTouch(seekBar: SeekBar?) {}
+
+                    override fun onStopTrackingTouch(seekBar: SeekBar?) {}
+                }
+            )
+        }
+    }
+
+    fun setValue(value: Float) {
+        slider.progress = value.toInt()
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/view/ClockFontSwitchViewHolder.kt b/src/com/android/wallpaper/customization/ui/view/ClockFontSwitchViewHolder.kt
new file mode 100644
index 00000000..6eb374b5
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/view/ClockFontSwitchViewHolder.kt
@@ -0,0 +1,49 @@
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
+package com.android.wallpaper.customization.ui.view
+
+import android.widget.Switch
+import android.widget.TextView
+import androidx.core.view.isVisible
+import com.android.systemui.plugins.clocks.ClockFontAxis
+import kotlin.math.abs
+
+class ClockFontSwitchViewHolder(val name: TextView, val switch: Switch) {
+
+    private var switchMaxValue: Float? = null
+
+    fun setIsVisible(isVisible: Boolean) {
+        name.isVisible = isVisible
+        switch.isVisible = isVisible
+    }
+
+    fun initView(clockFontAxis: ClockFontAxis, onFontAxisValueUpdated: (value: Float) -> Unit) {
+        switchMaxValue = clockFontAxis.maxValue
+        name.text = clockFontAxis.name
+        switch.apply {
+            isChecked = abs(clockFontAxis.currentValue - clockFontAxis.maxValue) < 0.01f
+            setOnCheckedChangeListener { v, _ ->
+                val value = if (v.isChecked) clockFontAxis.maxValue else clockFontAxis.minValue
+                onFontAxisValueUpdated.invoke(value)
+            }
+        }
+    }
+
+    fun setValue(value: Float) {
+        switchMaxValue?.let { switch.isChecked = abs(value - it) < 0.01f }
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/view/ShapeTileDrawable.kt b/src/com/android/wallpaper/customization/ui/view/ShapeTileDrawable.kt
new file mode 100644
index 00000000..3b492f48
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/view/ShapeTileDrawable.kt
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
+
+package com.android.wallpaper.customization.ui.view
+
+import android.graphics.Canvas
+import android.graphics.ColorFilter
+import android.graphics.Matrix
+import android.graphics.Paint
+import android.graphics.Path
+import android.graphics.PixelFormat
+import android.graphics.Rect
+import android.graphics.drawable.Drawable
+import androidx.core.graphics.PathParser
+
+/**
+ * Drawable that draws a shape tile with a given path.
+ *
+ * @param path Path of the shape assuming drawing on a 100x100 canvas.
+ */
+class ShapeTileDrawable(path: String) : Drawable() {
+
+    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
+    private val path = PathParser.createPathFromPathData(path)
+    // The path scaled with regard to the update of drawable bounds
+    private val scaledPath = Path(this.path)
+    private val scaleMatrix = Matrix()
+
+    override fun onBoundsChange(bounds: Rect) {
+        super.onBoundsChange(bounds)
+        scaleMatrix.setScale(bounds.width() / PATH_SIZE, bounds.height() / PATH_SIZE)
+        path.transform(scaleMatrix, scaledPath)
+    }
+
+    override fun draw(canvas: Canvas) {
+        canvas.drawPath(scaledPath, paint)
+    }
+
+    override fun setAlpha(alpha: Int) {
+        paint.alpha = alpha
+    }
+
+    override fun setColorFilter(colorFilter: ColorFilter?) {
+        paint.setColorFilter(colorFilter)
+    }
+
+    @Deprecated(
+        "getOpacity() is deprecated",
+        ReplaceWith("setAlpha(int)", "android.graphics.drawable.Drawable"),
+    )
+    override fun getOpacity(): Int {
+        return PixelFormat.TRANSLUCENT
+    }
+
+    companion object {
+        const val PATH_SIZE = 100f
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ClockFloatingSheetHeightsViewModel.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ClockFloatingSheetHeightsViewModel.kt
index 37752af8..249f8628 100644
--- a/src/com/android/wallpaper/customization/ui/viewmodel/ClockFloatingSheetHeightsViewModel.kt
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/ClockFloatingSheetHeightsViewModel.kt
@@ -17,7 +17,7 @@
 package com.android.wallpaper.customization.ui.viewmodel
 
 data class ClockFloatingSheetHeightsViewModel(
-    val clockStyleContentHeight: Int,
-    val clockColorContentHeight: Int,
-    val clockSizeContentHeight: Int,
+    val clockStyleContentHeight: Int? = null,
+    val clockColorContentHeight: Int? = null,
+    val clockFontContentHeight: Int? = null,
 )
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ClockPickerViewModel.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ClockPickerViewModel.kt
index 6740b3bc..2a1a8c93 100644
--- a/src/com/android/wallpaper/customization/ui/viewmodel/ClockPickerViewModel.kt
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/ClockPickerViewModel.kt
@@ -29,12 +29,14 @@ import com.android.customization.picker.color.domain.interactor.ColorPickerInter
 import com.android.customization.picker.color.shared.model.ColorOptionModel
 import com.android.customization.picker.color.shared.model.ColorType
 import com.android.customization.picker.color.ui.viewmodel.ColorOptionIconViewModel
+import com.android.systemui.plugins.clocks.ClockFontAxisSetting
 import com.android.themepicker.R
 import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
 import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
 import com.android.wallpaper.picker.customization.ui.viewmodel.FloatingToolbarTabViewModel
 import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel2
 import dagger.assisted.Assisted
 import dagger.assisted.AssistedFactory
 import dagger.assisted.AssistedInject
@@ -51,10 +53,11 @@ import kotlinx.coroutines.flow.StateFlow
 import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.flow.distinctUntilChanged
-import kotlinx.coroutines.flow.flow
+import kotlinx.coroutines.flow.filterNotNull
 import kotlinx.coroutines.flow.flowOn
 import kotlinx.coroutines.flow.map
 import kotlinx.coroutines.flow.mapLatest
+import kotlinx.coroutines.flow.shareIn
 import kotlinx.coroutines.flow.stateIn
 
 /** View model for the clock customization screen. */
@@ -73,7 +76,7 @@ constructor(
     enum class Tab {
         STYLE,
         COLOR,
-        SIZE,
+        FONT,
     }
 
     private val colorMap = ClockColorViewModel.getPresetColorMap(context.resources)
@@ -86,11 +89,11 @@ constructor(
             listOf(
                 FloatingToolbarTabViewModel(
                     Icon.Resource(
-                        res = R.drawable.ic_style_filled_24px,
+                        res = R.drawable.ic_clock_filled_24px,
                         contentDescription = Text.Resource(R.string.clock_style),
                     ),
                     context.getString(R.string.clock_style),
-                    it == Tab.STYLE,
+                    it == Tab.STYLE || it == Tab.FONT,
                 ) {
                     _selectedTab.value = Tab.STYLE
                 },
@@ -104,58 +107,36 @@ constructor(
                 ) {
                     _selectedTab.value = Tab.COLOR
                 },
-                FloatingToolbarTabViewModel(
-                    Icon.Resource(
-                        res = R.drawable.ic_open_in_full_24px,
-                        contentDescription = Text.Resource(R.string.clock_size),
-                    ),
-                    context.getString(R.string.clock_size),
-                    it == Tab.SIZE,
-                ) {
-                    _selectedTab.value = Tab.SIZE
-                },
             )
         }
 
     // Clock style
     private val overridingClock = MutableStateFlow<ClockMetadataModel?>(null)
-    val previewingClock =
+    private val isClockEdited =
         combine(overridingClock, clockPickerInteractor.selectedClock) {
             overridingClock,
             selectedClock ->
-            overridingClock ?: selectedClock
+            overridingClock != null && overridingClock.clockId != selectedClock.clockId
         }
+    val selectedClock = clockPickerInteractor.selectedClock
+    val previewingClock =
+        combine(overridingClock, selectedClock) { overridingClock, selectedClock ->
+                (overridingClock ?: selectedClock)
+            }
+            .shareIn(viewModelScope, SharingStarted.WhileSubscribed(), 1)
+
+    data class ClockStyleModel(val thumbnail: Drawable, val showEditButton: StateFlow<Boolean>)
+
     @OptIn(ExperimentalCoroutinesApi::class)
-    val clockStyleOptions: StateFlow<List<OptionItemViewModel<Drawable>>> =
+    val clockStyleOptions: StateFlow<List<OptionItemViewModel2<ClockStyleModel>>> =
         clockPickerInteractor.allClocks
             .mapLatest { allClocks ->
                 // Delay to avoid the case that the full list of clocks is not initiated.
                 delay(CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
-                allClocks.map { clockModel ->
-                    val isSelectedFlow =
-                        previewingClock
-                            .map { it.clockId == clockModel.clockId }
-                            .stateIn(viewModelScope)
-                    val contentDescription =
-                        resources.getString(
-                            R.string.select_clock_action_description,
-                            clockModel.description,
-                        )
-                    OptionItemViewModel<Drawable>(
-                        key = MutableStateFlow(clockModel.clockId) as StateFlow<String>,
-                        payload = clockModel.thumbnail,
-                        text = Text.Loaded(contentDescription),
-                        isTextUserVisible = false,
-                        isSelected = isSelectedFlow,
-                        onClicked =
-                            isSelectedFlow.map { isSelected ->
-                                if (isSelected) {
-                                    null
-                                } else {
-                                    { overridingClock.value = clockModel }
-                                }
-                            },
-                    )
+                val allClockMap = allClocks.groupBy { it.fontAxes.isNotEmpty() }
+                buildList {
+                    allClockMap[true]?.map { add(it.toOption(resources)) }
+                    allClockMap[false]?.map { add(it.toOption(resources)) }
                 }
             }
             // makes sure that the operations above this statement are executed on I/O dispatcher
@@ -164,58 +145,122 @@ constructor(
             .flowOn(backgroundDispatcher.limitedParallelism(1))
             .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
 
+    private suspend fun ClockMetadataModel.toOption(
+        resources: Resources
+    ): OptionItemViewModel2<ClockStyleModel> {
+        val isSelectedFlow = previewingClock.map { it.clockId == clockId }.stateIn(viewModelScope)
+        val isEditable = fontAxes.isNotEmpty()
+        val showEditButton = isSelectedFlow.map { it && isEditable }.stateIn(viewModelScope)
+        val contentDescription =
+            resources.getString(R.string.select_clock_action_description, description)
+        return OptionItemViewModel2<ClockStyleModel>(
+            key = MutableStateFlow(clockId) as StateFlow<String>,
+            payload = ClockStyleModel(thumbnail = thumbnail, showEditButton = showEditButton),
+            text = Text.Loaded(contentDescription),
+            isTextUserVisible = false,
+            isSelected = isSelectedFlow,
+            onClicked =
+                isSelectedFlow.map { isSelected ->
+                    if (isSelected && isEditable) {
+                        fun() {
+                            _selectedTab.value = Tab.FONT
+                        }
+                    } else {
+                        fun() {
+                            overridingClock.value = this
+                            overrideClockFontAxisMap.value = null
+                        }
+                    }
+                },
+        )
+    }
+
+    // Clock Font Axis Editor
+    private val overrideClockFontAxisMap = MutableStateFlow<Map<String, Float>?>(null)
+    private val isFontAxisMapEdited = overrideClockFontAxisMap.map { it != null }
+    val selectedClockFontAxes =
+        previewingClock
+            .map { clock -> clock.fontAxes }
+            .stateIn(viewModelScope, SharingStarted.Eagerly, null)
+    private val selectedClockFontAxisMap =
+        selectedClockFontAxes
+            .filterNotNull()
+            .map { fontAxes -> fontAxes.associate { it.key to it.currentValue } }
+            .stateIn(viewModelScope, SharingStarted.Eagerly, null)
+    val previewingClockFontAxisMap =
+        combine(overrideClockFontAxisMap, selectedClockFontAxisMap.filterNotNull()) {
+                overrideAxisMap,
+                selectedAxisMap ->
+                overrideAxisMap?.let {
+                    val mutableMap = selectedAxisMap.toMutableMap()
+                    overrideAxisMap.forEach { (key, value) -> mutableMap[key] = value }
+                    mutableMap.toMap()
+                } ?: selectedAxisMap
+            }
+            .stateIn(viewModelScope, SharingStarted.Eagerly, emptyMap())
+
+    fun updatePreviewFontAxis(key: String, value: Float) {
+        val axisMap = (overrideClockFontAxisMap.value?.toMutableMap() ?: mutableMapOf())
+        axisMap[key] = value
+        overrideClockFontAxisMap.value = axisMap.toMap()
+    }
+
+    fun confirmFontAxes() {
+        _selectedTab.value = Tab.STYLE
+    }
+
+    fun cancelFontAxes() {
+        overrideClockFontAxisMap.value = null
+        _selectedTab.value = Tab.STYLE
+    }
+
     // Clock size
     private val overridingClockSize = MutableStateFlow<ClockSize?>(null)
+    private val isClockSizeEdited =
+        combine(overridingClockSize, clockPickerInteractor.selectedClockSize) {
+            overridingClockSize,
+            selectedClockSize ->
+            overridingClockSize != null && overridingClockSize != selectedClockSize
+        }
     val previewingClockSize =
         combine(overridingClockSize, clockPickerInteractor.selectedClockSize) {
             overridingClockSize,
             selectedClockSize ->
             overridingClockSize ?: selectedClockSize
         }
-    val sizeOptions = flow {
-        emit(
-            listOf(
-                ClockSizeOptionViewModel(
-                    ClockSize.DYNAMIC,
-                    previewingClockSize.map { it == ClockSize.DYNAMIC }.stateIn(viewModelScope),
-                    previewingClockSize
-                        .map {
-                            if (it == ClockSize.DYNAMIC) {
-                                null
-                            } else {
-                                { overridingClockSize.value = ClockSize.DYNAMIC }
-                            }
-                        }
-                        .stateIn(viewModelScope),
-                ),
-                ClockSizeOptionViewModel(
-                    ClockSize.SMALL,
-                    previewingClockSize.map { it == ClockSize.SMALL }.stateIn(viewModelScope),
-                    previewingClockSize
-                        .map {
-                            if (it == ClockSize.SMALL) {
-                                null
-                            } else {
-                                { overridingClockSize.value = ClockSize.SMALL }
-                            }
-                        }
-                        .stateIn(viewModelScope),
-                ),
-            )
-        )
-    }
+    val onClockSizeSwitchCheckedChange: Flow<(() -> Unit)> =
+        previewingClockSize.map {
+            {
+                when (it) {
+                    ClockSize.DYNAMIC -> overridingClockSize.value = ClockSize.SMALL
+                    ClockSize.SMALL -> overridingClockSize.value = ClockSize.DYNAMIC
+                }
+            }
+        }
 
     // Clock color
     // 0 - 100
     private val overridingClockColorId = MutableStateFlow<String?>(null)
+    private val isClockColorIdEdited =
+        combine(overridingClockColorId, clockPickerInteractor.selectedColorId) {
+            overridingClockColorId,
+            selectedColorId ->
+            overridingClockColorId != null && (overridingClockColorId != selectedColorId)
+        }
     private val previewingClockColorId =
         combine(overridingClockColorId, clockPickerInteractor.selectedColorId) {
             overridingClockColorId,
             selectedColorId ->
-            overridingClockColorId ?: selectedColorId
+            overridingClockColorId ?: selectedColorId ?: DEFAULT_CLOCK_COLOR_ID
         }
 
     private val overridingSliderProgress = MutableStateFlow<Int?>(null)
+    private val isSliderProgressEdited =
+        combine(overridingSliderProgress, clockPickerInteractor.colorToneProgress) {
+            overridingSliderProgress,
+            colorToneProgress ->
+            overridingSliderProgress != null && (overridingSliderProgress != colorToneProgress)
+        }
     val previewingSliderProgress: Flow<Int> =
         combine(overridingSliderProgress, clockPickerInteractor.colorToneProgress) {
             overridingSliderProgress,
@@ -224,8 +269,7 @@ constructor(
         }
     val isSliderEnabled: Flow<Boolean> =
         combine(previewingClock, previewingClockColorId) { clock, clockColorId ->
-                // clockColorId null means clock color is the system theme color, thus no slider
-                clock.isReactiveToTone && clockColorId != null
+                clock.isReactiveToTone && clockColorId != DEFAULT_CLOCK_COLOR_ID
             }
             .distinctUntilChanged()
 
@@ -235,7 +279,8 @@ constructor(
 
     val previewingSeedColor: Flow<Int?> =
         combine(previewingClockColorId, previewingSliderProgress) { clockColorId, sliderProgress ->
-            val clockColorViewModel = if (clockColorId == null) null else colorMap[clockColorId]
+            val clockColorViewModel =
+                if (clockColorId == DEFAULT_CLOCK_COLOR_ID) null else colorMap[clockColorId]
             if (clockColorViewModel == null) {
                 null
             } else {
@@ -322,7 +367,8 @@ constructor(
                 /** darkTheme= */
                 true
             )
-        val isSelectedFlow = previewingClockColorId.map { it == null }.stateIn(viewModelScope)
+        val isSelectedFlow =
+            previewingClockColorId.map { it == DEFAULT_CLOCK_COLOR_ID }.stateIn(viewModelScope)
         return OptionItemViewModel<ColorOptionIconViewModel>(
             key = MutableStateFlow(key) as StateFlow<String>,
             payload =
@@ -345,7 +391,7 @@ constructor(
                         null
                     } else {
                         {
-                            overridingClockColorId.value = null
+                            overridingClockColorId.value = DEFAULT_CLOCK_COLOR_ID
                             overridingSliderProgress.value =
                                 ClockMetadataModel.DEFAULT_COLOR_TONE_PROGRESS
                         }
@@ -354,31 +400,60 @@ constructor(
         )
     }
 
+    private val isEdited =
+        combine(
+            isClockEdited,
+            isClockSizeEdited,
+            isClockColorIdEdited,
+            isSliderProgressEdited,
+            isFontAxisMapEdited,
+        ) {
+            isClockEdited,
+            isClockSizeEdited,
+            isClockColorEdited,
+            isSliderProgressEdited,
+            isFontAxisMapEdited ->
+            isClockEdited ||
+                isClockSizeEdited ||
+                isClockColorEdited ||
+                isSliderProgressEdited ||
+                isFontAxisMapEdited
+        }
+
     val onApply: Flow<(suspend () -> Unit)?> =
         combine(
+            isEdited,
             previewingClock,
             previewingClockSize,
             previewingClockColorId,
             previewingSliderProgress,
-        ) { clock, size, colorId, progress ->
-            {
-                val clockColorViewModel = colorMap[colorId]
-                val seedColor =
-                    if (clockColorViewModel != null) {
-                        blendColorWithTone(
-                            color = clockColorViewModel.color,
-                            colorTone = clockColorViewModel.getColorTone(progress),
-                        )
-                    } else {
-                        null
-                    }
-                clockPickerInteractor.applyClock(
-                    clockId = clock.clockId,
-                    size = size,
-                    selectedColorId = colorId,
-                    colorToneProgress = progress,
-                    seedColor = seedColor,
-                )
+            previewingClockFontAxisMap,
+        ) { array ->
+            val isEdited = array[0] as Boolean
+            val clock = array[1] as ClockMetadataModel
+            val size = array[2] as ClockSize
+            val previewingColorId = array[3] as String
+            val previewProgress = array[4] as Int
+            val axisMap = array[5] as Map<String, Float>
+            if (isEdited) {
+                {
+                    clockPickerInteractor.applyClock(
+                        clockId = clock.clockId,
+                        size = size,
+                        selectedColorId = previewingColorId,
+                        colorToneProgress = previewProgress,
+                        seedColor =
+                            colorMap[previewingColorId]?.let {
+                                blendColorWithTone(
+                                    color = it.color,
+                                    colorTone = it.getColorTone(previewProgress),
+                                )
+                            },
+                        axisSettings = axisMap.map { ClockFontAxisSetting(it.key, it.value) },
+                    )
+                }
+            } else {
+                null
             }
         }
 
@@ -387,10 +462,12 @@ constructor(
         overridingClockSize.value = null
         overridingClockColorId.value = null
         overridingSliderProgress.value = null
+        overrideClockFontAxisMap.value = null
         _selectedTab.value = Tab.STYLE
     }
 
     companion object {
+        private const val DEFAULT_CLOCK_COLOR_ID = "DEFAULT"
         private val helperColorLab: DoubleArray by lazy { DoubleArray(3) }
 
         fun blendColorWithTone(color: Int, colorTone: Double): Int {
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ColorPickerViewModel2.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ColorPickerViewModel2.kt
index a0399963..4029dbe2 100644
--- a/src/com/android/wallpaper/customization/ui/viewmodel/ColorPickerViewModel2.kt
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/ColorPickerViewModel2.kt
@@ -20,26 +20,31 @@ import android.content.Context
 import com.android.customization.model.color.ColorOptionImpl
 import com.android.customization.module.logging.ThemesUserEventLogger
 import com.android.customization.picker.color.domain.interactor.ColorPickerInteractor
+import com.android.customization.picker.color.shared.model.ColorOptionModel
 import com.android.customization.picker.color.shared.model.ColorType
 import com.android.customization.picker.color.ui.viewmodel.ColorOptionIconViewModel
 import com.android.themepicker.R
 import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
 import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
 import com.android.wallpaper.picker.customization.ui.viewmodel.FloatingToolbarTabViewModel
-import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel2
 import dagger.assisted.Assisted
 import dagger.assisted.AssistedFactory
 import dagger.assisted.AssistedInject
 import dagger.hilt.android.qualifiers.ApplicationContext
 import dagger.hilt.android.scopes.ViewModelScoped
+import kotlin.coroutines.resume
+import kotlinx.coroutines.CancellableContinuation
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.flow.map
 import kotlinx.coroutines.flow.stateIn
 import kotlinx.coroutines.launch
+import kotlinx.coroutines.suspendCancellableCoroutine
 
 /** Models UI state for a color picker experience. */
 class ColorPickerViewModel2
@@ -51,14 +56,17 @@ constructor(
     @Assisted private val viewModelScope: CoroutineScope,
 ) {
 
+    private val overridingColorOption = MutableStateFlow<ColorOptionModel?>(null)
+    val previewingColorOption = overridingColorOption.asStateFlow()
+
     private val selectedColorTypeTabId = MutableStateFlow<ColorType?>(null)
+    private var onApplyContinuation: CancellableContinuation<Unit>? = null
 
     /** View-models for each color tab. */
     val colorTypeTabs: Flow<List<FloatingToolbarTabViewModel>> =
-        combine(
-            interactor.colorOptions,
-            selectedColorTypeTabId,
-        ) { colorOptions, selectedColorTypeIdOrNull ->
+        combine(interactor.colorOptions, selectedColorTypeTabId) {
+            colorOptions,
+            selectedColorTypeIdOrNull ->
             colorOptions.keys.mapIndexed { index, colorType ->
                 val isSelected =
                     (selectedColorTypeIdOrNull == null && index == 0) ||
@@ -105,7 +113,7 @@ constructor(
 
     /** The list of all color options mapped by their color type */
     private val allColorOptions:
-        Flow<Map<ColorType, List<OptionItemViewModel<ColorOptionIconViewModel>>>> =
+        Flow<Map<ColorType, List<OptionItemViewModel2<ColorOptionIconViewModel>>>> =
         interactor.colorOptions.map { colorOptions ->
             colorOptions
                 .map { colorOptionEntry ->
@@ -118,13 +126,13 @@ constructor(
                             val darkThemeColors =
                                 colorOption.previewInfo.resolveColors(/* darkTheme= */ true)
                             val isSelectedFlow: StateFlow<Boolean> =
-                                interactor.selectingColorOption
+                                previewingColorOption
                                     .map {
                                         it?.colorOption?.isEquivalent(colorOptionModel.colorOption)
                                             ?: colorOptionModel.isSelected
                                     }
                                     .stateIn(viewModelScope)
-                            OptionItemViewModel<ColorOptionIconViewModel>(
+                            OptionItemViewModel2<ColorOptionIconViewModel>(
                                 key = MutableStateFlow(colorOptionModel.key) as StateFlow<String>,
                                 payload =
                                     ColorOptionIconViewModel(
@@ -150,15 +158,7 @@ constructor(
                                         } else {
                                             {
                                                 viewModelScope.launch {
-                                                    interactor.select(colorOptionModel)
-                                                    logger.logThemeColorApplied(
-                                                        colorOptionModel.colorOption
-                                                            .sourceForLogging,
-                                                        colorOptionModel.colorOption
-                                                            .styleForLogging,
-                                                        colorOptionModel.colorOption
-                                                            .seedColorForLogging,
-                                                    )
+                                                    overridingColorOption.value = colorOptionModel
                                                 }
                                             }
                                         }
@@ -169,10 +169,48 @@ constructor(
                 .toMap()
         }
 
+    /**
+     * This function suspends until onApplyComplete is called to accommodate for configuration
+     * change updates, which are applied with a latency.
+     */
+    val onApply: Flow<(suspend () -> Unit)?> =
+        previewingColorOption.map { previewingColorOption ->
+            previewingColorOption?.let {
+                if (it.isSelected) {
+                    null
+                } else {
+                    {
+                        interactor.select(it)
+                        // Suspend until onApplyComplete is called, e.g. on configuration change
+                        suspendCancellableCoroutine { continuation: CancellableContinuation<Unit> ->
+                            onApplyContinuation?.cancel()
+                            onApplyContinuation = continuation
+                            continuation.invokeOnCancellation { onApplyContinuation = null }
+                        }
+                        logger.logThemeColorApplied(
+                            previewingColorOption.colorOption.sourceForLogging,
+                            previewingColorOption.colorOption.styleForLogging,
+                            previewingColorOption.colorOption.seedColor,
+                        )
+                    }
+                }
+            }
+        }
+
+    fun resetPreview() {
+        overridingColorOption.value = null
+    }
+
+    /** Resumes the onApply function if apply is in progress, otherwise no-op */
+    fun onApplyComplete() {
+        onApplyContinuation?.resume(Unit)
+        onApplyContinuation = null
+    }
+
     /** The list of all available color options for the selected Color Type. */
-    val colorOptions: Flow<List<OptionItemViewModel<ColorOptionIconViewModel>>> =
+    val colorOptions: Flow<List<OptionItemViewModel2<ColorOptionIconViewModel>>> =
         combine(allColorOptions, selectedColorTypeTabId) {
-            allColorOptions: Map<ColorType, List<OptionItemViewModel<ColorOptionIconViewModel>>>,
+            allColorOptions: Map<ColorType, List<OptionItemViewModel2<ColorOptionIconViewModel>>>,
             selectedColorTypeIdOrNull ->
             val selectedColorTypeId = selectedColorTypeIdOrNull ?: ColorType.WALLPAPER_COLOR
             allColorOptions[selectedColorTypeId]!!
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/KeyguardQuickAffordancePickerViewModel2.kt b/src/com/android/wallpaper/customization/ui/viewmodel/KeyguardQuickAffordancePickerViewModel2.kt
index fd94b781..fd04580c 100644
--- a/src/com/android/wallpaper/customization/ui/viewmodel/KeyguardQuickAffordancePickerViewModel2.kt
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/KeyguardQuickAffordancePickerViewModel2.kt
@@ -36,6 +36,7 @@ import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
 import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
 import com.android.wallpaper.picker.customization.ui.viewmodel.FloatingToolbarTabViewModel
 import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel2
 import dagger.assisted.Assisted
 import dagger.assisted.AssistedFactory
 import dagger.assisted.AssistedInject
@@ -174,7 +175,7 @@ constructor(
             .shareIn(scope = viewModelScope, started = SharingStarted.WhileSubscribed(), replay = 1)
 
     /** The list of all available quick affordances for the selected slot. */
-    val quickAffordances: Flow<List<OptionItemViewModel<Icon>>> =
+    val quickAffordances: Flow<List<OptionItemViewModel2<Icon>>> =
         quickAffordanceInteractor.affordances.map { affordances ->
             val isNoneSelected =
                 combine(selectedSlotId, previewingQuickAffordances, selectedAffordanceIds) {
@@ -219,7 +220,7 @@ constructor(
                                 } ?: selectedAffordanceIds.contains(affordance.id)
                             }
                             .stateIn(viewModelScope)
-                    OptionItemViewModel<Icon>(
+                    OptionItemViewModel2<Icon>(
                         key =
                             selectedSlotId
                                 .map { slotId -> "$slotId::${affordance.id}" }
@@ -374,8 +375,8 @@ constructor(
         slotId: StateFlow<String>,
         isSelected: StateFlow<Boolean>,
         onSelected: Flow<(() -> Unit)?>,
-    ): OptionItemViewModel<Icon> {
-        return OptionItemViewModel<Icon>(
+    ): OptionItemViewModel2<Icon> {
+        return OptionItemViewModel2<Icon>(
             key = slotId.map { "$it::none" }.stateIn(viewModelScope),
             payload = Icon.Resource(res = R.drawable.link_off, contentDescription = null),
             text = Text.Resource(res = R.string.keyguard_affordance_none),
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ShapeAndGridPickerViewModel.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ShapeAndGridPickerViewModel.kt
deleted file mode 100644
index a13a6525..00000000
--- a/src/com/android/wallpaper/customization/ui/viewmodel/ShapeAndGridPickerViewModel.kt
+++ /dev/null
@@ -1,132 +0,0 @@
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
-package com.android.wallpaper.customization.ui.viewmodel
-
-import android.content.Context
-import android.content.res.Resources
-import com.android.customization.model.ResourceConstants
-import com.android.customization.model.grid.GridOptionModel
-import com.android.customization.picker.grid.domain.interactor.GridInteractor2
-import com.android.customization.picker.grid.ui.viewmodel.GridIconViewModel
-import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
-import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
-import dagger.assisted.Assisted
-import dagger.assisted.AssistedFactory
-import dagger.assisted.AssistedInject
-import dagger.hilt.android.qualifiers.ApplicationContext
-import dagger.hilt.android.scopes.ViewModelScoped
-import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.flow.Flow
-import kotlinx.coroutines.flow.MutableStateFlow
-import kotlinx.coroutines.flow.SharingStarted
-import kotlinx.coroutines.flow.combine
-import kotlinx.coroutines.flow.filterNotNull
-import kotlinx.coroutines.flow.map
-import kotlinx.coroutines.flow.stateIn
-
-class ShapeAndGridPickerViewModel
-@AssistedInject
-constructor(
-    @ApplicationContext private val context: Context,
-    interactor: GridInteractor2,
-    @Assisted private val viewModelScope: CoroutineScope,
-) {
-    // The currently-set system grid option
-    val selectedGridOption =
-        interactor.selectedGridOption.filterNotNull().map { toOptionItemViewModel(it) }
-    private val _previewingGridOptionKey = MutableStateFlow<String?>(null)
-    // If the previewing key is null, use the currently-set system grid option
-    val previewingGridOptionKey =
-        combine(selectedGridOption, _previewingGridOptionKey) {
-            currentlySetGridOption,
-            previewingGridOptionKey ->
-            previewingGridOptionKey ?: currentlySetGridOption.key.value
-        }
-
-    fun resetPreview() {
-        _previewingGridOptionKey.tryEmit(null)
-    }
-
-    val optionItems: Flow<List<OptionItemViewModel<GridIconViewModel>>> =
-        interactor.gridOptions.filterNotNull().map { gridOptions ->
-            gridOptions.map { toOptionItemViewModel(it) }
-        }
-
-    val onApply: Flow<(suspend () -> Unit)?> =
-        combine(selectedGridOption, _previewingGridOptionKey) {
-            selectedGridOption,
-            previewingGridOptionKey ->
-            if (
-                previewingGridOptionKey == null ||
-                    previewingGridOptionKey == selectedGridOption.key.value
-            ) {
-                null
-            } else {
-                { interactor.applySelectedOption(previewingGridOptionKey) }
-            }
-        }
-
-    private fun toOptionItemViewModel(
-        option: GridOptionModel
-    ): OptionItemViewModel<GridIconViewModel> {
-        val iconShapePath =
-            context.resources.getString(
-                Resources.getSystem()
-                    .getIdentifier(
-                        ResourceConstants.CONFIG_ICON_MASK,
-                        "string",
-                        ResourceConstants.ANDROID_PACKAGE,
-                    )
-            )
-        val isSelected =
-            _previewingGridOptionKey
-                .map {
-                    if (it == null) {
-                        option.isCurrent
-                    } else {
-                        it == option.key
-                    }
-                }
-                .stateIn(
-                    scope = viewModelScope,
-                    started = SharingStarted.Eagerly,
-                    initialValue = false,
-                )
-
-        return OptionItemViewModel(
-            key = MutableStateFlow(option.key),
-            payload =
-                GridIconViewModel(columns = option.cols, rows = option.rows, path = iconShapePath),
-            text = Text.Loaded(option.title),
-            isSelected = isSelected,
-            onClicked =
-                isSelected.map {
-                    if (!it) {
-                        { _previewingGridOptionKey.value = option.key }
-                    } else {
-                        null
-                    }
-                },
-        )
-    }
-
-    @ViewModelScoped
-    @AssistedFactory
-    interface Factory {
-        fun create(viewModelScope: CoroutineScope): ShapeAndGridPickerViewModel
-    }
-}
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ShapeGridFloatingSheetHeightsViewModel.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ShapeGridFloatingSheetHeightsViewModel.kt
new file mode 100644
index 00000000..237ab365
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/ShapeGridFloatingSheetHeightsViewModel.kt
@@ -0,0 +1,22 @@
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
+package com.android.wallpaper.customization.ui.viewmodel
+
+data class ShapeGridFloatingSheetHeightsViewModel(
+    val shapeContentHeight: Int? = null,
+    val gridContentHeight: Int? = null,
+)
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ShapeGridPickerViewModel.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ShapeGridPickerViewModel.kt
new file mode 100644
index 00000000..1e19e804
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/ShapeGridPickerViewModel.kt
@@ -0,0 +1,229 @@
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
+package com.android.wallpaper.customization.ui.viewmodel
+
+import android.content.Context
+import android.content.res.Resources
+import com.android.customization.model.ResourceConstants
+import com.android.customization.model.grid.GridOptionModel
+import com.android.customization.model.grid.ShapeOptionModel
+import com.android.customization.picker.grid.domain.interactor.ShapeGridInteractor
+import com.android.customization.picker.grid.ui.viewmodel.GridIconViewModel
+import com.android.customization.picker.grid.ui.viewmodel.ShapeIconViewModel
+import com.android.themepicker.R
+import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
+import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
+import com.android.wallpaper.picker.customization.ui.viewmodel.FloatingToolbarTabViewModel
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel2
+import dagger.assisted.Assisted
+import dagger.assisted.AssistedFactory
+import dagger.assisted.AssistedInject
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.scopes.ViewModelScoped
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.shareIn
+import kotlinx.coroutines.flow.stateIn
+
+class ShapeGridPickerViewModel
+@AssistedInject
+constructor(
+    @ApplicationContext private val context: Context,
+    interactor: ShapeGridInteractor,
+    @Assisted private val viewModelScope: CoroutineScope,
+) {
+
+    enum class Tab {
+        SHAPE,
+        GRID,
+    }
+
+    //// Tabs
+    private val _selectedTab = MutableStateFlow(Tab.SHAPE)
+    val selectedTab: StateFlow<Tab> = _selectedTab.asStateFlow()
+    val tabs: Flow<List<FloatingToolbarTabViewModel>> =
+        _selectedTab.map {
+            listOf(
+                FloatingToolbarTabViewModel(
+                    Icon.Resource(
+                        res = R.drawable.ic_category_filled_24px,
+                        contentDescription = Text.Resource(R.string.preview_name_shape),
+                    ),
+                    context.getString(R.string.preview_name_shape),
+                    it == Tab.SHAPE,
+                ) {
+                    _selectedTab.value = Tab.SHAPE
+                },
+                FloatingToolbarTabViewModel(
+                    Icon.Resource(
+                        res = R.drawable.ic_apps_filled_24px,
+                        contentDescription = Text.Resource(R.string.grid_layout),
+                    ),
+                    context.getString(R.string.grid_layout),
+                    it == Tab.GRID,
+                ) {
+                    _selectedTab.value = Tab.GRID
+                },
+            )
+        }
+
+    //// Shape
+
+    // The currently-set system shape option
+    val selectedShapeKey =
+        interactor.selectedShapeOption
+            .filterNotNull()
+            .map { it.key }
+            .shareIn(scope = viewModelScope, started = SharingStarted.Lazily, replay = 1)
+    private val overridingShapeKey = MutableStateFlow<String?>(null)
+    // If the overriding key is null, use the currently-set system shape option
+    val previewingShapeKey =
+        combine(overridingShapeKey, selectedShapeKey) { overridingShapeOptionKey, selectedShapeKey
+            ->
+            overridingShapeOptionKey ?: selectedShapeKey
+        }
+
+    val shapeOptions: Flow<List<OptionItemViewModel<ShapeIconViewModel>>> =
+        interactor.shapeOptions
+            .filterNotNull()
+            .map { shapeOptions -> shapeOptions.map { toShapeOptionItemViewModel(it) } }
+            .shareIn(scope = viewModelScope, started = SharingStarted.Lazily, replay = 1)
+
+    //// Grid
+
+    // The currently-set system grid option
+    val selectedGridOption =
+        interactor.selectedGridOption
+            .filterNotNull()
+            .map { toGridOptionItemViewModel(it) }
+            .shareIn(scope = viewModelScope, started = SharingStarted.Lazily, replay = 1)
+    private val overridingGridKey = MutableStateFlow<String?>(null)
+    // If the overriding key is null, use the currently-set system grid option
+    val previewingGridKey =
+        combine(overridingGridKey, selectedGridOption) { overridingGridOptionKey, selectedGridOption
+            ->
+            overridingGridOptionKey ?: selectedGridOption.key.value
+        }
+
+    val gridOptions: Flow<List<OptionItemViewModel2<GridIconViewModel>>> =
+        interactor.gridOptions
+            .filterNotNull()
+            .map { gridOptions -> gridOptions.map { toGridOptionItemViewModel(it) } }
+            .shareIn(scope = viewModelScope, started = SharingStarted.Lazily, replay = 1)
+
+    val onApply: Flow<(suspend () -> Unit)?> =
+        combine(previewingGridKey, selectedGridOption, previewingShapeKey, selectedShapeKey) {
+            previewingGridOptionKey,
+            selectedGridOption,
+            previewingShapeKey,
+            selectedShapeKey ->
+            if (
+                previewingGridOptionKey == selectedGridOption.key.value &&
+                    previewingShapeKey == selectedShapeKey
+            ) {
+                null
+            } else {
+                { interactor.applySelectedOption(previewingShapeKey, previewingGridOptionKey) }
+            }
+        }
+
+    fun resetPreview() {
+        overridingShapeKey.value = null
+        overridingGridKey.value = null
+        _selectedTab.value = Tab.SHAPE
+    }
+
+    private fun toShapeOptionItemViewModel(
+        option: ShapeOptionModel
+    ): OptionItemViewModel<ShapeIconViewModel> {
+        val isSelected =
+            previewingShapeKey
+                .map { it == option.key }
+                .stateIn(
+                    scope = viewModelScope,
+                    started = SharingStarted.Lazily,
+                    initialValue = false,
+                )
+
+        return OptionItemViewModel(
+            key = MutableStateFlow(option.key),
+            payload = ShapeIconViewModel(option.key, option.path),
+            text = Text.Loaded(option.title),
+            isSelected = isSelected,
+            onClicked =
+                isSelected.map {
+                    if (!it) {
+                        { overridingShapeKey.value = option.key }
+                    } else {
+                        null
+                    }
+                },
+        )
+    }
+
+    private fun toGridOptionItemViewModel(
+        option: GridOptionModel
+    ): OptionItemViewModel2<GridIconViewModel> {
+        val iconShapePath =
+            context.resources.getString(
+                Resources.getSystem()
+                    .getIdentifier(
+                        ResourceConstants.CONFIG_ICON_MASK,
+                        "string",
+                        ResourceConstants.ANDROID_PACKAGE,
+                    )
+            )
+        val isSelected =
+            previewingGridKey
+                .map { it == option.key }
+                .stateIn(
+                    scope = viewModelScope,
+                    started = SharingStarted.Lazily,
+                    initialValue = false,
+                )
+
+        return OptionItemViewModel2(
+            key = MutableStateFlow(option.key),
+            payload =
+                GridIconViewModel(columns = option.cols, rows = option.rows, path = iconShapePath),
+            text = Text.Loaded(option.title),
+            isSelected = isSelected,
+            onClicked =
+                isSelected.map {
+                    if (!it) {
+                        { overridingGridKey.value = option.key }
+                    } else {
+                        null
+                    }
+                },
+        )
+    }
+
+    @ViewModelScoped
+    @AssistedFactory
+    interface Factory {
+        fun create(viewModelScope: CoroutineScope): ShapeGridPickerViewModel
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ThemePickerCustomizationOptionsViewModel.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ThemePickerCustomizationOptionsViewModel.kt
index 03831bd5..6bc61807 100644
--- a/src/com/android/wallpaper/customization/ui/viewmodel/ThemePickerCustomizationOptionsViewModel.kt
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/ThemePickerCustomizationOptionsViewModel.kt
@@ -16,6 +16,7 @@
 
 package com.android.wallpaper.customization.ui.viewmodel
 
+import com.android.customization.picker.mode.ui.viewmodel.DarkModeViewModel
 import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptionUtil
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModelFactory
@@ -26,8 +27,11 @@ import dagger.assisted.AssistedInject
 import dagger.hilt.android.scopes.ViewModelScoped
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.Job
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.flatMapLatest
 import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.map
@@ -41,7 +45,8 @@ constructor(
     keyguardQuickAffordancePickerViewModel2Factory: KeyguardQuickAffordancePickerViewModel2.Factory,
     colorPickerViewModel2Factory: ColorPickerViewModel2.Factory,
     clockPickerViewModelFactory: ClockPickerViewModel.Factory,
-    shapeAndGridPickerViewModelFactory: ShapeAndGridPickerViewModel.Factory,
+    shapeGridPickerViewModelFactory: ShapeGridPickerViewModel.Factory,
+    val darkModeViewModel: DarkModeViewModel,
     @Assisted private val viewModelScope: CoroutineScope,
 ) : CustomizationOptionsViewModel {
 
@@ -52,16 +57,37 @@ constructor(
     val keyguardQuickAffordancePickerViewModel2 =
         keyguardQuickAffordancePickerViewModel2Factory.create(viewModelScope = viewModelScope)
     val colorPickerViewModel2 = colorPickerViewModel2Factory.create(viewModelScope = viewModelScope)
-    val shapeAndGridPickerViewModel =
-        shapeAndGridPickerViewModelFactory.create(viewModelScope = viewModelScope)
+    val shapeGridPickerViewModel =
+        shapeGridPickerViewModelFactory.create(viewModelScope = viewModelScope)
+
+    private var onApplyJob: Job? = null
 
     override val selectedOption = defaultCustomizationOptionsViewModel.selectedOption
 
-    override fun deselectOption(): Boolean {
-        keyguardQuickAffordancePickerViewModel2.resetPreview()
-        shapeAndGridPickerViewModel.resetPreview()
-        clockPickerViewModel.resetPreview()
-        return defaultCustomizationOptionsViewModel.deselectOption()
+    override fun handleBackPressed(): Boolean {
+
+        if (
+            defaultCustomizationOptionsViewModel.selectedOption.value ==
+                ThemePickerCustomizationOptionUtil.ThemePickerLockCustomizationOption.CLOCK &&
+                clockPickerViewModel.selectedTab.value == ClockPickerViewModel.Tab.FONT
+        ) {
+            clockPickerViewModel.cancelFontAxes()
+            return true
+        }
+
+        val isBackPressedHandled = defaultCustomizationOptionsViewModel.handleBackPressed()
+
+        if (isBackPressedHandled) {
+            // If isBackPressedHandled is handled by DefaultCustomizationOptionsViewModel, it means
+            // we navigate back to the main screen from a secondary screen. Reset preview.
+            keyguardQuickAffordancePickerViewModel2.resetPreview()
+            shapeGridPickerViewModel.resetPreview()
+            clockPickerViewModel.resetPreview()
+            colorPickerViewModel2.resetPreview()
+            darkModeViewModel.resetPreview()
+        }
+
+        return isBackPressedHandled
     }
 
     val onCustomizeClockClicked: Flow<(() -> Unit)?> =
@@ -104,13 +130,13 @@ constructor(
             }
         }
 
-    val onCustomizeShapeAndGridClicked: Flow<(() -> Unit)?> =
+    val onCustomizeShapeGridClicked: Flow<(() -> Unit)?> =
         selectedOption.map {
             if (it == null) {
                 {
                     defaultCustomizationOptionsViewModel.selectOption(
                         ThemePickerCustomizationOptionUtil.ThemePickerHomeCustomizationOption
-                            .APP_SHAPE_AND_GRID
+                            .APP_SHAPE_GRID
                     )
                 }
             } else {
@@ -119,7 +145,7 @@ constructor(
         }
 
     @OptIn(ExperimentalCoroutinesApi::class)
-    val onApplyButtonClicked =
+    val onApplyButtonClicked: Flow<((onComplete: () -> Unit) -> Unit)?> =
         selectedOption
             .flatMapLatest {
                 when (it) {
@@ -128,28 +154,49 @@ constructor(
                     ThemePickerCustomizationOptionUtil.ThemePickerLockCustomizationOption
                         .SHORTCUTS -> keyguardQuickAffordancePickerViewModel2.onApply
                     ThemePickerCustomizationOptionUtil.ThemePickerHomeCustomizationOption
-                        .APP_SHAPE_AND_GRID -> shapeAndGridPickerViewModel.onApply
+                        .APP_SHAPE_GRID -> shapeGridPickerViewModel.onApply
+                    ThemePickerCustomizationOptionUtil.ThemePickerHomeCustomizationOption.COLORS ->
+                        combine(colorPickerViewModel2.onApply, darkModeViewModel.onApply) {
+                            colorOnApply,
+                            darkModeOnApply ->
+                            {
+                                colorOnApply?.invoke()
+                                darkModeOnApply?.invoke()
+                            }
+                        }
                     else -> flow { emit(null) }
                 }
             }
             .map { onApply ->
-                {
-                    if (onApply != null) {
-                        viewModelScope.launch {
-                            onApply()
-                            // We only wait until onApply() is done to execute deselectOption()
-                            deselectOption()
+                if (onApply != null) {
+                    fun(onComplete: () -> Unit) {
+                        // Prevent double apply
+                        if (onApplyJob?.isActive != true) {
+                            onApplyJob =
+                                viewModelScope.launch {
+                                    onApply()
+                                    onComplete()
+                                    onApplyJob = null
+                                }
                         }
-                    } else {
-                        null
                     }
+                } else {
+                    null
                 }
             }
             .stateIn(viewModelScope, SharingStarted.Eagerly, null)
 
-    val isOnApplyEnabled: Flow<Boolean> = onApplyButtonClicked.map { it != null }
+    val isApplyButtonEnabled: Flow<Boolean> = onApplyButtonClicked.map { it != null }
 
-    val isOnApplyVisible: Flow<Boolean> = selectedOption.map { it != null }
+    val isApplyButtonVisible: Flow<Boolean> = selectedOption.map { it != null }
+
+    val isToolbarCollapsed: Flow<Boolean> =
+        combine(selectedOption, clockPickerViewModel.selectedTab) { selectedOption, selectedTab ->
+                selectedOption ==
+                    ThemePickerCustomizationOptionUtil.ThemePickerLockCustomizationOption.CLOCK &&
+                    selectedTab == ClockPickerViewModel.Tab.FONT
+            }
+            .distinctUntilChanged()
 
     @ViewModelScoped
     @AssistedFactory
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ToolbarHeightsViewModel.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ToolbarHeightsViewModel.kt
new file mode 100644
index 00000000..0d859da8
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/ToolbarHeightsViewModel.kt
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
+package com.android.wallpaper.customization.ui.viewmodel
+
+data class ToolbarHeightsViewModel(
+    val navButtonHeight: Int? = null,
+    val toolbarHeight: Int? = null,
+    val applyButtonHeight: Int? = null,
+)
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/binder/ThemePickerWorkspaceCallbackBinder.kt b/src/com/android/wallpaper/picker/common/preview/ui/binder/ThemePickerWorkspaceCallbackBinder.kt
index eec7d5ac..e8c5b15e 100644
--- a/src/com/android/wallpaper/picker/common/preview/ui/binder/ThemePickerWorkspaceCallbackBinder.kt
+++ b/src/com/android/wallpaper/picker/common/preview/ui/binder/ThemePickerWorkspaceCallbackBinder.kt
@@ -23,12 +23,23 @@ import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
+import com.android.customization.model.grid.DefaultShapeGridManager.Companion.COL_GRID_NAME
+import com.android.customization.model.grid.DefaultShapeGridManager.Companion.COL_SHAPE_KEY
+import com.android.customization.picker.clock.shared.ClockSize
+import com.android.customization.picker.clock.ui.view.ClockViewFactory
+import com.android.customization.picker.color.data.util.MaterialColorsGenerator
 import com.android.systemui.shared.keyguard.shared.model.KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_END
 import com.android.systemui.shared.keyguard.shared.model.KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.CLOCK_SIZE_DYNAMIC
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.CLOCK_SIZE_SMALL
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.KEY_CLOCK_SIZE
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.KEY_HIDE_SMART_SPACE
 import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.KEY_INITIALLY_SELECTED_SLOT_ID
 import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.KEY_QUICK_AFFORDANCE_ID
 import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.KEY_SLOT_ID
 import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.MESSAGE_ID_DEFAULT_PREVIEW
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.MESSAGE_ID_HIDE_SMART_SPACE
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.MESSAGE_ID_PREVIEW_CLOCK_SIZE
 import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.MESSAGE_ID_PREVIEW_QUICK_AFFORDANCE_SELECTED
 import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.MESSAGE_ID_SLOT_SELECTED
 import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.MESSAGE_ID_START_CUSTOMIZING_QUICK_AFFORDANCES
@@ -36,28 +47,36 @@ import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptio
 import com.android.wallpaper.customization.ui.viewmodel.ThemePickerCustomizationOptionsViewModel
 import com.android.wallpaper.model.Screen
 import com.android.wallpaper.picker.common.preview.ui.binder.WorkspaceCallbackBinder.Companion.sendMessage
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
 import javax.inject.Inject
 import javax.inject.Singleton
+import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.launch
 
 @Singleton
 class ThemePickerWorkspaceCallbackBinder
 @Inject
-constructor(private val defaultWorkspaceCallbackBinder: DefaultWorkspaceCallbackBinder) :
-    WorkspaceCallbackBinder {
+constructor(
+    private val defaultWorkspaceCallbackBinder: DefaultWorkspaceCallbackBinder,
+    private val materialColorsGenerator: MaterialColorsGenerator,
+) : WorkspaceCallbackBinder {
 
     override fun bind(
         workspaceCallback: Message,
         viewModel: CustomizationOptionsViewModel,
+        colorUpdateViewModel: ColorUpdateViewModel,
         screen: Screen,
         lifecycleOwner: LifecycleOwner,
+        clockViewFactory: ClockViewFactory,
     ) {
         defaultWorkspaceCallbackBinder.bind(
             workspaceCallback = workspaceCallback,
             viewModel = viewModel,
+            colorUpdateViewModel = colorUpdateViewModel,
             screen = screen,
             lifecycleOwner = lifecycleOwner,
+            clockViewFactory = clockViewFactory,
         )
 
         if (viewModel !is ThemePickerCustomizationOptionsViewModel) {
@@ -81,7 +100,7 @@ constructor(private val defaultWorkspaceCallbackBinder: DefaultWorkspaceCallback
                                                     KEY_INITIALLY_SELECTED_SLOT_ID,
                                                     SLOT_ID_BOTTOM_START,
                                                 )
-                                            }
+                                            },
                                         )
                                     else ->
                                         workspaceCallback.sendMessage(
@@ -126,26 +145,115 @@ constructor(private val defaultWorkspaceCallbackBinder: DefaultWorkspaceCallback
                                     }
                                 }
                         }
+
+                        launch {
+                            combine(
+                                    viewModel.clockPickerViewModel.previewingClock,
+                                    viewModel.clockPickerViewModel.previewingClockSize,
+                                    ::Pair,
+                                )
+                                .collect { (previewingClock, previewingClockSize) ->
+                                    val hideSmartspace =
+                                        clockViewFactory
+                                            .getController(previewingClock.clockId)
+                                            .let {
+                                                when (previewingClockSize) {
+                                                    ClockSize.DYNAMIC ->
+                                                        it.largeClock.config
+                                                            .hasCustomWeatherDataDisplay
+                                                    ClockSize.SMALL ->
+                                                        it.smallClock.config
+                                                            .hasCustomWeatherDataDisplay
+                                                }
+                                            }
+                                    workspaceCallback.sendMessage(
+                                        MESSAGE_ID_HIDE_SMART_SPACE,
+                                        Bundle().apply {
+                                            putBoolean(KEY_HIDE_SMART_SPACE, hideSmartspace)
+                                        },
+                                    )
+
+                                    workspaceCallback.sendMessage(
+                                        MESSAGE_ID_PREVIEW_CLOCK_SIZE,
+                                        Bundle().apply {
+                                            putString(
+                                                KEY_CLOCK_SIZE,
+                                                when (previewingClockSize) {
+                                                    ClockSize.DYNAMIC -> CLOCK_SIZE_DYNAMIC
+                                                    ClockSize.SMALL -> CLOCK_SIZE_SMALL
+                                                },
+                                            )
+                                        },
+                                    )
+                                }
+                        }
                     }
                 }
             Screen.HOME_SCREEN ->
                 lifecycleOwner.lifecycleScope.launch {
                     lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                         launch {
-                            viewModel.shapeAndGridPickerViewModel.previewingGridOptionKey.collect {
+                            viewModel.shapeGridPickerViewModel.previewingShapeKey.collect {
+                                workspaceCallback.sendMessage(
+                                    MESSAGE_ID_UPDATE_SHAPE,
+                                    bundleOf(COL_SHAPE_KEY to it),
+                                )
+                            }
+                        }
+
+                        launch {
+                            viewModel.shapeGridPickerViewModel.previewingGridKey.collect {
                                 workspaceCallback.sendMessage(
                                     MESSAGE_ID_UPDATE_GRID,
-                                    bundleOf(KEY_GRID_NAME to it)
+                                    bundleOf(COL_GRID_NAME to it),
                                 )
                             }
                         }
+
+                        launch {
+                            colorUpdateViewModel.systemColorsUpdated.collect {
+                                viewModel.colorPickerViewModel2.onApplyComplete()
+                            }
+                        }
+
+                        launch {
+                            combine(
+                                    viewModel.colorPickerViewModel2.previewingColorOption,
+                                    viewModel.darkModeViewModel.overridingIsDarkMode,
+                                    ::Pair,
+                                )
+                                .collect { (colorModel, darkMode) ->
+                                    val bundle =
+                                        Bundle().apply {
+                                            if (colorModel != null) {
+                                                val (ids, colors) =
+                                                    materialColorsGenerator.generate(
+                                                        colorModel.colorOption.seedColor,
+                                                        colorModel.colorOption.style,
+                                                    )
+                                                putIntArray(KEY_COLOR_RESOURCE_IDS, ids)
+                                                putIntArray(KEY_COLOR_VALUES, colors)
+                                            }
+
+                                            if (darkMode != null) {
+                                                putBoolean(KEY_DARK_MODE, darkMode)
+                                            }
+                                        }
+                                    workspaceCallback.sendMessage(MESSAGE_ID_UPDATE_COLOR, bundle)
+                                }
+                        }
                     }
                 }
         }
     }
 
     companion object {
+        const val MESSAGE_ID_UPDATE_SHAPE = 2586
         const val MESSAGE_ID_UPDATE_GRID = 7414
-        const val KEY_GRID_NAME = "grid_name"
+
+        const val MESSAGE_ID_UPDATE_COLOR = 856
+        const val KEY_COLOR_RESOURCE_IDS: String = "color_resource_ids"
+        const val KEY_COLOR_VALUES: String = "color_values"
+        const val KEY_DARK_MODE: String = "use_dark_mode"
     }
 }
diff --git a/src/com/android/wallpaper/picker/di/modules/ThemePickerSharedAppModule.kt b/src/com/android/wallpaper/picker/di/modules/ThemePickerSharedAppModule.kt
index 0b321966..98c881f6 100644
--- a/src/com/android/wallpaper/picker/di/modules/ThemePickerSharedAppModule.kt
+++ b/src/com/android/wallpaper/picker/di/modules/ThemePickerSharedAppModule.kt
@@ -16,8 +16,10 @@
 
 package com.android.wallpaper.picker.di.modules
 
-import com.android.customization.model.grid.DefaultGridOptionsManager
-import com.android.customization.model.grid.GridOptionsManager2
+import com.android.customization.model.grid.DefaultShapeGridManager
+import com.android.customization.model.grid.ShapeGridManager
+import com.android.customization.picker.mode.shared.util.DarkModeUtil
+import com.android.customization.picker.mode.shared.util.DarkModeUtilImpl
 import dagger.Binds
 import dagger.Module
 import dagger.hilt.InstallIn
@@ -30,5 +32,7 @@ abstract class ThemePickerSharedAppModule {
 
     @Binds
     @Singleton
-    abstract fun bindGridOptionsManager2(impl: DefaultGridOptionsManager): GridOptionsManager2
+    abstract fun bindGridOptionsManager2(impl: DefaultShapeGridManager): ShapeGridManager
+
+    @Binds @Singleton abstract fun bindDarkModeUtil(impl: DarkModeUtilImpl): DarkModeUtil
 }
diff --git a/src_override/com/android/wallpaper/modules/ThemePickerAppModule.kt b/src_override/com/android/wallpaper/modules/ThemePickerAppModule.kt
index 31b4cd80..1c4ecc99 100644
--- a/src_override/com/android/wallpaper/modules/ThemePickerAppModule.kt
+++ b/src_override/com/android/wallpaper/modules/ThemePickerAppModule.kt
@@ -46,9 +46,11 @@ import com.android.wallpaper.module.logging.UserEventLogger
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
@@ -141,6 +143,12 @@ abstract class ThemePickerAppModule {
     @Singleton
     abstract fun bindThemesUserEventLogger(impl: ThemesUserEventLoggerImpl): ThemesUserEventLogger
 
+    @Binds
+    @Singleton
+    abstract fun bindThirdPartyCategoryInteractor(
+        impl: ThirdPartyCategoryInteractorImpl
+    ): ThirdPartyCategoryInteractor
+
     @Binds @Singleton abstract fun bindToolbarBinder(impl: ThemePickerToolbarBinder): ToolbarBinder
 
     @Binds
diff --git a/tests/common/src/com/android/customization/model/grid/FakeGridOptionsManager.kt b/tests/common/src/com/android/customization/model/grid/FakeGridOptionsManager.kt
deleted file mode 100644
index cc239818..00000000
--- a/tests/common/src/com/android/customization/model/grid/FakeGridOptionsManager.kt
+++ /dev/null
@@ -1,57 +0,0 @@
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
-package com.android.customization.model.grid
-
-import javax.inject.Inject
-import javax.inject.Singleton
-
-@Singleton
-class FakeGridOptionsManager @Inject constructor() : GridOptionsManager2 {
-
-    var isGridOptionAvailable: Boolean = true
-
-    private var gridOptions: List<GridOptionModel>? = DEFAULT_GRID_OPTION_LIST
-
-    override suspend fun isGridOptionAvailable(): Boolean = isGridOptionAvailable
-
-    override suspend fun getGridOptions(): List<GridOptionModel>? = gridOptions
-
-    override fun applyGridOption(gridName: String): Int {
-        gridOptions = gridOptions?.map { it.copy(isCurrent = it.key == gridName) }
-        return 0
-    }
-
-    companion object {
-        val DEFAULT_GRID_OPTION_LIST =
-            listOf(
-                GridOptionModel(
-                    key = "normal",
-                    title = "5x5",
-                    isCurrent = true,
-                    rows = 5,
-                    cols = 5,
-                ),
-                GridOptionModel(
-                    key = "practical",
-                    title = "4x5",
-                    isCurrent = false,
-                    rows = 5,
-                    cols = 4,
-                ),
-            )
-    }
-}
diff --git a/tests/common/src/com/android/customization/model/grid/FakeShapeGridManager.kt b/tests/common/src/com/android/customization/model/grid/FakeShapeGridManager.kt
new file mode 100644
index 00000000..b1f044a0
--- /dev/null
+++ b/tests/common/src/com/android/customization/model/grid/FakeShapeGridManager.kt
@@ -0,0 +1,104 @@
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
+package com.android.customization.model.grid
+
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+class FakeShapeGridManager @Inject constructor() : ShapeGridManager {
+
+    private var gridOptions: List<GridOptionModel>? = DEFAULT_GRID_OPTION_LIST
+
+    private var shapeOptions: List<ShapeOptionModel>? = DEFAULT_SHAPE_OPTION_LIST
+
+    override suspend fun getGridOptions(): List<GridOptionModel>? = gridOptions
+
+    override suspend fun getShapeOptions(): List<ShapeOptionModel>? = shapeOptions
+
+    override fun applyShapeGridOption(shapeKey: String, gridKey: String): Int {
+        shapeOptions = shapeOptions?.map { it.copy(isCurrent = it.key == shapeKey) }
+        gridOptions = gridOptions?.map { it.copy(isCurrent = it.key == gridKey) }
+        return 0
+    }
+
+    companion object {
+        val DEFAULT_GRID_OPTION_LIST =
+            listOf(
+                GridOptionModel(
+                    key = "normal",
+                    title = "5x5",
+                    isCurrent = true,
+                    rows = 5,
+                    cols = 5,
+                ),
+                GridOptionModel(
+                    key = "practical",
+                    title = "4x5",
+                    isCurrent = false,
+                    rows = 5,
+                    cols = 4,
+                ),
+            )
+
+        val DEFAULT_SHAPE_OPTION_LIST =
+            listOf(
+                ShapeOptionModel(
+                    key = "arch",
+                    title = "arch",
+                    path =
+                        "M100 83.46C100 85.471 100 86.476 99.9 87.321 99.116 93.916 93.916 99.116 87.321 99.9 86.476 100 85.471 100 83.46 100H16.54C14.529 100 13.524 100 12.679 99.9 6.084 99.116.884 93.916.1 87.321 0 86.476 0 85.471 0 83.46L0 50C0 22.386 22.386 0 50 0 77.614 0 100 22.386 100 50V83.46Z",
+                    isCurrent = true,
+                ),
+                ShapeOptionModel(
+                    key = "4-sided-cookie",
+                    title = "4-sided-cookie",
+                    path =
+                        "M63.605 3C84.733-6.176 106.176 15.268 97 36.395L95.483 39.888C92.681 46.338 92.681 53.662 95.483 60.112L97 63.605C106.176 84.732 84.733 106.176 63.605 97L60.112 95.483C53.662 92.681 46.338 92.681 39.888 95.483L36.395 97C15.267 106.176-6.176 84.732 3 63.605L4.517 60.112C7.319 53.662 7.319 46.338 4.517 39.888L3 36.395C-6.176 15.268 15.267-6.176 36.395 3L39.888 4.517C46.338 7.319 53.662 7.319 60.112 4.517L63.605 3Z",
+                    isCurrent = false,
+                ),
+                ShapeOptionModel(
+                    key = "7-sided-cookie",
+                    title = "7-sided-cookie",
+                    path =
+                        "M35.209 4.878C36.326 3.895 36.884 3.404 37.397 3.006 44.82-2.742 55.18-2.742 62.603 3.006 63.116 3.404 63.674 3.895 64.791 4.878 65.164 5.207 65.351 5.371 65.539 5.529 68.167 7.734 71.303 9.248 74.663 9.932 74.902 9.981 75.147 10.025 75.637 10.113 77.1 10.375 77.831 10.506 78.461 10.66 87.573 12.893 94.032 21.011 94.176 30.412 94.186 31.062 94.151 31.805 94.08 33.293 94.057 33.791 94.045 34.04 94.039 34.285 93.958 37.72 94.732 41.121 96.293 44.18 96.404 44.399 96.522 44.618 96.759 45.056 97.467 46.366 97.821 47.021 98.093 47.611 102.032 56.143 99.727 66.266 92.484 72.24 91.983 72.653 91.381 73.089 90.177 73.961 89.774 74.254 89.572 74.4 89.377 74.548 86.647 76.626 84.477 79.353 83.063 82.483 82.962 82.707 82.865 82.936 82.671 83.395 82.091 84.766 81.8 85.451 81.51 86.033 77.31 94.44 67.977 98.945 58.801 96.994 58.166 96.859 57.451 96.659 56.019 96.259 55.54 96.125 55.3 96.058 55.063 95.998 51.74 95.154 48.26 95.154 44.937 95.998 44.699 96.058 44.46 96.125 43.981 96.259 42.549 96.659 41.834 96.859 41.199 96.994 32.023 98.945 22.69 94.44 18.49 86.033 18.2 85.451 17.909 84.766 17.329 83.395 17.135 82.936 17.038 82.707 16.937 82.483 15.523 79.353 13.353 76.626 10.623 74.548 10.428 74.4 10.226 74.254 9.823 73.961 8.619 73.089 8.017 72.653 7.516 72.24.273 66.266-2.032 56.143 1.907 47.611 2.179 47.021 2.533 46.366 3.241 45.056 3.478 44.618 3.596 44.399 3.707 44.18 5.268 41.121 6.042 37.72 5.961 34.285 5.955 34.04 5.943 33.791 5.92 33.293 5.849 31.805 5.814 31.062 5.824 30.412 5.968 21.011 12.427 12.893 21.539 10.66 22.169 10.506 22.9 10.375 24.363 10.113 24.853 10.025 25.098 9.981 25.337 9.932 28.697 9.248 31.833 7.734 34.461 5.529 34.649 5.371 34.836 5.207 35.209 4.878Z",
+                    isCurrent = false,
+                ),
+                ShapeOptionModel(
+                    key = "sunny",
+                    title = "sunny",
+                    path =
+                        "M42.846 4.873C46.084-.531 53.916-.531 57.154 4.873L60.796 10.951C62.685 14.103 66.414 15.647 69.978 14.754L76.851 13.032C82.962 11.5 88.5 17.038 86.968 23.149L85.246 30.022C84.353 33.586 85.897 37.315 89.049 39.204L95.127 42.846C100.531 46.084 100.531 53.916 95.127 57.154L89.049 60.796C85.897 62.685 84.353 66.414 85.246 69.978L86.968 76.851C88.5 82.962 82.962 88.5 76.851 86.968L69.978 85.246C66.414 84.353 62.685 85.898 60.796 89.049L57.154 95.127C53.916 100.531 46.084 100.531 42.846 95.127L39.204 89.049C37.315 85.898 33.586 84.353 30.022 85.246L23.149 86.968C17.038 88.5 11.5 82.962 13.032 76.851L14.754 69.978C15.647 66.414 14.103 62.685 10.951 60.796L4.873 57.154C-.531 53.916-.531 46.084 4.873 42.846L10.951 39.204C14.103 37.315 15.647 33.586 14.754 30.022L13.032 23.149C11.5 17.038 17.038 11.5 23.149 13.032L30.022 14.754C33.586 15.647 37.315 14.103 39.204 10.951L42.846 4.873Z",
+                    isCurrent = false,
+                ),
+                ShapeOptionModel(
+                    key = "circle",
+                    title = "circle",
+                    path =
+                        "M99.18 50C99.18 77.162 77.162 99.18 50 99.18 22.838 99.18.82 77.162.82 50 .82 22.839 22.838.82 50 .82 77.162.82 99.18 22.839 99.18 50Z",
+                    isCurrent = false,
+                ),
+                ShapeOptionModel(
+                    key = "square",
+                    title = "square",
+                    path =
+                        "M99.18 53.689C99.18 67.434 99.18 74.306 97.022 79.758 93.897 87.649 87.649 93.897 79.758 97.022 74.306 99.18 67.434 99.18 53.689 99.18H46.311C32.566 99.18 25.694 99.18 20.242 97.022 12.351 93.897 6.103 87.649 2.978 79.758.82 74.306.82 67.434.82 53.689L.82 46.311C.82 32.566.82 25.694 2.978 20.242 6.103 12.351 12.351 6.103 20.242 2.978 25.694.82 32.566.82 46.311.82L53.689.82C67.434.82 74.306.82 79.758 2.978 87.649 6.103 93.897 12.351 97.022 20.242 99.18 25.694 99.18 32.566 99.18 46.311V53.689Z",
+                    isCurrent = false,
+                ),
+            )
+    }
+}
diff --git a/tests/common/src/com/android/customization/module/logging/TestThemesUserEventLogger.kt b/tests/common/src/com/android/customization/module/logging/TestThemesUserEventLogger.kt
index 46510673..05c95b07 100644
--- a/tests/common/src/com/android/customization/module/logging/TestThemesUserEventLogger.kt
+++ b/tests/common/src/com/android/customization/module/logging/TestThemesUserEventLogger.kt
@@ -40,6 +40,9 @@ class TestThemesUserEventLogger @Inject constructor() :
 
     var shortcutLogs: List<Pair<String, String>> = emptyList()
 
+    var useDarkTheme: Boolean = false
+        private set
+
     override fun logThemeColorApplied(@ColorSource source: Int, style: Int, seedColor: Int) {
         this.themeColorSource = source
         this.themeColorStyle = style
@@ -64,7 +67,9 @@ class TestThemesUserEventLogger @Inject constructor() :
         shortcutLogs = shortcutLogs.toMutableList().apply { add(shortcut to shortcutSlotId) }
     }
 
-    override fun logDarkThemeApplied(useDarkTheme: Boolean) {}
+    override fun logDarkThemeApplied(useDarkTheme: Boolean) {
+        this.useDarkTheme = useDarkTheme
+    }
 
     @ClockSize
     fun getLoggedClockSize(): Int {
diff --git a/tests/common/src/com/android/customization/testing/TestCustomizationInjector.kt b/tests/common/src/com/android/customization/testing/TestCustomizationInjector.kt
index 4e97599b..a474212b 100644
--- a/tests/common/src/com/android/customization/testing/TestCustomizationInjector.kt
+++ b/tests/common/src/com/android/customization/testing/TestCustomizationInjector.kt
@@ -14,10 +14,18 @@ import com.android.customization.picker.clock.ui.viewmodel.ClockCarouselViewMode
 import com.android.customization.picker.clock.ui.viewmodel.ClockSettingsViewModel
 import com.android.customization.picker.color.ui.viewmodel.ColorPickerViewModel
 import com.android.customization.picker.quickaffordance.domain.interactor.KeyguardQuickAffordancePickerInteractor
+import com.android.wallpaper.module.NetworkStatusNotifier
+import com.android.wallpaper.module.PartnerProvider
+import com.android.wallpaper.module.WallpaperPreferences
 import com.android.wallpaper.module.logging.UserEventLogger
+import com.android.wallpaper.network.Requester
 import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper
 import com.android.wallpaper.picker.customization.data.repository.WallpaperColorsRepository
+import com.android.wallpaper.picker.customization.domain.interactor.WallpaperInteractor
+import com.android.wallpaper.testing.FakeWallpaperClient
 import com.android.wallpaper.testing.TestInjector
+import com.android.wallpaper.testing.TestPackageStatusNotifier
+import com.android.wallpaper.util.DisplayUtils
 import javax.inject.Inject
 import javax.inject.Singleton
 
@@ -27,7 +35,29 @@ open class TestCustomizationInjector
 constructor(
     private val customPrefs: TestDefaultCustomizationPreferences,
     private val themesUserEventLogger: ThemesUserEventLogger,
-) : TestInjector(themesUserEventLogger), CustomizationInjector {
+    displayUtils: DisplayUtils,
+    requester: Requester,
+    networkStatusNotifier: NetworkStatusNotifier,
+    partnerProvider: PartnerProvider,
+    wallpaperClient: FakeWallpaperClient,
+    injectedWallpaperInteractor: WallpaperInteractor,
+    prefs: WallpaperPreferences,
+    private val fakeWallpaperCategoryWrapper: WallpaperCategoryWrapper,
+    private val testStatusNotifier: TestPackageStatusNotifier,
+) :
+    TestInjector(
+        themesUserEventLogger,
+        displayUtils,
+        requester,
+        networkStatusNotifier,
+        partnerProvider,
+        wallpaperClient,
+        injectedWallpaperInteractor,
+        prefs,
+        fakeWallpaperCategoryWrapper,
+        testStatusNotifier,
+    ),
+    CustomizationInjector {
     /////////////////
     // CustomizationInjector implementations
     /////////////////
@@ -82,6 +112,6 @@ constructor(
     }
 
     override fun getWallpaperCategoryWrapper(): WallpaperCategoryWrapper {
-        return super.fakeWallpaperCategoryWrapper
+        return fakeWallpaperCategoryWrapper
     }
 }
diff --git a/tests/common/src/com/android/wallpaper/di/modules/ThemePickerSharedAppTestModule.kt b/tests/common/src/com/android/wallpaper/di/modules/ThemePickerSharedAppTestModule.kt
index 7781d4ec..4969db4e 100644
--- a/tests/common/src/com/android/wallpaper/di/modules/ThemePickerSharedAppTestModule.kt
+++ b/tests/common/src/com/android/wallpaper/di/modules/ThemePickerSharedAppTestModule.kt
@@ -16,8 +16,10 @@
 
 package com.android.wallpaper.di.modules
 
-import com.android.customization.model.grid.FakeGridOptionsManager
-import com.android.customization.model.grid.GridOptionsManager2
+import com.android.customization.model.grid.FakeShapeGridManager
+import com.android.customization.model.grid.ShapeGridManager
+import com.android.customization.picker.mode.shared.util.DarkModeUtil
+import com.android.customization.picker.mode.shared.util.FakeDarkModeUtil
 import com.android.wallpaper.picker.di.modules.ThemePickerSharedAppModule
 import dagger.Binds
 import dagger.Module
@@ -28,11 +30,13 @@ import javax.inject.Singleton
 @Module
 @TestInstallIn(
     components = [SingletonComponent::class],
-    replaces = [ThemePickerSharedAppModule::class]
+    replaces = [ThemePickerSharedAppModule::class],
 )
 abstract class ThemePickerSharedAppTestModule {
 
     @Binds
     @Singleton
-    abstract fun bindGridOptionsManager2(impl: FakeGridOptionsManager): GridOptionsManager2
+    abstract fun bindGridOptionsManager2(impl: FakeShapeGridManager): ShapeGridManager
+
+    @Binds @Singleton abstract fun bindDarkModeUtil(impl: FakeDarkModeUtil): DarkModeUtil
 }
diff --git a/tests/module/src/com/android/wallpaper/ThemePickerTestModule.kt b/tests/module/src/com/android/wallpaper/ThemePickerTestModule.kt
index 8f09d51a..bc03f121 100644
--- a/tests/module/src/com/android/wallpaper/ThemePickerTestModule.kt
+++ b/tests/module/src/com/android/wallpaper/ThemePickerTestModule.kt
@@ -45,6 +45,10 @@ import com.android.wallpaper.module.logging.TestUserEventLogger
 import com.android.wallpaper.module.logging.UserEventLogger
 import com.android.wallpaper.modules.ThemePickerAppModule
 import com.android.wallpaper.network.Requester
+import com.android.wallpaper.picker.category.domain.interactor.CategoryInteractor
+import com.android.wallpaper.picker.category.domain.interactor.ThirdPartyCategoryInteractor
+import com.android.wallpaper.picker.category.ui.view.providers.IndividualPickerFactory
+import com.android.wallpaper.picker.category.ui.view.providers.implementation.DefaultIndividualPickerFactory
 import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper
 import com.android.wallpaper.picker.common.preview.ui.binder.ThemePickerWorkspaceCallbackBinder
 import com.android.wallpaper.picker.common.preview.ui.binder.WorkspaceCallbackBinder
@@ -55,7 +59,9 @@ import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import com.android.wallpaper.picker.di.modules.MainDispatcher
 import com.android.wallpaper.picker.preview.ui.util.DefaultImageEffectDialogUtil
 import com.android.wallpaper.picker.preview.ui.util.ImageEffectDialogUtil
+import com.android.wallpaper.testing.FakeCategoryInteractor
 import com.android.wallpaper.testing.FakeDefaultRequester
+import com.android.wallpaper.testing.FakeThirdPartyCategoryInteractor
 import com.android.wallpaper.testing.FakeWallpaperCategoryWrapper
 import com.android.wallpaper.testing.TestPartnerProvider
 import com.android.wallpaper.util.converter.DefaultWallpaperModelFactory
@@ -114,6 +120,16 @@ abstract class ThemePickerTestModule {
         impl: DefaultImageEffectDialogUtil
     ): ImageEffectDialogUtil
 
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
     @Binds @Singleton abstract fun bindInjector(impl: TestCustomizationInjector): Injector
 
     @Binds
@@ -126,6 +142,12 @@ abstract class ThemePickerTestModule {
     @Singleton
     abstract fun bindThemesUserEventLogger(impl: TestThemesUserEventLogger): ThemesUserEventLogger
 
+    @Binds
+    @Singleton
+    abstract fun bindThirdPartyCategoryInteractor(
+        impl: FakeThirdPartyCategoryInteractor
+    ): ThirdPartyCategoryInteractor
+
     @Binds @Singleton abstract fun bindToolbarBinder(impl: ThemePickerToolbarBinder): ToolbarBinder
 
     @Binds @Singleton abstract fun bindUserEventLogger(impl: TestUserEventLogger): UserEventLogger
diff --git a/tests/robotests/src/com/android/customization/model/color/ColorCustomizationManagerTest.kt b/tests/robotests/src/com/android/customization/model/color/ColorCustomizationManagerTest.kt
index 0776cc8b..13f58a51 100644
--- a/tests/robotests/src/com/android/customization/model/color/ColorCustomizationManagerTest.kt
+++ b/tests/robotests/src/com/android/customization/model/color/ColorCustomizationManagerTest.kt
@@ -64,14 +64,14 @@ class ColorCustomizationManagerTest {
                 provider,
                 application.contentResolver,
                 mockOM,
-                MoreExecutors.newDirectExecutorService()
+                MoreExecutors.newDirectExecutorService(),
             )
     }
 
     @Test
     fun testParseSettings() {
         val source = COLOR_SOURCE_HOME
-        val style = Style.SPRITZ
+        @Style.Type val style = Style.SPRITZ
         val someColor = "aabbcc"
         val someOtherColor = "bbccdd"
         val settings =
@@ -79,15 +79,15 @@ class ColorCustomizationManagerTest {
                 OVERLAY_CATEGORY_SYSTEM_PALETTE to someColor,
                 OVERLAY_CATEGORY_COLOR to someOtherColor,
                 OVERLAY_COLOR_SOURCE to source,
-                OVERLAY_THEME_STYLE to style.toString(),
-                ColorOption.TIMESTAMP_FIELD to "12345"
+                OVERLAY_THEME_STYLE to Style.toString(style),
+                ColorOption.TIMESTAMP_FIELD to "12345",
             )
         val json = JSONObject(settings).toString()
 
         manager.parseSettings(json)
 
         assertThat(manager.currentColorSource).isEqualTo(source)
-        assertThat(manager.currentStyle).isEqualTo(style.toString())
+        assertThat(manager.currentStyle).isEqualTo(Style.toString(style))
         assertThat(manager.currentOverlays.size).isEqualTo(2)
         assertThat(manager.currentOverlays[OVERLAY_CATEGORY_COLOR]).isEqualTo(someOtherColor)
         assertThat(manager.currentOverlays[OVERLAY_CATEGORY_SYSTEM_PALETTE]).isEqualTo(someColor)
@@ -106,14 +106,16 @@ class ColorCustomizationManagerTest {
             getPresetColorOption(index),
             object : CustomizationManager.Callback {
                 override fun onSuccess() {}
+
                 override fun onError(throwable: Throwable?) {}
-            }
+            },
         )
 
         val overlaysJson = JSONObject(manager.storedOverlays)
 
         assertThat(overlaysJson.getString(OVERLAY_COLOR_INDEX)).isEqualTo(value)
     }
+
     @Test
     fun apply_WallpaperColorOption_index() {
         testApplyWallpaperColorOption(1, "1")
@@ -127,8 +129,9 @@ class ColorCustomizationManagerTest {
             getWallpaperColorOption(index),
             object : CustomizationManager.Callback {
                 override fun onSuccess() {}
+
                 override fun onError(throwable: Throwable?) {}
-            }
+            },
         )
 
         val overlaysJson = JSONObject(manager.storedOverlays)
@@ -141,10 +144,11 @@ class ColorCustomizationManagerTest {
             mapOf("fake_package" to "fake_color"),
             /* isDefault= */ false,
             COLOR_SOURCE_PRESET,
+            12345,
             Style.TONAL_SPOT,
             index,
             ColorOptionImpl.PreviewInfo(intArrayOf(0), intArrayOf(0)),
-            ColorType.PRESET_COLOR
+            ColorType.PRESET_COLOR,
         )
     }
 
@@ -154,10 +158,11 @@ class ColorCustomizationManagerTest {
             mapOf("fake_package" to "fake_color"),
             /* isDefault= */ false,
             COLOR_SOURCE_HOME,
+            12345,
             Style.TONAL_SPOT,
             index,
             ColorOptionImpl.PreviewInfo(intArrayOf(0), intArrayOf(0)),
-            ColorType.WALLPAPER_COLOR
+            ColorType.WALLPAPER_COLOR,
         )
     }
 
@@ -170,8 +175,9 @@ class ColorCustomizationManagerTest {
             getWallpaperColorOption(0),
             object : CustomizationManager.Callback {
                 override fun onSuccess() {}
+
                 override fun onError(throwable: Throwable?) {}
-            }
+            },
         )
 
         val overlaysJson = JSONObject(manager.storedOverlays)
@@ -188,8 +194,9 @@ class ColorCustomizationManagerTest {
             getWallpaperColorOption(0),
             object : CustomizationManager.Callback {
                 override fun onSuccess() {}
+
                 override fun onError(throwable: Throwable?) {}
-            }
+            },
         )
 
         val overlaysJson = JSONObject(manager.storedOverlays)
diff --git a/tests/robotests/src/com/android/customization/model/color/ColorOptionTest.kt b/tests/robotests/src/com/android/customization/model/color/ColorOptionTest.kt
index b9156d6e..75d10ca1 100644
--- a/tests/robotests/src/com/android/customization/model/color/ColorOptionTest.kt
+++ b/tests/robotests/src/com/android/customization/model/color/ColorOptionTest.kt
@@ -15,6 +15,7 @@
  */
 package com.android.customization.model.color
 
+import android.graphics.Color
 import com.android.customization.model.ResourceConstants.OVERLAY_CATEGORY_SYSTEM_PALETTE
 import com.android.customization.model.color.ColorOptionsProvider.COLOR_SOURCE_HOME
 import com.android.customization.model.color.ColorOptionsProvider.COLOR_SOURCE_LOCK
@@ -54,10 +55,11 @@ class ColorOptionTest {
                 mapOf("fake_package" to "fake_color"),
                 false,
                 source,
+                12345,
                 Style.TONAL_SPOT,
                 /* index= */ 0,
                 ColorOptionImpl.PreviewInfo(intArrayOf(0), intArrayOf(0)),
-                ColorType.WALLPAPER_COLOR
+                ColorType.WALLPAPER_COLOR,
             )
         assertThat(colorOption.source).isEqualTo(source)
     }
@@ -70,17 +72,18 @@ class ColorOptionTest {
         testColorOptionStyle(Style.EXPRESSIVE)
     }
 
-    private fun testColorOptionStyle(style: Style) {
+    private fun testColorOptionStyle(@Style.Type style: Int) {
         val colorOption: ColorOption =
             ColorOptionImpl(
                 "fake color",
                 mapOf("fake_package" to "fake_color"),
                 /* isDefault= */ false,
                 "fake_source",
+                12345,
                 style,
                 0,
                 ColorOptionImpl.PreviewInfo(intArrayOf(0), intArrayOf(0)),
-                ColorType.WALLPAPER_COLOR
+                ColorType.WALLPAPER_COLOR,
             )
         assertThat(colorOption.style).isEqualTo(style)
     }
@@ -100,17 +103,41 @@ class ColorOptionTest {
                 mapOf("fake_package" to "fake_color"),
                 /* isDefault= */ false,
                 "fake_source",
+                12345,
                 Style.TONAL_SPOT,
                 index,
                 ColorOptionImpl.PreviewInfo(intArrayOf(0), intArrayOf(0)),
-                ColorType.WALLPAPER_COLOR
+                ColorType.WALLPAPER_COLOR,
             )
         assertThat(colorOption.index).isEqualTo(index)
     }
 
+    @Test
+    fun colorOption_seedColor() {
+        testColorOptionSeed(Color.RED)
+        testColorOptionSeed(Color.WHITE)
+        testColorOptionSeed(Color.BLACK)
+    }
+
+    private fun testColorOptionSeed(seedColor: Int) {
+        val colorOption: ColorOption =
+            ColorOptionImpl(
+                "fake color",
+                mapOf("fake_package" to "fake_color"),
+                /* isDefault= */ false,
+                "fake_source",
+                seedColor,
+                Style.TONAL_SPOT,
+                0,
+                ColorOptionImpl.PreviewInfo(intArrayOf(0), intArrayOf(0)),
+                ColorType.WALLPAPER_COLOR,
+            )
+        assertThat(colorOption.seedColor).isEqualTo(seedColor)
+    }
+
     private fun setUpWallpaperColorOption(
         isDefault: Boolean,
-        source: String = "some_source"
+        source: String = "some_source",
     ): ColorOptionImpl {
         val overlays =
             if (isDefault) {
@@ -124,10 +151,11 @@ class ColorOptionTest {
             overlays,
             isDefault,
             source,
+            12345,
             Style.TONAL_SPOT,
             /* index= */ 0,
             ColorOptionImpl.PreviewInfo(intArrayOf(0), intArrayOf(0)),
-            ColorType.WALLPAPER_COLOR
+            ColorType.WALLPAPER_COLOR,
         )
     }
 
diff --git a/tests/robotests/src/com/android/customization/model/picker/color/ui/viewmodel/ColorPickerViewModelTest.kt b/tests/robotests/src/com/android/customization/model/picker/color/ui/viewmodel/ColorPickerViewModelTest.kt
index f5878a48..b39a564b 100644
--- a/tests/robotests/src/com/android/customization/model/picker/color/ui/viewmodel/ColorPickerViewModelTest.kt
+++ b/tests/robotests/src/com/android/customization/model/picker/color/ui/viewmodel/ColorPickerViewModelTest.kt
@@ -17,7 +17,6 @@
 package com.android.customization.model.picker.color.ui.viewmodel
 
 import android.content.Context
-import android.graphics.Color
 import android.stats.style.StyleEnums
 import androidx.test.filters.SmallTest
 import androidx.test.platform.app.InstrumentationRegistry
@@ -86,7 +85,7 @@ class ColorPickerViewModelTest {
             ColorPickerViewModel.Factory(
                     context = context,
                     interactor = interactor,
-                    logger = logger
+                    logger = logger,
                 )
                 .create(ColorPickerViewModel::class.java)
 
@@ -105,19 +104,19 @@ class ColorPickerViewModelTest {
 
             assertColorOptionUiState(
                 colorOptions = colorSectionOptions(),
-                selectedColorOptionIndex = 0
+                selectedColorOptionIndex = 0,
             )
 
             selectColorOption(colorSectionOptions, 2)
             assertColorOptionUiState(
                 colorOptions = colorSectionOptions(),
-                selectedColorOptionIndex = 2
+                selectedColorOptionIndex = 2,
             )
 
             selectColorOption(colorSectionOptions, 4)
             assertColorOptionUiState(
                 colorOptions = colorSectionOptions(),
-                selectedColorOptionIndex = 4
+                selectedColorOptionIndex = 4,
             )
         }
 
@@ -129,12 +128,12 @@ class ColorPickerViewModelTest {
                     repository.buildWallpaperOption(
                         ColorOptionsProvider.COLOR_SOURCE_LOCK,
                         Style.EXPRESSIVE,
-                        "121212"
+                        121212,
                     )
                 ),
-                listOf(repository.buildPresetOption(Style.FRUIT_SALAD, "#ABCDEF")),
+                listOf(repository.buildPresetOption(Style.FRUIT_SALAD, -54321)),
                 ColorType.PRESET_COLOR,
-                0
+                0,
             )
 
             val colorTypes = collectLastValue(underTest.colorTypeTabs)
@@ -148,8 +147,9 @@ class ColorPickerViewModelTest {
 
             assertThat(logger.themeColorSource)
                 .isEqualTo(StyleEnums.COLOR_SOURCE_LOCK_SCREEN_WALLPAPER)
-            assertThat(logger.themeColorStyle).isEqualTo(Style.EXPRESSIVE.toString().hashCode())
-            assertThat(logger.themeSeedColor).isEqualTo(Color.parseColor("#121212"))
+            assertThat(logger.themeColorStyle)
+                .isEqualTo(Style.toString(Style.EXPRESSIVE).hashCode())
+            assertThat(logger.themeSeedColor).isEqualTo(121212)
         }
 
     @Test
@@ -160,12 +160,12 @@ class ColorPickerViewModelTest {
                     repository.buildWallpaperOption(
                         ColorOptionsProvider.COLOR_SOURCE_LOCK,
                         Style.EXPRESSIVE,
-                        "121212"
+                        121212,
                     )
                 ),
-                listOf(repository.buildPresetOption(Style.FRUIT_SALAD, "#ABCDEF")),
+                listOf(repository.buildPresetOption(Style.FRUIT_SALAD, -54321)),
                 ColorType.WALLPAPER_COLOR,
-                0
+                0,
             )
 
             val colorTypes = collectLastValue(underTest.colorTypeTabs)
@@ -178,8 +178,9 @@ class ColorPickerViewModelTest {
             advanceUntilIdle()
 
             assertThat(logger.themeColorSource).isEqualTo(StyleEnums.COLOR_SOURCE_PRESET_COLOR)
-            assertThat(logger.themeColorStyle).isEqualTo(Style.FRUIT_SALAD.toString().hashCode())
-            assertThat(logger.themeSeedColor).isEqualTo(Color.parseColor("#ABCDEF"))
+            assertThat(logger.themeColorStyle)
+                .isEqualTo(Style.toString(Style.FRUIT_SALAD).hashCode())
+            assertThat(logger.themeSeedColor).isEqualTo(-54321)
         }
 
     @Test
@@ -193,7 +194,7 @@ class ColorPickerViewModelTest {
                 colorTypes = colorTypes(),
                 colorOptions = colorOptions(),
                 selectedColorTypeText = "Wallpaper colors",
-                selectedColorOptionIndex = 0
+                selectedColorOptionIndex = 0,
             )
 
             // Select "Basic colors" tab
@@ -202,7 +203,7 @@ class ColorPickerViewModelTest {
                 colorTypes = colorTypes(),
                 colorOptions = colorOptions(),
                 selectedColorTypeText = "Basic colors",
-                selectedColorOptionIndex = -1
+                selectedColorOptionIndex = -1,
             )
 
             // Select a color option
@@ -214,7 +215,7 @@ class ColorPickerViewModelTest {
                 colorTypes = colorTypes(),
                 colorOptions = colorOptions(),
                 selectedColorTypeText = "Wallpaper colors",
-                selectedColorOptionIndex = -1
+                selectedColorOptionIndex = -1,
             )
 
             // Check new option is selected
@@ -223,7 +224,7 @@ class ColorPickerViewModelTest {
                 colorTypes = colorTypes(),
                 colorOptions = colorOptions(),
                 selectedColorTypeText = "Basic colors",
-                selectedColorOptionIndex = 2
+                selectedColorOptionIndex = 2,
             )
         }
 
diff --git a/tests/robotests/src/com/android/customization/model/picker/quickaffordance/ui/viewmodel/KeyguardQuickAffordancePickerViewModelTest.kt b/tests/robotests/src/com/android/customization/model/picker/quickaffordance/ui/viewmodel/KeyguardQuickAffordancePickerViewModelTest.kt
index 870d9f5a..36a723c3 100644
--- a/tests/robotests/src/com/android/customization/model/picker/quickaffordance/ui/viewmodel/KeyguardQuickAffordancePickerViewModelTest.kt
+++ b/tests/robotests/src/com/android/customization/model/picker/quickaffordance/ui/viewmodel/KeyguardQuickAffordancePickerViewModelTest.kt
@@ -33,6 +33,11 @@ import com.android.systemui.shared.customization.data.content.FakeCustomizationP
 import com.android.systemui.shared.keyguard.shared.model.KeyguardQuickAffordanceSlots
 import com.android.themepicker.R
 import com.android.wallpaper.module.InjectorProvider
+import com.android.wallpaper.module.NetworkStatusNotifier
+import com.android.wallpaper.module.PartnerProvider
+import com.android.wallpaper.module.WallpaperPreferences
+import com.android.wallpaper.network.Requester
+import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper
 import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
 import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
 import com.android.wallpaper.picker.customization.data.repository.WallpaperRepository
@@ -41,8 +46,11 @@ import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
 import com.android.wallpaper.testing.FakeWallpaperClient
 import com.android.wallpaper.testing.TestCurrentWallpaperInfoFactory
 import com.android.wallpaper.testing.TestInjector
+import com.android.wallpaper.testing.TestPackageStatusNotifier
 import com.android.wallpaper.testing.TestWallpaperPreferences
 import com.android.wallpaper.testing.collectLastValue
+import com.android.wallpaper.util.DisplayUtils
+import com.android.wallpaper.util.DisplaysProvider
 import com.google.common.truth.Truth.assertThat
 import com.google.common.truth.Truth.assertWithMessage
 import kotlinx.coroutines.Dispatchers
@@ -56,6 +64,7 @@ import org.junit.After
 import org.junit.Before
 import org.junit.Test
 import org.junit.runner.RunWith
+import org.mockito.Mockito.mock
 import org.robolectric.RobolectricTestRunner
 
 @OptIn(ExperimentalCoroutinesApi::class)
@@ -72,10 +81,10 @@ class KeyguardQuickAffordancePickerViewModelTest {
     private lateinit var client: FakeCustomizationProviderClient
     private lateinit var quickAffordanceInteractor: KeyguardQuickAffordancePickerInteractor
     private lateinit var wallpaperInteractor: WallpaperInteractor
+    private lateinit var testPackageStatusNotifier: TestPackageStatusNotifier
 
     @Before
     fun setUp() {
-        InjectorProvider.setInjector(TestInjector(logger))
         context = ApplicationProvider.getApplicationContext()
         val testDispatcher = StandardTestDispatcher()
         testScope = TestScope(testDispatcher)
@@ -100,8 +109,23 @@ class KeyguardQuickAffordancePickerViewModelTest {
                         client = FakeWallpaperClient(),
                         wallpaperPreferences = TestWallpaperPreferences(),
                         backgroundDispatcher = testDispatcher,
-                    ),
+                    )
+            )
+        testPackageStatusNotifier = TestPackageStatusNotifier()
+        InjectorProvider.setInjector(
+            TestInjector(
+                logger,
+                DisplayUtils(context, mock(DisplaysProvider::class.java)),
+                mock(Requester::class.java),
+                mock(NetworkStatusNotifier::class.java),
+                mock(PartnerProvider::class.java),
+                FakeWallpaperClient(),
+                wallpaperInteractor,
+                mock(WallpaperPreferences::class.java),
+                mock(WallpaperCategoryWrapper::class.java),
+                testPackageStatusNotifier,
             )
+        )
         underTest =
             KeyguardQuickAffordancePickerViewModel.Factory(
                     context = context,
@@ -348,12 +372,12 @@ class KeyguardQuickAffordancePickerViewModelTest {
                         icon1 =
                             Icon.Loaded(
                                 FakeCustomizationProviderClient.ICON_1,
-                                Text.Loaded("Left shortcut")
+                                Text.Loaded("Left shortcut"),
                             ),
                         icon2 =
                             Icon.Loaded(
                                 FakeCustomizationProviderClient.ICON_3,
-                                Text.Loaded("Right shortcut")
+                                Text.Loaded("Right shortcut"),
                             ),
                     )
                 )
@@ -376,7 +400,7 @@ class KeyguardQuickAffordancePickerViewModelTest {
                         icon1 =
                             Icon.Loaded(
                                 FakeCustomizationProviderClient.ICON_1,
-                                Text.Loaded("Left shortcut")
+                                Text.Loaded("Left shortcut"),
                             ),
                         icon2 = null,
                     )
@@ -404,7 +428,7 @@ class KeyguardQuickAffordancePickerViewModelTest {
                         icon2 =
                             Icon.Loaded(
                                 FakeCustomizationProviderClient.ICON_3,
-                                Text.Loaded("Right shortcut")
+                                Text.Loaded("Right shortcut"),
                             ),
                     )
                 )
@@ -465,11 +489,7 @@ class KeyguardQuickAffordancePickerViewModelTest {
         assertThat(affordances).isNotNull()
         affordances?.forEach { affordance ->
             val nameMatchesSelectedName =
-                Text.evaluationEquals(
-                    context,
-                    affordance.text,
-                    Text.Loaded(selectedAffordanceText),
-                )
+                Text.evaluationEquals(context, affordance.text, Text.Loaded(selectedAffordanceText))
             val isSelected: Boolean? = collectLastValue(affordance.isSelected).invoke()
             assertWithMessage(
                     "Expected affordance with name \"${affordance.text}\" to have" +
diff --git a/tests/robotests/src/com/android/customization/picker/clock/data/repository/FakeClockPickerRepository.kt b/tests/robotests/src/com/android/customization/picker/clock/data/repository/FakeClockPickerRepository.kt
index f97feefd..0e5a88ec 100644
--- a/tests/robotests/src/com/android/customization/picker/clock/data/repository/FakeClockPickerRepository.kt
+++ b/tests/robotests/src/com/android/customization/picker/clock/data/repository/FakeClockPickerRepository.kt
@@ -22,10 +22,14 @@ import androidx.annotation.IntRange
 import com.android.customization.picker.clock.data.repository.FakeClockPickerRepository.Companion.fakeClocks
 import com.android.customization.picker.clock.shared.ClockSize
 import com.android.customization.picker.clock.shared.model.ClockMetadataModel
+import com.android.systemui.plugins.clocks.AxisType
+import com.android.systemui.plugins.clocks.ClockFontAxis
+import com.android.systemui.plugins.clocks.ClockFontAxisSetting
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.update
 
 /** By default [FakeClockPickerRepository] uses [fakeClocks]. */
 open class FakeClockPickerRepository(clocks: List<ClockMetadataModel> = fakeClocks) :
@@ -36,12 +40,14 @@ open class FakeClockPickerRepository(clocks: List<ClockMetadataModel> = fakeCloc
     @ColorInt private val selectedColorId = MutableStateFlow<String?>(null)
     private val colorTone = MutableStateFlow(ClockMetadataModel.DEFAULT_COLOR_TONE_PROGRESS)
     @ColorInt private val seedColor = MutableStateFlow<Int?>(null)
+    private val fontAxes = MutableStateFlow<List<ClockFontAxis>>(listOf(buildFakeAxis(0)))
     override val selectedClock: Flow<ClockMetadataModel> =
-        combine(selectedClockId, selectedColorId, colorTone, seedColor) {
+        combine(selectedClockId, selectedColorId, colorTone, seedColor, fontAxes) {
             selectedClockId,
             selectedColor,
             colorTone,
-            seedColor ->
+            seedColor,
+            fontAxes ->
             val selectedClock = fakeClocks.find { clock -> clock.clockId == selectedClockId }
             checkNotNull(selectedClock)
             ClockMetadataModel(
@@ -50,6 +56,7 @@ open class FakeClockPickerRepository(clocks: List<ClockMetadataModel> = fakeCloc
                 description = "description",
                 thumbnail = ColorDrawable(0),
                 isReactiveToTone = selectedClock.isReactiveToTone,
+                fontAxes = fontAxes,
                 selectedColorId = selectedColor,
                 colorToneProgress = colorTone,
                 seedColor = seedColor,
@@ -77,7 +84,23 @@ open class FakeClockPickerRepository(clocks: List<ClockMetadataModel> = fakeCloc
         _selectedClockSize.value = size
     }
 
+    override suspend fun setClockFontAxes(axisSettings: List<ClockFontAxisSetting>) {
+        fontAxes.update { fontAxes -> ClockFontAxis.merge(fontAxes, axisSettings) }
+    }
+
     companion object {
+        fun buildFakeAxis(i: Int): ClockFontAxis {
+            return ClockFontAxis(
+                key = "key",
+                type = AxisType.Float,
+                maxValue = 0f,
+                minValue = 1000f,
+                currentValue = 50f * (i + 1),
+                name = "FakeAxis",
+                description = "Axis Description",
+            )
+        }
+
         const val CLOCK_ID_0 = "clock0"
         const val CLOCK_ID_1 = "clock1"
         const val CLOCK_ID_2 = "clock2"
@@ -90,6 +113,7 @@ open class FakeClockPickerRepository(clocks: List<ClockMetadataModel> = fakeCloc
                     "description0",
                     ColorDrawable(0),
                     true,
+                    listOf(buildFakeAxis(0)),
                     null,
                     50,
                     null,
@@ -100,6 +124,7 @@ open class FakeClockPickerRepository(clocks: List<ClockMetadataModel> = fakeCloc
                     "description1",
                     ColorDrawable(0),
                     true,
+                    listOf(buildFakeAxis(1)),
                     null,
                     50,
                     null,
@@ -110,6 +135,7 @@ open class FakeClockPickerRepository(clocks: List<ClockMetadataModel> = fakeCloc
                     "description2",
                     ColorDrawable(0),
                     true,
+                    listOf(buildFakeAxis(2)),
                     null,
                     50,
                     null,
@@ -120,6 +146,7 @@ open class FakeClockPickerRepository(clocks: List<ClockMetadataModel> = fakeCloc
                     "description3",
                     ColorDrawable(0),
                     false,
+                    listOf(buildFakeAxis(3)),
                     null,
                     50,
                     null,
diff --git a/tests/robotests/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractorTest.kt b/tests/robotests/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractorTest.kt
index 478b7956..43910ffd 100644
--- a/tests/robotests/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractorTest.kt
+++ b/tests/robotests/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractorTest.kt
@@ -80,4 +80,14 @@ class ClockPickerInteractorTest {
             .isEqualTo(FakeClockPickerRepository.CLOCK_COLOR_TONE_PROGRESS)
         Truth.assertThat(observedSeedColor()).isEqualTo(FakeClockPickerRepository.SEED_COLOR)
     }
+
+    @Test
+    fun setFontAxisSettings() = runTest {
+        val axisSettings = collectLastValue(underTest.axisSettings)
+        val fakeSettings = listOf(FakeClockPickerRepository.buildFakeAxis(10).toSetting())
+
+        underTest.setClockFontAxes(fakeSettings)
+
+        Truth.assertThat(axisSettings()).isEqualTo(fakeSettings)
+    }
 }
diff --git a/tests/robotests/src/com/android/customization/picker/clock/ui/FakeClockViewFactory.kt b/tests/robotests/src/com/android/customization/picker/clock/ui/FakeClockViewFactory.kt
index 32490241..418b4393 100644
--- a/tests/robotests/src/com/android/customization/picker/clock/ui/FakeClockViewFactory.kt
+++ b/tests/robotests/src/com/android/customization/picker/clock/ui/FakeClockViewFactory.kt
@@ -1,6 +1,5 @@
 package com.android.customization.picker.clock.ui
 
-import android.content.res.Resources
 import android.view.View
 import androidx.lifecycle.LifecycleOwner
 import com.android.customization.picker.clock.data.repository.FakeClockPickerRepository
@@ -9,6 +8,7 @@ import com.android.systemui.plugins.clocks.ClockConfig
 import com.android.systemui.plugins.clocks.ClockController
 import com.android.systemui.plugins.clocks.ClockEvents
 import com.android.systemui.plugins.clocks.ClockFaceController
+import com.android.systemui.plugins.clocks.ClockFontAxisSetting
 import java.io.PrintWriter
 import javax.inject.Inject
 
@@ -29,7 +29,7 @@ class FakeClockViewFactory @Inject constructor() : ClockViewFactory {
         override val events: ClockEvents
             get() = TODO("Not yet implemented")
 
-        override fun initialize(resources: Resources, dozeFraction: Float, foldFraction: Float) =
+        override fun initialize(isDarkTheme: Boolean, dozeFraction: Float, foldFraction: Float) =
             TODO("Not yet implemented")
 
         override fun dump(pw: PrintWriter) = TODO("Not yet implemented")
@@ -37,10 +37,6 @@ class FakeClockViewFactory @Inject constructor() : ClockViewFactory {
 
     override fun getController(clockId: String): ClockController = clockControllers[clockId]!!
 
-    override fun setReactiveTouchInteractionEnabled(clockId: String, enable: Boolean) {
-        TODO("Not yet implemented")
-    }
-
     override fun getLargeView(clockId: String): View {
         TODO("Not yet implemented")
     }
@@ -57,6 +53,10 @@ class FakeClockViewFactory @Inject constructor() : ClockViewFactory {
         TODO("Not yet implemented")
     }
 
+    override fun updateFontAxes(clockId: String, settings: List<ClockFontAxisSetting>) {
+        TODO("Not yet implemented")
+    }
+
     override fun updateRegionDarkness() {
         TODO("Not yet implemented")
     }
diff --git a/tests/robotests/src/com/android/customization/picker/clock/ui/viewmodel/ClockCarouselViewModelTest.kt b/tests/robotests/src/com/android/customization/picker/clock/ui/viewmodel/ClockCarouselViewModelTest.kt
index be852ac9..64efed60 100644
--- a/tests/robotests/src/com/android/customization/picker/clock/ui/viewmodel/ClockCarouselViewModelTest.kt
+++ b/tests/robotests/src/com/android/customization/picker/clock/ui/viewmodel/ClockCarouselViewModelTest.kt
@@ -58,10 +58,11 @@ class ClockCarouselViewModelTest {
                     description = "description",
                     thumbnail = ColorDrawable(0),
                     isReactiveToTone = true,
+                    fontAxes = listOf(),
                     selectedColorId = null,
                     colorToneProgress = ClockMetadataModel.DEFAULT_COLOR_TONE_PROGRESS,
                     seedColor = null,
-                ),
+                )
             )
         )
     }
diff --git a/tests/robotests/src/com/android/customization/picker/grid/data/repository/GridRepository2Test.kt b/tests/robotests/src/com/android/customization/picker/grid/data/repository/ShapeGridRepositoryTest.kt
similarity index 57%
rename from tests/robotests/src/com/android/customization/picker/grid/data/repository/GridRepository2Test.kt
rename to tests/robotests/src/com/android/customization/picker/grid/data/repository/ShapeGridRepositoryTest.kt
index 404f08b8..985d9834 100644
--- a/tests/robotests/src/com/android/customization/picker/grid/data/repository/GridRepository2Test.kt
+++ b/tests/robotests/src/com/android/customization/picker/grid/data/repository/ShapeGridRepositoryTest.kt
@@ -17,7 +17,7 @@
 package com.android.customization.picker.grid.data.repository
 
 import androidx.test.filters.SmallTest
-import com.android.customization.model.grid.FakeGridOptionsManager
+import com.android.customization.model.grid.FakeShapeGridManager
 import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import com.android.wallpaper.testing.collectLastValue
 import com.google.common.truth.Truth.assertThat
@@ -42,21 +42,21 @@ import org.robolectric.RobolectricTestRunner
 @OptIn(ExperimentalCoroutinesApi::class)
 @SmallTest
 @RunWith(RobolectricTestRunner::class)
-class GridRepository2Test {
+class ShapeGridRepositoryTest {
 
     @get:Rule var hiltRule = HiltAndroidRule(this)
-    @Inject lateinit var gridOptionsManager: FakeGridOptionsManager
+    @Inject lateinit var gridOptionsManager: FakeShapeGridManager
     @Inject lateinit var testScope: TestScope
     @BackgroundDispatcher @Inject lateinit var bgScope: CoroutineScope
     @BackgroundDispatcher @Inject lateinit var bgDispatcher: CoroutineDispatcher
 
-    private lateinit var underTest: GridRepository2
+    private lateinit var underTest: ShapeGridRepository
 
     @Before
     fun setUp() {
         hiltRule.inject()
         underTest =
-            GridRepository2(
+            ShapeGridRepository(
                 manager = gridOptionsManager,
                 bgScope = bgScope,
                 bgDispatcher = bgDispatcher,
@@ -69,55 +69,88 @@ class GridRepository2Test {
     }
 
     @Test
-    fun isGridOptionAvailable_false() =
+    fun shapeOptions_default() =
         testScope.runTest {
-            gridOptionsManager.isGridOptionAvailable = false
-            assertThat(underTest.isGridOptionAvailable()).isFalse()
+            val gridOptions = collectLastValue(underTest.shapeOptions)
+
+            assertThat(gridOptions()).isEqualTo(FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST)
         }
 
     @Test
-    fun isGridOptionAvailable_true() =
+    fun shapeOptions_shouldUpdateAfterApplyShapeGridOption() =
         testScope.runTest {
-            gridOptionsManager.isGridOptionAvailable = true
-            assertThat(underTest.isGridOptionAvailable()).isTrue()
+            val shapeOptions = collectLastValue(underTest.shapeOptions)
+
+            underTest.applySelectedOption("circle", "practical")
+
+            assertThat(shapeOptions())
+                .isEqualTo(
+                    FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST.map {
+                        it.copy(isCurrent = (it.key == "circle"))
+                    }
+                )
         }
 
     @Test
-    fun gridOptions_default() =
+    fun selectedShapeOption_default() =
         testScope.runTest {
-            val gridOptions = collectLastValue(underTest.gridOptions)
-            assertThat(gridOptions()).isEqualTo(FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST)
+            val selectedGridOption = collectLastValue(underTest.selectedShapeOption)
+
+            assertThat(selectedGridOption())
+                .isEqualTo(FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST[0])
         }
 
     @Test
-    fun selectedGridOption_default() =
+    fun selectedShapeOption_shouldUpdateAfterApplyShapeGridOption() =
         testScope.runTest {
-            val selectedGridOption = collectLastValue(underTest.selectedGridOption)
-            assertThat(selectedGridOption())
-                .isEqualTo(FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST[0])
+            val selectedShapeOption = collectLastValue(underTest.selectedShapeOption)
+
+            underTest.applySelectedOption("circle", "practical")
+
+            assertThat(selectedShapeOption())
+                .isEqualTo(FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST[4].copy(isCurrent = true))
+        }
+
+    @Test
+    fun gridOptions_default() =
+        testScope.runTest {
+            val gridOptions = collectLastValue(underTest.gridOptions)
+
+            assertThat(gridOptions()).isEqualTo(FakeShapeGridManager.DEFAULT_GRID_OPTION_LIST)
         }
 
     @Test
-    fun gridOptions_shouldUpdateAfterApplyGridOption() =
+    fun gridOptions_shouldUpdateAfterApplyShapeGridOption() =
         testScope.runTest {
             val gridOptions = collectLastValue(underTest.gridOptions)
-            underTest.applySelectedOption("practical")
+
+            underTest.applySelectedOption("circle", "practical")
+
             assertThat(gridOptions())
                 .isEqualTo(
-                    FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST.map {
-                        it.copy(isCurrent = it.key == "practical")
+                    FakeShapeGridManager.DEFAULT_GRID_OPTION_LIST.map {
+                        it.copy(isCurrent = (it.key == "practical"))
                     }
                 )
         }
 
     @Test
-    fun selectedGridOption_shouldUpdateAfterApplyGridOption() =
+    fun selectedGridOption_default() =
         testScope.runTest {
             val selectedGridOption = collectLastValue(underTest.selectedGridOption)
-            underTest.applySelectedOption("practical")
+
             assertThat(selectedGridOption())
-                .isEqualTo(
-                    FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST[1].copy(isCurrent = true)
-                )
+                .isEqualTo(FakeShapeGridManager.DEFAULT_GRID_OPTION_LIST[0])
+        }
+
+    @Test
+    fun selectedGridOption_shouldUpdateAfterApplyShapeGridOption() =
+        testScope.runTest {
+            val selectedGridOption = collectLastValue(underTest.selectedGridOption)
+
+            underTest.applySelectedOption("circle", "practical")
+
+            assertThat(selectedGridOption())
+                .isEqualTo(FakeShapeGridManager.DEFAULT_GRID_OPTION_LIST[1].copy(isCurrent = true))
         }
 }
diff --git a/tests/robotests/src/com/android/customization/picker/grid/domain/interactor/GridInteractor2Test.kt b/tests/robotests/src/com/android/customization/picker/grid/domain/interactor/ShapeGridInteractorTest.kt
similarity index 54%
rename from tests/robotests/src/com/android/customization/picker/grid/domain/interactor/GridInteractor2Test.kt
rename to tests/robotests/src/com/android/customization/picker/grid/domain/interactor/ShapeGridInteractorTest.kt
index bfbe282f..c0f519cf 100644
--- a/tests/robotests/src/com/android/customization/picker/grid/domain/interactor/GridInteractor2Test.kt
+++ b/tests/robotests/src/com/android/customization/picker/grid/domain/interactor/ShapeGridInteractorTest.kt
@@ -17,8 +17,8 @@
 package com.android.customization.picker.grid.domain.interactor
 
 import androidx.test.filters.SmallTest
-import com.android.customization.model.grid.FakeGridOptionsManager
-import com.android.customization.picker.grid.data.repository.GridRepository2
+import com.android.customization.model.grid.FakeShapeGridManager
+import com.android.customization.picker.grid.data.repository.ShapeGridRepository
 import com.android.wallpaper.testing.collectLastValue
 import com.google.common.truth.Truth.assertThat
 import dagger.hilt.android.testing.HiltAndroidRule
@@ -40,19 +40,19 @@ import org.robolectric.RobolectricTestRunner
 @OptIn(ExperimentalCoroutinesApi::class)
 @SmallTest
 @RunWith(RobolectricTestRunner::class)
-class GridInteractor2Test {
+class ShapeGridInteractorTest {
 
     @get:Rule var hiltRule = HiltAndroidRule(this)
-    @Inject lateinit var gridOptionsManager: FakeGridOptionsManager
-    @Inject lateinit var repository: GridRepository2
+    @Inject lateinit var gridOptionsManager: FakeShapeGridManager
+    @Inject lateinit var repository: ShapeGridRepository
     @Inject lateinit var testScope: TestScope
 
-    private lateinit var underTest: GridInteractor2
+    private lateinit var underTest: ShapeGridInteractor
 
     @Before
     fun setUp() {
         hiltRule.inject()
-        underTest = GridInteractor2(repository)
+        underTest = ShapeGridInteractor(repository)
     }
 
     @After
@@ -61,55 +61,88 @@ class GridInteractor2Test {
     }
 
     @Test
-    fun isGridOptionAvailable_false() =
+    fun shapeOptions_default() =
         testScope.runTest {
-            gridOptionsManager.isGridOptionAvailable = false
-            assertThat(underTest.isGridOptionAvailable()).isFalse()
+            val shapeOptions = collectLastValue(underTest.shapeOptions)
+
+            assertThat(shapeOptions()).isEqualTo(FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST)
         }
 
     @Test
-    fun isGridOptionAvailable_true() =
+    fun shapeOptions_shouldUpdateAfterApplyGridOption() =
         testScope.runTest {
-            gridOptionsManager.isGridOptionAvailable = true
-            assertThat(underTest.isGridOptionAvailable()).isTrue()
+            val shapeOptions = collectLastValue(underTest.shapeOptions)
+
+            underTest.applySelectedOption("circle", "practical")
+
+            assertThat(shapeOptions())
+                .isEqualTo(
+                    FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST.map {
+                        it.copy(isCurrent = (it.key == "circle"))
+                    }
+                )
         }
 
     @Test
-    fun gridOptions_default() =
+    fun selectedShapeOption_default() =
         testScope.runTest {
-            val gridOptions = collectLastValue(underTest.gridOptions)
-            assertThat(gridOptions()).isEqualTo(FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST)
+            val selectedShapeOption = collectLastValue(underTest.selectedShapeOption)
+
+            assertThat(selectedShapeOption())
+                .isEqualTo(FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST[0])
         }
 
     @Test
-    fun selectedGridOption_default() =
+    fun selectedShapeOption_shouldUpdateAfterApplyGridOption() =
         testScope.runTest {
-            val selectedGridOption = collectLastValue(underTest.selectedGridOption)
-            assertThat(selectedGridOption())
-                .isEqualTo(FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST[0])
+            val selectedShapeOption = collectLastValue(underTest.selectedShapeOption)
+
+            underTest.applySelectedOption("circle", "practical")
+
+            assertThat(selectedShapeOption())
+                .isEqualTo(FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST[4].copy(isCurrent = true))
+        }
+
+    @Test
+    fun gridOptions_default() =
+        testScope.runTest {
+            val gridOptions = collectLastValue(underTest.gridOptions)
+
+            assertThat(gridOptions()).isEqualTo(FakeShapeGridManager.DEFAULT_GRID_OPTION_LIST)
         }
 
     @Test
     fun gridOptions_shouldUpdateAfterApplyGridOption() =
         testScope.runTest {
             val gridOptions = collectLastValue(underTest.gridOptions)
-            underTest.applySelectedOption("practical")
+
+            underTest.applySelectedOption("arch", "practical")
+
             assertThat(gridOptions())
                 .isEqualTo(
-                    FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST.map {
-                        it.copy(isCurrent = it.key == "practical")
+                    FakeShapeGridManager.DEFAULT_GRID_OPTION_LIST.map {
+                        it.copy(isCurrent = (it.key == "practical"))
                     }
                 )
         }
 
+    @Test
+    fun selectedGridOption_default() =
+        testScope.runTest {
+            val selectedGridOption = collectLastValue(underTest.selectedGridOption)
+
+            assertThat(selectedGridOption())
+                .isEqualTo(FakeShapeGridManager.DEFAULT_GRID_OPTION_LIST[0])
+        }
+
     @Test
     fun selectedGridOption_shouldUpdateAfterApplyGridOption() =
         testScope.runTest {
             val selectedGridOption = collectLastValue(underTest.selectedGridOption)
-            underTest.applySelectedOption("practical")
+
+            underTest.applySelectedOption("arch", "practical")
+
             assertThat(selectedGridOption())
-                .isEqualTo(
-                    FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST[1].copy(isCurrent = true)
-                )
+                .isEqualTo(FakeShapeGridManager.DEFAULT_GRID_OPTION_LIST[1].copy(isCurrent = true))
         }
 }
diff --git a/tests/robotests/src/com/android/customization/picker/mode/ui/viewmodel/DarkModeViewModelTest.kt b/tests/robotests/src/com/android/customization/picker/mode/ui/viewmodel/DarkModeViewModelTest.kt
new file mode 100644
index 00000000..fbd56bc3
--- /dev/null
+++ b/tests/robotests/src/com/android/customization/picker/mode/ui/viewmodel/DarkModeViewModelTest.kt
@@ -0,0 +1,140 @@
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
+package com.android.customization.picker.mode.ui.viewmodel
+
+import com.android.customization.module.logging.TestThemesUserEventLogger
+import com.android.customization.picker.mode.data.repository.DarkModeRepository
+import com.android.customization.picker.mode.domain.interactor.DarkModeInteractor
+import com.android.wallpaper.testing.FakePowerManager
+import com.android.wallpaper.testing.FakeUiModeManager
+import com.android.wallpaper.testing.collectLastValue
+import com.google.common.truth.Truth.assertThat
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
+
+@HiltAndroidTest
+@OptIn(ExperimentalCoroutinesApi::class)
+@RunWith(RobolectricTestRunner::class)
+class DarkModeViewModelTest {
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+
+    @Inject lateinit var uiModeManager: FakeUiModeManager
+    @Inject lateinit var powerManager: FakePowerManager
+    @Inject lateinit var darkModeRepository: DarkModeRepository
+    @Inject lateinit var darkModeInteractor: DarkModeInteractor
+    @Inject lateinit var logger: TestThemesUserEventLogger
+    lateinit var darkModeViewModel: DarkModeViewModel
+
+    @Inject lateinit var testDispatcher: TestDispatcher
+    @Inject lateinit var testScope: TestScope
+
+    @Before
+    fun setUp() {
+        hiltRule.inject()
+        Dispatchers.setMain(testDispatcher)
+
+        darkModeViewModel = DarkModeViewModel(darkModeInteractor, logger)
+    }
+
+    @Test
+    fun isEnabled_powerSaveModeOn() {
+        testScope.runTest {
+            powerManager.setIsPowerSaveMode(true)
+            darkModeRepository.refreshIsPowerSaveModeActivated()
+
+            val isEnabled = collectLastValue(darkModeViewModel.isEnabled)()
+
+            assertThat(isEnabled).isFalse()
+        }
+    }
+
+    @Test
+    fun isEnabled_powerSaveModeOff() {
+        testScope.runTest {
+            powerManager.setIsPowerSaveMode(false)
+            darkModeRepository.refreshIsPowerSaveModeActivated()
+
+            val isEnabled = collectLastValue(darkModeViewModel.isEnabled)()
+
+            assertThat(isEnabled).isTrue()
+        }
+    }
+
+    @Test
+    fun toggleDarkMode() {
+        testScope.runTest {
+            uiModeManager.setNightModeActivated(false)
+            darkModeRepository.refreshIsDarkModeActivated()
+            val getOverridingIsDarkMode = collectLastValue(darkModeViewModel.overridingIsDarkMode)
+            val getPreviewingIsDarkMode = collectLastValue(darkModeViewModel.previewingIsDarkMode)
+            val getToggleDarkMode = collectLastValue(darkModeViewModel.toggleDarkMode)
+            assertThat(getPreviewingIsDarkMode()).isFalse()
+
+            getToggleDarkMode()?.invoke()
+
+            assertThat(getOverridingIsDarkMode()).isTrue()
+            assertThat(getPreviewingIsDarkMode()).isTrue()
+
+            getToggleDarkMode()?.invoke()
+
+            assertThat(getOverridingIsDarkMode()).isNull()
+            assertThat(getPreviewingIsDarkMode()).isFalse()
+        }
+    }
+
+    @Test
+    fun onApply_shouldLogDarkTheme() {
+        testScope.runTest {
+            uiModeManager.setNightModeActivated(false)
+            darkModeRepository.refreshIsDarkModeActivated()
+            val getToggleDarkMode = collectLastValue(darkModeViewModel.toggleDarkMode)
+            val onApply = collectLastValue(darkModeViewModel.onApply)
+
+            getToggleDarkMode()?.invoke()
+            onApply()?.invoke()
+
+            assertThat(logger.useDarkTheme).isTrue()
+        }
+    }
+
+    @Test
+    fun onApply_shouldApplyDarkTheme() {
+        testScope.runTest {
+            uiModeManager.setNightModeActivated(false)
+            darkModeRepository.refreshIsDarkModeActivated()
+            val getToggleDarkMode = collectLastValue(darkModeViewModel.toggleDarkMode)
+            val onApply = collectLastValue(darkModeViewModel.onApply)
+
+            getToggleDarkMode()?.invoke()
+            onApply()?.invoke()
+
+            assertThat(uiModeManager.getIsNightModeActivated()).isTrue()
+        }
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ClockPickerViewModelTest.kt b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ClockPickerViewModelTest.kt
index 72f3f6bf..76df4095 100644
--- a/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ClockPickerViewModelTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ClockPickerViewModelTest.kt
@@ -124,10 +124,6 @@ class ClockPickerViewModelTest {
         tabs()?.get(1)?.onClick?.invoke()
 
         assertThat(selectedTab()).isEqualTo(Tab.COLOR)
-
-        tabs()?.get(2)?.onClick?.invoke()
-
-        assertThat(selectedTab()).isEqualTo(Tab.SIZE)
     }
 
     @Test
@@ -139,10 +135,22 @@ class ClockPickerViewModelTest {
         tabs()?.get(1)?.onClick?.invoke()
 
         assertThat(tabs()?.get(1)?.isSelected).isTrue()
+    }
 
-        tabs()?.get(2)?.onClick?.invoke()
+    @Test
+    fun selectedTab_fontEditorWhenClickSelectedClock() = runTest {
+        val clockStyleOptions = collectLastValue(underTest.clockStyleOptions)
+        val selectedTab = collectLastValue(underTest.selectedTab)
+        // Advance CLOCKS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from clockStyleOptions
+        advanceTimeBy(ClockPickerViewModel.CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
+        assertThat(selectedTab()).isEqualTo(Tab.STYLE)
+
+        val firstClock = clockStyleOptions()!![0]
+        val onClicked = collectLastValue(firstClock.onClicked)
+        if (!firstClock.isSelected.value) onClicked()?.invoke()
+        onClicked()?.invoke()
 
-        assertThat(tabs()?.get(2)?.isSelected).isTrue()
+        assertThat(selectedTab()).isEqualTo(Tab.FONT)
     }
 
     @Test
@@ -173,7 +181,7 @@ class ClockPickerViewModelTest {
         val option1OnClicked = collectLastValue(clockStyleOptions()!![1].onClicked)
 
         assertThat(option0IsSelected()).isTrue()
-        assertThat(option0OnClicked()).isNull()
+        assertThat(option0OnClicked()).isNotNull()
 
         option1OnClicked()?.invoke()
         // Advance CLOCKS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from clockColorOptions
@@ -181,40 +189,90 @@ class ClockPickerViewModelTest {
 
         assertThat(option0IsSelected()).isFalse()
         assertThat(option1IsSelected()).isTrue()
-        assertThat(option1OnClicked()).isNull()
+        assertThat(option1OnClicked()).isNotNull()
     }
 
     @Test
-    fun previewingClockSize_whenClickOnSizeOptions() = runTest {
+    fun previewingClockSize_whenCallingOnClockSizeSwitchChecked() = runTest {
         val previewingClockSize = collectLastValue(underTest.previewingClockSize)
-        val sizeOptions = collectLastValue(underTest.sizeOptions)
 
         assertThat(previewingClockSize()).isEqualTo(ClockSize.DYNAMIC)
 
-        val option1OnClicked = collectLastValue(sizeOptions()!![1].onClicked)
-        option1OnClicked()?.invoke()
+        val onClockSizeSwitchCheckedChange =
+            collectLastValue(underTest.onClockSizeSwitchCheckedChange)
+        onClockSizeSwitchCheckedChange()?.invoke()
 
         assertThat(previewingClockSize()).isEqualTo(ClockSize.SMALL)
     }
 
     @Test
-    fun sizeOptions_whenClickOnSizeOptions() = runTest {
-        val sizeOptions = collectLastValue(underTest.sizeOptions)
-        val option0IsSelected = collectLastValue(sizeOptions()!![0].isSelected)
-        val option0OnClicked = collectLastValue(sizeOptions()!![0].onClicked)
-        val option1IsSelected = collectLastValue(sizeOptions()!![1].isSelected)
-        val option1OnClicked = collectLastValue(sizeOptions()!![1].onClicked)
-
-        assertThat(sizeOptions()!![0].size).isEqualTo(ClockSize.DYNAMIC)
-        assertThat(sizeOptions()!![1].size).isEqualTo(ClockSize.SMALL)
-        assertThat(option0IsSelected()).isTrue()
-        assertThat(option0OnClicked()).isNull()
+    fun previewingFontAxes_defaultWhenNoOverrides() = runTest {
+        val previewingFontAxes = collectLastValue(underTest.previewingClockFontAxisMap)
+        assertThat(previewingFontAxes()).isEqualTo(mapOf("key" to 50f))
+    }
 
-        option1OnClicked()?.invoke()
+    @Test
+    fun previewingFontAxes_updateAxisChangesSetting() = runTest {
+        val previewingFontAxes = collectLastValue(underTest.previewingClockFontAxisMap)
+        assertThat(previewingFontAxes()).isEqualTo(mapOf("key" to 50f))
 
-        assertThat(option0IsSelected()).isFalse()
-        assertThat(option1IsSelected()).isTrue()
-        assertThat(option1OnClicked()).isNull()
+        underTest.updatePreviewFontAxis("key", 100f)
+        assertThat(previewingFontAxes()).isEqualTo(mapOf("key" to 100f))
+
+        underTest.updatePreviewFontAxis("extra", 10f)
+        assertThat(previewingFontAxes()).isEqualTo(mapOf("key" to 100f, "extra" to 10f))
+    }
+
+    @Test
+    fun previewingFontAxes_applyFontEditorExitsTab_keepsPreviewAxis() = runTest {
+        val previewingFontAxes = collectLastValue(underTest.previewingClockFontAxisMap)
+        val clockStyleOptions = collectLastValue(underTest.clockStyleOptions)
+        val selectedTab = collectLastValue(underTest.selectedTab)
+        // Advance CLOCKS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from clockStyleOptions
+        advanceTimeBy(ClockPickerViewModel.CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
+
+        assertThat(previewingFontAxes()).isEqualTo(mapOf("key" to 50f))
+        assertThat(selectedTab()).isEqualTo(Tab.STYLE)
+
+        val firstClock = clockStyleOptions()!![0]
+        val onClicked = collectLastValue(firstClock.onClicked)
+        if (!firstClock.isSelected.value) onClicked()?.invoke()
+        onClicked()?.invoke()
+        underTest.updatePreviewFontAxis("key", 100f)
+
+        assertThat(selectedTab()).isEqualTo(Tab.FONT)
+        assertThat(previewingFontAxes()).isEqualTo(mapOf("key" to 100f))
+
+        underTest.confirmFontAxes()
+
+        assertThat(selectedTab()).isEqualTo(Tab.STYLE)
+        assertThat(previewingFontAxes()).isEqualTo(mapOf("key" to 100f))
+    }
+
+    @Test
+    fun previewingFontAxes_revertFontEditorExitsTab_revertsPreviewAxis() = runTest {
+        val previewingFontAxes = collectLastValue(underTest.previewingClockFontAxisMap)
+        val clockStyleOptions = collectLastValue(underTest.clockStyleOptions)
+        val selectedTab = collectLastValue(underTest.selectedTab)
+        // Advance CLOCKS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from clockStyleOptions
+        advanceTimeBy(ClockPickerViewModel.CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
+
+        assertThat(previewingFontAxes()).isEqualTo(mapOf("key" to 50f))
+        assertThat(selectedTab()).isEqualTo(Tab.STYLE)
+
+        val firstClock = clockStyleOptions()!![0]
+        val onClicked = collectLastValue(firstClock.onClicked)
+        if (!firstClock.isSelected.value) onClicked()?.invoke()
+        onClicked()?.invoke()
+        underTest.updatePreviewFontAxis("key", 100f)
+
+        assertThat(selectedTab()).isEqualTo(Tab.FONT)
+        assertThat(previewingFontAxes()).isEqualTo(mapOf("key" to 100f))
+
+        underTest.cancelFontAxes()
+
+        assertThat(selectedTab()).isEqualTo(Tab.STYLE)
+        assertThat(previewingFontAxes()).isEqualTo(mapOf("key" to 50f))
     }
 
     @Test
diff --git a/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ColorPickerViewModel2Test.kt b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ColorPickerViewModel2Test.kt
index d13d4b13..2056b1ed 100644
--- a/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ColorPickerViewModel2Test.kt
+++ b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ColorPickerViewModel2Test.kt
@@ -17,7 +17,6 @@
 package com.android.wallpaper.customization.ui.viewmodel
 
 import android.content.Context
-import android.graphics.Color
 import android.stats.style.StyleEnums
 import androidx.test.filters.SmallTest
 import androidx.test.platform.app.InstrumentationRegistry
@@ -30,13 +29,14 @@ import com.android.customization.picker.color.shared.model.ColorType
 import com.android.customization.picker.color.ui.viewmodel.ColorOptionIconViewModel
 import com.android.systemui.monet.Style
 import com.android.wallpaper.picker.customization.ui.viewmodel.FloatingToolbarTabViewModel
-import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel2
 import com.android.wallpaper.testing.FakeSnapshotStore
 import com.android.wallpaper.testing.collectLastValue
 import com.google.common.truth.Truth.assertThat
 import com.google.common.truth.Truth.assertWithMessage
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.launch
 import kotlinx.coroutines.runBlocking
 import kotlinx.coroutines.test.TestScope
 import kotlinx.coroutines.test.UnconfinedTestDispatcher
@@ -97,19 +97,40 @@ class ColorPickerViewModel2Test {
     }
 
     @Test
-    fun `Log selected wallpaper color`() =
+    fun onApply_suspendsUntilOnApplyCompleteIsCalled() =
+        testScope.runTest {
+            val colorTypes = collectLastValue(underTest.colorTypeTabs)
+            val colorOptions = collectLastValue(underTest.colorOptions)
+            val onApply = collectLastValue(underTest.onApply)
+
+            // Select "Wallpaper colors" tab
+            colorTypes()?.get(0)?.onClick?.invoke()
+            // Select a color option to preview
+            selectColorOption(colorOptions, 1)
+            // Apply the selected color option
+            val job = testScope.launch { onApply()?.invoke() }
+
+            assertThat(job.isActive).isTrue()
+
+            underTest.onApplyComplete()
+
+            assertThat(job.isActive).isFalse()
+        }
+
+    @Test
+    fun onApply_wallpaperColor_shouldLogColor() =
         testScope.runTest {
             repository.setOptions(
                 listOf(
                     repository.buildWallpaperOption(
                         ColorOptionsProvider.COLOR_SOURCE_LOCK,
                         Style.EXPRESSIVE,
-                        "121212"
+                        121212,
                     )
                 ),
-                listOf(repository.buildPresetOption(Style.FRUIT_SALAD, "#ABCDEF")),
+                listOf(repository.buildPresetOption(Style.FRUIT_SALAD, -54321)),
                 ColorType.PRESET_COLOR,
-                0
+                0,
             )
 
             val colorTypes = collectLastValue(underTest.colorTypeTabs)
@@ -117,29 +138,32 @@ class ColorPickerViewModel2Test {
 
             // Select "Wallpaper colors" tab
             colorTypes()?.get(0)?.onClick?.invoke()
-            // Select a color option
+            // Select a color option to preview
             selectColorOption(colorOptions, 0)
+            // Apply the selected color option
+            applySelectedColorOption()
 
             assertThat(logger.themeColorSource)
                 .isEqualTo(StyleEnums.COLOR_SOURCE_LOCK_SCREEN_WALLPAPER)
-            assertThat(logger.themeColorStyle).isEqualTo(Style.EXPRESSIVE.toString().hashCode())
-            assertThat(logger.themeSeedColor).isEqualTo(Color.parseColor("#121212"))
+            assertThat(logger.themeColorStyle)
+                .isEqualTo(Style.toString(Style.EXPRESSIVE).hashCode())
+            assertThat(logger.themeSeedColor).isEqualTo(121212)
         }
 
     @Test
-    fun `Log selected preset color`() =
+    fun onApply_presetColor_shouldLogColor() =
         testScope.runTest {
             repository.setOptions(
                 listOf(
                     repository.buildWallpaperOption(
                         ColorOptionsProvider.COLOR_SOURCE_LOCK,
                         Style.EXPRESSIVE,
-                        "121212"
+                        121212,
                     )
                 ),
-                listOf(repository.buildPresetOption(Style.FRUIT_SALAD, "#ABCDEF")),
+                listOf(repository.buildPresetOption(Style.FRUIT_SALAD, -54321)),
                 ColorType.WALLPAPER_COLOR,
-                0
+                0,
             )
 
             val colorTypes = collectLastValue(underTest.colorTypeTabs)
@@ -147,16 +171,19 @@ class ColorPickerViewModel2Test {
 
             // Select "Wallpaper colors" tab
             colorTypes()?.get(1)?.onClick?.invoke()
-            // Select a color option
+            // Select a color option to preview
             selectColorOption(colorOptions, 0)
+            // Apply the selected color option
+            applySelectedColorOption()
 
             assertThat(logger.themeColorSource).isEqualTo(StyleEnums.COLOR_SOURCE_PRESET_COLOR)
-            assertThat(logger.themeColorStyle).isEqualTo(Style.FRUIT_SALAD.toString().hashCode())
-            assertThat(logger.themeSeedColor).isEqualTo(Color.parseColor("#ABCDEF"))
+            assertThat(logger.themeColorStyle)
+                .isEqualTo(Style.toString(Style.FRUIT_SALAD).hashCode())
+            assertThat(logger.themeSeedColor).isEqualTo(-54321)
         }
 
     @Test
-    fun `Select a preset color`() =
+    fun selectColorOption() =
         testScope.runTest {
             val colorTypes = collectLastValue(underTest.colorTypeTabs)
             val colorOptions = collectLastValue(underTest.colorOptions)
@@ -166,7 +193,7 @@ class ColorPickerViewModel2Test {
                 colorTypes = colorTypes(),
                 colorOptions = colorOptions(),
                 selectedColorTypeText = "Wallpaper colors",
-                selectedColorOptionIndex = 0
+                selectedColorOptionIndex = 0,
             )
 
             // Select "Basic colors" tab
@@ -175,7 +202,7 @@ class ColorPickerViewModel2Test {
                 colorTypes = colorTypes(),
                 colorOptions = colorOptions(),
                 selectedColorTypeText = "Basic colors",
-                selectedColorOptionIndex = -1
+                selectedColorOptionIndex = -1,
             )
 
             // Select a color option
@@ -187,7 +214,7 @@ class ColorPickerViewModel2Test {
                 colorTypes = colorTypes(),
                 colorOptions = colorOptions(),
                 selectedColorTypeText = "Wallpaper colors",
-                selectedColorOptionIndex = -1
+                selectedColorOptionIndex = -1,
             )
 
             // Check new option is selected
@@ -196,13 +223,13 @@ class ColorPickerViewModel2Test {
                 colorTypes = colorTypes(),
                 colorOptions = colorOptions(),
                 selectedColorTypeText = "Basic colors",
-                selectedColorOptionIndex = 2
+                selectedColorOptionIndex = 2,
             )
         }
 
-    /** Simulates a user selecting the affordance at the given index, if that is clickable. */
+    /** Simulates a user selecting the color option at the given index. */
     private fun TestScope.selectColorOption(
-        colorOptions: () -> List<OptionItemViewModel<ColorOptionIconViewModel>>?,
+        colorOptions: () -> List<OptionItemViewModel2<ColorOptionIconViewModel>>?,
         index: Int,
     ) {
         val onClickedFlow = colorOptions()?.get(index)?.onClicked
@@ -210,10 +237,17 @@ class ColorPickerViewModel2Test {
             onClickedFlow?.let { collectLastValue(it) }
         onClickedLastValueOrNull?.let { onClickedLastValue ->
             val onClickedOrNull: (() -> Unit)? = onClickedLastValue()
-            onClickedOrNull?.let { onClicked -> onClicked() }
+            onClickedOrNull?.invoke()
         }
     }
 
+    /** Simulates a user applying the color option at the given index, and the apply completes. */
+    private suspend fun TestScope.applySelectedColorOption() {
+        val onApply = collectLastValue(underTest.onApply)()
+        testScope.launch { onApply?.invoke() }
+        underTest.onApplyComplete()
+    }
+
     /**
      * Asserts the entire picker UI state is what is expected. This includes the color type tabs and
      * the color options list.
@@ -226,7 +260,7 @@ class ColorPickerViewModel2Test {
      */
     private fun TestScope.assertPickerUiState(
         colorTypes: List<FloatingToolbarTabViewModel>?,
-        colorOptions: List<OptionItemViewModel<ColorOptionIconViewModel>>?,
+        colorOptions: List<OptionItemViewModel2<ColorOptionIconViewModel>>?,
         selectedColorTypeText: String,
         selectedColorOptionIndex: Int,
     ) {
@@ -251,7 +285,7 @@ class ColorPickerViewModel2Test {
      *   -1 stands for no color option should be selected
      */
     private fun TestScope.assertColorOptionUiState(
-        colorOptions: List<OptionItemViewModel<ColorOptionIconViewModel>>?,
+        colorOptions: List<OptionItemViewModel2<ColorOptionIconViewModel>>?,
         selectedColorOptionIndex: Int,
     ) {
         var foundSelectedColorOption = false
diff --git a/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/KeyguardQuickAffordancePickerViewModel2Test.kt b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/KeyguardQuickAffordancePickerViewModel2Test.kt
index b6f249e5..a7efc45c 100644
--- a/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/KeyguardQuickAffordancePickerViewModel2Test.kt
+++ b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/KeyguardQuickAffordancePickerViewModel2Test.kt
@@ -30,7 +30,7 @@ import com.android.themepicker.R
 import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
 import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
 import com.android.wallpaper.picker.customization.ui.viewmodel.FloatingToolbarTabViewModel
-import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel2
 import com.android.wallpaper.testing.collectLastValue
 import com.google.common.truth.Truth.assertThat
 import kotlinx.coroutines.Dispatchers
@@ -149,7 +149,7 @@ class KeyguardQuickAffordancePickerViewModel2Test {
                         KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START to
                             FakeCustomizationProviderClient.AFFORDANCE_1,
                         KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_END to
-                            FakeCustomizationProviderClient.AFFORDANCE_2
+                            FakeCustomizationProviderClient.AFFORDANCE_2,
                     )
                 )
 
@@ -203,7 +203,7 @@ class KeyguardQuickAffordancePickerViewModel2Test {
                 icon =
                     Icon.Loaded(
                         FakeCustomizationProviderClient.ICON_1,
-                        Text.Loaded("Right shortcut")
+                        Text.Loaded("Right shortcut"),
                     ),
                 text = "Right shortcut",
                 isSelected = true,
@@ -399,7 +399,7 @@ class KeyguardQuickAffordancePickerViewModel2Test {
 
     private fun assertQuickAffordance(
         testScope: TestScope,
-        quickAffordance: OptionItemViewModel<Icon>?,
+        quickAffordance: OptionItemViewModel2<Icon>?,
         key: String,
         icon: Icon,
         text: Text,
diff --git a/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ShapeAndGridPickerViewModelTest.kt b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ShapeGridPickerViewModelTest.kt
similarity index 54%
rename from tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ShapeAndGridPickerViewModelTest.kt
rename to tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ShapeGridPickerViewModelTest.kt
index 02d3ce7a..71ea0d90 100644
--- a/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ShapeAndGridPickerViewModelTest.kt
+++ b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ShapeGridPickerViewModelTest.kt
@@ -21,11 +21,13 @@ import android.content.res.Resources
 import androidx.test.core.app.ApplicationProvider
 import androidx.test.filters.SmallTest
 import com.android.customization.model.ResourceConstants
-import com.android.customization.model.grid.FakeGridOptionsManager
-import com.android.customization.picker.grid.domain.interactor.GridInteractor2
+import com.android.customization.model.grid.FakeShapeGridManager
+import com.android.customization.picker.grid.domain.interactor.ShapeGridInteractor
 import com.android.customization.picker.grid.ui.viewmodel.GridIconViewModel
+import com.android.customization.picker.grid.ui.viewmodel.ShapeIconViewModel
 import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
 import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel2
 import com.android.wallpaper.testing.collectLastValue
 import com.google.common.truth.Truth.assertThat
 import dagger.hilt.android.qualifiers.ApplicationContext
@@ -48,12 +50,12 @@ import org.robolectric.RobolectricTestRunner
 @OptIn(ExperimentalCoroutinesApi::class)
 @SmallTest
 @RunWith(RobolectricTestRunner::class)
-class ShapeAndGridPickerViewModelTest {
+class ShapeGridPickerViewModelTest {
 
     @get:Rule var hiltRule = HiltAndroidRule(this)
     @Inject lateinit var testScope: TestScope
-    @Inject lateinit var gridOptionsManager: FakeGridOptionsManager
-    @Inject lateinit var interactor: GridInteractor2
+    @Inject lateinit var gridOptionsManager: FakeShapeGridManager
+    @Inject lateinit var interactor: ShapeGridInteractor
     @Inject @ApplicationContext lateinit var appContext: Context
 
     private val iconShapePath =
@@ -68,12 +70,12 @@ class ShapeAndGridPickerViewModelTest {
                     )
             )
 
-    private lateinit var underTest: ShapeAndGridPickerViewModel
+    private lateinit var underTest: ShapeGridPickerViewModel
 
     @Before
     fun setUp() {
         hiltRule.inject()
-        underTest = ShapeAndGridPickerViewModel(appContext, interactor, testScope.backgroundScope)
+        underTest = ShapeGridPickerViewModel(appContext, interactor, testScope.backgroundScope)
     }
 
     @After
@@ -81,12 +83,84 @@ class ShapeAndGridPickerViewModelTest {
         Dispatchers.resetMain()
     }
 
+    @Test
+    fun selectedTabUpdates_whenClickOnGridTab() =
+        testScope.runTest {
+            val selectedTab = collectLastValue(underTest.selectedTab)
+            val tabs = collectLastValue(underTest.tabs)
+            val onGridTabClicked = tabs()?.get(1)?.onClick
+
+            assertThat(selectedTab()).isEqualTo(ShapeGridPickerViewModel.Tab.SHAPE)
+
+            onGridTabClicked?.invoke()
+
+            assertThat(selectedTab()).isEqualTo(ShapeGridPickerViewModel.Tab.GRID)
+        }
+
+    @Test
+    fun selectedShapeKey() =
+        testScope.runTest {
+            val selectedShapeKey = collectLastValue(underTest.selectedShapeKey)
+
+            assertThat(selectedShapeKey()).isEqualTo("arch")
+        }
+
+    @Test
+    fun shapeOptions() =
+        testScope.runTest {
+            val shapeOptions = collectLastValue(underTest.shapeOptions)
+
+            for (i in 0 until FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST.size) {
+                val (expectedKey, expectedPath, expectedTitle) =
+                    with(FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST[i]) {
+                        arrayOf(key, path, title)
+                    }
+                assertShapeItem(
+                    optionItem = shapeOptions()?.get(i),
+                    key = FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST[i].key,
+                    payload = ShapeIconViewModel(expectedKey, expectedPath),
+                    text = Text.Loaded(expectedTitle),
+                    isTextUserVisible = true,
+                    isSelected = expectedKey == "arch",
+                    isEnabled = true,
+                )
+            }
+        }
+
+    @Test
+    fun shapeOptions_whenClickOnCircleOption() =
+        testScope.runTest {
+            val shapeOptions = collectLastValue(underTest.shapeOptions)
+            val previewingShapeKey = collectLastValue(underTest.previewingShapeKey)
+            val onCircleOptionClicked =
+                shapeOptions()?.get(4)?.onClicked?.let { collectLastValue(it) }
+            checkNotNull(onCircleOptionClicked)
+
+            onCircleOptionClicked()?.invoke()
+
+            assertThat(previewingShapeKey()).isEqualTo("circle")
+            for (i in 0 until FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST.size) {
+                val expectedKey = FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST[i].key
+                val expectedPath = FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST[i].path
+                val expectedTitle = FakeShapeGridManager.DEFAULT_SHAPE_OPTION_LIST[i].title
+                assertShapeItem(
+                    optionItem = shapeOptions()?.get(i),
+                    key = expectedKey,
+                    payload = ShapeIconViewModel(expectedKey, expectedPath),
+                    text = Text.Loaded(expectedTitle),
+                    isTextUserVisible = true,
+                    isSelected = expectedKey == "circle",
+                    isEnabled = true,
+                )
+            }
+        }
+
     @Test
     fun selectedGridOption() =
         testScope.runTest {
             val selectedGridOption = collectLastValue(underTest.selectedGridOption)
 
-            assertOptionItem(
+            assertGridItem(
                 optionItem = selectedGridOption(),
                 key = "normal",
                 payload = GridIconViewModel(5, 5, iconShapePath),
@@ -101,7 +175,7 @@ class ShapeAndGridPickerViewModelTest {
     fun selectedGridOption_shouldUpdate_afterOnApply() =
         testScope.runTest {
             val selectedGridOption = collectLastValue(underTest.selectedGridOption)
-            val optionItems = collectLastValue(underTest.optionItems)
+            val optionItems = collectLastValue(underTest.gridOptions)
             val onApply = collectLastValue(underTest.onApply)
             val onPracticalOptionClick =
                 optionItems()?.get(1)?.onClicked?.let { collectLastValue(it) }
@@ -110,7 +184,7 @@ class ShapeAndGridPickerViewModelTest {
             onPracticalOptionClick()?.invoke()
             onApply()?.invoke()
 
-            assertOptionItem(
+            assertGridItem(
                 optionItem = selectedGridOption(),
                 key = "practical",
                 payload = GridIconViewModel(4, 5, iconShapePath),
@@ -124,9 +198,9 @@ class ShapeAndGridPickerViewModelTest {
     @Test
     fun optionItems() =
         testScope.runTest {
-            val optionItems = collectLastValue(underTest.optionItems)
+            val optionItems = collectLastValue(underTest.gridOptions)
 
-            assertOptionItem(
+            assertGridItem(
                 optionItem = optionItems()?.get(0),
                 key = "normal",
                 payload = GridIconViewModel(5, 5, iconShapePath),
@@ -135,7 +209,7 @@ class ShapeAndGridPickerViewModelTest {
                 isSelected = true,
                 isEnabled = true,
             )
-            assertOptionItem(
+            assertGridItem(
                 optionItem = optionItems()?.get(1),
                 key = "practical",
                 payload = GridIconViewModel(4, 5, iconShapePath),
@@ -149,14 +223,14 @@ class ShapeAndGridPickerViewModelTest {
     @Test
     fun optionItems_whenClickOnPracticalOption() =
         testScope.runTest {
-            val optionItems = collectLastValue(underTest.optionItems)
+            val optionItems = collectLastValue(underTest.gridOptions)
             val onPracticalOptionClick =
                 optionItems()?.get(1)?.onClicked?.let { collectLastValue(it) }
             checkNotNull(onPracticalOptionClick)
 
             onPracticalOptionClick()?.invoke()
 
-            assertOptionItem(
+            assertGridItem(
                 optionItem = optionItems()?.get(0),
                 key = "normal",
                 payload = GridIconViewModel(5, 5, iconShapePath),
@@ -165,7 +239,7 @@ class ShapeAndGridPickerViewModelTest {
                 isSelected = false,
                 isEnabled = true,
             )
-            assertOptionItem(
+            assertGridItem(
                 optionItem = optionItems()?.get(1),
                 key = "practical",
                 payload = GridIconViewModel(4, 5, iconShapePath),
@@ -176,8 +250,26 @@ class ShapeAndGridPickerViewModelTest {
             )
         }
 
-    private fun assertOptionItem(
-        optionItem: OptionItemViewModel<GridIconViewModel>?,
+    private fun TestScope.assertShapeItem(
+        optionItem: OptionItemViewModel<ShapeIconViewModel>?,
+        key: String,
+        payload: ShapeIconViewModel?,
+        text: Text,
+        isTextUserVisible: Boolean,
+        isSelected: Boolean,
+        isEnabled: Boolean,
+    ) {
+        checkNotNull(optionItem)
+        assertThat(collectLastValue(optionItem.key)()).isEqualTo(key)
+        assertThat(optionItem.text).isEqualTo(text)
+        assertThat(optionItem.payload).isEqualTo(payload)
+        assertThat(optionItem.isTextUserVisible).isEqualTo(isTextUserVisible)
+        assertThat(collectLastValue(optionItem.isSelected)()).isEqualTo(isSelected)
+        assertThat(optionItem.isEnabled).isEqualTo(isEnabled)
+    }
+
+    private fun TestScope.assertGridItem(
+        optionItem: OptionItemViewModel2<GridIconViewModel>?,
         key: String,
         payload: GridIconViewModel?,
         text: Text,
@@ -186,11 +278,11 @@ class ShapeAndGridPickerViewModelTest {
         isEnabled: Boolean,
     ) {
         checkNotNull(optionItem)
-        assertThat(optionItem.key.value).isEqualTo(key)
+        assertThat(collectLastValue(optionItem.key)()).isEqualTo(key)
         assertThat(optionItem.text).isEqualTo(text)
         assertThat(optionItem.payload).isEqualTo(payload)
         assertThat(optionItem.isTextUserVisible).isEqualTo(isTextUserVisible)
-        assertThat(optionItem.isSelected.value).isEqualTo(isSelected)
+        assertThat(collectLastValue(optionItem.isSelected)()).isEqualTo(isSelected)
         assertThat(optionItem.isEnabled).isEqualTo(isEnabled)
     }
 }
diff --git a/themes/res/values-mk/strings.xml b/themes/res/values-mk/strings.xml
index 94d1098b..5426e3b1 100644
--- a/themes/res/values-mk/strings.xml
+++ b/themes/res/values-mk/strings.xml
@@ -24,5 +24,5 @@
     <string name="rainbow_color_name_blue" msgid="3473176664458856892">"Сина"</string>
     <string name="rainbow_color_name_purple" msgid="2704722524588084868">"Виолетова"</string>
     <string name="rainbow_color_name_magenta" msgid="7248703626077785569">"Магента"</string>
-    <string name="monochromatic_name" msgid="2554823570460886176">"Монохроматски"</string>
+    <string name="monochromatic_name" msgid="2554823570460886176">"Еднобојно"</string>
 </resources>
```

