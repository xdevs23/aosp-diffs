```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 6e5844de..f89ff6e3 100755
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -80,6 +80,16 @@
             android:theme="@style/CustomizationTheme.NoActionBar"
             android:exported="false"/>
 
+        <activity
+            tools:node="replace"
+            android:name="com.android.wallpaper.picker.customization.ui.CustomizationPickerActivity2"
+            android:label="@string/app_name"
+            android:relinquishTaskIdentity="true"
+            android:resizeableActivity="false"
+            android:theme="@style/WallpaperTheme"
+            android:configChanges="assetsPaths"
+            android:exported="false"/>
+
         <activity
             tools:node="replace"
             android:name="com.android.wallpaper.picker.PassThroughCustomizationPickerActivity"
diff --git a/res/drawable/color_overflow.xml b/res/drawable/color_overflow.xml
index 1ad29fce..62050fb9 100644
--- a/res/drawable/color_overflow.xml
+++ b/res/drawable/color_overflow.xml
@@ -23,7 +23,7 @@
         <shape
             android:shape="ring"
             android:innerRadius="@dimen/component_color_overflow_small_radius_default"
-            android:thickness="-1dp"
+            android:thickness="-2dp"
             android:useLevel="false">
             <solid android:color="@color/system_outline"/>
         </shape>
diff --git a/res/drawable/customization_option_entry_icon_background.xml b/res/drawable/customization_option_entry_icon_background.xml
index b92fa0e2..3166ea73 100644
--- a/res/drawable/customization_option_entry_icon_background.xml
+++ b/res/drawable/customization_option_entry_icon_background.xml
@@ -16,6 +16,6 @@
 
 <shape xmlns:android="http://schemas.android.com/apk/res/android"
     android:shape="rectangle">
-    <solid android:color="@color/picker_section_icon_background" />
+    <solid android:color="@color/system_surface_container" />
     <corners android:radius="18dp" />
 </shape>
\ No newline at end of file
diff --git a/res/drawable/horizontal_divider_16dp.xml b/res/drawable/horizontal_divider_16dp.xml
new file mode 100644
index 00000000..a1a17df5
--- /dev/null
+++ b/res/drawable/horizontal_divider_16dp.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2021 The Android Open Source Project
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
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <size
+        android:width="16dp"
+        android:height="0dp" />
+</shape>
diff --git a/res/drawable/horizontal_divider_4dp.xml b/res/drawable/horizontal_divider_4dp.xml
new file mode 100644
index 00000000..db343c17
--- /dev/null
+++ b/res/drawable/horizontal_divider_4dp.xml
@@ -0,0 +1,21 @@
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
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <size
+        android:width="4dp"
+        android:height="0dp" />
+</shape>
diff --git a/res/drawable/ic_colors.xml b/res/drawable/ic_colors.xml
new file mode 100644
index 00000000..31bf4d9c
--- /dev/null
+++ b/res/drawable/ic_colors.xml
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
+  ~
+  -->
+
+<vector
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="960"
+    android:viewportHeight="960">
+    <path
+        android:fillColor="@android:color/white"
+        android:pathData="M346,820L100,574Q90,564 85,552Q80,540 80,527Q80,514 85,502Q90,490 100,480L330,251L224,145L286,80L686,480Q696,490 700.5,502Q705,514 705,527Q705,540 700.5,552Q696,564 686,574L440,820Q430,830 418,835Q406,840 393,840Q380,840 368,835Q356,830 346,820ZM393,314L179,528Q179,528 179,528Q179,528 179,528L607,528Q607,528 607,528Q607,528 607,528L393,314ZM792,840Q756,840 731,814.5Q706,789 706,752Q706,725 719.5,701Q733,677 750,654L792,600L836,654Q852,677 866,701Q880,725 880,752Q880,789 854,814.5Q828,840 792,840Z"/>
+</vector>
\ No newline at end of file
diff --git a/res/drawable/ic_open_in_full_24px.xml b/res/drawable/ic_open_in_full_24px.xml
new file mode 100644
index 00000000..48647929
--- /dev/null
+++ b/res/drawable/ic_open_in_full_24px.xml
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
+    <path android:fillColor="@android:color/white" android:pathData="M120,840L120,520L200,520L200,704L704,200L520,200L520,120L840,120L840,440L760,440L760,256L256,760L440,760L440,840L120,840Z"/>
+</vector>
\ No newline at end of file
diff --git a/res/drawable/ic_palette_filled_24px.xml b/res/drawable/ic_palette_filled_24px.xml
new file mode 100644
index 00000000..941335ff
--- /dev/null
+++ b/res/drawable/ic_palette_filled_24px.xml
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
+    <path android:fillColor="@android:color/white" android:pathData="M480,880Q398,880 325,848.5Q252,817 197.5,762.5Q143,708 111.5,635Q80,562 80,480Q80,397 112.5,324Q145,251 200.5,197Q256,143 330,111.5Q404,80 488,80Q568,80 639,107.5Q710,135 763.5,183.5Q817,232 848.5,298.5Q880,365 880,442Q880,557 810,618.5Q740,680 640,680L566,680Q557,680 553.5,685Q550,690 550,696Q550,708 565,730.5Q580,753 580,782Q580,832 552.5,856Q525,880 480,880ZM260,520Q286,520 303,503Q320,486 320,460Q320,434 303,417Q286,400 260,400Q234,400 217,417Q200,434 200,460Q200,486 217,503Q234,520 260,520ZM380,360Q406,360 423,343Q440,326 440,300Q440,274 423,257Q406,240 380,240Q354,240 337,257Q320,274 320,300Q320,326 337,343Q354,360 380,360ZM580,360Q606,360 623,343Q640,326 640,300Q640,274 623,257Q606,240 580,240Q554,240 537,257Q520,274 520,300Q520,326 537,343Q554,360 580,360ZM700,520Q726,520 743,503Q760,486 760,460Q760,434 743,417Q726,400 700,400Q674,400 657,417Q640,434 640,460Q640,486 657,503Q674,520 700,520Z"/>
+</vector>
\ No newline at end of file
diff --git a/res/drawable/ic_style_filled_24px.xml b/res/drawable/ic_style_filled_24px.xml
new file mode 100644
index 00000000..0b9ec324
--- /dev/null
+++ b/res/drawable/ic_style_filled_24px.xml
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
+    <path android:fillColor="@android:color/white" android:pathData="M159,792L125,778Q94,765 83.5,733Q73,701 87,670L159,514L159,792ZM319,880Q286,880 262.5,856.5Q239,833 239,800L239,560L345,854Q348,861 351,867.5Q354,874 359,880L319,880ZM525,876Q493,888 463,873Q433,858 421,826L243,338Q231,306 245,275.5Q259,245 291,234L593,124Q625,112 655,127Q685,142 697,174L875,662Q887,694 873,724.5Q859,755 827,766L525,876ZM439,400Q456,400 467.5,388.5Q479,377 479,360Q479,343 467.5,331.5Q456,320 439,320Q422,320 410.5,331.5Q399,343 399,360Q399,377 410.5,388.5Q422,400 439,400Z"/>
+</vector>
\ No newline at end of file
diff --git a/res/layout/clock_color_list_placeholder.xml b/res/layout/clock_color_list_placeholder.xml
new file mode 100644
index 00000000..d7912c14
--- /dev/null
+++ b/res/layout/clock_color_list_placeholder.xml
@@ -0,0 +1,37 @@
+<?xml version="1.0" encoding="utf-8"?><!--
+     Copyright (C) 2023 The Android Open Source Project
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
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="wrap_content"
+    android:layout_height="wrap_content"
+    android:visibility="invisible"
+    android:orientation="vertical">
+
+    <include
+        layout="@layout/color_option"
+        android:layout_width="@dimen/option_item_size"
+        android:layout_height="@dimen/option_item_size" />
+
+    <View
+        android:layout_width="match_parent"
+        android:layout_height="@dimen/floating_sheet_list_item_vertical_space"/>
+
+    <include
+        layout="@layout/color_option"
+        android:layout_width="@dimen/option_item_size"
+        android:layout_height="@dimen/option_item_size" />
+</LinearLayout>
+
diff --git a/res/layout/clock_host_view.xml b/res/layout/clock_host_view.xml
new file mode 100644
index 00000000..33cca019
--- /dev/null
+++ b/res/layout/clock_host_view.xml
@@ -0,0 +1,23 @@
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
+<com.android.customization.picker.clock.ui.view.ClockHostView2
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/clock_host_view"
+    android:importantForAccessibility="noHideDescendants"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:layout_gravity="center"
+    android:clipChildren="false"/>
\ No newline at end of file
diff --git a/res/layout/clock_style_list_placeholder.xml b/res/layout/clock_style_list_placeholder.xml
new file mode 100644
index 00000000..48ef9a8d
--- /dev/null
+++ b/res/layout/clock_style_list_placeholder.xml
@@ -0,0 +1,37 @@
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
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="wrap_content"
+    android:layout_height="wrap_content"
+    android:visibility="invisible"
+    android:orientation="vertical">
+
+    <include
+        layout="@layout/clock_style_option"
+        android:layout_width="@dimen/floating_sheet_clock_style_option_size"
+        android:layout_height="@dimen/floating_sheet_clock_style_option_size" />
+
+    <View
+        android:layout_width="match_parent"
+        android:layout_height="@dimen/floating_sheet_list_item_vertical_space"/>
+
+    <include
+        layout="@layout/clock_style_option"
+        android:layout_width="@dimen/floating_sheet_clock_style_option_size"
+        android:layout_height="@dimen/floating_sheet_clock_style_option_size" />
+</LinearLayout>
+
diff --git a/res/layout/clock_style_option.xml b/res/layout/clock_style_option.xml
new file mode 100644
index 00000000..fd72e85c
--- /dev/null
+++ b/res/layout/clock_style_option.xml
@@ -0,0 +1,43 @@
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
+<FrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="@dimen/floating_sheet_clock_style_option_size"
+    android:layout_height="@dimen/floating_sheet_clock_style_option_size">
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
+        android:id="@+id/foreground"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:layout_margin="@dimen/floating_sheet_clock_style_thumbnail_margin" />
+</FrameLayout>
+
diff --git a/res/layout/color_section_view.xml b/res/layout/color_section_view.xml
index cfa9be3a..e50a3518 100644
--- a/res/layout/color_section_view.xml
+++ b/res/layout/color_section_view.xml
@@ -37,7 +37,6 @@
         android:layout_width="match_parent"
         android:layout_height="wrap_content"
         android:orientation="horizontal"
-        android:paddingVertical="20dp"
         android:paddingHorizontal="24dp"
         android:weightSum="@integer/color_section_num_columns">
         <include
@@ -53,8 +52,8 @@
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:layout_gravity="center_horizontal"
-        android:layout_marginTop="10dp"
-        android:minHeight="48dp"
+        android:minHeight="24dp"
+        android:paddingVertical="16dp"
         android:gravity="center"
         android:drawablePadding="12dp"
         android:drawableStart="@drawable/ic_nav_color"
diff --git a/res/layout/customization_option_entry_app_shape.xml b/res/layout/customization_option_entry_app_shape.xml
deleted file mode 100644
index 66d9b07f..00000000
--- a/res/layout/customization_option_entry_app_shape.xml
+++ /dev/null
@@ -1,47 +0,0 @@
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
-<androidx.constraintlayout.widget.ConstraintLayout
-    xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:app="http://schemas.android.com/apk/res-auto"
-    android:layout_width="match_parent"
-    android:layout_height="wrap_content"
-    android:paddingHorizontal="@dimen/customization_option_entry_horizontal_padding"
-    android:paddingVertical="@dimen/customization_option_entry_vertical_padding"
-    android:clickable="true">
-
-    <TextView
-        style="@style/SectionTitleTextStyle"
-        android:layout_width="0dp"
-        android:layout_height="wrap_content"
-        android:text="@string/preview_name_shape"
-        android:layout_marginEnd="@dimen/customization_option_entry_text_margin_end"
-        app:layout_constraintStart_toStartOf="parent"
-        app:layout_constraintEnd_toStartOf="@+id/option_entry_app_shape_icon"
-        app:layout_constraintBottom_toBottomOf="parent"
-        app:layout_constraintTop_toTopOf="parent"
-        app:layout_constraintVertical_chainStyle="packed" />
-
-    <FrameLayout
-        android:id="@+id/option_entry_app_shape_icon"
-        android:layout_width="@dimen/customization_option_entry_icon_size"
-        android:layout_height="@dimen/customization_option_entry_icon_size"
-        android:orientation="horizontal"
-        android:background="@drawable/customization_option_entry_icon_background"
-        app:layout_constraintEnd_toEndOf="parent"
-        app:layout_constraintTop_toTopOf="parent"
-        app:layout_constraintBottom_toBottomOf="parent" />
-</androidx.constraintlayout.widget.ConstraintLayout>
diff --git a/res/layout/customization_option_entry_app_grid.xml b/res/layout/customization_option_entry_app_shape_and_grid.xml
similarity index 80%
rename from res/layout/customization_option_entry_app_grid.xml
rename to res/layout/customization_option_entry_app_shape_and_grid.xml
index bc8b8fd8..ea6da465 100644
--- a/res/layout/customization_option_entry_app_grid.xml
+++ b/res/layout/customization_option_entry_app_shape_and_grid.xml
@@ -25,36 +25,42 @@
 
     <TextView
         android:id="@+id/option_entry_app_grid_title"
-        style="@style/SectionTitleTextStyle"
+        style="@style/CustomizationOptionEntryTitleTextStyle"
         android:layout_width="0dp"
         android:layout_height="wrap_content"
         android:text="@string/grid_title"
         android:layout_marginEnd="@dimen/customization_option_entry_text_margin_end"
         app:layout_constraintStart_toStartOf="parent"
-        app:layout_constraintEnd_toStartOf="@+id/option_entry_app_grid_icon"
+        app:layout_constraintEnd_toStartOf="@+id/option_entry_app_grid_icon_container"
         app:layout_constraintBottom_toTopOf="@+id/option_entry_app_grid_description"
         app:layout_constraintTop_toTopOf="parent"
         app:layout_constraintVertical_chainStyle="packed" />
 
     <TextView
         android:id="@+id/option_entry_app_grid_description"
-        style="@style/SectionSubtitleTextStyle"
+        style="@style/CustomizationOptionEntrySubtitleTextStyle"
         android:layout_width="0dp"
         android:layout_height="wrap_content"
         android:layout_marginEnd="@dimen/customization_option_entry_text_margin_end"
-        android:text="4x4"
         app:layout_constraintBottom_toBottomOf="parent"
-        app:layout_constraintEnd_toStartOf="@+id/option_entry_app_grid_icon"
+        app:layout_constraintEnd_toStartOf="@+id/option_entry_app_grid_icon_container"
         app:layout_constraintStart_toStartOf="parent"
         app:layout_constraintTop_toBottomOf="@+id/option_entry_app_grid_title" />
 
     <FrameLayout
-        android:id="@+id/option_entry_app_grid_icon"
+        android:id="@+id/option_entry_app_grid_icon_container"
         android:layout_width="@dimen/customization_option_entry_icon_size"
         android:layout_height="@dimen/customization_option_entry_icon_size"
-        android:orientation="horizontal"
+        android:padding="@dimen/customization_option_entry_icon_padding"
         android:background="@drawable/customization_option_entry_icon_background"
         app:layout_constraintEnd_toEndOf="parent"
         app:layout_constraintTop_toTopOf="parent"
-        app:layout_constraintBottom_toBottomOf="parent" />
+        app:layout_constraintBottom_toBottomOf="parent">
+
+        <ImageView
+            android:id="@+id/option_entry_app_grid_icon"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:contentDescription="@string/grid_preview_card_content_description" />
+    </FrameLayout>
 </androidx.constraintlayout.widget.ConstraintLayout>
diff --git a/res/layout/customization_option_entry_clock.xml b/res/layout/customization_option_entry_clock.xml
index 4c569166..c302965d 100644
--- a/res/layout/customization_option_entry_clock.xml
+++ b/res/layout/customization_option_entry_clock.xml
@@ -24,7 +24,7 @@
     android:clickable="true">
 
     <TextView
-        style="@style/SectionTitleTextStyle"
+        style="@style/CustomizationOptionEntryTitleTextStyle"
         android:layout_width="0dp"
         android:layout_height="wrap_content"
         android:text="@string/clock_title"
diff --git a/res/layout/customization_option_entry_colors.xml b/res/layout/customization_option_entry_colors.xml
index cd32e745..3046173f 100644
--- a/res/layout/customization_option_entry_colors.xml
+++ b/res/layout/customization_option_entry_colors.xml
@@ -24,7 +24,7 @@
     android:clickable="true">
 
     <TextView
-        style="@style/SectionTitleTextStyle"
+        style="@style/CustomizationOptionEntryTitleTextStyle"
         android:layout_width="0dp"
         android:layout_height="wrap_content"
         android:text="@string/color_picker_title"
diff --git a/res/layout/customization_option_entry_keyguard_quick_affordance.xml b/res/layout/customization_option_entry_keyguard_quick_affordance.xml
index aa8152d1..d4d30dd9 100644
--- a/res/layout/customization_option_entry_keyguard_quick_affordance.xml
+++ b/res/layout/customization_option_entry_keyguard_quick_affordance.xml
@@ -26,7 +26,7 @@
 
     <TextView
         android:id="@+id/option_entry_keyguard_quick_affordance_title"
-        style="@style/SectionTitleTextStyle"
+        style="@style/CustomizationOptionEntryTitleTextStyle"
         android:layout_width="0dp"
         android:layout_height="wrap_content"
         android:text="@string/keyguard_quick_affordance_title"
@@ -39,7 +39,7 @@
 
     <TextView
         android:id="@+id/option_entry_keyguard_quick_affordance_description"
-        style="@style/SectionSubtitleTextStyle"
+        style="@style/CustomizationOptionEntrySubtitleTextStyle"
         android:layout_width="0dp"
         android:layout_height="wrap_content"
         android:layout_marginEnd="@dimen/customization_option_entry_text_margin_end"
@@ -56,8 +56,8 @@
         android:layout_height="@dimen/customization_option_entry_icon_size"
         android:orientation="horizontal"
         android:background="@drawable/customization_option_entry_icon_background"
-        android:divider="@drawable/horizontal_divider_14dp"
-        android:layout_gravity="center"
+        android:gravity="center"
+        android:divider="@drawable/horizontal_divider_4dp"
         android:showDividers="middle"
         android:importantForAccessibility="noHideDescendants"
         app:layout_constraintEnd_toEndOf="parent"
@@ -66,15 +66,15 @@
 
         <ImageView
             android:id="@+id/option_entry_keyguard_quick_affordance_icon_1"
-            android:layout_width="wrap_content"
-            android:layout_height="wrap_content"
+            android:layout_width="@dimen/customization_option_entry_shortcut_icon_size"
+            android:layout_height="@dimen/customization_option_entry_shortcut_icon_size"
             android:visibility="gone"
             android:tint="@color/system_on_surface" />
 
         <ImageView
             android:id="@+id/option_entry_keyguard_quick_affordance_icon_2"
-            android:layout_width="wrap_content"
-            android:layout_height="wrap_content"
+            android:layout_width="@dimen/customization_option_entry_shortcut_icon_size"
+            android:layout_height="@dimen/customization_option_entry_shortcut_icon_size"
             android:visibility="gone"
             android:tint="@color/system_on_surface" />
     </LinearLayout>
diff --git a/res/layout/customization_option_entry_more_lock_settings.xml b/res/layout/customization_option_entry_more_lock_settings.xml
index 6ddbe7e6..518af78d 100644
--- a/res/layout/customization_option_entry_more_lock_settings.xml
+++ b/res/layout/customization_option_entry_more_lock_settings.xml
@@ -20,12 +20,12 @@
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:paddingHorizontal="@dimen/customization_option_entry_horizontal_padding"
-    android:paddingVertical="@dimen/customization_option_entry_vertical_padding"
+    android:paddingVertical="@dimen/customization_option_entry_vertical_padding_large"
     android:clickable="true">
 
     <TextView
         android:id="@+id/option_entry_more_lock_settings_title"
-        style="@style/SectionTitleTextStyle"
+        style="@style/CustomizationOptionEntryTitleTextStyle"
         android:layout_width="0dp"
         android:layout_height="wrap_content"
         android:text="@string/more_settings_section_title"
@@ -37,7 +37,7 @@
 
     <TextView
         android:id="@+id/option_entry_more_lock_settings_description"
-        style="@style/SectionSubtitleTextStyle"
+        style="@style/CustomizationOptionEntrySubtitleTextStyle"
         android:layout_width="0dp"
         android:layout_height="wrap_content"
         android:text="@string/more_settings_section_description"
diff --git a/res/layout/customization_option_entry_show_notifications.xml b/res/layout/customization_option_entry_show_notifications.xml
index 2a482e8a..b0671313 100644
--- a/res/layout/customization_option_entry_show_notifications.xml
+++ b/res/layout/customization_option_entry_show_notifications.xml
@@ -21,11 +21,11 @@
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:paddingHorizontal="@dimen/customization_option_entry_horizontal_padding"
-    android:paddingVertical="@dimen/customization_option_entry_vertical_padding"
+    android:paddingVertical="@dimen/customization_option_entry_vertical_padding_large"
     android:clickable="true">
 
     <TextView
-        style="@style/SectionTitleTextStyle"
+        style="@style/CustomizationOptionEntryTitleTextStyle"
         android:layout_width="0dp"
         android:layout_height="wrap_content"
         android:text="@string/show_notifications_on_lock_screen"
diff --git a/res/layout/customization_option_entry_themed_icons.xml b/res/layout/customization_option_entry_themed_icons.xml
index 683fb0ad..06461dcd 100644
--- a/res/layout/customization_option_entry_themed_icons.xml
+++ b/res/layout/customization_option_entry_themed_icons.xml
@@ -21,12 +21,12 @@
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:paddingHorizontal="@dimen/customization_option_entry_horizontal_padding"
-    android:paddingVertical="@dimen/customization_option_entry_vertical_padding"
+    android:paddingVertical="@dimen/customization_option_entry_vertical_padding_large"
     android:clickable="true">
 
     <TextView
         android:id="@+id/option_entry_themed_icons_title"
-        style="@style/SectionTitleTextStyle"
+        style="@style/CustomizationOptionEntryTitleTextStyle"
         android:layout_width="0dp"
         android:layout_height="wrap_content"
         android:text="@string/themed_icon_title"
@@ -39,7 +39,7 @@
 
     <TextView
         android:id="@+id/option_entry_themed_icons_description"
-        style="@style/SectionSubtitleTextStyle"
+        style="@style/CustomizationOptionEntrySubtitleTextStyle"
         android:layout_width="0dp"
         android:layout_height="wrap_content"
         android:layout_marginEnd="@dimen/customization_option_entry_text_margin_end"
diff --git a/res/layout/floating_sheet_clock.xml b/res/layout/floating_sheet_clock.xml
new file mode 100644
index 00000000..9ca8f1a3
--- /dev/null
+++ b/res/layout/floating_sheet_clock.xml
@@ -0,0 +1,187 @@
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
+        android:id="@+id/clock_floating_sheet_content_container"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:paddingVertical="@dimen/floating_sheet_content_vertical_padding"
+        android:background="@drawable/floating_sheet_content_background"
+        android:clipToPadding="false"
+        android:clipChildren="false">
+
+        <FrameLayout
+            android:id="@+id/clock_floating_sheet_style_content"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:clipToPadding="false"
+            android:clipChildren="false">
+
+            <!--
+            This is an invisible placeholder put in place so that the parent keeps its height
+            stable as the RecyclerView updates from 0 items to N items. Keeping it stable allows
+            the layout logic to keep the size of the preview container stable as well, which
+            bodes well for setting up the SurfaceView for remote rendering without changing its
+            size after the content is loaded into the RecyclerView.
+
+            It's critical for any TextViews inside the included layout to have text.
+            -->
+            <include
+                layout="@layout/clock_style_list_placeholder"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:visibility="invisible" />
+
+            <androidx.recyclerview.widget.RecyclerView
+                android:id="@+id/clock_style_list"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:clipChildren="false"
+                android:clipToPadding="false"/>
+        </FrameLayout>
+
+
+        <LinearLayout
+            android:id="@+id/clock_floating_sheet_color_content"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:orientation="vertical"
+            android:clipToPadding="false"
+            android:clipChildren="false">
+
+            <FrameLayout
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:clipToPadding="false"
+                android:clipChildren="false"
+                android:layout_marginBottom="12dp">
+
+                <!--
+                This is an invisible placeholder put in place so that the parent keeps its height
+                stable as the RecyclerView updates from 0 items to N items. Keeping it stable allows
+                the layout logic to keep the size of the preview container stable as well, which
+                bodes well for setting up the SurfaceView for remote rendering without changing its
+                size after the content is loaded into the RecyclerView.
+
+                It's critical for any TextViews inside the included layout to have text.
+                -->
+                <include
+                    layout="@layout/clock_color_list_placeholder"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:visibility="invisible" />
+
+                <androidx.recyclerview.widget.RecyclerView
+                    android:id="@+id/clock_color_list"
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    android:clipChildren="false"
+                    android:clipToPadding="false" />
+            </FrameLayout>
+
+
+            <SeekBar
+                android:id="@+id/clock_color_slider"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:layout_gravity="center_vertical"
+                android:paddingHorizontal="@dimen/floating_sheet_content_horizontal_padding"
+                android:minHeight="@dimen/touch_target_min_height"
+                android:thumb="@null"
+                android:contentDescription="@string/accessibility_clock_slider_description"
+                android:background="@null"
+                android:progressDrawable="@drawable/saturation_progress_drawable"
+                android:splitTrack="false" />
+        </LinearLayout>
+
+        <LinearLayout
+            android:id="@+id/clock_floating_sheet_size_content"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:orientation="horizontal"
+            android:showDividers="middle"
+            android:baselineAligned="false"
+            android:divider="@drawable/horizontal_divider_16dp"
+            android:paddingVertical="@dimen/floating_sheet_content_vertical_padding"
+            android:paddingHorizontal="@dimen/floating_sheet_content_horizontal_padding">
+
+            <LinearLayout
+                android:id="@+id/clock_size_option_dynamic"
+                android:layout_width="0dp"
+                android:layout_height="wrap_content"
+                android:layout_weight="1"
+                android:orientation="vertical"
+                android:gravity="center_horizontal">
+                <ImageView
+                    android:layout_width="@dimen/floating_sheet_clock_size_icon_size"
+                    android:layout_height="@dimen/floating_sheet_clock_size_icon_size"
+                    android:background="#ff00ff"
+                    android:layout_marginBottom="@dimen/floating_sheet_clock_size_icon_margin_bottom" />
+                <TextView
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:textAppearance="@style/SectionTitleTextStyle"
+                    android:gravity="center"
+                    android:text="@string/clock_size_dynamic"/>
+                <TextView
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:textAppearance="@style/SectionSubtitleTextStyle"
+                    android:gravity="center"
+                    android:text="@string/clock_size_dynamic_description"/>
+            </LinearLayout>
+
+            <LinearLayout
+                android:id="@+id/clock_size_option_small"
+                android:layout_width="0dp"
+                android:layout_height="wrap_content"
+                android:layout_weight="1"
+                android:orientation="vertical"
+                android:gravity="center_horizontal">
+                <ImageView
+                    android:layout_width="@dimen/floating_sheet_clock_size_icon_size"
+                    android:layout_height="@dimen/floating_sheet_clock_size_icon_size"
+                    android:background="#ff00ff"
+                    android:layout_marginBottom="@dimen/floating_sheet_clock_size_icon_margin_bottom" />
+                <TextView
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:textAppearance="@style/SectionTitleTextStyle"
+                    android:gravity="center"
+                    android:text="@string/clock_size_small"/>
+                <TextView
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:textAppearance="@style/SectionSubtitleTextStyle"
+                    android:gravity="center"
+                    android:text="@string/clock_size_small_description"/>
+            </LinearLayout>
+        </LinearLayout>
+    </FrameLayout>
+
+    <com.android.wallpaper.picker.customization.ui.view.FloatingToolbar
+        android:id="@+id/floating_toolbar"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_gravity="center_horizontal"
+        android:layout_marginVertical="@dimen/floating_sheet_tab_toolbar_vertical_margin" />
+</LinearLayout>
diff --git a/res/layout/floating_sheet_colors.xml b/res/layout/floating_sheet_colors.xml
new file mode 100644
index 00000000..a22b2644
--- /dev/null
+++ b/res/layout/floating_sheet_colors.xml
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:paddingHorizontal="@dimen/floating_sheet_horizontal_padding"
+    android:orientation="vertical">
+
+    <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:background="@drawable/floating_sheet_content_background"
+        android:paddingVertical="@dimen/floating_sheet_content_vertical_padding"
+        android:orientation="vertical">
+
+        <TextView
+            android:id="@+id/color_type_tab_subhead"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="16dp"
+            android:layout_marginHorizontal="20dp"
+            android:gravity="center"
+            android:text="@string/wallpaper_color_subheader"
+            android:textColor="@color/system_on_surface"
+            android:textSize="12sp" />
+
+        <androidx.recyclerview.widget.RecyclerView
+            android:id="@+id/colors_horizontal_list"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:layout_marginBottom="12dp"
+            android:clipChildren="false"
+            android:clipToPadding="false" />
+
+        <LinearLayout
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:clickable="true"
+            android:gravity="center_vertical"
+            android:layout_marginHorizontal="@dimen/floating_sheet_content_horizontal_padding"
+            android:orientation="horizontal">
+
+            <TextView
+                android:id="@+id/dark_mode_toggle_title"
+                style="@style/SectionTitleTextStyle"
+                android:layout_width="0dp"
+                android:layout_height="wrap_content"
+                android:layout_weight="1"
+                android:text="@string/mode_title" />
+
+            <Switch
+                android:id="@+id/dark_mode_toggle"
+                style="@style/Switch.SettingsLib"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:background="@null"
+                android:clickable="false"
+                android:focusable="false"
+                android:minHeight="0dp" />
+        </LinearLayout>
+    </LinearLayout>
+
+    <com.android.wallpaper.picker.customization.ui.view.FloatingToolbar
+        android:id="@+id/floating_toolbar"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_gravity="center_horizontal"
+        android:layout_marginVertical="@dimen/floating_sheet_tab_toolbar_vertical_margin"  />
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/floating_sheet_shape_and_grid.xml b/res/layout/floating_sheet_shape_and_grid.xml
new file mode 100644
index 00000000..01a7a89e
--- /dev/null
+++ b/res/layout/floating_sheet_shape_and_grid.xml
@@ -0,0 +1,54 @@
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
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:paddingVertical="@dimen/floating_sheet_content_vertical_padding"
+        android:background="@drawable/floating_sheet_content_background"
+        android:clipToPadding="false"
+        android:clipChildren="false">
+
+        <!--
+        This is just an invisible placeholder put in place so that the parent keeps its height
+        stable as the RecyclerView updates from 0 items to N items. Keeping it stable allows the
+        layout logic to keep the size of the preview container stable as well, which bodes well
+        for setting up the SurfaceView for remote rendering without changing its size after the
+        content is loaded into the RecyclerView.
+
+        It's critical for any TextViews inside the included layout to have text.
+        -->
+        <include
+            layout="@layout/grid_option"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:visibility="invisible" />
+
+        <androidx.recyclerview.widget.RecyclerView
+            android:id="@id/options"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_gravity="center_horizontal"
+            android:clipToPadding="false"
+            android:clipChildren="false" />
+    </FrameLayout>
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/floating_sheet_shortcut.xml b/res/layout/floating_sheet_shortcut.xml
new file mode 100644
index 00000000..fb24ef48
--- /dev/null
+++ b/res/layout/floating_sheet_shortcut.xml
@@ -0,0 +1,46 @@
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
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:paddingVertical="@dimen/floating_sheet_content_vertical_padding"
+        android:background="@drawable/floating_sheet_content_background"
+        android:clipToPadding="false"
+        android:clipChildren="false">
+
+        <androidx.recyclerview.widget.RecyclerView
+            android:id="@+id/quick_affordance_horizontal_list"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_gravity="center_horizontal"
+            android:clipChildren="false"
+            android:clipToPadding="false"/>
+    </FrameLayout>
+
+    <com.android.wallpaper.picker.customization.ui.view.FloatingToolbar
+        android:id="@+id/floating_toolbar"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_gravity="center_horizontal"
+        android:layout_marginVertical="@dimen/floating_sheet_tab_toolbar_vertical_margin" />
+</LinearLayout>
diff --git a/res/layout/fragment_color_picker.xml b/res/layout/fragment_color_picker.xml
index d33fb1fb..78701401 100644
--- a/res/layout/fragment_color_picker.xml
+++ b/res/layout/fragment_color_picker.xml
@@ -44,7 +44,8 @@
             android:id="@+id/lock_preview"
             layout="@layout/wallpaper_preview_card"
             android:layout_width="wrap_content"
-            android:layout_height="wrap_content"/>
+            android:layout_height="wrap_content"
+            android:layout_marginEnd="12dp"/>
 
         <include
             android:id="@+id/home_preview"
diff --git a/res/layout/quick_affordance_list_item.xml b/res/layout/quick_affordance_list_item.xml
new file mode 100644
index 00000000..c6b3fd42
--- /dev/null
+++ b/res/layout/quick_affordance_list_item.xml
@@ -0,0 +1,63 @@
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
+    android:orientation="vertical"
+    android:layout_width="64dp"
+    android:layout_height="wrap_content"
+    android:divider="@drawable/vertical_divider_8dp"
+    android:clipChildren="false"
+    android:showDividers="middle">
+
+    <FrameLayout
+        android:layout_width="64dp"
+        android:layout_height="64dp"
+        android:background="@drawable/option_item_background"
+        android:clipChildren="false">
+
+        <ImageView
+            android:id="@id/selection_border"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:background="@drawable/option_item_border"
+            android:alpha="0"
+            android:importantForAccessibility="no" />
+
+        <ImageView
+            android:id="@id/background"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:background="@drawable/option_item_background"
+            android:importantForAccessibility="no" />
+
+        <ImageView
+            android:id="@id/foreground"
+            android:layout_width="@dimen/keyguard_quick_affordance_icon_size"
+            android:layout_height="@dimen/keyguard_quick_affordance_icon_size"
+            android:layout_gravity="center"
+            android:tint="@color/system_on_surface" />
+    </FrameLayout>
+
+    <TextView
+        android:id="@id/text"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:gravity="center_horizontal"
+        android:textColor="@color/system_on_surface"
+        android:lines="2"
+        android:hyphenationFrequency="normal"
+        android:ellipsize="end" />
+</LinearLayout>
\ No newline at end of file
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index adaa3b99..0f14a04f 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Horlosiekleur en -grootte"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Horlosiekleur en -grootte"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Styl"</string>
     <string name="clock_color" msgid="8081608867289156163">"Kleur"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Rooi"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Oranje"</string>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index a33a13e0..2eaab87f 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"የClock ቀለም እና መጠን"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"የClock ቀለም እና መጠን"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>፣ <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"ቅጥ"</string>
     <string name="clock_color" msgid="8081608867289156163">"ቀለም"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"ቀይ"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"ብርቱካናማ"</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 536dc3bf..6056defd 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"لون الساعة وحجمها"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"لون الساعة وحجمها"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g> و<xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"النمط"</string>
     <string name="clock_color" msgid="8081608867289156163">"اللون"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"أحمر"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"برتقالي"</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index 2d8b5299..e4418d57 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"ঘড়ীৰ ৰং আৰু আকাৰ"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"ঘড়ীৰ ৰং আৰু আকাৰ"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"শৈলী"</string>
     <string name="clock_color" msgid="8081608867289156163">"ৰং"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"ৰঙা"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"কমলা"</string>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index b6d1f556..76c2725c 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Saat rəngi və ölçü"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Saat rəngi və ölçüsü"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Üslub"</string>
     <string name="clock_color" msgid="8081608867289156163">"Rəng"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Qırmızı"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Narıncı"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 6b6293e6..59ef2592 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Boja i veličina sata"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Boja i veličina sata"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stil"</string>
     <string name="clock_color" msgid="8081608867289156163">"Boja"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Crvena"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Narandžasta"</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 6b2b4748..1005abf8 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Колер/памер гадз-ка"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Колер і памер гадзінніка"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Стыль"</string>
     <string name="clock_color" msgid="8081608867289156163">"Колер"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Чырвоны"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Аранжавы"</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 051cd354..f64a0181 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Часовн.: Цвят и размер"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Часовн.: Цвят и размер"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Стил"</string>
     <string name="clock_color" msgid="8081608867289156163">"Цвят"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"червено"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"оранжево"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index e419aac7..8ef1f377 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"ঘড়ির রঙ &amp; সাইজ"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"ঘড়ির রঙ ও সাইজ"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"স্টাইল"</string>
     <string name="clock_color" msgid="8081608867289156163">"রঙ"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"লাল"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"কমলা"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index e25a69af..9bd52e2c 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Boja i veličina sata"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Boja i veličina sata"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stil"</string>
     <string name="clock_color" msgid="8081608867289156163">"Boja"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Crvena"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Narandžasta"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index b37ddd83..94ec7587 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Color i mida rellotge"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Color i mida del rellotge"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Estil"</string>
     <string name="clock_color" msgid="8081608867289156163">"Color"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Vermell"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Taronja"</string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index ffe69a4d..aa174004 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Barva a velikost"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Barva a velikost"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Styl"</string>
     <string name="clock_color" msgid="8081608867289156163">"Barva"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Červená"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Oranžová"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index d99847b9..42a87602 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Urets farve og str."</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Urets farve og størrelse"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stil"</string>
     <string name="clock_color" msgid="8081608867289156163">"Farve"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Rød"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Orange"</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index be98c62e..07f05dc2 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Uhr-Farbe &amp; -Größe"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Uhr-Farbe und -Größe"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stil"</string>
     <string name="clock_color" msgid="8081608867289156163">"Farbe"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Rot"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Orange"</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index d9ce549f..a4eb1b94 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Χρώμα/μέγεθ. ρολογ."</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Χρώμα και μέγεθος"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Στιλ"</string>
     <string name="clock_color" msgid="8081608867289156163">"Χρώμα"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Κόκκινο"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Πορτοκαλί"</string>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index 33de28b9..d280efdf 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Clock colour &amp; size"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Clock colour and size"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Style"</string>
     <string name="clock_color" msgid="8081608867289156163">"Colour"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Red"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Orange"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index b256398f..dbfbe94a 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Clock color &amp; size"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Clock color &amp; size"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Style"</string>
     <string name="clock_color" msgid="8081608867289156163">"Color"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Red"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Orange"</string>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index 33de28b9..d280efdf 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Clock colour &amp; size"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Clock colour and size"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Style"</string>
     <string name="clock_color" msgid="8081608867289156163">"Colour"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Red"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Orange"</string>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index 33de28b9..d280efdf 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Clock colour &amp; size"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Clock colour and size"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Style"</string>
     <string name="clock_color" msgid="8081608867289156163">"Colour"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Red"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Orange"</string>
diff --git a/res/values-en-rXC/strings.xml b/res/values-en-rXC/strings.xml
index b6f48d35..07b31463 100644
--- a/res/values-en-rXC/strings.xml
+++ b/res/values-en-rXC/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‏‎‎‎‎‎‎‎‏‏‏‏‏‏‏‏‎‏‏‏‏‎‎‎‏‏‏‎‏‏‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‎‎‏‏‎‎‎‏‎‎‏‎‏‏‎‏‏‎‎‎‏‎‏‎‎‏‎‏‎‏‏‏‏‎Clock color &amp; size‎‏‎‎‏‎"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‏‎‎‎‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‎‎‎‏‏‎‎‏‎‏‏‏‎‏‎‎‎‎‎‎‎‏‏‎‎‎‎‏‏‎‏‎‎‏‎‎‎‎‏‏‎‎‏‎‎‏‏‏‏‏‎‏‏‎‎‏‏‎‏‏‏‎Clock color &amp; size‎‏‎‎‏‎"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‏‎‎‎‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‎‏‏‎‏‏‎‏‎‎‏‎‎‏‏‏‏‏‏‎‎‎‎‎‏‎‎‎‎‏‎‏‏‎‎‎‎‏‏‏‏‏‏‏‎‎‏‏‎‎‏‏‎‏‎‎‏‎‎‎‎‏‎‎‏‎‎‏‏‎<xliff:g id="ID_1">%1$s</xliff:g>‎‏‎‎‏‏‏‎, ‎‏‎‎‏‏‎<xliff:g id="ID_2">%2$s</xliff:g>‎‏‎‎‏‏‏‎‎‏‎‎‏‎"</string>
+    <string name="clock_style" msgid="6847711178193804308">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‏‎‎‎‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‎‏‏‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‎‏‎‏‎‎‎‎‏‎‎‏‎‎‏‎‏‏‎‎‏‎‏‏‎‏‏‎‏‎‎‏‏‏‎‎‎‎‎‏‎‏‎‎‎Style‎‏‎‎‏‎"</string>
     <string name="clock_color" msgid="8081608867289156163">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‏‎‎‎‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‎‎‎‎‏‎‎‏‏‏‏‎‏‎‎‏‎‎‎‏‏‏‎‎‏‎‎‏‎‏‎‏‎‎‎‏‏‎‏‎‏‎‏‏‎‎‏‎‏‎‎‏‎‎‎‎‏‏‎Color‎‏‎‎‏‎"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‏‎‎‎‎‎‎‎‏‏‏‏‏‏‏‏‏‎‏‏‎‏‎‏‎‏‎‏‎‏‏‎‏‏‎‏‏‏‏‎‏‎‏‏‏‎‎‎‎‎‏‏‏‎‎‎‎‏‎‏‎‎‏‎‏‏‎‏‎‎‏‎‏‏‏‏‎‎‏‎‎Red‎‏‎‎‏‎"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‏‎‎‎‎‎‎‎‏‏‏‏‏‏‏‏‏‎‏‏‏‎‎‏‏‏‏‏‎‎‏‏‎‏‏‏‎‎‎‎‏‎‏‏‎‏‎‎‏‏‎‎‎‎‎‏‎‏‏‎‏‏‏‎‏‏‏‎‎‎‏‏‎‏‎‏‏‏‎‎‎Orange‎‏‎‎‏‎"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 318e8448..25546011 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Color, tamaño de reloj"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Reloj: color, tamaño"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Estilo"</string>
     <string name="clock_color" msgid="8081608867289156163">"Color"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Rojo"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Naranja"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index ecb4e04c..753d3a75 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Color/tamaño (reloj)"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Color y tamaño del reloj"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Estilo"</string>
     <string name="clock_color" msgid="8081608867289156163">"Color"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Rojo"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Naranja"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 28fefd47..3275eed7 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Kella värv/suurus"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Kella värv ja suurus"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stiil"</string>
     <string name="clock_color" msgid="8081608867289156163">"Värv"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Punane"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Oranž"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 8c2b406a..1599ae17 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Erlojuaren kolorea eta tamaina"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Erlojuaren kolorea eta tamaina"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Estiloa"</string>
     <string name="clock_color" msgid="8081608867289156163">"Kolorea"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Gorria"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Laranja"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index fa81da6e..de42d861 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"اندازه و رنگ ساعت"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"اندازه و رنگ ساعت"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>، <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"سبک"</string>
     <string name="clock_color" msgid="8081608867289156163">"رنگ"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"قرمز"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"نارنجی"</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index feaadd33..fb506490 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Kellon väri ja koko"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Kellon väri ja koko"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Tyyli"</string>
     <string name="clock_color" msgid="8081608867289156163">"Väri"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Punainen"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Oranssi"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 1d2e3e5c..250eba4c 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Couleur/taille"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Couleur/taille (horloge)"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Style"</string>
     <string name="clock_color" msgid="8081608867289156163">"Couleur"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Rouge"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Orange"</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index 66eaa2e2..b191e3b9 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Taille et couleur de l\'Horloge"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Taille et couleur de l\'horloge"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Style"</string>
     <string name="clock_color" msgid="8081608867289156163">"Couleur"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Rouge"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Orange"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index beeface3..f35bc564 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Tamaño/cor (Reloxo)"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Tamaño/cor do reloxo"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Estilo"</string>
     <string name="clock_color" msgid="8081608867289156163">"Cor"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Vermello"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Laranxa"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index e396e914..2102a73c 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"ઘડિયાળનો રંગ અને કદ"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"ઘડિયાળનો રંગ અને કદ"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"શૈલી"</string>
     <string name="clock_color" msgid="8081608867289156163">"રંગ"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"લાલ"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"નારંગી"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 059eabb2..1457fc5b 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"वॉच का रंग और साइज़"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"घड़ी का रंग और साइज़"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"स्टाइल"</string>
     <string name="clock_color" msgid="8081608867289156163">"रंग"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"लाल"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"नारंगी"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 69591f7b..4a7b0bda 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Boja i veličina sata"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Boja i veličina sata"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stil"</string>
     <string name="clock_color" msgid="8081608867289156163">"Boja"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Crvena"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Narančasta"</string>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index ed4e10cd..84e2d809 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Óra színe és mérete"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Óra színe és mérete"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stílus"</string>
     <string name="clock_color" msgid="8081608867289156163">"Szín"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Piros"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Narancssárga"</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 0d75ee7e..86cbf9dd 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Գույնը և չափսը"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Գույնը և չափսը"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Ոճ"</string>
     <string name="clock_color" msgid="8081608867289156163">"Գույն"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Կարմիր"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Նարնջագույն"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 04ab4095..60672e57 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Warna &amp; ukuran jam"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Warna &amp; ukuran jam"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Gaya"</string>
     <string name="clock_color" msgid="8081608867289156163">"Warna"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Merah"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Oranye"</string>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index abad9eca..b4fc13e2 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Klukkustærð og litur"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Klukkustærð og litur"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stíll"</string>
     <string name="clock_color" msgid="8081608867289156163">"Litur"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Rauður"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Appelsínugulur"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 6dffc0bd..37e8b759 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Colore/dim. orologio"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Colore e dimensioni orologio"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stile"</string>
     <string name="clock_color" msgid="8081608867289156163">"Colore"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Rosso"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Arancione"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 8c5ad6eb..b8e1c5fd 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"הצבע והגודל של השעון"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"הצבע והגודל של השעון"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"סגנון"</string>
     <string name="clock_color" msgid="8081608867289156163">"צבע"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"אדום"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"כתום"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 4b079b85..6f6e0452 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"時計の色とサイズ"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"時計の色とサイズ"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>、<xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"スタイル"</string>
     <string name="clock_color" msgid="8081608867289156163">"色"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"赤"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"オレンジ"</string>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index c52a9446..4a82186d 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"საათის ფერი და ზომა"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"საათის ფერი &amp; amp; ზომა"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"სტილი"</string>
     <string name="clock_color" msgid="8081608867289156163">"ფერი"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"წითელი"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"ნარინჯისფერი"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 9389d036..b57b8da1 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Сағат түсі, көлемі"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Сағаттың түсі, өлшемі"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Стиль"</string>
     <string name="clock_color" msgid="8081608867289156163">"Түс"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Қызыл"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Қызғылт сары"</string>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index 19762ef8..fbd03b9e 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -17,7 +17,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="1647136562008520313">"ផ្ទាំងរូបភាព និងរចនាប័ទ្ម"</string>
+    <string name="app_name" msgid="1647136562008520313">"ផ្ទាំងរូបភាព និងរចនាបថ"</string>
     <string name="theme_title" msgid="2144932106319405101">"រចនាប័ទ្ម"</string>
     <string name="clock_title" msgid="1974314575211361352">"នាឡិកាផ្ទាល់ខ្លួន"</string>
     <string name="clock_description" msgid="3563839327378948">"ជ្រើសរើសនាឡិកាផ្ទាល់ខ្លួន"</string>
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"ពណ៌ និងទំហំនាឡិកា"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"ពណ៌ និងទំហំនាឡិកា"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"រចនាបថ"</string>
     <string name="clock_color" msgid="8081608867289156163">"ពណ៌"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"ក្រហម"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"ទឹកក្រូច"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 70e229f8..32d0e487 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"ಗಡಿಯಾರದ ಬಣ್ಣ, ಗಾತ್ರ"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"ಗಡಿಯಾರದ ಬಣ್ಣ, ಗಾತ್ರ"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"ಶೈಲಿ"</string>
     <string name="clock_color" msgid="8081608867289156163">"ಬಣ್ಣ"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"ಕೆಂಪು"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"ಕಿತ್ತಳೆ"</string>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index 3582ae67..8e869d05 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"시계 색상 및 크기"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"시계 색상 및 크기"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"스타일"</string>
     <string name="clock_color" msgid="8081608867289156163">"색상"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"빨간색"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"주황색"</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index cf574252..fd070ffd 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Сааттын түсү, өлчөмү"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Сааттын түсү, өлчөмү"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Стиль"</string>
     <string name="clock_color" msgid="8081608867289156163">"Түс"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"КЫЗЫЛ"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"КЫЗГЫЛТ САРЫ"</string>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index b33cebc9..8e44623e 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"ສີ ແລະ ຂະໜາດໂມງ"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"ສີ ແລະ ຂະໜາດໂມງ"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"ຮູບແບບ"</string>
     <string name="clock_color" msgid="8081608867289156163">"ສີ"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"ສີແດງ"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"ສີສົ້ມ"</string>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index d2a21d74..e0c8ffdd 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Laikr. spalva, dyd."</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Laikr. spalva ir dydis"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stilius"</string>
     <string name="clock_color" msgid="8081608867289156163">"Spalva"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Raudona"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Oranžinė"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index bc8f1558..68a6d4b2 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Pulksteņa krāsa/lielums"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Pulksteņa krāsa/lielums"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stils"</string>
     <string name="clock_color" msgid="8081608867289156163">"Krāsa"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Sarkana"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Oranža"</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index b3b8ab2b..cd9690b3 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Боја и големина"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Боја и големина"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Стил"</string>
     <string name="clock_color" msgid="8081608867289156163">"Боја"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Црвена"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Портокалова"</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 685f8f68..191c0661 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"ക്ലോക്കിന്റെ നിറം, വലുപ്പം"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"ക്ലോക്കിന്റെ നിറം, വലുപ്പം"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"സ്റ്റൈൽ"</string>
     <string name="clock_color" msgid="8081608867289156163">"നിറം"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"ചുവപ്പ്"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"ഓറഞ്ച്"</string>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 003a69d1..2353a9d5 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Цагны өнгө, хэмжээ"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Цагны өнгө, хэмжээ"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Загвар"</string>
     <string name="clock_color" msgid="8081608867289156163">"Өнгө"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Улаан"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Улбар шар"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 84197832..c5315142 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Clock चा रंग व आकार"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"घड्याळाचा रंग व आकार"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"शैली"</string>
     <string name="clock_color" msgid="8081608867289156163">"रंग"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"लाल"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"नारिंगी"</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 2757dc84..fb6a237f 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Warna &amp; saiz jam"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Warna &amp; saiz jam"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Gaya"</string>
     <string name="clock_color" msgid="8081608867289156163">"Warna"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Merah"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Jingga"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index bc71e174..3be7e0bd 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"နာရီအရောင်၊ အရွယ်"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"နာရီအရောင်နှင့်အရွယ်"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>၊ <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"ပုံစံ"</string>
     <string name="clock_color" msgid="8081608867289156163">"အရောင်"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"အနီရောင်"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"လိမ္မော်ရောင်"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index 20023dd3..f4cd48db 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Farge og størrelse"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Farge og størrelse"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stil"</string>
     <string name="clock_color" msgid="8081608867289156163">"Farge"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Rød"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Oransje"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 9a941ccc..9669e016 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"घडीको रङ र आकार"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"घडीको रङ र आकार"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"शैली"</string>
     <string name="clock_color" msgid="8081608867289156163">"रङ"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"रातो"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"सुन्तले"</string>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index 8c22a355..f8962ba8 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Kleur en grootte van klok"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Kleur en formaat van klok"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stijl"</string>
     <string name="clock_color" msgid="8081608867289156163">"Kleur"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Rood"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Oranje"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index c9f5ea62..d66efeed 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"ଘଣ୍ଟାର ରଙ୍ଗ ଓ ସାଇଜ"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"ଘଣ୍ଟାର ରଙ୍ଗ ଓ ଆକାର"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"ଷ୍ଟାଇଲ"</string>
     <string name="clock_color" msgid="8081608867289156163">"ରଙ୍ଗ"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"ଲାଲ"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"କମଳା"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 926dce18..66d127b3 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"ਘੜੀ ਦਾ ਰੰਗ ਅਤੇ ਆਕਾਰ"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"ਘੜੀ ਦਾ ਰੰਗ ਅਤੇ ਆਕਾਰ"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"ਸਟਾਈਲ"</string>
     <string name="clock_color" msgid="8081608867289156163">"ਰੰਗ"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"ਲਾਲ"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"ਸੰਤਰੀ"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index d91f0263..ea5e4892 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Kolor i rozmiar zegara"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Kolor i rozmiar zegara"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Styl"</string>
     <string name="clock_color" msgid="8081608867289156163">"Kolor"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Czerwony"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Pomarańczowy"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index c912c07e..57c397c7 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Cor e tamanho do relógio"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Cor e tamanho do relógio"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Estilo"</string>
     <string name="clock_color" msgid="8081608867289156163">"Cor"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Vermelho"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Laranja"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index ed833d52..4f4dc1ef 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Cor/tam. do relógio"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Cor e tamanho do relógio"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Estilo"</string>
     <string name="clock_color" msgid="8081608867289156163">"Cor"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Vermelho"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Laranja"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 44bd489f..9e873223 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Culoare / mărime"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Culoare / dimensiune"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stil"</string>
     <string name="clock_color" msgid="8081608867289156163">"Culoare"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Roșu"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Portocaliu"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index bc17db79..61ac300a 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Цвет и размер часов"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Цвет и размер часов"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>."</string>
+    <string name="clock_style" msgid="6847711178193804308">"Стиль"</string>
     <string name="clock_color" msgid="8081608867289156163">"Цвет"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Красный"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Оранжевый"</string>
@@ -37,7 +38,7 @@
     <string name="clock_color_gray" msgid="9221530636948859231">"Серый"</string>
     <string name="clock_color_teal" msgid="7499223425741344251">"Темно-бирюзовый"</string>
     <string name="clock_size" msgid="5028923902364418263">"Размер"</string>
-    <string name="clock_size_dynamic" msgid="1023930312455061642">"Динамичный"</string>
+    <string name="clock_size_dynamic" msgid="1023930312455061642">"Динамический"</string>
     <string name="clock_size_dynamic_description" msgid="2776620745774561662">"Размер часов меняется в зависимости от контента на заблокированном экране"</string>
     <string name="clock_size_large" msgid="3143248715744138979">"Большой"</string>
     <string name="clock_size_small" msgid="2280449912094164133">"Маленький"</string>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index 35cec6aa..84ad1f8b 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"ඔරලෝසු වර්ණය සහ තරම"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"ඔරලෝසු වර්ණය සහ තරම"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"විලාසය"</string>
     <string name="clock_color" msgid="8081608867289156163">"වර්ණය"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"රතු"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"තැඹිලි"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index 5f26d2f0..adc03233 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Farba a veľkosť"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Farba a veľkosť"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Štýl"</string>
     <string name="clock_color" msgid="8081608867289156163">"Farba"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Červená"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Oranžová"</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index c8fb3ce7..b53b7429 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Barva, velikost ure"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Barva, velikost ure"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Slog"</string>
     <string name="clock_color" msgid="8081608867289156163">"Barva"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Rdeča"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Oranžna"</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 19677fa3..b7f21116 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Ora: Ngjyrë/madhësi"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Ora: Ngjyra/madhësia"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stili"</string>
     <string name="clock_color" msgid="8081608867289156163">"Ngjyra"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"E kuqe"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Portokalli"</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 4040536e..6824fd93 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Боја и величина сата"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Боја и величина сата"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Стил"</string>
     <string name="clock_color" msgid="8081608867289156163">"Боја"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Црвена"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Наранџаста"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index 8749e960..4326de91 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Klockstorlek/färg"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Klockstorlek/färg"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stil"</string>
     <string name="clock_color" msgid="8081608867289156163">"Färg"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Röd"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Orange"</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 55f75fc8..40a426ba 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Rangi na ukubwa wa saa"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Rangi na ukubwa wa saa"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Muundo"</string>
     <string name="clock_color" msgid="8081608867289156163">"Rangi"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Nyekundu"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Rangi ya chungwa"</string>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 75609c7c..a3427842 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"கடிகார நிறம் &amp; அளவு"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"கடிகார நிறம் &amp; அளவு"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"ஸ்டைல்"</string>
     <string name="clock_color" msgid="8081608867289156163">"நிறம்"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"சிவப்பு"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"ஆரஞ்சு"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index c3189527..d292914b 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"గడియారం రంగు &amp; సైజు"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"గడియారం రంగు &amp; సైజు"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"స్టయిల్"</string>
     <string name="clock_color" msgid="8081608867289156163">"రంగు"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"ఎరుపు రంగు"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"నారింజ రంగు"</string>
@@ -104,7 +105,7 @@
     <string name="accessibility_custom_shape_title" msgid="7708408259374643129">"అనుకూల ఆకారం"</string>
     <string name="accessibility_custom_name_title" msgid="5494460518085463262">"అనుకూల స్టయిల్ పేరు"</string>
     <string name="accessibility_clock_slider_description" msgid="8374135133110681332">"రంగు తీవ్రత"</string>
-    <string name="mode_title" msgid="2394873501427436055">"ముదురు రంగు రూపం"</string>
+    <string name="mode_title" msgid="2394873501427436055">"డార్క్ థీమ్‌"</string>
     <string name="mode_disabled_msg" msgid="9196245518435936512">"బ్యాటరీ సేవర్ కారణంగా తాత్కాలికంగా డిజేబుల్‌ చేయబడింది"</string>
     <string name="mode_changed" msgid="2243581369395418584">"థీమ్ మార్చబడింది"</string>
     <string name="themed_icon_title" msgid="7312460430471956558">"రూపానికి తగిన చిహ్నాలు"</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index b92fb2d3..b0e70460 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"สีและขนาดนาฬิกา"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"สีและขนาดนาฬิกา"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"รูปแบบ"</string>
     <string name="clock_color" msgid="8081608867289156163">"สี"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"แดง"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"ส้ม"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 3daa94a2..00778e5e 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Kulay, laki ng clock"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Kulay, laki ng clock"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Istilo"</string>
     <string name="clock_color" msgid="8081608867289156163">"Kulay"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Pula"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Orange"</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 3cfce23d..7852cdd5 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Saat rengi ve boyutu"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Saat rengi ve boyutu"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Stil"</string>
     <string name="clock_color" msgid="8081608867289156163">"Renk"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Kırmızı"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Turuncu"</string>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index f44ff5b3..486a51d3 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Колір і розмір год."</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Колір і розмір годинника"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Стиль"</string>
     <string name="clock_color" msgid="8081608867289156163">"Колір"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Червоний"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Оранжевий"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 18eb802e..019de1f7 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"گھڑی کا رنگ و سائز"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"گھڑی کا رنگ اور سائز"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>، <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"اسٹائل"</string>
     <string name="clock_color" msgid="8081608867289156163">"رنگ"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"سرخ"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"نارنجی"</string>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index 1295959e..4f3cb774 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Soat rangi va hajmi"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Soat rangi va hajmi"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Uslub"</string>
     <string name="clock_color" msgid="8081608867289156163">"Rang"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Qizil"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Toʻq sariq"</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 9c4bba6e..f775f3db 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Màu và kích thước đồng hồ"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Màu và kích thước đồng hồ"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Kiểu"</string>
     <string name="clock_color" msgid="8081608867289156163">"Màu"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Đỏ"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Cam"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 3bf17dd3..9502ceff 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"时钟颜色和尺寸"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"时钟颜色和尺寸"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>、<xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"样式"</string>
     <string name="clock_color" msgid="8081608867289156163">"颜色"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"红色"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"橙色"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 59cbd740..6ebc6da1 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"時鐘顏色及大小"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"時鐘顏色及大小"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>，<xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"樣式"</string>
     <string name="clock_color" msgid="8081608867289156163">"顏色"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"紅色"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"橙色"</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 3143f29f..cf0a4ed5 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"時鐘顏色與大小"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"時鐘顏色與大小"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_2">%2$s</xliff:g>，<xliff:g id="ID_1">%1$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"樣式"</string>
     <string name="clock_color" msgid="8081608867289156163">"顏色"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"紅色"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"橘色"</string>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index d1569db8..4056a719 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -26,6 +26,7 @@
     <string name="clock_settings_title" msgid="2050906379377120431">"Umbala wewashi nosayizi"</string>
     <string name="clock_color_and_size_title" msgid="7146791234905111351">"Umbala wewashi nosayizi"</string>
     <string name="clock_color_and_size_description" msgid="6578061553012886817">"<xliff:g id="ID_1">%1$s</xliff:g>, <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="clock_style" msgid="6847711178193804308">"Isitayela"</string>
     <string name="clock_color" msgid="8081608867289156163">"Umbala"</string>
     <string name="clock_color_red" msgid="3843504214807597810">"Okubomvu"</string>
     <string name="clock_color_orange" msgid="4175805201144275804">"Okuwolintshi"</string>
diff --git a/res/values/dimens.xml b/res/values/dimens.xml
index 2f9daaec..6a923d9a 100644
--- a/res/values/dimens.xml
+++ b/res/values/dimens.xml
@@ -53,6 +53,9 @@
     <dimen name="theme_option_font_sample_width">52dp</dimen>
     <dimen name="theme_option_sample_margin">10dp</dimen>
 
+    <!-- Dimensions for the color options -->
+    <dimen name="color_options_selected_option_height">102dp</dimen>
+
     <!-- Note, using dp instead of sp as this text is more like a "snapshot" of the font -->
     <dimen name="theme_option_font_text_size">20dp</dimen>
     <dimen name="theme_option_font_min_text_size">15dp</dimen>
@@ -175,4 +178,16 @@
     <!-- Notification item dimensions -->
     <dimen name="notification_section_title_padding">8dp</dimen>
 
+    <!-- Floating sheet dimensions -->
+    <dimen name="floating_sheet_content_vertical_padding">20dp</dimen>
+    <dimen name="floating_sheet_content_horizontal_padding">20dp</dimen>
+    <dimen name="floating_sheet_horizontal_padding">16dp</dimen>
+    <dimen name="floating_sheet_tab_toolbar_vertical_margin">8dp</dimen>
+    <dimen name="floating_sheet_list_item_horizontal_space">4dp</dimen>
+    <dimen name="floating_sheet_list_item_vertical_space">4dp</dimen>
+    <dimen name="floating_sheet_clock_size_icon_size">80dp</dimen>
+    <dimen name="floating_sheet_clock_size_icon_margin_bottom">8dp</dimen>
+    <dimen name="floating_sheet_clock_style_option_size">82dp</dimen>
+    <dimen name="floating_sheet_clock_style_thumbnail_margin">12dp</dimen>
+    <dimen name="customization_option_entry_shortcut_icon_size">20dp</dimen>
 </resources>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 271a74c6..aee23939 100755
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -45,6 +45,9 @@
     <!-- Description of a section of the customization picker where the user can configure clock color and size, e.g. Violet, small. [CHAR LIMIT=NONE] -->
     <string name="clock_color_and_size_description"><xliff:g name="color">%1$s</xliff:g>, <xliff:g name="size">%2$s</xliff:g></string>
 
+    <!-- Title of a tab to change the clock style. [CHAR LIMIT=15] -->
+    <string name="clock_style">Style</string>
+
     <!-- Title of a tab to change the clock color. [CHAR LIMIT=15] -->
     <string name="clock_color">Color</string>
 
diff --git a/res/values/styles.xml b/res/values/styles.xml
index c2710f64..fc2fd8a7 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -130,6 +130,18 @@
         <item name="android:lineHeight">16sp</item>
     </style>
 
+    <style name="CustomizationOptionEntryTitleTextStyle">
+        <item name="android:fontFamily">@*android:string/config_headlineFontFamily</item>
+        <item name="android:textColor">@color/system_on_surface</item>
+        <item name="android:textSize">20sp</item>
+    </style>
+
+    <style name="CustomizationOptionEntrySubtitleTextStyle">
+        <item name="android:fontFamily">@*android:string/config_bodyFontFamily</item>
+        <item name="android:textColor">@color/system_on_surface_variant</item>
+        <item name="android:textSize">14sp</item>
+    </style>
+
     <style name="BetaTagTextStyle" parent="SectionTitleTextStyle">
         <item name="android:textSize">12sp</item>
         <item name="android:lineHeight">15dp</item>
diff --git a/src/com/android/customization/model/grid/DefaultGridOptionsManager.kt b/src/com/android/customization/model/grid/DefaultGridOptionsManager.kt
new file mode 100644
index 00000000..bc862fd8
--- /dev/null
+++ b/src/com/android/customization/model/grid/DefaultGridOptionsManager.kt
@@ -0,0 +1,94 @@
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
+class DefaultGridOptionsManager
+@Inject
+constructor(
+    @ApplicationContext private val context: Context,
+    @BackgroundDispatcher private val bgDispatcher: CoroutineDispatcher,
+) : GridOptionsManager2 {
+
+    private val authorityMetadataKey: String =
+        context.getString(R.string.grid_control_metadata_name)
+    private val previewUtils: PreviewUtils = PreviewUtils(context, authorityMetadataKey)
+
+    override suspend fun isGridOptionAvailable(): Boolean {
+        return previewUtils.supportsPreview() && (getGridOptions()?.size ?: 0) > 1
+    }
+
+    override suspend fun getGridOptions(): List<GridOptionModel>? =
+        withContext(bgDispatcher) {
+            context.contentResolver
+                .query(previewUtils.getUri(LIST_OPTIONS), null, null, null, null)
+                ?.use { cursor ->
+                    buildList {
+                        while (cursor.moveToNext()) {
+                            val rows = cursor.getInt(cursor.getColumnIndex(COL_ROWS))
+                            val cols = cursor.getInt(cursor.getColumnIndex(COL_COLS))
+                            add(
+                                GridOptionModel(
+                                    key = cursor.getString(cursor.getColumnIndex(COL_NAME)),
+                                    title =
+                                        context.getString(
+                                            com.android.themepicker.R.string.grid_title_pattern,
+                                            cols,
+                                            rows
+                                        ),
+                                    isCurrent =
+                                        cursor
+                                            .getString(cursor.getColumnIndex(COL_IS_DEFAULT))
+                                            .toBoolean(),
+                                    rows = rows,
+                                    cols = cols,
+                                )
+                            )
+                        }
+                    }
+                }
+        }
+
+    override fun applyGridOption(gridName: String): Int {
+        return context.contentResolver.update(
+            previewUtils.getUri(DEFAULT_GRID),
+            ContentValues().apply { put("name", gridName) },
+            null,
+            null,
+        )
+    }
+
+    companion object {
+        const val LIST_OPTIONS: String = "list_options"
+        const val DEFAULT_GRID: String = "default_grid"
+        const val COL_NAME: String = "name"
+        const val COL_ROWS: String = "rows"
+        const val COL_COLS: String = "cols"
+        const val COL_IS_DEFAULT: String = "is_default"
+    }
+}
diff --git a/src/com/android/customization/model/grid/GridOptionModel.kt b/src/com/android/customization/model/grid/GridOptionModel.kt
new file mode 100644
index 00000000..3e10a013
--- /dev/null
+++ b/src/com/android/customization/model/grid/GridOptionModel.kt
@@ -0,0 +1,25 @@
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
+data class GridOptionModel(
+    val key: String,
+    val title: String,
+    val isCurrent: Boolean,
+    val rows: Int,
+    val cols: Int,
+)
diff --git a/src/com/android/customization/model/grid/GridOptionsManager2.kt b/src/com/android/customization/model/grid/GridOptionsManager2.kt
new file mode 100644
index 00000000..ce8500ab
--- /dev/null
+++ b/src/com/android/customization/model/grid/GridOptionsManager2.kt
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
+package com.android.customization.model.grid
+
+interface GridOptionsManager2 {
+
+    suspend fun isGridOptionAvailable(): Boolean
+
+    suspend fun getGridOptions(): List<GridOptionModel>?
+
+    fun applyGridOption(gridName: String): Int
+}
diff --git a/src/com/android/customization/module/CustomizationInjector.kt b/src/com/android/customization/module/CustomizationInjector.kt
index d7615989..ca42ef37 100644
--- a/src/com/android/customization/module/CustomizationInjector.kt
+++ b/src/com/android/customization/module/CustomizationInjector.kt
@@ -22,10 +22,8 @@ import com.android.customization.picker.clock.domain.interactor.ClockPickerInter
 import com.android.customization.picker.clock.ui.view.ClockViewFactory
 import com.android.customization.picker.clock.ui.viewmodel.ClockCarouselViewModel
 import com.android.customization.picker.clock.ui.viewmodel.ClockSettingsViewModel
-import com.android.customization.picker.color.domain.interactor.ColorPickerInteractor
 import com.android.customization.picker.color.ui.viewmodel.ColorPickerViewModel
 import com.android.customization.picker.quickaffordance.domain.interactor.KeyguardQuickAffordancePickerInteractor
-import com.android.systemui.shared.clocks.ClockRegistry
 import com.android.wallpaper.module.Injector
 import com.android.wallpaper.picker.customization.data.repository.WallpaperColorsRepository
 
@@ -36,19 +34,7 @@ interface CustomizationInjector : Injector {
         context: Context,
     ): KeyguardQuickAffordancePickerInteractor
 
-    fun getClockRegistry(context: Context): ClockRegistry?
-
-    fun getClockPickerInteractor(context: Context): ClockPickerInteractor
-
-    fun getColorPickerInteractor(
-        context: Context,
-        wallpaperColorsRepository: WallpaperColorsRepository,
-    ): ColorPickerInteractor
-
-    fun getColorPickerViewModelFactory(
-        context: Context,
-        wallpaperColorsRepository: WallpaperColorsRepository,
-    ): ColorPickerViewModel.Factory
+    fun getColorPickerViewModelFactory(context: Context): ColorPickerViewModel.Factory
 
     fun getClockCarouselViewModelFactory(
         interactor: ClockPickerInteractor,
diff --git a/src/com/android/customization/module/DefaultCustomizationPreferences.kt b/src/com/android/customization/module/DefaultCustomizationPreferences.kt
index 49fd1a94..0ef4a1d2 100644
--- a/src/com/android/customization/module/DefaultCustomizationPreferences.kt
+++ b/src/com/android/customization/module/DefaultCustomizationPreferences.kt
@@ -17,8 +17,14 @@ package com.android.customization.module
 
 import android.content.Context
 import com.android.wallpaper.module.DefaultWallpaperPreferences
-
-open class DefaultCustomizationPreferences(context: Context) :
+import dagger.hilt.android.qualifiers.ApplicationContext
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+open class DefaultCustomizationPreferences
+@Inject
+constructor(@ApplicationContext context: Context) :
     DefaultWallpaperPreferences(context), CustomizationPreferences {
 
     override fun getSerializedCustomThemes(): String? {
diff --git a/src/com/android/customization/module/DefaultCustomizationSections.java b/src/com/android/customization/module/DefaultCustomizationSections.java
index 33cb6200..e9b7b2d5 100644
--- a/src/com/android/customization/module/DefaultCustomizationSections.java
+++ b/src/com/android/customization/module/DefaultCustomizationSections.java
@@ -19,6 +19,7 @@ import com.android.customization.picker.clock.ui.viewmodel.ClockCarouselViewMode
 import com.android.customization.picker.color.domain.interactor.ColorPickerInteractor;
 import com.android.customization.picker.color.ui.section.ColorSectionController;
 import com.android.customization.picker.color.ui.viewmodel.ColorPickerViewModel;
+import com.android.customization.picker.grid.domain.interactor.GridInteractor;
 import com.android.customization.picker.grid.ui.section.GridSectionController;
 import com.android.customization.picker.notifications.ui.section.NotificationSectionController;
 import com.android.customization.picker.notifications.ui.viewmodel.NotificationSectionViewModel;
@@ -61,6 +62,7 @@ public final class DefaultCustomizationSections implements CustomizationSections
     private final ClockViewFactory mClockViewFactory;
     private final ThemedIconSnapshotRestorer mThemedIconSnapshotRestorer;
     private final ThemedIconInteractor mThemedIconInteractor;
+    private final GridInteractor mGridInteractor;
     private final ColorPickerInteractor mColorPickerInteractor;
     private final ThemesUserEventLogger mThemesUserEventLogger;
 
@@ -75,6 +77,7 @@ public final class DefaultCustomizationSections implements CustomizationSections
             ClockViewFactory clockViewFactory,
             ThemedIconSnapshotRestorer themedIconSnapshotRestorer,
             ThemedIconInteractor themedIconInteractor,
+            GridInteractor gridInteractor,
             ColorPickerInteractor colorPickerInteractor,
             ThemesUserEventLogger themesUserEventLogger) {
         mColorPickerViewModelFactory = colorPickerViewModelFactory;
@@ -86,6 +89,7 @@ public final class DefaultCustomizationSections implements CustomizationSections
         mClockViewFactory = clockViewFactory;
         mThemedIconSnapshotRestorer = themedIconSnapshotRestorer;
         mThemedIconInteractor = themedIconInteractor;
+        mGridInteractor = gridInteractor;
         mColorPickerInteractor = colorPickerInteractor;
         mThemesUserEventLogger = themesUserEventLogger;
         mColorContrastSectionViewModelFactory = colorContrastSectionViewModelFactory;
@@ -125,6 +129,7 @@ public final class DefaultCustomizationSections implements CustomizationSections
                         sectionNavigationController,
                         wallpaperInteractor,
                         mThemedIconInteractor,
+                        mGridInteractor,
                         mColorPickerInteractor,
                         wallpaperManager,
                         isTwoPaneAndSmallWidth,
@@ -139,6 +144,7 @@ public final class DefaultCustomizationSections implements CustomizationSections
                                 wallpaperPreviewNavigator,
                                 wallpaperInteractor,
                                 mThemedIconInteractor,
+                                mGridInteractor,
                                 mColorPickerInteractor,
                                 wallpaperManager,
                                 isTwoPaneAndSmallWidth,
@@ -210,8 +216,7 @@ public final class DefaultCustomizationSections implements CustomizationSections
                         new GridSectionController(
                                 GridOptionsManager.getInstance(activity),
                                 sectionNavigationController,
-                                lifecycleOwner,
-                                /* isRevampedUiEnabled= */ true));
+                                lifecycleOwner));
                 break;
         }
 
diff --git a/src/com/android/customization/module/ThemePickerInjector.kt b/src/com/android/customization/module/ThemePickerInjector.kt
index da259506..b634df01 100644
--- a/src/com/android/customization/module/ThemePickerInjector.kt
+++ b/src/com/android/customization/module/ThemePickerInjector.kt
@@ -22,7 +22,6 @@ import android.content.Context
 import android.content.Intent
 import android.content.res.Resources
 import android.net.Uri
-import android.text.TextUtils
 import androidx.activity.ComponentActivity
 import androidx.lifecycle.DefaultLifecycleObserver
 import androidx.lifecycle.LifecycleOwner
@@ -39,15 +38,12 @@ import com.android.customization.model.themedicon.data.repository.ThemeIconRepos
 import com.android.customization.model.themedicon.domain.interactor.ThemedIconInteractor
 import com.android.customization.model.themedicon.domain.interactor.ThemedIconSnapshotRestorer
 import com.android.customization.module.logging.ThemesUserEventLogger
-import com.android.customization.picker.clock.data.repository.ClockPickerRepositoryImpl
-import com.android.customization.picker.clock.data.repository.ClockRegistryProvider
 import com.android.customization.picker.clock.domain.interactor.ClockPickerInteractor
 import com.android.customization.picker.clock.domain.interactor.ClockPickerSnapshotRestorer
 import com.android.customization.picker.clock.ui.view.ClockViewFactory
-import com.android.customization.picker.clock.ui.view.ClockViewFactoryImpl
+import com.android.customization.picker.clock.ui.view.ThemePickerClockViewFactory
 import com.android.customization.picker.clock.ui.viewmodel.ClockCarouselViewModel
 import com.android.customization.picker.clock.ui.viewmodel.ClockSettingsViewModel
-import com.android.customization.picker.color.data.repository.ColorPickerRepositoryImpl
 import com.android.customization.picker.color.domain.interactor.ColorPickerInteractor
 import com.android.customization.picker.color.domain.interactor.ColorPickerSnapshotRestorer
 import com.android.customization.picker.color.ui.viewmodel.ColorPickerViewModel
@@ -57,29 +53,25 @@ import com.android.customization.picker.grid.domain.interactor.GridSnapshotResto
 import com.android.customization.picker.grid.ui.viewmodel.GridScreenViewModel
 import com.android.customization.picker.notifications.domain.interactor.NotificationsSnapshotRestorer
 import com.android.customization.picker.notifications.ui.viewmodel.NotificationSectionViewModel
-import com.android.customization.picker.quickaffordance.data.repository.KeyguardQuickAffordancePickerRepository
 import com.android.customization.picker.quickaffordance.domain.interactor.KeyguardQuickAffordancePickerInteractor
 import com.android.customization.picker.quickaffordance.domain.interactor.KeyguardQuickAffordanceSnapshotRestorer
 import com.android.customization.picker.quickaffordance.ui.viewmodel.KeyguardQuickAffordancePickerViewModel
 import com.android.customization.picker.settings.ui.viewmodel.ColorContrastSectionViewModel
 import com.android.systemui.shared.clocks.ClockRegistry
-import com.android.systemui.shared.customization.data.content.CustomizationProviderClient
-import com.android.systemui.shared.customization.data.content.CustomizationProviderClientImpl
 import com.android.systemui.shared.notifications.data.repository.NotificationSettingsRepository
 import com.android.systemui.shared.notifications.domain.interactor.NotificationSettingsInteractor
+import com.android.systemui.shared.settings.data.repository.SecureSettingsRepository
+import com.android.systemui.shared.settings.data.repository.SystemSettingsRepository
 import com.android.wallpaper.config.BaseFlags
 import com.android.wallpaper.module.CustomizationSections
 import com.android.wallpaper.module.FragmentFactory
 import com.android.wallpaper.module.WallpaperPicker2Injector
 import com.android.wallpaper.picker.CustomizationPickerActivity
-import com.android.wallpaper.picker.customization.data.content.WallpaperClientImpl
 import com.android.wallpaper.picker.customization.data.repository.WallpaperColorsRepository
-import com.android.wallpaper.picker.customization.data.repository.WallpaperRepository
 import com.android.wallpaper.picker.customization.domain.interactor.WallpaperInteractor
 import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import com.android.wallpaper.picker.di.modules.MainDispatcher
 import com.android.wallpaper.picker.undo.domain.interactor.SnapshotRestorer
-import com.android.wallpaper.util.ScreenSizeCalculator
 import dagger.Lazy
 import javax.inject.Inject
 import javax.inject.Singleton
@@ -91,31 +83,20 @@ open class ThemePickerInjector
 @Inject
 constructor(
     @MainDispatcher private val mainScope: CoroutineScope,
-    @MainDispatcher private val mainDispatcher: CoroutineDispatcher,
     @BackgroundDispatcher private val bgScope: CoroutineScope,
     @BackgroundDispatcher private val bgDispatcher: CoroutineDispatcher,
-) : WallpaperPicker2Injector(mainScope, bgDispatcher), CustomizationInjector {
+) : WallpaperPicker2Injector(mainScope), CustomizationInjector {
     private var customizationSections: CustomizationSections? = null
-    private var wallpaperInteractor: WallpaperInteractor? = null
-    private var keyguardQuickAffordancePickerInteractor: KeyguardQuickAffordancePickerInteractor? =
-        null
     private var keyguardQuickAffordancePickerViewModelFactory:
         KeyguardQuickAffordancePickerViewModel.Factory? =
         null
-    private var customizationProviderClient: CustomizationProviderClient? = null
     private var fragmentFactory: FragmentFactory? = null
-    private var keyguardQuickAffordanceSnapshotRestorer: KeyguardQuickAffordanceSnapshotRestorer? =
-        null
     private var notificationsSnapshotRestorer: NotificationsSnapshotRestorer? = null
-    private var clockPickerInteractor: ClockPickerInteractor? = null
     private var clockCarouselViewModelFactory: ClockCarouselViewModel.Factory? = null
     private var clockViewFactory: ClockViewFactory? = null
-    private var clockPickerSnapshotRestorer: ClockPickerSnapshotRestorer? = null
     private var notificationSettingsInteractor: NotificationSettingsInteractor? = null
     private var notificationSectionViewModelFactory: NotificationSectionViewModel.Factory? = null
-    private var colorPickerInteractor: ColorPickerInteractor? = null
     private var colorPickerViewModelFactory: ColorPickerViewModel.Factory? = null
-    private var colorPickerSnapshotRestorer: ColorPickerSnapshotRestorer? = null
     private var colorCustomizationManager: ColorCustomizationManager? = null
     private var darkModeSnapshotRestorer: DarkModeSnapshotRestorer? = null
     private var themedIconSnapshotRestorer: ThemedIconSnapshotRestorer? = null
@@ -124,12 +105,24 @@ constructor(
     private var gridInteractor: GridInteractor? = null
     private var gridSnapshotRestorer: GridSnapshotRestorer? = null
     private var gridScreenViewModelFactory: GridScreenViewModel.Factory? = null
-    private var clockRegistryProvider: ClockRegistryProvider? = null
 
     // Injected objects, sorted by type
     @Inject
     lateinit var colorContrastSectionViewModelFactory: Lazy<ColorContrastSectionViewModel.Factory>
+    @Inject
+    lateinit var keyguardQuickAffordancePickerInteractor:
+        Lazy<KeyguardQuickAffordancePickerInteractor>
+    @Inject
+    lateinit var keyguardQuickAffordanceSnapshotRestorer:
+        Lazy<KeyguardQuickAffordanceSnapshotRestorer>
     @Inject lateinit var themesUserEventLogger: Lazy<ThemesUserEventLogger>
+    @Inject lateinit var colorPickerInteractor: Lazy<ColorPickerInteractor>
+    @Inject lateinit var colorPickerSnapshotRestorer: Lazy<ColorPickerSnapshotRestorer>
+    @Inject lateinit var clockRegistry: Lazy<ClockRegistry>
+    @Inject lateinit var secureSettingsRepository: Lazy<SecureSettingsRepository>
+    @Inject lateinit var systemSettingsRepository: Lazy<SystemSettingsRepository>
+    @Inject lateinit var clockPickerInteractor: Lazy<ClockPickerInteractor>
+    @Inject lateinit var clockPickerSnapshotRestorer: Lazy<ClockPickerSnapshotRestorer>
 
     override fun getCustomizationSections(activity: ComponentActivity): CustomizationSections {
         val appContext = activity.applicationContext
@@ -137,23 +130,21 @@ constructor(
         val resources = activity.resources
         return customizationSections
             ?: DefaultCustomizationSections(
-                    getColorPickerViewModelFactory(
-                        context = appContext,
-                        wallpaperColorsRepository = getWallpaperColorsRepository(),
-                    ),
+                    getColorPickerViewModelFactory(appContext),
                     getKeyguardQuickAffordancePickerViewModelFactory(appContext),
                     colorContrastSectionViewModelFactory.get(),
                     getNotificationSectionViewModelFactory(appContext),
                     getFlags(),
                     getClockCarouselViewModelFactory(
-                        interactor = getClockPickerInteractor(appContext),
+                        interactor = clockPickerInteractor.get(),
                         clockViewFactory = clockViewFactory,
                         resources = resources,
                     ),
                     clockViewFactory,
                     getThemedIconSnapshotRestorer(appContext),
                     getThemedIconInteractor(),
-                    getColorPickerInteractor(appContext, getWallpaperColorsRepository()),
+                    getGridInteractor(appContext),
+                    colorPickerInteractor.get(),
                     getUserEventLogger(),
                 )
                 .also { customizationSections = it }
@@ -180,12 +171,10 @@ constructor(
         return fragmentFactory ?: ThemePickerFragmentFactory().also { fragmentFactory }
     }
 
-    override fun getSnapshotRestorers(
-        context: Context,
-    ): Map<Int, SnapshotRestorer> {
+    override fun getSnapshotRestorers(context: Context): Map<Int, SnapshotRestorer> {
         return super<WallpaperPicker2Injector>.getSnapshotRestorers(context).toMutableMap().apply {
             this[KEY_QUICK_AFFORDANCE_SNAPSHOT_RESTORER] =
-                getKeyguardQuickAffordanceSnapshotRestorer(context)
+                keyguardQuickAffordanceSnapshotRestorer.get()
             // TODO(b/285047815): Enable after adding wallpaper id for default static wallpaper
             if (getFlags().isWallpaperRestorerEnabled()) {
                 this[KEY_WALLPAPER_SNAPSHOT_RESTORER] = getWallpaperSnapshotRestorer(context)
@@ -194,9 +183,8 @@ constructor(
             this[KEY_DARK_MODE_SNAPSHOT_RESTORER] = getDarkModeSnapshotRestorer(context)
             this[KEY_THEMED_ICON_SNAPSHOT_RESTORER] = getThemedIconSnapshotRestorer(context)
             this[KEY_APP_GRID_SNAPSHOT_RESTORER] = getGridSnapshotRestorer(context)
-            this[KEY_COLOR_PICKER_SNAPSHOT_RESTORER] =
-                getColorPickerSnapshotRestorer(context, getWallpaperColorsRepository())
-            this[KEY_CLOCKS_SNAPSHOT_RESTORER] = getClockPickerSnapshotRestorer(context)
+            this[KEY_COLOR_PICKER_SNAPSHOT_RESTORER] = colorPickerSnapshotRestorer.get()
+            this[KEY_CLOCKS_SNAPSHOT_RESTORER] = clockPickerSnapshotRestorer.get()
         }
     }
 
@@ -205,42 +193,13 @@ constructor(
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
-                            client =
-                                WallpaperClientImpl(
-                                    context = appContext,
-                                    wallpaperManager = WallpaperManager.getInstance(appContext),
-                                    wallpaperPreferences = getPreferences(appContext),
-                                ),
-                            wallpaperPreferences = getPreferences(context = appContext),
-                            backgroundDispatcher = bgDispatcher,
-                        ),
-                    shouldHandleReload = {
-                        TextUtils.equals(
-                            getColorCustomizationManager(appContext).currentColorSource,
-                            COLOR_SOURCE_PRESET,
-                        )
-                    }
-                )
-                .also { wallpaperInteractor = it }
+        return injectedWallpaperInteractor.get()
     }
 
     override fun getKeyguardQuickAffordancePickerInteractor(
         context: Context
     ): KeyguardQuickAffordancePickerInteractor {
-        return keyguardQuickAffordancePickerInteractor
-            ?: getKeyguardQuickAffordancePickerInteractorImpl(context).also {
-                keyguardQuickAffordancePickerInteractor = it
-            }
+        return keyguardQuickAffordancePickerInteractor.get()
     }
 
     fun getKeyguardQuickAffordancePickerViewModelFactory(
@@ -257,41 +216,8 @@ constructor(
                 .also { keyguardQuickAffordancePickerViewModelFactory = it }
     }
 
-    private fun getKeyguardQuickAffordancePickerInteractorImpl(
-        context: Context
-    ): KeyguardQuickAffordancePickerInteractor {
-        val client = getKeyguardQuickAffordancePickerProviderClient(context)
-        val appContext = context.applicationContext
-        return KeyguardQuickAffordancePickerInteractor(
-            KeyguardQuickAffordancePickerRepository(client, getApplicationCoroutineScope()),
-            client
-        ) {
-            getKeyguardQuickAffordanceSnapshotRestorer(appContext)
-        }
-    }
-
-    private fun getKeyguardQuickAffordancePickerProviderClient(
-        context: Context
-    ): CustomizationProviderClient {
-        return customizationProviderClient
-            ?: CustomizationProviderClientImpl(context.applicationContext, bgDispatcher).also {
-                customizationProviderClient = it
-            }
-    }
-
-    private fun getKeyguardQuickAffordanceSnapshotRestorer(
-        context: Context
-    ): KeyguardQuickAffordanceSnapshotRestorer {
-        return keyguardQuickAffordanceSnapshotRestorer
-            ?: KeyguardQuickAffordanceSnapshotRestorer(
-                    getKeyguardQuickAffordancePickerInteractor(context),
-                    getKeyguardQuickAffordancePickerProviderClient(context)
-                )
-                .also { keyguardQuickAffordanceSnapshotRestorer = it }
-    }
-
     fun getNotificationSectionViewModelFactory(
-        context: Context,
+        context: Context
     ): NotificationSectionViewModel.Factory {
         return notificationSectionViewModelFactory
             ?: NotificationSectionViewModel.Factory(
@@ -301,17 +227,16 @@ constructor(
                 .also { notificationSectionViewModelFactory = it }
     }
 
-    private fun getNotificationsInteractor(
-        context: Context,
-    ): NotificationSettingsInteractor {
+    private fun getNotificationsInteractor(context: Context): NotificationSettingsInteractor {
         return notificationSettingsInteractor
             ?: NotificationSettingsInteractor(
                     repository =
                         NotificationSettingsRepository(
-                            scope = getApplicationCoroutineScope(),
+                            backgroundScope = bgScope,
                             backgroundDispatcher = bgDispatcher,
-                            secureSettingsRepository = getSecureSettingsRepository(context),
-                        ),
+                            secureSettingsRepository = secureSettingsRepository.get(),
+                            systemSettingsRepository = systemSettingsRepository.get(),
+                        )
                 )
                 .also { notificationSettingsInteractor = it }
     }
@@ -319,45 +244,12 @@ constructor(
     private fun getNotificationsSnapshotRestorer(context: Context): NotificationsSnapshotRestorer {
         return notificationsSnapshotRestorer
             ?: NotificationsSnapshotRestorer(
-                    interactor =
-                        getNotificationsInteractor(
-                            context = context,
-                        ),
+                    interactor = getNotificationsInteractor(context = context),
                     backgroundScope = bgScope,
                 )
                 .also { notificationsSnapshotRestorer = it }
     }
 
-    override fun getClockRegistry(context: Context): ClockRegistry {
-        return (clockRegistryProvider
-                ?: ClockRegistryProvider(
-                        context = context.applicationContext,
-                        coroutineScope = getApplicationCoroutineScope(),
-                        mainDispatcher = mainDispatcher,
-                        backgroundDispatcher = bgDispatcher,
-                    )
-                    .also { clockRegistryProvider = it })
-            .get()
-    }
-
-    override fun getClockPickerInteractor(
-        context: Context,
-    ): ClockPickerInteractor {
-        val appContext = context.applicationContext
-        return clockPickerInteractor
-            ?: ClockPickerInteractor(
-                    repository =
-                        ClockPickerRepositoryImpl(
-                            secureSettingsRepository = getSecureSettingsRepository(appContext),
-                            registry = getClockRegistry(appContext),
-                            scope = getApplicationCoroutineScope(),
-                            mainDispatcher = mainDispatcher,
-                        ),
-                    snapshotRestorer = { getClockPickerSnapshotRestorer(appContext) },
-                )
-                .also { clockPickerInteractor = it }
-    }
-
     override fun getClockCarouselViewModelFactory(
         interactor: ClockPickerInteractor,
         clockViewFactory: ClockViewFactory,
@@ -376,12 +268,10 @@ constructor(
 
     override fun getClockViewFactory(activity: ComponentActivity): ClockViewFactory {
         return clockViewFactory
-            ?: ClockViewFactoryImpl(
-                    activity.applicationContext,
-                    ScreenSizeCalculator.getInstance()
-                        .getScreenSize(activity.windowManager.defaultDisplay),
+            ?: ThemePickerClockViewFactory(
+                    activity,
                     WallpaperManager.getInstance(activity.applicationContext),
-                    getClockRegistry(activity.applicationContext),
+                    clockRegistry.get(),
                 )
                 .also {
                     clockViewFactory = it
@@ -397,65 +287,23 @@ constructor(
                 }
     }
 
-    private fun getClockPickerSnapshotRestorer(
-        context: Context,
-    ): ClockPickerSnapshotRestorer {
-        return clockPickerSnapshotRestorer
-            ?: ClockPickerSnapshotRestorer(getClockPickerInteractor(context)).also {
-                clockPickerSnapshotRestorer = it
-            }
-    }
-
     override fun getWallpaperColorResources(
         wallpaperColors: WallpaperColors,
-        context: Context
-    ): WallpaperColorResources {
-        return ThemedWallpaperColorResources(wallpaperColors, getSecureSettingsRepository(context))
-    }
-
-    override fun getColorPickerInteractor(
         context: Context,
-        wallpaperColorsRepository: WallpaperColorsRepository,
-    ): ColorPickerInteractor {
-        val appContext = context.applicationContext
-        return colorPickerInteractor
-            ?: ColorPickerInteractor(
-                    repository =
-                        ColorPickerRepositoryImpl(
-                            wallpaperColorsRepository,
-                            getColorCustomizationManager(appContext)
-                        ),
-                    snapshotRestorer = {
-                        getColorPickerSnapshotRestorer(appContext, wallpaperColorsRepository)
-                    }
-                )
-                .also { colorPickerInteractor = it }
+    ): WallpaperColorResources {
+        return ThemedWallpaperColorResources(wallpaperColors, secureSettingsRepository.get())
     }
 
-    override fun getColorPickerViewModelFactory(
-        context: Context,
-        wallpaperColorsRepository: WallpaperColorsRepository,
-    ): ColorPickerViewModel.Factory {
+    override fun getColorPickerViewModelFactory(context: Context): ColorPickerViewModel.Factory {
         return colorPickerViewModelFactory
             ?: ColorPickerViewModel.Factory(
                     context.applicationContext,
-                    getColorPickerInteractor(context, wallpaperColorsRepository),
+                    colorPickerInteractor.get(),
                     getUserEventLogger(),
                 )
                 .also { colorPickerViewModelFactory = it }
     }
 
-    private fun getColorPickerSnapshotRestorer(
-        context: Context,
-        wallpaperColorsRepository: WallpaperColorsRepository,
-    ): ColorPickerSnapshotRestorer {
-        return colorPickerSnapshotRestorer
-            ?: ColorPickerSnapshotRestorer(
-                    getColorPickerInteractor(context, wallpaperColorsRepository)
-                )
-                .also { colorPickerSnapshotRestorer = it }
-    }
-
     private fun getColorCustomizationManager(context: Context): ColorCustomizationManager {
         return colorCustomizationManager
             ?: ColorCustomizationManager.getInstance(context, OverlayManagerCompat(context)).also {
@@ -463,9 +311,7 @@ constructor(
             }
     }
 
-    fun getDarkModeSnapshotRestorer(
-        context: Context,
-    ): DarkModeSnapshotRestorer {
+    fun getDarkModeSnapshotRestorer(context: Context): DarkModeSnapshotRestorer {
         val appContext = context.applicationContext
         return darkModeSnapshotRestorer
             ?: DarkModeSnapshotRestorer(
@@ -476,9 +322,7 @@ constructor(
                 .also { darkModeSnapshotRestorer = it }
     }
 
-    protected fun getThemedIconSnapshotRestorer(
-        context: Context,
-    ): ThemedIconSnapshotRestorer {
+    protected fun getThemedIconSnapshotRestorer(context: Context): ThemedIconSnapshotRestorer {
         val optionProvider = ThemedIconSwitchProvider.getInstance(context)
         return themedIconSnapshotRestorer
             ?: ThemedIconSnapshotRestorer(
@@ -493,10 +337,9 @@ constructor(
 
     protected fun getThemedIconInteractor(): ThemedIconInteractor {
         return themedIconInteractor
-            ?: ThemedIconInteractor(
-                    repository = ThemeIconRepository(),
-                )
-                .also { themedIconInteractor = it }
+            ?: ThemedIconInteractor(repository = ThemeIconRepository()).also {
+                themedIconInteractor = it
+            }
     }
 
     override fun getClockSettingsViewModelFactory(
@@ -507,11 +350,8 @@ constructor(
         return clockSettingsViewModelFactory
             ?: ClockSettingsViewModel.Factory(
                     context.applicationContext,
-                    getClockPickerInteractor(context),
-                    getColorPickerInteractor(
-                        context,
-                        wallpaperColorsRepository,
-                    ),
+                    clockPickerInteractor.get(),
+                    colorPickerInteractor.get(),
                     getUserEventLogger(),
                 ) { clockId ->
                     clockId?.let { clockViewFactory.getController(clockId).config.isReactiveToTone }
@@ -520,9 +360,7 @@ constructor(
                 .also { clockSettingsViewModelFactory = it }
     }
 
-    fun getGridScreenViewModelFactory(
-        context: Context,
-    ): ViewModelProvider.Factory {
+    fun getGridScreenViewModelFactory(context: Context): ViewModelProvider.Factory {
         return gridScreenViewModelFactory
             ?: GridScreenViewModel.Factory(
                     context = context,
@@ -549,14 +387,11 @@ constructor(
                 .also { gridInteractor = it }
     }
 
-    private fun getGridSnapshotRestorer(
-        context: Context,
-    ): GridSnapshotRestorer {
+    private fun getGridSnapshotRestorer(context: Context): GridSnapshotRestorer {
         return gridSnapshotRestorer
-            ?: GridSnapshotRestorer(
-                    interactor = getGridInteractor(context),
-                )
-                .also { gridSnapshotRestorer = it }
+            ?: GridSnapshotRestorer(interactor = getGridInteractor(context)).also {
+                gridSnapshotRestorer = it
+            }
     }
 
     override fun isCurrentSelectedColorPreset(context: Context): Boolean {
diff --git a/src/com/android/customization/module/logging/ThemesUserEventLoggerImpl.kt b/src/com/android/customization/module/logging/ThemesUserEventLoggerImpl.kt
index b28086b4..0a639fb1 100644
--- a/src/com/android/customization/module/logging/ThemesUserEventLoggerImpl.kt
+++ b/src/com/android/customization/module/logging/ThemesUserEventLoggerImpl.kt
@@ -56,7 +56,6 @@ import com.android.wallpaper.module.WallpaperPreferences
 import com.android.wallpaper.module.logging.UserEventLogger.EffectStatus
 import com.android.wallpaper.module.logging.UserEventLogger.SetWallpaperEntryPoint
 import com.android.wallpaper.module.logging.UserEventLogger.WallpaperDestination
-import com.android.wallpaper.util.ActivityUtils
 import com.android.wallpaper.util.LaunchSourceUtils
 import javax.inject.Inject
 import javax.inject.Singleton
@@ -124,7 +123,7 @@ constructor(
         effect: String,
         @EffectStatus status: Int,
         timeElapsedMillis: Long,
-        resultCode: Int
+        resultCode: Int,
     ) {
         SysUiStatsLogger(WALLPAPER_EFFECT_APPLIED)
             .setAppSessionId(appSessionId.getId())
@@ -146,7 +145,7 @@ constructor(
     override fun logEffectForegroundDownload(
         effect: String,
         @EffectStatus status: Int,
-        timeElapsedMillis: Long
+        timeElapsedMillis: Long,
     ) {
         SysUiStatsLogger(WALLPAPER_EFFECT_FG_DOWNLOAD)
             .setAppSessionId(appSessionId.getId())
@@ -164,11 +163,7 @@ constructor(
         SysUiStatsLogger(WALLPAPER_EXPLORE).setAppSessionId(appSessionId.getId()).log()
     }
 
-    override fun logThemeColorApplied(
-        @ColorSource source: Int,
-        style: Int,
-        seedColor: Int,
-    ) {
+    override fun logThemeColorApplied(@ColorSource source: Int, style: Int, seedColor: Int) {
         SysUiStatsLogger(THEME_COLOR_APPLIED)
             .setAppSessionId(appSessionId.getId())
             .setColorSource(source)
@@ -251,10 +246,9 @@ constructor(
                 LaunchSourceUtils.LAUNCH_SOURCE_TIPS -> LAUNCHED_TIPS
                 LaunchSourceUtils.LAUNCH_SOURCE_DEEP_LINK -> LAUNCHED_DEEP_LINK
                 LaunchSourceUtils.LAUNCH_SOURCE_KEYGUARD -> LAUNCHED_KEYGUARD
+                LaunchSourceUtils.LAUNCH_SOURCE_SETTINGS_SEARCH -> LAUNCHED_SETTINGS_SEARCH
                 else -> LAUNCHED_PREFERENCE_UNSPECIFIED
             }
-        } else if (ActivityUtils.isLaunchedFromSettingsSearch(this)) {
-            LAUNCHED_SETTINGS_SEARCH
         } else if (action != null && action == WallpaperManager.ACTION_CROP_AND_SET_WALLPAPER) {
             LAUNCHED_CROP_AND_SET_ACTION
         } else if (categories != null && categories.contains(Intent.CATEGORY_LAUNCHER)) {
diff --git a/src/com/android/customization/picker/clock/data/repository/ClockPickerRepositoryImpl.kt b/src/com/android/customization/picker/clock/data/repository/ClockPickerRepositoryImpl.kt
index 4a4aae1c..c0a1446a 100644
--- a/src/com/android/customization/picker/clock/data/repository/ClockPickerRepositoryImpl.kt
+++ b/src/com/android/customization/picker/clock/data/repository/ClockPickerRepositoryImpl.kt
@@ -16,6 +16,7 @@
  */
 package com.android.customization.picker.clock.data.repository
 
+import android.graphics.drawable.Drawable
 import android.provider.Settings
 import androidx.annotation.ColorInt
 import androidx.annotation.IntRange
@@ -24,6 +25,9 @@ import com.android.customization.picker.clock.shared.model.ClockMetadataModel
 import com.android.systemui.plugins.clocks.ClockMetadata
 import com.android.systemui.shared.clocks.ClockRegistry
 import com.android.systemui.shared.settings.data.repository.SecureSettingsRepository
+import com.android.wallpaper.picker.di.modules.MainDispatcher
+import javax.inject.Inject
+import javax.inject.Singleton
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.ExperimentalCoroutinesApi
@@ -42,11 +46,14 @@ import kotlinx.coroutines.flow.shareIn
 import org.json.JSONObject
 
 /** Implementation of [ClockPickerRepository], using [ClockRegistry]. */
-class ClockPickerRepositoryImpl(
+@Singleton
+class ClockPickerRepositoryImpl
+@Inject
+constructor(
     private val secureSettingsRepository: SecureSettingsRepository,
     private val registry: ClockRegistry,
-    scope: CoroutineScope,
-    mainDispatcher: CoroutineDispatcher,
+    @MainDispatcher mainScope: CoroutineScope,
+    @MainDispatcher mainDispatcher: CoroutineDispatcher,
 ) : ClockPickerRepository {
 
     @OptIn(ExperimentalCoroutinesApi::class)
@@ -55,8 +62,18 @@ class ClockPickerRepositoryImpl(
                 fun send() {
                     val activeClockId = registry.activeClockId
                     val allClocks =
-                        registry.getClocks().map {
-                            it.toModel(isSelected = it.clockId == activeClockId)
+                        registry.getClocks().mapNotNull {
+                            val clockConfig = registry.getClockPickerConfig(it.clockId)
+                            if (clockConfig != null) {
+                                it.toModel(
+                                    isSelected = it.clockId == activeClockId,
+                                    description = clockConfig.description,
+                                    thumbnail = clockConfig.thumbnail,
+                                    isReactiveToTone = clockConfig.isReactiveToTone,
+                                )
+                            } else {
+                                null
+                            }
                         }
 
                     trySend(allClocks)
@@ -87,17 +104,24 @@ class ClockPickerRepositoryImpl(
                 fun send() {
                     val activeClockId = registry.activeClockId
                     val metadata = registry.settings?.metadata
+                    val clockConfig = registry.getClockPickerConfig(activeClockId)
                     val model =
-                        registry
-                            .getClocks()
-                            .find { clockMetadata -> clockMetadata.clockId == activeClockId }
-                            ?.toModel(
-                                isSelected = true,
-                                selectedColorId = metadata?.getSelectedColorId(),
-                                colorTone = metadata?.getColorTone()
-                                        ?: ClockMetadataModel.DEFAULT_COLOR_TONE_PROGRESS,
-                                seedColor = registry.seedColor
-                            )
+                        clockConfig?.let {
+                            registry
+                                .getClocks()
+                                .find { clockMetadata -> clockMetadata.clockId == activeClockId }
+                                ?.toModel(
+                                    isSelected = true,
+                                    description = it.description,
+                                    thumbnail = it.thumbnail,
+                                    isReactiveToTone = it.isReactiveToTone,
+                                    selectedColorId = metadata?.getSelectedColorId(),
+                                    colorTone =
+                                        metadata?.getColorTone()
+                                            ?: ClockMetadataModel.DEFAULT_COLOR_TONE_PROGRESS,
+                                    seedColor = registry.seedColor,
+                                )
+                        }
                     trySend(model)
                 }
 
@@ -151,7 +175,7 @@ class ClockPickerRepositoryImpl(
             .map { isDynamic -> if (isDynamic) ClockSize.DYNAMIC else ClockSize.SMALL }
             .distinctUntilChanged()
             .shareIn(
-                scope = scope,
+                scope = mainScope,
                 started = SharingStarted.Eagerly,
                 replay = 1,
             )
@@ -181,6 +205,9 @@ class ClockPickerRepositoryImpl(
     /** By default, [ClockMetadataModel] has no color information unless specified. */
     private fun ClockMetadata.toModel(
         isSelected: Boolean,
+        description: String,
+        thumbnail: Drawable,
+        isReactiveToTone: Boolean,
         selectedColorId: String? = null,
         @IntRange(from = 0, to = 100) colorTone: Int = 0,
         @ColorInt seedColor: Int? = null,
@@ -188,6 +215,9 @@ class ClockPickerRepositoryImpl(
         return ClockMetadataModel(
             clockId = clockId,
             isSelected = isSelected,
+            description = description,
+            thumbnail = thumbnail,
+            isReactiveToTone = isReactiveToTone,
             selectedColorId = selectedColorId,
             colorToneProgress = colorTone,
             seedColor = seedColor,
diff --git a/src/com/android/customization/picker/clock/data/repository/ClockRegistryProvider.kt b/src/com/android/customization/picker/clock/data/repository/ClockRegistryProvider.kt
index b197edf9..652ffdd2 100644
--- a/src/com/android/customization/picker/clock/data/repository/ClockRegistryProvider.kt
+++ b/src/com/android/customization/picker/clock/data/repository/ClockRegistryProvider.kt
@@ -29,7 +29,6 @@ import com.android.systemui.shared.plugins.PluginInstance
 import com.android.systemui.shared.plugins.PluginManagerImpl
 import com.android.systemui.shared.plugins.PluginPrefs
 import com.android.systemui.shared.system.UncaughtExceptionPreHandlerManager_Factory
-import com.android.wallpaper.module.InjectorProvider
 import java.util.concurrent.Executors
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.CoroutineScope
@@ -56,8 +55,6 @@ class ClockRegistryProvider(
             DefaultClockProvider(context, LayoutInflater.from(context), context.resources),
             keepAllLoaded = true,
             subTag = "Picker",
-            isTransitClockEnabled =
-                InjectorProvider.getInjector().getFlags().isTransitClockEnabled(context)
         )
     }
 
diff --git a/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractor.kt b/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractor.kt
index 30887e5d..42eed34b 100644
--- a/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractor.kt
+++ b/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractor.kt
@@ -23,7 +23,8 @@ import com.android.customization.picker.clock.data.repository.ClockPickerReposit
 import com.android.customization.picker.clock.shared.ClockSize
 import com.android.customization.picker.clock.shared.model.ClockMetadataModel
 import com.android.customization.picker.clock.shared.model.ClockSnapshotModel
-import javax.inject.Provider
+import javax.inject.Inject
+import javax.inject.Singleton
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.firstOrNull
@@ -33,9 +34,12 @@ import kotlinx.coroutines.flow.map
  * Interactor for accessing application clock settings, as well as selecting and configuring custom
  * clocks.
  */
-class ClockPickerInteractor(
+@Singleton
+class ClockPickerInteractor
+@Inject
+constructor(
     private val repository: ClockPickerRepository,
-    private val snapshotRestorer: Provider<ClockPickerSnapshotRestorer>,
+    private val snapshotRestorer: ClockPickerSnapshotRestorer,
 ) {
 
     val allClocks: Flow<List<ClockMetadataModel>> = repository.allClocks
@@ -43,6 +47,8 @@ class ClockPickerInteractor(
     val selectedClockId: Flow<String> =
         repository.selectedClock.map { clock -> clock.clockId }.distinctUntilChanged()
 
+    val selectedClock: Flow<ClockMetadataModel> = repository.selectedClock
+
     val selectedColorId: Flow<String?> =
         repository.selectedClock.map { clock -> clock.selectedColorId }.distinctUntilChanged()
 
@@ -78,7 +84,25 @@ class ClockPickerInteractor(
         setClockOption(ClockSnapshotModel(clockSize = size))
     }
 
-    suspend fun setClockOption(clockSnapshotModel: ClockSnapshotModel) {
+    suspend fun applyClock(
+        clockId: String?,
+        size: ClockSize?,
+        selectedColorId: String?,
+        @IntRange(from = 0, to = 100) colorToneProgress: Int?,
+        @ColorInt seedColor: Int?,
+    ) {
+        setClockOption(
+            ClockSnapshotModel(
+                clockId = clockId,
+                clockSize = size,
+                selectedColorId = selectedColorId,
+                colorToneProgress = colorToneProgress,
+                seedColor = seedColor,
+            )
+        )
+    }
+
+    private suspend fun setClockOption(clockSnapshotModel: ClockSnapshotModel) {
         // [ClockCarouselViewModel] is monitoring the [ClockPickerInteractor.setSelectedClock] job,
         // so it needs to finish last.
         storeCurrentClockOption(clockSnapshotModel)
@@ -88,12 +112,17 @@ class ClockPickerInteractor(
             repository.setClockColor(
                 selectedColorId = clockSnapshotModel.selectedColorId,
                 colorToneProgress = clockSnapshotModel.colorToneProgress,
-                seedColor = clockSnapshotModel.seedColor
+                seedColor = clockSnapshotModel.seedColor,
             )
         }
         clockSnapshotModel.clockId?.let { repository.setSelectedClock(it) }
     }
 
+    private suspend fun storeCurrentClockOption(clockSnapshotModel: ClockSnapshotModel) {
+        val option = getCurrentClockToRestore(clockSnapshotModel)
+        snapshotRestorer.storeSnapshot(option)
+    }
+
     /**
      * Gets the [ClockSnapshotModel] from the storage and override with [latestOption].
      *
@@ -103,19 +132,16 @@ class ClockPickerInteractor(
      * [selectedColorId] and [seedColor] have null state collide with nullable type, but we know
      * they are presented whenever there's a [colorToneProgress].
      */
-    suspend fun getCurrentClockToRestore(latestOption: ClockSnapshotModel? = null) =
+    private suspend fun getCurrentClockToRestore(latestOption: ClockSnapshotModel) =
         ClockSnapshotModel(
-            clockId = latestOption?.clockId ?: selectedClockId.firstOrNull(),
-            clockSize = latestOption?.clockSize ?: selectedClockSize.firstOrNull(),
-            colorToneProgress = latestOption?.colorToneProgress ?: colorToneProgress.firstOrNull(),
-            selectedColorId = latestOption?.colorToneProgress?.let { latestOption.selectedColorId }
+            clockId = latestOption.clockId ?: selectedClockId.firstOrNull(),
+            clockSize = latestOption.clockSize ?: selectedClockSize.firstOrNull(),
+            colorToneProgress = latestOption.colorToneProgress ?: colorToneProgress.firstOrNull(),
+            selectedColorId =
+                latestOption.colorToneProgress?.let { latestOption.selectedColorId }
                     ?: selectedColorId.firstOrNull(),
-            seedColor = latestOption?.colorToneProgress?.let { latestOption.seedColor }
+            seedColor =
+                latestOption.colorToneProgress?.let { latestOption.seedColor }
                     ?: seedColor.firstOrNull(),
         )
-
-    private suspend fun storeCurrentClockOption(clockSnapshotModel: ClockSnapshotModel) {
-        val option = getCurrentClockToRestore(clockSnapshotModel)
-        snapshotRestorer.get().storeSnapshot(option)
-    }
 }
diff --git a/src/com/android/customization/picker/clock/domain/interactor/ClockPickerSnapshotRestorer.kt b/src/com/android/customization/picker/clock/domain/interactor/ClockPickerSnapshotRestorer.kt
index ecaf10f6..322c7242 100644
--- a/src/com/android/customization/picker/clock/domain/interactor/ClockPickerSnapshotRestorer.kt
+++ b/src/com/android/customization/picker/clock/domain/interactor/ClockPickerSnapshotRestorer.kt
@@ -19,14 +19,22 @@ package com.android.customization.picker.clock.domain.interactor
 
 import android.text.TextUtils
 import android.util.Log
+import com.android.customization.picker.clock.data.repository.ClockPickerRepository
 import com.android.customization.picker.clock.shared.model.ClockSnapshotModel
 import com.android.wallpaper.picker.undo.domain.interactor.SnapshotRestorer
 import com.android.wallpaper.picker.undo.domain.interactor.SnapshotStore
 import com.android.wallpaper.picker.undo.shared.model.RestorableSnapshot
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.flow.distinctUntilChanged
+import kotlinx.coroutines.flow.firstOrNull
+import kotlinx.coroutines.flow.map
 
 /** Handles state restoration for clocks. */
-class ClockPickerSnapshotRestorer(private val interactor: ClockPickerInteractor) :
-    SnapshotRestorer {
+@Singleton
+class ClockPickerSnapshotRestorer
+@Inject
+constructor(private val repository: ClockPickerRepository) : SnapshotRestorer {
     private var snapshotStore: SnapshotStore = SnapshotStore.NOOP
     private var originalOption: ClockSnapshotModel? = null
 
@@ -34,7 +42,23 @@ class ClockPickerSnapshotRestorer(private val interactor: ClockPickerInteractor)
         store: SnapshotStore,
     ): RestorableSnapshot {
         snapshotStore = store
-        originalOption = interactor.getCurrentClockToRestore()
+        originalOption =
+            ClockSnapshotModel(
+                clockId =
+                    repository.selectedClock
+                        .map { clock -> clock.clockId }
+                        .distinctUntilChanged()
+                        .firstOrNull(),
+                clockSize = repository.selectedClockSize.firstOrNull(),
+                colorToneProgress =
+                    repository.selectedClock.map { clock -> clock.colorToneProgress }.firstOrNull(),
+                selectedColorId =
+                    repository.selectedClock
+                        .map { clock -> clock.selectedColorId }
+                        .distinctUntilChanged()
+                        .firstOrNull(),
+                seedColor = repository.selectedClock.map { clock -> clock.seedColor }.firstOrNull(),
+            )
         return snapshot(originalOption)
     }
 
@@ -58,7 +82,15 @@ class ClockPickerSnapshotRestorer(private val interactor: ClockPickerInteractor)
                 )
             }
 
-            interactor.setClockOption(optionToRestore)
+            optionToRestore.clockSize?.let { repository.setClockSize(it) }
+            optionToRestore.colorToneProgress?.let {
+                repository.setClockColor(
+                    selectedColorId = optionToRestore.selectedColorId,
+                    colorToneProgress = optionToRestore.colorToneProgress,
+                    seedColor = optionToRestore.seedColor
+                )
+            }
+            optionToRestore.clockId?.let { repository.setSelectedClock(it) }
         }
     }
 
diff --git a/src/com/android/customization/picker/clock/shared/model/ClockMetadataModel.kt b/src/com/android/customization/picker/clock/shared/model/ClockMetadataModel.kt
index 6e2bfb38..3c8e7259 100644
--- a/src/com/android/customization/picker/clock/shared/model/ClockMetadataModel.kt
+++ b/src/com/android/customization/picker/clock/shared/model/ClockMetadataModel.kt
@@ -17,6 +17,7 @@
 
 package com.android.customization.picker.clock.shared.model
 
+import android.graphics.drawable.Drawable
 import androidx.annotation.ColorInt
 import androidx.annotation.IntRange
 
@@ -24,6 +25,9 @@ import androidx.annotation.IntRange
 data class ClockMetadataModel(
     val clockId: String,
     val isSelected: Boolean,
+    val description: String,
+    val thumbnail: Drawable,
+    val isReactiveToTone: Boolean,
     val selectedColorId: String?,
     @IntRange(from = 0, to = 100) val colorToneProgress: Int,
     @ColorInt val seedColor: Int?,
diff --git a/src/com/android/customization/picker/clock/ui/binder/ClockSettingsBinder.kt b/src/com/android/customization/picker/clock/ui/binder/ClockSettingsBinder.kt
index 7de25e70..616640c3 100644
--- a/src/com/android/customization/picker/clock/ui/binder/ClockSettingsBinder.kt
+++ b/src/com/android/customization/picker/clock/ui/binder/ClockSettingsBinder.kt
@@ -45,9 +45,9 @@ import com.android.customization.picker.clock.ui.view.ClockHostView
 import com.android.customization.picker.clock.ui.view.ClockViewFactory
 import com.android.customization.picker.clock.ui.viewmodel.ClockSettingsViewModel
 import com.android.customization.picker.color.ui.binder.ColorOptionIconBinder
-import com.android.customization.picker.common.ui.view.ItemSpacing
 import com.android.themepicker.R
 import com.android.wallpaper.config.BaseFlags
+import com.android.wallpaper.picker.common.ui.view.ItemSpacing
 import com.android.wallpaper.picker.option.ui.binder.OptionItemBinder
 import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.flow.mapNotNull
@@ -82,6 +82,7 @@ object ClockSettingsBinder {
                 }
 
                 override fun onStartTrackingTouch(seekBar: SeekBar?) = Unit
+
                 override fun onStopTrackingTouch(seekBar: SeekBar?) {
                     seekBar?.progress?.let {
                         lifecycleOwner.lifecycleScope.launch { viewModel.onSliderProgressStop(it) }
diff --git a/src/com/android/customization/picker/clock/ui/fragment/ClockSettingsFragment.kt b/src/com/android/customization/picker/clock/ui/fragment/ClockSettingsFragment.kt
index c2e67175..b66150f8 100644
--- a/src/com/android/customization/picker/clock/ui/fragment/ClockSettingsFragment.kt
+++ b/src/com/android/customization/picker/clock/ui/fragment/ClockSettingsFragment.kt
@@ -19,9 +19,13 @@ import android.os.Bundle
 import android.view.LayoutInflater
 import android.view.View
 import android.view.ViewGroup
+import android.view.ViewGroup.MarginLayoutParams
 import androidx.cardview.widget.CardView
 import androidx.core.content.ContextCompat
+import androidx.core.view.ViewCompat
+import androidx.core.view.WindowInsetsCompat
 import androidx.core.view.isVisible
+import androidx.core.view.updateLayoutParams
 import androidx.lifecycle.ViewModelProvider
 import androidx.lifecycle.get
 import androidx.transition.Transition
@@ -61,6 +65,14 @@ class ClockSettingsFragment : AppbarFragment() {
                 container,
                 false,
             )
+        ViewCompat.setOnApplyWindowInsetsListener(view) { v, windowInsets ->
+            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
+            v.updateLayoutParams<MarginLayoutParams> {
+                topMargin = insets.top
+                bottomMargin = insets.bottom
+            }
+            WindowInsetsCompat.CONSUMED
+        }
         setUpToolbar(view)
 
         val context = requireContext()
diff --git a/src/com/android/customization/picker/clock/ui/view/ClockCarouselView.kt b/src/com/android/customization/picker/clock/ui/view/ClockCarouselView.kt
index 6cbb0f5f..1d2f5956 100644
--- a/src/com/android/customization/picker/clock/ui/view/ClockCarouselView.kt
+++ b/src/com/android/customization/picker/clock/ui/view/ClockCarouselView.kt
@@ -145,8 +145,7 @@ class ClockCarouselView(
             clocks
                 .indexOfFirst { it.isSelected }
                 // If not found, default to the first clock as selected:
-                .takeIf { it != -1 }
-                ?: 0
+                .takeIf { it != -1 } ?: 0
         carousel.jumpToIndex(indexOfSelectedClock)
         motionLayout.setTransitionListener(
             object : MotionLayout.TransitionListener {
@@ -247,15 +246,13 @@ class ClockCarouselView(
                             offCenterClockHostView[0]
                         } else {
                             null
-                        }
-                            ?: return
+                        } ?: return
                     val toCenterClockFrame =
                         if (toCenterClockHostView.isNotEmpty()) {
                             toCenterClockHostView[0]
                         } else {
                             null
-                        }
-                            ?: return
+                        } ?: return
                     offCenterClockHostView.doOnPreDraw {
                         it.pivotX =
                             progress * it.width / 2 + (1 - progress) * getCenteredHostViewPivotX(it)
@@ -351,12 +348,12 @@ class ClockCarouselView(
             }
         }
 
-        val previousConstaintSet = motionLayout.getConstraintSet(R.id.previous)
-        val startConstaintSet = motionLayout.getConstraintSet(R.id.start)
-        val nextConstaintSet = motionLayout.getConstraintSet(R.id.next)
-        val constaintSetList =
-            listOf<ConstraintSet>(previousConstaintSet, startConstaintSet, nextConstaintSet)
-        constaintSetList.forEach { constraintSet ->
+        val previousConstraintSet = motionLayout.getConstraintSet(R.id.previous)
+        val startConstraintSet = motionLayout.getConstraintSet(R.id.start)
+        val nextConstraintSet = motionLayout.getConstraintSet(R.id.next)
+        val constraintSetList =
+            listOf<ConstraintSet>(previousConstraintSet, startConstraintSet, nextConstraintSet)
+        constraintSetList.forEach { constraintSet ->
             itemViewIds.forEach { id ->
                 constraintSet.getConstraint(id)?.let { constraint ->
                     val layout = constraint.layout
@@ -388,6 +385,16 @@ class ClockCarouselView(
         private val onClockSelected: (clock: ClockCarouselItemViewModel) -> Unit
     ) : Carousel.Adapter {
 
+        // This map is used to eagerly save the translation X and Y of each small clock view, so
+        // that the next time we need it, we do not need to wait for onPreDraw to obtain the
+        // translation X and Y.
+        // This is to solve the issue that when Fragment transition triggers another attach of the
+        // view for animation purposes. We need to obtain the translation X and Y quick enough so
+        // that the outgoing carousel view that shows this the small clock views are correctly
+        // positioned.
+        private val smallClockTranslationMap: MutableMap<String, Pair<Float, Float>> =
+            mutableMapOf()
+
         fun getContentDescription(index: Int, resources: Resources): String {
             return clocks[index].contentDescription
         }
@@ -440,6 +447,7 @@ class ClockCarouselView(
                     )
                 ClockSize.SMALL ->
                     initializeSmallClockView(
+                        clockId,
                         isMiddleView,
                         clockHostView,
                         clockView,
@@ -472,10 +480,18 @@ class ClockCarouselView(
         }
 
         private fun initializeSmallClockView(
+            clockId: String,
             isMiddleView: Boolean,
             clockHostView: ClockHostView,
             clockView: View,
         ) {
+            smallClockTranslationMap[clockId]?.let {
+                // If isMiddleView, the translation X and Y should both be 0
+                if (!isMiddleView) {
+                    clockView.translationX = it.first
+                    clockView.translationY = it.second
+                }
+            }
             clockHostView.doOnPreDraw {
                 if (isMiddleView) {
                     it.pivotX = getCenteredHostViewPivotX(it)
@@ -485,18 +501,21 @@ class ClockCarouselView(
                 } else {
                     it.pivotX = it.width / 2F
                     it.pivotY = it.height / 2F
-                    clockView.translationX =
+                    val translationX =
                         getTranslationDistance(
                             clockHostView.width,
                             clockView.width,
                             clockView.left,
                         )
-                    clockView.translationY =
+                    val translationY =
                         getTranslationDistance(
                             clockHostView.height,
                             clockView.height,
                             clockView.top,
                         )
+                    clockView.translationX = translationX
+                    clockView.translationY = translationY
+                    smallClockTranslationMap[clockId] = Pair(translationX, translationY)
                 }
             }
         }
diff --git a/src/com/android/customization/picker/clock/ui/view/ClockHostView2.kt b/src/com/android/customization/picker/clock/ui/view/ClockHostView2.kt
new file mode 100644
index 00000000..be2e53d3
--- /dev/null
+++ b/src/com/android/customization/picker/clock/ui/view/ClockHostView2.kt
@@ -0,0 +1,84 @@
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
+import android.widget.FrameLayout
+import com.android.customization.picker.clock.shared.ClockSize
+import com.android.wallpaper.util.ScreenSizeCalculator
+
+/**
+ * Parent view for the clock view. We will calculate the current display size and the preview size
+ * and scale down the clock view to fit in the preview.
+ */
+class ClockHostView2(context: Context, attrs: AttributeSet?) : FrameLayout(context, attrs) {
+
+    var clockSize: ClockSize = ClockSize.DYNAMIC
+        set(value) {
+            if (field != value) {
+                field = value
+                updatePivotAndScale()
+                invalidate()
+            }
+        }
+
+    override fun onLayout(changed: Boolean, left: Int, top: Int, right: Int, bottom: Int) {
+        super.onLayout(changed, left, top, right, bottom)
+        updatePivotAndScale()
+    }
+
+    override fun measureChildWithMargins(
+        child: View?,
+        parentWidthMeasureSpec: Int,
+        widthUsed: Int,
+        parentHeightMeasureSpec: Int,
+        heightUsed: Int,
+    ) {
+        val screenSize = ScreenSizeCalculator.getInstance().getScreenSize(display)
+        super.measureChildWithMargins(
+            child,
+            MeasureSpec.makeMeasureSpec(screenSize.x, EXACTLY),
+            widthUsed,
+            MeasureSpec.makeMeasureSpec(screenSize.y, EXACTLY),
+            heightUsed,
+        )
+    }
+
+    private fun updatePivotAndScale() {
+        when (clockSize) {
+            ClockSize.DYNAMIC -> {
+                resetPivot()
+            }
+            ClockSize.SMALL -> {
+                pivotX = getCenteredHostViewPivotX(this)
+                pivotY = 0F
+            }
+        }
+        val screenSize = ScreenSizeCalculator.getInstance().getScreenSize(display)
+        val ratio = measuredWidth / screenSize.x.toFloat()
+        scaleX = ratio
+        scaleY = ratio
+    }
+
+    companion object {
+        fun getCenteredHostViewPivotX(hostView: View): Float {
+            return if (hostView.isLayoutRtl) hostView.width.toFloat() else 0F
+        }
+    }
+}
diff --git a/src/com/android/customization/picker/clock/ui/view/ClockViewFactory.kt b/src/com/android/customization/picker/clock/ui/view/ClockViewFactory.kt
deleted file mode 100644
index 8e5992ed..00000000
--- a/src/com/android/customization/picker/clock/ui/view/ClockViewFactory.kt
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
-package com.android.customization.picker.clock.ui.view
-
-import android.view.View
-import androidx.annotation.ColorInt
-import androidx.lifecycle.LifecycleOwner
-import com.android.systemui.plugins.clocks.ClockController
-
-interface ClockViewFactory {
-
-    fun getController(clockId: String): ClockController
-
-    /**
-     * Reset the large view to its initial state when getting the view. This is because some view
-     * configs, e.g. animation state, might change during the reuse of the clock view in the app.
-     */
-    fun getLargeView(clockId: String): View
-
-    /**
-     * Reset the small view to its initial state when getting the view. This is because some view
-     * configs, e.g. translation X, might change during the reuse of the clock view in the app.
-     */
-    fun getSmallView(clockId: String): View
-
-    /** Enables or disables the reactive swipe interaction */
-    fun setReactiveTouchInteractionEnabled(clockId: String, enable: Boolean)
-
-    fun updateColorForAllClocks(@ColorInt seedColor: Int?)
-
-    fun updateColor(clockId: String, @ColorInt seedColor: Int?)
-
-    fun updateRegionDarkness()
-
-    fun updateTimeFormat(clockId: String)
-
-    fun registerTimeTicker(owner: LifecycleOwner)
-
-    fun onDestroy()
-
-    fun unregisterTimeTicker(owner: LifecycleOwner)
-}
diff --git a/src/com/android/customization/picker/clock/ui/view/ClockViewFactoryImpl.kt b/src/com/android/customization/picker/clock/ui/view/ThemePickerClockViewFactory.kt
similarity index 84%
rename from src/com/android/customization/picker/clock/ui/view/ClockViewFactoryImpl.kt
rename to src/com/android/customization/picker/clock/ui/view/ThemePickerClockViewFactory.kt
index dea67774..1f73727c 100644
--- a/src/com/android/customization/picker/clock/ui/view/ClockViewFactoryImpl.kt
+++ b/src/com/android/customization/picker/clock/ui/view/ThemePickerClockViewFactory.kt
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -15,37 +15,41 @@
  */
 package com.android.customization.picker.clock.ui.view
 
+import android.app.Activity
 import android.app.WallpaperColors
 import android.app.WallpaperManager
 import android.content.Context
-import android.content.res.Resources
-import android.graphics.Point
 import android.graphics.Rect
 import android.view.View
 import android.widget.FrameLayout
 import androidx.annotation.ColorInt
-import androidx.core.text.util.LocalePreferences
 import androidx.lifecycle.LifecycleOwner
+import com.android.internal.policy.SystemBarUtils
 import com.android.systemui.plugins.clocks.ClockController
 import com.android.systemui.plugins.clocks.WeatherData
 import com.android.systemui.shared.clocks.ClockRegistry
-import com.android.themepicker.R
 import com.android.wallpaper.config.BaseFlags
+import com.android.wallpaper.util.ScreenSizeCalculator
 import com.android.wallpaper.util.TimeUtils.TimeTicker
 import java.util.concurrent.ConcurrentHashMap
+import javax.inject.Inject
 
 /**
  * Provide reusable clock view and related util functions.
  *
  * @property screenSize The Activity or Fragment's window size.
  */
-class ClockViewFactoryImpl(
-    private val appContext: Context,
-    val screenSize: Point,
+class ThemePickerClockViewFactory
+@Inject
+constructor(
+    activity: Activity,
     private val wallpaperManager: WallpaperManager,
     private val registry: ClockRegistry,
 ) : ClockViewFactory {
+    private val appContext = activity.applicationContext
     private val resources = appContext.resources
+    private val screenSize =
+        ScreenSizeCalculator.getInstance().getScreenSize(activity.windowManager.defaultDisplay)
     private val timeTickListeners: ConcurrentHashMap<Int, TimeTicker> = ConcurrentHashMap()
     private val clockControllers: ConcurrentHashMap<String, ClockController> = ConcurrentHashMap()
     private val smallClockFrames: HashMap<String, FrameLayout> = HashMap()
@@ -97,7 +101,7 @@ class ClockViewFactoryImpl(
                 FrameLayout.LayoutParams.WRAP_CONTENT,
                 resources.getDimensionPixelSize(
                     com.android.systemui.customization.R.dimen.small_clock_height
-                )
+                ),
             )
         layoutParams.topMargin = getSmallClockTopMargin()
         layoutParams.marginStart = getSmallClockStartPadding()
@@ -107,7 +111,7 @@ class ClockViewFactoryImpl(
     }
 
     private fun getSmallClockTopMargin() =
-        getStatusBarHeight(appContext.resources) +
+        getStatusBarHeight(appContext) +
             appContext.resources.getDimensionPixelSize(
                 com.android.systemui.customization.R.dimen.small_clock_padding_top
             )
@@ -122,7 +126,7 @@ class ClockViewFactoryImpl(
     }
 
     override fun updateColor(clockId: String, @ColorInt seedColor: Int?) {
-        clockControllers[clockId]?.events?.onSeedColorChanged(seedColor)
+        getController(clockId).events.onSeedColorChanged(seedColor)
     }
 
     override fun updateRegionDarkness() {
@@ -202,21 +206,7 @@ class ClockViewFactoryImpl(
                 .toFloat()
         )
         controller.smallClock.events.onTargetRegionChanged(getSmallClockRegion())
-
-        // Use placeholder for weather clock preview in picker.
-        // Use locale default temp unit since assistant default is not available in this context.
-        val useCelsius =
-            LocalePreferences.getTemperatureUnit() == LocalePreferences.TemperatureUnit.CELSIUS
-        controller.events.onWeatherDataChanged(
-            WeatherData(
-                description = DESCRIPTION_PLACEHODLER,
-                state = WEATHERICON_PLACEHOLDER,
-                temperature =
-                    if (useCelsius) TEMPERATURE_CELSIUS_PLACEHOLDER
-                    else TEMPERATURE_FAHRENHEIT_PLACEHOLDER,
-                useCelsius = useCelsius,
-            )
-        )
+        controller.events.onWeatherDataChanged(WeatherData.getPlaceholderWeatherData())
         return controller
     }
 
@@ -253,17 +243,17 @@ class ClockViewFactoryImpl(
     }
 
     companion object {
-        const val DESCRIPTION_PLACEHODLER = ""
-        const val TEMPERATURE_FAHRENHEIT_PLACEHOLDER = 58
-        const val TEMPERATURE_CELSIUS_PLACEHOLDER = 21
-        val WEATHERICON_PLACEHOLDER = WeatherData.WeatherStateIcon.MOSTLY_SUNNY
-        const val USE_CELSIUS_PLACEHODLER = false
+        private fun getStatusBarHeight(context: Context): Int {
+            val display = context.displayNoVerify
+            if (display != null) {
+                return SystemBarUtils.getStatusBarHeight(context.resources, display.cutout)
+            }
 
-        private fun getStatusBarHeight(resource: Resources): Int {
             var result = 0
-            val resourceId: Int = resource.getIdentifier("status_bar_height", "dimen", "android")
+            val resourceId: Int =
+                context.resources.getIdentifier("status_bar_height", "dimen", "android")
             if (resourceId > 0) {
-                result = resource.getDimensionPixelSize(resourceId)
+                result = context.resources.getDimensionPixelSize(resourceId)
             }
             return result
         }
diff --git a/src/com/android/customization/picker/color/data/repository/ColorPickerRepositoryImpl.kt b/src/com/android/customization/picker/color/data/repository/ColorPickerRepositoryImpl.kt
index 942a8460..f5b4ac54 100644
--- a/src/com/android/customization/picker/color/data/repository/ColorPickerRepositoryImpl.kt
+++ b/src/com/android/customization/picker/color/data/repository/ColorPickerRepositoryImpl.kt
@@ -26,6 +26,8 @@ import com.android.customization.picker.color.shared.model.ColorType
 import com.android.systemui.monet.Style
 import com.android.wallpaper.picker.customization.data.repository.WallpaperColorsRepository
 import com.android.wallpaper.picker.customization.shared.model.WallpaperColorsModel
+import javax.inject.Inject
+import javax.inject.Singleton
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.StateFlow
@@ -36,7 +38,10 @@ import kotlinx.coroutines.suspendCancellableCoroutine
 
 // TODO (b/262924623): refactor to remove dependency on ColorCustomizationManager & ColorOption
 // TODO (b/268203200): Create test for ColorPickerRepositoryImpl
-class ColorPickerRepositoryImpl(
+@Singleton
+class ColorPickerRepositoryImpl
+@Inject
+constructor(
     wallpaperColorsRepository: WallpaperColorsRepository,
     private val colorManager: ColorCustomizationManager,
 ) : ColorPickerRepository {
diff --git a/src/com/android/customization/picker/color/domain/interactor/ColorPickerInteractor.kt b/src/com/android/customization/picker/color/domain/interactor/ColorPickerInteractor.kt
index e7759ce5..aebc6c2f 100644
--- a/src/com/android/customization/picker/color/domain/interactor/ColorPickerInteractor.kt
+++ b/src/com/android/customization/picker/color/domain/interactor/ColorPickerInteractor.kt
@@ -18,15 +18,19 @@ package com.android.customization.picker.color.domain.interactor
 
 import com.android.customization.picker.color.data.repository.ColorPickerRepository
 import com.android.customization.picker.color.shared.model.ColorOptionModel
-import javax.inject.Provider
+import javax.inject.Inject
+import javax.inject.Singleton
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.onEach
 
 /** Single entry-point for all application state and business logic related to system color. */
-class ColorPickerInteractor(
+@Singleton
+class ColorPickerInteractor
+@Inject
+constructor(
     private val repository: ColorPickerRepository,
-    private val snapshotRestorer: Provider<ColorPickerSnapshotRestorer>,
+    private val snapshotRestorer: ColorPickerSnapshotRestorer,
 ) {
     val isApplyingSystemColor = repository.isApplyingSystemColor
 
@@ -51,7 +55,7 @@ class ColorPickerInteractor(
             // actually updated until the picker restarts. Wait to do so when updated color options
             // become available
             repository.select(colorOptionModel)
-            snapshotRestorer.get().storeSnapshot(colorOptionModel)
+            snapshotRestorer.storeSnapshot(colorOptionModel)
         } catch (e: Exception) {
             _selectingColorOption.value = null
         }
diff --git a/src/com/android/customization/picker/color/domain/interactor/ColorPickerSnapshotRestorer.kt b/src/com/android/customization/picker/color/domain/interactor/ColorPickerSnapshotRestorer.kt
index dce59ebf..656663c4 100644
--- a/src/com/android/customization/picker/color/domain/interactor/ColorPickerSnapshotRestorer.kt
+++ b/src/com/android/customization/picker/color/domain/interactor/ColorPickerSnapshotRestorer.kt
@@ -18,14 +18,20 @@
 package com.android.customization.picker.color.domain.interactor
 
 import android.util.Log
+import com.android.customization.picker.color.data.repository.ColorPickerRepository
 import com.android.customization.picker.color.shared.model.ColorOptionModel
 import com.android.wallpaper.picker.undo.domain.interactor.SnapshotRestorer
 import com.android.wallpaper.picker.undo.domain.interactor.SnapshotStore
 import com.android.wallpaper.picker.undo.shared.model.RestorableSnapshot
+import javax.inject.Inject
+import javax.inject.Singleton
 
 /** Handles state restoration for the color picker system. */
-class ColorPickerSnapshotRestorer(
-    private val interactor: ColorPickerInteractor,
+@Singleton
+class ColorPickerSnapshotRestorer
+@Inject
+constructor(
+    private val repository: ColorPickerRepository,
 ) : SnapshotRestorer {
 
     private var snapshotStore: SnapshotStore = SnapshotStore.NOOP
@@ -39,7 +45,7 @@ class ColorPickerSnapshotRestorer(
         store: SnapshotStore,
     ): RestorableSnapshot {
         snapshotStore = store
-        originalOption = interactor.getCurrentColorOption()
+        originalOption = repository.getCurrentColorOption()
         return snapshot(originalOption)
     }
 
@@ -60,7 +66,7 @@ class ColorPickerSnapshotRestorer(
                 )
             }
 
-            interactor.select(optionToRestore)
+            repository.select(optionToRestore)
         }
     }
 
diff --git a/src/com/android/customization/picker/color/ui/binder/ColorPickerBinder.kt b/src/com/android/customization/picker/color/ui/binder/ColorPickerBinder.kt
index 7b5b5989..82ce77b8 100644
--- a/src/com/android/customization/picker/color/ui/binder/ColorPickerBinder.kt
+++ b/src/com/android/customization/picker/color/ui/binder/ColorPickerBinder.kt
@@ -32,8 +32,8 @@ import com.android.customization.picker.color.ui.adapter.ColorTypeTabAdapter
 import com.android.customization.picker.color.ui.view.ColorOptionIconView
 import com.android.customization.picker.color.ui.viewmodel.ColorOptionIconViewModel
 import com.android.customization.picker.color.ui.viewmodel.ColorPickerViewModel
-import com.android.customization.picker.common.ui.view.ItemSpacing
 import com.android.themepicker.R
+import com.android.wallpaper.picker.common.ui.view.ItemSpacing
 import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter
 import kotlinx.coroutines.flow.map
 import kotlinx.coroutines.launch
@@ -133,9 +133,10 @@ object ColorPickerBinder {
 
     interface Binding {
         fun saveInstanceState(savedState: Bundle)
+
         fun restoreInstanceState(savedState: Bundle)
     }
 
-    private val LAYOUT_MANAGER_SAVED_STATE: String = "layout_manager_state"
+    private const val LAYOUT_MANAGER_SAVED_STATE: String = "layout_manager_state"
     private var layoutManagerSavedState: Parcelable? = null
 }
diff --git a/src/com/android/customization/picker/color/ui/binder/ColorSectionViewBinder.kt b/src/com/android/customization/picker/color/ui/binder/ColorSectionViewBinder.kt
index c2dc381d..3adc9137 100644
--- a/src/com/android/customization/picker/color/ui/binder/ColorSectionViewBinder.kt
+++ b/src/com/android/customization/picker/color/ui/binder/ColorSectionViewBinder.kt
@@ -20,6 +20,7 @@ package com.android.customization.picker.color.ui.binder
 import android.content.res.Configuration
 import android.view.LayoutInflater
 import android.view.View
+import android.view.ViewGroup
 import android.widget.ImageView
 import android.widget.LinearLayout
 import androidx.core.view.isVisible
@@ -50,12 +51,34 @@ object ColorSectionViewBinder {
     ) {
         val optionContainer: LinearLayout =
             view.requireViewById(R.id.color_section_option_container)
+        val optionContainerLayoutParams = optionContainer.layoutParams
         val moreColorsButton: View = view.requireViewById(R.id.more_colors)
         if (isConnectedHorizontallyToOtherSections) {
             moreColorsButton.isVisible = true
             moreColorsButton.setOnClickListener(navigationOnClick)
+
+            // Match the height of option container and the other sections when connected
+            // horizontally.
+            optionContainerLayoutParams.height =
+                view.resources.getDimensionPixelSize(R.dimen.color_options_selected_option_height)
+            optionContainer.layoutParams = optionContainerLayoutParams
+            optionContainer.setPadding(
+                optionContainer.paddingLeft,
+                16,
+                optionContainer.paddingRight,
+                16
+            )
         } else {
             moreColorsButton.isVisible = false
+
+            optionContainerLayoutParams.height = ViewGroup.LayoutParams.WRAP_CONTENT
+            optionContainer.layoutParams = optionContainerLayoutParams
+            optionContainer.setPadding(
+                optionContainer.paddingLeft,
+                20,
+                optionContainer.paddingRight,
+                20
+            )
         }
         lifecycleOwner.lifecycleScope.launch {
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
diff --git a/src/com/android/customization/picker/color/ui/fragment/ColorPickerFragment.kt b/src/com/android/customization/picker/color/ui/fragment/ColorPickerFragment.kt
index a2dc526e..3f4bf57f 100644
--- a/src/com/android/customization/picker/color/ui/fragment/ColorPickerFragment.kt
+++ b/src/com/android/customization/picker/color/ui/fragment/ColorPickerFragment.kt
@@ -20,10 +20,14 @@ import android.os.Bundle
 import android.view.LayoutInflater
 import android.view.View
 import android.view.ViewGroup
+import android.view.ViewGroup.MarginLayoutParams
 import android.widget.FrameLayout
 import androidx.cardview.widget.CardView
 import androidx.core.content.ContextCompat
+import androidx.core.view.ViewCompat
+import androidx.core.view.WindowInsetsCompat
 import androidx.core.view.isVisible
+import androidx.core.view.updateLayoutParams
 import androidx.lifecycle.ViewModelProvider
 import androidx.lifecycle.get
 import androidx.lifecycle.lifecycleScope
@@ -70,7 +74,16 @@ class ColorPickerFragment : AppbarFragment() {
                 container,
                 false,
             )
+        ViewCompat.setOnApplyWindowInsetsListener(view) { v, windowInsets ->
+            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
+            v.updateLayoutParams<MarginLayoutParams> {
+                topMargin = insets.top
+                bottomMargin = insets.bottom
+            }
+            WindowInsetsCompat.CONSUMED
+        }
         setUpToolbar(view)
+
         val injector = InjectorProvider.getInjector() as ThemePickerInjector
         val lockScreenView: CardView = view.requireViewById(R.id.lock_preview)
         val homeScreenView: CardView = view.requireViewById(R.id.home_preview)
@@ -85,10 +98,7 @@ class ColorPickerFragment : AppbarFragment() {
                 viewModel =
                     ViewModelProvider(
                             requireActivity(),
-                            injector.getColorPickerViewModelFactory(
-                                context = requireContext(),
-                                wallpaperColorsRepository = wallpaperColorsRepository,
-                            ),
+                            injector.getColorPickerViewModelFactory(requireContext()),
                         )
                         .get(),
                 lifecycleOwner = this,
diff --git a/src/com/android/customization/picker/color/ui/viewmodel/ColorPickerViewModel.kt b/src/com/android/customization/picker/color/ui/viewmodel/ColorPickerViewModel.kt
index 52df31a9..61a648fe 100644
--- a/src/com/android/customization/picker/color/ui/viewmodel/ColorPickerViewModel.kt
+++ b/src/com/android/customization/picker/color/ui/viewmodel/ColorPickerViewModel.kt
@@ -202,6 +202,6 @@ private constructor(
     }
 
     companion object {
-        private const val COLOR_SECTION_OPTION_SIZE = 5
+        private const val COLOR_SECTION_OPTION_SIZE = 6
     }
 }
diff --git a/src/com/android/customization/picker/common/ui/view/DoubleRowListItemSpacing.kt b/src/com/android/customization/picker/common/ui/view/DoubleRowListItemSpacing.kt
new file mode 100644
index 00000000..9868073c
--- /dev/null
+++ b/src/com/android/customization/picker/common/ui/view/DoubleRowListItemSpacing.kt
@@ -0,0 +1,63 @@
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
+package com.android.customization.picker.common.ui.view
+
+import android.graphics.Rect
+import android.view.View
+import androidx.recyclerview.widget.RecyclerView
+
+/** Item spacing used by the horizontal RecyclerView with 2 rows. */
+class DoubleRowListItemSpacing(
+    private val edgeItemSpacePx: Int,
+    private val itemHorizontalSpacePx: Int,
+    private val itemVerticalSpacePx: Int,
+) : RecyclerView.ItemDecoration() {
+    override fun getItemOffsets(
+        outRect: Rect,
+        view: View,
+        parent: RecyclerView,
+        state: RecyclerView.State,
+    ) {
+        val itemIndex = parent.getChildAdapterPosition(view)
+        val columnIndex = itemIndex / 2
+        val isRtl = parent.layoutManager?.layoutDirection == View.LAYOUT_DIRECTION_RTL
+
+        val itemCount = parent.adapter?.itemCount ?: 0
+        val columnCount = (itemCount + 1) / 2
+        when {
+            columnCount == 1 -> {
+                outRect.left = edgeItemSpacePx
+                outRect.right = edgeItemSpacePx
+            }
+            columnIndex > 0 && columnIndex < columnCount - 1 -> {
+                outRect.left = itemHorizontalSpacePx
+                outRect.right = itemHorizontalSpacePx
+            }
+            columnIndex == 0 -> {
+                outRect.left = if (!isRtl) edgeItemSpacePx else itemHorizontalSpacePx
+                outRect.right = if (isRtl) edgeItemSpacePx else itemHorizontalSpacePx
+            }
+            columnIndex == columnCount - 1 -> {
+                outRect.right = if (!isRtl) edgeItemSpacePx else itemHorizontalSpacePx
+                outRect.left = if (isRtl) edgeItemSpacePx else itemHorizontalSpacePx
+            }
+        }
+
+        if (itemIndex % 2 == 0) {
+            outRect.bottom = itemVerticalSpacePx
+        }
+    }
+}
diff --git a/src/com/android/customization/picker/common/ui/view/ItemSpacing.kt b/src/com/android/customization/picker/common/ui/view/ItemSpacing.kt
deleted file mode 100644
index ca689aa2..00000000
--- a/src/com/android/customization/picker/common/ui/view/ItemSpacing.kt
+++ /dev/null
@@ -1,49 +0,0 @@
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
-package com.android.customization.picker.common.ui.view
-
-import android.graphics.Rect
-import androidx.core.view.ViewCompat
-import androidx.recyclerview.widget.RecyclerView
-
-/** Item spacing used by the RecyclerView. */
-class ItemSpacing(
-    private val itemSpacingDp: Int,
-) : RecyclerView.ItemDecoration() {
-    override fun getItemOffsets(outRect: Rect, itemPosition: Int, parent: RecyclerView) {
-        val addSpacingToStart = itemPosition > 0
-        val addSpacingToEnd = itemPosition < (parent.adapter?.itemCount ?: 0) - 1
-        val isRtl = parent.layoutManager?.layoutDirection == ViewCompat.LAYOUT_DIRECTION_RTL
-        val density = parent.context.resources.displayMetrics.density
-        val halfItemSpacingPx = itemSpacingDp.toPx(density) / 2
-        if (!isRtl) {
-            outRect.left = if (addSpacingToStart) halfItemSpacingPx else 0
-            outRect.right = if (addSpacingToEnd) halfItemSpacingPx else 0
-        } else {
-            outRect.left = if (addSpacingToEnd) halfItemSpacingPx else 0
-            outRect.right = if (addSpacingToStart) halfItemSpacingPx else 0
-        }
-    }
-
-    private fun Int.toPx(density: Float): Int {
-        return (this * density).toInt()
-    }
-
-    companion object {
-        const val TAB_ITEM_SPACING_DP = 12
-        const val ITEM_SPACING_DP = 8
-    }
-}
diff --git a/src/com/android/customization/picker/common/ui/view/SingleRowListItemSpacing.kt b/src/com/android/customization/picker/common/ui/view/SingleRowListItemSpacing.kt
new file mode 100644
index 00000000..5faf248e
--- /dev/null
+++ b/src/com/android/customization/picker/common/ui/view/SingleRowListItemSpacing.kt
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
+package com.android.customization.picker.common.ui.view
+
+import android.graphics.Rect
+import android.view.View
+import androidx.recyclerview.widget.RecyclerView
+
+/** Item spacing used by the horizontal RecyclerView with only 1 row. */
+class SingleRowListItemSpacing(
+    private val edgeItemSpacePx: Int,
+    private val itemHorizontalSpacePx: Int,
+) : RecyclerView.ItemDecoration() {
+    override fun getItemOffsets(
+        outRect: Rect,
+        view: View,
+        parent: RecyclerView,
+        state: RecyclerView.State,
+    ) {
+        val itemIndex = parent.getChildAdapterPosition(view)
+        val itemCount = parent.adapter?.itemCount ?: 0
+        val isRtl = parent.layoutManager?.layoutDirection == View.LAYOUT_DIRECTION_RTL
+        when (itemIndex) {
+            0 -> {
+                outRect.left = if (!isRtl) edgeItemSpacePx else itemHorizontalSpacePx
+                outRect.right = if (isRtl) edgeItemSpacePx else itemHorizontalSpacePx
+            }
+            itemCount - 1 -> {
+                outRect.right = if (!isRtl) edgeItemSpacePx else itemHorizontalSpacePx
+                outRect.left = if (isRtl) edgeItemSpacePx else itemHorizontalSpacePx
+            }
+            else -> {
+                outRect.left = itemHorizontalSpacePx
+                outRect.right = itemHorizontalSpacePx
+            }
+        }
+    }
+}
diff --git a/src/com/android/customization/picker/grid/data/repository/GridRepository.kt b/src/com/android/customization/picker/grid/data/repository/GridRepository.kt
index f3844294..dc308db4 100644
--- a/src/com/android/customization/picker/grid/data/repository/GridRepository.kt
+++ b/src/com/android/customization/picker/grid/data/repository/GridRepository.kt
@@ -30,6 +30,8 @@ import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.map
 import kotlinx.coroutines.flow.stateIn
 import kotlinx.coroutines.suspendCancellableCoroutine
@@ -37,11 +39,17 @@ import kotlinx.coroutines.withContext
 
 interface GridRepository {
     suspend fun isAvailable(): Boolean
+
     fun getOptionChanges(): Flow<Unit>
+
     suspend fun getOptions(): GridOptionItemsModel
-    fun getSelectedOption(): GridOption?
+
+    fun getSelectedOption(): StateFlow<GridOption?>
+
     fun applySelectedOption(callback: Callback)
+
     fun clearSelectedOption()
+
     fun isSelectedOptionApplied(): Boolean
 }
 
@@ -63,7 +71,7 @@ class GridRepositoryImpl(
 
     private var appliedOption: GridOption? = null
 
-    override fun getSelectedOption() = selectedOption.value
+    override fun getSelectedOption() = selectedOption.asStateFlow()
 
     override suspend fun getOptions(): GridOptionItemsModel {
         return withContext(backgroundDispatcher) {
@@ -133,6 +141,7 @@ class GridRepositoryImpl(
                         option,
                         object : CustomizationManager.Callback {
                             override fun onSuccess() {
+                                selectedOption.value = option
                                 continuation.resume(true)
                             }
 
@@ -147,7 +156,7 @@ class GridRepositoryImpl(
     }
 
     override fun applySelectedOption(callback: Callback) {
-        val option = getSelectedOption()
+        val option = getSelectedOption().value
         manager.apply(
             option,
             if (isGridApplyButtonEnabled) {
diff --git a/src/com/android/customization/picker/grid/data/repository/GridRepository2.kt b/src/com/android/customization/picker/grid/data/repository/GridRepository2.kt
new file mode 100644
index 00000000..8ce4374c
--- /dev/null
+++ b/src/com/android/customization/picker/grid/data/repository/GridRepository2.kt
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
+ *
+ */
+
+package com.android.customization.picker.grid.data.repository
+
+import com.android.customization.model.grid.GridOptionModel
+import com.android.customization.model.grid.GridOptionsManager2
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.withContext
+
+@Singleton
+class GridRepository2
+@Inject
+constructor(
+    private val manager: GridOptionsManager2,
+    @BackgroundDispatcher private val bgScope: CoroutineScope,
+    @BackgroundDispatcher private val bgDispatcher: CoroutineDispatcher,
+) {
+
+    suspend fun isGridOptionAvailable(): Boolean =
+        withContext(bgDispatcher) { manager.isGridOptionAvailable() }
+
+    private val _gridOptions = MutableStateFlow<List<GridOptionModel>?>(null)
+
+    init {
+        bgScope.launch {
+            val options = manager.getGridOptions()
+            _gridOptions.value = options
+        }
+    }
+
+    val gridOptions: StateFlow<List<GridOptionModel>?> = _gridOptions.asStateFlow()
+
+    val selectedGridOption: Flow<GridOptionModel?> =
+        gridOptions.map { gridOptions -> gridOptions?.firstOrNull { it.isCurrent } }
+
+    suspend fun applySelectedOption(key: String) =
+        withContext(bgDispatcher) {
+            manager.applyGridOption(key)
+            // After applying new grid option, we should query and update the grid options again.
+            _gridOptions.value = manager.getGridOptions()
+        }
+}
diff --git a/src/com/android/customization/picker/grid/domain/interactor/GridInteractor.kt b/src/com/android/customization/picker/grid/domain/interactor/GridInteractor.kt
index 02e16ddf..015bcdf1 100644
--- a/src/com/android/customization/picker/grid/domain/interactor/GridInteractor.kt
+++ b/src/com/android/customization/picker/grid/domain/interactor/GridInteractor.kt
@@ -18,7 +18,6 @@
 package com.android.customization.picker.grid.domain.interactor
 
 import com.android.customization.model.CustomizationManager
-import com.android.customization.model.grid.GridOption
 import com.android.customization.picker.grid.data.repository.GridRepository
 import com.android.customization.picker.grid.shared.model.GridOptionItemModel
 import com.android.customization.picker.grid.shared.model.GridOptionItemsModel
@@ -75,7 +74,7 @@ class GridInteractor(
         }
     }
 
-    fun getSelectOptionNonSuspend(): GridOption? = repository.getSelectedOption()
+    fun getSelectOptionStateFlow() = repository.getSelectedOption()
 
     fun clearSelectedOption() = repository.clearSelectedOption()
 
diff --git a/src/com/android/customization/picker/grid/domain/interactor/GridInteractor2.kt b/src/com/android/customization/picker/grid/domain/interactor/GridInteractor2.kt
new file mode 100644
index 00000000..30c87d8d
--- /dev/null
+++ b/src/com/android/customization/picker/grid/domain/interactor/GridInteractor2.kt
@@ -0,0 +1,37 @@
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
+package com.android.customization.picker.grid.domain.interactor
+
+import com.android.customization.picker.grid.data.repository.GridRepository2
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+class GridInteractor2
+@Inject
+constructor(
+    private val repository: GridRepository2,
+) {
+    suspend fun isGridOptionAvailable(): Boolean = repository.isGridOptionAvailable()
+
+    val gridOptions = repository.gridOptions
+
+    val selectedGridOption = repository.selectedGridOption
+
+    suspend fun applySelectedOption(key: String) = repository.applySelectedOption(key)
+}
diff --git a/src/com/android/customization/picker/grid/ui/binder/GridScreenBinder.kt b/src/com/android/customization/picker/grid/ui/binder/GridScreenBinder.kt
index 9948deec..36d16cde 100644
--- a/src/com/android/customization/picker/grid/ui/binder/GridScreenBinder.kt
+++ b/src/com/android/customization/picker/grid/ui/binder/GridScreenBinder.kt
@@ -26,10 +26,10 @@ import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
 import androidx.recyclerview.widget.LinearLayoutManager
 import androidx.recyclerview.widget.RecyclerView
-import com.android.customization.picker.common.ui.view.ItemSpacing
 import com.android.customization.picker.grid.ui.viewmodel.GridIconViewModel
 import com.android.customization.picker.grid.ui.viewmodel.GridScreenViewModel
 import com.android.themepicker.R
+import com.android.wallpaper.picker.common.ui.view.ItemSpacing
 import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter
 import com.android.wallpaper.picker.option.ui.binder.OptionItemBinder
 import kotlinx.coroutines.CoroutineDispatcher
diff --git a/src/com/android/customization/picker/grid/ui/fragment/GridFragment.kt b/src/com/android/customization/picker/grid/ui/fragment/GridFragment.kt
index b48f41a3..7637994e 100644
--- a/src/com/android/customization/picker/grid/ui/fragment/GridFragment.kt
+++ b/src/com/android/customization/picker/grid/ui/fragment/GridFragment.kt
@@ -22,10 +22,14 @@ import android.util.Log
 import android.view.LayoutInflater
 import android.view.View
 import android.view.ViewGroup
+import android.view.ViewGroup.MarginLayoutParams
 import android.widget.Button
 import android.widget.Toast
 import androidx.core.content.ContextCompat
+import androidx.core.view.ViewCompat
+import androidx.core.view.WindowInsetsCompat
 import androidx.core.view.isVisible
+import androidx.core.view.updateLayoutParams
 import androidx.lifecycle.ViewModelProvider
 import androidx.transition.Transition
 import androidx.transition.doOnStart
@@ -66,6 +70,14 @@ class GridFragment : AppbarFragment() {
                 container,
                 false,
             )
+        ViewCompat.setOnApplyWindowInsetsListener(view) { v, windowInsets ->
+            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
+            v.updateLayoutParams<MarginLayoutParams> {
+                topMargin = insets.top
+                bottomMargin = insets.bottom
+            }
+            WindowInsetsCompat.CONSUMED
+        }
         setUpToolbar(view)
 
         val isGridApplyButtonEnabled = BaseFlags.get().isGridApplyButtonEnabled(requireContext())
@@ -115,7 +127,7 @@ class GridFragment : AppbarFragment() {
                                     context,
                                     getString(
                                         R.string.toast_of_changing_grid,
-                                        gridInteractor.getSelectOptionNonSuspend()?.title
+                                        gridInteractor.getSelectOptionStateFlow().value?.title
                                     ),
                                     Toast.LENGTH_SHORT
                                 )
@@ -128,7 +140,7 @@ class GridFragment : AppbarFragment() {
                             val errorMsg =
                                 getString(
                                     R.string.toast_of_failure_to_change_grid,
-                                    gridInteractor.getSelectOptionNonSuspend()?.title
+                                    gridInteractor.getSelectOptionStateFlow().value?.title
                                 )
                             Toast.makeText(context, errorMsg, Toast.LENGTH_SHORT).show()
                             Log.e(TAG, errorMsg, throwable)
@@ -178,7 +190,10 @@ class GridFragment : AppbarFragment() {
                         ),
                     initialExtrasProvider = {
                         val bundle = Bundle()
-                        bundle.putString("name", gridInteractor.getSelectOptionNonSuspend()?.name)
+                        bundle.putString(
+                            "name",
+                            gridInteractor.getSelectOptionStateFlow().value?.name
+                        )
                         bundle
                     },
                     wallpaperInfoProvider = {
diff --git a/src/com/android/customization/picker/grid/ui/section/GridSectionController.java b/src/com/android/customization/picker/grid/ui/section/GridSectionController.java
index 0e156096..bc668128 100644
--- a/src/com/android/customization/picker/grid/ui/section/GridSectionController.java
+++ b/src/com/android/customization/picker/grid/ui/section/GridSectionController.java
@@ -51,8 +51,7 @@ public class GridSectionController implements CustomizationSectionController<Gri
     public GridSectionController(
             GridOptionsManager gridOptionsManager,
             CustomizationSectionNavigationController sectionNavigationController,
-            LifecycleOwner lifecycleOwner,
-            boolean isRevampedUiEnabled) {
+            LifecycleOwner lifecycleOwner) {
         mGridOptionsManager = gridOptionsManager;
         mSectionNavigationController = sectionNavigationController;
         mLifecycleOwner = lifecycleOwner;
diff --git a/src/com/android/customization/picker/preview/ui/section/PreviewWithClockCarouselSectionController.kt b/src/com/android/customization/picker/preview/ui/section/PreviewWithClockCarouselSectionController.kt
index e1f8df25..db43f4b5 100644
--- a/src/com/android/customization/picker/preview/ui/section/PreviewWithClockCarouselSectionController.kt
+++ b/src/com/android/customization/picker/preview/ui/section/PreviewWithClockCarouselSectionController.kt
@@ -39,6 +39,7 @@ import com.android.customization.picker.clock.ui.view.ClockCarouselView
 import com.android.customization.picker.clock.ui.view.ClockViewFactory
 import com.android.customization.picker.clock.ui.viewmodel.ClockCarouselViewModel
 import com.android.customization.picker.color.domain.interactor.ColorPickerInteractor
+import com.android.customization.picker.grid.domain.interactor.GridInteractor
 import com.android.themepicker.R
 import com.android.wallpaper.model.CustomizationSectionController
 import com.android.wallpaper.model.CustomizationSectionController.CustomizationSectionNavigationController
@@ -72,6 +73,7 @@ class PreviewWithClockCarouselSectionController(
     private val navigationController: CustomizationSectionNavigationController,
     wallpaperInteractor: WallpaperInteractor,
     themedIconInteractor: ThemedIconInteractor,
+    gridInteractor: GridInteractor,
     colorPickerInteractor: ColorPickerInteractor,
     wallpaperManager: WallpaperManager,
     private val isTwoPaneAndSmallWidth: Boolean,
@@ -87,6 +89,7 @@ class PreviewWithClockCarouselSectionController(
         wallpaperPreviewNavigator,
         wallpaperInteractor,
         themedIconInteractor,
+        gridInteractor,
         colorPickerInteractor,
         wallpaperManager,
         isTwoPaneAndSmallWidth,
diff --git a/src/com/android/customization/picker/preview/ui/section/PreviewWithThemeSectionController.kt b/src/com/android/customization/picker/preview/ui/section/PreviewWithThemeSectionController.kt
index 78e37451..cd3e702a 100644
--- a/src/com/android/customization/picker/preview/ui/section/PreviewWithThemeSectionController.kt
+++ b/src/com/android/customization/picker/preview/ui/section/PreviewWithThemeSectionController.kt
@@ -23,6 +23,7 @@ import android.content.Context
 import androidx.lifecycle.LifecycleOwner
 import com.android.customization.model.themedicon.domain.interactor.ThemedIconInteractor
 import com.android.customization.picker.color.domain.interactor.ColorPickerInteractor
+import com.android.customization.picker.grid.domain.interactor.GridInteractor
 import com.android.customization.picker.preview.ui.viewmodel.PreviewWithThemeViewModel
 import com.android.wallpaper.R
 import com.android.wallpaper.model.Screen
@@ -52,6 +53,7 @@ open class PreviewWithThemeSectionController(
     wallpaperPreviewNavigator: WallpaperPreviewNavigator,
     private val wallpaperInteractor: WallpaperInteractor,
     private val themedIconInteractor: ThemedIconInteractor,
+    private val gridInteractor: GridInteractor,
     private val colorPickerInteractor: ColorPickerInteractor,
     wallpaperManager: WallpaperManager,
     isTwoPaneAndSmallWidth: Boolean,
@@ -121,6 +123,7 @@ open class PreviewWithThemeSectionController(
             initialExtrasProvider = { getInitialExtras(isOnLockScreen) },
             wallpaperInteractor = wallpaperInteractor,
             themedIconInteractor = themedIconInteractor,
+            gridInteractor = gridInteractor,
             colorPickerInteractor = colorPickerInteractor,
             screen = screen,
         )
diff --git a/src/com/android/customization/picker/preview/ui/viewmodel/PreviewWithThemeViewModel.kt b/src/com/android/customization/picker/preview/ui/viewmodel/PreviewWithThemeViewModel.kt
index 7877f11a..331ec2ea 100644
--- a/src/com/android/customization/picker/preview/ui/viewmodel/PreviewWithThemeViewModel.kt
+++ b/src/com/android/customization/picker/preview/ui/viewmodel/PreviewWithThemeViewModel.kt
@@ -21,6 +21,7 @@ import android.app.WallpaperColors
 import android.os.Bundle
 import com.android.customization.model.themedicon.domain.interactor.ThemedIconInteractor
 import com.android.customization.picker.color.domain.interactor.ColorPickerInteractor
+import com.android.customization.picker.grid.domain.interactor.GridInteractor
 import com.android.wallpaper.model.Screen
 import com.android.wallpaper.model.WallpaperInfo
 import com.android.wallpaper.picker.customization.domain.interactor.WallpaperInteractor
@@ -28,6 +29,8 @@ import com.android.wallpaper.picker.customization.ui.viewmodel.ScreenPreviewView
 import com.android.wallpaper.util.PreviewUtils
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.merge
 
 /** A ThemePicker version of the [ScreenPreviewViewModel] */
 class PreviewWithThemeViewModel(
@@ -36,7 +39,8 @@ class PreviewWithThemeViewModel(
     wallpaperInfoProvider: suspend (forceReload: Boolean) -> WallpaperInfo?,
     onWallpaperColorChanged: (WallpaperColors?) -> Unit = {},
     wallpaperInteractor: WallpaperInteractor,
-    private val themedIconInteractor: ThemedIconInteractor? = null,
+    private val themedIconInteractor: ThemedIconInteractor,
+    private val gridInteractor: GridInteractor,
     colorPickerInteractor: ColorPickerInteractor? = null,
     screen: Screen,
 ) :
@@ -48,7 +52,11 @@ class PreviewWithThemeViewModel(
         wallpaperInteractor,
         screen,
     ) {
-    override fun workspaceUpdateEvents(): Flow<Boolean>? = themedIconInteractor?.isActivated
+    override fun workspaceUpdateEvents(): Flow<Unit> =
+        merge(
+            themedIconInteractor.isActivated.map {},
+            gridInteractor.getSelectOptionStateFlow().map {}
+        )
 
     private val wallpaperIsLoading = super.isLoading
 
diff --git a/src/com/android/customization/picker/quickaffordance/data/repository/KeyguardQuickAffordancePickerRepository.kt b/src/com/android/customization/picker/quickaffordance/data/repository/KeyguardQuickAffordancePickerRepository.kt
index 6bfe3484..ff5f8289 100644
--- a/src/com/android/customization/picker/quickaffordance/data/repository/KeyguardQuickAffordancePickerRepository.kt
+++ b/src/com/android/customization/picker/quickaffordance/data/repository/KeyguardQuickAffordancePickerRepository.kt
@@ -20,7 +20,10 @@ package com.android.customization.picker.quickaffordance.data.repository
 import com.android.customization.picker.quickaffordance.shared.model.KeyguardQuickAffordancePickerAffordanceModel as AffordanceModel
 import com.android.customization.picker.quickaffordance.shared.model.KeyguardQuickAffordancePickerSelectionModel as SelectionModel
 import com.android.customization.picker.quickaffordance.shared.model.KeyguardQuickAffordancePickerSlotModel as SlotModel
-import com.android.systemui.shared.customization.data.content.CustomizationProviderClient as Client
+import com.android.systemui.shared.customization.data.content.CustomizationProviderClient
+import com.android.wallpaper.picker.di.modules.MainDispatcher
+import javax.inject.Inject
+import javax.inject.Singleton
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.SharingStarted
@@ -31,10 +34,10 @@ import kotlinx.coroutines.flow.shareIn
  * Abstracts access to application state related to functionality for selecting, picking, or setting
  * lock screen quick affordances.
  */
-class KeyguardQuickAffordancePickerRepository(
-    private val client: Client,
-    private val scope: CoroutineScope
-) {
+@Singleton
+class KeyguardQuickAffordancePickerRepository
+@Inject
+constructor(client: CustomizationProviderClient, @MainDispatcher mainScope: CoroutineScope) {
     /** List of slots available on the device. */
     val slots: Flow<List<SlotModel>> =
         client.observeSlots().map { slots -> slots.map { slot -> slot.toModel() } }
@@ -44,23 +47,23 @@ class KeyguardQuickAffordancePickerRepository(
         client
             .observeAffordances()
             .map { affordances -> affordances.map { affordance -> affordance.toModel() } }
-            .shareIn(scope, replay = 1, started = SharingStarted.Lazily)
+            .shareIn(mainScope, replay = 1, started = SharingStarted.Lazily)
 
     /** List of slot-affordance pairs, modeling what the user has currently chosen for each slot. */
     val selections: Flow<List<SelectionModel>> =
         client
             .observeSelections()
             .map { selections -> selections.map { selection -> selection.toModel() } }
-            .shareIn(scope, replay = 1, started = SharingStarted.Lazily)
+            .shareIn(mainScope, replay = 1, started = SharingStarted.Lazily)
 
-    private fun Client.Slot.toModel(): SlotModel {
+    private fun CustomizationProviderClient.Slot.toModel(): SlotModel {
         return SlotModel(
             id = id,
             maxSelectedQuickAffordances = capacity,
         )
     }
 
-    private fun Client.Affordance.toModel(): AffordanceModel {
+    private fun CustomizationProviderClient.Affordance.toModel(): AffordanceModel {
         return AffordanceModel(
             id = id,
             name = name,
@@ -73,7 +76,7 @@ class KeyguardQuickAffordancePickerRepository(
         )
     }
 
-    private fun Client.Selection.toModel(): SelectionModel {
+    private fun CustomizationProviderClient.Selection.toModel(): SelectionModel {
         return SelectionModel(
             slotId = slotId,
             affordanceId = affordanceId,
diff --git a/src/com/android/customization/picker/quickaffordance/domain/interactor/KeyguardQuickAffordancePickerInteractor.kt b/src/com/android/customization/picker/quickaffordance/domain/interactor/KeyguardQuickAffordancePickerInteractor.kt
index 3eca6241..b17b939a 100644
--- a/src/com/android/customization/picker/quickaffordance/domain/interactor/KeyguardQuickAffordancePickerInteractor.kt
+++ b/src/com/android/customization/picker/quickaffordance/domain/interactor/KeyguardQuickAffordancePickerInteractor.kt
@@ -23,18 +23,22 @@ import com.android.customization.picker.quickaffordance.data.repository.Keyguard
 import com.android.customization.picker.quickaffordance.shared.model.KeyguardQuickAffordancePickerAffordanceModel as AffordanceModel
 import com.android.customization.picker.quickaffordance.shared.model.KeyguardQuickAffordancePickerSelectionModel as SelectionModel
 import com.android.customization.picker.quickaffordance.shared.model.KeyguardQuickAffordancePickerSlotModel as SlotModel
-import com.android.systemui.shared.customization.data.content.CustomizationProviderClient as Client
-import javax.inject.Provider
+import com.android.systemui.shared.customization.data.content.CustomizationProviderClient
+import javax.inject.Inject
+import javax.inject.Singleton
 import kotlinx.coroutines.flow.Flow
 
 /**
  * Single entry-point for all application state and business logic related to quick affordances on
  * the lock screen.
  */
-class KeyguardQuickAffordancePickerInteractor(
-    private val repository: KeyguardQuickAffordancePickerRepository,
-    private val client: Client,
-    private val snapshotRestorer: Provider<KeyguardQuickAffordanceSnapshotRestorer>,
+@Singleton
+class KeyguardQuickAffordancePickerInteractor
+@Inject
+constructor(
+    repository: KeyguardQuickAffordancePickerRepository,
+    private val client: CustomizationProviderClient,
+    private val snapshotRestorer: KeyguardQuickAffordanceSnapshotRestorer,
 ) {
     /** List of slots available on the device. */
     val slots: Flow<List<SlotModel>> = repository.slots
@@ -60,7 +64,7 @@ class KeyguardQuickAffordancePickerInteractor(
             affordanceId = affordanceId,
         )
 
-        snapshotRestorer.get().storeSnapshot()
+        snapshotRestorer.storeSnapshot()
     }
 
     /** Unselects all affordances from the slot with the given ID. */
@@ -69,7 +73,7 @@ class KeyguardQuickAffordancePickerInteractor(
             slotId = slotId,
         )
 
-        snapshotRestorer.get().storeSnapshot()
+        snapshotRestorer.storeSnapshot()
     }
 
     /** Unselects all affordances from all slots. */
diff --git a/src/com/android/customization/picker/quickaffordance/domain/interactor/KeyguardQuickAffordanceSnapshotRestorer.kt b/src/com/android/customization/picker/quickaffordance/domain/interactor/KeyguardQuickAffordanceSnapshotRestorer.kt
index fee0cb51..f467989a 100644
--- a/src/com/android/customization/picker/quickaffordance/domain/interactor/KeyguardQuickAffordanceSnapshotRestorer.kt
+++ b/src/com/android/customization/picker/quickaffordance/domain/interactor/KeyguardQuickAffordanceSnapshotRestorer.kt
@@ -21,10 +21,14 @@ import com.android.systemui.shared.customization.data.content.CustomizationProvi
 import com.android.wallpaper.picker.undo.domain.interactor.SnapshotRestorer
 import com.android.wallpaper.picker.undo.domain.interactor.SnapshotStore
 import com.android.wallpaper.picker.undo.shared.model.RestorableSnapshot
+import javax.inject.Inject
+import javax.inject.Singleton
 
 /** Handles state restoration for the quick affordances system. */
-class KeyguardQuickAffordanceSnapshotRestorer(
-    private val interactor: KeyguardQuickAffordancePickerInteractor,
+@Singleton
+class KeyguardQuickAffordanceSnapshotRestorer
+@Inject
+constructor(
     private val client: CustomizationProviderClient,
 ) : SnapshotRestorer {
 
@@ -43,7 +47,7 @@ class KeyguardQuickAffordanceSnapshotRestorer(
 
     override suspend fun restoreToSnapshot(snapshot: RestorableSnapshot) {
         // reset all current selections
-        interactor.unselectAll()
+        client.querySlots().forEach { client.deleteAllSelections(it.id) }
 
         val allSelections = checkNotNull(snapshot.args[KEY_SELECTIONS])
         if (allSelections.isEmpty()) return
@@ -55,9 +59,9 @@ class KeyguardQuickAffordanceSnapshotRestorer(
             }
 
         selections.forEach { (slotId, affordanceId) ->
-            interactor.select(
-                slotId,
-                affordanceId,
+            client.insertSelection(
+                slotId = slotId,
+                affordanceId = affordanceId,
             )
         }
     }
diff --git a/src/com/android/customization/picker/quickaffordance/ui/binder/KeyguardQuickAffordancePickerBinder.kt b/src/com/android/customization/picker/quickaffordance/ui/binder/KeyguardQuickAffordancePickerBinder.kt
index 3b583f38..9f3458ce 100644
--- a/src/com/android/customization/picker/quickaffordance/ui/binder/KeyguardQuickAffordancePickerBinder.kt
+++ b/src/com/android/customization/picker/quickaffordance/ui/binder/KeyguardQuickAffordancePickerBinder.kt
@@ -31,7 +31,6 @@ import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
 import androidx.recyclerview.widget.LinearLayoutManager
 import androidx.recyclerview.widget.RecyclerView
-import com.android.customization.picker.common.ui.view.ItemSpacing
 import com.android.customization.picker.quickaffordance.ui.adapter.SlotTabAdapter
 import com.android.customization.picker.quickaffordance.ui.viewmodel.KeyguardQuickAffordancePickerViewModel
 import com.android.themepicker.R
@@ -39,6 +38,7 @@ import com.android.wallpaper.picker.common.dialog.ui.viewbinder.DialogViewBinder
 import com.android.wallpaper.picker.common.dialog.ui.viewmodel.DialogViewModel
 import com.android.wallpaper.picker.common.icon.ui.viewbinder.IconViewBinder
 import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
+import com.android.wallpaper.picker.common.ui.view.ItemSpacing
 import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.flow.collectIndexed
diff --git a/src/com/android/customization/picker/quickaffordance/ui/fragment/KeyguardQuickAffordancePickerFragment.kt b/src/com/android/customization/picker/quickaffordance/ui/fragment/KeyguardQuickAffordancePickerFragment.kt
index 8b1c44ae..f9925b42 100644
--- a/src/com/android/customization/picker/quickaffordance/ui/fragment/KeyguardQuickAffordancePickerFragment.kt
+++ b/src/com/android/customization/picker/quickaffordance/ui/fragment/KeyguardQuickAffordancePickerFragment.kt
@@ -21,8 +21,12 @@ import android.os.Bundle
 import android.view.LayoutInflater
 import android.view.View
 import android.view.ViewGroup
+import android.view.ViewGroup.MarginLayoutParams
 import androidx.core.content.ContextCompat
+import androidx.core.view.ViewCompat
+import androidx.core.view.WindowInsetsCompat
 import androidx.core.view.isVisible
+import androidx.core.view.updateLayoutParams
 import androidx.lifecycle.ViewModelProvider
 import androidx.lifecycle.get
 import androidx.transition.Transition
@@ -38,6 +42,7 @@ import com.android.wallpaper.picker.AppbarFragment
 class KeyguardQuickAffordancePickerFragment : AppbarFragment() {
     companion object {
         const val DESTINATION_ID = "quick_affordances"
+
         @JvmStatic
         fun newInstance(): KeyguardQuickAffordancePickerFragment {
             return KeyguardQuickAffordancePickerFragment()
@@ -55,7 +60,16 @@ class KeyguardQuickAffordancePickerFragment : AppbarFragment() {
                 container,
                 false,
             )
+        ViewCompat.setOnApplyWindowInsetsListener(view) { v, windowInsets ->
+            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
+            v.updateLayoutParams<MarginLayoutParams> {
+                topMargin = insets.top
+                bottomMargin = insets.bottom
+            }
+            WindowInsetsCompat.CONSUMED
+        }
         setUpToolbar(view)
+
         val injector = InjectorProvider.getInjector() as ThemePickerInjector
         val viewModel: KeyguardQuickAffordancePickerViewModel =
             ViewModelProvider(
diff --git a/src/com/android/customization/picker/settings/data/repository/ColorContrastSectionRepository.kt b/src/com/android/customization/picker/settings/data/repository/ColorContrastSectionRepository.kt
index 85cf307b..6d5b0bc0 100644
--- a/src/com/android/customization/picker/settings/data/repository/ColorContrastSectionRepository.kt
+++ b/src/com/android/customization/picker/settings/data/repository/ColorContrastSectionRepository.kt
@@ -17,6 +17,7 @@
 package com.android.customization.picker.settings.data.repository
 
 import android.app.UiModeManager
+import android.app.UiModeManager.ContrastUtils
 import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
 import com.android.wallpaper.system.UiModeManagerWrapper
 import java.util.concurrent.Executor
@@ -35,16 +36,18 @@ constructor(
     uiModeManager: UiModeManagerWrapper,
     @BackgroundDispatcher bgDispatcher: CoroutineDispatcher,
 ) {
-    var contrast: Flow<Float> = callbackFlow {
+    var contrast: Flow<Int> = callbackFlow {
         val executor: Executor = bgDispatcher.asExecutor()
         val listener =
             UiModeManager.ContrastChangeListener { contrast ->
                 // Emit the new contrast value whenever it changes
-                trySend(contrast)
+                trySend(ContrastUtils.toContrastLevel(contrast))
             }
 
         // Emit the current contrast value immediately
-        uiModeManager.getContrast()?.let { currentContrast -> trySend(currentContrast) }
+        uiModeManager.getContrast()?.let { currentContrast ->
+            trySend(ContrastUtils.toContrastLevel(currentContrast))
+        }
 
         uiModeManager.addContrastChangeListener(executor, listener)
 
diff --git a/src/com/android/customization/picker/settings/domain/interactor/ColorContrastSectionInteractor.kt b/src/com/android/customization/picker/settings/domain/interactor/ColorContrastSectionInteractor.kt
index 003d4d09..c4ccfb31 100644
--- a/src/com/android/customization/picker/settings/domain/interactor/ColorContrastSectionInteractor.kt
+++ b/src/com/android/customization/picker/settings/domain/interactor/ColorContrastSectionInteractor.kt
@@ -25,5 +25,5 @@ import kotlinx.coroutines.flow.Flow
 class ColorContrastSectionInteractor
 @Inject
 constructor(colorContrastSectionRepository: ColorContrastSectionRepository) {
-    val contrast: Flow<Float> = colorContrastSectionRepository.contrast
+    val contrast: Flow<Int> = colorContrastSectionRepository.contrast
 }
diff --git a/src/com/android/customization/picker/settings/ui/viewmodel/ColorContrastSectionViewModel.kt b/src/com/android/customization/picker/settings/ui/viewmodel/ColorContrastSectionViewModel.kt
index ecbe9d19..3ea63cb4 100644
--- a/src/com/android/customization/picker/settings/ui/viewmodel/ColorContrastSectionViewModel.kt
+++ b/src/com/android/customization/picker/settings/ui/viewmodel/ColorContrastSectionViewModel.kt
@@ -16,6 +16,10 @@
 
 package com.android.customization.picker.settings.ui.viewmodel
 
+import android.app.UiModeManager.ContrastUtils.CONTRAST_LEVEL_HIGH
+import android.app.UiModeManager.ContrastUtils.CONTRAST_LEVEL_MEDIUM
+import android.app.UiModeManager.ContrastUtils.CONTRAST_LEVEL_STANDARD
+import android.util.Log
 import androidx.lifecycle.ViewModel
 import androidx.lifecycle.ViewModelProvider
 import com.android.customization.picker.settings.domain.interactor.ColorContrastSectionInteractor
@@ -28,62 +32,54 @@ import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.map
 
 class ColorContrastSectionViewModel
-private constructor(
-    colorContrastSectionInteractor: ColorContrastSectionInteractor,
-) : ViewModel() {
+private constructor(colorContrastSectionInteractor: ColorContrastSectionInteractor) : ViewModel() {
 
     val summary: Flow<ColorContrastSectionDataViewModel> =
         colorContrastSectionInteractor.contrast.map { contrastValue ->
             when (contrastValue) {
-                ContrastValue.STANDARD.value ->
+                CONTRAST_LEVEL_STANDARD ->
                     ColorContrastSectionDataViewModel(
                         Text.Resource(R.string.color_contrast_default_title),
                         Icon.Resource(
                             res = R.drawable.ic_contrast_standard,
                             contentDescription = null,
-                        )
+                        ),
                     )
-                ContrastValue.MEDIUM.value ->
+                CONTRAST_LEVEL_MEDIUM ->
                     ColorContrastSectionDataViewModel(
                         Text.Resource(R.string.color_contrast_medium_title),
                         Icon.Resource(
                             res = R.drawable.ic_contrast_medium,
                             contentDescription = null,
-                        )
+                        ),
                     )
-                ContrastValue.HIGH.value ->
+                CONTRAST_LEVEL_HIGH ->
                     ColorContrastSectionDataViewModel(
                         Text.Resource(R.string.color_contrast_high_title),
-                        Icon.Resource(
-                            res = R.drawable.ic_contrast_high,
-                            contentDescription = null,
-                        )
+                        Icon.Resource(res = R.drawable.ic_contrast_high, contentDescription = null),
                     )
                 else -> {
-                    println("Invalid contrast value: $contrastValue")
-                    throw IllegalArgumentException("Invalid contrast value")
+                    Log.e(TAG, "Invalid contrast value: $contrastValue")
+                    throw IllegalArgumentException("Invalid contrast value: $contrastValue")
                 }
             }
         }
 
-    enum class ContrastValue(val value: Float) {
-        STANDARD(0f),
-        MEDIUM(0.5f),
-        HIGH(1f)
-    }
-
     @Singleton
     class Factory
     @Inject
-    constructor(
-        private val colorContrastSectionInteractor: ColorContrastSectionInteractor,
-    ) : ViewModelProvider.Factory {
+    constructor(private val colorContrastSectionInteractor: ColorContrastSectionInteractor) :
+        ViewModelProvider.Factory {
         override fun <T : ViewModel> create(modelClass: Class<T>): T {
             @Suppress("UNCHECKED_CAST")
             return ColorContrastSectionViewModel(
-                colorContrastSectionInteractor = colorContrastSectionInteractor,
+                colorContrastSectionInteractor = colorContrastSectionInteractor
             )
                 as T
         }
     }
+
+    companion object {
+        private const val TAG = "ColorContrastSectionViewModel"
+    }
 }
diff --git a/src/com/android/wallpaper/customization/ui/binder/ClockFloatingSheetBinder.kt b/src/com/android/wallpaper/customization/ui/binder/ClockFloatingSheetBinder.kt
new file mode 100644
index 00000000..a8d06a59
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/binder/ClockFloatingSheetBinder.kt
@@ -0,0 +1,311 @@
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
+import android.annotation.DrawableRes
+import android.content.Context
+import android.content.res.Configuration
+import android.graphics.drawable.Drawable
+import android.view.View
+import android.view.ViewGroup
+import android.widget.ImageView
+import android.widget.SeekBar
+import androidx.core.content.res.ResourcesCompat
+import androidx.core.view.doOnLayout
+import androidx.core.view.isVisible
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import androidx.recyclerview.widget.GridLayoutManager
+import androidx.recyclerview.widget.RecyclerView
+import com.android.customization.picker.clock.shared.ClockSize
+import com.android.customization.picker.color.ui.binder.ColorOptionIconBinder
+import com.android.customization.picker.color.ui.view.ColorOptionIconView
+import com.android.customization.picker.color.ui.viewmodel.ColorOptionIconViewModel
+import com.android.customization.picker.common.ui.view.DoubleRowListItemSpacing
+import com.android.themepicker.R
+import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptionUtil.ThemePickerLockCustomizationOption.CLOCK
+import com.android.wallpaper.customization.ui.viewmodel.ClockFloatingSheetHeightsViewModel
+import com.android.wallpaper.customization.ui.viewmodel.ClockPickerViewModel.Tab.COLOR
+import com.android.wallpaper.customization.ui.viewmodel.ClockPickerViewModel.Tab.SIZE
+import com.android.wallpaper.customization.ui.viewmodel.ClockPickerViewModel.Tab.STYLE
+import com.android.wallpaper.customization.ui.viewmodel.ThemePickerCustomizationOptionsViewModel
+import com.android.wallpaper.picker.customization.ui.view.FloatingToolbar
+import com.android.wallpaper.picker.customization.ui.view.adapter.FloatingToolbarTabAdapter
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
+import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter
+import java.lang.ref.WeakReference
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.launch
+
+object ClockFloatingSheetBinder {
+    private const val SLIDER_ENABLED_ALPHA = 1f
+    private const val SLIDER_DISABLED_ALPHA = .3f
+    private const val ANIMATION_DURATION = 200L
+
+    private val _clockFloatingSheetHeights: MutableStateFlow<ClockFloatingSheetHeightsViewModel?> =
+        MutableStateFlow(null)
+    private val clockFloatingSheetHeights: Flow<ClockFloatingSheetHeightsViewModel?> =
+        _clockFloatingSheetHeights.asStateFlow()
+
+    fun bind(
+        view: View,
+        optionsViewModel: ThemePickerCustomizationOptionsViewModel,
+        colorUpdateViewModel: ColorUpdateViewModel,
+        lifecycleOwner: LifecycleOwner,
+    ) {
+        val viewModel = optionsViewModel.clockPickerViewModel
+
+        val appContext = view.context.applicationContext
+
+        val tabs = view.requireViewById<FloatingToolbar>(R.id.floating_toolbar)
+        val tabAdapter =
+            FloatingToolbarTabAdapter(
+                    colorUpdateViewModel = WeakReference(colorUpdateViewModel),
+                    shouldAnimateColor = { optionsViewModel.selectedOption.value == CLOCK },
+                )
+                .also { tabs.setAdapter(it) }
+
+        val floatingSheetContainer =
+            view.requireViewById<ViewGroup>(R.id.clock_floating_sheet_content_container)
+
+        // Clock style
+        val clockStyleContent = view.requireViewById<View>(R.id.clock_floating_sheet_style_content)
+        val clockStyleAdapter = createClockStyleOptionItemAdapter(lifecycleOwner)
+        val clockStyleList =
+            view.requireViewById<RecyclerView>(R.id.clock_style_list).apply {
+                initStyleList(appContext, clockStyleAdapter)
+            }
+
+        // Clock color
+        val clockColorContent = view.requireViewById<View>(R.id.clock_floating_sheet_color_content)
+        val clockColorAdapter =
+            createClockColorOptionItemAdapter(view.resources.configuration.uiMode, lifecycleOwner)
+        val clockColorList =
+            view.requireViewById<RecyclerView>(R.id.clock_color_list).apply {
+                initColorList(appContext, clockColorAdapter)
+            }
+        val clockColorSlider: SeekBar = view.requireViewById(R.id.clock_color_slider)
+        clockColorSlider.setOnSeekBarChangeListener(
+            object : SeekBar.OnSeekBarChangeListener {
+                override fun onProgressChanged(p0: SeekBar?, progress: Int, fromUser: Boolean) {
+                    if (fromUser) {
+                        viewModel.onSliderProgressChanged(progress)
+                    }
+                }
+
+                override fun onStartTrackingTouch(seekBar: SeekBar?) = Unit
+
+                override fun onStopTrackingTouch(seekBar: SeekBar?) = Unit
+            }
+        )
+
+        // Clock size
+        val clockSizeContent = view.requireViewById<View>(R.id.clock_floating_sheet_size_content)
+        val clockSizeOptionDynamic = view.requireViewById<View>(R.id.clock_size_option_dynamic)
+        val clockSizeOptionSmall = view.requireViewById<View>(R.id.clock_size_option_small)
+
+        view.doOnLayout {
+            if (_clockFloatingSheetHeights.value == null) {
+                _clockFloatingSheetHeights.value =
+                    ClockFloatingSheetHeightsViewModel(
+                        clockStyleContentHeight = clockStyleContent.height,
+                        clockColorContentHeight = clockColorContent.height,
+                        clockSizeContentHeight = clockSizeContent.height,
+                    )
+            }
+        }
+
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                launch { viewModel.tabs.collect { tabAdapter.submitList(it) } }
+
+                launch {
+                    combine(clockFloatingSheetHeights, viewModel.selectedTab) { heights, selectedTab
+                            ->
+                            heights to selectedTab
+                        }
+                        .collect { (heights, selectedTab) ->
+                            heights ?: return@collect
+                            val targetHeight =
+                                when (selectedTab) {
+                                    STYLE -> heights.clockStyleContentHeight
+                                    COLOR -> heights.clockColorContentHeight
+                                    SIZE -> heights.clockSizeContentHeight
+                                } +
+                                    view.resources.getDimensionPixelSize(
+                                        R.dimen.floating_sheet_content_vertical_padding
+                                    ) * 2
+
+                            val animationFloatingSheet =
+                                ValueAnimator.ofInt(floatingSheetContainer.height, targetHeight)
+                            animationFloatingSheet.addUpdateListener { valueAnimator ->
+                                val value = valueAnimator.animatedValue as Int
+                                floatingSheetContainer.layoutParams =
+                                    floatingSheetContainer.layoutParams.apply { height = value }
+                            }
+                            animationFloatingSheet.setDuration(ANIMATION_DURATION)
+                            animationFloatingSheet.start()
+
+                            clockStyleContent.isVisible = selectedTab == STYLE
+                            clockColorContent.isVisible = selectedTab == COLOR
+                            clockSizeContent.isVisible = selectedTab == SIZE
+                        }
+                }
+
+                launch {
+                    viewModel.clockStyleOptions.collect { styleOptions ->
+                        clockStyleAdapter.setItems(styleOptions) {
+                            var indexToFocus = styleOptions.indexOfFirst { it.isSelected.value }
+                            indexToFocus = if (indexToFocus < 0) 0 else indexToFocus
+                            (clockStyleList.layoutManager as GridLayoutManager)
+                                .scrollToPositionWithOffset(indexToFocus, 0)
+                        }
+                    }
+                }
+
+                launch {
+                    viewModel.clockColorOptions.collect { colorOptions ->
+                        clockColorAdapter.setItems(colorOptions) {
+                            var indexToFocus = colorOptions.indexOfFirst { it.isSelected.value }
+                            indexToFocus = if (indexToFocus < 0) 0 else indexToFocus
+                            (clockColorList.layoutManager as GridLayoutManager)
+                                .scrollToPositionWithOffset(indexToFocus, 0)
+                        }
+                    }
+                }
+
+                launch {
+                    viewModel.previewingSliderProgress.collect { progress ->
+                        clockColorSlider.setProgress(progress, true)
+                    }
+                }
+
+                launch {
+                    viewModel.isSliderEnabled.collect { isEnabled ->
+                        clockColorSlider.isEnabled = isEnabled
+                        clockColorSlider.alpha =
+                            if (isEnabled) SLIDER_ENABLED_ALPHA else SLIDER_DISABLED_ALPHA
+                    }
+                }
+
+                launch {
+                    viewModel.sizeOptions.collect { sizeOptions ->
+                        sizeOptions.forEach { option ->
+                            lifecycleOwner.lifecycleScope.launch {
+                                lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                                    launch {
+                                        option.onClicked.collect { onClicked ->
+                                            when (option.size) {
+                                                ClockSize.DYNAMIC ->
+                                                    clockSizeOptionDynamic.setOnClickListener {
+                                                        onClicked?.invoke()
+                                                    }
+                                                ClockSize.SMALL ->
+                                                    clockSizeOptionSmall.setOnClickListener {
+                                                        onClicked?.invoke()
+                                                    }
+                                            }
+                                        }
+                                    }
+                                }
+                            }
+                        }
+                    }
+                }
+            }
+        }
+    }
+
+    private fun createClockStyleOptionItemAdapter(
+        lifecycleOwner: LifecycleOwner
+    ): OptionItemAdapter<Drawable> =
+        OptionItemAdapter(
+            layoutResourceId = R.layout.clock_style_option,
+            lifecycleOwner = lifecycleOwner,
+            bindIcon = { foregroundView: View, drawable: Drawable ->
+                (foregroundView as ImageView).setImageDrawable(drawable)
+            },
+        )
+
+    private fun RecyclerView.initStyleList(context: Context, adapter: OptionItemAdapter<Drawable>) {
+        apply {
+            this.adapter = adapter
+            layoutManager = GridLayoutManager(context, 2, GridLayoutManager.HORIZONTAL, false)
+            addItemDecoration(
+                DoubleRowListItemSpacing(
+                    context.resources.getDimensionPixelSize(
+                        R.dimen.floating_sheet_content_horizontal_padding
+                    ),
+                    context.resources.getDimensionPixelSize(
+                        R.dimen.floating_sheet_list_item_horizontal_space
+                    ),
+                    context.resources.getDimensionPixelSize(
+                        R.dimen.floating_sheet_list_item_vertical_space
+                    ),
+                )
+            )
+        }
+    }
+
+    private fun createClockColorOptionItemAdapter(
+        uiMode: Int,
+        lifecycleOwner: LifecycleOwner,
+    ): OptionItemAdapter<ColorOptionIconViewModel> =
+        OptionItemAdapter(
+            layoutResourceId = R.layout.color_option,
+            lifecycleOwner = lifecycleOwner,
+            bindIcon = { foregroundView: View, colorIcon: ColorOptionIconViewModel ->
+                val colorOptionIconView = foregroundView as? ColorOptionIconView
+                val night =
+                    uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
+                colorOptionIconView?.let { ColorOptionIconBinder.bind(it, colorIcon, night) }
+            },
+        )
+
+    private fun RecyclerView.initColorList(
+        context: Context,
+        adapter: OptionItemAdapter<ColorOptionIconViewModel>,
+    ) {
+        apply {
+            this.adapter = adapter
+            layoutManager = GridLayoutManager(context, 2, GridLayoutManager.HORIZONTAL, false)
+            addItemDecoration(
+                DoubleRowListItemSpacing(
+                    context.resources.getDimensionPixelSize(
+                        R.dimen.floating_sheet_content_horizontal_padding
+                    ),
+                    context.resources.getDimensionPixelSize(
+                        R.dimen.floating_sheet_list_item_horizontal_space
+                    ),
+                    context.resources.getDimensionPixelSize(
+                        R.dimen.floating_sheet_list_item_vertical_space
+                    ),
+                )
+            )
+        }
+    }
+
+    private fun getDrawable(context: Context, @DrawableRes res: Int): Drawable? {
+        return ResourcesCompat.getDrawable(context.resources, res, null)
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/binder/ColorsFloatingSheetBinder.kt b/src/com/android/wallpaper/customization/ui/binder/ColorsFloatingSheetBinder.kt
new file mode 100644
index 00000000..b06748ad
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/binder/ColorsFloatingSheetBinder.kt
@@ -0,0 +1,134 @@
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
+import android.content.Context
+import android.content.res.Configuration.UI_MODE_NIGHT_MASK
+import android.content.res.Configuration.UI_MODE_NIGHT_YES
+import android.view.View
+import android.widget.TextView
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import androidx.recyclerview.widget.GridLayoutManager
+import androidx.recyclerview.widget.LinearLayoutManager
+import androidx.recyclerview.widget.RecyclerView
+import com.android.customization.picker.color.ui.binder.ColorOptionIconBinder
+import com.android.customization.picker.color.ui.view.ColorOptionIconView
+import com.android.customization.picker.color.ui.viewmodel.ColorOptionIconViewModel
+import com.android.customization.picker.common.ui.view.DoubleRowListItemSpacing
+import com.android.themepicker.R
+import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptionUtil.ThemePickerHomeCustomizationOption.COLORS
+import com.android.wallpaper.customization.ui.viewmodel.ThemePickerCustomizationOptionsViewModel
+import com.android.wallpaper.picker.customization.ui.view.FloatingToolbar
+import com.android.wallpaper.picker.customization.ui.view.adapter.FloatingToolbarTabAdapter
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
+import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter
+import java.lang.ref.WeakReference
+import kotlinx.coroutines.launch
+
+object ColorsFloatingSheetBinder {
+
+    fun bind(
+        view: View,
+        optionsViewModel: ThemePickerCustomizationOptionsViewModel,
+        colorUpdateViewModel: ColorUpdateViewModel,
+        lifecycleOwner: LifecycleOwner,
+    ) {
+        val viewModel = optionsViewModel.colorPickerViewModel2
+
+        val subhead = view.requireViewById<TextView>(R.id.color_type_tab_subhead)
+
+        val colorsAdapter =
+            createOptionItemAdapter(view.resources.configuration.uiMode, lifecycleOwner)
+        val colorsList =
+            view.requireViewById<RecyclerView>(R.id.colors_horizontal_list).also {
+                it.initColorsList(view.context.applicationContext, colorsAdapter)
+            }
+
+        val tabs = view.requireViewById<FloatingToolbar>(R.id.floating_toolbar)
+        val tabAdapter =
+            FloatingToolbarTabAdapter(
+                    colorUpdateViewModel = WeakReference(colorUpdateViewModel),
+                    shouldAnimateColor = { optionsViewModel.selectedOption.value == COLORS }
+                )
+                .also { tabs.setAdapter(it) }
+
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                launch { viewModel.colorTypeTabs.collect { tabAdapter.submitList(it) } }
+
+                launch { viewModel.colorTypeTabSubheader.collect { subhead.text = it } }
+
+                launch {
+                    viewModel.colorOptions.collect { colorOptions ->
+                        colorsAdapter.setItems(colorOptions) {
+                            var indexToFocus = colorOptions.indexOfFirst { it.isSelected.value }
+                            indexToFocus = if (indexToFocus < 0) 0 else indexToFocus
+                            (colorsList.layoutManager as LinearLayoutManager)
+                                .scrollToPositionWithOffset(indexToFocus, 0)
+                        }
+                    }
+                }
+            }
+        }
+    }
+
+    private fun createOptionItemAdapter(
+        uiMode: Int,
+        lifecycleOwner: LifecycleOwner
+    ): OptionItemAdapter<ColorOptionIconViewModel> =
+        OptionItemAdapter(
+            layoutResourceId = R.layout.color_option,
+            lifecycleOwner = lifecycleOwner,
+            bindIcon = { foregroundView: View, colorIcon: ColorOptionIconViewModel ->
+                val colorOptionIconView = foregroundView as? ColorOptionIconView
+                val night = uiMode and UI_MODE_NIGHT_MASK == UI_MODE_NIGHT_YES
+                colorOptionIconView?.let { ColorOptionIconBinder.bind(it, colorIcon, night) }
+            }
+        )
+
+    private fun RecyclerView.initColorsList(
+        context: Context,
+        adapter: OptionItemAdapter<ColorOptionIconViewModel>,
+    ) {
+        apply {
+            this.adapter = adapter
+            layoutManager =
+                GridLayoutManager(
+                    context,
+                    2,
+                    GridLayoutManager.HORIZONTAL,
+                    false,
+                )
+            addItemDecoration(
+                DoubleRowListItemSpacing(
+                    context.resources.getDimensionPixelSize(
+                        R.dimen.floating_sheet_content_horizontal_padding
+                    ),
+                    context.resources.getDimensionPixelSize(
+                        R.dimen.floating_sheet_list_item_horizontal_space
+                    ),
+                    context.resources.getDimensionPixelSize(
+                        R.dimen.floating_sheet_list_item_vertical_space
+                    ),
+                )
+            )
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/binder/ShapeAndGridFloatingSheetBinder.kt b/src/com/android/wallpaper/customization/ui/binder/ShapeAndGridFloatingSheetBinder.kt
new file mode 100644
index 00000000..7217f619
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/binder/ShapeAndGridFloatingSheetBinder.kt
@@ -0,0 +1,117 @@
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
+import android.content.Context
+import android.view.View
+import android.widget.ImageView
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import androidx.recyclerview.widget.LinearLayoutManager
+import androidx.recyclerview.widget.RecyclerView
+import com.android.customization.picker.common.ui.view.SingleRowListItemSpacing
+import com.android.customization.picker.grid.ui.binder.GridIconViewBinder
+import com.android.customization.picker.grid.ui.viewmodel.GridIconViewModel
+import com.android.wallpaper.R
+import com.android.wallpaper.customization.ui.viewmodel.ShapeAndGridPickerViewModel
+import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter
+import com.android.wallpaper.picker.option.ui.binder.OptionItemBinder
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.launch
+
+object ShapeAndGridFloatingSheetBinder {
+
+    fun bind(
+        view: View,
+        viewModel: ShapeAndGridPickerViewModel,
+        lifecycleOwner: LifecycleOwner,
+        backgroundDispatcher: CoroutineDispatcher,
+    ) {
+        val adapter = createOptionItemAdapter(view.context, lifecycleOwner, backgroundDispatcher)
+        val gridOptionList =
+            view.requireViewById<RecyclerView>(R.id.options).also {
+                it.initGridOptionList(view.context, adapter)
+            }
+
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                launch {
+                    viewModel.optionItems.collect { options ->
+                        adapter.setItems(options) {
+                            val indexToFocus =
+                                options.indexOfFirst { it.isSelected.value }.coerceAtLeast(0)
+                            (gridOptionList.layoutManager as LinearLayoutManager).scrollToPosition(
+                                indexToFocus
+                            )
+                        }
+                    }
+                }
+            }
+        }
+    }
+
+    private fun createOptionItemAdapter(
+        context: Context,
+        lifecycleOwner: LifecycleOwner,
+        backgroundDispatcher: CoroutineDispatcher,
+    ): OptionItemAdapter<GridIconViewModel> =
+        OptionItemAdapter(
+            layoutResourceId = com.android.themepicker.R.layout.grid_option,
+            lifecycleOwner = lifecycleOwner,
+            backgroundDispatcher = backgroundDispatcher,
+            foregroundTintSpec =
+                OptionItemBinder.TintSpec(
+                    selectedColor = context.getColor(R.color.system_on_surface),
+                    unselectedColor = context.getColor(R.color.system_on_surface),
+                ),
+            bindIcon = { foregroundView: View, gridIcon: GridIconViewModel ->
+                val imageView = foregroundView as? ImageView
+                imageView?.let { GridIconViewBinder.bind(imageView, gridIcon) }
+            }
+        )
+
+    private fun RecyclerView.initGridOptionList(
+        context: Context,
+        adapter: OptionItemAdapter<GridIconViewModel>,
+    ) {
+        apply {
+            this.layoutManager =
+                LinearLayoutManager(
+                    context,
+                    RecyclerView.HORIZONTAL,
+                    false,
+                )
+            addItemDecoration(
+                SingleRowListItemSpacing(
+                    edgeItemSpacePx =
+                        context.resources.getDimensionPixelSize(
+                            com.android.themepicker.R.dimen
+                                .floating_sheet_content_horizontal_padding
+                        ),
+                    itemHorizontalSpacePx =
+                        context.resources.getDimensionPixelSize(
+                            com.android.themepicker.R.dimen
+                                .floating_sheet_list_item_horizontal_space
+                        ),
+                )
+            )
+            this.adapter = adapter
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/binder/ShortcutFloatingSheetBinder.kt b/src/com/android/wallpaper/customization/ui/binder/ShortcutFloatingSheetBinder.kt
new file mode 100644
index 00000000..bc8ff967
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/binder/ShortcutFloatingSheetBinder.kt
@@ -0,0 +1,189 @@
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
+import android.app.Dialog
+import android.content.Context
+import android.view.View
+import android.widget.ImageView
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import androidx.recyclerview.widget.GridLayoutManager
+import androidx.recyclerview.widget.RecyclerView
+import com.android.customization.picker.common.ui.view.DoubleRowListItemSpacing
+import com.android.themepicker.R
+import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptionUtil.ThemePickerLockCustomizationOption.SHORTCUTS
+import com.android.wallpaper.customization.ui.viewmodel.ThemePickerCustomizationOptionsViewModel
+import com.android.wallpaper.picker.common.dialog.ui.viewbinder.DialogViewBinder
+import com.android.wallpaper.picker.common.dialog.ui.viewmodel.DialogViewModel
+import com.android.wallpaper.picker.common.icon.ui.viewbinder.IconViewBinder
+import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
+import com.android.wallpaper.picker.customization.ui.view.FloatingToolbar
+import com.android.wallpaper.picker.customization.ui.view.adapter.FloatingToolbarTabAdapter
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
+import com.android.wallpaper.picker.option.ui.adapter.OptionItemAdapter
+import java.lang.ref.WeakReference
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.flow.collectIndexed
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.distinctUntilChanged
+import kotlinx.coroutines.flow.flatMapLatest
+import kotlinx.coroutines.launch
+
+@OptIn(ExperimentalCoroutinesApi::class)
+object ShortcutFloatingSheetBinder {
+
+    fun bind(
+        view: View,
+        optionsViewModel: ThemePickerCustomizationOptionsViewModel,
+        colorUpdateViewModel: ColorUpdateViewModel,
+        lifecycleOwner: LifecycleOwner,
+    ) {
+        val viewModel = optionsViewModel.keyguardQuickAffordancePickerViewModel2
+
+        val quickAffordanceAdapter = createOptionItemAdapter(lifecycleOwner)
+        val quickAffordanceList =
+            view.requireViewById<RecyclerView>(R.id.quick_affordance_horizontal_list).also {
+                it.initQuickAffordanceList(view.context.applicationContext, quickAffordanceAdapter)
+            }
+
+        val tabs = view.requireViewById<FloatingToolbar>(R.id.floating_toolbar)
+        val tabAdapter =
+            FloatingToolbarTabAdapter(
+                    colorUpdateViewModel = WeakReference(colorUpdateViewModel),
+                    shouldAnimateColor = { optionsViewModel.selectedOption.value == SHORTCUTS }
+                )
+                .also { tabs.setAdapter(it) }
+
+        var dialog: Dialog? = null
+
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                launch { viewModel.tabs.collect { tabAdapter.submitList(it) } }
+
+                launch {
+                    viewModel.quickAffordances.collect { affordances ->
+                        quickAffordanceAdapter.setItems(affordances)
+                    }
+                }
+
+                launch {
+                    viewModel.quickAffordances
+                        .flatMapLatest { affordances ->
+                            combine(affordances.map { affordance -> affordance.isSelected }) {
+                                selectedFlags ->
+                                selectedFlags.indexOfFirst { it }
+                            }
+                        }
+                        .collectIndexed { index, selectedPosition ->
+                            // Scroll the view to show the first selected affordance.
+                            if (selectedPosition != -1) {
+                                // We use "post" because we need to give the adapter item a pass to
+                                // update the view.
+                                quickAffordanceList.post {
+                                    if (index == 0) {
+                                        // don't animate on initial collection
+                                        quickAffordanceList.scrollToPosition(selectedPosition)
+                                    } else {
+                                        quickAffordanceList.smoothScrollToPosition(selectedPosition)
+                                    }
+                                }
+                            }
+                        }
+                }
+
+                launch {
+                    viewModel.dialog.distinctUntilChanged().collect { dialogRequest ->
+                        dialog?.dismiss()
+                        dialog =
+                            if (dialogRequest != null) {
+                                showDialog(
+                                    context = view.context,
+                                    request = dialogRequest,
+                                    onDismissed = viewModel::onDialogDismissed
+                                )
+                            } else {
+                                null
+                            }
+                    }
+                }
+
+                launch {
+                    viewModel.activityStartRequests.collect { intent ->
+                        if (intent != null) {
+                            view.context.startActivity(intent)
+                            viewModel.onActivityStarted()
+                        }
+                    }
+                }
+            }
+        }
+    }
+
+    private fun showDialog(
+        context: Context,
+        request: DialogViewModel,
+        onDismissed: () -> Unit,
+    ): Dialog {
+        return DialogViewBinder.show(
+            context = context,
+            viewModel = request,
+            onDismissed = onDismissed,
+        )
+    }
+
+    private fun createOptionItemAdapter(lifecycleOwner: LifecycleOwner): OptionItemAdapter<Icon> =
+        OptionItemAdapter(
+            layoutResourceId = R.layout.quick_affordance_list_item,
+            lifecycleOwner = lifecycleOwner,
+            bindIcon = { foregroundView: View, gridIcon: Icon ->
+                val imageView = foregroundView as? ImageView
+                imageView?.let { IconViewBinder.bind(imageView, gridIcon) }
+            },
+        )
+
+    private fun RecyclerView.initQuickAffordanceList(
+        context: Context,
+        adapter: OptionItemAdapter<Icon>
+    ) {
+        apply {
+            this.adapter = adapter
+            layoutManager =
+                GridLayoutManager(
+                    context,
+                    2,
+                    GridLayoutManager.HORIZONTAL,
+                    false,
+                )
+            addItemDecoration(
+                DoubleRowListItemSpacing(
+                    context.resources.getDimensionPixelSize(
+                        R.dimen.floating_sheet_content_horizontal_padding
+                    ),
+                    context.resources.getDimensionPixelSize(
+                        R.dimen.floating_sheet_list_item_horizontal_space
+                    ),
+                    context.resources.getDimensionPixelSize(
+                        R.dimen.floating_sheet_list_item_vertical_space
+                    ),
+                )
+            )
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/binder/ThemePickerCustomizationOptionBinder.kt b/src/com/android/wallpaper/customization/ui/binder/ThemePickerCustomizationOptionBinder.kt
index 349c7c5c..e223ebc7 100644
--- a/src/com/android/wallpaper/customization/ui/binder/ThemePickerCustomizationOptionBinder.kt
+++ b/src/com/android/wallpaper/customization/ui/binder/ThemePickerCustomizationOptionBinder.kt
@@ -17,18 +17,36 @@
 package com.android.wallpaper.customization.ui.binder
 
 import android.view.View
+import android.view.ViewGroup
+import android.widget.ImageView
+import android.widget.TextView
+import androidx.core.content.ContextCompat
+import androidx.core.view.isVisible
 import androidx.lifecycle.Lifecycle
 import androidx.lifecycle.LifecycleOwner
 import androidx.lifecycle.lifecycleScope
 import androidx.lifecycle.repeatOnLifecycle
+import com.android.customization.picker.clock.shared.ClockSize
+import com.android.customization.picker.clock.ui.view.ClockHostView2
+import com.android.customization.picker.clock.ui.view.ClockViewFactory
+import com.android.customization.picker.grid.ui.binder.GridIconViewBinder
+import com.android.themepicker.R
+import com.android.wallpaper.config.BaseFlags
+import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptionUtil.ThemePickerHomeCustomizationOption
 import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptionUtil.ThemePickerLockCustomizationOption
 import com.android.wallpaper.customization.ui.viewmodel.ThemePickerCustomizationOptionsViewModel
+import com.android.wallpaper.picker.common.icon.ui.viewbinder.IconViewBinder
+import com.android.wallpaper.picker.common.text.ui.viewbinder.TextViewBinder
 import com.android.wallpaper.picker.customization.ui.binder.CustomizationOptionsBinder
 import com.android.wallpaper.picker.customization.ui.binder.DefaultCustomizationOptionsBinder
 import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil.CustomizationOption
-import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
+import com.android.wallpaper.picker.customization.ui.viewmodel.ColorUpdateViewModel
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationPickerViewModel2
 import javax.inject.Inject
 import javax.inject.Singleton
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.filterNotNull
 import kotlinx.coroutines.launch
 
 @Singleton
@@ -41,40 +59,228 @@ constructor(private val defaultCustomizationOptionsBinder: DefaultCustomizationO
         view: View,
         lockScreenCustomizationOptionEntries: List<Pair<CustomizationOption, View>>,
         homeScreenCustomizationOptionEntries: List<Pair<CustomizationOption, View>>,
-        viewModel: CustomizationOptionsViewModel,
-        lifecycleOwner: LifecycleOwner
+        customizationOptionFloatingSheetViewMap: Map<CustomizationOption, View>?,
+        viewModel: CustomizationPickerViewModel2,
+        colorUpdateViewModel: ColorUpdateViewModel,
+        lifecycleOwner: LifecycleOwner,
     ) {
         defaultCustomizationOptionsBinder.bind(
             view,
             lockScreenCustomizationOptionEntries,
             homeScreenCustomizationOptionEntries,
+            customizationOptionFloatingSheetViewMap,
             viewModel,
-            lifecycleOwner
+            colorUpdateViewModel,
+            lifecycleOwner,
         )
 
         val optionClock =
             lockScreenCustomizationOptionEntries
                 .find { it.first == ThemePickerLockCustomizationOption.CLOCK }
                 ?.second
+
         val optionShortcut =
             lockScreenCustomizationOptionEntries
                 .find { it.first == ThemePickerLockCustomizationOption.SHORTCUTS }
                 ?.second
-        viewModel as ThemePickerCustomizationOptionsViewModel
+        val optionShortcutDescription =
+            optionShortcut?.findViewById<TextView>(
+                R.id.option_entry_keyguard_quick_affordance_description
+            )
+        val optionShortcutIcon1 =
+            optionShortcut?.findViewById<ImageView>(
+                R.id.option_entry_keyguard_quick_affordance_icon_1
+            )
+        val optionShortcutIcon2 =
+            optionShortcut?.findViewById<ImageView>(
+                R.id.option_entry_keyguard_quick_affordance_icon_2
+            )
+
+        val optionColors =
+            homeScreenCustomizationOptionEntries
+                .find { it.first == ThemePickerHomeCustomizationOption.COLORS }
+                ?.second
 
+        val optionShapeAndGrid =
+            homeScreenCustomizationOptionEntries
+                .find { it.first == ThemePickerHomeCustomizationOption.APP_SHAPE_AND_GRID }
+                ?.second
+        val optionShapeAndGridDescription =
+            optionShapeAndGrid?.findViewById<TextView>(R.id.option_entry_app_grid_description)
+        val optionShapeAndGridIcon =
+            optionShapeAndGrid?.findViewById<ImageView>(R.id.option_entry_app_grid_icon)
+
+        val optionsViewModel =
+            viewModel.customizationOptionsViewModel as ThemePickerCustomizationOptionsViewModel
         lifecycleOwner.lifecycleScope.launch {
             lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                 launch {
-                    viewModel.onCustomizeClockClicked.collect {
+                    optionsViewModel.onCustomizeClockClicked.collect {
                         optionClock?.setOnClickListener { _ -> it?.invoke() }
                     }
                 }
 
                 launch {
-                    viewModel.onCustomizeShortcutClicked.collect {
+                    optionsViewModel.onCustomizeShortcutClicked.collect {
                         optionShortcut?.setOnClickListener { _ -> it?.invoke() }
                     }
                 }
+
+                launch {
+                    optionsViewModel.keyguardQuickAffordancePickerViewModel2.summary.collect {
+                        summary ->
+                        optionShortcutDescription?.let {
+                            TextViewBinder.bind(view = it, viewModel = summary.description)
+                        }
+                        summary.icon1?.let { icon ->
+                            optionShortcutIcon1?.let {
+                                IconViewBinder.bind(view = it, viewModel = icon)
+                            }
+                        }
+                        optionShortcutIcon1?.isVisible = summary.icon1 != null
+
+                        summary.icon2?.let { icon ->
+                            optionShortcutIcon2?.let {
+                                IconViewBinder.bind(view = it, viewModel = icon)
+                            }
+                        }
+                        optionShortcutIcon2?.isVisible = summary.icon2 != null
+                    }
+                }
+
+                launch {
+                    optionsViewModel.onCustomizeColorsClicked.collect {
+                        optionColors?.setOnClickListener { _ -> it?.invoke() }
+                    }
+                }
+
+                launch {
+                    optionsViewModel.onCustomizeShapeAndGridClicked.collect {
+                        optionShapeAndGrid?.setOnClickListener { _ -> it?.invoke() }
+                    }
+                }
+
+                launch {
+                    optionsViewModel.shapeAndGridPickerViewModel.selectedGridOption.collect {
+                        gridOption ->
+                        optionShapeAndGridDescription?.let {
+                            TextViewBinder.bind(it, gridOption.text)
+                        }
+                        gridOption.payload?.let { gridIconViewModel ->
+                            optionShapeAndGridIcon?.let {
+                                GridIconViewBinder.bind(view = it, viewModel = gridIconViewModel)
+                            }
+                            // TODO(b/363018910): Use ColorUpdateBinder to update color
+                            optionShapeAndGridIcon?.setColorFilter(
+                                ContextCompat.getColor(
+                                    view.context,
+                                    com.android.wallpaper.R.color.system_on_surface_variant,
+                                )
+                            )
+                        }
+                    }
+                }
+            }
+        }
+
+        customizationOptionFloatingSheetViewMap
+            ?.get(ThemePickerLockCustomizationOption.CLOCK)
+            ?.let {
+                ClockFloatingSheetBinder.bind(
+                    it,
+                    optionsViewModel,
+                    colorUpdateViewModel,
+                    lifecycleOwner,
+                )
+            }
+
+        customizationOptionFloatingSheetViewMap
+            ?.get(ThemePickerLockCustomizationOption.SHORTCUTS)
+            ?.let {
+                ShortcutFloatingSheetBinder.bind(
+                    it,
+                    optionsViewModel,
+                    colorUpdateViewModel,
+                    lifecycleOwner,
+                )
+            }
+
+        customizationOptionFloatingSheetViewMap
+            ?.get(ThemePickerHomeCustomizationOption.COLORS)
+            ?.let {
+                ColorsFloatingSheetBinder.bind(
+                    it,
+                    optionsViewModel,
+                    colorUpdateViewModel,
+                    lifecycleOwner,
+                )
+            }
+
+        customizationOptionFloatingSheetViewMap
+            ?.get(ThemePickerHomeCustomizationOption.APP_SHAPE_AND_GRID)
+            ?.let {
+                ShapeAndGridFloatingSheetBinder.bind(
+                    it,
+                    optionsViewModel.shapeAndGridPickerViewModel,
+                    lifecycleOwner,
+                    Dispatchers.IO,
+                )
+            }
+    }
+
+    override fun bindClockPreview(
+        clockHostView: View,
+        viewModel: CustomizationPickerViewModel2,
+        lifecycleOwner: LifecycleOwner,
+        clockViewFactory: ClockViewFactory,
+    ) {
+        clockHostView as ClockHostView2
+        val clockPickerViewModel =
+            (viewModel.customizationOptionsViewModel as ThemePickerCustomizationOptionsViewModel)
+                .clockPickerViewModel
+
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                launch {
+                    combine(
+                            clockPickerViewModel.previewingClock.filterNotNull(),
+                            clockPickerViewModel.previewingClockSize,
+                        ) { clock, size ->
+                            clock to size
+                        }
+                        .collect { (clock, size) ->
+                            clockHostView.removeAllViews()
+                            if (BaseFlags.get().isClockReactiveVariantsEnabled()) {
+                                clockViewFactory.setReactiveTouchInteractionEnabled(
+                                    clock.clockId,
+                                    true,
+                                )
+                            }
+                            val clockView =
+                                when (size) {
+                                    ClockSize.DYNAMIC ->
+                                        clockViewFactory.getLargeView(clock.clockId)
+                                    ClockSize.SMALL -> clockViewFactory.getSmallView(clock.clockId)
+                                }
+                            // The clock view might still be attached to an existing parent. Detach
+                            // before adding to another parent.
+                            (clockView.parent as? ViewGroup)?.removeView(clockView)
+                            clockHostView.addView(clockView)
+                            clockHostView.clockSize = size
+                        }
+                }
+
+                launch {
+                    combine(
+                            clockPickerViewModel.previewingSeedColor,
+                            clockPickerViewModel.previewingClock,
+                        ) { color, clock ->
+                            color to clock
+                        }
+                        .collect { (color, clock) ->
+                            clockViewFactory.updateColor(clock.clockId, color)
+                        }
+                }
             }
         }
     }
diff --git a/src/com/android/wallpaper/customization/ui/binder/ThemePickerToolbarBinder.kt b/src/com/android/wallpaper/customization/ui/binder/ThemePickerToolbarBinder.kt
new file mode 100644
index 00000000..91705dc5
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/binder/ThemePickerToolbarBinder.kt
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
+package com.android.wallpaper.customization.ui.binder
+
+import android.widget.Button
+import android.widget.FrameLayout
+import android.widget.Toolbar
+import androidx.core.view.isVisible
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import com.android.wallpaper.customization.ui.viewmodel.ThemePickerCustomizationOptionsViewModel
+import com.android.wallpaper.picker.customization.ui.binder.DefaultToolbarBinder
+import com.android.wallpaper.picker.customization.ui.binder.ToolbarBinder
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.launch
+
+@Singleton
+class ThemePickerToolbarBinder
+@Inject
+constructor(private val defaultToolbarBinder: DefaultToolbarBinder) : ToolbarBinder {
+
+    override fun bind(
+        navButton: FrameLayout,
+        toolbar: Toolbar,
+        applyButton: Button,
+        viewModel: CustomizationOptionsViewModel,
+        lifecycleOwner: LifecycleOwner,
+    ) {
+        defaultToolbarBinder.bind(navButton, toolbar, applyButton, viewModel, lifecycleOwner)
+
+        if (viewModel !is ThemePickerCustomizationOptionsViewModel) {
+            throw IllegalArgumentException(
+                "viewModel $viewModel is not a ThemePickerCustomizationOptionsViewModel."
+            )
+        }
+
+        lifecycleOwner.lifecycleScope.launch {
+            lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                launch {
+                    viewModel.onApplyButtonClicked.collect { onApplyButtonClicked ->
+                        applyButton.setOnClickListener { onApplyButtonClicked?.invoke() }
+                    }
+                }
+
+                launch { viewModel.isOnApplyVisible.collect { applyButton.isVisible = it } }
+
+                launch { viewModel.isOnApplyEnabled.collect { applyButton.isEnabled = it } }
+            }
+        }
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/util/ThemePickerCustomizationOptionUtil.kt b/src/com/android/wallpaper/customization/ui/util/ThemePickerCustomizationOptionUtil.kt
index 49055510..7a73b7d8 100644
--- a/src/com/android/wallpaper/customization/ui/util/ThemePickerCustomizationOptionUtil.kt
+++ b/src/com/android/wallpaper/customization/ui/util/ThemePickerCustomizationOptionUtil.kt
@@ -18,6 +18,7 @@ package com.android.wallpaper.customization.ui.util
 
 import android.view.LayoutInflater
 import android.view.View
+import android.view.ViewGroup
 import android.widget.FrameLayout
 import android.widget.LinearLayout
 import com.android.themepicker.R
@@ -44,24 +45,17 @@ constructor(private val defaultCustomizationOptionUtil: DefaultCustomizationOpti
 
     enum class ThemePickerHomeCustomizationOption : CustomizationOptionUtil.CustomizationOption {
         COLORS,
-        APP_GRID,
-        APP_SHAPE,
+        APP_SHAPE_AND_GRID,
         THEMED_ICONS,
     }
 
-    private var viewMap: Map<CustomizationOptionUtil.CustomizationOption, View>? = null
-
     override fun getOptionEntries(
         screen: Screen,
         optionContainer: LinearLayout,
         layoutInflater: LayoutInflater,
     ): List<Pair<CustomizationOptionUtil.CustomizationOption, View>> {
         val defaultOptionEntries =
-            defaultCustomizationOptionUtil.getOptionEntries(
-                screen,
-                optionContainer,
-                layoutInflater,
-            )
+            defaultCustomizationOptionUtil.getOptionEntries(screen, optionContainer, layoutInflater)
         return when (screen) {
             LOCK_SCREEN ->
                 buildList {
@@ -79,7 +73,7 @@ constructor(private val defaultCustomizationOptionUtil: DefaultCustomizationOpti
                             layoutInflater.inflate(
                                 R.layout.customization_option_entry_keyguard_quick_affordance,
                                 optionContainer,
-                                false
+                                false,
                             )
                     )
                     add(
@@ -111,17 +105,9 @@ constructor(private val defaultCustomizationOptionUtil: DefaultCustomizationOpti
                             )
                     )
                     add(
-                        ThemePickerHomeCustomizationOption.APP_GRID to
-                            layoutInflater.inflate(
-                                R.layout.customization_option_entry_app_grid,
-                                optionContainer,
-                                false,
-                            )
-                    )
-                    add(
-                        ThemePickerHomeCustomizationOption.APP_SHAPE to
+                        ThemePickerHomeCustomizationOption.APP_SHAPE_AND_GRID to
                             layoutInflater.inflate(
-                                R.layout.customization_option_entry_app_shape,
+                                R.layout.customization_option_entry_app_shape_and_grid,
                                 optionContainer,
                                 false,
                             )
@@ -138,49 +124,73 @@ constructor(private val defaultCustomizationOptionUtil: DefaultCustomizationOpti
         }
     }
 
-    override fun initBottomSheetContent(
+    override fun initFloatingSheet(
         bottomSheetContainer: FrameLayout,
-        layoutInflater: LayoutInflater
-    ) {
-        defaultCustomizationOptionUtil.initBottomSheetContent(bottomSheetContainer, layoutInflater)
-        viewMap = buildMap {
+        layoutInflater: LayoutInflater,
+    ): Map<CustomizationOptionUtil.CustomizationOption, View> {
+        val map =
+            defaultCustomizationOptionUtil.initFloatingSheet(bottomSheetContainer, layoutInflater)
+        return buildMap {
+            putAll(map)
             put(
                 ThemePickerLockCustomizationOption.CLOCK,
-                createCustomizationPickerBottomSheetView(
+                inflateFloatingSheet(
                         ThemePickerLockCustomizationOption.CLOCK,
                         bottomSheetContainer,
                         layoutInflater,
                     )
-                    .also { bottomSheetContainer.addView(it) }
+                    .also { bottomSheetContainer.addView(it) },
             )
             put(
                 ThemePickerLockCustomizationOption.SHORTCUTS,
-                createCustomizationPickerBottomSheetView(
+                inflateFloatingSheet(
                         ThemePickerLockCustomizationOption.SHORTCUTS,
                         bottomSheetContainer,
                         layoutInflater,
                     )
-                    .also { bottomSheetContainer.addView(it) }
+                    .also { bottomSheetContainer.addView(it) },
+            )
+            put(
+                ThemePickerHomeCustomizationOption.COLORS,
+                inflateFloatingSheet(
+                        ThemePickerHomeCustomizationOption.COLORS,
+                        bottomSheetContainer,
+                        layoutInflater,
+                    )
+                    .also { bottomSheetContainer.addView(it) },
+            )
+            put(
+                ThemePickerHomeCustomizationOption.APP_SHAPE_AND_GRID,
+                inflateFloatingSheet(
+                        ThemePickerHomeCustomizationOption.APP_SHAPE_AND_GRID,
+                        bottomSheetContainer,
+                        layoutInflater,
+                    )
+                    .also { bottomSheetContainer.addView(it) },
             )
         }
     }
 
-    override fun getBottomSheetContent(option: CustomizationOptionUtil.CustomizationOption): View? {
-        return defaultCustomizationOptionUtil.getBottomSheetContent(option) ?: viewMap?.get(option)
-    }
-
-    override fun onDestroy() {
-        viewMap = null
+    override fun createClockPreviewAndAddToParent(
+        parentView: ViewGroup,
+        layoutInflater: LayoutInflater,
+    ): View? {
+        val clockHostView = layoutInflater.inflate(R.layout.clock_host_view, parentView, false)
+        parentView.addView(clockHostView)
+        return clockHostView
     }
 
-    private fun createCustomizationPickerBottomSheetView(
-        option: ThemePickerLockCustomizationOption,
+    private fun inflateFloatingSheet(
+        option: CustomizationOptionUtil.CustomizationOption,
         bottomSheetContainer: FrameLayout,
         layoutInflater: LayoutInflater,
     ): View =
         when (option) {
-            ThemePickerLockCustomizationOption.CLOCK -> R.layout.bottom_sheet_clock
-            ThemePickerLockCustomizationOption.SHORTCUTS -> R.layout.bottom_sheet_shortcut
+            ThemePickerLockCustomizationOption.CLOCK -> R.layout.floating_sheet_clock
+            ThemePickerLockCustomizationOption.SHORTCUTS -> R.layout.floating_sheet_shortcut
+            ThemePickerHomeCustomizationOption.COLORS -> R.layout.floating_sheet_colors
+            ThemePickerHomeCustomizationOption.APP_SHAPE_AND_GRID ->
+                R.layout.floating_sheet_shape_and_grid
             else ->
                 throw IllegalStateException(
                     "Customization option $option does not have a bottom sheet view"
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ClockFloatingSheetHeightsViewModel.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ClockFloatingSheetHeightsViewModel.kt
new file mode 100644
index 00000000..37752af8
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/ClockFloatingSheetHeightsViewModel.kt
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
+data class ClockFloatingSheetHeightsViewModel(
+    val clockStyleContentHeight: Int,
+    val clockColorContentHeight: Int,
+    val clockSizeContentHeight: Int,
+)
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ClockOptionItemViewModel.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ClockOptionItemViewModel.kt
new file mode 100644
index 00000000..cd223a0b
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/ClockOptionItemViewModel.kt
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
+package com.android.wallpaper.customization.ui.viewmodel
+
+import android.graphics.drawable.Drawable
+
+data class ClockOptionItemViewModel(
+    val clockId: String,
+    val isSelected: Boolean,
+    val contentDescription: String,
+    val thumbnail: Drawable,
+)
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ClockPickerViewModel.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ClockPickerViewModel.kt
new file mode 100644
index 00000000..6740b3bc
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/ClockPickerViewModel.kt
@@ -0,0 +1,410 @@
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
+package com.android.wallpaper.customization.ui.viewmodel
+
+import android.content.Context
+import android.content.res.Resources
+import android.graphics.drawable.Drawable
+import androidx.core.graphics.ColorUtils
+import com.android.customization.model.color.ColorOptionImpl
+import com.android.customization.module.logging.ThemesUserEventLogger
+import com.android.customization.picker.clock.domain.interactor.ClockPickerInteractor
+import com.android.customization.picker.clock.shared.ClockSize
+import com.android.customization.picker.clock.shared.model.ClockMetadataModel
+import com.android.customization.picker.clock.ui.viewmodel.ClockColorViewModel
+import com.android.customization.picker.color.domain.interactor.ColorPickerInteractor
+import com.android.customization.picker.color.shared.model.ColorOptionModel
+import com.android.customization.picker.color.shared.model.ColorType
+import com.android.customization.picker.color.ui.viewmodel.ColorOptionIconViewModel
+import com.android.themepicker.R
+import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
+import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
+import com.android.wallpaper.picker.customization.ui.viewmodel.FloatingToolbarTabViewModel
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
+import dagger.assisted.Assisted
+import dagger.assisted.AssistedFactory
+import dagger.assisted.AssistedInject
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.scopes.ViewModelScoped
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.distinctUntilChanged
+import kotlinx.coroutines.flow.flow
+import kotlinx.coroutines.flow.flowOn
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.mapLatest
+import kotlinx.coroutines.flow.stateIn
+
+/** View model for the clock customization screen. */
+class ClockPickerViewModel
+@AssistedInject
+constructor(
+    @ApplicationContext context: Context,
+    resources: Resources,
+    private val clockPickerInteractor: ClockPickerInteractor,
+    colorPickerInteractor: ColorPickerInteractor,
+    private val logger: ThemesUserEventLogger,
+    @BackgroundDispatcher private val backgroundDispatcher: CoroutineDispatcher,
+    @Assisted private val viewModelScope: CoroutineScope,
+) {
+
+    enum class Tab {
+        STYLE,
+        COLOR,
+        SIZE,
+    }
+
+    private val colorMap = ClockColorViewModel.getPresetColorMap(context.resources)
+
+    // Tabs
+    private val _selectedTab = MutableStateFlow(Tab.STYLE)
+    val selectedTab: StateFlow<Tab> = _selectedTab.asStateFlow()
+    val tabs: Flow<List<FloatingToolbarTabViewModel>> =
+        _selectedTab.asStateFlow().map {
+            listOf(
+                FloatingToolbarTabViewModel(
+                    Icon.Resource(
+                        res = R.drawable.ic_style_filled_24px,
+                        contentDescription = Text.Resource(R.string.clock_style),
+                    ),
+                    context.getString(R.string.clock_style),
+                    it == Tab.STYLE,
+                ) {
+                    _selectedTab.value = Tab.STYLE
+                },
+                FloatingToolbarTabViewModel(
+                    Icon.Resource(
+                        res = R.drawable.ic_palette_filled_24px,
+                        contentDescription = Text.Resource(R.string.clock_color),
+                    ),
+                    context.getString(R.string.clock_color),
+                    it == Tab.COLOR,
+                ) {
+                    _selectedTab.value = Tab.COLOR
+                },
+                FloatingToolbarTabViewModel(
+                    Icon.Resource(
+                        res = R.drawable.ic_open_in_full_24px,
+                        contentDescription = Text.Resource(R.string.clock_size),
+                    ),
+                    context.getString(R.string.clock_size),
+                    it == Tab.SIZE,
+                ) {
+                    _selectedTab.value = Tab.SIZE
+                },
+            )
+        }
+
+    // Clock style
+    private val overridingClock = MutableStateFlow<ClockMetadataModel?>(null)
+    val previewingClock =
+        combine(overridingClock, clockPickerInteractor.selectedClock) {
+            overridingClock,
+            selectedClock ->
+            overridingClock ?: selectedClock
+        }
+    @OptIn(ExperimentalCoroutinesApi::class)
+    val clockStyleOptions: StateFlow<List<OptionItemViewModel<Drawable>>> =
+        clockPickerInteractor.allClocks
+            .mapLatest { allClocks ->
+                // Delay to avoid the case that the full list of clocks is not initiated.
+                delay(CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
+                allClocks.map { clockModel ->
+                    val isSelectedFlow =
+                        previewingClock
+                            .map { it.clockId == clockModel.clockId }
+                            .stateIn(viewModelScope)
+                    val contentDescription =
+                        resources.getString(
+                            R.string.select_clock_action_description,
+                            clockModel.description,
+                        )
+                    OptionItemViewModel<Drawable>(
+                        key = MutableStateFlow(clockModel.clockId) as StateFlow<String>,
+                        payload = clockModel.thumbnail,
+                        text = Text.Loaded(contentDescription),
+                        isTextUserVisible = false,
+                        isSelected = isSelectedFlow,
+                        onClicked =
+                            isSelectedFlow.map { isSelected ->
+                                if (isSelected) {
+                                    null
+                                } else {
+                                    { overridingClock.value = clockModel }
+                                }
+                            },
+                    )
+                }
+            }
+            // makes sure that the operations above this statement are executed on I/O dispatcher
+            // while parallelism limits the number of threads this can run on which makes sure that
+            // the flows run sequentially
+            .flowOn(backgroundDispatcher.limitedParallelism(1))
+            .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
+
+    // Clock size
+    private val overridingClockSize = MutableStateFlow<ClockSize?>(null)
+    val previewingClockSize =
+        combine(overridingClockSize, clockPickerInteractor.selectedClockSize) {
+            overridingClockSize,
+            selectedClockSize ->
+            overridingClockSize ?: selectedClockSize
+        }
+    val sizeOptions = flow {
+        emit(
+            listOf(
+                ClockSizeOptionViewModel(
+                    ClockSize.DYNAMIC,
+                    previewingClockSize.map { it == ClockSize.DYNAMIC }.stateIn(viewModelScope),
+                    previewingClockSize
+                        .map {
+                            if (it == ClockSize.DYNAMIC) {
+                                null
+                            } else {
+                                { overridingClockSize.value = ClockSize.DYNAMIC }
+                            }
+                        }
+                        .stateIn(viewModelScope),
+                ),
+                ClockSizeOptionViewModel(
+                    ClockSize.SMALL,
+                    previewingClockSize.map { it == ClockSize.SMALL }.stateIn(viewModelScope),
+                    previewingClockSize
+                        .map {
+                            if (it == ClockSize.SMALL) {
+                                null
+                            } else {
+                                { overridingClockSize.value = ClockSize.SMALL }
+                            }
+                        }
+                        .stateIn(viewModelScope),
+                ),
+            )
+        )
+    }
+
+    // Clock color
+    // 0 - 100
+    private val overridingClockColorId = MutableStateFlow<String?>(null)
+    private val previewingClockColorId =
+        combine(overridingClockColorId, clockPickerInteractor.selectedColorId) {
+            overridingClockColorId,
+            selectedColorId ->
+            overridingClockColorId ?: selectedColorId
+        }
+
+    private val overridingSliderProgress = MutableStateFlow<Int?>(null)
+    val previewingSliderProgress: Flow<Int> =
+        combine(overridingSliderProgress, clockPickerInteractor.colorToneProgress) {
+            overridingSliderProgress,
+            colorToneProgress ->
+            overridingSliderProgress ?: colorToneProgress
+        }
+    val isSliderEnabled: Flow<Boolean> =
+        combine(previewingClock, previewingClockColorId) { clock, clockColorId ->
+                // clockColorId null means clock color is the system theme color, thus no slider
+                clock.isReactiveToTone && clockColorId != null
+            }
+            .distinctUntilChanged()
+
+    fun onSliderProgressChanged(progress: Int) {
+        overridingSliderProgress.value = progress
+    }
+
+    val previewingSeedColor: Flow<Int?> =
+        combine(previewingClockColorId, previewingSliderProgress) { clockColorId, sliderProgress ->
+            val clockColorViewModel = if (clockColorId == null) null else colorMap[clockColorId]
+            if (clockColorViewModel == null) {
+                null
+            } else {
+                blendColorWithTone(
+                    color = clockColorViewModel.color,
+                    colorTone = clockColorViewModel.getColorTone(sliderProgress),
+                )
+            }
+        }
+
+    val clockColorOptions: Flow<List<OptionItemViewModel<ColorOptionIconViewModel>>> =
+        colorPickerInteractor.colorOptions.map { colorOptions ->
+            // Use mapLatest and delay(100) here to prevent too many selectedClockColor update
+            // events from ClockRegistry upstream, caused by sliding the saturation level bar.
+            delay(COLOR_OPTIONS_EVENT_UPDATE_DELAY_MILLIS)
+            buildList {
+                val defaultThemeColorOptionViewModel =
+                    (colorOptions[ColorType.WALLPAPER_COLOR]?.find { it.isSelected })
+                        ?.toOptionItemViewModel(context)
+                        ?: (colorOptions[ColorType.PRESET_COLOR]?.find { it.isSelected })
+                            ?.toOptionItemViewModel(context)
+                if (defaultThemeColorOptionViewModel != null) {
+                    add(defaultThemeColorOptionViewModel)
+                }
+
+                colorMap.values.forEachIndexed { index, colorModel ->
+                    val isSelectedFlow =
+                        previewingClockColorId
+                            .map { colorMap.keys.indexOf(it) == index }
+                            .stateIn(viewModelScope)
+                    add(
+                        OptionItemViewModel<ColorOptionIconViewModel>(
+                            key = MutableStateFlow(colorModel.colorId) as StateFlow<String>,
+                            payload =
+                                ColorOptionIconViewModel(
+                                    lightThemeColor0 = colorModel.color,
+                                    lightThemeColor1 = colorModel.color,
+                                    lightThemeColor2 = colorModel.color,
+                                    lightThemeColor3 = colorModel.color,
+                                    darkThemeColor0 = colorModel.color,
+                                    darkThemeColor1 = colorModel.color,
+                                    darkThemeColor2 = colorModel.color,
+                                    darkThemeColor3 = colorModel.color,
+                                ),
+                            text =
+                                Text.Loaded(
+                                    context.getString(
+                                        R.string.content_description_color_option,
+                                        index,
+                                    )
+                                ),
+                            isTextUserVisible = false,
+                            isSelected = isSelectedFlow,
+                            onClicked =
+                                isSelectedFlow.map { isSelected ->
+                                    if (isSelected) {
+                                        null
+                                    } else {
+                                        {
+                                            overridingClockColorId.value = colorModel.colorId
+                                            overridingSliderProgress.value =
+                                                ClockMetadataModel.DEFAULT_COLOR_TONE_PROGRESS
+                                        }
+                                    }
+                                },
+                        )
+                    )
+                }
+            }
+        }
+
+    private suspend fun ColorOptionModel.toOptionItemViewModel(
+        context: Context
+    ): OptionItemViewModel<ColorOptionIconViewModel> {
+        val lightThemeColors =
+            (colorOption as ColorOptionImpl)
+                .previewInfo
+                .resolveColors(
+                    /** darkTheme= */
+                    false
+                )
+        val darkThemeColors =
+            colorOption.previewInfo.resolveColors(
+                /** darkTheme= */
+                true
+            )
+        val isSelectedFlow = previewingClockColorId.map { it == null }.stateIn(viewModelScope)
+        return OptionItemViewModel<ColorOptionIconViewModel>(
+            key = MutableStateFlow(key) as StateFlow<String>,
+            payload =
+                ColorOptionIconViewModel(
+                    lightThemeColor0 = lightThemeColors[0],
+                    lightThemeColor1 = lightThemeColors[1],
+                    lightThemeColor2 = lightThemeColors[2],
+                    lightThemeColor3 = lightThemeColors[3],
+                    darkThemeColor0 = darkThemeColors[0],
+                    darkThemeColor1 = darkThemeColors[1],
+                    darkThemeColor2 = darkThemeColors[2],
+                    darkThemeColor3 = darkThemeColors[3],
+                ),
+            text = Text.Loaded(context.getString(R.string.default_theme_title)),
+            isTextUserVisible = true,
+            isSelected = isSelectedFlow,
+            onClicked =
+                isSelectedFlow.map { isSelected ->
+                    if (isSelected) {
+                        null
+                    } else {
+                        {
+                            overridingClockColorId.value = null
+                            overridingSliderProgress.value =
+                                ClockMetadataModel.DEFAULT_COLOR_TONE_PROGRESS
+                        }
+                    }
+                },
+        )
+    }
+
+    val onApply: Flow<(suspend () -> Unit)?> =
+        combine(
+            previewingClock,
+            previewingClockSize,
+            previewingClockColorId,
+            previewingSliderProgress,
+        ) { clock, size, colorId, progress ->
+            {
+                val clockColorViewModel = colorMap[colorId]
+                val seedColor =
+                    if (clockColorViewModel != null) {
+                        blendColorWithTone(
+                            color = clockColorViewModel.color,
+                            colorTone = clockColorViewModel.getColorTone(progress),
+                        )
+                    } else {
+                        null
+                    }
+                clockPickerInteractor.applyClock(
+                    clockId = clock.clockId,
+                    size = size,
+                    selectedColorId = colorId,
+                    colorToneProgress = progress,
+                    seedColor = seedColor,
+                )
+            }
+        }
+
+    fun resetPreview() {
+        overridingClock.value = null
+        overridingClockSize.value = null
+        overridingClockColorId.value = null
+        overridingSliderProgress.value = null
+        _selectedTab.value = Tab.STYLE
+    }
+
+    companion object {
+        private val helperColorLab: DoubleArray by lazy { DoubleArray(3) }
+
+        fun blendColorWithTone(color: Int, colorTone: Double): Int {
+            ColorUtils.colorToLAB(color, helperColorLab)
+            return ColorUtils.LABToColor(colorTone, helperColorLab[1], helperColorLab[2])
+        }
+
+        const val COLOR_OPTIONS_EVENT_UPDATE_DELAY_MILLIS: Long = 100
+        const val CLOCKS_EVENT_UPDATE_DELAY_MILLIS: Long = 100
+    }
+
+    @ViewModelScoped
+    @AssistedFactory
+    interface Factory {
+        fun create(viewModelScope: CoroutineScope): ClockPickerViewModel
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ClockSizeOptionViewModel.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ClockSizeOptionViewModel.kt
new file mode 100644
index 00000000..de2c54a7
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/ClockSizeOptionViewModel.kt
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
+package com.android.wallpaper.customization.ui.viewmodel
+
+import com.android.customization.picker.clock.shared.ClockSize
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.StateFlow
+
+data class ClockSizeOptionViewModel(
+    val size: ClockSize,
+    val isSelected: StateFlow<Boolean>,
+    val onClicked: Flow<(() -> Unit)?>,
+)
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ColorPickerViewModel2.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ColorPickerViewModel2.kt
new file mode 100644
index 00000000..a0399963
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/ColorPickerViewModel2.kt
@@ -0,0 +1,186 @@
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
+package com.android.wallpaper.customization.ui.viewmodel
+
+import android.content.Context
+import com.android.customization.model.color.ColorOptionImpl
+import com.android.customization.module.logging.ThemesUserEventLogger
+import com.android.customization.picker.color.domain.interactor.ColorPickerInteractor
+import com.android.customization.picker.color.shared.model.ColorType
+import com.android.customization.picker.color.ui.viewmodel.ColorOptionIconViewModel
+import com.android.themepicker.R
+import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
+import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
+import com.android.wallpaper.picker.customization.ui.viewmodel.FloatingToolbarTabViewModel
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
+import dagger.assisted.Assisted
+import dagger.assisted.AssistedFactory
+import dagger.assisted.AssistedInject
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.scopes.ViewModelScoped
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.stateIn
+import kotlinx.coroutines.launch
+
+/** Models UI state for a color picker experience. */
+class ColorPickerViewModel2
+@AssistedInject
+constructor(
+    @ApplicationContext context: Context,
+    private val interactor: ColorPickerInteractor,
+    private val logger: ThemesUserEventLogger,
+    @Assisted private val viewModelScope: CoroutineScope,
+) {
+
+    private val selectedColorTypeTabId = MutableStateFlow<ColorType?>(null)
+
+    /** View-models for each color tab. */
+    val colorTypeTabs: Flow<List<FloatingToolbarTabViewModel>> =
+        combine(
+            interactor.colorOptions,
+            selectedColorTypeTabId,
+        ) { colorOptions, selectedColorTypeIdOrNull ->
+            colorOptions.keys.mapIndexed { index, colorType ->
+                val isSelected =
+                    (selectedColorTypeIdOrNull == null && index == 0) ||
+                        selectedColorTypeIdOrNull == colorType
+
+                val name =
+                    when (colorType) {
+                        ColorType.WALLPAPER_COLOR ->
+                            context.resources.getString(R.string.wallpaper_color_tab)
+                        ColorType.PRESET_COLOR ->
+                            context.resources.getString(R.string.preset_color_tab_2)
+                    }
+
+                FloatingToolbarTabViewModel(
+                    Icon.Resource(
+                        res =
+                            when (colorType) {
+                                ColorType.WALLPAPER_COLOR ->
+                                    com.android.wallpaper.R.drawable.ic_baseline_wallpaper_24
+                                ColorType.PRESET_COLOR -> R.drawable.ic_colors
+                            },
+                        contentDescription = Text.Loaded(name),
+                    ),
+                    name,
+                    isSelected,
+                ) {
+                    if (!isSelected) {
+                        this.selectedColorTypeTabId.value = colorType
+                    }
+                }
+            }
+        }
+
+    /** View-models for each color tab subheader */
+    val colorTypeTabSubheader: Flow<String> =
+        selectedColorTypeTabId.map { selectedColorTypeIdOrNull ->
+            when (selectedColorTypeIdOrNull ?: ColorType.WALLPAPER_COLOR) {
+                ColorType.WALLPAPER_COLOR ->
+                    context.resources.getString(R.string.wallpaper_color_subheader)
+                ColorType.PRESET_COLOR ->
+                    context.resources.getString(R.string.preset_color_subheader)
+            }
+        }
+
+    /** The list of all color options mapped by their color type */
+    private val allColorOptions:
+        Flow<Map<ColorType, List<OptionItemViewModel<ColorOptionIconViewModel>>>> =
+        interactor.colorOptions.map { colorOptions ->
+            colorOptions
+                .map { colorOptionEntry ->
+                    colorOptionEntry.key to
+                        colorOptionEntry.value.map { colorOptionModel ->
+                            val colorOption: ColorOptionImpl =
+                                colorOptionModel.colorOption as ColorOptionImpl
+                            val lightThemeColors =
+                                colorOption.previewInfo.resolveColors(/* darkTheme= */ false)
+                            val darkThemeColors =
+                                colorOption.previewInfo.resolveColors(/* darkTheme= */ true)
+                            val isSelectedFlow: StateFlow<Boolean> =
+                                interactor.selectingColorOption
+                                    .map {
+                                        it?.colorOption?.isEquivalent(colorOptionModel.colorOption)
+                                            ?: colorOptionModel.isSelected
+                                    }
+                                    .stateIn(viewModelScope)
+                            OptionItemViewModel<ColorOptionIconViewModel>(
+                                key = MutableStateFlow(colorOptionModel.key) as StateFlow<String>,
+                                payload =
+                                    ColorOptionIconViewModel(
+                                        lightThemeColor0 = lightThemeColors[0],
+                                        lightThemeColor1 = lightThemeColors[1],
+                                        lightThemeColor2 = lightThemeColors[2],
+                                        lightThemeColor3 = lightThemeColors[3],
+                                        darkThemeColor0 = darkThemeColors[0],
+                                        darkThemeColor1 = darkThemeColors[1],
+                                        darkThemeColor2 = darkThemeColors[2],
+                                        darkThemeColor3 = darkThemeColors[3],
+                                    ),
+                                text =
+                                    Text.Loaded(
+                                        colorOption.getContentDescription(context).toString()
+                                    ),
+                                isTextUserVisible = false,
+                                isSelected = isSelectedFlow,
+                                onClicked =
+                                    isSelectedFlow.map { isSelected ->
+                                        if (isSelected) {
+                                            null
+                                        } else {
+                                            {
+                                                viewModelScope.launch {
+                                                    interactor.select(colorOptionModel)
+                                                    logger.logThemeColorApplied(
+                                                        colorOptionModel.colorOption
+                                                            .sourceForLogging,
+                                                        colorOptionModel.colorOption
+                                                            .styleForLogging,
+                                                        colorOptionModel.colorOption
+                                                            .seedColorForLogging,
+                                                    )
+                                                }
+                                            }
+                                        }
+                                    },
+                            )
+                        }
+                }
+                .toMap()
+        }
+
+    /** The list of all available color options for the selected Color Type. */
+    val colorOptions: Flow<List<OptionItemViewModel<ColorOptionIconViewModel>>> =
+        combine(allColorOptions, selectedColorTypeTabId) {
+            allColorOptions: Map<ColorType, List<OptionItemViewModel<ColorOptionIconViewModel>>>,
+            selectedColorTypeIdOrNull ->
+            val selectedColorTypeId = selectedColorTypeIdOrNull ?: ColorType.WALLPAPER_COLOR
+            allColorOptions[selectedColorTypeId]!!
+        }
+
+    @ViewModelScoped
+    @AssistedFactory
+    interface Factory {
+        fun create(viewModelScope: CoroutineScope): ColorPickerViewModel2
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/KeyguardQuickAffordancePickerViewModel2.kt b/src/com/android/wallpaper/customization/ui/viewmodel/KeyguardQuickAffordancePickerViewModel2.kt
new file mode 100644
index 00000000..fd94b781
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/KeyguardQuickAffordancePickerViewModel2.kt
@@ -0,0 +1,469 @@
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
+import android.annotation.SuppressLint
+import android.content.Context
+import android.content.Intent
+import android.graphics.drawable.Drawable
+import androidx.annotation.DrawableRes
+import com.android.customization.module.logging.ThemesUserEventLogger
+import com.android.customization.picker.quickaffordance.domain.interactor.KeyguardQuickAffordancePickerInteractor
+import com.android.customization.picker.quickaffordance.ui.viewmodel.KeyguardQuickAffordanceSlotViewModel
+import com.android.customization.picker.quickaffordance.ui.viewmodel.KeyguardQuickAffordanceSummaryViewModel
+import com.android.systemui.shared.keyguard.shared.model.KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_END
+import com.android.systemui.shared.keyguard.shared.model.KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.KEYGUARD_QUICK_AFFORDANCE_ID_NONE
+import com.android.themepicker.R
+import com.android.wallpaper.picker.common.button.ui.viewmodel.ButtonStyle
+import com.android.wallpaper.picker.common.button.ui.viewmodel.ButtonViewModel
+import com.android.wallpaper.picker.common.dialog.ui.viewmodel.DialogViewModel
+import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
+import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
+import com.android.wallpaper.picker.customization.ui.viewmodel.FloatingToolbarTabViewModel
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
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
+import kotlinx.coroutines.flow.flowOf
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.shareIn
+import kotlinx.coroutines.flow.stateIn
+
+class KeyguardQuickAffordancePickerViewModel2
+@AssistedInject
+constructor(
+    @ApplicationContext private val applicationContext: Context,
+    private val quickAffordanceInteractor: KeyguardQuickAffordancePickerInteractor,
+    private val logger: ThemesUserEventLogger,
+    @Assisted private val viewModelScope: CoroutineScope,
+) {
+    /** A locally-selected slot, if the user ever switched from the original one. */
+    private val _selectedSlotId = MutableStateFlow<String?>(null)
+    /** The ID of the selected slot. */
+    val selectedSlotId: StateFlow<String> =
+        combine(quickAffordanceInteractor.slots, _selectedSlotId) { slots, selectedSlotIdOrNull ->
+                if (selectedSlotIdOrNull != null) {
+                    slots.first { slot -> slot.id == selectedSlotIdOrNull }
+                } else {
+                    // If we haven't yet selected a new slot locally, default to the first slot.
+                    slots[0]
+                }
+            }
+            .map { selectedSlot -> selectedSlot.id }
+            .stateIn(
+                scope = viewModelScope,
+                started = SharingStarted.WhileSubscribed(),
+                initialValue = "",
+            )
+    private val _previewingQuickAffordances = MutableStateFlow<Map<String, String>>(emptyMap())
+    val previewingQuickAffordances: Flow<Map<String, String>> =
+        _previewingQuickAffordances.asStateFlow()
+
+    fun resetPreview() {
+        _previewingQuickAffordances.tryEmit(emptyMap())
+        _selectedSlotId.tryEmit(SLOT_ID_BOTTOM_START)
+    }
+
+    /** View-models for each slot, keyed by slot ID. */
+    private val slots: StateFlow<Map<String, KeyguardQuickAffordanceSlotViewModel>> =
+        combine(
+                quickAffordanceInteractor.slots,
+                quickAffordanceInteractor.affordances,
+                quickAffordanceInteractor.selections,
+                previewingQuickAffordances,
+                selectedSlotId,
+            ) { slots, affordances, selections, selectedQuickAffordances, selectedSlotId ->
+                slots.associate { slot ->
+                    val selectedAffordanceIds =
+                        selectedQuickAffordances[slot.id]?.let { setOf(it) }
+                            ?: selections
+                                .filter { selection -> selection.slotId == slot.id }
+                                .map { selection -> selection.affordanceId }
+                                .toSet()
+                    val selectedAffordances =
+                        affordances.filter { affordance ->
+                            selectedAffordanceIds.contains(affordance.id)
+                        }
+
+                    val isSelected = selectedSlotId == slot.id
+                    slot.id to
+                        KeyguardQuickAffordanceSlotViewModel(
+                            name = getSlotName(slot.id),
+                            isSelected = isSelected,
+                            selectedQuickAffordances =
+                                selectedAffordances.map { affordanceModel ->
+                                    OptionItemViewModel<Icon>(
+                                        key =
+                                            MutableStateFlow("${slot.id}::${affordanceModel.id}")
+                                                as StateFlow<String>,
+                                        payload =
+                                            Icon.Loaded(
+                                                drawable =
+                                                    getAffordanceIcon(
+                                                        affordanceModel.iconResourceId
+                                                    ),
+                                                contentDescription =
+                                                    Text.Loaded(getSlotContentDescription(slot.id)),
+                                            ),
+                                        text = Text.Loaded(affordanceModel.name),
+                                        isSelected = MutableStateFlow(true) as StateFlow<Boolean>,
+                                        onClicked = flowOf(null),
+                                        onLongClicked = null,
+                                        isEnabled = true,
+                                    )
+                                },
+                            maxSelectedQuickAffordances = slot.maxSelectedQuickAffordances,
+                            onClicked =
+                                if (isSelected) {
+                                    null
+                                } else {
+                                    { _selectedSlotId.tryEmit(slot.id) }
+                                },
+                        )
+                }
+            }
+            .stateIn(
+                scope = viewModelScope,
+                started = SharingStarted.WhileSubscribed(),
+                initialValue = emptyMap(),
+            )
+
+    val tabs: Flow<List<FloatingToolbarTabViewModel>> =
+        slots.map { slotById ->
+            slotById.values.map {
+                FloatingToolbarTabViewModel(it.getIcon(), it.name, it.isSelected, it.onClicked)
+            }
+        }
+
+    /**
+     * The set of IDs of the currently-selected affordances. These change with user selection of new
+     * or different affordances in the currently-selected slot or when slot selection changes.
+     */
+    private val selectedAffordanceIds: Flow<Set<String>> =
+        combine(quickAffordanceInteractor.selections, selectedSlotId) { selections, selectedSlotId
+                ->
+                selections
+                    .filter { selection -> selection.slotId == selectedSlotId }
+                    .map { selection -> selection.affordanceId }
+                    .toSet()
+            }
+            .shareIn(scope = viewModelScope, started = SharingStarted.WhileSubscribed(), replay = 1)
+
+    /** The list of all available quick affordances for the selected slot. */
+    val quickAffordances: Flow<List<OptionItemViewModel<Icon>>> =
+        quickAffordanceInteractor.affordances.map { affordances ->
+            val isNoneSelected =
+                combine(selectedSlotId, previewingQuickAffordances, selectedAffordanceIds) {
+                        selectedSlotId,
+                        selectedQuickAffordances,
+                        selectedAffordanceIds ->
+                        selectedQuickAffordances[selectedSlotId]?.let {
+                            it == KEYGUARD_QUICK_AFFORDANCE_ID_NONE
+                        } ?: selectedAffordanceIds.isEmpty()
+                    }
+                    .stateIn(viewModelScope)
+            listOf(
+                none(
+                    slotId = selectedSlotId,
+                    isSelected = isNoneSelected,
+                    onSelected =
+                        combine(isNoneSelected, selectedSlotId) { isSelected, selectedSlotId ->
+                            if (!isSelected) {
+                                {
+                                    val newMap =
+                                        _previewingQuickAffordances.value.toMutableMap().apply {
+                                            put(selectedSlotId, KEYGUARD_QUICK_AFFORDANCE_ID_NONE)
+                                        }
+                                    _previewingQuickAffordances.tryEmit(newMap)
+                                }
+                            } else {
+                                null
+                            }
+                        },
+                )
+            ) +
+                affordances.map { affordance ->
+                    val affordanceIcon = getAffordanceIcon(affordance.iconResourceId)
+                    val isSelectedFlow: StateFlow<Boolean> =
+                        combine(
+                                selectedSlotId,
+                                previewingQuickAffordances,
+                                selectedAffordanceIds,
+                            ) { selectedSlotId, selectedQuickAffordances, selectedAffordanceIds ->
+                                selectedQuickAffordances[selectedSlotId]?.let {
+                                    it == affordance.id
+                                } ?: selectedAffordanceIds.contains(affordance.id)
+                            }
+                            .stateIn(viewModelScope)
+                    OptionItemViewModel<Icon>(
+                        key =
+                            selectedSlotId
+                                .map { slotId -> "$slotId::${affordance.id}" }
+                                .stateIn(viewModelScope),
+                        payload = Icon.Loaded(drawable = affordanceIcon, contentDescription = null),
+                        text = Text.Loaded(affordance.name),
+                        isSelected = isSelectedFlow,
+                        onClicked =
+                            if (affordance.isEnabled) {
+                                combine(isSelectedFlow, selectedSlotId) { isSelected, selectedSlotId
+                                    ->
+                                    if (!isSelected) {
+                                        {
+                                            val newMap =
+                                                _previewingQuickAffordances.value
+                                                    .toMutableMap()
+                                                    .apply { put(selectedSlotId, affordance.id) }
+                                            _previewingQuickAffordances.tryEmit(newMap)
+                                        }
+                                    } else {
+                                        null
+                                    }
+                                }
+                            } else {
+                                flowOf {
+                                    showEnablementDialog(
+                                        icon = affordanceIcon,
+                                        name = affordance.name,
+                                        explanation = affordance.enablementExplanation,
+                                        actionText = affordance.enablementActionText,
+                                        actionIntent = affordance.enablementActionIntent,
+                                    )
+                                }
+                            },
+                        onLongClicked =
+                            if (affordance.configureIntent != null) {
+                                { requestActivityStart(affordance.configureIntent) }
+                            } else {
+                                null
+                            },
+                        isEnabled = affordance.isEnabled,
+                    )
+                }
+        }
+
+    val onApply: Flow<(suspend () -> Unit)?> =
+        previewingQuickAffordances.map {
+            if (it.isEmpty()) {
+                null
+            } else {
+                {
+                    it.forEach { entry ->
+                        val slotId = entry.key
+                        val affordanceId = entry.value
+                        if (slotId == KEYGUARD_QUICK_AFFORDANCE_ID_NONE) {
+                            quickAffordanceInteractor.unselectAllFromSlot(slotId)
+                        } else {
+                            quickAffordanceInteractor.select(
+                                slotId = slotId,
+                                affordanceId = affordanceId,
+                            )
+                        }
+                        logger.logShortcutApplied(shortcut = affordanceId, shortcutSlotId = slotId)
+                    }
+                }
+            }
+        }
+
+    private val _dialog = MutableStateFlow<DialogViewModel?>(null)
+    /**
+     * The current dialog to show. If `null`, no dialog should be shown.
+     *
+     * When the dialog is dismissed, [onDialogDismissed] must be called.
+     */
+    val dialog: Flow<DialogViewModel?> = _dialog.asStateFlow()
+
+    private val _activityStartRequests = MutableStateFlow<Intent?>(null)
+    /**
+     * Requests to start an activity with the given [Intent].
+     *
+     * Important: once the activity is started, the [Intent] should be consumed by calling
+     * [onActivityStarted].
+     */
+    val activityStartRequests: StateFlow<Intent?> = _activityStartRequests.asStateFlow()
+
+    /** Notifies that the dialog has been dismissed in the UI. */
+    fun onDialogDismissed() {
+        _dialog.value = null
+    }
+
+    /**
+     * Notifies that an activity request from [activityStartRequests] has been fulfilled (e.g. the
+     * activity was started and the view-model can forget needing to start this activity).
+     */
+    fun onActivityStarted() {
+        _activityStartRequests.value = null
+    }
+
+    private fun requestActivityStart(intent: Intent) {
+        _activityStartRequests.value = intent
+    }
+
+    private fun showEnablementDialog(
+        icon: Drawable,
+        name: String,
+        explanation: String,
+        actionText: String?,
+        actionIntent: Intent?,
+    ) {
+        _dialog.value =
+            DialogViewModel(
+                icon = Icon.Loaded(drawable = icon, contentDescription = null),
+                headline = Text.Resource(R.string.keyguard_affordance_enablement_dialog_headline),
+                message = Text.Loaded(explanation),
+                buttons =
+                    buildList {
+                        add(
+                            ButtonViewModel(
+                                text =
+                                    Text.Resource(
+                                        if (actionText != null) {
+                                            // This is not the only button on the dialog.
+                                            R.string.cancel
+                                        } else {
+                                            // This is the only button on the dialog.
+                                            R.string
+                                                .keyguard_affordance_enablement_dialog_dismiss_button
+                                        }
+                                    ),
+                                style = ButtonStyle.Secondary,
+                            )
+                        )
+
+                        if (actionText != null) {
+                            add(
+                                ButtonViewModel(
+                                    text = Text.Loaded(actionText),
+                                    style = ButtonStyle.Primary,
+                                    onClicked = {
+                                        actionIntent?.let { intent -> requestActivityStart(intent) }
+                                    },
+                                )
+                            )
+                        }
+                    },
+            )
+    }
+
+    /** Returns a view-model for the special "None" option. */
+    @SuppressLint("UseCompatLoadingForDrawables")
+    private suspend fun none(
+        slotId: StateFlow<String>,
+        isSelected: StateFlow<Boolean>,
+        onSelected: Flow<(() -> Unit)?>,
+    ): OptionItemViewModel<Icon> {
+        return OptionItemViewModel<Icon>(
+            key = slotId.map { "$it::none" }.stateIn(viewModelScope),
+            payload = Icon.Resource(res = R.drawable.link_off, contentDescription = null),
+            text = Text.Resource(res = R.string.keyguard_affordance_none),
+            isSelected = isSelected,
+            onClicked = onSelected,
+            onLongClicked = null,
+            isEnabled = true,
+        )
+    }
+
+    private fun getSlotName(slotId: String): String {
+        return applicationContext.getString(
+            when (slotId) {
+                SLOT_ID_BOTTOM_START -> R.string.keyguard_slot_name_bottom_start
+                SLOT_ID_BOTTOM_END -> R.string.keyguard_slot_name_bottom_end
+                else -> error("No name for slot with ID of \"$slotId\"!")
+            }
+        )
+    }
+
+    private fun getSlotContentDescription(slotId: String): String {
+        return applicationContext.getString(
+            when (slotId) {
+                SLOT_ID_BOTTOM_START -> R.string.keyguard_slot_name_bottom_start
+                SLOT_ID_BOTTOM_END -> R.string.keyguard_slot_name_bottom_end
+                else -> error("No accessibility label for slot with ID \"$slotId\"!")
+            }
+        )
+    }
+
+    private suspend fun getAffordanceIcon(@DrawableRes iconResourceId: Int): Drawable {
+        return quickAffordanceInteractor.getAffordanceIcon(iconResourceId)
+    }
+
+    val summary: Flow<KeyguardQuickAffordanceSummaryViewModel> =
+        slots.map { slots ->
+            val icon2 =
+                (slots[SLOT_ID_BOTTOM_END]?.selectedQuickAffordances?.firstOrNull())?.payload
+            val icon1 =
+                (slots[SLOT_ID_BOTTOM_START]?.selectedQuickAffordances?.firstOrNull())?.payload
+
+            KeyguardQuickAffordanceSummaryViewModel(
+                description = toDescriptionText(applicationContext, slots),
+                icon1 =
+                    icon1
+                        ?: if (icon2 == null) {
+                            Icon.Resource(res = R.drawable.link_off, contentDescription = null)
+                        } else {
+                            null
+                        },
+                icon2 = icon2,
+            )
+        }
+
+    private fun toDescriptionText(
+        context: Context,
+        slots: Map<String, KeyguardQuickAffordanceSlotViewModel>,
+    ): Text {
+        val bottomStartAffordanceName =
+            slots[SLOT_ID_BOTTOM_START]?.selectedQuickAffordances?.firstOrNull()?.text
+        val bottomEndAffordanceName =
+            slots[SLOT_ID_BOTTOM_END]?.selectedQuickAffordances?.firstOrNull()?.text
+
+        return when {
+            bottomStartAffordanceName != null && bottomEndAffordanceName != null -> {
+                Text.Loaded(
+                    context.getString(
+                        R.string.keyguard_quick_affordance_two_selected_template,
+                        bottomStartAffordanceName.asString(context),
+                        bottomEndAffordanceName.asString(context),
+                    )
+                )
+            }
+            bottomStartAffordanceName != null -> bottomStartAffordanceName
+            bottomEndAffordanceName != null -> bottomEndAffordanceName
+            else -> Text.Resource(R.string.keyguard_quick_affordance_none_selected)
+        }
+    }
+
+    companion object {
+        private fun KeyguardQuickAffordanceSlotViewModel.getIcon(): Icon =
+            selectedQuickAffordances.firstOrNull()?.payload
+                ?: Icon.Resource(res = R.drawable.link_off, contentDescription = null)
+    }
+
+    @ViewModelScoped
+    @AssistedFactory
+    interface Factory {
+        fun create(viewModelScope: CoroutineScope): KeyguardQuickAffordancePickerViewModel2
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ShapeAndGridPickerViewModel.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ShapeAndGridPickerViewModel.kt
new file mode 100644
index 00000000..a13a6525
--- /dev/null
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/ShapeAndGridPickerViewModel.kt
@@ -0,0 +1,132 @@
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
+import com.android.customization.picker.grid.domain.interactor.GridInteractor2
+import com.android.customization.picker.grid.ui.viewmodel.GridIconViewModel
+import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
+import dagger.assisted.Assisted
+import dagger.assisted.AssistedFactory
+import dagger.assisted.AssistedInject
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.scopes.ViewModelScoped
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.filterNotNull
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.stateIn
+
+class ShapeAndGridPickerViewModel
+@AssistedInject
+constructor(
+    @ApplicationContext private val context: Context,
+    interactor: GridInteractor2,
+    @Assisted private val viewModelScope: CoroutineScope,
+) {
+    // The currently-set system grid option
+    val selectedGridOption =
+        interactor.selectedGridOption.filterNotNull().map { toOptionItemViewModel(it) }
+    private val _previewingGridOptionKey = MutableStateFlow<String?>(null)
+    // If the previewing key is null, use the currently-set system grid option
+    val previewingGridOptionKey =
+        combine(selectedGridOption, _previewingGridOptionKey) {
+            currentlySetGridOption,
+            previewingGridOptionKey ->
+            previewingGridOptionKey ?: currentlySetGridOption.key.value
+        }
+
+    fun resetPreview() {
+        _previewingGridOptionKey.tryEmit(null)
+    }
+
+    val optionItems: Flow<List<OptionItemViewModel<GridIconViewModel>>> =
+        interactor.gridOptions.filterNotNull().map { gridOptions ->
+            gridOptions.map { toOptionItemViewModel(it) }
+        }
+
+    val onApply: Flow<(suspend () -> Unit)?> =
+        combine(selectedGridOption, _previewingGridOptionKey) {
+            selectedGridOption,
+            previewingGridOptionKey ->
+            if (
+                previewingGridOptionKey == null ||
+                    previewingGridOptionKey == selectedGridOption.key.value
+            ) {
+                null
+            } else {
+                { interactor.applySelectedOption(previewingGridOptionKey) }
+            }
+        }
+
+    private fun toOptionItemViewModel(
+        option: GridOptionModel
+    ): OptionItemViewModel<GridIconViewModel> {
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
+            _previewingGridOptionKey
+                .map {
+                    if (it == null) {
+                        option.isCurrent
+                    } else {
+                        it == option.key
+                    }
+                }
+                .stateIn(
+                    scope = viewModelScope,
+                    started = SharingStarted.Eagerly,
+                    initialValue = false,
+                )
+
+        return OptionItemViewModel(
+            key = MutableStateFlow(option.key),
+            payload =
+                GridIconViewModel(columns = option.cols, rows = option.rows, path = iconShapePath),
+            text = Text.Loaded(option.title),
+            isSelected = isSelected,
+            onClicked =
+                isSelected.map {
+                    if (!it) {
+                        { _previewingGridOptionKey.value = option.key }
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
+        fun create(viewModelScope: CoroutineScope): ShapeAndGridPickerViewModel
+    }
+}
diff --git a/src/com/android/wallpaper/customization/ui/viewmodel/ThemePickerCustomizationOptionsViewModel.kt b/src/com/android/wallpaper/customization/ui/viewmodel/ThemePickerCustomizationOptionsViewModel.kt
index cc909b5b..03831bd5 100644
--- a/src/com/android/wallpaper/customization/ui/viewmodel/ThemePickerCustomizationOptionsViewModel.kt
+++ b/src/com/android/wallpaper/customization/ui/viewmodel/ThemePickerCustomizationOptionsViewModel.kt
@@ -18,22 +18,51 @@ package com.android.wallpaper.customization.ui.viewmodel
 
 import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptionUtil
 import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModelFactory
 import com.android.wallpaper.picker.customization.ui.viewmodel.DefaultCustomizationOptionsViewModel
+import dagger.assisted.Assisted
+import dagger.assisted.AssistedFactory
+import dagger.assisted.AssistedInject
 import dagger.hilt.android.scopes.ViewModelScoped
-import javax.inject.Inject
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.flatMapLatest
+import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.stateIn
+import kotlinx.coroutines.launch
 
-@ViewModelScoped
 class ThemePickerCustomizationOptionsViewModel
-@Inject
+@AssistedInject
 constructor(
-    private val defaultCustomizationOptionsViewModel: DefaultCustomizationOptionsViewModel
+    defaultCustomizationOptionsViewModelFactory: DefaultCustomizationOptionsViewModel.Factory,
+    keyguardQuickAffordancePickerViewModel2Factory: KeyguardQuickAffordancePickerViewModel2.Factory,
+    colorPickerViewModel2Factory: ColorPickerViewModel2.Factory,
+    clockPickerViewModelFactory: ClockPickerViewModel.Factory,
+    shapeAndGridPickerViewModelFactory: ShapeAndGridPickerViewModel.Factory,
+    @Assisted private val viewModelScope: CoroutineScope,
 ) : CustomizationOptionsViewModel {
 
+    private val defaultCustomizationOptionsViewModel =
+        defaultCustomizationOptionsViewModelFactory.create(viewModelScope)
+
+    val clockPickerViewModel = clockPickerViewModelFactory.create(viewModelScope = viewModelScope)
+    val keyguardQuickAffordancePickerViewModel2 =
+        keyguardQuickAffordancePickerViewModel2Factory.create(viewModelScope = viewModelScope)
+    val colorPickerViewModel2 = colorPickerViewModel2Factory.create(viewModelScope = viewModelScope)
+    val shapeAndGridPickerViewModel =
+        shapeAndGridPickerViewModelFactory.create(viewModelScope = viewModelScope)
+
     override val selectedOption = defaultCustomizationOptionsViewModel.selectedOption
 
-    override fun deselectOption(): Boolean = defaultCustomizationOptionsViewModel.deselectOption()
+    override fun deselectOption(): Boolean {
+        keyguardQuickAffordancePickerViewModel2.resetPreview()
+        shapeAndGridPickerViewModel.resetPreview()
+        clockPickerViewModel.resetPreview()
+        return defaultCustomizationOptionsViewModel.deselectOption()
+    }
 
     val onCustomizeClockClicked: Flow<(() -> Unit)?> =
         selectedOption.map {
@@ -61,4 +90,72 @@ constructor(
                 null
             }
         }
+
+    val onCustomizeColorsClicked: Flow<(() -> Unit)?> =
+        selectedOption.map {
+            if (it == null) {
+                {
+                    defaultCustomizationOptionsViewModel.selectOption(
+                        ThemePickerCustomizationOptionUtil.ThemePickerHomeCustomizationOption.COLORS
+                    )
+                }
+            } else {
+                null
+            }
+        }
+
+    val onCustomizeShapeAndGridClicked: Flow<(() -> Unit)?> =
+        selectedOption.map {
+            if (it == null) {
+                {
+                    defaultCustomizationOptionsViewModel.selectOption(
+                        ThemePickerCustomizationOptionUtil.ThemePickerHomeCustomizationOption
+                            .APP_SHAPE_AND_GRID
+                    )
+                }
+            } else {
+                null
+            }
+        }
+
+    @OptIn(ExperimentalCoroutinesApi::class)
+    val onApplyButtonClicked =
+        selectedOption
+            .flatMapLatest {
+                when (it) {
+                    ThemePickerCustomizationOptionUtil.ThemePickerLockCustomizationOption.CLOCK ->
+                        clockPickerViewModel.onApply
+                    ThemePickerCustomizationOptionUtil.ThemePickerLockCustomizationOption
+                        .SHORTCUTS -> keyguardQuickAffordancePickerViewModel2.onApply
+                    ThemePickerCustomizationOptionUtil.ThemePickerHomeCustomizationOption
+                        .APP_SHAPE_AND_GRID -> shapeAndGridPickerViewModel.onApply
+                    else -> flow { emit(null) }
+                }
+            }
+            .map { onApply ->
+                {
+                    if (onApply != null) {
+                        viewModelScope.launch {
+                            onApply()
+                            // We only wait until onApply() is done to execute deselectOption()
+                            deselectOption()
+                        }
+                    } else {
+                        null
+                    }
+                }
+            }
+            .stateIn(viewModelScope, SharingStarted.Eagerly, null)
+
+    val isOnApplyEnabled: Flow<Boolean> = onApplyButtonClicked.map { it != null }
+
+    val isOnApplyVisible: Flow<Boolean> = selectedOption.map { it != null }
+
+    @ViewModelScoped
+    @AssistedFactory
+    interface Factory : CustomizationOptionsViewModelFactory {
+        override fun create(
+            viewModelScope: CoroutineScope
+        ): ThemePickerCustomizationOptionsViewModel
+    }
 }
diff --git a/src/com/android/wallpaper/picker/common/preview/ui/binder/ThemePickerWorkspaceCallbackBinder.kt b/src/com/android/wallpaper/picker/common/preview/ui/binder/ThemePickerWorkspaceCallbackBinder.kt
new file mode 100644
index 00000000..eec7d5ac
--- /dev/null
+++ b/src/com/android/wallpaper/picker/common/preview/ui/binder/ThemePickerWorkspaceCallbackBinder.kt
@@ -0,0 +1,151 @@
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
+import androidx.core.os.bundleOf
+import androidx.lifecycle.Lifecycle
+import androidx.lifecycle.LifecycleOwner
+import androidx.lifecycle.lifecycleScope
+import androidx.lifecycle.repeatOnLifecycle
+import com.android.systemui.shared.keyguard.shared.model.KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_END
+import com.android.systemui.shared.keyguard.shared.model.KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.KEY_INITIALLY_SELECTED_SLOT_ID
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.KEY_QUICK_AFFORDANCE_ID
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.KEY_SLOT_ID
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.MESSAGE_ID_DEFAULT_PREVIEW
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.MESSAGE_ID_PREVIEW_QUICK_AFFORDANCE_SELECTED
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.MESSAGE_ID_SLOT_SELECTED
+import com.android.systemui.shared.quickaffordance.shared.model.KeyguardPreviewConstants.MESSAGE_ID_START_CUSTOMIZING_QUICK_AFFORDANCES
+import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptionUtil.ThemePickerLockCustomizationOption
+import com.android.wallpaper.customization.ui.viewmodel.ThemePickerCustomizationOptionsViewModel
+import com.android.wallpaper.model.Screen
+import com.android.wallpaper.picker.common.preview.ui.binder.WorkspaceCallbackBinder.Companion.sendMessage
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.launch
+
+@Singleton
+class ThemePickerWorkspaceCallbackBinder
+@Inject
+constructor(private val defaultWorkspaceCallbackBinder: DefaultWorkspaceCallbackBinder) :
+    WorkspaceCallbackBinder {
+
+    override fun bind(
+        workspaceCallback: Message,
+        viewModel: CustomizationOptionsViewModel,
+        screen: Screen,
+        lifecycleOwner: LifecycleOwner,
+    ) {
+        defaultWorkspaceCallbackBinder.bind(
+            workspaceCallback = workspaceCallback,
+            viewModel = viewModel,
+            screen = screen,
+            lifecycleOwner = lifecycleOwner,
+        )
+
+        if (viewModel !is ThemePickerCustomizationOptionsViewModel) {
+            throw IllegalArgumentException(
+                "viewModel $viewModel is not a ThemePickerCustomizationOptionsViewModel."
+            )
+        }
+
+        when (screen) {
+            Screen.LOCK_SCREEN ->
+                lifecycleOwner.lifecycleScope.launch {
+                    lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                        launch {
+                            viewModel.selectedOption.collect {
+                                when (it) {
+                                    ThemePickerLockCustomizationOption.SHORTCUTS ->
+                                        workspaceCallback.sendMessage(
+                                            MESSAGE_ID_START_CUSTOMIZING_QUICK_AFFORDANCES,
+                                            Bundle().apply {
+                                                putString(
+                                                    KEY_INITIALLY_SELECTED_SLOT_ID,
+                                                    SLOT_ID_BOTTOM_START,
+                                                )
+                                            }
+                                        )
+                                    else ->
+                                        workspaceCallback.sendMessage(
+                                            MESSAGE_ID_DEFAULT_PREVIEW,
+                                            Bundle.EMPTY,
+                                        )
+                                }
+                            }
+                        }
+
+                        launch {
+                            viewModel.keyguardQuickAffordancePickerViewModel2.selectedSlotId
+                                .collect {
+                                    workspaceCallback.sendMessage(
+                                        MESSAGE_ID_SLOT_SELECTED,
+                                        Bundle().apply { putString(KEY_SLOT_ID, it) },
+                                    )
+                                }
+                        }
+
+                        launch {
+                            viewModel.keyguardQuickAffordancePickerViewModel2
+                                .previewingQuickAffordances
+                                .collect {
+                                    it[SLOT_ID_BOTTOM_START]?.let {
+                                        workspaceCallback.sendMessage(
+                                            MESSAGE_ID_PREVIEW_QUICK_AFFORDANCE_SELECTED,
+                                            Bundle().apply {
+                                                putString(KEY_SLOT_ID, SLOT_ID_BOTTOM_START)
+                                                putString(KEY_QUICK_AFFORDANCE_ID, it)
+                                            },
+                                        )
+                                    }
+                                    it[SLOT_ID_BOTTOM_END]?.let {
+                                        workspaceCallback.sendMessage(
+                                            MESSAGE_ID_PREVIEW_QUICK_AFFORDANCE_SELECTED,
+                                            Bundle().apply {
+                                                putString(KEY_SLOT_ID, SLOT_ID_BOTTOM_END)
+                                                putString(KEY_QUICK_AFFORDANCE_ID, it)
+                                            },
+                                        )
+                                    }
+                                }
+                        }
+                    }
+                }
+            Screen.HOME_SCREEN ->
+                lifecycleOwner.lifecycleScope.launch {
+                    lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
+                        launch {
+                            viewModel.shapeAndGridPickerViewModel.previewingGridOptionKey.collect {
+                                workspaceCallback.sendMessage(
+                                    MESSAGE_ID_UPDATE_GRID,
+                                    bundleOf(KEY_GRID_NAME to it)
+                                )
+                            }
+                        }
+                    }
+                }
+        }
+    }
+
+    companion object {
+        const val MESSAGE_ID_UPDATE_GRID = 7414
+        const val KEY_GRID_NAME = "grid_name"
+    }
+}
diff --git a/src_override/com/android/wallpaper/picker/di/modules/EffectsModule.kt b/src/com/android/wallpaper/picker/di/modules/ThemePickerSharedAppModule.kt
similarity index 73%
rename from src_override/com/android/wallpaper/picker/di/modules/EffectsModule.kt
rename to src/com/android/wallpaper/picker/di/modules/ThemePickerSharedAppModule.kt
index 4fc0fbb7..0b321966 100644
--- a/src_override/com/android/wallpaper/picker/di/modules/EffectsModule.kt
+++ b/src/com/android/wallpaper/picker/di/modules/ThemePickerSharedAppModule.kt
@@ -13,22 +13,22 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
+
 package com.android.wallpaper.picker.di.modules
 
-import com.android.wallpaper.effects.DefaultEffectsController
-import com.android.wallpaper.effects.EffectsController
+import com.android.customization.model.grid.DefaultGridOptionsManager
+import com.android.customization.model.grid.GridOptionsManager2
 import dagger.Binds
 import dagger.Module
 import dagger.hilt.InstallIn
 import dagger.hilt.components.SingletonComponent
 import javax.inject.Singleton
 
-/** This class provides the singleton scoped effects controller for wallpaper picker. */
-@InstallIn(SingletonComponent::class)
 @Module
-abstract class EffectsModule {
+@InstallIn(SingletonComponent::class)
+abstract class ThemePickerSharedAppModule {
 
     @Binds
     @Singleton
-    abstract fun bindEffectsController(impl: DefaultEffectsController): EffectsController
+    abstract fun bindGridOptionsManager2(impl: DefaultGridOptionsManager): GridOptionsManager2
 }
diff --git a/src_override/com/android/wallpaper/modules/ThemePickerActivityModule.kt b/src_override/com/android/wallpaper/modules/ThemePickerActivityModule.kt
index 90a0e3b2..31213e5c 100644
--- a/src_override/com/android/wallpaper/modules/ThemePickerActivityModule.kt
+++ b/src_override/com/android/wallpaper/modules/ThemePickerActivityModule.kt
@@ -16,6 +16,8 @@
 
 package com.android.wallpaper.modules
 
+import com.android.customization.picker.clock.ui.view.ClockViewFactory
+import com.android.customization.picker.clock.ui.view.ThemePickerClockViewFactory
 import com.android.wallpaper.customization.ui.util.ThemePickerCustomizationOptionUtil
 import com.android.wallpaper.picker.customization.ui.util.CustomizationOptionUtil
 import dagger.Binds
@@ -28,6 +30,10 @@ import dagger.hilt.android.scopes.ActivityScoped
 @InstallIn(ActivityComponent::class)
 abstract class ThemePickerActivityModule {
 
+    @Binds
+    @ActivityScoped
+    abstract fun bindClockViewFactory(impl: ThemePickerClockViewFactory): ClockViewFactory
+
     @Binds
     @ActivityScoped
     abstract fun bindCustomizationOptionUtil(
diff --git a/src_override/com/android/wallpaper/modules/ThemePickerActivityRetainedModule.kt b/src_override/com/android/wallpaper/modules/ThemePickerActivityRetainedModule.kt
new file mode 100644
index 00000000..9462c6a1
--- /dev/null
+++ b/src_override/com/android/wallpaper/modules/ThemePickerActivityRetainedModule.kt
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
+package com.android.wallpaper.modules
+
+import com.android.wallpaper.picker.preview.data.util.DefaultLiveWallpaperDownloader
+import com.android.wallpaper.picker.preview.data.util.LiveWallpaperDownloader
+import dagger.Binds
+import dagger.Module
+import dagger.hilt.InstallIn
+import dagger.hilt.android.components.ActivityRetainedComponent
+import dagger.hilt.android.scopes.ActivityRetainedScoped
+
+@Module
+@InstallIn(ActivityRetainedComponent::class)
+abstract class ThemePickerActivityRetainedModule {
+
+    @Binds
+    @ActivityRetainedScoped
+    abstract fun bindLiveWallpaperDownloader(
+        impl: DefaultLiveWallpaperDownloader
+    ): LiveWallpaperDownloader
+}
diff --git a/src_override/com/android/wallpaper/modules/ThemePickerAppModule.kt b/src_override/com/android/wallpaper/modules/ThemePickerAppModule.kt
index ab1541c5..31b4cd80 100644
--- a/src_override/com/android/wallpaper/modules/ThemePickerAppModule.kt
+++ b/src_override/com/android/wallpaper/modules/ThemePickerAppModule.kt
@@ -23,14 +23,42 @@ import com.android.customization.module.DefaultCustomizationPreferences
 import com.android.customization.module.ThemePickerInjector
 import com.android.customization.module.logging.ThemesUserEventLogger
 import com.android.customization.module.logging.ThemesUserEventLoggerImpl
+import com.android.customization.picker.clock.data.repository.ClockPickerRepository
+import com.android.customization.picker.clock.data.repository.ClockPickerRepositoryImpl
+import com.android.customization.picker.clock.data.repository.ClockRegistryProvider
+import com.android.customization.picker.color.data.repository.ColorPickerRepository
+import com.android.customization.picker.color.data.repository.ColorPickerRepositoryImpl
+import com.android.systemui.shared.clocks.ClockRegistry
+import com.android.systemui.shared.customization.data.content.CustomizationProviderClient
+import com.android.systemui.shared.customization.data.content.CustomizationProviderClientImpl
+import com.android.systemui.shared.settings.data.repository.SecureSettingsRepository
+import com.android.systemui.shared.settings.data.repository.SecureSettingsRepositoryImpl
+import com.android.systemui.shared.settings.data.repository.SystemSettingsRepository
+import com.android.systemui.shared.settings.data.repository.SystemSettingsRepositoryImpl
 import com.android.wallpaper.customization.ui.binder.ThemePickerCustomizationOptionsBinder
+import com.android.wallpaper.customization.ui.binder.ThemePickerToolbarBinder
+import com.android.wallpaper.effects.DefaultEffectsController
+import com.android.wallpaper.effects.EffectsController
 import com.android.wallpaper.module.DefaultPartnerProvider
 import com.android.wallpaper.module.PartnerProvider
 import com.android.wallpaper.module.WallpaperPreferences
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
+import com.android.wallpaper.picker.common.preview.ui.binder.ThemePickerWorkspaceCallbackBinder
+import com.android.wallpaper.picker.common.preview.ui.binder.WorkspaceCallbackBinder
 import com.android.wallpaper.picker.customization.ui.binder.CustomizationOptionsBinder
-import com.android.wallpaper.picker.preview.data.util.DefaultLiveWallpaperDownloader
-import com.android.wallpaper.picker.preview.data.util.LiveWallpaperDownloader
+import com.android.wallpaper.picker.customization.ui.binder.ToolbarBinder
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
+import com.android.wallpaper.picker.di.modules.MainDispatcher
 import com.android.wallpaper.picker.preview.ui.util.DefaultImageEffectDialogUtil
 import com.android.wallpaper.picker.preview.ui.util.ImageEffectDialogUtil
 import com.android.wallpaper.util.converter.DefaultWallpaperModelFactory
@@ -42,55 +70,118 @@ import dagger.hilt.InstallIn
 import dagger.hilt.android.qualifiers.ApplicationContext
 import dagger.hilt.components.SingletonComponent
 import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
 
 @Module
 @InstallIn(SingletonComponent::class)
 abstract class ThemePickerAppModule {
-    @Binds @Singleton abstract fun bindInjector(impl: ThemePickerInjector): CustomizationInjector
 
     @Binds
     @Singleton
-    abstract fun bindUserEventLogger(impl: ThemesUserEventLoggerImpl): UserEventLogger
+    abstract fun bindClockPickerRepository(impl: ClockPickerRepositoryImpl): ClockPickerRepository
 
     @Binds
     @Singleton
-    abstract fun bindThemesUserEventLogger(impl: ThemesUserEventLoggerImpl): ThemesUserEventLogger
+    abstract fun bindColorPickerRepository(impl: ColorPickerRepositoryImpl): ColorPickerRepository
 
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
+    abstract fun bindWallpaperCategoryWrapper(
+        impl: DefaultWallpaperCategoryWrapper
+    ): WallpaperCategoryWrapper
 
     @Binds
     @Singleton
-    abstract fun bindPartnerProvider(impl: DefaultPartnerProvider): PartnerProvider
+    abstract fun bindCustomizationInjector(impl: ThemePickerInjector): CustomizationInjector
+
+    @Binds
+    @Singleton
+    abstract fun bindCustomizationOptionsBinder(
+        impl: ThemePickerCustomizationOptionsBinder
+    ): CustomizationOptionsBinder
+
+    @Binds
+    @Singleton
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
-        impl: ThemePickerCustomizationOptionsBinder
-    ): CustomizationOptionsBinder
+    abstract fun bindIndividualPickerFactoryFragment(
+        impl: DefaultIndividualPickerFactory
+    ): IndividualPickerFactory
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
+    @Binds
+    @Singleton
+    abstract fun bindThemesUserEventLogger(impl: ThemesUserEventLoggerImpl): ThemesUserEventLogger
+
+    @Binds @Singleton abstract fun bindToolbarBinder(impl: ThemePickerToolbarBinder): ToolbarBinder
+
+    @Binds
+    @Singleton
+    abstract fun bindUserEventLogger(impl: ThemesUserEventLoggerImpl): UserEventLogger
+
+    @Binds
+    @Singleton
+    abstract fun bindWallpaperModelFactory(
+        impl: DefaultWallpaperModelFactory
+    ): WallpaperModelFactory
+
+    @Binds
+    @Singleton
+    abstract fun bindWallpaperPreferences(
+        impl: DefaultCustomizationPreferences
+    ): WallpaperPreferences
+
+    @Binds
+    @Singleton
+    abstract fun bindWorkspaceCallbackBinder(
+        impl: ThemePickerWorkspaceCallbackBinder
+    ): WorkspaceCallbackBinder
 
     companion object {
+
         @Provides
         @Singleton
-        fun provideWallpaperPreferences(
-            @ApplicationContext context: Context
-        ): WallpaperPreferences {
-            return DefaultCustomizationPreferences(context)
+        fun provideClockRegistry(
+            @ApplicationContext context: Context,
+            @MainDispatcher mainScope: CoroutineScope,
+            @MainDispatcher mainDispatcher: CoroutineDispatcher,
+            @BackgroundDispatcher bgDispatcher: CoroutineDispatcher,
+        ): ClockRegistry {
+            return ClockRegistryProvider(
+                    context = context,
+                    coroutineScope = mainScope,
+                    mainDispatcher = mainDispatcher,
+                    backgroundDispatcher = bgDispatcher,
+                )
+                .get()
         }
 
         @Provides
@@ -100,5 +191,32 @@ abstract class ThemePickerAppModule {
         ): ColorCustomizationManager {
             return ColorCustomizationManager.getInstance(context, OverlayManagerCompat(context))
         }
+
+        @Provides
+        @Singleton
+        fun provideCustomizationProviderClient(
+            @ApplicationContext context: Context,
+            @BackgroundDispatcher bgDispatcher: CoroutineDispatcher,
+        ): CustomizationProviderClient {
+            return CustomizationProviderClientImpl(context, bgDispatcher)
+        }
+
+        @Provides
+        @Singleton
+        fun provideSecureSettingsRepository(
+            @ApplicationContext context: Context,
+            @BackgroundDispatcher bgDispatcher: CoroutineDispatcher,
+        ): SecureSettingsRepository {
+            return SecureSettingsRepositoryImpl(context.contentResolver, bgDispatcher)
+        }
+
+        @Provides
+        @Singleton
+        fun provideSystemSettingsRepository(
+            @ApplicationContext context: Context,
+            @BackgroundDispatcher bgDispatcher: CoroutineDispatcher,
+        ): SystemSettingsRepository {
+            return SystemSettingsRepositoryImpl(context.contentResolver, bgDispatcher)
+        }
     }
 }
diff --git a/src_override/com/android/wallpaper/modules/ThemePickerViewModelModule.kt b/src_override/com/android/wallpaper/modules/ThemePickerViewModelModule.kt
index 3a80437b..3a2da15b 100644
--- a/src_override/com/android/wallpaper/modules/ThemePickerViewModelModule.kt
+++ b/src_override/com/android/wallpaper/modules/ThemePickerViewModelModule.kt
@@ -17,7 +17,7 @@
 package com.android.wallpaper.modules
 
 import com.android.wallpaper.customization.ui.viewmodel.ThemePickerCustomizationOptionsViewModel
-import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModel
+import com.android.wallpaper.picker.customization.ui.viewmodel.CustomizationOptionsViewModelFactory
 import dagger.Binds
 import dagger.Module
 import dagger.hilt.InstallIn
@@ -30,7 +30,7 @@ abstract class ThemePickerViewModelModule {
 
     @Binds
     @ViewModelScoped
-    abstract fun bindCustomizationOptionsViewModel(
-        impl: ThemePickerCustomizationOptionsViewModel
-    ): CustomizationOptionsViewModel
+    abstract fun bindCustomizationOptionsViewModelFactory(
+        impl: ThemePickerCustomizationOptionsViewModel.Factory
+    ): CustomizationOptionsViewModelFactory
 }
diff --git a/src_override/com/android/wallpaper/picker/di/modules/InteractorModule.kt b/src_override/com/android/wallpaper/picker/di/modules/InteractorModule.kt
deleted file mode 100644
index 81edb2fa..00000000
--- a/src_override/com/android/wallpaper/picker/di/modules/InteractorModule.kt
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
- */
-package com.android.wallpaper.picker.di.modules
-
-import android.text.TextUtils
-import com.android.customization.model.color.ColorCustomizationManager
-import com.android.customization.model.color.ColorOptionsProvider.COLOR_SOURCE_PRESET
-import com.android.wallpaper.picker.customization.data.repository.WallpaperRepository
-import com.android.wallpaper.picker.customization.domain.interactor.WallpaperInteractor
-import dagger.Module
-import dagger.Provides
-import dagger.hilt.InstallIn
-import dagger.hilt.components.SingletonComponent
-import javax.inject.Singleton
-
-/** This class provides the singleton scoped interactors for theme picker. */
-@InstallIn(SingletonComponent::class)
-@Module
-internal object InteractorModule {
-
-    @Provides
-    @Singleton
-    fun provideWallpaperInteractor(
-        wallpaperRepository: WallpaperRepository,
-        colorCustomizationManager: ColorCustomizationManager,
-    ): WallpaperInteractor {
-        return WallpaperInteractor(wallpaperRepository) {
-            TextUtils.equals(colorCustomizationManager.currentColorSource, COLOR_SOURCE_PRESET)
-        }
-    }
-}
diff --git a/tests/Android.bp b/tests/Android.bp
index 5b12a4a4..a311e5a0 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -65,9 +65,9 @@ android_test {
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
 
     kotlincflags: ["-Xjvm-default=all"],
diff --git a/tests/common/src/com/android/customization/model/grid/FakeGridOptionsManager.kt b/tests/common/src/com/android/customization/model/grid/FakeGridOptionsManager.kt
new file mode 100644
index 00000000..cc239818
--- /dev/null
+++ b/tests/common/src/com/android/customization/model/grid/FakeGridOptionsManager.kt
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
+package com.android.customization.model.grid
+
+import javax.inject.Inject
+import javax.inject.Singleton
+
+@Singleton
+class FakeGridOptionsManager @Inject constructor() : GridOptionsManager2 {
+
+    var isGridOptionAvailable: Boolean = true
+
+    private var gridOptions: List<GridOptionModel>? = DEFAULT_GRID_OPTION_LIST
+
+    override suspend fun isGridOptionAvailable(): Boolean = isGridOptionAvailable
+
+    override suspend fun getGridOptions(): List<GridOptionModel>? = gridOptions
+
+    override fun applyGridOption(gridName: String): Int {
+        gridOptions = gridOptions?.map { it.copy(isCurrent = it.key == gridName) }
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
+    }
+}
diff --git a/tests/common/src/com/android/customization/module/logging/TestThemesUserEventLogger.kt b/tests/common/src/com/android/customization/module/logging/TestThemesUserEventLogger.kt
index 8e9dacdb..46510673 100644
--- a/tests/common/src/com/android/customization/module/logging/TestThemesUserEventLogger.kt
+++ b/tests/common/src/com/android/customization/module/logging/TestThemesUserEventLogger.kt
@@ -31,11 +31,15 @@ class TestThemesUserEventLogger @Inject constructor() :
     @ColorSource
     var themeColorSource: Int = StyleEnums.COLOR_SOURCE_UNSPECIFIED
         private set
+
     var themeColorStyle: Int = -1
         private set
+
     var themeSeedColor: Int = -1
         private set
 
+    var shortcutLogs: List<Pair<String, String>> = emptyList()
+
     override fun logThemeColorApplied(@ColorSource source: Int, style: Int, seedColor: Int) {
         this.themeColorSource = source
         this.themeColorStyle = style
@@ -56,7 +60,9 @@ class TestThemesUserEventLogger @Inject constructor() :
 
     override fun logLockScreenNotificationApplied(showLockScreenNotifications: Boolean) {}
 
-    override fun logShortcutApplied(shortcut: String, shortcutSlotId: String) {}
+    override fun logShortcutApplied(shortcut: String, shortcutSlotId: String) {
+        shortcutLogs = shortcutLogs.toMutableList().apply { add(shortcut to shortcutSlotId) }
+    }
 
     override fun logDarkThemeApplied(useDarkTheme: Boolean) {}
 
diff --git a/tests/common/src/com/android/customization/testing/TestCustomizationInjector.kt b/tests/common/src/com/android/customization/testing/TestCustomizationInjector.kt
index caa5029f..4e97599b 100644
--- a/tests/common/src/com/android/customization/testing/TestCustomizationInjector.kt
+++ b/tests/common/src/com/android/customization/testing/TestCustomizationInjector.kt
@@ -12,11 +12,10 @@ import com.android.customization.picker.clock.domain.interactor.ClockPickerInter
 import com.android.customization.picker.clock.ui.view.ClockViewFactory
 import com.android.customization.picker.clock.ui.viewmodel.ClockCarouselViewModel
 import com.android.customization.picker.clock.ui.viewmodel.ClockSettingsViewModel
-import com.android.customization.picker.color.domain.interactor.ColorPickerInteractor
 import com.android.customization.picker.color.ui.viewmodel.ColorPickerViewModel
 import com.android.customization.picker.quickaffordance.domain.interactor.KeyguardQuickAffordancePickerInteractor
-import com.android.systemui.shared.clocks.ClockRegistry
 import com.android.wallpaper.module.logging.UserEventLogger
+import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper
 import com.android.wallpaper.picker.customization.data.repository.WallpaperColorsRepository
 import com.android.wallpaper.testing.TestInjector
 import javax.inject.Inject
@@ -27,7 +26,7 @@ open class TestCustomizationInjector
 @Inject
 constructor(
     private val customPrefs: TestDefaultCustomizationPreferences,
-    private val themesUserEventLogger: ThemesUserEventLogger
+    private val themesUserEventLogger: ThemesUserEventLogger,
 ) : TestInjector(themesUserEventLogger), CustomizationInjector {
     /////////////////
     // CustomizationInjector implementations
@@ -43,32 +42,14 @@ constructor(
         throw UnsupportedOperationException("not implemented")
     }
 
-    override fun getClockRegistry(context: Context): ClockRegistry? {
-        throw UnsupportedOperationException("not implemented")
-    }
-
-    override fun getClockPickerInteractor(context: Context): ClockPickerInteractor {
-        throw UnsupportedOperationException("not implemented")
-    }
-
     override fun getWallpaperColorResources(
         wallpaperColors: WallpaperColors,
-        context: Context
-    ): WallpaperColorResources {
-        throw UnsupportedOperationException("not implemented")
-    }
-
-    override fun getColorPickerInteractor(
         context: Context,
-        wallpaperColorsRepository: WallpaperColorsRepository,
-    ): ColorPickerInteractor {
+    ): WallpaperColorResources {
         throw UnsupportedOperationException("not implemented")
     }
 
-    override fun getColorPickerViewModelFactory(
-        context: Context,
-        wallpaperColorsRepository: WallpaperColorsRepository,
-    ): ColorPickerViewModel.Factory {
+    override fun getColorPickerViewModelFactory(context: Context): ColorPickerViewModel.Factory {
         throw UnsupportedOperationException("not implemented")
     }
 
@@ -99,4 +80,8 @@ constructor(
     override fun getUserEventLogger(): UserEventLogger {
         return themesUserEventLogger
     }
+
+    override fun getWallpaperCategoryWrapper(): WallpaperCategoryWrapper {
+        return super.fakeWallpaperCategoryWrapper
+    }
 }
diff --git a/tests/common/src/com/android/wallpaper/di/modules/ThemePickerSharedAppTestModule.kt b/tests/common/src/com/android/wallpaper/di/modules/ThemePickerSharedAppTestModule.kt
new file mode 100644
index 00000000..7781d4ec
--- /dev/null
+++ b/tests/common/src/com/android/wallpaper/di/modules/ThemePickerSharedAppTestModule.kt
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
+package com.android.wallpaper.di.modules
+
+import com.android.customization.model.grid.FakeGridOptionsManager
+import com.android.customization.model.grid.GridOptionsManager2
+import com.android.wallpaper.picker.di.modules.ThemePickerSharedAppModule
+import dagger.Binds
+import dagger.Module
+import dagger.hilt.components.SingletonComponent
+import dagger.hilt.testing.TestInstallIn
+import javax.inject.Singleton
+
+@Module
+@TestInstallIn(
+    components = [SingletonComponent::class],
+    replaces = [ThemePickerSharedAppModule::class]
+)
+abstract class ThemePickerSharedAppTestModule {
+
+    @Binds
+    @Singleton
+    abstract fun bindGridOptionsManager2(impl: FakeGridOptionsManager): GridOptionsManager2
+}
diff --git a/tests/module/src/com/android/wallpaper/ThemePickerTestModule.kt b/tests/module/src/com/android/wallpaper/ThemePickerTestModule.kt
index 5ed89629..8f09d51a 100644
--- a/tests/module/src/com/android/wallpaper/ThemePickerTestModule.kt
+++ b/tests/module/src/com/android/wallpaper/ThemePickerTestModule.kt
@@ -15,6 +15,7 @@
  */
 package com.android.wallpaper
 
+import android.content.Context
 import androidx.test.core.app.ApplicationProvider
 import com.android.customization.model.color.ColorCustomizationManager
 import com.android.customization.model.theme.OverlayManagerCompat
@@ -22,8 +23,19 @@ import com.android.customization.module.CustomizationInjector
 import com.android.customization.module.CustomizationPreferences
 import com.android.customization.module.logging.TestThemesUserEventLogger
 import com.android.customization.module.logging.ThemesUserEventLogger
+import com.android.customization.picker.clock.data.repository.ClockPickerRepository
+import com.android.customization.picker.clock.data.repository.ClockPickerRepositoryImpl
+import com.android.customization.picker.clock.data.repository.ClockRegistryProvider
+import com.android.customization.picker.color.data.repository.ColorPickerRepository
+import com.android.customization.picker.color.data.repository.ColorPickerRepositoryImpl
 import com.android.customization.testing.TestCustomizationInjector
 import com.android.customization.testing.TestDefaultCustomizationPreferences
+import com.android.systemui.shared.clocks.ClockRegistry
+import com.android.systemui.shared.customization.data.content.CustomizationProviderClient
+import com.android.systemui.shared.customization.data.content.CustomizationProviderClientImpl
+import com.android.systemui.shared.settings.data.repository.SecureSettingsRepository
+import com.android.systemui.shared.settings.data.repository.SecureSettingsRepositoryImpl
+import com.android.wallpaper.customization.ui.binder.ThemePickerToolbarBinder
 import com.android.wallpaper.effects.EffectsController
 import com.android.wallpaper.effects.FakeEffectsController
 import com.android.wallpaper.module.Injector
@@ -33,47 +45,42 @@ import com.android.wallpaper.module.logging.TestUserEventLogger
 import com.android.wallpaper.module.logging.UserEventLogger
 import com.android.wallpaper.modules.ThemePickerAppModule
 import com.android.wallpaper.network.Requester
+import com.android.wallpaper.picker.category.wrapper.WallpaperCategoryWrapper
+import com.android.wallpaper.picker.common.preview.ui.binder.ThemePickerWorkspaceCallbackBinder
+import com.android.wallpaper.picker.common.preview.ui.binder.WorkspaceCallbackBinder
 import com.android.wallpaper.picker.customization.ui.binder.CustomizationOptionsBinder
 import com.android.wallpaper.picker.customization.ui.binder.DefaultCustomizationOptionsBinder
-import com.android.wallpaper.picker.di.modules.EffectsModule
-import com.android.wallpaper.picker.preview.data.util.FakeLiveWallpaperDownloader
-import com.android.wallpaper.picker.preview.data.util.LiveWallpaperDownloader
+import com.android.wallpaper.picker.customization.ui.binder.ToolbarBinder
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
+import com.android.wallpaper.picker.di.modules.MainDispatcher
 import com.android.wallpaper.picker.preview.ui.util.DefaultImageEffectDialogUtil
 import com.android.wallpaper.picker.preview.ui.util.ImageEffectDialogUtil
 import com.android.wallpaper.testing.FakeDefaultRequester
+import com.android.wallpaper.testing.FakeWallpaperCategoryWrapper
 import com.android.wallpaper.testing.TestPartnerProvider
 import com.android.wallpaper.util.converter.DefaultWallpaperModelFactory
 import com.android.wallpaper.util.converter.WallpaperModelFactory
 import dagger.Binds
 import dagger.Module
 import dagger.Provides
+import dagger.hilt.android.qualifiers.ApplicationContext
 import dagger.hilt.components.SingletonComponent
 import dagger.hilt.testing.TestInstallIn
 import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
 
 @Module
-@TestInstallIn(
-    components = [SingletonComponent::class],
-    replaces = [EffectsModule::class, ThemePickerAppModule::class]
-)
+@TestInstallIn(components = [SingletonComponent::class], replaces = [ThemePickerAppModule::class])
 abstract class ThemePickerTestModule {
-    //// WallpaperPicker2 prod
-
-    @Binds @Singleton abstract fun bindInjector(impl: TestCustomizationInjector): Injector
-
-    @Binds @Singleton abstract fun bindUserEventLogger(impl: TestUserEventLogger): UserEventLogger
-
-    @Binds @Singleton abstract fun bindFakeRequester(impl: FakeDefaultRequester): Requester
 
     @Binds
     @Singleton
-    abstract fun bindThemesUserEventLogger(impl: TestThemesUserEventLogger): ThemesUserEventLogger
+    abstract fun bindClockPickerRepository(impl: ClockPickerRepositoryImpl): ClockPickerRepository
 
     @Binds
     @Singleton
-    abstract fun bindWallpaperPrefs(impl: TestDefaultCustomizationPreferences): WallpaperPreferences
-
-    //// ThemePicker prod
+    abstract fun bindColorPickerRepository(impl: ColorPickerRepositoryImpl): ColorPickerRepository
 
     @Binds
     @Singleton
@@ -81,50 +88,110 @@ abstract class ThemePickerTestModule {
 
     @Binds
     @Singleton
-    abstract fun bindCustomizationPrefs(
+    abstract fun bindCustomizationOptionsBinder(
+        impl: DefaultCustomizationOptionsBinder
+    ): CustomizationOptionsBinder
+
+    @Binds
+    @Singleton
+    abstract fun bindCustomizationPreferences(
         impl: TestDefaultCustomizationPreferences
     ): CustomizationPreferences
 
     @Binds
     @Singleton
-    abstract fun bindWallpaperModelFactory(
-        impl: DefaultWallpaperModelFactory
-    ): WallpaperModelFactory
+    abstract fun bindEffectsController(impl: FakeEffectsController): EffectsController
 
     @Binds
     @Singleton
-    abstract fun bindLiveWallpaperDownloader(
-        impl: FakeLiveWallpaperDownloader
-    ): LiveWallpaperDownloader
+    abstract fun bindWallpaperCategoryWrapper(
+        impl: FakeWallpaperCategoryWrapper
+    ): WallpaperCategoryWrapper
+
+    @Binds
+    @Singleton
+    abstract fun bindImageEffectDialogUtil(
+        impl: DefaultImageEffectDialogUtil
+    ): ImageEffectDialogUtil
+
+    @Binds @Singleton abstract fun bindInjector(impl: TestCustomizationInjector): Injector
 
     @Binds
     @Singleton
     abstract fun providePartnerProvider(impl: TestPartnerProvider): PartnerProvider
 
+    @Binds @Singleton abstract fun bindRequester(impl: FakeDefaultRequester): Requester
+
     @Binds
     @Singleton
-    abstract fun bindEffectsWallpaperDialogUtil(
-        impl: DefaultImageEffectDialogUtil
-    ): ImageEffectDialogUtil
+    abstract fun bindThemesUserEventLogger(impl: TestThemesUserEventLogger): ThemesUserEventLogger
+
+    @Binds @Singleton abstract fun bindToolbarBinder(impl: ThemePickerToolbarBinder): ToolbarBinder
+
+    @Binds @Singleton abstract fun bindUserEventLogger(impl: TestUserEventLogger): UserEventLogger
 
     @Binds
     @Singleton
-    abstract fun bindEffectsController(impl: FakeEffectsController): EffectsController
+    abstract fun bindWallpaperModelFactory(
+        impl: DefaultWallpaperModelFactory
+    ): WallpaperModelFactory
 
     @Binds
     @Singleton
-    abstract fun bindCustomizationOptionsBinder(
-        impl: DefaultCustomizationOptionsBinder
-    ): CustomizationOptionsBinder
+    abstract fun bindWallpaperPreferences(
+        impl: TestDefaultCustomizationPreferences
+    ): WallpaperPreferences
+
+    @Binds
+    @Singleton
+    abstract fun bindWorkspaceCallbackBinder(
+        impl: ThemePickerWorkspaceCallbackBinder
+    ): WorkspaceCallbackBinder
 
     companion object {
+
+        @Provides
+        @Singleton
+        fun provideClockRegistry(
+            @ApplicationContext context: Context,
+            @MainDispatcher mainScope: CoroutineScope,
+            @MainDispatcher mainDispatcher: CoroutineDispatcher,
+            @BackgroundDispatcher bgDispatcher: CoroutineDispatcher,
+        ): ClockRegistry {
+            return ClockRegistryProvider(
+                    context = context,
+                    coroutineScope = mainScope,
+                    mainDispatcher = mainDispatcher,
+                    backgroundDispatcher = bgDispatcher,
+                )
+                .get()
+        }
+
         @Provides
         @Singleton
         fun provideColorCustomizationManager(): ColorCustomizationManager {
             return ColorCustomizationManager.getInstance(
                 ApplicationProvider.getApplicationContext(),
-                OverlayManagerCompat(ApplicationProvider.getApplicationContext())
+                OverlayManagerCompat(ApplicationProvider.getApplicationContext()),
             )
         }
+
+        @Provides
+        @Singleton
+        fun provideCustomizationProviderClient(
+            @ApplicationContext context: Context,
+            @BackgroundDispatcher bgDispatcher: CoroutineDispatcher,
+        ): CustomizationProviderClient {
+            return CustomizationProviderClientImpl(context, bgDispatcher)
+        }
+
+        @Provides
+        @Singleton
+        fun provideSecureSettingsRepository(
+            @ApplicationContext context: Context,
+            @BackgroundDispatcher bgDispatcher: CoroutineDispatcher,
+        ): SecureSettingsRepository {
+            return SecureSettingsRepositoryImpl(context.contentResolver, bgDispatcher)
+        }
     }
 }
diff --git a/tests/robotests/src/com/android/customization/model/grid/data/repository/FakeGridRepository.kt b/tests/robotests/src/com/android/customization/model/grid/data/repository/FakeGridRepository.kt
index de68bf07..391e2708 100644
--- a/tests/robotests/src/com/android/customization/model/grid/data/repository/FakeGridRepository.kt
+++ b/tests/robotests/src/com/android/customization/model/grid/data/repository/FakeGridRepository.kt
@@ -18,7 +18,6 @@
 package com.android.customization.model.grid.data.repository
 
 import com.android.customization.model.CustomizationManager
-import com.android.customization.model.grid.GridOption
 import com.android.customization.picker.grid.data.repository.GridRepository
 import com.android.customization.picker.grid.shared.model.GridOptionItemModel
 import com.android.customization.picker.grid.shared.model.GridOptionItemsModel
@@ -54,7 +53,7 @@ class FakeGridRepository(
         return options
     }
 
-    override fun getSelectedOption(): GridOption? = null
+    override fun getSelectedOption() = MutableStateFlow(null)
 
     override fun applySelectedOption(callback: CustomizationManager.Callback) {}
 
diff --git a/tests/robotests/src/com/android/customization/model/notifications/domain/interactor/NotificationsSnapshotRestorerTest.kt b/tests/robotests/src/com/android/customization/model/notifications/domain/interactor/NotificationsSnapshotRestorerTest.kt
index bf8cfda2..094ab818 100644
--- a/tests/robotests/src/com/android/customization/model/notifications/domain/interactor/NotificationsSnapshotRestorerTest.kt
+++ b/tests/robotests/src/com/android/customization/model/notifications/domain/interactor/NotificationsSnapshotRestorerTest.kt
@@ -23,6 +23,7 @@ import com.android.customization.picker.notifications.domain.interactor.Notifica
 import com.android.systemui.shared.notifications.data.repository.NotificationSettingsRepository
 import com.android.systemui.shared.notifications.domain.interactor.NotificationSettingsInteractor
 import com.android.systemui.shared.settings.data.repository.FakeSecureSettingsRepository
+import com.android.systemui.shared.settings.data.repository.FakeSystemSettingsRepository
 import com.android.wallpaper.testing.FakeSnapshotStore
 import com.android.wallpaper.testing.collectLastValue
 import com.google.common.truth.Truth.assertThat
@@ -44,6 +45,7 @@ class NotificationsSnapshotRestorerTest {
 
     private lateinit var underTest: NotificationsSnapshotRestorer
     private lateinit var fakeSecureSettingsRepository: FakeSecureSettingsRepository
+    private lateinit var fakeSystemSettingsRepository: FakeSystemSettingsRepository
     private lateinit var interactor: NotificationSettingsInteractor
 
     private lateinit var testScope: TestScope
@@ -54,13 +56,15 @@ class NotificationsSnapshotRestorerTest {
         Dispatchers.setMain(testDispatcher)
         testScope = TestScope(testDispatcher)
         fakeSecureSettingsRepository = FakeSecureSettingsRepository()
+        fakeSystemSettingsRepository = FakeSystemSettingsRepository()
         interactor =
             NotificationSettingsInteractor(
                 repository =
                     NotificationSettingsRepository(
-                        scope = testScope.backgroundScope,
+                        backgroundScope = testScope.backgroundScope,
                         backgroundDispatcher = testDispatcher,
                         secureSettingsRepository = fakeSecureSettingsRepository,
+                        systemSettingsRepository = fakeSystemSettingsRepository,
                     ),
             )
         underTest =
diff --git a/tests/robotests/src/com/android/customization/model/picker/color/domain/interactor/ColorPickerInteractorTest.kt b/tests/robotests/src/com/android/customization/model/picker/color/domain/interactor/ColorPickerInteractorTest.kt
index d4f24ee0..97d4a9a0 100644
--- a/tests/robotests/src/com/android/customization/model/picker/color/domain/interactor/ColorPickerInteractorTest.kt
+++ b/tests/robotests/src/com/android/customization/model/picker/color/domain/interactor/ColorPickerInteractorTest.kt
@@ -52,11 +52,10 @@ class ColorPickerInteractorTest {
         underTest =
             ColorPickerInteractor(
                 repository = repository,
-                snapshotRestorer = {
-                    ColorPickerSnapshotRestorer(interactor = underTest).apply {
+                snapshotRestorer =
+                    ColorPickerSnapshotRestorer(repository = repository).apply {
                         runBlocking { setUpSnapshotRestorer(store = store) }
-                    }
-                },
+                    },
             )
         repository.setOptions(4, 4, ColorType.WALLPAPER_COLOR, 0)
     }
diff --git a/tests/robotests/src/com/android/customization/model/picker/color/domain/interactor/ColorPickerSnapshotRestorerTest.kt b/tests/robotests/src/com/android/customization/model/picker/color/domain/interactor/ColorPickerSnapshotRestorerTest.kt
index 5f3e39eb..b050237f 100644
--- a/tests/robotests/src/com/android/customization/model/picker/color/domain/interactor/ColorPickerSnapshotRestorerTest.kt
+++ b/tests/robotests/src/com/android/customization/model/picker/color/domain/interactor/ColorPickerSnapshotRestorerTest.kt
@@ -21,7 +21,6 @@ import android.content.Context
 import androidx.test.filters.SmallTest
 import androidx.test.platform.app.InstrumentationRegistry
 import com.android.customization.picker.color.data.repository.FakeColorPickerRepository
-import com.android.customization.picker.color.domain.interactor.ColorPickerInteractor
 import com.android.customization.picker.color.domain.interactor.ColorPickerSnapshotRestorer
 import com.android.customization.picker.color.shared.model.ColorOptionModel
 import com.android.customization.picker.color.shared.model.ColorType
@@ -51,14 +50,7 @@ class ColorPickerSnapshotRestorerTest {
     fun setUp() {
         context = InstrumentationRegistry.getInstrumentation().targetContext
         repository = FakeColorPickerRepository(context = context)
-        underTest =
-            ColorPickerSnapshotRestorer(
-                interactor =
-                    ColorPickerInteractor(
-                        repository = repository,
-                        snapshotRestorer = { underTest },
-                    )
-            )
+        underTest = ColorPickerSnapshotRestorer(repository = repository)
         store = FakeSnapshotStore()
     }
 
diff --git a/tests/robotests/src/com/android/customization/model/picker/color/ui/viewmodel/ColorPickerViewModelTest.kt b/tests/robotests/src/com/android/customization/model/picker/color/ui/viewmodel/ColorPickerViewModelTest.kt
index 889720e4..f5878a48 100644
--- a/tests/robotests/src/com/android/customization/model/picker/color/ui/viewmodel/ColorPickerViewModelTest.kt
+++ b/tests/robotests/src/com/android/customization/model/picker/color/ui/viewmodel/ColorPickerViewModelTest.kt
@@ -76,11 +76,10 @@ class ColorPickerViewModelTest {
         interactor =
             ColorPickerInteractor(
                 repository = repository,
-                snapshotRestorer = {
-                    ColorPickerSnapshotRestorer(interactor = interactor).apply {
+                snapshotRestorer =
+                    ColorPickerSnapshotRestorer(repository = repository).apply {
                         runBlocking { setUpSnapshotRestorer(store = store) }
-                    }
-                },
+                    },
             )
 
         underTest =
diff --git a/tests/robotests/src/com/android/customization/model/picker/quickaffordance/data/repository/KeyguardQuickAffordancePickerRepositoryTest.kt b/tests/robotests/src/com/android/customization/model/picker/quickaffordance/data/repository/KeyguardQuickAffordancePickerRepositoryTest.kt
index 8687b301..55fb2cbb 100644
--- a/tests/robotests/src/com/android/customization/model/picker/quickaffordance/data/repository/KeyguardQuickAffordancePickerRepositoryTest.kt
+++ b/tests/robotests/src/com/android/customization/model/picker/quickaffordance/data/repository/KeyguardQuickAffordancePickerRepositoryTest.kt
@@ -53,7 +53,7 @@ class KeyguardQuickAffordancePickerRepositoryTest {
         underTest =
             KeyguardQuickAffordancePickerRepository(
                 client = client,
-                scope = testScope.backgroundScope,
+                mainScope = testScope.backgroundScope,
             )
     }
 
diff --git a/tests/robotests/src/com/android/customization/model/picker/quickaffordance/domain/interactor/KeyguardQuickAffordancePickerInteractorTest.kt b/tests/robotests/src/com/android/customization/model/picker/quickaffordance/domain/interactor/KeyguardQuickAffordancePickerInteractorTest.kt
index 4b4790ad..2b84ee4c 100644
--- a/tests/robotests/src/com/android/customization/model/picker/quickaffordance/domain/interactor/KeyguardQuickAffordancePickerInteractorTest.kt
+++ b/tests/robotests/src/com/android/customization/model/picker/quickaffordance/domain/interactor/KeyguardQuickAffordancePickerInteractorTest.kt
@@ -24,12 +24,10 @@ import com.android.customization.picker.quickaffordance.domain.interactor.Keygua
 import com.android.customization.picker.quickaffordance.shared.model.KeyguardQuickAffordancePickerSelectionModel
 import com.android.systemui.shared.customization.data.content.FakeCustomizationProviderClient
 import com.android.systemui.shared.keyguard.shared.model.KeyguardQuickAffordanceSlots
-import com.android.wallpaper.testing.FakeSnapshotStore
 import com.android.wallpaper.testing.collectLastValue
 import com.google.common.truth.Truth.assertThat
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.ExperimentalCoroutinesApi
-import kotlinx.coroutines.runBlocking
 import kotlinx.coroutines.test.StandardTestDispatcher
 import kotlinx.coroutines.test.TestScope
 import kotlinx.coroutines.test.resetMain
@@ -62,16 +60,10 @@ class KeyguardQuickAffordancePickerInteractorTest {
                 repository =
                     KeyguardQuickAffordancePickerRepository(
                         client = client,
-                        scope = testScope.backgroundScope,
+                        mainScope = testScope.backgroundScope,
                     ),
                 client = client,
-                snapshotRestorer = {
-                    KeyguardQuickAffordanceSnapshotRestorer(
-                            interactor = underTest,
-                            client = client,
-                        )
-                        .apply { runBlocking { setUpSnapshotRestorer(FakeSnapshotStore()) } }
-                },
+                snapshotRestorer = KeyguardQuickAffordanceSnapshotRestorer(client),
             )
     }
 
diff --git a/tests/robotests/src/com/android/customization/model/picker/quickaffordance/ui/viewmodel/KeyguardQuickAffordancePickerViewModelTest.kt b/tests/robotests/src/com/android/customization/model/picker/quickaffordance/ui/viewmodel/KeyguardQuickAffordancePickerViewModelTest.kt
index 53ade86c..870d9f5a 100644
--- a/tests/robotests/src/com/android/customization/model/picker/quickaffordance/ui/viewmodel/KeyguardQuickAffordancePickerViewModelTest.kt
+++ b/tests/robotests/src/com/android/customization/model/picker/quickaffordance/ui/viewmodel/KeyguardQuickAffordancePickerViewModelTest.kt
@@ -38,7 +38,6 @@ import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
 import com.android.wallpaper.picker.customization.data.repository.WallpaperRepository
 import com.android.wallpaper.picker.customization.domain.interactor.WallpaperInteractor
 import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
-import com.android.wallpaper.testing.FakeSnapshotStore
 import com.android.wallpaper.testing.FakeWallpaperClient
 import com.android.wallpaper.testing.TestCurrentWallpaperInfoFactory
 import com.android.wallpaper.testing.TestInjector
@@ -48,7 +47,6 @@ import com.google.common.truth.Truth.assertThat
 import com.google.common.truth.Truth.assertWithMessage
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.ExperimentalCoroutinesApi
-import kotlinx.coroutines.runBlocking
 import kotlinx.coroutines.test.StandardTestDispatcher
 import kotlinx.coroutines.test.TestScope
 import kotlinx.coroutines.test.resetMain
@@ -89,16 +87,10 @@ class KeyguardQuickAffordancePickerViewModelTest {
                 repository =
                     KeyguardQuickAffordancePickerRepository(
                         client = client,
-                        scope = testScope.backgroundScope,
+                        mainScope = testScope.backgroundScope,
                     ),
                 client = client,
-                snapshotRestorer = {
-                    KeyguardQuickAffordanceSnapshotRestorer(
-                            interactor = quickAffordanceInteractor,
-                            client = client,
-                        )
-                        .apply { runBlocking { setUpSnapshotRestorer(FakeSnapshotStore()) } }
-                },
+                snapshotRestorer = KeyguardQuickAffordanceSnapshotRestorer(client),
             )
         wallpaperInteractor =
             WallpaperInteractor(
diff --git a/tests/robotests/src/com/android/customization/model/picker/settings/data/repository/ColorContrastSectionRepositoryTest.kt b/tests/robotests/src/com/android/customization/model/picker/settings/data/repository/ColorContrastSectionRepositoryTest.kt
index cde597a9..9d76b533 100644
--- a/tests/robotests/src/com/android/customization/model/picker/settings/data/repository/ColorContrastSectionRepositoryTest.kt
+++ b/tests/robotests/src/com/android/customization/model/picker/settings/data/repository/ColorContrastSectionRepositoryTest.kt
@@ -16,6 +16,7 @@
 
 package com.android.customization.model.picker.settings.data.repository
 
+import android.app.UiModeManager.ContrastUtils
 import androidx.test.filters.SmallTest
 import com.android.customization.picker.settings.data.repository.ColorContrastSectionRepository
 import com.android.wallpaper.testing.FakeUiModeManager
@@ -61,8 +62,10 @@ class ColorContrastSectionRepositoryTest {
     fun contrastFlowEmitsValues() =
         testScope.runTest {
             val nextContrastValues = listOf(0.5f, 0.7f, 0.8f)
+            val expectedContrastValues =
+                nextContrastValues.map { ContrastUtils.toContrastLevel(it) }
             // Set up a flow to collect all contrast values
-            val flowCollector = mutableListOf<Float>()
+            val flowCollector = mutableListOf<Int>()
             // Start collecting values from the flow, using an unconfined dispatcher to start
             // collecting from the flow right away (rather than explicitly calling `runCurrent`)
             // See https://developer.android.com/kotlin/flow/test#continuous-collection
@@ -74,6 +77,6 @@ class ColorContrastSectionRepositoryTest {
 
             // Ignore the first contrast value from constructing the repository
             val collectedValues = flowCollector.drop(1)
-            assertThat(collectedValues).containsExactlyElementsIn(nextContrastValues)
+            assertThat(collectedValues).containsExactlyElementsIn(expectedContrastValues)
         }
 }
diff --git a/tests/robotests/src/com/android/customization/model/picker/settings/domain/interactor/ColorContrastSectionInteractorTest.kt b/tests/robotests/src/com/android/customization/model/picker/settings/domain/interactor/ColorContrastSectionInteractorTest.kt
index afa6427c..d66cddf7 100644
--- a/tests/robotests/src/com/android/customization/model/picker/settings/domain/interactor/ColorContrastSectionInteractorTest.kt
+++ b/tests/robotests/src/com/android/customization/model/picker/settings/domain/interactor/ColorContrastSectionInteractorTest.kt
@@ -16,6 +16,7 @@
 
 package com.android.customization.model.picker.settings.domain.interactor
 
+import android.app.UiModeManager.ContrastUtils
 import androidx.test.filters.SmallTest
 import com.android.customization.picker.settings.domain.interactor.ColorContrastSectionInteractor
 import com.android.wallpaper.testing.FakeUiModeManager
@@ -47,11 +48,12 @@ class ColorContrastSectionInteractorTest {
 
     @Test
     fun contrastEmitCorrectValuesFromRepository() = runTest {
-        val expectedContrast = 1.5f
-        uiModeManager.setContrast(expectedContrast)
+        val contrastVal = 0.5f
+        val expectedContrastVal = ContrastUtils.toContrastLevel(contrastVal)
+        uiModeManager.setContrast(contrastVal)
 
         val result = interactor.contrast.first()
 
-        assertThat(result).isEqualTo(expectedContrast)
+        assertThat(result).isEqualTo(expectedContrastVal)
     }
 }
diff --git a/tests/robotests/src/com/android/customization/model/picker/settings/ui/viewmodel/ColorContrastSectionViewModelTest.kt b/tests/robotests/src/com/android/customization/model/picker/settings/ui/viewmodel/ColorContrastSectionViewModelTest.kt
index 0c420e03..22232823 100644
--- a/tests/robotests/src/com/android/customization/model/picker/settings/ui/viewmodel/ColorContrastSectionViewModelTest.kt
+++ b/tests/robotests/src/com/android/customization/model/picker/settings/ui/viewmodel/ColorContrastSectionViewModelTest.kt
@@ -16,6 +16,7 @@
 
 package com.android.customization.model.picker.settings.ui.viewmodel
 
+import android.app.UiModeManager.ContrastUtils
 import com.android.customization.picker.settings.ui.viewmodel.ColorContrastSectionDataViewModel
 import com.android.customization.picker.settings.ui.viewmodel.ColorContrastSectionViewModel
 import com.android.themepicker.R
@@ -60,11 +61,13 @@ class ColorContrastSectionViewModelTest {
 
     @Test
     fun summaryEmitsCorrectDataValueForStandard() = runTest {
-        uiModeManager.setContrast(ColorContrastSectionViewModel.ContrastValue.STANDARD.value)
+        uiModeManager.setContrast(
+            ContrastUtils.fromContrastLevel(ContrastUtils.CONTRAST_LEVEL_STANDARD)
+        )
         val expected =
             ColorContrastSectionDataViewModel(
                 Text.Resource(R.string.color_contrast_default_title),
-                Icon.Resource(res = R.drawable.ic_contrast_standard, contentDescription = null)
+                Icon.Resource(res = R.drawable.ic_contrast_standard, contentDescription = null),
             )
 
         val result = viewModel.summary.first()
@@ -74,11 +77,13 @@ class ColorContrastSectionViewModelTest {
 
     @Test
     fun summaryEmitsCorrectDataValueForMedium() = runTest {
-        uiModeManager.setContrast(ColorContrastSectionViewModel.ContrastValue.MEDIUM.value)
+        uiModeManager.setContrast(
+            ContrastUtils.fromContrastLevel(ContrastUtils.CONTRAST_LEVEL_MEDIUM)
+        )
         val expected =
             ColorContrastSectionDataViewModel(
                 Text.Resource(R.string.color_contrast_medium_title),
-                Icon.Resource(res = R.drawable.ic_contrast_medium, contentDescription = null)
+                Icon.Resource(res = R.drawable.ic_contrast_medium, contentDescription = null),
             )
 
         val result = viewModel.summary.first()
@@ -88,11 +93,13 @@ class ColorContrastSectionViewModelTest {
 
     @Test
     fun summaryEmitsCorrectDataValueForHigh() = runTest {
-        uiModeManager.setContrast(ColorContrastSectionViewModel.ContrastValue.HIGH.value)
+        uiModeManager.setContrast(
+            ContrastUtils.fromContrastLevel(ContrastUtils.CONTRAST_LEVEL_HIGH)
+        )
         val expected =
             ColorContrastSectionDataViewModel(
                 Text.Resource(R.string.color_contrast_high_title),
-                Icon.Resource(res = R.drawable.ic_contrast_high, contentDescription = null)
+                Icon.Resource(res = R.drawable.ic_contrast_high, contentDescription = null),
             )
 
         val result = viewModel.summary.first()
diff --git a/tests/robotests/src/com/android/customization/picker/clock/data/repository/FakeClockPickerRepository.kt b/tests/robotests/src/com/android/customization/picker/clock/data/repository/FakeClockPickerRepository.kt
index 4d8f32e5..f97feefd 100644
--- a/tests/robotests/src/com/android/customization/picker/clock/data/repository/FakeClockPickerRepository.kt
+++ b/tests/robotests/src/com/android/customization/picker/clock/data/repository/FakeClockPickerRepository.kt
@@ -16,6 +16,7 @@
 package com.android.customization.picker.clock.data.repository
 
 import android.graphics.Color
+import android.graphics.drawable.ColorDrawable
 import androidx.annotation.ColorInt
 import androidx.annotation.IntRange
 import com.android.customization.picker.clock.data.repository.FakeClockPickerRepository.Companion.fakeClocks
@@ -36,24 +37,26 @@ open class FakeClockPickerRepository(clocks: List<ClockMetadataModel> = fakeCloc
     private val colorTone = MutableStateFlow(ClockMetadataModel.DEFAULT_COLOR_TONE_PROGRESS)
     @ColorInt private val seedColor = MutableStateFlow<Int?>(null)
     override val selectedClock: Flow<ClockMetadataModel> =
-        combine(
+        combine(selectedClockId, selectedColorId, colorTone, seedColor) {
             selectedClockId,
-            selectedColorId,
+            selectedColor,
             colorTone,
-            seedColor,
-        ) { selectedClockId, selectedColor, colorTone, seedColor ->
+            seedColor ->
             val selectedClock = fakeClocks.find { clock -> clock.clockId == selectedClockId }
             checkNotNull(selectedClock)
             ClockMetadataModel(
                 clockId = selectedClock.clockId,
                 isSelected = true,
+                description = "description",
+                thumbnail = ColorDrawable(0),
+                isReactiveToTone = selectedClock.isReactiveToTone,
                 selectedColorId = selectedColor,
                 colorToneProgress = colorTone,
                 seedColor = seedColor,
             )
         }
 
-    private val _selectedClockSize = MutableStateFlow(ClockSize.SMALL)
+    private val _selectedClockSize = MutableStateFlow(ClockSize.DYNAMIC)
     override val selectedClockSize: Flow<ClockSize> = _selectedClockSize.asStateFlow()
 
     override suspend fun setSelectedClock(clockId: String) {
@@ -81,10 +84,46 @@ open class FakeClockPickerRepository(clocks: List<ClockMetadataModel> = fakeCloc
         const val CLOCK_ID_3 = "clock3"
         val fakeClocks =
             listOf(
-                ClockMetadataModel(CLOCK_ID_0, true, null, 50, null),
-                ClockMetadataModel(CLOCK_ID_1, false, null, 50, null),
-                ClockMetadataModel(CLOCK_ID_2, false, null, 50, null),
-                ClockMetadataModel(CLOCK_ID_3, false, null, 50, null),
+                ClockMetadataModel(
+                    CLOCK_ID_0,
+                    true,
+                    "description0",
+                    ColorDrawable(0),
+                    true,
+                    null,
+                    50,
+                    null,
+                ),
+                ClockMetadataModel(
+                    CLOCK_ID_1,
+                    false,
+                    "description1",
+                    ColorDrawable(0),
+                    true,
+                    null,
+                    50,
+                    null,
+                ),
+                ClockMetadataModel(
+                    CLOCK_ID_2,
+                    false,
+                    "description2",
+                    ColorDrawable(0),
+                    true,
+                    null,
+                    50,
+                    null,
+                ),
+                ClockMetadataModel(
+                    CLOCK_ID_3,
+                    false,
+                    "description3",
+                    ColorDrawable(0),
+                    false,
+                    null,
+                    50,
+                    null,
+                ),
             )
         const val CLOCK_COLOR_ID = "RED"
         const val CLOCK_COLOR_TONE_PROGRESS = 87
diff --git a/tests/robotests/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractorTest.kt b/tests/robotests/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractorTest.kt
index c8e39be8..478b7956 100644
--- a/tests/robotests/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractorTest.kt
+++ b/tests/robotests/src/com/android/customization/picker/clock/domain/interactor/ClockPickerInteractorTest.kt
@@ -30,14 +30,14 @@ class ClockPickerInteractorTest {
     fun setUp() {
         val testDispatcher = StandardTestDispatcher()
         Dispatchers.setMain(testDispatcher)
+        val repository = FakeClockPickerRepository()
         underTest =
             ClockPickerInteractor(
-                repository = FakeClockPickerRepository(),
-                snapshotRestorer = {
-                    ClockPickerSnapshotRestorer(interactor = underTest).apply {
+                repository = repository,
+                snapshotRestorer =
+                    ClockPickerSnapshotRestorer(repository = repository).apply {
                         runBlocking { setUpSnapshotRestorer(store = FakeSnapshotStore()) }
-                    }
-                },
+                    },
             )
     }
 
diff --git a/tests/robotests/src/com/android/customization/picker/clock/ui/FakeClockViewFactory.kt b/tests/robotests/src/com/android/customization/picker/clock/ui/FakeClockViewFactory.kt
index 41192e77..32490241 100644
--- a/tests/robotests/src/com/android/customization/picker/clock/ui/FakeClockViewFactory.kt
+++ b/tests/robotests/src/com/android/customization/picker/clock/ui/FakeClockViewFactory.kt
@@ -4,24 +4,22 @@ import android.content.res.Resources
 import android.view.View
 import androidx.lifecycle.LifecycleOwner
 import com.android.customization.picker.clock.data.repository.FakeClockPickerRepository
-import com.android.customization.picker.clock.ui.FakeClockViewFactory.Companion.fakeClocks
 import com.android.customization.picker.clock.ui.view.ClockViewFactory
 import com.android.systemui.plugins.clocks.ClockConfig
 import com.android.systemui.plugins.clocks.ClockController
 import com.android.systemui.plugins.clocks.ClockEvents
 import com.android.systemui.plugins.clocks.ClockFaceController
 import java.io.PrintWriter
+import javax.inject.Inject
 
 /**
  * This is a fake [ClockViewFactory]. Only implement the function if it's actually called in a test.
  */
-class FakeClockViewFactory(
-    val clockControllers: MutableMap<String, ClockController> = fakeClocks.toMutableMap(),
-) : ClockViewFactory {
+class FakeClockViewFactory @Inject constructor() : ClockViewFactory {
 
-    class FakeClockController(
-        override var config: ClockConfig,
-    ) : ClockController {
+    private val clockControllers: MutableMap<String, ClockController> = fakeClocks.toMutableMap()
+
+    class FakeClockController(override var config: ClockConfig) : ClockController {
         override val smallClock: ClockFaceController
             get() = TODO("Not yet implemented")
 
@@ -37,7 +35,7 @@ class FakeClockViewFactory(
         override fun dump(pw: PrintWriter) = TODO("Not yet implemented")
     }
 
-    override fun getController(clockId: String): ClockController = clockControllers.get(clockId)!!
+    override fun getController(clockId: String): ClockController = clockControllers[clockId]!!
 
     override fun setReactiveTouchInteractionEnabled(clockId: String, enable: Boolean) {
         TODO("Not yet implemented")
@@ -81,17 +79,15 @@ class FakeClockViewFactory(
 
     companion object {
         val fakeClocks =
-            FakeClockPickerRepository.fakeClocks
-                .map { clock ->
-                    clock.clockId to
-                        FakeClockController(
-                            ClockConfig(
-                                id = clock.clockId,
-                                name = "Name: ${clock.clockId}",
-                                description = "Desc: ${clock.clockId}"
-                            )
+            FakeClockPickerRepository.fakeClocks.associate { clock ->
+                clock.clockId to
+                    FakeClockController(
+                        ClockConfig(
+                            id = clock.clockId,
+                            name = "Name: ${clock.clockId}",
+                            description = "Desc: ${clock.clockId}",
                         )
-                }
-                .toMap()
+                    )
+            }
     }
 }
diff --git a/tests/robotests/src/com/android/customization/picker/clock/ui/viewmodel/ClockCarouselViewModelTest.kt b/tests/robotests/src/com/android/customization/picker/clock/ui/viewmodel/ClockCarouselViewModelTest.kt
index 46afe35d..be852ac9 100644
--- a/tests/robotests/src/com/android/customization/picker/clock/ui/viewmodel/ClockCarouselViewModelTest.kt
+++ b/tests/robotests/src/com/android/customization/picker/clock/ui/viewmodel/ClockCarouselViewModelTest.kt
@@ -15,6 +15,7 @@
  */
 package com.android.customization.picker.clock.ui.viewmodel
 
+import android.graphics.drawable.ColorDrawable
 import androidx.test.filters.SmallTest
 import androidx.test.platform.app.InstrumentationRegistry
 import com.android.customization.module.logging.TestThemesUserEventLogger
@@ -54,6 +55,9 @@ class ClockCarouselViewModelTest {
                 ClockMetadataModel(
                     clockId = FakeClockPickerRepository.CLOCK_ID_0,
                     isSelected = true,
+                    description = "description",
+                    thumbnail = ColorDrawable(0),
+                    isReactiveToTone = true,
                     selectedColorId = null,
                     colorToneProgress = ClockMetadataModel.DEFAULT_COLOR_TONE_PROGRESS,
                     seedColor = null,
@@ -100,11 +104,10 @@ class ClockCarouselViewModelTest {
     private fun getClockPickerInteractor(repository: ClockPickerRepository): ClockPickerInteractor {
         return ClockPickerInteractor(
                 repository = repository,
-                snapshotRestorer = {
-                    ClockPickerSnapshotRestorer(interactor = interactor).apply {
+                snapshotRestorer =
+                    ClockPickerSnapshotRestorer(repository = repository).apply {
                         runBlocking { setUpSnapshotRestorer(store = FakeSnapshotStore()) }
-                    }
-                }
+                    },
             )
             .also { interactor = it }
     }
diff --git a/tests/robotests/src/com/android/customization/picker/clock/ui/viewmodel/ClockSettingsViewModelTest.kt b/tests/robotests/src/com/android/customization/picker/clock/ui/viewmodel/ClockSettingsViewModelTest.kt
index d3ae9cba..dd68589b 100644
--- a/tests/robotests/src/com/android/customization/picker/clock/ui/viewmodel/ClockSettingsViewModelTest.kt
+++ b/tests/robotests/src/com/android/customization/picker/clock/ui/viewmodel/ClockSettingsViewModelTest.kt
@@ -61,23 +61,23 @@ class ClockSettingsViewModelTest {
         Dispatchers.setMain(testDispatcher)
         context = InstrumentationRegistry.getInstrumentation().targetContext
         testScope = TestScope(testDispatcher)
+        val repository = FakeClockPickerRepository()
         clockPickerInteractor =
             ClockPickerInteractor(
-                repository = FakeClockPickerRepository(),
-                snapshotRestorer = {
-                    ClockPickerSnapshotRestorer(interactor = clockPickerInteractor).apply {
+                repository = repository,
+                snapshotRestorer =
+                    ClockPickerSnapshotRestorer(repository = repository).apply {
                         runBlocking { setUpSnapshotRestorer(store = FakeSnapshotStore()) }
-                    }
-                },
+                    },
             )
+        val colorPickerRepository = FakeColorPickerRepository(context = context)
         colorPickerInteractor =
             ColorPickerInteractor(
-                repository = FakeColorPickerRepository(context = context),
-                snapshotRestorer = {
-                    ColorPickerSnapshotRestorer(interactor = colorPickerInteractor).apply {
+                repository = colorPickerRepository,
+                snapshotRestorer =
+                    ColorPickerSnapshotRestorer(repository = colorPickerRepository).apply {
                         runBlocking { setUpSnapshotRestorer(store = FakeSnapshotStore()) }
-                    }
-                },
+                    },
             )
         underTest =
             ClockSettingsViewModel.Factory(
diff --git a/tests/robotests/src/com/android/customization/picker/grid/data/repository/GridRepository2Test.kt b/tests/robotests/src/com/android/customization/picker/grid/data/repository/GridRepository2Test.kt
new file mode 100644
index 00000000..404f08b8
--- /dev/null
+++ b/tests/robotests/src/com/android/customization/picker/grid/data/repository/GridRepository2Test.kt
@@ -0,0 +1,123 @@
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
+package com.android.customization.picker.grid.data.repository
+
+import androidx.test.filters.SmallTest
+import com.android.customization.model.grid.FakeGridOptionsManager
+import com.android.wallpaper.picker.di.modules.BackgroundDispatcher
+import com.android.wallpaper.testing.collectLastValue
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.resetMain
+import kotlinx.coroutines.test.runTest
+import org.junit.After
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+
+@HiltAndroidTest
+@OptIn(ExperimentalCoroutinesApi::class)
+@SmallTest
+@RunWith(RobolectricTestRunner::class)
+class GridRepository2Test {
+
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+    @Inject lateinit var gridOptionsManager: FakeGridOptionsManager
+    @Inject lateinit var testScope: TestScope
+    @BackgroundDispatcher @Inject lateinit var bgScope: CoroutineScope
+    @BackgroundDispatcher @Inject lateinit var bgDispatcher: CoroutineDispatcher
+
+    private lateinit var underTest: GridRepository2
+
+    @Before
+    fun setUp() {
+        hiltRule.inject()
+        underTest =
+            GridRepository2(
+                manager = gridOptionsManager,
+                bgScope = bgScope,
+                bgDispatcher = bgDispatcher,
+            )
+    }
+
+    @After
+    fun tearDown() {
+        Dispatchers.resetMain()
+    }
+
+    @Test
+    fun isGridOptionAvailable_false() =
+        testScope.runTest {
+            gridOptionsManager.isGridOptionAvailable = false
+            assertThat(underTest.isGridOptionAvailable()).isFalse()
+        }
+
+    @Test
+    fun isGridOptionAvailable_true() =
+        testScope.runTest {
+            gridOptionsManager.isGridOptionAvailable = true
+            assertThat(underTest.isGridOptionAvailable()).isTrue()
+        }
+
+    @Test
+    fun gridOptions_default() =
+        testScope.runTest {
+            val gridOptions = collectLastValue(underTest.gridOptions)
+            assertThat(gridOptions()).isEqualTo(FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST)
+        }
+
+    @Test
+    fun selectedGridOption_default() =
+        testScope.runTest {
+            val selectedGridOption = collectLastValue(underTest.selectedGridOption)
+            assertThat(selectedGridOption())
+                .isEqualTo(FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST[0])
+        }
+
+    @Test
+    fun gridOptions_shouldUpdateAfterApplyGridOption() =
+        testScope.runTest {
+            val gridOptions = collectLastValue(underTest.gridOptions)
+            underTest.applySelectedOption("practical")
+            assertThat(gridOptions())
+                .isEqualTo(
+                    FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST.map {
+                        it.copy(isCurrent = it.key == "practical")
+                    }
+                )
+        }
+
+    @Test
+    fun selectedGridOption_shouldUpdateAfterApplyGridOption() =
+        testScope.runTest {
+            val selectedGridOption = collectLastValue(underTest.selectedGridOption)
+            underTest.applySelectedOption("practical")
+            assertThat(selectedGridOption())
+                .isEqualTo(
+                    FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST[1].copy(isCurrent = true)
+                )
+        }
+}
diff --git a/tests/robotests/src/com/android/customization/picker/grid/domain/interactor/GridInteractor2Test.kt b/tests/robotests/src/com/android/customization/picker/grid/domain/interactor/GridInteractor2Test.kt
new file mode 100644
index 00000000..bfbe282f
--- /dev/null
+++ b/tests/robotests/src/com/android/customization/picker/grid/domain/interactor/GridInteractor2Test.kt
@@ -0,0 +1,115 @@
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
+package com.android.customization.picker.grid.domain.interactor
+
+import androidx.test.filters.SmallTest
+import com.android.customization.model.grid.FakeGridOptionsManager
+import com.android.customization.picker.grid.data.repository.GridRepository2
+import com.android.wallpaper.testing.collectLastValue
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.resetMain
+import kotlinx.coroutines.test.runTest
+import org.junit.After
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+
+@HiltAndroidTest
+@OptIn(ExperimentalCoroutinesApi::class)
+@SmallTest
+@RunWith(RobolectricTestRunner::class)
+class GridInteractor2Test {
+
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+    @Inject lateinit var gridOptionsManager: FakeGridOptionsManager
+    @Inject lateinit var repository: GridRepository2
+    @Inject lateinit var testScope: TestScope
+
+    private lateinit var underTest: GridInteractor2
+
+    @Before
+    fun setUp() {
+        hiltRule.inject()
+        underTest = GridInteractor2(repository)
+    }
+
+    @After
+    fun tearDown() {
+        Dispatchers.resetMain()
+    }
+
+    @Test
+    fun isGridOptionAvailable_false() =
+        testScope.runTest {
+            gridOptionsManager.isGridOptionAvailable = false
+            assertThat(underTest.isGridOptionAvailable()).isFalse()
+        }
+
+    @Test
+    fun isGridOptionAvailable_true() =
+        testScope.runTest {
+            gridOptionsManager.isGridOptionAvailable = true
+            assertThat(underTest.isGridOptionAvailable()).isTrue()
+        }
+
+    @Test
+    fun gridOptions_default() =
+        testScope.runTest {
+            val gridOptions = collectLastValue(underTest.gridOptions)
+            assertThat(gridOptions()).isEqualTo(FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST)
+        }
+
+    @Test
+    fun selectedGridOption_default() =
+        testScope.runTest {
+            val selectedGridOption = collectLastValue(underTest.selectedGridOption)
+            assertThat(selectedGridOption())
+                .isEqualTo(FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST[0])
+        }
+
+    @Test
+    fun gridOptions_shouldUpdateAfterApplyGridOption() =
+        testScope.runTest {
+            val gridOptions = collectLastValue(underTest.gridOptions)
+            underTest.applySelectedOption("practical")
+            assertThat(gridOptions())
+                .isEqualTo(
+                    FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST.map {
+                        it.copy(isCurrent = it.key == "practical")
+                    }
+                )
+        }
+
+    @Test
+    fun selectedGridOption_shouldUpdateAfterApplyGridOption() =
+        testScope.runTest {
+            val selectedGridOption = collectLastValue(underTest.selectedGridOption)
+            underTest.applySelectedOption("practical")
+            assertThat(selectedGridOption())
+                .isEqualTo(
+                    FakeGridOptionsManager.DEFAULT_GRID_OPTION_LIST[1].copy(isCurrent = true)
+                )
+        }
+}
diff --git a/tests/robotests/src/com/android/customization/picker/notifications/ui/viewmodel/NotificationSectionViewModelTest.kt b/tests/robotests/src/com/android/customization/picker/notifications/ui/viewmodel/NotificationSectionViewModelTest.kt
index e9f7ffd0..cab4b12b 100644
--- a/tests/robotests/src/com/android/customization/picker/notifications/ui/viewmodel/NotificationSectionViewModelTest.kt
+++ b/tests/robotests/src/com/android/customization/picker/notifications/ui/viewmodel/NotificationSectionViewModelTest.kt
@@ -23,6 +23,7 @@ import com.android.customization.module.logging.ThemesUserEventLogger
 import com.android.systemui.shared.notifications.data.repository.NotificationSettingsRepository
 import com.android.systemui.shared.notifications.domain.interactor.NotificationSettingsInteractor
 import com.android.systemui.shared.settings.data.repository.FakeSecureSettingsRepository
+import com.android.systemui.shared.settings.data.repository.FakeSystemSettingsRepository
 import com.android.wallpaper.testing.collectLastValue
 import com.google.common.truth.Truth.assertThat
 import kotlinx.coroutines.Dispatchers
@@ -59,9 +60,10 @@ class NotificationSectionViewModelTest {
             NotificationSettingsInteractor(
                 repository =
                     NotificationSettingsRepository(
-                        scope = testScope.backgroundScope,
+                        backgroundScope = testScope.backgroundScope,
                         backgroundDispatcher = testDispatcher,
                         secureSettingsRepository = FakeSecureSettingsRepository(),
+                        systemSettingsRepository = FakeSystemSettingsRepository(),
                     ),
             )
 
diff --git a/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ClockPickerViewModelTest.kt b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ClockPickerViewModelTest.kt
new file mode 100644
index 00000000..72f3f6bf
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ClockPickerViewModelTest.kt
@@ -0,0 +1,337 @@
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
+import androidx.test.filters.SmallTest
+import com.android.customization.module.logging.TestThemesUserEventLogger
+import com.android.customization.picker.clock.data.repository.FakeClockPickerRepository
+import com.android.customization.picker.clock.domain.interactor.ClockPickerInteractor
+import com.android.customization.picker.clock.domain.interactor.ClockPickerSnapshotRestorer
+import com.android.customization.picker.clock.shared.ClockSize
+import com.android.customization.picker.clock.shared.model.ClockMetadataModel
+import com.android.customization.picker.clock.ui.viewmodel.ClockColorViewModel
+import com.android.customization.picker.clock.ui.viewmodel.ClockSettingsViewModel
+import com.android.customization.picker.color.data.repository.FakeColorPickerRepository
+import com.android.customization.picker.color.domain.interactor.ColorPickerInteractor
+import com.android.customization.picker.color.domain.interactor.ColorPickerSnapshotRestorer
+import com.android.wallpaper.customization.ui.viewmodel.ClockPickerViewModel.Tab
+import com.android.wallpaper.testing.FakeSnapshotStore
+import com.android.wallpaper.testing.collectLastValue
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.runBlocking
+import kotlinx.coroutines.test.TestDispatcher
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.advanceTimeBy
+import kotlinx.coroutines.test.resetMain
+import kotlinx.coroutines.test.runTest
+import kotlinx.coroutines.test.setMain
+import org.junit.After
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+
+@HiltAndroidTest
+@OptIn(ExperimentalCoroutinesApi::class)
+@SmallTest
+@RunWith(RobolectricTestRunner::class)
+class ClockPickerViewModelTest {
+
+    private val logger = TestThemesUserEventLogger()
+
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+    @Inject @ApplicationContext lateinit var context: Context
+    @Inject lateinit var testDispatcher: TestDispatcher
+    @Inject lateinit var testScope: TestScope
+
+    private lateinit var colorMap: Map<String, ClockColorViewModel>
+    private lateinit var underTest: ClockPickerViewModel
+
+    @Before
+    fun setUp() {
+        hiltRule.inject()
+        Dispatchers.setMain(testDispatcher)
+        val repository = FakeClockPickerRepository()
+        val clockPickerInteractor =
+            ClockPickerInteractor(
+                repository = repository,
+                snapshotRestorer =
+                    ClockPickerSnapshotRestorer(repository = repository).apply {
+                        runBlocking { setUpSnapshotRestorer(store = FakeSnapshotStore()) }
+                    },
+            )
+        val colorPickerRepository = FakeColorPickerRepository(context = context)
+        val colorPickerInteractor =
+            ColorPickerInteractor(
+                repository = colorPickerRepository,
+                snapshotRestorer =
+                    ColorPickerSnapshotRestorer(repository = colorPickerRepository).apply {
+                        runBlocking { setUpSnapshotRestorer(store = FakeSnapshotStore()) }
+                    },
+            )
+        colorMap = ClockColorViewModel.getPresetColorMap(context.resources)
+        underTest =
+            ClockPickerViewModel(
+                context = context,
+                resources = context.resources,
+                clockPickerInteractor = clockPickerInteractor,
+                colorPickerInteractor = colorPickerInteractor,
+                logger = logger,
+                backgroundDispatcher = testDispatcher,
+                viewModelScope = testScope,
+            )
+
+        testScope.launch {
+            clockPickerInteractor.setSelectedClock(FakeClockPickerRepository.CLOCK_ID_0)
+        }
+    }
+
+    @After
+    fun tearDown() {
+        Dispatchers.resetMain()
+    }
+
+    @Test
+    fun selectedTab_whenClickOnTabs() = runTest {
+        val tabs = collectLastValue(underTest.tabs)
+        val selectedTab = collectLastValue(underTest.selectedTab)
+
+        assertThat(selectedTab()).isEqualTo(Tab.STYLE)
+
+        tabs()?.get(1)?.onClick?.invoke()
+
+        assertThat(selectedTab()).isEqualTo(Tab.COLOR)
+
+        tabs()?.get(2)?.onClick?.invoke()
+
+        assertThat(selectedTab()).isEqualTo(Tab.SIZE)
+    }
+
+    @Test
+    fun tabs_whenClickOnTabs() = runTest {
+        val tabs = collectLastValue(underTest.tabs)
+
+        assertThat(tabs()?.get(0)?.isSelected).isTrue()
+
+        tabs()?.get(1)?.onClick?.invoke()
+
+        assertThat(tabs()?.get(1)?.isSelected).isTrue()
+
+        tabs()?.get(2)?.onClick?.invoke()
+
+        assertThat(tabs()?.get(2)?.isSelected).isTrue()
+    }
+
+    @Test
+    fun previewingClock_whenClickOnStyleOptions() = runTest {
+        val previewingClock = collectLastValue(underTest.previewingClock)
+        val clockStyleOptions = collectLastValue(underTest.clockStyleOptions)
+        // Advance CLOCKS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from clockStyleOptions
+        advanceTimeBy(ClockPickerViewModel.CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
+
+        assertThat(previewingClock()?.clockId).isEqualTo(FakeClockPickerRepository.CLOCK_ID_0)
+
+        val option1OnClicked = collectLastValue(clockStyleOptions()!![1].onClicked)
+        option1OnClicked()?.invoke()
+        // Advance CLOCKS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from clockColorOptions
+        advanceTimeBy(ClockPickerViewModel.CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
+
+        assertThat(previewingClock()?.clockId).isEqualTo(FakeClockPickerRepository.CLOCK_ID_1)
+    }
+
+    @Test
+    fun clockStyleOptions_whenClickOnStyleOptions() = runTest {
+        val clockStyleOptions = collectLastValue(underTest.clockStyleOptions)
+        // Advance CLOCKS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from clockStyleOptions
+        advanceTimeBy(ClockPickerViewModel.CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
+        val option0IsSelected = collectLastValue(clockStyleOptions()!![0].isSelected)
+        val option0OnClicked = collectLastValue(clockStyleOptions()!![0].onClicked)
+        val option1IsSelected = collectLastValue(clockStyleOptions()!![1].isSelected)
+        val option1OnClicked = collectLastValue(clockStyleOptions()!![1].onClicked)
+
+        assertThat(option0IsSelected()).isTrue()
+        assertThat(option0OnClicked()).isNull()
+
+        option1OnClicked()?.invoke()
+        // Advance CLOCKS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from clockColorOptions
+        advanceTimeBy(ClockPickerViewModel.CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
+
+        assertThat(option0IsSelected()).isFalse()
+        assertThat(option1IsSelected()).isTrue()
+        assertThat(option1OnClicked()).isNull()
+    }
+
+    @Test
+    fun previewingClockSize_whenClickOnSizeOptions() = runTest {
+        val previewingClockSize = collectLastValue(underTest.previewingClockSize)
+        val sizeOptions = collectLastValue(underTest.sizeOptions)
+
+        assertThat(previewingClockSize()).isEqualTo(ClockSize.DYNAMIC)
+
+        val option1OnClicked = collectLastValue(sizeOptions()!![1].onClicked)
+        option1OnClicked()?.invoke()
+
+        assertThat(previewingClockSize()).isEqualTo(ClockSize.SMALL)
+    }
+
+    @Test
+    fun sizeOptions_whenClickOnSizeOptions() = runTest {
+        val sizeOptions = collectLastValue(underTest.sizeOptions)
+        val option0IsSelected = collectLastValue(sizeOptions()!![0].isSelected)
+        val option0OnClicked = collectLastValue(sizeOptions()!![0].onClicked)
+        val option1IsSelected = collectLastValue(sizeOptions()!![1].isSelected)
+        val option1OnClicked = collectLastValue(sizeOptions()!![1].onClicked)
+
+        assertThat(sizeOptions()!![0].size).isEqualTo(ClockSize.DYNAMIC)
+        assertThat(sizeOptions()!![1].size).isEqualTo(ClockSize.SMALL)
+        assertThat(option0IsSelected()).isTrue()
+        assertThat(option0OnClicked()).isNull()
+
+        option1OnClicked()?.invoke()
+
+        assertThat(option0IsSelected()).isFalse()
+        assertThat(option1IsSelected()).isTrue()
+        assertThat(option1OnClicked()).isNull()
+    }
+
+    @Test
+    fun sliderProgress_whenOnSliderProgressChanged() = runTest {
+        val sliderProgress = collectLastValue(underTest.previewingSliderProgress)
+
+        assertThat(sliderProgress()).isEqualTo(ClockMetadataModel.DEFAULT_COLOR_TONE_PROGRESS)
+
+        underTest.onSliderProgressChanged(87)
+
+        assertThat(sliderProgress()).isEqualTo(87)
+    }
+
+    @Test
+    fun isSliderEnabledShouldBeTrue_whenTheClockIsReactiveToToneAndSolidColor() = runTest {
+        val clockStyleOptions = collectLastValue(underTest.clockStyleOptions)
+        // Advance CLOCKS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from clockStyleOptions
+        advanceTimeBy(ClockPickerViewModel.CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
+        val styleOption0OnClicked = collectLastValue(clockStyleOptions()!![0].onClicked)
+        val clockColorOptions = collectLastValue(underTest.clockColorOptions)
+        // Advance COLOR_OPTIONS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from
+        // clockColorOptions
+        advanceTimeBy(ClockPickerViewModel.COLOR_OPTIONS_EVENT_UPDATE_DELAY_MILLIS)
+        val colorOption1OnClicked = collectLastValue(clockColorOptions()!![1].onClicked)
+        val isSliderEnabled = collectLastValue(underTest.isSliderEnabled)
+
+        styleOption0OnClicked()?.invoke()
+        colorOption1OnClicked()?.invoke()
+        // Advance CLOCKS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from clockStyleOptions
+        advanceTimeBy(ClockPickerViewModel.CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
+
+        assertThat(isSliderEnabled()).isTrue()
+    }
+
+    @Test
+    fun isSliderEnabledShouldBeFalse_whenTheClockIsReactiveToToneAndDefaultColor() = runTest {
+        val clockStyleOptions = collectLastValue(underTest.clockStyleOptions)
+        // Advance CLOCKS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from clockStyleOptions
+        advanceTimeBy(ClockPickerViewModel.CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
+        val styleOption0OnClicked = collectLastValue(clockStyleOptions()!![0].onClicked)
+        val clockColorOptions = collectLastValue(underTest.clockColorOptions)
+        // Advance COLOR_OPTIONS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from
+        // clockColorOptions
+        advanceTimeBy(ClockPickerViewModel.COLOR_OPTIONS_EVENT_UPDATE_DELAY_MILLIS)
+        val colorOption0OnClicked = collectLastValue(clockColorOptions()!![0].onClicked)
+        val isSliderEnabled = collectLastValue(underTest.isSliderEnabled)
+
+        styleOption0OnClicked()?.invoke()
+        colorOption0OnClicked()?.invoke()
+        // Advance CLOCKS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from clockStyleOptions
+        advanceTimeBy(ClockPickerViewModel.CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
+
+        assertThat(isSliderEnabled()).isFalse()
+    }
+
+    @Test
+    fun isSliderEnabledShouldBeFalse_whenTheClockIsNotReactiveToTone() = runTest {
+        val clockStyleOptions = collectLastValue(underTest.clockStyleOptions)
+        // Advance CLOCKS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from clockStyleOptions
+        advanceTimeBy(ClockPickerViewModel.CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
+        val styleOption3OnClicked = collectLastValue(clockStyleOptions()!![3].onClicked)
+        val isSliderEnabled = collectLastValue(underTest.isSliderEnabled)
+
+        styleOption3OnClicked()?.invoke()
+        // Advance CLOCKS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from clockStyleOptions
+        advanceTimeBy(ClockPickerViewModel.CLOCKS_EVENT_UPDATE_DELAY_MILLIS)
+
+        assertThat(isSliderEnabled()).isFalse()
+    }
+
+    @Test
+    fun previewingSeedColor_whenChangeColorOptionAndToneProgress() = runTest {
+        val previewingSeedColor = collectLastValue(underTest.previewingSeedColor)
+        val clockColorOptions = collectLastValue(underTest.clockColorOptions)
+        // Advance COLOR_OPTIONS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from
+        // clockColorOptions
+        advanceTimeBy(ClockPickerViewModel.COLOR_OPTIONS_EVENT_UPDATE_DELAY_MILLIS)
+        val option1OnClicked = collectLastValue(clockColorOptions()!![1].onClicked)
+
+        option1OnClicked()?.invoke()
+        // Advance COLOR_OPTIONS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from
+        // clockColorOptions
+        advanceTimeBy(ClockPickerViewModel.COLOR_OPTIONS_EVENT_UPDATE_DELAY_MILLIS)
+        val targetProgress = 55
+        underTest.onSliderProgressChanged(targetProgress)
+
+        val expectedSelectedColorModel = colorMap.values.first() // RED
+        assertThat(previewingSeedColor())
+            .isEqualTo(
+                ClockSettingsViewModel.blendColorWithTone(
+                    expectedSelectedColorModel.color,
+                    expectedSelectedColorModel.getColorTone(targetProgress),
+                )
+            )
+    }
+
+    @Test
+    fun clockColorOptions_whenClickOnColorOptions() = runTest {
+        val clockColorOptions = collectLastValue(underTest.clockColorOptions)
+        // Advance COLOR_OPTIONS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from
+        // clockColorOptions
+        advanceTimeBy(ClockPickerViewModel.COLOR_OPTIONS_EVENT_UPDATE_DELAY_MILLIS)
+        val option0IsSelected = collectLastValue(clockColorOptions()!![0].isSelected)
+        val option0OnClicked = collectLastValue(clockColorOptions()!![0].onClicked)
+        val option1IsSelected = collectLastValue(clockColorOptions()!![1].isSelected)
+        val option1OnClicked = collectLastValue(clockColorOptions()!![1].onClicked)
+
+        assertThat(option0IsSelected()).isTrue()
+        assertThat(option0OnClicked()).isNull()
+
+        option1OnClicked()?.invoke()
+        // Advance COLOR_OPTIONS_EVENT_UPDATE_DELAY_MILLIS since there is a delay from
+        // clockColorOptions
+        advanceTimeBy(ClockPickerViewModel.COLOR_OPTIONS_EVENT_UPDATE_DELAY_MILLIS)
+
+        assertThat(option0IsSelected()).isFalse()
+        assertThat(option1IsSelected()).isTrue()
+        assertThat(option1OnClicked()).isNull()
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ColorPickerViewModel2Test.kt b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ColorPickerViewModel2Test.kt
new file mode 100644
index 00000000..d13d4b13
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ColorPickerViewModel2Test.kt
@@ -0,0 +1,307 @@
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
+import android.graphics.Color
+import android.stats.style.StyleEnums
+import androidx.test.filters.SmallTest
+import androidx.test.platform.app.InstrumentationRegistry
+import com.android.customization.model.color.ColorOptionsProvider
+import com.android.customization.module.logging.TestThemesUserEventLogger
+import com.android.customization.picker.color.data.repository.FakeColorPickerRepository
+import com.android.customization.picker.color.domain.interactor.ColorPickerInteractor
+import com.android.customization.picker.color.domain.interactor.ColorPickerSnapshotRestorer
+import com.android.customization.picker.color.shared.model.ColorType
+import com.android.customization.picker.color.ui.viewmodel.ColorOptionIconViewModel
+import com.android.systemui.monet.Style
+import com.android.wallpaper.picker.customization.ui.viewmodel.FloatingToolbarTabViewModel
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
+import com.android.wallpaper.testing.FakeSnapshotStore
+import com.android.wallpaper.testing.collectLastValue
+import com.google.common.truth.Truth.assertThat
+import com.google.common.truth.Truth.assertWithMessage
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.runBlocking
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.UnconfinedTestDispatcher
+import kotlinx.coroutines.test.resetMain
+import kotlinx.coroutines.test.runTest
+import kotlinx.coroutines.test.setMain
+import org.junit.After
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+
+@OptIn(ExperimentalCoroutinesApi::class)
+@SmallTest
+@RunWith(RobolectricTestRunner::class)
+class ColorPickerViewModel2Test {
+    private val logger = TestThemesUserEventLogger()
+    private lateinit var underTest: ColorPickerViewModel2
+    private lateinit var repository: FakeColorPickerRepository
+    private lateinit var interactor: ColorPickerInteractor
+    private lateinit var store: FakeSnapshotStore
+
+    private lateinit var context: Context
+    private lateinit var testScope: TestScope
+
+    @Before
+    fun setUp() {
+        context = InstrumentationRegistry.getInstrumentation().targetContext
+        val testDispatcher = UnconfinedTestDispatcher()
+        Dispatchers.setMain(testDispatcher)
+        testScope = TestScope(testDispatcher)
+        repository = FakeColorPickerRepository(context = context)
+        store = FakeSnapshotStore()
+
+        interactor =
+            ColorPickerInteractor(
+                repository = repository,
+                snapshotRestorer =
+                    ColorPickerSnapshotRestorer(repository = repository).apply {
+                        runBlocking { setUpSnapshotRestorer(store = store) }
+                    },
+            )
+
+        underTest =
+            ColorPickerViewModel2(
+                context = context,
+                interactor = interactor,
+                logger = logger,
+                viewModelScope = testScope.backgroundScope,
+            )
+
+        repository.setOptions(4, 4, ColorType.WALLPAPER_COLOR, 0)
+    }
+
+    @After
+    fun tearDown() {
+        Dispatchers.resetMain()
+    }
+
+    @Test
+    fun `Log selected wallpaper color`() =
+        testScope.runTest {
+            repository.setOptions(
+                listOf(
+                    repository.buildWallpaperOption(
+                        ColorOptionsProvider.COLOR_SOURCE_LOCK,
+                        Style.EXPRESSIVE,
+                        "121212"
+                    )
+                ),
+                listOf(repository.buildPresetOption(Style.FRUIT_SALAD, "#ABCDEF")),
+                ColorType.PRESET_COLOR,
+                0
+            )
+
+            val colorTypes = collectLastValue(underTest.colorTypeTabs)
+            val colorOptions = collectLastValue(underTest.colorOptions)
+
+            // Select "Wallpaper colors" tab
+            colorTypes()?.get(0)?.onClick?.invoke()
+            // Select a color option
+            selectColorOption(colorOptions, 0)
+
+            assertThat(logger.themeColorSource)
+                .isEqualTo(StyleEnums.COLOR_SOURCE_LOCK_SCREEN_WALLPAPER)
+            assertThat(logger.themeColorStyle).isEqualTo(Style.EXPRESSIVE.toString().hashCode())
+            assertThat(logger.themeSeedColor).isEqualTo(Color.parseColor("#121212"))
+        }
+
+    @Test
+    fun `Log selected preset color`() =
+        testScope.runTest {
+            repository.setOptions(
+                listOf(
+                    repository.buildWallpaperOption(
+                        ColorOptionsProvider.COLOR_SOURCE_LOCK,
+                        Style.EXPRESSIVE,
+                        "121212"
+                    )
+                ),
+                listOf(repository.buildPresetOption(Style.FRUIT_SALAD, "#ABCDEF")),
+                ColorType.WALLPAPER_COLOR,
+                0
+            )
+
+            val colorTypes = collectLastValue(underTest.colorTypeTabs)
+            val colorOptions = collectLastValue(underTest.colorOptions)
+
+            // Select "Wallpaper colors" tab
+            colorTypes()?.get(1)?.onClick?.invoke()
+            // Select a color option
+            selectColorOption(colorOptions, 0)
+
+            assertThat(logger.themeColorSource).isEqualTo(StyleEnums.COLOR_SOURCE_PRESET_COLOR)
+            assertThat(logger.themeColorStyle).isEqualTo(Style.FRUIT_SALAD.toString().hashCode())
+            assertThat(logger.themeSeedColor).isEqualTo(Color.parseColor("#ABCDEF"))
+        }
+
+    @Test
+    fun `Select a preset color`() =
+        testScope.runTest {
+            val colorTypes = collectLastValue(underTest.colorTypeTabs)
+            val colorOptions = collectLastValue(underTest.colorOptions)
+
+            // Initially, the wallpaper color tab should be selected
+            assertPickerUiState(
+                colorTypes = colorTypes(),
+                colorOptions = colorOptions(),
+                selectedColorTypeText = "Wallpaper colors",
+                selectedColorOptionIndex = 0
+            )
+
+            // Select "Basic colors" tab
+            colorTypes()?.get(1)?.onClick?.invoke()
+            assertPickerUiState(
+                colorTypes = colorTypes(),
+                colorOptions = colorOptions(),
+                selectedColorTypeText = "Basic colors",
+                selectedColorOptionIndex = -1
+            )
+
+            // Select a color option
+            selectColorOption(colorOptions, 2)
+
+            // Check original option is no longer selected
+            colorTypes()?.get(0)?.onClick?.invoke()
+            assertPickerUiState(
+                colorTypes = colorTypes(),
+                colorOptions = colorOptions(),
+                selectedColorTypeText = "Wallpaper colors",
+                selectedColorOptionIndex = -1
+            )
+
+            // Check new option is selected
+            colorTypes()?.get(1)?.onClick?.invoke()
+            assertPickerUiState(
+                colorTypes = colorTypes(),
+                colorOptions = colorOptions(),
+                selectedColorTypeText = "Basic colors",
+                selectedColorOptionIndex = 2
+            )
+        }
+
+    /** Simulates a user selecting the affordance at the given index, if that is clickable. */
+    private fun TestScope.selectColorOption(
+        colorOptions: () -> List<OptionItemViewModel<ColorOptionIconViewModel>>?,
+        index: Int,
+    ) {
+        val onClickedFlow = colorOptions()?.get(index)?.onClicked
+        val onClickedLastValueOrNull: (() -> (() -> Unit)?)? =
+            onClickedFlow?.let { collectLastValue(it) }
+        onClickedLastValueOrNull?.let { onClickedLastValue ->
+            val onClickedOrNull: (() -> Unit)? = onClickedLastValue()
+            onClickedOrNull?.let { onClicked -> onClicked() }
+        }
+    }
+
+    /**
+     * Asserts the entire picker UI state is what is expected. This includes the color type tabs and
+     * the color options list.
+     *
+     * @param colorTypes The observed color type view-models, keyed by ColorType
+     * @param colorOptions The observed color options
+     * @param selectedColorTypeText The text of the color type that's expected to be selected
+     * @param selectedColorOptionIndex The index of the color option that's expected to be selected,
+     *   -1 stands for no color option should be selected
+     */
+    private fun TestScope.assertPickerUiState(
+        colorTypes: List<FloatingToolbarTabViewModel>?,
+        colorOptions: List<OptionItemViewModel<ColorOptionIconViewModel>>?,
+        selectedColorTypeText: String,
+        selectedColorOptionIndex: Int,
+    ) {
+        assertColorTypeTabUiState(
+            colorTypes = colorTypes,
+            colorTypeId = ColorType.WALLPAPER_COLOR,
+            isSelected = "Wallpaper colors" == selectedColorTypeText,
+        )
+        assertColorTypeTabUiState(
+            colorTypes = colorTypes,
+            colorTypeId = ColorType.PRESET_COLOR,
+            isSelected = "Basic colors" == selectedColorTypeText,
+        )
+        assertColorOptionUiState(colorOptions, selectedColorOptionIndex)
+    }
+
+    /**
+     * Asserts the picker section UI state is what is expected.
+     *
+     * @param colorOptions The observed color options
+     * @param selectedColorOptionIndex The index of the color option that's expected to be selected,
+     *   -1 stands for no color option should be selected
+     */
+    private fun TestScope.assertColorOptionUiState(
+        colorOptions: List<OptionItemViewModel<ColorOptionIconViewModel>>?,
+        selectedColorOptionIndex: Int,
+    ) {
+        var foundSelectedColorOption = false
+        assertThat(colorOptions).isNotNull()
+        if (colorOptions != null) {
+            for (i in colorOptions.indices) {
+                val colorOptionHasSelectedIndex = i == selectedColorOptionIndex
+                val isSelected: Boolean? = collectLastValue(colorOptions[i].isSelected).invoke()
+                assertWithMessage(
+                        "Expected color option with index \"${i}\" to have" +
+                            " isSelected=$colorOptionHasSelectedIndex but it was" +
+                            " ${isSelected}, num options: ${colorOptions.size}"
+                    )
+                    .that(isSelected)
+                    .isEqualTo(colorOptionHasSelectedIndex)
+                foundSelectedColorOption = foundSelectedColorOption || colorOptionHasSelectedIndex
+            }
+            if (selectedColorOptionIndex == -1) {
+                assertWithMessage(
+                        "Expected no color options to be selected, but a color option is" +
+                            " selected"
+                    )
+                    .that(foundSelectedColorOption)
+                    .isFalse()
+            } else {
+                assertWithMessage(
+                        "Expected a color option to be selected, but no color option is" +
+                            " selected"
+                    )
+                    .that(foundSelectedColorOption)
+                    .isTrue()
+            }
+        }
+    }
+
+    /**
+     * Asserts that a color type tab has the correct UI state.
+     *
+     * @param colorTypes The observed color type view-models, keyed by ColorType enum
+     * @param colorTypeId the ID of the color type to assert
+     * @param isSelected Whether that color type should be selected
+     */
+    private fun assertColorTypeTabUiState(
+        colorTypes: List<FloatingToolbarTabViewModel>?,
+        colorTypeId: ColorType,
+        isSelected: Boolean,
+    ) {
+        val position = if (colorTypeId == ColorType.WALLPAPER_COLOR) 0 else 1
+        val viewModel =
+            colorTypes?.get(position) ?: error("No color type with ID \"$colorTypeId\"!")
+        assertThat(viewModel.isSelected).isEqualTo(isSelected)
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/KeyguardQuickAffordancePickerViewModel2Test.kt b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/KeyguardQuickAffordancePickerViewModel2Test.kt
new file mode 100644
index 00000000..b6f249e5
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/KeyguardQuickAffordancePickerViewModel2Test.kt
@@ -0,0 +1,418 @@
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
+import androidx.test.core.app.ApplicationProvider
+import androidx.test.filters.SmallTest
+import com.android.customization.module.logging.TestThemesUserEventLogger
+import com.android.customization.picker.quickaffordance.data.repository.KeyguardQuickAffordancePickerRepository
+import com.android.customization.picker.quickaffordance.domain.interactor.KeyguardQuickAffordancePickerInteractor
+import com.android.customization.picker.quickaffordance.domain.interactor.KeyguardQuickAffordanceSnapshotRestorer
+import com.android.systemui.shared.customization.data.content.CustomizationProviderClient
+import com.android.systemui.shared.customization.data.content.FakeCustomizationProviderClient
+import com.android.systemui.shared.keyguard.shared.model.KeyguardQuickAffordanceSlots
+import com.android.themepicker.R
+import com.android.wallpaper.picker.common.icon.ui.viewmodel.Icon
+import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
+import com.android.wallpaper.picker.customization.ui.viewmodel.FloatingToolbarTabViewModel
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
+import com.android.wallpaper.testing.collectLastValue
+import com.google.common.truth.Truth.assertThat
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.flow.emptyFlow
+import kotlinx.coroutines.test.TestDispatcher
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.UnconfinedTestDispatcher
+import kotlinx.coroutines.test.resetMain
+import kotlinx.coroutines.test.runTest
+import kotlinx.coroutines.test.setMain
+import org.junit.After
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+
+@OptIn(ExperimentalCoroutinesApi::class)
+@SmallTest
+@RunWith(RobolectricTestRunner::class)
+class KeyguardQuickAffordancePickerViewModel2Test {
+
+    private val logger = TestThemesUserEventLogger()
+
+    private lateinit var underTest: KeyguardQuickAffordancePickerViewModel2
+
+    private lateinit var context: Context
+    private lateinit var testDispatcher: TestDispatcher
+    private lateinit var testScope: TestScope
+    private lateinit var client: FakeCustomizationProviderClient
+
+    @Before
+    fun setUp() {
+        context = ApplicationProvider.getApplicationContext()
+        testDispatcher = UnconfinedTestDispatcher()
+        Dispatchers.setMain(testDispatcher)
+        testScope = TestScope(testDispatcher)
+        client = FakeCustomizationProviderClient()
+        val quickAffordanceInteractor =
+            KeyguardQuickAffordancePickerInteractor(
+                repository =
+                    KeyguardQuickAffordancePickerRepository(
+                        client = client,
+                        mainScope = testScope.backgroundScope,
+                    ),
+                client = client,
+                snapshotRestorer = KeyguardQuickAffordanceSnapshotRestorer(client),
+            )
+        underTest =
+            KeyguardQuickAffordancePickerViewModel2(
+                applicationContext = context,
+                quickAffordanceInteractor = quickAffordanceInteractor,
+                logger = logger,
+                viewModelScope = testScope.backgroundScope,
+            )
+    }
+
+    @After
+    fun tearDown() {
+        Dispatchers.resetMain()
+    }
+
+    @Test
+    fun selectedSlotIdUpdates_whenClickingOnTabsAndCallingResetPreview() =
+        testScope.runTest {
+            val selectedSlotId = collectLastValue(underTest.selectedSlotId)
+
+            val tabs = collectLastValue(underTest.tabs)
+
+            // Default selected slot ID is bottom_start
+            assertThat(selectedSlotId())
+                .isEqualTo(KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START)
+
+            // Click on tab1
+            val tab1 = tabs()?.get(1) ?: throw NullPointerException("secondTab should not be null.")
+            tab1.onClick?.invoke()
+            assertThat(selectedSlotId()).isEqualTo(KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_END)
+
+            underTest.resetPreview()
+            assertThat(selectedSlotId())
+                .isEqualTo(KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START)
+        }
+
+    @Test
+    fun selectedQuickAffordancesMapUpdates_whenClickingOnQuickAffordanceOptionsAndCallingResetPreview() =
+        testScope.runTest {
+            val previewingQuickAffordances = collectLastValue(underTest.previewingQuickAffordances)
+
+            val tabs = collectLastValue(underTest.tabs)
+            val quickAffordances = collectLastValue(underTest.quickAffordances)
+
+            // Default selectedQuickAffordances is an empty map
+            assertThat(previewingQuickAffordances()).isEqualTo(emptyMap<String, String>())
+
+            // Click on quick affordance 1 when selected slot ID is bottom_start
+            val onClickAffordance1 =
+                collectLastValue(quickAffordances()?.get(1)?.onClicked ?: emptyFlow())
+            onClickAffordance1()?.invoke()
+            assertThat(previewingQuickAffordances())
+                .isEqualTo(
+                    mapOf(
+                        KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START to
+                            FakeCustomizationProviderClient.AFFORDANCE_1
+                    )
+                )
+
+            // Click on tab 1 to change the selected slot ID to bottom_end and click on quick
+            // affordance 2
+            tabs()?.get(1)?.onClick?.invoke()
+            val onClickAffordance2 =
+                collectLastValue(quickAffordances()?.get(2)?.onClicked ?: emptyFlow())
+            onClickAffordance2()?.invoke()
+            assertThat(previewingQuickAffordances())
+                .isEqualTo(
+                    mapOf(
+                        KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START to
+                            FakeCustomizationProviderClient.AFFORDANCE_1,
+                        KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_END to
+                            FakeCustomizationProviderClient.AFFORDANCE_2
+                    )
+                )
+
+            underTest.resetPreview()
+            assertThat(previewingQuickAffordances()).isEqualTo(emptyMap<String, String>())
+        }
+
+    @Test
+    fun tabsUpdates_whenClickingOnTabsAndQuickAffordanceOptions() =
+        testScope.runTest {
+            val tabs = collectLastValue(underTest.tabs)
+
+            val quickAffordances = collectLastValue(underTest.quickAffordances)
+
+            // Default state of the 2 tabs
+            assertTabUiState(
+                tab = tabs()?.get(0),
+                icon = Icon.Resource(R.drawable.link_off, null),
+                text = "Left shortcut",
+                isSelected = true,
+            )
+            assertTabUiState(
+                tab = tabs()?.get(1),
+                icon = Icon.Resource(R.drawable.link_off, null),
+                text = "Right shortcut",
+                isSelected = false,
+            )
+
+            // Click on tab 1
+            tabs()?.get(1)?.onClick?.invoke()
+            assertTabUiState(
+                tab = tabs()?.get(0),
+                icon = Icon.Resource(R.drawable.link_off, null),
+                text = "Left shortcut",
+                isSelected = false,
+            )
+            val tab1 = tabs()?.get(1)
+            assertTabUiState(
+                tab = tab1,
+                icon = Icon.Resource(R.drawable.link_off, null),
+                text = "Right shortcut",
+                isSelected = true,
+            )
+
+            // Click on quick affordance 1 when tab 1 is selected. Icon should change
+            val clickOnQuickAffordance1 =
+                collectLastValue(quickAffordances()?.get(1)?.onClicked ?: emptyFlow())
+            clickOnQuickAffordance1()?.invoke()
+            assertTabUiState(
+                tab = tabs()?.get(1),
+                icon =
+                    Icon.Loaded(
+                        FakeCustomizationProviderClient.ICON_1,
+                        Text.Loaded("Right shortcut")
+                    ),
+                text = "Right shortcut",
+                isSelected = true,
+            )
+        }
+
+    @Test
+    fun quickAffordancesUpdates_whenClickingOnTabsAndQuickAffordanceOptions() =
+        testScope.runTest {
+            val quickAffordances = collectLastValue(underTest.quickAffordances)
+
+            val tabs = collectLastValue(underTest.tabs)
+
+            // The default quickAffordances snapshot
+            assertThat(quickAffordances()?.size).isEqualTo(4)
+            assertQuickAffordance(
+                testScope = this,
+                quickAffordance = quickAffordances()?.get(0),
+                key = "${KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START}::none",
+                icon = Icon.Resource(R.drawable.link_off, null),
+                text = Text.Resource(R.string.keyguard_affordance_none),
+                isSelected = true,
+            )
+            assertQuickAffordance(
+                testScope = this,
+                quickAffordance = quickAffordances()?.get(1),
+                key =
+                    "${KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START}::${FakeCustomizationProviderClient.AFFORDANCE_1}",
+                icon = Icon.Loaded(FakeCustomizationProviderClient.ICON_1, null),
+                text = Text.Loaded(FakeCustomizationProviderClient.AFFORDANCE_1),
+                isSelected = false,
+            )
+            assertQuickAffordance(
+                testScope = this,
+                quickAffordance = quickAffordances()?.get(2),
+                key =
+                    "${KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START}::${FakeCustomizationProviderClient.AFFORDANCE_2}",
+                icon = Icon.Loaded(FakeCustomizationProviderClient.ICON_2, null),
+                text = Text.Loaded(FakeCustomizationProviderClient.AFFORDANCE_2),
+                isSelected = false,
+            )
+            assertQuickAffordance(
+                testScope = this,
+                quickAffordance = quickAffordances()?.get(3),
+                key =
+                    "${KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START}::${FakeCustomizationProviderClient.AFFORDANCE_3}",
+                icon = Icon.Loaded(FakeCustomizationProviderClient.ICON_3, null),
+                text = Text.Loaded(FakeCustomizationProviderClient.AFFORDANCE_3),
+                isSelected = false,
+            )
+
+            // Click on quick affordance 2. Quick affordance 0 will be unselected and quick
+            // affordance 2 will be selected.
+            val onClickQuickAffordance2 =
+                collectLastValue(quickAffordances()?.get(2)?.onClicked ?: emptyFlow())
+            onClickQuickAffordance2()?.invoke()
+            assertQuickAffordance(
+                testScope = this,
+                quickAffordance = quickAffordances()?.get(0),
+                key = "${KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START}::none",
+                icon = Icon.Resource(R.drawable.link_off, null),
+                text = Text.Resource(R.string.keyguard_affordance_none),
+                isSelected = false,
+            )
+            assertQuickAffordance(
+                testScope = this,
+                quickAffordance = quickAffordances()?.get(2),
+                key =
+                    "${KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START}::${FakeCustomizationProviderClient.AFFORDANCE_2}",
+                icon = Icon.Loaded(FakeCustomizationProviderClient.ICON_2, null),
+                text = Text.Loaded(FakeCustomizationProviderClient.AFFORDANCE_2),
+                isSelected = true,
+            )
+
+            tabs()?.get(1)?.onClick?.invoke()
+            assertQuickAffordance(
+                testScope = this,
+                quickAffordance = quickAffordances()?.get(0),
+                key = "${KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_END}::none",
+                icon = Icon.Resource(R.drawable.link_off, null),
+                text = Text.Resource(R.string.keyguard_affordance_none),
+                isSelected = true,
+            )
+            assertQuickAffordance(
+                testScope = this,
+                quickAffordance = quickAffordances()?.get(1),
+                key =
+                    "${KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_END}::${FakeCustomizationProviderClient.AFFORDANCE_1}",
+                icon = Icon.Loaded(FakeCustomizationProviderClient.ICON_1, null),
+                text = Text.Loaded(FakeCustomizationProviderClient.AFFORDANCE_1),
+                isSelected = false,
+            )
+            assertQuickAffordance(
+                testScope = this,
+                quickAffordance = quickAffordances()?.get(2),
+                key =
+                    "${KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_END}::${FakeCustomizationProviderClient.AFFORDANCE_2}",
+                icon = Icon.Loaded(FakeCustomizationProviderClient.ICON_2, null),
+                text = Text.Loaded(FakeCustomizationProviderClient.AFFORDANCE_2),
+                isSelected = false,
+            )
+            assertQuickAffordance(
+                testScope = this,
+                quickAffordance = quickAffordances()?.get(3),
+                key =
+                    "${KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_END}::${FakeCustomizationProviderClient.AFFORDANCE_3}",
+                icon = Icon.Loaded(FakeCustomizationProviderClient.ICON_3, null),
+                text = Text.Loaded(FakeCustomizationProviderClient.AFFORDANCE_3),
+                isSelected = false,
+            )
+
+            // When tab 1 is selected, click on quick affordance 3. Quick affordance 0 will be
+            // unselected and quick affordance 3 will be selected.
+            val onClickQuickAffordance3 =
+                collectLastValue(quickAffordances()?.get(3)?.onClicked ?: emptyFlow())
+            onClickQuickAffordance3()?.invoke()
+            assertQuickAffordance(
+                testScope = this,
+                quickAffordance = quickAffordances()?.get(0),
+                key = "${KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_END}::none",
+                icon = Icon.Resource(R.drawable.link_off, null),
+                text = Text.Resource(R.string.keyguard_affordance_none),
+                isSelected = false,
+            )
+            assertQuickAffordance(
+                testScope = this,
+                quickAffordance = quickAffordances()?.get(3),
+                key =
+                    "${KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_END}::${FakeCustomizationProviderClient.AFFORDANCE_3}",
+                icon = Icon.Loaded(FakeCustomizationProviderClient.ICON_3, null),
+                text = Text.Loaded(FakeCustomizationProviderClient.AFFORDANCE_3),
+                isSelected = true,
+            )
+        }
+
+    @Test
+    fun loggerShouldLogAndClientShouldUpdate_whenOnApply() =
+        testScope.runTest {
+            val onApply = collectLastValue(underTest.onApply)
+
+            val tabs = collectLastValue(underTest.tabs)
+            val quickAffordances = collectLastValue(underTest.quickAffordances)
+
+            // Select the preview quick affordances
+            val onClickAffordance1 =
+                collectLastValue(quickAffordances()?.get(1)?.onClicked ?: emptyFlow())
+            onClickAffordance1()?.invoke()
+            tabs()?.get(1)?.onClick?.invoke()
+            val onClickAffordance2 =
+                collectLastValue(quickAffordances()?.get(2)?.onClicked ?: emptyFlow())
+            onClickAffordance2()?.invoke()
+
+            onApply()?.invoke()
+            assertThat(client.querySelections())
+                .isEqualTo(
+                    listOf(
+                        CustomizationProviderClient.Selection(
+                            slotId = KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START,
+                            affordanceId = FakeCustomizationProviderClient.AFFORDANCE_1,
+                            affordanceName = FakeCustomizationProviderClient.AFFORDANCE_1,
+                        ),
+                        CustomizationProviderClient.Selection(
+                            slotId = KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_END,
+                            affordanceId = FakeCustomizationProviderClient.AFFORDANCE_2,
+                            affordanceName = FakeCustomizationProviderClient.AFFORDANCE_2,
+                        ),
+                    )
+                )
+            assertThat(logger.shortcutLogs)
+                .isEqualTo(
+                    listOf(
+                        FakeCustomizationProviderClient.AFFORDANCE_1 to
+                            KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_START,
+                        FakeCustomizationProviderClient.AFFORDANCE_2 to
+                            KeyguardQuickAffordanceSlots.SLOT_ID_BOTTOM_END,
+                    )
+                )
+        }
+
+    private fun assertTabUiState(
+        tab: FloatingToolbarTabViewModel?,
+        icon: Icon?,
+        text: String,
+        isSelected: Boolean,
+    ) {
+        if (tab == null) {
+            throw NullPointerException("tab is null.")
+        }
+        assertThat(tab.icon).isEqualTo(icon)
+        assertThat(tab.text).isEqualTo(text)
+        assertThat(tab.isSelected).isEqualTo(isSelected)
+    }
+
+    private fun assertQuickAffordance(
+        testScope: TestScope,
+        quickAffordance: OptionItemViewModel<Icon>?,
+        key: String,
+        icon: Icon,
+        text: Text,
+        isSelected: Boolean,
+    ) {
+        if (quickAffordance == null) {
+            throw NullPointerException("quickAffordance is null.")
+        }
+        assertThat(testScope.collectLastValue(quickAffordance.key)()).isEqualTo(key)
+        assertThat(quickAffordance.payload).isEqualTo(icon)
+        assertThat(quickAffordance.text).isEqualTo(text)
+        assertThat(quickAffordance.isTextUserVisible).isEqualTo(true)
+        assertThat(testScope.collectLastValue(quickAffordance.isSelected)()).isEqualTo(isSelected)
+        assertThat(quickAffordance.isEnabled).isEqualTo(true)
+    }
+}
diff --git a/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ShapeAndGridPickerViewModelTest.kt b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ShapeAndGridPickerViewModelTest.kt
new file mode 100644
index 00000000..02d3ce7a
--- /dev/null
+++ b/tests/robotests/src/com/android/wallpaper/customization/ui/viewmodel/ShapeAndGridPickerViewModelTest.kt
@@ -0,0 +1,196 @@
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
+import androidx.test.core.app.ApplicationProvider
+import androidx.test.filters.SmallTest
+import com.android.customization.model.ResourceConstants
+import com.android.customization.model.grid.FakeGridOptionsManager
+import com.android.customization.picker.grid.domain.interactor.GridInteractor2
+import com.android.customization.picker.grid.ui.viewmodel.GridIconViewModel
+import com.android.wallpaper.picker.common.text.ui.viewmodel.Text
+import com.android.wallpaper.picker.option.ui.viewmodel.OptionItemViewModel
+import com.android.wallpaper.testing.collectLastValue
+import com.google.common.truth.Truth.assertThat
+import dagger.hilt.android.qualifiers.ApplicationContext
+import dagger.hilt.android.testing.HiltAndroidRule
+import dagger.hilt.android.testing.HiltAndroidTest
+import javax.inject.Inject
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.resetMain
+import kotlinx.coroutines.test.runTest
+import org.junit.After
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+
+@HiltAndroidTest
+@OptIn(ExperimentalCoroutinesApi::class)
+@SmallTest
+@RunWith(RobolectricTestRunner::class)
+class ShapeAndGridPickerViewModelTest {
+
+    @get:Rule var hiltRule = HiltAndroidRule(this)
+    @Inject lateinit var testScope: TestScope
+    @Inject lateinit var gridOptionsManager: FakeGridOptionsManager
+    @Inject lateinit var interactor: GridInteractor2
+    @Inject @ApplicationContext lateinit var appContext: Context
+
+    private val iconShapePath =
+        ApplicationProvider.getApplicationContext<Context>()
+            .resources
+            .getString(
+                Resources.getSystem()
+                    .getIdentifier(
+                        ResourceConstants.CONFIG_ICON_MASK,
+                        "string",
+                        ResourceConstants.ANDROID_PACKAGE,
+                    )
+            )
+
+    private lateinit var underTest: ShapeAndGridPickerViewModel
+
+    @Before
+    fun setUp() {
+        hiltRule.inject()
+        underTest = ShapeAndGridPickerViewModel(appContext, interactor, testScope.backgroundScope)
+    }
+
+    @After
+    fun tearDown() {
+        Dispatchers.resetMain()
+    }
+
+    @Test
+    fun selectedGridOption() =
+        testScope.runTest {
+            val selectedGridOption = collectLastValue(underTest.selectedGridOption)
+
+            assertOptionItem(
+                optionItem = selectedGridOption(),
+                key = "normal",
+                payload = GridIconViewModel(5, 5, iconShapePath),
+                text = Text.Loaded("5x5"),
+                isTextUserVisible = true,
+                isSelected = true,
+                isEnabled = true,
+            )
+        }
+
+    @Test
+    fun selectedGridOption_shouldUpdate_afterOnApply() =
+        testScope.runTest {
+            val selectedGridOption = collectLastValue(underTest.selectedGridOption)
+            val optionItems = collectLastValue(underTest.optionItems)
+            val onApply = collectLastValue(underTest.onApply)
+            val onPracticalOptionClick =
+                optionItems()?.get(1)?.onClicked?.let { collectLastValue(it) }
+            checkNotNull(onPracticalOptionClick)
+
+            onPracticalOptionClick()?.invoke()
+            onApply()?.invoke()
+
+            assertOptionItem(
+                optionItem = selectedGridOption(),
+                key = "practical",
+                payload = GridIconViewModel(4, 5, iconShapePath),
+                text = Text.Loaded("4x5"),
+                isTextUserVisible = true,
+                isSelected = true,
+                isEnabled = true,
+            )
+        }
+
+    @Test
+    fun optionItems() =
+        testScope.runTest {
+            val optionItems = collectLastValue(underTest.optionItems)
+
+            assertOptionItem(
+                optionItem = optionItems()?.get(0),
+                key = "normal",
+                payload = GridIconViewModel(5, 5, iconShapePath),
+                text = Text.Loaded("5x5"),
+                isTextUserVisible = true,
+                isSelected = true,
+                isEnabled = true,
+            )
+            assertOptionItem(
+                optionItem = optionItems()?.get(1),
+                key = "practical",
+                payload = GridIconViewModel(4, 5, iconShapePath),
+                text = Text.Loaded("4x5"),
+                isTextUserVisible = true,
+                isSelected = false,
+                isEnabled = true,
+            )
+        }
+
+    @Test
+    fun optionItems_whenClickOnPracticalOption() =
+        testScope.runTest {
+            val optionItems = collectLastValue(underTest.optionItems)
+            val onPracticalOptionClick =
+                optionItems()?.get(1)?.onClicked?.let { collectLastValue(it) }
+            checkNotNull(onPracticalOptionClick)
+
+            onPracticalOptionClick()?.invoke()
+
+            assertOptionItem(
+                optionItem = optionItems()?.get(0),
+                key = "normal",
+                payload = GridIconViewModel(5, 5, iconShapePath),
+                text = Text.Loaded("5x5"),
+                isTextUserVisible = true,
+                isSelected = false,
+                isEnabled = true,
+            )
+            assertOptionItem(
+                optionItem = optionItems()?.get(1),
+                key = "practical",
+                payload = GridIconViewModel(4, 5, iconShapePath),
+                text = Text.Loaded("4x5"),
+                isTextUserVisible = true,
+                isSelected = true,
+                isEnabled = true,
+            )
+        }
+
+    private fun assertOptionItem(
+        optionItem: OptionItemViewModel<GridIconViewModel>?,
+        key: String,
+        payload: GridIconViewModel?,
+        text: Text,
+        isTextUserVisible: Boolean,
+        isSelected: Boolean,
+        isEnabled: Boolean,
+    ) {
+        checkNotNull(optionItem)
+        assertThat(optionItem.key.value).isEqualTo(key)
+        assertThat(optionItem.text).isEqualTo(text)
+        assertThat(optionItem.payload).isEqualTo(payload)
+        assertThat(optionItem.isTextUserVisible).isEqualTo(isTextUserVisible)
+        assertThat(optionItem.isSelected.value).isEqualTo(isSelected)
+        assertThat(optionItem.isEnabled).isEqualTo(isEnabled)
+    }
+}
diff --git a/themes/res/values-bn/strings.xml b/themes/res/values-bn/strings.xml
index 8a90e02e..a935ae6a 100644
--- a/themes/res/values-bn/strings.xml
+++ b/themes/res/values-bn/strings.xml
@@ -22,7 +22,7 @@
     <string name="rainbow_color_name_yellow" msgid="8675574652757989201">"হলুদ"</string>
     <string name="rainbow_color_name_green" msgid="1932895389710184112">"সবুজ"</string>
     <string name="rainbow_color_name_blue" msgid="3473176664458856892">"নীল"</string>
-    <string name="rainbow_color_name_purple" msgid="2704722524588084868">"বেগুনি"</string>
+    <string name="rainbow_color_name_purple" msgid="2704722524588084868">"পার্পেল"</string>
     <string name="rainbow_color_name_magenta" msgid="7248703626077785569">"ম্যাজেন্টা"</string>
     <string name="monochromatic_name" msgid="2554823570460886176">"মোনোক্রোম্যাটিক"</string>
 </resources>
```

