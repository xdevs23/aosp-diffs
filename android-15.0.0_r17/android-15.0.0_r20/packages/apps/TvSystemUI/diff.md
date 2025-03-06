```diff
diff --git a/Android.bp b/Android.bp
index ef0c5aa..8d11ee0 100644
--- a/Android.bp
+++ b/Android.bp
@@ -47,6 +47,7 @@ android_library {
         "SystemUIPluginLib",
         "SystemUISharedLib",
         "TvSystemUI-res",
+        "TwoPanelSettingsLib"
     ],
     javacflags: ["-Adagger.fastInit=enabled"],
     manifest: "AndroidManifest.xml",
diff --git a/res/anim/tooltip_window_enter.xml b/res/anim/tooltip_window_enter.xml
new file mode 100644
index 0000000..e53b8c5
--- /dev/null
+++ b/res/anim/tooltip_window_enter.xml
@@ -0,0 +1,24 @@
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
+<set xmlns:android="http://schemas.android.com/apk/res/android">
+    <alpha
+        android:fromAlpha="0.0"
+        android:toAlpha="1.0"
+        android:duration="200"
+        android:interpolator="@interpolator/easing_standard" />
+</set>
\ No newline at end of file
diff --git a/res/anim/tooltip_window_exit.xml b/res/anim/tooltip_window_exit.xml
new file mode 100644
index 0000000..9de6c23
--- /dev/null
+++ b/res/anim/tooltip_window_exit.xml
@@ -0,0 +1,24 @@
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
+<set xmlns:android="http://schemas.android.com/apk/res/android">
+    <alpha
+        android:fromAlpha="1.0"
+        android:toAlpha="0.0"
+        android:duration="200"
+        android:interpolator="@interpolator/easing_standard" />
+</set>
\ No newline at end of file
diff --git a/res/color/media_dialog_settings_icon.xml b/res/color/media_dialog_settings_icon.xml
new file mode 100644
index 0000000..9c47e68
--- /dev/null
+++ b/res/color/media_dialog_settings_icon.xml
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_focused="true"
+          android:color="@color/media_dialog_settings_icon_focused"/>
+    <item android:color="@color/media_dialog_settings_icon_unfocused"/>
+</selector>
\ No newline at end of file
diff --git a/res/color/seekbar_progress_background_color.xml b/res/color/seekbar_progress_background_color.xml
new file mode 100644
index 0000000..6e72738
--- /dev/null
+++ b/res/color/seekbar_progress_background_color.xml
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_focused="true"
+        android:color="@color/seekbar_progress_background_focused_color"/>
+    <item android:color="@color/seekbar_progress_background_unfocused_color"/>
+</selector>
\ No newline at end of file
diff --git a/res/color/seekbar_progress_color.xml b/res/color/seekbar_progress_color.xml
new file mode 100644
index 0000000..944ec22
--- /dev/null
+++ b/res/color/seekbar_progress_color.xml
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_focused="true"
+        android:color="@color/seekbar_progress_focused_color"/>
+    <item android:color="@color/seekbar_progress_unfocused_color"/>
+</selector>
\ No newline at end of file
diff --git a/res/color/switch_thumb_color.xml b/res/color/switch_thumb_color.xml
new file mode 100644
index 0000000..8e29925
--- /dev/null
+++ b/res/color/switch_thumb_color.xml
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_focused="true" android:state_checked="true"
+          android:color="@color/switch_thumb_focused_color"/>
+    <item android:state_checked="true"
+          android:color="@color/switch_thumb_unfocused_color"/>
+    <item android:color="@color/switch_thumb_unchecked_color"/>
+</selector>
\ No newline at end of file
diff --git a/res/color/switch_track_border_color.xml b/res/color/switch_track_border_color.xml
new file mode 100644
index 0000000..5362c34
--- /dev/null
+++ b/res/color/switch_track_border_color.xml
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_focused="false" android:state_checked="false" android:state_enabled="true"
+          android:color="@color/switch_track_border_unfocused_unchecked"/>
+    <item android:state_focused="false" android:state_enabled="false"
+        android:color="@color/switch_track_border_unfocused_disabled"/>
+    <item android:color="@android:color/transparent"/>
+</selector>
\ No newline at end of file
diff --git a/res/color/switch_track_color.xml b/res/color/switch_track_color.xml
new file mode 100644
index 0000000..cf37598
--- /dev/null
+++ b/res/color/switch_track_color.xml
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:state_focused="true" android:state_checked="true"
+          android:color="@color/switch_track_focused_color"/>
+    <item android:state_checked="true"
+          android:color="@color/switch_track_unfocused_color"/>
+    <item android:color="@color/switch_track_unchecked_color"/>
+</selector>
\ No newline at end of file
diff --git a/res/drawable/both_end_fading_edge.xml b/res/drawable/both_end_fading_edge.xml
new file mode 100644
index 0000000..d176c6a
--- /dev/null
+++ b/res/drawable/both_end_fading_edge.xml
@@ -0,0 +1,9 @@
+<?xml version="1.0" encoding="utf-8"?>
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:id="@+id/top_fading_edge"
+        android:drawable="@drawable/top_fading_edge"/>
+    <item
+        android:id="@+id/bottom_fading_edge"
+        android:drawable="@drawable/bottom_fading_edge"/>
+</layer-list>
\ No newline at end of file
diff --git a/res/drawable/bottom_fading_edge.xml b/res/drawable/bottom_fading_edge.xml
new file mode 100644
index 0000000..733759e
--- /dev/null
+++ b/res/drawable/bottom_fading_edge.xml
@@ -0,0 +1,12 @@
+<?xml version="1.0" encoding="utf-8"?>
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <corners android:radius="@dimen/media_dialog_bg_radius"/>
+    <gradient
+        android:type="linear"
+        android:angle="270"
+        android:centerY="85%"
+        android:startColor="@android:color/transparent"
+        android:centerColor="@android:color/transparent"
+        android:endColor="@color/media_dialog_bg" />
+</shape>
\ No newline at end of file
diff --git a/res/drawable/custom_switch_thumb.xml b/res/drawable/custom_switch_thumb.xml
new file mode 100644
index 0000000..1cfc224
--- /dev/null
+++ b/res/drawable/custom_switch_thumb.xml
@@ -0,0 +1,25 @@
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
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+       android:shape="oval" >
+    <solid android:color="@color/switch_thumb_color" />
+    <size
+        android:width="@dimen/switch_height"
+        android:height="@dimen/switch_height" />
+    <stroke android:color="@android:color/transparent" android:width="8dp"/>
+</shape>
\ No newline at end of file
diff --git a/res/drawable/custom_switch_track.xml b/res/drawable/custom_switch_track.xml
new file mode 100644
index 0000000..bf8254e
--- /dev/null
+++ b/res/drawable/custom_switch_track.xml
@@ -0,0 +1,27 @@
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
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
+    <item>
+        <shape android:shape="rectangle">
+            <corners android:radius="25dp"/>
+            <solid android:color="@color/switch_track_color" />
+            <size android:height="@dimen/switch_height" android:width="@dimen/switch_width"/>
+            <stroke android:color="@android:color/transparent" android:width="2.5dp"/>
+        </shape>
+    </item>
+</layer-list>
\ No newline at end of file
diff --git a/res/drawable/dpad_right.xml b/res/drawable/dpad_right.xml
new file mode 100644
index 0000000..3035670
--- /dev/null
+++ b/res/drawable/dpad_right.xml
@@ -0,0 +1,39 @@
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="20dp"
+    android:height="20dp"
+    android:autoMirrored="true"
+    android:viewportHeight="20"
+    android:viewportWidth="20">
+
+    <group>
+
+        <clip-path android:pathData="M10,0L10,0A10,10 0,0 1,20 10L20,10A10,10 0,0 1,10 20L10,20A10,10 0,0 1,0 10L0,10A10,10 0,0 1,10 0z" />
+        <!-- DPAD_RIGHT -->
+        <path
+            android:fillColor="@color/media_dialog_item_title_unfocused"
+            android:fillType="evenOdd"
+            android:pathData="M14.32,6.769C15,7.691 15.374,8.813 15.374,9.974C15.374,11.147 14.992,12.281 14.297,13.209L17.568,16.48C19.115,14.674 19.974,12.368 19.974,9.974C19.974,7.592 19.124,5.297 17.592,3.496L14.32,6.769Z" />
+        <!-- DPAD_LEFT -->
+        <path
+            android:fillColor="#445664"
+            android:fillType="evenOdd"
+            android:pathData="M5.654,13.208C4.974,12.285 4.6,11.163 4.6,10.002C4.6,8.829 4.982,7.695 5.677,6.767L2.406,3.496C0.859,5.302 0,7.608 0,10.002C0,12.384 0.85,14.679 2.382,16.48L5.654,13.208Z" />
+        <!-- DPAD_UP -->
+        <path
+            android:fillColor="#445664"
+            android:fillType="evenOdd"
+            android:pathData="M13.207,14.32C12.284,15.001 11.162,15.375 10.001,15.375C8.828,15.375 7.694,14.993 6.766,14.298L3.495,17.569C5.301,19.116 7.607,19.975 10.001,19.975C12.383,19.974 14.678,19.125 16.479,17.593L13.207,14.32Z" />
+        <!-- DPAD_DOWN -->
+        <path
+            android:fillColor="#445664"
+            android:fillType="evenOdd"
+            android:pathData="M6.768,5.655C7.69,4.975 8.812,4.601 9.973,4.601C11.146,4.601 12.28,4.983 13.208,5.678L16.479,2.407C14.673,0.86 12.367,0.001 9.973,0.001C7.591,0.001 5.296,0.851 3.495,2.383L6.768,5.655Z" />
+        <!-- DPAD_CENTER -->
+        <path
+            android:fillColor="#445664"
+            android:fillType="evenOdd"
+            android:pathData="M10,13.75C12.071,13.75 13.75,12.071 13.75,10C13.75,7.929 12.071,6.25 10,6.25C7.929,6.25 6.25,7.929 6.25,10C6.25,12.071 7.929,13.75 10,13.75Z" />
+
+    </group>
+
+</vector>
diff --git a/res/drawable/ic_media_device_settings.xml b/res/drawable/ic_media_device_settings.xml
new file mode 100644
index 0000000..c9122bb
--- /dev/null
+++ b/res/drawable/ic_media_device_settings.xml
@@ -0,0 +1,27 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
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
+  limitations under the License
+  -->
+
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="@dimen/media_dialog_settings_icon_size"
+    android:height="@dimen/media_dialog_settings_icon_size"
+    android:viewportWidth="960"
+    android:viewportHeight="960"
+    android:tint="?attr/colorControlNormal">
+    <path
+        android:fillColor="@android:color/white"
+        android:pathData="M370,880L354,752Q341,747 329.5,740Q318,733 307,725L188,775L78,585L181,507Q180,500 180,493.5Q180,487 180,480Q180,473 180,466.5Q180,460 181,453L78,375L188,185L307,235Q318,227 330,220Q342,213 354,208L370,80L590,80L606,208Q619,213 630.5,220Q642,227 653,235L772,185L882,375L779,453Q780,460 780,466.5Q780,473 780,480Q780,487 780,493.5Q780,500 778,507L881,585L771,775L653,725Q642,733 630,740Q618,747 606,752L590,880L370,880ZM440,800L519,800L533,694Q564,686 590.5,670.5Q617,655 639,633L738,674L777,606L691,541Q696,527 698,511.5Q700,496 700,480Q700,464 698,448.5Q696,433 691,419L777,354L738,286L639,328Q617,305 590.5,289.5Q564,274 533,266L520,160L441,160L427,266Q396,274 369.5,289.5Q343,305 321,327L222,286L183,354L269,418Q264,433 262,448Q260,463 260,480Q260,496 262,511Q264,526 269,541L183,606L222,674L321,632Q343,655 369.5,670.5Q396,686 427,694L440,800ZM482,620Q540,620 581,579Q622,538 622,480Q622,422 581,381Q540,340 482,340Q423,340 382.5,381Q342,422 342,480Q342,538 382.5,579Q423,620 482,620ZM480,480L480,480Q480,480 480,480Q480,480 480,480L480,480L480,480L480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480L480,480L480,480L480,480Q480,480 480,480Q480,480 480,480L480,480L480,480L480,480Q480,480 480,480Q480,480 480,480L480,480L480,480L480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480L480,480L480,480L480,480Q480,480 480,480Q480,480 480,480L480,480Z"/>
+</vector>
\ No newline at end of file
diff --git a/res/drawable/media_dialog_icon_bg.xml b/res/drawable/media_dialog_icon_bg.xml
index ca9555e..f8e82c8 100644
--- a/res/drawable/media_dialog_icon_bg.xml
+++ b/res/drawable/media_dialog_icon_bg.xml
@@ -15,7 +15,6 @@
   -->
 
 <shape xmlns:android="http://schemas.android.com/apk/res/android"
-       android:shape="rectangle">
-    <corners android:radius="@dimen/media_dialog_icon_bg_radius"/>
+       android:shape="oval">
     <solid android:color="@color/media_dialog_icon_bg" />
 </shape>
\ No newline at end of file
diff --git a/res/drawable/media_dialog_item_bg_rounded.xml b/res/drawable/media_dialog_item_bg_rounded.xml
new file mode 100644
index 0000000..092f4c0
--- /dev/null
+++ b/res/drawable/media_dialog_item_bg_rounded.xml
@@ -0,0 +1,21 @@
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
+  -->
+
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+       android:shape="rectangle">
+    <corners android:radius="@dimen/media_dialog_item_bg_radius_rounded"/>
+    <solid android:color="@color/media_dialog_item_bg" />
+</shape>
\ No newline at end of file
diff --git a/res/drawable/seekbar_background.xml b/res/drawable/seekbar_background.xml
new file mode 100644
index 0000000..e19f518
--- /dev/null
+++ b/res/drawable/seekbar_background.xml
@@ -0,0 +1,12 @@
+<?xml version="1.0" encoding="utf-8"?>
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
+    <!--  Avoid empty space between progress and background when value reaches 0 -->
+    <item android:start="-1dp">
+        <shape>
+            <corners android:radius="@dimen/seekbar_widget_track_corner_radius" />
+            <size android:height="@dimen/seekbar_height"/>
+            <solid android:color="@color/seekbar_progress_background_color"/>
+            <stroke android:color="@android:color/transparent" android:width="@dimen/seekbar_background_stroke_width"/>
+        </shape>
+    </item>
+</layer-list>
\ No newline at end of file
diff --git a/res/drawable/seekbar_progress.xml b/res/drawable/seekbar_progress.xml
new file mode 100644
index 0000000..a531d68
--- /dev/null
+++ b/res/drawable/seekbar_progress.xml
@@ -0,0 +1,12 @@
+<?xml version="1.0" encoding="utf-8"?>
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:id="@+id/progressshape">
+        <scale android:scaleWidth="100%">
+            <shape android:shape="rectangle">
+                <size android:height="@dimen/seekbar_height" />
+                <corners android:radius="@dimen/seekbar_widget_progress_corner_radius" />
+                <solid android:color="@color/seekbar_progress_color" />
+            </shape>
+        </scale>
+    </item>
+</layer-list>
\ No newline at end of file
diff --git a/res/drawable/seekbar_style_drawable.xml b/res/drawable/seekbar_style_drawable.xml
new file mode 100644
index 0000000..2b00288
--- /dev/null
+++ b/res/drawable/seekbar_style_drawable.xml
@@ -0,0 +1,10 @@
+<?xml version="1.0" encoding="utf-8"?>
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:id="@android:id/background"
+        android:drawable="@drawable/seekbar_background"/>
+
+    <item android:id="@android:id/progress">
+        <scale android:drawable="@drawable/seekbar_progress"/>
+    </item>
+</layer-list>
\ No newline at end of file
diff --git a/res/drawable/tooltip_arrow.xml b/res/drawable/tooltip_arrow.xml
new file mode 100644
index 0000000..c37296a
--- /dev/null
+++ b/res/drawable/tooltip_arrow.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
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
+  limitations under the License
+  -->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="6dp"
+    android:height="9dp"
+    android:viewportWidth="6"
+    android:viewportHeight="9"
+    android:autoMirrored="true">
+    <path android:fillColor="@color/media_dialog_bg"
+        android:pathData="M0,0 6,4.5 0,9 0,0"/>
+</vector>
\ No newline at end of file
diff --git a/res/drawable/tooltip_background.xml b/res/drawable/tooltip_background.xml
new file mode 100644
index 0000000..b93f665
--- /dev/null
+++ b/res/drawable/tooltip_background.xml
@@ -0,0 +1,22 @@
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
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <solid android:color="@color/media_dialog_bg" />
+    <corners android:radius="@dimen/tooltip_bg_radius"/>
+</shape>
\ No newline at end of file
diff --git a/res/drawable/top_fading_edge.xml b/res/drawable/top_fading_edge.xml
new file mode 100644
index 0000000..ccca0e1
--- /dev/null
+++ b/res/drawable/top_fading_edge.xml
@@ -0,0 +1,11 @@
+<?xml version="1.0" encoding="utf-8"?>
+<shape xmlns:android="http://schemas.android.com/apk/res/android"
+    android:shape="rectangle">
+    <gradient
+        android:type="linear"
+        android:angle="270"
+        android:centerY="15%"
+        android:startColor="@color/media_dialog_bg"
+        android:centerColor="@android:color/transparent"
+        android:endColor="@android:color/transparent" />
+</shape>
\ No newline at end of file
diff --git a/res/interpolator/easing_standard.xml b/res/interpolator/easing_standard.xml
new file mode 100644
index 0000000..0e2fe6f
--- /dev/null
+++ b/res/interpolator/easing_standard.xml
@@ -0,0 +1,22 @@
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
+<pathInterpolator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:controlX1="0.2"
+    android:controlY1="0"
+    android:controlX2="0"
+    android:controlY2="1"/>
\ No newline at end of file
diff --git a/res/layout/basic_centered_control_widget.xml b/res/layout/basic_centered_control_widget.xml
new file mode 100644
index 0000000..8dc17c3
--- /dev/null
+++ b/res/layout/basic_centered_control_widget.xml
@@ -0,0 +1,38 @@
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/basic_icon_title_container"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:gravity="center"
+    android:duplicateParentState="true"
+    android:orientation="horizontal">
+
+    <ImageView
+        android:id="@android:id/icon"
+        style="@style/ControlWidgetIconStyle"
+        android:layout_marginEnd="@dimen/control_widget_icon_margin_end"
+        android:duplicateParentState="true" />
+
+    <com.android.systemui.tv.SmoothScalingTextView
+        android:id="@android:id/title"
+        style="@style/TextAppearance.Panel.ListItem"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:duplicateParentState="true" />
+</LinearLayout>
diff --git a/res/layout/basic_centered_slice_pref.xml b/res/layout/basic_centered_slice_pref.xml
new file mode 100644
index 0000000..ddb032f
--- /dev/null
+++ b/res/layout/basic_centered_slice_pref.xml
@@ -0,0 +1,22 @@
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
+<view class="com.android.systemui.tv.media.settings.BasicCenteredSlicePreference$BasicCenteredControlWidget"
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    style="@style/BasicCenteredIconTextWidgetStyle"
+    android:id="@+id/basic_control_widget_view"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content" />
\ No newline at end of file
diff --git a/res/layout/basic_control_widget.xml b/res/layout/basic_control_widget.xml
new file mode 100644
index 0000000..3fcbc12
--- /dev/null
+++ b/res/layout/basic_control_widget.xml
@@ -0,0 +1,27 @@
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/basic_icon_title_container"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:gravity="center_vertical"
+    android:duplicateParentState="true"
+    android:orientation="horizontal">
+
+    <include layout="@layout/core_slice_preference" />
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/basic_slice_pref.xml b/res/layout/basic_slice_pref.xml
new file mode 100644
index 0000000..eb0c186
--- /dev/null
+++ b/res/layout/basic_slice_pref.xml
@@ -0,0 +1,22 @@
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
+<view class="com.android.systemui.tv.media.settings.BasicSlicePreference$BasicControlWidget"
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    style="@style/BasicIconTextWidgetStyle"
+    android:id="@+id/basic_control_widget_view"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content" />
\ No newline at end of file
diff --git a/res/layout/category_slice_preference.xml b/res/layout/category_slice_preference.xml
new file mode 100644
index 0000000..d97de6b
--- /dev/null
+++ b/res/layout/category_slice_preference.xml
@@ -0,0 +1,37 @@
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
+<FrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/media_output_group_divider"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:layout_marginHorizontal="@dimen/media_dialog_item_margin_horizontal"
+    android:focusable="false">
+
+    <TextView
+        android:id="@android:id/title"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginTop="@dimen/media_output_text_divider_margin_top"
+        android:layout_gravity="center_horizontal"
+        android:textAllCaps="true"
+        android:letterSpacing="0.08"
+        android:fontFamily="@string/font_overline"
+        android:textSize="@dimen/media_dialog_divider_text"
+        android:textColor="@color/media_dialog_divider_text" />
+</FrameLayout>
\ No newline at end of file
diff --git a/res/layout/checkbox_control_widget.xml b/res/layout/checkbox_control_widget.xml
new file mode 100644
index 0000000..f0ca3c5
--- /dev/null
+++ b/res/layout/checkbox_control_widget.xml
@@ -0,0 +1,33 @@
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/checkbox_widget_container"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:gravity="center_vertical"
+    android:duplicateParentState="true"
+    android:orientation="horizontal">
+
+    <include layout="@layout/core_slice_preference" />
+
+    <CheckBox
+        android:id="@android:id/checkbox"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:focusable="false" />
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/checkbox_slice_pref.xml b/res/layout/checkbox_slice_pref.xml
new file mode 100644
index 0000000..9ea3d48
--- /dev/null
+++ b/res/layout/checkbox_slice_pref.xml
@@ -0,0 +1,22 @@
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
+<view class="com.android.systemui.tv.media.settings.CheckboxSlicePreference$CheckboxControlWidget"
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    style="@style/CheckboxWidgetStyle"
+    android:id="@+id/checkbox_widget_view"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content" />
\ No newline at end of file
diff --git a/res/layout/core_slice_preference.xml b/res/layout/core_slice_preference.xml
new file mode 100644
index 0000000..4681e19
--- /dev/null
+++ b/res/layout/core_slice_preference.xml
@@ -0,0 +1,46 @@
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
+<merge xmlns:android="http://schemas.android.com/apk/res/android">
+    <ImageView
+        android:id="@android:id/icon"
+        android:duplicateParentState="true"
+        android:layout_marginEnd="@dimen/control_widget_icon_margin_end"
+        style="@style/ControlWidgetIconStyle" />
+
+    <LinearLayout
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:layout_weight="1"
+        android:gravity="start|center_vertical"
+        android:layout_marginEnd="@dimen/media_dialog_item_padding"
+        android:duplicateParentState="true"
+        android:orientation="vertical">
+        <com.android.systemui.tv.SmoothScalingTextView
+            android:id="@android:id/title"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:textAppearance="@style/TextAppearance.Panel.ListItem"
+            android:duplicateParentState="true" />
+        <com.android.systemui.tv.SmoothScalingTextView
+            android:id="@android:id/summary"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:textAppearance="@style/TextAppearance.Panel.ListItem.Secondary"
+            android:duplicateParentState="true" />
+    </LinearLayout>
+</merge>
\ No newline at end of file
diff --git a/res/layout/info_slice_preference.xml b/res/layout/info_slice_preference.xml
new file mode 100644
index 0000000..609243d
--- /dev/null
+++ b/res/layout/info_slice_preference.xml
@@ -0,0 +1,59 @@
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:orientation="vertical">
+
+    <View
+        android:id="@+id/media_output_divider_line"
+        android:layout_width="@dimen/media_output_divider_width"
+        android:layout_height="@dimen/media_output_divider_height"
+        android:layout_gravity="center"
+        android:background="@color/media_dialog_divider_line"
+        android:layout_marginVertical="@dimen/media_output_divider_margin_vertical" />
+
+    <LinearLayout
+        android:id="@+id/main_container"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:importantForAccessibility="no"
+        android:orientation="horizontal">
+
+        <FrameLayout
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:importantForAccessibility="no"
+            android:layout_gravity="center_horizontal|top">
+
+            <ImageView
+                android:id="@android:id/icon"
+                android:duplicateParentState="true"
+                android:layout_marginHorizontal="@dimen/media_dialog_item_margin_horizontal"
+                style="@style/ControlWidgetIconStyle" />
+        </FrameLayout>
+
+        <LinearLayout
+            android:id="@+id/item_container"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_weight="1"
+            android:focusable="true"
+            android:orientation="vertical" />
+    </LinearLayout>
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/info_slice_preference_item.xml b/res/layout/info_slice_preference_item.xml
new file mode 100644
index 0000000..62ebf0d
--- /dev/null
+++ b/res/layout/info_slice_preference_item.xml
@@ -0,0 +1,39 @@
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:orientation="vertical"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:layout_marginBottom="12dp">
+
+    <TextView
+        android:id="@+id/info_item_title"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:textColor="@color/media_dialog_subtitle"
+        android:fontFamily="@string/font_body_small"
+        android:textSize="@dimen/media_dialog_item_title" />
+
+    <TextView
+        android:id="@+id/info_item_summary"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:textColor="@color/media_dialog_subtitle"
+        android:fontFamily="@string/font_body_small"
+        android:textSize="@dimen/media_dialog_item_subtitle" />
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/media_output_device_widget.xml b/res/layout/media_output_device_widget.xml
new file mode 100644
index 0000000..a9e92f6
--- /dev/null
+++ b/res/layout/media_output_device_widget.xml
@@ -0,0 +1,73 @@
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
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/media_output_dialog_item"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:gravity="center_vertical"
+    android:duplicateParentState="true"
+    android:orientation="horizontal">
+
+    <FrameLayout
+        android:layout_width="@dimen/media_dialog_icon_bg_size"
+        android:layout_height="@dimen/media_dialog_icon_bg_size"
+        android:background="@drawable/media_dialog_icon_bg"
+        android:duplicateParentState="true"
+        android:gravity="center">
+        <ImageView
+            android:id="@+id/media_output_item_icon"
+            android:layout_width="@dimen/media_dialog_icon_size"
+            android:layout_height="@dimen/media_dialog_icon_size"
+            android:layout_gravity="center"
+            android:gravity="center"
+            android:duplicateParentState="true"
+            android:tint="@color/media_dialog_icon" />
+    </FrameLayout>
+
+    <LinearLayout
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:layout_weight="1"
+        android:gravity="start|center_vertical"
+        android:paddingHorizontal="@dimen/media_dialog_item_padding"
+        android:duplicateParentState="true"
+        android:orientation="vertical">
+        <com.android.systemui.tv.SmoothScalingTextView
+            android:id="@+id/media_dialog_item_title"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:textAppearance="@style/TextAppearance.Panel.ListItem"
+            android:duplicateParentState="true"
+            style="@style/SingleLineMarquee" />
+        <com.android.systemui.tv.SmoothScalingTextView
+            android:id="@+id/media_dialog_item_subtitle"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:textAppearance="@style/TextAppearance.Panel.ListItem.Secondary"
+            android:duplicateParentState="true"
+            style="@style/SingleLineMarquee" />
+    </LinearLayout>
+
+    <RadioButton
+        android:id="@+id/media_dialog_radio_button"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:focusable="false"
+        android:clickable="false" />
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/media_output_dialog.xml b/res/layout/media_output_dialog.xml
index 535c862..55713e0 100644
--- a/res/layout/media_output_dialog.xml
+++ b/res/layout/media_output_dialog.xml
@@ -24,21 +24,8 @@
     android:focusable="false"
     android:orientation="vertical">
 
-    <TextView
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:layout_gravity="center_horizontal"
-        android:layout_margin="@dimen/media_dialog_title_margin"
-        android:text="@string/media_output_dialog_title"
-        android:textColor="@color/media_dialog_title"
-        android:fontFamily="@string/font_label_large"
-        android:textSize="@dimen/media_dialog_title" />
-
-    <com.android.internal.widget.RecyclerView
-        android:id="@+id/device_list"
+    <FrameLayout
+        android:id="@+id/media_output_fragment"
         android:layout_width="match_parent"
-        android:layout_height="wrap_content"
-        android:layout_weight="1"
-        android:scrollbars="vertical"
-        android:clipToPadding="false" />
+        android:layout_height="match_parent" />
 </LinearLayout>
\ No newline at end of file
diff --git a/res/layout/media_output_list_item_advanced.xml b/res/layout/media_output_list_item_advanced.xml
index 4253104..64c127a 100644
--- a/res/layout/media_output_list_item_advanced.xml
+++ b/res/layout/media_output_list_item_advanced.xml
@@ -1,86 +1,35 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!--
-  ~ Copyright (C) 2023 The Android Open Source Project
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
-<LinearLayout
-    xmlns:android="http://schemas.android.com/apk/res/android"
-    android:id="@+id/media_output_dialog_item"
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
-    android:background="@drawable/media_dialog_item_bg"
-    android:stateListAnimator="@anim/media_dialog_item_state_list_animator"
-    android:layout_marginHorizontal="@dimen/media_dialog_item_margin_horizontal"
-    android:padding="@dimen/media_dialog_item_padding"
-    android:gravity="center_vertical"
+    android:focusable="false"
+    android:clipChildren="false"
+    android:clipToPadding="false"
+    android:paddingVertical="1dp"
+    android:paddingHorizontal="@dimen/media_dialog_item_padding"
     android:orientation="horizontal">
 
-    <FrameLayout
-        android:layout_width="@dimen/media_dialog_icon_bg_size"
-        android:layout_height="@dimen/media_dialog_icon_bg_size"
-        android:background="@drawable/media_dialog_icon_bg"
-        android:duplicateParentState="true"
-        android:gravity="center">
-        <ImageView
-            android:id="@+id/media_output_item_icon"
-            android:layout_width="@dimen/media_dialog_icon_size"
-            android:layout_height="@dimen/media_dialog_icon_size"
-            android:layout_gravity="center"
-            android:gravity="center"
-            android:duplicateParentState="true"
-            android:tint="@color/media_dialog_icon" />
-    </FrameLayout>
-
-    <LinearLayout
+    <view
+        class="com.android.systemui.tv.media.OutputDeviceControlWidget"
+        android:id="@+id/media_dialog_device_widget"
+        style="@style/OutputDeviceWidgetStyle"
+        android:focusable="true"
         android:layout_width="0dp"
         android:layout_height="wrap_content"
-        android:layout_weight="1"
-        android:gravity="start|center_vertical"
-        android:paddingHorizontal="@dimen/media_dialog_item_padding"
-        android:duplicateParentState="true"
-        android:orientation="vertical">
-        <com.android.systemui.tv.SmoothScalingTextView
-            android:id="@+id/media_dialog_item_title"
-            android:layout_width="wrap_content"
-            android:layout_height="wrap_content"
-            android:textColor="@color/media_dialog_item_title"
-            android:textSize="@dimen/media_dialog_item_title"
-            android:fontFamily="@string/font_label_medium"
-            android:ellipsize="marquee"
-            android:singleLine="true"
-            android:marqueeRepeatLimit="marquee_forever"
-            android:scrollHorizontally="true"
-            android:duplicateParentState="true" />
-        <com.android.systemui.tv.SmoothScalingTextView
-            android:id="@+id/media_dialog_item_subtitle"
-            android:layout_width="wrap_content"
-            android:layout_height="wrap_content"
-            android:textColor="@color/media_dialog_item_subtitle"
-            android:textSize="@dimen/media_dialog_item_subtitle"
-            android:fontFamily="@string/font_body_extra_small"
-            android:ellipsize="marquee"
-            android:singleLine="true"
-            android:marqueeRepeatLimit="marquee_forever"
-            android:scrollHorizontally="true"
-            android:duplicateParentState="true" />
-    </LinearLayout>
+        android:layout_weight="1" />
 
-    <RadioButton
-        android:id="@+id/media_dialog_radio_button"
+    <ImageButton
+        android:id="@+id/media_dialog_item_a11y_settings"
         android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:focusable="false"
-        android:clickable="false" />
-</LinearLayout>
\ No newline at end of file
+        android:layout_height="match_parent"
+        android:visibility="gone"
+        android:background="@drawable/media_dialog_item_bg"
+        android:stateListAnimator="@anim/media_dialog_item_state_list_animator"
+        android:src="@drawable/ic_media_device_settings"
+        android:tint="@color/media_dialog_settings_icon"
+        android:layout_gravity="center"
+        android:gravity="center"
+        android:padding="@dimen/media_dialog_item_padding"
+        android:layout_marginStart="8dp" />
+
+</LinearLayout>
diff --git a/res/layout/media_output_main_fragment.xml b/res/layout/media_output_main_fragment.xml
new file mode 100644
index 0000000..3ed4711
--- /dev/null
+++ b/res/layout/media_output_main_fragment.xml
@@ -0,0 +1,43 @@
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
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/media_output_dialog"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:focusable="false"
+    android:orientation="vertical">
+
+    <TextView
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_gravity="center_horizontal"
+        android:layout_margin="@dimen/media_dialog_title_margin"
+        android:text="@string/media_output_dialog_title"
+        android:textColor="@color/media_dialog_title"
+        android:fontFamily="@string/font_label_large"
+        android:textSize="@dimen/media_dialog_title" />
+
+    <androidx.recyclerview.widget.RecyclerView
+        android:id="@+id/device_list"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_weight="1"
+        android:scrollbars="none"
+        android:clipToPadding="false" />
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/media_output_settings_progress.xml b/res/layout/media_output_settings_progress.xml
new file mode 100644
index 0000000..022c17b
--- /dev/null
+++ b/res/layout/media_output_settings_progress.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2019 The Android Open Source Project
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
+<RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:background="@null">
+  <ProgressBar
+      android:id="@+id/progress_bar"
+      android:visibility="gone"
+      android:layout_width="wrap_content"
+      android:layout_height="wrap_content"
+      android:tint="@color/progress_bar_color"
+      android:background="@null"
+      android:layout_centerInParent="true"/>
+</RelativeLayout>
\ No newline at end of file
diff --git a/res/layout/media_output_settings_title.xml b/res/layout/media_output_settings_title.xml
new file mode 100644
index 0000000..8515813
--- /dev/null
+++ b/res/layout/media_output_settings_title.xml
@@ -0,0 +1,47 @@
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
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/decor_title_container"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:focusable="false"
+    android:orientation="vertical"
+    android:padding="@dimen/media_dialog_title_margin">
+
+    <TextView
+        android:id="@+id/decor_title"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_gravity="center_horizontal"
+        android:gravity="center_horizontal"
+        android:textColor="@color/media_dialog_title"
+        android:fontFamily="@string/font_label_large"
+        android:textSize="@dimen/media_dialog_title" />
+
+    <TextView
+        android:id="@+id/decor_subtitle"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_gravity="center_horizontal"
+        android:gravity="center_horizontal"
+        android:layout_marginTop="@dimen/media_dialog_subtitle_margin"
+        android:textColor="@color/media_dialog_subtitle"
+        android:fontFamily="@string/font_body_small"
+        android:textSize="@dimen/media_dialog_subtitle" />
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/radio_control_widget.xml b/res/layout/radio_control_widget.xml
new file mode 100644
index 0000000..b4b1758
--- /dev/null
+++ b/res/layout/radio_control_widget.xml
@@ -0,0 +1,32 @@
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
+    android:id="@+id/radio_widget_container"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:orientation="horizontal"
+    android:duplicateParentState="true"
+    android:gravity="center_vertical">
+
+    <include layout="@layout/core_slice_preference" />
+
+    <RadioButton
+        android:id="@android:id/checkbox"
+        android:layout_height="wrap_content"
+        android:layout_width="wrap_content"
+        android:focusable="false" />
+</LinearLayout>
diff --git a/res/layout/radio_slice_pref.xml b/res/layout/radio_slice_pref.xml
new file mode 100644
index 0000000..eeff247
--- /dev/null
+++ b/res/layout/radio_slice_pref.xml
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
+
+<view class="com.android.systemui.tv.media.settings.RadioSlicePreference$RadioControlWidget"
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    style="@style/RadioWidgetStyle"
+    android:id="@+id/radio_control_widget_view"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"/>
\ No newline at end of file
diff --git a/res/layout/seekbar_control_widget.xml b/res/layout/seekbar_control_widget.xml
new file mode 100644
index 0000000..f3cf4f2
--- /dev/null
+++ b/res/layout/seekbar_control_widget.xml
@@ -0,0 +1,55 @@
+<?xml version="1.0" encoding="utf-8"?>
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:duplicateParentState="true"
+    android:orientation="vertical">
+
+    <LinearLayout
+        android:id="@+id/seekbar_icon_title_container"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:orientation="horizontal"
+        android:gravity="center_vertical"
+        android:layout_marginBottom="@dimen/seekbar_widget_title_margin_bottom"
+        android:duplicateParentState="true">
+
+        <ImageView
+            android:id="@android:id/icon"
+            android:duplicateParentState="true"
+            android:layout_marginEnd="@dimen/control_widget_icon_margin_end"
+            style="@style/ControlWidgetSmallIconStyle" />
+
+        <com.android.systemui.tv.SmoothScalingTextView
+            android:id="@android:id/title"
+            android:duplicateParentState="true"
+            android:layout_width="0dp"
+            android:layout_weight="1"
+            android:layout_height="wrap_content"
+            android:layout_gravity="center_vertical"
+            android:layout_marginEnd="@dimen/media_dialog_item_padding"
+            style="@style/TextAppearance.Panel.ListItem" />
+
+        <com.android.systemui.tv.SmoothScalingTextView
+            android:id="@+id/seekbar_value"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:duplicateParentState="true"
+            style="@style/TextAppearance.Panel.ListItem" />
+    </LinearLayout>
+
+    <SeekBar
+        android:id="@+id/seekbar"
+        android:layout_width="match_parent"
+        android:layout_height="@dimen/seekbar_height"
+        android:focusable="false"
+        android:clickable="false"
+        android:duplicateParentState="true"
+        android:splitTrack="false"
+        android:background="@null"
+        android:paddingStart="0dp"
+        android:paddingEnd="0dp"
+        android:progressDrawable="@drawable/seekbar_style_drawable"
+        android:thumb="@null" />
+
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/seekbar_slice_pref.xml b/res/layout/seekbar_slice_pref.xml
new file mode 100644
index 0000000..a855022
--- /dev/null
+++ b/res/layout/seekbar_slice_pref.xml
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
+
+<view class="com.android.systemui.tv.media.settings.SeekbarSlicePreference$SeekbarControlWidget"
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    style="@style/SeekbarWidgetStyle"
+    android:id="@+id/seekbar_control_widget_view"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"/>
\ No newline at end of file
diff --git a/res/layout/switch_control_widget.xml b/res/layout/switch_control_widget.xml
new file mode 100644
index 0000000..671c6a2
--- /dev/null
+++ b/res/layout/switch_control_widget.xml
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
+
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/switch_icon_title_container"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:gravity="center_vertical"
+    android:duplicateParentState="true"
+    android:orientation="horizontal">
+
+    <include layout="@layout/core_slice_preference" />
+
+    <Switch
+        android:id="@android:id/switch_widget"
+        android:layout_width="@dimen/switch_width"
+        android:layout_height="@dimen/switch_height"
+        android:background="@null"
+        android:clickable="false"
+        android:duplicateParentState="true"
+        android:focusable="false"
+        android:thumb="@drawable/custom_switch_thumb"
+        android:track="@drawable/custom_switch_track" />
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/switch_slice_pref.xml b/res/layout/switch_slice_pref.xml
new file mode 100644
index 0000000..f5c47a4
--- /dev/null
+++ b/res/layout/switch_slice_pref.xml
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
+
+<view class="com.android.systemui.tv.media.settings.SwitchSlicePreference$SwitchControlWidget"
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    style="@style/SwitchWidgetStyle"
+    android:id="@+id/switch_control_widget_view"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"/>
\ No newline at end of file
diff --git a/res/layout/text_slice_preference.xml b/res/layout/text_slice_preference.xml
new file mode 100644
index 0000000..8b9725f
--- /dev/null
+++ b/res/layout/text_slice_preference.xml
@@ -0,0 +1,35 @@
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
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/media_output_dialog_item"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:enabled="false"
+    android:focusable="false"
+    android:clickable="false"
+    android:background="@android:color/transparent"
+    android:layout_marginHorizontal="@dimen/media_dialog_item_margin_horizontal"
+    android:layout_marginVertical="@dimen/media_dialog_item_margin_vertical"
+    android:padding="@dimen/media_dialog_item_padding"
+    android:gravity="center_vertical"
+    android:orientation="horizontal">
+
+    <include layout="@layout/core_slice_preference" />
+
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/tooltip_window.xml b/res/layout/tooltip_window.xml
new file mode 100644
index 0000000..b7df9cc
--- /dev/null
+++ b/res/layout/tooltip_window.xml
@@ -0,0 +1,58 @@
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="@dimen/tooltip_window_width"
+    android:layout_height="wrap_content"
+    android:gravity="center_vertical"
+    android:orientation="horizontal">
+
+    <LinearLayout
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:background="@drawable/tooltip_background"
+        android:orientation="vertical"
+        android:clipChildren="false"
+        android:layout_weight="1"
+        android:padding="@dimen/tooltip_window_padding">
+
+        <ImageView
+            android:id="@+id/tooltip_image"
+            android:layout_width="@dimen/tooltip_image_width"
+            android:layout_height="@dimen/tooltip_image_height"
+            android:layout_marginBottom="6dp"
+            android:importantForAccessibility="no"
+            android:scaleType="fitCenter" />
+
+        <TextView
+            android:id="@+id/tooltip_text"
+            style="@style/ControlWidgetTooltipTextStyle"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content" />
+
+        <TextView
+            android:id="@+id/tooltip_summary"
+            style="@style/ControlWidgetTooltipTextSummaryStyle"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content" />
+    </LinearLayout>
+
+    <ImageView
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:src="@drawable/tooltip_arrow" />
+</LinearLayout>
\ No newline at end of file
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 968c9e0..ad9d775 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Oudio-uitvoer"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Ander toestelle"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Koppel ’n ander toestel"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Kyk jy nog?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Die TV gaan na \'n ander invoer oorskakel. Kies een opsie om te verhoed dat die toestel afskakel."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Ja"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Jou TV het aangedui dat jy na ’n ander inset oorgeskakel het en dat hierdie toestel binnekort sal gaan slaap. Kies ’n opsie om hierdie toestel wakker te hou."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ja (<xliff:g id="SECONDS">%1$d</xliff:g> sek.)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Moenie weer vra nie"</string>
 </resources>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index aa59803..37ee645 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"የኦዲዮ ውጤት"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"ሌሎች መሣሪያዎች"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"ሌላ መሣሪያ ያገናኙ"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"አሁንም እየተመለከቱ ነው?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"ቴሌቪዥኑ ሌላ ግብዓት ሊያሳይ እንደሆነ አሳወቀን። ይህን መሣሪያ ንቁ አድርጎ ለማቆየት አንድ አማራጭን ይምረጡ።"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"አዎ"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ቲቪዎ ወደ የተለየ ግብዓት እንደቀየሩ ያመለክታል እና ይህ መሣሪያ በቅርቡ ወደ እንቅልፍ ይሄዳል። ይህን መሣሪያ ንቁ አድርጎ ለማቆየት አማራጭ ይምረጡ።"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"አዎ (<xliff:g id="SECONDS">%1$d</xliff:g>ሰ)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"ዳግም አትጠይቅ"</string>
 </resources>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 41d0434..6f3beb1 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"إخراج الصوت"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"أجهزة أخرى"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"ربط جهاز آخر"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"هل ما زلت تشاهد المحتوى؟"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"هناك إشعار على التلفزيون بأنّه سيتم عرض محتوى مصدر إدخال آخر. حدِّد خيارًا واحدًا لإبقاء هذا الجهاز نشطًا."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"نعم"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"تم الكشف عن تغيير في أحد مصادر الإدخال على التلفزيون، وسيبدأ وضع السكون في هذا الجهاز قريبًا. عليك تحديد أحد الخيارات لإبقاء هذا الجهاز نشطًا."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"نعم (عدد الثواني: <xliff:g id="SECONDS">%1$d</xliff:g>)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"عدم السؤال مرة أخرى"</string>
 </resources>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index d9cc47f..b49dc15 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"অডিঅ’ আউটপুট"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"অন্য ডিভাইচ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"আন এটা ডিভাইচ সংযোগ কৰক"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"আপুনি এতিয়াও চাই আছে নেকি?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"টিভিটোৱে আমাক জনাইছে যে ই আন এটা ইনপুট দেখুৱাব। এই ডিভাইচটো জাগ্ৰত কৰি ৰাখিবলৈ এটা বিকল্প বাছনি কৰক।"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"হয়"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"আপোনাৰ টিভিয়ে সূচাইছে যে আপুনি অন্য কোনো ইনপুটলৈ সলনি কৰিছে আৰু এই ডিভাইচটো সোনকালেই সুপ্ত হ’ব। এই ডিভাইচটো সক্ৰিয় কৰি ৰাখিবলৈ এটা বিকল্প বাছনি কৰক।"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"হয় (<xliff:g id="SECONDS">%1$d</xliff:g>ছে)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"পুনৰ নুসুধিব"</string>
 </resources>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 91d4246..5980fe0 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio çıxışı"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Digər cihazlar"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Başqa cihaz qoşun"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Hələ də izləyirsiniz?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"TV başqa daxiletmə göstərəcəyini bildirdi. Bu cihazı oyaq saxlamaq üçün bir seçim edin."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Bəli"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV fərqli daxiletməyə keçdiyinizi göstərdi və bu cihaz tezliklə yuxu rejiminə keçəcək. Bu cihazı oyaq saxlamaq üçün seçim edin."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Bəli (<xliff:g id="SECONDS">%1$d</xliff:g> san.)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Yenidən soruşmayın"</string>
 </resources>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index f4f0ef3..70daf9a 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio izlaz"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Drugi uređaji"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Poveži drugi uređaj"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Gledate li još uvek?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"TV nas je obavestio da će prikazati drugi ulaz. Izaberite jednu opciju da ovaj uređaj ne bi prešao u stanje mirovanja."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Da"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV je pokazao da ste prešli na drugi ulaz i ovaj uređaj će uskoro preći u stanje mirovanja. Izaberite neku opciju da ovaj uređaj ne bi prešao u stanje mirovanja."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Da (<xliff:g id="SECONDS">%1$d</xliff:g> sek)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Ne pitaj ponovo"</string>
 </resources>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 5e76139..602fb4b 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аўдыявыхад"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Іншыя прылады"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Падключыць іншую прыладу"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Усё яшчэ гледзіце?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Ад тэлевізара атрымана паведамленне, што для паказу відарыса будзе выкарыстоўвацца сігнал з іншага ўваходу. Выберыце адзін з варыянтаў, каб прылада не перайшла ў рэжым сну."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Так"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Тэлевізар паказвае, што вы пераключыліся на іншую крыніцу ўваходу і гэта прылада хутка пяройдзе ў рэжым сну. Каб прылада не перайшла ў рэжым сну, выберыце патрэбны варыянт."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Так (<xliff:g id="SECONDS">%1$d</xliff:g> с)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Больш не пытацца"</string>
 </resources>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index fc07f7d..c323034 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аудиоизход"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Други устройства"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Свързване на друго устройство"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Още ли гледате?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Телевизорът ни съобщи, че ще показва изображение от друг вход. Изберете една опция, за да остане устройството активно."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Да"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Телевизорът ви сигнализира, че сте превключили към друг вход и това устройство скоро ще премине в спящ режим. Изберете опция, за да остане устройството активно."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Да (<xliff:g id="SECONDS">%1$d</xliff:g> сек)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Без повторно питане"</string>
 </resources>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index c22e45f..4eaaea4 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"অডিও আউটপুট"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"অন্যান্য ডিভাইস"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"আরেকটি ডিভাইস কানেক্ট করুন"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"আপনি কি এখনও দেখছেন?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"এই টিভি অন্য কোনও ইনপুট দেখাবে। এই ডিভাইস চালু রাখার জন্য একটি বিকল্প বেছে নিন।"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"হ্যাঁ"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"আপনার টিভি থেকে জানা যায় যে আপনি অন্য কোনও ইনপুটে পরিবর্তন করেছেন এবং এই ডিভাইসটি শীঘ্রই স্লিপ মোড চলে যাবে। এই ডিভাইস চালু রাখার জন্য কোনও বিকল্প বেছে নিন।"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"হ্যাঁ (<xliff:g id="SECONDS">%1$d</xliff:g>সেকেন্ড)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"আর দেখতে চাই না"</string>
 </resources>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 7d37b6f..62bacab 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Izlaz zvuka"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Drugi uređaji"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Povežite drugi uređaj"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Gledate li još uvijek?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"TV nam je rekao da će prikazivati drugi ulaz. Odaberite jednu opciju da uređaj ostane aktivan."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Da"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV je pokazao da ste prebacili na drugi ulaz i uređaj će uskoro preći u mirovanje. Odaberite opciju da uređaj ostane aktivan."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Da (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Ne pitaj ponovo"</string>
 </resources>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index fd2f0c2..e620411 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Sortida d\'àudio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Altres dispositius"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Connecta un altre dispositiu"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Encara mires el contingut?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"El televisor indica que es mostrarà una altra entrada. Selecciona una opció per mantenir aquest dispositiu activat."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Sí"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"El televisor ha indicat que has canviat a una altra entrada i aquest dispositiu aviat entrarà en mode de repòs. Selecciona una opció per mantenir aquest dispositiu activat."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Sí (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"No m\'ho tornis a preguntar"</string>
 </resources>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index 3e74c17..c0c7acc 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Zvukový výstup"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Ostatní zařízení"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Připojte další zařízení"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ještě jste tady?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Televize nám sdělila, že zobrazí jiný vstup. Vyberte jednu z možností, aby toto zařízení nepřešlo do režimu spánku."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Ano"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Vaše televize zaznamenala, že jste přepnuli na jiný vstup, a toto zařízení brzy přejde do režimu spánku. Vyberte jednu z možností, aby toto zařízení nepřešlo do režimu spánku."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ano (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Příště se neptat"</string>
 </resources>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index bf5c6de..c9b49f0 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Lydudgang"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Andre enheder"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Forbind en anden enhed"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ser du stadig med?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Fjernsynet vil gerne vise en anden indgangskilde. Vælg én mulighed for at holde enheden aktiv."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Ja"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Dit fjernsyn har angivet, at du har skiftet til en anden indgang, og denne enhed går snart i dvale. Vælg en mulighed for at holde enheden aktiv."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ja (<xliff:g id="SECONDS">%1$d</xliff:g> sek.)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Spørg ikke igen"</string>
 </resources>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index e8e2291..d2b12e1 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audioausgabe"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Andere Geräte"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Anderes Gerät verbinden"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Bist du noch da?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Der Fernseher ist dabei, einen anderen Eingang anzuzeigen. Wähle eine Option aus, damit dieses Gerät aktiviert bleibt."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Ja"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Dein Fernseher hat signalisiert, dass du einen anderen Eingang ausgewählt hast. Daher wechselt dieses Gerät bald in den Ruhemodus. Wähle eine Option aus, damit dieses Gerät aktiv bleibt."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ja (<xliff:g id="SECONDS">%1$d</xliff:g> Sek.)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Nicht mehr fragen"</string>
 </resources>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index b891c31..f90491b 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Έξοδος ήχου"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Άλλες συσκευές"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Σύνδεση σε άλλη συσκευή"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Παρακολουθείτε ακόμα;"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Η τηλεόραση ενημέρωσε ότι θα προβάλλει κάποια άλλη πηγή. Ορίστε μία επιλογή για να παραμείνει αυτή η συσκευή σε κανονική κατάσταση λειτουργίας."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Ναι"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Η τηλεόραση υπέδειξε ότι κάνατε εναλλαγή σε διαφορετική είσοδο και αυτή η συσκευή θα μεταβεί σύντομα σε κατάσταση αδράνειας. Ορίστε μια επιλογή, για να παραμείνει αυτή η συσκευή σε κανονική κατάσταση λειτουργίας."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ναι (<xliff:g id="SECONDS">%1$d</xliff:g> δ.)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Να μην ερωτηθώ ξανά"</string>
 </resources>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index da99159..0e64e2c 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio output"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Other devices"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Connect another device"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Are you still watching?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"The TV told us that it will display another input. Select one option to keep this device awake."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Yes"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Your TV indicated that you switched to a different input and this device will go to sleep soon. Select an option to keep this device awake."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yes (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Don\'t ask again"</string>
 </resources>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index e33e151..49cae17 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -33,8 +33,11 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio output"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Other devices"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Connect another device"</string>
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Built-in speaker + S/PDIF"</string>
+    <string name="audio_device_tooltip_right" msgid="8410621031774996322">"Press "<annotation icon="dpad_icon">"DPAD_RIGHT"</annotation>" for audio device settings"</string>
+    <string name="audio_device_tooltip_left" msgid="9062689648623861935">"Press "<annotation icon="dpad_icon">"DPAD_LEFT"</annotation>" for audio device settings"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Are you still watching?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"The TV told us it will display another input. Select one option to keep this device awake."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Yes"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Your TV indicated that you switched to a different input and this device will go to sleep soon. Select an option to keep this device awake."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yes (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Don’t ask again"</string>
 </resources>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index da99159..0e64e2c 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio output"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Other devices"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Connect another device"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Are you still watching?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"The TV told us that it will display another input. Select one option to keep this device awake."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Yes"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Your TV indicated that you switched to a different input and this device will go to sleep soon. Select an option to keep this device awake."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yes (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Don\'t ask again"</string>
 </resources>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index da99159..0e64e2c 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio output"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Other devices"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Connect another device"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Are you still watching?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"The TV told us that it will display another input. Select one option to keep this device awake."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Yes"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Your TV indicated that you switched to a different input and this device will go to sleep soon. Select an option to keep this device awake."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yes (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Don\'t ask again"</string>
 </resources>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index c60fea6..6db9ef8 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -33,8 +33,11 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Salida de audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Otros dispositivos"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Conectar otro dispositivo"</string>
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Bocina integrada + S/PDIF"</string>
+    <string name="audio_device_tooltip_right" msgid="8410621031774996322">"Presiona "<annotation icon="dpad_icon">"DPAD_RIGHT"</annotation>" para acceder a configuración"</string>
+    <string name="audio_device_tooltip_left" msgid="9062689648623861935">"Presiona "<annotation icon="dpad_icon">"DPAD_LEFT"</annotation>" para acceder a configuración"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"¿Sigues mirando?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"La TV nos indicó que mostrará otra entrada. Selecciona una opción para mantener activo este dispositivo."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Sí"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Tu TV indicó que cambiaste a una entrada diferente y el dispositivo se pondrá en suspensión pronto. Selecciona una opción para mantenerlo activo."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Sí (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"No volver a preguntar"</string>
 </resources>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 626c299..24388c8 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Salida de audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Otros dispositivos"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Conecta otro dispositivo"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"¿Sigues ahí?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"La TV indica que se mostrará otra entrada. Selecciona una opción para mantener este dispositivo activo."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Sí"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Tu televisión ha indicado que has cambiado a otra entrada y que este dispositivo entrará en suspensión pronto. Selecciona una opción para mantener este dispositivo activo."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Sí (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"No volver a preguntar"</string>
 </resources>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 4321550..5d569e1 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Heliväljund"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Muud seadmed"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Ühendage teine seade"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Kas vaatate veel?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Teler hakkab kuvama muud sisendit. Tehke valik, et hoida see seade ärkvel."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Jah"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Teie teleri järgi olete aktiveerinud teise sisendi ja see seade lülitub peagi unerežiimi. Tehke valik, et hoida see seade ärkvel."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Jah (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Ära enam küsi"</string>
 </resources>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 4d95907..34ceb9c 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio-irteera"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Beste gailu batzuk"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Konektatu beste gailu bat"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Hor jarraitzen duzu?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Beste sarrera bat bistaratuko da telebistan. Hautatu aukera bat gailua aktibo mantentzeko."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Bai"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Beste sarrera-iturburu batera aldatu zarela adierazi du telebistak, eta gailu hau inaktibo ezarriko da laster. Hautatu aukera bat gailua aktibo mantentzeko."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Bai (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Ez galdetu berriro"</string>
 </resources>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 017cd1f..274417f 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"خروجی صوتی"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"دستگاه‌های دیگر"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"اتصال دستگاهی دیگر"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"هنوز درحال تماشا هستید؟"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"تلویزیون به ما گفت ورودی دیگری را نشان خواهد داد. برای بیدار نگه داشتن این دستگاه، یکی از گزینه‌ها را انتخاب کنید."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"بله"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"تلویزیون شما نشان می‌دهد که به ورودی دیگری رفته‌اید و این دستگاه به‌زودی به حالت خواب می‌رود. برای بیدار نگه داشتن این دستگاه، یکی از گزینه‌ها را انتخاب کنید."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"بله (<xliff:g id="SECONDS">%1$d</xliff:g> ثانیه)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"دوباره سؤال نشود"</string>
 </resources>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 74c8f3b..83ad509 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audion toistotapa"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Muut laitteet"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Yhdistä toinen laite"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Katseletko tätä vielä?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"TV ilmoitti, että se näyttää toisen tulon. Valitse yksi vaihtoehto, niin laite pysyy aktivoituna."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Kyllä"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV ilmoitti, että olet vaihtanut toiseen toistotapaan, ja laite siirtyy pian lepotilaan. Valitse yksi vaihtoehto, niin laite pysyy aktiivisena."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Kyllä (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Älä kysy uudestaan"</string>
 </resources>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index faa9fb4..52cb5f3 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Sortie audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Autres appareils"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Connecter un autre appareil"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Êtes-vous toujours là?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Le téléviseur nous a avisés qu\'il allait afficher le contenu d\'une autre entrée. Sélectionnez une option pour maintenir cet appareil allumé."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Oui"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Votre téléviseur a indiqué que vous êtes passé à une autre entrée et cet appareil va bientôt se mettre en veille. Sélectionnez une option pour maintenir cet appareil allumé."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Oui (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Ne plus me demander"</string>
 </resources>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index 8366a7e..a539f6c 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Sortie audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Autres appareils"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Associer un autre appareil"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Êtes-vous toujours en train de regarder ?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"La TV nous a indiqué qu\'elle allait afficher une autre entrée. Sélectionnez une option pour que cet appareil reste allumé."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Oui"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Votre téléviseur a indiqué que vous aviez changé d\'entrée et que cet appareil allait bientôt se mettre en veille. Sélectionnez une option pour que cet appareil reste allumé."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Oui (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Ne plus me demander"</string>
 </resources>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 33a272f..6fdaaa0 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Saída de audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Outros dispositivos"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Conectar outro dispositivo"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Segues aí?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"A televisión indica que se mostrará outra entrada. Escolle unha opción para manter este dispositivo activo."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Si"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"A televisión indicou que cambiaches a unha entrada diferente e que este dispositivo entrará pronto en modo de suspensión. Escolle unha opción para mantelo activo."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Si (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Non preguntar de novo"</string>
 </resources>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 77639c1..d3be7ed 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ઑડિયો આઉટપુટ"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"અન્ય ડિવાઇસ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"અન્ય ડિવાઇસ કનેક્ટ કરો"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"શું તમે હજી પણ જોઈ રહ્યાં છો?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"ટીવીએ અમને જણાવ્યું કે તે અન્ય ઇનપુટ બતાવશે. આ ડિવાઇસ સક્રિય રાખવા માટે, કોઈ વિકલ્પ પસંદ કરો."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"હા"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"તમે કોઈ અલગ ઇનપુટ પર સ્વિચ થયા હોવાનું તમારા ટીવી દ્વારા સૂચવવામાં આવ્યું છે અને ટૂંક સમયમાં આ ડિવાઇસ નિષ્ક્રિય થઈ જશે. આ ડિવાઇસ સક્રિય રાખવા માટે, કોઈ વિકલ્પ પસંદ કરો."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"હા (<xliff:g id="SECONDS">%1$d</xliff:g> સેકન્ડ)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"ફરીથી પૂછશો નહીં"</string>
 </resources>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index c8438af..7d7e66a 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ऑडियो आउटपुट"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"दूसरे डिवाइस"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"दूसरा डिवाइस कनेक्ट करें"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"क्या अब भी टीवी देखना जारी रखना है?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"टीवी पर कोई दूसरा इनपुट दिखाया जाएगा. इस डिवाइस को चालू रखने के लिए कोई एक विकल्प चुनें."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"हां"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"आपके टीवी से पता चलता है कि आपने किसी दूसरे इनपुट पर स्विच किया है और यह डिवाइस जल्द ही स्लीप मोड में चला जाएगा. इस डिवाइस की स्क्रीन को चालू रखने के लिए कोई विकल्प चुनें."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"हां (<xliff:g id="SECONDS">%1$d</xliff:g>से°)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"दोबारा न पूछें"</string>
 </resources>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 8237ae4..64e8d7e 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audioizlaz"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Ostali uređaji"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Povezivanje s drugim uređajem"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Još uvijek gledate?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"TV nam je prenio da će prikazivati putem drugog ulaza. Odaberite opciju da bi ovaj uređaj ostao u aktivnom stanju."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Da"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV pokazuje da ste prešli na drugi ulazni signal i ovaj će se uređaj uskoro isključiti. Odaberite opciju da bi ovaj uređaj ostao u aktivnom stanju."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Da (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Više me ne pitaj"</string>
 </resources>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index 4da8942..e8e0a26 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Hangkimenet"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Egyéb eszközök"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Másik eszköz csatlakoztatása"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Nézi még?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"A tévé tájékoztatott arról, hogy másik bemenetet jelenít meg. Válasszon a lehetőségek közül az eszköz ébren tartásához."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Igen"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"A tévé jelezte, hogy Ön másik bemenetre váltott, ezért ez az eszköz hamarosan alvó üzemmódba lép. Válassza ki valamelyik lehetőséget az eszköz ébren tartásához."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Igen (<xliff:g id="SECONDS">%1$d</xliff:g> mp)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Ne jelenjen meg többé"</string>
 </resources>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 74276c8..a1185a3 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Աուդիո ելք"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Այլ սարքեր"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Միացրեք մեկ այլ սարք"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Դուք դեռ դիտո՞ւմ եք։"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Հեռուստացույցի հաղորդագրության մեջ ասվում է, որ այլ մուտք է ցուցադրվելու։ Ընտրեք տարբերակ՝ այս սարքն արթուն պահելու համար։"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Այո"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Ձեր հեռուստացույցը հատկորոշել է, որ դուք փոխել եք մուտքը, և այս սարքը շուտով կանցնի քնի ռեժիմին։ Ընտրեք տարբերակ՝ այս սարքն արթուն պահելու համար։"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Այո (<xliff:g id="SECONDS">%1$d</xliff:g> վ)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Այլևս չհարցնել"</string>
 </resources>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 9381778..03f980f 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Output audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Perangkat lain"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Hubungkan perangkat lain"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Apakah Anda masih menonton?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"TV memberi tahu bahwa TV akan menampilkan input lainnya. Pilih salah satu opsi agar perangkat ini tetap aktif."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Ya"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV Anda menunjukkan bahwa Anda beralih ke input lain dan perangkat ini akan segera masuk ke mode tidur. Pilih salah satu opsi agar perangkat ini tetap aktif."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ya (<xliff:g id="SECONDS">%1$d</xliff:g> dtk)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Jangan tanya lagi"</string>
 </resources>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 6373e50..61f9b6c 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Hljóðúttak"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Önnur tæki"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Tengja annað tæki"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ertu að horfa?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Sjónvarpið sagði okkur að það muni sýna annað inntak. Veldu einn kost til að halda þessu tæki vakandi."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Já"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Sjónvarpið þitt gaf til kynna að þú hefðir skipt yfir í annað inntak og þetta tæki skiptir brátt yfir í svefnstillingu. Veldu kost til að halda þessu tæki vakandi."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Já (<xliff:g id="SECONDS">%1$d</xliff:g> sek.)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Ekki spyrja aftur"</string>
 </resources>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 3b20acf..8090cbe 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Uscita audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Altri dispositivi"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Connetti un altro dispositivo"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Stai ancora guardando?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"La TV ha indicato che mostrerà un altro ingresso. Seleziona un\'opzione per mantenere attivo questo dispositivo."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Sì"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"La TV ha indicato che è stato attivato un ingresso diverso e che questo dispositivo andrà in modalità di riposo a breve. Seleziona un\'opzione per mantenere attivo questo dispositivo."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Sì (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Non chiedermelo più"</string>
 </resources>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index e645884..292c338 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"פלט אודיו"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"מכשירים אחרים"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"חיבור של מכשיר אחר"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"רוצה להמשיך לצפות?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"נשלחה הודעה מהטלוויזיה שהתוכן יוצג במכשיר אחר. עליך לבחור אחת מהאפשרויות כדי שהמכשיר יישאר פעיל."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"כן"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"הטלוויזיה זיהתה שעברת לקלט ממקור אחר ובקרוב המכשיר הזה יעבור למצב שינה. כדי שהמכשיר יישאר פעיל, עליך לבחור אחת מהאפשרויות."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"כן (<xliff:g id="SECONDS">%1$d</xliff:g> שנ\')"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"לא לשאול שוב"</string>
 </resources>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 59aba3d..32d2ed3 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -33,8 +33,11 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"音声出力"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"他のデバイス"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"別のデバイスに接続"</string>
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"内蔵スピーカー + S/PDIF"</string>
+    <string name="audio_device_tooltip_right" msgid="8410621031774996322">"オーディオ機器の設定に移動するには "<annotation icon="dpad_icon">"DPAD_RIGHT"</annotation>" を押します"</string>
+    <string name="audio_device_tooltip_left" msgid="9062689648623861935">"オーディオ機器の設定に移動するには "<annotation icon="dpad_icon">"DPAD_LEFT"</annotation>" を押します"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"まだ視聴中ですか？"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"このテレビで別の入力が表示されることになります。このデバイスの電源を入れたままにするためのオプションを 1 つ選択してください。"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"はい"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"テレビで別の入力に切り替えたため、このデバイスはまもなくスリープ状態になります。このデバイスの電源を入れたままにするためのオプションを 1 つ選択してください。"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"はい（<xliff:g id="SECONDS">%1$d</xliff:g> 秒）"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"次回から表示しない"</string>
 </resources>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index fddb1f2..e2d264d 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"გამომავალი აუდიო"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"სხვა მოწყობილობები"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"სხვა მოწყობილობის დაკავშირება"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"კიდევ უყურებთ?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"ტელევიზორი აჩვენებს სხვა შემავალ სიგნალს. აირჩიეთ ერთი ვარიანტი, რომ მოწყობილობა არ გაითიშოს."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"დიახ"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"თქვენმა ტელევიზორმა მიუთითა, რომ გადაერთეთ სხვა შემავალ სიგნალზე და ეს მოწყობილობა მალე ძილის რეჟიმში გადავა. აირჩიეთ ვარიანტი, რომ მოწყობილობა არ გაითიშოს."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"დიახ (<xliff:g id="SECONDS">%1$d</xliff:g> წამი)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"აღარ მკითხო"</string>
 </resources>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 17ba09f..9cc75e4 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аудио шығысы"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Басқа құрылғылар"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Басқа құрылғыны қосу"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Әлі көріп отырсыз ба?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Теледидар басқа кірісті көрсететінін айтты. Бұл құрылғы өшіп қалмауы үшін, бір опцияны таңдаңыз."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Иә"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Теледидарыңыз басқа кіріске ауысқаныңызды және бұл құрылғы жақын арада ұйқы режиміне өтетінін анықтады. Бұл құрылғы өшіп қалмауы үшін, тиісті опцияны таңдаңыз."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Иә (<xliff:g id="SECONDS">%1$d</xliff:g> сек)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Қайта сұралмасын"</string>
 </resources>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index 06d27df..e967c68 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ធាតុចេញសំឡេង"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"ឧបករណ៍ផ្សេងទៀត"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"ភ្ជាប់ឧបករណ៍ផ្សេងទៀត"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"តើអ្នកកំពុងនៅមើលដែរឬទេ?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"ទូរទស្សន៍បានប្រាប់យើងថានឹងបង្ហាញឧបករណ៍បញ្ចូលមួយទៀត។ ជ្រើសរើសជម្រើសមួយ ដើម្បីរក្សាឧបករណ៍នេះឱ្យនៅបើកចោល។"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"បាទ/ចាស"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ទូរទស្សន៍របស់អ្នកបានបង្ហាញថាអ្នកបានប្ដូរទៅឧបករណ៍​បញ្ចូលផ្សេង ហើយឧបករណ៍នេះនឹងប្ដូរទៅមុខងារដេកក្នុងពេលឆាប់ៗនេះ។ ជ្រើសរើសជម្រើសមួយ ដើម្បីរក្សាឧបករណ៍នេះឱ្យនៅបើកចោល។"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"បាទ/ចាស (<xliff:g id="SECONDS">%1$d</xliff:g> វិនាទី)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"កុំ​សួរ​ម្ដងទៀត"</string>
 </resources>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 10934b2..8fe27a2 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ಆಡಿಯೋ ಔಟ್‌ಪುಟ್"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"ಇತರ ಸಾಧನಗಳು"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"ಮತ್ತೊಂದು ಸಾಧನವನ್ನು ಕನೆಕ್ಟ್ ಮಾಡಿ"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"ನೀವು ಇನ್ನೂ ವೀಕ್ಷಿಸುತ್ತಿದ್ದೀರಾ?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"ಮತ್ತೊಂದು ಇನ್‌ಪುಟ್ ಅನ್ನು ಪ್ರದರ್ಶಿಸುತ್ತದೆ ಎಂದು ಟಿವಿ ನಮಗೆ ಹೇಳಿದೆ. ಈ ಸಾಧನವನ್ನು ಎಚ್ಚರವಾಗಿರಿಸಲು ಒಂದು ಆಯ್ಕೆಯನ್ನು ಆರಿಸಿ."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"ಹೌದು"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ನೀವು ಬೇರೆ ಇನ್‌ಪುಟ್‌ಗೆ ಬದಲಾಯಿಸಿದ್ದೀರಿ ಮತ್ತು ಈ ಸಾಧನವು ಶೀಘ್ರದಲ್ಲೇ ನಿದ್ರಿಸಲಿದೆ ಎಂದು ನಿಮ್ಮ ಟಿವಿ ಸೂಚಿಸುತ್ತದೆ. ಈ ಸಾಧನವನ್ನು ಎಚ್ಚರವಾಗಿರಿಸಲು ಒಂದು ಆಯ್ಕೆಯನ್ನು ಆಯ್ಕೆಮಾಡಿ."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ಹೌದು (<xliff:g id="SECONDS">%1$d</xliff:g>ಗಳು)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"ಪುನಃ ಕೇಳಬೇಡ"</string>
 </resources>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index f559b38..6d0da53 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"오디오 출력"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"다른 기기"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"다른 기기 연결"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"아직 시청하고 계신가요?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"TV에서 다른 입력을 표시하려고 합니다. 하나를 선택하여 이 기기를 켜진 상태로 유지하세요."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"예"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV에서 다른 입력으로 전환되었다고 표시되었으며 이 기기는 곧 절전 모드로 전환될 예정입니다. 옵션을 선택하여 이 기기를 켜진 상태로 유지하세요."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"예(<xliff:g id="SECONDS">%1$d</xliff:g>초)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"다시 묻지 않음"</string>
 </resources>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index bef2251..2dadbb1 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аудио түзмөк"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Башка түзмөктөр"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Башка түзмөктү туташтыруу"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Көрүп жатасызбы?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Сыналгыдагы билдирүүдө башка киргизүү булагы көрсөтүлөрү айтылды. Бул түзмөктүн экраны өчүп калбашы үчүн, бир параметрди тандаңыз."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Ооба"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Сыналгыңыз башка киргизүү булагына которулганыңызды жана бул түзмөк жакында уйку режимине өтөрүн көрсөттү. Бул түзмөктүн экраны өчүп калбашы үчүн, параметр тандаңыз."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ооба (<xliff:g id="SECONDS">%1$d</xliff:g> сек.)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Экинчи суралбасын"</string>
 </resources>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index 279e25d..30468dc 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ເອົ້າພຸດສຽງ"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"ອຸປະກອນອື່ນໆ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"ເຊື່ອມຕໍ່ອຸປະກອນອື່ນ"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"ທ່ານຍັງຄົງເບິ່ງຢູ່ບໍ?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"ໂທລະທັດແຈ້ງພວກເຮົາວ່າຈະສະແດງອິນພຸດອື່ນ. ກະລຸນາເລືອກ 1 ຕົວເລືອກເພື່ອເປີດອຸປະກອນນີ້ປະໄວ້."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"ແມ່ນ"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ໂທລະທັດຂອງທ່ານລະບຸວ່າທ່ານໄດ້ສະຫຼັບໄປໃຊ້ອິນພຸດອື່ນ ແລະ ອຸປະກອນນີ້ກຳລັງຈະເຂົ້າສູ່ໂໝດນອນໃນໄວໆນີ້. ກະລຸນາເລືອກຕົວເລືອກໃດໜຶ່ງເພື່ອເປີດອຸປະກອນນີ້ປະໄວ້."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ແມ່ນ (<xliff:g id="SECONDS">%1$d</xliff:g> ວິ)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"ບໍ່ຕ້ອງຖາມອີກ"</string>
 </resources>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index 067e022..a64f108 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -33,8 +33,11 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Garso išvestis"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Kiti įrenginiai"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Prijunkite kitą įrenginį"</string>
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Įtaisytas garsiakalbis + S/PDIF"</string>
+    <string name="audio_device_tooltip_right" msgid="8410621031774996322">"Pasp. "<annotation icon="dpad_icon">"DPAD_RIGHT"</annotation>", kad būtų rodomi garso įr. nust."</string>
+    <string name="audio_device_tooltip_left" msgid="9062689648623861935">"Pasp. "<annotation icon="dpad_icon">"DPAD_LEFT"</annotation>", kad pasiekt. garso įreng. nust."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ar tebežiūrite?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Televizorius nurodė, kad rodys kitą įvestį. Pasirinkite vieną parinktį, kad šis įrenginys išliktų aktyvus."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Taip"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Televizorius nurodė, kad perjungėte į kitą įvestį, ir šis įrenginys netrukus bus išjungtas. Pasirinkite parinktį, kad šis įrenginys išliktų aktyvus."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Taip (<xliff:g id="SECONDS">%1$d</xliff:g> sek.)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Daugiau neklausti"</string>
 </resources>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index ad5cb75..be38f50 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio izvade"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Citas ierīces"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Pievienot citu ierīci"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Vai jūs joprojām skatāties?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Televizorā tika parādīts paziņojums, ka tiks izmantots cita ieejas avota signāls. Atlasiet vienu opciju, lai neļautu šai ierīcei pāriet miega režīmā."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Jā"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Jūsu televizors norādīja, ka pārslēdzāties uz citu ievades avotu un šī ierīce drīz pāries miega režīmā. Atlasiet opciju, lai neļautu šai ierīcei pāriet miega režīmā."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Jā (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Vairs nejautāt"</string>
 </resources>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 8724829..48dba92 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Излез за аудио"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Други уреди"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Поврзете друг уред"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Дали сѐ уште гледате?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Телевизорот ни кажа дека ќе прикаже друг влез. Изберете една опција за да го држи уредов буден."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Да"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Вашиот телевизор покажа дека сте се префрлиле на друг влез и дека уредов наскоро ќе влезе во „Режим на мирување“. Изберете една опција за да го држи уредов буден."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Да (<xliff:g id="SECONDS">%1$d</xliff:g> сек.)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Не прашувај повторно"</string>
 </resources>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index bfc0d94..96e4fc4 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ഓഡിയോ ഔട്ട്‌പുട്ട്"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"മറ്റ് ഉപകരണങ്ങൾ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"മറ്റൊരു ഉപകരണം കണക്റ്റ് ചെയ്യുക"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"ഇപ്പോഴും കാണുന്നുണ്ടോ?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"ടിവി മറ്റൊരു ഇൻപുട്ട് പ്രദർശിപ്പിക്കുമെന്ന് അറിയിച്ചു. ഈ ഉപകരണം സജീവമാക്കി നിലനിർത്താൻ ഒരു ഓപ്ഷൻ തിരഞ്ഞെടുക്കുക."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"ഉവ്വ്"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"നിങ്ങൾ മറ്റൊരു ഇൻപുട്ടിലേക്ക് മാറിയെന്നും ഉപകരണം ഉടൻ പ്രവർത്തനരഹിതമാക്കുമെന്നും ടിവി സൂചിപ്പിച്ചിരിക്കുന്നു. ഈ ഉപകരണം സജീവമാക്കി നിലനിർത്താൻ ഓപ്ഷൻ തിരഞ്ഞെടുക്കുക."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"അതെ (<xliff:g id="SECONDS">%1$d</xliff:g>)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"വീണ്ടും ആവശ്യപ്പെടരുത്"</string>
 </resources>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 721e406..e43ce00 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аудио гаралт"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Бусад төхөөрөмж"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Өөр төхөөрөмж холбох"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Та үзсээр байна уу?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"ТВ бидэнд өөр оролт үзүүлнэ гэдгээ хэлсэн. Энэ төхөөрөмжийг идэвхтэй байлгахын тулд нэг сонголтыг сонгоно уу."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Тийм"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Таны ТВ таныг өөр оролт руу сэлгэсэн болохыг илэрхийлсэн ба энэ төхөөрөмж удахгүй идэвхгүй болно. Энэ төхөөрөмжийг идэвхтэй байлгахын тулд нэг сонголтыг сонгоно уу."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Тийм (<xliff:g id="SECONDS">%1$d</xliff:g> сек)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Дахиж бүү асуу"</string>
 </resources>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 205f6a5..6a86991 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ऑडिओ आउटपुट"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"इतर डिव्हाइस"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"दुसरे डिव्हाझस कनेक्ट करा"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"तुम्ही अजूनही पाहत आहात का?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"टीव्हीने आम्हाला सांगितले की तो दुसरे इनपुट प्रदर्शित करेल. हे डिव्हाइस सुरू ठेवण्यासाठी एक पर्याय निवडा."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"होय"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"तुमच्या टीव्हीने सूचित केले आहे की तुम्ही वेगळ्या इनपुटवर स्विच केले आहे आणि हे डिव्हाइस लवकरच निष्क्रिय होईल. हे डिव्हाइस सुरू ठेवण्यासाठी पर्याय निवडा."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"होय (<xliff:g id="SECONDS">%1$d</xliff:g>से)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"पुन्हा विचारू नका"</string>
 </resources>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 19051be..1e5fb2e 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Output audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Peranti lain"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Sambungkan peranti lain"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Adakah anda masih menonton?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"TV memberitahu kami bahawa TV akan memaparkan input lain. Pilih satu pilihan untuk memastikan peranti berjaga."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Ya"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV anda menunjukkan bahawa anda telah beralih kepada input yang berbeza dan peranti ini akan tidur tidak lama lagi. Pilih satu pilihan untuk memastikan peranti ini berjaga."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ya (<xliff:g id="SECONDS">%1$d</xliff:g>)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Jangan tanya lagi"</string>
 </resources>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index d3d5aa8..a2b766a 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"အသံထွက်မည့် ကိရိယာ"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"အခြားစက်များ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"အခြားစက်နှင့် ချိတ်ဆက်ခြင်း"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"ကြည့်နေသေးသလား။"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"TV သည် အဝင်ပေါက်နောက်တစ်ခုကို ပြမည်ဟု ပြောထားသည်။ ဤစက်ကို ဖွင့်ထားရန် နည်းလမ်းတစ်ခု ရွေးပါ။"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Yes"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"အခြားအဝင်ပေါက်ကို ပြောင်းထားသည်ဟု သင့် TV က ညွှန်ပြထားပြီး ဤစက်သည် မကြာမီတွင် ပိတ်သွားပါမည်။ ဤစက်ကို ဖွင့်ထားရန် နည်းလမ်းတစ်ခု ရွေးပါ။"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yes (<xliff:g id="SECONDS">%1$d</xliff:g> စက္ကန့်)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"ထပ်မမေးပါနှင့်"</string>
 </resources>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index 7653150..022c11c 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Lydutdata"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Andre enheter"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Koble til en annen enhet"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ser du fortsatt på?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"TV-en har informert oss om at den kommer til å vise en annen inndataenhet. Velg et alternativ for å holde denne enheten våken."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Ja"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV-en har indikert at du har byttet til en annen inndataenhet, og denne enheten går snart i hvilemodus. Velg et alternativ for å holde denne enheten våken."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ja (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Ikke spør igjen"</string>
 </resources>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index fadfcb5..005932d 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -20,7 +20,7 @@
     <string name="notification_vpn_connected" msgid="3759650739592615548">"VPN कनेक्ट गरिएको छ"</string>
     <string name="notification_vpn_disconnected" msgid="4645099900080931794">"VPN डिस्कनेक्ट गरिएको छ"</string>
     <string name="notification_disclosure_vpn_text" msgid="5776051625744545968">"<xliff:g id="VPN_APP">%1$s</xliff:g> मार्फत"</string>
-    <string name="notification_panel_title" msgid="4172378174173345988">"सूचनाहरू"</string>
+    <string name="notification_panel_title" msgid="4172378174173345988">"नोटिफिकेसनहरू"</string>
     <string name="notification_panel_no_notifications" msgid="7573560690974118175">"कुनै पनि सूचना प्राप्त भएको छैन"</string>
     <string name="mic_recording_announcement" msgid="9199688557748836482">"माइक्रोफोनले रेकर्ड गरिरहेको छ"</string>
     <string name="camera_recording_announcement" msgid="4749050102986152529">"क्यामेराले रेकर्ड गरिरहेको छ"</string>
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"अडियो आउटपुट"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"अन्य डिभाइसहरू"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"अर्को डिभाइस कनेक्ट गर्नुहोस्"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"तपाईं अझै पनि हेरिरहनुभएको छ?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"टिभीले हामीलाई अर्को इनपुट देखाउने कुरा बताएको छ। यो डिभाइसको स्क्रिन अन राख्न एउटा विकल्प चयन गर्नुहोस्।"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"अँ"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"तपाईंको टिभीले तपाईंले अर्को इन्पुट बदल्नुभएको छ र यो डिभाइस चाँडै नै स्लिप मोडमा जाने छ भन्ने कुरा जनाएको छ। यो डिभाइसको स्क्रिन अन राख्न एउटा विकल्प चयन गर्नुहोस्।"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"अँ (<xliff:g id="SECONDS">%1$d</xliff:g> सेकेन्ड)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"फेरि नसोध्नुहोस्"</string>
 </resources>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index 677413c..8066ac9 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio-uitvoer"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Andere apparaten"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Nog een apparaat koppelen"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ben je nog aan het kijken?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"De tv geeft aan dat er een andere invoer wordt weergegeven. Selecteer een optie om dit apparaat actief te houden."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Ja"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Je tv heeft aangegeven dat je bent overgeschakeld naar een andere ingang en dat dit apparaat binnenkort in de slaapstand gaat. Selecteer een optie om dit apparaat actief te houden."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ja (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Niet meer vragen"</string>
 </resources>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 57a4706..e682687 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ଅଡିଓ ଆଉଟପୁଟ"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"ଅନ୍ୟ ଡିଭାଇସ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"ଅନ୍ୟ ଏକ ଡିଭାଇସ କନେକ୍ଟ କରନ୍ତୁ"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"ଆପଣ ଏବେ ବି ଦେଖୁଛନ୍ତି?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"ଏହି ଟିଭି ଅନ୍ୟ ଏକ ଇନପୁଟ ଡିସପ୍ଲେ କରିବ ବୋଲି ଆମକୁ କହିଛି। ଏହି ଡିଭାଇସକୁ ସକ୍ରିୟ ରଖିବା ପାଇଁ ଗୋଟିଏ ବିକଳ୍ପକୁ ଚୟନ କରନ୍ତୁ।"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"ହଁ"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ଆପଣ ଏକ ଭିନ୍ନ ଇନପୁଟକୁ ସୁଇଚ କରିଛନ୍ତି ଏବଂ ଏହି ଡିଭାଇସ ଶୀଘ୍ର ବନ୍ଦ ହୋଇଯିବ ବୋଲି ଆପଣଙ୍କ ଟିଭି ସୂଚିତ କରିଛି। ଏହି ଡିଭାଇସକୁ ସକ୍ରିୟ ରଖିବା ପାଇଁ ଏକ ବିକଳ୍ପକୁ ଚୟନ କରନ୍ତୁ।"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ହଁ (<xliff:g id="SECONDS">%1$d</xliff:g> ସେକେଣ୍ଡ)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"ପୁଣି ପଚାର ନାହିଁ"</string>
 </resources>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index ca5d745..53306ed 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ਆਡੀਓ ਆਊਟਪੁੱਟ"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"ਹੋਰ ਡੀਵਾਈਸ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"ਕੋਈ ਹੋਰ ਡੀਵਾਈਸ ਕਨੈਕਟ ਕਰੋ"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"ਕੀ ਤੁਸੀਂ ਹਾਲੇ ਵੀ ਦੇਖ ਰਹੇ ਹੋ?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"ਟੀਵੀ ਨੇ ਦੱਸਿਆ ਕਿ ਇਹ ਕੋਈ ਹੋਰ ਇਨਪੁੱਟ ਦਿਖਾਏਗਾ। ਇਸ ਡੀਵਾਈਸ ਨੂੰ ਕਿਰਿਆਸ਼ੀਲ ਰੱਖਣ ਲਈ ਇੱਕ ਵਿਕਲਪ ਚੁਣੋ।"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"ਹਾਂ"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ਤੁਹਾਡੇ ਟੀਵੀ ਨੇ ਸੰਕੇਤ ਦਿੱਤਾ ਹੈ ਕਿ ਤੁਸੀਂ ਕਿਸੇ ਵੱਖਰੇ ਇਨਪੁੱਟ \'ਤੇ ਸਵਿੱਚ ਕੀਤਾ ਹੈ ਅਤੇ ਇਹ ਡੀਵਾਈਸ ਜਲਦੀ ਹੀ ਸਲੀਪ ਮੋਡ ਵਿੱਚ ਚਲਾ ਜਾਵੇਗਾ। ਇਸ ਡੀਵਾਈਸ ਨੂੰ ਕਿਰਿਆਸ਼ੀਲ ਰੱਖਣ ਲਈ ਇੱਕ ਵਿਕਲਪ ਚੁਣੋ।"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ਹਾਂ (<xliff:g id="SECONDS">%1$d</xliff:g>ਸਕਿੰਟ)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"ਦੁਬਾਰਾ ਨਾ ਪੁੱਛੋ"</string>
 </resources>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 89e2e10..51a4f57 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Wyjście audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Inne urządzenia"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Podłącz inne urządzenie"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Oglądasz jeszcze?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Telewizor poinformował, że będzie wyświetlał obraz z innego wejścia. Wybierz jedną opcję, aby utrzymać aktywność tego urządzenia."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Tak"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Telewizor wskazał, że przełączono na inne wejście i urządzenie wkrótce przejdzie w stan uśpienia. Wybierz opcję, aby utrzymać aktywność tego urządzenia."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Tak (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Nie pytaj ponownie"</string>
 </resources>
diff --git a/res/values-pt-rBR/strings.xml b/res/values-pt-rBR/strings.xml
index fb4f3ac..f0bf513 100644
--- a/res/values-pt-rBR/strings.xml
+++ b/res/values-pt-rBR/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Saída de áudio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Outros dispositivos"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Conectar outro dispositivo"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ainda está assistindo?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"A TV vai mostrar outra entrada. Selecione uma opção para manter o dispositivo ativado."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Sim"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Sua TV indicou que você mudou para uma entrada diferente, e o dispositivo vai entrar no modo de suspensão em breve. Selecione uma opção para manter o dispositivo ativado."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Sim (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Não perguntar de novo"</string>
 </resources>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 72d7092..9b64d2d 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -33,8 +33,11 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Saída de áudio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Outros dispositivos"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Ligue outro dispositivo"</string>
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Altifalante integrado + S/PDIF"</string>
+    <string name="audio_device_tooltip_right" msgid="8410621031774996322">"Prima "<annotation icon="dpad_icon">"DPAD_RIGHT"</annotation>" para definições do dispositivo de áudio"</string>
+    <string name="audio_device_tooltip_left" msgid="9062689648623861935">"Prima "<annotation icon="dpad_icon">"DPAD_LEFT"</annotation>" para definições do dispositivo de áudio"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ainda está a ver?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"A TV disse-nos que iria apresentar outra entrada. Selecione uma opção para manter este dispositivo ativado."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Sim"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"A sua TV indicou que mudou para uma entrada diferente e este dispositivo vai entrar em suspensão em breve. Selecione uma opção para manter este dispositivo ativado."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Sim (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Não perguntar novamente"</string>
 </resources>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index fb4f3ac..f0bf513 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Saída de áudio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Outros dispositivos"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Conectar outro dispositivo"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ainda está assistindo?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"A TV vai mostrar outra entrada. Selecione uma opção para manter o dispositivo ativado."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Sim"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Sua TV indicou que você mudou para uma entrada diferente, e o dispositivo vai entrar no modo de suspensão em breve. Selecione uma opção para manter o dispositivo ativado."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Sim (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Não perguntar de novo"</string>
 </resources>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 23d36ef..ebc7218 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Ieșire audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Alte dispozitive"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Conectează alt dispozitiv"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Încă vizionezi?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Televizorul a anunțat că va afișa altă intrare. Selectează o opțiune pentru a menține dispozitivul activ."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Da"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Televizorul a indicat că ai comutat la altă intrare și dispozitivul va intra în modul de repaus în curând. Selectează o opțiune pentru a menține dispozitivul activ."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Da (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Nu mai întreba"</string>
 </resources>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 8fb92e6..5121074 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аудиовыход"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Другие устройства"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Подключить другое устройство"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Вы всё ещё смотрите?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"В сообщении на телевизоре сказано, что будет транслироваться другой источник сигнала. Выберите один, чтобы устройство не перешло в спящий режим."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Да"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Так как вы переключились на другой вход, это устройство скоро перейдет в спящий режим. Чтобы устройство оставалось активным, выберите нужный вариант."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Да (<xliff:g id="SECONDS">%1$d</xliff:g> сек.)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Больше не спрашивать"</string>
 </resources>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index 857478e..a37da52 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ශ්‍රව්‍ය ප්‍රතිදානය"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"වෙනත් උපාංග"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"වෙනත් උපාංගයක් සම්බන්ධ කරන්න"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"ඔබ තවමත් නරඹනවා ද?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"රූපවාහිනිය අපට පැවසුවේ එය තවත් ආදානයක් පෙන්වන බවයි. මෙම උපාංගය අවදියෙන් තබා ගැනීමට එක් විකල්පයක් තෝරන්න."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"ඔව්"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ඔබ වෙනත් ආදානයකට මාරු වූ බව ඔබේ රූපවාහිනිය පෙන්වා දුන් අතර මෙම උපාංගය ඉක්මනින් නින්දට යනු ඇත. මෙම උපාංගය අවදියෙන් තබා ගැනීමට විකල්පයක් තෝරන්න."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ඔව් (ත<xliff:g id="SECONDS">%1$d</xliff:g>)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"නැවත නොඅසන්න"</string>
 </resources>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index a8fd914..15b7de6 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Zvukový výstup"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Iné zariadenia"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Pripojte ďalšie zariadenie"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Stále pozeráte?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Televízor nás informoval, že bude zobrazovať iný vstup. Vyberte jednu možnosť, aby toto zariadenie neprešlo do režimu spánku."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Áno"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Signál z televízora naznačil, že ste prepli na iný vstup a toto zariadenie sa čoskoro prepne do režimu spánku. Vyberte niektorú možnosť, aby toto zariadenie neprešlo do režimu spánku."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Áno (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Nabudúce sa nepýtať"</string>
 </resources>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index 2d74211..3079231 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Zvočni izhod"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Druge naprave"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Povežite drugo napravo"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ali še vedno gledate?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Televizor je sporočil, da bo prikazal drug vhod. Izberite eno možnost, da se ta naprava ne bo zaklenila."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Da"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Televizor je sporočil, da ste preklopili na drug vhod, in ta naprava bo kmalu preklopila v stanje pripravljenosti. Izberite eno možnost, da ta naprava ostane aktivna."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Da (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Ne vprašaj me več"</string>
 </resources>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index a469b70..3c8515b 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Dalja e audios"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Pajisjet e tjera"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Lidh një pajisje tjetër"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Po vazhdon të shikosh?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Televizori na ka treguar se do të shfaqë një hyrje tjetër. Zgjidh një opsion për ta mbajtur zgjuar këtë pajisje."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Po"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Televizori yt ka treguar se ke kaluar te një hyrje tjetër dhe kjo pajisje do të kalojë së shpejti në gjumë. Zgjidh një opsion për ta mbajtur zgjuar këtë pajisje."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Po (<xliff:g id="SECONDS">%1$d</xliff:g> sek.)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Mos pyet më"</string>
 </resources>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index b6a8d20..0741b26 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аудио излаз"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Други уређаји"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Повежи други уређај"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Гледате ли још увек?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"ТВ нас је обавестио да ће приказати други улаз. Изаберите једну опцију да овај уређај не би прешао у стање мировања."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Да"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ТВ је показао да сте прешли на други улаз и овај уређај ће ускоро прећи у стање мировања. Изаберите неку опцију да овај уређај не би прешао у стање мировања."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Да (<xliff:g id="SECONDS">%1$d</xliff:g> сек)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Не питај поново"</string>
 </resources>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index b1f3607..8bd31dc 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Ljudutgång"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Andra enheter"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Anslut en annan enhet"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Tittar du fortfarande?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Tv:n meddelade att den ska visa data från en annan ingång. Gör ett val så att inte enheten stängs av."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Ja"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Tv:n indikerade att du bytte till en annan ingång och den här enheten går snart i viloläge. Gör ett val så att inte enheten stängs av."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yes (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Fråga inte igen"</string>
 </resources>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index f21bf60..b41ebfc 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Mfumo wa kutoa sauti"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Vifaa vingine"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Unganisha kifaa kingine"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Je, bado unatazama?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"TV imetuambia kuwa itaonyesha kifaa kingine cha kuingiza data. Teua chaguo moja ili kifaa hiki kisizime."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Ndiyo"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV yako imeonyesha kuwa ulitumia kifaa tofauti cha kuingiza data na kifaa hiki kitaingia katika hali tuli hivi karibuni. Teua chaguo ili kifaa hiki kisizime."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ndiyo (Sek <xliff:g id="SECONDS">%1$d</xliff:g>)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Usiniulize tena"</string>
 </resources>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 2106506..3900093 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ஆடியோ அவுட்புட்"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"பிற சாதனங்கள்"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"வேறொரு சாதனத்தை இணையுங்கள்"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"இன்னும் பார்க்கிறீர்களா?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"டிவி வேறொரு இன்புட்டைக் காட்டும் என இதில் தெரிவிக்கப்பட்டுள்ளது. இந்தச் சாதனத்தை இயக்கத்தில் வைத்திருக்க ஒரு விருப்பத்தைத் தேர்வுசெய்யுங்கள்."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"ஆம்"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"நீங்கள் வேறொரு உள்ளீட்டிற்கு மாறிவிட்டீர்கள் என்றும் இந்தச் சாதனம் விரைவில் உறக்கப் பயன்முறைக்குச் செல்லும் என்றும் உங்கள் டிவி குறிப்பிட்டுள்ளது. இந்தச் சாதனத்தை இயக்கத்தில் வைத்திருக்க ஒரு விருப்பத்தைத் தேர்வுசெய்யவும்."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ஆம் (<xliff:g id="SECONDS">%1$d</xliff:g>வி)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"மீண்டும் கேட்காதே"</string>
 </resources>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index b7c3002..2c008c7 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ఆడియో అవుట్‌పుట్"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"ఇతర పరికరాలు"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"మరొక పరికరాన్ని కనెక్ట్ చేయండి"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"మీరు ఇంకా చూస్తున్నారా?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"టీవీ మరొక ఇన్‌పుట్‌ను ప్రదర్శిస్తుందని మాకు చెప్పింది. ఈ పరికరాన్ని యాక్టివ్‌గా ఉంచడానికి ఒక ఆప్షన్‌ను ఎంచుకోండి."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"అవును"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"మీరు వేరొక ఇన్‌పుట్‌కు మారారని మీ TV ఇండికేట్ చేస్తుంది, ఈ పరికరం త్వరలో స్లీప్ మోడ్‌లోకి వెళ్తుంది. ఈ పరికరాన్ని యాక్టివ్‌గా ఉంచడానికి ఒక ఆప్షన్‌ను ఎంచుకోండి."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yes (<xliff:g id="SECONDS">%1$d</xliff:g>సె)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"మళ్లీ అడగవద్దు"</string>
 </resources>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index 54df187..489cc9a 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"เอาต์พุตเสียง"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"อุปกรณ์อื่นๆ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"เชื่อมต่ออุปกรณ์อื่น"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"คุณยังรับชมอยู่ไหม"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"ทีวีแจ้งว่าจะแสดงอินพุตอื่น เลือกตัวเลือกหนึ่งเพื่อเปิดอุปกรณ์นี้ค้างไว้"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"ใช่"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ทีวีแจ้งว่าคุณเปลี่ยนเป็นอินพุตอื่นและอุปกรณ์นี้จะเข้าสู่โหมดสลีปในไม่ช้า เลือกตัวเลือกเพื่อเปิดอุปกรณ์นี้ค้างไว้"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ใช่เลย (<xliff:g id="SECONDS">%1$d</xliff:g> วินาที)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"ไม่ต้องถามอีก"</string>
 </resources>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index fa52aa0..4f01e57 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio output"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Iba pang device"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Magkonekta ng ibang device"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Nanonood ka pa ba?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Ipinakita sa amin ng TV na magpapakita ito ng isa pang input. Pumili ng isang opsyon para panatilihing nakabukas ang device na ito."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Oo"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Tinukoy ng TV mo na lumipat ka sa ibang input at malapit nang mag-sleep ang device na ito. Pumili ng isang opsyon para panatilihing nakabukas ang device na ito."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Oo (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Huwag nang itanong ulit"</string>
 </resources>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 8635fe9..d5b061c 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Ses çıkışı"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Diğer cihazlar"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Başka bir cihaz bağlayın"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Hâlâ izliyor musunuz?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"TV\'niz başka bir girişin gösterileceğini belirtti. Bu cihazın uyanık kalması için bir seçenek belirleyin."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Evet"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV\'niz farklı bir girişe geçtiğinizi bildirdi ve bu cihaz yakında uyku moduna geçecektir. Bu cihazın uyanık kalması için bir seçenek belirleyin."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Evet (<xliff:g id="SECONDS">%1$d</xliff:g> sn.)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Tekrar sorma"</string>
 </resources>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index e11e6bb..5e0a7cb 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аудіовихід"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Інші пристрої"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Підключити інший пристрій"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ви ще дивитеся?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Телевізор скоро почне транслювати сигнал з іншого джерела. Виберіть один із варіантів, щоб цей пристрій не перейшов у режим сну."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Так"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Телевізор повідомив, що ви перемкнулися на інше джерело вхідного сигналу й цей пристрій скоро перейде в режим сну. Виберіть опцію, щоб цей пристрій не переходив у режим сну."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Так (<xliff:g id="SECONDS">%1$d</xliff:g> с)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Не запитувати знову"</string>
 </resources>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index a4e7ed0..7173d02 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"آڈیو کا آؤٹ پُٹ"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"دیگر آلات"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"کسی اور آلے کو منسلک کریں"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"کیا آپ اب تک دیکھ رہے ہیں؟"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"TV نے ہمیں بتایا کہ یہ ایک اور ان پٹ دکھائے گا۔ اس آلے کو بیدار رکھنے کے لیے ایک اختیار منتخب کریں۔"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"ہاں"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"آپ کے TV نے نشاندہی کی ہے کہ آپ نے ایک مختلف ان پٹ پر سوئچ کیا ہے اور یہ آلہ جلد ہی سلیپ موڈ میں چلا جائے گا۔ اس آلے کو بیدار رکھنے کے لیے ایک اختیار منتخب کریں۔"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ہاں (<xliff:g id="SECONDS">%1$d</xliff:g> سیکنڈ)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"دوبارہ نہ پوچھیں"</string>
 </resources>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index b5e5b1a..cfaf89a 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio chiqishi"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Boshqa qurilmalar"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Boshqa qurilmaga ulang"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Tomosha qilyapsizmi?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"Televizor boshqa kirishni koʻrsatishini aytdi. Bu qurilmani hushyor tutish uchun bitta variantni tanlang."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Ha"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Televizoringiz boshqa kirishga oʻtganingizni va bu qurilma tez orada uyquga ketishini koʻrsatdi. Bu qurilmani hushyor tutish uchun bitta variantni tanlang."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ha (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Boshqa soʻralmasin"</string>
 </resources>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index b431ba3..e7da3de 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Đầu ra âm thanh"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Thiết bị khác"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Kết nối thiết bị khác"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Bạn vẫn đang xem?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"TV muốn hiển thị một cổng vào khác. Hãy chọn một cổng vào để duy trì trạng thái bật của thiết bị này."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Đúng vậy"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV của bạn cho biết rằng bạn đã chuyển sang một cổng vào khác và thiết bị này sắp chuyển sang chế độ ngủ. Hãy chọn một cổng vào để thiết bị này tiếp tục ở trạng thái bật."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Được (<xliff:g id="SECONDS">%1$d</xliff:g> giây)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Không hỏi lại"</string>
 </resources>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 307751b..bab3385 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"音频输出"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"其他设备"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"连接另一部设备"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"您仍在观看吗？"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"我们得知这台电视将显示另一输入源的内容。选择一个选项即可使该设备保持唤醒状态。"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"是"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"您的电视显示您已切换到其他输入源，此设备即将进入睡眠模式。选择一个选项即可使该设备保持唤醒状态。"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"是（<xliff:g id="SECONDS">%1$d</xliff:g> 秒）"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"不再询问"</string>
 </resources>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 63d75ed..6155bac 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"音訊輸出"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"其他裝置"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"連接另一部裝置"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"你仍在觀看嗎？"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"電視將會顯示另一個訊號源的內容。請選取其中一個選項以保持此裝置於啟用狀態。"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"是"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"你的電視表示你已切換至其他輸入來源，而此裝置即將進入休眠模式。請選取任何選項，讓此裝置保持啟用狀態。"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"是 (<xliff:g id="SECONDS">%1$d</xliff:g> 秒)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"不要再詢問"</string>
 </resources>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 0b2302c..0b1f0cc 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"音訊輸出裝置"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"其他裝置"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"連結其他裝置"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"你仍在觀賞影視內容嗎？"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"我們得知電視將顯示其他輸入端的畫面。請選取其中一個選項，讓這部裝置保持啟用狀態。"</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"是"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"電視顯示你已切換至其他輸入端，因此這部裝置即將進入休眠模式。如要讓這部裝置保持啟用狀態，請選取其中一個選項。"</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"是 (<xliff:g id="SECONDS">%1$d</xliff:g> 秒)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"不要再詢問"</string>
 </resources>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index a1529f5..870ee26 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -33,8 +33,14 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Okukhishwayo komsindo"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Amanye amadivayisi"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Xhuma enye idivayisi"</string>
+    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
+    <skip />
+    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
+    <skip />
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ingabe usabukele?"</string>
-    <string name="hdmi_cec_on_active_source_lost_description" msgid="3360234213187507600">"I-TV isitshele ukuthi izoveza okunye kokufaka. Khetha okukhethwayo okukodwa ukuze ugcine le divayisi ivukile."</string>
-    <string name="hdmi_cec_on_active_source_lost_ok" msgid="2979087317246080268">"Yebo"</string>
+    <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"I-TV yakho ibonise ukuze ushintshele kokuhlukile kokufaka futhi le divayisi izolala maduzane. Khetha ongakhetha kukho ukuze ugcine le divayisi ivulekile."</string>
+    <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yebo (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"Ungabuzi futhi"</string>
 </resources>
diff --git a/res/values/colors.xml b/res/values/colors.xml
index f484617..19251b7 100644
--- a/res/values/colors.xml
+++ b/res/values/colors.xml
@@ -42,7 +42,7 @@
     <color name="notification_blur_background_color">#a0383838</color>
     <color name="notification_text_color">#FFFFFF</color>
 
-    <color name="media_dialog_bg">#1E232C</color>
+    <color name="media_dialog_bg">#FF1E232C</color>
     <color name="media_dialog_item_bg_focused">#E4F3FF</color>
     <color name="media_dialog_item_bg_unfocused">#0FDFF3FF</color>
     <color name="media_dialog_icon_bg_focused">#004A77</color>
@@ -52,16 +52,44 @@
     <color name="media_dialog_radio_button_focused">#8E918F</color>
     <color name="media_dialog_radio_button_unfocused">#8E918F</color>
     <color name="media_dialog_radio_button_checked">#0842A0</color>
+    <color name="media_dialog_settings_icon_focused">#0842A0</color>
+    <color name="media_dialog_settings_icon_unfocused">#8E918F</color>
 
     <color name="media_dialog_title">#E8EAED</color>
+    <color name="media_dialog_subtitle">#B8E8EAED</color>
     <color name="media_dialog_item_title_focused">#0E0E0F</color>
     <color name="media_dialog_item_title_unfocused">#E8EAED</color>
+    <color name="media_dialog_item_title_disabled">@color/media_dialog_item_subtitle_focused</color>
     <color name="media_dialog_item_subtitle_focused">#6B7887</color>
     <color name="media_dialog_item_subtitle_unfocused">#989CA3</color>
+    <color name="media_dialog_item_subtitle_disabled">@color/media_dialog_item_subtitle_focused</color>
     <color name="media_dialog_low_battery_text">#EE675C</color>
     <color name="media_dialog_divider_line">#E4F3FF</color>
-    <color name="media_dialog_divider_text">#E4F3FF</color>
+    <color name="media_dialog_divider_text">@color/media_dialog_subtitle</color>
     <color name="media_dialog_low_battery_focused">#8C1D18</color>
     <color name="media_dialog_low_battery_unfocused">#C27D7A</color>
 
+    <color name="tv_panel_window_background">@color/media_dialog_bg</color>
+
+    <color name="switch_track_unfocused_color">#FFC2E7FF</color>
+    <color name="switch_track_focused_color">#FF004A77</color>
+    <color name="switch_track_unchecked_color">#FF282A2C</color>
+
+    <color name="switch_track_border_unfocused_unchecked">#33DFF3FF</color>
+    <color name="switch_track_border_unfocused_disabled">#33DFF3FF</color>
+
+    <color name="switch_thumb_unfocused_color">#FF004A77</color>
+    <color name="switch_thumb_focused_color">#FFC2E7FF</color>
+    <color name="switch_thumb_unchecked_color">#FF8E918F</color>
+
+    <color name="switch_info_on">#FF5BB974</color>
+    <color name="switch_info_off">#FFEE675C</color>
+
+    <color name="seekbar_progress_focused_color">#FF004A77</color>
+    <color name="seekbar_progress_unfocused_color">#FFE4F3FF</color>
+    <color name="seekbar_progress_background_focused_color">#FFA8C7FA</color>
+    <color name="seekbar_progress_background_unfocused_color">#FF3D4043</color>
+
+    <color name="progress_bar_color">#E5E5E5</color>
+
 </resources>
diff --git a/res/values/config.xml b/res/values/config.xml
index 2de901d..972a3bb 100644
--- a/res/values/config.xml
+++ b/res/values/config.xml
@@ -42,4 +42,8 @@
 
     <!-- Configuration to set Learn more in device logs as URL link -->
     <bool name="log_access_confirmation_learn_more_as_link">false</bool>
+
+    <!-- Configuration to set whether the builtin speaker audio route also outputs to S/PDIF output,
+    often times optical output -->
+    <bool name="config_audioOutputInternalSpeakerGroupedWithSpdif">false</bool>
 </resources>
diff --git a/res/values/dimens.xml b/res/values/dimens.xml
index 96ee3bc..a8b1adf 100644
--- a/res/values/dimens.xml
+++ b/res/values/dimens.xml
@@ -65,21 +65,25 @@
 
     <dimen name="media_dialog_bg_radius">20dp</dimen>
     <dimen name="media_dialog_item_bg_radius">16dp</dimen>
-    <dimen name="media_dialog_icon_bg_radius">16dp</dimen>
+    <dimen name="media_dialog_item_bg_radius_rounded">100dp</dimen>
 
     <dimen name="media_dialog_width">272dp</dimen>
     <dimen name="media_dialog_margin_vertical">16dp</dimen>
     <dimen name="media_dialog_margin_end">24dp</dimen>
     <dimen name="media_dialog_item_margin_horizontal">12dp</dimen>
+    <dimen name="media_dialog_item_margin_vertical">4dp</dimen>
     <dimen name="media_dialog_title_margin">16dp</dimen>
+    <dimen name="media_dialog_subtitle_margin">4dp</dimen>
 
-    <dimen name="media_dialog_item_spacing">8dp</dimen>
+    <dimen name="media_dialog_item_spacing">6dp</dimen>
     <dimen name="media_dialog_item_padding">12dp</dimen>
     <dimen name="media_dialog_icon_size">16dp</dimen>
     <dimen name="media_dialog_icon_bg_size">32dp</dimen>
+    <dimen name="media_dialog_settings_icon_size">24dp</dimen>
     <dimen name="media_dialog_radio_size">24dp</dimen>
 
     <dimen name="media_dialog_title">14sp</dimen>
+    <dimen name="media_dialog_subtitle">12sp</dimen>
     <dimen name="media_dialog_divider_text">9sp</dimen>
     <dimen name="media_dialog_item_title">12sp</dimen>
     <dimen name="media_dialog_item_subtitle">12sp</dimen>
@@ -89,4 +93,32 @@
     <dimen name="media_output_divider_height">1dp</dimen>
     <dimen name="media_output_divider_margin_vertical">14dp</dimen>
     <dimen name="media_output_text_divider_margin_top">20dp</dimen>
+
+    <!-- Control widget basic -->
+    <dimen name="control_widget_background_corner_radius">16dp</dimen>
+    <dimen name="control_widget_icon_margin_end">6dp</dimen>
+    <dimen name="control_widget_icon_size">32dp</dimen>
+    <dimen name="control_widget_small_icon_size">16dp</dimen>
+    <dimen name="control_widget_icon_padding">2dp</dimen>
+
+    <!-- Switch widget basic -->
+    <dimen name="switch_height">20dp</dimen>
+    <dimen name="switch_width">40dp</dimen>
+
+    <!-- Seekbar widget basic -->
+    <dimen name="seekbar_widget_progress_corner_radius">12dp</dimen>
+    <dimen name="seekbar_widget_track_corner_radius">12dp</dimen>
+    <dimen name="seekbar_widget_title_margin_bottom">6dp</dimen>
+    <dimen name="seekbar_height">10dp</dimen>
+    <dimen name="seekbar_background_stroke_width">5dp</dimen>
+
+    <!-- Tooltip window -->
+    <dimen name="tooltip_window_width">234dp</dimen>
+    <dimen name="tooltip_window_padding">12dp</dimen>
+    <dimen name="tooltip_bg_radius">12dp</dimen>
+    <dimen name="tooltip_image_width">204dp</dimen>
+    <dimen name="tooltip_image_height">115dp</dimen>
+    <dimen name="tooltip_window_vertical_margin">6dp</dimen>
+    <dimen name="tooltip_window_horizontal_margin">4dp</dimen>
+
 </resources>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 52b2cc0..347779f 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -38,10 +38,23 @@
     <string name="media_output_dialog_other_devices">Other devices</string>
     <string name="media_output_dialog_pairing_new">Connect another device</string>
 
+    <!-- TV media output switcher. Subtitle for internal speaker audio output when grouped with
+    S/PDIF [CHAR LIMIT=NONE] -->
+    <string name="media_output_internal_speaker_spdif_subtitle">Built-in speaker + S/PDIF</string>
+
+    <!-- Tooltip text instructing the user to press the DPAD right button (for LTR layout direction)
+    to access the audio device settings [CHAR LIMIT=50] -->
+    <string name="audio_device_tooltip_right">Press <annotation icon="dpad_icon">DPAD_RIGHT</annotation> for audio device settings</string>
+
+    <!-- Tooltip text instructing the user to press the DPAD left button (for RTL layout direction)
+    to access the audio device settings [CHAR LIMIT=50] -->
+    <string name="audio_device_tooltip_left">Press <annotation icon="dpad_icon">DPAD_LEFT</annotation> for audio device settings</string>
+
+    <string name="audio_device_settings_content_description"><xliff:g id="audio_device_name" example="Foo Soundbar">%1$s</xliff:g> settings.</string>
 
     <string name="hdmi_cec_on_active_source_lost_title">Are you still watching?</string>
-    <string name="hdmi_cec_on_active_source_lost_description">The TV told us it will display another input. Select one option to keep this device awake.</string>
-    <string name="hdmi_cec_on_active_source_lost_ok">Yes</string>
+    <string name="hdmi_cec_on_active_source_lost_description">Your TV indicated that you switched to a different input and this device will go to sleep soon. Select an option to keep this device awake.</string>
+    <string name="hdmi_cec_on_active_source_lost_ok">Yes (<xliff:g id="seconds" example="10">%1$d</xliff:g>s)</string>
     <string name="hdmi_cec_on_active_source_lost_do_not_show">Don\u2019t ask again</string>
 
     <string name="font_display_large" translatable="false">sans-serif</string>
@@ -67,4 +80,15 @@
     <string name="font_body_extra_small" translatable="false">roboto</string>
 
     <string name="font_overline" translatable="false">sans-serif</string>
+
+    <string name="audio_output_builtin_speaker_slice_uri" translatable="false"/>
+    <string name="audio_output_wired_headphone_slice_uri" translatable="false" />
+    <string name="audio_output_bluetooth_slice_uri" translatable="false"/>
+    <string name="audio_output_hdmi_slice_uri" translatable="false"/>
+    <string name="audio_output_hdmi_e_arc_slice_uri" translatable="false"/>
+    <string name="audio_output_usb_slice_uri" translatable="false"/>
+    <string name="audio_output_remote_avr_slice_uri" translatable="false" />
+    <string name="audio_output_cast_device_slice_uri" translatable="false" />
+    <string name="audio_output_cast_group_slice_uri" translatable="false" />
+
 </resources>
diff --git a/res/values/styles.xml b/res/values/styles.xml
index 0dae126..0b5c658 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -85,4 +85,147 @@
         <item name="android:windowContentOverlay">@null</item>
         <item name="android:windowIsFloating">true</item>
     </style>
+
+    <style name="PanelTitle">
+        <item name="android:fontFamily">@string/font_title_medium</item>
+        <item name="android:includeFontPadding">true</item>
+        <item name="android:textSize">@dimen/media_dialog_title</item>
+        <item name="android:gravity">center</item>
+        <item name="android:padding">@dimen/media_dialog_title_margin</item>
+        <item name="android:singleLine">true</item>
+        <item name="android:marqueeRepeatLimit">marquee_forever</item>
+        <item name="android:ellipsize">marquee</item>>
+        <item name="android:textAllCaps">false</item>
+        <item name="android:textColor">@color/media_dialog_title</item>
+    </style>
+
+    <style name="TextAppearance.Panel.ListItem" parent="android:TextAppearance">
+        <item name="android:textColor">@color/media_dialog_item_title</item>
+        <item name="android:textSize">@dimen/media_dialog_item_title</item>
+        <item name="android:fontFamily">@string/font_label_medium</item>
+    </style>
+
+    <style name="TextAppearance.Panel.ListItem.Secondary" parent="TextAppearance.Panel.ListItem">
+        <item name="android:textColor">@color/media_dialog_item_subtitle</item>
+        <item name="android:textSize">@dimen/media_dialog_item_subtitle</item>
+        <item name="android:fontFamily">@string/font_body_extra_small</item>
+    </style>
+
+    <style name="TextSliceStyle">
+        <item name="android:layout_marginHorizontal">12dp</item>
+        <item name="android:layout_marginVertical">5dp</item>
+        <item name="android:focusable">false</item>
+        <item name="android:clickable">false</item>
+        <item name="android:clipChildren">false</item>
+        <item name="android:clipToPadding">false</item>
+    </style>
+
+    <style name="ControlWidgetStyle">
+        <item name="android:layout_marginHorizontal">12dp</item>
+        <item name="android:layout_marginVertical">5dp</item>
+        <item name="android:background">@drawable/media_dialog_item_bg</item>
+        <item name="android:stateListAnimator">@anim/media_dialog_item_state_list_animator</item>
+        <item name="android:focusable">true</item>
+        <item name="android:clickable">true</item>
+        <item name="android:clipChildren">false</item>
+        <item name="android:clipToPadding">false</item>
+    </style>
+
+    <style name="ControlWidgetSubTextStyle" parent="ControlWidgetTextStyle">
+        <item name="android:textColor">@color/media_dialog_item_subtitle</item>
+    </style>
+
+    <style name="ControlWidgetIconStyle">
+        <item name="android:layout_width">@dimen/control_widget_icon_size</item>
+        <item name="android:layout_height">@dimen/control_widget_icon_size</item>
+        <item name="android:layout_gravity">center_vertical</item>
+    </style>
+
+    <style name="ControlWidgetSmallIconStyle">
+        <item name="android:layout_width">@dimen/control_widget_small_icon_size</item>
+        <item name="android:layout_height">@dimen/control_widget_small_icon_size</item>
+        <item name="android:tint">@color/media_dialog_item_title</item>
+        <item name="android:layout_gravity">center_vertical</item>
+    </style>
+
+    <style name="ControlWidgetTextStyle">
+        <item name="android:fontFamily">@string/font_label_medium</item>
+        <item name="android:includeFontPadding">false</item>
+        <item name="android:textSize">12sp</item>
+        <item name="android:letterSpacing">0.01</item>
+        <item name="android:gravity">start</item>
+        <item name="android:singleLine">true</item>
+        <item name="android:marqueeRepeatLimit">1</item>
+        <item name="android:ellipsize">marquee</item>
+        <item name="android:textColor">@color/media_dialog_item_title</item>
+        <item name="android:textAlignment">viewStart</item>
+    </style>
+
+    <style name="SwitchWidgetStyle" parent="ControlWidgetStyle">
+        <item name="android:paddingStart">12dp</item>
+        <item name="android:paddingEnd">8dp</item>
+        <item name="android:paddingVertical">14dp</item>
+    </style>
+
+    <style name="CheckboxWidgetStyle" parent="ControlWidgetStyle">
+        <item name="android:paddingStart">12dp</item>
+        <item name="android:paddingEnd">8dp</item>
+        <item name="android:paddingVertical">12dp</item>
+    </style>
+
+    <style name="RadioWidgetStyle" parent="ControlWidgetStyle">
+        <item name="android:paddingStart">12dp</item>
+        <item name="android:paddingEnd">8dp</item>
+        <item name="android:paddingVertical">12dp</item>
+    </style>
+
+    <style name="OutputDeviceWidgetStyle" parent="RadioWidgetStyle">
+        <!--    Handled through RecyclerView.ItemDecoration    -->
+        <item name="android:layout_marginVertical">0dp</item>
+        <!--    Added to the parent instead due to a11y settings button -->
+        <item name="android:layout_marginHorizontal">0dp</item>
+    </style>
+
+    <style name="SeekbarWidgetStyle" parent="ControlWidgetStyle">
+        <item name="android:paddingHorizontal">12dp</item>
+        <item name="android:paddingVertical">12dp</item>
+    </style>
+
+    <style name="BasicIconTextWidgetStyle" parent="ControlWidgetStyle">
+        <item name="android:paddingHorizontal">12dp</item>
+        <item name="android:paddingVertical">14dp</item>
+    </style>
+
+    <style name="BasicCenteredIconTextWidgetStyle" parent="BasicIconTextWidgetStyle">
+        <item name="android:background">@drawable/media_dialog_item_bg_rounded</item>
+    </style>
+
+    <style name="ControlWidgetTooltipWindowAnimation">
+        <item name="android:windowEnterAnimation">@anim/tooltip_window_enter</item>
+        <item name="android:windowExitAnimation">@anim/tooltip_window_exit</item>
+    </style>
+
+    <style name="ControlWidgetTooltipTextStyle">
+        <item name="android:fontFamily">@string/font_label_medium</item>
+        <item name="android:textSize">10sp</item>
+        <item name="android:singleLine">true</item>
+        <item name="android:textColor">@color/media_dialog_item_title</item>
+        <item name="android:textAlignment">viewStart</item>
+    </style>
+
+    <style name="ControlWidgetTooltipTextSummaryStyle">
+        <item name="android:fontFamily">@string/font_body_extra_small</item>
+        <item name="android:textSize">10sp</item>
+        <item name="android:singleLine">false</item>
+        <item name="android:textColor">@color/media_dialog_item_subtitle</item>
+        <item name="android:textAlignment">viewStart</item>
+    </style>
+
+    <style name="SingleLineMarquee">
+        <item name="android:ellipsize">marquee</item>
+        <item name="android:singleLine">true</item>
+        <item name="android:marqueeRepeatLimit">marquee_forever</item>
+        <item name="android:scrollHorizontally">true</item>
+    </style>
+
 </resources>
diff --git a/src/com/android/systemui/tv/dagger/TvSysUIComponent.kt b/src/com/android/systemui/tv/dagger/TvSysUIComponent.kt
index 916255c..8ed78bc 100644
--- a/src/com/android/systemui/tv/dagger/TvSysUIComponent.kt
+++ b/src/com/android/systemui/tv/dagger/TvSysUIComponent.kt
@@ -23,8 +23,6 @@ import com.android.systemui.keyguard.dagger.KeyguardModule
 import com.android.systemui.navigationbar.NoopNavigationBarControllerModule
 import com.android.systemui.scene.ShadelessSceneContainerFrameworkModule
 import com.android.systemui.statusbar.dagger.CentralSurfacesDependenciesModule
-import com.android.systemui.statusbar.notification.dagger.NotificationsModule
-import com.android.systemui.statusbar.notification.row.NotificationRowModule
 import com.android.systemui.tv.recents.TvRecentsModule
 import com.android.systemui.wallpapers.dagger.NoopWallpaperModule
 import dagger.Subcomponent
@@ -42,8 +40,6 @@ import dagger.Subcomponent
     KeyguardModule::class,
     NoopNavigationBarControllerModule::class,
     NoopWallpaperModule::class,
-    NotificationRowModule::class,
-    NotificationsModule::class,
     TvRecentsModule::class,
     ShadelessSceneContainerFrameworkModule::class,
     SystemUIModule::class,
diff --git a/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt b/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt
index fe17eb9..a930b8a 100644
--- a/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt
+++ b/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt
@@ -52,12 +52,13 @@ import com.android.systemui.statusbar.NotificationLockscreenUserManager
 import com.android.systemui.statusbar.NotificationLockscreenUserManagerImpl
 import com.android.systemui.statusbar.NotificationShadeWindowController
 import com.android.systemui.statusbar.events.StatusBarEventsModule
+import com.android.systemui.statusbar.notification.dagger.ReferenceNotificationsModule
+import com.android.systemui.statusbar.notification.headsup.HeadsUpEmptyImplModule
 import com.android.systemui.statusbar.phone.DozeServiceHost
 import com.android.systemui.statusbar.phone.StatusBarKeyguardViewManager
 import com.android.systemui.statusbar.policy.AospPolicyModule
 import com.android.systemui.statusbar.policy.DeviceProvisionedController
 import com.android.systemui.statusbar.policy.DeviceProvisionedControllerImpl
-import com.android.systemui.statusbar.policy.HeadsUpEmptyImplModule
 import com.android.systemui.statusbar.policy.IndividualSensorPrivacyController
 import com.android.systemui.statusbar.policy.IndividualSensorPrivacyControllerImpl
 import com.android.systemui.statusbar.policy.SensorPrivacyController
@@ -107,6 +108,7 @@ import kotlinx.coroutines.ExperimentalCoroutinesApi
     PowerModule::class,
     PrivacyModule::class,
     QSModule::class,
+    ReferenceNotificationsModule::class,
     ReferenceScreenshotModule::class,
     ShadeEmptyImplModule::class,
     StatusBarEventsModule::class,
diff --git a/src/com/android/systemui/tv/dagger/TvWMComponent.kt b/src/com/android/systemui/tv/dagger/TvWMComponent.kt
index 818f104..2fca37c 100644
--- a/src/com/android/systemui/tv/dagger/TvWMComponent.kt
+++ b/src/com/android/systemui/tv/dagger/TvWMComponent.kt
@@ -15,8 +15,8 @@
  */
 package com.android.systemui.tv.dagger
 
-import com.android.systemui.dagger.WMComponent
 import com.android.wm.shell.dagger.TvWMShellModule
+import com.android.wm.shell.dagger.WMComponent
 import com.android.wm.shell.dagger.WMSingleton
 import dagger.Subcomponent
 
@@ -33,4 +33,4 @@ interface TvWMComponent : WMComponent {
     interface Builder : WMComponent.Builder {
         override fun build(): TvWMComponent
     }
-}
\ No newline at end of file
+}
diff --git a/src/com/android/systemui/tv/hdmi/HdmiCecActiveSourceLostActivity.java b/src/com/android/systemui/tv/hdmi/HdmiCecActiveSourceLostActivity.java
index 313ba34..e5372af 100644
--- a/src/com/android/systemui/tv/hdmi/HdmiCecActiveSourceLostActivity.java
+++ b/src/com/android/systemui/tv/hdmi/HdmiCecActiveSourceLostActivity.java
@@ -21,7 +21,10 @@ import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
 import android.hardware.hdmi.HdmiControlManager;
+import android.hardware.hdmi.HdmiPlaybackClient;
 import android.os.Bundle;
+import android.os.CountDownTimer;
+import android.util.Slog;
 import android.view.View;
 import android.view.WindowManager;
 import android.widget.Button;
@@ -38,7 +41,9 @@ import com.android.systemui.tv.res.R;
  */
 public class HdmiCecActiveSourceLostActivity extends TvBottomSheetActivity
         implements View.OnClickListener {
+    private static final String TAG = "HdmiCecActiveSourceLostActivity";
     private HdmiControlManager mHdmiControlManager;
+    private static final int COUNTDOWN_GO_TO_SLEEP_MS = 30_000; // 30 seconds
 
     @Override
     public final void onCreate(Bundle b) {
@@ -68,6 +73,18 @@ public class HdmiCecActiveSourceLostActivity extends TvBottomSheetActivity
             mHdmiControlManager.setPowerStateChangeOnActiveSourceLost(
                     HdmiControlManager.POWER_STATE_CHANGE_ON_ACTIVE_SOURCE_LOST_NONE);
         }
+        HdmiPlaybackClient playbackClient = mHdmiControlManager.getPlaybackClient();
+        if (playbackClient != null) {
+            playbackClient.oneTouchPlay(new HdmiPlaybackClient.OneTouchPlayCallback() {
+                @Override
+                public void onComplete(int result) {
+                    if (result != HdmiControlManager.RESULT_SUCCESS) {
+                        Slog.w(TAG, "One touch play failed: " + result);
+                    }
+                }
+            });
+        }
+
         finish();
     }
 
@@ -84,7 +101,20 @@ public class HdmiCecActiveSourceLostActivity extends TvBottomSheetActivity
         icon.setImageResource(R.drawable.ic_input_switch);
         secondIcon.setVisibility(View.GONE);
 
-        okButton.setText(R.string.hdmi_cec_on_active_source_lost_ok);
+        new CountDownTimer(COUNTDOWN_GO_TO_SLEEP_MS, 1000) {
+            public void onTick(long millisUntilFinished) {
+                // Start countdown from 30, not 29.
+                okButton.setText(String.format(getResources()
+                                .getString(R.string.hdmi_cec_on_active_source_lost_ok),
+                        millisUntilFinished / 1000 + 1));
+            }
+            public void onFinish() {
+                okButton.setText(String.format(getResources()
+                                .getString(R.string.hdmi_cec_on_active_source_lost_ok), 0));
+            }
+        }.start();
+
+
         okButton.setOnClickListener(this);
         okButton.requestFocus();
 
diff --git a/src/com/android/systemui/tv/hdmi/HdmiCecSetMenuLanguageActivity.java b/src/com/android/systemui/tv/hdmi/HdmiCecSetMenuLanguageActivity.java
index f9ca205..c8e610a 100644
--- a/src/com/android/systemui/tv/hdmi/HdmiCecSetMenuLanguageActivity.java
+++ b/src/com/android/systemui/tv/hdmi/HdmiCecSetMenuLanguageActivity.java
@@ -61,10 +61,10 @@ public class HdmiCecSetMenuLanguageActivity extends TvBottomSheetActivity
         super.onResume();
         CharSequence title =
                 getString(
-                        com.android.systemui.R.string.hdmi_cec_set_menu_language_title,
+                        com.android.systemui.res.R.string.hdmi_cec_set_menu_language_title,
                         mHdmiCecSetMenuLanguageHelper.getLocale().getDisplayLanguage());
         CharSequence text =
-                getString(com.android.systemui.R.string.hdmi_cec_set_menu_language_description);
+                getString(com.android.systemui.res.R.string.hdmi_cec_set_menu_language_description);
         initUI(title, text);
     }
 
@@ -91,10 +91,10 @@ public class HdmiCecSetMenuLanguageActivity extends TvBottomSheetActivity
         icon.setImageResource(com.android.internal.R.drawable.ic_settings_language);
         secondIcon.setVisibility(View.GONE);
 
-        okButton.setText(com.android.systemui.R.string.hdmi_cec_set_menu_language_accept);
+        okButton.setText(com.android.systemui.res.R.string.hdmi_cec_set_menu_language_accept);
         okButton.setOnClickListener(this);
 
-        cancelButton.setText(com.android.systemui.R.string.hdmi_cec_set_menu_language_decline);
+        cancelButton.setText(com.android.systemui.res.R.string.hdmi_cec_set_menu_language_decline);
         cancelButton.setOnClickListener(this);
         cancelButton.requestFocus();
     }
diff --git a/src/com/android/systemui/tv/media/FadingEdgeUtil.java b/src/com/android/systemui/tv/media/FadingEdgeUtil.java
new file mode 100644
index 0000000..4008bca
--- /dev/null
+++ b/src/com/android/systemui/tv/media/FadingEdgeUtil.java
@@ -0,0 +1,85 @@
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
+package com.android.systemui.tv.media;
+
+import android.content.Context;
+import android.graphics.drawable.Drawable;
+import android.view.View;
+import android.view.ViewGroup;
+
+import androidx.annotation.Nullable;
+import androidx.recyclerview.widget.RecyclerView;
+
+import com.android.systemui.tv.res.R;
+
+public class FadingEdgeUtil {
+
+    @Nullable
+    public static Drawable getForegroundDrawable(RecyclerView recyclerView, Context context) {
+        if (shouldShowTopFadingEdge(recyclerView) && shouldShowBottomFadingEdge(recyclerView)) {
+            return context.getDrawable(R.drawable.both_end_fading_edge);
+        } else if (shouldShowBottomFadingEdge(recyclerView)) {
+            return context.getDrawable(R.drawable.bottom_fading_edge);
+        } else if (shouldShowTopFadingEdge(recyclerView)) {
+            return context.getDrawable(R.drawable.top_fading_edge);
+        }
+        return null;
+    }
+
+    @SuppressWarnings("nullness")
+    private static boolean shouldShowTopFadingEdge(RecyclerView recyclerView) {
+        RecyclerView.LayoutManager layoutManager = recyclerView.getLayoutManager();
+        View firstVisibleChildView = layoutManager.getChildAt(0);
+        int positionOfCurrentFistView = layoutManager.getPosition(firstVisibleChildView);
+        boolean isFirstAdapterItemVisible = (positionOfCurrentFistView == 0);
+        if (!isFirstAdapterItemVisible) {
+            return true;
+        }
+        int top = firstVisibleChildView.getTop();
+        return top < 0;
+    }
+
+    @SuppressWarnings("nullness")
+    private static boolean shouldShowBottomFadingEdge(RecyclerView recyclerView) {
+        // Get adapter's last child View.
+        View lastChildView = null;
+        RecyclerView.ViewHolder holder =
+                recyclerView.findViewHolderForAdapterPosition(
+                        recyclerView.getAdapter().getItemCount() - 1);
+        if (holder != null) {
+            lastChildView = holder.itemView;
+        }
+        if (lastChildView == null) {
+            // If last child is not inflated yet, then it definitely is not visible.
+            return true;
+        }
+        if (lastChildView.getTop() >= recyclerView.getBottom()) {
+            // If last child is below dashboard's bottom edge, then it should be invisible
+            // currently.
+            // Sometimes even if the last item is not visible, it still get counted in
+            // layoutManager's
+            // children. So use the coordinates would be more precise.
+            return true;
+        }
+        int rvBottom = recyclerView.getBottom();
+        int bottom = lastChildView.getBottom();
+        int bottomMargin =
+                ((ViewGroup.MarginLayoutParams) lastChildView.getLayoutParams()).bottomMargin;
+        return bottom + bottomMargin > rvBottom;
+    }
+
+}
diff --git a/src/com/android/systemui/tv/media/OutputDeviceControlWidget.java b/src/com/android/systemui/tv/media/OutputDeviceControlWidget.java
new file mode 100644
index 0000000..3721035
--- /dev/null
+++ b/src/com/android/systemui/tv/media/OutputDeviceControlWidget.java
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
+package com.android.systemui.tv.media;
+
+import android.content.Context;
+import android.util.AttributeSet;
+import android.view.View;
+
+import androidx.annotation.Nullable;
+
+import com.android.systemui.tv.media.settings.ControlWidget;
+import com.android.systemui.tv.res.R;
+
+public class OutputDeviceControlWidget extends ControlWidget {
+    public OutputDeviceControlWidget(Context context) {
+        this(context, null);
+    }
+
+    public OutputDeviceControlWidget(Context context,
+            @Nullable AttributeSet attrs) {
+        this(context, attrs, 0);
+    }
+
+    public OutputDeviceControlWidget(Context context, @Nullable AttributeSet attrs,
+            int defStyleAttr) {
+        super(context, attrs, defStyleAttr);
+        View.inflate(context, R.layout.media_output_device_widget, /* root= */ this);
+    }
+}
diff --git a/src/com/android/systemui/tv/media/OutputDevicesFragment.java b/src/com/android/systemui/tv/media/OutputDevicesFragment.java
new file mode 100644
index 0000000..1fabba2
--- /dev/null
+++ b/src/com/android/systemui/tv/media/OutputDevicesFragment.java
@@ -0,0 +1,277 @@
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
+package com.android.systemui.tv.media;
+
+import android.app.KeyguardManager;
+import android.content.Context;
+import android.graphics.Rect;
+import android.graphics.drawable.Drawable;
+import android.media.AudioManager;
+import android.media.session.MediaSessionManager;
+import android.os.Bundle;
+import android.os.Handler;
+import android.os.Looper;
+import android.os.PowerExemptionManager;
+import android.util.Log;
+import android.view.LayoutInflater;
+import android.view.View;
+import android.view.ViewGroup;
+
+import androidx.annotation.NonNull;
+import androidx.fragment.app.Fragment;
+import androidx.fragment.app.FragmentManager;
+import androidx.recyclerview.widget.LinearLayoutManager;
+import androidx.recyclerview.widget.RecyclerView;
+
+import com.android.settingslib.bluetooth.LocalBluetoothManager;
+import com.android.settingslib.media.MediaDevice;
+import com.android.systemui.animation.DialogTransitionAnimator;
+import com.android.systemui.flags.FeatureFlags;
+import com.android.systemui.media.dialog.MediaSwitchingController;
+import com.android.systemui.media.nearby.NearbyMediaDevicesManager;
+import com.android.systemui.plugins.ActivityStarter;
+import com.android.systemui.settings.UserTracker;
+import com.android.systemui.statusbar.notification.collection.notifcollection.CommonNotifCollection;
+import com.android.systemui.tv.res.R;
+import com.android.systemui.volume.panel.domain.interactor.VolumePanelGlobalStateInteractor;
+
+import javax.annotation.Nullable;
+import javax.inject.Inject;
+
+public class OutputDevicesFragment extends Fragment
+        implements MediaSwitchingController.Callback, TvMediaOutputAdapter.PanelCallback {
+
+    private static final String TAG = OutputDevicesFragment.class.getSimpleName();
+    private static final boolean DEBUG = false;
+
+    private TvMediaOutputController mMediaOutputController;
+    private TvMediaOutputAdapter mAdapter;
+    private RecyclerView mDevicesRecyclerView;
+
+    private final MediaSessionManager mMediaSessionManager;
+    private final LocalBluetoothManager mLocalBluetoothManager;
+    private final ActivityStarter mActivityStarter;
+    private final CommonNotifCollection mCommonNotifCollection;
+    private final DialogTransitionAnimator mDialogTransitionAnimator;
+    private final NearbyMediaDevicesManager mNearbyMediaDevicesManager;
+    private final AudioManager mAudioManager;
+    private final PowerExemptionManager mPowerExemptionManager;
+    private final KeyguardManager mKeyguardManager;
+    private final FeatureFlags mFeatureFlags;
+    private final VolumePanelGlobalStateInteractor mVolumePanelGlobalStateInteractor;
+    private final UserTracker mUserTracker;
+
+    protected final Handler mMainThreadHandler = new Handler(Looper.getMainLooper());
+    private String mActiveDeviceId;
+
+    @Inject
+    public OutputDevicesFragment(
+            MediaSessionManager mediaSessionManager,
+            @Nullable LocalBluetoothManager localBluetoothManager,
+            ActivityStarter activityStarter,
+            CommonNotifCollection commonNotifCollection,
+            DialogTransitionAnimator dialogTransitionAnimator,
+            NearbyMediaDevicesManager nearbyMediaDevicesManager,
+            AudioManager audioManager,
+            PowerExemptionManager powerExemptionManager,
+            KeyguardManager keyguardManager,
+            FeatureFlags featureFlags,
+            VolumePanelGlobalStateInteractor volumePanelGlobalStateInteractor,
+            UserTracker userTracker) {
+        mMediaSessionManager = mediaSessionManager;
+        mLocalBluetoothManager = localBluetoothManager;
+        mActivityStarter = activityStarter;
+        mCommonNotifCollection = commonNotifCollection;
+        mDialogTransitionAnimator = dialogTransitionAnimator;
+        mNearbyMediaDevicesManager = nearbyMediaDevicesManager;
+        mAudioManager = audioManager;
+        mPowerExemptionManager = powerExemptionManager;
+        mKeyguardManager = keyguardManager;
+        mFeatureFlags = featureFlags;
+        mVolumePanelGlobalStateInteractor = volumePanelGlobalStateInteractor;
+        mUserTracker = userTracker;
+    }
+
+    @Override
+    public void onCreate(Bundle savedInstanceState) {
+        super.onCreate(savedInstanceState);
+        mMediaOutputController =
+                new TvMediaOutputController(
+                        getContext(),
+                        getContext().getPackageName(),
+                        mMediaSessionManager,
+                        mLocalBluetoothManager,
+                        mActivityStarter,
+                        mCommonNotifCollection,
+                        mDialogTransitionAnimator,
+                        mNearbyMediaDevicesManager,
+                        mAudioManager,
+                        mPowerExemptionManager,
+                        mKeyguardManager,
+                        mFeatureFlags,
+                        mVolumePanelGlobalStateInteractor,
+                        mUserTracker);
+        mAdapter = new TvMediaOutputAdapter(getContext(), mMediaOutputController, this);
+    }
+
+    @Nullable
+    @Override
+    public View onCreateView(
+            @NonNull LayoutInflater inflater,
+            @Nullable ViewGroup container,
+            @Nullable Bundle savedInstanceState) {
+        View view = inflater.inflate(R.layout.media_output_main_fragment, null);
+
+        mDevicesRecyclerView = view.requireViewById(R.id.device_list);
+        mDevicesRecyclerView.setLayoutManager(new LayoutManagerWrapper(view.getContext()));
+        mDevicesRecyclerView.setAdapter(mAdapter);
+
+        mDevicesRecyclerView.addOnScrollListener(
+                new RecyclerView.OnScrollListener() {
+                    @Override
+                    public void onScrolled(@NonNull RecyclerView recyclerView, int dx, int dy) {
+                        super.onScrolled(recyclerView, dx, dy);
+                        Drawable foreground = FadingEdgeUtil.getForegroundDrawable(
+                                recyclerView, requireContext());
+                        if (foreground != recyclerView.getForeground()) {
+                            recyclerView.setForeground(foreground);
+                        }
+                    }
+                });
+
+        int itemSpacingPx = getResources().getDimensionPixelSize(R.dimen.media_dialog_item_spacing);
+        mDevicesRecyclerView.addItemDecoration(new SpacingDecoration(itemSpacingPx));
+
+        return view;
+    }
+
+    @Override
+    public void onStart() {
+        super.onStart();
+        mMediaOutputController.start(this);
+    }
+
+    @Override
+    public void onStop() {
+        mMediaOutputController.stop();
+        super.onStop();
+    }
+
+    @Override
+    public void onResume() {
+        super.onResume();
+        if (DEBUG) Log.d(TAG, "resuming OutputDevicesFragment");
+        int position = mAdapter.getFocusPosition();
+        mDevicesRecyclerView.getLayoutManager().scrollToPosition(position);
+        // Ensure layout is complete before requesting focus.
+        mDevicesRecyclerView.post(() -> {
+            View itemToFocus = mDevicesRecyclerView.getLayoutManager().findViewByPosition(position);
+            if (itemToFocus != null) {
+                itemToFocus.requestFocus();
+            }
+        });
+    }
+
+    private void refresh(boolean deviceSetChanged) {
+        if (DEBUG) Log.d(TAG, "refresh: deviceSetChanged " + deviceSetChanged);
+        // If the dialog is going away or is already refreshing, do nothing.
+        if (mMediaOutputController.isRefreshing()) {
+            return;
+        }
+        mMediaOutputController.setRefreshing(true);
+        mAdapter.updateItems();
+    }
+
+    @Override
+    public void onMediaChanged() {
+        // NOOP
+    }
+
+    @Override
+    public void onMediaStoppedOrPaused() {
+        // NOOP
+    }
+
+    @Override
+    public void onRouteChanged() {
+        mMainThreadHandler.post(() -> refresh(/* deviceSetChanged= */ false));
+        MediaDevice activeDevice = mMediaOutputController.getCurrentConnectedMediaDevice();
+        if (mActiveDeviceId != null && !mActiveDeviceId.equals(activeDevice.getId())) {
+            mMediaOutputController.showVolumeDialog();
+        }
+        mActiveDeviceId = activeDevice.getId();
+    }
+
+    @Override
+    public void onDeviceListChanged() {
+        mMainThreadHandler.post(() -> refresh(/* deviceSetChanged= */ true));
+        if (mActiveDeviceId == null
+                && mMediaOutputController.getCurrentConnectedMediaDevice() != null) {
+            mActiveDeviceId = mMediaOutputController.getCurrentConnectedMediaDevice().getId();
+        }
+    }
+
+    @Override
+    public void dismissDialog() {
+        if (DEBUG) Log.d(TAG, "dismissDialog");
+        if (getActivity() != null) {
+            getActivity().finish();
+        }
+    }
+
+    @Override
+    public void openDeviceSettings(
+            String uri, CharSequence title, CharSequence subtitle, String id) {
+        FragmentManager fragmentManager = getParentFragmentManager();
+        Bundle deviceInfo = new Bundle();
+        deviceInfo.putString("uri", uri);
+        deviceInfo.putCharSequence("title", title);
+        deviceInfo.putCharSequence("subtitle", subtitle);
+        deviceInfo.putString("deviceId", id);
+        fragmentManager.setFragmentResult("deviceSettings", deviceInfo);
+    }
+
+    private class LayoutManagerWrapper extends LinearLayoutManager {
+        LayoutManagerWrapper(Context context) {
+            super(context);
+        }
+
+        @Override
+        public void onLayoutCompleted(RecyclerView.State state) {
+            super.onLayoutCompleted(state);
+            mMediaOutputController.setRefreshing(false);
+            mMediaOutputController.refreshDataSetIfNeeded();
+        }
+    }
+
+    private static class SpacingDecoration extends RecyclerView.ItemDecoration {
+        private final int mMarginPx;
+
+        SpacingDecoration(int marginPx) {
+            mMarginPx = marginPx;
+        }
+
+        @Override
+        public void getItemOffsets(
+                Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
+            if (parent.getChildAdapterPosition(view) == 0) {
+                outRect.top = mMarginPx;
+            }
+            outRect.bottom = mMarginPx;
+        }
+    }
+}
diff --git a/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java b/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java
index b03aec6..728c0bc 100644
--- a/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java
+++ b/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java
@@ -20,25 +20,39 @@ import android.content.Context;
 import android.content.Intent;
 import android.content.res.Resources;
 import android.graphics.drawable.Drawable;
+import android.media.MediaRoute2Info;
+import android.net.Uri;
 import android.os.Bundle;
+import android.text.Annotation;
+import android.text.Spannable;
+import android.text.SpannableString;
+import android.text.SpannedString;
 import android.text.TextUtils;
 import android.util.Log;
+import android.view.KeyEvent;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
+import android.view.accessibility.AccessibilityManager;
+import android.widget.ImageButton;
 import android.widget.ImageView;
 import android.widget.RadioButton;
 import android.widget.TextView;
 
 import androidx.annotation.NonNull;
+import androidx.recyclerview.widget.RecyclerView;
 
-import com.android.internal.widget.RecyclerView;
+import com.android.settingslib.media.BluetoothMediaDevice;
 import com.android.settingslib.media.LocalMediaManager;
 import com.android.settingslib.media.MediaDevice;
+import com.android.settingslib.media.MediaDevice.MediaDeviceType;
 import com.android.systemui.media.dialog.MediaItem;
-import com.android.systemui.media.dialog.MediaSwitchingController;
+import com.android.systemui.tv.media.settings.CenteredImageSpan;
+import com.android.systemui.tv.media.settings.ControlWidget;
+
 import com.android.systemui.tv.res.R;
 
+import java.util.Arrays;
 import java.util.List;
 import java.util.concurrent.CopyOnWriteArrayList;
 
@@ -51,27 +65,37 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
     private static final boolean DEBUG = false;
 
     private final TvMediaOutputController mMediaOutputController;
-    private final MediaSwitchingController.Callback mCallback;
+    private final PanelCallback mCallback;
     private final Context mContext;
     protected List<MediaItem> mMediaItemList = new CopyOnWriteArrayList<>();
 
+    private final AccessibilityManager mA11yManager;
+
     private final int mFocusedRadioTint;
     private final int mUnfocusedRadioTint;
     private final int mCheckedRadioTint;
 
-    TvMediaOutputAdapter(
-            Context context,
-            TvMediaOutputController mediaOutputController,
-            MediaSwitchingController.Callback callback) {
+    private final CharSequence mTooltipText;
+    private String mSavedDeviceId;
+
+    private final boolean mIsRtl;
+
+    TvMediaOutputAdapter(Context context, TvMediaOutputController mediaOutputController,
+            PanelCallback callback) {
         mContext = context;
         mMediaOutputController = mediaOutputController;
         mCallback = callback;
 
+        mA11yManager = context.getSystemService(AccessibilityManager.class);
+
         Resources res = mContext.getResources();
         mFocusedRadioTint = res.getColor(R.color.media_dialog_radio_button_focused);
         mUnfocusedRadioTint = res.getColor(R.color.media_dialog_radio_button_unfocused);
         mCheckedRadioTint = res.getColor(R.color.media_dialog_radio_button_checked);
 
+        mIsRtl = res.getConfiguration().getLayoutDirection() == View.LAYOUT_DIRECTION_RTL;
+        mTooltipText = createTooltipText();
+
         setHasStableIds(true);
     }
 
@@ -124,6 +148,51 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
         return mMediaItemList.size();
     }
 
+    /**
+     * Returns position of the MediaDevice with the saved device id.
+     */
+    protected int getFocusPosition() {
+        if (DEBUG) Log.d(TAG, "getFocusPosition, deviceId: " + mSavedDeviceId);
+        if (mSavedDeviceId == null) {
+            return 0;
+        }
+        for (int i = 0; i < mMediaItemList.size(); i++) {
+            MediaItem item = mMediaItemList.get(i);
+            if (item.getMediaDevice().isPresent()) {
+                if (item.getMediaDevice().get().getId().equals(mSavedDeviceId)) {
+                    mSavedDeviceId = null;
+                    return i;
+                }
+            }
+        }
+        return 0;
+    }
+
+    /**
+     * Replaces the dpad action with an icon.
+     */
+    private CharSequence createTooltipText() {
+        Resources res = mContext.getResources();
+        final SpannedString tooltipText = (SpannedString) res.getText(mIsRtl
+                ? R.string.audio_device_tooltip_right : R.string.audio_device_tooltip_left);
+        final SpannableString spannableString = new SpannableString(tooltipText);
+        Arrays.stream(tooltipText.getSpans(0, tooltipText.length(), Annotation.class)).findFirst()
+                .ifPresent(annotation -> {
+                    final Drawable icon =
+                            res.getDrawable(R.drawable.dpad_right, mContext.getTheme());
+                    icon.setLayoutDirection(
+                            mContext.getResources().getConfiguration().getLayoutDirection());
+                    icon.mutate();
+                    icon.setBounds(0, 0, icon.getIntrinsicWidth(), icon.getIntrinsicHeight());
+                    spannableString.setSpan(new CenteredImageSpan(icon),
+                            tooltipText.getSpanStart(annotation),
+                            tooltipText.getSpanEnd(annotation),
+                            Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
+                });
+
+        return spannableString;
+    }
+
     @Override
     public long getItemId(int position) {
         MediaItem item = mMediaItemList.get(position);
@@ -156,6 +225,9 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
         final TextView mTitle;
         final TextView mSubtitle;
         final RadioButton mRadioButton;
+        final ImageButton mA11ySettingsButton;
+        final OutputDeviceControlWidget mWidget;
+        MediaDevice mMediaDevice;
 
         DeviceViewHolder(View itemView) {
             super(itemView);
@@ -163,9 +235,13 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
             mTitle = itemView.requireViewById(R.id.media_dialog_item_title);
             mSubtitle = itemView.requireViewById(R.id.media_dialog_item_subtitle);
             mRadioButton = itemView.requireViewById(R.id.media_dialog_radio_button);
+
+            mWidget = itemView.requireViewById(R.id.media_dialog_device_widget);
+            mA11ySettingsButton = itemView.requireViewById(R.id.media_dialog_item_a11y_settings);
         }
 
         void onBind(MediaDevice mediaDevice, int position) {
+            mMediaDevice = mediaDevice;
             // Title
             mTitle.setText(mediaDevice.getName());
 
@@ -178,7 +254,7 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
                     == LocalMediaManager.MediaDeviceState.STATE_CONNECTING_FAILED) {
                 icon =
                         mContext.getDrawable(
-                                com.android.systemui.R.drawable.media_output_status_failed);
+                                com.android.systemui.res.R.drawable.media_output_status_failed);
             } else {
                 icon = mediaDevice.getIconWithoutBackground();
             }
@@ -193,18 +269,81 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
             mRadioButton.setChecked(isCurrentlyConnected(mediaDevice));
             setRadioButtonColor();
 
-            itemView.setOnFocusChangeListener((view, focused) -> {
+            mWidget.setOnFocusChangeListener((view, focused) -> {
                 setSummary(mediaDevice);
                 setRadioButtonColor();
                 mTitle.setSelected(focused);
                 mSubtitle.setSelected(focused);
             });
 
-            itemView.setOnClickListener(v -> transferOutput(mediaDevice));
+            mWidget.setOnClickListener(v -> transferOutput(mediaDevice));
+
+            String baseUri = getBaseUriForDevice(mContext, mMediaDevice);
+            boolean hasSettings = baseUri != null && !baseUri.isEmpty();
+
+            if (hasSettings) {
+                if (mA11yManager.isEnabled()) {
+                    mA11ySettingsButton.setVisibility(View.VISIBLE);
+                    mA11ySettingsButton.setContentDescription(
+                            mContext.getString(R.string.audio_device_settings_content_description,
+                            mediaDevice.getName()));
+                    mA11ySettingsButton.setOnClickListener((view) -> {
+                        openDeviceSettings(baseUri);
+                    });
+                } else {
+                    ControlWidget.TooltipConfig toolTipConfig = new ControlWidget.TooltipConfig();
+                    toolTipConfig.setShouldShowTooltip(true);
+                    toolTipConfig.setTooltipText(mTooltipText);
+                    mWidget.setTooltipConfig(toolTipConfig);
+
+                    mWidget.setOnKeyListener(
+                            (v, keyCode, event) -> {
+                                if (event.getAction() != KeyEvent.ACTION_UP) {
+                                    return false;
+                                }
+                                int dpadArrow = mIsRtl ?
+                                        KeyEvent.KEYCODE_DPAD_LEFT : KeyEvent.KEYCODE_DPAD_RIGHT;
+                                if (mMediaDevice != null
+                                        && (keyCode == dpadArrow
+                                        || (keyCode == KeyEvent.KEYCODE_DPAD_CENTER
+                                        && event.isLongPress()))) {
+
+                                    return openDeviceSettings(baseUri);
+                                }
+                                return false;
+                            });
+
+                    mA11ySettingsButton.setVisibility(View.GONE);
+                }
+            } else {
+                mA11ySettingsButton.setVisibility(View.GONE);
+            }
+        }
+
+        private boolean openDeviceSettings(@NonNull String baseUri) {
+            Uri uri = Uri.parse(baseUri);
+            if (mMediaDevice.getDeviceType()
+                    == MediaDeviceType.TYPE_BLUETOOTH_DEVICE) {
+                uri =
+                        Uri.withAppendedPath(
+                                uri,
+                                ((BluetoothMediaDevice) mMediaDevice)
+                                        .getCachedDevice()
+                                        .getAddress());
+            }
+
+            mSavedDeviceId = mMediaDevice.getId();
+            mCallback.openDeviceSettings(
+                    uri.toString(),
+                    mTitle.getText(),
+                    getSummary(mMediaDevice, /* focused= */ false),
+                    mMediaDevice.getId());
+
+            return true;
         }
 
         private void setRadioButtonColor() {
-            if (itemView.hasFocus()) {
+            if (mWidget.hasFocus()) {
                 mRadioButton.getButtonDrawable().setTint(
                         mRadioButton.isChecked() ? mCheckedRadioTint : mFocusedRadioTint);
             } else {
@@ -213,20 +352,30 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
         }
 
         private void setSummary(MediaDevice mediaDevice) {
-            CharSequence summary;
+            CharSequence summary = getSummary(mediaDevice, mWidget.hasFocus());
+            if (mediaDevice.getDeviceType() == MediaDeviceType.TYPE_PHONE_DEVICE
+                    && mContext.getResources().getBoolean(
+                    com.android.systemui.tv.res.R.bool.
+                            config_audioOutputInternalSpeakerGroupedWithSpdif)) {
+                mSubtitle.setText(mContext.getResources().getString(
+                        R.string.media_output_internal_speaker_spdif_subtitle));
+            } else {
+                mSubtitle.setText(summary);
+            }
+            mSubtitle.setVisibility(summary == null || summary.isEmpty()
+                    ? View.GONE : View.VISIBLE);
+        }
+
+        private CharSequence getSummary(MediaDevice mediaDevice, boolean focused) {
             if (mediaDevice.getState()
                     == LocalMediaManager.MediaDeviceState.STATE_CONNECTING_FAILED) {
-                summary = mContext.getString(
-                        com.android.systemui.R.string.media_output_dialog_connect_failed);
+                return mContext.getString(
+                        com.android.systemui.res.R.string.media_output_dialog_connect_failed);
             } else {
-                summary = mediaDevice.getSummaryForTv(itemView.hasFocus()
+                return mediaDevice.getSummaryForTv(focused
                         ? R.color.media_dialog_low_battery_focused
                         : R.color.media_dialog_low_battery_unfocused);
             }
-
-            mSubtitle.setText(summary);
-            mSubtitle.setVisibility(summary == null || summary.isEmpty()
-                    ? View.GONE : View.VISIBLE);
         }
 
         private void transferOutput(MediaDevice mediaDevice) {
@@ -255,12 +404,12 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
         }
 
         void onBindNewDevice() {
-            mIcon.setImageResource(com.android.systemui.R.drawable.ic_add);
+            mIcon.setImageResource(com.android.systemui.res.R.drawable.ic_add);
             mTitle.setText(R.string.media_output_dialog_pairing_new);
             mSubtitle.setVisibility(View.GONE);
             mRadioButton.setVisibility(View.GONE);
 
-            itemView.setOnClickListener(v -> launchBluetoothSettings());
+            mWidget.setOnClickListener(v -> launchBluetoothSettings());
         }
 
         private void launchBluetoothSettings() {
@@ -284,6 +433,57 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
             }
             return false;
         }
+
+        static String getBaseUriForDevice(Context context, MediaDevice device) {
+            int resourceId;
+
+            int deviceType = device.getDeviceType();
+
+            if (deviceType == MediaDeviceType.TYPE_USB_C_AUDIO_DEVICE) {
+                int routeType = device.getRouteType();
+                switch (routeType) {
+                    case MediaRoute2Info.TYPE_HDMI:
+                        resourceId = R.string.audio_output_hdmi_slice_uri;
+                        break;
+                    case MediaRoute2Info.TYPE_HDMI_ARC:
+                    case MediaRoute2Info.TYPE_HDMI_EARC:
+                        resourceId = R.string.audio_output_hdmi_e_arc_slice_uri;
+                        break;
+                    case MediaRoute2Info.TYPE_USB_HEADSET:
+                    case MediaRoute2Info.TYPE_USB_DEVICE:
+                    case MediaRoute2Info.TYPE_USB_ACCESSORY:
+                        resourceId = R.string.audio_output_usb_slice_uri;
+                        break;
+                    default:
+                        return null;
+                }
+            } else {
+                switch (deviceType) {
+                    case MediaDeviceType.TYPE_PHONE_DEVICE:
+                        resourceId = R.string.audio_output_builtin_speaker_slice_uri;
+                        break;
+                    case MediaDeviceType.TYPE_BLUETOOTH_DEVICE:
+                        resourceId = R.string.audio_output_bluetooth_slice_uri;
+                        break;
+                    case MediaDeviceType.TYPE_3POINT5_MM_AUDIO_DEVICE:
+                        resourceId = R.string.audio_output_wired_headphone_slice_uri;
+                        break;
+                    case MediaDeviceType.TYPE_CAST_DEVICE:
+                        resourceId = R.string.audio_output_cast_device_slice_uri;
+                        break;
+                    case MediaDeviceType.TYPE_CAST_GROUP_DEVICE:
+                        resourceId = R.string.audio_output_cast_group_slice_uri;
+                        break;
+                    case MediaDeviceType.TYPE_REMOTE_AUDIO_VIDEO_RECEIVER:
+                        resourceId = R.string.audio_output_remote_avr_slice_uri;
+                        break;
+                    default:
+                        return null;
+                }
+            }
+
+            return context.getString(resourceId);
+        }
     }
 
     private static class DividerViewHolder extends RecyclerView.ViewHolder {
@@ -306,4 +506,10 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
         }
 
     }
+
+    interface PanelCallback {
+        void openDeviceSettings(String uri, CharSequence title, CharSequence subtitle, String id);
+
+        void dismissDialog();
+    }
 }
diff --git a/src/com/android/systemui/tv/media/TvMediaOutputDialogActivity.java b/src/com/android/systemui/tv/media/TvMediaOutputDialogActivity.java
index 50142e3..b698bc0 100644
--- a/src/com/android/systemui/tv/media/TvMediaOutputDialogActivity.java
+++ b/src/com/android/systemui/tv/media/TvMediaOutputDialogActivity.java
@@ -17,43 +17,27 @@
 package com.android.systemui.tv.media;
 
 import android.annotation.SuppressLint;
-import android.app.Activity;
-import android.app.KeyguardManager;
-import android.content.Context;
 import android.content.res.Resources;
 import android.graphics.Rect;
-import android.media.AudioManager;
 import android.media.MediaRouter2;
-import android.media.session.MediaSessionManager;
 import android.os.Bundle;
-import android.os.Handler;
-import android.os.Looper;
-import android.os.PowerExemptionManager;
 import android.util.DisplayMetrics;
 import android.util.Log;
 import android.view.Gravity;
-import android.view.View;
 import android.view.Window;
 import android.view.WindowManager;
 
-import com.android.internal.widget.LinearLayoutManager;
-import com.android.internal.widget.RecyclerView;
-import com.android.settingslib.bluetooth.LocalBluetoothManager;
-import com.android.settingslib.media.MediaDevice;
+import androidx.fragment.app.FragmentActivity;
+import androidx.fragment.app.FragmentManager;
+import androidx.fragment.app.FragmentTransaction;
+
 import com.android.settingslib.media.flags.Flags;
-import com.android.systemui.animation.DialogTransitionAnimator;
-import com.android.systemui.flags.FeatureFlags;
-import com.android.systemui.media.dialog.MediaSwitchingController;
-import com.android.systemui.media.nearby.NearbyMediaDevicesManager;
-import com.android.systemui.plugins.ActivityStarter;
-import com.android.systemui.settings.UserTracker;
-import com.android.systemui.statusbar.notification.collection.notifcollection.CommonNotifCollection;
+import com.android.systemui.tv.media.settings.SliceFragment;
 import com.android.systemui.tv.res.R;
-import com.android.systemui.volume.panel.domain.interactor.VolumePanelGlobalStateInteractor;
+import com.android.tv.twopanelsettings.slices.SlicesConstants;
 
 import java.util.Collections;
 
-import javax.annotation.Nullable;
 import javax.inject.Inject;
 
 /**
@@ -63,56 +47,16 @@ import javax.inject.Inject;
  * {@link com.android.systemui.media.dialog.MediaOutputDialogReceiver} or by calling {@link
  * MediaRouter2#showSystemOutputSwitcher()}
  */
-public class TvMediaOutputDialogActivity extends Activity
-        implements MediaSwitchingController.Callback {
+public class TvMediaOutputDialogActivity extends FragmentActivity {
     private static final String TAG = TvMediaOutputDialogActivity.class.getSimpleName();
     private static final boolean DEBUG = false;
 
-    private TvMediaOutputController mMediaOutputController;
-    private TvMediaOutputAdapter mAdapter;
-
-    private final MediaSessionManager mMediaSessionManager;
-    private final LocalBluetoothManager mLocalBluetoothManager;
-    private final ActivityStarter mActivityStarter;
-    private final CommonNotifCollection mCommonNotifCollection;
-    private final DialogTransitionAnimator mDialogTransitionAnimator;
-    private final NearbyMediaDevicesManager mNearbyMediaDevicesManager;
-    private final AudioManager mAudioManager;
-    private final PowerExemptionManager mPowerExemptionManager;
-    private final KeyguardManager mKeyguardManager;
-    private final FeatureFlags mFeatureFlags;
-    private final VolumePanelGlobalStateInteractor mVolumePanelGlobalStateInteractor;
-    private final UserTracker mUserTracker;
-
-    protected final Handler mMainThreadHandler = new Handler(Looper.getMainLooper());
-    private String mActiveDeviceId;
+    private FragmentManager mFragmentManager;
+    private final OutputDevicesFragment mOutputDevicesFragment;
 
     @Inject
-    public TvMediaOutputDialogActivity(
-            MediaSessionManager mediaSessionManager,
-            @Nullable LocalBluetoothManager localBluetoothManager,
-            ActivityStarter activityStarter,
-            CommonNotifCollection commonNotifCollection,
-            DialogTransitionAnimator dialogTransitionAnimator,
-            NearbyMediaDevicesManager nearbyMediaDevicesManager,
-            AudioManager audioManager,
-            PowerExemptionManager powerExemptionManager,
-            KeyguardManager keyguardManager,
-            FeatureFlags featureFlags,
-            VolumePanelGlobalStateInteractor volumePanelGlobalStateInteractor,
-            UserTracker userTracker) {
-        mMediaSessionManager = mediaSessionManager;
-        mLocalBluetoothManager = localBluetoothManager;
-        mActivityStarter = activityStarter;
-        mCommonNotifCollection = commonNotifCollection;
-        mDialogTransitionAnimator = dialogTransitionAnimator;
-        mNearbyMediaDevicesManager = nearbyMediaDevicesManager;
-        mAudioManager = audioManager;
-        mPowerExemptionManager = powerExemptionManager;
-        mKeyguardManager = keyguardManager;
-        mFeatureFlags = featureFlags;
-        mVolumePanelGlobalStateInteractor = volumePanelGlobalStateInteractor;
-        mUserTracker = userTracker;
+    public TvMediaOutputDialogActivity(OutputDevicesFragment outputDevicesFragment) {
+        mOutputDevicesFragment = outputDevicesFragment;
     }
 
     @SuppressLint("MissingPermission")
@@ -128,23 +72,6 @@ public class TvMediaOutputDialogActivity extends Activity
 
         setContentView(R.layout.media_output_dialog);
 
-        mMediaOutputController =
-                new TvMediaOutputController(
-                        this,
-                        getPackageName(),
-                        mMediaSessionManager,
-                        mLocalBluetoothManager,
-                        mActivityStarter,
-                        mCommonNotifCollection,
-                        mDialogTransitionAnimator,
-                        mNearbyMediaDevicesManager,
-                        mAudioManager,
-                        mPowerExemptionManager,
-                        mKeyguardManager,
-                        mFeatureFlags,
-                        mVolumePanelGlobalStateInteractor,
-                        mUserTracker);
-        mAdapter = new TvMediaOutputAdapter(this, mMediaOutputController, this);
 
         Resources res = getResources();
         DisplayMetrics metrics = res.getDisplayMetrics();
@@ -165,105 +92,45 @@ public class TvMediaOutputDialogActivity extends Activity
         window.setAttributes(lp);
         window.setElevation(getWindow().getElevation() + 5);
         window.setTitle(getString(
-                com.android.systemui.R.string.media_output_dialog_accessibility_title));
+                com.android.systemui.res.R.string.media_output_dialog_accessibility_title));
 
         window.getDecorView().addOnLayoutChangeListener(
                 (v, left, top, right, bottom, oldLeft, oldTop, oldRight, oldBottom)
                         -> findViewById(android.R.id.content).setUnrestrictedPreferKeepClearRects(
                         Collections.singletonList(new Rect(left, top, right, bottom))));
 
-        RecyclerView devicesRecyclerView = requireViewById(R.id.device_list);
-        devicesRecyclerView.setLayoutManager(new LayoutManagerWrapper(this));
-        devicesRecyclerView.setAdapter(mAdapter);
-
-        int itemSpacingPx = getResources().getDimensionPixelSize(R.dimen.media_dialog_item_spacing);
-        devicesRecyclerView.addItemDecoration(new SpacingDecoration(itemSpacingPx));
-    }
-
-    @Override
-    public void onStart() {
-        super.onStart();
-        mMediaOutputController.start(this);
-    }
-
-    @Override
-    public void onStop() {
-        mMediaOutputController.stop();
-        super.onStop();
-    }
-
-    private void refresh(boolean deviceSetChanged) {
-        if (DEBUG) Log.d(TAG, "refresh: deviceSetChanged " + deviceSetChanged);
-        // If the dialog is going away or is already refreshing, do nothing.
-        if (mMediaOutputController.isRefreshing()) {
-            return;
-        }
-        mMediaOutputController.setRefreshing(true);
-        mAdapter.updateItems();
-    }
-
-    @Override
-    public void onMediaChanged() {
-        // NOOP
+        mFragmentManager = getSupportFragmentManager();
+        mFragmentManager.setFragmentResultListener(
+                "deviceSettings",
+                this,
+                (key, bundle) -> {
+                    if (key.equals("deviceSettings")) {
+                        CharSequence title = bundle.getString("title");
+                        CharSequence subtitle = bundle.getCharSequence("subtitle");
+                        String uri = bundle.getString("uri");
+
+                        SliceFragment sliceFragment = new SliceFragment();
+                        Bundle args = new Bundle();
+                        args.putString(SlicesConstants.TAG_TARGET_URI, uri);
+                        args.putCharSequence(SlicesConstants.TAG_SCREEN_TITLE, title);
+                        args.putCharSequence(SliceFragment.TAG_SCREEN_SUBTITLE, subtitle);
+                        sliceFragment.setArguments(args);
+
+                        mFragmentManager
+                                .beginTransaction()
+                                .replace(R.id.media_output_fragment, sliceFragment)
+                                .addToBackStack("device")
+                                .commit();
+                    }
+                });
+
+        showMainFragment();
     }
 
-    @Override
-    public void onMediaStoppedOrPaused() {
-        // NOOP
+    private void showMainFragment() {
+        FragmentTransaction transaction = mFragmentManager.beginTransaction();
+        transaction.replace(R.id.media_output_fragment, mOutputDevicesFragment);
+        transaction.commit();
     }
 
-    @Override
-    public void onRouteChanged() {
-        mMainThreadHandler.post(() -> refresh(/* deviceSetChanged= */ false));
-        MediaDevice activeDevice = mMediaOutputController.getCurrentConnectedMediaDevice();
-        if (mActiveDeviceId != null && !mActiveDeviceId.equals(activeDevice.getId())) {
-            mMediaOutputController.showVolumeDialog();
-        }
-        mActiveDeviceId = activeDevice.getId();
-    }
-
-    @Override
-    public void onDeviceListChanged() {
-        mMainThreadHandler.post(() -> refresh(/* deviceSetChanged= */ true));
-        if (mActiveDeviceId == null
-                && mMediaOutputController.getCurrentConnectedMediaDevice() != null) {
-            mActiveDeviceId = mMediaOutputController.getCurrentConnectedMediaDevice().getId();
-        }
-    }
-
-    @Override
-    public void dismissDialog() {
-        if (DEBUG) Log.d(TAG, "dismissDialog");
-        finish();
-    }
-
-    private class LayoutManagerWrapper extends LinearLayoutManager {
-        LayoutManagerWrapper(Context context) {
-            super(context);
-        }
-
-        @Override
-        public void onLayoutCompleted(RecyclerView.State state) {
-            super.onLayoutCompleted(state);
-            mMediaOutputController.setRefreshing(false);
-            mMediaOutputController.refreshDataSetIfNeeded();
-        }
-    }
-
-    private static class SpacingDecoration extends RecyclerView.ItemDecoration {
-        private final int mMarginPx;
-
-        SpacingDecoration(int marginPx) {
-            mMarginPx = marginPx;
-        }
-
-        @Override
-        public void getItemOffsets(Rect outRect, View view, RecyclerView parent,
-                RecyclerView.State state) {
-            if (parent.getChildAdapterPosition(view) == 0) {
-                outRect.top = mMarginPx;
-            }
-            outRect.bottom = mMarginPx;
-        }
-    }
 }
diff --git a/src/com/android/systemui/tv/media/settings/BasicCenteredSlicePreference.java b/src/com/android/systemui/tv/media/settings/BasicCenteredSlicePreference.java
new file mode 100644
index 0000000..ecc3f1e
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/BasicCenteredSlicePreference.java
@@ -0,0 +1,81 @@
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
+package com.android.systemui.tv.media.settings;
+
+import android.content.Context;
+import android.util.AttributeSet;
+import android.view.View;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.preference.PreferenceViewHolder;
+
+import com.android.systemui.tv.res.R;
+import com.android.tv.twopanelsettings.slices.SlicePreference;
+
+
+/**
+ * Basic slice preference for one panel settings that only shows the title in a pill shape.
+ * Alternative to the {@link BasicSlicePreference}.
+ */
+public class BasicCenteredSlicePreference extends SlicePreference implements TooltipPreference {
+    private ControlWidget.TooltipConfig mTooltipConfig = new ControlWidget.TooltipConfig();
+
+    public BasicCenteredSlicePreference(Context context) {
+        this(context, null);
+    }
+
+    public BasicCenteredSlicePreference(Context context, @Nullable AttributeSet attrs) {
+        super(context, attrs);
+        setLayoutResource(R.layout.basic_centered_slice_pref);
+    }
+
+    @Override
+    public void onBindViewHolder(@NonNull PreferenceViewHolder holder) {
+        super.onBindViewHolder(holder);
+        BasicCenteredControlWidget widget = (BasicCenteredControlWidget) holder.itemView;
+        widget.setEnabled(this.isEnabled());
+        widget.setTooltipConfig(mTooltipConfig);
+    }
+
+    /** Set tool tip related attributes. */
+    @Override
+    public void setTooltipConfig(ControlWidget.TooltipConfig tooltipConfig) {
+        if (!this.mTooltipConfig.equals(tooltipConfig)) {
+            this.mTooltipConfig = tooltipConfig;
+            notifyChanged();
+        }
+    }
+
+    static class BasicCenteredControlWidget extends ControlWidget {
+
+        public BasicCenteredControlWidget(Context context) {
+            this(context, /* attrs= */ null);
+        }
+
+        public BasicCenteredControlWidget(Context context, @Nullable AttributeSet attrs) {
+            this(context, attrs, /* defStyleAttr= */ 0);
+        }
+
+        public BasicCenteredControlWidget(Context context, @Nullable AttributeSet attrs,
+                int defStyleAttr) {
+            super(context, attrs, defStyleAttr);
+            View.inflate(context, R.layout.basic_centered_control_widget, /* root= */ this);
+        }
+    }
+
+}
diff --git a/src/com/android/systemui/tv/media/settings/BasicSlicePreference.java b/src/com/android/systemui/tv/media/settings/BasicSlicePreference.java
new file mode 100644
index 0000000..384e4ed
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/BasicSlicePreference.java
@@ -0,0 +1,78 @@
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
+package com.android.systemui.tv.media.settings;
+
+import android.content.Context;
+import android.util.AttributeSet;
+import android.view.View;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.preference.PreferenceViewHolder;
+
+import com.android.systemui.tv.res.R;
+import com.android.tv.twopanelsettings.slices.SlicePreference;
+
+
+/**
+ * Basic slice preference for one panel settings that only shows the title, subtitle and icon.
+ * If there's only a title, the {@link BasicCenteredSlicePreference} might be used.
+ */
+public class BasicSlicePreference extends SlicePreference implements TooltipPreference {
+    private ControlWidget.TooltipConfig mTooltipConfig = new ControlWidget.TooltipConfig();
+
+    public BasicSlicePreference(Context context) {
+        this(context, null);
+    }
+
+    public BasicSlicePreference(Context context, @Nullable AttributeSet attrs) {
+        super(context, attrs);
+        setLayoutResource(R.layout.basic_slice_pref);
+    }
+
+    @Override
+    public void onBindViewHolder(@NonNull PreferenceViewHolder holder) {
+        super.onBindViewHolder(holder);
+        BasicControlWidget widget = (BasicControlWidget) holder.itemView;
+        widget.setEnabled(this.isEnabled());
+        widget.setTooltipConfig(mTooltipConfig);
+    }
+
+    /** Set tool tip related attributes. */
+    @Override
+    public void setTooltipConfig(ControlWidget.TooltipConfig tooltipConfig) {
+        if (!this.mTooltipConfig.equals(tooltipConfig)) {
+            this.mTooltipConfig = tooltipConfig;
+            notifyChanged();
+        }
+    }
+
+    static class BasicControlWidget extends ControlWidget {
+        public BasicControlWidget(Context context) {
+            this(context, /* attrs= */ null);
+        }
+
+        public BasicControlWidget(Context context, @Nullable AttributeSet attrs) {
+            this(context, attrs, /* defStyleAttr= */ 0);
+        }
+
+        public BasicControlWidget(Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
+            super(context, attrs, defStyleAttr);
+            View.inflate(context, R.layout.basic_control_widget, /* root= */ this);
+        }
+    }
+}
diff --git a/src/com/android/systemui/tv/media/settings/CategorySlicePreference.java b/src/com/android/systemui/tv/media/settings/CategorySlicePreference.java
new file mode 100644
index 0000000..22b2340
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/CategorySlicePreference.java
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
+package com.android.systemui.tv.media.settings;
+
+import android.content.Context;
+import android.util.AttributeSet;
+
+import com.android.systemui.tv.res.R;
+import com.android.tv.twopanelsettings.slices.CustomContentDescriptionPreferenceCategory;
+
+/**
+ * Slice element for one panel settings that displays a section heading to split settings into
+ * multiple subgroups.
+ */
+public class CategorySlicePreference extends CustomContentDescriptionPreferenceCategory {
+
+    public CategorySlicePreference(Context context) {
+        this(context, null);
+    }
+
+    public CategorySlicePreference(Context context, AttributeSet attrs) {
+        super(context, attrs);
+        setLayoutResource(R.layout.category_slice_preference);
+    }
+}
diff --git a/src/com/android/systemui/tv/media/settings/CenteredImageSpan.java b/src/com/android/systemui/tv/media/settings/CenteredImageSpan.java
new file mode 100644
index 0000000..f2e709b
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/CenteredImageSpan.java
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
+package com.android.systemui.tv.media.settings;
+
+import android.graphics.Canvas;
+import android.graphics.Paint;
+import android.graphics.Rect;
+import android.graphics.drawable.Drawable;
+import android.text.style.ImageSpan;
+
+/** An ImageSpan for a Drawable that is centered vertically in the line. */
+public class CenteredImageSpan extends ImageSpan {
+
+    private final Drawable mDrawable;
+
+    public CenteredImageSpan(Drawable drawable) {
+        super(drawable);
+        mDrawable = drawable;
+    }
+
+    @Override
+    public int getSize(
+            Paint paint, CharSequence text, int start, int end, Paint.FontMetricsInt fontMetrics) {
+        final Rect rect = mDrawable.getBounds();
+
+        if (fontMetrics != null) {
+            Paint.FontMetricsInt fmPaint = paint.getFontMetricsInt();
+            int fontHeight = fmPaint.descent - fmPaint.ascent;
+            int drHeight = rect.bottom - rect.top;
+            int centerY = fmPaint.ascent + fontHeight / 2;
+
+            fontMetrics.ascent = centerY - drHeight / 2;
+            fontMetrics.top = fontMetrics.ascent;
+            fontMetrics.bottom = centerY + drHeight / 2;
+            fontMetrics.descent = fontMetrics.bottom;
+        }
+        return rect.right;
+    }
+
+    @Override
+    public void draw(
+            Canvas canvas,
+            CharSequence text,
+            int start,
+            int end,
+            float x,
+            int top,
+            int y,
+            int bottom,
+            Paint paint) {
+        canvas.save();
+        final int transY = (bottom - mDrawable.getBounds().bottom) / 2;
+        canvas.translate(x, transY);
+        mDrawable.draw(canvas);
+        canvas.restore();
+    }
+}
diff --git a/src/com/android/systemui/tv/media/settings/CheckboxSlicePreference.java b/src/com/android/systemui/tv/media/settings/CheckboxSlicePreference.java
new file mode 100644
index 0000000..7085f7b
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/CheckboxSlicePreference.java
@@ -0,0 +1,112 @@
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
+package com.android.systemui.tv.media.settings;
+
+import android.content.Context;
+import android.content.res.Resources;
+import android.graphics.drawable.Drawable;
+import android.util.AttributeSet;
+import android.view.View;
+import android.widget.CheckBox;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.preference.PreferenceViewHolder;
+
+import com.android.systemui.tv.res.R;
+import com.android.tv.twopanelsettings.slices.SliceCheckboxPreference;
+import com.android.tv.twopanelsettings.slices.compat.core.SliceActionImpl;
+
+/**
+ * Slice preference for one panel settings which shows a checkbox in addition to the capabilities of
+ * {@link BasicSlicePreference}.
+ */
+public class CheckboxSlicePreference extends SliceCheckboxPreference implements TooltipPreference {
+    private ControlWidget.TooltipConfig mTooltipConfig = new ControlWidget.TooltipConfig();
+    private View mItemView;
+    private CheckBox mCheckBox;
+
+    private final int mFocusedCheckboxTint;
+    private final int mUnfocusedCheckboxTint;
+    private final int mCheckedCheckboxTint;
+
+    public CheckboxSlicePreference(Context context, SliceActionImpl action) {
+        this(context, null, action);
+    }
+
+    public CheckboxSlicePreference(Context context, @Nullable AttributeSet attrs,
+            SliceActionImpl action) {
+        super(context, attrs, action);
+        setLayoutResource(R.layout.checkbox_slice_pref);
+
+        Resources res = context.getResources();
+        mFocusedCheckboxTint = res.getColor(R.color.media_dialog_radio_button_focused);
+        mUnfocusedCheckboxTint = res.getColor(R.color.media_dialog_radio_button_unfocused);
+        mCheckedCheckboxTint = res.getColor(R.color.media_dialog_radio_button_checked);
+    }
+
+    @Override
+    public void onBindViewHolder(@NonNull PreferenceViewHolder holder) {
+        super.onBindViewHolder(holder);
+        mItemView = holder.itemView;
+        mItemView.setOnFocusChangeListener((v, hasFocus) -> updateColors());
+
+        CheckboxControlWidget widget = (CheckboxControlWidget) mItemView;
+        widget.setEnabled(this.isEnabled());
+        widget.setTooltipConfig(mTooltipConfig);
+
+        mCheckBox = mItemView.findViewById(android.R.id.checkbox);
+        mCheckBox.setOnCheckedChangeListener((buttonView, isChecked) -> updateColors());
+        updateColors();
+    }
+
+    private void updateColors() {
+        Drawable drawable = mCheckBox.getButtonDrawable();
+        if (mItemView.hasFocus()) {
+            drawable.setTint(mCheckBox.isChecked() ? mCheckedCheckboxTint : mFocusedCheckboxTint);
+        } else {
+            drawable.setTint(mUnfocusedCheckboxTint);
+        }
+    }
+
+    /** Set tool tip related attributes. */
+    @Override
+    public void setTooltipConfig(ControlWidget.TooltipConfig tooltipConfig) {
+        if (!this.mTooltipConfig.equals(tooltipConfig)) {
+            this.mTooltipConfig = tooltipConfig;
+            notifyChanged();
+        }
+    }
+
+    static class CheckboxControlWidget extends ControlWidget {
+
+        public CheckboxControlWidget(Context context) {
+            this(context, /* attrs= */ null);
+        }
+
+        public CheckboxControlWidget(Context context, @Nullable AttributeSet attrs) {
+            this(context, attrs, /* defStyleAttr= */ 0);
+        }
+
+        public CheckboxControlWidget(Context context, @Nullable AttributeSet attrs,
+                int defStyleAttr) {
+            super(context, attrs, defStyleAttr);
+            View.inflate(context, R.layout.checkbox_control_widget, /* root= */ this);
+        }
+    }
+
+}
diff --git a/src/com/android/systemui/tv/media/settings/ControlWidget.java b/src/com/android/systemui/tv/media/settings/ControlWidget.java
new file mode 100644
index 0000000..4fcb4df
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/ControlWidget.java
@@ -0,0 +1,361 @@
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
+package com.android.systemui.tv.media.settings;
+
+import android.content.Context;
+import android.graphics.Rect;
+import android.graphics.drawable.Drawable;
+import android.os.CountDownTimer;
+import android.util.AttributeSet;
+import android.util.Log;
+import android.view.Gravity;
+import android.view.KeyEvent;
+import android.view.View;
+import android.view.ViewGroup;
+import android.view.ViewTreeObserver;
+import android.widget.FrameLayout;
+import android.widget.ImageView;
+import android.widget.PopupWindow;
+import android.widget.TextView;
+
+import androidx.annotation.Nullable;
+
+import java.util.Objects;
+
+import com.android.systemui.tv.res.R;
+
+/**
+ * Base control widget that has default tooltip functionality.
+ **/
+public class ControlWidget extends FrameLayout
+        implements View.OnFocusChangeListener, View.OnKeyListener {
+    private static final String TAG = ControlWidget.class.getSimpleName();
+    private static final boolean DEBUG = false;
+
+    private static final int TOOLTIP_DELAY_MS = 2000;
+    private TooltipConfig mTooltipConfig;
+    private View mTooltipView;
+    private PopupWindow mTooltipWindow;
+    @Nullable
+    private OnKeyListener mExternalOnKeyListener;
+    @Nullable
+    private OnFocusChangeListener mExternalOnFocusChangeListener;
+
+    private final CountDownTimer mTooltipTimer;
+
+    public ControlWidget(Context context) {
+        this(context, /* attrs= */ null);
+    }
+
+    public ControlWidget(Context context, @Nullable AttributeSet attrs) {
+        this(context, attrs, /* defStyleAttr= */ 0);
+    }
+
+    @SuppressWarnings("nullness")
+    public ControlWidget(Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
+        super(context, attrs, defStyleAttr);
+        super.setOnFocusChangeListener(this);
+        super.setOnKeyListener(this);
+        this.mTooltipTimer = createTooltipTimer(TOOLTIP_DELAY_MS);
+    }
+
+    @Override
+    public void setEnabled(boolean enabled) {
+        if (this.isEnabled() == enabled) {
+            return;
+        }
+        super.setEnabled(enabled);
+        setAlpha(enabled ? 1f : 0.6f);
+    }
+
+    @Override
+    public void setOnKeyListener(@Nullable OnKeyListener onKeyListener) {
+        this.mExternalOnKeyListener = onKeyListener;
+    }
+
+    @Override
+    public void setOnFocusChangeListener(@Nullable OnFocusChangeListener onFocusChangeListener) {
+        this.mExternalOnFocusChangeListener = onFocusChangeListener;
+    }
+
+    public void setTooltipConfig(TooltipConfig tooltipConfig) {
+        if (Objects.equals(this.mTooltipConfig, tooltipConfig)) {
+            return;
+        }
+
+        this.mTooltipConfig = tooltipConfig;
+
+        if (tooltipConfig == null) {
+            dismissTooltipWindow();
+        } else {
+            // reflect tool tip config changes
+            if (!tooltipConfig.getShouldShowTooltip()) {
+                dismissTooltipWindow();
+            }
+
+            if (mTooltipView != null && mTooltipWindow != null && mTooltipWindow.isShowing()) {
+                loadText();
+                loadSummary();
+                loadImage();
+            }
+        }
+    }
+
+    private boolean shouldAbortShowingTooltip() {
+        return !isFocused() || mTooltipConfig == null || !mTooltipConfig.getShouldShowTooltip()
+                || !isAttachedToWindow();
+    }
+
+    private void showTooltipView() {
+        if (shouldAbortShowingTooltip()) {
+            return;
+        }
+        int width = getContext().getResources().getDimensionPixelSize(R.dimen.tooltip_window_width);
+
+        // Construct tooltip pop-up window.
+        mTooltipView = View.inflate(this.getContext(), R.layout.tooltip_window, null);
+        mTooltipView.getViewTreeObserver().addOnGlobalLayoutListener(
+                new ViewTreeObserver.OnGlobalLayoutListener() {
+
+                    @Override
+                    public void onGlobalLayout() {
+                        if (DEBUG) Log.d(TAG, "onGlobalLayoutListener");
+                        mTooltipView.getViewTreeObserver().removeOnGlobalLayoutListener(this);
+                        if (shouldAbortShowingTooltip()) {
+                            return;
+                        }
+                        // Calculate tooltip location on screen.
+                        Rect location = locateView(ControlWidget.this);
+                        int[] position = ControlWidget.this.calculateWindowOffset(location);
+                        if (DEBUG) {
+                            Log.d(TAG,
+                                    "new position, x=" + position[0] + ", y=" + position[1]);
+                        }
+
+                        // Only update the position, not the size
+                        mTooltipWindow.update(position[0], position[1], -1, -1);
+                        mTooltipView.postDelayed(() -> {
+                            if (shouldAbortShowingTooltip()) {
+                                return;
+                            }
+                            if (DEBUG) Log.d(TAG, "postDelayed, make visible");
+                            mTooltipView.setVisibility(VISIBLE);
+                        }, 100);
+                    }
+                });
+
+        mTooltipWindow = new PopupWindow(mTooltipView, width, ViewGroup.LayoutParams.WRAP_CONTENT,
+                false);
+        mTooltipWindow.setAnimationStyle(R.style.ControlWidgetTooltipWindowAnimation);
+        mTooltipView.setVisibility(INVISIBLE);
+
+        // Load image and text.
+        loadImage();
+        loadSummary();
+        loadText();
+
+        // Calculate tooltip location on screen.
+        Rect location = locateView(this);
+        int[] position = calculateWindowOffset(location);
+
+        // Display tooltip window.
+        mTooltipWindow.showAtLocation(this, Gravity.NO_GRAVITY, position[0], position[1]);
+    }
+
+    public void dismissTooltipWindow() {
+        if (mTooltipWindow != null && mTooltipWindow.isShowing()) {
+            mTooltipWindow.dismiss();
+        } else {
+            mTooltipTimer.cancel();
+        }
+    }
+
+    private static Rect locateView(View view) {
+        int[] locationInt = new int[2];
+        view.getLocationOnScreen(locationInt);
+        Rect location = new Rect();
+        location.left = locationInt[0];
+        location.top = locationInt[1];
+        location.right = location.left + view.getWidth();
+        location.bottom = location.top + view.getHeight();
+        return location;
+    }
+
+    private int[] calculateWindowOffset(Rect focusedRect) {
+        int[] windowOffset = new int[2];
+        int tooltipWidth = getContext().getResources().getDimensionPixelSize(
+                R.dimen.tooltip_window_width);
+        boolean isRtl =
+                getResources().getConfiguration().getLayoutDirection() == View.LAYOUT_DIRECTION_RTL;
+        // X offset
+        if (isRtl) {
+            // controlWidget.width  + margin
+            windowOffset[0] = focusedRect.right
+                    + getContext().getResources()
+                    .getDimensionPixelOffset(R.dimen.tooltip_window_horizontal_margin);
+        } else {
+            windowOffset[0] = -tooltipWidth
+                    - getContext().getResources()
+                    .getDimensionPixelOffset(R.dimen.tooltip_window_horizontal_margin);
+        }
+        // Y offset
+        if (mTooltipView.getMeasuredHeight() <= 0) {
+            // Height unknown -> fixed offset
+            windowOffset[1] = focusedRect.top
+                    - getContext().getResources()
+                    .getDimensionPixelOffset(R.dimen.media_dialog_margin_vertical)
+                    + getContext().getResources().getDimensionPixelSize(
+                    R.dimen.tooltip_window_vertical_margin);
+        } else {
+            // Height known -> calculate centered position
+            windowOffset[1] = (focusedRect.top + focusedRect.bottom) / 2
+                    - mTooltipView.getMeasuredHeight() / 2
+                    - getContext().getResources()
+                    .getDimensionPixelOffset(R.dimen.media_dialog_margin_vertical);
+        }
+
+        return windowOffset;
+    }
+
+    private void loadText() {
+        CharSequence text = mTooltipConfig.getTooltipText();
+        TextView textView = mTooltipView.requireViewById(R.id.tooltip_text);
+
+        if (text == null || text.isEmpty()) {
+            textView.setVisibility(GONE);
+        } else {
+            textView.setVisibility(VISIBLE);
+            textView.setText(text);
+        }
+    }
+
+    private void loadSummary() {
+        CharSequence summary = mTooltipConfig.getTooltipSummary();
+        TextView summaryView = mTooltipView.requireViewById(R.id.tooltip_summary);
+
+        if (summary == null || summary.isEmpty()) {
+            summaryView.setVisibility(GONE);
+        } else {
+            summaryView.setVisibility(VISIBLE);
+            summaryView.setText(summary);
+        }
+    }
+
+    private void loadImage() {
+        ImageView tooltipImage = mTooltipView.requireViewById(R.id.tooltip_image);
+        Drawable imageDrawable = mTooltipConfig.getImageDrawable();
+        if (imageDrawable == null) {
+            tooltipImage.setVisibility(GONE);
+        } else {
+            tooltipImage.setImageDrawable(imageDrawable);
+            tooltipImage.setVisibility(VISIBLE);
+        }
+    }
+
+    private CountDownTimer createTooltipTimer(long delayMs) {
+        return new CountDownTimer(delayMs, delayMs) {
+            @Override
+            public void onTick(long millisUntilFinished) {
+            }
+
+            @Override
+            public void onFinish() {
+                showTooltipView();
+            }
+        };
+    }
+
+    @Override
+    public void onFocusChange(View v, boolean hasFocus) {
+        if (mExternalOnFocusChangeListener != null) {
+            mExternalOnFocusChangeListener.onFocusChange(v, hasFocus);
+        }
+        if (mTooltipConfig == null || !mTooltipConfig.getShouldShowTooltip()) {
+            return;
+        }
+        if (hasFocus) {
+            mTooltipTimer.start();
+        } else {
+            if (mTooltipWindow != null && mTooltipWindow.isShowing()) {
+                mTooltipWindow.dismiss();
+            } else {
+                mTooltipTimer.cancel();
+            }
+        }
+    }
+
+    @Override
+    public boolean onKey(View v, int keyCode, KeyEvent event) {
+        if (event.getAction() == KeyEvent.ACTION_DOWN) {
+            if (mTooltipWindow != null && mTooltipWindow.isShowing()) {
+                mTooltipWindow.dismiss();
+            } else {
+                mTooltipTimer.cancel();
+            }
+            if (mTooltipConfig != null
+                    && mTooltipConfig.getShouldShowTooltip()
+                    && isFocused()) {
+                // Start the timer in case user hover 3 seconds again.
+                mTooltipTimer.start();
+            }
+        }
+        if (mExternalOnKeyListener != null) {
+            return mExternalOnKeyListener.onKey(v, keyCode, event);
+        }
+        return false;
+    }
+
+    /** Wrapper class for callers to set tool tip related attributes. */
+    public static final class TooltipConfig {
+        private boolean mShouldShowTooltip;
+        private Drawable mImageDrawable;
+        private CharSequence mTooltipText;
+        private CharSequence mTooltipSummary;
+
+        public void setShouldShowTooltip(boolean shouldShowTooltip) {
+            this.mShouldShowTooltip = shouldShowTooltip;
+        }
+
+        public boolean getShouldShowTooltip() {
+            return mShouldShowTooltip;
+        }
+
+        public void setImageDrawable(Drawable imageDrawable) {
+            this.mImageDrawable = imageDrawable;
+        }
+
+        public Drawable getImageDrawable() {
+            return mImageDrawable;
+        }
+
+        public void setTooltipText(CharSequence tooltipText) {
+            this.mTooltipText = tooltipText;
+        }
+
+        public CharSequence getTooltipText() {
+            return mTooltipText;
+        }
+
+        public void setTooltipSummary(CharSequence tooltipSummary) {
+            this.mTooltipSummary = tooltipSummary;
+        }
+
+        public CharSequence getTooltipSummary() {
+            return mTooltipSummary;
+        }
+    }
+}
diff --git a/src/com/android/systemui/tv/media/settings/EmbeddedPreference.java b/src/com/android/systemui/tv/media/settings/EmbeddedPreference.java
new file mode 100644
index 0000000..5bbd4fe
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/EmbeddedPreference.java
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
+package com.android.systemui.tv.media.settings;
+
+import android.content.Context;
+
+import com.android.systemui.tv.res.R;
+import com.android.tv.twopanelsettings.slices.EmbeddedSlicePreference;
+
+/**
+ * Slice preference for one panel settings which shows a setting like the
+ * @link BasicSlicePreference}, but takes its content from another slice.
+ */
+public class EmbeddedPreference extends EmbeddedSlicePreference {
+
+    public EmbeddedPreference(Context context, String uri) {
+        super(context, uri);
+        setLayoutResource(R.layout.basic_slice_pref);
+    }
+
+}
diff --git a/src/com/android/systemui/tv/media/settings/IconUtil.java b/src/com/android/systemui/tv/media/settings/IconUtil.java
new file mode 100644
index 0000000..8adaefa
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/IconUtil.java
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
+package com.android.systemui.tv.media.settings;
+
+import android.content.Context;
+import android.content.res.ColorStateList;
+import android.content.res.Resources;
+import android.graphics.drawable.Drawable;
+import android.graphics.drawable.LayerDrawable;
+import android.util.Log;
+import android.view.Gravity;
+
+import com.android.systemui.tv.res.R;
+
+/**
+ * Get themed settings icon with outer circle.
+ */
+public class IconUtil {
+    private static final int INSET = 12;
+    private static final String TAG = "IconUtil";
+
+    /**
+     * Add the border and return the compound icon.
+     */
+    public static Drawable getCompoundIcon(Context context, Drawable icon) {
+        Drawable container = context.getDrawable(R.drawable.media_dialog_icon_bg);
+
+        Resources res = context.getResources();
+        try {
+            ColorStateList colorStateList = res.getColorStateList(R.color.media_dialog_icon);
+            icon.setTintList(colorStateList);
+        } catch (Exception e) {
+            Log.e(TAG, "Cannot set tint", e);
+
+        }
+
+        LayerDrawable compoundDrawable = new LayerDrawable(new Drawable[] {container, icon});
+        compoundDrawable.setLayerGravity(0, Gravity.CENTER);
+        compoundDrawable.setLayerGravity(1, Gravity.CENTER);
+        compoundDrawable.setLayerInset(1, INSET, INSET, INSET, INSET);
+        return compoundDrawable;
+    }
+}
diff --git a/src/com/android/systemui/tv/media/settings/InfoSlicePreference.java b/src/com/android/systemui/tv/media/settings/InfoSlicePreference.java
new file mode 100644
index 0000000..aa46dd7
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/InfoSlicePreference.java
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
+package com.android.systemui.tv.media.settings;
+
+import android.content.Context;
+import android.util.Pair;
+import android.view.LayoutInflater;
+import android.view.View;
+import android.view.ViewGroup;
+import android.widget.TextView;
+
+import androidx.preference.Preference;
+import androidx.preference.PreferenceViewHolder;
+
+import com.android.systemui.tv.res.R;
+import com.android.tv.twopanelsettings.slices.HasCustomContentDescription;
+
+import java.util.List;
+
+/**
+ * InfoPreference which could be used to display a list of information.
+ */
+public class InfoSlicePreference extends Preference implements HasCustomContentDescription {
+    private String mContentDescription;
+    private final List<Pair<CharSequence, CharSequence>> mInfoList;
+
+    public InfoSlicePreference(Context context, List<Pair<CharSequence, CharSequence>> infoList) {
+        super(context);
+        mInfoList = infoList;
+        setLayoutResource(R.layout.info_slice_preference);
+        setEnabled(false);
+    }
+
+    @Override
+    public void onBindViewHolder(final PreferenceViewHolder holder) {
+        super.onBindViewHolder(holder);
+        ViewGroup container = holder.itemView.requireViewById(R.id.item_container);
+        container.removeAllViews();
+        for (Pair<CharSequence, CharSequence> info : mInfoList) {
+            View view = LayoutInflater.from(getContext()).inflate(
+                    R.layout.info_slice_preference_item, container, false);
+            ((TextView) view.requireViewById(R.id.info_item_title)).setText(info.first);
+            ((TextView) view.requireViewById(R.id.info_item_summary)).setText(info.second);
+            container.addView(view);
+        }
+    }
+
+    /**
+     * Sets the accessibility content description that will be read to the TalkBack users when they
+     * focus on this preference.
+     */
+    public void setContentDescription(String contentDescription) {
+        this.mContentDescription = contentDescription;
+    }
+
+    public String getContentDescription() {
+        return mContentDescription;
+    }
+}
diff --git a/src/com/android/systemui/tv/media/settings/RadioSlicePreference.java b/src/com/android/systemui/tv/media/settings/RadioSlicePreference.java
new file mode 100644
index 0000000..bedc4a0
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/RadioSlicePreference.java
@@ -0,0 +1,106 @@
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
+package com.android.systemui.tv.media.settings;
+
+import android.content.Context;
+import android.content.res.Resources;
+import android.graphics.drawable.Drawable;
+import android.util.AttributeSet;
+import android.view.View;
+import android.widget.RadioButton;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.preference.PreferenceViewHolder;
+
+import com.android.systemui.tv.res.R;
+import com.android.tv.twopanelsettings.slices.SliceRadioPreference;
+import com.android.tv.twopanelsettings.slices.compat.core.SliceActionImpl;
+
+/**
+ * Slice preference for one panel settings which shows a radio button in addition to the
+ * capabilities of the {@link BasicSlicePreference}.
+ */
+public class RadioSlicePreference extends SliceRadioPreference implements TooltipPreference {
+    private ControlWidget.TooltipConfig mTooltipConfig = new ControlWidget.TooltipConfig();
+    private View mItemView;
+    private RadioButton mRadioButton;
+
+    private final int mFocusedRadioTint;
+    private final int mUnfocusedRadioTint;
+    private final int mCheckedRadioTint;
+
+    public RadioSlicePreference(Context context, SliceActionImpl action) {
+        super(context,  action);
+        setLayoutResource(R.layout.radio_slice_pref);
+
+        Resources res = context.getResources();
+        mFocusedRadioTint = res.getColor(R.color.media_dialog_radio_button_focused);
+        mUnfocusedRadioTint = res.getColor(R.color.media_dialog_radio_button_unfocused);
+        mCheckedRadioTint = res.getColor(R.color.media_dialog_radio_button_checked);
+    }
+
+    @Override
+    public void onBindViewHolder(@NonNull PreferenceViewHolder holder) {
+        super.onBindViewHolder(holder);
+        mItemView = holder.itemView;
+        mItemView.setOnFocusChangeListener((v, hasFocus) -> updateColors());
+
+        RadioControlWidget widget = (RadioControlWidget) mItemView;
+        widget.setEnabled(this.isEnabled());
+        widget.setTooltipConfig(mTooltipConfig);
+
+        mRadioButton = mItemView.findViewById(android.R.id.checkbox);
+        mRadioButton.setOnCheckedChangeListener((buttonView, isChecked) -> updateColors());
+        updateColors();
+    }
+
+    private void updateColors() {
+        Drawable drawable = mRadioButton.getButtonDrawable();
+        if (mItemView.hasFocus()) {
+            drawable.setTint(mRadioButton.isChecked() ? mCheckedRadioTint : mFocusedRadioTint);
+        } else {
+            drawable.setTint(mUnfocusedRadioTint);
+        }
+    }
+
+    /** Set tool tip related attributes. */
+    @Override
+    public void setTooltipConfig(ControlWidget.TooltipConfig tooltipConfig) {
+        if (!this.mTooltipConfig.equals(tooltipConfig)) {
+            this.mTooltipConfig = tooltipConfig;
+            notifyChanged();
+        }
+    }
+
+    static class RadioControlWidget extends ControlWidget {
+
+        public RadioControlWidget(Context context) {
+            this(context, /* attrs= */ null);
+        }
+
+        public RadioControlWidget(Context context, @Nullable AttributeSet attrs) {
+            this(context, attrs, /* defStyleAttr= */ 0);
+        }
+
+        public RadioControlWidget(Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
+            super(context, attrs, defStyleAttr);
+            View.inflate(context, R.layout.radio_control_widget, /* root= */ this);
+        }
+    }
+
+}
diff --git a/src/com/android/systemui/tv/media/settings/SeekbarSlicePreference.java b/src/com/android/systemui/tv/media/settings/SeekbarSlicePreference.java
new file mode 100644
index 0000000..0ad981e
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/SeekbarSlicePreference.java
@@ -0,0 +1,173 @@
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
+package com.android.systemui.tv.media.settings;
+
+import static android.view.accessibility.AccessibilityNodeInfo.AccessibilityAction.ACTION_SET_PROGRESS;
+
+import static androidx.core.view.accessibility.AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_SCROLL_BACKWARD;
+import static androidx.core.view.accessibility.AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_SCROLL_FORWARD;
+
+import android.content.Context;
+import android.graphics.Outline;
+import android.os.Bundle;
+import android.util.AttributeSet;
+import android.view.View;
+import android.view.ViewOutlineProvider;
+import android.view.accessibility.AccessibilityNodeInfo;
+import android.widget.SeekBar;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.preference.PreferenceViewHolder;
+
+import com.android.systemui.tv.res.R;
+import com.android.tv.twopanelsettings.slices.SliceSeekbarPreference;
+import com.android.tv.twopanelsettings.slices.compat.core.SliceActionImpl;
+
+/**
+ * Slice preference for one panel settings a small icon, title, seekbar and the current seekbar
+ * value. Large non-themed icons/images are not supported.
+ */
+public class SeekbarSlicePreference extends SliceSeekbarPreference implements TooltipPreference {
+    private ControlWidget.TooltipConfig mTooltipConfig = new ControlWidget.TooltipConfig();
+    private SeekBar mSeekbar;
+
+    private SeekBar.OnSeekBarChangeListener mChangeListener;
+
+    public SeekbarSlicePreference(Context context, SliceActionImpl action, int min, int max,
+            int value) {
+        this(context, null, action, min, max, value);
+    }
+
+    public SeekbarSlicePreference(Context context, AttributeSet attrs, SliceActionImpl action,
+            int min, int max, int value) {
+        super(context, attrs, action, min, max, value);
+        setLayoutResource(R.layout.seekbar_slice_pref);
+        setShowSeekBarValue(true);
+    }
+
+    @Override
+    public void onBindViewHolder(@NonNull PreferenceViewHolder holder) {
+        super.onBindViewHolder(holder);
+
+        SeekbarControlWidget seekbarControlWidget = (SeekbarControlWidget) holder.itemView;
+        seekbarControlWidget.setEnabled(this.isEnabled());
+        seekbarControlWidget.setTooltipConfig(mTooltipConfig);
+
+        mSeekbar = holder.itemView.requireViewById(R.id.seekbar);
+
+        // Set outline of the seekbar to clip the thumb when getting closer to 0.
+        mSeekbar.setOutlineProvider(
+                new ViewOutlineProvider() {
+                    @Override
+                    public void getOutline(View view, Outline outline) {
+                        outline.setRoundRect(
+                                /* left= */ 0,
+                                /* top= */ 0,
+                                view.getWidth(),
+                                view.getHeight(),
+                                getContext().getResources().getDimensionPixelOffset(
+                                        R.dimen.seekbar_widget_track_corner_radius));
+                    }
+                });
+        mSeekbar.setClipToOutline(true);
+
+        holder.itemView.setAccessibilityDelegate(
+                new View.AccessibilityDelegate() {
+                    @Override
+                    public void onInitializeAccessibilityNodeInfo(@NonNull View host,
+                            @NonNull AccessibilityNodeInfo info) {
+                        super.onInitializeAccessibilityNodeInfo(host, info);
+                        info.addAction(ACTION_SET_PROGRESS);
+                        info.setRangeInfo(getCurrentRange());
+                    }
+
+                    @Override
+                    public boolean performAccessibilityAction(@NonNull View host, int action,
+                            Bundle args) {
+                        if (action == ACTION_SCROLL_FORWARD.getId()) {
+                            return increaseValue();
+                        }
+                        if (action == ACTION_SCROLL_BACKWARD.getId()) {
+                            return decreaseValue();
+                        }
+                        return super.performAccessibilityAction(host, action, args);
+                    }
+                });
+
+        mSeekbar.setOnSeekBarChangeListener(mChangeListener);
+    }
+
+    public void setOnSeekbarChangedListener(SeekBar.OnSeekBarChangeListener listener) {
+        mChangeListener = listener;
+        if (mSeekbar != null) {
+            mSeekbar.setOnSeekBarChangeListener(listener);
+        }
+    }
+
+    public AccessibilityNodeInfo.RangeInfo getCurrentRange() {
+        return new AccessibilityNodeInfo.RangeInfo(
+                AccessibilityNodeInfo.RangeInfo.RANGE_TYPE_INT, getMin(), getMax(), getValue());
+    }
+
+    private boolean increaseValue() {
+        int newProgress = getValue() + getSeekBarIncrement();
+
+        if (newProgress <= getMax()) {
+            setValue(newProgress);
+            callChangeListener(newProgress);
+            return true;
+        }
+        return false;
+    }
+
+    private boolean decreaseValue() {
+        int newProgress = getValue() - getSeekBarIncrement();
+        if (newProgress >= getMin()) {
+            setValue(newProgress);
+            callChangeListener(newProgress);
+            return true;
+        }
+        return false;
+    }
+
+    /** Set tool tip related attributes. */
+    @Override
+    public void setTooltipConfig(ControlWidget.TooltipConfig tooltipConfig) {
+        if (!this.mTooltipConfig.equals(tooltipConfig)) {
+            this.mTooltipConfig = tooltipConfig;
+            notifyChanged();
+        }
+    }
+
+    static class SeekbarControlWidget extends ControlWidget {
+        public SeekbarControlWidget(Context context) {
+            this(context, /* attrs= */ null);
+        }
+
+        public SeekbarControlWidget(Context context, @Nullable AttributeSet attrs) {
+            this(context, attrs, /* defStyleAttr= */ 0);
+        }
+
+        @SuppressWarnings("nullness")
+        public SeekbarControlWidget(Context context, @Nullable AttributeSet attrs,
+                int defStyleAttr) {
+            super(context, attrs, defStyleAttr);
+            View.inflate(context, R.layout.seekbar_control_widget, /* root= */ this);
+        }
+    }
+}
diff --git a/src/com/android/systemui/tv/media/settings/SliceFragment.java b/src/com/android/systemui/tv/media/settings/SliceFragment.java
new file mode 100644
index 0000000..bcad4f5
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/SliceFragment.java
@@ -0,0 +1,773 @@
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
+package com.android.systemui.tv.media.settings;
+
+import static android.app.slice.Slice.EXTRA_TOGGLE_STATE;
+import static android.app.slice.Slice.HINT_PARTIAL;
+
+import static com.android.tv.twopanelsettings.slices.SlicesConstants.EXTRA_PREFERENCE_INFO_STATUS;
+import static com.android.tv.twopanelsettings.slices.SlicesConstants.EXTRA_PREFERENCE_KEY;
+import static com.android.tv.twopanelsettings.slices.SlicesConstants.EXTRA_SLICE_FOLLOWUP;
+
+import android.app.Activity;
+import android.app.PendingIntent;
+import android.app.PendingIntent.CanceledException;
+import android.app.tvsettings.TvSettingsEnums;
+import android.content.ContentProviderClient;
+import android.content.Intent;
+import android.content.IntentSender;
+import android.database.ContentObserver;
+import android.graphics.drawable.Drawable;
+import android.net.Uri;
+import android.os.Bundle;
+import android.os.Handler;
+import android.os.Parcelable;
+import android.text.TextUtils;
+import android.util.Log;
+import android.view.LayoutInflater;
+import android.view.View;
+import android.view.ViewGroup;
+import android.widget.SeekBar;
+import android.widget.TextView;
+import android.widget.Toast;
+
+import androidx.activity.result.ActivityResult;
+import androidx.activity.result.ActivityResultCallback;
+import androidx.activity.result.ActivityResultLauncher;
+import androidx.activity.result.IntentSenderRequest;
+import androidx.activity.result.contract.ActivityResultContracts;
+import androidx.annotation.Keep;
+import androidx.annotation.NonNull;
+import androidx.fragment.app.Fragment;
+import androidx.lifecycle.Observer;
+import androidx.preference.Preference;
+import androidx.preference.PreferenceDialogFragmentCompat;
+import androidx.preference.PreferenceFragmentCompat;
+import androidx.preference.PreferenceManager;
+import androidx.preference.PreferenceScreen;
+import androidx.preference.TwoStatePreference;
+import androidx.recyclerview.widget.RecyclerView;
+
+import com.android.systemui.tv.media.FadingEdgeUtil;
+import com.android.systemui.tv.res.R;
+
+import com.android.tv.twopanelsettings.TwoPanelSettingsFragment.SliceFragmentCallback;
+import com.android.tv.twopanelsettings.slices.EmbeddedSlicePreference;
+import com.android.tv.twopanelsettings.slices.HasCustomContentDescription;
+import com.android.tv.twopanelsettings.slices.HasSliceAction;
+import com.android.tv.twopanelsettings.slices.HasSliceUri;
+import com.android.tv.twopanelsettings.slices.SettingsPreferenceFragment;
+import com.android.tv.twopanelsettings.slices.SlicePreference;
+import com.android.tv.twopanelsettings.slices.SliceRadioPreference;
+import com.android.tv.twopanelsettings.slices.SliceSeekbarPreference;
+import com.android.tv.twopanelsettings.slices.SlicesConstants;
+import com.android.tv.twopanelsettings.slices.ContextSingleton;
+import com.android.tv.twopanelsettings.slices.compat.Slice;
+import com.android.tv.twopanelsettings.slices.compat.SliceItem;
+import com.android.tv.twopanelsettings.slices.compat.widget.ListContent;
+import com.android.tv.twopanelsettings.slices.compat.widget.SliceContent;
+
+import java.util.ArrayList;
+import java.util.HashMap;
+import java.util.IdentityHashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.Objects;
+
+/**
+ * A screen presenting a slice in TV settings.
+ * Forked from {@link com.android.tv.twopanelsettings.slices.SliceFragment}.
+ */
+@Keep
+public class SliceFragment extends SettingsPreferenceFragment implements Observer<Slice>,
+        SliceFragmentCallback, PreferenceFragmentCompat.OnPreferenceStartFragmentCallback {
+
+    private static final String TAG = "SliceFragment";
+    private static final boolean DEBUG = false;
+
+    public static final String TAG_SCREEN_SUBTITLE = "TAG_SCREEN_SUBTITLE";
+
+    // Keys for saving state
+    private static final String KEY_PREFERENCE_FOLLOWUP_INTENT = "key_preference_followup_intent";
+    private static final String KEY_PREFERENCE_FOLLOWUP_RESULT_CODE =
+            "key_preference_followup_result_code";
+    private static final String KEY_SCREEN_TITLE = "key_screen_title";
+    private static final String KEY_SCREEN_SUBTITLE = "key_screen_subtitle";
+    private static final String KEY_LAST_PREFERENCE = "key_last_preference";
+    private static final String KEY_URI_STRING = "key_uri_string";
+
+    private Slice mSlice;
+    private String mUriString = null;
+    private int mCurrentPageId;
+    private CharSequence mScreenTitle;
+    private CharSequence mScreenSubtitle;
+    private PendingIntent mPreferenceFollowupIntent;
+    private int mFollowupPendingIntentResultCode;
+    private Intent mFollowupPendingIntentExtras;
+    private Intent mFollowupPendingIntentExtrasCopy;
+    private String mLastFocusedPreferenceKey;
+
+    private final ActivityResultLauncher<IntentSenderRequest> mActivityResultLauncher =
+            registerForActivityResult(new ActivityResultContracts.StartIntentSenderForResult(),
+                    new ActivityResultCallback<>() {
+                        @Override
+                        public void onActivityResult(ActivityResult result) {
+                            Intent data = result.getData();
+                            mFollowupPendingIntentExtras = data;
+                            mFollowupPendingIntentExtrasCopy = data == null ? null : new Intent(
+                                    data);
+                            mFollowupPendingIntentResultCode = result.getResultCode();
+                        }
+                    });
+    private final ContentObserver mContentObserver = new ContentObserver(new Handler()) {
+        @Override
+        public void onChange(boolean selfChange, Uri uri) {
+            handleUri(uri);
+            super.onChange(selfChange, uri);
+        }
+    };
+
+    @Override
+    public void onCreate(Bundle savedInstanceState) {
+        mUriString = getArguments().getString(SlicesConstants.TAG_TARGET_URI);
+        if (!TextUtils.isEmpty(mUriString)) {
+            ContextSingleton.getInstance().grantFullAccess(getContext(), Uri.parse(mUriString));
+        }
+        if (TextUtils.isEmpty(mScreenTitle)) {
+            mScreenTitle = getArguments().getCharSequence(SlicesConstants.TAG_SCREEN_TITLE, "");
+        }
+        if (TextUtils.isEmpty(mScreenSubtitle)) {
+            mScreenSubtitle = getArguments().getCharSequence(TAG_SCREEN_SUBTITLE, "");
+        }
+        super.onCreate(savedInstanceState);
+        getPreferenceManager().setPreferenceComparisonCallback(
+                new PreferenceManager.SimplePreferenceComparisonCallback() {
+                    @Override
+                    public boolean arePreferenceContentsTheSame(Preference preference1,
+                            Preference preference2) {
+                        // Should only check for the default SlicePreference objects, and ignore
+                        // other instances of slice reference classes since they all override
+                        // Preference.onBindViewHolder(PreferenceViewHolder)
+                        return preference1.getClass() == SlicePreference.class
+                                && super.arePreferenceContentsTheSame(preference1, preference2);
+                    }
+                });
+    }
+
+    @Override
+    public final boolean onPreferenceStartFragment(PreferenceFragmentCompat caller,
+            Preference pref) {
+        if (DEBUG) Log.d(TAG, "onPreferenceStartFragment");
+        if (pref.getFragment() != null) {
+            if (pref instanceof SlicePreference) {
+                SlicePreference slicePref = (SlicePreference) pref;
+                if (slicePref.getUri() == null || !isUriValid(slicePref.getUri())) {
+                    return false;
+                }
+                Bundle b = pref.getExtras();
+                b.putString(SlicesConstants.TAG_TARGET_URI, slicePref.getUri());
+                b.putCharSequence(SlicesConstants.TAG_SCREEN_TITLE, slicePref.getTitle());
+                if (DEBUG) Log.d(TAG, "TAG_TARGET_URI: " + slicePref.getUri()
+                        + ", TAG_SCREEN_TITLE: " + slicePref.getTitle());
+            }
+        }
+        final Fragment f =
+                Fragment.instantiate(getActivity(), pref.getFragment(), pref.getExtras());
+        f.setTargetFragment(caller, 0);
+        if (f instanceof PreferenceFragmentCompat || f instanceof PreferenceDialogFragmentCompat) {
+            startPreferenceFragment(f);
+        }
+        return true;
+    }
+
+    public void startPreferenceFragment(@NonNull Fragment fragment) {
+        if (DEBUG) Log.d(TAG, "startPreferenceFragment");
+
+        getParentFragmentManager().beginTransaction()
+                .replace(R.id.media_output_fragment, fragment)
+                .addToBackStack(null)
+                .commit();
+    }
+
+    @Override
+    public void onResume() {
+        this.setTitle(mScreenTitle);
+        this.setSubtitle(mScreenSubtitle);
+
+        showProgressBar();
+        if (!TextUtils.isEmpty(mUriString)) {
+            ContextSingleton.getInstance()
+                    .addSliceObserver(getActivity(), Uri.parse(mUriString), this);
+        }
+
+        super.onResume();
+        if (!TextUtils.isEmpty(mUriString)) {
+            getContext().getContentResolver().registerContentObserver(
+                    SlicePreferencesUtil.getStatusPath(mUriString), false, mContentObserver);
+        }
+        fireFollowupPendingIntent();
+    }
+
+    private void fireFollowupPendingIntent() {
+        if (mFollowupPendingIntentExtras == null) {
+            return;
+        }
+        // If there is followup pendingIntent returned from initial activity, send it.
+        // Otherwise send the followup pendingIntent provided by slice api.
+        Parcelable followupPendingIntent;
+        try {
+            followupPendingIntent = mFollowupPendingIntentExtrasCopy.getParcelableExtra(
+                    EXTRA_SLICE_FOLLOWUP);
+        } catch (Throwable ex) {
+            // unable to parse, the Intent has custom Parcelable, fallback
+            followupPendingIntent = null;
+        }
+        if (followupPendingIntent instanceof PendingIntent) {
+            try {
+                ((PendingIntent) followupPendingIntent).send();
+            } catch (CanceledException e) {
+                Log.e(TAG, "Followup PendingIntent for slice cannot be sent", e);
+            }
+        } else {
+            if (mPreferenceFollowupIntent == null) {
+                return;
+            }
+            try {
+                mPreferenceFollowupIntent.send(getContext(),
+                        mFollowupPendingIntentResultCode, mFollowupPendingIntentExtras);
+            } catch (CanceledException e) {
+                Log.e(TAG, "Followup PendingIntent for slice cannot be sent", e);
+            }
+            mPreferenceFollowupIntent = null;
+        }
+    }
+
+    @Override
+    public void onPause() {
+        super.onPause();
+        hideProgressBar();
+        getContext().getContentResolver().unregisterContentObserver(mContentObserver);
+        if (!TextUtils.isEmpty(mUriString)) {
+            ContextSingleton.getInstance()
+                    .removeSliceObserver(getActivity(), Uri.parse(mUriString), this);
+        }
+    }
+
+    @Override
+    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
+        PreferenceScreen preferenceScreen = getPreferenceManager()
+                .createPreferenceScreen(getContext());
+        setPreferenceScreen(preferenceScreen);
+    }
+
+    private boolean isUriValid(String uri) {
+        if (uri == null) {
+            return false;
+        }
+        ContentProviderClient client =
+                getContext().getContentResolver().acquireContentProviderClient(Uri.parse(uri));
+        if (client != null) {
+            client.close();
+            return true;
+        } else {
+            return false;
+        }
+    }
+
+    private void update() {
+        PreferenceScreen preferenceScreen =
+                getPreferenceManager().getPreferenceScreen();
+
+        if (preferenceScreen == null) {
+            return;
+        }
+
+        List<SliceContent> items = new ListContent(mSlice).getRowItems();
+        if (items.isEmpty()) {
+            return;
+        }
+
+        SliceItem redirectSliceItem = SlicePreferencesUtil.getRedirectSlice(items);
+        String redirectSlice = null;
+        if (redirectSliceItem != null) {
+            SlicePreferencesUtil.Data data = SlicePreferencesUtil.extract(redirectSliceItem);
+            CharSequence title = SlicePreferencesUtil.getText(data.mTitleItem);
+            if (!TextUtils.isEmpty(title)) {
+                redirectSlice = title.toString();
+            }
+        }
+        if (isUriValid(redirectSlice)) {
+            ContextSingleton.getInstance()
+                    .removeSliceObserver(getActivity(), Uri.parse(mUriString), this);
+            getContext().getContentResolver().unregisterContentObserver(mContentObserver);
+            mUriString = redirectSlice;
+            ContextSingleton.getInstance()
+                    .addSliceObserver(getActivity(), Uri.parse(mUriString), this);
+            getContext().getContentResolver().registerContentObserver(
+                    SlicePreferencesUtil.getStatusPath(mUriString), false, mContentObserver);
+        }
+
+        SliceItem screenTitleItem = SlicePreferencesUtil.getScreenTitleItem(items);
+        if (screenTitleItem == null) {
+            setTitle(mScreenTitle);
+            setSubtitle(mScreenSubtitle);
+        } else {
+            SlicePreferencesUtil.Data data = SlicePreferencesUtil.extract(screenTitleItem);
+            mCurrentPageId = SlicePreferencesUtil.getPageId(screenTitleItem);
+            CharSequence title = SlicePreferencesUtil.getText(data.mTitleItem);
+            if (!TextUtils.isEmpty(title)) {
+                mScreenTitle = title;
+            }
+            setTitle(mScreenTitle);
+
+            CharSequence subtitle = SlicePreferencesUtil.getText(data.mSubtitleItem);
+            if (!TextUtils.isEmpty(subtitle)) {
+                mScreenSubtitle = subtitle;
+            }
+            setSubtitle(subtitle);
+        }
+
+        SliceItem focusedPrefItem = SlicePreferencesUtil.getFocusedPreferenceItem(items);
+        CharSequence defaultFocusedKey = null;
+        if (focusedPrefItem != null) {
+            SlicePreferencesUtil.Data data = SlicePreferencesUtil.extract(focusedPrefItem);
+            CharSequence title = SlicePreferencesUtil.getText(data.mTitleItem);
+            if (!TextUtils.isEmpty(title)) {
+                defaultFocusedKey = title;
+            }
+        }
+
+        List<Preference> newPrefs = new ArrayList<>();
+        for (SliceContent contentItem : items) {
+            SliceItem item = contentItem.getSliceItem();
+            if (SlicesConstants.TYPE_PREFERENCE.equals(item.getSubType())
+                    || SlicesConstants.TYPE_PREFERENCE_CATEGORY.equals(item.getSubType())
+                    || SlicesConstants.TYPE_PREFERENCE_EMBEDDED_PLACEHOLDER.equals(
+                    item.getSubType())) {
+                Preference preference =
+                        SlicePreferencesUtil.getPreference(
+                                item, getContext(), getClass().getCanonicalName());
+                if (preference != null) {
+                    // Listen to changes of the seekbar.
+                    if (preference instanceof SeekbarSlicePreference) {
+                        SeekbarSlicePreference seekbarPreference =
+                                (SeekbarSlicePreference) preference;
+                        seekbarPreference.setOnSeekbarChangedListener(
+                                new SeekBar.OnSeekBarChangeListener() {
+                                    @Override
+                                    public void onProgressChanged(SeekBar seekBar, int progress,
+                                            boolean fromUser) {
+                                        onSeekbarPreferenceValueChanged(seekbarPreference,
+                                                progress);
+                                    }
+
+                                    @Override
+                                    public void onStartTrackingTouch(SeekBar seekBar) {
+                                        // NOOP
+                                    }
+
+                                    @Override
+                                    public void onStopTrackingTouch(SeekBar seekBar) {
+                                        // NOOP
+                                    }
+                                });
+                    }
+                    newPrefs.add(preference);
+                }
+            }
+        }
+        updatePreferenceScreen(preferenceScreen, newPrefs);
+        if (defaultFocusedKey != null) {
+            scrollToPreference(defaultFocusedKey.toString());
+        } else if (mLastFocusedPreferenceKey != null) {
+            scrollToPreference(mLastFocusedPreferenceKey);
+        }
+    }
+
+    private void back() {
+        if (DEBUG) Log.d(TAG, "back");
+        getParentFragmentManager().popBackStack();
+    }
+
+    private void updatePreferenceScreen(PreferenceScreen screen, List<Preference> newPrefs) {
+        // Remove all the preferences in the screen that satisfy such three cases:
+        // (a) Preference without key
+        // (b) Preference with key which does not appear in the new list.
+        // (c) Preference with key which does appear in the new list, but the preference has changed
+        // ability to handle slices and needs to be replaced instead of re-used.
+        int index = 0;
+        IdentityHashMap<Preference, Preference> newToOld = new IdentityHashMap<>();
+        while (index < screen.getPreferenceCount()) {
+            boolean needToRemoveCurrentPref = true;
+            Preference oldPref = screen.getPreference(index);
+            for (Preference newPref : newPrefs) {
+                if (isSamePreference(oldPref, newPref)) {
+                    needToRemoveCurrentPref = false;
+                    newToOld.put(newPref, oldPref);
+                    break;
+                }
+            }
+
+            if (needToRemoveCurrentPref) {
+                screen.removePreference(oldPref);
+            } else {
+                index++;
+            }
+        }
+
+        Map<Integer, Boolean> twoStatePreferenceIsCheckedByOrder = new HashMap<>();
+        for (int i = 0; i < newPrefs.size(); i++) {
+            if (newPrefs.get(i) instanceof TwoStatePreference) {
+                twoStatePreferenceIsCheckedByOrder.put(
+                        i, ((TwoStatePreference) newPrefs.get(i)).isChecked());
+            }
+        }
+
+        //Iterate the new preferences list and give each preference a correct order
+        for (int i = 0; i < newPrefs.size(); i++) {
+            Preference newPref = newPrefs.get(i);
+            // If the newPref has a key and has a corresponding old preference, update the old
+            // preference and give it a new order.
+
+            Preference oldPref = newToOld.get(newPref);
+            if (oldPref == null) {
+                newPref.setOrder(i);
+                screen.addPreference(newPref);
+                continue;
+            }
+
+            oldPref.setOrder(i);
+            if (oldPref instanceof EmbeddedSlicePreference) {
+                // EmbeddedSlicePreference has its own slice observer
+                // (EmbeddedSlicePreferenceHelper). Should therefore not be updated by
+                // slice observer in SliceFragment.
+                // The order will however still need to be updated, as this can not be handled
+                // by EmbeddedSlicePreferenceHelper.
+                continue;
+            }
+
+            oldPref.setTitle(newPref.getTitle());
+            oldPref.setSummary(newPref.getSummary());
+            oldPref.setEnabled(newPref.isEnabled());
+            oldPref.setSelectable(newPref.isSelectable());
+            oldPref.setFragment(newPref.getFragment());
+            oldPref.getExtras().putAll(newPref.getExtras());
+            if ((oldPref instanceof HasSliceAction)
+                    && (newPref instanceof HasSliceAction)) {
+                ((HasSliceAction) oldPref)
+                        .setSliceAction(
+                                ((HasSliceAction) newPref).getSliceAction());
+            }
+            if ((oldPref instanceof HasSliceUri)
+                    && (newPref instanceof HasSliceUri)) {
+                ((HasSliceUri) oldPref)
+                        .setUri(((HasSliceUri) newPref).getUri());
+            }
+            if ((oldPref instanceof HasCustomContentDescription)
+                    && (newPref instanceof HasCustomContentDescription)) {
+                ((HasCustomContentDescription) oldPref).setContentDescription(
+                        ((HasCustomContentDescription) newPref)
+                                .getContentDescription());
+            }
+        }
+
+        //addPreference will reset the checked status of TwoStatePreference.
+        //So we need to add them back
+        for (int i = 0; i < screen.getPreferenceCount(); i++) {
+            Preference screenPref = screen.getPreference(i);
+            if (screenPref instanceof TwoStatePreference
+                    && twoStatePreferenceIsCheckedByOrder.get(screenPref.getOrder()) != null) {
+                ((TwoStatePreference) screenPref)
+                        .setChecked(twoStatePreferenceIsCheckedByOrder.get(screenPref.getOrder()));
+            }
+        }
+    }
+
+    private static boolean isSamePreference(Preference oldPref, Preference newPref) {
+        if (oldPref == null || newPref == null) {
+            return false;
+        }
+
+        if (newPref instanceof HasSliceUri != oldPref instanceof HasSliceUri) {
+            return false;
+        }
+
+        if (newPref instanceof EmbeddedSlicePreference) {
+            return oldPref instanceof EmbeddedSlicePreference
+                    && Objects.equals(((EmbeddedSlicePreference) newPref).getUri(),
+                    ((EmbeddedSlicePreference) oldPref).getUri());
+        } else if (oldPref instanceof EmbeddedSlicePreference) {
+            return false;
+        }
+
+        return newPref.getKey() != null && newPref.getKey().equals(oldPref.getKey());
+    }
+
+    @Override
+    public void onPreferenceFocused(Preference preference) {
+        setLastFocused(preference);
+    }
+
+    @Override
+    public void onSeekbarPreferenceChanged(SliceSeekbarPreference preference, int addValue) {
+        if (DEBUG) Log.d(TAG, "onSeekbarPreferenceChanged, addValue: " + addValue);
+        int curValue = preference.getValue();
+        onSeekbarPreferenceValueChanged(preference, curValue);
+    }
+
+    public void onSeekbarPreferenceValueChanged(SliceSeekbarPreference preference, int newValue) {
+        if (DEBUG) Log.d(TAG, "onSeekbarPreferenceChanged, newValue: " + newValue);
+
+        try {
+            Intent fillInIntent =
+                    new Intent()
+                            .putExtra(EXTRA_PREFERENCE_KEY, preference.getKey())
+                            .putExtra(SlicesConstants.SUBTYPE_SEEKBAR_VALUE, newValue);
+            firePendingIntent(preference, fillInIntent);
+        } catch (Exception e) {
+            Log.e(TAG, "PendingIntent for slice cannot be sent", e);
+        }
+    }
+
+    @Override
+    public boolean onPreferenceTreeClick(Preference preference) {
+        if (preference instanceof SliceRadioPreference) {
+            SliceRadioPreference radioPref = (SliceRadioPreference) preference;
+            if (!radioPref.isChecked()) {
+                radioPref.setChecked(true);
+                if (TextUtils.isEmpty(radioPref.getUri())) {
+                    return true;
+                }
+            }
+
+            Intent fillInIntent =
+                    new Intent().putExtra(EXTRA_PREFERENCE_KEY, preference.getKey());
+            boolean result = firePendingIntent(radioPref, fillInIntent);
+            radioPref.clearOtherRadioPreferences(getPreferenceScreen());
+            if (result) {
+                return true;
+            }
+        } else if (preference instanceof TwoStatePreference
+                && preference instanceof HasSliceAction) {
+            boolean isChecked = ((TwoStatePreference) preference).isChecked();
+            preference.getExtras().putBoolean(EXTRA_PREFERENCE_INFO_STATUS, isChecked);
+            Intent fillInIntent =
+                    new Intent()
+                            .putExtra(EXTRA_TOGGLE_STATE, isChecked)
+                            .putExtra(EXTRA_PREFERENCE_KEY, preference.getKey());
+            if (firePendingIntent((HasSliceAction) preference, fillInIntent)) {
+                return true;
+            }
+            return true;
+        } else if (preference instanceof SlicePreference) {
+            Intent fillInIntent =
+                    new Intent().putExtra(EXTRA_PREFERENCE_KEY, preference.getKey());
+            if (firePendingIntent((HasSliceAction) preference, fillInIntent)) {
+                return true;
+            }
+        }
+
+        return super.onPreferenceTreeClick(preference);
+    }
+
+    private boolean firePendingIntent(@NonNull HasSliceAction preference, Intent fillInIntent) {
+        if (preference.getSliceAction() == null) {
+            return false;
+        }
+        IntentSender intentSender = preference.getSliceAction().getAction().getIntentSender();
+        mActivityResultLauncher.launch(
+                new IntentSenderRequest.Builder(intentSender).setFillInIntent(
+                        fillInIntent).build());
+        if (preference.getFollowupSliceAction() != null) {
+            mPreferenceFollowupIntent = preference.getFollowupSliceAction().getAction();
+        }
+
+        return true;
+    }
+
+    @Override
+    public void onSaveInstanceState(Bundle outState) {
+        super.onSaveInstanceState(outState);
+        outState.putParcelable(KEY_PREFERENCE_FOLLOWUP_INTENT, mPreferenceFollowupIntent);
+        outState.putInt(KEY_PREFERENCE_FOLLOWUP_RESULT_CODE, mFollowupPendingIntentResultCode);
+        outState.putCharSequence(KEY_SCREEN_TITLE, mScreenTitle);
+        outState.putCharSequence(KEY_SCREEN_SUBTITLE, mScreenSubtitle);
+        outState.putString(KEY_LAST_PREFERENCE, mLastFocusedPreferenceKey);
+        outState.putString(KEY_URI_STRING, mUriString);
+    }
+
+    @Override
+    public void onActivityCreated(Bundle savedInstanceState) {
+        super.onActivityCreated(savedInstanceState);
+        if (savedInstanceState != null) {
+            mPreferenceFollowupIntent =
+                    savedInstanceState.getParcelable(KEY_PREFERENCE_FOLLOWUP_INTENT);
+            mFollowupPendingIntentResultCode =
+                    savedInstanceState.getInt(KEY_PREFERENCE_FOLLOWUP_RESULT_CODE);
+            mScreenTitle = savedInstanceState.getCharSequence(KEY_SCREEN_TITLE);
+            mScreenSubtitle = savedInstanceState.getCharSequence(KEY_SCREEN_SUBTITLE);
+            mLastFocusedPreferenceKey = savedInstanceState.getString(KEY_LAST_PREFERENCE);
+            mUriString = savedInstanceState.getString(KEY_URI_STRING);
+        }
+    }
+
+    @Override
+    public void onChanged(Slice slice) {
+        mSlice = slice;
+        // Make TvSettings guard against the case that slice provider is not set up correctly
+        if (slice == null || slice.getHints() == null) {
+            return;
+        }
+
+        if (slice.getHints().contains(HINT_PARTIAL)) {
+            showProgressBar();
+        } else {
+            hideProgressBar();
+        }
+        update();
+    }
+
+    private void showProgressBar() {
+        View view = this.getView();
+        View progressBar = view == null ? null : getView().findViewById(R.id.progress_bar);
+        if (progressBar != null) {
+            progressBar.bringToFront();
+            progressBar.setVisibility(View.VISIBLE);
+        }
+    }
+
+    private void hideProgressBar() {
+        View view = this.getView();
+        View progressBar = view == null ? null : getView().findViewById(R.id.progress_bar);
+        if (progressBar != null) {
+            progressBar.setVisibility(View.GONE);
+        }
+    }
+
+    private void setSubtitle(CharSequence subtitle) {
+        View view = this.getView();
+        if (view == null) {
+            return;
+        }
+        TextView decorSubtitle = view.findViewById(R.id.decor_subtitle);
+        if (decorSubtitle != null) {
+            if (TextUtils.isEmpty(subtitle)) {
+                decorSubtitle.setVisibility(View.GONE);
+            } else {
+                decorSubtitle.setVisibility(View.VISIBLE);
+                decorSubtitle.setText(subtitle);
+            }
+        }
+        mScreenSubtitle = subtitle;
+    }
+
+    @Override
+    public View onCreateView(
+            LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
+        final ViewGroup view =
+                (ViewGroup) super.onCreateView(inflater, container, savedInstanceState);
+
+        LayoutInflater themedInflater = LayoutInflater.from(getContext());
+
+        final View newTitleContainer = themedInflater.inflate(
+                R.layout.media_output_settings_title, null);
+        if (newTitleContainer != null) {
+            newTitleContainer.setOutlineProvider(null);
+        }
+        view.removeView(
+                view.findViewById(androidx.leanback.preference.R.id.decor_title_container));
+        view.addView(newTitleContainer, 0);
+        view.setBackgroundResource(android.R.color.transparent);
+
+        RecyclerView recyclerView = view.findViewById(androidx.leanback.preference.R.id.list);
+        if (recyclerView != null) {
+            recyclerView.addOnScrollListener(
+                    new RecyclerView.OnScrollListener() {
+                        @Override
+                        public void onScrolled(@NonNull RecyclerView recyclerView, int dx, int dy) {
+                            super.onScrolled(recyclerView, dx, dy);
+                            Drawable foreground = FadingEdgeUtil.getForegroundDrawable(
+                                    recyclerView, requireContext());
+                            if (foreground != recyclerView.getForeground()) {
+                                recyclerView.setForeground(foreground);
+                            }
+                        }
+                    });
+        }
+
+        final View newContainer =
+                themedInflater.inflate(R.layout.media_output_settings_progress, null);
+        if (newContainer != null) {
+            ((ViewGroup) newContainer).addView(view);
+        }
+        return newContainer;
+    }
+
+    public void setLastFocused(Preference preference) {
+        mLastFocusedPreferenceKey = preference.getKey();
+    }
+
+    private void handleUri(Uri uri) {
+        String uriString = uri.getQueryParameter(SlicesConstants.PARAMETER_URI);
+        String errorMessage = uri.getQueryParameter(SlicesConstants.PARAMETER_ERROR);
+        if (DEBUG) Log.d(TAG, "handleUri: " + uri);
+
+        if (errorMessage != null) {
+            Toast.makeText(getActivity(), errorMessage, Toast.LENGTH_SHORT).show();
+        }
+        // Provider should provide the correct slice uri in the parameter if it wants to do certain
+        // action(includes go back, forward), otherwise TvSettings would ignore it.
+        if (uriString == null || !uriString.equals(mUriString)) {
+            return;
+        }
+        String direction = uri.getQueryParameter(SlicesConstants.PARAMETER_DIRECTION);
+        if (DEBUG) Log.d(TAG, "direction: " + direction);
+        if (direction != null) {
+            if (direction.equals(SlicesConstants.BACKWARD)) {
+                back();
+            } else if (direction.equals(SlicesConstants.EXIT)) {
+                finish();
+            }
+        }
+    }
+
+    private void finish() {
+        if (getActivity() != null) {
+            getActivity().setResult(Activity.RESULT_OK);
+            getActivity().finish();
+        }
+    }
+
+    private int getPreferenceActionId(Preference preference) {
+        if (preference instanceof HasSliceAction) {
+            return ((HasSliceAction) preference).getActionId() != 0
+                    ? ((HasSliceAction) preference).getActionId()
+                    : TvSettingsEnums.ENTRY_DEFAULT;
+        }
+        return TvSettingsEnums.ENTRY_DEFAULT;
+    }
+
+    @Override
+    protected int getPageId() {
+        return mCurrentPageId != 0 ? mCurrentPageId : TvSettingsEnums.PAGE_SLICE_DEFAULT;
+    }
+
+    @Deprecated
+    public int getMetricsCategory() {
+        return 0;
+    }
+}
diff --git a/src/com/android/systemui/tv/media/settings/SlicePreferencesUtil.java b/src/com/android/systemui/tv/media/settings/SlicePreferencesUtil.java
new file mode 100644
index 0000000..32513b7
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/SlicePreferencesUtil.java
@@ -0,0 +1,649 @@
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
+package com.android.systemui.tv.media.settings;
+
+import static android.app.slice.Slice.HINT_PARTIAL;
+import static android.app.slice.Slice.HINT_SUMMARY;
+import static android.app.slice.Slice.HINT_TITLE;
+import static android.app.slice.Slice.SUBTYPE_CONTENT_DESCRIPTION;
+import static android.app.slice.SliceItem.FORMAT_ACTION;
+import static android.app.slice.SliceItem.FORMAT_IMAGE;
+import static android.app.slice.SliceItem.FORMAT_INT;
+import static android.app.slice.SliceItem.FORMAT_LONG;
+import static android.app.slice.SliceItem.FORMAT_SLICE;
+import static android.app.slice.SliceItem.FORMAT_TEXT;
+
+import static com.android.tv.twopanelsettings.slices.HasCustomContentDescription.CONTENT_DESCRIPTION_SEPARATOR;
+import static com.android.tv.twopanelsettings.slices.SlicesConstants.CHECKMARK;
+import static com.android.tv.twopanelsettings.slices.SlicesConstants.EXTRA_ACTION_ID;
+import static com.android.tv.twopanelsettings.slices.SlicesConstants.EXTRA_ADD_INFO_STATUS;
+import static com.android.tv.twopanelsettings.slices.SlicesConstants.EXTRA_PAGE_ID;
+import static com.android.tv.twopanelsettings.slices.SlicesConstants.EXTRA_PREFERENCE_INFO_IMAGE;
+import static com.android.tv.twopanelsettings.slices.SlicesConstants.EXTRA_PREFERENCE_INFO_SUMMARY;
+import static com.android.tv.twopanelsettings.slices.SlicesConstants.EXTRA_PREFERENCE_INFO_TEXT;
+import static com.android.tv.twopanelsettings.slices.SlicesConstants.EXTRA_PREFERENCE_INFO_TITLE_ICON;
+import static com.android.tv.twopanelsettings.slices.SlicesConstants.RADIO;
+import static com.android.tv.twopanelsettings.slices.SlicesConstants.SEEKBAR;
+import static com.android.tv.twopanelsettings.slices.SlicesConstants.SWITCH;
+
+import android.content.Context;
+import android.graphics.drawable.Drawable;
+import android.graphics.drawable.Icon;
+import android.net.Uri;
+import android.text.TextUtils;
+import android.util.Log;
+import android.util.Pair;
+
+import androidx.core.graphics.drawable.IconCompat;
+import androidx.preference.Preference;
+
+import com.android.tv.twopanelsettings.slices.CustomContentDescriptionPreference;
+import com.android.tv.twopanelsettings.slices.HasCustomContentDescription;
+import com.android.tv.twopanelsettings.slices.HasSliceAction;
+import com.android.tv.twopanelsettings.slices.HasSliceUri;
+import com.android.tv.twopanelsettings.slices.compat.Slice;
+import com.android.tv.twopanelsettings.slices.compat.SliceItem;
+import com.android.tv.twopanelsettings.slices.compat.core.SliceActionImpl;
+import com.android.tv.twopanelsettings.slices.compat.core.SliceQuery;
+import com.android.tv.twopanelsettings.slices.compat.widget.SliceContent;
+import com.android.tv.twopanelsettings.slices.SlicePreference;
+import com.android.tv.twopanelsettings.slices.SliceSwitchPreference;
+import com.android.tv.twopanelsettings.slices.SlicesConstants;
+
+import java.util.ArrayList;
+import java.util.List;
+
+/**
+ * Generate corresponding preference based upon the slice data. Forked from
+ * {@code com.android.tv.twopanelsettings.slices.SlicePreferencesUtil}.
+ */
+public final class SlicePreferencesUtil {
+
+    private static final String TAG = SlicePreferencesUtil.class.getSimpleName();
+    private static final boolean DEBUG = false;
+
+    static Preference getPreference(SliceItem item, Context context,
+            String className) {
+        Preference preference = null;
+        if (item == null) {
+            return null;
+        }
+        Data data = extract(item);
+        if (item.getSubType() != null) {
+            String subType = item.getSubType();
+            if (subType.equals(SlicesConstants.TYPE_PREFERENCE)
+                    || subType.equals(SlicesConstants.TYPE_PREFERENCE_EMBEDDED)
+                    || subType.equals(SlicesConstants.TYPE_PREFERENCE_EMBEDDED_PLACEHOLDER)) {
+                // TODO: Figure out all the possible cases and reorganize the logic
+                if (data.mInfoItems.size() > 0) {
+                    if (DEBUG) Log.d(TAG, "InfoSlicePreference");
+                    preference = new InfoSlicePreference(
+                                context, getInfoList(data.mInfoItems));
+                } else if (data.mIntentItem != null) {
+                    SliceActionImpl action = new SliceActionImpl(data.mIntentItem);
+                    if (action != null) {
+                        // Currently if we don't set icon for the SliceAction, slice lib will
+                        // automatically treat it as a toggle. To distinguish preference action and
+                        // toggle action, we need to add a subtype if this is a preference action.
+                        if (DEBUG) Log.d(TAG, "BasicCenteredSlicePreference - has intent");
+                        Icon icon = getIcon(data.mStartItem);
+                        CharSequence subtitle =
+                                data.mSubtitleItem != null ? data.mSubtitleItem.getText() : null;
+                        boolean subtitleExists = !TextUtils.isEmpty(subtitle)
+                                || (data.mSubtitleItem != null && data.mSubtitleItem.hasHint(
+                                HINT_PARTIAL));
+                        if (icon == null && !subtitleExists) {
+                            preference = new BasicCenteredSlicePreference(context);
+                        } else {
+                            preference = new BasicSlicePreference(context);
+                        }
+
+                        ((SlicePreference) preference).setSliceAction(action);
+                        ((SlicePreference) preference).setActionId(getActionId(item));
+                        if (data.mFollowupIntentItem != null) {
+                            SliceActionImpl followUpAction =
+                                    new SliceActionImpl(data.mFollowupIntentItem);
+                            ((SlicePreference) preference).setFollowupSliceAction(followUpAction);
+                        }
+                    }
+                } else if (!data.mEndItems.isEmpty() && data.mEndItems.get(0) != null) {
+                    SliceActionImpl action = new SliceActionImpl(data.mEndItems.get(0));
+                    if (action != null) {
+                        int buttonStyle = SlicePreferencesUtil.getButtonStyle(item);
+                        switch (buttonStyle) {
+                            case CHECKMARK :
+                                if (DEBUG) Log.d(TAG, "CheckboxSlicePreference");
+                                preference = new CheckboxSlicePreference(
+                                        context, action);
+                                break;
+                            case SWITCH :
+                                if (DEBUG) Log.d(TAG, "SwitchSlicePreference");
+                                preference = new SwitchSlicePreference(context, action);
+                                break;
+                            case RADIO:
+                                if (DEBUG) Log.d(TAG, "RadioSlicePreference");
+                                preference = new RadioSlicePreference(context, action);
+                                if (getRadioGroup(item) != null) {
+                                    ((RadioSlicePreference) preference).setRadioGroup(
+                                            getRadioGroup(item).toString());
+                                }
+                                break;
+                            case SEEKBAR :
+                                if (DEBUG) Log.d(TAG, "SeekbarSlicePreference");
+                                int min = SlicePreferencesUtil.getSeekbarMin(item);
+                                int max = SlicePreferencesUtil.getSeekbarMax(item);
+                                int value = SlicePreferencesUtil.getSeekbarValue(item);
+                                preference = new SeekbarSlicePreference(
+                                        context, action, min, max, value);
+                                break;
+                        }
+                        if (preference instanceof HasSliceAction) {
+                            ((HasSliceAction) preference).setActionId(getActionId(item));
+                        }
+                        if (data.mFollowupIntentItem != null) {
+                            SliceActionImpl followUpAction =
+                                    new SliceActionImpl(data.mFollowupIntentItem);
+                            ((HasSliceAction) preference).setFollowupSliceAction(followUpAction);
+
+                        }
+                    }
+                }
+
+                CharSequence uri = getText(data.mTargetSliceItem);
+                if (uri == null || TextUtils.isEmpty(uri)) {
+                    if (preference == null) {
+                        if (DEBUG) Log.d(TAG, "TextSlicePreference");
+                        preference = new TextSlicePreference(context);
+                    }
+                } else {
+                    if (preference == null) {
+                        if (subType.equals(SlicesConstants.TYPE_PREFERENCE_EMBEDDED_PLACEHOLDER)) {
+                            if (DEBUG) Log.d(TAG, "EmbeddedPreference");
+                            preference = new EmbeddedPreference(context,
+                                    String.valueOf(uri));
+                        } else {
+                            if (DEBUG) Log.d(TAG, "BasicSlicePreference - has target uri");
+                            preference = new BasicSlicePreference(context);
+                        }
+                    }
+                    ((HasSliceUri) preference).setUri(uri.toString());
+                    if (preference instanceof HasSliceAction) {
+                        ((HasSliceAction) preference).setActionId(getActionId(item));
+                    }
+                    preference.setFragment(className);
+                }
+            } else if (item.getSubType().equals(SlicesConstants.TYPE_PREFERENCE_CATEGORY)) {
+                if (DEBUG) Log.d(TAG, "CategorySlicePreference");
+                preference = new CategorySlicePreference(context);
+            }
+        }
+
+        if (preference != null) {
+            boolean isEnabled = enabled(item);
+            // Set whether preference is enabled.
+            if (preference instanceof InfoSlicePreference || !isEnabled) {
+                preference.setEnabled(false);
+            }
+            // Set whether preference is selectable
+            if (!selectable(item) || !isEnabled) {
+                preference.setSelectable(false);
+            }
+            // Set the key for the preference
+            CharSequence key = getKey(item);
+            if (key != null) {
+                preference.setKey(key.toString());
+            }
+
+            if (data.mTitleItem != null) {
+                preference.setTitle(getText(data.mTitleItem));
+            }
+
+            Icon icon = getIcon(data.mStartItem);
+            if (icon != null) {
+                Drawable iconDrawable = icon.loadDrawable(context);
+                boolean isIconNeedToBeProcessed =
+                        SlicePreferencesUtil.isIconNeedsToBeProcessed(item);
+                if (DEBUG) Log.d(TAG, "Icon, needs processing: " + isIconNeedToBeProcessed);
+
+                if (preference instanceof SeekbarSlicePreference) {
+                    if (isIconNeedToBeProcessed) {
+                        // This preference can only show single colored icons, not full color
+                        // image icons.
+                        preference.setIcon(iconDrawable);
+                    }
+                } else {
+                    if (isIconNeedToBeProcessed) {
+                        preference.setIcon(IconUtil.getCompoundIcon(context, iconDrawable));
+                    } else {
+                        preference.setIcon(iconDrawable);
+                    }
+                }
+            }
+
+
+            //Set summary
+            CharSequence subtitle =
+                    data.mSubtitleItem != null ? data.mSubtitleItem.getText() : null;
+            boolean subtitleExists = !TextUtils.isEmpty(subtitle)
+                    || (data.mSubtitleItem != null && data.mSubtitleItem.hasHint(HINT_PARTIAL));
+            if (subtitleExists) {
+                preference.setSummary(subtitle);
+            } else {
+                if (data.mSummaryItem != null) {
+                    preference.setSummary(getText(data.mSummaryItem));
+                }
+            }
+
+            ControlWidget.TooltipConfig tooltipConfig = new ControlWidget.TooltipConfig();
+
+            // Set preview info image and text
+            CharSequence infoText = getInfoText(item);
+            CharSequence infoSummary = getInfoSummary(item);
+            IconCompat infoImage = getInfoImage(item);
+            String fallbackInfoContentDescription = "";
+            if (preference.getTitle() != null) {
+                fallbackInfoContentDescription += preference.getTitle().toString();
+            }
+            if (infoImage != null) {
+                tooltipConfig.setImageDrawable(infoImage.loadDrawable(context));
+            }
+            if (infoText != null && !infoText.isEmpty()) {
+                tooltipConfig.setTooltipText(infoText);
+                if (preference.getTitle() != null
+                        && !preference.getTitle().equals(infoText.toString())) {
+                    fallbackInfoContentDescription +=
+                            CONTENT_DESCRIPTION_SEPARATOR + infoText.toString();
+                }
+
+            }
+            if (infoSummary != null && !infoSummary.isEmpty()) {
+                tooltipConfig.setTooltipSummary(infoSummary);
+                fallbackInfoContentDescription +=
+                        CONTENT_DESCRIPTION_SEPARATOR + infoSummary;
+            }
+            String contentDescription = getInfoContentDescription(item);
+            // Respect the content description values provided by slice.
+            // If not provided, for SlicePreference, SliceSwitchPreference,
+            // CustomContentDescriptionPreference, use the fallback value.
+            // Otherwise, do not set the contentDescription for preference. Rely on the talkback
+            // framework to generate the value itself.
+            if (!TextUtils.isEmpty(contentDescription)) {
+                if (preference instanceof HasCustomContentDescription) {
+                    ((HasCustomContentDescription) preference).setContentDescription(
+                            contentDescription);
+                }
+            } else {
+                if ((preference instanceof SlicePreference)
+                        || (preference instanceof SliceSwitchPreference)
+                        || (preference instanceof CustomContentDescriptionPreference)) {
+                    ((HasCustomContentDescription) preference).setContentDescription(
+                            fallbackInfoContentDescription);
+                }
+            }
+            if ((infoText == null || infoText.isEmpty() )
+                    && (infoSummary == null || infoSummary.isEmpty())) {
+                tooltipConfig.setShouldShowTooltip(false);
+            } else {
+                tooltipConfig.setShouldShowTooltip(true);
+            }
+
+            if (preference instanceof TooltipPreference) {
+                ((TooltipPreference) preference).setTooltipConfig(tooltipConfig);
+            }
+        }
+
+        return preference;
+    }
+
+    static class Data {
+        SliceItem mStartItem;
+        SliceItem mTitleItem;
+        SliceItem mSubtitleItem;
+        SliceItem mSummaryItem;
+        SliceItem mTargetSliceItem;
+        SliceItem mRadioGroupItem;
+        SliceItem mIntentItem;
+        SliceItem mFollowupIntentItem;
+        SliceItem mHasEndIconItem;
+        List<SliceItem> mEndItems = new ArrayList<>();
+        List<SliceItem> mInfoItems = new ArrayList<>();
+    }
+
+    static Data extract(SliceItem sliceItem) {
+        Data data = new Data();
+        List<SliceItem> possibleStartItems =
+                SliceQuery.findAll(sliceItem, null, HINT_TITLE, null);
+        if (possibleStartItems.size() > 0) {
+            // The start item will be at position 0 if it exists
+            String format = possibleStartItems.get(0).getFormat();
+            if ((FORMAT_ACTION.equals(format)
+                    && SliceQuery.find(possibleStartItems.get(0), FORMAT_IMAGE) != null)
+                    || FORMAT_SLICE.equals(format)
+                    || FORMAT_LONG.equals(format)
+                    || FORMAT_IMAGE.equals(format)) {
+                data.mStartItem = possibleStartItems.get(0);
+            }
+        }
+
+        List<SliceItem> items = sliceItem.getSlice().getItems();
+        for (int i = 0; i < items.size(); i++) {
+            final SliceItem item = items.get(i);
+            String subType = item.getSubType();
+            if (subType != null) {
+                switch (subType) {
+                    case SlicesConstants.SUBTYPE_INFO_PREFERENCE :
+                        data.mInfoItems.add(item);
+                        break;
+                    case SlicesConstants.SUBTYPE_INTENT :
+                        data.mIntentItem = item;
+                        break;
+                    case SlicesConstants.SUBTYPE_FOLLOWUP_INTENT :
+                        data.mFollowupIntentItem = item;
+                        break;
+                    case SlicesConstants.TAG_TARGET_URI :
+                        data.mTargetSliceItem = item;
+                        break;
+                    case SlicesConstants.EXTRA_HAS_END_ICON:
+                        data.mHasEndIconItem = item;
+                        break;
+                }
+            } else if (FORMAT_TEXT.equals(item.getFormat()) && (item.getSubType() == null)) {
+                if ((data.mTitleItem == null || !data.mTitleItem.hasHint(HINT_TITLE))
+                        && item.hasHint(HINT_TITLE) && !item.hasHint(HINT_SUMMARY)) {
+                    data.mTitleItem = item;
+                } else if (data.mSubtitleItem == null && !item.hasHint(HINT_SUMMARY)) {
+                    data.mSubtitleItem = item;
+                } else if (data.mSummaryItem == null && item.hasHint(HINT_SUMMARY)) {
+                    data.mSummaryItem = item;
+                }
+            } else {
+                data.mEndItems.add(item);
+            }
+        }
+        data.mEndItems.remove(data.mStartItem);
+        return data;
+    }
+
+    private static List<Pair<CharSequence, CharSequence>> getInfoList(List<SliceItem> sliceItems) {
+        List<Pair<CharSequence, CharSequence>> infoList = new ArrayList<>();
+        for (SliceItem item : sliceItems) {
+            Slice itemSlice = item.getSlice();
+            if (itemSlice != null) {
+                CharSequence title = null;
+                CharSequence summary = null;
+                for (SliceItem element : itemSlice.getItems()) {
+                    if (element.getHints().contains(HINT_TITLE)) {
+                        title = element.getText();
+                    } else if (element.getHints().contains(HINT_SUMMARY)) {
+                        summary = element.getText();
+                    }
+                }
+                infoList.add(new Pair<CharSequence, CharSequence>(title, summary));
+            }
+        }
+        return infoList;
+    }
+
+    private static CharSequence getKey(SliceItem item) {
+        SliceItem target = SliceQuery.findSubtype(item, FORMAT_TEXT, SlicesConstants.TAG_KEY);
+        return target != null ? target.getText() : null;
+    }
+
+    private static CharSequence getRadioGroup(SliceItem item) {
+        SliceItem target = SliceQuery.findSubtype(
+                item, FORMAT_TEXT, SlicesConstants.TAG_RADIO_GROUP);
+        return target != null ? target.getText() : null;
+    }
+
+    /**
+     * Get the screen title item for the slice.
+     * @param sliceItems list of SliceItem extracted from slice data.
+     * @return screen title item.
+     */
+    static SliceItem getScreenTitleItem(List<SliceContent> sliceItems) {
+        for (SliceContent contentItem : sliceItems)  {
+            SliceItem item = contentItem.getSliceItem();
+            if (item.getSubType() != null
+                    && item.getSubType().equals(SlicesConstants.TYPE_PREFERENCE_SCREEN_TITLE)) {
+                return item;
+            }
+        }
+        return null;
+    }
+
+    static SliceItem getRedirectSlice(List<SliceContent> sliceItems) {
+        for (SliceContent contentItem : sliceItems)  {
+            SliceItem item = contentItem.getSliceItem();
+            if (item.getSubType() != null
+                    && item.getSubType().equals(SlicesConstants.TYPE_REDIRECTED_SLICE_URI)) {
+                return item;
+            }
+        }
+        return null;
+    }
+
+    static SliceItem getFocusedPreferenceItem(List<SliceContent> sliceItems) {
+        for (SliceContent contentItem : sliceItems)  {
+            SliceItem item = contentItem.getSliceItem();
+            if (item.getSubType() != null
+                    && item.getSubType().equals(SlicesConstants.TYPE_FOCUSED_PREFERENCE)) {
+                return item;
+            }
+        }
+        return null;
+    }
+
+    static SliceItem getEmbeddedItem(List<SliceContent> sliceItems) {
+        for (SliceContent contentItem : sliceItems)  {
+            SliceItem item = contentItem.getSliceItem();
+            if (item.getSubType() != null
+                    && item.getSubType().equals(SlicesConstants.TYPE_PREFERENCE_EMBEDDED)) {
+                return item;
+            }
+        }
+        return null;
+    }
+
+    private static boolean isIconNeedsToBeProcessed(SliceItem sliceItem) {
+        List<SliceItem> items = sliceItem.getSlice().getItems();
+        for (SliceItem item : items)  {
+            if (item.getSubType() != null && item.getSubType().equals(
+                    SlicesConstants.SUBTYPE_ICON_NEED_TO_BE_PROCESSED)) {
+                return item.getInt() == 1;
+            }
+        }
+        return false;
+    }
+
+    private static int getButtonStyle(SliceItem sliceItem) {
+        List<SliceItem> items = sliceItem.getSlice().getItems();
+        for (SliceItem item : items)  {
+            if (item.getSubType() != null
+                    && item.getSubType().equals(SlicesConstants.SUBTYPE_BUTTON_STYLE)) {
+                return item.getInt();
+            }
+        }
+        return -1;
+    }
+
+    private static int getSeekbarMin(SliceItem sliceItem) {
+        List<SliceItem> items = sliceItem.getSlice().getItems();
+        for (SliceItem item : items)  {
+            if (item.getSubType() != null
+                    && item.getSubType().equals(SlicesConstants.SUBTYPE_SEEKBAR_MIN)) {
+                return item.getInt();
+            }
+        }
+        return -1;
+    }
+
+    private static int getSeekbarMax(SliceItem sliceItem) {
+        List<SliceItem> items = sliceItem.getSlice().getItems();
+        for (SliceItem item : items)  {
+            if (item.getSubType() != null
+                    && item.getSubType().equals(SlicesConstants.SUBTYPE_SEEKBAR_MAX)) {
+                return item.getInt();
+            }
+        }
+        return -1;
+    }
+
+    private static int getSeekbarValue(SliceItem sliceItem) {
+        List<SliceItem> items = sliceItem.getSlice().getItems();
+        for (SliceItem item : items)  {
+            if (item.getSubType() != null
+                    && item.getSubType().equals(SlicesConstants.SUBTYPE_SEEKBAR_VALUE)) {
+                return item.getInt();
+            }
+        }
+        return -1;
+    }
+
+    private static boolean enabled(SliceItem sliceItem) {
+        List<SliceItem> items = sliceItem.getSlice().getItems();
+        for (SliceItem item : items)  {
+            if (item.getSubType() != null
+                    && item.getSubType().equals(SlicesConstants.SUBTYPE_IS_ENABLED)) {
+                return item.getInt() == 1;
+            }
+        }
+        return true;
+    }
+
+    private static boolean selectable(SliceItem sliceItem) {
+        List<SliceItem> items = sliceItem.getSlice().getItems();
+        for (SliceItem item : items)  {
+            if (item.getSubType() != null
+                    && item.getSubType().equals(SlicesConstants.SUBTYPE_IS_SELECTABLE)) {
+                return item.getInt() == 1;
+            }
+        }
+        return true;
+    }
+
+    private static boolean addInfoStatus(SliceItem sliceItem) {
+        List<SliceItem> items = sliceItem.getSlice().getItems();
+        for (SliceItem item : items)  {
+            if (item.getSubType() != null
+                    && item.getSubType().equals(EXTRA_ADD_INFO_STATUS)) {
+                return item.getInt() == 1;
+            }
+        }
+        return true;
+    }
+
+    private static boolean hasEndIcon(SliceItem item) {
+        return item != null && item.getInt() > 0;
+    }
+
+    /**
+     * Checks if custom content description should be forced to be used if provided. This function
+     * can be extended with more cases if needed.
+     *
+     * @param item The {@link SliceItem} containing the necessary information.
+     * @return <code>true</code> if custom content description should be used.
+     */
+    private static boolean shouldForceContentDescription(SliceItem sliceItem) {
+        List<SliceItem> items = sliceItem.getSlice().getItems();
+        for (SliceItem item : items)  {
+            // Checks if an end icon has been set.
+            if (item.getSubType() != null
+                    && item.getSubType().equals(SlicesConstants.EXTRA_HAS_END_ICON)) {
+                return hasEndIcon(item);
+            }
+        }
+        return false;
+    }
+
+    /**
+     * Get the text from the SliceItem.
+     */
+    static CharSequence getText(SliceItem item) {
+        if (item == null) {
+            return null;
+        }
+        return item.getText();
+    }
+
+    /** Get the icon from the SliceItem if available */
+    static Icon getIcon(SliceItem startItem) {
+        if (startItem != null && startItem.getSlice() != null
+                && startItem.getSlice().getItems() != null
+                && startItem.getSlice().getItems().size() > 0) {
+            SliceItem iconItem = startItem.getSlice().getItems().get(0);
+            if (FORMAT_IMAGE.equals(iconItem.getFormat())) {
+                IconCompat icon = iconItem.getIcon();
+                return icon.toIcon();
+            }
+        }
+        return null;
+    }
+
+    static Uri getStatusPath(String uriString) {
+        Uri statusUri = Uri.parse(uriString)
+                .buildUpon().path("/" + SlicesConstants.PATH_STATUS).build();
+        return statusUri;
+    }
+
+    static int getPageId(SliceItem item) {
+        SliceItem target = SliceQuery.findSubtype(item, FORMAT_INT, EXTRA_PAGE_ID);
+        return target != null ? target.getInt() : 0;
+    }
+
+    private static int getActionId(SliceItem item) {
+        SliceItem target = SliceQuery.findSubtype(item, FORMAT_INT, EXTRA_ACTION_ID);
+        return target != null ? target.getInt() : 0;
+    }
+
+
+    private static CharSequence getInfoText(SliceItem item) {
+        SliceItem target = SliceQuery.findSubtype(item, FORMAT_TEXT, EXTRA_PREFERENCE_INFO_TEXT);
+        return target != null ? target.getText() : null;
+    }
+
+    private static CharSequence getInfoSummary(SliceItem item) {
+        SliceItem target = SliceQuery.findSubtype(item, FORMAT_TEXT, EXTRA_PREFERENCE_INFO_SUMMARY);
+        return target != null ? target.getText() : null;
+    }
+
+    private static IconCompat getInfoImage(SliceItem item) {
+        SliceItem target = SliceQuery.findSubtype(item, FORMAT_IMAGE, EXTRA_PREFERENCE_INFO_IMAGE);
+        return target != null ? target.getIcon() : null;
+    }
+
+    private static IconCompat getInfoTitleIcon(SliceItem item) {
+        SliceItem target = SliceQuery.findSubtype(
+                item, FORMAT_IMAGE, EXTRA_PREFERENCE_INFO_TITLE_ICON);
+        return target != null ? target.getIcon() : null;
+    }
+
+    /**
+     * Get the content description from SliceItem if available
+     */
+    private static String getInfoContentDescription(
+            SliceItem sliceItem) {
+        List<SliceItem> items = sliceItem.getSlice().getItems();
+        for (SliceItem item : items)  {
+            if (item.getSubType() != null
+                    && item.getSubType().equals(SUBTYPE_CONTENT_DESCRIPTION)) {
+                return item.getText().toString();
+            }
+        }
+        return null;
+    }
+
+}
diff --git a/src/com/android/systemui/tv/media/settings/SwitchSlicePreference.java b/src/com/android/systemui/tv/media/settings/SwitchSlicePreference.java
new file mode 100644
index 0000000..ab19243
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/SwitchSlicePreference.java
@@ -0,0 +1,82 @@
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
+package com.android.systemui.tv.media.settings;
+
+import android.content.Context;
+import android.util.AttributeSet;
+import android.view.View;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.preference.PreferenceViewHolder;
+
+import com.android.systemui.tv.res.R;
+import com.android.tv.twopanelsettings.slices.SliceSwitchPreference;
+import com.android.tv.twopanelsettings.slices.compat.core.SliceActionImpl;
+
+/**
+ * Slice preference for one panel settings which shows a switch/toggle in addition to the
+ * capabilities of the {@link BasicSlicePreference}.
+ */
+public class SwitchSlicePreference extends SliceSwitchPreference implements TooltipPreference {
+    private ControlWidget.TooltipConfig mTooltipConfig = new ControlWidget.TooltipConfig();
+
+    public SwitchSlicePreference(Context context, SliceActionImpl action) {
+        this(context, null, action);
+    }
+
+    public SwitchSlicePreference(Context context, @Nullable AttributeSet attrs,
+            SliceActionImpl action) {
+        super(context, attrs, action);
+        setLayoutResource(R.layout.switch_slice_pref);
+    }
+
+    @Override
+    public void onBindViewHolder(@NonNull PreferenceViewHolder holder) {
+        super.onBindViewHolder(holder);
+        SwitchControlWidget widget = (SwitchControlWidget) holder.itemView;
+        widget.setEnabled(this.isEnabled());
+        widget.setTooltipConfig(mTooltipConfig);
+    }
+
+    /** Set tool tip related attributes. */
+    @Override
+    public void setTooltipConfig(ControlWidget.TooltipConfig tooltipConfig) {
+        if (!this.mTooltipConfig.equals(tooltipConfig)) {
+            this.mTooltipConfig = tooltipConfig;
+            notifyChanged();
+        }
+    }
+
+    static class SwitchControlWidget extends ControlWidget {
+
+        public SwitchControlWidget(Context context) {
+            this(context, /* attrs= */ null);
+        }
+
+        public SwitchControlWidget(Context context, @Nullable AttributeSet attrs) {
+            this(context, attrs, /* defStyleAttr= */ 0);
+        }
+
+        public SwitchControlWidget(Context context, @Nullable AttributeSet attrs,
+                int defStyleAttr) {
+            super(context, attrs, defStyleAttr);
+            View.inflate(context, R.layout.switch_control_widget, /* root= */ this);
+        }
+    }
+
+}
diff --git a/src/com/android/systemui/tv/media/settings/TextSlicePreference.java b/src/com/android/systemui/tv/media/settings/TextSlicePreference.java
new file mode 100644
index 0000000..26b72e3
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/TextSlicePreference.java
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
+package com.android.systemui.tv.media.settings;
+
+import android.content.Context;
+import android.util.AttributeSet;
+
+import androidx.preference.PreferenceViewHolder;
+
+import com.android.systemui.tv.res.R;
+import com.android.tv.twopanelsettings.slices.CustomContentDescriptionPreference;
+
+/**
+ * Slice preference for one panel settings like the {@link BasicSlicePreference}, but not focusable.
+ */
+public class TextSlicePreference extends CustomContentDescriptionPreference {
+
+    public TextSlicePreference(Context context) {
+        this(context, null);
+    }
+
+    public TextSlicePreference(Context context, AttributeSet attrs) {
+        super(context, attrs);
+        setLayoutResource(R.layout.text_slice_preference);
+    }
+
+    @Override
+    public void onBindViewHolder(PreferenceViewHolder holder) {
+        super.onBindViewHolder(holder);
+        holder.itemView.setFocusable(false);
+    }
+}
diff --git a/src/com/android/systemui/tv/media/settings/TooltipPreference.java b/src/com/android/systemui/tv/media/settings/TooltipPreference.java
new file mode 100644
index 0000000..d90130b
--- /dev/null
+++ b/src/com/android/systemui/tv/media/settings/TooltipPreference.java
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
+package com.android.systemui.tv.media.settings;
+
+public interface TooltipPreference {
+
+    void setTooltipConfig(ControlWidget.TooltipConfig tooltipConfig);
+
+}
\ No newline at end of file
diff --git a/src/com/android/systemui/tv/sensorprivacy/TvSensorPrivacyChangedActivity.java b/src/com/android/systemui/tv/sensorprivacy/TvSensorPrivacyChangedActivity.java
index 88fcc14..ac916c7 100644
--- a/src/com/android/systemui/tv/sensorprivacy/TvSensorPrivacyChangedActivity.java
+++ b/src/com/android/systemui/tv/sensorprivacy/TvSensorPrivacyChangedActivity.java
@@ -150,22 +150,22 @@ public class TvSensorPrivacyChangedActivity extends TvBottomSheetActivity {
     private void updateUiForMicUpdate(boolean blocked) {
         if (blocked) {
             mTitle.setText(
-                    com.android.systemui.R.string.sensor_privacy_mic_turned_off_dialog_title);
+                    com.android.systemui.res.R.string.sensor_privacy_mic_turned_off_dialog_title);
             if (isExplicitUserInteractionAudioBypassAllowed()) {
                 mContent.setText(
-                        com.android.systemui.R.string
+                        com.android.systemui.res.R.string
                                 .sensor_privacy_mic_blocked_with_exception_dialog_content);
             } else {
                 mContent.setText(
-                        com.android.systemui.R.string
+                        com.android.systemui.res.R.string
                                 .sensor_privacy_mic_blocked_no_exception_dialog_content);
             }
-            mIcon.setImageResource(com.android.systemui.R.drawable.unblock_hw_sensor_microphone);
+            mIcon.setImageResource(com.android.systemui.res.R.drawable.unblock_hw_sensor_microphone);
             mSecondIcon.setVisibility(View.GONE);
         } else {
-            mTitle.setText(com.android.systemui.R.string.sensor_privacy_mic_turned_on_dialog_title);
+            mTitle.setText(com.android.systemui.res.R.string.sensor_privacy_mic_turned_on_dialog_title);
             mContent.setText(
-                    com.android.systemui.R.string.sensor_privacy_mic_unblocked_dialog_content);
+                    com.android.systemui.res.R.string.sensor_privacy_mic_unblocked_dialog_content);
             mIcon.setImageResource(com.android.internal.R.drawable.ic_mic_allowed);
             mSecondIcon.setVisibility(View.GONE);
         }
@@ -174,16 +174,16 @@ public class TvSensorPrivacyChangedActivity extends TvBottomSheetActivity {
     private void updateUiForCameraUpdate(boolean blocked) {
         if (blocked) {
             mTitle.setText(
-                    com.android.systemui.R.string.sensor_privacy_camera_turned_off_dialog_title);
+                    com.android.systemui.res.R.string.sensor_privacy_camera_turned_off_dialog_title);
             mContent.setText(
-                    com.android.systemui.R.string.sensor_privacy_camera_blocked_dialog_content);
-            mIcon.setImageResource(com.android.systemui.R.drawable.unblock_hw_sensor_camera);
+                    com.android.systemui.res.R.string.sensor_privacy_camera_blocked_dialog_content);
+            mIcon.setImageResource(com.android.systemui.res.R.drawable.unblock_hw_sensor_camera);
             mSecondIcon.setVisibility(View.GONE);
         } else {
             mTitle.setText(
-                    com.android.systemui.R.string.sensor_privacy_camera_turned_on_dialog_title);
+                    com.android.systemui.res.R.string.sensor_privacy_camera_turned_on_dialog_title);
             mContent.setText(
-                    com.android.systemui.R.string.sensor_privacy_camera_unblocked_dialog_content);
+                    com.android.systemui.res.R.string.sensor_privacy_camera_unblocked_dialog_content);
             mIcon.setImageResource(com.android.internal.R.drawable.ic_camera_allowed);
             mSecondIcon.setVisibility(View.GONE);
         }
diff --git a/src/com/android/systemui/tv/sensorprivacy/TvUnblockSensorActivity.java b/src/com/android/systemui/tv/sensorprivacy/TvUnblockSensorActivity.java
index db16c68..3f02450 100644
--- a/src/com/android/systemui/tv/sensorprivacy/TvUnblockSensorActivity.java
+++ b/src/com/android/systemui/tv/sensorprivacy/TvUnblockSensorActivity.java
@@ -39,7 +39,7 @@ import android.widget.ImageView;
 import android.widget.TextView;
 import android.widget.Toast;
 
-import com.android.systemui.R;
+import com.android.systemui.res.R;
 import com.android.systemui.statusbar.policy.IndividualSensorPrivacyController;
 import com.android.systemui.tv.TvBottomSheetActivity;
 
diff --git a/src/com/android/systemui/tv/usb/TvUsbConfirmActivity.java b/src/com/android/systemui/tv/usb/TvUsbConfirmActivity.java
index 3b6a1bb..24f8d89 100644
--- a/src/com/android/systemui/tv/usb/TvUsbConfirmActivity.java
+++ b/src/com/android/systemui/tv/usb/TvUsbConfirmActivity.java
@@ -16,7 +16,7 @@
 
 package com.android.systemui.tv.usb;
 
-import com.android.systemui.R;
+import com.android.systemui.res.R;
 
 /**
  * Dialog shown to confirm the package to start when a USB device or accessory is attached and there
diff --git a/src/com/android/systemui/tv/usb/TvUsbPermissionActivity.java b/src/com/android/systemui/tv/usb/TvUsbPermissionActivity.java
index 211316b..4a18a39 100644
--- a/src/com/android/systemui/tv/usb/TvUsbPermissionActivity.java
+++ b/src/com/android/systemui/tv/usb/TvUsbPermissionActivity.java
@@ -16,7 +16,7 @@
 
 package com.android.systemui.tv.usb;
 
-import com.android.systemui.R;
+import com.android.systemui.res.R;
 
 /**
  * Dialog shown when a package requests access to a USB device or accessory on TVs.
diff --git a/src/com/android/systemui/tv/vpn/VpnStatusObserver.kt b/src/com/android/systemui/tv/vpn/VpnStatusObserver.kt
index b91142a..3c30a06 100644
--- a/src/com/android/systemui/tv/vpn/VpnStatusObserver.kt
+++ b/src/com/android/systemui/tv/vpn/VpnStatusObserver.kt
@@ -48,9 +48,9 @@ class VpnStatusObserver @Inject constructor(
 
     private val vpnIconId: Int
         get() = if (securityController.isVpnBranded) {
-            com.android.systemui.R.drawable.stat_sys_branded_vpn
+            com.android.systemui.res.R.drawable.stat_sys_branded_vpn
         } else {
-            com.android.systemui.R.drawable.stat_sys_vpn_ic
+            com.android.systemui.res.R.drawable.stat_sys_vpn_ic
         }
 
     private val vpnName: String?
```

