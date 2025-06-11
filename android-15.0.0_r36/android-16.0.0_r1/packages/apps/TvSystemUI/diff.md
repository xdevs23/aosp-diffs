```diff
diff --git a/Android.bp b/Android.bp
index 8d11ee0..d338400 100644
--- a/Android.bp
+++ b/Android.bp
@@ -46,6 +46,7 @@ android_library {
         "SystemUI-core",
         "SystemUIPluginLib",
         "SystemUISharedLib",
+        "SystemUI-shared-utils",
         "TvSystemUI-res",
         "TwoPanelSettingsLib"
     ],
diff --git a/res/color/control_tint_selector.xml b/res/color/control_tint_selector.xml
new file mode 100644
index 0000000..71191ce
--- /dev/null
+++ b/res/color/control_tint_selector.xml
@@ -0,0 +1,33 @@
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="@color/preference_control_on_focused_color"
+        android:state_enabled="true"
+        android:state_focused="true"
+        android:state_checked="true"/>
+    <item android:color="@color/preference_control_off_focused_color"
+        android:state_enabled="true"
+        android:state_focused="true"/>
+    <item android:color="@color/preference_control_on_default_color"
+        android:state_enabled="true"
+        android:state_checked="true"/>
+    <item android:color="@color/preference_control_off_default_color"
+        android:state_enabled="true"/>
+    <item android:color="@color/preference_control_disabled_focused_color"
+        android:state_focused="true"/>
+    <item android:color="@color/preference_control_disabled_default_color" />
+</selector>
\ No newline at end of file
diff --git a/res/color/switch_track_border_color.xml b/res/color/switch_track_border_color.xml
deleted file mode 100644
index 5362c34..0000000
--- a/res/color/switch_track_border_color.xml
+++ /dev/null
@@ -1,23 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
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
-<selector xmlns:android="http://schemas.android.com/apk/res/android">
-    <item android:state_focused="false" android:state_checked="false" android:state_enabled="true"
-          android:color="@color/switch_track_border_unfocused_unchecked"/>
-    <item android:state_focused="false" android:state_enabled="false"
-        android:color="@color/switch_track_border_unfocused_disabled"/>
-    <item android:color="@android:color/transparent"/>
-</selector>
\ No newline at end of file
diff --git a/res/color/thumb_tint_selector.xml b/res/color/thumb_tint_selector.xml
new file mode 100644
index 0000000..37b4096
--- /dev/null
+++ b/res/color/thumb_tint_selector.xml
@@ -0,0 +1,38 @@
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
+    <item android:color="@color/preference_switch_thumb_on_focused_color"
+        android:state_enabled="true"
+        android:state_focused="true"
+        android:state_checked="true"/>
+    <item android:color="@color/preference_switch_thumb_off_focused_color"
+        android:state_enabled="true"
+        android:state_focused="true"/>
+    <item android:color="@color/preference_switch_thumb_on_default_color"
+        android:state_enabled="true"
+        android:state_checked="true"/>
+    <item android:color="@color/preference_switch_thumb_off_default_color"
+        android:state_enabled="true"/>
+    <item android:color="@color/preference_switch_thumb_on_focused_disabled_color"
+        android:state_focused="true"
+        android:state_checked="true"/>
+    <item android:color="@color/preference_switch_thumb_off_focused_disabled_color"
+        android:state_focused="true"/>
+    <item android:color="@color/preference_switch_thumb_on_default_disabled_color"
+        android:state_checked="true"/>
+    <item android:color="@color/preference_switch_thumb_off_default_disabled_color" />
+</selector>
\ No newline at end of file
diff --git a/res/color/switch_thumb_color.xml b/res/color/thumb_tint_selector_focused.xml
similarity index 57%
rename from res/color/switch_thumb_color.xml
rename to res/color/thumb_tint_selector_focused.xml
index 8e29925..7a197f7 100644
--- a/res/color/switch_thumb_color.xml
+++ b/res/color/thumb_tint_selector_focused.xml
@@ -1,6 +1,6 @@
 <?xml version="1.0" encoding="utf-8"?>
 <!--
-  ~ Copyright (C) 2024 The Android Open Source Project
+  ~ Copyright (C) 2025 The Android Open Source Project
   ~
   ~ Licensed under the Apache License, Version 2.0 (the "License");
   ~ you may not use this file except in compliance with the License.
@@ -15,9 +15,12 @@
   ~ limitations under the License.
   -->
 <selector xmlns:android="http://schemas.android.com/apk/res/android">
-    <item android:state_focused="true" android:state_checked="true"
-          android:color="@color/switch_thumb_focused_color"/>
-    <item android:state_checked="true"
-          android:color="@color/switch_thumb_unfocused_color"/>
-    <item android:color="@color/switch_thumb_unchecked_color"/>
+    <item android:color="@color/preference_switch_thumb_on_focused_color"
+        android:state_enabled="true"
+        android:state_checked="true"/>
+    <item android:color="@color/preference_switch_thumb_off_focused_color"
+        android:state_enabled="true"/>
+    <item android:color="@color/preference_switch_thumb_on_focused_disabled_color"
+        android:state_checked="true"/>
+    <item android:color="@color/preference_switch_thumb_off_focused_disabled_color"/>
 </selector>
\ No newline at end of file
diff --git a/res/drawable/custom_switch_thumb.xml b/res/drawable/custom_switch_thumb.xml
deleted file mode 100644
index 1cfc224..0000000
--- a/res/drawable/custom_switch_thumb.xml
+++ /dev/null
@@ -1,25 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
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
-<shape xmlns:android="http://schemas.android.com/apk/res/android"
-       android:shape="oval" >
-    <solid android:color="@color/switch_thumb_color" />
-    <size
-        android:width="@dimen/switch_height"
-        android:height="@dimen/switch_height" />
-    <stroke android:color="@android:color/transparent" android:width="8dp"/>
-</shape>
\ No newline at end of file
diff --git a/res/drawable/custom_switch_track.xml b/res/drawable/custom_switch_track.xml
deleted file mode 100644
index bf8254e..0000000
--- a/res/drawable/custom_switch_track.xml
+++ /dev/null
@@ -1,27 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
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
-<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
-    <item>
-        <shape android:shape="rectangle">
-            <corners android:radius="25dp"/>
-            <solid android:color="@color/switch_track_color" />
-            <size android:height="@dimen/switch_height" android:width="@dimen/switch_width"/>
-            <stroke android:color="@android:color/transparent" android:width="2.5dp"/>
-        </shape>
-    </item>
-</layer-list>
\ No newline at end of file
diff --git a/res/drawable/volume_row_seekbar.xml b/res/drawable/volume_row_seekbar.xml
index e49fc15..97c7152 100644
--- a/res/drawable/volume_row_seekbar.xml
+++ b/res/drawable/volume_row_seekbar.xml
@@ -21,7 +21,7 @@
         <layer-list>
             <item android:id="@+id/volume_seekbar_background_solid">
                 <shape>
-                    <size android:height="@dimen/volume_dialog_slider_width" />
+                    <size android:height="@dimen/volume_dialog_slider_track_width" />
                     <solid android:color="@color/tv_volume_dialog_seek_bar_background"/>
                     <corners android:radius="@dimen/volume_dialog_slider_corner_radius" />
                 </shape>
diff --git a/res/drawable/volume_row_seekbar_progress.xml b/res/drawable/volume_row_seekbar_progress.xml
index bce193a..74c0c6b 100644
--- a/res/drawable/volume_row_seekbar_progress.xml
+++ b/res/drawable/volume_row_seekbar_progress.xml
@@ -21,9 +21,9 @@
     android:autoMirrored="true">
     <item android:id="@+id/volume_seekbar_progress_solid">
         <shape android:shape="rectangle">
-            <size android:height="@dimen/volume_dialog_slider_width"/>
+            <size android:height="@dimen/volume_dialog_slider_track_width"/>
             <solid android:color="@color/tv_volume_dialog_seek_bar_fill" />
-            <corners android:radius="@dimen/volume_dialog_slider_width" />
+            <corners android:radius="@dimen/volume_dialog_slider_corner_radius" />
         </shape>
     </item>
 </layer-list>
diff --git a/res/layout/checkbox_control_widget.xml b/res/layout/checkbox_control_widget.xml
index f0ca3c5..4b6fde8 100644
--- a/res/layout/checkbox_control_widget.xml
+++ b/res/layout/checkbox_control_widget.xml
@@ -29,5 +29,5 @@
         android:id="@android:id/checkbox"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
-        android:focusable="false" />
+        style="@style/SliceCheckboxStyle" />
 </LinearLayout>
\ No newline at end of file
diff --git a/res/layout/core_slice_preference.xml b/res/layout/core_slice_preference.xml
index 4681e19..e883559 100644
--- a/res/layout/core_slice_preference.xml
+++ b/res/layout/core_slice_preference.xml
@@ -15,7 +15,16 @@
   ~ limitations under the License.
   -->
 
-<merge xmlns:android="http://schemas.android.com/apk/res/android">
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="0dp"
+    android:layout_height="wrap_content"
+    android:layout_weight="1"
+    android:orientation="horizontal"
+    android:gravity="center_vertical"
+    android:paddingVertical="@dimen/control_widget_padding"
+    android:minHeight="48dp"
+    android:duplicateParentState="true">
+
     <ImageView
         android:id="@android:id/icon"
         android:duplicateParentState="true"
@@ -43,4 +52,4 @@
             android:textAppearance="@style/TextAppearance.Panel.ListItem.Secondary"
             android:duplicateParentState="true" />
     </LinearLayout>
-</merge>
\ No newline at end of file
+</LinearLayout>
\ No newline at end of file
diff --git a/res/layout/media_output_device_widget.xml b/res/layout/media_output_device_widget.xml
index a9e92f6..a425ee8 100644
--- a/res/layout/media_output_device_widget.xml
+++ b/res/layout/media_output_device_widget.xml
@@ -22,6 +22,7 @@
     android:layout_height="wrap_content"
     android:gravity="center_vertical"
     android:duplicateParentState="true"
+    android:paddingVertical="@dimen/control_widget_padding"
     android:orientation="horizontal">
 
     <FrameLayout
@@ -68,6 +69,5 @@
         android:id="@+id/media_dialog_radio_button"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
-        android:focusable="false"
-        android:clickable="false" />
+        style="@style/SliceRadioButtonStyle" />
 </LinearLayout>
\ No newline at end of file
diff --git a/res/layout/media_output_settings_progress.xml b/res/layout/media_output_settings_progress.xml
index 022c17b..d5c067e 100644
--- a/res/layout/media_output_settings_progress.xml
+++ b/res/layout/media_output_settings_progress.xml
@@ -22,7 +22,7 @@
       android:visibility="gone"
       android:layout_width="wrap_content"
       android:layout_height="wrap_content"
-      android:tint="@color/progress_bar_color"
+      android:indeterminateTint="@color/progress_bar_color"
       android:background="@null"
       android:layout_centerInParent="true"/>
 </RelativeLayout>
\ No newline at end of file
diff --git a/res/layout/radio_control_widget.xml b/res/layout/radio_control_widget.xml
index b4b1758..8052ed3 100644
--- a/res/layout/radio_control_widget.xml
+++ b/res/layout/radio_control_widget.xml
@@ -26,7 +26,7 @@
 
     <RadioButton
         android:id="@android:id/checkbox"
-        android:layout_height="wrap_content"
         android:layout_width="wrap_content"
-        android:focusable="false" />
+        android:layout_height="wrap_content"
+        style="@style/SliceRadioButtonStyle"/>
 </LinearLayout>
diff --git a/res/layout/switch_control_widget.xml b/res/layout/switch_control_widget.xml
index 671c6a2..878fce1 100644
--- a/res/layout/switch_control_widget.xml
+++ b/res/layout/switch_control_widget.xml
@@ -24,14 +24,10 @@
 
     <include layout="@layout/core_slice_preference" />
 
-    <Switch
+    <com.google.android.material.materialswitch.MaterialSwitch
         android:id="@android:id/switch_widget"
-        android:layout_width="@dimen/switch_width"
-        android:layout_height="@dimen/switch_height"
-        android:background="@null"
-        android:clickable="false"
-        android:duplicateParentState="true"
-        android:focusable="false"
-        android:thumb="@drawable/custom_switch_thumb"
-        android:track="@drawable/custom_switch_track" />
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:theme="@style/SliceSwitchStyle"
+        style="@style/SliceSwitchStyle"/>
 </LinearLayout>
\ No newline at end of file
diff --git a/res/color/switch_track_color.xml b/res/layout/volume_dialog_bottom_section.xml
similarity index 51%
rename from res/color/switch_track_color.xml
rename to res/layout/volume_dialog_bottom_section.xml
index cf37598..9fed234 100644
--- a/res/color/switch_track_color.xml
+++ b/res/layout/volume_dialog_bottom_section.xml
@@ -1,6 +1,5 @@
-<?xml version="1.0" encoding="utf-8"?>
 <!--
-  ~ Copyright (C) 2024 The Android Open Source Project
+  ~ Copyright (C) 2025 The Android Open Source Project
   ~
   ~ Licensed under the Apache License, Version 2.0 (the "License");
   ~ you may not use this file except in compliance with the License.
@@ -14,10 +13,12 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License.
   -->
-<selector xmlns:android="http://schemas.android.com/apk/res/android">
-    <item android:state_focused="true" android:state_checked="true"
-          android:color="@color/switch_track_focused_color"/>
-    <item android:state_checked="true"
-          android:color="@color/switch_track_unfocused_color"/>
-    <item android:color="@color/switch_track_unchecked_color"/>
-</selector>
\ No newline at end of file
+<com.android.keyguard.AlphaOptimizedImageButton xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/volume_row_icon"
+    style="@style/VolumeButtons"
+    android:layout_width="@dimen/volume_dialog_button_size"
+    android:layout_height="@dimen/volume_dialog_button_size"
+    android:layout_gravity="center"
+    android:background="@drawable/tv_volume_dialog_circle"
+    android:soundEffectsEnabled="false"
+    android:tint="@color/accent_tint_color_selector" />
\ No newline at end of file
diff --git a/res/layout/volume_dialog_slider.xml b/res/layout/volume_dialog_slider.xml
new file mode 100644
index 0000000..8d41c88
--- /dev/null
+++ b/res/layout/volume_dialog_slider.xml
@@ -0,0 +1,31 @@
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
+<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="@dimen/volume_dialog_slider_width"
+    android:layout_height="@dimen/volume_dialog_slider_height">
+
+    <SeekBar
+        android:id="@+id/volume_dialog_slider"
+        android:layout_width="@dimen/volume_dialog_slider_height"
+        android:layout_height="@dimen/volume_dialog_slider_width"
+        android:layout_gravity="center"
+        android:background="@null"
+        android:layoutDirection="ltr"
+        android:progressDrawable="@drawable/volume_row_seekbar"
+        android:rotation="270"
+        android:splitTrack="false"
+        android:thumb="@drawable/tv_volume_row_seek_thumb" />
+</FrameLayout>
\ No newline at end of file
diff --git a/res/layout/volume_dialog_top_section.xml b/res/layout/volume_dialog_top_section.xml
new file mode 100644
index 0000000..ece67aa
--- /dev/null
+++ b/res/layout/volume_dialog_top_section.xml
@@ -0,0 +1,41 @@
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
+<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="@dimen/volume_dialog_width"
+    android:layout_height="@dimen/volume_dialog_button_size"
+    android:layout_gravity="bottom|end">
+
+    <View
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:layout_marginBottom="@dimen/volume_dialog_background_top_margin"
+        android:layout_marginTop="@dimen/volume_dialog_background_vertical_margin"
+        android:background="@drawable/volume_dialog_ringer_background" />
+
+    <TextView xmlns:android="http://schemas.android.com/apk/res/android"
+        android:id="@+id/volume_number"
+        android:layout_width="@dimen/volume_dialog_button_size"
+        android:layout_height="@dimen/volume_dialog_button_size"
+        android:layout_gravity="center"
+        android:background="@drawable/tv_volume_dialog_circle"
+        android:fontFeatureSettings="tnum"
+        android:gravity="center"
+        android:maxLength="3"
+        android:textColor="@color/tv_volume_dialog_accent"
+        android:textSize="@dimen/tv_volume_number_text_size" />
+
+</FrameLayout>
\ No newline at end of file
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index ad9d775..de33b70 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Oudio-uitvoer"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Ander toestelle"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Koppel ’n ander toestel"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Ingeboude luidspreker + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Druk "<annotation icon="dpad_icon">"D-paneel"</annotation>" vir oudiotoestelinstellings."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>-instellings"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Kyk jy nog?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Jou TV het aangedui dat jy na ’n ander inset oorgeskakel het en dat hierdie toestel binnekort sal gaan slaap. Kies ’n opsie om hierdie toestel wakker te hou."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ja (<xliff:g id="SECONDS">%1$d</xliff:g> sek.)"</string>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index 37ee645..00701ab 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"የኦዲዮ ውጤት"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"ሌሎች መሣሪያዎች"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"ሌላ መሣሪያ ያገናኙ"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"አብሮ ገነብ ድምፅ ማውጫ + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"ለአዲዮ የመሣሪያ ቅንብሮች "<annotation icon="dpad_icon">"DPAD"</annotation>" ይጫኑ።"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"የ<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> ቅንብሮች።"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"አሁንም እየተመለከቱ ነው?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ቲቪዎ ወደ የተለየ ግብዓት እንደቀየሩ ያመለክታል እና ይህ መሣሪያ በቅርቡ ወደ እንቅልፍ ይሄዳል። ይህን መሣሪያ ንቁ አድርጎ ለማቆየት አማራጭ ይምረጡ።"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"አዎ (<xliff:g id="SECONDS">%1$d</xliff:g>ሰ)"</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 6f3beb1..fc92968 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"إخراج الصوت"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"أجهزة أخرى"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"ربط جهاز آخر"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"مكبّر الصوت المُدمَج + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"للوصول إلى إعدادات الجهاز السماعي، يجب الضغط على "<annotation icon="dpad_icon">"أزرار الاتجاهات"</annotation>"."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"إعدادات <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"هل ما زلت تشاهد المحتوى؟"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"تم الكشف عن تغيير في أحد مصادر الإدخال على التلفزيون، وسيبدأ وضع السكون في هذا الجهاز قريبًا. عليك تحديد أحد الخيارات لإبقاء هذا الجهاز نشطًا."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"نعم (عدد الثواني: <xliff:g id="SECONDS">%1$d</xliff:g>)"</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index b49dc15..ebfff74 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"অডিঅ’ আউটপুট"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"অন্য ডিভাইচ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"আন এটা ডিভাইচ সংযোগ কৰক"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"বিল্ট-ইন স্পীকাৰ + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"অডিঅ’ ডিভাইচৰ ছেটিঙৰ বাবে "<annotation icon="dpad_icon">"DPAD"</annotation>" টিপক।"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>ৰ ছেটিং।"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"আপুনি এতিয়াও চাই আছে নেকি?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"আপোনাৰ টিভিয়ে সূচাইছে যে আপুনি অন্য কোনো ইনপুটলৈ সলনি কৰিছে আৰু এই ডিভাইচটো সোনকালেই সুপ্ত হ’ব। এই ডিভাইচটো সক্ৰিয় কৰি ৰাখিবলৈ এটা বিকল্প বাছনি কৰক।"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"হয় (<xliff:g id="SECONDS">%1$d</xliff:g>ছে)"</string>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 5980fe0..95facc3 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio çıxışı"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Digər cihazlar"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Başqa cihaz qoşun"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Daxili dinamik + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Audio cihaz ayarları üçün "<annotation icon="dpad_icon">"DPAD"</annotation>" üzərinə basın."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> ayarları."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Hələ də izləyirsiniz?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV fərqli daxiletməyə keçdiyinizi göstərdi və bu cihaz tezliklə yuxu rejiminə keçəcək. Bu cihazı oyaq saxlamaq üçün seçim edin."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Bəli (<xliff:g id="SECONDS">%1$d</xliff:g> san.)"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 70daf9a..194da0c 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio izlaz"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Drugi uređaji"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Poveži drugi uređaj"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Ugrađeni zvučnik + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Pritisnite "<annotation icon="dpad_icon">"DPAD"</annotation>" da biste pristupili podešavanjima audio uređaja."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Podešavanja za <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Gledate li još uvek?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV je pokazao da ste prešli na drugi ulaz i ovaj uređaj će uskoro preći u stanje mirovanja. Izaberite neku opciju da ovaj uređaj ne bi prešao u stanje mirovanja."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Da (<xliff:g id="SECONDS">%1$d</xliff:g> sek)"</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 602fb4b..ad39b32 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аўдыявыхад"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Іншыя прылады"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Падключыць іншую прыладу"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Убудаваны дынамік + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Каб адкрыць налады аўдыяпрылады, націсніце "<annotation icon="dpad_icon">"DPAD"</annotation>"."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Налады прылады \"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>\"."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Усё яшчэ гледзіце?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Тэлевізар паказвае, што вы пераключыліся на іншую крыніцу ўваходу і гэта прылада хутка пяройдзе ў рэжым сну. Каб прылада не перайшла ў рэжым сну, выберыце патрэбны варыянт."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Так (<xliff:g id="SECONDS">%1$d</xliff:g> с)"</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index c323034..51c97dc 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аудиоизход"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Други устройства"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Свързване на друго устройство"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Вграден високоговорител + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Натиснете "<annotation icon="dpad_icon">"DPAD"</annotation>" за настройки на аудиоустройството"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Настройки на <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Още ли гледате?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Телевизорът ви сигнализира, че сте превключили към друг вход и това устройство скоро ще премине в спящ режим. Изберете опция, за да остане устройството активно."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Да (<xliff:g id="SECONDS">%1$d</xliff:g> сек)"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 4eaaea4..783e512 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"অডিও আউটপুট"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"অন্যান্য ডিভাইস"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"আরেকটি ডিভাইস কানেক্ট করুন"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"বিল্ট-ইন স্পিকার + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"অডিও ডিভাইস সেটিংসের জন্য "<annotation icon="dpad_icon">"ডি-প্যাড"</annotation>" প্রেস করুন।"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> সেটিংস।"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"আপনি কি এখনও দেখছেন?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"আপনার টিভি থেকে জানা যায় যে আপনি অন্য কোনও ইনপুটে পরিবর্তন করেছেন এবং এই ডিভাইসটি শীঘ্রই স্লিপ মোড চলে যাবে। এই ডিভাইস চালু রাখার জন্য কোনও বিকল্প বেছে নিন।"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"হ্যাঁ (<xliff:g id="SECONDS">%1$d</xliff:g>সেকেন্ড)"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 62bacab..26c15c1 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Izlaz zvuka"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Drugi uređaji"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Povežite drugi uređaj"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Ugrađeni zvučnik + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Za postavke audio uređaja pritisnite "<annotation icon="dpad_icon">"dugmad za smjer"</annotation>"."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Postavke uređaja <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Gledate li još uvijek?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV je pokazao da ste prebacili na drugi ulaz i uređaj će uskoro preći u mirovanje. Odaberite opciju da uređaj ostane aktivan."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Da (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index e620411..a6fb976 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Sortida d\'àudio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Altres dispositius"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Connecta un altre dispositiu"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Altaveu integrat + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Prem la "<annotation icon="dpad_icon">"creu direccional"</annotation>" per a la configuració del dispositiu d\'àudio."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Configuració de <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Encara mires el contingut?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"El televisor ha indicat que has canviat a una altra entrada i aquest dispositiu aviat entrarà en mode de repòs. Selecciona una opció per mantenir aquest dispositiu activat."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Sí (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index c0c7acc..691a96c 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Zvukový výstup"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Ostatní zařízení"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Připojte další zařízení"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Intergoraný reproduktor + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Pro nastavení audiozařízení stiskněte "<annotation icon="dpad_icon">"DPAD"</annotation>"."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Nastavení zařízení <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ještě jste tady?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Vaše televize zaznamenala, že jste přepnuli na jiný vstup, a toto zařízení brzy přejde do režimu spánku. Vyberte jednu z možností, aby toto zařízení nepřešlo do režimu spánku."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ano (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index c9b49f0..44d5ba3 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Lydudgang"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Andre enheder"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Forbind en anden enhed"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Indbygget højttaler + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Tryk på "<annotation icon="dpad_icon">"D-pad"</annotation>" for at gå til indstillingerne for lydenheden."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Indstillinger for <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ser du stadig med?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Dit fjernsyn har angivet, at du har skiftet til en anden indgang, og denne enhed går snart i dvale. Vælg en mulighed for at holde enheden aktiv."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ja (<xliff:g id="SECONDS">%1$d</xliff:g> sek.)"</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index d2b12e1..276c951 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audioausgabe"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Andere Geräte"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Anderes Gerät verbinden"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Integrierter Lautsprecher und S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Drücke auf das "<annotation icon="dpad_icon">"Steuerkreuz"</annotation>", um die Audioeinstellungen des Geräts aufzurufen."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Einstellungen für <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Bist du noch da?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Dein Fernseher hat signalisiert, dass du einen anderen Eingang ausgewählt hast. Daher wechselt dieses Gerät bald in den Ruhemodus. Wähle eine Option aus, damit dieses Gerät aktiv bleibt."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ja (<xliff:g id="SECONDS">%1$d</xliff:g> Sek.)"</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index f90491b..ff24e55 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Έξοδος ήχου"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Άλλες συσκευές"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Σύνδεση σε άλλη συσκευή"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Ενσωματωμένο ηχείο + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Πατήστε "<annotation icon="dpad_icon">"DPAD"</annotation>" για τις ρυθμίσεις συσκευής ήχου."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Ρυθμίσεις του <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Παρακολουθείτε ακόμα;"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Η τηλεόραση υπέδειξε ότι κάνατε εναλλαγή σε διαφορετική είσοδο και αυτή η συσκευή θα μεταβεί σύντομα σε κατάσταση αδράνειας. Ορίστε μια επιλογή, για να παραμείνει αυτή η συσκευή σε κανονική κατάσταση λειτουργίας."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ναι (<xliff:g id="SECONDS">%1$d</xliff:g> δ.)"</string>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index 0e64e2c..d711940 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio output"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Other devices"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Connect another device"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Built-in speaker + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Press "<annotation icon="dpad_icon">"DPAD"</annotation>" for audio device settings."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> settings."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Are you still watching?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Your TV indicated that you switched to a different input and this device will go to sleep soon. Select an option to keep this device awake."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yes (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 49cae17..7dfac89 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -34,8 +34,8 @@
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Other devices"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Connect another device"</string>
     <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Built-in speaker + S/PDIF"</string>
-    <string name="audio_device_tooltip_right" msgid="8410621031774996322">"Press "<annotation icon="dpad_icon">"DPAD_RIGHT"</annotation>" for audio device settings"</string>
-    <string name="audio_device_tooltip_left" msgid="9062689648623861935">"Press "<annotation icon="dpad_icon">"DPAD_LEFT"</annotation>" for audio device settings"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Press "<annotation icon="dpad_icon">"DPAD"</annotation>" for audio device settings."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> settings."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Are you still watching?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Your TV indicated that you switched to a different input and this device will go to sleep soon. Select an option to keep this device awake."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yes (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index 0e64e2c..d711940 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio output"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Other devices"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Connect another device"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Built-in speaker + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Press "<annotation icon="dpad_icon">"DPAD"</annotation>" for audio device settings."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> settings."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Are you still watching?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Your TV indicated that you switched to a different input and this device will go to sleep soon. Select an option to keep this device awake."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yes (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index 0e64e2c..d711940 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio output"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Other devices"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Connect another device"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Built-in speaker + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Press "<annotation icon="dpad_icon">"DPAD"</annotation>" for audio device settings."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> settings."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Are you still watching?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Your TV indicated that you switched to a different input and this device will go to sleep soon. Select an option to keep this device awake."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yes (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 6db9ef8..31309a6 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -34,8 +34,8 @@
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Otros dispositivos"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Conectar otro dispositivo"</string>
     <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Bocina integrada + S/PDIF"</string>
-    <string name="audio_device_tooltip_right" msgid="8410621031774996322">"Presiona "<annotation icon="dpad_icon">"DPAD_RIGHT"</annotation>" para acceder a configuración"</string>
-    <string name="audio_device_tooltip_left" msgid="9062689648623861935">"Presiona "<annotation icon="dpad_icon">"DPAD_LEFT"</annotation>" para acceder a configuración"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Presiona "<annotation icon="dpad_icon">"DPAD"</annotation>" para acceder a configuración."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Configuración de <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"¿Sigues mirando?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Tu TV indicó que cambiaste a una entrada diferente y el dispositivo se pondrá en suspensión pronto. Selecciona una opción para mantenerlo activo."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Sí (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 24388c8..db2f7af 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Salida de audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Otros dispositivos"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Conecta otro dispositivo"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Altavoz integrado + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Pulsa "<annotation icon="dpad_icon">"CRUCETA"</annotation>" para acceder a los ajustes del dispositivo de audio."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Ajustes de <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"¿Sigues ahí?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Tu televisión ha indicado que has cambiado a otra entrada y que este dispositivo entrará en suspensión pronto. Selecciona una opción para mantener este dispositivo activo."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Sí (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 5d569e1..c22f66c 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Heliväljund"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Muud seadmed"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Ühendage teine seade"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Sisseehitatud kõlar + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Heliseadmete seadete avamiseks vajutage klahvi "<annotation icon="dpad_icon">"DPAD"</annotation>"."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Seadme <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> seaded."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Kas vaatate veel?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Teie teleri järgi olete aktiveerinud teise sisendi ja see seade lülitub peagi unerežiimi. Tehke valik, et hoida see seade ärkvel."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Jah (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 34ceb9c..61d5298 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio-irteera"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Beste gailu batzuk"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Konektatu beste gailu bat"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Bozgorailu integratua + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Sakatu "<annotation icon="dpad_icon">"DPAD"</annotation>" audio-gailuaren ezarpenak ikusteko."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> gailuaren ezarpenak."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Hor jarraitzen duzu?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Beste sarrera-iturburu batera aldatu zarela adierazi du telebistak, eta gailu hau inaktibo ezarriko da laster. Hautatu aukera bat gailua aktibo mantentzeko."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Bai (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 274417f..7720450 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -33,14 +33,11 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"خروجی صوتی"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"دستگاه‌های دیگر"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"اتصال دستگاهی دیگر"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"بلندگوی داخلی + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"برای تنظیمات دستگاه صوتی، "<annotation icon="dpad_icon">"DPAD"</annotation>" را فشار دهید."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"تنظیمات <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"هنوز درحال تماشا هستید؟"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"تلویزیون شما نشان می‌دهد که به ورودی دیگری رفته‌اید و این دستگاه به‌زودی به حالت خواب می‌رود. برای بیدار نگه داشتن این دستگاه، یکی از گزینه‌ها را انتخاب کنید."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"بله (<xliff:g id="SECONDS">%1$d</xliff:g> ثانیه)"</string>
-    <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"دوباره سؤال نشود"</string>
+    <string name="hdmi_cec_on_active_source_lost_do_not_show" msgid="8498435538121140325">"دوباره پرسیده نشود"</string>
 </resources>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 83ad509..3e17c6b 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audion toistotapa"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Muut laitteet"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Yhdistä toinen laite"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Sisäänrakennettu kaiutin + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Avaa audiolaitteen asetukset painamalla "<annotation icon="dpad_icon">"DPAD"</annotation>"."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Asetukset: <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Katseletko tätä vielä?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV ilmoitti, että olet vaihtanut toiseen toistotapaan, ja laite siirtyy pian lepotilaan. Valitse yksi vaihtoehto, niin laite pysyy aktiivisena."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Kyllä (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 52cb5f3..284bfe1 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Sortie audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Autres appareils"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Connecter un autre appareil"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Haut-parleur intégré et S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Appuyez sur "<annotation icon="dpad_icon">"pavé directionnel"</annotation>" pour accéder aux paramètres de l\'appareil audio."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Paramètres de <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Êtes-vous toujours là?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Votre téléviseur a indiqué que vous êtes passé à une autre entrée et cet appareil va bientôt se mettre en veille. Sélectionnez une option pour maintenir cet appareil allumé."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Oui (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index a539f6c..0da645a 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Sortie audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Autres appareils"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Associer un autre appareil"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Haut-parleur intégré + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Appuyer sur "<annotation icon="dpad_icon">"DPAD"</annotation>" pour les paramètres de l\'appareil audio."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Paramètres <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Êtes-vous toujours en train de regarder ?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Votre téléviseur a indiqué que vous aviez changé d\'entrée et que cet appareil allait bientôt se mettre en veille. Sélectionnez une option pour que cet appareil reste allumé."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Oui (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 6fdaaa0..059ef1f 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Saída de audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Outros dispositivos"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Conectar outro dispositivo"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Altofalante integrado + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Preme a "<annotation icon="dpad_icon">"cruceta"</annotation>" para acceder á configuración de audio do dispositivo."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Configuración do dispositivo (<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>)."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Segues aí?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"A televisión indicou que cambiaches a unha entrada diferente e que este dispositivo entrará pronto en modo de suspensión. Escolle unha opción para mantelo activo."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Si (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index d3be7ed..1324532 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ઑડિયો આઉટપુટ"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"અન્ય ડિવાઇસ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"અન્ય ડિવાઇસ કનેક્ટ કરો"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"બિલ્ટ-ઇન સ્પીકર + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"ઑડિયો ડિવાઇસના સેટિંગ માટે "<annotation icon="dpad_icon">"DPAD"</annotation>" દબાવો."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> સેટિંગ."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"શું તમે હજી પણ જોઈ રહ્યાં છો?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"તમે કોઈ અલગ ઇનપુટ પર સ્વિચ થયા હોવાનું તમારા ટીવી દ્વારા સૂચવવામાં આવ્યું છે અને ટૂંક સમયમાં આ ડિવાઇસ નિષ્ક્રિય થઈ જશે. આ ડિવાઇસ સક્રિય રાખવા માટે, કોઈ વિકલ્પ પસંદ કરો."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"હા (<xliff:g id="SECONDS">%1$d</xliff:g> સેકન્ડ)"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 7d7e66a..814c9d4 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ऑडियो आउटपुट"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"दूसरे डिवाइस"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"दूसरा डिवाइस कनेक्ट करें"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"टीवी में पहले से मौजूद स्पीकर और S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"ऑडियो डिवाइस की सेटिंग में जाने के लिए, "<annotation icon="dpad_icon">"डी-पैड"</annotation>" दबाएं."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> सेटिंग."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"क्या अब भी टीवी देखना जारी रखना है?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"आपके टीवी से पता चलता है कि आपने किसी दूसरे इनपुट पर स्विच किया है और यह डिवाइस जल्द ही स्लीप मोड में चला जाएगा. इस डिवाइस की स्क्रीन को चालू रखने के लिए कोई विकल्प चुनें."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"हां (<xliff:g id="SECONDS">%1$d</xliff:g>से°)"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 64e8d7e..8513bc9 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audioizlaz"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Ostali uređaji"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Povezivanje s drugim uređajem"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Ugrađeni zvučnik + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Pritisnite "<annotation icon="dpad_icon">"plohu za smjerove"</annotation>" za postavke audiouređaja."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> – postavke."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Još uvijek gledate?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV pokazuje da ste prešli na drugi ulazni signal i ovaj će se uređaj uskoro isključiti. Odaberite opciju da bi ovaj uređaj ostao u aktivnom stanju."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Da (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index e8e0a26..b86ea15 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Hangkimenet"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Egyéb eszközök"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Másik eszköz csatlakoztatása"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Beépített hangszóró + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Az audioeszköz beállításaihoz nyomja meg a "<annotation icon="dpad_icon">"D-PAD"</annotation>" gombot."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> beállításai."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Nézi még?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"A tévé jelezte, hogy Ön másik bemenetre váltott, ezért ez az eszköz hamarosan alvó üzemmódba lép. Válassza ki valamelyik lehetőséget az eszköz ébren tartásához."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Igen (<xliff:g id="SECONDS">%1$d</xliff:g> mp)"</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index a1185a3..606bfe0 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Աուդիո ելք"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Այլ սարքեր"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Միացրեք մեկ այլ սարք"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Ներկառուցված բարձրախոս + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Սեղմեք "<annotation icon="dpad_icon">"DPAD"</annotation>"՝ աուդիո սարքի կարգավորումների համար։"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> սարքի կարգավորումներ։"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Դուք դեռ դիտո՞ւմ եք։"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Ձեր հեռուստացույցը հատկորոշել է, որ դուք փոխել եք մուտքը, և այս սարքը շուտով կանցնի քնի ռեժիմին։ Ընտրեք տարբերակ՝ այս սարքն արթուն պահելու համար։"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Այո (<xliff:g id="SECONDS">%1$d</xliff:g> վ)"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 03f980f..570e0fa 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Output audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Perangkat lain"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Hubungkan perangkat lain"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Speaker bawaan + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Tekan "<annotation icon="dpad_icon">"DPAD"</annotation>" untuk membuka setelan perangkat audio."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Setelan <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Apakah Anda masih menonton?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV Anda menunjukkan bahwa Anda beralih ke input lain dan perangkat ini akan segera masuk ke mode tidur. Pilih salah satu opsi agar perangkat ini tetap aktif."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ya (<xliff:g id="SECONDS">%1$d</xliff:g> dtk)"</string>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 61f9b6c..51d6685 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Hljóðúttak"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Önnur tæki"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Tengja annað tæki"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Innbyggður hátalari + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Ýttu á "<annotation icon="dpad_icon">"stýriflötinn"</annotation>" til að opna hljóðstillingar tækisins."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Stillingar <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ertu að horfa?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Sjónvarpið þitt gaf til kynna að þú hefðir skipt yfir í annað inntak og þetta tæki skiptir brátt yfir í svefnstillingu. Veldu kost til að halda þessu tæki vakandi."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Já (<xliff:g id="SECONDS">%1$d</xliff:g> sek.)"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 8090cbe..f7cbe7f 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Uscita audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Altri dispositivi"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Connetti un altro dispositivo"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Speaker integrato + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Premi "<annotation icon="dpad_icon">"D-PAD"</annotation>" per le impostazioni del dispositivo audio."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Impostazioni di <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Stai ancora guardando?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"La TV ha indicato che è stato attivato un ingresso diverso e che questo dispositivo andrà in modalità di riposo a breve. Seleziona un\'opzione per mantenere attivo questo dispositivo."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Sì (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 292c338..cfcc26b 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"פלט אודיו"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"מכשירים אחרים"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"חיבור של מכשיר אחר"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"רמקול מובנה + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"לוחצים על "<annotation icon="dpad_icon">"DPAD"</annotation>" כדי לפתוח את הגדרות מכשיר האודיו."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"ההגדרות של <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"רוצה להמשיך לצפות?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"הטלוויזיה זיהתה שעברת לקלט ממקור אחר ובקרוב המכשיר הזה יעבור למצב שינה. כדי שהמכשיר יישאר פעיל, עליך לבחור אחת מהאפשרויות."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"כן (<xliff:g id="SECONDS">%1$d</xliff:g> שנ\')"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 32d2ed3..0501814 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -34,8 +34,8 @@
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"他のデバイス"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"別のデバイスに接続"</string>
     <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"内蔵スピーカー + S/PDIF"</string>
-    <string name="audio_device_tooltip_right" msgid="8410621031774996322">"オーディオ機器の設定に移動するには "<annotation icon="dpad_icon">"DPAD_RIGHT"</annotation>" を押します"</string>
-    <string name="audio_device_tooltip_left" msgid="9062689648623861935">"オーディオ機器の設定に移動するには "<annotation icon="dpad_icon">"DPAD_LEFT"</annotation>" を押します"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"オーディオ機器の設定に移動するには "<annotation icon="dpad_icon">"DPAD"</annotation>" を押します。"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> の設定。"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"まだ視聴中ですか？"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"テレビで別の入力に切り替えたため、このデバイスはまもなくスリープ状態になります。このデバイスの電源を入れたままにするためのオプションを 1 つ選択してください。"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"はい（<xliff:g id="SECONDS">%1$d</xliff:g> 秒）"</string>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index e2d264d..bbd8df8 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"გამომავალი აუდიო"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"სხვა მოწყობილობები"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"სხვა მოწყობილობის დაკავშირება"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"ჩაშენებული დინამიკი + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"აუდიომოწყობილობის პარამეტრებისთვის დააჭირეთ: "<annotation icon="dpad_icon">"DPAD"</annotation></string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>-ის პარამეტრები."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"კიდევ უყურებთ?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"თქვენმა ტელევიზორმა მიუთითა, რომ გადაერთეთ სხვა შემავალ სიგნალზე და ეს მოწყობილობა მალე ძილის რეჟიმში გადავა. აირჩიეთ ვარიანტი, რომ მოწყობილობა არ გაითიშოს."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"დიახ (<xliff:g id="SECONDS">%1$d</xliff:g> წამი)"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 9cc75e4..bb658c4 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аудио шығысы"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Басқа құрылғылар"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Басқа құрылғыны қосу"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Ендірілген динамик + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Аудио құрылғы параметрлері үшін "<annotation icon="dpad_icon">"DPAD"</annotation>" түймесін басыңыз."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> параметрлері."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Әлі көріп отырсыз ба?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Теледидарыңыз басқа кіріске ауысқаныңызды және бұл құрылғы жақын арада ұйқы режиміне өтетінін анықтады. Бұл құрылғы өшіп қалмауы үшін, тиісті опцияны таңдаңыз."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Иә (<xliff:g id="SECONDS">%1$d</xliff:g> сек)"</string>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index e967c68..52d6085 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ធាតុចេញសំឡេង"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"ឧបករណ៍ផ្សេងទៀត"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"ភ្ជាប់ឧបករណ៍ផ្សេងទៀត"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"ឧបករណ៍សំឡេងដែលភ្ជាប់មកជាមួយស្រាប់ + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"ចុច "<annotation icon="dpad_icon">"DPAD"</annotation>" សម្រាប់ការ​កំណត់ឧបករណ៍សំឡេង។"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"ការកំណត់ <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>។"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"តើអ្នកកំពុងនៅមើលដែរឬទេ?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ទូរទស្សន៍របស់អ្នកបានបង្ហាញថាអ្នកបានប្ដូរទៅឧបករណ៍​បញ្ចូលផ្សេង ហើយឧបករណ៍នេះនឹងប្ដូរទៅមុខងារដេកក្នុងពេលឆាប់ៗនេះ។ ជ្រើសរើសជម្រើសមួយ ដើម្បីរក្សាឧបករណ៍នេះឱ្យនៅបើកចោល។"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"បាទ/ចាស (<xliff:g id="SECONDS">%1$d</xliff:g> វិនាទី)"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 8fe27a2..0cd8723 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ಆಡಿಯೋ ಔಟ್‌ಪುಟ್"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"ಇತರ ಸಾಧನಗಳು"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"ಮತ್ತೊಂದು ಸಾಧನವನ್ನು ಕನೆಕ್ಟ್ ಮಾಡಿ"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"ಇನ್-ಬಿಲ್ಟ್ ಸ್ಪೀಕರ್ + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"ಆಡಿಯೋ ಸಾಧನ ಸೆಟ್ಟಿಂಗ್‌ಗಳಿಗಾಗಿ "<annotation icon="dpad_icon">"DPAD"</annotation>" ಒತ್ತಿರಿ"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> ಸೆಟ್ಟಿಂಗ್‌ಗಳು."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"ನೀವು ಇನ್ನೂ ವೀಕ್ಷಿಸುತ್ತಿದ್ದೀರಾ?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ನೀವು ಬೇರೆ ಇನ್‌ಪುಟ್‌ಗೆ ಬದಲಾಯಿಸಿದ್ದೀರಿ ಮತ್ತು ಈ ಸಾಧನವು ಶೀಘ್ರದಲ್ಲೇ ನಿದ್ರಿಸಲಿದೆ ಎಂದು ನಿಮ್ಮ ಟಿವಿ ಸೂಚಿಸುತ್ತದೆ. ಈ ಸಾಧನವನ್ನು ಎಚ್ಚರವಾಗಿರಿಸಲು ಒಂದು ಆಯ್ಕೆಯನ್ನು ಆಯ್ಕೆಮಾಡಿ."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ಹೌದು (<xliff:g id="SECONDS">%1$d</xliff:g>ಗಳು)"</string>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index 6d0da53..447c884 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"오디오 출력"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"다른 기기"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"다른 기기 연결"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"내장 스피커 + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"오디오 기기 설정을 보려면 "<annotation icon="dpad_icon">"방향 패드"</annotation>"를 누르세요."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> 설정입니다."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"아직 시청하고 계신가요?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV에서 다른 입력으로 전환되었다고 표시되었으며 이 기기는 곧 절전 모드로 전환될 예정입니다. 옵션을 선택하여 이 기기를 켜진 상태로 유지하세요."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"예(<xliff:g id="SECONDS">%1$d</xliff:g>초)"</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index 2dadbb1..6351e54 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аудио түзмөк"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Башка түзмөктөр"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Башка түзмөктү туташтыруу"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Кыстарылган динамик + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Аудио түзмөктүн параметрлери – "<annotation icon="dpad_icon">"DPAD"</annotation>" дегенди басыңыз."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> параметрлери."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Көрүп жатасызбы?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Сыналгыңыз башка киргизүү булагына которулганыңызды жана бул түзмөк жакында уйку режимине өтөрүн көрсөттү. Бул түзмөктүн экраны өчүп калбашы үчүн, параметр тандаңыз."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ооба (<xliff:g id="SECONDS">%1$d</xliff:g> сек.)"</string>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index 30468dc..ff35907 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ເອົ້າພຸດສຽງ"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"ອຸປະກອນອື່ນໆ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"ເຊື່ອມຕໍ່ອຸປະກອນອື່ນ"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"ລຳໂພງໃນຕົວ + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"ກົດ "<annotation icon="dpad_icon">"Dpad"</annotation>" ສຳລັບການຕັ້ງຄ່າເຄື່ອງສຽງ."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"ການຕັ້ງຄ່າ <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"ທ່ານຍັງຄົງເບິ່ງຢູ່ບໍ?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ໂທລະທັດຂອງທ່ານລະບຸວ່າທ່ານໄດ້ສະຫຼັບໄປໃຊ້ອິນພຸດອື່ນ ແລະ ອຸປະກອນນີ້ກຳລັງຈະເຂົ້າສູ່ໂໝດນອນໃນໄວໆນີ້. ກະລຸນາເລືອກຕົວເລືອກໃດໜຶ່ງເພື່ອເປີດອຸປະກອນນີ້ປະໄວ້."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ແມ່ນ (<xliff:g id="SECONDS">%1$d</xliff:g> ວິ)"</string>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index a64f108..3f51b4f 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -34,8 +34,8 @@
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Kiti įrenginiai"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Prijunkite kitą įrenginį"</string>
     <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Įtaisytas garsiakalbis + S/PDIF"</string>
-    <string name="audio_device_tooltip_right" msgid="8410621031774996322">"Pasp. "<annotation icon="dpad_icon">"DPAD_RIGHT"</annotation>", kad būtų rodomi garso įr. nust."</string>
-    <string name="audio_device_tooltip_left" msgid="9062689648623861935">"Pasp. "<annotation icon="dpad_icon">"DPAD_LEFT"</annotation>", kad pasiekt. garso įreng. nust."</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Paspauskite "<annotation icon="dpad_icon">"DPAD"</annotation>", kad būtų rodomi garso įrenginio nustatymai."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"„<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>“ nustatymai."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ar tebežiūrite?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Televizorius nurodė, kad perjungėte į kitą įvestį, ir šis įrenginys netrukus bus išjungtas. Pasirinkite parinktį, kad šis įrenginys išliktų aktyvus."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Taip (<xliff:g id="SECONDS">%1$d</xliff:g> sek.)"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index be38f50..ad9929c 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio izvade"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Citas ierīces"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Pievienot citu ierīci"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Iebūvēts skaļrunis un S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Nospiediet "<annotation icon="dpad_icon">"DPAD"</annotation>", lai atvērtu audioierīces iestatījumus."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Iestatījumi ierīcei <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Vai jūs joprojām skatāties?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Jūsu televizors norādīja, ka pārslēdzāties uz citu ievades avotu un šī ierīce drīz pāries miega režīmā. Atlasiet opciju, lai neļautu šai ierīcei pāriet miega režīmā."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Jā (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 48dba92..16cd932 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Излез за аудио"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Други уреди"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Поврзете друг уред"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Вграден звучник + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Притиснете "<annotation icon="dpad_icon">"DPAD"</annotation>" за поставките за аудиоуредот."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Поставки за <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Дали сѐ уште гледате?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Вашиот телевизор покажа дека сте се префрлиле на друг влез и дека уредов наскоро ќе влезе во „Режим на мирување“. Изберете една опција за да го држи уредов буден."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Да (<xliff:g id="SECONDS">%1$d</xliff:g> сек.)"</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 96e4fc4..2b70dba 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ഓഡിയോ ഔട്ട്‌പുട്ട്"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"മറ്റ് ഉപകരണങ്ങൾ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"മറ്റൊരു ഉപകരണം കണക്റ്റ് ചെയ്യുക"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"ബിൽറ്റ്-ഇൻ സ്‌പീക്കർ + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"ഓഡിയോ ഉപകരണ ക്രമീകരണത്തിനുള്ള "<annotation icon="dpad_icon">"DPAD"</annotation>" അമർത്തുക."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> ക്രമീകരണം."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"ഇപ്പോഴും കാണുന്നുണ്ടോ?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"നിങ്ങൾ മറ്റൊരു ഇൻപുട്ടിലേക്ക് മാറിയെന്നും ഉപകരണം ഉടൻ പ്രവർത്തനരഹിതമാക്കുമെന്നും ടിവി സൂചിപ്പിച്ചിരിക്കുന്നു. ഈ ഉപകരണം സജീവമാക്കി നിലനിർത്താൻ ഓപ്ഷൻ തിരഞ്ഞെടുക്കുക."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"അതെ (<xliff:g id="SECONDS">%1$d</xliff:g>)"</string>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index e43ce00..e06e1c9 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аудио гаралт"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Бусад төхөөрөмж"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Өөр төхөөрөмж холбох"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Бүрэлдэхүүн чанга яригч + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Аудио төхөөрөмжийн тохиргоонд хандах бол "<annotation icon="dpad_icon">"DPAD"</annotation>" дээр дарна уу."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>-н тохиргоо."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Та үзсээр байна уу?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Таны ТВ таныг өөр оролт руу сэлгэсэн болохыг илэрхийлсэн ба энэ төхөөрөмж удахгүй идэвхгүй болно. Энэ төхөөрөмжийг идэвхтэй байлгахын тулд нэг сонголтыг сонгоно уу."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Тийм (<xliff:g id="SECONDS">%1$d</xliff:g> сек)"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 6a86991..c3a534b 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ऑडिओ आउटपुट"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"इतर डिव्हाइस"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"दुसरे डिव्हाझस कनेक्ट करा"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"बिल्ट-इन स्पीकर + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"ऑडिओ डिव्हाइस सेटिंग्जसाठी "<annotation icon="dpad_icon">"DPAD"</annotation>" प्रेस करा"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> सेटिंग्ज."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"तुम्ही अजूनही पाहत आहात का?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"तुमच्या टीव्हीने सूचित केले आहे की तुम्ही वेगळ्या इनपुटवर स्विच केले आहे आणि हे डिव्हाइस लवकरच निष्क्रिय होईल. हे डिव्हाइस सुरू ठेवण्यासाठी पर्याय निवडा."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"होय (<xliff:g id="SECONDS">%1$d</xliff:g>से)"</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 1e5fb2e..b868a44 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Output audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Peranti lain"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Sambungkan peranti lain"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Pembesar suara terbina dalam + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Tekan "<annotation icon="dpad_icon">"DPAD"</annotation>" untuk tetapan peranti audio."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Tetapan <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Adakah anda masih menonton?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV anda menunjukkan bahawa anda telah beralih kepada input yang berbeza dan peranti ini akan tidur tidak lama lagi. Pilih satu pilihan untuk memastikan peranti ini berjaga."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ya (<xliff:g id="SECONDS">%1$d</xliff:g>)"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index a2b766a..d6df819 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"အသံထွက်မည့် ကိရိယာ"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"အခြားစက်များ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"အခြားစက်နှင့် ချိတ်ဆက်ခြင်း"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"အသင့်ပါပြီး စပီကာ + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"အသံစက်ပစ္စည်း ဆက်တင်များအတွက် "<annotation icon="dpad_icon">"DPAD"</annotation>" ကို နှိပ်ပါ။"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> ဆက်တင်များ။"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"ကြည့်နေသေးသလား။"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"အခြားအဝင်ပေါက်ကို ပြောင်းထားသည်ဟု သင့် TV က ညွှန်ပြထားပြီး ဤစက်သည် မကြာမီတွင် ပိတ်သွားပါမည်။ ဤစက်ကို ဖွင့်ထားရန် နည်းလမ်းတစ်ခု ရွေးပါ။"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yes (<xliff:g id="SECONDS">%1$d</xliff:g> စက္ကန့်)"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index 022c11c..8e5c783 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Lydutdata"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Andre enheter"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Koble til en annen enhet"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Innebygd høyttaler + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Trykk på "<annotation icon="dpad_icon">"DPAD"</annotation>" for å åpne lydenhetsinnstillingene."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Innstillinger for <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ser du fortsatt på?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV-en har indikert at du har byttet til en annen inndataenhet, og denne enheten går snart i hvilemodus. Velg et alternativ for å holde denne enheten våken."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ja (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 005932d..5cbfa9a 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"अडियो आउटपुट"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"अन्य डिभाइसहरू"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"अर्को डिभाइस कनेक्ट गर्नुहोस्"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"अन्तनिर्मित स्पिकर + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"अडियो डिभाइसका सेटिङ एक्सेस गर्न "<annotation icon="dpad_icon">"DPAD"</annotation>" थिच्नुहोस्।"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> का सेटिङ।"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"तपाईं अझै पनि हेरिरहनुभएको छ?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"तपाईंको टिभीले तपाईंले अर्को इन्पुट बदल्नुभएको छ र यो डिभाइस चाँडै नै स्लिप मोडमा जाने छ भन्ने कुरा जनाएको छ। यो डिभाइसको स्क्रिन अन राख्न एउटा विकल्प चयन गर्नुहोस्।"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"अँ (<xliff:g id="SECONDS">%1$d</xliff:g> सेकेन्ड)"</string>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index 8066ac9..75a9feb 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio-uitvoer"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Andere apparaten"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Nog een apparaat koppelen"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Ingebouwde speaker + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Druk op "<annotation icon="dpad_icon">"DPAD"</annotation>" voor de instellingen van het audioapparaat."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Instellingen voor <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ben je nog aan het kijken?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Je tv heeft aangegeven dat je bent overgeschakeld naar een andere ingang en dat dit apparaat binnenkort in de slaapstand gaat. Selecteer een optie om dit apparaat actief te houden."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ja (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index e682687..7fca05c 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ଅଡିଓ ଆଉଟପୁଟ"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"ଅନ୍ୟ ଡିଭାଇସ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"ଅନ୍ୟ ଏକ ଡିଭାଇସ କନେକ୍ଟ କରନ୍ତୁ"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"ବିଲ୍ଟ-ଇନ ସ୍ପିକର + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"ଅଡିଓ ଡିଭାଇସ ସେଟିଂସ ପାଇଁ "<annotation icon="dpad_icon">"DPAD"</annotation>"କୁ ଦବାନ୍ତୁ।"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> ସେଟିଂସ।"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"ଆପଣ ଏବେ ବି ଦେଖୁଛନ୍ତି?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ଆପଣ ଏକ ଭିନ୍ନ ଇନପୁଟକୁ ସୁଇଚ କରିଛନ୍ତି ଏବଂ ଏହି ଡିଭାଇସ ଶୀଘ୍ର ବନ୍ଦ ହୋଇଯିବ ବୋଲି ଆପଣଙ୍କ ଟିଭି ସୂଚିତ କରିଛି। ଏହି ଡିଭାଇସକୁ ସକ୍ରିୟ ରଖିବା ପାଇଁ ଏକ ବିକଳ୍ପକୁ ଚୟନ କରନ୍ତୁ।"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ହଁ (<xliff:g id="SECONDS">%1$d</xliff:g> ସେକେଣ୍ଡ)"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 53306ed..d19b12b 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ਆਡੀਓ ਆਊਟਪੁੱਟ"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"ਹੋਰ ਡੀਵਾਈਸ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"ਕੋਈ ਹੋਰ ਡੀਵਾਈਸ ਕਨੈਕਟ ਕਰੋ"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"ਬਿਲਟ-ਇਨ ਸਪੀਕਰ + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"ਆਡੀਓ ਡੀਵਾਈਸ ਸੈਟਿੰਗਾਂ ਲਈ "<annotation icon="dpad_icon">"DPAD"</annotation>" ਦਬਾਓ।"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> ਸੈਟਿੰਗਾਂ।"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"ਕੀ ਤੁਸੀਂ ਹਾਲੇ ਵੀ ਦੇਖ ਰਹੇ ਹੋ?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ਤੁਹਾਡੇ ਟੀਵੀ ਨੇ ਸੰਕੇਤ ਦਿੱਤਾ ਹੈ ਕਿ ਤੁਸੀਂ ਕਿਸੇ ਵੱਖਰੇ ਇਨਪੁੱਟ \'ਤੇ ਸਵਿੱਚ ਕੀਤਾ ਹੈ ਅਤੇ ਇਹ ਡੀਵਾਈਸ ਜਲਦੀ ਹੀ ਸਲੀਪ ਮੋਡ ਵਿੱਚ ਚਲਾ ਜਾਵੇਗਾ। ਇਸ ਡੀਵਾਈਸ ਨੂੰ ਕਿਰਿਆਸ਼ੀਲ ਰੱਖਣ ਲਈ ਇੱਕ ਵਿਕਲਪ ਚੁਣੋ।"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ਹਾਂ (<xliff:g id="SECONDS">%1$d</xliff:g>ਸਕਿੰਟ)"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 51a4f57..f67f803 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Wyjście audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Inne urządzenia"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Podłącz inne urządzenie"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Wbudowany głośnik + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Naciśnij "<annotation icon="dpad_icon">"pad kierunkowy"</annotation>", aby otworzyć ustawienia urządzenia audio."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Ustawienia urządzenia <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Oglądasz jeszcze?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Telewizor wskazał, że przełączono na inne wejście i urządzenie wkrótce przejdzie w stan uśpienia. Wybierz opcję, aby utrzymać aktywność tego urządzenia."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Tak (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-pt-rBR/strings.xml b/res/values-pt-rBR/strings.xml
index f0bf513..89638aa 100644
--- a/res/values-pt-rBR/strings.xml
+++ b/res/values-pt-rBR/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Saída de áudio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Outros dispositivos"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Conectar outro dispositivo"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Alto-falante integrado + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Pressione o botão "<annotation icon="dpad_icon">"DPAD"</annotation>" para ver as configurações do dispositivo de áudio."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Configurações de <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ainda está assistindo?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Sua TV indicou que você mudou para uma entrada diferente, e o dispositivo vai entrar no modo de suspensão em breve. Selecione uma opção para manter o dispositivo ativado."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Sim (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 9b64d2d..72c5a91 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -32,10 +32,10 @@
     <string name="screen_stopped_recording_announcement" msgid="4206290782104851906">"Gravação de ecrã parada"</string>
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Saída de áudio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Outros dispositivos"</string>
-    <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Ligue outro dispositivo"</string>
+    <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Ligar outro dispositivo"</string>
     <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Altifalante integrado + S/PDIF"</string>
-    <string name="audio_device_tooltip_right" msgid="8410621031774996322">"Prima "<annotation icon="dpad_icon">"DPAD_RIGHT"</annotation>" para definições do dispositivo de áudio"</string>
-    <string name="audio_device_tooltip_left" msgid="9062689648623861935">"Prima "<annotation icon="dpad_icon">"DPAD_LEFT"</annotation>" para definições do dispositivo de áudio"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Prima o "<annotation icon="dpad_icon">"teclado direcional"</annotation>" para aceder às definições do dispositivo de áudio."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Definições do dispositivo <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ainda está a ver?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"A sua TV indicou que mudou para uma entrada diferente e este dispositivo vai entrar em suspensão em breve. Selecione uma opção para manter este dispositivo ativado."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Sim (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index f0bf513..89638aa 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Saída de áudio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Outros dispositivos"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Conectar outro dispositivo"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Alto-falante integrado + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Pressione o botão "<annotation icon="dpad_icon">"DPAD"</annotation>" para ver as configurações do dispositivo de áudio."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Configurações de <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ainda está assistindo?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Sua TV indicou que você mudou para uma entrada diferente, e o dispositivo vai entrar no modo de suspensão em breve. Selecione uma opção para manter o dispositivo ativado."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Sim (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index ebc7218..0ce0783 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Ieșire audio"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Alte dispozitive"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Conectează alt dispozitiv"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Difuzor încorporat + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Apasă pe "<annotation icon="dpad_icon">"DPAD"</annotation>" pentru setările dispozitivului audio."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Setări <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Încă vizionezi?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Televizorul a indicat că ai comutat la altă intrare și dispozitivul va intra în modul de repaus în curând. Selectează o opțiune pentru a menține dispozitivul activ."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Da (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 5121074..30a38c6 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аудиовыход"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Другие устройства"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Подключить другое устройство"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Встроенный динамик и S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Чтобы открыть настройки аудиоустройства, нажмите "<annotation icon="dpad_icon">"DPAD"</annotation></string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Настройки устройства \"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>\"."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Вы всё ещё смотрите?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Так как вы переключились на другой вход, это устройство скоро перейдет в спящий режим. Чтобы устройство оставалось активным, выберите нужный вариант."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Да (<xliff:g id="SECONDS">%1$d</xliff:g> сек.)"</string>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index a37da52..e533e61 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ශ්‍රව්‍ය ප්‍රතිදානය"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"වෙනත් උපාංග"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"වෙනත් උපාංගයක් සම්බන්ධ කරන්න"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"එකට තැනූ ස්පීකරය + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"ශ්‍රව්‍ය උපාංග සැකසීම් සඳහා "<annotation icon="dpad_icon">"DPAD"</annotation>" ඔබන්න."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> සැකසීම්."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"ඔබ තවමත් නරඹනවා ද?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ඔබ වෙනත් ආදානයකට මාරු වූ බව ඔබේ රූපවාහිනිය පෙන්වා දුන් අතර මෙම උපාංගය ඉක්මනින් නින්දට යනු ඇත. මෙම උපාංගය අවදියෙන් තබා ගැනීමට විකල්පයක් තෝරන්න."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ඔව් (ත<xliff:g id="SECONDS">%1$d</xliff:g>)"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index 15b7de6..75bc841 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Zvukový výstup"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Iné zariadenia"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Pripojte ďalšie zariadenie"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Vstavaný reproduktor + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Ak chcete zobraziť k nastavenia audio zariadenia, stlačte "<annotation icon="dpad_icon">"DPAD"</annotation></string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Nastavenia zariadenia <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Stále pozeráte?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Signál z televízora naznačil, že ste prepli na iný vstup a toto zariadenie sa čoskoro prepne do režimu spánku. Vyberte niektorú možnosť, aby toto zariadenie neprešlo do režimu spánku."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Áno (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index 3079231..62badd2 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Zvočni izhod"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Druge naprave"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Povežite drugo napravo"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Vgrajen zvočnik + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Pritisnite "<annotation icon="dpad_icon">"DPAD"</annotation>" za nastavitve naprave za zvok."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Nastavitve naprave <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ali še vedno gledate?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Televizor je sporočil, da ste preklopili na drug vhod, in ta naprava bo kmalu preklopila v stanje pripravljenosti. Izberite eno možnost, da ta naprava ostane aktivna."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Da (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 3c8515b..9ac5ac4 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Dalja e audios"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Pajisjet e tjera"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Lidh një pajisje tjetër"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Altoparlanti i integruar + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Shtyp "<annotation icon="dpad_icon">"DPAD"</annotation>" për cilësimet e pajisjes audio."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Cilësimet e <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Po vazhdon të shikosh?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Televizori yt ka treguar se ke kaluar te një hyrje tjetër dhe kjo pajisje do të kalojë së shpejti në gjumë. Zgjidh një opsion për ta mbajtur zgjuar këtë pajisje."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Po (<xliff:g id="SECONDS">%1$d</xliff:g> sek.)"</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 0741b26..77d72df 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аудио излаз"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Други уређаји"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Повежи други уређај"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Уграђени звучник + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Притисните "<annotation icon="dpad_icon">"DPAD"</annotation>" да бисте приступили подешавањима аудио уређаја."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Подешавања за <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Гледате ли још увек?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ТВ је показао да сте прешли на други улаз и овај уређај ће ускоро прећи у стање мировања. Изаберите неку опцију да овај уређај не би прешао у стање мировања."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Да (<xliff:g id="SECONDS">%1$d</xliff:g> сек)"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index 8bd31dc..03f8a66 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Ljudutgång"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Andra enheter"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Anslut en annan enhet"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Inbyggd högtalare + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Tryck på "<annotation icon="dpad_icon">"DPAD"</annotation>" för ljudenhetsinställningarna."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Inställningar för <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Tittar du fortfarande?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Tv:n indikerade att du bytte till en annan ingång och den här enheten går snart i viloläge. Gör ett val så att inte enheten stängs av."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yes (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index b41ebfc..286c918 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Mfumo wa kutoa sauti"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Vifaa vingine"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Unganisha kifaa kingine"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Spika iliyojumuishwa + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Bonyeza "<annotation icon="dpad_icon">"DPAD"</annotation>" upate mipangilio ya kifaa cha sauti."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Mipangilio ya <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Je, bado unatazama?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV yako imeonyesha kuwa ulitumia kifaa tofauti cha kuingiza data na kifaa hiki kitaingia katika hali tuli hivi karibuni. Teua chaguo ili kifaa hiki kisizime."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ndiyo (Sek <xliff:g id="SECONDS">%1$d</xliff:g>)"</string>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 3900093..6400841 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ஆடியோ அவுட்புட்"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"பிற சாதனங்கள்"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"வேறொரு சாதனத்தை இணையுங்கள்"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"உள்ளமைந்த ஸ்பீக்கர் + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"ஆடியோ சாதன அமைப்புகளுக்கு "<annotation icon="dpad_icon">"டி-பேட்"</annotation>" பட்டனை அழுத்தவும்."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> அமைப்புகள்."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"இன்னும் பார்க்கிறீர்களா?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"நீங்கள் வேறொரு உள்ளீட்டிற்கு மாறிவிட்டீர்கள் என்றும் இந்தச் சாதனம் விரைவில் உறக்கப் பயன்முறைக்குச் செல்லும் என்றும் உங்கள் டிவி குறிப்பிட்டுள்ளது. இந்தச் சாதனத்தை இயக்கத்தில் வைத்திருக்க ஒரு விருப்பத்தைத் தேர்வுசெய்யவும்."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ஆம் (<xliff:g id="SECONDS">%1$d</xliff:g>வி)"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 2c008c7..dd3fa03 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"ఆడియో అవుట్‌పుట్"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"ఇతర పరికరాలు"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"మరొక పరికరాన్ని కనెక్ట్ చేయండి"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"బిల్ట్-ఇన్ స్పీకర్ + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"ఆడియో పరికర సెట్టింగ్‌ల కోసం "<annotation icon="dpad_icon">"DPAD"</annotation>"‌ను నొక్కండి."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> సెట్టింగ్‌లు."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"మీరు ఇంకా చూస్తున్నారా?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"మీరు వేరొక ఇన్‌పుట్‌కు మారారని మీ TV ఇండికేట్ చేస్తుంది, ఈ పరికరం త్వరలో స్లీప్ మోడ్‌లోకి వెళ్తుంది. ఈ పరికరాన్ని యాక్టివ్‌గా ఉంచడానికి ఒక ఆప్షన్‌ను ఎంచుకోండి."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yes (<xliff:g id="SECONDS">%1$d</xliff:g>సె)"</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index 489cc9a..d00f535 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"เอาต์พุตเสียง"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"อุปกรณ์อื่นๆ"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"เชื่อมต่ออุปกรณ์อื่น"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"ลำโพงในตัว + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"กด "<annotation icon="dpad_icon">"Dpad"</annotation>" เพื่อตั้งค่าอุปกรณ์เสียง"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"การตั้งค่า <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"คุณยังรับชมอยู่ไหม"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"ทีวีแจ้งว่าคุณเปลี่ยนเป็นอินพุตอื่นและอุปกรณ์นี้จะเข้าสู่โหมดสลีปในไม่ช้า เลือกตัวเลือกเพื่อเปิดอุปกรณ์นี้ค้างไว้"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ใช่เลย (<xliff:g id="SECONDS">%1$d</xliff:g> วินาที)"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 4f01e57..7ae869b 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio output"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Iba pang device"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Magkonekta ng ibang device"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Built-in na speaker + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Pindutin ang "<annotation icon="dpad_icon">"DPAD"</annotation>" para sa mga setting ng audio device."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Mga setting ng <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Nanonood ka pa ba?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Tinukoy ng TV mo na lumipat ka sa ibang input at malapit nang mag-sleep ang device na ito. Pumili ng isang opsyon para panatilihing nakabukas ang device na ito."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Oo (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index d5b061c..785ffab 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Ses çıkışı"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Diğer cihazlar"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Başka bir cihaz bağlayın"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Dahili hoparlör + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Ses sistemi ayarları için "<annotation icon="dpad_icon">"DPAD"</annotation>" tuşuna basın."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> ayarları."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Hâlâ izliyor musunuz?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV\'niz farklı bir girişe geçtiğinizi bildirdi ve bu cihaz yakında uyku moduna geçecektir. Bu cihazın uyanık kalması için bir seçenek belirleyin."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Evet (<xliff:g id="SECONDS">%1$d</xliff:g> sn.)"</string>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index 5e0a7cb..4accf09 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Аудіовихід"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Інші пристрої"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Підключити інший пристрій"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Вбудований динамік + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Натисніть "<annotation icon="dpad_icon">"DPAD"</annotation>", щоб перейти до налаштувань аудіопристрою."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Налаштування пристрою \"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>\"."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ви ще дивитеся?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Телевізор повідомив, що ви перемкнулися на інше джерело вхідного сигналу й цей пристрій скоро перейде в режим сну. Виберіть опцію, щоб цей пристрій не переходив у режим сну."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Так (<xliff:g id="SECONDS">%1$d</xliff:g> с)"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 7173d02..766aec5 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"آڈیو کا آؤٹ پُٹ"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"دیگر آلات"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"کسی اور آلے کو منسلک کریں"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"پہلے سے شامل اسپیکر ‎+ S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"ہر آڈیو آلے کی ترتیبات کے لیے "<annotation icon="dpad_icon">"DPAD"</annotation>" دبائيں۔"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"‫<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> کی ترتیبات۔"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"کیا آپ اب تک دیکھ رہے ہیں؟"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"آپ کے TV نے نشاندہی کی ہے کہ آپ نے ایک مختلف ان پٹ پر سوئچ کیا ہے اور یہ آلہ جلد ہی سلیپ موڈ میں چلا جائے گا۔ اس آلے کو بیدار رکھنے کے لیے ایک اختیار منتخب کریں۔"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"ہاں (<xliff:g id="SECONDS">%1$d</xliff:g> سیکنڈ)"</string>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index cfaf89a..ee0cd37 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Audio chiqishi"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Boshqa qurilmalar"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Boshqa qurilmaga ulang"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Ichki karnay + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Audio qurilma sozlamalari uchun "<annotation icon="dpad_icon">"DPAD"</annotation>" tugmasini bosing."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g> sozlamalari."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Tomosha qilyapsizmi?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"Televizoringiz boshqa kirishga oʻtganingizni va bu qurilma tez orada uyquga ketishini koʻrsatdi. Bu qurilmani hushyor tutish uchun bitta variantni tanlang."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Ha (<xliff:g id="SECONDS">%1$d</xliff:g> s)"</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index e7da3de..8e993b9 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Đầu ra âm thanh"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Thiết bị khác"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Kết nối thiết bị khác"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Loa tích hợp + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Nhấn "<annotation icon="dpad_icon">"DPAD"</annotation>" để xem chế độ cài đặt thiết bị âm thanh."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Cài đặt <xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Bạn vẫn đang xem?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"TV của bạn cho biết rằng bạn đã chuyển sang một cổng vào khác và thiết bị này sắp chuyển sang chế độ ngủ. Hãy chọn một cổng vào để thiết bị này tiếp tục ở trạng thái bật."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Được (<xliff:g id="SECONDS">%1$d</xliff:g> giây)"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index bab3385..b9a0ad6 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"音频输出"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"其他设备"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"连接另一部设备"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"内置扬声器 + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"按"<annotation icon="dpad_icon">"方向键"</annotation>"可打开音频设备设置。"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"“<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>”的设置。"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"您仍在观看吗？"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"您的电视显示您已切换到其他输入源，此设备即将进入睡眠模式。选择一个选项即可使该设备保持唤醒状态。"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"是（<xliff:g id="SECONDS">%1$d</xliff:g> 秒）"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 6155bac..7657cbf 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"音訊輸出"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"其他裝置"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"連接另一部裝置"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"內置喇叭 + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"按一下 "<annotation icon="dpad_icon">"十字鍵"</annotation>" 以存取音響裝置設定。"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"「<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>」設定。"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"你仍在觀看嗎？"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"你的電視表示你已切換至其他輸入來源，而此裝置即將進入休眠模式。請選取任何選項，讓此裝置保持啟用狀態。"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"是 (<xliff:g id="SECONDS">%1$d</xliff:g> 秒)"</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 0b1f0cc..49e6406 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"音訊輸出裝置"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"其他裝置"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"連結其他裝置"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"內建揚聲器 + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"按下 "<annotation icon="dpad_icon">"DPAD"</annotation>" 可存取音訊裝置設定。"</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"「<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>」設定。"</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"你仍在觀賞影視內容嗎？"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"電視顯示你已切換至其他輸入端，因此這部裝置即將進入休眠模式。如要讓這部裝置保持啟用狀態，請選取其中一個選項。"</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"是 (<xliff:g id="SECONDS">%1$d</xliff:g> 秒)"</string>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index 870ee26..147c8cf 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -33,12 +33,9 @@
     <string name="media_output_dialog_title" msgid="6307582009756803143">"Okukhishwayo komsindo"</string>
     <string name="media_output_dialog_other_devices" msgid="3247897577557171573">"Amanye amadivayisi"</string>
     <string name="media_output_dialog_pairing_new" msgid="5488290054300850034">"Xhuma enye idivayisi"</string>
-    <!-- no translation found for media_output_internal_speaker_spdif_subtitle (98802379666893998) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_right (8410621031774996322) -->
-    <skip />
-    <!-- no translation found for audio_device_tooltip_left (9062689648623861935) -->
-    <skip />
+    <string name="media_output_internal_speaker_spdif_subtitle" msgid="98802379666893998">"Isipikha esakhelwe ngaphakathi + S/PDIF"</string>
+    <string name="audio_device_settings_tooltip" msgid="2817501350919310424">"Cindezela "<annotation icon="dpad_icon">"I-DPAD"</annotation>" ukuthola amasethingi edivayisi yokulalelwayo."</string>
+    <string name="audio_device_settings_content_description" msgid="5204846097117099044">"Amasethingi e-<xliff:g id="AUDIO_DEVICE_NAME">%1$s</xliff:g>."</string>
     <string name="hdmi_cec_on_active_source_lost_title" msgid="5570532026531076971">"Ingabe usabukele?"</string>
     <string name="hdmi_cec_on_active_source_lost_description" msgid="4366679671166643699">"I-TV yakho ibonise ukuze ushintshele kokuhlukile kokufaka futhi le divayisi izolala maduzane. Khetha ongakhetha kukho ukuze ugcine le divayisi ivulekile."</string>
     <string name="hdmi_cec_on_active_source_lost_ok" msgid="7905385172151500115">"Yebo (<xliff:g id="SECONDS">%1$d</xliff:g>s)"</string>
diff --git a/res/values/colors.xml b/res/values/colors.xml
index 19251b7..07e3f77 100644
--- a/res/values/colors.xml
+++ b/res/values/colors.xml
@@ -49,9 +49,6 @@
     <color name="media_dialog_icon_bg_unfocused">#0ADFF3FF</color>
     <color name="media_dialog_icon_focused">#C2E7FF</color>
     <color name="media_dialog_icon_unfocused">#E4F3FF</color>
-    <color name="media_dialog_radio_button_focused">#8E918F</color>
-    <color name="media_dialog_radio_button_unfocused">#8E918F</color>
-    <color name="media_dialog_radio_button_checked">#0842A0</color>
     <color name="media_dialog_settings_icon_focused">#0842A0</color>
     <color name="media_dialog_settings_icon_unfocused">#8E918F</color>
 
@@ -71,25 +68,23 @@
 
     <color name="tv_panel_window_background">@color/media_dialog_bg</color>
 
-    <color name="switch_track_unfocused_color">#FFC2E7FF</color>
-    <color name="switch_track_focused_color">#FF004A77</color>
-    <color name="switch_track_unchecked_color">#FF282A2C</color>
+    <color name="preference_switch_thumb_on_default_color">#FF062E64</color>
+    <color name="preference_switch_thumb_off_default_color">#FFFAFAFA</color>
+    <color name="preference_switch_thumb_disabled_color">#FF131314</color>
+    <color name="preference_switch_thumb_focused_color">#FFFFFFFF</color>
 
-    <color name="switch_track_border_unfocused_unchecked">#33DFF3FF</color>
-    <color name="switch_track_border_unfocused_disabled">#33DFF3FF</color>
-
-    <color name="switch_thumb_unfocused_color">#FF004A77</color>
-    <color name="switch_thumb_focused_color">#FFC2E7FF</color>
-    <color name="switch_thumb_unchecked_color">#FF8E918F</color>
-
-    <color name="switch_info_on">#FF5BB974</color>
-    <color name="switch_info_off">#FFEE675C</color>
+    <color name="preference_control_on_default_color">#FFABC7FA</color>
+    <color name="preference_control_off_default_color">#FF8A8A8A</color>
+    <color name="preference_control_on_focused_color">#FF0B57D0</color>
+    <color name="preference_control_off_focused_color">#FF8A8A8A</color>
+    <color name="preference_control_disabled_focused_color">#FF0B57D0</color>
+    <color name="preference_control_disabled_default_color">#FF616161</color>
 
     <color name="seekbar_progress_focused_color">#FF004A77</color>
     <color name="seekbar_progress_unfocused_color">#FFE4F3FF</color>
     <color name="seekbar_progress_background_focused_color">#FFA8C7FA</color>
     <color name="seekbar_progress_background_unfocused_color">#FF3D4043</color>
 
-    <color name="progress_bar_color">#E5E5E5</color>
+    <color name="progress_bar_color">#FFFAFAFA</color>
 
 </resources>
diff --git a/res/values/dimens.xml b/res/values/dimens.xml
index a8b1adf..750e36e 100644
--- a/res/values/dimens.xml
+++ b/res/values/dimens.xml
@@ -100,6 +100,7 @@
     <dimen name="control_widget_icon_size">32dp</dimen>
     <dimen name="control_widget_small_icon_size">16dp</dimen>
     <dimen name="control_widget_icon_padding">2dp</dimen>
+    <dimen name="control_widget_padding">12dp</dimen>
 
     <!-- Switch widget basic -->
     <dimen name="switch_height">20dp</dimen>
@@ -121,4 +122,14 @@
     <dimen name="tooltip_window_vertical_margin">6dp</dimen>
     <dimen name="tooltip_window_horizontal_margin">4dp</dimen>
 
+    <!-- Volume -->
+    <dimen name="volume_dialog_width">48dp</dimen>
+    <dimen name="volume_dialog_background_corner_radius">24dp</dimen>
+    <dimen name="volume_dialog_background_vertical_margin">-6dp</dimen>
+    <dimen name="volume_dialog_components_spacing">0dp</dimen>
+    <dimen name="volume_dialog_button_size">36dp</dimen>
+    <dimen name="volume_dialog_window_margin">30dp</dimen>
+    <dimen name="volume_dialog_slider_height">190dp</dimen>
+    <dimen name="volume_dialog_slider_width">24dp</dimen>
+    <dimen name="volume_dialog_slider_track_width">4dp</dimen>
 </resources>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 347779f..9f6074e 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -42,13 +42,11 @@
     S/PDIF [CHAR LIMIT=NONE] -->
     <string name="media_output_internal_speaker_spdif_subtitle">Built-in speaker + S/PDIF</string>
 
-    <!-- Tooltip text instructing the user to press the DPAD right button (for LTR layout direction)
-    to access the audio device settings [CHAR LIMIT=50] -->
-    <string name="audio_device_tooltip_right">Press <annotation icon="dpad_icon">DPAD_RIGHT</annotation> for audio device settings</string>
-
-    <!-- Tooltip text instructing the user to press the DPAD left button (for RTL layout direction)
-    to access the audio device settings [CHAR LIMIT=50] -->
-    <string name="audio_device_tooltip_left">Press <annotation icon="dpad_icon">DPAD_LEFT</annotation> for audio device settings</string>
+    <!-- Tooltip text instructing the user to press the DPAD right button (or left for RTL)
+    to access the audio device settings. This string is not used when accessibility is turned on and
+    the annotation will therefore always be replaced with the right/left dpad icon.
+    [CHAR LIMIT=NONE] -->
+    <string name="audio_device_settings_tooltip">Press <annotation icon="dpad_icon">DPAD</annotation> for audio device settings.</string>
 
     <string name="audio_device_settings_content_description"><xliff:g id="audio_device_name" example="Foo Soundbar">%1$s</xliff:g> settings.</string>
 
diff --git a/res/values/styles.xml b/res/values/styles.xml
index 0b5c658..6ad3ed2 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -162,21 +162,52 @@
     </style>
 
     <style name="SwitchWidgetStyle" parent="ControlWidgetStyle">
-        <item name="android:paddingStart">12dp</item>
+        <item name="android:paddingStart">@dimen/control_widget_padding</item>
+        <!-- Reduced padding to keep alignment after scaling the switch -->
         <item name="android:paddingEnd">8dp</item>
-        <item name="android:paddingVertical">14dp</item>
+        <item name="android:paddingVertical">0dp</item>
+    </style>
+
+    <style name="SliceSwitchStyle" parent="Theme.Material3.Dark.NoActionBar">
+        <item name="thumbTint">@color/thumb_tint_selector</item>
+        <item name="trackTint">@color/track_tint_selector</item>
+        <item name="trackDecorationTint">@color/track_decoration_tint_selector</item>
+        <item name="android:scaleX">0.78</item>
+        <item name="android:scaleY">0.78</item>
+        <item name="android:duplicateParentState">true</item>
+        <item name="android:background">@null</item>
+        <item name="android:focusable">false</item>
+        <item name="android:clickable">false</item>
+    </style>
+
+    <style name="SliceCheckboxStyle" parent="Widget.AppCompat.CompoundButton.CheckBox">
+        <item name="android:buttonTint">@color/control_tint_selector</item>
+        <item name="android:button">@drawable/checkbox_drawable</item>
+        <item name="android:duplicateParentState">true</item>
+        <item name="android:background">@null</item>
+        <item name="android:focusable">false</item>
+        <item name="android:clickable">false</item>
+    </style>
+
+    <style name="SliceRadioButtonStyle" parent="Widget.AppCompat.CompoundButton.RadioButton">
+        <item name="android:buttonTint">@color/control_tint_selector</item>
+        <item name="android:duplicateParentState">true</item>
+        <item name="android:background">@null</item>
+        <item name="android:layout_gravity">center</item>
+        <item name="android:focusable">false</item>
+        <item name="android:clickable">false</item>
     </style>
 
     <style name="CheckboxWidgetStyle" parent="ControlWidgetStyle">
-        <item name="android:paddingStart">12dp</item>
-        <item name="android:paddingEnd">8dp</item>
-        <item name="android:paddingVertical">12dp</item>
+        <item name="android:paddingHorizontal">@dimen/control_widget_padding</item>
+        <item name="android:paddingVertical">0dp</item>
     </style>
 
     <style name="RadioWidgetStyle" parent="ControlWidgetStyle">
-        <item name="android:paddingStart">12dp</item>
+        <item name="android:paddingStart">@dimen/control_widget_padding</item>
+        <!-- Reduced padding due to space around the radio button -->
         <item name="android:paddingEnd">8dp</item>
-        <item name="android:paddingVertical">12dp</item>
+        <item name="android:paddingVertical">0dp</item>
     </style>
 
     <style name="OutputDeviceWidgetStyle" parent="RadioWidgetStyle">
@@ -187,16 +218,18 @@
     </style>
 
     <style name="SeekbarWidgetStyle" parent="ControlWidgetStyle">
-        <item name="android:paddingHorizontal">12dp</item>
-        <item name="android:paddingVertical">12dp</item>
+        <item name="android:paddingHorizontal">@dimen/control_widget_padding</item>
+        <item name="android:paddingVertical">@dimen/control_widget_padding</item>
     </style>
 
     <style name="BasicIconTextWidgetStyle" parent="ControlWidgetStyle">
-        <item name="android:paddingHorizontal">12dp</item>
-        <item name="android:paddingVertical">14dp</item>
+        <item name="android:paddingHorizontal">@dimen/control_widget_padding</item>
+        <item name="android:paddingVertical">0dp</item>
     </style>
 
-    <style name="BasicCenteredIconTextWidgetStyle" parent="BasicIconTextWidgetStyle">
+    <style name="BasicCenteredIconTextWidgetStyle" parent="ControlWidgetStyle">
+        <item name="android:paddingHorizontal">@dimen/control_widget_padding</item>
+        <item name="android:paddingVertical">@dimen/control_widget_padding</item>
         <item name="android:background">@drawable/media_dialog_item_bg_rounded</item>
     </style>
 
@@ -208,7 +241,6 @@
     <style name="ControlWidgetTooltipTextStyle">
         <item name="android:fontFamily">@string/font_label_medium</item>
         <item name="android:textSize">10sp</item>
-        <item name="android:singleLine">true</item>
         <item name="android:textColor">@color/media_dialog_item_title</item>
         <item name="android:textAlignment">viewStart</item>
     </style>
diff --git a/src/com/android/systemui/tv/dagger/TvSysUIComponent.kt b/src/com/android/systemui/tv/dagger/TvSysUIComponent.kt
index 8ed78bc..115fe2d 100644
--- a/src/com/android/systemui/tv/dagger/TvSysUIComponent.kt
+++ b/src/com/android/systemui/tv/dagger/TvSysUIComponent.kt
@@ -25,6 +25,7 @@ import com.android.systemui.scene.ShadelessSceneContainerFrameworkModule
 import com.android.systemui.statusbar.dagger.CentralSurfacesDependenciesModule
 import com.android.systemui.tv.recents.TvRecentsModule
 import com.android.systemui.wallpapers.dagger.NoopWallpaperModule
+import com.android.systemui.window.dagger.WindowRootViewBlurNotSupportedModule;
 import dagger.Subcomponent
 
 /**
@@ -46,6 +47,7 @@ import dagger.Subcomponent
     TvSystemUIBinder::class,
     TVSystemUICoreStartableModule::class,
     TvSystemUIModule::class,
+    WindowRootViewBlurNotSupportedModule::class,
 ]
 )
 interface TvSysUIComponent : SysUIComponent {
diff --git a/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt b/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt
index a930b8a..cc59990 100644
--- a/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt
+++ b/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt
@@ -25,6 +25,7 @@ import com.android.systemui.accessibility.AccessibilityModule
 import com.android.systemui.accessibility.data.repository.AccessibilityRepositoryModule
 import com.android.systemui.animation.DialogTransitionAnimator
 import com.android.systemui.broadcast.BroadcastSender
+import com.android.systemui.communal.posturing.dagger.NoopPosturingModule
 import com.android.systemui.dagger.ReferenceSystemUIModule
 import com.android.systemui.dagger.SysUISingleton
 import com.android.systemui.display.ui.viewmodel.ConnectingDisplayViewModel
@@ -45,6 +46,7 @@ import com.android.systemui.qs.tileimpl.QSFactoryImpl
 import com.android.systemui.screenshot.ReferenceScreenshotModule
 import com.android.systemui.settings.MultiUserUtilsModule
 import com.android.systemui.settings.UserTracker
+import com.android.systemui.settings.brightness.dagger.BrightnessSliderModule
 import com.android.systemui.shade.ShadeEmptyImplModule
 import com.android.systemui.statusbar.KeyboardShortcutsModule
 import com.android.systemui.statusbar.NotificationListener
@@ -71,12 +73,12 @@ import com.android.systemui.tv.notifications.TvNotificationsModule
 import com.android.systemui.tv.privacy.PrivacyModule
 import com.android.systemui.tv.sensorprivacy.TvSensorPrivacyModule
 import com.android.systemui.tv.shade.TvNotificationShadeWindowController
+import com.android.systemui.tv.volume.dagger.TvVolumeModule
 import com.android.systemui.unfold.SysUIUnfoldStartableModule
 import com.android.systemui.usb.UsbAccessoryUriActivity
 import com.android.systemui.usb.UsbDebuggingActivity
 import com.android.systemui.usb.UsbDebuggingSecondaryUserActivity
 import com.android.systemui.user.CreateUserActivity
-import com.android.systemui.volume.dagger.VolumeModule
 import dagger.Binds
 import dagger.Module
 import dagger.Provides
@@ -97,6 +99,7 @@ import kotlinx.coroutines.ExperimentalCoroutinesApi
     AccessibilityModule::class,
     AccessibilityRepositoryModule::class,
     AospPolicyModule::class,
+    BrightnessSliderModule::class,
     ConnectingDisplayViewModel.StartableModule::class,
     GestureModule::class,
     HdmiModule::class,
@@ -105,6 +108,7 @@ import kotlinx.coroutines.ExperimentalCoroutinesApi
     MediaMuteAwaitConnectionCli.StartableModule::class,
     MultiUserUtilsModule::class,
     NearbyMediaDevicesManager.StartableModule::class,
+    NoopPosturingModule::class,
     PowerModule::class,
     PrivacyModule::class,
     QSModule::class,
@@ -115,7 +119,7 @@ import kotlinx.coroutines.ExperimentalCoroutinesApi
     SysUIUnfoldStartableModule::class,
     TvNotificationsModule::class,
     TvSensorPrivacyModule::class,
-    VolumeModule::class,
+    TvVolumeModule::class,
 ]
 )
 abstract class TvSystemUIModule {
diff --git a/src/com/android/systemui/tv/hdmi/HdmiCecActiveSourceLostActivity.java b/src/com/android/systemui/tv/hdmi/HdmiCecActiveSourceLostActivity.java
index e5372af..f0ff520 100644
--- a/src/com/android/systemui/tv/hdmi/HdmiCecActiveSourceLostActivity.java
+++ b/src/com/android/systemui/tv/hdmi/HdmiCecActiveSourceLostActivity.java
@@ -111,6 +111,7 @@ public class HdmiCecActiveSourceLostActivity extends TvBottomSheetActivity
             public void onFinish() {
                 okButton.setText(String.format(getResources()
                                 .getString(R.string.hdmi_cec_on_active_source_lost_ok), 0));
+                finish();
             }
         }.start();
 
diff --git a/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java b/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java
index 728c0bc..0e95794 100644
--- a/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java
+++ b/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java
@@ -49,7 +49,6 @@ import com.android.settingslib.media.MediaDevice.MediaDeviceType;
 import com.android.systemui.media.dialog.MediaItem;
 import com.android.systemui.tv.media.settings.CenteredImageSpan;
 import com.android.systemui.tv.media.settings.ControlWidget;
-
 import com.android.systemui.tv.res.R;
 
 import java.util.Arrays;
@@ -71,10 +70,6 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
 
     private final AccessibilityManager mA11yManager;
 
-    private final int mFocusedRadioTint;
-    private final int mUnfocusedRadioTint;
-    private final int mCheckedRadioTint;
-
     private final CharSequence mTooltipText;
     private String mSavedDeviceId;
 
@@ -89,10 +84,6 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
         mA11yManager = context.getSystemService(AccessibilityManager.class);
 
         Resources res = mContext.getResources();
-        mFocusedRadioTint = res.getColor(R.color.media_dialog_radio_button_focused);
-        mUnfocusedRadioTint = res.getColor(R.color.media_dialog_radio_button_unfocused);
-        mCheckedRadioTint = res.getColor(R.color.media_dialog_radio_button_checked);
-
         mIsRtl = res.getConfiguration().getLayoutDirection() == View.LAYOUT_DIRECTION_RTL;
         mTooltipText = createTooltipText();
 
@@ -173,8 +164,8 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
      */
     private CharSequence createTooltipText() {
         Resources res = mContext.getResources();
-        final SpannedString tooltipText = (SpannedString) res.getText(mIsRtl
-                ? R.string.audio_device_tooltip_right : R.string.audio_device_tooltip_left);
+        final SpannedString tooltipText = (SpannedString) res.getText(
+                R.string.audio_device_settings_tooltip);
         final SpannableString spannableString = new SpannableString(tooltipText);
         Arrays.stream(tooltipText.getSpans(0, tooltipText.length(), Annotation.class)).findFirst()
                 .ifPresent(annotation -> {
@@ -267,11 +258,9 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
 
             mRadioButton.setVisibility(mediaDevice.isConnected() ? View.VISIBLE : View.GONE);
             mRadioButton.setChecked(isCurrentlyConnected(mediaDevice));
-            setRadioButtonColor();
 
             mWidget.setOnFocusChangeListener((view, focused) -> {
                 setSummary(mediaDevice);
-                setRadioButtonColor();
                 mTitle.setSelected(focused);
                 mSubtitle.setSelected(focused);
             });
@@ -342,15 +331,6 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
             return true;
         }
 
-        private void setRadioButtonColor() {
-            if (mWidget.hasFocus()) {
-                mRadioButton.getButtonDrawable().setTint(
-                        mRadioButton.isChecked() ? mCheckedRadioTint : mFocusedRadioTint);
-            } else {
-                mRadioButton.getButtonDrawable().setTint(mUnfocusedRadioTint);
-            }
-        }
-
         private void setSummary(MediaDevice mediaDevice) {
             CharSequence summary = getSummary(mediaDevice, mWidget.hasFocus());
             if (mediaDevice.getDeviceType() == MediaDeviceType.TYPE_PHONE_DEVICE
@@ -415,10 +395,14 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
         private void launchBluetoothSettings() {
             mCallback.dismissDialog();
 
+            String uri = mMediaOutputController.getBluetoothSettingsSliceUri();
+            if (uri == null) {
+                return;
+            }
+
             Intent bluetoothIntent = new Intent("android.settings.SLICE_SETTINGS");
             Bundle extra = new Bundle();
-            extra.putString("slice_uri",
-                    "content://com.google.android.tv.btservices.settings.sliceprovider/general");
+            extra.putString("slice_uri", uri);
             bluetoothIntent.putExtras(extra);
             bluetoothIntent.addFlags(
                     Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
diff --git a/src/com/android/systemui/tv/media/TvMediaOutputController.java b/src/com/android/systemui/tv/media/TvMediaOutputController.java
index 59ddc6e..01eb571 100644
--- a/src/com/android/systemui/tv/media/TvMediaOutputController.java
+++ b/src/com/android/systemui/tv/media/TvMediaOutputController.java
@@ -26,10 +26,13 @@ import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_USB
 
 import android.app.KeyguardManager;
 import android.content.Context;
+import android.content.pm.PackageManager.NameNotFoundException;
+import android.content.res.Resources;
 import android.media.AudioManager;
 import android.media.session.MediaSessionManager;
 import android.os.PowerExemptionManager;
 import android.text.TextUtils;
+import android.util.Log;
 
 import com.android.settingslib.bluetooth.LocalBluetoothManager;
 import com.android.settingslib.media.MediaDevice;
@@ -55,6 +58,9 @@ import java.util.List;
  */
 public class TvMediaOutputController extends MediaSwitchingController {
 
+    private static final String TAG = TvMediaOutputController.class.getSimpleName();
+    private static final String SETTINGS_PACKAGE = "com.android.tv.settings";
+
     private final Context mContext;
     private final AudioManager mAudioManager;
 
@@ -229,10 +235,31 @@ public class TvMediaOutputController extends MediaSwitchingController {
     }
 
     private void addConnectAnotherDeviceItem(List<MediaItem> mediaItems) {
+        if (getBluetoothSettingsSliceUri() == null) {
+            Log.d(TAG, "No bluetooth slice set.");
+            return;
+        }
         mediaItems.add(MediaItem.createGroupDividerMediaItem(/* title */ null));
         mediaItems.add(MediaItem.createPairNewDeviceMediaItem());
     }
 
+    String getBluetoothSettingsSliceUri() {
+        String uri = null;
+        Resources res;
+
+        try {
+            res = mContext.getPackageManager().getResourcesForApplication(SETTINGS_PACKAGE);
+            int resourceId = res.getIdentifier(
+                    SETTINGS_PACKAGE + ":string/connected_devices_slice_uri", null, null);
+            if (resourceId != 0) {
+                uri = res.getString(resourceId);
+            }
+        } catch (NameNotFoundException exception) {
+            Log.e(TAG, "Could not find TvSettings package: " + exception);
+        }
+        return uri;
+    }
+
     @Override
     protected void start(@NotNull Callback cb) {
         super.start(cb);
diff --git a/src/com/android/systemui/tv/media/settings/CheckboxSlicePreference.java b/src/com/android/systemui/tv/media/settings/CheckboxSlicePreference.java
index 7085f7b..9113bc1 100644
--- a/src/com/android/systemui/tv/media/settings/CheckboxSlicePreference.java
+++ b/src/com/android/systemui/tv/media/settings/CheckboxSlicePreference.java
@@ -17,11 +17,8 @@
 package com.android.systemui.tv.media.settings;
 
 import android.content.Context;
-import android.content.res.Resources;
-import android.graphics.drawable.Drawable;
 import android.util.AttributeSet;
 import android.view.View;
-import android.widget.CheckBox;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
@@ -37,12 +34,6 @@ import com.android.tv.twopanelsettings.slices.compat.core.SliceActionImpl;
  */
 public class CheckboxSlicePreference extends SliceCheckboxPreference implements TooltipPreference {
     private ControlWidget.TooltipConfig mTooltipConfig = new ControlWidget.TooltipConfig();
-    private View mItemView;
-    private CheckBox mCheckBox;
-
-    private final int mFocusedCheckboxTint;
-    private final int mUnfocusedCheckboxTint;
-    private final int mCheckedCheckboxTint;
 
     public CheckboxSlicePreference(Context context, SliceActionImpl action) {
         this(context, null, action);
@@ -52,35 +43,15 @@ public class CheckboxSlicePreference extends SliceCheckboxPreference implements
             SliceActionImpl action) {
         super(context, attrs, action);
         setLayoutResource(R.layout.checkbox_slice_pref);
-
-        Resources res = context.getResources();
-        mFocusedCheckboxTint = res.getColor(R.color.media_dialog_radio_button_focused);
-        mUnfocusedCheckboxTint = res.getColor(R.color.media_dialog_radio_button_unfocused);
-        mCheckedCheckboxTint = res.getColor(R.color.media_dialog_radio_button_checked);
     }
 
     @Override
     public void onBindViewHolder(@NonNull PreferenceViewHolder holder) {
         super.onBindViewHolder(holder);
-        mItemView = holder.itemView;
-        mItemView.setOnFocusChangeListener((v, hasFocus) -> updateColors());
 
-        CheckboxControlWidget widget = (CheckboxControlWidget) mItemView;
+        CheckboxControlWidget widget = (CheckboxControlWidget) holder.itemView;
         widget.setEnabled(this.isEnabled());
         widget.setTooltipConfig(mTooltipConfig);
-
-        mCheckBox = mItemView.findViewById(android.R.id.checkbox);
-        mCheckBox.setOnCheckedChangeListener((buttonView, isChecked) -> updateColors());
-        updateColors();
-    }
-
-    private void updateColors() {
-        Drawable drawable = mCheckBox.getButtonDrawable();
-        if (mItemView.hasFocus()) {
-            drawable.setTint(mCheckBox.isChecked() ? mCheckedCheckboxTint : mFocusedCheckboxTint);
-        } else {
-            drawable.setTint(mUnfocusedCheckboxTint);
-        }
     }
 
     /** Set tool tip related attributes. */
diff --git a/src/com/android/systemui/tv/media/settings/RadioSlicePreference.java b/src/com/android/systemui/tv/media/settings/RadioSlicePreference.java
index bedc4a0..511138d 100644
--- a/src/com/android/systemui/tv/media/settings/RadioSlicePreference.java
+++ b/src/com/android/systemui/tv/media/settings/RadioSlicePreference.java
@@ -17,11 +17,8 @@
 package com.android.systemui.tv.media.settings;
 
 import android.content.Context;
-import android.content.res.Resources;
-import android.graphics.drawable.Drawable;
 import android.util.AttributeSet;
 import android.view.View;
-import android.widget.RadioButton;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
@@ -37,45 +34,19 @@ import com.android.tv.twopanelsettings.slices.compat.core.SliceActionImpl;
  */
 public class RadioSlicePreference extends SliceRadioPreference implements TooltipPreference {
     private ControlWidget.TooltipConfig mTooltipConfig = new ControlWidget.TooltipConfig();
-    private View mItemView;
-    private RadioButton mRadioButton;
-
-    private final int mFocusedRadioTint;
-    private final int mUnfocusedRadioTint;
-    private final int mCheckedRadioTint;
 
     public RadioSlicePreference(Context context, SliceActionImpl action) {
         super(context,  action);
         setLayoutResource(R.layout.radio_slice_pref);
-
-        Resources res = context.getResources();
-        mFocusedRadioTint = res.getColor(R.color.media_dialog_radio_button_focused);
-        mUnfocusedRadioTint = res.getColor(R.color.media_dialog_radio_button_unfocused);
-        mCheckedRadioTint = res.getColor(R.color.media_dialog_radio_button_checked);
     }
 
     @Override
     public void onBindViewHolder(@NonNull PreferenceViewHolder holder) {
         super.onBindViewHolder(holder);
-        mItemView = holder.itemView;
-        mItemView.setOnFocusChangeListener((v, hasFocus) -> updateColors());
 
-        RadioControlWidget widget = (RadioControlWidget) mItemView;
+        RadioControlWidget widget = (RadioControlWidget) holder.itemView;
         widget.setEnabled(this.isEnabled());
         widget.setTooltipConfig(mTooltipConfig);
-
-        mRadioButton = mItemView.findViewById(android.R.id.checkbox);
-        mRadioButton.setOnCheckedChangeListener((buttonView, isChecked) -> updateColors());
-        updateColors();
-    }
-
-    private void updateColors() {
-        Drawable drawable = mRadioButton.getButtonDrawable();
-        if (mItemView.hasFocus()) {
-            drawable.setTint(mRadioButton.isChecked() ? mCheckedRadioTint : mFocusedRadioTint);
-        } else {
-            drawable.setTint(mUnfocusedRadioTint);
-        }
     }
 
     /** Set tool tip related attributes. */
diff --git a/src/com/android/systemui/tv/media/settings/SlicePreferencesUtil.java b/src/com/android/systemui/tv/media/settings/SlicePreferencesUtil.java
index 32513b7..3548b74 100644
--- a/src/com/android/systemui/tv/media/settings/SlicePreferencesUtil.java
+++ b/src/com/android/systemui/tv/media/settings/SlicePreferencesUtil.java
@@ -258,6 +258,9 @@ public final class SlicePreferencesUtil {
             if (preference.getTitle() != null) {
                 fallbackInfoContentDescription += preference.getTitle().toString();
             }
+            if (subtitleExists) {
+                fallbackInfoContentDescription += CONTENT_DESCRIPTION_SEPARATOR + subtitle;
+            }
             if (infoImage != null) {
                 tooltipConfig.setImageDrawable(infoImage.loadDrawable(context));
             }
diff --git a/src/com/android/systemui/tv/sensorprivacy/TvUnblockSensorActivity.java b/src/com/android/systemui/tv/sensorprivacy/TvUnblockSensorActivity.java
index 3f02450..41badae 100644
--- a/src/com/android/systemui/tv/sensorprivacy/TvUnblockSensorActivity.java
+++ b/src/com/android/systemui/tv/sensorprivacy/TvUnblockSensorActivity.java
@@ -279,6 +279,7 @@ public class TvUnblockSensorActivity extends TvBottomSheetActivity {
         mPositiveButton.setText(R.string.sensor_privacy_dialog_open_settings);
         mPositiveButton.setOnClickListener(v -> {
             Intent openPrivacySettings = new Intent(ACTION_MANAGE_MICROPHONE_PRIVACY);
+            openPrivacySettings.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
             ActivityInfo activityInfo = openPrivacySettings.resolveActivityInfo(getPackageManager(),
                     PackageManager.MATCH_SYSTEM_ONLY);
             if (activityInfo == null) {
diff --git a/src/com/android/systemui/tv/statusbar/TvStatusBar.java b/src/com/android/systemui/tv/statusbar/TvStatusBar.java
index 2d2056d..2e34cfb 100644
--- a/src/com/android/systemui/tv/statusbar/TvStatusBar.java
+++ b/src/com/android/systemui/tv/statusbar/TvStatusBar.java
@@ -28,6 +28,7 @@ import com.android.systemui.assist.AssistManager;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.statusbar.CommandQueue;
 import com.android.systemui.statusbar.KeyboardShortcuts;
+import com.android.systemui.utils.windowmanager.WindowManagerProvider;
 
 import dagger.Lazy;
 
@@ -47,13 +48,15 @@ public class TvStatusBar implements CoreStartable, CommandQueue.Callbacks {
     private final Context mContext;
     private final CommandQueue mCommandQueue;
     private final Lazy<AssistManager> mAssistManagerLazy;
+    private final WindowManagerProvider mWindowManagerProvider;
 
     @Inject
     public TvStatusBar(Context context, CommandQueue commandQueue,
-            Lazy<AssistManager> assistManagerLazy) {
+            Lazy<AssistManager> assistManagerLazy, WindowManagerProvider windowManagerProvider) {
         mContext = context;
         mCommandQueue = commandQueue;
         mAssistManagerLazy = assistManagerLazy;
+        mWindowManagerProvider = windowManagerProvider;
     }
 
     @Override
@@ -82,6 +85,6 @@ public class TvStatusBar implements CoreStartable, CommandQueue.Callbacks {
 
     @Override
     public void toggleKeyboardShortcutsMenu(int deviceId) {
-        KeyboardShortcuts.show(mContext, deviceId);
+        KeyboardShortcuts.show(mContext, deviceId, mWindowManagerProvider);
     }
 }
diff --git a/src/com/android/systemui/tv/volume/dagger/TvVolumeModule.kt b/src/com/android/systemui/tv/volume/dagger/TvVolumeModule.kt
new file mode 100644
index 0000000..7b9cf1a
--- /dev/null
+++ b/src/com/android/systemui/tv/volume/dagger/TvVolumeModule.kt
@@ -0,0 +1,163 @@
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
+package com.android.systemui.tv.volume.dagger
+
+import android.content.BroadcastReceiver
+import android.content.Context
+import android.media.AudioManager
+import android.os.Looper
+import com.android.internal.jank.InteractionJankMonitor
+import com.android.systemui.CoreStartable
+import com.android.systemui.Flags
+import com.android.systemui.dump.DumpManager
+import com.android.systemui.media.dialog.MediaOutputDialogManager
+import com.android.systemui.plugins.VolumeDialog
+import com.android.systemui.plugins.VolumeDialogController
+import com.android.systemui.statusbar.VibratorHelper
+import com.android.systemui.statusbar.policy.AccessibilityManagerWrapper
+import com.android.systemui.statusbar.policy.ConfigurationController
+import com.android.systemui.statusbar.policy.DevicePostureController
+import com.android.systemui.statusbar.policy.DeviceProvisionedController
+import com.android.systemui.tv.volume.dialog.dagger.TvVolumeDialogPluginComponent
+import com.android.systemui.util.settings.SecureSettings
+import com.android.systemui.util.time.SystemClock
+import com.android.systemui.volume.CsdWarningDialog
+import com.android.systemui.volume.VolumeComponent
+import com.android.systemui.volume.VolumeDialogComponent
+import com.android.systemui.volume.VolumeDialogImpl
+import com.android.systemui.volume.VolumePanelDialogReceiver
+import com.android.systemui.volume.VolumeUI
+import com.android.systemui.volume.dagger.AncModule
+import com.android.systemui.volume.dagger.AudioModule
+import com.android.systemui.volume.dagger.AudioSharingModule
+import com.android.systemui.volume.dagger.CaptioningModule
+import com.android.systemui.volume.dagger.MediaDevicesModule
+import com.android.systemui.volume.dagger.SpatializerModule
+import com.android.systemui.volume.dialog.VolumeDialogPlugin
+import com.android.systemui.volume.dialog.dagger.factory.VolumeDialogPluginComponentFactory
+import com.android.systemui.volume.domain.interactor.VolumeDialogInteractor
+import com.android.systemui.volume.domain.interactor.VolumePanelNavigationInteractor
+import com.android.systemui.volume.panel.dagger.VolumePanelComponent
+import com.android.systemui.volume.panel.dagger.factory.VolumePanelComponentFactory
+import com.android.systemui.volume.panel.shared.flag.VolumePanelFlag
+import com.android.systemui.volume.ui.navigation.VolumeNavigator
+import com.google.android.msdl.domain.MSDLPlayer
+import dagger.Binds
+import dagger.Lazy
+import dagger.Module
+import dagger.Provides
+import dagger.multibindings.ClassKey
+import dagger.multibindings.IntoMap
+import dagger.multibindings.IntoSet
+
+@Module(
+    includes =
+        [
+            AudioModule::class,
+            AudioSharingModule::class,
+            AncModule::class,
+            CaptioningModule::class,
+            MediaDevicesModule::class,
+            SpatializerModule::class,
+        ],
+    subcomponents = [VolumePanelComponent::class, TvVolumeDialogPluginComponent::class],
+)
+interface TvVolumeModule {
+
+    @Binds
+    @IntoMap
+    @ClassKey(VolumePanelDialogReceiver::class)
+    fun bindVolumePanelDialogReceiver(receiver: VolumePanelDialogReceiver): BroadcastReceiver
+
+    @Binds
+    @IntoMap
+    @ClassKey(VolumeUI::class)
+    fun bindVolumeUIStartable(impl: VolumeUI): CoreStartable
+
+    @Binds
+    @IntoSet
+    fun bindVolumeUIConfigChanges(impl: VolumeUI): ConfigurationController.ConfigurationListener
+
+    @Binds fun provideVolumeComponent(volumeDialogComponent: VolumeDialogComponent): VolumeComponent
+
+    @Binds
+    fun bindVolumePanelComponentFactory(
+        impl: VolumePanelComponent.Factory
+    ): VolumePanelComponentFactory
+
+    @Binds
+    fun bindVolumeDialogPluginComponentFactory(
+        impl: TvVolumeDialogPluginComponent.Factory
+    ): VolumeDialogPluginComponentFactory
+
+    companion object {
+        @Provides
+        fun provideVolumeDialog(
+            volumeDialogProvider: Lazy<VolumeDialogPlugin>,
+            context: Context,
+            volumeDialogController: VolumeDialogController,
+            accessibilityManagerWrapper: AccessibilityManagerWrapper,
+            deviceProvisionedController: DeviceProvisionedController,
+            configurationController: ConfigurationController,
+            mediaOutputDialogManager: MediaOutputDialogManager,
+            interactionJankMonitor: InteractionJankMonitor,
+            volumePanelNavigationInteractor: VolumePanelNavigationInteractor,
+            volumeNavigator: VolumeNavigator,
+            csdFactory: CsdWarningDialog.Factory,
+            devicePostureController: DevicePostureController,
+            volumePanelFlag: VolumePanelFlag,
+            dumpManager: DumpManager,
+            secureSettings: Lazy<SecureSettings>,
+            vibratorHelper: VibratorHelper,
+            msdlPlayer: MSDLPlayer,
+            systemClock: SystemClock,
+            interactor: VolumeDialogInteractor,
+        ): VolumeDialog {
+            return if (Flags.volumeRedesign()) {
+                volumeDialogProvider.get()
+            } else {
+                VolumeDialogImpl(
+                        context,
+                        volumeDialogController,
+                        accessibilityManagerWrapper,
+                        deviceProvisionedController,
+                        configurationController,
+                        mediaOutputDialogManager,
+                        interactionJankMonitor,
+                        volumePanelNavigationInteractor,
+                        volumeNavigator,
+                        true,
+                        csdFactory,
+                        devicePostureController,
+                        Looper.getMainLooper(),
+                        volumePanelFlag,
+                        dumpManager,
+                        secureSettings,
+                        vibratorHelper,
+                        msdlPlayer,
+                        systemClock,
+                        interactor,
+                    )
+                    .apply {
+                        setStreamImportant(AudioManager.STREAM_SYSTEM, false)
+                        setAutomute(true)
+                        setSilentMode(false)
+                    }
+            }
+        }
+    }
+}
diff --git a/src/com/android/systemui/tv/volume/dialog/dagger/TvVolumeDialogComponent.kt b/src/com/android/systemui/tv/volume/dialog/dagger/TvVolumeDialogComponent.kt
new file mode 100644
index 0000000..f099c27
--- /dev/null
+++ b/src/com/android/systemui/tv/volume/dialog/dagger/TvVolumeDialogComponent.kt
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
+
+package com.android.systemui.tv.volume.dialog.dagger
+
+import com.android.systemui.tv.volume.dialog.dagger.module.TvVolumeDialogModule
+import com.android.systemui.volume.dialog.dagger.VolumeDialogComponent
+import com.android.systemui.volume.dialog.dagger.factory.VolumeDialogComponentFactory
+import com.android.systemui.volume.dialog.dagger.scope.VolumeDialog
+import com.android.systemui.volume.dialog.dagger.scope.VolumeDialogScope
+import dagger.BindsInstance
+import dagger.Subcomponent
+import kotlinx.coroutines.CoroutineScope
+
+@VolumeDialogScope
+@Subcomponent(modules = [TvVolumeDialogModule::class])
+interface TvVolumeDialogComponent : VolumeDialogComponent {
+
+    @Subcomponent.Factory
+    interface Factory : VolumeDialogComponentFactory {
+
+        override fun create(
+            @BindsInstance @VolumeDialog scope: CoroutineScope
+        ): TvVolumeDialogComponent
+    }
+}
diff --git a/src/com/android/systemui/tv/volume/dialog/dagger/TvVolumeDialogPluginComponent.kt b/src/com/android/systemui/tv/volume/dialog/dagger/TvVolumeDialogPluginComponent.kt
new file mode 100644
index 0000000..06aaa94
--- /dev/null
+++ b/src/com/android/systemui/tv/volume/dialog/dagger/TvVolumeDialogPluginComponent.kt
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
+
+package com.android.systemui.tv.volume.dialog.dagger
+
+import com.android.systemui.tv.volume.dialog.dagger.module.TvVolumeDialogPluginModule
+import com.android.systemui.volume.dialog.dagger.VolumeDialogPluginComponent
+import com.android.systemui.volume.dialog.dagger.factory.VolumeDialogPluginComponentFactory
+import com.android.systemui.volume.dialog.dagger.scope.VolumeDialogPlugin
+import com.android.systemui.volume.dialog.dagger.scope.VolumeDialogPluginScope
+import dagger.BindsInstance
+import dagger.Subcomponent
+import kotlinx.coroutines.CoroutineScope
+
+@VolumeDialogPluginScope
+@Subcomponent(modules = [TvVolumeDialogPluginModule::class])
+interface TvVolumeDialogPluginComponent : VolumeDialogPluginComponent {
+
+    @Subcomponent.Factory
+    interface Factory : VolumeDialogPluginComponentFactory {
+
+        override fun create(
+            @BindsInstance @VolumeDialogPlugin scope: CoroutineScope
+        ): TvVolumeDialogPluginComponent
+    }
+}
diff --git a/src/com/android/systemui/tv/volume/dialog/dagger/module/TvVolumeDialogModule.kt b/src/com/android/systemui/tv/volume/dialog/dagger/module/TvVolumeDialogModule.kt
new file mode 100644
index 0000000..578788c
--- /dev/null
+++ b/src/com/android/systemui/tv/volume/dialog/dagger/module/TvVolumeDialogModule.kt
@@ -0,0 +1,49 @@
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
+package com.android.systemui.tv.volume.dialog.dagger.module
+
+import com.android.systemui.tv.volume.dialog.footer.ui.binder.TvVolumeDialogFooterViewBinder
+import com.android.systemui.tv.volume.dialog.header.ui.binder.TvVolumeDialogHeaderViewBinder
+import com.android.systemui.tv.volume.dialog.slider.ui.binder.TvVolumeDialogSliderViewBinder
+import com.android.systemui.volume.dialog.dagger.scope.VolumeDialog
+import com.android.systemui.volume.dialog.ringer.data.repository.VolumeDialogRingerFeedbackRepository
+import com.android.systemui.volume.dialog.ringer.data.repository.VolumeDialogRingerFeedbackRepositoryImpl
+import com.android.systemui.volume.dialog.sliders.dagger.VolumeDialogSliderComponent
+import com.android.systemui.volume.dialog.ui.binder.ViewBinder
+import dagger.Binds
+import dagger.Module
+import dagger.Provides
+
+@Module(subcomponents = [VolumeDialogSliderComponent::class])
+interface TvVolumeDialogModule {
+
+    @Binds
+    fun bindVolumeDialogRingerFeedbackRepository(
+        ringerFeedbackRepository: VolumeDialogRingerFeedbackRepositoryImpl
+    ): VolumeDialogRingerFeedbackRepository
+
+    companion object {
+
+        @Provides
+        @VolumeDialog
+        fun provideViewBinders(
+            slidersViewBinder: TvVolumeDialogSliderViewBinder,
+            headerViewBinder: TvVolumeDialogHeaderViewBinder,
+            footerViewBinder: TvVolumeDialogFooterViewBinder,
+        ): List<ViewBinder> = listOf(slidersViewBinder, headerViewBinder, footerViewBinder)
+    }
+}
diff --git a/src/com/android/systemui/tv/volume/dialog/dagger/module/TvVolumeDialogPluginModule.kt b/src/com/android/systemui/tv/volume/dialog/dagger/module/TvVolumeDialogPluginModule.kt
new file mode 100644
index 0000000..949780e
--- /dev/null
+++ b/src/com/android/systemui/tv/volume/dialog/dagger/module/TvVolumeDialogPluginModule.kt
@@ -0,0 +1,45 @@
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
+package com.android.systemui.tv.volume.dialog.dagger.module
+
+import com.android.systemui.tv.volume.dialog.dagger.TvVolumeDialogComponent
+import com.android.systemui.volume.dialog.dagger.factory.VolumeDialogComponentFactory
+import com.android.systemui.volume.dialog.shared.model.CsdWarningConfigModel
+import com.android.systemui.volume.dialog.utils.VolumeTracer
+import com.android.systemui.volume.dialog.utils.VolumeTracerImpl
+import dagger.Binds
+import dagger.Module
+import dagger.Provides
+
+@Module(subcomponents = [TvVolumeDialogComponent::class])
+interface TvVolumeDialogPluginModule {
+
+    @Binds
+    fun bindVolumeDialogComponentFactory(
+        factory: TvVolumeDialogComponent.Factory
+    ): VolumeDialogComponentFactory
+
+    @Binds
+    fun bindVolumeTracer(volumeTracer: VolumeTracerImpl): VolumeTracer
+
+    companion object {
+
+        @Provides
+        fun provideCsdWarningConfigModel(): CsdWarningConfigModel =
+            CsdWarningConfigModel(emptyList())
+    }
+}
diff --git a/src/com/android/systemui/tv/volume/dialog/footer/ui/binder/TvVolumeDialogFooterViewBinder.kt b/src/com/android/systemui/tv/volume/dialog/footer/ui/binder/TvVolumeDialogFooterViewBinder.kt
new file mode 100644
index 0000000..02fae9b
--- /dev/null
+++ b/src/com/android/systemui/tv/volume/dialog/footer/ui/binder/TvVolumeDialogFooterViewBinder.kt
@@ -0,0 +1,42 @@
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
+package com.android.systemui.tv.volume.dialog.footer.ui.binder
+
+import android.view.View
+import android.widget.ImageView
+import com.android.app.tracing.coroutines.launchInTraced
+import com.android.systemui.res.R
+import com.android.systemui.tv.volume.dialog.footer.ui.viewmodel.TvVolumeDialogFooterViewModel
+import com.android.systemui.volume.dialog.dagger.scope.VolumeDialogScope
+import com.android.systemui.volume.dialog.ui.binder.ViewBinder
+import javax.inject.Inject
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.flow.onEach
+
+@VolumeDialogScope
+class TvVolumeDialogFooterViewBinder @Inject constructor(
+    private val viewModel: TvVolumeDialogFooterViewModel
+) :
+    ViewBinder {
+
+    override fun CoroutineScope.bind(view: View) {
+        val volumeRowIcon = view.requireViewById<ImageView>(R.id.volume_row_icon)
+        viewModel.icon.onEach {
+            volumeRowIcon.setImageDrawable(it)
+        }.launchInTraced("TVDFVB#icon", this)
+    }
+}
diff --git a/src/com/android/systemui/tv/volume/dialog/footer/ui/viewmodel/TvVolumeDialogFooterViewModel.kt b/src/com/android/systemui/tv/volume/dialog/footer/ui/viewmodel/TvVolumeDialogFooterViewModel.kt
new file mode 100644
index 0000000..668ef21
--- /dev/null
+++ b/src/com/android/systemui/tv/volume/dialog/footer/ui/viewmodel/TvVolumeDialogFooterViewModel.kt
@@ -0,0 +1,46 @@
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
+package com.android.systemui.tv.volume.dialog.footer.ui.viewmodel
+
+import android.graphics.drawable.Drawable
+import com.android.systemui.volume.dialog.dagger.scope.VolumeDialog
+import com.android.systemui.volume.dialog.dagger.scope.VolumeDialogScope
+import com.android.systemui.volume.dialog.sliders.ui.viewmodel.VolumeDialogSlidersViewModel
+import javax.inject.Inject
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.flatMapLatest
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.mapNotNull
+import kotlinx.coroutines.flow.stateIn
+
+@VolumeDialogScope
+class TvVolumeDialogFooterViewModel
+@Inject
+constructor(
+    slidersViewModel: VolumeDialogSlidersViewModel,
+    @VolumeDialog private val coroutineScope: CoroutineScope,
+) {
+
+    val icon: Flow<Drawable> =
+        slidersViewModel.sliders
+            .flatMapLatest { it.sliderComponent.sliderViewModel().state }
+            .map { it.icon }
+            .stateIn(coroutineScope, SharingStarted.Eagerly, null)
+            .mapNotNull { it?.drawable }
+}
diff --git a/src/com/android/systemui/tv/volume/dialog/header/ui/binder/TvVolumeDialogHeaderViewBinder.kt b/src/com/android/systemui/tv/volume/dialog/header/ui/binder/TvVolumeDialogHeaderViewBinder.kt
new file mode 100644
index 0000000..2d46df5
--- /dev/null
+++ b/src/com/android/systemui/tv/volume/dialog/header/ui/binder/TvVolumeDialogHeaderViewBinder.kt
@@ -0,0 +1,44 @@
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
+package com.android.systemui.tv.volume.dialog.header.ui.binder
+
+import android.annotation.SuppressLint
+import android.view.View
+import android.widget.TextView
+import com.android.app.tracing.coroutines.launchInTraced
+import com.android.systemui.res.R
+import com.android.systemui.tv.volume.dialog.header.ui.viewmodel.TvVolumeDialogHeaderViewModel
+import com.android.systemui.volume.dialog.dagger.scope.VolumeDialogScope
+import com.android.systemui.volume.dialog.ui.binder.ViewBinder
+import javax.inject.Inject
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.flow.onEach
+
+@VolumeDialogScope
+class TvVolumeDialogHeaderViewBinder @Inject constructor(
+    private val viewModel: TvVolumeDialogHeaderViewModel
+) :
+    ViewBinder {
+
+    @SuppressLint("SetTextI18n")
+    override fun CoroutineScope.bind(view: View) {
+        val volumeNumber = view.requireViewById<TextView>(R.id.volume_number)
+        viewModel.sliderProgress.onEach {
+            volumeNumber.text = it.toString()
+        }.launchInTraced("TVDHVB#sliderProgress", this)
+    }
+}
diff --git a/src/com/android/systemui/tv/volume/dialog/header/ui/viewmodel/TvVolumeDialogHeaderViewModel.kt b/src/com/android/systemui/tv/volume/dialog/header/ui/viewmodel/TvVolumeDialogHeaderViewModel.kt
new file mode 100644
index 0000000..f8180ea
--- /dev/null
+++ b/src/com/android/systemui/tv/volume/dialog/header/ui/viewmodel/TvVolumeDialogHeaderViewModel.kt
@@ -0,0 +1,40 @@
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
+package com.android.systemui.tv.volume.dialog.header.ui.viewmodel
+
+import com.android.systemui.volume.dialog.dagger.scope.VolumeDialogScope
+import com.android.systemui.volume.dialog.sliders.dagger.VolumeDialogSliderComponent
+import com.android.systemui.volume.dialog.sliders.domain.interactor.VolumeDialogSlidersInteractor
+import javax.inject.Inject
+import kotlin.math.roundToInt
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.flatMapLatest
+import kotlinx.coroutines.flow.map
+
+@VolumeDialogScope
+class TvVolumeDialogHeaderViewModel
+@Inject
+constructor(
+    slidersInteractor: VolumeDialogSlidersInteractor,
+    private val sliderComponentFactory: VolumeDialogSliderComponent.Factory,
+) {
+
+    val sliderProgress: Flow<Int> =
+        slidersInteractor.sliders
+            .flatMapLatest { sliderComponentFactory.create(it.slider).sliderViewModel().state }
+            .map { it.value.roundToInt() }
+}
diff --git a/src/com/android/systemui/tv/volume/dialog/slider/ui/binder/TvVolumeDialogSliderViewBinder.kt b/src/com/android/systemui/tv/volume/dialog/slider/ui/binder/TvVolumeDialogSliderViewBinder.kt
new file mode 100644
index 0000000..0f83150
--- /dev/null
+++ b/src/com/android/systemui/tv/volume/dialog/slider/ui/binder/TvVolumeDialogSliderViewBinder.kt
@@ -0,0 +1,75 @@
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
+package com.android.systemui.tv.volume.dialog.slider.ui.binder
+
+import android.view.View
+import android.widget.SeekBar
+import com.android.app.tracing.coroutines.launchInTraced
+import com.android.systemui.res.R
+import com.android.systemui.volume.dialog.dagger.scope.VolumeDialogScope
+import com.android.systemui.volume.dialog.sliders.ui.viewmodel.VolumeDialogSliderViewModel
+import com.android.systemui.volume.dialog.sliders.ui.viewmodel.VolumeDialogSlidersViewModel
+import com.android.systemui.volume.dialog.ui.binder.ViewBinder
+import javax.inject.Inject
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.flow.onEach
+
+@VolumeDialogScope
+class TvVolumeDialogSliderViewBinder
+@Inject
+constructor(private val slidersViewModel: VolumeDialogSlidersViewModel) : ViewBinder {
+
+    override fun CoroutineScope.bind(view: View) {
+        val seekBar: SeekBar = view.requireViewById(R.id.volume_dialog_slider)
+        slidersViewModel.sliders
+            .onEach { bindSlider(seekBar, it.sliderComponent.sliderViewModel()) }
+            .launchInTraced("TVDSVB#sliders", this)
+    }
+
+    private suspend fun bindSlider(seekBar: SeekBar, viewModel: VolumeDialogSliderViewModel) =
+        coroutineScope {
+            seekBar.setOnSeekBarChangeListener(viewModel.createSeekBarListener())
+
+            viewModel.state
+                .onEach { state ->
+                    with(seekBar) {
+                        // disable value animation due to performance limitations of lower end TVs
+                        setProgress(state.value.toInt(), false)
+                        max = state.valueRange.endInclusive.toInt()
+                        min = state.valueRange.start.toInt()
+                    }
+                }
+                .launchInTraced("TVDSVB#state", this)
+        }
+
+    private fun VolumeDialogSliderViewModel.createSeekBarListener() =
+        object : SeekBar.OnSeekBarChangeListener {
+            override fun onProgressChanged(bar: SeekBar, value: Int, fromUser: Boolean) {
+                setStreamVolume(value.toFloat(), fromUser)
+            }
+
+            override fun onStartTrackingTouch(seekBar: SeekBar) {
+                onSliderDragStarted()
+            }
+
+            override fun onStopTrackingTouch(seekBar: SeekBar) {
+                onSliderDragFinished()
+                onSliderChangeFinished(seekBar.progress.toFloat())
+            }
+        }
+}
```

