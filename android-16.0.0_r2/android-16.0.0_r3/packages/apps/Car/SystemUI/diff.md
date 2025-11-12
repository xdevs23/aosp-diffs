```diff
diff --git a/Android.bp b/Android.bp
index 2d91ada9..5fb50708 100644
--- a/Android.bp
+++ b/Android.bp
@@ -55,6 +55,8 @@ java_defaults {
         "car-ui-lib-no-overlayable",
         "car-qc-lib",
         "car-scalable-ui-lib",
+        "car-scalable-ui-designcompose-lib",
+        "car-tos-lib",
         "com_android_systemui_car_flags_lib",
         "androidx.annotation_annotation",
         "androidx.legacy_legacy-support-v4",
@@ -225,7 +227,10 @@ android_library {
         "car-ui-lib-no-overlayable",
         "car-qc-lib",
         "car-scalable-ui-lib",
+        "car-scalable-ui-designcompose-lib",
+        "car-tos-lib",
         "com_android_systemui_car_flags_lib",
+        "com_android_car_scalableui_flags_lib",
         "CarDockLib",
         "car-data-subscription-lib",
         "testng",
diff --git a/OWNERS b/OWNERS
index 65e6e886..d8d7edbb 100644
--- a/OWNERS
+++ b/OWNERS
@@ -4,6 +4,9 @@ alexstetson@google.com
 # Secondary
 babakbo@google.com
 
+# For scalable UI changes.
+include platform/packages/apps/Car/systemlibs:car-scalable-ui-lib/OWNERS
+
 # Owners from Core Android SystemUI in case quick approval is needed for simple refactoring.
 # But generally, someone from the AAOS SystemUI listed above should be included.
 dupin@google.com
diff --git a/aconfig/carsystemui.aconfig b/aconfig/carsystemui.aconfig
index d371443f..bb8868a4 100644
--- a/aconfig/carsystemui.aconfig
+++ b/aconfig/carsystemui.aconfig
@@ -77,3 +77,17 @@ flag {
     description: "Allow per-package persistent system bar visibility control."
     bug: "328511033"
 }
+
+flag {
+    name: "display_compatibility_auto_decor_safe_region"
+    namespace: "car_sys_exp"
+    description: "This flag controls enabling the back button (using AutoDecor) and safe region for display compatibility."
+    bug: "370104463"
+}
+
+flag {
+    name: "scalable_ui_design_compose"
+    namespace: "car_sys_exp"
+    description: "This flag controls enabling loading the system ui using the DesignCompose dcf file instead of xml."
+    bug: "414813386"
+}
diff --git a/proguard.flags b/proguard.flags
index d7ba7636..4aac72c6 100644
--- a/proguard.flags
+++ b/proguard.flags
@@ -15,3 +15,10 @@
 -keep class com.android.systemui.car.qc.ProfileSwitcher { *; }
 -keep class com.android.systemui.car.qc.DriveModeQcPanel { *; }
 -keep class com.android.systemui.car.qc.QCFooterView { *; }
+-keep class com.android.systemui.car.wm.scalableui.panel.controller.BaseTaskPanelController { *; }
+-keep class com.android.systemui.car.wm.scalableui.panel.controller.MapsPanelController { *; }
+-keep class com.android.systemui.car.wm.scalableui.view.GripBarViewController { *; }
+-keep class com.android.systemui.car.wm.scalableui.view.PanelOverlayController { *; }
+-keep class com.android.systemui.car.wm.scalableui.view.ViewProvider { *; }
+-keep class com.android.systemui.car.wm.scalableui.view.GripBar { *; }
+-keep class com.android.systemui.car.wm.scalableui.view.PanelOverlay { *; }
\ No newline at end of file
diff --git a/res/color/pin_pad_icon_background_color.xml b/res/color/pin_pad_icon_background_color.xml
index 56e663b7..936f4743 100644
--- a/res/color/pin_pad_icon_background_color.xml
+++ b/res/color/pin_pad_icon_background_color.xml
@@ -42,7 +42,7 @@
             </item>
             <item>
                 <shape>
-                    <solid android:color="@color/car_secondary_container"/>
+                    <solid android:color="?oemColorSecondaryContainer"/>
                     <corners android:radius="?pinPadKeyRadius"/>
                 </shape>
             </item>
diff --git a/res/drawable/car_ic_aspect_ratio.xml b/res/drawable/car_ic_aspect_ratio.xml
new file mode 100644
index 00000000..c8442740
--- /dev/null
+++ b/res/drawable/car_ic_aspect_ratio.xml
@@ -0,0 +1,25 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="24"
+    android:viewportHeight="24">
+    <path
+        android:fillColor="?oemColorOnSurface"
+        android:pathData="M19,12h-2v3h-3v2h5v-5zM7,9h3L10,7L5,7v5h2L7,9zM21,3L3,3c-1.1,0 -2,0.9 -2,2v14c0,1.1 0.9,2 2,2h18c1.1,0 2,-0.9 2,-2L23,5c0,-1.1 -0.9,-2 -2,-2zM21,19.01L3,19.01L3,4.99h18v14.02z"/>
+</vector>
diff --git a/res/drawable/car_ic_palette.xml b/res/drawable/car_ic_palette.xml
new file mode 100644
index 00000000..024ea120
--- /dev/null
+++ b/res/drawable/car_ic_palette.xml
@@ -0,0 +1,27 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="960"
+        android:viewportHeight="960">
+    <path
+        android:fillColor="@color/car_quick_controls_icon_drawable_color"
+        android:strokeWidth="0.33333334"
+        android:pathData="M480,880Q398,880 325,848.5Q252,817 197.5,762.5Q143,708 111.5,635Q80,562 80,480Q80,397 112.5,324Q145,251 200.5,197Q256,143 330,111.5Q404,80 488,80Q568,80 639,107.5Q710,135 763.5,183.5Q817,232 848.5,298.5Q880,365 880,442Q880,557 810,618.5Q740,680 640,680L566,680Q557,680 553.5,685Q550,690 550,696Q550,708 565,730.5Q580,753 580,782Q580,832 552.5,856Q525,880 480,880ZM480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480L480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480ZM260,520Q286,520 303,503Q320,486 320,460Q320,434 303,417Q286,400 260,400Q234,400 217,417Q200,434 200,460Q200,486 217,503Q234,520 260,520ZM380,360Q406,360 423,343Q440,326 440,300Q440,274 423,257Q406,240 380,240Q354,240 337,257Q320,274 320,300Q320,326 337,343Q354,360 380,360ZM580,360Q606,360 623,343Q640,326 640,300Q640,274 623,257Q606,240 580,240Q554,240 537,257Q520,274 520,300Q520,326 537,343Q554,360 580,360ZM700,520Q726,520 743,503Q760,486 760,460Q760,434 743,417Q726,400 700,400Q674,400 657,417Q640,434 640,460Q640,486 657,503Q674,520 700,520ZM480,800Q489,800 494.5,795Q500,790 500,782Q500,768 485,749Q470,730 470,692Q470,650 499,625Q528,600 570,600L640,600Q706,600 753,561.5Q800,523 800,442Q800,321 707.5,240.5Q615,160 488,160Q352,160 256,253Q160,346 160,480Q160,613 253.5,706.5Q347,800 480,800Z"/>
+</vector>
diff --git a/res/drawable/grip_bar_background.xml b/res/drawable/grip_bar_background.xml
new file mode 100644
index 00000000..794293dd
--- /dev/null
+++ b/res/drawable/grip_bar_background.xml
@@ -0,0 +1,35 @@
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
+
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
+    <item>
+        <shape>
+            <solid android:color="?oemColorSurface"/>
+            <corners android:topLeftRadius="@dimen/panel_grip_bar_corner_radius"
+                android:topRightRadius="@dimen/panel_grip_bar_corner_radius"
+                android:bottomLeftRadius="0dp" android:bottomRightRadius="0dp"/>
+        </shape>
+    </item>
+
+    <item android:top="@dimen/panel_grip_bar_decor_top_margin" android:gravity="center_horizontal|top">
+        <shape>
+            <corners android:radius="@dimen/panel_grip_bar_decor_corner_radius" />
+            <size android:width="@dimen/panel_grip_bar_decor_width" android:height="@dimen/panel_grip_bar_decor_height" />
+            <solid android:color="?oemColorSurfaceVariant" />
+        </shape>
+    </item>
+</layer-list>
\ No newline at end of file
diff --git a/res/drawable/hvac_panel_handle_bar.xml b/res/drawable/hvac_panel_handle_bar.xml
index 25211e4b..6b505e89 100644
--- a/res/drawable/hvac_panel_handle_bar.xml
+++ b/res/drawable/hvac_panel_handle_bar.xml
@@ -19,7 +19,7 @@
     android:color="@color/car_ui_ripple_color">
     <item>
         <shape android:shape="rectangle">
-            <corners android:radius="@dimen/clear_all_button_radius"/>
+            <corners android:radius="?clearAllButtonRadius"/>
             <solid android:color="@color/hvac_panel_handle_bar_color"/>
         </shape>
     </item>
diff --git a/res/drawable/notification_handle_bar.xml b/res/drawable/notification_handle_bar.xml
index 8c2b2bf0..df7b3a1e 100644
--- a/res/drawable/notification_handle_bar.xml
+++ b/res/drawable/notification_handle_bar.xml
@@ -19,7 +19,7 @@
     android:color="?oemColorOnSurface">
     <item>
         <shape android:shape="rectangle">
-            <corners android:radius="@dimen/clear_all_button_radius"/>
+            <corners android:radius="?clearAllButtonRadius"/>
             <solid android:color="@color/notification_handle_bar_color"/>
         </shape>
     </item>
diff --git a/res/drawable/overlay_panel_background.xml b/res/drawable/overlay_panel_background.xml
new file mode 100644
index 00000000..5828f62b
--- /dev/null
+++ b/res/drawable/overlay_panel_background.xml
@@ -0,0 +1,27 @@
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
+
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item >
+        <shape>
+            <solid android:color="?oemColorOnSurfaceInverse"/>
+            <corners android:topLeftRadius="20dp"
+                android:topRightRadius="20dp"
+                android:bottomLeftRadius="20dp" android:bottomRightRadius="20dp"/>
+        </shape>
+    </item>
+</selector>
\ No newline at end of file
diff --git a/res/layout/car_bottom_system_bar.xml b/res/layout/car_bottom_system_bar.xml
index 2f8f1c98..566f5f50 100644
--- a/res/layout/car_bottom_system_bar.xml
+++ b/res/layout/car_bottom_system_bar.xml
@@ -36,7 +36,7 @@
             android:id="@+id/home"
             android:contentDescription="@string/system_bar_home_label"
             style="@style/SystemBarButton"
-            systemui:componentNames="com.android.car.carlauncher/.CarLauncher"
+            systemui:componentNames="@string/config_homeComponentName"
             systemui:highlightWhenSelected="true"
             systemui:icon="@drawable/car_ic_home"
             systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
@@ -157,7 +157,7 @@
             android:id="@+id/home"
             android:contentDescription="@string/system_bar_home_label"
             style="@style/SystemBarButton"
-            systemui:componentNames="com.android.car.carlauncher/.CarLauncher"
+            systemui:componentNames="@string/config_homeComponentName"
             systemui:highlightWhenSelected="true"
             systemui:icon="@drawable/car_ic_home"
             systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
diff --git a/res/layout/car_left_system_bar_default.xml b/res/layout/car_left_system_bar_default.xml
index 7fa011c6..380d9896 100644
--- a/res/layout/car_left_system_bar_default.xml
+++ b/res/layout/car_left_system_bar_default.xml
@@ -102,7 +102,7 @@
             android:id="@+id/home"
             android:contentDescription="@string/system_bar_home_label"
             style="@style/SystemBarButton.Vertical"
-            systemui:componentNames="com.android.car.carlauncher/.CarLauncher"
+            systemui:componentNames="@string/config_homeComponentName"
             systemui:icon="@drawable/car_ic_overview"
             systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
             systemui:selectedIcon="@drawable/car_ic_overview_selected"
diff --git a/res/layout/car_right_system_bar_default.xml b/res/layout/car_right_system_bar_default.xml
index be968776..0d84271b 100644
--- a/res/layout/car_right_system_bar_default.xml
+++ b/res/layout/car_right_system_bar_default.xml
@@ -105,7 +105,7 @@
             android:id="@+id/home"
             android:contentDescription="@string/system_bar_home_label"
             style="@style/SystemBarButton.Vertical"
-            systemui:componentNames="com.android.car.carlauncher/.CarLauncher"
+            systemui:componentNames="@string/config_homeComponentName"
             systemui:icon="@drawable/car_ic_overview"
             systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"
             systemui:selectedIcon="@drawable/car_ic_overview_selected"
diff --git a/res/layout/data_subscription_popup_window.xml b/res/layout/data_subscription_popup_window.xml
index 532f824c..80a71f90 100644
--- a/res/layout/data_subscription_popup_window.xml
+++ b/res/layout/data_subscription_popup_window.xml
@@ -47,11 +47,22 @@
             android:layout_height="wrap_content"
             android:gravity="center"
             android:paddingBottom="@dimen/data_subscription_pop_up_vertical_padding"
-            android:paddingEnd="@dimen/data_subscription_pop_up_horizontal_padding"
             android:paddingStart="@dimen/data_subscription_pop_up_horizontal_padding"
+            android:paddingEnd="@dimen/data_subscription_pop_up_text_padding"
+            android:paddingTop="@dimen/data_subscription_pop_up_vertical_padding"
+            android:textColor="@color/qc_pop_up_text_color"
+            android:layout_marginStart="@dimen/data_subscription_pop_up_horizontal_margin"/>
+        <TextView
+            android:id="@+id/popup_uxr_text_view"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:gravity="center"
+            android:paddingBottom="@dimen/data_subscription_pop_up_vertical_padding"
+            android:paddingStart="@dimen/data_subscription_pop_up_text_padding"
+            android:paddingEnd="@dimen/data_subscription_pop_up_horizontal_padding"
             android:paddingTop="@dimen/data_subscription_pop_up_vertical_padding"
             android:textColor="@color/qc_pop_up_text_color"
-            android:layout_marginHorizontal="@dimen/data_subscription_pop_up_horizontal_margin"/>
+            android:layout_marginEnd="@dimen/data_subscription_pop_up_horizontal_margin"/>
 
         <Button
             android:id="@+id/data_subscription_explore_options_button"
diff --git a/res/layout/display_compat_toolbar.xml b/res/layout/display_compat_toolbar.xml
new file mode 100644
index 00000000..ed83828c
--- /dev/null
+++ b/res/layout/display_compat_toolbar.xml
@@ -0,0 +1,51 @@
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
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:id="@+id/caption"
+    style="@style/CaptionBarStyle"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content">
+    <Button
+        android:id="@+id/back_button"
+        style="@style/CaptionButtonStyle"
+        android:background="@drawable/arrow_back"
+        android:contentDescription="@string/back_button_text"
+        android:duplicateParentState="true" />
+    <Space
+        android:layout_width="wrap_content"
+        android:layout_height="match_parent"
+        android:layout_weight="0.97"
+        android:elevation="2dp" />
+    <Button
+        android:id="@+id/aspect_ratio"
+        style="@style/CaptionButtonStyle"
+        android:background="@drawable/car_ic_aspect_ratio"
+        android:contentDescription="@string/user_aspect_ratio_settings_button_description"
+        android:duplicateParentState="true" />
+    <Space
+        android:layout_width="wrap_content"
+        android:layout_height="match_parent"
+        android:layout_weight="0.03"
+        android:elevation="2dp" />
+    <Button
+        android:id="@+id/close_window"
+        style="@style/CaptionButtonStyle"
+        android:background="@drawable/close"
+        android:contentDescription="@string/close_button_text"
+        android:duplicateParentState="true" />
+</LinearLayout>
diff --git a/res/layout/qc_status_icons_horizontal.xml b/res/layout/qc_status_icons_horizontal.xml
index f3c9c69c..a77ba6ac 100644
--- a/res/layout/qc_status_icons_horizontal.xml
+++ b/res/layout/qc_status_icons_horizontal.xml
@@ -138,4 +138,26 @@
             android:src="@drawable/car_ic_debug"
             android:contentDescription="@string/status_icon_debug_status"/>
     </com.android.systemui.car.systembar.CarSystemBarPanelButtonView>
+    <com.android.systemui.car.systembar.CarSystemBarButton
+        android:id="@+id/aaos_studio"
+        android:layout_width="@dimen/car_quick_controls_entry_points_button_width"
+        android:layout_height="match_parent"
+        android:orientation="horizontal"
+        android:gravity="center"
+        android:layout_alignParentStart="true"
+        style="@style/TopBarButton"
+        systemui:componentNames="@string/config_aaosStudioComponentName"
+        systemui:highlightWhenSelected="true"
+        systemui:intent="intent:#Intent;action=android.intent.action.MAIN;package=com.android.aaos.studio;component=com.android.aaos.studio/.TokenActivity;end"
+        systemui:systemBarDisableFlags="home"
+        systemui:controller="com.android.systemui.car.systembar.AaosStudioButtonController">
+        <ImageView
+            android:id="@+id/aaos_studio_icon"
+            android:layout_width="@dimen/car_quick_controls_icon_drawable_width"
+            android:layout_height="@dimen/car_quick_controls_icon_drawable_height"
+            android:layout_gravity="center"
+            android:tint="@color/car_status_icon_color"
+            android:duplicateParentState="true"
+            android:src="@drawable/car_ic_palette" />
+    </com.android.systemui.car.systembar.CarSystemBarButton>
 </LinearLayout>
diff --git a/res/raw/ScalableSystemUi.dcf b/res/raw/ScalableSystemUi.dcf
new file mode 100644
index 00000000..ed5d6777
Binary files /dev/null and b/res/raw/ScalableSystemUi.dcf differ
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 30efd900..039fddc6 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Terug"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Volskerm"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Sien pakkette"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Jou internetpakket het verval"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s het ’n internetverbinding nodig"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Hierdie app"</string>
 </resources>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index 765ae9a5..d0e014de 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"ተመለስ"</string>
     <string name="fullscreen" msgid="7648956467442135844">"ሙሉ ገፅ ዕይታ"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"ዕቅዶችን አሳይ"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"የበይነመረብ ዕቅድዎ ጊዜው አልፎበታል"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s የበይነመረብ ግንኙነት ያስፈልገዋል"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ይህ መተግበሪያ"</string>
 </resources>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 621359fc..b0074fe8 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"رجوع"</string>
     <string name="fullscreen" msgid="7648956467442135844">"ملء الشاشة"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"الاطّلاع على الخطط"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"انتهت صلاحية خطط الإنترنت الخاصة بك"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"يحتاج %s إلى الاتصال بالإنترنت"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"هذا التطبيق"</string>
 </resources>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index cadd3af1..e1c695ef 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"উভতি যাওক"</string>
     <string name="fullscreen" msgid="7648956467442135844">"পূৰ্ণ স্ক্ৰীন"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"আঁচনি চাওক"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"আপোনাৰ ইণ্টাৰনেটৰ আঁচনিৰ ম্যাদ উকলিছে"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%sক ইণ্টাৰনেট সংযোগৰ আৱশ্যক"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"এইটো এপ্‌"</string>
 </resources>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 095efed5..6bfe8dea 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Geri"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Tam ekran"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Planlara baxın"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"İnternet planının vaxtı keçib"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s internet bağlantısı tələb edir"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Bu tətbiq"</string>
 </resources>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 0ab254a5..8731027f 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Nazad"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Ceo ekran"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Prikaži pakete"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Internet paket je istekao"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s zahteva internet vezu"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ova aplikacija"</string>
 </resources>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 772386ee..7a459cee 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Назад"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Поўнаэкранны рэжым"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Паглядзець тарыфныя планы"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Тэрмін дзеяння вашага інтэрнэт-плана скончыўся"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s патрабуе падключэння да інтэрнэту"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Гэта праграма"</string>
 </resources>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 0c66e8f7..f069345e 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Назад"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Цял екран"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Вижте плановете"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Планът ви за интернет е изтекъл"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s се нуждае от връзка с интернет"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Това приложение"</string>
 </resources>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index c2ae3937..5d7217a9 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"ফিরে যান"</string>
     <string name="fullscreen" msgid="7648956467442135844">"ফুল-স্ক্রিন"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"প্ল্যান দেখুন"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"আপনার ইন্টারনেট প্ল্যানের মেয়াদ শেষ হয়ে গেছে"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s-এর ক্ষেত্রে ইন্টারনেট কানেকশন প্রয়োজন"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"এই অ্যাপ"</string>
 </resources>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 3f1f11d5..ac8b6be2 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Nazad"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Prikaži preko cijelog ekrana"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Pogledajte pakete"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Internetski paket je istekao"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s treba internetsku vezu"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ova aplikacija"</string>
 </resources>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index d406e0e2..edc4e9ad 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -46,7 +46,7 @@
     <string name="mic_privacy_chip_off_toast" msgid="8718743873640788032">"El micròfon s\'ha desactivat"</string>
     <string name="mic_privacy_chip_dialog_ok" msgid="2298690833121720237">"D\'acord"</string>
     <string name="sensor_privacy_start_use_mic_dialog_title" msgid="8774244900043105266">"Vols activar el micròfon del vehicle?"</string>
-    <string name="sensor_privacy_start_use_mic_dialog_content" msgid="8382980879434990801">"Per continuar, activa el micròfon del sistema d\'informació i entreteniment. Això activarà el micròfon per a totes les aplicacions que tinguin permís."</string>
+    <string name="sensor_privacy_start_use_mic_dialog_content" msgid="8382980879434990801">"Per continuar, activa el micròfon del sistema d\'infoentreteniment. Això activarà el micròfon per a totes les aplicacions que tinguin permís."</string>
     <string name="camera_privacy_chip_app_using_camera_suffix" msgid="2591363552459967509">"<xliff:g id="APP">%s</xliff:g> està utilitzant la càmera"</string>
     <string name="camera_privacy_chip_apps_using_camera_suffix" msgid="8033118959615498419">"<xliff:g id="APP_LIST">%s</xliff:g> estan utilitzant la càmera"</string>
     <string name="camera_privacy_chip_app_recently_used_camera_suffix" msgid="4534950658276502559">"<xliff:g id="APP">%s</xliff:g> ha utilitzat la càmera recentment"</string>
@@ -55,7 +55,7 @@
     <string name="camera_privacy_chip_off_toast" msgid="7135472255099347229">"La càmera s\'ha desactivat"</string>
     <string name="camera_privacy_chip_dialog_ok" msgid="7285467760928137765">"D\'acord"</string>
     <string name="sensor_privacy_start_use_camera_dialog_title" msgid="4787836783010823885">"Vols activar la càmera del vehicle?"</string>
-    <string name="sensor_privacy_start_use_camera_dialog_content" msgid="7749639131326657668">"Per continuar, activa la càmera del sistema d\'informació i entreteniment. Això activarà la càmera per a totes les aplicacions que tinguin permís."</string>
+    <string name="sensor_privacy_start_use_camera_dialog_content" msgid="7749639131326657668">"Per continuar, activa la càmera del sistema d\'infoentreteniment. Això activarà la càmera per a totes les aplicacions que tinguin permís."</string>
     <string name="system_bar_home_label" msgid="8413273833405495948">"Pantalla d\'inici"</string>
     <string name="system_bar_phone_label" msgid="5664288201806823777">"Telèfon"</string>
     <string name="system_bar_applications_label" msgid="7081862804211786227">"Aplicacions"</string>
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Enrere"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Pantalla completa"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Mostra els plans"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"El teu pla d\'Internet ha caducat"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s necessita connexió a Internet"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Aquesta aplicació"</string>
 </resources>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index 3db3a829..690cf3a3 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Zpět"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Celá obrazovka"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Zobrazit tarify"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Vašemu internetovému tarifu vypršela platnost"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s potřebuje připojení k internetu"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Tato aplikace"</string>
 </resources>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index 1650f319..eeb4cdc4 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Tilbage"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Fuld skærm"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Se abonnementer"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Dit internetabonnement er udløbet"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s kræver en internetforbindelse"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Denne app"</string>
 </resources>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index 6e3d3ffe..4d696d29 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Zurück"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Vollbild"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Tarife ansehen"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Dein Internettarif ist abgelaufen"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s benötigt eine Internetverbindung"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Diese App"</string>
 </resources>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index e92e269f..384b28f5 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Πίσω"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Πλήρης οθόνη"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Δείτε τα προγράμματα"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Το πρόγραμμα δεδομένων σας στο διαδίκτυο έληξε"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s χρειάζεται σύνδεση στο διαδίκτυο"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Αυτή η εφαρμογή"</string>
 </resources>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index eeff2460..f2ebdda1 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Back"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Full Screen"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"See plans"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Your Internet plan has expired"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s needs an Internet connection"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"This app"</string>
 </resources>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 33baafbf..d0f74241 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Back"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Full Screen"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"See plans"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Your internet plan expired"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s needs an internet connection"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"This app"</string>
 </resources>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index eeff2460..f2ebdda1 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Back"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Full Screen"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"See plans"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Your Internet plan has expired"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s needs an Internet connection"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"This app"</string>
 </resources>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index eeff2460..f2ebdda1 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Back"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Full Screen"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"See plans"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Your Internet plan has expired"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s needs an Internet connection"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"This app"</string>
 </resources>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index e3a48707..5b8e4f8c 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Atrás"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Pantalla completa"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Ver planes"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Tu plan de Internet venció"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s requiere conexión a Internet"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Esta app"</string>
 </resources>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 01d446ab..13f358cd 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Atrás"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Pantalla completa"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Ver planes"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Tu plan de Internet ha caducado"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s necesita conexión a Internet"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Esta aplicación"</string>
 </resources>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index a1255f3f..3660c8fc 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Tagasi"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Täisekraan"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Kuva paketid"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Teie internetipakett on aegunud"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s vajab internetiühendust"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"See rakendus"</string>
 </resources>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 1d7a01b7..b0377b3e 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Atzera"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Pantaila osoa"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Ikusi kidetzak"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Interneteko kidetza iraungi da"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"Beharrezkoa da %s Internetera konektatzea"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"aplikazio hau"</string>
 </resources>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index cf959ef0..ef9c55f7 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"برگشتن"</string>
     <string name="fullscreen" msgid="7648956467442135844">"تمام صفحه"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"دیدن طرح‌ها"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"طرح اینترنت شما منقضی شده است"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"‫%s به اتصال اینترنت نیاز دارد"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"این برنامه"</string>
 </resources>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 4d87388f..7580dde5 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Takaisin"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Koko näyttö"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Katso liittymät"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Internetliittymä on vanhentunut"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s tarvitsee internetyhteyden"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Tämä sovellus"</string>
 </resources>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 2f277ae8..282d9f20 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Retour"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Plein écran"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Voir les forfaits"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Votre forfait Internet a expiré"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s nécessite une connexion Internet"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Cette appli"</string>
 </resources>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index 591c59b6..85bf7095 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Retour"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Plein écran"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Afficher les forfaits"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Votre forfait Internet a expiré"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s nécessite une connexion Internet."</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Cette appli"</string>
 </resources>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 77592874..e7a5ddc1 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Volver"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Pantalla completa"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Ver plans"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"O teu plan de Internet caducou"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s necesita conexión a Internet"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Esta aplicación"</string>
 </resources>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index dc1257a5..5ef021a3 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"પાછળ"</string>
     <string name="fullscreen" msgid="7648956467442135844">"પૂર્ણ સ્ક્રીન"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"પ્લાન જુઓ"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"તમારો ઇન્ટરનેટ પ્લાન સમાપ્ત થઈ ગયો છે"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s માટે ઇન્ટરનેટ કનેક્શન જરૂરી છે"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"આ ઍપ"</string>
 </resources>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 8cd5fb6e..8b0e238f 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"वापस जाएं"</string>
     <string name="fullscreen" msgid="7648956467442135844">"फ़ुल स्क्रीन"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"प्लान देखें"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"आपका इंटरनेट प्लान खत्म हो गया है"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s के लिए इंटरनेट कनेक्शन होना ज़रूरी है"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"यह ऐप्लिकेशन"</string>
 </resources>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 15c0c6bf..e127548a 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Natrag"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Cijeli zaslon"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Prikaži pakete"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Vaš je internetski paket istekao"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s zahtijeva internetsku vezu"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ova aplikacija"</string>
 </resources>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index 0b70d881..44d6d164 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Vissza"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Teljes képernyő"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Csomagok megtekintése"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Lejárt az internetcsomagja"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"A(z) %s internetkapcsolatot igényel"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ez az alkalmazás"</string>
 </resources>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index ce37b35e..b54a1581 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Հետ"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Լիաէկրան"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Դիտել պլանները"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Ձեր ինտերնետ սակագնային պլանի ժամկետը սպառվել է"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s հավելվածի աշխատանքի համար ինտերնետ կապ է հարկավոր"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Այս"</string>
 </resources>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index f38982da..baaf25cd 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Kembali"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Layar Penuh"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Lihat paket"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Masa berlaku paket internet Anda telah berakhir"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s memerlukan koneksi internet"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Aplikasi ini"</string>
 </resources>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 02736ceb..e40afc89 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Til baka"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Allur skjárinn"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Sjá áskriftir"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Netáskriftin þín rann út"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s þarf nettengingu"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Þetta forrit"</string>
 </resources>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 8be90c22..85db2917 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Indietro"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Schermo intero"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Vedi i piani"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Il tuo piano internet è scaduto"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s richiede una connessione a internet"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Quest\'app"</string>
 </resources>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 6fb5b11c..e2b74f9b 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"חזרה"</string>
     <string name="fullscreen" msgid="7648956467442135844">"מסך מלא"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"להצגת חבילות הגלישה"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"חבילת הגלישה שלך כבר לא תקפה"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"ל-%s נדרש חיבור לאינטרנט"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"האפליקציה הזו"</string>
 </resources>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index d727defd..a6f60dfa 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"戻る"</string>
     <string name="fullscreen" msgid="7648956467442135844">"全画面表示"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"プランを見る"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"ご利用のインターネット プランの期限が切れています"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s を使用するには、インターネット接続が必要です"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"このアプリ"</string>
 </resources>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index 0ffca9fd..8c87dadc 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"უკან"</string>
     <string name="fullscreen" msgid="7648956467442135844">"სრულ ეკრანზე"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"გეგმების ნახვა"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"თქვენს ინტერნეტის გეგმას ვადა გაუვიდა"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s საჭიროებს ინტერნეტ-კავშირს"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ეს აპი"</string>
 </resources>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index f813b19c..de959162 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Артқа"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Толық экран"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Жоспарларды көру"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Интернет тарифтік жоспарыңыздың мерзімі аяқталды."</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s үшін интернет байланысы қажет."</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Осы қолданба"</string>
 </resources>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index 62c01a77..4a9f7bda 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"ថយក្រោយ"</string>
     <string name="fullscreen" msgid="7648956467442135844">"អេក្រង់ពេញ"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"មើល​គម្រោង"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"គម្រោងអ៊ីនធឺណិតរបស់អ្នកផុតកំណត់ហើយ"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ត្រូវការការតភ្ជាប់អ៊ីនធឺណិត"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"កម្មវិធីនេះ"</string>
 </resources>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 962a8713..9a73e663 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"ಹಿಂದಕ್ಕೆ"</string>
     <string name="fullscreen" msgid="7648956467442135844">"ಪೂರ್ಣ ಸ್ಕ್ರೀನ್"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"ಪ್ಲಾನ್‌ಗಳನ್ನು ನೋಡಿ"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"ನಿಮ್ಮ ಇಂಟರ್ನೆಟ್ ಪ್ಲಾನ್ ಅವಧಿ ಮುಗಿದಿದೆ"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ಗೆಇಂಟರ್‌ನೆಟ್ ಕನೆಕ್ಷನ್‌ನ ಅಗತ್ಯವಿದೆ"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ಈ ಆ್ಯಪ್"</string>
 </resources>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index 35f9dfd7..c4e8f98b 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"뒤로"</string>
     <string name="fullscreen" msgid="7648956467442135844">"전체 화면"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"요금제 보기"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"인터넷 요금제가 만료되었습니다."</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s에 인터넷 연결이 필요합니다."</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"이 앱"</string>
 </resources>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index c0eb9ee9..7bc55101 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Артка"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Толук экран"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Тарифтик пландарды көрүү"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Интернет үчүн тарифтик планыңыздын мөөнөтү бүттү"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s үчүн Интернет байланышы керек"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ушул колдонмо"</string>
 </resources>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index 34530c6e..4f65482c 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"ກັບຄືນ"</string>
     <string name="fullscreen" msgid="7648956467442135844">"ເຕັມຈໍ"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"ເບິ່ງແພັກເກດ"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"ແພັກເກດອິນເຕີເນັດຂອງທ່ານໝົດອາຍຸແລ້ວ"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ຕ້ອງການການເຊື່ອມຕໍ່ອິນເຕີເນັດ"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ແອັບນີ້"</string>
 </resources>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index edfc1f92..4c0b5a2c 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Atgal"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Visas ekranas"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Peržiūrėti planus"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Jūsų interneto planas nebegalioja"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s reikalingas interneto ryšys"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Šiai programai"</string>
 </resources>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 10a0d094..848d9fca 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Atpakaļ"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Pilnekrāna režīms"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Skatīt plānus"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Beidzies jūsu interneta plāna derīguma termiņš"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s pieprasa interneta savienojumu"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Šī lietotne"</string>
 </resources>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 3b35ead5..8d1d394d 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Назад"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Цел екран"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Погледнете ги пакетите"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Вашиот интернет-пакет е истечен"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s бара интернет-врска"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Оваа апликација"</string>
 </resources>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 6382526f..59b86381 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"മടങ്ങുക"</string>
     <string name="fullscreen" msgid="7648956467442135844">"പൂർണ്ണ സ്ക്രീൻ"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"പ്ലാനുകൾ കാണുക"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"നിങ്ങളുടെ ഇന്റർനെറ്റ് പ്ലാൻ കാലഹരണപ്പെട്ടു"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s എന്നതിന് ഇന്റർനെറ്റ് കണക്ഷൻ ആവശ്യമാണ്"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ഈ ആപ്പ്"</string>
 </resources>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 447e9e1b..793cce11 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Буцах"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Бүтэн дэлгэц"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Багцыг харах"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Таны интернэт багцын хугацаа дууссан"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s-д интернэт холболт шаардлагатай"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Энэ апп"</string>
 </resources>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 70c12300..50fe3935 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"मागे जा"</string>
     <string name="fullscreen" msgid="7648956467442135844">"फुल स्क्रीन"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"प्लॅन पहा"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"तुमचा इंटरनेट प्लॅन एक्स्पायर झाला आहे"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ला इंटरनेट कनेक्शन आवश्यक आहे"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"हे अ‍ॅप"</string>
 </resources>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 06d76a2f..8853082a 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Kembali"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Skrin Penuh"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Lihat pelan"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Pelan Internet anda telah tamat tempoh"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s memerlukan sambungan Internet"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Apl ini"</string>
 </resources>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index a219fa05..d17575f3 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"နောက်သို့"</string>
     <string name="fullscreen" msgid="7648956467442135844">"ဖန်သားပြင်အပြည့်"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"အစီအစဉ်များ ကြည့်ရန်"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"သင့်အင်တာနက်အစီအစဉ် သက်တမ်းကုန်သွားပါပြီ"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s သည် အင်တာနက်ချိတ်ဆက်မှု လိုအပ်သည်"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ဤအက်ပ်"</string>
 </resources>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index 0d255b34..6a74f3d6 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Tilbake"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Fullskjerm"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Se abonnementer"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Internettabonnementet ditt er utløpt"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s trenger internettilkobling"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Denne appen"</string>
 </resources>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index cf94c8b2..7044cfa5 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"पछाडि"</string>
     <string name="fullscreen" msgid="7648956467442135844">"फुल स्क्रिन"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"योजनाहरू हेर्नुहोस्"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"तपाईंको इन्टरनेट योजनाको म्याद सकिएको छ"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s चलाउन इन्टरनेट कनेक्सन चाहिन्छ"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"यो एप"</string>
 </resources>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index a93f406c..9430a071 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Terug"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Volledig scherm"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Abonnementen bekijken"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Je internetabonnement is verlopen"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s heeft een internetverbinding nodig"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Deze app"</string>
 </resources>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 85137dd9..25128db6 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"ପଛକୁ ଫେରନ୍ତୁ"</string>
     <string name="fullscreen" msgid="7648956467442135844">"ପୂର୍ଣ୍ଣ ସ୍କ୍ରିନ"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"ପ୍ଲାନଗୁଡ଼ିକ ଦେଖନ୍ତୁ"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"ଆପଣଙ୍କର ଇଣ୍ଟର୍ନେଟ ପ୍ଲାନର ମିଆଦ ଶେଷ ହୋଇଯାଇଛି"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ଏକ ଇଣ୍ଟର୍ନେଟ କନେକ୍ସନ ଆବଶ୍ୟକ କରେ"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ଏହି ଆପ"</string>
 </resources>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 042c6a0c..61527b41 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"ਪਿੱਛੇ"</string>
     <string name="fullscreen" msgid="7648956467442135844">"ਪੂਰੀ ਸਕ੍ਰੀਨ"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"ਪਲਾਨ ਦੇਖੋ"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"ਤੁਹਾਡੇ ਇੰਟਰਨੈੱਟ ਪਲਾਨ ਦੀ ਮਿਆਦ ਸਮਾਪਤ ਹੋ ਗਈ ਹੈ"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ਲਈ ਇੰਟਰਨੈੱਟ ਕਨੈਕਸ਼ਨ ਦੀ ਲੋੜ ਹੈ"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ਇਹ ਐਪ"</string>
 </resources>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 694d3421..7e317222 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Wstecz"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Pełny ekran"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Zobacz abonamenty"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Twój abonament internetowy stracił ważność"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s wymaga połączenia z internetem"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ta aplikacja"</string>
 </resources>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index b513fd7f..bfde63dc 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Anterior"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Ecrã inteiro"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Ver planos"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"O seu plano de Internet expirou"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s precisa de uma ligação à Internet"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Esta app"</string>
 </resources>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index d3d244d0..c819d376 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Voltar"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Tela cheia"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Ver planos"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Seu plano de Internet expirou"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s precisa de conexão com a Internet"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Este app"</string>
 </resources>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 05218f16..8d39e9a3 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Înapoi"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Ecran complet"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Vezi planurile"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Planul tău de internet a expirat"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s necesită o conexiune la internet"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Această aplicație"</string>
 </resources>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 6619b425..9fc2f96b 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Назад"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Полноэкранный режим"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Посмотреть тарифы"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Ваш тарифный план на интернет больше не действует"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s требует подключения к интернету."</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Это приложение"</string>
 </resources>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index aa394f10..639d0bc3 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"ආපසු"</string>
     <string name="fullscreen" msgid="7648956467442135844">"පූර්ණ තිරය"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"සැලසුම් බලන්න"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"ඔබේ අන්තර්ජාල සැලසුම කල් ඉකුත් විය"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s හට අන්තර්ජාල සම්බන්ධතාවයක් අවශ්‍යයි"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"මෙම යෙදුම"</string>
 </resources>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index 1f56c1f7..0eb64b99 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Späť"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Celá obrazovka"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Zobraziť tarify"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Vaša internetová tarifa vypršala"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"Aplikácia %s vyžaduje internetové pripojenie"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Táto aplikácia"</string>
 </resources>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index cc42b201..0d215a47 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Nazaj"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Celozaslonski način"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Oglejte si pakete"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Vaš internetni paket je potekel"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s potrebuje internetno povezavo"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ta aplikacija"</string>
 </resources>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 64b8d3f8..92ab7520 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Pas"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Ekran i plotë"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Shiko planet"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Plani yt i internetit ka skaduar"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ka nevojë për një lidhje interneti"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ky aplikacion"</string>
 </resources>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index a85595a3..9b6861a0 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Назад"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Цео екран"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Прикажи пакете"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Интернет пакет је истекао"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s захтева интернет везу"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ова апликација"</string>
 </resources>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index 20ff69e1..cf5ad8cc 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Tillbaka"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Helskärm"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Se abonnemang"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Ditt internetabonnemang har löpt ut"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s behöver en internetanslutning"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Den här appen"</string>
 </resources>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 6c36e57f..c58dd6a2 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Rudi nyuma"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Skrini Nzima"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Angalia mipango"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Muda wa mpango wako wa intaneti umeisha"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s inahitaji muunganisho wa intaneti"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Programu hii"</string>
 </resources>
diff --git a/res/values-sw800dp-land/dimens.xml b/res/values-sw800dp-land/dimens.xml
new file mode 100644
index 00000000..685e4c5d
--- /dev/null
+++ b/res/values-sw800dp-land/dimens.xml
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
+  ~ limitations under the License
+  -->
+<resources>
+    <!-- Width of the disabled microphone dialog -->
+    <dimen name="large_dialog_width">1056dp</dimen>
+
+    <!-- coordinates of rect to be used for safe region to open compat apps -->
+    <dimen name="safe_region_left">0dp</dimen>
+    <dimen name="safe_region_top">144dp</dimen>
+    <dimen name="safe_region_right">1443dp</dimen>
+    <dimen name="safe_region_bottom">716dp</dimen>
+
+    <!-- coordinates of rect to be used to show toolbar for compat apps -->
+    <!-- height = 68dp -->
+    <dimen name="caption_region_left">0dp</dimen>
+    <dimen name="caption_region_top">76dp</dimen>
+    <dimen name="caption_region_right">1443dp</dimen>
+    <dimen name="caption_region_bottom">144dp</dimen>
+</resources>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 756f4967..478a163f 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"பின்செல்"</string>
     <string name="fullscreen" msgid="7648956467442135844">"முழுத்திரை"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"திட்டங்களைக் காட்டு"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"உங்கள் இணையத் திட்டம் காலாவதியாகிவிட்டது"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%sக்கு இணைய இணைப்பு தேவை"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"இந்த ஆப்ஸ்"</string>
 </resources>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index eac7891e..4e649b8c 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"వెనుకకు"</string>
     <string name="fullscreen" msgid="7648956467442135844">"ఫుల్ స్క్రీన్"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"ప్లాన్‌లను చూడండి"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"మీ ఇంటర్నెట్ ప్లాన్‌ గడువు ముగిసింది"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s‌కు ఇంటర్నెట్ కనెక్షన్ అవసరం"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ఈ యాప్"</string>
 </resources>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index 0e1ddb04..c8e2ea36 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"กลับ"</string>
     <string name="fullscreen" msgid="7648956467442135844">"เต็มหน้าจอ"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"ดูแพ็กเกจ"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"แพ็กเกจอินเทอร์เน็ตของคุณหมดอายุแล้ว"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ต้องมีการเชื่อมต่ออินเทอร์เน็ต"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"แอปนี้"</string>
 </resources>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 1f8fd945..8d29c977 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Bumalik"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Full Screen"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Tingnan ang mga plan"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Nag-expire na ang internet plan mo"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"Kailangan ng %s ng koneksyon sa internet"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"App na ito"</string>
 </resources>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 2700333d..c6ab9a38 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Geri"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Tam Ekran"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Planları göster"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"İnternet planınızın süresi doldu"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s için internet bağlantısı gerekiyor"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Bu uygulama"</string>
 </resources>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index 6fc72a84..30332f2c 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Назад"</string>
     <string name="fullscreen" msgid="7648956467442135844">"На весь екран"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Переглянути плани"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Строк дії вашого тарифного плану Інтернету закінчився"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s потребує інтернет-з’єднання"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Цей додаток"</string>
 </resources>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index cb2ded37..6f773f95 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"پیچھے جائیں"</string>
     <string name="fullscreen" msgid="7648956467442135844">"فُل اسکرین"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"پلانز دیکھیں"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"آپ کے انٹرنیٹ پلان کی میعاد ختم ہو گئی"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"‫%s کو انٹرنیٹ کنکشن درکار ہے"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"یہ ایپ"</string>
 </resources>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index de0b5890..979d4a39 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Orqaga"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Butun ekran"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Tarif rejalari"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Internet tarif rejangiz muddati tugagan"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ilovasiga internet aloqasi kerak"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Bu ilova"</string>
 </resources>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 61dfdcca..62b47853 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Quay lại"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Toàn màn hình"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Xem các gói"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Gói Internet của bạn đã hết hạn"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s cần có kết nối Internet"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ứng dụng này"</string>
 </resources>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 96db2780..b89dffe3 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"返回"</string>
     <string name="fullscreen" msgid="7648956467442135844">"全屏"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"查看套餐"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"您的互联网套餐已过期"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s需要连接到互联网"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"此应用"</string>
 </resources>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 7967974f..81c07ca9 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"返回"</string>
     <string name="fullscreen" msgid="7648956467442135844">"全螢幕"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"查看計劃"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"你的互聯網計劃已到期"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s 需要互聯網連線"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"此應用程式"</string>
 </resources>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 8d7d5668..86bfd814 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"返回"</string>
     <string name="fullscreen" msgid="7648956467442135844">"全螢幕"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"查看方案"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"你的網際網路方案已過期"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"「%s」需連上網路"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"這個應用程式"</string>
 </resources>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index ab5fc6e8..18886d9e 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -139,7 +139,4 @@
     <string name="back_btn" msgid="7774349944465667391">"Emuva"</string>
     <string name="fullscreen" msgid="7648956467442135844">"Isikrini Esigcwele"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Bona izinhlelo"</string>
-    <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Uhlelo lwakho lwe-inthanethi luphelelwe isikhathi"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"I-%s idinga ukuxhumeka kwe-inthanethi"</string>
-    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Le app"</string>
 </resources>
diff --git a/res/values/attrs.xml b/res/values/attrs.xml
index 3058a4fc..680a2942 100644
--- a/res/values/attrs.xml
+++ b/res/values/attrs.xml
@@ -287,4 +287,5 @@
     <attr name="pinPadKeyRadius" format="dimension"/>
     <attr name="dataSubscriptionPopUpRadius" format="dimension"/>
     <attr name="dataSubscriptionPopUpArrowRadius" format="dimension"/>
+    <attr name="clearAllButtonRadius" format="dimension"/>
 </resources>
diff --git a/res/values/colors.xml b/res/values/colors.xml
index 07374421..a6365425 100644
--- a/res/values/colors.xml
+++ b/res/values/colors.xml
@@ -30,4 +30,6 @@
 
     <!-- Color for PIN Pad icon.-->
     <color name="pin_pad_icon_color">@color/car_ui_text_color_primary</color>
+
+    <color name="overlay_panel_bg_color">#46000000</color>
 </resources>
diff --git a/res/values/config.xml b/res/values/config.xml
index d31fddfc..0ff5cc33 100644
--- a/res/values/config.xml
+++ b/res/values/config.xml
@@ -150,9 +150,15 @@
         <item>com.android.cts.verifier</item>
     </string-array>
 
+    <!-- Specifies the component name of the home activity -->
+    <string name="config_homeComponentName" translatable="false">com.android.car.carlauncher/.CarLauncher</string>
+
     <!-- Specifies the component name of the app grid activity -->
     <string name="config_appGridComponentName" translatable="false">com.android.car.carlauncher/.AppGridActivity</string>
 
+    <!-- Specifies the component name of the AAOS Studio activity -->
+    <string name="config_aaosStudioComponentName" translatable="false">com.android.aaos.studio/.TokenActivity</string>
+
     <!--Percentage of the screen height, from the top, where the border between HVAC panel closing
         or opening, depending on where its handle bar is released after being dragged, would be
         drawn.
@@ -234,6 +240,16 @@
     <!-- 3 immersive based on bar control policy  -->
     <integer name="config_systemBarPersistency">1</integer>
 
+    <!-- Determines if the system bars should be forced into a particular system bar behavior when
+         the Setup Wizard is currently in progress. This config only takes effect if
+         config_remoteInsetsControllerControlsSystemBars is set to true and will supplement the
+         behavior of config_systemBarPersistency. -->
+    <!-- 0 disabled - will not modify config_systemBarPersistency behavior for SUW. -->
+    <!-- 1 immersive, force hide both bars for SUW -->
+    <!-- 2 immersive_with_nav, force show nav bar and hide status bar for SUW -->
+    <!-- 3 immersive_with_status, force show status bar and hide nav bar for SUW  -->
+    <integer name="config_systemBarSuwBehavior">0</integer>
+
     <!-- Determines the orientation of the status icon. -->
     <!-- 0 horizontal. -->
     <!-- 1 vertical -->
@@ -248,22 +264,6 @@
     <!-- Media blocking activity component name -->
     <string name="config_mediaBlockingActivity" translatable="false">com.android.car.media/.MediaBlockingActivity</string>
 
-    <!--
-        The list to define which activities the data subscription pop-up should not display
-        a message when they are launched
-    -->
-    <string-array translatable="false" name="config_dataSubscriptionBlockedActivitiesList">
-    </string-array>
-
-    <!--
-    The list to define which packages the data subscription pop-up should not display
-    a message when they are launched
-    -->
-    <string-array translatable="false" name="config_dataSubscriptionBlockedPackagesList">
-        <item>com.android.car.settings</item>
-        <item>com.android.car.carlauncher</item>
-    </string-array>
-
     <!--
        The devices that certain debug features should be shown on.
        Emulators are included by default.
@@ -309,4 +309,13 @@
     -->
     <string-array name="config_default_activities" translatable="false">
     </string-array>
+
+    <!-- Enable toolkit for data subscription. -->
+    <bool name="config_enableDataSubscriptionToolkit">true</bool>
+
+    <!-- Setup and add safe area and toolbar per display on for Display Compat apps . -->
+    <bool name="config_enableSafeAreaAndToolbarPerDisplay">true</bool>
+
+    <!-- Figma file ID for the DCF file used to load system ui -->
+    <string name="config_scalableUiDcfFileId">cydzv1nh1pZBdFmZAbdFQU</string>
 </resources>
diff --git a/res/values/dimens.xml b/res/values/dimens.xml
index e4544432..0897c346 100644
--- a/res/values/dimens.xml
+++ b/res/values/dimens.xml
@@ -454,6 +454,7 @@
     <dimen name="data_subscription_pop_up_arrow_offset">84dp</dimen>
     <dimen name="data_subscription_pop_up_vertical_padding">46dp</dimen>
     <dimen name="data_subscription_pop_up_horizontal_padding">@*android:dimen/car_padding_3</dimen>
+    <dimen name="data_subscription_pop_up_text_padding">0dp</dimen>
     <dimen name="data_subscription_pop_up_button_width">224dp</dimen>
     <dimen name="data_subscription_pop_up_button_height">68dp</dimen>
     <dimen name="car_quick_controls_panel_margin">8dp</dimen>
@@ -466,4 +467,31 @@
     <dimen name="passenger_keyguard_lockpattern_height">350dp</dimen>
 
     <dimen name="freeform_decor_caption_height">68dp</dimen>
+
+    <!-- TODO(b/409131368): Remove when Hudson is migrated to scalable ui -->
+    <!-- coordinates of rect to be used for safe region to open compat apps -->
+    <dimen name="safe_region_left">0dp</dimen>
+    <dimen name="safe_region_top">144dp</dimen>
+    <dimen name="safe_region_right">1408dp</dimen>
+    <dimen name="safe_region_bottom">696dp</dimen>
+
+    <!-- TODO(b/409131368): Remove when Hudson is migrated to scalable ui -->
+    <!-- coordinates of rect to be used to show toolbar for compat apps -->
+    <!-- height = 68dp -->
+    <dimen name="caption_region_left">0dp</dimen>
+    <dimen name="caption_region_top">76dp</dimen>
+    <dimen name="caption_region_right">1408dp</dimen>
+    <dimen name="caption_region_bottom">144dp</dimen>
+
+    <dimen name="overlay_panel_view_vail_width">96dp</dimen>
+    <dimen name="overlay_panel_view_vail_height">96dp</dimen>
+
+    <!-- Grip bar for panels -->
+    <dimen name="panel_grip_bar_corner_radius">48dp</dimen>
+    <dimen name="panel_grip_bar_decor_top_margin">15dp</dimen>
+    <dimen name="panel_grip_bar_decor_corner_radius">2dp</dimen>
+    <dimen name="panel_grip_bar_decor_width">100dp</dimen>
+    <dimen name="panel_grip_bar_decor_height">4dp</dimen>
+
+
 </resources>
diff --git a/res/values/integers.xml b/res/values/integers.xml
index 5c988d5c..75581cc1 100644
--- a/res/values/integers.xml
+++ b/res/values/integers.xml
@@ -69,4 +69,7 @@
     <integer name="data_subscription_pop_up_startup_cycle_limit">3</integer>
     <!-- The number of active days after which the popup is not shown anymore -->
     <integer name="data_subscription_pop_up_active_days_limit">5</integer>
+
+    <integer name="overlay_panel_blur_corner_radius">20</integer>
+    <integer name="overlay_panel_blur_radius">20</integer>
 </resources>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index eb9129ef..e18d4031 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -301,9 +301,5 @@
 
     <!-- Data subscription button text [CHAR LIMIT=30]-->
     <string name="data_subscription_button_text">See plans</string>
-    <!-- Data subscription proactive message prompt-->
-    <string name="data_subscription_proactive_msg_prompt">Your internet plan expired</string>
-    <string name="data_subscription_reactive_msg_prompt">%s needs an internet connection</string>
-    <string name="data_subscription_reactive_generic_app_label">This app</string>
 
 </resources>
diff --git a/res/values/styles.xml b/res/values/styles.xml
index 50cc1687..162ec9dd 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -278,5 +278,6 @@
         <item name="pinPadKeyRadius">?oemShapeCornerFull</item>
         <item name="dataSubscriptionPopUpRadius">?oemShapeCornerMedium</item>
         <item name="dataSubscriptionPopUpArrowRadius">?oemShapeCornerExtraSmall</item>
+        <item name="clearAllButtonRadius">?oemShapeCornerExtraLarge</item>
     </style>
 </resources>
diff --git a/samples/SystemBarBottom/res/values/config.xml b/samples/SystemBarBottom/res/values/config.xml
index 88645ef5..fae89cda 100644
--- a/samples/SystemBarBottom/res/values/config.xml
+++ b/samples/SystemBarBottom/res/values/config.xml
@@ -56,6 +56,10 @@
     <string name="config_notificationPanelViewMediator" translatable="false">
         com.android.systemui.car.notification.BottomNotificationPanelViewMediator</string>
 
+    <!-- Specifies the component name of the home activity -->
+    <string name="config_homeComponentName" translatable="false">
+        com.android.car.carlauncher/.CarLauncher</string>
+
     <!-- Specifies the component name of the app grid activity -->
     <string name="config_appGridComponentName" translatable="false">
         com.android.car.carlauncher/.AppGridActivity</string>
diff --git a/samples/SystemBarBottomRounded/res/values/config.xml b/samples/SystemBarBottomRounded/res/values/config.xml
index 88645ef5..fae89cda 100644
--- a/samples/SystemBarBottomRounded/res/values/config.xml
+++ b/samples/SystemBarBottomRounded/res/values/config.xml
@@ -56,6 +56,10 @@
     <string name="config_notificationPanelViewMediator" translatable="false">
         com.android.systemui.car.notification.BottomNotificationPanelViewMediator</string>
 
+    <!-- Specifies the component name of the home activity -->
+    <string name="config_homeComponentName" translatable="false">
+        com.android.car.carlauncher/.CarLauncher</string>
+
     <!-- Specifies the component name of the app grid activity -->
     <string name="config_appGridComponentName" translatable="false">
         com.android.car.carlauncher/.AppGridActivity</string>
diff --git a/samples/SystemBarLeft/res/values/config.xml b/samples/SystemBarLeft/res/values/config.xml
index 1950636d..27622c80 100644
--- a/samples/SystemBarLeft/res/values/config.xml
+++ b/samples/SystemBarLeft/res/values/config.xml
@@ -74,6 +74,10 @@
     <string name="config_notificationPanelViewMediator" translatable="false">
         com.android.systemui.car.notification.NotificationPanelViewMediator</string>
 
+    <!-- Specifies the component name of the home activity -->
+    <string name="config_homeComponentName" translatable="false">
+        com.android.car.carlauncher/.CarLauncher</string>
+
     <string name="config_appGridComponentName" translatable="false">
         com.android.car.carlauncher/.AppGridActivity</string>
 
diff --git a/samples/SystemBarLeft/res/xml/car_sysui_overlays.xml b/samples/SystemBarLeft/res/xml/car_sysui_overlays.xml
index 53af82d0..7ee52f3d 100644
--- a/samples/SystemBarLeft/res/xml/car_sysui_overlays.xml
+++ b/samples/SystemBarLeft/res/xml/car_sysui_overlays.xml
@@ -18,6 +18,10 @@
         target="string/config_appGridComponentName"
         value="@string/config_appGridComponentName" />
 
+    <item
+        target="string/config_homeComponentName"
+        value="@string/config_homeComponentName" />
+
     <item
         target="bool/config_enableTopSystemBar"
         value="@bool/config_enableTopSystemBar" />
diff --git a/samples/SystemBarRight/res/values/config.xml b/samples/SystemBarRight/res/values/config.xml
index a583a05f..3bbba0e3 100644
--- a/samples/SystemBarRight/res/values/config.xml
+++ b/samples/SystemBarRight/res/values/config.xml
@@ -67,6 +67,10 @@
     <string name="config_notificationPanelViewMediator" translatable="false">
         com.android.systemui.car.notification.NotificationPanelViewMediator</string>
 
+    <!-- Specifies the component name of the home activity -->
+    <string name="config_homeComponentName" translatable="false">
+        com.android.car.carlauncher/.CarLauncher</string>
+
     <string name="config_appGridComponentName" translatable="false">
         com.android.car.carlauncher/.AppGridActivity</string>
 
diff --git a/samples/SystemBarRight/res/xml/car_sysui_overlays.xml b/samples/SystemBarRight/res/xml/car_sysui_overlays.xml
index 70b660df..1af1f11e 100644
--- a/samples/SystemBarRight/res/xml/car_sysui_overlays.xml
+++ b/samples/SystemBarRight/res/xml/car_sysui_overlays.xml
@@ -18,6 +18,10 @@
         target="string/config_appGridComponentName"
         value="@string/config_appGridComponentName" />
 
+    <item
+        target="string/config_homeComponentName"
+        value="@string/config_homeComponentName" />
+
     <item
         target="bool/config_enableTopSystemBar"
         value="@bool/config_enableTopSystemBar" />
diff --git a/src/com/android/systemui/CarSystemUIApplication.java b/src/com/android/systemui/CarSystemUIApplication.java
index 6139586c..56560846 100644
--- a/src/com/android/systemui/CarSystemUIApplication.java
+++ b/src/com/android/systemui/CarSystemUIApplication.java
@@ -26,7 +26,6 @@ import android.content.Context;
 import android.content.res.Configuration;
 import android.os.Bundle;
 import android.os.UserHandle;
-import android.view.ContextThemeWrapper;
 import android.view.Display;
 import android.view.WindowManager;
 
@@ -65,6 +64,12 @@ public class CarSystemUIApplication extends SystemUIApplication {
         }
     }
 
+    @Override
+    public void onConfigurationChanged(@NonNull Configuration newConfig) {
+        Token.applyOemTokenStyle(this);
+        super.onConfigurationChanged(newConfig);
+    }
+
     @Override
     protected boolean shouldStartSystemUserServices() {
         if (mIsVisibleBackgroundUserSysUI) {
@@ -88,29 +93,45 @@ public class CarSystemUIApplication extends SystemUIApplication {
 
     @Override
     public void attachBaseContext(Context base) {
-        Context context = Token.createOemStyledContext(base);
-        context.getTheme().applyStyle(R.style.CarSystemUIThemeOverlay, true);
-        super.attachBaseContext(context);
+        Token.applyOemTokenStyle(base);
+        base.getTheme().applyStyle(R.style.CarSystemUIThemeOverlay, true);
+        super.attachBaseContext(base);
     }
 
     @Override
+    @NonNull
     public Context createContextAsUser(UserHandle user, @CreatePackageOptions int flags) {
         Context context = super.createContextAsUser(user, flags);
-        return new ContextThemeWrapper(context, this.getTheme());
+        context.getTheme().setTo(getTheme());
+        context.getTheme().rebase();
+        return context;
     }
 
     @Override
     @NonNull
     public Context createWindowContext(@WindowManager.LayoutParams.WindowType int type,
-        @Nullable Bundle options) {
+            @Nullable Bundle options) {
         Context context = super.createWindowContext(type, options);
-        return new ContextThemeWrapper(context, this.getTheme());
+        context.getTheme().setTo(getTheme());
+        context.getTheme().rebase();
+        return context;
+    }
+
+    @Override
+    @NonNull
+    public Context createWindowContext(@NonNull Display display, int type,
+            @Nullable Bundle options) {
+        Context context = super.createWindowContext(display, type, options);
+        context.getTheme().setTo(getTheme());
+        context.getTheme().rebase();
+        return context;
     }
 
     @Override
     public Context createConfigurationContext(Configuration overrideConfiguration) {
         Context context = super.createConfigurationContext(overrideConfiguration);
-        return new ContextThemeWrapper(context, this.getTheme());
+        context.getTheme().setTo(getTheme());
+        context.getTheme().rebase();
+        return context;
     }
-
 }
diff --git a/src/com/android/systemui/CarSystemUIBinder.java b/src/com/android/systemui/CarSystemUIBinder.java
index dd649228..41683d76 100644
--- a/src/com/android/systemui/CarSystemUIBinder.java
+++ b/src/com/android/systemui/CarSystemUIBinder.java
@@ -16,6 +16,7 @@
 
 package com.android.systemui;
 
+import com.android.systemui.car.debug.CarSystemUIDebugModule;
 import com.android.systemui.car.keyguard.CarKeyguardModule;
 import com.android.systemui.car.notification.CarNotificationModule;
 import com.android.systemui.car.qc.QuickControlsModule;
@@ -34,6 +35,7 @@ import dagger.Module;
 @Module(includes = {RecentsModule.class, CentralSurfacesDependenciesModule.class,
         NotificationsModule.class, NotificationRowModule.class, CarKeyguardModule.class,
         OverlayWindowModule.class, CarNotificationModule.class, QuickControlsModule.class,
-        QuickControlsEntryPointsModule.class, CarSystemBarModule.class, EventHandlerModule.class})
+        QuickControlsEntryPointsModule.class, CarSystemBarModule.class, EventHandlerModule.class,
+        CarSystemUIDebugModule.class})
 public abstract class CarSystemUIBinder {
 }
diff --git a/src/com/android/systemui/CarSystemUICoreStartableModule.kt b/src/com/android/systemui/CarSystemUICoreStartableModule.kt
index 40df7e3d..098671d8 100644
--- a/src/com/android/systemui/CarSystemUICoreStartableModule.kt
+++ b/src/com/android/systemui/CarSystemUICoreStartableModule.kt
@@ -19,7 +19,6 @@ package com.android.systemui
 import com.android.keyguard.KeyguardBiometricLockoutLogger
 import com.android.systemui.car.input.DisplayInputSinkController
 import com.android.systemui.car.toast.CarToastUI
-import com.android.systemui.car.voicerecognition.ConnectedDeviceVoiceRecognitionNotifier
 import com.android.systemui.car.window.SystemUIOverlayWindowManager
 import com.android.systemui.car.wm.activity.window.ActivityWindowManager
 import com.android.systemui.car.wm.cluster.ClusterDisplayController
@@ -70,14 +69,6 @@ abstract class CarSystemUICoreStartableModule {
     @ClassKey(DisplayInputSinkController::class)
     abstract fun bindDisplayInputSinkController(service: DisplayInputSinkController): CoreStartable
 
-    /** Inject into ConnectedDeviceVoiceRecognitionNotifier.  */
-    @Binds
-    @IntoMap
-    @ClassKey(ConnectedDeviceVoiceRecognitionNotifier::class)
-    abstract fun bindConnectedDeviceVoiceRecognitionNotifier(
-            service: ConnectedDeviceVoiceRecognitionNotifier
-    ): CoreStartable
-
     /** Inject into KeyguardBiometricLockoutLogger.  */
     @Binds
     @IntoMap
diff --git a/src/com/android/systemui/CarSystemUIInitializer.java b/src/com/android/systemui/CarSystemUIInitializer.java
index c7258a6f..fd7523c9 100644
--- a/src/com/android/systemui/CarSystemUIInitializer.java
+++ b/src/com/android/systemui/CarSystemUIInitializer.java
@@ -58,6 +58,7 @@ public class CarSystemUIInitializer extends SystemUIInitializer {
 
     private void initWmComponents(CarWMComponent carWm) {
         carWm.getDisplaySystemBarsController();
+        carWm.getAutoCaptionPerDisplayInitializer();
         if (Process.myUserHandle().isSystem()) {
             carWm.getCarSystemUIProxy();
             carWm.getRemoteCarTaskViewTransitions();
diff --git a/src/com/android/systemui/CarSystemUIModule.java b/src/com/android/systemui/CarSystemUIModule.java
index f4768186..b18f52b2 100644
--- a/src/com/android/systemui/CarSystemUIModule.java
+++ b/src/com/android/systemui/CarSystemUIModule.java
@@ -23,6 +23,7 @@ import android.content.Context;
 import android.hardware.SensorPrivacyManager;
 import android.window.DisplayAreaOrganizer;
 
+import com.android.car.datasubscription.DataSubscriptionMessageCreator;
 import com.android.keyguard.KeyguardViewController;
 import com.android.keyguard.dagger.KeyguardDisplayModule;
 import com.android.systemui.accessibility.AccessibilityModule;
@@ -30,6 +31,7 @@ import com.android.systemui.accessibility.data.repository.AccessibilityRepositor
 import com.android.systemui.biometrics.dagger.BiometricsModule;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarDeviceProvisionedControllerImpl;
+import com.android.systemui.car.decor.CarPolicyModule;
 import com.android.systemui.car.decor.CarPrivacyChipDecorProviderFactory;
 import com.android.systemui.car.decor.CarPrivacyChipViewController;
 import com.android.systemui.car.displayconfig.ExternalDisplayController;
@@ -45,11 +47,15 @@ import com.android.systemui.dagger.GlobalRootComponent;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Main;
 import com.android.systemui.decor.PrivacyDotDecorProviderFactory;
+import com.android.systemui.display.dagger.SystemUIDisplaySubcomponent;
 import com.android.systemui.dock.DockManager;
 import com.android.systemui.dock.DockManagerImpl;
 import com.android.systemui.doze.DozeHost;
 import com.android.systemui.media.muteawait.MediaMuteAwaitConnectionCli;
 import com.android.systemui.media.nearby.NearbyMediaDevicesManager;
+import com.android.systemui.Flags;
+import com.android.systemui.minmode.MinModeManager;
+import com.android.systemui.minmode.MinModeManagerImpl;
 import com.android.systemui.navigationbar.NoopNavigationBarControllerModule;
 import com.android.systemui.navigationbar.gestural.GestureModule;
 import com.android.systemui.plugins.qs.QSFactory;
@@ -69,7 +75,6 @@ import com.android.systemui.statusbar.NotificationLockscreenUserManagerImpl;
 import com.android.systemui.statusbar.NotificationShadeWindowController;
 import com.android.systemui.statusbar.events.PrivacyDotViewController;
 import com.android.systemui.statusbar.notification.headsup.HeadsUpEmptyImplModule;
-import com.android.systemui.statusbar.policy.AospPolicyModule;
 import com.android.systemui.statusbar.policy.DeviceProvisionedController;
 import com.android.systemui.statusbar.policy.IndividualSensorPrivacyController;
 import com.android.systemui.statusbar.policy.IndividualSensorPrivacyControllerImpl;
@@ -84,18 +89,20 @@ import dagger.Module;
 import dagger.Provides;
 
 import java.util.concurrent.Executor;
+import java.util.Optional;
 
 import javax.inject.Named;
+import javax.inject.Provider;
 
 @Module(
         includes = {
                 AccessibilityModule.class,
                 AccessibilityRepositoryModule.class,
                 ActivityWindowModule.class,
-                AospPolicyModule.class,
                 BiometricsModule.class,
                 BrightnessSliderModule.class,
                 CarMultiUserUtilsModule.class,
+                CarPolicyModule.class,
                 CarVolumeModule.class,
                 ExternalDisplayController.StartableModule.class,
                 DriveModeModule.class,
@@ -115,6 +122,9 @@ import javax.inject.Named;
                 ShadeEmptyImplModule.class,
                 SysUIUnfoldStartableModule.class,
                 WindowRootViewBlurNotSupportedModule.class
+        },
+        subcomponents = {
+                SystemUIDisplaySubcomponent.class
         }
 )
 abstract class CarSystemUIModule {
@@ -209,4 +219,21 @@ abstract class CarSystemUIModule {
     @Binds
     abstract PrivacyDotDecorProviderFactory providePrivacyDotDecorProviderFactory(
             CarPrivacyChipDecorProviderFactory carPrivacyDotDecorProviderFactory);
+
+    @Provides
+    static DataSubscriptionMessageCreator bindDataSubscriptionMessageCreator(
+            Context context) {
+        return new DataSubscriptionMessageCreator(context);
+    }
+
+    @Provides
+    @SysUISingleton
+    static Optional<MinModeManager> provideMinModeManager(
+            Provider<MinModeManagerImpl> minModeManagerProvider) {
+        if (Flags.enableMinmode()) {
+            return Optional.of(minModeManagerProvider.get());
+        } else {
+            return Optional.empty();
+        }
+    }
 }
diff --git a/src/com/android/systemui/car/debug/CarSystemUIDebugModule.java b/src/com/android/systemui/car/debug/CarSystemUIDebugModule.java
new file mode 100644
index 00000000..0d10857c
--- /dev/null
+++ b/src/com/android/systemui/car/debug/CarSystemUIDebugModule.java
@@ -0,0 +1,58 @@
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
+package com.android.systemui.car.debug;
+
+import com.android.systemui.CoreStartable;
+
+import dagger.Binds;
+import dagger.Module;
+import dagger.multibindings.ClassKey;
+import dagger.multibindings.IntoMap;
+import dagger.multibindings.IntoSet;
+import dagger.multibindings.Multibinds;
+
+import java.util.Set;
+
+/**
+ * Dagger injection module for debug constructs of CarSystemUi.
+ */
+@Module
+public abstract class CarSystemUIDebugModule {
+    /** Inject CarSystemUIShellCommandRegisterer as a CoreStartable */
+    @Binds
+    @IntoMap
+    @ClassKey(CarSystemUIShellCommandRegisterer.class)
+    public abstract CoreStartable bindCarSystemUIShellCommandRegisterer(
+            CarSystemUIShellCommandRegisterer registerer);
+
+
+    /** Empty set for CarSystemBarShellCommands. */
+    @Multibinds
+    abstract Set<CarSystemUIShellCommand> bindEmptyShellCommandSet();
+
+    /** Inject ScalableUIEventDispatcherCommand as a CarSystemUIShellCommand */
+    @Binds
+    @IntoSet
+    public abstract CarSystemUIShellCommand bindEventDispatcherShellCommand(
+            ScalableUIEventDispatcherCommand command);
+
+    /** Inject ScalableUIPanelStateDumpCommand as a CarSystemUIShellCommand */
+    @Binds
+    @IntoSet
+    public abstract CarSystemUIShellCommand bindPanelStateDumpCommand(
+            ScalableUIPanelStateDumpCommand command);
+}
diff --git a/src/com/android/systemui/car/debug/CarSystemUIShellCommand.java b/src/com/android/systemui/car/debug/CarSystemUIShellCommand.java
new file mode 100644
index 00000000..4e6f45a7
--- /dev/null
+++ b/src/com/android/systemui/car/debug/CarSystemUIShellCommand.java
@@ -0,0 +1,29 @@
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
+package com.android.systemui.car.debug;
+
+import com.android.systemui.statusbar.commandline.Command;
+
+/**
+ * Base class for a shell command to be registered for CarSystemUI debugging.
+ */
+public abstract class CarSystemUIShellCommand implements Command {
+    /**
+     * The command string to be registered as `adb shell cmd statusbar [commandName]`.
+     */
+    public abstract String getCommandName();
+}
diff --git a/src/com/android/systemui/car/debug/CarSystemUIShellCommandRegisterer.java b/src/com/android/systemui/car/debug/CarSystemUIShellCommandRegisterer.java
new file mode 100644
index 00000000..76e973a6
--- /dev/null
+++ b/src/com/android/systemui/car/debug/CarSystemUIShellCommandRegisterer.java
@@ -0,0 +1,60 @@
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
+package com.android.systemui.car.debug;
+
+import android.os.Build;
+
+import com.android.systemui.CoreStartable;
+import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.process.ProcessWrapper;
+import com.android.systemui.statusbar.commandline.CommandRegistry;
+
+import java.util.Set;
+
+import javax.inject.Inject;
+
+/**
+ * CoreStartable class to register all instances of {@link CarSystemUIShellCommand} as a
+ * statusbar shell command. This will only be registered on debug builds for the system user
+ * process of SystemUI.
+ */
+@SysUISingleton
+public class CarSystemUIShellCommandRegisterer implements CoreStartable {
+    private final CommandRegistry mCommandRegistry;
+    private final ProcessWrapper mProcessWrapper;
+    private final Set<CarSystemUIShellCommand> mCommands;
+
+    @Inject
+    public CarSystemUIShellCommandRegisterer(CommandRegistry commandRegistry,
+            ProcessWrapper processWrapper,
+            Set<CarSystemUIShellCommand> commands) {
+        mCommandRegistry = commandRegistry;
+        mProcessWrapper = processWrapper;
+        mCommands = commands;
+    }
+
+    @Override
+    public void start() {
+        if (!Build.IS_DEBUGGABLE || !mProcessWrapper.isSystemUser()) {
+            // only enable on debug builds for system user
+            return;
+        }
+
+        mCommands.forEach(command -> mCommandRegistry.registerCommand(command.getCommandName(),
+                ()-> command));
+    }
+}
diff --git a/src/com/android/systemui/car/debug/ScalableUIEventDispatcherCommand.java b/src/com/android/systemui/car/debug/ScalableUIEventDispatcherCommand.java
new file mode 100644
index 00000000..8fd16a11
--- /dev/null
+++ b/src/com/android/systemui/car/debug/ScalableUIEventDispatcherCommand.java
@@ -0,0 +1,67 @@
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
+package com.android.systemui.car.debug;
+
+import com.android.car.scalableui.model.Event;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
+import com.android.systemui.dagger.SysUISingleton;
+
+import java.io.PrintWriter;
+import java.util.List;
+
+import javax.inject.Inject;
+
+/**
+ * Shell command to inject ScalableUI events into the system.
+ * Usage: adb shell cmd statusbar carsysui-dispatch-event [eventId] [tokens]
+ */
+@SysUISingleton
+public class ScalableUIEventDispatcherCommand extends CarSystemUIShellCommand {
+    private final EventDispatcher mEventDispatcher;
+
+    @Inject
+    public ScalableUIEventDispatcherCommand(EventDispatcher eventDispatcher) {
+        mEventDispatcher = eventDispatcher;
+    }
+
+    @Override
+    public String getCommandName() {
+        return "carsysui-dispatch-event";
+    }
+
+    @Override
+    public void execute(PrintWriter pw, List<String> args) {
+        if (args == null || args.isEmpty()) {
+            pw.println("Must specify eventId");
+            return;
+        }
+
+        String eventId = args.get(0);
+        Event.Builder event = new Event.Builder(eventId);
+        if (args.size() > 1) {
+            event.addTokensFromString(args.get(1));
+        }
+
+        mEventDispatcher.executeTransaction(event.build());
+    }
+
+    @Override
+    public void help(PrintWriter pw) {
+        pw.println("Usage: adb shell cmd statusbar " + getCommandName()
+                + " [eventId] [tokens]");
+    }
+}
diff --git a/src/com/android/systemui/car/debug/ScalableUIPanelStateDumpCommand.java b/src/com/android/systemui/car/debug/ScalableUIPanelStateDumpCommand.java
new file mode 100644
index 00000000..4e2f8920
--- /dev/null
+++ b/src/com/android/systemui/car/debug/ScalableUIPanelStateDumpCommand.java
@@ -0,0 +1,53 @@
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
+package com.android.systemui.car.debug;
+
+import com.android.car.scalableui.manager.StateManager;
+import com.android.systemui.dagger.SysUISingleton;
+
+import java.io.PrintWriter;
+import java.util.List;
+
+import javax.inject.Inject;
+
+/**
+ * Shell command to dump all the current PanelStates of the system
+ * Usage: adb shell cmd statusbar carsysui-dump-panelstates
+ */
+@SysUISingleton
+public class ScalableUIPanelStateDumpCommand extends CarSystemUIShellCommand {
+
+    @Inject
+    public ScalableUIPanelStateDumpCommand() {
+    }
+
+    @Override
+    public String getCommandName() {
+        return "carsysui-dump-panelstates";
+    }
+
+    @Override
+    public void execute(PrintWriter pw, List<String> args) {
+        pw.println("Current Panel States:");
+        StateManager.dumpPanelStates(pw);
+    }
+
+    @Override
+    public void help(PrintWriter pw) {
+        pw.println("Usage: adb shell cmd statusbar " + getCommandName());
+    }
+}
diff --git a/src/com/android/systemui/car/decor/CarPolicyModule.java b/src/com/android/systemui/car/decor/CarPolicyModule.java
new file mode 100644
index 00000000..65cc481e
--- /dev/null
+++ b/src/com/android/systemui/car/decor/CarPolicyModule.java
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
+package com.android.systemui.car.decor;
+
+import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.statusbar.policy.BatteryController;
+
+import dagger.Module;
+import dagger.Provides;
+
+/**
+ * Override of AospPolicyModule
+ */
+@Module
+public class CarPolicyModule {
+    @Provides
+    @SysUISingleton
+    static BatteryController provideNoOpBatteryController() {
+        return new NoOpBatteryController();
+    }
+}
diff --git a/src/com/android/systemui/car/decor/CarPrivacyChipViewController.java b/src/com/android/systemui/car/decor/CarPrivacyChipViewController.java
index 87ba318f..9c031fe2 100644
--- a/src/com/android/systemui/car/decor/CarPrivacyChipViewController.java
+++ b/src/com/android/systemui/car/decor/CarPrivacyChipViewController.java
@@ -76,7 +76,7 @@ public class CarPrivacyChipViewController extends PrivacyDotViewControllerImpl
             CommandQueue commandQueue,
             SystemBarConfigs systemBarConfigs) {
         super(mainExecutor, scope, stateController, configurationController, contentInsetsProvider,
-                animationScheduler, null, uiExecutor);
+                animationScheduler, null, null, uiExecutor, context.getDisplayId(), null);
         commandQueue.addCallback(this);
         mAnimationHelper = new CarPrivacyChipAnimationHelper(context);
         mBarType = systemBarConfigs.getInsetsFrameProvider(context.getResources().getInteger(
diff --git a/src/com/android/systemui/car/decor/NoOpBatteryController.java b/src/com/android/systemui/car/decor/NoOpBatteryController.java
new file mode 100644
index 00000000..9aad3c54
--- /dev/null
+++ b/src/com/android/systemui/car/decor/NoOpBatteryController.java
@@ -0,0 +1,70 @@
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
+package com.android.systemui.car.decor;
+
+import android.os.Bundle;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import com.android.systemui.animation.Expandable;
+import com.android.systemui.statusbar.policy.BatteryController;
+
+import java.io.PrintWriter;
+
+public class NoOpBatteryController implements BatteryController {
+
+    @Override
+    public void dump(PrintWriter pw, String[] args) {
+        // no-op
+    }
+
+    @Override
+    public void setPowerSaveMode(boolean powerSave, @Nullable Expandable expandable) {
+        // no-op
+    }
+
+    @Override
+    public boolean isPluggedIn() {
+        return false;
+    }
+
+    @Override
+    public boolean isPowerSave() {
+        return false;
+    }
+
+    @Override
+    public boolean isAodPowerSave() {
+        return false;
+    }
+
+    @Override
+    public void dispatchDemoCommand(String command, Bundle args) {
+        // no-op
+    }
+
+    @Override
+    public void addCallback(@NonNull BatteryStateChangeCallback listener) {
+        // no-op
+    }
+
+    @Override
+    public void removeCallback(@NonNull BatteryStateChangeCallback listener) {
+        // no-op
+    }
+}
diff --git a/src/com/android/systemui/car/input/DisplayInputSink.java b/src/com/android/systemui/car/input/DisplayInputSink.java
index 7bbf4e0b..190af5bc 100644
--- a/src/com/android/systemui/car/input/DisplayInputSink.java
+++ b/src/com/android/systemui/car/input/DisplayInputSink.java
@@ -52,7 +52,6 @@ public final class DisplayInputSink {
 
     private BaseIWindow mFakeWindow;
     private InputTransferToken mFocusGrantToken;
-    private InputChannel mInputChannel;
     @VisibleForTesting
     InputEventReceiver mInputEventReceiver;
 
@@ -107,7 +106,7 @@ public final class DisplayInputSink {
         mFakeWindow = new BaseIWindow();
         mFakeWindow.setSession(mWindowSession);
         mFocusGrantToken = new InputTransferToken();
-        mInputChannel = new InputChannel();
+        InputChannel inputChannel = new InputChannel();
         try {
             mWindowSession.grantInputChannel(
                     mDisplayId,
@@ -121,12 +120,12 @@ public final class DisplayInputSink {
                     /* windowToken= */ null,
                     mFocusGrantToken,
                     "InputListener of " + mSurfaceControl.toString(),
-                    mInputChannel);
+                    inputChannel);
         } catch (RemoteException e) {
             e.rethrowFromSystemServer();
         }
 
-        mInputEventReceiver = new InputEventReceiver(mInputChannel, Looper.getMainLooper()) {
+        mInputEventReceiver = new InputEventReceiver(inputChannel, Looper.getMainLooper()) {
             @Override
             public void onInputEvent(InputEvent event) {
                 mCallback.onInputEvent(event);
@@ -140,10 +139,6 @@ public final class DisplayInputSink {
             mInputEventReceiver.dispose();
             mInputEventReceiver = null;
         }
-        if (mInputChannel != null) {
-            mInputChannel.dispose();
-            mInputChannel = null;
-        }
         try {
             if (mFakeWindow != null) {
                 mWindowSession.remove(mFakeWindow);
@@ -158,7 +153,7 @@ public final class DisplayInputSink {
         StringBuilder sb = new StringBuilder("name='DisplayInputSink-");
         sb.append(mDisplayId)
                 .append("', inputChannelToken=")
-                .append(mInputChannel != null ? mInputChannel.getToken() : "null");
+                .append(mInputEventReceiver != null ? mInputEventReceiver.getToken() : "null");
         return sb.toString();
     }
 
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardDisplayManager.java b/src/com/android/systemui/car/keyguard/CarKeyguardDisplayManager.java
index 252f9e52..ec945b99 100644
--- a/src/com/android/systemui/car/keyguard/CarKeyguardDisplayManager.java
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardDisplayManager.java
@@ -18,7 +18,7 @@ package com.android.systemui.car.keyguard;
 
 import android.content.Context;
 
-import com.android.keyguard.ConnectedDisplayKeyguardPresentation;
+import com.android.keyguard.ConnectedDisplayKeyguardPresentationFactory;
 import com.android.keyguard.KeyguardDisplayManager;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Application;
@@ -52,7 +52,7 @@ public class CarKeyguardDisplayManager extends KeyguardDisplayManager {
             Executor mainExecutor, Executor uiBgExecutor,
             KeyguardDisplayManager.DeviceStateHelper deviceStateHelper,
             KeyguardStateController keyguardStateController,
-            ConnectedDisplayKeyguardPresentation.Factory
+            ConnectedDisplayKeyguardPresentationFactory
                     connectedDisplayKeyguardPresentationFactory,
             Provider<ShadeDisplaysRepository> shadeDisplaysRepositoryProvider,
             @Application CoroutineScope appScope) {
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardModule.java b/src/com/android/systemui/car/keyguard/CarKeyguardModule.java
index 839af741..e2f04923 100644
--- a/src/com/android/systemui/car/keyguard/CarKeyguardModule.java
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardModule.java
@@ -25,7 +25,7 @@ import com.android.internal.jank.InteractionJankMonitor;
 import com.android.internal.logging.UiEventLogger;
 import com.android.internal.statusbar.IStatusBarService;
 import com.android.internal.widget.LockPatternUtils;
-import com.android.keyguard.ConnectedDisplayKeyguardPresentation;
+import com.android.keyguard.ConnectedDisplayKeyguardPresentationFactory;
 import com.android.keyguard.KeyguardDisplayManager;
 import com.android.keyguard.KeyguardUpdateMonitor;
 import com.android.keyguard.KeyguardViewController;
@@ -58,6 +58,7 @@ import com.android.systemui.keyguard.WindowManagerLockscreenVisibilityManager;
 import com.android.systemui.keyguard.WindowManagerOcclusionManager;
 import com.android.systemui.keyguard.dagger.GlanceableHubTransitionModule;
 import com.android.systemui.keyguard.dagger.KeyguardFaceAuthNotSupportedModule;
+import com.android.systemui.keyguard.dagger.KeyguardConnectedDisplaysModule;
 import com.android.systemui.keyguard.dagger.PrimaryBouncerTransitionModule;
 import com.android.systemui.keyguard.data.repository.KeyguardRepositoryModule;
 import com.android.systemui.keyguard.domain.interactor.KeyguardInteractor;
@@ -116,6 +117,7 @@ import javax.inject.Provider;
                 KeyguardRepositoryModule.class,
                 PrimaryBouncerTransitionModule.class,
                 StartKeyguardTransitionModule.class,
+                KeyguardConnectedDisplaysModule.class,
         })
 public interface CarKeyguardModule {
 
@@ -249,7 +251,7 @@ public interface CarKeyguardModule {
             @UiBackground Executor uiBgExecutor,
             KeyguardDisplayManager.DeviceStateHelper deviceStateHelper,
             KeyguardStateController keyguardStateController,
-            ConnectedDisplayKeyguardPresentation.Factory
+            ConnectedDisplayKeyguardPresentationFactory
                     connectedDisplayKeyguardPresentationFactory,
             Provider<ShadeDisplaysRepository> shadeDisplaysRepositoryProvider,
             @Application CoroutineScope appScope) {
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java b/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java
index 46311cbc..c3eb00d0 100644
--- a/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java
@@ -55,6 +55,7 @@ import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Main;
 import com.android.systemui.keyguard.KeyguardWmStateRefactor;
 import com.android.systemui.keyguard.ui.viewmodel.GlanceableHubToPrimaryBouncerTransitionViewModel;
+import com.android.systemui.keyguard.ui.viewmodel.PrimaryBouncerToDreamingTransitionViewModel;
 import com.android.systemui.keyguard.ui.viewmodel.PrimaryBouncerToGoneTransitionViewModel;
 import com.android.systemui.log.BouncerLogger;
 import com.android.systemui.settings.UserTracker;
@@ -73,6 +74,8 @@ import com.android.systemui.util.kotlin.JavaAdapter;
 
 import dagger.Lazy;
 
+import kotlinx.coroutines.CoroutineDispatcher;
+
 import java.util.Optional;
 
 import javax.inject.Inject;
@@ -103,6 +106,7 @@ public class CarKeyguardViewController extends OverlayViewController implements
     private final KeyguardBouncerViewModel mKeyguardBouncerViewModel;
     private final KeyguardBouncerComponent.Factory mKeyguardBouncerComponentFactory;
     private final BouncerView mBouncerView;
+    private final CoroutineDispatcher mMainDispatcher;
     private final PrimaryBouncerExpansionCallback mExpansionCallback =
             new PrimaryBouncerExpansionCallback() {
                 @Override
@@ -147,6 +151,8 @@ public class CarKeyguardViewController extends OverlayViewController implements
     private boolean mIsSleeping;
     private int mToastShowDurationMillisecond;
     private ViewGroup mKeyguardContainer;
+    private PrimaryBouncerToDreamingTransitionViewModel
+            mPrimaryBouncerToDreamingTransitionViewModel;
     private PrimaryBouncerToGoneTransitionViewModel mPrimaryBouncerToGoneTransitionViewModel;
     private GlanceableHubToPrimaryBouncerTransitionViewModel
             mGlanceableHubToPrimaryBouncerTransitionViewModel;
@@ -171,6 +177,7 @@ public class CarKeyguardViewController extends OverlayViewController implements
             PrimaryBouncerInteractor primaryBouncerInteractor,
             KeyguardSecurityModel keyguardSecurityModel,
             KeyguardBouncerViewModel keyguardBouncerViewModel,
+            PrimaryBouncerToDreamingTransitionViewModel primaryBouncerToDreamingTransitionViewModel,
             PrimaryBouncerToGoneTransitionViewModel primaryBouncerToGoneTransitionViewModel,
             GlanceableHubToPrimaryBouncerTransitionViewModel
                     glanceableHubToPrimaryBouncerTransitionViewModel,
@@ -182,6 +189,7 @@ public class CarKeyguardViewController extends OverlayViewController implements
             SelectedUserInteractor selectedUserInteractor,
             Optional<KeyguardSystemBarPresenter> keyguardSystemBarPresenter,
             StatusBarKeyguardViewManagerInteractor statusBarKeyguardViewManagerInteractor,
+            @Main CoroutineDispatcher mainDispatcher,
             JavaAdapter javaAdapter) {
         super(R.id.keyguard_stub, overlayViewGlobalStateController);
 
@@ -199,6 +207,7 @@ public class CarKeyguardViewController extends OverlayViewController implements
         mKeyguardSecurityModel = keyguardSecurityModel;
         mKeyguardBouncerViewModel = keyguardBouncerViewModel;
         mKeyguardBouncerComponentFactory = keyguardBouncerComponentFactory;
+        mPrimaryBouncerToDreamingTransitionViewModel = primaryBouncerToDreamingTransitionViewModel;
         mPrimaryBouncerToGoneTransitionViewModel = primaryBouncerToGoneTransitionViewModel;
         mGlanceableHubToPrimaryBouncerTransitionViewModel =
                 glanceableHubToPrimaryBouncerTransitionViewModel;
@@ -214,6 +223,7 @@ public class CarKeyguardViewController extends OverlayViewController implements
         mKeyguardSystemBarPresenter = keyguardSystemBarPresenter;
         mStatusBarKeyguardViewManagerInteractor = statusBarKeyguardViewManagerInteractor;
         mJavaAdapter = javaAdapter;
+        mMainDispatcher = mainDispatcher;
 
         if (KeyguardWmStateRefactor.isEnabled()) {
             // Show the keyguard views whenever we've told WM that the lockscreen is visible.
@@ -243,8 +253,9 @@ public class CarKeyguardViewController extends OverlayViewController implements
     @Override
     public void onFinishInflate() {
         mKeyguardContainer = getLayout().findViewById(R.id.keyguard_container);
-        KeyguardBouncerViewBinder.bind(mKeyguardContainer,
-                mKeyguardBouncerViewModel, mPrimaryBouncerToGoneTransitionViewModel,
+        KeyguardBouncerViewBinder.bind(mMainDispatcher, mKeyguardContainer,
+                mKeyguardBouncerViewModel, mPrimaryBouncerToDreamingTransitionViewModel,
+                mPrimaryBouncerToGoneTransitionViewModel,
                 mGlanceableHubToPrimaryBouncerTransitionViewModel,
                 mKeyguardBouncerComponentFactory,
                 mMessageAreaControllerFactory,
diff --git a/src/com/android/systemui/car/privacy/CameraPrivacyChip.java b/src/com/android/systemui/car/privacy/CameraPrivacyChip.java
index 9d23a91b..c514e86e 100644
--- a/src/com/android/systemui/car/privacy/CameraPrivacyChip.java
+++ b/src/com/android/systemui/car/privacy/CameraPrivacyChip.java
@@ -24,6 +24,7 @@ import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
 import com.android.systemui.R;
+import com.android.systemui.car.systembar.CameraPrivacyChipViewController;
 
 /** Car optimized Camera Privacy Chip View that is shown when camera is being used. */
 public class CameraPrivacyChip extends PrivacyChip {
@@ -73,4 +74,13 @@ public class CameraPrivacyChip extends PrivacyChip {
     protected String getSensorNameWithFirstLetterCapitalized() {
         return SENSOR_NAME_WITH_FIRST_LETTER_CAPITALIZED;
     }
+
+    @Override
+    public Class<?> getElementControllerClass() {
+        Class<?> superClass = super.getElementControllerClass();
+        if (superClass != null) {
+            return superClass;
+        }
+        return CameraPrivacyChipViewController.class;
+    }
 }
diff --git a/src/com/android/systemui/car/privacy/CameraQcPanel.java b/src/com/android/systemui/car/privacy/CameraQcPanel.java
index 8c97bfd3..84ab30ac 100644
--- a/src/com/android/systemui/car/privacy/CameraQcPanel.java
+++ b/src/com/android/systemui/car/privacy/CameraQcPanel.java
@@ -21,7 +21,6 @@ import androidx.annotation.DrawableRes;
 
 import com.android.car.qc.provider.BaseLocalQCProvider;
 import com.android.systemui.R;
-import com.android.systemui.car.systembar.CameraPrivacyChipViewController;
 
 import javax.inject.Inject;
 
@@ -35,11 +34,8 @@ public class CameraQcPanel extends SensorQcPanel {
     private static final String SENSOR_NAME_WITH_FIRST_LETTER_CAPITALIZED = "Camera";
 
     @Inject
-    public CameraQcPanel(Context context,
-            CameraPrivacyChipViewController cameraPrivacyChipViewController,
-            CameraPrivacyElementsProviderImpl cameraPrivacyElementsProvider) {
-        super(context, cameraPrivacyChipViewController,
-                cameraPrivacyElementsProvider);
+    public CameraQcPanel(Context context, CameraSensorPrivacyInfoProvider infoProvider) {
+        super(context, infoProvider);
     }
 
     @Override
diff --git a/src/com/android/systemui/car/privacy/CameraPrivacyElementsProviderImpl.java b/src/com/android/systemui/car/privacy/CameraSensorPrivacyInfoProvider.java
similarity index 67%
rename from src/com/android/systemui/car/privacy/CameraPrivacyElementsProviderImpl.java
rename to src/com/android/systemui/car/privacy/CameraSensorPrivacyInfoProvider.java
index eaa1774e..11fb692c 100644
--- a/src/com/android/systemui/car/privacy/CameraPrivacyElementsProviderImpl.java
+++ b/src/com/android/systemui/car/privacy/CameraSensorPrivacyInfoProvider.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2022 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,11 +13,13 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 package com.android.systemui.car.privacy;
 
+import static android.hardware.SensorPrivacyManager.Sensors.CAMERA;
+
 import android.content.Context;
 import android.content.pm.PackageManager;
+import android.hardware.SensorPrivacyManager;
 import android.permission.PermissionManager;
 
 import com.android.systemui.dagger.SysUISingleton;
@@ -30,25 +32,30 @@ import javax.inject.Inject;
 
 /**
  * Implementation of {@link
- * com.android.systemui.car.privacy.SensorQcPanel.SensorPrivacyElementsProvider} for camera.
+ * com.android.systemui.car.privacy.SensorPrivacyInfoProvider} for camera.
  */
 @SysUISingleton
-public class CameraPrivacyElementsProviderImpl extends PrivacyElementsProviderImpl {
-
+public class CameraSensorPrivacyInfoProvider extends SensorPrivacyInfoProvider {
     @Inject
-    public CameraPrivacyElementsProviderImpl(
-            Context context,
+    public CameraSensorPrivacyInfoProvider(Context context,
             PermissionManager permissionManager,
             PackageManager packageManager,
+            SensorPrivacyManager sensorPrivacyManager,
             PrivacyItemController privacyItemController,
             UserTracker userTracker,
             PrivacyLogger privacyLogger) {
-        super(context, permissionManager, packageManager, privacyItemController, userTracker,
-                privacyLogger);
+        super(context, permissionManager, packageManager, sensorPrivacyManager,
+                privacyItemController,
+                userTracker, privacyLogger);
     }
 
     @Override
     protected PrivacyType getProviderPrivacyType() {
         return PrivacyType.TYPE_CAMERA;
     }
+
+    @Override
+    protected int getChipSensor() {
+        return CAMERA;
+    }
 }
diff --git a/src/com/android/systemui/car/privacy/MicPrivacyChip.java b/src/com/android/systemui/car/privacy/MicPrivacyChip.java
index e30588ba..cb5b58fb 100644
--- a/src/com/android/systemui/car/privacy/MicPrivacyChip.java
+++ b/src/com/android/systemui/car/privacy/MicPrivacyChip.java
@@ -24,6 +24,7 @@ import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
 import com.android.systemui.R;
+import com.android.systemui.car.systembar.MicPrivacyChipViewController;
 
 /** Car optimized Mic Privacy Chip View that is shown when microphone is being used. */
 public class MicPrivacyChip extends PrivacyChip {
@@ -73,4 +74,13 @@ public class MicPrivacyChip extends PrivacyChip {
     protected String getSensorNameWithFirstLetterCapitalized() {
         return SENSOR_NAME_WITH_FIRST_LETTER_CAPITALIZED;
     }
+
+    @Override
+    public Class<?> getElementControllerClass() {
+        Class<?> superClass = super.getElementControllerClass();
+        if (superClass != null) {
+            return superClass;
+        }
+        return MicPrivacyChipViewController.class;
+    }
 }
diff --git a/src/com/android/systemui/car/privacy/MicQcPanel.java b/src/com/android/systemui/car/privacy/MicQcPanel.java
index 8bda3dcc..8d828dd7 100644
--- a/src/com/android/systemui/car/privacy/MicQcPanel.java
+++ b/src/com/android/systemui/car/privacy/MicQcPanel.java
@@ -21,7 +21,6 @@ import androidx.annotation.DrawableRes;
 
 import com.android.car.qc.provider.BaseLocalQCProvider;
 import com.android.systemui.R;
-import com.android.systemui.car.systembar.MicPrivacyChipViewController;
 
 import javax.inject.Inject;
 
@@ -35,10 +34,8 @@ public class MicQcPanel extends SensorQcPanel {
     private static final String SENSOR_NAME_WITH_FIRST_LETTER_CAPITALIZED = "Microphone";
 
     @Inject
-    public MicQcPanel(Context context,
-            MicPrivacyChipViewController micPrivacyChipViewController,
-            MicPrivacyElementsProviderImpl micPrivacyElementsProvider) {
-        super(context, micPrivacyChipViewController, micPrivacyElementsProvider);
+    public MicQcPanel(Context context, MicSensorPrivacyInfoProvider infoProvider) {
+        super(context, infoProvider);
     }
 
     @Override
diff --git a/src/com/android/systemui/car/privacy/MicPrivacyElementsProviderImpl.java b/src/com/android/systemui/car/privacy/MicSensorPrivacyInfoProvider.java
similarity index 67%
rename from src/com/android/systemui/car/privacy/MicPrivacyElementsProviderImpl.java
rename to src/com/android/systemui/car/privacy/MicSensorPrivacyInfoProvider.java
index 9a83ebdc..ea752fb3 100644
--- a/src/com/android/systemui/car/privacy/MicPrivacyElementsProviderImpl.java
+++ b/src/com/android/systemui/car/privacy/MicSensorPrivacyInfoProvider.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2021 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,11 +13,13 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 package com.android.systemui.car.privacy;
 
+import static android.hardware.SensorPrivacyManager.Sensors.MICROPHONE;
+
 import android.content.Context;
 import android.content.pm.PackageManager;
+import android.hardware.SensorPrivacyManager;
 import android.permission.PermissionManager;
 
 import com.android.systemui.dagger.SysUISingleton;
@@ -30,25 +32,30 @@ import javax.inject.Inject;
 
 /**
  * Implementation of {@link
- * com.android.systemui.car.privacy.SensorQcPanel.SensorPrivacyElementsProvider} for microphone.
+ * com.android.systemui.car.privacy.SensorPrivacyInfoProvider} for microphone.
  */
 @SysUISingleton
-public class MicPrivacyElementsProviderImpl extends PrivacyElementsProviderImpl {
-
+public class MicSensorPrivacyInfoProvider extends SensorPrivacyInfoProvider {
     @Inject
-    public MicPrivacyElementsProviderImpl(
-            Context context,
+    public MicSensorPrivacyInfoProvider(Context context,
             PermissionManager permissionManager,
             PackageManager packageManager,
+            SensorPrivacyManager sensorPrivacyManager,
             PrivacyItemController privacyItemController,
             UserTracker userTracker,
             PrivacyLogger privacyLogger) {
-        super(context, permissionManager, packageManager, privacyItemController, userTracker,
-                privacyLogger);
+        super(context, permissionManager, packageManager, sensorPrivacyManager,
+                privacyItemController,
+                userTracker, privacyLogger);
     }
 
     @Override
     protected PrivacyType getProviderPrivacyType() {
         return PrivacyType.TYPE_MICROPHONE;
     }
+
+    @Override
+    protected int getChipSensor() {
+        return MICROPHONE;
+    }
 }
diff --git a/src/com/android/systemui/car/privacy/PrivacyChip.java b/src/com/android/systemui/car/privacy/PrivacyChip.java
index 83d3383e..74b8071f 100644
--- a/src/com/android/systemui/car/privacy/PrivacyChip.java
+++ b/src/com/android/systemui/car/privacy/PrivacyChip.java
@@ -32,6 +32,9 @@ import androidx.constraintlayout.motion.widget.MotionLayout;
 
 import com.android.systemui.R;
 import com.android.systemui.car.statusicon.AnimatedStatusIcon;
+import com.android.systemui.car.systembar.element.CarSystemBarElement;
+import com.android.systemui.car.systembar.element.CarSystemBarElementFlags;
+import com.android.systemui.car.systembar.element.CarSystemBarElementResolver;
 
 import java.util.concurrent.Executors;
 import java.util.concurrent.ScheduledExecutorService;
@@ -60,10 +63,15 @@ import java.util.concurrent.TimeUnit;
  * <li>SENSOR_OFF - panel opened ->> SENSOR_OFF_SELECTED</li>
  * </ul>
  */
-public abstract class PrivacyChip extends MotionLayout implements AnimatedStatusIcon {
+public abstract class PrivacyChip extends MotionLayout implements AnimatedStatusIcon,
+        CarSystemBarElement {
     private static final boolean DEBUG = Build.IS_DEBUGGABLE;
     private static final String TAG = "PrivacyChip";
 
+    private final Class<?> mElementControllerClassAttr;
+    private final int mSystemBarDisableFlags;
+    private final int mSystemBarDisable2Flags;
+    private final boolean mDisableForLockTaskModeLocked;
     private final int mDelayPillToCircle;
     private final int mDelayToNoSensorUsage;
 
@@ -85,6 +93,18 @@ public abstract class PrivacyChip extends MotionLayout implements AnimatedStatus
             @Nullable AttributeSet attrs, int defStyleAttrs) {
         super(context, attrs, defStyleAttrs);
 
+        mElementControllerClassAttr =
+                CarSystemBarElementResolver.getElementControllerClassFromAttributes(context, attrs);
+        mSystemBarDisableFlags =
+                CarSystemBarElementFlags.getStatusBarManagerDisableFlagsFromAttributes(context,
+                        attrs);
+        mSystemBarDisable2Flags =
+                CarSystemBarElementFlags.getStatusBarManagerDisable2FlagsFromAttributes(context,
+                        attrs);
+        mDisableForLockTaskModeLocked =
+                CarSystemBarElementFlags.getDisableForLockTaskModeLockedFromAttributes(context,
+                        attrs);
+
         mDelayPillToCircle = getResources().getInteger(R.integer.privacy_chip_pill_to_circle_delay);
         mDelayToNoSensorUsage =
                 getResources().getInteger(R.integer.privacy_chip_no_sensor_usage_delay);
@@ -562,6 +582,29 @@ public abstract class PrivacyChip extends MotionLayout implements AnimatedStatus
         super.setTransition(transitionId);
     }
 
+    @Override
+    public Class<?> getElementControllerClass() {
+        if (mElementControllerClassAttr != null) {
+            return mElementControllerClassAttr;
+        }
+        return null;
+    }
+
+    @Override
+    public int getSystemBarDisableFlags() {
+        return mSystemBarDisableFlags;
+    }
+
+    @Override
+    public int getSystemBarDisable2Flags() {
+        return mSystemBarDisable2Flags;
+    }
+
+    @Override
+    public boolean disableForLockTaskModeLocked() {
+        return mDisableForLockTaskModeLocked;
+    }
+
     protected abstract @DrawableRes int getLightMutedIconResourceId();
 
     protected abstract @DrawableRes int getDarkMutedIconResourceId();
diff --git a/src/com/android/systemui/car/privacy/PrivacyElementsProviderImpl.java b/src/com/android/systemui/car/privacy/SensorPrivacyInfoProvider.java
similarity index 64%
rename from src/com/android/systemui/car/privacy/PrivacyElementsProviderImpl.java
rename to src/com/android/systemui/car/privacy/SensorPrivacyInfoProvider.java
index ccd23886..105912bc 100644
--- a/src/com/android/systemui/car/privacy/PrivacyElementsProviderImpl.java
+++ b/src/com/android/systemui/car/privacy/SensorPrivacyInfoProvider.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2022 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,9 +13,10 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 package com.android.systemui.car.privacy;
 
+import static android.hardware.SensorPrivacyManager.Sources.QS_TILE;
+import static android.hardware.SensorPrivacyManager.TOGGLE_TYPE_SOFTWARE;
 import static android.os.UserHandle.USER_SYSTEM;
 
 import android.Manifest;
@@ -23,16 +24,19 @@ import android.content.Context;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.UserInfo;
+import android.hardware.SensorPrivacyManager;
 import android.os.UserHandle;
 import android.os.UserManager;
 import android.permission.PermissionGroupUsage;
 import android.permission.PermissionManager;
 import android.util.Log;
 
+import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.annotation.WorkerThread;
 
 import com.android.systemui.privacy.PrivacyDialog;
+import com.android.systemui.privacy.PrivacyItem;
 import com.android.systemui.privacy.PrivacyItemController;
 import com.android.systemui.privacy.PrivacyType;
 import com.android.systemui.privacy.logging.PrivacyLogger;
@@ -46,12 +50,10 @@ import java.util.Optional;
 import java.util.stream.Collectors;
 
 /**
- * Implementation of {@link
- * com.android.systemui.car.privacy.SensorQcPanel.SensorPrivacyElementsProvider}
+ * Helper class to provide privacy elements and updates to sensor panels.
  */
-public abstract class PrivacyElementsProviderImpl implements
-        SensorQcPanel.SensorPrivacyElementsProvider {
-    private static final String TAG = "PrivacyElementsProviderImpl";
+public abstract class SensorPrivacyInfoProvider {
+    private static final String TAG = SensorPrivacyInfoProvider.class.getSimpleName();
     private static final String EMPTY_APP_NAME = "";
 
     private static final Map<String, PrivacyType> PERM_GROUP_TO_PRIVACY_TYPE_MAP =
@@ -59,31 +61,86 @@ public abstract class PrivacyElementsProviderImpl implements
                     Manifest.permission_group.MICROPHONE, PrivacyType.TYPE_MICROPHONE,
                     Manifest.permission_group.LOCATION, PrivacyType.TYPE_LOCATION);
 
-
+    private final Context mContext;
     private final PermissionManager mPermissionManager;
     private final UserTracker mUserTracker;
     private final PrivacyLogger mPrivacyLogger;
     private final PackageManager mPackageManager;
+    private final SensorPrivacyManager mSensorPrivacyManager;
     private final PrivacyItemController mPrivacyItemController;
     private final UserManager mUserManager;
+    private boolean mListenersRegistered;
+    @Nullable
+    private SensorInfoUpdateListener mSensorInfoUpdateListener;
 
-    public PrivacyElementsProviderImpl(
+    private final SensorPrivacyManager.OnSensorPrivacyChangedListener
+            mOnSensorPrivacyChangedListener =
+            new SensorPrivacyManager.OnSensorPrivacyChangedListener() {
+                @Override
+                public void onSensorPrivacyChanged(int sensor, boolean enabled) {
+                    // Since this is launched using a callback thread, its UI based elements need
+                    // to execute on main executor.
+                    mContext.getMainExecutor().execute(() -> {
+                        if (mSensorInfoUpdateListener != null) {
+                            mSensorInfoUpdateListener.onSensorPrivacyChanged();
+                        }
+                    });
+                }
+            };
+
+    private final PrivacyItemController.Callback mPicCallback =
+            new PrivacyItemController.Callback() {
+                @Override
+                public void onPrivacyItemsChanged(@NonNull List<PrivacyItem> privacyItems) {
+                    if (mSensorInfoUpdateListener != null) {
+                        mSensorInfoUpdateListener.onSensorPrivacyChanged();
+                    }
+                }
+            };
+
+    public SensorPrivacyInfoProvider(
             Context context,
             PermissionManager permissionManager,
             PackageManager packageManager,
+            SensorPrivacyManager sensorPrivacyManager,
             PrivacyItemController privacyItemController,
             UserTracker userTracker,
             PrivacyLogger privacyLogger) {
+        mContext = context;
         mPermissionManager = permissionManager;
         mPackageManager = packageManager;
+        mSensorPrivacyManager = sensorPrivacyManager;
         mPrivacyItemController = privacyItemController;
         mUserTracker = userTracker;
         mPrivacyLogger = privacyLogger;
-
         mUserManager = context.getSystemService(UserManager.class);
     }
 
-    @Override
+    /** Whether the sensor specified by {@link #getChipSensor} is enabled */
+    public boolean isSensorEnabled() {
+        // We need to negate return of isSensorPrivacyEnabled since when it is {@code true}, it
+        // means the sensor (microphone/camera) has been toggled off
+        return !mSensorPrivacyManager.isSensorPrivacyEnabled(/* toggleType= */ TOGGLE_TYPE_SOFTWARE,
+                /* sensor= */ getChipSensor());
+    }
+
+    /** Toggle the sensor specified by {@link #getChipSensor} */
+    public void toggleSensor() {
+        mSensorPrivacyManager.setSensorPrivacy(/* source= */ QS_TILE, /* sensor= */ getChipSensor(),
+                /* enable= */ isSensorEnabled(), mUserTracker.getUserId());
+    }
+
+    /** Set the {@link SensorInfoUpdateListener} for this provider */
+    public void setSensorInfoUpdateListener(@Nullable SensorInfoUpdateListener listener) {
+        mSensorInfoUpdateListener = listener;
+        if (listener != null) {
+            registerListeners();
+        } else {
+            unregisterListeners();
+        }
+    }
+
+    /** Obtain privacy elements for the privacy type of {@link #getProviderPrivacyType} */
     public List<PrivacyDialog.PrivacyElement> getPrivacyElements() {
         List<PrivacyDialog.PrivacyElement> elements = filterAndSort(createPrivacyElements());
         mPrivacyLogger.logShowDialogContents(elements);
@@ -92,6 +149,30 @@ public abstract class PrivacyElementsProviderImpl implements
 
     protected abstract PrivacyType getProviderPrivacyType();
 
+    protected abstract @SensorPrivacyManager.Sensors.Sensor int getChipSensor();
+
+    private void registerListeners() {
+        if (mListenersRegistered) {
+            return;
+        }
+        mListenersRegistered = true;
+        mPrivacyItemController.addCallback(mPicCallback);
+        mSensorPrivacyManager.removeSensorPrivacyListener(getChipSensor(),
+                mOnSensorPrivacyChangedListener);
+        mSensorPrivacyManager.addSensorPrivacyListener(getChipSensor(),
+                mOnSensorPrivacyChangedListener);
+    }
+
+    private void unregisterListeners() {
+        if (!mListenersRegistered) {
+            return;
+        }
+        mListenersRegistered = false;
+        mPrivacyItemController.removeCallback(mPicCallback);
+        mSensorPrivacyManager.removeSensorPrivacyListener(getChipSensor(),
+                mOnSensorPrivacyChangedListener);
+    }
+
     private List<PrivacyDialog.PrivacyElement> createPrivacyElements() {
         List<UserInfo> userInfos = mUserTracker.getUserProfiles();
         List<PermissionGroupUsage> permGroupUsages = getPermGroupUsages();
diff --git a/src/com/android/systemui/car/privacy/SensorQcPanel.java b/src/com/android/systemui/car/privacy/SensorQcPanel.java
index e6ad955b..d23981a7 100644
--- a/src/com/android/systemui/car/privacy/SensorQcPanel.java
+++ b/src/com/android/systemui/car/privacy/SensorQcPanel.java
@@ -61,15 +61,11 @@ public abstract class SensorQcPanel extends BaseLocalQCProvider
     protected Icon mSensorOffIcon;
     protected String mSensorOffTitleText;
     protected String mSensorSubtitleText;
+    private SensorPrivacyInfoProvider mSensorInfoProvider;
 
-    private SensorPrivacyElementsProvider mSensorPrivacyElementsProvider;
-    private SensorInfoProvider mSensorInfoProvider;
-
-    public SensorQcPanel(Context context, SensorInfoProvider infoProvider,
-            SensorPrivacyElementsProvider elementsProvider) {
+    public SensorQcPanel(Context context, SensorPrivacyInfoProvider infoProvider) {
         super(context);
         mSensorInfoProvider = infoProvider;
-        mSensorPrivacyElementsProvider = elementsProvider;
         mPhoneCallTitle = context.getString(R.string.ongoing_privacy_dialog_phonecall);
         mSensorOnTitleText = context.getString(R.string.privacy_chip_use_sensor, getSensorName());
         mSensorOffTitleText = context.getString(R.string.privacy_chip_off_content,
@@ -82,15 +78,14 @@ public abstract class SensorQcPanel extends BaseLocalQCProvider
 
     @Override
     public QCItem getQCItem() {
-        if (mSensorInfoProvider == null || mSensorPrivacyElementsProvider == null) {
+        if (mSensorInfoProvider == null) {
             return null;
         }
 
         QCList.Builder listBuilder = new QCList.Builder();
         listBuilder.addRow(createSensorToggleRow(mSensorInfoProvider.isSensorEnabled()));
 
-        List<PrivacyDialog.PrivacyElement> elements =
-                mSensorPrivacyElementsProvider.getPrivacyElements();
+        List<PrivacyDialog.PrivacyElement> elements = mSensorInfoProvider.getPrivacyElements();
 
         List<PrivacyDialog.PrivacyElement> activeElements = elements.stream()
                 .filter(PrivacyDialog.PrivacyElement::getActive)
@@ -241,49 +236,10 @@ public abstract class SensorQcPanel extends BaseLocalQCProvider
         mSensorInfoProvider.setSensorInfoUpdateListener(null);
     }
 
-    /**
-     * A helper object that retrieves sensor
-     * {@link com.android.systemui.privacy.PrivacyDialog.PrivacyElement} list for
-     * {@link SensorQcPanel}
-     */
-    public interface SensorPrivacyElementsProvider {
-        /**
-         * @return A list of sensors
-         * {@link com.android.systemui.privacy.PrivacyDialog.PrivacyElement}
-         */
-        List<PrivacyDialog.PrivacyElement> getPrivacyElements();
-    }
-
-    /**
-     * A helper object that allows the {@link SensorQcPanel} to communicate with
-     * {@link android.hardware.SensorPrivacyManager}
-     */
-    public interface SensorInfoProvider {
-        /**
-         * @return {@code true} if sensor privacy is not enabled (e.g., microphone/camera is on)
-         */
-        boolean isSensorEnabled();
-
-        /**
-         * Toggles sensor privacy
-         */
-        void toggleSensor();
-
-        /**
-         * Informs {@link SensorQcPanel} to update its state.
-         */
-        void setNotifyUpdateRunnable(Runnable runnable);
-
-        /**
-         * Set the listener to monitor the update.
-         */
-        void setSensorInfoUpdateListener(SensorInfoUpdateListener listener);
-    }
-
     private static class SensorToggleActionHandler implements QCItem.ActionHandler {
-        private final SensorInfoProvider mSensorInfoProvider;
+        private final SensorPrivacyInfoProvider mSensorInfoProvider;
 
-        SensorToggleActionHandler(SensorInfoProvider sensorInfoProvider) {
+        SensorToggleActionHandler(SensorPrivacyInfoProvider sensorInfoProvider) {
             this.mSensorInfoProvider = sensorInfoProvider;
         }
 
diff --git a/src/com/android/systemui/car/qc/DataSubscriptionController.java b/src/com/android/systemui/car/qc/DataSubscriptionController.java
deleted file mode 100644
index 24820f8f..00000000
--- a/src/com/android/systemui/car/qc/DataSubscriptionController.java
+++ /dev/null
@@ -1,630 +0,0 @@
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
-package com.android.systemui.car.qc;
-
-import static android.Manifest.permission.ACCESS_NETWORK_STATE;
-import static android.Manifest.permission.INTERNET;
-import static android.widget.PopupWindow.INPUT_METHOD_NOT_NEEDED;
-
-import android.annotation.Nullable;
-import android.annotation.SuppressLint;
-import android.app.ActivityManager;
-import android.app.ActivityTaskManager;
-import android.app.TaskStackListener;
-import android.car.drivingstate.CarUxRestrictions;
-import android.content.Context;
-import android.content.Intent;
-import android.content.SharedPreferences;
-import android.content.pm.ApplicationInfo;
-import android.content.pm.PackageInfo;
-import android.content.pm.PackageManager;
-import android.content.res.Resources;
-import android.net.ConnectivityManager;
-import android.net.Network;
-import android.net.NetworkCapabilities;
-import android.os.Build;
-import android.os.Handler;
-import android.text.TextUtils;
-import android.util.Log;
-import android.view.LayoutInflater;
-import android.view.MotionEvent;
-import android.view.View;
-import android.widget.Button;
-import android.widget.LinearLayout;
-import android.widget.PopupWindow;
-import android.widget.TextView;
-
-import androidx.annotation.NonNull;
-import androidx.annotation.VisibleForTesting;
-
-import com.android.car.datasubscription.DataSubscription;
-import com.android.car.datasubscription.DataSubscriptionStatus;
-import com.android.car.ui.utils.CarUxRestrictionsUtil;
-import com.android.systemui.R;
-import com.android.systemui.car.qc.DataSubscriptionStatsLogHelper.DataSubscriptionMessageType;
-import com.android.systemui.dagger.SysUISingleton;
-import com.android.systemui.dagger.qualifiers.Background;
-import com.android.systemui.dagger.qualifiers.Main;
-import com.android.systemui.settings.UserTracker;
-
-import java.time.LocalDate;
-import java.time.ZoneId;
-import java.time.format.DateTimeFormatter;
-import java.time.temporal.ChronoUnit;
-import java.util.Arrays;
-import java.util.HashSet;
-import java.util.List;
-import java.util.Set;
-import java.util.concurrent.CountDownLatch;
-import java.util.concurrent.Executor;
-import java.util.concurrent.TimeUnit;
-
-import javax.inject.Inject;
-
-/**
- * Controller to display the data subscription pop-up
- */
-@SysUISingleton
-public class DataSubscriptionController implements DataSubscription.DataSubscriptionChangeListener {
-    private static final boolean DEBUG = Build.IS_DEBUGGABLE;
-    private static final String TAG = DataSubscriptionController.class.toString();
-    private static final String DATA_SUBSCRIPTION_ACTION =
-            "android.intent.action.DATA_SUBSCRIPTION";
-    private static final String DATA_SUBSCRIPTION_SHARED_PREFERENCE_PATH =
-            "com.android.car.systemui.car.qc.DataSubscriptionController";
-    // Timeout for network callback in ms
-    private static final int CALLBACK_TIMEOUT_MS = 1000;
-    private final Context mContext;
-    private DataSubscription mSubscription;
-    private final UserTracker mUserTracker;
-    private PopupWindow mPopupWindow;
-    private final View mPopupView;
-    private Button mExplorationButton;
-    private final Intent mIntent;
-    private ConnectivityManager mConnectivityManager;
-    private DataSubscriptionNetworkCallback mNetworkCallback;
-    private final Handler mMainHandler;
-    private final Executor mBackGroundExecutor;
-    private Set<String> mActivitiesBlocklist;
-    private Set<String> mPackagesBlocklist;
-    private CountDownLatch mLatch;
-    private boolean mIsNetworkCallbackRegistered;
-    private final DataSubscriptionStatsLogHelper mDataSubscriptionStatsLogHelper;
-    private final TaskStackListener mTaskStackListener = new TaskStackListener() {
-        @SuppressLint("MissingPermission")
-        @Override
-        public void onTaskMovedToFront(ActivityManager.RunningTaskInfo taskInfo) {
-            if (mIsNetworkCallbackRegistered && mConnectivityManager != null) {
-                mConnectivityManager.unregisterNetworkCallback(mNetworkCallback);
-                mIsNetworkCallbackRegistered = false;
-            }
-
-            if (taskInfo.topActivity == null || mConnectivityManager == null) {
-                return;
-            }
-            mTopPackage = taskInfo.topActivity.getPackageName();
-            if (mPackagesBlocklist.contains(mTopPackage)) {
-                return;
-            }
-
-            mTopActivity = taskInfo.topActivity.flattenToString();
-            if (mActivitiesBlocklist.contains(mTopActivity)) {
-                return;
-            }
-
-            PackageInfo info;
-            int userId = mUserTracker.getUserId();
-            try {
-                info = mContext.getPackageManager().getPackageInfoAsUser(mTopPackage,
-                        PackageManager.GET_PERMISSIONS, userId);
-                if (info != null) {
-                    String[] permissions = info.requestedPermissions;
-                    boolean appReqInternet = Arrays.asList(permissions).contains(
-                            ACCESS_NETWORK_STATE)
-                            && Arrays.asList(permissions).contains(INTERNET);
-                    if (!appReqInternet) {
-                        mActivitiesBlocklist.add(mTopActivity);
-                        return;
-                    }
-                }
-
-                ApplicationInfo appInfo = mContext.getPackageManager().getApplicationInfoAsUser(
-                        mTopPackage, 0, mUserTracker.getUserId());
-                mTopLabel = appInfo.loadLabel(mContext.getPackageManager());
-                int uid = appInfo.uid;
-                mConnectivityManager.registerDefaultNetworkCallbackForUid(uid, mNetworkCallback,
-                        mMainHandler);
-                mIsNetworkCallbackRegistered = true;
-                // since we don't have the option of using the synchronous call of getting the
-                // default network by UID, we need to set a timeout period to make sure the network
-                // from the callback is updated correctly before deciding to display the message
-                //TODO: b/336869328 use the synchronous call to update network status
-                mLatch = new CountDownLatch(CALLBACK_TIMEOUT_MS);
-                mBackGroundExecutor.execute(() -> {
-                    try {
-                        mLatch.await(CALLBACK_TIMEOUT_MS, TimeUnit.MILLISECONDS);
-                    } catch (InterruptedException e) {
-                        Log.e(TAG, "error updating network callback" + e);
-                    } finally {
-                        if (mNetworkCallback.mNetwork == null) {
-                            mNetworkCapabilities = null;
-                            updateShouldDisplayReactiveMsg();
-                        }
-                    }
-                });
-            } catch (Exception e) {
-                Log.e(TAG, mTopPackage + " not found : " + e);
-            }
-        }
-    };
-
-    private final CarUxRestrictionsUtil.OnUxRestrictionsChangedListener
-            mUxRestrictionsChangedListener =
-            new CarUxRestrictionsUtil.OnUxRestrictionsChangedListener() {
-                @Override
-                public void onRestrictionsChanged(@NonNull CarUxRestrictions carUxRestrictions) {
-                    mIsDistractionOptimizationRequired =
-                            carUxRestrictions.isRequiresDistractionOptimization();
-                    if (mIsProactiveMsg) {
-                        if (mIsDistractionOptimizationRequired
-                                && mPopupWindow != null
-                                && mPopupWindow.isShowing()) {
-                            mPopupWindow.dismiss();
-                            mDataSubscriptionStatsLogHelper.logSessionFinished();
-                        }
-                    } else {
-                        if (mIsDistractionOptimizationRequired && mPopupWindow != null) {
-                            mExplorationButton.setVisibility(View.GONE);
-
-                        } else {
-                            mExplorationButton.setVisibility(View.VISIBLE);
-                        }
-                        mPopupWindow.update();
-                    }
-                }
-            };
-
-    // Determines whether a proactive message was already displayed
-    private boolean mWasProactiveMsgDisplayed;
-    // Determines whether the current message being displayed is proactive or reactive
-    private boolean mIsProactiveMsg;
-    private boolean mIsDistractionOptimizationRequired;
-    private View mAnchorView;
-    private boolean mShouldDisplayProactiveMsg;
-
-    private final int mPopUpTimeOut;
-    private boolean mShouldDisplayReactiveMsg;
-    private String mTopActivity;
-    private String mTopPackage;
-    private CharSequence mTopLabel;
-    private NetworkCapabilities mNetworkCapabilities;
-    private boolean mIsUxRestrictionsListenerRegistered;
-    private SharedPreferences mSharedPreferences;
-    private SharedPreferences.Editor mEditor;
-    private int mCurrentInterval;
-    private int mCurrentCycle;
-    private int mCurrentActiveDays;
-
-    @VisibleForTesting
-    static final String KEY_PREV_POPUP_DATE =
-            "com.android.car.systemui.car.qc.PREV_DATE";
-    @VisibleForTesting
-    static final String KEY_PREV_POPUP_CYCLE =
-            "com.android.car.systemui.car.qc.PREV_CYCLE";
-    @VisibleForTesting
-    static final String KEY_PREV_POPUP_ACTIVE_DAYS =
-            "com.android.car.systemui.car.qc.PREV_ACTIVE_DAYS";
-    @VisibleForTesting
-    static final String KEY_PREV_POPUP_STATUS =
-            "com.android.car.systemui.car.qc.PREV_STATUS";
-
-    @SuppressLint("MissingPermission")
-    @Inject
-    public DataSubscriptionController(Context context,
-            UserTracker userTracker,
-            @Main Handler mainHandler,
-            @Background Executor backgroundExecutor,
-            DataSubscriptionStatsLogHelper dataSubscriptionStatsLogHelper) {
-        mContext = context;
-        mSubscription = new DataSubscription(context);
-        mUserTracker = userTracker;
-        mMainHandler = mainHandler;
-        mBackGroundExecutor = backgroundExecutor;
-        mDataSubscriptionStatsLogHelper = dataSubscriptionStatsLogHelper;
-        mIntent = new Intent(DATA_SUBSCRIPTION_ACTION);
-        mIntent.setPackage(mContext.getString(
-                R.string.connectivity_flow_app));
-        mIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-        LayoutInflater inflater = LayoutInflater.from(mContext);
-        mPopupView = inflater.inflate(R.layout.data_subscription_popup_window, null);
-        mPopUpTimeOut = mContext.getResources().getInteger(
-                R.integer.data_subscription_pop_up_timeout);
-        int width = LinearLayout.LayoutParams.WRAP_CONTENT;
-        int height = LinearLayout.LayoutParams.WRAP_CONTENT;
-        boolean focusable = true;
-        mPopupWindow = new PopupWindow(mPopupView, width, height, focusable);
-        mPopupWindow.setTouchModal(false);
-        mPopupWindow.setOutsideTouchable(true);
-        mPopupWindow.setInputMethodMode(INPUT_METHOD_NOT_NEEDED);
-        mPopupView.setOnTouchListener(new View.OnTouchListener() {
-            @Override
-            public boolean onTouch(View v, MotionEvent event) {
-                if (mPopupWindow != null) {
-                    mPopupWindow.dismiss();
-                    if (!mWasProactiveMsgDisplayed) {
-                        mWasProactiveMsgDisplayed = true;
-                    }
-                    mDataSubscriptionStatsLogHelper.logSessionFinished();
-                }
-                return true;
-            }
-        });
-
-        mExplorationButton = mPopupView.findViewById(
-                R.id.data_subscription_explore_options_button);
-        mExplorationButton.setOnClickListener(v -> {
-            mPopupWindow.dismiss();
-            mContext.startActivityAsUser(mIntent, mUserTracker.getUserHandle());
-            mDataSubscriptionStatsLogHelper.logButtonClicked();
-        });
-        mConnectivityManager = mContext.getSystemService(ConnectivityManager.class);
-        mNetworkCallback = new DataSubscriptionNetworkCallback();
-        mActivitiesBlocklist = new HashSet<>();
-        mPackagesBlocklist = new HashSet<>();
-
-        Resources res = mContext.getResources();
-        String[] blockActivities = res.getStringArray(
-                R.array.config_dataSubscriptionBlockedActivitiesList);
-        mActivitiesBlocklist.addAll(List.of(blockActivities));
-        String[] blockComponents = res.getStringArray(
-                R.array.config_dataSubscriptionBlockedPackagesList);
-        mPackagesBlocklist.addAll(List.of(blockComponents));
-        try {
-            ActivityTaskManager.getService().registerTaskStackListener(mTaskStackListener);
-        } catch (Exception e) {
-            Log.e(TAG, "error while registering TaskStackListener " + e);
-        }
-        mSharedPreferences = mContext.getSharedPreferences(
-                DATA_SUBSCRIPTION_SHARED_PREFERENCE_PATH, Context.MODE_PRIVATE);
-        mEditor = mSharedPreferences.edit();
-    }
-
-    void updateShouldDisplayProactiveMsg() {
-        if (mIsDistractionOptimizationRequired) {
-            if (mPopupWindow != null && mPopupWindow.isShowing()) {
-                mPopupWindow.dismiss();
-                mDataSubscriptionStatsLogHelper.logSessionFinished();
-            }
-        } else {
-            // Determines whether a proactive message should be displayed
-            mShouldDisplayProactiveMsg = !mWasProactiveMsgDisplayed
-                    && mSubscription.isDataSubscriptionInactive()
-                    && isValidTimeInterval()
-                    && isValidCycle()
-                    && isValidActiveDays();
-            if (mShouldDisplayProactiveMsg && mPopupWindow != null
-                    && !mPopupWindow.isShowing()) {
-                mIsProactiveMsg = true;
-                showPopUpWindow();
-                writeLatestPopupDate();
-                writeLatestPopupCycle();
-                writeLatestPopupActiveDays();
-            }
-        }
-    }
-
-    private void updateShouldDisplayReactiveMsg() {
-        if (mIsDistractionOptimizationRequired) {
-            mExplorationButton.setVisibility(View.GONE);
-
-        } else {
-            mExplorationButton.setVisibility(View.VISIBLE);
-        }
-        if (!mPopupWindow.isShowing()) {
-            mShouldDisplayReactiveMsg = ((mNetworkCapabilities == null
-                    || (!isSuspendedNetwork() && !isValidNetwork()))
-                    && mSubscription.isDataSubscriptionInactive());
-            if (mShouldDisplayReactiveMsg) {
-                mIsProactiveMsg = false;
-                showPopUpWindow();
-                mActivitiesBlocklist.add(mTopActivity);
-            } else {
-                if (mPopupWindow != null && mPopupWindow.isShowing()) {
-                    mPopupWindow.dismiss();
-                    mDataSubscriptionStatsLogHelper.logSessionFinished();
-                }
-            }
-        }
-    }
-
-    @VisibleForTesting
-    void showPopUpWindow() {
-        if (mAnchorView != null) {
-            mAnchorView.post(new Runnable() {
-                @Override
-                public void run() {
-                    TextView popUpPrompt = mPopupView.findViewById(R.id.popup_text_view);
-                    if (popUpPrompt != null) {
-                        if (mIsProactiveMsg) {
-                            popUpPrompt.setText(R.string.data_subscription_proactive_msg_prompt);
-                            mDataSubscriptionStatsLogHelper.logSessionStarted(
-                                    DataSubscriptionMessageType.PROACTIVE);
-                        } else {
-                            popUpPrompt.setText(getReactiveMsg());
-                            mDataSubscriptionStatsLogHelper.logSessionStarted(
-                                    DataSubscriptionMessageType.REACTIVE);
-                        }
-                    }
-                    int xOffsetInPx = mContext.getResources().getDimensionPixelSize(
-                            R.dimen.data_subscription_pop_up_horizontal_offset);
-                    int yOffsetInPx = mContext.getResources().getDimensionPixelSize(
-                            R.dimen.data_subscription_pop_up_vertical_offset);
-                    mPopupWindow.showAsDropDown(mAnchorView, -xOffsetInPx, yOffsetInPx);
-                    mAnchorView.getHandler().postDelayed(new Runnable() {
-
-                        public void run() {
-                            if (mPopupWindow.isShowing()) {
-                                mPopupWindow.dismiss();
-                                mWasProactiveMsgDisplayed = true;
-                                // after the proactive msg dismisses, it won't get displayed again
-                                // hence the msg from now on will just be reactive
-                                mIsProactiveMsg = false;
-                                mDataSubscriptionStatsLogHelper.logSessionFinished();
-                            }
-                        }
-                    }, mPopUpTimeOut);
-                }
-            });
-        }
-    }
-
-    /** Set the anchor view. If null, unregisters active data subscription listeners */
-    public void setAnchorView(@Nullable View view) {
-        mAnchorView = view;
-        if (mAnchorView != null) {
-            mSubscription.addDataSubscriptionListener(this);
-            updateCurrentStatus();
-            updateCurrentInterval();
-            updateCurrentCycle();
-            updateCurrentActiveDays();
-            updateShouldDisplayProactiveMsg();
-            if (!mIsUxRestrictionsListenerRegistered) {
-                CarUxRestrictionsUtil.getInstance(mContext).register(
-                        mUxRestrictionsChangedListener);
-                mIsUxRestrictionsListenerRegistered = true;
-            }
-        } else {
-            mSubscription.removeDataSubscriptionListener();
-            if (mIsUxRestrictionsListenerRegistered) {
-                CarUxRestrictionsUtil.getInstance(mContext).unregister(
-                        mUxRestrictionsChangedListener);
-                mIsUxRestrictionsListenerRegistered = false;
-            }
-        }
-    }
-
-    boolean isValidNetwork() {
-        return mNetworkCapabilities.hasCapability(
-                NetworkCapabilities.NET_CAPABILITY_VALIDATED);
-    }
-
-    boolean isSuspendedNetwork() {
-        return !mNetworkCapabilities.hasCapability(
-                NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED);
-    }
-
-    private CharSequence getReactiveMsg() {
-        return mContext.getString(
-                R.string.data_subscription_reactive_msg_prompt, mTopLabel.isEmpty()
-                ? mContext.getResources().getString(
-                        R.string.data_subscription_reactive_generic_app_label) :
-                        mTopLabel);
-
-    }
-
-    @Override
-    public void onChange(int value) {
-        updateCurrentStatus();
-        updateShouldDisplayProactiveMsg();
-    }
-
-    public class DataSubscriptionNetworkCallback extends ConnectivityManager.NetworkCallback {
-        Network mNetwork;
-
-        @Override
-        public void onAvailable(@NonNull Network network) {
-            if (DEBUG) {
-                Log.d(TAG, "onAvailable " + network);
-            }
-            mNetwork = network;
-            mLatch.countDown();
-        }
-
-        @Override
-        public void onCapabilitiesChanged(@NonNull Network network,
-                @NonNull NetworkCapabilities networkCapabilities) {
-            if (DEBUG) {
-                Log.d(TAG, "onCapabilitiesChanged " + network);
-            }
-            mNetwork = network;
-            mNetworkCapabilities = networkCapabilities;
-            updateShouldDisplayReactiveMsg();
-        }
-    }
-
-    private boolean isValidTimeInterval() {
-        return mCurrentInterval >= mContext.getResources().getInteger(
-                R.integer.data_subscription_pop_up_frequency);
-    }
-
-    private boolean isValidCycle() {
-        if (mCurrentCycle == 1) {
-            return true;
-        }
-        return mCurrentCycle <= mContext.getResources().getInteger(
-                R.integer.data_subscription_pop_up_startup_cycle_limit);
-    }
-
-    private boolean isValidActiveDays() {
-        if (mCurrentActiveDays == 1) {
-            return true;
-        }
-        return mCurrentActiveDays <= mContext.getResources().getInteger(
-                R.integer.data_subscription_pop_up_active_days_limit);
-    }
-
-    private void updateCurrentStatus() {
-        int prevStatus = mSharedPreferences.getInt(KEY_PREV_POPUP_STATUS, 0);
-        int currentStatus = mSubscription.getDataSubscriptionStatus();
-        if (prevStatus == DataSubscriptionStatus.INACTIVE && prevStatus != currentStatus) {
-            mEditor.clear();
-            mEditor.apply();
-        }
-        mEditor.putInt(KEY_PREV_POPUP_STATUS, currentStatus);
-        mEditor.apply();
-    }
-
-    private void updateCurrentInterval() {
-        mCurrentInterval = mContext.getResources().getInteger(
-                R.integer.data_subscription_pop_up_frequency);
-        String prevDate = mSharedPreferences.getString(KEY_PREV_POPUP_DATE, /* defValue=*/ "");
-        if (!TextUtils.isEmpty(prevDate)) {
-            mCurrentInterval = (int) ChronoUnit.DAYS.between(LocalDate.parse(prevDate),
-                    LocalDate.now(ZoneId.systemDefault()));
-        }
-    }
-
-    private void updateCurrentCycle() {
-        mCurrentCycle = mSharedPreferences.getInt(
-                KEY_PREV_POPUP_CYCLE, /* defValue=*/ 0);
-    }
-
-    private void updateCurrentActiveDays() {
-        mCurrentActiveDays = mSharedPreferences.getInt(
-                KEY_PREV_POPUP_ACTIVE_DAYS, /* defValue=*/ 0);
-    }
-
-    private void writeLatestPopupDate() {
-        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
-        LocalDate newDate = LocalDate.now(ZoneId.systemDefault());
-        String formattedNewDate = newDate.format(formatter);
-        mEditor.putString(KEY_PREV_POPUP_DATE, formattedNewDate);
-        mEditor.apply();
-    }
-
-    private void writeLatestPopupCycle() {
-        mEditor.putInt(KEY_PREV_POPUP_CYCLE, mSharedPreferences.getInt(
-                KEY_PREV_POPUP_CYCLE, /* defValue=*/ 1) + 1);
-        mEditor.apply();
-    }
-
-    private void writeLatestPopupActiveDays() {
-        mEditor.putInt(KEY_PREV_POPUP_ACTIVE_DAYS, mSharedPreferences.getInt(
-                KEY_PREV_POPUP_ACTIVE_DAYS, /* defValue=*/ 1) + 1);
-        mEditor.apply();
-    }
-
-    @VisibleForTesting
-    void setPopupWindow(PopupWindow popupWindow) {
-        mPopupWindow = popupWindow;
-    }
-
-    @VisibleForTesting
-    void setSubscription(DataSubscription dataSubscription) {
-        mSubscription = dataSubscription;
-    }
-
-    @VisibleForTesting
-    boolean getShouldDisplayProactiveMsg() {
-        return mShouldDisplayProactiveMsg;
-    }
-
-    @VisibleForTesting
-    void setPackagesBlocklist(Set<String> list) {
-        mPackagesBlocklist = list;
-    }
-
-    @VisibleForTesting
-    void setActivitiesBlocklist(Set<String> list) {
-        mActivitiesBlocklist = list;
-    }
-
-    @VisibleForTesting
-    void setConnectivityManager(ConnectivityManager connectivityManager) {
-        mConnectivityManager = connectivityManager;
-    }
-
-    @VisibleForTesting
-    TaskStackListener getTaskStackListener() {
-        return mTaskStackListener;
-    }
-
-    @VisibleForTesting
-    boolean getShouldDisplayReactiveMsg() {
-        return mShouldDisplayReactiveMsg;
-    }
-
-    @VisibleForTesting
-    void setNetworkCallback(DataSubscriptionNetworkCallback callback) {
-        mNetworkCallback = callback;
-    }
-
-    @VisibleForTesting
-    void setIsCallbackRegistered(boolean value) {
-        mIsNetworkCallbackRegistered = value;
-    }
-
-    @VisibleForTesting
-    void setIsProactiveMsg(boolean value) {
-        mIsProactiveMsg = value;
-    }
-
-    @VisibleForTesting
-    void setExplorationButton(Button button) {
-        mExplorationButton = button;
-    }
-
-    @VisibleForTesting
-    void setIsUxRestrictionsListenerRegistered(boolean value) {
-        mIsUxRestrictionsListenerRegistered = value;
-    }
-
-    @VisibleForTesting
-    void setSharedPreference(SharedPreferences sharedPreference) {
-        mSharedPreferences = sharedPreference;
-    }
-
-    @VisibleForTesting
-    void setCurrentInterval(int currentInterval) {
-        mCurrentInterval = currentInterval;
-    }
-
-    @VisibleForTesting
-    void setCurrentCycle(int cycle) {
-        mCurrentCycle = cycle;
-    }
-
-    @VisibleForTesting
-    void setCurrentActiveDays(int activeDays) {
-        mCurrentActiveDays = activeDays;
-    }
-
-    @VisibleForTesting
-    void setWasProactiveMsgDisplayed(boolean value) {
-        mWasProactiveMsgDisplayed = value;
-    }
-}
diff --git a/src/com/android/systemui/car/qc/DataSubscriptionStatsLogHelper.java b/src/com/android/systemui/car/qc/DataSubscriptionStatsLogHelper.java
index 16a23ebf..76ca09aa 100644
--- a/src/com/android/systemui/car/qc/DataSubscriptionStatsLogHelper.java
+++ b/src/com/android/systemui/car/qc/DataSubscriptionStatsLogHelper.java
@@ -136,7 +136,7 @@ public class DataSubscriptionStatsLogHelper {
      */
     private void writeDataSubscriptionEventReported(int eventType, int messageType) {
         if (Build.isDebuggable()) {
-            Log.v(TAG, "writing CAR_SYSTEM_UI_DATA_SUBSCRIPTION_EVENT_REPORTED. sessionId="
+            Log.d(TAG, "writing CAR_SYSTEM_UI_DATA_SUBSCRIPTION_EVENT_REPORTED. sessionId="
                     + mSessionId + ", eventType= " + eventType
                     + ", messageType=" + messageType);
         }
diff --git a/src/com/android/systemui/car/qc/DataSubscriptionToolkitView.java b/src/com/android/systemui/car/qc/DataSubscriptionToolkitView.java
new file mode 100644
index 00000000..9002e70a
--- /dev/null
+++ b/src/com/android/systemui/car/qc/DataSubscriptionToolkitView.java
@@ -0,0 +1,257 @@
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
+package com.android.systemui.car.qc;
+
+import static android.widget.PopupWindow.INPUT_METHOD_NOT_NEEDED;
+
+import static com.android.car.datasubscription.DataSubscription.DATA_SUBSCRIPTION_ACTION;
+
+import android.content.Context;
+import android.content.Intent;
+import android.view.LayoutInflater;
+import android.view.MotionEvent;
+import android.view.View;
+import android.widget.Button;
+import android.widget.LinearLayout;
+import android.widget.PopupWindow;
+import android.widget.TextView;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.VisibleForTesting;
+
+import com.android.car.datasubscription.DataSubscriptionController;
+import com.android.car.datasubscription.DataSubscriptionMessageCreator;
+import com.android.car.datasubscription.DataSubscriptionMessageEventListener;
+import com.android.car.datasubscription.DataSubscriptionViewActionListener;
+import com.android.systemui.R;
+import com.android.systemui.dagger.qualifiers.Main;
+import com.android.systemui.settings.UserTracker;
+
+import java.util.concurrent.Executor;
+
+import javax.inject.Inject;
+
+/**
+ * Create a toolkit view for data subscription controller
+ */
+public class DataSubscriptionToolkitView implements DataSubscriptionMessageEventListener {
+    private final DataSubscriptionStatsLogHelper mDataSubscriptionStatsLogHelper;
+    private final Context mContext;
+    @NonNull
+    private PopupWindow mPopupWindow;
+    private Button mExplorationButton;
+    private final View mPopupView;
+    private final Intent mIntent;
+    private final int mPopUpTimeOut;
+    private final UserTracker mUserTracker;
+    private View mAnchorView;
+    private boolean mIsProactiveMessage;
+    private DataSubscriptionViewActionListener mListener;
+    private TextView mPopUpPrompt;
+    private TextView mUxrPrompt;
+    private final Executor mMainExecutor;
+
+    private final UserTracker.Callback mUserChangedCallback =
+            new UserTracker.Callback() {
+                @Override
+                public void onUserChanged(int newUser, Context userContext) {
+                    mListener.setUserId(newUser);
+                }
+            };
+
+    @Inject
+    public DataSubscriptionToolkitView(
+            Context context,
+            UserTracker userTracker,
+            DataSubscriptionStatsLogHelper dataSubscriptionStatsLogHelper,
+            DataSubscriptionMessageCreator dataSubscriptionMessageCreator,
+            @Main Executor mainExecutor) {
+        mContext = context;
+        mUserTracker = userTracker;
+        mDataSubscriptionStatsLogHelper = dataSubscriptionStatsLogHelper;
+        mListener = new DataSubscriptionController(mContext, dataSubscriptionMessageCreator);
+        mMainExecutor = mainExecutor;
+        mIntent = new Intent(DATA_SUBSCRIPTION_ACTION);
+        mIntent.setPackage(mContext.getString(
+                R.string.connectivity_flow_app));
+        mIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+        LayoutInflater inflater = LayoutInflater.from(mContext);
+        mPopupView = inflater.inflate(R.layout.data_subscription_popup_window, null);
+        mPopUpTimeOut = mContext.getResources().getInteger(
+                R.integer.data_subscription_pop_up_timeout);
+        int width = LinearLayout.LayoutParams.WRAP_CONTENT;
+        int height = LinearLayout.LayoutParams.WRAP_CONTENT;
+        boolean focusable = true;
+        mPopupWindow = new PopupWindow(mPopupView, width, height, focusable);
+        mPopupWindow.setTouchModal(false);
+        mPopupWindow.setOutsideTouchable(true);
+        mPopupWindow.setInputMethodMode(INPUT_METHOD_NOT_NEEDED);
+        mPopupView.setOnTouchListener(new View.OnTouchListener() {
+            @Override
+            public boolean onTouch(View v, MotionEvent event) {
+                mPopupWindow.dismiss();
+                mDataSubscriptionStatsLogHelper.logSessionFinished();
+                return true;
+            }
+        });
+
+        mExplorationButton = mPopupView.findViewById(
+                R.id.data_subscription_explore_options_button);
+        mExplorationButton.setOnClickListener(v -> {
+            mPopupWindow.dismiss();
+            mContext.startActivityAsUser(mIntent, mUserTracker.getUserHandle());
+            mDataSubscriptionStatsLogHelper.logButtonClicked();
+        });
+        mPopUpPrompt = mPopupView.findViewById(R.id.popup_text_view);
+        mUxrPrompt = mPopupView.findViewById(R.id.popup_uxr_text_view);
+    }
+
+    @Override
+    public boolean onDataSubscriptionStatusChanged(boolean isUxrRequired,
+            String proactiveMessage, String uxrPrompt) {
+        if (isUxrRequired && mPopupWindow.isShowing()) {
+            mPopupWindow.dismiss();
+            mDataSubscriptionStatsLogHelper.logSessionFinished();
+            return false;
+        }
+        if (proactiveMessage != null && !proactiveMessage.isEmpty()
+                && !mPopupWindow.isShowing()) {
+            mIsProactiveMessage = true;
+            showPopUpWindow(proactiveMessage, uxrPrompt);
+            return true;
+        }
+        return false;
+    }
+    @Override
+    public boolean onAppForegrounded(boolean isUxrRequired, String reactiveMessage,
+            String uxrPrompt) {
+        if (isUxrRequired && mPopupWindow.isShowing()) {
+            mPopupWindow.dismiss();
+            mDataSubscriptionStatsLogHelper.logSessionFinished();
+            return false;
+        }
+        if (isUxrRequired) {
+            mExplorationButton.setVisibility(View.GONE);
+        } else {
+            mExplorationButton.setVisibility(View.VISIBLE);
+        }
+
+        if (reactiveMessage != null && !reactiveMessage.isEmpty()
+                && !mPopupWindow.isShowing()) {
+            mIsProactiveMessage = false;
+            showPopUpWindow(reactiveMessage, uxrPrompt);
+            return true;
+        }
+        return false;
+    }
+
+    @Override
+    public boolean onUxrChanged(boolean isUxrRequired, String uxrPrompt) {
+        if (mIsProactiveMessage && mPopupWindow.isShowing() && isUxrRequired) {
+            mPopupWindow.dismiss();
+            mDataSubscriptionStatsLogHelper.logSessionFinished();
+            return false;
+        }
+
+        if (!mIsProactiveMessage && mPopupWindow.isShowing()) {
+            if (isUxrRequired) {
+                mExplorationButton.setVisibility(View.GONE);
+            } else {
+                mExplorationButton.setVisibility(View.VISIBLE);
+            }
+            mUxrPrompt.setText(uxrPrompt);
+            mPopupWindow.update();
+            return true;
+        }
+        return false;
+    }
+
+    @VisibleForTesting
+    void showPopUpWindow(String message, String uxrPrompt) {
+        if (mAnchorView != null) {
+            mPopUpPrompt.setText(message);
+            mUxrPrompt.setText(uxrPrompt);
+            if (mIsProactiveMessage) {
+                mDataSubscriptionStatsLogHelper.logSessionStarted(
+                        DataSubscriptionStatsLogHelper.DataSubscriptionMessageType
+                                .PROACTIVE);
+            } else {
+                mDataSubscriptionStatsLogHelper.logSessionStarted(
+                        DataSubscriptionStatsLogHelper.DataSubscriptionMessageType
+                                .REACTIVE);
+            }
+            int xOffsetInPx = mContext.getResources().getDimensionPixelSize(
+                    R.dimen.data_subscription_pop_up_horizontal_offset);
+            int yOffsetInPx = mContext.getResources().getDimensionPixelSize(
+                    R.dimen.data_subscription_pop_up_vertical_offset);
+            mAnchorView.post(() -> {
+                mPopupWindow.showAsDropDown(mAnchorView, -xOffsetInPx, yOffsetInPx);
+                mAnchorView.getHandler().postDelayed(() -> {
+                    if (mPopupWindow.isShowing()) {
+                        // after the proactive message dismisses, it won't get displayed again
+                        // hence the message from now on will just be reactive
+                        mIsProactiveMessage = false;
+                        mPopupWindow.dismiss();
+                        mDataSubscriptionStatsLogHelper.logSessionFinished();
+                    }
+                }, mPopUpTimeOut);
+            });
+        }
+    }
+
+    /** Set the anchor view. If null, unregisters active data subscription listeners */
+    public void setAnchorView(View view) {
+        mAnchorView = view;
+        if (view != null) {
+            mListener.setDataSubscriptionMessageEventListener(this);
+            mListener.registerListeners();
+            mListener.setUserId(mUserTracker.getUserId());
+            mUserTracker.addCallback(mUserChangedCallback, mMainExecutor);
+        } else {
+            if (mListener != null) {
+                mListener.setDataSubscriptionMessageEventListener(null);
+                mListener.unregisterListeners();
+                mUserTracker.removeCallback(mUserChangedCallback);
+            }
+        }
+    }
+
+    @VisibleForTesting
+    void setPopupWindow(PopupWindow popupWindow) {
+        mPopupWindow = popupWindow;
+    }
+
+    @VisibleForTesting
+    void setIsProactiveMessage(boolean isProactiveMessage) {
+        mIsProactiveMessage = isProactiveMessage;
+    }
+
+    @VisibleForTesting
+    Button getExplorationButton() {
+        return mExplorationButton;
+    }
+
+    @VisibleForTesting
+    TextView getPopUpPrompt() {
+        return mPopUpPrompt;
+    }
+
+    @VisibleForTesting
+    void setDataSubscriptionViewActionListener(DataSubscriptionViewActionListener listener) {
+        mListener = listener;
+    }
+}
diff --git a/src/com/android/systemui/car/qc/ProfileSwitcher.java b/src/com/android/systemui/car/qc/ProfileSwitcher.java
index b45f377a..291b0663 100644
--- a/src/com/android/systemui/car/qc/ProfileSwitcher.java
+++ b/src/com/android/systemui/car/qc/ProfileSwitcher.java
@@ -248,7 +248,7 @@ public class ProfileSwitcher extends BaseLocalQCProvider {
             if (mPendingUserAdd) {
                 return;
             }
-            if (!mUserManager.canAddMoreUsers()) {
+            if (!mUserManager.canAddMoreUsers(UserManager.USER_TYPE_FULL_SECONDARY)) {
                 showMaxUserLimitReachedDialog();
             } else {
                 showConfirmAddUserDialog();
@@ -433,19 +433,25 @@ public class ProfileSwitcher extends BaseLocalQCProvider {
     }
 
     private int getMaxSupportedRealUsers() {
-        int maxSupportedUsers = UserManager.getMaxSupportedUsers();
-        if (UserManager.isHeadlessSystemUserMode()) {
-            maxSupportedUsers -= 1;
-        }
-        List<UserInfo> users = mUserManager.getAliveUsers();
-        // Count all users that are managed profiles of another user.
-        int managedProfilesCount = 0;
-        for (UserInfo user : users) {
-            if (user.isManagedProfile()) {
-                managedProfilesCount++;
+        if (!android.multiuser.Flags.consistentMaxUsers()
+                || !android.multiuser.Flags.maxUsersInCarIsForSecondary()) {
+            int maxSupportedUsers = UserManager.getMaxSupportedUsers();
+            if (UserManager.isHeadlessSystemUserMode()) {
+                maxSupportedUsers -= 1;
+            }
+            List<UserInfo> users = mUserManager.getAliveUsers();
+            // Count all users that are managed profiles of another user.
+            int managedProfilesCount = 0;
+            for (UserInfo user : users) {
+                if (user.isManagedProfile()) {
+                    managedProfilesCount++;
+                }
             }
+            return maxSupportedUsers - managedProfilesCount;
         }
-        return maxSupportedUsers - managedProfilesCount;
+        // "Real" users means secondary users and - for non-HSUM devices - the full system user.
+        return mUserManager.getCurrentAllowedNumberOfUsers(UserManager.USER_TYPE_FULL_SECONDARY)
+                + (UserManager.isHeadlessSystemUserMode() ? 0 : 1);
     }
 
     private void showMaxUserLimitReachedDialog() {
diff --git a/src/com/android/systemui/car/statusicon/StatusIconPanelViewController.java b/src/com/android/systemui/car/statusicon/StatusIconPanelViewController.java
index 543bb4e7..1f69d1f4 100644
--- a/src/com/android/systemui/car/statusicon/StatusIconPanelViewController.java
+++ b/src/com/android/systemui/car/statusicon/StatusIconPanelViewController.java
@@ -316,6 +316,7 @@ public class StatusIconPanelViewController extends ViewController<View> {
 
     /**
      * Create the PopupWindow panel and assign to {@link mPanel}.
+     *
      * @return true if the panel was created, false otherwise
      */
     private boolean createPanel() {
@@ -371,7 +372,7 @@ public class StatusIconPanelViewController extends ViewController<View> {
     private void dismissAllSystemDialogs() {
         Intent intent = new Intent(Intent.ACTION_CLOSE_SYSTEM_DIALOGS);
         intent.setIdentifier(mIdentifier);
-        mContext.sendBroadcastAsUser(intent, mUserTracker.getUserHandle());
+        mContext.getApplicationContext().sendBroadcastAsUser(intent, mUserTracker.getUserHandle());
     }
 
     private void registerFocusListener(boolean register) {
@@ -487,7 +488,8 @@ public class StatusIconPanelViewController extends ViewController<View> {
                 ConfigurationController configurationController,
                 CarDeviceProvisionedController deviceProvisionedController,
                 CarSystemBarElementInitializer elementInitializer) {
-            mContext = context;
+            mContext = context.createWindowContext(context.getDisplay(),
+                    WindowManager.LayoutParams.TYPE_SYSTEM_DIALOG, null);
             mUserTracker = userTracker;
             mBroadcastDispatcher = broadcastDispatcher;
             mConfigurationController = configurationController;
@@ -514,7 +516,10 @@ public class StatusIconPanelViewController extends ViewController<View> {
             return this;
         }
 
-        /** Set the panel's gravity - by default the gravity will be `Gravity.TOP | Gravity.START`*/
+        /**
+         * Set the panel's gravity - by default the gravity will be `Gravity.TOP | Gravity
+         * .START`
+         */
         public Builder setGravity(int gravity) {
             mGravity = gravity;
             return this;
@@ -550,8 +555,8 @@ public class StatusIconPanelViewController extends ViewController<View> {
          */
         public StatusIconPanelViewController build(View anchorView, @LayoutRes int layoutRes,
                 @DimenRes int widthRes) {
-            return new StatusIconPanelViewController(mContext, mUserTracker, mBroadcastDispatcher,
-                    mConfigurationController, mCarDeviceProvisionedController,
+            return new StatusIconPanelViewController(mContext, mUserTracker,
+                    mBroadcastDispatcher, mConfigurationController, mCarDeviceProvisionedController,
                     mCarSystemBarElementInitializer, anchorView, layoutRes, widthRes, mXOffset,
                     mYOffset, mGravity, mIsDisabledWhileDriving, mIsDisabledWhileUnprovisioned,
                     mShowAsDropDown);
diff --git a/src/com/android/systemui/car/statusicon/ui/SignalStatusIconController.java b/src/com/android/systemui/car/statusicon/ui/SignalStatusIconController.java
index 95b97758..dfe23247 100644
--- a/src/com/android/systemui/car/statusicon/ui/SignalStatusIconController.java
+++ b/src/com/android/systemui/car/statusicon/ui/SignalStatusIconController.java
@@ -25,7 +25,7 @@ import androidx.annotation.VisibleForTesting;
 import com.android.car.datasubscription.Flags;
 import com.android.settingslib.graph.SignalDrawable;
 import com.android.systemui.R;
-import com.android.systemui.car.qc.DataSubscriptionController;
+import com.android.systemui.car.qc.DataSubscriptionToolkitView;
 import com.android.systemui.car.statusicon.StatusIconView;
 import com.android.systemui.car.statusicon.StatusIconViewController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
@@ -52,7 +52,7 @@ public class SignalStatusIconController extends StatusIconViewController impleme
     private final Resources mResources;
     private final HotspotController mHotspotController;
     private final NetworkController mNetworkController;
-    private final DataSubscriptionController mDataSubscriptionController;
+    private final DataSubscriptionToolkitView mDataSubscriptionToolkitView;
     private SignalDrawable mMobileSignalIconDrawable;
     private Drawable mWifiSignalIconDrawable;
     private Drawable mHotSpotIconDrawable;
@@ -74,14 +74,13 @@ public class SignalStatusIconController extends StatusIconViewController impleme
             @Main Resources resources,
             NetworkController networkController,
             HotspotController hotspotController,
-            DataSubscriptionController dataSubscriptionController) {
+            DataSubscriptionToolkitView dataSubscriptionToolkitView) {
         super(view, disableController, stateController);
         mContext = context;
         mResources = resources;
         mHotspotController = hotspotController;
         mNetworkController = networkController;
-        mDataSubscriptionController = dataSubscriptionController;
-
+        mDataSubscriptionToolkitView = dataSubscriptionToolkitView;
         mMobileSignalIconDrawable = new SignalDrawable(mContext);
         mHotSpotIconDrawable = mResources.getDrawable(R.drawable.ic_hotspot, mContext.getTheme());
 
@@ -100,8 +99,9 @@ public class SignalStatusIconController extends StatusIconViewController impleme
         super.onViewAttached();
         mNetworkController.addCallback(this);
         mHotspotController.addCallback(this);
-        if (Flags.dataSubscriptionPopUp()) {
-            mDataSubscriptionController.setAnchorView(mView);
+        if (Flags.dataSubscriptionPopUp()
+                && mResources.getBoolean(R.bool.config_enableDataSubscriptionToolkit)) {
+            mDataSubscriptionToolkitView.setAnchorView(mView);
         }
     }
 
@@ -110,8 +110,9 @@ public class SignalStatusIconController extends StatusIconViewController impleme
         super.onViewDetached();
         mNetworkController.removeCallback(this);
         mHotspotController.removeCallback(this);
-        if (Flags.dataSubscriptionPopUp()) {
-            mDataSubscriptionController.setAnchorView(null);
+        if (Flags.dataSubscriptionPopUp()
+                && mResources.getBoolean(R.bool.config_enableDataSubscriptionToolkit)) {
+            mDataSubscriptionToolkitView.setAnchorView(null);
         }
     }
 
diff --git a/src/com/android/systemui/car/systembar/AaosStudioButtonController.java b/src/com/android/systemui/car/systembar/AaosStudioButtonController.java
new file mode 100644
index 00000000..d0465218
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/AaosStudioButtonController.java
@@ -0,0 +1,74 @@
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
+package com.android.systemui.car.systembar;
+
+import android.content.Context;
+import android.content.pm.PackageInfo;
+import android.content.pm.PackageManager;
+
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
+import com.android.systemui.settings.UserTracker;
+
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+/**
+ * A CarSystemBarElementController for handling AAOS Studio interactions.
+ */
+public class AaosStudioButtonController extends CarSystemBarButtonController  {
+
+    private static final String AAOS_STUDIO_PACKAGE_NAME = "com.android.aaos.studio";
+
+    private final Context mContext;
+
+    @AssistedInject
+    public AaosStudioButtonController(@Assisted CarSystemBarButton button,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController,
+            UserTracker userTracker, EventDispatcher eventDispatcher,
+            ButtonSelectionStateController buttonSelectionStateController) {
+        super(button, disableController, stateController, userTracker, eventDispatcher,
+                buttonSelectionStateController);
+        mContext = button.getContext();
+    }
+
+    @AssistedFactory
+    public interface Factory extends
+            CarSystemBarElementController.Factory<CarSystemBarButton,
+                    AaosStudioButtonController> {
+    }
+
+    @Override
+    protected boolean shouldBeVisible() {
+        return isPackageInstalled(mContext);
+    }
+
+    private boolean isPackageInstalled(Context context) {
+        PackageManager packageManager = context.getPackageManager();
+        try {
+            PackageInfo packageInfo = packageManager.getPackageInfo(AAOS_STUDIO_PACKAGE_NAME, 0);
+            return packageInfo != null;
+        } catch (PackageManager.NameNotFoundException e) {
+            return false; // Package not found
+        } catch (Exception e) {
+            return false;
+        }
+    }
+}
diff --git a/src/com/android/systemui/car/systembar/AssistantButton.java b/src/com/android/systemui/car/systembar/AssistantButton.java
index fcbea28a..40826064 100644
--- a/src/com/android/systemui/car/systembar/AssistantButton.java
+++ b/src/com/android/systemui/car/systembar/AssistantButton.java
@@ -75,6 +75,10 @@ public class AssistantButton extends CarSystemBarButton {
                     @Override
                     public void onSetUiHints(Bundle hints) {
                     }
+
+                    @Override
+                    public void onSetInvocationEffectEnabled(boolean enabled) {
+                    }
                 }
         );
     }
diff --git a/src/com/android/systemui/car/systembar/ButtonSelectionStateController.java b/src/com/android/systemui/car/systembar/ButtonSelectionStateController.java
index 299f57f7..afdd1fe7 100644
--- a/src/com/android/systemui/car/systembar/ButtonSelectionStateController.java
+++ b/src/com/android/systemui/car/systembar/ButtonSelectionStateController.java
@@ -398,6 +398,7 @@ public class ButtonSelectionStateController {
         return selectedButtons;
     }
 
+    @Nullable
     protected ComponentName getTopActivity(RootTaskInfo validTaskInfo) {
         // Window mode being WINDOW_MODE_MULTI_WINDOW implies TaskView might be visible on the
         // display. In such cases, topActivity reported by validTaskInfo will be the one hosted in
@@ -409,12 +410,12 @@ public class ButtonSelectionStateController {
                         ActivityTaskManager.getService().getRootTaskInfoOnDisplay(
                                 WINDOWING_MODE_FULLSCREEN, ACTIVITY_TYPE_UNDEFINED,
                                 validTaskInfo.displayId);
-                return rootTaskInfo == null ? null : rootTaskInfo.topActivity;
+                return SystemBarUtil.INSTANCE.getTaskComponentName(rootTaskInfo);
             } catch (RemoteException e) {
                 Log.e(TAG, "findSelectedButtons: Failed getting root task info", e);
             }
         } else {
-            return validTaskInfo.topActivity;
+            return SystemBarUtil.INSTANCE.getTaskComponentName(validTaskInfo);
         }
 
         return null;
diff --git a/src/com/android/systemui/car/systembar/CameraPrivacyChipViewController.java b/src/com/android/systemui/car/systembar/CameraPrivacyChipViewController.java
index e6b2c356..7cdff8a6 100644
--- a/src/com/android/systemui/car/systembar/CameraPrivacyChipViewController.java
+++ b/src/com/android/systemui/car/systembar/CameraPrivacyChipViewController.java
@@ -24,23 +24,44 @@ import android.hardware.SensorPrivacyManager;
 import androidx.annotation.IdRes;
 
 import com.android.systemui.R;
-import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.car.CarDeviceProvisionedController;
+import com.android.systemui.car.privacy.PrivacyChip;
+import com.android.systemui.car.statusicon.StatusIconPanelViewController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
 import com.android.systemui.privacy.PrivacyItemController;
 import com.android.systemui.privacy.PrivacyType;
 import com.android.systemui.settings.UserTracker;
 
-import javax.inject.Inject;
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+import javax.inject.Provider;
 
 /** Controls a Camera Privacy Chip view in system icons. */
-@SysUISingleton
 public class CameraPrivacyChipViewController extends PrivacyChipViewController {
 
-    @Inject
-    public CameraPrivacyChipViewController(Context context,
+    @AssistedInject
+    public CameraPrivacyChipViewController(@Assisted PrivacyChip view,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController,
+            Context context,
             PrivacyItemController privacyItemController,
             SensorPrivacyManager sensorPrivacyManager,
-            UserTracker userTracker) {
-        super(context, privacyItemController, sensorPrivacyManager, userTracker);
+            UserTracker userTracker,
+            CarDeviceProvisionedController carDeviceProvisionedController,
+            Provider<StatusIconPanelViewController.Builder> panelControllerBuilderProvider) {
+        super(view, disableController, stateController, context, privacyItemController,
+                sensorPrivacyManager, userTracker, carDeviceProvisionedController,
+                panelControllerBuilderProvider);
+    }
+
+    @AssistedFactory
+    public interface Factory extends
+            CarSystemBarElementController.Factory<PrivacyChip,
+                    CameraPrivacyChipViewController> {
     }
 
     @Override
@@ -57,4 +78,9 @@ public class CameraPrivacyChipViewController extends PrivacyChipViewController {
     protected @IdRes int getChipResourceId() {
         return R.id.camera_privacy_chip;
     }
+
+    @Override
+    protected int getPanelLayoutRes() {
+        return R.layout.qc_camera_panel;
+    }
 }
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java b/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java
index 989ad899..4df1c468 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java
@@ -89,7 +89,6 @@ import dagger.Lazy;
 
 import java.util.ArrayList;
 import java.util.HashMap;
-import java.util.Locale;
 import java.util.Map;
 import java.util.Set;
 
@@ -104,10 +103,6 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
 
     private static final String OVERLAY_FILTER_DATA_SCHEME = "package";
 
-    private static final int MAX_RETRIES_FOR_WINDOW_CONTEXT_UPDATE_CHECK = 3;
-
-    private static final long RETRY_DELAY_FOR_WINDOW_CONTEXT_UPDATE_CHECK = 500;
-
     private final Context mContext;
     private final CarSystemBarViewFactory mCarSystemBarViewFactory;
     private final SystemBarConfigs mSystemBarConfigs;
@@ -162,7 +157,6 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
     // it's open.
     private boolean mDeviceIsSetUpForUser = true;
     private boolean mIsUserSetupInProgress = false;
-    private int mWindowContextUpdateCheckRetryCount = 0;
 
     private AppearanceRegion[] mAppearanceRegions = new AppearanceRegion[0];
     @BarTransitions.TransitionMode
@@ -171,41 +165,6 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
     private int mSystemBarMode;
     private boolean mStatusBarTransientShown;
     private boolean mNavBarTransientShown;
-    private Handler mHandler;
-
-    private boolean mIsUiModeNight = false;
-
-    private Locale mCurrentLocale;
-
-    private final Runnable mWindowContextUpdateCheckRunnable = new Runnable() {
-        @Override
-        public void run() {
-            if (checkSystemBarWindowContextsAreUpdated()) {
-                // cache the current state
-                Map<Integer, Bundle> cachedSystemBarCurrentState = cacheSystemBarCurrentState();
-
-                resetSystemBarContent(/* isProvisionedStateChange= */ false);
-
-                // retrieve the previous state
-                restoreSystemBarSavedState(cachedSystemBarCurrentState);
-                mWindowContextUpdateCheckRetryCount = 0;
-            } else if (mWindowContextUpdateCheckRetryCount
-                    == MAX_RETRIES_FOR_WINDOW_CONTEXT_UPDATE_CHECK) {
-                resetSystemBarContext();
-
-                // cache the current state
-                Map<Integer, Bundle> cachedSystemBarCurrentState = cacheSystemBarCurrentState();
-
-                resetSystemBarContent(/* isProvisionedStateChange= */ false);
-
-                // retrieve the previous state
-                restoreSystemBarSavedState(cachedSystemBarCurrentState);
-            } else {
-                mWindowContextUpdateCheckRetryCount++;
-                mHandler.postDelayed(this, RETRY_DELAY_FOR_WINDOW_CONTEXT_UPDATE_CHECK);
-            }
-        }
-    };
 
     public CarSystemBarControllerImpl(Context context,
             UserTracker userTracker,
@@ -243,12 +202,9 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
         mIconPolicyLazy = iconPolicyLazy;
         mDisplayId = context.getDisplayId();
         mDisplayTracker = displayTracker;
-        mIsUiModeNight = mContext.getResources().getConfiguration().isNightModeActive();
-        mCurrentLocale = mContext.getResources().getConfiguration().getLocales().get(0);
         mConfigurationController = configurationController;
         mCarSystemBarRestartTracker = restartTracker;
         mDisplayCompatToolbarController = toolbarController;
-        mHandler = handler;
     }
 
     /**
@@ -429,37 +385,11 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
 
     @Override
     public void onConfigChanged(Configuration newConfig) {
-        Locale oldLocale = mCurrentLocale;
-        mCurrentLocale = newConfig.getLocales().get(0);
-
-        boolean isConfigNightMode = newConfig.isNightModeActive();
-        if (isConfigNightMode == mIsUiModeNight
-                && ((mCurrentLocale != null && mCurrentLocale.equals(oldLocale))
-                || mCurrentLocale == oldLocale)) {
-            return;
-        }
-
-        // Refresh UI on Night mode or system language changes.
-        if (isConfigNightMode != mIsUiModeNight) {
-            mIsUiModeNight = isConfigNightMode;
-        }
-
-        if (mWindowContextUpdateCheckRunnable != null) {
-            mHandler.removeCallbacks(mWindowContextUpdateCheckRunnable);
-            mWindowContextUpdateCheckRetryCount = 0;
-        }
-        mHandler.post(mWindowContextUpdateCheckRunnable);
-    }
-
-
-    private boolean checkSystemBarWindowContextsAreUpdated() {
-        return mSystemBarConfigs.getSystemBarSidesByZOrder().stream().allMatch(side -> {
-            Configuration windowConfig = mSystemBarConfigs.getWindowContextBySide(
-                    side).getResources().getConfiguration();
-            Locale locale = windowConfig.getLocales().get(0);
-            return windowConfig.isNightModeActive() == mIsUiModeNight && (
-                    (locale != null && locale.equals(mCurrentLocale)) || locale == mCurrentLocale);
-        });
+        // cache the current state
+        Map<Integer, Bundle> cachedSystemBarCurrentState = cacheSystemBarCurrentState();
+        resetSystemBarContent(/* isProvisionedStateChange= */ false);
+        // retrieve the previous state
+        restoreSystemBarSavedState(cachedSystemBarCurrentState);
     }
 
     private Map<Integer, Bundle> cacheSystemBarCurrentState() {
@@ -666,13 +596,6 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
         readConfigs();
     }
 
-    /**
-     * Invalidate SystemBar window context and recreates from application context.
-     */
-    void resetSystemBarContext() {
-        mSystemBarConfigs.resetSystemBarWindowContext();
-    }
-
     protected void updateKeyboardVisibility(boolean isKeyboardVisible) {
         mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(side -> {
             if (mHideBarForKeyboardMap.get(side)) {
@@ -825,6 +748,7 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
 
         if (!isProvisionedStateChange) {
             mCarSystemBarViewFactory.resetSystemBarViewCache();
+            mSystemBarConfigs.resetSystemBarConfigs();
         }
         clearSystemBarWindow(/* removeUnusedWindow= */ false);
 
@@ -938,11 +862,6 @@ public class CarSystemBarControllerImpl implements CarSystemBarController,
         });
     }
 
-    @VisibleForTesting
-    boolean getIsUiModeNight() {
-        return mIsUiModeNight;
-    }
-
     private void clearTransient() {
         if (mStatusBarTransientShown) {
             mStatusBarTransientShown = false;
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarModule.java b/src/com/android/systemui/car/systembar/CarSystemBarModule.java
index b91e5369..9ac5b031 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarModule.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarModule.java
@@ -16,10 +16,10 @@
 
 package com.android.systemui.car.systembar;
 
+import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
 import static com.android.systemui.car.systembar.CarSystemBarController.LEFT;
-import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
 import static com.android.systemui.car.systembar.CarSystemBarController.RIGHT;
-import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
+import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
 
 import android.annotation.Nullable;
 import android.content.Context;
@@ -143,8 +143,6 @@ public abstract class CarSystemBarModule {
             UserTracker userTracker,
             CarSystemBarViewFactory carSystemBarViewFactory,
             ButtonSelectionStateController buttonSelectionStateController,
-            Lazy<MicPrivacyChipViewController> micPrivacyChipViewControllerLazy,
-            Lazy<CameraPrivacyChipViewController> cameraPrivacyChipViewControllerLazy,
             ButtonRoleHolderController buttonRoleHolderController,
             SystemBarConfigs systemBarConfigs,
             Provider<StatusIconPanelViewController.Builder> panelControllerBuilderProvider,
@@ -276,7 +274,7 @@ public abstract class CarSystemBarModule {
     @IntoMap
     @IntKey(TOP)
     public abstract CarSystemBarViewControllerFactory bindTopCarSystemBarViewFactory(
-            CarTopSystemBarViewController.Factory factory);
+            CarSystemBarViewControllerImpl.Factory factory);
 
     /** Injects CarSystemBarViewController for @SystemBarSide RIGHT */
     @Binds
@@ -299,6 +297,20 @@ public abstract class CarSystemBarModule {
     public abstract CarSystemBarElementController.Factory bindCarSystemBarButtonControllerFactory(
             CarSystemBarButtonController.Factory factory);
 
+    /** Injects MicPrivacyChipViewController */
+    @Binds
+    @IntoMap
+    @ClassKey(MicPrivacyChipViewController.class)
+    public abstract CarSystemBarElementController.Factory bindMicChipViewControllerFactory(
+            MicPrivacyChipViewController.Factory factory);
+
+    /** Injects CameraPrivacyChipViewController */
+    @Binds
+    @IntoMap
+    @ClassKey(CameraPrivacyChipViewController.class)
+    public abstract CarSystemBarElementController.Factory bindCameraChipViewControllerFactory(
+            CameraPrivacyChipViewController.Factory factory);
+
     /** Injects NotificationButtonController */
     @Binds
     @IntoMap
@@ -342,6 +354,13 @@ public abstract class CarSystemBarModule {
     public abstract CarSystemBarElementController.Factory bindControlCenterButtonControllerFactory(
             ControlCenterButtonController.Factory factory);
 
+    /** Injects AaosStudioButtonController */
+    @Binds
+    @IntoMap
+    @ClassKey(AaosStudioButtonController.class)
+    public abstract CarSystemBarElementController.Factory bindAaosStudioButtonControllerFactory(
+            AaosStudioButtonController.Factory factory);
+
     /** Injects SystemBarConfigs */
     @SysUISingleton
     @Binds
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarViewControllerImpl.java b/src/com/android/systemui/car/systembar/CarSystemBarViewControllerImpl.java
index 6cd290aa..be223114 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarViewControllerImpl.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarViewControllerImpl.java
@@ -38,7 +38,6 @@ import com.android.systemui.car.window.OverlayVisibilityMediator;
 import com.android.systemui.settings.UserTracker;
 import com.android.systemui.util.ViewController;
 
-import dagger.Lazy;
 import dagger.assisted.Assisted;
 import dagger.assisted.AssistedFactory;
 import dagger.assisted.AssistedInject;
@@ -60,8 +59,6 @@ public class CarSystemBarViewControllerImpl
     private final CarSystemBarElementInitializer mCarSystemBarElementInitializer;
     private final SystemBarConfigs mSystemBarConfigs;
     private final ButtonRoleHolderController mButtonRoleHolderController;
-    private final Lazy<MicPrivacyChipViewController> mMicPrivacyChipViewControllerLazy;
-    private final Lazy<CameraPrivacyChipViewController> mCameraPrivacyChipViewControllerLazy;
     private final @SystemBarSide int mSide;
     private final OverlayVisibilityMediator mOverlayVisibilityMediator;
 
@@ -79,8 +76,6 @@ public class CarSystemBarViewControllerImpl
             CarSystemBarElementInitializer elementInitializer,
             SystemBarConfigs systemBarConfigs,
             ButtonRoleHolderController buttonRoleHolderController,
-            Lazy<CameraPrivacyChipViewController> cameraPrivacyChipViewControllerLazy,
-            Lazy<MicPrivacyChipViewController> micPrivacyChipViewControllerLazy,
             OverlayVisibilityMediator overlayVisibilityMediator,
             @Assisted @SystemBarSide int side,
             @Assisted ViewGroup systemBarView) {
@@ -91,8 +86,6 @@ public class CarSystemBarViewControllerImpl
         mCarSystemBarElementInitializer = elementInitializer;
         mSystemBarConfigs = systemBarConfigs;
         mButtonRoleHolderController = buttonRoleHolderController;
-        mCameraPrivacyChipViewControllerLazy = cameraPrivacyChipViewControllerLazy;
-        mMicPrivacyChipViewControllerLazy = micPrivacyChipViewControllerLazy;
         mSide = side;
         mOverlayVisibilityMediator = overlayVisibilityMediator;
 
@@ -207,15 +200,11 @@ public class CarSystemBarViewControllerImpl
         mSystemBarConfigs.insetSystemBar(mSide, mView);
 
         mButtonRoleHolderController.addAllButtonsWithRoleName(mView);
-        mMicPrivacyChipViewControllerLazy.get().addPrivacyChipView(mView);
-        mCameraPrivacyChipViewControllerLazy.get().addPrivacyChipView(mView);
     }
 
     @Override
     protected void onViewDetached() {
         mButtonRoleHolderController.removeAll();
-        mMicPrivacyChipViewControllerLazy.get().removeAll();
-        mCameraPrivacyChipViewControllerLazy.get().removeAll();
     }
 
     @AssistedFactory
diff --git a/src/com/android/systemui/car/systembar/CarTopSystemBarViewController.java b/src/com/android/systemui/car/systembar/CarTopSystemBarViewController.java
deleted file mode 100644
index 1b3ffb03..00000000
--- a/src/com/android/systemui/car/systembar/CarTopSystemBarViewController.java
+++ /dev/null
@@ -1,133 +0,0 @@
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
-package com.android.systemui.car.systembar;
-
-import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
-
-import android.annotation.LayoutRes;
-import android.content.Context;
-import android.view.Gravity;
-import android.view.View;
-import android.view.ViewGroup;
-
-import androidx.annotation.Nullable;
-
-import com.android.systemui.R;
-import com.android.systemui.car.CarDeviceProvisionedController;
-import com.android.systemui.car.statusicon.StatusIconPanelViewController;
-import com.android.systemui.car.systembar.CarSystemBarController.SystemBarSide;
-import com.android.systemui.car.systembar.element.CarSystemBarElementInitializer;
-import com.android.systemui.car.window.OverlayVisibilityMediator;
-import com.android.systemui.settings.UserTracker;
-
-import dagger.Lazy;
-import dagger.assisted.Assisted;
-import dagger.assisted.AssistedFactory;
-import dagger.assisted.AssistedInject;
-
-import javax.inject.Provider;
-
-/**
- * A controller for initializing the TOP CarSystemBarView.
- * TODO(b/373710798): remove privacy chip related code when they are migrated to flexible ui.
- */
-public class CarTopSystemBarViewController extends CarSystemBarViewControllerImpl {
-
-    private final CarDeviceProvisionedController mCarDeviceProvisionedController;
-    private final Provider<StatusIconPanelViewController.Builder> mPanelControllerBuilderProvider;
-
-    private int mPrivacyChipXOffset;
-    private StatusIconPanelViewController mMicPanelController;
-    private StatusIconPanelViewController mCameraPanelController;
-
-    @AssistedInject
-    public CarTopSystemBarViewController(Context context,
-            UserTracker userTracker,
-            CarSystemBarElementInitializer elementInitializer,
-            SystemBarConfigs systemBarConfigs,
-            ButtonRoleHolderController buttonRoleHolderController,
-            Lazy<CameraPrivacyChipViewController> cameraPrivacyChipViewControllerLazy,
-            Lazy<MicPrivacyChipViewController> micPrivacyChipViewControllerLazy,
-            CarDeviceProvisionedController deviceProvisionedController,
-            Provider<StatusIconPanelViewController.Builder> panelControllerBuilderProvider,
-            OverlayVisibilityMediator overlayVisibilityMediator,
-            @Assisted ViewGroup systemBarView) {
-        super(context,
-                userTracker,
-                elementInitializer,
-                systemBarConfigs,
-                buttonRoleHolderController,
-                cameraPrivacyChipViewControllerLazy,
-                micPrivacyChipViewControllerLazy,
-                overlayVisibilityMediator,
-                TOP,
-                systemBarView);
-        mCarDeviceProvisionedController = deviceProvisionedController;
-        mPanelControllerBuilderProvider = panelControllerBuilderProvider;
-
-        mPrivacyChipXOffset = -context.getResources()
-                .getDimensionPixelOffset(R.dimen.privacy_chip_horizontal_padding);
-    }
-
-    @Override
-    protected void onInit() {
-        super.onInit();
-
-        if (isDeviceSetupForUser()) {
-            // We do not want the privacy chips or the profile picker to be clickable in
-            // unprovisioned mode.
-            mMicPanelController = setupSensorQcPanel(mMicPanelController, R.id.mic_privacy_chip,
-                    R.layout.qc_mic_panel);
-            mCameraPanelController = setupSensorQcPanel(mCameraPanelController,
-                    R.id.camera_privacy_chip, R.layout.qc_camera_panel);
-        }
-    }
-
-    private StatusIconPanelViewController setupSensorQcPanel(
-            @Nullable StatusIconPanelViewController panelController, int chipId,
-            @LayoutRes int panelLayoutRes) {
-        if (panelController == null) {
-            View privacyChip = mView.findViewById(chipId);
-            if (privacyChip != null) {
-                panelController = mPanelControllerBuilderProvider.get()
-                        .setXOffset(mPrivacyChipXOffset)
-                        .setGravity(Gravity.TOP | Gravity.END)
-                        .build(privacyChip, panelLayoutRes, R.dimen.car_sensor_qc_panel_width);
-                panelController.init();
-            }
-        }
-        return panelController;
-    }
-
-    private boolean isDeviceSetupForUser() {
-        return mCarDeviceProvisionedController.isCurrentUserSetup()
-                && !mCarDeviceProvisionedController.isCurrentUserSetupInProgress();
-    }
-
-    @AssistedFactory
-    public interface Factory extends CarSystemBarViewControllerImpl.Factory {
-        @Override
-        default CarSystemBarViewControllerImpl create(@SystemBarSide int side, ViewGroup view) {
-            if (side == TOP) {
-                return create(view);
-            }
-            throw new UnsupportedOperationException("Side not supported");
-        }
-
-        /** Create instance of CarTopSystemBarViewController for system bar views */
-        CarTopSystemBarViewController create(ViewGroup view);
-    }
-}
diff --git a/src/com/android/systemui/car/systembar/DataSubscriptionUnseenIconController.java b/src/com/android/systemui/car/systembar/DataSubscriptionUnseenIconController.java
index e6f0100e..cd539e5a 100644
--- a/src/com/android/systemui/car/systembar/DataSubscriptionUnseenIconController.java
+++ b/src/com/android/systemui/car/systembar/DataSubscriptionUnseenIconController.java
@@ -48,7 +48,7 @@ public class DataSubscriptionUnseenIconController extends
     }
 
     @Override
-    public void onChange(int value) {
+    public void onStatusChanged(int value) {
         updateShouldDisplayUnseenIcon();
     }
 
diff --git a/src/com/android/systemui/car/systembar/MicPrivacyChipViewController.java b/src/com/android/systemui/car/systembar/MicPrivacyChipViewController.java
index 2de44c78..ee7868ab 100644
--- a/src/com/android/systemui/car/systembar/MicPrivacyChipViewController.java
+++ b/src/com/android/systemui/car/systembar/MicPrivacyChipViewController.java
@@ -24,23 +24,44 @@ import android.hardware.SensorPrivacyManager;
 import androidx.annotation.IdRes;
 
 import com.android.systemui.R;
-import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.car.CarDeviceProvisionedController;
+import com.android.systemui.car.privacy.PrivacyChip;
+import com.android.systemui.car.statusicon.StatusIconPanelViewController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
 import com.android.systemui.privacy.PrivacyItemController;
 import com.android.systemui.privacy.PrivacyType;
 import com.android.systemui.settings.UserTracker;
 
-import javax.inject.Inject;
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+import javax.inject.Provider;
 
 /** Controls a Mic Privacy Chip view in system icons. */
-@SysUISingleton
 public class MicPrivacyChipViewController extends PrivacyChipViewController {
 
-    @Inject
-    public MicPrivacyChipViewController(Context context,
+    @AssistedInject
+    public MicPrivacyChipViewController(@Assisted PrivacyChip view,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController,
+            Context context,
             PrivacyItemController privacyItemController,
             SensorPrivacyManager sensorPrivacyManager,
-            UserTracker userTracker) {
-        super(context, privacyItemController, sensorPrivacyManager, userTracker);
+            UserTracker userTracker,
+            CarDeviceProvisionedController carDeviceProvisionedController,
+            Provider<StatusIconPanelViewController.Builder> panelControllerBuilderProvider) {
+        super(view, disableController, stateController, context, privacyItemController,
+                sensorPrivacyManager, userTracker, carDeviceProvisionedController,
+                panelControllerBuilderProvider);
+    }
+
+    @AssistedFactory
+    public interface Factory extends
+            CarSystemBarElementController.Factory<PrivacyChip,
+                    MicPrivacyChipViewController> {
     }
 
     @Override
@@ -57,4 +78,9 @@ public class MicPrivacyChipViewController extends PrivacyChipViewController {
     protected @IdRes int getChipResourceId() {
         return R.id.mic_privacy_chip;
     }
+
+    @Override
+    protected int getPanelLayoutRes() {
+        return R.layout.qc_mic_panel;
+    }
 }
diff --git a/src/com/android/systemui/car/systembar/PrivacyChipViewController.java b/src/com/android/systemui/car/systembar/PrivacyChipViewController.java
index ee92a03d..002ab722 100644
--- a/src/com/android/systemui/car/systembar/PrivacyChipViewController.java
+++ b/src/com/android/systemui/car/systembar/PrivacyChipViewController.java
@@ -16,20 +16,24 @@
 
 package com.android.systemui.car.systembar;
 
-import static android.hardware.SensorPrivacyManager.Sources.QS_TILE;
 import static android.hardware.SensorPrivacyManager.TOGGLE_TYPE_SOFTWARE;
 
+import android.annotation.LayoutRes;
 import android.content.Context;
 import android.hardware.SensorPrivacyManager;
-import android.view.View;
+import android.view.Gravity;
 
 import androidx.annotation.IdRes;
 import androidx.annotation.NonNull;
+import androidx.annotation.VisibleForTesting;
 
+import com.android.systemui.R;
+import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.privacy.PrivacyChip;
-import com.android.systemui.car.privacy.SensorInfoUpdateListener;
-import com.android.systemui.car.privacy.SensorQcPanel;
-import com.android.systemui.privacy.OngoingPrivacyChip;
+import com.android.systemui.car.statusicon.StatusIconPanelViewController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
 import com.android.systemui.privacy.PrivacyItem;
 import com.android.systemui.privacy.PrivacyItemController;
 import com.android.systemui.privacy.PrivacyType;
@@ -38,17 +42,18 @@ import com.android.systemui.settings.UserTracker;
 import java.util.List;
 import java.util.Optional;
 
+import javax.inject.Provider;
+
 /** Controls a Privacy Chip view in system icons. */
-public abstract class PrivacyChipViewController implements SensorQcPanel.SensorInfoProvider {
+public abstract class PrivacyChipViewController extends CarSystemBarElementController<PrivacyChip> {
 
     private final PrivacyItemController mPrivacyItemController;
     private final SensorPrivacyManager mSensorPrivacyManager;
     private final UserTracker mUserTracker;
-
+    private final CarDeviceProvisionedController mCarDeviceProvisionedController;
+    private final Provider<StatusIconPanelViewController.Builder> mPanelControllerBuilderProvider;
     private Context mContext;
-    private PrivacyChip mPrivacyChip;
-    private Runnable mQsTileNotifyUpdateRunnable;
-    private SensorInfoUpdateListener mSensorInfoUpdateListener;
+
     private final SensorPrivacyManager.OnSensorPrivacyChangedListener
             mOnSensorPrivacyChangedListener = (sensor, sensorPrivacyEnabled) -> {
         if (mContext == null) {
@@ -59,18 +64,14 @@ public abstract class PrivacyChipViewController implements SensorQcPanel.SensorI
         mContext.getMainExecutor().execute(() -> {
             // We need to negate enabled since when it is {@code true} it means
             // the sensor (such as microphone or camera) has been toggled off.
-            mPrivacyChip.setSensorEnabled(/* enabled= */ !sensorPrivacyEnabled);
-            mQsTileNotifyUpdateRunnable.run();
-            if (mSensorInfoUpdateListener != null) {
-                mSensorInfoUpdateListener.onSensorPrivacyChanged();
-            }
+            mView.setSensorEnabled(/* enabled= */ !sensorPrivacyEnabled);
         });
     };
 
     private final UserTracker.Callback mUserSwitchCallback = new UserTracker.Callback() {
         @Override
         public void onUserChanged(int newUser, Context userContext) {
-            mPrivacyChip.setSensorEnabled(isSensorEnabled());
+            mView.setSensorEnabled(isSensorEnabled());
         }
     };
 
@@ -81,14 +82,10 @@ public abstract class PrivacyChipViewController implements SensorQcPanel.SensorI
             new PrivacyItemController.Callback() {
                 @Override
                 public void onPrivacyItemsChanged(@NonNull List<PrivacyItem> privacyItems) {
-                    if (mPrivacyChip == null) {
+                    if (mView == null) {
                         return;
                     }
 
-                    // Call QS Tile notify update runnable here so that QS tile can update when app
-                    // usage is added/removed/updated
-                    mQsTileNotifyUpdateRunnable.run();
-
                     boolean shouldShowPrivacyChip = isSensorPartOfPrivacyItems(privacyItems);
                     if (mIsPrivacyChipVisible == shouldShowPrivacyChip) {
                         return;
@@ -96,10 +93,6 @@ public abstract class PrivacyChipViewController implements SensorQcPanel.SensorI
 
                     mIsPrivacyChipVisible = shouldShowPrivacyChip;
                     setChipVisibility(shouldShowPrivacyChip);
-
-                    if (mSensorInfoUpdateListener != null) {
-                        mSensorInfoUpdateListener.onPrivacyItemsChanged();
-                    }
                 }
 
                 @Override
@@ -125,48 +118,40 @@ public abstract class PrivacyChipViewController implements SensorQcPanel.SensorI
                 }
             };
 
-    public PrivacyChipViewController(Context context, PrivacyItemController privacyItemController,
-            SensorPrivacyManager sensorPrivacyManager, UserTracker userTracker) {
+    public PrivacyChipViewController(PrivacyChip view,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController,
+            Context context,
+            PrivacyItemController privacyItemController,
+            SensorPrivacyManager sensorPrivacyManager, UserTracker userTracker,
+            CarDeviceProvisionedController carDeviceProvisionedController,
+            Provider<StatusIconPanelViewController.Builder> panelControllerBuilderProvider) {
+        super(view, disableController, stateController);
         mContext = context;
         mPrivacyItemController = privacyItemController;
         mSensorPrivacyManager = sensorPrivacyManager;
         mUserTracker = userTracker;
-
-        mQsTileNotifyUpdateRunnable = () -> {
-        };
+        mCarDeviceProvisionedController = carDeviceProvisionedController;
+        mPanelControllerBuilderProvider = panelControllerBuilderProvider;
         mIsPrivacyChipVisible = false;
     }
 
-    @Override
-    public boolean isSensorEnabled() {
+    @VisibleForTesting
+    boolean isSensorEnabled() {
         // We need to negate return of isSensorPrivacyEnabled since when it is {@code true} it
         // means the sensor (microphone/camera) has been toggled off
         return !mSensorPrivacyManager.isSensorPrivacyEnabled(/* toggleType= */ TOGGLE_TYPE_SOFTWARE,
                 /* sensor= */ getChipSensor());
     }
 
-    @Override
-    public void toggleSensor() {
-        mSensorPrivacyManager.setSensorPrivacy(/* source= */ QS_TILE, /* sensor= */ getChipSensor(),
-                /* enable= */ isSensorEnabled(), mUserTracker.getUserId());
-    }
-
-    @Override
-    public void setNotifyUpdateRunnable(Runnable runnable) {
-        mQsTileNotifyUpdateRunnable = runnable;
-    }
-
-    @Override
-    public void setSensorInfoUpdateListener(SensorInfoUpdateListener listener) {
-        mSensorInfoUpdateListener = listener;
-    }
-
     protected abstract @SensorPrivacyManager.Sensors.Sensor int getChipSensor();
 
     protected abstract PrivacyType getChipPrivacyType();
 
     protected abstract @IdRes int getChipResourceId();
 
+    protected abstract @LayoutRes int getPanelLayoutRes();
+
     private boolean isSensorPartOfPrivacyItems(@NonNull List<PrivacyItem> privacyItems) {
         Optional<PrivacyItem> optionalSensorPrivacyItem = privacyItems.stream()
                 .filter(privacyItem -> privacyItem.getPrivacyType()
@@ -175,17 +160,23 @@ public abstract class PrivacyChipViewController implements SensorQcPanel.SensorI
         return optionalSensorPrivacyItem.isPresent();
     }
 
-    /**
-     * Finds the {@link OngoingPrivacyChip} and sets relevant callbacks.
-     */
-    public void addPrivacyChipView(View view) {
-        if (mPrivacyChip != null) {
-            return;
+    @Override
+    protected void onInit() {
+        super.onInit();
+        if (isDeviceSetupForUser() && getPanelLayoutRes() != 0) {
+            StatusIconPanelViewController panelViewController =
+                    mPanelControllerBuilderProvider.get()
+                    .setXOffset(-mContext.getResources()
+                            .getDimensionPixelOffset(R.dimen.privacy_chip_horizontal_padding))
+                    .setGravity(Gravity.TOP | Gravity.END)
+                    .build(mView, getPanelLayoutRes(), R.dimen.car_sensor_qc_panel_width);
+            panelViewController.init();
         }
+    }
 
-        mPrivacyChip = view.findViewById(getChipResourceId());
-        if (mPrivacyChip == null) return;
-
+    @Override
+    protected void onViewAttached() {
+        super.onViewAttached();
         mAllIndicatorsEnabled = mPrivacyItemController.getAllIndicatorsAvailable();
         mMicCameraIndicatorsEnabled = mPrivacyItemController.getMicCameraAvailable();
         mPrivacyItemController.addCallback(mPicCallback);
@@ -198,37 +189,30 @@ public abstract class PrivacyChipViewController implements SensorQcPanel.SensorI
         // Since this can be launched using a callback thread, its UI based elements need
         // to execute on main executor.
         mContext.getMainExecutor().execute(() -> {
-            mPrivacyChip.setSensorEnabled(isSensorEnabled());
+            mView.setSensorEnabled(isSensorEnabled());
         });
         mUserTracker.removeCallback(mUserSwitchCallback);
         mUserTracker.addCallback(mUserSwitchCallback, mContext.getMainExecutor());
     }
 
-    /**
-     * Cleans up the controller and removes callbacks.
-     */
-    public void removeAll() {
+    @Override
+    protected void onViewDetached() {
+        super.onViewDetached();
         mIsPrivacyChipVisible = false;
         mPrivacyItemController.removeCallback(mPicCallback);
         mSensorPrivacyManager.removeSensorPrivacyListener(getChipSensor(),
                 mOnSensorPrivacyChangedListener);
         mUserTracker.removeCallback(mUserSwitchCallback);
-        mPrivacyChip = null;
-        mSensorInfoUpdateListener = null;
     }
 
     private void setChipVisibility(boolean chipVisible) {
-        if (mPrivacyChip == null) {
-            return;
-        }
-
         // Since this is launched using a callback thread, its UI based elements need
         // to execute on main executor.
         mContext.getMainExecutor().execute(() -> {
             if (chipVisible && getChipEnabled()) {
-                mPrivacyChip.animateIn();
+                mView.animateIn();
             } else {
-                mPrivacyChip.animateOut();
+                mView.animateOut();
             }
         });
     }
@@ -236,4 +220,9 @@ public abstract class PrivacyChipViewController implements SensorQcPanel.SensorI
     private boolean getChipEnabled() {
         return mMicCameraIndicatorsEnabled || mAllIndicatorsEnabled;
     }
+
+    private boolean isDeviceSetupForUser() {
+        return mCarDeviceProvisionedController.isCurrentUserSetup()
+                && !mCarDeviceProvisionedController.isCurrentUserSetupInProgress();
+    }
 }
diff --git a/src/com/android/systemui/car/systembar/SystemBarConfigs.java b/src/com/android/systemui/car/systembar/SystemBarConfigs.java
index 34395689..13a97175 100644
--- a/src/com/android/systemui/car/systembar/SystemBarConfigs.java
+++ b/src/com/android/systemui/car/systembar/SystemBarConfigs.java
@@ -41,16 +41,6 @@ public interface SystemBarConfigs {
      */
     void resetSystemBarConfigs();
 
-    /**
-     * Invalidates cached window context and creates a new window from application context.
-     *
-     * <p>
-     * This method should be called when the window context configurations are not in sync with
-     * application context configurations.
-     * </p>
-     */
-    void resetSystemBarWindowContext();
-
     /**
      * When creating system bars or overlay windows, use a WindowContext
      * for that particular window type to ensure proper display metrics.
diff --git a/src/com/android/systemui/car/systembar/SystemBarConfigsImpl.java b/src/com/android/systemui/car/systembar/SystemBarConfigsImpl.java
index 0303563f..8a201965 100644
--- a/src/com/android/systemui/car/systembar/SystemBarConfigsImpl.java
+++ b/src/com/android/systemui/car/systembar/SystemBarConfigsImpl.java
@@ -112,6 +112,7 @@ public class SystemBarConfigsImpl implements SystemBarConfigs {
     }
 
     private void init() {
+        mWindowContexts.clear();
         populateMaps();
         readConfigs();
 
@@ -140,14 +141,6 @@ public class SystemBarConfigsImpl implements SystemBarConfigs {
         init();
     }
 
-    @Override
-    public void resetSystemBarWindowContext() {
-        for (int windowType : mWindowContexts.keySet()) {
-            Context context = mContext.createWindowContext(windowType, /* options= */ null);
-            mWindowContexts.put(windowType, context);
-        }
-    }
-
     @Override
     public Context getWindowContextBySide(@SystemBarSide int side) {
         SystemBarConfig config = mSystemBarConfigMap.get(side);
@@ -158,6 +151,7 @@ public class SystemBarConfigsImpl implements SystemBarConfigs {
         if (mWindowContexts.containsKey(windowType)) {
             return mWindowContexts.get(windowType);
         }
+
         Context context = mContext.createWindowContext(windowType, /* options= */ null);
         mWindowContexts.put(windowType, context);
         return context;
diff --git a/src/com/android/systemui/car/systembar/SystemBarUtil.kt b/src/com/android/systemui/car/systembar/SystemBarUtil.kt
index de4e5f38..2299eaf1 100644
--- a/src/com/android/systemui/car/systembar/SystemBarUtil.kt
+++ b/src/com/android/systemui/car/systembar/SystemBarUtil.kt
@@ -5,7 +5,7 @@
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *
- *      http://www.apache.org/licenses/LICENSE-2.0
+ * http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
@@ -17,7 +17,9 @@
 package com.android.systemui.car.systembar
 
 import android.app.ActivityOptions
+import android.app.TaskInfo
 import android.car.settings.CarSettings.Secure.KEY_UNACCEPTED_TOS_DISABLED_APPS
+import android.content.ComponentName
 import android.content.Context
 import android.content.Intent
 import android.os.UserHandle
@@ -25,6 +27,7 @@ import android.provider.Settings
 import android.text.TextUtils
 import android.util.ArraySet
 import android.util.Log
+import androidx.annotation.Nullable
 import com.android.systemui.R
 import com.android.systemui.settings.UserTracker
 import java.net.URISyntaxException
@@ -36,6 +39,10 @@ object SystemBarUtil {
     const val SYSTEM_BAR_PERSISTENCY_CONFIG_IMMERSIVE = 1
     const val SYSTEM_BAR_PERSISTENCY_CONFIG_IMMERSIVE_WITH_NAV = 2
     const val SYSTEM_BAR_PERSISTENCY_CONFIG_BARPOLICY = 3
+    const val SYSTEM_BAR_SUW_PERSISTENCY_CONFIG_DISABLED = 0
+    const val SYSTEM_BAR_SUW_PERSISTENCY_CONFIG_IMMERSIVE = 1
+    const val SYSTEM_BAR_SUW_PERSISTENCY_CONFIG_IMMERSIVE_WITH_NAV = 2
+    const val SYSTEM_BAR_SUW_PERSISTENCY_CONFIG_IMMERSIVE_WITH_STATUS = 3
     const val VISIBLE_BAR_VISIBILITIES_TYPES_INDEX: Int = 0
     const val INVISIBLE_BAR_VISIBILITIES_TYPES_INDEX: Int = 1
 
@@ -113,4 +120,40 @@ object SystemBarUtil {
         }
         launchApp(context, tosIntent, userHandle)
     }
+
+    /**
+     * Helper method to safely extract the ComponentName from a [TaskInfo].
+     * It checks [TaskInfo.topActivity], [TaskInfo.realActivity],
+     * [TaskInfo.baseActivity], and finally the [TaskInfo.baseIntent]
+     * in that order to find a valid ComponentName.
+     *
+     * @param taskInfo The [TaskInfo] object.
+     * @return The ComponentName associated with the task, or null if it cannot be determined.
+     */
+    @Nullable
+    fun getTaskComponentName(@Nullable taskInfo: TaskInfo?): ComponentName? {
+        if (taskInfo == null) {
+            return null
+        }
+
+        // 1. Try topActivity
+        taskInfo.topActivity?.let { return it }
+
+        // 2. Try realActivity
+        taskInfo.realActivity?.let { return it }
+
+        // 3. Try baseActivity (the original attempt)
+        taskInfo.baseActivity?.let { return it }
+
+        // 4. Try baseIntent
+        taskInfo.baseIntent?.let { baseIntent ->
+            // First, try getting the component from the intent
+            baseIntent.component?.let { return it }
+            // If component is null, we can't get ComponentName from the intent
+        }
+
+        // If none of the above worked, return null
+        Log.w(TAG, "Could not determine ComponentName for taskId: ${taskInfo.taskId}")
+        return null
+    }
 }
diff --git a/src/com/android/systemui/car/systembar/element/CarSystemBarElementController.java b/src/com/android/systemui/car/systembar/element/CarSystemBarElementController.java
index 9dcb3a78..fd8bd9d7 100644
--- a/src/com/android/systemui/car/systembar/element/CarSystemBarElementController.java
+++ b/src/com/android/systemui/car/systembar/element/CarSystemBarElementController.java
@@ -97,7 +97,7 @@ public abstract class CarSystemBarElementController<V extends View & CarSystemBa
      */
     protected final void updateVisibility() {
         boolean visible = shouldBeVisible() && !mIsDisabledBySystemBarState;
-        mView.setVisibility(visible ? View.VISIBLE : View.INVISIBLE);
+        mView.setVisibility(visible ? View.VISIBLE : View.GONE);
     }
 
     /**
diff --git a/src/com/android/systemui/car/userpicker/DialogManager.java b/src/com/android/systemui/car/userpicker/DialogManager.java
index 1dfe8b06..e5cd759c 100644
--- a/src/com/android/systemui/car/userpicker/DialogManager.java
+++ b/src/com/android/systemui/car/userpicker/DialogManager.java
@@ -22,6 +22,7 @@ import android.annotation.IntDef;
 import android.app.AlertDialog;
 import android.app.Dialog;
 import android.content.Context;
+import android.os.UserManager;
 import android.util.Log;
 import android.util.Slog;
 import android.util.SparseArray;
@@ -194,7 +195,16 @@ final class DialogManager {
                 message = mUserAddingMessage;
                 break;
             case DIALOG_TYPE_MAX_USER_COUNT_REACHED:
-                message = String.format(mMaxUserLimitReachedMessage, getMaxSupportedUsers());
+                if (android.multiuser.Flags.consistentMaxUsers()
+                        && android.multiuser.Flags.maxUsersInCarIsForSecondary()) {
+                    // Includes secondary users and - for non-HSUM devices - the full system user.
+                    int maxSupportedUsers = mContext.getSystemService(UserManager.class)
+                            .getCurrentAllowedNumberOfUsers(UserManager.USER_TYPE_FULL_SECONDARY)
+                            + (UserManager.isHeadlessSystemUserMode() ? 0 : 1);
+                    message = String.format(mMaxUserLimitReachedMessage, maxSupportedUsers);
+                } else {
+                    message = String.format(mMaxUserLimitReachedMessage, getMaxSupportedUsers());
+                }
                 break;
             case DIALOG_TYPE_CONFIRM_ADD_USER:
                 message = mConfirmAddUserMessage;
diff --git a/src/com/android/systemui/car/userpicker/UserEventManager.java b/src/com/android/systemui/car/userpicker/UserEventManager.java
index 0dce136c..b5b37679 100644
--- a/src/com/android/systemui/car/userpicker/UserEventManager.java
+++ b/src/com/android/systemui/car/userpicker/UserEventManager.java
@@ -216,7 +216,17 @@ public final class UserEventManager {
         }
     }
 
+    private static boolean areMaxUsersMethodFlagsEnabled() {
+        return android.multiuser.Flags.consistentMaxUsers()
+                && android.multiuser.Flags.maxUsersInCarIsForSecondary();
+    }
+
     static int getMaxSupportedUsers() {
+        if (areMaxUsersMethodFlagsEnabled()) {
+            // TODO(b/394178333): When the flags are permanent, delete this method entirely.
+            throw new UnsupportedOperationException("This method is no longer supported");
+        }
+
         int maxSupportedUsers = UserManager.getMaxSupportedUsers();
         if (isHeadlessSystemUserMode()) {
             maxSupportedUsers -= 1;
@@ -252,14 +262,17 @@ public final class UserEventManager {
     }
 
     boolean isUserLimitReached() {
-        int countNonGuestUsers = getAliveUsers().size();
-        int maxSupportedUsers = getMaxSupportedUsers();
+        if (!areMaxUsersMethodFlagsEnabled()) {
+            int countNonGuestUsers = getAliveUsers().size();
+            int maxSupportedUsers = getMaxSupportedUsers();
 
-        if (countNonGuestUsers > maxSupportedUsers) {
-            Slog.e(TAG, "There are more users on the device than allowed.");
-            return true;
+            if (countNonGuestUsers > maxSupportedUsers) {
+                Slog.e(TAG, "There are more users on the device than allowed.");
+                return true;
+            }
+            return countNonGuestUsers == maxSupportedUsers;
         }
-        return countNonGuestUsers == maxSupportedUsers;
+        return !mUserManager.canAddMoreUsers(UserManager.USER_TYPE_FULL_SECONDARY);
     }
 
     boolean canForegroundUserAddUsers() {
diff --git a/src/com/android/systemui/car/userswitcher/UserGridRecyclerView.java b/src/com/android/systemui/car/userswitcher/UserGridRecyclerView.java
index 0bee7e83..4d8d5d8e 100644
--- a/src/com/android/systemui/car/userswitcher/UserGridRecyclerView.java
+++ b/src/com/android/systemui/car/userswitcher/UserGridRecyclerView.java
@@ -349,7 +349,7 @@ public class UserGridRecyclerView extends RecyclerView {
         }
 
         private void handleAddUserClicked() {
-            if (!mUserManager.canAddMoreUsers()) {
+            if (!mUserManager.canAddMoreUsers(UserManager.USER_TYPE_FULL_SECONDARY)) {
                 mAddUserView.setEnabled(true);
                 showMaxUserLimitReachedDialog();
             } else {
@@ -362,27 +362,32 @@ public class UserGridRecyclerView extends RecyclerView {
          * on the device. This is a dynamic value and it decreases with the increase of the number
          * of managed profiles on the device.
          *
-         * <p> It excludes system user in headless system user model.
-         *
          * @return Maximum number of real users that can be created.
          */
         private int getMaxSupportedRealUsers() {
-            int maxSupportedUsers = UserManager.getMaxSupportedUsers();
-            if (UserManager.isHeadlessSystemUserMode()) {
-                maxSupportedUsers -= 1;
-            }
+            if (!android.multiuser.Flags.consistentMaxUsers()
+                    || !android.multiuser.Flags.maxUsersInCarIsForSecondary()) {
+                int maxSupportedUsers = UserManager.getMaxSupportedUsers();
+                if (UserManager.isHeadlessSystemUserMode()) {
+                    maxSupportedUsers -= 1;
+                }
 
-            List<UserInfo> users = mUserManager.getAliveUsers();
+                List<UserInfo> users = mUserManager.getAliveUsers();
 
-            // Count all users that are managed profiles of another user.
-            int managedProfilesCount = 0;
-            for (UserInfo user : users) {
-                if (user.isManagedProfile()) {
-                    managedProfilesCount++;
+                // Count all users that are managed profiles of another user.
+                int managedProfilesCount = 0;
+                for (UserInfo user : users) {
+                    if (user.isManagedProfile()) {
+                        managedProfilesCount++;
+                    }
                 }
+
+                return maxSupportedUsers - managedProfilesCount;
             }
 
-            return maxSupportedUsers - managedProfilesCount;
+            // "Real" users means secondary users and - for non-HSUM devices - the full system user.
+            return mUserManager.getCurrentAllowedNumberOfUsers(UserManager.USER_TYPE_FULL_SECONDARY)
+                    + (UserManager.isHeadlessSystemUserMode() ? 0 : 1);
         }
 
         private void showMaxUserLimitReachedDialog() {
diff --git a/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewController.java b/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewController.java
index ae70bc63..34102a99 100644
--- a/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewController.java
+++ b/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewController.java
@@ -18,7 +18,6 @@ package com.android.systemui.car.userswitcher;
 
 import static android.car.settings.CarSettings.Global.ENABLE_USER_SWITCH_DEVELOPER_MESSAGE;
 
-import static com.android.systemui.Flags.refactorGetCurrentUser;
 import static com.android.systemui.car.Flags.userSwitchKeyguardShownTimeout;
 
 import android.annotation.UserIdInt;
@@ -140,9 +139,6 @@ public class UserSwitchTransitionViewController extends OverlayViewController {
             mTransitionViewShowing = true;
             try {
                 mWindowManagerService.setSwitchingUser(true);
-                if (!refactorGetCurrentUser()) {
-                    mWindowManagerService.lockNow(null);
-                }
             } catch (RemoteException e) {
                 Log.e(TAG, "unable to notify window manager service regarding user switch");
             }
@@ -154,7 +150,7 @@ public class UserSwitchTransitionViewController extends OverlayViewController {
             mCancelRunnable = mMainExecutor.executeDelayed(mWindowShownTimeoutCallback,
                     mWindowShownTimeoutMs);
 
-            if (refactorGetCurrentUser() && mKeyguardManager.isDeviceSecure(newUserId)) {
+            if (mKeyguardManager.isDeviceSecure(newUserId)) {
                 // Setup keyguard timeout but don't lock the device just yet.
                 // The device cannot be locked until we receive a user switching event - otherwise
                 // the KeyguardViewMediator will not have the new userId.
@@ -164,9 +160,6 @@ public class UserSwitchTransitionViewController extends OverlayViewController {
     }
 
     void handleSwitching(int newUserId) {
-        if (!refactorGetCurrentUser()) {
-            return;
-        }
         if (!mKeyguardManager.isDeviceSecure(newUserId)) {
             return;
         }
diff --git a/src/com/android/systemui/car/voicerecognition/ConnectedDeviceVoiceRecognitionNotifier.java b/src/com/android/systemui/car/voicerecognition/ConnectedDeviceVoiceRecognitionNotifier.java
deleted file mode 100644
index 6dff1bd5..00000000
--- a/src/com/android/systemui/car/voicerecognition/ConnectedDeviceVoiceRecognitionNotifier.java
+++ /dev/null
@@ -1,105 +0,0 @@
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
-
-package com.android.systemui.car.voicerecognition;
-
-import android.content.BroadcastReceiver;
-import android.content.Context;
-import android.content.Intent;
-import android.content.IntentFilter;
-import android.os.UserHandle;
-import android.util.Log;
-import android.widget.Toast;
-
-import com.android.internal.annotations.VisibleForTesting;
-import com.android.systemui.CoreStartable;
-import com.android.systemui.R;
-import com.android.systemui.SysUIToast;
-import com.android.systemui.dagger.qualifiers.Main;
-import com.android.systemui.util.concurrency.DelayableExecutor;
-
-import javax.inject.Inject;
-
-/**
- * Controller responsible for showing toast message when voice recognition over bluetooth device
- * getting activated.
- */
-public class ConnectedDeviceVoiceRecognitionNotifier implements CoreStartable {
-
-    private static final String TAG = "CarVoiceRecognition";
-    @VisibleForTesting
-    static final int INVALID_VALUE = -1;
-    @VisibleForTesting
-    static final int VOICE_RECOGNITION_STARTED = 1;
-
-    // TODO(b/218911666): {@link BluetoothHeadsetClient.ACTION_AG_EVENT} is a hidden API.
-    private static final String HEADSET_CLIENT_ACTION_AG_EVENT =
-            "android.bluetooth.headsetclient.profile.action.AG_EVENT";
-    // TODO(b/218911666): {@link BluetoothHeadsetClient.EXTRA_VOICE_RECOGNITION} is a hidden API.
-    private static final String HEADSET_CLIENT_EXTRA_VOICE_RECOGNITION =
-            "android.bluetooth.headsetclient.extra.VOICE_RECOGNITION";
-
-    private final Context mContext;
-    private final DelayableExecutor mExecutor;
-
-    private final BroadcastReceiver mVoiceRecognitionReceiver = new BroadcastReceiver() {
-        @Override
-        public void onReceive(Context context, Intent intent) {
-            if (Log.isLoggable(TAG, Log.DEBUG)) {
-                Log.d(TAG, "Voice recognition received an intent!");
-            }
-            if (intent == null
-                    || intent.getAction() == null
-                    || !HEADSET_CLIENT_ACTION_AG_EVENT.equals(intent.getAction())
-                    || !intent.hasExtra(HEADSET_CLIENT_EXTRA_VOICE_RECOGNITION)) {
-                return;
-            }
-
-            int voiceRecognitionState = intent.getIntExtra(
-                    HEADSET_CLIENT_EXTRA_VOICE_RECOGNITION, INVALID_VALUE);
-
-            if (voiceRecognitionState == VOICE_RECOGNITION_STARTED) {
-                showToastMessage();
-            }
-        }
-    };
-
-    private void showToastMessage() {
-        mExecutor.execute(() -> SysUIToast.makeText(mContext, R.string.voice_recognition_toast,
-                Toast.LENGTH_LONG).show());
-    }
-
-    @Inject
-    public ConnectedDeviceVoiceRecognitionNotifier(
-            Context context,
-            @Main DelayableExecutor mainExecutor
-    ) {
-        mContext = context;
-        mExecutor = mainExecutor;
-    }
-
-    @Override
-    public void start() {
-    }
-
-    @Override
-    public void onBootCompleted() {
-        IntentFilter filter = new IntentFilter();
-        filter.addAction(HEADSET_CLIENT_ACTION_AG_EVENT);
-        mContext.registerReceiverAsUser(mVoiceRecognitionReceiver, UserHandle.ALL, filter,
-                /* broadcastPermission= */ null, /* scheduler= */ null);
-    }
-}
diff --git a/src/com/android/systemui/car/wm/AutoCaptionBarViewFactoryImpl.java b/src/com/android/systemui/car/wm/AutoCaptionBarViewFactoryImpl.java
new file mode 100644
index 00000000..a4801672
--- /dev/null
+++ b/src/com/android/systemui/car/wm/AutoCaptionBarViewFactoryImpl.java
@@ -0,0 +1,119 @@
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
+package com.android.systemui.car.wm;
+
+import android.app.ActivityManager;
+import android.content.ComponentName;
+import android.content.Context;
+import android.content.Intent;
+import android.graphics.Rect;
+import android.hardware.input.InputManager;
+import android.net.Uri;
+import android.os.SystemClock;
+import android.os.UserHandle;
+import android.provider.Settings;
+import android.util.Log;
+import android.view.InputDevice;
+import android.view.KeyCharacterMap;
+import android.view.KeyEvent;
+import android.view.LayoutInflater;
+import android.view.View;
+import android.widget.Button;
+import android.window.WindowContainerTransaction;
+
+import com.android.systemui.R;
+import com.android.wm.shell.ShellTaskOrganizer;
+import com.android.wm.shell.automotive.AutoCaptionBarViewFactory;
+import com.android.wm.shell.automotive.RootTaskStack;
+
+/**
+ * Factory to provide views for caption bar. See
+ * {@link com.android.wm.shell.automotive.AutoCaptionController#setSafeRegionAndCaptionRegion(RootTaskStack, Rect, Rect, AutoCaptionBarViewFactory)}
+ * for more details.
+ */
+public class AutoCaptionBarViewFactoryImpl extends AutoCaptionBarViewFactory {
+
+    private static final String TAG = AutoCaptionBarViewFactoryImpl.class.getSimpleName();
+    private final Context mContext;
+    private final ShellTaskOrganizer mShellTaskOrganizer;
+
+    public AutoCaptionBarViewFactoryImpl(Context context, ShellTaskOrganizer shellTaskOrganizer) {
+        mContext = context;
+        mShellTaskOrganizer = shellTaskOrganizer;
+    }
+
+    @Override
+    public View createView(ActivityManager.RunningTaskInfo taskInfo) {
+        View displayCompatToolbar = LayoutInflater.from(mContext).inflate(
+                R.layout.display_compat_toolbar, null);
+
+        Button backButton = displayCompatToolbar.findViewById(R.id.back_button);
+        if (backButton != null) {
+            backButton.setOnClickListener(view -> sendBackEvent(taskInfo.getDisplayId()));
+        }
+
+        Button aspectRatioButton = displayCompatToolbar.findViewById(R.id.aspect_ratio);
+        if (aspectRatioButton != null) {
+            ComponentName topActivity = taskInfo.topActivity;
+            if (topActivity == null) {
+                aspectRatioButton.setVisibility(View.GONE);
+            } else {
+                aspectRatioButton.setOnClickListener(view -> {
+                    Intent intent =
+                            new Intent(Settings.ACTION_MANAGE_USER_ASPECT_RATIO_SETTINGS);
+                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
+                            | Intent.FLAG_ACTIVITY_CLEAR_TASK);
+                    intent.setData(Uri.parse("package:" + topActivity.getPackageName()));
+                    mContext.startActivityAsUser(intent, UserHandle.of(taskInfo.userId));
+                });
+            }
+        }
+
+        Button closeButton = displayCompatToolbar.findViewById(R.id.close_window);
+        if (closeButton != null) {
+            closeButton.setOnClickListener(view -> {
+                if (taskInfo == null) {
+                    return;
+                }
+                WindowContainerTransaction wct = new WindowContainerTransaction();
+                wct.removeTask(taskInfo.token);
+                mShellTaskOrganizer.applyTransaction(wct);
+            });
+        }
+
+        return displayCompatToolbar;
+    }
+
+    private void sendBackEvent(int displayId) {
+        final long eventTime = SystemClock.uptimeMillis();
+        sendBackEvent(KeyEvent.ACTION_DOWN, displayId, eventTime - 1);
+        sendBackEvent(KeyEvent.ACTION_UP, displayId, eventTime);
+    }
+
+    private void sendBackEvent(int action, int displayId, long eventTime) {
+        final KeyEvent ev = new KeyEvent(eventTime, eventTime, action, KeyEvent.KEYCODE_BACK,
+                0 /* repeat */, 0 /* metaState */, KeyCharacterMap.VIRTUAL_KEYBOARD,
+                0 /* scancode */, KeyEvent.FLAG_FROM_SYSTEM | KeyEvent.FLAG_VIRTUAL_HARD_KEY,
+                InputDevice.SOURCE_KEYBOARD);
+
+        ev.setDisplayId(displayId);
+        if (!mContext.getSystemService(InputManager.class)
+                .injectInputEvent(ev, InputManager.INJECT_INPUT_EVENT_MODE_ASYNC)) {
+            Log.e(TAG, "Inject input event fail");
+        }
+    }
+}
diff --git a/src/com/android/systemui/car/wm/AutoCaptionPerDisplayInitializer.java b/src/com/android/systemui/car/wm/AutoCaptionPerDisplayInitializer.java
new file mode 100644
index 00000000..f395df6a
--- /dev/null
+++ b/src/com/android/systemui/car/wm/AutoCaptionPerDisplayInitializer.java
@@ -0,0 +1,121 @@
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
+package com.android.systemui.car.wm;
+
+import static com.android.systemui.car.Flags.displayCompatibilityAutoDecorSafeRegion;
+import static com.android.systemui.car.users.CarSystemUIUserUtil.isSecondaryMUMDSystemUI;
+
+import android.content.Context;
+import android.graphics.Rect;
+import android.util.SparseArray;
+import android.window.DisplayAreaInfo;
+
+import com.android.systemui.R;
+import com.android.wm.shell.RootTaskDisplayAreaOrganizer;
+import com.android.wm.shell.ShellTaskOrganizer;
+import com.android.wm.shell.automotive.AutoCaptionController;
+import com.android.wm.shell.common.DisplayController;
+
+/**
+ * Initialises caption bars(using AutoDecor) and safe regions for displays in the system.
+ * TODO(b/409131368): Remove this class when Hudson is migrated to scalable ui
+ */
+public class AutoCaptionPerDisplayInitializer implements
+        DisplayController.OnDisplaysChangedListener {
+    private final AutoCaptionController mAutoCaptionController;
+    private final AutoCaptionBarViewFactoryImpl mAutoCaptionBarViewFactoryImpl;
+    private final boolean mEnableSafeAreaAndToolbarPerDisplay;
+    private final Rect mSafeRegion;
+    private final Rect mCaptionRegion;
+    private final RootTaskDisplayAreaOrganizer mRootTaskDisplayAreaOrganizer;
+    private final SparseArray<RootTaskDisplayAreaOrganizer.RootTaskDisplayAreaListener>
+            mDisplayIdToListenerMap = new SparseArray<>();
+
+    public AutoCaptionPerDisplayInitializer(
+            Context context,
+            ShellTaskOrganizer shellTaskOrganizer,
+            AutoCaptionController autoCaptionController,
+            DisplayController displayController,
+            RootTaskDisplayAreaOrganizer rootTaskDisplayAreaOrganizer) {
+        mAutoCaptionController = autoCaptionController;
+        mAutoCaptionBarViewFactoryImpl =
+                new AutoCaptionBarViewFactoryImpl(context, shellTaskOrganizer);
+        mEnableSafeAreaAndToolbarPerDisplay = context.getResources().getBoolean(
+                R.bool.config_enableSafeAreaAndToolbarPerDisplay);
+        mSafeRegion = new Rect(
+                context.getResources().getDimensionPixelSize(R.dimen.safe_region_left),
+                context.getResources().getDimensionPixelSize(R.dimen.safe_region_top),
+                context.getResources().getDimensionPixelSize(R.dimen.safe_region_right),
+                context.getResources().getDimensionPixelSize(R.dimen.safe_region_bottom)
+        );
+        mCaptionRegion = new Rect(
+                context.getResources().getDimensionPixelSize(R.dimen.caption_region_left),
+                context.getResources().getDimensionPixelSize(R.dimen.caption_region_top),
+                context.getResources().getDimensionPixelSize(R.dimen.caption_region_right),
+                context.getResources().getDimensionPixelSize(R.dimen.caption_region_bottom)
+        );
+        mRootTaskDisplayAreaOrganizer = rootTaskDisplayAreaOrganizer;
+        if (!displayCompatibilityAutoDecorSafeRegion() || !mEnableSafeAreaAndToolbarPerDisplay) {
+            return;
+        }
+        if (!isSecondaryMUMDSystemUI()) {
+            displayController.addDisplayWindowListener(this);
+        }
+    }
+
+    @Override
+    public void onDisplayAdded(int displayId) {
+        if (!displayCompatibilityAutoDecorSafeRegion() || !mEnableSafeAreaAndToolbarPerDisplay) {
+            return;
+        }
+        RootTDAListener listener = new RootTDAListener();
+        mRootTaskDisplayAreaOrganizer.registerListener(displayId, listener);
+        mDisplayIdToListenerMap.append(displayId, listener);
+    }
+
+    @Override
+    public void onDisplayRemoved(int displayId) {
+        if (!displayCompatibilityAutoDecorSafeRegion() || !mEnableSafeAreaAndToolbarPerDisplay) {
+            return;
+        }
+        RootTaskDisplayAreaOrganizer.RootTaskDisplayAreaListener listener =
+                mDisplayIdToListenerMap.removeReturnOld(displayId);
+        if (listener != null) {
+            mRootTaskDisplayAreaOrganizer.unregisterListener(listener);
+        }
+        mAutoCaptionController.removeSafeRegionAndCaptionRegion(displayId);
+    }
+
+    /**
+     * {@link RootTaskDisplayAreaOrganizer.RootTaskDisplayAreaListener} that attaches the safe
+     * region and toolbar to new display areas.
+     */
+    private class RootTDAListener implements
+            RootTaskDisplayAreaOrganizer.RootTaskDisplayAreaListener {
+        @Override
+        public void onDisplayAreaAppeared(DisplayAreaInfo displayAreaInfo) {
+            if (displayAreaInfo == null) {
+                return;
+            }
+            mAutoCaptionController.setSafeRegionAndCaptionRegion(displayAreaInfo.displayId,
+                    mSafeRegion,
+                    mCaptionRegion,
+                    mAutoCaptionBarViewFactoryImpl
+            );
+        }
+    }
+}
diff --git a/src/com/android/systemui/car/wm/AutoDisplayCompatWindowDecorViewModel.java b/src/com/android/systemui/car/wm/AutoDisplayCompatWindowDecorViewModel.java
index 4a4f94c7..98663d8d 100644
--- a/src/com/android/systemui/car/wm/AutoDisplayCompatWindowDecorViewModel.java
+++ b/src/com/android/systemui/car/wm/AutoDisplayCompatWindowDecorViewModel.java
@@ -21,10 +21,13 @@ import static com.android.systemui.car.Flags.displayCompatibilityCaptionBar;
 import static com.android.systemui.car.displaycompat.CarDisplayCompatUtils.getPackageName;
 import static com.android.systemui.car.displaycompat.CarDisplayCompatUtils.requiresDisplayCompat;
 
+import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.app.ActivityManager;
 import android.car.content.pm.CarPackageManager;
 import android.content.Context;
+import android.os.Handler;
+import android.view.SurfaceControl;
 
 import com.android.systemui.car.CarServiceProvider;
 import com.android.wm.shell.ShellTaskOrganizer;
@@ -36,15 +39,24 @@ import com.android.wm.shell.shared.annotations.ShellBackgroundThread;
 import com.android.wm.shell.shared.annotations.ShellMainThread;
 import com.android.wm.shell.sysui.ShellInit;
 import com.android.wm.shell.transition.FocusTransitionObserver;
+import com.android.wm.shell.transition.Transitions;
 import com.android.wm.shell.windowdecor.CarWindowDecorViewModel;
 import com.android.wm.shell.windowdecor.common.viewhost.WindowDecorViewHost;
 import com.android.wm.shell.windowdecor.common.viewhost.WindowDecorViewHostSupplier;
 
+/**
+ * Implementation of {@link CarWindowDecorViewModel} that adds
+ * {@link com.android.wm.shell.windowdecor.CarWindowDecoration} to the tasks that require
+ * display compatibility.
+ * TODO(b/409134330): Remove when new auto decor solution is merged and approved.
+ */
 public class AutoDisplayCompatWindowDecorViewModel extends CarWindowDecorViewModel {
     @Nullable
     private CarPackageManager mCarPackageManager;
 
     public AutoDisplayCompatWindowDecorViewModel(Context context,
+            @NonNull @ShellMainThread Handler handler,
+            @NonNull Transitions transitions,
             @ShellMainThread ShellExecutor mainExecutor,
             @ShellBackgroundThread ShellExecutor bgExecutor,
             ShellInit shellInit,
@@ -55,16 +67,41 @@ public class AutoDisplayCompatWindowDecorViewModel extends CarWindowDecorViewMod
             FocusTransitionObserver focusTransitionObserver,
             WindowDecorViewHostSupplier<WindowDecorViewHost> windowDecorViewHostSupplier,
             CarServiceProvider carServiceProvider) {
-        super(context, mainExecutor, bgExecutor, shellInit, taskOrganizer, displayController,
-                displayInsetsController, syncQueue, focusTransitionObserver,
+        super(context, handler, transitions, mainExecutor, bgExecutor, shellInit, taskOrganizer,
+                displayController, displayInsetsController, syncQueue, focusTransitionObserver,
                 windowDecorViewHostSupplier);
-        carServiceProvider.addListener(
-                car -> mCarPackageManager = car.getCarManager(CarPackageManager.class));
+        if (displayCompatibilityCaptionBar()) {
+            carServiceProvider.addListener(
+                    car -> mCarPackageManager = car.getCarManager(CarPackageManager.class));
+        }
+    }
+
+    @Override
+    public boolean onTaskOpening(ActivityManager.RunningTaskInfo taskInfo,
+            SurfaceControl taskSurface, SurfaceControl.Transaction startT,
+            SurfaceControl.Transaction finishT) {
+        if (!displayCompatibilityCaptionBar()) {
+            return false;
+        }
+        return super.onTaskOpening(taskInfo, taskSurface, startT, finishT);
+    }
+
+    @Override
+    public void onTaskChanging(
+            ActivityManager.RunningTaskInfo taskInfo,
+            SurfaceControl taskSurface,
+            SurfaceControl.Transaction startT,
+            SurfaceControl.Transaction finishT) {
+        if (!displayCompatibilityCaptionBar()) {
+            return;
+        }
+        super.onTaskChanging(taskInfo, taskSurface, startT, finishT);
     }
 
     @Override
     protected boolean shouldShowWindowDecor(ActivityManager.RunningTaskInfo taskInfo) {
         return displayCompatibilityCaptionBar()
+                && taskInfo != null
                 && requiresDisplayCompat(
                 getPackageName(taskInfo), taskInfo.userId, mCarPackageManager)
                 && taskInfo.displayId == DEFAULT_DISPLAY;
diff --git a/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java b/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java
index 69659bc4..688a51e9 100644
--- a/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java
+++ b/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java
@@ -15,11 +15,8 @@
  */
 package com.android.systemui.car.wm.activity;
 
-import static android.app.WindowConfiguration.WINDOWING_MODE_MULTI_WINDOW;
-
 import static com.android.systemui.car.Flags.configAppBlockingActivities;
 
-import android.app.ActivityManager;
 import android.car.Car;
 import android.car.CarOccupantZoneManager;
 import android.car.app.CarActivityManager;
@@ -30,7 +27,6 @@ import android.content.ActivityNotFoundException;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
-import android.content.pm.PackageManager;
 import android.graphics.Insets;
 import android.graphics.PixelFormat;
 import android.graphics.Rect;
@@ -41,7 +37,6 @@ import android.os.Bundle;
 import android.os.Handler;
 import android.os.Looper;
 import android.os.UserHandle;
-import android.text.TextUtils;
 import android.util.Log;
 import android.util.Slog;
 import android.view.Display;
@@ -61,7 +56,6 @@ import com.android.systemui.car.ndo.BlockerViewModel;
 import com.android.systemui.car.ndo.NdoViewModelFactory;
 import com.android.systemui.car.wm.activity.blurredbackground.BlurredSurfaceRenderer;
 
-import java.util.List;
 import java.util.concurrent.Executor;
 
 import javax.inject.Inject;
@@ -197,6 +191,15 @@ public class ActivityBlockingActivity extends FragmentActivity {
 
     @Override
     protected void onResume() {
+        // TODO(b/412839927): Provide a way to know the task under ABA. If the task under ABA is DO,
+        // then close the ABA. Right now, it is possible that
+        // - A NDO activity launch. ABA start call is fired.
+        // - While ABA is being started, another DO activity comes to top.
+        // - ABA shown now
+        // In this case, we have NDO, DO and then ABA. We don't want to show ABA over DO activity.
+        // So we need to add the logic to check what is below ABA, and if it is DO, then
+        // close ABA. Currently there is no reliable way to check what task is under ABA.
+
         super.onResume();
 
         // Display info about the current blocked activity, and optionally show an exit button
@@ -208,16 +211,9 @@ public class ActivityBlockingActivity extends FragmentActivity {
         // blockedActivity is expected to be always passed in as the topmost activity of task.
         String blockedActivity = getIntent().getStringExtra(
                 CarPackageManager.BLOCKING_INTENT_EXTRA_BLOCKED_ACTIVITY_NAME);
-        if (!TextUtils.isEmpty(blockedActivity)) {
-            if (isTopActivityBehindAbaDistractionOptimized()) {
-                Slog.w(TAG, "Top activity is already DO, so finishing");
-                finish();
-                return;
-            }
 
-            if (Log.isLoggable(TAG, Log.DEBUG)) {
-                Slog.d(TAG, "Blocking activity " + blockedActivity);
-            }
+        if (Log.isLoggable(TAG, Log.DEBUG)) {
+            Slog.d(TAG, "Blocking activity " + blockedActivity);
         }
 
         displayExitButton();
@@ -360,68 +356,6 @@ public class ActivityBlockingActivity extends FragmentActivity {
                 : getString(R.string.exit_button_go_back);
     }
 
-    /**
-     * It is possible that the stack info has changed between when the intent to launch this
-     * activity was initiated and when this activity is started. Check whether the activity behind
-     * the ABA is distraction optimized.
-     *
-     * @return {@code true} if the activity is distraction optimized, {@code false} if the top task
-     * behind the ABA is null or the top task's top activity is null or if the top activity is
-     * non-distraction optimized.
-     */
-    private boolean isTopActivityBehindAbaDistractionOptimized() {
-        List<ActivityManager.RunningTaskInfo> taskInfosTopToBottom;
-        taskInfosTopToBottom = mCarActivityManager.getVisibleTasks();
-        ActivityManager.RunningTaskInfo topStackBehindAba = null;
-
-        // Iterate in bottom to top manner
-        for (int i = taskInfosTopToBottom.size() - 1; i >= 0; i--) {
-            ActivityManager.RunningTaskInfo taskInfo = taskInfosTopToBottom.get(i);
-            if (taskInfo.displayId != getDisplayId()) {
-                // ignore stacks on other displays
-                continue;
-            }
-
-            // TODO(b/359583186): Remove this check when targets with splitscreen multitasking
-            // feature are moved to DaViews.
-            if (getApplicationContext().getPackageManager().hasSystemFeature(
-                    PackageManager.FEATURE_CAR_SPLITSCREEN_MULTITASKING)
-                    && taskInfo.getWindowingMode() != WINDOWING_MODE_MULTI_WINDOW) {
-                // targets which have splitscreen multitasking feature, can have other visible
-                // tasks such as home which are not blocked. Only consider tasks with multi
-                // window windowing mode.
-                continue;
-            }
-
-            if (getComponentName().equals(taskInfo.topActivity)) {
-                // quit when stack with the blocking activity is encountered because the last seen
-                // task will be the topStackBehindAba.
-                break;
-            }
-
-            topStackBehindAba = taskInfo;
-        }
-
-        if (Log.isLoggable(TAG, Log.DEBUG)) {
-            Slog.d(TAG, String.format("Top stack behind ABA is: %s", topStackBehindAba));
-        }
-
-        if (topStackBehindAba != null && topStackBehindAba.topActivity != null) {
-            boolean isDo = mCarPackageManager.isActivityDistractionOptimized(
-                    topStackBehindAba.topActivity.getPackageName(),
-                    topStackBehindAba.topActivity.getClassName());
-            if (Log.isLoggable(TAG, Log.DEBUG)) {
-                Slog.d(TAG,
-                        String.format("Top activity (%s) is DO: %s", topStackBehindAba.topActivity,
-                                isDo));
-            }
-            return isDo;
-        }
-
-        // unknown top stack / activity, default to considering it non-DO
-        return false;
-    }
-
     private void displayDebugInfo() {
         String blockedActivity = getIntent().getStringExtra(
                 CarPackageManager.BLOCKING_INTENT_EXTRA_BLOCKED_ACTIVITY_NAME);
diff --git a/src/com/android/systemui/car/wm/scalableui/EventDispatcher.java b/src/com/android/systemui/car/wm/scalableui/EventDispatcher.java
index 0346e0e0..1a67cb4d 100644
--- a/src/com/android/systemui/car/wm/scalableui/EventDispatcher.java
+++ b/src/com/android/systemui/car/wm/scalableui/EventDispatcher.java
@@ -38,16 +38,16 @@ import javax.inject.Inject;
 public class EventDispatcher {
 
     private final Context mContext;
-    private final TaskPanelTransitionCoordinator mTaskPanelTransitionCoordinator;
+    private final PanelTransitionCoordinator mPanelTransitionCoordinator;
 
     @Inject
     public EventDispatcher(Context context,
-            Lazy<TaskPanelTransitionCoordinator> taskPanelTransitionCoordinator) {
+            Lazy<PanelTransitionCoordinator> panelTransitionCoordinator) {
         mContext = context;
         if (isScalableUIEnabled()) {
-            mTaskPanelTransitionCoordinator = taskPanelTransitionCoordinator.get();
+            mPanelTransitionCoordinator = panelTransitionCoordinator.get();
         } else {
-            mTaskPanelTransitionCoordinator = null;
+            mPanelTransitionCoordinator = null;
         }
     }
 
@@ -80,11 +80,23 @@ public class EventDispatcher {
         if (!isScalableUIEnabled()) {
             throw new IllegalStateException("ScalableUI disabled - cannot execute transaction");
         }
-        mTaskPanelTransitionCoordinator.startTransition(getTransaction(event));
+        mPanelTransitionCoordinator.startTransition(getTransaction(event));
     }
 
     private boolean isScalableUIEnabled() {
         return scalableUi() && enableAutoTaskStackController()
                 && mContext.getResources().getBoolean(R.bool.config_enableScalableUI);
     }
+
+    /**
+     * An interface representing an object that can produce {@link Event} and dispatch them.
+     *
+     * TODO(b/409615558): Create a broadcast receiver to receive event from other system components.
+     */
+    public interface EventProducer {
+        /**
+         * Sets the {@link EventDispatcher} that this producer should use to dispatch events.
+         */
+        void setEventDispatcher(EventDispatcher eventDispatcher);
+    }
 }
diff --git a/src/com/android/systemui/car/wm/scalableui/PanelAutoTaskStackTransitionHandlerDelegate.java b/src/com/android/systemui/car/wm/scalableui/PanelAutoTaskStackTransitionHandlerDelegate.java
index 491e94c5..d7c920f5 100644
--- a/src/com/android/systemui/car/wm/scalableui/PanelAutoTaskStackTransitionHandlerDelegate.java
+++ b/src/com/android/systemui/car/wm/scalableui/PanelAutoTaskStackTransitionHandlerDelegate.java
@@ -16,11 +16,13 @@
 package com.android.systemui.car.wm.scalableui;
 
 import static android.app.WindowConfiguration.ACTIVITY_TYPE_HOME;
+import static android.view.WindowInsets.Type.systemOverlays;
 import static android.view.WindowManager.TRANSIT_FLAG_AVOID_MOVE_TO_FRONT;
 
 import static com.android.systemui.car.Flags.scalableUi;
 import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.COMPONENT_TOKEN_ID;
 import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.EMPTY_EVENT_ID;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.PACKAGE_TOKEN_ID;
 import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.PANEL_TOKEN_ID;
 import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_HOME_EVENT_ID;
 import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_TASK_CLOSE_EVENT_ID;
@@ -41,13 +43,17 @@ import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
 import com.android.car.internal.dep.Trace;
+import com.android.car.scalableui.manager.StateManager;
 import com.android.car.scalableui.model.Event;
+import com.android.car.scalableui.model.PanelState;
 import com.android.car.scalableui.model.PanelTransaction;
+import com.android.car.scalableui.model.Variant;
 import com.android.car.scalableui.panel.Panel;
 import com.android.systemui.R;
 import com.android.systemui.car.wm.scalableui.panel.PanelUtils;
 import com.android.systemui.car.wm.scalableui.panel.TaskPanel;
 import com.android.systemui.car.wm.scalableui.panel.TaskPanelInfoRepository;
+import com.android.wm.shell.automotive.AutoLayoutManager;
 import com.android.wm.shell.automotive.AutoTaskStackController;
 import com.android.wm.shell.automotive.AutoTaskStackState;
 import com.android.wm.shell.automotive.AutoTaskStackTransaction;
@@ -56,6 +62,7 @@ import com.android.wm.shell.shared.TransitionUtil;
 import com.android.wm.shell.transition.Transitions;
 
 import java.util.Map;
+import java.util.stream.IntStream;
 
 import javax.inject.Inject;
 
@@ -71,24 +78,27 @@ public class PanelAutoTaskStackTransitionHandlerDelegate implements
     private static final boolean DEBUG = Build.IS_DEBUGGABLE;
 
     private final AutoTaskStackController mAutoTaskStackController;
-    private final TaskPanelTransitionCoordinator mTaskPanelTransitionCoordinator;
+    private final PanelTransitionCoordinator mPanelTransitionCoordinator;
     private final Context mContext;
     private final PanelUtils mPanelUtils;
-    private final TaskPanelInfoRepository mTaskPanelInfoRepository;
+    private final TaskPanelInfoRepository mPanelInfoRepository;
+    private final AutoLayoutManager mAutoLayoutManager;
 
     @Inject
     public PanelAutoTaskStackTransitionHandlerDelegate(
             Context context,
             AutoTaskStackController autoTaskStackController,
-            TaskPanelTransitionCoordinator taskPanelTransitionCoordinator,
+            PanelTransitionCoordinator panelTransitionCoordinator,
             PanelUtils panelUtils,
-            TaskPanelInfoRepository taskPanelInfoRepository
+            TaskPanelInfoRepository panelInfoRepository,
+            AutoLayoutManager autoLayoutManager
     ) {
         mAutoTaskStackController = autoTaskStackController;
-        mTaskPanelTransitionCoordinator = taskPanelTransitionCoordinator;
+        mPanelTransitionCoordinator = panelTransitionCoordinator;
         mContext = context;
         mPanelUtils = panelUtils;
-        mTaskPanelInfoRepository = taskPanelInfoRepository;
+        mPanelInfoRepository = panelInfoRepository;
+        mAutoLayoutManager = autoLayoutManager;
     }
 
     /**
@@ -114,8 +124,9 @@ public class PanelAutoTaskStackTransitionHandlerDelegate implements
             Event event = calculateEvent(request);
             PanelTransaction panelTransaction = EventDispatcher.getTransaction(event);
             AutoTaskStackTransaction wct =
-                    mTaskPanelTransitionCoordinator.createAutoTaskStackTransaction(transition,
+                    mPanelTransitionCoordinator.createAutoTaskStackTransaction(transition,
                             panelTransaction);
+            mPanelTransitionCoordinator.resetUnpreparedDecorPanel(panelTransaction);
             if (DEBUG) {
                 Log.d(TAG, "handleRequest: COMPLETED " + wct);
             }
@@ -148,16 +159,18 @@ public class PanelAutoTaskStackTransitionHandlerDelegate implements
                     + ", finishTransaction=" + finishTransaction.getId());
         }
 
-        mTaskPanelTransitionCoordinator.maybeResolveConflict(changedTaskStacks, transition);
-        mTaskPanelInfoRepository.maybeNotifyTopTaskOnPanelChanged();
+        mPanelTransitionCoordinator.maybeResolveConflict(changedTaskStacks, transition);
+        mPanelInfoRepository.maybeNotifyTopTaskOnPanelChanged();
 
         Trace.beginSection(TAG + "#startAnimation");
 
+        // Its expected for the auto transition handler delegate to apply startTransaction for now.
+        // TODO(b/421966313) Think about applying this in car-wm-shell instead.
         calculateTransaction(startTransaction, info, /* isFinish= */ false);
         calculateTransaction(finishTransaction, info, /* isFinish= */ true);
         startTransaction.apply();
 
-        boolean animationStarted = mTaskPanelTransitionCoordinator.playPendingAnimations(transition,
+        boolean animationStarted = mPanelTransitionCoordinator.playPendingAnimations(transition,
                 finishCallback);
         Trace.endSection();
         return animationStarted;
@@ -167,27 +180,64 @@ public class PanelAutoTaskStackTransitionHandlerDelegate implements
             @NonNull TransitionInfo info, boolean isFinish) {
         SurfaceControl leash = null;
         Rect pos = null;
+        boolean visibility;
+        float cornerRadius;
+        int layer;
         for (TransitionInfo.Change change : info.getChanges()) {
             if (change.getTaskInfo() == null) {
                 continue;
             }
             TaskPanel taskPanel = mPanelUtils.getTaskPanel(
                     tp -> tp.getRootTaskId() == change.getTaskInfo().taskId);
-            if (taskPanel == null) {
+
+            if (taskPanel == null || taskPanel.getLeash() == null) {
+                Log.e(TAG, "TaskPanel is null " + change.getTaskInfo() + ", or leash is null"
+                        + taskPanel);
                 continue;
             }
+            leash = taskPanel.getLeash();
 
-            leash = change.getLeash();
             if (isFinish) {
-                pos = change.getEndAbsBounds();
+                // Use the PanelState is up to date even before animation, but not Panel.
+                PanelState ps = StateManager.getPanelState(
+                        taskPanel.getPanelId());
+                if (ps == null) {
+                    Log.e(TAG, "PanelState is null " + taskPanel.getPanelId());
+                    continue;
+                }
+                Variant currentVariant = ps.getCurrentVariant();
+                if (currentVariant == null) {
+                    Log.e(TAG, "Current Variant for panelState is null " + taskPanel.getPanelId());
+                    continue;
+                }
+                pos = currentVariant.getBounds();
+                visibility = currentVariant.isVisible();
+                cornerRadius = currentVariant.getCornerRadius();
+                layer = currentVariant.getLayer();
             } else {
-                pos = change.getStartAbsBounds();
+                // Start from current panel surface bounds rather than using window bounds from
+                // change.
+                pos = taskPanel.getBounds();
+                visibility = taskPanel.isVisible();
+                cornerRadius = taskPanel.getCornerRadius();
+                layer = taskPanel.getLayer();
+            }
+            if (DEBUG) {
+                Log.d(TAG, taskPanel.getPanelId() + (isFinish ? "end" : "start") + " bounds=" + pos
+                        + ", visibility=" + visibility + ", cornerRadius" + cornerRadius
+                        + ", layer=" + layer);
             }
+            //TODO(b/404959846): use panel update.
             transaction.setPosition(leash, pos.left, pos.top);
-            transaction.setCornerRadius(leash, taskPanel.getCornerRadius());
+            transaction.setCornerRadius(leash, cornerRadius);
+            transaction.setVisibility(leash, visibility);
+            transaction.setLayer(leash, layer);
             taskPanel.setLeash(leash);
-
-            transaction.setLayer(leash, taskPanel.getLayer());
+            Rect[] panelInsets = taskPanel.getInsetRects(/* variant= */ null);
+            IntStream.range(0, panelInsets.length).forEach(sideIndex -> {
+                mAutoLayoutManager.addOrUpdateInsets(taskPanel.getRootStack(), sideIndex,
+                        systemOverlays(), panelInsets[sideIndex]);
+            });
         }
     }
 
@@ -200,9 +250,10 @@ public class PanelAutoTaskStackTransitionHandlerDelegate implements
                 && request.getTriggerTask().baseIntent.getCategories().contains(
                 Intent.CATEGORY_HOME)) {
             ComponentName component = request.getTriggerTask().baseActivity;
-            String componentString = component != null ? component.flattenToString() : null;
-            return new Event.Builder(SYSTEM_HOME_EVENT_ID).addToken(COMPONENT_TOKEN_ID,
-                    componentString).build();
+            String packageString = component != null ? component.getPackageName() : null;
+            // Multiple SUW activities have home as categories. Panels should treat them the same.
+            return new Event.Builder(SYSTEM_HOME_EVENT_ID).addToken(PACKAGE_TOKEN_ID,
+                    packageString).build();
         }
 
         if ((request.getFlags() & TRANSIT_FLAG_AVOID_MOVE_TO_FRONT)
@@ -213,24 +264,15 @@ public class PanelAutoTaskStackTransitionHandlerDelegate implements
             return EMPTY_EVENT;
         }
 
-        ComponentName component;
-        if (TransitionUtil.isClosingType(request.getType())) {
-            // On a closing event, the baseActivity may be null but the realActivity will still
-            // return the component being closed.
-            component = request.getTriggerTask().realActivity;
-            if (DEBUG) {
-                Log.d(TAG, "Closing transition - using realActivity component=" + component);
-            }
-        } else {
-            component = request.getTriggerTask().baseActivity;
-            if (DEBUG) {
-                Log.d(TAG, "Open transition - using baseActivity component=" + component);
-            }
+        ComponentName component = mPanelUtils.getTaskComponentName(request.getTriggerTask());
+        if (DEBUG) {
+            Log.d(TAG, "Transition type=" + request.getType()
+                    + " using component=" + component);
         }
         String componentString = component != null ? component.flattenToString() : null;
         String panelId;
         TaskPanel panel = null;
-        if (componentString != null) {
+        if (component != null) {
             panel = mPanelUtils.getTaskPanel(tp -> tp.handles(component));
         }
         if (panel == null) {
@@ -250,11 +292,15 @@ public class PanelAutoTaskStackTransitionHandlerDelegate implements
                     .addToken(PANEL_TOKEN_ID, panelId)
                     .addToken(COMPONENT_TOKEN_ID, componentString)
                     .build();
+        } else if (TransitionUtil.isOpeningType(request.getType())) {
+            return new Event.Builder(SYSTEM_TASK_OPEN_EVENT_ID)
+                    .addToken(PANEL_TOKEN_ID, panelId)
+                    .addToken(COMPONENT_TOKEN_ID, componentString)
+                    .build();
+        } else {
+            Log.e(TAG, "Unknown transition type " + request.getType());
+            return EMPTY_EVENT;
         }
-        return new Event.Builder(SYSTEM_TASK_OPEN_EVENT_ID)
-                .addToken(PANEL_TOKEN_ID, panelId)
-                .addToken(COMPONENT_TOKEN_ID, componentString)
-                .build();
     }
 
     @Override
@@ -262,10 +308,11 @@ public class PanelAutoTaskStackTransitionHandlerDelegate implements
             @NonNull Map<Integer, AutoTaskStackState> changedTaskStacks, boolean aborted,
             @Nullable SurfaceControl.Transaction finishTransaction) {
         if (DEBUG) {
-            Log.d(TAG, "onTransitionConsumed=" + aborted);
+            Log.d(TAG, "onTransitionConsumed=" + aborted + ", transition=" + transition
+                    + ", changedTaskStacks" + changedTaskStacks);
         }
         Trace.beginSection(TAG + "#onTransitionConsumed");
-        mTaskPanelTransitionCoordinator.stopRunningAnimations();
+        mPanelTransitionCoordinator.stopRunningAnimations(transition);
         Trace.endSection();
     }
 
@@ -276,10 +323,10 @@ public class PanelAutoTaskStackTransitionHandlerDelegate implements
             @NonNull IBinder mergeTarget,
             @NonNull Transitions.TransitionFinishCallback finishCallback) {
         if (DEBUG) {
-            Log.d(TAG, "mergeAnimation");
+            Log.d(TAG, "mergeAnimation " + transition);
         }
         Trace.beginSection(TAG + "#mergeAnimation");
-        mTaskPanelTransitionCoordinator.stopRunningAnimations();
+        mPanelTransitionCoordinator.stopRunningAnimations(transition);
         Trace.endSection();
     }
 }
diff --git a/src/com/android/systemui/car/wm/scalableui/PanelConfigReader.java b/src/com/android/systemui/car/wm/scalableui/PanelConfigReader.java
index 8bc71b9e..c76a548f 100644
--- a/src/com/android/systemui/car/wm/scalableui/PanelConfigReader.java
+++ b/src/com/android/systemui/car/wm/scalableui/PanelConfigReader.java
@@ -22,7 +22,15 @@ import android.content.res.TypedArray;
 import android.os.Build;
 import android.util.Log;
 
+import java.io.IOException;
+import java.io.InputStream;
+import java.net.URL;
+import java.util.List;
+
 import com.android.car.internal.dep.Trace;
+import com.android.car.scalableui.designcompose.DocLoadException;
+import com.android.car.scalableui.designcompose.PanelStateDocLoader;
+import com.android.car.scalableui.loader.xml.XmlModelLoader;
 import com.android.car.scalableui.manager.StateManager;
 import com.android.car.scalableui.model.PanelState;
 import com.android.car.scalableui.panel.PanelPool;
@@ -31,9 +39,7 @@ import com.android.systemui.car.wm.scalableui.panel.DecorPanel;
 import com.android.systemui.car.wm.scalableui.panel.TaskPanel;
 import com.android.wm.shell.dagger.WMSingleton;
 
-import org.xmlpull.v1.XmlPullParserException;
-
-import java.io.IOException;
+import static com.android.systemui.car.Flags.scalableUiDesignCompose;
 
 @WMSingleton
 public class PanelConfigReader {
@@ -45,9 +51,7 @@ public class PanelConfigReader {
 
     public PanelConfigReader(Context context, TaskPanel.Factory taskPanelFactory,
             DecorPanel.Factory decorPanelFactory) {
-        if (DEBUG) {
-            Log.d(TAG, "PanelConfig initialized user: " + ActivityManager.getCurrentUser());
-        }
+        debugLog("PanelConfig initialized user: " + ActivityManager.getCurrentUser());
         mContext = context;
         mTaskPanelFactory = taskPanelFactory;
         mDecorPanelFactory = decorPanelFactory;
@@ -68,21 +72,62 @@ public class PanelConfigReader {
 
         try {
             Trace.beginSection(TAG + "#init");
-            Resources res = mContext.getResources();
             StateManager.clearStates();
-            try (TypedArray states = res.obtainTypedArray(R.array.window_states)) {
-                for (int i = 0; i < states.length(); i++) {
-                    int xmlResId = states.getResourceId(i, 0);
-                    if (DEBUG) {
-                        Log.d(TAG, "PanelConfig adding state: " + xmlResId);
-                    }
-                    StateManager.addState(mContext, xmlResId);
-                }
+
+            if (scalableUiDesignCompose()) {
+                loadFromDcf();
+            } else {
+                loadFromXml();
             }
-        } catch (XmlPullParserException | IOException e) {
-            throw new RuntimeException(e);
         } finally {
             Trace.endSection();
         }
     }
+
+    private void loadFromDcf() {
+        try {
+            InputStream dcfStream = mContext.getResources().openRawResource(R.raw.ScalableSystemUi);
+            if (dcfStream == null) {
+                Log.e(TAG, "Failed to open file ScalableSystemUi.dcf");
+                // Throw a runtime exception to cause a crash
+                throw new RuntimeException("Failed to open ScalableSystemUi.dcf");
+            }
+
+            debugLog("Loading panel states from DCF file");
+            PanelStateDocLoader dcLoader = new PanelStateDocLoader(mContext);
+            String docId = mContext.getResources().getString(R.string.config_scalableUiDcfFileId);
+
+            List<PanelState> states = dcLoader.loadPanelStates(dcfStream, docId);
+            debugLog("Loaded Panels: " + states.size());
+
+            for (PanelState panelState : states) {
+                debugLog("PanelConfig adding state: " + panelState.getId());
+                StateManager.addState(panelState);
+            }
+        } catch (Exception e) {
+            Log.e(TAG, "Error opening or processing DCF file: " + e);
+            // Throw a runtime exception to cause a crash
+            throw new RuntimeException("Error opening or processing DCF file: ", e);
+        }
+    }
+
+    private void loadFromXml() {
+        debugLog("Loading panel states from XML");
+        Resources res = mContext.getResources();
+        try (TypedArray states = res.obtainTypedArray(R.array.window_states)) {
+            for (int i = 0; i < states.length(); i++) {
+                int xmlResId = states.getResourceId(i, 0);
+                debugLog("PanelConfig adding state: " + xmlResId);
+                XmlModelLoader loader = new XmlModelLoader(mContext);
+                PanelState panelState = loader.createPanelState(xmlResId);
+                StateManager.addState(panelState);
+            }
+        }
+    }
+
+    private void debugLog(String logMsg) {
+        if (DEBUG) {
+            Log.d(TAG, logMsg);
+        }
+    }
 }
diff --git a/src/com/android/systemui/car/wm/scalableui/TaskPanelTransitionCoordinator.java b/src/com/android/systemui/car/wm/scalableui/PanelTransitionCoordinator.java
similarity index 60%
rename from src/com/android/systemui/car/wm/scalableui/TaskPanelTransitionCoordinator.java
rename to src/com/android/systemui/car/wm/scalableui/PanelTransitionCoordinator.java
index 7a4e6962..4618dc22 100644
--- a/src/com/android/systemui/car/wm/scalableui/TaskPanelTransitionCoordinator.java
+++ b/src/com/android/systemui/car/wm/scalableui/PanelTransitionCoordinator.java
@@ -15,9 +15,10 @@
  */
 package com.android.systemui.car.wm.scalableui;
 
-import static android.view.WindowInsets.Type.systemOverlays;
-
+import static com.android.car.scalableui.Flags.enableAnimationEndEvent;
 import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.PANEL_TOKEN_ID;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.PANEL_TO_VARIANT_ID;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_ON_ANIMATION_END_EVENT_ID;
 import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_TASK_CLOSE_EVENT_ID;
 import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_TASK_OPEN_EVENT_ID;
 
@@ -25,7 +26,6 @@ import android.animation.Animator;
 import android.animation.AnimatorListenerAdapter;
 import android.animation.AnimatorSet;
 import android.animation.ValueAnimator;
-import android.graphics.Rect;
 import android.os.Build;
 import android.os.IBinder;
 import android.util.Log;
@@ -43,6 +43,7 @@ import com.android.car.scalableui.model.Transition;
 import com.android.car.scalableui.model.Variant;
 import com.android.car.scalableui.panel.Panel;
 import com.android.car.scalableui.panel.PanelPool;
+import com.android.systemui.car.wm.scalableui.panel.BasePanel;
 import com.android.systemui.car.wm.scalableui.panel.DecorPanel;
 import com.android.systemui.car.wm.scalableui.panel.PanelUtils;
 import com.android.systemui.car.wm.scalableui.panel.TaskPanel;
@@ -52,7 +53,9 @@ import com.android.wm.shell.automotive.AutoSurfaceTransactionFactory;
 import com.android.wm.shell.automotive.AutoTaskStackController;
 import com.android.wm.shell.automotive.AutoTaskStackState;
 import com.android.wm.shell.automotive.AutoTaskStackTransaction;
+import com.android.wm.shell.common.ShellExecutor;
 import com.android.wm.shell.dagger.WMSingleton;
+import com.android.wm.shell.shared.annotations.ShellMainThread;
 import com.android.wm.shell.transition.Transitions;
 
 import java.util.ArrayList;
@@ -70,10 +73,11 @@ import javax.inject.Inject;
  * based on event triggers and then applying visual updates to panels based on their current state.
  */
 @WMSingleton
-public class TaskPanelTransitionCoordinator {
-    private static final String TAG = TaskPanelTransitionCoordinator.class.getName();
+public class PanelTransitionCoordinator {
+    private static final String TAG = PanelTransitionCoordinator.class.getName();
     private static final boolean DEBUG = Build.IS_DEBUGGABLE;
     private static final String DECOR_TRANSACTION = "DECOR_TRANSACTION";
+    private static final String PANEL_TRANSACTION = "PANEL_TRANSACTION";
 
     private final AutoTaskStackController mAutoTaskStackController;
     @GuardedBy("mPendingPanelTransactions")
@@ -81,55 +85,98 @@ public class TaskPanelTransitionCoordinator {
     private AnimatorSet mRunningAnimatorSet = null;
     private final AutoSurfaceTransactionFactory mAutoSurfaceTransactionFactory;
     private final PanelUtils mPanelUtils;
+    private IBinder mActiveTransition;
     private final AutoLayoutManager mAutoLayoutManager;
+    private final ShellExecutor mMainExecutor;
 
     @Inject
-    public TaskPanelTransitionCoordinator(AutoTaskStackController autoTaskStackController,
+    public PanelTransitionCoordinator(AutoTaskStackController autoTaskStackController,
             AutoSurfaceTransactionFactory autoSurfaceTransactionFactory,
-            PanelUtils panelUtils, AutoLayoutManager autoLayoutManager) {
+            PanelUtils panelUtils,
+            AutoLayoutManager autoLayoutManager,
+            @ShellMainThread ShellExecutor mainExecutor) {
         mAutoTaskStackController = autoTaskStackController;
         mAutoSurfaceTransactionFactory = autoSurfaceTransactionFactory;
         mPanelUtils = panelUtils;
         mAutoLayoutManager = autoLayoutManager;
+        mMainExecutor = mainExecutor;
     }
 
     /**
-     * Start a new transition for a given {@link PanelTransaction}
+     * Starts a panel transition using the provided {@link PanelTransaction} that causes window
+     * state change.
+     *
+     * @param transaction The {@link PanelTransaction} object containing the details of the
+     *                    transition.
      */
     public void startTransition(PanelTransaction transaction) {
-        synchronized (mPendingPanelTransactions) {
-            Log.d(TAG, "startTransition:" + transaction);
-            updateDecorPanelByTransition(transaction);
-            IBinder transition = mAutoTaskStackController.startTransition(
-                    createAutoTaskStackTransaction(transaction));
-            mPendingPanelTransactions.put(transition, transaction);
+        if (transaction.hasWindowChanges()) {
+            mMainExecutor.execute(() -> {
+                synchronized (mPendingPanelTransactions) {
+                    IBinder transition = mAutoTaskStackController.startTransition(
+                            createAutoTaskStackTransaction(transaction));
+                    mPendingPanelTransactions.put(transition, transaction);
+                    resetUnpreparedDecorPanel(transaction);
+                    playPendingAnimations(transition, null);
+                }
+            });
+        } else {
+            // If the transaction does not involve window changes, execute it directly. Posting
+            // to the shell main thread could introduce unnecessary latency and visual lag.
+            updatePanelSurface(transaction);
         }
     }
 
-    private void updateDecorPanelByTransition(PanelTransaction panelTransaction) {
+    /**
+     * Resets {@link DecorPanel} with no {@link AutoDecor} initialized.
+     *
+     * <p>This method iterates through each panel state defined in the provided
+     * {@code PanelTransaction}. For each entry, it attempts to find the corresponding
+     * {@code DecorPanel} using its ID. If a {@code DecorPanel} is found,and it does not have an
+     * associated {@link AutoDecor} and its target variant in the
+     * transaction
+     * is set to be visible, then the {@code DecorPanel} will be reset to its
+     * default state.
+     */
+    public void resetUnpreparedDecorPanel(PanelTransaction transaction) {
+        for (Map.Entry<String, Transition> entry : transaction.getPanelTransactionStates()) {
+            DecorPanel decorPanel = mPanelUtils.getDecorPanel(
+                    p -> p.getPanelId().equals(entry.getKey()));
+            if (decorPanel == null) {
+                continue;
+            }
+            Variant toVariant = entry.getValue().getToVariant();
+            if (decorPanel.getAutoDecor() == null && toVariant.isVisible()) {
+                decorPanel.reset();
+            }
+        }
+    }
+
+    private void updatePanelSurface(PanelTransaction panelTransaction) {
+        logIfDebuggable("updatePanelSurface: " + panelTransaction);
         AutoSurfaceTransaction autoSurfaceTransaction =
                 mAutoSurfaceTransactionFactory.createTransaction(DECOR_TRANSACTION);
+        SurfaceControl.Transaction tx = new SurfaceControl.Transaction();
         for (Map.Entry<String, Transition> entry : panelTransaction.getPanelTransactionStates()) {
             Panel panel = PanelPool.getInstance().getPanel(
                     p -> p.getPanelId().equals(entry.getKey()));
             if (panel == null) {
-                if (DEBUG) {
-                    Log.d(TAG, "Panel is null for " + entry.getKey());
-                }
+                logIfDebuggable("Panel is null for " + entry.getKey());
                 continue;
             }
             Transition transition = entry.getValue();
             Variant toVariant = transition.getToVariant();
-            if (panel instanceof DecorPanel decorPanel && decorPanel.getAutoDecor() != null) {
-                if (DEBUG) {
-                    Log.d(TAG, "move decorPanel=" + decorPanel.getPanelId() + " to"
-                            + toVariant.getBounds() + " layer=" + toVariant.getLayer()
-                            + " visible=" + toVariant.isVisible());
-                }
-                autoSurfaceTransaction.setBounds(decorPanel.getAutoDecor(), toVariant.getBounds());
-                autoSurfaceTransaction.setVisibility(decorPanel.getAutoDecor(),
-                        toVariant.isVisible());
-                autoSurfaceTransaction.setZOrder(decorPanel.getAutoDecor(), toVariant.getLayer());
+            if (panel instanceof BasePanel basePanel) {
+                basePanel.update(autoSurfaceTransaction, tx, toVariant);
+            } else {
+                Log.e(TAG, "Invalid panel " + panel);
+            }
+        }
+        for (String unchangedPanelId : panelTransaction.getLockededPanelIdSet()) {
+            Panel panel = PanelPool.getInstance().getPanel(
+                    p -> p.getPanelId().equals(unchangedPanelId));
+            if (panel instanceof BasePanel basePanel) {
+                basePanel.update(autoSurfaceTransaction, tx, /* variant= */ null);
             }
         }
         autoSurfaceTransaction.apply();
@@ -159,9 +206,7 @@ public class TaskPanelTransitionCoordinator {
                     taskPanel.getRootStack() != null
                             && taskPanel.getRootStack().getId() == autoTaskStackId);
             if (tp == null || !tp.isLaunchRoot()) {
-                if (DEBUG) {
-                    Log.d(TAG, "Panel is null or not launch root" + tp);
-                }
+                logIfDebuggable("Panel is null or not launch root" + tp);
                 continue;
             }
 
@@ -223,26 +268,31 @@ public class TaskPanelTransitionCoordinator {
             panelTransaction = mPendingPanelTransactions.get(transition);
         }
         if (panelTransaction == null || panelTransaction.getAnimators().isEmpty()) {
-            if (DEBUG) {
-                Log.d(TAG, "No animations for transition " + transition);
-            }
+            logIfDebuggable("No animations for transition " + transition);
             return false;
         }
-        if (DEBUG) {
-            Log.d(TAG, "playPendingAnimations: " + panelTransaction.getAnimators().size());
-        }
+        logIfDebuggable("playPendingAnimations: " + panelTransaction.getAnimators().size());
         Trace.beginSection(TAG + "#playPendingAnimations");
-        stopRunningAnimations();
+
+        // TODO(b/409121871): resolve potential glitch after stopping previous animation.
+        stopRunningAnimations(transition);
 
         mRunningAnimatorSet = new AnimatorSet();
+        mActiveTransition = transition;
 
         long totalDuration = Long.MIN_VALUE;
         List<Animator> animationToRun = new ArrayList<>();
         for (Map.Entry<String, Animator> entry : panelTransaction.getAnimators()) {
             Animator animator = entry.getValue();
+            logIfDebuggable(
+                    entry.getKey() + " duration for animator " + animator.getTotalDuration());
             totalDuration = Math.max(totalDuration, animator.getTotalDuration());
             animationToRun.add(animator);
         }
+
+        totalDuration = Math.max(0, totalDuration);
+
+        logIfDebuggable("total duration " + totalDuration);
         animationToRun.add(createSurfaceAnimator(totalDuration, panelTransaction.getAnimators()));
         mRunningAnimatorSet.playTogether(animationToRun);
         mRunningAnimatorSet.addListener(new AnimatorListenerAdapter() {
@@ -260,22 +310,7 @@ public class TaskPanelTransitionCoordinator {
             public void onAnimationEnd(Animator animation) {
                 Trace.beginSection(TAG + "#onAnimationEnd");
                 super.onAnimationEnd(animation);
-                if (DEBUG) {
-                    Log.d(TAG, "Animation set finished " + finishCallback);
-                }
-                if (finishCallback != null) {
-                    if (DEBUG) {
-                        Log.d(TAG, "Finish the transition");
-                    }
-                    finishCallback.onTransitionFinished(/* wct= */ null);
-                }
-                synchronized (mPendingPanelTransactions) {
-                    mPendingPanelTransactions.remove(transition);
-                }
-                if (panelTransaction.getAnimationEndCallbackRunnable() != null) {
-                    panelTransaction.getAnimationEndCallbackRunnable().run();
-                }
-                Trace.endSection();
+                mayFinishTransaction(finishCallback, panelTransaction, transition);
             }
         });
         mRunningAnimatorSet.start();
@@ -283,19 +318,88 @@ public class TaskPanelTransitionCoordinator {
         return true;
     }
 
+    private void mayFinishTransaction(Transitions.TransitionFinishCallback finishCallback,
+            PanelTransaction panelTransaction, IBinder transition) {
+        logIfDebuggable("Animation set finished " + finishCallback);
+
+        if (finishCallback != null) {
+            logIfDebuggable("Finish the transition");
+            finishCallback.onTransitionFinished(/* wct= */ null);
+        }
+
+        // Enforce the surface state for panels.
+        AutoSurfaceTransaction autoSurfaceTransaction =
+                mAutoSurfaceTransactionFactory.createTransaction(PANEL_TRANSACTION);
+        for (Map.Entry<String, Transition> entry :
+                panelTransaction.getPanelTransactionStates()) {
+            BasePanel basePanel = mPanelUtils.getBasePanel(
+                    dp -> dp.getPanelId().equals(entry.getKey()));
+            if (basePanel == null) {
+                continue;
+            }
+            Variant toVariant = entry.getValue().getToVariant();
+            basePanel.update(autoSurfaceTransaction, /* tx= */ null,
+                    toVariant, /* updateChildren= */ true);
+        }
+        autoSurfaceTransaction.apply();
+
+        synchronized (mPendingPanelTransactions) {
+            mPendingPanelTransactions.remove(transition);
+            mActiveTransition = null;
+        }
+        if (panelTransaction.getAnimationEndCallbackRunnable() != null) {
+            panelTransaction.getAnimationEndCallbackRunnable().run();
+        }
+        Trace.endSection();
+
+        for (Map.Entry<String, Animator> entry : panelTransaction.getAnimators()) {
+            Transition trans = panelTransaction.getPanelTransactionState(entry.getKey());
+            if (trans == null) {
+                continue;
+            }
+            dispatchAnimationEndEvent(entry.getKey(), trans.getToVariant().getIdName());
+        }
+    }
+
+    private void dispatchAnimationEndEvent(String panelId, String variantId) {
+        if (!enableAnimationEndEvent()) {
+            return;
+        }
+        logIfDebuggable("dispatching animation end event for panel " + panelId
+                + " with variant " + variantId);
+        PanelTransaction transaction = StateManager.handleEvent(new Event.Builder(
+                SYSTEM_ON_ANIMATION_END_EVENT_ID)
+                .addToken(PANEL_TOKEN_ID, panelId)
+                .addToken(PANEL_TO_VARIANT_ID, variantId)
+                .build());
+        startTransition(transaction);
+    }
+
     /**
-     * Ends any running animations associated with this instance.
+     * Stops any currently running animation if it belongs to a transition different from the
+     * provided one.If an animation is running and its associated transition does not match the
+     * incoming{@code transition} token, the animation set is immediately advanced to its end
+     * state.
+     *
+     * @param transition The {@link IBinder} token for the incoming transition request. Used to
+     *                   check if the currently running animation is for a different transition.
      */
-    void stopRunningAnimations() {
-        if (isAnimationRunning()) {
-            if (DEBUG) {
-                Log.d(TAG, "stopRunningAnimations: has running animatorSet "
-                        + mRunningAnimatorSet.getCurrentPlayTime());
-            }
+    void stopRunningAnimations(@NonNull IBinder transition) {
+        logIfDebuggable("stopRunningAnimationsIfNeed " + transition);
+        if (isAnimationRunning() && transition != mActiveTransition) {
+            logIfDebuggable("stopRunningAnimations: has running animatorSet "
+                    + mRunningAnimatorSet.getCurrentPlayTime() + ", incoming transition = "
+                    + transition + ", active transition = " + mActiveTransition);
             mRunningAnimatorSet.end();
         }
     }
 
+    private static void logIfDebuggable(String msg) {
+        if (DEBUG) {
+            Log.d(TAG, msg);
+        }
+    }
+
     @VisibleForTesting
     boolean isAnimationRunning() {
         return mRunningAnimatorSet != null && mRunningAnimatorSet.isRunning();
@@ -327,6 +431,12 @@ public class TaskPanelTransitionCoordinator {
                     toVariant.getLayer());
             autoTaskStackTransaction.setTaskStackState(taskPanel.getRootStack().getId(),
                     autoTaskStackState);
+
+            if (toVariant.isVisible() && taskPanel.isRootTaskEmpty()
+                    && mPanelUtils.isUserUnlocked()) {
+                taskPanel.setBaseIntent(autoTaskStackTransaction);
+                logIfDebuggable("Set base intent for " + taskPanel.getPanelId());
+            }
         }
 
         return autoTaskStackTransaction;
@@ -338,22 +448,18 @@ public class TaskPanelTransitionCoordinator {
         surfaceAnimator.setDuration(duration);
         surfaceAnimator.addUpdateListener(animation -> {
             Trace.beginSection(TAG + "#updatePanelSurface");
+            logIfDebuggable("Surface animation progress " + animation.getAnimatedFraction());
             AutoSurfaceTransaction autoSurfaceTransaction =
                     mAutoSurfaceTransactionFactory.createTransaction(DECOR_TRANSACTION);
+
             SurfaceControl.Transaction tx = new SurfaceControl.Transaction();
             for (Map.Entry<String, Animator> entry : animators) {
                 String id = entry.getKey();
-                if (DEBUG) {
-                    Log.d(TAG, "panelTransaction: " + id);
-                }
                 Panel panel = PanelPool.getInstance().getPanel(p -> p.getPanelId().equals(id));
-                if (panel instanceof TaskPanel taskPanel) {
-                    updatePanelSurface(taskPanel, tx);
-                } else if (panel instanceof DecorPanel decorPanel) {
-                    updateDecorPanelSurface(decorPanel, autoSurfaceTransaction);
+                if (panel instanceof BasePanel basePanel) {
+                    basePanel.update(autoSurfaceTransaction, tx, /* variant= */ null);
                 }
             }
-
             //TODO(b/404959846): migrate to autoSurfaceTransaction here once api is added.
             tx.apply();
             autoSurfaceTransaction.apply();
@@ -361,57 +467,4 @@ public class TaskPanelTransitionCoordinator {
         });
         return surfaceAnimator;
     }
-
-    private void updateDecorPanelSurface(DecorPanel decorPanel,
-            AutoSurfaceTransaction autoSurfaceTransaction) {
-        if (decorPanel.getAutoDecor() == null) {
-            Log.e(TAG, "AutoDecor is null for " + decorPanel);
-            return;
-        }
-        Log.d(TAG, "updateDecorPanelSurface:" + decorPanel);
-        autoSurfaceTransaction.setBounds(decorPanel.getAutoDecor(), decorPanel.getBounds());
-        autoSurfaceTransaction.setVisibility(decorPanel.getAutoDecor(), decorPanel.isVisible());
-        autoSurfaceTransaction.setZOrder(decorPanel.getAutoDecor(), decorPanel.getLayer());
-    }
-
-    private void updatePanelSurface(TaskPanel taskPanel, SurfaceControl.Transaction tx) {
-        SurfaceControl sc = taskPanel.getLeash();
-        if (sc == null) {
-            Log.e(TAG, "leash is null for " + taskPanel);
-            return;
-        }
-
-        if (DEBUG) {
-            Log.d(TAG, "updatePanelSurface:" + taskPanel);
-        }
-        tx.setVisibility(sc, taskPanel.isVisible());
-        tx.setAlpha(sc, taskPanel.getAlpha());
-        tx.setLayer(sc, taskPanel.getLayer());
-        tx.setPosition(sc, taskPanel.getBounds().left, taskPanel.getBounds().top);
-        tx.setWindowCrop(sc, taskPanel.getBounds().width(), taskPanel.getBounds().height());
-        tx.setCornerRadius(sc, taskPanel.getCornerRadius());
-        tx.apply();
-
-        Rect insets = taskPanel.getInsets().toRect();
-        mAutoLayoutManager.addOrUpdateInsets(taskPanel.getRootStack(),
-                /* left */ 0, systemOverlays(),
-                new Rect(0, 0, insets.left, taskPanel.getBounds().bottom));
-        mAutoLayoutManager.addOrUpdateInsets(taskPanel.getRootStack(),
-                /* top */ 1, systemOverlays(),
-                new Rect(0, 0, taskPanel.getBounds().right, insets.top));
-        mAutoLayoutManager.addOrUpdateInsets(taskPanel.getRootStack(),
-                /* right */ 2, systemOverlays(),
-                new Rect(
-                        taskPanel.getBounds().right - insets.right,
-                        0,
-                        taskPanel.getBounds().right,
-                        taskPanel.getBounds().bottom));
-        mAutoLayoutManager.addOrUpdateInsets(taskPanel.getRootStack(),
-                /* bottom */ 3, systemOverlays(),
-                new Rect(
-                        0,
-                        taskPanel.getBounds().bottom - insets.bottom,
-                        taskPanel.getBounds().right,
-                        taskPanel.getBounds().bottom));
-    }
 }
diff --git a/src/com/android/systemui/car/wm/scalableui/panel/BasePanel.java b/src/com/android/systemui/car/wm/scalableui/panel/BasePanel.java
index 8287eefc..04ab9597 100644
--- a/src/com/android/systemui/car/wm/scalableui/panel/BasePanel.java
+++ b/src/com/android/systemui/car/wm/scalableui/panel/BasePanel.java
@@ -15,14 +15,23 @@
  */
 package com.android.systemui.car.wm.scalableui.panel;
 
+import static com.android.car.scalableui.model.Role.DEFAULT_ROLE;
+
 import android.content.Context;
 import android.graphics.Insets;
 import android.graphics.Rect;
 import android.os.Build;
+import android.util.Log;
+import android.view.SurfaceControl;
 
 import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
 
+import com.android.car.scalableui.model.PanelControllerMetadata;
+import com.android.car.scalableui.model.Role;
+import com.android.car.scalableui.model.Variant;
 import com.android.car.scalableui.panel.Panel;
+import com.android.wm.shell.automotive.AutoSurfaceTransaction;
 
 /**
  * Abstract base class for implementing a {@link Panel}.
@@ -31,37 +40,44 @@ import com.android.car.scalableui.panel.Panel;
  */
 public abstract class BasePanel implements Panel {
     protected static final boolean DEBUG = Build.isDebuggable();
+    private static final String TAG = BasePanel.class.getSimpleName();
+    protected static final String RESET_TRANSACTION = "Reset : ";
+    protected static final String REFRESH_TRANSACTION = "Refresh : ";
 
     private final Context mContext;
     private int mLayer = -1;
 
-    private int mRole = 0;
-    private Rect mBounds = null;
+    @NonNull
+    private Role mRole;
+    @NonNull
+    private Rect mBounds = new Rect();
     private boolean mIsVisible;
-    private String mId;
+    private String mPanelId;
     private float mAlpha;
     private int mDisplayId;
     private int mCornerRadius;
     @NonNull
     private Insets mInsets = Insets.NONE;
+    @Nullable
+    private PanelControllerMetadata mPanelControllerMetadata;
 
-    public BasePanel(@NonNull Context context, String id) {
+    public BasePanel(@NonNull Context context, String panelId) {
         mContext = context;
-        mId = id;
+        mPanelId = panelId;
+        mRole = DEFAULT_ROLE;
     }
 
+    @NonNull
     public Context getContext() {
         return mContext;
     }
 
-    public int getRole() {
+    @Override
+    @NonNull
+    public Role getRole() {
         return mRole;
     }
 
-    public String getId() {
-        return mId;
-    }
-
     @Override
     public int getDisplayId() {
         return mDisplayId;
@@ -70,7 +86,7 @@ public abstract class BasePanel implements Panel {
     @Override
     @NonNull
     public String getPanelId() {
-        return mId;
+        return mPanelId;
     }
 
     @Override
@@ -128,6 +144,16 @@ public abstract class BasePanel implements Panel {
         return mIsVisible;
     }
 
+    @Override
+    public void reset() {
+        logIfDebuggable("Reset panel " + getPanelId());
+    }
+
+    @Override
+    public void init() {
+        logIfDebuggable("Init panel " + getPanelId());
+    }
+
     @Override
     public void setVisibility(boolean isVisible) {
         if (mIsVisible == isVisible) {
@@ -172,17 +198,81 @@ public abstract class BasePanel implements Panel {
     }
 
     @Override
-    public void setRole(int role) {
+    public void setRole(@NonNull Role role) {
         mRole = role;
     }
 
     @Override
-    public void setInsets(Insets insets) {
+    public void setInsets(@NonNull Insets insets) {
         mInsets = insets;
     }
 
     @Override
+    @NonNull
     public Insets getInsets() {
         return mInsets;
     }
+
+    @Override
+    @Nullable
+    public PanelControllerMetadata getPanelControllerMetadata() {
+        return mPanelControllerMetadata;
+    }
+
+    /**
+     * Updates surface of the {@link BasePanel} based on the provided {@link Variant}.
+     *
+     * <p> if provided {@link Variant} is null, update the surface with the data from {@link Panel}
+     * itself.
+     *
+     * @param autoSurfaceTransaction The {@link AutoSurfaceTransaction} instance used to apply
+     *                               surface property changes. Must not be {@code null}.
+     * @param tx                     An optional {@link android.view.SurfaceControl.Transaction}.
+     *                               This parameter is currently not used in the method's body. It
+     *                               can be {@code null}.
+     * @param variant                The {@link Variant} configuration object that provides the
+     *                               desired properties (bounds, visibility, layer, corner radius,
+     *                               alpha) for the decor surface. Maybe {@code null}.
+     * @param updateChildren         Update the children components used in this panel, should only
+     *                               set to true on animationEnd or reset.
+     */
+    public abstract void update(
+            @NonNull AutoSurfaceTransaction autoSurfaceTransaction,
+            @Nullable SurfaceControl.Transaction tx,
+            @Nullable Variant variant,
+            boolean updateChildren);
+
+    /**
+     * Updates surface of the {@link BasePanel} based on the provided {@link Variant} without update
+     * children.
+     *
+     * <p> if provided {@link Variant} is null, update the surface with the data from {@link Panel}
+     * itself.
+     *
+     * @param autoSurfaceTransaction The {@link AutoSurfaceTransaction} instance used to apply
+     *                               surface property changes. Must not be {@code null}.
+     * @param tx                     An optional {@link android.view.SurfaceControl.Transaction}.
+     *                               This parameter is currently not used in the method's body. It
+     *                               can be {@code null}.
+     * @param variant                The {@link Variant} configuration object that provides the
+     *                               desired properties (bounds, visibility, layer, corner radius,
+     *                               alpha) for the decor surface. Maybe {@code null}.
+     */
+    public void update(
+            @NonNull AutoSurfaceTransaction autoSurfaceTransaction,
+            @Nullable SurfaceControl.Transaction tx,
+            @Nullable Variant variant) {
+        update(autoSurfaceTransaction, tx, variant, /* updateChildren= */ false);
+    }
+
+    public void setPanelControllerMetadata(
+            @Nullable PanelControllerMetadata panelControllerMetadata) {
+        mPanelControllerMetadata = panelControllerMetadata;
+    }
+
+    protected static void logIfDebuggable(String msg) {
+        if (DEBUG) {
+            Log.d(TAG, msg);
+        }
+    }
 }
diff --git a/src/com/android/systemui/car/wm/scalableui/panel/DecorPanel.java b/src/com/android/systemui/car/wm/scalableui/panel/DecorPanel.java
index 59c7a9c0..13487df3 100644
--- a/src/com/android/systemui/car/wm/scalableui/panel/DecorPanel.java
+++ b/src/com/android/systemui/car/wm/scalableui/panel/DecorPanel.java
@@ -16,16 +16,26 @@
 package com.android.systemui.car.wm.scalableui.panel;
 
 import android.content.Context;
+import android.graphics.Rect;
 import android.util.Log;
-import android.view.LayoutInflater;
+import android.view.SurfaceControl;
 import android.view.View;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
+import androidx.annotation.VisibleForTesting;
 
+import com.android.car.scalableui.manager.StateManager;
+import com.android.car.scalableui.model.PanelState;
+import com.android.car.scalableui.model.Variant;
+import com.android.car.scalableui.panel.DecorPanelController;
 import com.android.car.scalableui.panel.Panel;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
+import com.android.systemui.car.wm.scalableui.view.DecorPanelControllerBase;
 import com.android.wm.shell.automotive.AutoDecor;
 import com.android.wm.shell.automotive.AutoDecorManager;
+import com.android.wm.shell.automotive.AutoSurfaceTransaction;
+import com.android.wm.shell.automotive.AutoSurfaceTransactionFactory;
 import com.android.wm.shell.common.ShellExecutor;
 import com.android.wm.shell.shared.annotations.ExternalMainThread;
 
@@ -37,52 +47,71 @@ import dagger.assisted.AssistedInject;
  * A {@link AutoDecor} based implementation of a {@link Panel}.
  */
 public final class DecorPanel extends BasePanel {
-
-    private static final String ROLE_TYPE_LAYOUT = "layout";
     private static final String TAG = DecorPanel.class.getSimpleName();
 
     private final AutoDecorManager mAutoDecorManager;
     private final PanelUtils mPanelUtils;
     private final ShellExecutor mMainExecutor;
-    private AutoDecor mAutoDecor;
+    private final EventDispatcher mEventDispatcher;
+    private final AutoSurfaceTransactionFactory mAutoSurfaceTransactionFactory;
+    @VisibleForTesting
+    AutoDecor mAutoDecor;
 
+    @Nullable
     private View mDecorView;
+    @Nullable
+    DecorPanelController mDecorPanelController;
 
     @AssistedInject
-    public DecorPanel(@NonNull Context context,
+    public DecorPanel(
+            @NonNull Context context,
             AutoDecorManager autoDecorManager,
+            EventDispatcher eventDispatcher,
             PanelUtils panelUtils,
             @ExternalMainThread ShellExecutor mainExecutor,
-            @Assisted String id) {
+            AutoSurfaceTransactionFactory autoSurfaceTransactionFactory,
+            @Assisted String id
+    ) {
         super(context, id);
         mAutoDecorManager = autoDecorManager;
         mPanelUtils = panelUtils;
         mMainExecutor = mainExecutor;
+        mEventDispatcher = eventDispatcher;
+        mAutoSurfaceTransactionFactory = autoSurfaceTransactionFactory;
     }
 
+    @NonNull
     @Override
-    public void setRole(int role) {
-        if (getRole() == role) return;
-        super.setRole(role);
+    public Rect getSafeBounds() {
+        // no-op
+        return new Rect();
     }
 
+    @Override
+    public void setSafeBounds(@NonNull Rect safeBounds) {
+        // no-op
+    }
+
+    @VisibleForTesting
     @Nullable
-    private View inflateDecorView() {
-        int role = getRole();
-        String roleTypeName = getContext().getResources().getResourceTypeName(getRole());
-        LayoutInflater inflater = LayoutInflater.from(getContext());
-
-        switch (roleTypeName) {
-            case ROLE_TYPE_LAYOUT:
-                return inflater.inflate(role, null);
-            default:
-                Log.e(TAG, "Unsupported view type" + roleTypeName);
+    View inflateDecorView() {
+        View view = getRole().getView(getContext());
+        return view != null ? view : initFromController();
+    }
+
+    @Nullable
+    private View initFromController() {
+        mDecorPanelController = DecorPanelControllerBase.createDecorPanelController(
+                getContext(), getPanelControllerMetadata());
+        if (mDecorPanelController instanceof EventDispatcher.EventProducer eventProducer) {
+            eventProducer.setEventDispatcher(mEventDispatcher);
         }
-        return null;
+        return mDecorPanelController == null ? null : mDecorPanelController.getView();
     }
 
     @Override
     public void init() {
+        super.init();
         if (mPanelUtils.isUserUnlocked()) {
             reset();
         }
@@ -90,6 +119,7 @@ public final class DecorPanel extends BasePanel {
 
     @Override
     public void reset() {
+        super.reset();
         // Only modify the view and window on the main thread to prevent thread-based exceptions
         mMainExecutor.execute(() -> {
             // Remove existing autoDecor that holds the view.
@@ -98,18 +128,80 @@ public final class DecorPanel extends BasePanel {
             }
             // Reinflate and reattach the view.
             mDecorView = inflateDecorView();
-            if (mDecorView == null) return;
+            if (mDecorView == null) {
+                Log.e(TAG, "DecorView is null, fail to create AutoDecor, " + getPanelId());
+                return;
+            }
             mAutoDecor = mAutoDecorManager.createAutoDecor(mDecorView, getLayer(), getBounds(),
                     getPanelId());
             mAutoDecorManager.attachAutoDecorToDisplay(mAutoDecor, getDisplayId());
+
+            AutoSurfaceTransaction autoSurfaceTransaction = mAutoSurfaceTransactionFactory
+                    .createTransaction(RESET_TRANSACTION + getPanelId());
+
+            PanelState panelState = StateManager.getPanelState(getPanelId());
+            Variant currentVariant = panelState == null ? null : panelState.getCurrentVariant();
+
+            update(autoSurfaceTransaction, /* tx= */ null, currentVariant,
+                    /* updateChildren= */ true);
+            autoSurfaceTransaction.apply();
         });
     }
 
+    @Override
+    public void refreshTheme() {
+        if (mDecorPanelController != null) {
+            mDecorPanelController.refreshTheme();
+        }
+        reset();
+    }
+
     @Nullable
     public AutoDecor getAutoDecor() {
         return mAutoDecor;
     }
 
+    @VisibleForTesting
+    void setDecorView(View view) {
+        mDecorView = view;
+    }
+
+    @Override
+    public void update(
+            @NonNull AutoSurfaceTransaction autoSurfaceTransaction,
+            @Nullable SurfaceControl.Transaction tx,
+            @Nullable Variant variant,
+            boolean updateChildren) {
+        if (getAutoDecor() == null) {
+            Log.e(TAG, "AutoDecor is null for " + getPanelId());
+            return;
+        }
+        logIfDebuggable("updateDecorPanelSurface:" + this);
+        Rect bounds = variant == null ? getBounds() : variant.getBounds();
+        autoSurfaceTransaction.setBounds(getAutoDecor(), bounds);
+        autoSurfaceTransaction.setVisibility(getAutoDecor(),
+                variant == null ? isVisible() : variant.isVisible());
+        autoSurfaceTransaction.setZOrder(getAutoDecor(),
+                variant == null ? getLayer() : variant.getLayer());
+        autoSurfaceTransaction.setCornerRadius(getAutoDecor(),
+                variant == null ? getCornerRadius() : variant.getCornerRadius());
+        autoSurfaceTransaction.setCrop(getAutoDecor(),
+                new Rect(0, 0, bounds.width(), bounds.height()));
+        //TODO(b/404959846): replace with autoSurfaceTransaction api if available.
+        if (mDecorView != null) {
+            mDecorView.setAlpha(variant == null ? getAlpha() : variant.getAlpha());
+            mDecorView.post(() -> {
+                int vis;
+                if (variant == null) {
+                    vis = isVisible() ? View.VISIBLE : View.GONE;
+                } else {
+                    vis = variant.isVisible() ? View.VISIBLE : View.GONE;
+                }
+                mDecorView.setVisibility(vis);
+            });
+        }
+    }
+
     @AssistedFactory
     public interface Factory {
         /** Create instance of {@link DecorPanel} with specified id */
@@ -120,9 +212,9 @@ public final class DecorPanel extends BasePanel {
     public String toString() {
         return "DecorPanel{"
                 + "mId='" + getPanelId() + '\''
+                + ", mBounds=" + getBounds()
                 + ", mLayer=" + getLayer()
                 + ", mRole=" + getRole()
-                + ", mBounds=" + getBounds()
                 + ", mIsVisible=" + isVisible()
                 + ", mAlpha=" + getAlpha()
                 + ", mDisplayId=" + getDisplayId()
diff --git a/src/com/android/systemui/car/wm/scalableui/panel/PanelUtils.java b/src/com/android/systemui/car/wm/scalableui/panel/PanelUtils.java
index 7df2501a..0335d20f 100644
--- a/src/com/android/systemui/car/wm/scalableui/panel/PanelUtils.java
+++ b/src/com/android/systemui/car/wm/scalableui/panel/PanelUtils.java
@@ -15,16 +15,27 @@
  */
 package com.android.systemui.car.wm.scalableui.panel;
 
+import android.annotation.NonNull;
 import android.app.ActivityManager;
+import android.app.TaskInfo;
+import android.content.ComponentName;
 import android.content.Context;
+import android.content.pm.ActivityInfo;
+import android.content.pm.PackageInfo;
+import android.content.pm.PackageManager;
 import android.os.UserManager;
+import android.util.Log;
 
 import androidx.annotation.Nullable;
 
+import com.android.car.scalableui.model.PanelControllerMetadata;
 import com.android.car.scalableui.panel.PanelPool;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.wm.shell.dagger.WMSingleton;
 
+import java.util.HashSet;
+import java.util.List;
+import java.util.Set;
 import java.util.function.Predicate;
 
 import javax.inject.Inject;
@@ -66,6 +77,30 @@ public class PanelUtils {
                 p -> (p instanceof TaskPanel tp) && predicate.test(tp));
     }
 
+    /**
+     * Retrieves a {@link DecorPanel} that satisfies the given {@link Predicate}.
+     *
+     * @param predicate The predicate to test against potential {@link DecorPanel} instances.
+     * @return The matching {@link DecorPanel}, or null if none is found.
+     */
+    @Nullable
+    public DecorPanel getDecorPanel(Predicate<DecorPanel> predicate) {
+        return (DecorPanel) PanelPool.getInstance().getPanel(
+                p -> (p instanceof DecorPanel decorPanel) && predicate.test(decorPanel));
+    }
+
+    /**
+     * Retrieves a {@link BasePanel} that satisfies the given {@link Predicate}.
+     *
+     * @param predicate The predicate to test against potential {@link BasePanel} instances.
+     * @return The matching {@link BasePanel}, or null if none is found.
+     */
+    @Nullable
+    public BasePanel getBasePanel(Predicate<BasePanel> predicate) {
+        return (BasePanel) PanelPool.getInstance().getPanel(
+                p -> (p instanceof BasePanel basePanel) && predicate.test(basePanel));
+    }
+
     /**
      * Checks if the user is unlocked.
      */
@@ -76,4 +111,122 @@ public class PanelUtils {
 
         return mUserManager != null && mUserManager.isUserUnlocked(userId);
     }
+
+    /**
+     * Helper method to safely extract the ComponentName from a TaskInfo.
+     * It checks topActivity, realActivity, baseActivity, and finally the baseIntent
+     * in that order to find a valid component.
+     *
+     * @param taskInfo The TaskInfo object.
+     * @return The ComponentName associated with the task, or null if it cannot be determined.
+     */
+    @Nullable
+    public ComponentName getTaskComponentName(@Nullable TaskInfo taskInfo) {
+        if (taskInfo == null) {
+            return null;
+        }
+
+        // 1. Try topActivity
+        if (taskInfo.topActivity != null) {
+            return taskInfo.topActivity;
+        }
+
+        // 2. Try realActivity
+        if (taskInfo.realActivity != null) {
+            return taskInfo.realActivity;
+        }
+
+        // 3. Try baseActivity (the original attempt)
+        if (taskInfo.baseActivity != null) {
+            return taskInfo.baseActivity;
+        }
+
+        // 4. Try getting the component from the baseIntent
+        ComponentName component = taskInfo.baseIntent.getComponent();
+        if (component != null) {
+            return component;
+        }
+
+        // If none of the above worked, return null
+        Log.w(TAG, "Could not determine component for taskId: " + taskInfo.taskId);
+        return null;
+    }
+
+    /**
+     * Helper method to safely extract the package name from a TaskInfo.
+     * See {@link #getTaskComponentName} for ordering of retrieving component. If not present,
+     * attempt to fall back to baseIntent package.
+     *
+     * @param taskInfo The TaskInfo object.
+     * @return The package name associated with the task, or null if it cannot be determined.
+     */
+    @Nullable
+    public String getTaskPackageName(@Nullable TaskInfo taskInfo) {
+        if (taskInfo == null) {
+            return null;
+        }
+
+        ComponentName taskComponentName = getTaskComponentName(taskInfo);
+        if (taskComponentName != null) {
+            return taskComponentName.getPackageName();
+        }
+
+        // If component is null, the package might be set explicitly on the intent
+        String intentPackage = taskInfo.baseIntent.getPackage();
+        if (intentPackage != null) {
+            return intentPackage;
+        }
+
+        // If none of the above worked, return null
+        Log.w(TAG, "Could not determine package name for taskId: " + taskInfo.taskId);
+        return null;
+    }
+
+    /**
+     * Parses persistent activity {@link ComponentName}s from package names specified in the
+     * configuration.
+     */
+    @NonNull
+    public Set<ComponentName> parsePersistentActivitiesFromPackages(
+            @NonNull PanelControllerMetadata panelControllerMetadata, @NonNull String configName) {
+        Set<ComponentName> set = new HashSet<>();
+        if (!panelControllerMetadata.hasConfiguration(configName)) {
+            return set;
+        }
+        List<String> list = panelControllerMetadata.getListConfiguration(configName);
+        if (list == null) {
+            String value = panelControllerMetadata.getStringConfiguration(configName);
+            set.addAll(getComponentNamesFromPackage(value));
+        } else {
+            for (String item : list) {
+                set.addAll(getComponentNamesFromPackage(item));
+            }
+        }
+        return set;
+    }
+
+    @NonNull
+    private Set<ComponentName> getComponentNamesFromPackage(@Nullable String packageName) {
+        Set<ComponentName> set = new HashSet<>();
+        if (packageName == null) {
+            return set;
+        }
+        PackageManager pm = mContext.getPackageManager();
+        try {
+            // User may not be unlocked when parsing package info - use MATCH_DIRECT_BOOT_AWARE
+            // and MATCH_DIRECT_BOOT_UNAWARE to retrieve activities regardless of user state.
+            PackageInfo packageInfo = pm.getPackageInfoAsUser(packageName,
+                    PackageManager.GET_ACTIVITIES | PackageManager.MATCH_DIRECT_BOOT_AWARE
+                            | PackageManager.MATCH_DIRECT_BOOT_UNAWARE,
+                    ActivityManager.getCurrentUser());
+            if (packageInfo != null && packageInfo.activities != null) {
+                for (ActivityInfo ai : packageInfo.activities) {
+                    set.add(ai.getComponentName());
+                }
+            }
+        } catch (PackageManager.NameNotFoundException e) {
+            Log.e(TAG, "Fail to find package Info for " + packageName + ", e=" + e);
+        }
+        return set;
+    }
 }
diff --git a/src/com/android/systemui/car/wm/scalableui/panel/TaskPanel.java b/src/com/android/systemui/car/wm/scalableui/panel/TaskPanel.java
index 8b723003..4d3804ab 100644
--- a/src/com/android/systemui/car/wm/scalableui/panel/TaskPanel.java
+++ b/src/com/android/systemui/car/wm/scalableui/panel/TaskPanel.java
@@ -15,11 +15,14 @@
  */
 package com.android.systemui.car.wm.scalableui.panel;
 
+import static android.view.WindowInsets.Type.systemOverlays;
 
+import static com.android.car.scalableui.Flags.enableDecor;
+import static com.android.systemui.car.Flags.displayCompatibilityAutoDecorSafeRegion;
 import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.PANEL_TOKEN_ID;
 import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_TASK_PANEL_EMPTY_EVENT_ID;
 
-import android.annotation.MainThread;
+import android.annotation.SuppressLint;
 import android.app.ActivityManager;
 import android.app.ActivityOptions;
 import android.app.PendingIntent;
@@ -27,6 +30,7 @@ import android.car.app.CarActivityManager;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
+import android.graphics.Rect;
 import android.os.Build;
 import android.os.UserHandle;
 import android.util.ArraySet;
@@ -38,56 +42,118 @@ import androidx.annotation.Nullable;
 import androidx.annotation.VisibleForTesting;
 
 import com.android.car.internal.dep.Trace;
-
+import com.android.car.scalableui.manager.StateManager;
+import com.android.car.scalableui.model.Decor;
 import com.android.car.scalableui.model.Event;
+import com.android.car.scalableui.model.PanelControllerMetadata;
 import com.android.car.scalableui.model.PanelState;
+import com.android.car.scalableui.model.Role;
+import com.android.car.scalableui.model.Variant;
 import com.android.car.scalableui.panel.Panel;
+import com.android.car.scalableui.panel.TaskPanelController;
 import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.car.wm.AutoCaptionBarViewFactoryImpl;
 import com.android.systemui.car.wm.scalableui.AutoTaskStackHelper;
 import com.android.systemui.car.wm.scalableui.EventDispatcher;
+import com.android.systemui.car.wm.scalableui.panel.controller.PanelControllerInitializer;
+import com.android.wm.shell.ShellTaskOrganizer;
+import com.android.wm.shell.automotive.AutoCaptionController;
+import com.android.wm.shell.automotive.AutoDecor;
+import com.android.wm.shell.automotive.AutoDecorManager;
+import com.android.wm.shell.automotive.AutoLayoutManager;
+import com.android.wm.shell.automotive.AutoSurfaceTransaction;
+import com.android.wm.shell.automotive.AutoSurfaceTransactionFactory;
 import com.android.wm.shell.automotive.AutoTaskStackController;
 import com.android.wm.shell.automotive.AutoTaskStackState;
 import com.android.wm.shell.automotive.AutoTaskStackTransaction;
 import com.android.wm.shell.automotive.RootTaskStack;
 import com.android.wm.shell.automotive.RootTaskStackListener;
+import com.android.wm.shell.common.ShellExecutor;
+import com.android.wm.shell.shared.annotations.ShellMainThread;
 
 import dagger.assisted.Assisted;
 import dagger.assisted.AssistedFactory;
 import dagger.assisted.AssistedInject;
 
+import java.util.Arrays;
+import java.util.HashMap;
+import java.util.Map;
+import java.util.Objects;
 import java.util.Set;
+import java.util.stream.Collectors;
+import java.util.stream.IntStream;
 
 /**
  * A {@link RootTaskStack} based implementation of a {@link Panel}.
  */
 public final class TaskPanel extends BasePanel {
     private static final String TAG = TaskPanel.class.getSimpleName();
-    private static final String ROLE_TYPE_STRING = "string";
-    private static final String ROLE_TYPE_ARRAY = "array";
+
     private static final boolean DEBUG = Build.isDebuggable();
+    private static final String TASK_PANEL_TRANSACTION = ", TASK_PANEL_TRANSACTION";
 
+    @NonNull
     private final AutoTaskStackController mAutoTaskStackController;
+    @NonNull
     private final CarServiceProvider mCarServiceProvider;
+    @NonNull
     private final Set<ComponentName> mPersistedActivities;
+    @NonNull
     private final AutoTaskStackHelper mAutoTaskStackHelper;
+    @NonNull
+    private final AutoCaptionController mAutoCaptionController;
+    @NonNull
+    private final AutoCaptionBarViewFactoryImpl mAutoCaptionBarViewFactoryImpl;
+    @NonNull
     private final TaskPanelInfoRepository mTaskPanelInfoRepository;
+    @NonNull
     private final EventDispatcher mEventDispatcher;
-
+    @NonNull
+    private final PanelControllerInitializer mPanelControllerInitializer;
+    @NonNull
+    private final PanelUtils mPanelUtils;
+    @NonNull
+    private final AutoDecorManager mAutoDecorManager;
+    @NonNull
+    private final Context mContext;
+    @Nullable
     private CarActivityManager mCarActivityManager;
     private int mRootTaskId = -1;
+    @Nullable
     private SurfaceControl mLeash;
     private boolean mIsLaunchRoot;
+    @NonNull
+    private Rect mSafeBounds = new Rect();
+    @Nullable
     private RootTaskStack mRootTaskStack;
-    private PanelUtils mPanelUtils;
+    @NonNull
+    private final Map<String, AutoDecor> mExistingAutoDecors;
+    @Nullable
+    private String mTopTaskPackageName;
+    @Nullable
+    private TaskPanelController mTaskPanelController;
+    @NonNull
+    private final AutoLayoutManager mAutoLayoutManager;
+    @NonNull
+    private final ShellExecutor mMainExecutor;
+    @NonNull
+    private final AutoSurfaceTransactionFactory mAutoSurfaceTransactionFactory;
 
     @AssistedInject
     public TaskPanel(AutoTaskStackController autoTaskStackController,
             @NonNull Context context,
             CarServiceProvider carServiceProvider,
             AutoTaskStackHelper autoTaskStackHelper,
+            ShellTaskOrganizer shellTaskOrganizer,
+            AutoCaptionController autoCaptionController,
             PanelUtils panelUtils,
             TaskPanelInfoRepository taskPanelInfoRepository,
+            AutoDecorManager autoDecorManager,
             EventDispatcher dispatcher,
+            PanelControllerInitializer panelControllerInitializer,
+            AutoLayoutManager autoLayoutManager,
+            @ShellMainThread ShellExecutor mainExecutor,
+            AutoSurfaceTransactionFactory autoSurfaceTransactionFactory,
             @Assisted String id) {
         super(context, id);
         mAutoTaskStackController = autoTaskStackController;
@@ -97,6 +163,16 @@ public final class TaskPanel extends BasePanel {
         mEventDispatcher = dispatcher;
         mPersistedActivities = new ArraySet<>();
         mPanelUtils = panelUtils;
+        mAutoCaptionController = autoCaptionController;
+        mAutoCaptionBarViewFactoryImpl =
+                new AutoCaptionBarViewFactoryImpl(context, shellTaskOrganizer);
+        mAutoDecorManager = autoDecorManager;
+        mContext = context;
+        mPanelControllerInitializer = panelControllerInitializer;
+        mAutoLayoutManager = autoLayoutManager;
+        mMainExecutor = mainExecutor;
+        mAutoSurfaceTransactionFactory = autoSurfaceTransactionFactory;
+        mExistingAutoDecors = new HashMap<>();
     }
 
     /**
@@ -104,8 +180,10 @@ public final class TaskPanel extends BasePanel {
      */
     @Override
     public void init() {
+        super.init();
         mCarServiceProvider.addListener(
                 car -> {
+                    logIfDebuggable("On car connected:" + this);
                     mCarActivityManager = car.getCarManager(CarActivityManager.class);
                     trySetPersistentActivity();
                 });
@@ -125,6 +203,8 @@ public final class TaskPanel extends BasePanel {
                                     getDisplayId(),
                                     mRootTaskId);
                         }
+                        setupToolbarAndSafeRegion();
+                        setLeash(mRootTaskStack.getLeash());
 
                         if (mPanelUtils.isUserUnlocked()) {
                             reset();
@@ -139,6 +219,7 @@ public final class TaskPanel extends BasePanel {
 
                     @Override
                     public void onRootTaskStackDestroyed(@NonNull RootTaskStack rootTaskStack) {
+                        mAutoCaptionController.removeSafeRegionAndCaptionRegion(rootTaskStack);
                         mRootTaskStack = null;
                         mRootTaskId = -1;
                     }
@@ -146,20 +227,27 @@ public final class TaskPanel extends BasePanel {
                     @Override
                     public void onTaskAppeared(ActivityManager.RunningTaskInfo taskInfo,
                             SurfaceControl leash) {
+
+                        mTopTaskPackageName = mPanelUtils.getTaskPackageName(taskInfo);
+                        if (mTopTaskPackageName == null) {
+                            Log.e(TAG, "onTaskAppeared: Failed to get package name for task "
+                                    + taskInfo.taskId);
+                            return;
+                        }
+
                         mAutoTaskStackHelper.setTaskUntrimmableIfNeeded(taskInfo);
-                        mTaskPanelInfoRepository.onTaskAppearedOnPanel(getId(), taskInfo);
+                        mTaskPanelInfoRepository.onTaskAppearedOnPanel(getPanelId(), taskInfo);
                     }
 
                     @Override
                     public void onTaskInfoChanged(ActivityManager.RunningTaskInfo taskInfo) {
-                        mTaskPanelInfoRepository.onTaskChangedOnPanel(getId(), taskInfo);
+                        mTaskPanelInfoRepository.onTaskChangedOnPanel(getPanelId(), taskInfo);
                     }
 
                     @Override
                     public void onTaskVanished(ActivityManager.RunningTaskInfo taskInfo) {
-                        mTaskPanelInfoRepository.onTaskVanishedOnPanel(getId(), taskInfo);
-                        if (mRootTaskStack != null
-                                && mRootTaskStack.getRootTaskInfo().numActivities == 0) {
+                        mTaskPanelInfoRepository.onTaskVanishedOnPanel(getPanelId(), taskInfo);
+                        if (isRootTaskEmpty()) {
                             mEventDispatcher.executeTransaction(new Event.Builder(
                                     SYSTEM_TASK_PANEL_EMPTY_EVENT_ID).addToken(PANEL_TOKEN_ID,
                                     getPanelId()).build());
@@ -170,6 +258,7 @@ public final class TaskPanel extends BasePanel {
 
     @Override
     public void reset() {
+        super.reset();
         if (getRootStack() == null) {
             Log.e(TAG, "Cannot reset when root stack is null for panel" + getPanelId());
             return;
@@ -181,10 +270,107 @@ public final class TaskPanel extends BasePanel {
         if (isVisible()) {
             setBaseIntent(autoTaskStackTransaction);
         }
-        mAutoTaskStackController.startTransition(autoTaskStackTransaction);
+        mMainExecutor.execute(
+                () -> mAutoTaskStackController.startTransition(autoTaskStackTransaction));
+
+        AutoSurfaceTransaction autoSurfaceTransaction = mAutoSurfaceTransactionFactory
+                .createTransaction(RESET_TRANSACTION + getPanelId());
+        SurfaceControl.Transaction tx = new SurfaceControl.Transaction();
+
+        PanelState panelState = StateManager.getPanelState(getPanelId());
+        Variant currentVariant = panelState == null ? null : panelState.getCurrentVariant();
+
+        update(autoSurfaceTransaction, tx, currentVariant, /* updateChildren= */ true);
+
+        tx.apply();
+        autoSurfaceTransaction.apply();
+    }
+
+    private void updateDecors(@NonNull AutoSurfaceTransaction autoSurfaceTransaction,
+            @Nullable Variant variant) {
+        logIfDebuggable("Update " + getPanelId() + " decors, with variant" + variant);
+        if (!enableDecor()) {
+            return;
+        }
+
+        mMainExecutor.execute(() -> {
+            if (getRootStack() == null) {
+                return;
+            }
+
+            Map<String, Decor> decors = variant == null
+                    ? getCurrentDecors()
+                    : variant.getDecors();
+
+            logIfDebuggable("Update " + getPanelId() + " decors, with decors" + decors);
+
+            decors.forEach((id, decor) -> {
+                logIfDebuggable("Create decor " + id);
+                AutoDecor autoDecor = mExistingAutoDecors.getOrDefault(id,
+                        mAutoDecorManager.createAutoDecor(decor.getView(mContext),
+                                decor.getLayer(), getSafeBounds(), decor.getId()));
+                if (!mExistingAutoDecors.containsKey(id)) {
+                    mAutoDecorManager.attachAutoDecorToTask(autoDecor, getRootTaskId());
+                    mExistingAutoDecors.put(id, autoDecor);
+                }
+
+                updateAutoDecor(autoDecor, decor, autoSurfaceTransaction);
+            });
+
+            // Remove the AutoDecor that is no longer there.
+            Set<Map.Entry<String, AutoDecor>> decorToRemove =
+                    mExistingAutoDecors.entrySet().stream()
+                            .filter(entry -> !variant.getDecors().containsKey(entry.getKey()))
+                            .peek(entry -> {
+                                logIfDebuggable("Remove decor" + entry.getKey());
+                                mAutoDecorManager.removeAutoDecor(entry.getValue());
+                            })
+                            .collect(Collectors.toSet());
+            if (!decorToRemove.isEmpty()) {
+                decorToRemove.forEach(entry -> mExistingAutoDecors.remove(entry.getKey()));
+            }
+        });
+    }
+
+    @NonNull
+    private Map<String, Decor> getCurrentDecors() {
+        PanelState panelState = StateManager.getPanelState(getPanelId());
+        Variant currentVariant = panelState == null ? null : panelState.getCurrentVariant();
+        return currentVariant == null ? new HashMap<>() : currentVariant.getDecors();
     }
 
-    private void setBaseIntent(AutoTaskStackTransaction autoTaskStackTransaction) {
+    private void updateAutoDecor(AutoDecor autoDecor, Decor decor,
+            AutoSurfaceTransaction autoSurfaceTransaction) {
+        Rect bounds = new Rect(0, 0, getBounds().width(), getBounds().height());
+        autoSurfaceTransaction.setBounds(autoDecor, bounds);
+        autoSurfaceTransaction.setVisibility(autoDecor, true);
+        autoSurfaceTransaction.setZOrder(autoDecor, decor.getLayer());
+        autoSurfaceTransaction.setCornerRadius(autoDecor, getCornerRadius());
+        autoSurfaceTransaction.setCrop(autoDecor, bounds);
+    }
+
+    @Override
+    public void refreshTheme() {
+        mExistingAutoDecors.forEach((id, autoDecor) -> {
+            mAutoDecorManager.removeAutoDecor(autoDecor);
+            mExistingAutoDecors.remove(id);
+        });
+        AutoSurfaceTransaction autoSurfaceTransaction = mAutoSurfaceTransactionFactory
+                .createTransaction(REFRESH_TRANSACTION + getPanelId());
+        updateDecors(autoSurfaceTransaction, null);
+        autoSurfaceTransaction.apply();
+    }
+
+    /**
+     * Sets the base intent for the provided AutoTaskStackTransaction.
+     *
+     * This method configures and sends a PendingIntent based on the default intent
+     * of this component, targeting the root task of the current root stack.
+     * It will return early if no default intent or root task info is available.
+     *
+     * @param autoTaskStackTransaction The transaction to which the base intent will be applied.
+     */
+    public void setBaseIntent(AutoTaskStackTransaction autoTaskStackTransaction) {
         if (getDefaultIntent() == null || getRootStack().getRootTaskInfo() == null) {
             return;
         }
@@ -200,6 +386,7 @@ public final class TaskPanel extends BasePanel {
                 PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
         autoTaskStackTransaction.sendPendingIntent(pendingIntent, defaultIntent,
                 options.toBundle());
+        logIfDebuggable("setBaseIntent:" + this);
         Trace.endSection();
     }
 
@@ -212,10 +399,7 @@ public final class TaskPanel extends BasePanel {
      * Returns the task ID of the root task associated with this panel.
      */
     public int getRootTaskId() {
-        if (mRootTaskStack == null) {
-            return -1;
-        }
-        return mRootTaskStack.getRootTaskInfo().taskId;
+        return mRootTaskId;
     }
 
     /**
@@ -225,6 +409,9 @@ public final class TaskPanel extends BasePanel {
      */
     @Nullable
     public Intent getDefaultIntent() {
+        if (mTaskPanelController != null) {
+            return mTaskPanelController.getDefaultComponent();
+        }
         ComponentName componentName = mAutoTaskStackHelper.getDefaultIntent(getPanelId());
         if (componentName == null) {
             return null;
@@ -235,11 +422,17 @@ public final class TaskPanel extends BasePanel {
         return defaultIntent;
     }
 
+    @Nullable
     public SurfaceControl getLeash() {
         return mLeash;
     }
 
-    public void setLeash(SurfaceControl leash) {
+    @Nullable
+    public String getTopTaskPackageName() {
+        return mTopTaskPackageName;
+    }
+
+    public void setLeash(@Nullable SurfaceControl leash) {
         mLeash = leash;
     }
 
@@ -250,34 +443,127 @@ public final class TaskPanel extends BasePanel {
         return mIsLaunchRoot;
     }
 
+    @NonNull
+    @Override
+    public Rect getSafeBounds() {
+        return mSafeBounds;
+    }
+
+    @Override
+    public void setSafeBounds(@NonNull Rect safeBounds) {
+        if (safeBounds.isEmpty() && !getBounds().isEmpty()) {
+            throw new IllegalArgumentException(
+                    "Tried setting incorrect safe bounds: " + safeBounds + "on panel: "
+                            + getPanelId());
+        }
+        mSafeBounds = safeBounds;
+        setupToolbarAndSafeRegion();
+    }
+
     @Override
-    public void setRole(int role) {
+    public void setRole(@NonNull Role role) {
         if (getRole() == role) return;
         super.setRole(role);
-        String roleTypeName = getContext().getResources().getResourceTypeName(getRole());
-        switch (roleTypeName) {
-            case ROLE_TYPE_STRING:
-                String roleString = getContext().getResources().getString(getRole());
-                if (PanelState.DEFAULT_ROLE.equals(roleString)) {
-                    mIsLaunchRoot = true;
-                    return;
-                }
-                mPersistedActivities.clear();
-                ComponentName componentName = ComponentName.unflattenFromString(roleString);
-                mPersistedActivities.add(componentName);
-                break;
-            case ROLE_TYPE_ARRAY:
+
+        if (getRole().isDefault()) {
+            mIsLaunchRoot = true;
+            return;
+        } else {
+            ComponentName[] persistedActivities = getRole().getPersistedActivities();
+            if (persistedActivities != null) {
                 mPersistedActivities.clear();
-                String[] componentNameStrings = getContext().getResources().getStringArray(
-                        getRole());
-                mPersistedActivities.addAll(convertToComponentNames(componentNameStrings));
-                break;
-            default: {
-                Log.e(TAG, "Role type is not supported " + roleTypeName);
+                mPersistedActivities.addAll(Arrays.asList(persistedActivities));
             }
         }
     }
 
+
+    /**
+     * Calculates the four rectangular areas representing the insets of this {@link TaskPanel}.
+     *
+     * <p>This method uses the inset values and bounds of this {@link TaskPanel} (or an optionally
+     * provided {@link Variant}) to define four distinct {@link Rect} objects. Each rectangle
+     * corresponds to the screen area effectively occupied by the left, top, right, or bottom
+     * inset, relative to the panel's bounds.
+     *
+     * @param variant An optional {@link Variant} to use for calculating insets. If null, the
+     *                current panel's insets and bounds are used.
+     * @return An array of {@link Rect} objects of size 4, ordered as follows:
+     * <ul>
+     * <li>Index 0: Rectangle representing the left inset area.</li>
+     * <li>Index 1: Rectangle representing the top inset area.</li>
+     * <li>Index 2: Rectangle representing the right inset area.</li>
+     * <li>Index 3: Rectangle representing the bottom inset area.</li>
+     * </ul>
+     */
+    public Rect[] getInsetRects(@Nullable Variant variant) {
+        Rect insets = variant == null ? getInsets().toRect() : variant.getInsets().toRect();
+        Rect bounds = variant == null ? getBounds() : variant.getBounds();
+
+        Rect[] insetSides = new Rect[4];
+        insetSides[0] = new Rect(0, 0, insets.left, bounds.bottom);
+        insetSides[1] = new Rect(0, 0, bounds.right, insets.top);
+        insetSides[2] = new Rect(bounds.right - insets.right, 0, bounds.right, bounds.bottom);
+        insetSides[3] = new Rect(0, bounds.bottom - insets.bottom, bounds.right, bounds.bottom);
+        return insetSides;
+    }
+
+    @Override
+    public void update(
+            @NonNull AutoSurfaceTransaction autoSurfaceTransaction,
+            @Nullable SurfaceControl.Transaction tx,
+            @Nullable Variant variant,
+            boolean updateChildren) {
+        if (getRootStack() == null) {
+            Log.e(TAG, "RootStack is null for " + getPanelId());
+            return;
+        }
+        logIfDebuggable(
+                "update TaskPanel:" + getPanelId() + ", updateChildren =" + updateChildren + ", "
+                        + "variant" + variant);
+        int taskId = getRootTaskId();
+        Rect bounds = variant == null ? getBounds() : variant.getBounds();
+        autoSurfaceTransaction.setTaskSurfaceCrop(taskId,
+                new Rect(0, 0, bounds.width(), bounds.height()));
+        autoSurfaceTransaction.setTaskSurfacePosition(taskId, bounds.left,
+                bounds.top);
+        autoSurfaceTransaction.setTaskSurfaceCornerRadius(taskId,
+                variant == null ? getCornerRadius() : variant.getCornerRadius());
+
+        //TODO(b/404959846): move following to AutoSurfaceTransaction
+        if (tx != null && getLeash() != null) {
+            tx.setVisibility(getLeash(), variant == null ? isVisible() : variant.isVisible());
+            tx.setAlpha(getLeash(), variant == null ? getAlpha() : variant.getAlpha());
+            tx.setLayer(getLeash(), variant == null ? getLayer() : variant.getLayer());
+        } else {
+            Log.e(TAG, "leash is " + getLeash() + ", tx is " + tx);
+        }
+
+        Rect[] panelInsets = getInsetRects(variant);
+        IntStream.range(0, panelInsets.length).forEach(sideIndex -> {
+            mAutoLayoutManager.addOrUpdateInsets(getRootStack(), sideIndex,
+                    systemOverlays(), panelInsets[sideIndex]);
+        });
+        if (updateChildren) {
+            updateDecors(autoSurfaceTransaction, variant);
+        }
+    }
+
+    @Override
+    public void setPanelControllerMetadata(
+            @Nullable PanelControllerMetadata panelControllerMetadata) {
+        if (Objects.equals(getPanelControllerMetadata(), panelControllerMetadata)) {
+            logIfDebuggable(getPanelId() + ": PanelControllerMetadata unchanged.");
+            return;
+        }
+        super.setPanelControllerMetadata(panelControllerMetadata);
+        mTaskPanelController = mPanelControllerInitializer.createTaskPanelController(
+                panelControllerMetadata);
+        if (mTaskPanelController != null) {
+            mTaskPanelController.registerTaskPanelHandler(this::trySetPersistentActivity);
+        }
+    }
+
     private ArraySet<ComponentName> convertToComponentNames(String[] componentStrings) {
         ArraySet<ComponentName> componentNames = new ArraySet<>(componentStrings.length);
         for (int i = componentStrings.length - 1; i >= 0; i--) {
@@ -286,19 +572,21 @@ public final class TaskPanel extends BasePanel {
         return componentNames;
     }
 
+    @SuppressLint("MissingPermission")
     private void trySetPersistentActivity() {
         if (mCarActivityManager == null || mRootTaskStack == null) {
             if (DEBUG) {
                 Log.d(TAG,
-                        "mCarActivityManager or mRootTaskStack is null, [" + getId() + ","
+                        "mCarActivityManager or mRootTaskStack is null, [" + getPanelId() + ","
                                 + mCarActivityManager + ", " + mRootTaskStack + "]");
             }
             return;
         }
 
-        if (getRole() == 0) {
+        if (getRole().getPersistedActivities() == null
+                || getRole().getPersistedActivities().length == 0) {
             if (DEBUG) {
-                Log.d(TAG, "mRole is 0, [" + getPanelId() + "]");
+                Log.d(TAG, "Persistent Activities is empty, [" + getPanelId() + "]");
             }
             return;
         }
@@ -310,9 +598,96 @@ public final class TaskPanel extends BasePanel {
             return;
         }
 
-        mCarActivityManager.setPersistentActivitiesOnRootTask(
-                mPersistedActivities.stream().toList(),
-                mRootTaskStack.getRootTaskInfo().token.asBinder());
+        if (mTaskPanelController != null
+                && !mTaskPanelController.getPersistentActivities().isEmpty()) {
+            mCarActivityManager.setPersistentActivitiesOnRootTask(
+                    mTaskPanelController.getPersistentActivities().stream().toList(),
+                    mRootTaskStack.getRootTaskInfo().token.asBinder());
+        } else {
+            mCarActivityManager.setPersistentActivitiesOnRootTask(
+                    mPersistedActivities.stream().toList(),
+                    mRootTaskStack.getRootTaskInfo().token.asBinder());
+        }
+    }
+
+    /**
+     * Checks if the root task stack exists and is currently empty (contains no activities).
+     *
+     * @return True if mRootTaskStack is not null and the root task has zero activities, false
+     * otherwise.
+     */
+    public boolean isRootTaskEmpty() {
+        return mRootTaskStack != null
+                && mRootTaskStack.getRootTaskInfo().numActivities == 0;
+    }
+
+    private void setupToolbarAndSafeRegion() {
+        if (!displayCompatibilityAutoDecorSafeRegion()) {
+            return;
+        }
+        if (mRootTaskStack == null) {
+            logVerbose("Root TaskStack not set for panel: " + getPanelId());
+            return;
+        }
+        if (mSafeBounds.isEmpty()) {
+            // TODO(b/409067170): update AutoCaptionController API to be able to set these values
+            //  independently
+            logVerbose("Invalid Safe Bounds, not setting safe region for panel: " + getPanelId());
+            return;
+        }
+        if (getBounds() == null || getBounds().isEmpty()) {
+            logVerbose("Null or invalid panel bounds, not setting safe region for panel: "
+                    + getPanelId());
+            return;
+        }
+        if (mSafeBounds.equals(getBounds())) {
+            logVerbose("SafeBounds equivalent to panel bounds, not setting safe region for panel: "
+                    + getPanelId());
+            return;
+        }
+
+        Rect toolbarBounds = calculateToolbarBounds(getBounds(), getSafeBounds());
+        if (toolbarBounds.isEmpty()) {
+            logVerbose("Toolbar with bounds: " + toolbarBounds + " cannot be added to panel: "
+                    + getPanelId());
+            return;
+        }
+        toolbarBounds.offset(-getBounds().left, -getBounds().top);
+
+        logVerbose("Setting up toolbar and safe region with following values: "
+                + "rootTaskStack = " + mRootTaskStack
+                + ", safe bounds = " + mSafeBounds
+                + ", toolbar bounds = " + toolbarBounds
+                + ", panel bounds = " + getBounds());
+
+        mAutoCaptionController.setSafeRegionAndCaptionRegion(mRootTaskStack, mSafeBounds,
+                toolbarBounds, mAutoCaptionBarViewFactoryImpl);
+    }
+
+    @NonNull
+    private Rect calculateToolbarBounds(@NonNull Rect panelBounds, @NonNull Rect safeBounds) {
+        // TODO(b/409067170): remove this when AutoCaptionController API is able to handle safe
+        //  region and toolbar separately
+        if (panelBounds.top < safeBounds.top) {
+            return new Rect(safeBounds.left, panelBounds.top, safeBounds.right, safeBounds.top);
+        }
+        if (panelBounds.bottom > safeBounds.bottom) {
+            return new Rect(safeBounds.left, safeBounds.bottom, safeBounds.right,
+                    panelBounds.bottom);
+        }
+        if (panelBounds.left < safeBounds.left) {
+            return new Rect(panelBounds.left, safeBounds.top, safeBounds.left, safeBounds.bottom);
+        }
+        if (panelBounds.right > safeBounds.right) {
+            return new Rect(safeBounds.right, safeBounds.top, panelBounds.right, safeBounds.bottom);
+        }
+        return new Rect();
+    }
+
+    private void logVerbose(String message) {
+        if (DEBUG) {
+            Log.v(TAG, message);
+        }
     }
 
     @VisibleForTesting
@@ -322,13 +697,21 @@ public final class TaskPanel extends BasePanel {
 
     @Override
     public String toString() {
+
+        String decorString = mExistingAutoDecors.isEmpty()
+                ? "Empty"
+                : mExistingAutoDecors.entrySet()
+                        .stream()
+                        .map(entry -> entry.getKey() + "=" + entry.getValue())
+                        .collect(Collectors.joining(" , "));
+
         return "TaskPanel{"
-                + "mId='" + getPanelId() + '\''
+                + "mId='" + getPanelId()
+                + ", isRooTaskEmpty=" + isRootTaskEmpty()
+                + ", mBounds=" + getBounds()
                 + ", mAlpha=" + getAlpha()
                 + ", mIsVisible=" + isVisible()
-                + ", mBounds=" + getBounds()
                 + ", mRootTaskId=" + mRootTaskId
-                + ", mContext=" + getContext()
                 + ", mRole=" + getRole()
                 + ", mLayer=" + getLayer()
                 + ", mLeash=" + mLeash
@@ -336,6 +719,7 @@ public final class TaskPanel extends BasePanel {
                 + ", mCornerRadius=" + getCornerRadius()
                 + ", mIsLaunchRoot=" + mIsLaunchRoot
                 + ", mDisplayId=" + getDisplayId()
+                + ", mDecors=" + decorString
                 + '}';
     }
 
@@ -343,6 +727,9 @@ public final class TaskPanel extends BasePanel {
      * Checks if the activity with given {@link ComponentName} should show in current panel.
      */
     public boolean handles(@Nullable ComponentName componentName) {
+        if (mTaskPanelController != null) {
+            return mTaskPanelController.handles(componentName);
+        }
         return componentName != null && mPersistedActivities.contains(componentName);
     }
 
diff --git a/src/com/android/systemui/car/wm/scalableui/panel/controller/BaseTaskPanelController.java b/src/com/android/systemui/car/wm/scalableui/panel/controller/BaseTaskPanelController.java
new file mode 100644
index 00000000..a9325dc2
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/panel/controller/BaseTaskPanelController.java
@@ -0,0 +1,240 @@
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
+package com.android.systemui.car.wm.scalableui.panel.controller;
+
+import android.annotation.NonNull;
+import android.annotation.SuppressLint;
+import android.app.ActivityManager;
+import android.content.BroadcastReceiver;
+import android.content.ComponentName;
+import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
+import android.content.pm.PackageManager;
+import android.content.pm.ResolveInfo;
+import android.os.Build;
+import android.util.Log;
+
+import androidx.annotation.GuardedBy;
+import androidx.annotation.Nullable;
+import androidx.annotation.VisibleForTesting;
+
+import com.android.car.scalableui.model.PanelControllerMetadata;
+import com.android.car.scalableui.panel.TaskPanelController;
+import com.android.car.scalableui.panel.TaskPanelHandler;
+import com.android.systemui.car.wm.scalableui.panel.PanelUtils;
+
+import java.net.URISyntaxException;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Set;
+import java.util.stream.Collectors;
+
+/**
+ * A base controller for managing {@link com.android.systemui.car.wm.scalableui.panel.TaskPanel}.
+ *
+ * <p>This class provides a foundational implementation for {@link TaskPanelController},
+ * handling common tasks such as initializing based on {@link PanelControllerMetadata},
+ * managing persistent activities, setting a default component, and responding to
+ * application installation and uninstallation events. Subclasses can extend this
+ * class to implement specific panel behaviors.
+ */
+public class BaseTaskPanelController implements TaskPanelController {
+    private static final String TAG = BaseTaskPanelController.class.getSimpleName();
+    protected static final boolean DEBUG = Build.isDebuggable();
+    private static final String PACKAGE_DATA_SCHEME = "package";
+    protected final Context mContext;
+    @NonNull
+    private final Object mLock = new Object();
+    @NonNull
+    private final PanelControllerMetadata mPanelControllerMetadata;
+    @NonNull
+    private final Set<ComponentName> mPersistentActivities;
+    @NonNull
+    private final PanelUtils mPanelUtils;
+    @Nullable
+    private ComponentName mDefaultComponent;
+    @Nullable
+    private Intent mUpdateFilter;
+    @GuardedBy("mLock")
+    @Nullable
+    private TaskPanelHandler mTaskPanelHandler;
+
+    /**
+     * Constructs a new {@code BaseTaskPanelController}.
+     *
+     * @param context                 The application context.
+     * @param panelControllerMetadata The metadata associated with this panel controller,
+     *                                containing configuration information.
+     */
+    public BaseTaskPanelController(@NonNull Context context,
+            @NonNull PanelControllerMetadata panelControllerMetadata,
+            @NonNull PanelUtils panelUtils) {
+        mContext = context;
+        mPanelControllerMetadata = panelControllerMetadata;
+        mPersistentActivities = new HashSet<>();
+        mPanelUtils = panelUtils;
+        init(panelControllerMetadata);
+    }
+
+    private void init(PanelControllerMetadata metadata) {
+        mDefaultComponent = parseDefaultComponent(metadata);
+        mUpdateFilter = parseUpdateFilter(metadata);
+        if (mUpdateFilter != null) {
+            registerApplicationInstallUninstallReceiver();
+        }
+        updatePersistentActivities();
+        logIfDebuggable("Panel Controller init: " + this);
+    }
+
+    private Intent parseUpdateFilter(@NonNull PanelControllerMetadata metadata) {
+        String intentString = metadata.getStringConfiguration(
+                PanelControllerMetadata.UPDATABLE_INTENT_FILTER);
+        return getIntentFromString(intentString);
+    }
+
+    private ComponentName parseDefaultComponent(@NonNull PanelControllerMetadata metadata) {
+        String defaultIntentString =
+                metadata.getStringConfiguration(
+                        PanelControllerMetadata.DEFAULT_COMPONENT);
+        return defaultIntentString == null ? null : ComponentName.unflattenFromString(
+                defaultIntentString);
+    }
+
+    private void registerApplicationInstallUninstallReceiver() {
+        IntentFilter filter = new IntentFilter();
+        filter.addAction(Intent.ACTION_PACKAGE_ADDED);
+        filter.addAction(Intent.ACTION_PACKAGE_REMOVED);
+        filter.addDataScheme(PACKAGE_DATA_SCHEME);
+        mContext.registerReceiver(new BroadcastReceiver() {
+            @Override
+            public void onReceive(Context context, Intent intent) {
+                updatePersistentActivities();
+            }
+        }, filter, Context.RECEIVER_EXPORTED);
+    }
+
+    @SuppressLint("MissingPermission")
+    @VisibleForTesting
+    void updatePersistentActivities() {
+        mPersistentActivities.clear();
+        if (mUpdateFilter != null) {
+            List<ResolveInfo> result = mContext.getPackageManager().queryIntentActivitiesAsUser(
+                    mUpdateFilter, PackageManager.MATCH_ALL, ActivityManager.getCurrentUser());
+            for (ResolveInfo info : result) {
+                if (info == null || info.activityInfo == null
+                        || info.activityInfo.getComponentName() == null) {
+                    continue;
+                }
+                if (mPersistentActivities.add(info.activityInfo.getComponentName())) {
+                    logIfDebuggable("adding the following component to show on fullscreen: "
+                            + info.activityInfo.getComponentName());
+                }
+            }
+        }
+        mPersistentActivities.addAll(
+                mPanelUtils.parsePersistentActivitiesFromPackages(mPanelControllerMetadata,
+                        PanelControllerMetadata.PERSISTENT_PACKAGE));
+        mPersistentActivities.addAll(parsePersistentActivities(mPanelControllerMetadata,
+                PanelControllerMetadata.PERSISTENT_ACTIVITY));
+        synchronized (mLock) {
+            if (mTaskPanelHandler != null) {
+                mTaskPanelHandler.onApplicationChanged();
+            }
+        }
+    }
+
+    protected void logIfDebuggable(String s) {
+        if (DEBUG) {
+            Log.d(TAG, s);
+        }
+    }
+
+    @Nullable
+    private Intent getIntentFromString(@Nullable String string) {
+        if (string == null) {
+            return null;
+        }
+        try {
+            return Intent.parseUri(string, Intent.URI_ANDROID_APP_SCHEME);
+        } catch (URISyntaxException e) {
+            Log.e(TAG, "Fail to parse intent string" + string + ", e=" + e);
+            return null;
+        }
+    }
+
+    private Set<ComponentName> parsePersistentActivities(
+            @NonNull PanelControllerMetadata panelControllerMetadata, @NonNull String configName) {
+        Set<ComponentName> set = new HashSet<>();
+        if (!mPanelControllerMetadata.hasConfiguration(configName)) {
+            return set;
+        }
+        List<String> list = panelControllerMetadata.getListConfiguration(configName);
+        if (list == null) {
+            String value = panelControllerMetadata.getStringConfiguration(configName);
+            if (value != null) {
+                set.add(ComponentName.unflattenFromString(value));
+            }
+        } else {
+            for (String item : list) {
+                ComponentName componentName = ComponentName.unflattenFromString(item);
+                if (componentName == null) {
+                    continue;
+                }
+                set.add(componentName);
+            }
+        }
+        return set;
+    }
+
+    @Override
+    public Intent getDefaultComponent() {
+        Intent intent = new Intent();
+        intent.setComponent(mDefaultComponent);
+        logIfDebuggable("getDefaultComponent =  " + intent);
+        return intent;
+    }
+
+    @Override
+    @NonNull
+    public Set<ComponentName> getPersistentActivities() {
+        return mPersistentActivities;
+    }
+
+    @Override
+    public void registerTaskPanelHandler(TaskPanelHandler taskPanelHandler) {
+        synchronized (mLock) {
+            mTaskPanelHandler = taskPanelHandler;
+        }
+    }
+
+    @Override
+    public boolean handles(ComponentName componentName) {
+        return mPersistentActivities.contains(componentName);
+    }
+
+    @Override
+    public String toString() {
+        String persistentActivities = mPersistentActivities.stream().map(
+                ComponentName::toString).collect(Collectors.joining(","));
+        return "PanelController{"
+                + "mPanelControllerMetadata=" + mPanelControllerMetadata
+                + ", mPersistentActivities=" + persistentActivities
+                + ", mDefaultComponent=" + getDefaultComponent()
+                + ", mUpdateFilter=" + mUpdateFilter
+                + '}';
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/panel/controller/MapsPanelController.java b/src/com/android/systemui/car/wm/scalableui/panel/controller/MapsPanelController.java
new file mode 100644
index 00000000..0cc792ce
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/panel/controller/MapsPanelController.java
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
+package com.android.systemui.car.wm.scalableui.panel.controller;
+
+import android.annotation.NonNull;
+import android.content.Context;
+import android.content.Intent;
+
+import com.android.car.scalableui.model.PanelControllerMetadata;
+import com.android.car.tos.TosHelper;
+import com.android.systemui.R;
+import com.android.systemui.car.wm.scalableui.panel.PanelUtils;
+
+public final class MapsPanelController extends BaseTaskPanelController {
+    private static final String TAG = MapsPanelController.class.getSimpleName();
+
+    public MapsPanelController(@NonNull Context context,
+            @NonNull PanelControllerMetadata panelControllerMetadata,
+            @NonNull PanelUtils panelUtils) {
+        super(context, panelControllerMetadata, panelUtils);
+    }
+
+    @Override
+    public Intent getDefaultComponent() {
+        Intent mapIntent = super.getDefaultComponent();
+        Intent result = TosHelper.maybeReplaceWithTosMapIntent(mContext, mapIntent,
+                R.string.config_tosMapIntent);
+        logIfDebuggable(TAG + ", getDefaultComponent =  " + result);
+        return result;
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/panel/controller/PanelControllerInitializer.java b/src/com/android/systemui/car/wm/scalableui/panel/controller/PanelControllerInitializer.java
new file mode 100644
index 00000000..ecbec1d4
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/panel/controller/PanelControllerInitializer.java
@@ -0,0 +1,106 @@
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
+package com.android.systemui.car.wm.scalableui.panel.controller;
+
+import android.annotation.NonNull;
+import android.content.Context;
+import android.os.Build;
+import android.util.Log;
+
+import androidx.annotation.Nullable;
+
+import com.android.car.scalableui.model.PanelControllerMetadata;
+import com.android.car.scalableui.panel.TaskPanelController;
+import com.android.systemui.car.wm.scalableui.panel.PanelUtils;
+import com.android.wm.shell.dagger.WMSingleton;
+
+import java.lang.reflect.Constructor;
+import java.lang.reflect.InvocationTargetException;
+
+import javax.inject.Inject;
+
+/**
+ * Initializes {@link TaskPanelController} instances based on provided metadata.
+ *
+ * <p>This class is responsible for dynamically creating instances of {@link TaskPanelController}
+ * by using the controller class name specified in the {@link PanelControllerMetadata}. It handles
+ * potential exceptions that may occur during class loading and instantiation.
+ *
+ * TODO(411549493): Move DecorPanelController here.
+ */
+@WMSingleton
+public class PanelControllerInitializer {
+    private static final boolean DEBUG = Build.isDebuggable();
+    private static final String TAG = PanelControllerInitializer.class.getSimpleName();
+    private final Context mContext;
+    private final PanelUtils mPanelUtils;
+
+    @Inject
+    public PanelControllerInitializer(@NonNull Context context,
+            @NonNull PanelUtils panelUtils) {
+        mContext = context;
+        mPanelUtils = panelUtils;
+    }
+
+    /**
+     * Creates a {@link TaskPanelController} instance based on the provided metadata.
+     *
+     * <p>This method attempts to load the class specified by
+     * {@link PanelControllerMetadata#getControllerName()},
+     * ensures it is a subclass of {@link TaskPanelController}, and then instantiates it using a
+     * constructor that accepts a {@link Context} and a {@link PanelControllerMetadata}.
+     *
+     * @param metadata The metadata containing information about the panel controller to create.
+     *                 If {@code null}, this method will return {@code null}.
+     * @return A new instance of {@link TaskPanelController} if successful, otherwise {@code null}.
+     */
+    public TaskPanelController createTaskPanelController(
+            @Nullable PanelControllerMetadata metadata) {
+        if (metadata == null) {
+            logIfDebuggable("Metadata is null");
+            return null;
+        }
+        String controllerName = metadata.getControllerName();
+
+        logIfDebuggable("Init TaskPanelController with class name" + controllerName);
+        try {
+            Class<?> clazz = Class.forName(controllerName);
+            if (TaskPanelController.class.isAssignableFrom(clazz)) {
+                Constructor<?> constructor = clazz.getConstructor(Context.class,
+                        PanelControllerMetadata.class, PanelUtils.class);
+                //TODO(b/411549493): move to factory pattern.
+                return (TaskPanelController) constructor.newInstance(mContext, metadata,
+                        mPanelUtils);
+            }
+        } catch (ClassNotFoundException | NoSuchMethodException e) {
+            // Handle the case where the class is not found
+            Log.e(TAG, "Class not found: " + controllerName, e);
+        } catch (InvocationTargetException e) {
+            Log.e(TAG, "InvocationTargetException: " + controllerName, e);
+        } catch (InstantiationException e) {
+            Log.e(TAG, "InstantiationException: " + controllerName, e);
+        } catch (IllegalAccessException e) {
+            Log.e(TAG, "IllegalAccessException: " + controllerName, e);
+        }
+        return null;
+    }
+
+    private static void logIfDebuggable(String msg) {
+        if (DEBUG) {
+            Log.d(TAG, msg);
+        }
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/systemevents/EventHandlerModule.java b/src/com/android/systemui/car/wm/scalableui/systemevents/EventHandlerModule.java
index c50c7414..1da2e9e6 100644
--- a/src/com/android/systemui/car/wm/scalableui/systemevents/EventHandlerModule.java
+++ b/src/com/android/systemui/car/wm/scalableui/systemevents/EventHandlerModule.java
@@ -16,11 +16,13 @@
 package com.android.systemui.car.wm.scalableui.systemevents;
 
 import com.android.systemui.CoreStartable;
+import com.android.systemui.statusbar.policy.ConfigurationController;
 
 import dagger.Binds;
 import dagger.Module;
 import dagger.multibindings.ClassKey;
 import dagger.multibindings.IntoMap;
+import dagger.multibindings.IntoSet;
 
 /**
  * Dagger injection module for {@link SystemEventHandler}
@@ -33,4 +35,10 @@ public abstract class EventHandlerModule {
     @IntoMap
     @ClassKey(SystemEventHandler.class)
     public abstract CoreStartable bindUserSystemEventHandler(SystemEventHandler systemEventHandler);
+
+    /** Injects SystemEventHandler as ConfigurationListener*/
+    @Binds
+    @IntoSet
+    public abstract ConfigurationController.ConfigurationListener provideCarSystemBarConfigListener(
+            SystemEventHandler systemEventHandler);
 }
diff --git a/src/com/android/systemui/car/wm/scalableui/systemevents/SystemEventConstants.java b/src/com/android/systemui/car/wm/scalableui/systemevents/SystemEventConstants.java
index f75fa551..58bd20d6 100644
--- a/src/com/android/systemui/car/wm/scalableui/systemevents/SystemEventConstants.java
+++ b/src/com/android/systemui/car/wm/scalableui/systemevents/SystemEventConstants.java
@@ -23,9 +23,16 @@ public class SystemEventConstants {
     public static final String SYSTEM_TASK_CLOSE_EVENT_ID = "_System_TaskCloseEvent";
     public static final String SYSTEM_TASK_PANEL_EMPTY_EVENT_ID = "_System_TaskPanelEmptyEvent";
     public static final String SYSTEM_ENTER_SUW_EVENT_ID = "_System_EnterSuwEvent";
-    public static final String SYSTEM_EXIST_SUW_EVENT_ID = "_System_ExitSuwEvent";
+    public static final String SYSTEM_EXIT_SUW_EVENT_ID = "_System_ExitSuwEvent";
+    public static final String SYSTEM_ON_ANIMATION_END_EVENT_ID = "_System_OnAnimationEndEvent";
 
     /** Token IDs */
     public static final String PANEL_TOKEN_ID = "panelId";
+    /**
+     * Represents the variant at the end of the animation.
+     */
+    public static final String PANEL_TO_VARIANT_ID = "panelToVariantId";
+    public static final String PANEL_DRAG_DIRECTION_ID = "direction";
     public static final String COMPONENT_TOKEN_ID = "component";
+    public static final String PACKAGE_TOKEN_ID = "package";
 }
diff --git a/src/com/android/systemui/car/wm/scalableui/systemevents/SystemEventHandler.java b/src/com/android/systemui/car/wm/scalableui/systemevents/SystemEventHandler.java
index cd8ef422..6bc9ba30 100644
--- a/src/com/android/systemui/car/wm/scalableui/systemevents/SystemEventHandler.java
+++ b/src/com/android/systemui/car/wm/scalableui/systemevents/SystemEventHandler.java
@@ -16,20 +16,27 @@
 package com.android.systemui.car.wm.scalableui.systemevents;
 
 import static android.car.user.CarUserManager.USER_LIFECYCLE_EVENT_TYPE_UNLOCKED;
+import static android.content.res.Configuration.ORIENTATION_LANDSCAPE;
+import static android.content.res.Configuration.ORIENTATION_PORTRAIT;
 
 import static com.android.systemui.car.Flags.scalableUi;
 import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_ENTER_SUW_EVENT_ID;
-import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_EXIST_SUW_EVENT_ID;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.SYSTEM_EXIT_SUW_EVENT_ID;
 import static com.android.wm.shell.Flags.enableAutoTaskStackController;
 
 import android.car.user.CarUserManager;
 import android.content.Context;
+import android.content.res.TypedArray;
 import android.os.Build;
 import android.util.Log;
 
 import androidx.annotation.NonNull;
 
+import com.android.car.scalableui.loader.xml.XmlModelLoader;
 import com.android.car.scalableui.manager.StateManager;
+import com.android.car.scalableui.model.PanelState;
+import com.android.car.scalableui.panel.Panel;
+import com.android.car.scalableui.panel.PanelPool;
 import com.android.systemui.CoreStartable;
 import com.android.systemui.R;
 import com.android.systemui.car.CarDeviceProvisionedController;
@@ -39,7 +46,10 @@ import com.android.systemui.car.wm.scalableui.EventDispatcher;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Background;
 import com.android.systemui.settings.UserTracker;
+import com.android.systemui.statusbar.policy.ConfigurationController;
 
+import java.util.ArrayList;
+import java.util.List;
 import java.util.concurrent.Executor;
 
 import javax.inject.Inject;
@@ -53,7 +63,8 @@ import javax.inject.Inject;
  * is being set up.
  */
 @SysUISingleton
-public class SystemEventHandler implements CoreStartable {
+public class SystemEventHandler implements CoreStartable,
+        ConfigurationController.ConfigurationListener {
     private static final String TAG = SystemEventHandler.class.getSimpleName();
     private static final boolean DEBUG = Build.IS_DEBUGGABLE;
 
@@ -67,25 +78,28 @@ public class SystemEventHandler implements CoreStartable {
     private CarUserManager mCarUserManager;
     private boolean mIsUserSetupInProgress;
 
+    private int mCurrentOrientation;
+
     private final CarUserManager.UserLifecycleListener mUserLifecycleListener =
             new CarUserManager.UserLifecycleListener() {
                 @Override
                 public void onEvent(@NonNull CarUserManager.UserLifecycleEvent event) {
                     if (DEBUG) {
-                        Log.d(TAG, "on User event = " + event + ", mIsUserSetupInProgress="
-                                + mIsUserSetupInProgress);
-                    }
-                    if (mIsUserSetupInProgress) {
-                        return;
+                        Log.d(TAG, "on User event = " + event);
                     }
                     if (event.getUserHandle().isSystem()) {
+                        Log.i(TAG, "Ignore system event");
                         return;
                     }
 
                     if (event.getEventType() == USER_LIFECYCLE_EVENT_TYPE_UNLOCKED) {
                         if (event.getUserId() == mUserTracker.getUserId()) {
                             StateManager.handlePanelReset();
+                        } else {
+                            Log.i(TAG, "Not current user" + event.getUserId());
                         }
+                    } else {
+                        Log.i(TAG, "Ignore system event" + event.getEventType());
                     }
                 }
             };
@@ -96,6 +110,16 @@ public class SystemEventHandler implements CoreStartable {
                 public void onUserSetupInProgressChanged() {
                     updateUserSetupState();
                 }
+
+                @Override
+                public void onDeviceProvisionedChanged() {
+                    updateUserSetupState();
+                }
+
+                @Override
+                public void onUserSwitched() {
+                    updateUserSetupState();
+                }
             };
 
     @Inject
@@ -113,22 +137,22 @@ public class SystemEventHandler implements CoreStartable {
         mUserTracker = userTracker;
         mCarDeviceProvisionedController = carDeviceProvisionedController;
         mEventDispatcher = dispatcher;
-        mIsUserSetupInProgress = mCarDeviceProvisionedController.isCurrentUserSetupInProgress();
+        mCurrentOrientation = mContext.getResources().getConfiguration().orientation;
     }
 
     private void updateUserSetupState() {
-        boolean isUserSetupInProgress =
-                mCarDeviceProvisionedController.isCurrentUserSetupInProgress();
+        boolean isUserSetupInProgress = !mCarDeviceProvisionedController.isCurrentUserFullySetup();
         if (isUserSetupInProgress != mIsUserSetupInProgress) {
             mIsUserSetupInProgress = isUserSetupInProgress;
-            if (mIsUserSetupInProgress) {
-                mEventDispatcher.executeTransaction(SYSTEM_ENTER_SUW_EVENT_ID);
-            } else {
-                mEventDispatcher.executeTransaction(SYSTEM_EXIST_SUW_EVENT_ID);
-            }
+            notifySuwStateEvent();
         }
     }
 
+    private void notifySuwStateEvent() {
+        mEventDispatcher.executeTransaction(
+                mIsUserSetupInProgress ? SYSTEM_ENTER_SUW_EVENT_ID : SYSTEM_EXIT_SUW_EVENT_ID);
+    }
+
     @Override
     public void start() {
         if (isScalableUIEnabled()) {
@@ -137,7 +161,31 @@ public class SystemEventHandler implements CoreStartable {
         }
     }
 
+    @Override
+    public void onUiModeChanged() {
+        PanelPool.getInstance().forEach(Panel::refreshTheme);
+    }
+
+    @Override
+    public void onOrientationChanged(int orientation) {
+        if (mCurrentOrientation != orientation && (ORIENTATION_LANDSCAPE == orientation
+                || ORIENTATION_PORTRAIT == orientation)) {
+            mCurrentOrientation = orientation;
+            TypedArray states = mContext.getResources().obtainTypedArray(R.array.window_states);
+            List<PanelState> panelStateList = new ArrayList<>();
+            for (int i = 0; i < states.length(); i++) {
+                int xmlResId = states.getResourceId(i, 0);
+                XmlModelLoader loader = new XmlModelLoader(mContext);
+                PanelState panelState = loader.createPanelState(xmlResId);
+                panelStateList.add(panelState);
+            }
+            StateManager.reloadPanelState(panelStateList);
+        }
+    }
+
     private void registerProvisionedStateListener() {
+        mIsUserSetupInProgress = !mCarDeviceProvisionedController.isCurrentUserFullySetup();
+        notifySuwStateEvent();
         mCarDeviceProvisionedController.addCallback(mCarDeviceProvisionedListener);
     }
 
@@ -151,7 +199,8 @@ public class SystemEventHandler implements CoreStartable {
     }
 
     private boolean isScalableUIEnabled() {
-        return scalableUi() && enableAutoTaskStackController()
+        return scalableUi()
+                && enableAutoTaskStackController()
                 && mContext.getResources().getBoolean(R.bool.config_enableScalableUI);
     }
 }
diff --git a/src/com/android/systemui/car/wm/scalableui/view/DecorPanelControllerBase.java b/src/com/android/systemui/car/wm/scalableui/view/DecorPanelControllerBase.java
new file mode 100644
index 00000000..d2540c5b
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/view/DecorPanelControllerBase.java
@@ -0,0 +1,128 @@
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
+package com.android.systemui.car.wm.scalableui.view;
+
+import android.content.Context;
+import android.util.Log;
+import android.view.View;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import com.android.car.scalableui.model.PanelControllerMetadata;
+import com.android.car.scalableui.panel.DecorPanelController;
+
+import java.lang.reflect.Constructor;
+import java.lang.reflect.InvocationTargetException;
+
+public abstract class DecorPanelControllerBase implements DecorPanelController {
+    private static final String TAG = DecorPanelControllerBase.class.getSimpleName();
+    private static final boolean DEBUG = true;
+    protected final Context mContext;
+    protected final String mViewName;
+    protected final PanelControllerMetadata mMetadata;
+    protected View mView;
+
+    protected DecorPanelControllerBase(Context context, PanelControllerMetadata metadata) {
+        mContext = context;
+        mMetadata = metadata;
+        mViewName = metadata.getStringConfiguration(PanelControllerMetadata.VIEW_TAG);
+        if (mViewName == null) {
+            throw new RuntimeException("ViewName must be set " + metadata);
+        }
+    }
+
+    private static View initView(Context context, String viewClassName) {
+        if (viewClassName == null) {
+            Log.e(TAG, "viewClassName is null");
+            return null;
+        }
+        try {
+            //TODO(b/422493779): replace the reflection to reduce the security risk.
+            Class<?> clazz = Class.forName(viewClassName);
+            if (View.class.isAssignableFrom(clazz)) {
+                Constructor<?> constructor = clazz.getConstructor(Context.class);
+                return (View) constructor.newInstance(context);
+            }
+        } catch (ClassNotFoundException | NoSuchMethodException e) {
+            // Handle the case where the class is not found
+            Log.e(TAG, "Class or method not found not found: " + viewClassName, e);
+        } catch (InvocationTargetException e) {
+            Log.e(TAG, "InvocationTargetException: " + viewClassName, e);
+        } catch (InstantiationException e) {
+            Log.e(TAG, "InstantiationException: " + viewClassName, e);
+        } catch (IllegalAccessException e) {
+            Log.e(TAG, "IllegalAccessException: " + viewClassName, e);
+        }
+        return null;
+    }
+
+    /**
+     * Initialized a {@link DecorPanelController}.
+     */
+    @Nullable
+    public static DecorPanelController createDecorPanelController(@NonNull Context context,
+            @Nullable PanelControllerMetadata metadata) {
+        if (metadata == null) {
+            logIfDebuggable("Metadata is null");
+            return null;
+        }
+        String controllerName = metadata.getControllerName();
+
+        logIfDebuggable("Init view provider with class name" + controllerName);
+        try {
+            //TODO(b/422493779): replace the reflection to reduce the security risk.
+            Class<?> clazz = Class.forName(controllerName);
+            if (DecorPanelControllerBase.class.isAssignableFrom(clazz)) {
+                Constructor<?> constructor = clazz.getConstructor(Context.class,
+                        PanelControllerMetadata.class);
+                return (DecorPanelControllerBase) constructor.newInstance(context, metadata);
+            }
+        } catch (ClassNotFoundException | NoSuchMethodException e) {
+            // Handle the case where the class is not found
+            Log.e(TAG, "Class not found: " + controllerName, e);
+        } catch (InvocationTargetException e) {
+            Log.e(TAG, "InvocationTargetException: " + controllerName, e);
+        } catch (InstantiationException e) {
+            Log.e(TAG, "InstantiationException: " + controllerName, e);
+        } catch (IllegalAccessException e) {
+            Log.e(TAG, "IllegalAccessException: " + controllerName, e);
+        }
+        return null;
+    }
+
+    protected Context getContext() {
+        return mContext;
+    }
+
+    @Override
+    @Nullable
+    public View getView() {
+        mView = mView == null ? initView(mContext, mViewName) : mView;
+        return mView;
+    }
+
+    @Override
+    public void refreshTheme() {
+        mView = initView(mContext, mViewName);
+    }
+
+    protected static void logIfDebuggable(String msg) {
+        if (DEBUG) {
+            Log.d(TAG, msg);
+        }
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/view/GripBar.java b/src/com/android/systemui/car/wm/scalableui/view/GripBar.java
new file mode 100644
index 00000000..adf0af08
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/view/GripBar.java
@@ -0,0 +1,135 @@
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
+package com.android.systemui.car.wm.scalableui.view;
+
+import android.annotation.SuppressLint;
+import android.content.Context;
+import android.util.AttributeSet;
+import android.view.GestureDetector;
+import android.view.MotionEvent;
+import android.view.View;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.constraintlayout.widget.ConstraintLayout;
+
+import com.android.systemui.R;
+
+import java.util.ArrayList;
+import java.util.List;
+
+/**
+ * A custom view representing a "grip" or handle, often used for interacting with
+ * draggable or resizable UI elements.
+ */
+public class GripBar extends ConstraintLayout {
+    private static final String TAG = GripBar.class.getSimpleName();
+    private final GestureDetector mGestureDetector;
+    private final List<GripBarEventHandler> mGripBarEventHandlers;
+
+    private class SingleTapListener extends GestureDetector.SimpleOnGestureListener {
+        @Override
+        public boolean onSingleTapUp(@NonNull MotionEvent e) {
+            notifyClickEvent();
+            return true;
+        }
+    }
+    /**
+     * Constructor for GripBar.
+     */
+    public GripBar(@NonNull Context context) {
+        this(context, null);
+    }
+
+    public GripBar(@NonNull Context context, @Nullable AttributeSet attrs) {
+        this(context, attrs, 0);
+    }
+
+    public GripBar(@NonNull Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
+        this(context, attrs, defStyleAttr, 0);
+    }
+
+    @SuppressLint("ClickableViewAccessibility")
+    public GripBar(@NonNull Context context, @Nullable AttributeSet attrs, int defStyleAttr,
+            int defStyleRes) {
+        super(context, attrs, defStyleAttr, defStyleRes);
+        //TODO(b/422235782): Supports refresh with Token
+        setBackgroundResource(R.drawable.grip_bar_background);
+        setOnTouchListener(this::onTouchEvent);
+        setOnClickListener(v -> onClickEvent());
+        mGestureDetector = new GestureDetector(context, new SingleTapListener());
+        mGripBarEventHandlers = new ArrayList<>();
+    }
+
+    private boolean onTouchEvent(View v, MotionEvent event) {
+        if (mGestureDetector.onTouchEvent(event)) {
+            return true;
+        }
+        notifyTouchEvent(event);
+        return true;
+    }
+
+    private void notifyTouchEvent(MotionEvent event) {
+        synchronized (mGripBarEventHandlers) {
+            for (GripBarEventHandler gripBarEventHandler: mGripBarEventHandlers) {
+                gripBarEventHandler.onTouch(event);
+            }
+        }
+    }
+
+    private boolean onClickEvent() {
+        notifyClickEvent();
+        return true;
+    }
+
+    private void notifyClickEvent() {
+        synchronized (mGripBarEventHandlers) {
+            for (GripBarEventHandler gripBarEventHandler: mGripBarEventHandlers) {
+                gripBarEventHandler.onClick();
+            }
+        }
+    }
+
+    /** Register a GripBarEventHandler */
+    public void addGripBarEventHandlers(@NonNull GripBarEventHandler handler) {
+        synchronized (mGripBarEventHandlers) {
+            mGripBarEventHandlers.add(handler);
+        }
+    }
+
+    /** Unregister a GripBarEventHandler */
+    public void removeGripBarEventHandlers(@NonNull GripBarEventHandler handler) {
+        synchronized (mGripBarEventHandlers) {
+            mGripBarEventHandlers.remove(handler);
+        }
+    }
+
+    /**
+     * Interface definition for callbacks to be invoked when a Grip Bar is interacted with.
+     */
+    public interface GripBarEventHandler {
+        /**
+         * Called when a touch event occurs on the Grip Bar.
+         * @param motionEvent The details of the touch event.
+         */
+        void onTouch(MotionEvent motionEvent);
+
+        /**
+         * Called when a click event is detected on the Grip Bar.
+         */
+        void onClick();
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/view/GripBarViewController.java b/src/com/android/systemui/car/wm/scalableui/view/GripBarViewController.java
new file mode 100644
index 00000000..9a8c373d
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/view/GripBarViewController.java
@@ -0,0 +1,241 @@
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
+package com.android.systemui.car.wm.scalableui.view;
+
+import static com.android.car.scalableui.model.PanelControllerMetadata.DRAG_DEC_EVENT_ID_TAG;
+import static com.android.car.scalableui.model.PanelControllerMetadata.DRAG_INC_EVENT_ID_TAG;
+import static com.android.systemui.car.wm.scalableui.systemevents.SystemEventConstants.PANEL_DRAG_DIRECTION_ID;
+
+import android.annotation.SuppressLint;
+import android.content.Context;
+import android.util.Log;
+import android.view.MotionEvent;
+import android.view.View;
+
+import androidx.annotation.Nullable;
+
+import com.android.car.scalableui.model.BreakPoint;
+import com.android.car.scalableui.model.Event;
+import com.android.car.scalableui.model.KeyFrameEvent;
+import com.android.car.scalableui.model.PanelControllerMetadata;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
+
+import java.util.ArrayList;
+import java.util.List;
+import java.util.stream.Collectors;
+
+/**
+ * A Controller for the {@link GripBar}
+ * <p>
+ * Configuration for the GripBar is read from a themed attribute, which is
+ * expected to be an array resource. The array should contain values defining
+ * the behavior of the GripBar. The following indices in the configuration
+ * array are used:
+ * </p>
+ * <ul>
+ * <li>Index 0: View provider name (String)</li>
+ * <li>Index 1: View class name (String)</li>
+ * <li>Index 2: Drag event ID (String)</li>
+ * <li>Index 3: Orientation (0 for vertical, 1 for horizontal) (Integer)</li>
+ * <li>Index 4: Snap threshold (Dimension)</li>
+ * <li>Index 5: Resource ID of the breakpoint definition array (Integer)</li>
+ * </ul>
+ */
+public class GripBarViewController extends DecorPanelControllerBase implements
+        EventDispatcher.EventProducer, GripBar.GripBarEventHandler {
+    private static final String TAG = GripBarViewController.class.getSimpleName();
+    private static final String DRAG_NO_CHANGE = "noChange";
+    private static final String DRAG_INCREASE = "increase";
+    private static final String DRAG_DECREASE = "decrease";
+    private GripBar mGripBar;
+    private boolean mIsHorizontal;
+
+    private String mDragEventId;
+    private String mDragDecreaseEventId;
+    private String mDragIncreaseEventId;
+    private float mSnapThreshold;
+    private float mDragStart;
+
+    private int mState = 0;
+
+    private final List<BreakPoint> mBreakPoints;
+    private BreakPoint mStartBreakPoint;
+    private EventDispatcher mEventDispatcher;
+    private float mLastDispatchedProgress;
+
+    @Override
+    public void onClick() {
+        Event event = new Event.Builder((mBreakPoints.get(mState).getEventId())).build();
+        dispatchEvent(event);
+        mState = (mState + 1) % mBreakPoints.size();
+        logIfDebuggable("onclick " + event);
+    }
+
+    /**
+     * Sets the {@link EventDispatcher} for the controller.
+     *
+     * @param eventDispatcher The {@link EventDispatcher} to set. Must not be null.
+     */
+    public void setEventDispatcher(EventDispatcher eventDispatcher) {
+        mEventDispatcher = eventDispatcher;
+    }
+
+    public GripBarViewController(Context context, PanelControllerMetadata metadata) {
+        super(context, metadata);
+        mBreakPoints = new ArrayList<>();
+        init(metadata);
+    }
+
+    @SuppressLint("ClickableViewAccessibility")
+    @Override
+    @Nullable
+    public View getView() {
+        View view = super.getView();
+        if (view instanceof GripBar gripBar) {
+            mGripBar = gripBar;
+        } else {
+            throw new RuntimeException("GripBarViewController mush have a gripBar view");
+        }
+        mGripBar.addGripBarEventHandlers(this);
+        return mGripBar;
+    }
+
+    private void init(PanelControllerMetadata metadata) {
+        mDragEventId = metadata.getStringConfiguration(PanelControllerMetadata.EVENT_ID_TAG);
+        mDragDecreaseEventId = metadata.getStringConfiguration(DRAG_DEC_EVENT_ID_TAG);
+        mDragIncreaseEventId = metadata.getStringConfiguration(DRAG_INC_EVENT_ID_TAG);
+        mIsHorizontal = Integer.parseInt(
+                metadata.getStringConfiguration(PanelControllerMetadata.ORIENTATION_TAG)) == 1;
+        mSnapThreshold = Integer.parseInt(
+                metadata.getStringConfiguration(PanelControllerMetadata.SNAPTHREADHOLD_TAG));
+        mBreakPoints.clear();
+        mBreakPoints.addAll(metadata.getBreakPoints());
+        logIfDebuggable("Parse array: " + this);
+    }
+
+    private void dispatchEvent(Event event) {
+        if (mEventDispatcher == null) {
+            Log.e(TAG, "EventDispatcher is null");
+            return;
+        }
+        mEventDispatcher.executeTransaction(event);
+    }
+
+    private float getDistance(BreakPoint breakPoint, float value) {
+        return Math.abs(value - breakPoint.getPoint());
+    }
+
+    private BreakPoint findClosestBreakPoint(float value) {
+        BreakPoint closest = mBreakPoints.getFirst();
+        float minDistance = Float.MAX_VALUE;
+        for (BreakPoint breakPoint : mBreakPoints) {
+            float distance = getDistance(breakPoint, value);
+            if (distance < minDistance) {
+                minDistance = distance;
+                closest = breakPoint;
+            }
+        }
+        return closest;
+    }
+
+    @Override
+    public void onTouch(MotionEvent event) {
+        if (mBreakPoints.size() < 2) {
+            logIfDebuggable("break point not valid " + mBreakPoints.size());
+            return;
+        }
+
+        float value = mIsHorizontal ? event.getRawX() : event.getRawY();
+        float min = mBreakPoints.getFirst().getPoint();
+        float max = mBreakPoints.getLast().getPoint();
+        BreakPoint closest = findClosestBreakPoint(value);
+        float closestDistance = getDistance(closest, value);
+        if (closestDistance < mSnapThreshold) {
+            value = closest.getPoint();
+        }
+
+        if (mStartBreakPoint == null) {
+            mStartBreakPoint = findClosestBreakPoint(value);
+        }
+
+        float progress = (value - min) / (max - min);
+        logIfDebuggable("progress " + progress);
+        if (progress < 0 || progress > 1) {
+            progress = progress < 0 ? 0 : 1;
+        }
+
+        switch (event.getAction()) {
+            case MotionEvent.ACTION_DOWN:
+                mDragStart = mIsHorizontal ? event.getRawX() : event.getRawY();
+                return;
+            case MotionEvent.ACTION_MOVE:
+                dispatchEvent(progress, value, event);
+                break;
+            case MotionEvent.ACTION_CANCEL:
+            case MotionEvent.ACTION_UP:
+                dispatchDirectionEvent(value, closest);
+                mStartBreakPoint = null;
+                break;
+            default:
+        }
+    }
+
+    private void dispatchEvent(float progress, float value, MotionEvent event) {
+        if (progress == mLastDispatchedProgress && event.getAction() != MotionEvent.ACTION_UP) {
+            // don't dispatch multiple events from same progress
+            return;
+        }
+        if (mDragDecreaseEventId != null && value < mDragStart) {
+            KeyFrameEvent keyFrameEvent = new KeyFrameEvent.Builder(mDragDecreaseEventId,
+                    progress).build();
+            dispatchEvent(keyFrameEvent);
+        } else if (mDragIncreaseEventId != null) {
+            KeyFrameEvent keyFrameEvent = new KeyFrameEvent.Builder(mDragIncreaseEventId,
+                    progress).build();
+            dispatchEvent(keyFrameEvent);
+        } else {
+            dispatchEvent(new KeyFrameEvent.Builder(mDragEventId,
+                    progress).build());
+        }
+        mLastDispatchedProgress = progress;
+    }
+
+    private void dispatchDirectionEvent(float value, BreakPoint breakPoin) {
+        String direction;
+        if (mStartBreakPoint.getEventId().equals(breakPoin.getEventId())) {
+            direction = DRAG_NO_CHANGE;
+        } else if (value < mDragStart) {
+            direction = DRAG_DECREASE;
+        } else {
+            direction = DRAG_INCREASE;
+        }
+        dispatchEvent(new Event.Builder(breakPoin.getEventId())
+                .addToken(PANEL_DRAG_DIRECTION_ID, direction)
+                .build());
+    }
+
+    @Override
+    public String toString() {
+        String breakpointsString = (mBreakPoints == null) ? "null" :
+                mBreakPoints.stream()
+                        .map(Object::toString)
+                        .collect(Collectors.joining(", ", "[", "]"));
+
+        return "GripBarViewProvider{" + "mGripBar=" + mGripBar + ", mIsHorizontal=" + mIsHorizontal
+                + ", mDragEventId='" + mDragEventId + '\'' + ", mSnapThreshold=" + mSnapThreshold
+                + ", mBreakPoints=" + breakpointsString + '}';
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/view/PanelOverlay.java b/src/com/android/systemui/car/wm/scalableui/view/PanelOverlay.java
new file mode 100644
index 00000000..ff536ae8
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/view/PanelOverlay.java
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
+package com.android.systemui.car.wm.scalableui.view;
+
+import android.annotation.SuppressLint;
+import android.content.Context;
+import android.graphics.Canvas;
+import android.util.AttributeSet;
+import android.view.View;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.constraintlayout.widget.ConstraintLayout;
+
+/**
+ * An overlay panel that can be used for blur effect or can be used to overlay a panel while in
+ * split mode.
+ */
+public class PanelOverlay extends ConstraintLayout {
+
+    /**
+     * Callback for view's visibility changes.
+     */
+    public interface OnChangeListener {
+
+        /**
+         * Invoked when visibility changes.
+         */
+        void onVisibilityChange(int visibility);
+
+        /**
+         * Invoked when alpha changes.
+         */
+        void onAlphaChanged(float alpha);
+    }
+
+    private static final String TAG = PanelOverlay.class.getSimpleName();
+    private OnChangeListener mOnChangeListener;
+
+    /**
+     * Constructor for GripBar.
+     */
+    public PanelOverlay(@NonNull Context context) {
+        this(context, null);
+        setVisibility(GONE);
+    }
+
+    public PanelOverlay(@NonNull Context context, @Nullable AttributeSet attrs) {
+        this(context, attrs, 0);
+    }
+
+    public PanelOverlay(@NonNull Context context, @Nullable AttributeSet attrs,
+            int defStyleAttr) {
+        this(context, attrs, defStyleAttr, 0);
+    }
+
+    @SuppressLint("ClickableViewAccessibility")
+    public PanelOverlay(@NonNull Context context, @Nullable AttributeSet attrs,
+            int defStyleAttr,
+            int defStyleRes) {
+        super(context, attrs, defStyleAttr, defStyleRes);
+    }
+
+    public void setOnChangeListener(OnChangeListener listener) {
+        mOnChangeListener = listener;
+    }
+
+    @Override
+    protected void onVisibilityChanged(View changedView, int visibility) {
+        super.onVisibilityChanged(changedView, visibility);
+        mOnChangeListener.onVisibilityChange(visibility);
+    }
+
+    @Override
+    protected void onDraw(Canvas canvas) {
+        super.onDraw(canvas);
+
+        if (mOnChangeListener != null) {
+            mOnChangeListener.onAlphaChanged(getAlpha());
+        }
+    }
+}
diff --git a/src/com/android/systemui/car/wm/scalableui/view/PanelOverlayController.java b/src/com/android/systemui/car/wm/scalableui/view/PanelOverlayController.java
new file mode 100644
index 00000000..2fe6145e
--- /dev/null
+++ b/src/com/android/systemui/car/wm/scalableui/view/PanelOverlayController.java
@@ -0,0 +1,188 @@
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
+package com.android.systemui.car.wm.scalableui.view;
+
+import static com.android.car.scalableui.model.PanelControllerMetadata.BACKGROUND_COLOR;
+import static com.android.car.scalableui.model.PanelControllerMetadata.OVERLAY_PANEL_ID;
+
+import android.annotation.SuppressLint;
+import android.content.Context;
+import android.content.pm.PackageManager;
+import android.graphics.Color;
+import android.graphics.drawable.Drawable;
+import android.util.Log;
+import android.view.View;
+import android.widget.ImageView;
+
+import androidx.annotation.NonNull;
+import androidx.constraintlayout.widget.ConstraintLayout;
+import androidx.constraintlayout.widget.ConstraintSet;
+
+import com.android.car.scalableui.model.PanelControllerMetadata;
+import com.android.car.scalableui.panel.Panel;
+import com.android.car.scalableui.panel.PanelPool;
+import com.android.internal.graphics.drawable.BackgroundBlurDrawable;
+import com.android.systemui.R;
+import com.android.systemui.car.wm.scalableui.panel.TaskPanel;
+
+/**
+ * A Controller for the {@link GripBar}
+ * <p>
+ * Configuration for the GripBar is read from a themed attribute, which is
+ * expected to be an array resource. The array should contain values defining
+ * the behavior of the GripBar. The following indices in the configuration
+ * array are used:
+ * </p>
+ * <ul>
+ * <li>Index 0: View provider name (String)</li>
+ * <li>Index 1: View class name (String)</li>
+ * <li>Index 2: Drag event ID (String)</li>
+ * <li>Index 3: Orientation (0 for vertical, 1 for horizontal) (Integer)</li>
+ * <li>Index 4: Snap threshold (Dimension)</li>
+ * <li>Index 5: Resource ID of the breakpoint definition array (Integer)</li>
+ * </ul>
+ */
+public class PanelOverlayController extends DecorPanelControllerBase {
+    private static final String TAG = PanelOverlayController.class.getSimpleName();
+    private PanelOverlay mPanelOverlay;
+    private String mOverlayPanelId;
+    private String mBackgroundColorHex;
+    private BackgroundBlurDrawable mBackgroundBlurDrawable;
+    private int mBlurRadius;
+
+    public PanelOverlayController(Context context, PanelControllerMetadata metadata) {
+        super(context, metadata);
+        init(metadata);
+    }
+
+    @SuppressLint("ClickableViewAccessibility")
+    @Override
+    @NonNull
+    public View getView() {
+        Log.e(TAG, "getView... ");
+        View view = super.getView();
+        if (view instanceof PanelOverlay panelOverlay) {
+            mPanelOverlay = panelOverlay;
+        } else {
+            throw new RuntimeException("PanelOverlayController mush have a PanelOverlay view");
+        }
+        mPanelOverlay.setOnChangeListener(new PanelOverlay.OnChangeListener() {
+            @Override
+            public void onVisibilityChange(int visibility) {
+                Log.e(TAG, "visibility changed... " + visibility
+                        + " mOverlayPanelId: " + mOverlayPanelId);
+                if (visibility == View.GONE) {
+                    return;
+                }
+                setBlur();
+                PanelPool pool = PanelPool.getInstance();
+                Panel panel = pool.getPanel(mOverlayPanelId);
+                if (panel instanceof TaskPanel) {
+                    String packageName = ((TaskPanel) panel).getTopTaskPackageName();
+                    setVail(packageName);
+                }
+            }
+
+            @Override
+            public void onAlphaChanged(float alpha) {
+                mBackgroundBlurDrawable.setBlurRadius((int) (mBlurRadius * alpha));
+                mPanelOverlay.setBackground(mBackgroundBlurDrawable);
+            }
+        });
+        return mPanelOverlay;
+    }
+
+    private void init(PanelControllerMetadata metadata) {
+        mOverlayPanelId = metadata.getStringConfiguration(OVERLAY_PANEL_ID);
+        mBackgroundColorHex = metadata.getStringConfiguration(BACKGROUND_COLOR);
+    }
+
+    private void setVail(String packageName) {
+        if (packageName == null) {
+            Log.i(TAG, "can't set vail as package name is null.");
+            return;
+        }
+        Drawable icon;
+        try {
+            icon = mContext.getPackageManager().getApplicationIcon(
+                    packageName);
+        } catch (PackageManager.NameNotFoundException e) {
+            Log.e(TAG, "vail can't be set for package name ", e);
+            icon = mContext.getDrawable(R.drawable.car_ic_apps);
+        }
+        ImageView iconImageView = new ImageView(getContext());
+        iconImageView.setImageDrawable(icon);
+        int width = getContext().getResources().getDimensionPixelSize(
+                R.dimen.overlay_panel_view_vail_width);
+        int height = getContext().getResources().getDimensionPixelSize(
+                R.dimen.overlay_panel_view_vail_height);
+        addCenteredIconWithConstraintSet(iconImageView, width, height);
+    }
+
+    private void setBlur() {
+        if (mPanelOverlay.getBackground() != null) {
+            return;
+        }
+        mBackgroundBlurDrawable =
+                mPanelOverlay.getViewRootImpl().createBackgroundBlurDrawable();
+        int color;
+        if (mBackgroundColorHex != null && !mBackgroundColorHex.isEmpty()) {
+            color = Color.parseColor(mBackgroundColorHex);
+        } else {
+            color = mContext.getResources().getColor(R.color.overlay_panel_bg_color);
+        }
+
+        mBackgroundBlurDrawable.setColor(color);
+        mBackgroundBlurDrawable.setCornerRadius(
+                mContext.getResources().getInteger(R.integer.overlay_panel_blur_corner_radius));
+        mBlurRadius = mContext.getResources().getInteger(R.integer.overlay_panel_blur_radius);
+        mBackgroundBlurDrawable.setBlurRadius(mBlurRadius);
+        mPanelOverlay.setBackground(mBackgroundBlurDrawable);
+    }
+
+    private void addCenteredIconWithConstraintSet(ImageView iconImageView, int width, int height) {
+        if (iconImageView.getId() == View.NO_ID) {
+            iconImageView.setId(View.generateViewId());
+        }
+
+        ConstraintLayout.LayoutParams initialParams = new ConstraintLayout.LayoutParams(width,
+                height);
+        iconImageView.setLayoutParams(initialParams);
+
+        mPanelOverlay.post(() -> {
+            mPanelOverlay.removeAllViews();
+            mPanelOverlay.addView(iconImageView);
+
+            ConstraintSet constraintSet = new ConstraintSet();
+            constraintSet.clone(mPanelOverlay);
+
+            // Center Horizontally
+            constraintSet.connect(iconImageView.getId(), ConstraintSet.START,
+                    ConstraintSet.PARENT_ID, ConstraintSet.START);
+            constraintSet.connect(iconImageView.getId(), ConstraintSet.END, ConstraintSet.PARENT_ID,
+                    ConstraintSet.END);
+
+            // Center Vertically
+            constraintSet.connect(iconImageView.getId(), ConstraintSet.TOP, ConstraintSet.PARENT_ID,
+                    ConstraintSet.TOP);
+            constraintSet.connect(iconImageView.getId(), ConstraintSet.BOTTOM,
+                    ConstraintSet.PARENT_ID, ConstraintSet.BOTTOM);
+
+            // Apply the constraints
+            constraintSet.applyTo(mPanelOverlay);
+        });
+    }
+}
diff --git a/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewServerImpl.java b/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewServerImpl.java
index bb7c8d71..8d9a9bfc 100644
--- a/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewServerImpl.java
+++ b/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewServerImpl.java
@@ -202,18 +202,8 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
             if (taskInfo == null) {
                 return;
             }
-            if (mTaskViewTransitions.isUsingShellTransitions() && mTaskViewTransitions != null) {
-                mTaskViewTransitions.setTaskViewVisible(mTaskViewTaskController, /* visible= */
-                        true, /* reorder= */ true);
-                return;
-            }
-
-            WindowContainerTransaction wct = new WindowContainerTransaction();
-            // Clears the hidden flag to make it TopFocusedRootTask: b/228092608
-            wct.setHidden(taskInfo.token, /* hidden= */ false);
-            // Moves the embedded task to the top to make it resumed: b/225388469
-            wct.reorder(taskInfo.token, /* onTop= */ true);
-            mShellTaskOrganizer.applyTransaction(wct);
+            mTaskViewTransitions.setTaskViewVisible(mTaskViewTaskController, /* visible= */
+                    true, /* reorder= */ true);
         }
 
         @Override
@@ -227,14 +217,7 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
             if (taskInfo == null) {
                 return;
             }
-            if (mTaskViewTransitions.isUsingShellTransitions()) {
-                mTaskViewTransitions.setTaskViewVisible(mTaskViewTaskController, visibility);
-                return;
-            }
-
-            WindowContainerTransaction wct = new WindowContainerTransaction();
-            wct.setHidden(taskInfo.token, !visibility);
-            mShellTaskOrganizer.applyTransaction(wct);
+            mTaskViewTransitions.setTaskViewVisible(mTaskViewTaskController, visibility);
         }
 
         @Override
@@ -249,14 +232,7 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
                 return;
             }
 
-            if (mTaskViewTransitions.isUsingShellTransitions()) {
-                mTaskViewTransitions.reorderTaskViewTask(mTaskViewTaskController, onTop);
-                return;
-            }
-
-            WindowContainerTransaction wct = new WindowContainerTransaction();
-            wct.reorder(taskInfo.token, onTop);
-            mShellTaskOrganizer.applyTransaction(wct);
+            mTaskViewTransitions.reorderTaskViewTask(mTaskViewTaskController, onTop);
         }
 
         @Override
diff --git a/src/com/android/systemui/car/wm/taskview/RootTaskMediator.java b/src/com/android/systemui/car/wm/taskview/RootTaskMediator.java
index ea34750f..68d20802 100644
--- a/src/com/android/systemui/car/wm/taskview/RootTaskMediator.java
+++ b/src/com/android/systemui/car/wm/taskview/RootTaskMediator.java
@@ -157,18 +157,10 @@ public final class RootTaskMediator implements ShellTaskOrganizer.TaskListener {
             }
 
             // Attach the root task with the taskview shell part.
-            if (mTransitions.isUsingShellTransitions()) {
-                // Do not trigger onTaskAppeared on shell part directly as it is no longer the
-                // correct entry point for a new task in the task view.
-                // Shell part will eventually trigger onTaskAppeared on the client as well.
-                mTransitions.startRootTask(mTaskViewTaskShellPart, taskInfo, leash, wct);
-            } else {
-                if (wct != null) {
-                    mShellTaskOrganizer.applyTransaction(wct);
-                }
-                // Shell part will eventually trigger onTaskAppeared on the client as well.
-                mTaskViewTaskShellPart.onTaskAppeared(taskInfo, leash);
-            }
+            // Do not trigger onTaskAppeared on shell part directly as it is no longer the
+            // correct entry point for a new task in the task view.
+            // Shell part will eventually trigger onTaskAppeared on the client as well.
+            mTransitions.startRootTask(mTaskViewTaskShellPart, taskInfo, leash, wct);
             return;
         }
 
@@ -256,12 +248,7 @@ public final class RootTaskMediator implements ShellTaskOrganizer.TaskListener {
         // from mLaunchRootStack
         wct.removeTask(topTask.token);
 
-        if (mTransitions.isUsingShellTransitions()) {
-            mTransitions.startInstantTransition(TRANSIT_CLOSE, wct);
-        } else {
-            mShellTaskOrganizer.applyTransaction(wct);
-        }
-
+        mTransitions.startInstantTransition(TRANSIT_CLOSE, wct);
     }
 
     @Override
@@ -308,11 +295,7 @@ public final class RootTaskMediator implements ShellTaskOrganizer.TaskListener {
         if (mIsLaunchRoot) {
             WindowContainerTransaction wct = new WindowContainerTransaction();
             wct.setLaunchRoot(mRootTask.token, null, null);
-            if (mTransitions.isUsingShellTransitions()) {
-                mTransitions.startInstantTransition(TRANSIT_CHANGE, wct);
-            } else {
-                mShellTaskOrganizer.applyTransaction(wct);
-            }
+            mTransitions.startInstantTransition(TRANSIT_CHANGE, wct);
         }
         // Should run on shell's executor
         mShellTaskOrganizer.deleteRootTask(mRootTask.token);
diff --git a/src/com/android/systemui/wm/DisplaySystemBarsController.java b/src/com/android/systemui/wm/DisplaySystemBarsController.java
index bc62b209..874e33e1 100644
--- a/src/com/android/systemui/wm/DisplaySystemBarsController.java
+++ b/src/com/android/systemui/wm/DisplaySystemBarsController.java
@@ -25,6 +25,10 @@ import static com.android.systemui.car.systembar.SystemBarUtil.SYSTEM_BAR_PERSIS
 import static com.android.systemui.car.systembar.SystemBarUtil.SYSTEM_BAR_PERSISTENCY_CONFIG_IMMERSIVE;
 import static com.android.systemui.car.systembar.SystemBarUtil.SYSTEM_BAR_PERSISTENCY_CONFIG_IMMERSIVE_WITH_NAV;
 import static com.android.systemui.car.systembar.SystemBarUtil.SYSTEM_BAR_PERSISTENCY_CONFIG_NON_IMMERSIVE;
+import static com.android.systemui.car.systembar.SystemBarUtil.SYSTEM_BAR_SUW_PERSISTENCY_CONFIG_DISABLED;
+import static com.android.systemui.car.systembar.SystemBarUtil.SYSTEM_BAR_SUW_PERSISTENCY_CONFIG_IMMERSIVE;
+import static com.android.systemui.car.systembar.SystemBarUtil.SYSTEM_BAR_SUW_PERSISTENCY_CONFIG_IMMERSIVE_WITH_NAV;
+import static com.android.systemui.car.systembar.SystemBarUtil.SYSTEM_BAR_SUW_PERSISTENCY_CONFIG_IMMERSIVE_WITH_STATUS;
 import static com.android.systemui.car.systembar.SystemBarUtil.VISIBLE_BAR_VISIBILITIES_TYPES_INDEX;
 import static com.android.systemui.car.systembar.SystemBarUtil.INVISIBLE_BAR_VISIBILITIES_TYPES_INDEX;
 import static com.android.systemui.car.users.CarSystemUIUserUtil.isSecondaryMUMDSystemUI;
@@ -32,15 +36,21 @@ import static com.android.systemui.car.Flags.packageLevelSystemBarVisibility;
 
 import android.annotation.NonNull;
 import android.annotation.Nullable;
+import android.app.ActivityManager;
+import android.car.settings.CarSettings;
 import android.content.BroadcastReceiver;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
+import android.database.ContentObserver;
+import android.net.Uri;
 import android.os.Build;
 import android.os.Handler;
 import android.os.PatternMatcher;
 import android.os.RemoteException;
+import android.os.UserHandle;
+import android.provider.Settings;
 import android.util.Slog;
 import android.util.SparseArray;
 import android.view.IDisplayWindowInsetsController;
@@ -63,6 +73,8 @@ import com.android.wm.shell.common.DisplayInsetsController;
 import java.util.Arrays;
 import java.util.Objects;
 
+import javax.annotation.concurrent.GuardedBy;
+
 /**
  * Controller that maps between displays and {@link IDisplayWindowInsetsController} in order to
  * give system bar control to SystemUI.
@@ -82,6 +94,7 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
     protected final IWindowManager mWmService;
     protected final DisplayInsetsController mDisplayInsetsController;
     protected final Handler mHandler;
+    protected final ContentObserver mSuwSettingsObserver;
 
     private final int[] mDefaultVisibilities =
             new int[]{WindowInsets.Type.systemBars(), 0};
@@ -98,6 +111,8 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
     private final int[] mImmersiveVisibilities =
             new int[]{0, WindowInsets.Type.systemBars()};
 
+    private final Object mPerDisplaySparseArrayLock = new Object();
+    @GuardedBy("mPerDisplaySparseArrayLock")
     @VisibleForTesting
     SparseArray<PerDisplay> mPerDisplaySparseArray;
     @InsetsType
@@ -106,6 +121,7 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
     private int mAppRequestedVisibleTypes = WindowInsets.Type.defaultVisible();
     @InsetsType
     private int mImmersiveState = systemBars();
+    private boolean mIsSuwInProgress = false;
 
     public DisplaySystemBarsController(
             Context context,
@@ -117,11 +133,24 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
         mWmService = wmService;
         mDisplayInsetsController = displayInsetsController;
         mHandler = mainHandler;
+
+        mSuwSettingsObserver = new ContentObserver(mHandler) {
+            @Override
+            public void onChange(boolean selfChange, @Nullable Uri uri,
+                    int flags) {
+                onUserSetupInProgressChanged();
+            }
+        };
+
         if (!isSecondaryMUMDSystemUI()) {
             // This WM controller should only be initialized once for the primary SystemUI, as it
             // will affect insets on all displays.
             // TODO(b/262773276): support per-user remote inset controllers
             displayController.addDisplayWindowListener(this);
+            mIsSuwInProgress = isSuwInProgress();
+            mContext.getContentResolver().registerContentObserver(Settings.Secure.getUriFor(
+                    CarSettings.Secure.KEY_SETUP_WIZARD_IN_PROGRESS),
+                    /* notifyForDescendants= */ true, mSuwSettingsObserver, UserHandle.USER_ALL);
         }
     }
 
@@ -130,24 +159,49 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
         PerDisplay pd = new PerDisplay(displayId);
         pd.register();
         // Lazy loading policy control filters instead of during boot.
-        if (mPerDisplaySparseArray == null) {
-            mPerDisplaySparseArray = new SparseArray<>();
-            BarControlPolicy.reloadFromSetting(mContext);
-            BarControlPolicy.registerContentObserver(mContext, mHandler, () -> {
-                int size = mPerDisplaySparseArray.size();
-                for (int i = 0; i < size; i++) {
-                    mPerDisplaySparseArray.valueAt(i).updateDisplayWindowRequestedVisibleTypes();
-                }
-            });
+        synchronized (mPerDisplaySparseArrayLock) {
+            if (mPerDisplaySparseArray == null) {
+                mPerDisplaySparseArray = new SparseArray<>();
+                BarControlPolicy.reloadFromSetting(mContext);
+                BarControlPolicy.registerContentObserver(mContext, mHandler, () -> {
+                    synchronized (mPerDisplaySparseArrayLock) {
+                        int size = mPerDisplaySparseArray.size();
+                        for (int i = 0; i < size; i++) {
+                            mPerDisplaySparseArray.valueAt(
+                                    i).updateDisplayWindowRequestedVisibleTypes();
+                        }
+                    }
+                });
+            }
+            mPerDisplaySparseArray.put(displayId, pd);
         }
-        mPerDisplaySparseArray.put(displayId, pd);
     }
 
     @Override
     public void onDisplayRemoved(int displayId) {
-        PerDisplay pd = mPerDisplaySparseArray.get(displayId);
-        pd.unregister();
-        mPerDisplaySparseArray.remove(displayId);
+        synchronized (mPerDisplaySparseArrayLock) {
+            PerDisplay pd = mPerDisplaySparseArray.get(displayId);
+            pd.unregister();
+            mPerDisplaySparseArray.remove(displayId);
+        }
+    }
+
+    private void onUserSetupInProgressChanged() {
+        mIsSuwInProgress = isSuwInProgress();
+        synchronized (mPerDisplaySparseArrayLock) {
+            if (mPerDisplaySparseArray == null) {
+                return;
+            }
+            for (int i = 0; i < mPerDisplaySparseArray.size(); i++) {
+                mPerDisplaySparseArray.valueAt(i).updateDisplayWindowRequestedVisibleTypes();
+            }
+        }
+    }
+
+    private boolean isSuwInProgress() {
+        return Settings.Secure.getIntForUser(mContext.getContentResolver(),
+                CarSettings.Secure.KEY_SETUP_WIZARD_IN_PROGRESS, 0,
+                ActivityManager.getCurrentUser()) != 0;
     }
 
     class PerDisplay implements DisplayInsetsController.OnInsetsChangedListener {
@@ -159,6 +213,7 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
         int mRequestedVisibleTypes = WindowInsets.Type.defaultVisible();
         String mPackageName;
         int mBehavior = 0;
+        int mSuwBehavior = 0;
         BroadcastReceiver mOverlayChangeBroadcastReceiver;
 
         PerDisplay(int displayId) {
@@ -173,6 +228,8 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
             );
             mBehavior = mContext.getResources().getInteger(
                     R.integer.config_systemBarPersistency);
+            mSuwBehavior = mContext.getResources().getInteger(
+                    R.integer.config_systemBarSuwBehavior);
         }
 
         public void register() {
@@ -192,18 +249,16 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
         }
 
         @Override
-        public void hideInsets(@InsetsType int types, boolean fromIme,
-                @Nullable ImeTracker.Token statsToken) {
+        public void hideInsets(@InsetsType int types, @Nullable ImeTracker.Token statsToken) {
             if ((types & WindowInsets.Type.ime()) == 0) {
-                mInsetsController.hide(types, /* fromIme = */ false, statsToken);
+                mInsetsController.hide(types, statsToken);
             }
         }
 
         @Override
-        public void showInsets(@InsetsType int types, boolean fromIme,
-                @Nullable ImeTracker.Token statsToken) {
+        public void showInsets(@InsetsType int types, @Nullable ImeTracker.Token statsToken) {
             if ((types & WindowInsets.Type.ime()) == 0) {
-                mInsetsController.show(types, /* fromIme= */ false, statsToken);
+                mInsetsController.show(types, statsToken);
             }
         }
 
@@ -328,9 +383,9 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
             mAppRequestedVisibleTypes = mRequestedVisibleTypes;
 
             showInsets(barVisibilities[VISIBLE_BAR_VISIBILITIES_TYPES_INDEX],
-                    /* fromIme= */ false, /* statsToken= */ null);
+                    /* statsToken= */ null);
             hideInsets(barVisibilities[INVISIBLE_BAR_VISIBILITIES_TYPES_INDEX],
-                    /* fromIme= */ false, /* statsToken = */ null);
+                    /* statsToken = */ null);
 
             int insetMask = barVisibilities[VISIBLE_BAR_VISIBILITIES_TYPES_INDEX]
                     | barVisibilities[INVISIBLE_BAR_VISIBILITIES_TYPES_INDEX];
@@ -345,7 +400,9 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
 
         private int[] getBarVisibilities(int immersiveState) {
             int[] barVisibilities;
-            if (mBehavior == SYSTEM_BAR_PERSISTENCY_CONFIG_BARPOLICY) {
+            if (mIsSuwInProgress && mSuwBehavior != SYSTEM_BAR_SUW_PERSISTENCY_CONFIG_DISABLED) {
+                barVisibilities = getBarVisibilitiesForSuw();
+            } else if (mBehavior == SYSTEM_BAR_PERSISTENCY_CONFIG_BARPOLICY) {
                 barVisibilities = packageLevelSystemBarVisibility()
                         ? BarControlPolicy.getBarVisibilities(
                                 mPackageName, mWindowRequestedVisibleTypes)
@@ -363,11 +420,27 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
             }
             if (DEBUG) {
                 Slog.d(TAG, "mBehavior=" + mBehavior + ", mImmersiveState = " + immersiveState
+                        + ", mIsSuwInProgress = " + mIsSuwInProgress
+                        + ", mSuwBehavior = " + mSuwBehavior
                         + ", barVisibilities to " + Arrays.toString(barVisibilities));
             }
             return barVisibilities;
         }
 
+        private int[] getBarVisibilitiesForSuw() {
+            if (mSuwBehavior == SYSTEM_BAR_SUW_PERSISTENCY_CONFIG_IMMERSIVE) {
+                return mImmersiveVisibilities;
+            } else if (mSuwBehavior == SYSTEM_BAR_SUW_PERSISTENCY_CONFIG_IMMERSIVE_WITH_NAV) {
+                return mImmersiveWithNavBarVisibilities;
+            } else if (mSuwBehavior == SYSTEM_BAR_SUW_PERSISTENCY_CONFIG_IMMERSIVE_WITH_STATUS) {
+                return mImmersiveWithStatusBarVisibilities;
+            } else {
+                Slog.e(TAG, "Invalid SUW visibility config " + mSuwBehavior
+                        + " - using default visibility");
+                return mDefaultVisibilities;
+            }
+        }
+
         protected void updateRequestedVisibleTypes(@InsetsType int types, boolean visible) {
             mRequestedVisibleTypes = visible
                     ? (mRequestedVisibleTypes | types)
diff --git a/src/com/android/systemui/wmshell/CarWMComponent.java b/src/com/android/systemui/wmshell/CarWMComponent.java
index c2623980..fceab6ce 100644
--- a/src/com/android/systemui/wmshell/CarWMComponent.java
+++ b/src/com/android/systemui/wmshell/CarWMComponent.java
@@ -16,6 +16,7 @@
 
 package com.android.systemui.wmshell;
 
+import com.android.systemui.car.wm.AutoCaptionPerDisplayInitializer;
 import com.android.systemui.car.wm.CarSystemUIProxyImpl;
 import com.android.systemui.car.wm.displayarea.DaViewTransitions;
 import com.android.systemui.car.wm.scalableui.EventDispatcher;
@@ -55,6 +56,12 @@ public interface CarWMComponent extends WMComponent {
     @WMSingleton
     DisplaySystemBarsController getDisplaySystemBarsController();
 
+    /**
+     * Returns the initializer used to initialize AutoCaption per display.
+     */
+    @WMSingleton
+    Optional<AutoCaptionPerDisplayInitializer> getAutoCaptionPerDisplayInitializer();
+
     /**
      * Returns the implementation of car system ui proxy which will be used by other apps to
      * interact with the car system ui.
diff --git a/src/com/android/systemui/wmshell/CarWMShellModule.java b/src/com/android/systemui/wmshell/CarWMShellModule.java
index 45df7a9f..4202d478 100644
--- a/src/com/android/systemui/wmshell/CarWMShellModule.java
+++ b/src/com/android/systemui/wmshell/CarWMShellModule.java
@@ -27,6 +27,7 @@ import androidx.annotation.NonNull;
 
 import com.android.systemui.R;
 import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.car.wm.AutoCaptionPerDisplayInitializer;
 import com.android.systemui.car.wm.AutoDisplayCompatWindowDecorViewModel;
 import com.android.systemui.car.wm.CarFullscreenTaskMonitorListener;
 import com.android.systemui.car.wm.scalableui.PanelAutoTaskStackTransitionHandlerDelegate;
@@ -36,7 +37,9 @@ import com.android.systemui.car.wm.scalableui.panel.DecorPanel;
 import com.android.systemui.car.wm.scalableui.panel.TaskPanel;
 import com.android.systemui.dagger.qualifiers.Main;
 import com.android.systemui.wm.DisplaySystemBarsController;
+import com.android.wm.shell.RootTaskDisplayAreaOrganizer;
 import com.android.wm.shell.ShellTaskOrganizer;
+import com.android.wm.shell.automotive.AutoCaptionController;
 import com.android.wm.shell.automotive.AutoShellModule;
 import com.android.wm.shell.automotive.AutoTaskRepository;
 import com.android.wm.shell.common.DisplayController;
@@ -54,6 +57,7 @@ import com.android.wm.shell.shared.annotations.ShellMainThread;
 import com.android.wm.shell.sysui.ShellInit;
 import com.android.wm.shell.taskview.TaskViewTransitions;
 import com.android.wm.shell.transition.FocusTransitionObserver;
+import com.android.wm.shell.transition.Transitions;
 import com.android.wm.shell.windowdecor.WindowDecorViewModel;
 import com.android.wm.shell.windowdecor.common.viewhost.DefaultWindowDecorViewHostSupplier;
 import com.android.wm.shell.windowdecor.common.viewhost.WindowDecorViewHost;
@@ -82,6 +86,19 @@ public abstract class CarWMShellModule {
                 displayInsetsController, mainHandler);
     }
 
+    @WMSingleton
+    @Provides
+    static Optional<AutoCaptionPerDisplayInitializer> provideAutoCaptionPerDisplayInitializer(
+            Context context,
+            ShellTaskOrganizer shellTaskOrganizer,
+            AutoCaptionController autoCaptionController,
+            DisplayController displayController,
+            RootTaskDisplayAreaOrganizer rootTaskDisplayAreaOrganizer) {
+        return Optional.of(
+                new AutoCaptionPerDisplayInitializer(context, shellTaskOrganizer,
+                        autoCaptionController, displayController, rootTaskDisplayAreaOrganizer));
+    }
+
     @BindsOptionalOf
     abstract Pip optionalPip();
 
@@ -119,6 +136,8 @@ public abstract class CarWMShellModule {
     @Provides
     static WindowDecorViewModel provideWindowDecorViewModel(
             Context context,
+            @ShellMainThread Handler handler,
+            Transitions transitions,
             @ShellMainThread ShellExecutor mainExecutor,
             @ShellBackgroundThread ShellExecutor bgExecutor,
             ShellInit shellInit,
@@ -132,6 +151,8 @@ public abstract class CarWMShellModule {
     ) {
         return new AutoDisplayCompatWindowDecorViewModel(
                 context,
+                handler,
+                transitions,
                 mainExecutor,
                 bgExecutor,
                 shellInit,
diff --git a/tests/AndroidTest.xml b/tests/AndroidTest.xml
index 05d21883..46784781 100644
--- a/tests/AndroidTest.xml
+++ b/tests/AndroidTest.xml
@@ -26,6 +26,7 @@
     <test class="com.android.tradefed.testtype.AndroidJUnitTest">
         <option name="package" value="com.android.systemui.tests"/>
         <option name="runner" value="android.testing.TestableInstrumentation"/>
+        <option name="include-annotation" value="com.android.systemui.car.CarSystemUiTest" />
         <option name="hidden-api-checks" value="false"/>
     </test>
 </configuration>
diff --git a/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt b/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt
index ceb3856b..2ac9a88d 100644
--- a/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt
+++ b/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt
@@ -105,4 +105,6 @@ class FakeDisplayRepository(
     override val defaultDisplayOff: Flow<Boolean> = emptyFlow(),
     override val pendingDisplay: Flow<PendingDisplay?> = fakePendingDisplayFlow,
     override val displayIds: StateFlow<Set<Int>> = MutableStateFlow(emptySet()),
-) : DisplayRepository
+) : DisplayRepository {
+    override fun getDisplay(displayId: Int): Display? = null
+}
diff --git a/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewControllerTest.java b/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewControllerTest.java
index 41ce6ebb..c2e5dd03 100644
--- a/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewControllerTest.java
@@ -156,6 +156,8 @@ public class HvacPanelOverlayViewControllerTest extends CarSysuiTestCase {
         when(mockHvacPanelParentView.indexOfChild(mockHvacPanelView)).thenReturn(mockIndex);
         when(mockHvacPanelParentView.generateLayoutParams(any())).thenReturn(
                 mock(ViewGroup.LayoutParams.class));
+        when(mockHvacPanelParentView.generateLayoutParams(any(), any())).thenReturn(
+                mock(ViewGroup.LayoutParams.class));
         when(mockHvacPanelView.getParent()).thenReturn(mockHvacPanelParentView);
         when(mockHvacPanelView.getLayoutParams()).thenReturn(mock(ViewGroup.LayoutParams.class));
         when(mockHvacPanelView.findViewById(R.id.hvac_temperature_text)).thenReturn(
diff --git a/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java b/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java
index aa750247..d4726ec2 100644
--- a/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java
@@ -52,6 +52,7 @@ import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.window.OverlayViewGlobalStateController;
 import com.android.systemui.car.window.SystemUIOverlayWindowController;
 import com.android.systemui.keyguard.ui.viewmodel.GlanceableHubToPrimaryBouncerTransitionViewModel;
+import com.android.systemui.keyguard.ui.viewmodel.PrimaryBouncerToDreamingTransitionViewModel;
 import com.android.systemui.keyguard.ui.viewmodel.PrimaryBouncerToGoneTransitionViewModel;
 import com.android.systemui.log.BouncerLogger;
 import com.android.systemui.settings.UserTracker;
@@ -64,6 +65,8 @@ import com.android.systemui.util.concurrency.FakeExecutor;
 import com.android.systemui.util.kotlin.JavaAdapter;
 import com.android.systemui.util.time.FakeSystemClock;
 
+import kotlinx.coroutines.CoroutineDispatcher;
+
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -104,6 +107,9 @@ public class CarKeyguardViewControllerTest extends CarSysuiTestCase {
     @Mock
     private KeyguardBouncerComponent.Factory mKeyguardBouncerComponentFactory;
     @Mock
+    private PrimaryBouncerToDreamingTransitionViewModel
+            mPrimaryBouncerToDreamingTransitionViewModel;
+    @Mock
     private PrimaryBouncerToGoneTransitionViewModel mPrimaryBouncerToGoneTransitionViewModel;
     @Mock
     private GlanceableHubToPrimaryBouncerTransitionViewModel
@@ -146,6 +152,7 @@ public class CarKeyguardViewControllerTest extends CarSysuiTestCase {
                 mPrimaryBouncerInteractor,
                 mKeyguardSecurityModel,
                 mKeyguardBouncerViewModel,
+                mPrimaryBouncerToDreamingTransitionViewModel,
                 mPrimaryBouncerToGoneTransitionViewModel,
                 mGlanceableHubToPrimaryBouncerTransitionViewModel,
                 mKeyguardBouncerComponentFactory,
@@ -156,6 +163,7 @@ public class CarKeyguardViewControllerTest extends CarSysuiTestCase {
                 mock(SelectedUserInteractor.class),
                 Optional.of(mKeyguardSystemBarPresenter),
                 mock(StatusBarKeyguardViewManagerInteractor.class),
+                mock(CoroutineDispatcher.class),
                 mock(JavaAdapter.class)
         );
         mCarKeyguardViewController.inflate((ViewGroup) LayoutInflater.from(mContext).inflate(
diff --git a/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerTest.java b/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerTest.java
index ddcde34c..cb2564dd 100644
--- a/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/keyguard/passenger/PassengerKeyguardCredentialViewControllerTest.java
@@ -102,7 +102,7 @@ public class PassengerKeyguardCredentialViewControllerTest extends CarSysuiTestC
 
         ExtendedMockito.verify(() -> LockPatternChecker.verifyCredential(any(), any(), anyInt(),
                 anyInt(), captor.capture()));
-        captor.getValue().onVerified(VerifyCredentialResponse.ERROR, 0);
+        captor.getValue().onVerified(VerifyCredentialResponse.OTHER_ERROR, 0);
         verify(mMainHandler).post(failureRunnable);
     }
 
@@ -117,7 +117,7 @@ public class PassengerKeyguardCredentialViewControllerTest extends CarSysuiTestC
 
         ExtendedMockito.verify(() -> LockPatternChecker.verifyCredential(any(), any(), anyInt(),
                 anyInt(), captor.capture()));
-        captor.getValue().onVerified(VerifyCredentialResponse.ERROR, throttleTimeoutMs);
+        captor.getValue().onVerified(VerifyCredentialResponse.OTHER_ERROR, throttleTimeoutMs);
         ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
         verify(mMainHandler).post(runnableCaptor.capture());
         runnableCaptor.getValue().run();
diff --git a/tests/src/com/android/systemui/car/privacy/CameraQcPanelTest.java b/tests/src/com/android/systemui/car/privacy/CameraQcPanelTest.java
index 90a22a4c..52b7a088 100644
--- a/tests/src/com/android/systemui/car/privacy/CameraQcPanelTest.java
+++ b/tests/src/com/android/systemui/car/privacy/CameraQcPanelTest.java
@@ -40,7 +40,6 @@ import com.android.car.qc.QCList;
 import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
 import com.android.systemui.car.CarSystemUiTest;
-import com.android.systemui.car.systembar.CameraPrivacyChipViewController;
 import com.android.systemui.privacy.PrivacyDialog;
 
 import org.junit.Before;
@@ -71,9 +70,7 @@ public class CameraQcPanelTest extends CarSysuiTestCase {
     @Mock
     private Context mUserContext;
     @Mock
-    private CameraPrivacyElementsProviderImpl mCameraPrivacyElementsProvider;
-    @Mock
-    private CameraPrivacyChipViewController mCameraSensorInfoProvider;
+    private CameraSensorPrivacyInfoProvider mCameraSensorInfoProvider;
     @Mock
     private PackageManager mPackageManager;
     @Mock
@@ -89,8 +86,7 @@ public class CameraQcPanelTest extends CarSysuiTestCase {
         mContext.prepareCreateContextAsUser(UserHandle.SYSTEM, mUserContext);
         when(mUserContext.getPackageManager()).thenReturn(mPackageManager);
 
-        mCameraQcPanel = new CameraQcPanel(mContext, mCameraSensorInfoProvider,
-                mCameraPrivacyElementsProvider);
+        mCameraQcPanel = new CameraQcPanel(mContext, mCameraSensorInfoProvider);
 
         mPhoneCallTitle = mContext.getString(R.string.ongoing_privacy_dialog_phonecall);
         mCameraOnTitleText = mContext.getString(R.string.privacy_chip_use_sensor,
@@ -104,7 +100,7 @@ public class CameraQcPanelTest extends CarSysuiTestCase {
     public void testGetQCItem_cameraDisabled_noPrivacyItems_returnsOnlyCameraOffRow() {
         when(mCameraSensorInfoProvider.isSensorEnabled()).thenReturn(false);
         List<PrivacyDialog.PrivacyElement> elements = Collections.emptyList();
-        when(mCameraPrivacyElementsProvider.getPrivacyElements()).thenReturn(elements);
+        when(mCameraSensorInfoProvider.getPrivacyElements()).thenReturn(elements);
 
         QCList list = getQCList();
 
@@ -116,7 +112,7 @@ public class CameraQcPanelTest extends CarSysuiTestCase {
     public void testGetQCItem_cameraEnabled_noPrivacyItems_returnsOnlyCameraOffRow() {
         when(mCameraSensorInfoProvider.isSensorEnabled()).thenReturn(true);
         List<PrivacyDialog.PrivacyElement> elements = Collections.emptyList();
-        when(mCameraPrivacyElementsProvider.getPrivacyElements()).thenReturn(elements);
+        when(mCameraSensorInfoProvider.getPrivacyElements()).thenReturn(elements);
 
         QCList list = getQCList();
 
@@ -129,7 +125,7 @@ public class CameraQcPanelTest extends CarSysuiTestCase {
         when(mCameraSensorInfoProvider.isSensorEnabled()).thenReturn(true);
         List<PrivacyDialog.PrivacyElement> elements =
                 List.of(getPrivacyElement(/* active=*/ true, /* phoneCall= */ false));
-        when(mCameraPrivacyElementsProvider.getPrivacyElements()).thenReturn(elements);
+        when(mCameraSensorInfoProvider.getPrivacyElements()).thenReturn(elements);
 
         QCList list = getQCList();
 
@@ -144,7 +140,7 @@ public class CameraQcPanelTest extends CarSysuiTestCase {
         when(mCameraSensorInfoProvider.isSensorEnabled()).thenReturn(true);
         List<PrivacyDialog.PrivacyElement> elements =
                 List.of(getPrivacyElement(/* active=*/ true, /* phoneCall= */ false));
-        when(mCameraPrivacyElementsProvider.getPrivacyElements()).thenReturn(elements);
+        when(mCameraSensorInfoProvider.getPrivacyElements()).thenReturn(elements);
 
         QCList list = getQCList();
 
@@ -158,7 +154,7 @@ public class CameraQcPanelTest extends CarSysuiTestCase {
         when(mCameraSensorInfoProvider.isSensorEnabled()).thenReturn(false);
         List<PrivacyDialog.PrivacyElement> elements =
                 List.of(getPrivacyElement(/* active=*/ false, /* phoneCall= */ true));
-        when(mCameraPrivacyElementsProvider.getPrivacyElements()).thenReturn(elements);
+        when(mCameraSensorInfoProvider.getPrivacyElements()).thenReturn(elements);
 
         QCList list = getQCList();
 
@@ -175,7 +171,7 @@ public class CameraQcPanelTest extends CarSysuiTestCase {
         when(mCameraSensorInfoProvider.isSensorEnabled()).thenReturn(false);
         List<PrivacyDialog.PrivacyElement> elements =
                 List.of(getPrivacyElement(/* active=*/ false, /* phoneCall= */ true));
-        when(mCameraPrivacyElementsProvider.getPrivacyElements()).thenReturn(elements);
+        when(mCameraSensorInfoProvider.getPrivacyElements()).thenReturn(elements);
 
         QCList list = getQCList();
 
@@ -192,7 +188,7 @@ public class CameraQcPanelTest extends CarSysuiTestCase {
         elements.add(getPrivacyElement(/* active=*/ false, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ true));
-        when(mCameraPrivacyElementsProvider.getPrivacyElements())
+        when(mCameraSensorInfoProvider.getPrivacyElements())
                 .thenReturn(elements);
 
         QCList list = getQCList();
@@ -212,7 +208,7 @@ public class CameraQcPanelTest extends CarSysuiTestCase {
         elements.add(getPrivacyElement(/* active=*/ false, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ true));
-        when(mCameraPrivacyElementsProvider.getPrivacyElements())
+        when(mCameraSensorInfoProvider.getPrivacyElements())
                 .thenReturn(elements);
 
         QCList list = getQCList();
@@ -232,7 +228,7 @@ public class CameraQcPanelTest extends CarSysuiTestCase {
         elements.add(getPrivacyElement(/* active=*/ false, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ true));
-        when(mCameraPrivacyElementsProvider.getPrivacyElements())
+        when(mCameraSensorInfoProvider.getPrivacyElements())
                 .thenReturn(elements);
 
         QCList list = getQCList();
@@ -253,7 +249,7 @@ public class CameraQcPanelTest extends CarSysuiTestCase {
         elements.add(getPrivacyElement(/* active=*/ false, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ true));
-        when(mCameraPrivacyElementsProvider.getPrivacyElements())
+        when(mCameraSensorInfoProvider.getPrivacyElements())
                 .thenReturn(elements);
 
         QCList list = getQCList();
diff --git a/tests/src/com/android/systemui/car/privacy/MicQcPanelTest.java b/tests/src/com/android/systemui/car/privacy/MicQcPanelTest.java
index 047cd9bc..461daa63 100644
--- a/tests/src/com/android/systemui/car/privacy/MicQcPanelTest.java
+++ b/tests/src/com/android/systemui/car/privacy/MicQcPanelTest.java
@@ -40,7 +40,6 @@ import com.android.car.qc.QCList;
 import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
 import com.android.systemui.car.CarSystemUiTest;
-import com.android.systemui.car.systembar.MicPrivacyChipViewController;
 import com.android.systemui.privacy.PrivacyDialog;
 
 import org.junit.Before;
@@ -71,9 +70,7 @@ public class MicQcPanelTest extends CarSysuiTestCase {
     @Mock
     private Context mUserContext;
     @Mock
-    private MicPrivacyElementsProviderImpl mMicPrivacyElementsProvider;
-    @Mock
-    private MicPrivacyChipViewController mMicSensorInfoProvider;
+    private MicSensorPrivacyInfoProvider mMicSensorInfoProvider;
     @Mock
     private PackageManager mPackageManager;
     @Mock
@@ -89,8 +86,7 @@ public class MicQcPanelTest extends CarSysuiTestCase {
         mContext.prepareCreateContextAsUser(UserHandle.SYSTEM, mUserContext);
         when(mUserContext.getPackageManager()).thenReturn(mPackageManager);
 
-        mMicQcPanel = new MicQcPanel(mContext, mMicSensorInfoProvider,
-                mMicPrivacyElementsProvider);
+        mMicQcPanel = new MicQcPanel(mContext, mMicSensorInfoProvider);
 
         mPhoneCallTitle = mContext.getString(R.string.ongoing_privacy_dialog_phonecall);
         mMicOnTitleText = mContext.getString(R.string.privacy_chip_use_sensor,
@@ -104,7 +100,7 @@ public class MicQcPanelTest extends CarSysuiTestCase {
     public void testGetQCItem_micDisabled_noPrivacyItems_returnsOnlyMicMutedRow() {
         when(mMicSensorInfoProvider.isSensorEnabled()).thenReturn(false);
         List<PrivacyDialog.PrivacyElement> elements = Collections.emptyList();
-        when(mMicPrivacyElementsProvider.getPrivacyElements()).thenReturn(elements);
+        when(mMicSensorInfoProvider.getPrivacyElements()).thenReturn(elements);
 
         QCList list = getQCList();
 
@@ -116,7 +112,7 @@ public class MicQcPanelTest extends CarSysuiTestCase {
     public void testGetQCItem_micEnabled_noPrivacyItems_returnsOnlyMicMutedRow() {
         when(mMicSensorInfoProvider.isSensorEnabled()).thenReturn(true);
         List<PrivacyDialog.PrivacyElement> elements = Collections.emptyList();
-        when(mMicPrivacyElementsProvider.getPrivacyElements()).thenReturn(elements);
+        when(mMicSensorInfoProvider.getPrivacyElements()).thenReturn(elements);
 
         QCList list = getQCList();
 
@@ -129,7 +125,7 @@ public class MicQcPanelTest extends CarSysuiTestCase {
         when(mMicSensorInfoProvider.isSensorEnabled()).thenReturn(true);
         List<PrivacyDialog.PrivacyElement> elements =
                 List.of(getPrivacyElement(/* active=*/ true, /* phoneCall= */ false));
-        when(mMicPrivacyElementsProvider.getPrivacyElements()).thenReturn(elements);
+        when(mMicSensorInfoProvider.getPrivacyElements()).thenReturn(elements);
 
         QCList list = getQCList();
 
@@ -144,7 +140,7 @@ public class MicQcPanelTest extends CarSysuiTestCase {
         when(mMicSensorInfoProvider.isSensorEnabled()).thenReturn(true);
         List<PrivacyDialog.PrivacyElement> elements =
                 List.of(getPrivacyElement(/* active=*/ true, /* phoneCall= */ false));
-        when(mMicPrivacyElementsProvider.getPrivacyElements()).thenReturn(elements);
+        when(mMicSensorInfoProvider.getPrivacyElements()).thenReturn(elements);
 
         QCList list = getQCList();
 
@@ -157,7 +153,7 @@ public class MicQcPanelTest extends CarSysuiTestCase {
         when(mMicSensorInfoProvider.isSensorEnabled()).thenReturn(false);
         List<PrivacyDialog.PrivacyElement> elements =
                 List.of(getPrivacyElement(/* active=*/ false, /* phoneCall= */ true));
-        when(mMicPrivacyElementsProvider.getPrivacyElements()).thenReturn(elements);
+        when(mMicSensorInfoProvider.getPrivacyElements()).thenReturn(elements);
 
         QCList list = getQCList();
 
@@ -173,7 +169,7 @@ public class MicQcPanelTest extends CarSysuiTestCase {
         when(mMicSensorInfoProvider.isSensorEnabled()).thenReturn(false);
         List<PrivacyDialog.PrivacyElement> elements =
                 List.of(getPrivacyElement(/* active=*/ false, /* phoneCall= */ true));
-        when(mMicPrivacyElementsProvider.getPrivacyElements()).thenReturn(elements);
+        when(mMicSensorInfoProvider.getPrivacyElements()).thenReturn(elements);
 
         QCList list = getQCList();
 
@@ -190,7 +186,7 @@ public class MicQcPanelTest extends CarSysuiTestCase {
         elements.add(getPrivacyElement(/* active=*/ false, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ true));
-        when(mMicPrivacyElementsProvider.getPrivacyElements())
+        when(mMicSensorInfoProvider.getPrivacyElements())
                 .thenReturn(elements);
 
         QCList list = getQCList();
@@ -210,7 +206,7 @@ public class MicQcPanelTest extends CarSysuiTestCase {
         elements.add(getPrivacyElement(/* active=*/ false, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ true));
-        when(mMicPrivacyElementsProvider.getPrivacyElements())
+        when(mMicSensorInfoProvider.getPrivacyElements())
                 .thenReturn(elements);
 
         QCList list = getQCList();
@@ -230,7 +226,7 @@ public class MicQcPanelTest extends CarSysuiTestCase {
         elements.add(getPrivacyElement(/* active=*/ false, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ true));
-        when(mMicPrivacyElementsProvider.getPrivacyElements())
+        when(mMicSensorInfoProvider.getPrivacyElements())
                 .thenReturn(elements);
 
         QCList list = getQCList();
@@ -251,7 +247,7 @@ public class MicQcPanelTest extends CarSysuiTestCase {
         elements.add(getPrivacyElement(/* active=*/ false, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ false));
         elements.add(getPrivacyElement(/* active=*/ true, /* phoneCall= */ true));
-        when(mMicPrivacyElementsProvider.getPrivacyElements())
+        when(mMicSensorInfoProvider.getPrivacyElements())
                 .thenReturn(elements);
 
         QCList list = getQCList();
diff --git a/tests/src/com/android/systemui/car/qc/DataSubscriptionControllerTest.java b/tests/src/com/android/systemui/car/qc/DataSubscriptionControllerTest.java
deleted file mode 100644
index ba0996f2..00000000
--- a/tests/src/com/android/systemui/car/qc/DataSubscriptionControllerTest.java
+++ /dev/null
@@ -1,439 +0,0 @@
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
-package com.android.systemui.car.qc;
-
-import static android.Manifest.permission.ACCESS_NETWORK_STATE;
-import static android.Manifest.permission.INTERNET;
-
-import static com.android.car.datasubscription.Flags.FLAG_DATA_SUBSCRIPTION_POP_UP;
-import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
-import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
-
-import static org.junit.Assert.assertFalse;
-import static org.junit.Assert.assertTrue;
-import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.ArgumentMatchers.anyInt;
-import static org.mockito.ArgumentMatchers.anyString;
-import static org.mockito.Mockito.mock;
-import static org.mockito.Mockito.never;
-import static org.mockito.Mockito.spy;
-import static org.mockito.Mockito.verify;
-import static org.mockito.Mockito.when;
-
-import android.app.ActivityManager;
-import android.car.drivingstate.CarUxRestrictions;
-import android.content.ComponentName;
-import android.content.pm.ApplicationInfo;
-import android.content.pm.PackageInfo;
-import android.content.pm.PackageManager;
-import android.net.ConnectivityManager;
-import android.net.Network;
-import android.os.Handler;
-import android.os.RemoteException;
-import android.os.UserHandle;
-import android.platform.test.annotations.RequiresFlagsEnabled;
-import android.platform.test.flag.junit.CheckFlagsRule;
-import android.platform.test.flag.junit.DeviceFlagsValueProvider;
-import android.testing.AndroidTestingRunner;
-import android.testing.TestableLooper;
-import android.view.View;
-import android.widget.Button;
-import android.widget.PopupWindow;
-
-import androidx.test.filters.SmallTest;
-
-import com.android.car.datasubscription.DataSubscription;
-import com.android.car.datasubscription.DataSubscriptionStatus;
-import com.android.car.ui.utils.CarUxRestrictionsUtil;
-import com.android.systemui.CarSysuiTestCase;
-import com.android.systemui.R;
-import com.android.systemui.car.CarSystemUiTest;
-import com.android.systemui.settings.UserTracker;
-import com.android.systemui.util.FakeSharedPreferences;
-
-import org.junit.After;
-import org.junit.Assert;
-import org.junit.Before;
-import org.junit.Rule;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.mockito.ArgumentCaptor;
-import org.mockito.Mock;
-import org.mockito.MockitoSession;
-import org.mockito.quality.Strictness;
-
-import java.util.HashSet;
-import java.util.concurrent.Executor;
-
-@CarSystemUiTest
-@RunWith(AndroidTestingRunner.class)
-@TestableLooper.RunWithLooper
-@SmallTest
-public class DataSubscriptionControllerTest extends CarSysuiTestCase {
-    @Mock
-    private UserTracker mUserTracker;
-    @Mock
-    private DataSubscription mDataSubscription;
-    @Mock
-    private PopupWindow mPopupWindow;
-    @Mock
-    private View mAnchorView;
-    @Mock
-    private ConnectivityManager mConnectivityManager;
-    @Mock
-    private PackageManager mPackageManager;
-    @Mock
-    private DataSubscriptionController.DataSubscriptionNetworkCallback mNetworkCallback;
-    @Mock
-    private Network mTestNetwork;
-    @Mock
-    private Handler mHandler;
-    @Mock
-    private Executor mExecutor;
-    @Mock
-    private CarUxRestrictionsUtil mCarUxRestrictionsUtil;
-    @Mock
-    private DataSubscriptionStatsLogHelper mDataSubscriptionStatsLogHelper;
-    private final FakeSharedPreferences mSharedPreferences = new FakeSharedPreferences();
-    private MockitoSession mMockingSession;
-    private ActivityManager.RunningTaskInfo mRunningTaskInfoMock;
-    private DataSubscriptionController mController;
-    @Rule
-    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
-
-    @Before
-    public void setUp() {
-        mMockingSession = mockitoSession()
-                .initMocks(this)
-                .mockStatic(CarUxRestrictionsUtil.class)
-                .strictness(Strictness.WARN)
-                .startMocking();
-
-        mContext = spy(mContext);
-        when(mUserTracker.getUserHandle()).thenReturn(UserHandle.of(1000));
-        mController = new DataSubscriptionController(mContext, mUserTracker, mHandler, mExecutor,
-                mDataSubscriptionStatsLogHelper);
-        mController.setSubscription(mDataSubscription);
-        mController.setPopupWindow(mPopupWindow);
-        mController.setConnectivityManager(mConnectivityManager);
-        mController.setSharedPreference(mSharedPreferences);
-        mRunningTaskInfoMock = new ActivityManager.RunningTaskInfo();
-        mRunningTaskInfoMock.topActivity = new ComponentName("testPkgName", "testClassName");
-        mRunningTaskInfoMock.taskId = 1;
-        mNetworkCallback.mNetwork = mTestNetwork;
-        doReturn(mCarUxRestrictionsUtil).when(() -> CarUxRestrictionsUtil.getInstance(any()));
-    }
-
-    @After
-    public void tearDown() {
-        if (mMockingSession != null) {
-            mMockingSession.finishMocking();
-        }
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void updateShouldDisplayProactiveMsg_noCachedTimeInterval_popUpDisplay() {
-        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
-                "2025-01-15");
-        when(mPopupWindow.isShowing()).thenReturn(false);
-        when(mDataSubscription.isDataSubscriptionInactive()).thenReturn(true);
-
-        mController.setWasProactiveMsgDisplayed(false);
-        mController.setCurrentInterval(mContext.getResources()
-                .getInteger(R.integer.data_subscription_pop_up_frequency) + 1);
-
-        mController.updateShouldDisplayProactiveMsg();
-
-        assertTrue(mController.getShouldDisplayProactiveMsg());
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void updateShouldDisplayProactiveMsg_allConfigsAreValid_popUpDisplay() {
-        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
-                "2025-01-15");
-        when(mPopupWindow.isShowing()).thenReturn(false);
-        when(mDataSubscription.isDataSubscriptionInactive()).thenReturn(true);
-
-        mController.setWasProactiveMsgDisplayed(false);
-        mController.setCurrentInterval(mContext.getResources()
-                .getInteger(R.integer.data_subscription_pop_up_frequency));
-        mController.setCurrentCycle(mContext.getResources()
-                .getInteger(R.integer.data_subscription_pop_up_startup_cycle_limit));
-        mController.setCurrentActiveDays(mContext.getResources()
-                .getInteger(R.integer.data_subscription_pop_up_active_days_limit));
-
-        mController.updateShouldDisplayProactiveMsg();
-
-        assertTrue(mController.getShouldDisplayProactiveMsg());
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void updateShouldDisplayProactiveMsg_invalidTimeInterval_popUpNotDisplay() {
-        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
-                "2025-01-15");
-        when(mPopupWindow.isShowing()).thenReturn(false);
-        when(mDataSubscription.isDataSubscriptionInactive()).thenReturn(true);
-
-        mController.setWasProactiveMsgDisplayed(false);
-        mController.setCurrentInterval(mContext.getResources()
-                .getInteger(R.integer.data_subscription_pop_up_frequency) - 1);
-        mController.setCurrentCycle(mContext.getResources()
-                .getInteger(R.integer.data_subscription_pop_up_startup_cycle_limit));
-
-        mController.updateShouldDisplayProactiveMsg();
-
-        assertFalse(mController.getShouldDisplayProactiveMsg());
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void updateShouldDisplayProactiveMsg_invalidCycle_popUpNotDisplay() {
-        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
-                "2025-01-15");
-        when(mPopupWindow.isShowing()).thenReturn(false);
-        when(mDataSubscription.isDataSubscriptionInactive()).thenReturn(true);
-
-        mController.setWasProactiveMsgDisplayed(false);
-        mController.setCurrentInterval(mContext.getResources()
-                .getInteger(R.integer.data_subscription_pop_up_frequency));
-        mController.setCurrentCycle(mContext.getResources()
-                .getInteger(R.integer.data_subscription_pop_up_startup_cycle_limit));
-        mController.setCurrentCycle(mContext.getResources()
-                .getInteger(R.integer.data_subscription_pop_up_startup_cycle_limit) + 1);
-
-        mController.updateShouldDisplayProactiveMsg();
-
-        assertFalse(mController.getShouldDisplayProactiveMsg());
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void updateShouldDisplayProactiveMsg_invalidActiveDays_popUpNotDisplay() {
-        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
-                "2025-01-15");
-        when(mPopupWindow.isShowing()).thenReturn(false);
-        when(mDataSubscription.isDataSubscriptionInactive()).thenReturn(true);
-        mController.setWasProactiveMsgDisplayed(false);
-        mController.setCurrentInterval(mContext.getResources()
-                .getInteger(R.integer.data_subscription_pop_up_frequency));
-        mController.setCurrentCycle(mContext.getResources()
-                .getInteger(R.integer.data_subscription_pop_up_startup_cycle_limit) + 1);
-
-        mController.updateShouldDisplayProactiveMsg();
-
-        assertFalse(mController.getShouldDisplayProactiveMsg());
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void updateShouldDisplayProactiveMsg_resetStatus_popUpDisplay() {
-        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
-                "2025-01-15");
-        when(mPopupWindow.isShowing()).thenReturn(false);
-        when(mDataSubscription.isDataSubscriptionInactive()).thenReturn(true);
-        mSharedPreferences.edit().putInt(DataSubscriptionController.KEY_PREV_POPUP_STATUS,
-                DataSubscriptionStatus.INACTIVE);
-
-        mController.setWasProactiveMsgDisplayed(false);
-        mController.setCurrentInterval(mContext.getResources()
-                .getInteger(R.integer.data_subscription_pop_up_frequency));
-        mController.setCurrentCycle(mContext.getResources()
-                .getInteger(R.integer.data_subscription_pop_up_startup_cycle_limit));
-        mController.setCurrentActiveDays(mContext.getResources()
-                .getInteger(R.integer.data_subscription_pop_up_active_days_limit) + 1);
-
-        mController.updateShouldDisplayProactiveMsg();
-
-        assertFalse(mController.getShouldDisplayProactiveMsg());
-
-        mSharedPreferences.edit().putInt(DataSubscriptionController.KEY_PREV_POPUP_STATUS,
-                DataSubscriptionStatus.PAID);
-
-        mController.setAnchorView(mAnchorView);
-        mController.updateShouldDisplayProactiveMsg();
-        assertTrue(mController.getShouldDisplayProactiveMsg());
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void setAnchorView_viewNull_popUpNotDisplay() {
-        when(mPopupWindow.isShowing()).thenReturn(false);
-        when(mDataSubscription.isDataSubscriptionInactive()).thenReturn(true);
-        mController.setIsUxRestrictionsListenerRegistered(true);
-
-        mController.setAnchorView(null);
-
-        verify(mDataSubscription).removeDataSubscriptionListener();
-        verify(mCarUxRestrictionsUtil).unregister(any());
-        verify(mAnchorView, never()).post(any());
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void onTaskMovedToFront_TopPackageBlocked_popUpNotDisplay() throws RemoteException {
-        HashSet<String> packagesBlocklist = new HashSet<>();
-        packagesBlocklist.add(mRunningTaskInfoMock.topActivity.getPackageName());
-        mController.setPackagesBlocklist(packagesBlocklist);
-
-        mController.getTaskStackListener().onTaskMovedToFront(mRunningTaskInfoMock);
-
-        Assert.assertFalse(mController.getShouldDisplayReactiveMsg());
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void onTaskMovedToFront_TopActivityBlocked_popUpNotDisplay() throws RemoteException {
-        HashSet<String> activitiesBlocklist = new HashSet<>();
-        activitiesBlocklist.add(mRunningTaskInfoMock.topActivity.flattenToString());
-        mController.setActivitiesBlocklist(activitiesBlocklist);
-
-        mController.getTaskStackListener().onTaskMovedToFront(mRunningTaskInfoMock);
-
-        Assert.assertFalse(mController.getShouldDisplayReactiveMsg());
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void onTaskMovedToFront_AppNotRequireInternet_popUpNotDisplay()
-            throws RemoteException, PackageManager.NameNotFoundException {
-        PackageInfo packageInfo = new PackageInfo();
-        when(mUserTracker.getUserId()).thenReturn(1000);
-        when(mContext.getPackageManager()).thenReturn(mPackageManager);
-        when(mPackageManager.getPackageInfoAsUser(
-                anyString(), anyInt(), anyInt())).thenReturn(packageInfo);
-
-        mController.getTaskStackListener().onTaskMovedToFront(mRunningTaskInfoMock);
-
-        Assert.assertFalse(mController.getShouldDisplayReactiveMsg());
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void onTaskMovedToFront_AppRequiresInternetAndNotBlocked_registerCallback()
-            throws RemoteException, PackageManager.NameNotFoundException {
-        PackageInfo packageInfo = new PackageInfo();
-        ApplicationInfo appInfo = new ApplicationInfo();
-        appInfo.uid = 1000;
-        packageInfo.requestedPermissions = new String[] {ACCESS_NETWORK_STATE, INTERNET};
-        when(mUserTracker.getUserId()).thenReturn(1000);
-        when(mContext.getPackageManager()).thenReturn(mPackageManager);
-        when(mPackageManager.getPackageInfoAsUser(
-                anyString(), anyInt(), anyInt())).thenReturn(packageInfo);
-        when(mPackageManager.getApplicationInfoAsUser(
-                anyString(), anyInt(), anyInt())).thenReturn(appInfo);
-
-        mController.getTaskStackListener().onTaskMovedToFront(mRunningTaskInfoMock);
-
-        verify(mConnectivityManager).registerDefaultNetworkCallbackForUid(anyInt(), any(), any());
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void onTaskMovedToFront_invalidNetCap_popUpDisplay()
-            throws RemoteException, PackageManager.NameNotFoundException {
-        PackageInfo packageInfo = new PackageInfo();
-        ApplicationInfo appInfo = new ApplicationInfo();
-        appInfo.uid = 1000;
-        packageInfo.requestedPermissions = new String[] {ACCESS_NETWORK_STATE, INTERNET};
-        mController.setNetworkCallback(mNetworkCallback);
-        when(mUserTracker.getUserId()).thenReturn(1000);
-        when(mContext.getPackageManager()).thenReturn(mPackageManager);
-        when(mPackageManager.getPackageInfoAsUser(
-                anyString(), anyInt(), anyInt())).thenReturn(packageInfo);
-        when(mPackageManager.getApplicationInfoAsUser(
-                anyString(), anyInt(), anyInt())).thenReturn(appInfo);
-
-        mController.getTaskStackListener().onTaskMovedToFront(mRunningTaskInfoMock);
-
-        Assert.assertFalse(mController.getShouldDisplayReactiveMsg());
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void onTaskMovedToFront_callbackRegistered_unregisterAndRegisterCallback()
-            throws RemoteException, PackageManager.NameNotFoundException {
-        PackageInfo packageInfo = new PackageInfo();
-        ApplicationInfo appInfo = new ApplicationInfo();
-        appInfo.uid = 1000;
-        packageInfo.requestedPermissions = new String[] {ACCESS_NETWORK_STATE, INTERNET};
-        mController.setIsCallbackRegistered(true);
-        when(mUserTracker.getUserId()).thenReturn(1000);
-        when(mContext.getPackageManager()).thenReturn(mPackageManager);
-        when(mPackageManager.getPackageInfoAsUser(
-                anyString(), anyInt(), anyInt())).thenReturn(packageInfo);
-        when(mPackageManager.getApplicationInfoAsUser(
-                anyString(), anyInt(), anyInt())).thenReturn(appInfo);
-
-        mController.getTaskStackListener().onTaskMovedToFront(mRunningTaskInfoMock);
-
-        verify(mConnectivityManager).unregisterNetworkCallback(
-                (ConnectivityManager.NetworkCallback) any());
-        verify(mConnectivityManager).registerDefaultNetworkCallbackForUid(anyInt(), any(), any());
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void onRestrictionsChanged_optimizationRequired_proactiveMsgDismissed() {
-        doReturn(mCarUxRestrictionsUtil).when(() -> CarUxRestrictionsUtil.getInstance(any()));
-
-        when(mPopupWindow.isShowing()).thenReturn(true);
-        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
-                "2025-01-15");
-        ArgumentCaptor<CarUxRestrictionsUtil.OnUxRestrictionsChangedListener> captor =
-                ArgumentCaptor.forClass(
-                        CarUxRestrictionsUtil.OnUxRestrictionsChangedListener.class);
-        mController.setAnchorView(mAnchorView);
-        verify(mCarUxRestrictionsUtil).register(captor.capture());
-        CarUxRestrictionsUtil.OnUxRestrictionsChangedListener listener = captor.getValue();
-        CarUxRestrictions carUxRestrictions = mock(CarUxRestrictions.class);
-        when(carUxRestrictions.isRequiresDistractionOptimization()).thenReturn(true);
-        mController.setIsProactiveMsg(true);
-
-        listener.onRestrictionsChanged(carUxRestrictions);
-
-        verify(mPopupWindow).dismiss();
-    }
-
-    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
-    @Test
-    public void onRestrictionsChanged_optimizationRequired_buttonDismissedInReactiveMsg() {
-        doReturn(mCarUxRestrictionsUtil).when(() -> CarUxRestrictionsUtil.getInstance(any()));
-
-        when(mPopupWindow.isShowing()).thenReturn(true);
-        mSharedPreferences.edit().putString(DataSubscriptionController.KEY_PREV_POPUP_DATE,
-                "2025-01-15");
-        ArgumentCaptor<CarUxRestrictionsUtil.OnUxRestrictionsChangedListener> captor =
-                ArgumentCaptor.forClass(
-                        CarUxRestrictionsUtil.OnUxRestrictionsChangedListener.class);
-        mController.setAnchorView(mAnchorView);
-        verify(mCarUxRestrictionsUtil).register(captor.capture());
-        CarUxRestrictionsUtil.OnUxRestrictionsChangedListener listener = captor.getValue();
-        CarUxRestrictions carUxRestrictions = mock(CarUxRestrictions.class);
-        when(carUxRestrictions.isRequiresDistractionOptimization()).thenReturn(true);
-
-        Button button = mock(Button.class);
-        mController.setExplorationButton(button);
-        mController.setIsProactiveMsg(false);
-
-        listener.onRestrictionsChanged(carUxRestrictions);
-
-        verify(button).setVisibility(anyInt());
-    }
-}
diff --git a/tests/src/com/android/systemui/car/qc/DataSubscriptonToolkitViewTest.java b/tests/src/com/android/systemui/car/qc/DataSubscriptonToolkitViewTest.java
new file mode 100644
index 00000000..0653bcc4
--- /dev/null
+++ b/tests/src/com/android/systemui/car/qc/DataSubscriptonToolkitViewTest.java
@@ -0,0 +1,182 @@
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
+package com.android.systemui.car.qc;
+
+import static com.android.car.datasubscription.Flags.FLAG_DATA_SUBSCRIPTION_POP_UP;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.os.UserHandle;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
+import android.testing.AndroidTestingRunner;
+import android.testing.TestableLooper;
+import android.view.View;
+import android.widget.PopupWindow;
+
+import androidx.test.filters.SmallTest;
+
+import com.android.car.datasubscription.DataSubscriptionMessageCreator;
+import com.android.car.datasubscription.DataSubscriptionViewActionListener;
+import com.android.systemui.CarSysuiTestCase;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.settings.UserTracker;
+
+import junit.framework.Assert;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+import java.util.concurrent.Executor;
+
+@CarSystemUiTest
+@RunWith(AndroidTestingRunner.class)
+@TestableLooper.RunWithLooper
+@SmallTest
+public class DataSubscriptonToolkitViewTest extends CarSysuiTestCase {
+    @Mock
+    private PopupWindow mPopupWindow;
+    @Mock
+    private View mAnchorView;
+    @Mock
+    private DataSubscriptionStatsLogHelper mDataSubscriptionStatsLogHelper;
+    @Mock
+    private UserTracker mUserTracker;
+    @Mock
+    private DataSubscriptionViewActionListener mDataSubscriptionViewActionListener;
+    @Mock
+    private DataSubscriptionMessageCreator mDataSubscriptionMessageCreator;
+
+    @Mock
+    private Executor mExecutor;
+
+    private DataSubscriptionToolkitView mDataSubscriptionToolkitView;
+    private String mUxrPrompt = "Test UXR Prompt";
+
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.initMocks(this);
+        when(mUserTracker.getUserHandle()).thenReturn(UserHandle.of(1000));
+        mDataSubscriptionToolkitView = new DataSubscriptionToolkitView(mContext, mUserTracker,
+                mDataSubscriptionStatsLogHelper, mDataSubscriptionMessageCreator, mExecutor);
+        mDataSubscriptionToolkitView.setDataSubscriptionViewActionListener(
+                mDataSubscriptionViewActionListener);
+        mDataSubscriptionToolkitView.setPopupWindow(mPopupWindow);
+    }
+
+    @After()
+    public void tearDown() {
+        mDataSubscriptionToolkitView.getPopUpPrompt().setText("");
+    }
+
+    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
+    @Test
+    public void setAnchorView_viewNull_notRegisterListeners() {
+        mDataSubscriptionToolkitView.setAnchorView(null);
+
+        verify(mDataSubscriptionViewActionListener).unregisterListeners();
+    }
+
+    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
+    @Test
+    public void setAnchorView_viewNotNull_registerListeners() {
+        mDataSubscriptionToolkitView.setAnchorView(mAnchorView);
+
+        verify(mDataSubscriptionViewActionListener).registerListeners();
+    }
+
+    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
+    @Test
+    public void onDataSubscriptionStatusChanged_emptyProactiveMessage_popUpNotDisplay() {
+        when(mPopupWindow.isShowing()).thenReturn(true);
+
+        mDataSubscriptionToolkitView.onDataSubscriptionStatusChanged(false, "",
+                mUxrPrompt);
+
+        assertThat(mDataSubscriptionToolkitView.getPopUpPrompt().getText().isEmpty())
+                .isTrue();
+    }
+
+    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
+    @Test
+    public void onDataSubscriptionStatusChanged_validProactiveMessage_popUpDisplay() {
+        when(mPopupWindow.isShowing()).thenReturn(true);
+
+        mDataSubscriptionToolkitView.onDataSubscriptionStatusChanged(
+                false, "Valid Message", mUxrPrompt);
+
+        Assert.assertNotNull(mDataSubscriptionToolkitView.getPopUpPrompt().getText());
+    }
+
+    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
+    @Test
+    public void onAppForeground_emptyReactiveMessage_popUpNotDisplay() {
+        when(mPopupWindow.isShowing()).thenReturn(true);
+
+        mDataSubscriptionToolkitView.onAppForegrounded(false, "",
+                mUxrPrompt);
+
+        assertThat(mDataSubscriptionToolkitView.getPopUpPrompt().getText().isEmpty())
+                .isTrue();
+    }
+
+    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
+    @Test
+    public void onAppForeground_validReactiveMessage_popUpDisplay() {
+        when(mPopupWindow.isShowing()).thenReturn(true);
+
+        mDataSubscriptionToolkitView.onAppForegrounded(false, "Valid Message",
+                mUxrPrompt);
+
+        Assert.assertNotNull(mDataSubscriptionToolkitView.getPopUpPrompt().getText());
+    }
+
+    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
+    @Test
+    public void onUxrChanged_UxrRequired_proactivePopUpDimissed() {
+        mDataSubscriptionToolkitView.setIsProactiveMessage(true);
+        when(mPopupWindow.isShowing()).thenReturn(true);
+
+        mDataSubscriptionToolkitView.onUxrChanged(true, mUxrPrompt);
+
+        verify(mPopupWindow).dismiss();
+    }
+
+    @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
+    @Test
+    public void onUxrChanged_UxrRequired_reactivePopUpButtonGone() {
+        mDataSubscriptionToolkitView.setIsProactiveMessage(false);
+        when(mPopupWindow.isShowing()).thenReturn(true);
+
+        mDataSubscriptionToolkitView.onUxrChanged(true, mUxrPrompt);
+
+        assertThat(mDataSubscriptionToolkitView.getExplorationButton().getVisibility())
+                .isEqualTo(View.GONE);
+    }
+}
diff --git a/tests/src/com/android/systemui/car/statusicon/StatusIconPanelViewControllerTest.java b/tests/src/com/android/systemui/car/statusicon/StatusIconPanelViewControllerTest.java
index d77de653..0c747f16 100644
--- a/tests/src/com/android/systemui/car/statusicon/StatusIconPanelViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/statusicon/StatusIconPanelViewControllerTest.java
@@ -54,7 +54,6 @@ import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
@@ -143,20 +142,6 @@ public class StatusIconPanelViewControllerTest extends CarSysuiTestCase {
         assertThat(mViewController.getPanel().isShowing()).isFalse();
     }
 
-    @Test
-    public void onPanelAnchorViewClicked_sendsIntentToDismissSystemDialogsWithIdentifier() {
-        ArgumentCaptor<Intent> argumentCaptor = ArgumentCaptor.forClass(Intent.class);
-
-        clickAnchorView();
-        waitForIdleSync();
-
-        verify(mContext).sendBroadcastAsUser(argumentCaptor.capture(), eq(mUserHandle));
-        assertThat(argumentCaptor.getValue().getAction()).isEqualTo(
-                Intent.ACTION_CLOSE_SYSTEM_DIALOGS);
-        assertThat(argumentCaptor.getValue().getIdentifier()).isEqualTo(
-                mViewController.getIdentifier());
-    }
-
     @Test
     public void onDismissSystemDialogReceived_fromSelf_panelOpen_doesNotDismissPanel() {
         Intent intent = new Intent();
diff --git a/tests/src/com/android/systemui/car/statusicon/ui/SignalStatusIconControllerTest.java b/tests/src/com/android/systemui/car/statusicon/ui/SignalStatusIconControllerTest.java
index 1086d92f..9162ea2e 100644
--- a/tests/src/com/android/systemui/car/statusicon/ui/SignalStatusIconControllerTest.java
+++ b/tests/src/com/android/systemui/car/statusicon/ui/SignalStatusIconControllerTest.java
@@ -30,7 +30,7 @@ import androidx.test.filters.SmallTest;
 import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
 import com.android.systemui.car.CarSystemUiTest;
-import com.android.systemui.car.qc.DataSubscriptionController;
+import com.android.systemui.car.qc.DataSubscriptionToolkitView;
 import com.android.systemui.car.statusicon.StatusIconView;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
@@ -58,7 +58,7 @@ public class SignalStatusIconControllerTest extends CarSysuiTestCase {
     @Mock
     HotspotController mHotspotController;
     @Mock
-    DataSubscriptionController mDataSubscriptionController;
+    DataSubscriptionToolkitView mDataSubscriptionToolkitView;
     @Mock
     CarSystemBarElementStatusBarDisableController mDisableController;
     @Mock
@@ -74,7 +74,7 @@ public class SignalStatusIconControllerTest extends CarSysuiTestCase {
         mView = new StatusIconView(mContext);
         mSignalStatusIconController = new SignalStatusIconController(mView, mDisableController,
                 mStateController, mContext, mResources, mNetworkController, mHotspotController,
-                mDataSubscriptionController);
+                mDataSubscriptionToolkitView);
     }
 
     @Test
diff --git a/tests/src/com/android/systemui/car/systembar/CameraPrivacyChipViewControllerTest.java b/tests/src/com/android/systemui/car/systembar/CameraPrivacyChipViewControllerTest.java
index 97848cdf..63d17fb4 100644
--- a/tests/src/com/android/systemui/car/systembar/CameraPrivacyChipViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CameraPrivacyChipViewControllerTest.java
@@ -17,14 +17,12 @@
 package com.android.systemui.car.systembar;
 
 import static android.hardware.SensorPrivacyManager.Sensors.CAMERA;
-import static android.hardware.SensorPrivacyManager.Sources.QS_TILE;
 
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.eq;
-import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.reset;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
@@ -36,15 +34,17 @@ import android.hardware.SensorPrivacyManager;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
 import android.view.LayoutInflater;
-import android.view.View;
-import android.widget.FrameLayout;
 
 import androidx.test.filters.SmallTest;
 
 import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
+import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.privacy.CameraPrivacyChip;
+import com.android.systemui.car.statusicon.StatusIconPanelViewController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
 import com.android.systemui.privacy.PrivacyItem;
 import com.android.systemui.privacy.PrivacyItemController;
 import com.android.systemui.privacy.PrivacyType;
@@ -61,6 +61,8 @@ import org.mockito.MockitoAnnotations;
 import java.util.Collections;
 import java.util.concurrent.Executor;
 
+import javax.inject.Provider;
+
 @CarSystemUiTest
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
@@ -69,7 +71,6 @@ public class CameraPrivacyChipViewControllerTest extends CarSysuiTestCase {
     private static final int TEST_USER_ID = 1001;
 
     private CameraPrivacyChipViewController mCameraPrivacyChipViewController;
-    private FrameLayout mFrameLayout;
     private CameraPrivacyChip mCameraPrivacyChip;
 
     @Captor
@@ -80,6 +81,10 @@ public class CameraPrivacyChipViewControllerTest extends CarSysuiTestCase {
     private ArgumentCaptor<SensorPrivacyManager.OnSensorPrivacyChangedListener>
             mOnSensorPrivacyChangedListenerArgumentCaptor;
 
+    @Mock
+    private CarSystemBarElementStatusBarDisableController mBarElementDisableController;
+    @Mock
+    private CarSystemBarElementStateController mBarElementStateController;
     @Mock
     private PrivacyItemController mPrivacyItemController;
     @Mock
@@ -91,41 +96,43 @@ public class CameraPrivacyChipViewControllerTest extends CarSysuiTestCase {
     @Mock
     private UserTracker mUserTracker;
     @Mock
-    private Car mCar;
+    private CarDeviceProvisionedController mCarDeviceProvisionedController;
     @Mock
-    private Runnable mQsTileNotifyUpdateRunnable;
+    private Provider<StatusIconPanelViewController.Builder> mPanelControllerBuilderProvider;
+    @Mock
+    private Car mCar;
 
     @Before
     public void setUp() {
         MockitoAnnotations.initMocks(/* testClass= */ this);
 
-        mFrameLayout = new FrameLayout(mContext);
         mCameraPrivacyChip = spy((CameraPrivacyChip) LayoutInflater.from(mContext)
                 .inflate(R.layout.camera_privacy_chip, /* root= */ null));
-        mFrameLayout.addView(mCameraPrivacyChip);
         mContext = spy(mContext);
 
         when(mContext.getMainExecutor()).thenReturn(mExecutor);
         when(mCar.isConnected()).thenReturn(true);
         when(mUserTracker.getUserId()).thenReturn(TEST_USER_ID);
 
-        mCameraPrivacyChipViewController = new CameraPrivacyChipViewController(mContext,
-                mPrivacyItemController, mSensorPrivacyManager, mUserTracker);
+        mCameraPrivacyChipViewController = new CameraPrivacyChipViewController(mCameraPrivacyChip,
+                mBarElementDisableController, mBarElementStateController, mContext,
+                mPrivacyItemController, mSensorPrivacyManager, mUserTracker,
+                mCarDeviceProvisionedController, mPanelControllerBuilderProvider);
     }
 
     @Test
-    public void addPrivacyChipView_privacyChipViewPresent_addCallbackCalled() {
-        mCameraPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+    public void onViewAttached_addCallbackCalled() {
+        mCameraPrivacyChipViewController.onViewAttached();
 
         verify(mPrivacyItemController).addCallback(any());
         verify(mUserTracker).addCallback(any(), any());
     }
 
     @Test
-    public void addPrivacyChipView_privacyChipViewPresent_sensorStatusSet() {
+    public void onViewAttached_sensorStatusSet() {
         when(mSensorPrivacyManager.isSensorPrivacyEnabled(anyInt(), eq(CAMERA)))
                 .thenReturn(false);
-        mCameraPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mCameraPrivacyChipViewController.onViewAttached();
         verify(mExecutor).execute(mRunnableArgumentCaptor.capture());
 
         mRunnableArgumentCaptor.getValue().run();
@@ -133,19 +140,11 @@ public class CameraPrivacyChipViewControllerTest extends CarSysuiTestCase {
         verify(mCameraPrivacyChip).setSensorEnabled(eq(true));
     }
 
-    @Test
-    public void addPrivacyChipView_privacyChipViewNotPresent_addCallbackNotCalled() {
-        mCameraPrivacyChipViewController.addPrivacyChipView(new View(getContext()));
-
-        verify(mPrivacyItemController, never()).addCallback(any());
-        verify(mUserTracker, never()).addCallback(any(), any());
-    }
-
     @Test
     public void onUserChanged_cameraStatusSet() {
         when(mSensorPrivacyManager.isSensorPrivacyEnabled(anyInt(), eq(CAMERA)))
                 .thenReturn(false);
-        mCameraPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mCameraPrivacyChipViewController.onViewAttached();
         ArgumentCaptor<UserTracker.Callback> captor = ArgumentCaptor.forClass(
                 UserTracker.Callback.class);
         verify(mUserTracker).addCallback(captor.capture(), any());
@@ -157,7 +156,7 @@ public class CameraPrivacyChipViewControllerTest extends CarSysuiTestCase {
     @Test
     public void onPrivacyItemsChanged_cameraIsPartOfPrivacyItems_animateInCalled() {
         when(mPrivacyItem.getPrivacyType()).thenReturn(PrivacyType.TYPE_CAMERA);
-        mCameraPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mCameraPrivacyChipViewController.onViewAttached();
         verify(mPrivacyItemController).addCallback(mPicCallbackArgumentCaptor.capture());
         mPicCallbackArgumentCaptor.getValue().onFlagAllChanged(true);
         mPicCallbackArgumentCaptor.getValue().onFlagMicCameraChanged(true);
@@ -173,7 +172,7 @@ public class CameraPrivacyChipViewControllerTest extends CarSysuiTestCase {
     @Test
     public void onPrivacyItemsChanged_cameraIsPartOfPrivacyItemsTwice_animateInCalledOnce() {
         when(mPrivacyItem.getPrivacyType()).thenReturn(PrivacyType.TYPE_CAMERA);
-        mCameraPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mCameraPrivacyChipViewController.onViewAttached();
         verify(mPrivacyItemController).addCallback(mPicCallbackArgumentCaptor.capture());
         mPicCallbackArgumentCaptor.getValue().onFlagAllChanged(true);
         mPicCallbackArgumentCaptor.getValue().onFlagMicCameraChanged(true);
@@ -191,7 +190,7 @@ public class CameraPrivacyChipViewControllerTest extends CarSysuiTestCase {
     @Test
     public void onPrivacyItemsChanged_cameraIsNotPartOfPrivacyItems_animateOutCalled() {
         when(mPrivacyItem.getPrivacyType()).thenReturn(PrivacyType.TYPE_CAMERA);
-        mCameraPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mCameraPrivacyChipViewController.onViewAttached();
         verify(mPrivacyItemController).addCallback(mPicCallbackArgumentCaptor.capture());
         mPicCallbackArgumentCaptor.getValue().onFlagAllChanged(true);
         mPicCallbackArgumentCaptor.getValue().onFlagMicCameraChanged(true);
@@ -209,7 +208,7 @@ public class CameraPrivacyChipViewControllerTest extends CarSysuiTestCase {
     @Test
     public void onPrivacyItemsChanged_cameraIsNotPartOfPrivacyItemsTwice_animateOutCalledOnce() {
         when(mPrivacyItem.getPrivacyType()).thenReturn(PrivacyType.TYPE_CAMERA);
-        mCameraPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mCameraPrivacyChipViewController.onViewAttached();
         verify(mPrivacyItemController).addCallback(mPicCallbackArgumentCaptor.capture());
         mPicCallbackArgumentCaptor.getValue().onFlagAllChanged(true);
         mPicCallbackArgumentCaptor.getValue().onFlagMicCameraChanged(true);
@@ -225,25 +224,9 @@ public class CameraPrivacyChipViewControllerTest extends CarSysuiTestCase {
         verify(mCameraPrivacyChip).animateOut();
     }
 
-    @Test
-    public void onPrivacyItemsChanged_qsTileNotifyUpdateRunnableExecuted() {
-        when(mPrivacyItem.getPrivacyType()).thenReturn(PrivacyType.TYPE_CAMERA);
-        mCameraPrivacyChipViewController.setNotifyUpdateRunnable(mQsTileNotifyUpdateRunnable);
-        mCameraPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
-        verify(mPrivacyItemController).addCallback(mPicCallbackArgumentCaptor.capture());
-        mPicCallbackArgumentCaptor.getValue().onFlagAllChanged(true);
-        mPicCallbackArgumentCaptor.getValue().onFlagMicCameraChanged(true);
-
-        mPicCallbackArgumentCaptor.getValue().onPrivacyItemsChanged(Collections.emptyList());
-        verify(mExecutor).execute(mRunnableArgumentCaptor.capture());
-        mRunnableArgumentCaptor.getAllValues().forEach(Runnable::run);
-
-        verify(mQsTileNotifyUpdateRunnable).run();
-    }
-
     @Test
     public void onSensorPrivacyChanged_argTrue_setSensorEnabledWithFalseCalled() {
-        mCameraPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mCameraPrivacyChipViewController.onViewAttached();
         verify(mSensorPrivacyManager).addSensorPrivacyListener(eq(CAMERA),
                 mOnSensorPrivacyChangedListenerArgumentCaptor.capture());
         reset(mCameraPrivacyChip);
@@ -259,7 +242,7 @@ public class CameraPrivacyChipViewControllerTest extends CarSysuiTestCase {
 
     @Test
     public void onSensorPrivacyChanged_argFalse_setSensorEnabledWithTrueCalled() {
-        mCameraPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mCameraPrivacyChipViewController.onViewAttached();
         verify(mSensorPrivacyManager).addSensorPrivacyListener(eq(CAMERA),
                 mOnSensorPrivacyChangedListenerArgumentCaptor.capture());
         reset(mCameraPrivacyChip);
@@ -273,23 +256,6 @@ public class CameraPrivacyChipViewControllerTest extends CarSysuiTestCase {
         verify(mCameraPrivacyChip).setSensorEnabled(eq(true));
     }
 
-    @Test
-    public void onSensorPrivacyChanged_qsTileNotifyUpdateRunnableExecuted() {
-        mCameraPrivacyChipViewController.setNotifyUpdateRunnable(mQsTileNotifyUpdateRunnable);
-        mCameraPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
-        verify(mSensorPrivacyManager).addSensorPrivacyListener(eq(CAMERA),
-                mOnSensorPrivacyChangedListenerArgumentCaptor.capture());
-        reset(mCameraPrivacyChip);
-        reset(mExecutor);
-        mOnSensorPrivacyChangedListenerArgumentCaptor.getValue()
-                .onSensorPrivacyChanged(CAMERA, /* enabled= */ true);
-        verify(mExecutor).execute(mRunnableArgumentCaptor.capture());
-
-        mRunnableArgumentCaptor.getAllValues().forEach(Runnable::run);
-
-        verify(mQsTileNotifyUpdateRunnable).run();
-    }
-
     @Test
     public void isSensorEnabled_sensorPrivacyEnabled_returnFalse() {
         when(mSensorPrivacyManager.isSensorPrivacyEnabled(anyInt(), eq(CAMERA)))
@@ -305,26 +271,4 @@ public class CameraPrivacyChipViewControllerTest extends CarSysuiTestCase {
 
         assertThat(mCameraPrivacyChipViewController.isSensorEnabled()).isTrue();
     }
-
-    @Test
-    public void toggleSensor_cameraTurnedOn_sensorPrivacyEnabled() {
-        when(mSensorPrivacyManager.isSensorPrivacyEnabled(anyInt(), eq(CAMERA)))
-                .thenReturn(false);
-
-        mCameraPrivacyChipViewController.toggleSensor();
-
-        verify(mSensorPrivacyManager).setSensorPrivacy(eq(QS_TILE), eq(CAMERA), eq(true),
-                eq(TEST_USER_ID));
-    }
-
-    @Test
-    public void toggleSensor_cameraTurnedOff_sensorPrivacyDisabled() {
-        when(mSensorPrivacyManager.isSensorPrivacyEnabled(anyInt(), eq(CAMERA)))
-                .thenReturn(true);
-
-        mCameraPrivacyChipViewController.toggleSensor();
-
-        verify(mSensorPrivacyManager).setSensorPrivacy(eq(QS_TILE), eq(CAMERA), eq(false),
-                eq(TEST_USER_ID));
-    }
 }
diff --git a/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java b/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java
index df28c7de..21e9724e 100644
--- a/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java
@@ -215,8 +215,7 @@ public class CarSystemBarControllerTest extends CarSysuiTestCase {
                         return spy(new CarSystemBarViewControllerImpl(mSpiedContext, mUserTracker,
                                 carSystemBarElementInitializer, mSystemBarConfigs,
                                 mButtonRoleHolderController,
-                                () -> mCameraPrivacyChipViewController,
-                                () -> mMicPrivacyChipViewController, mOverlayVisibilityMediator,
+                                mOverlayVisibilityMediator,
                                 side, view));
                     }
                 };
diff --git a/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java b/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java
index 115b5694..01f9a567 100644
--- a/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java
@@ -39,7 +39,6 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.app.ActivityManager;
-import android.content.res.Configuration;
 import android.graphics.Rect;
 import android.os.Handler;
 import android.os.RemoteException;
@@ -499,20 +498,6 @@ public class CarSystemBarTest extends CarSysuiTestCase {
         verify(mCarSystemBarController).setSystemBarStates(0, 0);
     }
 
-    @Test
-    public void onConfigChanged_toggleNightMode() {
-        // get the current mode and then change to the opposite
-        boolean isNightMode = mContext.getResources().getConfiguration().isNightModeActive();
-        Configuration config = new Configuration();
-        config.uiMode =
-                isNightMode ? Configuration.UI_MODE_NIGHT_NO : Configuration.UI_MODE_NIGHT_YES;
-
-        mCarSystemBarController.init();
-        mCarSystemBarController.onConfigChanged(config);
-
-        assertThat(mCarSystemBarController.getIsUiModeNight()).isNotEqualTo(isNightMode);
-    }
-
     @Test
     public void restartSystemBars_newSystemBarConfig_recreatesSystemBars() {
         mTestableResources.addOverride(R.integer.config_showDisplayCompatToolbarOnSystemBar, 0);
diff --git a/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java b/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java
index 8226db5b..ee0f54b6 100644
--- a/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java
@@ -140,8 +140,6 @@ public class CarSystemBarViewTest extends CarSysuiTestCase {
                 mCarSystemBarElementInitializer,
                 systemBarConfigs,
                 mButtonRoleHolderController,
-                () -> mCameraPrivacyChipViewController,
-                () -> mMicPrivacyChipViewController,
                 mOverlayVisibilityMediator,
                 0,
                 view);
diff --git a/tests/src/com/android/systemui/car/systembar/DataSubscriptionUnseenIconControllerTest.java b/tests/src/com/android/systemui/car/systembar/DataSubscriptionUnseenIconControllerTest.java
index 830c4d0a..259decb1 100644
--- a/tests/src/com/android/systemui/car/systembar/DataSubscriptionUnseenIconControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/DataSubscriptionUnseenIconControllerTest.java
@@ -17,11 +17,17 @@
 package com.android.systemui.car.systembar;
 
 import static com.android.car.datasubscription.Flags.FLAG_DATA_SUBSCRIPTION_POP_UP;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
 
 import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
+import android.content.Context;
+import android.content.res.Resources;
+import android.content.res.XmlResourceParser;
 import android.platform.test.annotations.RequiresFlagsEnabled;
 import android.platform.test.flag.junit.CheckFlagsRule;
 import android.platform.test.flag.junit.DeviceFlagsValueProvider;
@@ -31,18 +37,26 @@ import android.testing.TestableLooper;
 import androidx.test.filters.SmallTest;
 
 import com.android.car.datasubscription.DataSubscription;
+import com.android.car.datasubscription.DataSubscriptionConfig;
+import com.android.car.datasubscription.DataSubscriptionConfig.DataSubscriptionStatusType;
+import com.android.car.datasubscription.DataSubscriptionConfigParser;
 import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
 import com.android.systemui.car.systembar.element.layout.CarSystemBarImageView;
 
+import org.junit.After;
 import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
+import org.mockito.MockitoSession;
+import org.mockito.quality.Strictness;
+
+import java.util.HashMap;
+import java.util.Map;
 
 @CarSystemUiTest
 @RunWith(AndroidTestingRunner.class)
@@ -58,17 +72,66 @@ public class DataSubscriptionUnseenIconControllerTest extends CarSysuiTestCase {
     private CarSystemBarElementStateController mStateController;
     @Mock
     private DataSubscription mDataSubscription;
+    @Mock
+    private Resources mResources;
+    @Mock
+    private Context mContext;
+    @Mock
+    private XmlResourceParser mParser;
+    private MockitoSession mMockingSession;
+
     @Rule
     public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
+    private Map<Integer, DataSubscriptionConfig> mConfigData = new HashMap<>();
 
     @Before
     public void setUp() {
-        MockitoAnnotations.initMocks(this);
+        mMockingSession = mockitoSession()
+                .initMocks(this)
+                .mockStatic(DataSubscriptionConfigParser.class)
+                .strictness(Strictness.WARN)
+                .startMocking();
+        DataSubscriptionConfig config1 = new DataSubscriptionConfig(
+                DataSubscriptionStatusType.INACTIVE,
+                true,
+                "Proactive A", "Reactive A");
+        DataSubscriptionConfig config2 = new DataSubscriptionConfig(
+                DataSubscriptionStatusType.TRIAL,
+                true,
+                "Proactive B", "Reactive B");
+        DataSubscriptionConfig config3 = new DataSubscriptionConfig(
+                DataSubscriptionStatusType.PAID,
+                true,
+                "", "");
+        DataSubscriptionConfig config4 = new DataSubscriptionConfig(
+                DataSubscriptionStatusType.EXPIRING,
+                true,
+                "", "");
+
+        mConfigData.put(1, config1);
+        mConfigData.put(2, config2);
+        mConfigData.put(3, config3);
+        mConfigData.put(4, config4);
+
+
+        when(mView.getContext()).thenReturn(mContext);
+        when(mContext.getResources()).thenReturn(mResources);
+        when(mResources.getXml(anyInt())).thenReturn(mParser);
+
+        doReturn(mConfigData).when(() -> DataSubscriptionConfigParser.loadConfig(any()));
+
         mController = new DataSubscriptionUnseenIconController(mView,
                 mDisableController, mStateController);
         mController.setSubscription(mDataSubscription);
     }
 
+    @After
+    public void tearDown() {
+        if (mMockingSession != null) {
+            mMockingSession.finishMocking();
+        }
+    }
+
     @RequiresFlagsEnabled(FLAG_DATA_SUBSCRIPTION_POP_UP)
     @Test
     public void onViewAttached_registerListener() {
diff --git a/tests/src/com/android/systemui/car/systembar/MicPrivacyChipViewControllerTest.java b/tests/src/com/android/systemui/car/systembar/MicPrivacyChipViewControllerTest.java
index ef1707cb..92447b7a 100644
--- a/tests/src/com/android/systemui/car/systembar/MicPrivacyChipViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/MicPrivacyChipViewControllerTest.java
@@ -17,14 +17,12 @@
 package com.android.systemui.car.systembar;
 
 import static android.hardware.SensorPrivacyManager.Sensors.MICROPHONE;
-import static android.hardware.SensorPrivacyManager.Sources.QS_TILE;
 
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.eq;
-import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.reset;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
@@ -36,15 +34,17 @@ import android.hardware.SensorPrivacyManager;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
 import android.view.LayoutInflater;
-import android.view.View;
-import android.widget.FrameLayout;
 
 import androidx.test.filters.SmallTest;
 
 import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.R;
+import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.privacy.MicPrivacyChip;
+import com.android.systemui.car.statusicon.StatusIconPanelViewController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
 import com.android.systemui.privacy.PrivacyItem;
 import com.android.systemui.privacy.PrivacyItemController;
 import com.android.systemui.privacy.PrivacyType;
@@ -61,6 +61,8 @@ import org.mockito.MockitoAnnotations;
 import java.util.Collections;
 import java.util.concurrent.Executor;
 
+import javax.inject.Provider;
+
 @CarSystemUiTest
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
@@ -69,7 +71,6 @@ public class MicPrivacyChipViewControllerTest extends CarSysuiTestCase {
     private static final int TEST_USER_ID = 1001;
 
     private MicPrivacyChipViewController mMicPrivacyChipViewController;
-    private FrameLayout mFrameLayout;
     private MicPrivacyChip mMicPrivacyChip;
 
     @Captor
@@ -80,6 +81,10 @@ public class MicPrivacyChipViewControllerTest extends CarSysuiTestCase {
     private ArgumentCaptor<SensorPrivacyManager.OnSensorPrivacyChangedListener>
             mOnSensorPrivacyChangedListenerArgumentCaptor;
 
+    @Mock
+    private CarSystemBarElementStatusBarDisableController mBarElementDisableController;
+    @Mock
+    private CarSystemBarElementStateController mBarElementStateController;
     @Mock
     private PrivacyItemController mPrivacyItemController;
     @Mock
@@ -91,41 +96,43 @@ public class MicPrivacyChipViewControllerTest extends CarSysuiTestCase {
     @Mock
     private UserTracker mUserTracker;
     @Mock
-    private Car mCar;
+    private CarDeviceProvisionedController mCarDeviceProvisionedController;
     @Mock
-    private Runnable mQsTileNotifyUpdateRunnable;
+    private Provider<StatusIconPanelViewController.Builder> mPanelControllerBuilderProvider;
+    @Mock
+    private Car mCar;
 
     @Before
     public void setUp() {
         MockitoAnnotations.initMocks(/* testClass= */ this);
 
-        mFrameLayout = new FrameLayout(mContext);
         mMicPrivacyChip = spy((MicPrivacyChip) LayoutInflater.from(mContext)
                 .inflate(R.layout.mic_privacy_chip, /* root= */ null));
-        mFrameLayout.addView(mMicPrivacyChip);
         mContext = spy(mContext);
 
         when(mContext.getMainExecutor()).thenReturn(mExecutor);
         when(mCar.isConnected()).thenReturn(true);
         when(mUserTracker.getUserId()).thenReturn(TEST_USER_ID);
 
-        mMicPrivacyChipViewController = new MicPrivacyChipViewController(mContext,
-                mPrivacyItemController, mSensorPrivacyManager, mUserTracker);
+        mMicPrivacyChipViewController = new MicPrivacyChipViewController(mMicPrivacyChip,
+                mBarElementDisableController, mBarElementStateController, mContext,
+                mPrivacyItemController, mSensorPrivacyManager, mUserTracker,
+                mCarDeviceProvisionedController, mPanelControllerBuilderProvider);
     }
 
     @Test
-    public void addPrivacyChipView_privacyChipViewPresent_addCallbackCalled() {
-        mMicPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+    public void onViewAttached_addCallbackCalled() {
+        mMicPrivacyChipViewController.onViewAttached();
 
         verify(mPrivacyItemController).addCallback(any());
         verify(mUserTracker).addCallback(any(), any());
     }
 
     @Test
-    public void addPrivacyChipView_privacyChipViewPresent_micStatusSet() {
+    public void onViewAttached_micStatusSet() {
         when(mSensorPrivacyManager.isSensorPrivacyEnabled(anyInt(), eq(MICROPHONE)))
                 .thenReturn(false);
-        mMicPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mMicPrivacyChipViewController.onViewAttached();
         verify(mExecutor).execute(mRunnableArgumentCaptor.capture());
 
         mRunnableArgumentCaptor.getValue().run();
@@ -133,19 +140,11 @@ public class MicPrivacyChipViewControllerTest extends CarSysuiTestCase {
         verify(mMicPrivacyChip).setSensorEnabled(eq(true));
     }
 
-    @Test
-    public void addPrivacyChipView_privacyChipViewNotPresent_addCallbackNotCalled() {
-        mMicPrivacyChipViewController.addPrivacyChipView(new View(getContext()));
-
-        verify(mPrivacyItemController, never()).addCallback(any());
-        verify(mUserTracker, never()).addCallback(any(), any());
-    }
-
     @Test
     public void onUserChanged_micStatusSet() {
         when(mSensorPrivacyManager.isSensorPrivacyEnabled(anyInt(), eq(MICROPHONE)))
                 .thenReturn(false);
-        mMicPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mMicPrivacyChipViewController.onViewAttached();
         ArgumentCaptor<UserTracker.Callback> captor = ArgumentCaptor.forClass(
                 UserTracker.Callback.class);
         verify(mUserTracker).addCallback(captor.capture(), any());
@@ -157,7 +156,7 @@ public class MicPrivacyChipViewControllerTest extends CarSysuiTestCase {
     @Test
     public void onPrivacyItemsChanged_micIsPartOfPrivacyItems_animateInCalled() {
         when(mPrivacyItem.getPrivacyType()).thenReturn(PrivacyType.TYPE_MICROPHONE);
-        mMicPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mMicPrivacyChipViewController.onViewAttached();
         verify(mPrivacyItemController).addCallback(mPicCallbackArgumentCaptor.capture());
         mPicCallbackArgumentCaptor.getValue().onFlagAllChanged(true);
         mPicCallbackArgumentCaptor.getValue().onFlagMicCameraChanged(true);
@@ -173,7 +172,7 @@ public class MicPrivacyChipViewControllerTest extends CarSysuiTestCase {
     @Test
     public void onPrivacyItemsChanged_micIsPartOfPrivacyItemsTwice_animateInCalledOnce() {
         when(mPrivacyItem.getPrivacyType()).thenReturn(PrivacyType.TYPE_MICROPHONE);
-        mMicPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mMicPrivacyChipViewController.onViewAttached();
         verify(mPrivacyItemController).addCallback(mPicCallbackArgumentCaptor.capture());
         mPicCallbackArgumentCaptor.getValue().onFlagAllChanged(true);
         mPicCallbackArgumentCaptor.getValue().onFlagMicCameraChanged(true);
@@ -191,7 +190,7 @@ public class MicPrivacyChipViewControllerTest extends CarSysuiTestCase {
     @Test
     public void onPrivacyItemsChanged_micIsNotPartOfPrivacyItems_animateOutCalled() {
         when(mPrivacyItem.getPrivacyType()).thenReturn(PrivacyType.TYPE_MICROPHONE);
-        mMicPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mMicPrivacyChipViewController.onViewAttached();
         verify(mPrivacyItemController).addCallback(mPicCallbackArgumentCaptor.capture());
         mPicCallbackArgumentCaptor.getValue().onFlagAllChanged(true);
         mPicCallbackArgumentCaptor.getValue().onFlagMicCameraChanged(true);
@@ -209,7 +208,7 @@ public class MicPrivacyChipViewControllerTest extends CarSysuiTestCase {
     @Test
     public void onPrivacyItemsChanged_micIsNotPartOfPrivacyItemsTwice_animateOutCalledOnce() {
         when(mPrivacyItem.getPrivacyType()).thenReturn(PrivacyType.TYPE_MICROPHONE);
-        mMicPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mMicPrivacyChipViewController.onViewAttached();
         verify(mPrivacyItemController).addCallback(mPicCallbackArgumentCaptor.capture());
         mPicCallbackArgumentCaptor.getValue().onFlagAllChanged(true);
         mPicCallbackArgumentCaptor.getValue().onFlagMicCameraChanged(true);
@@ -225,25 +224,9 @@ public class MicPrivacyChipViewControllerTest extends CarSysuiTestCase {
         verify(mMicPrivacyChip).animateOut();
     }
 
-    @Test
-    public void onPrivacyItemsChanged_qsTileNotifyUpdateRunnableExecuted() {
-        when(mPrivacyItem.getPrivacyType()).thenReturn(PrivacyType.TYPE_MICROPHONE);
-        mMicPrivacyChipViewController.setNotifyUpdateRunnable(mQsTileNotifyUpdateRunnable);
-        mMicPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
-        verify(mPrivacyItemController).addCallback(mPicCallbackArgumentCaptor.capture());
-        mPicCallbackArgumentCaptor.getValue().onFlagAllChanged(true);
-        mPicCallbackArgumentCaptor.getValue().onFlagMicCameraChanged(true);
-
-        mPicCallbackArgumentCaptor.getValue().onPrivacyItemsChanged(Collections.emptyList());
-        verify(mExecutor).execute(mRunnableArgumentCaptor.capture());
-        mRunnableArgumentCaptor.getAllValues().forEach(Runnable::run);
-
-        verify(mQsTileNotifyUpdateRunnable).run();
-    }
-
     @Test
     public void onSensorPrivacyChanged_argTrue_setSensorEnabledWithFalseCalled() {
-        mMicPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mMicPrivacyChipViewController.onViewAttached();
         verify(mSensorPrivacyManager).addSensorPrivacyListener(eq(MICROPHONE),
                 mOnSensorPrivacyChangedListenerArgumentCaptor.capture());
         reset(mMicPrivacyChip);
@@ -259,7 +242,7 @@ public class MicPrivacyChipViewControllerTest extends CarSysuiTestCase {
 
     @Test
     public void onSensorPrivacyChanged_argFalse_setSensorEnabledWithTrueCalled() {
-        mMicPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
+        mMicPrivacyChipViewController.onViewAttached();
         verify(mSensorPrivacyManager).addSensorPrivacyListener(eq(MICROPHONE),
                 mOnSensorPrivacyChangedListenerArgumentCaptor.capture());
         reset(mMicPrivacyChip);
@@ -273,23 +256,6 @@ public class MicPrivacyChipViewControllerTest extends CarSysuiTestCase {
         verify(mMicPrivacyChip).setSensorEnabled(eq(true));
     }
 
-    @Test
-    public void onSensorPrivacyChanged_qsTileNotifyUpdateRunnableExecuted() {
-        mMicPrivacyChipViewController.setNotifyUpdateRunnable(mQsTileNotifyUpdateRunnable);
-        mMicPrivacyChipViewController.addPrivacyChipView(mFrameLayout);
-        verify(mSensorPrivacyManager).addSensorPrivacyListener(eq(MICROPHONE),
-                mOnSensorPrivacyChangedListenerArgumentCaptor.capture());
-        reset(mMicPrivacyChip);
-        reset(mExecutor);
-        mOnSensorPrivacyChangedListenerArgumentCaptor.getValue()
-                .onSensorPrivacyChanged(MICROPHONE, /* enabled= */ true);
-        verify(mExecutor).execute(mRunnableArgumentCaptor.capture());
-
-        mRunnableArgumentCaptor.getAllValues().forEach(Runnable::run);
-
-        verify(mQsTileNotifyUpdateRunnable).run();
-    }
-
     @Test
     public void isSensorEnabled_sensorPrivacyEnabled_returnFalse() {
         when(mSensorPrivacyManager.isSensorPrivacyEnabled(anyInt(), eq(MICROPHONE)))
@@ -305,26 +271,4 @@ public class MicPrivacyChipViewControllerTest extends CarSysuiTestCase {
 
         assertThat(mMicPrivacyChipViewController.isSensorEnabled()).isTrue();
     }
-
-    @Test
-    public void toggleSensor_micTurnedOn_sensorPrivacyEnabled() {
-        when(mSensorPrivacyManager.isSensorPrivacyEnabled(anyInt(), eq(MICROPHONE)))
-                .thenReturn(false);
-
-        mMicPrivacyChipViewController.toggleSensor();
-
-        verify(mSensorPrivacyManager).setSensorPrivacy(eq(QS_TILE), eq(MICROPHONE), eq(true),
-                eq(TEST_USER_ID));
-    }
-
-    @Test
-    public void toggleSensor_micTurnedOff_sensorPrivacyDisabled() {
-        when(mSensorPrivacyManager.isSensorPrivacyEnabled(anyInt(), eq(MICROPHONE)))
-                .thenReturn(true);
-
-        mMicPrivacyChipViewController.toggleSensor();
-
-        verify(mSensorPrivacyManager).setSensorPrivacy(eq(QS_TILE), eq(MICROPHONE), eq(false),
-                eq(TEST_USER_ID));
-    }
 }
diff --git a/tests/src/com/android/systemui/car/userpicker/UserEventManagerTest.java b/tests/src/com/android/systemui/car/userpicker/UserEventManagerTest.java
index f4919b57..80e12804 100644
--- a/tests/src/com/android/systemui/car/userpicker/UserEventManagerTest.java
+++ b/tests/src/com/android/systemui/car/userpicker/UserEventManagerTest.java
@@ -19,7 +19,6 @@ import static android.car.user.CarUserManager.USER_LIFECYCLE_EVENT_TYPE_INVISIBL
 
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.mock;
-import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.spyOn;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
 
@@ -55,8 +54,7 @@ import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
-import org.mockito.MockitoSession;
-import org.mockito.quality.Strictness;
+import org.mockito.MockitoAnnotations;
 
 @CarSystemUiTest
 @RunWith(AndroidTestingRunner.class)
@@ -82,15 +80,9 @@ public class UserEventManagerTest extends UserPickerTestCase {
     @Mock
     private UserCreationResult mCreateResult;
 
-    private MockitoSession mMockingSession;
-
     @Before
     public void setUp() {
-        mMockingSession = mockitoSession()
-                .initMocks(this)
-                .spyStatic(ActivityManager.class)
-                .strictness(Strictness.WARN)
-                .startMocking();
+        MockitoAnnotations.initMocks(this);
 
         doReturn(MAIN_DISPLAY_ID).when(mContext).getDisplayId();
         doReturn(mMockCarUserManager).when(mMockCarServiceMediator).getCarUserManager();
@@ -106,9 +98,6 @@ public class UserEventManagerTest extends UserPickerTestCase {
     @After
     public void tearDown() {
         mUserEventManager.unregisterOnUpdateUsersListener(MAIN_DISPLAY_ID);
-        if (mMockingSession != null) {
-            mMockingSession.finishMocking();
-        }
     }
 
     @Test
diff --git a/tests/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewControllerTest.java b/tests/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewControllerTest.java
index 73d53952..aed1e491 100644
--- a/tests/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/userswitcher/UserSwitchTransitionViewControllerTest.java
@@ -16,7 +16,6 @@
 
 package com.android.systemui.car.userswitcher;
 
-import static com.android.systemui.Flags.FLAG_REFACTOR_GET_CURRENT_USER;
 import static com.android.systemui.car.Flags.FLAG_USER_SWITCH_KEYGUARD_SHOWN_TIMEOUT;
 
 import static com.google.common.truth.Truth.assertThat;
@@ -182,22 +181,8 @@ public class UserSwitchTransitionViewControllerTest extends CarSysuiTestCase {
                 any());
     }
 
-    @Test
-    public void onHandleShow_noUserRefactor_setsWMState() throws RemoteException {
-        mSetFlagsRule.disableFlags(FLAG_REFACTOR_GET_CURRENT_USER);
-
-        mCarUserSwitchingDialogController.handleShow(/* newUserId= */ TEST_USER_1);
-        mExecutor.advanceClockToLast();
-        mExecutor.runAllReady();
-
-        verify(mWindowManagerService).setSwitchingUser(true);
-        verify(mWindowManagerService).lockNow(null);
-    }
-
     @Test
     public void onHandleShow_userRefactor_setsWMState() throws RemoteException {
-        mSetFlagsRule.enableFlags(FLAG_REFACTOR_GET_CURRENT_USER);
-
         mCarUserSwitchingDialogController.handleShow(/* newUserId= */ TEST_USER_1);
         mExecutor.advanceClockToLast();
         mExecutor.runAllReady();
@@ -206,21 +191,8 @@ public class UserSwitchTransitionViewControllerTest extends CarSysuiTestCase {
         verify(mWindowManagerService, never()).lockNow(null);
     }
 
-    @Test
-    public void handleSwitching_noUserRefactor_doNothing() throws RemoteException {
-        mSetFlagsRule.disableFlags(FLAG_REFACTOR_GET_CURRENT_USER);
-
-        mCarUserSwitchingDialogController.handleSwitching(/* newUserId= */ TEST_USER_1);
-        mExecutor.advanceClockToLast();
-        mExecutor.runAllReady();
-
-        verify(mWindowManagerService, never()).lockNow(null);
-    }
-
     @Test
     public void handleSwitching_userRefactor_userNotSecure_doNothing() throws RemoteException {
-        mSetFlagsRule.enableFlags(FLAG_REFACTOR_GET_CURRENT_USER);
-
         mCarUserSwitchingDialogController.handleSwitching(/* newUserId= */ TEST_USER_1);
         mExecutor.advanceClockToLast();
         mExecutor.runAllReady();
@@ -230,7 +202,6 @@ public class UserSwitchTransitionViewControllerTest extends CarSysuiTestCase {
 
     @Test
     public void handleSwitching_userRefactor_userSecure_setsWMState() throws RemoteException {
-        mSetFlagsRule.enableFlags(FLAG_REFACTOR_GET_CURRENT_USER);
         when(mKeyguardManager.isDeviceSecure(anyInt())).thenReturn(true);
 
         mCarUserSwitchingDialogController.handleSwitching(/* newUserId= */ TEST_USER_1);
diff --git a/tests/src/com/android/systemui/car/voicerecognition/ConnectedDeviceVoiceRecognitionNotifierTest.java b/tests/src/com/android/systemui/car/voicerecognition/ConnectedDeviceVoiceRecognitionNotifierTest.java
deleted file mode 100644
index 0759bf29..00000000
--- a/tests/src/com/android/systemui/car/voicerecognition/ConnectedDeviceVoiceRecognitionNotifierTest.java
+++ /dev/null
@@ -1,150 +0,0 @@
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
-
-package com.android.systemui.car.voicerecognition;
-
-import static com.android.systemui.car.voicerecognition.ConnectedDeviceVoiceRecognitionNotifier.INVALID_VALUE;
-import static com.android.systemui.car.voicerecognition.ConnectedDeviceVoiceRecognitionNotifier.VOICE_RECOGNITION_STARTED;
-
-import static com.google.common.truth.Truth.assertThat;
-
-import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.Mockito.never;
-import static org.mockito.Mockito.verify;
-
-import android.bluetooth.BluetoothAdapter;
-import android.bluetooth.BluetoothDevice;
-import android.content.BroadcastReceiver;
-import android.content.Context;
-import android.content.Intent;
-import android.content.IntentFilter;
-import android.testing.AndroidTestingRunner;
-
-import androidx.test.filters.SmallTest;
-
-import com.android.systemui.CarSysuiTestCase;
-import com.android.systemui.car.CarSystemUiTest;
-import com.android.systemui.util.concurrency.DelayableExecutor;
-
-import org.junit.Before;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.mockito.ArgumentCaptor;
-import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
-
-@CarSystemUiTest
-@RunWith(AndroidTestingRunner.class)
-@SmallTest
-// TODO(b/162866441): Refactor to use the Executor pattern instead.
-public class ConnectedDeviceVoiceRecognitionNotifierTest extends CarSysuiTestCase {
-
-    // TODO(b/218911666): {@link BluetoothHeadsetClient.ACTION_AG_EVENT} is a hidden API.
-    private static final String HEADSET_CLIENT_ACTION_AG_EVENT =
-            "android.bluetooth.headsetclient.profile.action.AG_EVENT";
-    // TODO(b/218911666): {@link BluetoothHeadsetClient.EXTRA_VOICE_RECOGNITION} is a hidden API.
-    private static final String HEADSET_CLIENT_EXTRA_VOICE_RECOGNITION =
-            "android.bluetooth.headsetclient.extra.VOICE_RECOGNITION";
-    // TODO(b/218911666): {@link BluetoothHeadsetClient.ACTION_AUDIO_STATE_CHANGED} is a hidden API.
-    private static final String HEADSET_CLIENT_ACTION_AUDIO_STATE_CHANGED =
-            "android.bluetooth.headsetclient.profile.action.AUDIO_STATE_CHANGED";
-
-    private static final String BLUETOOTH_REMOTE_ADDRESS = "00:11:22:33:44:55";
-
-    private ConnectedDeviceVoiceRecognitionNotifier mVoiceRecognitionNotifier;
-    private BluetoothDevice mBluetoothDevice;
-
-    @Mock
-    private Context mMockContext;
-    @Mock
-    private DelayableExecutor mExecutor;
-
-    @Before
-    public void setUp() throws Exception {
-        MockitoAnnotations.initMocks(this);
-        mBluetoothDevice = BluetoothAdapter.getDefaultAdapter().getRemoteDevice(
-                BLUETOOTH_REMOTE_ADDRESS);
-        mVoiceRecognitionNotifier = new ConnectedDeviceVoiceRecognitionNotifier(
-                mMockContext, mExecutor);
-    }
-
-    @Test
-    public void onBootComplete_registersReceiver() {
-        mVoiceRecognitionNotifier.onBootCompleted();
-
-        ArgumentCaptor<IntentFilter> captor = ArgumentCaptor.forClass(IntentFilter.class);
-        verify(mMockContext).registerReceiverAsUser(any(), any(), captor.capture(), any(), any());
-
-        assertThat(captor.getValue().hasAction(HEADSET_CLIENT_ACTION_AG_EVENT)).isTrue();
-    }
-
-    @Test
-    public void testReceiveIntent_started_showToast() {
-        BroadcastReceiver receiver = onBootCompleteGetBroadcastReceiver();
-        Intent intent = new Intent(HEADSET_CLIENT_ACTION_AG_EVENT);
-        intent.putExtra(HEADSET_CLIENT_EXTRA_VOICE_RECOGNITION, VOICE_RECOGNITION_STARTED);
-        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mBluetoothDevice);
-
-        receiver.onReceive(mMockContext, intent);
-
-        ArgumentCaptor<Runnable> argumentCaptor = ArgumentCaptor.forClass(Runnable.class);
-        verify(mExecutor).execute(argumentCaptor.capture());
-        assertThat(argumentCaptor.getValue()).isNotNull();
-        assertThat(argumentCaptor.getValue()).isNotEqualTo(this);
-    }
-
-    @Test
-    public void testReceiveIntent_invalidExtra_noToast() {
-        BroadcastReceiver receiver = onBootCompleteGetBroadcastReceiver();
-        Intent intent = new Intent(HEADSET_CLIENT_ACTION_AG_EVENT);
-        intent.putExtra(HEADSET_CLIENT_EXTRA_VOICE_RECOGNITION, INVALID_VALUE);
-        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mBluetoothDevice);
-
-        receiver.onReceive(mMockContext, intent);
-
-        verify(mExecutor, never()).execute(any());
-    }
-
-    @Test
-    public void testReceiveIntent_noExtra_noToast() {
-        BroadcastReceiver receiver = onBootCompleteGetBroadcastReceiver();
-        Intent intent = new Intent(HEADSET_CLIENT_ACTION_AG_EVENT);
-        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mBluetoothDevice);
-
-        receiver.onReceive(mMockContext, intent);
-
-        verify(mExecutor, never()).execute(any());
-    }
-
-    @Test
-    public void testReceiveIntent_invalidIntent_noToast() {
-        BroadcastReceiver receiver = onBootCompleteGetBroadcastReceiver();
-        Intent intent = new Intent(HEADSET_CLIENT_ACTION_AUDIO_STATE_CHANGED);
-        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mBluetoothDevice);
-
-        receiver.onReceive(mMockContext, intent);
-
-        verify(mExecutor, never()).execute(any());
-    }
-
-    private BroadcastReceiver onBootCompleteGetBroadcastReceiver() {
-        mVoiceRecognitionNotifier.onBootCompleted();
-
-        ArgumentCaptor<BroadcastReceiver> captor = ArgumentCaptor.forClass(BroadcastReceiver.class);
-        verify(mMockContext).registerReceiverAsUser(captor.capture(), any(), any(), any(), any());
-        return captor.getValue();
-    }
-}
diff --git a/tests/src/com/android/systemui/car/wm/scalableui/PanelAutoTaskStackTransitionHandlerDelegateTest.java b/tests/src/com/android/systemui/car/wm/scalableui/PanelAutoTaskStackTransitionHandlerDelegateTest.java
index a8f6c6db..b4dafa2a 100644
--- a/tests/src/com/android/systemui/car/wm/scalableui/PanelAutoTaskStackTransitionHandlerDelegateTest.java
+++ b/tests/src/com/android/systemui/car/wm/scalableui/PanelAutoTaskStackTransitionHandlerDelegateTest.java
@@ -39,6 +39,7 @@ import com.android.systemui.CarSysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.wm.scalableui.panel.PanelUtils;
 import com.android.systemui.car.wm.scalableui.panel.TaskPanelInfoRepository;
+import com.android.wm.shell.automotive.AutoLayoutManager;
 import com.android.wm.shell.automotive.AutoTaskStackController;
 import com.android.wm.shell.automotive.AutoTaskStackState;
 import com.android.wm.shell.automotive.AutoTaskStackTransaction;
@@ -63,22 +64,24 @@ public class PanelAutoTaskStackTransitionHandlerDelegateTest extends CarSysuiTes
     @Mock
     private AutoTaskStackController mAutoTaskStackController;
     @Mock
-    private TaskPanelTransitionCoordinator mTaskPanelTransitionCoordinator;
+    private PanelTransitionCoordinator mPanelTransitionCoordinator;
     @Mock
     private Transitions.TransitionFinishCallback mFinishCallback;
     @Mock
     private PanelUtils mPanelUtils;
     @Mock
     private TaskPanelInfoRepository mTaskPanelInfoRepository;
+    @Mock
+    private AutoLayoutManager mAutoLayoutManager;
 
     @Before
     public void setUp() {
         MockitoAnnotations.initMocks(this);
-        when(mTaskPanelTransitionCoordinator.createAutoTaskStackTransaction(any(),
+        when(mPanelTransitionCoordinator.createAutoTaskStackTransaction(any(),
                 any())).thenReturn(new AutoTaskStackTransaction());
         mDelegate = new PanelAutoTaskStackTransitionHandlerDelegate(mContext,
-                mAutoTaskStackController, mTaskPanelTransitionCoordinator, mPanelUtils,
-                mTaskPanelInfoRepository);
+                mAutoTaskStackController, mPanelTransitionCoordinator, mPanelUtils,
+                mTaskPanelInfoRepository, mAutoLayoutManager);
     }
 
     @Test
@@ -113,7 +116,7 @@ public class PanelAutoTaskStackTransitionHandlerDelegateTest extends CarSysuiTes
         TransitionInfo info = mock(TransitionInfo.class);
         SurfaceControl.Transaction startTransaction = mock(SurfaceControl.Transaction.class);
         SurfaceControl.Transaction finishTransaction = mock(SurfaceControl.Transaction.class);
-        when(mTaskPanelTransitionCoordinator.playPendingAnimations(any(), any())).thenReturn(true);
+        when(mPanelTransitionCoordinator.playPendingAnimations(any(), any())).thenReturn(true);
 
         boolean result = mDelegate.startAnimation(
                 mock(IBinder.class),
@@ -132,7 +135,7 @@ public class PanelAutoTaskStackTransitionHandlerDelegateTest extends CarSysuiTes
         TransitionInfo info = mock(TransitionInfo.class);
         SurfaceControl.Transaction startTransaction = mock(SurfaceControl.Transaction.class);
         SurfaceControl.Transaction finishTransaction = mock(SurfaceControl.Transaction.class);
-        when(mTaskPanelTransitionCoordinator.playPendingAnimations(any(), any())).thenReturn(false);
+        when(mPanelTransitionCoordinator.playPendingAnimations(any(), any())).thenReturn(false);
 
         boolean result = mDelegate.startAnimation(
                 mock(IBinder.class),
@@ -153,7 +156,7 @@ public class PanelAutoTaskStackTransitionHandlerDelegateTest extends CarSysuiTes
                 false,
                 mock(SurfaceControl.Transaction.class));
 
-        verify(mTaskPanelTransitionCoordinator).stopRunningAnimations();
+        verify(mPanelTransitionCoordinator).stopRunningAnimations(any());
     }
 
     @Test
@@ -166,6 +169,6 @@ public class PanelAutoTaskStackTransitionHandlerDelegateTest extends CarSysuiTes
                 mock(IBinder.class),
                 mock(Transitions.TransitionFinishCallback.class));
 
-        verify(mTaskPanelTransitionCoordinator).stopRunningAnimations();
+        verify(mPanelTransitionCoordinator).stopRunningAnimations(any());
     }
 }
diff --git a/tests/src/com/android/systemui/car/wm/scalableui/TaskPanelTransitionCoordinatorTest.java b/tests/src/com/android/systemui/car/wm/scalableui/PanelTransitionCoordinatorTest.java
similarity index 66%
rename from tests/src/com/android/systemui/car/wm/scalableui/TaskPanelTransitionCoordinatorTest.java
rename to tests/src/com/android/systemui/car/wm/scalableui/PanelTransitionCoordinatorTest.java
index 3bdcbd03..a1b72610 100644
--- a/tests/src/com/android/systemui/car/wm/scalableui/TaskPanelTransitionCoordinatorTest.java
+++ b/tests/src/com/android/systemui/car/wm/scalableui/PanelTransitionCoordinatorTest.java
@@ -36,12 +36,14 @@ import androidx.test.platform.app.InstrumentationRegistry;
 
 import com.android.car.scalableui.model.PanelTransaction;
 import com.android.systemui.CarSysuiTestCase;
+import com.android.systemui.ShellSyncExecutor;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.wm.scalableui.panel.PanelUtils;
 import com.android.wm.shell.automotive.AutoLayoutManager;
 import com.android.wm.shell.automotive.AutoSurfaceTransaction;
 import com.android.wm.shell.automotive.AutoSurfaceTransactionFactory;
 import com.android.wm.shell.automotive.AutoTaskStackController;
+import com.android.wm.shell.common.ShellExecutor;
 import com.android.wm.shell.transition.Transitions;
 
 import org.junit.Before;
@@ -58,9 +60,10 @@ import java.util.concurrent.atomic.AtomicBoolean;
 @RunWith(AndroidJUnit4.class)
 @TestableLooper.RunWithLooper
 @SmallTest
-public class TaskPanelTransitionCoordinatorTest extends CarSysuiTestCase {
+public class PanelTransitionCoordinatorTest extends CarSysuiTestCase {
 
-    private TaskPanelTransitionCoordinator mTaskPanelTransitionCoordinator;
+    private PanelTransitionCoordinator mPanelTransitionCoordinator;
+    private ShellExecutor mMainExecutor;
 
     @Mock
     private Transitions.TransitionFinishCallback mFinishCallback;
@@ -78,9 +81,10 @@ public class TaskPanelTransitionCoordinatorTest extends CarSysuiTestCase {
     @Before
     public void setUp() {
         MockitoAnnotations.initMocks(this);
-        mTaskPanelTransitionCoordinator = new TaskPanelTransitionCoordinator(
+        mMainExecutor = new ShellSyncExecutor();
+        mPanelTransitionCoordinator = new PanelTransitionCoordinator(
                 mAutoTaskStackController, mAutoSurfaceTransactionFactory, mPanelUtils,
-                mAutoLayoutManager);
+                mAutoLayoutManager, mMainExecutor);
         when(mAutoSurfaceTransactionFactory.createTransaction(anyString())).thenReturn(
                 mAutoSurfaceTransaction);
     }
@@ -91,12 +95,12 @@ public class TaskPanelTransitionCoordinatorTest extends CarSysuiTestCase {
         Animator animator = new ValueAnimator();
         when(mAutoTaskStackController.startTransition(any())).thenReturn(binder);
         PanelTransaction panelTransaction = new PanelTransaction.Builder()
-                .addAnimator("testPanel", animator).build();
+                .addAnimator("testPanel", animator).setHasWindowChanges(true).build();
 
-        mTaskPanelTransitionCoordinator.startTransition(panelTransaction);
+        mPanelTransitionCoordinator.startTransition(panelTransaction);
 
         PanelTransaction pendingTransaction =
-                mTaskPanelTransitionCoordinator.getPendingPanelTransaction(binder);
+                mPanelTransitionCoordinator.getPendingPanelTransaction(binder);
         assertThat(pendingTransaction).isNotNull();
         assertThat(pendingTransaction.getAnimators().size()).isEqualTo(1);
     }
@@ -107,7 +111,7 @@ public class TaskPanelTransitionCoordinatorTest extends CarSysuiTestCase {
         AtomicBoolean animationStarted = new AtomicBoolean(false);
 
         InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
-            animationStarted.set(mTaskPanelTransitionCoordinator.playPendingAnimations(binder,
+            animationStarted.set(mPanelTransitionCoordinator.playPendingAnimations(binder,
                     mFinishCallback));
         });
 
@@ -129,27 +133,29 @@ public class TaskPanelTransitionCoordinatorTest extends CarSysuiTestCase {
         });
         PanelTransaction panelTransaction = new PanelTransaction.Builder()
                 .addAnimator("testPanel", animator).build();
-        mTaskPanelTransitionCoordinator.createAutoTaskStackTransaction(binder, panelTransaction);
+        mPanelTransitionCoordinator.createAutoTaskStackTransaction(binder, panelTransaction);
 
         AtomicBoolean animationStarted = new AtomicBoolean(false);
         InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
-            animationStarted.set(mTaskPanelTransitionCoordinator.playPendingAnimations(binder,
+            animationStarted.set(mPanelTransitionCoordinator.playPendingAnimations(binder,
                     mFinishCallback));
         });
 
         assertThat(animationStarted.get()).isTrue();
-        assertThat(latch.await(/* timeout= */ 5, TimeUnit.SECONDS)).isTrue();
+        assertThat(latch.await(/* timeout= */ 10, TimeUnit.SECONDS)).isTrue();
         assertThat(latch.getCount()).isEqualTo(0);
-        assertThat(mTaskPanelTransitionCoordinator.isAnimationRunning()).isFalse();
+        assertThat(mPanelTransitionCoordinator.isAnimationRunning()).isFalse();
         // There may be a slight delay between the Animator receiving onAnimationEnd and the
         // AnimatorSet receiving onAnimationEnd.
         verify(mFinishCallback, timeout(1000)).onTransitionFinished(null);
     }
 
     @Test
-    public void testStopRunningAnimations() throws InterruptedException {
+    public void testStopRunningAnimationsIfNeed_differentTransition_stopAnimation()
+            throws InterruptedException {
         CountDownLatch latch = new CountDownLatch(1); // Latch for waiting
         IBinder binder = new Binder();
+        IBinder binder2 = new Binder();
         ValueAnimator animator = ValueAnimator.ofFloat(0, 1);
         animator.setDuration(5000L);
         animator.addListener(new AnimatorListenerAdapter() {
@@ -161,21 +167,57 @@ public class TaskPanelTransitionCoordinatorTest extends CarSysuiTestCase {
         });
         PanelTransaction panelTransaction = new PanelTransaction.Builder()
                 .addAnimator("testPanel", animator).build();
-        mTaskPanelTransitionCoordinator.createAutoTaskStackTransaction(binder, panelTransaction);
+        mPanelTransitionCoordinator.createAutoTaskStackTransaction(binder, panelTransaction);
 
         // Run the animation on the main looper
         InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
-            mTaskPanelTransitionCoordinator.playPendingAnimations(binder, mFinishCallback);
+            mPanelTransitionCoordinator.playPendingAnimations(binder, mFinishCallback);
         });
 
-        mTaskPanelTransitionCoordinator.stopRunningAnimations();
+        mPanelTransitionCoordinator.stopRunningAnimations(binder2);
         // onAnimationEnd should still be called when cancelled - wait for a small amount of time
         // and expect animation end callback to execute
         assertThat(latch.await(/* timeout= */ 1, TimeUnit.SECONDS)).isTrue();
         assertThat(latch.getCount()).isEqualTo(0);
-        assertThat(mTaskPanelTransitionCoordinator.isAnimationRunning()).isFalse();
         // There may be a slight delay between the Animator receiving onAnimationEnd and the
         // AnimatorSet receiving onAnimationEnd.
         verify(mFinishCallback, timeout(1000)).onTransitionFinished(null);
     }
+
+    @Test
+    public void testStopRunningAnimations_sameTransition_keepAnimation()
+            throws InterruptedException {
+        CountDownLatch latch = new CountDownLatch(1); // Latch for waiting
+        IBinder binder = new Binder();
+        ValueAnimator animator = ValueAnimator.ofFloat(0, 1);
+        animator.setDuration(5000L);
+        animator.addListener(new AnimatorListenerAdapter() {
+            @Override
+            public void onAnimationEnd(Animator animation) {
+                super.onAnimationEnd(animation);
+                latch.countDown();
+            }
+        });
+        PanelTransaction panelTransaction = new PanelTransaction.Builder()
+                .addAnimator("testPanel", animator).build();
+        mPanelTransitionCoordinator.createAutoTaskStackTransaction(binder, panelTransaction);
+
+        // Run the animation on the main looper
+        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
+            mPanelTransitionCoordinator.playPendingAnimations(binder, mFinishCallback);
+        });
+
+        mPanelTransitionCoordinator.stopRunningAnimations(binder);
+        // Animation should continue on the same binder
+        assertThat(latch.await(/* timeout= */ 1, TimeUnit.SECONDS)).isFalse();
+        assertThat(latch.getCount()).isEqualTo(1);
+        assertThat(mPanelTransitionCoordinator.isAnimationRunning()).isTrue();
+        // There may be a slight delay between the Animator receiving onAnimationEnd and the
+        // AnimatorSet receiving onAnimationEnd.
+
+        assertThat(latch.await(/* timeout= */ 5, TimeUnit.SECONDS)).isTrue();
+        assertThat(latch.getCount()).isEqualTo(0);
+        assertThat(mPanelTransitionCoordinator.isAnimationRunning()).isFalse();
+        verify(mFinishCallback, timeout(5000)).onTransitionFinished(null);
+    }
 }
diff --git a/tests/src/com/android/systemui/car/wm/scalableui/panel/DecorPanelTest.java b/tests/src/com/android/systemui/car/wm/scalableui/panel/DecorPanelTest.java
new file mode 100644
index 00000000..29bbba3c
--- /dev/null
+++ b/tests/src/com/android/systemui/car/wm/scalableui/panel/DecorPanelTest.java
@@ -0,0 +1,206 @@
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
+package com.android.systemui.car.wm.scalableui.panel;
+
+import static org.junit.Assert.assertEquals;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.doAnswer;
+import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.spy;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.content.Context;
+import android.content.res.Resources;
+import android.graphics.Rect;
+import android.view.View;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.filters.SmallTest;
+
+import com.android.car.scalableui.model.Role;
+import com.android.systemui.CarSysuiTestCase;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.wm.scalableui.EventDispatcher;
+import com.android.wm.shell.automotive.AutoDecor;
+import com.android.wm.shell.automotive.AutoDecorManager;
+import com.android.wm.shell.automotive.AutoSurfaceTransaction;
+import com.android.wm.shell.automotive.AutoSurfaceTransactionFactory;
+import com.android.wm.shell.common.ShellExecutor;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Captor;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+@CarSystemUiTest
+@RunWith(AndroidJUnit4.class)
+@SmallTest
+public class DecorPanelTest extends CarSysuiTestCase {
+
+    private static final String TEST_PANEL_ID = "testPanel";
+    private static final int TEST_LAYER = 1;
+    private static final String TEST_PANEL_ID_NAME = "DecorName";
+    private static final int TEST_DISPLAY_ID = 0;
+
+    // --- Mocks for Dependencies ---
+    @Mock
+    private Context mMockContext;
+    @Mock
+    private Resources mResources;
+    @Mock
+    private AutoDecorManager mAutoDecorManager;
+    @Mock
+    private EventDispatcher mEventDispatcher;
+    @Mock
+    private PanelUtils mPanelUtils;
+    @Mock
+    private ShellExecutor mShellExecutor;
+    @Mock
+    private AutoDecor mMockExistingAutoDecor;
+    @Mock
+    private AutoDecor mMockNewAutoDecor;
+    @Mock
+    private View mMockDecorView;
+    @Mock
+    private Rect mMockBounds;
+    @Mock
+    private AutoDecor mAutoDecor;
+    @Mock
+    private Role mRole;
+    @Mock
+    private AutoSurfaceTransactionFactory mAutoSurfaceTransactionFactory;
+    @Mock
+    private AutoSurfaceTransaction mAutoSurfaceTransaction;
+
+    // --- Captors ---
+    @Captor
+    private ArgumentCaptor<Runnable> mRunnableArgumentCaptor;
+
+    // --- Class Under Test (using @Spy) ---
+    private DecorPanel mDecorPanel;
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.openMocks(this);
+        // Manual Spy initialization is safer with complex/assisted constructors
+        mDecorPanel = spy(new DecorPanel(
+                mMockContext,
+                mAutoDecorManager,
+                mEventDispatcher,
+                mPanelUtils,
+                mShellExecutor,
+                mAutoSurfaceTransactionFactory,
+                TEST_PANEL_ID
+        ));
+
+        doReturn(mResources).when(mMockContext).getResources();
+        doReturn(mMockDecorView).when(mRole).getView(any());
+        doReturn(mRole).when(mDecorPanel).getRole();
+
+        // --- Handle Executor ---
+        doAnswer(invocation -> {
+            Runnable runnable = invocation.getArgument(0);
+            if (runnable != null) {
+                runnable.run();
+            }
+            return null;
+        }).when(mShellExecutor).execute(any(Runnable.class));
+
+        // --- Stub BasePanel methods (called via spy) ---
+        doReturn(TEST_LAYER).when(mDecorPanel).getLayer();
+        doReturn(mMockBounds).when(mDecorPanel).getBounds();
+        doReturn(TEST_PANEL_ID_NAME).when(mDecorPanel).getPanelId();
+        doReturn(TEST_DISPLAY_ID).when(mDecorPanel).getDisplayId();
+
+        // --- Stub AutoDecorManager ---
+        when(mAutoDecorManager.createAutoDecor(any(), anyInt(), any(), any()))
+                .thenReturn(mMockNewAutoDecor);
+
+        when(mAutoSurfaceTransactionFactory.createTransaction(any())).thenReturn(
+                mAutoSurfaceTransaction);
+    }
+
+    // --- Tests for init() ---
+    @Test
+    public void init_whenUserIsUnlocked_callsReset() {
+        when(mPanelUtils.isUserUnlocked()).thenReturn(true);
+
+        mDecorPanel.init();
+
+        verify(mDecorPanel).reset();
+        verify(mShellExecutor).execute(any(Runnable.class));
+    }
+
+    @Test
+    public void init_whenUserIsLocked_doesNotCallReset() {
+        when(mPanelUtils.isUserUnlocked()).thenReturn(false);
+
+        mDecorPanel.init();
+
+        verify(mDecorPanel, never()).reset();
+        verify(mShellExecutor, never()).execute(any(Runnable.class));
+    }
+
+    // --- Tests for reset() ---
+
+    @Test
+    public void reset_whenNoExistingDecor_andInflateSucceeds_createsAndAttachesNewDecor() {
+        mDecorPanel.mAutoDecor = null;
+        when(mAutoDecorManager.createAutoDecor(any(), anyInt(), any(), anyString())).thenReturn(
+                mAutoDecor);
+
+        mDecorPanel.reset();
+
+        verify(mShellExecutor).execute(mRunnableArgumentCaptor.capture());
+        verify(mAutoDecorManager, never()).removeAutoDecor(any());
+        verify(mDecorPanel).inflateDecorView();
+        verify(mAutoDecorManager).createAutoDecor(
+                eq(mMockDecorView),
+                eq(TEST_LAYER),
+                eq(mMockBounds),
+                eq(TEST_PANEL_ID_NAME));
+        verify(mAutoDecorManager).attachAutoDecorToDisplay(
+                eq(mAutoDecor),
+                eq(TEST_DISPLAY_ID));
+        assertEquals(mAutoDecor, mDecorPanel.getAutoDecor());
+    }
+
+    @Test
+    public void reset_whenExistingDecor_andInflateSucceeds_removesOldCreatesAndAttachesNewDecor() {
+        mDecorPanel.mAutoDecor = mMockExistingAutoDecor;
+        when(mAutoDecorManager.createAutoDecor(any(), anyInt(), any(), anyString())).thenReturn(
+                mAutoDecor);
+
+        mDecorPanel.reset();
+
+        verify(mShellExecutor).execute(mRunnableArgumentCaptor.capture());
+        verify(mAutoDecorManager).removeAutoDecor(mMockExistingAutoDecor);
+        verify(mDecorPanel).inflateDecorView();
+        verify(mAutoDecorManager).createAutoDecor(eq(mMockDecorView), eq(TEST_LAYER),
+                eq(mMockBounds), eq(TEST_PANEL_ID_NAME));
+        verify(mAutoDecorManager).attachAutoDecorToDisplay(eq(mAutoDecor),
+                eq(TEST_DISPLAY_ID));
+        assertEquals(mAutoDecor, mDecorPanel.getAutoDecor());
+    }
+}
diff --git a/tests/src/com/android/systemui/car/wm/scalableui/panel/TaskPanelTest.java b/tests/src/com/android/systemui/car/wm/scalableui/panel/TaskPanelTest.java
index 52378182..3505f2be 100644
--- a/tests/src/com/android/systemui/car/wm/scalableui/panel/TaskPanelTest.java
+++ b/tests/src/com/android/systemui/car/wm/scalableui/panel/TaskPanelTest.java
@@ -30,13 +30,22 @@ import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
 import com.android.systemui.CarSysuiTestCase;
+import com.android.systemui.ShellSyncExecutor;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.wm.scalableui.AutoTaskStackHelper;
 import com.android.systemui.car.wm.scalableui.EventDispatcher;
+import com.android.systemui.car.wm.scalableui.panel.controller.PanelControllerInitializer;
+import com.android.wm.shell.ShellTaskOrganizer;
+import com.android.wm.shell.automotive.AutoCaptionController;
+import com.android.wm.shell.automotive.AutoDecorManager;
+import com.android.wm.shell.automotive.AutoLayoutManager;
+import com.android.wm.shell.automotive.AutoSurfaceTransaction;
+import com.android.wm.shell.automotive.AutoSurfaceTransactionFactory;
 import com.android.wm.shell.automotive.AutoTaskStackController;
 import com.android.wm.shell.automotive.AutoTaskStackTransaction;
 import com.android.wm.shell.automotive.RootTaskStack;
+import com.android.wm.shell.common.ShellExecutor;
 
 import org.junit.Before;
 import org.junit.Test;
@@ -47,10 +56,11 @@ import org.mockito.MockitoAnnotations;
 @CarSystemUiTest
 @RunWith(AndroidJUnit4.class)
 @SmallTest
-public class TaskPanelTest extends CarSysuiTestCase{
+public class TaskPanelTest extends CarSysuiTestCase {
     private static final String TASK_PANEL_ID = "TASK_PANEL_ID";
 
     private TaskPanel mTaskPanel;
+    private ShellExecutor mMainExecutor;
 
     @Mock
     private AutoTaskStackController mAutoTaskStackController;
@@ -59,10 +69,16 @@ public class TaskPanelTest extends CarSysuiTestCase{
     @Mock
     private AutoTaskStackHelper mAutoTaskStackHelper;
     @Mock
+    private AutoCaptionController mAutoCaptionController;
+    @Mock
+    private ShellTaskOrganizer mShellTaskOrganizer;
+    @Mock
     private TaskPanel.Factory mFactory;
     @Mock
     private RootTaskStack mRootTaskStack;
     @Mock
+    private AutoDecorManager mAutoDecorManager;
+    @Mock
     private CarActivityManager mCarActivityManager;
     @Mock
     private PanelUtils mPanelUtils;
@@ -70,14 +86,28 @@ public class TaskPanelTest extends CarSysuiTestCase{
     private TaskPanelInfoRepository mTaskPanelInfoRepository;
     @Mock
     private EventDispatcher mEventDispatcher;
+    @Mock
+    private PanelControllerInitializer mPanelControllerInitializer;
+    @Mock
+    private AutoLayoutManager mAutoLayoutManager;
+    @Mock
+    AutoSurfaceTransactionFactory mAutoSurfaceTransactionFactory;
+    @Mock
+    private AutoSurfaceTransaction mAutoSurfaceTransaction;
 
     @Before
     public void setUp() {
         MockitoAnnotations.initMocks(this);
+        mMainExecutor = new ShellSyncExecutor();
         mTaskPanel = new TaskPanel(mAutoTaskStackController, mContext, mCarServiceProvider,
-                mAutoTaskStackHelper, mPanelUtils, mTaskPanelInfoRepository, mEventDispatcher,
-                TASK_PANEL_ID);
+                mAutoTaskStackHelper, mShellTaskOrganizer, mAutoCaptionController, mPanelUtils,
+                mTaskPanelInfoRepository, mAutoDecorManager, mEventDispatcher,
+                mPanelControllerInitializer, mAutoLayoutManager, mMainExecutor,
+                mAutoSurfaceTransactionFactory, TASK_PANEL_ID);
         when(mFactory.create(any())).thenReturn(mTaskPanel);
+
+        when(mAutoSurfaceTransactionFactory.createTransaction(any())).thenReturn(
+                mAutoSurfaceTransaction);
     }
 
     @Test
diff --git a/tests/src/com/android/systemui/car/wm/scalableui/panel/controller/BaseTaskPanelControllerTest.java b/tests/src/com/android/systemui/car/wm/scalableui/panel/controller/BaseTaskPanelControllerTest.java
new file mode 100644
index 00000000..b312767d
--- /dev/null
+++ b/tests/src/com/android/systemui/car/wm/scalableui/panel/controller/BaseTaskPanelControllerTest.java
@@ -0,0 +1,212 @@
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
+package com.android.systemui.car.wm.scalableui.panel.controller;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertTrue;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.content.BroadcastReceiver;
+import android.content.ComponentName;
+import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
+import android.content.pm.PackageManager;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.filters.SmallTest;
+
+import com.android.car.scalableui.model.PanelControllerMetadata;
+import com.android.car.scalableui.panel.TaskPanelHandler;
+import com.android.systemui.CarSysuiTestCase;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.wm.scalableui.panel.PanelUtils;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+import java.net.URISyntaxException;
+import java.util.List;
+import java.util.Set;
+
+@CarSystemUiTest
+@RunWith(AndroidJUnit4.class)
+@SmallTest
+public class BaseTaskPanelControllerTest extends CarSysuiTestCase {
+    private static final ComponentName DEFAULT_ACTIVITY = new ComponentName("com.example",
+            "DefaultActivity");
+    private static final ComponentName ACTIVITY_1 = new ComponentName("com.test",
+            "Activity1");
+    private static final ComponentName ACTIVITY_2 = new ComponentName("com.test", "Activity2");
+
+    @Mock
+    private Context mMockContext;
+    @Mock
+    private PackageManager mPackageManager;
+    @Mock
+    private TaskPanelHandler mTaskPanelHandler;
+    @Mock
+    private PanelControllerMetadata mPanelControllerMetadata;
+    @Mock
+    private PanelUtils mPanelUtils;
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.openMocks(this);
+        when(mMockContext.getPackageManager()).thenReturn(mPackageManager);
+    }
+
+    @Test
+    public void constructor_parsesDefaultComponent() {
+        when(mPanelControllerMetadata.getStringConfiguration(
+                PanelControllerMetadata.DEFAULT_COMPONENT)).thenReturn(
+                DEFAULT_ACTIVITY.flattenToString());
+        BaseTaskPanelController controller = new BaseTaskPanelController(mMockContext,
+                mPanelControllerMetadata, mPanelUtils);
+        Intent defaultIntent = controller.getDefaultComponent();
+        assertNotNull(defaultIntent);
+        assertEquals(DEFAULT_ACTIVITY, defaultIntent.getComponent());
+    }
+
+    @Test
+    public void constructor_noDefaultComponent() {
+        when(mPanelControllerMetadata.getStringConfiguration(
+                PanelControllerMetadata.DEFAULT_COMPONENT)).thenReturn(null);
+        BaseTaskPanelController controller = new BaseTaskPanelController(mMockContext,
+                mPanelControllerMetadata, mPanelUtils);
+        Intent defaultIntent = controller.getDefaultComponent();
+        assertNotNull(defaultIntent);
+        assertNull(defaultIntent.getComponent());
+    }
+
+    @Test
+    public void constructor_parsesPersistentActivities() {
+        when(mPanelControllerMetadata.getListConfiguration(
+                PanelControllerMetadata.PERSISTENT_ACTIVITY)).thenReturn(
+                List.of(ACTIVITY_1.flattenToString(), ACTIVITY_2.flattenToString()));
+        when(mPanelControllerMetadata.hasConfiguration(
+                PanelControllerMetadata.PERSISTENT_ACTIVITY)).thenReturn(true);
+        BaseTaskPanelController controller = new BaseTaskPanelController(mMockContext,
+                mPanelControllerMetadata, mPanelUtils);
+        Set<ComponentName> persistentActivities = controller.getPersistentActivities();
+        assertEquals(2, persistentActivities.size());
+        assertTrue(persistentActivities.contains(ACTIVITY_1));
+        assertTrue(persistentActivities.contains(ACTIVITY_2));
+    }
+
+    @Test
+    public void constructor_noPersistentActivities() {
+        when(mPanelControllerMetadata.getStringConfiguration(
+                PanelControllerMetadata.PERSISTENT_ACTIVITY)).thenReturn(null);
+        BaseTaskPanelController controller = new BaseTaskPanelController(mMockContext,
+                mPanelControllerMetadata, mPanelUtils);
+        Set<ComponentName> persistentActivities = controller.getPersistentActivities();
+        assertTrue(persistentActivities.isEmpty());
+    }
+
+    @Test
+    public void constructor_registersReceiverForUpdateFilter() throws URISyntaxException {
+        String updateFilterString = "android-app://com.example.package/path";
+        when(mPanelControllerMetadata.getStringConfiguration(
+                PanelControllerMetadata.UPDATABLE_INTENT_FILTER)).thenReturn(updateFilterString);
+
+        new BaseTaskPanelController(mMockContext, mPanelControllerMetadata, mPanelUtils);
+
+        ArgumentCaptor<BroadcastReceiver> receiverCaptor = ArgumentCaptor.forClass(
+                BroadcastReceiver.class);
+        ArgumentCaptor<IntentFilter> filterCaptor = ArgumentCaptor.forClass(IntentFilter.class);
+        verify(mMockContext).registerReceiver(receiverCaptor.capture(), filterCaptor.capture(),
+                eq(Context.RECEIVER_EXPORTED));
+
+        IntentFilter filter = filterCaptor.getValue();
+        assertEquals(2, filter.countActions());
+        assertTrue(filter.hasAction(Intent.ACTION_PACKAGE_ADDED));
+        assertTrue(filter.hasAction(Intent.ACTION_PACKAGE_REMOVED));
+        assertEquals("package", filter.getDataScheme(0));
+    }
+
+    @Test
+    public void constructor_noUpdateFilter_doesNotRegisterReceiver() {
+        when(mPanelControllerMetadata.getStringConfiguration(
+                PanelControllerMetadata.UPDATABLE_INTENT_FILTER)).thenReturn(null);
+
+        new BaseTaskPanelController(mMockContext, mPanelControllerMetadata, mPanelUtils);
+
+        verify(mMockContext, never()).registerReceiver(any(BroadcastReceiver.class),
+                any(IntentFilter.class), eq(Context.RECEIVER_EXPORTED));
+    }
+
+    @Test
+    public void updatePersistentActivities_addsStaticPersistentActivities() {
+        mPanelControllerMetadata = PanelControllerMetadata.builder("id").addConfiguration(
+                PanelControllerMetadata.PERSISTENT_ACTIVITY,
+                ACTIVITY_1.flattenToString()).build();
+        BaseTaskPanelController controller = new BaseTaskPanelController(mMockContext,
+                mPanelControllerMetadata, mPanelUtils);
+        controller.registerTaskPanelHandler(mTaskPanelHandler);
+        // Trigger update (e.g., after package event)
+        controller.updatePersistentActivities();
+        Set<ComponentName> updatedPersistent = controller.getPersistentActivities();
+        assertEquals(1, updatedPersistent.size());
+        assertTrue(updatedPersistent.contains(ACTIVITY_1));
+        verify(mTaskPanelHandler, times(1)).onApplicationChanged();
+    }
+
+    @Test
+    public void handles_returnsTrueIfPersistent() {
+        mPanelControllerMetadata = PanelControllerMetadata.builder("id").addConfiguration(
+                PanelControllerMetadata.PERSISTENT_ACTIVITY,
+                ACTIVITY_1.flattenToString()).build();
+        BaseTaskPanelController controller = new BaseTaskPanelController(mMockContext,
+                mPanelControllerMetadata, mPanelUtils);
+        assertTrue(controller.handles(ACTIVITY_1));
+    }
+
+    @Test
+    public void handles_returnsFalseIfNotPersistent() {
+        mPanelControllerMetadata = PanelControllerMetadata.builder("id").addConfiguration(
+                PanelControllerMetadata.PERSISTENT_ACTIVITY,
+                ACTIVITY_1.flattenToString()).build();
+
+        BaseTaskPanelController controller = new BaseTaskPanelController(mMockContext,
+                mPanelControllerMetadata, mPanelUtils);
+        assertFalse(controller.handles(ACTIVITY_2));
+    }
+
+    @Test
+    public void getDefaultComponent_returnsIntentWithDefaultComponent() {
+        when(mPanelControllerMetadata.getStringConfiguration(
+                PanelControllerMetadata.DEFAULT_COMPONENT)).thenReturn(
+                DEFAULT_ACTIVITY.flattenToString());
+        BaseTaskPanelController controller = new BaseTaskPanelController(mMockContext,
+                mPanelControllerMetadata, mPanelUtils);
+        Intent intent = controller.getDefaultComponent();
+        assertNotNull(intent);
+        assertEquals(DEFAULT_ACTIVITY, intent.getComponent());
+    }
+}
diff --git a/tests/utils/src/com/android/systemui/CarSysuiTestCase.java b/tests/utils/src/com/android/systemui/CarSysuiTestCase.java
index 60b2f70c..bf28cd35 100644
--- a/tests/utils/src/com/android/systemui/CarSysuiTestCase.java
+++ b/tests/utils/src/com/android/systemui/CarSysuiTestCase.java
@@ -27,6 +27,8 @@ import android.util.Singleton;
 import androidx.annotation.NonNull;
 import androidx.test.InstrumentationRegistry;
 
+import com.android.car.oem.tokens.Token;
+
 import org.junit.Rule;
 import org.mockito.Mockito;
 
@@ -43,7 +45,10 @@ public class CarSysuiTestCase extends SysuiTestCase {
 
         if (isRobolectricTest()) {
             // Manually associate a Display to context for Robolectric test. Similar to b/214297409
-            return context.createDefaultDisplayContext();
+            SysuiTestableContext displayContext = context.createDefaultDisplayContext();
+            Token.applyOemTokenStyle(displayContext);
+            displayContext.getTheme().applyStyle(R.style.CarSystemUIThemeOverlay, true);
+            return displayContext;
         } else {
             return context;
         }
diff --git a/tests/utils/src/com/android/systemui/ShellSyncExecutor.java b/tests/utils/src/com/android/systemui/ShellSyncExecutor.java
new file mode 100644
index 00000000..bcd80e8d
--- /dev/null
+++ b/tests/utils/src/com/android/systemui/ShellSyncExecutor.java
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
+
+package com.android.systemui;
+
+import com.android.wm.shell.common.ShellExecutor;
+
+/**
+ * And executor that just executes everything synchronously.
+ */
+public class ShellSyncExecutor implements ShellExecutor {
+    @Override
+    public void execute(Runnable runnable) {
+        runnable.run();
+    }
+
+    @Override
+    public void executeDelayed(Runnable runnable, long delayMillis) {
+        runnable.run();
+    }
+
+    @Override
+    public void removeCallbacks(Runnable runnable) {
+    }
+
+    @Override
+    public boolean hasCallback(Runnable runnable) {
+        return false;
+    }
+}
```

