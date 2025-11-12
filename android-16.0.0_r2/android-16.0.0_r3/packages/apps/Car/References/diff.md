```diff
diff --git a/scalable-ui/codelab/OnePanelRRO/Android.bp b/scalable-ui/codelab/OnePanelRRO/Android.bp
new file mode 100644
index 0000000..f5c165f
--- /dev/null
+++ b/scalable-ui/codelab/OnePanelRRO/Android.bp
@@ -0,0 +1,28 @@
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
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+// CarSystemUI scalableUI configs
+runtime_resource_overlay {
+    name: "OnePanelRRO",
+    resource_dirs: ["res"],
+    certificate: "platform",
+    manifest: "AndroidManifest.xml",
+    system_ext_specific: true,
+}
diff --git a/scalable-ui/codelab/OnePanelRRO/AndroidManifest.xml b/scalable-ui/codelab/OnePanelRRO/AndroidManifest.xml
new file mode 100644
index 0000000..3f52455
--- /dev/null
+++ b/scalable-ui/codelab/OnePanelRRO/AndroidManifest.xml
@@ -0,0 +1,25 @@
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.systemui.rro.scalableUI.onePanel.codelab">
+    <application android:hasCode="false" />
+    <!-- priority need to be higher than CarSystemUIDewdUIRRO -->
+    <overlay
+        android:targetPackage="com.android.systemui"
+        android:isStatic="false"
+        android:priority="111" />
+</manifest>
diff --git a/scalable-ui/codelab/OnePanelRRO/res/values/config.xml b/scalable-ui/codelab/OnePanelRRO/res/values/config.xml
new file mode 100644
index 0000000..2ed4e8d
--- /dev/null
+++ b/scalable-ui/codelab/OnePanelRRO/res/values/config.xml
@@ -0,0 +1,26 @@
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
+<resources>
+    <bool name="config_enableScalableUI" translatable="false">true</bool>
+    <bool name="config_enableClearBackStack" translatable="false">false</bool>
+    <string name="system_bar_app_drawer_intent" translatable="false">intent:#Intent;action=com.android.car.carlauncher.ACTION_APP_GRID;package=com.android.car.portraitlauncher;launchFlags=0x24000000;end</string>
+
+    <array name="window_states">
+        <item>@xml/app_panel</item>
+    </array>
+</resources>
diff --git a/scalable-ui/codelab/OnePanelRRO/res/values/dimens.xml b/scalable-ui/codelab/OnePanelRRO/res/values/dimens.xml
new file mode 100644
index 0000000..ac852b5
--- /dev/null
+++ b/scalable-ui/codelab/OnePanelRRO/res/values/dimens.xml
@@ -0,0 +1,50 @@
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
+<resources xmlns:tools="http://schemas.android.com/tools" tools:ignore="MissingDefaultResource,PxUsage">
+    <dimen name="screen_height">2048px</dimen>
+
+    <dimen name="top_bar_bottom">80px</dimen>
+
+    <dimen name="bottom_bar_top">1836px</dimen>
+    <dimen name="bottom_bar_bottom">1920px</dimen>
+
+    <dimen name="app_grid_drawer_bottom">@dimen/contextual_bar_top</dimen>
+    <dimen name="app_grid_drawer_height">749px</dimen>
+
+    <dimen name="map_top">0px</dimen>
+    <dimen name="map_height">1479px</dimen>
+
+    <dimen name="contextual_bar_top">1428px</dimen>
+    <dimen name="contextual_bar_bottom">1836px</dimen>
+    <dimen name="contextual_bar_height">408px</dimen>
+
+    <dimen name="app_immersive_top">@dimen/top_bar_bottom</dimen>
+    <dimen name="app_immersive_height">1712px</dimen>
+    <dimen name="app_bottom">@dimen/contextual_bar_top</dimen>
+    <dimen name="app_height">749px</dimen>
+
+    <dimen name="assistant_left">0px</dimen>
+    <dimen name="assistant_right">1080px</dimen>
+    <dimen name="assistant_top">0px</dimen>
+    <dimen name="assistant_height">1920px</dimen>
+
+    <dimen name="calm_mode_left">0px</dimen>
+    <dimen name="calm_mode_top">0px</dimen>
+    <dimen name="calm_mode_height">1836px</dimen>
+
+    <dimen name="safe_bounds_open_top">600px</dimen>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/OnePanelRRO/res/values/integers.xml b/scalable-ui/codelab/OnePanelRRO/res/values/integers.xml
new file mode 100644
index 0000000..607de04
--- /dev/null
+++ b/scalable-ui/codelab/OnePanelRRO/res/values/integers.xml
@@ -0,0 +1,20 @@
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
+<resources>
+    <integer name="app_panel_layer">50</integer>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/OnePanelRRO/res/values/strings.xml b/scalable-ui/codelab/OnePanelRRO/res/values/strings.xml
new file mode 100644
index 0000000..717a708
--- /dev/null
+++ b/scalable-ui/codelab/OnePanelRRO/res/values/strings.xml
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
+<resources>
+    <string name="default_config">DEFAULT</string>
+</resources>
diff --git a/scalable-ui/codelab/OnePanelRRO/res/xml/app_panel.xml b/scalable-ui/codelab/OnePanelRRO/res/xml/app_panel.xml
new file mode 100644
index 0000000..a3e0513
--- /dev/null
+++ b/scalable-ui/codelab/OnePanelRRO/res/xml/app_panel.xml
@@ -0,0 +1,34 @@
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
+<Panel id="app_panel" defaultVariant="@id/closed" role="@string/default_config" displayId="0">
+    <Variant id="@+id/opened">
+        <Layer layer="@integer/app_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Alpha alpha="1.0" />
+        <Bounds left="0" top="0" width="100%" height="100%" />
+    </Variant>
+    <Variant id="@+id/closed">
+        <Layer layer="@integer/app_panel_layer"/>
+        <Alpha alpha="0.0" />
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/screen_height" width="100%" height="100%" />
+    </Variant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/opened"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/Android.bp b/scalable-ui/codelab/SplitPanelHorzRRO/Android.bp
new file mode 100644
index 0000000..27a2353
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/Android.bp
@@ -0,0 +1,28 @@
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
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+// CarSystemUI scalableUI configs
+runtime_resource_overlay {
+    name: "SplitPanelHorzRRO",
+    resource_dirs: ["res"],
+    certificate: "platform",
+    manifest: "AndroidManifest.xml",
+    system_ext_specific: true,
+}
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/AndroidManifest.xml b/scalable-ui/codelab/SplitPanelHorzRRO/AndroidManifest.xml
new file mode 100644
index 0000000..d2c4c86
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/AndroidManifest.xml
@@ -0,0 +1,25 @@
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.systemui.rro.scalableUI.splitPanel.horz.codelab">
+    <application android:hasCode="false" />
+    <!-- priority need to be higher than CarSystemUIDewdUIRRO -->
+    <overlay
+        android:targetPackage="com.android.systemui"
+        android:isStatic="false"
+        android:priority="111" />
+</manifest>
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/drawable/grip_bar_background.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/drawable/grip_bar_background.xml
new file mode 100644
index 0000000..9eb1f32
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/drawable/grip_bar_background.xml
@@ -0,0 +1,41 @@
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
+<!--
+  The <inset> drawable is used to create margins around the inner shape.
+  This makes the drawable appear smaller than the View it's applied to,
+  with transparent space filling the inset area.
+-->
+<inset xmlns:android="http://schemas.android.com/apk/res/android"
+    android:insetLeft="16dp"
+    android:insetTop="0dp"
+    android:insetRight="16dp"
+    android:insetBottom="0dp">
+
+    <!-- This is the visible part of the drawable -->
+    <shape android:shape="rectangle">
+        <!-- The color of the grip bar -->
+        <solid android:color="#44464E"/>
+        <!--
+          The corner radius for the grip bar.
+          Using android:radius is a shorthand for setting all four corners
+          to the same value.
+        -->
+        <corners android:radius="16dp" />
+    </shape>
+
+</inset>
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/drawable/nav_bar_background.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/drawable/nav_bar_background.xml
new file mode 100644
index 0000000..e83bcba
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/drawable/nav_bar_background.xml
@@ -0,0 +1,18 @@
+<?xml version='1.0' encoding='UTF-8'?>
+<!-- Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <solid android:color="#f00" />
+</shape>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/drawable/status_bar_background.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/drawable/status_bar_background.xml
new file mode 100644
index 0000000..3960235
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/drawable/status_bar_background.xml
@@ -0,0 +1,18 @@
+<?xml version='1.0' encoding='UTF-8'?>
+<!-- Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <solid android:color="#000" />
+</shape>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/values/colors.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/values/colors.xml
new file mode 100644
index 0000000..5ec02f2
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/values/colors.xml
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
+  ~ limitations under the License
+  -->
+<resources xmlns:android="http://schemas.android.com/apk/res/android">
+    <color name="overlay_panel_bg_color">#333333</color>
+</resources>
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/values/config.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/values/config.xml
new file mode 100644
index 0000000..9fb37d4
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/values/config.xml
@@ -0,0 +1,36 @@
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
+<resources>
+    <bool name="config_enableScalableUI" translatable="false">true</bool>
+    <bool name="config_enableClearBackStack" translatable="false">false</bool>
+    <string name="system_bar_app_drawer_intent" translatable="false">intent:#Intent;action=com.android.car.carlauncher.ACTION_APP_GRID;package=com.android.car.portraitlauncher;launchFlags=0x24000000;end</string>
+
+    <array name="window_states">
+        <item>@xml/app_panel</item>
+        <item>@xml/map_panel</item>
+        <item>@xml/decor_grip_bar_split_task</item>
+        <item>@xml/decor_split_nav_overlay</item>
+        <item>@xml/decor_split_app_overlay</item>
+    </array>
+
+    <string-array name="config_default_activities" translatable="false">
+        <item>paintbooth_panel;com.android.car.ui.paintbooth/com.android.car.ui.paintbooth.MainActivity</item>
+        <item>map_panel;com.android.car.portraitlauncher/.homeactivities.BackgroundPanelBaseActivity</item>
+        <item>kitchen_sink_panel;com.google.android.car.kitchensink/com.google.android.car.kitchensink.KitchenSinkActivity</item>
+    </string-array>
+</resources>
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/values/dimens.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/values/dimens.xml
new file mode 100644
index 0000000..79ce9c8
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/values/dimens.xml
@@ -0,0 +1,45 @@
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
+<resources xmlns:tools="http://schemas.android.com/tools"
+    tools:ignore="MissingDefaultResource,PxUsage">
+    <dimen name="screen_width">2560px</dimen>
+    <dimen name="screen_height">1600px</dimen>
+
+    <dimen name="top_bar_bottom">71px</dimen>
+
+    <dimen name="bottom_bar_top">1450px</dimen>
+    <dimen name="bottom_bar_bottom">2560px</dimen>
+
+    <dimen name="map_top">@dimen/top_bar_bottom</dimen>
+    <dimen name="map_left">1300px</dimen>
+    <dimen name="map_bottom">@dimen/bottom_bar_top</dimen>
+    <dimen name="map_right">2544px</dimen>
+
+    <dimen name="grip_bar_split_task_left">1260px</dimen>
+    <dimen name="grip_bar_split_task_top">690px</dimen>
+    <dimen name="grip_bar_split_task_right">1300px</dimen>
+    <dimen name="grip_bar_split_task_bottom">890px</dimen>
+
+    <dimen name="corner_radius">36dp</dimen>
+    <dimen name="drag_corner_radius">36dp</dimen>
+
+    <dimen name="app_right">1260px</dimen>
+
+    <dimen name="safe_bounds_open_top">1100px</dimen>
+    <dimen name="safe_bounds_close_top">2156px</dimen>
+    <dimen name="safe_bounds_close_bottom">2837px</dimen>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/values/integers.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/values/integers.xml
new file mode 100644
index 0000000..f2ca264
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/values/integers.xml
@@ -0,0 +1,23 @@
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
+<resources>
+    <integer name="map_panel_layer">2</integer>
+    <integer name="app_panel_layer">50</integer>
+    <integer name="decor_vail_overlay_panel_layer">101</integer>
+    <integer name="decor_grip_bar_panel_layer">102</integer>
+</resources>
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/values/strings.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/values/strings.xml
new file mode 100644
index 0000000..aea9c76
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/values/strings.xml
@@ -0,0 +1,42 @@
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
+<resources>
+    <string name="appgrid_componentName" translatable="false">com.android.car.portraitlauncher/com.android.car.carlauncher.AppGrcom.android.car.portraitlauncher/com.android.car.carlauncher.AppGridActivity</string>
+    <string name="kitchen_sink_componentName" translatable="false">com.google.android.car.kitchensink/com.google.android.car.kitchensink.KitchenSinkActivity</string>
+    <string name="paintbooth_componentName" translatable="false">com.android.car.ui.paintbooth/com.android.car.ui.paintbooth.MainActivity</string>
+    <string name="themeplayground_componentName" translatable="false">com.android.car.themeplayground/com.android.car.themeplayground.TextSamples</string>
+    <string name="contextual_bar_component" translatable="false">com.android.car.portraitlauncher/com.android.car.carlauncher.ControlBarActivity</string>
+    <string name="calmMode_componentName">com.android.car.portraitlauncher/com.android.car.portraitlauncher.calmmode.PortraitCalmModeActivity</string>
+    <string name="default_config">DEFAULT</string>
+    <string name="overlay">overlay</string>
+
+    <string-array name="nav_components" translatable="false">
+        <item>com.google.android.apps.maps/com.google.android.maps.MapsActivity</item>
+    </string-array>
+
+    <string-array name="assistant_components" translatable="false">
+        <item>com.google.android.carassistant/com.google.android.libraries.assistant.auto.tng.assistant.ui.activity.AutoAssistantActivity</item>
+        <item>com.google.android.carassistant/com.google.android.apps.gsa.binaries.auto.app.voiceplate.VoicePlateActivity</item>
+    </string-array>
+
+    <string name="config_appGridComponentName">@string/appgrid_componentName</string>
+
+    <string name="task_switch_grid_bar_provider">task_switch_grid_bar_provider</string>
+    <string name="decor_split_grip_bar_provider">decor_split_grip_bar_provider</string>
+    <string name="decor_split_nav_overlay_panel_provider">decor_split_nav_overlay_panel_provider</string>
+    <string name="decor_split_app_overlay_panel_provider">decor_split_app_overlay_panel_provider</string>
+</resources>
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/app_panel.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/app_panel.xml
new file mode 100644
index 0000000..f1f81f5
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/app_panel.xml
@@ -0,0 +1,70 @@
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
+<Panel id="app_panel" defaultVariant="@id/closed" role="@string/default_config"  displayId="0">
+    <Variant id="@+id/base">
+        <Corner radius="@dimen/corner_radius"/>
+        <Visibility isVisible="true"/>
+        <Layer layer="@integer/app_panel_layer"/>
+    </Variant>
+    <Variant id="@+id/left_opened" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Corner radius="@dimen/corner_radius"/>
+        <Bounds left="16" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="@dimen/app_right" />
+        <SafeBounds
+            bottom="@dimen/bottom_bar_top"
+            left="70"
+            top="@dimen/top_bar_bottom"
+            right="@dimen/app_right" />
+    </Variant>
+    <Variant id="@+id/opened_full" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Corner radius="@dimen/corner_radius"/>
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="2520" />
+        <SafeBounds
+            bottom="@dimen/bottom_bar_top"
+            left="70"
+            top="@dimen/top_bar_bottom"
+            right="@dimen/app_right" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="0" left="-1260"/>
+        <SafeBounds
+            bottom="@dimen/bottom_bar_top"
+            width="945"
+            top="@dimen/top_bar_bottom"
+            right="0" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/closed" />
+        <KeyFrame frame="50" variant="@id/left_opened" />
+        <KeyFrame frame="100" variant="@id/opened_full" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" fromVariant="@id/closed" toVariant="@id/left_opened"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" fromVariant="@id/left_opened" toVariant="@id/left_opened"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" fromVariant="@id/opened_full" toVariant="@id/opened_full"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=map_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" toVariant="@id/closed"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" toVariant="@id/left_opened"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" onEventTokens="direction=noChange" toVariant="@id/opened_full" />
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=decor_split_app_overlay;panelToVariantId=opened_full" toVariant="@id/opened_full" duration="0"/>
+        <Transition onEvent="_User_DragEvent_split_decrease" toVariant="@id/drag"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_grib_bar_split_controller.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_grib_bar_split_controller.xml
new file mode 100644
index 0000000..9a7a8ed
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_grib_bar_split_controller.xml
@@ -0,0 +1,29 @@
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
+<Controller id="drag_split_task_grip_controller">
+    <Config key="ControllerName" value="com.android.systemui.car.wm.scalableui.view.GripBarViewController"/>
+    <Config key="View" value="com.android.systemui.car.wm.scalableui.view.GripBar"/>
+    <Config key="EventId" value="_User_DragEvent_split" />
+    <Config key="dragDecreaseEventId" value="_User_DragEvent_split_decrease" />
+    <Config key="dragIncreaseEventId" value="_User_DragEvent_split_increase" />
+    <Config key="Orientation" value="1" />
+    <Config key="SnapThreadhold" value="5"/>
+    <BreakPoints>
+        <BreakPoint point="40" eventId="_Drag_TaskSplitEvent_f0" />
+        <BreakPoint point="1280" eventId="_Drag_TaskSplitEvent_f50" />
+        <BreakPoint point="2520" eventId="_Drag_TaskSplitEvent_f100" />
+    </BreakPoints>
+</Controller>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_grip_bar_split_task.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_grip_bar_split_task.xml
new file mode 100644
index 0000000..96e94ce
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_grip_bar_split_task.xml
@@ -0,0 +1,58 @@
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
+<Panel id="decor_grip_bar_split_task" defaultVariant="@id/closed" role="@string/decor_split_grip_bar_provider" controller="@xml/decor_grib_bar_split_controller">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/decor_grip_bar_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Corner radius="@dimen/drag_corner_radius"/>
+    </Variant>
+
+    <Variant id="@+id/opened_left" parent="@id/base">
+        <Bounds top="@dimen/grip_bar_split_task_top" left="0" bottom="@dimen/grip_bar_split_task_bottom" right="40" />
+    </Variant>
+    <Variant id="@+id/opened_center" parent="@id/base">
+        <Bounds top="@dimen/grip_bar_split_task_top" left="@dimen/grip_bar_split_task_left" bottom="@dimen/grip_bar_split_task_bottom" right="@dimen/grip_bar_split_task_right" />
+    </Variant>
+    <Variant id="@+id/opened_right" parent="@id/base">
+        <Bounds top="@dimen/grip_bar_split_task_top" left="2520" bottom="@dimen/grip_bar_split_task_bottom" right="2560" />
+    </Variant>
+
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="@dimen/grip_bar_split_task_left" top="@dimen/bottom_bar_bottom" right="@dimen/grip_bar_split_task_right" height="100%" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/opened_left" />
+        <KeyFrame frame="100" variant="@id/opened_right" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/opened_center"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=map_panel" toVariant="@id/opened_left"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/opened_left"/>
+        <Transition onEvent="_System_EnterSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_ExitSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="close_app_grid" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_split_increase"  toVariant="@id/drag"/>
+        <Transition onEvent="_User_DragEvent_split_decrease"  toVariant="@id/drag"/>
+
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" toVariant="@id/opened_left"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" toVariant="@id/opened_center"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" toVariant="@id/opened_right"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_split_app_overlay.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_split_app_overlay.xml
new file mode 100644
index 0000000..e1d374a
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_split_app_overlay.xml
@@ -0,0 +1,62 @@
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
+<Panel id="decor_split_app_overlay" defaultVariant="@id/closed" role="@string/decor_split_app_overlay_panel_provider" controller="@xml/decor_split_app_overlay_controller">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/decor_vail_overlay_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Corner radius="@dimen/drag_corner_radius"/>
+    </Variant>
+
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" width="@dimen/app_right" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_0" parent="@id/base">
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="0" />
+    </Variant>
+    <Variant id="@+id/drag_frame_100" parent="@id/base">
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="2520" />
+    </Variant>
+
+    <Variant id="@+id/opened_full" parent="@id/base">
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="2520" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_frame_0" />
+        <KeyFrame frame="100" variant="@id/drag_frame_100" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_EnterSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_ExitSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="close_app_grid" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_split_increase" toVariant="@id/drag"/>
+        <Transition onEvent="_User_DragEvent_split_decrease" toVariant="@id/closed"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" onEventTokens="direction=increase" toVariant="@id/closed"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" onEventTokens="direction=increase" toVariant="@id/opened_full"/>
+
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=map_panel;panelToVariantId=drag_frame_100" toVariant="@id/closed" duration="0"/>
+
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" onEventTokens="direction=noChange" toVariant="@id/closed" duration="0"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" onEventTokens="direction=noChange" toVariant="@id/closed" />
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" onEventTokens="direction=noChange" toVariant="@id/closed" duration="0"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_split_app_overlay_controller.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_split_app_overlay_controller.xml
new file mode 100644
index 0000000..0194ea1
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_split_app_overlay_controller.xml
@@ -0,0 +1,20 @@
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
+<Controller id="decor_split_app_overlay_controller">
+    <Config key="ControllerName" value="com.android.systemui.car.wm.scalableui.view.PanelOverlayController"/>
+    <Config key="View" value="com.android.systemui.car.wm.scalableui.view.PanelOverlay"/>
+    <Config key="overlayPanelId" value="app_panel" />
+</Controller>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_split_nav_overlay.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_split_nav_overlay.xml
new file mode 100644
index 0000000..9d47fcb
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_split_nav_overlay.xml
@@ -0,0 +1,64 @@
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
+<Panel id="decor_split_nav_overlay" defaultVariant="@id/closed_Center" role="@string/decor_split_nav_overlay_panel_provider" controller="@xml/decor_split_nav_overlay_controller">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/decor_vail_overlay_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Corner radius="@dimen/drag_corner_radius"/>
+    </Variant>
+
+    <Variant id="@+id/closed_Center" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="@dimen/map_left" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/map_bottom" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_0" parent="@id/base">
+        <Bounds left="40"  bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="@dimen/screen_width" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_100" parent="@id/base">
+        <Bounds left="@dimen/screen_width"  bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="@dimen/screen_width" />
+    </Variant>
+
+    <Variant id="@+id/opened" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/map_bottom" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_frame_0" />
+        <KeyFrame frame="100" variant="@id/drag_frame_100" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed_Center"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed_Center"/>
+        <Transition onEvent="_System_EnterSuwEvent" toVariant="@id/closed_Center"/>
+        <Transition onEvent="_System_ExitSuwEvent" toVariant="@id/closed_Center"/>
+        <Transition onEvent="close_app_grid" toVariant="@id/closed_Center"/>
+        <Transition onEvent="_User_DragEvent_split_decrease" toVariant="@id/drag"/>
+        <Transition onEvent="_User_DragEvent_split_increase" toVariant="@id/closed_Center"/>
+
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" onEventTokens="direction=decrease" toVariant="@id/opened"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" onEventTokens="direction=decrease" toVariant="@id/closed_Center"/>
+
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" onEventTokens="direction=noChange" toVariant="@id/closed_Center" duration="0"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" onEventTokens="direction=noChange" toVariant="@id/closed_Center"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" onEventTokens="direction=noChange" toVariant="@id/closed_Center" duration="0"/>
+    </Transitions>
+
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_split_nav_overlay_controller.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_split_nav_overlay_controller.xml
new file mode 100644
index 0000000..299a750
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/decor_split_nav_overlay_controller.xml
@@ -0,0 +1,20 @@
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
+<Controller id="decor_split_nav_overlay_controller">
+    <Config key="ControllerName" value="com.android.systemui.car.wm.scalableui.view.PanelOverlayController"/>
+    <Config key="View" value="com.android.systemui.car.wm.scalableui.view.PanelOverlay"/>
+    <Config key="overlayPanelId" value="map_panel" />
+</Controller>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/map_panel.xml b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/map_panel.xml
new file mode 100644
index 0000000..bc2083a
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelHorzRRO/res/xml/map_panel.xml
@@ -0,0 +1,51 @@
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
+<Panel id="map_panel" defaultVariant="@id/opened" role="@array/nav_components" displayId="0">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/map_panel_layer"/>
+        <Corner radius="@dimen/corner_radius"/>
+    </Variant>
+    <Variant id="@+id/opened" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Corner radius="@dimen/corner_radius"/>
+        <Bounds left="40" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/map_bottom" />
+    </Variant>
+    <Variant id="@+id/opened_split" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Corner radius="@dimen/corner_radius"/>
+        <Bounds left="@dimen/map_left" top="@dimen/map_top" right="2544" bottom="@dimen/map_bottom" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_100" parent="@id/base">
+        <Bounds left="2560" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" width="50%"  />
+        <Visibility isVisible="false"/>
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag_from_center" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/opened" />
+        <KeyFrame frame="100" variant="@id/drag_frame_100" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/opened"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=map_panel" toVariant="@id/opened"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=app_panel;panelToVariantId=left_opened" toVariant="@id/opened_split" duration="50"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=app_panel;panelToVariantId=opened_full" toVariant="@id/drag_frame_100" duration="0"/>
+        <Transition onEvent="_User_DragEvent_split_increase" toVariant="@id/drag_from_center"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" toVariant="@id/opened"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" toVariant="@id/opened_split" />
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/Android.bp b/scalable-ui/codelab/SplitPanelLandRRO/Android.bp
new file mode 100644
index 0000000..aadc609
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/Android.bp
@@ -0,0 +1,28 @@
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
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+// CarSystemUI scalableUI configs
+runtime_resource_overlay {
+    name: "SplitPanelLandRRO",
+    resource_dirs: ["res"],
+    certificate: "platform",
+    manifest: "AndroidManifest.xml",
+    system_ext_specific: true,
+}
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/AndroidManifest.xml b/scalable-ui/codelab/SplitPanelLandRRO/AndroidManifest.xml
new file mode 100644
index 0000000..c9219c0
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/AndroidManifest.xml
@@ -0,0 +1,25 @@
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.systemui.rro.scalableUI.splitLand.codelab">
+    <application android:hasCode="false" />
+    <!-- priority need to be higher than CarSystemUIDewdUIRRO -->
+    <overlay
+        android:targetPackage="com.android.systemui"
+        android:isStatic="false"
+        android:priority="111" />
+</manifest>
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/animator/fade_in.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/animator/fade_in.xml
new file mode 100644
index 0000000..3352f11
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/animator/fade_in.xml
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
+  ~ limitations under the License
+  -->
+<objectAnimator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:propertyName="alpha"
+    android:duration="2000"
+    android:valueTo="1"
+    android:valueType="floatType" />
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/animator/fade_out.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/animator/fade_out.xml
new file mode 100644
index 0000000..b2f2381
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/animator/fade_out.xml
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
+  ~ limitations under the License
+  -->
+<objectAnimator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:propertyName="alpha"
+    android:duration="300"
+    android:valueTo="0"
+    android:valueType="floatType" />
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/values/colors.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/values/colors.xml
new file mode 100644
index 0000000..a7382ad
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/values/colors.xml
@@ -0,0 +1,20 @@
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
+<resources xmlns:android="http://schemas.android.com/apk/res/android">
+    <color name="blur_background_color">#f00</color>
+    <color name="overlay_panel_bg_color">#5F6368</color>
+</resources>
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/values/config.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/values/config.xml
new file mode 100644
index 0000000..9fb37d4
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/values/config.xml
@@ -0,0 +1,36 @@
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
+<resources>
+    <bool name="config_enableScalableUI" translatable="false">true</bool>
+    <bool name="config_enableClearBackStack" translatable="false">false</bool>
+    <string name="system_bar_app_drawer_intent" translatable="false">intent:#Intent;action=com.android.car.carlauncher.ACTION_APP_GRID;package=com.android.car.portraitlauncher;launchFlags=0x24000000;end</string>
+
+    <array name="window_states">
+        <item>@xml/app_panel</item>
+        <item>@xml/map_panel</item>
+        <item>@xml/decor_grip_bar_split_task</item>
+        <item>@xml/decor_split_nav_overlay</item>
+        <item>@xml/decor_split_app_overlay</item>
+    </array>
+
+    <string-array name="config_default_activities" translatable="false">
+        <item>paintbooth_panel;com.android.car.ui.paintbooth/com.android.car.ui.paintbooth.MainActivity</item>
+        <item>map_panel;com.android.car.portraitlauncher/.homeactivities.BackgroundPanelBaseActivity</item>
+        <item>kitchen_sink_panel;com.google.android.car.kitchensink/com.google.android.car.kitchensink.KitchenSinkActivity</item>
+    </string-array>
+</resources>
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/values/dimens.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/values/dimens.xml
new file mode 100644
index 0000000..c98d76f
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/values/dimens.xml
@@ -0,0 +1,64 @@
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
+<resources xmlns:tools="http://schemas.android.com/tools" tools:ignore="MissingDefaultResource,PxUsage">
+    <dimen name="screen_width">2048px</dimen>
+    <dimen name="screen_height">1080px</dimen>
+
+    <dimen name="top_bar_bottom">67px</dimen>
+
+    <dimen name="bottom_bar_top">940px</dimen>
+    <dimen name="bottom_bar_bottom">1080px</dimen>
+
+    <dimen name="app_grid_drawer_width">749px</dimen>
+
+    <dimen name="map_top">@dimen/top_bar_bottom</dimen>
+    <dimen name="map_left">1033px</dimen>
+    <dimen name="map_bottom">@dimen/bottom_bar_top</dimen>
+    <dimen name="map_right">2048px</dimen>
+
+    <dimen name="split_center">1000px</dimen>
+
+    <dimen name="grip_bar_split_task_left">1019px</dimen>
+    <dimen name="grip_bar_split_task_top">300px</dimen>
+    <dimen name="grip_bar_split_task_right">1029px</dimen>
+    <dimen name="grip_bar_split_task_bottom">700px</dimen>
+
+    <dimen name="corner_radius">40dp</dimen>
+    <dimen name="drag_corner_radius">80dp</dimen>
+
+    <dimen name="app_right">1015px</dimen>
+
+    <dimen name="top_breakpoint_switch">350px</dimen>
+    <dimen name="bottom_breakpoint_switch">1400px</dimen>
+
+    <dimen name="top_breakpoint_split">400px</dimen>
+    <dimen name="bottom_breakpoint_split">1500px</dimen>
+
+    <dimen name="safe_bounds_open_top">1100px</dimen>
+    <dimen name="safe_bounds_close_top">2156px</dimen>
+    <dimen name="safe_bounds_close_bottom">2837px</dimen>
+
+    <dimen name="lower_grip_bar_switch_task_left">1350px</dimen>
+    <dimen name="lower_grip_bar_switch_task_top">300px</dimen>
+    <dimen name="lower_grip_bar_switch_task_right">1450px</dimen>
+    <dimen name="lower_grip_bar_switch_task_bottom">400px</dimen>
+
+    <dimen name="upper_grip_bar_switch_task_left">20px</dimen>
+    <dimen name="upper_grip_bar_switch_task_top">420px</dimen>
+    <dimen name="upper_grip_bar_switch_task_right">40px</dimen>
+    <dimen name="upper_grip_bar_switch_task_bottom">520px</dimen>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/values/integers.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/values/integers.xml
new file mode 100644
index 0000000..fff2b7a
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/values/integers.xml
@@ -0,0 +1,22 @@
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
+<resources>
+    <integer name="map_panel_layer">2</integer>
+    <integer name="app_panel_layer">50</integer>
+    <integer name="decor_vail_overlay_panel_layer">101</integer>
+</resources>
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/values/strings.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/values/strings.xml
new file mode 100644
index 0000000..2cd6f40
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/values/strings.xml
@@ -0,0 +1,42 @@
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
+<resources>
+    <string name="appgrid_componentName" translatable="false">com.android.car.portraitlauncher/com.android.car.carlauncher.AppGrcom.android.car.portraitlauncher/com.android.car.carlauncher.AppGridActivity</string>
+    <string name="kitchen_sink_componentName" translatable="false">com.google.android.car.kitchensink/com.google.android.car.kitchensink.KitchenSinkActivity</string>
+    <string name="paintbooth_componentName" translatable="false">com.android.car.ui.paintbooth/com.android.car.ui.paintbooth.MainActivity</string>
+    <string name="themeplayground_componentName" translatable="false">com.android.car.themeplayground/com.android.car.themeplayground.TextSamples</string>
+    <string name="contextual_bar_component" translatable="false">com.android.car.portraitlauncher/com.android.car.carlauncher.ControlBarActivity</string>
+    <string name="calmMode_componentName">com.android.car.portraitlauncher/com.android.car.portraitlauncher.calmmode.PortraitCalmModeActivity</string>
+    <string name="default_config">DEFAULT</string>
+    <string name="overlay">overlay</string>
+
+    <string-array name="nav_components" translatable="false">
+        <item>com.google.android.apps.maps/com.google.android.maps.MapsActivity</item>
+    </string-array>
+
+    <string-array name="assistant_components" translatable="false">
+        <item>com.google.android.carassistant/com.google.android.libraries.assistant.auto.tng.assistant.ui.activity.AutoAssistantActivity</item>
+        <item>com.google.android.carassistant/com.google.android.apps.gsa.binaries.auto.app.voiceplate.VoicePlateActivity</item>
+    </string-array>
+
+    <string name="config_appGridComponentName">@string/appgrid_componentName</string>
+
+    <string name="task_switch_grid_bar_provider">task_switch_grid_bar_provider</string>
+    <string name="decor_split_grip_bar_provider">decor_split_grip_bar_provider</string>
+    <string name="decor_split_nav_overlay_panel_provider">decor_split_nav_overlay_panel_provider</string>
+    <string name="decor_split_theme_overlay_panel_provider">decor_split_theme_overlay_panel_provider</string>
+</resources>
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/xml/app_panel.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/app_panel.xml
new file mode 100644
index 0000000..9f8b947
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/app_panel.xml
@@ -0,0 +1,84 @@
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
+<Panel id="app_panel" defaultVariant="@id/closed" role="@string/default_config"  displayId="0">
+    <Variant id="@+id/base">
+        <Corner radius="@dimen/corner_radius"/>
+        <Visibility isVisible="true"/>
+        <Layer layer="@integer/app_panel_layer"/>
+    </Variant>
+    <Variant id="@+id/left_opened" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" width="@dimen/app_right" />
+        <SafeBounds
+            bottom="@dimen/bottom_bar_top"
+            left="70"
+            top="@dimen/top_bar_bottom"
+            right="@dimen/app_right" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds right="0" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" width="@dimen/app_right" height="@dimen/app_grid_drawer_width" />
+        <SafeBounds
+            bottom="@dimen/bottom_bar_top"
+            width="945"
+            top="@dimen/top_bar_bottom"
+            right="0" />
+    </Variant>
+    <Variant id="@+id/drag_left_opened" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" width="@dimen/app_right" />
+        <SurfaceBounds right="0" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" width="@dimen/app_right" height="@dimen/app_grid_drawer_width" />
+    </Variant>
+
+
+    <Variant id="@+id/drag_frame_0" parent="@id/base">
+        <Bounds left="0" top="@dimen/top_bar_bottom" right="515" bottom="@dimen/bottom_bar_top"/>
+        <SafeBounds
+            bottom="@dimen/bottom_bar_top"
+            left="40"
+            top="@dimen/top_bar_bottom"
+            right="515" />
+    </Variant>
+    <Variant id="@+id/drag_frame_50" parent="@id/base">
+        <Bounds left="0" top="@dimen/top_bar_bottom" right="1015" bottom="@dimen/bottom_bar_top" />
+        <SafeBounds
+            bottom="@dimen/bottom_bar_top"
+            left="70"
+            top="@dimen/top_bar_bottom"
+            right="1015" />
+    </Variant>
+    <Variant id="@+id/drag_frame_100" parent="@id/base">
+        <Bounds left="0" top="@dimen/top_bar_bottom" right="1515" bottom="@dimen/bottom_bar_top"/>
+        <SafeBounds
+            bottom="@dimen/bottom_bar_top"
+            left="90"
+            top="@dimen/top_bar_bottom"
+            right="1015" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_left_opened" />
+        <KeyFrame frame="100" variant="@id/left_opened" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/left_opened"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" toVariant="@id/drag_frame_0"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" toVariant="@id/drag_frame_50"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" toVariant="@id/drag_frame_100"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_grib_bar_split_controller.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_grib_bar_split_controller.xml
new file mode 100644
index 0000000..c50ec65
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_grib_bar_split_controller.xml
@@ -0,0 +1,29 @@
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
+<Controller id="drag_split_task_grip_controller">
+    <Config key="ControllerName" value="com.android.systemui.car.wm.scalableui.view.GripBarViewController"/>
+    <Config key="View" value="com.android.systemui.car.wm.scalableui.view.GripBar"/>
+    <Config key="EventId" value="_User_DragEvent_split" />
+    <Config key="dragDecreaseEventId" value="_User_DragEvent_split_decrease" />
+    <Config key="dragIncreaseEventId" value="_User_DragEvent_split_increase" />
+    <Config key="Orientation" value="1" />
+    <Config key="SnapThreadhold" value="5"/>
+    <BreakPoints>
+        <BreakPoint point="0" eventId="_Drag_TaskSplitEvent_f0" />
+        <BreakPoint point="1024" eventId="_Drag_TaskSplitEvent_f50" />
+        <BreakPoint point="2048" eventId="_Drag_TaskSplitEvent_f100" />
+    </BreakPoints>
+</Controller>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_grip_bar_split_task.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_grip_bar_split_task.xml
new file mode 100644
index 0000000..416496b
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_grip_bar_split_task.xml
@@ -0,0 +1,64 @@
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
+<Panel id="decor_grip_bar_split_task" defaultVariant="@id/closed" role="@string/decor_split_grip_bar_provider" controller="@xml/decor_grib_bar_split_controller">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/decor_vail_overlay_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Corner radius="@dimen/drag_corner_radius"/>
+    </Variant>
+
+    <Variant id="@+id/opened_left" parent="@id/base">
+        <Bounds top="300" left="519" bottom="700" right="529" />
+    </Variant>
+    <Variant id="@+id/opened_center" parent="@id/base">
+        <Bounds top="300" left="1015" bottom="700" right="1035" />
+    </Variant>
+    <Variant id="@+id/opened_right" parent="@id/base">
+        <Bounds top="300" left="1519" bottom="700" right="1529" />
+    </Variant>
+
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="@dimen/grip_bar_split_task_left" top="@dimen/bottom_bar_bottom" right="@dimen/grip_bar_split_task_right" height="100%" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_0" parent="@id/base">
+        <Bounds top="300" left="-10" bottom="700" right="0" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_100" parent="@id/base">
+        <Bounds top="300" left="2048" bottom="700" right="2058" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_frame_0" />
+        <KeyFrame frame="100" variant="@id/drag_frame_100" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/opened_center"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_EnterSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_ExitSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="close_app_grid" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_split"  toVariant="@id/drag"/>
+
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" toVariant="@id/opened_left"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" toVariant="@id/opened_center"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" toVariant="@id/opened_right"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_split_app_overlay.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_split_app_overlay.xml
new file mode 100644
index 0000000..8d02862
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_split_app_overlay.xml
@@ -0,0 +1,54 @@
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
+<Panel id="decor_split_theme_overlay" defaultVariant="@id/closed" role="@string/decor_split_theme_overlay_panel_provider" controller="@xml/decor_split_app_overlay_controller">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/decor_vail_overlay_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Corner radius="@dimen/drag_corner_radius"/>
+    </Variant>
+
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="10" top="@dimen/bottom_bar_bottom" width="20" height="100" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_0" parent="@id/base">
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="0" />
+    </Variant>
+    <Variant id="@+id/drag_frame_100" parent="@id/base">
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="2048" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_frame_0" />
+        <KeyFrame frame="100" variant="@id/drag_frame_100" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_EnterSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_ExitSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="close_app_grid" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_split_increase" toVariant="@id/drag"/>
+        <Transition onEvent="_User_DragEvent_split_decrease" toVariant="@id/closed"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" toVariant="@id/closed"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" toVariant="@id/closed"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" toVariant="@id/closed"/>
+    </Transitions>
+
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_split_app_overlay_controller.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_split_app_overlay_controller.xml
new file mode 100644
index 0000000..ab1e5df
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_split_app_overlay_controller.xml
@@ -0,0 +1,20 @@
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
+<Controller id="decor_split_theme_overlay_controller">
+    <Config key="ControllerName" value="com.android.systemui.car.wm.scalableui.view.PanelOverlayController"/>
+    <Config key="View" value="com.android.systemui.car.wm.scalableui.view.PanelOverlay"/>
+    <Config key="overlayPanelId" value="app_panel" />
+</Controller>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_split_nav_overlay.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_split_nav_overlay.xml
new file mode 100644
index 0000000..387f384
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_split_nav_overlay.xml
@@ -0,0 +1,55 @@
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
+<Panel id="decor_split_nav_overlay" defaultVariant="@id/closed" role="@string/decor_split_nav_overlay_panel_provider" controller="@xml/decor_split_nav_overlay_controller">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/decor_vail_overlay_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Corner radius="@dimen/drag_corner_radius"/>
+    </Variant>
+
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="10" top="@dimen/bottom_bar_bottom" width="20" height="100" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_0" parent="@id/base">
+        <Bounds left="0"  bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="2048" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_100" parent="@id/base">
+        <Bounds left="2048"  bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="2048" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_frame_0" />
+        <KeyFrame frame="100" variant="@id/drag_frame_100" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_EnterSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_ExitSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="close_app_grid" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_split_decrease" toVariant="@id/drag"/>
+        <Transition onEvent="_User_DragEvent_split_increase" toVariant="@id/closed"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" toVariant="@id/closed"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" toVariant="@id/closed"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" toVariant="@id/closed"/>
+    </Transitions>
+
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_split_nav_overlay_controller.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_split_nav_overlay_controller.xml
new file mode 100644
index 0000000..299a750
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/decor_split_nav_overlay_controller.xml
@@ -0,0 +1,20 @@
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
+<Controller id="decor_split_nav_overlay_controller">
+    <Config key="ControllerName" value="com.android.systemui.car.wm.scalableui.view.PanelOverlayController"/>
+    <Config key="View" value="com.android.systemui.car.wm.scalableui.view.PanelOverlay"/>
+    <Config key="overlayPanelId" value="map_panel" />
+</Controller>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelLandRRO/res/xml/map_panel.xml b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/map_panel.xml
new file mode 100644
index 0000000..7283601
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelLandRRO/res/xml/map_panel.xml
@@ -0,0 +1,48 @@
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
+<Panel id="map_panel" defaultVariant="@id/opened" role="@array/nav_components" displayId="0">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/map_panel_layer"/>
+        <Corner radius="@dimen/corner_radius"/>
+    </Variant>
+    <Variant id="@+id/opened" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" top="@dimen/map_top" width="100%" bottom="@dimen/map_bottom" />
+    </Variant>
+    <Variant id="@+id/opened_split" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="@dimen/map_left" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/map_bottom" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/map_top" width="100%" height="100%" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_0" parent="@id/base">
+        <Bounds left="533" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="@dimen/map_right" />  </Variant>
+    <Variant id="@+id/drag_frame_50" parent="@id/base">
+        <Bounds left="1033" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="@dimen/map_right" />  </Variant>
+    <Variant id="@+id/drag_frame_100" parent="@id/base">
+        <Bounds left="1533" bottom="@dimen/bottom_bar_top" top="@dimen/top_bar_bottom" right="@dimen/map_right" /> </Variant>
+
+    <Transitions defaultInterpolator="@android:anim/bounce_interpolator" defaultDuration="700">
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/opened"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/opened_split"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" toVariant="@id/drag_frame_0"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" toVariant="@id/drag_frame_50"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" toVariant="@id/drag_frame_100"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/Android.bp b/scalable-ui/codelab/SplitPanelRRO/Android.bp
new file mode 100644
index 0000000..f451d98
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/Android.bp
@@ -0,0 +1,28 @@
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
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+// CarSystemUI scalableUI configs
+runtime_resource_overlay {
+    name: "SplitPanelRRO",
+    resource_dirs: ["res"],
+    certificate: "platform",
+    manifest: "AndroidManifest.xml",
+    system_ext_specific: true,
+}
diff --git a/scalable-ui/codelab/SplitPanelRRO/AndroidManifest.xml b/scalable-ui/codelab/SplitPanelRRO/AndroidManifest.xml
new file mode 100644
index 0000000..00a3ed9
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/AndroidManifest.xml
@@ -0,0 +1,25 @@
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.systemui.rro.scalableUI.splitPanel.codelab">
+    <application android:hasCode="false" />
+    <!-- priority need to be higher than CarSystemUIDewdUIRRO -->
+    <overlay
+        android:targetPackage="com.android.systemui"
+        android:isStatic="false"
+        android:priority="111" />
+</manifest>
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/animator/fade_in.xml b/scalable-ui/codelab/SplitPanelRRO/res/animator/fade_in.xml
new file mode 100644
index 0000000..3352f11
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/animator/fade_in.xml
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
+  ~ limitations under the License
+  -->
+<objectAnimator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:propertyName="alpha"
+    android:duration="2000"
+    android:valueTo="1"
+    android:valueType="floatType" />
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/animator/fade_out.xml b/scalable-ui/codelab/SplitPanelRRO/res/animator/fade_out.xml
new file mode 100644
index 0000000..b2f2381
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/animator/fade_out.xml
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
+  ~ limitations under the License
+  -->
+<objectAnimator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:propertyName="alpha"
+    android:duration="300"
+    android:valueTo="0"
+    android:valueType="floatType" />
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/drawable/grip_bar_background.xml b/scalable-ui/codelab/SplitPanelRRO/res/drawable/grip_bar_background.xml
new file mode 100644
index 0000000..b6d696a
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/drawable/grip_bar_background.xml
@@ -0,0 +1,41 @@
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
+<!--
+  The <inset> drawable is used to create margins around the inner shape.
+  This makes the drawable appear smaller than the View it's applied to,
+  with transparent space filling the inset area.
+-->
+<inset xmlns:android="http://schemas.android.com/apk/res/android"
+    android:insetLeft="0dp"
+    android:insetTop="16dp"
+    android:insetRight="0dp"
+    android:insetBottom="16dp">
+
+    <!-- This is the visible part of the drawable -->
+    <shape android:shape="rectangle">
+        <!-- The color of the grip bar -->
+        <solid android:color="#44464E"/>
+        <!--
+          The corner radius for the grip bar.
+          Using android:radius is a shorthand for setting all four corners
+          to the same value.
+        -->
+        <corners android:radius="16dp" />
+    </shape>
+
+</inset>
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/drawable/nav_bar_background.xml b/scalable-ui/codelab/SplitPanelRRO/res/drawable/nav_bar_background.xml
new file mode 100644
index 0000000..e83bcba
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/drawable/nav_bar_background.xml
@@ -0,0 +1,18 @@
+<?xml version='1.0' encoding='UTF-8'?>
+<!-- Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <solid android:color="#f00" />
+</shape>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/drawable/status_bar_background.xml b/scalable-ui/codelab/SplitPanelRRO/res/drawable/status_bar_background.xml
new file mode 100644
index 0000000..3960235
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/drawable/status_bar_background.xml
@@ -0,0 +1,18 @@
+<?xml version='1.0' encoding='UTF-8'?>
+<!-- Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <solid android:color="#000" />
+</shape>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/values-h2731dp/dimens.xml b/scalable-ui/codelab/SplitPanelRRO/res/values-h2731dp/dimens.xml
new file mode 100644
index 0000000..f08dc0a
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/values-h2731dp/dimens.xml
@@ -0,0 +1,60 @@
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
+<resources xmlns:tools="http://schemas.android.com/tools" tools:ignore="MissingDefaultResource,PxUsage">
+  <dimen name="screen_height">2560px</dimen>
+  <dimen name="screen_width">1600px</dimen>
+
+  <dimen name="top_bar_bottom">86px</dimen>
+
+  <dimen name="bottom_bar_top">2410px</dimen>
+  <dimen name="bottom_bar_bottom">2560px</dimen>
+
+  <dimen name="map_top">@dimen/top_bar_bottom</dimen>
+  <dimen name="map_right">1584px</dimen>
+
+  <dimen name="top_breakpoint_switch">420px</dimen>
+  <dimen name="bottom_breakpoint_switch">1720px</dimen>
+
+  <dimen name="app_height">1100px</dimen>
+  <dimen name="app_right">1584px</dimen>
+  <dimen name="split_bottom">1220px</dimen>
+
+  <dimen name="grip_bar_split_task_left_p0">700px</dimen>
+  <dimen name="grip_bar_split_task_top_p0">400px</dimen>
+  <dimen name="grip_bar_split_task_right_p0">900px</dimen>
+  <dimen name="grip_bar_split_task_bottom_p0">440px</dimen>
+
+  <dimen name="grip_bar_split_task_left_p1">700px</dimen>
+  <dimen name="grip_bar_split_task_top_p1">1050px</dimen>
+  <dimen name="grip_bar_split_task_right_p1">900px</dimen>
+  <dimen name="grip_bar_split_task_bottom_p1">1090px</dimen>
+
+  <dimen name="grip_bar_split_task_left_p2">700px</dimen>
+  <dimen name="grip_bar_split_task_top_p2">1700px</dimen>
+  <dimen name="grip_bar_split_task_right_p2">900px</dimen>
+  <dimen name="grip_bar_split_task_bottom_p2">1740px</dimen>
+
+  <dimen name="lower_grip_bar_switch_task_left">0px</dimen>
+  <dimen name="lower_grip_bar_switch_task_top">1700px</dimen>
+  <dimen name="lower_grip_bar_switch_task_right">45px</dimen>
+  <dimen name="lower_grip_bar_switch_task_bottom">2000px</dimen>
+
+  <dimen name="upper_grip_bar_switch_task_left">0px</dimen>
+  <dimen name="upper_grip_bar_switch_task_top">420px</dimen>
+  <dimen name="upper_grip_bar_switch_task_right">45px</dimen>
+  <dimen name="upper_grip_bar_switch_task_bottom">720px</dimen>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/values/colors.xml b/scalable-ui/codelab/SplitPanelRRO/res/values/colors.xml
new file mode 100644
index 0000000..5ec02f2
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/values/colors.xml
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
+  ~ limitations under the License
+  -->
+<resources xmlns:android="http://schemas.android.com/apk/res/android">
+    <color name="overlay_panel_bg_color">#333333</color>
+</resources>
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/values/config.xml b/scalable-ui/codelab/SplitPanelRRO/res/values/config.xml
new file mode 100644
index 0000000..8c5096b
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/values/config.xml
@@ -0,0 +1,41 @@
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
+<resources>
+    <bool name="config_enableScalableUI" translatable="false">true</bool>
+    <bool name="config_enableClearBackStack" translatable="false">false</bool>
+    <string name="system_bar_app_drawer_intent" translatable="false">intent:#Intent;action=com.android.car.carlauncher.ACTION_APP_GRID;package=com.android.car.portraitlauncher;launchFlags=0x24000000;end</string>
+
+    <array name="window_states">
+        <item>@xml/app_panel</item>
+        <item>@xml/map_panel</item>
+        <item>@xml/kitchen_sink_panel</item>
+        <item>@xml/paintbooth_panel</item>
+        <item>@xml/themeplayground_panel</item>
+        <item>@xml/decor_grip_bar_switch_task</item>
+        <item>@xml/decor_grip_bar_split_task</item>
+        <item>@xml/decor_split_nav_overlay</item>
+        <item>@xml/decor_split_theme_overlay</item>
+        <item>@xml/decor_frost_overlay</item>
+    </array>
+
+    <string-array name="config_default_activities" translatable="false">
+        <item>paintbooth_panel;com.android.car.ui.paintbooth/com.android.car.ui.paintbooth.MainActivity</item>
+        <item>map_panel;com.android.car.portraitlauncher/.homeactivities.BackgroundPanelBaseActivity</item>
+        <item>kitchen_sink_panel;com.google.android.car.kitchensink/com.google.android.car.kitchensink.KitchenSinkActivity</item>
+    </string-array>
+</resources>
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/values/dimens.xml b/scalable-ui/codelab/SplitPanelRRO/res/values/dimens.xml
new file mode 100644
index 0000000..45ad75c
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/values/dimens.xml
@@ -0,0 +1,78 @@
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
+<resources xmlns:tools="http://schemas.android.com/tools" tools:ignore="MissingDefaultResource,PxUsage">
+    <dimen name="screen_height">2048px</dimen>
+    <dimen name="screen_width">1080px</dimen>
+
+    <dimen name="top_bar_bottom">80px</dimen>
+
+    <dimen name="bottom_bar_top">1780px</dimen>
+    <dimen name="bottom_bar_bottom">1920px</dimen>
+
+    <dimen name="app_grid_drawer_height">749px</dimen>
+
+    <dimen name="map_top">@dimen/top_bar_bottom</dimen>
+    <dimen name="map_right">1080px</dimen>
+    <dimen name="map_bottom">@dimen/bottom_bar_top</dimen>
+    <dimen name="map_height">1479px</dimen>
+
+    <dimen name="split_bottom">1000px</dimen>
+
+    <dimen name="grip_bar_split_task_left_p0">300px</dimen>
+    <dimen name="grip_bar_split_task_top_p0">400px</dimen>
+    <dimen name="grip_bar_split_task_right_p0">700px</dimen>
+    <dimen name="grip_bar_split_task_bottom_p0">415px</dimen>
+
+    <dimen name="grip_bar_split_task_left_p1">300px</dimen>
+    <dimen name="grip_bar_split_task_top_p1">950px</dimen>
+    <dimen name="grip_bar_split_task_right_p1">700px</dimen>
+    <dimen name="grip_bar_split_task_bottom_p1">965px</dimen>
+
+    <dimen name="grip_bar_split_task_left_p2">300px</dimen>
+    <dimen name="grip_bar_split_task_top_p2">1500px</dimen>
+    <dimen name="grip_bar_split_task_right_p2">700px</dimen>
+    <dimen name="grip_bar_split_task_bottom_p2">1515px</dimen>
+
+    <dimen name="corner_radius">36dp</dimen>
+    <dimen name="drag_corner_radius">36dp</dimen>
+
+    <dimen name="app_immersive_top">@dimen/top_bar_bottom</dimen>
+    <dimen name="app_immersive_height">1712px</dimen>
+    <dimen name="app_height">749px</dimen>
+    <dimen name="app_right">1064px</dimen>
+
+    <dimen name="top_breakpoint_switch">350px</dimen>
+    <dimen name="bottom_breakpoint_switch">1400px</dimen>
+
+    <dimen name="top_breakpoint_split">400px</dimen>
+    <dimen name="bottom_breakpoint_split">1500px</dimen>
+
+    <dimen name="lower_grip_bar_switch_task_left">20px</dimen>
+    <dimen name="lower_grip_bar_switch_task_top">1350px</dimen>
+    <dimen name="lower_grip_bar_switch_task_right">40px</dimen>
+    <dimen name="lower_grip_bar_switch_task_bottom">1450px</dimen>
+
+    <dimen name="upper_grip_bar_switch_task_left">20px</dimen>
+    <dimen name="upper_grip_bar_switch_task_top">420px</dimen>
+    <dimen name="upper_grip_bar_switch_task_right">40px</dimen>
+    <dimen name="upper_grip_bar_switch_task_bottom">520px</dimen>
+
+    <dimen name="safe_bounds_open_top">1100px</dimen>
+    <dimen name="safe_bounds_close_top">2156px</dimen>
+    <dimen name="safe_bounds_close_bottom">2837px</dimen>
+
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/values/integers.xml b/scalable-ui/codelab/SplitPanelRRO/res/values/integers.xml
new file mode 100644
index 0000000..5da8b0d
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/values/integers.xml
@@ -0,0 +1,28 @@
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
+<resources>
+    <integer name="map_panel_layer">2</integer>
+    <integer name="frost_overlay_layer">40</integer>
+    <integer name="app_panel_layer">50</integer>
+    <integer name="app_grid_panel_layer">100</integer>
+    <integer name="paintbooth_panel_layer">100</integer>
+    <integer name="themeplayground_panel_layer">100</integer>
+    <integer name="decor_vail_overlay_panel_layer">101</integer>
+    <integer name="grip_bar_paintbooth_panel_layer">102</integer>
+    <integer name="assistant_panel_layer">200</integer>
+</resources>
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/values/strings.xml b/scalable-ui/codelab/SplitPanelRRO/res/values/strings.xml
new file mode 100644
index 0000000..6243f0c
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/values/strings.xml
@@ -0,0 +1,46 @@
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
+<resources>
+    <string name="appgrid_componentName" translatable="false">com.android.car.portraitlauncher/com.android.car.carlauncher.AppGrcom.android.car.portraitlauncher/com.android.car.carlauncher.AppGridActivity</string>
+    <string name="kitchen_sink_componentName" translatable="false">com.google.android.car.kitchensink/com.google.android.car.kitchensink.KitchenSinkActivity</string>
+    <string name="contextual_bar_component" translatable="false">com.android.car.portraitlauncher/com.android.car.carlauncher.ControlBarActivity</string>
+    <string name="calmMode_componentName">com.android.car.portraitlauncher/com.android.car.portraitlauncher.calmmode.PortraitCalmModeActivity</string>
+    <string name="default_config">DEFAULT</string>
+    <string name="overlay">overlay</string>
+
+    <string-array name="nav_components" translatable="false">
+        <item>com.google.android.apps.maps/com.google.android.maps.MapsActivity</item>
+    </string-array>
+
+    <string-array name="paintbooth_componentNames" translatable="false">
+        <item>com.android.car.ui.paintbooth/com.android.car.ui.paintbooth.MainActivity</item>
+        <item>com.android.car.ui.paintbooth/com.android.car.ui.paintbooth.overlays.OverlayActivity</item>
+    </string-array>
+    <string-array name="themeplayground_componentNames" translatable="false">
+        <item>com.android.car.media/com.android.car.media.MediaActivity</item>
+        <item>com.android.car.themeplayground/com.android.car.themeplayground.TextSamples</item>
+        <item>com.android.car.media/com.android.car.media.MediaDispatcherActivity</item>
+    </string-array>
+
+    <string name="config_appGridComponentName">@string/appgrid_componentName</string>
+
+    <string name="task_switch_grid_bar_provider">task_switch_grid_bar_provider</string>
+    <string name="decor_split_grip_bar_provider">decor_split_grip_bar_provider</string>
+    <string name="decor_split_nav_overlay_panel_provider">decor_split_nav_overlay_panel_provider</string>
+    <string name="decor_split_theme_overlay_panel_provider">decor_split_theme_overlay_panel_provider</string>
+    <string name="decor_frost_overlay_provider">decor_frost_overlay_provider</string>
+</resources>
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/app_panel.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/app_panel.xml
new file mode 100644
index 0000000..0bdbc2e
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/app_panel.xml
@@ -0,0 +1,49 @@
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
+<Panel id="app_panel" defaultVariant="@id/closed" role="@string/default_config" displayId="0">
+    <Variant id="@+id/base">
+        <Corner radius="@dimen/corner_radius"/>
+    </Variant>
+    <Variant id="@+id/opened" parent="@id/base">
+        <Layer layer="@integer/app_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Alpha alpha="1.0" />
+        <Bounds left="16" bottom="@dimen/bottom_bar_top" right="1584" height="@dimen/app_height" />
+        <SafeBounds
+            bottom="@dimen/bottom_bar_top"
+            left="0"
+            top="@dimen/safe_bounds_open_top"
+            width="100%" />
+    </Variant>
+    <Variant id="@+id/closed">
+        <Layer layer="@integer/app_panel_layer"/>
+        <Alpha alpha="0.0" />
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/screen_height" width="100%" height="@dimen/app_height" />
+        <SafeBounds
+        bottom="@dimen/safe_bounds_close_bottom"
+        left="0"
+        top="@dimen/safe_bounds_close_top"
+        width="100%" />
+    </Variant>
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/opened"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=themeplayground_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_frost_overlay.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_frost_overlay.xml
new file mode 100644
index 0000000..b6db816
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_frost_overlay.xml
@@ -0,0 +1,40 @@
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
+<Panel id="decor_frost_overlay" defaultVariant="@id/closed" role="@string/decor_frost_overlay_provider" controller="@xml/decor_frost_overlay_controller">
+    <Variant id="@+id/map_base">
+        <Layer layer="@integer/frost_overlay_layer"/>
+        <Corner radius="@dimen/corner_radius"/>
+    </Variant>
+    <Variant id="@+id/opened_frost" parent="@id/map_base">
+        <Visibility isVisible="true"/>
+        <Alpha alpha="1.0" />
+        <Bounds left="0" top="@dimen/map_top" right="@dimen/screen_width" bottom="@dimen/map_bottom" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/map_base">
+        <Visibility isVisible="false"/>
+        <Alpha alpha="0.1" />
+        <Bounds left="0" top="@dimen/map_top" width="100%" height="100%" />
+    </Variant>
+
+    <Transitions>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=map_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/opened_frost"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_top" toVariant="@id/closed"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_bottom" toVariant="@id/closed"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_frost_overlay_controller.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_frost_overlay_controller.xml
new file mode 100644
index 0000000..0fe6e07
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_frost_overlay_controller.xml
@@ -0,0 +1,21 @@
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
+<Controller id="decor_frost_overlay_controller">
+    <Config key="ControllerName" value="com.android.systemui.car.wm.scalableui.view.PanelOverlayController"/>
+    <Config key="View" value="com.android.systemui.car.wm.scalableui.view.PanelOverlay"/>
+    <Config key="overlayPanelId" value="map_panel" />
+    <Config key="backgroundColor" value="#46000000" />
+</Controller>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_grip_bar_split_task.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_grip_bar_split_task.xml
new file mode 100644
index 0000000..908da6f
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_grip_bar_split_task.xml
@@ -0,0 +1,64 @@
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
+<!-- TODO(b/409116725): migrate role to design compose friendly config. -->
+<Panel id="decor_grip_bar_split_task" defaultVariant="@id/closed" role="@string/decor_split_grip_bar_provider" controller="@xml/drag_split_task_grip_controller">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/grip_bar_paintbooth_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Corner radius="@dimen/drag_corner_radius"/>
+    </Variant>
+
+    <Variant id="@+id/opened" parent="@id/base">
+        <Bounds left="@dimen/grip_bar_split_task_left_p1" right="@dimen/grip_bar_split_task_right_p1" top="@dimen/grip_bar_split_task_top_p1" bottom="@dimen/grip_bar_split_task_bottom_p1" />
+    </Variant>
+
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="@dimen/grip_bar_split_task_left_p1" right="@dimen/grip_bar_split_task_right_p1" top="@dimen/grip_bar_split_task_top_p1" bottom="@dimen/grip_bar_split_task_bottom_p1" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_0" parent="@id/base">
+        <Bounds left="@dimen/grip_bar_split_task_left_p0" right="@dimen/grip_bar_split_task_right_p0" top="@dimen/grip_bar_split_task_top_p0" bottom="@dimen/grip_bar_split_task_bottom_p0" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_100" parent="@id/base">
+        <Bounds left="@dimen/grip_bar_split_task_left_p2" right="@dimen/grip_bar_split_task_right_p2" top="@dimen/grip_bar_split_task_top_p2" bottom="@dimen/grip_bar_split_task_bottom_p2" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_frame_0" />
+        <KeyFrame frame="50" variant="@id/opened" />
+        <KeyFrame frame="100" variant="@id/drag_frame_100" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=themeplayground_panel" toVariant="@id/opened"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_EnterSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_ExitSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="close_app_grid" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_split_decrease" toVariant="@id/drag"/>
+        <Transition onEvent="_User_DragEvent_split_increase" toVariant="@id/drag"/>
+
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" toVariant="@id/drag_frame_0"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" toVariant="@id/opened"/>
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" toVariant="@id/drag_frame_100"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_grip_bar_switch_task.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_grip_bar_switch_task.xml
new file mode 100644
index 0000000..6d79448
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_grip_bar_switch_task.xml
@@ -0,0 +1,65 @@
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
+<!-- TODO(b/409116725): migrate role to design compose friendly config. -->
+<Panel id="decor_grip_bar_switch_task" defaultVariant="@id/closed" role="@string/task_switch_grid_bar_provider" controller="@xml/drag_switch_task_grip_controller">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/grip_bar_paintbooth_panel_layer"/>
+        <Corner radius="@dimen/drag_corner_radius"/>
+    </Variant>
+
+    <Variant id="@+id/opened_bottom" parent="@id/base">
+        <Bounds left="@dimen/lower_grip_bar_switch_task_left" right="@dimen/lower_grip_bar_switch_task_right" top="@dimen/lower_grip_bar_switch_task_top" bottom="@dimen/lower_grip_bar_switch_task_bottom" />
+    </Variant>
+    <Variant id="@+id/opened_top" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="@dimen/upper_grip_bar_switch_task_left" right="@dimen/upper_grip_bar_switch_task_right" top="@dimen/upper_grip_bar_switch_task_top" bottom="@dimen/upper_grip_bar_switch_task_bottom" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="10" top="@dimen/bottom_bar_bottom" width="20" height="300" />
+    </Variant>
+
+    <Variant id="@+id/drag_switch" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="@dimen/upper_grip_bar_switch_task_left" right="@dimen/upper_grip_bar_switch_task_right" top="@dimen/upper_grip_bar_switch_task_top" bottom="@dimen/upper_grip_bar_switch_task_bottom" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_0" parent="@id/base">
+        <Bounds left="10" right="35" top="470" bottom="670" />
+    </Variant>
+    <Variant id="@+id/drag_frame_100" parent="@id/base">
+        <Bounds left="10" right="35" top="1750" bottom="1950" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_frame_0" />
+        <KeyFrame frame="100" variant="@id/drag_frame_100" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/opened_bottom"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_EnterSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_ExitSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="close_app_grid" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_switch"  toVariant="@id/drag"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_top" toVariant="@id/opened_top"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_bottom"  toVariant="@id/opened_bottom"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_split_nav_overlay.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_split_nav_overlay.xml
new file mode 100644
index 0000000..dc84cc6
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_split_nav_overlay.xml
@@ -0,0 +1,82 @@
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
+<!-- TODO(b/409116725): migrate role to design compose friendly config. -->
+<Panel id="decor_split_nav_overlay" defaultVariant="@id/closed" role="@string/decor_split_nav_overlay_panel_provider" controller="@xml/decor_split_nav_overlay_controller">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/decor_vail_overlay_panel_layer"/>
+        <Corner radius="@dimen/corner_radius"/>
+    </Variant>
+
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="16" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/grip_bar_split_task_top_p1" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_0" parent="@id/base">
+        <Bounds left="16" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/grip_bar_split_task_top_p0" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_50" parent="@id/base">
+        <Bounds left="16" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/grip_bar_split_task_top_p1" />  </Variant>
+
+    <Variant id="@+id/drag_frame_100" parent="@id/base">
+        <Bounds left="16" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/grip_bar_split_task_top_p2" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_frame_0" />
+        <KeyFrame frame="50" variant="@id/drag_frame_50" />
+        <KeyFrame frame="100" variant="@id/drag_frame_100" />
+    </KeyFrameVariant>
+
+    <Variant id="@+id/frame_0" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="16" top="80" right="@dimen/map_right" bottom="@dimen/grip_bar_split_task_top_p0" />  </Variant>
+    <Variant id="@+id/frame_50" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="16" top="80" right="@dimen/map_right" bottom="@dimen/grip_bar_split_task_top_p1" />  </Variant>
+    <Variant id="@+id/frame_100" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="16" top="80" right="@dimen/map_right" bottom="@dimen/grip_bar_split_task_top_p2" /> </Variant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=themeplayground_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_EnterSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_ExitSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="close_app_grid" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_split_decrease" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_split_increase" toVariant="@id/drag"/>
+        <Transition onEvent="_User_DragEvent_switch"  toVariant="@id/closed" duration="0"/>
+
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" onEventTokens="direction=increase" toVariant="@id/drag_frame_0" />
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" onEventTokens="direction=increase" toVariant="@id/drag_frame_50" />
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" onEventTokens="direction=increase" toVariant="@id/drag_frame_100" />
+
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=map_panel;panelToVariantId=drag_frame_0" toVariant="@id/closed" duration="5"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=map_panel;panelToVariantId=opened_split" toVariant="@id/closed" duration="5"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=map_panel;panelToVariantId=drag_frame_100" toVariant="@id/closed" duration="5"/>
+
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" onEventTokens="direction=noChange" fromVariant="@id/closed" toVariant="@id/closed" />
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" onEventTokens="direction=noChange" toVariant="@id/closed" />
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" onEventTokens="direction=noChange" toVariant="@id/closed" />
+    </Transitions>
+
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_split_nav_overlay_controller.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_split_nav_overlay_controller.xml
new file mode 100644
index 0000000..299a750
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_split_nav_overlay_controller.xml
@@ -0,0 +1,20 @@
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
+<Controller id="decor_split_nav_overlay_controller">
+    <Config key="ControllerName" value="com.android.systemui.car.wm.scalableui.view.PanelOverlayController"/>
+    <Config key="View" value="com.android.systemui.car.wm.scalableui.view.PanelOverlay"/>
+    <Config key="overlayPanelId" value="map_panel" />
+</Controller>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_split_theme_overlay.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_split_theme_overlay.xml
new file mode 100644
index 0000000..7bfc5f3
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_split_theme_overlay.xml
@@ -0,0 +1,84 @@
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
+<Panel id="decor_split_theme_overlay" defaultVariant="@id/closed" role="@string/decor_split_theme_overlay_panel_provider" controller="@xml/decor_split_theme_overlay_controller">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/decor_vail_overlay_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Corner radius="@dimen/corner_radius"/>
+    </Variant>
+
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="16" top="@dimen/grip_bar_split_task_bottom_p1" right="@dimen/app_right" bottom="@dimen/bottom_bar_top" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_0" parent="@id/base">
+        <Bounds left="16" top="@dimen/grip_bar_split_task_bottom_p0" right="@dimen/app_right" bottom="@dimen/bottom_bar_top" />
+    </Variant>
+    <Variant id="@+id/drag_frame_50" parent="@id/base">
+        <Bounds left="16" top="@dimen/grip_bar_split_task_bottom_p1" right="@dimen/app_right" bottom="@dimen/bottom_bar_top" />
+    </Variant>
+    <Variant id="@+id/drag_frame_100" parent="@id/base">
+        <Bounds left="16" top="@dimen/grip_bar_split_task_bottom_p2" right="@dimen/app_right" bottom="@dimen/bottom_bar_top" />
+    </Variant>
+
+    <Variant id="@+id/bottom_opened" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="16" top="@dimen/grip_bar_split_task_bottom_p1" right="@dimen/app_right" bottom="@dimen/bottom_bar_top" />
+    </Variant>
+
+    <Variant id="@+id/frame_0" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="16" top="@dimen/grip_bar_split_task_bottom_p0" right="@dimen/app_right" bottom="@dimen/bottom_bar_top" />
+    </Variant>
+    <Variant id="@+id/frame_100" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="16" top="@dimen/grip_bar_split_task_bottom_p2" right="@dimen/app_right" bottom="@dimen/bottom_bar_top" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_frame_0" />
+        <KeyFrame frame="50" variant="@id/drag_frame_50" />
+        <KeyFrame frame="100" variant="@id/drag_frame_100" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=themeplayground_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_EnterSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_ExitSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="close_app_grid" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_split_increase" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_split_decrease" toVariant="@id/drag"/>
+
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" onEventTokens="direction=decrease"  toVariant="@id/drag_frame_0"  />
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" onEventTokens="direction=decrease" toVariant="@id/drag_frame_50" />
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" onEventTokens="direction=decrease" toVariant="@id/drag_frame_100" />
+
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=themeplayground_panel;panelToVariantId=drag_frame_0" toVariant="@id/closed" duration="5"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=themeplayground_panel;panelToVariantId=bottom_opened" toVariant="@id/closed" duration="5"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=themeplayground_panel;panelToVariantId=drag_frame_100" toVariant="@id/closed" duration="5"/>
+
+        <Transition onEvent="_Drag_TaskSplitEvent_f0" onEventTokens="direction=noChange"  toVariant="@id/closed"  />
+        <Transition onEvent="_Drag_TaskSplitEvent_f50" onEventTokens="direction=noChange" toVariant="@id/closed"  />
+        <Transition onEvent="_Drag_TaskSplitEvent_f100" onEventTokens="direction=noChange" toVariant="@id/closed" />
+
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_split_theme_overlay_controller.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_split_theme_overlay_controller.xml
new file mode 100644
index 0000000..91077c9
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/decor_split_theme_overlay_controller.xml
@@ -0,0 +1,20 @@
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
+<Controller id="decor_split_theme_overlay_controller">
+    <Config key="ControllerName" value="com.android.systemui.car.wm.scalableui.view.PanelOverlayController"/>
+    <Config key="View" value="com.android.systemui.car.wm.scalableui.view.PanelOverlay"/>
+    <Config key="overlayPanelId" value="themeplayground_panel" />
+</Controller>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/drag_split_task_grip_controller.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/drag_split_task_grip_controller.xml
new file mode 100644
index 0000000..082da97
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/drag_split_task_grip_controller.xml
@@ -0,0 +1,29 @@
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
+<Controller id="drag_split_task_grip_controller">
+    <Config key="ControllerName" value="com.android.systemui.car.wm.scalableui.view.GripBarViewController"/>
+    <Config key="View" value="com.android.systemui.car.wm.scalableui.view.GripBar"/>
+    <Config key="EventId" value="_User_DragEvent_split" />
+    <Config key="dragDecreaseEventId" value="_User_DragEvent_split_decrease" />
+    <Config key="dragIncreaseEventId" value="_User_DragEvent_split_increase" />
+    <Config key="Orientation" value="0" />
+    <Config key="SnapThreadhold" value="5"/>
+    <BreakPoints>
+        <BreakPoint point="420" eventId="_Drag_TaskSplitEvent_f0" />
+        <BreakPoint point="1070" eventId="_Drag_TaskSplitEvent_f50" />
+        <BreakPoint point="1720" eventId="_Drag_TaskSplitEvent_f100" />
+    </BreakPoints>
+</Controller>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/drag_switch_task_grip_controller.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/drag_switch_task_grip_controller.xml
new file mode 100644
index 0000000..12cb98f
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/drag_switch_task_grip_controller.xml
@@ -0,0 +1,26 @@
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
+<Controller id="grip_bar_controller">
+    <Config key="ControllerName" value="com.android.systemui.car.wm.scalableui.view.GripBarViewController"/>
+    <Config key="View" value="com.android.systemui.car.wm.scalableui.view.GripBar"/>
+    <Config key="EventId" value="_User_DragEvent_switch" />
+    <Config key="Orientation" value="0" />
+    <Config key="SnapThreadhold" value="5"/>
+    <BreakPoints>
+        <BreakPoint point="@dimen/top_breakpoint_switch" eventId="_Drag_TaskSwitchEvent_top" />
+        <BreakPoint point="@dimen/bottom_breakpoint_switch" eventId="_Drag_TaskSwitchEvent_bottom" />
+    </BreakPoints>
+</Controller>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/kitchen_sink_panel.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/kitchen_sink_panel.xml
new file mode 100644
index 0000000..e84277c
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/kitchen_sink_panel.xml
@@ -0,0 +1,39 @@
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
+<Panel id="kitchen_sink_panel" defaultVariant="@id/closed" role="@string/kitchen_sink_componentName" displayId="0">
+    <Variant id="@+id/base">
+        <Corner radius="@dimen/corner_radius"/>
+    </Variant>
+    <Variant id="@+id/opened" parent="@id/base">
+        <Layer layer="@integer/app_grid_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Corner radius="@dimen/corner_radius"/>
+        <Bounds left="16" bottom="@dimen/bottom_bar_top" right="1584" height="@dimen/app_height" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/base">
+        <Layer layer="@integer/app_grid_panel_layer"/>
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/bottom_bar_bottom" width="100%" height="@dimen/app_grid_drawer_height" />
+    </Variant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/opened"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_EnterSuwEvent" toVariant="@id/closed"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/map_panel.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/map_panel.xml
new file mode 100644
index 0000000..75740cc
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/map_panel.xml
@@ -0,0 +1,71 @@
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
+<Panel id="map_panel" defaultVariant="@id/opened" role="@array/nav_components" displayId="0">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/map_panel_layer"/>
+        <Corner radius="@dimen/corner_radius"/>
+    </Variant>
+    <Variant id="@+id/opened" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" top="@dimen/map_top" right="@dimen/screen_width" bottom="@dimen/map_bottom" />
+    </Variant>
+    <Variant id="@+id/opened_split" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="16" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/grip_bar_split_task_top_p1" />
+    </Variant>
+    <Variant id="@+id/opened_paintbooth_split" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="16" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/split_bottom" />
+    </Variant>
+    <Variant id="@+id/opened_lower" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="16" bottom="@dimen/bottom_bar_top" right="@dimen/map_right" top="@dimen/split_bottom" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="16" top="@dimen/map_top" right="@dimen/map_right" height="100%" />
+    </Variant>
+    <Variant id="@+id/opened_overlap" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" top="@dimen/map_top" right="@dimen/screen_width" bottom="@dimen/map_bottom" />
+        <Insets left="0" top="@dimen/map_top" right="0" bottom="1110" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_0" parent="@id/base">
+        <Bounds left="16" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/grip_bar_split_task_top_p0" />  </Variant>
+     <Variant id="@+id/drag_frame_100" parent="@id/base">
+        <Bounds left="16" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/grip_bar_split_task_top_p2" /> </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_frame_0" />
+        <KeyFrame frame="100" variant="@id/drag_frame_100" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/opened"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=paintbooth_panel;panelToVariantId=bottom_opened" toVariant="@id/opened_paintbooth_split"/>
+
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/opened_overlap"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/opened_overlap"/>
+
+        <Transition onEvent="_Drag_TaskSwitchEvent_top" toVariant="@id/opened_lower"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_bottom" toVariant="@id/opened_paintbooth_split"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=themeplayground_panel;panelToVariantId=drag_frame_0" toVariant="@id/drag_frame_0" duration="20"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=themeplayground_panel;panelToVariantId=bottom_opened" toVariant="@id/opened_split" duration="20"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=themeplayground_panel;panelToVariantId=drag_frame_100" toVariant="@id/drag_frame_100" duration="20"/>
+
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/paintbooth_panel.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/paintbooth_panel.xml
new file mode 100644
index 0000000..33732cc
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/paintbooth_panel.xml
@@ -0,0 +1,50 @@
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
+<Panel id="paintbooth_panel" defaultVariant="@id/closed" role="@array/paintbooth_componentNames" displayId="0">
+    <Variant id="@+id/base">
+        <Corner radius="@dimen/corner_radius"/>
+        <Layer layer="@integer/paintbooth_panel_layer"/>
+    </Variant>
+    <Variant id="@+id/bottom_opened" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="16" bottom="@dimen/bottom_bar_top" right="@dimen/app_right" top="@dimen/split_bottom" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="16" top="@dimen/bottom_bar_bottom" right="@dimen/app_right" height="@dimen/app_grid_drawer_height" />
+    </Variant>
+
+    <Variant id="@+id/top_opened" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="16" top="@dimen/map_top" right="@dimen/app_right" bottom="@dimen/split_bottom" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/top_opened" />
+        <KeyFrame frame="100" variant="@id/bottom_opened" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/bottom_opened"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=themeplayground_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_switch"  toVariant="@id/drag"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_top" toVariant="@id/top_opened"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_bottom"  toVariant="@id/bottom_opened"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/SplitPanelRRO/res/xml/themeplayground_panel.xml b/scalable-ui/codelab/SplitPanelRRO/res/xml/themeplayground_panel.xml
new file mode 100644
index 0000000..ccbc6a8
--- /dev/null
+++ b/scalable-ui/codelab/SplitPanelRRO/res/xml/themeplayground_panel.xml
@@ -0,0 +1,60 @@
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
+<Panel id="themeplayground_panel" defaultVariant="@id/closed" role="@array/themeplayground_componentNames" displayId="0">
+    <Variant id="@+id/base">
+        <Corner radius="@dimen/corner_radius"/>
+        <Visibility isVisible="true"/>
+        <Layer layer="@integer/themeplayground_panel_layer"/>
+    </Variant>
+    <Variant id="@+id/bottom_opened" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="16" top="@dimen/grip_bar_split_task_bottom_p1" right="@dimen/app_right" bottom="@dimen/bottom_bar_top" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/bottom_bar_bottom" width="100%" height="@dimen/app_grid_drawer_height" />
+    </Variant>
+
+    <Variant id="@+id/drag_frame_0" parent="@id/base">
+        <Bounds left="16" top="@dimen/grip_bar_split_task_bottom_p0" right="@dimen/app_right" bottom="@dimen/bottom_bar_top" />  </Variant>
+    <Variant id="@+id/drag_frame_100" parent="@id/base">
+        <Bounds left="16" top="@dimen/grip_bar_split_task_bottom_p2" right="@dimen/app_right" bottom="@dimen/bottom_bar_top" /> </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_frame_0" />
+        <KeyFrame frame="100" variant="@id/drag_frame_100" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=themeplayground_panel" toVariant="@id/bottom_opened"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=decor_split_theme_overlay;panelToVariantId=drag_frame_0" toVariant="@id/drag_frame_0" duration="5"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=decor_split_theme_overlay;panelToVariantId=drag_frame_50" toVariant="@id/bottom_opened" duration="5"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=decor_split_theme_overlay;panelToVariantId=drag_frame_100" toVariant="@id/drag_frame_100" duration="5"/>
+
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=map_panel;panelToVariantId=drag_frame_0" toVariant="@id/drag_frame_0" duration="5"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=map_panel;panelToVariantId=drag_frame_50" toVariant="@id/bottom_opened" duration="5"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=map_panel;panelToVariantId=drag_frame_100" toVariant="@id/drag_frame_100" duration="5"/>
+
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=decor_split_nav_overlay;panelToVariantId=drag_frame_0" toVariant="@id/drag_frame_0" duration="100"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=decor_split_nav_overlay;panelToVariantId=drag_frame_50" toVariant="@id/bottom_opened" duration="100"/>
+        <Transition onEvent="_System_OnAnimationEndEvent" onEventTokens="panelId=decor_split_nav_overlay;panelToVariantId=drag_frame_100" toVariant="@id/drag_frame_100" duration="100"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/Android.bp b/scalable-ui/codelab/ThreePanelRRO/Android.bp
new file mode 100644
index 0000000..c9d576a
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/Android.bp
@@ -0,0 +1,28 @@
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
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+// CarSystemUI scalableUI configs
+runtime_resource_overlay {
+    name: "ThreePanelRRO",
+    resource_dirs: ["res"],
+    certificate: "platform",
+    manifest: "AndroidManifest.xml",
+    system_ext_specific: true,
+}
diff --git a/scalable-ui/codelab/ThreePanelRRO/AndroidManifest.xml b/scalable-ui/codelab/ThreePanelRRO/AndroidManifest.xml
new file mode 100644
index 0000000..bc12a6d
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/AndroidManifest.xml
@@ -0,0 +1,25 @@
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.systemui.rro.scalableUI.threePanel.codelab">
+    <application android:hasCode="false" />
+    <!-- priority need to be higher than CarSystemUIDewdUIRRO -->
+    <overlay
+        android:targetPackage="com.android.systemui"
+        android:isStatic="false"
+        android:priority="111" />
+</manifest>
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/animator/fade_in.xml b/scalable-ui/codelab/ThreePanelRRO/res/animator/fade_in.xml
new file mode 100644
index 0000000..fe168b6
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/animator/fade_in.xml
@@ -0,0 +1,6 @@
+<?xml version="1.0" encoding="utf-8"?>
+<objectAnimator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:propertyName="alpha"
+    android:duration="2000"
+    android:valueTo="1"
+    android:valueType="floatType" />
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/animator/fade_out.xml b/scalable-ui/codelab/ThreePanelRRO/res/animator/fade_out.xml
new file mode 100644
index 0000000..4a149d8
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/animator/fade_out.xml
@@ -0,0 +1,6 @@
+<?xml version="1.0" encoding="utf-8"?>
+<objectAnimator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:propertyName="alpha"
+    android:duration="300"
+    android:valueTo="0"
+    android:valueType="floatType" />
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/values-h2731dp/dimens.xml b/scalable-ui/codelab/ThreePanelRRO/res/values-h2731dp/dimens.xml
new file mode 100644
index 0000000..6d567d3
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/values-h2731dp/dimens.xml
@@ -0,0 +1,40 @@
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
+<resources xmlns:tools="http://schemas.android.com/tools" tools:ignore="MissingDefaultResource,PxUsage">
+  <dimen name="screen_height">2560px</dimen>
+
+  <dimen name="top_bar_bottom">86px</dimen>
+
+  <dimen name="bottom_bar_top">2410px</dimen>
+  <dimen name="bottom_bar_bottom">2560px</dimen>
+
+  <dimen name="map_top">0px</dimen>
+  <dimen name="map_right">1600px</dimen>
+
+  <dimen name="app_height">1100px</dimen>
+  <dimen name="split_bottom">1220px</dimen>
+
+  <dimen name="lower_grip_bar_switch_task_left">20px</dimen>
+  <dimen name="lower_grip_bar_switch_task_top">1700px</dimen>
+  <dimen name="lower_grip_bar_switch_task_right">40px</dimen>
+  <dimen name="lower_grip_bar_switch_task_bottom">2000px</dimen>
+
+  <dimen name="upper_grip_bar_switch_task_left">20px</dimen>
+  <dimen name="upper_grip_bar_switch_task_top">520px</dimen>
+  <dimen name="upper_grip_bar_switch_task_right">40px</dimen>
+  <dimen name="upper_grip_bar_switch_task_bottom">620px</dimen>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/values/colors.xml b/scalable-ui/codelab/ThreePanelRRO/res/values/colors.xml
new file mode 100644
index 0000000..2d40c52
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/values/colors.xml
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
+  ~ limitations under the License
+  -->
+<resources xmlns:android="http://schemas.android.com/apk/res/android">
+    <color name="overlay_panel_bg_color">#46000000</color>
+</resources>
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/values/config.xml b/scalable-ui/codelab/ThreePanelRRO/res/values/config.xml
new file mode 100644
index 0000000..6735707
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/values/config.xml
@@ -0,0 +1,36 @@
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
+<resources>
+    <bool name="config_enableScalableUI" translatable="false">true</bool>
+    <bool name="config_enableClearBackStack" translatable="false">false</bool>
+    <string name="system_bar_app_drawer_intent" translatable="false">intent:#Intent;action=com.android.car.carlauncher.ACTION_APP_GRID;package=com.android.car.portraitlauncher;launchFlags=0x24000000;end</string>
+
+    <array name="window_states">
+        <item>@xml/app_panel</item>
+        <item>@xml/map_panel</item>
+        <item>@xml/kitchen_sink_panel</item>
+        <item>@xml/paintbooth_panel</item>
+        <item>@xml/decor_split_nav_overlay</item>
+    </array>
+
+    <string-array name="config_default_activities" translatable="false">
+        <item>paintbooth_panel;com.android.car.ui.paintbooth/com.android.car.ui.paintbooth.MainActivity</item>
+        <item>map_panel;com.android.car.portraitlauncher/.homeactivities.BackgroundPanelBaseActivity</item>
+        <item>kitchen_sink_panel;com.google.android.car.kitchensink/com.google.android.car.kitchensink.KitchenSinkActivity</item>
+    </string-array>
+</resources>
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/values/dimens.xml b/scalable-ui/codelab/ThreePanelRRO/res/values/dimens.xml
new file mode 100644
index 0000000..8e9f150
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/values/dimens.xml
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
+<resources xmlns:tools="http://schemas.android.com/tools" tools:ignore="MissingDefaultResource,PxUsage">
+    <dimen name="screen_height">2048px</dimen>
+
+    <dimen name="top_bar_bottom">80px</dimen>
+
+    <dimen name="bottom_bar_top">1780px</dimen>
+    <dimen name="bottom_bar_bottom">1920px</dimen>
+
+    <dimen name="app_grid_drawer_height">749px</dimen>
+
+    <dimen name="map_top">@dimen/top_bar_bottom</dimen>
+    <dimen name="map_right">1080px</dimen>
+    <dimen name="map_bottom">@dimen/bottom_bar_top</dimen>
+
+    <dimen name="split_bottom">1020px</dimen>
+
+    <dimen name="corner_radius">40dp</dimen>
+    <dimen name="drag_corner_radius">80dp</dimen>
+
+    <dimen name="app_height">749px</dimen>
+
+    <dimen name="top_breakpoint">350px</dimen>
+    <dimen name="bottom_breakpoint">1400px</dimen>
+
+    <dimen name="lower_grip_bar_switch_task_left">20px</dimen>
+    <dimen name="lower_grip_bar_switch_task_top">1350px</dimen>
+    <dimen name="lower_grip_bar_switch_task_right">40px</dimen>
+    <dimen name="lower_grip_bar_switch_task_bottom">1450px</dimen>
+
+    <dimen name="upper_grip_bar_switch_task_left">20px</dimen>
+    <dimen name="upper_grip_bar_switch_task_top">420px</dimen>
+    <dimen name="upper_grip_bar_switch_task_right">40px</dimen>
+    <dimen name="upper_grip_bar_switch_task_bottom">520px</dimen>
+
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/values/integers.xml b/scalable-ui/codelab/ThreePanelRRO/res/values/integers.xml
new file mode 100644
index 0000000..05de9c7
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/values/integers.xml
@@ -0,0 +1,26 @@
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
+<resources>
+    <integer name="assistant_panel_layer">200</integer>
+    <integer name="app_panel_layer">50</integer>
+    <integer name="app_grid_panel_layer">100</integer>
+    <integer name="paintbooth_panel_layer">100</integer>
+    <integer name="grip_bar_paintbooth_panel_layer">101</integer>
+    <integer name="map_panel_layer">2</integer>
+    <integer name="decor_overlay_panel_layer">3</integer>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/values/strings.xml b/scalable-ui/codelab/ThreePanelRRO/res/values/strings.xml
new file mode 100644
index 0000000..40a28fa
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/values/strings.xml
@@ -0,0 +1,40 @@
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
+<resources>
+    <string name="appgrid_componentName" translatable="false">com.android.car.portraitlauncher/com.android.car.carlauncher.AppGrcom.android.car.portraitlauncher/com.android.car.carlauncher.AppGridActivity</string>
+    <string name="kitchen_sink_componentName" translatable="false">com.google.android.car.kitchensink/com.google.android.car.kitchensink.KitchenSinkActivity</string>
+    <string name="paintbooth_componentName" translatable="false"> com.android.car.ui.paintbooth/com.android.car.ui.paintbooth.MainActivity</string>
+    <string name="contextual_bar_component" translatable="false">com.android.car.portraitlauncher/com.android.car.carlauncher.ControlBarActivity</string>
+    <string name="calmMode_componentName">com.android.car.portraitlauncher/com.android.car.portraitlauncher.calmmode.PortraitCalmModeActivity</string>
+    <string name="default_config">DEFAULT</string>
+    <string name="overlay">overlay</string>
+
+    <string-array name="nav_components" translatable="false">
+        <item>com.google.android.apps.maps/com.google.android.maps.MapsActivity</item>
+    </string-array>
+
+    <string-array name="assistant_components" translatable="false">
+        <item>com.google.android.carassistant/com.google.android.libraries.assistant.auto.tng.assistant.ui.activity.AutoAssistantActivity</item>
+        <item>com.google.android.carassistant/com.google.android.apps.gsa.binaries.auto.app.voiceplate.VoicePlateActivity</item>
+    </string-array>
+
+    <string name="config_appGridComponentName">@string/appgrid_componentName</string>
+    <string name="decor_split_nav_overlay_panel_provider">decor_split_nav_overlay_panel_provider</string>
+
+    <string name="task_switch_grid_bar_provider">task_switch_grid_bar_provider</string>
+    <string name="decor_split_grip_bar_provider">decor_split_grip_bar_provider</string>
+</resources>
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/xml/app_panel.xml b/scalable-ui/codelab/ThreePanelRRO/res/xml/app_panel.xml
new file mode 100644
index 0000000..bc3aba1
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/xml/app_panel.xml
@@ -0,0 +1,38 @@
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
+<Panel id="app_panel" defaultVariant="@id/closed" role="@string/default_config" displayId="0">
+    <Variant id="@+id/base">
+        <Corner radius="@dimen/corner_radius"/>
+    </Variant>
+    <Variant id="@+id/opened" parent="@id/base">
+        <Layer layer="@integer/app_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Alpha alpha="1.0" />
+        <Bounds left="16" bottom="@dimen/bottom_bar_top" right="99%" height="@dimen/app_height" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/base">
+        <Layer layer="@integer/app_panel_layer"/>
+        <Alpha alpha="0.0" />
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/screen_height" width="100%" height="@dimen/app_height" />
+    </Variant>
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/opened"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/xml/decor_grip_bar_switch_task.xml b/scalable-ui/codelab/ThreePanelRRO/res/xml/decor_grip_bar_switch_task.xml
new file mode 100644
index 0000000..2ba6010
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/xml/decor_grip_bar_switch_task.xml
@@ -0,0 +1,58 @@
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
+<!-- TODO(b/409116725): migrate role to design compose friendly config. -->
+<Panel id="decor_grip_bar_switch_task" defaultVariant="@id/closed" role="@string/task_switch_grid_bar_provider" controller="@xml/drag_switch_task_grip_controller">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/grip_bar_paintbooth_panel_layer"/>
+        <Corner radius="@dimen/drag_corner_radius"/>
+    </Variant>
+
+    <Variant id="@+id/opened_bottom" parent="@id/base">
+        <Bounds left="@dimen/lower_grip_bar_switch_task_left" right="@dimen/lower_grip_bar_switch_task_right" top="@dimen/lower_grip_bar_switch_task_top" bottom="@dimen/lower_grip_bar_switch_task_bottom" />
+    </Variant>
+    <Variant id="@+id/opened_top" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="@dimen/upper_grip_bar_switch_task_left" right="@dimen/upper_grip_bar_switch_task_right" top="@dimen/upper_grip_bar_switch_task_top" bottom="@dimen/upper_grip_bar_switch_task_bottom" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="10" top="@dimen/bottom_bar_bottom" width="20" height="100" />
+    </Variant>
+
+    <Variant id="@+id/drag_switch" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="@dimen/upper_grip_bar_switch_task_left" right="@dimen/upper_grip_bar_switch_task_right" top="@dimen/upper_grip_bar_switch_task_top" bottom="@dimen/upper_grip_bar_switch_task_bottom" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_switch" />
+        <KeyFrame frame="100" variant="@id/opened_top" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/opened_bottom"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_EnterSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_ExitSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="close_app_grid" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_split"  toVariant="@id/drag"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_top" toVariant="@id/opened_top"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_bottom"  toVariant="@id/opened_bottom"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/xml/decor_split_grip_bar.xml b/scalable-ui/codelab/ThreePanelRRO/res/xml/decor_split_grip_bar.xml
new file mode 100644
index 0000000..3ff6eaf
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/xml/decor_split_grip_bar.xml
@@ -0,0 +1,58 @@
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
+<!-- TODO(b/409116725): migrate role to design compose friendly config. -->
+<Panel id="decor_split_grip_bar" defaultVariant="@id/closed" role="@string/decor_split_grip_bar_provider" controller="@xml/drag_switch_task_grip_controller">
+    <Variant id="@+id/base">
+        <Layer layer="@integer/grip_bar_paintbooth_panel_layer"/>
+        <Corner radius="@dimen/drag_corner_radius"/>
+    </Variant>
+
+    <Variant id="@+id/opened_bottom" parent="@id/base">
+        <Bounds left="@dimen/lower_grip_bar_switch_task_left" right="@dimen/lower_grip_bar_switch_task_right" top="@dimen/lower_grip_bar_switch_task_top" bottom="@dimen/lower_grip_bar_switch_task_bottom" />
+    </Variant>
+    <Variant id="@+id/opened_top" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="@dimen/lower_grip_bar_switch_task_left" right="@dimen/lower_grip_bar_switch_task_right" top="@dimen/lower_grip_bar_switch_task_top" bottom="@dimen/lower_grip_bar_switch_task_bottom" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="10" top="@dimen/bottom_bar_bottom" width="20" height="100" />
+    </Variant>
+
+    <Variant id="@+id/drag_switch" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="@dimen/upper_grip_bar_switch_task_left" right="@dimen/upper_grip_bar_switch_task_right" top="@dimen/upper_grip_bar_switch_task_top" bottom="@dimen/upper_grip_bar_switch_task_bottom" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_switch" />
+        <KeyFrame frame="100" variant="@id/opened_top" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/opened_bottom"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_EnterSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_ExitSuwEvent" toVariant="@id/closed"/>
+        <Transition onEvent="close_app_grid" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_split"  toVariant="@id/drag"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_top" toVariant="@id/opened_top"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_bottom"  toVariant="@id/opened_bottom"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/xml/decor_split_nav_overlay.xml b/scalable-ui/codelab/ThreePanelRRO/res/xml/decor_split_nav_overlay.xml
new file mode 100644
index 0000000..d063d90
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/xml/decor_split_nav_overlay.xml
@@ -0,0 +1,40 @@
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
+<Panel id="decor_split_nav_overlay" defaultVariant="@id/closed" role="@string/decor_split_nav_overlay_panel_provider" controller="@xml/decor_split_nav_overlay_controller">
+    <Variant id="@+id/map_base">
+        <Layer layer="@integer/decor_overlay_panel_layer"/>
+        <Corner radius="@dimen/corner_radius"/>
+    </Variant>
+    <Variant id="@+id/opened_blur" parent="@id/map_base">
+        <Visibility isVisible="true"/>
+        <Alpha alpha="1.0" />
+        <Bounds left="0" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/map_bottom" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/map_base">
+        <Visibility isVisible="false"/>
+        <Alpha alpha="0.1" />
+        <Bounds left="0" top="@dimen/map_top" width="100%" height="100%" />
+    </Variant>
+
+    <Transitions defaultInterpolator="@android:anim/bounce_interpolator" defaultDuration="700">
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/opened_blur"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_top" toVariant="@id/closed"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_bottom" toVariant="@id/closed"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/xml/decor_split_nav_overlay_controller.xml b/scalable-ui/codelab/ThreePanelRRO/res/xml/decor_split_nav_overlay_controller.xml
new file mode 100644
index 0000000..299a750
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/xml/decor_split_nav_overlay_controller.xml
@@ -0,0 +1,20 @@
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
+<Controller id="decor_split_nav_overlay_controller">
+    <Config key="ControllerName" value="com.android.systemui.car.wm.scalableui.view.PanelOverlayController"/>
+    <Config key="View" value="com.android.systemui.car.wm.scalableui.view.PanelOverlay"/>
+    <Config key="overlayPanelId" value="map_panel" />
+</Controller>
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/xml/drag_split_task_grip_controller.xml b/scalable-ui/codelab/ThreePanelRRO/res/xml/drag_split_task_grip_controller.xml
new file mode 100644
index 0000000..4c96b1c
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/xml/drag_split_task_grip_controller.xml
@@ -0,0 +1,26 @@
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
+<Controller id="split_grip_bar_controller">
+    <Config key="ControllerName" value="com.android.systemui.car.wm.scalableui.view.GripBarViewController"/>
+    <Config key="View" value="com.android.systemui.car.wm.scalableui.view.GripBar"/>
+    <Config key="EventId" value="_User_DragEvent_split" />
+    <Config key="Orientation" value="0" />
+    <Config key="SnapThreadhold" value="5"/>
+    <BreakPoints>
+        <BreakPoint point="@dimen/top_breakpoint" eventId="_Drag_TaskSwitchEvent_top" />
+        <BreakPoint point="@dimen/bottom_breakpoint" eventId="_Drag_TaskSwitchEvent_bottom" />
+    </BreakPoints>
+</Controller>
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/xml/drag_switch_task_grip_controller.xml b/scalable-ui/codelab/ThreePanelRRO/res/xml/drag_switch_task_grip_controller.xml
new file mode 100644
index 0000000..9dd37ba
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/xml/drag_switch_task_grip_controller.xml
@@ -0,0 +1,26 @@
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
+<Controller id="grip_bar_controller">
+    <Config key="ControllerName" value="com.android.systemui.car.wm.scalableui.view.GripBarViewController"/>
+    <Config key="View" value="com.android.systemui.car.wm.scalableui.view.GripBar"/>
+    <Config key="EventId" value="_User_DragEvent_split" />
+    <Config key="Orientation" value="0" />
+    <Config key="SnapThreadhold" value="5"/>
+    <BreakPoints>
+        <BreakPoint point="@dimen/top_breakpoint" eventId="_Drag_TaskSwitchEvent_top" />
+        <BreakPoint point="@dimen/bottom_breakpoint" eventId="_Drag_TaskSwitchEvent_bottom" />
+    </BreakPoints>
+</Controller>
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/xml/kitchen_sink_panel.xml b/scalable-ui/codelab/ThreePanelRRO/res/xml/kitchen_sink_panel.xml
new file mode 100644
index 0000000..008f01c
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/xml/kitchen_sink_panel.xml
@@ -0,0 +1,39 @@
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
+<Panel id="kitchen_sink_panel" defaultVariant="@id/closed" role="@string/kitchen_sink_componentName" displayId="0">
+    <Variant id="@+id/base">
+        <Corner radius="@dimen/corner_radius"/>
+    </Variant>
+    <Variant id="@+id/opened" parent="@id/base">
+        <Layer layer="@integer/app_grid_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Corner radius="@dimen/corner_radius"/>
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" width="100%" height="@dimen/app_height" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/base">
+        <Layer layer="@integer/app_grid_panel_layer"/>
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/bottom_bar_bottom" width="100%" height="@dimen/app_grid_drawer_height" />
+    </Variant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/opened"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_System_EnterSuwEvent" toVariant="@id/closed"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/xml/map_panel.xml b/scalable-ui/codelab/ThreePanelRRO/res/xml/map_panel.xml
new file mode 100644
index 0000000..1730abd
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/xml/map_panel.xml
@@ -0,0 +1,54 @@
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
+<Panel id="map_panel" defaultVariant="@id/opened" role="@array/nav_components" displayId="0">
+    <Variant id="@+id/map_base">
+        <Layer layer="@integer/map_panel_layer"/>
+        <Corner radius="@dimen/corner_radius"/>
+    </Variant>
+    <Variant id="@+id/opened" parent="@id/map_base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/map_bottom" />
+    </Variant>
+    <Variant id="@+id/opened_split" parent="@id/map_base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/split_bottom" />
+    </Variant>
+    <Variant id="@+id/opened_split_blur" parent="@id/map_base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/split_bottom" />
+    </Variant>
+    <Variant id="@+id/opened_lower" parent="@id/map_base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" width="100%" height="@dimen/app_height" />
+    </Variant>
+    <Variant id="@+id/opened_blur" parent="@id/map_base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/map_bottom" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/map_base">
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/map_top" width="100%" height="100%" />
+    </Variant>
+
+    <Transitions defaultInterpolator="@android:anim/bounce_interpolator" defaultDuration="700">
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/opened"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/opened_split"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/opened"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/opened_blur"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_top" toVariant="@id/opened_lower"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_bottom" toVariant="@id/opened_split"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/ThreePanelRRO/res/xml/paintbooth_panel.xml b/scalable-ui/codelab/ThreePanelRRO/res/xml/paintbooth_panel.xml
new file mode 100644
index 0000000..4f6a021
--- /dev/null
+++ b/scalable-ui/codelab/ThreePanelRRO/res/xml/paintbooth_panel.xml
@@ -0,0 +1,52 @@
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
+<Panel id="paintbooth_panel" defaultVariant="@id/closed" role="@string/paintbooth_componentName" displayId="0">
+    <Variant id="@+id/base">
+        <Corner radius="@dimen/corner_radius"/>
+        <Layer layer="@integer/paintbooth_panel_layer"/>
+    </Variant>
+    <Variant id="@+id/bottom_opened" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" width="100%" height="@dimen/app_height" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/base">
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/bottom_bar_bottom" width="100%" height="@dimen/app_grid_drawer_height" />
+    </Variant>
+    <Variant id="@+id/drag_top_opened" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" width="100%" height="@dimen/app_height" />
+    </Variant>
+    <Variant id="@+id/top_opened" parent="@id/base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" top="@dimen/map_top" right="@dimen/map_right" bottom="@dimen/split_bottom" />
+    </Variant>
+
+    <KeyFrameVariant id="@+id/drag" parent="@id/base">
+        <KeyFrame frame="0" variant="@id/drag_top_opened" />
+        <KeyFrame frame="100" variant="@id/bottom_opened" />
+    </KeyFrameVariant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=paintbooth_panel" toVariant="@id/bottom_opened"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=kitchen_sink_panel" toVariant="@id/closed"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+        <Transition onEvent="_User_DragEvent_split"  toVariant="@id/drag"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_top" toVariant="@id/top_opened"/>
+        <Transition onEvent="_Drag_TaskSwitchEvent_bottom"  toVariant="@id/bottom_opened"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRRO/Android.bp b/scalable-ui/codelab/TwoPanelRRO/Android.bp
new file mode 100644
index 0000000..0cdf329
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRRO/Android.bp
@@ -0,0 +1,28 @@
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
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+// CarSystemUI scalableUI configs
+runtime_resource_overlay {
+    name: "TwoPanelRRO",
+    resource_dirs: ["res"],
+    certificate: "platform",
+    manifest: "AndroidManifest.xml",
+    system_ext_specific: true,
+}
diff --git a/scalable-ui/codelab/TwoPanelRRO/AndroidManifest.xml b/scalable-ui/codelab/TwoPanelRRO/AndroidManifest.xml
new file mode 100644
index 0000000..649cd46
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRRO/AndroidManifest.xml
@@ -0,0 +1,25 @@
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.systemui.rro.scalableUI.twoPanel.codelab">
+    <application android:hasCode="false" />
+    <!-- priority need to be higher than CarSystemUIDewdUIRRO -->
+    <overlay
+        android:targetPackage="com.android.systemui"
+        android:isStatic="false"
+        android:priority="111" />
+</manifest>
diff --git a/scalable-ui/codelab/TwoPanelRRO/res/animator/fade_in.xml b/scalable-ui/codelab/TwoPanelRRO/res/animator/fade_in.xml
new file mode 100644
index 0000000..96433df
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRRO/res/animator/fade_in.xml
@@ -0,0 +1,6 @@
+<?xml version="1.0" encoding="utf-8"?>
+<objectAnimator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:propertyName="alpha"
+    android:duration="300"
+    android:valueTo="1"
+    android:valueType="floatType" />
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRRO/res/animator/fade_out.xml b/scalable-ui/codelab/TwoPanelRRO/res/animator/fade_out.xml
new file mode 100644
index 0000000..4a149d8
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRRO/res/animator/fade_out.xml
@@ -0,0 +1,6 @@
+<?xml version="1.0" encoding="utf-8"?>
+<objectAnimator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:propertyName="alpha"
+    android:duration="300"
+    android:valueTo="0"
+    android:valueType="floatType" />
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRRO/res/values/config.xml b/scalable-ui/codelab/TwoPanelRRO/res/values/config.xml
new file mode 100644
index 0000000..9b05140
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRRO/res/values/config.xml
@@ -0,0 +1,31 @@
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
+<resources>
+    <bool name="config_enableScalableUI" translatable="false">true</bool>
+    <bool name="config_enableClearBackStack" translatable="false">false</bool>
+    <string name="system_bar_app_drawer_intent" translatable="false">intent:#Intent;action=com.android.car.carlauncher.ACTION_APP_GRID;package=com.android.car.portraitlauncher;launchFlags=0x24000000;end</string>
+
+    <array name="window_states">
+        <item>@xml/app_panel</item>
+        <item>@xml/map_panel</item>
+    </array>
+
+    <string-array name="config_default_activities" translatable="false">
+        <item>map_panel;com.android.car.portraitlauncher/.homeactivities.BackgroundPanelBaseActivity</item>
+    </string-array>
+</resources>
diff --git a/scalable-ui/codelab/TwoPanelRRO/res/values/dimens.xml b/scalable-ui/codelab/TwoPanelRRO/res/values/dimens.xml
new file mode 100644
index 0000000..cb9cbfe
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRRO/res/values/dimens.xml
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
+  -->
+<resources xmlns:tools="http://schemas.android.com/tools" tools:ignore="MissingDefaultResource,PxUsage">
+    <dimen name="screen_height">2048px</dimen>
+
+    <dimen name="top_bar_bottom">80px</dimen>
+
+    <dimen name="bottom_bar_top">1836px</dimen>
+    <dimen name="bottom_bar_bottom">1920px</dimen>
+
+    <dimen name="map_top">0px</dimen>
+
+    <dimen name="app_height">1000px</dimen>
+
+    <dimen name="assistant_left">0px</dimen>
+    <dimen name="assistant_right">1080px</dimen>
+    <dimen name="assistant_top">0px</dimen>
+    <dimen name="assistant_height">1920px</dimen>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRRO/res/values/integers.xml b/scalable-ui/codelab/TwoPanelRRO/res/values/integers.xml
new file mode 100644
index 0000000..0c10f84
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRRO/res/values/integers.xml
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
+
+<resources>
+    <integer name="app_panel_layer">50</integer>
+    <integer name="map_panel_layer">2</integer>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRRO/res/values/strings.xml b/scalable-ui/codelab/TwoPanelRRO/res/values/strings.xml
new file mode 100644
index 0000000..e153e53
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRRO/res/values/strings.xml
@@ -0,0 +1,23 @@
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
+<resources>
+    <string name="default_config">DEFAULT</string>
+
+    <string-array name="nav_components" translatable="false">
+        <item>com.google.android.apps.maps/com.google.android.maps.MapsActivity</item>
+    </string-array>
+</resources>
diff --git a/scalable-ui/codelab/TwoPanelRRO/res/xml/app_panel.xml b/scalable-ui/codelab/TwoPanelRRO/res/xml/app_panel.xml
new file mode 100644
index 0000000..c81b432
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRRO/res/xml/app_panel.xml
@@ -0,0 +1,35 @@
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
+<Panel id="app_panel" defaultVariant="@id/closed" role="@string/default_config" displayId="0">
+    <Variant id="@+id/opened">
+        <Layer layer="@integer/app_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Alpha alpha="1.0" />
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" width="100%" height="@dimen/app_height" />
+    </Variant>
+    <Variant id="@+id/closed">
+        <Layer layer="@integer/app_panel_layer"/>
+        <Alpha alpha="0.0" />
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/screen_height" width="100%" height="@dimen/app_height" />
+    </Variant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=panel_app_grid" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/opened"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRRO/res/xml/map_panel.xml b/scalable-ui/codelab/TwoPanelRRO/res/xml/map_panel.xml
new file mode 100644
index 0000000..234535a
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRRO/res/xml/map_panel.xml
@@ -0,0 +1,32 @@
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
+<Panel id="map_panel" defaultVariant="@id/opened" role="@array/nav_components" displayId="0">
+    <Variant id="@+id/map_base">
+        <Layer layer="@integer/map_panel_layer"/>
+    </Variant>
+    <Variant id="@+id/opened" parent="@id/map_base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" top="@dimen/map_top" width="100%" height="100%" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/map_base">
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/map_top" width="100%" height="100%" />
+    </Variant>
+
+    <Transitions defaultInterpolator="@android:anim/bounce_interpolator" defaultDuration="700">
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/opened"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRROCast/Android.bp b/scalable-ui/codelab/TwoPanelRROCast/Android.bp
new file mode 100644
index 0000000..793ff6e
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROCast/Android.bp
@@ -0,0 +1,28 @@
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
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+// CarSystemUI scalableUI configs
+runtime_resource_overlay {
+    name: "TwoPanelRROCast",
+    resource_dirs: ["res"],
+    certificate: "platform",
+    manifest: "AndroidManifest.xml",
+    system_ext_specific: true,
+}
diff --git a/scalable-ui/codelab/TwoPanelRROCast/AndroidManifest.xml b/scalable-ui/codelab/TwoPanelRROCast/AndroidManifest.xml
new file mode 100644
index 0000000..e6e963e
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROCast/AndroidManifest.xml
@@ -0,0 +1,25 @@
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.systemui.rro.scalableUI.twoPanelCast.codelab">
+    <application android:hasCode="false" />
+    <!-- priority need to be higher than CarSystemUIDewdUIRRO -->
+    <overlay
+        android:targetPackage="com.android.systemui"
+        android:isStatic="false"
+        android:priority="111" />
+</manifest>
diff --git a/scalable-ui/codelab/TwoPanelRROCast/res/animator/fade_in.xml b/scalable-ui/codelab/TwoPanelRROCast/res/animator/fade_in.xml
new file mode 100644
index 0000000..96433df
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROCast/res/animator/fade_in.xml
@@ -0,0 +1,6 @@
+<?xml version="1.0" encoding="utf-8"?>
+<objectAnimator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:propertyName="alpha"
+    android:duration="300"
+    android:valueTo="1"
+    android:valueType="floatType" />
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRROCast/res/animator/fade_out.xml b/scalable-ui/codelab/TwoPanelRROCast/res/animator/fade_out.xml
new file mode 100644
index 0000000..4a149d8
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROCast/res/animator/fade_out.xml
@@ -0,0 +1,6 @@
+<?xml version="1.0" encoding="utf-8"?>
+<objectAnimator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:propertyName="alpha"
+    android:duration="300"
+    android:valueTo="0"
+    android:valueType="floatType" />
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRROCast/res/values-h2731dp/dimens.xml b/scalable-ui/codelab/TwoPanelRROCast/res/values-h2731dp/dimens.xml
new file mode 100644
index 0000000..7977139
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROCast/res/values-h2731dp/dimens.xml
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
+<resources xmlns:tools="http://schemas.android.com/tools" tools:ignore="MissingDefaultResource,PxUsage">
+  <dimen name="screen_height">2560px</dimen>
+  <dimen name="screen_width">1600px</dimen>
+
+  <dimen name="top_bar_bottom">86px</dimen>
+
+  <dimen name="bottom_bar_top">2410px</dimen>
+  <dimen name="bottom_bar_bottom">2560px</dimen>
+
+  <dimen name="map_height">1300px</dimen>
+
+  <dimen name="app_height">1110px</dimen>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRROCast/res/values/config.xml b/scalable-ui/codelab/TwoPanelRROCast/res/values/config.xml
new file mode 100644
index 0000000..9b05140
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROCast/res/values/config.xml
@@ -0,0 +1,31 @@
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
+<resources>
+    <bool name="config_enableScalableUI" translatable="false">true</bool>
+    <bool name="config_enableClearBackStack" translatable="false">false</bool>
+    <string name="system_bar_app_drawer_intent" translatable="false">intent:#Intent;action=com.android.car.carlauncher.ACTION_APP_GRID;package=com.android.car.portraitlauncher;launchFlags=0x24000000;end</string>
+
+    <array name="window_states">
+        <item>@xml/app_panel</item>
+        <item>@xml/map_panel</item>
+    </array>
+
+    <string-array name="config_default_activities" translatable="false">
+        <item>map_panel;com.android.car.portraitlauncher/.homeactivities.BackgroundPanelBaseActivity</item>
+    </string-array>
+</resources>
diff --git a/scalable-ui/codelab/TwoPanelRROCast/res/values/dimens.xml b/scalable-ui/codelab/TwoPanelRROCast/res/values/dimens.xml
new file mode 100644
index 0000000..8615bf2
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROCast/res/values/dimens.xml
@@ -0,0 +1,35 @@
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
+<resources xmlns:tools="http://schemas.android.com/tools" tools:ignore="MissingDefaultResource,PxUsage">
+    <dimen name="screen_height">2048px</dimen>
+
+    <dimen name="top_bar_bottom">80px</dimen>
+
+    <dimen name="bottom_bar_top">1836px</dimen>
+    <dimen name="bottom_bar_bottom">1087px</dimen>
+
+    <dimen name="app_grid_drawer_bottom">@dimen/contextual_bar_top</dimen>
+    <dimen name="app_grid_drawer_height">749px</dimen>
+
+    <dimen name="map_top">0px</dimen>
+    <dimen name="map_height">1087px</dimen>
+
+    <dimen name="contextual_bar_top">1428px</dimen>
+
+    <dimen name="app_bottom">@dimen/contextual_bar_top</dimen>
+    <dimen name="app_height">749px</dimen>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRROCast/res/values/integers.xml b/scalable-ui/codelab/TwoPanelRROCast/res/values/integers.xml
new file mode 100644
index 0000000..0c10f84
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROCast/res/values/integers.xml
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
+
+<resources>
+    <integer name="app_panel_layer">50</integer>
+    <integer name="map_panel_layer">2</integer>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRROCast/res/values/strings.xml b/scalable-ui/codelab/TwoPanelRROCast/res/values/strings.xml
new file mode 100644
index 0000000..e153e53
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROCast/res/values/strings.xml
@@ -0,0 +1,23 @@
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
+<resources>
+    <string name="default_config">DEFAULT</string>
+
+    <string-array name="nav_components" translatable="false">
+        <item>com.google.android.apps.maps/com.google.android.maps.MapsActivity</item>
+    </string-array>
+</resources>
diff --git a/scalable-ui/codelab/TwoPanelRROCast/res/xml/app_panel.xml b/scalable-ui/codelab/TwoPanelRROCast/res/xml/app_panel.xml
new file mode 100644
index 0000000..358c096
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROCast/res/xml/app_panel.xml
@@ -0,0 +1,34 @@
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
+<Panel id="app_panel" defaultVariant="@id/closed" role="@string/default_config" displayId="0">
+    <Variant id="@+id/opened">
+        <Layer layer="@integer/app_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Alpha alpha="1.0" />
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" width="100%" top="@dimen/map_height" height="@dimen/app_height" />
+    </Variant>
+    <Variant id="@+id/closed">
+        <Layer layer="@integer/app_panel_layer"/>
+        <Alpha alpha="0.0" />
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/screen_height" width="100%" height="@dimen/app_height" />
+    </Variant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/opened"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRROCast/res/xml/map_panel.xml b/scalable-ui/codelab/TwoPanelRROCast/res/xml/map_panel.xml
new file mode 100644
index 0000000..e7dfd9f
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROCast/res/xml/map_panel.xml
@@ -0,0 +1,32 @@
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
+<Panel id="map_panel" defaultVariant="@id/opened" role="@array/nav_components" displayId="0">
+    <Variant id="@+id/map_base">
+        <Layer layer="@integer/map_panel_layer"/>
+    </Variant>
+    <Variant id="@+id/opened" parent="@id/map_base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" top="@dimen/map_top" width="100%" height="@dimen/map_height" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/map_base">
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/map_top" width="100%" height="@dimen/map_height" />
+    </Variant>
+
+    <Transitions defaultInterpolator="@android:anim/bounce_interpolator" defaultDuration="700">
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/opened"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRROSafeBounds/Android.bp b/scalable-ui/codelab/TwoPanelRROSafeBounds/Android.bp
new file mode 100644
index 0000000..6c5e628
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROSafeBounds/Android.bp
@@ -0,0 +1,28 @@
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
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+// CarSystemUI scalableUI configs
+runtime_resource_overlay {
+    name: "TwoPanelRROSafeBounds",
+    resource_dirs: ["res"],
+    certificate: "platform",
+    manifest: "AndroidManifest.xml",
+    system_ext_specific: true,
+}
diff --git a/scalable-ui/codelab/TwoPanelRROSafeBounds/AndroidManifest.xml b/scalable-ui/codelab/TwoPanelRROSafeBounds/AndroidManifest.xml
new file mode 100644
index 0000000..5e57c53
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROSafeBounds/AndroidManifest.xml
@@ -0,0 +1,25 @@
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.systemui.rro.scalableUI.twoPanelSafeBounds.codelab">
+    <application android:hasCode="false" />
+    <!-- priority need to be higher than CarSystemUIDewdUIRRO -->
+    <overlay
+        android:targetPackage="com.android.systemui"
+        android:isStatic="false"
+        android:priority="111" />
+</manifest>
diff --git a/scalable-ui/codelab/TwoPanelRROSafeBounds/res/animator/fade_in.xml b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/animator/fade_in.xml
new file mode 100644
index 0000000..96433df
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/animator/fade_in.xml
@@ -0,0 +1,6 @@
+<?xml version="1.0" encoding="utf-8"?>
+<objectAnimator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:propertyName="alpha"
+    android:duration="300"
+    android:valueTo="1"
+    android:valueType="floatType" />
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRROSafeBounds/res/animator/fade_out.xml b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/animator/fade_out.xml
new file mode 100644
index 0000000..4a149d8
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/animator/fade_out.xml
@@ -0,0 +1,6 @@
+<?xml version="1.0" encoding="utf-8"?>
+<objectAnimator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:propertyName="alpha"
+    android:duration="300"
+    android:valueTo="0"
+    android:valueType="floatType" />
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values-h2731dp/dimens.xml b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values-h2731dp/dimens.xml
new file mode 100644
index 0000000..e14b892
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values-h2731dp/dimens.xml
@@ -0,0 +1,32 @@
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
+<resources xmlns:tools="http://schemas.android.com/tools" tools:ignore="MissingDefaultResource,PxUsage">
+  <dimen name="screen_height">2560px</dimen>
+  <dimen name="screen_width">1600px</dimen>
+
+  <dimen name="top_bar_bottom">86px</dimen>
+
+  <dimen name="bottom_bar_top">2410px</dimen>
+  <dimen name="bottom_bar_bottom">2560px</dimen>
+
+  <dimen name="map_top">0px</dimen>
+  <dimen name="map_right">1600px</dimen>
+
+  <dimen name="app_height">1200px</dimen>
+
+  <dimen name="app_height_safe">1100px</dimen>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values/config.xml b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values/config.xml
new file mode 100644
index 0000000..9b05140
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values/config.xml
@@ -0,0 +1,31 @@
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
+<resources>
+    <bool name="config_enableScalableUI" translatable="false">true</bool>
+    <bool name="config_enableClearBackStack" translatable="false">false</bool>
+    <string name="system_bar_app_drawer_intent" translatable="false">intent:#Intent;action=com.android.car.carlauncher.ACTION_APP_GRID;package=com.android.car.portraitlauncher;launchFlags=0x24000000;end</string>
+
+    <array name="window_states">
+        <item>@xml/app_panel</item>
+        <item>@xml/map_panel</item>
+    </array>
+
+    <string-array name="config_default_activities" translatable="false">
+        <item>map_panel;com.android.car.portraitlauncher/.homeactivities.BackgroundPanelBaseActivity</item>
+    </string-array>
+</resources>
diff --git a/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values/dimens.xml b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values/dimens.xml
new file mode 100644
index 0000000..61f4353
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values/dimens.xml
@@ -0,0 +1,40 @@
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
+<resources xmlns:tools="http://schemas.android.com/tools" tools:ignore="MissingDefaultResource,PxUsage">
+    <dimen name="screen_height">2048px</dimen>
+
+    <dimen name="top_bar_bottom">80px</dimen>
+
+    <dimen name="bottom_bar_top">1836px</dimen>
+    <dimen name="bottom_bar_bottom">1920px</dimen>
+
+    <dimen name="app_grid_drawer_bottom">@dimen/contextual_bar_top</dimen>
+    <dimen name="app_grid_drawer_height">749px</dimen>
+
+    <dimen name="map_top">0px</dimen>
+    <dimen name="map_height">1479px</dimen>
+
+    <dimen name="contextual_bar_top">1428px</dimen>
+    <dimen name="contextual_bar_bottom">1836px</dimen>
+    <dimen name="contextual_bar_height">408px</dimen>
+
+    <dimen name="app_bottom">@dimen/contextual_bar_top</dimen>
+    <dimen name="app_height">749px</dimen>
+
+    <dimen name="app_height_safe">673px</dimen>
+    <dimen name="app_safe_top_offset">76px</dimen>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values/integers.xml b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values/integers.xml
new file mode 100644
index 0000000..0c10f84
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values/integers.xml
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
+
+<resources>
+    <integer name="app_panel_layer">50</integer>
+    <integer name="map_panel_layer">2</integer>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values/strings.xml b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values/strings.xml
new file mode 100644
index 0000000..e153e53
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/values/strings.xml
@@ -0,0 +1,23 @@
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
+<resources>
+    <string name="default_config">DEFAULT</string>
+
+    <string-array name="nav_components" translatable="false">
+        <item>com.google.android.apps.maps/com.google.android.maps.MapsActivity</item>
+    </string-array>
+</resources>
diff --git a/scalable-ui/codelab/TwoPanelRROSafeBounds/res/xml/app_panel.xml b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/xml/app_panel.xml
new file mode 100644
index 0000000..4fb8534
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/xml/app_panel.xml
@@ -0,0 +1,37 @@
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
+<Panel id="app_panel" defaultVariant="@id/closed" role="@string/default_config" displayId="0">
+    <Variant id="@+id/opened">
+        <Layer layer="@integer/app_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Alpha alpha="1.0" />
+        <Bounds left="0" bottom="100%" width="100%" height="@dimen/app_height" />
+        <SafeBounds left="0" bottom="100%" width="100%" height="@dimen/app_height_safe"/>
+    </Variant>
+    <Variant id="@+id/closed">
+        <Layer layer="@integer/app_panel_layer"/>
+        <Alpha alpha="0.0" />
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/screen_height" width="100%" height="@dimen/app_height" />
+        <SafeBounds left="0" top="100%" width="100%" height="@dimen/app_height_safe" topOffset="@dimen/app_safe_top_offset"/>
+    </Variant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=panel_app_grid" toVariant="@id/closed"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/opened"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelRROSafeBounds/res/xml/map_panel.xml b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/xml/map_panel.xml
new file mode 100644
index 0000000..234535a
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelRROSafeBounds/res/xml/map_panel.xml
@@ -0,0 +1,32 @@
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
+<Panel id="map_panel" defaultVariant="@id/opened" role="@array/nav_components" displayId="0">
+    <Variant id="@+id/map_base">
+        <Layer layer="@integer/map_panel_layer"/>
+    </Variant>
+    <Variant id="@+id/opened" parent="@id/map_base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" top="@dimen/map_top" width="100%" height="100%" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/map_base">
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/map_top" width="100%" height="100%" />
+    </Variant>
+
+    <Transitions defaultInterpolator="@android:anim/bounce_interpolator" defaultDuration="700">
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/opened"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelWithInsetsRRO/Android.bp b/scalable-ui/codelab/TwoPanelWithInsetsRRO/Android.bp
new file mode 100644
index 0000000..a67f592
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelWithInsetsRRO/Android.bp
@@ -0,0 +1,28 @@
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
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+// CarSystemUI scalableUI configs
+runtime_resource_overlay {
+    name: "TwoPanelWithInsetsRRO",
+    resource_dirs: ["res"],
+    certificate: "platform",
+    manifest: "AndroidManifest.xml",
+    system_ext_specific: true,
+}
diff --git a/scalable-ui/codelab/TwoPanelWithInsetsRRO/AndroidManifest.xml b/scalable-ui/codelab/TwoPanelWithInsetsRRO/AndroidManifest.xml
new file mode 100644
index 0000000..d95fd49
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelWithInsetsRRO/AndroidManifest.xml
@@ -0,0 +1,25 @@
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.systemui.rro.scalableUI.twoPanelWithInset.codelab">
+    <application android:hasCode="false" />
+    <!-- priority need to be higher than CarSystemUIDewdUIRRO -->
+    <overlay
+        android:targetPackage="com.android.systemui"
+        android:isStatic="false"
+        android:priority="111" />
+</manifest>
diff --git a/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/animator/fade_in.xml b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/animator/fade_in.xml
new file mode 100644
index 0000000..71fa8fb
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/animator/fade_in.xml
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
+<objectAnimator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:propertyName="alpha"
+    android:duration="300"
+    android:valueTo="1"
+    android:valueType="floatType" />
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/animator/fade_out.xml b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/animator/fade_out.xml
new file mode 100644
index 0000000..5a86342
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/animator/fade_out.xml
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
+<objectAnimator xmlns:android="http://schemas.android.com/apk/res/android"
+    android:propertyName="alpha"
+    android:duration="300"
+    android:valueTo="0"
+    android:valueType="floatType" />
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/values/config.xml b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/values/config.xml
new file mode 100644
index 0000000..9b05140
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/values/config.xml
@@ -0,0 +1,31 @@
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
+<resources>
+    <bool name="config_enableScalableUI" translatable="false">true</bool>
+    <bool name="config_enableClearBackStack" translatable="false">false</bool>
+    <string name="system_bar_app_drawer_intent" translatable="false">intent:#Intent;action=com.android.car.carlauncher.ACTION_APP_GRID;package=com.android.car.portraitlauncher;launchFlags=0x24000000;end</string>
+
+    <array name="window_states">
+        <item>@xml/app_panel</item>
+        <item>@xml/map_panel</item>
+    </array>
+
+    <string-array name="config_default_activities" translatable="false">
+        <item>map_panel;com.android.car.portraitlauncher/.homeactivities.BackgroundPanelBaseActivity</item>
+    </string-array>
+</resources>
diff --git a/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/values/dimens.xml b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/values/dimens.xml
new file mode 100644
index 0000000..28e6453
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/values/dimens.xml
@@ -0,0 +1,48 @@
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
+<resources>
+    <dimen name="screen_height">2048px</dimen>
+
+    <dimen name="top_bar_bottom">80px</dimen>
+
+    <dimen name="bottom_bar_top">1836px</dimen>
+    <dimen name="bottom_bar_bottom">1920px</dimen>
+
+    <dimen name="app_grid_drawer_bottom">@dimen/contextual_bar_top</dimen>
+    <dimen name="app_grid_drawer_height">749px</dimen>
+
+    <dimen name="map_top">0px</dimen>
+    <dimen name="map_height">1479px</dimen>
+
+    <dimen name="contextual_bar_top">1428px</dimen>
+    <dimen name="contextual_bar_bottom">1836px</dimen>
+    <dimen name="contextual_bar_height">408px</dimen>
+
+    <dimen name="app_immersive_top">@dimen/top_bar_bottom</dimen>
+    <dimen name="app_immersive_height">1712px</dimen>
+    <dimen name="app_bottom">@dimen/contextual_bar_top</dimen>
+    <dimen name="app_height">749px</dimen>
+
+    <dimen name="assistant_left">0px</dimen>
+    <dimen name="assistant_right">1080px</dimen>
+    <dimen name="assistant_top">0px</dimen>
+    <dimen name="assistant_height">1920px</dimen>
+
+    <dimen name="calm_mode_left">0px</dimen>
+    <dimen name="calm_mode_top">0px</dimen>
+    <dimen name="calm_mode_height">1836px</dimen>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/values/integers.xml b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/values/integers.xml
new file mode 100644
index 0000000..0c10f84
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/values/integers.xml
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
+
+<resources>
+    <integer name="app_panel_layer">50</integer>
+    <integer name="map_panel_layer">2</integer>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/values/strings.xml b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/values/strings.xml
new file mode 100644
index 0000000..e153e53
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/values/strings.xml
@@ -0,0 +1,23 @@
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
+<resources>
+    <string name="default_config">DEFAULT</string>
+
+    <string-array name="nav_components" translatable="false">
+        <item>com.google.android.apps.maps/com.google.android.maps.MapsActivity</item>
+    </string-array>
+</resources>
diff --git a/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/xml/app_panel.xml b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/xml/app_panel.xml
new file mode 100644
index 0000000..d804340
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/xml/app_panel.xml
@@ -0,0 +1,34 @@
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
+<Panel id="app_panel" defaultVariant="@id/closed" role="@string/default_config" displayId="0">
+    <Variant id="@+id/opened">
+        <Layer layer="@integer/app_panel_layer"/>
+        <Visibility isVisible="true"/>
+        <Alpha alpha="1.0" />
+        <Bounds left="0" bottom="@dimen/bottom_bar_top" width="100%" height="@dimen/app_height" />
+    </Variant>
+    <Variant id="@+id/closed">
+        <Layer layer="@integer/app_panel_layer"/>
+        <Alpha alpha="0.0" />
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/screen_height" width="100%" height="@dimen/app_height" />
+    </Variant>
+
+    <Transitions>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/opened"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/closed"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/xml/map_panel.xml b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/xml/map_panel.xml
new file mode 100644
index 0000000..bc7ba08
--- /dev/null
+++ b/scalable-ui/codelab/TwoPanelWithInsetsRRO/res/xml/map_panel.xml
@@ -0,0 +1,40 @@
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
+<Panel id="map_panel" defaultVariant="@id/opened" role="@array/nav_components" displayId="0">
+    <Variant id="@+id/map_base">
+        <Layer layer="@integer/map_panel_layer"/>
+    </Variant>
+    <Variant id="@+id/opened" parent="@id/map_base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" top="@dimen/map_top" width="100%" height="100%" />
+    </Variant>
+    <Variant id="@+id/opened_overlap" parent="@id/map_base">
+        <Visibility isVisible="true"/>
+        <Bounds left="0" top="@dimen/map_top" width="100%" height="100%" />
+        <!--  (screen_height) 1920 - (bottom_bar_top) 1836 = 833 -->
+        <Insets left="0" top="0" right="0" bottom="833" />
+    </Variant>
+    <Variant id="@+id/closed" parent="@id/map_base">
+        <Visibility isVisible="false"/>
+        <Bounds left="0" top="@dimen/map_top" width="100%" height="100%" />
+    </Variant>
+
+    <Transitions defaultInterpolator="@android:anim/bounce_interpolator" defaultDuration="700">
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=app_panel" toVariant="@id/opened_overlap"/>
+        <Transition onEvent="_System_TaskOpenEvent" onEventTokens="panelId=map_panel" toVariant="@id/opened"/>
+        <Transition onEvent="_System_OnHomeEvent" toVariant="@id/opened"/>
+    </Transitions>
+</Panel>
\ No newline at end of file
diff --git a/scalable-ui/test/app/ScalableUiTestApp/Android.bp b/scalable-ui/test/app/ScalableUiTestApp/Android.bp
new file mode 100644
index 0000000..1dc3f44
--- /dev/null
+++ b/scalable-ui/test/app/ScalableUiTestApp/Android.bp
@@ -0,0 +1,53 @@
+//
+// Copyright (C) 2025 Google Inc.
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
+    name: "ScalableUiTestApp",
+
+    srcs: ["src/**/*.java"],
+
+    manifest: "AndroidManifest.xml",
+
+    platform_apis: true,
+    certificate: "platform",
+    static_libs: [
+        "androidx-constraintlayout_constraintlayout-solver",
+        "androidx-constraintlayout_constraintlayout",
+        "androidx.lifecycle_lifecycle-extensions",
+        "androidx.car.app_app",
+        "androidx.core_core",
+        "car-ui-lib",
+        "com.google.android.material_material",
+    ],
+
+    libs: [
+        "android.car",
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
diff --git a/scalable-ui/test/app/ScalableUiTestApp/AndroidManifest.xml b/scalable-ui/test/app/ScalableUiTestApp/AndroidManifest.xml
new file mode 100644
index 0000000..3fe947f
--- /dev/null
+++ b/scalable-ui/test/app/ScalableUiTestApp/AndroidManifest.xml
@@ -0,0 +1,58 @@
+<!--
+  ~ Copyright (C) 2025 Google Inc.
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
+    package="com.android.car.insets"
+    coreApp="true">
+
+    <!-- Permission to get car driving state -->
+    <uses-permission android:name="android.car.permission.CAR_DRIVING_STATE"/>
+
+    <application
+        android:label="Scalable UI test APP"
+        android:theme="@style/Theme.CarUi.NoToolbar"
+        tools:replace="android:label,android:theme"
+        tools:node="merge">
+        <uses-library android:name="com.android.oem.tokens" android:required="false"/>
+
+        <activity
+            android:name=".InsetsTestActivity"
+            android:exported="true"
+            android:configChanges="density|fontScale|keyboard|keyboardHidden|layoutDirection|locale|mcc|mnc|navigation|orientation|screenLayout|screenSize|smallestScreenSize|touchscreen|uiMode"
+            android:excludeFromRecents="true">
+            <meta-data android:name="distractionOptimized" android:value="true"/>
+            <intent-filter>
+                <action android:name="android.intent.action.MAIN"/>
+                <category android:name="android.intent.category.DEFAULT"/>
+            </intent-filter>
+        </activity>
+
+        <activity android:name="com.android.car.blur.BlurTestActivity"
+            android:exported="true"
+            android:configChanges="density|fontScale|keyboard|keyboardHidden|layoutDirection|locale|mcc|mnc|navigation|orientation|screenLayout|screenSize|smallestScreenSize|touchscreen|uiMode"
+            android:theme="@style/Theme.BlurExample.BlurTestActivityTheme"
+            android:excludeFromRecents="true">
+            <meta-data android:name="distractionOptimized" android:value="true"/>
+            <intent-filter>
+                <action android:name="android.intent.action.MAIN"/>
+                <category android:name="android.intent.category.DEFAULT"/>
+            </intent-filter>
+        </activity>
+
+    </application>
+</manifest>
diff --git a/scalable-ui/test/app/ScalableUiTestApp/res/layout/blur_test_activity.xml b/scalable-ui/test/app/ScalableUiTestApp/res/layout/blur_test_activity.xml
new file mode 100644
index 0000000..0d41193
--- /dev/null
+++ b/scalable-ui/test/app/ScalableUiTestApp/res/layout/blur_test_activity.xml
@@ -0,0 +1,58 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 Google Inc.
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
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:orientation="vertical"
+    android:padding="16dp"
+    android:gravity="center"
+    tools:context=".BlurTestActivity">
+
+    <TextView
+        android:id="@+id/content_text"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:text="This is the content INSIDE the Activity window.\nTry 'Blur Within' to see this text get potentially blurred by the window background."
+        android:textSize="18sp"
+        android:gravity="center"
+        android:padding="20dp"
+        android:layout_marginBottom="30dp"
+        android:background="#DDFFFFFF" />
+
+    <Button
+        android:id="@+id/button_blur_behind"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:text="Enable Blur Behind Window"
+        android:layout_marginBottom="16dp"/>
+
+    <Button
+        android:id="@+id/button_blur_within"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:text="Enable Blur Within Window"
+        android:layout_marginBottom="16dp"/>
+
+    <Button
+        android:id="@+id/button_clear_blurs"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:text="Disable / Clear Blurs"/>
+
+</LinearLayout>
\ No newline at end of file
diff --git a/scalable-ui/test/app/ScalableUiTestApp/res/layout/insets_test_activity.xml b/scalable-ui/test/app/ScalableUiTestApp/res/layout/insets_test_activity.xml
new file mode 100644
index 0000000..fa62be3
--- /dev/null
+++ b/scalable-ui/test/app/ScalableUiTestApp/res/layout/insets_test_activity.xml
@@ -0,0 +1,113 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 Google Inc.
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
+    android:id="@+id/root_view"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:background="#FAFAFA">
+
+    <ScrollView
+        android:id="@+id/content_frame"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:clipToPadding="false">
+
+        <LinearLayout
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:gravity="center_horizontal"
+            android:orientation="vertical"
+            android:padding="16dp">
+
+            <TextView
+                android:id="@+id/status_bar_inset"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:layout_marginBottom="8dp"
+                android:background="#EEEEEE"
+                android:padding="8dp"
+                android:text="Status Bar Inset:"
+                android:textSize="16sp" />
+
+            <TextView
+                android:id="@+id/nav_bar_inset"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:layout_marginBottom="8dp"
+                android:background="#EEEEEE"
+                android:padding="8dp"
+                android:text="Navigation Bar Inset:"
+                android:textSize="16sp" />
+
+            <TextView
+                android:id="@+id/ime_inset"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:layout_marginBottom="8dp"
+                android:background="#EEEEEE"
+                android:padding="8dp"
+                android:text="IME Inset:"
+                android:textSize="16sp" />
+
+            <TextView
+                android:id="@+id/system_gesture_inset"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:layout_marginBottom="8dp"
+                android:background="#EEEEEE"
+                android:padding="8dp"
+                android:text="System Gesture Inset:"
+                android:textSize="16sp" />
+
+            <TextView
+                android:id="@+id/tappable_element_inset"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:layout_marginBottom="8dp"
+                android:background="#EEEEEE"
+                android:padding="8dp"
+                android:text="Tappable Element Inset:"
+                android:textSize="16sp" />
+
+            <TextView
+                android:id="@+id/system_bar_inset"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:layout_marginBottom="8dp"
+                android:background="#EEEEEE"
+                android:padding="8dp"
+                android:text="System Bar Inset:"
+                android:textSize="16sp" />
+
+            <!--            <TextView-->
+            <!--                android:id="@+id/system_overlay_inset"-->
+            <!--                android:layout_width="match_parent"-->
+            <!--                android:layout_height="wrap_content"-->
+            <!--                android:text="System Bar Inset:"-->
+            <!--                android:textSize="16sp"-->
+            <!--                android:padding="8dp"-->
+            <!--                android:background="#EEEEEE"-->
+            <!--                android:layout_marginBottom="8dp" />-->
+
+
+        </LinearLayout>
+    </ScrollView>
+    <com.android.car.insets.FrostedGlassView
+        android:id="@+id/frostedGlassView"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent" />
+</FrameLayout>
diff --git a/scalable-ui/test/app/ScalableUiTestApp/res/values/styles.xml b/scalable-ui/test/app/ScalableUiTestApp/res/values/styles.xml
new file mode 100644
index 0000000..50ff687
--- /dev/null
+++ b/scalable-ui/test/app/ScalableUiTestApp/res/values/styles.xml
@@ -0,0 +1,32 @@
+<?xml version="1.0" encoding="utf-8" ?>
+<!--
+  ~ Copyright (C) 2025 Google Inc.
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
+    <style name="StubCarLauncherTheme" parent="Theme.CarUi.NoToolbar">
+    </style>
+
+    <style name="Theme.BlurExample" parent="Theme.MaterialComponents.DayNight.DarkActionBar">
+    </style>
+
+    <style name="Theme.BlurExample.BlurTestActivityTheme" parent="Theme.AppCompat.Dialog">
+        <item name="android:windowNoTitle">true</item>
+        <item name="android:backgroundDimEnabled">false</item>
+    </style>
+
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/test/app/ScalableUiTestApp/res/values/themes.xml b/scalable-ui/test/app/ScalableUiTestApp/res/values/themes.xml
new file mode 100644
index 0000000..dad0a0d
--- /dev/null
+++ b/scalable-ui/test/app/ScalableUiTestApp/res/values/themes.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="utf-8" ?>
+<!--
+  ~ Copyright (C) 2025 Google Inc.
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
+<resources xmlns:tools="http://schemas.android.com/tools">
+    <!-- Base application theme. -->
+    <style name="Base.Theme.TestScalable" parent="Theme.Material3.DayNight.NoActionBar">
+
+    </style>
+
+    <style name="Theme.TestScalable" parent="Base.Theme.TestScalable" >
+        <item name="android:windowDrawsSystemBarBackgrounds">true</item>
+        <item name="android:statusBarColor">@android:color/transparent</item>
+        <item name="android:navigationBarColor">@android:color/transparent</item>
+        <item name="android:windowSplashScreenAnimatedIcon">@android:color/transparent</item>
+        <item name="android:windowSplashScreenAnimationDuration">0</item>
+    </style>
+</resources>
\ No newline at end of file
diff --git a/scalable-ui/test/app/ScalableUiTestApp/src/com/android/car/blur/BlurTestActivity.java b/scalable-ui/test/app/ScalableUiTestApp/src/com/android/car/blur/BlurTestActivity.java
new file mode 100644
index 0000000..5d1c86b
--- /dev/null
+++ b/scalable-ui/test/app/ScalableUiTestApp/src/com/android/car/blur/BlurTestActivity.java
@@ -0,0 +1,125 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+package com.android.car.blur;
+
+import androidx.appcompat.app.AppCompatActivity;
+import androidx.core.content.ContextCompat;
+
+import android.graphics.Color;
+import android.graphics.drawable.ColorDrawable;
+import android.os.Build;
+import android.os.Bundle;
+import android.view.WindowManager;
+import android.widget.Button;
+import android.widget.Toast;
+import android.util.Log;
+
+import com.android.car.insets.R;
+
+public class BlurTestActivity extends AppCompatActivity {
+
+    private static final String TAG = "BlurTestActivity";
+    private static final int BLUR_RADIUS = 25;
+            // Adjust blur intensity (0-100 might be typical range)
+
+    private Button buttonBlurBehind;
+    private Button buttonBlurWithin;
+    private Button buttonClearBlurs;
+    private ColorDrawable originalWindowBackground; // To restore original background
+
+    @Override
+    protected void onCreate(Bundle savedInstanceState) {
+        super.onCreate(savedInstanceState);
+        setContentView(R.layout.blur_test_activity);
+
+        buttonBlurBehind = findViewById(R.id.button_blur_behind);
+        buttonBlurWithin = findViewById(R.id.button_blur_within);
+        buttonClearBlurs = findViewById(R.id.button_clear_blurs);
+
+        // Store the original background if it's a ColorDrawable
+        if (getWindow().getDecorView().getBackground() instanceof ColorDrawable) {
+            originalWindowBackground = (ColorDrawable) getWindow().getDecorView().getBackground();
+        } else {
+            // Set a default fallback if needed, or handle other drawable types
+            originalWindowBackground = new ColorDrawable(ContextCompat.getColor(this,
+                    android.R.color.background_light)); // Example fallback
+        }
+
+        buttonBlurBehind.setOnClickListener(v -> {
+            Log.d(TAG, "Attempting to enable Blur Behind");
+            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
+                getWindow().addFlags(WindowManager.LayoutParams.FLAG_BLUR_BEHIND);
+                getWindow().getAttributes().setBlurBehindRadius(BLUR_RADIUS);
+                getWindow().setAttributes(getWindow().getAttributes());
+                Toast.makeText(this, "Blur Behind Enabled (Radius: " + BLUR_RADIUS + ")",
+                        Toast.LENGTH_SHORT).show();
+                Log.d(TAG, "Blur Behind flags/radius set.");
+                // IMPORTANT: For FLAG_BLUR_BEHIND to work, the Activity theme
+                // usually needs to be translucent or floating. See Manifest/Theme section below.
+            } else {
+                Toast.makeText(this, "Blur Behind requires Android 12 (API 31+)",
+                        Toast.LENGTH_LONG).show();
+                Log.w(TAG, "Blur Behind requires Android 12+");
+            }
+        });
+
+        buttonBlurWithin.setOnClickListener(v -> {
+            Log.d(TAG, "Attempting to enable Blur Within");
+            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
+                // IMPORTANT: For setBackgroundBlurRadius to have a visible effect,
+                // the window *must* have a translucent background DRAWABLE.
+                // Let's set a semi-transparent background color.
+                getWindow().setBackgroundDrawable(new ColorDrawable(
+                        Color.parseColor("#80FFFFFF"))); // Example: 50% transparent white
+                // Now apply the blur radius
+                getWindow().setBackgroundBlurRadius(BLUR_RADIUS);
+                Toast.makeText(this, "Blur Within Enabled (Radius: " + BLUR_RADIUS + ")",
+                        Toast.LENGTH_SHORT).show();
+                Log.d(TAG, "Background blur radius set.");
+            } else {
+                Toast.makeText(this, "Background Blur requires Android 12 (API 31+)",
+                        Toast.LENGTH_LONG).show();
+                Log.w(TAG, "Background Blur requires Android 12+");
+            }
+        });
+
+        buttonClearBlurs.setOnClickListener(v -> {
+            Log.d(TAG, "Attempting to clear blurs");
+            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
+                // Clear Blur Behind flag and radius
+                getWindow().clearFlags(WindowManager.LayoutParams.FLAG_BLUR_BEHIND);
+                getWindow().getAttributes().setBlurBehindRadius(0); // Reset radius
+
+                // Clear Background Blur radius
+                getWindow().setBackgroundBlurRadius(0); // Reset radius
+
+                // Restore original background drawable if possible
+                getWindow().setBackgroundDrawable(originalWindowBackground);
+
+                // Re-apply attributes just in case
+                getWindow().setAttributes(getWindow().getAttributes());
+
+                Toast.makeText(this, "Blurs Cleared", Toast.LENGTH_SHORT).show();
+                Log.d(TAG, "Blurs cleared.");
+            } else {
+                Toast.makeText(this, "Blurs only applicable on Android 12+",
+                        Toast.LENGTH_SHORT).show();
+                Log.w(TAG, "Clear blurs called on pre-Android 12");
+            }
+        });
+    }
+}
\ No newline at end of file
diff --git a/scalable-ui/test/app/ScalableUiTestApp/src/com/android/car/insets/InsetsTestActivity.java b/scalable-ui/test/app/ScalableUiTestApp/src/com/android/car/insets/InsetsTestActivity.java
new file mode 100644
index 0000000..ce40c94
--- /dev/null
+++ b/scalable-ui/test/app/ScalableUiTestApp/src/com/android/car/insets/InsetsTestActivity.java
@@ -0,0 +1,106 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+package com.android.car.insets;
+
+import android.graphics.Insets;
+import android.os.Bundle;
+import android.util.Log;
+import android.view.View;
+import android.view.WindowInsets;
+import android.view.WindowInsets.Type;
+import android.widget.FrameLayout;
+import android.widget.TextView;
+
+import androidx.annotation.Nullable;
+import androidx.appcompat.app.AppCompatActivity;
+
+public class InsetsTestActivity extends AppCompatActivity {
+
+    private static final String TAG = "InsetsTestActivity";
+
+    private TextView statusBarText;
+    private TextView navBarText;
+    private TextView imeText;
+    private TextView systemGestureText;
+    private TextView tappableElementText;
+    private TextView systemBarText;
+
+    private FrameLayout contentLayout;
+
+    @Override
+    protected void onCreate(@Nullable Bundle savedInstanceState) {
+        super.onCreate(savedInstanceState);
+        setContentView(R.layout.insets_test_activity);
+
+        statusBarText = findViewById(R.id.status_bar_inset);
+        navBarText = findViewById(R.id.nav_bar_inset);
+        imeText = findViewById(R.id.ime_inset);
+        systemGestureText = findViewById(R.id.system_gesture_inset);
+        tappableElementText = findViewById(R.id.tappable_element_inset);
+        systemBarText = findViewById(R.id.system_bar_inset);
+        contentLayout = findViewById(R.id.content_frame);
+
+        View rootView = findViewById(R.id.root_view);
+        rootView.setOnApplyWindowInsetsListener((view, insets) -> {
+            if (insets == null) return view.onApplyWindowInsets(insets);
+
+            Insets statusBar = insets.getInsets(Type.statusBars());
+            Insets navBar = insets.getInsets(Type.navigationBars());
+            Insets ime = insets.getInsets(Type.ime());
+            Insets systemGesture = insets.getInsets(Type.systemGestures());
+            Insets tappableElement = insets.getInsets(Type.tappableElement());
+            Insets systemBars = insets.getInsets(Type.systemBars());
+            Insets systemOverlay = insets.getInsets(Type.systemOverlays());
+            Insets all = insets.getInsets(Type.all());
+
+            Log.d(TAG, "Insets changed:");
+            Log.d(TAG, "Status Bar Inset: " + statusBar.toString());
+            Log.d(TAG, "Navigation Bar Inset: " + navBar.toString());
+            Log.d(TAG, "IME Inset: " + ime.toString());
+            Log.d(TAG, "System Gesture Inset: " + systemGesture.toString());
+            Log.d(TAG, "Tappable Element Inset: " + tappableElement.toString());
+            Log.d(TAG, "System Bars Inset: " + systemBars.toString());
+            Log.d(TAG, "System overlay Inset: " + systemOverlay.toString());
+            Log.d(TAG, "ALL Inset: " + all.toString());
+
+            // Set text
+            statusBarText.setText("Status Bar Inset: " + statusBar);
+            navBarText.setText("Navigation Bar Inset: " + navBar);
+            imeText.setText("IME Inset: " + ime);
+            systemGestureText.setText("System Gesture Inset: " + systemGesture);
+            tappableElementText.setText("Tappable Element Inset: " + tappableElement);
+            systemBarText.setText("System Bar Inset (Combined): " + systemBars);
+
+            // Apply padding with max of all insets per side
+            int paddingTop = Math.max(statusBar.top, Math.max(systemGesture.top, systemBars.top));
+            int paddingBottom = Math.max(navBar.bottom, Math.max(systemGesture.bottom, ime.bottom));
+            int paddingLeft = Math.max(navBar.left, Math.max(systemGesture.left, systemBars.left));
+            int paddingRight = Math.max(navBar.right,
+                    Math.max(systemGesture.right, systemBars.right));
+
+            contentLayout.setPadding(paddingLeft, paddingTop, paddingRight, paddingBottom);
+
+            Log.d(TAG, "Applied Padding - Left: " + paddingLeft + ", Top: " + paddingTop +
+                    ", Right: " + paddingRight + ", Bottom: " + paddingBottom);
+
+            return view.onApplyWindowInsets(insets);
+        });
+
+        // Request insets manually if needed
+        rootView.requestApplyInsets();
+    }
+}
```

