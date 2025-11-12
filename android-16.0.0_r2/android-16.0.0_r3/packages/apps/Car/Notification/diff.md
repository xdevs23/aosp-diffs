```diff
diff --git a/Android.bp b/Android.bp
index bf8c05eb..a9529b40 100644
--- a/Android.bp
+++ b/Android.bp
@@ -42,12 +42,17 @@ android_app {
         "androidx.palette_palette",
         "car-assist-client-lib",
         "car-ui-lib-no-overlayable",
-        "car-resource-common",
         "androidx-constraintlayout_constraintlayout",
         "car-uxr-client-lib-no-overlayable",
+        "oem-token-lib",
     ],
 
-    libs: ["android.car-system-stubs"],
+    libs: [
+        "android.car-system-stubs",
+        "token-shared-lib-prebuilt",
+    ],
+
+    enforce_uses_libs: false,
 
     manifest: "AndroidManifest.xml",
 
@@ -84,12 +89,17 @@ android_app {
         "androidx.palette_palette",
         "car-assist-client-lib",
         "car-ui-lib-no-overlayable",
-        "car-resource-common",
         "androidx-constraintlayout_constraintlayout",
         "car-uxr-client-lib-no-overlayable",
+        "oem-token-lib",
+    ],
+
+    libs: [
+        "android.car-system-stubs",
+        "token-shared-lib-prebuilt",
     ],
 
-    libs: ["android.car-system-stubs"],
+    enforce_uses_libs: false,
 }
 
 // As Lib
@@ -115,12 +125,18 @@ android_library {
         "androidx.palette_palette",
         "car-assist-client-lib",
         "car-ui-lib-no-overlayable",
-        "car-resource-common",
         "androidx-constraintlayout_constraintlayout",
         "car-uxr-client-lib-no-overlayable",
+        "oem-token-lib",
     ],
 
-    libs: ["android.car-system-stubs"],
+    libs: [
+        "android.car-system-stubs",
+        "token-shared-lib-prebuilt",
+    ],
+
+    enforce_uses_libs: false,
+
     // TODO(b/319708040): re-enable use_resource_processor
     use_resource_processor: false,
 }
@@ -134,10 +150,17 @@ android_library {
     manifest: "AndroidManifest-res.xml",
     use_resource_processor: true,
     static_libs: [
-        "car-resource-common",
         "car-ui-lib-no-overlayable",
         "car-uxr-client-lib-no-overlayable",
+        "oem-token-lib",
     ],
+
+    libs: [
+        "token-shared-lib-prebuilt",
+    ],
+
+    enforce_uses_libs: false,
+
     lint: {
         disabled_checks: ["MissingClass"],
     },
@@ -173,12 +196,17 @@ android_library {
         "androidx.palette_palette",
         "car-assist-client-lib",
         "car-ui-lib-no-overlayable",
-        "car-resource-common",
         "androidx-constraintlayout_constraintlayout",
         "car-uxr-client-lib-no-overlayable",
+        "oem-token-lib",
+    ],
+
+    libs: [
+        "android.car-system-stubs",
+        "token-shared-lib-prebuilt",
     ],
 
-    libs: ["android.car-system-stubs"],
+    enforce_uses_libs: false,
 
     dxflags: ["--multi-dex"],
 
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index b5034216..ab4bd2f1 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -51,6 +51,7 @@
     <application android:name=".NotificationApplication"
                  android:label="@string/app_label"
                  android:icon="@mipmap/ic_launcher">
+        <uses-library android:name="com.android.oem.tokens" android:required="false"/>
         <activity android:name=".CarNotificationCenterActivity"
                   android:theme="@style/Theme.DeviceDefault.NoActionBar.Notification"
                   android:launchMode="singleInstance"
diff --git a/res/color/call_accept_button.xml b/res/color/call_accept_button.xml
new file mode 100644
index 00000000..4a0c4047
--- /dev/null
+++ b/res/color/call_accept_button.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorGreen"/>
+</selector>
diff --git a/res/color/call_accept_button_text.xml b/res/color/call_accept_button_text.xml
new file mode 100644
index 00000000..b30fd9d4
--- /dev/null
+++ b/res/color/call_accept_button_text.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnGreen"/>
+</selector>
diff --git a/res/color/call_decline_button.xml b/res/color/call_decline_button.xml
new file mode 100644
index 00000000..396dc878
--- /dev/null
+++ b/res/color/call_decline_button.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorError"/>
+</selector>
diff --git a/res/color/call_decline_button_text.xml b/res/color/call_decline_button_text.xml
new file mode 100644
index 00000000..028df2bb
--- /dev/null
+++ b/res/color/call_decline_button_text.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnError"/>
+</selector>
diff --git a/res/color/card_background.xml b/res/color/card_background.xml
new file mode 100644
index 00000000..66bf04aa
--- /dev/null
+++ b/res/color/card_background.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceContainerHigh"/>
+</selector>
diff --git a/res/color/clear_all_button_background_color.xml b/res/color/clear_all_button_background_color.xml
new file mode 100644
index 00000000..18941bf8
--- /dev/null
+++ b/res/color/clear_all_button_background_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSecondaryContainer"/>
+</selector>
diff --git a/res/color/count_text.xml b/res/color/count_text.xml
new file mode 100644
index 00000000..39b0785e
--- /dev/null
+++ b/res/color/count_text.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnPrimary"/>
+</selector>
diff --git a/res/color/dark_icon_tint.xml b/res/color/dark_icon_tint.xml
new file mode 100644
index 00000000..39b0785e
--- /dev/null
+++ b/res/color/dark_icon_tint.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnPrimary"/>
+</selector>
diff --git a/res/color/emergency_background_color.xml b/res/color/emergency_background_color.xml
new file mode 100644
index 00000000..bc45304c
--- /dev/null
+++ b/res/color/emergency_background_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorErrorContainer"/>
+</selector>
diff --git a/res/color/emergency_primary_text_color.xml b/res/color/emergency_primary_text_color.xml
new file mode 100644
index 00000000..0015eaca
--- /dev/null
+++ b/res/color/emergency_primary_text_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnErrorContainer"/>
+</selector>
diff --git a/res/color/emergency_secondary_text_color.xml b/res/color/emergency_secondary_text_color.xml
new file mode 100644
index 00000000..028df2bb
--- /dev/null
+++ b/res/color/emergency_secondary_text_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnError"/>
+</selector>
diff --git a/res/color/first_action_button_text_color.xml b/res/color/first_action_button_text_color.xml
new file mode 100644
index 00000000..39b0785e
--- /dev/null
+++ b/res/color/first_action_button_text_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnPrimary"/>
+</selector>
diff --git a/res/color/group_notification_background_color.xml b/res/color/group_notification_background_color.xml
new file mode 100644
index 00000000..5180b582
--- /dev/null
+++ b/res/color/group_notification_background_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceContainerHighest"/>
+</selector>
diff --git a/res/color/ic_launcher_background.xml b/res/color/ic_launcher_background.xml
new file mode 100644
index 00000000..f063c10d
--- /dev/null
+++ b/res/color/ic_launcher_background.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorPrimary"/>
+</selector>
diff --git a/res/color/icon_tint.xml b/res/color/icon_tint.xml
new file mode 100644
index 00000000..d1178591
--- /dev/null
+++ b/res/color/icon_tint.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSecondaryContainer"/>
+</selector>
diff --git a/res/color/information_background_color.xml b/res/color/information_background_color.xml
new file mode 100644
index 00000000..66bf04aa
--- /dev/null
+++ b/res/color/information_background_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceContainerHigh"/>
+</selector>
diff --git a/res/color/information_primary_text_color.xml b/res/color/information_primary_text_color.xml
new file mode 100644
index 00000000..dca5d37c
--- /dev/null
+++ b/res/color/information_primary_text_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/information_secondary_text_color.xml b/res/color/information_secondary_text_color.xml
new file mode 100644
index 00000000..1ff2f30e
--- /dev/null
+++ b/res/color/information_secondary_text_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurfaceVariant"/>
+</selector>
diff --git a/res/color/notification_accent_color.xml b/res/color/notification_accent_color.xml
new file mode 100644
index 00000000..d1178591
--- /dev/null
+++ b/res/color/notification_accent_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSecondaryContainer"/>
+</selector>
diff --git a/res/color/notification_background_color.xml b/res/color/notification_background_color.xml
new file mode 100644
index 00000000..66bf04aa
--- /dev/null
+++ b/res/color/notification_background_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceContainerHigh"/>
+</selector>
diff --git a/res/color/notification_list_divider_color.xml b/res/color/notification_list_divider_color.xml
new file mode 100644
index 00000000..dca5d37c
--- /dev/null
+++ b/res/color/notification_list_divider_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/primary_text_color.xml b/res/color/primary_text_color.xml
new file mode 100644
index 00000000..dca5d37c
--- /dev/null
+++ b/res/color/primary_text_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/res/color/progress_bar_bg_color.xml b/res/color/progress_bar_bg_color.xml
new file mode 100644
index 00000000..865ade66
--- /dev/null
+++ b/res/color/progress_bar_bg_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorSurfaceVariant"/>
+</selector>
diff --git a/res/color/progress_bar_color.xml b/res/color/progress_bar_color.xml
new file mode 100644
index 00000000..f063c10d
--- /dev/null
+++ b/res/color/progress_bar_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorPrimary"/>
+</selector>
diff --git a/res/color/secondary_text_color.xml b/res/color/secondary_text_color.xml
new file mode 100644
index 00000000..1ff2f30e
--- /dev/null
+++ b/res/color/secondary_text_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnSurfaceVariant"/>
+</selector>
diff --git a/res/color/unmute_button.xml b/res/color/unmute_button.xml
new file mode 100644
index 00000000..f063c10d
--- /dev/null
+++ b/res/color/unmute_button.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorPrimary"/>
+</selector>
diff --git a/res/color/warning_background_color.xml b/res/color/warning_background_color.xml
new file mode 100644
index 00000000..bf5d7a83
--- /dev/null
+++ b/res/color/warning_background_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorYellow"/>
+</selector>
diff --git a/res/color/warning_primary_text_color.xml b/res/color/warning_primary_text_color.xml
new file mode 100644
index 00000000..85e8bc0f
--- /dev/null
+++ b/res/color/warning_primary_text_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnYellow"/>
+</selector>
diff --git a/res/color/warning_secondary_text_color.xml b/res/color/warning_secondary_text_color.xml
new file mode 100644
index 00000000..c045cc22
--- /dev/null
+++ b/res/color/warning_secondary_text_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+    Copyright (C) 2025 The Android Open Source Project
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
+-->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorYellowContainer"/>
+</selector>
diff --git a/res/drawable/action_button_background.xml b/res/drawable/action_button_background.xml
index 5c8b7059..c1439919 100644
--- a/res/drawable/action_button_background.xml
+++ b/res/drawable/action_button_background.xml
@@ -17,18 +17,18 @@
 <selector xmlns:android="http://schemas.android.com/apk/res/android">
     <item android:state_focused="true">
         <shape android:shape="rectangle">
-            <corners android:radius="@dimen/action_button_radius"/>
+            <corners android:radius="?oemShapeCornerLarge"/>
             <solid android:color="@color/car_ui_rotary_focus_fill_color"/>
             <stroke android:width="@dimen/car_ui_rotary_focus_stroke_width"
                     android:color="@color/car_ui_rotary_focus_stroke_color"/>
         </shape>
     </item>
     <item>
-        <ripple android:color="@color/notification_accent_color">
+        <ripple android:color="?oemColorOnSecondaryContainer">
             <item>
                 <shape android:shape="rectangle">
-                    <corners android:radius="@dimen/action_button_radius"/>
-                    <solid android:color="@color/action_button_background_color"/>
+                    <corners android:radius="?oemShapeCornerLarge"/>
+                    <solid android:color="?oemColorSecondaryContainer"/>
                 </shape>
             </item>
         </ripple>
diff --git a/res/drawable/call_action_button_background.xml b/res/drawable/call_action_button_background.xml
index 8849c1e0..bb794722 100644
--- a/res/drawable/call_action_button_background.xml
+++ b/res/drawable/call_action_button_background.xml
@@ -17,17 +17,17 @@
 <selector xmlns:android="http://schemas.android.com/apk/res/android">
     <item android:state_focused="true">
         <shape android:shape="rectangle">
-            <corners android:radius="@dimen/action_button_radius"/>
+            <corners android:radius="?oemShapeCornerLarge"/>
             <solid android:color="@color/car_ui_rotary_focus_fill_color"/>
             <stroke android:width="@dimen/car_ui_rotary_focus_stroke_width"
                     android:color="@color/car_ui_rotary_focus_stroke_color"/>
         </shape>
     </item>
     <item>
-        <ripple android:color="@color/notification_accent_color">
+        <ripple android:color="?oemColorOnSecondaryContainer">
             <item>
                 <shape android:shape="rectangle">
-                    <corners android:radius="@dimen/action_button_radius"/>
+                    <corners android:radius="?oemShapeCornerLarge"/>
                 </shape>
             </item>
         </ripple>
diff --git a/res/drawable/clear_all_button_background.xml b/res/drawable/clear_all_button_background.xml
index 9ea214a4..806a5e79 100644
--- a/res/drawable/clear_all_button_background.xml
+++ b/res/drawable/clear_all_button_background.xml
@@ -17,7 +17,7 @@
 <selector xmlns:android="http://schemas.android.com/apk/res/android">
     <item android:state_focused="true">
         <shape android:shape="rectangle">
-            <corners android:radius="@dimen/clear_all_button_radius"/>
+            <corners android:radius="?oemShapeCornerExtraLarge"/>
             <solid android:color="@color/car_ui_rotary_focus_fill_color"/>
             <stroke android:width="@dimen/car_ui_rotary_focus_stroke_width"
                     android:color="@color/car_ui_rotary_focus_stroke_color"/>
@@ -27,7 +27,7 @@
         <ripple android:color="@color/notification_ripple_untinted_color">
             <item>
                 <shape android:shape="rectangle">
-                    <corners android:radius="@dimen/clear_all_button_radius"/>
+                    <corners android:radius="?oemShapeCornerExtraLarge"/>
                     <solid android:color="@color/clear_all_button_background_color"/>
                 </shape>
             </item>
diff --git a/res/drawable/headsup_scrim.xml b/res/drawable/headsup_scrim.xml
index c9925314..bb5698a5 100644
--- a/res/drawable/headsup_scrim.xml
+++ b/res/drawable/headsup_scrim.xml
@@ -18,7 +18,7 @@
     xmlns:android="http://schemas.android.com/apk/res/android"
     android:shape="rectangle">
     <gradient
-        android:startColor="@android:color/black"
+        android:startColor="?oemColorSurface"
         android:endColor="@android:color/transparent"
         android:angle="270" />
 </shape>
diff --git a/res/drawable/headsup_scrim_bottom.xml b/res/drawable/headsup_scrim_bottom.xml
index 1724ef00..7765225a 100644
--- a/res/drawable/headsup_scrim_bottom.xml
+++ b/res/drawable/headsup_scrim_bottom.xml
@@ -18,7 +18,7 @@
     xmlns:android="http://schemas.android.com/apk/res/android"
     android:shape="rectangle">
     <gradient
-        android:startColor="@android:color/black"
+        android:startColor="?oemColorSurface"
         android:endColor="@android:color/transparent"
         android:angle="90" />
 </shape>
diff --git a/res/drawable/ic_launcher_foreground.xml b/res/drawable/ic_launcher_foreground.xml
index cdc1a09e..be70fd4d 100644
--- a/res/drawable/ic_launcher_foreground.xml
+++ b/res/drawable/ic_launcher_foreground.xml
@@ -25,6 +25,6 @@
            android:translateY="68.02">
         <path
             android:pathData="M179,278.06C185.38,278.06 190.79,275.84 195.23,271.4C199.67,266.68 201.89,261.27 201.89,255.16H155.69C155.69,261.27 158.05,266.68 162.77,271.4C167.48,275.84 172.9,278.06 179,278.06ZM98.66,230.19H258.92V205.63H242.27V157.35C242.27,140.7 237.83,125.43 228.95,111.56C220.35,97.68 208.14,89.22 192.32,86.17V73.26C192.32,69.65 191.07,66.6 188.57,64.1C186.08,61.33 182.88,59.94 179,59.94C175.12,59.94 171.79,61.33 169.01,64.1C166.51,66.6 165.26,69.65 165.26,73.26V86.17C149.45,89.22 137.1,97.4 128.22,110.72C119.61,124.04 115.31,138.75 115.31,154.85V205.63H98.66V230.19ZM139.87,205.63V152.35C139.87,141.25 143.62,131.68 151.11,123.63C158.6,115.58 167.9,111.56 179,111.56C189.82,111.56 198.98,115.58 206.47,123.63C213.96,131.68 217.71,141.25 217.71,152.35V205.63H139.87ZM179,338C155.69,338 133.77,333.56 113.23,324.68C92.7,315.8 74.8,303.73 59.53,288.46C44.27,273.2 32.2,255.3 23.32,234.77C14.44,214.23 10,192.31 10,169C10,145.41 14.44,123.35 23.32,102.82C32.2,82.28 44.27,64.52 59.53,49.53C74.8,34.27 92.7,22.2 113.23,13.32C133.77,4.44 155.69,0 179,0C202.59,0 224.65,4.44 245.18,13.32C265.72,22.2 283.48,34.27 298.46,49.53C313.73,64.52 325.8,82.28 334.68,102.82C343.56,123.35 348,145.41 348,169C348,192.31 343.56,214.23 334.68,234.77C325.8,255.3 313.73,273.2 298.46,288.46C283.48,303.73 265.58,315.8 244.77,324.68C224.23,333.56 202.31,338 179,338ZM179,309.7C218.13,309.7 251.29,295.96 278.48,268.48C305.96,241.01 319.7,207.85 319.7,169C319.7,129.87 305.96,96.71 278.48,69.51C251.29,42.04 218.13,28.31 179,28.31C140.15,28.31 106.99,42.04 79.51,69.51C52.04,96.71 38.31,129.87 38.31,169C38.31,207.85 52.04,241.01 79.51,268.48C106.99,295.96 140.15,309.7 179,309.7Z"
-            android:fillColor="#ffffff"/>
+            android:fillColor="?oemColorOnSurface"/>
     </group>
 </vector>
\ No newline at end of file
diff --git a/res/layout/basic_headsup_notification_template.xml b/res/layout/basic_headsup_notification_template.xml
index 57c3df53..839d9a65 100644
--- a/res/layout/basic_headsup_notification_template.xml
+++ b/res/layout/basic_headsup_notification_template.xml
@@ -23,7 +23,6 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/HeadsUpNotificationCard">
 
         <RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
diff --git a/res/layout/basic_notification_template.xml b/res/layout/basic_notification_template.xml
index e9574bff..f41fd8bf 100644
--- a/res/layout/basic_notification_template.xml
+++ b/res/layout/basic_notification_template.xml
@@ -23,7 +23,6 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/NotificationCard">
 
         <RelativeLayout
diff --git a/res/layout/call_headsup_notification_template.xml b/res/layout/call_headsup_notification_template.xml
index 3ed42455..bbf780c5 100644
--- a/res/layout/call_headsup_notification_template.xml
+++ b/res/layout/call_headsup_notification_template.xml
@@ -24,7 +24,6 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/HeadsUpNotificationCard">
 
         <RelativeLayout
diff --git a/res/layout/call_notification_template.xml b/res/layout/call_notification_template.xml
index 5ddeec87..c6f62200 100644
--- a/res/layout/call_notification_template.xml
+++ b/res/layout/call_notification_template.xml
@@ -24,7 +24,6 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/NotificationCard">
 
         <RelativeLayout
diff --git a/res/layout/car_emergency_headsup_notification_template.xml b/res/layout/car_emergency_headsup_notification_template.xml
index 0108b70d..d562b7e1 100644
--- a/res/layout/car_emergency_headsup_notification_template.xml
+++ b/res/layout/car_emergency_headsup_notification_template.xml
@@ -23,7 +23,6 @@
 
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/HeadsUpNotificationCard">
 
         <FrameLayout
diff --git a/res/layout/car_emergency_notification_template.xml b/res/layout/car_emergency_notification_template.xml
index 6aef64b1..a93d7ccf 100644
--- a/res/layout/car_emergency_notification_template.xml
+++ b/res/layout/car_emergency_notification_template.xml
@@ -22,7 +22,6 @@
 
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/NotificationCard">
 
         <FrameLayout
diff --git a/res/layout/car_information_headsup_notification_template.xml b/res/layout/car_information_headsup_notification_template.xml
index b4a635e8..ec08b0c4 100644
--- a/res/layout/car_information_headsup_notification_template.xml
+++ b/res/layout/car_information_headsup_notification_template.xml
@@ -24,7 +24,6 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/HeadsUpNotificationCard">
 
         <FrameLayout
diff --git a/res/layout/car_information_notification_template.xml b/res/layout/car_information_notification_template.xml
index 96b86170..f5ec509b 100644
--- a/res/layout/car_information_notification_template.xml
+++ b/res/layout/car_information_notification_template.xml
@@ -23,7 +23,6 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/NotificationCard">
 
         <FrameLayout
diff --git a/res/layout/car_warning_headsup_notification_template.xml b/res/layout/car_warning_headsup_notification_template.xml
index b4a635e8..ec08b0c4 100644
--- a/res/layout/car_warning_headsup_notification_template.xml
+++ b/res/layout/car_warning_headsup_notification_template.xml
@@ -24,7 +24,6 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/HeadsUpNotificationCard">
 
         <FrameLayout
diff --git a/res/layout/car_warning_notification_template.xml b/res/layout/car_warning_notification_template.xml
index 0b8e40b8..21d26a88 100644
--- a/res/layout/car_warning_notification_template.xml
+++ b/res/layout/car_warning_notification_template.xml
@@ -23,7 +23,6 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/NotificationCard">
 
         <FrameLayout
diff --git a/res/layout/group_notification_template.xml b/res/layout/group_notification_template.xml
index 5cadd770..adcc2121 100644
--- a/res/layout/group_notification_template.xml
+++ b/res/layout/group_notification_template.xml
@@ -59,7 +59,7 @@
         android:layout_marginEnd="@dimen/notification_card_margin_horizontal"
         android:layout_marginStart="@dimen/notification_card_margin_horizontal"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius">
+        app:cardCornerRadius="?oemShapeCornerLarge">
 
         <RelativeLayout
             android:layout_width="match_parent"
diff --git a/res/layout/inbox_headsup_notification_template.xml b/res/layout/inbox_headsup_notification_template.xml
index d96210d8..c83984e8 100644
--- a/res/layout/inbox_headsup_notification_template.xml
+++ b/res/layout/inbox_headsup_notification_template.xml
@@ -24,7 +24,6 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/HeadsUpNotificationCard">
 
         <RelativeLayout
diff --git a/res/layout/inbox_notification_template.xml b/res/layout/inbox_notification_template.xml
index fb1412a3..8db7833f 100644
--- a/res/layout/inbox_notification_template.xml
+++ b/res/layout/inbox_notification_template.xml
@@ -23,7 +23,6 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/NotificationCard">
 
         <RelativeLayout
diff --git a/res/layout/media_notification_template.xml b/res/layout/media_notification_template.xml
index 0a836712..4ca7dacb 100644
--- a/res/layout/media_notification_template.xml
+++ b/res/layout/media_notification_template.xml
@@ -22,7 +22,6 @@
 
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/NotificationCard">
 
         <include
diff --git a/res/layout/media_notification_template_inner.xml b/res/layout/media_notification_template_inner.xml
index b0ab4e11..cb7f3cc0 100644
--- a/res/layout/media_notification_template_inner.xml
+++ b/res/layout/media_notification_template_inner.xml
@@ -50,7 +50,7 @@
         android:gravity="center_vertical">
 
         <ImageButton
-            style="@android:style/Widget.Material.Button.Borderless.Small"
+            style="@android:style/Widget.DeviceDefault.Button.Borderless"
             android:id="@+id/action_1"
             android:layout_width="@dimen/media_action_icon_size"
             android:layout_height="@dimen/media_action_icon_size"
@@ -59,7 +59,7 @@
             android:visibility="gone"/>
 
         <ImageButton
-            style="@android:style/Widget.Material.Button.Borderless.Small"
+            style="@android:style/Widget.DeviceDefault.Button.Borderless"
             android:id="@+id/action_2"
             android:layout_width="@dimen/media_action_icon_size"
             android:layout_height="@dimen/media_action_icon_size"
@@ -68,7 +68,7 @@
             android:visibility="gone"/>
 
         <ImageButton
-            style="@android:style/Widget.Material.Button.Borderless.Small"
+            style="@android:style/Widget.DeviceDefault.Button.Borderless"
             android:id="@+id/action_3"
             android:layout_width="@dimen/media_action_icon_size"
             android:layout_height="@dimen/media_action_icon_size"
@@ -77,7 +77,7 @@
             android:visibility="gone"/>
 
         <ImageButton
-            style="@android:style/Widget.Material.Button.Borderless.Small"
+            style="@android:style/Widget.DeviceDefault.Button.Borderless"
             android:id="@+id/action_4"
             android:layout_width="@dimen/media_action_icon_size"
             android:layout_height="@dimen/media_action_icon_size"
@@ -86,7 +86,7 @@
             android:visibility="gone"/>
 
         <ImageButton
-            style="@android:style/Widget.Material.Button.Borderless.Small"
+            style="@android:style/Widget.DeviceDefault.Button.Borderless"
             android:id="@+id/action_5"
             android:layout_width="@dimen/media_action_icon_size"
             android:layout_height="@dimen/media_action_icon_size"
diff --git a/res/layout/message_headsup_notification_template.xml b/res/layout/message_headsup_notification_template.xml
index 2e657d2e..6812b98b 100644
--- a/res/layout/message_headsup_notification_template.xml
+++ b/res/layout/message_headsup_notification_template.xml
@@ -24,7 +24,6 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/HeadsUpNotificationCard">
 
         <RelativeLayout
diff --git a/res/layout/message_notification_template.xml b/res/layout/message_notification_template.xml
index e290f332..960b9fee 100644
--- a/res/layout/message_notification_template.xml
+++ b/res/layout/message_notification_template.xml
@@ -23,7 +23,6 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/NotificationCard">
 
         <RelativeLayout
diff --git a/res/layout/navigation_headsup_notification_template.xml b/res/layout/navigation_headsup_notification_template.xml
index 650d9b71..26d5f5d3 100644
--- a/res/layout/navigation_headsup_notification_template.xml
+++ b/res/layout/navigation_headsup_notification_template.xml
@@ -23,7 +23,6 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/HeadsUpNotificationCard">
 
         <RelativeLayout
diff --git a/res/layout/notification_center_activity.xml b/res/layout/notification_center_activity.xml
index 9da055ce..1890b833 100644
--- a/res/layout/notification_center_activity.xml
+++ b/res/layout/notification_center_activity.xml
@@ -91,7 +91,7 @@
                 app:layout_constraintTop_toTopOf="parent"
                 app:layout_constraintVertical_chainStyle="packed"
                 android:text="@string/empty_notification_header"
-                android:textAppearance="?android:attr/textAppearanceLarge"
+                android:textAppearance="?oemTextAppearanceDisplayLarge"
                 android:visibility="gone"/>
 
             <Button
diff --git a/res/layout/progress_notification_template.xml b/res/layout/progress_notification_template.xml
index d2fec622..e659c139 100644
--- a/res/layout/progress_notification_template.xml
+++ b/res/layout/progress_notification_template.xml
@@ -23,7 +23,6 @@
     <androidx.cardview.widget.CardView
         android:id="@+id/card_view"
         app:cardBackgroundColor="@color/notification_background_color"
-        app:cardCornerRadius="@dimen/notification_card_radius"
         style="@style/NotificationCard">
 
         <RelativeLayout
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index fa5c311f..64f570ed 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -29,7 +29,7 @@
     <string name="toast_message_sent_success" msgid="1159956191974273064">"మెసేజ్‌ విజయవంతంగా పంపబడింది."</string>
     <string name="notification_service_label" msgid="7512186049723777468">"కార్ నోటిఫికేషన్ వినే కేంద్రం"</string>
     <string name="notifications" msgid="2865534625906329283">"నోటిఫికేషన్ కేంద్రం"</string>
-    <string name="clear_all" msgid="1845314281571237722">"అన్నీ తీసివేయండి"</string>
+    <string name="clear_all" msgid="1845314281571237722">"అన్నీ క్లియర్ చేయండి"</string>
     <string name="ellipsized_string" msgid="6993649229498857557">"…"</string>
     <string name="show_more" msgid="7291378544926443344">"మరిన్ని చూపు"</string>
     <string name="notification_header" msgid="324550431063568049">"నోటిఫికేషన్‌లు"</string>
diff --git a/res/values/colors.xml b/res/values/colors.xml
index de15453d..5a5ff471 100644
--- a/res/values/colors.xml
+++ b/res/values/colors.xml
@@ -15,42 +15,9 @@
     limitations under the License.
 -->
 <resources>
-    <color name="ic_launcher_background">@color/car_primary</color>
-    <color name="notification_background_color">@color/car_surface_1</color>
-    <color name="group_notification_background_color">@*android:color/car_grey_900</color>
-    <color name="action_button_background_color">@color/car_secondary_container</color>
-    <color name="emergency_background_color">@color/car_error_container</color>
-    <color name="emergency_primary_text_color">@color/car_on_error_container</color>
-    <color name="emergency_secondary_text_color">@color/car_error</color>
-    <color name="information_background_color">@color/car_surface_2</color>
-    <color name="information_primary_text_color">@color/car_on_surface</color>
-    <color name="information_secondary_text_color">@color/car_on_surface_variant</color>
-    <color name="warning_background_color">@color/car_yellow_color</color>
-    <color name="warning_primary_text_color">@color/car_yellow_on_color</color>
-    <color name="warning_secondary_text_color">@color/car_yellow_color_container</color>
-    <color name="call_accept_button">@color/car_confirm_green</color>
-    <color name="call_decline_button">@color/car_decline_red</color>
-    <color name="call_accept_button_text">@color/car_on_confirm_green</color>
-    <color name="call_decline_button_text">@color/car_on_decline_red</color>
-    <color name="unmute_button">@color/car_primary</color>
-    <color name="primary_text_color">@color/car_on_surface</color>
-    <color name="secondary_text_color">@color/car_on_surface_variant</color>
-    <color name="notification_accent_color">@color/car_on_secondary_container</color>
-    <color name="progress_bar_color">@color/car_primary</color>
-    <color name="progress_bar_bg_color">@color/car_surface_variant</color>
-
-    <!-- The color of the clear all button for notifications -->
-    <color name="clear_all_button_background_color">@color/car_secondary_container</color>
-
     <!-- The color of the ripples on the untinted notifications -->
-    <color name="notification_ripple_untinted_color">@color/car_control_highlight</color>
+    <color name="notification_ripple_untinted_color">?android:colorControlHighlight</color>
 
-    <color name="notification_list_divider_color">@color/car_secondary</color>
-    <color name="icon_tint">@color/car_on_secondary_container</color>
-    <color name="dark_icon_tint">@color/car_on_primary</color>
-    <color name="first_action_button_text_color">@color/car_on_primary</color>
+    <!-- The color of the ripples on the untinted notifications -->
     <color name="play_icon_tint">@color/first_action_button_text_color</color>
-    <color name="count_text">@color/car_primary</color>
-
-    <color name="card_background">@color/car_surface_1</color>
 </resources>
diff --git a/res/values/dimens.xml b/res/values/dimens.xml
index 40d1ffc6..998a7620 100644
--- a/res/values/dimens.xml
+++ b/res/values/dimens.xml
@@ -46,7 +46,6 @@
     <dimen name="body_big_icon_margin">@*android:dimen/car_padding_4</dimen>
     <dimen name="time_margin">@*android:dimen/car_padding_4</dimen>
     <dimen name="expanded_package_name_margin">@*android:dimen/car_padding_4</dimen>
-    <dimen name="notification_card_radius">32dp</dimen>
     <dimen name="notification_body_title_margin">@*android:dimen/car_padding_2</dimen>
     <dimen name="notification_body_content_top_margin">8dp</dimen>
     <dimen name="message_count_top_margin">12dp</dimen>
@@ -54,12 +53,10 @@
     <dimen name="group_icon_fill_alpha">0.72</dimen>
 
     <!-- Text -->
-    <dimen name="time_stamp_text_size_in_group">@*android:dimen/car_body3_size</dimen>
     <dimen name="notification_text_max_width">950dp</dimen>
 
     <!-- Action View -->
     <dimen name="action_button_height">@dimen/button_height</dimen>
-    <dimen name="action_button_radius">32dp</dimen>
     <dimen name="action_view_left_margin">16dp</dimen>
     <dimen name="action_view_right_margin">16dp</dimen>
     <dimen name="action_button_padding">@*android:dimen/car_padding_2</dimen>
@@ -112,7 +109,6 @@
     <dimen name="clear_all_button_padding">@*android:dimen/car_padding_4</dimen>
     <dimen name="clear_all_button_height">@dimen/button_height</dimen>
     <dimen name="clear_all_button_min_width">156dp</dimen>
-    <dimen name="clear_all_button_radius">44dp</dimen>
 
     <!-- Manage button -->
     <dimen name="manage_button_height">@*android:dimen/car_button_height</dimen>
diff --git a/res/values/styles.xml b/res/values/styles.xml
index d7eb377b..d6446682 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -14,28 +14,31 @@
     See the License for the specific language governing permissions and
     limitations under the License.
 -->
-<resources>
+<resources
+    xmlns:app="http://schemas.android.com/apk/res-auto">
 
-    <style name="NotificationCenterAppTitle" parent="@android:TextAppearance.DeviceDefault.Large">
+    <style name="NotificationCenterAppTitle">
+        <item name="android:textAppearance">?oemTextAppearanceDisplayLarge</item>
         <item name="android:maxLines">1</item>
     </style>
 
-    <style name="NotificationCenterHeaderText" parent="TextAppearance.Car.Subhead.Medium">
+    <style name="NotificationCenterHeaderText">
+        <item name="android:textAppearance">?oemTextAppearanceDisplayLarge</item>
         <item name="android:layout_marginStart">@dimen/notification_card_margin_horizontal</item>
         <item name="android:paddingBottom">@dimen/notification_header_text_padding_bottom</item>
         <item name="android:paddingTop">@dimen/notification_header_text_padding_top</item>
-        <item name="android:textAppearance">?android:attr/textAppearanceLarge</item>
     </style>
 
-    <style name="NotificationHeaderText" parent="@android:TextAppearance.DeviceDefault">
+    <style name="NotificationHeaderText">
+        <item name="android:textAppearance">?oemTextAppearanceBodyLarge</item>
         <item name="android:gravity">center_vertical</item>
         <item name="android:maxWidth">@dimen/notification_text_max_width</item>
         <item name="android:maxLines">1</item>
         <item name="android:ellipsize">end</item>
-        <item name="android:textSize">@*android:dimen/car_headline3_size</item>
     </style>
 
-    <style name="NotificationBodyTitleText" parent="TextAppearance.Car.Body.Large">
+    <style name="NotificationBodyTitleText">
+        <item name="android:textAppearance">?oemTextAppearanceBodyLarge</item>
         <item name="android:maxLines">3</item>
         <item name="android:maxWidth">@dimen/notification_text_max_width</item>
         <item name="android:ellipsize">end</item>
@@ -44,24 +47,24 @@
         <item name="android:includeFontPadding">false</item>
     </style>
 
-    <style name="InGroupTimeStampText" parent="@android:TextAppearance.DeviceDefault">
-        <item name="android:textSize">@dimen/time_stamp_text_size_in_group</item>
+    <style name="InGroupTimeStampText">
+        <item name="android:textSize">?oemTextAppearanceLabelLarge</item>
         <item name="android:textColor">@color/secondary_text_color</item>
         <item name="android:textAlignment">viewStart</item>
         <item name="android:ellipsize">end</item>
         <item name="android:maxLines">1</item>
-        <item name="android:textSize">@*android:dimen/car_headline3_size</item>
     </style>
 
-    <style name="NotificationBodyContentText" parent="TextAppearance.Car.Body.Small">
+    <style name="NotificationBodyContentText">
+        <item name="android:textAppearance">?oemTextAppearanceBodySmall</item>
         <item name="android:ellipsize">end</item>
         <item name="android:maxWidth">@dimen/notification_text_max_width</item>
         <item name="android:textColor">@color/secondary_text_color</item>
         <item name="android:textAlignment">viewStart</item>
-        <item name="android:textSize">@*android:dimen/car_headline3_size</item>
     </style>
 
-    <style name="GroupNotificationFooterText" parent="TextAppearance.Car.Subhead.Medium">
+    <style name="GroupNotificationFooterText">
+        <item name="android:textAppearance">?oemTextAppearanceTitleMedium</item>
         <item name="android:gravity">center</item>
         <item name="android:ellipsize">end</item>
         <item name="android:maxWidth">@dimen/notification_text_max_width</item>
@@ -69,12 +72,10 @@
         <item name="android:textStyle">bold</item>
         <item name="android:textAlignment">gravity</item>
         <item name="android:textDirection">locale</item>
-        <item name="android:textSize">@*android:dimen/car_headline3_size</item>
     </style>
 
-    <style name="ExpandedGroupNotificationHeaderText"
-           parent="@android:TextAppearance.DeviceDefault">
-        <item name="android:textSize">@*android:dimen/car_headline2_size</item>
+    <style name="ExpandedGroupNotificationHeaderText">
+        <item name="android:textAppearance">?oemTextAppearanceHeadlineSmall</item>
         <item name="android:gravity">center_vertical</item>
         <item name="android:ellipsize">end</item>
         <item name="android:maxWidth">@dimen/notification_text_max_width</item>
@@ -114,12 +115,12 @@
 
     <style name="NotificationActionButton3" parent="NotificationActionButtonBase"/>
 
-    <style name="NotificationActionButtonText" parent="TextAppearance.Car.Button">
+    <style name="NotificationActionButtonText">
+        <item name="android:textAppearance">?oemTextAppearanceTitleSmall</item>
         <item name="android:textAllCaps">false</item>
         <item name="android:textColor">@color/notification_accent_color</item>
         <item name="android:maxLines">1</item>
         <item name="android:ellipsize">end</item>
-        <item name="android:textSize">@*android:dimen/car_headline3_size</item>
     </style>
 
     <style name="NotificationActionButtonImage">
@@ -134,7 +135,7 @@
         <item name="android:minWidth">@dimen/clear_all_button_min_width</item>
         <item name="android:paddingStart">@dimen/clear_all_button_padding</item>
         <item name="android:paddingEnd">@dimen/clear_all_button_padding</item>
-        <item name="android:textColor">@android:color/white</item>
+        <item name="android:textColor">?oemColorOnSurface</item>
         <item name="android:gravity">center</item>
         <item name="android:textAllCaps">false</item>
         <item name="android:background">@drawable/clear_all_button_background</item>
@@ -155,6 +156,7 @@
         <item name="android:layout_gravity">center_horizontal</item>
         <item name="android:layout_marginEnd">@dimen/notification_card_margin_horizontal</item>
         <item name="android:layout_marginStart">@dimen/notification_card_margin_horizontal</item>
+        <item name="app:cardCornerRadius">?oemShapeCornerLarge</item>
     </style>
 
     <style name="HeadsUpNotificationCard" parent="NotificationCard">
diff --git a/res/values/themes.xml b/res/values/themes.xml
index 2334e6e5..1d7d8a0a 100644
--- a/res/values/themes.xml
+++ b/res/values/themes.xml
@@ -17,5 +17,6 @@
 <resources>
     <style name="Theme.DeviceDefault.NoActionBar.Notification" parent="@android:Theme.DeviceDefault.NoActionBar">
         <item name="android:colorPrimary">@color/card_background</item>
+        <item name="oemTokenOverrideEnabled">true</item>
     </style>
 </resources>
\ No newline at end of file
diff --git a/src/com/android/car/notification/CarHeadsUpNotificationManager.java b/src/com/android/car/notification/CarHeadsUpNotificationManager.java
index 2d645bae..66973d11 100644
--- a/src/com/android/car/notification/CarHeadsUpNotificationManager.java
+++ b/src/com/android/car/notification/CarHeadsUpNotificationManager.java
@@ -21,6 +21,8 @@ import static android.view.ViewTreeObserver.OnGlobalFocusChangeListener;
 import static android.view.ViewTreeObserver.OnGlobalLayoutListener;
 
 import static com.android.car.assist.client.CarAssistUtils.isCarCompatibleMessagingNotification;
+import static com.android.car.notification.CarNotificationDiff.sameNotificationKey;
+import static com.android.car.notification.NotificationUtils.isCategoryCall;
 
 import android.animation.Animator;
 import android.animation.AnimatorListenerAdapter;
@@ -35,6 +37,8 @@ import android.car.drivingstate.CarUxRestrictionsManager;
 import android.content.Context;
 import android.os.Build;
 import android.service.notification.NotificationListenerService;
+import android.service.notification.NotificationListenerService.Ranking;
+import android.service.notification.NotificationListenerService.RankingMap;
 import android.util.Log;
 import android.util.Pair;
 import android.view.LayoutInflater;
@@ -55,7 +59,6 @@ import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
-import java.util.Objects;
 import java.util.Set;
 import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.ScheduledThreadPoolExecutor;
@@ -77,6 +80,17 @@ public class CarHeadsUpNotificationManager
         void onStateChange(AlertEntry alertEntry, HeadsUpState headsUpState);
     }
 
+    /**
+     * Provider class for the latest updated {@link RankingMap} retrievable from
+     * {@link NotificationListenerService}.
+     */
+    public interface RankingMapProvider {
+        /**
+         * @return latest cached {@link RankingMap} from the provider class.
+         */
+        RankingMap getCurrentRanking();
+    }
+
     /**
      * Captures HUN State with following values:
      * <ul>
@@ -135,12 +149,14 @@ public class CarHeadsUpNotificationManager
     private final Map<HeadsUpEntry,
             Pair<OnComputeInternalInsetsListener, OnGlobalFocusChangeListener>>
             mRegisteredViewTreeListeners = new HashMap<>();
+    private final ArrayList<AlertEntry> mPendingCalls = new ArrayList<>();
 
     private boolean mShouldRestrictMessagePreview;
     private NotificationClickHandlerFactory mClickHandlerFactory;
     private NotificationDataManager mNotificationDataManager;
     private CarHeadsUpNotificationQueue mCarHeadsUpNotificationQueue;
     private Clock mClock;
+    private RankingMapProvider mRankingMapProvider;
 
     public CarHeadsUpNotificationManager(Context context,
             NotificationClickHandlerFactory clickHandlerFactory,
@@ -175,11 +191,14 @@ public class CarHeadsUpNotificationManager
         mCarHeadsUpNotificationQueueCallback =
                 new CarHeadsUpNotificationQueue.CarHeadsUpNotificationQueueCallback() {
                     @Override
-                    public void showAsHeadsUp(AlertEntry alertEntry,
-                            NotificationListenerService.RankingMap rankingMap) {
-                        mContext.getMainExecutor().execute(() -> showHeadsUp(
-                                mPreprocessingManager.optimizeForDriving(alertEntry),
-                                rankingMap)
+                    public void showAsHeadsUp(AlertEntry alertEntry) {
+                        mContext.getMainExecutor().execute(() -> {
+                            if (isCategoryCall(alertEntry)) {
+                                showOrScheduleCallHun(alertEntry);
+                            } else {
+                                showHeadsUp(mPreprocessingManager.optimizeForDriving(alertEntry));
+                            }
+                        }
                         );
                     }
 
@@ -228,15 +247,20 @@ public class CarHeadsUpNotificationManager
     }
 
     /**
-     * Show the notification as a heads-up if it meets the criteria.
+     * Show the notification as a heads-up if the {@link AlertEntry} metadata meets the criteria,
+     * and the current condition is reasonable to immediately display it to the user.
      *
-     * <p>Return's true if the notification will be shown as a heads up, false otherwise.
+     * <p> If the {@link AlertEntry} meets the criteria, but the current condition is not reasonable
+     * to immediately display it, the entry should be immediately added to
+     * {@link CarHeadsUpNotificationQueue} or another list in {@link CarHeadsUpNotificationManager}
+     * to eventually display it.
+     *
+     * <p> Return {@code true} if the notification will eventually be shown unless cancelled by
+     * notification sender, and return {@code false} otherwise.
      */
-    public boolean maybeShowHeadsUp(
-            AlertEntry alertEntry,
-            NotificationListenerService.RankingMap rankingMap,
+    public boolean maybeShowOrScheduleHun(AlertEntry alertEntry,
             Map<String, AlertEntry> activeNotifications) {
-        if (!shouldShowHeadsUp(alertEntry, rankingMap)) {
+        if (!canShowOrScheduleHeadsUp(alertEntry)) {
             if (!isActiveHun(alertEntry)) {
                 if (DEBUG) {
                     Log.d(TAG, alertEntry + " is not an active heads up notification");
@@ -246,35 +270,54 @@ public class CarHeadsUpNotificationManager
             // Check if this is an update to the existing notification and if it should still show
             // as a heads up or not.
             HeadsUpEntry currentActiveHeadsUpNotification = getActiveHeadsUpEntry(alertEntry);
-            if (CarNotificationDiff.sameNotificationKey(currentActiveHeadsUpNotification,
-                    alertEntry)
+            if (sameNotificationKey(currentActiveHeadsUpNotification, alertEntry)
                     && currentActiveHeadsUpNotification.getHandler().hasMessagesOrCallbacks()) {
                 dismissHun(alertEntry, /* shouldAnimate= */ true);
             }
             return false;
         }
-        boolean containsKeyFlag = !activeNotifications.containsKey(alertEntry.getKey());
-        boolean canUpdateFlag = canUpdate(alertEntry);
-        boolean alertAgainFlag = alertAgain(alertEntry.getNotification());
+
+        boolean isActiveNotification = activeNotifications.containsKey(alertEntry.getKey());
+        boolean isActiveHunUpdate = canUpdate(alertEntry);
+        boolean canAlertAgain = alertAgain(alertEntry.getNotification());
+
         if (DEBUG) {
-            Log.d(TAG, alertEntry + " is an active notification: " + containsKeyFlag);
-            Log.d(TAG, alertEntry + " is an updatable notification: " + canUpdateFlag);
-            Log.d(TAG, alertEntry + " is not an alert once notification: " + alertAgainFlag);
+            Log.d(TAG, alertEntry + " is not an active hun: " + !isActiveNotification);
+            Log.d(TAG, alertEntry + " is an update to active hun: " + isActiveHunUpdate);
+            Log.d(TAG, alertEntry + " is not an FLAG_ONLY_ALERT_ONCE hun: " + canAlertAgain);
         }
-        if (canUpdateFlag) {
-            showHeadsUp(mPreprocessingManager.optimizeForDriving(alertEntry),
-                    rankingMap);
-            return true;
-        } else if (containsKeyFlag || alertAgainFlag) {
-            if (!mIsSuppressAndThrottleHeadsUp) {
-                showHeadsUp(mPreprocessingManager.optimizeForDriving(alertEntry),
-                        rankingMap);
-            } else {
-                mCarHeadsUpNotificationQueue.addToQueue(alertEntry, rankingMap);
+
+        if (isActiveNotification && !isActiveHunUpdate && !canAlertAgain) {
+            return false;
+        }
+
+        if (mIsSuppressAndThrottleHeadsUp && !isActiveHunUpdate) {
+            // never throttle an update to an active HUN already shown to user
+            mCarHeadsUpNotificationQueue.addToQueue(alertEntry);
+        } else if (isCategoryCall(alertEntry)) {
+            showOrScheduleCallHun(alertEntry);
+        } else {
+            showHeadsUp(mPreprocessingManager.optimizeForDriving(alertEntry));
+        }
+        return true;
+    }
+
+    private void showOrScheduleCallHun(AlertEntry alertEntry) {
+        boolean hasActiveCallShown = mActiveHeadsUpNotifications.values().stream().anyMatch(
+                NotificationUtils::isCategoryCall);
+        if (!hasActiveCallShown || isUpdate(alertEntry)) {
+            showHeadsUp(mPreprocessingManager.optimizeForDriving(alertEntry));
+            return;
+        }
+        for (int i = 0; i < mPendingCalls.size(); i++) {
+            if (sameNotificationKey(mPendingCalls.get(i), alertEntry)) {
+                // substitute the first pending AlertEntry with a new entry if an update is posted
+                // before the first has been shown yet
+                mPendingCalls.set(i, alertEntry);
+                return;
             }
-            return true;
         }
-        return false;
+        mPendingCalls.add(alertEntry);
     }
 
     /**
@@ -285,10 +328,17 @@ public class CarHeadsUpNotificationManager
             return;
         }
 
+        if (isCategoryCall(alertEntry)) {
+            boolean removed = mPendingCalls.removeIf(pendingEntry ->
+                    sameNotificationKey(alertEntry, pendingEntry));
+            if (removed) return;
+        }
+
         if (!isActiveHun(alertEntry)) {
             // If the heads up notification is already removed do nothing.
             return;
         }
+
         tagCurrentActiveHunToBeRemoved(alertEntry);
 
         scheduleRemoveHeadsUp(alertEntry);
@@ -307,6 +357,7 @@ public class CarHeadsUpNotificationManager
      */
     public void clearCache() {
         mCarHeadsUpNotificationQueue.clearCache();
+        mPendingCalls.clear();
         for (AlertEntry alertEntry : mActiveHeadsUpNotifications.values()) {
             dismissHun(alertEntry, /* shouldAnimate= */ false);
         }
@@ -339,6 +390,13 @@ public class CarHeadsUpNotificationManager
         }
     }
 
+    /**
+     * Sets the {@link RankingMapProvider} for retrieving the latest {@link RankingMap}.
+     */
+    public void setRankingMapProvider(RankingMapProvider provider) {
+        mRankingMapProvider = provider;
+    }
+
     /**
      * Unregisters all {@link OnHeadsUpNotificationStateChange} listeners along with other listeners
      * registered by {@link CarHeadsUpNotificationManager}.
@@ -372,7 +430,7 @@ public class CarHeadsUpNotificationManager
      * notification.
      */
     private boolean isUpdate(AlertEntry alertEntry) {
-        return isActiveHun(alertEntry) && CarNotificationDiff.sameNotificationKey(
+        return isActiveHun(alertEntry) && sameNotificationKey(
                 getActiveHeadsUpEntry(alertEntry), alertEntry);
     }
 
@@ -426,15 +484,14 @@ public class CarHeadsUpNotificationManager
      * </ol>
      */
     @UiThread
-    private void showHeadsUp(AlertEntry alertEntry,
-            NotificationListenerService.RankingMap rankingMap) {
+    private void showHeadsUp(AlertEntry alertEntry) {
         // Show animations only when there is no active HUN and notification is new. This check
         // needs to be done here because after this the new notification will be added to the map
         // holding ongoing notifications.
         boolean shouldShowAnimation = !isUpdate(alertEntry);
         HeadsUpEntry currentNotification = getOrCreateHeadsUpEntry(alertEntry);
         if (currentNotification.mIsNewHeadsUp) {
-            playSound(alertEntry, rankingMap);
+            playSound(alertEntry);
             setAutoDismissViews(currentNotification, alertEntry);
         } else if (currentNotification.mIsAlertAgain) {
             setAutoDismissViews(currentNotification, alertEntry);
@@ -454,7 +511,7 @@ public class CarHeadsUpNotificationManager
                             mClickHandlerFactory));
         }
 
-        currentNotification.getViewHolder().setHideDismissButton(!isHeadsUpDismissible(alertEntry));
+        currentNotification.getViewHolder().setHideDismissButton(/* hideDismissButton= */ false);
 
         if (mShouldRestrictMessagePreview && notificationTypeItem.getNotificationType()
                 == NotificationViewType.MESSAGE) {
@@ -507,7 +564,6 @@ public class CarHeadsUpNotificationManager
         // Add swipe gesture
         View cardView = notificationView.findViewById(R.id.card_view);
         cardView.setOnTouchListener(new HeadsUpNotificationOnTouchListener(cardView,
-                isHeadsUpDismissible(alertEntry),
                 () -> dismissHun(alertEntry, /* shouldAnimate= */ false)));
 
         // Add dismiss button listener
@@ -556,10 +612,9 @@ public class CarHeadsUpNotificationManager
         info.touchableRegion.set(minX, minY, maxX, maxY);
     }
 
-    private void playSound(AlertEntry alertEntry,
-            NotificationListenerService.RankingMap rankingMap) {
+    private void playSound(@NonNull AlertEntry alertEntry) {
         NotificationListenerService.Ranking ranking = getRanking();
-        if (rankingMap.getRanking(alertEntry.getKey(), ranking)) {
+        if (mRankingMapProvider.getCurrentRanking().getRanking(alertEntry.getKey(), ranking)) {
             NotificationChannel notificationChannel = ranking.getChannel();
             // If sound is not set on the notification channel and default is not chosen it
             // can be null.
@@ -571,18 +626,9 @@ public class CarHeadsUpNotificationManager
         }
     }
 
-    /**
-     * @return true if the {@code alertEntry} can be dismissed/swiped away.
-     */
-    public static boolean isHeadsUpDismissible(@NonNull AlertEntry alertEntry) {
-        return !(hasFullScreenIntent(alertEntry)
-                && Objects.equals(alertEntry.getNotification().category, Notification.CATEGORY_CALL)
-                && alertEntry.getStatusBarNotification().isOngoing());
-    }
-
     @VisibleForTesting
-    protected Map<String, HeadsUpEntry> getActiveHeadsUpNotifications() {
-        return mActiveHeadsUpNotifications;
+    protected NotificationListenerService.Ranking getRanking() {
+        return new Ranking();
     }
 
     private void setAutoDismissViews(HeadsUpEntry currentNotification, AlertEntry alertEntry) {
@@ -629,26 +675,26 @@ public class CarHeadsUpNotificationManager
         }
 
         if (!shouldAnimate) {
-            postDismiss(alertEntry, headsUpView);
+            postDismissHunFinished(alertEntry, headsUpView);
             return;
         }
 
-
         AnimatorSet animatorSet = mAnimationHelper.getAnimateOutAnimator(mContext, headsUpView);
         animatorSet.setTarget(headsUpView);
         animatorSet.addListener(new AnimatorListenerAdapter() {
             @Override
             public void onAnimationEnd(Animator animation) {
-                postDismiss(alertEntry, headsUpView);
+                postDismissHunFinished(alertEntry, headsUpView);
             }
         });
         animatorSet.start();
     }
 
     /**
-     * Method to be called after HUN is dismissed.
+     * Method to be called after HUN dismissal animation is finished. If no animation is played, it
+     * should be called immediately.
      */
-    private void postDismiss(AlertEntry alertEntry, View headsUpView) {
+    private void postDismissHunFinished(AlertEntry alertEntry, View headsUpView) {
         removeHeadsUpEntry(alertEntry, headsUpView);
 
         boolean isRemovedBySender =
@@ -659,6 +705,12 @@ public class CarHeadsUpNotificationManager
 
         mHeadsUpNotificationsToBeRemoved.remove(alertEntry.getKey());
         mDismissingHeadsUpNotifications.remove(alertEntry.getKey());
+        mBeeper.stopBeeping();
+
+        if (isCategoryCall(alertEntry) && !mPendingCalls.isEmpty()) {
+            // CATEGORY_CALL notifications are to be shown sequentially and one at a time
+            showHeadsUp(mPendingCalls.removeFirst());
+        }
     }
 
     private void resetHeadsUpEntry(@NonNull AlertEntry alertEntry) {
@@ -686,7 +738,8 @@ public class CarHeadsUpNotificationManager
     }
 
     /**
-     * Helper method that determines whether a notification should show as a heads-up.
+     * Helper method that determines whether the {@link AlertEntry} should be shown based on the
+     * meta-data provided the current device configuration and lock screen status.
      *
      * <p> A notification will never be shown as a heads-up if:
      * <ul>
@@ -709,9 +762,7 @@ public class CarHeadsUpNotificationManager
      *
      * @return true if a notification should be shown as a heads-up
      */
-    private boolean shouldShowHeadsUp(
-            AlertEntry alertEntry,
-            NotificationListenerService.RankingMap rankingMap) {
+    private boolean canShowOrScheduleHeadsUp(AlertEntry alertEntry) {
         if (mKeyguardManager.isKeyguardLocked()) {
             if (DEBUG) {
                 Log.d(TAG, "Unable to show as HUN: Keyguard is locked");
@@ -744,8 +795,8 @@ public class CarHeadsUpNotificationManager
         }
 
         // Do not show if importance < HIGH
-        NotificationListenerService.Ranking ranking = getRanking();
-        if (rankingMap.getRanking(alertEntry.getKey(), ranking)) {
+        Ranking ranking = getRanking();
+        if (mRankingMapProvider.getCurrentRanking().getRanking(alertEntry.getKey(), ranking)) {
             if (ranking.getImportance() < NotificationManager.IMPORTANCE_HIGH) {
                 if (DEBUG) {
                     Log.d(TAG, "Unable to show as HUN: importance is not sufficient");
@@ -780,7 +831,7 @@ public class CarHeadsUpNotificationManager
         }
 
         // Allow for Call, and nav TBT categories.
-        return Notification.CATEGORY_CALL.equals(notification.category)
+        return isCategoryCall(alertEntry)
                 || Notification.CATEGORY_NAVIGATION.equals(notification.category);
     }
 
@@ -800,11 +851,6 @@ public class CarHeadsUpNotificationManager
         mHeadsUpNotificationsToBeRemoved.add(alertEntry.getKey());
     }
 
-    @VisibleForTesting
-    protected NotificationListenerService.Ranking getRanking() {
-        return new NotificationListenerService.Ranking();
-    }
-
     @Override
     public void onUxRestrictionsChanged(CarUxRestrictions restrictions) {
         mCarHeadsUpNotificationQueue.setActiveUxRestriction(
@@ -814,6 +860,11 @@ public class CarHeadsUpNotificationManager
                         & CarUxRestrictions.UX_RESTRICTIONS_NO_TEXT_MESSAGE) != 0;
     }
 
+    @VisibleForTesting
+    protected Map<String, HeadsUpEntry> getActiveHeadsUpNotifications() {
+        return mActiveHeadsUpNotifications;
+    }
+
     /**
      * Sets the source of {@link View.OnClickListener}
      *
@@ -839,4 +890,9 @@ public class CarHeadsUpNotificationManager
     void addActiveHeadsUpNotification(HeadsUpEntry headsUpEntry) {
         mActiveHeadsUpNotifications.put(headsUpEntry.getKey(), headsUpEntry);
     }
+
+    @VisibleForTesting
+    List<AlertEntry> getPendingCalls() {
+        return mPendingCalls;
+    }
 }
diff --git a/src/com/android/car/notification/CarHeadsUpNotificationQueue.java b/src/com/android/car/notification/CarHeadsUpNotificationQueue.java
index dfede430..3a8b2dcd 100644
--- a/src/com/android/car/notification/CarHeadsUpNotificationQueue.java
+++ b/src/com/android/car/notification/CarHeadsUpNotificationQueue.java
@@ -27,7 +27,6 @@ import android.car.drivingstate.CarUxRestrictionsManager;
 import android.content.Context;
 import android.os.RemoteException;
 import android.os.UserHandle;
-import android.service.notification.NotificationListenerService;
 import android.text.TextUtils;
 
 import androidx.annotation.AnyThread;
@@ -76,7 +75,6 @@ public class CarHeadsUpNotificationQueue implements
     private final Set<String> mPackagesToThrottleHeadsUp;
     private final Map<String, AlertEntry> mKeyToAlertEntryMap;
     private final Set<Integer> mThrottledDisplays;
-    private NotificationListenerService.RankingMap mRankingMap;
     private Clock mClock;
     @VisibleForTesting
     ScheduledFuture<?> mScheduledFuture;
@@ -160,12 +158,9 @@ public class CarHeadsUpNotificationQueue implements
     /**
      * Adds an {@link AlertEntry} into the queue.
      */
-    public void addToQueue(AlertEntry alertEntry,
-            NotificationListenerService.RankingMap rankingMap) {
-        mRankingMap = rankingMap;
+    public void addToQueue(AlertEntry alertEntry) {
         if (isCategoryImmediateShow(alertEntry.getNotification().category)) {
-            mQueueCallback.getActiveHeadsUpNotifications().forEach(mQueueCallback::dismissHeadsUp);
-            mQueueCallback.showAsHeadsUp(alertEntry, rankingMap);
+            mQueueCallback.showAsHeadsUp(alertEntry);
             return;
         }
         boolean headsUpExistsInQueue = mKeyToAlertEntryMap.containsKey(alertEntry.getKey());
@@ -192,9 +187,7 @@ public class CarHeadsUpNotificationQueue implements
         mIsOngoingHeadsUpFlush = true;
 
         if (mDismissHeadsUpWhenNotificationCenterOpens) {
-            mQueueCallback.getActiveHeadsUpNotifications().stream()
-                    .filter(CarHeadsUpNotificationManager::isHeadsUpDismissible)
-                    .forEach(mQueueCallback::dismissHeadsUp);
+            mQueueCallback.getActiveHeadsUpNotifications().forEach(mQueueCallback::dismissHeadsUp);
         }
         while (!mPriorityQueue.isEmpty()) {
             String key = mPriorityQueue.poll();
@@ -268,7 +261,7 @@ public class CarHeadsUpNotificationQueue implements
                 alertEntry = null;
             }
         } while (alertEntry == null);
-        mQueueCallback.showAsHeadsUp(alertEntry, mRankingMap);
+        mQueueCallback.showAsHeadsUp(alertEntry);
     }
 
     private boolean canShowHeadsUp() {
@@ -350,8 +343,7 @@ public class CarHeadsUpNotificationQueue implements
          * Show the AlertEntry as HUN.
          */
         @AnyThread
-        void showAsHeadsUp(AlertEntry alertEntry,
-                NotificationListenerService.RankingMap rankingMap);
+        void showAsHeadsUp(AlertEntry alertEntry);
 
         /**
          * AlertEntry removed from the queue without being shown as HUN.
diff --git a/src/com/android/car/notification/CarNotificationItemTouchListener.java b/src/com/android/car/notification/CarNotificationItemTouchListener.java
index 8bfa3403..c5b9b709 100644
--- a/src/com/android/car/notification/CarNotificationItemTouchListener.java
+++ b/src/com/android/car/notification/CarNotificationItemTouchListener.java
@@ -489,7 +489,8 @@ public class CarNotificationItemTouchListener extends RecyclerView.SimpleOnItemT
                     alertEntry.getStatusBarNotification().getKey(),
                     NotificationStats.DISMISSAL_SHADE,
                     NotificationStats.DISMISS_SENTIMENT_NEUTRAL,
-                    notificationVisibility);
+                    notificationVisibility,
+                    /* fromBundle= */ false);
         } catch (RemoteException e) {
             Log.e(TAG, "clearNotifications: ", e);
         }
diff --git a/src/com/android/car/notification/CarNotificationListener.java b/src/com/android/car/notification/CarNotificationListener.java
index 3d1b3dc9..29d2f699 100644
--- a/src/com/android/car/notification/CarNotificationListener.java
+++ b/src/com/android/car/notification/CarNotificationListener.java
@@ -46,7 +46,8 @@ import java.util.stream.Stream;
  * NotificationListenerService that fetches all notifications from system.
  */
 public class CarNotificationListener extends NotificationListenerService implements
-        CarHeadsUpNotificationManager.OnHeadsUpNotificationStateChange {
+        CarHeadsUpNotificationManager.OnHeadsUpNotificationStateChange,
+        CarHeadsUpNotificationManager.RankingMapProvider {
     private static final String TAG = "CarNotificationListener";
     private static final boolean DEBUG = Build.IS_ENG || Build.IS_USERDEBUG;
     static final String ACTION_LOCAL_BINDING = "local_binding";
@@ -66,7 +67,7 @@ public class CarNotificationListener extends NotificationListenerService impleme
     /**
      * Map that contains all the active notifications that are not currently HUN. These
      * notifications may or may not be visible to the user if they get filtered out. The only time
-     * these will be removed from the map is when the {@llink NotificationListenerService} calls the
+     * these will be removed from the map is when the {@link NotificationListenerService} calls the
      * onNotificationRemoved method. New notifications will be added to this map if the notification
      * is posted as a non-HUN or when a HUN's state is changed to non-HUN.
      */
@@ -91,6 +92,8 @@ public class CarNotificationListener extends NotificationListenerService impleme
                     NotificationUtils.getCurrentUser(context));
             mHeadsUpManager = carHeadsUpNotificationManager;
             mHeadsUpManager.registerHeadsUpNotificationStateChangeListener(this);
+            mHeadsUpManager.setRankingMapProvider(this);
+
             carUxRestrictionManagerWrapper.setCarHeadsUpNotificationManager(
                     carHeadsUpNotificationManager);
         } catch (RemoteException e) {
@@ -292,19 +295,22 @@ public class CarNotificationListener extends NotificationListenerService impleme
             mNotificationDataManager.untrackUnseenNotification(alertEntry);
         }
 
-        boolean isShowingHeadsUp = false;
-        if (!mIsNotificationPanelVisible
-                || !CarHeadsUpNotificationManager.isHeadsUpDismissible(alertEntry)) {
-            isShowingHeadsUp = mHeadsUpManager.maybeShowHeadsUp(alertEntry, getCurrentRanking(),
+        boolean isHunShownOrScheduled = false;
+        if (!mIsNotificationPanelVisible) {
+            isHunShownOrScheduled = mHeadsUpManager.maybeShowOrScheduleHun(alertEntry,
                     mActiveNotifications);
         }
         if (DEBUG) {
-            Log.d(TAG, "Is " + alertEntry + " shown as HUN?: " + isShowingHeadsUp);
+            Log.d(TAG, "Is " + alertEntry + " added to HUN manager?: " + isHunShownOrScheduled);
         }
-        if (!isShowingHeadsUp) {
-            updateOverrideGroupKey(alertEntry);
-            postNewNotification(alertEntry);
+        if (isHunShownOrScheduled) {
+            // if a notification is shown as heads-up notification, delay posting it to notification
+            // view until it is dismissed / swiped away by the user.
+            return;
         }
+        // notification is not shown as a hun and should be immediately posted.
+        updateOverrideGroupKey(alertEntry);
+        postNewNotification(alertEntry);
     }
 
     private boolean isNotificationForCurrentUser(StatusBarNotification sbn) {
diff --git a/src/com/android/car/notification/HeadsUpNotificationOnTouchListener.java b/src/com/android/car/notification/HeadsUpNotificationOnTouchListener.java
index c31d973e..58c129e7 100644
--- a/src/com/android/car/notification/HeadsUpNotificationOnTouchListener.java
+++ b/src/com/android/car/notification/HeadsUpNotificationOnTouchListener.java
@@ -58,7 +58,6 @@ class HeadsUpNotificationOnTouchListener implements View.OnTouchListener {
      * Distance a touch can wander before we think the user is scrolling in pixels.
      */
     private final int mTouchSlop;
-    private final boolean mDismissOnSwipe;
     /**
      * The proportion which view has to be swiped before it dismisses.
      */
@@ -109,11 +108,9 @@ class HeadsUpNotificationOnTouchListener implements View.OnTouchListener {
         }
     }
 
-    HeadsUpNotificationOnTouchListener(View view, boolean dismissOnSwipe,
-            DismissCallbacks callbacks) {
+    HeadsUpNotificationOnTouchListener(View view, DismissCallbacks callbacks) {
         mView = view;
         mCallbacks = callbacks;
-        mDismissOnSwipe = dismissOnSwipe;
         Resources res = view.getContext().getResources();
         mDismissAxis = res.getBoolean(R.bool.config_isHeadsUpNotificationDismissibleVertically)
                 ? Axis.VERTICAL : Axis.HORIZONTAL;
@@ -185,7 +182,7 @@ class HeadsUpNotificationOnTouchListener implements View.OnTouchListener {
                             getVelocityInAxis(mVelocityTracker, mDismissAxis) > 0;
                 }
 
-                if (shouldBeDismissed && mDismissOnSwipe) {
+                if (shouldBeDismissed) {
                     mCallbacks.onDismiss();
                     animateDismissInAxis(mView, mDismissAxis, dismissInPositiveDirection);
                 } else if (mSwiping) {
@@ -222,9 +219,7 @@ class HeadsUpNotificationOnTouchListener implements View.OnTouchListener {
                     mTranslation = deltaInDismissAxis;
                     moveView(mView,
                             /* translation= */ deltaInDismissAxis - mSwipingSlop, mDismissAxis);
-                    if (mDismissOnSwipe) {
-                        mView.setAlpha(getAlphaForDismissingView(mTranslation, mMaxTranslation));
-                    }
+                    mView.setAlpha(getAlphaForDismissingView(mTranslation, mMaxTranslation));
                     return true;
                 }
             }
diff --git a/src/com/android/car/notification/NotificationApplication.java b/src/com/android/car/notification/NotificationApplication.java
index 86f8591c..bbd368bb 100644
--- a/src/com/android/car/notification/NotificationApplication.java
+++ b/src/com/android/car/notification/NotificationApplication.java
@@ -26,6 +26,7 @@ import android.os.IBinder;
 import android.os.ServiceManager;
 import android.util.Log;
 
+import com.android.car.oem.tokens.Token;
 import com.android.internal.statusbar.IStatusBarService;
 
 /**
@@ -97,4 +98,10 @@ public class NotificationApplication extends Application {
     public NotificationClickHandlerFactory getClickHandlerFactory() {
         return mClickHandlerFactory;
     }
+
+    @Override
+    public void attachBaseContext(Context base) {
+        Token.applyOemTokenStyle(base);
+        super.attachBaseContext(base);
+    }
 }
diff --git a/src/com/android/car/notification/NotificationClickHandlerFactory.java b/src/com/android/car/notification/NotificationClickHandlerFactory.java
index 4d52ac30..bec64dac 100644
--- a/src/com/android/car/notification/NotificationClickHandlerFactory.java
+++ b/src/com/android/car/notification/NotificationClickHandlerFactory.java
@@ -398,7 +398,8 @@ public class NotificationClickHandlerFactory {
                     alertEntry.getStatusBarNotification().getKey(),
                     NotificationStats.DISMISSAL_SHADE,
                     NotificationStats.DISMISS_SENTIMENT_NEUTRAL,
-                    notificationVisibility);
+                    notificationVisibility,
+                    /* fromBundle= */ false);
         } catch (RemoteException e) {
             Log.e(TAG, "clearNotifications: ", e);
         }
diff --git a/src/com/android/car/notification/NotificationUtils.java b/src/com/android/car/notification/NotificationUtils.java
index cb199f01..c38d02ee 100644
--- a/src/com/android/car/notification/NotificationUtils.java
+++ b/src/com/android/car/notification/NotificationUtils.java
@@ -17,6 +17,7 @@
 package com.android.car.notification;
 
 import android.annotation.ColorInt;
+import android.annotation.NonNull;
 import android.app.ActivityManager;
 import android.app.Notification;
 import android.content.Context;
@@ -310,4 +311,13 @@ public class NotificationUtils {
                 : findContrastColorAgainstLightBackground(
                         foregroundColor, backgroundColor, minContrastRatio);
     }
+
+    /**
+     * @return {@code true} if this {@link AlertEntry} is {@link Notification.CATEGORY_CALL} and
+     * {@code false} otherwise.
+     */
+    public static boolean isCategoryCall(@NonNull AlertEntry alertEntry) {
+        if (alertEntry.getNotification() == null) return false;
+        return Notification.CATEGORY_CALL.equals(alertEntry.getNotification().category);
+    }
 }
diff --git a/src/com/android/car/notification/PreprocessingManager.java b/src/com/android/car/notification/PreprocessingManager.java
index 8683316d..a2f43be8 100644
--- a/src/com/android/car/notification/PreprocessingManager.java
+++ b/src/com/android/car/notification/PreprocessingManager.java
@@ -17,6 +17,8 @@ package com.android.car.notification;
 
 import static android.app.Notification.FLAG_AUTOGROUP_SUMMARY;
 
+import static com.android.car.notification.NotificationUtils.isCategoryCall;
+
 import android.annotation.Nullable;
 import android.app.Notification;
 import android.app.NotificationManager;
@@ -218,12 +220,8 @@ public class PreprocessingManager {
     protected List<AlertEntry> filter(
             List<AlertEntry> notifications,
             RankingMap rankingMap) {
-        // Call notifications should not be shown in the panel.
-        // Since they're shown as persistent HUNs, and notifications are not added to the panel
-        // until after they're dismissed as HUNs, it does not make sense to have them in the panel,
-        // and sequencing could cause them to be removed before being added here.
-        notifications.removeIf(alertEntry -> Notification.CATEGORY_CALL.equals(
-                alertEntry.getNotification().category));
+        // remove notifications that should be filtered.
+        notifications.removeIf(alertEntry -> shouldFilter(alertEntry, rankingMap));
 
         // HUN suppression notifications should not be shown in the panel.
         notifications.removeIf(alertEntry -> CarHeadsUpNotificationQueue.CATEGORY_HUN_QUEUE_INTERNAL
@@ -372,7 +370,7 @@ public class PreprocessingManager {
             Notification notification = alertEntry.getNotification();
 
             String groupKey;
-            if (Notification.CATEGORY_CALL.equals(notification.category)) {
+            if (isCategoryCall(alertEntry)) {
                 // DO NOT group CATEGORY_CALL.
                 groupKey = UUID.randomUUID().toString();
             } else {
@@ -388,10 +386,13 @@ public class PreprocessingManager {
                 NotificationGroup notificationGroup = new NotificationGroup();
                 groupedNotifications.put(groupKey, notificationGroup);
             }
-            if (notification.isGroupSummary()) {
+
+            if (notification.isGroupSummary() && !isCategoryCall(alertEntry)) {
                 groupedNotifications.get(groupKey)
                         .setGroupSummaryNotification(alertEntry);
             } else {
+                // CATEGORY_CALL notifications are NOT grouped and contains no child AlertEntry, so
+                // they should be added as a singleton notification.
                 groupedNotifications.get(groupKey).addNotification(alertEntry);
             }
         }
diff --git a/src/com/android/car/notification/template/CarNotificationActionButton.java b/src/com/android/car/notification/template/CarNotificationActionButton.java
index 3d1b2850..42fa8649 100644
--- a/src/com/android/car/notification/template/CarNotificationActionButton.java
+++ b/src/com/android/car/notification/template/CarNotificationActionButton.java
@@ -67,11 +67,13 @@ public class CarNotificationActionButton extends LinearLayout {
                     context.obtainStyledAttributes(attrs, R.styleable.CarNotificationActionButton);
             int color = attributes.getColor(
                     R.styleable.CarNotificationActionButton_textColor, /* defaultValue= */
-                    context.getResources().getColor(R.color.notification_accent_color));
+                    context.getResources().getColor(
+                            R.color.notification_accent_color, context.getTheme()));
             attributes.recycle();
             mDefaultTextColor = color;
         } else {
-            mDefaultTextColor = context.getResources().getColor(R.color.notification_accent_color);
+            mDefaultTextColor = context.getResources().getColor(
+                    R.color.notification_accent_color, context.getTheme());
         }
         mTextView.setTextColor(mDefaultTextColor);
     }
diff --git a/src/com/android/car/notification/template/CarNotificationBaseViewHolder.java b/src/com/android/car/notification/template/CarNotificationBaseViewHolder.java
index 7e9bcd30..7d58fb3a 100644
--- a/src/com/android/car/notification/template/CarNotificationBaseViewHolder.java
+++ b/src/com/android/car/notification/template/CarNotificationBaseViewHolder.java
@@ -161,9 +161,9 @@ public abstract class CarNotificationBaseViewHolder extends RecyclerView.ViewHol
                 mContext.getResources().getBoolean(R.bool.config_enableSmallIconAccentColor);
         mIsSeenAlpha = mContext.getResources().getFloat(R.dimen.config_olderNotificationsAlpha);
         mUseCustomColorForWarningNotification = mContext.getResources().getBoolean(
-                R.color.warning_background_color);
+                R.bool.config_useCustomColorsForWarningNotification);
         mUseCustomColorForInformationNotification = mContext.getResources().getBoolean(
-                R.color.information_background_color);
+                R.bool.config_useCustomColorsForInformationNotification);
     }
 
     /**
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index 161f6eee..e1df0251 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -30,7 +30,9 @@ android_test {
         "android.test.runner.stubs.system",
         "android.test.base.stubs.system",
         "android.test.mock.stubs.system",
+        "token-shared-lib-prebuilt",
     ],
+    enforce_uses_libs: false,
 
     static_libs: [
         "CarNotificationLibForUnitTesting",
diff --git a/tests/unit/AndroidManifest.xml b/tests/unit/AndroidManifest.xml
index f0fb0811..c64ffd10 100644
--- a/tests/unit/AndroidManifest.xml
+++ b/tests/unit/AndroidManifest.xml
@@ -17,7 +17,7 @@
 
 <manifest
     xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.android.car.notification.tests.unit">
+    package="com.android.car.notification">
 
     <uses-permission android:name="android.permission.INTERNAL_SYSTEM_WINDOW"/>
     <uses-permission android:name="android.permission.INTERACT_ACROSS_USERS"/>
@@ -26,8 +26,10 @@
     <uses-permission android:name="android.permission.ACCESS_VOICE_INTERACTION_SERVICE"/>
     <uses-permission android:name="android.permission.MANAGE_ACTIVITY_TASKS"/>
 
-    <application android:debuggable="true">
+    <application android:name="com.android.car.notification.tests.unit.NotificationTestApplication"
+        android:debuggable="true">
         <uses-library android:name="android.test.runner"/>
+        <uses-library android:name="com.android.oem.tokens" android:required="false"/>
 
         <activity
             android:name="com.android.car.notification.headsup.HeadsUpContainerViewTestActivity"/>
diff --git a/tests/unit/res/layout/test_car_notification_view_layout.xml b/tests/unit/res/layout/test_car_notification_view_layout.xml
index e8363b7c..ba98e603 100644
--- a/tests/unit/res/layout/test_car_notification_view_layout.xml
+++ b/tests/unit/res/layout/test_car_notification_view_layout.xml
@@ -69,7 +69,7 @@
         app:layout_constraintTop_toTopOf="parent"
         app:layout_constraintVertical_chainStyle="packed"
         android:text="@string/empty_notification_header"
-        android:textAppearance="?android:attr/textAppearanceLarge"
+        android:textAppearance="?oemTextAppearanceDisplayLarge"
         android:visibility="gone"/>
 
     <Button
diff --git a/tests/unit/src/com/android/car/notification/CarHeadsUpNotificationManagerTest.java b/tests/unit/src/com/android/car/notification/CarHeadsUpNotificationManagerTest.java
index 0c09c006..1285cb50 100644
--- a/tests/unit/src/com/android/car/notification/CarHeadsUpNotificationManagerTest.java
+++ b/tests/unit/src/com/android/car/notification/CarHeadsUpNotificationManagerTest.java
@@ -32,7 +32,6 @@ import android.app.KeyguardManager;
 import android.app.Notification;
 import android.app.NotificationChannel;
 import android.app.NotificationManager;
-import android.app.PendingIntent;
 import android.content.Context;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageInfo;
@@ -47,14 +46,13 @@ import android.testing.TestableContext;
 import android.view.View;
 
 import androidx.annotation.Nullable;
+import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
-import androidx.test.platform.app.InstrumentationRegistry;
 
 import com.android.car.notification.headsup.CarHeadsUpNotificationContainer;
 import com.android.car.notification.utils.MockMessageNotificationBuilder;
 
 import org.junit.Before;
-import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
@@ -86,14 +84,9 @@ public class CarHeadsUpNotificationManagerTest {
     private static final UserHandle USER_HANDLE = new UserHandle(/* userId= */ 12);
     private static final NotificationChannel CHANNEL = new NotificationChannel(CHANNEL_ID,
             CHANNEL_NAME, NotificationManager.IMPORTANCE_HIGH);
-    @Rule
+
     public final TestableContext mContext = new TestableContext(
-            InstrumentationRegistry.getInstrumentation().getTargetContext()) {
-        @Override
-        public Context createApplicationContext(ApplicationInfo application, int flags) {
-            return this;
-        }
-    };
+            ApplicationProvider.getApplicationContext());
     @Mock
     NotificationListenerService.RankingMap mRankingMapMock;
     @Mock
@@ -105,6 +98,8 @@ public class CarHeadsUpNotificationManagerTest {
     @Mock
     PackageManager mPackageManager;
     @Mock
+    CarNotificationListener mCarNotificationListener;
+    @Mock
     CarHeadsUpNotificationContainer mCarHeadsUpNotificationContainer;
     @Mock
     CarHeadsUpNotificationQueue mCarHeadsUpNotificationQueue;
@@ -118,9 +113,8 @@ public class CarHeadsUpNotificationManagerTest {
     private AlertEntry mAlertEntryMessageHeadsUp;
     private AlertEntry mAlertEntryNavigationHeadsUp;
     private AlertEntry mAlertEntryCallHeadsUp;
+    private AlertEntry mAlertEntryCallHeadsUp2;
     private AlertEntry mAlertEntryInboxHeadsUp;
-    private AlertEntry mAlertEntryWarningHeadsUp;
-    private AlertEntry mAlertEntryEmergencyHeadsUp;
     private AlertEntry mAlertEntryCarInformationHeadsUp;
     private Map<String, AlertEntry> mActiveNotifications;
     private List<CarHeadsUpNotificationManager.HeadsUpState> mHeadsUpStates;
@@ -147,12 +141,12 @@ public class CarHeadsUpNotificationManagerTest {
         when(mKeyguardManager.isKeyguardLocked()).thenReturn(false);
         mContext.addMockSystemService(Context.KEYGUARD_SERVICE, mKeyguardManager);
 
-        when(mClickHandlerFactory.getClickHandler(any())).thenReturn(v -> {
-        });
+        when(mClickHandlerFactory.getClickHandler(any())).thenReturn(v -> {});
 
         when(mRankingMock.getChannel()).thenReturn(CHANNEL);
         when(mRankingMapMock.getRanking(any(), any())).thenReturn(true);
         when(mRankingMock.getImportance()).thenReturn(NotificationManager.IMPORTANCE_HIGH);
+        when(mCarNotificationListener.getCurrentRanking()).thenReturn(mRankingMapMock);
 
         Notification mNotificationMessageHeadsUp = new MockMessageNotificationBuilder(mContext,
                 CHANNEL_ID, android.R.drawable.sym_def_app_icon)
@@ -172,6 +166,11 @@ public class CarHeadsUpNotificationManagerTest {
                 .setContentTitle(CONTENT_TITLE)
                 .setCategory(Notification.CATEGORY_CALL)
                 .build();
+        Notification mNotificationCallHeadsUp2 = new MockMessageNotificationBuilder(mContext,
+                CHANNEL_ID, android.R.drawable.sym_def_app_icon)
+                .setContentTitle(CONTENT_TITLE)
+                .setCategory(Notification.CATEGORY_CALL)
+                .build();
         Notification mNotificationWarningHeadsUp = new MockMessageNotificationBuilder(mContext,
                 CHANNEL_ID, android.R.drawable.sym_def_app_icon)
                 .setContentTitle(CONTENT_TITLE)
@@ -211,17 +210,13 @@ public class CarHeadsUpNotificationManagerTest {
         mAlertEntryCallHeadsUp = new AlertEntry(
                 new StatusBarNotification(PKG_1, OP_PKG, ID, TAG, UID, INITIAL_PID,
                         mNotificationCallHeadsUp, USER_HANDLE, OVERRIDE_GROUP_KEY, POST_TIME));
+        mAlertEntryCallHeadsUp2 = new AlertEntry(
+                new StatusBarNotification(PKG_2, OP_PKG, ID, TAG, UID, INITIAL_PID,
+                        mNotificationCallHeadsUp2, USER_HANDLE, OVERRIDE_GROUP_KEY, POST_TIME));
         mAlertEntryInboxHeadsUp = new AlertEntry(
                 new StatusBarNotification(PKG_1, OP_PKG, ID, TAG, UID, INITIAL_PID,
                         mNotificationBuilderInboxHeadsUp, USER_HANDLE, OVERRIDE_GROUP_KEY,
                         POST_TIME));
-        mAlertEntryWarningHeadsUp = new AlertEntry(
-                new StatusBarNotification(PKG_1, OP_PKG, ID, TAG, UID, INITIAL_PID,
-                        mNotificationWarningHeadsUp, USER_HANDLE, OVERRIDE_GROUP_KEY, POST_TIME));
-        mAlertEntryEmergencyHeadsUp = new AlertEntry(
-                new StatusBarNotification(PKG_1, OP_PKG, ID, TAG, UID, INITIAL_PID,
-                        mNotificationEmergencyHeadsUp, USER_HANDLE, OVERRIDE_GROUP_KEY,
-                        POST_TIME));
         mAlertEntryCarInformationHeadsUp = new AlertEntry(
                 new StatusBarNotification(PKG_1, OP_PKG, ID, TAG, UID, INITIAL_PID,
                         mNotificationCarInformationHeadsUp, USER_HANDLE, OVERRIDE_GROUP_KEY,
@@ -234,142 +229,163 @@ public class CarHeadsUpNotificationManagerTest {
     }
 
     @Test
-    public void maybeShowHeadsUp_isNotImportant_returnsFalseAndNotAddedToQueue()
+    public void maybeShowOrScheduleHun_isNotImportant_returnsFalseAndNotAddedToQueue()
             throws PackageManager.NameNotFoundException {
         when(mRankingMock.getImportance()).thenReturn(NotificationManager.IMPORTANCE_DEFAULT);
         setPackageInfo(PKG_2, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
 
-        boolean result = mManager.maybeShowHeadsUp(mAlertEntryNavigationHeadsUp, mRankingMapMock,
+        boolean result = mManager.maybeShowOrScheduleHun(mAlertEntryNavigationHeadsUp,
                 mActiveNotifications);
 
         assertThat(result).isFalse();
-        verify(mCarHeadsUpNotificationQueue, never()).addToQueue(any(), any());
+        verify(mCarHeadsUpNotificationQueue, never()).addToQueue(any());
     }
 
     @Test
-    public void maybeShowHeadsUp_isImportanceHigh_returnsTrueAndAddedToQueue()
+    public void maybeShowOrScheduleHun_isImportanceHigh_returnsTrueAndAddedToQueue()
             throws PackageManager.NameNotFoundException {
         setPackageInfo(PKG_2, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
 
-        boolean result = mManager.maybeShowHeadsUp(mAlertEntryNavigationHeadsUp, mRankingMapMock,
+        boolean result = mManager.maybeShowOrScheduleHun(mAlertEntryNavigationHeadsUp,
                 mActiveNotifications);
 
         assertThat(result).isTrue();
-        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryNavigationHeadsUp,
-                mRankingMapMock);
+        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryNavigationHeadsUp);
     }
 
     @Test
-    public void maybeShowHeadsUp_categoryCarInformation_returnsFalseAndNotAddedToQueue()
+    public void maybeShowOrScheduleHun_categoryCarInformation_returnsFalseAndNotAddedToQueue()
             throws PackageManager.NameNotFoundException {
         setPackageInfo(PKG_1, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
 
-        boolean result = mManager.maybeShowHeadsUp(mAlertEntryCarInformationHeadsUp,
-                mRankingMapMock, mActiveNotifications);
+        boolean result = mManager.maybeShowOrScheduleHun(mAlertEntryCarInformationHeadsUp,
+                mActiveNotifications);
 
         assertThat(result).isFalse();
-        verify(mCarHeadsUpNotificationQueue, never()).addToQueue(any(), any());
+        verify(mCarHeadsUpNotificationQueue, never()).addToQueue(any());
     }
 
     @Test
-    public void maybeShowHeadsUp_categoryMessage_returnsTrueAndAddedToQueue()
+    public void maybeShowOrScheduleHun_categoryMessage_returnsTrueAndAddedToQueue()
             throws PackageManager.NameNotFoundException {
         setPackageInfo(PKG_1, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
 
-        boolean result = mManager.maybeShowHeadsUp(mAlertEntryMessageHeadsUp, mRankingMapMock,
+        boolean result = mManager.maybeShowOrScheduleHun(mAlertEntryMessageHeadsUp,
                 mActiveNotifications);
 
         assertThat(result).isTrue();
-        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryMessageHeadsUp, mRankingMapMock);
+        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryMessageHeadsUp);
     }
 
     @Test
-    public void maybeShowHeadsUp_categoryCall_returnsTrueAndAddedToQueue()
+    public void maybeShowOrScheduleHun_categoryCall_returnsTrueAndAddedToQueue()
             throws PackageManager.NameNotFoundException {
         setPackageInfo(PKG_1, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
 
-        boolean result = mManager.maybeShowHeadsUp(mAlertEntryCallHeadsUp, mRankingMapMock,
+        boolean result = mManager.maybeShowOrScheduleHun(mAlertEntryCallHeadsUp,
                 mActiveNotifications);
 
         assertThat(result).isTrue();
-        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryCallHeadsUp, mRankingMapMock);
+        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryCallHeadsUp);
     }
 
     @Test
-    public void maybeShowHeadsUp_categoryNavigation_returnsTrueAndAddedToQueue()
+    public void maybeShowOrScheduleHun_categoryNavigation_returnsTrueAndAddedToQueue()
             throws PackageManager.NameNotFoundException {
         setPackageInfo(PKG_1, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
 
-        boolean result = mManager.maybeShowHeadsUp(mAlertEntryNavigationHeadsUp, mRankingMapMock,
+        boolean result = mManager.maybeShowOrScheduleHun(mAlertEntryNavigationHeadsUp,
                 mActiveNotifications);
 
         assertThat(result).isTrue();
-        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryNavigationHeadsUp,
-                mRankingMapMock);
+        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryNavigationHeadsUp);
     }
 
     @Test
-    public void maybeShowHeadsUp_inboxHeadsUp_returnsTrueAndAddedToQueue()
+    public void maybeShowOrScheduleHun_inboxHeadsUp_returnsTrueAndAddedToQueue()
             throws PackageManager.NameNotFoundException {
         setPackageInfo(PKG_1, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
 
-        boolean result = mManager.maybeShowHeadsUp(mAlertEntryInboxHeadsUp, mRankingMapMock,
+        boolean result = mManager.maybeShowOrScheduleHun(mAlertEntryInboxHeadsUp,
                 mActiveNotifications);
 
         assertThat(result).isTrue();
-        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryInboxHeadsUp, mRankingMapMock);
+        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryInboxHeadsUp);
     }
 
     @Test
-    public void maybeShowHeadsUp_isSignedWithPlatformKey_returnsTrueAndAddedToQueue()
+    public void maybeShowOrScheduleHun_isSignedWithPlatformKey_returnsTrueAndAddedToQueue()
             throws PackageManager.NameNotFoundException {
         setPackageInfo(PKG_1, /* isSystem= */ false, /* isSignedWithPlatformKey= */ true);
 
-        boolean result = mManager.maybeShowHeadsUp(mAlertEntryCarInformationHeadsUp,
-                mRankingMapMock, mActiveNotifications);
+        boolean result = mManager.maybeShowOrScheduleHun(mAlertEntryCarInformationHeadsUp,
+                mActiveNotifications);
 
         assertThat(result).isTrue();
-        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryCarInformationHeadsUp,
-                mRankingMapMock);
+        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryCarInformationHeadsUp);
     }
 
     @Test
-    public void maybeShowHeadsUp_isSystemApp_returnsTrueAndAddedToQueue()
+    public void maybeShowOrScheduleHun_isSystemApp_returnsTrueAndAddedToQueue()
             throws PackageManager.NameNotFoundException {
         setPackageInfo(PKG_1, /* isSystem= */ true, /* isSignedWithPlatformKey= */ false);
 
-        boolean result = mManager.maybeShowHeadsUp(mAlertEntryCarInformationHeadsUp,
-                mRankingMapMock, mActiveNotifications);
+        boolean result = mManager.maybeShowOrScheduleHun(mAlertEntryCarInformationHeadsUp,
+                mActiveNotifications);
 
         assertThat(result).isTrue();
-        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryCarInformationHeadsUp,
-                mRankingMapMock);
+        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryCarInformationHeadsUp);
     }
 
     @Test
-    public void maybeShowHeadsUp_nonMutedNotification_returnsTrueAndAddedToQueue()
+    public void maybeShowOrScheduleHun_nonMutedNotification_returnsTrueAndAddedToQueue()
             throws PackageManager.NameNotFoundException {
         when(mNotificationDataManager.isMessageNotificationMuted(any())).thenReturn(false);
         setPackageInfo(PKG_1, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
 
-        boolean result = mManager.maybeShowHeadsUp(mAlertEntryInboxHeadsUp, mRankingMapMock,
+        boolean result = mManager.maybeShowOrScheduleHun(mAlertEntryInboxHeadsUp,
                 mActiveNotifications);
 
         assertThat(result).isTrue();
-        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryInboxHeadsUp, mRankingMapMock);
+        verify(mCarHeadsUpNotificationQueue).addToQueue(mAlertEntryInboxHeadsUp);
     }
 
     @Test
-    public void maybeShowHeadsUp_mutedNotification_returnsFalseAndNotAddedToQueue()
+    public void maybeShowOrScheduleHun_mutedNotification_returnsFalseAndNotAddedToQueue()
             throws PackageManager.NameNotFoundException {
         when(mNotificationDataManager.isMessageNotificationMuted(any())).thenReturn(true);
         setPackageInfo(PKG_1, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
 
-        boolean result = mManager.maybeShowHeadsUp(mAlertEntryInboxHeadsUp, mRankingMapMock,
+        boolean result = mManager.maybeShowOrScheduleHun(mAlertEntryCallHeadsUp,
                 mActiveNotifications);
 
         assertThat(result).isFalse();
-        verify(mCarHeadsUpNotificationQueue, never()).addToQueue(any(), any());
+        verify(mCarHeadsUpNotificationQueue, never()).addToQueue(any());
+    }
+
+    @Test
+    public void maybeShowOrScheduleHun_simultaneousCall_returnsTrueAndAddedToPendingCalls()
+            throws PackageManager.NameNotFoundException {
+        mContext.getOrCreateTestableResources().addOverride(
+                R.bool.config_suppressAndThrottleHeadsUp, /* value= */ false);
+        createCarHeadsUpNotificationManager();
+
+        setPackageInfo(PKG_1, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
+        setPackageInfo(PKG_2, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
+
+        Looper.prepare();
+
+        mManager.maybeShowOrScheduleHun(mAlertEntryCallHeadsUp, mActiveNotifications);
+        assertThat(NotificationUtils.isCategoryCall(mAlertEntryCallHeadsUp)).isTrue();
+        assertThat(mManager.getPendingCalls().size()).isEqualTo(0);
+
+        HeadsUpEntry headsUpEntry = createMockHeadsUpEntry("key1");
+        when(headsUpEntry.getNotification()).thenReturn(mAlertEntryCallHeadsUp.getNotification());
+        assertThat(NotificationUtils.isCategoryCall(headsUpEntry)).isTrue();
+
+        mManager.addActiveHeadsUpNotification(headsUpEntry);
+        mManager.maybeShowOrScheduleHun(mAlertEntryCallHeadsUp2, mActiveNotifications);
+        assertThat(mManager.getPendingCalls().size()).isEqualTo(1);
     }
 
     @Test
@@ -383,8 +399,7 @@ public class CarHeadsUpNotificationManagerTest {
         // HeadsUpEntry}.
         Looper.prepare();
         setPackageInfo(PKG_2, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
-        mManager.maybeShowHeadsUp(mAlertEntryNavigationHeadsUp, mRankingMapMock,
-                mActiveNotifications);
+        mManager.maybeShowOrScheduleHun(mAlertEntryNavigationHeadsUp, mActiveNotifications);
 
         Map<String, HeadsUpEntry> activeHeadsUpNotifications =
                 mManager.getActiveHeadsUpNotifications();
@@ -404,9 +419,8 @@ public class CarHeadsUpNotificationManagerTest {
         Looper.prepare();
         setPackageInfo(PKG_1, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
         setPackageInfo(PKG_2, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
-        mManager.maybeShowHeadsUp(mAlertEntryCallHeadsUp, mRankingMapMock, mActiveNotifications);
-        mManager.maybeShowHeadsUp(mAlertEntryNavigationHeadsUp, mRankingMapMock,
-                mActiveNotifications);
+        mManager.maybeShowOrScheduleHun(mAlertEntryCallHeadsUp, mActiveNotifications);
+        mManager.maybeShowOrScheduleHun(mAlertEntryNavigationHeadsUp, mActiveNotifications);
 
         Map<String, HeadsUpEntry> activeHeadsUpNotifications =
                 mManager.getActiveHeadsUpNotifications();
@@ -425,8 +439,8 @@ public class CarHeadsUpNotificationManagerTest {
         // HeadsUpEntry}.
         Looper.prepare();
         setPackageInfo(PKG_1, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
-        mManager.maybeShowHeadsUp(mAlertEntryCallHeadsUp, mRankingMapMock, mActiveNotifications);
-        mManager.maybeShowHeadsUp(mAlertEntryCallHeadsUp, mRankingMapMock, mActiveNotifications);
+        mManager.maybeShowOrScheduleHun(mAlertEntryCallHeadsUp, mActiveNotifications);
+        mManager.maybeShowOrScheduleHun(mAlertEntryCallHeadsUp, mActiveNotifications);
 
         Map<String, HeadsUpEntry> activeHeadsUpNotifications =
                 mManager.getActiveHeadsUpNotifications();
@@ -434,22 +448,6 @@ public class CarHeadsUpNotificationManagerTest {
         assertThat(activeHeadsUpNotifications.size()).isEqualTo(1);
     }
 
-    @Test
-    public void isHeadsUpDismissible_ongoingCallNotificationWithFullScreenIntent_returnsFalse() {
-        Notification.Builder notificationBuilder = new Notification.Builder(mContext, CHANNEL_ID)
-                .setCategory(Notification.CATEGORY_CALL)
-                .setOngoing(true)
-                .setFullScreenIntent(mock(PendingIntent.class), /* highPriority= */ true);
-        StatusBarNotification sbn = mock(StatusBarNotification.class);
-        when(sbn.getNotification()).thenReturn(notificationBuilder.build());
-        when(sbn.isOngoing()).thenReturn(true);
-        AlertEntry alertEntry = new AlertEntry(sbn, /* postTime= */ 1000);
-
-        boolean result = CarHeadsUpNotificationManager.isHeadsUpDismissible(alertEntry);
-
-        assertThat(result).isFalse();
-    }
-
     @Test
     public void notification_removedFromQueue_notifyListeners()
             throws PackageManager.NameNotFoundException {
@@ -483,6 +481,69 @@ public class CarHeadsUpNotificationManagerTest {
                 .isTrue();
     }
 
+
+    @Test
+    public void maybeRemoveHeadsUp_categoryCall_removesActiveEntry()
+            throws PackageManager.NameNotFoundException {
+        mContext.getOrCreateTestableResources().addOverride(
+                R.bool.config_suppressAndThrottleHeadsUp, /* value= */ false);
+        createCarHeadsUpNotificationManager();
+
+        setPackageInfo(PKG_1, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
+        setPackageInfo(PKG_2, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
+
+        Looper.prepare();
+
+        mManager.maybeShowOrScheduleHun(mAlertEntryCallHeadsUp, mActiveNotifications);
+        assertThat(NotificationUtils.isCategoryCall(mAlertEntryCallHeadsUp)).isTrue();
+        assertThat(mManager.getPendingCalls().size()).isEqualTo(0);
+
+        HeadsUpEntry headsUpEntry = createMockHeadsUpEntry(mAlertEntryCallHeadsUp.getKey());
+        when(headsUpEntry.getNotification()).thenReturn(mAlertEntryCallHeadsUp.getNotification());
+        assertThat(NotificationUtils.isCategoryCall(headsUpEntry)).isTrue();
+
+        mManager.addActiveHeadsUpNotification(headsUpEntry);
+        mManager.maybeShowOrScheduleHun(mAlertEntryCallHeadsUp2, mActiveNotifications);
+        assertThat(mManager.getPendingCalls().size()).isEqualTo(1);
+        assertThat(headsUpEntry.getHandler().hasMessagesOrCallbacks()).isFalse();
+
+        mManager.maybeRemoveHeadsUp(mAlertEntryCallHeadsUp);
+        assertThat(mManager.getPendingCalls().size()).isEqualTo(1);
+        // verify that headsUpEntry was reset before removed
+        verify(headsUpEntry.getHandler(), times(1))
+                .removeCallbacksAndMessages(any());
+    }
+
+    @Test
+    public void maybeRemoveHeadsUp_categoryCall_removesPendingEntry()
+            throws PackageManager.NameNotFoundException {
+        mContext.getOrCreateTestableResources().addOverride(
+                R.bool.config_suppressAndThrottleHeadsUp, /* value= */ false);
+        createCarHeadsUpNotificationManager();
+
+        setPackageInfo(PKG_1, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
+        setPackageInfo(PKG_2, /* isSystem= */ false, /* isSignedWithPlatformKey= */ false);
+
+        Looper.prepare();
+
+        mManager.maybeShowOrScheduleHun(mAlertEntryCallHeadsUp, mActiveNotifications);
+        assertThat(NotificationUtils.isCategoryCall(mAlertEntryCallHeadsUp)).isTrue();
+        assertThat(mManager.getPendingCalls().size()).isEqualTo(0);
+
+        HeadsUpEntry headsUpEntry = createMockHeadsUpEntry("key1");
+        when(headsUpEntry.getNotification()).thenReturn(mAlertEntryCallHeadsUp.getNotification());
+        assertThat(NotificationUtils.isCategoryCall(headsUpEntry)).isTrue();
+
+        mManager.addActiveHeadsUpNotification(headsUpEntry);
+        mManager.maybeShowOrScheduleHun(mAlertEntryCallHeadsUp2, mActiveNotifications);
+        assertThat(mManager.getPendingCalls().size()).isEqualTo(1);
+
+        mManager.maybeRemoveHeadsUp(mAlertEntryCallHeadsUp2);
+        // verify that headsUpEntry was NOT reset and therefore remains displayed to user
+        verify(headsUpEntry.getHandler(), times(0))
+                .removeCallbacksAndMessages(any());
+    }
+
     private void createCarHeadsUpNotificationManager() {
         createCarHeadsUpNotificationManager(mCarHeadsUpNotificationQueue);
     }
@@ -500,6 +561,7 @@ public class CarHeadsUpNotificationManagerTest {
             mManager.setCarHeadsUpNotificationQueue(carHeadsUpNotificationQueue);
         }
         mManager.setNotificationDataManager(mNotificationDataManager);
+        mManager.setRankingMapProvider(mCarNotificationListener);
     }
 
     private void setPackageInfo(String packageName, boolean isSystem,
diff --git a/tests/unit/src/com/android/car/notification/CarHeadsUpNotificationQueueTest.java b/tests/unit/src/com/android/car/notification/CarHeadsUpNotificationQueueTest.java
index 1a465399..3a9f6e9c 100644
--- a/tests/unit/src/com/android/car/notification/CarHeadsUpNotificationQueueTest.java
+++ b/tests/unit/src/com/android/car/notification/CarHeadsUpNotificationQueueTest.java
@@ -23,7 +23,6 @@ import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
-import static org.mockito.ArgumentMatchers.nullable;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
@@ -43,8 +42,8 @@ import android.service.notification.NotificationListenerService;
 import android.service.notification.StatusBarNotification;
 import android.testing.TestableContext;
 
+import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
-import androidx.test.platform.app.InstrumentationRegistry;
 
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 
@@ -97,7 +96,7 @@ public class CarHeadsUpNotificationQueueTest {
 
     @Rule
     public final TestableContext mContext = new TestableContext(
-            InstrumentationRegistry.getInstrumentation().getTargetContext());
+            ApplicationProvider.getApplicationContext());
 
     private static final String PKG_1 = "PKG_1";
     private static final String PKG_2 = "PKG_2";
@@ -144,11 +143,11 @@ public class CarHeadsUpNotificationQueueTest {
         AlertEntry alertEntry5 = new AlertEntry(generateMockStatusBarNotification(
                 "key5", "msg"), 1000);
 
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry1, mRankingMap);
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry2, mRankingMap);
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry3, mRankingMap);
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry4, mRankingMap);
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry5, mRankingMap);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry1);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry2);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry3);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry4);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry5);
 
         PriorityQueue<String> result = mCarHeadsUpNotificationQueue.getPriorityQueue();
         assertThat(result.size()).isEqualTo(5);
@@ -178,11 +177,11 @@ public class CarHeadsUpNotificationQueueTest {
         AlertEntry alertEntry5 = new AlertEntry(generateMockStatusBarNotification(
                 "key5", "msg"), 1000);
 
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry1, mRankingMap);
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry2, mRankingMap);
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry3, mRankingMap);
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry4, mRankingMap);
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry5, mRankingMap);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry1);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry2);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry3);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry4);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry5);
 
         PriorityQueue<String> result = mCarHeadsUpNotificationQueue.getPriorityQueue();
         assertThat(result.size()).isEqualTo(5);
@@ -209,10 +208,10 @@ public class CarHeadsUpNotificationQueueTest {
         AlertEntry alertEntry4 = new AlertEntry(generateMockStatusBarNotification(
                 "key4", "msg"), 1000);
 
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry1, mRankingMap);
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry2, mRankingMap);
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry3, mRankingMap);
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry4, mRankingMap);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry1);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry2);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry3);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry4);
 
         PriorityQueue<String> result = mCarHeadsUpNotificationQueue.getPriorityQueue();
         assertThat(result.size()).isEqualTo(4);
@@ -232,9 +231,9 @@ public class CarHeadsUpNotificationQueueTest {
         AlertEntry alertEntry3 = new AlertEntry(generateMockStatusBarNotification(
                 "key1", "msg"), 3000);
 
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry1, mRankingMap);
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry2, mRankingMap);
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry3, mRankingMap);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry1);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry2);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry3);
 
         PriorityQueue<String> result = mCarHeadsUpNotificationQueue.getPriorityQueue();
         assertThat(result.size()).isEqualTo(2);
@@ -257,13 +256,11 @@ public class CarHeadsUpNotificationQueueTest {
         when(mCarHeadsUpNotificationQueueCallback.getActiveHeadsUpNotifications()).thenReturn(
                 new ArrayList<>(Collections.singletonList(alertEntry3)));
 
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry1, mRankingMap);
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry2, mRankingMap);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry1);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry2);
 
-        verify(mCarHeadsUpNotificationQueueCallback).dismissHeadsUp(alertEntry3);
         verify(mCarHeadsUpNotificationQueueCallback)
-                .showAsHeadsUp(mAlertEntryArg.capture(),
-                        any(NotificationListenerService.RankingMap.class));
+                .showAsHeadsUp(mAlertEntryArg.capture());
         assertThat(mAlertEntryArg.getValue().getKey()).isEqualTo("key2");
     }
 
@@ -273,7 +270,7 @@ public class CarHeadsUpNotificationQueueTest {
         AlertEntry alertEntry1 = new AlertEntry(generateMockStatusBarNotification(
                 "key1", /* category= */ null), 4000);
 
-        mCarHeadsUpNotificationQueue.addToQueue(alertEntry1, mRankingMap);
+        mCarHeadsUpNotificationQueue.addToQueue(alertEntry1);
 
         PriorityQueue<String> result = mCarHeadsUpNotificationQueue.getPriorityQueue();
         assertThat(result.size()).isEqualTo(1);
@@ -309,8 +306,7 @@ public class CarHeadsUpNotificationQueueTest {
                 .removedFromHeadsUpQueue(mAlertEntryArg.capture());
         assertThat(mAlertEntryArg.getValue().getKey()).isEqualTo("key1");
         verify(mCarHeadsUpNotificationQueueCallback)
-                .showAsHeadsUp(mAlertEntryArg.capture(),
-                        nullable(NotificationListenerService.RankingMap.class));
+                .showAsHeadsUp(mAlertEntryArg.capture());
         assertThat(mAlertEntryArg.getValue().getKey()).isEqualTo("key2");
         assertThat(result.contains("key3")).isTrue();
     }
@@ -341,8 +337,7 @@ public class CarHeadsUpNotificationQueueTest {
 
         PriorityQueue<String> result = mCarHeadsUpNotificationQueue.getPriorityQueue();
         verify(mCarHeadsUpNotificationQueueCallback)
-                .showAsHeadsUp(mAlertEntryArg.capture(),
-                        nullable(NotificationListenerService.RankingMap.class));
+                .showAsHeadsUp(mAlertEntryArg.capture());
         assertThat(mAlertEntryArg.getValue().getKey()).isEqualTo("key1");
         assertThat(result.contains("key2")).isTrue();
         assertThat(result.contains("key3")).isTrue();
@@ -377,8 +372,7 @@ public class CarHeadsUpNotificationQueueTest {
                 .removedFromHeadsUpQueue(mAlertEntryArg.capture());
         assertThat(mAlertEntryArg.getValue().getKey()).isEqualTo("key1");
         verify(mCarHeadsUpNotificationQueueCallback)
-                .showAsHeadsUp(mAlertEntryArg.capture(),
-                        nullable(NotificationListenerService.RankingMap.class));
+                .showAsHeadsUp(mAlertEntryArg.capture());
         assertThat(mAlertEntryArg.getValue().getKey()).isEqualTo("key2");
         assertThat(result.contains("key3")).isTrue();
     }
@@ -515,8 +509,7 @@ public class CarHeadsUpNotificationQueueTest {
 
         PriorityQueue<String> result = mCarHeadsUpNotificationQueue.getPriorityQueue();
         verify(mCarHeadsUpNotificationQueueCallback)
-                .showAsHeadsUp(mAlertEntryArg.capture(),
-                        nullable(NotificationListenerService.RankingMap.class));
+                .showAsHeadsUp(mAlertEntryArg.capture());
         assertThat(mAlertEntryArg.getValue().getKey()).isEqualTo("key1");
         assertThat(result.contains("key2")).isTrue();
         assertThat(result.contains("key3")).isTrue();
@@ -542,8 +535,7 @@ public class CarHeadsUpNotificationQueueTest {
         mTaskStackListenerArg.getValue().onTaskMovedToFront(mockRunningTaskInfo);
         mCarHeadsUpNotificationQueue.triggerCallback();
 
-        verify(mCarHeadsUpNotificationQueueCallback, never()).showAsHeadsUp(
-                any(AlertEntry.class), nullable(NotificationListenerService.RankingMap.class));
+        verify(mCarHeadsUpNotificationQueueCallback, never()).showAsHeadsUp(any(AlertEntry.class));
     }
 
     @Test
@@ -566,8 +558,7 @@ public class CarHeadsUpNotificationQueueTest {
         mTaskStackListenerArg.getValue().onTaskMovedToFront(mockRunningTaskInfo);
         mCarHeadsUpNotificationQueue.triggerCallback();
 
-        verify(mCarHeadsUpNotificationQueueCallback).showAsHeadsUp(
-                mAlertEntryArg.capture(), nullable(NotificationListenerService.RankingMap.class));
+        verify(mCarHeadsUpNotificationQueueCallback).showAsHeadsUp(mAlertEntryArg.capture());
         assertThat(mAlertEntryArg.getValue().getKey()).isEqualTo("key1");
     }
 
@@ -830,8 +821,7 @@ public class CarHeadsUpNotificationQueueTest {
         mCarHeadsUpNotificationQueue.onStateChange(alertEntry,
                 CarHeadsUpNotificationManager.HeadsUpState.SHOWN);
 
-        verify(mCarHeadsUpNotificationQueueCallback, never()).showAsHeadsUp(any(AlertEntry.class),
-                nullable(NotificationListenerService.RankingMap.class));
+        verify(mCarHeadsUpNotificationQueueCallback, never()).showAsHeadsUp(any(AlertEntry.class));
     }
 
     @Test
@@ -850,8 +840,7 @@ public class CarHeadsUpNotificationQueueTest {
         mCarHeadsUpNotificationQueue.onStateChange(alertEntry,
                 CarHeadsUpNotificationManager.HeadsUpState.REMOVED_FROM_QUEUE);
 
-        verify(mCarHeadsUpNotificationQueueCallback, never()).showAsHeadsUp(any(AlertEntry.class),
-                nullable(NotificationListenerService.RankingMap.class));
+        verify(mCarHeadsUpNotificationQueueCallback, never()).showAsHeadsUp(any(AlertEntry.class));
     }
 
 
diff --git a/tests/unit/src/com/android/car/notification/CarNotificationListenerTest.java b/tests/unit/src/com/android/car/notification/CarNotificationListenerTest.java
index 93b6bdb9..addec9f7 100644
--- a/tests/unit/src/com/android/car/notification/CarNotificationListenerTest.java
+++ b/tests/unit/src/com/android/car/notification/CarNotificationListenerTest.java
@@ -388,7 +388,7 @@ public class CarNotificationListenerTest {
         if (isHeadsUpNotification) {
             // Messages are always heads-up notifications.
             notification.category = Notification.CATEGORY_MESSAGE;
-            when(mCarHeadsUpNotificationManager.maybeShowHeadsUp(any(), any(), any()))
+            when(mCarHeadsUpNotificationManager.maybeShowOrScheduleHun(any(), any()))
                     .thenReturn(true);
         }
 
diff --git a/tests/unit/src/com/android/car/notification/CarNotificationViewAdapterTest.java b/tests/unit/src/com/android/car/notification/CarNotificationViewAdapterTest.java
index 92d8ef3d..8df0ff83 100644
--- a/tests/unit/src/com/android/car/notification/CarNotificationViewAdapterTest.java
+++ b/tests/unit/src/com/android/car/notification/CarNotificationViewAdapterTest.java
@@ -28,7 +28,6 @@ import static org.testng.Assert.assertThrows;
 
 import android.app.Notification;
 import android.car.drivingstate.CarUxRestrictions;
-import android.content.Context;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
 import android.os.UserHandle;
@@ -39,8 +38,8 @@ import android.view.View;
 
 import androidx.annotation.Nullable;
 import androidx.recyclerview.widget.RecyclerView;
+import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
-import androidx.test.platform.app.InstrumentationRegistry;
 
 import com.android.car.notification.template.BasicNotificationViewHolder;
 import com.android.car.notification.template.CarNotificationBaseViewHolder;
@@ -51,7 +50,6 @@ import com.android.car.notification.template.MessageNotificationViewHolder;
 import com.android.car.notification.template.ProgressNotificationViewHolder;
 
 import org.junit.Before;
-import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
@@ -75,14 +73,8 @@ public class CarNotificationViewAdapterTest {
     private static final long POST_TIME = 12345l;
     private static final UserHandle USER_HANDLE = new UserHandle(12);
 
-    @Rule
     public final TestableContext mContext = new TestableContext(
-            InstrumentationRegistry.getInstrumentation().getTargetContext()) {
-        @Override
-        public Context createApplicationContext(ApplicationInfo application, int flags) {
-            return this;
-        }
-    };
+            ApplicationProvider.getApplicationContext());
 
     @Mock
     NotificationClickHandlerFactory mClickHandlerFactoryMock;
diff --git a/tests/unit/src/com/android/car/notification/CarNotificationViewTest.java b/tests/unit/src/com/android/car/notification/CarNotificationViewTest.java
index 40e3b2a3..cc325f3f 100644
--- a/tests/unit/src/com/android/car/notification/CarNotificationViewTest.java
+++ b/tests/unit/src/com/android/car/notification/CarNotificationViewTest.java
@@ -26,9 +26,7 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.app.Notification;
-import android.content.Context;
 import android.content.Intent;
-import android.content.pm.ApplicationInfo;
 import android.os.UserHandle;
 import android.provider.Settings;
 import android.service.notification.StatusBarNotification;
@@ -39,13 +37,12 @@ import android.widget.Button;
 import android.widget.FrameLayout;
 
 import androidx.recyclerview.widget.RecyclerView;
+import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
-import androidx.test.platform.app.InstrumentationRegistry;
 
 import com.android.car.notification.template.GroupNotificationViewHolder;
 
 import org.junit.Before;
-import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
@@ -73,14 +70,8 @@ public class CarNotificationViewTest {
 
     private CarNotificationView mCarNotificationView;
 
-    @Rule
     public TestableContext mContext = new TestableContext(
-            InstrumentationRegistry.getInstrumentation().getTargetContext()) {
-        @Override
-        public Context createApplicationContext(ApplicationInfo application, int flags) {
-            return this;
-        }
-    };
+            ApplicationProvider.getApplicationContext());
 
     @Mock
     private NotificationClickHandlerFactory mClickHandlerFactory;
@@ -323,4 +314,4 @@ public class CarNotificationViewTest {
 
         return notificationGroup;
     }
-}
\ No newline at end of file
+}
diff --git a/tests/unit/src/com/android/car/notification/CarNotificationVisibilityLoggerTest.java b/tests/unit/src/com/android/car/notification/CarNotificationVisibilityLoggerTest.java
index 0fe97c88..9311e96a 100644
--- a/tests/unit/src/com/android/car/notification/CarNotificationVisibilityLoggerTest.java
+++ b/tests/unit/src/com/android/car/notification/CarNotificationVisibilityLoggerTest.java
@@ -24,21 +24,18 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.app.Notification;
-import android.content.Context;
-import android.content.pm.ApplicationInfo;
 import android.os.RemoteException;
 import android.os.UserHandle;
 import android.service.notification.StatusBarNotification;
 import android.testing.TestableContext;
 
+import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
-import androidx.test.platform.app.InstrumentationRegistry;
 
 import com.android.internal.statusbar.IStatusBarService;
 import com.android.internal.statusbar.NotificationVisibility;
 
 import org.junit.Before;
-import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
@@ -62,14 +59,8 @@ public class CarNotificationVisibilityLoggerTest {
     private static final long POST_TIME = 12345L;
     private static final UserHandle USER_HANDLE = new UserHandle(12);
 
-    @Rule
-    public TestableContext mContext = new TestableContext(
-            InstrumentationRegistry.getInstrumentation().getTargetContext()) {
-        @Override
-        public Context createApplicationContext(ApplicationInfo application, int flags) {
-            return this;
-        }
-    };
+    public final TestableContext mContext = new TestableContext(
+            ApplicationProvider.getApplicationContext());
 
     @Mock
     private IStatusBarService mBarService;
diff --git a/tests/unit/src/com/android/car/notification/HeadsUpNotificationOnTouchListenerTest.java b/tests/unit/src/com/android/car/notification/HeadsUpNotificationOnTouchListenerTest.java
index e2cd469b..5132dc72 100644
--- a/tests/unit/src/com/android/car/notification/HeadsUpNotificationOnTouchListenerTest.java
+++ b/tests/unit/src/com/android/car/notification/HeadsUpNotificationOnTouchListenerTest.java
@@ -383,7 +383,7 @@ public class HeadsUpNotificationOnTouchListenerTest {
 
     private void createHeadsUpNotificationOnTouchListener() {
         mHeadsUpNotificationOnTouchListener = new HeadsUpNotificationOnTouchListener(mView,
-                /* dismissOnSwipe= */ true, mDismissCallbacks) {
+                mDismissCallbacks) {
             @Override
             MotionEvent obtainMotionEvent(MotionEvent motionEvent) {
                 return mNewMotionEvent;
diff --git a/tests/unit/src/com/android/car/notification/NotificationClickHandlerFactoryTest.java b/tests/unit/src/com/android/car/notification/NotificationClickHandlerFactoryTest.java
index 1dd0682d..fcde3da0 100644
--- a/tests/unit/src/com/android/car/notification/NotificationClickHandlerFactoryTest.java
+++ b/tests/unit/src/com/android/car/notification/NotificationClickHandlerFactoryTest.java
@@ -230,7 +230,8 @@ public class NotificationClickHandlerFactoryTest {
                     mAlertEntry1.getKey(),
                     NotificationStats.DISMISSAL_SHADE,
                     NotificationStats.DISMISS_SENTIMENT_NEUTRAL,
-                    notificationVisibility);
+                    notificationVisibility,
+                    /* fromBundle= */ false);
         } catch (RemoteException ex) {
             // ignore
         }
@@ -389,7 +390,8 @@ public class NotificationClickHandlerFactoryTest {
                     mAlertEntryMessageWithMuteAction.getStatusBarNotification().getKey(),
                     NotificationStats.DISMISSAL_SHADE,
                     NotificationStats.DISMISS_SENTIMENT_NEUTRAL,
-                    notificationVisibility);
+                    notificationVisibility,
+                    /* fromBundle= */ false);
         } catch (RemoteException e) {
             // ignore.
         }
@@ -538,7 +540,8 @@ public class NotificationClickHandlerFactoryTest {
                     mAlertEntry1.getStatusBarNotification().getKey(),
                     NotificationStats.DISMISSAL_SHADE,
                     NotificationStats.DISMISS_SENTIMENT_NEUTRAL,
-                    notificationVisibility);
+                    notificationVisibility,
+                    /* fromBundle= */ false);
         } catch (RemoteException e) {
             // ignore.
         }
@@ -568,7 +571,8 @@ public class NotificationClickHandlerFactoryTest {
                     mAlertEntry2.getStatusBarNotification().getKey(),
                     NotificationStats.DISMISSAL_SHADE,
                     NotificationStats.DISMISS_SENTIMENT_NEUTRAL,
-                    notificationVisibility);
+                    notificationVisibility,
+                    /* fromBundle= */ false);
         } catch (RemoteException e) {
             // ignore.
         }
@@ -597,7 +601,8 @@ public class NotificationClickHandlerFactoryTest {
                     mAlertEntry2.getStatusBarNotification().getKey(),
                     NotificationStats.DISMISSAL_SHADE,
                     NotificationStats.DISMISS_SENTIMENT_NEUTRAL,
-                    notificationVisibility);
+                    notificationVisibility,
+                    /* fromBundle= */ false);
         } catch (RemoteException e) {
             // ignore.
         }
diff --git a/tests/unit/src/com/android/car/notification/NotificationTestApplication.java b/tests/unit/src/com/android/car/notification/NotificationTestApplication.java
new file mode 100644
index 00000000..54775818
--- /dev/null
+++ b/tests/unit/src/com/android/car/notification/NotificationTestApplication.java
@@ -0,0 +1,30 @@
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
+package com.android.car.notification.tests.unit;
+
+import android.app.Application;
+import android.content.Context;
+
+import com.android.car.oem.tokens.Token;
+
+public class NotificationTestApplication extends Application {
+    @Override
+    public void attachBaseContext(Context base) {
+        Context context = Token.createOemStyledContext(base);
+        super.attachBaseContext(context);
+    }
+}
diff --git a/tests/unit/src/com/android/car/notification/NotificationUtilsTest.java b/tests/unit/src/com/android/car/notification/NotificationUtilsTest.java
index 832a8429..a91d69de 100644
--- a/tests/unit/src/com/android/car/notification/NotificationUtilsTest.java
+++ b/tests/unit/src/com/android/car/notification/NotificationUtilsTest.java
@@ -34,14 +34,13 @@ import android.os.UserManager;
 import android.service.notification.StatusBarNotification;
 import android.testing.TestableContext;
 
+import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
-import androidx.test.platform.app.InstrumentationRegistry;
 
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 
 import org.junit.After;
 import org.junit.Before;
-import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
@@ -53,9 +52,8 @@ import java.util.Map;
 
 @RunWith(AndroidJUnit4.class)
 public class NotificationUtilsTest {
-    @Rule
     public final TestableContext mContext = new TestableContext(
-            InstrumentationRegistry.getInstrumentation().getTargetContext());
+            ApplicationProvider.getApplicationContext());
 
     private static final String CHANNEL_ID = "CHANNEL_ID";
     private static final String CONTENT_TITLE = "CONTENT_TITLE";
diff --git a/tests/unit/src/com/android/car/notification/PreprocessingManagerTest.java b/tests/unit/src/com/android/car/notification/PreprocessingManagerTest.java
index 9982f30e..972e890e 100644
--- a/tests/unit/src/com/android/car/notification/PreprocessingManagerTest.java
+++ b/tests/unit/src/com/android/car/notification/PreprocessingManagerTest.java
@@ -49,11 +49,10 @@ import android.testing.TestableContext;
 import android.testing.TestableResources;
 import android.text.TextUtils;
 
+import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
-import androidx.test.platform.app.InstrumentationRegistry;
 
 import org.junit.Before;
-import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
@@ -92,9 +91,8 @@ public class PreprocessingManagerTest {
     private static final String GROUP_KEY_D = "GROUP_KEY_D";
     private static final int MAX_STRING_LENGTH = 10;
     private static final int DEFAULT_MIN_GROUPING_THRESHOLD = 4;
-    @Rule
     public final TestableContext mContext = new TestableContext(
-            InstrumentationRegistry.getInstrumentation().getTargetContext());
+            ApplicationProvider.getApplicationContext());
     @Mock
     private StatusBarNotification mStatusBarNotification1;
     @Mock
@@ -276,6 +274,33 @@ public class PreprocessingManagerTest {
         initTestData(/* includeAdditionalNotifs= */ false);
     }
 
+    @Test
+    public void onFilter_filtersLessImportantForeground() {
+        mPreprocessingManager
+                .filter(mAlertEntries, mRankingMap);
+
+        assertThat(mAlertEntries.contains(mLessImportantBackground)).isTrue();
+        assertThat(mAlertEntries.contains(mLessImportantForeground)).isFalse();
+    }
+
+    @Test
+    public void onFilter_doesNotFilterMoreImportantForeground() {
+        mPreprocessingManager
+                .filter(mAlertEntries, mRankingMap);
+
+        assertThat(mAlertEntries.contains(mImportantBackground)).isTrue();
+        assertThat(mAlertEntries.contains(mImportantForeground)).isTrue();
+    }
+
+    @Test
+    public void onFilter_filtersMediaAndNavigation() {
+        mPreprocessingManager
+                .filter(mAlertEntries, mRankingMap);
+
+        assertThat(mAlertEntries.contains(mMedia)).isFalse();
+        assertThat(mAlertEntries.contains(mNavigation)).isFalse();
+    }
+
     @Test
     public void onOptimizeForDriving_alertEntryHasNonMessageNotification_trimsNotificationTexts() {
         when(mCarUxRestrictions.getMaxRestrictedStringLength()).thenReturn(MAX_STRING_LENGTH);
diff --git a/tests/unit/src/com/android/car/notification/headsup/HeadsUpContainerViewTestActivity.java b/tests/unit/src/com/android/car/notification/headsup/HeadsUpContainerViewTestActivity.java
index a118a69f..9d510dc2 100644
--- a/tests/unit/src/com/android/car/notification/headsup/HeadsUpContainerViewTestActivity.java
+++ b/tests/unit/src/com/android/car/notification/headsup/HeadsUpContainerViewTestActivity.java
@@ -21,17 +21,14 @@ import android.os.Bundle;
 import android.testing.TestableContext;
 
 import androidx.annotation.Nullable;
-import androidx.test.platform.app.InstrumentationRegistry;
+import androidx.test.core.app.ApplicationProvider;
 
 import com.android.car.notification.R;
 
-import org.junit.Rule;
-
 public class HeadsUpContainerViewTestActivity extends Activity {
     private HeadsUpContainerView mHeadsUpContainerView;
-    @Rule
     public final TestableContext mContext = new TestableContext(
-            InstrumentationRegistry.getInstrumentation().getTargetContext());
+            ApplicationProvider.getApplicationContext());
 
     @Override
     protected void onCreate(@Nullable Bundle savedInstanceState) {
diff --git a/tests/unit/src/com/android/car/notification/template/GroupNotificationViewHolderTest.java b/tests/unit/src/com/android/car/notification/template/GroupNotificationViewHolderTest.java
index b83eae4d..38803089 100644
--- a/tests/unit/src/com/android/car/notification/template/GroupNotificationViewHolderTest.java
+++ b/tests/unit/src/com/android/car/notification/template/GroupNotificationViewHolderTest.java
@@ -32,8 +32,8 @@ import android.view.LayoutInflater;
 import android.view.View;
 
 import androidx.recyclerview.widget.RecyclerView;
+import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
-import androidx.test.platform.app.InstrumentationRegistry;
 
 import com.android.car.notification.AlertEntry;
 import com.android.car.notification.CarNotificationViewAdapter;
@@ -43,7 +43,6 @@ import com.android.car.notification.R;
 import com.android.car.notification.utils.MockMessageNotificationBuilder;
 
 import org.junit.Before;
-import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
@@ -63,9 +62,8 @@ public class GroupNotificationViewHolderTest {
     private static final String OVERRIDE_GROUP_KEY = "OVERRIDE_GROUP_KEY";
     private static final long POST_TIME = 12345L;
     private static final UserHandle USER_HANDLE = new UserHandle(/* userId= */ 12);
-    @Rule
     public final TestableContext mContext = new TestableContext(
-            InstrumentationRegistry.getInstrumentation().getTargetContext());
+            ApplicationProvider.getApplicationContext());
     private GroupNotificationViewHolder mGroupNotificationViewHolder;
     private RecyclerView mNotificationListView;
     private View mExpansionFooterView;
```

