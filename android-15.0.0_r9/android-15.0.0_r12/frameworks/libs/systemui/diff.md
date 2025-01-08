```diff
diff --git a/iconloaderlib/res/values-night-v31/colors.xml b/iconloaderlib/res/values-night-v31/colors.xml
index e7d89b4..e5ebda6 100644
--- a/iconloaderlib/res/values-night-v31/colors.xml
+++ b/iconloaderlib/res/values-night-v31/colors.xml
@@ -17,6 +17,8 @@
 */
 -->
 <resources>
+    <color name="themed_icon_color">@android:color/system_accent1_200</color>
+    <color name="themed_icon_background_color">@android:color/system_accent2_800</color>
     <color name="themed_badge_icon_color">@android:color/system_accent2_800</color>
     <color name="themed_badge_icon_background_color">@android:color/system_accent1_200</color>
 </resources>
diff --git a/iconloaderlib/res/values-night/colors.xml b/iconloaderlib/res/values-night/colors.xml
index f23f1c0..9de7074 100644
--- a/iconloaderlib/res/values-night/colors.xml
+++ b/iconloaderlib/res/values-night/colors.xml
@@ -16,9 +16,9 @@
 ** limitations under the License.
 */
 -->
-<resources xmlns:androidprv="http://schemas.android.com/apk/prv/res/android">
-    <color name="themed_icon_color">@androidprv:color/system_on_theme_app_dark</color>
-    <color name="themed_icon_background_color">@androidprv:color/system_theme_app_dark</color>
+<resources>
+    <color name="themed_icon_color">#A8C7FA</color>
+    <color name="themed_icon_background_color">#003355</color>
     <color name="themed_badge_icon_color">#003355</color>
     <color name="themed_badge_icon_background_color">#A8C7FA</color>
 </resources>
diff --git a/iconloaderlib/res/values-v31/colors.xml b/iconloaderlib/res/values-v31/colors.xml
index 28614a2..1405ad0 100644
--- a/iconloaderlib/res/values-v31/colors.xml
+++ b/iconloaderlib/res/values-v31/colors.xml
@@ -17,6 +17,8 @@
 */
 -->
 <resources>
+    <color name="themed_icon_color">@android:color/system_accent1_700</color>
+    <color name="themed_icon_background_color">@android:color/system_accent1_100</color>
     <color name="themed_badge_icon_color">@android:color/system_accent1_700</color>
     <color name="themed_badge_icon_background_color">@android:color/system_accent1_100</color>
 </resources>
diff --git a/iconloaderlib/res/values/colors.xml b/iconloaderlib/res/values/colors.xml
index ee8bce2..56ae0b6 100644
--- a/iconloaderlib/res/values/colors.xml
+++ b/iconloaderlib/res/values/colors.xml
@@ -16,9 +16,9 @@
 ** limitations under the License.
 */
 -->
-<resources xmlns:androidprv="http://schemas.android.com/apk/prv/res/android">
-    <color name="themed_icon_color">@androidprv:color/system_on_theme_app_light</color>
-    <color name="themed_icon_background_color">@androidprv:color/system_theme_app_light</color>
+<resources>
+    <color name="themed_icon_color">#0842A0</color>
+    <color name="themed_icon_background_color">#D3E3FD</color>
     <color name="themed_badge_icon_color">#0842A0</color>
     <color name="themed_badge_icon_background_color">#D3E3FD</color>
 
```

