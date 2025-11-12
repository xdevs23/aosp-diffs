```diff
diff --git a/METADATA b/METADATA
index d4394e0..bcfa79a 100644
--- a/METADATA
+++ b/METADATA
@@ -1,17 +1,21 @@
-name: "libdisplay-info"
-description:
-    "libdisplay-info is library providing EDID parsing and DisplayID "
-    "functionalities."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/libdisplay-info
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "libdisplay-info"
+description: "libdisplay-info is library providing EDID parsing and DisplayID functionalities."
 third_party {
-homepage: "https://gitlab.freedesktop.org/emersion/libdisplay-info/-/tree/0.2.0?ref_type=tags"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 3
+    day: 26
+  }
+  homepage: "https://gitlab.freedesktop.org/emersion/libdisplay-info/-/tree/0.2.0?ref_type=tags"
   identifier {
     type: "Git"
     value: "https://gitlab.freedesktop.org/emersion/libdisplay-info.git"
+    version: "0.2.0"
     primary_source: true
-    version: "66b802d05b374cd8f388dc6ad1e7ae4f08cb3300"
   }
-  version: "66b802d05b374cd8f388dc6ad1e7ae4f08cb3300"
-  last_upgrade_date { year: 2024 month: 11 day: 20 }
-  license_type: NOTICE
 }
```

