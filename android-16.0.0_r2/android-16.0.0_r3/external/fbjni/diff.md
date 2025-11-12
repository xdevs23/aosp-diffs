```diff
diff --git a/METADATA b/METADATA
index 9be7eee..93630d4 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,21 @@
-name: "fbjni"
-description:
-    "The Facebook JNI helpers library is designed to simplify usage of the Java "
-    "Native Interface. The helpers were implemented to ease the integration of "
-    "cross-platform mobile code on Android, but there are no Android specifics "
-    "in the design. It can be used with any Java VM that supports JNI."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/fbjni
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "fbjni"
+description: "The Facebook JNI helpers library is designed to simplify usage of the Java Native Interface. The helpers were implemented to ease the integration of cross-platform mobile code on Android, but there are no Android specifics in the design. It can be used with any Java VM that supports JNI."
 third_party {
-homepage: "https://github.com/facebookincubator/fbjni"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2024
+    month: 11
+    day: 25
+  }
+  homepage: "https://github.com/facebookincubator/fbjni"
   identifier {
-    type: "Archive"
+    type: "Git"
     value: "https://github.com/facebookincubator/fbjni"
-    primary_source: true
     version: "v0.7.0"
+    primary_source: true
   }
-  version: "v0.7.0"
-  last_upgrade_date { year: 2024 month: 11 day: 25 }
-  license_type: NOTICE
-}
\ No newline at end of file
+}
diff --git a/OWNERS b/OWNERS
index a2a4268..2e8f086 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1 @@
 include platform/system/core:main:/janitors/OWNERS
-include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

