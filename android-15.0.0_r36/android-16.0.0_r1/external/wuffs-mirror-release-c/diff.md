```diff
diff --git a/METADATA b/METADATA
index 1dc143c..1a06a90 100644
--- a/METADATA
+++ b/METADATA
@@ -1,13 +1,14 @@
 name: "Wuffs Mirror Release C"
-description:
-    ""
-
 third_party {
-  url {
-    type: GIT
-    value: "https://skia.googlesource.com/external/github.com/google/wuffs-mirror-release-c/"
-  }
-  version: "a0e2454f0c21369f9775cad3bcaf1e3bb1db70b6"
-  last_upgrade_date { year: 2021 month: 12 day: 8 }
   license_type: NOTICE
+  last_upgrade_date {
+    year: 2021
+    month: 12
+    day: 13
+  }
+  identifier {
+    type: "Git"
+    value: "https://github.com/google/wuffs-mirror-release-c"
+    version: "bf9dab31e512c194872ab02b3d44b72457bd578b"
+  }
 }
diff --git a/OWNERS.android b/OWNERS.android
index 36e9945..7f1e6fd 100644
--- a/OWNERS.android
+++ b/OWNERS.android
@@ -1 +1,2 @@
 nigeltao@google.com
+include platform/system/core:main:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

