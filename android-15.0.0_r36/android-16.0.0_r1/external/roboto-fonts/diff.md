```diff
diff --git a/OWNERS b/OWNERS
index 5706b09..0b22372 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 # Default code reviewers picked from top 3 or more developers.
 # Please update this list if you find better candidates.
 include platform/external/noto-fonts:/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/font_config.json b/font_config.json
index f080f8b..5e46ece 100644
--- a/font_config.json
+++ b/font_config.json
@@ -22,5 +22,19 @@
                 }
             }
         ]
+    },
+    {
+        // Always install roboto font since ThemeHostTest depends on Roboto font.
+        // Theme HostTest replaces sans-serif font with Roboto before executing tests.
+        "name": "roboto",
+        "fonts": [
+            {
+                "file": "Roboto-Regular.ttf",
+                "supportedAxes": "wght,ital",
+                "axes": {
+                    "wdth": "100"
+                }
+            }
+        ]
     }
-]
\ No newline at end of file
+]
```

