```diff
diff --git a/Android.bp b/Android.bp
index bf56fe6..aaaeb21 100644
--- a/Android.bp
+++ b/Android.bp
@@ -37,7 +37,6 @@ python_library {
         "mako/ext/*.py",
     ],
     libs: [
-        "py-setuptools",
         "py-markupsafe",
-    ]
+    ],
 }
diff --git a/OWNERS b/OWNERS
index 682a067..ed7755d 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 enh@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

