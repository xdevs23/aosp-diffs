```diff
diff --git a/Android.bp b/Android.bp
index 4033ce5..130827d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -57,6 +57,7 @@ cc_defaults {
         "external/blktrace",
         "external/blktrace/btt",
     ],
+    c_std: "gnu17",
     cflags: [
         "-O2",
         "-g",
@@ -115,7 +116,6 @@ cc_binary {
     ],
 }
 
-
 cc_binary {
     name: "btt",
     defaults: ["blktrace_defaults"],
@@ -146,7 +146,7 @@ cc_binary {
         "btt/q2d.c",
         "btt/aqd.c",
         "btt/plat.c",
-        "btt/p_live.c", 
+        "btt/p_live.c",
         "btt/rstats.c",
     ],
 }
```

