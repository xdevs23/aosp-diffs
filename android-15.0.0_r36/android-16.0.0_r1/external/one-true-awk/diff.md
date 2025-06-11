```diff
diff --git a/Android.bp b/Android.bp
index 3f89d6e..2f7e50a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -47,11 +47,6 @@ cc_defaults {
         "-Wno-macro-redefined",
     ],
     stl: "none",
-    yacc: {
-        flags: [
-            "-y",
-        ],
-    },
 }
 
 genrule {
@@ -67,7 +62,7 @@ genrule {
 
 genrule {
     name: "awkgram.tab.h",
-    cmd: "M4=$(location m4) $(location bison) -y --no-lines --defines=$(genDir)/awkgram.tab.h --output=$(genDir)/awkgram.tab.c $(in)",
+    cmd: "M4=$(location m4) $(location bison) -y --no-lines --defines=$(genDir)/awkgram.tab.h $(in)",
     out: ["awkgram.tab.h"],
     srcs: ["awkgram.y"],
     tools: [
```

