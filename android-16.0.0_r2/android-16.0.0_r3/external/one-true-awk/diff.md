```diff
diff --git a/Android.bp b/Android.bp
index 2f7e50a..43c672c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -62,7 +62,9 @@ genrule {
 
 genrule {
     name: "awkgram.tab.h",
-    cmd: "M4=$(location m4) $(location bison) -y --no-lines --defines=$(genDir)/awkgram.tab.h $(in)",
+    // bison --defines outputs an extra file in addition to outputting the parser,
+    // so we still use --output to ensure the unused file is still in genDir.
+    cmd: "M4=$(location m4) $(location bison) -y --no-lines --defines=$(genDir)/awkgram.tab.h --output=$(genDir)/unused $(in)",
     out: ["awkgram.tab.h"],
     srcs: ["awkgram.y"],
     tools: [
```

