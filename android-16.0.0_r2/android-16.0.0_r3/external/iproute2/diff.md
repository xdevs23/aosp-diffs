```diff
diff --git a/tc/Android.bp b/tc/Android.bp
index cd8529ff..bf8b027b 100644
--- a/tc/Android.bp
+++ b/tc/Android.bp
@@ -52,7 +52,9 @@ genrule {
 
 genrule {
     name: "emp_ematch.yacc.h",
-    cmd: "M4=$(location m4) $(location bison) -y --defines=$(genDir)/emp_ematch.yacc.h $(in)",
+    // bison --defines outputs an extra file in addition to outputting the parser,
+    // so we still use --output to ensure the unused file is still in genDir.
+    cmd: "M4=$(location m4) $(location bison) -y --defines=$(genDir)/emp_ematch.yacc.h --output=$(genDir)/unused $(in)",
     out: ["emp_ematch.yacc.h"],
     srcs: ["emp_ematch.y"],
     tools: [
```

