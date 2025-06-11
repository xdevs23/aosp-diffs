```diff
diff --git a/OWNERS b/OWNERS
index c24680e9..9310bff1 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 set noparent
 file:platform/packages/modules/Connectivity:main:/OWNERS_core_networking
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/tc/Android.bp b/tc/Android.bp
index 99219001..cd8529ff 100644
--- a/tc/Android.bp
+++ b/tc/Android.bp
@@ -52,7 +52,7 @@ genrule {
 
 genrule {
     name: "emp_ematch.yacc.h",
-    cmd: "M4=$(location m4) $(location bison) -y --defines=$(genDir)/emp_ematch.yacc.h --output=$(genDir)/emp_ematch.yacc.c $(in)",
+    cmd: "M4=$(location m4) $(location bison) -y --defines=$(genDir)/emp_ematch.yacc.h $(in)",
     out: ["emp_ematch.yacc.h"],
     srcs: ["emp_ematch.y"],
     tools: [
```

