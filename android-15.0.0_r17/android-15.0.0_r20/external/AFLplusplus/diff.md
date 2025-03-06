```diff
diff --git a/Android.bp b/Android.bp
index 5c510ab2..b7157c57 100644
--- a/Android.bp
+++ b/Android.bp
@@ -40,6 +40,8 @@ cc_defaults {
     "include",
     "instrumentation",
   ],
+  // Upstream hasn't yet adapted to () meaning (void) rather than (...) in C23.
+  c_std: "gnu17",
   cflags: [
     "-funroll-loops",
     "-Wno-pointer-sign",
@@ -156,7 +158,7 @@ cc_binary {
     "src/afl-forkserver.c",
     "src/afl-performance.c",
   ],
-} 
+}
 
 cc_object {
   name: "aflpp_driver",
```

