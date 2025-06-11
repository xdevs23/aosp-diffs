```diff
diff --git a/Android.bp b/Android.bp
index 8e8fbe9726..7d5cb26afa 100644
--- a/Android.bp
+++ b/Android.bp
@@ -48,7 +48,6 @@ cc_defaults {
     header_libs: ["clang-headers"],
 
     cflags: [
-        "-pedantic",
         "-Wno-cast-qual",
         "-Wno-long-long",
         "-Wno-unreachable-code-loop-increment",
diff --git a/OWNERS b/OWNERS
index 3e17018abb..0d95a8e94e 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,6 +1,6 @@
 # Default maintainers and code reviewers:
 srhines@google.com
 pirama@google.com
-chh@google.com
 # mailing list cannot be a reviewer yet
 # android-llvm-dev+owners-review@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

