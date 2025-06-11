```diff
diff --git a/Android.bp b/Android.bp
index 351ee1ea..3f17ec22 100644
--- a/Android.bp
+++ b/Android.bp
@@ -47,8 +47,6 @@ cc_defaults {
         "-DHAVE_GETTID",
         "-DHAVE_LIBGEN_H",
         "-DHAVE_MEMFD_CREATE",
-        "-fcommon", //ld.lld: error: duplicate symbol igt_subtest_jmpbuf: external/igt-gpu-tools/lib/igt_core.h:146
-        //Fixed upstream so we enable -fcommon locally
     ],
     static_libs: [
         "libelf",
diff --git a/OWNERS b/OWNERS
index 75869def..ea358746 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,3 +2,4 @@ adelva@google.com
 salidoa@google.com
 solomondaniel@google.com
 spyffe@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/lib/igt_core.c b/lib/igt_core.c
index 42ada85d..82b714f4 100644
--- a/lib/igt_core.c
+++ b/lib/igt_core.c
@@ -258,6 +258,8 @@
  * such as those related to Chamelium support.
  */
 
+jmp_buf igt_subtest_jmpbuf;
+
 static unsigned int exit_handler_count;
 const char *igt_interactive_debug;
 bool igt_skip_crc_compare;
diff --git a/lib/igt_core.h b/lib/igt_core.h
index 1e770f63..eae22c90 100644
--- a/lib/igt_core.h
+++ b/lib/igt_core.h
@@ -147,7 +147,7 @@ void __igt_fixture_end(void) __attribute__((noreturn));
 			 __igt_fixture_complete())
 
 /* subtest infrastructure */
-jmp_buf igt_subtest_jmpbuf;
+extern jmp_buf igt_subtest_jmpbuf;
 typedef int (*igt_opt_handler_t)(int opt, int opt_index, void *data);
 #define IGT_OPT_HANDLER_SUCCESS 0
 #define IGT_OPT_HANDLER_ERROR -2
```

