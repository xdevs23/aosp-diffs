```diff
diff --git a/gwp_asan/tests/harness.h b/gwp_asan/tests/harness.h
index c96f846..3fbcf99 100644
--- a/gwp_asan/tests/harness.h
+++ b/gwp_asan/tests/harness.h
@@ -12,7 +12,9 @@
 #include <stdarg.h>
 
 #if defined(__Fuchsia__)
+#ifndef ZXTEST_USE_STREAMABLE_MACROS
 #define ZXTEST_USE_STREAMABLE_MACROS
+#endif
 #include <zxtest/zxtest.h>
 namespace testing = zxtest;
 // zxtest defines a different ASSERT_DEATH, taking a lambda and an error message
```

