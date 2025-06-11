```diff
diff --git a/OWNERS b/OWNERS
index 794240714b..94774d0793 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include platform/external/clang:/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/lib/Support/regcomp.c b/lib/Support/regcomp.c
index ebde64f9cf..ac7bb8cbbe 100644
--- a/lib/Support/regcomp.c
+++ b/lib/Support/regcomp.c
@@ -150,6 +150,7 @@ static char nuls[10];		/* place to point scanner in event of error */
 #else
 #define	DUPMAX	255
 #endif
+#undef INFINITY // Android-added: avoid collision with C23 <float.h> INFINITY (via <limits.h>)
 #define	INFINITY	(DUPMAX + 1)
 
 #ifndef NDEBUG
```

