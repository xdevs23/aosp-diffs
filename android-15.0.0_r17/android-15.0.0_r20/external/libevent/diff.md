```diff
diff --git a/Android.bp b/Android.bp
index 9abb533..51aca8f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -63,7 +63,6 @@ cc_library {
     cflags: [
         "-D_BSD_SOURCE",
         "-O3",
-        "-Wno-implicit-function-declaration",
         "-Wno-strict-aliasing",
         "-Wno-unused-parameter",
         "-Werror",
@@ -105,6 +104,7 @@ cc_library {
     target: {
         linux: {
             srcs: ["epoll.c"],
+            cflags: ["-D_GNU_SOURCE=1"],
         },
         linux_bionic: {
             enabled: true,
diff --git a/include/event2/event-config.h b/include/event2/event-config.h
index 83a1b97..742e63b 100644
--- a/include/event2/event-config.h
+++ b/include/event2/event-config.h
@@ -1,4 +1,7 @@
-#include <sys/cdefs.h>  /* Defines __BIONIC__ */
+/* We include this to get __BIONIC__,
+ * but this means _BSD_SOURCE and/or _GNU_SOURCE
+ * must be set in the .bp file. */
+#include <sys/cdefs.h>
 
 #if defined(__BIONIC__)
 #  include <event2/event-config-bionic.h>
diff --git a/strlcpy.c b/strlcpy.c
index 3876475..04c7429 100644
--- a/strlcpy.c
+++ b/strlcpy.c
@@ -44,11 +44,7 @@ static char *rcsid = "$OpenBSD: strlcpy.c,v 1.5 2001/05/13 15:40:16 deraadt Exp
  * will be copied.  Always NUL terminates (unless siz == 0).
  * Returns strlen(src); if retval >= siz, truncation occurred.
  */
-size_t
-event_strlcpy_(dst, src, siz)
-	char *dst;
-	const char *src;
-	size_t siz;
+size_t event_strlcpy_(char *dst, const char *src, size_t siz)
 {
 	register char *d = dst;
 	register const char *s = src;
```

