```diff
diff --git a/android/include/math.h b/android/include/math.h
index dbc80be7..a587f65b 100644
--- a/android/include/math.h
+++ b/android/include/math.h
@@ -28,9 +28,8 @@
 
 #pragma once
 
-/* GNU extensions not in musl. */
+/* POSIX extensions not in musl. */
 
-#if defined(_GNU_SOURCE)
 #define M_El            2.718281828459045235360287471352662498L /* e */
 #define M_LOG2El        1.442695040888963407359924681001892137L /* log 2e */
 #define M_LOG10El       0.434294481903251827651128918916605082L /* log 10e */
@@ -44,6 +43,5 @@
 #define M_2_SQRTPIl     1.128379167095512573896158903121545172L /* 2/sqrt(pi) */
 #define M_SQRT2l        1.414213562373095048801688724209698079L /* sqrt(2) */
 #define M_SQRT1_2l      0.707106781186547524400844362104849039L /* 1/sqrt(2) */
-#endif
 
 #include_next <math.h>
diff --git a/android/include/sys/prctl.h b/android/include/sys/prctl.h
new file mode 100644
index 00000000..bed5d4d8
--- /dev/null
+++ b/android/include/sys/prctl.h
@@ -0,0 +1,22 @@
+#ifndef _SYS_PRCTL_H
+#define _SYS_PRCTL_H
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+#include <stdint.h>
+
+/*
+ * Get the constants and structs from uapi so that code that
+ * includes <linux/prctl.h> doesn't conflict with <sys/prctl.h>.
+ */
+#include <linux/prctl.h>
+
+int prctl (int, ...);
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif
```

