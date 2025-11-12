```diff
diff --git a/system.c b/system.c
index b2f904c..16365f2 100644
--- a/system.c
+++ b/system.c
@@ -38,17 +38,46 @@
 #endif
 
 /*
- * Assert the value of SECURE_ALL_BITS at compile-time.
- * Android devices are currently compiled against 4.4 kernel headers. Kernel 4.3
- * added a new securebit.
- * When a new securebit is added, the new SECURE_ALL_BITS mask will return EPERM
- * when used on older kernels. The compile-time assert will catch this situation
- * at compile time.
+ * SECBIT_EXEC_RESTRICT_FILE was added in kernel 6.14, so fill in the
+ * definition if the securebits header doesn't provide it.
+ */
+#ifndef SECBIT_EXEC_RESTRICT_FILE
+#define SECBIT_EXEC_RESTRICT_FILE (issecure_mask(8))
+#endif
+
+#ifndef SECBIT_EXEC_RESTRICT_FILE_LOCKED
+#define SECBIT_EXEC_RESTRICT_FILE_LOCKED (issecure_mask(9))
+#endif
+
+/*
+ * SECBIT_EXEC_DENY_INTERACTIVE was added in kernel 6.14, so fill in the
+ * definition if the securebits header doesn't provide it.
+ */
+#ifndef SECBIT_EXEC_DENY_INTERACTIVE
+#define SECBIT_EXEC_DENY_INTERACTIVE (issecure_mask(10))
+#endif
+
+#ifndef SECBIT_EXEC_DENY_INTERACTIVE_LOCKED
+#define SECBIT_EXEC_DENY_INTERACTIVE_LOCKED (issecure_mask(11))
+#endif
+
+/*
+ * Assert the value of SECURE_ALL_BITS at compile-time to detect a change in
+ * the set of secure bits coming from the kernel headers.
+ * Kernel 6.14 introduced new secure bits that need to be removed when
+ * running on older kernels. An older kernel can be detected when the
+ * prctl(PR_SET_SECUREBITS, ...) fails with errno set to EPERM.
+ * When this is detected, remove the new bits and try the prctl call again.
  */
 #if defined(__ANDROID__)
-_Static_assert(SECURE_ALL_BITS == 0x55, "SECURE_ALL_BITS == 0x55.");
+_Static_assert(SECURE_ALL_BITS == 0x555, "SECURE_ALL_BITS == 0x555.");
 #endif
 
+#define SECURE_BITS_6_14                                                       \
+	(SECBIT_EXEC_RESTRICT_FILE | SECBIT_EXEC_DENY_INTERACTIVE)
+#define SECURE_LOCK_BITS_6_14                                                  \
+	(SECBIT_EXEC_RESTRICT_FILE_LOCKED | SECBIT_EXEC_DENY_INTERACTIVE_LOCKED)
+
 /* Used by lookup_(user|group) functions. */
 #define MAX_PWENT_SZ (1 << 20)
 #define MAX_GRENT_SZ (1 << 20)
@@ -102,8 +131,18 @@ int lock_securebits(uint64_t skip_mask, bool require_keep_caps)
 	}
 	int securebits_ret = prctl(PR_SET_SECUREBITS, securebits);
 	if (securebits_ret < 0) {
-		pwarn("prctl(PR_SET_SECUREBITS) failed");
-		return -1;
+		if (errno == EPERM &&
+		    (securebits & (SECURE_BITS_6_14 | SECURE_LOCK_BITS_6_14)) !=
+			0) {
+			/* Possibly running on kernel < 6.14. */
+			securebits &=
+			    ~(SECURE_BITS_6_14 | SECURE_LOCK_BITS_6_14);
+			securebits_ret = prctl(PR_SET_SECUREBITS, securebits);
+		}
+		if (securebits_ret < 0) {
+			pwarn("prctl(PR_SET_SECUREBITS) failed");
+			return -1;
+		}
 	}
 
 	return 0;
```

