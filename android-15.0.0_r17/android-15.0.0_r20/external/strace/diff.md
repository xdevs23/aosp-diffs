```diff
diff --git a/count.c b/count.c
index d667ec50..1ec46a95 100644
--- a/count.c
+++ b/count.c
@@ -75,14 +75,14 @@ count_syscall(struct tcb *tcp, const struct timespec *syscall_exiting_ts)
 }
 
 static int
-time_cmp(void *a, void *b)
+time_cmp(const void *a, const void *b)
 {
 	return -ts_cmp(&counts[*((int *) a)].time,
 		       &counts[*((int *) b)].time);
 }
 
 static int
-syscall_cmp(void *a, void *b)
+syscall_cmp(const void *a, const void *b)
 {
 	const char *a_name = sysent[*((int *) a)].sys_name;
 	const char *b_name = sysent[*((int *) b)].sys_name;
@@ -90,7 +90,7 @@ syscall_cmp(void *a, void *b)
 }
 
 static int
-count_cmp(void *a, void *b)
+count_cmp(const void *a, const void *b)
 {
 	int     m = counts[*((int *) a)].calls;
 	int     n = counts[*((int *) b)].calls;
@@ -98,7 +98,7 @@ count_cmp(void *a, void *b)
 	return (m < n) ? 1 : (m > n) ? -1 : 0;
 }
 
-static int (*sortfun)();
+static int (*sortfun)(const void *, const void *);
 
 void
 set_sortby(const char *sortby)
diff --git a/sysent.h b/sysent.h
index cf2daed1..d3ffb2f1 100644
--- a/sysent.h
+++ b/sysent.h
@@ -1,11 +1,13 @@
 #ifndef STRACE_SYSENT_H
 #define STRACE_SYSENT_H
 
+struct tcb;
+
 typedef struct sysent {
 	unsigned nargs;
 	int	sys_flags;
 	int	sen;
-	int	(*sys_func)();
+	int	(*sys_func)(struct tcb *);
 	const char *sys_name;
 } struct_sysent;
 
```

