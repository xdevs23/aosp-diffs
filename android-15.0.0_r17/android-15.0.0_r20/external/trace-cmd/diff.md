```diff
diff --git a/lib/trace-cmd/trace-timesync.c b/lib/trace-cmd/trace-timesync.c
index bbefda2..cc44af3 100644
--- a/lib/trace-cmd/trace-timesync.c
+++ b/lib/trace-cmd/trace-timesync.c
@@ -41,28 +41,6 @@ struct tsync_probe_request_msg {
 	unsigned short	cpu;
 } __packed;
 
-#ifdef __ANDROID__
-#define __NR_sched_setaffinity 122
-#define __NR_sched_getaffinity 123
-
-static int pthread_setaffinity_np(pthread_t thread, size_t cpusetsize, const cpu_set_t *cpuset)
-{
-	return -syscall(__NR_sched_setaffinity, thread, cpusetsize, cpuset);
-}
-
-static int pthread_getaffinity_np(pthread_t thread, size_t cpusetsize, const cpu_set_t *cpuset)
-{
-	long ret = syscall(__NR_sched_getaffinity, thread, cpusetsize, cpuset);
-
-	if (ret < 0)
-		return ret;
-	if (ret < cpusetsize)
-		memset((char *)cpuset+ret, 0, cpusetsize-ret);
-
-	return 0;
-}
-#endif /* __ANDROID__ */
-
 static struct tsync_proto *tsync_proto_list;
 
 static struct tsync_proto *tsync_proto_find(const char *proto_name)
```

