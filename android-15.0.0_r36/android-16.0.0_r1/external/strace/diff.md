```diff
diff --git a/OWNERS b/OWNERS
index 682a067b..ed7755d6 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 enh@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/sched.c b/sched.c
index f96dfadf..bd10b037 100644
--- a/sched.c
+++ b/sched.c
@@ -124,7 +124,7 @@ print_sched_attr(struct tcb *const tcp, const kernel_ulong_t addr,
 
 	tprintf("{size=%u", attr.size);
 
-	if (size >= SCHED_ATTR_MIN_SIZE) {
+	if (size >= SCHED_ATTR_SIZE_VER0) {
 		tprints(", sched_policy=");
 		printxval(schedulers, attr.sched_policy, "SCHED_???");
 		tprints(", sched_flags=");
@@ -135,9 +135,13 @@ print_sched_attr(struct tcb *const tcp, const kernel_ulong_t addr,
 
 		PRINT_SCHED_FIELD(sched_nice, "d");
 		PRINT_SCHED_FIELD(sched_priority, "u");
-		PRINT_SCHED_FIELD(sched_runtime, PRIu64);
-		PRINT_SCHED_FIELD(sched_deadline, PRIu64);
-		PRINT_SCHED_FIELD(sched_period, PRIu64);
+		tprintf(", sched_runtime=%llu", (unsigned long long) attr.sched_runtime);
+		tprintf(", sched_deadline=%llu", (unsigned long long) attr.sched_deadline);
+		tprintf(", sched_period=%llu", (unsigned long long) attr.sched_period);
+	}
+	if (size >= SCHED_ATTR_SIZE_VER1) {
+		PRINT_SCHED_FIELD(sched_util_min, "u");
+		PRINT_SCHED_FIELD(sched_util_max, "u");
 
 		if (usize > size)
 			tprints(", ...");
diff --git a/sched_attr.h b/sched_attr.h
index 251d2c4f..5b4251c2 100644
--- a/sched_attr.h
+++ b/sched_attr.h
@@ -3,17 +3,6 @@
 
 # include <stdint.h>
 
-struct sched_attr {
-	uint32_t size;
-	uint32_t sched_policy;
-	uint64_t sched_flags;
-	uint32_t sched_nice;
-	uint32_t sched_priority;
-	uint64_t sched_runtime;
-	uint64_t sched_deadline;
-	uint64_t sched_period;
-};
-
 # define SCHED_ATTR_MIN_SIZE	48
 
 #endif /* !STRACE_SCHED_ATTR_H */
```

