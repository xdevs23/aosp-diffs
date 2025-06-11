```diff
diff --git a/OWNERS b/OWNERS
index 074d060..5d50ee4 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 balsini@google.com
 drosen@google.com
 paullawrence@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/lib/android_config.h b/lib/android_config.h
index b05b316..6917911 100644
--- a/lib/android_config.h
+++ b/lib/android_config.h
@@ -1,2 +1,61 @@
-#define pthread_setcancelstate(x, y)
-#define pthread_cancel(c)
+#pragma once
+
+#include <pthread.h>
+#include <signal.h>
+
+// Signal handler that does nothing but indicates receipt
+static void signal_handler(int signo) {
+    /* Nothing to do */
+}
+
+// Macro to set up SIG signal handler to do nothing
+#define SETUP_SIG_HANDLER(sig)                                      \
+    do {                                                            \
+        struct sigaction sa;                                        \
+        sa.sa_handler = signal_handler;                             \
+        sa.sa_flags = 0;                                            \
+        sigemptyset(&sa.sa_mask);                                   \
+        sigaction(sig, &sa, NULL);                                  \
+    } while (0)
+
+// Macros for signal handling
+#define ENABLE_SIGNAL(sig)                          \
+    do {                                            \
+        SETUP_SIG_HANDLER(sig);  /* Ensure SIG is handled by empty_signal_handler */ \
+        sigset_t set;                               \
+        sigemptyset(&set);                          \
+        sigaddset(&set, sig);                       \
+        pthread_sigmask(SIG_UNBLOCK, &set, NULL);   \
+    } while (0)
+
+#define DISABLE_SIGNAL(sig)                         \
+    do {                                            \
+        sigset_t set;                               \
+        sigemptyset(&set);                          \
+        sigaddset(&set, sig);                       \
+        pthread_sigmask(SIG_BLOCK, &set, NULL);     \
+    } while (0)
+
+// Macros to simulate pthread_setcancelstate and pthread_cancel
+#define PTHREAD_CANCEL_ENABLE 1
+#define PTHREAD_CANCEL_DISABLE 0
+
+#define pthread_setcancelstate(state, oldstate)                             \
+    do {                                                                    \
+        static __thread int thread_cancel_state = PTHREAD_CANCEL_ENABLE;    \
+        if (oldstate != NULL) {                                             \
+            *(int*)oldstate = thread_cancel_state;                          \
+        }                                                                   \
+        if (state == PTHREAD_CANCEL_ENABLE) {                               \
+            thread_cancel_state = PTHREAD_CANCEL_ENABLE;                    \
+            ENABLE_SIGNAL(SIGUSR1);                                         \
+        } else if (state == PTHREAD_CANCEL_DISABLE) {                       \
+            thread_cancel_state = PTHREAD_CANCEL_DISABLE;                   \
+            DISABLE_SIGNAL(SIGUSR1);                                        \
+        }                                                                   \
+    } while (0)
+
+#define pthread_cancel(thread)                                              \
+    do {                                                                    \
+        pthread_kill(thread, SIGUSR1);                                      \
+    } while (0)
diff --git a/lib/fuse_lowlevel.c b/lib/fuse_lowlevel.c
index e53f8a1..eb2923f 100644
--- a/lib/fuse_lowlevel.c
+++ b/lib/fuse_lowlevel.c
@@ -2165,6 +2165,13 @@ void do_init(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
 		if (arg->max_readahead < se->conn.max_readahead)
 			se->conn.max_readahead = arg->max_readahead;
 		inargflags = arg->flags;
+		/* Unpatched Android Kernels using the old value for passthrough may
+		 * accidentally set all extended init values, while not meaning to
+		 * set any. If the old passthrough value is used, ignore extended
+		 * flags
+		 */
+		if ((inargflags & FUSE_INIT_EXT) && (inargflags & (1ULL << 31)))
+			inargflags &= ~FUSE_INIT_EXT;
 		if (inargflags & FUSE_INIT_EXT)
 			inargflags = inargflags | (uint64_t) arg->flags2 << 32;
 		if (inargflags & FUSE_ASYNC_READ)
@@ -2225,7 +2232,7 @@ void do_init(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
 			if (inargflags & (1ULL << 63))
 				se->conn.capable |= FUSE_CAP_PASSTHROUGH;
 		} else {
-			if (inargflags & (1 << 31))
+			if (inargflags & (1ULL << 31))
 				se->conn.capable |= FUSE_CAP_PASSTHROUGH;
 		}
 	} else {
@@ -2374,7 +2381,7 @@ void do_init(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
 		if (inargflags & FUSE_INIT_EXT)
 			outargflags |= (1ULL << 63);
 		else
-			outargflags |= (1 << 31);
+			outargflags |= (1ULL << 31);
 	}
 	if (inargflags & FUSE_INIT_EXT) {
 		outargflags |= FUSE_INIT_EXT;
```

