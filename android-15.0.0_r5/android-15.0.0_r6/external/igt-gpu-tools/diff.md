```diff
diff --git a/lib/drmtest.h b/lib/drmtest.h
index 614f57e6..e34fa763 100644
--- a/lib/drmtest.h
+++ b/lib/drmtest.h
@@ -38,6 +38,10 @@
 
 #include "igt_core.h"
 
+#ifdef __cplusplus
+extern "C" {
+#endif
+
 /*
  * NOTE: Theser are _only_ for testcases exercising driver specific rendering
  * ioctls and uapi (and a bunch of historical reasons). And KMS testcase should
@@ -132,4 +136,8 @@ bool is_vc4_device(int fd);
 	errno = 0; \
 } while (0)
 
+#ifdef __cplusplus
+}
+#endif
+
 #endif /* DRMTEST_H */
diff --git a/lib/igt_aux.h b/lib/igt_aux.h
index 04d22904..6f654803 100644
--- a/lib/igt_aux.h
+++ b/lib/igt_aux.h
@@ -264,7 +264,7 @@ void igt_unlock_mem(void);
 		uint64_t elapsed__ = igt_nsec_elapsed(&tv__) >> 20;	\
 									\
 		if (COND) {						\
-			igt_debug("%s took %"PRIu64"ms\n", #COND, elapsed__); \
+			igt_debug("%s took %" PRIu64 "ms\n", #COND, elapsed__); \
 			ret__ = true;					\
 			break;						\
 		}							\
diff --git a/lib/igt_core.h b/lib/igt_core.h
index 177d2431..1e770f63 100644
--- a/lib/igt_core.h
+++ b/lib/igt_core.h
@@ -42,6 +42,10 @@
 #include <getopt.h>
 #include <unistd.h>
 
+#ifdef __cplusplus
+extern "C" {
+#endif
+
 #ifndef IGT_LOG_DOMAIN
 #define IGT_LOG_DOMAIN (NULL)
 #endif
@@ -1205,10 +1209,21 @@ void igt_kmsg(const char *format, ...);
 #define KMSG_INFO	"<6>[IGT] "
 #define KMSG_DEBUG	"<7>[IGT] "
 
+#ifdef __cplusplus
+extern "C++" {
+#include <type_traits>
+#define READ_ONCE(x) (*(volatile std::remove_reference<decltype(x)>::type *)(&(x)))
+}
+#else
 #define READ_ONCE(x) (*(volatile typeof(x) *)(&(x)))
+#endif
 
 #define MSEC_PER_SEC (1000)
 #define USEC_PER_SEC (1000*MSEC_PER_SEC)
 #define NSEC_PER_SEC (1000*USEC_PER_SEC)
 
+#ifdef __cplusplus
+}
+#endif
+
 #endif /* IGT_CORE_H */
diff --git a/lib/igt_debugfs.h b/lib/igt_debugfs.h
index 36b63817..2c176710 100644
--- a/lib/igt_debugfs.h
+++ b/lib/igt_debugfs.h
@@ -29,7 +29,11 @@
 #include <stdint.h>
 #include <stdio.h>
 
-enum pipe;
+enum pipe
+#ifdef __cplusplus
+: int
+#endif
+;
 
 const char *igt_debugfs_mount(void);
 char *igt_debugfs_path(int device, char *path, int pathlen);
diff --git a/lib/igt_dummyload.c b/lib/igt_dummyload.c
index 0e06276a..6b706b86 100644
--- a/lib/igt_dummyload.c
+++ b/lib/igt_dummyload.c
@@ -90,7 +90,7 @@ emit_recursive_batch(igt_spin_t *spin,
 
 		for_each_context_engine(fd, opts->ctx, engine) {
 			if (opts->flags & IGT_SPIN_POLL_RUN &&
-			    !gem_class_can_store_dword(fd, engine->class))
+			    !gem_class_can_store_dword(fd, engine->engine_class))
 				continue;
 
 			flags[nengine++] = engine->flags;
@@ -321,7 +321,7 @@ igt_spin_factory(int fd, const struct igt_spin_factory *opts)
 
 		if (!gem_context_lookup_engine(fd, opts->engine,
 					       opts->ctx, &e)) {
-			class = e.class;
+			class = e.engine_class;
 		} else {
 			gem_require_ring(fd, opts->engine);
 			class = gem_execbuf_flags_to_engine_class(opts->engine);
diff --git a/lib/igt_fb.h b/lib/igt_fb.h
index 7290b69f..6943caa3 100644
--- a/lib/igt_fb.h
+++ b/lib/igt_fb.h
@@ -45,6 +45,10 @@
 #define USE_VC4
 #endif
 
+#ifdef __cplusplus
+extern "C" {
+#endif
+
 /*
  * Internal format to denote a buffer compatible with pixman's
  * floating point format. Range [0-1].
@@ -208,5 +212,9 @@ int igt_format_plane_bpp(uint32_t drm_format, int plane);
 void igt_format_array_fill(uint32_t **formats_array, unsigned int *count,
 			   bool allow_yuv);
 
+#ifdef __cplusplus
+}
+#endif
+
 #endif /* __IGT_FB_H__ */
 
diff --git a/lib/igt_gt.h b/lib/igt_gt.h
index 73b5002a..19493fed 100644
--- a/lib/igt_gt.h
+++ b/lib/igt_gt.h
@@ -90,11 +90,11 @@ bool gem_ring_is_physical_engine(int fd, unsigned int ring);
 bool gem_ring_has_physical_engine(int fd, unsigned int ring);
 
 bool gem_can_store_dword(int fd, unsigned int engine);
-bool gem_class_can_store_dword(int fd, int class);
+bool gem_class_can_store_dword(int fd, int engine_class);
 
 extern const struct intel_execution_engine2 {
 	const char *name;
-	int class;
+	int engine_class;
 	int instance;
 	uint64_t flags;
 	bool is_virtual;
diff --git a/lib/igt_kms.h b/lib/igt_kms.h
index 56481fd1..23c617a7 100644
--- a/lib/igt_kms.h
+++ b/lib/igt_kms.h
@@ -38,6 +38,10 @@
 #include "igt_fb.h"
 #include "ioctl_wrappers.h"
 
+#ifdef __cplusplus
+extern "C" {
+#endif
+
 /* Low-level helpers with kmstest_ prefix */
 
 /**
@@ -52,7 +56,11 @@
  * @PIPE_F: Sixth crtc.
  * @IGT_MAX_PIPES: Max number of pipes allowed.
  */
-enum pipe {
+enum pipe
+#ifdef __cplusplus
+: int
+#endif
+{
         PIPE_NONE = -1,
         PIPE_ANY = PIPE_NONE,
         PIPE_A = 0,
@@ -499,8 +507,13 @@ static inline bool igt_output_is_connected(igt_output_t *output)
  * depends upon runtime probing of the actual kms driver that is being tested.
  * Use #for_each_pipe_static instead.
  */
+#ifdef __cplusplus
+#define for_each_pipe(display, pipe_i)					\
+	for (pipe_i = (enum pipe)0; assert(igt_can_fail()), pipe_i < igt_display_get_n_pipes(display); pipe_i = (enum pipe)((int)pipe_i + 1))
+#else
 #define for_each_pipe(display, pipe)					\
 	for (pipe = 0; assert(igt_can_fail()), pipe < igt_display_get_n_pipes(display); pipe++)
+#endif
 
 /**
  * for_each_pipe_with_valid_output:
@@ -834,4 +847,8 @@ static inline bool igt_vblank_before(uint32_t a, uint32_t b)
 	return igt_vblank_after(b, a);
 }
 
+#ifdef __cplusplus
+}
+#endif
+
 #endif /* __IGT_KMS_H__ */
diff --git a/lib/igt_stats.h b/lib/igt_stats.h
index 5faeced4..f0f18fd7 100644
--- a/lib/igt_stats.h
+++ b/lib/igt_stats.h
@@ -29,6 +29,10 @@
 #include <stdbool.h>
 #include <math.h>
 
+#ifdef __cplusplus
+extern "C" {
+#endif
+
 /**
  * igt_stats_t:
  * @values_u64: An array containing pushed integer values
@@ -100,4 +104,8 @@ void igt_mean_add(struct igt_mean *m, double v);
 double igt_mean_get(struct igt_mean *m);
 double igt_mean_get_variance(struct igt_mean *m);
 
+#ifdef __cplusplus
+}
+#endif
+
 #endif /* __IGT_STATS_H__ */
diff --git a/lib/intel_chipset.h b/lib/intel_chipset.h
index e3176ac3..f30f6957 100644
--- a/lib/intel_chipset.h
+++ b/lib/intel_chipset.h
@@ -86,8 +86,6 @@ unsigned intel_gen(uint16_t devid) __attribute__((pure));
 
 unsigned intel_gt(uint16_t devid) __attribute__((pure));
 
-extern enum pch_type intel_pch;
-
 enum pch_type {
 	PCH_NONE,
 	PCH_IBX,
@@ -95,6 +93,8 @@ enum pch_type {
 	PCH_LPT,
 };
 
+extern enum pch_type intel_pch;
+
 void intel_check_pch(void);
 
 #define HAS_IBX (intel_pch == PCH_IBX)
```

