```diff
diff --git a/app/memorylatencybench/main.c b/app/memorylatencybench/main.c
index 7139896..a6015ac 100644
--- a/app/memorylatencybench/main.c
+++ b/app/memorylatencybench/main.c
@@ -81,7 +81,11 @@ static void get_formatted_value_cb(char* buf,
     }
 }
 
+static uint64_t mem_lat_pmu_evt_arr[] = {PMU_EV_CPU_CYCLES,
+                                         PMU_EV_INST_RETIRED};
+
 BENCH_SETUP(memlatency) {
+    BENCH_INIT_PMU(mem_lat_pmu_evt_arr);
     trusty_bench_get_param_name_cb = &get_param_name_cb_fixed;
     trusty_bench_get_formatted_value_cb = &get_formatted_value_cb;
     memlatency_state_start =
@@ -163,4 +167,16 @@ BENCH_RESULT(memlatency, latency_write, time_micro_seconds) {
     return bench_get_duration_ns();
 }
 
+BENCH_RESULT(memlatency, latency_read, cycle_counter_0) {
+    return bench_get_pmu_cnt(0);
+}
+
+BENCH_RESULT(memlatency, latency_read, cycle_counter) {
+    return bench_get_pmu_cnt(1);
+}
+
+BENCH_RESULT(memlatency, latency_read, inst_retired) {
+    return bench_get_pmu_cnt(2);
+}
+
 PORT_TEST(memlatency, "com.android.kernel.memorylatency.bench");
diff --git a/app/mmutest/mmutest.c b/app/mmutest/mmutest.c
index ad22b01..1444150 100644
--- a/app/mmutest/mmutest.c
+++ b/app/mmutest/mmutest.c
@@ -1013,6 +1013,8 @@ TEST_F(mmutest_slice, overflow) {
 
 /* Test suite for PMM */
 
+#define RESERVE_PAGES 500
+
 typedef struct {
     vmm_aspace_t* aspace;
 } mmutest_pmm_t;
@@ -1032,36 +1034,77 @@ TEST_F_TEARDOWN(mmutest_pmm) {
 test_abort:;
 }
 
+static uint probe_max_aspace_quota_pages(void) {
+    struct vmm_aspace* probe_aspace = NULL;
+    uint alloc_pages = 4096;
+    uint alloc_step = 4096;
+    status_t ret;
+
+    do {
+        ret = vmm_create_aspace_with_quota(&probe_aspace, "probe_aspace",
+                                           PAGE_SIZE * alloc_pages, 0);
+
+        if (probe_aspace) {
+            vmm_free_aspace(probe_aspace);
+            probe_aspace = NULL;
+        }
+
+        if (ret == NO_ERROR) {
+            alloc_pages += alloc_step;
+        } else if (alloc_step) {
+            alloc_pages -= alloc_step;
+            alloc_step = alloc_step / 2;
+        } else {
+            alloc_pages--;
+        }
+
+    } while (alloc_step > 0 || ret != NO_ERROR);
+
+    return alloc_pages;
+}
+
 /*
  * Reserve physical pages and allocate from reserved memory.
  */
 TEST_F(mmutest_pmm, reserve) {
     void* ptr = NULL;
-    void* ptr_unused_1 = NULL;
-    void* ptr_unused_2 = NULL;
+    void* ptr_unused = NULL;
     status_t ret;
     struct vmm_aspace* temp_aspace = NULL;
-    ret = vmm_alloc(_state->aspace, "test_reserve", PAGE_SIZE * 5002, &ptr, 0,
+    uint max_pages;
+
+    /* Allocate virtual space without quota or pmm, which should pass */
+    ret = vmm_alloc(_state->aspace, "test_reserve",
+                    PAGE_SIZE * (RESERVE_PAGES + 2), &ptr, 0,
                     VMM_FLAG_NO_PHYSICAL, ARCH_MMU_FLAG_PERM_NO_EXECUTE);
     ASSERT_EQ(NO_ERROR, ret);
+
+    /* Allocate all quota pages at previous virtual address */
     ret = vmm_alloc(_state->aspace, "test_from_reserved", PAGE_SIZE * 2, &ptr,
                     0, VMM_FLAG_QUOTA | VMM_FLAG_VALLOC_SPECIFIC,
                     ARCH_MMU_FLAG_PERM_NO_EXECUTE);
     ASSERT_EQ(NO_ERROR, ret);
 
-    while (!vmm_create_aspace_with_quota(&temp_aspace, "temp_aspace",
-                                         PAGE_SIZE * 5000, 0)) {
-    }
-    ptr += PAGE_SIZE * 2;
+    /* Check the maximum quota that can be allocated to an aspace */
+    max_pages = probe_max_aspace_quota_pages();
+    ASSERT_GT(max_pages, RESERVE_PAGES);
 
-    ret = vmm_alloc(_state->aspace, "test_failure", PAGE_SIZE * 5000,
-                    &ptr_unused_1, 0, 0, ARCH_MMU_FLAG_PERM_NO_EXECUTE);
-    ASSERT_EQ(ERR_NO_MEMORY, ret);
-    ret = vmm_alloc(_state->aspace, "test_success", PAGE_SIZE * 2,
-                    &ptr_unused_2, 0, 0, ARCH_MMU_FLAG_PERM_NO_EXECUTE);
+    /* Reserve most pages for temp_aspace, leaving RESERVE_PAGES / 2 free */
+    ret = vmm_create_aspace_with_quota(
+            &temp_aspace, "temp_aspace",
+            PAGE_SIZE * (max_pages - RESERVE_PAGES / 2), 0);
     ASSERT_EQ(NO_ERROR, ret);
-    ret = vmm_alloc(temp_aspace, "test_from_reserved_success", PAGE_SIZE * 5000,
-                    &ptr, 0, VMM_FLAG_QUOTA | VMM_FLAG_VALLOC_SPECIFIC,
+
+    /* Almost all pages are reserved for temp_aspace quota; this should fail */
+    ret = vmm_alloc(_state->aspace, "test_failure", PAGE_SIZE * RESERVE_PAGES,
+                    &ptr_unused, 0, 0, ARCH_MMU_FLAG_PERM_NO_EXECUTE);
+    ASSERT_EQ(ERR_NO_MEMORY, ret);
+
+    /* Allocate from temp_aspace quota reservation */
+    ptr += PAGE_SIZE * 2;
+    ret = vmm_alloc(temp_aspace, "test_from_reserved_success",
+                    PAGE_SIZE * RESERVE_PAGES, &ptr, 0,
+                    VMM_FLAG_QUOTA | VMM_FLAG_VALLOC_SPECIFIC,
                     ARCH_MMU_FLAG_PERM_NO_EXECUTE);
     ASSERT_EQ(NO_ERROR, ret);
 test_abort:
diff --git a/app/trusty/user-tasks.mk b/app/trusty/user-tasks.mk
index abbad19..535cf64 100644
--- a/app/trusty/user-tasks.mk
+++ b/app/trusty/user-tasks.mk
@@ -109,10 +109,13 @@ $(foreach lib,$(ALLHOSTMODULES),\
 # account for differing licenses across projects.
 TRUSTY_SDK_MODULES := \
 	external/boringssl \
+	external/open-dice \
 	trusty/kernel/lib/libc-ext \
 	trusty/kernel/lib/ubsan \
 	trusty/user/base/interface/hwaes \
+	trusty/user/base/interface/hwbcc \
 	trusty/user/base/interface/hwkey \
+	trusty/user/base/interface/keybox \
 	trusty/user/base/interface/keymaster \
 	trusty/user/base/interface/spi \
 	trusty/user/base/interface/storage \
@@ -120,9 +123,11 @@ TRUSTY_SDK_MODULES := \
 	trusty/user/base/lib/dlmalloc \
 	trusty/user/base/lib/googletest \
 	trusty/user/base/lib/hwaes \
+	trusty/user/base/lib/hwbcc/client \
 	trusty/user/base/lib/hwbcc/rust \
 	trusty/user/base/lib/hwkey \
 	trusty/user/base/lib/hwkey/rust \
+	trusty/user/base/lib/keybox/client \
 	trusty/user/base/lib/keymaster \
 	trusty/user/base/lib/libc-trusty \
 	trusty/user/base/lib/libcxxabi-trusty \
diff --git a/include/shared/lk/trusty_bench_common.h b/include/shared/lk/trusty_bench_common.h
index 629392e..0b55c5d 100644
--- a/include/shared/lk/trusty_bench_common.h
+++ b/include/shared/lk/trusty_bench_common.h
@@ -94,6 +94,7 @@ struct bench_metric_list_node {
     int64_t (*bench_result)(void);
     trusty_bench_get_formatted_value_callback_t formatted_value_cb;
     trusty_bench_get_param_name_callback_t param_name_cb;
+    trusty_bench_check_results_callback_t check_results_cb;
 };
 
 /*
@@ -182,15 +183,20 @@ static inline bool trusty_bench_validate_numeric(const char* s) {
  * @metric_name:        Name of the metric for which this value is to be
  *                      formatted
  */
-static inline void trusty_bench_sprint_col_stat(char* buffer,
-                                                size_t buffer_len,
-                                                int64_t val,
-                                                const char* metric_name) {
-    if (trusty_bench_get_formatted_value_cb == NULL) {
+static inline void trusty_bench_sprint_col_stat(
+        char* buffer,
+        size_t buffer_len,
+        int64_t val,
+        const char* metric_name,
+        trusty_bench_get_formatted_value_callback_t value_format_cb) {
+    if (value_format_cb == NULL) {
+        value_format_cb = trusty_bench_get_formatted_value_cb;
+    }
+
+    if (value_format_cb == NULL) {
         snprintf(buffer, buffer_len, "%" PRId64, val);
     } else {
-        trusty_bench_get_formatted_value_cb(buffer, buffer_len, val,
-                                            metric_name);
+        value_format_cb(buffer, buffer_len, val, metric_name);
         EXPECT_EQ(trusty_bench_validate_numeric(buffer), true,
                   "%s is not a valid double representation.\n", buffer);
     }
diff --git a/include/shared/lk/trusty_bench_json_print.h b/include/shared/lk/trusty_bench_json_print.h
index e2636ba..58e9214 100644
--- a/include/shared/lk/trusty_bench_json_print.h
+++ b/include/shared/lk/trusty_bench_json_print.h
@@ -81,18 +81,18 @@ static inline void trusty_bench_print_json_metric_list(
         /* print formatted values */
         trusty_bench_sprint_col_stat(
                 buf, sizeof(buf), entry->metric.aggregates[BENCH_AGGREGATE_MIN],
-                entry->name);
+                entry->name, entry->formatted_value_cb);
         trusty_unittest_printf("\"min\": \"%s\",", buf);
         trusty_bench_sprint_col_stat(
                 buf, sizeof(buf), entry->metric.aggregates[BENCH_AGGREGATE_MAX],
-                entry->name);
+                entry->name, entry->formatted_value_cb);
         trusty_unittest_printf("\"max\": \"%s\",", buf);
         trusty_bench_sprint_col_stat(
                 buf, sizeof(buf), entry->metric.aggregates[BENCH_AGGREGATE_AVG],
-                entry->name);
+                entry->name, entry->formatted_value_cb);
         trusty_unittest_printf("\"avg\": \"%s\",", buf);
         trusty_bench_sprint_col_stat(buf, sizeof(buf), entry->metric.cold,
-                                     entry->name);
+                                     entry->name, entry->formatted_value_cb);
         trusty_unittest_printf("\"cold\": \"%s\",", buf);
 
         /* Formatting is conditional to Metric Name, so we always print raw
diff --git a/include/shared/lk/trusty_bench_option_cb.h b/include/shared/lk/trusty_bench_option_cb.h
index fa350a0..33697ba 100644
--- a/include/shared/lk/trusty_bench_option_cb.h
+++ b/include/shared/lk/trusty_bench_option_cb.h
@@ -51,6 +51,17 @@ typedef void (*trusty_bench_get_param_name_callback_t)(char* buf,
  */
 static trusty_bench_get_param_name_callback_t trusty_bench_get_param_name_cb;
 
+// Forward declaration for the trusty_bench_check_results_callback_t definition
+struct bench_metric_list_node;
+
+/**
+ * typedef trusty_bench_check_results_callback_t - Type of the callback to
+ *                  check if aggregate values are in desired range
+ * @metric_node:    The metric node to be validated
+ */
+typedef bool (*trusty_bench_check_results_callback_t)(
+        struct bench_metric_list_node* metric_node);
+
 /**
  * typedef trusty_bench_get_formatted_value_callback - Type of the callback to
  * customize value printing
diff --git a/include/shared/lk/trusty_bench_print_tables.h b/include/shared/lk/trusty_bench_print_tables.h
index 0c6c944..97eef58 100644
--- a/include/shared/lk/trusty_bench_print_tables.h
+++ b/include/shared/lk/trusty_bench_print_tables.h
@@ -212,7 +212,7 @@ static inline void trusty_bench_compute_widths(struct list_node* metric_list,
         /* Get the size of the max value */
         trusty_bench_sprint_col_stat(
                 buf, sizeof(buf), entry->metric.aggregates[BENCH_AGGREGATE_MAX],
-                entry->name);
+                entry->name, entry->formatted_value_cb);
         trusty_bench_max_column_width =
                 MAX(strnlen(buf, sizeof(buf)), trusty_bench_max_column_width);
         trusty_bench_max_metric_digit_width = MAX(
@@ -221,11 +221,12 @@ static inline void trusty_bench_compute_widths(struct list_node* metric_list,
         /* Get the size of the min value, because aggregates are signed */
         trusty_bench_sprint_col_stat(
                 buf, sizeof(buf), entry->metric.aggregates[BENCH_AGGREGATE_MIN],
-                entry->name);
+                entry->name, entry->formatted_value_cb);
         trusty_bench_max_column_width =
                 MAX(strnlen(buf, sizeof(buf)), trusty_bench_max_column_width);
         trusty_bench_max_metric_digit_width = MAX(
                 trusty_bench_max_metric_digit_width, strnlen(buf, sizeof(buf)));
+        column_width = MAX(column_width, trusty_bench_max_metric_digit_width);
 
         /* Check Column is not too big */
         if (trusty_bench_max_column_width > BENCH_MAX_COL_SIZE) {
diff --git a/include/shared/lk/trusty_benchmark.h b/include/shared/lk/trusty_benchmark.h
index 1bb4728..8a1019c 100644
--- a/include/shared/lk/trusty_benchmark.h
+++ b/include/shared/lk/trusty_benchmark.h
@@ -125,6 +125,7 @@
 #include <stdarg.h>
 #include <stdlib.h>
 
+#include <lib/pmu/pmu_arch.h>
 #include <lib/unittest/unittest.h>
 #include <trusty_log.h>
 #include "trusty_bench_common.h"
@@ -141,6 +142,10 @@
 #endif
 #include <uapi/err.h>
 
+#ifdef WITH_TEST_PMU
+#include <lib/pmu/pmu.h>
+#endif
+
 /*
  * A few helper macros for static dispatch
  */
@@ -159,10 +164,14 @@ __BEGIN_CDECLS
  * @last_bench_body_duration:   nanoseconds duration of the last execution of
  *                              the bench body.
  * @cur_param_idx:              index of current parameter in param_array.
+ * @pmu:                        state of pmu counters
  */
 static struct benchmark_internal_state {
     int64_t last_bench_body_duration;
     size_t cur_param_idx;
+#ifdef WITH_TEST_PMU
+    struct trusty_pmu_state pmu;
+#endif
 } bench_state;
 
 /**
@@ -299,6 +308,29 @@ static inline void trusty_bench_run_metrics(struct list_node* metric_list,
     }
 }
 
+/**
+ * trusty_bench_check_metrics -        Check if All Metric are within range
+ * after one iteration of bench function for all param/metric in the last BENCH.
+ * @metric_list:        List of metrics aggregated during all BENCH runs.
+ * @param_idx:          Index of the current parameter in the param_array of
+ *                      BENCH.
+ */
+static inline bool trusty_bench_check_metrics(struct list_node* metric_list,
+                                              size_t param_idx) {
+    struct bench_metric_list_node* entry;
+
+    list_for_every_entry(metric_list, entry, struct bench_metric_list_node,
+                         node) {
+        if (param_idx == entry->param_idx) {
+            if (entry->check_results_cb != NULL &&
+                !entry->check_results_cb(entry)) {
+                return false;
+            }
+        }
+    }
+    return true;
+}
+
 /**
  * trusty_bench_reset_metrics -        Run All Metric Updaters after one
  * iteration of bench function for all param/metric in the last BENCH.
@@ -344,14 +376,20 @@ static inline void trusty_bench_reset_metrics(struct list_node* metric_list,
  * @suite_name:         Identifier of the current suite.
  * @bench_name:         Unique identifier of the Bench in the suite.
  * @metric_name:        Name of the metric to print in the result table.
- * @formatted_value_cb:        [optional] A callback of
- * trusty_bench_get_formatted_value_callback_t type for formatting the result
- * value to a string
- * @param_name_cb:              [optional] A callback of
- * trusty_bench_get_param_name_callback_t type for formatting the param name
+ * @formatted_value_cb: [optional] A callback of
+ *                      trusty_bench_get_formatted_value_callback_t type
+ *                      for formatting the result
+ *                      value to a string
+ * @param_name_cb:      [optional] A callback of
+ *                      trusty_bench_get_param_name_callback_t type
+ *                      for formatting the param name
+ * @check_results_cb:   [optional] A callback of
+ *                      trusty_bench_check_results_callback_t
+ *                      type for formatting the param name
  */
 #define BENCH_RESULT_INNER(suite_name, bench_name, metric_name,                 \
-                           formatted_value_cb_, param_name_cb_)                 \
+                           formatted_value_cb_, param_name_cb_,                 \
+                           check_results_cb_)                                   \
     static int64_t update_##suite_name##_##bench_name##_##metric_name(void);    \
     static struct bench_metric_list_node                                        \
             suite_name##_##bench_name##_##metric_name##_node = {                \
@@ -363,7 +401,8 @@ static inline void trusty_bench_reset_metrics(struct list_node* metric_list,
                     .bench_result =                                             \
                             update_##suite_name##_##bench_name##_##metric_name, \
                     .formatted_value_cb = formatted_value_cb_,                  \
-                    .param_name_cb = param_name_cb_};                           \
+                    .param_name_cb = param_name_cb_,                            \
+                    .check_results_cb = check_results_cb_};                     \
     __attribute__((constructor)) void                                           \
             suite_name##_##bench_name##_##metric_name##_add(void) {             \
         list_add_tail(&suite_name##_##bench_name##_metric_list,                 \
@@ -374,16 +413,38 @@ static inline void trusty_bench_reset_metrics(struct list_node* metric_list,
 
 /* Dispatch Mechanics for BENCH_RESULT */
 #define BENCH_RESULT_3(suite_name, bench_name, metric_name) \
-    BENCH_RESULT_INNER(suite_name, bench_name, metric_name, 0, 0)
+    BENCH_RESULT_INNER(suite_name, bench_name, metric_name, 0, 0, 0)
+
 #define BENCH_RESULT_4(suite_name, bench_name, metric_name, \
                        formatted_value_cb)                  \
     BENCH_RESULT_INNER(suite_name, bench_name, metric_name, \
-                       formatted_value_cb, 0)
+                       formatted_value_cb, 0, 0)
+
 #define BENCH_RESULT_5(suite_name, bench_name, metric_name, \
                        formatted_value_cb, param_name_cb)   \
     BENCH_RESULT_INNER(suite_name, bench_name, metric_name, \
-                       formatted_value_cb, param_name_cb)
+                       formatted_value_cb, param_name_cb, 0)
 
+#define BENCH_RESULT_6(suite_name, bench_name, metric_name,                 \
+                       formatted_value_cb, param_name_cb, check_results_cb) \
+    BENCH_RESULT_INNER(suite_name, bench_name, metric_name,                 \
+                       formatted_value_cb, param_name_cb, check_results_cb)
+
+#ifdef WITH_TEST_PMU
+/**
+ * bench_get_pmu_cnt - convenience function to use in BENCH_RESULT to get
+ * the value of a pmu counter for the last bench body execution.
+ *
+ * Return: The value of a pmu counter of the last completed BENCH body.
+ */
+static inline int64_t bench_get_pmu_cnt(size_t idx) {
+    return bench_state.pmu.vals[idx];
+}
+#else
+static inline int64_t bench_get_pmu_cnt(size_t idx) {
+    return 0;
+}
+#endif
 /**
  * BENCH_RESULT             Dispatch BENCH_RESULT Called 3, 4 or 5 parameters.
  * @suite_name:             Identifier of the current suite.
@@ -468,6 +529,14 @@ static inline struct bench_metric_list_node* set_param_metric(
         TLOGE("Failed to Allocate memory for bench_metric_list_node!");
         return NULL;
     }
+
+    // clear parameterized_list from previous runs
+    struct list_node* node = NULL;
+    do {
+        node = list_remove_head(parameterized_list);
+        free(node);
+    } while (node != NULL);
+
     list_for_every_entry(unparameterized_list, entry,
                          struct bench_metric_list_node, node) {
         for (size_t idx_param = 0; idx_param < nb_params; ++idx_param) {
@@ -480,6 +549,7 @@ static inline struct bench_metric_list_node* set_param_metric(
             list_pool[idx].bench_result = entry->bench_result;
             list_pool[idx].formatted_value_cb = entry->formatted_value_cb;
             list_pool[idx].param_name_cb = entry->param_name_cb;
+            list_pool[idx].check_results_cb = entry->check_results_cb;
             list_add_tail(parameterized_list, &(list_pool[idx].node));
             ++idx;
         }
@@ -538,6 +608,21 @@ static inline int get_extended_bench_name(const char* test_name_in,
     return 0;
 }
 
+#ifdef WITH_TEST_PMU
+#define BENCH_INIT_PMU(evt_arr) \
+    init_pmu_state(evt_arr, countof(evt_arr), &bench_state.pmu)
+#define PMU_START() pmu_start(&bench_state.pmu);
+#define PMU_STOP() pmu_stop(&bench_state.pmu);
+#define RESET_PMU() reset_pmu_cnts(&bench_state.pmu)
+#define CLEAN_PMU() clean_pmu(&bench_state.pmu)
+#else
+#define BENCH_INIT_PMU(evt_arr) (void)(evt_arr)
+#define PMU_START()
+#define PMU_STOP()
+#define RESET_PMU()
+#define CLEAN_PMU()
+#endif
+
 /**
  * BENCH_CORE -             Called by both parametrized and unparameterized
  * BENCH for their common part
@@ -589,6 +674,7 @@ static inline int get_extended_bench_name(const char* test_name_in,
         }                                                                       \
         int64_t overhead = trusty_bench_get_overhead();                         \
                                                                                 \
+        PMU_START();                                                            \
         /* Cold Run */                                                          \
         int64_t start_time;                                                     \
         int64_t end_time;                                                       \
@@ -596,6 +682,8 @@ static inline int get_extended_bench_name(const char* test_name_in,
         int64_t res = suite_name##_##bench_name##_inner_##params();             \
         end_time = get_current_time_ns();                                       \
                                                                                 \
+        PMU_STOP();                                                             \
+                                                                                \
         if (res != NO_ERROR) {                                                  \
             TLOGE("ERROR During Cold Run%" PRId64 "\n", res);                   \
             _test_context.all_ok = false;                                       \
@@ -615,13 +703,17 @@ static inline int get_extended_bench_name(const char* test_name_in,
                                                                                 \
         if (!_test_context.hard_fail && _test_context.all_ok) {                 \
             trusty_bench_run_metrics(&metric_list, idx_param, true);            \
+            RESET_PMU();                                                        \
         }                                                                       \
                                                                                 \
         for (size_t idx_run = 0; idx_run < nb_runs; ++idx_run) {                \
             if (!_test_context.hard_fail && _test_context.all_ok) {             \
+                PMU_START();                                                    \
                 start_time = get_current_time_ns();                             \
                 res = suite_name##_##bench_name##_inner_##params();             \
                 end_time = get_current_time_ns();                               \
+                PMU_STOP();                                                     \
+                                                                                \
                 bench_state.last_bench_body_duration = end_time - start_time;   \
                 if (overhead >= bench_state.last_bench_body_duration) {         \
                     TLOGE("Benchmark internal function is too fast %" PRId64    \
@@ -637,12 +729,18 @@ static inline int get_extended_bench_name(const char* test_name_in,
             }                                                                   \
             if (!_test_context.hard_fail && _test_context.all_ok) {             \
                 trusty_bench_run_metrics(&metric_list, idx_param, false);       \
+                RESET_PMU();                                                    \
             }                                                                   \
         }                                                                       \
         suite_name##_teardown();                                                \
         rc = trusty_bench_multi_cpus_teardown();                                \
         if (rc != NO_ERROR) {                                                   \
             TLOGW("failed to reset CPU affinity: %d\n", rc);                    \
+        }                                                                       \
+                                                                                \
+        if (!trusty_bench_check_metrics(&metric_list, idx_param)) {             \
+            _test_context.all_ok = false;                                       \
+            _test_context.tests_failed++;                                       \
         }                                                                       \
         TEST_END_FUNC();                                                        \
         free(extended_test_name);                                               \
@@ -652,7 +750,8 @@ static inline int get_extended_bench_name(const char* test_name_in,
                           STRINGIFY(suite_name),                                \
                           STRINGIFY(bench_name##_##params));                    \
     trusty_bench_get_param_name_cb = NULL;                                      \
-    trusty_bench_get_formatted_value_cb = NULL
+    trusty_bench_get_formatted_value_cb = NULL;                                 \
+    CLEAN_PMU();
 
 /**
  * BENCH_PARAMETERIZED_PTR -Called when BENCH has 5 parameters. This allows
diff --git a/lib/pmu/include/lib/pmu/pmu.h b/lib/pmu/include/lib/pmu/pmu.h
new file mode 100644
index 0000000..1a00ece
--- /dev/null
+++ b/lib/pmu/include/lib/pmu/pmu.h
@@ -0,0 +1,431 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining
+ * a copy of this software and associated documentation files
+ * (the "Software"), to deal in the Software without restriction,
+ * including without limitation the rights to use, copy, modify, merge,
+ * publish, distribute, sublicense, and/or sell copies of the Software,
+ * and to permit persons to whom the Software is furnished to do so,
+ * subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be
+ * included in all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+ * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+ * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
+ * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
+ * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+ * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+ * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#pragma once
+
+#include <inttypes.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include "pmu_arch.h"
+
+#ifndef ARM64_READ_SYSREG
+#define DSB __asm__ volatile("dsb sy" ::: "memory")
+#define ISB __asm__ volatile("isb" ::: "memory")
+
+#define STRINGIFY(x) #x
+#define TOSTRING(x) STRINGIFY(x)
+
+#define ARM64_READ_SYSREG(reg)                                  \
+    ({                                                          \
+        uint64_t _val;                                          \
+        __asm__ volatile("mrs %0," TOSTRING(reg) : "=r"(_val)); \
+        _val;                                                   \
+    })
+
+#define ARM64_WRITE_SYSREG_RAW(reg, val) \
+    ({ __asm__ volatile("msr " TOSTRING(reg) ", %0" ::"r"(val)); })
+
+#define ARM64_WRITE_SYSREG(reg, val)      \
+    ({                                    \
+        ARM64_WRITE_SYSREG_RAW(reg, val); \
+        ISB;                              \
+    })
+#endif
+
+static uint64_t set_bit(uint64_t reg, uint64_t bit_number) {
+    return reg | bit_number;
+}
+
+static uint64_t clear_bit(uint64_t reg, uint64_t bit_number) {
+    return reg & (~bit_number);
+}
+
+/**
+ * get_pmu_feat - Returns ID_DFR0_EL1.PerfMon Bits
+ *
+ * Return: ID_DFR0_EL1.PerfMon Bits
+ */
+static uint64_t get_pmu_feat(void) {
+    uint64_t id_dfr0_el1 = ARM64_READ_SYSREG(ID_DFR0_EL1);
+    id_dfr0_el1 = id_dfr0_el1 >> 24; /* Shift PerfMon field down to bit 0 */
+    id_dfr0_el1 &= 0x7;              /* Mask to leave just the PerfMon bits */
+    return id_dfr0_el1;
+}
+
+/**
+ * get_pmn - Returns the number of programmable counters
+ *
+ * Return: The number of available programmable counters
+ */
+static uint64_t get_pmn(void) {
+    uint64_t pmcr_el0 = ARM64_READ_SYSREG(PMCR_EL0);
+    pmcr_el0 = pmcr_el0 >> 11; /* Shift N field down to bit 0 */
+    pmcr_el0 &= 0x1F;          /* Mask to leave just the 5 N bits */
+    return pmcr_el0;
+}
+
+/**
+ * pmn_config - Sets the event for a programmable counter to record
+ * @counter: r0 = Which counter to program  (e.g. 0 for PMN0, 1 for PMN1)
+ * @event:   r1 = The event code (from appropriate TRM or ARM Architecture
+ * Reference Manual)
+ */
+static void pmn_config(uint64_t counter, uint64_t event) {
+    ARM64_WRITE_SYSREG(PMSELR_EL0, counter);
+    ARM64_WRITE_SYSREG(PMXEVTYPER_EL0, event);
+}
+
+/**
+ * set_pmu_filters - Set Event Counter Filters
+ *
+ * @counter:     the index of the programmable counter slot to which the filter
+ * applies
+ * @filter_flags: filters to be applied to the programmable counter slot
+ */
+static void set_pmu_filters(uint64_t counter, uint64_t filter_flags) {
+    ARM64_WRITE_SYSREG(PMSELR_EL0, counter);
+    ARM64_WRITE_SYSREG(PMCCFILTR_EL0, filter_flags);
+}
+
+/**
+ * ccnt_divider - Enables/disables the divider (1/64) on CCNT
+ * @divider: r0 = If 0 disable divider, else enable dvider
+ */
+static void ccnt_divider(bool divider) {
+    if (divider) {
+        uint64_t reg = ARM64_READ_SYSREG(PMSELR_EL0);
+        reg = clear_bit(reg, PMCR_EL0_D_BIT);
+        ARM64_WRITE_SYSREG(PMSELR_EL0, reg);
+    } else {
+        uint64_t reg = ARM64_READ_SYSREG(PMSELR_EL0);
+        reg = set_bit(reg, PMCR_EL0_D_BIT);
+        ARM64_WRITE_SYSREG(PMSELR_EL0, reg);
+    }
+}
+
+/**
+ * enable_pmu - Global PMU enable
+ * On ARM11 this enables the PMU, and the counters start immediately
+ * On Cortex this enables the PMU, there are individual enables for the counters
+ */
+static void enable_pmu(void) {
+    uint64_t reg = ARM64_READ_SYSREG(PMCR_EL0);
+    reg = set_bit(reg, PMCR_EL0_E_BIT);
+    ARM64_WRITE_SYSREG(PMCR_EL0, reg);
+}
+
+/**
+ * disable_pmu - Global PMU disable
+ * On Cortex, this overrides the enable state of the individual counters
+ */
+static void disable_pmu(void) {
+    uint64_t reg = ARM64_READ_SYSREG(PMCR_EL0);
+    reg = clear_bit(reg, PMCR_EL0_E_BIT);
+    ARM64_WRITE_SYSREG(PMCR_EL0, reg);
+}
+
+/**
+ * enable_ccnt - Enable the CCNT
+ */
+static void enable_ccnt(void) {
+    uint64_t reg = ARM64_READ_SYSREG(PMCNTENSET_EL0);
+    reg = set_bit(reg, PMCNTENSET_EL0_C_BIT);
+    ARM64_WRITE_SYSREG(PMCNTENSET_EL0, reg);
+}
+
+/**
+ * disable_ccnt - Disable the CCNT
+ */
+static void disable_ccnt(void) {
+    uint64_t reg = ARM64_READ_SYSREG(PMCNTENSET_EL0);
+    reg = clear_bit(reg, PMCNTENSET_EL0_C_BIT);
+    ARM64_WRITE_SYSREG(PMCNTENSET_EL0, reg);
+}
+
+/**
+ * enable_pmn - Enable PMN{n}
+ * @counter: The counter to enable (e.g. 0 for PMN0, 1 for PMN1)
+ */
+static void enable_pmn(uint64_t counter) {
+    uint64_t reg = ARM64_READ_SYSREG(PMCNTENSET_EL0);
+    reg = set_bit(reg, (uint64_t)1 << counter);
+    ARM64_WRITE_SYSREG(PMCNTENSET_EL0, reg);
+}
+
+/**
+ * disable_pmn - Disable PMN{n}
+ * @counter: The counter to disable (e.g. 0 for PMN0, 1 for PMN1)
+ */
+static void disable_pmn(uint64_t counter) {
+    uint64_t reg = ARM64_READ_SYSREG(PMCNTENSET_EL0);
+    reg = clear_bit(reg, (uint64_t)1 << counter);
+    ARM64_WRITE_SYSREG(PMCNTENSET_EL0, reg);
+}
+
+/**
+ * read_ccnt - Returns the value of CCNT
+ *
+ * Return: the value to PMCCNTR_EL0
+ */
+static uint64_t read_ccnt(void) {
+    return ARM64_READ_SYSREG(PMCCNTR_EL0);
+}
+
+/**
+ * read_pmn - Returns the value of PMN{n}
+ * @counter: The counter to read (e.g. 0 for PMN0, 1 for PMN1)
+ *
+ * Return: the value to PMXEVCNTR_EL0 after selecting event
+ */
+static uint64_t read_pmn(uint64_t counter) {
+    counter &= 0x1F;
+    ARM64_WRITE_SYSREG(PMSELR_EL0, counter);
+    return ARM64_READ_SYSREG(PMXEVCNTR_EL0);
+}
+
+/**
+ * read_flags - Returns the value of the overflow flags
+ *
+ * Return: the value of PmovSCLR_EL0
+ */
+static uint64_t read_flags(void) {
+    return ARM64_READ_SYSREG(PmovSCLR_EL0);
+}
+
+/**
+ * write_flags - Writes the overflow flags
+ * @flags: value of the flags to write to PmovSSET_EL0
+ */
+static void write_flags(uint64_t flags) {
+    ARM64_WRITE_SYSREG(PmovSCLR_EL0, flags);
+}
+
+/**
+ * reset_pmn - Resets the programmable counters
+ */
+static void reset_pmn(void) {
+    uint64_t reg = ARM64_READ_SYSREG(PMCR_EL0);
+    reg = set_bit(reg, PMCR_EL0_P_BIT);
+    ARM64_WRITE_SYSREG(PMCR_EL0, reg);
+}
+
+/**
+ * reset_ccnt - Resets the CCNT
+ */
+static void reset_ccnt(void) {
+    uint64_t reg = ARM64_READ_SYSREG(PMCR_EL0);
+    reg = set_bit(reg, PMCR_EL0_C_BIT);
+    ARM64_WRITE_SYSREG(PMCR_EL0, reg);
+}
+/**
+ * get_event_code_string - Get the code name for a given PMU event
+ *
+ * @event:  current states of the pmu counters
+ *
+ * Return:  The Code of the event as a String
+ */
+static const char* get_event_code_string(int event) {
+    switch (event) {
+    case PMU_EV_SW_INCR:
+        return "SW_INCR";
+    case PMU_EV_L1I_CACHE_REFILL:
+        return "L1I_CACHE_REFILL";
+    case PMU_EV_L1I_TLB_REFILL:
+        return "L1I_TLB_REFILL";
+    case PMU_EV_L1D_CACHE_REFILL:
+        return "L1D_CACHE_REFILL";
+    case PMU_EV_L1D_CACHE:
+        return "L1D_CACHE";
+    case PMU_EV_L1D_TLB_REFILL:
+        return "L1D_TLB_REFILL";
+    case PMU_EV_LD_RETIRED:
+        return "LD_RETIRED";
+    case PMU_EV_ST_RETIRED:
+        return "ST_RETIRED";
+    case PMU_EV_INST_RETIRED:
+        return "INST_RETIRED";
+    case PMU_EV_EXC_TAKEN:
+        return "EXC_TAKEN";
+    case PMU_EV_EXC_RETURN:
+        return "EXC_RETURN";
+    case PMU_EV_CID_WRITE_RETIRED:
+        return "CID_WRITE_RETIRED";
+    case PMU_EV_PC_WRITE_RETIRED:
+        return "PC_WRITE_RETIRED";
+    case PMU_EV_BR_IMMED_RETIRED:
+        return "BR_IMMED_RETIRED";
+    case PMU_EV_UNALIGNED_LDST_RETIRED:
+        return "UNALIGNED_LDST_RETIRED";
+    case PMU_EV_BR_MIS_PRED:
+        return "BR_MIS_PRED";
+    case PMU_EV_CPU_CYCLES:
+        return "CPU_CYCLES";
+    case PMU_EV_BR_PRED:
+        return "BR_PRED";
+    case PMU_EV_MEM_ACCESS:
+        return "MEM_ACCESS";
+    case PMU_EV_L1I_CACHE:
+        return "L1I_CACHE";
+    case PMU_EV_L1D_CACHE_WB:
+        return "L1D_CACHE_WB";
+    case PMU_EV_L2D_CACHE:
+        return "L2D_CACHE";
+    case PMU_EV_L2D_CACHE_REFILL:
+        return "L2D_CACHE_REFILL";
+    case PMU_EV_L2D_CACHE_WB:
+        return "L2D_CACHE_WB";
+    case PMU_EV_BUS_ACCESS:
+        return "BUS_ACCESS";
+    case PMU_EV_MEMORY_ERROR:
+        return "MEMORY_ERROR";
+    case PMU_EV_BUS_CYCLES:
+        return "BUS_CYCLES";
+    case PMU_EV_CHAIN:
+        return "CHAIN";
+    case PMU_EV_BUS_ACCESS_LD:
+        return "BUS_ACCESS_LD";
+    case PMU_EV_BUS_ACCESS_ST:
+        return "BUS_ACCESS_ST";
+    case PMU_EV_BR_INDIRECT_SPEC:
+        return "BR_INDIRECT_SPEC";
+    case PMU_EV_EXC_IRQ:
+        return "EXC_IRQ";
+    case PMU_EV_EXC_FIQ:
+        return "EXC_FIQ";
+    case -1:
+        return "CCNT";
+    default:
+        return "UNKNOWN_EVENT";
+    }
+}
+
+#define RECORD_SEL1 (U(0) | PMCCFILTR_EL0_U_BIT | PMCCFILTR_EL0_NSK_BIT)
+#define RECORD_EL3 \
+    (U(0) | PMCCFILTR_EL0_U_BIT | PMCCFILTR_EL0_P_BIT | PMCCFILTR_EL0_M_BIT)
+#define RECORD_ALL (U(0) | PMCCFILTR_EL0_NSH_BIT)
+
+/**
+ * struct trusty_pmu_state - Holds the current state of pmu slots and counters.
+ * @evts:             array of pmu counter events codes with which respective
+ * slot have to be programmed
+ * @vals:             array of pmu counter current values
+ * @evt_cnt:         number of events/values
+ */
+struct trusty_pmu_state {
+    uint64_t* evts;
+    uint64_t* vals;
+    uint64_t evt_cnt;
+};
+
+/**
+ * pmu_start - Setup events slots and Start recording
+ *
+ * @state:      current states of the pmu counters
+ */
+static void pmu_start(struct trusty_pmu_state* state) {
+    if (state == NULL || state->evts == NULL) {
+        return;
+    }
+
+    uint64_t nb_counters = get_pmn();
+
+    if (nb_counters < state->evt_cnt) {
+        fprintf(stderr,
+                "ERROR: There are only %" PRIu64
+                " Programmable Counters, yet you are trying to record %" PRIu64
+                " events.\n",
+                nb_counters, state->evt_cnt);
+
+        return;
+    }
+
+    enable_pmu();                  // Enable the PMU
+    reset_ccnt();                  // Reset the CCNT (cycle counter)
+    reset_pmn();                   // Reset the configurable counters
+    write_flags((1 << 31) | 0xf);  // Reset overflow flags
+
+    for (size_t i = 0; i < state->evt_cnt; i++) {
+        pmn_config(i, state->evts[i] | RECORD_ALL);
+        set_pmu_filters(i, 0U | RECORD_ALL);
+    }
+    ccnt_divider(0);  // Enable divide by 64
+    enable_ccnt();    // Enable CCNT
+
+    for (size_t i = 0; i < state->evt_cnt; i++)
+        enable_pmn(i);
+}
+
+/**
+ * pmu_stop - Stop recording
+ *
+ * @state:      current states of the pmu counters
+ */
+static void pmu_stop(struct trusty_pmu_state* state) {
+    if (state == NULL || state->evts == NULL) {
+        return;
+    }
+    disable_ccnt();
+
+    for (size_t i = 0; i < state->evt_cnt; i++)
+        disable_pmn(i);
+
+    for (size_t i = 0; i < state->evt_cnt; i++) {
+        state->vals[i + 1] = read_pmn(i);
+    }
+    state->vals[0] = read_ccnt();  // Read CCNT
+}
+
+/**
+ * init_pmu_state - Allocate memory for values and bind events to be programmed
+ *
+ * @evt_arr:        array of events on whiches to program into the slots
+ * @evt_arr_sz:     countof/nb_elements of evt_arr
+ * @pmu_state:      current states of the pmu counters
+ */
+static inline void init_pmu_state(uint64_t* evt_arr,
+                                  size_t evt_arr_sz,
+                                  struct trusty_pmu_state* pmu_state) {
+    pmu_state->vals = calloc(evt_arr_sz + 1, sizeof(uint64_t));
+    pmu_state->evts = evt_arr;
+    pmu_state->evt_cnt = evt_arr_sz;
+}
+
+/**
+ * clean_pmu - Frees memory of value array and reset size
+ *
+ * @pmu_state:      current states of the pmu counters
+ */
+static inline void clean_pmu(struct trusty_pmu_state* pmu_state) {
+    free(pmu_state->vals);
+    pmu_state->vals = NULL;
+    pmu_state->evt_cnt = 0;
+}
+
+/**
+ * reset_pmu_cnts - Resets all pmu counters to 0
+ *
+ * @pmu_state:      current states of the pmu counters
+ */
+static inline void reset_pmu_cnts(struct trusty_pmu_state* pmu_state) {
+    memset(pmu_state->vals, 0, sizeof(uint64_t) * pmu_state->evt_cnt);
+}
diff --git a/lib/pmu/include/lib/pmu/pmu_arch.h b/lib/pmu/include/lib/pmu/pmu_arch.h
new file mode 100644
index 0000000..689f640
--- /dev/null
+++ b/lib/pmu/include/lib/pmu/pmu_arch.h
@@ -0,0 +1,117 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining
+ * a copy of this software and associated documentation files
+ * (the "Software"), to deal in the Software without restriction,
+ * including without limitation the rights to use, copy, modify, merge,
+ * publish, distribute, sublicense, and/or sell copies of the Software,
+ * and to permit persons to whom the Software is furnished to do so,
+ * subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be
+ * included in all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+ * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+ * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
+ * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
+ * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+ * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+ * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifndef PMU_ARCH_H
+#define PMU_ARCH_H
+
+#define U(_x) (_x##U)
+
+/*******************************************************************************
+ * Definitions of register offsets and fields in the CNTBaseN Frame of the
+ * system level implementation of the Generic Timer.
+ ******************************************************************************/
+/* Physical Count register. */
+#define CNTPCT_LO U(0x0)
+/* Counter Frequency register. */
+#define CNTBASEN_CNTFRQ U(0x10)
+/* Physical Timer CompareValue register. */
+#define CNTP_CVAL_LO U(0x20)
+/* Physical Timer Control register. */
+#define CNTP_CTL U(0x2c)
+
+/* PMCR_EL0 definitions */
+#define PMCR_EL0_RESET_VAL U(0x0)
+#define PMCR_EL0_N_SHIFT U(11)
+#define PMCR_EL0_N_MASK U(0x1f)
+#define PMCR_EL0_N_BITS (PMCR_EL0_N_MASK << PMCR_EL0_N_SHIFT)
+#define PMCR_EL0_LC_BIT (U(1) << 6)
+#define PMCR_EL0_DP_BIT (U(1) << 5)
+#define PMCR_EL0_X_BIT (U(1) << 4)
+#define PMCR_EL0_D_BIT (U(1) << 3)
+#define PMCR_EL0_C_BIT (U(1) << 2)
+#define PMCR_EL0_P_BIT (U(1) << 1)
+#define PMCR_EL0_E_BIT (U(1) << 0)
+
+/* PMCNTENSET_EL0 definitions */
+#define PMCNTENSET_EL0_C_BIT (U(1) << 31)
+#define PMCNTENSET_EL0_P_BIT(x) (U(1) << x)
+
+/* PMEVTYPER<n>_EL0 definitions */
+#define PMEVTYPER_EL0_P_BIT (U(1) << 31)
+#define PMEVTYPER_EL0_NSK_BIT (U(1) << 29)
+#define PMEVTYPER_EL0_NSH_BIT (U(1) << 27)
+#define PMEVTYPER_EL0_M_BIT (U(1) << 26)
+#define PMEVTYPER_EL0_MT_BIT (U(1) << 25)
+#define PMEVTYPER_EL0_SH_BIT (U(1) << 24)
+#define PMEVTYPER_EL0_EVTCOUNT_BITS U(0x000003FF)
+
+/* PMCCFILTR_EL0 definitions */
+#define PMCCFILTR_EL0_P_BIT (U(1) << 31)
+#define PMCCFILTR_EL0_U_BIT (U(1) << 30)
+#define PMCCFILTR_EL0_NSK_BIT (U(1) << 29)
+#define PMCCFILTR_EL0_NSH_BIT (U(1) << 27)
+#define PMCCFILTR_EL0_M_BIT (U(1) << 26)
+#define PMCCFILTR_EL0_MT_BIT (U(1) << 25)
+#define PMCCFILTR_EL0_SH_BIT (U(1) << 24)
+#define PMCCFILTR_EL0_T_BIT (U(1) << 23)
+#define PMCCFILTR_EL0_RLK_BIT (U(1) << 22)
+#define PMCCFILTR_EL0_RLU_BIT (U(1) << 21)
+#define PMCCFILTR_EL0_RLH_BIT (U(1) << 20)
+
+/* PMU event counter ID definitions */
+#define PMU_EV_SW_INCR U(0x00)
+#define PMU_EV_L1I_CACHE_REFILL U(0x01)
+#define PMU_EV_L1I_TLB_REFILL U(0x02)
+#define PMU_EV_L1D_CACHE_REFILL U(0x03)
+#define PMU_EV_L1D_CACHE U(0x04)
+#define PMU_EV_L1D_TLB_REFILL U(0x05)
+#define PMU_EV_LD_RETIRED U(0x06)
+#define PMU_EV_ST_RETIRED U(0x07)
+#define PMU_EV_INST_RETIRED U(0x08)
+#define PMU_EV_EXC_TAKEN U(0x09)
+#define PMU_EV_EXC_RETURN U(0x0A)
+#define PMU_EV_CID_WRITE_RETIRED U(0x0B)
+#define PMU_EV_PC_WRITE_RETIRED U(0x0C)
+#define PMU_EV_BR_IMMED_RETIRED U(0x0D)
+#define PMU_EV_BR_RETURN_RETIRED U(0x0E)
+#define PMU_EV_UNALIGNED_LDST_RETIRED U(0x0F)
+#define PMU_EV_BR_MIS_PRED U(0x10)
+#define PMU_EV_CPU_CYCLES U(0x11)
+#define PMU_EV_BR_PRED U(0x12)
+#define PMU_EV_MEM_ACCESS U(0x13)
+#define PMU_EV_L1I_CACHE U(0x14)
+#define PMU_EV_L1D_CACHE_WB U(0x15)
+#define PMU_EV_L2D_CACHE U(0x16)
+#define PMU_EV_L2D_CACHE_REFILL U(0x17)
+#define PMU_EV_L2D_CACHE_WB U(0x18)
+#define PMU_EV_BUS_ACCESS U(0x19)
+#define PMU_EV_MEMORY_ERROR U(0x1A)
+#define PMU_EV_BUS_CYCLES U(0x1D)
+#define PMU_EV_CHAIN U(0x1E)
+#define PMU_EV_BUS_ACCESS_LD U(0x60)
+#define PMU_EV_BUS_ACCESS_ST U(0x61)
+#define PMU_EV_BR_INDIRECT_SPEC U(0x7A)
+#define PMU_EV_EXC_IRQ U(0x86)
+#define PMU_EV_EXC_FIQ U(0x87)
+
+#endif /* PMU_ARCH_H */
diff --git a/lib/pmu/rules.mk b/lib/pmu/rules.mk
new file mode 100644
index 0000000..7050fd5
--- /dev/null
+++ b/lib/pmu/rules.mk
@@ -0,0 +1,29 @@
+# Copyright (C) 2023 The Android Open Source Project
+#
+# Permission is hereby granted, free of charge, to any person obtaining
+# a copy of this software and associated documentation files
+# (the "Software"), to deal in the Software without restriction,
+# including without limitation the rights to use, copy, modify, merge,
+# publish, distribute, sublicense, and/or sell copies of the Software,
+# and to permit persons to whom the Software is furnished to do so,
+# subject to the following conditions:
+#
+# The above copyright notice and this permission notice shall be
+# included in all copies or substantial portions of the Software.
+#
+# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
+# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
+# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+#
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+GLOBAL_INCLUDES += $(LOCAL_DIR)/include/
+
+include make/module.mk
diff --git a/lib/syscall/arch/x86/64/syscall.S b/lib/syscall/arch/x86/64/syscall.S
index ff921e7..879a882 100644
--- a/lib/syscall/arch/x86/64/syscall.S
+++ b/lib/syscall/arch/x86/64/syscall.S
@@ -24,62 +24,72 @@
 #include <asm.h>
 
 #define SYSCALL_ENTRY_SIZE    0x08
+#define SYSCALL_STACK_OFF     0x08
 
+/*
+ * Entry state:
+ * %rax: syscall number set by syscall stub
+ * %rdi: 1st argument
+ * %rsi: 2nd argument
+ * %rdx: 3rd argument
+ * %rcx: return address saved by syscall instructions (4th argument in ABI)
+ * %r8: 5th argument (unused?)
+ * %r9: 6th argument (unused?)
+ * %r10: 4th argument copied from %rcx by syscall stub
+ * %r11: flags saved by syscall instructions
+ * %rsp: user-space stack (ignored)
+ * %r15: user-space stack saved by stub
+ */
 FUNCTION (x86_syscall)
+    /* clear user-space controlled stack pointer */
+    xor %esp, %esp
+
     /* switch to kernel gs */
     swapgs
+    movq  %gs:SYSCALL_STACK_OFF, %rsp
 
     sti
-    pushq %rbx /* Ring 3 return address */
-    pushq %rbp /* Ring 3 RSP */
-
-    pushq %r15
-    pushq %r14
-    pushq %r13
-    pushq %r12
-    pushq %r11
-    pushq %r10
-    pushq %r9
-    pushq %r8
-    pushq %rcx
-    pushq %rdx
-    pushq %rbx
-    pushq %rbp
-    pushq %rsi
-    pushq %rdi
-
-    movq %rdx,%r9
+    pushq %rcx /* Ring 3 return address */
+    pushq %r15 /* Ring 3 RSP */
+    movq  %r10, %rcx
+
+    pushq %r11 /* saved flags */
+    subq  $0x8, %rsp /* align stack */
+
+    /* Check if syscall index (%rax) is in range */
+    cmp $nr_syscalls, %rax
+    jae .Lundefined_syscall
+
+    /* Load entry from syscall table */
+    movq syscall_table(,%rax,SYSCALL_ENTRY_SIZE), %rax
+
+    /* Check if syscall entry is NULL */
+    test %rax, %rax
+    jz .Lundefined_syscall
+
+    /* Call syscall handler now in %rax */
+.Lsyscall_addr_ready:
+    call *%rax
+
     /*
-     * Arranging params to pass to sysenter handling
-     * syscall table is long. Multiplication to find offset.
-     * Multiplier different for 32 and 64
+     * Clear non-callee saved registers to avoid leaking kernel data to
+     * user-space.
+     * Skip floating/vector registers since the kernel is not allowed to use
+     * them.
+     * Skip 4th argument (%rcx) and %r11 since they get overwritten with
+     * user-space pointers or flags below.
      */
-    movq $SYSCALL_ENTRY_SIZE, %r15
-    /* Result is stored in RAX. Before multiplication RAX contains syscall No. */
-
-    mul %r15
-    movq $syscall_table, %r14
-    add %r14, %rax
-    movq %r9,%rdx
-    call *(%rax)
-
-    popq %rdi
-    popq %rsi
-    popq %rbp
-    popq %rbx
-    popq %rdx
-    popq %rcx
-    popq %r8
-    popq %r9
-    popq %r10
-    popq %r11
-    popq %r12
-    popq %r13
-    popq %r14
-    popq %r15
-
-    popq %rcx /* pop RSP */
-    popq %rdx /* pop RIP */
+    xor %edi, %edi /* clear 1st argument/temporary register */
+    xor %esi, %esi /* clear 2nd argument/temporary register */
+    xor %edx, %edx /* clear 3rd argument/temporary register */
+    xor %r8d, %r8d /* clear 5th argument/temporary register */
+    xor %r9d, %r9d /* clear 6th argument/temporary register */
+    xor %r10d, %r10d /* clear temporary register */
+
+    addq  $0x8, %rsp /* remove stack alignment padding */
+    popq %r11 /* saved flags */
+    popq %r15 /* pop RSP */
+    popq %rcx /* pop RIP */
 
     /*
      * switch to user gs
@@ -89,6 +99,29 @@ FUNCTION (x86_syscall)
      */
     cli
     swapgs
-    sti
 
-    sysexitq
+    /*
+     * Clear kernel stack pointer to avoid leaking ASLR info. We don't restore
+     * the user-space stack pointer here, since sysret can trigger a fault and
+     * we don't want that fault handler to use a user-space controlled stack
+     * pointer. A 0 stack pointer will trigger a double fault instead.
+     */
+    xor %esp, %esp
+
+    /*
+     * Exit state:
+     * %rax: return code
+     * %rcx: return address used by sysret instruction
+     * %r11: saved flags used by sysret instruction
+     * %r15: user-space stack used by stub
+     */
+    sysretq
+
+    /*
+     * Use sys_undefined as the syscall handler if the index in %rax is out of
+     * range of the syscall table or if %rax is in range, but the entry in the
+     * syscall table is NULL.
+     */
+.Lundefined_syscall:
+    movq $sys_undefined, %rax
+    jmp .Lsyscall_addr_ready
diff --git a/lib/syscall/stubgen/stubgen.py b/lib/syscall/stubgen/stubgen.py
index 1deb9dd..1cff770 100755
--- a/lib/syscall/stubgen/stubgen.py
+++ b/lib/syscall/stubgen/stubgen.py
@@ -131,19 +131,13 @@ SECTION_GNU_NOTE_PROPERTY_AARCH64_FEATURES(GNU_NOTE_FEATURE_AARCH64_BTI)
 .global _trusty_%(sys_fn)s
 .type _trusty_%(sys_fn)s,STT_FUNC
 _trusty_%(sys_fn)s:
-    pushfq
-    pushq %%rbp
-    pushq %%rbx
     pushq %%r15
     movq $__NR_%(sys_fn)s, %%rax
-    leaq .L%(sys_fn)s_sysreturn(%%rip), %%rbx
-    movq %%rsp, %%rbp
-    sysenter
-.L%(sys_fn)s_sysreturn:
+    movq %%rcx, %%r10
+    movq %%rsp, %%r15
+    syscall
+    movq %%r15, %%rsp
     popq %%r15
-    popq %%rbx
-    popq %%rbp
-    popfq
     ret
 .size _trusty_%(sys_fn)s,.-_trusty_%(sys_fn)s
 """),
diff --git a/lib/trusty/tipc_dev_ql.c b/lib/trusty/tipc_dev_ql.c
index 24ccda4..ecc58b7 100644
--- a/lib/trusty/tipc_dev_ql.c
+++ b/lib/trusty/tipc_dev_ql.c
@@ -483,9 +483,16 @@ static long dev_has_event(struct ql_tipc_dev* dev,
                           void* ns_data,
                           size_t ns_sz,
                           uint32_t target) {
+    const int opcode = QL_TIPC_DEV_FC_HAS_EVENT;
+
+    if (ns_sz < (sizeof(struct tipc_cmd_hdr) + sizeof(bool)) ||
+        ns_sz > dev->ns_sz) {
+        return set_status(dev, opcode, ERR_INVALID_ARGS, 0);
+    }
+
     bool* ready = (bool*)((uint8_t*)dev->ns_va + sizeof(struct tipc_cmd_hdr));
     *ready = handle_set_ready(dev->handle_set);
-    return set_status(dev, QL_TIPC_DEV_FC_HAS_EVENT, 0, sizeof(*ready));
+    return set_status(dev, opcode, 0, sizeof(*ready));
 }
 
 static long dev_get_event(struct ql_tipc_dev* dev,
@@ -499,11 +506,11 @@ static long dev_get_event(struct ql_tipc_dev* dev,
     struct tipc_wait_req req;
     uint32_t chan_event = 0;
     struct tipc_ept* ept = NULL;
-    int opcode = QL_TIPC_DEV_GET_EVENT;
+    const int opcode = QL_TIPC_DEV_GET_EVENT;
     struct tipc_event* evt = (struct tipc_event*)((uint8_t*)dev->ns_va +
                                                   sizeof(struct tipc_cmd_hdr));
 
-    if (ns_sz < sizeof(req))
+    if (ns_sz < sizeof(req) || ns_sz > dev->ns_sz)
         return set_status(dev, opcode, ERR_INVALID_ARGS, 0);
 
     if (target) {
@@ -640,9 +647,9 @@ long ql_tipc_handle_cmd(ext_mem_client_id_t client_id,
         goto err_not_found;
     }
 
-    /* check for minimum size */
-    if (cmd_sz < sizeof(cmd_hdr)) {
-        TRACEF("message is too short (%zu)\n", (size_t)cmd_sz);
+    /* check for valid size */
+    if (cmd_sz < sizeof(cmd_hdr) || cmd_sz > dev->ns_sz) {
+        TRACEF("message size invalid (%zu)\n", (size_t)cmd_sz);
         goto err_invalid;
     }
 
diff --git a/lib/trusty/trusty_app.c b/lib/trusty/trusty_app.c
index 3059b2d..3b7c401 100644
--- a/lib/trusty/trusty_app.c
+++ b/lib/trusty/trusty_app.c
@@ -51,6 +51,8 @@
 
 #define LOCAL_TRACE 0
 
+#define NS2MS_CEIL(ns) DIV_ROUND_UP(ns, 1000000ULL)
+
 #define DEFAULT_MGMT_FLAGS APP_MANIFEST_MGMT_FLAGS_NONE
 
 #define TRUSTY_APP_RESTART_TIMEOUT_SUCCESS (10ULL * 1000ULL * 1000ULL)
@@ -511,8 +513,6 @@ static int trusty_thread_startup(void* arg) {
     user_addr_t elf_tables = trusty_thread_write_elf_tables(
             trusty_thread, &stack_ptr, trusty_thread->app->load_bias);
 
-    thread_sleep_until_ns(trusty_thread->app->min_start_time);
-
     user_addr_t shadow_stack_base = 0;
 #if USER_SCS_SUPPORTED
     shadow_stack_base = trusty_thread->shadow_stack_base;
@@ -1665,15 +1665,18 @@ status_t trusty_app_setup_mmio(struct trusty_app* trusty_app,
 
     list_for_every_entry(&trusty_app->props.mmio_entry_list, mmio_entry,
                          struct manifest_mmio_entry, node) {
+        char name[32];
+
         if (mmio_entry->id != mmio_id) {
             continue;
         }
 
         map_size = round_up(map_size, PAGE_SIZE);
+        snprintf(name, sizeof(name), "mmio-%" PRIu32, mmio_id);
 
         ret = vmm_alloc_obj(
-                trusty_app->aspace, "mmio", &mmio_entry->phys_mem_obj.vmm_obj,
-                0, map_size, &va, 0, 0,
+                trusty_app->aspace, name, &mmio_entry->phys_mem_obj.vmm_obj, 0,
+                map_size, &va, 0, 0,
                 ARCH_MMU_FLAG_PERM_USER | ARCH_MMU_FLAG_PERM_NO_EXECUTE);
         if (ret == NO_ERROR) {
             *uaddr_p = (user_addr_t)(uintptr_t)va;
@@ -1967,13 +1970,31 @@ static status_t app_mgr_handle_terminating(struct trusty_app* app) {
 static int app_mgr(void* arg) {
     status_t ret;
     struct trusty_app* app;
+    lk_time_ns_t min_start_time = UINT64_MAX;
+    lk_time_ns_t now = 0;
 
     while (true) {
-        LTRACEF("app manager waiting for events\n");
-        event_wait(&app_mgr_event);
+        lk_time_t timeout_ms = 0;
+
+        if (min_start_time == UINT64_MAX) {
+            timeout_ms = INFINITE_TIME;
+        } else {
+            now = current_time_ns();
+            if (min_start_time > now) {
+                timeout_ms = NS2MS_CEIL(min_start_time - now);
+            }
+        }
+
+        LTRACEF("app manager waiting for events with timeout_ms=%d\n",
+                (int32_t)timeout_ms);
+
+        event_wait_timeout(&app_mgr_event, timeout_ms);
 
         mutex_acquire(&apps_lock);
 
+        now = current_time_ns();
+        min_start_time = UINT64_MAX;
+
         list_for_every_entry(&trusty_app_list, app, struct trusty_app, node) {
             switch (app->state) {
             case APP_TERMINATING:
@@ -1986,15 +2007,19 @@ static int app_mgr(void* arg) {
             case APP_NOT_RUNNING:
                 break;
             case APP_STARTING:
-                ret = app_mgr_handle_starting(app);
-                if (ret != NO_ERROR) {
-                    if (!(app->props.mgmt_flags &
-                          APP_MANIFEST_MGMT_FLAGS_NON_CRITICAL_APP)) {
-                        panic("failed(%d) to start app %u, %s\n", ret,
-                              app->app_id, app->props.app_name);
+                if (now >= app->min_start_time) {
+                    ret = app_mgr_handle_starting(app);
+                    if (ret != NO_ERROR) {
+                        if (!(app->props.mgmt_flags &
+                              APP_MANIFEST_MGMT_FLAGS_NON_CRITICAL_APP)) {
+                            panic("failed(%d) to start app %u, %s\n", ret,
+                                  app->app_id, app->props.app_name);
+                        }
+                        TRACEF("failed(%d) to start app %u, %s\n", ret,
+                               app->app_id, app->props.app_name);
                     }
-                    TRACEF("failed(%d) to start app %u, %s\n", ret, app->app_id,
-                           app->props.app_name);
+                } else if (app->min_start_time < min_start_time) {
+                    min_start_time = app->min_start_time;
                 }
                 break;
             case APP_RUNNING:
diff --git a/lib/trusty/trusty_virtio.c b/lib/trusty/trusty_virtio.c
index 615b9ff..7f8616d 100644
--- a/lib/trusty/trusty_virtio.c
+++ b/lib/trusty/trusty_virtio.c
@@ -504,7 +504,7 @@ status_t virtio_start(ext_mem_client_id_t client_id,
         goto err_bad_state;
     }
 
-    if ((size_t)descr_sz != vb->descr_size) {
+    if ((size_t)descr_sz != vb->descr_size || descr_sz == 0) {
         LTRACEF("unexpected descriptor size (%zd vs. %zd)\n", (size_t)descr_sz,
                 vb->descr_size);
         ret = ERR_INVALID_ARGS;
diff --git a/lib/unittest/rules.mk b/lib/unittest/rules.mk
index e6baedd..bf73fb7 100644
--- a/lib/unittest/rules.mk
+++ b/lib/unittest/rules.mk
@@ -24,9 +24,11 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
-MODULE_SRCS := \
-	$(LOCAL_DIR)/unittest.c
+MODULE_SRCS := $(LOCAL_DIR)/unittest.c
 
-GLOBAL_INCLUDES += $(LOCAL_DIR)/include/
+GLOBAL_INCLUDES += 	$(LOCAL_DIR)/include/ \
+					$(LOCAL_DIR)/../pmu/include/
+
+MODULE_DEPS += trusty/kernel/lib/pmu
 
 include make/module.mk
diff --git a/make/generic_compile.mk b/make/generic_compile.mk
index dde729c..28ac211 100644
--- a/make/generic_compile.mk
+++ b/make/generic_compile.mk
@@ -43,6 +43,8 @@ ifeq ($(GENERIC_OBJ_DIR), )
 $(error GENERIC_OBJ_DIR must be specified)
 endif
 
+GENERIC_FLAGS += --sysroot $(CLANG_HOST_SYSROOT)
+
 # Group the source files so we can differ the flags between C, C++, and assembly.
 GENERIC_C_SRCS := $(filter %.c,$(GENERIC_SRCS))
 GENERIC_C_OBJS := $(addprefix $(GENERIC_OBJ_DIR)/,$(patsubst %.c,%.o,$(GENERIC_C_SRCS)))
diff --git a/make/host_test.mk b/make/host_test.mk
index e377d1d..69acfdb 100644
--- a/make/host_test.mk
+++ b/make/host_test.mk
@@ -49,7 +49,8 @@ HOST_TEST_BUILDDIR := $(TRUSTY_TOP_LEVEL_BUILDDIR)
 endif
 
 # We should use the prebuilt linker rather than the host linker
-HOST_LDFLAGS := -B$(CLANG_BINDIR) -fuse-ld=lld
+HOST_LDFLAGS := -B$(CLANG_BINDIR) -B$(CLANG_HOST_SEARCHDIR) \
+	$(foreach dir,$(CLANG_HOST_LDDIRS),-L$(dir)) --sysroot=$(CLANG_HOST_SYSROOT) -fuse-ld=lld
 
 HOST_CC := $(CLANG_BINDIR)/clang
 HOST_SANITIZER_FLAGS := -fsanitize=address -fno-omit-frame-pointer
diff --git a/make/host_tool.mk b/make/host_tool.mk
index dbcf26a..1cab70e 100644
--- a/make/host_tool.mk
+++ b/make/host_tool.mk
@@ -58,7 +58,8 @@ HOST_LDFLAGS += -lpthread
 endif
 
 # We should use the prebuilt linker rather than the host linker
-HOST_LDFLAGS += -B$(CLANG_BINDIR) -fuse-ld=lld
+HOST_LDFLAGS += -B$(CLANG_BINDIR) -B$(CLANG_HOST_SEARCHDIR) \
+	$(foreach dir,$(CLANG_HOST_LDDIRS),-L$(dir)) --sysroot=$(CLANG_HOST_SYSROOT) -fuse-ld=lld
 
 # When using clang, we need to always use the prebuilt libc++ library
 # because we can't be sure what version of libstdc++ the host system
diff --git a/platform/generic-x86_64/rules.mk b/platform/generic-x86_64/rules.mk
index c32ef81..ca9811a 100644
--- a/platform/generic-x86_64/rules.mk
+++ b/platform/generic-x86_64/rules.mk
@@ -30,6 +30,5 @@ MODULE_DEPS += \
 	$(LOCAL_DIR)/rust \
 	dev/interrupt/x86_lapic \
 	dev/timer/x86_generic \
-	dev/virtio/vsock-rust \
 
 include make/module.mk
diff --git a/platform/generic-x86_64/rust/rules.mk b/platform/generic-x86_64/rust/rules.mk
index 6a71969..40c05fd 100644
--- a/platform/generic-x86_64/rust/rules.mk
+++ b/platform/generic-x86_64/rust/rules.mk
@@ -10,5 +10,6 @@ MODULE_SRCS += \
 MODULE_LIBRARY_DEPS += \
 	external/rust/crates/acpi \
 	external/rust/crates/log \
+	dev/virtio/vsock-rust \
 
 include make/library.mk
diff --git a/platform/generic-x86_64/rust/src/lib.rs b/platform/generic-x86_64/rust/src/lib.rs
index 67b3ca0..2c78b62 100644
--- a/platform/generic-x86_64/rust/src/lib.rs
+++ b/platform/generic-x86_64/rust/src/lib.rs
@@ -86,7 +86,14 @@ impl AcpiHandler for LkAcpiHandler {
     }
 }
 
-extern "C" fn platform_acpi_init_func(_level: c_uint) {
+/// Search the ACPI tables for the physical address which is the base of the MMIO
+/// region and pass it to `pci_init_mmio` to initialize the virtio-vsock bridge.
+///
+/// # Safety
+///
+/// A caller must ensure that this function is called exactly once during kernel
+/// initialization on a system which has a BIOS (as opposed to UEFI systems).
+unsafe extern "C" fn platform_acpi_init_func(_level: c_uint) {
     // SAFETY: search_for_rsdp_bios searches for a RSDP on BIOS systems.
     // It is not safe to call on a UEFI system. crosvm currently emulates
     // a BIOS system.
@@ -109,10 +116,10 @@ extern "C" fn platform_acpi_init_func(_level: c_uint) {
 
     let entry_size = (1 + entry.bus_number_end as usize - entry.bus_number_start as usize) << 20;
 
-    log::error!(
-        "TODO: call init function for pci bus at {:#x}, size {entry_size:#x}",
-        entry.base_address as usize
-    );
+    // SAFETY: the first argument must be a valid physical address pointing to the base of the MMIO region.
+    // The second argument must be the size of the MMIO region and be valid under the PCI express version
+    // implemented by the system. `pci_init_mmio` must not have been called previously.
+    unsafe { vsock::pci_init_mmio(entry.base_address as usize, entry_size, 1usize << 15) };
 }
 
 LK_INIT_HOOK!(platform_acpi_init, platform_acpi_init_func, lk_init_level::LK_INIT_LEVEL_THREADING);
```

