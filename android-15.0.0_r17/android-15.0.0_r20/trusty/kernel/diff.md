```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..f0acdd0
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_trusty_kernel",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/app/mmutest/mmutest.c b/app/mmutest/mmutest.c
index 1444150..19584a2 100644
--- a/app/mmutest/mmutest.c
+++ b/app/mmutest/mmutest.c
@@ -1071,7 +1071,7 @@ TEST_F(mmutest_pmm, reserve) {
     void* ptr_unused = NULL;
     status_t ret;
     struct vmm_aspace* temp_aspace = NULL;
-    uint max_pages;
+    uint max_pages, temp_aspace_pages;
 
     /* Allocate virtual space without quota or pmm, which should pass */
     ret = vmm_alloc(_state->aspace, "test_reserve",
@@ -1090,9 +1090,9 @@ TEST_F(mmutest_pmm, reserve) {
     ASSERT_GT(max_pages, RESERVE_PAGES);
 
     /* Reserve most pages for temp_aspace, leaving RESERVE_PAGES / 2 free */
-    ret = vmm_create_aspace_with_quota(
-            &temp_aspace, "temp_aspace",
-            PAGE_SIZE * (max_pages - RESERVE_PAGES / 2), 0);
+    temp_aspace_pages = max_pages - (RESERVE_PAGES / 2);
+    ret = vmm_create_aspace_with_quota(&temp_aspace, "temp_aspace",
+                                       PAGE_SIZE * temp_aspace_pages, 0);
     ASSERT_EQ(NO_ERROR, ret);
 
     /* Almost all pages are reserved for temp_aspace quota; this should fail */
@@ -1100,10 +1100,10 @@ TEST_F(mmutest_pmm, reserve) {
                     &ptr_unused, 0, 0, ARCH_MMU_FLAG_PERM_NO_EXECUTE);
     ASSERT_EQ(ERR_NO_MEMORY, ret);
 
-    /* Allocate from temp_aspace quota reservation */
+    /* Allocate from the temp_aspace quota reservation; should succeed */
     ptr += PAGE_SIZE * 2;
     ret = vmm_alloc(temp_aspace, "test_from_reserved_success",
-                    PAGE_SIZE * RESERVE_PAGES, &ptr, 0,
+                    PAGE_SIZE * MIN(temp_aspace_pages, RESERVE_PAGES), &ptr, 0,
                     VMM_FLAG_QUOTA | VMM_FLAG_VALLOC_SPECIFIC,
                     ARCH_MMU_FLAG_PERM_NO_EXECUTE);
     ASSERT_EQ(NO_ERROR, ret);
@@ -1199,9 +1199,8 @@ TEST_F(mmutest_res_group, reserve_group_release_ref) {
     ASSERT_EQ(NO_ERROR, vmm_free_aspace(_state->aspace));
     _state->aspace = NULL;
     ASSERT_EQ(true, obj_has_only_ref(&slice.obj->obj, &slice.obj_ref));
-test_abort:
-    if (slice_init == NO_ERROR && obj_has_ref(&slice.obj->obj))
-        obj_del_ref(&slice.obj->obj, &slice.obj_ref, NULL);
+    vmm_obj_slice_release(&slice);
+test_abort:;
 }
 
 TEST_F(mmutest_res_group, no_physical_inner_obj) {
@@ -1221,6 +1220,7 @@ TEST_F(mmutest_res_group, no_physical_inner_obj) {
     ASSERT_EQ(PAGE_SIZE, slice.size);
     ASSERT_EQ(NO_ERROR, vmm_free_region(_state->aspace, (vaddr_t)ptr));
     ASSERT_EQ(true, obj_has_only_ref(&slice.obj->obj, &slice.obj_ref));
+    vmm_obj_slice_release(&slice);
 test_abort:;
 }
 
diff --git a/app/stdcalltest/stdcalltest.c b/app/stdcalltest/stdcalltest.c
index b9aae5a..e6cb6d3 100644
--- a/app/stdcalltest/stdcalltest.c
+++ b/app/stdcalltest/stdcalltest.c
@@ -31,6 +31,7 @@
 #include <arch/ops.h>
 #include <err.h>
 #include <inttypes.h>
+#include <kernel/thread.h>
 #include <kernel/vm.h>
 #include <lib/sm.h>
 #include <lib/sm/sm_err.h>
@@ -38,6 +39,7 @@
 #include <lib/smc/smc.h>
 #include <limits.h>
 #include <lk/init.h>
+#include <stdatomic.h>
 #include <string.h>
 #include <trace.h>
 
@@ -170,6 +172,131 @@ end_stdcalltest_clobber_sve:
     ARM64_WRITE_SYSREG(cpacr_el1, v_cpacr_el1);
     return ret;
 }
+
+static long stdcalltest_compute_fpacr(uint64_t* old_cpacr,
+                                      uint64_t* new_cpacr) {
+    uint64_t cpacr = ARM64_READ_SYSREG(cpacr_el1);
+
+    DEBUG_ASSERT(old_cpacr);
+    DEBUG_ASSERT(new_cpacr);
+
+    if ((cpacr >> 20) & 1) {
+        return SM_ERR_NOT_ALLOWED;
+    }
+
+    *old_cpacr = cpacr;
+    *new_cpacr = cpacr | (3 << 20);
+    return 0;
+}
+
+static uint32_t stdcalltest_random_u32(void) {
+    /* Initialize the RNG seed to the golden ratio */
+    static atomic_int hash = 0x9e3779b1U;
+    int oldh, newh;
+
+    /* Update the RNG with MurmurHash3 */
+    do {
+        newh = oldh = atomic_load(&hash);
+        newh ^= newh >> 16;
+        __builtin_mul_overflow(newh, 0x85ebca6bU, &newh);
+        newh ^= newh >> 13;
+        __builtin_mul_overflow(newh, 0xc2b2ae35U, &newh);
+        newh ^= newh >> 16;
+    } while (!atomic_compare_exchange_weak(&hash, &oldh, newh));
+
+    return (uint32_t)oldh;
+}
+
+static struct fpstate stdcalltest_random_fpstate;
+
+static long stdcalltest_clobber_fpsimd_clobber(struct smc32_args* args) {
+    long ret;
+    uint64_t old_cpacr, new_cpacr;
+    bool loaded;
+
+    /*
+     * Check if the FPU at EL1 is already on;
+     * it shouldn't be, so return an error if it is.
+     * Otherwise, save the old value and restore it
+     * after we're done.
+     */
+    ret = stdcalltest_compute_fpacr(&old_cpacr, &new_cpacr);
+    if (ret) {
+        return ret;
+    }
+
+    for (size_t i = 0; i < countof(stdcalltest_random_fpstate.regs); i++) {
+        stdcalltest_random_fpstate.regs[i] =
+                ((uint64_t)stdcalltest_random_u32() << 32) |
+                stdcalltest_random_u32();
+    }
+    /*
+     * TODO: set FPCR&FPSR to random values, but they need to be masked
+     * because many of their bits are MBZ
+     */
+    stdcalltest_random_fpstate.fpcr = 0;
+    stdcalltest_random_fpstate.fpsr = 0;
+
+    ARM64_WRITE_SYSREG(cpacr_el1, new_cpacr);
+    loaded = arm64_fpu_load_fpstate(&stdcalltest_random_fpstate, true);
+    ARM64_WRITE_SYSREG(cpacr_el1, old_cpacr);
+    return loaded ? 0 : SM_ERR_INTERNAL_FAILURE;
+}
+
+static long stdcalltest_clobber_fpsimd_check(struct smc32_args* args) {
+    long ret;
+    uint64_t old_cpacr, new_cpacr;
+    struct fpstate new_fpstate;
+    bool loaded;
+
+    ret = stdcalltest_compute_fpacr(&old_cpacr, &new_cpacr);
+    if (ret) {
+        return ret;
+    }
+
+    ARM64_WRITE_SYSREG(cpacr_el1, new_cpacr);
+    loaded = arm64_fpu_load_fpstate(&stdcalltest_random_fpstate, false);
+    arm64_fpu_save_fpstate(&new_fpstate);
+    ARM64_WRITE_SYSREG(cpacr_el1, old_cpacr);
+
+    if (loaded) {
+        /*
+         * Check whether the current fpstate is still the one set
+         * earlier by the clobber. If not, it means another thread
+         * ran and overwrote our registers, and we do not want to
+         * leak them here.
+         */
+        ret = SM_ERR_BUSY;
+        goto err;
+    }
+
+    for (size_t i = 0; i < countof(new_fpstate.regs); i++) {
+        if (new_fpstate.regs[i] != stdcalltest_random_fpstate.regs[i]) {
+            TRACEF("regs[%zu] mismatch: %" PRIx64 " != %" PRIx64 "\n", i,
+                   new_fpstate.regs[i], stdcalltest_random_fpstate.regs[i]);
+            ret = SM_ERR_INTERNAL_FAILURE;
+            goto err;
+        }
+    }
+    if (new_fpstate.fpcr != stdcalltest_random_fpstate.fpcr) {
+        TRACEF("FPCR mismatch: %" PRIx32 " != %" PRIx32 "\n", new_fpstate.fpcr,
+               stdcalltest_random_fpstate.fpcr);
+        ret = SM_ERR_INTERNAL_FAILURE;
+        goto err;
+    }
+    if (new_fpstate.fpsr != stdcalltest_random_fpstate.fpsr) {
+        TRACEF("FPSR mismatch: %" PRIx32 " != %" PRIx32 "\n", new_fpstate.fpsr,
+               stdcalltest_random_fpstate.fpsr);
+        ret = SM_ERR_INTERNAL_FAILURE;
+        goto err;
+    }
+
+    /* Return 0 on success */
+    ret = 0;
+
+err:
+    return ret;
+}
 #endif
 
 static long stdcalltest_stdcall(struct smc32_args* args) {
@@ -189,8 +316,27 @@ static long stdcalltest_stdcall(struct smc32_args* args) {
     }
 }
 
+static long stdcalltest_fastcall(struct smc32_args* args) {
+    switch (args->smc_nr) {
+#if ARCH_ARM64
+    case SMC_FC_TEST_CLOBBER_FPSIMD_CLOBBER:
+        return stdcalltest_clobber_fpsimd_clobber(args);
+    case SMC_FC_TEST_CLOBBER_FPSIMD_CHECK:
+        return stdcalltest_clobber_fpsimd_check(args);
+#else
+        /* This test is a no-op on other architectures, e.g., arm32 */
+    case SMC_FC_TEST_CLOBBER_FPSIMD_CLOBBER:
+    case SMC_FC_TEST_CLOBBER_FPSIMD_CHECK:
+        return 0;
+#endif
+    default:
+        return SM_ERR_UNDEFINED_SMC;
+    }
+}
+
 static struct smc32_entity stdcalltest_sm_entity = {
         .stdcall_handler = stdcalltest_stdcall,
+        .fastcall_handler = stdcalltest_fastcall,
 };
 
 static void stdcalltest_init(uint level) {
diff --git a/app/stdcalltest/stdcalltest.h b/app/stdcalltest/stdcalltest.h
index 979432e..b30d72f 100644
--- a/app/stdcalltest/stdcalltest.h
+++ b/app/stdcalltest/stdcalltest.h
@@ -63,4 +63,36 @@
  */
 #define SMC_SC_TEST_CLOBBER_SVE SMC_STDCALL_NR(SMC_ENTITY_TEST, 2)
 
+/**
+ * SMC_SC_TEST_CLOBBER_FPSIMD_CLOBBER - Test save and clobber of FP/SIMD
+ * registers during an NS <-> TF-A <-> Trusty roundtrip.
+ *
+ * Return: 0 on success, or one of the libsm errors otherwise:
+ * * %SM_ERR_NOT_ALLOWED: Not allowed to enable the FPU in Trusty.
+ * * %SM_ERR_INTERNAL_FAILURE: The test failed to load random values
+ *                             into the FP registers.
+ *
+ * Set all of the secure-side FP registers to random values.
+ */
+#define SMC_FC_TEST_CLOBBER_FPSIMD_CLOBBER SMC_FASTCALL_NR(SMC_ENTITY_TEST, 0)
+
+/**
+ * SMC_SC_TEST_CLOBBER_FPSIMD_CHECK - Check and restore FP/SIMD
+ * registers after an NS <-> TF-A <-> Trusty roundtrip.
+ *
+ * Return: 0 on success, or one of the libsm errors otherwise:
+ * * %SM_ERR_NOT_ALLOWED: Not allowed to enable the FPU in Trusty.
+ * * %SM_ERR_BUSY: Another thread clobbered our registers.
+ * * %SM_ERR_INTERNAL_FAILURE: The FP registers did not match
+ *                             the expected values.
+ *
+ * The call should immediately follow a corresponding clobber,
+ * since the latter stores some internal state in Trusty.
+ *
+ * The caller should disable interrupts before
+ * &SMC_FC_TEST_CLOBBER_FPSIMD_CLOBBER and don't re-enable before
+ * &SMC_FC_TEST_CLOBBER_FPSIMD_CHECK returns to avoid the %SM_ERR_BUSY error.
+ */
+#define SMC_FC_TEST_CLOBBER_FPSIMD_CHECK SMC_FASTCALL_NR(SMC_ENTITY_TEST, 1)
+
 #define TRUSTY_STDCALLTEST_API_VERSION 1
diff --git a/include/shared/lk/trusty_unittest.h b/include/shared/lk/trusty_unittest.h
index ed22548..8cc6cab 100644
--- a/include/shared/lk/trusty_unittest.h
+++ b/include/shared/lk/trusty_unittest.h
@@ -23,6 +23,7 @@
 
 #pragma once
 
+#include <inttypes.h>
 #include <lk/compiler.h>
 #include <lk/list.h>
 #include <stdbool.h>
@@ -30,6 +31,14 @@
 
 __BEGIN_CDECLS
 
+/*
+ * This function returns a time in nanoseconds based on hardware counters
+ * it is expected to:
+ *  - Be non-wrapping or have very long (years) roll-over period
+ *  - Have a resolution below 100nsc
+ */
+uint64_t get_current_time_ns(void);
+
 /*
  * Test functions can be defined with:
  * TEST(SuiteName, TestName) {
@@ -95,18 +104,20 @@ __BEGIN_CDECLS
 
 /**
  * struct test_context - struct representing the state of a test run.
- * @tests_total:    Number of conditions checked
- * @tests_skipped:  Number of tests skipped
- * @tests_disabled: Number of disabled tests skipped
- * @tests_failed:   Number of conditions failed
- * @inst_name:      Name of the current parameter instantiation
- * @suite_name:     Name of the current test suite
- * @param_name:     Name of the current parameter
- * @test_name:      Name of current test case
- * @test_param:     The current test parameter
- * @all_ok:         State of current test case
- * @skipped:        Current test was skipped.
- * @hard_fail:      Type of test failure (when @all_ok is false)
+ * @tests_total:      Number of conditions checked
+ * @tests_skipped:    Number of tests skipped
+ * @tests_disabled:   Number of disabled tests skipped
+ * @tests_failed:     Number of conditions failed
+ * @inst_name:        Name of the current parameter instantiation
+ * @suite_name:       Name of the current test suite
+ * @param_name:       Name of the current parameter
+ * @test_name:        Name of current test case
+ * @test_param:       The current test parameter
+ * @all_ok:           State of current test case
+ * @skipped:          Current test was skipped.
+ * @hard_fail:        Type of test failure (when @all_ok is false)
+ * @test_start_time:  Test Start Time in ns
+ * @suite_duration_ms:Test Suite duration in ms
  */
 struct test_context {
     unsigned int tests_total;
@@ -121,6 +132,8 @@ struct test_context {
     bool all_ok;
     bool skipped;
     bool hard_fail;
+    uint64_t test_start_time;
+    uint64_t suite_duration_ms;
 };
 
 /**
@@ -197,21 +210,49 @@ static struct list_node _test_list = LIST_INITIAL_VALUE(_test_list);
  */
 static struct list_node _test_param_list = LIST_INITIAL_VALUE(_test_param_list);
 
+static inline void trusty_unittest_print_status_name_param_duration(
+        const char* status,
+        const char* param_gen_inst_name, /* parameter generator instance name */
+        const char* suite_name,
+        const char* test_name,
+        const char* param_name,
+        const char* duration_ms) {
+    if (param_gen_inst_name) {
+        trusty_unittest_printf("[ %s ] %s/%s.%s/%s%s\n", status,
+                               param_gen_inst_name, suite_name, test_name,
+                               param_name, duration_ms);
+    } else {
+        trusty_unittest_printf("[ %s ] %s.%s%s\n", status, suite_name,
+                               test_name, duration_ms);
+    }
+}
+
 static inline void trusty_unittest_print_status_name(const char* suite_name,
                                                      const char* test_name,
                                                      const char* status) {
-    if (_test_context.test_param) {
-        trusty_unittest_printf("[ %s ] %s/%s.%s/%s\n", status,
-                               _test_context.inst_name, suite_name, test_name,
-                               _test_context.param_name);
-    } else {
-        trusty_unittest_printf("[ %s ] %s.%s\n", status, suite_name, test_name);
-    }
+    trusty_unittest_print_status_name_param_duration(
+            status, _test_context.inst_name, suite_name, test_name,
+            _test_context.param_name, "");
 }
 
 static inline void trusty_unittest_print_status(const char* status) {
-    trusty_unittest_print_status_name(_test_context.suite_name,
-                                      _test_context.test_name, status);
+    trusty_unittest_print_status_name_param_duration(
+            status, _test_context.inst_name, _test_context.suite_name,
+            _test_context.test_name, _test_context.param_name, "");
+}
+
+static inline void trusty_unittest_print_status_duration(
+        const char* status,
+        uint64_t test_duration_ms) {
+    char duration_str[16] = "";
+
+    /* print duration at end of test case */
+    snprintf(duration_str, sizeof(duration_str), " (%" PRIu64 " ms)",
+             test_duration_ms);
+    trusty_unittest_print_status_name_param_duration(
+            status, _test_context.inst_name, _test_context.suite_name,
+            _test_context.test_name, _test_context.param_name,
+            (const char*)duration_str);
 }
 
 static inline void TEST_BEGIN_FUNC(const char* suite_name,
@@ -223,15 +264,23 @@ static inline void TEST_BEGIN_FUNC(const char* suite_name,
     _test_context.skipped = false;
     _test_context.tests_total++;
     trusty_unittest_print_status("RUN     ");
+    /*
+     * initialize the test start time
+     * (after the print status is slightly better)
+     */
+    _test_context.test_start_time = get_current_time_ns();
 }
 
 static inline void TEST_END_FUNC(void) {
+    uint64_t test_duration_ms =
+            (get_current_time_ns() - _test_context.test_start_time) / 1000000;
+    _test_context.suite_duration_ms += test_duration_ms;
     if (_test_context.skipped) {
-        trusty_unittest_print_status(" SKIPPED");
+        trusty_unittest_print_status_duration(" SKIPPED", test_duration_ms);
     } else if (_test_context.all_ok) {
-        trusty_unittest_print_status("      OK");
+        trusty_unittest_print_status_duration("      OK", test_duration_ms);
     } else {
-        trusty_unittest_print_status(" FAILED ");
+        trusty_unittest_print_status_duration(" FAILED ", test_duration_ms);
     }
     _test_context.test_name = NULL;
 }
@@ -488,49 +537,205 @@ static inline bool has_disabled_prefix(const char* str) {
     return strncmp(str, disabled_prefix, strlen(disabled_prefix)) == 0;
 }
 
-static inline bool test_is_disabled(struct test_list_node* entry) {
+static inline bool trusty_unittest_test_is_disabled(
+        struct test_list_node* entry) {
     return has_disabled_prefix(entry->suite) ||
            has_disabled_prefix(entry->name);
 }
 
-static bool test_suite_instantiated(const char* suite) {
+/**
+ * trusty_unittest_count_param_entries - Count parameter entries for a given
+ * test suite.
+ *
+ * @suite: Name of test suite associated with the parameters
+ *         suite is never going to be NULL (see invocation),
+ *         no need to guard against this case.
+ *
+ * For each parameter generator associated with the suite, accrue
+ * the number of parameter entries.
+ *
+ * Not meant for external use.
+ *
+ * Return: count of parameter entries
+ */
+static int trusty_unittest_count_param_entries(
+        struct test_list_node* test_case) {
+    int param_count = 0;
+    int i;
     struct test_param_list_node* param_entry;
+    bool has_param_gen = 0;
+    bool invalid_run = false;
+    /*
+     * for each parameter generator associated with the suite,
+     * accrue the number of parameter entries
+     */
     list_for_every_entry(&_test_param_list, param_entry,
                          struct test_param_list_node, node) {
-        if (!strcmp(suite, param_entry->suite)) {
-            return true;
+        if (!strcmp(test_case->suite, param_entry->suite)) {
+            i = 0;
+            has_param_gen = true;
+            /* For each parameter from the generator */
+            while (param_entry->param_gen.gen_param(param_entry->param_gen.priv,
+                                                    i)) {
+                i++;
+            }
+            if (!i) {
+                /*
+                 * No parameter entries: parameterized test case exist
+                 * but the test generator is empty
+                 */
+                trusty_unittest_print_status_name_param_duration(
+                        " FAILED ", param_entry->inst_name, test_case->suite,
+                        test_case->name,
+                        "NO PARAMS: Parameterized Test Case Generator without Params!",
+                        "");
+                invalid_run = true;
+            }
+            param_count += i;
+        }
+    }
+    /*
+     * No parameter generator: parameterized test case exist
+     * but the test suite is not associated with any param generator
+     */
+    if (!has_param_gen) {
+        trusty_unittest_print_status_name_param_duration(
+                " FAILED ", "NO PARAM GENERATOR", test_case->suite,
+                test_case->name,
+                "NO PARAMS: Parameterized Test Case without Param Generator!",
+                "");
+    }
+    return invalid_run ? 0 : param_count;
+}
+
+/**
+ * trusty_unittest_has_parameterized_test_case - test suite with parameterized
+ * test cases
+ *
+ * @suite: Name of test suite associated with the parameters.
+ *         suite is never going to be NULL (see invocation),
+ *         no need to guard against this case.
+ *
+ * Check whether a test suite has parameterized test cases.
+ * Not meant for external use.
+ *
+ * Return: True if parameterized test
+ */
+static bool trusty_unittest_has_parameterized_test_case(const char* suite) {
+    struct test_list_node* test_case;
+    list_for_every_entry(&_test_list, test_case, struct test_list_node, node) {
+        if (!strcmp(suite, test_case->suite)) {
+            if (test_case->needs_param) {
+                return true;
+            }
         }
     }
     return false;
 }
 
-static void run_test_suite(const char* suite, bool needs_param) {
+/**
+ * trusty_unittest_count_test_cases - Count test cases associated with test
+ * suite.
+ *
+ * @suite: Name of test suite.
+ *         When suite is NULL, all test cases from all test suites are counted.
+ *
+ * This test case count shall comply to the GTest parser requirements
+ * and thus shall not include disabled test cases.
+ * Not meant for external use.
+ *
+ * Return: count of test cases, -1 in case of detected test suite coding error
+ */
+static int trusty_unittest_count_test_cases(const char* suite) {
+    struct test_list_node* test_case;
+    struct test_param_list_node* param_entry;
+    bool test_code_error = false;
+    size_t test_case_count = 0;
+    bool disabled;
+    int param_entries = 0;
+    const char* param_entries_suite = NULL;
+    int current_test_case_count;
+    /* count all non parameterized and parameterized test cases */
+    list_for_every_entry(&_test_list, test_case, struct test_list_node, node) {
+        /* exclude tests not part of the requested suite */
+        if (suite && strcmp(suite, test_case->suite)) {
+            continue;
+        }
+        /* only count non-disabled test case as required by the GTest parser */
+        disabled = trusty_unittest_test_is_disabled(test_case);
+        if (test_case->needs_param) {
+            if (!param_entries_suite || !param_entries ||
+                strcmp(param_entries_suite, test_case->suite)) {
+                /* count param_entries for test_case->suite */
+                param_entries = trusty_unittest_count_param_entries(test_case);
+                param_entries_suite = test_case->suite;
+            }
+            if (!param_entries) {
+                /*
+                 * Test code error shall be fixed and will prevent test
+                 * execution however we don't bail right away with the goal of
+                 * logging all erroneous test cases.
+                 */
+                test_code_error = true;
+                continue;
+            }
+            current_test_case_count = param_entries;
+        } else {
+            current_test_case_count = 1;
+        }
+        if (!disabled) {
+            /* non parameterized (singular) test case */
+            test_case_count += current_test_case_count;
+        }
+    }
+    /*
+     * Search for a test coding issue where a test generator exists
+     * but is not backed by existing test case
+     */
+    list_for_every_entry(&_test_param_list, param_entry,
+                         struct test_param_list_node, node) {
+        if (!trusty_unittest_has_parameterized_test_case(param_entry->suite)) {
+            test_code_error = true;
+            trusty_unittest_print_status_name_param_duration(
+                    " FAILED ", param_entry->inst_name, param_entry->suite,
+                    "NO_TESTS", "Parameter Generator without tests!", "");
+        }
+    }
+    return test_code_error ? -1 : test_case_count;
+}
+
+/**
+ * trusty_unittest_run_test_suite - run each test case associated with test
+ * suite.
+ *
+ * @suite:      Name of test suite
+ *              when suite is NULL, all test cases
+ *              from all test suites are executed.
+ * @needs_param: when true run the parameterised test cases,
+ *               otherwise run the non-parameterised test cases
+ *
+ * Not meant for external use.
+ *
+ * Return: count of executed test cases
+ */
+static int trusty_unittest_run_test_suite(const char* suite, bool needs_param) {
     struct test_list_node* entry;
-    bool valid_suite = false;
+    int test_case_count = 0;
 
     list_for_every_entry(&_test_list, entry, struct test_list_node, node) {
         if ((!suite || !strcmp(suite, entry->suite)) &&
             (entry->needs_param == needs_param)) {
-            valid_suite = true;
-            if (test_is_disabled(entry)) {
+            if (trusty_unittest_test_is_disabled(entry)) {
                 trusty_unittest_print_status_name(entry->suite, entry->name,
                                                   "DISABLED");
                 _test_context.tests_disabled++;
             } else {
+                test_case_count++;
                 entry->func();
             }
         }
-        if (!needs_param && entry->needs_param &&
-            !test_suite_instantiated(entry->suite)) {
-            trusty_unittest_print_status_name(entry->suite, entry->name,
-                                              "NO PARAM");
-            _test_context.tests_failed++;
-        }
-    }
-    if (needs_param && !valid_suite) {
-        trusty_unittest_print_status_name(suite, "[NO TESTS]", " FAILED ");
-        _test_context.tests_failed++;
     }
+    return test_case_count;
 }
 
 /*
@@ -561,14 +766,26 @@ static inline bool RUN_ALL_SUITE_TESTS(const char* suite) {
     const void* test_param;
     int i;
     char param_str[64];
+    int actual_test_count = 0;
+    int expected_test_count = trusty_unittest_count_test_cases(suite);
+    if (expected_test_count == -1) {
+        trusty_unittest_printf("Test Coding Error - aborting execution.\n");
+        return false;
+    }
+
+    trusty_unittest_printf(
+            "[==========] Running %d tests from %s test suite%s.\n",
+            expected_test_count, suite ? suite : "all", suite ? "" : "s");
+
     _test_context.tests_total = 0;
     _test_context.tests_disabled = 0;
     _test_context.tests_failed = 0;
     _test_context.test_param = NULL;
+    _test_context.inst_name = NULL;
     _test_context.param_name = param_str;
-
+    _test_context.suite_duration_ms = 0;
     /* Run all the non-parameterized tests in the suite */
-    run_test_suite(suite, false);
+    actual_test_count = trusty_unittest_run_test_suite(suite, false);
 
     /* For each parameter generator associated with the suite */
     list_for_every_entry(&_test_param_list, param_entry,
@@ -588,14 +805,36 @@ static inline bool RUN_ALL_SUITE_TESTS(const char* suite) {
                     snprintf(param_str, sizeof(param_str), "%d", i);
                 }
                 /* Run all the parameterized tests in the suite */
-                run_test_suite(param_entry->suite, true);
+                actual_test_count += trusty_unittest_run_test_suite(
+                        param_entry->suite, true);
                 i++;
             }
         }
     }
+    if (actual_test_count != expected_test_count) {
+        trusty_unittest_printf("[ RUN      ] %s.test_count_match_check\n",
+                               suite ? suite : "all_suites");
+        trusty_unittest_printf(
+                "[----------] %d tests ran, but expected %d tests.\n",
+                actual_test_count, expected_test_count);
+        trusty_unittest_print_status_name(suite ? suite : "all_suites",
+                                          "test_count_match_check", " FAILED ");
+        ++_test_context.tests_failed;
+        ++_test_context.tests_total;
+    } else if (actual_test_count == 0 && _test_context.tests_disabled == 0) {
+        trusty_unittest_printf("[ RUN      ] %s.test_count_empty_check\n",
+                               suite ? suite : "all_suites");
+        trusty_unittest_printf("[----------] 0 tests but none disabled.\n");
+        trusty_unittest_print_status_name(suite ? suite : "all_suites",
+                                          "test_count_empty_check", " FAILED ");
+        ++_test_context.tests_failed;
+        ++_test_context.tests_total;
+    }
+
+    trusty_unittest_printf(
+            "[==========] %d tests ran (%" PRIu64 " ms total).\n",
+            _test_context.tests_total, _test_context.suite_duration_ms);
 
-    trusty_unittest_printf("[==========] %d tests ran.\n",
-                           _test_context.tests_total);
     if (_test_context.tests_total != _test_context.tests_failed) {
         trusty_unittest_printf(
                 "[  PASSED  ] %d tests.\n",
diff --git a/include/uapi/uapi/mm.h b/include/uapi/uapi/mm.h
index ad1499c..a8d2310 100644
--- a/include/uapi/uapi/mm.h
+++ b/include/uapi/uapi/mm.h
@@ -143,4 +143,15 @@ struct dma_pmem {
  */
 #define DMA_FLAG_ALLOW_PARTIAL (0x1 << 3)
 
+/*
+ * If DMA_FLAG_NO_PMEM is set, the caller of prepare_dma should not pass any
+ * dma_pmem structs and must provide a NULL pointer instead.  Memory mapping
+ * will not take place, but cache maintance operations appropriate for the DMA
+ * direction will be called.
+ *
+ * On success prepare_dma() will return 0.
+ *
+ */
+#define DMA_FLAG_NO_PMEM (0x1 << 4)
+
 #endif /* __UAPI_MM_H */
diff --git a/kerneltests-inc.mk b/kerneltests-inc.mk
index 8dd8b09..51b3e19 100644
--- a/kerneltests-inc.mk
+++ b/kerneltests-inc.mk
@@ -44,7 +44,6 @@ ifeq ($(LK_LIBC_IMPLEMENTATION),musl)
 MODULES += \
 	trusty/kernel/lib/libc-trusty/test \
 	trusty/kernel/lib/libcxx-trusty/test \
-	trusty/user/base/app/device_tree/tests/kernel \
 
 endif
 
diff --git a/lib/arm_ffa/arm_ffa.c b/lib/arm_ffa/arm_ffa.c
index 3f27126..b838423 100644
--- a/lib/arm_ffa/arm_ffa.c
+++ b/lib/arm_ffa/arm_ffa.c
@@ -45,6 +45,7 @@ static void* ffa_tx;
 static void* ffa_rx;
 static bool supports_ns_bit = false;
 static bool supports_rx_release = false;
+static bool console_log_is_unsupported;
 
 static mutex_t ffa_rxtx_buffer_lock = MUTEX_INITIAL_VALUE(ffa_rxtx_buffer_lock);
 
@@ -360,6 +361,127 @@ static status_t arm_ffa_call_rx_release(void) {
     }
 }
 
+#if WITH_SMP
+static status_t ffa_call_secondary_ep_register(void) {
+    struct smc_ret8 smc_ret;
+    paddr_t secondary_ep_paddr;
+    extern char _start[];
+
+    secondary_ep_paddr = vaddr_to_paddr(_start);
+
+    smc_ret = smc8(SMC_FC64_FFA_SECONDARY_EP_REGISTER, secondary_ep_paddr, 0, 0,
+                   0, 0, 0, 0);
+    switch ((uint32_t)smc_ret.r0) {
+    case SMC_FC_FFA_SUCCESS:
+    case SMC_FC64_FFA_SUCCESS:
+        return NO_ERROR;
+
+    case SMC_FC_FFA_ERROR:
+        switch ((int)smc_ret.r2) {
+        case FFA_ERROR_NOT_SUPPORTED:
+            return ERR_NOT_SUPPORTED;
+        case FFA_ERROR_INVALID_PARAMETERS:
+            return ERR_INVALID_ARGS;
+        default:
+            return ERR_NOT_VALID;
+        }
+
+    case SMC_UNKNOWN:
+        return ERR_NOT_SUPPORTED;
+
+    default:
+        return ERR_NOT_VALID;
+    }
+}
+#endif /* WITH_SMP */
+
+struct smc_ret8 arm_ffa_call_error(enum ffa_error err) {
+    long target = 0; /* Target must be zero (MBZ) at secure FF-A instances */
+    return smc8(SMC_FC_FFA_ERROR, target, (ulong)err, 0, 0, 0, 0, 0);
+}
+
+struct smc_ret8 arm_ffa_call_msg_wait(void) {
+    return smc8(SMC_FC_FFA_MSG_WAIT, 0, 0, 0, 0, 0, 0, 0);
+}
+
+struct smc_ret8 arm_ffa_msg_send_direct_resp(
+        const struct smc_ret8* direct_req_regs,
+        ulong a0,
+        ulong a1,
+        ulong a2,
+        ulong a3,
+        ulong a4) {
+    ulong fid;
+    uint32_t sender_receiver_id;
+    uint32_t flags;
+
+    DEBUG_ASSERT(direct_req_regs);
+    switch (direct_req_regs->r0) {
+    case SMC_FC_FFA_MSG_SEND_DIRECT_REQ:
+        fid = SMC_FC_FFA_MSG_SEND_DIRECT_RESP;
+        break;
+    case SMC_FC64_FFA_MSG_SEND_DIRECT_REQ:
+        fid = SMC_FC64_FFA_MSG_SEND_DIRECT_RESP;
+        break;
+    default:
+        dprintf(CRITICAL, "Invalid direct request function id %lx\n",
+                direct_req_regs->r0);
+        return arm_ffa_call_error(FFA_ERROR_INVALID_PARAMETERS);
+    }
+
+    /* Copy and flip the sender from the direct message request */
+    sender_receiver_id =
+            (direct_req_regs->r1 >> 16) | ((uint32_t)ffa_local_id << 16);
+    /* Copy the flags as well */
+    flags = direct_req_regs->r2;
+
+    return smc8(fid, sender_receiver_id, flags, a0, a1, a2, a3, a4);
+}
+
+ssize_t arm_ffa_console_log(const char* buf, size_t len) {
+    struct smc_ret8 smc_ret;
+
+    if (console_log_is_unsupported) {
+        return ERR_NOT_SUPPORTED;
+    }
+    if (!len) {
+        /* Nothing to print, just return */
+        return 0;
+    }
+    if (len != 1) {
+        /* TODO: support more than one character */
+        len = 1;
+    }
+
+    smc_ret = smc8(SMC_FC_FFA_CONSOLE_LOG, len, (ulong)buf[0], 0, 0, 0, 0, 0);
+    switch ((uint32_t)smc_ret.r0) {
+    case SMC_FC_FFA_SUCCESS:
+    case SMC_FC64_FFA_SUCCESS:
+        return len;
+
+    case SMC_FC_FFA_ERROR:
+        switch ((int32_t)smc_ret.r2) {
+        case FFA_ERROR_NOT_SUPPORTED:
+            console_log_is_unsupported = true;
+            return ERR_NOT_SUPPORTED;
+        case FFA_ERROR_INVALID_PARAMETERS:
+            return ERR_INVALID_ARGS;
+        case FFA_ERROR_RETRY:
+            /* FFA_ERROR_RETRY returns how many characters were printed */
+            return (uint32_t)smc_ret.r3;
+        default:
+            return ERR_NOT_VALID;
+        }
+
+    case SMC_UNKNOWN:
+        console_log_is_unsupported = true;
+        return ERR_NOT_SUPPORTED;
+
+    default:
+        return ERR_NOT_VALID;
+    }
+}
+
 static status_t arm_ffa_rx_release_is_implemented(bool* is_implemented) {
     bool is_implemented_val;
     status_t res = arm_ffa_call_features(SMC_FC_FFA_RX_RELEASE,
@@ -908,6 +1030,16 @@ static void arm_ffa_init(uint level) {
 
     if (res == NO_ERROR) {
         arm_ffa_init_is_success = true;
+
+#if WITH_SMP
+        res = ffa_call_secondary_ep_register();
+        if (res == ERR_NOT_SUPPORTED) {
+            LTRACEF("FFA_SECONDARY_EP_REGISTER is not supported\n");
+        } else if (res != NO_ERROR) {
+            TRACEF("Failed to register secondary core entry point (err=%d)\n",
+                   res);
+        }
+#endif
     } else {
         TRACEF("Failed to initialize FF-A (err=%d)\n", res);
     }
diff --git a/lib/arm_ffa/include/lib/arm_ffa/arm_ffa.h b/lib/arm_ffa/include/lib/arm_ffa/arm_ffa.h
index aaaeb1c..273d4ba 100644
--- a/lib/arm_ffa/include/lib/arm_ffa/arm_ffa.h
+++ b/lib/arm_ffa/include/lib/arm_ffa/arm_ffa.h
@@ -24,6 +24,8 @@
 #pragma once
 
 #include <arch/ops.h>
+#include <interface/arm_ffa/arm_ffa.h>
+#include <lib/smc/smc.h>
 #include <stdbool.h>
 
 /**
@@ -115,3 +117,50 @@ status_t arm_ffa_mem_retrieve_next_frag(
  * Return: 0 on success, LK error code on failure.
  */
 status_t arm_ffa_rx_release(void);
+
+/**
+ * arm_ffa_call_error() - Report an error.
+ *
+ * @err: FF-A error code from &enum ffa_error.
+ *
+ * Return: the values of the CPU registers on return to Trusty.
+ */
+struct smc_ret8 arm_ffa_call_error(enum ffa_error err);
+
+/**
+ * arm_ffa_call_msg_wait() - Invoke FFA_MSG_WAIT.
+ *
+ * Return: the values of the CPU registers on return to Trusty.
+ */
+struct smc_ret8 arm_ffa_call_msg_wait(void);
+
+/**
+ * arm_ffa_msg_send_direct_resp() - Send a direct message response.
+ *
+ * @direct_req_args: The registers passed to the correspoding direct request
+ *                   message. Must not be %NULL.
+ * @a0: The 1st argument returned as the response.
+ * @a1: The 2nd argument returned as the response.
+ * @a2: The 3rd argument returned as the response.
+ * @a3: The 4th argument returned as the response.
+ * @a4: The 5th argument returned as the response.
+ *
+ * Return: the values of the CPU registers on return to Trusty.
+ */
+struct smc_ret8 arm_ffa_msg_send_direct_resp(
+        const struct smc_ret8* direct_req_regs,
+        ulong a0,
+        ulong a1,
+        ulong a2,
+        ulong a3,
+        ulong a4);
+
+/**
+ * arm_ffa_console_log() - Output a buffer using %FFA_CONSOLE_LOG.
+ *
+ * @buf: The buffer to print.
+ * @len: The length of the buffer to print.
+ *
+ * Return: the number of characters successfully printed, or an error code.
+ */
+ssize_t arm_ffa_console_log(const char* buf, size_t len);
diff --git a/lib/dtb_service/dtb_service.cpp b/lib/dtb_service/dtb_service.cpp
index 637f30f..0e184b8 100644
--- a/lib/dtb_service/dtb_service.cpp
+++ b/lib/dtb_service/dtb_service.cpp
@@ -21,12 +21,17 @@
  * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  */
 
+/* Guards uses of trusty/kernel/lib/shared/binder_discover */
+#define ENABLE_KERNEL_BINDER (0)
+
 #include <err.h>
 #include <kernel/vm.h>
 #include <lib/dtb_service/dtb_service.h>
 #include <lib/ktipc/ktipc.h>
+#if ENABLE_KERNEL_BINDER
 #include <lib/shared/binder_discover/binder_discover.h>
 #include <lib/shared/device_tree/service/device_tree_service.h>
+#endif
 #include <lib/trusty/ipc.h>
 #include <lib/vmm_obj_service/vmm_obj_service.h>
 #include <libfdt.h>
@@ -149,6 +154,7 @@ int dtb_service_add(const void* dtb,
         return ERR_INVALID_ARGS;
     }
 
+#if ENABLE_KERNEL_BINDER
     auto dt = android::sp<com::android::trusty::device_tree::DeviceTree>::make(
             static_cast<const unsigned char*>(dtb), dtb_size);
     int err = binder_discover_add_service(dt_port, dt);
@@ -156,10 +162,13 @@ int dtb_service_add(const void* dtb,
         TRACEF("error adding service (%d)\n", err);
         return ERR_GENERIC;
     }
+#endif
 
     int rc = dtb_service_add_user(dtb, dtb_size, dtb_port, server);
     if (rc < 0) {
+#if ENABLE_KERNEL_BINDER
         binder_discover_remove_service(dt_port);
+#endif
         return rc;
     }
 
diff --git a/lib/dtb_service/rules.mk b/lib/dtb_service/rules.mk
index da0f677..0cf6fed 100644
--- a/lib/dtb_service/rules.mk
+++ b/lib/dtb_service/rules.mk
@@ -28,12 +28,14 @@ MODULE_SRCS += \
 
 MODULE_DEPS += \
 	external/dtc/libfdt \
-	trusty/kernel/lib/shared/binder_discover \
-	trusty/kernel/lib/shared/device_tree/service/kernel \
 	trusty/kernel/lib/trusty \
 	trusty/kernel/lib/ktipc \
 	trusty/kernel/lib/vmm_obj_service \
 
+	# TODO: disabled because linking fails with CFI disabled.
+	# trusty/kernel/lib/shared/binder_discover \
+	# trusty/kernel/lib/shared/device_tree/service/kernel \
+
 GLOBAL_INCLUDES += \
 	$(LOCAL_DIR)/include \
 
diff --git a/lib/metrics/metrics.c b/lib/metrics/metrics.c
index 098a24d..ee5f02f 100644
--- a/lib/metrics/metrics.c
+++ b/lib/metrics/metrics.c
@@ -155,7 +155,7 @@ static int send_req(struct handle* chan,
 
 static int report_crash(struct handle* chan,
                         struct trusty_app* app,
-                        uint32_t crash_reason) {
+                        const struct trusty_error_args* error_args) {
     int rc;
     struct metrics_req req = {};
     struct metrics_report_crash_req args = {};
@@ -166,7 +166,12 @@ static int report_crash(struct handle* chan,
     uuid_to_str(&app->props.uuid, args.app_id);
 
     req.cmd = METRICS_CMD_REPORT_CRASH;
-    args.crash_reason = crash_reason;
+    args.crash_reason = error_args->reason;
+    args.far = error_args->far;
+    memcpy(args.far_hash, error_args->far_hash, sizeof(args.far_hash));
+    args.elr = error_args->elr;
+    memcpy(args.elr_hash, error_args->elr_hash, sizeof(args.elr_hash));
+    args.is_hash = error_args->is_hash;
 
     struct iovec_kern iovs[] = {
             {
@@ -195,7 +200,7 @@ static int report_crash(struct handle* chan,
 
 static int report_exit(struct handle* chan,
                         struct trusty_app* app,
-                        uint32_t exit_code) {
+                        const struct trusty_error_args* error_args) {
     int rc;
     struct metrics_req req = {};
     struct metrics_report_exit_req args = {};
@@ -206,7 +211,7 @@ static int report_exit(struct handle* chan,
     uuid_to_str(&app->props.uuid, args.app_id);
 
     req.cmd = METRICS_CMD_REPORT_EXIT;
-    args.exit_code = exit_code;
+    args.exit_code = error_args->reason;
 
     struct iovec_kern iovs[] = {
             {
@@ -260,7 +265,7 @@ static int report_event_drop(struct handle* chan) {
     return NO_ERROR;
 }
 
-static int on_ta_crash(struct trusty_app* app, uint32_t reason, bool is_crash) {
+static int on_ta_crash(struct trusty_app* app, const struct trusty_error_args* error_args) {
     int rc;
 
     mutex_acquire(&ctx_lock);
@@ -277,12 +282,12 @@ static int on_ta_crash(struct trusty_app* app, uint32_t reason, bool is_crash) {
         goto out;
     }
 
-    if(is_crash) {
-        rc = report_crash(ctx.chan, app, reason);
+    if(error_args->is_crash) {
+        rc = report_crash(ctx.chan, app, error_args);
         ctx.chan_state = CHAN_STATE_WAITING_CRASH_RESP;
     }
     else {
-        rc = report_exit(ctx.chan, app, reason);
+        rc = report_exit(ctx.chan, app, error_args);
         ctx.chan_state = CHAN_STATE_WAITING_EXIT_RESP;
     }
     if (rc != NO_ERROR) {
diff --git a/lib/sm/include/lib/sm.h b/lib/sm/include/lib/sm.h
index d9f8dd4..ce4be93 100644
--- a/lib/sm/include/lib/sm.h
+++ b/lib/sm/include/lib/sm.h
@@ -90,7 +90,7 @@ long smc_get_smp_max_cpus(struct smc32_args* args);
 long smc_intc_get_next_irq(struct smc32_args* args);
 /* return 0 to enter ns-fiq handler, return non-0 to return */
 status_t sm_intc_fiq_enter(void);
-void sm_intc_enable_interrupts(void);
+enum handler_return sm_intc_enable_interrupts(void);
 
 /* Get the argument block passed in by the bootloader */
 status_t sm_get_boot_args(void** boot_argsp, size_t* args_sizep);
diff --git a/lib/sm/sm.c b/lib/sm/sm.c
index 1432d86..cec2df6 100644
--- a/lib/sm/sm.c
+++ b/lib/sm/sm.c
@@ -177,7 +177,16 @@ static long sm_queue_stdcall(struct smc32_args* args) {
 
     if (stdcallstate.event.signaled || stdcallstate.done) {
         if (args->smc_nr == SMC_SC_RESTART_LAST &&
-            stdcallstate.active_cpu == -1) {
+            stdcallstate.args.client_id != args->client_id) {
+            dprintf(CRITICAL,
+                    "%s: cpu %d, unexpected restart, "
+                    "client %" PRIx64 " != %" PRIx64 "\n",
+                    __func__, cpu, stdcallstate.args.client_id,
+                    args->client_id);
+            ret = SM_ERR_UNEXPECTED_RESTART;
+            goto err;
+        } else if (args->smc_nr == SMC_SC_RESTART_LAST &&
+                   stdcallstate.active_cpu == -1) {
             stdcallstate.restart_count++;
             LTRACEF_LEVEL(3, "cpu %d, restart std call, restart_count %d\n",
                           cpu, stdcallstate.restart_count);
@@ -234,7 +243,8 @@ static void sm_sched_nonsecure_fiq_loop(long ret, struct smc32_args* args) {
 }
 
 /* must be called with irqs disabled */
-static void sm_return_and_wait_for_next_stdcall(long ret, int cpu) {
+static enum handler_return sm_return_and_wait_for_next_stdcall(long ret,
+                                                               int cpu) {
     struct smc32_args args = SMC32_ARGS_INITIAL_VALUE(args);
 
     do {
@@ -254,7 +264,8 @@ static void sm_return_and_wait_for_next_stdcall(long ret, int cpu) {
             ret = sm_queue_stdcall(&args);
         }
     } while (ret);
-    sm_intc_enable_interrupts();
+
+    return sm_intc_enable_interrupts();
 }
 
 static void sm_irq_return_ns(void) {
@@ -337,6 +348,31 @@ err:
     return ret;
 }
 
+static uint enter_smcall_critical_section(void) {
+    /*
+     * Disable interrupts so stdcallstate.active_cpu does not
+     * change to or from this cpu after checking it in the critical
+     * section.
+     */
+    arch_disable_ints();
+
+    /* Switch to sm-stdcall if sm_queue_stdcall woke it up */
+    thread_yield();
+
+    return arch_curr_cpu_num();
+}
+
+static void exit_smcall_critical_section(long ret, uint cpu) {
+    enum handler_return resched;
+
+    resched = sm_return_and_wait_for_next_stdcall(ret, cpu);
+    if (resched == INT_RESCHEDULE)
+        thread_preempt();
+
+    /* Re-enable interrupts (needed for SMC_SC_NOP) */
+    arch_enable_ints();
+}
+
 static int sm_wait_for_smcall(void* arg) {
     int cpu;
     long ret = 0;
@@ -344,25 +380,14 @@ static int sm_wait_for_smcall(void* arg) {
     LTRACEF("wait for stdcalls, on cpu %d\n", arch_curr_cpu_num());
 
     while (true) {
-        /*
-         * Disable interrupts so stdcallstate.active_cpu does not
-         * change to or from this cpu after checking it below.
-         */
-        arch_disable_ints();
+        cpu = enter_smcall_critical_section();
 
-        /* Switch to sm-stdcall if sm_queue_stdcall woke it up */
-        thread_yield();
-
-        cpu = arch_curr_cpu_num();
         if (cpu == stdcallstate.active_cpu)
             ret = sm_get_stdcall_ret();
         else
             ret = SM_ERR_NOP_DONE;
 
-        sm_return_and_wait_for_next_stdcall(ret, cpu);
-
-        /* Re-enable interrupts (needed for SMC_SC_NOP) */
-        arch_enable_ints();
+        exit_smcall_critical_section(ret, cpu);
     }
 }
 
diff --git a/lib/smc/include/lib/smc/smc.h b/lib/smc/include/lib/smc/smc.h
index 9d990a2..44999e6 100644
--- a/lib/smc/include/lib/smc/smc.h
+++ b/lib/smc/include/lib/smc/smc.h
@@ -25,6 +25,9 @@
 
 #include <sys/types.h>
 
+/* Unknown SMC (defined by ARM DEN 0028A(0.9.0) */
+#define SMC_UNKNOWN 0xFFFFFFFFU
+
 struct smc_ret8 {
     ulong r0;
     ulong r1;
diff --git a/lib/trusty/include/lib/trusty/trusty_app.h b/lib/trusty/include/lib/trusty/trusty_app.h
index 6e20e49..c6571a9 100644
--- a/lib/trusty/include/lib/trusty/trusty_app.h
+++ b/lib/trusty/include/lib/trusty/trusty_app.h
@@ -35,6 +35,11 @@
 #include <stdbool.h>
 #include <sys/types.h>
 
+/**
+ * SHA512 output size
+ */
+#define HASH_SIZE_BYTES 64
+
 enum app_state {
     APP_NOT_RUNNING = 0,
     APP_STARTING,
@@ -206,7 +211,7 @@ status_t trusty_app_request_start_by_port(const char* port_path,
                                           const uuid_t* uuid);
 
 void trusty_app_exit(int status) __NO_RETURN;
-void trusty_app_crash(uint32_t) __NO_RETURN;
+void trusty_app_crash(uint32_t reason, uint64_t far, uint64_t elr) __NO_RETURN;
 status_t trusty_app_setup_mmio(struct trusty_app* trusty_app,
                                uint32_t mmio_id,
                                user_addr_t* uaddr_p,
@@ -215,11 +220,21 @@ void trusty_app_forall(void (*fn)(struct trusty_app* ta, void* data),
                        void* data);
 void trusty_thread_exit(int status);
 
+struct trusty_error_args {
+    uint32_t reason;
+    bool is_crash;
+    uint64_t far;
+    uint8_t far_hash[HASH_SIZE_BYTES];
+    uint64_t elr;
+    uint8_t elr_hash[HASH_SIZE_BYTES];
+    bool is_hash;
+};
+
 struct trusty_app_notifier {
     struct list_node node;
     status_t (*startup)(struct trusty_app* app);
     status_t (*shutdown)(struct trusty_app* app);
-    status_t (*crash)(struct trusty_app* app, uint32_t reason, bool is_crash);
+    status_t (*crash)(struct trusty_app* app, const struct trusty_error_args* error_args);
 };
 
 /*
diff --git a/lib/trusty/syscall.c b/lib/trusty/syscall.c
index 746abea..1f7a232 100644
--- a/lib/trusty/syscall.c
+++ b/lib/trusty/syscall.c
@@ -362,6 +362,9 @@ long sys_prepare_dma(user_addr_t uaddr,
     if (size == 0)
         return ERR_INVALID_ARGS;
 
+    if ((flags & DMA_FLAG_NO_PMEM) && pmem)
+        return ERR_INVALID_ARGS;
+
     struct trusty_app* trusty_app = current_trusty_app();
     struct vmm_obj_slice slice;
     vmm_obj_slice_init(&slice);
@@ -375,37 +378,42 @@ long sys_prepare_dma(user_addr_t uaddr,
         goto err;
     }
 
-    do {
-        paddr_t paddr;
-        size_t paddr_size;
-        ret = slice.obj->ops->get_page(slice.obj, slice.offset + mapped_size,
-                                       &paddr, &paddr_size);
-        if (ret != NO_ERROR)
-            goto err;
-
-        memset(&kpmem, 0, sizeof(kpmem));
-        kpmem.paddr = paddr;
-        kpmem.size = MIN(size - mapped_size, paddr_size);
-
-        /*
-         * Here, kpmem.size is either the remaining mapping size
-         * (size - mapping_size)
-         * or the distance to a page boundary that is not physically
-         * contiguous with the next page mapped in the given virtual
-         * address range.
-         * In either case it marks the end of the current kpmem record.
-         */
-
-        ret = copy_to_user(pmem, &kpmem, sizeof(struct dma_pmem));
-        if (ret != NO_ERROR)
-            goto err;
-
-        pmem += sizeof(struct dma_pmem);
-
-        mapped_size += kpmem.size;
-        entries++;
-
-    } while (mapped_size < size && (flags & DMA_FLAG_MULTI_PMEM));
+    /* Check if caller wants physical addresses returned */
+    if (flags & DMA_FLAG_NO_PMEM) {
+        mapped_size = size;
+    } else {
+        do {
+            paddr_t paddr;
+            size_t paddr_size;
+            ret = slice.obj->ops->get_page(
+                    slice.obj, slice.offset + mapped_size, &paddr, &paddr_size);
+            if (ret != NO_ERROR)
+                goto err;
+
+            memset(&kpmem, 0, sizeof(kpmem));
+            kpmem.paddr = paddr;
+            kpmem.size = MIN(size - mapped_size, paddr_size);
+
+            /*
+             * Here, kpmem.size is either the remaining mapping size
+             * (size - mapping_size)
+             * or the distance to a page boundary that is not physically
+             * contiguous with the next page mapped in the given virtual
+             * address range.
+             * In either case it marks the end of the current kpmem record.
+             */
+
+            ret = copy_to_user(pmem, &kpmem, sizeof(struct dma_pmem));
+            if (ret != NO_ERROR)
+                goto err;
+
+            pmem += sizeof(struct dma_pmem);
+
+            mapped_size += kpmem.size;
+            entries++;
+
+        } while (mapped_size < size && (flags & DMA_FLAG_MULTI_PMEM));
+    }
 
     if (flags & DMA_FLAG_FROM_DEVICE)
         arch_clean_invalidate_cache_range(vaddr, mapped_size);
diff --git a/lib/trusty/trusty_app.c b/lib/trusty/trusty_app.c
index 3b7c401..5b37f5b 100644
--- a/lib/trusty/trusty_app.c
+++ b/lib/trusty/trusty_app.c
@@ -1311,8 +1311,10 @@ static status_t alloc_address_map(struct trusty_app* trusty_app) {
         } else {
             has_guard_low++;
         }
-        if (elf_vaddr_mapped(trusty_app, prg_hdr->p_vaddr + prg_hdr->p_memsz,
-                             PAGE_SIZE)) {
+        if (elf_vaddr_mapped(
+                    trusty_app,
+                    prg_hdr->p_vaddr + round_up(prg_hdr->p_memsz, PAGE_SIZE),
+                    0)) {
             vmm_flags |= VMM_FLAG_NO_END_GUARD;
         } else {
             has_guard_high++;
@@ -1803,7 +1805,9 @@ err_aspace:
 
 static void __NO_RETURN trusty_app_exit_etc(int status,
                                             uint32_t crash_reason,
-                                            bool is_crash) {
+                                            bool is_crash,
+                                            uint64_t far,
+                                            uint64_t elr) {
     status_t ret;
     struct trusty_app* app;
     struct trusty_app_notifier* notifier;
@@ -1841,13 +1845,22 @@ static void __NO_RETURN trusty_app_exit_etc(int status,
     }
     /* Do not report normal exits with exit code 0 */
     if (is_crash || crash_reason != 0) {
+        /* Always request obfuscation; logic to conditionally send truth values later */
+        const struct trusty_error_args error_args = {
+            .reason = crash_reason,
+            .is_crash = is_crash,
+            .far = far,
+            .elr = elr,
+            .is_hash = true,
+        };
+
         list_for_every_entry(&app_notifier_list, notifier,
                              struct trusty_app_notifier, node) {
             if (!notifier->crash) {
                 continue;
             }
 
-            ret = notifier->crash(app, crash_reason, is_crash);
+            ret = notifier->crash(app, &error_args);
             if (ret != NO_ERROR) {
                 panic("crash notifier failed(%d) for app %u, %s\n", ret,
                       app->app_id, app->props.app_name);
@@ -1867,11 +1880,11 @@ static void __NO_RETURN trusty_app_exit_etc(int status,
 
 void trusty_app_exit(int status) {
     /* Report exits with non-zero status as crashes */
-    trusty_app_exit_etc(status, (uint32_t)status, false);
+    trusty_app_exit_etc(status, (uint32_t)status, false, 0, 0);
 }
 
-void trusty_app_crash(uint32_t reason) {
-    trusty_app_exit_etc(1 /*EXIT_FAILURE*/, reason, true);
+void trusty_app_crash(uint32_t reason, uint64_t far, uint64_t elr) {
+    trusty_app_exit_etc(1 /*EXIT_FAILURE*/, reason, true, far, elr);
 }
 
 static status_t app_mgr_handle_starting(struct trusty_app* app) {
diff --git a/lib/ubsan/exemptlist b/lib/ubsan/exemptlist
index 67eaaf0..2e18349 100644
--- a/lib/ubsan/exemptlist
+++ b/lib/ubsan/exemptlist
@@ -1,3 +1,4 @@
+#!special-case-list-v1
 #
 # Copyright (c) 2019, Google, Inc. All rights reserved
 #
diff --git a/lib/unittest/include/lib/unittest/unittest.h b/lib/unittest/include/lib/unittest/unittest.h
index ec9778f..7cb7f9a 100644
--- a/lib/unittest/include/lib/unittest/unittest.h
+++ b/lib/unittest/include/lib/unittest/unittest.h
@@ -55,14 +55,6 @@ int unittest_add(struct unittest* test);
 #include <lk/init.h>
 #include <platform.h>
 
-/*
- * This function returns a time in nanoseconds based on hardware counters
- * it is expected to:
- *  - Be non-wrapping or have very long (years) roll-over period
- *  - Have a resolution below 100ns
- */
-uint64_t get_current_time_ns(void);
-
 #define PORT_TEST_COMMON(suite_name, port_name_string, suite_name_string) \
     static bool run_##suite_name(struct unittest* test) {                 \
         return RUN_ALL_SUITE_TESTS(suite_name_string);                    \
diff --git a/make/host_lib.mk b/make/host_lib.mk
index 16e95bb..b367e42 100644
--- a/make/host_lib.mk
+++ b/make/host_lib.mk
@@ -61,8 +61,8 @@ HEADER_GUARD_HOST_LIB_$(BUILDDIR)_$(HOST_LIB_NAME)_$(HOST_LIB_VARIANT):=1
 GENERIC_CC := $(HOST_CC)
 GENERIC_SRCS := $(HOST_LIB_SRCS)
 GENERIC_OBJ_DIR := $(BUILDDIR)/host_libs/obj/$(HOST_LIB_NAME)$(HOST_LIB_VARIANT)
-GENERIC_FLAGS := -O1 -g -Wall -Wextra -Wno-unused-parameter -Werror $(HOST_SANITIZER_FLAGS) $(HOST_LIB_FLAGS) $(addprefix -I, $(HOST_INCLUDE_DIRS))
-GENERIC_CFLAGS := -std=c11 -D_POSIX_C_SOURCE=200809 -Wno-missing-field-initializers
+GENERIC_FLAGS := -O1 -g -Wall -Wextra -Wno-unused-parameter -Werror -Wno-missing-field-initializers $(HOST_SANITIZER_FLAGS) $(HOST_LIB_FLAGS) $(addprefix -I, $(HOST_INCLUDE_DIRS))
+GENERIC_CFLAGS := -std=c11 -D_POSIX_C_SOURCE=200809
 GENERIC_CPPFLAGS := -std=c++20 $(HOST_LIBCXX_CPPFLAGS)
 GENERIC_LOG_NAME := $(HOST_LIB_NAME)
 include make/generic_compile.mk
diff --git a/make/host_test.mk b/make/host_test.mk
index 69acfdb..9244786 100644
--- a/make/host_test.mk
+++ b/make/host_test.mk
@@ -85,8 +85,8 @@ $(foreach t,$(HOST_DEPS),\
 GENERIC_CC := $(HOST_CC)
 GENERIC_SRCS := $(HOST_SRCS)
 GENERIC_OBJ_DIR := $(HOST_TEST_BUILDDIR)/host_tests/obj/$(HOST_TEST)
-GENERIC_FLAGS := -O1 -g -Wall -Wextra -Wno-unused-parameter -Werror $(HOST_SANITIZER_FLAGS) $(HOST_FLAGS) $(addprefix -I, $(HOST_INCLUDE_DIRS))
-GENERIC_CFLAGS := -std=c11 -D_POSIX_C_SOURCE=200809 -Wno-missing-field-initializers
+GENERIC_FLAGS := -O1 -g -Wall -Wextra -Wno-unused-parameter -Werror -Wno-missing-field-initializers $(HOST_SANITIZER_FLAGS) $(HOST_FLAGS) $(addprefix -I, $(HOST_INCLUDE_DIRS))
+GENERIC_CFLAGS := -std=c11 -D_POSIX_C_SOURCE=200809
 GENERIC_CPPFLAGS := -std=c++20 -Wno-c99-designator $(HOST_LIBCXX_CPPFLAGS)
 GENERIC_LOG_NAME := $(HOST_TEST)
 include make/generic_compile.mk
diff --git a/make/host_tool.mk b/make/host_tool.mk
index 1cab70e..d13b97d 100644
--- a/make/host_tool.mk
+++ b/make/host_tool.mk
@@ -99,8 +99,8 @@ include $(addsuffix /rules.mk, $(HOST_DEPS))
 GENERIC_CC := $(HOST_CC)
 GENERIC_SRCS := $(HOST_SRCS)
 GENERIC_OBJ_DIR := $(BUILDDIR)/host_tools/obj/$(HOST_TOOL_NAME)
-GENERIC_FLAGS := -O1 -g -Wall -Wextra -Wno-unused-parameter -Werror $(HOST_SANITIZER_FLAGS) $(HOST_FLAGS) $(addprefix -I, $(HOST_INCLUDE_DIRS))
-GENERIC_CFLAGS := -std=c11 -D_POSIX_C_SOURCE=200809 -Wno-missing-field-initializers
+GENERIC_FLAGS := -O1 -g -Wall -Wextra -Wno-unused-parameter -Werror -Wno-missing-field-initializers $(HOST_SANITIZER_FLAGS) $(HOST_FLAGS) $(addprefix -I, $(HOST_INCLUDE_DIRS))
+GENERIC_CFLAGS := -std=c11 -D_POSIX_C_SOURCE=200809
 GENERIC_CPPFLAGS := -std=c++20 $(HOST_LIBCXX_CPPFLAGS)
 GENERIC_SRCDEPS := $(HOST_SRCDEPS)
 GENERIC_LOG_NAME := $(HOST_TOOL_NAME)
diff --git a/platform/generic-arm64/debug.c b/platform/generic-arm64/debug.c
index 4909fae..514791b 100644
--- a/platform/generic-arm64/debug.c
+++ b/platform/generic-arm64/debug.c
@@ -34,6 +34,10 @@
 #include "smc.h"
 #endif
 
+#if GENERIC_ARM64_DEBUG_FFA
+#include <lib/arm_ffa/arm_ffa.h>
+#endif
+
 #if GENERIC_ARM64_DEBUG_UART
 enum uart_type {
     UART_NONE,
@@ -95,6 +99,8 @@ void generic_arm64_setup_uart(void* fdt) {
 void platform_dputc(char c) {
 #if GENERIC_ARM64_DEBUG_SMC_DEBUG_PUTC
     generic_arm64_smc(SMC_FC_DEBUG_PUTC, (unsigned long)c, 0, 0);
+#elif GENERIC_ARM64_DEBUG_FFA
+    arm_ffa_console_log(&c, 1);
 #elif GENERIC_ARM64_DEBUG_UART
     if (!uart_base) {
         return;
diff --git a/platform/generic-arm64/platform.c b/platform/generic-arm64/platform.c
index 26cdb03..bff837a 100644
--- a/platform/generic-arm64/platform.c
+++ b/platform/generic-arm64/platform.c
@@ -22,8 +22,8 @@
  */
 
 #include <debug.h>
-#include <dev/interrupt/arm_gic.h>
 #include <dev/timer/arm_generic.h>
+#include <err.h>
 #include <inttypes.h>
 #include <kernel/vm.h>
 #include <lib/device_tree/libfdt_helpers.h>
@@ -31,6 +31,7 @@
 #include <platform/gic.h>
 #include <string.h>
 #include <sys/types.h>
+#include <vsock/vsock.h>
 
 #include "debug.h"
 
@@ -38,6 +39,9 @@
 #include "smc.h"
 #endif
 
+#ifdef GIC_VERSION
+#include <dev/interrupt/arm_gic.h>
+
 #define ARM_GENERIC_TIMER_INT_CNTV 27
 #define ARM_GENERIC_TIMER_INT_CNTPS 29
 #define ARM_GENERIC_TIMER_INT_CNTP 30
@@ -61,6 +65,12 @@
 #define GICR_SIZE (0x40000 * SMP_MAX_CPUS)
 #endif
 #endif
+#elif HAFNIUM
+#include <hf/types.h>
+#define ARM_GENERIC_TIMER_INT HF_VIRTUAL_TIMER_INTID
+#else
+#error "Unknown interrupt library"
+#endif
 
 extern ulong lk_boot_args[4];
 
@@ -146,7 +156,27 @@ static paddr_t generic_arm64_get_reg_base(int reg) {
 
 #endif
 
+int static pci_init_fdt(const void* fdt) {
+    int fdt_pci_offset =
+            fdt_node_offset_by_compatible(fdt, 0, "pci-host-cam-generic");
+    if (fdt_pci_offset < 0) {
+        dprintf(CRITICAL, "failed to find pci device tree node\n");
+        return ERR_NOT_FOUND;
+    }
+
+    paddr_t pci_paddr;
+    size_t pci_size;
+    int ret = fdt_helper_get_reg(fdt, fdt_pci_offset, 0, &pci_paddr, &pci_size);
+    if (ret) {
+        dprintf(CRITICAL, "failed to find get reg, err %d\n", ret);
+        return ERR_NOT_VALID;
+    }
+
+    return pci_init_mmio(pci_paddr, pci_size, 1 << 11);
+}
+
 static void platform_after_vm_init(uint level) {
+#ifdef GIC_VERSION
 #if ARM64_BOOT_PROTOCOL_X0_MEMSIZE || ARCH_ARM
     paddr_t gicc = generic_arm64_get_reg_base(SMC_GET_GIC_BASE_GICC);
     paddr_t gicd = generic_arm64_get_reg_base(SMC_GET_GIC_BASE_GICD);
@@ -172,6 +202,7 @@ static void platform_after_vm_init(uint level) {
     }
     fdt_size = fdt_totalsize(fdt);
     if (fdt_size > PAGE_SIZE) {
+        fdt_size = page_align(fdt_size);
         dprintf(INFO, "remapping device tree with size 0x%zx\n", fdt_size);
         vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)fdt);
         ret = vmm_alloc_physical(
@@ -229,9 +260,14 @@ static void platform_after_vm_init(uint level) {
             .gicr_size = GICR_SIZE,
     };
     arm_gic_init_map(&init_info);
+#endif /* GIC_VERSION */
 
     /* initialize the timer block */
     arm_generic_timer_init(ARM_GENERIC_TIMER_INT, 0);
+
+#if ARM64_BOOT_PROTOCOL_X0_DTB
+    pci_init_fdt(fdt); /* ignore pci init errors */
+#endif
 }
 
 LK_INIT_HOOK(platform_after_vm, platform_after_vm_init, LK_INIT_LEVEL_VM + 1);
diff --git a/platform/generic-arm64/rules.mk b/platform/generic-arm64/rules.mk
index cfe2c40..6c25bd8 100644
--- a/platform/generic-arm64/rules.mk
+++ b/platform/generic-arm64/rules.mk
@@ -33,9 +33,11 @@ endif
 ARM_CPU := armv8-a
 WITH_SMP := 1
 
+ifeq (false,$(call TOBOOL,$(HAFNIUM)))
 ifneq (2,$(GIC_VERSION))
 ARM_MERGE_FIQ_IRQ := true
 endif
+endif
 
 MEMBASE ?= 0
 MEMSIZE ?= 1
@@ -43,8 +45,13 @@ MEMSIZE ?= 1
 GLOBAL_INCLUDES += \
 	$(LOCAL_DIR)/include
 
-MODULE_DEFINES += \
-	GIC_VERSION=$(GIC_VERSION) \
+ifeq (true,$(call TOBOOL,$(HAFNIUM)))
+MODULE_DEFINES += HAFNIUM=1
+MODULE_DEPS += dev/interrupt/hafnium
+else
+MODULE_DEFINES += GIC_VERSION=$(GIC_VERSION)
+MODULE_DEPS += dev/interrupt/arm_gic
+endif
 
 GENERIC_ARM64_DEBUG ?= SMC_DEBUG_PUTC
 GLOBAL_DEFINES += GENERIC_ARM64_DEBUG_$(GENERIC_ARM64_DEBUG)=1
@@ -60,8 +67,8 @@ MODULE_INCLUDES += \
 	$(TRUSTY_TOP)/trusty/kernel/lib/sm/include \
 
 MODULE_DEPS += \
-	dev/interrupt/arm_gic \
-	dev/timer/arm_generic
+	dev/timer/arm_generic \
+	dev/virtio/vsock-rust \
 
 GLOBAL_DEFINES += \
 	MEMBASE=$(MEMBASE) \
@@ -86,4 +93,8 @@ MODULE_DEPS += \
 	trusty/kernel/lib/dtb_service \
 	trusty/kernel/lib/ktipc \
 
+ifeq ($(GENERIC_ARM64_DEBUG),FFA)
+MODULE_DEPS += trusty/kernel/lib/arm_ffa
+endif
+
 include make/module.mk
diff --git a/platform/generic-x86_64/rust/rules.mk b/platform/generic-x86_64/rust/rules.mk
index 40c05fd..2fcaf82 100644
--- a/platform/generic-x86_64/rust/rules.mk
+++ b/platform/generic-x86_64/rust/rules.mk
@@ -8,8 +8,8 @@ MODULE_SRCS += \
 	$(LOCAL_DIR)/src/lib.rs \
 
 MODULE_LIBRARY_DEPS += \
-	external/rust/crates/acpi \
-	external/rust/crates/log \
+	$(call FIND_CRATE,acpi) \
+	$(call FIND_CRATE,log) \
 	dev/virtio/vsock-rust \
 
 include make/library.mk
```

