```diff
diff --git a/Android.bp b/Android.bp
index 426ce24..8d58242 100644
--- a/Android.bp
+++ b/Android.bp
@@ -27,15 +27,6 @@ license {
     license_text: ["LICENSE"],
 }
 
-bpf {
-    name: "timeInState.o",
-    srcs: ["timeInState.c"],
-    include_dirs: [
-        "system/bpf/progs/include",
-        "system/bpf/include/defs",
-    ],
-}
-
 libbpf_prog {
     name: "timeInState.bpf",
     srcs: ["timeInState.c"],
@@ -54,3 +45,12 @@ bpf {
         "system/bpf/include/defs",
     ],
 }
+
+libbpf_prog {
+    name: "fuseMedia.bpf",
+    srcs: ["fuseMedia.c"],
+    header_libs: [
+        "android_bpf_defs",
+        "libfuse_headers",
+    ],
+}
diff --git a/test/Android.bp b/test/Android.bp
deleted file mode 100644
index a524d5e..0000000
--- a/test/Android.bp
+++ /dev/null
@@ -1,24 +0,0 @@
-//
-// Copyright (C) 2018 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-//
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-bpf {
-    name: "bpfLoadTpProg.o",
-    srcs: ["bpfLoadTpProg.c"],
-}
diff --git a/test/bpfLoadTpProg.c b/test/bpfLoadTpProg.c
deleted file mode 100644
index 7462552..0000000
--- a/test/bpfLoadTpProg.c
+++ /dev/null
@@ -1,63 +0,0 @@
-/*
- * Copyright (C) 2018 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#include <linux/bpf.h>
-#include <stdbool.h>
-#include <stdint.h>
-#include <bpf_helpers.h>
-
-/* Assume max of 1024 CPUs */
-DEFINE_BPF_MAP(cpu_pid_map, ARRAY, int, uint32_t, 1024)
-
-struct switch_args {
-    unsigned long long ignore;
-    char prev_comm[16];
-    int prev_pid;
-    int prev_prio;
-    long long prev_state;
-    char next_comm[16];
-    int next_pid;
-    int next_prio;
-};
-
-DEFINE_BPF_PROG("tracepoint/sched/sched_switch", AID_ROOT, AID_ROOT, tp_sched_switch)
-(struct switch_args* args) {
-    int key;
-    uint32_t val;
-
-    key = bpf_get_smp_processor_id();
-    val = args->next_pid;
-
-    bpf_cpu_pid_map_update_elem(&key, &val, BPF_ANY);
-    return 0;
-}
-
-
-struct wakeup_args {
-    unsigned long long ignore;
-    char comm[16];
-    int pid;
-    int prio;
-    int success;
-    int target_cpu;
-};
-
-DEFINE_BPF_PROG_KVER("tracepoint/sched/sched_wakeup", AID_ROOT, AID_ROOT, tp_sched_wakeup, KVER_INF)
-(struct wakeup_args* __unused args) {
-    return 0;
-}
-
-LICENSE("GPL");
```

