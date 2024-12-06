```diff
diff --git a/Android.bp b/Android.bp
index 56fb00e..5244bee 100644
--- a/Android.bp
+++ b/Android.bp
@@ -55,7 +55,7 @@ genrule {
     ],
 }
 
-cc_library_static {
+cc_library {
     name: "libbpf",
     defaults: ["elfutils_transitive_defaults"],
     host_supported: true,
@@ -88,6 +88,8 @@ cc_library_static {
         "//external/bcc/libbpf-tools",
         "//external/dwarves",
         "//external/stg",
+        "//hardware/interfaces/health/utils/libhealthloop", // For use in tests only.
+        "//test/sts/tests/hostside/securityPatch/CVE-2023-28147", // For use in tests only.
     ],
     target: {
         host: {
diff --git a/android/android.h b/android/android.h
index ab0a3db..c7845ce 100644
--- a/android/android.h
+++ b/android/android.h
@@ -1,6 +1,3 @@
 #pragma once
 
-#define __user
-#define __force
-
 typedef unsigned __poll_t;
diff --git a/android/linux/perf_event.h b/android/linux/perf_event.h
deleted file mode 120000
index 2747eee..0000000
--- a/android/linux/perf_event.h
+++ /dev/null
@@ -1 +0,0 @@
-../../../../bionic/libc/kernel/uapi/linux/perf_event.h
\ No newline at end of file
diff --git a/android/linux/pkt_cls.h b/android/linux/pkt_cls.h
deleted file mode 120000
index 91cd90f..0000000
--- a/android/linux/pkt_cls.h
+++ /dev/null
@@ -1 +0,0 @@
-../../../../bionic/libc/kernel/uapi/linux/pkt_cls.h
\ No newline at end of file
diff --git a/android/linux/pkt_sched.h b/android/linux/pkt_sched.h
deleted file mode 120000
index cb366ee..0000000
--- a/android/linux/pkt_sched.h
+++ /dev/null
@@ -1 +0,0 @@
-../../../../bionic/libc/kernel/uapi/linux/pkt_sched.h
\ No newline at end of file
```

