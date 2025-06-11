```diff
diff --git a/Android.bp b/Android.bp
index 14a195b..fd5b5cf 100644
--- a/Android.bp
+++ b/Android.bp
@@ -43,20 +43,40 @@ cc_defaults {
     cflags: [
         "-Wall",
         "-Werror",
+        "-Werror=conditional-uninitialized",
+        "-Werror=implicit-fallthrough",
+        "-Werror=sometimes-uninitialized",
         "-Wextra",
         "-Wnullable-to-nonnull-conversion",
+        "-Wshadow",
+        "-Wsign-compare",
+        "-Wtautological-unsigned-zero-compare",
         "-Wthread-safety",
+        "-Wuninitialized",
         "-Wunused-parameter",
     ],
     tidy: true,
     tidy_checks: [
         "android-*",
+        "bugprone-*",
         "cert-*",
         "-cert-err34-c",
         "clang-analyzer-security*",
         // Many calls to snprintf/sscanf/memset/memcpy in libbpf.c have the following warning.
         "-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling",
+        "google-*",
         // Disabling due to many unavoidable warnings from POSIX API usage.
         "-google-runtime-int",
+        "misc-*",
+        "performance-*",
+    ],
+    tidy_checks_as_errors: [
+        "android-*",
+        "bugprone-*",
+        "cert-*",
+        "clang-analyzer-security*",
+        "google-*",
+        "misc-*",
+        "performance-*",
     ],
 }
diff --git a/OWNERS_bpf b/OWNERS_bpf
index 6a4cc76..d54c798 100644
--- a/OWNERS_bpf
+++ b/OWNERS_bpf
@@ -1,5 +1,6 @@
-lorenzo@google.com
-maze@google.com
 nkapron@google.com
-smoreland@google.com
-sspatil@google.com
+
+lorenzo@google.com #{LAST_RESORT_SUGGESTION}
+maze@google.com #{LAST_RESORT_SUGGESTION}
+smoreland@google.com #{LAST_RESORT_SUGGESTION}
+sspatil@google.com #{LAST_RESORT_SUGGESTION}
\ No newline at end of file
diff --git a/loader/Loader.cpp b/loader/Loader.cpp
index 09e2e17..940ce19 100644
--- a/loader/Loader.cpp
+++ b/loader/Loader.cpp
@@ -431,9 +431,9 @@ static int readCodeSections(ifstream& elfFile, vector<codeSection>& cs,
         vector<string> csSymNames;
         ret = getSectionSymNames(elfFile, oldName, csSymNames, STT_FUNC);
         if (ret || !csSymNames.size()) return ret;
-        for (size_t i = 0; i < progDefNames.size(); ++i) {
-            if (!progDefNames[i].compare(csSymNames[0] + "_def")) {
-                cs_temp.prog_def = pd[i];
+        for (size_t j = 0; j < progDefNames.size(); ++j) {
+            if (!progDefNames[j].compare(csSymNames[0] + "_def")) {
+                cs_temp.prog_def = pd[j];
                 break;
             }
         }
@@ -882,10 +882,6 @@ constexpr bpf_prog_type kMemEventsAllowedProgTypes[] = {
         BPF_PROG_TYPE_SOCKET_FILTER,
 };
 
-constexpr bpf_prog_type kUprobestatsAllowedProgTypes[] = {
-        BPF_PROG_TYPE_KPROBE,
-};
-
 // see b/162057235. For arbitrary program types, the concern is that due to the lack of
 // SELinux access controls over BPF program attachpoints, we have no way to control the
 // attachment of programs to shared resources (or to detect when a shared resource
@@ -909,13 +905,6 @@ const Location locations[] = {
                 .allowedProgTypes = kMemEventsAllowedProgTypes,
                 .allowedProgTypesLength = arraysize(kMemEventsAllowedProgTypes),
         },
-        // uprobestats
-        {
-                .dir = "/system/etc/bpf/uprobestats/",
-                .prefix = "uprobestats/",
-                .allowedProgTypes = kUprobestatsAllowedProgTypes,
-                .allowedProgTypesLength = arraysize(kUprobestatsAllowedProgTypes),
-        },
         // Vendor operating system
         {
                 .dir = "/vendor/etc/bpf/",
```

