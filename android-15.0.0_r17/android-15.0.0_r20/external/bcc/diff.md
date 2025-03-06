```diff
diff --git a/libbpf-tools/Android.bp b/libbpf-tools/Android.bp
index a7b02905..9d5453d5 100644
--- a/libbpf-tools/Android.bp
+++ b/libbpf-tools/Android.bp
@@ -27,6 +27,10 @@ package {
 cc_defaults {
     name: "bcc_bpf_defaults",
     compile_multilib: "first",
+
+    // Pinned to pre-C23 because of bool/false/true #defines in "vmlinux.h".
+    c_std: "gnu17",
+
     cflags: [
         "-fno-data-sections",
         "-fno-function-sections",
@@ -126,7 +130,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "bindsnoop.skel.h",
     srcs: [":bindsnoop.bpf.o"],
     out: ["bindsnoop.skel.h"],
@@ -146,7 +150,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "cpudist.skel.h",
     srcs: [":cpudist.bpf.o"],
     out: ["cpudist.skel.h"],
@@ -166,7 +170,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "cpufreq.skel.h",
     srcs: [":cpufreq.bpf.o"],
     out: ["cpufreq.skel.h"],
@@ -186,7 +190,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "drsnoop.skel.h",
     srcs: [":drsnoop.bpf.o"],
     out: ["drsnoop.skel.h"],
@@ -206,7 +210,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "filelife.skel.h",
     srcs: [":filelife.bpf.o"],
     out: ["filelife.skel.h"],
@@ -226,7 +230,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "filetop.skel.h",
     srcs: [":filetop.bpf.o"],
     out: ["filetop.skel.h"],
@@ -246,7 +250,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "fsdist.skel.h",
     srcs: [":fsdist.bpf.o"],
     out: ["fsdist.skel.h"],
@@ -266,7 +270,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "fsslower.skel.h",
     srcs: [":fsslower.bpf.o"],
     out: ["fsslower.skel.h"],
@@ -286,7 +290,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "funclatency.skel.h",
     srcs: [":funclatency.bpf.o"],
     out: ["funclatency.skel.h"],
@@ -309,7 +313,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "gethostlatency.skel.h",
     srcs: [":gethostlatency.bpf.o"],
     out: ["gethostlatency.skel.h"],
@@ -332,7 +336,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "ksnoop.skel.h",
     srcs: [":ksnoop.bpf.o"],
     out: ["ksnoop.skel.h"],
@@ -352,7 +356,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "llcstat.skel.h",
     srcs: [":llcstat.bpf.o"],
     out: ["llcstat.skel.h"],
@@ -372,7 +376,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "offcputime.skel.h",
     srcs: [":offcputime.bpf.o"],
     out: ["offcputime.skel.h"],
@@ -395,7 +399,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "oomkill.skel.h",
     srcs: [":oomkill.bpf.o"],
     out: ["oomkill.skel.h"],
@@ -418,7 +422,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "runqlat.skel.h",
     srcs: [":runqlat.bpf.o"],
     out: ["runqlat.skel.h"],
@@ -438,7 +442,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "runqlen.skel.h",
     srcs: [":runqlen.bpf.o"],
     out: ["runqlen.skel.h"],
@@ -458,7 +462,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "runqslower.skel.h",
     srcs: [":runqslower.bpf.o"],
     out: ["runqslower.skel.h"],
@@ -478,7 +482,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "softirqs.skel.h",
     srcs: [":softirqs.bpf.o"],
     out: ["softirqs.skel.h"],
@@ -498,7 +502,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "solisten.skel.h",
     srcs: [":solisten.bpf.o"],
     out: ["solisten.skel.h"],
@@ -521,7 +525,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "tcpconnect.skel.h",
     srcs: [":tcpconnect.bpf.o"],
     out: ["tcpconnect.skel.h"],
@@ -545,7 +549,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "tcprtt.skel.h",
     srcs: [":tcprtt.bpf.o"],
     out: ["tcprtt.skel.h"],
@@ -565,7 +569,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "vfsstat.skel.h",
     srcs: [":vfsstat.bpf.o"],
     out: ["vfsstat.skel.h"],
@@ -585,7 +589,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "biolatency.skel.h",
     srcs: [":biolatency.bpf.o"],
     out: ["biolatency.skel.h"],
@@ -605,7 +609,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "biostacks.skel.h",
     srcs: [":biostacks.bpf.o"],
     out: ["biostacks.skel.h"],
@@ -625,7 +629,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "biosnoop.skel.h",
     srcs: [":biosnoop.bpf.o"],
     out: ["biosnoop.skel.h"],
@@ -656,7 +660,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "exitsnoop.skel.h",
     srcs: [":exitsnoop.bpf.o"],
     out: ["exitsnoop.skel.h"],
@@ -676,7 +680,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "biopattern.skel.h",
     srcs: [":biopattern.bpf.o"],
     out: ["biopattern.skel.h"],
@@ -696,7 +700,7 @@ cc_object {
     defaults: ["bcc_bpf_defaults"],
 }
 
-genrule {
+cc_genrule {
     name: "bitesize.skel.h",
     srcs: [":bitesize.bpf.o"],
     out: ["bitesize.skel.h"],
```

