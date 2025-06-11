```diff
diff --git a/.github/workflows/toybox.yml b/.github/workflows/toybox.yml
index a2f06219..2eb12efb 100644
--- a/.github/workflows/toybox.yml
+++ b/.github/workflows/toybox.yml
@@ -7,8 +7,8 @@ on:
     branches: [ master ]
 
 jobs:
-  MacOS-12:
-    runs-on: macos-12
+  MacOS-13:
+    runs-on: macos-13
 
     steps:
     - uses: actions/checkout@v2
diff --git a/Android.bp b/Android.bp
index 9f6ac1c9..70e9c99c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -215,6 +215,7 @@ device_srcs = [
     "toys/other/vmstat.c",
     "toys/other/watch.c",
     "toys/pending/brctl.c",
+    "toys/pending/dhcp.c",
     "toys/pending/getfattr.c",
     "toys/pending/lsof.c",
     "toys/pending/modprobe.c",
diff --git a/METADATA b/METADATA
index 9dc2b516..9b1463aa 100644
--- a/METADATA
+++ b/METADATA
@@ -7,14 +7,14 @@ description: "Toybox: all-in-one Linux command line."
 third_party {
   license_type: UNENCUMBERED
   last_upgrade_date {
-    year: 2024
-    month: 12
-    day: 4
+    year: 2025
+    month: 3
+    day: 10
   }
   homepage: "https://landley.net/toybox/"
   identifier {
     type: "Git"
     value: "https://github.com/landley/toybox"
-    version: "46e22bce880f004b227fd7e674a10253dc097365"
+    version: "2cc5e25fb107fe0ff77c95a983474497b76ac9f8"
   }
 }
diff --git a/OWNERS b/OWNERS
index 7529cb92..ed7755d6 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
-include platform/system/core:/janitors/OWNERS
+enh@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/android/device/generated/config.h b/android/device/generated/config.h
index b2d73a20..04ee6d94 100644
--- a/android/device/generated/config.h
+++ b/android/device/generated/config.h
@@ -138,8 +138,8 @@
 #define USE_DHCP6(...)
 #define CFG_DHCPD 0
 #define USE_DHCPD(...)
-#define CFG_DHCP 0
-#define USE_DHCP(...)
+#define CFG_DHCP 1
+#define USE_DHCP(...) __VA_ARGS__
 #define CFG_DIFF 1
 #define USE_DIFF(...) __VA_ARGS__
 #define CFG_DIRNAME 1
@@ -316,8 +316,6 @@
 #define USE_KILL(...) __VA_ARGS__
 #define CFG_KLOGD 0
 #define USE_KLOGD(...)
-#define CFG_KLOGD_SOURCE_RING_BUFFER 0
-#define USE_KLOGD_SOURCE_RING_BUFFER(...)
 #define CFG_LAST 0
 #define USE_LAST(...)
 #define CFG_LINK 0
@@ -374,16 +372,6 @@
 #define USE_MKDIR(...) __VA_ARGS__
 #define CFG_MKDIR_Z 1
 #define USE_MKDIR_Z(...) __VA_ARGS__
-#define CFG_MKE2FS_EXTENDED 0
-#define USE_MKE2FS_EXTENDED(...)
-#define CFG_MKE2FS_GEN 0
-#define USE_MKE2FS_GEN(...)
-#define CFG_MKE2FS 0
-#define USE_MKE2FS(...)
-#define CFG_MKE2FS_JOURNAL 0
-#define USE_MKE2FS_JOURNAL(...)
-#define CFG_MKE2FS_LABEL 0
-#define USE_MKE2FS_LABEL(...)
 #define CFG_MKFIFO 1
 #define USE_MKFIFO(...) __VA_ARGS__
 #define CFG_MKFIFO_Z 1
@@ -422,6 +410,8 @@
 #define USE_NICE(...) __VA_ARGS__
 #define CFG_NL 1
 #define USE_NL(...) __VA_ARGS__
+#define CFG_NOLOGIN 0
+#define USE_NOLOGIN(...)
 #define CFG_NOHUP 1
 #define USE_NOHUP(...) __VA_ARGS__
 #define CFG_NPROC 1
diff --git a/android/device/generated/flags.h b/android/device/generated/flags.h
index 32af7294..e3de2a35 100644
--- a/android/device/generated/flags.h
+++ b/android/device/generated/flags.h
@@ -683,7 +683,7 @@
 #undef FLAG_H
 #endif
 
-// dhcp   V:H:F:x*r:O*A#<0=20T#<0=3t#<0=3s:p:i:SBRCaovqnbf
+// dhcp V:H:F:x*r:O*A#<0=20T#<0=3t#<0=3s:p:i:SBRCaovqnbf V:H:F:x*r:O*A#<0=20T#<0=3t#<0=3s:p:i:SBRCaovqnbf
 #undef OPTSTR_dhcp
 #define OPTSTR_dhcp "V:H:F:x*r:O*A#<0=20T#<0=3t#<0=3s:p:i:SBRCaovqnbf"
 #ifdef CLEANUP_dhcp
@@ -2325,6 +2325,14 @@
 #undef FOR_nohup
 #endif
 
+// nologin    
+#undef OPTSTR_nologin
+#define OPTSTR_nologin 0
+#ifdef CLEANUP_nologin
+#undef CLEANUP_nologin
+#undef FOR_nologin
+#endif
+
 // nproc (all) (all)
 #undef OPTSTR_nproc
 #define OPTSTR_nproc "(all)"
@@ -2446,9 +2454,9 @@
 #undef FLAG_no_backup_if_mismatch
 #endif
 
-// pgrep ?cld:u*U*t*s*P*g*G*fnovxL:[-no] ?cld:u*U*t*s*P*g*G*fnovxL:[-no]
+// pgrep acld:u*U*t*s*P*g*G*fnovxL:[-no] acld:u*U*t*s*P*g*G*fnovxL:[-no]
 #undef OPTSTR_pgrep
-#define OPTSTR_pgrep "?cld:u*U*t*s*P*g*G*fnovxL:[-no]"
+#define OPTSTR_pgrep "acld:u*U*t*s*P*g*G*fnovxL:[-no]"
 #ifdef CLEANUP_pgrep
 #undef CLEANUP_pgrep
 #undef FOR_pgrep
@@ -2468,6 +2476,7 @@
 #undef FLAG_d
 #undef FLAG_l
 #undef FLAG_c
+#undef FLAG_a
 #endif
 
 // pidof so:x so:x
@@ -3239,9 +3248,9 @@
 #undef FLAG_f
 #endif
 
-// tar &(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa] &(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]
+// tar &(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*Z(zstd)o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa] &(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*Z(zstd)o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]
 #undef OPTSTR_tar
-#define OPTSTR_tar "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]"
+#define OPTSTR_tar "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*Z(zstd)o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]"
 #ifdef CLEANUP_tar
 #undef CLEANUP_tar
 #undef FOR_tar
@@ -3267,6 +3276,7 @@
 #undef FLAG_k
 #undef FLAG_p
 #undef FLAG_o
+#undef FLAG_Z
 #undef FLAG_xform
 #undef FLAG_strip
 #undef FLAG_to_command
@@ -3500,6 +3510,16 @@
 #undef FLAG_i
 #endif
 
+// trap   lp
+#undef OPTSTR_trap
+#define OPTSTR_trap "lp"
+#ifdef CLEANUP_trap
+#undef CLEANUP_trap
+#undef FOR_trap
+#undef FLAG_p
+#undef FLAG_l
+#endif
+
 // true    
 #undef OPTSTR_true
 #define OPTSTR_true 0
@@ -4586,29 +4606,29 @@
 #ifndef TT
 #define TT this.dhcp
 #endif
-#define FLAG_f (FORCED_FLAG<<0)
-#define FLAG_b (FORCED_FLAG<<1)
-#define FLAG_n (FORCED_FLAG<<2)
-#define FLAG_q (FORCED_FLAG<<3)
-#define FLAG_v (FORCED_FLAG<<4)
-#define FLAG_o (FORCED_FLAG<<5)
-#define FLAG_a (FORCED_FLAG<<6)
-#define FLAG_C (FORCED_FLAG<<7)
-#define FLAG_R (FORCED_FLAG<<8)
-#define FLAG_B (FORCED_FLAG<<9)
-#define FLAG_S (FORCED_FLAG<<10)
-#define FLAG_i (FORCED_FLAG<<11)
-#define FLAG_p (FORCED_FLAG<<12)
-#define FLAG_s (FORCED_FLAG<<13)
-#define FLAG_t (FORCED_FLAG<<14)
-#define FLAG_T (FORCED_FLAG<<15)
-#define FLAG_A (FORCED_FLAG<<16)
-#define FLAG_O (FORCED_FLAG<<17)
-#define FLAG_r (FORCED_FLAG<<18)
-#define FLAG_x (FORCED_FLAG<<19)
-#define FLAG_F (FORCED_FLAG<<20)
-#define FLAG_H (FORCED_FLAG<<21)
-#define FLAG_V (FORCED_FLAG<<22)
+#define FLAG_f (1LL<<0)
+#define FLAG_b (1LL<<1)
+#define FLAG_n (1LL<<2)
+#define FLAG_q (1LL<<3)
+#define FLAG_v (1LL<<4)
+#define FLAG_o (1LL<<5)
+#define FLAG_a (1LL<<6)
+#define FLAG_C (1LL<<7)
+#define FLAG_R (1LL<<8)
+#define FLAG_B (1LL<<9)
+#define FLAG_S (1LL<<10)
+#define FLAG_i (1LL<<11)
+#define FLAG_p (1LL<<12)
+#define FLAG_s (1LL<<13)
+#define FLAG_t (1LL<<14)
+#define FLAG_T (1LL<<15)
+#define FLAG_A (1LL<<16)
+#define FLAG_O (1LL<<17)
+#define FLAG_r (1LL<<18)
+#define FLAG_x (1LL<<19)
+#define FLAG_F (1LL<<20)
+#define FLAG_H (1LL<<21)
+#define FLAG_V (1LL<<22)
 #endif
 
 #ifdef FOR_dhcp6
@@ -6089,6 +6109,13 @@
 #endif
 #endif
 
+#ifdef FOR_nologin
+#define CLEANUP_nologin
+#ifndef TT
+#define TT this.nologin
+#endif
+#endif
+
 #ifdef FOR_nproc
 #define CLEANUP_nproc
 #ifndef TT
@@ -6222,6 +6249,7 @@
 #define FLAG_d (1LL<<13)
 #define FLAG_l (1LL<<14)
 #define FLAG_c (1LL<<15)
+#define FLAG_a (1LL<<16)
 #endif
 
 #ifdef FOR_pidof
@@ -6959,33 +6987,34 @@
 #define FLAG_k (1LL<<19)
 #define FLAG_p (1LL<<20)
 #define FLAG_o (1LL<<21)
-#define FLAG_xform (1LL<<22)
-#define FLAG_strip (1LL<<23)
-#define FLAG_to_command (1LL<<24)
-#define FLAG_owner (1LL<<25)
-#define FLAG_group (1LL<<26)
-#define FLAG_mtime (1LL<<27)
-#define FLAG_mode (1LL<<28)
-#define FLAG_sort (1LL<<29)
-#define FLAG_exclude (1LL<<30)
-#define FLAG_overwrite (1LL<<31)
-#define FLAG_no_same_permissions (1LL<<32)
-#define FLAG_numeric_owner (1LL<<33)
-#define FLAG_null (1LL<<34)
-#define FLAG_no_recursion (1LL<<35)
-#define FLAG_full_time (1LL<<36)
-#define FLAG_restrict (1LL<<37)
-#define FLAG_selinux (1LL<<38)
-#define FLAG_show_transformed_names (1LL<<39)
-#define FLAG_wildcards_match_slash (1LL<<40)
-#define FLAG_no_wildcards_match_slash (1LL<<41)
-#define FLAG_wildcards (1LL<<42)
-#define FLAG_no_wildcards (1LL<<43)
-#define FLAG_anchored (1LL<<44)
-#define FLAG_no_anchored (1LL<<45)
-#define FLAG_ignore_case (1LL<<46)
-#define FLAG_no_ignore_case (1LL<<47)
-#define FLAG_one_file_system (1LL<<48)
+#define FLAG_Z (1LL<<22)
+#define FLAG_xform (1LL<<23)
+#define FLAG_strip (1LL<<24)
+#define FLAG_to_command (1LL<<25)
+#define FLAG_owner (1LL<<26)
+#define FLAG_group (1LL<<27)
+#define FLAG_mtime (1LL<<28)
+#define FLAG_mode (1LL<<29)
+#define FLAG_sort (1LL<<30)
+#define FLAG_exclude (1LL<<31)
+#define FLAG_overwrite (1LL<<32)
+#define FLAG_no_same_permissions (1LL<<33)
+#define FLAG_numeric_owner (1LL<<34)
+#define FLAG_null (1LL<<35)
+#define FLAG_no_recursion (1LL<<36)
+#define FLAG_full_time (1LL<<37)
+#define FLAG_restrict (1LL<<38)
+#define FLAG_selinux (1LL<<39)
+#define FLAG_show_transformed_names (1LL<<40)
+#define FLAG_wildcards_match_slash (1LL<<41)
+#define FLAG_no_wildcards_match_slash (1LL<<42)
+#define FLAG_wildcards (1LL<<43)
+#define FLAG_no_wildcards (1LL<<44)
+#define FLAG_anchored (1LL<<45)
+#define FLAG_no_anchored (1LL<<46)
+#define FLAG_ignore_case (1LL<<47)
+#define FLAG_no_ignore_case (1LL<<48)
+#define FLAG_one_file_system (1LL<<49)
 #endif
 
 #ifdef FOR_taskset
@@ -7177,6 +7206,15 @@
 #define FLAG_i (1LL<<19)
 #endif
 
+#ifdef FOR_trap
+#define CLEANUP_trap
+#ifndef TT
+#define TT this.trap
+#endif
+#define FLAG_p (FORCED_FLAG<<0)
+#define FLAG_l (FORCED_FLAG<<1)
+#endif
+
 #ifdef FOR_true
 #define CLEANUP_true
 #ifndef TT
diff --git a/android/device/generated/globals.h b/android/device/generated/globals.h
index ba08bf21..d234ed96 100644
--- a/android/device/generated/globals.h
+++ b/android/device/generated/globals.h
@@ -303,6 +303,21 @@ struct brctl_data {
     int sockfd;
 };
 
+struct dhcp_data {
+    char *iface;
+    char *pidfile;
+    char *script;
+    long retries;
+    long timeout;
+    long tryagain;
+    struct arg_list *req_opt;
+    char *req_ip;
+    struct arg_list *pkt_opt;
+    char *fdn_name;
+    char *hostname;
+    char *vendor_cls;
+};
+
 struct diff_data {
   long U;
   struct arg_list *L;
@@ -861,6 +876,7 @@ extern union global_union {
 	struct watch_data watch;
 	struct xxd_data xxd;
 	struct brctl_data brctl;
+	struct dhcp_data dhcp;
 	struct diff_data diff;
 	struct expr_data expr;
 	struct getfattr_data getfattr;
diff --git a/android/device/generated/help.h b/android/device/generated/help.h
index 7e596863..4a598dbb 100644
--- a/android/device/generated/help.h
+++ b/android/device/generated/help.h
@@ -236,6 +236,8 @@
 
 #define HELP_unshare "usage: unshare [-imnpuUr] COMMAND...\n\nCreate new container namespace(s) for this process and its children, allowing\nthe new set of processes to have a different view of the system than the\nparent process.\n\n-a	Unshare all supported namespaces\n-f	Fork command in the background (--fork)\n-r	Become root (map current euid/egid to 0/0, implies -U) (--map-root-user)\n\nAvailable namespaces:\n-C	Control groups (--cgroup)\n-i	SysV IPC (message queues, semaphores, shared memory) (--ipc)\n-m	Mount/unmount tree (--mount)\n-n	Network address, sockets, routing, iptables (--net)\n-p	Process IDs and init (--pid)\n-u	Host and domain names (--uts)\n-U	UIDs, GIDs, capabilities (--user)\n\nEach namespace can take an optional argument, a persistent mountpoint usable\nby the nsenter command to add new processes to that the namespace. (Specify\nmultiple namespaces to unshare separately, ala -c -i -m because -cim is -c\nwith persistent mount \"im\".)"
 
+#define HELP_nologin "usage: nologin\n\nPrint /etc/nologin.txt and return failure."
+
 #define HELP_nbd_server "usage: nbd-server [-r] FILE\n\nServe a Network Block Device from FILE on stdin/out (ala inetd).\n\n-r	Read only export"
 
 #define HELP_nbd_client "usage: nbd-client [-ns] [-b BLKSZ] HOST PORT DEVICE\n\n-b	Block size (default 4096)\n-n	Do not daemonize\n-s	nbd swap support (lock server into memory)"
@@ -396,6 +398,8 @@
 
 #define HELP_wait "usage: wait [-n] [ID...]\n\nWait for background processes to exit, returning its exit code.\nID can be PID or job, with no IDs waits for all backgrounded processes.\n\n-n	Wait for next process to exit"
 
+#define HELP_trap "usage: trap [-l] [[COMMAND] SIGNAL]\n\nRun COMMAND as handler for signal. With no arguments, list active handlers.\nThe COMMAND \"-\" resets the signal to default.\n\n-l	List signals.\n\nThe special signal EXIT gets called before the shell exits, RETURN when\na function or source returns, and DEBUG is called before each command."
+
 #define HELP_source "usage: source FILE [ARGS...]\n\nRead FILE and execute commands. Any ARGS become positional parameters."
 
 #define HELP_shift "usage: shift [N]\n\nSkip N (default 1) positional parameters, moving $1 and friends along the list.\nDoes not affect $0."
@@ -444,7 +448,7 @@
 
 #define HELP_last "usage: last [-W] [-f FILE]\n\nShow listing of last logged in users.\n\n-W      Display the information without host-column truncation\n-f FILE Read from file FILE instead of /var/log/wtmp"
 
-#define HELP_klogd "usage: klogd [-n] [-c PRIORITY]\n\n-c	Print to console messages more urgent than PRIORITY (1-8)\"\n-n	Run in foreground\n-s	Use syscall instead of /proc"
+#define HELP_klogd "usage: klogd [-n] [-c PRIORITY]\n\nForward messages from the kernel ring buffer (read by dmesg) to syslogd.\n\n-c	Print to console messages more urgent than PRIORITY (1-8)\n-n	Run in foreground\n-s	Use syscall instead of /proc"
 
 #define HELP_ipcs "usage: ipcs [[-smq] -i shmid] | [[-asmq] [-tcplu]]\n\n-i Show specific resource\nResource specification:\n-a All (default)\n-m Shared memory segments\n-q Message queues\n-s Semaphore arrays\nOutput format:\n-c Creator\n-l Limits\n-p Pid\n-t Time\n-u Summary"
 
@@ -548,7 +552,7 @@
 
 #define HELP_tee "usage: tee [-ai] [FILE...]\n\nCopy stdin to each listed file, and also to stdout.\nFilename \"-\" is a synonym for stdout.\n\n-a	Append to files\n-i	Ignore SIGINT"
 
-#define HELP_tar "usage: tar [-cxt] [-fvohmjkOS] [-XTCf NAME] [--selinux] [FILE...]\n\nCreate, extract, or list files in a .tar (or compressed t?z) file.\n\nOptions:\nc  Create                x  Extract               t  Test (list)\nf  tar FILE (default -)  C  Change to DIR first   v  Verbose display\nJ  xz compression        j  bzip2 compression     z  gzip compression\no  Ignore owner          h  Follow symlinks       m  Ignore mtime\nO  Extract to stdout     X  exclude names in FILE T  include names in FILE\ns  Sort dirs (--sort)\n\n--exclude        FILENAME to exclude  --full-time         Show seconds with -tv\n--mode MODE      Adjust permissions   --owner NAME[:UID]  Set file ownership\n--mtime TIME     Override timestamps  --group NAME[:GID]  Set file group\n--sparse         Record sparse files  --selinux           Save/restore labels\n--restrict       All under one dir    --no-recursion      Skip dir contents\n--numeric-owner  Use numeric uid/gid, not user/group names\n--null           Filenames in -T FILE are null-separated, not newline\n--strip-components NUM  Ignore first NUM directory components when extracting\n--xform=SED      Modify filenames via SED expression (ala s/find/replace/g)\n-I PROG          Filter through PROG to compress or PROG -d to decompress\n\nFilename filter types. Create command line args aren't filtered, extract\ndefaults to --anchored, --exclude defaults to --wildcards-match-slash,\nuse no- prefix to disable:\n\n--anchored  Match name not path       --ignore-case       Case insensitive\n--wildcards Expand *?[] like shell    --wildcards-match-slash"
+#define HELP_tar "usage: tar [-cxt] [-fvohmjkOS] [-XTCf NAME] [--selinux] [FILE...]\n\nCreate, extract, or list files in a .tar (or compressed t?z) file.\n\nOptions:\nc  Create                x  Extract               t  Test (list)\nf  tar FILE (default -)  C  Change to DIR first   v  Verbose display\nJ  xz compression        j  bzip2 compression     z  gzip compression\no  Ignore owner          h  Follow symlinks       m  Ignore mtime\nO  Extract to stdout     X  exclude names in FILE T  include names in FILE\ns  Sort dirs (--sort)    Z  zstd compression\n\n--exclude        FILENAME to exclude  --full-time         Show seconds with -tv\n--mode MODE      Adjust permissions   --owner NAME[:UID]  Set file ownership\n--mtime TIME     Override timestamps  --group NAME[:GID]  Set file group\n--sparse         Record sparse files  --selinux           Save/restore labels\n--restrict       All under one dir    --no-recursion      Skip dir contents\n--numeric-owner  Use numeric uid/gid, not user/group names\n--null           Filenames in -T FILE are null-separated, not newline\n--strip-components NUM  Ignore first NUM directory components when extracting\n--xform=SED      Modify filenames via SED expression (ala s/find/replace/g)\n-I PROG          Filter through PROG to compress or PROG -d to decompress\n\nFilename filter types. Create command line args aren't filtered, extract\ndefaults to --anchored, --exclude defaults to --wildcards-match-slash,\nuse no- prefix to disable:\n\n--anchored  Match name not path       --ignore-case       Case insensitive\n--wildcards Expand *?[] like shell    --wildcards-match-slash"
 
 #define HELP_tail "usage: tail [-n|c NUMBER] [-f|F] [-s SECONDS] [FILE...]\n\nCopy last lines from files to stdout. If no files listed, copy from\nstdin. Filename \"-\" is a synonym for stdin.\n\n-n	Output the last NUMBER lines (default 10), +X counts from start\n-c	Output the last NUMBER bytes, +NUMBER counts from start\n-f	Follow FILE(s) by descriptor, waiting for more data to be appended\n-F	Follow FILE(s) by filename, waiting for more data, and retrying\n-s	Used with -F, sleep SECONDS between retries (default 1)"
 
@@ -572,7 +576,7 @@
 
 #define HELP_pkill "usage: pkill [-fnovx] [-SIGNAL|-l SIGNAL] [PATTERN] [-G GID,] [-g PGRP,] [-P PPID,] [-s SID,] [-t TERM,] [-U UID,] [-u EUID,]\n\n-l	Send SIGNAL (default SIGTERM)\n-V	Verbose\n-f	Check full command line for PATTERN\n-G	Match real Group ID(s)\n-g	Match Process Group(s) (0 is current user)\n-n	Newest match only\n-o	Oldest match only\n-P	Match Parent Process ID(s)\n-s	Match Session ID(s) (0 for current)\n-t	Match Terminal(s)\n-U	Match real User ID(s)\n-u	Match effective User ID(s)\n-v	Negate the match\n-x	Match whole command (not substring)"
 
-#define HELP_pgrep "usage: pgrep [-clfnovx] [-d DELIM] [-L SIGNAL] [PATTERN] [-G GID,] [-g PGRP,] [-P PPID,] [-s SID,] [-t TERM,] [-U UID,] [-u EUID,]\n\nSearch for process(es). PATTERN is an extended regular expression checked\nagainst command names.\n\n-c	Show only count of matches\n-d	Use DELIM instead of newline\n-L	Send SIGNAL instead of printing name\n-l	Show command name\n-f	Check full command line for PATTERN\n-G	Match real Group ID(s)\n-g	Match Process Group(s) (0 is current user)\n-n	Newest match only\n-o	Oldest match only\n-P	Match Parent Process ID(s)\n-s	Match Session ID(s) (0 for current)\n-t	Match Terminal(s)\n-U	Match real User ID(s)\n-u	Match effective User ID(s)\n-v	Negate the match\n-x	Match whole command (not substring)"
+#define HELP_pgrep "usage: pgrep [-aclfnovx] [-d DELIM] [-L SIGNAL] [PATTERN] [-G GID,] [-g PGRP,] [-P PPID,] [-s SID,] [-t TERM,] [-U UID,] [-u EUID,]\n\nSearch for process(es). PATTERN is an extended regular expression checked\nagainst command names.\n\n-a	Show the full command line\n-c	Show only count of matches\n-d	Use DELIM instead of newline\n-L	Send SIGNAL instead of printing name\n-l	Show command name\n-f	Check full command line for PATTERN\n-G	Match real Group ID(s)\n-g	Match Process Group(s) (0 is current user)\n-n	Newest match only\n-o	Oldest match only\n-P	Match Parent Process ID(s)\n-s	Match Session ID(s) (0 for current)\n-t	Match Terminal(s)\n-U	Match real User ID(s)\n-u	Match effective User ID(s)\n-v	Negate the match\n-x	Match whole command (not substring)"
 
 #define HELP_iotop "usage: iotop [-AaKObq] [-n NUMBER] [-d SECONDS] [-p PID,] [-u USER,]\n\nRank processes by I/O.\n\n-A	All I/O, not just disk\n-a	Accumulated I/O (not percentage)\n-H	Show threads\n-K	Kilobytes\n-k	Fallback sort FIELDS (default -[D]IO,-ETIME,-PID)\n-m	Maximum number of tasks to show\n-O	Only show processes doing I/O\n-o	Show FIELDS (default PID,PR,USER,[D]READ,[D]WRITE,SWAP,[D]IO,COMM)\n-s	Sort by field number (0-X, default 6)\n-b	Batch mode (no tty)\n-d	Delay SECONDS between each cycle (default 3)\n-n	Exit after NUMBER iterations\n-p	Show these PIDs\n-u	Show these USERs\n-q	Quiet (no header lines)\n\nCursor LEFT/RIGHT to change sort, UP/DOWN move list, space to force\nupdate, R to reverse sort, Q to exit."
 
diff --git a/android/device/generated/newtoys.h b/android/device/generated/newtoys.h
index 45b39f49..69c22588 100644
--- a/android/device/generated/newtoys.h
+++ b/android/device/generated/newtoys.h
@@ -211,6 +211,7 @@ USE_NETSTAT(NEWTOY(netstat, "pWrxwutneal", TOYFLAG_BIN))
 USE_NICE(NEWTOY(nice, "^<1n#", TOYFLAG_BIN))
 USE_NL(NEWTOY(nl, "v#=1l#w#<0=6b:n:s:E", TOYFLAG_USR|TOYFLAG_BIN))
 USE_NOHUP(NEWTOY(nohup, "<1^", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(125)))
+USE_NOLOGIN(NEWTOY(nologin, 0, TOYFLAG_BIN|TOYFLAG_NOHELP))
 USE_NPROC(NEWTOY(nproc, "(all)", TOYFLAG_USR|TOYFLAG_BIN))
 USE_NSENTER(NEWTOY(nsenter, "<1a(all)F(no-fork)t#<1(target)C(cgroup):; i(ipc):; m(mount):; n(net):; p(pid):; u(uts):; U(user):; ", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_STAYROOT))
 USE_OD(NEWTOY(od, "j#vw#<1=16N#xsodcbA:t*", TOYFLAG_USR|TOYFLAG_BIN))
@@ -220,7 +221,7 @@ USE_PARTPROBE(NEWTOY(partprobe, "<1", TOYFLAG_SBIN))
 USE_PASSWD(NEWTOY(passwd, ">1a:dlu", TOYFLAG_STAYROOT|TOYFLAG_USR|TOYFLAG_BIN))
 USE_PASTE(NEWTOY(paste, "d:s", TOYFLAG_USR|TOYFLAG_BIN))
 USE_PATCH(NEWTOY(patch, ">2(no-backup-if-mismatch)(dry-run)F#g#fulp#v(verbose)@d:i:Rs(quiet)[!sv]", TOYFLAG_USR|TOYFLAG_BIN))
-USE_PGREP(NEWTOY(pgrep, "?cld:u*U*t*s*P*g*G*fnovxL:[-no]", TOYFLAG_USR|TOYFLAG_BIN))
+USE_PGREP(NEWTOY(pgrep, "acld:u*U*t*s*P*g*G*fnovxL:[-no]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_PIDOF(NEWTOY(pidof, "so:x", TOYFLAG_BIN))
 USE_PING(NEWTOY(ping, "<1>1m#t#<0>255=64c#<0=3s#<0>4064=56i%W#<0=3w#<0qf46I:[-46]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_PING(OLDTOY(ping6, ping, TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
@@ -290,7 +291,7 @@ USE_SYSCTL(NEWTOY(sysctl, "^neNqwpaA[!ap][!aq][!aw][+aA]", TOYFLAG_SBIN))
 USE_SYSLOGD(NEWTOY(syslogd,">0l#<1>8=8R:b#<0>99=1s#<0=200m#<0>71582787=20O:p:f:a:nSKLD", TOYFLAG_SBIN|TOYFLAG_STAYROOT))
 USE_TAC(NEWTOY(tac, NULL, TOYFLAG_USR|TOYFLAG_BIN))
 USE_TAIL(NEWTOY(tail, "?fFs:c(bytes)-n(lines)-[-cn][-fF]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
-USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
+USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*Z(zstd)o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
 USE_TASKSET(NEWTOY(taskset, "<1^pa", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TCPSVD(NEWTOY(tcpsvd, "^<3c#=30<1b#=20<0C:u:l:hEv", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TEE(NEWTOY(tee, "ia", TOYFLAG_USR|TOYFLAG_BIN))
@@ -307,6 +308,7 @@ USE_SH(OLDTOY(toysh, sh, TOYFLAG_BIN))
 USE_TR(NEWTOY(tr, "^<1>2Ccstd[+cC]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TRACEROUTE(NEWTOY(traceroute, "<1>2i:f#<1>255=1z#<0>86400=0g*w#<0>86400=5t#<0>255=0s:q#<1>255=3p#<1>65535=33434m#<1>255=30rvndlIUF64", TOYFLAG_STAYROOT|TOYFLAG_USR|TOYFLAG_BIN))
 USE_TRACEROUTE(OLDTOY(traceroute6,traceroute, TOYFLAG_STAYROOT|TOYFLAG_USR|TOYFLAG_BIN))
+USE_SH(NEWTOY(trap, "lp", TOYFLAG_NOFORK))
 USE_TRUE(NEWTOY(true, NULL, TOYFLAG_BIN|TOYFLAG_NOHELP|TOYFLAG_MAYFORK))
 USE_TRUNCATE(NEWTOY(truncate, "<1s:|c", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TS(NEWTOY(ts, "ims", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
diff --git a/android/linux/generated/config.h b/android/linux/generated/config.h
index 655f55c2..3bf1cd69 100644
--- a/android/linux/generated/config.h
+++ b/android/linux/generated/config.h
@@ -316,8 +316,6 @@
 #define USE_KILL(...)
 #define CFG_KLOGD 0
 #define USE_KLOGD(...)
-#define CFG_KLOGD_SOURCE_RING_BUFFER 0
-#define USE_KLOGD_SOURCE_RING_BUFFER(...)
 #define CFG_LAST 0
 #define USE_LAST(...)
 #define CFG_LINK 0
@@ -374,16 +372,6 @@
 #define USE_MKDIR(...) __VA_ARGS__
 #define CFG_MKDIR_Z 0
 #define USE_MKDIR_Z(...)
-#define CFG_MKE2FS_EXTENDED 0
-#define USE_MKE2FS_EXTENDED(...)
-#define CFG_MKE2FS_GEN 0
-#define USE_MKE2FS_GEN(...)
-#define CFG_MKE2FS 0
-#define USE_MKE2FS(...)
-#define CFG_MKE2FS_JOURNAL 0
-#define USE_MKE2FS_JOURNAL(...)
-#define CFG_MKE2FS_LABEL 0
-#define USE_MKE2FS_LABEL(...)
 #define CFG_MKFIFO 0
 #define USE_MKFIFO(...)
 #define CFG_MKFIFO_Z 0
@@ -424,6 +412,8 @@
 #define USE_NL(...) __VA_ARGS__
 #define CFG_NOHUP 0
 #define USE_NOHUP(...)
+#define CFG_NOLOGIN 0
+#define USE_NOLOGIN(...)
 #define CFG_NPROC 1
 #define USE_NPROC(...) __VA_ARGS__
 #define CFG_NSENTER 0
diff --git a/android/linux/generated/flags.h b/android/linux/generated/flags.h
index 7a1555ba..0fcbbc4b 100644
--- a/android/linux/generated/flags.h
+++ b/android/linux/generated/flags.h
@@ -2325,6 +2325,14 @@
 #undef FOR_nohup
 #endif
 
+// nologin    
+#undef OPTSTR_nologin
+#define OPTSTR_nologin 0
+#ifdef CLEANUP_nologin
+#undef CLEANUP_nologin
+#undef FOR_nologin
+#endif
+
 // nproc (all) (all)
 #undef OPTSTR_nproc
 #define OPTSTR_nproc "(all)"
@@ -2446,9 +2454,9 @@
 #undef FLAG_no_backup_if_mismatch
 #endif
 
-// pgrep ?cld:u*U*t*s*P*g*G*fnovxL:[-no] ?cld:u*U*t*s*P*g*G*fnovxL:[-no]
+// pgrep acld:u*U*t*s*P*g*G*fnovxL:[-no] acld:u*U*t*s*P*g*G*fnovxL:[-no]
 #undef OPTSTR_pgrep
-#define OPTSTR_pgrep "?cld:u*U*t*s*P*g*G*fnovxL:[-no]"
+#define OPTSTR_pgrep "acld:u*U*t*s*P*g*G*fnovxL:[-no]"
 #ifdef CLEANUP_pgrep
 #undef CLEANUP_pgrep
 #undef FOR_pgrep
@@ -2468,6 +2476,7 @@
 #undef FLAG_d
 #undef FLAG_l
 #undef FLAG_c
+#undef FLAG_a
 #endif
 
 // pidof   so:x
@@ -3239,9 +3248,9 @@
 #undef FLAG_f
 #endif
 
-// tar &(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa] &(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]
+// tar &(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*Z(zstd)o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa] &(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*Z(zstd)o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]
 #undef OPTSTR_tar
-#define OPTSTR_tar "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]"
+#define OPTSTR_tar "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*Z(zstd)o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]"
 #ifdef CLEANUP_tar
 #undef CLEANUP_tar
 #undef FOR_tar
@@ -3267,6 +3276,7 @@
 #undef FLAG_k
 #undef FLAG_p
 #undef FLAG_o
+#undef FLAG_Z
 #undef FLAG_xform
 #undef FLAG_strip
 #undef FLAG_to_command
@@ -3500,6 +3510,16 @@
 #undef FLAG_i
 #endif
 
+// trap   lp
+#undef OPTSTR_trap
+#define OPTSTR_trap "lp"
+#ifdef CLEANUP_trap
+#undef CLEANUP_trap
+#undef FOR_trap
+#undef FLAG_p
+#undef FLAG_l
+#endif
+
 // true    
 #undef OPTSTR_true
 #define OPTSTR_true 0
@@ -6089,6 +6109,13 @@
 #endif
 #endif
 
+#ifdef FOR_nologin
+#define CLEANUP_nologin
+#ifndef TT
+#define TT this.nologin
+#endif
+#endif
+
 #ifdef FOR_nproc
 #define CLEANUP_nproc
 #ifndef TT
@@ -6222,6 +6249,7 @@
 #define FLAG_d (1LL<<13)
 #define FLAG_l (1LL<<14)
 #define FLAG_c (1LL<<15)
+#define FLAG_a (1LL<<16)
 #endif
 
 #ifdef FOR_pidof
@@ -6959,33 +6987,34 @@
 #define FLAG_k (1LL<<19)
 #define FLAG_p (1LL<<20)
 #define FLAG_o (1LL<<21)
-#define FLAG_xform (1LL<<22)
-#define FLAG_strip (1LL<<23)
-#define FLAG_to_command (1LL<<24)
-#define FLAG_owner (1LL<<25)
-#define FLAG_group (1LL<<26)
-#define FLAG_mtime (1LL<<27)
-#define FLAG_mode (1LL<<28)
-#define FLAG_sort (1LL<<29)
-#define FLAG_exclude (1LL<<30)
-#define FLAG_overwrite (1LL<<31)
-#define FLAG_no_same_permissions (1LL<<32)
-#define FLAG_numeric_owner (1LL<<33)
-#define FLAG_null (1LL<<34)
-#define FLAG_no_recursion (1LL<<35)
-#define FLAG_full_time (1LL<<36)
-#define FLAG_restrict (1LL<<37)
-#define FLAG_selinux (1LL<<38)
-#define FLAG_show_transformed_names (1LL<<39)
-#define FLAG_wildcards_match_slash (1LL<<40)
-#define FLAG_no_wildcards_match_slash (1LL<<41)
-#define FLAG_wildcards (1LL<<42)
-#define FLAG_no_wildcards (1LL<<43)
-#define FLAG_anchored (1LL<<44)
-#define FLAG_no_anchored (1LL<<45)
-#define FLAG_ignore_case (1LL<<46)
-#define FLAG_no_ignore_case (1LL<<47)
-#define FLAG_one_file_system (1LL<<48)
+#define FLAG_Z (1LL<<22)
+#define FLAG_xform (1LL<<23)
+#define FLAG_strip (1LL<<24)
+#define FLAG_to_command (1LL<<25)
+#define FLAG_owner (1LL<<26)
+#define FLAG_group (1LL<<27)
+#define FLAG_mtime (1LL<<28)
+#define FLAG_mode (1LL<<29)
+#define FLAG_sort (1LL<<30)
+#define FLAG_exclude (1LL<<31)
+#define FLAG_overwrite (1LL<<32)
+#define FLAG_no_same_permissions (1LL<<33)
+#define FLAG_numeric_owner (1LL<<34)
+#define FLAG_null (1LL<<35)
+#define FLAG_no_recursion (1LL<<36)
+#define FLAG_full_time (1LL<<37)
+#define FLAG_restrict (1LL<<38)
+#define FLAG_selinux (1LL<<39)
+#define FLAG_show_transformed_names (1LL<<40)
+#define FLAG_wildcards_match_slash (1LL<<41)
+#define FLAG_no_wildcards_match_slash (1LL<<42)
+#define FLAG_wildcards (1LL<<43)
+#define FLAG_no_wildcards (1LL<<44)
+#define FLAG_anchored (1LL<<45)
+#define FLAG_no_anchored (1LL<<46)
+#define FLAG_ignore_case (1LL<<47)
+#define FLAG_no_ignore_case (1LL<<48)
+#define FLAG_one_file_system (1LL<<49)
 #endif
 
 #ifdef FOR_taskset
@@ -7177,6 +7206,15 @@
 #define FLAG_i (FORCED_FLAG<<19)
 #endif
 
+#ifdef FOR_trap
+#define CLEANUP_trap
+#ifndef TT
+#define TT this.trap
+#endif
+#define FLAG_p (FORCED_FLAG<<0)
+#define FLAG_l (FORCED_FLAG<<1)
+#endif
+
 #ifdef FOR_true
 #define CLEANUP_true
 #ifndef TT
diff --git a/android/linux/generated/help.h b/android/linux/generated/help.h
index 0c099c13..17e54569 100644
--- a/android/linux/generated/help.h
+++ b/android/linux/generated/help.h
@@ -238,6 +238,8 @@
 
 #define HELP_unshare "usage: unshare [-imnpuUr] COMMAND...\n\nCreate new container namespace(s) for this process and its children, allowing\nthe new set of processes to have a different view of the system than the\nparent process.\n\n-a	Unshare all supported namespaces\n-f	Fork command in the background (--fork)\n-r	Become root (map current euid/egid to 0/0, implies -U) (--map-root-user)\n\nAvailable namespaces:\n-C	Control groups (--cgroup)\n-i	SysV IPC (message queues, semaphores, shared memory) (--ipc)\n-m	Mount/unmount tree (--mount)\n-n	Network address, sockets, routing, iptables (--net)\n-p	Process IDs and init (--pid)\n-u	Host and domain names (--uts)\n-U	UIDs, GIDs, capabilities (--user)\n\nEach namespace can take an optional argument, a persistent mountpoint usable\nby the nsenter command to add new processes to that the namespace. (Specify\nmultiple namespaces to unshare separately, ala -c -i -m because -cim is -c\nwith persistent mount \"im\".)"
 
+#define HELP_nologin "usage: nologin\n\nPrint /etc/nologin.txt and return failure."
+
 #define HELP_nbd_server "usage: nbd-server [-r] FILE\n\nServe a Network Block Device from FILE on stdin/out (ala inetd).\n\n-r	Read only export"
 
 #define HELP_nbd_client "usage: nbd-client [-ns] [-b BLKSZ] HOST PORT DEVICE\n\n-b	Block size (default 4096)\n-n	Do not daemonize\n-s	nbd swap support (lock server into memory)"
@@ -398,6 +400,8 @@
 
 #define HELP_wait "usage: wait [-n] [ID...]\n\nWait for background processes to exit, returning its exit code.\nID can be PID or job, with no IDs waits for all backgrounded processes.\n\n-n	Wait for next process to exit"
 
+#define HELP_trap "usage: trap [-l] [[COMMAND] SIGNAL]\n\nRun COMMAND as handler for signal. With no arguments, list active handlers.\nThe COMMAND \"-\" resets the signal to default.\n\n-l	List signals.\n\nThe special signal EXIT gets called before the shell exits, RETURN when\na function or source returns, and DEBUG is called before each command."
+
 #define HELP_source "usage: source FILE [ARGS...]\n\nRead FILE and execute commands. Any ARGS become positional parameters."
 
 #define HELP_shift "usage: shift [N]\n\nSkip N (default 1) positional parameters, moving $1 and friends along the list.\nDoes not affect $0."
@@ -446,7 +450,7 @@
 
 #define HELP_last "usage: last [-W] [-f FILE]\n\nShow listing of last logged in users.\n\n-W      Display the information without host-column truncation\n-f FILE Read from file FILE instead of /var/log/wtmp"
 
-#define HELP_klogd "usage: klogd [-n] [-c PRIORITY]\n\n-c	Print to console messages more urgent than PRIORITY (1-8)\"\n-n	Run in foreground\n-s	Use syscall instead of /proc"
+#define HELP_klogd "usage: klogd [-n] [-c PRIORITY]\n\nForward messages from the kernel ring buffer (read by dmesg) to syslogd.\n\n-c	Print to console messages more urgent than PRIORITY (1-8)\n-n	Run in foreground\n-s	Use syscall instead of /proc"
 
 #define HELP_ipcs "usage: ipcs [[-smq] -i shmid] | [[-asmq] [-tcplu]]\n\n-i Show specific resource\nResource specification:\n-a All (default)\n-m Shared memory segments\n-q Message queues\n-s Semaphore arrays\nOutput format:\n-c Creator\n-l Limits\n-p Pid\n-t Time\n-u Summary"
 
@@ -550,7 +554,7 @@
 
 #define HELP_tee "usage: tee [-ai] [FILE...]\n\nCopy stdin to each listed file, and also to stdout.\nFilename \"-\" is a synonym for stdout.\n\n-a	Append to files\n-i	Ignore SIGINT"
 
-#define HELP_tar "usage: tar [-cxt] [-fvohmjkOS] [-XTCf NAME] [--selinux] [FILE...]\n\nCreate, extract, or list files in a .tar (or compressed t?z) file.\n\nOptions:\nc  Create                x  Extract               t  Test (list)\nf  tar FILE (default -)  C  Change to DIR first   v  Verbose display\nJ  xz compression        j  bzip2 compression     z  gzip compression\no  Ignore owner          h  Follow symlinks       m  Ignore mtime\nO  Extract to stdout     X  exclude names in FILE T  include names in FILE\ns  Sort dirs (--sort)\n\n--exclude        FILENAME to exclude  --full-time         Show seconds with -tv\n--mode MODE      Adjust permissions   --owner NAME[:UID]  Set file ownership\n--mtime TIME     Override timestamps  --group NAME[:GID]  Set file group\n--sparse         Record sparse files  --selinux           Save/restore labels\n--restrict       All under one dir    --no-recursion      Skip dir contents\n--numeric-owner  Use numeric uid/gid, not user/group names\n--null           Filenames in -T FILE are null-separated, not newline\n--strip-components NUM  Ignore first NUM directory components when extracting\n--xform=SED      Modify filenames via SED expression (ala s/find/replace/g)\n-I PROG          Filter through PROG to compress or PROG -d to decompress\n\nFilename filter types. Create command line args aren't filtered, extract\ndefaults to --anchored, --exclude defaults to --wildcards-match-slash,\nuse no- prefix to disable:\n\n--anchored  Match name not path       --ignore-case       Case insensitive\n--wildcards Expand *?[] like shell    --wildcards-match-slash"
+#define HELP_tar "usage: tar [-cxt] [-fvohmjkOS] [-XTCf NAME] [--selinux] [FILE...]\n\nCreate, extract, or list files in a .tar (or compressed t?z) file.\n\nOptions:\nc  Create                x  Extract               t  Test (list)\nf  tar FILE (default -)  C  Change to DIR first   v  Verbose display\nJ  xz compression        j  bzip2 compression     z  gzip compression\no  Ignore owner          h  Follow symlinks       m  Ignore mtime\nO  Extract to stdout     X  exclude names in FILE T  include names in FILE\ns  Sort dirs (--sort)    Z  zstd compression\n\n--exclude        FILENAME to exclude  --full-time         Show seconds with -tv\n--mode MODE      Adjust permissions   --owner NAME[:UID]  Set file ownership\n--mtime TIME     Override timestamps  --group NAME[:GID]  Set file group\n--sparse         Record sparse files  --selinux           Save/restore labels\n--restrict       All under one dir    --no-recursion      Skip dir contents\n--numeric-owner  Use numeric uid/gid, not user/group names\n--null           Filenames in -T FILE are null-separated, not newline\n--strip-components NUM  Ignore first NUM directory components when extracting\n--xform=SED      Modify filenames via SED expression (ala s/find/replace/g)\n-I PROG          Filter through PROG to compress or PROG -d to decompress\n\nFilename filter types. Create command line args aren't filtered, extract\ndefaults to --anchored, --exclude defaults to --wildcards-match-slash,\nuse no- prefix to disable:\n\n--anchored  Match name not path       --ignore-case       Case insensitive\n--wildcards Expand *?[] like shell    --wildcards-match-slash"
 
 #define HELP_tail "usage: tail [-n|c NUMBER] [-f|F] [-s SECONDS] [FILE...]\n\nCopy last lines from files to stdout. If no files listed, copy from\nstdin. Filename \"-\" is a synonym for stdin.\n\n-n	Output the last NUMBER lines (default 10), +X counts from start\n-c	Output the last NUMBER bytes, +NUMBER counts from start\n-f	Follow FILE(s) by descriptor, waiting for more data to be appended\n-F	Follow FILE(s) by filename, waiting for more data, and retrying\n-s	Used with -F, sleep SECONDS between retries (default 1)"
 
@@ -574,7 +578,7 @@
 
 #define HELP_pkill "usage: pkill [-fnovx] [-SIGNAL|-l SIGNAL] [PATTERN] [-G GID,] [-g PGRP,] [-P PPID,] [-s SID,] [-t TERM,] [-U UID,] [-u EUID,]\n\n-l	Send SIGNAL (default SIGTERM)\n-V	Verbose\n-f	Check full command line for PATTERN\n-G	Match real Group ID(s)\n-g	Match Process Group(s) (0 is current user)\n-n	Newest match only\n-o	Oldest match only\n-P	Match Parent Process ID(s)\n-s	Match Session ID(s) (0 for current)\n-t	Match Terminal(s)\n-U	Match real User ID(s)\n-u	Match effective User ID(s)\n-v	Negate the match\n-x	Match whole command (not substring)"
 
-#define HELP_pgrep "usage: pgrep [-clfnovx] [-d DELIM] [-L SIGNAL] [PATTERN] [-G GID,] [-g PGRP,] [-P PPID,] [-s SID,] [-t TERM,] [-U UID,] [-u EUID,]\n\nSearch for process(es). PATTERN is an extended regular expression checked\nagainst command names.\n\n-c	Show only count of matches\n-d	Use DELIM instead of newline\n-L	Send SIGNAL instead of printing name\n-l	Show command name\n-f	Check full command line for PATTERN\n-G	Match real Group ID(s)\n-g	Match Process Group(s) (0 is current user)\n-n	Newest match only\n-o	Oldest match only\n-P	Match Parent Process ID(s)\n-s	Match Session ID(s) (0 for current)\n-t	Match Terminal(s)\n-U	Match real User ID(s)\n-u	Match effective User ID(s)\n-v	Negate the match\n-x	Match whole command (not substring)"
+#define HELP_pgrep "usage: pgrep [-aclfnovx] [-d DELIM] [-L SIGNAL] [PATTERN] [-G GID,] [-g PGRP,] [-P PPID,] [-s SID,] [-t TERM,] [-U UID,] [-u EUID,]\n\nSearch for process(es). PATTERN is an extended regular expression checked\nagainst command names.\n\n-a	Show the full command line\n-c	Show only count of matches\n-d	Use DELIM instead of newline\n-L	Send SIGNAL instead of printing name\n-l	Show command name\n-f	Check full command line for PATTERN\n-G	Match real Group ID(s)\n-g	Match Process Group(s) (0 is current user)\n-n	Newest match only\n-o	Oldest match only\n-P	Match Parent Process ID(s)\n-s	Match Session ID(s) (0 for current)\n-t	Match Terminal(s)\n-U	Match real User ID(s)\n-u	Match effective User ID(s)\n-v	Negate the match\n-x	Match whole command (not substring)"
 
 #define HELP_iotop "usage: iotop [-AaKObq] [-n NUMBER] [-d SECONDS] [-p PID,] [-u USER,]\n\nRank processes by I/O.\n\n-A	All I/O, not just disk\n-a	Accumulated I/O (not percentage)\n-H	Show threads\n-K	Kilobytes\n-k	Fallback sort FIELDS (default -[D]IO,-ETIME,-PID)\n-m	Maximum number of tasks to show\n-O	Only show processes doing I/O\n-o	Show FIELDS (default PID,PR,USER,[D]READ,[D]WRITE,SWAP,[D]IO,COMM)\n-s	Sort by field number (0-X, default 6)\n-b	Batch mode (no tty)\n-d	Delay SECONDS between each cycle (default 3)\n-n	Exit after NUMBER iterations\n-p	Show these PIDs\n-u	Show these USERs\n-q	Quiet (no header lines)\n\nCursor LEFT/RIGHT to change sort, UP/DOWN move list, space to force\nupdate, R to reverse sort, Q to exit."
 
diff --git a/android/linux/generated/newtoys.h b/android/linux/generated/newtoys.h
index 45b39f49..69c22588 100644
--- a/android/linux/generated/newtoys.h
+++ b/android/linux/generated/newtoys.h
@@ -211,6 +211,7 @@ USE_NETSTAT(NEWTOY(netstat, "pWrxwutneal", TOYFLAG_BIN))
 USE_NICE(NEWTOY(nice, "^<1n#", TOYFLAG_BIN))
 USE_NL(NEWTOY(nl, "v#=1l#w#<0=6b:n:s:E", TOYFLAG_USR|TOYFLAG_BIN))
 USE_NOHUP(NEWTOY(nohup, "<1^", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(125)))
+USE_NOLOGIN(NEWTOY(nologin, 0, TOYFLAG_BIN|TOYFLAG_NOHELP))
 USE_NPROC(NEWTOY(nproc, "(all)", TOYFLAG_USR|TOYFLAG_BIN))
 USE_NSENTER(NEWTOY(nsenter, "<1a(all)F(no-fork)t#<1(target)C(cgroup):; i(ipc):; m(mount):; n(net):; p(pid):; u(uts):; U(user):; ", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_STAYROOT))
 USE_OD(NEWTOY(od, "j#vw#<1=16N#xsodcbA:t*", TOYFLAG_USR|TOYFLAG_BIN))
@@ -220,7 +221,7 @@ USE_PARTPROBE(NEWTOY(partprobe, "<1", TOYFLAG_SBIN))
 USE_PASSWD(NEWTOY(passwd, ">1a:dlu", TOYFLAG_STAYROOT|TOYFLAG_USR|TOYFLAG_BIN))
 USE_PASTE(NEWTOY(paste, "d:s", TOYFLAG_USR|TOYFLAG_BIN))
 USE_PATCH(NEWTOY(patch, ">2(no-backup-if-mismatch)(dry-run)F#g#fulp#v(verbose)@d:i:Rs(quiet)[!sv]", TOYFLAG_USR|TOYFLAG_BIN))
-USE_PGREP(NEWTOY(pgrep, "?cld:u*U*t*s*P*g*G*fnovxL:[-no]", TOYFLAG_USR|TOYFLAG_BIN))
+USE_PGREP(NEWTOY(pgrep, "acld:u*U*t*s*P*g*G*fnovxL:[-no]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_PIDOF(NEWTOY(pidof, "so:x", TOYFLAG_BIN))
 USE_PING(NEWTOY(ping, "<1>1m#t#<0>255=64c#<0=3s#<0>4064=56i%W#<0=3w#<0qf46I:[-46]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_PING(OLDTOY(ping6, ping, TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
@@ -290,7 +291,7 @@ USE_SYSCTL(NEWTOY(sysctl, "^neNqwpaA[!ap][!aq][!aw][+aA]", TOYFLAG_SBIN))
 USE_SYSLOGD(NEWTOY(syslogd,">0l#<1>8=8R:b#<0>99=1s#<0=200m#<0>71582787=20O:p:f:a:nSKLD", TOYFLAG_SBIN|TOYFLAG_STAYROOT))
 USE_TAC(NEWTOY(tac, NULL, TOYFLAG_USR|TOYFLAG_BIN))
 USE_TAIL(NEWTOY(tail, "?fFs:c(bytes)-n(lines)-[-cn][-fF]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
-USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
+USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*Z(zstd)o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
 USE_TASKSET(NEWTOY(taskset, "<1^pa", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TCPSVD(NEWTOY(tcpsvd, "^<3c#=30<1b#=20<0C:u:l:hEv", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TEE(NEWTOY(tee, "ia", TOYFLAG_USR|TOYFLAG_BIN))
@@ -307,6 +308,7 @@ USE_SH(OLDTOY(toysh, sh, TOYFLAG_BIN))
 USE_TR(NEWTOY(tr, "^<1>2Ccstd[+cC]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TRACEROUTE(NEWTOY(traceroute, "<1>2i:f#<1>255=1z#<0>86400=0g*w#<0>86400=5t#<0>255=0s:q#<1>255=3p#<1>65535=33434m#<1>255=30rvndlIUF64", TOYFLAG_STAYROOT|TOYFLAG_USR|TOYFLAG_BIN))
 USE_TRACEROUTE(OLDTOY(traceroute6,traceroute, TOYFLAG_STAYROOT|TOYFLAG_USR|TOYFLAG_BIN))
+USE_SH(NEWTOY(trap, "lp", TOYFLAG_NOFORK))
 USE_TRUE(NEWTOY(true, NULL, TOYFLAG_BIN|TOYFLAG_NOHELP|TOYFLAG_MAYFORK))
 USE_TRUNCATE(NEWTOY(truncate, "<1s:|c", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TS(NEWTOY(ts, "ims", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
diff --git a/android/mac/generated/config.h b/android/mac/generated/config.h
index e948a22f..d890ee2a 100644
--- a/android/mac/generated/config.h
+++ b/android/mac/generated/config.h
@@ -316,8 +316,6 @@
 #define USE_KILL(...)
 #define CFG_KLOGD 0
 #define USE_KLOGD(...)
-#define CFG_KLOGD_SOURCE_RING_BUFFER 0
-#define USE_KLOGD_SOURCE_RING_BUFFER(...)
 #define CFG_LAST 0
 #define USE_LAST(...)
 #define CFG_LINK 0
@@ -374,16 +372,6 @@
 #define USE_MKDIR(...) __VA_ARGS__
 #define CFG_MKDIR_Z 0
 #define USE_MKDIR_Z(...)
-#define CFG_MKE2FS_EXTENDED 0
-#define USE_MKE2FS_EXTENDED(...)
-#define CFG_MKE2FS_GEN 0
-#define USE_MKE2FS_GEN(...)
-#define CFG_MKE2FS 0
-#define USE_MKE2FS(...)
-#define CFG_MKE2FS_JOURNAL 0
-#define USE_MKE2FS_JOURNAL(...)
-#define CFG_MKE2FS_LABEL 0
-#define USE_MKE2FS_LABEL(...)
 #define CFG_MKFIFO 0
 #define USE_MKFIFO(...)
 #define CFG_MKFIFO_Z 0
@@ -424,6 +412,8 @@
 #define USE_NL(...) __VA_ARGS__
 #define CFG_NOHUP 0
 #define USE_NOHUP(...)
+#define CFG_NOLOGIN 0
+#define USE_NOLOGIN(...)
 #define CFG_NPROC 0
 #define USE_NPROC(...)
 #define CFG_NSENTER 0
diff --git a/android/mac/generated/flags.h b/android/mac/generated/flags.h
index 48ed0167..dc3be59d 100644
--- a/android/mac/generated/flags.h
+++ b/android/mac/generated/flags.h
@@ -2325,6 +2325,14 @@
 #undef FOR_nohup
 #endif
 
+// nologin    
+#undef OPTSTR_nologin
+#define OPTSTR_nologin 0
+#ifdef CLEANUP_nologin
+#undef CLEANUP_nologin
+#undef FOR_nologin
+#endif
+
 // nproc   (all)
 #undef OPTSTR_nproc
 #define OPTSTR_nproc "(all)"
@@ -2446,9 +2454,9 @@
 #undef FLAG_no_backup_if_mismatch
 #endif
 
-// pgrep   ?cld:u*U*t*s*P*g*G*fnovxL:[-no]
+// pgrep   acld:u*U*t*s*P*g*G*fnovxL:[-no]
 #undef OPTSTR_pgrep
-#define OPTSTR_pgrep "?cld:u*U*t*s*P*g*G*fnovxL:[-no]"
+#define OPTSTR_pgrep "acld:u*U*t*s*P*g*G*fnovxL:[-no]"
 #ifdef CLEANUP_pgrep
 #undef CLEANUP_pgrep
 #undef FOR_pgrep
@@ -2468,6 +2476,7 @@
 #undef FLAG_d
 #undef FLAG_l
 #undef FLAG_c
+#undef FLAG_a
 #endif
 
 // pidof   so:x
@@ -3239,9 +3248,9 @@
 #undef FLAG_f
 #endif
 
-// tar &(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa] &(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]
+// tar &(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*Z(zstd)o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa] &(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*Z(zstd)o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]
 #undef OPTSTR_tar
-#define OPTSTR_tar "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]"
+#define OPTSTR_tar "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*Z(zstd)o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]"
 #ifdef CLEANUP_tar
 #undef CLEANUP_tar
 #undef FOR_tar
@@ -3267,6 +3276,7 @@
 #undef FLAG_k
 #undef FLAG_p
 #undef FLAG_o
+#undef FLAG_Z
 #undef FLAG_xform
 #undef FLAG_strip
 #undef FLAG_to_command
@@ -3500,6 +3510,16 @@
 #undef FLAG_i
 #endif
 
+// trap   lp
+#undef OPTSTR_trap
+#define OPTSTR_trap "lp"
+#ifdef CLEANUP_trap
+#undef CLEANUP_trap
+#undef FOR_trap
+#undef FLAG_p
+#undef FLAG_l
+#endif
+
 // true    
 #undef OPTSTR_true
 #define OPTSTR_true 0
@@ -6089,6 +6109,13 @@
 #endif
 #endif
 
+#ifdef FOR_nologin
+#define CLEANUP_nologin
+#ifndef TT
+#define TT this.nologin
+#endif
+#endif
+
 #ifdef FOR_nproc
 #define CLEANUP_nproc
 #ifndef TT
@@ -6222,6 +6249,7 @@
 #define FLAG_d (FORCED_FLAG<<13)
 #define FLAG_l (FORCED_FLAG<<14)
 #define FLAG_c (FORCED_FLAG<<15)
+#define FLAG_a (FORCED_FLAG<<16)
 #endif
 
 #ifdef FOR_pidof
@@ -6959,33 +6987,34 @@
 #define FLAG_k (1LL<<19)
 #define FLAG_p (1LL<<20)
 #define FLAG_o (1LL<<21)
-#define FLAG_xform (1LL<<22)
-#define FLAG_strip (1LL<<23)
-#define FLAG_to_command (1LL<<24)
-#define FLAG_owner (1LL<<25)
-#define FLAG_group (1LL<<26)
-#define FLAG_mtime (1LL<<27)
-#define FLAG_mode (1LL<<28)
-#define FLAG_sort (1LL<<29)
-#define FLAG_exclude (1LL<<30)
-#define FLAG_overwrite (1LL<<31)
-#define FLAG_no_same_permissions (1LL<<32)
-#define FLAG_numeric_owner (1LL<<33)
-#define FLAG_null (1LL<<34)
-#define FLAG_no_recursion (1LL<<35)
-#define FLAG_full_time (1LL<<36)
-#define FLAG_restrict (1LL<<37)
-#define FLAG_selinux (1LL<<38)
-#define FLAG_show_transformed_names (1LL<<39)
-#define FLAG_wildcards_match_slash (1LL<<40)
-#define FLAG_no_wildcards_match_slash (1LL<<41)
-#define FLAG_wildcards (1LL<<42)
-#define FLAG_no_wildcards (1LL<<43)
-#define FLAG_anchored (1LL<<44)
-#define FLAG_no_anchored (1LL<<45)
-#define FLAG_ignore_case (1LL<<46)
-#define FLAG_no_ignore_case (1LL<<47)
-#define FLAG_one_file_system (1LL<<48)
+#define FLAG_Z (1LL<<22)
+#define FLAG_xform (1LL<<23)
+#define FLAG_strip (1LL<<24)
+#define FLAG_to_command (1LL<<25)
+#define FLAG_owner (1LL<<26)
+#define FLAG_group (1LL<<27)
+#define FLAG_mtime (1LL<<28)
+#define FLAG_mode (1LL<<29)
+#define FLAG_sort (1LL<<30)
+#define FLAG_exclude (1LL<<31)
+#define FLAG_overwrite (1LL<<32)
+#define FLAG_no_same_permissions (1LL<<33)
+#define FLAG_numeric_owner (1LL<<34)
+#define FLAG_null (1LL<<35)
+#define FLAG_no_recursion (1LL<<36)
+#define FLAG_full_time (1LL<<37)
+#define FLAG_restrict (1LL<<38)
+#define FLAG_selinux (1LL<<39)
+#define FLAG_show_transformed_names (1LL<<40)
+#define FLAG_wildcards_match_slash (1LL<<41)
+#define FLAG_no_wildcards_match_slash (1LL<<42)
+#define FLAG_wildcards (1LL<<43)
+#define FLAG_no_wildcards (1LL<<44)
+#define FLAG_anchored (1LL<<45)
+#define FLAG_no_anchored (1LL<<46)
+#define FLAG_ignore_case (1LL<<47)
+#define FLAG_no_ignore_case (1LL<<48)
+#define FLAG_one_file_system (1LL<<49)
 #endif
 
 #ifdef FOR_taskset
@@ -7177,6 +7206,15 @@
 #define FLAG_i (FORCED_FLAG<<19)
 #endif
 
+#ifdef FOR_trap
+#define CLEANUP_trap
+#ifndef TT
+#define TT this.trap
+#endif
+#define FLAG_p (FORCED_FLAG<<0)
+#define FLAG_l (FORCED_FLAG<<1)
+#endif
+
 #ifdef FOR_true
 #define CLEANUP_true
 #ifndef TT
diff --git a/android/mac/generated/help.h b/android/mac/generated/help.h
index 0c099c13..17e54569 100644
--- a/android/mac/generated/help.h
+++ b/android/mac/generated/help.h
@@ -238,6 +238,8 @@
 
 #define HELP_unshare "usage: unshare [-imnpuUr] COMMAND...\n\nCreate new container namespace(s) for this process and its children, allowing\nthe new set of processes to have a different view of the system than the\nparent process.\n\n-a	Unshare all supported namespaces\n-f	Fork command in the background (--fork)\n-r	Become root (map current euid/egid to 0/0, implies -U) (--map-root-user)\n\nAvailable namespaces:\n-C	Control groups (--cgroup)\n-i	SysV IPC (message queues, semaphores, shared memory) (--ipc)\n-m	Mount/unmount tree (--mount)\n-n	Network address, sockets, routing, iptables (--net)\n-p	Process IDs and init (--pid)\n-u	Host and domain names (--uts)\n-U	UIDs, GIDs, capabilities (--user)\n\nEach namespace can take an optional argument, a persistent mountpoint usable\nby the nsenter command to add new processes to that the namespace. (Specify\nmultiple namespaces to unshare separately, ala -c -i -m because -cim is -c\nwith persistent mount \"im\".)"
 
+#define HELP_nologin "usage: nologin\n\nPrint /etc/nologin.txt and return failure."
+
 #define HELP_nbd_server "usage: nbd-server [-r] FILE\n\nServe a Network Block Device from FILE on stdin/out (ala inetd).\n\n-r	Read only export"
 
 #define HELP_nbd_client "usage: nbd-client [-ns] [-b BLKSZ] HOST PORT DEVICE\n\n-b	Block size (default 4096)\n-n	Do not daemonize\n-s	nbd swap support (lock server into memory)"
@@ -398,6 +400,8 @@
 
 #define HELP_wait "usage: wait [-n] [ID...]\n\nWait for background processes to exit, returning its exit code.\nID can be PID or job, with no IDs waits for all backgrounded processes.\n\n-n	Wait for next process to exit"
 
+#define HELP_trap "usage: trap [-l] [[COMMAND] SIGNAL]\n\nRun COMMAND as handler for signal. With no arguments, list active handlers.\nThe COMMAND \"-\" resets the signal to default.\n\n-l	List signals.\n\nThe special signal EXIT gets called before the shell exits, RETURN when\na function or source returns, and DEBUG is called before each command."
+
 #define HELP_source "usage: source FILE [ARGS...]\n\nRead FILE and execute commands. Any ARGS become positional parameters."
 
 #define HELP_shift "usage: shift [N]\n\nSkip N (default 1) positional parameters, moving $1 and friends along the list.\nDoes not affect $0."
@@ -446,7 +450,7 @@
 
 #define HELP_last "usage: last [-W] [-f FILE]\n\nShow listing of last logged in users.\n\n-W      Display the information without host-column truncation\n-f FILE Read from file FILE instead of /var/log/wtmp"
 
-#define HELP_klogd "usage: klogd [-n] [-c PRIORITY]\n\n-c	Print to console messages more urgent than PRIORITY (1-8)\"\n-n	Run in foreground\n-s	Use syscall instead of /proc"
+#define HELP_klogd "usage: klogd [-n] [-c PRIORITY]\n\nForward messages from the kernel ring buffer (read by dmesg) to syslogd.\n\n-c	Print to console messages more urgent than PRIORITY (1-8)\n-n	Run in foreground\n-s	Use syscall instead of /proc"
 
 #define HELP_ipcs "usage: ipcs [[-smq] -i shmid] | [[-asmq] [-tcplu]]\n\n-i Show specific resource\nResource specification:\n-a All (default)\n-m Shared memory segments\n-q Message queues\n-s Semaphore arrays\nOutput format:\n-c Creator\n-l Limits\n-p Pid\n-t Time\n-u Summary"
 
@@ -550,7 +554,7 @@
 
 #define HELP_tee "usage: tee [-ai] [FILE...]\n\nCopy stdin to each listed file, and also to stdout.\nFilename \"-\" is a synonym for stdout.\n\n-a	Append to files\n-i	Ignore SIGINT"
 
-#define HELP_tar "usage: tar [-cxt] [-fvohmjkOS] [-XTCf NAME] [--selinux] [FILE...]\n\nCreate, extract, or list files in a .tar (or compressed t?z) file.\n\nOptions:\nc  Create                x  Extract               t  Test (list)\nf  tar FILE (default -)  C  Change to DIR first   v  Verbose display\nJ  xz compression        j  bzip2 compression     z  gzip compression\no  Ignore owner          h  Follow symlinks       m  Ignore mtime\nO  Extract to stdout     X  exclude names in FILE T  include names in FILE\ns  Sort dirs (--sort)\n\n--exclude        FILENAME to exclude  --full-time         Show seconds with -tv\n--mode MODE      Adjust permissions   --owner NAME[:UID]  Set file ownership\n--mtime TIME     Override timestamps  --group NAME[:GID]  Set file group\n--sparse         Record sparse files  --selinux           Save/restore labels\n--restrict       All under one dir    --no-recursion      Skip dir contents\n--numeric-owner  Use numeric uid/gid, not user/group names\n--null           Filenames in -T FILE are null-separated, not newline\n--strip-components NUM  Ignore first NUM directory components when extracting\n--xform=SED      Modify filenames via SED expression (ala s/find/replace/g)\n-I PROG          Filter through PROG to compress or PROG -d to decompress\n\nFilename filter types. Create command line args aren't filtered, extract\ndefaults to --anchored, --exclude defaults to --wildcards-match-slash,\nuse no- prefix to disable:\n\n--anchored  Match name not path       --ignore-case       Case insensitive\n--wildcards Expand *?[] like shell    --wildcards-match-slash"
+#define HELP_tar "usage: tar [-cxt] [-fvohmjkOS] [-XTCf NAME] [--selinux] [FILE...]\n\nCreate, extract, or list files in a .tar (or compressed t?z) file.\n\nOptions:\nc  Create                x  Extract               t  Test (list)\nf  tar FILE (default -)  C  Change to DIR first   v  Verbose display\nJ  xz compression        j  bzip2 compression     z  gzip compression\no  Ignore owner          h  Follow symlinks       m  Ignore mtime\nO  Extract to stdout     X  exclude names in FILE T  include names in FILE\ns  Sort dirs (--sort)    Z  zstd compression\n\n--exclude        FILENAME to exclude  --full-time         Show seconds with -tv\n--mode MODE      Adjust permissions   --owner NAME[:UID]  Set file ownership\n--mtime TIME     Override timestamps  --group NAME[:GID]  Set file group\n--sparse         Record sparse files  --selinux           Save/restore labels\n--restrict       All under one dir    --no-recursion      Skip dir contents\n--numeric-owner  Use numeric uid/gid, not user/group names\n--null           Filenames in -T FILE are null-separated, not newline\n--strip-components NUM  Ignore first NUM directory components when extracting\n--xform=SED      Modify filenames via SED expression (ala s/find/replace/g)\n-I PROG          Filter through PROG to compress or PROG -d to decompress\n\nFilename filter types. Create command line args aren't filtered, extract\ndefaults to --anchored, --exclude defaults to --wildcards-match-slash,\nuse no- prefix to disable:\n\n--anchored  Match name not path       --ignore-case       Case insensitive\n--wildcards Expand *?[] like shell    --wildcards-match-slash"
 
 #define HELP_tail "usage: tail [-n|c NUMBER] [-f|F] [-s SECONDS] [FILE...]\n\nCopy last lines from files to stdout. If no files listed, copy from\nstdin. Filename \"-\" is a synonym for stdin.\n\n-n	Output the last NUMBER lines (default 10), +X counts from start\n-c	Output the last NUMBER bytes, +NUMBER counts from start\n-f	Follow FILE(s) by descriptor, waiting for more data to be appended\n-F	Follow FILE(s) by filename, waiting for more data, and retrying\n-s	Used with -F, sleep SECONDS between retries (default 1)"
 
@@ -574,7 +578,7 @@
 
 #define HELP_pkill "usage: pkill [-fnovx] [-SIGNAL|-l SIGNAL] [PATTERN] [-G GID,] [-g PGRP,] [-P PPID,] [-s SID,] [-t TERM,] [-U UID,] [-u EUID,]\n\n-l	Send SIGNAL (default SIGTERM)\n-V	Verbose\n-f	Check full command line for PATTERN\n-G	Match real Group ID(s)\n-g	Match Process Group(s) (0 is current user)\n-n	Newest match only\n-o	Oldest match only\n-P	Match Parent Process ID(s)\n-s	Match Session ID(s) (0 for current)\n-t	Match Terminal(s)\n-U	Match real User ID(s)\n-u	Match effective User ID(s)\n-v	Negate the match\n-x	Match whole command (not substring)"
 
-#define HELP_pgrep "usage: pgrep [-clfnovx] [-d DELIM] [-L SIGNAL] [PATTERN] [-G GID,] [-g PGRP,] [-P PPID,] [-s SID,] [-t TERM,] [-U UID,] [-u EUID,]\n\nSearch for process(es). PATTERN is an extended regular expression checked\nagainst command names.\n\n-c	Show only count of matches\n-d	Use DELIM instead of newline\n-L	Send SIGNAL instead of printing name\n-l	Show command name\n-f	Check full command line for PATTERN\n-G	Match real Group ID(s)\n-g	Match Process Group(s) (0 is current user)\n-n	Newest match only\n-o	Oldest match only\n-P	Match Parent Process ID(s)\n-s	Match Session ID(s) (0 for current)\n-t	Match Terminal(s)\n-U	Match real User ID(s)\n-u	Match effective User ID(s)\n-v	Negate the match\n-x	Match whole command (not substring)"
+#define HELP_pgrep "usage: pgrep [-aclfnovx] [-d DELIM] [-L SIGNAL] [PATTERN] [-G GID,] [-g PGRP,] [-P PPID,] [-s SID,] [-t TERM,] [-U UID,] [-u EUID,]\n\nSearch for process(es). PATTERN is an extended regular expression checked\nagainst command names.\n\n-a	Show the full command line\n-c	Show only count of matches\n-d	Use DELIM instead of newline\n-L	Send SIGNAL instead of printing name\n-l	Show command name\n-f	Check full command line for PATTERN\n-G	Match real Group ID(s)\n-g	Match Process Group(s) (0 is current user)\n-n	Newest match only\n-o	Oldest match only\n-P	Match Parent Process ID(s)\n-s	Match Session ID(s) (0 for current)\n-t	Match Terminal(s)\n-U	Match real User ID(s)\n-u	Match effective User ID(s)\n-v	Negate the match\n-x	Match whole command (not substring)"
 
 #define HELP_iotop "usage: iotop [-AaKObq] [-n NUMBER] [-d SECONDS] [-p PID,] [-u USER,]\n\nRank processes by I/O.\n\n-A	All I/O, not just disk\n-a	Accumulated I/O (not percentage)\n-H	Show threads\n-K	Kilobytes\n-k	Fallback sort FIELDS (default -[D]IO,-ETIME,-PID)\n-m	Maximum number of tasks to show\n-O	Only show processes doing I/O\n-o	Show FIELDS (default PID,PR,USER,[D]READ,[D]WRITE,SWAP,[D]IO,COMM)\n-s	Sort by field number (0-X, default 6)\n-b	Batch mode (no tty)\n-d	Delay SECONDS between each cycle (default 3)\n-n	Exit after NUMBER iterations\n-p	Show these PIDs\n-u	Show these USERs\n-q	Quiet (no header lines)\n\nCursor LEFT/RIGHT to change sort, UP/DOWN move list, space to force\nupdate, R to reverse sort, Q to exit."
 
diff --git a/android/mac/generated/newtoys.h b/android/mac/generated/newtoys.h
index 45b39f49..69c22588 100644
--- a/android/mac/generated/newtoys.h
+++ b/android/mac/generated/newtoys.h
@@ -211,6 +211,7 @@ USE_NETSTAT(NEWTOY(netstat, "pWrxwutneal", TOYFLAG_BIN))
 USE_NICE(NEWTOY(nice, "^<1n#", TOYFLAG_BIN))
 USE_NL(NEWTOY(nl, "v#=1l#w#<0=6b:n:s:E", TOYFLAG_USR|TOYFLAG_BIN))
 USE_NOHUP(NEWTOY(nohup, "<1^", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(125)))
+USE_NOLOGIN(NEWTOY(nologin, 0, TOYFLAG_BIN|TOYFLAG_NOHELP))
 USE_NPROC(NEWTOY(nproc, "(all)", TOYFLAG_USR|TOYFLAG_BIN))
 USE_NSENTER(NEWTOY(nsenter, "<1a(all)F(no-fork)t#<1(target)C(cgroup):; i(ipc):; m(mount):; n(net):; p(pid):; u(uts):; U(user):; ", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_STAYROOT))
 USE_OD(NEWTOY(od, "j#vw#<1=16N#xsodcbA:t*", TOYFLAG_USR|TOYFLAG_BIN))
@@ -220,7 +221,7 @@ USE_PARTPROBE(NEWTOY(partprobe, "<1", TOYFLAG_SBIN))
 USE_PASSWD(NEWTOY(passwd, ">1a:dlu", TOYFLAG_STAYROOT|TOYFLAG_USR|TOYFLAG_BIN))
 USE_PASTE(NEWTOY(paste, "d:s", TOYFLAG_USR|TOYFLAG_BIN))
 USE_PATCH(NEWTOY(patch, ">2(no-backup-if-mismatch)(dry-run)F#g#fulp#v(verbose)@d:i:Rs(quiet)[!sv]", TOYFLAG_USR|TOYFLAG_BIN))
-USE_PGREP(NEWTOY(pgrep, "?cld:u*U*t*s*P*g*G*fnovxL:[-no]", TOYFLAG_USR|TOYFLAG_BIN))
+USE_PGREP(NEWTOY(pgrep, "acld:u*U*t*s*P*g*G*fnovxL:[-no]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_PIDOF(NEWTOY(pidof, "so:x", TOYFLAG_BIN))
 USE_PING(NEWTOY(ping, "<1>1m#t#<0>255=64c#<0=3s#<0>4064=56i%W#<0=3w#<0qf46I:[-46]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_PING(OLDTOY(ping6, ping, TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
@@ -290,7 +291,7 @@ USE_SYSCTL(NEWTOY(sysctl, "^neNqwpaA[!ap][!aq][!aw][+aA]", TOYFLAG_SBIN))
 USE_SYSLOGD(NEWTOY(syslogd,">0l#<1>8=8R:b#<0>99=1s#<0=200m#<0>71582787=20O:p:f:a:nSKLD", TOYFLAG_SBIN|TOYFLAG_STAYROOT))
 USE_TAC(NEWTOY(tac, NULL, TOYFLAG_USR|TOYFLAG_BIN))
 USE_TAIL(NEWTOY(tail, "?fFs:c(bytes)-n(lines)-[-cn][-fF]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
-USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
+USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*Z(zstd)o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
 USE_TASKSET(NEWTOY(taskset, "<1^pa", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TCPSVD(NEWTOY(tcpsvd, "^<3c#=30<1b#=20<0C:u:l:hEv", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TEE(NEWTOY(tee, "ia", TOYFLAG_USR|TOYFLAG_BIN))
@@ -307,6 +308,7 @@ USE_SH(OLDTOY(toysh, sh, TOYFLAG_BIN))
 USE_TR(NEWTOY(tr, "^<1>2Ccstd[+cC]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TRACEROUTE(NEWTOY(traceroute, "<1>2i:f#<1>255=1z#<0>86400=0g*w#<0>86400=5t#<0>255=0s:q#<1>255=3p#<1>65535=33434m#<1>255=30rvndlIUF64", TOYFLAG_STAYROOT|TOYFLAG_USR|TOYFLAG_BIN))
 USE_TRACEROUTE(OLDTOY(traceroute6,traceroute, TOYFLAG_STAYROOT|TOYFLAG_USR|TOYFLAG_BIN))
+USE_SH(NEWTOY(trap, "lp", TOYFLAG_NOFORK))
 USE_TRUE(NEWTOY(true, NULL, TOYFLAG_BIN|TOYFLAG_NOHELP|TOYFLAG_MAYFORK))
 USE_TRUNCATE(NEWTOY(truncate, "<1s:|c", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TS(NEWTOY(ts, "ims", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
diff --git a/config-device b/config-device
index 694720c5..d4b9f02f 100644
--- a/config-device
+++ b/config-device
@@ -82,7 +82,7 @@ CONFIG_DEVMEM=y
 CONFIG_DF=y
 # CONFIG_DHCP6 is not set
 # CONFIG_DHCPD is not set
-# CONFIG_DHCP is not set
+CONFIG_DHCP=y
 CONFIG_DIFF=y
 CONFIG_DIRNAME=y
 CONFIG_DMESG=y
@@ -171,7 +171,6 @@ CONFIG_IOTOP=y
 CONFIG_KILLALL=y
 CONFIG_KILL=y
 # CONFIG_KLOGD is not set
-# CONFIG_KLOGD_SOURCE_RING_BUFFER is not set
 # CONFIG_LAST is not set
 # CONFIG_LINK is not set
 # CONFIG_LINUX32 is not set
@@ -200,11 +199,6 @@ CONFIG_MICROCOM=y
 # CONFIG_MIX is not set
 CONFIG_MKDIR=y
 CONFIG_MKDIR_Z=y
-# CONFIG_MKE2FS_EXTENDED is not set
-# CONFIG_MKE2FS_GEN is not set
-# CONFIG_MKE2FS is not set
-# CONFIG_MKE2FS_JOURNAL is not set
-# CONFIG_MKE2FS_LABEL is not set
 CONFIG_MKFIFO=y
 CONFIG_MKFIFO_Z=y
 CONFIG_MKNOD=y
@@ -224,6 +218,7 @@ CONFIG_NETCAT=y
 CONFIG_NETSTAT=y
 CONFIG_NICE=y
 CONFIG_NL=y
+# CONFIG_NOLOGIN is not set
 CONFIG_NOHUP=y
 CONFIG_NPROC=y
 CONFIG_NSENTER=y
diff --git a/config-linux b/config-linux
index 140293ce..378680fe 100644
--- a/config-linux
+++ b/config-linux
@@ -171,7 +171,6 @@ CONFIG_INSTALL=y
 # CONFIG_KILLALL is not set
 # CONFIG_KILL is not set
 # CONFIG_KLOGD is not set
-# CONFIG_KLOGD_SOURCE_RING_BUFFER is not set
 # CONFIG_LAST is not set
 # CONFIG_LINK is not set
 # CONFIG_LINUX32 is not set
@@ -200,11 +199,6 @@ CONFIG_MICROCOM=y
 # CONFIG_MIX is not set
 CONFIG_MKDIR=y
 # CONFIG_MKDIR_Z is not set
-# CONFIG_MKE2FS_EXTENDED is not set
-# CONFIG_MKE2FS_GEN is not set
-# CONFIG_MKE2FS is not set
-# CONFIG_MKE2FS_JOURNAL is not set
-# CONFIG_MKE2FS_LABEL is not set
 # CONFIG_MKFIFO is not set
 # CONFIG_MKFIFO_Z is not set
 # CONFIG_MKNOD is not set
@@ -225,6 +219,7 @@ CONFIG_MV=y
 # CONFIG_NICE is not set
 CONFIG_NL=y
 # CONFIG_NOHUP is not set
+# CONFIG_NOLOGIN is not set
 CONFIG_NPROC=y
 # CONFIG_NSENTER is not set
 CONFIG_OD=y
diff --git a/config-mac b/config-mac
index d8468c7e..aaca4b46 100644
--- a/config-mac
+++ b/config-mac
@@ -171,7 +171,6 @@ CONFIG_INSTALL=y
 # CONFIG_KILLALL is not set
 # CONFIG_KILL is not set
 # CONFIG_KLOGD is not set
-# CONFIG_KLOGD_SOURCE_RING_BUFFER is not set
 # CONFIG_LAST is not set
 # CONFIG_LINK is not set
 # CONFIG_LINUX32 is not set
@@ -200,11 +199,6 @@ CONFIG_MICROCOM=y
 # CONFIG_MIX is not set
 CONFIG_MKDIR=y
 # CONFIG_MKDIR_Z is not set
-# CONFIG_MKE2FS_EXTENDED is not set
-# CONFIG_MKE2FS_GEN is not set
-# CONFIG_MKE2FS is not set
-# CONFIG_MKE2FS_JOURNAL is not set
-# CONFIG_MKE2FS_LABEL is not set
 # CONFIG_MKFIFO is not set
 # CONFIG_MKFIFO_Z is not set
 # CONFIG_MKNOD is not set
@@ -225,6 +219,7 @@ CONFIG_MV=y
 # CONFIG_NICE is not set
 CONFIG_NL=y
 # CONFIG_NOHUP is not set
+# CONFIG_NOLOGIN is not set
 # CONFIG_NPROC is not set
 # CONFIG_NSENTER is not set
 CONFIG_OD=y
diff --git a/lib/dirtree.c b/lib/dirtree.c
index 2d120890..5634759e 100644
--- a/lib/dirtree.c
+++ b/lib/dirtree.c
@@ -201,7 +201,7 @@ int dirtree_recurse(struct dirtree *node,
   }
 
 done:
-  closedir(dir);
+  if (dir) closedir(dir);
   node->dirfd = -1;
 
   return (new == DIRTREE_ABORTVAL) ? DIRTREE_ABORT : flags;
diff --git a/lib/lib.c b/lib/lib.c
index 75ac51dc..b4ff4f79 100644
--- a/lib/lib.c
+++ b/lib/lib.c
@@ -532,6 +532,17 @@ int anystart(char *s, char **try)
   return 0;
 }
 
+// does this entire string match one of the strings in try[]?
+// Returns 0 if not, index+1 if so
+int anystr(char *s, char **try)
+{
+  char **and = try;
+
+  while (*try) if (!strcmp(s, *try++)) return try-and;
+
+  return 0;
+}
+
 int same_file(struct stat *st1, struct stat *st2)
 {
   return st1->st_ino==st2->st_ino && st1->st_dev==st2->st_dev;
diff --git a/lib/lib.h b/lib/lib.h
index dd18cdf2..e353921b 100644
--- a/lib/lib.h
+++ b/lib/lib.h
@@ -233,6 +233,7 @@ char *strend(char *str, char *suffix);
 int strstart(char **a, char *b);
 int strcasestart(char **a, char *b);
 int anystart(char *s, char **try);
+int anystr(char *s, char **try);
 int same_file(struct stat *st1, struct stat *st2);
 int same_dev_ino(struct stat *st, struct dev_ino *di);
 off_t fdlength(int fd);
diff --git a/lib/portability.h b/lib/portability.h
index a62a0cb9..324ddc81 100644
--- a/lib/portability.h
+++ b/lib/portability.h
@@ -128,49 +128,25 @@ void *memmem(const void *haystack, size_t haystack_length,
 
 // Work out how to do endianness
 
+#define IS_LITTLE_ENDIAN (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
+#define IS_BIG_ENDIAN (!IS_LITTLE_ENDIAN)
+
 #ifdef __APPLE__
 
 #include <libkern/OSByteOrder.h>
-
-#ifdef __BIG_ENDIAN__
-#define IS_BIG_ENDIAN 1
-#else
-#define IS_BIG_ENDIAN 0
-#endif
-
 #define bswap_16(x) OSSwapInt16(x)
 #define bswap_32(x) OSSwapInt32(x)
 #define bswap_64(x) OSSwapInt64(x)
-
 #elif defined(__FreeBSD__) || defined(__OpenBSD__)
-
 #include <sys/endian.h>
-
-#if _BYTE_ORDER == _BIG_ENDIAN
-#define IS_BIG_ENDIAN 1
-#else
-#define IS_BIG_ENDIAN 0
-#endif
-
 #define bswap_16(x) bswap16(x)
 #define bswap_32(x) bswap32(x)
 #define bswap_64(x) bswap64(x)
-
 #else
-
 #include <byteswap.h>
-#include <endian.h>
-
-#if __BYTE_ORDER == __BIG_ENDIAN
-#define IS_BIG_ENDIAN 1
-#else
-#define IS_BIG_ENDIAN 0
-#endif
-
 #endif
 
 #if IS_BIG_ENDIAN
-#define IS_LITTLE_ENDIAN 0
 #define SWAP_BE16(x) (x)
 #define SWAP_BE32(x) (x)
 #define SWAP_BE64(x) (x)
@@ -178,7 +154,6 @@ void *memmem(const void *haystack, size_t haystack_length,
 #define SWAP_LE32(x) bswap_32(x)
 #define SWAP_LE64(x) bswap_64(x)
 #else
-#define IS_LITTLE_ENDIAN 1
 #define SWAP_BE16(x) bswap_16(x)
 #define SWAP_BE32(x) bswap_32(x)
 #define SWAP_BE64(x) bswap_64(x)
diff --git a/main.c b/main.c
index 397b727b..69cc8afc 100644
--- a/main.c
+++ b/main.c
@@ -240,8 +240,12 @@ void toy_exec_which(struct toy_list *which, char *argv[])
   // so convert to integers. (LP64 says sizeof(long)==sizeof(pointer).)
   // Signed typecast so stack growth direction is irrelevant: we're measuring
   // the distance between two pointers on the same stack, hence the labs().
-  if (!CFG_TOYBOX_NORECURSE && toys.stacktop)
+  if (!CFG_TOYBOX_NORECURSE && toys.stacktop) {
+    int i;
+
     if (labs((long)toys.stacktop-(long)&which)>24000) return;
+    for (i = 0; i<NSIG; i++) signal(i, SIG_DFL);
+  }
 
   // Return if we need to re-exec to acquire root via suid bit.
   if (toys.which && (which->flags&TOYFLAG_ROOTONLY) && toys.wasroot) return;
@@ -316,9 +320,6 @@ int main(int argc, char *argv[])
     toys.stacktop = &stack_start;
   }
 
-  // Android before O had non-default SIGPIPE, 7 years = remove in Sep 2024.
-  if (CFG_TOYBOX_ON_ANDROID) signal(SIGPIPE, SIG_DFL);
-
   if (CFG_TOYBOX) {
     // Call the multiplexer with argv[] as its arguments so it can toy_find()
     toys.argv = argv-1;
diff --git a/mkroot/mkroot.sh b/mkroot/mkroot.sh
index d2cbd44f..90e603af 100755
--- a/mkroot/mkroot.sh
+++ b/mkroot/mkroot.sh
@@ -203,9 +203,9 @@ get_target_config()
     # This could use the same VIRT board as armv7, but let's demonstrate a
     # different one requiring a separate device tree binary.
     KARCH=arm KARGS=ttyAMA0 VMLINUX=zImage
-    QEMU="arm -M versatilepb -net nic,model=rtl8139 -net user"
+    QEMU="arm -M versatilepb"
     KCONF="$(be2csv CPU_ARM926T MMU VFP ARM_THUMB AEABI ARCH_VERSATILE ATAGS \
-      DEPRECATED_PARAM_STRUCT BLK_DEV_SD NET_VENDOR_REALTEK 8139CP \
+      DEPRECATED_PARAM_STRUCT BLK_DEV_SD GPIOLIB NET_VENDOR_SMSC SMC91X \
       ARM_ATAG_DTB_COMPAT{,_CMDLINE_EXTEND} PCI{,_VERSATILE} \
       SERIAL_AMBA_PL011{,_CONSOLE} RTC_{CLASS,DRV_PL031,HCTOSYS} \
       SCSI{,_LOWLEVEL,_SYM53C8XX_{2,MMIO,DMA_ADDRESSING_MODE=0}})"
@@ -245,7 +245,8 @@ get_target_config()
   elif [ "$CROSS" == microblaze ]; then
     QEMU_M=petalogix-s3adsp1800 KARCH=microblaze KARGS=ttyUL0
     KCONF="$(be2csv MMU CPU_BIG_ENDIAN SERIAL_UARTLITE{,_CONSOLE} \
-      XILINX_{EMACLITE,MICROBLAZE0_{FAMILY="spartan3adsp",USE_{{MSR,PCMP}_INSTR,BARREL,HW_MUL}=1}})"
+      XILINX_{EMACLITE,MICROBLAZE0_{FAMILY="spartan3adsp",USE_{{MSR,PCMP}_INSTR,BARREL,HW_MUL}=1}} \
+      NET_VENDOR_XILINX)"
   elif [ "${CROSS#mips}" != "$CROSS" ]; then # mips mipsel mips64 mips64el
     QEMU_M=malta KARCH=mips
     KCONF="$(be2csv MIPS_MALTA CPU_MIPS32_R2 BLK_DEV_SD NET_VENDOR_AMD PCNET32 \
@@ -254,8 +255,9 @@ get_target_config()
       KCONF+=,64BIT,CPU_MIPS64_R1,MIPS32_O32
     [ "${CROSS%el}" != "$CROSS" ] && KCONF+=,CPU_LITTLE_ENDIAN
   elif [ "$CROSS" == or1k ]; then
-    KARCH=openrisc QEMU_M=or1k-sim KARGS=ttyS0
-    KCONF="$(be2csv ETHOC SERIO SERIAL_OF_PLATFORM SERIAL_8250{,_CONSOLE})"
+    KARCH=openrisc QEMU_M=virt KARGS=ttyS0
+    KCONF="$(be2csv ETHOC SERIO SERIAL_OF_PLATFORM SERIAL_8250{,_CONSOLE} \
+      VIRTIO_{MENU,NET,BLK,PCI,MMIO} POWER_RESET{,_SYSCON{,_POWEROFF}} SYSCON_REBOOT_MODE)"
   elif [ "$CROSS" == powerpc ]; then
     KARCH=powerpc QEMU="ppc -M g3beige"
     KCONF="$(be2csv ALTIVEC PATA_MACIO BLK_DEV_SD MACINTOSH_DRIVERS SERIO \
@@ -297,7 +299,7 @@ get_target_config()
     KCONF="$(be2csv CPU_SUBTYPE_SH7751R MMU VSYSCALL SH_{FPU,RTS7751R2D} PCI \
       RTS7751R2D_PLUS SERIAL_SH_SCI{,_CONSOLE} NET_VENDOR_REALTEK 8139CP \
       BLK_DEV_SD ATA{,_SFF,_BMDMA} PATA_PLATFORM BINFMT_ELF_FDPIC \
-      CMDLINE_EXTEND MEMORY_START=0x0c000000)"
+      CMDLINE_FROM_BOOTLOADER MEMORY_START=0x0c000000)"
 #see also SPI{,_SH_SCI} MFD_SM501 RTC_{CLASS,DRV_{R9701,SH},HCTOSYS}
     [ "$CROSS" == sh4eb ] && KCONF+=,CPU_BIG_ENDIAN
   else die "Unknown \$CROSS=$CROSS"
@@ -306,7 +308,7 @@ get_target_config()
 }
 
 # Linux kernel .config symbols common to all architectures
-: ${GENERIC_KCONF:=$(be2csv PANIC_TIMEOUT=1 NO_HZ HIGH_RES_TIMERS RD_GZIP \
+: ${GENERIC_KCONF:=$(be2csv PANIC_TIMEOUT=1 NO_HZ_IDLE HIGH_RES_TIMERS RD_GZIP \
   BINFMT_{ELF,SCRIPT} BLK_DEV{,_INITRD,_LOOP} EXT4_{FS,USE_FOR_EXT2} \
   VFAT_FS FAT_DEFAULT_UTF8 MISC_FILESYSTEMS NLS_{CODEPAGE_437,ISO8859_1} \
   SQUASHFS{,_XATTR,_ZLIB} TMPFS{,_POSIX_ACL} DEVTMPFS{,_MOUNT} \
diff --git a/mkroot/packages/dropbear b/mkroot/packages/dropbear
index 9a4adcb8..3fd70e3b 100755
--- a/mkroot/packages/dropbear
+++ b/mkroot/packages/dropbear
@@ -4,11 +4,11 @@
 
 echo === download source
 
-download e6d119755acdf9104d7ba236b1242696940ed6dd \
-  http://downloads.sf.net/libpng/zlib-1.2.11.tar.gz
+download f535367b1a11e2f9ac3bec723fb007fbc0d189e5 \
+  https://www.zlib.net/fossils/zlib-1.3.1.tar.gz
 
-download 9719ea91b5ce8d93ee9a50b5c3a5bcd628736181 \
-  https://matt.ucc.asn.au/dropbear/releases/dropbear-2022.82.tar.bz2
+download 216ae176572dc008e128042eae82b6aacfdc8a51 \
+  https://matt.ucc.asn.au/dropbear/releases/dropbear-2024.86.tar.bz2
 
 echo === Native build static zlib
 
@@ -28,8 +28,8 @@ echo 'echo "$@"' > config.sub &&
 ZLIB="$(echo ../zlib*)" &&
 CC="$CROSS_COMPILE"cc CFLAGS="-I $ZLIB -O2" LDFLAGS="-L $ZLIB" ./configure --enable-static \
   --disable-wtmp --host="$(basename "$CROSS_COMPILE" | sed 's/-$//')" &&
-sed -i 's@/usr/bin/dbclient@ssh@' options.h &&
-sed -i 's@\(#define NON_INETD_MODE\) 1@\1 0@' default_options.h &&
+sed -i 's@/usr/bin/dbclient@ssh@;s@\(#define NON_INETD_MODE\) 1@\1 0@' \
+  src/default_options.h &&
 make -j $(nproc) PROGRAMS="dropbear dbclient dropbearkey dropbearconvert scp" MULTI=1 SCPPROGRESS=1 &&
 ${CROSS_COMPILE}strip dropbearmulti &&
 mkdir -p "$ROOT"/{bin,etc/{rc,dropbear},var/log} &&
diff --git a/scripts/help.txt b/scripts/help.txt
index feca0a8d..5117f977 100644
--- a/scripts/help.txt
+++ b/scripts/help.txt
@@ -12,8 +12,8 @@
                     to show all failures.
   clean           - Delete temporary files.
   distclean       - Delete everything that isn't shipped.
-  install_airlock - Install toybox and host toolchain into $PREFIX directory
-                    (providing $PATH for hermetic builds).
+  install_airlock - Install toybox and host toolchain (plus $TOOLCHAIN if any)
+                    into $PREFIX directory, providing $PATH for hermetic builds.
   install_flat    - Install toybox into $PREFIX directory.
   install         - Install toybox into subdirectories of $PREFIX.
   uninstall_flat  - Remove toybox from $PREFIX directory.
diff --git a/scripts/install.sh b/scripts/install.sh
index 22bb472c..2e4fde1a 100755
--- a/scripts/install.sh
+++ b/scripts/install.sh
@@ -106,7 +106,7 @@ done
 # For now symlink the host version. This list must go away by 1.0.
 
 PENDING="expr git tr bash sh gzip   awk bison flex make ar"
-TOOLCHAIN+=" as cc ld objdump  bc gcc"
+TOOLCHAIN="${TOOLCHAIN//,/ } as cc ld objdump  bc gcc"
 
 # Tools needed to build packages
 for i in $TOOLCHAIN $PENDING $HOST_EXTRA
diff --git a/scripts/mkstatus.py b/scripts/mkstatus.py
index 41a1bed2..b9b333c3 100755
--- a/scripts/mkstatus.py
+++ b/scripts/mkstatus.py
@@ -55,7 +55,7 @@ conv = [("posix", '<a href="http://pubs.opengroup.org/onlinepubs/9699919799/util
         ("sash_cmd", "", '#%s#'), ("sbase_cmd", "", '@%s@'),
         ("beastiebox_cmd", "", '*%s*'), ("tizen_cmd", "", '$%s$'),
         ("fhs_cmd", "", '-%s-'), ("yocto_cmd", "", ".%s."),
-        ("shell", "", "%%%s%%"),
+        ("buildroot_cmd", "", "~%s~"), ("shell", "", "%%%s%%"),
         ("request", '<a href="https://man7.org/linux/man-pages/man1/%s.1.html">%%s</a>', '+%s+')]
 
 def categorize(reverse, i, skippy=""):
diff --git a/scripts/runtest.sh b/scripts/runtest.sh
index 1289d4c6..9ee6cd80 100644
--- a/scripts/runtest.sh
+++ b/scripts/runtest.sh
@@ -102,7 +102,9 @@ skipnot()
 # Skip this test (rest of command line) when not running toybox.
 toyonly()
 {
-  IS_TOYBOX="$("$C" --version 2>/dev/null)"
+  [ -z "$TEST_HOST" ] && IS_TOYBOX=toybox
+  : ${IS_TOYBOX:=$("$C" --version 2>/dev/null | grep -o toybox)} \
+    ${IS_TOYBOX:="$(basename $(readlink -f "$C"))"}
   # Ideally we'd just check for "toybox", but toybox sed lies to make autoconf
   # happy, so we have at least two things to check for.
   case "$IS_TOYBOX" in
@@ -145,7 +147,7 @@ testing()
   if ! verbose_has quiet && { [ -n "$DIFF" ] || verbose_has spam; }
   then
     [ ! -z "$4" ] && printf "%s\n" "echo -ne \"$4\" > input"
-    printf "%s\n" "echo -ne '$5' |$EVAL $2"
+    printf "%s\n" "echo -ne '$5' |$EVAL ${2@Q}"
     [ -n "$DIFF" ] && printf "%s\n" "$DIFF"
   fi
 
diff --git a/tests/cut.test b/tests/cut.test
index c354b9b2..83dbbd2f 100755
--- a/tests/cut.test
+++ b/tests/cut.test
@@ -18,7 +18,7 @@ testcmd "-b overlaps" "-b 1-3,2-5,7-9,9-10 abc.txt" \
   "one:to:th\nalphabeta\nthe qick \n" "" ""
 testcmd "-b encapsulated" "-b 3-8,4-6 abc.txt" "e:two:\npha:be\ne quic\n" \
   "" ""
-testcmd "-bO overlaps" "-O ' ' -b 1-3,2-5,7-9,9-10 abc.txt" \
+toyonly testcmd "-bO overlaps" "-O ' ' -b 1-3,2-5,7-9,9-10 abc.txt" \
   "one:t o:th\nalpha beta\nthe q ick \n" "" ""
 testcmd "high-low error" "-b 8-3 abc.txt 2>/dev/null || echo err" "err\n" \
   "" ""
@@ -36,7 +36,7 @@ toyonly testcmd "-c japan.txt" '-c 3-6,9-12 "$FILES/utf8/japan.txt"' \
 toyonly testcmd "-C test1.txt" '-C -1 "$FILES/utf8/test1.txt"' "l̴̗̞̠\n" "" ""
 
 # substitute for awk
-testcmd "-DF" "-DF 2,7,5" \
+toyonly testcmd "-DF" "-DF 2,7,5" \
   "said and your\nare\nis demand. supply\nforecast :\nyou you better,\n\nEm: Took hate\n" "" \
 "Bother, said Pooh. It's your husband, and he has a gun.
 Cheerios are donut seeds.
@@ -45,7 +45,7 @@ Weather forecast for tonight : dark.
 Apple: you can buy better, but you can't pay more.
 Subcalifragilisticexpialidocious.
 Auntie Em: Hate you, hate Kansas. Took the dog. Dorothy."
-testcmd "-DF 2" "-DF 7,1,3-6,2-5" \
+toyonly testcmd "-DF 2" "-DF 7,1,3-6,2-5" \
   "seven one three four five six two three four five\n" "" \
   "one two three four five six seven eight nine\n"
 
diff --git a/tests/echo.test b/tests/echo.test
index bd2c3ff7..fef5db90 100755
--- a/tests/echo.test
+++ b/tests/echo.test
@@ -46,7 +46,7 @@ testcmd "-e \p" "-e '\\p'" "\\p\n" "" ""
 testcmd "-En" "-En 'one\ntwo'" 'one\\ntwo' "" ""
 testcmd "-eE" "-eE '\e'" '\\e\n' "" ""
 
-# This is how bash's built-in echo behaves, but now how /bin/echo behaves.
+# This is how bash's built-in echo behaves, but not how /bin/echo behaves.
 toyonly testcmd "" "-e 'a\x123\ufb3bbc' | od -An -tx1" \
   " 61 12 33 ef ac bb 62 63 0a\n" "" ""
 
diff --git a/tests/factor.test b/tests/factor.test
index 90151851..eb861f4f 100755
--- a/tests/factor.test
+++ b/tests/factor.test
@@ -20,8 +20,8 @@ testing "10000000019" "factor 10000000019" \
 testing "3 6 from stdin" "factor" "3: 3\n6: 2 3\n" "" "3 6"
 testing "stdin newline" "factor" "3: 3\n6: 2 3\n" "" "3\n6\n"
 
-testing "-h" "factor -h $(((1<<63)-26))" \
+toyonly testing "-h" "factor -h $(((1<<63)-26))" \
   "9223372036854775782: 2 3^4 17 23 319279 456065899\n" "" ""
-testing "-x" "factor -x $(((1<<63)-20))" \
+toyonly testing "-x" "factor -x $(((1<<63)-20))" \
   "7fffffffffffffec: 2 2 3 283 43f2ba978e663\n" "" ""
 
diff --git a/tests/file.test b/tests/file.test
index 8dddfe3f..e87d5a3a 100755
--- a/tests/file.test
+++ b/tests/file.test
@@ -24,12 +24,12 @@ rm -f empty
 testing "script" "file input | grep -o ' script'" " script\n" "#!/bin/bash\n" ""
 testing "script with spaces" "file input | grep -o ' script'" " script\n" \
   "#!  /bin/bash\n" ""
-testing "env script" "file input | egrep -o '(python|script)' | sort" \
+testing "env script" "file input | tr P p | egrep -o '(python|script)' | sort" \
   "python\nscript\n" "#! /usr/bin/env python\n" ""
 testing "ascii" "file input" "input: ASCII text\n" "Hello, world!\n" ""
 testing "utf-8" \
-  "file \"$FILES\"/utf8/japan.txt | egrep -o '(UTF-8|text)' | LANG=c sort" \
-  "UTF-8\ntext\n" "" ""
+  "file \"$FILES\"/utf8/japan.txt | egrep -o 'UTF-8 text' | LANG=c sort" \
+  "UTF-8 text\n" "" ""
 
 # TODO each of these has multiple options we could test
 testing "java class" \
@@ -37,8 +37,9 @@ testing "java class" \
   "Java class\nversion 53.0\n" "" ""
 
 echo "cafebabe000000020100000700000003000040000000d9300000000e0100000c8000000200014000000098500000000e" | xxd -r -p > universal
-testcmd "mach-o universal" "universal" \
-  "universal: Mach-O universal binary with 2 architectures: [x86_64] [arm64]\n" "" ""
+testcmd "mach-o universal" \
+  "universal | egrep -o '(Mach-O|universal|x86_64|arm64)' | sort -u" \
+  "Mach-O\narm64\nuniversal\nx86_64\n" "" ""
 rm universal
 
 test_line "tar file" "tar/tar.tar" "POSIX tar archive (GNU)\n" "" ""
@@ -65,13 +66,14 @@ rm -f android.dex
 # These actually test a lot of the ELF code: 32-/64-bit, arm/arm64, PT_INTERP,
 # the two kinds of NDK ELF note, BuildID, and stripped/not stripped.
 toyonly test_line "Android NDK full ELF note" "elf/ndk-elf-note-full" \
-    "ELF shared object, 64-bit LSB arm64, dynamic (/system/bin/linker64), for Android 24, built by NDK r19b (5304403), BuildID=0c712b8af424d57041b85326f0000fadad38ee0a, not stripped\n" "" ""
+  "ELF shared object, 64-bit LSB arm64, dynamic (/system/bin/linker64), for Android 24, built by NDK r19b (5304403), BuildID=0c712b8af424d57041b85326f0000fadad38ee0a, not stripped\n" "" ""
 toyonly test_line "Android NDK short ELF note" "elf/ndk-elf-note-short" \
-    "ELF shared object, 32-bit LSB arm, EABI5, soft float, dynamic (/system/bin/linker), for Android 28, BuildID=da6a5f4ca8da163b9339326e626d8a3c, stripped\n" "" ""
+  "ELF shared object, 32-bit LSB arm, EABI5, soft float, dynamic (/system/bin/linker), for Android 28, BuildID=da6a5f4ca8da163b9339326e626d8a3c, stripped\n" "" ""
 toyonly test_line "ELF static fdpic" "elf/fdstatic" \
-    "ELF executable (fdpic), 32-bit MSB sh, static, stripped\n" "" ""
+  "ELF executable (fdpic), 32-bit MSB sh, static, stripped\n" "" ""
 echo -ne '\x7fELF\00000000000000000000000000000000000000000000' > bad-bits
-testing "ELF bad bits" "file bad-bits" "bad-bits: ELF (bad type 12336), (bad class -1) (bad endian 48) unknown arch 12336\n" "" ""
+testing "ELF bad bits" "file bad-bits | egrep -o '(ELF|unknown)'" \
+  "ELF\nunknown\n" "" ""
 rm -f bad-bits
 
 testing "broken symlink" "file dangler" "dangler: broken symbolic link to $BROKEN\n" "" ""
diff --git a/tests/hexdump.test b/tests/hexdump.test
index e319957c..1a2955f8 100755
--- a/tests/hexdump.test
+++ b/tests/hexdump.test
@@ -2,6 +2,7 @@
 
 [ -f testing.sh ] && . testing.sh
 
+[ -n "$TEST_HOST" ] && NOSPACE=1
 testcmd "simple file" "input" "0000000 6973 706d 656c 000a\n0000007\n" "simple\\n" ""
 testcmd "simple file -b" "-b input" "0000000 163 151 155 160 154 145 012\n0000007\n" "simple\\n" ""
 testcmd "simple file -c" "-c input" "0000000   s   i   m   p   l   e  \\\\n\n0000007\n" "simple\\n" ""
diff --git a/tests/iconv.test b/tests/iconv.test
index d0a3cb1d..39718f5c 100755
--- a/tests/iconv.test
+++ b/tests/iconv.test
@@ -10,7 +10,7 @@
 echo -ne "\x24\xe2\x82\xac\xf0\x90\x90\xb7" > chars
 
 #testing "name" "command" "result" "infile" "stdin"
-
+utf8locale
 testing "" "iconv chars | xxd -p" "24e282acf09090b7\n" "" ""
 testing "-t UTF-16BE" "iconv -t UTF-16BE chars | xxd -p" "002420acd801dc37\n" "" ""
 testing "-t UTF-16LE" "iconv -t UTF-16LE chars | xxd -p" "2400ac2001d837dc\n" "" ""
diff --git a/tests/pgrep.test b/tests/pgrep.test
index 8db848f8..59570066 100644
--- a/tests/pgrep.test
+++ b/tests/pgrep.test
@@ -11,7 +11,7 @@ killall yes >/dev/null 2>&1
 #testing "name" "command" "result" "infile" "stdin"
 
 # Starting processes to test pgrep command
-yes >/dev/null &
+yes and no >/dev/null &
 proc=$!
 #echo "# Process created with id: $proc"
 sleep .1
@@ -24,11 +24,21 @@ testing "pattern" "pgrep yes" "$proc\n" "" ""
 testing "wildCardPattern" "pgrep ^y.*s$" "$proc\n" "" ""
 testing "-l pattern" "pgrep -l yes" "$proc yes\n" "" ""
 testing "-f pattern" "pgrep -f yes" "$proc\n" "" ""
+testing "-a pattern" "pgrep -a yes" "$proc yes and no\n" "" ""
+testing "-la pattern" "pgrep -la yes" "$proc yes and no\n" "" ""
+testing "-fa pattern" "pgrep -fa yes" "$proc yes and no\n" "" ""
+testing "-lf pattern" "pgrep -lf yes" "$proc yes\n" "" ""
+testing "-fa pattern" "pgrep -fa yes" "$proc yes and no\n" "" ""
+testing "-lfa pattern" "pgrep -lfa yes" "$proc yes and no\n" "" ""
 testing "-n pattern" "pgrep -n yes" "$proc\n" "" ""
 testing "-o pattern" "pgrep -o yes" "$proc\n" "" ""
 testing "-s" "pgrep -s $session_id yes" "$proc\n" "" ""
 testing "-P" "pgrep -P $proc_parent yes" "$proc\n" "" ""
 
+testing "-f 'full command line'" "pgrep -f 'yes and no'" "$proc\n" "" ""
+testing "-l 'full command line nomatch'" "pgrep -l 'yes and no'" "" "" ""
+testing "-a 'full command line nomatch'" "pgrep -a 'yes and no'" "" "" ""
+
 testing "return success" "pgrep yes && echo success" "$proc\nsuccess\n" "" ""
 testing "return failure" "pgrep almost-certainly-not || echo failure" \
     "failure\n" "" ""
diff --git a/tests/sed.test b/tests/sed.test
index ce35161f..06fec59b 100755
--- a/tests/sed.test
+++ b/tests/sed.test
@@ -191,6 +191,7 @@ testcmd '\n too high' '-E "s/(.*)/\2/p" 2>/dev/null || echo OK' "OK\n" "" "foo"
 
 toyonly testcmd 's///x' '"s/(hello )?(world)/\2/x"' "world" "" "hello world"
 
+SKIP=1
 # Performance test
 X=x; Y=20; while [ $Y -gt 0 ]; do X=$X$X; Y=$(($Y-1)); done
 testing 'megabyte s/x/y/g (20 sec timeout)' \
diff --git a/tests/sh.test b/tests/sh.test
index 27555c7a..008fee1d 100644
--- a/tests/sh.test
+++ b/tests/sh.test
@@ -74,7 +74,7 @@ testing '$LINENO 1' "$SH input" "1\n" 'echo $LINENO' ''
 
 mkdir sub
 echo echo hello > sub/script
-$BROKEN testing 'simple script in $PATH' "PATH='$PWD/sub:$PATH' $SH script" \
+testing 'simple script in $PATH' "PATH='$PWD/sub:$PATH' $SH script" \
   'hello\n' '' ''
 rm -rf sub
 
@@ -733,6 +733,9 @@ testing "\$'' suppresses variable expansion" \
 testing 'if; is a syntax error but if $EMPTY; is not' \
   'if $NONE; then echo hello; fi' 'hello\n' '' ''
 
+testing 'trap1' $'trap \'echo T=$?;false\' USR1;kill -s usr1 $$;echo A=$?' \
+  'T=0\nA=0\n' '' ''
+
 # TODO finish variable list from shell init
 
 # $# $? $- $! $0  # $$
diff --git a/tests/test.test b/tests/test.test
index 185eab8b..02225662 100644
--- a/tests/test.test
+++ b/tests/test.test
@@ -114,14 +114,17 @@ testing "-lt" "arith_test -lt" "l" "" ""
 testing "-le" "arith_test -le" "le" "" ""
 
 touch oldfile -d 1970-01-01
-touch newfile -d 2031-01-01
+touch newfile -d 2031-01-01T00:00:00.5
+ln -s newfile samefile
 
 testcmd "-ef" "newfile -ef newfile && echo yes" "yes\n" "" ""
+testcmd "-ef link" "newfile -ef samefile && echo yes" "yes\n" "" ""
 testcmd "-ef2" "newfile -ef oldfile || echo no" "no\n" "" ""
 testcmd "-ot" "oldfile -ot newfile && echo yes" "yes\n" "" ""
 testcmd "-ot2" "oldfile -ot oldfile || echo no" "no\n" "" ""
 testcmd "-nt" "newfile -nt oldfile && echo yes" "yes\n" "" ""
 testcmd "-nt2" "oldfile -nt newfile || echo no" "no\n" "" ""
+testcmd "-nt2" "oldfile -nt newfile || echo no" "no\n" "" ""
 
 testing "positional" "test -a == -a && echo yes" "yes\n" "" ""
 testing "! stacks" 'test \! \! \! \! 2 -eq 2 && echo yes' "yes\n" "" ""
@@ -132,11 +135,10 @@ testing "<2" 'test def \< abc || echo yes' "yes\n" "" ""
 testing ">1" 'test abc \> def || echo yes' "yes\n" "" ""
 testing ">2" 'test def \> abc && echo yes' "yes\n" "" ""
 
-# toyonly doesn't work with TOYFLAG_NOHELP
 # bash only has this for [[ ]] but extra tests to _exclude_ silly...
-#toyonly testcmd "=~" 'abc =~ a.c && echo yes' "yes\n" "" ""
-#toyonly testcmd "=~ fail" 'abc =~ d.c; echo $?' '1\n' "" ""
-#toyonly testcmd "=~ zero length match" 'abc =~ "1*" && echo yes' 'yes\n' '' ''
+#toyonly testcmd "=~" "abc \'=~\' a.c && echo yes" "yes\n" "" ""
+#toyonly testcmd "=~ fail" "abc '=~' d.c; echo $?" '1\n' "" ""
+#toyonly testcmd "=~ zero length match" 'abc '=~' "1*" && echo yes' 'yes\n' '' ''
 
 # test ! = -o a
 # test ! \( = -o a \)
diff --git a/toys.h b/toys.h
index 94d0c4b5..5ec71ce9 100644
--- a/toys.h
+++ b/toys.h
@@ -141,5 +141,5 @@ extern char **environ, *toybox_version, toybuf[4096], libbuf[4096];
 #ifndef TOYBOX_VENDOR
 #define TOYBOX_VENDOR ""
 #endif
-#define TOYBOX_VERSION "0.8.11"TOYBOX_VENDOR
+#define TOYBOX_VERSION "0.8.12"TOYBOX_VENDOR
 #endif
diff --git a/toys/example/hello.c b/toys/example/hello.c
index ad74eba8..6c2f192f 100644
--- a/toys/example/hello.c
+++ b/toys/example/hello.c
@@ -2,7 +2,7 @@
  *
  * Copyright 2012 Rob Landley <rob@landley.net>
  *
- * See http://pubs.opengroup.org/onlinepubs/9699919799/utilities/
+ * See https://pubs.opengroup.org/onlinepubs/9799919799/utilities/
  * See http://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/cmdbehav.html
  * See https://www.ietf.org/rfc/rfc3.txt
  * See https://man7.org/linux/man-pages/man1/intro.1.html
diff --git a/toys/example/skeleton.c b/toys/example/skeleton.c
index 4382e7d6..224c2b5f 100644
--- a/toys/example/skeleton.c
+++ b/toys/example/skeleton.c
@@ -3,7 +3,7 @@
  *
  * Copyright 2014 Rob Landley <rob@landley.net>
  *
- * See http://pubs.opengroup.org/onlinepubs/9699919799/utilities/
+ * See https://pubs.opengroup.org/onlinepubs/9799919799/utilities/
  * See http://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/cmdbehav.html
  * See https://www.ietf.org/rfc/rfc3.txt
  * See https://man7.org/linux/man-pages/man1/intro.1.html
diff --git a/toys/other/devmem.c b/toys/other/devmem.c
index 90c25060..9c579d0a 100644
--- a/toys/other/devmem.c
+++ b/toys/other/devmem.c
@@ -43,9 +43,10 @@ unsigned long xatolu(char *str, int bytes)
 void devmem_main(void)
 {
   int ii, writing = toys.optc > 2, bytes = 4, fd;
-  unsigned long data QUIET, map_len QUIET,
+  unsigned long data = 0, map_len QUIET,
     addr = xatolu(*toys.optargs, sizeof(long));
   void *map QUIET, *p QUIET;
+  char *pdata;
 
   // WIDTH?
   if (toys.optc>1) {
@@ -55,6 +56,7 @@ void devmem_main(void)
       error_exit("bad width: %s", toys.optargs[1]);
     bytes = 1<<ii;
   }
+  pdata = ((char *)&data)+IS_BIG_ENDIAN*(sizeof(long)-bytes);
 
   // Map in just enough.
   if (CFG_TOYBOX_FORK) {
@@ -73,28 +75,25 @@ void devmem_main(void)
   } else p = (void *)addr;
 
   // Not using peek()/poke() because registers care about size of read/write.
-  if (writing) {
-    for (ii = 2; ii<toys.optc; ii++) {
-      data = xatolu(toys.optargs[ii], bytes);
-      if (FLAG(no_mmap)) xwrite(fd, &data, bytes);
-      else {
-        if (bytes==1) *(char *)p = data;
-        else if (bytes==2) *(unsigned short *)p = data;
-        else if (bytes==4) *(unsigned int *)p = data;
-        else if (sizeof(long)==8 && bytes==8) *(unsigned long *)p = data;
-        p += bytes;
-      }
+  if (writing) for (ii = 2; ii<toys.optc; ii++) {
+    data = xatolu(toys.optargs[ii], bytes);
+    if (FLAG(no_mmap)) xwrite(fd, pdata, bytes);
+    else {
+      if (bytes==1) *(char *)p = data;
+      else if (bytes==2) *(unsigned short *)p = data;
+      else if (bytes==4) *(unsigned *)p = data;
+      else if (sizeof(long)==8 && bytes==8) *(unsigned long *)p = data;
+      p += bytes;
     }
   } else {
-    if (FLAG(no_mmap)) xread(fd, &data, bytes);
+    if (FLAG(no_mmap)) xread(fd, pdata, bytes);
     else {
       if (bytes==1) data = *(char *)p;
       else if (bytes==2) data = *(unsigned short *)p;
-      else if (bytes==4) data = *(unsigned int *)p;
+      else if (bytes==4) data = *(unsigned *)p;
       else if (sizeof(long)==8 && bytes==8) data = *(unsigned long *)p;
     }
-    printf((!strchr(*toys.optargs, 'x')) ? "%0*ld\n" : "0x%0*lx\n",
-      bytes*2, data);
+    printf(strchr(*toys.optargs, 'x') ? "0x%0*lx\n" : "%0*ld\n", bytes*2, data);
   }
 
   if (CFG_TOYBOX_FORK) {
diff --git a/toys/other/lsusb.c b/toys/other/lsusb.c
index 3abbe47b..001acb1a 100644
--- a/toys/other/lsusb.c
+++ b/toys/other/lsusb.c
@@ -241,7 +241,7 @@ static int list_pci(struct dirtree *new)
     snprintf(toybuf, sizeof(toybuf), "/sys/bus/pci/devices/%s/config", new->name);
     fp = xfopen(toybuf, "r");
     while ((b = fgetc(fp)) != EOF) {
-      if ((col % 16) == 0) printf("%02x: ", col & 0xf0);
+      if ((col % 16) == 0) printf("%02x: ", col & ~0xf);
       printf("%02x ", (b & 0xff));
       if ((++col % 16) == 0) xputc('\n');
       if (col == max) break;
diff --git a/toys/other/modinfo.c b/toys/other/modinfo.c
index e1a64ba6..5a94a4fd 100644
--- a/toys/other/modinfo.c
+++ b/toys/other/modinfo.c
@@ -64,7 +64,7 @@ static void modinfo_file(char *full_name)
 
   for (i=0; i<ARRAY_LEN(modinfo_tags); i++) {
     char *field = modinfo_tags[i], *p = buf;
-    int slen = sprintf(toybuf, "%s=", field);
+    int slen = sprintf(toybuf, "%c%s=", 0, field);
 
     while (p && p < end) {
       p = memmem(p, end-p, toybuf, slen);
diff --git a/toys/other/nologin.c b/toys/other/nologin.c
new file mode 100644
index 00000000..851cd793
--- /dev/null
+++ b/toys/other/nologin.c
@@ -0,0 +1,24 @@
+/* nologin.c - False with a message.
+ *
+ * Copyright 2025 Rob Landley <rob@landley.net>
+ *
+ * No standard.
+
+USE_NOLOGIN(NEWTOY(nologin, 0, TOYFLAG_BIN|TOYFLAG_NOHELP))
+
+config NOLOGIN
+  bool "nologin"
+  default y
+  help
+    usage: nologin
+
+    Print /etc/nologin.txt and return failure.
+*/
+
+#include "toys.h"
+
+void nologin_main(void)
+{
+  toys.exitval = 1;
+  puts(readfile("/etc/nologin.txt", 0, 0) ? : toys.which->name);
+}
diff --git a/toys/pending/crond.c b/toys/pending/crond.c
index ac96061d..cef27ea0 100644
--- a/toys/pending/crond.c
+++ b/toys/pending/crond.c
@@ -27,13 +27,11 @@ config CROND
 #include "toys.h"
 
 GLOBALS(
-  char *crontabs_dir;
-  char *logfile;
+  char *c, *l;
   int loglevel_d;
   int loglevel;
 
   time_t crontabs_dir_mtime;
-  uint8_t flagd;
 )
 
 typedef struct _var {
@@ -60,44 +58,37 @@ static char months[]={"jan""feb""mar""apr""may""jun""jul"
   "aug""sep""oct""nov""dec"};
 CRONFILE *gclist;
 
-#define LOG_EXIT 0
-#define LOG_LEVEL5 5
-#define LOG_LEVEL7 7
-#define LOG_LEVEL8 8
-#define LOG_LEVEL9 9 // warning
-#define LOG_ERROR 20
-
-static void loginfo(uint8_t loglevel, char *msg, ...)
+static void loginfo(int loglevel, char *msg, ...)
 {
   va_list s, d;
+  int used;
+  char *smsg;
+
+  if (loglevel < TT.loglevel) return;
 
   va_start(s, msg);
   va_copy(d, s);
-  if (loglevel >= TT.loglevel) {
-    int used;
-    char *smsg;
-
-    if (!TT.flagd && TT.logfile) {
-      int fd = open(TT.logfile, O_WRONLY | O_CREAT | O_APPEND, 0666);
-      if (fd==-1) perror_msg("'%s", TT.logfile);
-      else {
-        dup2(fd, 2);
-        close(fd);
-      }
+
+  if (!FLAG(d) && TT.l) {
+    int fd = open(TT.l, O_WRONLY | O_CREAT | O_APPEND, 0666);
+    if (fd==-1) perror_msg("%s", TT.l);
+    else {
+      dup2(fd, 2);
+      close(fd);
     }
-    used = vsnprintf(NULL, 0, msg, d);
-    smsg = xzalloc(++used);
-    vsnprintf(smsg, used, msg, s);
-    if (TT.flagd || TT.logfile) {
-      fflush(NULL);
-      smsg[used-1] = '\n';
-      writeall((loglevel > 8) ? 2 : 1, smsg, used);
-    } else syslog((loglevel > 8) ? LOG_ERR : LOG_INFO, "%s", smsg);
-    free(smsg);
   }
+  used = vsnprintf(NULL, 0, msg, d);
+  smsg = xzalloc(++used);
+  vsnprintf(smsg, used, msg, s);
+  if (FLAG(d) || TT.l) {
+    fflush(NULL);
+    smsg[used-1] = '\n';
+    writeall((loglevel > 8) ? 2 : 1, smsg, used);
+  } else syslog((loglevel > 8) ? LOG_ERR : LOG_INFO, "%s", smsg);
+  free(smsg);
+
   va_end(d);
   va_end(s);
-  if (!loglevel) exit(20);
 }
 
 /*
@@ -187,14 +178,14 @@ static int parse_and_fillarray(char *dst, int min, int max, char *src)
     }
   }
 
-  if (TT.flagd && (TT.loglevel <= 5)) {
+  if (FLAG(d) && (TT.loglevel <= 5)) {
     for (start = 0; start < max; start++)
       fprintf(stderr, "%d", (unsigned char)dst[start]);
     fputc('\n', stderr);
   }
   return 0;
 ERROR:
-  loginfo(LOG_LEVEL9, "parse error at %s", src);
+  loginfo(9, "parse error at %s", src);
   return -1;
 }
 
@@ -226,7 +217,7 @@ static void parse_line(char *line, CRONFILE *cfile)
    * @hourly -> Run once an hour (0 * * * *).
    */
   if (*line == '@') return;
-  if (TT.flagd) loginfo(LOG_LEVEL5, "user:%s entry:%s", cfile->username, line);
+  if (FLAG(d)) loginfo(5, "user:%s entry:%s", cfile->username, line);
   while (count<5) {
     int len = strcspn(line, " \t");
 
@@ -276,7 +267,7 @@ static void parse_line(char *line, CRONFILE *cfile)
         goto STOP_PARSING;
       j->cmd = xstrdup(line);
 
-      if (TT.flagd) loginfo(LOG_LEVEL5, " command:%s", j->cmd);
+      if (FLAG(d)) loginfo(5, " command:%s", j->cmd);
       dlist_add_nomalloc((struct double_list **)&cfile->job, (struct double_list *)j);
       return;
 STOP_PARSING:
@@ -284,6 +275,8 @@ STOP_PARSING:
       return;
     default: return;
   }
+  // strip the newline from val, if any
+  strtok(val, "\n");
   if (!strcmp(name, "MAILTO")) cfile->mailto = xstrdup(val);
   else {
     v = xzalloc(sizeof(VAR));
@@ -367,8 +360,11 @@ static void scan_cronfiles()
   struct dirent *entry;
 
   remove_completed_jobs();
-  if (chdir(TT.crontabs_dir)) loginfo(LOG_EXIT, "chdir(%s)", TT.crontabs_dir);
-  if (!(dp = opendir("."))) loginfo(LOG_EXIT, "chdir(%s)", ".");
+  if (!(dp = opendir(TT.c))) {
+    loginfo(10, "chdir(%s)", TT.c);
+    toys.exitval = 20;
+    xexit();
+  }
 
   while ((entry = readdir(dp))) {
     CRONFILE *cfile;
@@ -379,7 +375,7 @@ static void scan_cronfiles()
     if (isdotdot(entry->d_name)) continue;
 
     if (!getpwnam(entry->d_name)) {
-      loginfo(LOG_LEVEL7, "ignoring file '%s' (no such user)", entry->d_name);
+      loginfo(7, "ignoring file '%s' (no such user)", entry->d_name);
       continue;
     }
 
@@ -430,24 +426,22 @@ static void do_fork(CRONFILE *cfile, JOB *job, int fd, char *prog)
     VAR *v, *vstart = (VAR *)cfile->var;
     struct passwd *pwd = getpwnam(cfile->username);
 
-    if (!pwd) loginfo(LOG_LEVEL9, "can't get uid for %s", cfile->username);
+    if (!pwd) loginfo(9, "can't get uid for %s", cfile->username);
     else {
       char *file = "/bin/sh";
 
       if (setenv("USER", pwd->pw_name, 1)) _exit(1);
+      if (setenv("LOGNAME", pwd->pw_name, 1)) _exit(1);
+      if (setenv("HOME", pwd->pw_dir, 1)) _exit(1);
       for (v = vstart; v;) {
         if (!strcmp("SHELL", v->name)) file = v->val;
         if (setenv(v->name, v->val, 1)) _exit(1);
         if ((v=v->next) == vstart) break;
       }
-      if (!getenv("HOME")) {
-        if (setenv("HOME", pwd->pw_dir, 1))
-          _exit(1);
-      }
       xsetuser(pwd);
-      if (chdir(pwd->pw_dir)) loginfo(LOG_LEVEL9, "chdir(%s)", pwd->pw_dir);
+      if (chdir(pwd->pw_dir)) loginfo(9, "chdir(%s)", pwd->pw_dir);
       if (prog) file = prog;
-      if (TT.flagd) loginfo(LOG_LEVEL5, "child running %s", file);
+      if (FLAG(d)) loginfo(5, "child running %s", file);
 
       if (fd >= 0) {
         int newfd = prog ? 0 : 1;
@@ -459,14 +453,14 @@ static void do_fork(CRONFILE *cfile, JOB *job, int fd, char *prog)
       }
       setpgrp();
       execlp(file, file, (prog ? "-ti" : "-c"), (prog ? NULL : job->cmd), (char *) NULL);
-      loginfo(LOG_ERROR, "can't execute '%s' for user %s", file, cfile->username);
+      loginfo(10, "can't execute '%s' for user %s", file, cfile->username);
 
       if (!prog) dprintf(1, "Exec failed: %s -c %s\n", file, job->cmd);
       _exit(EXIT_SUCCESS);
     }
   }
   if (pid < 0) {
-    loginfo(LOG_ERROR, "can't vfork");
+    loginfo(10, "can't vfork");
     pid = 0;
   }
   if (fd >=0) close(fd);
@@ -554,7 +548,7 @@ static void execute_jobs(void)
               cfile->username, getpid());
           if ((mailfd = open(toybuf, O_CREAT|O_TRUNC|O_WRONLY|O_EXCL|O_APPEND,
                   0600)) < 0) {
-            loginfo(LOG_ERROR, "can't create mail file %s for user %s, "
+            loginfo(10, "can't create mail file %s for user %s, "
                 "discarding output", toybuf, cfile->username);
           } else {
             dprintf(mailfd, "To: %s\nSubject: cron: %s\n\n", cfile->mailto, job->cmd);
@@ -570,7 +564,7 @@ static void execute_jobs(void)
               free(mailfile);
             }
           }
-          loginfo(LOG_LEVEL8, "USER %s pid %3d cmd %s",
+          loginfo(8, "USER %s pid %3d cmd %s",
               cfile->username, job->pid, job->cmd);
           if (job->pid < 0) job->needstart = 1;
           else job->isrunning = 1;
@@ -596,20 +590,20 @@ static void schedule_jobs(time_t ctime, time_t ptime)
     lt = localtime(&tm);
 
     while (cfile) {
-      if (TT.flagd) loginfo(LOG_LEVEL5, "file %s:", cfile->username);
+      if (FLAG(d)) loginfo(5, "file %s:", cfile->username);
       if (cfile->invalid) goto NEXT_CRONFILE;
       job = jstart = (JOB *)cfile->job;
 
       while (job) {
-        if (TT.flagd) loginfo(LOG_LEVEL5, " line %s", job->cmd);
+        if (FLAG(d)) loginfo(5, " line %s", job->cmd);
 
         if (job->min[lt->tm_min] && job->hour[lt->tm_hour]
-            && (job->dom[lt->tm_mday] || job->dow[lt->tm_wday])
-            && job->mon[lt->tm_mon-1]) {
-          if (TT.flagd)
-            loginfo(LOG_LEVEL5, " job: %d %s\n", (int)job->pid, job->cmd);
+            && (job->dom[lt->tm_mday-1] && job->dow[lt->tm_wday])
+            && job->mon[lt->tm_mon]) {
+          if (FLAG(d))
+            loginfo(5, " job: %d %s\n", (int)job->pid, job->cmd);
           if (job->pid > 0) {
-            loginfo(LOG_LEVEL8, "user %s: process already running: %s",
+            loginfo(8, "user %s: process already running: %s",
                 cfile->username, job->cmd);
           } else if (!job->pid) {
             job->pid = -1;
@@ -627,53 +621,47 @@ NEXT_CRONFILE:
 
 void crond_main(void)
 {
-  time_t ctime, ptime;
+  long long ctime, ptime, tdiff;
   int sleepfor = 60;
   struct stat sb;
 
-  TT.flagd = (toys.optflags & FLAG_d);
-
-  // Setting default params.
-  if (TT.flagd) TT.loglevel = TT.loglevel_d;
-  if (!(toys.optflags & (FLAG_f | FLAG_b))) toys.optflags |= FLAG_b;
-  if (!(toys.optflags & (FLAG_S | FLAG_L))) toys.optflags |= FLAG_S;
+  // We do this twice on nommu (because xvdaemon restart) but here for error msg
+  if (TT.c) {
+    if (!strend(TT.c, "/")) TT.c = xmprintf("%s/", TT.c);
+  } else TT.c = "/var/spool/cron/crontabs/";
+  xchdir(TT.c);
 
-  if ((toys.optflags & FLAG_c)
-      && (TT.crontabs_dir[strlen(TT.crontabs_dir)-1] != '/'))
-    TT.crontabs_dir = xmprintf("%s/", TT.crontabs_dir);
+  if (!FLAG(f)) xvdaemon();
 
-  if (!TT.crontabs_dir) TT.crontabs_dir = xstrdup("/var/spool/cron/crontabs/");
-  if (toys.optflags & FLAG_b) daemon(0,0);
+  // Setting default params.
+  if (FLAG(d)) TT.loglevel = TT.loglevel_d;
 
-  if (!TT.flagd && !TT.logfile)
+  if (!FLAG(d) && !TT.l)
     openlog(toys.which->name, LOG_CONS | LOG_PID, LOG_CRON);
 
   // Set default shell once.
-  if (setenv("SHELL", "/bin/sh", 1)) error_exit("Can't set default shell");
-  xchdir(TT.crontabs_dir);
-  loginfo(LOG_LEVEL8, "crond started, log level %d", TT.loglevel);
+  setenv("SHELL", "/bin/sh", 1);
+  loginfo(8, "crond started, log level %d", TT.loglevel);
 
-  if (stat(TT.crontabs_dir, &sb)) sb.st_mtime = 0;
+  if (stat(TT.c, &sb)) sb.st_mtime = 0;
   TT.crontabs_dir_mtime = sb.st_mtime;
   scan_cronfiles();
-  ctime = time(NULL);
-
-  while (1) {
-    long tdiff;
+  ctime = time(0);
 
+  for (;;) {
     ptime = ctime;
     sleep(sleepfor - (ptime%sleepfor) +1);
-    tdiff =(long) ((ctime = time(NULL)) - ptime);
+    tdiff = (ctime = time(0)) - ptime;
 
-    if (stat(TT.crontabs_dir, &sb)) sb.st_mtime = 0;
+    if (stat(TT.c, &sb)) sb.st_mtime = 0;
     if (TT.crontabs_dir_mtime != sb.st_mtime) {
       TT.crontabs_dir_mtime = sb.st_mtime;
       scan_cronfiles();
     }
 
-    if (TT.flagd) loginfo(LOG_LEVEL5, "wakeup diff=%ld\n", tdiff);
+    if (FLAG(d)) loginfo(5, "wakeup diff=%ld\n", tdiff);
     if (tdiff < -60 * 60 || tdiff > 60 * 60)
-      loginfo(LOG_LEVEL9, "time disparity of %ld minutes detected", tdiff / 60);
+      loginfo(9, "time disparity of %ld minutes detected", tdiff / 60);
     else if (tdiff > 0) {
       schedule_jobs(ctime, ptime);
       execute_jobs();
diff --git a/toys/pending/crontab.c b/toys/pending/crontab.c
index 575398f2..ced5755e 100644
--- a/toys/pending/crontab.c
+++ b/toys/pending/crontab.c
@@ -234,6 +234,7 @@ static void update_crontab(char *src, char *dest)
   int fdin, fdout;
 
   snprintf(toybuf, sizeof(toybuf), "%s%s", TT.cdir, dest);
+  unlink(toybuf);
   fdout = xcreate(toybuf, O_WRONLY|O_CREAT|O_TRUNC, 0600);
   fdin = xopenro(src);
   xsendfile(fdin, fdout);
diff --git a/toys/pending/getty.c b/toys/pending/getty.c
index 7d0f9b14..1bd795da 100644
--- a/toys/pending/getty.c
+++ b/toys/pending/getty.c
@@ -149,6 +149,7 @@ void print_issue(void)
       else if (ch == 'r') xputsn(TT.uts.release);
       else if (ch == 's') xputsn(TT.uts.sysname);
       else if (ch == 'l') xputsn(TT.tty_name);
+      else if (ch == '\\') xputc(ch);
       else printf("<bad escape>");
     } else xputc(ch);
   }
diff --git a/toys/pending/hexdump.c b/toys/pending/hexdump.c
index b688fc48..7d824c61 100644
--- a/toys/pending/hexdump.c
+++ b/toys/pending/hexdump.c
@@ -28,7 +28,7 @@ config HEXDUMP
 
 config HD
   bool "hd"
-  default HEXDUMP
+  default n
   help
     usage: hd [FILE...]
 
@@ -151,5 +151,5 @@ void hexdump_main(void)
   else TT.fmt = " %04x";
 
   loopfiles(toys.optargs, do_hexdump);
-  FLAG(C) ? printf("%08llx\n", TT.pos) : printf("%07llx\n", TT.pos);
+  printf("%0*llx\n", 7+FLAG(C), TT.pos);
 }
diff --git a/toys/pending/klogd.c b/toys/pending/klogd.c
index fbc7e165..8e84e2b6 100644
--- a/toys/pending/klogd.c
+++ b/toys/pending/klogd.c
@@ -13,7 +13,9 @@ config KLOGD
   help
   usage: klogd [-n] [-c PRIORITY]
 
-  -c	Print to console messages more urgent than PRIORITY (1-8)"
+  Forward messages from the kernel ring buffer (read by dmesg) to syslogd.
+
+  -c	Print to console messages more urgent than PRIORITY (1-8)
   -n	Run in foreground
   -s	Use syscall instead of /proc
 */
@@ -41,11 +43,10 @@ static void set_log_level(int level)
 
 static void handle_signal(int sig)
 {
-  if (FLAG(s)) {
-    klogctl(7, 0, 0);
-    klogctl(0, 0, 0);
-  } else {
-    set_log_level(7); // TODO: hardwired? Old value...?
+  // TODO: level 7 hardwired? How to read old value...?
+  if (FLAG(s)) klogctl(8, 0, 7);
+  else {
+    if (FLAG(c)) set_log_level(7);
     xclose(TT.fd);
   }
   syslog(LOG_NOTICE, "KLOGD: Daemon exiting......");
@@ -61,12 +62,11 @@ void klogd_main(void)
   int prio, size, used = 0;
   char *start, *line_start;
 
-  if (!FLAG(n) xvdaemon();
+  if (!FLAG(n)) xvdaemon();
   sigatexit(handle_signal);
   if (FLAG(c)) set_log_level(TT.level);    //set log level
 
-  if (FLAG(s)) klogctl(1, 0, 0);
-  else TT.fd = xopenro("/proc/kmsg"); //_PATH_KLOG in paths.h
+  if (!FLAG(s)) TT.fd = xopenro("/proc/kmsg"); //_PATH_KLOG in paths.h
   syslog(LOG_NOTICE, "KLOGD: started with %s as log source\n",
     FLAG(s) ? "Kernel ring buffer" : "/proc/kmsg");
   openlog("Kernel", 0, LOG_KERN);    //open connection to system logger..
@@ -81,9 +81,8 @@ void klogd_main(void)
     if (used) start = toybuf;
     while (start) {
       if ((line_start = strsep(&start, "\n")) && start) used = 0;
-      else {      //Incomplete line, copy it to start of buff.
-        used = strlen(line_start);
-        strcpy(toybuf, line_start);
+      else {      //Incomplete line, copy it to start of buf
+        used = stpcpy(toybuf, line_start)-toybuf;
         if (used < (sizeof(toybuf) - 1)) break;
         used = 0; //we have buffer full, log it as it is.
       }
diff --git a/toys/pending/sh.c b/toys/pending/sh.c
index 1be952d0..9d2145c1 100644
--- a/toys/pending/sh.c
+++ b/toys/pending/sh.c
@@ -60,6 +60,7 @@ USE_SH(NEWTOY(set, 0, TOYFLAG_NOFORK))
 USE_SH(NEWTOY(shift, ">1", TOYFLAG_NOFORK))
 USE_SH(NEWTOY(source, "<1", TOYFLAG_NOFORK))
 USE_SH(OLDTOY(., source, TOYFLAG_NOFORK))
+USE_SH(NEWTOY(trap, "lp", TOYFLAG_NOFORK))
 USE_SH(NEWTOY(unset, "fvn[!fv]", TOYFLAG_NOFORK))
 USE_SH(NEWTOY(wait, "n", TOYFLAG_NOFORK))
 
@@ -313,6 +314,21 @@ config SOURCE
 
     Read FILE and execute commands. Any ARGS become positional parameters.
 
+config TRAP
+  bool
+  default n
+  depends on SH
+  help
+    usage: trap [-l] [[COMMAND] SIGNAL]
+
+    Run COMMAND as handler for signal. With no arguments, list active handlers.
+    The COMMAND "-" resets the signal to default.
+
+    -l	List signals.
+
+    The special signal EXIT gets called before the shell exits, RETURN when
+    a function or source returns, and DEBUG is called before each command.
+
 config WAIT
   bool
   default n
@@ -341,16 +357,19 @@ GLOBALS(
 
   // keep SECONDS here: used to work around compiler limitation in run_command()
   long long SECONDS;
-  char *isexec, *wcpat;
-  unsigned options, jobcnt, LINENO;
-  int hfd, pid, bangpid, srclvl, recursion, recfile[50+200*CFG_TOYBOX_FORK];
+  char *isexec, *wcpat, *traps[NSIG+2];
+  unsigned options, jobcnt;
+  int hfd, pid, bangpid, recursion;
+  struct double_list *nextsig;
+  jmp_buf forkchild;
 
   // Callable function array
   struct sh_function {
     char *name;
     struct sh_pipeline {  // pipeline segments: linked list of arg w/metadata
       struct sh_pipeline *next, *prev, *end;
-      int count, here, type, lineno;
+      int count, here, type;
+      long lineno;
       struct sh_arg {
         char **v;
         int c;
@@ -360,20 +379,21 @@ GLOBALS(
   } **functions;
   long funcslen;
 
-  // runtime function call stack
+  // runtime function call stack. TT.ff is current function, returns to ->next
   struct sh_fcall {
     struct sh_fcall *next, *prev;
 
-    // This dlist in reverse order: TT.ff current function, TT.ff->prev globals
+    // Each level has its own local variables, root (TT.ff->prev) is globals
     struct sh_vars {
       long flags;
       char *str;
     } *vars;
-    long varslen, varscap, shift, oldlineno;
+    long varslen, varscap, shift, lineno, signal;
 
-    struct sh_function *func; // TODO wire this up
+    struct sh_function *function;
+    FILE *source;
+    char *ifs, *name, *_;
     struct sh_pipeline *pl;
-    char *ifs, *omnom;
     struct sh_arg arg;
     struct arg_list *delete;
 
@@ -387,25 +407,22 @@ GLOBALS(
       struct arg_list *fdelete;    // farg's cleanup list
       char *fvar;                  // for/select's iteration variable name
     } *blk;
-  } *ff;
 
 // TODO ctrl-Z suspend should stop script
-  struct sh_process {
-    struct sh_process *next, *prev; // | && ||
-    struct arg_list *delete;   // expanded strings
-    // undo redirects, a=b at start, child PID, exit status, has !, job #
-    int *urd, envlen, pid, exit, flags, job, dash;
-    long long when; // when job backgrounded/suspended
-    struct sh_arg *raw, arg;
-  } *pp; // currently running process
+    struct sh_process {
+      struct sh_process *next, *prev; // | && ||
+      struct arg_list *delete;   // expanded strings
+      // undo redirects, a=b at start, child PID, exit status, has !, job #
+      int *urd, envlen, pid, exit, flags, job, dash, refcount;
+      long long when; // when job backgrounded/suspended
+      struct sh_arg *raw, arg;
+    } *pp;
+  } *ff;
 
   // job list, command line for $*, scratch space for do_wildcard_files()
   struct sh_arg jobs, *wcdeck;
-  FILE *script;
 )
 
-// Prototype because $($($(blah))) nests, leading to run->parse->run loop
-int do_source(char *name, FILE *ff);
 // functions contain pipelines contain functions: prototype because loop
 static void free_pipeline(void *pipeline);
 // recalculate needs to get/set variables, but setvar_found calls recalculate
@@ -429,14 +446,33 @@ static const char *redirectors[] = {"<<<", "<<-", "<<", "<&", "<>", "<", ">>",
 // struct sh_process->flags
 #define PFLAG_NOT    1
 
+static void sherror_msg(char *msg, ...)
+{
+  va_list va;
+  struct sh_fcall *ff;
+
+  va_start(va, msg);
+// TODO $ sh -c 'x() { ${x:?blah}; }; x'
+// environment: line 1: x: blah
+  for (ff = TT.ff; !ff->source || !ff->name; ff = ff->next);
+  if (!FLAG(i) || ff!=TT.ff->prev)
+    fprintf(stderr, "%s: line %ld: ", ff->name,
+      ff->pl ? ff->pl->lineno : ff->lineno);
+  verror_msg(msg, 0, va);
+  va_end(va);
+}
+
+static int dashi(void)
+{
+  return TT.options&FLAG_i;
+}
+
 static void syntax_err(char *s)
 {
-  struct sh_fcall *ff = TT.ff;
 // TODO: script@line only for script not interactive.
-  for (ff = TT.ff; ff != TT.ff->prev; ff = ff->next) if (ff->omnom) break;
-  error_msg("syntax error '%s'@%u: %s", ff->omnom ? : "-c", TT.LINENO, s);
+  sherror_msg("syntax error: %s", s);
   toys.exitval = 2;
-  if (!(TT.options&FLAG_i)) xexit();
+  if (!dashi()) xexit();
 }
 
 void debug_show_fds()
@@ -521,7 +557,7 @@ static char *varend(char *s)
 // TODO: this has to handle VAR_NAMEREF, but return dangling symlink
 // Also, unset -n, also "local ISLINK" to parent var.
 // Return sh_vars * or 0 if not found.
-// Sets *pff to function (only if found), only returns whiteouts if pff not NULL
+// Sets *pff to fcall (only if found), only returns whiteouts when pff not NULL
 static struct sh_vars *findvar(char *name, struct sh_fcall **pff)
 {
   int len = varend(name)-name;
@@ -555,7 +591,7 @@ static char *getvar(char *s)
 
     if (c == 'S') sprintf(toybuf, "%lld", (millitime()-TT.SECONDS)/1000);
     else if (c == 'R') sprintf(toybuf, "%ld", random()&((1<<16)-1));
-    else if (c == 'L') sprintf(toybuf, "%u", TT.ff->pl->lineno);
+    else if (c == 'L') sprintf(toybuf, "%ld", TT.ff->pl->lineno);
     else if (c == 'G') sprintf(toybuf, "TODO: GROUPS");
     else if (c == 'B') sprintf(toybuf, "%d", getpid());
     else if (c == 'E') {
@@ -639,9 +675,8 @@ static int recalculate(long long *dd, char **ss, int lvl)
   // If we got a variable, evaluate its contents to set *dd
   if (var) {
     // Recursively evaluate, catching x=y; y=x; echo $((x))
-    TT.recfile[TT.recursion++] = 0;
-    if (TT.recursion == ARRAY_LEN(TT.recfile)) {
-      perror_msg("recursive occlusion");
+    if (TT.recursion==100) {
+      sherror_msg("recursive occlusion");
       --TT.recursion;
 
       return 0;
@@ -651,7 +686,7 @@ static int recalculate(long long *dd, char **ss, int lvl)
     TT.recursion--;
     if (!ii) return 0;
     if (*val) {
-      perror_msg("bad math: %s @ %d", var, (int)(val-var));
+      sherror_msg("bad math: %s @ %d", var, (int)(val-var));
 
       return 0;
     }
@@ -689,7 +724,7 @@ static int recalculate(long long *dd, char **ss, int lvl)
       else if (cc=='|') *dd |= ee;
       else if (!cc) *dd = ee;
       else if (!ee) {
-        perror_msg("%c0", cc);
+        sherror_msg("%c0", cc);
 
         return 0;
       } else if (cc=='/') *dd /= ee;
@@ -702,7 +737,7 @@ static int recalculate(long long *dd, char **ss, int lvl)
   // x**y binds first
   if (lvl<=14) while (strstart(nospace(ss), "**")) {
     if (!recalculate(&ee, ss, noa|15)) return 0;
-    if (ee<0) perror_msg("** < 0");
+    if (ee<0) sherror_msg("** < 0");
     for (ff = *dd, *dd = 1; ee; ee--) *dd *= ff;
   }
 
@@ -712,7 +747,7 @@ static int recalculate(long long *dd, char **ss, int lvl)
     if (!recalculate(&ee, ss, noa|14)) return 0;
     if (cc=='*') *dd *= ee;
     else if (!ee) {
-      perror_msg("%c0", cc);
+      sherror_msg("%c0", cc);
 
       return 0;
     } else if (cc=='%') *dd %= ee;
@@ -836,14 +871,6 @@ static int utf8chr(char *wc, char *chrs, int *len)
   return 0;
 }
 
-// does this entire string match one of the strings in try[]
-static int anystr(char *s, char **try)
-{
-  while (*try) if (!strcmp(s, *try++)) return 1;
-
-  return 0;
-}
-
 // Update $IFS cache in function call stack after variable assignment
 static void cache_ifs(char *s, struct sh_fcall *ff)
 {
@@ -858,22 +885,20 @@ static void cache_ifs(char *s, struct sh_fcall *ff)
 // Assign new name=value string for existing variable. s takes x=y or x+=y
 static struct sh_vars *setvar_found(char *s, int freeable, struct sh_vars *var)
 {
-  char *ss, *sss, *sd, buf[24];
+  char *vs = var->str, *ss, *sss, *sd, buf[24];
   long ii, jj, kk, flags = var->flags&~VAR_WHITEOUT;
   long long ll;
   int cc, vlen = varend(s)-s;
 
   if (flags&VAR_READONLY) {
-    error_msg("%.*s: read only", vlen, s);
+    sherror_msg("%.*s: read only", vlen, s);
     goto bad;
   }
 
   // If += has no old value (addvar placeholder or empty old var) yank the +
   if (s[vlen]=='+' && (var->str==s || !strchr(var->str, '=')[1])) {
     ss = xmprintf("%.*s%s", vlen, s, s+vlen+1);
-    if (var->str==s) {
-      if (!freeable++) var->flags |= VAR_NOFREE;
-    } else if (freeable++) free(s);
+    if (vs!=s && freeable++) free(s);
     s = ss;
   }
 
@@ -881,7 +906,7 @@ static struct sh_vars *setvar_found(char *s, int freeable, struct sh_vars *var)
   if (strncmp(var->str, s, vlen)) {
     ss = s+vlen+(s[vlen]=='+')+1;
     ss = xmprintf("%.*s%s", (vlen = varend(var->str)-var->str)+1, var->str, ss);
-    if (freeable++) free(s);
+    if (vs!=s && freeable++) free(s);
     s = ss;
   }
 
@@ -900,7 +925,7 @@ static struct sh_vars *setvar_found(char *s, int freeable, struct sh_vars *var)
       }
     }
     *sd = 0;
-    if (freeable++) free(s);
+    if (vs!=s && freeable++) free(s);
     s = sss;
   }
 
@@ -909,7 +934,7 @@ static struct sh_vars *setvar_found(char *s, int freeable, struct sh_vars *var)
   if (flags&VAR_INT) {
     sd = ss;
     if (!recalculate(&ll, &sd, 0) || *sd) {
-      perror_msg("bad math: %s @ %d", ss, (int)(sd-ss));
+      sherror_msg("bad math: %s @ %d", ss, (int)(sd-ss));
 
       goto bad;
     }
@@ -927,12 +952,12 @@ static struct sh_vars *setvar_found(char *s, int freeable, struct sh_vars *var)
     } else if (s[vlen]=='+' || strcmp(buf, ss)) {
       if (s[vlen]=='+') ll += atoll(strchr(var->str, '=')+1);
       ss = xmprintf("%.*s=%lld", vlen, s, ll);
-      if (freeable++) free(s);
+      if (vs!=s && freeable++) free(s);
       s = ss;
     }
   } else if (s[vlen]=='+' && !(flags&VAR_MAGIC)) {
     ss = xmprintf("%s%s", var->str, ss);
-    if (freeable++) free(s);
+    if (vs!=s && freeable++) free(s);
     s = ss;
   }
 
@@ -960,7 +985,7 @@ static struct sh_vars *setvar_long(char *s, int freeable, struct sh_fcall *ff)
   if (!s) return 0;
   ss = varend(s);
   if (ss[*ss=='+']!='=') {
-    error_msg("bad setvar %s\n", s);
+    sherror_msg("bad setvar %s\n", s);
     if (freeable) free(s);
 
     return 0;
@@ -994,7 +1019,7 @@ static int unsetvar(char *name)
   int len = varend(name)-name;
 
   if (!var || (var->flags&VAR_WHITEOUT)) return 0;
-  if (var->flags&VAR_READONLY) error_msg("readonly %.*s", len, name);
+  if (var->flags&VAR_READONLY) sherror_msg("readonly %.*s", len, name);
   else {
     // turn local into whiteout
     if (ff != TT.ff->prev) {
@@ -1234,10 +1259,11 @@ static void unredirect(int *urd)
 // TODO: waitpid(WNOHANG) to clean up zombies and catch background& ending
 static void subshell_callback(char **argv)
 {
-  int i;
+  struct sh_fcall *ff;
 
   // Don't leave open filehandles to scripts in children
-  for (i = 0; i<TT.recursion; i++)  if (TT.recfile[i]>0) close(TT.recfile[i]);
+  for (ff = TT.ff; ff!=TT.ff->prev; ff = ff->next)
+    if (ff->source) fclose(ff->source);
 
   // This depends on environ having been replaced by caller
   environ[1] = xmprintf("@%d,%d", getpid(), getppid());
@@ -1314,7 +1340,7 @@ static void add_block(void)
 }
 
 // Add entry to runtime function call stack
-static void call_function(void)
+static struct sh_fcall *call_function(void)
 {
   // dlist in reverse order: TT.ff = current function, TT.ff->prev = globals
   dlist_add_nomalloc((void *)&TT.ff, xzalloc(sizeof(struct sh_fcall)));
@@ -1326,6 +1352,8 @@ static void call_function(void)
   TT.ff->arg.v = TT.ff->next->arg.v;
   TT.ff->arg.c = TT.ff->next->arg.c;
   TT.ff->ifs = TT.ff->next->ifs;
+
+  return TT.ff;
 }
 
 static void free_function(struct sh_function *funky)
@@ -1337,30 +1365,59 @@ static void free_function(struct sh_function *funky)
   free(funky);
 }
 
-// TODO: old function-vs-source definition is "has variables", but no ff->func?
-// returns 0 if source popped, nonzero if function popped
-static int end_fcall(int funconly)
+static int free_process(struct sh_process *pp)
+{
+  int rc;
+
+  if (!pp) return 127;
+  rc = pp->exit;
+  if (!--pp->refcount) {
+    llist_traverse(pp->delete, llist_free_arg);
+    free(pp);
+  }
+
+  return rc;
+}
+
+// Clean up and pop TT.ff
+static void end_fcall(void)
 {
   struct sh_fcall *ff = TT.ff;
-  int func = ff->next!=ff && ff->vars;
 
-  if (!func && funconly) return 0;
-  llist_traverse(ff->delete, llist_free_arg);
-  ff->delete = 0;
-  while (ff->blk->next) pop_block();
-  pop_block();
+  // forked child does NOT clean up
+  if (ff->pp == (void *)1) _exit(toys.exitval);
 
-  // for a function, free variables and pop context
-  if (!func) return 0;
+  // Free local vars then update $_ in other vars
   while (ff->varslen)
     if (!(ff->vars[--ff->varslen].flags&VAR_NOFREE))
       free(ff->vars[ff->varslen].str);
   free(ff->vars);
+  ff->vars = 0;
+  if (ff->_) setvarval("_", ff->_);
+
+  // Free the rest
+  llist_traverse(ff->delete, llist_free_arg);
+  ff->delete = 0;
+  while (pop_block());
   free(ff->blk);
-  free_function(ff->func);
-  free(dlist_pop(&TT.ff));
+  free_function(ff->function);
+  if (ff->pp) {
+    unredirect(ff->pp->urd);
+    ff->pp->urd = 0;
+    free_process(ff->pp);
+  }
 
-  return 1;
+  // Unblock signal we just finished handling
+  if (TT.ff->signal) {
+    sigset_t set;
+
+    sigemptyset(&set);
+    sigaddset(&set, TT.ff->signal>>8);
+    sigprocmask(SIG_UNBLOCK, &set, 0);
+    toys.exitval = TT.ff->signal&255;
+  }
+
+  free(dlist_pop(&TT.ff));
 }
 
 // TODO check every caller of run_subshell for error, or syntax_error() here
@@ -1377,10 +1434,10 @@ static int run_subshell(char *str, int len)
   if (CFG_TOYBOX_FORK) {
     if ((pid = fork())<0) perror_msg("fork");
     else if (!pid) {
-      call_function();
+      call_function()->pp = (void *)1;
       if (str) {
-        do_source(0, fmemopen(str, len, "r"));
-        _exit(toys.exitval);
+        TT.ff->source = fmemopen(str, len, "r");
+        longjmp(TT.forkchild, 1);
       }
     }
 
@@ -1409,8 +1466,9 @@ static int run_subshell(char *str, int len)
 
     // marshall context to child
     close(254);
-    dprintf(pipes[1], "%lld %u %u %u %u\n", TT.SECONDS,
-      TT.options, TT.LINENO, TT.pid, TT.bangpid);
+    // TODO: need ff->name and ff->source's lineno
+    dprintf(pipes[1], "%lld %u %ld %u %u\n", TT.SECONDS,
+      TT.options, TT.ff->lineno, TT.pid, TT.bangpid);
 
     for (i = 0, vv = visible_vars(); vv[i]; i++)
       dprintf(pipes[1], "%u %lu\n%.*s", (unsigned)strlen(vv[i]->str),
@@ -1895,7 +1953,7 @@ static int expand_arg_nobrace(struct sh_arg *arg, char *str, unsigned flags,
 
         // Recursively calculate result
         if (!recalculate(&ll, &s, 0) || *s) {
-          error_msg("bad math: %s @ %ld", ss, (long)(s-ss)+1);
+          sherror_msg("bad math: %s @ %ld", ss, (long)(s-ss)+1);
           goto fail;
         }
         ii += kk-1;
@@ -1951,7 +2009,6 @@ static int expand_arg_nobrace(struct sh_arg *arg, char *str, unsigned flags,
 
         continue;
       } else if (cc == '{') {
-
         // Skip escapes to find }, parse_word() guarantees ${} terminates
         for (cc = *++ss; str[ii] != '}'; ii++) if (str[ii]=='\\') ii++;
         ii++;
@@ -2023,7 +2080,7 @@ static int expand_arg_nobrace(struct sh_arg *arg, char *str, unsigned flags,
         if (ifs == (void *)1) {
 barf:
           if (!(((unsigned long)ifs)>>1)) ifs = "bad substitution";
-          error_msg("%.*s: %s", (int)(slice-ss), ss, ifs);
+          sherror_msg("%.*s: %s", (int)(slice-ss), ss, ifs); // TODO: show ${}
           goto fail;
         }
       } else jj = 1;
@@ -2096,7 +2153,7 @@ barf:
           if (!lc || *ss != '}') {
             // Find ${blah} context for error message
             while (*slice!='$') slice--;
-            error_msg("bad %.*s @ %ld", (int)(strchr(ss, '}')+1-slice), slice,
+            sherror_msg("bad %.*s @ %ld", (int)(strchr(ss, '}')+1-slice), slice,
               (long)(ss-slice));
             goto fail;
           }
@@ -2532,6 +2589,7 @@ static struct sh_process *expand_redir(struct sh_arg *arg, int skip, int *urd)
   pp = xzalloc(sizeof(struct sh_process));
   pp->urd = urd;
   pp->raw = arg;
+  pp->refcount = 1;
 
   // When redirecting, copy each displaced filehandle to restore it later.
   // Expand arguments and perform redirections
@@ -2590,7 +2648,7 @@ static struct sh_process *expand_redir(struct sh_arg *arg, int skip, int *urd)
 
       if (!expand_arg(&tmp, sss, 0, &pp->delete) && tmp.c == 1) sss = *tmp.v;
       else {
-        if (tmp.c > 1) error_msg("%s: ambiguous redirect", sss);
+        if (tmp.c > 1) sherror_msg("%s: ambiguous redirect", sss);
         s = 0;
       }
       free(tmp.v);
@@ -2729,16 +2787,60 @@ notfd:
   return pp;
 }
 
+// Handler called with all signals blocked, so no special locking needed.
+static void sig_fcall(int sig, siginfo_t *info, void *ucontext)
+{
+  // Tell run_lines() to eval trap, keep signal blocked until trap func ends
+  dlist_add(&TT.nextsig, (void *)(long)sig);
+  sigaddset(&((ucontext_t *)ucontext)->uc_sigmask, sig);
+}
+
+// Set signal handler to exec string, or reset to default if NULL
+static void signify(int sig, char *throw)
+{
+  void *ign = (sig==SIGPIPE || (sig==SIGINT && dashi())) ? SIG_IGN : SIG_DFL;
+  struct sigaction act = {0};
+  struct sh_fcall *ff;
+
+  if (throw && !*throw) throw = 0, ign = SIG_IGN;
+
+  // If we're replacing a running trap handler, garbe collect in fcall pop.
+  for (ff = TT.ff; ff && ff!=TT.ff->prev; ff = ff->next) {
+    if (ff->signal>>8==sig) {
+      push_arg(&ff->delete, TT.traps[sig]);
+      TT.traps[sig] = 0;
+      break;
+    }
+  }
+  free(TT.traps[sig]);
+  TT.traps[sig] = throw;
+
+  // Set signal handler (not for synthetic signals like EXIT)
+  if (sig && sig<NSIG) {
+    if (!TT.traps[sig]) {
+      act.sa_handler = ign;
+      act.sa_flags = SA_RESTART;
+    } else {
+      sigfillset(&act.sa_mask);
+      act.sa_flags = SA_SIGINFO;
+      act.sa_sigaction = sig_fcall;
+    }
+    sigaction(sig, &act, 0);
+  }
+}
+
+
+
 // Call binary, or run script via xexec("sh --")
 static void sh_exec(char **argv)
 {
-  char *pp = getvar("PATH" ? : _PATH_DEFPATH), *ss = TT.isexec ? : *argv,
+  char *pp = getvar("PATH") ? : _PATH_DEFPATH, *ss = TT.isexec ? : *argv,
     **sss = 0, **oldenv = environ, **argv2;
-  int norecurse = CFG_TOYBOX_NORECURSE || !toys.stacktop || TT.isexec, ii;
+  int norecurse = CFG_TOYBOX_NORECURSE || !toys.stacktop || TT.isexec;
   struct string_list *sl = 0;
   struct toy_list *tl = 0;
 
-  if (getpid() != TT.pid) signal(SIGINT, SIG_DFL); // TODO: restore all?
+  if (getpid() != TT.pid) signify(SIGINT, 0); // TODO: restore all?
   errno = ENOENT;
   if (strchr(ss, '/')) {
     if (access(ss, X_OK)) ss = 0;
@@ -2768,9 +2870,12 @@ static void sh_exec(char **argv)
     *sss = xmprintf("_=%s", ss);
 
     // Don't leave open filehandles to scripts in children
-    if (!TT.isexec)
-      for (ii = 0; ii<TT.recursion; ii++)
-        if (TT.recfile[ii]>0) close(TT.recfile[ii]);
+    if (!TT.isexec) {
+      struct sh_fcall *ff;
+
+      for (ff = TT.ff; ff!=TT.ff->prev; ff = ff->next)
+        if (ff->source) fclose(ff->source);
+    }
 
     // Run builtin, exec command, or call shell script without #!
     toy_exec_which(tl, argv);
@@ -2801,7 +2906,8 @@ static struct sh_process *run_command(void)
 {
   char *s, *ss, *sss;
   struct sh_arg *arg = TT.ff->pl->arg;
-  int envlen, skiplen, funk = TT.funcslen, ii, jj = 0, prefix = 0;
+  int envlen, skiplen, funk = TT.funcslen, ii, jj, prefix = 0,
+      pipe = TT.ff->blk->pipe;
   struct sh_process *pp;
 
   // Count leading variable assignments
@@ -2809,8 +2915,9 @@ static struct sh_process *run_command(void)
     if ((ss = varend(arg->v[envlen]))==arg->v[envlen] || ss[*ss=='+']!='=')
       break;
 
-  // Skip [[ ]] and (( )) contents for now
+  // Was anything left after the assignments?
   if ((s = arg->v[envlen])) {
+    // Skip [[ ]] and (( )) contents for now
     if (!smemcmp(s, "((", 2)) skiplen = 1;
     else if (!strcmp(s, "[[")) while (strcmp(arg->v[envlen+skiplen++], "]]"));
   }
@@ -2818,6 +2925,7 @@ static struct sh_process *run_command(void)
 
 // TODO: if error stops redir, expansion assignments, prefix assignments,
 // what sequence do they occur in?
+  // Handle expansions for (( )) and [[ ]]
   if (skiplen) {
     // Trailing redirects can't expand to any contents
     if (pp->arg.c) {
@@ -2829,30 +2937,23 @@ static struct sh_process *run_command(void)
 // TODO: [[ ~ ] expands but ((~)) doesn't, what else?
         if (expand_arg(&pp->arg, arg->v[envlen+ii], NO_PATH|NO_SPLIT, &pp->delete))
           break;
-      if (ii != skiplen) pp->exit = toys.exitval = 1;
+      if (ii!=skiplen) pp->exit = toys.exitval = 1;
     }
     if (pp->exit) return pp;
   }
 
   // Are we calling a shell function?  TODO binary search
-  if (pp->arg.c)
-    if (!strchr(s, '/')) for (funk = 0; funk<TT.funcslen; funk++)
-       if (!strcmp(s, TT.functions[funk]->name)) break;
-
-  // Create new function context to hold local vars?
-  if (funk != TT.funcslen || (envlen && pp->arg.c) || TT.ff->blk->pipe) {
-    call_function();
-// TODO function needs to run asynchronously in pipeline
-    if (funk != TT.funcslen) {
-      TT.ff->delete = pp->delete;
-      pp->delete = 0;
-    }
-    addvar(0, TT.ff); // function context (not source) so end_fcall deletes
-    prefix = 1;  // create local variables for function prefix assignment
-  }
+  if (pp->arg.c && !strchr(s, '/')) for (funk = 0; funk<TT.funcslen; funk++)
+    if (!strcmp(s, TT.functions[funk]->name)) break;
+
+  // If calling a function, or prefix assignment, or output is piped,
+  // create new function context to hold local vars
+  prefix = (envlen && pp->arg.c) || pipe;
+  (call_function()->pp = pp)->refcount++;
+// TODO function needs to run asynchronously in pipeline, and backgrounded
 
   // perform any assignments
-  if (envlen) for (; jj<envlen && !pp->exit; jj++) {
+  for (jj = 0; jj<envlen && !pp->exit; jj++) {
     struct sh_vars *vv;
 
     if ((sss = expand_one_arg(ss = arg->v[jj], SEMI_IFS))) {
@@ -2861,47 +2962,38 @@ static struct sh_process *run_command(void)
         if (prefix) vv->flags |= VAR_EXPORT;
         continue;
       }
-    }
-
-    pp->exit = 1;
-    break;
+    } else pp->exit = 1;
   }
 
-  // Do the thing
-  if (pp->exit || envlen==arg->c) s = 0; // leave $_ alone
-  else if (!pp->arg.c) s = "";           // nothing to do but blank $_
-
-// TODO: call functions() FUNCTION
 // TODO what about "echo | x=1 | export fruit", must subshell? Test this.
 //   Several NOFORK can just NOP in a pipeline? Except ${a?b} still errors
 
+  // If variable expansion or assignment errored, do nothing
+  if (pp->exit);
+  // If nothing to do after assignments, blank $_
+  else if (!pp->arg.c) TT.ff->_ = "";
   // ((math))
-  else if (!smemcmp(s = *pp->arg.v, "((", 2)) {
+  else if (skiplen && !smemcmp(s = *pp->arg.v, "((", 2)) {
     char *ss = s+2;
     long long ll;
 
-    funk = TT.funcslen;
     ii = strlen(s)-2;
     if (!recalculate(&ll, &ss, 0) || ss!=s+ii)
-      perror_msg("bad math: %.*s @ %ld", ii-2, s+2, (long)(ss-s)-2);
+      sherror_msg("bad math: %.*s @ %ld", ii-2, s+2, (long)(ss-s)-2);
     else toys.exitval = !ll;
     pp->exit = toys.exitval;
-    s = 0; // Really!
-
   // call shell function
   } else if (funk != TT.funcslen) {
-    s = 0; // $_ set on return, not here
-    (TT.ff->func = TT.functions[funk])->refcount++;
-    TT.ff->pl = TT.ff->func->pipeline;
+    (TT.ff->function = TT.functions[funk])->refcount++;
+    TT.ff->pl = TT.ff->function->pipeline;
     TT.ff->arg = pp->arg;
-// TODO: unredirect(pp->urd) called below but haven't traversed function yet
+    TT.ff->_ = pp->arg.v[pp->arg.c-1];
+  // call command from $PATH or toybox builtin
   } else {
     struct toy_list *tl = toy_find(*pp->arg.v);
 
     jj = tl ? tl->flags : 0;
-    TT.pp = pp;
-    s = pp->arg.v[pp->arg.c-1];
-    sss = pp->arg.v[pp->arg.c];
+    TT.ff->_ = pp->arg.v[pp->arg.c-1];
 //dprintf(2, "%d run command %p %s\n", getpid(), TT.ff, *pp->arg.v); debug_show_fds();
 // TODO: figure out when can exec instead of forking, ala sh -c blah
 
@@ -2928,34 +3020,20 @@ static struct sh_process *run_command(void)
       toys.rebound = prebound;
       pp->exit = toys.exitval;
       clearerr(stdout);
-      if (toys.optargs != toys.argv+1) free(toys.optargs);
+      if (toys.optargs != toys.argv+1) push_arg(&pp->delete, toys.optargs);
       if (toys.old_umask) umask(toys.old_umask);
       memcpy(&toys, &temp, jj);
+    // Run command in new child process
     } else if (-1==(pp->pid = xpopen_setup(pp->arg.v, 0, sh_exec)))
         perror_msg("%s: vfork", *pp->arg.v);
   }
 
-  // cleanup process
-  unredirect(pp->urd);
-  pp->urd = 0;
-  if (prefix && funk == TT.funcslen) end_fcall(0);
-  if (s) setvarval("_", s);
+  // pop the new function context if nothing left for it to do
+  if (!TT.ff->source && !TT.ff->pl) end_fcall();
 
   return pp;
 }
 
-static int free_process(struct sh_process *pp)
-{
-  int rc;
-
-  if (!pp) return 127;
-  rc = pp->exit;
-  llist_traverse(pp->delete, llist_free_arg);
-  free(pp);
-
-  return rc;
-}
-
 // if then fi for while until select done done case esac break continue return
 
 // Free one pipeline segment.
@@ -2986,7 +3064,7 @@ static struct sh_pipeline *add_pl(struct sh_pipeline **ppl, struct sh_arg **arg)
   struct sh_pipeline *pl = xzalloc(sizeof(struct sh_pipeline));
 
   if (arg) *arg = pl->arg;
-  pl->lineno = TT.LINENO;
+  pl->lineno = TT.ff->lineno;
   dlist_add_nomalloc((void *)ppl, (void *)pl);
 
   return pl->end = pl;
@@ -2994,12 +3072,11 @@ static struct sh_pipeline *add_pl(struct sh_pipeline **ppl, struct sh_arg **arg)
 
 // Add a line of shell script to a shell function. Returns 0 if finished,
 // 1 to request another line of input (> prompt), -1 for syntax err
-static int parse_line(char *line, struct sh_pipeline **ppl,
-   struct double_list **expect)
+static int parse_line(char *line, struct double_list **expect)
 {
   char *start = line, *delete = 0, *end, *s, *ex, done = 0,
     *tails[] = {"fi", "done", "esac", "}", "]]", ")", 0};
-  struct sh_pipeline *pl = *ppl ? (*ppl)->prev : 0, *pl2, *pl3;
+  struct sh_pipeline *pl = TT.ff->pl ? TT.ff->pl->prev : 0, *pl2, *pl3;
   struct sh_arg *arg = 0;
   long i;
 
@@ -3020,12 +3097,12 @@ static int parse_line(char *line, struct sh_pipeline **ppl,
     } else if (pl->count != pl->here) {
 here_loop:
       // Back up to oldest unfinished pipeline segment.
-      while (pl != *ppl && pl->prev->count != pl->prev->here) pl = pl->prev;
+      while (pl!=TT.ff->pl && pl->prev->count != pl->prev->here) pl = pl->prev;
       arg = pl->arg+1+pl->here;
 
       // Match unquoted EOF.
       if (!line) {
-        error_msg("%u: <<%s EOF", TT.LINENO, arg->v[arg->c]);
+        sherror_msg("<<%s EOF", arg->v[arg->c]);
         goto here_end;
       }
       for (s = line, end = arg->v[arg->c]; *end; s++, end++) {
@@ -3043,7 +3120,7 @@ here_end:
         // End segment and advance/consume bridge segments
         arg->v[arg->c] = 0;
         if (pl->count == ++pl->here)
-          while (pl->next != *ppl && (pl = pl->next)->here == -1)
+          while (pl->next!=TT.ff->pl && (pl = pl->next)->here == -1)
             pl->here = pl->count;
       }
       if (pl->here != pl->count) {
@@ -3070,14 +3147,14 @@ here_end:
 
         // Add another arg[] to the pipeline segment (removing/re-adding
         // to list because realloc can move pointer, and adjusing end pointers)
-        dlist_lpop(ppl);
+        dlist_lpop(&TT.ff->pl);
         pl2 = pl;
         pl = xrealloc(pl, sizeof(*pl)+(++pl->count+1)*sizeof(struct sh_arg));
         arg = pl->arg;
-        dlist_add_nomalloc((void *)ppl, (void *)pl);
-        for (pl3 = *ppl;;) {
+        dlist_add_nomalloc((void *)&TT.ff->pl, (void *)pl);
+        for (pl3 = TT.ff->pl;;) {
           if (pl3->end == pl2) pl3->end = pl;
-          if ((pl3 = pl3->next) == *ppl) break;
+          if ((pl3 = pl3->next)==TT.ff->pl) break;
         }
 
         // queue up HERE EOF so input loop asks for more lines.
@@ -3110,7 +3187,7 @@ here_end:
     }
 
     // Is this a new pipeline segment?
-    if (!pl) pl = add_pl(ppl, &arg);
+    if (!pl) pl = add_pl(&TT.ff->pl, &arg);
 
     // Do we need to request another line to finish word (find ending quote)?
     if (!end) {
@@ -3146,7 +3223,7 @@ here_end:
           if (pl->prev->type == 2) {
             // Add a call to "true" between empty ) ;;
             arg_add(arg, xstrdup(":"));
-            pl = add_pl(ppl, &arg);
+            pl = add_pl(&TT.ff->pl, &arg);
           }
           pl->type = 129;
         } else {
@@ -3175,8 +3252,8 @@ here_end:
       // Stop at EOL. Discard blank pipeline segment, else end segment
       if (end == start) done++;
       if (!pl->type && !arg->c) {
-        free_pipeline(dlist_lpop(ppl));
-        pl = *ppl ? (*ppl)->prev : 0;
+        free_pipeline(dlist_lpop(&TT.ff->pl));
+        pl = TT.ff->pl ? TT.ff->pl->prev : 0;
       } else pl->count = -1;
 
       continue;
@@ -3194,7 +3271,7 @@ here_end:
         if (arg->c==3) {
           if (strcmp(s, "in")) goto flush;
           pl->type = 1;
-          (pl = add_pl(ppl, &arg))->type = 129;
+          (pl = add_pl(&TT.ff->pl, &arg))->type = 129;
         }
 
         continue;
@@ -3211,7 +3288,7 @@ here_end:
           // esac right after "in" or ";;" ends block, fall through
           if (arg->c>1) {
             arg->v[1] = 0;
-            pl = add_pl(ppl, &arg);
+            pl = add_pl(&TT.ff->pl, &arg);
             arg_add(arg, s);
           } else pl->type = 0;
         } else {
@@ -3219,7 +3296,7 @@ here_end:
           if (i>0 && ((i&1)==!!strchr("|)", *s) || strchr(";(", *s)))
             goto flush;
           if (*s=='&' || !strcmp(s, "||")) goto flush;
-          if (*s==')') pl = add_pl(ppl, &arg);
+          if (*s==')') pl = add_pl(&TT.ff->pl, &arg);
 
           continue;
         }
@@ -3400,8 +3477,8 @@ here_end:
   free(delete);
 
   // Return now if line didn't tell us to DO anything.
-  if (!*ppl) return 0;
-  pl = (*ppl)->prev;
+  if (!TT.ff->pl) return 0;
+  pl = TT.ff->pl->prev;
 
   // return if HERE document pending or more flow control needed to complete
   if (pl->count != pl->here) return 1;
@@ -3435,23 +3512,19 @@ here_end:
       pl2->prev = 0;
       pl3->next = 0;
     }
-    if (pl == *ppl) break;
+    if (pl == TT.ff->pl) break;
     pl = pl->prev;
   }
 
   // Don't need more input, can start executing.
 
-  dlist_terminate(*ppl);
+  dlist_terminate(TT.ff->pl);
   return 0;
 
 flush:
   if (s) syntax_err(s);
-  llist_traverse(*ppl, free_pipeline);
-  *ppl = 0;
-  llist_traverse(*expect, free);
-  *expect = 0;
 
-  return 0-!!s;
+  return -1;
 }
 
 // Find + and - jobs. Returns index of plus, writes minus to *minus
@@ -3502,7 +3575,7 @@ char *show_job(struct sh_process *pp, char dash)
 // Wait for pid to exit and remove from jobs table, returning process or 0.
 struct sh_process *wait_job(int pid, int nohang)
 {
-  struct sh_process *pp = pp;
+  struct sh_process *pp QUIET;
   int ii, status, minus, plus;
 
   if (TT.jobs.c<1) return 0;
@@ -3543,7 +3616,7 @@ static int wait_pipeline(struct sh_process *pp)
     rc = (pp->flags&PFLAG_NOT) ? !pp->exit : pp->exit;
   }
 
-  while ((pp = wait_job(-1, 1)) && (TT.options&FLAG_i)) {
+  while ((pp = wait_job(-1, 1)) && dashi()) {
     char *s = show_job(pp, pp->dash);
 
     dprintf(2, "%s\n", s);
@@ -3567,7 +3640,7 @@ static void do_prompt(char *prompt)
     if (c=='!') {
       if (*prompt=='!') prompt++;
       else {
-        pp += snprintf(pp, len, "%u", TT.LINENO);
+        pp += snprintf(pp, len, "%ld", TT.ff->lineno);
         continue;
       }
     } else if (c=='\\') {
@@ -3613,13 +3686,15 @@ static void do_prompt(char *prompt)
   writeall(2, toybuf, len);
 }
 
-// returns NULL for EOF, 1 for invalid, else null terminated string.
-static char *get_next_line(FILE *ff, int prompt)
+// returns NULL for EOF or error, else null terminated string.
+static char *get_next_line(FILE *fp, int prompt)
 {
   char *new;
   int len, cc;
+  unsigned uu;
 
-  if (!ff) {
+  if (!fp) return 0;
+  if (prompt>2 || (fp==stdin && dashi())) {
     char ps[16];
 
     sprintf(ps, "PS%d", prompt);
@@ -3636,10 +3711,9 @@ static char *get_next_line(FILE *ff, int prompt)
 
   for (new = 0, len = 0;;) {
     errno = 0;
-    if (!(cc = getc(ff ? : stdin))) {
-      if (TT.LINENO) continue;
-      free(new);
-      return (char *)1;
+    if (!(cc = getc(fp))) {
+      if (prompt!=1 || TT.ff->lineno) continue;
+      cc = 255; // force invalid utf8 sequence detection
     }
     if (cc<0) {
       if (errno == EINTR) continue;
@@ -3648,8 +3722,20 @@ static char *get_next_line(FILE *ff, int prompt)
     if (!(len&63)) new = xrealloc(new, len+65);
     if ((new[len++] = cc) == '\n') break;
   }
-  if (new) new[len] = 0;
-
+  if (!new) return new;
+  new[len] = 0;
+
+  // Check for binary file?
+  if (prompt<3 && !TT.ff->lineno++ && TT.ff->name) {
+    // A shell script's first line has no high bytes that aren't valid utf-8.
+    for (len = 0; new[len]>6 && 0<(cc = utf8towc(&uu, new+len, 4)); len += cc);
+    if (new[len]) {
+      sherror_msg("'%s' is binary", TT.ff->name); // TODO syntax_err() exit?
+      free(new);
+      new = 0;
+    }
+  }
+//dprintf(2, "%d get_next_line=%s\n", getpid(), new ? : "(null)");
   return new;
 }
 
@@ -3678,9 +3764,27 @@ static void run_lines(void)
 
   // iterate through pipeline segments
   for (;;) {
+    // Call functions for pending signals, in order received
+    while (TT.nextsig) {
+      struct double_list *dl;
+      sigset_t set;
+
+      // Block signals so list doesn't change under us
+      sigemptyset(&set);
+      sigprocmask(SIG_SETMASK, &set, &set);
+      dl = dlist_pop(&TT.nextsig);
+      sigprocmask(SIG_SETMASK, &set, 0);
+      ss = TT.traps[call_function()->signal = (long)dl->data];
+      TT.ff->signal = (TT.ff->signal<<8)|(toys.exitval&255);
+      free(dl);
+      TT.ff->source = fmemopen(ss, strlen(ss), "r");
+    }
     if (!TT.ff->pl) {
-      if (!end_fcall(1)) break;
-      goto advance;
+      if (TT.ff->source) break;
+      i = TT.ff->signal;
+      end_fcall();
+// TODO can we move advance logic to start of loop to avoid straddle?
+      if (!i || !TT.ff || !TT.ff->pl) goto advance;
     }
 
     ctl = TT.ff->pl->end->arg->v[TT.ff->pl->end->arg->c];
@@ -3698,20 +3802,19 @@ static void run_lines(void)
       }
 
       if (TT.options&OPT_x) {
-        unsigned lineno;
         char *ss, *ps4 = getvar("PS4");
+        struct sh_fcall *ff;
 
         // duplicate first char of ps4 call depth times
         if (ps4 && *ps4) {
+
+          for (ff = TT.ff, i = 0; ff != TT.ff->prev; ff = ff->next)
+            if (ff->source && ff->name) i++;
           j = getutf8(ps4, k = strlen(ps4), 0);
-          ss = xmalloc(TT.srclvl*j+k+1);
-          for (k = 0; k<TT.srclvl; k++) memcpy(ss+k*j, ps4, j);
+          ss = xmalloc(i*j+k+1);
+          for (k = 0; k<i; k++) memcpy(ss+k*j, ps4, j);
           strcpy(ss+k*j, ps4+j);
-          // show saved line number from function, not next to read
-          lineno = TT.LINENO;
-          TT.LINENO = TT.ff->pl->lineno;
           do_prompt(ss);
-          TT.LINENO = lineno;
           free(ss);
 
           // TODO resolve variables
@@ -3757,11 +3860,11 @@ static void run_lines(void)
     }
 
     // If executable segment parse and run next command saving resulting process
-    if (!TT.ff->pl->type) 
-      dlist_add_nomalloc((void *)&pplist, (void *)run_command());
+    if (!TT.ff->pl->type) {
+      if ((pp = run_command())) dlist_add_nomalloc((void *)&pplist, (void *)pp);
 
     // Start of flow control block?
-    else if (TT.ff->pl->type == 1) {
+    } else if (TT.ff->pl->type == 1) {
 
 // TODO test cat | {thingy} is new PID: { is ( for |
 
@@ -3785,7 +3888,6 @@ static void run_lines(void)
       // If we spawn a subshell, pass data off to child process
       if (TT.ff->blk->next->pipe || !strcmp(s, "(") || (ctl && !strcmp(ctl, "&"))) {
         if (!(pp->pid = run_subshell(0, -1))) {
-
           // zap forked child's cleanup context and advance to next statement
           pplist = 0;
           while (TT.ff->blk->next) TT.ff->blk = TT.ff->blk->next;
@@ -3839,7 +3941,7 @@ static void run_lines(void)
             }
             in = out = *TT.ff->blk->farg.v;
             if (!recalculate(&ll, &in, 0) || *in) {
-              perror_msg("bad math: %s @ %ld", in, (long)(in-out));
+              sherror_msg("bad math: %s @ %ld", in, (long)(in-out));
               break;
             }
 
@@ -3926,7 +4028,7 @@ do_then:
           blk->run = blk->run && toys.exitval;
           toys.exitval = 0;
         } else if (!strcmp(ss, "select")) {
-          if (!(ss = get_next_line(0, 3)) || ss==(void *)1) {
+          if (!(ss = get_next_line(stdin, 3))) {
             TT.ff->pl = pop_block();
             printf("\n");
           } else {
@@ -3951,7 +4053,7 @@ do_then:
             }
             aa = bb = TT.ff->blk->farg.v[i];
             if (!recalculate(&ll, &aa, 0) || *aa) {
-              perror_msg("bad math: %s @ %ld", aa, (long)(aa-bb));
+              sherror_msg("bad math: %s @ %ld", aa, (long)(aa-bb));
               break;
             }
             if (i==1 && !ll) TT.ff->pl = pop_block();
@@ -4001,7 +4103,7 @@ do_then:
         if (!TT.jobs.c) TT.jobcnt = 0;
         pplist->job = ++TT.jobcnt;
         arg_add(&TT.jobs, (void *)pplist);
-        if (TT.options&FLAG_i) dprintf(2, "[%u] %u\n", pplist->job,pplist->pid);
+        if (dashi()) dprintf(2, "[%u] %u\n", pplist->job,pplist->pid);
       } else {
         toys.exitval = wait_pipeline(pplist);
         llist_traverse(pplist, (void *)free_process);
@@ -4009,6 +4111,7 @@ do_then:
       pplist = 0;
     }
 advance:
+    if (!TT.ff || !TT.ff->pl) break;
     // for && and || skip pipeline segment(s) based on return code
     if (!TT.ff->pl->type || TT.ff->pl->type == 3) {
       for (;;) {
@@ -4025,15 +4128,12 @@ advance:
     toys.exitval = wait_pipeline(pplist);
     llist_traverse(pplist, (void *)free_process);
   }
-
-  // exit source context (and function calls on syntax err)
-  while (end_fcall(0));
 }
 
 // set variable
 static struct sh_vars *initvar(char *name, char *val)
 {
-  return addvar(xmprintf("%s=%s", name, val ? val : ""), TT.ff);
+  return addvar(xmprintf("%s=%s", name, val ? : ""), TT.ff);
 }
 
 static struct sh_vars *initvardef(char *name, char *val, char *def)
@@ -4081,7 +4181,7 @@ FILE *fpathopen(char *name)
 
   if (fd==-1) {
     for (sl = find_in_path(pp, name); sl; free(llist_pop(&sl)))
-      if (-1==(fd = open(sl->str, O_RDONLY|O_CLOEXEC))) break;
+      if (-1!=(fd = open(sl->str, O_RDONLY|O_CLOEXEC))) break;
     if (sl) llist_traverse(sl, free);
   }
   if (fd != -1) {
@@ -4094,75 +4194,6 @@ FILE *fpathopen(char *name)
   return fd==-1 ? 0 : fdopen(fd, "r");
 }
 
-// Read script input and execute lines, with or without prompts
-// If !ff input is interactive (prompt, editing, etc)
-int do_source(char *name, FILE *ff)
-{
-  struct sh_pipeline *pl = 0;
-  struct double_list *expect = 0;
-  unsigned lineno = TT.LINENO, more = 0, wc;
-  int cc, ii;
-  char *new;
-
-  TT.recfile[TT.recursion++] = ff ? fileno(ff) : 0;
-  if (TT.recursion++>ARRAY_LEN(TT.recfile)) {
-    error_msg("recursive occlusion");
-
-    goto end;
-  }
-
-  if (name) TT.ff->omnom = name;
-
-// TODO fix/catch O_NONBLOCK on input?
-// TODO when DO we reset lineno? (!LINENO means \0 returns 1)
-// when do we NOT reset lineno? Inherit but preserve perhaps? newline in $()?
-  if (!name) TT.LINENO = 0;
-
-  do {
-    if ((void *)1 == (new = get_next_line(ff, more+1))) goto is_binary;
-//dprintf(2, "%d getline from %p %s\n", getpid(), ff, new); debug_show_fds();
-    // did we exec an ELF file or something?
-    if (!TT.LINENO++ && name && new) {
-      // A shell script's first line has no high bytes that aren't valid utf-8.
-      for (ii = 0; new[ii]>6 && 0<(cc = utf8towc(&wc, new+ii, 4)); ii += cc);
-      if (new[ii]) {
-is_binary:
-        if (name) error_msg("'%s' is binary", name); // TODO syntax_err() exit?
-        if (new != (void *)1) free(new);
-        new = 0;
-      }
-    }
-
-    // TODO: source <(echo 'echo hello\') vs source <(echo -n 'echo hello\')
-    // prints "hello" vs "hello\"
-
-    // returns 0 if line consumed, command if it needs more data
-    more = parse_line(new, &pl, &expect);
-    free(new);
-    if (more==1) {
-      if (!new) syntax_err("unexpected end of file");
-      else continue;
-    } else if (!more && pl) {
-      TT.ff->pl = pl;
-      run_lines();
-    } else more = 0;
-
-    llist_traverse(pl, free_pipeline);
-    pl = 0;
-    llist_traverse(expect, free);
-    expect = 0;
-  } while (new);
-
-  if (ff) fclose(ff);
-
-  if (!name) TT.LINENO = lineno;
-
-end:
-  TT.recursion--;
-
-  return more;
-}
-
 // On nommu we had to exec(), so parent environment is passed via a pipe.
 static void nommu_reentry(void)
 {
@@ -4170,7 +4201,6 @@ static void nommu_reentry(void)
   int ii, pid, ppid, len;
   unsigned long ll;
   char *s = 0;
-  FILE *fp;
 
   // Sanity check
   if (!fstat(254, &st) && S_ISFIFO(st.st_mode)) {
@@ -4182,27 +4212,31 @@ static void nommu_reentry(void)
   }
   if (!s || s[len] || pid!=getpid() || ppid!=getppid()) error_exit(0);
 
+  // NOMMU subshell commands come from pipe from parent
+  TT.ff->source = fdopen(254, "r");
+
+  // But first, we have to marshall context across the pipe into child
+
 // TODO signal setup before this so fscanf can't EINTR.
 // TODO marshall TT.jobcnt TT.funcslen: child needs jobs and function list
+// TODO marshall functions (including signal handlers?)
+// TODO test: call function from subshell, send signal to subshell/background
+
   // Marshall magics: $SECONDS $- $LINENO $$ $!
-  if (5!=fscanf(fp = fdopen(254, "r"), "%lld %u %u %u %u%*[^\n]", &TT.SECONDS,
-      &TT.options, &TT.LINENO, &TT.pid, &TT.bangpid)) error_exit(0);
+  if (5!=fscanf(TT.ff->source, "%lld %u %ld %u %u%*[^\n]", &TT.SECONDS,
+      &TT.options, &TT.ff->lineno, &TT.pid, &TT.bangpid)) error_exit(0);
 
   // Read named variables: type, len, var=value\0
   for (;;) {
     len = ll = 0;
-    (void)fscanf(fp, "%u %lu%*[^\n]", &len, &ll);
-    fgetc(fp); // Discard the newline fscanf didn't eat.
+    (void)fscanf(TT.ff->source, "%u %lu%*[^\n]", &len, &ll);
+    fgetc(TT.ff->source); // Discard the newline fscanf didn't eat.
     if (!len) break;
     (s = xmalloc(len+1))[len] = 0;
     for (ii = 0; ii<len; ii += pid)
-      if (1>(pid = fread(s+ii, 1, len-ii, fp))) error_exit(0);
+      if (1>(pid = fread(s+ii, 1, len-ii, TT.ff->source))) error_exit(0);
     set_varflags(s, ll, 0);
   }
-
-  // Perform subshell command(s)
-  do_source(0, fp);
-  xexit();
 }
 
 // init locals, sanitize environment, handle nommu subshell handoff
@@ -4263,9 +4297,6 @@ static void subshell_setup(void)
     cache_ifs(s, TT.ff); // TODO: replace with set(get("IFS")) after loop
   }
 
-  // set/update PWD
-  do_source(0, fmemopen("cd .", 4, "r"));
-
   // set _ to path to this shell
   s = toys.argv[0];
   ss = 0;
@@ -4284,32 +4315,52 @@ static void subshell_setup(void)
   else {
     char buf[16];
 
-    sprintf(buf, "%u", atoi(ss+6)+1);
+    sprintf(buf, "%u", atoi(ss)+1);
     setvarval("SHLVL", buf)->flags |= VAR_EXPORT;
   }
+  if (dashi() && !getvar("PS1")) setvarval("PS1", "$ "); // "\\s-\\v$ "
+  // TODO Set up signal handlers and grab control of this tty.
+  // ^C SIGINT ^\ SIGQUIT ^Z SIGTSTP SIGTTIN SIGTTOU SIGCHLD
+  // setsid(), setpgid(), tcsetpgrp()...
+  signify(SIGINT, 0);
+
+  // Find input source
+  if (TT.sh.c) {
+    TT.ff->source = fmemopen(TT.sh.c, strlen(TT.sh.c), "r");
+    TT.ff->name = "-c";
+  } else if (TT.options&FLAG_s) TT.ff->source = stdin;
+  else if (!(TT.ff->source = fpathopen(TT.ff->name = *toys.optargs)))
+    perror_exit_raw(*toys.optargs);
+
+  // Add additional input sources (in reverse order so they pop off stack right)
+
+  // /etc/profile, ~/.bashrc...
+
+  // set/update PWD, but don't let it overwrite $_
+  call_function()->source = fmemopen("cd .", 4, "r");
+  addvar("_=", TT.ff)->flags = VAR_NOFREE;
 }
 
 void sh_main(void)
 {
-  char *cc = 0;
-  FILE *ff;
+// TODO should expect also move into TT.ff like pl did
+  struct double_list *expect = 0;
+  char *new;
+  unsigned more = 0;
 
 //dprintf(2, "%d main", getpid()); for (unsigned uu = 0; toys.argv[uu]; uu++) dprintf(2, " %s", toys.argv[uu]); dprintf(2, "\n");
 
-  signal(SIGPIPE, SIG_IGN);
+  signify(SIGPIPE, 0);
   TT.options = OPT_B;
   TT.pid = getpid();
   srandom(TT.SECONDS = millitime());
 
   // TODO euid stuff?
   // TODO login shell?
-  // TODO read profile, read rc
-
-  // if (!FLAG(noprofile)) { }
+  // TODO read profile, read rc, if (!FLAG(noprofile)) { }
 
   // If not reentering, figure out if this is an interactive shell.
   if (toys.stacktop) {
-    cc = TT.sh.c;
     if (!FLAG(c)) {
       if (toys.optc==1) toys.optflags |= FLAG_s;
       if (FLAG(s) && isatty(0)) toys.optflags |= FLAG_i;
@@ -4322,32 +4373,50 @@ void sh_main(void)
   }
 
   // Create initial function context
-  call_function();
-  TT.ff->arg.v = toys.optargs;
-  TT.ff->arg.c = toys.optc;
+  call_function()->arg = (struct sh_arg){.v = toys.optargs, .c = toys.optc};
   TT.ff->ifs = " \t\n";
+  TT.ff->name = FLAG(i) ? toys.which->name : "main";
+
+  // Set up environment variables and queue up initial command input source
+  if (CFG_TOYBOX_FORK || toys.stacktop) subshell_setup();
+  else nommu_reentry();
 
-  // Set up environment variables.
-  // Note: can call run_command() which blanks argument sections of TT and this,
+  // Note: run_command() blanks argument sections of TT and this,
   // so parse everything we need from shell command line before here.
-  if (CFG_TOYBOX_FORK || toys.stacktop) subshell_setup(); // returns
-  else nommu_reentry(); // does not return
-
-  if (TT.options&FLAG_i) {
-    if (!getvar("PS1")) setvarval("PS1", getpid() ? "\\$ " : "# ");
-    // TODO Set up signal handlers and grab control of this tty.
-    // ^C SIGINT ^\ SIGQUIT ^Z SIGTSTP SIGTTIN SIGTTOU SIGCHLD
-    // setsid(), setpgid(), tcsetpgrp()...
-    xsignal(SIGINT, SIG_IGN);
-  }
 
-  if (cc) ff = fmemopen(cc, strlen(cc), "r");
-  else if (TT.options&FLAG_s) ff = (TT.options&FLAG_i) ? 0 : stdin;
-  else if (!(ff = fpathopen(*toys.optargs))) perror_exit_raw(*toys.optargs);
+// TODO fix/catch O_NONBLOCK on input?
+
+  // Main execution loop: read input and execute lines, with or without prompts.
+  if (CFG_TOYBOX_FORK) setjmp(TT.forkchild);
+  for (;;) {
+    // if this fcall has source but not dlist_terminate()d pl, get line & parse
+    if (TT.ff->source && (!TT.ff->pl || TT.ff->pl->prev)) {
+      new = get_next_line(TT.ff->source, more+1);
+      more = parse_line(new, &expect);
+      free(new);
+      if (more==1) {
+        if (new) continue;
+        syntax_err("unexpected end of file");
+      }
+      // at EOF or error, close source and signal run_lines to pop fcall
+      if (!new && TT.ff->source) {
+        fclose(TT.ff->source);
+        TT.ff->source = 0;
+      }
+    }
+
+    // TODO: source <(echo 'echo hello\') vs source <(echo -n 'echo hello\')
+    // prints "hello" vs "hello\"
+    if (!more) run_lines();
+    if (!TT.ff) break;
+    more = 0;
+    llist_traverse(TT.ff->pl, free_pipeline);
+    TT.ff->pl = 0;
+    llist_traverse(expect, free);
+    expect = 0;
+  }
 
-  // Read and execute lines from file
-  if (do_source(cc ? : *toys.optargs, ff))
-    error_exit("%u:unfinished line"+3*!TT.LINENO, TT.LINENO);
+  // exit signal.
 }
 
 // TODO: ./blah.sh one two three: put one two three in scratch.arg
@@ -4357,13 +4426,24 @@ void sh_main(void)
 // Note: "break &" in bash breaks in the child, this breaks in the parent.
 void break_main(void)
 {
-  int i = *toys.optargs ? atolx_range(*toys.optargs, 1, INT_MAX) : 1;
+  unsigned ii = *toys.optargs ? atolx_range(*toys.optargs, 1, INT_MAX) : 1,
+    jj = ii;
+  struct sh_fcall *ff = TT.ff->next;
+  struct sh_blockstack *blk = ff->blk;
 
-  // Peel off encosing do blocks
-  while (i && TT.ff->blk->next)
-    if (TT.ff->blk->middle && !strcmp(*TT.ff->blk->middle->arg->v, "do")
-        && !--i && *toys.which->name=='c') TT.ff->pl = TT.ff->blk->start;
-    else TT.ff->pl = pop_block();
+  // Search for target.
+  for (;;) {
+    if (blk->middle && !strcmp(*blk->middle->arg->v, "do") && !--ii) break;
+    if ((blk = blk->next)) continue;
+    if (ff==TT.ff->prev || ff->function) break;
+    ff = ff->next;
+  }
+  // We try to continue/break N levels deep, but accept fewer.
+  if (ii==jj) error_exit("need for/while/until");
+
+  // Unroll to target
+  while (TT.ff->blk != blk) if (!pop_block()) end_fcall();
+  TT.ff->pl = *toys.which->name=='c' ? TT.ff->blk->start : pop_block();
 }
 
 #define FOR_cd
@@ -4378,7 +4458,7 @@ void cd_main(void)
 
   // For cd - use $OLDPWD as destination directory
   if (!strcmp(dd, "-") && (!(dd = getvar("OLDPWD")) || !*dd))
-    return perror_msg("No $OLDPWD");
+    return error_msg("No $OLDPWD");
 
   if (*dd == '/') pwd = 0;
 
@@ -4483,22 +4563,69 @@ void set_main(void)
   // handle positional parameters
   if (cc) {
     struct arg_list *al, **head;
-    struct sh_arg *arg = &TT.ff->arg;
+    struct sh_fcall *ff = TT.ff->next;
+    struct sh_arg *arg = &ff->arg;
+
+    // Make sure we have a deletion list at correct persistence level
+    if (!ff->pp) {
+      ff->pp = TT.ff->pp;
+      TT.ff->pp = 0;
+    }
 
-    // don't free memory that's already scheduled for deletion
-    for (al = *(head = &TT.ff->delete); al; al = *(head = &al->next))
+    // Was this memory already scheduled for deletion by a previous "set"?
+    for (al = *(head = &ff->pp->delete); al; al = *(head = &al->next))
       if (al->arg == (void *)arg->v) break;
 
     // free last set's memory (if any) so it doesn't accumulate in loop
-    if (al) for (jj = arg->c+1; jj; jj--) {
+    cc = *arg->v;
+    if (al) for (jj = arg->c; jj; jj--) {
       *head = al->next;
       free(al->arg);
       free(al);
+      al = *head;
     }
 
+    // Add copies of each new argument, scheduling them for deletion.
+    *arg = (struct sh_arg){0, 0};
+    arg_add(arg, cc);
     while (toys.optargs[ii])
-      arg_add(arg, push_arg(&TT.ff->delete, strdup(toys.optargs[ii++])));
-    push_arg(&TT.ff->delete, arg->v);
+      arg_add(arg, push_arg(&ff->pp->delete, xstrdup(toys.optargs[ii++])));
+    push_arg(&ff->pp->delete, arg->v);
+  }
+}
+
+#define FOR_trap
+#include "generated/flags.h"
+
+void trap_main(void)
+{
+  int ii, jj;
+  char *sig = *toys.optargs;
+  struct signame sn[] = {{0, "EXIT"}, {NSIG, "DEBUG"}, {NSIG+1, "RETURN"}};
+
+  // Display data when asked
+  if (FLAG(l)) return list_signals();
+  else if (FLAG(p) || !toys.optc) {
+    for (ii = 0; ii<NSIG+2; ii++) if (TT.traps[ii]) {
+      if (!(sig = num_to_sig(ii))) for (jj = 0; jj<ARRAY_LEN(sn); jj++)
+        if (ii==sn[jj].num) sig = sn[jj].name;
+      if (sig) printf("trap -- '%s' %s\n", TT.traps[ii], sig); // TODO $'' esc
+    }
+    return;
+  }
+
+  // Assign new handler to each listed signal
+  if (toys.optc==1 || !**toys.optargs || !strcmp(*toys.optargs, "-")) sig = 0;
+  for (ii = toys.optc>1; toys.optargs[ii]; ii++) {
+    if (1>(jj = sig_to_num(toys.optargs[ii]))) {
+      while (++jj<ARRAY_LEN(sn))
+        if (!strcasecmp(toys.optargs[ii], sn[jj].name)) break;
+      if (jj==ARRAY_LEN(sn)) {
+        sherror_msg("%s: bad signal", toys.optargs[ii]);
+        continue;
+      } else jj = sn[jj].num;
+    }
+    signify(jj, (sig && *sig) ? xstrdup(sig) : sig);
   }
 }
 
@@ -4589,7 +4716,7 @@ void declare_main(void)
   } else if (FLAG(p)) for (arg = toys.optargs; *arg; arg++) {
     struct sh_vars *vv = *varend(ss = *arg) ? 0 : findvar(ss, 0);
 
-    if (!vv) perror_msg("%s: not found", ss);
+    if (!vv) error_msg("%s: not found", ss);
     else {
       xputs(ss = declarep(vv));
       free(ss);
@@ -4608,16 +4735,14 @@ void eval_main(void)
 {
   char *s;
 
-  // borrow the $* expand infrastructure
-  call_function();
-  TT.ff->arg.v = toys.argv;
-  TT.ff->arg.c = toys.optc+1;
-  s = expand_one_arg("\"$*\"", SEMI_IFS);
+  // borrow the $* expand infrastructure to add sh_fcall->source with no ->name
+  TT.ff->arg = (struct sh_arg){.v = toys.argv, .c = toys.optc+1};
+  TT.ff->lineno = TT.ff->next->lineno;
+  s = push_arg(&TT.ff->pp->delete,
+    TT.ff->_ = expand_one_arg("\"$*\"", SEMI_IFS));
+  TT.ff->source = fmemopen(s, strlen(s), "r");
   TT.ff->arg.v = TT.ff->next->arg.v;
   TT.ff->arg.c = TT.ff->next->arg.c;
-  do_source(0, fmemopen(s, strlen(s), "r"));
-  free(dlist_pop(&TT.ff));
-  free(s);
 }
 
 #define FOR_exec
@@ -4628,15 +4753,16 @@ void exec_main(void)
   char *ee[1] = {0}, **old = environ;
 
   // discard redirects and return if nothing to exec
-  free(TT.pp->urd);
-  TT.pp->urd = 0;
+  free(TT.ff->pp->urd);
+  TT.ff->pp->urd = 0;
   if (!toys.optc) return;
 
+//TODO zap isexec
   // exec, handling -acl
   TT.isexec = *toys.optargs;
   if (FLAG(c)) environ = ee;
   if (TT.exec.a || FLAG(l))
-    *toys.optargs = xmprintf("%s%s", FLAG(l) ? "-" : "", TT.exec.a?:TT.isexec);
+    *toys.optargs = xmprintf("-%s"+!FLAG(l), TT.exec.a?:TT.isexec);
   sh_exec(toys.optargs);
 
   // report error (usually ENOENT) and return
@@ -4690,7 +4816,7 @@ void jobs_main(void)
     if (toys.optc) {
       if (!(s = toys.optargs[i])) break;
       if ((j = find_job(s+('%' == *s))) == -1) {
-        perror_msg("%s: no such job", s);
+        error_msg("%s: no such job", s);
 
         continue;
       }
@@ -4714,7 +4840,7 @@ void local_main(void)
   // find local variable context
   for (ff = TT.ff;; ff = ff->next) {
     if (ff == TT.ff->prev) return error_msg("not in function");
-    if (ff->vars) break;
+    if (ff->function) break;
   }
 
   // list existing vars (todo:
@@ -4730,7 +4856,7 @@ void local_main(void)
       continue;
     }
 
-    if ((var = findvar(*arg, &ff2)) && ff == ff2 && !*eq) continue;
+    if ((var = findvar(*arg, &ff2)) && ff==ff2 && !*eq) continue;
     if (var && (var->flags&VAR_READONLY)) {
       error_msg("%.*s: readonly variable", (int)(varend(*arg)-*arg), *arg);
       continue;
@@ -4756,18 +4882,15 @@ void return_main(void)
 
   if (*toys.optargs) {
     toys.exitval = estrtol(*toys.optargs, &ss, 0);
-    if (errno || *ss) error_msg("NaN");
+    if (errno || *ss) return error_msg("NaN");
   }
 
   // Do we have a non-transparent function context in the call stack?
-  for (ff = TT.ff; !ff->func; ff = ff->next)
-    if (ff == TT.ff->prev) return error_msg("not function or source");
+  for (ff = TT.ff; !ff->function && !ff->source; ff = ff->next)
+    if (ff==TT.ff->prev) return error_msg("not function or source");
 
-  // Pop all blocks to start of function
-  for (ff = TT.ff;; ff = ff->next) {
-    while (TT.ff->blk->next) TT.ff->pl = pop_block();
-    if (ff->func) break;
-  }
+  while (TT.ff!=ff) end_fcall();
+  TT.ff->pl = 0;
 }
 
 void shift_main(void)
@@ -4775,32 +4898,26 @@ void shift_main(void)
   long long by = 1;
 
   if (toys.optc) by = atolx(*toys.optargs);
-  by += TT.ff->shift;
-  if (by<0 || by>=TT.ff->arg.c) toys.exitval++;
-  else TT.ff->shift = by;
+  by += TT.ff->next->shift;
+  if (by<0 || by>=TT.ff->next->arg.c) toys.exitval++;
+  else TT.ff->next->shift = by;
 }
 
+// TODO add tests: sh -c "source input four five" one two three
 void source_main(void)
 {
-  char *name = *toys.optargs;
-  FILE *ff = fpathopen(name);
+  int ii;
 
-  if (!ff) return perror_msg_raw(name);
-  // $0 is shell name, not source file name while running this
-// TODO add tests: sh -c "source input four five" one two three
+  if (!(TT.ff->source = fpathopen(*toys.optargs)))
+    return perror_msg_raw(*toys.optargs);
+
+  // lifetime of optargs handled by TT.ff->pp
+  TT.ff->_ = toys.optargs[toys.optc-1];
+  TT.ff->name = *toys.optargs;
   *toys.optargs = *toys.argv;
-  ++TT.srclvl;
-  call_function();
-  TT.ff->func = (void *)1;
-  TT.ff->arg.v = toys.optargs;
-  TT.ff->arg.c = toys.optc;
-  TT.ff->oldlineno = TT.LINENO;
-  TT.LINENO = 0;
-  do_source(name, ff);
-  TT.LINENO = TT.ff->oldlineno;
-  // TODO: this doesn't do proper cleanup but isn't normal fcall either
-  free(dlist_pop(&TT.ff));
-  --TT.srclvl;
+  TT.ff->arg.v = toys.argv; // $0 is shell name, not source file name. Bash!
+  for (ii = 0; toys.argv[ii]; ii++);
+  TT.ff->arg.c = ii;
 }
 
 #define FOR_wait
diff --git a/toys/posix/file.c b/toys/posix/file.c
index 566daf1d..0f3af847 100644
--- a/toys/posix/file.c
+++ b/toys/posix/file.c
@@ -322,6 +322,8 @@ static void do_regular_file(int fd, char *name)
     xprintf("bzip2 compressed data, block size = %c00k\n", *s);
   else if (len>31 && peek_be(s, 7) == 0xfd377a585a0000ULL)
     xputs("xz compressed data");
+  else if (len>10 && strstart(&s, "\x28\xb5\x2f\xfd"))
+    xputs("zstd compressed data");
   else if (len>10 && strstart(&s, "\x1f\x8b")) xputs("gzip compressed data");
   else if (len>32 && !smemcmp(s+1, "\xfa\xed\xfe", 3)) {
     int bit = (*s==0xce) ? 32 : 64;
diff --git a/toys/posix/patch.c b/toys/posix/patch.c
index 4030834d..b66d590c 100644
--- a/toys/posix/patch.c
+++ b/toys/posix/patch.c
@@ -166,6 +166,7 @@ static int apply_one_hunk(void)
     }
   }
   matcheof = !trail || trail < TT.context;
+  if (FLAG(F) && !TT.F) fuzz = 0;
   if (fuzz>1) allfuzz = TT.F ? : TT.context ? TT.context-1 : 0;
 
   // Loop through input data searching for this hunk. Match all context
diff --git a/toys/posix/ps.c b/toys/posix/ps.c
index 0e95c9eb..0fc81a84 100644
--- a/toys/posix/ps.c
+++ b/toys/posix/ps.c
@@ -51,7 +51,7 @@ USE_PS(NEWTOY(ps, "k(sort)*P(ppid)*aAdeflMno*O*p(pid)*s*t*Tu*U*g*G*wZ[!ol][+Ae][
 // the default values are different but the flags are in the same order.
 USE_TOP(NEWTOY(top, ">0O*h" "Hk*o*p*u*s#<1d%<100=3000m#n#<1bq[!oO]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_IOTOP(NEWTOY(iotop, ">0AaKO" "Hk*o*p*u*s#<1=7d%<100=3000m#n#<1bq", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_STAYROOT))
-USE_PGREP(NEWTOY(pgrep, "?cld:u*U*t*s*P*g*G*fnovxL:[-no]", TOYFLAG_USR|TOYFLAG_BIN))
+USE_PGREP(NEWTOY(pgrep, "acld:u*U*t*s*P*g*G*fnovxL:[-no]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_PKILL(NEWTOY(pkill,    "?Vu*U*t*s*P*g*G*fnovxl:[-no]", TOYFLAG_USR|TOYFLAG_BIN))
 
 config PS
@@ -142,11 +142,12 @@ config PGREP
   bool "pgrep"
   default y
   help
-    usage: pgrep [-clfnovx] [-d DELIM] [-L SIGNAL] [PATTERN] [-G GID,] [-g PGRP,] [-P PPID,] [-s SID,] [-t TERM,] [-U UID,] [-u EUID,]
+    usage: pgrep [-aclfnovx] [-d DELIM] [-L SIGNAL] [PATTERN] [-G GID,] [-g PGRP,] [-P PPID,] [-s SID,] [-t TERM,] [-U UID,] [-u EUID,]
 
     Search for process(es). PATTERN is an extended regular expression checked
     against command names.
 
+    -a	Show the full command line
     -c	Show only count of matches
     -d	Use DELIM instead of newline
     -L	Send SIGNAL instead of printing name
@@ -864,14 +865,9 @@ static int get_ps(struct dirtree *new)
       while ((line = xgetline(fp))) {
         if ((s = strstr(line, ":cpuset:/"))) {
           s += strlen(":cpuset:/");
-          if (!*s || !strcmp(s, "foreground")) strcpy(tb->pcy, "fg");
-          else if (!strcmp(s, "system-background")) strcpy(tb->pcy, "  ");
-          else if (!strcmp(s, "background")) strcpy(tb->pcy, "bg");
-          else if (!strcmp(s, "top-app")) strcpy(tb->pcy, "ta");
-          else if (!strcmp(s, "restricted")) strcpy(tb->pcy, "rs");
-          else if (!strcmp(s, "foreground_window")) strcpy(tb->pcy, "wi");
-          else if (!strcmp(s, "camera-daemon")) strcpy(tb->pcy, "cd");
-          else strcpy(tb->pcy, "?");
+          sprintf(tb->pcy, "%.2s","? fgfg  bgtarswicd"+2*anystr(s, (char *[]){
+            "", "foreground", "system-background", "background", "top-app",
+            "restricted", "foreground_window", "camera-daemon", 0}));
         }
         free(line);
       }
@@ -1907,7 +1903,7 @@ static void do_pgk(struct procpid *tb)
   }
   if (!FLAG(c) && (!TT.pgrep.signal || TT.tty)) {
     printf("%lld", *tb->slot);
-    if (FLAG(l)) printf(" %s", tb->str+tb->offset[4]*FLAG(f));
+    if (FLAG(a)|FLAG(l)) printf(" %s", tb->str+tb->offset[4]*FLAG(a));
     printf("%s", TT.pgrep.d ? TT.pgrep.d : "\n");
   }
 }
@@ -1976,7 +1972,7 @@ void pgrep_main(void)
       !(toys.optflags&(FLAG_G|FLAG_g|FLAG_P|FLAG_s|FLAG_t|FLAG_U|FLAG_u)))
     if (!toys.optc) help_exit("No PATTERN");
 
-  if (FLAG(f)) TT.bits |= _PS_CMDLINE;
+  if (FLAG(f)|FLAG(a)) TT.bits |= _PS_CMDLINE;
   for (arg = toys.optargs; *arg; arg++) {
     reg = xmalloc(sizeof(struct regex_list));
     xregcomp(&reg->reg, *arg, REG_EXTENDED);
diff --git a/toys/posix/tar.c b/toys/posix/tar.c
index 998e668d..06482c16 100644
--- a/toys/posix/tar.c
+++ b/toys/posix/tar.c
@@ -20,7 +20,7 @@
  * No --no-null because the args infrastructure isn't ready.
  * Until args.c learns about no- toggles, --no-thingy always wins over --thingy
 
-USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
+USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*Z(zstd)o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
 
 config TAR
   bool "tar"
@@ -36,7 +36,7 @@ config TAR
     J  xz compression        j  bzip2 compression     z  gzip compression
     o  Ignore owner          h  Follow symlinks       m  Ignore mtime
     O  Extract to stdout     X  exclude names in FILE T  include names in FILE
-    s  Sort dirs (--sort)
+    s  Sort dirs (--sort)    Z  zstd compression
 
     --exclude        FILENAME to exclude  --full-time         Show seconds with -tv
     --mode MODE      Adjust permissions   --owner NAME[:UID]  Set file ownership
@@ -403,10 +403,10 @@ static int add_to_tar(struct dirtree *node)
       if (len>999999 || (sz && len>sz)) len = -1, errno = E2BIG;
       if (buf || len<1) {
         if (len>0) {
-          strcpy(buf+start+sz, "\n");
-          write_prefix_block(buf, start+sz+2, 'x');
+          strcpy(buf+start+sz-1, "\n");
+          write_prefix_block(buf, start+sz, 'x');
         } else if (errno==ENODATA || errno==ENOTSUP) len = 0;
-        if (len) perror_msg("getfilecon %s", name);
+        if (len<0) perror_msg("getfilecon %s", name);
 
         free(buf);
         break;
@@ -415,7 +415,7 @@ static int add_to_tar(struct dirtree *node)
       // Allocate buffer. Length includes prefix: calculate twice (wrap 99->100)
       temp = snprintf(0, 0, "%d", sz = (start = 22)+len+1);
       start += temp + (temp != snprintf(0, 0, "%d", temp+sz));
-      buf = xmprintf("%u RHT.%s=%.*s", start+len+1, sec, sz = len, "");
+      buf = xmprintf("%u RHT.%s=%.*s", start+len, sec, sz = len, "");
     }
   }
 
@@ -1001,9 +1001,9 @@ static void do_XT(char **pline, long len)
   if (pline) trim2list(TT.X ? &TT.excl : &TT.incl, *pline);
 }
 
-static  char *get_archiver()
+static char *get_archiver()
 {
-  return TT.I ? : FLAG(z) ? "gzip" : FLAG(j) ? "bzip2" : "xz";
+  return TT.I ? : FLAG(z)?"gzip" : FLAG(j)?"bzip2" : FLAG(Z)?"zstd" : "xz";
 }
 
 void tar_main(void)
@@ -1094,12 +1094,13 @@ void tar_main(void)
     char *hdr = 0;
 
     // autodetect compression type when not specified
-    if (!(FLAG(j)||FLAG(z)||FLAG(I)||FLAG(J))) {
+    if (!(FLAG(j)||FLAG(z)||FLAG(I)||FLAG(J)||FLAG(Z))) {
       len = xread(TT.fd, hdr = toybuf+sizeof(toybuf)-512, 512);
       if (len!=512 || !is_tar_header(hdr)) {
         // detect gzip and bzip signatures
         if (SWAP_BE16(*(short *)hdr)==0x1f8b) toys.optflags |= FLAG_z;
         else if (!smemcmp(hdr, "BZh", 3)) toys.optflags |= FLAG_j;
+	else if (!smemcmp(hdr, "\x28\xb5\x2f\xfd", 4)) toys.optflags|=FLAG_Z;
         else if (peek_be(hdr, 7) == 0xfd377a585a0000ULL) toys.optflags |= FLAG_J;
         else error_exit("Not tar");
 
@@ -1108,10 +1109,10 @@ void tar_main(void)
       }
     }
 
-    if (FLAG(j)||FLAG(z)||FLAG(I)||FLAG(J)) {
+    if (FLAG(j)||FLAG(z)||FLAG(I)||FLAG(J)||FLAG(Z)) {
       int pipefd[2] = {hdr ? -1 : TT.fd, -1}, i, pid;
       struct string_list *zcat = FLAG(I) ? 0 : find_in_path(getenv("PATH"),
-        FLAG(z) ? "zcat" : FLAG(j) ? "bzcat" : "xzcat");
+        FLAG(z)?"zcat" : FLAG(j)?"bzcat" : FLAG(Z)?"zstdcat" : "xzcat");
 
       // Toybox provides more decompressors than compressors, so try them first
       TT.pid = xpopen_both(zcat ? (char *[]){zcat->str, 0} :
@@ -1174,17 +1175,19 @@ void tar_main(void)
     struct double_list *dl = TT.incl;
 
     // autodetect compression type based on -f name. (Use > to avoid.)
-    if (TT.f && !FLAG(j) && !FLAG(z) && !FLAG(I) && !FLAG(J)) {
+    if (TT.f && !(FLAG(j)||FLAG(z)||FLAG(I)||FLAG(J)||FLAG(Z))) {
       char *tbz[] = {".tbz", ".tbz2", ".tar.bz", ".tar.bz2"};
       if (strend(TT.f, ".tgz") || strend(TT.f, ".tar.gz"))
         toys.optflags |= FLAG_z;
-      if (strend(TT.f, ".txz") || strend(TT.f, ".tar.xz"))
+      else if (strend(TT.f, ".txz") || strend(TT.f, ".tar.xz"))
         toys.optflags |= FLAG_J;
+      else if (strend(TT.f, ".tzst") || strend(TT.f, ".tar.zst"))
+        toys.optflags |= FLAG_Z;
       else for (len = 0; len<ARRAY_LEN(tbz); len++)
         if (strend(TT.f, tbz[len])) toys.optflags |= FLAG_j;
     }
 
-    if (FLAG(j)||FLAG(z)||FLAG(I)||FLAG(J)) {
+    if (FLAG(j)||FLAG(z)||FLAG(I)||FLAG(J)||FLAG(Z)) {
       int pipefd[2] = {-1, TT.fd};
 
       TT.pid = xpopen_both((char *[]){get_archiver(), 0}, pipefd);
diff --git a/toys/posix/test.c b/toys/posix/test.c
index 8395b8d3..2fda1718 100644
--- a/toys/posix/test.c
+++ b/toys/posix/test.c
@@ -98,10 +98,12 @@ static int do_test(char **args, int *count)
       if (i==8) return a < b;
       if (i==10) return a<= b;
       if (i==12) return (st1.st_dev==st2.st_dev) && (st1.st_ino==st2.st_ino);
-      if (i==14) return (st1.st_atim.tv_sec < st2.st_atim.tv_sec) ||
-        (st1.st_atim.tv_nsec < st2.st_atim.tv_nsec);
-      if (i==16) return (st1.st_atim.tv_sec > st2.st_atim.tv_sec) ||
-        (st1.st_atim.tv_nsec > st2.st_atim.tv_nsec);
+      if (i==14) return (st1.st_mtim.tv_sec < st2.st_mtim.tv_sec) ||
+        (st1.st_mtim.tv_sec == st2.st_mtim.tv_sec &&
+        st1.st_mtim.tv_nsec < st2.st_mtim.tv_nsec);
+      if (i==16) return (st1.st_mtim.tv_sec > st2.st_mtim.tv_sec) ||
+        (st1.st_mtim.tv_sec == st2.st_mtim.tv_sec &&
+        st1.st_mtim.tv_nsec > st2.st_mtim.tv_nsec);
     }
   }
   s = *args;
diff --git a/www/header.html b/www/header.html
index ec0d2969..e91265e1 100644
--- a/www/header.html
+++ b/www/header.html
@@ -15,7 +15,6 @@
       - <a href="help.html">Help</a><br>
       - <a href="faq.html">FAQ</a></br>
       - <a href="news.html">News</a></br>
-      - <a href="https://www.youtube.com/channel/UC4VFy3wc1nzq5tUHhiti6fw">Youtube</a></br>
     </li>
 
     <li>Why is it?<br>
@@ -31,7 +30,7 @@
       </ul>
     </li>
     <li><a href="downloads">Source tarballs</a></li>
-    <li><a href="bin">Binaries</a></li>
+    <li><a href="/bin">Binaries</a></li>
     <li><a href="downloads/binaries/mkroot/latest">System Images</a></li>
     <li><a href="downloads/binaries/toolchains/latest">Compilers</a></li>
   </ul>
@@ -55,5 +54,5 @@
 </td>
 
 <td valign=top>
-<h2>Current release <a href=https://landley.net/toybox/news.html>0.8.11</a> (April 8, 2024)</a></h2>
+<h2>Current release <a href=https://landley.net/toybox/news.html>0.8.12</a> (January 18, 2025)</a></h2>
 <hr>
diff --git a/www/license.html b/www/license.html
index 55521e73..a7233132 100755
--- a/www/license.html
+++ b/www/license.html
@@ -51,7 +51,14 @@ by sticking the two licenses at
 <a href=http://git.busybox.net/busybox/tree/networking/ping.c?id=887a1ad57fe978cd320be358effbe66df8a068bf>opposite ends of the file</a> and hoping nobody
 noticed.</a>
 
-<p>Note: I asked <a href=https://www.oreilly.com/openbook/opensources/book/kirkmck.html>Kirk McKusick</a> for permission to call this a BSD license at
+<p>I asked <a href=https://www.oreilly.com/openbook/opensources/book/kirkmck.html>Kirk McKusick</a> for permission to call this a BSD license at
 a conference shortly before I started using the name,
 and <a href=0bsd-mckusick.txt>again in 2018</a>.</p>
+
+<p>In 2017 while walking 0BSD through the github choose-a-license approval
+process, I copied to my blog two very long posts in the thread
+(<a href=https://landley.net/notes-2017.html#26-03-2017>part one</a>,
+<a href=https://landley.net/notes-2017.html#27-03-2017>part two</a>)
+explaining why the license is like that and what it was trying to
+accomplish. It seems to have <a href=https://github.com/search?q=license%3A0bsd&type=Repositories>been convincing</a>.</p>
 <!--#include file="footer.html" -->
diff --git a/www/news.html b/www/news.html
index 8054c635..65f31e1d 100644
--- a/www/news.html
+++ b/www/news.html
@@ -37,6 +37,228 @@ bootable under QEMU (built using a <a href=https://github.com/landley/linux/tree
 <u>Build</u>:
 -->
 
+<a name="18-01-2025" /><a href="#18-01-2025"><hr><h2><b>Jan 18, 2025</b></h2></a>
+<blockquote>
+<p>The regular early morning yell of horror was the sound of Arthur Dent waking
+up and suddenly remembering where he was.</p>
+</p> - The Hitchhiker's Guide to the Galaxy</p>
+</blockquote>
+
+<p><a href=downloads/toybox-0.8.12.tar.gz>Toybox 0.8.12</a>
+(<a href=https://github.com/landley/toybox/releases/tag/0.8.12>git commit</a>)
+is out, with prebuilt <a href=/bin/toybox/0.8.12>static binaries</a> and
+<a href=/bin/mkroot/0.8.12>mkroot images</a>
+bootable under QEMU 9.2.0 (built using a <a href=/bin/mkroot/0.8.12/linux-patches/>lightly patched</a> linux-6.12).</p>
+
+<p>Posix-2024 (SUSv5, issue 8) finally came out, and a few things
+have been tweaked, but as with Posix-2008 (SUSv4, issue 7, released
+16 years ago) it was mostly codifying what the Linux man pages
+already said.</p>
+
+<p>Toybox is now only the fifth most starred repository of the
+<a href=https://github.com/search?q=license%3A0bsd&type=Repositories&ref=advsearch>~60k 0BSD licensed projects on github</a>, which means
+<a href=https://spdx.org/licenses/0BSD.html>Zero Clause BSD</a> has
+outgrown its roots.</p>
+
+<p><u>Features</u>: added <b>netcat -o -O</b> (hex output, the first
+preserving original input groups and the latter continuous), and
+<b>tar</b> now handles another obsolete sparse format you get in old tarballs sometimes (with test).
+Elliott added NPROCESSORS_CONF and NPROCESSORS_ONLN to <b>getconf</b>,
+added -f FILE and --no-sync to <b>devmem</b>, and
+taught <b>tar</b> to call out to zstd.
+Oliver Webb added <b>test -ef -ot -nt</b>,
+Brian Norris added <b>dmesg -W</b>.
+Karthikeyan Ramasubramanian added <b>devmen --no-mmap</b>.
+Kana Steimle added <b>mount LABEL=</b>.
+Firas Khalil Khana made <b>lsusb</b> and <b>lspci</b> also check
+/usr/share/hwdata (since the Linux Foundation killed the Linux Standard
+Base system packagers can't quite agree where stuff should live).
+</p>
+
+<p><u>Bugfixes</u>:
+<b>grep -r</b> now opens files with O_NOBLOCK|O_NOCTTY to avoid getting hung
+up on FIFOs or attaching the console to dev/tty nodes,
+<b>patch -F0</b> disables fuzz support,
+<b>find -size</b> implies -type f,
+<b>host</b> detects truncated replies and doesn't output the length byte at
+the start of TXT replies,
+more complicated relative file permission parsing like <b>chmod g+rX-ws</b>
+is now handled properly,
+<b>tar</b> honors umask unless -p supplied (with tests),
+<b>test</b> -nt and -ot now only check nanoseconds when the seconds match,
+and a weird corner case in <b>ps</b> was because the <b>make.sh</b> plumbing
+wasn't switching FLAG_x to "long long" quite fast enough (when 1&lt;&lt;31
+is negative, using it in nontrivial bitmask checks can go strange).</p>
+
+<p>Elliott fixed a crash when <b>file</b> tried to parse corrupted ELF files,
+fixed <b>cp -i -v</b> verbose notifications (showing source when they should
+show destination, etc), and fixed
+a sendfile_len() bounds check. Ray Gardner found a unicode bug in lib.c's
+strlower() (which is now checked for in find.test).
+Yi-Yo Chiang fixed </b>netcat -f</b> and two bugs in <b>microcom</b>'s
+"paste" command.
+Xiuhong Wang fixed <b>ionice</b>'s output when checking the IO priority of a
+process you don't have permission to access.
+Dima Buzdyk taught <b>lsusb</b> to handle multiple PCIe controllers, including printing
+the controller domain id when there's more than one.
+Peter Collingbourne noticed that <b>ps</b>/<b>top</b> etc were setting the stdout buffer
+twice (which glibc doesn't support).
+Kana Steimle fixed <b>blkid</b> to match util-linux behavior more closely.</p>
+
+<p><u>Library</u>:
+Added <b>cfspeed2bps()</b> and <b>bsp2cfspeed()</b> functions (converting bits per second
+values to/from the cfsetspeed() argument bitmask), and make <b>xsetspeed()</b>
+use them. Moved <b>anystart()</b> and <b>anystr()</b> to lib.c.</p>
+
+<p><u>Mkroot</u>:
+New <b>riscv32</b> and <b>riscv64</b> targets, and <b>or1k</b> switched to the
+-M virt board emulation so it can exit now. The <b>armv5l</b> -M versatilepb
+board no longer micromanages the network card selection (which was working
+around a bug from 2007 long since fixed upstream).
+All <a href=https://landley.net/bin/mkroot/0.8.12>shipped targets</a> fully
+pass <b>mkroot/testroot.sh</b> except <b>or1k</b>
+(no default -hda bus <a href=https://lists.gnu.org/archive/html/qemu-devel/2025-01/msg00996.html>in qemu</a>'s
+board emulation), <b>microblaze</b> (no -hda
+available even with -drive, and the board emulation doesn't know how to exit
+without being killed), and <b>sh4eb</b> (an endianess disagreement between
+the ethernet driver and device emulation, little endian works fine with the
+same config).</p>
+
+<p><b>VMLINUX=</b> no longer needs a path to a zimage file, it looks under
+arch/$KARCH/boot when it's not at the top level. <b>QEMU_M=</b>
+is now a short way to say "qemu-system-$CROSS -M $QEMU_M".
+In <b>mkroot/packages</b>, updated the <b>dropbear</b> and <b>zlib</b>
+versions, and added an initial script to convert the <b>Linux From Scratch</b>
+12.1 sources into a squashfs
+(just a start, several of the shipped patches are in the obsolete diff -c
+"copied context" format because gnu, and I haven't taught patch to apply
+the old format yet. Maye a new LFS release will stop doing that?)
+<b>setupfor</b> now handles tarballs that don't extract to a directory with
+the same name.
+Fixed mkroot running in a container where /dev/tty was never associated
+(where writing to it produces an error). The airlock build is skippable
+so don't rely on it to set mkroot $VERSION.</p>
+
+<p><b>mkroot/record-commands</b> can now be run from an arbitrary directory,
+to more easily log command line usage in other projects' builds. Running
+it with no arguments now sets up a persistent wrapper and outputs
+an "export" line needed to update the $PATH and such to use it.
+(Running a command under it the way chroot or sh -c work still sets up
+the wrapper, runs the command, then tears down the wrapper again leaving
+the log.) Also, make it work on a busybox-based host (where "find -type"
+didn't understand commas).</p>
+
+<p><u>Pending</u>:
+New <b>awk.c</b> from Ray Gadner, which is 4500 lines long and counting
+(46 commits so far).
+Eric Roshan-Eisner fixed several issues in <b>vi</b> and its tests.
+Elliott fixed /etc/issue in <b>getty</b>.
+Daniel Rosenberg added <b>diff --no-dereference</b> and fixed comparisons
+between symlinks and fifos (with test).
+Kana Steimle fixed several things in <b>crond</b>.</p>
+
+<p>Use DRAIN instead of FLUSH in <b>stty</b>,
+Consistently indent the help text blocks (in syslogd.c, dhcp6, diff.c...),
+and the partial mke2fs.c was removed because gcc 14 breaks trying to build it
+(due to a design change in gcc, which used to be able to compile it but
+can't anymore, if I get around to finishing it I can check in one that
+actually performs its intended function but bug reports about code that
+doesn't work = remove it).</p>
+
+<p>More <b>toysh</b> work, most notably a
+<a href=https://github.com/landley/toybox/commit/7a2f81c82d1c>design change</a>
+that allows "trap" to asynchronlysly call functions from an interrupt handler
+(by removing the recursive do_source() function, moving the read/parse/run
+loop to sh_main(), and giving each sh_fcall stack entry a FILE *source
+it can read data from when the parsed sh_pipeline is empty, and then pop
+the sh_fcall on EOF and continue in the calling context.)
+The tests that are currently expected to fail are now
+annotated with $BROKEN (use "BROKEN= make test_sh" to try them), and
+TEST_HOST now passes on bash 5.2. Implement <b>return</b>, move <b>break</b>
+and <b>continue</b> to normal builtin commands (instead of special case
+inline processing in run_lines()), make the xexit() longjmp() back to the shell
+from builtins nest multiple levels deep if necessary (in case builtins call
+builtins, which is less likely under the new design), bump script filehandle
+to high fd and CLOEXEC it (instead of leaking into children).
+Another one line fix had
+<a href=https://github.com/landley/toybox/commit/0b2d5c2bb3f1>several paragraphs</a>
+of explanation, but boils down to "kernels with static initramfs have no
+stdin/stdout/stderr so toysh needs to cope when redirect opens one
+of those as a temporary filehandle". Fixed backslash parsing in $'' so \'
+doesn't end the quoting context.</p>
+
+<p><u>Cleanup</u>:
+Although <b>klogd</b> is cleaned up most of the way to being promotable,
+since it just passes stuff along to syslogd (which isn't) it's not much
+use on its own. Switched most remaining toys.optflags&amp;FLAG_x checks to
+<b>FLAG(x)</b>. Minor cleanup on <b>cp -r</b>.
+Elliott added input buffering to <b>xxd</b>, made find.c use S_ISREG() instead
+of inlining it. Brian Norris added line buffering to dmesg stdout.
+<b>klogd</b> is cleaned up most of the way to being promotable, but
+since it just passes stuff along to syslogd (which isn't) it's not much
+use on its own.</p>
+
+<p><u>Portability</u>:
+Fixed <b>hwclock</b> when settimeofday() syscall isn't available (which
+musl and glibc broke in
+<a href=https://github.com/landley/toybox/commit/da1474b1589a>different ways</a>),
+endianness checking now uses the compiler's built-in <b>__BYTE_ORDER__</b> macro
+instead of needing to #include headers. The nommu-friendly <b>xvdaemon()</b>
+will now chdir("/") so background processes don't pin mount points, and
+find.test now skips a test that triggered a macos bug.
+Elliott dropped ps.c's dependency on android libprocessgroup (it now
+reads /proc/$PID/cgroup directly). Vidar Karlsen had some freebsd updates.
+Kana Steimle worked around closedir(NULL) segfaulting on musl (which doesn't
+consider that a NOP).</p>
+
+<u>Documentation</u>:
+<b>sysctl</b> now accepts -A as an alias for -a but
+<a href=https://github.com/landley/toybox/commit/41e7186b012e>doesn't try to explain it</a>.
+More FAQ entries. and added some links to the end of <a href=license.html>license.html</a>.
+Old entries in this news page no longer drive vi's html syntax highlighting nuts.
+Elliott clarified the relationship between <b>ls -s</b> and --block-size</b>.
+Ivan Mirić fixed some typos in mkroot's README.</p>
+
+<p><u>Plumbing</u>:
+Added <b>TOYFLAG_NOBUF</b>, used by microcom to disable stdio buffering.
+The "lie to autoconf" help pluming moved into main.c as <b>TOYFLAG_AUTOCONF</b>
+because <b>grep</b> needs it too now.</p>
+
+<p><u>Test suite</u>:
+lots of tests updated to pass with TEST_HOST on Devuan Daedalus (I.E.
+Debian Bookworm). Various .1 second timeouts were expanded to give loaded
+servers time to schedule processes. (An unloaded raspberry pi should have no
+trouble, and a swap-thrashing system may not finish even with a 5 second wait
+to flush asynchronous activity, but it's at least a better guess.)
+For some reason, ASAN on Debian's current gcc/glibc turns glibc's <b>crypt()</b>
+function into a null pointer dereference. This seems to be a host toolchain bug,
+and there's work underway to replace the host crypt() with a lib/lib.c
+implementation using the builtin hashes in a future release, but for now
+you have to switch off "mkpasswd" in menuconfig to pass "make tests" on
+Debian. It worked fine on the old debian version, works fine built under
+musl-libc, works fine without ASAN enabled, is not failing IN
+crypt (it's never reaching it, the dynamic linker is turning the call into
+a jump to NULL). The shipped binaries are built against musl where crypt()
+(and thus mkpasswd) still works.</p>
+
+<p><u>Build</u>:
+Setting $TOOLCHAIN for <b>scripts/install.sh</b> (and thus
+<b>make airlock_install</b>) now symlinks the listed additional commands from
+the host $PATH into the new airlock directory.
+Fixed ASAN to mostly work with newer gcc/glibc (from Debian 12) except for
+the crypt() thing. Most files like generated/tags.h are now generated with sed and bash instead
+of building a native C program to emit them.
+Added --start-group and --end-group around the "extra" libraries when static
+linking (because probing them in parallel doesn't preserve the magic order).
+Sadly -f does not reliably shut up gnu/chmod, despite its longopt aliases
+being "--silent" and "--quiet" (the <strike>aristocrats</strike> FSF!)
+so redirect the noise to /dev/null.
+Added "ar" to the airlock install's PENDING list because the dropbear build
+grew a dependency on it. (You'd think that would use the cross compiler's
+prefixed-ar, but no.)
+Squelched more spurious clang warnings
+<a href=https://github.com/landley/toybox/commit/b9cb58b797b7>about nothing</a>.</p>
+
 <a name="08-04-2024" /><a href="#08-04-2024"><hr><h2><b>April 8, 2024</b></h2></a>
 <blockquote>
 <p>Another thing that got forgotten was the fact that against all probability a
@@ -451,7 +673,7 @@ entries, and merged most KERNEL_CONFIG lines into KCONF.
 NAME=\"this\ that\" to work right.) Added the legacy NLS
 dependencies the VFAT driver needs (even though we selected UTF8) to the
 base config. The init script now tests if stdin is open via
-"2>/dev/null <0 || blah" so only does the exec redirect for /dev/console
+"2&gt;/dev/null &lt;0 || blah" so only does the exec redirect for /dev/console
 when necessary.
 Fixed the .config checker to replace the toybox config when CONFIG_SH=y
 isn't set, so "make defconfig; mkroot/mkroot.sh" should work now.
@@ -909,7 +1131,7 @@ file metadata comparisons. (If you're wondering why something so simple should
 have a function encapsulating the logic, this release also has at least 3
 different bugfix commits for thinkos from switching all the commands over
 to use them instead of doing the test ourselves. All missing/extra ! or
-&& vs || level stuff.)</p>
+&amp;&amp; vs || level stuff.)</p>
 
 <p>The <b>exit_signal()</b> handler now blocks signals so <b>sigatexit()</b> won't
 re-enter the list when it receives two different killer signals. (Since
@@ -1056,9 +1278,6 @@ talk to).</p>
 <p>One command was removed: <b>catv</b> didn't really serve a purpose
 (everybody just uses <b>cat -v</b>).</p>
 
-
-
-
 <p><u>Features</u>:
 <b>top</b> can now move the list with the LEFT/RIGHT cursor keys (changing the
 sort field is now SHIFT LEFT/RIGHT). Added <b>find -samefile</b>,
@@ -1142,7 +1361,7 @@ Minor cleanups to ping, fsync, ionice, pmap, truncate, timeout, tty,
 factor, mount.
 Went through and replaced \033 with \e in strings (since clang supports
 it and \033 is just awkward). Added LL to constant 0 in the FLAG macros
-to prevent gcc from warning that 0<<32 might produce 0.
+to prevent gcc from warning that 0&lt;&lt;32 might produce 0.
 Moved llvm's -Wno-string-plus-int into configure instead of probing
 for it, since gcc no longer dies when asked to suppress an unknown warning.</p>
 
@@ -1674,7 +1893,7 @@ with toysh making it all the way through toyroot's init script.
 
 <p><u>Toyroot</u>: <b>make root</b> now does what it says on the tin, it
 builds a bootable toybox-based Linux system using two source
-packages (toybox and linux). The trivial version is "make root && sudo chroot
+packages (toybox and linux). The trivial version is "make root &amp;&amp; sudo chroot
 root/host/fs /init". Here's
 a <a href=http://lists.landley.net/pipermail/toybox-landley.net/2020-April/011667.html>post with instructions</a> if you want to know how to build the
 cross compilers for testing the various architectures. The self-contained
@@ -2407,7 +2626,7 @@ needs that for the s390x target).</p>
 <p><u>Coding style</u>:
 Rob converted the rest of the option GLOBALS() to the new single letter
 coding style, and the new FLAG(x) macro is a slightly tidier way to say
-"toys.optflags&FLAG_x".
+"toys.optflags&amp;FLAG_x".
 Removed CFG_SORT_BIG (the sort command always
 has the full functionality now. The general future direction or toybox
 is to either have a command or not have it; multiple versions of the
@@ -2623,7 +2842,7 @@ uppercase characters.
 Elliott fixed several things in <b>top</b> (removed spurious '\r' characters from -b
 output, removed interactive flicker, made running processes bold), and
 pushed Rob to make <b>file</b> work better recognizing things on stdin
-("cat /bin/ls | file -" still won't work but "file - < /bin/ls" should).
+("cat /bin/ls | file -" still won't work but "file - &lt; /bin/ls" should).
 Rob fixed a bug in <b>netstat</b> on 64 bit big endian systems,
 and fixed <b>cut</b> -DF
 (a posix compliance fix broke its ability to act as a decent awk replacment
@@ -2637,7 +2856,7 @@ to two columns.</p>
 
 <p><u>Library</u>:
 FLAGS_NODASH is now set in toys.optargs when an optstring starting
-with & has no dash in its first argument. (This lets "ps -ax" and "ps ax"
+with &amp; has no dash in its first argument. (This lets "ps -ax" and "ps ax"
 behave differently.) Factored out xtestfile() into lib/.
 The comma-separated-list parsing infrastructure moved to lib/commas.c.
 Added mkpath() for the common case of mkpathat() and #defined MKPATHAT_*
@@ -2875,7 +3094,7 @@ simple range checks for fields (to avoid false positives from things like
 timezones and daylight savings time), removed %s from date's help (we
 didn't implement it, we have @seconds[.nanoseconds] instead), fixed
 zcat's buffer flush logic (which was always failing on files larger
-than 32k), and factor now detects requests for numbers >64 bits and fails
+than 32k), and factor now detects requests for numbers &gt;64 bits and fails
 loudly instead of producing incorrect answers.
 Elliott fixed touch -a/-m (they were backwards), and allowed ':' in
 setprop's property names. Grep now exits with 2 for errors (so -q can
@@ -3398,7 +3617,7 @@ to explain what they're for.</p>
 <li><p>Expanded toys.optargs to 64 bits so a command can have more than 32 options.</p></li>
 <li><p>Added NOEXIT() wrapper to turn xwrap() functions into warning versions
 using the existing longjump(toys.rebound) infrastructure.</p></li>
-<li><p>Renamed dirtree->data to dirfd and stopped storing symlink length
+<li><p>Renamed dirtree-&gt;data to dirfd and stopped storing symlink length
 into it (this fixed a bug where following symlinks to directories
 didn't give a valid directory filehandle, noticeable with ls -Z).</p></li>
 <li><p>New TAGGED_ARRAY() infrastructure generates index and bitmask macros
@@ -4170,7 +4389,7 @@ got enough OS bits working to run a full configureand make.</p>
 
 <p>Library code: xcreate/xopen now O_CLOEXEC by default to avoid leaking
 filehandles to child processes. DIRTREE_COMEAGAIN's second callback is now
-done with the directory filehandle still open (new dir->again variable added
+done with the directory filehandle still open (new dir-&gt;again variable added
 to distinguish first from second callback, and requesting DIRTREE_RECURSE now
 requires passing in the specific macro value, not just a true/false).
 Use daemon() out of libc instead of hand-rolled daemonize() in various
@@ -4613,7 +4832,7 @@ didn't match anybody else's behavior and thus made the test suite hiccup
 between TEST_HOST and testing toybox. (If you go "TEST_HOST=1 scripts/test.sh
 command" it sanity checks the tests against the host implementation.)</p>
 
-<p>Last release, "mkdir sub/sub && chmod 007 sub/sub && rm -rf sub" didn't
+<p>Last release, "mkdir sub/sub &amp;&amp; chmod 007 sub/sub &amp;&amp; rm -rf sub" didn't
 delete sub and didn't exit with an error either. Neither was correct, rm
 should now be fixed.</p>
 
@@ -4988,7 +5207,7 @@ you need a quarter-second sleep, it can do that now), and fixed a build bug
 on slackware.</p>
 
 <p>Daniel Walter contributed a string to mode_t parser (in use by chmod and
-mkdir -m).  Ilya Kuzmich contributed comm. Elie De Brauwer added mountpoint,
+mkdir -m). Ilya Kuzmich contributed comm. Elie De Brauwer added mountpoint,
 vmstat, logname, login, and mktemp. Kevin Chase did some portability cleanups.
 Pere Orga fixed some documentation.</p>
 
diff --git a/www/roadmap.html b/www/roadmap.html
index 78b1729b..32efac86 100644
--- a/www/roadmap.html
+++ b/www/roadmap.html
@@ -6,9 +6,13 @@
 
 <ul>
 <li><a href=#goals>Introduction</a></li>
-<li><a href=#susv4>POSIX-2008/SUSv4</a></li>
+<li>Main Standards
+<ul>
+<li><a href=#susv5>POSIX-2024/SUSv5</a></li>
 <li><a href=#sigh>Linux "Standard" Base</a></li>
-<li><a href=#rfc>IETF RFCs and Man Pages</a></li>
+<li><a href=#man>Man Pages</a></li>
+<li><a href=#rfc>IETF RFCs</a></li>
+</ul></li>
 <li><a href=#dev_env>Development Environment</a></li>
 <li><a href=#android>Android Toolbox</a></li>
 <li><a href=#aosp>Building AOSP</a></li>
@@ -23,7 +27,7 @@
 <li><a href=#todo>TODO list</a></li>
 </ul>
 
-<a name="goals" />
+<a name="goals" /><!--Jan 2025-->
 <h2>Introduction (Goals and use cases)</h2>
 
 <p>We have several potential use cases for a new set of command line
@@ -32,72 +36,82 @@ for Toybox's 1.0 release. Most of these have their own section in the
 <a href=status.html>status page</a>, showing current progress towards
 commplation.</p>
 
-<p>The most interesting publicly available standards are A) POSIX-2008 (also
-known as SUSv4), B) the Linux Standard Base version 4.1, and C) the official
-<a href=https://www.kernel.org/doc/man-pages/>Linux man pages</a>.
-But each of those include commands we've decided not implement, exclude
-commands or features we have, and don't always entirely match reality.</p>
+<p>The most interesting publicly available command line standards are:</p>
+<ol>
+<li>POSIX-2024 (also known as SUSv5)</li>
+<li>the Linux Standard Base version 4.1 (frozen, becoming obsolete)</li>
+<li>the official <a href=https://www.kernel.org/doc/man-pages/>Linux man pages</a></li>
+<li>IETF Request For Comments>
+</ol>
+But each of those include commands we've decided not implement and/or exclude
+commands or features we have, nor do they always entirely match reality.</p>
 
 <p>The most thorough real world test (other than a large interactive
-userbase) is using toybox as the command line in a build system such as
-<a href=https://landley.net/aboriginal/about.html>Aboriginal
-Linux</a>, having it rebuild itself from source code, and using the result
+userbase) is using toybox as the command line in a
+<a href=https://landley.net/aboriginal/about.html>build system</a> container
+where it can rebuild itself from source code, then using the result
 to <a href=https://github.com/landley/control-images>build Linux From Scratch</a>.
 The current "minimal native development system" goal is to use
 <a href=faq.html#mkroot>mkroot</a>
 plus <a href=faq.html#cross>musl-cross-make</a> to hermetically build
 <a href=https://source.android.com>AOSP</a>.</p>
 
-<p>We've also checked what commands were provided by similar projects
-(klibc, sash, sbase, embutils, nash, beastiebox...), looked at various
+<p>Over the years we've also checked what commands were provided by similar
+projects (klibc, sash, sbase, embutils, nash, beastiebox...), looked at various
 vendor configurations of busybox, and collected end user requests.</p>
 
 <p>Finally, we'd like to provide a good replacement for the Bash shell,
 which was the first program Linux ever ran (leading up to the 0.0.1 release
 in 1991) and remains the standard shell of Linux (no matter what Ubuntu says).
 This doesn't necessarily mean including every last Bash 5.x feature, but
-does involve {various,features} &lt(beyond) posix.</p>
+does involve {various,features} &lt;(beyond) posix.</p>
 
-<p>See the <a href=status.html>status page</a> for the categorized command list
-and progress towards implementing it.</p>
+<p>See the <a href=status.html>status page</a> for the current categorized
+command list and progress towards implementing it.</p>
 
 <hr />
 <a name="standards">
 <h2>Use case: standards compliance.</h2>
 
-<h3><a name=susv4 /><a href="#susv4">POSIX-2008/SUSv4</a></h3>
+<a name=susv4 />
+<h3><a name=susv5 /><a href="#susv5">POSIX-2024/SUSv5</a></h3><!--REDO for SUSv5-->
 <p>The best standards describe reality rather than attempting to impose a
 new one. I.E. "A good standard should document, not legislate."
 Standards which document existing reality tend to be approved by
-more than one standards body, such as ANSI and ISO both approving <a href=https://landley.net/c99-draft.html>C99</a>. That's why IEEE 1003.1-2008,
-the Single Unix Specification version 4, and the Open Group Base Specification
-edition 7 are all the same standard from three sources, which most people just
+more than one standards body, such as ANSI and ISO both approving <a href=https://landley.net/c99-draft.html>C99</a>. That's why IEEE 1003.1-2024,
+the Single Unix Specification version 5, and the Open Group Base Specification
+Issue 8 are all the same standard from three sources, which most people just
 call "posix" (short for "portable operating system that works like unix").
-It's available <a href=https://pubs.opengroup.org/onlinepubs/9699919799>online in full</a>, and may be downloaded as a tarball.
-Previous versions (<a href=https://pubs.opengroup.org/onlinepubs/009695399/>SUSv3</a> and
+It's available <a href=https://pubs.opengroup.org/onlinepubs/9799919799/>online
+in full</a>
+https://pubs.opengroup.org/onlinepubs/9699919799>online in full</a>, and may
+be <a href=https://pubs.opengroup.org/onlinepubs/9799919799/download>downloaded</a>
+as a tarball. Previous versions
+(<a href=https://pubs.opengroup.org/onlinepubs/9699919799.2008edition/>SUSv4</a>,
+<a href=https://pubs.opengroup.org/onlinepubs/009695399/>SUSv3</a> and
 <a href=https://pubs.opengroup.org/onlinepubs/7990989775/>SUSv2</a>)
 are also available.</p>
 
 <p>The original Posix was a collection of different standards (POSIX.1
 from 1988, POSIX.1b from 1993, and POSIX.1c from 1995). The unified
-SUSv2 came out in 1997 and SUSv3 came out in 2001.
-<a href=https://pubs.opengroup.org/onlinepubs/9699919799.2008edition/>Posix
-2008</a> was then reissued in 2013 and 2018, the first was minor wordsmithing
-with no behavioral changes, the second was to renew a ten year timeout
-to still be considered a "current standard" by some government regulations,
-but isn't officially a new standard. It's still posix-2008/SUSv4/Issue 7.
-The endless committee process to produce
-"Issue 8" has been ongoing for over 15 years now, with conference
-calls on mondays and thursdays, mostly to discuss recent bug tracker
-entries then publish the minutes of the meeting on the mailing list.
-Prominent committee members have died during this time.</p>
+SUSv2 came out in 1997 and SUSv3 came out in 2001. SUSv4 came out in 2008
+and remained the current version for 16 years (although it was
+re-released in 2013, 2016, and 2018 with basically typo fixes, but was
+still SUSv4 and Issue 7), until the current SUSv5 (Issue 8) finally came out
+in 2024.</p>
 
 <h3>Why not just use posix for everything?</h3>
 
 <p>Unfortunately, Posix describes an incomplete subset of reality, because
-it was designed to. It started with proprietary unix vendors collaborating to
-describe the functionality their fragmented APIs could agree on, which was then
-incorporated into <a href=https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub151-2-1993.pdf>US federal procurement standards</a>
+it was designed to. Those first few pre-SUSv2 Posix standards (which remain
+unavailable on the Open Group's wesite) were produced during a period known as
+"<a href=https://en.wikipedia.org/wiki/Unix_wars>the unix wars</a>" when
+AT&amp;T's prioprietary control over the original UNIX(tm) intellectual property
+sucked the old UNIX(tm) ecosystem dry until Linux and FreeBSD swept away
+the irrelevant debris. That's why the standards process started with proprietary
+unix vendors collaborating to describe what little functionality their
+fragmented APIs could agree on, which was then incorporated into
+<a href=https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub151-2-1993.pdf>US federal procurement standards</a>
 as a <a href=https://www.youtube.com/watch?v=nwrTTXOg-KI>compliance requirement</a>
 for things like navy contracts, giving large corporations
 like IBM and Microsoft millions of dollars of incentive
@@ -105,9 +119,10 @@ to punch holes in the standard big enough to drive
 <a href=https://en.wikipedia.org/wiki/Microsoft_POSIX_subsystem>Windows NT</a> and
 <a href=http://www.naspa.net/magazine/1996/May/T9605006.PDF>OS/360</a> through.
 When open source projects like Linux started developing on the internet
-(enabled by the 1993 relaxation of the National Science Foundation's
+(enabled by the 1993 <a href=https://en.wikipedia.org/wiki/Eternal_September>relaxation</a> of the National Science Foundation's
 "Acceptable Use Policy" allowing everyone to connect to the internet,
-previously restricted to approved government/military/university organizations),
+previously restricted to approved government/military/university organizations
+until the budget funding its backbone links passed from DARPA to NSF),
 Posix <a href=http://www.opengroup.org/testing/fips/policy_info.html>ignored
 the upstarts</a> and Linux eventually
 <a href=https://www.linuxjournal.com/article/3417>returned the favor</a>,
@@ -179,10 +194,10 @@ who xargs zcat
 </span>
 </b></blockquote>
 
-<h3><a name=sigh /><a href="#sigh">Linux Standard Base</a></h3>
+<h3><a name=sigh /><a href="#sigh">Linux Standard Base</a></h3><!--Jan 2025-->
 
 <p>One attempt to supplement POSIX towards an actual usable system was the
-Linux Standard Base. Unfortunately, the quality of this "standard" is
+Linux Standard Base. Unfortunately, the quality of this "standard" was
 fairly low, largely due to the Free Standards Group that maintained it
 being consumed by <a href=https://landley.net/notes-2010.html#18-07-2010>the Linux Foundation</a> in 2007.</p>
 
@@ -193,33 +208,32 @@ the Linux Standard Base's failure mode was different. They responded to
 pressure by including anything their members paid them enough to promote,
 such as allowing Red Hat to push
 RPM into the standard even though all sorts of distros (Debian, Slackware, Arch,
-Gentoo, Android, Alpine...) don't use it and never will. This means anything in the LSB is
-at best a suggestion: arbitrary portions of this standard are widely
+Gentoo, Android, Alpine...) don't use it and never will. This means anything in LSB was
+at best a suggestion: arbitrary portions of this standard were widely
 ignored.</p>
 
 <p>The <a href=https://mjg59.dreamwidth.org/39546.html>community perception</a>
-seems to be that the Linux Standard Base is
-the best standard money can buy: the Linux Foundation is supported by
-financial donations from large companies and the LSB
-<a href=https://www.softwarefreedom.org/blog/2016/apr/11/lf/>represents the interests
-of those donors</a> regardless of technical merit. (The Linux Foundation, which
-maintains the LSB, is NOT a 501c3. It's a 501c6, the
+became that the Linux Standard Base was the best standard money can buy: the
+Linux Foundation was supported by financial donations from large companies and
+LSB <a href=https://www.softwarefreedom.org/blog/2016/apr/11/lf/>represented
+the interests of those donors</a> regardless of technical merit. (The Linux
+Foundation, which maintained the LSB, is NOT a 501c3. It's a 501c6, the
 same kind of legal entity as the Tobacco Institute and
 <a href=https://lwn.net/Articles/706585/>Microsoft's</a>
 old "<a href=https://en.wikipedia.org/wiki/Don%27t_Copy_That_Floppy>Don't Copy That Floppy</a>" campaign.) Debian officially
 <a href=http://lwn.net/Articles/658809>washed its hands of LSB</a> by
 refusing to adopt release 5.0 in 2015, and no longer even pretends to support
-it (which affects Debian derivatives like Ubuntu and Knoppix). Toybox has
-stayed on 4.1 for similar reasons.</p>
+it (which affects Debian derivatives like Ubuntu and Knoppix).
+Toybox has stayed on 4.1 for similar reasons.</p>
 
-<p>That said, Posix by itself isn't enough, and this is the next most
+<p>That said, Posix by itself isn't enough, and this was the next most
 comprehensive standards effort for Linux so far, so we salvage what we can.
 A lot of historical effort went into producing the standard before the
 Linux Foundation took over.</p>
 
 <h3>Analysis</h3>
 
-<p>LSB 4.1 specifies a <a href=http://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/cmdbehav.html>list of command line
+<p>LSB 4.1 specified a <a href=http://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/cmdbehav.html>list of command line
 utilities</a>:</p>
 
 <blockquote><b>
@@ -243,7 +257,7 @@ interested in the set of LSB tools that aren't mentioned in posix.</p>
 
 <p>Of these, gettext and msgfmt are internationalization, install_initd and
 remove_initd weren't present even in Ubuntu 10.04, lpr is out of scope,
-lsb_release just reports information in /etc/os-release, and sendmail's
+lsb_release just reports information in /etc/os-release, and sendmail
 turned into a pile of cryptographic verification and DNS shenanigans due
 to spammers.</p>
 
@@ -258,10 +272,12 @@ su sync tar umount useradd userdel usermod zcat
 </span>
 </b></blockquote>
 
-<h3><a name=rfc /><a href="#rfc">IETF RFCs and Man Pages</a></h3>
+<h3><a name=rfc /><a href="#rfc">IETF RFCs and Man Pages</a></h3><!--Jan 2025-->
 
+<h3><a name=rfc /><a href="#rfc">IETF RFCs and Man Pages</a></h3><!--Jan 2025-->
 <p>They're very nice, but there's thousands of them. The signal to noise
-ratio here is terrible.</p>
+ratio here is terrible, and neither is a good indicator of whether a linux
+system should or should not include a given command in its basic command set.</p>
 
 <p>Discussion of standards wouldn't be complete without the Internet
 Engineering Task Force's "<a href=https://www.rfc-editor.org/in-notes/rfc-index.txt>Request For Comments</a>" collection and Michael Kerrisk's
@@ -271,27 +287,46 @@ low barriers to inclusion. They're not saying "you should support
 X", they're saying "if you do, here's how".
 Thus neither really helps us select which commands to include.</p>
 
-<p>The man pages website includes the commands in git, yum, perf, postgres,
-flatpack... Great for examining the features of a command you've
-already decided to include, useless for deciding _what_ to include.</p>
-
-<p>The RFCs are more about protocols than commands. The noise level is
-extremely high: there's thousands of RFCs, many describing a proposed idea
-that never took off, and less than 1% of the resulting documents are
-currently relevant to toybox. The documents are numbered based on the
-order they were received, with no real attempt at coherently indexing
-the result. As with man pages they can be <a href=https://www.ietf.org/rfc/rfc0610.txt>long and complicated</a> or
+<p>Unix's first production deployment in 1970 was a typesetting system for
+AT&amp;T's internal patent and trademark licensing office (providing the
+budget for Bell Labs' engineers to port their prototype system from a
+surplus PDP-7 fished out of an attic to a newly purchased PDP-11), and
+has retained a robust documentation tradition ever since, albeit still
+written in the old "troff" typesetting language designed to control 1970's
+daisy wheel printers, and in a terse style intended to save both memory
+and paper. Still: every command in a descendant of unix should have an
+entry in the unix instruction manual, with section 1 (ala "man 1 ls") listing
+commands available to normal users and section 8 ("man 8 mount") listing
+system administration commands for use by the root account. Run "man -k ."
+to see every manual page currently installed onthe system.</p>
+
+<p>The modern Linux man pages project has loosened up a bitwebsite includes commands from git, yum, perf, postgres,
+flatpack... It's useful for examining the features of a command you've
+already decided to include, but useless for deciding _what_ to include.</p>
+
+<p>The RFCs are mostly about protocols and file formats, not commands.
+The documents are numbered based on the order they were received, with
+no real attempt at coherently indexing the result.
+The noise level is also extremely high: there's thousands of RFCs, many
+describing a proposed idea that never took off, and most of the rest are
+extensions to or replacements for earlier RFCs. Less than 1% of the resulting
+documents are currently relevant to toybox. As with man pages they can be
+<a href=https://www.ietf.org/rfc/rfc0610.txt>long and complicated</a> or
 <a href=https://www.ietf.org/rfc/rfc1951.txt>terse and impenetrable</a>,
 have developed a certain amount of <a href=https://www.ietf.org/rfc/rfc8179.txt>bureaucracy</a> over the years, and often the easiest way to understand what
 they <a href=https://www.ietf.org/rfc/rfc4330.txt>document</a> is to find an <a href=https://www.ietf.org/rfc/rfc1769.txt>earlier version</a> to read first.
 (This is an example of the greybeard community problem, where all current
 documentation was written by people who don't remember NOT already knowing
-this stuff and the resources they originally learned from are long gone.)</p>
+this stuff and the resources they originally learned from are long gone,
+and <a href=https://tldp.org/HOWTO/Bootdisk-HOWTO/buildroot.html>excellent</a>
+<a href=https://landley.net/kdocs/mirror/lki-single.html>historical</a>
+<a href=https://linuxfromscratch.org/hints/downloads/files/OLD/bsd-init.txt>documents</a>
+have no obvious modern alternative.)</p>
 
 <p>That said, RFC documents can be useful (especially for networking protocols)
-and the four URL templates the recommended starting files
+and the four URL templates provided by the recommended starting files
 for new commands (hello.c and skeleton.c in the toys/example directory)
-provide point to example posix, lsb, man, and rfc pages online.</p>
+point to example posix, lsb, man, and rfc pages online.</p>
 
 <hr />
 <a name="dev_env">
@@ -367,6 +402,17 @@ significantly affect the rest of this analysis (although the "rebuild itself
 from source" test should now include building musl-cross-make under either
 mkroot or toybox's "make airlock" host environment).</p>
 
+<p>Toybox source includes
+a <b>scripts/mcm-buildall.sh</b> wrapper script around musl-cross-make, which
+builds cross and native versions of gcc+musl toolchains for a dozen
+different architectures, and a <b>mkroot/testroot.sh</b> that boots
+all the <b>mkroot/mkroot CROSS=allnonstop LINUX=~/linux</b> systems under
+qemu and performs basic automated smoketesting that they run, have a current
+clock, and their network and block device support works. The "make airlock"
+target is implemented by <b>scripts/install.sh</b> which sets the
+$PENDING and $TOOLCHAIN variables to lists of commands to symlink out of the
+host.</p>
+
 <p>Building Linux From Scratch is not the same as building the
 <a href=https://source.android.com>Android Open Source Project</a>,
 but after toybox 1.0 we plan to try
@@ -383,7 +429,7 @@ this goal.</p>
 <h2><a name=android /><a href="#android">Use case: Replacing Android Toolbox</a></h2>
 
 <p>Android has a policy against GPL in userspace, so even though BusyBox
-predates Android by many years, they couldn't use it. Instead they grabbed
+predates Android by many years, they didn't use it. Instead they grabbed
 an old version of ash (later replaced by
 <a href="https://www.mirbsd.org/mksh.htm">mksh</a>)
 and implemented their own command line utility set
@@ -467,15 +513,12 @@ getevent gzip modprobe newfs_msdos sh
 </span>
 </b></blockquote>
 
-<p>Update: <a href=https://android.googlesource.com/platform/system/core/+/master/system/core/Android.bp>
-external/toybox/Android.bp</a> has symlinks for the following toys out
-of "pending". (The toybox modprobe is also built for the device, but
-it isn't actually used and is only there for sanity checking against
-the libmodprobe-based implementation.) These should be a priority for
-cleanup:</p>
+<p>Update: Android's <a href=https://android.googlesource.com/platform/external/toybox/+/refs/heads/main/Android.bp>external/toybox/Android.bp</a>
+builds the following commands out of "pending", which
+should be a priority for cleanup:</p>
 
 <blockquote><b>
-diff expr getopt tr brctl getfattr lsof modprobe more stty traceroute vi
+diff expr tr brctl getfattr lsof modprobe more stty traceroute vi
 </b></blockquote>
 
 <p>Android wishlist:</p>
@@ -654,15 +697,16 @@ shutdown fdisk getty halt ifconfig init mkswap reboot route swapon swapoff
 </span>
 </b></blockquote>
 
-<hr /><a name=buildroot />
+<hr /><a name=buildroot /><!--Jan 2025-->
 <h2>buildroot:</h2>
 
 <p>If a toybox-based development environment is to support running
 buildroot under it, the <a href=https://buildroot.org/downloads/manual/manual.html#requirement-mandatory>mandatory packages</a>
 section of the buildroot manual lists:</p>
-
 <blockquote><p><b>
-which sed make bash patch gzip bzip2 tar cpio unzip rsync file bc wget
+<span id=buildroot_cmd>
+which sed make diff bash patch gzip bzip2 tar cpio unzip rsync file bc find wget
+</span>
 </b></p></blockquote>
 
 <p>(It also lists binutils gcc g++ perl python, and for debian it wants
@@ -674,7 +718,7 @@ breaks otherwise</a>.)</p>
 with a prefix of "".  If you try, and chop out the test for a blank prefix,
 it dies trying to run "/usr/bin/-gcc". In theory you can modify any open source
 project to do anything if you rewrite enough of it, but buildroot's developers
-explicitly do not support this usage model.</p>
+<b>explicitly</b> do not support this usage model.</p>
 
 <hr /><a name=klibc />
 <h2>klibc:</h2>
@@ -1258,6 +1302,7 @@ rsync
 linux32 hd strace
 gpiodetect gpiofind gpioget gpioinfo gpioset httpd uclampset
 nbd-server
+memeater
 </span>
 </b></blockquote>
 
```

