```diff
diff --git a/Android.bp b/Android.bp
index c93935f9..56ec317f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -508,7 +508,6 @@ cc_defaults {
             shared_libs: [
                 "libcrypto",
                 "liblog",
-                "libprocessgroup",
                 "libselinux",
                 "libz",
             ],
@@ -560,11 +559,8 @@ cc_binary {
         "libm",
         "libz",
         "libbase",
-        "libcgrouprc",
-        "libcgrouprc_format",
         "libcrypto_static",
         "liblog",
-        "libprocessgroup",
         "libselinux",
     ],
     dist: {
diff --git a/METADATA b/METADATA
index 72d58400..d610dd40 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/toybox
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "toybox"
 description: "Toybox: all-in-one Linux command line."
@@ -8,13 +8,13 @@ third_party {
   license_type: UNENCUMBERED
   last_upgrade_date {
     year: 2024
-    month: 6
-    day: 11
+    month: 9
+    day: 13
   }
   homepage: "https://landley.net/toybox/"
   identifier {
     type: "Git"
     value: "https://github.com/landley/toybox"
-    version: "2c3363f742eb7ec1caba5a5a12b688fb3f8dd18d"
+    version: "9cde5834249786ba5239774c787b5db3de1b6d97"
   }
 }
diff --git a/android/device/generated/config.h b/android/device/generated/config.h
index 7dca3830..b2d73a20 100644
--- a/android/device/generated/config.h
+++ b/android/device/generated/config.h
@@ -40,6 +40,8 @@
 #define USE_ARPING(...)
 #define CFG_ARP 0
 #define USE_ARP(...)
+#define CFG_AWK 0
+#define USE_AWK(...)
 #define CFG_ASCII 0
 #define USE_ASCII(...)
 #define CFG_BASE32 0
diff --git a/android/device/generated/flags.h b/android/device/generated/flags.h
index 1f56155f..9c056073 100644
--- a/android/device/generated/flags.h
+++ b/android/device/generated/flags.h
@@ -70,6 +70,19 @@
 #undef FOR_ascii
 #endif
 
+// awk   F:v*f*bc
+#undef OPTSTR_awk
+#define OPTSTR_awk "F:v*f*bc"
+#ifdef CLEANUP_awk
+#undef CLEANUP_awk
+#undef FOR_awk
+#undef FLAG_c
+#undef FLAG_b
+#undef FLAG_f
+#undef FLAG_v
+#undef FLAG_F
+#endif
+
 // base32   diw#<0=76[!dw]
 #undef OPTSTR_base32
 #define OPTSTR_base32 "diw#<0=76[!dw]"
@@ -628,12 +641,14 @@
 #undef FOR_demo_utf8towc
 #endif
 
-// devmem <1>3 <1>3
+// devmem <1(no-sync)f: <1(no-sync)f:
 #undef OPTSTR_devmem
-#define OPTSTR_devmem "<1>3"
+#define OPTSTR_devmem "<1(no-sync)f:"
 #ifdef CLEANUP_devmem
 #undef CLEANUP_devmem
 #undef FOR_devmem
+#undef FLAG_f
+#undef FLAG_no_sync
 #endif
 
 // df HPkhit*a[-HPh] HPkhit*a[-HPh]
@@ -718,9 +733,9 @@
 #undef FLAG_P
 #endif
 
-// diff <2>2(unchanged-line-format):;(old-line-format):;(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3 <2>2(unchanged-line-format):;(old-line-format):;(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3
+// diff <2>2(unchanged-line-format):;(old-line-format):;(no-dereference);(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3 <2>2(unchanged-line-format):;(old-line-format):;(no-dereference);(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3
 #undef OPTSTR_diff
-#define OPTSTR_diff "<2>2(unchanged-line-format):;(old-line-format):;(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3"
+#define OPTSTR_diff "<2>2(unchanged-line-format):;(old-line-format):;(no-dereference);(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3"
 #ifdef CLEANUP_diff
 #undef CLEANUP_diff
 #undef FOR_diff
@@ -744,6 +759,7 @@
 #undef FLAG_strip_trailing_cr
 #undef FLAG_color
 #undef FLAG_new_line_format
+#undef FLAG_no_dereference
 #undef FLAG_old_line_format
 #undef FLAG_unchanged_line_format
 #endif
@@ -756,9 +772,9 @@
 #undef FOR_dirname
 #endif
 
-// dmesg w(follow)CSTtrs#<1n#c[!Ttr][!Cc][!Sw] w(follow)CSTtrs#<1n#c[!Ttr][!Cc][!Sw]
+// dmesg w(follow)W(follow-new)CSTtrs#<1n#c[!Ttr][!Cc][!SWw] w(follow)W(follow-new)CSTtrs#<1n#c[!Ttr][!Cc][!SWw]
 #undef OPTSTR_dmesg
-#define OPTSTR_dmesg "w(follow)CSTtrs#<1n#c[!Ttr][!Cc][!Sw]"
+#define OPTSTR_dmesg "w(follow)W(follow-new)CSTtrs#<1n#c[!Ttr][!Cc][!SWw]"
 #ifdef CLEANUP_dmesg
 #undef CLEANUP_dmesg
 #undef FOR_dmesg
@@ -770,6 +786,7 @@
 #undef FLAG_T
 #undef FLAG_S
 #undef FLAG_C
+#undef FLAG_W
 #undef FLAG_w
 #endif
 
@@ -1941,9 +1958,9 @@
 #undef FLAG_l
 #endif
 
-// lspci emkn@x@i: emkn@x@i:
+// lspci eDmkn@x@i: eDmkn@x@i:
 #undef OPTSTR_lspci
-#define OPTSTR_lspci "emkn@x@i:"
+#define OPTSTR_lspci "eDmkn@x@i:"
 #ifdef CLEANUP_lspci
 #undef CLEANUP_lspci
 #undef FOR_lspci
@@ -1952,6 +1969,7 @@
 #undef FLAG_n
 #undef FLAG_k
 #undef FLAG_m
+#undef FLAG_D
 #undef FLAG_e
 #endif
 
@@ -3760,12 +3778,13 @@
 #undef FOR_vconfig
 #endif
 
-// vi >1s: >1s:
+// vi >1s:c: >1s:c:
 #undef OPTSTR_vi
-#define OPTSTR_vi ">1s:"
+#define OPTSTR_vi ">1s:c:"
 #ifdef CLEANUP_vi
 #undef CLEANUP_vi
 #undef FOR_vi
+#undef FLAG_c
 #undef FLAG_s
 #endif
 
@@ -3994,6 +4013,18 @@
 #endif
 #endif
 
+#ifdef FOR_awk
+#define CLEANUP_awk
+#ifndef TT
+#define TT this.awk
+#endif
+#define FLAG_c (FORCED_FLAG<<0)
+#define FLAG_b (FORCED_FLAG<<1)
+#define FLAG_f (FORCED_FLAG<<2)
+#define FLAG_v (FORCED_FLAG<<3)
+#define FLAG_F (FORCED_FLAG<<4)
+#endif
+
 #ifdef FOR_base32
 #define CLEANUP_base32
 #ifndef TT
@@ -4515,6 +4546,8 @@
 #ifndef TT
 #define TT this.devmem
 #endif
+#define FLAG_f (1LL<<0)
+#define FLAG_no_sync (1LL<<1)
 #endif
 
 #ifdef FOR_df
@@ -4620,8 +4653,9 @@
 #define FLAG_strip_trailing_cr (1LL<<17)
 #define FLAG_color (1LL<<18)
 #define FLAG_new_line_format (1LL<<19)
-#define FLAG_old_line_format (1LL<<20)
-#define FLAG_unchanged_line_format (1LL<<21)
+#define FLAG_no_dereference (1LL<<20)
+#define FLAG_old_line_format (1LL<<21)
+#define FLAG_unchanged_line_format (1LL<<22)
 #endif
 
 #ifdef FOR_dirname
@@ -4644,7 +4678,8 @@
 #define FLAG_T (1LL<<5)
 #define FLAG_S (1LL<<6)
 #define FLAG_C (1LL<<7)
-#define FLAG_w (1LL<<8)
+#define FLAG_W (1LL<<8)
+#define FLAG_w (1LL<<9)
 #endif
 
 #ifdef FOR_dnsdomainname
@@ -5726,7 +5761,8 @@
 #define FLAG_n (1LL<<2)
 #define FLAG_k (1LL<<3)
 #define FLAG_m (1LL<<4)
-#define FLAG_e (1LL<<5)
+#define FLAG_D (1LL<<5)
+#define FLAG_e (1LL<<6)
 #endif
 
 #ifdef FOR_lsusb
@@ -7399,7 +7435,8 @@
 #ifndef TT
 #define TT this.vi
 #endif
-#define FLAG_s (1LL<<0)
+#define FLAG_c (1LL<<0)
+#define FLAG_s (1LL<<1)
 #endif
 
 #ifdef FOR_vmstat
diff --git a/android/device/generated/globals.h b/android/device/generated/globals.h
index dc1bc35e..ba08bf21 100644
--- a/android/device/generated/globals.h
+++ b/android/device/generated/globals.h
@@ -128,6 +128,10 @@ struct chrt_data {
   long p;
 };
 
+struct devmem_data {
+  char *f;
+};
+
 struct dos2unix_data {
   char *tempfile;
 };
@@ -304,7 +308,7 @@ struct diff_data {
   struct arg_list *L;
   char *F, *S, *new_line_format, *old_line_format, *unchanged_line_format;
 
-  int dir_num, size, is_binary, differ, change, len[2], *offset[2];
+  int dir_num, size, is_binary, is_symlink, differ, change, len[2], *offset[2];
   struct stat st[2];
   struct {
     char **list;
@@ -314,6 +318,10 @@ struct diff_data {
     FILE *fp;
     int len;
   } file[2];
+  struct {
+    char *name;
+    int len;
+  } link[2];
 };
 
 struct expr_data {
@@ -379,18 +387,15 @@ struct traceroute_data {
 };
 
 struct vi_data {
-  char *s;
+  char *c, *s;
 
   char *filename;
-  int vi_mode, tabstop, list;
-  int cur_col, cur_row, scr_row;
-  int drawn_row, drawn_col;
-  int count0, count1, vi_mov_flag;
+  int vi_mode, tabstop, list, cur_col, cur_row, scr_row, drawn_row, drawn_col,
+      count0, count1, vi_mov_flag;
   unsigned screen_height, screen_width;
   char vi_reg, *last_search;
   struct str_line {
-    int alloc;
-    int len;
+    int alloc, len;
     char *data;
   } *il;
   size_t screen, cursor; //offsets
@@ -398,7 +403,7 @@ struct vi_data {
   struct yank_buf {
     char reg;
     int alloc;
-    char* data;
+    char *data;
   } yank;
 
   size_t filesize;
@@ -407,8 +412,7 @@ struct vi_data {
   struct block_list {
     struct block_list *next, *prev;
     struct mem_block {
-      size_t size;
-      size_t len;
+      size_t size, len;
       enum alloc_flag {
         MMAP,  //can be munmap() before exit()
         HEAP,  //can be free() before exit()
@@ -757,7 +761,7 @@ struct tar_data {
   // Parsed information about a tar header.
   struct tar_header {
     char *name, *link_target, *uname, *gname;
-    long long size, ssize;
+    long long size, ssize, oldsparse;
     uid_t uid;
     gid_t gid;
     mode_t mode;
@@ -825,6 +829,7 @@ extern union global_union {
 	struct blkid_data blkid;
 	struct blockdev_data blockdev;
 	struct chrt_data chrt;
+	struct devmem_data devmem;
 	struct dos2unix_data dos2unix;
 	struct fallocate_data fallocate;
 	struct fmt_data fmt;
diff --git a/android/device/generated/help.h b/android/device/generated/help.h
index 746f73a0..92dd3687 100644
--- a/android/device/generated/help.h
+++ b/android/device/generated/help.h
@@ -108,7 +108,7 @@
 
 #define HELP_gzip "usage: gzip [-19cdfkt] [FILE...]\n\nCompress files. With no files, compresses stdin to stdout.\nOn success, the input files are removed and replaced by new\nfiles with the .gz suffix.\n\n-c	Output to stdout\n-d	Decompress (act as gunzip)\n-f	Force: allow overwrite of output file\n-k	Keep input files (default is to remove)\n-t	Test integrity\n-#	Compression level 1-9 (1:fastest, 6:default, 9:best)"
 
-#define HELP_dmesg "usage: dmesg [-Cc] [-r|-t|-T] [-n LEVEL] [-s SIZE] [-w]\n\nPrint or control the kernel ring buffer.\n\n-C	Clear ring buffer without printing\n-c	Clear ring buffer after printing\n-n	Set kernel logging LEVEL (1-8)\n-r	Raw output (with <level markers>)\n-S	Use syslog(2) rather than /dev/kmsg\n-s	Show the last SIZE many bytes\n-T	Human readable timestamps\n-t	Don't print timestamps\n-w	Keep waiting for more output (aka --follow)"
+#define HELP_dmesg "usage: dmesg [-Cc] [-r|-t|-T] [-n LEVEL] [-s SIZE] [-w|-W]\n\nPrint or control the kernel ring buffer.\n\n-C	Clear ring buffer without printing\n-c	Clear ring buffer after printing\n-n	Set kernel logging LEVEL (1-8)\n-r	Raw output (with <level markers>)\n-S	Use syslog(2) rather than /dev/kmsg\n-s	Show the last SIZE many bytes\n-T	Human readable timestamps\n-t	Don't print timestamps\n-w	Keep waiting for more output (aka --follow)\n-W	Wait for output, only printing new messages"
 
 #define HELP_wget_libtls "Enable HTTPS support for wget by linking to LibTLS.\nSupports using libtls, libretls or libtls-bearssl.\n\nUse TOYBOX_LIBCRYPTO to enable HTTPS support via OpenSSL."
 
@@ -124,7 +124,7 @@
 
 #define HELP_netstat "usage: netstat [-pWrxwutneal]\n\nDisplay networking information. Default is netstat -tuwx\n\n-r	Routing table\n-a	All sockets (not just connected)\n-l	Listening server sockets\n-t	TCP sockets\n-u	UDP sockets\n-w	Raw sockets\n-x	Unix sockets\n-e	Extended info\n-n	Don't resolve names\n-W	Wide display\n-p	Show PID/program name of sockets"
 
-#define HELP_netcat "usage: netcat [-46ELlntUu] [-pqWw #] [-s addr] [-o FILE] {IPADDR PORTNUM|-f FILENAME|COMMAND...}\n\nForward stdin/stdout to a file or network connection.\n\n-4	Force IPv4\n-6	Force IPv6\n-E	Forward stderr\n-f	Use FILENAME (ala /dev/ttyS0) instead of network\n-L	Listen and background each incoming connection (server mode)\n-l	Listen for one incoming connection, then exit\n-n	No DNS lookup\n-o	Hex dump to FILE (-o- writes hex only to stdout)\n-O	Hex dump to FILE (collated)\n-p	Local port number\n-q	Quit SECONDS after EOF on stdin, even if stdout hasn't closed yet\n-s	Local source address\n-t	Allocate tty\n-u	Use UDP\n-U	Use a UNIX domain socket\n-W	SECONDS timeout for more data on an idle connection\n-w	SECONDS timeout to establish connection\n-z	zero-I/O mode [used for scanning]\n\nWhen listening the COMMAND line is executed as a child process to handle\nan incoming connection. With no COMMAND -l forwards the connection\nto stdin/stdout. If no -p specified, -l prints the port it bound to and\nbackgrounds itself (returning immediately).\n\nFor a quick-and-dirty server, try something like:\nnetcat -s 127.0.0.1 -p 1234 -tL sh -l\n\nOr use \"stty 115200 -F /dev/ttyS0 && stty raw -echo -ctlecho\" with\nnetcat -f to connect to a serial port."
+#define HELP_netcat "usage: netcat [-46ELlntUu] [-pqWw #] [-s addr] [-o FILE] {IPADDR PORTNUM|-f FILENAME|COMMAND...}\n\nForward stdin/stdout to a file or network connection.\n\n-4	Force IPv4\n-6	Force IPv6\n-E	Forward stderr\n-f	Use FILENAME (ala /dev/ttyS0) instead of network\n-L	Listen and background each incoming connection (server mode)\n-l	Listen for one incoming connection, then exit\n-n	No DNS lookup\n-o	Hex dump to FILE (show packets, -o- writes hex only to stdout)\n-O	Hex dump to FILE (streaming mode)\n-p	Local port number\n-q	Quit SECONDS after EOF on stdin, even if stdout hasn't closed yet\n-s	Local source address\n-t	Allocate tty\n-u	Use UDP\n-U	Use a UNIX domain socket\n-W	SECONDS timeout for more data on an idle connection\n-w	SECONDS timeout to establish connection\n-z	zero-I/O mode [used for scanning]\n\nWhen listening the COMMAND line is executed as a child process to handle\nan incoming connection. With no COMMAND -l forwards the connection\nto stdin/stdout. If no -p specified, -l prints the port it bound to and\nbackgrounds itself (returning immediately).\n\nFor a quick-and-dirty server, try something like:\nnetcat -s 127.0.0.1 -p 1234 -tL sh -l\n\nOr use \"stty 115200 -F /dev/ttyS0 && stty raw -echo -ctlecho\" with\nnetcat -f to connect to a serial port."
 
 #define HELP_microcom "usage: microcom [-s SPEED] [-X] DEVICE\n\nSimple serial console. Hit CTRL-] for menu.\n\n-s	Set baud rate to SPEED\n-X	Ignore ^] menu escape"
 
@@ -258,7 +258,7 @@
 
 #define HELP_lsusb "usage: lsusb [-i]\n\nList USB hosts/devices.\n\n-i	ID database (default /etc/usb.ids[.gz])"
 
-#define HELP_lspci "usage: lspci [-ekmn] [-i FILE]\n\nList PCI devices.\n\n-e	Extended (6 digit) class\n-i	ID database (default /etc/pci.ids[.gz])\n-k	Show kernel driver\n-m	Machine readable\n-n	Numeric output (-nn for both)\n-x	Hex dump of config space (64 bytes; -xxx for 256, -xxxx for 4096)"
+#define HELP_lspci "usage: lspci [-ekmn] [-i FILE]\n\nList PCI devices.\n\n-e	Extended (6 digit) class\n-i	ID database (default /etc/pci.ids[.gz])\n-k	Show kernel driver\n-m	Machine readable\n-n	Numeric output (-nn for both)\n-D	Print domain numbers\n-x	Hex dump of config space (64 bytes; -xxx for 256, -xxxx for 4096)"
 
 #define HELP_lsmod "usage: lsmod\n\nDisplay the currently loaded modules, their sizes and their dependencies."
 
@@ -330,7 +330,7 @@
 
 #define HELP_dos2unix "usage: dos2unix [FILE...]\n\nConvert newline format from dos \"\\r\\n\" to unix \"\\n\".\nIf no files listed copy from stdin, \"-\" is a synonym for stdin."
 
-#define HELP_devmem "usage: devmem ADDR [WIDTH [DATA]]\n\nRead/write physical address. WIDTH is 1, 2, 4, or 8 bytes (default 4).\nPrefix ADDR with 0x for hexadecimal, output is in same base as address."
+#define HELP_devmem "usage: devmem [-f FILE] ADDR [WIDTH [DATA...]]\n\nRead/write physical addresses. WIDTH is 1, 2, 4, or 8 bytes (default 4).\nPrefix ADDR with 0x for hexadecimal, output is in same base as address.\n\n-f FILE		File to operate on (default /dev/mem)\n--no-sync	Don't open the file with O_SYNC (for cached access)"
 
 #define HELP_count "usage: count [-l]\n\n-l	Long output (total bytes, human readable, transfer rate, elapsed time)\n\nCopy stdin to stdout, displaying simple progress indicator to stderr."
 
@@ -366,7 +366,7 @@
 
 #define HELP_xzcat "usage: xzcat [FILE...]\n\nDecompress listed files to stdout. Use stdin if no files listed."
 
-#define HELP_vi "usage: vi [-s SCRIPT] FILE\n\nVisual text editor. Predates keyboards with standardized cursor keys.\nIf you don't know how to use it, hit the ESC key, type :q! and press ENTER.\n\n-s	run SCRIPT of commands on FILE\n\nvi mode commands:\n\n  [count][cmd][motion]\n  cmd: c d y\n  motion: 0 b e G H h j k L l M w $ f F\n\n  [count][cmd]\n  cmd: D I J O n o p x dd yy\n\n  [cmd]\n  cmd: / ? : A a i CTRL_D CTRL_B CTRL_E CTRL_F CTRL_Y \\e \\b\n\nex mode commands:\n\n  [cmd]\n  \\b \\e \\n w wq q! 'set list' 'set nolist' d $ % g v"
+#define HELP_vi "usage: vi [-s SCRIPT] FILE\n\nVisual text editor. Predates keyboards with standardized cursor keys.\nIf you don't know how to use it, hit the ESC key, type :q! and press ENTER.\n\n-s	run SCRIPT as if typed at keyboard (like -c \"source SCRIPT\")\n-c	run SCRIPT of ex commands\n\nThe editor is usually in one of three modes:\n\n  Hit ESC for \"vi mode\" where each key is a command.\n  Hit : for \"ex mode\" which runs command lines typed at bottom of screen.\n  Hit i (from vi mode) for \"insert mode\" where typing adds to the file.\n\nex mode commands (ESC to exit ex mode):\n\n  q   Quit (exit editor if no unsaved changes)\n  q!  Quit discarding unsaved changes\n  w   Write changed contents to file (optionally to NAME argument)\n  wq  Write to file, then quit\n\nvi mode single key commands:\n  i  switch to insert mode (until next ESC)\n  u  undo last change (can be repeated)\n  a  append (move one character right, switch to insert mode)\n  A  append (jump to end of line, switch to insert mode)\n\nvi mode commands that prompt for more data on bottom line:\n  :  switch to ex mode\n  /  search forwards for regex\n  ?  search backwards for regex\n  .  repeat last command\n\n  [count][cmd][motion]\n  cmd: c d y\n  motion: 0 b e G H h j k L l M w $ f F\n\n  [count][cmd]\n  cmd: D I J O n o p x dd yy\n\n  [cmd]\n  cmd: / ? : A a i CTRL_D CTRL_B CTRL_E CTRL_F CTRL_Y \\e \\b\n\n  [cmd]\n  \\b \\e \\n 'set list' 'set nolist' d $ % g v"
 
 #define HELP_userdel "usage: userdel [-r] USER\nusage: deluser [-r] USER\n\nDelete USER from the SYSTEM\n\n-r	remove home directory"
 
@@ -492,7 +492,7 @@
 
 #define HELP_dumpleases "usage: dumpleases [-r|-a] [-f LEASEFILE]\n\nDisplay DHCP leases granted by udhcpd\n-f FILE,  Lease file\n-r        Show remaining time\n-a        Show expiration time"
 
-#define HELP_diff "usage: diff [-abBdiNqrTstw] [-L LABEL] [-S FILE] [-U LINES] [-F REGEX ] FILE1 FILE2\n\n-a	Treat all files as text\n-b	Ignore changes in the amount of whitespace\n-B	Ignore changes whose lines are all blank\n-d	Try hard to find a smaller set of changes\n-F 	Show the most recent line matching the regex\n-i	Ignore case differences\n-L	Use LABEL instead of the filename in the unified header\n-N	Treat absent files as empty\n-q	Output only whether files differ\n-r	Recurse\n-S	Start with FILE when comparing directories\n-s	Report when two files are the same\n-T	Make tabs line up by prefixing a tab when necessary\n-t	Expand tabs to spaces in output\n-u	Unified diff\n-U	Output LINES lines of context\n-w	Ignore all whitespace\n\n--color     Color output   --strip-trailing-cr   Strip '\\r' from input lines\n--TYPE-line-format=FORMAT  Display TYPE (unchanged/old/new) lines using FORMAT\n  FORMAT uses printf integer escapes (ala %-2.4x) followed by LETTER: FELMNn\nSupported format specifiers are:\n* %l, the contents of the line, without the trailing newline\n* %L, the contents of the line, including the trailing newline\n* %%, the character '%'"
+#define HELP_diff "usage: diff [-abBdiNqrTstw] [-L LABEL] [-S FILE] [-U LINES] [-F REGEX ] FILE1 FILE2\n\n-a	Treat all files as text\n-b	Ignore changes in the amount of whitespace\n-B	Ignore changes whose lines are all blank\n-d	Try hard to find a smaller set of changes\n-F 	Show the most recent line matching the regex\n-i	Ignore case differences\n-L	Use LABEL instead of the filename in the unified header\n-N	Treat absent files as empty\n-q	Output only whether files differ\n-r	Recurse\n-S	Start with FILE when comparing directories\n-s	Report when two files are the same\n-T	Make tabs line up by prefixing a tab when necessary\n-t	Expand tabs to spaces in output\n-u	Unified diff\n-U	Output LINES lines of context\n-w	Ignore all whitespace\n\n--color     Color output   --strip-trailing-cr   Strip '\\r' from input lines\n--no-dereference Don't follow symbolic links\n--TYPE-line-format=FORMAT  Display TYPE (unchanged/old/new) lines using FORMAT\n  FORMAT uses printf integer escapes (ala %-2.4x) followed by LETTER: FELMNn\nSupported format specifiers are:\n* %l, the contents of the line, without the trailing newline\n* %L, the contents of the line, including the trailing newline\n* %%, the character '%'"
 
 #define HELP_dhcpd "usage: dhcpd [-46fS] [-i IFACE] [-P N] [CONFFILE]\n\n -f    Run in foreground\n -i Interface to use\n -S    Log to syslog too\n -P N  Use port N (default ipv4 67, ipv6 547)\n -4, -6    Run as a DHCPv4 or DHCPv6 server"
 
@@ -514,6 +514,8 @@
 
 #define HELP_bc "usage: bc [-ilqsw] [file ...]\n\nbc is a command-line calculator with a Turing-complete language.\n\noptions:\n\n  -i  --interactive  force interactive mode\n  -l  --mathlib      use predefined math routines:\n\n                     s(expr)  =  sine of expr in radians\n                     c(expr)  =  cosine of expr in radians\n                     a(expr)  =  arctangent of expr, returning radians\n                     l(expr)  =  natural log of expr\n                     e(expr)  =  raises e to the power of expr\n                     j(n, x)  =  Bessel function of integer order n of x\n\n  -q  --quiet        don't print version and copyright\n  -s  --standard     error if any non-POSIX extensions are used\n  -w  --warn         warn if any non-POSIX extensions are used"
 
+#define HELP_awk "usage:  awk [-F sepstring] [-v assignment]... program [argument...]\n  or:\n        awk [-F sepstring] -f progfile [-f progfile]... [-v assignment]...\n              [argument...]\n  also:\n  -b : use bytes, not characters\n  -c : compile only, do not run"
+
 #define HELP_arping "usage: arping [-fqbDUA] [-c CNT] [-w TIMEOUT] [-I IFACE] [-s SRC_IP] DST_IP\n\nSend ARP requests/replies\n\n-f         Quit on first ARP reply\n-q         Quiet\n-b         Keep broadcasting, don't go unicast\n-D         Duplicated address detection mode\n-U         Unsolicited ARP mode, update your neighbors\n-A         ARP answer mode, update your neighbors\n-c N       Stop after sending N ARP requests\n-w TIMEOUT Time to wait for ARP reply, seconds\n-I IFACE   Interface to use (default eth0)\n-s SRC_IP  Sender IP address\nDST_IP     Target IP address"
 
 #define HELP_arp "usage: arp\n[-vn] [-H HWTYPE] [-i IF] -a [HOSTNAME]\n[-v]              [-i IF] -d HOSTNAME [pub]\n[-v]  [-H HWTYPE] [-i IF] -s HOSTNAME HWADDR [temp]\n[-v]  [-H HWTYPE] [-i IF] -s HOSTNAME HWADDR [netmask MASK] pub\n[-v]  [-H HWTYPE] [-i IF] -Ds HOSTNAME IFACE [netmask MASK] pub\n\nManipulate ARP cache.\n\n-a	Display (all) hosts\n-s	Set new ARP entry\n-d	Delete a specified entry\n-v	Verbose\n-n	Don't resolve names\n-i IFACE	Network interface\n-D	Read <hwaddr> from given device\n-A,-p AF	Protocol family\n-H HWTYPE	Hardware address type"
@@ -548,7 +550,7 @@
 
 #define HELP_time "usage: time [-pv] COMMAND...\n\nRun command line and report real, user, and system time elapsed in seconds.\n(real = clock on the wall, user = cpu used by command's code,\nsystem = cpu used by OS on behalf of command.)\n\n-p	POSIX format output\n-v	Verbose"
 
-#define HELP_test "usage: test [-bcdefghkLprSsuwx PATH] [-nz STRING] [-t FD] [X ?? Y]\n\nReturn true or false by performing tests. No arguments is false, one argument\nis true if not empty string.\n\n--- Tests with a single argument (after the option):\nPATH is/has:\n  -b  block device   -f  regular file   -p  fifo           -u  setuid bit\n  -c  char device    -g  setgid         -r  readable       -w  writable\n  -d  directory      -h  symlink        -S  socket         -x  executable\n  -e  exists         -L  symlink        -s  nonzero size   -k  sticky bit\nSTRING is:\n  -n  nonzero size   -z  zero size\nFD (integer file descriptor) is:\n  -t  a TTY\n\n--- Tests with one argument on each side of an operator:\nTwo strings:\n  =  are identical   !=  differ         =~  string matches regex\nAlphabetical sort:\n  <  first is lower  >   first higher\nTwo integers:\n  -eq  equal         -gt  first > second    -lt  first < second\n  -ne  not equal     -ge  first >= second   -le  first <= second\n\n--- Modify or combine tests:\n  ! EXPR     not (swap true/false)   EXPR -a EXPR    and (are both true)\n  ( EXPR )   evaluate this first     EXPR -o EXPR    or (is either true)"
+#define HELP_test "usage: test [-bcdefghkLprSsuwx PATH] [-nz STRING] [-t FD] [X ?? Y]\n\nReturn true or false by performing tests. No arguments is false, one argument\nis true if not empty string.\n\n--- Tests with a single argument (after the option):\nPATH is/has:\n  -b  block device   -f  regular file   -p  fifo           -u  setuid bit\n  -c  char device    -g  setgid         -r  readable       -w  writable\n  -d  directory      -h  symlink        -S  socket         -x  executable\n  -e  exists         -L  symlink        -s  nonzero size   -k  sticky bit\nSTRING is:\n  -n  nonzero size   -z  zero size\nFD (integer file descriptor) is:\n  -t  a TTY\n\n--- Tests with one argument on each side of an operator:\nTwo strings:\n  =  are identical   !=  differ         =~  string matches regex\nAlphabetical sort:\n  <  first is lower  >   first higher\nTwo integers:\n  -eq  equal         -gt  first > second    -lt  first < second\n  -ne  not equal     -ge  first >= second   -le  first <= second\nTwo files:\n  -ot  Older mtime   -nt  Newer mtime       -ef  same dev/inode\n\n--- Modify or combine tests:\n  ! EXPR     not (swap true/false)   EXPR -a EXPR    and (are both true)\n  ( EXPR )   evaluate this first     EXPR -o EXPR    or (is either true)"
 
 #define HELP_tee "usage: tee [-ai] [FILE...]\n\nCopy stdin to each listed file, and also to stdout.\nFilename \"-\" is a synonym for stdout.\n\n-a	Append to files\n-i	Ignore SIGINT"
 
diff --git a/android/device/generated/newtoys.h b/android/device/generated/newtoys.h
index 0582c103..c41eb83f 100644
--- a/android/device/generated/newtoys.h
+++ b/android/device/generated/newtoys.h
@@ -13,6 +13,7 @@ USE_ARCH(NEWTOY(arch, 0, TOYFLAG_USR|TOYFLAG_BIN))
 USE_ARP(NEWTOY(arp, "vi:nDsdap:A:H:[+Ap][!sd]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_ARPING(NEWTOY(arping, "<1>1s:I:w#<0c#<0AUDbqf[+AU][+Df]", TOYFLAG_USR|TOYFLAG_SBIN))
 USE_ASCII(NEWTOY(ascii, 0, TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
+USE_AWK(NEWTOY(awk, "F:v*f*bc", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_BASE32(NEWTOY(base32, "diw#<0=76[!dw]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_BASE64(NEWTOY(base64, "diw#<0=76[!dw]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_BASENAME(NEWTOY(basename, "^<1as:", TOYFLAG_USR|TOYFLAG_BIN))
@@ -59,20 +60,20 @@ USE_DEMO_MANY_OPTIONS(NEWTOY(demo_many_options, "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwv
 USE_DEMO_NUMBER(NEWTOY(demo_number, "D#=3<3M#<0hcdbs", TOYFLAG_BIN))
 USE_DEMO_SCANKEY(NEWTOY(demo_scankey, 0, TOYFLAG_BIN))
 USE_DEMO_UTF8TOWC(NEWTOY(demo_utf8towc, 0, TOYFLAG_USR|TOYFLAG_BIN))
-USE_DEVMEM(NEWTOY(devmem, "<1>3", TOYFLAG_USR|TOYFLAG_SBIN))
+USE_DEVMEM(NEWTOY(devmem, "<1(no-sync)f:", TOYFLAG_USR|TOYFLAG_SBIN))
 USE_DF(NEWTOY(df, "HPkhit*a[-HPh]", TOYFLAG_BIN))
 USE_DHCP(NEWTOY(dhcp, "V:H:F:x*r:O*A#<0=20T#<0=3t#<0=3s:p:i:SBRCaovqnbf", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
 USE_DHCP6(NEWTOY(dhcp6, "r:A#<0T#<0t#<0s:p:i:SRvqnbf", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
 USE_DHCPD(NEWTOY(dhcpd, ">1P#<0>65535fi:S46[!46]", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
-USE_DIFF(NEWTOY(diff, "<2>2(unchanged-line-format):;(old-line-format):;(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)))
+USE_DIFF(NEWTOY(diff, "<2>2(unchanged-line-format):;(old-line-format):;(no-dereference);(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)))
 USE_DIRNAME(NEWTOY(dirname, "<1", TOYFLAG_USR|TOYFLAG_BIN))
-USE_DMESG(NEWTOY(dmesg, "w(follow)CSTtrs#<1n#c[!Ttr][!Cc][!Sw]", TOYFLAG_BIN))
+USE_DMESG(NEWTOY(dmesg, "w(follow)W(follow-new)CSTtrs#<1n#c[!Ttr][!Cc][!SWw]", TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_DNSDOMAINNAME(NEWTOY(dnsdomainname, ">0", TOYFLAG_BIN))
 USE_DOS2UNIX(NEWTOY(dos2unix, 0, TOYFLAG_BIN))
 USE_DU(NEWTOY(du, "d#<0=-1hmlcaHkKLsxb[-HL][-kKmh]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_DUMPLEASES(NEWTOY(dumpleases, ">0arf:[!ar]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_ECHO(NEWTOY(echo, "^?Een[-eE]", TOYFLAG_BIN|TOYFLAG_MAYFORK|TOYFLAG_LINEBUF))
-USE_EGREP(OLDTOY(egrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF))
+USE_EGREP(OLDTOY(egrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF|TOYFLAG_AUTOCONF))
 USE_EJECT(NEWTOY(eject, ">1stT[!tT]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_ENV(NEWTOY(env, "^e:i0u*", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(125)))
 USE_SH(NEWTOY(eval, 0, TOYFLAG_NOFORK))
@@ -85,7 +86,7 @@ USE_FACTOR(NEWTOY(factor, "?hx", TOYFLAG_USR|TOYFLAG_BIN))
 USE_FALLOCATE(NEWTOY(fallocate, ">1l#|o#", TOYFLAG_USR|TOYFLAG_BIN))
 USE_FALSE(NEWTOY(false, NULL, TOYFLAG_BIN|TOYFLAG_NOHELP|TOYFLAG_MAYFORK))
 USE_FDISK(NEWTOY(fdisk, "C#<0H#<0S#<0b#<512ul", TOYFLAG_SBIN))
-USE_FGREP(OLDTOY(fgrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF))
+USE_FGREP(OLDTOY(fgrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF|TOYFLAG_AUTOCONF))
 USE_FILE(NEWTOY(file, "<1b(brief)hLs[!hL]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_FIND(NEWTOY(find, "?^HL[-HL]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_FLOCK(NEWTOY(flock, "<1>1nsux[-sux]", TOYFLAG_USR|TOYFLAG_BIN))
@@ -114,7 +115,7 @@ USE_GPIOFIND(NEWTOY(gpiofind, "<1>1", TOYFLAG_USR|TOYFLAG_BIN))
 USE_GPIOGET(NEWTOY(gpioget, "<2l", TOYFLAG_USR|TOYFLAG_BIN))
 USE_GPIOINFO(NEWTOY(gpioinfo, 0, TOYFLAG_USR|TOYFLAG_BIN))
 USE_GPIOSET(NEWTOY(gpioset, "<2l", TOYFLAG_USR|TOYFLAG_BIN))
-USE_GREP(NEWTOY(grep, "(line-buffered)(color):;(exclude-dir)*S(exclude)*M(include)*ZzEFHIab(byte-offset)h(no-filename)ino(only-matching)rRsvwc(count)L(files-without-match)l(files-with-matches)q(quiet)(silent)e*f*C#B#A#m#x[!wx][!EF]", TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF))
+USE_GREP(NEWTOY(grep, "(line-buffered)(color):;(exclude-dir)*S(exclude)*M(include)*ZzEFHIab(byte-offset)h(no-filename)ino(only-matching)rRsvwc(count)L(files-without-match)l(files-with-matches)q(quiet)(silent)e*f*C#B#A#m#x[!wx][!EF]", TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF|TOYFLAG_AUTOCONF))
 USE_GROUPADD(NEWTOY(groupadd, "<1>2R:g#<0>2147483647S", TOYFLAG_NEEDROOT|TOYFLAG_SBIN))
 USE_GROUPDEL(NEWTOY(groupdel, "<1>2?", TOYFLAG_NEEDROOT|TOYFLAG_SBIN))
 USE_GROUPS(NEWTOY(groups, NULL, TOYFLAG_USR|TOYFLAG_BIN))
@@ -176,7 +177,7 @@ USE_LS(NEWTOY(ls, "(sort):(color):;(full-time)(show-control-chars)\377(block-siz
 USE_LSATTR(NEWTOY(lsattr, "ldapvR", TOYFLAG_BIN))
 USE_LSMOD(NEWTOY(lsmod, NULL, TOYFLAG_SBIN))
 USE_LSOF(NEWTOY(lsof, "lp*t", TOYFLAG_USR|TOYFLAG_BIN))
-USE_LSPCI(NEWTOY(lspci, "emkn@x@i:", TOYFLAG_USR|TOYFLAG_BIN))
+USE_LSPCI(NEWTOY(lspci, "eDmkn@x@i:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_LSUSB(NEWTOY(lsusb, "i:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MAKEDEVS(NEWTOY(makedevs, "<1>1d:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MAN(NEWTOY(man, "k:M:", TOYFLAG_USR|TOYFLAG_BIN))
@@ -250,7 +251,7 @@ USE_RMMOD(NEWTOY(rmmod, "<1wf", TOYFLAG_SBIN|TOYFLAG_NEEDROOT))
 USE_ROUTE(NEWTOY(route, "?neA:", TOYFLAG_SBIN))
 USE_RTCWAKE(NEWTOY(rtcwake, "(list-modes);(auto)a(device)d:(local)l(mode)m:(seconds)s#(time)t#(utc)u(verbose)v[!alu]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_RUNCON(NEWTOY(runcon, "^<2", TOYFLAG_USR|TOYFLAG_SBIN))
-USE_SED(NEWTOY(sed, "(help)(version)(tarxform)e*f*i:;nErz(null-data)s[+Er]", TOYFLAG_BIN|TOYFLAG_NOHELP))
+USE_SED(NEWTOY(sed, "(help)(version)(tarxform)e*f*i:;nErz(null-data)s[+Er]", TOYFLAG_BIN|TOYFLAG_AUTOCONF))
 USE_SENDEVENT(NEWTOY(sendevent, "<4>4", TOYFLAG_USR|TOYFLAG_SBIN))
 USE_SEQ(NEWTOY(seq, "<1>3?f:s:w[!fw]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_SH(NEWTOY(set, 0, TOYFLAG_NOFORK))
@@ -288,7 +289,7 @@ USE_SYSCTL(NEWTOY(sysctl, "^neNqwpaA[!ap][!aq][!aw][+aA]", TOYFLAG_SBIN))
 USE_SYSLOGD(NEWTOY(syslogd,">0l#<1>8=8R:b#<0>99=1s#<0=200m#<0>71582787=20O:p:f:a:nSKLD", TOYFLAG_SBIN|TOYFLAG_STAYROOT))
 USE_TAC(NEWTOY(tac, NULL, TOYFLAG_USR|TOYFLAG_BIN))
 USE_TAIL(NEWTOY(tail, "?fFs:c(bytes)-n(lines)-[-cn][-fF]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
-USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN))
+USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
 USE_TASKSET(NEWTOY(taskset, "<1^pa", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TCPSVD(NEWTOY(tcpsvd, "^<3c#=30<1b#=20<0C:u:l:hEv", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TEE(NEWTOY(tee, "ia", TOYFLAG_USR|TOYFLAG_BIN))
@@ -330,7 +331,7 @@ USE_UUDECODE(NEWTOY(uudecode, ">1o:", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
 USE_UUENCODE(NEWTOY(uuencode, "<1>2m", TOYFLAG_USR|TOYFLAG_BIN))
 USE_UUIDGEN(NEWTOY(uuidgen, ">0r(random)", TOYFLAG_USR|TOYFLAG_BIN))
 USE_VCONFIG(NEWTOY(vconfig, "<2>4", TOYFLAG_NEEDROOT|TOYFLAG_SBIN))
-USE_VI(NEWTOY(vi, ">1s:", TOYFLAG_USR|TOYFLAG_BIN))
+USE_VI(NEWTOY(vi, ">1s:c:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_VMSTAT(NEWTOY(vmstat, ">2n", TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_W(NEWTOY(w, NULL, TOYFLAG_USR|TOYFLAG_BIN))
 USE_SH(NEWTOY(wait, "n", TOYFLAG_NOFORK))
diff --git a/android/linux/generated/config.h b/android/linux/generated/config.h
index 330982dd..655f55c2 100644
--- a/android/linux/generated/config.h
+++ b/android/linux/generated/config.h
@@ -42,6 +42,8 @@
 #define USE_ARP(...)
 #define CFG_ASCII 0
 #define USE_ASCII(...)
+#define CFG_AWK 0
+#define USE_AWK(...)
 #define CFG_BASE32 0
 #define USE_BASE32(...)
 #define CFG_BASE64 0
diff --git a/android/linux/generated/flags.h b/android/linux/generated/flags.h
index 6e123935..e73e4bf8 100644
--- a/android/linux/generated/flags.h
+++ b/android/linux/generated/flags.h
@@ -70,6 +70,19 @@
 #undef FOR_ascii
 #endif
 
+// awk   F:v*f*bc
+#undef OPTSTR_awk
+#define OPTSTR_awk "F:v*f*bc"
+#ifdef CLEANUP_awk
+#undef CLEANUP_awk
+#undef FOR_awk
+#undef FLAG_c
+#undef FLAG_b
+#undef FLAG_f
+#undef FLAG_v
+#undef FLAG_F
+#endif
+
 // base32   diw#<0=76[!dw]
 #undef OPTSTR_base32
 #define OPTSTR_base32 "diw#<0=76[!dw]"
@@ -628,12 +641,14 @@
 #undef FOR_demo_utf8towc
 #endif
 
-// devmem   <1>3
+// devmem   <1(no-sync)f:
 #undef OPTSTR_devmem
-#define OPTSTR_devmem "<1>3"
+#define OPTSTR_devmem "<1(no-sync)f:"
 #ifdef CLEANUP_devmem
 #undef CLEANUP_devmem
 #undef FOR_devmem
+#undef FLAG_f
+#undef FLAG_no_sync
 #endif
 
 // df   HPkhit*a[-HPh]
@@ -718,9 +733,9 @@
 #undef FLAG_P
 #endif
 
-// diff <2>2(unchanged-line-format):;(old-line-format):;(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3 <2>2(unchanged-line-format):;(old-line-format):;(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3
+// diff <2>2(unchanged-line-format):;(old-line-format):;(no-dereference);(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3 <2>2(unchanged-line-format):;(old-line-format):;(no-dereference);(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3
 #undef OPTSTR_diff
-#define OPTSTR_diff "<2>2(unchanged-line-format):;(old-line-format):;(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3"
+#define OPTSTR_diff "<2>2(unchanged-line-format):;(old-line-format):;(no-dereference);(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3"
 #ifdef CLEANUP_diff
 #undef CLEANUP_diff
 #undef FOR_diff
@@ -744,6 +759,7 @@
 #undef FLAG_strip_trailing_cr
 #undef FLAG_color
 #undef FLAG_new_line_format
+#undef FLAG_no_dereference
 #undef FLAG_old_line_format
 #undef FLAG_unchanged_line_format
 #endif
@@ -756,9 +772,9 @@
 #undef FOR_dirname
 #endif
 
-// dmesg   w(follow)CSTtrs#<1n#c[!Ttr][!Cc][!Sw]
+// dmesg   w(follow)W(follow-new)CSTtrs#<1n#c[!Ttr][!Cc][!SWw]
 #undef OPTSTR_dmesg
-#define OPTSTR_dmesg "w(follow)CSTtrs#<1n#c[!Ttr][!Cc][!Sw]"
+#define OPTSTR_dmesg "w(follow)W(follow-new)CSTtrs#<1n#c[!Ttr][!Cc][!SWw]"
 #ifdef CLEANUP_dmesg
 #undef CLEANUP_dmesg
 #undef FOR_dmesg
@@ -770,6 +786,7 @@
 #undef FLAG_T
 #undef FLAG_S
 #undef FLAG_C
+#undef FLAG_W
 #undef FLAG_w
 #endif
 
@@ -1941,9 +1958,9 @@
 #undef FLAG_l
 #endif
 
-// lspci   emkn@x@i:
+// lspci   eDmkn@x@i:
 #undef OPTSTR_lspci
-#define OPTSTR_lspci "emkn@x@i:"
+#define OPTSTR_lspci "eDmkn@x@i:"
 #ifdef CLEANUP_lspci
 #undef CLEANUP_lspci
 #undef FOR_lspci
@@ -1952,6 +1969,7 @@
 #undef FLAG_n
 #undef FLAG_k
 #undef FLAG_m
+#undef FLAG_D
 #undef FLAG_e
 #endif
 
@@ -3760,12 +3778,13 @@
 #undef FOR_vconfig
 #endif
 
-// vi   >1s:
+// vi   >1s:c:
 #undef OPTSTR_vi
-#define OPTSTR_vi ">1s:"
+#define OPTSTR_vi ">1s:c:"
 #ifdef CLEANUP_vi
 #undef CLEANUP_vi
 #undef FOR_vi
+#undef FLAG_c
 #undef FLAG_s
 #endif
 
@@ -3994,6 +4013,18 @@
 #endif
 #endif
 
+#ifdef FOR_awk
+#define CLEANUP_awk
+#ifndef TT
+#define TT this.awk
+#endif
+#define FLAG_c (FORCED_FLAG<<0)
+#define FLAG_b (FORCED_FLAG<<1)
+#define FLAG_f (FORCED_FLAG<<2)
+#define FLAG_v (FORCED_FLAG<<3)
+#define FLAG_F (FORCED_FLAG<<4)
+#endif
+
 #ifdef FOR_base32
 #define CLEANUP_base32
 #ifndef TT
@@ -4515,6 +4546,8 @@
 #ifndef TT
 #define TT this.devmem
 #endif
+#define FLAG_f (FORCED_FLAG<<0)
+#define FLAG_no_sync (FORCED_FLAG<<1)
 #endif
 
 #ifdef FOR_df
@@ -4620,8 +4653,9 @@
 #define FLAG_strip_trailing_cr (1LL<<17)
 #define FLAG_color (1LL<<18)
 #define FLAG_new_line_format (1LL<<19)
-#define FLAG_old_line_format (1LL<<20)
-#define FLAG_unchanged_line_format (1LL<<21)
+#define FLAG_no_dereference (1LL<<20)
+#define FLAG_old_line_format (1LL<<21)
+#define FLAG_unchanged_line_format (1LL<<22)
 #endif
 
 #ifdef FOR_dirname
@@ -4644,7 +4678,8 @@
 #define FLAG_T (FORCED_FLAG<<5)
 #define FLAG_S (FORCED_FLAG<<6)
 #define FLAG_C (FORCED_FLAG<<7)
-#define FLAG_w (FORCED_FLAG<<8)
+#define FLAG_W (FORCED_FLAG<<8)
+#define FLAG_w (FORCED_FLAG<<9)
 #endif
 
 #ifdef FOR_dnsdomainname
@@ -5726,7 +5761,8 @@
 #define FLAG_n (FORCED_FLAG<<2)
 #define FLAG_k (FORCED_FLAG<<3)
 #define FLAG_m (FORCED_FLAG<<4)
-#define FLAG_e (FORCED_FLAG<<5)
+#define FLAG_D (FORCED_FLAG<<5)
+#define FLAG_e (FORCED_FLAG<<6)
 #endif
 
 #ifdef FOR_lsusb
@@ -7399,7 +7435,8 @@
 #ifndef TT
 #define TT this.vi
 #endif
-#define FLAG_s (FORCED_FLAG<<0)
+#define FLAG_c (FORCED_FLAG<<0)
+#define FLAG_s (FORCED_FLAG<<1)
 #endif
 
 #ifdef FOR_vmstat
diff --git a/android/linux/generated/globals.h b/android/linux/generated/globals.h
index 37bdea6b..188306e8 100644
--- a/android/linux/generated/globals.h
+++ b/android/linux/generated/globals.h
@@ -99,7 +99,7 @@ struct diff_data {
   struct arg_list *L;
   char *F, *S, *new_line_format, *old_line_format, *unchanged_line_format;
 
-  int dir_num, size, is_binary, differ, change, len[2], *offset[2];
+  int dir_num, size, is_binary, is_symlink, differ, change, len[2], *offset[2];
   struct stat st[2];
   struct {
     char **list;
@@ -109,6 +109,10 @@ struct diff_data {
     FILE *fp;
     int len;
   } file[2];
+  struct {
+    char *name;
+    int len;
+  } link[2];
 };
 
 struct expr_data {
@@ -378,7 +382,7 @@ struct tar_data {
   // Parsed information about a tar header.
   struct tar_header {
     char *name, *link_target, *uname, *gname;
-    long long size, ssize;
+    long long size, ssize, oldsparse;
     uid_t uid;
     gid_t gid;
     mode_t mode;
diff --git a/android/linux/generated/help.h b/android/linux/generated/help.h
index c701383a..f25a0785 100644
--- a/android/linux/generated/help.h
+++ b/android/linux/generated/help.h
@@ -110,7 +110,7 @@
 
 #define HELP_gzip "usage: gzip [-19cdfkt] [FILE...]\n\nCompress files. With no files, compresses stdin to stdout.\nOn success, the input files are removed and replaced by new\nfiles with the .gz suffix.\n\n-c	Output to stdout\n-d	Decompress (act as gunzip)\n-f	Force: allow overwrite of output file\n-k	Keep input files (default is to remove)\n-t	Test integrity\n-#	Compression level 1-9 (1:fastest, 6:default, 9:best)"
 
-#define HELP_dmesg "usage: dmesg [-Cc] [-r|-t|-T] [-n LEVEL] [-s SIZE] [-w]\n\nPrint or control the kernel ring buffer.\n\n-C	Clear ring buffer without printing\n-c	Clear ring buffer after printing\n-n	Set kernel logging LEVEL (1-8)\n-r	Raw output (with <level markers>)\n-S	Use syslog(2) rather than /dev/kmsg\n-s	Show the last SIZE many bytes\n-T	Human readable timestamps\n-t	Don't print timestamps\n-w	Keep waiting for more output (aka --follow)"
+#define HELP_dmesg "usage: dmesg [-Cc] [-r|-t|-T] [-n LEVEL] [-s SIZE] [-w|-W]\n\nPrint or control the kernel ring buffer.\n\n-C	Clear ring buffer without printing\n-c	Clear ring buffer after printing\n-n	Set kernel logging LEVEL (1-8)\n-r	Raw output (with <level markers>)\n-S	Use syslog(2) rather than /dev/kmsg\n-s	Show the last SIZE many bytes\n-T	Human readable timestamps\n-t	Don't print timestamps\n-w	Keep waiting for more output (aka --follow)\n-W	Wait for output, only printing new messages"
 
 #define HELP_wget_libtls "Enable HTTPS support for wget by linking to LibTLS.\nSupports using libtls, libretls or libtls-bearssl.\n\nUse TOYBOX_LIBCRYPTO to enable HTTPS support via OpenSSL."
 
@@ -126,7 +126,7 @@
 
 #define HELP_netstat "usage: netstat [-pWrxwutneal]\n\nDisplay networking information. Default is netstat -tuwx\n\n-r	Routing table\n-a	All sockets (not just connected)\n-l	Listening server sockets\n-t	TCP sockets\n-u	UDP sockets\n-w	Raw sockets\n-x	Unix sockets\n-e	Extended info\n-n	Don't resolve names\n-W	Wide display\n-p	Show PID/program name of sockets"
 
-#define HELP_netcat "usage: netcat [-46ELlntUu] [-pqWw #] [-s addr] [-o FILE] {IPADDR PORTNUM|-f FILENAME|COMMAND...}\n\nForward stdin/stdout to a file or network connection.\n\n-4	Force IPv4\n-6	Force IPv6\n-E	Forward stderr\n-f	Use FILENAME (ala /dev/ttyS0) instead of network\n-L	Listen and background each incoming connection (server mode)\n-l	Listen for one incoming connection, then exit\n-n	No DNS lookup\n-o	Hex dump to FILE (-o- writes hex only to stdout)\n-O	Hex dump to FILE (collated)\n-p	Local port number\n-q	Quit SECONDS after EOF on stdin, even if stdout hasn't closed yet\n-s	Local source address\n-t	Allocate tty\n-u	Use UDP\n-U	Use a UNIX domain socket\n-W	SECONDS timeout for more data on an idle connection\n-w	SECONDS timeout to establish connection\n-z	zero-I/O mode [used for scanning]\n\nWhen listening the COMMAND line is executed as a child process to handle\nan incoming connection. With no COMMAND -l forwards the connection\nto stdin/stdout. If no -p specified, -l prints the port it bound to and\nbackgrounds itself (returning immediately).\n\nFor a quick-and-dirty server, try something like:\nnetcat -s 127.0.0.1 -p 1234 -tL sh -l\n\nOr use \"stty 115200 -F /dev/ttyS0 && stty raw -echo -ctlecho\" with\nnetcat -f to connect to a serial port."
+#define HELP_netcat "usage: netcat [-46ELlntUu] [-pqWw #] [-s addr] [-o FILE] {IPADDR PORTNUM|-f FILENAME|COMMAND...}\n\nForward stdin/stdout to a file or network connection.\n\n-4	Force IPv4\n-6	Force IPv6\n-E	Forward stderr\n-f	Use FILENAME (ala /dev/ttyS0) instead of network\n-L	Listen and background each incoming connection (server mode)\n-l	Listen for one incoming connection, then exit\n-n	No DNS lookup\n-o	Hex dump to FILE (show packets, -o- writes hex only to stdout)\n-O	Hex dump to FILE (streaming mode)\n-p	Local port number\n-q	Quit SECONDS after EOF on stdin, even if stdout hasn't closed yet\n-s	Local source address\n-t	Allocate tty\n-u	Use UDP\n-U	Use a UNIX domain socket\n-W	SECONDS timeout for more data on an idle connection\n-w	SECONDS timeout to establish connection\n-z	zero-I/O mode [used for scanning]\n\nWhen listening the COMMAND line is executed as a child process to handle\nan incoming connection. With no COMMAND -l forwards the connection\nto stdin/stdout. If no -p specified, -l prints the port it bound to and\nbackgrounds itself (returning immediately).\n\nFor a quick-and-dirty server, try something like:\nnetcat -s 127.0.0.1 -p 1234 -tL sh -l\n\nOr use \"stty 115200 -F /dev/ttyS0 && stty raw -echo -ctlecho\" with\nnetcat -f to connect to a serial port."
 
 #define HELP_microcom "usage: microcom [-s SPEED] [-X] DEVICE\n\nSimple serial console. Hit CTRL-] for menu.\n\n-s	Set baud rate to SPEED\n-X	Ignore ^] menu escape"
 
@@ -260,7 +260,7 @@
 
 #define HELP_lsusb "usage: lsusb [-i]\n\nList USB hosts/devices.\n\n-i	ID database (default /etc/usb.ids[.gz])"
 
-#define HELP_lspci "usage: lspci [-ekmn] [-i FILE]\n\nList PCI devices.\n\n-e	Extended (6 digit) class\n-i	ID database (default /etc/pci.ids[.gz])\n-k	Show kernel driver\n-m	Machine readable\n-n	Numeric output (-nn for both)\n-x	Hex dump of config space (64 bytes; -xxx for 256, -xxxx for 4096)"
+#define HELP_lspci "usage: lspci [-ekmn] [-i FILE]\n\nList PCI devices.\n\n-e	Extended (6 digit) class\n-i	ID database (default /etc/pci.ids[.gz])\n-k	Show kernel driver\n-m	Machine readable\n-n	Numeric output (-nn for both)\n-D	Print domain numbers\n-x	Hex dump of config space (64 bytes; -xxx for 256, -xxxx for 4096)"
 
 #define HELP_lsmod "usage: lsmod\n\nDisplay the currently loaded modules, their sizes and their dependencies."
 
@@ -332,7 +332,7 @@
 
 #define HELP_dos2unix "usage: dos2unix [FILE...]\n\nConvert newline format from dos \"\\r\\n\" to unix \"\\n\".\nIf no files listed copy from stdin, \"-\" is a synonym for stdin."
 
-#define HELP_devmem "usage: devmem ADDR [WIDTH [DATA]]\n\nRead/write physical address. WIDTH is 1, 2, 4, or 8 bytes (default 4).\nPrefix ADDR with 0x for hexadecimal, output is in same base as address."
+#define HELP_devmem "usage: devmem [-f FILE] ADDR [WIDTH [DATA...]]\n\nRead/write physical addresses. WIDTH is 1, 2, 4, or 8 bytes (default 4).\nPrefix ADDR with 0x for hexadecimal, output is in same base as address.\n\n-f FILE		File to operate on (default /dev/mem)\n--no-sync	Don't open the file with O_SYNC (for cached access)"
 
 #define HELP_count "usage: count [-l]\n\n-l	Long output (total bytes, human readable, transfer rate, elapsed time)\n\nCopy stdin to stdout, displaying simple progress indicator to stderr."
 
@@ -368,7 +368,7 @@
 
 #define HELP_xzcat "usage: xzcat [FILE...]\n\nDecompress listed files to stdout. Use stdin if no files listed."
 
-#define HELP_vi "usage: vi [-s SCRIPT] FILE\n\nVisual text editor. Predates keyboards with standardized cursor keys.\nIf you don't know how to use it, hit the ESC key, type :q! and press ENTER.\n\n-s	run SCRIPT of commands on FILE\n\nvi mode commands:\n\n  [count][cmd][motion]\n  cmd: c d y\n  motion: 0 b e G H h j k L l M w $ f F\n\n  [count][cmd]\n  cmd: D I J O n o p x dd yy\n\n  [cmd]\n  cmd: / ? : A a i CTRL_D CTRL_B CTRL_E CTRL_F CTRL_Y \\e \\b\n\nex mode commands:\n\n  [cmd]\n  \\b \\e \\n w wq q! 'set list' 'set nolist' d $ % g v"
+#define HELP_vi "usage: vi [-s SCRIPT] FILE\n\nVisual text editor. Predates keyboards with standardized cursor keys.\nIf you don't know how to use it, hit the ESC key, type :q! and press ENTER.\n\n-s	run SCRIPT as if typed at keyboard (like -c \"source SCRIPT\")\n-c	run SCRIPT of ex commands\n\nThe editor is usually in one of three modes:\n\n  Hit ESC for \"vi mode\" where each key is a command.\n  Hit : for \"ex mode\" which runs command lines typed at bottom of screen.\n  Hit i (from vi mode) for \"insert mode\" where typing adds to the file.\n\nex mode commands (ESC to exit ex mode):\n\n  q   Quit (exit editor if no unsaved changes)\n  q!  Quit discarding unsaved changes\n  w   Write changed contents to file (optionally to NAME argument)\n  wq  Write to file, then quit\n\nvi mode single key commands:\n  i  switch to insert mode (until next ESC)\n  u  undo last change (can be repeated)\n  a  append (move one character right, switch to insert mode)\n  A  append (jump to end of line, switch to insert mode)\n\nvi mode commands that prompt for more data on bottom line:\n  :  switch to ex mode\n  /  search forwards for regex\n  ?  search backwards for regex\n  .  repeat last command\n\n  [count][cmd][motion]\n  cmd: c d y\n  motion: 0 b e G H h j k L l M w $ f F\n\n  [count][cmd]\n  cmd: D I J O n o p x dd yy\n\n  [cmd]\n  cmd: / ? : A a i CTRL_D CTRL_B CTRL_E CTRL_F CTRL_Y \\e \\b\n\n  [cmd]\n  \\b \\e \\n 'set list' 'set nolist' d $ % g v"
 
 #define HELP_userdel "usage: userdel [-r] USER\nusage: deluser [-r] USER\n\nDelete USER from the SYSTEM\n\n-r	remove home directory"
 
@@ -494,7 +494,7 @@
 
 #define HELP_dumpleases "usage: dumpleases [-r|-a] [-f LEASEFILE]\n\nDisplay DHCP leases granted by udhcpd\n-f FILE,  Lease file\n-r        Show remaining time\n-a        Show expiration time"
 
-#define HELP_diff "usage: diff [-abBdiNqrTstw] [-L LABEL] [-S FILE] [-U LINES] [-F REGEX ] FILE1 FILE2\n\n-a	Treat all files as text\n-b	Ignore changes in the amount of whitespace\n-B	Ignore changes whose lines are all blank\n-d	Try hard to find a smaller set of changes\n-F 	Show the most recent line matching the regex\n-i	Ignore case differences\n-L	Use LABEL instead of the filename in the unified header\n-N	Treat absent files as empty\n-q	Output only whether files differ\n-r	Recurse\n-S	Start with FILE when comparing directories\n-s	Report when two files are the same\n-T	Make tabs line up by prefixing a tab when necessary\n-t	Expand tabs to spaces in output\n-u	Unified diff\n-U	Output LINES lines of context\n-w	Ignore all whitespace\n\n--color     Color output   --strip-trailing-cr   Strip '\\r' from input lines\n--TYPE-line-format=FORMAT  Display TYPE (unchanged/old/new) lines using FORMAT\n  FORMAT uses printf integer escapes (ala %-2.4x) followed by LETTER: FELMNn\nSupported format specifiers are:\n* %l, the contents of the line, without the trailing newline\n* %L, the contents of the line, including the trailing newline\n* %%, the character '%'"
+#define HELP_diff "usage: diff [-abBdiNqrTstw] [-L LABEL] [-S FILE] [-U LINES] [-F REGEX ] FILE1 FILE2\n\n-a	Treat all files as text\n-b	Ignore changes in the amount of whitespace\n-B	Ignore changes whose lines are all blank\n-d	Try hard to find a smaller set of changes\n-F 	Show the most recent line matching the regex\n-i	Ignore case differences\n-L	Use LABEL instead of the filename in the unified header\n-N	Treat absent files as empty\n-q	Output only whether files differ\n-r	Recurse\n-S	Start with FILE when comparing directories\n-s	Report when two files are the same\n-T	Make tabs line up by prefixing a tab when necessary\n-t	Expand tabs to spaces in output\n-u	Unified diff\n-U	Output LINES lines of context\n-w	Ignore all whitespace\n\n--color     Color output   --strip-trailing-cr   Strip '\\r' from input lines\n--no-dereference Don't follow symbolic links\n--TYPE-line-format=FORMAT  Display TYPE (unchanged/old/new) lines using FORMAT\n  FORMAT uses printf integer escapes (ala %-2.4x) followed by LETTER: FELMNn\nSupported format specifiers are:\n* %l, the contents of the line, without the trailing newline\n* %L, the contents of the line, including the trailing newline\n* %%, the character '%'"
 
 #define HELP_dhcpd "usage: dhcpd [-46fS] [-i IFACE] [-P N] [CONFFILE]\n\n -f    Run in foreground\n -i Interface to use\n -S    Log to syslog too\n -P N  Use port N (default ipv4 67, ipv6 547)\n -4, -6    Run as a DHCPv4 or DHCPv6 server"
 
@@ -516,6 +516,8 @@
 
 #define HELP_bc "usage: bc [-ilqsw] [file ...]\n\nbc is a command-line calculator with a Turing-complete language.\n\noptions:\n\n  -i  --interactive  force interactive mode\n  -l  --mathlib      use predefined math routines:\n\n                     s(expr)  =  sine of expr in radians\n                     c(expr)  =  cosine of expr in radians\n                     a(expr)  =  arctangent of expr, returning radians\n                     l(expr)  =  natural log of expr\n                     e(expr)  =  raises e to the power of expr\n                     j(n, x)  =  Bessel function of integer order n of x\n\n  -q  --quiet        don't print version and copyright\n  -s  --standard     error if any non-POSIX extensions are used\n  -w  --warn         warn if any non-POSIX extensions are used"
 
+#define HELP_awk "usage:  awk [-F sepstring] [-v assignment]... program [argument...]\n  or:\n        awk [-F sepstring] -f progfile [-f progfile]... [-v assignment]...\n              [argument...]\n  also:\n  -b : use bytes, not characters\n  -c : compile only, do not run"
+
 #define HELP_arping "usage: arping [-fqbDUA] [-c CNT] [-w TIMEOUT] [-I IFACE] [-s SRC_IP] DST_IP\n\nSend ARP requests/replies\n\n-f         Quit on first ARP reply\n-q         Quiet\n-b         Keep broadcasting, don't go unicast\n-D         Duplicated address detection mode\n-U         Unsolicited ARP mode, update your neighbors\n-A         ARP answer mode, update your neighbors\n-c N       Stop after sending N ARP requests\n-w TIMEOUT Time to wait for ARP reply, seconds\n-I IFACE   Interface to use (default eth0)\n-s SRC_IP  Sender IP address\nDST_IP     Target IP address"
 
 #define HELP_arp "usage: arp\n[-vn] [-H HWTYPE] [-i IF] -a [HOSTNAME]\n[-v]              [-i IF] -d HOSTNAME [pub]\n[-v]  [-H HWTYPE] [-i IF] -s HOSTNAME HWADDR [temp]\n[-v]  [-H HWTYPE] [-i IF] -s HOSTNAME HWADDR [netmask MASK] pub\n[-v]  [-H HWTYPE] [-i IF] -Ds HOSTNAME IFACE [netmask MASK] pub\n\nManipulate ARP cache.\n\n-a	Display (all) hosts\n-s	Set new ARP entry\n-d	Delete a specified entry\n-v	Verbose\n-n	Don't resolve names\n-i IFACE	Network interface\n-D	Read <hwaddr> from given device\n-A,-p AF	Protocol family\n-H HWTYPE	Hardware address type"
@@ -550,7 +552,7 @@
 
 #define HELP_time "usage: time [-pv] COMMAND...\n\nRun command line and report real, user, and system time elapsed in seconds.\n(real = clock on the wall, user = cpu used by command's code,\nsystem = cpu used by OS on behalf of command.)\n\n-p	POSIX format output\n-v	Verbose"
 
-#define HELP_test "usage: test [-bcdefghkLprSsuwx PATH] [-nz STRING] [-t FD] [X ?? Y]\n\nReturn true or false by performing tests. No arguments is false, one argument\nis true if not empty string.\n\n--- Tests with a single argument (after the option):\nPATH is/has:\n  -b  block device   -f  regular file   -p  fifo           -u  setuid bit\n  -c  char device    -g  setgid         -r  readable       -w  writable\n  -d  directory      -h  symlink        -S  socket         -x  executable\n  -e  exists         -L  symlink        -s  nonzero size   -k  sticky bit\nSTRING is:\n  -n  nonzero size   -z  zero size\nFD (integer file descriptor) is:\n  -t  a TTY\n\n--- Tests with one argument on each side of an operator:\nTwo strings:\n  =  are identical   !=  differ         =~  string matches regex\nAlphabetical sort:\n  <  first is lower  >   first higher\nTwo integers:\n  -eq  equal         -gt  first > second    -lt  first < second\n  -ne  not equal     -ge  first >= second   -le  first <= second\n\n--- Modify or combine tests:\n  ! EXPR     not (swap true/false)   EXPR -a EXPR    and (are both true)\n  ( EXPR )   evaluate this first     EXPR -o EXPR    or (is either true)"
+#define HELP_test "usage: test [-bcdefghkLprSsuwx PATH] [-nz STRING] [-t FD] [X ?? Y]\n\nReturn true or false by performing tests. No arguments is false, one argument\nis true if not empty string.\n\n--- Tests with a single argument (after the option):\nPATH is/has:\n  -b  block device   -f  regular file   -p  fifo           -u  setuid bit\n  -c  char device    -g  setgid         -r  readable       -w  writable\n  -d  directory      -h  symlink        -S  socket         -x  executable\n  -e  exists         -L  symlink        -s  nonzero size   -k  sticky bit\nSTRING is:\n  -n  nonzero size   -z  zero size\nFD (integer file descriptor) is:\n  -t  a TTY\n\n--- Tests with one argument on each side of an operator:\nTwo strings:\n  =  are identical   !=  differ         =~  string matches regex\nAlphabetical sort:\n  <  first is lower  >   first higher\nTwo integers:\n  -eq  equal         -gt  first > second    -lt  first < second\n  -ne  not equal     -ge  first >= second   -le  first <= second\nTwo files:\n  -ot  Older mtime   -nt  Newer mtime       -ef  same dev/inode\n\n--- Modify or combine tests:\n  ! EXPR     not (swap true/false)   EXPR -a EXPR    and (are both true)\n  ( EXPR )   evaluate this first     EXPR -o EXPR    or (is either true)"
 
 #define HELP_tee "usage: tee [-ai] [FILE...]\n\nCopy stdin to each listed file, and also to stdout.\nFilename \"-\" is a synonym for stdout.\n\n-a	Append to files\n-i	Ignore SIGINT"
 
diff --git a/android/linux/generated/newtoys.h b/android/linux/generated/newtoys.h
index 0582c103..c41eb83f 100644
--- a/android/linux/generated/newtoys.h
+++ b/android/linux/generated/newtoys.h
@@ -13,6 +13,7 @@ USE_ARCH(NEWTOY(arch, 0, TOYFLAG_USR|TOYFLAG_BIN))
 USE_ARP(NEWTOY(arp, "vi:nDsdap:A:H:[+Ap][!sd]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_ARPING(NEWTOY(arping, "<1>1s:I:w#<0c#<0AUDbqf[+AU][+Df]", TOYFLAG_USR|TOYFLAG_SBIN))
 USE_ASCII(NEWTOY(ascii, 0, TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
+USE_AWK(NEWTOY(awk, "F:v*f*bc", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_BASE32(NEWTOY(base32, "diw#<0=76[!dw]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_BASE64(NEWTOY(base64, "diw#<0=76[!dw]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_BASENAME(NEWTOY(basename, "^<1as:", TOYFLAG_USR|TOYFLAG_BIN))
@@ -59,20 +60,20 @@ USE_DEMO_MANY_OPTIONS(NEWTOY(demo_many_options, "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwv
 USE_DEMO_NUMBER(NEWTOY(demo_number, "D#=3<3M#<0hcdbs", TOYFLAG_BIN))
 USE_DEMO_SCANKEY(NEWTOY(demo_scankey, 0, TOYFLAG_BIN))
 USE_DEMO_UTF8TOWC(NEWTOY(demo_utf8towc, 0, TOYFLAG_USR|TOYFLAG_BIN))
-USE_DEVMEM(NEWTOY(devmem, "<1>3", TOYFLAG_USR|TOYFLAG_SBIN))
+USE_DEVMEM(NEWTOY(devmem, "<1(no-sync)f:", TOYFLAG_USR|TOYFLAG_SBIN))
 USE_DF(NEWTOY(df, "HPkhit*a[-HPh]", TOYFLAG_BIN))
 USE_DHCP(NEWTOY(dhcp, "V:H:F:x*r:O*A#<0=20T#<0=3t#<0=3s:p:i:SBRCaovqnbf", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
 USE_DHCP6(NEWTOY(dhcp6, "r:A#<0T#<0t#<0s:p:i:SRvqnbf", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
 USE_DHCPD(NEWTOY(dhcpd, ">1P#<0>65535fi:S46[!46]", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
-USE_DIFF(NEWTOY(diff, "<2>2(unchanged-line-format):;(old-line-format):;(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)))
+USE_DIFF(NEWTOY(diff, "<2>2(unchanged-line-format):;(old-line-format):;(no-dereference);(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)))
 USE_DIRNAME(NEWTOY(dirname, "<1", TOYFLAG_USR|TOYFLAG_BIN))
-USE_DMESG(NEWTOY(dmesg, "w(follow)CSTtrs#<1n#c[!Ttr][!Cc][!Sw]", TOYFLAG_BIN))
+USE_DMESG(NEWTOY(dmesg, "w(follow)W(follow-new)CSTtrs#<1n#c[!Ttr][!Cc][!SWw]", TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_DNSDOMAINNAME(NEWTOY(dnsdomainname, ">0", TOYFLAG_BIN))
 USE_DOS2UNIX(NEWTOY(dos2unix, 0, TOYFLAG_BIN))
 USE_DU(NEWTOY(du, "d#<0=-1hmlcaHkKLsxb[-HL][-kKmh]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_DUMPLEASES(NEWTOY(dumpleases, ">0arf:[!ar]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_ECHO(NEWTOY(echo, "^?Een[-eE]", TOYFLAG_BIN|TOYFLAG_MAYFORK|TOYFLAG_LINEBUF))
-USE_EGREP(OLDTOY(egrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF))
+USE_EGREP(OLDTOY(egrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF|TOYFLAG_AUTOCONF))
 USE_EJECT(NEWTOY(eject, ">1stT[!tT]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_ENV(NEWTOY(env, "^e:i0u*", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(125)))
 USE_SH(NEWTOY(eval, 0, TOYFLAG_NOFORK))
@@ -85,7 +86,7 @@ USE_FACTOR(NEWTOY(factor, "?hx", TOYFLAG_USR|TOYFLAG_BIN))
 USE_FALLOCATE(NEWTOY(fallocate, ">1l#|o#", TOYFLAG_USR|TOYFLAG_BIN))
 USE_FALSE(NEWTOY(false, NULL, TOYFLAG_BIN|TOYFLAG_NOHELP|TOYFLAG_MAYFORK))
 USE_FDISK(NEWTOY(fdisk, "C#<0H#<0S#<0b#<512ul", TOYFLAG_SBIN))
-USE_FGREP(OLDTOY(fgrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF))
+USE_FGREP(OLDTOY(fgrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF|TOYFLAG_AUTOCONF))
 USE_FILE(NEWTOY(file, "<1b(brief)hLs[!hL]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_FIND(NEWTOY(find, "?^HL[-HL]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_FLOCK(NEWTOY(flock, "<1>1nsux[-sux]", TOYFLAG_USR|TOYFLAG_BIN))
@@ -114,7 +115,7 @@ USE_GPIOFIND(NEWTOY(gpiofind, "<1>1", TOYFLAG_USR|TOYFLAG_BIN))
 USE_GPIOGET(NEWTOY(gpioget, "<2l", TOYFLAG_USR|TOYFLAG_BIN))
 USE_GPIOINFO(NEWTOY(gpioinfo, 0, TOYFLAG_USR|TOYFLAG_BIN))
 USE_GPIOSET(NEWTOY(gpioset, "<2l", TOYFLAG_USR|TOYFLAG_BIN))
-USE_GREP(NEWTOY(grep, "(line-buffered)(color):;(exclude-dir)*S(exclude)*M(include)*ZzEFHIab(byte-offset)h(no-filename)ino(only-matching)rRsvwc(count)L(files-without-match)l(files-with-matches)q(quiet)(silent)e*f*C#B#A#m#x[!wx][!EF]", TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF))
+USE_GREP(NEWTOY(grep, "(line-buffered)(color):;(exclude-dir)*S(exclude)*M(include)*ZzEFHIab(byte-offset)h(no-filename)ino(only-matching)rRsvwc(count)L(files-without-match)l(files-with-matches)q(quiet)(silent)e*f*C#B#A#m#x[!wx][!EF]", TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF|TOYFLAG_AUTOCONF))
 USE_GROUPADD(NEWTOY(groupadd, "<1>2R:g#<0>2147483647S", TOYFLAG_NEEDROOT|TOYFLAG_SBIN))
 USE_GROUPDEL(NEWTOY(groupdel, "<1>2?", TOYFLAG_NEEDROOT|TOYFLAG_SBIN))
 USE_GROUPS(NEWTOY(groups, NULL, TOYFLAG_USR|TOYFLAG_BIN))
@@ -176,7 +177,7 @@ USE_LS(NEWTOY(ls, "(sort):(color):;(full-time)(show-control-chars)\377(block-siz
 USE_LSATTR(NEWTOY(lsattr, "ldapvR", TOYFLAG_BIN))
 USE_LSMOD(NEWTOY(lsmod, NULL, TOYFLAG_SBIN))
 USE_LSOF(NEWTOY(lsof, "lp*t", TOYFLAG_USR|TOYFLAG_BIN))
-USE_LSPCI(NEWTOY(lspci, "emkn@x@i:", TOYFLAG_USR|TOYFLAG_BIN))
+USE_LSPCI(NEWTOY(lspci, "eDmkn@x@i:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_LSUSB(NEWTOY(lsusb, "i:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MAKEDEVS(NEWTOY(makedevs, "<1>1d:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MAN(NEWTOY(man, "k:M:", TOYFLAG_USR|TOYFLAG_BIN))
@@ -250,7 +251,7 @@ USE_RMMOD(NEWTOY(rmmod, "<1wf", TOYFLAG_SBIN|TOYFLAG_NEEDROOT))
 USE_ROUTE(NEWTOY(route, "?neA:", TOYFLAG_SBIN))
 USE_RTCWAKE(NEWTOY(rtcwake, "(list-modes);(auto)a(device)d:(local)l(mode)m:(seconds)s#(time)t#(utc)u(verbose)v[!alu]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_RUNCON(NEWTOY(runcon, "^<2", TOYFLAG_USR|TOYFLAG_SBIN))
-USE_SED(NEWTOY(sed, "(help)(version)(tarxform)e*f*i:;nErz(null-data)s[+Er]", TOYFLAG_BIN|TOYFLAG_NOHELP))
+USE_SED(NEWTOY(sed, "(help)(version)(tarxform)e*f*i:;nErz(null-data)s[+Er]", TOYFLAG_BIN|TOYFLAG_AUTOCONF))
 USE_SENDEVENT(NEWTOY(sendevent, "<4>4", TOYFLAG_USR|TOYFLAG_SBIN))
 USE_SEQ(NEWTOY(seq, "<1>3?f:s:w[!fw]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_SH(NEWTOY(set, 0, TOYFLAG_NOFORK))
@@ -288,7 +289,7 @@ USE_SYSCTL(NEWTOY(sysctl, "^neNqwpaA[!ap][!aq][!aw][+aA]", TOYFLAG_SBIN))
 USE_SYSLOGD(NEWTOY(syslogd,">0l#<1>8=8R:b#<0>99=1s#<0=200m#<0>71582787=20O:p:f:a:nSKLD", TOYFLAG_SBIN|TOYFLAG_STAYROOT))
 USE_TAC(NEWTOY(tac, NULL, TOYFLAG_USR|TOYFLAG_BIN))
 USE_TAIL(NEWTOY(tail, "?fFs:c(bytes)-n(lines)-[-cn][-fF]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
-USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN))
+USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
 USE_TASKSET(NEWTOY(taskset, "<1^pa", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TCPSVD(NEWTOY(tcpsvd, "^<3c#=30<1b#=20<0C:u:l:hEv", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TEE(NEWTOY(tee, "ia", TOYFLAG_USR|TOYFLAG_BIN))
@@ -330,7 +331,7 @@ USE_UUDECODE(NEWTOY(uudecode, ">1o:", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
 USE_UUENCODE(NEWTOY(uuencode, "<1>2m", TOYFLAG_USR|TOYFLAG_BIN))
 USE_UUIDGEN(NEWTOY(uuidgen, ">0r(random)", TOYFLAG_USR|TOYFLAG_BIN))
 USE_VCONFIG(NEWTOY(vconfig, "<2>4", TOYFLAG_NEEDROOT|TOYFLAG_SBIN))
-USE_VI(NEWTOY(vi, ">1s:", TOYFLAG_USR|TOYFLAG_BIN))
+USE_VI(NEWTOY(vi, ">1s:c:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_VMSTAT(NEWTOY(vmstat, ">2n", TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_W(NEWTOY(w, NULL, TOYFLAG_USR|TOYFLAG_BIN))
 USE_SH(NEWTOY(wait, "n", TOYFLAG_NOFORK))
diff --git a/android/mac/generated/config.h b/android/mac/generated/config.h
index c395991f..e948a22f 100644
--- a/android/mac/generated/config.h
+++ b/android/mac/generated/config.h
@@ -42,6 +42,8 @@
 #define USE_ARP(...)
 #define CFG_ASCII 0
 #define USE_ASCII(...)
+#define CFG_AWK 0
+#define USE_AWK(...)
 #define CFG_BASE32 0
 #define USE_BASE32(...)
 #define CFG_BASE64 0
diff --git a/android/mac/generated/flags.h b/android/mac/generated/flags.h
index b117d9a8..504dd782 100644
--- a/android/mac/generated/flags.h
+++ b/android/mac/generated/flags.h
@@ -70,6 +70,19 @@
 #undef FOR_ascii
 #endif
 
+// awk   F:v*f*bc
+#undef OPTSTR_awk
+#define OPTSTR_awk "F:v*f*bc"
+#ifdef CLEANUP_awk
+#undef CLEANUP_awk
+#undef FOR_awk
+#undef FLAG_c
+#undef FLAG_b
+#undef FLAG_f
+#undef FLAG_v
+#undef FLAG_F
+#endif
+
 // base32   diw#<0=76[!dw]
 #undef OPTSTR_base32
 #define OPTSTR_base32 "diw#<0=76[!dw]"
@@ -628,12 +641,14 @@
 #undef FOR_demo_utf8towc
 #endif
 
-// devmem   <1>3
+// devmem   <1(no-sync)f:
 #undef OPTSTR_devmem
-#define OPTSTR_devmem "<1>3"
+#define OPTSTR_devmem "<1(no-sync)f:"
 #ifdef CLEANUP_devmem
 #undef CLEANUP_devmem
 #undef FOR_devmem
+#undef FLAG_f
+#undef FLAG_no_sync
 #endif
 
 // df   HPkhit*a[-HPh]
@@ -718,9 +733,9 @@
 #undef FLAG_P
 #endif
 
-// diff <2>2(unchanged-line-format):;(old-line-format):;(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3 <2>2(unchanged-line-format):;(old-line-format):;(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3
+// diff <2>2(unchanged-line-format):;(old-line-format):;(no-dereference);(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3 <2>2(unchanged-line-format):;(old-line-format):;(no-dereference);(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3
 #undef OPTSTR_diff
-#define OPTSTR_diff "<2>2(unchanged-line-format):;(old-line-format):;(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3"
+#define OPTSTR_diff "<2>2(unchanged-line-format):;(old-line-format):;(no-dereference);(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3"
 #ifdef CLEANUP_diff
 #undef CLEANUP_diff
 #undef FOR_diff
@@ -744,6 +759,7 @@
 #undef FLAG_strip_trailing_cr
 #undef FLAG_color
 #undef FLAG_new_line_format
+#undef FLAG_no_dereference
 #undef FLAG_old_line_format
 #undef FLAG_unchanged_line_format
 #endif
@@ -756,9 +772,9 @@
 #undef FOR_dirname
 #endif
 
-// dmesg   w(follow)CSTtrs#<1n#c[!Ttr][!Cc][!Sw]
+// dmesg   w(follow)W(follow-new)CSTtrs#<1n#c[!Ttr][!Cc][!SWw]
 #undef OPTSTR_dmesg
-#define OPTSTR_dmesg "w(follow)CSTtrs#<1n#c[!Ttr][!Cc][!Sw]"
+#define OPTSTR_dmesg "w(follow)W(follow-new)CSTtrs#<1n#c[!Ttr][!Cc][!SWw]"
 #ifdef CLEANUP_dmesg
 #undef CLEANUP_dmesg
 #undef FOR_dmesg
@@ -770,6 +786,7 @@
 #undef FLAG_T
 #undef FLAG_S
 #undef FLAG_C
+#undef FLAG_W
 #undef FLAG_w
 #endif
 
@@ -1941,9 +1958,9 @@
 #undef FLAG_l
 #endif
 
-// lspci   emkn@x@i:
+// lspci   eDmkn@x@i:
 #undef OPTSTR_lspci
-#define OPTSTR_lspci "emkn@x@i:"
+#define OPTSTR_lspci "eDmkn@x@i:"
 #ifdef CLEANUP_lspci
 #undef CLEANUP_lspci
 #undef FOR_lspci
@@ -1952,6 +1969,7 @@
 #undef FLAG_n
 #undef FLAG_k
 #undef FLAG_m
+#undef FLAG_D
 #undef FLAG_e
 #endif
 
@@ -3760,12 +3778,13 @@
 #undef FOR_vconfig
 #endif
 
-// vi   >1s:
+// vi   >1s:c:
 #undef OPTSTR_vi
-#define OPTSTR_vi ">1s:"
+#define OPTSTR_vi ">1s:c:"
 #ifdef CLEANUP_vi
 #undef CLEANUP_vi
 #undef FOR_vi
+#undef FLAG_c
 #undef FLAG_s
 #endif
 
@@ -3994,6 +4013,18 @@
 #endif
 #endif
 
+#ifdef FOR_awk
+#define CLEANUP_awk
+#ifndef TT
+#define TT this.awk
+#endif
+#define FLAG_c (FORCED_FLAG<<0)
+#define FLAG_b (FORCED_FLAG<<1)
+#define FLAG_f (FORCED_FLAG<<2)
+#define FLAG_v (FORCED_FLAG<<3)
+#define FLAG_F (FORCED_FLAG<<4)
+#endif
+
 #ifdef FOR_base32
 #define CLEANUP_base32
 #ifndef TT
@@ -4515,6 +4546,8 @@
 #ifndef TT
 #define TT this.devmem
 #endif
+#define FLAG_f (FORCED_FLAG<<0)
+#define FLAG_no_sync (FORCED_FLAG<<1)
 #endif
 
 #ifdef FOR_df
@@ -4620,8 +4653,9 @@
 #define FLAG_strip_trailing_cr (1LL<<17)
 #define FLAG_color (1LL<<18)
 #define FLAG_new_line_format (1LL<<19)
-#define FLAG_old_line_format (1LL<<20)
-#define FLAG_unchanged_line_format (1LL<<21)
+#define FLAG_no_dereference (1LL<<20)
+#define FLAG_old_line_format (1LL<<21)
+#define FLAG_unchanged_line_format (1LL<<22)
 #endif
 
 #ifdef FOR_dirname
@@ -4644,7 +4678,8 @@
 #define FLAG_T (FORCED_FLAG<<5)
 #define FLAG_S (FORCED_FLAG<<6)
 #define FLAG_C (FORCED_FLAG<<7)
-#define FLAG_w (FORCED_FLAG<<8)
+#define FLAG_W (FORCED_FLAG<<8)
+#define FLAG_w (FORCED_FLAG<<9)
 #endif
 
 #ifdef FOR_dnsdomainname
@@ -5726,7 +5761,8 @@
 #define FLAG_n (FORCED_FLAG<<2)
 #define FLAG_k (FORCED_FLAG<<3)
 #define FLAG_m (FORCED_FLAG<<4)
-#define FLAG_e (FORCED_FLAG<<5)
+#define FLAG_D (FORCED_FLAG<<5)
+#define FLAG_e (FORCED_FLAG<<6)
 #endif
 
 #ifdef FOR_lsusb
@@ -7399,7 +7435,8 @@
 #ifndef TT
 #define TT this.vi
 #endif
-#define FLAG_s (FORCED_FLAG<<0)
+#define FLAG_c (FORCED_FLAG<<0)
+#define FLAG_s (FORCED_FLAG<<1)
 #endif
 
 #ifdef FOR_vmstat
diff --git a/android/mac/generated/globals.h b/android/mac/generated/globals.h
index a4172c13..c71fa5c7 100644
--- a/android/mac/generated/globals.h
+++ b/android/mac/generated/globals.h
@@ -79,7 +79,7 @@ struct diff_data {
   struct arg_list *L;
   char *F, *S, *new_line_format, *old_line_format, *unchanged_line_format;
 
-  int dir_num, size, is_binary, differ, change, len[2], *offset[2];
+  int dir_num, size, is_binary, is_symlink, differ, change, len[2], *offset[2];
   struct stat st[2];
   struct {
     char **list;
@@ -89,6 +89,10 @@ struct diff_data {
     FILE *fp;
     int len;
   } file[2];
+  struct {
+    char *name;
+    int len;
+  } link[2];
 };
 
 struct expr_data {
@@ -324,7 +328,7 @@ struct tar_data {
   // Parsed information about a tar header.
   struct tar_header {
     char *name, *link_target, *uname, *gname;
-    long long size, ssize;
+    long long size, ssize, oldsparse;
     uid_t uid;
     gid_t gid;
     mode_t mode;
diff --git a/android/mac/generated/help.h b/android/mac/generated/help.h
index c701383a..f25a0785 100644
--- a/android/mac/generated/help.h
+++ b/android/mac/generated/help.h
@@ -110,7 +110,7 @@
 
 #define HELP_gzip "usage: gzip [-19cdfkt] [FILE...]\n\nCompress files. With no files, compresses stdin to stdout.\nOn success, the input files are removed and replaced by new\nfiles with the .gz suffix.\n\n-c	Output to stdout\n-d	Decompress (act as gunzip)\n-f	Force: allow overwrite of output file\n-k	Keep input files (default is to remove)\n-t	Test integrity\n-#	Compression level 1-9 (1:fastest, 6:default, 9:best)"
 
-#define HELP_dmesg "usage: dmesg [-Cc] [-r|-t|-T] [-n LEVEL] [-s SIZE] [-w]\n\nPrint or control the kernel ring buffer.\n\n-C	Clear ring buffer without printing\n-c	Clear ring buffer after printing\n-n	Set kernel logging LEVEL (1-8)\n-r	Raw output (with <level markers>)\n-S	Use syslog(2) rather than /dev/kmsg\n-s	Show the last SIZE many bytes\n-T	Human readable timestamps\n-t	Don't print timestamps\n-w	Keep waiting for more output (aka --follow)"
+#define HELP_dmesg "usage: dmesg [-Cc] [-r|-t|-T] [-n LEVEL] [-s SIZE] [-w|-W]\n\nPrint or control the kernel ring buffer.\n\n-C	Clear ring buffer without printing\n-c	Clear ring buffer after printing\n-n	Set kernel logging LEVEL (1-8)\n-r	Raw output (with <level markers>)\n-S	Use syslog(2) rather than /dev/kmsg\n-s	Show the last SIZE many bytes\n-T	Human readable timestamps\n-t	Don't print timestamps\n-w	Keep waiting for more output (aka --follow)\n-W	Wait for output, only printing new messages"
 
 #define HELP_wget_libtls "Enable HTTPS support for wget by linking to LibTLS.\nSupports using libtls, libretls or libtls-bearssl.\n\nUse TOYBOX_LIBCRYPTO to enable HTTPS support via OpenSSL."
 
@@ -126,7 +126,7 @@
 
 #define HELP_netstat "usage: netstat [-pWrxwutneal]\n\nDisplay networking information. Default is netstat -tuwx\n\n-r	Routing table\n-a	All sockets (not just connected)\n-l	Listening server sockets\n-t	TCP sockets\n-u	UDP sockets\n-w	Raw sockets\n-x	Unix sockets\n-e	Extended info\n-n	Don't resolve names\n-W	Wide display\n-p	Show PID/program name of sockets"
 
-#define HELP_netcat "usage: netcat [-46ELlntUu] [-pqWw #] [-s addr] [-o FILE] {IPADDR PORTNUM|-f FILENAME|COMMAND...}\n\nForward stdin/stdout to a file or network connection.\n\n-4	Force IPv4\n-6	Force IPv6\n-E	Forward stderr\n-f	Use FILENAME (ala /dev/ttyS0) instead of network\n-L	Listen and background each incoming connection (server mode)\n-l	Listen for one incoming connection, then exit\n-n	No DNS lookup\n-o	Hex dump to FILE (-o- writes hex only to stdout)\n-O	Hex dump to FILE (collated)\n-p	Local port number\n-q	Quit SECONDS after EOF on stdin, even if stdout hasn't closed yet\n-s	Local source address\n-t	Allocate tty\n-u	Use UDP\n-U	Use a UNIX domain socket\n-W	SECONDS timeout for more data on an idle connection\n-w	SECONDS timeout to establish connection\n-z	zero-I/O mode [used for scanning]\n\nWhen listening the COMMAND line is executed as a child process to handle\nan incoming connection. With no COMMAND -l forwards the connection\nto stdin/stdout. If no -p specified, -l prints the port it bound to and\nbackgrounds itself (returning immediately).\n\nFor a quick-and-dirty server, try something like:\nnetcat -s 127.0.0.1 -p 1234 -tL sh -l\n\nOr use \"stty 115200 -F /dev/ttyS0 && stty raw -echo -ctlecho\" with\nnetcat -f to connect to a serial port."
+#define HELP_netcat "usage: netcat [-46ELlntUu] [-pqWw #] [-s addr] [-o FILE] {IPADDR PORTNUM|-f FILENAME|COMMAND...}\n\nForward stdin/stdout to a file or network connection.\n\n-4	Force IPv4\n-6	Force IPv6\n-E	Forward stderr\n-f	Use FILENAME (ala /dev/ttyS0) instead of network\n-L	Listen and background each incoming connection (server mode)\n-l	Listen for one incoming connection, then exit\n-n	No DNS lookup\n-o	Hex dump to FILE (show packets, -o- writes hex only to stdout)\n-O	Hex dump to FILE (streaming mode)\n-p	Local port number\n-q	Quit SECONDS after EOF on stdin, even if stdout hasn't closed yet\n-s	Local source address\n-t	Allocate tty\n-u	Use UDP\n-U	Use a UNIX domain socket\n-W	SECONDS timeout for more data on an idle connection\n-w	SECONDS timeout to establish connection\n-z	zero-I/O mode [used for scanning]\n\nWhen listening the COMMAND line is executed as a child process to handle\nan incoming connection. With no COMMAND -l forwards the connection\nto stdin/stdout. If no -p specified, -l prints the port it bound to and\nbackgrounds itself (returning immediately).\n\nFor a quick-and-dirty server, try something like:\nnetcat -s 127.0.0.1 -p 1234 -tL sh -l\n\nOr use \"stty 115200 -F /dev/ttyS0 && stty raw -echo -ctlecho\" with\nnetcat -f to connect to a serial port."
 
 #define HELP_microcom "usage: microcom [-s SPEED] [-X] DEVICE\n\nSimple serial console. Hit CTRL-] for menu.\n\n-s	Set baud rate to SPEED\n-X	Ignore ^] menu escape"
 
@@ -260,7 +260,7 @@
 
 #define HELP_lsusb "usage: lsusb [-i]\n\nList USB hosts/devices.\n\n-i	ID database (default /etc/usb.ids[.gz])"
 
-#define HELP_lspci "usage: lspci [-ekmn] [-i FILE]\n\nList PCI devices.\n\n-e	Extended (6 digit) class\n-i	ID database (default /etc/pci.ids[.gz])\n-k	Show kernel driver\n-m	Machine readable\n-n	Numeric output (-nn for both)\n-x	Hex dump of config space (64 bytes; -xxx for 256, -xxxx for 4096)"
+#define HELP_lspci "usage: lspci [-ekmn] [-i FILE]\n\nList PCI devices.\n\n-e	Extended (6 digit) class\n-i	ID database (default /etc/pci.ids[.gz])\n-k	Show kernel driver\n-m	Machine readable\n-n	Numeric output (-nn for both)\n-D	Print domain numbers\n-x	Hex dump of config space (64 bytes; -xxx for 256, -xxxx for 4096)"
 
 #define HELP_lsmod "usage: lsmod\n\nDisplay the currently loaded modules, their sizes and their dependencies."
 
@@ -332,7 +332,7 @@
 
 #define HELP_dos2unix "usage: dos2unix [FILE...]\n\nConvert newline format from dos \"\\r\\n\" to unix \"\\n\".\nIf no files listed copy from stdin, \"-\" is a synonym for stdin."
 
-#define HELP_devmem "usage: devmem ADDR [WIDTH [DATA]]\n\nRead/write physical address. WIDTH is 1, 2, 4, or 8 bytes (default 4).\nPrefix ADDR with 0x for hexadecimal, output is in same base as address."
+#define HELP_devmem "usage: devmem [-f FILE] ADDR [WIDTH [DATA...]]\n\nRead/write physical addresses. WIDTH is 1, 2, 4, or 8 bytes (default 4).\nPrefix ADDR with 0x for hexadecimal, output is in same base as address.\n\n-f FILE		File to operate on (default /dev/mem)\n--no-sync	Don't open the file with O_SYNC (for cached access)"
 
 #define HELP_count "usage: count [-l]\n\n-l	Long output (total bytes, human readable, transfer rate, elapsed time)\n\nCopy stdin to stdout, displaying simple progress indicator to stderr."
 
@@ -368,7 +368,7 @@
 
 #define HELP_xzcat "usage: xzcat [FILE...]\n\nDecompress listed files to stdout. Use stdin if no files listed."
 
-#define HELP_vi "usage: vi [-s SCRIPT] FILE\n\nVisual text editor. Predates keyboards with standardized cursor keys.\nIf you don't know how to use it, hit the ESC key, type :q! and press ENTER.\n\n-s	run SCRIPT of commands on FILE\n\nvi mode commands:\n\n  [count][cmd][motion]\n  cmd: c d y\n  motion: 0 b e G H h j k L l M w $ f F\n\n  [count][cmd]\n  cmd: D I J O n o p x dd yy\n\n  [cmd]\n  cmd: / ? : A a i CTRL_D CTRL_B CTRL_E CTRL_F CTRL_Y \\e \\b\n\nex mode commands:\n\n  [cmd]\n  \\b \\e \\n w wq q! 'set list' 'set nolist' d $ % g v"
+#define HELP_vi "usage: vi [-s SCRIPT] FILE\n\nVisual text editor. Predates keyboards with standardized cursor keys.\nIf you don't know how to use it, hit the ESC key, type :q! and press ENTER.\n\n-s	run SCRIPT as if typed at keyboard (like -c \"source SCRIPT\")\n-c	run SCRIPT of ex commands\n\nThe editor is usually in one of three modes:\n\n  Hit ESC for \"vi mode\" where each key is a command.\n  Hit : for \"ex mode\" which runs command lines typed at bottom of screen.\n  Hit i (from vi mode) for \"insert mode\" where typing adds to the file.\n\nex mode commands (ESC to exit ex mode):\n\n  q   Quit (exit editor if no unsaved changes)\n  q!  Quit discarding unsaved changes\n  w   Write changed contents to file (optionally to NAME argument)\n  wq  Write to file, then quit\n\nvi mode single key commands:\n  i  switch to insert mode (until next ESC)\n  u  undo last change (can be repeated)\n  a  append (move one character right, switch to insert mode)\n  A  append (jump to end of line, switch to insert mode)\n\nvi mode commands that prompt for more data on bottom line:\n  :  switch to ex mode\n  /  search forwards for regex\n  ?  search backwards for regex\n  .  repeat last command\n\n  [count][cmd][motion]\n  cmd: c d y\n  motion: 0 b e G H h j k L l M w $ f F\n\n  [count][cmd]\n  cmd: D I J O n o p x dd yy\n\n  [cmd]\n  cmd: / ? : A a i CTRL_D CTRL_B CTRL_E CTRL_F CTRL_Y \\e \\b\n\n  [cmd]\n  \\b \\e \\n 'set list' 'set nolist' d $ % g v"
 
 #define HELP_userdel "usage: userdel [-r] USER\nusage: deluser [-r] USER\n\nDelete USER from the SYSTEM\n\n-r	remove home directory"
 
@@ -494,7 +494,7 @@
 
 #define HELP_dumpleases "usage: dumpleases [-r|-a] [-f LEASEFILE]\n\nDisplay DHCP leases granted by udhcpd\n-f FILE,  Lease file\n-r        Show remaining time\n-a        Show expiration time"
 
-#define HELP_diff "usage: diff [-abBdiNqrTstw] [-L LABEL] [-S FILE] [-U LINES] [-F REGEX ] FILE1 FILE2\n\n-a	Treat all files as text\n-b	Ignore changes in the amount of whitespace\n-B	Ignore changes whose lines are all blank\n-d	Try hard to find a smaller set of changes\n-F 	Show the most recent line matching the regex\n-i	Ignore case differences\n-L	Use LABEL instead of the filename in the unified header\n-N	Treat absent files as empty\n-q	Output only whether files differ\n-r	Recurse\n-S	Start with FILE when comparing directories\n-s	Report when two files are the same\n-T	Make tabs line up by prefixing a tab when necessary\n-t	Expand tabs to spaces in output\n-u	Unified diff\n-U	Output LINES lines of context\n-w	Ignore all whitespace\n\n--color     Color output   --strip-trailing-cr   Strip '\\r' from input lines\n--TYPE-line-format=FORMAT  Display TYPE (unchanged/old/new) lines using FORMAT\n  FORMAT uses printf integer escapes (ala %-2.4x) followed by LETTER: FELMNn\nSupported format specifiers are:\n* %l, the contents of the line, without the trailing newline\n* %L, the contents of the line, including the trailing newline\n* %%, the character '%'"
+#define HELP_diff "usage: diff [-abBdiNqrTstw] [-L LABEL] [-S FILE] [-U LINES] [-F REGEX ] FILE1 FILE2\n\n-a	Treat all files as text\n-b	Ignore changes in the amount of whitespace\n-B	Ignore changes whose lines are all blank\n-d	Try hard to find a smaller set of changes\n-F 	Show the most recent line matching the regex\n-i	Ignore case differences\n-L	Use LABEL instead of the filename in the unified header\n-N	Treat absent files as empty\n-q	Output only whether files differ\n-r	Recurse\n-S	Start with FILE when comparing directories\n-s	Report when two files are the same\n-T	Make tabs line up by prefixing a tab when necessary\n-t	Expand tabs to spaces in output\n-u	Unified diff\n-U	Output LINES lines of context\n-w	Ignore all whitespace\n\n--color     Color output   --strip-trailing-cr   Strip '\\r' from input lines\n--no-dereference Don't follow symbolic links\n--TYPE-line-format=FORMAT  Display TYPE (unchanged/old/new) lines using FORMAT\n  FORMAT uses printf integer escapes (ala %-2.4x) followed by LETTER: FELMNn\nSupported format specifiers are:\n* %l, the contents of the line, without the trailing newline\n* %L, the contents of the line, including the trailing newline\n* %%, the character '%'"
 
 #define HELP_dhcpd "usage: dhcpd [-46fS] [-i IFACE] [-P N] [CONFFILE]\n\n -f    Run in foreground\n -i Interface to use\n -S    Log to syslog too\n -P N  Use port N (default ipv4 67, ipv6 547)\n -4, -6    Run as a DHCPv4 or DHCPv6 server"
 
@@ -516,6 +516,8 @@
 
 #define HELP_bc "usage: bc [-ilqsw] [file ...]\n\nbc is a command-line calculator with a Turing-complete language.\n\noptions:\n\n  -i  --interactive  force interactive mode\n  -l  --mathlib      use predefined math routines:\n\n                     s(expr)  =  sine of expr in radians\n                     c(expr)  =  cosine of expr in radians\n                     a(expr)  =  arctangent of expr, returning radians\n                     l(expr)  =  natural log of expr\n                     e(expr)  =  raises e to the power of expr\n                     j(n, x)  =  Bessel function of integer order n of x\n\n  -q  --quiet        don't print version and copyright\n  -s  --standard     error if any non-POSIX extensions are used\n  -w  --warn         warn if any non-POSIX extensions are used"
 
+#define HELP_awk "usage:  awk [-F sepstring] [-v assignment]... program [argument...]\n  or:\n        awk [-F sepstring] -f progfile [-f progfile]... [-v assignment]...\n              [argument...]\n  also:\n  -b : use bytes, not characters\n  -c : compile only, do not run"
+
 #define HELP_arping "usage: arping [-fqbDUA] [-c CNT] [-w TIMEOUT] [-I IFACE] [-s SRC_IP] DST_IP\n\nSend ARP requests/replies\n\n-f         Quit on first ARP reply\n-q         Quiet\n-b         Keep broadcasting, don't go unicast\n-D         Duplicated address detection mode\n-U         Unsolicited ARP mode, update your neighbors\n-A         ARP answer mode, update your neighbors\n-c N       Stop after sending N ARP requests\n-w TIMEOUT Time to wait for ARP reply, seconds\n-I IFACE   Interface to use (default eth0)\n-s SRC_IP  Sender IP address\nDST_IP     Target IP address"
 
 #define HELP_arp "usage: arp\n[-vn] [-H HWTYPE] [-i IF] -a [HOSTNAME]\n[-v]              [-i IF] -d HOSTNAME [pub]\n[-v]  [-H HWTYPE] [-i IF] -s HOSTNAME HWADDR [temp]\n[-v]  [-H HWTYPE] [-i IF] -s HOSTNAME HWADDR [netmask MASK] pub\n[-v]  [-H HWTYPE] [-i IF] -Ds HOSTNAME IFACE [netmask MASK] pub\n\nManipulate ARP cache.\n\n-a	Display (all) hosts\n-s	Set new ARP entry\n-d	Delete a specified entry\n-v	Verbose\n-n	Don't resolve names\n-i IFACE	Network interface\n-D	Read <hwaddr> from given device\n-A,-p AF	Protocol family\n-H HWTYPE	Hardware address type"
@@ -550,7 +552,7 @@
 
 #define HELP_time "usage: time [-pv] COMMAND...\n\nRun command line and report real, user, and system time elapsed in seconds.\n(real = clock on the wall, user = cpu used by command's code,\nsystem = cpu used by OS on behalf of command.)\n\n-p	POSIX format output\n-v	Verbose"
 
-#define HELP_test "usage: test [-bcdefghkLprSsuwx PATH] [-nz STRING] [-t FD] [X ?? Y]\n\nReturn true or false by performing tests. No arguments is false, one argument\nis true if not empty string.\n\n--- Tests with a single argument (after the option):\nPATH is/has:\n  -b  block device   -f  regular file   -p  fifo           -u  setuid bit\n  -c  char device    -g  setgid         -r  readable       -w  writable\n  -d  directory      -h  symlink        -S  socket         -x  executable\n  -e  exists         -L  symlink        -s  nonzero size   -k  sticky bit\nSTRING is:\n  -n  nonzero size   -z  zero size\nFD (integer file descriptor) is:\n  -t  a TTY\n\n--- Tests with one argument on each side of an operator:\nTwo strings:\n  =  are identical   !=  differ         =~  string matches regex\nAlphabetical sort:\n  <  first is lower  >   first higher\nTwo integers:\n  -eq  equal         -gt  first > second    -lt  first < second\n  -ne  not equal     -ge  first >= second   -le  first <= second\n\n--- Modify or combine tests:\n  ! EXPR     not (swap true/false)   EXPR -a EXPR    and (are both true)\n  ( EXPR )   evaluate this first     EXPR -o EXPR    or (is either true)"
+#define HELP_test "usage: test [-bcdefghkLprSsuwx PATH] [-nz STRING] [-t FD] [X ?? Y]\n\nReturn true or false by performing tests. No arguments is false, one argument\nis true if not empty string.\n\n--- Tests with a single argument (after the option):\nPATH is/has:\n  -b  block device   -f  regular file   -p  fifo           -u  setuid bit\n  -c  char device    -g  setgid         -r  readable       -w  writable\n  -d  directory      -h  symlink        -S  socket         -x  executable\n  -e  exists         -L  symlink        -s  nonzero size   -k  sticky bit\nSTRING is:\n  -n  nonzero size   -z  zero size\nFD (integer file descriptor) is:\n  -t  a TTY\n\n--- Tests with one argument on each side of an operator:\nTwo strings:\n  =  are identical   !=  differ         =~  string matches regex\nAlphabetical sort:\n  <  first is lower  >   first higher\nTwo integers:\n  -eq  equal         -gt  first > second    -lt  first < second\n  -ne  not equal     -ge  first >= second   -le  first <= second\nTwo files:\n  -ot  Older mtime   -nt  Newer mtime       -ef  same dev/inode\n\n--- Modify or combine tests:\n  ! EXPR     not (swap true/false)   EXPR -a EXPR    and (are both true)\n  ( EXPR )   evaluate this first     EXPR -o EXPR    or (is either true)"
 
 #define HELP_tee "usage: tee [-ai] [FILE...]\n\nCopy stdin to each listed file, and also to stdout.\nFilename \"-\" is a synonym for stdout.\n\n-a	Append to files\n-i	Ignore SIGINT"
 
diff --git a/android/mac/generated/newtoys.h b/android/mac/generated/newtoys.h
index 0582c103..c41eb83f 100644
--- a/android/mac/generated/newtoys.h
+++ b/android/mac/generated/newtoys.h
@@ -13,6 +13,7 @@ USE_ARCH(NEWTOY(arch, 0, TOYFLAG_USR|TOYFLAG_BIN))
 USE_ARP(NEWTOY(arp, "vi:nDsdap:A:H:[+Ap][!sd]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_ARPING(NEWTOY(arping, "<1>1s:I:w#<0c#<0AUDbqf[+AU][+Df]", TOYFLAG_USR|TOYFLAG_SBIN))
 USE_ASCII(NEWTOY(ascii, 0, TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
+USE_AWK(NEWTOY(awk, "F:v*f*bc", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_BASE32(NEWTOY(base32, "diw#<0=76[!dw]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_BASE64(NEWTOY(base64, "diw#<0=76[!dw]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_BASENAME(NEWTOY(basename, "^<1as:", TOYFLAG_USR|TOYFLAG_BIN))
@@ -59,20 +60,20 @@ USE_DEMO_MANY_OPTIONS(NEWTOY(demo_many_options, "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwv
 USE_DEMO_NUMBER(NEWTOY(demo_number, "D#=3<3M#<0hcdbs", TOYFLAG_BIN))
 USE_DEMO_SCANKEY(NEWTOY(demo_scankey, 0, TOYFLAG_BIN))
 USE_DEMO_UTF8TOWC(NEWTOY(demo_utf8towc, 0, TOYFLAG_USR|TOYFLAG_BIN))
-USE_DEVMEM(NEWTOY(devmem, "<1>3", TOYFLAG_USR|TOYFLAG_SBIN))
+USE_DEVMEM(NEWTOY(devmem, "<1(no-sync)f:", TOYFLAG_USR|TOYFLAG_SBIN))
 USE_DF(NEWTOY(df, "HPkhit*a[-HPh]", TOYFLAG_BIN))
 USE_DHCP(NEWTOY(dhcp, "V:H:F:x*r:O*A#<0=20T#<0=3t#<0=3s:p:i:SBRCaovqnbf", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
 USE_DHCP6(NEWTOY(dhcp6, "r:A#<0T#<0t#<0s:p:i:SRvqnbf", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
 USE_DHCPD(NEWTOY(dhcpd, ">1P#<0>65535fi:S46[!46]", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
-USE_DIFF(NEWTOY(diff, "<2>2(unchanged-line-format):;(old-line-format):;(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)))
+USE_DIFF(NEWTOY(diff, "<2>2(unchanged-line-format):;(old-line-format):;(no-dereference);(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)))
 USE_DIRNAME(NEWTOY(dirname, "<1", TOYFLAG_USR|TOYFLAG_BIN))
-USE_DMESG(NEWTOY(dmesg, "w(follow)CSTtrs#<1n#c[!Ttr][!Cc][!Sw]", TOYFLAG_BIN))
+USE_DMESG(NEWTOY(dmesg, "w(follow)W(follow-new)CSTtrs#<1n#c[!Ttr][!Cc][!SWw]", TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_DNSDOMAINNAME(NEWTOY(dnsdomainname, ">0", TOYFLAG_BIN))
 USE_DOS2UNIX(NEWTOY(dos2unix, 0, TOYFLAG_BIN))
 USE_DU(NEWTOY(du, "d#<0=-1hmlcaHkKLsxb[-HL][-kKmh]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_DUMPLEASES(NEWTOY(dumpleases, ">0arf:[!ar]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_ECHO(NEWTOY(echo, "^?Een[-eE]", TOYFLAG_BIN|TOYFLAG_MAYFORK|TOYFLAG_LINEBUF))
-USE_EGREP(OLDTOY(egrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF))
+USE_EGREP(OLDTOY(egrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF|TOYFLAG_AUTOCONF))
 USE_EJECT(NEWTOY(eject, ">1stT[!tT]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_ENV(NEWTOY(env, "^e:i0u*", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(125)))
 USE_SH(NEWTOY(eval, 0, TOYFLAG_NOFORK))
@@ -85,7 +86,7 @@ USE_FACTOR(NEWTOY(factor, "?hx", TOYFLAG_USR|TOYFLAG_BIN))
 USE_FALLOCATE(NEWTOY(fallocate, ">1l#|o#", TOYFLAG_USR|TOYFLAG_BIN))
 USE_FALSE(NEWTOY(false, NULL, TOYFLAG_BIN|TOYFLAG_NOHELP|TOYFLAG_MAYFORK))
 USE_FDISK(NEWTOY(fdisk, "C#<0H#<0S#<0b#<512ul", TOYFLAG_SBIN))
-USE_FGREP(OLDTOY(fgrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF))
+USE_FGREP(OLDTOY(fgrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF|TOYFLAG_AUTOCONF))
 USE_FILE(NEWTOY(file, "<1b(brief)hLs[!hL]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_FIND(NEWTOY(find, "?^HL[-HL]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_FLOCK(NEWTOY(flock, "<1>1nsux[-sux]", TOYFLAG_USR|TOYFLAG_BIN))
@@ -114,7 +115,7 @@ USE_GPIOFIND(NEWTOY(gpiofind, "<1>1", TOYFLAG_USR|TOYFLAG_BIN))
 USE_GPIOGET(NEWTOY(gpioget, "<2l", TOYFLAG_USR|TOYFLAG_BIN))
 USE_GPIOINFO(NEWTOY(gpioinfo, 0, TOYFLAG_USR|TOYFLAG_BIN))
 USE_GPIOSET(NEWTOY(gpioset, "<2l", TOYFLAG_USR|TOYFLAG_BIN))
-USE_GREP(NEWTOY(grep, "(line-buffered)(color):;(exclude-dir)*S(exclude)*M(include)*ZzEFHIab(byte-offset)h(no-filename)ino(only-matching)rRsvwc(count)L(files-without-match)l(files-with-matches)q(quiet)(silent)e*f*C#B#A#m#x[!wx][!EF]", TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF))
+USE_GREP(NEWTOY(grep, "(line-buffered)(color):;(exclude-dir)*S(exclude)*M(include)*ZzEFHIab(byte-offset)h(no-filename)ino(only-matching)rRsvwc(count)L(files-without-match)l(files-with-matches)q(quiet)(silent)e*f*C#B#A#m#x[!wx][!EF]", TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF|TOYFLAG_AUTOCONF))
 USE_GROUPADD(NEWTOY(groupadd, "<1>2R:g#<0>2147483647S", TOYFLAG_NEEDROOT|TOYFLAG_SBIN))
 USE_GROUPDEL(NEWTOY(groupdel, "<1>2?", TOYFLAG_NEEDROOT|TOYFLAG_SBIN))
 USE_GROUPS(NEWTOY(groups, NULL, TOYFLAG_USR|TOYFLAG_BIN))
@@ -176,7 +177,7 @@ USE_LS(NEWTOY(ls, "(sort):(color):;(full-time)(show-control-chars)\377(block-siz
 USE_LSATTR(NEWTOY(lsattr, "ldapvR", TOYFLAG_BIN))
 USE_LSMOD(NEWTOY(lsmod, NULL, TOYFLAG_SBIN))
 USE_LSOF(NEWTOY(lsof, "lp*t", TOYFLAG_USR|TOYFLAG_BIN))
-USE_LSPCI(NEWTOY(lspci, "emkn@x@i:", TOYFLAG_USR|TOYFLAG_BIN))
+USE_LSPCI(NEWTOY(lspci, "eDmkn@x@i:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_LSUSB(NEWTOY(lsusb, "i:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MAKEDEVS(NEWTOY(makedevs, "<1>1d:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MAN(NEWTOY(man, "k:M:", TOYFLAG_USR|TOYFLAG_BIN))
@@ -250,7 +251,7 @@ USE_RMMOD(NEWTOY(rmmod, "<1wf", TOYFLAG_SBIN|TOYFLAG_NEEDROOT))
 USE_ROUTE(NEWTOY(route, "?neA:", TOYFLAG_SBIN))
 USE_RTCWAKE(NEWTOY(rtcwake, "(list-modes);(auto)a(device)d:(local)l(mode)m:(seconds)s#(time)t#(utc)u(verbose)v[!alu]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_RUNCON(NEWTOY(runcon, "^<2", TOYFLAG_USR|TOYFLAG_SBIN))
-USE_SED(NEWTOY(sed, "(help)(version)(tarxform)e*f*i:;nErz(null-data)s[+Er]", TOYFLAG_BIN|TOYFLAG_NOHELP))
+USE_SED(NEWTOY(sed, "(help)(version)(tarxform)e*f*i:;nErz(null-data)s[+Er]", TOYFLAG_BIN|TOYFLAG_AUTOCONF))
 USE_SENDEVENT(NEWTOY(sendevent, "<4>4", TOYFLAG_USR|TOYFLAG_SBIN))
 USE_SEQ(NEWTOY(seq, "<1>3?f:s:w[!fw]", TOYFLAG_USR|TOYFLAG_BIN))
 USE_SH(NEWTOY(set, 0, TOYFLAG_NOFORK))
@@ -288,7 +289,7 @@ USE_SYSCTL(NEWTOY(sysctl, "^neNqwpaA[!ap][!aq][!aw][+aA]", TOYFLAG_SBIN))
 USE_SYSLOGD(NEWTOY(syslogd,">0l#<1>8=8R:b#<0>99=1s#<0=200m#<0>71582787=20O:p:f:a:nSKLD", TOYFLAG_SBIN|TOYFLAG_STAYROOT))
 USE_TAC(NEWTOY(tac, NULL, TOYFLAG_USR|TOYFLAG_BIN))
 USE_TAIL(NEWTOY(tail, "?fFs:c(bytes)-n(lines)-[-cn][-fF]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
-USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN))
+USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
 USE_TASKSET(NEWTOY(taskset, "<1^pa", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TCPSVD(NEWTOY(tcpsvd, "^<3c#=30<1b#=20<0C:u:l:hEv", TOYFLAG_USR|TOYFLAG_BIN))
 USE_TEE(NEWTOY(tee, "ia", TOYFLAG_USR|TOYFLAG_BIN))
@@ -330,7 +331,7 @@ USE_UUDECODE(NEWTOY(uudecode, ">1o:", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
 USE_UUENCODE(NEWTOY(uuencode, "<1>2m", TOYFLAG_USR|TOYFLAG_BIN))
 USE_UUIDGEN(NEWTOY(uuidgen, ">0r(random)", TOYFLAG_USR|TOYFLAG_BIN))
 USE_VCONFIG(NEWTOY(vconfig, "<2>4", TOYFLAG_NEEDROOT|TOYFLAG_SBIN))
-USE_VI(NEWTOY(vi, ">1s:", TOYFLAG_USR|TOYFLAG_BIN))
+USE_VI(NEWTOY(vi, ">1s:c:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_VMSTAT(NEWTOY(vmstat, ">2n", TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_W(NEWTOY(w, NULL, TOYFLAG_USR|TOYFLAG_BIN))
 USE_SH(NEWTOY(wait, "n", TOYFLAG_NOFORK))
diff --git a/config-device b/config-device
index cae98bfb..694720c5 100644
--- a/config-device
+++ b/config-device
@@ -33,6 +33,7 @@ CONFIG_ACPI=y
 # CONFIG_ARCH is not set
 # CONFIG_ARPING is not set
 # CONFIG_ARP is not set
+# CONFIG_AWK is not set
 # CONFIG_ASCII is not set
 # CONFIG_BASE32 is not set
 CONFIG_BASE64=y
diff --git a/config-linux b/config-linux
index 24132c62..140293ce 100644
--- a/config-linux
+++ b/config-linux
@@ -34,6 +34,7 @@ CONFIG_TOYBOX_UID_USR=500
 # CONFIG_ARPING is not set
 # CONFIG_ARP is not set
 # CONFIG_ASCII is not set
+# CONFIG_AWK is not set
 # CONFIG_BASE32 is not set
 # CONFIG_BASE64 is not set
 CONFIG_BASENAME=y
diff --git a/config-mac b/config-mac
index b0b928ea..d8468c7e 100644
--- a/config-mac
+++ b/config-mac
@@ -34,6 +34,7 @@ CONFIG_TOYBOX_UID_USR=500
 # CONFIG_ARPING is not set
 # CONFIG_ARP is not set
 # CONFIG_ASCII is not set
+# CONFIG_AWK is not set
 # CONFIG_BASE32 is not set
 # CONFIG_BASE64 is not set
 CONFIG_BASENAME=y
diff --git a/lib/lib.c b/lib/lib.c
index dc578804..75ac51dc 100644
--- a/lib/lib.c
+++ b/lib/lib.c
@@ -522,6 +522,16 @@ int strcasestart(char **a, char *b)
   return i;
 }
 
+// return length of match found at this point (try is null terminated array)
+int anystart(char *s, char **try)
+{
+  char *ss = s;
+
+  while (*try) if (strstart(&s, *try++)) return s-ss;
+
+  return 0;
+}
+
 int same_file(struct stat *st1, struct stat *st2)
 {
   return st1->st_ino==st2->st_ino && st1->st_dev==st2->st_dev;
diff --git a/lib/lib.h b/lib/lib.h
index 147bcf2f..dd18cdf2 100644
--- a/lib/lib.h
+++ b/lib/lib.h
@@ -232,6 +232,7 @@ int unescape2(char **c, int echo);
 char *strend(char *str, char *suffix);
 int strstart(char **a, char *b);
 int strcasestart(char **a, char *b);
+int anystart(char *s, char **try);
 int same_file(struct stat *st1, struct stat *st2);
 int same_dev_ino(struct stat *st, struct dev_ino *di);
 off_t fdlength(int fd);
@@ -262,7 +263,7 @@ struct group *bufgetgrgid(gid_t gid);
 int readlinkat0(int dirfd, char *path, char *buf, int len);
 int readlink0(char *path, char *buf, int len);
 int regexec0(regex_t *preg, char *string, long len, int nmatch,
-  regmatch_t pmatch[], int eflags);
+  regmatch_t *pmatch, int eflags);
 char *getusername(uid_t uid);
 char *getgroupname(gid_t gid);
 void do_lines(int fd, char delim, void (*call)(char **pline, long len));
diff --git a/lib/portability.h b/lib/portability.h
index cb4725b8..0b9e282f 100644
--- a/lib/portability.h
+++ b/lib/portability.h
@@ -343,20 +343,6 @@ static inline int stub_out_log_write(int pri, const char *tag, const char *msg)
 
 #endif
 
-// libprocessgroup is an Android platform library not included in the NDK.
-#if defined(__BIONIC__)
-#if __has_include(<processgroup/sched_policy.h>)
-#include <processgroup/sched_policy.h>
-#define GOT_IT
-#endif
-#endif
-#ifdef GOT_IT
-#undef GOT_IT
-#else
-static inline int get_sched_policy(int tid, void *policy) {return 0;}
-static inline char *get_sched_policy_name(int policy) {return "unknown";}
-#endif
-
 #ifndef SYSLOG_NAMES
 typedef struct {char *c_name; int c_val;} CODE;
 extern CODE prioritynames[], facilitynames[];
diff --git a/lib/toyflags.h b/lib/toyflags.h
index 928fe0bb..9ef644ab 100644
--- a/lib/toyflags.h
+++ b/lib/toyflags.h
@@ -27,10 +27,11 @@
 
 // Suppress default --help processing
 #define TOYFLAG_NOHELP   (1<<9)
+#define TOYFLAG_AUTOCONF (1<<10)
 
 // Line buffered stdout
-#define TOYFLAG_LINEBUF  (1<<10)
-#define TOYFLAG_NOBUF    (1<<11)
+#define TOYFLAG_LINEBUF  (1<<11)
+#define TOYFLAG_NOBUF    (1<<12)
 
 // Error code to return if argument parsing fails (default 1)
 #define TOYFLAG_ARGFAIL(x) (x<<24)
diff --git a/main.c b/main.c
index 2cbaf172..397b727b 100644
--- a/main.c
+++ b/main.c
@@ -132,9 +132,10 @@ static void unknown(char *name)
 // Parse --help and --version for (almost) all commands
 void check_help(char **arg)
 {
+  long flags = toys.which->flags;
+
   if (!CFG_TOYBOX_HELP_DASHDASH || !*arg) return;
-  if (!CFG_TOYBOX || toys.which != toy_list)
-    if (toys.which->flags&TOYFLAG_NOHELP) return;
+  if (!CFG_TOYBOX || toys.which!=toy_list) if (flags&TOYFLAG_NOHELP) return;
 
   if (!strcmp(*arg, "--help")) {
     if (CFG_TOYBOX && toys.which == toy_list && arg[1]) {
@@ -146,7 +147,13 @@ void check_help(char **arg)
   }
 
   if (!strcmp(*arg, "--version")) {
-    xprintf("toybox %s\n", toybox_version);
+    // Lie to autoconf when it asks stupid questions, so configure regexes
+    // that look for "GNU sed version %f" greater than some old buggy number
+    // don't fail us for not matching their narrow expectations.
+    *toybuf = 0;
+    if (flags&TOYFLAG_AUTOCONF)
+      sprintf(toybuf, " (is not GNU %s 9.0)", toys.which->name);
+    xprintf("toybox %s%s\n", toybox_version, toybuf);
     xexit();
   }
 }
diff --git a/mkroot/mkroot.sh b/mkroot/mkroot.sh
index 3a422c78..26912997 100755
--- a/mkroot/mkroot.sh
+++ b/mkroot/mkroot.sh
@@ -202,7 +202,7 @@ get_target_config()
   if [ "$CROSS" == armv5l ] || [ "$CROSS" == armv4l ]; then
     # This could use the same VIRT board as armv7, but let's demonstrate a
     # different one requiring a separate device tree binary.
-    KARCH=arm KARGS=ttyAMA0 VMLINUX=arch/arm/boot/zImage
+    KARCH=arm KARGS=ttyAMA0 VMLINUX=zImage
     QEMU="arm -M versatilepb -net nic,model=rtl8139 -net user"
     KCONF="$(be2csv CPU_ARM926T MMU VFP ARM_THUMB AEABI ARCH_VERSATILE ATAGS \
       DEPRECATED_PARAM_STRUCT BLK_DEV_SD NET_VENDOR_REALTEK 8139CP \
@@ -212,10 +212,9 @@ get_target_config()
     DTB=versatile-pb.dtb
   elif [ "$CROSS" == armv7l ] || [ "$CROSS" == aarch64 ]; then
     if [ "$CROSS" == aarch64 ]; then
-      QEMU="aarch64 -M virt -cpu cortex-a57"
-      KARCH=arm64 VMLINUX=arch/arm64/boot/Image
+      QEMU="aarch64 -M virt -cpu cortex-a57" KARCH=arm64 VMLINUX=Image
     else
-      QEMU="arm -M virt" KARCH=arm VMLINUX=arch/arm/boot/zImage
+      QEMU="arm -M virt" KARCH=arm VMLINUX=zImage
     fi
     KARGS=ttyAMA0
     KCONF="$(be2csv MMU SOC_DRA7XX VDSO CPU_IDLE KERNEL_MODE_NEON \
@@ -236,7 +235,7 @@ get_target_config()
       QEMU=x86_64 KCONF=64BIT
       [ "$CROSS" == x32 ] && KCONF=X86_X32
     fi
-    KARCH=x86 VMLINUX=arch/x86/boot/bzImage
+    KARCH=x86 VMLINUX=bzImage
     KCONF+=,"$(be2csv UNWINDER_FRAME_POINTER PCI BLK_DEV_SD NET_VENDOR_INTEL \
       E1000 RTC_CLASS ATA{,_SFF,_BMDMA,_PIIX} SERIAL_8250{,_CONSOLE})"
   elif [ "$CROSS" == m68k ]; then
@@ -270,8 +269,19 @@ get_target_config()
       PPC_{PSERIES,OF_BOOT_TRAMPOLINE,TRANSACTIONAL_MEM,DISABLE_WERROR} \
       SCSI_{LOWLEVEL,IBMVSCSI})"
     [ "$CROSS" == powerpc64le ] && KCONF=$KCONF,CPU_LITTLE_ENDIAN
+  elif [ "$CROSS" = riscv32 ]; then
+    # Note: -hda file.img doesn't work, but this insane overcomplicated pile:
+    # -drive file=file.img,format=raw,id=hd0 -device virtio-blk-device,drive=hd0
+    QEMU="riscv32 -M virt -netdev user,id=net0 -device virtio-net-device,netdev=net0"
+    KARCH=riscv VMLINUX=Image
+    # Probably only about half of these kernel symbols are actually needed?
+    KCONF="$(be2csv MMU SOC_VIRT NONPORTABLE ARCH_RV32I CMODEL_MEDANY \
+      RISCV_ISA_{ZICBO{M,Z},FALLBACK} FPU PCI{,_HOST_GENERIC} BLK_DEV_SD \
+      SCSI_{PROC_FS,LOWLEVEL,VIRTIO} VIRTIO_{MENU,NET,BLK,PCI} SERIO_SERPORT \
+      SERIAL_{EARLYCON,8250{,_CONSOLE,_PCI},OF_PLATFORM} HW_RANDOM{,_VIRTIO} \
+      RTC_{CLASS,HCTOSYS} DMADEVICES VIRTIO_{MENU,PCI{,_LEGACY},INPUT,MMIO})"
   elif [ "$CROSS" = s390x ]; then
-    QEMU="s390x" KARCH=s390 VMLINUX=arch/s390/boot/bzImage
+    QEMU="s390x" KARCH=s390 VMLINUX=bzImage
     KCONF="$(be2csv MARCH_Z900 PACK_STACK S390_GUEST VIRTIO_{NET,BLK} \
       SCLP_VT220_{TTY,CONSOLE})"
   elif [ "$CROSS" == sh2eb ]; then
@@ -284,7 +294,7 @@ get_target_config()
     KCONF+=,CMDLINE=\"console=ttyUL0\ earlycon\"
   elif [ "$CROSS" == sh4 ] || [ "$CROSS" == sh4eb ]; then
     QEMU="$CROSS -M r2d -serial null -serial mon:stdio" KARCH=sh
-    KARGS="ttySC1 noiotrap" VMLINUX=arch/sh/boot/zImage
+    KARGS="ttySC1 noiotrap" VMLINUX=zImage
     KCONF="$(be2csv CPU_SUBTYPE_SH7751R MMU VSYSCALL SH_{FPU,RTS7751R2D} PCI \
       RTS7751R2D_PLUS SERIAL_SH_SCI{,_CONSOLE} NET_VENDOR_REALTEK 8139CP \
       BLK_DEV_SD ATA{,_SFF,_BMDMA} PATA_PLATFORM BINFMT_ELF_FDPIC \
@@ -362,6 +372,7 @@ else
       (cd modz && find lib/modules | cpio -o -H newc -R +0:+0 ) | gzip \
        > "$OUTDOC/modules.cpio.gz" || exit 1
   fi
+  [ ! -e "$VMLINUX" ] && VMLINUX=arch/$KARCH/boot/$VMLINUX
   cp "$VMLINUX" "$OUTPUT"/linux-kernel && cd .. && rm -rf linux && popd ||exit 1
 fi
 
diff --git a/mkroot/packages/lfs-sources b/mkroot/packages/lfs-sources
new file mode 100755
index 00000000..63269cf4
--- /dev/null
+++ b/mkroot/packages/lfs-sources
@@ -0,0 +1,35 @@
+#!/bin/echo Try "mkroot/mkroot.sh lfs"
+
+[ -z "$(which mksquashfs)" ] && echo "no squashfs" && exit 1
+
+# Download osuosl's rollup tarball of all the LFS packages.
+
+download 45a27da2ee443a8e35a7e29db8a0c6877bbb98bb \
+  http://ftp.osuosl.org/pub/lfs/lfs-packages/lfs-packages-12.1.tar
+
+# This one's a little weird, we're creating a target-agonstic squashfs image
+# not part of the initramfs.
+
+setupfor lfs-packages
+LFS="$OUTPUT/lfs" LFSRC="$LFS/src"
+rm -rf "$LFS" && mkdir -p "$LFSRC/tzdata" &&
+# Fixup names
+tar xfC tzdata*.tar.gz "$LFSRC/tzdata" && # Horrible package, no subdirectory!
+rm tzdata*.tar.gz &&
+mv {expect*,expect-0}.tar.gz &&           # broken name (no - before version)
+rm -f tcl*-html.tar.gz &&                 # Broken _and_ duplicate name
+mv {tcl*,tcl-0}.tar.gz &&
+mkdir sub || exit 1
+# extract tarballs to package name in output and apply patches (if any)
+for i in *.tar*; do
+  PKG="${i/-[0-9]*/}"
+  echo process $PKG
+  tar xfC $i sub && mv sub/* "$LFSRC/$PKG" || exit 1
+  for j in $PKG*.patch; do
+    [ -e "$j" ] && { ( cd "$LFSRC/$PKG" && patch -p1) < "$j" || exit 1 ; }
+  done
+done
+
+# Archive the sources
+
+mksquashfs "$LFSRC" "$TOP"/lfs.sqf -noappend -all-root >/dev/null
diff --git a/mkroot/packages/plumbing b/mkroot/packages/plumbing
index e72247c0..306f4854 100755
--- a/mkroot/packages/plumbing
+++ b/mkroot/packages/plumbing
@@ -31,7 +31,9 @@ setupfor() {
   if [ -d "$DOWNLOAD/$PACKAGE" ]; then
     cp -la "$DOWNLOAD/$PACKAGE/." "$PACKAGE" && cd "$PACKAGE" || exit 1
   else
-    tar xvaf "$DOWNLOAD/$PACKAGE"-*.t* && cd "$PACKAGE"-* || exit 1
+    local DIR=$(mktemp -dp.)
+    tar xvafC "$DOWNLOAD/$PACKAGE"-*.t* "$DIR" &&
+    mv "$DIR"/* "$PACKAGE" && rmdir "$DIR" && cd "$PACKAGE" || exit 1
   fi
 }
 
diff --git a/scripts/install.sh b/scripts/install.sh
index 8ba3495e..7c90036e 100755
--- a/scripts/install.sh
+++ b/scripts/install.sh
@@ -105,7 +105,7 @@ done
 # The following are commands toybox should provide, but doesn't yet.
 # For now symlink the host version. This list must go away by 1.0.
 
-PENDING="expr git tr bash sh gzip   awk bison flex make"
+PENDING="expr git tr bash sh gzip   awk bison flex make ar"
 TOOLCHAIN="as cc ld objdump"
 TOOLCHAIN+=" bc gcc" # both patched out but not in vanilla yet
 
diff --git a/scripts/portability.sh b/scripts/portability.sh
index e8ad197a..98412c76 100644
--- a/scripts/portability.sh
+++ b/scripts/portability.sh
@@ -32,7 +32,7 @@ fi
 if [ -n "$ASAN" ]; then
   # Turn ASan on and disable most optimization to get more readable backtraces.
   # (Technically ASAN is just "-fsanitize=address" and the rest is optional.)
-  export CFLAGS="$CFLAGS -fsanitize=address -O1 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls"
+  export CFLAGS="$CFLAGS -fsanitize=address -O1 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls -static-libasan"
   export NOSTRIP=1
   # Ignore leaks on exit. TODO
   export ASAN_OPTIONS="detect_leaks=0"
diff --git a/tests/awk.test b/tests/awk.test
new file mode 100644
index 00000000..a9ea76de
--- /dev/null
+++ b/tests/awk.test
@@ -0,0 +1,469 @@
+#!/bin/bash
+
+# Original found at http://lists.landley.net/pipermail/toybox-landley.net/2015-March/015201.html
+
+# Copyright 2015 Divya Kothari <divya.s.kothari@gmail.com>
+
+# 2023: A few mods by Ray Gardner <raygard@gmail.com>
+#   See "awk -f test04.awk" near line 170
+#   and "awk -e ..." tests near line 415
+# 2024: Mods to use testcmd instead of testing for most tests
+#       Added new tests (after line 420)
+
+[ -f testing.sh ] && . testing.sh
+
+#testcmd "name" "command" "result" "infile" "stdin"
+#testing "name" "progname command" "result" "infile" "stdin"
+
+FILE1="abc def ghi 5\nghi jkl mno 10\nmno pqr stu 15\nstu vwx abc 20\n"
+FILE2="abc,def,ghi,5\nghi,jkl,mno,10\nmno,pqr,stu,15\nstu,vwx,abc,20\n"
+FILE3="abc:def:ghi:5\nghi:jkl:mno:10\nmno:pqr:stu:15\nstu:vwx:abc:20\n"
+FILE4="abc def ghi -5\nghi jkl mno -10\nmno pqr stu -15\nstu vwx abc -20\n"
+
+testcmd "awk PATTERN input" "'/abc/' input" \
+  "abc def ghi 5\nstu vwx abc 20\n" "$FILE1" ""
+
+testcmd "awk SUBPATTERN input" "'/ab/' input" \
+  "abc def ghi 5\nstu vwx abc 20\n" "$FILE1" ""
+
+testcmd "awk FIELD input" "'{print \$2,\$3}' input" \
+  "def ghi\njkl mno\npqr stu\nvwx abc\n" "$FILE1" ""
+
+testcmd "awk FIELD input (out range)" "'{print \$2,\$8}' input" \
+  "def \njkl \npqr \nvwx \n" "$FILE1" ""
+
+L1="def def def def def def def def def def"
+L2="jkl jkl jkl jkl jkl jkl jkl jkl jkl jkl"
+L3="pqr pqr pqr pqr pqr pqr pqr pqr pqr pqr"
+L4="vwx vwx vwx vwx vwx vwx vwx vwx vwx vwx"
+testing "awk FIELD input (single, multiple times)" \
+  "awk '{ print \$2,\$2,\$2,\$2,\$2,\$2,\$2,\$2,\$2,\$2 }' input" \
+  "$L1\n$L2\n$L3\n$L4\n" "$FILE1" ""
+
+
+HEAD="Head1\tHead2\tHead3"
+FOOT="Report Generated"
+testcmd "awk CODE input" "'BEGIN { print \"$HEAD\"; } {
+   print \$1,\"\t\",\$3; } END { print \"$FOOT\"; }' input" \
+  "$HEAD\nabc \t ghi\nghi \t mno\nmno \t stu\nstu \t abc\n$FOOT\n" "$FILE1" ""
+
+testcmd "awk '>' input" "'\$4>0' input" \
+  "abc def ghi 5\nghi jkl mno 10\nmno pqr stu 15\nstu vwx abc 20\n" "$FILE1" ""
+
+testcmd "awk '<' input" "'\$4<25' input" \
+  "abc def ghi 5\nghi jkl mno 10\nmno pqr stu 15\nstu vwx abc 20\n" "$FILE1" ""
+
+testcmd "awk '==' input" "'\$4==15' input" "mno pqr stu 15\n" "$FILE1" ""
+
+testcmd "awk CMP input" "'\$1~/abc/' input" "abc def ghi 5\n" "$FILE1" ""
+
+testcmd "awk COUNT input" "'BEGIN { count=0; } \$1~/abc/ { count++; } END {
+   print \"Total Count =\",count; }' input" "Total Count = 1\n" "$FILE1" ""
+
+testcmd "awk COLUMN input" "'{ print \$1 }' input" "abc\nghi\nmno\nstu\n" \
+  "$FILE1" ""
+
+testcmd "awk SUM input" "'BEGIN { sum=0; } { sum=sum+\$4; } END {
+   print \"Sum is =\",sum; }' input" "Sum is = 50\n" "$FILE1" ""
+
+testcmd "awk IF input" "'{ if(\$2 == \"jkl\") print \$1; }' input" "ghi\n" \
+  "$FILE1" ""
+
+testing "awk FOR MUL input" \
+  "awk 'BEGIN { for(i=1;i<=3;i++) print \"square of\", i, \"is\",i*i; }'" \
+  "square of 1 is 1\nsquare of 2 is 4\nsquare of 3 is 9\n" "" ""
+
+testing "awk FOR ADD input" \
+  "awk 'BEGIN { for(i=1;i<=3;i++) print \"twice of\", i, \"is\",i+i; }'" \
+  "twice of 1 is 2\ntwice of 2 is 4\ntwice of 3 is 6\n" "" ""
+
+testing "awk FOR SUB input" \
+  "awk 'BEGIN { for(i=1;i<=3;i++) print \"sub of\", i, \"is\",i-i; }'" \
+  "sub of 1 is 0\nsub of 2 is 0\nsub of 3 is 0\n" "" ""
+
+testcmd "awk {FS:invalid} input1" "'BEGIN { FS=\"69793793\" } { print \$2
+   }' input" "\n\n\n\n" "$FILE3" ""
+
+testcmd "awk -F invalid input1" "-F69793793 '{ print \$2 }' input" \
+  "\n\n\n\n" "$FILE3" ""
+
+testcmd "awk {FS} input2" "'BEGIN { FS=\",\" } { print \$2 }' input" \
+  "def\njkl\npqr\nvwx\n" "$FILE2" ""
+
+testcmd "awk -F input2" "-F\",\" '{ print \$2 }' input" \
+  "def\njkl\npqr\nvwx\n" "$FILE2" ""
+
+testcmd "awk {FS} input3" "'BEGIN { FS=\":\" } { print \$2 }' input" \
+  "def\njkl\npqr\nvwx\n" "$FILE3" ""
+
+testcmd "awk -F input3" "-F: '{ print \$2 }' input" "def\njkl\npqr\nvwx\n" \
+  "$FILE3" ""
+
+testcmd "awk {OFS} {1} input" "'BEGIN { OFS=\"__\" } { print \$2 }' input" \
+  "def\njkl\npqr\nvwx\n" "$FILE1" ""
+
+testcmd "awk {OFS} {1,2} input" "'BEGIN { OFS=\"__\" } { print \$2,\$3
+   }' input" "def__ghi\njkl__mno\npqr__stu\nvwx__abc\n" "$FILE1" ""
+
+testcmd "awk {NF} input" "'{print NF}' input" "4\n4\n4\n4\n" "$FILE1" ""
+
+testcmd "awk {NR} input" "'{print NR}' input" "1\n2\n3\n4\n" "$FILE1" ""
+
+testcmd "awk END{NR} input" "'END {print NR}' input" "4\n" "$FILE1" ""
+
+testcmd "awk SPLIT input" "'{ split(\$0,arr,\" \"); if(arr[3] == \"abc\")
+   print \$2 }' input" "vwx\n" "$FILE1" ""
+
+testcmd "awk SUBSTR input" "'{if (substr(\$0,1,3) == \"abc\") { print \$3 }
+   }' input" "ghi\n" "$FILE1" ""
+
+testcmd "awk SEARCH {PRINT} input" "'/ghi/ {print \$1,\$2,\$3,\$4}' input" \
+  "abc def ghi 5\nghi jkl mno 10\n" "$FILE1" ""
+
+testcmd "awk SEARCH {PRINTF} input" "'/ghi/ { printf \$1 \$2 \$3 \$4
+   }' input" "abcdefghi5ghijklmno10" "$FILE1" ""
+
+testcmd "awk {PRINT with TAB} input" "'{print \$2,\"\t\",\$4}' input" \
+  "def \t 5\njkl \t 10\npqr \t 15\nvwx \t 20\n" "$FILE1" ""
+
+testcmd "awk {PRINT 2,4} input" "'{print \$2,\$4}' input" \
+  "def 5\njkl 10\npqr 15\nvwx 20\n" "$FILE1" ""
+
+testcmd "awk {PRINT 4,2} input" "'{print \$4,\$2}' input" \
+  "5 def\n10 jkl\n15 pqr\n20 vwx\n" "$FILE1" ""
+
+testcmd "awk {PRINT X,Y} input" "'{print \$6,\$9}' input" \
+  " \n \n \n \n" "$FILE1" ""
+
+testcmd "awk {PRINT} input" "'{ print }' input" "$FILE1" "$FILE1" ""
+
+testcmd "awk INVALID_ARGS1 input" "'{ print x,y }' input" \
+  " \n \n \n \n" "$FILE1" ""
+
+testcmd "awk INVALID_ARGS2 input" "'{ print \$4,\$5 }' input" \
+  "5 \n10 \n15 \n20 \n" "$FILE1" ""
+
+testcmd "awk PATTERN input (not found)" "'/abcd/' input && echo 'yes'" \
+  "yes\n" "$FILE1" ""
+
+testcmd "awk {PATTERN:-ve} input" "'/-5/' input" "abc def ghi -5\n" \
+  "$FILE4" ""
+
+testcmd "awk FIELD input (high value)" "'{print \$99999}' input &&
+   echo 'yes'" "\n\n\n\nyes\n" "$FILE1" ""
+
+#### Starting "-f file" tests ####
+
+echo "{ if (\$1 == \"#START\") { FS=\":\"; } else if (\$1 == \"#STOP\") {
+  FS=\" \"; } else { print \$3 } }" > test.awk
+testcmd "awk -f test01.awk" "-f test.awk input" \
+  "ghi\nmno\nstu\nabc\n" "$FILE1" ""
+
+echo "BEGIN { i=1; while (i <= 5) { printf i \"-\" i*i \" \"; i=i+1; }
+  for (i=1; i <= 5; i++) { printf i \"-\" i*i \" \"; } }" > test.awk
+testcmd "awk -f test02.awk" "-f test.awk" \
+  "1-1 2-4 3-9 4-16 5-25 1-1 2-4 3-9 4-16 5-25 " "" ""
+
+echo "BEGIN { print \"Start.\" } { print \$1,\"-\",\$1*\$1; }
+  END { print \"End.\" }" > test.awk
+testcmd "awk -f test03.awk" "-f test.awk" \
+  "Start.\n5 - 25\n10 - 100\n15 - 225\n20 - 400\nEnd.\n" "" "5\n10\n15\n20\n"
+
+### echo "{ if ( \$0 ~ /:/ ) {FS=\":\";} else {FS=\" \";} print \$3 }" > test.awk
+### testing "awk -f test04.awk" "awk -f test.awk input" \
+###   "ghi\nmno\nstu\nabc\nghi\nmno\nstu\nabc\n" "$FILE1$FILE3" ""
+
+### TEST ERROR This test originally ended with:
+###   "ghi\nmno\nstu\nabc\nghi\nmno\nstu\nabc\n" "$FILE1$FILE3" ""
+### This is wrong; gawk/mawk/bbawk/bwk awk agree that second ghi should not appear.
+### (My current version of goawk agrees with the "wrong" expected value;
+###  I need to update to latest goawk and test again. rdg 2023-10-29)
+echo "{ if ( \$0 ~ /:/ ) {FS=\":\";} else {FS=\" \";} print \$3 }" > test.awk
+testcmd "awk -f test04.awk" "-f test.awk input" \
+  "ghi\nmno\nstu\nabc\n\nmno\nstu\nabc\n" "$FILE1$FILE3" ""
+
+echo "BEGIN { lines=0; total=0; } { lines++; total+=\$1; } END {
+  print \"Read:\",lines; print \"Total:\",total; if (lines > 0 ) {
+  print \"Average:\", total/lines; } else { print \"0\"; } }" > test.awk
+testcmd "awk -f test05.awk" "-f test.awk input" \
+  "Read: 5\nTotal: 150\nAverage: 30\n" "10\n20\n30\n40\n50\n" ""
+
+echo "BEGIN{FS=\":\";}{if(\$2==\"pqr\"){print \"first one:\", \$1;}}" > test.awk
+testcmd "awk -f test06.awk" "-f test.awk input" \
+  "first one: mno\n" "$FILE3" ""
+
+echo "{ print \$2; FS=\":\"; print \$2 }" > test.awk
+testcmd "awk -f test07.awk" "-f test.awk input" \
+  "\n\njkl\njkl\npqr\npqr\nvwx\nvwx\n" "$FILE3" ""
+
+echo "BEGIN { FS=\":\"; OFS=\":\"; } { \$2=\"\"; print }" > test.awk
+testcmd "awk -f test09.awk" "-f test.awk input" \
+  "abc::ghi:5\nghi::mno:10\nmno::stu:15\nstu::abc:20\n" "$FILE3" ""
+
+mkdir dir && touch dir/file && LLDATA="`ls -l dir`"
+rm -rf dir
+echo "{ if (NF==8) { print \$8; } else if (NF==9) { print \$9; } }" > test.awk
+testcmd "awk -f test10.awk" "-f test.awk input" "file\n" "$LLDATA" ""
+
+echo "{ if (NR >= 1) { print NR;} }" > test.awk
+testcmd "awk -f test11.awk" "-f test.awk input" "1\n2\n" "$LLDATA" ""
+
+echo "BEGIN { RS=\"\"; FS=\"\n\" } { print \$2,\$3; }" > test.awk
+testcmd "awk -f test12.awk" "-f test.awk input" \
+  "ghi jkl mno 10 mno pqr stu 15\n" "$FILE1" ""
+
+L="abc\ndef\nghi\n5\nghi\njkl\nmno\n10\nmno\npqr\nstu\n15\nstu\nvwx\nabc\n20\n"
+echo "BEGIN { RS=\" \"; } { print; }" > test.awk
+testcmd "awk -f test13.awk" "-f test.awk input" "$L\n" "$FILE1" ""
+
+L="abc def ghi 5\r\nghi jkl mno 10\r\nmno pqr stu 15\r\nstu vwx abc 20\r\n"
+echo "BEGIN { ORS=\"\r\n\" } { print }" > test.awk
+testcmd "awk -f test14.awk" "-f test.awk input" "$L" "$FILE1" ""
+
+echo "BEGIN { f=\"\"; }{ if(f != FILENAME){ f=FILENAME; print f }}" > test.awk
+testcmd "awk -f test15.awk" "-f test.awk input" "input\n" "$FILE1" ""
+
+echo "{ if (NF == 6) { } else { if (FILENAME == \"-\" ) { print \"ERROR\",
+  NR,\"line:\"; } else { print \"ERROR\",FILENAME,NR;}}}" > test.awk
+testcmd "awk -f test16.awk" "-f test.awk input" \
+  "ERROR input 1\nERROR input 2\nERROR input 3\nERROR input 4\n" "$FILE1" ""
+
+echo "BEGIN { number_of_users=0; } { if (NF>7) {
+  user=0; for (i=1; i<=number_of_users; i++) { if (username[i] == \$3) { user=i;
+  } } if (user == 0) { username[++number_of_users]=\$3; user=number_of_users; }
+  count[user]++; } } END { for (i=1; i<=number_of_users; i++) {
+  print count[i], username[i] } } " > test.awk
+testcmd "awk -f test17.awk" "-f test.awk input" "1 $USER\n" "$LLDATA" ""
+
+echo "{ usrname[\$3]++;}END{for(i in usrname){print usrname[i],i;} }" > test.awk
+testcmd "awk -f test18.awk" "-f test.awk input" "1 \n1 $USER\n" "$LLDATA" ""
+
+echo "{ if (NF>7) { username[\$3]++; } } END { for (i in username) {
+  print username[i], i; } }" > test.awk
+testcmd "awk -f test19.awk" "-f test.awk input" "1 $USER\n" "$LLDATA" ""
+
+echo "BEGIN { username[\"\"]=0; } { username[\$3]++; } END {
+  for (i in username) { if (i != \"\") { print username[i], i; }}}" > test.awk
+testcmd "awk -f test20.awk" "-f test.awk input" "1 $USER\n" "$LLDATA" ""
+
+echo "{ printf \"%5s %3d\n\", \$3, \$4; }" > test.awk
+testcmd "awk -f test22.awk" "-f test.awk input" \
+  "  ghi   5\n  mno  10\n  stu  15\n  abc  20\n" "$FILE1" ""
+
+echo "BEGIN { format1 =\"%8s %6sn\"; format2 =\"%8s %6dn\"; }
+  { printf(format2, \$1, \$4); }" > test.awk
+testcmd "awk -f test23.awk" "-f test.awk input" \
+  "     abc      5n     ghi     10n     mno     15n     stu     20n" "$FILE1" ""
+
+echo "END { for (i=1;i<=2;i++) {
+  printf(\"i=%d\n\", i) > \"ConcatedFile_a\" i; } }" > test.awk
+testcmd "awk -f test24.awk" "-f test.awk && cat ConcatedFile_a1 &&
+  cat ConcatedFile_a2 && rm -f ConcatedFile_a*" "i=1\ni=2\n" "" ""
+
+L1="             abc def ghi 5\n"
+L2="            ghi jkl mno 10\n"
+L3="            mno pqr stu 15\n"
+L4="            stu vwx abc 20\n"
+echo "{ if (length(\$0) < 80) { prefix = \"\";
+  for (i = 1;i<(40-length(\$0))/2;i++) { prefix = prefix \" \" };
+  print prefix \$0; } else { print; } }" > test.awk
+testcmd "awk -f test26.awk" "-f test.awk input" "$L1$L2$L3$L4" "$FILE1" ""
+
+echo "{ line = \$0; while (substr(line,length(line),1) == \"\\\\\") {
+  line = substr(line,1,length(line)-1); i=getline; if (i > 0) {
+  line = line \$0; } else { printf(\"%d\", NR); } } print line; }" > test.awk
+testcmd "awk -f test27.awk" "-f test.awk input" "$FILE1" "$FILE1" ""
+
+echo "BEGIN { for (x = 0; x <= 20; x++) { if (x == 5) { continue; }
+  printf \"%d \",x } print \"\" }" > test.awk
+testcmd "awk -f test28.awk" "-f test.awk" \
+  "0 1 2 3 4 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 \n" "" ""
+
+echo "{ i = 1; while (i <= 2) { print \$i; i++ } }" > test.awk
+testcmd "awk -f test29.awk" "-f test.awk input" \
+  "abc\ndef\nghi\njkl\nmno\npqr\nstu\nvwx\n" "$FILE1" ""
+
+L1="abc def ghi 5\nabc def ghi 5\nabc def ghi 5\n"
+L2="ghi jkl mno 10\nghi jkl mno 10\nghi jkl mno 10\n"
+L3="mno pqr stu 15\nmno pqr stu 15\nmno pqr stu 15\n"
+L4="stu vwx abc 20\nstu vwx abc 20\nstu vwx abc 20\n"
+echo "{ i = 1; do { print \$0; i++ } while (i <= 3) }" > test.awk
+testcmd "awk -f test30.awk" "-f test.awk input" "$L1$L2$L3$L4" "$FILE1" ""
+
+echo "{ for (i = 1; i <= 3; i++) print \$i }" > test.awk
+testcmd "awk -f test31.awk" "-f test.awk input" \
+  "abc\ndef\nghi\nghi\njkl\nmno\nmno\npqr\nstu\nstu\nvwx\nabc\n" "$FILE1" ""
+
+echo "{ num = \$1; for (div = 2; div*div <= num; div++) { if (num % div == 0) {
+  break } } if (num % div == 0) { printf \"divisor of %d is %d\n\", num, div }
+  else { printf \"%d is prime\n\", num } }" > test.awk
+testcmd "awk -f test32.awk" "-f test.awk input" \
+  "divisor of 10 is 2\ndivisor of 15 is 3\n17 is prime\n" "10\n15\n17\n" ""
+
+# Mod in case prog name is not 'awk'
+##  echo "BEGIN { for (i = 0; i < ARGC; i++) { print ARGV[i] } }" > test.awk
+##  testcmd "awk -f test33.awk" "-f test.awk input1 input2 input3 input4" \
+##    "awk\ninput1\ninput2\ninput3\ninput4\n" "$FILE1" ""
+echo "BEGIN { for (i = 1; i < ARGC; i++) { print ARGV[i] } }" > test.awk
+testcmd "awk -f test33.awk" "-f test.awk input1 input2 input3 input4" \
+  "input1\ninput2\ninput3\ninput4\n" "$FILE1" ""
+
+echo "NR == 2 { NR = 17 } { print NR }" > test.awk
+testcmd "awk -f test34.awk" "-f test.awk input" "1\n17\n18\n19\n" \
+  "$FILE1" ""
+
+echo "BEGIN{n=0;}/abc/{++n;}END{print \"abc appears\",n,\"times\"}" > test.awk
+testcmd "awk -f test35.awk" "-f test.awk input" "abc appears 2 times\n" \
+  "$FILE1" ""
+
+echo "{ print \"Square root of\", \$1, \"is\", sqrt(\$1) }" > test.awk
+testcmd "awk -f test36.awk" "-f test.awk input" \
+  "Square root of 25 is 5\n" "25" ""
+
+FILE5="foo bar 2500\nabc def 2400\n"
+echo "\$1 == \"foo\" { print \$2 }" > test.awk
+testcmd "awk -f test37.awk" "-f test.awk input" "bar\n" "$FILE5" ""
+
+echo "/2400/ && /foo/" > test.awk
+testcmd "awk -f test38.awk" "-f test.awk input" "" "$FILE5" ""
+
+echo "/2400/ || /foo/" > test.awk
+testcmd "awk -f test39.awk" "-f test.awk input" "$FILE5" "$FILE5" ""
+
+echo "! /foo/" > test.awk
+testcmd "awk -f test40.awk" "-f test.awk input" "abc def 2400\n" "$FILE5" ""
+
+echo "\$1 ~ /foo/ { print \$2 }" > test.awk
+testcmd "awk -f test41.awk" "-f test.awk input" "bar\n" "$FILE5" ""
+
+echo "{ if (! (\$0 ~ /foo/)) print }" > test.awk
+testcmd "awk -f test42.awk" "-f test.awk input" "abc def 2400\n" "$FILE5" ""
+
+FILE6="Pat 100 97 58\nSandy 84 72 93\nChris 72 92 89\n"
+
+echo "{ print \"F1:\", \$1 }" > test.awk
+testcmd "awk -f test43.awk" "-f test.awk input" "F1: foo\nF1: abc\n" \
+  "$FILE5" ""
+
+echo "{ sum = \$2 + \$3 + \$4 ; avg = sum / 3; print \$1, avg }" > test.awk
+testcmd "awk -f test44.awk" "-f test.awk input" \
+  "Pat 85\nSandy 83\nChris 84.3333\n" "$FILE6" ""
+
+echo "{ print \$1 > \"list1\"; print \$2 > \"list2\" }" > test.awk
+testcmd "awk -f test45.awk" "-f test.awk input && cat list1 && cat list2" \
+  "Pat\nSandy\nChris\n100\n84\n72\n" "$FILE6" ""
+rm -f list1 list2
+
+echo "{ print \$(2*2) }" > test.awk
+testcmd "awk -f test46.awk" "-f test.awk input" "58\n93\n89\n" "$FILE6" ""
+
+echo "{ sub(/a+/,\"<A>\"); print }" > test.awk
+testcmd "awk -f test47.awk" "-f test.awk input" \
+  "P<A>t 100 97 58\nS<A>ndy 84 72 93\nChris 72 92 89\n" "$FILE6" ""
+
+echo "{ l[lines] = \$0; ++lines } END { for (i = lines-1; i >= 0; --i) {
+  print l[i]} }" > test.awk
+testcmd "awk -f test48.awk" "-f test.awk input" \
+  "Chris 72 92 89\nSandy 84 72 93\n\n" "$FILE6" ""
+
+FILE7="Pat 100 97 58 77 89 11 45\nSandy 84 729\nChris 92 89\nsagar 22 2213\n"
+L1="Pat 100 97 58 77 89 11 45"
+L2="sagar 22 2213"
+L3="dd 335566778856"
+testcmd "awk Print line longer than 12" "'length(\$0) > 12' input" \
+  "$L1\n$L2\n" "$FILE7" ""
+
+FILE8="red apple blue berry green thumb"
+testcmd "awk Print first two field opposite order" "'{ print \$2, \$1 }' input" \
+  "apple red\n" "$FILE8" ""
+
+FILE9="1, Justin Timberlake, Title 545, Price $7.30\n2, Taylor Swift, Title 723, Price $7.90\n3, Mick Jagger, Title 610, Price $7.90\n4, Lady Gaga, Title 118, Price $7.30\n5, Johnny Cash, Title 482, Price $6.50\n6, Elvis Presley, Title 335, Price $7.30\n7, John Lennon, Title 271, Price $7.90\n8, Michael Jackson, Title 373, Price $5.50\n"
+testcmd "awk filter data" "'{ print \$5 }' input" \
+  "545,\n723,\n610,\n118,\n482,\n335,\n271,\n373,\n" "$FILE9" ""
+
+FILE10="abcd efgh ijkl mnop\nqrst uvwx yzab cdef\nghij klmn opqr stuv\nwxyz abcd efgh ijkl\nmnop qrst uvwx yz\n"
+L1="abcd efgh ijkl mnop"
+L2="wxyz abcd efgh ijkl"
+testcmd "awk print selected lines" "'/abcd/' input" \
+   "$L1\n$L2\n" "$FILE10" ""
+L1="efgh mnop"
+L2="uvwx cdef"
+L3="klmn stuv"
+L4="abcd ijkl"
+L5="qrst yz"
+testcmd "awk print selected fields" "'{print \$2, \$4}' input" \
+   "$L1\n$L2\n$L3\n$L4\n$L5\n" "$FILE10" ""
+
+FILE11="abcd efgh ijkl mnop 4\nqrst uvwx yzab cdef 6\nghij klmn opqr stuv 0\nwxyz abcd efgh ijkl 1\nmnop qrst uvwx yz 2\n"
+FILE12="abcd\efgh\ijkl\mnop\4\nqrst\uvwx\yzab\cdef\6\nghij\klmn\opqr\stuv\0\nwxyz\abcd\efgh\ijkl\1\nmnop\qrst\uvwx\yz\2\n"
+testcmd "awk FS" "'BEGIN {FS=k;lksa;lkf;l} {print \$2}' input" "b\nr\nh\nx\nn\n" "$FILE11" ""
+
+echo "{ if (\$1 == \"#START\") { FS=\":\"; } else if (\$1 == \"#STOP\") {
+  FS=\" \"; } else { print \$3 } }" > test.awk
+testcmd "awk -v var=val -f test.awk" "-v var=2 -f test.awk input" \
+  "ghi\nmno\nstu\nabc\nghi\nmno\nstu\nabc\n" "$FILE1$FILE4" ""
+
+echo -e "abc def ghi 5\nghi jkl mno 10\nmno pqr stu 15\nstu vwx abc 20\n" > testfile1.txt
+echo -e "abc,def,ghi,5\nghi,jkl,mno,10\nmno,pqr,stu,15\nstu,vwx,abc,20\n" > testfile2.txt
+echo "{ if (\$1 == \"#START\") { FS=\":\"; } else if (\$1 == \"#STOP\") {
+  FS=\" \"; } else { print \$3 } }" > test.awk
+testcmd "awk -v myvar=val -f file1 file" "-v myvar=$2 -f test.awk testfile1.txt testfile2.txt" "ghi\nmno\nstu\nabc\n\n\n\n\n\n\n" "" ""
+
+### The -e option is non-standard. gawk and bbawk accept it; mawk and goawk do not, bwk awk says unknown option -e ignored but continues
+### bbawk does nothing useful with it: accepts -f and -e but runs the -e code out of order.
+### Correction: bbawk does do -e correctly now (since about December 2023?)
+
+###testing "awk -e print print ARGC file1 file2" "awk -e '{ print \$1; print ARGC }' testfile1.txt testfile2.txt" "abc\n3\nghi\n3\nmno\n3\nstu\n3\n\n3\nabc,def,ghi,5\n3\nghi,jkl,mno,10\n3\nmno,pqr,stu,15\n3\nstu,vwx,abc,20\n3\n\n3\n" "" ""
+###testing "awk -e print ARGC file" "awk -e '{ print ARGC }' testfile1.txt" "2\n2\n2\n2\n2\n" "$FILE1" ""
+###testing "awk -e print print ARGC input" "awk -e '{ print \$1; print ARGC }' input" "abc\n2\nghi\n2\nmno\n2\nstu\n2\n" "$FILE1" ""
+
+
+# 2024: New tests -- not in Divya Kothari's original ...
+
+testcmd "nextfile" " '{print NR, FNR, \$0};/ghi jkl/{nextfile}/ghi,jkl/{nextfile}' testfile1.txt testfile2.txt" "1 1 abc def ghi 5\n2 2 ghi jkl mno 10\n3 1 abc,def,ghi,5\n4 2 ghi,jkl,mno,10\n" "" ""
+
+testcmd "getline var numeric string bug fixed 20240514"  "'BEGIN{getline var; print (var < 10.0)}'" "1\n" "" "5.0\n"
+
+testcmd "lshift()" "'BEGIN{print lshift(3,2)}'" "12\n" "" ""
+testcmd "lshift() 64 bit" "'BEGIN{print lshift(1,40)}'" "1099511627776\n" "" ""
+testcmd "rshift()" "'BEGIN{print rshift(12, 1)}'" "6\n" "" ""
+testcmd "rshift() 64 bit" "'BEGIN{print rshift(1099511627776,39)}'" "2\n" "" ""
+testcmd "and()" "'BEGIN{print and(16, 25)}'" "16\n" "" ""
+testcmd "and(a, b, ...)" "'BEGIN{print and(16, 25, 10+16)}'" "16\n" "" ""
+testcmd "or()" "'BEGIN{print or(256, 16)}'" "272\n" "" ""
+testcmd "or(a, b, ...)" "'BEGIN{print or(256, 16, 8)}'" "280\n" "" ""
+testcmd "toupper()" "'BEGIN{print toupper(\"abABcD\")}'" "ABABCD\n" "" ""
+testcmd "tolower()" "'BEGIN{print tolower(\"abABcD\")}'" "ababcd\n" "" ""
+testcmd "substr()" "'BEGIN{print substr(\"abac\", 2, 2)}'" "ba\n" "" ""
+testcmd "atan2()" "'BEGIN{print substr(atan2(0, -1), 1, 5)}'" "3.141\n" "" ""
+testcmd "length()" "'{print length()}'" "1\n2\n0\n4\n" "" "a\n12\n\n6502"
+[ -n "$TEST_HOST" ] && export LC_ALL=en_US.UTF-8
+testcmd "length() utf8" "'{print length()}'< $FILES/utf8/japan.txt" "25\n" "" ""
+testcmd "substr() utf8" "'{print substr(\$0,2,1)}' < $FILES/utf8/arabic.txt" "ل\nأ\n" "" ""
+testcmd "index() utf8" "'{print index(\$0, \"ス\")}' < $FILES/utf8/japan.txt"\
+  "5\n" "" ""
+testcmd "tolower() utf8" "'{print tolower(\$0)}'" "ğжþ\n" "" "ĞЖÞ"
+testcmd "tolower() utf8 expand" "'{print tolower(\$0)}'" "ⱥⱥⱥⱥⱥⱥⱥⱥⱥⱥⱥⱥⱥⱥⱥⱥⱥⱥⱥⱥⱥⱥ\n"\
+  "" "ȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺ\n"
+testcmd "index() none" "'BEGIN{print index(\"ス\", \"deadbeef\")}'" "0\n" "" ""
+testcmd "index() same" "'BEGIN{print index(\"deadbeef\", \"deadbeef\")}'" "1\n" "" ""
+testcmd "match()" "'BEGIN{print match(\"bcdab\", \"ab\")}'" "4\n" "" ""
+testcmd "match() none" "'BEGIN{print match(\"ス\", \"deadbeef\")}'" "0\n" "" ""
+testcmd "match() utf8" "'{print match(\$0, \"ス\")}' < $FILES/utf8/japan.txt"\
+  "5\n" "" ""
+testcmd "\\u" "'BEGIN{print \"\\u20\u255\"}' < /dev/null" " ɕ\n" "" ""
+testcmd "printf %c" "'BEGIN{a=255; printf \"%c%c%c\", a, b, 255}'"\
+  "ÿ\0ÿ" "" ""
+
+testcmd "printf %c, 0" "'BEGIN{a=0; printf \"(%c)\", a}'" "(\000)" "" ""
+testcmd "printf %c, null_string" "'BEGIN{a=\"\"; printf \"(%c)\", a}'" "(\000)" "" ""
+testcmd "printf %c, utf8" "'BEGIN{a=\"ú\"; printf \"(%c)\", a}'" "(ú)" "" ""
+#testcmd "name" "command" "result" "infile" "stdin"
+
+testcmd "-b" "-b '{print length()}'< $FILES/utf8/japan.txt" "75\n" "" ""
+
+testcmd "awk -e print print ARGC file1 file2" "'{ print \$1; print ARGC }' testfile1.txt testfile2.txt" "abc\n3\nghi\n3\nmno\n3\nstu\n3\n\n3\nabc,def,ghi,5\n3\nghi,jkl,mno,10\n3\nmno,pqr,stu,15\n3\nstu,vwx,abc,20\n3\n\n3\n" "" ""
+testcmd "awk -e print ARGC file" "'{ print ARGC }' testfile1.txt" "2\n2\n2\n2\n2\n" "$FILE1" ""
+testcmd "awk -e print print ARGC input" "'{ print \$1; print ARGC }' input" "abc\n2\nghi\n2\nmno\n2\nstu\n2\n" "$FILE1" ""
+
+rm test.awk testfile1.txt testfile2.txt
diff --git a/tests/devmem.test b/tests/devmem.test
new file mode 100755
index 00000000..2b16bfd4
--- /dev/null
+++ b/tests/devmem.test
@@ -0,0 +1,22 @@
+#!/bin/bash
+
+#testing "name" "command" "result" "infile" "stdin"
+
+echo "xxxxxxxxhello, world!" > foo
+testcmd 'read default (4)' '-f foo 0x8' '0x6c6c6568\n' '' ''
+testcmd 'read 1' '-f foo 0x8 1' '0x68\n' '' ''
+testcmd 'read 2' '-f foo 0x8 2' '0x6568\n' '' ''
+testcmd 'read 4' '-f foo 0x8 4' '0x6c6c6568\n' '' ''
+testcmd 'read 8' '-f foo 0x8 8' '0x77202c6f6c6c6568\n' '' ''
+
+head -c 32 /dev/zero > foo
+NOSPACE=1 testcmd 'write 1' '-f foo 0x8 1 0x12 && od -t x foo' '0000000 00000000 00000000 00000012 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
+NOSPACE=1 testcmd 'write 2' '-f foo 0x8 2 0x1234 && od -t x foo' '0000000 00000000 00000000 00001234 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
+NOSPACE=1 testcmd 'write 4' '-f foo 0x8 4 0x12345678 && od -t x foo' '0000000 00000000 00000000 12345678 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
+NOSPACE=1 testcmd 'write 8' '-f foo 0x8 8 0x12345678abcdef01 && od -t x foo' '0000000 00000000 00000000 abcdef01 12345678\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
+
+head -c 32 /dev/zero > foo
+NOSPACE=1 testcmd 'write 1 multiple' '-f foo 0x8 1 0x12 0x34 && od -t x foo' '0000000 00000000 00000000 00003412 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
+NOSPACE=1 testcmd 'write 2 multiple' '-f foo 0x8 2 0x1234 0x5678 && od -t x foo' '0000000 00000000 00000000 56781234 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
+NOSPACE=1 testcmd 'write 4 multiple' '-f foo 0x8 4 0x12345678 0xabcdef01 && od -t x foo' '0000000 00000000 00000000 12345678 abcdef01\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
+NOSPACE=1 testcmd 'write 8 multiple' '-f foo 0x8 8 0x12345678abcdef01 0x1122334455667788 && od -t x foo' '0000000 00000000 00000000 abcdef01 12345678\n0000020 55667788 11223344 00000000 00000000\n0000040\n' '' ''
diff --git a/tests/diff.test b/tests/diff.test
index 9361a41e..4c2fd8a7 100644
--- a/tests/diff.test
+++ b/tests/diff.test
@@ -18,6 +18,7 @@ testcmd "simple" "-u -L lll -L rrr left right" '--- lll
  10
 +11
 ' "" ""
+rm left right
 
 mkdir -p tree1 tree2
 echo foo > tree1/file
@@ -31,6 +32,8 @@ testcmd "-r" "-u -r -L tree1/file -L tree2/file tree1 tree2 | grep -v ^diff" \
 -foo
 +food
 ' "" ""
+rm tree1/file tree2/file
+rmdir tree1 tree2
 
 echo -e "hello\r\nworld\r\n"> a
 echo -e "hello\nworld\n"> b
@@ -43,6 +46,14 @@ echo -e "1\n3" > bb
 testcmd "line format" "--unchanged-line-format=U%l --old-line-format=D%l --new-line-format=A%l aa bb" "U1D2A3" "" ""
 testcmd "line format empty" "--unchanged-line-format= --old-line-format=D%l --new-line-format=A%l aa bb" "D2A3" "" ""
 
+ln -s aa cc
+testcmd "follow symlink" "-q -L aa -L cc aa cc" "" "" ""
+testcmd "no follow symlink" "-q --no-dereference -L aa -L cc aa cc" "File aa is a regular file while file cc is a symbolic link\n" "" ""
+ln -s ./aa dd
+testcmd "symlink differs" "-q -L cc -L dd cc dd" "" "" ""
+testcmd "symlink differs no follow" "-q --no-dereference -L cc -L dd cc dd" "Symbolic links cc and dd differ\n" "" ""
+rm aa bb cc dd
+
 mkfifo fifo1
 mkfifo fifo2
 echo -e "1\n2" > fifo1&
@@ -55,6 +66,22 @@ testcmd "fifos" "-u -L fifo1 -L fifo2 fifo1 fifo2" '--- fifo1
 +3
 ' "" ""
 
+echo -e "1\n2" > fifo1&
+echo -e "1\n3" > file1
+ln -s file1 link1
+
+testcmd "fifo symlinked file" "-u -L fifo1 -L link1 fifo1 link1" '--- fifo1
++++ link1
+@@ -1,2 +1,2 @@
+ 1
+-2
++3
+' "" ""
+
+testcmd "fifo symlinked file no follow" "-u -L fifo1 -L link1 fifo1 link1 --no-dereference" "File fifo1 is a fifo while file link1 is a symbolic link\n" "" ""
+testcmd "symlinked file stdin no follow" "-u -L link1 -L - link1 - --no-dereference" "File link1 is a symbolic link while file - is a fifo\n" "" "test"
+rm fifo1 fifo2 link1 file1
+
 echo -e 'int bar() {
 }
 
@@ -102,6 +129,7 @@ testcmd 'show function' "--show-function-line=' {$' -U1 -L lll -L rrr a b" \
  }
 ' \
 '' ''
+rm a b
 
 seq 1 100000 > one
 seq 1 4 100000 > two
diff --git a/tests/file.test b/tests/file.test
index a749c695..8dddfe3f 100755
--- a/tests/file.test
+++ b/tests/file.test
@@ -70,6 +70,9 @@ toyonly test_line "Android NDK short ELF note" "elf/ndk-elf-note-short" \
     "ELF shared object, 32-bit LSB arm, EABI5, soft float, dynamic (/system/bin/linker), for Android 28, BuildID=da6a5f4ca8da163b9339326e626d8a3c, stripped\n" "" ""
 toyonly test_line "ELF static fdpic" "elf/fdstatic" \
     "ELF executable (fdpic), 32-bit MSB sh, static, stripped\n" "" ""
+echo -ne '\x7fELF\00000000000000000000000000000000000000000000' > bad-bits
+testing "ELF bad bits" "file bad-bits" "bad-bits: ELF (bad type 12336), (bad class -1) (bad endian 48) unknown arch 12336\n" "" ""
+rm -f bad-bits
 
 testing "broken symlink" "file dangler" "dangler: broken symbolic link to $BROKEN\n" "" ""
 testing "symlink" "file symlink" "symlink: symbolic link to $LINK\n" "" ""
diff --git a/tests/files/tar/dir.tar b/tests/files/tar/dir.tar
new file mode 100644
index 00000000..84bacb59
Binary files /dev/null and b/tests/files/tar/dir.tar differ
diff --git a/tests/files/tar/oldsparse.tgz b/tests/files/tar/oldsparse.tgz
new file mode 100644
index 00000000..a5be64b1
Binary files /dev/null and b/tests/files/tar/oldsparse.tgz differ
diff --git a/tests/tar.test b/tests/tar.test
index 772f2da6..d07de368 100755
--- a/tests/tar.test
+++ b/tests/tar.test
@@ -283,6 +283,11 @@ rm -f blah.img
     "807664bcad0e827793318ff742991d6f006b2127\n" "" ""
   rm fweep2 fweep2.tar
 
+  testcmd 'extract obsolete sparse format' \
+    'xf "$FILES"/tar/oldsparse.tgz && sha1sum hello-sparse.c | head -c 12' \
+    '9714dc7ac8c0' '' ''
+  rm -f hello-sparse.c
+
 SKIP=0 # End of sparse tests
 
 mkdir -p links
@@ -424,6 +429,17 @@ touch file
 testing './file bug' 'tar c ./file > tar.tar && tar t ./file < tar.tar' \
   './file\n' '' ''
 
+skipnot [ $(id -u) -ne 0 ]  # Root defaults to -p
+testing 'honor umask' \
+  'umask 0022 && rm -rf dir && mkdir dir && tar xf $FILES/tar/dir.tar && stat -c%A dir dir/file' \
+  'drwxr-xr-x\n-rwxr-xr-x\n' '' ''
+testing 'extract changes directory permissions' \
+  'umask 0022 && rm -rf dir && mkdir dir && umask 0 && tar xf $FILES/tar/dir.tar && stat -c%A dir dir/file' \
+  'drwxrwxrwx\n-rwxrwxrwx\n' '' ''
+testing '-p overrides umask' \
+  'umask 0022 && rm -rf dir && mkdir dir && tar xpf $FILES/tar/dir.tar && stat -c%A dir dir/file' \
+  'drwxrwxrwx\n-rwxrwxrwx\n' '' ''
+
 if false
 then
 # Sequencing issues that leak implementation details out the interface
diff --git a/tests/test.test b/tests/test.test
index 2174f405..185eab8b 100644
--- a/tests/test.test
+++ b/tests/test.test
@@ -113,6 +113,16 @@ testing "-ge" "arith_test -ge" "eg" "" ""
 testing "-lt" "arith_test -lt" "l" "" ""
 testing "-le" "arith_test -le" "le" "" ""
 
+touch oldfile -d 1970-01-01
+touch newfile -d 2031-01-01
+
+testcmd "-ef" "newfile -ef newfile && echo yes" "yes\n" "" ""
+testcmd "-ef2" "newfile -ef oldfile || echo no" "no\n" "" ""
+testcmd "-ot" "oldfile -ot newfile && echo yes" "yes\n" "" ""
+testcmd "-ot2" "oldfile -ot oldfile || echo no" "no\n" "" ""
+testcmd "-nt" "newfile -nt oldfile && echo yes" "yes\n" "" ""
+testcmd "-nt2" "oldfile -nt newfile || echo no" "no\n" "" ""
+
 testing "positional" "test -a == -a && echo yes" "yes\n" "" ""
 testing "! stacks" 'test \! \! \! \! 2 -eq 2 && echo yes' "yes\n" "" ""
 
@@ -121,10 +131,12 @@ testing "<1" 'test abc \< def && echo yes' "yes\n" "" ""
 testing "<2" 'test def \< abc || echo yes' "yes\n" "" ""
 testing ">1" 'test abc \> def || echo yes' "yes\n" "" ""
 testing ">2" 'test def \> abc && echo yes' "yes\n" "" ""
+
+# toyonly doesn't work with TOYFLAG_NOHELP
 # bash only has this for [[ ]] but extra tests to _exclude_ silly...
-toyonly testcmd "=~" 'abc =~ a.c && echo yes' "yes\n" "" ""
-toyonly testcmd "=~ fail" 'abc =~ d.c; echo $?' '1\n' "" ""
-toyonly testcmd "=~ zero length match" 'abc =~ "1*" && echo yes' 'yes\n' '' ''
+#toyonly testcmd "=~" 'abc =~ a.c && echo yes' "yes\n" "" ""
+#toyonly testcmd "=~ fail" 'abc =~ d.c; echo $?' '1\n' "" ""
+#toyonly testcmd "=~ zero length match" 'abc =~ "1*" && echo yes' 'yes\n' '' ''
 
 # test ! = -o a
 # test ! \( = -o a \)
diff --git a/toys/lsb/dmesg.c b/toys/lsb/dmesg.c
index b7963b8b..29539af9 100644
--- a/toys/lsb/dmesg.c
+++ b/toys/lsb/dmesg.c
@@ -7,13 +7,13 @@
  * Linux 6.0 celebrates the 10th anniversary of this being in "testing":
  * http://kernel.org/doc/Documentation/ABI/testing/dev-kmsg
 
-USE_DMESG(NEWTOY(dmesg, "w(follow)CSTtrs#<1n#c[!Ttr][!Cc][!Sw]", TOYFLAG_BIN))
+USE_DMESG(NEWTOY(dmesg, "w(follow)W(follow-new)CSTtrs#<1n#c[!Ttr][!Cc][!SWw]", TOYFLAG_BIN|TOYFLAG_LINEBUF))
 
 config DMESG
   bool "dmesg"
   default y
   help
-    usage: dmesg [-Cc] [-r|-t|-T] [-n LEVEL] [-s SIZE] [-w]
+    usage: dmesg [-Cc] [-r|-t|-T] [-n LEVEL] [-s SIZE] [-w|-W]
 
     Print or control the kernel ring buffer.
 
@@ -26,6 +26,7 @@ config DMESG
     -T	Human readable timestamps
     -t	Don't print timestamps
     -w	Keep waiting for more output (aka --follow)
+    -W	Wait for output, only printing new messages
 */
 
 #define FOR_dmesg
@@ -136,12 +137,12 @@ void dmesg_main(void)
 
     // Each read returns one message. By default, we block when there are no
     // more messages (--follow); O_NONBLOCK is needed for for usual behavior.
-    fd = open("/dev/kmsg", O_RDONLY|O_NONBLOCK*!FLAG(w));
+    fd = open("/dev/kmsg", O_RDONLY|O_NONBLOCK*!(FLAG(w) || FLAG(W)));
     if (fd == -1) goto klogctl_mode;
 
     // SYSLOG_ACTION_CLEAR(5) doesn't actually remove anything from /dev/kmsg,
     // you need to seek to the last clear point.
-    lseek(fd, 0, SEEK_DATA);
+    lseek(fd, 0, FLAG(W) ? SEEK_END : SEEK_DATA);
 
     for (;;) {
       // why does /dev/kmesg return EPIPE instead of EAGAIN if oldest message
diff --git a/toys/net/host.c b/toys/net/host.c
index 4082a8f3..1d06159f 100644
--- a/toys/net/host.c
+++ b/toys/net/host.c
@@ -40,7 +40,7 @@ static const struct rrt {
   { "CNAME", "is a nickname for", 5 }, { "SOA", "start of authority", 6 },
   { "PTR", "domain name pointer", 12 }, { "HINFO", "host information", 13 },
   { "MX", "mail is handled", 15 }, { "TXT", "descriptive text", 16 },
-  { "AAAA", "has address", 28 }, { "SRV", "mail is handled", 33 }
+  { "AAAA", "has IPv6 address", 28 }, { "SRV", "has SRV record", 33 }
 };
 
 int xdn_expand(char *packet, char *endpkt, char *comp, char *expand, int elen)
diff --git a/toys/net/netcat.c b/toys/net/netcat.c
index 65eeea74..557380a4 100644
--- a/toys/net/netcat.c
+++ b/toys/net/netcat.c
@@ -22,8 +22,8 @@ config NETCAT
     -L	Listen and background each incoming connection (server mode)
     -l	Listen for one incoming connection, then exit
     -n	No DNS lookup
-    -o	Hex dump to FILE (-o- writes hex only to stdout)
-    -O	Hex dump to FILE (collated)
+    -o	Hex dump to FILE (show packets, -o- writes hex only to stdout)
+    -O	Hex dump to FILE (streaming mode)
     -p	Local port number
     -q	Quit SECONDS after EOF on stdin, even if stdout hasn't closed yet
     -s	Local source address
diff --git a/toys/other/blkid.c b/toys/other/blkid.c
index cdeb3a6f..f6502e7c 100644
--- a/toys/other/blkid.c
+++ b/toys/other/blkid.c
@@ -205,6 +205,7 @@ static void do_blkid(int fd, char *name)
         if (!(i&1)) *s++ = '-';
         *s++ = toybuf[uoff++];
       }
+      *s = 0;
     } else {
       for (j = 0; j < 16; j++)
         s += sprintf(s, "-%02x"+!(0x550 & (1<<j)), toybuf[uoff+j]);
diff --git a/toys/other/devmem.c b/toys/other/devmem.c
index 43ddacd2..9f9a9e03 100644
--- a/toys/other/devmem.c
+++ b/toys/other/devmem.c
@@ -2,21 +2,28 @@
  *
  * Copyright 2019 The Android Open Source Project
 
-USE_DEVMEM(NEWTOY(devmem, "<1>3", TOYFLAG_USR|TOYFLAG_SBIN))
+USE_DEVMEM(NEWTOY(devmem, "<1(no-sync)f:", TOYFLAG_USR|TOYFLAG_SBIN))
 
 config DEVMEM
   bool "devmem"
   default y
   help
-    usage: devmem ADDR [WIDTH [DATA]]
+    usage: devmem [-f FILE] ADDR [WIDTH [DATA...]]
 
-    Read/write physical address. WIDTH is 1, 2, 4, or 8 bytes (default 4).
+    Read/write physical addresses. WIDTH is 1, 2, 4, or 8 bytes (default 4).
     Prefix ADDR with 0x for hexadecimal, output is in same base as address.
+
+    -f FILE		File to operate on (default /dev/mem)
+    --no-sync	Don't open the file with O_SYNC (for cached access)
 */
 
 #define FOR_devmem
 #include "toys.h"
 
+GLOBALS(
+  char *f;
+)
+
 unsigned long xatolu(char *str, int bytes)
 {
   char *end = str;
@@ -34,7 +41,8 @@ unsigned long xatolu(char *str, int bytes)
 
 void devmem_main(void)
 {
-  int writing = toys.optc == 3, page_size = sysconf(_SC_PAGESIZE), bytes = 4,fd;
+  int writing = toys.optc > 2, page_size = sysconf(_SC_PAGESIZE), bytes = 4, fd,
+    flags;
   unsigned long data = 0, map_off, map_len,
     addr = xatolu(*toys.optargs, sizeof(long));
   char *sizes = sizeof(long)==8 ? "1248" : "124";
@@ -49,13 +57,11 @@ void devmem_main(void)
     bytes = 1<<i;
   }
 
-  // DATA?
-  if (writing) data = xatolu(toys.optargs[2], bytes);
-
   // Map in just enough.
   if (CFG_TOYBOX_FORK) {
-    fd = xopen("/dev/mem", (writing ? O_RDWR : O_RDONLY) | O_SYNC);
-
+    flags = writing ? O_RDWR : O_RDONLY;
+    if (!FLAG(no_sync)) flags |= O_SYNC;
+    fd = xopen(TT.f ?: "/dev/mem", flags);
     map_off = addr & ~(page_size - 1ULL);
     map_len = (addr+bytes-map_off);
     map = xmmap(0, map_len, writing ? PROT_WRITE : PROT_READ, MAP_SHARED, fd,
@@ -64,12 +70,16 @@ void devmem_main(void)
     close(fd);
   } else p = (void *)addr;
 
-  // Not using peek()/poke() because registers care about size of read/write
+  // Not using peek()/poke() because registers care about size of read/write.
   if (writing) {
-    if (bytes==1) *(char *)p = data;
-    else if (bytes==2) *(unsigned short *)p = data;
-    else if (bytes==4) *(unsigned int *)p = data;
-    else if (sizeof(long)==8 && bytes==8) *(unsigned long *)p = data;
+    for (int i = 2; i < toys.optc; i++) {
+      data = xatolu(toys.optargs[i], bytes);
+      if (bytes==1) *(char *)p = data;
+      else if (bytes==2) *(unsigned short *)p = data;
+      else if (bytes==4) *(unsigned int *)p = data;
+      else if (sizeof(long)==8 && bytes==8) *(unsigned long *)p = data;
+      p += bytes;
+    }
   } else {
     if (bytes==1) data = *(char *)p;
     else if (bytes==2) data = *(unsigned short *)p;
diff --git a/toys/other/hwclock.c b/toys/other/hwclock.c
index 5186a2d1..2f11cd4e 100644
--- a/toys/other/hwclock.c
+++ b/toys/other/hwclock.c
@@ -41,7 +41,11 @@ GLOBALS(
 
 // Bug workaround for musl commit 2c2c3605d3b3 which rewrote the syscall
 // wrapper to not use the syscall, which is the only way to set kernel's sys_tz
+#ifdef _NR_settimeofday
 #define settimeofday(x, tz) syscall(__NR_settimeofday, (void *)0, (void *)tz)
+#else
+#define settimeofday(x, tz) ((tz)->tz_minuteswest = 0)
+#endif
 
 void hwclock_main()
 {
diff --git a/toys/other/lsusb.c b/toys/other/lsusb.c
index 6bbfe0df..bf0f13f8 100644
--- a/toys/other/lsusb.c
+++ b/toys/other/lsusb.c
@@ -4,7 +4,7 @@
  * Copyright 2013 Isaac Dunham <ibid.ag@gmail.com>
 
 USE_LSUSB(NEWTOY(lsusb, "i:", TOYFLAG_USR|TOYFLAG_BIN))
-USE_LSPCI(NEWTOY(lspci, "emkn@x@i:", TOYFLAG_USR|TOYFLAG_BIN))
+USE_LSPCI(NEWTOY(lspci, "eDmkn@x@i:", TOYFLAG_USR|TOYFLAG_BIN))
 
 config LSPCI
   bool "lspci"
@@ -19,6 +19,7 @@ config LSPCI
     -k	Show kernel driver
     -m	Machine readable
     -n	Numeric output (-nn for both)
+    -D	Print domain numbers
     -x	Hex dump of config space (64 bytes; -xxx for 256, -xxxx for 4096)
 
 config LSUSB
@@ -192,11 +193,13 @@ static int list_pci(struct dirtree *new)
   char *driver = 0, buf[16], *ss, *names[3];
   int cvd[3] = {0}, ii, revision = 0;
   off_t len = sizeof(toybuf);
+  /* skip 0000: part by default */
+  char *bus = strchr(new->name, ':') + 1;
 
 // Output formats: -n, -nn, -m, -nm, -nnm, -k
 
   if (!new->parent) return DIRTREE_RECURSE;
-  if (strlen(new->name)<6) return 0;
+  if (!bus || strlen(new->name)<6) return 0;
   TT.count = 0;
 
   // Load revision
@@ -214,11 +217,12 @@ static int list_pci(struct dirtree *new)
   if (!FLAG(e)) cvd[0] >>= 8;
 
   // Output line according to flags
-  printf("%s", new->name+5);
+  if (FLAG(D) || strncmp(new->name, "0000:", bus-new->name)) bus = new->name;
+  printf("%s", bus);
   for (ii = 0; ii<3; ii++) {
     sprintf(buf, "%0*x", 6-2*(ii||!FLAG(e)), cvd[ii]);
     if (!TT.n) printf(FLAG(m) ? " \"%s\"" : ": %s"+(ii!=1), names[ii] ? : buf);
-    else if (TT.n==1) printf(FLAG(m) ? " \"%s\"" : (ii==2) ? "%s " : " %s:", buf);
+    else if (TT.n==1) printf(FLAG(m) ? " \"%s\"" : (ii==2)?"%s ":" %s:", buf);
     else if (!FLAG(m)) {
       // This one permutes the order, so do it all first time and abort loop
       printf(" %s [%s]: %s %s [%04x:%04x]", names[0], buf, names[1], names[2],
@@ -234,9 +238,7 @@ static int list_pci(struct dirtree *new)
     FILE *fp;
     int b, col = 0, max = (TT.x >= 4) ? 4096 : ((TT.x >= 3) ? 256 : 64);
 
-    // TODO: where does the "0000:" come from?
-    snprintf(toybuf, sizeof(toybuf), "/sys/bus/pci/devices/0000:%s/config",
-      new->name+5);
+    snprintf(toybuf, sizeof(toybuf), "/sys/bus/pci/devices/%s/config", new->name);
     fp = xfopen(toybuf, "r");
     while ((b = fgetc(fp)) != EOF) {
       if ((col % 16) == 0) printf("%02x: ", col & 0xf0);
diff --git a/toys/pending/awk.c b/toys/pending/awk.c
new file mode 100644
index 00000000..fd7675ec
--- /dev/null
+++ b/toys/pending/awk.c
@@ -0,0 +1,4554 @@
+/* awk.c - An awk implementation.
+ * vi: tabstop=2 softtabstop=2 shiftwidth=2
+ *
+ * Copyright 2024 Ray Gardner <raygard@gmail.com>
+ *
+ * See https://pubs.opengroup.org/onlinepubs/9699919799/utilities/awk.html
+
+USE_AWK(NEWTOY(awk, "F:v*f*bc", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
+
+config AWK
+  bool "awk"
+  default n
+  help
+    usage:  awk [-F sepstring] [-v assignment]... program [argument...]
+      or:
+            awk [-F sepstring] -f progfile [-f progfile]... [-v assignment]...
+                  [argument...]
+      also:
+      -b : use bytes, not characters
+      -c : compile only, do not run
+*/
+
+#define FOR_awk
+#include "toys.h"
+
+GLOBALS(
+  struct arg_list *f;
+  struct arg_list *v;
+  char *F;
+
+  struct scanner_state {
+      char *p;
+      char *progstring;
+      struct arg_list *prog_args;
+      char *filename;
+      char *line;
+      size_t line_size;
+      ssize_t line_len;
+      int line_num;
+      int ch;
+      FILE *fp;
+      // state includes latest token seen
+      int tok;
+      int tokbuiltin;
+      int toktype;
+      char *tokstr;
+      size_t maxtok;
+      size_t toklen;
+      double numval;
+      int error;  // Set if lexical error.
+  } *scs;
+  char *tokstr;
+  int prevtok;
+
+  struct compiler_globals {
+    int in_print_stmt;
+    int paren_level;
+    int in_function_body;
+    int funcnum;
+    int nparms;
+    int compile_error_count;
+    int first_begin;
+    int last_begin;
+    int first_end;
+    int last_end;
+    int first_recrule;
+    int last_recrule;
+    int break_dest;
+    int continue_dest;
+    int stack_offset_to_fix;  // fixup stack if return in for(e in a)
+    int range_pattern_num;
+    int rule_type;  // tkbegin, tkend, or 0
+  } cgl;
+
+  // zvalue: the main awk value type
+  // Can be number or string or both, or else map (array) or regex
+  struct zvalue {
+    unsigned flags;
+    double num;
+    union { // anonymous union not in C99; not going to fix it now.
+      struct zstring *vst;
+      struct zmap *map;
+      regex_t *rx;
+    };
+  } nozvalue;   // to shut up compiler warning TODO FIXME
+
+  struct runtime_globals {
+    struct zvalue cur_arg;
+    FILE *fp;           // current data file
+    int narg;           // cmdline arg index
+    int nfiles;         // num of cmdline data file args processed
+    int eof;            // all cmdline files (incl. stdin) read
+    char *recptr;
+    struct zstring *zspr;      // Global to receive sprintf() string value
+  } rgl;
+
+  // Expanding sequential list
+  struct zlist {
+    char *base, *limit, *avail;
+    size_t size;
+  } globals_table,  // global symbol table
+    locals_table,     // local symbol table
+    func_def_table;  // function symbol table
+  // runtime lists
+  struct zlist literals, fields, zcode, stack;
+
+  char *progname;
+
+  int spec_var_limit;
+  int zcode_last;
+  struct zvalue *stackp;  // top of stack ptr
+
+  char *pbuf;   // Used for number formatting in num_to_zstring()
+#define RS_MAX  64
+  char rs_last[RS_MAX];
+  regex_t rx_rs_default, rx_rs_last;
+  regex_t rx_default, rx_last, rx_printf_fmt;
+#define FS_MAX  64
+  char fs_last[FS_MAX];
+  char one_char_fs[4];
+  int nf_internal;  // should match NF
+  char range_sw[64];   // FIXME TODO quick and dirty set of range switches
+  int file_cnt, std_file_cnt;
+
+  struct zfile {
+    struct zfile *next;
+    char *fn;
+    FILE *fp;
+    char mode;  // w, a, or r
+    char file_or_pipe;  // 1 if file, 0 if pipe
+    char is_tty;
+    char is_std_file;
+    char *recbuf;
+    size_t recbufsize;
+    char *recbuf_multi;
+    size_t recbufsize_multi;
+    char *recbuf_multx;
+    size_t recbufsize_multx;
+    int recoffs, endoffs;
+  } *zfiles, *cfile, *zstdout;
+)
+
+static void awk_exit(int status)
+{
+  toys.exitval = status;
+  xexit();
+}
+#ifdef __GNUC__
+#define ATTR_FALLTHROUGH_INTENDED __attribute__ ((fallthrough))
+#else
+#define ATTR_FALLTHROUGH_INTENDED
+#endif
+
+////////////////////
+////   declarations
+////////////////////
+
+#define PBUFSIZE  512 // For num_to_zstring()
+
+enum toktypes {
+    // EOF (use -1 from stdio.h)
+    ERROR = 2, NEWLINE, VAR, NUMBER, STRING, REGEX, USERFUNC, BUILTIN, TOKEN,
+    KEYWORD
+    };
+
+// Must align with lbp_table[]
+enum tokens {
+    tkunusedtoken, tkeof, tkerr, tknl,
+    tkvar, tknumber, tkstring, tkregex, tkfunc, tkbuiltin,
+
+// static char *ops = " ;  ,  [  ]  (  )  {  }  $  ++ -- ^  !  *  /  %  +  -     "
+//        "<  <= != == >  >= ~  !~ && || ?  :  ^= %= *= /= += -= =  >> |  ";
+    tksemi, tkcomma, tklbracket, tkrbracket, tklparen, tkrparen, tklbrace,
+    tkrbrace, tkfield, tkincr, tkdecr, tkpow, tknot, tkmul, tkdiv, tkmod,
+    tkplus, tkminus,
+    tkcat, // !!! Fake operator for concatenation (just adjacent string exprs)
+    tklt, tkle, tkne, tkeq, tkgt, tkge, tkmatchop, tknotmatch, tkand, tkor,
+    tkternif, tkternelse, tkpowasgn, tkmodasgn, tkmulasgn, tkdivasgn,
+    tkaddasgn, tksubasgn, tkasgn, tkappend, tkpipe,
+
+// static char *keywords = " in        BEGIN     END       if        else      "
+//    "while     for       do        break     continue  exit      function  "
+//    "return    next      nextfile  delete    print     printf    getline   ";
+    tkin, tkbegin, tkend, tkif, tkelse,
+    tkwhile, tkfor, tkdo, tkbreak, tkcontinue, tkexit, tkfunction,
+    tkreturn, tknext, tknextfile, tkdelete, tkprint, tkprintf, tkgetline,
+
+// static char *builtins = " atan2     cos       sin       exp       "
+//    "log       sqrt      int       rand      srand     length    "
+//    "tolower   toupper   system    fflush    "
+//    "and       or        xor       lshift    rshift    ";
+    tkatan2, tkcos, tksin, tkexp, tklog, tksqrt, tkint, tkrand, tksrand,
+    tklength, tktolower, tktoupper, tksystem, tkfflush,
+    tkband, tkbor, tkbxor, tklshift, tkrshift,
+
+// static char *specialfuncs = " close     index     match     split     "
+//    "sub       gsub      sprintf   substr    ";
+    tkclose, tkindex, tkmatch, tksplit,
+    tksub, tkgsub, tksprintf, tksubstr, tklasttk
+    };
+
+enum opcodes {
+    opunusedop = tklasttk,
+    opvarref, opmapref, opfldref, oppush, opdrop, opdrop_n, opnotnot,
+    oppreincr, oppredecr, oppostincr, oppostdecr, opnegate, opjump, opjumptrue,
+    opjumpfalse, opprepcall, opmap, opmapiternext, opmapdelete, opmatchrec,
+    opquit, opprintrec, oprange1, oprange2, oprange3, oplastop
+};
+
+// Special variables (POSIX). Must align with char *spec_vars[]
+enum spec_var_names { ARGC=1, ARGV, CONVFMT, ENVIRON, FILENAME, FNR, FS, NF,
+    NR, OFMT, OFS, ORS, RLENGTH, RS, RSTART, SUBSEP };
+
+struct symtab_slot {    // global symbol table entry
+  unsigned flags;
+  char *name;
+};
+
+// zstring: flexible string type.
+// Capacity must be > size because we insert a NUL byte.
+struct zstring {
+  int refcnt;
+  unsigned size;
+  unsigned capacity;
+  char str[];   // C99 flexible array member
+};
+
+// Flag bits for zvalue and symbol tables
+#define ZF_MAYBEMAP (1u << 1)
+#define ZF_MAP      (1u << 2)
+#define ZF_SCALAR   (1u << 3)
+#define ZF_NUM      (1u << 4)
+#define ZF_RX       (1u << 5)
+#define ZF_STR      (1u << 6)
+#define ZF_NUMSTR   (1u << 7)   // "numeric string" per posix
+#define ZF_REF      (1u << 9)   // for lvalues
+#define ZF_MAPREF   (1u << 10)  // for lvalues
+#define ZF_FIELDREF (1u << 11)  // for lvalues
+#define ZF_EMPTY_RX (1u << 12)
+#define ZF_ANYMAP   (ZF_MAP | ZF_MAYBEMAP)
+
+// Macro to help facilitate possible future change in zvalue layout.
+#define ZVINIT(flags, num, ptr) {(flags), (double)(num), {(ptr)}}
+
+#define IS_STR(zvalp) ((zvalp)->flags & ZF_STR)
+#define IS_RX(zvalp) ((zvalp)->flags & ZF_RX)
+#define IS_NUM(zvalp) ((zvalp)->flags & ZF_NUM)
+#define IS_MAP(zvalp) ((zvalp)->flags & ZF_MAP)
+#define IS_EMPTY_RX(zvalp) ((zvalp)->flags & ZF_EMPTY_RX)
+
+#define GLOBAL      ((struct symtab_slot *)TT.globals_table.base)
+#define LOCAL       ((struct symtab_slot *)TT.locals_table.base)
+#define FUNC_DEF    ((struct functab_slot *)TT.func_def_table.base)
+
+#define LITERAL     ((struct zvalue *)TT.literals.base)
+#define STACK       ((struct zvalue *)TT.stack.base)
+#define FIELD       ((struct zvalue *)TT.fields.base)
+
+#define ZCODE       ((int *)TT.zcode.base)
+
+#define FUNC_DEFINED    (1u)
+#define FUNC_CALLED     (2u)
+
+#define MIN_STACK_LEFT 1024
+
+struct functab_slot {    // function symbol table entry
+  unsigned flags;
+  char *name;
+  struct zlist function_locals;
+  int zcode_addr;
+};
+
+// Elements of the hash table (key/value pairs)
+struct zmap_slot {
+  int hash;       // store hash key to speed hash table expansion
+  struct zstring *key;
+  struct zvalue val;
+};
+#define ZMSLOTINIT(hash, key, val) {hash, key, val}
+
+// zmap: Mapping data type for arrays; a hash table. Values in hash are either
+// 0 (unused), -1 (marked deleted), or one plus the number of the zmap slot
+// containing a key/value pair. The zlist slot entries are numbered from 0 to
+// count-1, so need to add one to distinguish from unused.  The probe sequence
+// is borrowed from Python dict, using the "perturb" idea to mix in upper bits
+// of the original hash value.
+struct zmap {
+  unsigned mask;  // tablesize - 1; tablesize is 2 ** n
+  int *hash;      // (mask + 1) elements
+  int limit;      // 80% of table size ((mask+1)*8/10)
+  int count;      // number of occupied slots in hash
+  int deleted;    // number of deleted slots
+  struct zlist slot;     // expanding list of zmap_slot elements
+};
+
+#define MAPSLOT    ((struct zmap_slot *)(m->slot).base)
+#define FFATAL(format, ...) zzerr("$" format, __VA_ARGS__)
+#define FATAL(...) zzerr("$%s\n", __VA_ARGS__)
+#define XERR(format, ...) zzerr(format, __VA_ARGS__)
+
+#define NO_EXIT_STATUS  (9999987)  // value unlikely to appear in exit stmt
+
+ssize_t getline(char **lineptr, size_t *n, FILE *stream);
+ssize_t getdelim(char ** restrict lineptr, size_t * restrict n, int delimiter, FILE *stream);
+
+
+
+////////////////////
+//// lib
+////////////////////
+
+static void xfree(void *p)
+{
+  free(p);
+}
+
+static int hexval(int c)
+{
+  // Assumes c is valid hex digit
+  return isdigit(c) ? c - '0' : (c | 040) - 'a' + 10;
+}
+
+////////////////////
+//// common defs
+////////////////////
+
+// These (ops, keywords, builtins) must align with enum tokens
+static char *ops = " ;  ,  [  ]  (  )  {  }  $  ++ -- ^  !  *  /  %  +  -  .. "
+        "<  <= != == >  >= ~  !~ && || ?  :  ^= %= *= /= += -= =  >> |  ";
+
+static char *keywords = " in        BEGIN     END       if        else      "
+    "while     for       do        break     continue  exit      function  "
+    "return    next      nextfile  delete    print     printf    getline   ";
+
+static char *builtins = " atan2     cos       sin       exp       log       "
+    "sqrt      int       rand      srand     length    "
+    "tolower   toupper   system    fflush    "
+    "and       or        xor       lshift    rshift    "
+    "close     index     match     split     "
+    "sub       gsub      sprintf   substr    ";
+
+static void zzerr(char *format, ...)
+{
+  va_list args;
+  int fatal_sw = 0;
+  fprintf(stderr, "%s: ", TT.progname);
+  if (format[0] == '$') {
+    fprintf(stderr, "FATAL: ");
+    format++;
+    fatal_sw = 1;
+  }
+  fprintf(stderr, "file %s line %d: ", TT.scs->filename, TT.scs->line_num);
+  va_start(args, format);
+  vfprintf(stderr, format, args);
+  va_end(args);
+  if (format[strlen(format)-1] != '\n') fputc('\n', stderr); // TEMP FIXME !!!
+  fflush(stderr);
+  if (fatal_sw) awk_exit(2);
+        // Don't bump error count for warnings
+  else if (!strstr(format, "arning")) TT.cgl.compile_error_count++;
+}
+
+static void get_token_text(char *op, int tk)
+{
+  // This MUST ? be changed if ops string or tk... assignments change!
+  memmove(op, ops + 3 * (tk - tksemi) + 1, 2);
+  op[ op[1] == ' ' ? 1 : 2 ] = 0;
+}
+
+////////////////////
+/// UTF-8
+////////////////////
+
+// Return number of bytes in 'cnt' utf8 codepoints
+static int bytesinutf8(char *str, size_t len, size_t cnt)
+{
+  if (FLAG(b)) return cnt;
+  unsigned wch;
+  char *lim = str + len, *s0 = str;
+  while (cnt-- && str < lim) {
+    int r = utf8towc(&wch, str, lim - str);
+    str += r > 0 ? r : 1;
+  }
+  return str - s0;
+}
+
+// Return number of utf8 codepoints in str
+static int utf8cnt(char *str, size_t len)
+{
+  unsigned wch;
+  int cnt = 0;
+  char *lim;
+  if (!len || FLAG(b)) return len;
+  for (lim = str + len; str < lim; cnt++) {
+    int r = utf8towc(&wch, str, lim - str);
+    str += r > 0 ? r : 1;
+  }
+  return cnt;
+}
+
+////////////////////
+////   zlist
+////////////////////
+
+static struct zlist *zlist_initx(struct zlist *p, size_t size, size_t count)
+{
+  p->base = p->avail = xzalloc(count * size);
+  p->limit = p->base + size * count;
+  p->size = size;
+  return p;
+}
+
+static struct zlist *zlist_init(struct zlist *p, size_t size)
+{
+#define SLIST_MAX_INIT_BYTES 128
+  return zlist_initx(p, size, SLIST_MAX_INIT_BYTES / size);
+}
+
+// This is called from zlist_append() and add_stack() in run
+static void zlist_expand(struct zlist *p)
+{
+  size_t offset = p->avail - p->base;
+  size_t cap = p->limit - p->base;
+  size_t newcap = maxof(cap + p->size, ((cap / p->size) * 3 / 2) * p->size);
+  if (newcap <= cap) error_exit("mem req error");
+  char *base = xrealloc(p->base, newcap);
+  p->base = base;
+  p->limit = base + newcap;
+  p->avail = base + offset;
+}
+
+static size_t zlist_append(struct zlist *p, void *obj)
+{
+  // Insert obj (p->size bytes) at end of list, expand as needed.
+  // Return scaled offset to newly inserted obj; i.e. the
+  // "slot number" 0, 1, 2,...
+  void *objtemp = 0;
+  if (p->avail > p->limit - p->size) {
+    objtemp = xmalloc(p->size);     // Copy obj in case it is in
+    memmove(objtemp, obj, p->size); // the area realloc might free!
+    obj = objtemp;
+    zlist_expand(p);
+  }
+  memmove(p->avail, obj, p->size);
+  if (objtemp) xfree(objtemp);
+  p->avail += p->size;
+  return (p->avail - p->base - p->size) / p->size;  // offset of updated slot
+}
+
+static int zlist_len(struct zlist *p)
+{
+  return (p->avail - p->base) / p->size;
+}
+
+////////////////////
+////   zstring
+////////////////////
+
+static void zstring_release(struct zstring **s)
+{
+  if (*s && (**s).refcnt-- == 0) xfree(*s); //free_zstring(s);
+  *s = 0;
+}
+
+static void zstring_incr_refcnt(struct zstring *s)
+{
+  if (s) s->refcnt++;
+}
+
+// !! Use only if 'to' is NULL or its refcnt is 0.
+static struct zstring *zstring_modify(struct zstring *to, size_t at, char *s, size_t n)
+{
+  size_t cap = at + n + 1;
+  if (!to || to->capacity < cap) {
+    to = xrealloc(to, sizeof(*to) + cap);
+    to->capacity = cap;
+    to->refcnt = 0;
+  }
+  memcpy(to->str + at, s, n);
+  to->size = at + n;
+  to->str[to->size] = '\0';
+  return to;
+}
+
+// The 'to' pointer may move by realloc, so return (maybe updated) pointer.
+// If refcnt is nonzero then there is another pointer to this zstring,
+// so copy this one and release it. If refcnt is zero we can mutate this.
+static struct zstring *zstring_update(struct zstring *to, size_t at, char *s, size_t n)
+{
+  if (to && to->refcnt) {
+    struct zstring *to_before = to;
+    to = zstring_modify(0, 0, to->str, to->size);
+    zstring_release(&to_before);
+  }
+  return zstring_modify(to, at, s, n);
+}
+
+static struct zstring *zstring_copy(struct zstring *to, struct zstring *from)
+{
+  return zstring_update(to, 0, from->str, from->size);
+}
+
+static struct zstring *zstring_extend(struct zstring *to, struct zstring *from)
+{
+  return zstring_update(to, to->size, from->str, from->size);
+}
+
+static struct zstring *new_zstring(char *s, size_t size)
+{
+  return zstring_modify(0, 0, s, size);
+}
+
+////////////////////
+////   zvalue
+////////////////////
+
+static struct zvalue uninit_zvalue = ZVINIT(0, 0.0, 0);
+
+// This will be reassigned in init_globals() with an empty string.
+// It's a special value used for "uninitialized" field vars
+// referenced past $NF. See push_field().
+static struct zvalue uninit_string_zvalue = ZVINIT(0, 0.0, 0);
+
+static struct zvalue new_str_val(char *s)
+{
+  // Only if no nul inside string!
+  struct zvalue v = ZVINIT(ZF_STR, 0.0, new_zstring(s, strlen(s)));
+  return v;
+}
+
+static void zvalue_release_zstring(struct zvalue *v)
+{
+  if (v && ! (v->flags & (ZF_ANYMAP | ZF_RX))) zstring_release(&v->vst);
+}
+
+// push_val() is used for initializing globals (see init_compiler())
+// but mostly used in runtime
+// WARNING: push_val may change location of v, so do NOT depend on it after!
+// Note the incr refcnt used to be after the zlist_append, but that caused a
+// heap-use-after-free error when the zlist_append relocated the zvalue being
+// pushed, invalidating the v pointer.
+static void push_val(struct zvalue *v)
+{
+  if (IS_STR(v) && v->vst) v->vst->refcnt++;  // inlined zstring_incr_refcnt()
+  *++TT.stackp = *v;
+}
+
+static void zvalue_copy(struct zvalue *to, struct zvalue *from)
+{
+  if (IS_RX(from)) *to = *from;
+  else {
+    zvalue_release_zstring(to);
+    *to = *from;
+    zstring_incr_refcnt(to->vst);
+  }
+}
+
+static void zvalue_dup_zstring(struct zvalue *v)
+{
+  struct zstring *z = new_zstring(v->vst->str, v->vst->size);
+  zstring_release(&v->vst);
+  v->vst = z;
+}
+
+////////////////////
+////   zmap (array) implementation
+////////////////////
+
+static int zstring_match(struct zstring *a, struct zstring *b)
+{
+  return a->size == b->size && memcmp(a->str, b->str, a->size) == 0;
+}
+
+static int zstring_hash(struct zstring *s)
+{   // djb2 -- small, fast, good enough for this
+  unsigned h = 5381;
+  char *p = s->str, *lim = p + s->size;
+  while (p < lim)
+    h = (h << 5) + h + *p++;
+  return h;
+}
+
+enum { PSHIFT = 5 };  // "perturb" shift -- see find_mapslot() below
+
+static struct zmap_slot *find_mapslot(struct zmap *m, struct zstring *key, int *hash, int *probe)
+{
+  struct zmap_slot *x = 0;
+  unsigned perturb = *hash = zstring_hash(key);
+  *probe = *hash & m->mask;
+  int n, first_deleted = -1;
+  while ((n = m->hash[*probe])) {
+    if (n > 0) {
+      x = &MAPSLOT[n-1];
+      if (*hash == x->hash && zstring_match(key, x->key)) {
+        return x;
+      }
+    } else if (first_deleted < 0) first_deleted = *probe;
+    // Based on technique in Python dict implementation. Comment there
+    // (https://github.com/python/cpython/blob/3.10/Objects/dictobject.c)
+    // says
+    //
+    // j = ((5*j) + 1) mod 2**i
+    // For any initial j in range(2**i), repeating that 2**i times generates
+    // each int in range(2**i) exactly once (see any text on random-number
+    // generation for proof).
+    //
+    // The addition of 'perturb' greatly improves the probe sequence. See
+    // the Python dict implementation for more details.
+    *probe = (*probe * 5 + 1 + (perturb >>= PSHIFT)) & m->mask;
+  }
+  if (first_deleted >= 0) *probe = first_deleted;
+  return 0;
+}
+
+static struct zvalue *zmap_find(struct zmap *m, struct zstring *key)
+{
+  int hash, probe;
+  struct zmap_slot *x = find_mapslot(m, key, &hash, &probe);
+  return x ? &x->val : 0;
+}
+
+static void zmap_init(struct zmap *m)
+{
+  enum {INIT_SIZE = 8};
+  m->mask = INIT_SIZE - 1;
+  m->hash = xzalloc(INIT_SIZE * sizeof(*m->hash));
+  m->limit = INIT_SIZE * 8 / 10;
+  m->count = 0;
+  m->deleted = 0;
+  zlist_init(&m->slot, sizeof(struct zmap_slot));
+}
+
+static void zvalue_map_init(struct zvalue *v)
+{
+  struct zmap *m = xmalloc(sizeof(*m));
+  zmap_init(m);
+  v->map = m;
+  v->flags |= ZF_MAP;
+}
+
+static void zmap_delete_map_incl_slotdata(struct zmap *m)
+{
+  for (struct zmap_slot *p = &MAPSLOT[0]; p < &MAPSLOT[zlist_len(&m->slot)]; p++) {
+    if (p->key) zstring_release(&p->key);
+    if (p->val.vst) zstring_release(&p->val.vst);
+  }
+  xfree(m->slot.base);
+  xfree(m->hash);
+}
+
+static void zmap_delete_map(struct zmap *m)
+{
+  zmap_delete_map_incl_slotdata(m);
+  zmap_init(m);
+}
+
+static void zmap_rehash(struct zmap *m)
+{
+  // New table is twice the size of old.
+  int size = m->mask + 1;
+  unsigned mask = 2 * size - 1;
+  int *h = xzalloc(2 * size * sizeof(*m->hash));
+  // Step through the old hash table, set up location in new table.
+  for (int i = 0; i < size; i++) {
+    int n = m->hash[i];
+    if (n > 0) {
+      int hash = MAPSLOT[n-1].hash;
+      unsigned perturb = hash;
+      int p = hash & mask;
+      while (h[p]) {
+        p = (p * 5 + 1 + (perturb >>= PSHIFT)) & mask;
+      }
+      h[p] = n;
+    }
+  }
+  m->mask = mask;
+  xfree(m->hash);
+  m->hash = h;
+  m->limit = 2 * size * 8 / 10;
+}
+
+static struct zmap_slot *zmap_find_or_insert_key(struct zmap *m, struct zstring *key)
+{
+  int hash, probe;
+  struct zmap_slot *x = find_mapslot(m, key, &hash, &probe);
+  if (x) return x;
+  // not found; insert it.
+  if (m->count == m->limit) {
+    zmap_rehash(m);         // rehash if getting too full.
+    // rerun find_mapslot to get new probe index
+    x = find_mapslot(m, key, &hash, &probe);
+  }
+  // Assign key to new slot entry and bump refcnt.
+  struct zmap_slot zs = ZMSLOTINIT(hash, key, (struct zvalue)ZVINIT(0, 0.0, 0));
+  zstring_incr_refcnt(key);
+  int n = zlist_append(&m->slot, &zs);
+  m->count++;
+  m->hash[probe] = n + 1;
+  return &MAPSLOT[n];
+}
+
+static void zmap_delete(struct zmap *m, struct zstring *key)
+{
+  int hash, probe;
+  struct zmap_slot *x = find_mapslot(m, key, &hash, &probe);
+  if (!x) return;
+  zstring_release(&MAPSLOT[m->hash[probe] - 1].key);
+  m->hash[probe] = -1;
+  m->deleted++;
+}
+
+////////////////////
+//// scan (lexical analyzer)
+////////////////////
+
+// TODO:
+// IS line_num getting incr correctly? Newline counts as start of line!?
+// Handle nuls in file better.
+// Open files "rb" and handle CRs in program.
+// Roll gch() into get_char() ?
+// Deal with signed char (at EOF? elsewhere?)
+//
+// 2023-01-11: Allow nul bytes inside strings? regexes?
+
+static void progfile_open(void)
+{
+  TT.scs->filename = TT.scs->prog_args->arg;
+  TT.scs->prog_args = TT.scs->prog_args->next;
+  TT.scs->fp = stdin;
+  if (strcmp(TT.scs->filename, "-")) TT.scs->fp = fopen(TT.scs->filename, "r");
+  if (!TT.scs->fp) error_exit("Can't open %s", TT.scs->filename);
+  TT.scs->line_num = 0;
+}
+
+static int get_char(void)
+{
+  static char *nl = "\n";
+  // On first entry, TT.scs->p points to progstring if any, or null string.
+  for (;;) {
+    int c = *(TT.scs->p)++;
+    if (c) {
+      return c;
+    }
+    if (TT.scs->progstring) {  // Fake newline at end of progstring.
+      if (TT.scs->progstring == nl) return EOF;
+      TT.scs->p = TT.scs->progstring = nl;
+      continue;
+    }
+    // Here if getting from progfile(s).
+    if (TT.scs->line == nl) return EOF;
+    if (!TT.scs->fp) {
+      progfile_open();
+    // The "  " + 1 is to set p to null string but allow ref to prev char for
+    // "lastchar" test below.
+    }
+    // Save last char to allow faking final newline.
+    int lastchar = (TT.scs->p)[-2];
+    TT.scs->line_len = getline(&TT.scs->line, &TT.scs->line_size, TT.scs->fp);
+    if (TT.scs->line_len > 0) {
+      TT.scs->line_num++;
+      TT.scs->p = TT.scs->line;
+      continue;
+    }
+    // EOF
+    // FIXME TODO or check for error? feof() vs. ferror()
+    fclose(TT.scs->fp);
+    TT.scs->fp = 0;
+    TT.scs->p = "  " + 2;
+    if (!TT.scs->prog_args) {
+      xfree(TT.scs->line);
+      if (lastchar == '\n') return EOF;
+      // Fake final newline
+      TT.scs->line = TT.scs->p = nl;
+    }
+  }
+}
+
+static void append_this_char(int c)
+{
+  if (TT.scs->toklen == TT.scs->maxtok - 1) {
+    TT.scs->maxtok *= 2;
+    TT.scs->tokstr = xrealloc(TT.scs->tokstr, TT.scs->maxtok);
+  }
+  TT.scs->tokstr[TT.scs->toklen++] = c;
+  TT.scs->tokstr[TT.scs->toklen] = 0;
+}
+
+static void gch(void)
+{
+  // FIXME probably not right place to skip CRs.
+  do {
+    TT.scs->ch = get_char();
+  } while (TT.scs->ch == '\r');
+}
+
+static void append_char(void)
+{
+  append_this_char(TT.scs->ch);
+  gch();
+}
+
+static int find_keyword_or_builtin(char *table,
+    int first_tok_in_table)
+{
+  char s[16] = " ", *p;
+  // keywords and builtin functions are spaced 10 apart for strstr() lookup,
+  // so must be less than that long.
+  if (TT.scs->toklen >= 10) return 0;
+  strcat(s, TT.scs->tokstr);
+  strcat(s, " ");
+  p = strstr(table, s);
+  if (!p) return 0;
+  return first_tok_in_table + (p - table) / 10;
+}
+
+static int find_token(void)
+{
+  char s[6] = " ", *p;
+  // tokens are spaced 3 apart for strstr() lookup, so must be less than
+  // that long.
+  strcat(s, TT.scs->tokstr);
+  strcat(s, " ");
+  p = strstr(ops, s);
+  if (!p) return 0;
+  return tksemi + (p - ops) / 3;
+}
+
+static int find_keyword(void)
+{
+  return find_keyword_or_builtin(keywords, tkin);
+}
+
+static int find_builtin(void)
+{
+  return find_keyword_or_builtin(builtins, tkatan2);
+}
+
+static void get_number(void)
+{
+  // Assumes TT.scs->ch is digit or dot on entry.
+  // TT.scs->p points to the following character.
+  // OK formats: 1 1. 1.2 1.2E3 1.2E+3 1.2E-3 1.E2 1.E+2 1.E-2 1E2 .1 .1E2
+  // .1E+2 .1E-2
+  // NOT OK: . .E .E1 .E+ .E+1 ; 1E .1E 1.E 1.E+ 1.E- parse as number
+  // followed by variable E.
+  // gawk accepts 12.E+ and 12.E- as 12; nawk & mawk say syntax error.
+  char *leftover;
+  int len;
+  TT.scs->numval = strtod(TT.scs->p - 1, &leftover);
+  len = leftover - TT.scs->p + 1;
+  if (len == 0) {
+    append_char();
+    TT.scs->toktype = ERROR;
+    TT.scs->tok = tkerr;
+    TT.scs->error = 1;
+    FFATAL("Unexpected token '%s'\n", TT.scs->tokstr);
+    return;
+  }
+  while (len--)
+    append_char();
+}
+
+static void get_string_or_regex(int endchar)
+{
+  gch();
+  while (TT.scs->ch != endchar) {
+    if (TT.scs->ch == '\n') {
+      // FIXME Handle unterminated string or regex. Is this OK?
+      // FIXME TODO better diagnostic here?
+      XERR("%s\n", "unterminated string or regex");
+      break;
+    } else if (TT.scs->ch == '\\') {
+      // \\ \a \b \f \n \r \t \v \" \/ \ddd
+      char *p, *escapes = "\\abfnrtv\"/";
+      gch();
+      if (TT.scs->ch == '\n') {  // backslash newline is continuation
+        gch();
+        continue;
+      } else if ((p = strchr(escapes, TT.scs->ch))) {
+        // posix regex does not use these escapes,
+        // but awk does, so do them.
+        int c = "\\\a\b\f\n\r\t\v\"/"[p-escapes];
+        append_this_char(c);
+        // Need to double up \ inside literal regex
+        if (endchar == '/' && c == '\\') append_this_char('\\');
+        gch();
+      } else if (TT.scs->ch == 'x') {
+        gch();
+        if (isxdigit(TT.scs->ch)) {
+          int c = hexval(TT.scs->ch);
+          gch();
+          if (isxdigit(TT.scs->ch)) {
+            c = c * 16 + hexval(TT.scs->ch);
+            gch();
+          }
+          append_this_char(c);
+        } else append_this_char('x');
+      } else if (TT.scs->ch == 'u') {
+        gch();
+        if (isxdigit(TT.scs->ch)) {
+          int i = 0, j = 0, c = 0;
+          char codep[9] = {0};
+          do {
+            codep[j++] = TT.scs->ch;
+            gch();
+          } while (j < 8 && isxdigit(TT.scs->ch));
+          c = strtol(codep, 0, 16);
+          for (i = wctoutf8(codep, c), j = 0; j < i; j++)
+            append_this_char(codep[j]);
+        } else append_this_char('u');
+      } else if (isdigit(TT.scs->ch)) {
+        if (TT.scs->ch < '8') {
+          int k, c = 0;
+          for (k = 0; k < 3; k++) {
+            if (isdigit(TT.scs->ch) && TT.scs->ch < '8') {
+              c = c * 8 + TT.scs->ch - '0';
+              gch();
+            } else
+              break;
+          }
+          append_this_char(c);
+        } else {
+          append_char();
+        }
+      } else {
+        if (endchar == '/') {
+          // pass \ unmolested if not awk escape,
+          // so that regex routines can see it.
+          if (!strchr(".[]()*+?{}|^$-", TT.scs->ch)) {
+            XERR("warning: '\\%c' -- unknown regex escape\n", TT.scs->ch);
+          }
+          append_this_char('\\');
+        } else {
+          XERR("warning: '\\%c' treated as plain '%c'\n", TT.scs->ch, TT.scs->ch);
+        }
+      }
+    } else if (TT.scs->ch == EOF) {
+      FATAL("EOF in string or regex\n");
+    } else {
+      append_char();
+    }
+  }
+  gch();
+}
+
+static void ascan_opt_div(int div_op_allowed_here)
+{
+  int n;
+  for (;;) {
+    TT.scs->tokbuiltin = 0;
+    TT.scs->toklen = 0;
+    TT.scs->tokstr[0] = 0;
+    while (TT.scs->ch == ' ' || TT.scs->ch == '\t')
+      gch();
+    if (TT.scs->ch == '\\') {
+      append_char();
+      if (TT.scs->ch == '\n') {
+        gch();
+        continue;
+      }
+      TT.scs->toktype = ERROR;   // \ not last char in line.
+      TT.scs->tok = tkerr;
+      TT.scs->error = 3;
+      FATAL("backslash not last char in line\n");
+      return;
+    }
+    break;
+  }
+  // Note \<NEWLINE> in comment does not continue it.
+  if (TT.scs->ch == '#') {
+    gch();
+    while (TT.scs->ch != '\n')
+      gch();
+    // Need to fall through here to pick up newline.
+  }
+  if (TT.scs->ch == '\n') {
+    TT.scs->toktype = NEWLINE;
+    TT.scs->tok = tknl;
+    append_char();
+  } else if (isalpha(TT.scs->ch) || TT.scs->ch == '_') {
+    append_char();
+    while (isalnum(TT.scs->ch) || TT.scs->ch == '_') {
+      append_char();
+    }
+    if ((n = find_keyword()) != 0) {
+      TT.scs->toktype = KEYWORD;
+      TT.scs->tok = n;
+    } else if ((n = find_builtin()) != 0) {
+      TT.scs->toktype = BUILTIN;
+      TT.scs->tok = tkbuiltin;
+      TT.scs->tokbuiltin = n;
+    } else if ((TT.scs->ch == '(')) {
+      TT.scs->toktype = USERFUNC;
+      TT.scs->tok = tkfunc;
+    } else {
+      TT.scs->toktype = VAR;
+      TT.scs->tok = tkvar;
+      // skip whitespace to be able to check for , or )
+      while (TT.scs->ch == ' ' || TT.scs->ch == '\t')
+        gch();
+    }
+    return;
+  } else if (TT.scs->ch == '"') {
+    TT.scs->toktype = STRING;
+    TT.scs->tok = tkstring;
+    get_string_or_regex('"');
+  } else if (isdigit(TT.scs->ch) || TT.scs->ch == '.') {
+    TT.scs->toktype = NUMBER;
+    TT.scs->tok = tknumber;
+    get_number();
+  } else if (TT.scs->ch == '/' && ! div_op_allowed_here) {
+    TT.scs->toktype = REGEX;
+    TT.scs->tok = tkregex;
+    get_string_or_regex('/');
+  } else if (TT.scs->ch == EOF) {
+    TT.scs->toktype = EOF;
+    TT.scs->tok = tkeof;
+  } else if (TT.scs->ch == '\0') {
+    append_char();
+    TT.scs->toktype = ERROR;
+    TT.scs->tok = tkerr;
+    TT.scs->error = 5;
+    FATAL("null char\n");
+  } else {
+    // All other tokens.
+    TT.scs->toktype = TT.scs->ch;
+    append_char();
+    // Special case for **= and ** tokens
+    if (TT.scs->toktype == '*' && TT.scs->ch == '*') {
+      append_char();
+      if (TT.scs->ch == '=') {
+        append_char();
+        TT.scs->tok = tkpowasgn;
+      } else TT.scs->tok = tkpow;
+      TT.scs->toktype = TT.scs->tok + 200;
+      return;
+    }
+    // Is it a 2-character token?
+    if (TT.scs->ch != ' ' && TT.scs->ch != '\n') {
+      append_this_char(TT.scs->ch);
+      if (find_token()) {
+        TT.scs->tok = find_token();
+        TT.scs->toktype = TT.scs->tok + 200;
+        gch();  // Eat second char of token.
+        return;
+      }
+      TT.scs->toklen--;  // Not 2-character token; back off.
+      TT.scs->tokstr[TT.scs->toklen] = 0;
+    }
+    TT.scs->tok = find_token();
+    if (TT.scs->tok) return;
+    TT.scs->toktype = ERROR;
+    TT.scs->tok = tkerr;
+    TT.scs->error = 4;
+    FFATAL("Unexpected token '%s'\n", TT.scs->tokstr);
+  }
+}
+
+static void scan_opt_div(int div_op_allowed_here)
+{
+  // TODO FIXME need better diags for bad tokens!
+  // TODO Also set global syntax error flag.
+  do ascan_opt_div(div_op_allowed_here); while (TT.scs->tok == tkerr);
+}
+
+static void init_scanner(void)
+{
+  TT.prevtok = tkeof;
+  gch();
+}
+
+// POSIX says '/' does not begin a regex wherever '/' or '/=' can mean divide.
+// Pretty sure if / or /= comes after these, it means divide:
+static char div_preceders[] = {tknumber, tkstring, tkvar, tkgetline, tkrparen, tkrbracket, tkincr, tkdecr, 0};
+
+// For checking end of prev statement for termination and if '/' can come next
+
+static void scan(void)
+{
+  TT.prevtok = TT.scs->tok;
+  if (TT.prevtok && strchr(div_preceders, TT.prevtok)) scan_opt_div(1);
+  else scan_opt_div(0);
+  TT.tokstr = TT.scs->tokstr;
+}
+
+////////////////////
+//// compile
+////////////////////
+
+//  NOTES:
+//  NL ok after , { && || do else OR after right paren after if/while/for
+//  TODO:
+//    see case tkgetline -- test more
+//    case tkmatchop, tknotmatch -- fix ~ (/re/)
+
+// Forward declarations -- for mutually recursive parsing functions
+static int expr(int rbp);
+static void lvalue(void);
+static int primary(void);
+static void stmt(void);
+static void action(int action_type);
+
+#define CURTOK() (TT.scs->tok)
+#define ISTOK(toknum) (TT.scs->tok == (toknum))
+
+static int havetok(int tk)
+{
+  if (!ISTOK(tk)) return 0;
+  scan();
+  return 1;
+}
+
+//// code and "literal" emitters
+static void gencd(int op)
+{
+  TT.zcode_last = zlist_append(&TT.zcode, &op);
+}
+
+static void gen2cd(int op, int n)
+{
+  gencd(op);
+  gencd(n);
+}
+
+static int make_literal_str_val(char *s)
+{
+  // Only if no nul inside string!
+  struct zvalue v = new_str_val(s);
+  return zlist_append(&TT.literals, &v);
+}
+
+static int make_literal_regex_val(char *s)
+{
+  regex_t *rx;
+  rx = xmalloc(sizeof(*rx));
+  xregcomp(rx, s, REG_EXTENDED);
+  struct zvalue v = ZVINIT(ZF_RX, 0, 0);
+  v.rx = rx;
+  // Flag empty rx to make it easy to identify for split() special case
+  if (!*s) v.flags |= ZF_EMPTY_RX;
+  return zlist_append(&TT.literals, &v);
+}
+
+static int make_literal_num_val(double num)
+{
+  struct zvalue v = ZVINIT(ZF_NUM, num, 0);
+  return zlist_append(&TT.literals, &v);
+}
+
+static int make_uninit_val(void)
+{
+  return zlist_append(&TT.literals, &uninit_zvalue);
+}
+//// END code and "literal" emitters
+
+//// Symbol tables functions
+static int find_func_def_entry(char *s)
+{
+  for (int k = 1; k < zlist_len(&TT.func_def_table); k++)
+    if (!strcmp(s, FUNC_DEF[k].name)) return k;
+  return 0;
+}
+
+static int add_func_def_entry(char *s)
+{
+  struct functab_slot ent = {0, 0, {0, 0, 0, 0}, 0};
+  ent.name = xstrdup(s);
+  int slotnum = zlist_append(&TT.func_def_table, &ent);
+  return slotnum;
+}
+
+static int find_global(char *s)
+{
+  for (int k = 1; k < zlist_len(&TT.globals_table); k++)
+    if (!strcmp(s, GLOBAL[k].name)) return k;
+  return 0;
+}
+
+static int add_global(char *s)
+{
+  struct symtab_slot ent = {0, 0};
+  ent.name = xstrdup(s);
+  int slotnum = zlist_append(&TT.globals_table, &ent);
+  return slotnum;
+}
+
+static int find_local_entry(char *s)
+{
+  for (int k = 1; k < zlist_len(&TT.locals_table); k++)
+    if (!strcmp(s, LOCAL[k].name)) return k;
+  return 0;
+}
+
+static int add_local_entry(char *s)
+{
+  struct symtab_slot ent = {0, 0};
+  ent.name = xstrdup(s);
+  int slotnum = zlist_append(&TT.locals_table, &ent);
+  return slotnum;
+}
+
+static int find_or_add_var_name(void)
+{
+  int slotnum = 0;    // + means global; - means local to function
+  int globals_ent = 0;
+  int locals_ent = find_local_entry(TT.tokstr);   // in local symbol table?
+  if (locals_ent) {
+    slotnum = -locals_ent;
+  } else {
+    globals_ent = find_global(TT.tokstr);
+    if (!globals_ent) globals_ent = add_global(TT.tokstr);
+    slotnum = globals_ent;
+    if (find_func_def_entry(TT.tokstr))
+      // POSIX: The same name shall not be used both as a variable name
+      // with global scope and as the name of a function.
+      XERR("var '%s' used as function name\n", TT.tokstr);
+  }
+  return slotnum;
+}
+
+//// END Symbol tables functions
+
+//// Initialization
+static void init_locals_table(void)
+{
+  static struct symtab_slot locals_ent;
+  zlist_init(&TT.locals_table, sizeof(struct symtab_slot));
+  zlist_append(&TT.locals_table, &locals_ent);
+}
+
+static void init_tables(void)
+{
+  static struct symtab_slot global_ent;
+  static struct functab_slot func_ent;
+
+  // Append dummy elements in lists to force valid offsets nonzero.
+  zlist_init(&TT.globals_table, sizeof(struct symtab_slot));
+  zlist_append(&TT.globals_table, &global_ent);
+  zlist_init(&TT.func_def_table, sizeof(struct functab_slot));
+  zlist_append(&TT.func_def_table, &func_ent);
+  init_locals_table();
+  zlist_init(&TT.zcode, sizeof(int));
+  gencd(tkeof);   // to ensure zcode offsets are non-zero
+  zlist_init(&TT.literals, sizeof(struct zvalue));
+  // Init stack size at twice MIN_STACK_LEFT. MIN_STACK_LEFT is at least as
+  // many entries as any statement may ever take.  Currently there is no diag
+  // if this is exceeded; prog. will probably crash. 1024 should be plenty?
+  zlist_initx(&TT.stack, sizeof(struct zvalue), 2 * MIN_STACK_LEFT);
+  TT.stackp = (struct zvalue *)TT.stack.base;
+  zlist_init(&TT.fields, sizeof(struct zvalue));
+  zlist_append(&TT.literals, &uninit_zvalue);
+  zlist_append(&TT.stack, &uninit_zvalue);
+  zlist_append(&TT.fields, &uninit_zvalue);
+  FIELD[0].vst = new_zstring("", 0);
+}
+
+static void init_compiler(void)
+{
+  // Special variables (POSIX). Must align with enum spec_var_names
+  static char *spec_vars[] = { "ARGC", "ARGV", "CONVFMT", "ENVIRON", "FILENAME",
+      "FNR", "FS", "NF", "NR", "OFMT", "OFS", "ORS", "RLENGTH", "RS", "RSTART",
+      "SUBSEP", 0};
+
+  init_tables();
+  for (int k = 0; spec_vars[k]; k++) {
+    TT.spec_var_limit = add_global(spec_vars[k]);
+    GLOBAL[TT.spec_var_limit++].flags |= (k == 1 || k == 3) ? ZF_MAP : ZF_SCALAR;
+    push_val(&uninit_zvalue);
+  }
+}
+//// END Initialization
+
+//// Parsing and compiling to TT.zcode
+// Left binding powers
+static int lbp_table[] = {  // Must align with enum Toks
+  0, 0, 0, 0,     // tkunusedtoken, tkeof, tkerr, tknl,
+  250, 250, 250,  // tkvar, tknumber, tkstring,
+  250, 250, 250,  // tkregex, tkfunc, tkbuiltin,
+  0, 0, 210, 0, // tksemi, tkcomma, tklbracket, tkrbracket,
+  200, 0, 0, 0, // tklparen, tkrparen, tklbrace, tkrbrace,
+  190, 180, 180, 170, 160, // tkfield, tkincr, tkdecr, tkpow, tknot,
+  150, 150, 150, 140, 140, // tkmul, tkdiv, tkmod, tkplus, tkminus,
+  130, // tkcat, // FAKE (?) optor for concatenation (adjacent string exprs)
+  110, 110, 110, 110, 110, 110, // tklt, tkle, tkne, tkeq, tkgt, tkge,
+  100, 100, // tkmatchop, tknotmatch,
+  80, 70, // tkand, tkor,
+  60, 0, // tkternif, tkternelse,
+  50, 50, 50, 50,   // tkpowasgn, tkmodasgn, tkmulasgn, tkdivasgn,
+  50, 50, 50, // tkaddasgn, tksubasgn, tkasgn,
+  0, 120, // tkappend, tkpipe,
+  90 // tkin
+};
+
+static int getlbp(int tok)
+{
+  // FIXME: should tkappend be here too? is tkpipe needed?
+  // In print statement outside parens: make '>' end an expression
+  if (TT.cgl.in_print_stmt && ! TT.cgl.paren_level && (tok == tkgt || tok == tkpipe))
+    return 0;
+  return (0 <= tok && tok <= tkin) ? lbp_table[tok] :
+    // getline is special, not a normal builtin.
+    // close, index, match, split, sub, gsub, sprintf, substr
+    // are really builtin functions though bwk treats them as keywords.
+    (tkgetline <= tok && tok <= tksubstr) ? 240 : 0;     // FIXME 240 is temp?
+}
+
+// Get right binding power. Same as left except for right associative optors
+static int getrbp(int tok)
+{
+  int lbp = getlbp(tok);
+  // ternary (?:), assignment, power ops are right associative
+  return (lbp <= 60 || lbp == 170) ? lbp - 1 : lbp;
+}
+
+static void unexpected_eof(void)
+{
+  error_exit("terminated with error(s)");
+}
+
+//// syntax error diagnostic and recovery (Turner's method)
+// D.A. Turner, Error diagnosis and recovery in one pass compilers,
+// Information Processing Letters, Volume 6, Issue 4, 1977, Pages 113-115
+static int recovering = 0;
+
+static void complain(int tk)
+{
+  char op[3], tkstr[10];
+  if (recovering) return;
+  recovering = 1;
+  if (!strcmp(TT.tokstr, "\n")) TT.tokstr = "<newline>";
+  if (tksemi <= tk && tk <= tkpipe) {
+    get_token_text(op, tk);
+    XERR("syntax near '%s' -- '%s' expected\n", TT.tokstr, op);
+  } else if (tk >= tkin && tk <= tksubstr) {
+    if (tk < tkatan2) memmove(tkstr, keywords + 1 + 10 * (tk - tkin), 10);
+    else memmove(tkstr, builtins + 1 + 10 * (tk - tkatan2), 10);
+    *strchr(tkstr, ' ') = 0;
+    XERR("syntax near '%s' -- '%s' expected\n", TT.tokstr, tkstr);
+  } else XERR("syntax near '%s'\n", TT.tokstr);
+}
+
+static void expect(int tk)
+{
+  if (recovering) {
+    while (!ISTOK(tkeof) && !ISTOK(tk))
+      scan();
+    if (ISTOK(tkeof)) unexpected_eof();
+    scan(); // consume expected token
+    recovering = 0;
+  } else if (!havetok(tk)) complain(tk);
+}
+
+static void skip_to(char *tklist)
+{
+  do scan(); while (!ISTOK(tkeof) && !strchr(tklist, CURTOK()));
+  if (ISTOK(tkeof)) unexpected_eof();
+}
+
+//// END syntax error diagnostic and recovery (Turner's method)
+
+static void optional_nl_or_semi(void)
+{
+  while (havetok(tknl) || havetok(tksemi))
+    ;
+}
+
+static void optional_nl(void)
+{
+  while (havetok(tknl))
+    ;
+}
+
+static void rparen(void)
+{
+  expect(tkrparen);
+  optional_nl();
+}
+
+static int have_comma(void)
+{
+  if (!havetok(tkcomma)) return 0;
+  optional_nl();
+  return 1;
+}
+
+static void check_set_map(int slotnum)
+{
+  // POSIX: The same name shall not be used within the same scope both as
+  // a scalar variable and as an array.
+  if (slotnum < 0 && LOCAL[-slotnum].flags & ZF_SCALAR)
+    XERR("scalar param '%s' used as array\n", LOCAL[-slotnum].name);
+  if (slotnum > 0 && GLOBAL[slotnum].flags & ZF_SCALAR)
+    XERR("scalar var '%s' used as array\n", GLOBAL[slotnum].name);
+  if (slotnum < 0) LOCAL[-slotnum].flags |= ZF_MAP;
+  if (slotnum > 0) GLOBAL[slotnum].flags |= ZF_MAP;
+}
+
+static void check_set_scalar(int slotnum)
+{
+  if (slotnum < 0 && LOCAL[-slotnum].flags & ZF_MAP)
+    XERR("array param '%s' used as scalar\n", LOCAL[-slotnum].name);
+  if (slotnum > 0 && GLOBAL[slotnum].flags & ZF_MAP)
+    XERR("array var '%s' used as scalar\n", GLOBAL[slotnum].name);
+  if (slotnum < 0) LOCAL[-slotnum].flags |= ZF_SCALAR;
+  if (slotnum > 0) GLOBAL[slotnum].flags |= ZF_SCALAR;
+}
+
+static void map_name(void)
+{
+  int slotnum;
+  check_set_map(slotnum = find_or_add_var_name());
+  gen2cd(tkvar, slotnum);
+}
+
+static void check_builtin_arg_counts(int tk, int num_args, char *fname)
+{
+  static char builtin_1_arg[] = { tkcos, tksin, tkexp, tklog, tksqrt, tkint,
+                                  tktolower, tktoupper, tkclose, tksystem, 0};
+  static char builtin_2_arg[] = { tkatan2, tkmatch, tkindex, tklshift, tkrshift, 0};
+  static char builtin_al_2_arg[] = { tkband, tkbor, tkbxor, 0};
+  static char builtin_2_3_arg[] = { tksub, tkgsub, tksplit, tksubstr, 0};
+  static char builtin_0_1_arg[] = { tksrand, tklength, tkfflush, 0};
+
+  if (tk == tkrand && num_args)
+    XERR("function '%s' expected no args, got %d\n", fname, num_args);
+  else if (strchr(builtin_1_arg, tk) && num_args != 1)
+    XERR("function '%s' expected 1 arg, got %d\n", fname, num_args);
+  else if (strchr(builtin_2_arg, tk) && num_args != 2)
+    XERR("function '%s' expected 2 args, got %d\n", fname, num_args);
+  else if (strchr(builtin_al_2_arg, tk) && num_args < 2)
+    XERR("function '%s' expected at least 2 args, got %d\n", fname, num_args);
+  else if (strchr(builtin_2_3_arg, tk) && num_args != 2 && num_args != 3)
+    XERR("function '%s' expected 2 or 3 args, got %d\n", fname, num_args);
+  else if (strchr(builtin_0_1_arg, tk) && num_args != 0 && num_args != 1)
+    XERR("function '%s' expected no arg or 1 arg, got %d\n", fname, num_args);
+}
+
+static void builtin_call(int tk, char *builtin_name)
+{
+  int num_args = 0;
+  expect(tklparen);
+  TT.cgl.paren_level++;
+  switch (tk) {
+    case tksub:
+    case tkgsub:
+      if (ISTOK(tkregex)) {
+        gen2cd(tkregex, make_literal_regex_val(TT.tokstr));
+        scan();
+      } else expr(0);
+      expect(tkcomma);
+      optional_nl();
+      expr(0);
+      if (have_comma()) {
+        lvalue();
+      } else {
+        gen2cd(tknumber, make_literal_num_val(0));
+        gen2cd(opfldref, tkeof);
+      }
+      num_args = 3;
+      break;
+
+    case tkmatch:
+      expr(0);
+      expect(tkcomma);
+      optional_nl();
+      if (ISTOK(tkregex)) {
+        gen2cd(tkregex, make_literal_regex_val(TT.tokstr));
+        scan();
+      } else expr(0);
+      num_args = 2;
+      break;
+
+    case tksplit:
+      expr(0);
+      expect(tkcomma);
+      optional_nl();
+      if (ISTOK(tkvar) && (TT.scs->ch == ',' || TT.scs->ch == ')')) {
+        map_name();
+        scan();
+      } else {
+        XERR("%s\n", "expected array name as split() 2nd arg");
+        expr(0);
+      }
+      // FIXME some recovery needed here!?
+      num_args = 2;
+      if (have_comma()) {
+        if (ISTOK(tkregex)) {
+          gen2cd(tkregex, make_literal_regex_val(TT.tokstr));
+          scan();
+        } else expr(0);
+        num_args++;
+      }
+      break;
+
+    case tklength:
+      if (ISTOK(tkvar) && (TT.scs->ch == ',' || TT.scs->ch == ')')) {
+        gen2cd(tkvar, find_or_add_var_name());
+        scan();
+        num_args++;
+      }
+      ATTR_FALLTHROUGH_INTENDED;
+
+    default:
+      if (ISTOK(tkrparen)) break;
+      do {
+        expr(0);
+        num_args++;
+      } while (have_comma());
+      break;
+  }
+  expect(tkrparen);
+  TT.cgl.paren_level--;
+
+  check_builtin_arg_counts(tk, num_args, builtin_name);
+
+  gen2cd(tk, num_args);
+}
+
+static void function_call(void)
+{
+  // Function call: generate TT.zcode to:
+  //  push placeholder for return value, push placeholder for return addr,
+  //  push args, then push number of args, then:
+  //      for builtins: gen opcode (e.g. tkgsub)
+  //      for user func: gen (tkfunc, number-of-args)
+  int functk = 0, funcnum = 0;
+  char builtin_name[16];  // be sure it's long enough for all builtins
+  if (ISTOK(tkbuiltin)) {
+    functk = TT.scs->tokbuiltin;
+    strcpy(builtin_name, TT.tokstr);
+  } else if (ISTOK(tkfunc)) { // user function
+    funcnum = find_func_def_entry(TT.tokstr);
+    if (!funcnum) funcnum = add_func_def_entry(TT.tokstr);
+    FUNC_DEF[funcnum].flags |= FUNC_CALLED;
+    gen2cd(opprepcall, funcnum);
+  } else error_exit("bad function %s!", TT.tokstr);
+  scan();
+  // length() can appear without parens
+  int num_args = 0;
+  if (functk == tklength && !ISTOK(tklparen)) {
+    gen2cd(functk, 0);
+    return;
+  }
+  if (functk) {   // builtin
+    builtin_call(functk, builtin_name);
+    return;
+  }
+  expect(tklparen);
+  TT.cgl.paren_level++;
+  if (ISTOK(tkrparen)) {
+    scan();
+  } else {
+    do {
+      if (ISTOK(tkvar) && (TT.scs->ch == ',' || TT.scs->ch == ')')) {
+        // Function call arg that is a lone variable. Cannot tell in this
+        // context if it is a scalar or map. Just add it to symbol table.
+        gen2cd(tkvar, find_or_add_var_name());
+        scan();
+      } else expr(0);
+      num_args++;
+    } while (have_comma());
+    expect(tkrparen);
+  }
+  TT.cgl.paren_level--;
+  gen2cd(tkfunc, num_args);
+}
+
+static void var(void)
+{
+  // var name is in TT.tokstr
+  // slotnum: + means global; - means local to function
+  int slotnum = find_or_add_var_name();
+  scan();
+  if (havetok(tklbracket)) {
+    check_set_map(slotnum);
+    int num_subscripts = 0;
+    do {
+      expr(0);
+      num_subscripts++;
+    } while (have_comma());
+    expect(tkrbracket);
+    if (num_subscripts > 1) gen2cd(tkrbracket, num_subscripts);
+    gen2cd(opmap, slotnum);
+  } else {
+    check_set_scalar(slotnum);
+    gen2cd(tkvar, slotnum);
+  }
+}
+
+//   Dollar $ tkfield can be followed by "any" expresson, but
+//   the way it binds varies.
+//   The following are valid lvalues:
+//   $ ( expr )
+//   $ tkvar $ tknumber $ tkstring $ tkregex
+//   $ tkfunc(...)
+//   $ tkbuiltin(...)
+//   $ length   # with no parens after
+//   $ tkclose(), ... $ tksubstr
+//   $ tkgetline FIXME TODO TEST THIS
+//   $ ++ lvalue
+//   $ -- lvalue
+//   $ + expression_up_to_exponentiation (also -, ! prefix ops)
+//   $ $ whatever_can_follow_and_bind_to_dollar
+//
+//     tkvar, tknumber, tkstring, tkregex, tkfunc, tkbuiltin, tkfield, tkminus,
+//     tkplus, tknot, tkincr, tkdecr, tklparen, tkgetline,
+//     tkclose, tkindex, tkmatch, tksplit, tksub, tkgsub, tksprintf, tksubstr
+//
+// ray@radon:~$ awk 'BEGIN { $0 = "7 9 5 8"; k=2; print $k*k }'
+// 18
+// ray@radon:~$ awk 'BEGIN { $0 = "7 9 5 8"; k=2; print $+k*k }'
+// 18
+// ray@radon:~$ awk 'BEGIN { $0 = "7 9 5 8"; k=2; print $k^k }'
+// 81
+// ray@radon:~$ awk 'BEGIN { $0 = "7 9 5 8"; k=2; print $+k^k }'
+// 8
+
+static void field_op(void)
+{
+  // CURTOK() must be $ here.
+  expect(tkfield);
+  // tkvar, tknumber, tkstring, tkregex, tkfunc, tkbuiltin, tkfield, tkminus,
+  // tkplus, tknot, tkincr, tkdecr, tklparen, tkgetline, tkclose, tkindex,
+  // tkmatch, tksplit, tksub, tkgsub, tksprintf, tksubstr
+  if (ISTOK(tkfield)) field_op();
+  else if (ISTOK(tkvar)) var();
+  else primary();
+  // tkfield op has "dummy" 2nd word so that convert_push_to_reference(void)
+  // can find either tkfield or tkvar at same place (ZCODE[TT.zcode_last-1]).
+  gen2cd(tkfield, tkeof);
+}
+
+// Tokens that can start expression
+static char exprstartsy[] = {tkvar, tknumber, tkstring, tkregex, tkfunc,
+  tkbuiltin, tkfield, tkminus, tkplus, tknot, tkincr, tkdecr, tklparen,
+  tkgetline, tkclose, tkindex, tkmatch, tksplit, tksub, tkgsub, tksprintf,
+  tksubstr, tkband, tkbor, tkbxor, tkrshift, tklshift, 0};
+
+// Tokens that can end statement
+static char stmtendsy[] = {tknl, tksemi, tkrbrace, 0};
+
+// Tokens that can follow expressions of a print statement
+static char printexprendsy[] = {tkgt, tkappend, tkpipe, tknl, tksemi, tkrbrace, 0};
+
+// !! Ensure this:
+// ternary op is right associative, so
+// a ? b : c ? d : e        evaluates as
+// a ? b : (c ? d : e)      not as
+// (a ? b : c) ? d : e
+
+static void convert_push_to_reference(void)
+{
+  if (ZCODE[TT.zcode_last - 1] == tkvar) ZCODE[TT.zcode_last-1] = opvarref;
+  else if (ZCODE[TT.zcode_last - 1] == opmap) ZCODE[TT.zcode_last - 1] = opmapref;
+  else if (ZCODE[TT.zcode_last - 1] == tkfield) ZCODE[TT.zcode_last - 1] = opfldref;
+  else error_exit("bad lvalue?");
+}
+
+static void lvalue(void)
+{
+  if (ISTOK(tkfield)) {
+    field_op();
+    convert_push_to_reference();
+  } else if (ISTOK(tkvar)) {
+    var();
+    convert_push_to_reference();
+  } else {
+    XERR("syntax near '%s' (bad lvalue)\n", TT.tokstr);
+  }
+}
+
+static int primary(void)
+{
+  //  On entry: CURTOK() is first token of expression
+  //  On exit: CURTOK() is infix operator (for binary_op() to handle) or next
+  //   token after end of expression.
+  //  return -1 for field or var (potential lvalue);
+  //      2 or more for comma-separated expr list
+  //          as in "multiple subscript expression in array"
+  //          e.g. (1, 2) in array_name, or a print/printf list;
+  //      otherwise return 0
+  //
+  //  expr can start with:
+  //      tkvar, tknumber, tkstring, tkregex, tkfunc, tkbuiltin, tkfield, tkminus,
+  //      tkplus, tknot, tkincr, tkdecr, tklparen, tkgetline, tkclose, tkindex,
+  //      tkmatch, tksplit, tksub, tkgsub, tksprintf, tksubstr
+  //
+  //  bwk treats these as keywords, not builtins: close index match split sub gsub
+  //      sprintf substr
+  //
+  //  bwk builtins are: atan2 cos sin exp log sqrt int rand srand length tolower
+  //      toupper system fflush
+  //  NOTE: fflush() is NOT in POSIX awk
+  //
+  //  primary() must consume prefix and postfix operators as well as
+  //      num, string, regex, var, var with subscripts, and function calls
+
+  int num_exprs = 0;
+  int nargs, modifier;
+  int tok = CURTOK();
+  switch (tok) {
+    case tkvar:
+    case tkfield:
+      if (ISTOK(tkvar)) var();
+      else field_op();
+      if (ISTOK(tkincr) || ISTOK(tkdecr)) {
+        convert_push_to_reference();
+        gencd(CURTOK());
+        scan();
+      } else return -1;
+      break;
+
+    case tknumber:
+      gen2cd(tknumber, make_literal_num_val(TT.scs->numval));
+      scan();
+      break;
+
+    case tkstring:
+      gen2cd(tkstring, make_literal_str_val(TT.tokstr));
+      scan();
+      break;
+
+    case tkregex:
+      // When an ERE token appears as an expression in any context other
+      // than as the right-hand of the '~' or "!~" operator or as one of
+      // the built-in function arguments described below, the value of
+      // the resulting expression shall be the equivalent of: $0 ~ /ere/
+      // FIXME TODO
+      gen2cd(opmatchrec, make_literal_regex_val(TT.tokstr));
+      scan();
+      break;
+
+    case tkbuiltin: // various builtins
+    case tkfunc:    // user-defined function
+      function_call();
+      break;
+
+    // Unary prefix ! + -
+    case tknot:
+    case tkminus:
+    case tkplus:
+      scan();
+      expr(getlbp(tknot));   // unary +/- same precedence as !
+      if (tok == tknot) gencd(tknot);
+      else gencd(opnegate);               // forces to number
+      if (tok == tkplus) gencd(opnegate); // forces to number
+      break;
+
+      // Unary prefix ++ -- MUST take lvalue
+    case tkincr:
+    case tkdecr:
+      scan();
+      lvalue();
+      if (tok == tkincr) gencd(oppreincr);
+      else gencd(oppredecr);
+      break;
+
+    case tklparen:
+      scan();
+      TT.cgl.paren_level++;
+      num_exprs = 0;
+      do {
+        expr(0);
+        num_exprs++;
+      } while (have_comma());
+      expect(tkrparen);
+      TT.cgl.paren_level--;
+      if (num_exprs > 1) return num_exprs;
+      break;
+
+    case tkgetline:
+      // getline may be (according to awk book):
+      // getline [var [<file]]
+      // getline <file
+      // cmd | getline [var]
+      // var must be lvalue (can be any lvalue?)
+      scan();
+      nargs = 0;
+      modifier = tkeof;
+      if (ISTOK(tkfield) || ISTOK(tkvar)) {
+        lvalue();
+        nargs++;
+      }
+      if (havetok(tklt)) {
+        expr(getrbp(tkcat));   // bwk "historical practice" precedence
+        nargs++;
+        modifier = tklt;
+      }
+      gen2cd(tkgetline, nargs);
+      gencd(modifier);
+      break;
+
+    default:
+      XERR("syntax near '%s'\n", TT.tokstr[0] == '\n' ? "\\n" : TT.tokstr);
+      skip_to(stmtendsy);
+      break;
+  }
+  return 0;
+}
+
+static void binary_op(int optor)  // Also for ternary ?: optor.
+{
+  int nargs, cdx = 0;  // index in TT.zcode list
+  int rbp = getrbp(optor);
+  if (optor != tkcat) scan();
+  // CURTOK() holds first token of right operand.
+  switch (optor) {
+    case tkin:
+      // right side of 'in' must be (only) an array name
+      map_name();
+      gencd(tkin);
+      scan();
+      // FIXME TODO 20230109 x = y in a && 2 works OK?
+      // x = y in a + 2 does not; it's parsed as x = (y in a) + 2
+      // The +2 is not cat'ed with (y in a) as in bwk's OTA.
+      // Other awks see y in a + 2 as a syntax error. They (may)
+      // not want anything after y in a except a lower binding operator
+      // (&& || ?:) or end of expression, i.e. ')' ';' '}'
+      break;
+
+  case tkpipe:
+      expect(tkgetline);
+      nargs = 1;
+      if (ISTOK(tkfield) || ISTOK(tkvar)) {
+        lvalue();
+        nargs++;
+      }
+      gen2cd(tkgetline, nargs);
+      gencd(tkpipe);
+      break;
+
+  case tkand:
+  case tkor:
+      optional_nl();
+      gen2cd(optor, -1);  // tkand: jump if false, else drop
+      cdx = TT.zcode_last;   // tkor:  jump if true, else drop
+      expr(rbp);
+      gencd(opnotnot);    // replace TT.stack top with truth value
+      ZCODE[cdx] = TT.zcode_last - cdx;
+      break;
+
+  case tkternif:
+      gen2cd(optor, -1);
+      cdx = TT.zcode_last;
+      expr(0);
+      expect(tkternelse);
+      gen2cd(tkternelse, -1);
+      ZCODE[cdx] = TT.zcode_last - cdx;
+      cdx = TT.zcode_last;
+      expr(rbp);
+      ZCODE[cdx] = TT.zcode_last - cdx;
+      break;
+
+  case tkmatchop:
+  case tknotmatch:
+      expr(rbp);
+      if (ZCODE[TT.zcode_last - 1] == opmatchrec) ZCODE[TT.zcode_last - 1] = tkregex;
+      gencd(optor);
+      break;
+
+  default:
+      expr(rbp);
+      gencd(optor);
+  }
+}
+
+static int cat_start_concated_expr(int tok)
+{
+  // concat'ed expr can start w/ var number string func builtin $ ! ( (or ++ if prev was not lvalue)
+  static char exprstarttermsy[] = {tkvar, tknumber, tkstring, tkregex, tkfunc, tkbuiltin,
+    tkfield, tknot, tkincr, tkdecr, tklparen, tkgetline, 0};
+
+  // NOTE this depends on builtins (close etc) being >= tkgetline
+  return !! strchr(exprstarttermsy, tok) || tok >= tkgetline;
+}
+
+#define CALLED_BY_PRINT 99987 // Arbitrary, different from any real rbp value
+
+static int expr(int rbp)
+{
+  // On entry: TT.scs has first symbol of expression, e.g. var, number, string,
+  // regex, func, getline, left paren, prefix op ($ ++ -- ! unary + or -) etc.
+  static char asgnops[] = {tkpowasgn, tkmodasgn, tkmulasgn, tkdivasgn,
+    tkaddasgn, tksubasgn, tkasgn, 0};
+  int prim_st = primary();
+  // If called directly by print_stmt(), and found a parenthesized expression list
+  //    followed by an end of print statement: any of > >> | ; } <newline>
+  //    Then: return the count of expressions in list
+  //    Else: continue parsing an expression
+  if (rbp == CALLED_BY_PRINT) {
+    if (prim_st > 0 && strchr(printexprendsy, CURTOK())) return prim_st;
+    else rbp = 0;
+  }
+
+  // mult_expr_list in parens must be followed by 'in' unless it
+  // immediately follows print or printf, where it may still be followed
+  // by 'in' ... unless at end of statement
+  if (prim_st > 0 && ! ISTOK(tkin))
+    XERR("syntax near '%s'; expected 'in'\n", TT.tokstr);
+  if (prim_st > 0) gen2cd(tkrbracket, prim_st);
+  // primary() has eaten subscripts, function args, postfix ops.
+  // CURTOK() should be a binary op.
+  int optor = CURTOK();
+  if (strchr(asgnops, optor)) {
+
+    // TODO FIXME ?  NOT SURE IF THIS WORKS RIGHT!
+    // awk does not parse according to POSIX spec in some odd cases.
+    // When an assignment (lvalue =) is on the right of certain operators,
+    // it is not treated as a bad lvalue (as it is in C).
+    // Example: (1 && a=2) # no error; the assignment is performed.
+    // This happens for ?: || && ~ !~ < <= ~= == > >=
+    //
+    static char odd_assignment_rbp[] = {59, 60, 70, 80, 100, 110, 0};
+    if (prim_st < 0 && (rbp <= getrbp(optor) || strchr(odd_assignment_rbp, rbp))) {
+      convert_push_to_reference();
+      scan();
+      expr(getrbp(optor));
+      gencd(optor);
+      return 0;
+    }
+    XERR("syntax near '%s'\n", TT.tokstr[0] == '\n' ? "\\n" : TT.tokstr);
+    skip_to(stmtendsy);
+  }
+  if (cat_start_concated_expr(optor)) optor = tkcat;
+  while (rbp < getlbp(optor)) {
+    binary_op(optor);
+    // HERE tok s/b an operator or expression terminator ( ; etc.).
+    optor = CURTOK();
+    if (cat_start_concated_expr(optor)) optor = tkcat;
+  }
+  return 0;
+}
+
+static void print_stmt(int tk)
+{
+  static char outmodes[] = {tkgt, tkappend, tkpipe, 0};
+  int num_exprs = 0, outmode;
+  TT.cgl.in_print_stmt = 1;
+  expect(tk); // tkprint or tkprintf
+  if ((tk == tkprintf) || !strchr(printexprendsy, CURTOK())) {
+    // printf always needs expression
+    // print non-empty statement needs expression
+    num_exprs = expr(CALLED_BY_PRINT);
+    if (num_exprs > 0 && !strchr(printexprendsy, CURTOK())) FATAL("print stmt bug");
+    if (!num_exprs) {
+      for (num_exprs++; have_comma(); num_exprs++)
+        expr(0);
+    }
+  }
+  outmode = CURTOK();
+  if (strchr(outmodes, outmode)) {
+    scan();
+    expr(0); // FIXME s/b only bwk term? check POSIX
+    num_exprs++;
+  } else outmode = 0;
+  gen2cd(tk, num_exprs);
+  gencd(outmode);
+  TT.cgl.in_print_stmt = 0;
+}
+
+static void delete_stmt(void)
+{
+  expect(tkdelete);
+  if (ISTOK(tkvar)) {
+    int slotnum = find_or_add_var_name();
+    check_set_map(slotnum);
+    scan();
+    if (havetok(tklbracket)) {
+      int num_subscripts = 0;
+      do {
+        expr(0);
+        num_subscripts++;
+      } while (have_comma());
+      expect(tkrbracket);
+      if (num_subscripts > 1) gen2cd(tkrbracket, num_subscripts);
+      gen2cd(opmapref, slotnum);
+      gencd(tkdelete);
+    } else {
+      // delete entire map (elements only; var is still a map)
+      gen2cd(opmapref, slotnum);
+      gencd(opmapdelete);
+    }
+  } else expect(tkvar);
+}
+
+static void simple_stmt(void)
+{
+  if (strchr(exprstartsy, CURTOK())) {
+    expr(0);
+    gencd(opdrop);
+    return;
+  }
+  switch (CURTOK()) {
+    case tkprint:
+    case tkprintf:
+      print_stmt(CURTOK());
+      break;
+
+    case tkdelete:
+      delete_stmt();
+      break;
+
+    default:
+      XERR("syntax near '%s'\n", TT.tokstr[0] == '\n' ? "\\n" : TT.tokstr);
+      skip_to(stmtendsy);
+  }
+}
+
+static int prev_was_terminated(void)
+{
+  return !!strchr(stmtendsy, TT.prevtok);
+}
+
+static int is_nl_semi(void)
+{
+  return ISTOK(tknl) || ISTOK(tksemi);
+}
+
+static void if_stmt(void)
+{
+  expect(tkif);
+  expect(tklparen);
+  expr(0);
+  rparen();
+  gen2cd(tkif, -1);
+  int cdx = TT.zcode_last;
+  stmt();
+  if (!prev_was_terminated() && is_nl_semi()) {
+    scan();
+    optional_nl();
+  }
+  if (prev_was_terminated()) {
+    optional_nl();
+    if (havetok(tkelse)) {
+      gen2cd(tkelse, -1);
+      ZCODE[cdx] = TT.zcode_last - cdx;
+      cdx = TT.zcode_last;
+      optional_nl();
+      stmt();
+    }
+  }
+  ZCODE[cdx] = TT.zcode_last - cdx;
+}
+
+static void save_break_continue(int *brk, int *cont)
+{
+  *brk = TT.cgl.break_dest;
+  *cont = TT.cgl.continue_dest;
+}
+
+static void restore_break_continue(int *brk, int *cont)
+{
+  TT.cgl.break_dest = *brk;
+  TT.cgl.continue_dest = *cont;
+}
+
+static void while_stmt(void)
+{
+  int brk, cont;
+  save_break_continue(&brk, &cont);
+  expect(tkwhile);
+  expect(tklparen);
+  TT.cgl.continue_dest = TT.zcode_last + 1;
+  expr(0);
+  rparen();
+  gen2cd(tkwhile, 2);    // drop, jump if true
+  TT.cgl.break_dest = TT.zcode_last + 1;
+  gen2cd(opjump, -1);     // jump here to break
+  stmt();
+  gen2cd(opjump, -1);     // jump to continue
+  ZCODE[TT.zcode_last] = TT.cgl.continue_dest - TT.zcode_last - 1;
+  ZCODE[TT.cgl.break_dest + 1] = TT.zcode_last - TT.cgl.break_dest - 1;
+  restore_break_continue(&brk, &cont);
+}
+
+static void do_stmt(void)
+{
+  int brk, cont;
+  save_break_continue(&brk, &cont);
+  expect(tkdo);
+  optional_nl();
+  gen2cd(opjump, 4);   // jump over jumps, to statement
+  TT.cgl.continue_dest = TT.zcode_last + 1;
+  gen2cd(opjump, -1);   // here on continue
+  TT.cgl.break_dest = TT.zcode_last + 1;
+  gen2cd(opjump, -1);   // here on break
+  stmt();
+  if (!prev_was_terminated()) {
+    if (is_nl_semi()) {
+      scan();
+      optional_nl();
+    } else {
+      XERR("syntax near '%s' -- ';' or newline expected\n", TT.tokstr);
+      // FIXME
+    }
+  }
+  ZCODE[TT.cgl.continue_dest + 1] = TT.zcode_last - TT.cgl.continue_dest - 1;
+  optional_nl();
+  expect(tkwhile);
+  expect(tklparen);
+  expr(0);
+  rparen();
+  gen2cd(tkwhile, TT.cgl.break_dest - TT.zcode_last - 1);
+  ZCODE[TT.cgl.break_dest + 1] = TT.zcode_last - TT.cgl.break_dest - 1;
+  restore_break_continue(&brk, &cont);
+}
+
+static void for_not_map_iter(void)
+{
+  // Here after loop initialization, if any; loop condition
+  int condition_loc = TT.zcode_last + 1;
+  if (havetok(tksemi)) {
+    // "endless" loop variant; no condition
+    // no NL allowed here in OTA
+    gen2cd(opjump, -1);     // jump to statement
+  } else {
+    optional_nl();                // NOT posix or awk book; in OTA
+    expr(0);                 // loop while true
+    expect(tksemi);
+    gen2cd(tkwhile, -1);    // drop, jump to statement if true
+  }
+  optional_nl();                    // NOT posix or awk book; in OTA
+  TT.cgl.break_dest = TT.zcode_last + 1;
+  gen2cd(opjump, -1);
+  TT.cgl.continue_dest = TT.zcode_last + 1;
+  if (!ISTOK(tkrparen)) simple_stmt();  // "increment"
+  gen2cd(opjump, condition_loc - TT.zcode_last - 3);
+  rparen();
+  ZCODE[TT.cgl.break_dest - 1] = TT.zcode_last - TT.cgl.break_dest + 1;
+  stmt();
+  gen2cd(opjump, TT.cgl.continue_dest - TT.zcode_last - 3);
+  ZCODE[TT.cgl.break_dest + 1] = TT.zcode_last - TT.cgl.break_dest - 1;
+}
+
+static int valid_for_array_iteration(int first, int last)
+{
+  return ZCODE[first] == tkvar && ZCODE[first + 2] == tkvar
+      && ZCODE[first + 4] == tkin && ZCODE[first + 5] == opdrop
+      && first + 5 == last;
+}
+
+static void for_stmt(void)
+{
+  int brk, cont;
+  save_break_continue(&brk, &cont);
+  expect(tkfor);
+  expect(tklparen);
+  if (havetok(tksemi)) {
+    // No "initialization" part
+    for_not_map_iter();
+  } else {
+    int loop_start_loc = TT.zcode_last + 1;
+    simple_stmt();  // initializaton part, OR varname in arrayname form
+    if (!havetok(tkrparen)) {
+      expect(tksemi);
+      for_not_map_iter();
+    } else {
+      // Must be map iteration
+      // Check here for varname in varname!
+      // FIXME TODO must examine generated TT.zcode for var in array?
+      if (!valid_for_array_iteration(loop_start_loc, TT.zcode_last))
+        XERR("%s", "bad 'for (var in array)' loop\n");
+      else {
+        ZCODE[TT.zcode_last-5] = opvarref;
+        ZCODE[TT.zcode_last-1] = tknumber;
+        ZCODE[TT.zcode_last] = make_literal_num_val(-1);
+        TT.cgl.continue_dest = TT.zcode_last + 1;
+        gen2cd(opmapiternext, 2);
+        TT.cgl.break_dest = TT.zcode_last + 1;
+        gen2cd(opjump, -1);   // fill in with loc after stmt
+      }
+      optional_nl();
+      // fixup TT.stack if return or exit inside for (var in array)
+      TT.cgl.stack_offset_to_fix += 3;
+      stmt();
+      TT.cgl.stack_offset_to_fix -= 3;
+      gen2cd(opjump, TT.cgl.continue_dest - TT.zcode_last - 3);
+      ZCODE[TT.cgl.break_dest + 1] = TT.zcode_last - TT.cgl.break_dest - 1;
+      gencd(opdrop);
+      gencd(opdrop);
+      gencd(opdrop);
+    }
+  }
+  restore_break_continue(&brk, &cont);
+}
+
+static void stmt(void)
+{
+  switch (CURTOK()) {
+    case tkeof:
+      break;     // FIXME ERROR?
+
+    case tkbreak:
+      scan();
+      if (TT.cgl.break_dest) gen2cd(tkbreak, TT.cgl.break_dest - TT.zcode_last - 3);
+      else XERR("%s", "break not in a loop\n");
+      break;
+
+    case tkcontinue:
+      scan();
+      if (TT.cgl.continue_dest)
+        gen2cd(tkcontinue, TT.cgl.continue_dest - TT.zcode_last - 3);
+      else XERR("%s", "continue not in a loop\n");
+      break;
+
+    case tknext:
+      scan();
+      gencd(tknext);
+      if (TT.cgl.rule_type) XERR("%s", "next inside BEGIN or END\n");
+      if (TT.cgl.in_function_body) XERR("%s", "next inside function def\n");
+      break;
+
+    case tknextfile:
+      scan();
+      gencd(tknextfile);
+      if (TT.cgl.rule_type) XERR("%s", "nextfile inside BEGIN or END\n");
+      if (TT.cgl.in_function_body) XERR("%s", "nextfile inside function def\n");
+      break;
+
+    case tkexit:
+      scan();
+      if (strchr(exprstartsy, CURTOK())) {
+        expr(0);
+      } else gen2cd(tknumber, make_literal_num_val(NO_EXIT_STATUS));
+      gencd(tkexit);
+      break;
+
+    case tkreturn:
+      scan();
+      if (TT.cgl.stack_offset_to_fix) gen2cd(opdrop_n, TT.cgl.stack_offset_to_fix);
+      if (strchr(exprstartsy, CURTOK())) {
+        expr(0);
+      } else gen2cd(tknumber, make_literal_num_val(0.0));
+      gen2cd(tkreturn, TT.cgl.nparms);
+      if (!TT.cgl.in_function_body) XERR("%s", "return outside function def\n");
+      break;
+
+    case tklbrace:
+      action(tklbrace);
+      break;
+
+    case tkif:
+      if_stmt();
+      break;
+
+    case tkwhile:
+      while_stmt();
+      break;
+
+    case tkdo:
+      do_stmt();
+      break;
+
+    case tkfor:
+      for_stmt();
+      break;
+
+    case tksemi:
+      scan();
+      break;
+    default:
+      simple_stmt();      // expression print printf delete
+  }
+}
+
+static void add_param(int funcnum, char *s)
+{
+  if (!find_local_entry(s)) add_local_entry(s);
+  else XERR("function '%s' dup param '%s'\n", FUNC_DEF[funcnum].name, s);
+  TT.cgl.nparms++;
+
+  // POSIX: The same name shall not be used as both a function parameter name
+  // and as the name of a function or a special awk variable.
+  // !!! NOTE seems implementations exc. mawk only compare param names with
+  // builtin funcs; use same name as userfunc is OK!
+  if (!strcmp(s, FUNC_DEF[funcnum].name))
+    XERR("function '%s' param '%s' matches func name\n",
+        FUNC_DEF[funcnum].name, s);
+  if (find_global(s) && find_global(s) < TT.spec_var_limit)
+    XERR("function '%s' param '%s' matches special var\n",
+        FUNC_DEF[funcnum].name, s);
+}
+
+static void function_def(void)
+{
+  expect(tkfunction);
+  int funcnum = find_func_def_entry(TT.tokstr);
+  if (!funcnum) {
+    funcnum = add_func_def_entry(TT.tokstr);
+  } else if (FUNC_DEF[funcnum].flags & FUNC_DEFINED) {
+    XERR("dup defined function '%s'\n", TT.tokstr);
+  }
+  FUNC_DEF[funcnum].flags |= FUNC_DEFINED;
+  if (find_global(TT.tokstr)) {
+    // POSIX: The same name shall not be used both as a variable name with
+    // global scope and as the name of a function.
+    XERR("function name '%s' previously defined\n", TT.tokstr);
+  }
+
+  gen2cd(tkfunction, funcnum);
+  FUNC_DEF[funcnum].zcode_addr = TT.zcode_last - 1;
+  TT.cgl.funcnum = funcnum;
+  TT.cgl.nparms = 0;
+  if (ISTOK(tkfunc)) expect(tkfunc); // func name with no space before (
+  else expect(tkvar);  // func name with space before (
+  expect(tklparen);
+  if (ISTOK(tkvar)) {
+    add_param(funcnum, TT.tokstr);
+    scan();
+    // FIXME is the the best way? what if TT.tokstr not a tkvar?
+    while (have_comma()) {
+      add_param(funcnum, TT.tokstr);
+      expect(tkvar);
+    }
+  }
+  rparen();
+  if (ISTOK(tklbrace)) {
+    TT.cgl.in_function_body = 1;
+    action(tkfunc);
+    TT.cgl.in_function_body = 0;
+    // Need to return uninit value if falling off end of function.
+    gen2cd(tknumber, make_uninit_val());
+    gen2cd(tkreturn, TT.cgl.nparms);
+  } else {
+    XERR("syntax near '%s'\n", TT.tokstr);
+    // FIXME some recovery needed here!?
+  }
+  // Do not re-init locals table for dup function.
+  // Avoids memory leak detected by LeakSanitizer.
+  if (!FUNC_DEF[funcnum].function_locals.base) {
+    FUNC_DEF[funcnum].function_locals = TT.locals_table;
+    init_locals_table();
+  }
+}
+
+static void action(int action_type)
+{
+(void)action_type;
+  // action_type is tkbegin, tkend, tkdo (every line), tkif (if pattern),
+  //                  tkfunc (function body), tklbrace (compound statement)
+  // Should have lbrace on entry.
+  expect(tklbrace);
+  for (;;) {
+    if (ISTOK(tkeof)) unexpected_eof();
+    optional_nl_or_semi();
+    if (havetok(tkrbrace)) {
+      break;
+    }
+    stmt();
+    // stmt() is normally unterminated here, but may be terminated if we
+    // have if with no else (had to consume terminator looking for else)
+    //   !!!   if (ISTOK(tkrbrace) || prev_was_terminated())
+    if (prev_was_terminated()) continue;
+    if (!is_nl_semi() && !ISTOK(tkrbrace)) {
+      XERR("syntax near '%s' -- newline, ';', or '}' expected\n", TT.tokstr);
+      while (!is_nl_semi() && !ISTOK(tkrbrace) && !ISTOK(tkeof)) scan();
+      if (ISTOK(tkeof)) unexpected_eof();
+    }
+    if (havetok(tkrbrace)) break;
+    // Must be semicolon or newline
+    scan();
+  }
+}
+
+static void rule(void)
+{
+  //       pa_pat
+  //     | pa_pat lbrace stmtlist '}'
+  //     | pa_pat ',' opt_nl pa_pat
+  //     | pa_pat ',' opt_nl pa_pat lbrace stmtlist '}'
+  //     | lbrace stmtlist '}'
+  //     | XBEGIN lbrace stmtlist '}'
+  //     | XEND lbrace stmtlist '}'
+  //     | FUNC funcname '(' varlist rparen  lbrace stmtlist '}'
+
+  switch (CURTOK()) {
+    case tkbegin:
+      scan();
+      if (TT.cgl.last_begin) ZCODE[TT.cgl.last_begin] = TT.zcode_last - TT.cgl.last_begin;
+      else TT.cgl.first_begin = TT.zcode_last + 1;
+
+      TT.cgl.rule_type = tkbegin;
+      action(tkbegin);
+      TT.cgl.rule_type = 0;
+      gen2cd(opjump, -1);
+      TT.cgl.last_begin = TT.zcode_last;
+      break;
+
+    case tkend:
+      scan();
+      if (TT.cgl.last_end) ZCODE[TT.cgl.last_end] = TT.zcode_last - TT.cgl.last_end;
+      else TT.cgl.first_end = TT.zcode_last + 1;
+
+      TT.cgl.rule_type = tkbegin;
+      action(tkend);
+      TT.cgl.rule_type = 0;
+      gen2cd(opjump, -1);
+      TT.cgl.last_end = TT.zcode_last;
+      break;
+
+    case tklbrace:
+      if (TT.cgl.last_recrule)
+        ZCODE[TT.cgl.last_recrule] = TT.zcode_last - TT.cgl.last_recrule;
+      else TT.cgl.first_recrule = TT.zcode_last + 1;
+      action(tkdo);
+      gen2cd(opjump, -1);
+      TT.cgl.last_recrule = TT.zcode_last;
+      break;
+
+    case tkfunction:
+      function_def();
+      break;
+    default:
+      if (TT.cgl.last_recrule)
+        ZCODE[TT.cgl.last_recrule] = TT.zcode_last - TT.cgl.last_recrule;
+      else TT.cgl.first_recrule = TT.zcode_last + 1;
+      gen2cd(opjump, 1);
+      gencd(tkeof);
+      int cdx = 0, saveloc = TT.zcode_last;
+      expr(0);
+      if (!have_comma()) {
+        gen2cd(tkif, -1);
+        cdx = TT.zcode_last;
+      } else {
+        gen2cd(oprange2, ++TT.cgl.range_pattern_num);
+        gencd(-1);
+        cdx = TT.zcode_last;
+        ZCODE[saveloc-2] = oprange1;
+        ZCODE[saveloc-1] = TT.cgl.range_pattern_num;
+        ZCODE[saveloc] = TT.zcode_last - saveloc;
+        expr(0);
+        gen2cd(oprange3, TT.cgl.range_pattern_num);
+      }
+      if (ISTOK(tklbrace)) {
+        action(tkif);
+        ZCODE[cdx] = TT.zcode_last - cdx;
+      } else {
+        gencd(opprintrec);   // print $0 ?
+        ZCODE[cdx] = TT.zcode_last - cdx;
+      }
+      gen2cd(opjump, -1);
+      TT.cgl.last_recrule = TT.zcode_last;
+  }
+}
+
+static void diag_func_def_ref(void)
+{
+  int n = zlist_len(&TT.func_def_table);
+  for (int k = 1; k < n; k++) {
+    if ((FUNC_DEF[k].flags & FUNC_CALLED) &&
+            !(FUNC_DEF[k].flags & FUNC_DEFINED)) {
+      // Sorry, we can't tell where this was called from, for now at least.
+      XERR("Undefined function '%s'", FUNC_DEF[k].name);
+    }
+  }
+}
+
+static void compile(void)
+{
+  init_compiler();
+  init_scanner();
+  scan();
+  optional_nl_or_semi();        // Does posix allow NL or ; before first rule?
+  while (! ISTOK(tkeof)) {
+    rule();
+    optional_nl_or_semi();        // NOT POSIX
+  }
+
+
+  if (TT.cgl.last_begin) ZCODE[TT.cgl.last_begin-1] = opquit;
+  if (TT.cgl.last_end) ZCODE[TT.cgl.last_end-1] = opquit;
+  if (TT.cgl.last_recrule) ZCODE[TT.cgl.last_recrule-1] = opquit;
+
+  gen2cd(tknumber, make_literal_num_val(0.0));
+  gencd(tkexit);
+  gencd(opquit);
+  // If there are only BEGIN and END or only END actions, generate actions to
+  // read all input before END.
+  if (TT.cgl.first_end && !TT.cgl.first_recrule) {
+    gencd(opquit);
+    TT.cgl.first_recrule = TT.zcode_last;
+  }
+  gencd(opquit);  // One more opcode to keep ip in bounds in run code.
+  diag_func_def_ref();
+}
+
+////////////////////
+//// runtime
+////////////////////
+
+static void check_numeric_string(struct zvalue *v)
+{
+  if (v->vst) {
+    char *end, *s = v->vst->str;
+    // Significant speed gain with this test:
+    // num string must begin space, +, -, ., or digit.
+    if (strchr("+-.1234567890 ", *s)) {
+      double num = strtod(s, &end);
+      if (s == end || end[strspn(end, " ")]) return;
+      v->num = num;
+      v->flags |= ZF_NUM | ZF_STR | ZF_NUMSTR;
+    }
+  }
+}
+
+static struct zstring *num_to_zstring(double n, char *fmt)
+{
+  int k;
+  if (n == (long long)n) k = snprintf(TT.pbuf, PBUFSIZE, "%lld", (long long)n);
+  else k = snprintf(TT.pbuf, PBUFSIZE, fmt, n);
+  if (k < 0 || k >= PBUFSIZE) FFATAL("error encoding %f via '%s'", n, fmt);
+  return new_zstring(TT.pbuf, k);
+}
+
+////////////////////
+//// regex routines
+////////////////////
+
+static char *escape_str(char *s, int is_regex)
+{
+  char *p, *escapes = is_regex ? "abfnrtv\"/" : "\\abfnrtv\"/";
+  // FIXME TODO should / be in there?
+  char *s0 = s, *to = s;
+  while ((*to = *s)) {
+    if (*s != '\\') { to++, s++;
+    } else if ((p = strchr(escapes, *++s))) {
+      // checking char after \ for known escapes
+      int c = (is_regex?"\a\b\f\n\r\t\v\"/":"\\\a\b\f\n\r\t\v\"/")[p-escapes];
+      if (c) *to = c, s++;  // else final backslash
+      to++;
+    } else if ('0' <= *s && *s <= '9') {
+      int k, c = *s++ - '0';
+      for (k = 0; k < 2 && '0' <= *s && *s <= '9'; k++)
+        c = c * 8 + *s++ - '0';
+      *to++ = c;
+    } else if (*s == 'x') {
+      if (isxdigit(s[1])) {
+        int c = hexval(*++s);
+        if (isxdigit(s[1])) c = c * 16 + hexval(*++s);
+        *to++ = c, s++;
+      }
+    } else {
+      if (is_regex) *to++ = '\\';
+      *to++ = *s++;
+    }
+  }
+  return s0;
+}
+
+static void force_maybemap_to_scalar(struct zvalue *v)
+{
+  if (!(v->flags & ZF_ANYMAP)) return;
+  if (v->flags & ZF_MAP || v->map->count)
+    FATAL("array in scalar context");
+  v->flags = 0;
+  v->map = 0; // v->flags = v->map = 0 gets warning
+}
+
+static void force_maybemap_to_map(struct zvalue *v)
+{
+  if (v->flags & ZF_MAYBEMAP) v->flags = ZF_MAP;
+}
+
+// fmt_offs is either CONVFMT or OFMT (offset in stack to zvalue)
+static struct zvalue *to_str_fmt(struct zvalue *v, int fmt_offs)
+{
+  force_maybemap_to_scalar(v);
+  // TODO: consider handling numstring differently
+  if (v->flags & ZF_NUMSTR) v->flags = ZF_STR;
+  if (IS_STR(v)) return v;
+  else if (!v->flags) { // uninitialized
+    v->vst = new_zstring("", 0);
+  } else if (IS_NUM(v)) {
+    zvalue_release_zstring(v);
+    if (!IS_STR(&STACK[fmt_offs])) {
+      zstring_release(&STACK[fmt_offs].vst);
+      STACK[fmt_offs].vst = num_to_zstring(STACK[fmt_offs].num, "%.6g");
+      STACK[fmt_offs].flags = ZF_STR;
+    }
+    v->vst = num_to_zstring(v->num, STACK[fmt_offs].vst->str);
+  } else {
+    FATAL("Wrong or unknown type in to_str_fmt\n");
+  }
+  v->flags = ZF_STR;
+  return v;
+}
+
+static struct zvalue *to_str(struct zvalue *v)
+{
+  return to_str_fmt(v, CONVFMT);
+}
+
+// TODO FIXME Is this needed? (YES -- investigate) Just use to_str()?
+#define ENSURE_STR(v) (IS_STR(v) ? (v) : to_str(v))
+
+static void rx_zvalue_compile(regex_t **rx, struct zvalue *pat)
+{
+  if (IS_RX(pat)) *rx = pat->rx;
+  else {
+    zvalue_dup_zstring(to_str(pat));
+    escape_str(pat->vst->str, 1);
+    xregcomp(*rx, pat->vst->str, REG_EXTENDED);
+  }
+}
+
+static void rx_zvalue_free(regex_t *rx, struct zvalue *pat)
+{
+  if (!IS_RX(pat) || rx != pat->rx) regfree(rx);
+}
+
+// Used by the match/not match ops (~ !~) and implicit $0 match (/regex/)
+static int match(struct zvalue *zvsubject, struct zvalue *zvpat)
+{
+  int r;
+  regex_t rx, *rxp = &rx;
+  rx_zvalue_compile(&rxp, zvpat);
+  if ((r = regexec(rxp, to_str(zvsubject)->vst->str, 0, 0, 0)) != 0) {
+    if (r != REG_NOMATCH) {
+      char errbuf[256];
+      regerror(r, &rx, errbuf, sizeof(errbuf));
+      // FIXME TODO better diagnostic here
+      error_exit("regex match error %d: %s", r, errbuf);
+    }
+    rx_zvalue_free(rxp, zvpat);
+    return 1;
+  }
+  rx_zvalue_free(rxp, zvpat);
+  return 0;
+}
+
+static int rx_find(regex_t *rx, char *s, regoff_t *start, regoff_t *end, int eflags)
+{
+  regmatch_t matches[1];
+  int r = regexec(rx, s, 1, matches, eflags);
+  if (r == REG_NOMATCH) return r;
+  if (r) FATAL("regexec error");  // TODO ? use regerr() to meaningful msg
+  *start = matches[0].rm_so;
+  *end = matches[0].rm_eo;
+  return 0;
+}
+
+// Differs from rx_find() in that FS cannot match null (empty) string.
+// See https://www.austingroupbugs.net/view.php?id=1468.
+static int rx_find_FS(regex_t *rx, char *s, regoff_t *start, regoff_t *end, int eflags)
+{
+  int r = rx_find(rx, s, start, end, eflags);
+  if (r || *start != *end) return r;  // not found, or found non-empty match
+  // Found empty match, retry starting past the match
+  char *p = s + *end;
+  if (!*p) return REG_NOMATCH;  // End of string, no non-empty match found
+  // Empty match not at EOS, move ahead and try again
+  while (!r && *start == *end && *++p)
+    r = rx_find(rx, p, start, end, eflags);
+  if (r || !*p) return REG_NOMATCH;  // no non-empty match found
+  *start += p - s;  // offsets from original string
+  *end += p - s;
+  return 0;
+}
+
+////////////////////
+////   fields
+////////////////////
+
+#define FIELDS_MAX  102400 // Was 1024; need more for toybox awk test
+#define THIS_MEANS_SET_NF 999999999
+
+static int get_int_val(struct zvalue *v)
+{
+  if (IS_NUM(v)) return (int)v->num;
+  if (IS_STR(v) && v->vst) return (int)atof(v->vst->str);
+  return 0;
+}
+
+// A single-char FS is never a regex, so make it a [<char>] regex to
+// match only that one char in case FS is a regex metachar.
+// If regex FS is needed, must use > 1 char. If a '.' regex
+// is needed, use e.g. '.|.' (unlikely case).
+static char *fmt_one_char_fs(char *fs)
+{
+  if (strlen(fs) != 1) return fs;
+  snprintf(TT.one_char_fs, sizeof(TT.one_char_fs), "[%c]", fs[0]);
+  return TT.one_char_fs;
+}
+
+static regex_t *rx_fs_prep(char *fs)
+{
+  if (!strcmp(fs, " ")) return &TT.rx_default;
+  if (!strcmp(fs, TT.fs_last)) return &TT.rx_last;
+  if (strlen(fs) >= FS_MAX) FATAL("FS too long");
+  strcpy(TT.fs_last, fs);
+  regfree(&TT.rx_last);
+  xregcomp(&TT.rx_last, fmt_one_char_fs(fs), REG_EXTENDED);
+  return &TT.rx_last;
+}
+
+// Only for use by split() builtin
+static void set_map_element(struct zmap *m, int k, char *val, size_t len)
+{
+  // Do not need format here b/c k is integer, uses "%lld" format.
+  struct zstring *key = num_to_zstring(k, "");// "" vs 0 format avoids warning
+  struct zmap_slot *zs = zmap_find_or_insert_key(m, key);
+  zstring_release(&key);
+  zs->val.vst = zstring_update(zs->val.vst, 0, val, len);
+  zs->val.flags = ZF_STR;
+  check_numeric_string(&zs->val);
+}
+
+static void set_zvalue_str(struct zvalue *v, char *s, size_t size)
+{
+  v->vst = zstring_update(v->vst, 0, s, size);
+  v->flags = ZF_STR;
+}
+
+// All changes to NF go through here!
+static void set_nf(int nf)
+{
+  STACK[NF].num = TT.nf_internal = nf;
+  STACK[NF].flags = ZF_NUM;
+}
+
+static void set_field(struct zmap *unused, int fnum, char *s, size_t size)
+{ (void)unused;
+  if (fnum < 0 || fnum > FIELDS_MAX) FFATAL("bad field num %d\n", fnum);
+  int nfields = zlist_len(&TT.fields);
+  // Need nfields to be > fnum b/c e.g. fnum==1 implies 2 TT.fields
+  while (nfields <= fnum)
+    nfields = zlist_append(&TT.fields, &uninit_zvalue) + 1;
+  set_zvalue_str(&FIELD[fnum], s, size);
+  set_nf(fnum);
+  check_numeric_string(&FIELD[fnum]);
+}
+
+// Split s via fs, using setter; return number of TT.fields.
+// This is used to split TT.fields and also for split() builtin.
+static int splitter(void (*setter)(struct zmap *, int, char *, size_t), struct zmap *m, char *s, struct zvalue *zvfs)
+{
+  regex_t *rx;
+  regoff_t offs, end;
+  int multiline_null_rs = !ENSURE_STR(&STACK[RS])->vst->str[0];
+  if (!IS_RX(zvfs)) to_str(zvfs);
+  char *s0 = s, *fs = IS_STR(zvfs) ? zvfs->vst->str : "";
+  int one_char_fs = utf8cnt(zvfs->vst->str, zvfs->vst->size) == 1;
+  int nf = 0, r = 0, eflag = 0;
+  // Empty string or empty fs (regex).
+  // Need to include !*s b/c empty string, otherwise
+  // split("", a, "x") splits to a 1-element (empty element) array
+  if (!*s || (IS_STR(zvfs) && !*fs) || IS_EMPTY_RX(zvfs)) {
+    while (*s) {
+      if (*s < 128) setter(m, ++nf, s++, 1);
+      else {        // Handle UTF-8
+        char cbuf[8];
+        unsigned wc;
+        int nc = utf8towc(&wc, s, strlen(s));
+        if (nc < 2) FATAL("bad string for split: \"%s\"\n", s0);
+        s += nc;
+        nc = wctoutf8(cbuf, wc);
+        setter(m, ++nf, cbuf, nc);
+      }
+    }
+    return nf;
+  }
+  if (IS_RX(zvfs)) rx = zvfs->rx;
+  else rx = rx_fs_prep(fs);
+  while (*s) {
+    // Find the next occurrence of FS.
+    // rx_find_FS() returns 0 if found. If nonzero, the field will
+    // be the rest of the record (all of it if first time through).
+    if ((r = rx_find_FS(rx, s, &offs, &end, eflag))) offs = end = strlen(s);
+    else if (setter == set_field && multiline_null_rs && one_char_fs) {
+      // Contra POSIX, if RS=="" then newline is always also a
+      // field separator only if FS is a single char (see gawk manual)
+      int k = strcspn(s, "\n");
+      if (k < offs) offs = k, end = k + 1;
+    }
+    eflag |= REG_NOTBOL;
+
+    // Field will be s up to (not including) the offset. If offset
+    // is zero and FS is found and FS is ' ' (TT.rx_default "[ \t]+"),
+    // then the find is the leading or trailing spaces and/or tabs.
+    // If so, skip this (empty) field, otherwise set field, length is offs.
+    if (offs || r || rx != &TT.rx_default) setter(m, ++nf, s, offs);
+    s += end;
+  }
+  if (!r && rx != &TT.rx_default) setter(m, ++nf, "", 0);
+  return nf;
+}
+
+static void build_fields(void)
+{
+  char *rec = FIELD[0].vst->str;
+  // TODO test this -- why did I not want to split empty $0?
+  // Maybe don't split empty $0 b/c non-default FS gets NF==1 with splitter()?
+  set_nf(*rec ? splitter(set_field, 0, rec, to_str(&STACK[FS])) : 0);
+}
+
+static void rebuild_field0(void)
+{
+  struct zstring *s = FIELD[0].vst;
+  int nf = TT.nf_internal;
+  // uninit value needed for eventual reference to .vst in zstring_release()
+  struct zvalue tempv = uninit_zvalue;
+  zvalue_copy(&tempv, to_str(&STACK[OFS]));
+  for (int i = 1; i <= nf; i++) {
+    if (i > 1) {
+      s = s ? zstring_extend(s, tempv.vst) : zstring_copy(s, tempv.vst);
+    }
+    if (FIELD[i].flags) to_str(&FIELD[i]);
+    if (FIELD[i].vst) {
+      if (i > 1) s = zstring_extend(s, FIELD[i].vst);
+      else s = zstring_copy(s, FIELD[i].vst);
+    }
+  }
+  FIELD[0].vst = s;
+  FIELD[0].flags |= ZF_STR;
+  zvalue_release_zstring(&tempv);
+}
+
+// get field ref (lvalue ref) in prep for assignment to field.
+// [... assigning to a nonexistent field (for example, $(NF+2)=5) shall
+// increase the value of NF; create any intervening TT.fields with the
+// uninitialized value; and cause the value of $0 to be recomputed, with the
+// TT.fields being separated by the value of OFS.]
+// Called by setup_lvalue()
+static struct zvalue *get_field_ref(int fnum)
+{
+  if (fnum < 0 || fnum > FIELDS_MAX) error_exit("bad field num %d", fnum);
+  if (fnum > TT.nf_internal) {
+    // Ensure TT.fields list is large enough for fnum
+    // Need len of TT.fields to be > fnum b/c e.g. fnum==1 implies 2 TT.fields
+    for (int i = TT.nf_internal + 1; i <= fnum; i++) {
+      if (i == zlist_len(&TT.fields)) zlist_append(&TT.fields, &uninit_zvalue);
+      zvalue_copy(&FIELD[i], &uninit_string_zvalue);
+    }
+    set_nf(fnum);
+  }
+  return &FIELD[fnum];
+}
+
+// Called by tksplit op
+static int split(struct zstring *s, struct zvalue *a, struct zvalue *fs)
+{
+  return splitter(set_map_element, a->map, s->str, fs);
+}
+
+// Called by getrec_f0_f() and getrec_f0()
+static void copy_to_field0(char *buf, size_t k)
+{
+  set_zvalue_str(&FIELD[0], buf, k);
+  check_numeric_string(&FIELD[0]);
+  build_fields();
+}
+
+// After changing $0, must rebuild TT.fields & reset NF
+// Changing other field must rebuild $0
+// Called by gsub() and assignment ops.
+static void fixup_fields(int fnum)
+{
+  if (fnum == THIS_MEANS_SET_NF) {  // NF was assigned to
+    int new_nf = get_int_val(&STACK[NF]);
+    // Ensure TT.fields list is large enough for fnum
+    // Need len of TT.fields to be > fnum b/c e.g. fnum==1 implies 2 TT.fields
+    for (int i = TT.nf_internal + 1; i <= new_nf; i++) {
+      if (i == zlist_len(&TT.fields)) zlist_append(&TT.fields, &uninit_zvalue);
+      zvalue_copy(&FIELD[i], &uninit_string_zvalue);
+    }
+    set_nf(TT.nf_internal = STACK[NF].num);
+    rebuild_field0();
+    return;
+  }
+  // fnum is # of field that was just updated.
+  // If it's 0, need to rebuild the TT.fields 1... n.
+  // If it's non-0, need to rebuild field 0.
+  to_str(&FIELD[fnum]);
+  if (fnum) check_numeric_string(&FIELD[fnum]);
+  if (fnum) rebuild_field0();
+  else build_fields();
+}
+
+// Fetching non-existent field gets uninit string value; no change to NF!
+// Called by tkfield op       // TODO inline it?
+static void push_field(int fnum)
+{
+  if (fnum < 0 || fnum > FIELDS_MAX) error_exit("bad field num %d", fnum);
+  // Contrary to posix, awk evaluates TT.fields beyond $NF as empty strings.
+  if (fnum > TT.nf_internal) push_val(&uninit_string_zvalue);
+  else push_val(&FIELD[fnum]);
+}
+
+////////////////////
+////   END fields
+////////////////////
+
+#define STKP    TT.stackp   // pointer to top of stack
+
+static double seedrand(double seed)
+{
+  static double prev_seed;
+  double r = prev_seed;
+  srandom(trunc(prev_seed = seed));
+  return r;
+}
+
+static int popnumval(void)
+{
+  return STKP-- -> num;
+}
+
+static void drop(void)
+{
+  if (!(STKP->flags & (ZF_ANYMAP | ZF_RX))) zstring_release(&STKP->vst);
+  STKP--;
+}
+
+static void drop_n(int n)
+{
+  while (n--) drop();
+}
+
+static void swap(void)
+{
+  struct zvalue tmp = STKP[-1];
+  STKP[-1] = STKP[0];
+  STKP[0] = tmp;
+}
+
+// Set and return logical (0/1) val of top TT.stack value; flag value as NUM.
+static int get_set_logical(void)
+{
+  struct zvalue *v = STKP;
+  force_maybemap_to_scalar(v);
+  int r = 0;
+  if (IS_NUM(v)) r = !! v->num;
+  else if (IS_STR(v)) r = (v->vst && v->vst->str[0]);
+  zvalue_release_zstring(v);
+  v->num = r;
+  v->flags = ZF_NUM;
+  return r;
+}
+
+
+static double to_num(struct zvalue *v)
+{
+  force_maybemap_to_scalar(v);
+  if (v->flags & ZF_NUMSTR) zvalue_release_zstring(v);
+  else if (!IS_NUM(v)) {
+    v->num = 0.0;
+    if (IS_STR(v) && v->vst) v->num = atof(v->vst->str);
+    zvalue_release_zstring(v);
+  }
+  v->flags = ZF_NUM;
+  return v->num;
+}
+
+static void set_num(struct zvalue *v, double n)
+{
+  zstring_release(&v->vst);
+  v->num = n;
+  v->flags = ZF_NUM;
+}
+
+static void incr_zvalue(struct zvalue *v)
+{
+  v->num = trunc(to_num(v)) + 1;
+}
+
+static void push_int_val(ptrdiff_t n)
+{
+  struct zvalue v = ZVINIT(ZF_NUM, n, 0);
+  push_val(&v);
+}
+
+static struct zvalue *get_map_val(struct zvalue *v, struct zvalue *key)
+{
+  struct zmap_slot *x = zmap_find_or_insert_key(v->map, to_str(key)->vst);
+  return &x->val;
+}
+
+static struct zvalue *setup_lvalue(int ref_stack_ptr, int parmbase, int *field_num)
+{
+  // ref_stack_ptr is number of slots down in stack the ref is
+  // for +=, *=, etc
+  // Stack is: ... scalar_ref value_to_op_by
+  // or ... subscript_val map_ref value_to_op_by
+  // or ... fieldref value_to_op_by
+  // for =, ++, --
+  // Stack is: ... scalar_ref
+  // or ... subscript_val map_ref
+  // or ... fieldnum fieldref
+  int k;
+  struct zvalue *ref, *v = 0; // init v to mute "may be uninit" warning
+  *field_num = -1;
+  ref = STKP - ref_stack_ptr;
+  if (ref->flags & ZF_FIELDREF) return get_field_ref(*field_num = ref->num);
+  k = ref->num >= 0 ? ref->num : parmbase - ref->num;
+  if (k == NF) *field_num = THIS_MEANS_SET_NF;
+  v = &STACK[k];
+  if (ref->flags & ZF_REF) {
+    force_maybemap_to_scalar(v);
+  } else if (ref->flags & ZF_MAPREF) {
+    force_maybemap_to_map(v);
+    if (!IS_MAP(v)) FATAL("scalar in array context");
+    v = get_map_val(v, STKP - ref_stack_ptr - 1);
+    swap();
+    drop();
+  } else FATAL("assignment to bad lvalue");
+  return v; // order FATAL() and return to mute warning
+}
+
+static struct zfile *new_file(char *fn, FILE *fp, char mode, char file_or_pipe,
+                              char is_std_file)
+{
+  struct zfile *f = xzalloc(sizeof(struct zfile));
+  *f = (struct zfile){TT.zfiles, xstrdup(fn), fp, mode, file_or_pipe,
+                isatty(fileno(fp)), is_std_file, 0, 0, 0, 0, 0, 0, 0, 0};
+  return TT.zfiles = f;
+}
+
+static int fflush_all(void)
+{
+  int ret = 0;
+  for (struct zfile *p = TT.zfiles; p; p = p->next)
+    if (fflush(p->fp)) ret = -1;
+  return ret;
+}
+
+static int fflush_file(int nargs)
+{
+  if (!nargs) return fflush_all();
+
+  to_str(STKP);   // filename at top of TT.stack
+  // Null string means flush all
+  if (!STKP[0].vst->str[0]) return fflush_all();
+
+  // is it open in file table?
+  for (struct zfile *p = TT.zfiles; p; p = p->next)
+    if (!strcmp(STKP[0].vst->str, p->fn))
+      if (!fflush(p->fp)) return 0;
+  return -1;    // error, or file not found in table
+}
+static int close_file(char *fn)
+{
+  // !fn (null ptr) means close all (exc. stdin/stdout/stderr)
+  int r = 0;
+  struct zfile *np, **pp = &TT.zfiles;
+  for (struct zfile *p = TT.zfiles; p; p = np) {
+    np = p->next;   // save in case unlinking file (invalidates p->next)
+    // Don't close std files -- wrecks print/printf (can be fixed though TODO)
+    if ((!p->is_std_file) && (!fn || !strcmp(fn, p->fn))) {
+      xfree(p->recbuf);
+      xfree(p->recbuf_multi);
+      xfree(p->recbuf_multx);
+      xfree(p->fn);
+      r = (p->fp) ? (p->file_or_pipe ? fclose : pclose)(p->fp) : -1;
+      *pp = p->next;
+      xfree(p);
+      if (fn) return r;
+    } else pp = &p->next; // only if not unlinking zfile
+  }
+  return -1;  // file not in table, or closed all files
+}
+
+static struct zfile badfile_obj, *badfile = &badfile_obj;
+
+// FIXME TODO check if file/pipe/mode matches what's in the table already.
+// Apparently gawk/mawk/nawk are OK with different mode, but just use the file
+// in whatever mode it's already in; i.e. > after >> still appends.
+static struct zfile *setup_file(char file_or_pipe, char *mode)
+{
+  to_str(STKP);   // filename at top of TT.stack
+  char *fn = STKP[0].vst->str;
+  // is it already open in file table?
+  for (struct zfile *p = TT.zfiles; p; p = p->next)
+    if (!strcmp(fn, p->fn)) {
+      drop();
+      return p;   // open; return it
+    }
+  FILE *fp = (file_or_pipe ? fopen : popen)(fn, mode);
+  if (fp) {
+    struct zfile *p = new_file(fn, fp, *mode, file_or_pipe, 0);
+    drop();
+    return p;
+  }
+  if (*mode != 'r') FFATAL("cannot open '%s'\n", fn);
+  drop();
+  return badfile;
+}
+
+// TODO FIXME should be a function?
+#define stkn(n) ((int)(TT.stackp - (n) - (struct zvalue *)TT.stack.base))
+
+static int getcnt(int k)
+{
+  if (k >= stkn(0)) FATAL("too few args for printf\n");
+  return (int)to_num(&STACK[k]);
+}
+
+static int fsprintf(FILE *ignored, const char *fmt, ...)
+{
+  (void)ignored;
+  va_list args, args2;
+  va_start(args, fmt);
+  va_copy(args2, args);
+  int len = vsnprintf(0, 0, fmt, args); // size needed
+  va_end(args);
+  if (len < 0) FATAL("Bad sprintf format");
+  // Unfortunately we have to mess with zstring internals here.
+  if (TT.rgl.zspr->size + len + 1 > TT.rgl.zspr->capacity) {
+      // This should always work b/c capacity > size
+      unsigned cap = 2 * TT.rgl.zspr->capacity + len;
+      TT.rgl.zspr = xrealloc(TT.rgl.zspr, sizeof(*TT.rgl.zspr) + cap);
+      TT.rgl.zspr->capacity = cap;
+    }
+  vsnprintf(TT.rgl.zspr->str + TT.rgl.zspr->size, len+1, fmt, args2);
+  TT.rgl.zspr->size += len;
+  TT.rgl.zspr->str[TT.rgl.zspr->size] = 0;
+  va_end(args2);
+  return 0;
+}
+
+static void varprint(int(*fpvar)(FILE *, const char *, ...), FILE *outfp, int nargs)
+{
+  int k, nn, nnc, fmtc, holdc, cnt1 = 0, cnt2 = 0;
+  char *s = 0;  // to shut up spurious warning
+  regoff_t offs = -1, e = -1;
+  char *pfmt, *fmt = to_str(STKP-nargs+1)->vst->str;
+  k = stkn(nargs - 2);
+  while (*fmt) {
+    double n = 0;
+    nn = strcspn(fmt, "%");
+    if (nn) {
+      holdc = fmt[nn];
+      fmt[nn] = 0;
+      fpvar(outfp, "%s", fmt);
+      fmt[nn] = holdc;
+    }
+    fmt += nn;
+    if (!*(pfmt = fmt)) break;
+    nnc = strcspn(fmt+1, "aAdiouxXfFeEgGcs%");
+    fmtc = fmt[nnc+1];
+    if (!fmtc) FFATAL("bad printf format '%s'", fmt);
+    holdc = fmt[nnc+2];
+    fmt[nnc+2] = 0;
+    if (rx_find(&TT.rx_printf_fmt, fmt, &offs, &e, 0))
+      FFATAL("bad printf format <%s>\n", fmt);
+    int nargsneeded = 1;
+    for (char *p = strchr(fmt, '*'); p; p = strchr(p+1, '*'))
+      nargsneeded++;
+    nargsneeded -= fmtc == '%';
+
+    switch (nargsneeded) {
+      case 0:
+        fpvar(outfp, fmt);
+        break;
+      case 3:
+        cnt1 = getcnt(k++);
+        ATTR_FALLTHROUGH_INTENDED;
+      case 2:
+        cnt2 = getcnt(k++);
+        ATTR_FALLTHROUGH_INTENDED;
+      case 1:
+        if (k > stkn(0)) FATAL("too few args for printf\n");
+        if (fmtc == 's') {
+          s = to_str(&STACK[k++])->vst->str;
+        } else if (fmtc == 'c' && !IS_NUM(&STACK[k])) {
+          unsigned wch;
+          struct zvalue *z = &STACK[k++];
+          if (z->vst && z->vst->str[0])
+            n = utf8towc(&wch, z->vst->str, z->vst->size) < 1 ? 0xfffd : wch;
+        } else {
+          n = to_num(&STACK[k++]);
+        }
+        if (strchr("cdiouxX", fmtc)) {
+          pfmt = strcpy(TT.pbuf, fmt);
+          if (pfmt[nnc] != 'l') {
+            strcpy(pfmt+nnc+1, "l_");
+            pfmt[nnc+2] = fmtc;
+          }
+        }
+        if (fmtc == 'c' && n > 0x10ffff) n = 0xfffd;  // musl won't take larger "wchar"
+        switch (nargsneeded) {
+          case 1:
+            if (fmtc == 's') fpvar(outfp, pfmt, s);
+            else if (fmtc == 'c') fpvar(outfp, pfmt, (wint_t)n);
+            else if (strchr("di", fmtc)) fpvar(outfp, pfmt, (long)n);
+            else if (strchr("ouxX", fmtc)) fpvar(outfp, pfmt, (unsigned long)n);
+            else fpvar(outfp, pfmt, n);
+            break;
+          case 2:
+            if (fmtc == 's') fpvar(outfp, pfmt, cnt2, s);
+            else if (fmtc == 'c') fpvar(outfp, pfmt, cnt2, (wint_t)n);
+            else if (strchr("di", fmtc)) fpvar(outfp, pfmt, cnt2, (long)n);
+            else if (strchr("ouxX", fmtc)) fpvar(outfp, pfmt, cnt2, (unsigned long)n);
+            else fpvar(outfp, pfmt, cnt2, n);
+            break;
+          case 3:
+            if (fmtc == 's') fpvar(outfp, pfmt, cnt1, cnt2, s);
+            else if (fmtc == 'c') fpvar(outfp, pfmt, cnt1, cnt2, (wint_t)n);
+            else if (strchr("di", fmtc)) fpvar(outfp, pfmt, cnt1, cnt2, (long)n);
+            else if (strchr("ouxX", fmtc)) fpvar(outfp, pfmt, cnt1, cnt2, (unsigned long)n);
+            else fpvar(outfp, pfmt, cnt1, cnt2, n);
+            break;
+        }
+        break;
+      default:
+        FATAL("bad printf format\n");
+    }
+    fmt += nnc + 2;
+    *fmt = holdc;
+  }
+}
+
+static int is_ok_varname(char *v)
+{
+  char *ok = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
+  if (!*v) return 0;
+  for (int i = 0; v[i]; i++)
+    if (i ? !strchr(ok, v[i]) : !strchr(ok + 10, v[i])) return 0;
+  return 1;
+}
+
+// FIXME TODO return value never used. What if assign to var not in globals?
+static int assign_global(char *var, char *value)
+{
+  if (!is_ok_varname(var)) FFATAL("Invalid variable name '%s'\n", var);
+  int globals_ent = find_global(var);
+  if (globals_ent) {
+    struct zvalue *v = &STACK[globals_ent];
+    if (IS_MAP(v)) error_exit("-v assignment to array");  // Maybe not needed?
+
+// The compile phase may insert a var in global table with flag of zero.  Then
+// init_globals() will assign a ZF_MAYBEMAP flag to it. If it is then assigned
+// via -v option or by assignment_arg() it will here be assigned a string value.
+// So first, remove all map data to prevent memory leak. BUG FIX // 2024-02-13.
+    if (v->flags & ZF_ANYMAP) {
+      zmap_delete_map_incl_slotdata(v->map);
+      xfree(v->map);
+      v->map = 0;
+      v->flags &= ~ZF_ANYMAP;
+    }
+
+    zvalue_release_zstring(v);
+    value = xstrdup(value);
+    *v = new_str_val(escape_str(value, 0));
+    xfree(value);
+    check_numeric_string(v);
+    return 1;
+  }
+  return 0;
+}
+
+// If valid assignment arg, assign the global and return 1;
+// otherwise return 0.
+// TODO FIXME This does not check the format of the variable per posix.
+// Needs to start w/ _A-Za-z then _A-Za-z0-9
+// If not valid assignment form, then nextfilearg needs to treat as filename.
+static int assignment_arg(char *arg)
+{
+  char *val = strchr(arg, '=');
+  if (val) {
+    *val++ = 0;
+    if (!is_ok_varname(arg)) {
+      *--val = '=';
+      return 0;
+    }
+    assign_global(arg, val);
+    *--val = '=';
+    return 1;
+  } else return 0;
+}
+
+static char *nextfilearg(void)
+{
+  char *arg;
+  do {
+    if (++TT.rgl.narg >= (int)to_num(&STACK[ARGC])) return 0;
+    struct zvalue *v = &STACK[ARGV];
+    struct zvalue zkey = ZVINIT(ZF_STR, 0,
+        num_to_zstring(TT.rgl.narg, to_str(&STACK[CONVFMT])->vst->str));
+    arg = "";
+    if (zmap_find(v->map, zkey.vst)) {
+      zvalue_copy(&TT.rgl.cur_arg, to_str(get_map_val(v, &zkey)));
+      arg = TT.rgl.cur_arg.vst->str;
+    }
+    zvalue_release_zstring(&zkey);
+  } while (!*arg || assignment_arg(arg));
+  TT.rgl.nfiles++;
+  return arg;
+}
+
+static int next_fp(void)
+{
+  char *fn = nextfilearg();
+  if (TT.cfile->fp && TT.cfile->fp != stdin) fclose(TT.cfile->fp);
+  if ((!fn && !TT.rgl.nfiles && TT.cfile->fp != stdin) || (fn && !strcmp(fn, "-"))) {
+    TT.cfile->fp = stdin;
+    TT.cfile->fn = "<stdin>";
+    zvalue_release_zstring(&STACK[FILENAME]);
+    STACK[FILENAME].vst = new_zstring("<stdin>", 7);
+  } else if (fn) {
+    if (!(TT.cfile->fp = fopen(fn, "r"))) FFATAL("can't open %s\n", fn);
+    TT.cfile->fn = fn;
+    zvalue_copy(&STACK[FILENAME], &TT.rgl.cur_arg);
+  } else {
+    TT.rgl.eof = 1;
+    return 0;
+  }
+  set_num(&STACK[FNR], 0);
+  TT.cfile->recoffs = TT.cfile->endoffs = 0;  // reset record buffer
+  TT.cfile->is_tty = isatty(fileno(TT.cfile->fp));
+  return 1;
+}
+
+static ssize_t getrec_multiline(struct zfile *zfp)
+{
+  ssize_t k, kk;
+  do {
+    k = getdelim(&zfp->recbuf_multi, &zfp->recbufsize_multi, '\n', zfp->fp);
+  } while (k > 0 && zfp->recbuf_multi[0] == '\n');
+  TT.rgl.recptr = zfp->recbuf_multi;
+  if (k < 0) return k;
+  // k > 0 and recbuf_multi is not only a \n. Prob. ends w/ \n
+  // but may not at EOF (last line w/o newline)
+  for (;;) {
+    kk = getdelim(&zfp->recbuf_multx, &zfp->recbufsize_multx, '\n', zfp->fp);
+    if (kk < 0 || zfp->recbuf_multx[0] == '\n') break;
+    // data is in zfp->recbuf_multi[0..k-1]; append to it
+    if ((size_t)(k + kk + 1) > zfp->recbufsize_multi)
+      zfp->recbuf_multi =
+          xrealloc(zfp->recbuf_multi, zfp->recbufsize_multi = k + kk + 1);
+    memmove(zfp->recbuf_multi + k, zfp->recbuf_multx, kk+1);
+    k += kk;
+  }
+  if (k > 1 && zfp->recbuf_multi[k-1] == '\n') zfp->recbuf_multi[--k] = 0;
+  TT.rgl.recptr = zfp->recbuf_multi;
+  return k;
+}
+
+static int rx_findx(regex_t *rx, char *s, long len, regoff_t *start, regoff_t *end, int eflags)
+{
+  regmatch_t matches[1];
+  int r = regexec0(rx, s, len, 1, matches, eflags);
+  if (r == REG_NOMATCH) return r;
+  if (r) FATAL("regexec error");  // TODO ? use regerr() to meaningful msg
+  *start = matches[0].rm_so;
+  *end = matches[0].rm_eo;
+  return 0;
+}
+
+// get a record; return length, or 0 at EOF
+static ssize_t getrec_f(struct zfile *zfp)
+{
+  int r = 0;
+  if (!ENSURE_STR(&STACK[RS])->vst->str[0]) return getrec_multiline(zfp);
+  regex_t rsrx, *rsrxp = &rsrx;
+  // TEMP!! FIXME Need to cache and avoid too-frequent rx compiles
+  rx_zvalue_compile(&rsrxp, &STACK[RS]);
+  regoff_t so = 0, eo = 0;
+  long ret = -1;
+  for ( ;; ) {
+    if (zfp->recoffs == zfp->endoffs) {
+#define INIT_RECBUF_LEN     8192
+#define RS_LENGTH_MARGIN    (INIT_RECBUF_LEN / 8)
+      if (!zfp->recbuf)
+        zfp->recbuf = xmalloc((zfp->recbufsize = INIT_RECBUF_LEN) + 1);
+      if (zfp->is_tty && !memcmp(STACK[RS].vst->str, "\n", 2)) {
+        zfp->endoffs = 0;
+        if (fgets(zfp->recbuf, zfp->recbufsize, zfp->fp))
+          zfp->endoffs = strlen(zfp->recbuf);
+      } else zfp->endoffs = fread(zfp->recbuf, 1, zfp->recbufsize, zfp->fp);
+      zfp->recoffs = 0;
+      zfp->recbuf[zfp->endoffs] = 0;
+      if (!zfp->endoffs) break;
+    }
+    TT.rgl.recptr = zfp->recbuf + zfp->recoffs;
+    r = rx_findx(rsrxp, TT.rgl.recptr, zfp->endoffs - zfp->recoffs, &so, &eo, 0);
+    if (!r && so == eo) r = 1;  // RS was empty, so fake not found
+    if (r || zfp->recoffs + eo > (int)zfp->recbufsize - RS_LENGTH_MARGIN) {
+      // not found, or found "near" end of buffer...
+      if (zfp->endoffs < (int)zfp->recbufsize &&
+          (r || zfp->recoffs + eo == zfp->endoffs)) {
+        // at end of data, and (not found or found at end of data)
+        ret = zfp->endoffs - zfp->recoffs;
+        zfp->recoffs = zfp->endoffs;
+        break;
+      }
+      if (zfp->recoffs) {
+        // room to move data up: move remaining data in buffer to low end
+        memmove(zfp->recbuf, TT.rgl.recptr, zfp->endoffs - zfp->recoffs);
+        zfp->endoffs -= zfp->recoffs;
+        zfp->recoffs = 0;
+      } else zfp->recbuf =    // enlarge buffer
+        xrealloc(zfp->recbuf, (zfp->recbufsize = zfp->recbufsize * 3 / 2) + 1);
+      // try to read more into buffer past current data
+      zfp->endoffs += fread(zfp->recbuf + zfp->endoffs,
+                      1, zfp->recbufsize - zfp->endoffs, zfp->fp);
+      zfp->recbuf[zfp->endoffs] = 0;
+    } else {
+      // found and not too near end of data
+      ret = so;
+      TT.rgl.recptr[so] = 0;
+      zfp->recoffs += eo;
+      break;
+    }
+  }
+  regfree(rsrxp);
+  return ret;
+}
+
+static ssize_t getrec(void)
+{
+  ssize_t k;
+  if (TT.rgl.eof) return -1;
+  if (!TT.cfile->fp) next_fp();
+  do {
+    if ((k = getrec_f(TT.cfile)) >= 0) return k;
+  } while (next_fp());
+  return -1;
+}
+
+static ssize_t getrec_f0_f(struct zfile *zfp)
+{
+  ssize_t k = getrec_f(zfp);
+  if (k >= 0) {
+    copy_to_field0(TT.rgl.recptr, k);
+  }
+  return k;
+}
+
+static ssize_t getrec_f0(void)
+{
+  ssize_t k = getrec();
+  if (k >= 0) {
+    copy_to_field0(TT.rgl.recptr, k);
+    incr_zvalue(&STACK[NR]);
+    incr_zvalue(&STACK[FNR]);
+  }
+  return k;
+}
+
+// source is tkeof (no pipe/file), tklt (file), or tkpipe (pipe)
+// fp is file or pipe (is NULL if file/pipe could not be opened)
+// FIXME TODO should -1 return be replaced by test at caller?
+// v is NULL or an lvalue ref
+static int awk_getline(int source, struct zfile *zfp, struct zvalue *v)
+{
+  ssize_t k;
+  int is_stream = source != tkeof;
+  if (is_stream && !zfp->fp) return -1;
+  if (v) {
+    if ((k = is_stream ? getrec_f(zfp) : getrec()) < 0) return 0;
+    zstring_release(&v->vst);
+    v->vst = new_zstring(TT.rgl.recptr, k);
+    v->flags = ZF_STR;
+    check_numeric_string(v);    // bug fix 20240514
+    if (!is_stream) {
+      incr_zvalue(&STACK[NR]);
+      incr_zvalue(&STACK[FNR]);
+    }
+  } else k = is_stream ? getrec_f0_f(zfp) : getrec_f0();
+  return k < 0 ? 0 : 1;
+}
+
+// Define GAWK_SUB to get the same behavior with sub()/gsub() replacement text
+// as with gawk, goawk, and recent bwk awk (nawk) versions. Undefine GAWK_SUB
+// to get the simpler POSIX behavior, but I think most users will prefer the
+// gawk behavior. See the gawk (GNU Awk) manual,
+// sec. 9.1.4.1 // More about '\' and '&' with sub(), gsub(), and gensub()
+// for details on the differences.
+//
+#undef GAWK_SUB
+#define GAWK_SUB
+
+// sub(ere, repl[, in]) Substitute the string repl in place of the
+// first instance of the extended regular expression ERE in string 'in'
+// and return the number of substitutions.  An <ampersand> ( '&' )
+// appearing in the string repl shall be replaced by the string from in
+// that matches the ERE. (partial spec... there's more)
+static void gsub(int opcode, int nargs, int parmbase)
+{ (void)nargs;
+  int field_num = -1;
+  // compile ensures 3 args
+  struct zvalue *v = setup_lvalue(0, parmbase, &field_num);
+  struct zvalue *ere = STKP-2;
+  struct zvalue *repl = STKP-1;
+  regex_t rx, *rxp = &rx;
+  rx_zvalue_compile(&rxp, ere);
+  to_str(repl);
+  to_str(v);
+
+#define SLEN(zvalp) ((zvalp)->vst->size)
+  char *p, *rp0 = repl->vst->str, *rp = rp0, *s = v->vst->str;
+  int namps = 0, nhits = 0, is_sub = (opcode == tksub), eflags = 0;
+  regoff_t so = -1, eo;
+  // Count ampersands in repl string; may be overcount due to \& escapes.
+  for (rp = rp0; *rp; rp++) namps += *rp == '&';
+  p = s;
+  regoff_t need = SLEN(v) + 1;  // capacity needed for result string
+  // A pass just to determine needed destination (result) string size.
+  while(!rx_find(rxp, p, &so, &eo, eflags)) {
+    need += SLEN(repl) + (eo - so) * (namps - 1);
+    if (!*p) break;
+    p += eo ? eo : 1; // ensure progress if empty hit at start
+    if (is_sub) break;
+    eflags |= REG_NOTBOL;
+  }
+
+  if (so >= 0) {  // at least one hit
+    struct zstring *z = xzalloc(sizeof(*z) + need);
+    z->capacity = need;
+
+    char *e = z->str; // result destination pointer
+    p = s;
+    eflags = 0;
+    char *ep0 = p, *sp, *ep;
+    while(!rx_find(rxp, p, &so, &eo, eflags)) {
+      sp = p + so;
+      ep = p + eo;
+      memmove(e, ep0, sp - ep0);  // copy unchanged part
+      e += sp - ep0;
+      // Skip match if not at start and just after prev match and this is empty
+      if (p == s || sp - ep0 || eo - so) {
+        nhits++;
+        for (rp = rp0; *rp; rp++) { // copy replacement
+          if (*rp == '&') {
+            memmove(e, sp, eo - so);  //copy match
+            e += eo - so;
+          } else if (*rp == '\\') {
+            if (rp[1] == '&') *e++ = *++rp;
+            else if (rp[1] != '\\') *e++ = *rp;
+            else {
+#ifdef GAWK_SUB
+              if (rp[2] == '\\' && rp[3] == '&') {
+                rp += 2;
+                *e++ = *rp;
+              } else if (rp[2] != '&') *e++ = '\\';
+#endif
+              *e++ = *++rp;
+            }
+          } else *e++ = *rp;
+        }
+      }
+      ep0 = ep;
+      if (!*p) break;
+      p += eo ? eo : 1; // ensure progress if empty hit at start
+      if (is_sub) break;
+      eflags |= REG_NOTBOL;
+    }
+    // copy remaining subject string
+    memmove(e, ep0, s + SLEN(v) - ep0);
+    e += s + SLEN(v) - ep0;
+    *e = 0;
+    z->size = e - z->str;
+    zstring_release(&v->vst);
+    v->vst = z;
+  }
+  rx_zvalue_free(rxp, ere);
+  if (!IS_RX(STKP-2)) zstring_release(&STKP[-2].vst);
+  drop_n(3);
+  push_int_val(nhits);
+  if (field_num >= 0) fixup_fields(field_num);
+}
+
+// Initially set stackp_needmore at MIN_STACK_LEFT before limit.
+// When stackp > stackp_needmore, then expand and reset stackp_needmore
+static void add_stack(struct zvalue **stackp_needmore)
+{
+  int k = stkn(0);  // stack elements in use
+  zlist_expand(&TT.stack);
+  STKP = (struct zvalue *)TT.stack.base + k;
+  *stackp_needmore = (struct zvalue *)TT.stack.limit - MIN_STACK_LEFT;
+}
+
+#define CLAMP(x, lo, hi) ((x) < (lo) ? (lo) : (x) > (hi) ? (hi) : (x))
+
+// Main loop of interpreter. Run this once for all BEGIN rules (which
+// have had their instructions chained in compile), all END rules (also
+// chained in compile), and once for each record of the data file(s).
+static int interpx(int start, int *status)
+{
+  int *ip = &ZCODE[start];
+  int opcode, op2, k, r, nargs, nsubscrs, range_num, parmbase = 0;
+  int field_num;
+  double nleft, nright, d;
+  double (*mathfunc[])(double) = {cos, sin, exp, log, sqrt, trunc};
+  struct zvalue *v, vv,
+        *stackp_needmore = (struct zvalue*)TT.stack.limit - MIN_STACK_LEFT;
+  while ((opcode = *ip++)) {
+
+    switch (opcode) {
+      case opquit:
+        return opquit;
+
+      case tknot:
+        (STKP)->num = ! get_set_logical();
+        break;
+
+      case opnotnot:
+        get_set_logical();
+        break;
+
+      case opnegate:
+        STKP->num = -to_num(STKP);
+        break;
+
+      case tkpow:         // FALLTHROUGH intentional here
+      case tkmul:         // FALLTHROUGH intentional here
+      case tkdiv:         // FALLTHROUGH intentional here
+      case tkmod:         // FALLTHROUGH intentional here
+      case tkplus:        // FALLTHROUGH intentional here
+      case tkminus:
+        nleft = to_num(STKP-1);
+        nright = to_num(STKP);
+        switch (opcode) {
+          case tkpow: nleft = pow(nleft, nright); break;
+          case tkmul: nleft *= nright; break;
+          case tkdiv: nleft /= nright; break;
+          case tkmod: nleft = fmod(nleft, nright); break;
+          case tkplus: nleft += nright; break;
+          case tkminus: nleft -= nright; break;
+        }
+        drop();
+        STKP->num = nleft;
+        break;
+
+      // FIXME REDO REDO ?
+      case tkcat:
+        to_str(STKP-1);
+        to_str(STKP);
+        STKP[-1].vst = zstring_extend(STKP[-1].vst, STKP[0].vst);
+        drop();
+        break;
+
+        // Comparisons (with the '<', "<=", "!=", "==", '>', and ">="
+        // operators) shall be made numerically if both operands are numeric,
+        // if one is numeric and the other has a string value that is a numeric
+        // string, or if one is numeric and the other has the uninitialized
+        // value. Otherwise, operands shall be converted to strings as required
+        // and a string comparison shall be made as follows:
+        //
+        // For the "!=" and "==" operators, the strings should be compared to
+        // check if they are identical but may be compared using the
+        // locale-specific collation sequence to check if they collate equally.
+        //
+        // For the other operators, the strings shall be compared using the
+        // locale-specific collation sequence.
+        //
+        // The value of the comparison expression shall be 1 if the relation is
+        // true, or 0 if the relation is false.
+      case tklt:          // FALLTHROUGH intentional here
+      case tkle:          // FALLTHROUGH intentional here
+      case tkne:          // FALLTHROUGH intentional here
+      case tkeq:          // FALLTHROUGH intentional here
+      case tkgt:          // FALLTHROUGH intentional here
+      case tkge:
+        ; int cmp = 31416;
+
+        if (  (IS_NUM(&STKP[-1]) &&
+              (STKP[0].flags & (ZF_NUM | ZF_NUMSTR) || !STKP[0].flags)) ||
+              (IS_NUM(&STKP[0]) &&
+              (STKP[-1].flags & (ZF_NUM | ZF_NUMSTR) || !STKP[-1].flags))) {
+          switch (opcode) {
+            case tklt: cmp = STKP[-1].num < STKP[0].num; break;
+            case tkle: cmp = STKP[-1].num <= STKP[0].num; break;
+            case tkne: cmp = STKP[-1].num != STKP[0].num; break;
+            case tkeq: cmp = STKP[-1].num == STKP[0].num; break;
+            case tkgt: cmp = STKP[-1].num > STKP[0].num; break;
+            case tkge: cmp = STKP[-1].num >= STKP[0].num; break;
+          }
+        } else {
+          cmp = strcmp(to_str(STKP-1)->vst->str, to_str(STKP)->vst->str);
+          switch (opcode) {
+            case tklt: cmp = cmp < 0; break;
+            case tkle: cmp = cmp <= 0; break;
+            case tkne: cmp = cmp != 0; break;
+            case tkeq: cmp = cmp == 0; break;
+            case tkgt: cmp = cmp > 0; break;
+            case tkge: cmp = cmp >= 0; break;
+          }
+        }
+        drop();
+        drop();
+        push_int_val(cmp);
+        break;
+
+      case opmatchrec:
+        op2 = *ip++;
+        int mret = match(&FIELD[0], &LITERAL[op2]);
+        push_int_val(!mret);
+        break;
+
+      case tkmatchop:
+      case tknotmatch:
+        mret = match(STKP-1, STKP); // mret == 0 if match
+        drop();
+        drop();
+        push_int_val(!mret == (opcode == tkmatchop));
+        break;
+
+      case tkpowasgn:     // FALLTHROUGH intentional here
+      case tkmodasgn:     // FALLTHROUGH intentional here
+      case tkmulasgn:     // FALLTHROUGH intentional here
+      case tkdivasgn:     // FALLTHROUGH intentional here
+      case tkaddasgn:     // FALLTHROUGH intentional here
+      case tksubasgn:
+        // Stack is: ... scalar_ref value_to_op_by
+        // or ... subscript_val map_ref value_to_op_by
+        // or ... fieldref value_to_op_by
+        v = setup_lvalue(1, parmbase, &field_num);
+        to_num(v);
+        to_num(STKP);
+        switch (opcode) {
+          case tkpowasgn:
+            // TODO
+            v->num = pow(v->num, STKP->num);
+            break;
+          case tkmodasgn:
+            // TODO
+            v->num = fmod(v->num, STKP->num);
+            break;
+          case tkmulasgn:
+            v->num *= STKP->num;
+            break;
+          case tkdivasgn:
+            v->num /= STKP->num;
+            break;
+          case tkaddasgn:
+            v->num += STKP->num;
+            break;
+          case tksubasgn:
+            v->num -= STKP->num;
+            break;
+        }
+
+        drop_n(2);
+        v->flags = ZF_NUM;
+        push_val(v);
+        if (field_num >= 0) fixup_fields(field_num);
+        break;
+
+      case tkasgn:
+        // Stack is: ... scalar_ref value_to_assign
+        // or ... subscript_val map_ref value_to_assign
+        // or ... fieldref value_to_assign
+        v = setup_lvalue(1, parmbase, &field_num);
+        force_maybemap_to_scalar(STKP);
+        zvalue_copy(v, STKP);
+        swap();
+        drop();
+        if (field_num >= 0) fixup_fields(field_num);
+        break;
+
+      case tkincr:        // FALLTHROUGH intentional here
+      case tkdecr:        // FALLTHROUGH intentional here
+      case oppreincr:     // FALLTHROUGH intentional here
+      case oppredecr:
+        // Stack is: ... scalar_ref
+        // or ... subscript_val map_ref
+        // or ... fieldnum fieldref
+        v = setup_lvalue(0, parmbase, &field_num);
+        to_num(v);
+        switch (opcode) {
+          case tkincr: case tkdecr:
+            // Must be done in this order because push_val(v) may move v,
+            // invalidating the pointer.
+            v->num += (opcode == tkincr) ? 1 : -1;
+            push_val(v);
+            // Now reverse the incr/decr on the top TT.stack val.
+            STKP->num -= (opcode == tkincr) ? 1 : -1;
+            break;
+          case oppreincr: case oppredecr:
+            v->num += (opcode == oppreincr) ? 1 : -1;
+            push_val(v);
+            break;
+        }
+        swap();
+        drop();
+        if (field_num >= 0) fixup_fields(field_num);
+        break;
+
+      case tknumber:      // FALLTHROUGH intentional here
+      case tkstring:      // FALLTHROUGH intentional here
+      case tkregex:
+        push_val(&LITERAL[*ip++]);
+        break;
+
+      case tkprint:
+      case tkprintf:
+        nargs = *ip++;
+        int outmode = *ip++;
+        struct zfile *outfp = TT.zstdout;
+        switch (outmode) {
+          case tkgt: outfp = setup_file(1, "w"); break;     // file
+          case tkappend: outfp = setup_file(1, "a"); break; // file
+          case tkpipe: outfp = setup_file(0, "w"); break;   // pipe
+          default: nargs++; break;
+        }
+        nargs--;
+        if (opcode == tkprintf) {
+          varprint(fprintf, outfp->fp, nargs);
+          drop_n(nargs);
+          break;
+        }
+        if (!nargs) {
+          fprintf(outfp->fp, "%s", to_str(&FIELD[0])->vst->str);
+        } else {
+          struct zvalue tempv = uninit_zvalue;
+          zvalue_copy(&tempv, &STACK[OFS]);
+          to_str(&tempv);
+          for (int k = 0; k < nargs; k++) {
+            if (k) fprintf(outfp->fp, "%s", tempv.vst->str);
+            int sp = stkn(nargs - 1 - k);
+            ////// FIXME refcnt -- prob. don't need to copy from TT.stack?
+            v = &STACK[sp];
+            to_str_fmt(v, OFMT);
+            struct zstring *zs = v->vst;
+            fprintf(outfp->fp, "%s", zs ? zs->str : "");
+          }
+          zvalue_release_zstring(&tempv);
+          drop_n(nargs);
+        }
+        fputs(ENSURE_STR(&STACK[ORS])->vst->str, outfp->fp);
+        break;
+
+      case opdrop:
+        drop();
+        break;
+
+      case opdrop_n:
+        drop_n(*ip++);
+        break;
+
+        // Stack frame layout relative to parmbase:
+#define RETURN_VALUE    -4
+#define RETURN_ADDR     -3
+#define PREV_PARMBASE   -2
+#define ARG_CNT         -1
+#define FUNCTION_NUM    0
+        // Actual args follow, starting at parmbase + 1
+      case tkfunction:    // function definition
+        op2 = *ip++;    // func table num
+        struct functab_slot *pfdef = &FUNC_DEF[op2];
+        struct zlist *loctab = &pfdef->function_locals;
+        int nparms = zlist_len(loctab)-1;
+
+        nargs = popnumval();
+        int newparmbase = stkn(nargs);
+        STACK[newparmbase + PREV_PARMBASE].num = parmbase;
+        parmbase = newparmbase;
+        for ( ;nargs > nparms; nargs--)
+          drop();
+        for ( ;nargs < nparms; nargs++) {
+          // Push additional "args" that were not passed by the caller, to
+          // match the formal parameters (parms) defined in the function
+          // definition. In the local var table we may have the type as scalar
+          // or map if it is used as such within the function. In that case we
+          // init the pushed arg from the type of the locals table.
+          // But if a var appears only as a bare arg in a function call it will
+          // not be typed in the locals table. In that case we can only say it
+          // "may be" a map, but we have to assume the possibility and attach a
+          // map to the var. When/if the var is used as a map or scalar in the
+          // called function it will be converted to a map or scalar as
+          // required.
+          // See force_maybemap_to_scalar().
+          struct symtab_slot *q = &((struct symtab_slot *)loctab->base)[nargs+1];
+          vv = (struct zvalue)ZVINIT(q->flags, 0, 0);
+          if (vv.flags == 0) {
+            zvalue_map_init(&vv);
+            vv.flags = ZF_MAYBEMAP;
+          } else if (IS_MAP(&vv)) {
+            zvalue_map_init(&vv);
+          } else {
+            vv.flags = 0;
+          }
+          push_val(&vv);
+        }
+        break;
+
+      case tkreturn:
+        nparms = *ip++;
+        nargs = STACK[parmbase+ARG_CNT].num;
+        force_maybemap_to_scalar(STKP); // Unneeded?
+        zvalue_copy(&STACK[parmbase+RETURN_VALUE], STKP);
+        drop();
+        // Remove the local args (not supplied by caller) from TT.stack, check to
+        // release any map data created.
+        while (stkn(0) > parmbase + nargs) {
+          if ((STKP)->flags & ZF_ANYMAP) {
+            zmap_delete_map_incl_slotdata((STKP)->map);
+            xfree((STKP)->map);
+          }
+          drop();
+        }
+        while (stkn(0) > parmbase + RETURN_VALUE)
+          drop();
+        ip = &ZCODE[(int)STACK[parmbase+RETURN_ADDR].num];
+        parmbase = STACK[parmbase+PREV_PARMBASE].num;
+        break;
+
+      case opprepcall:    // function call prep
+        if (STKP > stackp_needmore) add_stack(&stackp_needmore);
+        push_int_val(0);      // return value placeholder
+        push_int_val(0);      // return addr
+        push_int_val(0);      // parmbase
+        push_int_val(0);      // arg count
+        push_int_val(*ip++);  // function tbl ref
+        break;
+
+      case tkfunc:        // function call
+        nargs = *ip++;
+        newparmbase = stkn(nargs);
+        STACK[newparmbase+RETURN_ADDR].num = ip - &ZCODE[0];
+        STACK[newparmbase+ARG_CNT].num = nargs;
+        push_int_val(nargs);      // FIXME TODO pass this in a zregister?
+        ip = &ZCODE[FUNC_DEF[(int)STACK[newparmbase+FUNCTION_NUM].num].zcode_addr];
+        break;
+
+      case tkrbracket:    // concat multiple map subscripts
+        nsubscrs = *ip++;
+        while (--nsubscrs) {
+          swap();
+          to_str(STKP);
+          push_val(&STACK[SUBSEP]);
+          to_str(STKP);
+          STKP[-1].vst = zstring_extend(STKP[-1].vst, STKP->vst);
+          drop();
+          swap();
+          to_str(STKP);
+          STKP[-1].vst = zstring_extend(STKP[-1].vst, STKP->vst);
+          drop();
+        }
+        break;
+
+      case opmapdelete:
+      case tkdelete:
+        k = STKP->num;
+        if (k < 0) k = parmbase - k;    // loc of var on TT.stack
+        v = &STACK[k];
+        force_maybemap_to_map(v);
+        if (opcode == opmapdelete) {
+          zmap_delete_map(v->map);
+        } else {
+          drop();
+          zmap_delete(v->map, to_str(STKP)->vst);
+        }
+        drop();
+        break;
+
+      case opmap:
+        op2 = *ip++;
+        k = op2 < 0 ? parmbase - op2 : op2;
+        v = &STACK[k];
+        force_maybemap_to_map(v);
+        if (!IS_MAP(v)) FATAL("scalar in array context");
+        v = get_map_val(v, STKP);
+        drop();     // drop subscript
+        push_val(v);
+        break;
+
+      case tkin:
+        if (!(STKP->flags & ZF_ANYMAP)) FATAL("scalar in array context");
+        v = zmap_find(STKP->map, to_str(STKP-1)->vst);
+        drop();
+        drop();
+        push_int_val(v ? 1 : 0);
+        break;
+
+      case opmapiternext:
+        op2 = *ip++;
+        v = STKP-1;
+        force_maybemap_to_map(v);
+        if (!IS_MAP(v)) FATAL("scalar in array context");
+        struct zmap *m = v->map;   // Need for MAPSLOT macro
+        int zlen = zlist_len(&m->slot);
+        int kk = STKP->num + 1;
+        while (kk < zlen && !(MAPSLOT[kk].key)) // skip deleted slots
+          kk++;
+        STKP->num = kk; // save index for next iteration
+        if (kk < zlen) {
+          struct zvalue *var = setup_lvalue(2, parmbase, &field_num);
+          var->flags = ZF_STR;
+          zstring_release(&var->vst);
+          var->vst = MAPSLOT[kk].key;
+          zstring_incr_refcnt(var->vst);
+          ip += op2;
+        }
+        break;
+
+      case tkvar:
+        op2 = *ip++;
+        k = op2 < 0 ? parmbase - op2 : op2;
+        v = &STACK[k];
+        push_val(v);
+        break;
+
+      case tkfield:
+        // tkfield op has "dummy" 2nd word so that convert_push_to_reference(void)
+        // can find either tkfield or tkvar at same place (ZCODE[TT.zcode_last-1]).
+        ip++; // skip dummy "operand" instruction field
+        push_field((int)(to_num(STKP)));
+
+        swap();
+        drop();
+        break;
+
+      case oppush:
+        push_int_val(*ip++);
+        break;
+
+      case tkand:
+        op2 = *ip++;
+        if (get_set_logical()) drop();
+        else ip += op2;
+        break;
+
+      case tkor:
+        op2 = *ip++;
+        if (!get_set_logical()) drop();
+        else ip += op2;
+        break;
+
+      case tkwhile:
+        (STKP)->num = ! get_set_logical();
+        ATTR_FALLTHROUGH_INTENDED;
+        // FALLTHROUGH to tkternif
+      case tkif:
+        // FALLTHROUGH to tkternif
+      case tkternif:
+        op2 = *ip++;
+        int t = get_set_logical();  // FIXME only need to get, not set
+        drop();
+        if (!t) ip += op2;
+        break;
+
+      case tkelse:        // FALLTHROUGH intentional here
+      case tkternelse:    // FALLTHROUGH intentional here
+      case tkbreak:       // FALLTHROUGH intentional here
+      case tkcontinue:    // FALLTHROUGH intentional here
+      case opjump:
+        op2 = *ip++;
+        ip += op2;
+        break;
+
+      case opvarref:
+        op2 = *ip++;
+        vv = (struct zvalue)ZVINIT(ZF_REF, op2, 0);
+        push_val(&vv);
+        break;
+
+      case opmapref:
+        op2 = *ip++;
+        vv = (struct zvalue)ZVINIT(ZF_MAPREF, op2, 0);
+        push_val(&vv);
+        break;
+
+      case opfldref:
+        to_num(STKP);
+        (STKP)->flags |= ZF_FIELDREF;
+        ip++; // skip dummy "operand" instruction field
+        break;
+
+      case opprintrec:
+        puts(to_str(&FIELD[0])->vst->str);
+        break;
+
+      case oprange1:
+        range_num = *ip++;
+        op2 = *ip++;
+        if (TT.range_sw[range_num]) ip += op2;
+        break;
+
+      case oprange2:
+        range_num = *ip++;
+        op2 = *ip++;
+        t = get_set_logical();  // FIXME only need to get, not set
+        drop();
+        if (t) TT.range_sw[range_num] = 1;
+        else ip += op2;
+        break;
+
+      case oprange3:
+        range_num = *ip++;
+        t = get_set_logical();  // FIXME only need to get, not set
+        drop();
+        if (t) TT.range_sw[range_num] = 0;
+        break;
+
+      case tkexit:
+        r = popnumval();
+        if (r != NO_EXIT_STATUS) *status = (int)r & 255;
+        // TODO FIXME do we need NO_EXIT_STATUS at all? Just use 0?
+        ATTR_FALLTHROUGH_INTENDED;
+      case tknext:
+      case tknextfile:
+        return opcode;
+
+      case tkgetline:
+        nargs = *ip++;
+        int source = *ip++;
+        // TT.stack is:
+        // if tkgetline 0 tkeof:   (nothing stacked; plain getline)
+        // if tkgetline 1 tkeof:   (lvalue)
+        // if tkgetline 1 tklt:    (filename_string)
+        // if tkgetline 2 tklt:    (lvalue) (filename_string)
+        // if tkgetline 1 tkpipe:  (pipe_command_string)
+        // if tkgetline 2 tkpipe:  (pipe_command_string) (lvalue)
+        // effect is to set:
+        // if tkgetline 0 tkeof:   $0 NF NR FNR
+        // if tkgetline 1 tkeof:   var NR FNR
+        // if tkgetline 1 tklt:    $0 NF
+        // if tkgetline 2 tklt:    var
+        // if tkgetline 1 tkpipe:  $0 NF
+        // if tkgetline 2 tkpipe:  var
+        // Ensure pipe cmd on top
+        if (nargs == 2 && source == tkpipe) swap();
+        struct zfile *zfp = 0;
+        if (source == tklt || source == tkpipe) {
+          zfp = setup_file(source == tklt, "r");
+          nargs--;
+        }
+        // now cases are:
+        // nargs source  TT.stack
+        //  0 tkeof:   (nothing; plain getline) from current data file
+        //  1 tkeof:   (lvalue)  from current data file
+        //  0 tklt:    (nothing) from named file in 'stream'
+        //  1 tklt:    (lvalue)  from  named file in 'stream'
+        //  0 tkpipe:  (nothing) from piped command in 'stream'
+        //  1 tkpipe:  (lvalue)  from piped command in 'stream'
+        v = nargs ? setup_lvalue(0, parmbase, &field_num) : 0;
+        if (v) drop();
+        // source is tkeof (no pipe/file), tklt (file), or tkpipe (pipe)
+        // stream is name of file or pipe
+        // v is NULL or an lvalue ref
+        if (zfp != badfile) push_int_val(awk_getline(source, zfp, v));
+        else push_int_val(-1);
+
+        // fake return value for now
+        break;
+
+        ////// builtin functions ///////
+
+      case tksplit:
+        nargs = *ip++;
+        if (nargs == 2) push_val(&STACK[FS]);
+        struct zstring *s = to_str(STKP-2)->vst;
+        force_maybemap_to_map(STKP-1);
+        struct zvalue *a = STKP-1;
+        struct zvalue *fs = STKP;
+        zmap_delete_map(a->map);
+        k = split(s, a, fs);
+        drop_n(3);
+        push_int_val(k);
+        break;
+
+      case tkmatch:
+        nargs = *ip++;
+        if (!IS_RX(STKP)) to_str(STKP);
+        regex_t rx_pat, *rxp = &rx_pat;
+        rx_zvalue_compile(&rxp, STKP);
+        regoff_t rso = 0, reo = 0;  // shut up warning (may be uninit)
+        k = rx_find(rxp, to_str(STKP-1)->vst->str, &rso, &reo, 0);
+        rx_zvalue_free(rxp, STKP);
+        // Force these to num before setting.
+        to_num(&STACK[RSTART]);
+        to_num(&STACK[RLENGTH]);
+        if (k) STACK[RSTART].num = 0, STACK[RLENGTH].num = -1;
+        else {
+          reo = utf8cnt(STKP[-1].vst->str, reo);
+          rso = utf8cnt(STKP[-1].vst->str, rso);
+          STACK[RSTART].num = rso + 1, STACK[RLENGTH].num = reo - rso;
+        }
+        drop();
+        drop();
+        push_int_val(k ? 0 : rso + 1);
+        break;
+
+      case tksub:
+      case tkgsub:
+        gsub(opcode, *ip++, parmbase);  // tksub/tkgsub, args
+        break;
+
+      case tksubstr:
+        nargs = *ip++;
+        struct zstring *zz = to_str(STKP - nargs + 1)->vst;
+        int nchars = utf8cnt(zz->str, zz->size);  // number of utf8 codepoints
+        // Offset of start of string (in chars not bytes); convert 1-based to 0-based
+        ssize_t mm = CLAMP(trunc(to_num(STKP - nargs + 2)) - 1, 0, nchars);
+        ssize_t nn = nchars - mm;   // max possible substring length (chars)
+        if (nargs == 3) nn = CLAMP(trunc(to_num(STKP)), 0, nn);
+        mm = bytesinutf8(zz->str, zz->size, mm);
+        nn = bytesinutf8(zz->str + mm, zz->size - mm, nn);
+        struct zstring *zzz = new_zstring(zz->str + mm, nn);
+        zstring_release(&(STKP - nargs + 1)->vst);
+        (STKP - nargs + 1)->vst = zzz;
+        drop_n(nargs - 1);
+        break;
+
+      case tkindex:
+        nargs = *ip++;
+        char *s1 = to_str(STKP-1)->vst->str;
+        char *s3 = strstr(s1, to_str(STKP)->vst->str);
+        ptrdiff_t offs = s3 ? utf8cnt(s1, s3 - s1) + 1 : 0;
+        drop();
+        drop();
+        push_int_val(offs);
+        break;
+
+      case tkband:
+      case tkbor:
+      case tkbxor:
+      case tklshift:
+      case tkrshift:
+        ; size_t acc = to_num(STKP);
+        nargs = *ip++;
+        for (int i = 1; i < nargs; i++) switch (opcode) {
+          case tkband: acc &= (size_t)to_num(STKP-i); break;
+          case tkbor:  acc |= (size_t)to_num(STKP-i); break;
+          case tkbxor: acc ^= (size_t)to_num(STKP-i); break;
+          case tklshift: acc = (size_t)to_num(STKP-i) << acc; break;
+          case tkrshift: acc = (size_t)to_num(STKP-i) >> acc; break;
+        }
+        drop_n(nargs);
+        push_int_val(acc);
+        break;
+
+      case tktolower:
+      case tktoupper:
+        nargs = *ip++;
+        struct zstring *z = to_str(STKP)->vst;
+        unsigned zzlen = z->size + 4; // Allow for expansion
+        zz = zstring_update(0, zzlen, "", 0);
+        char *p = z->str, *e = z->str + z->size, *q = zz->str;
+        // Similar logic to toybox strlower(), but fixed.
+        while (p < e) {
+          unsigned wch;
+          int len = utf8towc(&wch, p, e-p);
+          if (len < 1) {  // nul byte, error, or truncated code
+            *q++ = *p++;
+            continue;
+          }
+          p += len;
+          wch = (opcode == tktolower ? towlower : towupper)(wch);
+          len = wctoutf8(q, wch);
+          q += len;
+          // Need realloc here if overflow possible
+          if ((len = q - zz->str) + 4 < (int)zzlen) continue;
+          zz = zstring_update(zz, zzlen = len + 16, "", 0);
+          q = zz->str + len;
+        }
+        *q = 0;
+        zz->size = q - zz->str;
+        zstring_release(&z);
+        STKP->vst = zz;
+        break;
+
+      case tklength:
+        nargs = *ip++;
+        v = nargs ? STKP : &FIELD[0];
+        force_maybemap_to_map(v);
+        if (IS_MAP(v)) k = v->map->count - v->map->deleted;
+        else {
+          to_str(v);
+          k = utf8cnt(v->vst->str, v->vst->size);
+        }
+        if (nargs) drop();
+        push_int_val(k);
+        break;
+
+      case tksystem:
+        nargs = *ip++;
+        fflush(stdout);
+        fflush(stderr);
+        r = system(to_str(STKP)->vst->str);
+#ifdef WEXITSTATUS
+        // WEXITSTATUS is in sys/wait.h, but I'm not including that.
+        // It seems to also be in stdlib.h in gcc and musl-gcc.
+        // No idea how portable this is!
+        if (WIFEXITED(r)) r = WEXITSTATUS(r);
+#endif
+        drop();
+        push_int_val(r);
+        break;
+
+      case tkfflush:
+        nargs = *ip++;
+        r = fflush_file(nargs);
+        if (nargs) drop();
+        push_int_val(r);
+        break;
+
+      case tkclose:
+        nargs = *ip++;
+        r = close_file(to_str(STKP)->vst->str);
+        drop();
+        push_int_val(r);
+        break;
+
+      case tksprintf:
+        nargs = *ip++;
+        zstring_release(&TT.rgl.zspr);
+        TT.rgl.zspr = new_zstring("", 0);
+        varprint(fsprintf, 0, nargs);
+        drop_n(nargs);
+        vv = (struct zvalue)ZVINIT(ZF_STR, 0, TT.rgl.zspr);
+        push_val(&vv);
+        break;
+
+      // Math builtins -- move here (per Oliver Webb suggestion)
+      case tkatan2:
+        nargs = *ip++;
+        d = atan2(to_num(STKP-1), to_num(STKP));
+        drop();
+        STKP->num = d;
+        break;
+      case tkrand:
+        nargs = *ip++;
+        push_int_val(0);
+        // Get all 53 mantissa bits in play:
+        // (upper 26 bits * 2^27 + upper 27 bits) / 2^53
+        STKP->num =
+          ((random() >> 5) * 134217728.0 + (random() >> 4)) / 9007199254740992.0;
+        break;
+      case tksrand:
+        nargs = *ip++;
+        if (nargs == 1) {
+          STKP->num = seedrand(to_num(STKP));
+        } else push_int_val(seedrand(time(0)));
+        break;
+      case tkcos: case tksin: case tkexp: case tklog: case tksqrt: case tkint:
+        nargs = *ip++;
+        STKP->num = mathfunc[opcode-tkcos](to_num(STKP));
+        break;
+
+      default:
+        // This should never happen:
+        error_exit("!!! Unimplemented opcode %d", opcode);
+    }
+  }
+  return opquit;
+}
+
+// interp() wraps the main interpreter loop interpx(). The main purpose
+// is to allow the TT.stack to be readjusted after an 'exit' from a function.
+// Also catches errors, as the normal operation should leave the TT.stack
+// depth unchanged after each run through the rules.
+static int interp(int start, int *status)
+{
+  int stkptrbefore = stkn(0);
+  int r = interpx(start, status);
+  // If exit from function, TT.stack will be loaded with args etc. Clean it.
+  if (r == tkexit) {
+    // TODO FIXME is this safe? Just remove extra entries?
+    STKP = &STACK[stkptrbefore];
+  }
+  if (stkn(0) - stkptrbefore)
+    error_exit("!!AWK BUG stack pointer offset: %d", stkn(0) - stkptrbefore);
+  return r;
+}
+
+static void insert_argv_map(struct zvalue *map, int key, char *value)
+{
+  struct zvalue zkey = ZVINIT(ZF_STR, 0, num_to_zstring(key, ENSURE_STR(&STACK[CONVFMT])->vst->str));
+  struct zvalue *v = get_map_val(map, &zkey);
+  zvalue_release_zstring(&zkey);
+  zvalue_release_zstring(v);
+  *v = new_str_val(value);
+  check_numeric_string(v);
+}
+
+static void init_globals(int optind, int argc, char **argv, char *sepstring,
+    struct arg_list *assign_args)
+{
+  // Global variables reside at the bottom of the TT.stack. Start with the awk
+  // "special variables":  ARGC, ARGV, CONVFMT, ENVIRON, FILENAME, FNR, FS, NF,
+  // NR, OFMT, OFS, ORS, RLENGTH, RS, RSTART, SUBSEP
+
+  STACK[CONVFMT] = new_str_val("%.6g");
+  // Init ENVIRON map.
+  struct zvalue m = ZVINIT(ZF_MAP, 0, 0);
+  zvalue_map_init(&m);
+  STACK[ENVIRON] = m;
+  for (char **pkey = environ; *pkey; pkey++) {
+    char *pval = strchr(*pkey, '=');
+    if (!pval) continue;
+    struct zvalue zkey = ZVINIT(ZF_STR, 0, new_zstring(*pkey, pval - *pkey));
+    struct zvalue *v = get_map_val(&m, &zkey);
+    zstring_release(&zkey.vst);
+    if (v->vst) FFATAL("env var dup? (%s)", pkey);
+    *v = new_str_val(++pval);    // FIXME refcnt
+    check_numeric_string(v);
+  }
+
+  // Init ARGV map.
+  m = (struct zvalue)ZVINIT(ZF_MAP, 0, 0);
+  zvalue_map_init(&m);
+  STACK[ARGV] = m;
+  insert_argv_map(&m, 0, TT.progname);
+  int nargc = 1;
+  for (int k = optind; k < argc; k++) {
+    insert_argv_map(&m, nargc, argv[k]);
+    nargc++;
+  }
+
+  // Init rest of the awk special variables.
+  STACK[ARGC] = (struct zvalue)ZVINIT(ZF_NUM, nargc, 0);
+  STACK[FILENAME] = new_str_val("");
+  STACK[FNR] = (struct zvalue)ZVINIT(ZF_NUM, 0, 0);
+  STACK[FS] = new_str_val(sepstring);
+  STACK[NF] = (struct zvalue)ZVINIT(ZF_NUM, 0, 0);
+  STACK[NR] = (struct zvalue)ZVINIT(ZF_NUM, 0, 0);
+  STACK[OFMT] = new_str_val("%.6g");
+  STACK[OFS] = new_str_val(" ");
+  STACK[ORS] = new_str_val("\n");
+  STACK[RLENGTH] = (struct zvalue)ZVINIT(ZF_NUM, 0, 0);
+  STACK[RS] = new_str_val("\n");
+  STACK[RSTART] = (struct zvalue)ZVINIT(ZF_NUM, 0, 0);
+  STACK[SUBSEP] = new_str_val("\034");
+
+  // Init program globals.
+  //
+  // Push global variables on the TT.stack at offsets matching their index in the
+  // global var table.  In the global var table we may have the type as scalar
+  // or map if it is used as such in the program. In that case we init the
+  // pushed arg from the type of the globals table.
+  // But if a global var appears only as a bare arg in a function call it will
+  // not be typed in the globals table. In that case we can only say it "may be"
+  // a map, but we have to assume the possibility and attach a map to the
+  // var. When/if the var is used as a map or scalar in the called function it
+  // will be converted to a map or scalar as required.
+  // See force_maybemap_to_scalar(), and the similar comment in
+  // 'case tkfunction:' above.
+  //
+  int gstx, len = zlist_len(&TT.globals_table);
+  for (gstx = TT.spec_var_limit; gstx < len; gstx++) {
+    struct symtab_slot gs = GLOBAL[gstx];
+    struct zvalue v = ZVINIT(gs.flags, 0, 0);
+    if (v.flags == 0) {
+      zvalue_map_init(&v);
+      v.flags = ZF_MAYBEMAP;
+    } else if (IS_MAP(&v)) {
+      zvalue_map_init(&v);
+    } else {
+      // Set SCALAR flag 0 to create "uninitialized" scalar.
+      v.flags = 0;
+    }
+    push_val(&v);
+  }
+
+  // Init -v assignment options.
+  for (struct arg_list *p = assign_args; p; p = p->next) {
+    char *asgn = p->arg;
+    char *val = strchr(asgn, '=');
+    if (!val) error_exit("bad -v assignment format");
+    *val++ = 0;
+    assign_global(asgn, val);
+  }
+
+  TT.rgl.cur_arg = new_str_val("<cmdline>");
+  uninit_string_zvalue = new_str_val("");
+  zvalue_copy(&FIELD[0], &uninit_string_zvalue);
+}
+
+static void run_files(int *status)
+{
+  int r = 0;
+  while (r != tkexit && *status < 0 && getrec_f0() >= 0)
+    if ((r = interp(TT.cgl.first_recrule, status)) == tknextfile) next_fp();
+}
+
+static void free_literal_regex(void)
+{
+  int len = zlist_len(&TT.literals);
+  for (int k = 1; k < len; k++)
+    if (IS_RX(&LITERAL[k])) regfree(LITERAL[k].rx);
+}
+
+static void run(int optind, int argc, char **argv, char *sepstring,
+    struct arg_list *assign_args)
+{
+  char *printf_fmt_rx = "%[-+ #0']*([*]|[0-9]*)([.]([*]|[0-9]*))?l?[aAdiouxXfFeEgGcs%]";
+  init_globals(optind, argc, argv, sepstring, assign_args);
+  TT.cfile = xzalloc(sizeof(struct zfile));
+  xregcomp(&TT.rx_default, "[ \t\n]+", REG_EXTENDED);
+  xregcomp(&TT.rx_last, "[ \t\n]+", REG_EXTENDED);
+  xregcomp(&TT.rx_printf_fmt, printf_fmt_rx, REG_EXTENDED);
+  new_file("-", stdin, 'r', 1, 1);
+  new_file("/dev/stdin", stdin, 'r', 1, 1);
+  new_file("/dev/stdout", stdout, 'w', 1, 1);
+  TT.zstdout = TT.zfiles;
+  new_file("/dev/stderr", stderr, 'w', 1, 1);
+  seedrand(1);
+  int status = -1, r = 0;
+  if (TT.cgl.first_begin) r = interp(TT.cgl.first_begin, &status);
+  if (r != tkexit)
+    if (TT.cgl.first_recrule) run_files(&status);
+  if (TT.cgl.first_end) r = interp(TT.cgl.first_end, &status);
+  regfree(&TT.rx_printf_fmt);
+  regfree(&TT.rx_default);
+  regfree(&TT.rx_last);
+  free_literal_regex();
+  close_file(0);    // close all files
+  if (status >= 0) awk_exit(status);
+}
+
+////////////////////
+//// main
+////////////////////
+
+static void progfiles_init(char *progstring, struct arg_list *prog_args)
+{
+  TT.scs->p = progstring ? progstring : "  " + 2;
+  TT.scs->progstring = progstring;
+  TT.scs->prog_args = prog_args;
+  TT.scs->filename = "(cmdline)";
+  TT.scs->maxtok = 256;
+  TT.scs->tokstr = xzalloc(TT.scs->maxtok);
+}
+
+static int awk(char *sepstring, char *progstring, struct arg_list *prog_args,
+    struct arg_list *assign_args, int optind, int argc, char **argv,
+    int opt_run_prog)
+{
+  struct scanner_state ss = {0};
+  TT.scs = &ss;
+
+  setlocale(LC_NUMERIC, "");
+  progfiles_init(progstring, prog_args);
+  compile();
+
+  if (TT.cgl.compile_error_count)
+    error_exit("%d syntax error(s)", TT.cgl.compile_error_count);
+  else {
+    if (opt_run_prog)
+      run(optind, argc, argv, sepstring, assign_args);
+  }
+
+  return TT.cgl.compile_error_count;
+}
+
+void awk_main(void)
+{
+  char *sepstring = TT.F ? escape_str(TT.F, 0) : " ";
+  int optind = 0;
+  char *progstring = NULL;
+
+  TT.pbuf = toybuf;
+  toys.exitval = 2;
+  if (!TT.f) {
+    if (*toys.optargs) progstring = toys.optargs[optind++];
+    else error_exit("No program string\n");
+  }
+  TT.progname = toys.which->name;
+  toys.exitval = awk(sepstring, progstring, TT.f, TT.v,
+      optind, toys.optc, toys.optargs, !FLAG(c));
+}
diff --git a/toys/pending/diff.c b/toys/pending/diff.c
index 27873cfd..362365df 100644
--- a/toys/pending/diff.c
+++ b/toys/pending/diff.c
@@ -8,7 +8,7 @@
  *
  * Deviations from posix: always does -u
 
-USE_DIFF(NEWTOY(diff, "<2>2(unchanged-line-format):;(old-line-format):;(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)))
+USE_DIFF(NEWTOY(diff, "<2>2(unchanged-line-format):;(old-line-format):;(no-dereference);(new-line-format):;(color)(strip-trailing-cr)B(ignore-blank-lines)d(minimal)b(ignore-space-change)ut(expand-tabs)w(ignore-all-space)i(ignore-case)T(initial-tab)s(report-identical-files)q(brief)a(text)S(starting-file):F(show-function-line):;L(label)*N(new-file)r(recursive)U(unified)#<0=3", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)))
 
 config DIFF
   bool "diff"
@@ -35,6 +35,7 @@ config DIFF
     -w	Ignore all whitespace
 
     --color     Color output   --strip-trailing-cr   Strip '\r' from input lines
+    --no-dereference Don't follow symbolic links
     --TYPE-line-format=FORMAT  Display TYPE (unchanged/old/new) lines using FORMAT
       FORMAT uses printf integer escapes (ala %-2.4x) followed by LETTER: FELMNn
     Supported format specifiers are:
@@ -51,7 +52,7 @@ GLOBALS(
   struct arg_list *L;
   char *F, *S, *new_line_format, *old_line_format, *unchanged_line_format;
 
-  int dir_num, size, is_binary, differ, change, len[2], *offset[2];
+  int dir_num, size, is_binary, is_symlink, differ, change, len[2], *offset[2];
   struct stat st[2];
   struct {
     char **list;
@@ -61,6 +62,10 @@ GLOBALS(
     FILE *fp;
     int len;
   } file[2];
+  struct {
+    char *name;
+    int len;
+  } link[2];
 )
 
 #define IS_STDIN(s)     (*(s)=='-' && !(s)[1])
@@ -90,6 +95,11 @@ enum {
   space = 1 << 12
 };
 
+void xlstat(char *path, struct stat *st)
+{
+  if(lstat(path, st)) perror_exit("Can't lstat %s", path);
+}
+
 static int comp(void *a, void *b)
 {
   int i = ((struct v_vector *)a)->hash - ((struct v_vector *)b)->hash;
@@ -512,19 +522,19 @@ static int list_dir(struct dirtree *node)
 
   if (S_ISDIR(node->st.st_mode) && !node->parent) { //add root dirs.
     add_to_list(node);
-    return (DIRTREE_RECURSE|DIRTREE_SYMFOLLOW);
+    return (DIRTREE_RECURSE|((FLAG(no_dereference)) ? 0 : DIRTREE_SYMFOLLOW));
   }
 
   if (S_ISDIR(node->st.st_mode) && FLAG(r)) {
     if (!FLAG(N)) ret = skip(node);
-    if (!ret) return DIRTREE_RECURSE|DIRTREE_SYMFOLLOW;
+    if (!ret) return DIRTREE_RECURSE|((FLAG(no_dereference)) ? 0 : DIRTREE_SYMFOLLOW);
     else {
       add_to_list(node); //only at one side.
       return 0;
     }
   } else {
     add_to_list(node);
-    return S_ISDIR(node->st.st_mode) ? 0 : (DIRTREE_RECURSE|DIRTREE_SYMFOLLOW);
+    return S_ISDIR(node->st.st_mode) ? 0 : (DIRTREE_RECURSE|((FLAG(no_dereference)) ? 0 : DIRTREE_SYMFOLLOW));
   }
 }
 
@@ -578,6 +588,33 @@ static void show_label(char *prefix, char *filename, struct stat *sb)
   free(quoted_file);
 }
 
+static void do_symlink_diff(char **files)
+{
+  size_t i;
+  int s = sizeof(toybuf)/2;
+
+  TT.is_symlink = 1;
+  TT.differ = 0;
+  TT.link[0].name = TT.link[1].name = NULL;
+  for (i = 0; i < 2; i++) {
+    TT.link[i].name = xreadlink(files[i]);
+    if (TT.link[i].name == 0) {
+      perror_msg("readlink failed");
+      TT.differ = 2;
+      free(TT.link[0].name);
+      return;
+    }
+    TT.link[i].len = strlen(TT.link[i].name);
+  }
+
+  if (TT.link[0].len != TT.link[1].len) TT.differ = 1;
+  else if (smemcmp(TT.link[0].name, TT.link[1].name, TT.link[0].len))
+    TT.differ = 1;
+  free(TT.link[0].name);
+  free(TT.link[1].name);
+  return;
+}
+
 static void do_diff(char **files)
 {
   long i = 1, size = 1, x = 0, change = 0, ignore_white,
@@ -717,9 +754,9 @@ calc_ct:
 static void show_status(char **files)
 {
   if (TT.differ==2) return; // TODO: needed?
-  if (TT.differ ? FLAG(q) || TT.is_binary : FLAG(s))
-    printf("Files %s and %s %s\n", files[0], files[1],
-      TT.differ ? "differ" : "are identical");
+  if (TT.differ ? FLAG(q) || TT.is_binary || TT.is_symlink : FLAG(s))
+    printf("%s %s and %s %s\n", TT.is_symlink ? "Symbolic links" : "Files",
+      files[0], files[1], TT.differ ? "differ" : "are identical");
 }
 
 static void create_empty_entry(int l , int r, int j)
@@ -736,25 +773,30 @@ static void create_empty_entry(int l , int r, int j)
       f[!i] = "/dev/null";
     }
     path[i] = f[i] = TT.dir[i].list[i ? r : l];
-    stat(f[i], st+i);
+    (FLAG(no_dereference) ? lstat : stat)(f[i], st+i);
     if (j) st[!i] = st[i];
   }
 
   for (i = 0; i<2; i++) {
-    if (!S_ISREG(st[i].st_mode) && !S_ISDIR(st[i].st_mode)) {
-      printf("File %s is not a regular file or directory and was skipped\n",
+    if (!S_ISREG(st[i].st_mode) && !S_ISDIR(st[i].st_mode) && !S_ISLNK(st[i].st_mode)) {
+      printf("File %s is not a regular file, symbolic link, or directory and was skipped\n",
         path[i]);
       break;
     }
   }
 
   if (i != 2);
-  else if (S_ISDIR(st[0].st_mode) && S_ISDIR(st[1].st_mode))
-    printf("Common subdirectories: %s and %s\n", path[0], path[1]);
-  else if ((i = S_ISDIR(st[0].st_mode)) != S_ISDIR(st[1].st_mode)) {
-    char *fidir[] = {"directory", "regular file"};
+  else if ((st[0].st_mode & S_IFMT) != (st[1].st_mode & S_IFMT)) {
+    i = S_ISREG(st[0].st_mode) + 2 * S_ISLNK(st[0].st_mode);
+    int k = S_ISREG(st[1].st_mode) + 2 * S_ISLNK(st[1].st_mode);
+    char *fidir[] = {"directory", "regular file", "symbolic link"};
     printf("File %s is a %s while file %s is a %s\n",
-      path[0], fidir[!i], path[1], fidir[i]);
+      path[0], fidir[i], path[1], fidir[k]);
+  } else if (S_ISDIR(st[0].st_mode))
+    printf("Common subdirectories: %s and %s\n", path[0], path[1]);
+  else if (S_ISLNK(st[0].st_mode)) {
+    do_symlink_diff(f);
+    show_status(path);
   } else {
     do_diff(f);
     show_status(path);
@@ -814,7 +856,7 @@ static void diff_dir(int *start)
 
 void diff_main(void)
 {
-  int j = 0, k = 1, start[2] = {1, 1};
+  int i, j = 0, k = 1, start[2] = {1, 1};
   char **files = toys.optargs;
 
   toys.exitval = 2;
@@ -822,6 +864,7 @@ void diff_main(void)
 
   for (j = 0; j < 2; j++) {
     if (IS_STDIN(files[j])) fstat(0, &TT.st[j]);
+    else if (FLAG(no_dereference)) xlstat(files[j], &TT.st[j]);
     else xstat(files[j], &TT.st[j]);
   }
 
@@ -844,7 +887,7 @@ void diff_main(void)
   if (S_ISDIR(TT.st[0].st_mode) && S_ISDIR(TT.st[1].st_mode)) {
     for (j = 0; j < 2; j++) {
       memset(TT.dir+j, 0, sizeof(*TT.dir));
-      dirtree_flagread(files[j], DIRTREE_SYMFOLLOW, list_dir);
+      dirtree_flagread(files[j], (FLAG(no_dereference)) ? 0 : DIRTREE_SYMFOLLOW, list_dir);
       TT.dir[j].nr_elm = TT.size; //size updated in list_dir
       qsort(&TT.dir[j].list[1], TT.size-1, sizeof(char *), (void *)cmp);
 
@@ -868,10 +911,21 @@ void diff_main(void)
       char *slash = strrchr(files[d], '/');
 
       files[!d] = concat_file_path(files[!d], slash ? slash+1 : files[d]);
-      if (stat(files[!d], &TT.st[!d])) perror_exit("%s", files[!d]);
+      if ((FLAG(no_dereference) ? lstat : stat)(files[!d], &TT.st[!d]))
+        perror_exit("%s", files[!d]);
+    }
+    if ((S_ISLNK(TT.st[0].st_mode)) != S_ISLNK(TT.st[1].st_mode)) {
+      i = !strcmp(files[0], "-") ? 0 : S_ISREG(TT.st[0].st_mode) + 2 * S_ISLNK(TT.st[0].st_mode);
+      int k = !strcmp(files[0], "-") ? 0 : S_ISREG(TT.st[1].st_mode) + 2 * S_ISLNK(TT.st[1].st_mode);
+      char *fidir[] = {"fifo", "regular file", "symbolic link"};
+      printf("File %s is a %s while file %s is a %s\n",
+        files[0], fidir[i], files[1], fidir[k]);
+      TT.differ = 1;
+    } else {
+      if (S_ISLNK(TT.st[0].st_mode)) do_symlink_diff(files);
+      else do_diff(files);
+      show_status(files);
     }
-    do_diff(files);
-    show_status(files);
     if (TT.file[0].fp) fclose(TT.file[0].fp);
     if (TT.file[1].fp) fclose(TT.file[1].fp);
   }
diff --git a/toys/pending/getty.c b/toys/pending/getty.c
index 2d68b160..7d0f9b14 100644
--- a/toys/pending/getty.c
+++ b/toys/pending/getty.c
@@ -38,6 +38,7 @@ GLOBALS(
   char *tty_name, buff[128];
   int speeds[20], sc;
   struct termios termios;
+  struct utsname uts;
 )
 
 #define CTL(x)        ((x) ^ 0100)
@@ -133,24 +134,23 @@ static void sense_baud(void)
   if (tcsetattr(0, TCSANOW, &TT.termios) < 0) perror_exit("tcsetattr");
 }
 
-// Print /etc/isuue with taking care of each escape sequence
-void write_issue(char *file, struct utsname *uts)
+// Print /etc/issue, interpreting escape sequences.
+void print_issue(void)
 {
-  char buff[20] = {0,};
-  int fd = open(TT.f, O_RDONLY), size;
-
-  if (fd < 0) return;
-  while ((size = readall(fd, buff, 1)) > 0) {
-    char *ch = buff;
-
-    if (*ch == '\\' || *ch == '%') {
-      if (readall(fd, buff, 1) <= 0) perror_exit("readall");
-      if (*ch == 's') fputs(uts->sysname, stdout);
-      if (*ch == 'n'|| *ch == 'h') fputs(uts->nodename, stdout);
-      if (*ch == 'r') fputs(uts->release, stdout);
-      if (*ch == 'm') fputs(uts->machine, stdout);
-      if (*ch == 'l') fputs(TT.tty_name, stdout);
-    } else xputc(*ch);
+  FILE *fp = fopen(TT.f, "r");
+  int ch;
+
+  if (!fp) return;
+  while ((ch = fgetc(fp)) != -1) {
+    if (ch == '\\' || ch == '%') {
+      ch = fgetc(fp);
+      if (ch == 'h' || ch == 'n') xputsn(TT.uts.nodename);
+      else if (ch == 'm') xputsn(TT.uts.machine);
+      else if (ch == 'r') xputsn(TT.uts.release);
+      else if (ch == 's') xputsn(TT.uts.sysname);
+      else if (ch == 'l') xputsn(TT.tty_name);
+      else printf("<bad escape>");
+    } else xputc(ch);
   }
 }
 
@@ -159,14 +159,12 @@ static int read_login_name(void)
 {
   tcflush(0, TCIFLUSH); // Flush pending speed switches
   while (1) {
-    struct utsname uts;
     int i = 0;
 
-    uname(&uts);
+    if (!FLAG(i)) print_issue();
 
-    if (!FLAG(i)) write_issue(TT.f, &uts);
-
-    dprintf(1, "%s login: ", uts.nodename);
+    printf("%s login: ", TT.uts.nodename);
+    fflush(stdout);
 
     TT.buff[0] = getchar();
     if (!TT.buff[0] && TT.sc > 1) return 0; // Switch speed
@@ -212,6 +210,7 @@ void getty_main(void)
   char ch, *cmd[3] = {TT.l ? : "/bin/login", 0, 0}; // space to add username
 
   if (!FLAG(f)) TT.f = "/etc/issue";
+  uname(&TT.uts);
 
   // parse arguments and set $TERM
   if (isdigit(**toys.optargs)) {
diff --git a/toys/pending/sh.c b/toys/pending/sh.c
index 2d54e912..87a4633a 100644
--- a/toys/pending/sh.c
+++ b/toys/pending/sh.c
@@ -815,16 +815,6 @@ static int utf8chr(char *wc, char *chrs, int *len)
   return 0;
 }
 
-// return length of match found at this point (try is null terminated array)
-static int anystart(char *s, char **try)
-{
-  char *ss = s;
-
-  while (*try) if (strstart(&s, *try++)) return s-ss;
-
-  return 0;
-}
-
 // does this entire string match one of the strings in try[]
 static int anystr(char *s, char **try)
 {
@@ -2691,7 +2681,7 @@ notfd:
         s = 0;
 
         break;
-      }
+      } else if (from==to) saveclose |= 2;
     }
 
     // perform redirect, saving displaced "to".
diff --git a/toys/pending/vi.c b/toys/pending/vi.c
index 2283edb1..19c8d11f 100644
--- a/toys/pending/vi.c
+++ b/toys/pending/vi.c
@@ -5,7 +5,7 @@
  *
  * See http://pubs.opengroup.org/onlinepubs/9699919799/utilities/vi.html
 
-USE_VI(NEWTOY(vi, ">1s:", TOYFLAG_USR|TOYFLAG_BIN))
+USE_VI(NEWTOY(vi, ">1s:c:", TOYFLAG_USR|TOYFLAG_BIN))
 
 config VI
   bool "vi"
@@ -16,9 +16,33 @@ config VI
     Visual text editor. Predates keyboards with standardized cursor keys.
     If you don't know how to use it, hit the ESC key, type :q! and press ENTER.
 
-    -s	run SCRIPT of commands on FILE
+    -s	run SCRIPT as if typed at keyboard (like -c "source SCRIPT")
+    -c	run SCRIPT of ex commands
 
-    vi mode commands:
+    The editor is usually in one of three modes:
+
+      Hit ESC for "vi mode" where each key is a command.
+      Hit : for "ex mode" which runs command lines typed at bottom of screen.
+      Hit i (from vi mode) for "insert mode" where typing adds to the file.
+
+    ex mode commands (ESC to exit ex mode):
+
+      q   Quit (exit editor if no unsaved changes)
+      q!  Quit discarding unsaved changes
+      w   Write changed contents to file (optionally to NAME argument)
+      wq  Write to file, then quit
+
+    vi mode single key commands:
+      i  switch to insert mode (until next ESC)
+      u  undo last change (can be repeated)
+      a  append (move one character right, switch to insert mode)
+      A  append (jump to end of line, switch to insert mode)
+
+    vi mode commands that prompt for more data on bottom line:
+      :  switch to ex mode
+      /  search forwards for regex
+      ?  search backwards for regex
+      .  repeat last command
 
       [count][cmd][motion]
       cmd: c d y
@@ -30,28 +54,23 @@ config VI
       [cmd]
       cmd: / ? : A a i CTRL_D CTRL_B CTRL_E CTRL_F CTRL_Y \e \b
 
-    ex mode commands:
-
       [cmd]
-      \b \e \n w wq q! 'set list' 'set nolist' d $ % g v
+      \b \e \n 'set list' 'set nolist' d $ % g v
 */
 #define FOR_vi
 #include "toys.h"
 #define CTL(a) a-'@'
 
 GLOBALS(
-  char *s;
+  char *c, *s;
 
   char *filename;
-  int vi_mode, tabstop, list;
-  int cur_col, cur_row, scr_row;
-  int drawn_row, drawn_col;
-  int count0, count1, vi_mov_flag;
+  int vi_mode, tabstop, list, cur_col, cur_row, scr_row, drawn_row, drawn_col,
+      count0, count1, vi_mov_flag;
   unsigned screen_height, screen_width;
   char vi_reg, *last_search;
   struct str_line {
-    int alloc;
-    int len;
+    int alloc, len;
     char *data;
   } *il;
   size_t screen, cursor; //offsets
@@ -59,7 +78,7 @@ GLOBALS(
   struct yank_buf {
     char reg;
     int alloc;
-    char* data;
+    char *data;
   } yank;
 
   size_t filesize;
@@ -68,8 +87,7 @@ GLOBALS(
   struct block_list {
     struct block_list *next, *prev;
     struct mem_block {
-      size_t size;
-      size_t len;
+      size_t size, len;
       enum alloc_flag {
         MMAP,  //can be munmap() before exit()
         HEAP,  //can be free() before exit()
@@ -119,25 +137,23 @@ static int utf8_dec(char key, char *utf8_scratch, int *sta_p)
   char *c = utf8_scratch;
   c[*sta_p] = key;
   if (!(*sta_p))  *c = key;
-  if (*c < 0x7F) { *sta_p = 1; return 1; }
+  if (*c < 0x7F) return *sta_p = 1;
   if ((*c & 0xE0) == 0xc0) len = 2;
   else if ((*c & 0xF0) == 0xE0 ) len = 3;
   else if ((*c & 0xF8) == 0xF0 ) len = 4;
-  else {*sta_p = 0; return 0; }
+  else return *sta_p = 0;
 
-  (*sta_p)++;
+  if (++*sta_p == 1) return 0;
+  if ((c[*sta_p-1] & 0xc0) != 0x80) return *sta_p = 0;
 
-  if (*sta_p == 1) return 0;
-  if ((c[*sta_p-1] & 0xc0) != 0x80) {*sta_p = 0; return 0; }
-
-  if (*sta_p == len) { c[(*sta_p)] = 0; return 1; }
+  if (*sta_p == len) return !(c[(*sta_p)] = 0);
 
   return 0;
 }
 
 static char* utf8_last(char* str, int size)
 {
-  char* end = str+size;
+  char *end = str+size;
   int pos = size, len, width = 0;
 
   for (;pos >= 0; end--, pos--) {
@@ -1627,15 +1643,13 @@ static void draw_page()
 
 void vi_main(void)
 {
-  char stdout_buf[8192], keybuf[16] = {0}, vi_buf[16] = {0}, utf8_code[8] = {0};
+  char keybuf[16] = {0}, vi_buf[16] = {0}, utf8_code[8] = {0};
   int utf8_dec_p = 0, vi_buf_pos = 0;
-  FILE *script = FLAG(s) ? xfopen(TT.s, "r") : 0;
+  FILE *script = TT.s ? xfopen(TT.s, "r") : 0;
 
   TT.il = xzalloc(sizeof(struct str_line));
-  TT.il->data = xzalloc(80);
-  TT.yank.data = xzalloc(128);
-
-  TT.il->alloc = 80, TT.yank.alloc = 128;
+  TT.il->data = xzalloc(TT.il->alloc = 80);
+  TT.yank.data = xzalloc(TT.yank.alloc = 128);
 
   TT.filename = *toys.optargs;
   linelist_load(0, 1);
@@ -1647,27 +1661,30 @@ void vi_main(void)
   terminal_size(&TT.screen_width, &TT.screen_height);
   TT.screen_height -= 1;
 
-  // Avoid flicker.
-  setbuffer(stdout, stdout_buf, sizeof(stdout_buf));
-
   xsignal(SIGWINCH, generic_signal);
   set_terminal(0, 1, 0, 0);
   //writes stdout into different xterm buffer so when we exit
   //we dont get scroll log full of junk
   xputsn("\e[?1049h");
 
+  if (TT.c) {
+    FILE *cc = xfopen(TT.c, "r");
+    char *line;
+
+    while ((line = xgetline(cc))) if (run_ex_cmd(TT.il->data)) goto cleanup_vi;
+    fclose(cc);
+  }
+
   for (;;) {
     int key = 0;
 
     draw_page();
-    if (script) {
-      key = fgetc(script);
-      if (key == EOF) {
-        fclose(script);
-        script = 0;
-        key = scan_key(keybuf, -1);
-      }
-    } else key = scan_key(keybuf, -1);
+    // TODO script should handle cursor keys
+    if (script && EOF==(key = fgetc(script))) {
+      fclose(script);
+      script = 0;
+    }
+    if (!script) key = scan_key(keybuf, -1);
 
     if (key == -1) goto cleanup_vi;
     else if (key == -3) {
@@ -1694,6 +1711,7 @@ void vi_main(void)
       else if (key==KEY_END) vi_dollar(1, 1, 0);
       else if (key==KEY_PGDN) ctrl_f();
       else if (key==KEY_PGUP) ctrl_b();
+
       continue;
     }
 
diff --git a/toys/posix/cp.c b/toys/posix/cp.c
index 3306c49f..449b5723 100644
--- a/toys/posix/cp.c
+++ b/toys/posix/cp.c
@@ -193,20 +193,20 @@ static int cp_node(struct dirtree *try)
     if (!faccessat(cfd, catch, F_OK, 0) && !S_ISDIR(cst.st_mode)) {
       if (S_ISDIR(try->st.st_mode))
         error_msg("dir at '%s'", s = dirtree_path(try, 0));
-      else if ((flags & FLAG_F) && unlinkat(cfd, catch, 0))
+      else if (FLAG(F) && unlinkat(cfd, catch, 0))
         error_msg("unlink '%s'", catch);
-      else if (flags & FLAG_i) {
-        fprintf(stderr, "%s: overwrite '%s'", toys.which->name,
-          s = dirtree_path(try, 0));
+      else if (FLAG(i)) {
+        fprintf(stderr, "%s: overwrite '%s'", toys.which->name, catch);
         if (yesno(0)) rc++;
-      } else if (!((flags&FLAG_u) && nanodiff(&try->st.st_mtim, &cst.st_mtim)>0)
-                 && !(flags & FLAG_n)) rc++;
+      } else if (!(FLAG(u) && nanodiff(&try->st.st_mtim, &cst.st_mtim)>0)
+                 && !FLAG(n)) rc++;
       free(s);
       if (!rc) return save;
     }
 
-    if (flags & FLAG_v) {
-      printf("%s '%s'\n", toys.which->name, s = dirtree_path(try, 0));
+    if (FLAG(v)) {
+      printf("%s '%s' -> '%s'\n", toys.which->name, s = dirtree_path(try, 0),
+             catch);
       free(s);
     }
 
diff --git a/toys/posix/file.c b/toys/posix/file.c
index 30d22495..566daf1d 100644
--- a/toys/posix/file.c
+++ b/toys/posix/file.c
@@ -69,11 +69,12 @@ static void do_elf_file(int fd)
 
   // "x86".
   printf("%s", elf_arch_name(arch = elf_int(toybuf+18, 2)));
-  elf_print_flags(arch, elf_int(toybuf+36+12*bits, 4));
 
   // If what we've seen so far doesn't seem consistent, bail.
   if (bail) goto bad;
 
+  elf_print_flags(arch, elf_int(toybuf+36+12*bits, 4));
+
   // Stash what we need from the header; it's okay to reuse toybuf after this.
   phentsize = elf_int(toybuf+42+12*bits, 2);
   phnum = elf_int(toybuf+44+12*bits, 2);
diff --git a/toys/posix/grep.c b/toys/posix/grep.c
index 0d252b71..afd07cf3 100644
--- a/toys/posix/grep.c
+++ b/toys/posix/grep.c
@@ -7,9 +7,9 @@
  * Posix doesn't even specify -r: too many deviations to document.
  * TODO: -i is only ascii case insensitive, not unicode.
 
-USE_GREP(NEWTOY(grep, "(line-buffered)(color):;(exclude-dir)*S(exclude)*M(include)*ZzEFHIab(byte-offset)h(no-filename)ino(only-matching)rRsvwc(count)L(files-without-match)l(files-with-matches)q(quiet)(silent)e*f*C#B#A#m#x[!wx][!EF]", TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF))
-USE_EGREP(OLDTOY(egrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF))
-USE_FGREP(OLDTOY(fgrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF))
+USE_GREP(NEWTOY(grep, "(line-buffered)(color):;(exclude-dir)*S(exclude)*M(include)*ZzEFHIab(byte-offset)h(no-filename)ino(only-matching)rRsvwc(count)L(files-without-match)l(files-with-matches)q(quiet)(silent)e*f*C#B#A#m#x[!wx][!EF]", TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF|TOYFLAG_AUTOCONF))
+USE_EGREP(OLDTOY(egrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF|TOYFLAG_AUTOCONF))
+USE_FGREP(OLDTOY(fgrep, grep, TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)|TOYFLAG_LINEBUF|TOYFLAG_AUTOCONF))
 
 config GREP
   bool "grep"
diff --git a/toys/posix/ps.c b/toys/posix/ps.c
index 676bfcb9..0e95c9eb 100644
--- a/toys/posix/ps.c
+++ b/toys/posix/ps.c
@@ -287,6 +287,7 @@ struct procpid {
   long long slot[SLOT_count]; // data (see enum above)
   unsigned short offset[6];   // offset of fields in str[] (skip CMD, always 0)
   char state;
+  char pcy[3];                // Android scheduling policy
   char str[];                 // CMD, TTY, WCHAN, LABEL, COMM, ARGS, NAME
 };
 
@@ -632,7 +633,7 @@ static char *string_field(struct procpid *tb, struct ofields *field)
     out = out+strlen(out)-3-abs(field->len);
     if (out<buf) out = buf;
 
-  } else if (which==PS_PCY) sprintf(out, "%.2s", get_sched_policy_name(ll));
+  } else if (which==PS_PCY) sprintf(out, "%.2s", tb->pcy);
   else if (CFG_TOYBOX_DEBUG) error_exit("bad which %d", which);
 
   return out;
@@ -721,6 +722,7 @@ static int get_ps(struct dirtree *new)
   struct procpid *tb = (void *)toybuf;
   long long *slot = tb->slot;
   char *name, *s, *buf = tb->str, *end = 0;
+  FILE *fp;
   struct sysinfo si;
   int i, j, fd;
   off_t len;
@@ -852,8 +854,30 @@ static int get_ps(struct dirtree *new)
   }
 
   // Do we need Android scheduling policy?
-  if (TT.bits&_PS_PCY)
-    get_sched_policy(slot[SLOT_tid], (void *)&slot[SLOT_pcy]);
+  if (TT.bits&_PS_PCY) {
+    // Find the cpuset line in "/proc/$pid/cgroup", extract the final field,
+    // and translate it to one of Android's traditional 2-char names.
+    // TODO: if other Linux systems start using cgroups, conditionalize this.
+    sprintf(buf, "/proc/%lld/cgroup", slot[SLOT_tid]);
+    if ((fp = fopen(buf, "re"))) {
+      char *s, *line;
+      while ((line = xgetline(fp))) {
+        if ((s = strstr(line, ":cpuset:/"))) {
+          s += strlen(":cpuset:/");
+          if (!*s || !strcmp(s, "foreground")) strcpy(tb->pcy, "fg");
+          else if (!strcmp(s, "system-background")) strcpy(tb->pcy, "  ");
+          else if (!strcmp(s, "background")) strcpy(tb->pcy, "bg");
+          else if (!strcmp(s, "top-app")) strcpy(tb->pcy, "ta");
+          else if (!strcmp(s, "restricted")) strcpy(tb->pcy, "rs");
+          else if (!strcmp(s, "foreground_window")) strcpy(tb->pcy, "wi");
+          else if (!strcmp(s, "camera-daemon")) strcpy(tb->pcy, "cd");
+          else strcpy(tb->pcy, "?");
+        }
+        free(line);
+      }
+      fclose(fp);
+    } else strcpy(tb->pcy, "-");
+  }
 
   // Done using buf[] (tb->str) as scratch space, now read string data,
   // saving consective null terminated strings. (Save starting offsets into
@@ -929,10 +953,9 @@ static int get_ps(struct dirtree *new)
 
         // Couldn't find it, try all the tty drivers.
         if (i == 3) {
-          FILE *fp = fopen("/proc/tty/drivers", "r");
           int tty_major = 0, maj = dev_major(rdev), min = dev_minor(rdev);
 
-          if (fp) {
+          if ((fp = fopen("/proc/tty/drivers", "r"))) {
             while (fscanf(fp, "%*s %256s %d %*s %*s", buf, &tty_major) == 2) {
               // TODO: we could parse the minor range too.
               if (tty_major == maj) {
@@ -1522,13 +1545,11 @@ static void top_common(
     "iow", "irq", "sirq", "host"};
   unsigned tock = 0;
   int i, lines, topoff = 0, done = 0;
-  char stdout_buf[8192];
 
   if (!TT.fields) perror_exit("no -o");
 
   // Avoid flicker and hide the cursor in interactive mode.
   if (!FLAG(b)) {
-    setbuffer(stdout, stdout_buf, sizeof(stdout_buf));
     sigatexit(top_cursor_cleanup);
     xputsn("\e[?25l");
   }
diff --git a/toys/posix/sed.c b/toys/posix/sed.c
index 98fbd957..08588495 100644
--- a/toys/posix/sed.c
+++ b/toys/posix/sed.c
@@ -22,7 +22,7 @@
  * print, l escapes \n
  * Added --tarxform mode to support tar --xform
 
-USE_SED(NEWTOY(sed, "(help)(version)(tarxform)e*f*i:;nErz(null-data)s[+Er]", TOYFLAG_BIN|TOYFLAG_NOHELP))
+USE_SED(NEWTOY(sed, "(help)(version)(tarxform)e*f*i:;nErz(null-data)s[+Er]", TOYFLAG_BIN|TOYFLAG_AUTOCONF))
 
 config SED
   bool "sed"
@@ -1078,17 +1078,6 @@ void sed_main(void)
   if (FLAG(tarxform)) toys.optflags |= FLAG_z;
   if (!FLAG(z)) TT.delim = '\n';
 
-  // Lie to autoconf when it asks stupid questions, so configure regexes
-  // that look for "GNU sed version %f" greater than some old buggy number
-  // don't fail us for not matching their narrow expectations.
-  if (FLAG(version)) {
-    xprintf("This is not GNU sed version 9.0\n");
-    return;
-  }
-
-  // Handling our own --version means we handle our own --help too.
-  if (FLAG(help)) return show_help(stdout, 0);
-
   // Parse pattern into commands.
 
   // If no -e or -f, first argument is the pattern.
diff --git a/toys/posix/tar.c b/toys/posix/tar.c
index 780acc4c..998e668d 100644
--- a/toys/posix/tar.c
+++ b/toys/posix/tar.c
@@ -20,7 +20,7 @@
  * No --no-null because the args infrastructure isn't ready.
  * Until args.c learns about no- toggles, --no-thingy always wins over --thingy
 
-USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN))
+USE_TAR(NEWTOY(tar, "&(one-file-system)(no-ignore-case)(ignore-case)(no-anchored)(anchored)(no-wildcards)(wildcards)(no-wildcards-match-slash)(wildcards-match-slash)(show-transformed-names)(selinux)(restrict)(full-time)(no-recursion)(null)(numeric-owner)(no-same-permissions)(overwrite)(exclude)*(sort);:(mode):(mtime):(group):(owner):(to-command):~(strip-components)(strip)#~(transform)(xform)*o(no-same-owner)p(same-permissions)k(keep-old)c(create)|h(dereference)x(extract)|t(list)|v(verbose)J(xz)j(bzip2)z(gzip)S(sparse)O(to-stdout)P(absolute-names)m(touch)X(exclude-from)*T(files-from)*I(use-compress-program):C(directory):f(file):as[!txc][!jzJa]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_UMASK))
 
 config TAR
   bool "tar"
@@ -84,7 +84,7 @@ GLOBALS(
   // Parsed information about a tar header.
   struct tar_header {
     char *name, *link_target, *uname, *gname;
-    long long size, ssize;
+    long long size, ssize, oldsparse;
     uid_t uid;
     gid_t gid;
     mode_t mode;
@@ -526,6 +526,12 @@ static void wsettime(char *s, long long sec)
     perror_msg("settime %lld %s", sec, s);
 }
 
+static void freedup(char **to, char *from)
+{
+  free(*to);
+  *to = xstrdup(from);
+}
+
 // Do pending directory utimes(), NULL to flush all.
 static int dirflush(char *name, int isdir)
 {
@@ -547,8 +553,7 @@ static int dirflush(char *name, int isdir)
 
     // --restrict means first entry extracted is what everything must be under
     if (FLAG(restrict)) {
-      free(TT.cwd);
-      TT.cwd = xstrdup(s);
+      freedup(&TT.cwd, s);
       toys.optflags ^= FLAG_restrict;
     }
     // use resolved name so trailing / is stripped
@@ -590,7 +595,7 @@ static void sendfile_sparse(int fd)
         }
       } else {
         sent = len;
-        if (!(len = TT.sparse[i*2+1]) && ftruncate(fd, sent+len))
+        if (!(len = TT.sparse[i*2+1]) && ftruncate(fd, sent))
           perror_msg("ftruncate");
       }
       if (len+used>TT.hdr.size) error_exit("sparse overflow");
@@ -637,7 +642,7 @@ static void extract_to_disk(char *name)
     } else {
       int fd = WARN_ONLY|O_WRONLY|O_CREAT|(FLAG(overwrite) ? O_TRUNC : O_EXCL);
 
-      if ((fd = xcreate(name, fd, ala&07777)) != -1) sendfile_sparse(fd);
+      if ((fd = xcreate(name, fd, 0700)) != -1) sendfile_sparse(fd);
       else return skippy(TT.hdr.size);
     }
   } else if (S_ISDIR(ala)) {
@@ -646,7 +651,7 @@ static void extract_to_disk(char *name)
   } else if (S_ISLNK(ala)) {
     if (symlink(TT.hdr.link_target, name))
       return perror_msg("can't link '%s' -> '%s'", name, TT.hdr.link_target);
-  } else if (mknod(name, ala, TT.hdr.device))
+  } else if (mknod(name, ala&~toys.old_umask, TT.hdr.device))
     return perror_msg("can't create '%s'", name);
 
   // Set ownership
@@ -668,7 +673,7 @@ static void extract_to_disk(char *name)
     if (lchown(name, u, g)) perror_msg("chown %d:%d '%s'", u, g, name);;
   }
 
-  if (!S_ISLNK(ala)) chmod(name, FLAG(p) ? ala : ala&0777);
+  if (!S_ISLNK(ala)) chmod(name, FLAG(p) ? ala : ala&0777&~toys.old_umask);
 
   // Apply mtime.
   if (!FLAG(m)) {
@@ -752,11 +757,11 @@ static void unpack_tar(char *first)
             sefd = xopen("/proc/self/attr/fscreate", O_WRONLY|WARN_ONLY);
             if (sefd==-1 ||  i!=write(sefd, pp, i))
               perror_msg("setfscreatecon %s", pp);
-          } else if (strstart(&pp, "path=")) {
-            free(TT.hdr.name);
-            TT.hdr.name = xstrdup(pp);
-            break;
-          }
+          } else if (strstart(&pp, "path=")) freedup(&TT.hdr.name, pp);
+          // legacy sparse format circa 2005
+          else if (strstart(&pp, "GNU.sparse.name=")) freedup(&TT.hdr.name, pp);
+          else if (strstart(&pp, "GNU.sparse.realsize="))
+            TT.hdr.oldsparse = atoll(pp);
         }
         free(buf);
       }
@@ -795,7 +800,38 @@ static void unpack_tar(char *first)
       TT.sparselen /= 2;
       if (TT.sparselen)
         TT.hdr.ssize = TT.sparse[2*TT.sparselen-1]+TT.sparse[2*TT.sparselen-2];
-    } else TT.hdr.ssize = TT.hdr.size;
+    } else {
+      TT.hdr.ssize = TT.hdr.size;
+
+      // Handle obsolete sparse format
+      if (TT.hdr.oldsparse>0) {
+        char sparse[512], c;
+        long long ll = 0;
+
+        s = sparse+512;
+        for (i = 0;;) {
+          if (s == sparse+512) {
+            if (TT.hdr.size<512) break;
+            xreadall(TT.fd, s = sparse, 512);
+            TT.hdr.size -= 512;
+          } else if (!(c = *s++)) break;
+          else if (isdigit(c)) ll = (10*ll)+c-'0';
+          else {
+            if (!TT.sparselen)
+              TT.sparse = xzalloc(((TT.sparselen = ll)+1)*2*sizeof(long long));
+            else TT.sparse[i++] = ll;
+            ll = 0;
+            if (i == TT.sparselen*2) break;
+          }
+        }
+        if (TT.sparselen) {
+          ll = TT.sparse[2*(TT.sparselen-1)]+TT.sparse[2*TT.sparselen-1];
+          if (TT.hdr.oldsparse>ll)
+            TT.sparse[2*TT.sparselen++] = TT.hdr.oldsparse;
+        }
+        TT.hdr.oldsparse = 0;
+      }
+    }
 
     // At this point, we have something to output. Convert metadata.
     TT.hdr.mode = OTOI(tar.mode)&0xfff;
@@ -1033,7 +1069,8 @@ void tar_main(void)
   // nommu reentry for nonseekable input skips this, parent did it for us
   if (toys.stacktop) {
     if (TT.f && strcmp(TT.f, "-"))
-      TT.fd = xcreate(TT.f, TT.fd*(O_WRONLY|O_CREAT|O_TRUNC), 0666);
+      TT.fd = xcreate(TT.f, TT.fd*(O_WRONLY|O_CREAT|O_TRUNC),
+                      0666&~toys.old_umask);
     // Get destination directory
     if (TT.C) xchdir(TT.C);
   }
diff --git a/toys/posix/test.c b/toys/posix/test.c
index 881bb668..8395b8d3 100644
--- a/toys/posix/test.c
+++ b/toys/posix/test.c
@@ -38,6 +38,8 @@ config TEST
     Two integers:
       -eq  equal         -gt  first > second    -lt  first < second
       -ne  not equal     -ge  first >= second   -le  first <= second
+    Two files:
+      -ot  Older mtime   -nt  Newer mtime       -ef  same dev/inode
 
     --- Modify or combine tests:
       ! EXPR     not (swap true/false)   EXPR -a EXPR    and (are both true)
@@ -59,7 +61,7 @@ static int do_test(char **args, int *count)
 
   if (*count>=3) {
     *count = 3;
-    char *s = args[1], *ss = "eqnegtgeltle";
+    char *s = args[1], *ss = "eqnegtgeltleefotnt";
     // TODO shell integration case insensitivity
     if (!strcmp(s, "=") || !strcmp(s, "==")) return !strcmp(args[0], args[2]);
     if (!strcmp(s, "!=")) return strcmp(args[0], args[2]);
@@ -79,7 +81,15 @@ static int do_test(char **args, int *count)
       return (*s=='<') ? i<0 : i>0;
     }
     if (*s=='-' && strlen(s)==3 && (s = strstr(ss, s+1)) && !((i = s-ss)&1)) {
-      long long a = atolx(args[0]), b = atolx(args[2]);
+      struct stat st1, st2;
+      long long a QUIET, b QUIET;
+      if (i <= 10) {
+        a = atolx(args[0]);
+        b = atolx(args[2]);
+      } else {
+        if ((i == 12 ? stat : lstat)(args[0], &st1)
+          || (i == 12 ? stat : lstat)(args[2], &st2)) return 0;
+      }
 
       if (!i) return a == b;
       if (i==2) return a != b;
@@ -87,6 +97,11 @@ static int do_test(char **args, int *count)
       if (i==6) return a >= b;
       if (i==8) return a < b;
       if (i==10) return a<= b;
+      if (i==12) return (st1.st_dev==st2.st_dev) && (st1.st_ino==st2.st_ino);
+      if (i==14) return (st1.st_atim.tv_sec < st2.st_atim.tv_sec) ||
+        (st1.st_atim.tv_nsec < st2.st_atim.tv_nsec);
+      if (i==16) return (st1.st_atim.tv_sec > st2.st_atim.tv_sec) ||
+        (st1.st_atim.tv_nsec > st2.st_atim.tv_nsec);
     }
   }
   s = *args;
```

