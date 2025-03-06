```diff
diff --git a/Android.bp b/Android.bp
index 56ec317f..9f6ac1c9 100644
--- a/Android.bp
+++ b/Android.bp
@@ -250,6 +250,7 @@ toybox_symlinks = [
     "acpi",
     "base64",
     "basename",
+    "blkdiscard",
     "blockdev",
     "brctl",
     "cal",
@@ -526,7 +527,6 @@ cc_binary {
     name: "toybox",
     defaults: ["toybox-shared-defaults"],
     host_supported: true,
-    recovery_available: true,
     vendor_ramdisk_available: true,
 }
 
@@ -536,6 +536,13 @@ cc_binary {
     vendor: true,
 }
 
+cc_binary {
+    name: "toybox_recovery",
+    defaults: ["toybox-shared-defaults"],
+    recovery: true,
+    stem: "toybox",
+}
+
 //###########################################
 // Static toybox binaries for legacy devices
 //###########################################
diff --git a/METADATA b/METADATA
index d610dd40..9dc2b516 100644
--- a/METADATA
+++ b/METADATA
@@ -8,13 +8,13 @@ third_party {
   license_type: UNENCUMBERED
   last_upgrade_date {
     year: 2024
-    month: 9
-    day: 13
+    month: 12
+    day: 4
   }
   homepage: "https://landley.net/toybox/"
   identifier {
     type: "Git"
     value: "https://github.com/landley/toybox"
-    version: "9cde5834249786ba5239774c787b5db3de1b6d97"
+    version: "46e22bce880f004b227fd7e674a10253dc097365"
   }
 }
diff --git a/android/device/generated/flags.h b/android/device/generated/flags.h
index 9c056073..32af7294 100644
--- a/android/device/generated/flags.h
+++ b/android/device/generated/flags.h
@@ -190,6 +190,14 @@
 #undef FOR_brctl
 #endif
 
+// break   >1
+#undef OPTSTR_break
+#define OPTSTR_break ">1"
+#ifdef CLEANUP_break
+#undef CLEANUP_break
+#undef FOR_break
+#endif
+
 // bunzip2   cftkv
 #undef OPTSTR_bunzip2
 #define OPTSTR_bunzip2 "cftkv"
@@ -376,6 +384,14 @@
 #undef FLAG_3
 #endif
 
+// continue   >1
+#undef OPTSTR_continue
+#define OPTSTR_continue ">1"
+#ifdef CLEANUP_continue
+#undef CLEANUP_continue
+#undef FOR_continue
+#endif
+
 // count   <0>0l
 #undef OPTSTR_count
 #define OPTSTR_count "<0>0l"
@@ -641,13 +657,14 @@
 #undef FOR_demo_utf8towc
 #endif
 
-// devmem <1(no-sync)f: <1(no-sync)f:
+// devmem <1(no-sync)(no-mmap)f: <1(no-sync)(no-mmap)f:
 #undef OPTSTR_devmem
-#define OPTSTR_devmem "<1(no-sync)f:"
+#define OPTSTR_devmem "<1(no-sync)(no-mmap)f:"
 #ifdef CLEANUP_devmem
 #undef CLEANUP_devmem
 #undef FOR_devmem
 #undef FLAG_f
+#undef FLAG_no_mmap
 #undef FLAG_no_sync
 #endif
 
@@ -1744,12 +1761,13 @@
 #undef FLAG_o
 #endif
 
-// klogd   c#<1>8n
+// klogd   c#<1>8ns
 #undef OPTSTR_klogd
-#define OPTSTR_klogd "c#<1>8n"
+#define OPTSTR_klogd "c#<1>8ns"
 #ifdef CLEANUP_klogd
 #undef CLEANUP_klogd
 #undef FOR_klogd
+#undef FLAG_s
 #undef FLAG_n
 #undef FLAG_c
 #endif
@@ -2074,22 +2092,6 @@
 #undef FLAG_Z
 #endif
 
-// mke2fs   <1>2g:Fnqm#N#i#b#
-#undef OPTSTR_mke2fs
-#define OPTSTR_mke2fs "<1>2g:Fnqm#N#i#b#"
-#ifdef CLEANUP_mke2fs
-#undef CLEANUP_mke2fs
-#undef FOR_mke2fs
-#undef FLAG_b
-#undef FLAG_i
-#undef FLAG_N
-#undef FLAG_m
-#undef FLAG_q
-#undef FLAG_n
-#undef FLAG_F
-#undef FLAG_g
-#endif
-
 // mkfifo <1Z:m: <1Z:m:
 #undef OPTSTR_mkfifo
 #define OPTSTR_mkfifo "<1Z:m:"
@@ -4123,6 +4125,13 @@
 #endif
 #endif
 
+#ifdef FOR_break
+#define CLEANUP_break
+#ifndef TT
+#define TT this.break
+#endif
+#endif
+
 #ifdef FOR_bunzip2
 #define CLEANUP_bunzip2
 #ifndef TT
@@ -4292,6 +4301,13 @@
 #define FLAG_3 (1LL<<2)
 #endif
 
+#ifdef FOR_continue
+#define CLEANUP_continue
+#ifndef TT
+#define TT this.continue
+#endif
+#endif
+
 #ifdef FOR_count
 #define CLEANUP_count
 #ifndef TT
@@ -4547,7 +4563,8 @@
 #define TT this.devmem
 #endif
 #define FLAG_f (1LL<<0)
-#define FLAG_no_sync (1LL<<1)
+#define FLAG_no_mmap (1LL<<1)
+#define FLAG_no_sync (1LL<<2)
 #endif
 
 #ifdef FOR_df
@@ -5559,8 +5576,9 @@
 #ifndef TT
 #define TT this.klogd
 #endif
-#define FLAG_n (FORCED_FLAG<<0)
-#define FLAG_c (FORCED_FLAG<<1)
+#define FLAG_s (FORCED_FLAG<<0)
+#define FLAG_n (FORCED_FLAG<<1)
+#define FLAG_c (FORCED_FLAG<<2)
 #endif
 
 #ifdef FOR_last
@@ -5856,21 +5874,6 @@
 #define FLAG_Z (1LL<<3)
 #endif
 
-#ifdef FOR_mke2fs
-#define CLEANUP_mke2fs
-#ifndef TT
-#define TT this.mke2fs
-#endif
-#define FLAG_b (FORCED_FLAG<<0)
-#define FLAG_i (FORCED_FLAG<<1)
-#define FLAG_N (FORCED_FLAG<<2)
-#define FLAG_m (FORCED_FLAG<<3)
-#define FLAG_q (FORCED_FLAG<<4)
-#define FLAG_n (FORCED_FLAG<<5)
-#define FLAG_F (FORCED_FLAG<<6)
-#define FLAG_g (FORCED_FLAG<<7)
-#endif
-
 #ifdef FOR_mkfifo
 #define CLEANUP_mkfifo
 #ifndef TT
diff --git a/android/device/generated/help.h b/android/device/generated/help.h
index 92dd3687..7e596863 100644
--- a/android/device/generated/help.h
+++ b/android/device/generated/help.h
@@ -78,7 +78,7 @@
 
 #define HELP_passwd "usage: passwd [-a ALGO] [-dlu] [USER]\n\nUpdate user's login password. Defaults to current user.\n\n-a ALGO	Encryption method (des, md5, sha256, sha512) default: md5\n-d		Set password to ''\n-l		Lock (disable) account\n-u		Unlock (enable) account"
 
-#define HELP_mount "usage: mount [-afFrsvw] [-t TYPE] [-o OPTION,] [[DEVICE] DIR]\n\nMount new filesystem(s) on directories. With no arguments, display existing\nmounts.\n\n-a	Mount all entries in /etc/fstab (with -t, only entries of that TYPE)\n-O	Only mount -a entries that have this option\n-f	Fake it (don't actually mount)\n-r	Read only (same as -o ro)\n-w	Read/write (default, same as -o rw)\n-t	Specify filesystem type\n-v	Verbose\n\nOPTIONS is a comma separated list of options, which can also be supplied\nas --longopts.\n\nAutodetects loopback mounts (a file on a directory) and bind mounts (file\non file, directory on directory), so you don't need to say --bind or --loop.\nYou can also \"mount -a /path\" to mount everything in /etc/fstab under /path,\neven if it's noauto. DEVICE starting with UUID= is identified by blkid -U."
+#define HELP_mount "usage: mount [-afFrsvw] [-t TYPE] [-o OPTION,] [[DEVICE] DIR]\n\nMount new filesystem(s) on directories. With no arguments, display existing\nmounts.\n\n-a	Mount all entries in /etc/fstab (with -t, only entries of that TYPE)\n-O	Only mount -a entries that have this option\n-f	Fake it (don't actually mount)\n-r	Read only (same as -o ro)\n-w	Read/write (default, same as -o rw)\n-t	Specify filesystem type\n-v	Verbose\n\nOPTIONS is a comma separated list of options, which can also be supplied\nas --longopts.\n\nAutodetects loopback mounts (a file on a directory) and bind mounts (file\non file, directory on directory), so you don't need to say --bind or --loop.\nYou can also \"mount -a /path\" to mount everything in /etc/fstab under /path,\neven if it's noauto. DEVICE starting with UUID= is identified by blkid -U,\nand DEVICE starting with LABEL= is identified by blkid -L."
 
 #define HELP_mktemp "usage: mktemp [-dqtu] [-p DIR] [TEMPLATE]\n\nSafely create a new file \"DIR/TEMPLATE\" and print its name.\n\n-d	Create directory instead of file (--directory)\n-p	Put new file in DIR (--tmpdir)\n-q	Quiet, no error messages\n-t	Prefer $TMPDIR > DIR > /tmp (default DIR > $TMPDIR > /tmp)\n-u	Don't create anything, just print what would be created\n\nEach X in TEMPLATE is replaced with a random printable character. The\ndefault TEMPLATE is tmp.XXXXXXXXXX."
 
@@ -330,7 +330,7 @@
 
 #define HELP_dos2unix "usage: dos2unix [FILE...]\n\nConvert newline format from dos \"\\r\\n\" to unix \"\\n\".\nIf no files listed copy from stdin, \"-\" is a synonym for stdin."
 
-#define HELP_devmem "usage: devmem [-f FILE] ADDR [WIDTH [DATA...]]\n\nRead/write physical addresses. WIDTH is 1, 2, 4, or 8 bytes (default 4).\nPrefix ADDR with 0x for hexadecimal, output is in same base as address.\n\n-f FILE		File to operate on (default /dev/mem)\n--no-sync	Don't open the file with O_SYNC (for cached access)"
+#define HELP_devmem "usage: devmem [-f FILE] ADDR [WIDTH [DATA...]]\n\nRead/write physical addresses. WIDTH is 1, 2, 4, or 8 bytes (default 4).\nPrefix ADDR with 0x for hexadecimal, output is in same base as address.\n\n-f FILE		File to operate on (default /dev/mem)\n--no-sync	Don't open the file with O_SYNC (for cached access)\n--no-mmap	Don't mmap the file"
 
 #define HELP_count "usage: count [-l]\n\n-l	Long output (total bytes, human readable, transfer rate, elapsed time)\n\nCopy stdin to stdout, displaying simple progress indicator to stderr."
 
@@ -420,8 +420,12 @@
 
 #define HELP_declare "usage: declare [-pAailunxr] [NAME...]\n\nSet or print variable attributes and values.\n\n-p	Print variables instead of setting\n-A	Associative array\n-a	Indexed array\n-i	Integer\n-l	Lower case\n-n	Name reference (symlink)\n-r	Readonly\n-u	Uppercase\n-x	Export"
 
+#define HELP_continue "usage: continue [N]\n\nStart next entry in for/while/until loop (or Nth outer loop, default 1)."
+
 #define HELP_cd "usage: cd [-PL] [-] [path]\n\nChange current directory. With no arguments, go $HOME. Sets $OLDPWD to\nprevious directory: cd - to return to $OLDPWD.\n\n-P	Physical path: resolve symlinks in path\n-L	Local path: .. trims directories off $PWD (default)"
 
+#define HELP_break "usage: break [N]\n\nEnd N levels of for/while/until loop immediately (default 1)."
+
 #define HELP_sh "usage: sh [-c command] [script]\n\nCommand shell.  Runs a shell script, or reads input interactively\nand responds to it. Roughly compatible with \"bash\". Run \"help\" for\nlist of built-in commands.\n\n-c	command line to execute\n-i	interactive mode (default when STDIN is a tty)\n-s	don't run script (args set $* parameters but read commands from stdin)\n\nCommand shells parse each line of input (prompting when interactive), perform\nvariable expansion and redirection, execute commands (spawning child processes\nand background jobs), and perform flow control based on the return code.\n\nParsing:\n  syntax errors\n\nInteractive prompts:\n  line continuation\n\nVariable expansion:\n  Note: can cause syntax errors at runtime\n\nRedirection:\n  HERE documents (parsing)\n  Pipelines (flow control and job control)\n\nRunning commands:\n  process state\n  builtins\n    cd [[ ]] (( ))\n    ! : [ # TODO: help for these?\n    true false help echo kill printf pwd test\n  child processes\n\nJob control:\n  &    Background process\n  Ctrl-C kill process\n  Ctrl-Z suspend process\n  bg fg jobs kill\n\nFlow control:\n;    End statement (same as newline)\n&    Background process (returns true unless syntax error)\n&&   If this fails, next command fails without running\n||   If this succeeds, next command succeeds without running\n|    Pipelines! (Can of worms...)\nfor {name [in...]}|((;;)) do; BODY; done\nif TEST; then BODY; fi\nwhile TEST; do BODY; done\ncase a in X);; esac\n[[ TEST ]]\n((MATH))\n\nJob control:\n&    Background process\nCtrl-C kill process\nCtrl-Z suspend process\nbg fg jobs kill"
 
 #define HELP_route "usage: route [-ne] [-A [inet|inet6]] [add|del TARGET [OPTIONS]]\n\nDisplay, add or delete network routes in the \"Forwarding Information Base\",\nwhich send packets out a network interface to an address.\n\n-n	Show numerical addresses (no DNS lookups)\n-e	display netstat fields\n\nAssigning an address to an interface automatically creates an appropriate\nnetwork route (\"ifconfig eth0 10.0.2.15/8\" does \"route add 10.0.0.0/8 eth0\"\nfor you), although some devices (such as loopback) won't show it in the\ntable. For machines more than one hop away, you need to specify a gateway\n(ala \"route add default gw 10.0.2.2\").\n\nThe address \"default\" is a wildcard address (0.0.0.0/0) matching all\npackets without a more specific route.\n\nAvailable OPTIONS include:\nreject   - blocking route (force match failure)\ndev NAME - force matching packets out this interface (ala \"eth0\")\nnetmask  - old way of saying things like ADDR/24\ngw ADDR  - forward packets to gateway ADDR"
@@ -430,16 +434,6 @@
 
 #define HELP_modprobe "usage: modprobe [-alrqvsDb] [-d DIR] MODULE [symbol=value][...]\n\nmodprobe utility - inserts modules and dependencies.\n\n-a  Load multiple MODULEs\n-b  Apply blacklist to module names too\n-D  Show dependencies\n-d  Load modules from DIR, option may be used multiple times\n-l  List (MODULE is a pattern)\n-q  Quiet\n-r  Remove MODULE (stacks) or do autoclean\n-s  Log to syslog\n-v  Verbose"
 
-#define HELP_mke2fs_extended "usage: mke2fs [-E stride=###] [-O option[,option]]\n\n-E stride= Set RAID stripe size (in blocks)\n-O [opts]  Specify fewer ext2 option flags (for old kernels)\n           All of these are on by default (as appropriate)\n   none         Clear default options (all but journaling)\n   dir_index    Use htree indexes for large directories\n   filetype     Store file type info in directory entry\n   has_journal  Set by -j\n   journal_dev  Set by -J device=XXX\n   sparse_super Don't allocate huge numbers of redundant superblocks"
-
-#define HELP_mke2fs_label "usage: mke2fs [-L label] [-M path] [-o string]\n\n-L         Volume label\n-M         Path to mount point\n-o         Created by"
-
-#define HELP_mke2fs_gen "usage: gene2fs [options] device filename\n\nThe [options] are the same as mke2fs."
-
-#define HELP_mke2fs_journal "usage: mke2fs [-j] [-J size=###,device=XXX]\n\n-j         Create journal (ext3)\n-J         Journal options\n           size: Number of blocks (1024-102400)\n           device: Specify an external journal"
-
-#define HELP_mke2fs "usage: mke2fs [-Fnq] [-b ###] [-N|i ###] [-m ###] device\n\nCreate an ext2 filesystem on a block device or filesystem image.\n\n-F         Force to run on a mounted device\n-n         Don't write to device\n-q         Quiet (no output)\n-b size    Block size (1024, 2048, or 4096)\n-N inodes  Allocate this many inodes\n-i bytes   Allocate one inode for every XXX bytes of device\n-m percent Reserve this percent of filesystem space for root user"
-
 #define HELP_mdev_conf "The mdev config file (/etc/mdev.conf) contains lines that look like:\nhd[a-z][0-9]* 0:3 660\n(sd[a-z]) root:disk 660 =usb_storage\n\nEach line must contain three whitespace separated fields. The first\nfield is a regular expression matching one or more device names,\nthe second and third fields are uid:gid and file permissions for\nmatching devices. Fourth field is optional. It could be used to change\ndevice name (prefix '='), path (prefix '=' and postfix '/') or create a\nsymlink (prefix '>')."
 
 #define HELP_mdev "usage: mdev [-s]\n\nCreate devices in /dev using information from /sys.\n\n-s	Scan all entries in /sys to populate /dev"
@@ -450,7 +444,7 @@
 
 #define HELP_last "usage: last [-W] [-f FILE]\n\nShow listing of last logged in users.\n\n-W      Display the information without host-column truncation\n-f FILE Read from file FILE instead of /var/log/wtmp"
 
-#define HELP_klogd "usage: klogd [-n] [-c N]\n\n-c  N   Print to console messages more urgent than prio N (1-8)\"\n-n    Run in foreground"
+#define HELP_klogd "usage: klogd [-n] [-c PRIORITY]\n\n-c	Print to console messages more urgent than PRIORITY (1-8)\"\n-n	Run in foreground\n-s	Use syscall instead of /proc"
 
 #define HELP_ipcs "usage: ipcs [[-smq] -i shmid] | [[-asmq] [-tcplu]]\n\n-i Show specific resource\nResource specification:\n-a All (default)\n-m Shared memory segments\n-q Message queues\n-s Semaphore arrays\nOutput format:\n-c Creator\n-l Limits\n-p Pid\n-t Time\n-u Summary"
 
@@ -514,7 +508,7 @@
 
 #define HELP_bc "usage: bc [-ilqsw] [file ...]\n\nbc is a command-line calculator with a Turing-complete language.\n\noptions:\n\n  -i  --interactive  force interactive mode\n  -l  --mathlib      use predefined math routines:\n\n                     s(expr)  =  sine of expr in radians\n                     c(expr)  =  cosine of expr in radians\n                     a(expr)  =  arctangent of expr, returning radians\n                     l(expr)  =  natural log of expr\n                     e(expr)  =  raises e to the power of expr\n                     j(n, x)  =  Bessel function of integer order n of x\n\n  -q  --quiet        don't print version and copyright\n  -s  --standard     error if any non-POSIX extensions are used\n  -w  --warn         warn if any non-POSIX extensions are used"
 
-#define HELP_awk "usage:  awk [-F sepstring] [-v assignment]... program [argument...]\n  or:\n        awk [-F sepstring] -f progfile [-f progfile]... [-v assignment]...\n              [argument...]\n  also:\n  -b : use bytes, not characters\n  -c : compile only, do not run"
+#define HELP_awk "usage:  awk [-F sepstring] [-v assignment]... program [argument...]\n  or:\n        awk [-F sepstring] -f progfile [-f progfile]... [-v assignment]...\n              [argument...]\n  also:\n  -b : count bytes, not characters (experimental)\n  -c : compile only, do not run"
 
 #define HELP_arping "usage: arping [-fqbDUA] [-c CNT] [-w TIMEOUT] [-I IFACE] [-s SRC_IP] DST_IP\n\nSend ARP requests/replies\n\n-f         Quit on first ARP reply\n-q         Quiet\n-b         Keep broadcasting, don't go unicast\n-D         Duplicated address detection mode\n-U         Unsolicited ARP mode, update your neighbors\n-A         ARP answer mode, update your neighbors\n-c N       Stop after sending N ARP requests\n-w TIMEOUT Time to wait for ARP reply, seconds\n-I IFACE   Interface to use (default eth0)\n-s SRC_IP  Sender IP address\nDST_IP     Target IP address"
 
@@ -606,7 +600,7 @@
 
 #define HELP_mkdir "usage: mkdir [-vp] [-m MODE] [DIR...]\n\nCreate one or more directories.\n\n-m	Set permissions of directory to mode\n-p	Make parent directories as needed\n-v	Verbose"
 
-#define HELP_ls "usage: ls [-1ACFHLNRSUXZabcdfghilmnopqrstuwx] [--color[=auto]] [FILE...]\n\nList files\n\nwhat to show:\n-A  all files except . and ..      -a  all files including .hidden\n-b  escape nongraphic chars        -d  directory, not contents\n-F  append /dir *exe @sym |FIFO    -f  files (no sort/filter/format)\n-H  follow command line symlinks   -i  inode number\n-L  follow symlinks                -N  no escaping, even on tty\n-p  put '/' after dir names        -q  unprintable chars as '?'\n-R  recursively list in subdirs    -s  storage used (in --block-size)\n-Z  security context\n\noutput formats:\n-1  list one file per line         -C  columns (sorted vertically)\n-g  like -l but no owner           -h  human readable sizes\n-k  reset --block-size to default  -l  long (show full details)\n-m  comma separated                -ll long with nanoseconds (--full-time)\n-n  long with numeric uid/gid      -o  long without group column\n-r  reverse order                  -w  set column width\n-x  columns (horizontal sort)\n\nsort by:  (also --sort=longname,longname... ends with alphabetical)\n-c  ctime      -r  reverse    -S  size     -t  time    -u  atime    -U  none\n-X  extension  -!  dirfirst   -~  nocase\n\n--block-size N	block size (default 1024, -k resets to 1024)\n--color  =always (default)  =auto (when stdout is tty) =never\n    exe=green  suid=red  suidfile=redback  stickydir=greenback\n    device=yellow  symlink=turquoise/red  dir=blue  socket=purple\n\nLong output uses -cu for display, use -ltc/-ltu to also sort by ctime/atime."
+#define HELP_ls "usage: ls [-1ACFHLNRSUXZabcdfghilmnopqrstuwx] [--color[=auto]] [FILE...]\n\nList files\n\nwhat to show:\n-A  all files except . and ..      -a  all files including .hidden\n-b  escape nongraphic chars        -d  directory, not contents\n-F  append /dir *exe @sym |FIFO    -f  files (no sort/filter/format)\n-H  follow command line symlinks   -i  inode number\n-L  follow symlinks                -N  no escaping, even on tty\n-p  put '/' after dir names        -q  unprintable chars as '?'\n-R  recursively list in subdirs    -s  storage used (units of --block-size)\n-Z  security context\n\noutput formats:\n-1  list one file per line         -C  columns (sorted vertically)\n-g  like -l but no owner           -h  human readable sizes\n-k  reset --block-size to default  -l  long (show full details)\n-m  comma separated                -ll long with nanoseconds (--full-time)\n-n  long with numeric uid/gid      -o  long without group column\n-r  reverse order                  -w  set column width\n-x  columns (horizontal sort)\n\nsort by:  (also --sort=longname,longname... ends with alphabetical)\n-c  ctime      -r  reverse    -S  size     -t  time    -u  atime    -U  none\n-X  extension  -!  dirfirst   -~  nocase\n\n--block-size N	block size for -s (default 1024, -k resets to 1024)\n--color  =always (default)  =auto (when stdout is tty) =never\n    exe=green  suid=red  suidfile=redback  stickydir=greenback\n    device=yellow  symlink=turquoise/red  dir=blue  socket=purple\n\nLong output uses -cu for display, use -ltc/-ltu to also sort by ctime/atime."
 
 #define HELP_logger "usage: logger [-s] [-t TAG] [-p [FACILITY.]PRIORITY] [MESSAGE...]\n\nLog message (or stdin) to syslog.\n\n-s	Also write message to stderr\n-t	Use TAG instead of username to identify message source\n-p	Specify PRIORITY with optional FACILITY. Default is \"user.notice\""
 
diff --git a/android/device/generated/newtoys.h b/android/device/generated/newtoys.h
index c41eb83f..45b39f49 100644
--- a/android/device/generated/newtoys.h
+++ b/android/device/generated/newtoys.h
@@ -24,6 +24,7 @@ USE_BLKID(NEWTOY(blkid, "ULo:s*[!LU]", TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_BLOCKDEV(NEWTOY(blockdev, "<1>1(setro)(setrw)(getro)(getss)(getbsz)(setbsz)#<0(getsz)(getsize)(getsize64)(getra)(setra)#<0(flushbufs)(rereadpt)",TOYFLAG_SBIN))
 USE_BOOTCHARTD(NEWTOY(bootchartd, 0, TOYFLAG_STAYROOT|TOYFLAG_USR|TOYFLAG_BIN))
 USE_BRCTL(NEWTOY(brctl, "<1", TOYFLAG_USR|TOYFLAG_SBIN))
+USE_SH(NEWTOY(break, ">1", TOYFLAG_NOFORK))
 USE_BUNZIP2(NEWTOY(bunzip2, "cftkv", TOYFLAG_USR|TOYFLAG_BIN))
 USE_BZCAT(NEWTOY(bzcat, 0, TOYFLAG_USR|TOYFLAG_BIN))
 USE_CAL(NEWTOY(cal, ">3h", TOYFLAG_USR|TOYFLAG_BIN))
@@ -42,6 +43,7 @@ USE_CKSUM(NEWTOY(cksum, "HIPLN", TOYFLAG_BIN))
 USE_CLEAR(NEWTOY(clear, NULL, TOYFLAG_USR|TOYFLAG_BIN))
 USE_CMP(NEWTOY(cmp, "<1>4ls(silent)(quiet)n#<1[!ls]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)))
 USE_COMM(NEWTOY(comm, "<2>2321", TOYFLAG_USR|TOYFLAG_BIN))
+USE_SH(NEWTOY(continue, ">1", TOYFLAG_NOFORK))
 USE_COUNT(NEWTOY(count, "<0>0l", TOYFLAG_USR|TOYFLAG_BIN))
 USE_CP(NEWTOY(cp, "<1(preserve):;D(parents)RHLPprudaslv(verbose)nF(remove-destination)fit:T[-HLPd][-niu][+Rr]", TOYFLAG_BIN))
 USE_CPIO(NEWTOY(cpio, "(ignore-devno)(renumber-inodes)(quiet)(no-preserve-owner)R(owner):md(make-directories)uLH:p|i|t|F:v(verbose)o|[!pio][!pot][!pF]", TOYFLAG_BIN))
@@ -60,7 +62,7 @@ USE_DEMO_MANY_OPTIONS(NEWTOY(demo_many_options, "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwv
 USE_DEMO_NUMBER(NEWTOY(demo_number, "D#=3<3M#<0hcdbs", TOYFLAG_BIN))
 USE_DEMO_SCANKEY(NEWTOY(demo_scankey, 0, TOYFLAG_BIN))
 USE_DEMO_UTF8TOWC(NEWTOY(demo_utf8towc, 0, TOYFLAG_USR|TOYFLAG_BIN))
-USE_DEVMEM(NEWTOY(devmem, "<1(no-sync)f:", TOYFLAG_USR|TOYFLAG_SBIN))
+USE_DEVMEM(NEWTOY(devmem, "<1(no-sync)(no-mmap)f:", TOYFLAG_USR|TOYFLAG_SBIN))
 USE_DF(NEWTOY(df, "HPkhit*a[-HPh]", TOYFLAG_BIN))
 USE_DHCP(NEWTOY(dhcp, "V:H:F:x*r:O*A#<0=20T#<0=3t#<0=3s:p:i:SBRCaovqnbf", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
 USE_DHCP6(NEWTOY(dhcp6, "r:A#<0T#<0t#<0s:p:i:SRvqnbf", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
@@ -160,7 +162,7 @@ USE_SH(NEWTOY(jobs, "lnprs", TOYFLAG_NOFORK))
 USE_KILL(NEWTOY(kill, "?ls: ", TOYFLAG_BIN|TOYFLAG_MAYFORK))
 USE_KILLALL(NEWTOY(killall, "?s:ilqvw", TOYFLAG_USR|TOYFLAG_BIN))
 USE_KILLALL5(NEWTOY(killall5, "?o*ls: [!lo][!ls]", TOYFLAG_SBIN))
-USE_KLOGD(NEWTOY(klogd, "c#<1>8n", TOYFLAG_SBIN))
+USE_KLOGD(NEWTOY(klogd, "c#<1>8ns", TOYFLAG_SBIN))
 USE_LAST(NEWTOY(last, "f:W", TOYFLAG_BIN))
 USE_LINK(NEWTOY(link, "<2>2", TOYFLAG_USR|TOYFLAG_BIN))
 USE_LINUX32(NEWTOY(linux32, 0, TOYFLAG_USR|TOYFLAG_BIN))
@@ -188,7 +190,6 @@ USE_MEMEATER(NEWTOY(memeater, "<1>1M", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MICROCOM(NEWTOY(microcom, "<1>1s#X", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_NOBUF))
 USE_MIX(NEWTOY(mix, "c:d:l#r#", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MKDIR(NEWTOY(mkdir, "<1"USE_MKDIR_Z("Z:")"vp(parent)(parents)m:", TOYFLAG_BIN|TOYFLAG_UMASK))
-USE_MKE2FS(NEWTOY(mke2fs, "<1>2g:Fnqm#N#i#b#", TOYFLAG_SBIN))
 USE_MKFIFO(NEWTOY(mkfifo, "<1"USE_MKFIFO_Z("Z:")"m:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MKNOD(NEWTOY(mknod, "<2>4m(mode):"USE_MKNOD_Z("Z:"), TOYFLAG_BIN|TOYFLAG_UMASK))
 USE_MKPASSWD(NEWTOY(mkpasswd, ">2S:m:P#=0<0", TOYFLAG_USR|TOYFLAG_BIN))
diff --git a/android/device/generated/tags.h b/android/device/generated/tags.h
index d47e3a58..8ae910e6 100644
--- a/android/device/generated/tags.h
+++ b/android/device/generated/tags.h
@@ -85,7 +85,7 @@
 #define PS_RUID                          30
 #define _PS_RUID                         (1<<30)
 #define PS_RUSER                         31
-#define _PS_RUSER                        (1<<31)
+#define _PS_RUSER                        (1LL<<31)
 #define PS_GID                           32
 #define _PS_GID                          (1LL<<32)
 #define PS_GROUP                         33
diff --git a/android/linux/generated/flags.h b/android/linux/generated/flags.h
index e73e4bf8..7a1555ba 100644
--- a/android/linux/generated/flags.h
+++ b/android/linux/generated/flags.h
@@ -190,6 +190,14 @@
 #undef FOR_brctl
 #endif
 
+// break   >1
+#undef OPTSTR_break
+#define OPTSTR_break ">1"
+#ifdef CLEANUP_break
+#undef CLEANUP_break
+#undef FOR_break
+#endif
+
 // bunzip2   cftkv
 #undef OPTSTR_bunzip2
 #define OPTSTR_bunzip2 "cftkv"
@@ -376,6 +384,14 @@
 #undef FLAG_3
 #endif
 
+// continue   >1
+#undef OPTSTR_continue
+#define OPTSTR_continue ">1"
+#ifdef CLEANUP_continue
+#undef CLEANUP_continue
+#undef FOR_continue
+#endif
+
 // count   <0>0l
 #undef OPTSTR_count
 #define OPTSTR_count "<0>0l"
@@ -641,13 +657,14 @@
 #undef FOR_demo_utf8towc
 #endif
 
-// devmem   <1(no-sync)f:
+// devmem   <1(no-sync)(no-mmap)f:
 #undef OPTSTR_devmem
-#define OPTSTR_devmem "<1(no-sync)f:"
+#define OPTSTR_devmem "<1(no-sync)(no-mmap)f:"
 #ifdef CLEANUP_devmem
 #undef CLEANUP_devmem
 #undef FOR_devmem
 #undef FLAG_f
+#undef FLAG_no_mmap
 #undef FLAG_no_sync
 #endif
 
@@ -1744,12 +1761,13 @@
 #undef FLAG_o
 #endif
 
-// klogd   c#<1>8n
+// klogd   c#<1>8ns
 #undef OPTSTR_klogd
-#define OPTSTR_klogd "c#<1>8n"
+#define OPTSTR_klogd "c#<1>8ns"
 #ifdef CLEANUP_klogd
 #undef CLEANUP_klogd
 #undef FOR_klogd
+#undef FLAG_s
 #undef FLAG_n
 #undef FLAG_c
 #endif
@@ -2074,22 +2092,6 @@
 #undef FLAG_Z
 #endif
 
-// mke2fs   <1>2g:Fnqm#N#i#b#
-#undef OPTSTR_mke2fs
-#define OPTSTR_mke2fs "<1>2g:Fnqm#N#i#b#"
-#ifdef CLEANUP_mke2fs
-#undef CLEANUP_mke2fs
-#undef FOR_mke2fs
-#undef FLAG_b
-#undef FLAG_i
-#undef FLAG_N
-#undef FLAG_m
-#undef FLAG_q
-#undef FLAG_n
-#undef FLAG_F
-#undef FLAG_g
-#endif
-
 // mkfifo   <1Z:m:
 #undef OPTSTR_mkfifo
 #define OPTSTR_mkfifo "<1Z:m:"
@@ -4123,6 +4125,13 @@
 #endif
 #endif
 
+#ifdef FOR_break
+#define CLEANUP_break
+#ifndef TT
+#define TT this.break
+#endif
+#endif
+
 #ifdef FOR_bunzip2
 #define CLEANUP_bunzip2
 #ifndef TT
@@ -4292,6 +4301,13 @@
 #define FLAG_3 (1LL<<2)
 #endif
 
+#ifdef FOR_continue
+#define CLEANUP_continue
+#ifndef TT
+#define TT this.continue
+#endif
+#endif
+
 #ifdef FOR_count
 #define CLEANUP_count
 #ifndef TT
@@ -4547,7 +4563,8 @@
 #define TT this.devmem
 #endif
 #define FLAG_f (FORCED_FLAG<<0)
-#define FLAG_no_sync (FORCED_FLAG<<1)
+#define FLAG_no_mmap (FORCED_FLAG<<1)
+#define FLAG_no_sync (FORCED_FLAG<<2)
 #endif
 
 #ifdef FOR_df
@@ -5559,8 +5576,9 @@
 #ifndef TT
 #define TT this.klogd
 #endif
-#define FLAG_n (FORCED_FLAG<<0)
-#define FLAG_c (FORCED_FLAG<<1)
+#define FLAG_s (FORCED_FLAG<<0)
+#define FLAG_n (FORCED_FLAG<<1)
+#define FLAG_c (FORCED_FLAG<<2)
 #endif
 
 #ifdef FOR_last
@@ -5856,21 +5874,6 @@
 #define FLAG_Z (FORCED_FLAG<<3)
 #endif
 
-#ifdef FOR_mke2fs
-#define CLEANUP_mke2fs
-#ifndef TT
-#define TT this.mke2fs
-#endif
-#define FLAG_b (FORCED_FLAG<<0)
-#define FLAG_i (FORCED_FLAG<<1)
-#define FLAG_N (FORCED_FLAG<<2)
-#define FLAG_m (FORCED_FLAG<<3)
-#define FLAG_q (FORCED_FLAG<<4)
-#define FLAG_n (FORCED_FLAG<<5)
-#define FLAG_F (FORCED_FLAG<<6)
-#define FLAG_g (FORCED_FLAG<<7)
-#endif
-
 #ifdef FOR_mkfifo
 #define CLEANUP_mkfifo
 #ifndef TT
diff --git a/android/linux/generated/help.h b/android/linux/generated/help.h
index f25a0785..0c099c13 100644
--- a/android/linux/generated/help.h
+++ b/android/linux/generated/help.h
@@ -78,7 +78,7 @@
 
 #define HELP_passwd "usage: passwd [-a ALGO] [-dlu] [USER]\n\nUpdate user's login password. Defaults to current user.\n\n-a ALGO	Encryption method (des, md5, sha256, sha512) default: md5\n-d		Set password to ''\n-l		Lock (disable) account\n-u		Unlock (enable) account"
 
-#define HELP_mount "usage: mount [-afFrsvw] [-t TYPE] [-o OPTION,] [[DEVICE] DIR]\n\nMount new filesystem(s) on directories. With no arguments, display existing\nmounts.\n\n-a	Mount all entries in /etc/fstab (with -t, only entries of that TYPE)\n-O	Only mount -a entries that have this option\n-f	Fake it (don't actually mount)\n-r	Read only (same as -o ro)\n-w	Read/write (default, same as -o rw)\n-t	Specify filesystem type\n-v	Verbose\n\nOPTIONS is a comma separated list of options, which can also be supplied\nas --longopts.\n\nAutodetects loopback mounts (a file on a directory) and bind mounts (file\non file, directory on directory), so you don't need to say --bind or --loop.\nYou can also \"mount -a /path\" to mount everything in /etc/fstab under /path,\neven if it's noauto. DEVICE starting with UUID= is identified by blkid -U."
+#define HELP_mount "usage: mount [-afFrsvw] [-t TYPE] [-o OPTION,] [[DEVICE] DIR]\n\nMount new filesystem(s) on directories. With no arguments, display existing\nmounts.\n\n-a	Mount all entries in /etc/fstab (with -t, only entries of that TYPE)\n-O	Only mount -a entries that have this option\n-f	Fake it (don't actually mount)\n-r	Read only (same as -o ro)\n-w	Read/write (default, same as -o rw)\n-t	Specify filesystem type\n-v	Verbose\n\nOPTIONS is a comma separated list of options, which can also be supplied\nas --longopts.\n\nAutodetects loopback mounts (a file on a directory) and bind mounts (file\non file, directory on directory), so you don't need to say --bind or --loop.\nYou can also \"mount -a /path\" to mount everything in /etc/fstab under /path,\neven if it's noauto. DEVICE starting with UUID= is identified by blkid -U,\nand DEVICE starting with LABEL= is identified by blkid -L."
 
 #define HELP_mktemp "usage: mktemp [-dqtu] [-p DIR] [TEMPLATE]\n\nSafely create a new file \"DIR/TEMPLATE\" and print its name.\n\n-d	Create directory instead of file (--directory)\n-p	Put new file in DIR (--tmpdir)\n-q	Quiet, no error messages\n-t	Prefer $TMPDIR > DIR > /tmp (default DIR > $TMPDIR > /tmp)\n-u	Don't create anything, just print what would be created\n\nEach X in TEMPLATE is replaced with a random printable character. The\ndefault TEMPLATE is tmp.XXXXXXXXXX."
 
@@ -332,7 +332,7 @@
 
 #define HELP_dos2unix "usage: dos2unix [FILE...]\n\nConvert newline format from dos \"\\r\\n\" to unix \"\\n\".\nIf no files listed copy from stdin, \"-\" is a synonym for stdin."
 
-#define HELP_devmem "usage: devmem [-f FILE] ADDR [WIDTH [DATA...]]\n\nRead/write physical addresses. WIDTH is 1, 2, 4, or 8 bytes (default 4).\nPrefix ADDR with 0x for hexadecimal, output is in same base as address.\n\n-f FILE		File to operate on (default /dev/mem)\n--no-sync	Don't open the file with O_SYNC (for cached access)"
+#define HELP_devmem "usage: devmem [-f FILE] ADDR [WIDTH [DATA...]]\n\nRead/write physical addresses. WIDTH is 1, 2, 4, or 8 bytes (default 4).\nPrefix ADDR with 0x for hexadecimal, output is in same base as address.\n\n-f FILE		File to operate on (default /dev/mem)\n--no-sync	Don't open the file with O_SYNC (for cached access)\n--no-mmap	Don't mmap the file"
 
 #define HELP_count "usage: count [-l]\n\n-l	Long output (total bytes, human readable, transfer rate, elapsed time)\n\nCopy stdin to stdout, displaying simple progress indicator to stderr."
 
@@ -422,8 +422,12 @@
 
 #define HELP_declare "usage: declare [-pAailunxr] [NAME...]\n\nSet or print variable attributes and values.\n\n-p	Print variables instead of setting\n-A	Associative array\n-a	Indexed array\n-i	Integer\n-l	Lower case\n-n	Name reference (symlink)\n-r	Readonly\n-u	Uppercase\n-x	Export"
 
+#define HELP_continue "usage: continue [N]\n\nStart next entry in for/while/until loop (or Nth outer loop, default 1)."
+
 #define HELP_cd "usage: cd [-PL] [-] [path]\n\nChange current directory. With no arguments, go $HOME. Sets $OLDPWD to\nprevious directory: cd - to return to $OLDPWD.\n\n-P	Physical path: resolve symlinks in path\n-L	Local path: .. trims directories off $PWD (default)"
 
+#define HELP_break "usage: break [N]\n\nEnd N levels of for/while/until loop immediately (default 1)."
+
 #define HELP_sh "usage: sh [-c command] [script]\n\nCommand shell.  Runs a shell script, or reads input interactively\nand responds to it. Roughly compatible with \"bash\". Run \"help\" for\nlist of built-in commands.\n\n-c	command line to execute\n-i	interactive mode (default when STDIN is a tty)\n-s	don't run script (args set $* parameters but read commands from stdin)\n\nCommand shells parse each line of input (prompting when interactive), perform\nvariable expansion and redirection, execute commands (spawning child processes\nand background jobs), and perform flow control based on the return code.\n\nParsing:\n  syntax errors\n\nInteractive prompts:\n  line continuation\n\nVariable expansion:\n  Note: can cause syntax errors at runtime\n\nRedirection:\n  HERE documents (parsing)\n  Pipelines (flow control and job control)\n\nRunning commands:\n  process state\n  builtins\n    cd [[ ]] (( ))\n    ! : [ # TODO: help for these?\n    true false help echo kill printf pwd test\n  child processes\n\nJob control:\n  &    Background process\n  Ctrl-C kill process\n  Ctrl-Z suspend process\n  bg fg jobs kill\n\nFlow control:\n;    End statement (same as newline)\n&    Background process (returns true unless syntax error)\n&&   If this fails, next command fails without running\n||   If this succeeds, next command succeeds without running\n|    Pipelines! (Can of worms...)\nfor {name [in...]}|((;;)) do; BODY; done\nif TEST; then BODY; fi\nwhile TEST; do BODY; done\ncase a in X);; esac\n[[ TEST ]]\n((MATH))\n\nJob control:\n&    Background process\nCtrl-C kill process\nCtrl-Z suspend process\nbg fg jobs kill"
 
 #define HELP_route "usage: route [-ne] [-A [inet|inet6]] [add|del TARGET [OPTIONS]]\n\nDisplay, add or delete network routes in the \"Forwarding Information Base\",\nwhich send packets out a network interface to an address.\n\n-n	Show numerical addresses (no DNS lookups)\n-e	display netstat fields\n\nAssigning an address to an interface automatically creates an appropriate\nnetwork route (\"ifconfig eth0 10.0.2.15/8\" does \"route add 10.0.0.0/8 eth0\"\nfor you), although some devices (such as loopback) won't show it in the\ntable. For machines more than one hop away, you need to specify a gateway\n(ala \"route add default gw 10.0.2.2\").\n\nThe address \"default\" is a wildcard address (0.0.0.0/0) matching all\npackets without a more specific route.\n\nAvailable OPTIONS include:\nreject   - blocking route (force match failure)\ndev NAME - force matching packets out this interface (ala \"eth0\")\nnetmask  - old way of saying things like ADDR/24\ngw ADDR  - forward packets to gateway ADDR"
@@ -432,16 +436,6 @@
 
 #define HELP_modprobe "usage: modprobe [-alrqvsDb] [-d DIR] MODULE [symbol=value][...]\n\nmodprobe utility - inserts modules and dependencies.\n\n-a  Load multiple MODULEs\n-b  Apply blacklist to module names too\n-D  Show dependencies\n-d  Load modules from DIR, option may be used multiple times\n-l  List (MODULE is a pattern)\n-q  Quiet\n-r  Remove MODULE (stacks) or do autoclean\n-s  Log to syslog\n-v  Verbose"
 
-#define HELP_mke2fs_extended "usage: mke2fs [-E stride=###] [-O option[,option]]\n\n-E stride= Set RAID stripe size (in blocks)\n-O [opts]  Specify fewer ext2 option flags (for old kernels)\n           All of these are on by default (as appropriate)\n   none         Clear default options (all but journaling)\n   dir_index    Use htree indexes for large directories\n   filetype     Store file type info in directory entry\n   has_journal  Set by -j\n   journal_dev  Set by -J device=XXX\n   sparse_super Don't allocate huge numbers of redundant superblocks"
-
-#define HELP_mke2fs_label "usage: mke2fs [-L label] [-M path] [-o string]\n\n-L         Volume label\n-M         Path to mount point\n-o         Created by"
-
-#define HELP_mke2fs_gen "usage: gene2fs [options] device filename\n\nThe [options] are the same as mke2fs."
-
-#define HELP_mke2fs_journal "usage: mke2fs [-j] [-J size=###,device=XXX]\n\n-j         Create journal (ext3)\n-J         Journal options\n           size: Number of blocks (1024-102400)\n           device: Specify an external journal"
-
-#define HELP_mke2fs "usage: mke2fs [-Fnq] [-b ###] [-N|i ###] [-m ###] device\n\nCreate an ext2 filesystem on a block device or filesystem image.\n\n-F         Force to run on a mounted device\n-n         Don't write to device\n-q         Quiet (no output)\n-b size    Block size (1024, 2048, or 4096)\n-N inodes  Allocate this many inodes\n-i bytes   Allocate one inode for every XXX bytes of device\n-m percent Reserve this percent of filesystem space for root user"
-
 #define HELP_mdev_conf "The mdev config file (/etc/mdev.conf) contains lines that look like:\nhd[a-z][0-9]* 0:3 660\n(sd[a-z]) root:disk 660 =usb_storage\n\nEach line must contain three whitespace separated fields. The first\nfield is a regular expression matching one or more device names,\nthe second and third fields are uid:gid and file permissions for\nmatching devices. Fourth field is optional. It could be used to change\ndevice name (prefix '='), path (prefix '=' and postfix '/') or create a\nsymlink (prefix '>')."
 
 #define HELP_mdev "usage: mdev [-s]\n\nCreate devices in /dev using information from /sys.\n\n-s	Scan all entries in /sys to populate /dev"
@@ -452,7 +446,7 @@
 
 #define HELP_last "usage: last [-W] [-f FILE]\n\nShow listing of last logged in users.\n\n-W      Display the information without host-column truncation\n-f FILE Read from file FILE instead of /var/log/wtmp"
 
-#define HELP_klogd "usage: klogd [-n] [-c N]\n\n-c  N   Print to console messages more urgent than prio N (1-8)\"\n-n    Run in foreground"
+#define HELP_klogd "usage: klogd [-n] [-c PRIORITY]\n\n-c	Print to console messages more urgent than PRIORITY (1-8)\"\n-n	Run in foreground\n-s	Use syscall instead of /proc"
 
 #define HELP_ipcs "usage: ipcs [[-smq] -i shmid] | [[-asmq] [-tcplu]]\n\n-i Show specific resource\nResource specification:\n-a All (default)\n-m Shared memory segments\n-q Message queues\n-s Semaphore arrays\nOutput format:\n-c Creator\n-l Limits\n-p Pid\n-t Time\n-u Summary"
 
@@ -516,7 +510,7 @@
 
 #define HELP_bc "usage: bc [-ilqsw] [file ...]\n\nbc is a command-line calculator with a Turing-complete language.\n\noptions:\n\n  -i  --interactive  force interactive mode\n  -l  --mathlib      use predefined math routines:\n\n                     s(expr)  =  sine of expr in radians\n                     c(expr)  =  cosine of expr in radians\n                     a(expr)  =  arctangent of expr, returning radians\n                     l(expr)  =  natural log of expr\n                     e(expr)  =  raises e to the power of expr\n                     j(n, x)  =  Bessel function of integer order n of x\n\n  -q  --quiet        don't print version and copyright\n  -s  --standard     error if any non-POSIX extensions are used\n  -w  --warn         warn if any non-POSIX extensions are used"
 
-#define HELP_awk "usage:  awk [-F sepstring] [-v assignment]... program [argument...]\n  or:\n        awk [-F sepstring] -f progfile [-f progfile]... [-v assignment]...\n              [argument...]\n  also:\n  -b : use bytes, not characters\n  -c : compile only, do not run"
+#define HELP_awk "usage:  awk [-F sepstring] [-v assignment]... program [argument...]\n  or:\n        awk [-F sepstring] -f progfile [-f progfile]... [-v assignment]...\n              [argument...]\n  also:\n  -b : count bytes, not characters (experimental)\n  -c : compile only, do not run"
 
 #define HELP_arping "usage: arping [-fqbDUA] [-c CNT] [-w TIMEOUT] [-I IFACE] [-s SRC_IP] DST_IP\n\nSend ARP requests/replies\n\n-f         Quit on first ARP reply\n-q         Quiet\n-b         Keep broadcasting, don't go unicast\n-D         Duplicated address detection mode\n-U         Unsolicited ARP mode, update your neighbors\n-A         ARP answer mode, update your neighbors\n-c N       Stop after sending N ARP requests\n-w TIMEOUT Time to wait for ARP reply, seconds\n-I IFACE   Interface to use (default eth0)\n-s SRC_IP  Sender IP address\nDST_IP     Target IP address"
 
@@ -610,7 +604,7 @@
 
 #define HELP_mkdir "usage: mkdir [-vp] [-m MODE] [DIR...]\n\nCreate one or more directories.\n\n-m	Set permissions of directory to mode\n-p	Make parent directories as needed\n-v	Verbose"
 
-#define HELP_ls "usage: ls [-1ACFHLNRSUXZabcdfghilmnopqrstuwx] [--color[=auto]] [FILE...]\n\nList files\n\nwhat to show:\n-A  all files except . and ..      -a  all files including .hidden\n-b  escape nongraphic chars        -d  directory, not contents\n-F  append /dir *exe @sym |FIFO    -f  files (no sort/filter/format)\n-H  follow command line symlinks   -i  inode number\n-L  follow symlinks                -N  no escaping, even on tty\n-p  put '/' after dir names        -q  unprintable chars as '?'\n-R  recursively list in subdirs    -s  storage used (in --block-size)\n-Z  security context\n\noutput formats:\n-1  list one file per line         -C  columns (sorted vertically)\n-g  like -l but no owner           -h  human readable sizes\n-k  reset --block-size to default  -l  long (show full details)\n-m  comma separated                -ll long with nanoseconds (--full-time)\n-n  long with numeric uid/gid      -o  long without group column\n-r  reverse order                  -w  set column width\n-x  columns (horizontal sort)\n\nsort by:  (also --sort=longname,longname... ends with alphabetical)\n-c  ctime      -r  reverse    -S  size     -t  time    -u  atime    -U  none\n-X  extension  -!  dirfirst   -~  nocase\n\n--block-size N	block size (default 1024, -k resets to 1024)\n--color  =always (default)  =auto (when stdout is tty) =never\n    exe=green  suid=red  suidfile=redback  stickydir=greenback\n    device=yellow  symlink=turquoise/red  dir=blue  socket=purple\n\nLong output uses -cu for display, use -ltc/-ltu to also sort by ctime/atime."
+#define HELP_ls "usage: ls [-1ACFHLNRSUXZabcdfghilmnopqrstuwx] [--color[=auto]] [FILE...]\n\nList files\n\nwhat to show:\n-A  all files except . and ..      -a  all files including .hidden\n-b  escape nongraphic chars        -d  directory, not contents\n-F  append /dir *exe @sym |FIFO    -f  files (no sort/filter/format)\n-H  follow command line symlinks   -i  inode number\n-L  follow symlinks                -N  no escaping, even on tty\n-p  put '/' after dir names        -q  unprintable chars as '?'\n-R  recursively list in subdirs    -s  storage used (units of --block-size)\n-Z  security context\n\noutput formats:\n-1  list one file per line         -C  columns (sorted vertically)\n-g  like -l but no owner           -h  human readable sizes\n-k  reset --block-size to default  -l  long (show full details)\n-m  comma separated                -ll long with nanoseconds (--full-time)\n-n  long with numeric uid/gid      -o  long without group column\n-r  reverse order                  -w  set column width\n-x  columns (horizontal sort)\n\nsort by:  (also --sort=longname,longname... ends with alphabetical)\n-c  ctime      -r  reverse    -S  size     -t  time    -u  atime    -U  none\n-X  extension  -!  dirfirst   -~  nocase\n\n--block-size N	block size for -s (default 1024, -k resets to 1024)\n--color  =always (default)  =auto (when stdout is tty) =never\n    exe=green  suid=red  suidfile=redback  stickydir=greenback\n    device=yellow  symlink=turquoise/red  dir=blue  socket=purple\n\nLong output uses -cu for display, use -ltc/-ltu to also sort by ctime/atime."
 
 #define HELP_logger "usage: logger [-s] [-t TAG] [-p [FACILITY.]PRIORITY] [MESSAGE...]\n\nLog message (or stdin) to syslog.\n\n-s	Also write message to stderr\n-t	Use TAG instead of username to identify message source\n-p	Specify PRIORITY with optional FACILITY. Default is \"user.notice\""
 
diff --git a/android/linux/generated/newtoys.h b/android/linux/generated/newtoys.h
index c41eb83f..45b39f49 100644
--- a/android/linux/generated/newtoys.h
+++ b/android/linux/generated/newtoys.h
@@ -24,6 +24,7 @@ USE_BLKID(NEWTOY(blkid, "ULo:s*[!LU]", TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_BLOCKDEV(NEWTOY(blockdev, "<1>1(setro)(setrw)(getro)(getss)(getbsz)(setbsz)#<0(getsz)(getsize)(getsize64)(getra)(setra)#<0(flushbufs)(rereadpt)",TOYFLAG_SBIN))
 USE_BOOTCHARTD(NEWTOY(bootchartd, 0, TOYFLAG_STAYROOT|TOYFLAG_USR|TOYFLAG_BIN))
 USE_BRCTL(NEWTOY(brctl, "<1", TOYFLAG_USR|TOYFLAG_SBIN))
+USE_SH(NEWTOY(break, ">1", TOYFLAG_NOFORK))
 USE_BUNZIP2(NEWTOY(bunzip2, "cftkv", TOYFLAG_USR|TOYFLAG_BIN))
 USE_BZCAT(NEWTOY(bzcat, 0, TOYFLAG_USR|TOYFLAG_BIN))
 USE_CAL(NEWTOY(cal, ">3h", TOYFLAG_USR|TOYFLAG_BIN))
@@ -42,6 +43,7 @@ USE_CKSUM(NEWTOY(cksum, "HIPLN", TOYFLAG_BIN))
 USE_CLEAR(NEWTOY(clear, NULL, TOYFLAG_USR|TOYFLAG_BIN))
 USE_CMP(NEWTOY(cmp, "<1>4ls(silent)(quiet)n#<1[!ls]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)))
 USE_COMM(NEWTOY(comm, "<2>2321", TOYFLAG_USR|TOYFLAG_BIN))
+USE_SH(NEWTOY(continue, ">1", TOYFLAG_NOFORK))
 USE_COUNT(NEWTOY(count, "<0>0l", TOYFLAG_USR|TOYFLAG_BIN))
 USE_CP(NEWTOY(cp, "<1(preserve):;D(parents)RHLPprudaslv(verbose)nF(remove-destination)fit:T[-HLPd][-niu][+Rr]", TOYFLAG_BIN))
 USE_CPIO(NEWTOY(cpio, "(ignore-devno)(renumber-inodes)(quiet)(no-preserve-owner)R(owner):md(make-directories)uLH:p|i|t|F:v(verbose)o|[!pio][!pot][!pF]", TOYFLAG_BIN))
@@ -60,7 +62,7 @@ USE_DEMO_MANY_OPTIONS(NEWTOY(demo_many_options, "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwv
 USE_DEMO_NUMBER(NEWTOY(demo_number, "D#=3<3M#<0hcdbs", TOYFLAG_BIN))
 USE_DEMO_SCANKEY(NEWTOY(demo_scankey, 0, TOYFLAG_BIN))
 USE_DEMO_UTF8TOWC(NEWTOY(demo_utf8towc, 0, TOYFLAG_USR|TOYFLAG_BIN))
-USE_DEVMEM(NEWTOY(devmem, "<1(no-sync)f:", TOYFLAG_USR|TOYFLAG_SBIN))
+USE_DEVMEM(NEWTOY(devmem, "<1(no-sync)(no-mmap)f:", TOYFLAG_USR|TOYFLAG_SBIN))
 USE_DF(NEWTOY(df, "HPkhit*a[-HPh]", TOYFLAG_BIN))
 USE_DHCP(NEWTOY(dhcp, "V:H:F:x*r:O*A#<0=20T#<0=3t#<0=3s:p:i:SBRCaovqnbf", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
 USE_DHCP6(NEWTOY(dhcp6, "r:A#<0T#<0t#<0s:p:i:SRvqnbf", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
@@ -160,7 +162,7 @@ USE_SH(NEWTOY(jobs, "lnprs", TOYFLAG_NOFORK))
 USE_KILL(NEWTOY(kill, "?ls: ", TOYFLAG_BIN|TOYFLAG_MAYFORK))
 USE_KILLALL(NEWTOY(killall, "?s:ilqvw", TOYFLAG_USR|TOYFLAG_BIN))
 USE_KILLALL5(NEWTOY(killall5, "?o*ls: [!lo][!ls]", TOYFLAG_SBIN))
-USE_KLOGD(NEWTOY(klogd, "c#<1>8n", TOYFLAG_SBIN))
+USE_KLOGD(NEWTOY(klogd, "c#<1>8ns", TOYFLAG_SBIN))
 USE_LAST(NEWTOY(last, "f:W", TOYFLAG_BIN))
 USE_LINK(NEWTOY(link, "<2>2", TOYFLAG_USR|TOYFLAG_BIN))
 USE_LINUX32(NEWTOY(linux32, 0, TOYFLAG_USR|TOYFLAG_BIN))
@@ -188,7 +190,6 @@ USE_MEMEATER(NEWTOY(memeater, "<1>1M", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MICROCOM(NEWTOY(microcom, "<1>1s#X", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_NOBUF))
 USE_MIX(NEWTOY(mix, "c:d:l#r#", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MKDIR(NEWTOY(mkdir, "<1"USE_MKDIR_Z("Z:")"vp(parent)(parents)m:", TOYFLAG_BIN|TOYFLAG_UMASK))
-USE_MKE2FS(NEWTOY(mke2fs, "<1>2g:Fnqm#N#i#b#", TOYFLAG_SBIN))
 USE_MKFIFO(NEWTOY(mkfifo, "<1"USE_MKFIFO_Z("Z:")"m:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MKNOD(NEWTOY(mknod, "<2>4m(mode):"USE_MKNOD_Z("Z:"), TOYFLAG_BIN|TOYFLAG_UMASK))
 USE_MKPASSWD(NEWTOY(mkpasswd, ">2S:m:P#=0<0", TOYFLAG_USR|TOYFLAG_BIN))
diff --git a/android/linux/generated/tags.h b/android/linux/generated/tags.h
index d47e3a58..8ae910e6 100644
--- a/android/linux/generated/tags.h
+++ b/android/linux/generated/tags.h
@@ -85,7 +85,7 @@
 #define PS_RUID                          30
 #define _PS_RUID                         (1<<30)
 #define PS_RUSER                         31
-#define _PS_RUSER                        (1<<31)
+#define _PS_RUSER                        (1LL<<31)
 #define PS_GID                           32
 #define _PS_GID                          (1LL<<32)
 #define PS_GROUP                         33
diff --git a/android/mac/generated/flags.h b/android/mac/generated/flags.h
index 504dd782..48ed0167 100644
--- a/android/mac/generated/flags.h
+++ b/android/mac/generated/flags.h
@@ -190,6 +190,14 @@
 #undef FOR_brctl
 #endif
 
+// break   >1
+#undef OPTSTR_break
+#define OPTSTR_break ">1"
+#ifdef CLEANUP_break
+#undef CLEANUP_break
+#undef FOR_break
+#endif
+
 // bunzip2   cftkv
 #undef OPTSTR_bunzip2
 #define OPTSTR_bunzip2 "cftkv"
@@ -376,6 +384,14 @@
 #undef FLAG_3
 #endif
 
+// continue   >1
+#undef OPTSTR_continue
+#define OPTSTR_continue ">1"
+#ifdef CLEANUP_continue
+#undef CLEANUP_continue
+#undef FOR_continue
+#endif
+
 // count   <0>0l
 #undef OPTSTR_count
 #define OPTSTR_count "<0>0l"
@@ -641,13 +657,14 @@
 #undef FOR_demo_utf8towc
 #endif
 
-// devmem   <1(no-sync)f:
+// devmem   <1(no-sync)(no-mmap)f:
 #undef OPTSTR_devmem
-#define OPTSTR_devmem "<1(no-sync)f:"
+#define OPTSTR_devmem "<1(no-sync)(no-mmap)f:"
 #ifdef CLEANUP_devmem
 #undef CLEANUP_devmem
 #undef FOR_devmem
 #undef FLAG_f
+#undef FLAG_no_mmap
 #undef FLAG_no_sync
 #endif
 
@@ -1744,12 +1761,13 @@
 #undef FLAG_o
 #endif
 
-// klogd   c#<1>8n
+// klogd   c#<1>8ns
 #undef OPTSTR_klogd
-#define OPTSTR_klogd "c#<1>8n"
+#define OPTSTR_klogd "c#<1>8ns"
 #ifdef CLEANUP_klogd
 #undef CLEANUP_klogd
 #undef FOR_klogd
+#undef FLAG_s
 #undef FLAG_n
 #undef FLAG_c
 #endif
@@ -2074,22 +2092,6 @@
 #undef FLAG_Z
 #endif
 
-// mke2fs   <1>2g:Fnqm#N#i#b#
-#undef OPTSTR_mke2fs
-#define OPTSTR_mke2fs "<1>2g:Fnqm#N#i#b#"
-#ifdef CLEANUP_mke2fs
-#undef CLEANUP_mke2fs
-#undef FOR_mke2fs
-#undef FLAG_b
-#undef FLAG_i
-#undef FLAG_N
-#undef FLAG_m
-#undef FLAG_q
-#undef FLAG_n
-#undef FLAG_F
-#undef FLAG_g
-#endif
-
 // mkfifo   <1Z:m:
 #undef OPTSTR_mkfifo
 #define OPTSTR_mkfifo "<1Z:m:"
@@ -4123,6 +4125,13 @@
 #endif
 #endif
 
+#ifdef FOR_break
+#define CLEANUP_break
+#ifndef TT
+#define TT this.break
+#endif
+#endif
+
 #ifdef FOR_bunzip2
 #define CLEANUP_bunzip2
 #ifndef TT
@@ -4292,6 +4301,13 @@
 #define FLAG_3 (1LL<<2)
 #endif
 
+#ifdef FOR_continue
+#define CLEANUP_continue
+#ifndef TT
+#define TT this.continue
+#endif
+#endif
+
 #ifdef FOR_count
 #define CLEANUP_count
 #ifndef TT
@@ -4547,7 +4563,8 @@
 #define TT this.devmem
 #endif
 #define FLAG_f (FORCED_FLAG<<0)
-#define FLAG_no_sync (FORCED_FLAG<<1)
+#define FLAG_no_mmap (FORCED_FLAG<<1)
+#define FLAG_no_sync (FORCED_FLAG<<2)
 #endif
 
 #ifdef FOR_df
@@ -5559,8 +5576,9 @@
 #ifndef TT
 #define TT this.klogd
 #endif
-#define FLAG_n (FORCED_FLAG<<0)
-#define FLAG_c (FORCED_FLAG<<1)
+#define FLAG_s (FORCED_FLAG<<0)
+#define FLAG_n (FORCED_FLAG<<1)
+#define FLAG_c (FORCED_FLAG<<2)
 #endif
 
 #ifdef FOR_last
@@ -5856,21 +5874,6 @@
 #define FLAG_Z (FORCED_FLAG<<3)
 #endif
 
-#ifdef FOR_mke2fs
-#define CLEANUP_mke2fs
-#ifndef TT
-#define TT this.mke2fs
-#endif
-#define FLAG_b (FORCED_FLAG<<0)
-#define FLAG_i (FORCED_FLAG<<1)
-#define FLAG_N (FORCED_FLAG<<2)
-#define FLAG_m (FORCED_FLAG<<3)
-#define FLAG_q (FORCED_FLAG<<4)
-#define FLAG_n (FORCED_FLAG<<5)
-#define FLAG_F (FORCED_FLAG<<6)
-#define FLAG_g (FORCED_FLAG<<7)
-#endif
-
 #ifdef FOR_mkfifo
 #define CLEANUP_mkfifo
 #ifndef TT
diff --git a/android/mac/generated/help.h b/android/mac/generated/help.h
index f25a0785..0c099c13 100644
--- a/android/mac/generated/help.h
+++ b/android/mac/generated/help.h
@@ -78,7 +78,7 @@
 
 #define HELP_passwd "usage: passwd [-a ALGO] [-dlu] [USER]\n\nUpdate user's login password. Defaults to current user.\n\n-a ALGO	Encryption method (des, md5, sha256, sha512) default: md5\n-d		Set password to ''\n-l		Lock (disable) account\n-u		Unlock (enable) account"
 
-#define HELP_mount "usage: mount [-afFrsvw] [-t TYPE] [-o OPTION,] [[DEVICE] DIR]\n\nMount new filesystem(s) on directories. With no arguments, display existing\nmounts.\n\n-a	Mount all entries in /etc/fstab (with -t, only entries of that TYPE)\n-O	Only mount -a entries that have this option\n-f	Fake it (don't actually mount)\n-r	Read only (same as -o ro)\n-w	Read/write (default, same as -o rw)\n-t	Specify filesystem type\n-v	Verbose\n\nOPTIONS is a comma separated list of options, which can also be supplied\nas --longopts.\n\nAutodetects loopback mounts (a file on a directory) and bind mounts (file\non file, directory on directory), so you don't need to say --bind or --loop.\nYou can also \"mount -a /path\" to mount everything in /etc/fstab under /path,\neven if it's noauto. DEVICE starting with UUID= is identified by blkid -U."
+#define HELP_mount "usage: mount [-afFrsvw] [-t TYPE] [-o OPTION,] [[DEVICE] DIR]\n\nMount new filesystem(s) on directories. With no arguments, display existing\nmounts.\n\n-a	Mount all entries in /etc/fstab (with -t, only entries of that TYPE)\n-O	Only mount -a entries that have this option\n-f	Fake it (don't actually mount)\n-r	Read only (same as -o ro)\n-w	Read/write (default, same as -o rw)\n-t	Specify filesystem type\n-v	Verbose\n\nOPTIONS is a comma separated list of options, which can also be supplied\nas --longopts.\n\nAutodetects loopback mounts (a file on a directory) and bind mounts (file\non file, directory on directory), so you don't need to say --bind or --loop.\nYou can also \"mount -a /path\" to mount everything in /etc/fstab under /path,\neven if it's noauto. DEVICE starting with UUID= is identified by blkid -U,\nand DEVICE starting with LABEL= is identified by blkid -L."
 
 #define HELP_mktemp "usage: mktemp [-dqtu] [-p DIR] [TEMPLATE]\n\nSafely create a new file \"DIR/TEMPLATE\" and print its name.\n\n-d	Create directory instead of file (--directory)\n-p	Put new file in DIR (--tmpdir)\n-q	Quiet, no error messages\n-t	Prefer $TMPDIR > DIR > /tmp (default DIR > $TMPDIR > /tmp)\n-u	Don't create anything, just print what would be created\n\nEach X in TEMPLATE is replaced with a random printable character. The\ndefault TEMPLATE is tmp.XXXXXXXXXX."
 
@@ -332,7 +332,7 @@
 
 #define HELP_dos2unix "usage: dos2unix [FILE...]\n\nConvert newline format from dos \"\\r\\n\" to unix \"\\n\".\nIf no files listed copy from stdin, \"-\" is a synonym for stdin."
 
-#define HELP_devmem "usage: devmem [-f FILE] ADDR [WIDTH [DATA...]]\n\nRead/write physical addresses. WIDTH is 1, 2, 4, or 8 bytes (default 4).\nPrefix ADDR with 0x for hexadecimal, output is in same base as address.\n\n-f FILE		File to operate on (default /dev/mem)\n--no-sync	Don't open the file with O_SYNC (for cached access)"
+#define HELP_devmem "usage: devmem [-f FILE] ADDR [WIDTH [DATA...]]\n\nRead/write physical addresses. WIDTH is 1, 2, 4, or 8 bytes (default 4).\nPrefix ADDR with 0x for hexadecimal, output is in same base as address.\n\n-f FILE		File to operate on (default /dev/mem)\n--no-sync	Don't open the file with O_SYNC (for cached access)\n--no-mmap	Don't mmap the file"
 
 #define HELP_count "usage: count [-l]\n\n-l	Long output (total bytes, human readable, transfer rate, elapsed time)\n\nCopy stdin to stdout, displaying simple progress indicator to stderr."
 
@@ -422,8 +422,12 @@
 
 #define HELP_declare "usage: declare [-pAailunxr] [NAME...]\n\nSet or print variable attributes and values.\n\n-p	Print variables instead of setting\n-A	Associative array\n-a	Indexed array\n-i	Integer\n-l	Lower case\n-n	Name reference (symlink)\n-r	Readonly\n-u	Uppercase\n-x	Export"
 
+#define HELP_continue "usage: continue [N]\n\nStart next entry in for/while/until loop (or Nth outer loop, default 1)."
+
 #define HELP_cd "usage: cd [-PL] [-] [path]\n\nChange current directory. With no arguments, go $HOME. Sets $OLDPWD to\nprevious directory: cd - to return to $OLDPWD.\n\n-P	Physical path: resolve symlinks in path\n-L	Local path: .. trims directories off $PWD (default)"
 
+#define HELP_break "usage: break [N]\n\nEnd N levels of for/while/until loop immediately (default 1)."
+
 #define HELP_sh "usage: sh [-c command] [script]\n\nCommand shell.  Runs a shell script, or reads input interactively\nand responds to it. Roughly compatible with \"bash\". Run \"help\" for\nlist of built-in commands.\n\n-c	command line to execute\n-i	interactive mode (default when STDIN is a tty)\n-s	don't run script (args set $* parameters but read commands from stdin)\n\nCommand shells parse each line of input (prompting when interactive), perform\nvariable expansion and redirection, execute commands (spawning child processes\nand background jobs), and perform flow control based on the return code.\n\nParsing:\n  syntax errors\n\nInteractive prompts:\n  line continuation\n\nVariable expansion:\n  Note: can cause syntax errors at runtime\n\nRedirection:\n  HERE documents (parsing)\n  Pipelines (flow control and job control)\n\nRunning commands:\n  process state\n  builtins\n    cd [[ ]] (( ))\n    ! : [ # TODO: help for these?\n    true false help echo kill printf pwd test\n  child processes\n\nJob control:\n  &    Background process\n  Ctrl-C kill process\n  Ctrl-Z suspend process\n  bg fg jobs kill\n\nFlow control:\n;    End statement (same as newline)\n&    Background process (returns true unless syntax error)\n&&   If this fails, next command fails without running\n||   If this succeeds, next command succeeds without running\n|    Pipelines! (Can of worms...)\nfor {name [in...]}|((;;)) do; BODY; done\nif TEST; then BODY; fi\nwhile TEST; do BODY; done\ncase a in X);; esac\n[[ TEST ]]\n((MATH))\n\nJob control:\n&    Background process\nCtrl-C kill process\nCtrl-Z suspend process\nbg fg jobs kill"
 
 #define HELP_route "usage: route [-ne] [-A [inet|inet6]] [add|del TARGET [OPTIONS]]\n\nDisplay, add or delete network routes in the \"Forwarding Information Base\",\nwhich send packets out a network interface to an address.\n\n-n	Show numerical addresses (no DNS lookups)\n-e	display netstat fields\n\nAssigning an address to an interface automatically creates an appropriate\nnetwork route (\"ifconfig eth0 10.0.2.15/8\" does \"route add 10.0.0.0/8 eth0\"\nfor you), although some devices (such as loopback) won't show it in the\ntable. For machines more than one hop away, you need to specify a gateway\n(ala \"route add default gw 10.0.2.2\").\n\nThe address \"default\" is a wildcard address (0.0.0.0/0) matching all\npackets without a more specific route.\n\nAvailable OPTIONS include:\nreject   - blocking route (force match failure)\ndev NAME - force matching packets out this interface (ala \"eth0\")\nnetmask  - old way of saying things like ADDR/24\ngw ADDR  - forward packets to gateway ADDR"
@@ -432,16 +436,6 @@
 
 #define HELP_modprobe "usage: modprobe [-alrqvsDb] [-d DIR] MODULE [symbol=value][...]\n\nmodprobe utility - inserts modules and dependencies.\n\n-a  Load multiple MODULEs\n-b  Apply blacklist to module names too\n-D  Show dependencies\n-d  Load modules from DIR, option may be used multiple times\n-l  List (MODULE is a pattern)\n-q  Quiet\n-r  Remove MODULE (stacks) or do autoclean\n-s  Log to syslog\n-v  Verbose"
 
-#define HELP_mke2fs_extended "usage: mke2fs [-E stride=###] [-O option[,option]]\n\n-E stride= Set RAID stripe size (in blocks)\n-O [opts]  Specify fewer ext2 option flags (for old kernels)\n           All of these are on by default (as appropriate)\n   none         Clear default options (all but journaling)\n   dir_index    Use htree indexes for large directories\n   filetype     Store file type info in directory entry\n   has_journal  Set by -j\n   journal_dev  Set by -J device=XXX\n   sparse_super Don't allocate huge numbers of redundant superblocks"
-
-#define HELP_mke2fs_label "usage: mke2fs [-L label] [-M path] [-o string]\n\n-L         Volume label\n-M         Path to mount point\n-o         Created by"
-
-#define HELP_mke2fs_gen "usage: gene2fs [options] device filename\n\nThe [options] are the same as mke2fs."
-
-#define HELP_mke2fs_journal "usage: mke2fs [-j] [-J size=###,device=XXX]\n\n-j         Create journal (ext3)\n-J         Journal options\n           size: Number of blocks (1024-102400)\n           device: Specify an external journal"
-
-#define HELP_mke2fs "usage: mke2fs [-Fnq] [-b ###] [-N|i ###] [-m ###] device\n\nCreate an ext2 filesystem on a block device or filesystem image.\n\n-F         Force to run on a mounted device\n-n         Don't write to device\n-q         Quiet (no output)\n-b size    Block size (1024, 2048, or 4096)\n-N inodes  Allocate this many inodes\n-i bytes   Allocate one inode for every XXX bytes of device\n-m percent Reserve this percent of filesystem space for root user"
-
 #define HELP_mdev_conf "The mdev config file (/etc/mdev.conf) contains lines that look like:\nhd[a-z][0-9]* 0:3 660\n(sd[a-z]) root:disk 660 =usb_storage\n\nEach line must contain three whitespace separated fields. The first\nfield is a regular expression matching one or more device names,\nthe second and third fields are uid:gid and file permissions for\nmatching devices. Fourth field is optional. It could be used to change\ndevice name (prefix '='), path (prefix '=' and postfix '/') or create a\nsymlink (prefix '>')."
 
 #define HELP_mdev "usage: mdev [-s]\n\nCreate devices in /dev using information from /sys.\n\n-s	Scan all entries in /sys to populate /dev"
@@ -452,7 +446,7 @@
 
 #define HELP_last "usage: last [-W] [-f FILE]\n\nShow listing of last logged in users.\n\n-W      Display the information without host-column truncation\n-f FILE Read from file FILE instead of /var/log/wtmp"
 
-#define HELP_klogd "usage: klogd [-n] [-c N]\n\n-c  N   Print to console messages more urgent than prio N (1-8)\"\n-n    Run in foreground"
+#define HELP_klogd "usage: klogd [-n] [-c PRIORITY]\n\n-c	Print to console messages more urgent than PRIORITY (1-8)\"\n-n	Run in foreground\n-s	Use syscall instead of /proc"
 
 #define HELP_ipcs "usage: ipcs [[-smq] -i shmid] | [[-asmq] [-tcplu]]\n\n-i Show specific resource\nResource specification:\n-a All (default)\n-m Shared memory segments\n-q Message queues\n-s Semaphore arrays\nOutput format:\n-c Creator\n-l Limits\n-p Pid\n-t Time\n-u Summary"
 
@@ -516,7 +510,7 @@
 
 #define HELP_bc "usage: bc [-ilqsw] [file ...]\n\nbc is a command-line calculator with a Turing-complete language.\n\noptions:\n\n  -i  --interactive  force interactive mode\n  -l  --mathlib      use predefined math routines:\n\n                     s(expr)  =  sine of expr in radians\n                     c(expr)  =  cosine of expr in radians\n                     a(expr)  =  arctangent of expr, returning radians\n                     l(expr)  =  natural log of expr\n                     e(expr)  =  raises e to the power of expr\n                     j(n, x)  =  Bessel function of integer order n of x\n\n  -q  --quiet        don't print version and copyright\n  -s  --standard     error if any non-POSIX extensions are used\n  -w  --warn         warn if any non-POSIX extensions are used"
 
-#define HELP_awk "usage:  awk [-F sepstring] [-v assignment]... program [argument...]\n  or:\n        awk [-F sepstring] -f progfile [-f progfile]... [-v assignment]...\n              [argument...]\n  also:\n  -b : use bytes, not characters\n  -c : compile only, do not run"
+#define HELP_awk "usage:  awk [-F sepstring] [-v assignment]... program [argument...]\n  or:\n        awk [-F sepstring] -f progfile [-f progfile]... [-v assignment]...\n              [argument...]\n  also:\n  -b : count bytes, not characters (experimental)\n  -c : compile only, do not run"
 
 #define HELP_arping "usage: arping [-fqbDUA] [-c CNT] [-w TIMEOUT] [-I IFACE] [-s SRC_IP] DST_IP\n\nSend ARP requests/replies\n\n-f         Quit on first ARP reply\n-q         Quiet\n-b         Keep broadcasting, don't go unicast\n-D         Duplicated address detection mode\n-U         Unsolicited ARP mode, update your neighbors\n-A         ARP answer mode, update your neighbors\n-c N       Stop after sending N ARP requests\n-w TIMEOUT Time to wait for ARP reply, seconds\n-I IFACE   Interface to use (default eth0)\n-s SRC_IP  Sender IP address\nDST_IP     Target IP address"
 
@@ -610,7 +604,7 @@
 
 #define HELP_mkdir "usage: mkdir [-vp] [-m MODE] [DIR...]\n\nCreate one or more directories.\n\n-m	Set permissions of directory to mode\n-p	Make parent directories as needed\n-v	Verbose"
 
-#define HELP_ls "usage: ls [-1ACFHLNRSUXZabcdfghilmnopqrstuwx] [--color[=auto]] [FILE...]\n\nList files\n\nwhat to show:\n-A  all files except . and ..      -a  all files including .hidden\n-b  escape nongraphic chars        -d  directory, not contents\n-F  append /dir *exe @sym |FIFO    -f  files (no sort/filter/format)\n-H  follow command line symlinks   -i  inode number\n-L  follow symlinks                -N  no escaping, even on tty\n-p  put '/' after dir names        -q  unprintable chars as '?'\n-R  recursively list in subdirs    -s  storage used (in --block-size)\n-Z  security context\n\noutput formats:\n-1  list one file per line         -C  columns (sorted vertically)\n-g  like -l but no owner           -h  human readable sizes\n-k  reset --block-size to default  -l  long (show full details)\n-m  comma separated                -ll long with nanoseconds (--full-time)\n-n  long with numeric uid/gid      -o  long without group column\n-r  reverse order                  -w  set column width\n-x  columns (horizontal sort)\n\nsort by:  (also --sort=longname,longname... ends with alphabetical)\n-c  ctime      -r  reverse    -S  size     -t  time    -u  atime    -U  none\n-X  extension  -!  dirfirst   -~  nocase\n\n--block-size N	block size (default 1024, -k resets to 1024)\n--color  =always (default)  =auto (when stdout is tty) =never\n    exe=green  suid=red  suidfile=redback  stickydir=greenback\n    device=yellow  symlink=turquoise/red  dir=blue  socket=purple\n\nLong output uses -cu for display, use -ltc/-ltu to also sort by ctime/atime."
+#define HELP_ls "usage: ls [-1ACFHLNRSUXZabcdfghilmnopqrstuwx] [--color[=auto]] [FILE...]\n\nList files\n\nwhat to show:\n-A  all files except . and ..      -a  all files including .hidden\n-b  escape nongraphic chars        -d  directory, not contents\n-F  append /dir *exe @sym |FIFO    -f  files (no sort/filter/format)\n-H  follow command line symlinks   -i  inode number\n-L  follow symlinks                -N  no escaping, even on tty\n-p  put '/' after dir names        -q  unprintable chars as '?'\n-R  recursively list in subdirs    -s  storage used (units of --block-size)\n-Z  security context\n\noutput formats:\n-1  list one file per line         -C  columns (sorted vertically)\n-g  like -l but no owner           -h  human readable sizes\n-k  reset --block-size to default  -l  long (show full details)\n-m  comma separated                -ll long with nanoseconds (--full-time)\n-n  long with numeric uid/gid      -o  long without group column\n-r  reverse order                  -w  set column width\n-x  columns (horizontal sort)\n\nsort by:  (also --sort=longname,longname... ends with alphabetical)\n-c  ctime      -r  reverse    -S  size     -t  time    -u  atime    -U  none\n-X  extension  -!  dirfirst   -~  nocase\n\n--block-size N	block size for -s (default 1024, -k resets to 1024)\n--color  =always (default)  =auto (when stdout is tty) =never\n    exe=green  suid=red  suidfile=redback  stickydir=greenback\n    device=yellow  symlink=turquoise/red  dir=blue  socket=purple\n\nLong output uses -cu for display, use -ltc/-ltu to also sort by ctime/atime."
 
 #define HELP_logger "usage: logger [-s] [-t TAG] [-p [FACILITY.]PRIORITY] [MESSAGE...]\n\nLog message (or stdin) to syslog.\n\n-s	Also write message to stderr\n-t	Use TAG instead of username to identify message source\n-p	Specify PRIORITY with optional FACILITY. Default is \"user.notice\""
 
diff --git a/android/mac/generated/newtoys.h b/android/mac/generated/newtoys.h
index c41eb83f..45b39f49 100644
--- a/android/mac/generated/newtoys.h
+++ b/android/mac/generated/newtoys.h
@@ -24,6 +24,7 @@ USE_BLKID(NEWTOY(blkid, "ULo:s*[!LU]", TOYFLAG_BIN|TOYFLAG_LINEBUF))
 USE_BLOCKDEV(NEWTOY(blockdev, "<1>1(setro)(setrw)(getro)(getss)(getbsz)(setbsz)#<0(getsz)(getsize)(getsize64)(getra)(setra)#<0(flushbufs)(rereadpt)",TOYFLAG_SBIN))
 USE_BOOTCHARTD(NEWTOY(bootchartd, 0, TOYFLAG_STAYROOT|TOYFLAG_USR|TOYFLAG_BIN))
 USE_BRCTL(NEWTOY(brctl, "<1", TOYFLAG_USR|TOYFLAG_SBIN))
+USE_SH(NEWTOY(break, ">1", TOYFLAG_NOFORK))
 USE_BUNZIP2(NEWTOY(bunzip2, "cftkv", TOYFLAG_USR|TOYFLAG_BIN))
 USE_BZCAT(NEWTOY(bzcat, 0, TOYFLAG_USR|TOYFLAG_BIN))
 USE_CAL(NEWTOY(cal, ">3h", TOYFLAG_USR|TOYFLAG_BIN))
@@ -42,6 +43,7 @@ USE_CKSUM(NEWTOY(cksum, "HIPLN", TOYFLAG_BIN))
 USE_CLEAR(NEWTOY(clear, NULL, TOYFLAG_USR|TOYFLAG_BIN))
 USE_CMP(NEWTOY(cmp, "<1>4ls(silent)(quiet)n#<1[!ls]", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_ARGFAIL(2)))
 USE_COMM(NEWTOY(comm, "<2>2321", TOYFLAG_USR|TOYFLAG_BIN))
+USE_SH(NEWTOY(continue, ">1", TOYFLAG_NOFORK))
 USE_COUNT(NEWTOY(count, "<0>0l", TOYFLAG_USR|TOYFLAG_BIN))
 USE_CP(NEWTOY(cp, "<1(preserve):;D(parents)RHLPprudaslv(verbose)nF(remove-destination)fit:T[-HLPd][-niu][+Rr]", TOYFLAG_BIN))
 USE_CPIO(NEWTOY(cpio, "(ignore-devno)(renumber-inodes)(quiet)(no-preserve-owner)R(owner):md(make-directories)uLH:p|i|t|F:v(verbose)o|[!pio][!pot][!pF]", TOYFLAG_BIN))
@@ -60,7 +62,7 @@ USE_DEMO_MANY_OPTIONS(NEWTOY(demo_many_options, "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwv
 USE_DEMO_NUMBER(NEWTOY(demo_number, "D#=3<3M#<0hcdbs", TOYFLAG_BIN))
 USE_DEMO_SCANKEY(NEWTOY(demo_scankey, 0, TOYFLAG_BIN))
 USE_DEMO_UTF8TOWC(NEWTOY(demo_utf8towc, 0, TOYFLAG_USR|TOYFLAG_BIN))
-USE_DEVMEM(NEWTOY(devmem, "<1(no-sync)f:", TOYFLAG_USR|TOYFLAG_SBIN))
+USE_DEVMEM(NEWTOY(devmem, "<1(no-sync)(no-mmap)f:", TOYFLAG_USR|TOYFLAG_SBIN))
 USE_DF(NEWTOY(df, "HPkhit*a[-HPh]", TOYFLAG_BIN))
 USE_DHCP(NEWTOY(dhcp, "V:H:F:x*r:O*A#<0=20T#<0=3t#<0=3s:p:i:SBRCaovqnbf", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
 USE_DHCP6(NEWTOY(dhcp6, "r:A#<0T#<0t#<0s:p:i:SRvqnbf", TOYFLAG_SBIN|TOYFLAG_ROOTONLY))
@@ -160,7 +162,7 @@ USE_SH(NEWTOY(jobs, "lnprs", TOYFLAG_NOFORK))
 USE_KILL(NEWTOY(kill, "?ls: ", TOYFLAG_BIN|TOYFLAG_MAYFORK))
 USE_KILLALL(NEWTOY(killall, "?s:ilqvw", TOYFLAG_USR|TOYFLAG_BIN))
 USE_KILLALL5(NEWTOY(killall5, "?o*ls: [!lo][!ls]", TOYFLAG_SBIN))
-USE_KLOGD(NEWTOY(klogd, "c#<1>8n", TOYFLAG_SBIN))
+USE_KLOGD(NEWTOY(klogd, "c#<1>8ns", TOYFLAG_SBIN))
 USE_LAST(NEWTOY(last, "f:W", TOYFLAG_BIN))
 USE_LINK(NEWTOY(link, "<2>2", TOYFLAG_USR|TOYFLAG_BIN))
 USE_LINUX32(NEWTOY(linux32, 0, TOYFLAG_USR|TOYFLAG_BIN))
@@ -188,7 +190,6 @@ USE_MEMEATER(NEWTOY(memeater, "<1>1M", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MICROCOM(NEWTOY(microcom, "<1>1s#X", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_NOBUF))
 USE_MIX(NEWTOY(mix, "c:d:l#r#", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MKDIR(NEWTOY(mkdir, "<1"USE_MKDIR_Z("Z:")"vp(parent)(parents)m:", TOYFLAG_BIN|TOYFLAG_UMASK))
-USE_MKE2FS(NEWTOY(mke2fs, "<1>2g:Fnqm#N#i#b#", TOYFLAG_SBIN))
 USE_MKFIFO(NEWTOY(mkfifo, "<1"USE_MKFIFO_Z("Z:")"m:", TOYFLAG_USR|TOYFLAG_BIN))
 USE_MKNOD(NEWTOY(mknod, "<2>4m(mode):"USE_MKNOD_Z("Z:"), TOYFLAG_BIN|TOYFLAG_UMASK))
 USE_MKPASSWD(NEWTOY(mkpasswd, ">2S:m:P#=0<0", TOYFLAG_USR|TOYFLAG_BIN))
diff --git a/android/mac/generated/tags.h b/android/mac/generated/tags.h
index d47e3a58..8ae910e6 100644
--- a/android/mac/generated/tags.h
+++ b/android/mac/generated/tags.h
@@ -85,7 +85,7 @@
 #define PS_RUID                          30
 #define _PS_RUID                         (1<<30)
 #define PS_RUSER                         31
-#define _PS_RUSER                        (1<<31)
+#define _PS_RUSER                        (1LL<<31)
 #define PS_GID                           32
 #define _PS_GID                          (1LL<<32)
 #define PS_GROUP                         33
diff --git a/lib/portability.h b/lib/portability.h
index 0b9e282f..a62a0cb9 100644
--- a/lib/portability.h
+++ b/lib/portability.h
@@ -43,13 +43,10 @@
 // Test for gcc (using compiler builtin #define)
 
 #ifdef __GNUC__
-#ifndef __clang__
 #define QUIET = 0 // shut up false positive "may be used uninitialized" warning
-#else
-#define QUIET
-#endif
 #define printf_format	__attribute__((format(printf, 1, 2)))
 #else
+#define QUIET
 #define printf_format
 #endif
 
diff --git a/lib/xwrap.c b/lib/xwrap.c
index d07f355a..aa036d4d 100644
--- a/lib/xwrap.c
+++ b/lib/xwrap.c
@@ -198,6 +198,7 @@ void xvdaemon(void)
   }
 
   // new session id, point fd 0-2 at /dev/null, detach from tty
+  chdir("/");
   setsid();
   close(0);
   xopen_stdio("/dev/null", O_RDWR);
diff --git a/mkroot/mkroot.sh b/mkroot/mkroot.sh
index 26912997..d2cbd44f 100755
--- a/mkroot/mkroot.sh
+++ b/mkroot/mkroot.sh
@@ -223,8 +223,7 @@ get_target_config()
       SERIAL_AMBA_PL011{,_CONSOLE} RTC_{CLASS,HCTOSYS,DRV_PL031} \
       PATA_{,OF_}PLATFORM PCI{,_HOST_GENERIC})"
   elif [ "$CROSS" == hexagon ]; then
-    QEMU="hexagon -M comet"
-    KARCH="hexagon LLVM_IAS=1" KCONF=SPI,SPI_BITBANG,IOMMU_SUPPORT
+    QEMU_M=comet KARCH="hexagon LLVM_IAS=1" KCONF=SPI,SPI_BITBANG,IOMMU_SUPPORT
   elif [ "$CROSS" == i486 ] || [ "$CROSS" == i686 ] ||
        [ "$CROSS" == x86_64 ] || [ "$CROSS" == x32 ]; then
     if [ "$CROSS" == i486 ]; then
@@ -239,25 +238,24 @@ get_target_config()
     KCONF+=,"$(be2csv UNWINDER_FRAME_POINTER PCI BLK_DEV_SD NET_VENDOR_INTEL \
       E1000 RTC_CLASS ATA{,_SFF,_BMDMA,_PIIX} SERIAL_8250{,_CONSOLE})"
   elif [ "$CROSS" == m68k ]; then
-    QEMU="m68k -M q800" KARCH=m68k
+    QEMU_M=q800 KARCH=m68k
     KCONF="$(be2csv MMU M68040 M68KFPU_EMU MAC BLK_DEV_SD MACINTOSH_DRIVERS \
       NET_VENDOR_NATSEMI MACSONIC SCSI{,_LOWLEVEL,_MAC_ESP} \
       SERIAL_PMACZILOG{,_TTYS,_CONSOLE})"
   elif [ "$CROSS" == microblaze ]; then
-    QEMU="microblaze -M petalogix-s3adsp1800" KARCH=microblaze KARGS=ttyUL0
+    QEMU_M=petalogix-s3adsp1800 KARCH=microblaze KARGS=ttyUL0
     KCONF="$(be2csv MMU CPU_BIG_ENDIAN SERIAL_UARTLITE{,_CONSOLE} \
       XILINX_{EMACLITE,MICROBLAZE0_{FAMILY="spartan3adsp",USE_{{MSR,PCMP}_INSTR,BARREL,HW_MUL}=1}})"
   elif [ "${CROSS#mips}" != "$CROSS" ]; then # mips mipsel mips64 mips64el
-    QEMU="$CROSS -M malta" KARCH=mips
+    QEMU_M=malta KARCH=mips
     KCONF="$(be2csv MIPS_MALTA CPU_MIPS32_R2 BLK_DEV_SD NET_VENDOR_AMD PCNET32 \
       PCI SERIAL_8250{,_CONSOLE} ATA{,_SFF,_BMDMA,_PIIX} POWER_RESET{,_SYSCON})"
     [ "${CROSS/64/}" == "$CROSS" ] && KCONF+=,CPU_MIPS32_R2 ||
       KCONF+=,64BIT,CPU_MIPS64_R1,MIPS32_O32
     [ "${CROSS%el}" != "$CROSS" ] && KCONF+=,CPU_LITTLE_ENDIAN
   elif [ "$CROSS" == or1k ]; then
-    KARCH=openrisc QEMU="or1k -M or1k-sim" KARGS=FIXME BUILTIN=1
+    KARCH=openrisc QEMU_M=or1k-sim KARGS=ttyS0
     KCONF="$(be2csv ETHOC SERIO SERIAL_OF_PLATFORM SERIAL_8250{,_CONSOLE})"
-    KCONF+=,OPENRISC_BUILTIN_DTB=\"or1ksim\"
   elif [ "$CROSS" == powerpc ]; then
     KARCH=powerpc QEMU="ppc -M g3beige"
     KCONF="$(be2csv ALTIVEC PATA_MACIO BLK_DEV_SD MACINTOSH_DRIVERS SERIO \
@@ -269,19 +267,20 @@ get_target_config()
       PPC_{PSERIES,OF_BOOT_TRAMPOLINE,TRANSACTIONAL_MEM,DISABLE_WERROR} \
       SCSI_{LOWLEVEL,IBMVSCSI})"
     [ "$CROSS" == powerpc64le ] && KCONF=$KCONF,CPU_LITTLE_ENDIAN
-  elif [ "$CROSS" = riscv32 ]; then
+  elif [ "$CROSS" = riscv32 ] || [ "$CROSS" = riscv64 ]; then
     # Note: -hda file.img doesn't work, but this insane overcomplicated pile:
     # -drive file=file.img,format=raw,id=hd0 -device virtio-blk-device,drive=hd0
-    QEMU="riscv32 -M virt -netdev user,id=net0 -device virtio-net-device,netdev=net0"
+    QEMU_M="virt -netdev user,id=net0 -device virtio-net-device,netdev=net0"
     KARCH=riscv VMLINUX=Image
     # Probably only about half of these kernel symbols are actually needed?
-    KCONF="$(be2csv MMU SOC_VIRT NONPORTABLE ARCH_RV32I CMODEL_MEDANY \
+    KCONF="$(be2csv MMU SOC_VIRT NONPORTABLE CMODEL_MEDANY \
       RISCV_ISA_{ZICBO{M,Z},FALLBACK} FPU PCI{,_HOST_GENERIC} BLK_DEV_SD \
       SCSI_{PROC_FS,LOWLEVEL,VIRTIO} VIRTIO_{MENU,NET,BLK,PCI} SERIO_SERPORT \
       SERIAL_{EARLYCON,8250{,_CONSOLE,_PCI},OF_PLATFORM} HW_RANDOM{,_VIRTIO} \
       RTC_{CLASS,HCTOSYS} DMADEVICES VIRTIO_{MENU,PCI{,_LEGACY},INPUT,MMIO})"
+    [ "$CROSS" = riscv32 ] && KCONF+=,ARCH_RV32I
   elif [ "$CROSS" = s390x ]; then
-    QEMU="s390x" KARCH=s390 VMLINUX=bzImage
+    KARCH=s390 VMLINUX=bzImage
     KCONF="$(be2csv MARCH_Z900 PACK_STACK S390_GUEST VIRTIO_{NET,BLK} \
       SCLP_VT220_{TTY,CONSOLE})"
   elif [ "$CROSS" == sh2eb ]; then
@@ -293,16 +292,17 @@ get_target_config()
       BINFMT_{ELF_FDPIC,MISC} I2C{,_HELPER_AUTO})"
     KCONF+=,CMDLINE=\"console=ttyUL0\ earlycon\"
   elif [ "$CROSS" == sh4 ] || [ "$CROSS" == sh4eb ]; then
-    QEMU="$CROSS -M r2d -serial null -serial mon:stdio" KARCH=sh
+    QEMU_M="r2d -serial null -serial mon:stdio" KARCH=sh
     KARGS="ttySC1 noiotrap" VMLINUX=zImage
     KCONF="$(be2csv CPU_SUBTYPE_SH7751R MMU VSYSCALL SH_{FPU,RTS7751R2D} PCI \
       RTS7751R2D_PLUS SERIAL_SH_SCI{,_CONSOLE} NET_VENDOR_REALTEK 8139CP \
       BLK_DEV_SD ATA{,_SFF,_BMDMA} PATA_PLATFORM BINFMT_ELF_FDPIC \
-      MEMORY_START=0x0c000000)"
+      CMDLINE_EXTEND MEMORY_START=0x0c000000)"
 #see also SPI{,_SH_SCI} MFD_SM501 RTC_{CLASS,DRV_{R9701,SH},HCTOSYS}
     [ "$CROSS" == sh4eb ] && KCONF+=,CPU_BIG_ENDIAN
   else die "Unknown \$CROSS=$CROSS"
   fi
+  : ${QEMU:=$CROSS ${QEMU_M:+-M $QEMU_M}}
 }
 
 # Linux kernel .config symbols common to all architectures
diff --git a/scripts/install.sh b/scripts/install.sh
index 7c90036e..22bb472c 100755
--- a/scripts/install.sh
+++ b/scripts/install.sh
@@ -106,8 +106,7 @@ done
 # For now symlink the host version. This list must go away by 1.0.
 
 PENDING="expr git tr bash sh gzip   awk bison flex make ar"
-TOOLCHAIN="as cc ld objdump"
-TOOLCHAIN+=" bc gcc" # both patched out but not in vanilla yet
+TOOLCHAIN+=" as cc ld objdump  bc gcc"
 
 # Tools needed to build packages
 for i in $TOOLCHAIN $PENDING $HOST_EXTRA
diff --git a/scripts/make.sh b/scripts/make.sh
index ff677d5d..3f4b3070 100755
--- a/scripts/make.sh
+++ b/scripts/make.sh
@@ -218,7 +218,7 @@ $SED -ne '/TAGGED_ARRAY(/,/^)/{s/.*TAGGED_ARRAY[(]\([^,]*\),/\1/p' \
 while read i; do
   [ "$i" = "${i#_}" ] && { HEAD="$i"; X=0; LL=; continue;}
   for j in $i; do
-    [ $X -eq 32 ] && LL=LL
+    [ $X -eq 31 ] && LL=LL
     NAME="$HEAD$j"
     printf "#define $NAME %*s%s\n#define _$NAME %*s%s\n" \
       $((32-${#NAME})) "" "$X" $((31-${#NAME})) "" "(1$LL<<$((X++)))" || exit 1
diff --git a/tests/awk.test b/tests/awk.test
index a9ea76de..94f096c4 100644
--- a/tests/awk.test
+++ b/tests/awk.test
@@ -420,6 +420,33 @@ testcmd "awk -v myvar=val -f file1 file" "-v myvar=$2 -f test.awk testfile1.txt
 
 # 2024: New tests -- not in Divya Kothari's original ...
 
+# Assigning NF=0 caused trouble
+testcmd "assign NF=0" "'BEGIN { \$0 = \"a b\"; print NF, \"x\" \$0 \"y\"; NF = 0; print NF, \"x\" \$0 \"y\" }'" "2 xa by\n0 xy\n" "" ""
+
+# The following has never had a problem but is a good test anyway
+testcmd "split on empty string" "'BEGIN { n = split(\"abc\", a, \"\");print n, length(a)}'" "3 3\n" "" ""
+# The following must be run with ASAN=1 to cause failure with older versions
+testcmd "split on empty regex" "'BEGIN { n = split(\"abc\", a, //);print n, length(a)}'" "3 3\n" "" ""
+
+testcmd "srand() seeds unix time seconds" "'{dt = srand(srand()) - \$0; ok = dt == 0 || dt == 1; print ok}'" "1\n" "" "`date +%s`"
+testcmd "srand() default seed is 1" "'BEGIN{ print srand()}'" "1\n" "" ""
+
+# A file with empty lines can be treated as multiline records if RS="".
+FILEMULTILINE="abc defxy ghi\njkl mno\n\n\npqr stu\nvwxy abc\n"
+
+testcmd "multiline 1" "'BEGIN { RS=\"\"; FS=\"\"}; {print NR, NF, \$0; for (i=1;i<=NF;i++)printf \" %s %s\", i, \$i; print \"\"}'" "1 21 abc defxy ghi\njkl mno\n 1 a 2 b 3 c 4   5 d 6 e 7 f 8 x 9 y 10   11 g 12 h 13 i 14 \n 15 j 16 k 17 l 18   19 m 20 n 21 o\n2 16 pqr stu\nvwxy abc\n 1 p 2 q 3 r 4   5 s 6 t 7 u 8 \n 9 v 10 w 11 x 12 y 13   14 a 15 b 16 c\n" "" "$FILEMULTILINE"
+testcmd "multiline 2" "'BEGIN { RS=\"\"; FS=\" \"}; {print NR, NF, \$0; for (i=1;i<=NF;i++)printf \" %s %s\", i, \$i; print \"\"}'" "1 5 abc defxy ghi\njkl mno\n 1 abc 2 defxy 3 ghi 4 jkl 5 mno\n2 4 pqr stu\nvwxy abc\n 1 pqr 2 stu 3 vwxy 4 abc\n" "" "$FILEMULTILINE"
+testcmd "multiline 3" "'BEGIN { RS=\"\"; FS=\"x\"}; {print NR, NF, \$0; for (i=1;i<=NF;i++)printf \" %s %s\", i, \$i; print \"\"}'" "1 3 abc defxy ghi\njkl mno\n 1 abc def 2 y ghi 3 jkl mno\n2 3 pqr stu\nvwxy abc\n 1 pqr stu 2 vw 3 y abc\n" "" "$FILEMULTILINE"
+testcmd "multiline 4" "'BEGIN { RS=\"\"; FS=\"[ ]\"}; {print NR, NF, \$0; for (i=1;i<=NF;i++)printf \" %s %s\", i, \$i; print \"\"}'" "1 4 abc defxy ghi\njkl mno\n 1 abc 2 defxy 3 ghi\njkl 4 mno\n2 3 pqr stu\nvwxy abc\n 1 pqr 2 stu\nvwxy 3 abc\n" "" "$FILEMULTILINE"
+testcmd "multiline 5" "'BEGIN { RS=\"\"; FS=\"xy\"}; {print NR, NF, \$0; for (i=1;i<=NF;i++)printf \" %s %s\", i, \$i; print \"\"}'" "1 2 abc defxy ghi\njkl mno\n 1 abc def 2  ghi\njkl mno\n2 2 pqr stu\nvwxy abc\n 1 pqr stu\nvw 2  abc\n" "" "$FILEMULTILINE"
+
+# A "null" RS other than an empty string, e.g. "()" cannot match anywhere and most awks will take the entire file as one record.
+# A bug in earlier versions (also in busybox awk) cause infinite output on "null RS" test
+testcmd "null RS" "'BEGIN { RS=\"()\"; FS=\" \"}; {print NR, NF, \$0; for (i=1;i<=NF;i++)printf \" %s %s\", i, \$i; print \"\"}'" "1 9 abc defxy ghi\njkl mno\n\n\npqr stu\nvwxy abc\n\n 1 abc 2 defxy 3 ghi 4 jkl 5 mno 6 pqr 7 stu 8 vwxy 9 abc\n" "" "$FILEMULTILINE"
+
+testcmd "split() utf8"  "'BEGIN{n = split(\"aβc\", a, \"\"); printf \"%d %d\", n, length(a);for (e = 1; e <= n; e++) printf \" %s %s\", e, \"(\" a[e] \")\";print \"\"}'" "3 3 1 (a) 2 (β) 3 (c)\n" "" ""
+testcmd "split fields utf8"  "'BEGIN{FS=\"\"}; {printf \"%d\", NF; for (e = 1; e <= NF; e++) printf \" %s %s\", e, \"(\" \$e \")\"; print \"\"}'" "3 1 (a) 2 (β) 3 (c)\n" "" "aβc"
+
 testcmd "nextfile" " '{print NR, FNR, \$0};/ghi jkl/{nextfile}/ghi,jkl/{nextfile}' testfile1.txt testfile2.txt" "1 1 abc def ghi 5\n2 2 ghi jkl mno 10\n3 1 abc,def,ghi,5\n4 2 ghi,jkl,mno,10\n" "" ""
 
 testcmd "getline var numeric string bug fixed 20240514"  "'BEGIN{getline var; print (var < 10.0)}'" "1\n" "" "5.0\n"
diff --git a/tests/blkid.test b/tests/blkid.test
index bcd38f3d..420a03b2 100755
--- a/tests/blkid.test
+++ b/tests/blkid.test
@@ -45,6 +45,9 @@ testing "squashfs" "BLKID squashfs" 'temp.img: TYPE="squashfs"\n' "" ""
 testing "vfat" "BLKID vfat" \
   'temp.img: SEC_TYPE="msdos" LABEL="myvfat" UUID="7356-B91D" TYPE="vfat"\n' \
   "" ""
+testing "fat32" "BLKID fat32" \
+  'temp.img: LABEL="myfat32" UUID="2E7D-E046" TYPE="vfat"\n' \
+  "" ""
 testing "xfs" "BLKID xfs" \
   'temp.img: LABEL="XFS_test" UUID="d63a1dc3-27d5-4dd4-8b38-f4f97f495c6f" TYPE="xfs"\n' \
   "" ""
diff --git a/tests/devmem.test b/tests/devmem.test
index 2b16bfd4..9b3ecae6 100755
--- a/tests/devmem.test
+++ b/tests/devmem.test
@@ -9,14 +9,32 @@ testcmd 'read 2' '-f foo 0x8 2' '0x6568\n' '' ''
 testcmd 'read 4' '-f foo 0x8 4' '0x6c6c6568\n' '' ''
 testcmd 'read 8' '-f foo 0x8 8' '0x77202c6f6c6c6568\n' '' ''
 
+testcmd 'read --no-mmap default (4)' '--no-mmap -f foo 0x8' '0x6c6c6568\n' '' ''
+testcmd 'read --no-mmap 1' '--no-mmap -f foo 0x8 1' '0x68\n' '' ''
+testcmd 'read --no-mmap 2' '--no-mmap -f foo 0x8 2' '0x6568\n' '' ''
+testcmd 'read --no-mmap 4' '--no-mmap -f foo 0x8 4' '0x6c6c6568\n' '' ''
+testcmd 'read --no-mmap 8' '--no-mmap -f foo 0x8 8' '0x77202c6f6c6c6568\n' '' ''
+
 head -c 32 /dev/zero > foo
 NOSPACE=1 testcmd 'write 1' '-f foo 0x8 1 0x12 && od -t x foo' '0000000 00000000 00000000 00000012 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
 NOSPACE=1 testcmd 'write 2' '-f foo 0x8 2 0x1234 && od -t x foo' '0000000 00000000 00000000 00001234 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
 NOSPACE=1 testcmd 'write 4' '-f foo 0x8 4 0x12345678 && od -t x foo' '0000000 00000000 00000000 12345678 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
 NOSPACE=1 testcmd 'write 8' '-f foo 0x8 8 0x12345678abcdef01 && od -t x foo' '0000000 00000000 00000000 abcdef01 12345678\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
 
+head -c 32 /dev/zero > foo
+NOSPACE=1 testcmd 'write --no-mmap 1' '--no-mmap -f foo 0x8 1 0x12 && od -t x foo' '0000000 00000000 00000000 00000012 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
+NOSPACE=1 testcmd 'write --no-mmap 2' '--no-mmap -f foo 0x8 2 0x1234 && od -t x foo' '0000000 00000000 00000000 00001234 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
+NOSPACE=1 testcmd 'write --no-mmap 4' '--no-mmap -f foo 0x8 4 0x12345678 && od -t x foo' '0000000 00000000 00000000 12345678 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
+NOSPACE=1 testcmd 'write --no-mmap 8' '--no-mmap -f foo 0x8 8 0x12345678abcdef01 && od -t x foo' '0000000 00000000 00000000 abcdef01 12345678\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
+
 head -c 32 /dev/zero > foo
 NOSPACE=1 testcmd 'write 1 multiple' '-f foo 0x8 1 0x12 0x34 && od -t x foo' '0000000 00000000 00000000 00003412 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
 NOSPACE=1 testcmd 'write 2 multiple' '-f foo 0x8 2 0x1234 0x5678 && od -t x foo' '0000000 00000000 00000000 56781234 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
 NOSPACE=1 testcmd 'write 4 multiple' '-f foo 0x8 4 0x12345678 0xabcdef01 && od -t x foo' '0000000 00000000 00000000 12345678 abcdef01\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
 NOSPACE=1 testcmd 'write 8 multiple' '-f foo 0x8 8 0x12345678abcdef01 0x1122334455667788 && od -t x foo' '0000000 00000000 00000000 abcdef01 12345678\n0000020 55667788 11223344 00000000 00000000\n0000040\n' '' ''
+
+head -c 32 /dev/zero > foo
+NOSPACE=1 testcmd 'write --no-mmap 1 multiple' '--no-mmap -f foo 0x8 1 0x12 0x34 && od -t x foo' '0000000 00000000 00000000 00003412 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
+NOSPACE=1 testcmd 'write --no-mmap 2 multiple' '--no-mmap -f foo 0x8 2 0x1234 0x5678 && od -t x foo' '0000000 00000000 00000000 56781234 00000000\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
+NOSPACE=1 testcmd 'write --no-mmap 4 multiple' '--no-mmap -f foo 0x8 4 0x12345678 0xabcdef01 && od -t x foo' '0000000 00000000 00000000 12345678 abcdef01\n0000020 00000000 00000000 00000000 00000000\n0000040\n' '' ''
+NOSPACE=1 testcmd 'write --no-mmap 8 multiple' '--no-mmap -f foo 0x8 8 0x12345678abcdef01 0x1122334455667788 && od -t x foo' '0000000 00000000 00000000 abcdef01 12345678\n0000020 55667788 11223344 00000000 00000000\n0000040\n' '' ''
diff --git a/tests/files/blkid/fat32.bz2 b/tests/files/blkid/fat32.bz2
new file mode 100644
index 00000000..81eebc7d
Binary files /dev/null and b/tests/files/blkid/fat32.bz2 differ
diff --git a/tests/grep.test b/tests/grep.test
index 64ca105b..7d0aac97 100755
--- a/tests/grep.test
+++ b/tests/grep.test
@@ -245,3 +245,9 @@ testcmd 'grep -of' '-of input' 'abc\n' 'a.c\n' 'abcdef\n'
 
 testcmd '-A with -m' '-A1 -m2 match' 'match\n1\nmatch\n2\n' '' \
   'match\n1\nmatch\n2\nmatch\n3\n'
+
+mkdir sub
+mkfifo -m 600 sub/blah
+echo found > sub/found
+testcmd "don't block on FIFO" '-rh found sub && echo done' 'found\ndone\n' '' ''
+rm -rf sub
diff --git a/tests/sh.test b/tests/sh.test
index 14dff84d..27555c7a 100644
--- a/tests/sh.test
+++ b/tests/sh.test
@@ -14,6 +14,7 @@
 # insulate shell child process to get predictable results
 SS="env -i PATH=${PATH@Q} PS1='\\$ ' $SH --noediting --noprofile --norc -is"
 
+[ -z "$TEST_HOST" ] && : ${BROKEN=true}
 # Wrap txpect for shell testing
 shxpect() {
   X="$1"
@@ -73,7 +74,7 @@ testing '$LINENO 1' "$SH input" "1\n" 'echo $LINENO' ''
 
 mkdir sub
 echo echo hello > sub/script
-testing 'simple script in $PATH' "PATH='$PWD/sub:$PATH' $SH script" \
+$BROKEN testing 'simple script in $PATH' "PATH='$PWD/sub:$PATH' $SH script" \
   'hello\n' '' ''
 rm -rf sub
 
@@ -118,16 +119,16 @@ testing '<< \' $'cat<<EOF\nabc\\\ndef\nEOF\n' 'abcdef\n' '' ''
 testing '<< "\"' $'cat<<\\EOF\nabc\\\ndef\nEOF\n' 'abc\\\ndef\n' '' ''
 testing '<<""' $'cat<<"";echo hello\npotato\n\necho huh' 'potato\nhello\nhuh\n'\
   '' ''
-testing '<< trailing \' $'cat<<EOF 2>/dev/null\nabcde\nnext\\\nEOF\nEOF' \
+$BROKEN testing '<< trailing \' $'cat<<EOF 2>/dev/null\nabcde\nnext\\\nEOF\nEOF' \
   'abcde\nnextEOF\n' '' ''
-testing '<< trailing \ 2' $'cat<<EOF\nabcde\nEO\\\nF\necho hello' \
+$BROKEN testing '<< trailing \ 2' $'cat<<EOF\nabcde\nEO\\\nF\necho hello' \
   'abcde\nhello\n' '' ''
 testing '<< $(a)' $'cat<<$(a)\nx\n$(a)' 'x\n' '' ''
 testing 'HERE straddle' $'cat<<EOF;if true\nhello\nEOF\nthen echo also; fi' \
   'hello\nalso\n' '' ''
-testing '\\n in <<EOF' $'cat<<EO\\\nF\n$PATH\nEOF\n' "$PATH\n" "" ""
+$BROKEN testing '\\n in <<EOF' $'cat<<EO\\\nF\n$PATH\nEOF\n' "$PATH\n" "" ""
 testing '\\n in <<EOF with ""' $'cat<<EO\\\nF""\n$PATH\nEOF\n' '$PATH\n' '' ''
-testing '\\n in HERE terminator' $'cat<<EOF\nabc\nE\\\nOF\necho hello\n' \
+$BROKEN testing '\\n in HERE terminator' $'cat<<EOF\nabc\nE\\\nOF\necho hello\n' \
   'abc\nhello\n' '' ''
 ln -s "$(which echo)" echo2
 testing "undelimited redirect doesn't eat prefix" './echo2</dev/null hello' \
@@ -152,15 +153,15 @@ shxpect '$_ preserved on exec error' I$'true hello; ${}\n' \
 shxpect '$_ abspath on exec' I$'env | grep ^_=\n' O$'_=/usr/bin/env\n'
 testing '$_ literal after exec' 'env >/dev/null; echo $_' 'env\n' '' ''
 shxpect '$_ no path for builtin' I$'true; echo $_\n' O$'true\n'
-testing 'prefix is local for builtins' 'abc=123; abc=def unset abc; echo $abc' \
+$BROKEN testing 'prefix is local for builtins' 'abc=123; abc=def unset abc; echo $abc' \
   '123\n' '' ''
-testing 'prefix localizes magic vars' \
+$BROKEN testing 'prefix localizes magic vars' \
   'SECONDS=123; SECONDS=345 true; echo $SECONDS' '123\n' '' ''
 shxpect 'body evaluated before variable exports' I$'a=x${} y${}\n' RE'y${}' X1
 testing '$NOTHING clears $_' 'true; $NOTHING; echo $_' '\n' '' ''
 testing 'assignment with redirect is persistent, not prefix' \
   'ABC=DEF > potato && rm potato && echo $ABC' 'DEF\n' '' ''
-testing '$_ with functions' 'true; x(){ echo $_;}; x abc; echo $_' \
+$BROKEN testing '$_ with functions' 'true; x(){ echo $_;}; x abc; echo $_' \
   'true\nabc\n' '' ''
 
 mkdir -p one/two/three
@@ -177,10 +178,10 @@ testing "eval2" "eval 'echo hello'; echo $?" "hello\n0\n" "" ""
 testing "eval3" 'X="echo hello"; eval "$X"' "hello\n" "" ""
 testing "eval4" 'eval printf '=%s=' \" hello \"' "= hello =" "" ""
 NOSPACE=1 testing "eval5" 'eval echo \" hello \" | wc' ' 1 1 8' "" ""
-testing 'eval6' $'false; eval \'echo $?\'' '1\n' '' ''
+$BROKEN testing 'eval6' $'false; eval \'echo $?\'' '1\n' '' ''
 testing 'eval7' $'eval \'false\'; echo $?' '1\n' '' ''
 testing 'eval8' $'false; eval ''; echo $?' '0\n' '' ''
-testing 'eval9' $'A=echo; false; eval \'$A $?\'' '1\n' '' ''
+$BROKEN testing 'eval9' $'A=echo; false; eval \'$A $?\'' '1\n' '' ''
 testing "exec" "exec echo hello" "hello\n" "" ""
 testing "exec2" "exec echo hello; echo $?" "hello\n" "" "" 
 
@@ -260,7 +261,7 @@ testing 'hidden wildcards' \
 testing "backtick1" 'x=fred; echo `echo $x`' 'fred\n' "" ""
 testing "backtick2" 'x=fred; echo `x=y; echo $x`; echo $x' 'y\nfred\n' "" ""
 testing '$(( ) )' 'echo ab$((echo hello) | tr e x)cd' "abhxllocd\n" "" ""
-testing '$((x=y)) lifetime' 'a=boing; echo $a $a$((a=4))$a $a' 'boing boing44 4\n' '' ''
+$BROKEN testing '$((x=y)) lifetime' 'a=boing; echo $a $a$((a=4))$a $a' 'boing boing44 4\n' '' ''
 
 testing 'quote' "echo \"'\"" "'\n" "" ""
 
@@ -279,7 +280,7 @@ testing "predecrement vs prefix minus" 'echo $((---x)); echo $x' '1\n-1\n' '' ''
 testing "minus-minus-minus" 'echo $((x---7)); echo $x' '-7\n-1\n' '' ''
 testing "x---y is x-- -y not x- --y" 'x=1 y=1; echo $((x---y)) $x $y' '0 0 1\n'\
   '' ''
-testing "nesting ? :" \
+$BROKEN testing "nesting ? :" \
   'for((i=0;i<8;i++)); do echo $((i&1?i&2?1:i&4?2:3:4));done' \
   '4\n3\n4\n1\n4\n2\n4\n1\n' '' ''
 testing "inherited assignment suppression" 'echo $((0 ? (x++) : 2)); echo $x' \
@@ -291,10 +292,10 @@ testing "&& vs || priority" \
 testing "|| vs && priority" \
   'echo $((w++&&x++||y++&&z++)) w=$w x=$x y=$y z=$z' \
   '0 w=1 x= y=1 z=\n' '' ''
-shxpect '/0' I$'echo $((1/0)); echo here\n' E E"$P" I$'echo $?\n' O$'1\n'
-shxpect '%0' I$'echo $((1%0)); echo here\n' E E"$P" I$'echo $?\n' O$'1\n'
-shxpect '/=0' I$'echo $((x/=0)); echo here\n' E E"$P" I$'echo $?\n' O$'1\n'
-shxpect '%=0' I$'echo $((x%=0)); echo here\n' E E"$P" I$'echo $?\n' O$'1\n'
+$BROKEN shxpect '/0' I$'echo $((1/0)); echo here\n' E E"$P" I$'echo $?\n' O$'1\n'
+$BROKEN shxpect '%0' I$'echo $((1%0)); echo here\n' E E"$P" I$'echo $?\n' O$'1\n'
+$BROKEN shxpect '/=0' I$'echo $((x/=0)); echo here\n' E E"$P" I$'echo $?\n' O$'1\n'
+$BROKEN shxpect '%=0' I$'echo $((x%=0)); echo here\n' E E"$P" I$'echo $?\n' O$'1\n'
 
 # Loops and flow control
 testing "case" 'for i in A C J B; do case "$i" in A) echo got A ;; B) echo and B ;; C) echo then C ;; *) echo default ;; esac; done' \
@@ -310,7 +311,7 @@ testing 'loop in && ||' \
   'false && for i in a b c; do echo $i; done || echo no' 'no\n' '' ''
 testing "continue" 'for i in a b c; do for j in d e f; do echo $i $j; continue 2; done; done' \
   "a d\nb d\nc d\n" "" ""
-testing "piped loops that don't exit" \
+$BROKEN testing "piped loops that don't exit" \
   'while X=$(($X+1)); do echo $X; done | while read i; do echo $i; done | head -n 5' \
   '1\n2\n3\n4\n5\n' '' ''
 
@@ -328,7 +329,7 @@ testing "leading variable assignment" 'abc=def env | grep ^abc=; echo $abc' \
 testing "leading variable assignments" \
   "abc=def ghi=jkl env | egrep '^(abc|ghi)=' | sort; echo \$abc \$ghi" \
   "abc=def\nghi=jkl\n\n" "" ""
-testing "leading assignment occurs after parsing" \
+$BROKEN testing "leading assignment occurs after parsing" \
   'abc=def; abc=ghi echo $abc' "def\n" "" ""
 testing "leading assignment space" 'X="abc  def"; Y=$X; echo "$Y"' \
   "abc  def\n" "" ""
@@ -351,10 +352,10 @@ testing 'background curly block' \
   'hexxo\nyes\n' '' ''
 rm -f POIT
 
-testing 'background pipe block' \
+$BROKEN testing 'background pipe block' \
   'if true; then { sleep .25;bzcat "$FILES"/blkid/ntfs.bz2; }& fi | wc -c' \
   '8388608\n' '' ''
-testing 'background variable assignment' 'X=x; X=y & echo $X' 'x\n' '' ''
+$BROKEN testing 'background variable assignment' 'X=x; X=y & echo $X' 'x\n' '' ''
 
 #$ IFS=x X=xyxz; for i in abc${X}def; do echo =$i=; done
 #=abc=
@@ -384,7 +385,7 @@ testing "curly bracket whitespace" 'for i in {$,} ""{$,}; do echo ="$i"=; done'\
   '=$=\n=$=\n==\n' '' ''
 
 testing 'empty $! is blank' 'echo $!' "\n" "" ""
-testing '$! = jobs -p' 'true & [ $(jobs -p) = $! ] && echo yes' "yes\n" "" ""
+$BROKEN testing '$! = jobs -p' 'true & [ $(jobs -p) = $! ] && echo yes' "yes\n" "" ""
 
 testing '$*' 'cc(){ for i in $*;do echo =$i=;done;};cc "" "" "" "" ""' \
   "" "" ""
@@ -392,7 +393,7 @@ testing '$*2' 'cc(){ for i in "$*";do echo =$i=;done;};cc ""' \
   "==\n" "" ""
 testing '$*3... Flame. Flames. Flames, on the side of my face...' \
   'cc(){ for i in "$*";do echo =$i=;done;};cc "" ""' "= =\n" "" ""
-testing 'why... oh.' \
+$BROKEN testing 'why... oh.' \
   'cc() { echo ="$*"=; for i in =$*=; do echo -$i-; done;}; cc "" ""; echo and; cc ""' \
   '= =\n-=-\n-=-\nand\n==\n-==-\n' "" ""
 testing 'really?' 'cc() { for i in $*; do echo -$i-; done;}; cc "" "" ""' \
@@ -411,7 +412,7 @@ testing '$@' 'cc(){ for i in "$@";do echo =$i=;done;};cc "" "" "" "" ""' \
   "==\n==\n==\n==\n==\n" "" ""
 testing "IFS10" 'IFS=bcd; A=abcde; for i in $A; do echo =$i=; done' \
   "=a=\n==\n==\n=e=\n" "" ""
-testing "IFS11" \
+$BROKEN testing "IFS11" \
   'IFS=x; chicken() { for i in $@$@; do echo =$i=; done;}; chicken one "" abc dxf ghi' \
   "=one=\n==\n=abc=\n=d=\n=f=\n=ghione=\n==\n=abc=\n=d=\n=f=\n=ghi=\n" "" ""
 testing "IFS12" 'IFS=3;chicken(){ return 3;}; chicken;echo 3$?3' '3 3\n' "" ""
@@ -420,7 +421,7 @@ testing "IFS combinations" \
   'IFS=" x"; A=" x " B=" x" C="x " D=x E="   "; for i in $A $B $C $D L$A L$B L$C L$D $A= $B= $C= $D= L$A= L$B= L$C= L$D=; do echo -n {$i}; done' \
   "{}{}{}{}{L}{L}{L}{L}{}{=}{}{=}{}{=}{}{=}{L}{=}{L}{=}{L}{=}{L}{=}" "" ""
 
-testing "! isn't special" "echo !" "!\n" "" ""
+$BROKEN testing "! isn't special" "echo !" "!\n" "" ""
 testing "! by itself" '!; echo $?' "1\n" "" ""
 testing "! true" '! true; echo $?' "1\n" "" ""
 testing "! ! true" '! ! true; echo $?' "0\n" "" ""
@@ -463,19 +464,19 @@ NOSPACE=1 testing "curly brackets and pipe" \
 NOSPACE=1 testing "parentheses and pipe" \
   '(echo two;echo three)|tee blah.txt;wc blah.txt' \
   "two\nthree\n2 2 10 blah.txt\n" "" ""
-testing "pipe into parentheses" \
+$BROKEN testing "pipe into parentheses" \
   'echo hello | (read i <input; echo $i; read i; echo $i)' \
   "there\nhello\n" "there\n" ""
 
-testing "\$''" $'echo $\'abc\\\'def\\nghi\'' "abc'def\nghi\n" '' ''
+$BROKEN testing "\$''" $'echo $\'abc\\\'def\\nghi\'' "abc'def\nghi\n" '' ''
 testing "shift shift" 'shift; shift; shift; echo $? hello' "1 hello\n" "" ""
 testing 'search cross $*' 'chicken() { echo ${*/b c/ghi}; }; chicken a b c d' \
   "a b c d\n" "" ""
 testing 'eval $IFS' 'IFS=x; X=x; eval abc=a${X}b 2>/dev/null; echo $abc' \
   "\n" '' ''
-testing '${@:3:5}' 'chicken() { for i in "${@:3:5}"; do echo =$i=; done; } ; chicken ab cd ef gh ij kl mn op qr' \
+$BROKEN testing '${@:3:5}' 'chicken() { for i in "${@:3:5}"; do echo =$i=; done; } ; chicken ab cd ef gh ij kl mn op qr' \
   '=ef=\n=gh=\n=ij=\n=kl=\n=mn=\n' '' ''
-testing '${@:3:5}' 'chicken() { for i in "${*:3:5}"; do unset IFS; echo =$i=; done; } ; IFS=x chicken ab cd ef gh ij kl mn op qr' \
+$BROKEN testing '${*:3:5}' 'chicken() { for i in "${*:3:5}"; do unset IFS; echo =$i=; done; } ; IFS=x chicken ab cd ef gh ij kl mn op qr' \
   '=efxghxijxklxmn=\n' '' ''
 testing 'sequence check' 'IFS=x; X=abxcd; echo ${X/bxc/g}' 'agd\n' '' ''
 
@@ -500,7 +501,7 @@ testing 'here5' $'cat << EOF && cat << EOF2\nEOF2\nEOF\nEOF\nEOF2' \
 # Nothing is actually quoted, but there are quotes, therefore...
 testing 'here6' $'cat << EOF""\n$POTATO\nEOF' '$POTATO\n' '' ''
 # Not ambiguous when split, unlike <$FILENAME redirects
-testing 'here7' 'ABC="abc def"; cat <<< $ABC' 'abc def\n' '' ''
+$BROKEN testing 'here7' 'ABC="abc def"; cat <<< $ABC' 'abc def\n' '' ''
 # What does HERE expansion _not_ expand?
 testing 'here8' $'ABC="x y"\ncat << EOF\n~root/{"$ABC",def}\nEOF' \
   '~root/{"x y",def}\n' '' ''
@@ -510,37 +511,37 @@ testing '<<- eats leading tabs before expansion, but not after' \
 testing '${var}' 'X=abcdef; echo ${X}' 'abcdef\n' '' '' 
 testing '${#}' 'X=abcdef; echo ${#X}' "6\n" "" ""
 testing 'empty ${}' '{ echo ${};} 2>&1 | grep -o bad' 'bad\n' '' ''
-shxpect 'empty ${} syntax err abort' I$'echo ${}; echo hello\n' \
+$BROKEN shxpect 'empty ${} syntax err abort' I$'echo ${}; echo hello\n' \
   E I$'echo and\n' O$'and\n'
-testing '${$b}' '{ echo ${$b};} 2>&1 | grep -o bad' 'bad\n' '' ''
+$BROKEN testing '${$b}' '{ echo ${$b};} 2>&1 | grep -o bad' 'bad\n' '' ''
 testing '${!PATH*}' 'echo ${!PATH*}' 'PATH\n' '' ''
 testing '${!PATH@}' 'echo ${!PATH@}' 'PATH\n' '' ''
 #testing '${!PATH[@]}' 'echo ${!PATH[@]}' '0\n' '' ''
 testing '${!x}' 'X=abcdef Y=X; echo ${!Y}' 'abcdef\n' '' ''
 testing '${!x@}' 'ABC=def; def=ghi; echo ${!ABC@}' 'ABC\n' '' ''
-testing '${!x} err' '{ X=abcdef Y=X:2; echo ${!Y}; echo bang;} 2>/dev/null' \
+$BROKEN testing '${!x} err' '{ X=abcdef Y=X:2; echo ${!Y}; echo bang;} 2>/dev/null' \
   '' '' ''
 testing '${!x*}' 'abcdef=1 abc=2 abcq=; echo "${!abc@}" | tr " " \\n | sort' \
   'abc\nabcdef\nabcq\n' '' ''
 testing '${!x*} none' 'echo "${!abc*}"' '\n' '' ''
-testing '${!x*} err' '{ echo "${!abc*x}"; echo boing;} 2>/dev/null' '' '' ''
+$BROKEN testing '${!x*} err' '{ echo "${!abc*x}"; echo boing;} 2>/dev/null' '' '' ''
 # TODO bash 5.x broke this
 #testing '${!none@Q}' 'echo ${X@Q} ${!X@Q}; X=ABC; echo ${!X@Q}' '\n\n' '' ''
-testing '${!x@Q}' 'ABC=123 X=ABC; echo ${!X@Q}' "'123'\n" '' ''
-testing '${#@Q}' 'echo ${#@Q}' "'0'\n" '' ''
-testing '${!*}' 'xx() { echo ${!*};}; fruit=123; xx fruit' '123\n' '' ''
-testing '${!*} indirect' 'xx() { echo ${!a@Q};}; a=@; xx one two three' \
+$BROKEN testing '${!x@Q}' 'ABC=123 X=ABC; echo ${!X@Q}' "'123'\n" '' ''
+$BROKEN testing '${#@Q}' 'echo ${#@Q}' "'0'\n" '' ''
+$BROKEN testing '${!*}' 'xx() { echo ${!*};}; fruit=123; xx fruit' '123\n' '' ''
+$BROKEN testing '${!*} indirect' 'xx() { echo ${!a@Q};}; a=@; xx one two three' \
   "'one' 'two' 'three'\n" '' ''
-testing '${!x@ } match' \
+$BROKEN testing '${!x@ } match' \
   '{ ABC=def; def=ghi; echo ${!ABC@ }; } 2>&1 | grep -o bad' 'bad\n' '' ''
 # Bash added an error for this between 4.4 and 5.x.
 #testing '${!x@ } no match no err' 'echo ${!ABC@ }def' 'def\n' '' ''
-testing '${!x@ } no match no err2' 'ABC=def; echo ${!ABC@ }ghi' 'ghi\n' '' ''
+$BROKEN testing '${!x@ } no match no err2' 'ABC=def; echo ${!ABC@ }ghi' 'ghi\n' '' ''
 toyonly testing '${#x::}' 'ABC=abcdefghijklmno; echo ${#ABC:1:2}' '5\n' '' ''
 # TODO: ${!abc@x} does _not_ error? And ${PWD@q}
 testing '$""' 'ABC=def; echo $"$ABC"' 'def\n' '' ''
 testing '"$""" does not nest' 'echo "$"abc""' '$abc\n' '' ''
-testing '${\}}' 'ABC=ab}cd; echo ${ABC/\}/x}' 'abxcd\n' '' ''
+$BROKEN testing '${\}}' 'ABC=ab}cd; echo ${ABC/\}/x}' 'abxcd\n' '' ''
 testing 'bad ${^}' '{ echo ${^};} 2>&1 | grep -o bad' 'bad\n' '' ''
 shxpect '${:} empty len is err' I$'ABC=def; echo ${ABC:}\n' RE'ABC' X
 testing '${::} both empty=0' 'ABC=def; echo ${ABC::}' '\n' '' ''
@@ -548,7 +549,7 @@ testing '${::} first empty' 'ABC=def; echo ${ABC: : 2 }' 'de\n' '' ''
 testing '${::} second empty' 'ABC=def; echo ${ABC: 2 : }' '\n' '' ''
 testing '${:}' 'ABC=def; echo ${ABC:1}' 'ef\n' '' ''
 testing '${a: }' 'ABC=def; echo ${ABC: 1}' 'ef\n' '' ''
-testing '${a :}' 'ABC=def; { echo ${ABC :1};} 2>&1 | grep -o bad' 'bad\n' '' ''
+$BROKEN testing '${a :}' 'ABC=def; { echo ${ABC :1};} 2>&1 | grep -o bad' 'bad\n' '' ''
 testing '${::}' 'ABC=defghi; echo ${ABC:1:2}' 'ef\n' '' ''
 testing '${: : }' 'ABC=defghi; echo ${ABC: 1 : 2 }' 'ef\n' '' ''
 testing '${::} indirect' \
@@ -560,7 +561,7 @@ testing '${:-:-}2' 'echo ${ABC:-3:2}' '3:2\n' '' ''
 testing '${: -:}' 'ABC=defghi; echo ${ABC: -3:2}' 'gh\n' '' ''
 testing '${@%}' 'chicken() { for i in "${@%abc}"; do echo "=$i="; done;}; chicken 1abc 2abc 3abc' '=1=\n=2=\n=3=\n' '' ''
 testing '${*%}' 'chicken() { for i in "${*%abc}"; do echo "=$i="; done;}; chicken 1abc 2abc 3abc' '=1 2 3=\n' '' ''
-testing '${@@Q}' 'xx() { echo "${@@Q}"; }; xx one two three' \
+$BROKEN testing '${@@Q}' 'xx() { echo "${@@Q}"; }; xx one two three' \
   "'one' 'two' 'three'\n" '' ''
 
 shxpect '${/newline/}' I$'x=$\'\na\';echo ${x/\n' E'> ' I$'/b}\n' O$'ba\n' E'> '
@@ -570,25 +571,25 @@ shxpect 'line continuation' I$'echo "hello" \\\n' E'> ' I$'> blah\n' E"$P" \
 shxpect 'line continuation2' I$'echo ABC\\\n' E'> ' I$'DEF\n' O$'ABCDEF\n'
 testing "line continuation3" $'ec\\\nho hello' 'hello\n' '' ''
 testing "line continuation4" $'if true | \\\n(true);then echo true;fi' 'true\n' '' ''
-testing "line continuation5" $'XYZ=xyz; echo "abc$\\\nXYZ"' 'abcxyz\n' '' ''
+$BROKEN testing "line continuation5" $'XYZ=xyz; echo "abc$\\\nXYZ"' 'abcxyz\n' '' ''
 
 # Race condition (in bash, but not in toysh) can say 43.
-testing 'SECONDS' 'readonly SECONDS=41; sleep 1; echo $SECONDS' '42\n' '' ''
+$BROKEN testing 'SECONDS' 'readonly SECONDS=41; sleep 1; echo $SECONDS' '42\n' '' ''
 # testing 'SECONDS2' 'readonly SECONDS; SECONDS=0; echo $SECONDS' '' '' '' #bash!
-testing 'SECONDS2' 'SECONDS=123+456; echo $SECONDS' '0\n' '' '' #bash!!
-testing '$LINENO 2' $'echo $LINENO\necho $LINENO' '0\n1\n' '' ''
+$BROKEN testing 'SECONDS2' 'SECONDS=123+456; echo $SECONDS' '0\n' '' '' #bash!!
+testing '$LINENO 2' $'echo $LINENO\necho $LINENO' '1\n2\n' '' ''
 testing '$EUID' 'echo $EUID' "$(id -u)\n" '' ''
 testing '$UID' 'echo $UID' "$(id -ur)\n" '' ''
 
-testing 'readonly leading assignment' \
+$BROKEN testing 'readonly leading assignment' \
   '{ readonly abc=123;abc=def echo hello; echo $?;} 2>output; grep -o readonly output' \
   'hello\n0\nreadonly\n' '' ''
-testing 'readonly leading assignment2' \
+$BROKEN testing 'readonly leading assignment2' \
   'readonly boink=123; export boink; { boink=234 env | grep ^boink=;} 2>/dev/null; echo $?' 'boink=123\n0\n' '' ''
-testing 'readonly for' \
+$BROKEN testing 'readonly for' \
   'readonly i; for i in one two three; do echo $i; done 2>/dev/null; echo $?' \
   '1\n' '' ''
-testing 'readonly {}<' \
+$BROKEN testing 'readonly {}<' \
   'readonly i; echo hello 2>/dev/null {i}</dev/null; echo $?' '1\n' '' ''
 testing '$_ 1' 'echo walrus; echo $_' 'walrus\nwalrus\n' '' ''
 testing '$_ 2' 'unset _; echo $_' '_\n' '' ''
@@ -603,17 +604,17 @@ rm -f walrus wallpapers
 
 # Force parsing granularity via interactive shxpect because bash parses all
 # of sh -c "str" in one go, meaning the "shopt -s extglob" won't take effect
-shxpect 'IFS +(extglob)' I$'shopt -s extglob\n' E"$P" \
+$BROKEN shxpect 'IFS +(extglob)' I$'shopt -s extglob\n' E"$P" \
   I$'IFS=x; ABC=cxd; for i in +($ABC); do echo =$i=; done\n' \
   O$'=+(c=\n' O$'=d)=\n'
 
 touch abc\)d
-shxpect 'IFS +(extglob) 2' I$'shopt -s extglob\n' E"$P" \
+$BROKEN shxpect 'IFS +(extglob) 2' I$'shopt -s extglob\n' E"$P" \
   I$'ABC="c?d"; for i in ab+($ABC); do echo =$i=; done\n' \
   O$'=abc)d=\n'
 rm abc\)d
 
-shxpect '[+(]) overlap priority' I$'shopt -s extglob\n' E"$P" \
+$BROKEN shxpect '[+(]) overlap priority' I$'shopt -s extglob\n' E"$P" \
   I$'touch "AB[DEF]"; echo AB[+(DEF]) AB[+(DEF)? AB+([DEF)]\n' \
   O$'AB[+(DEF]) AB[DEF] AB+([DEF)]\n' \
   I$'X="("; Y=")"; echo AB[+${X}DEF${Y}?\n' O$'AB[DEF]\n'
@@ -622,7 +623,7 @@ shxpect '[+(]) overlap priority' I$'shopt -s extglob\n' E"$P" \
 shxpect '${a?b} sets err, stops cmdline eval' \
   I$': ${a?b} ${c:=d}\n' E E"$P" I$'echo $?$c\n' O$'1\n'
 
-shxpect 'trace redirect' I$'set -x; echo one\n' E$'+ echo one\n'"$P" O$'one\n' \
+$BROKEN shxpect 'trace redirect' I$'set -x; echo one\n' E$'+ echo one\n'"$P" O$'one\n' \
   I$'echo two 2>/dev/null\n' O$'two\n' E$'+ echo two\n'"$P" \
   I$'{ echo three; } 2>/dev/null\n' O$'three\n' E"$P"
 shxpect 'set -u' I$'set -u; echo $walrus\n' REwalrus X
@@ -642,17 +643,17 @@ testing 'source is live in functions' \
 testing 'subshell inheritance' \
   'func() { source input; cat <(echo $xx; xx=456; echo $xx); echo $xx;}; echo local xx=123 > input; func; echo $xx' \
   '123\n456\n123\n\n' 'x' ''
-testing 'semicolon vs newline' \
+$BROKEN testing 'semicolon vs newline' \
   'source input 2>/dev/null || echo yes' 'one\nyes\n' \
   'echo one\necho two; echo |' ''
-testing 'syntax err pops to source but encapsulating function continues' \
+$BROKEN testing 'syntax err pops to source but encapsulating function continues' \
   'func() { echo one; source <(echo -e "echo hello\necho |") 2>/dev/null; echo three;}; func; echo four' \
   'one\nhello\nthree\nfour\n' '' ''
-testing '"exit shell" means exit eval but encapsulating function continues' \
+$BROKEN testing '"exit shell" means exit eval but encapsulating function continues' \
   'func() { eval "echo one; echo \${?potato}; echo and" 2>/dev/null; echo plus;}; func; echo then' \
   'one\nplus\nthen\n' '' ''
-testing 'return needs function or source' \
-  'cat <(return 0 2>/dev/null; echo $?); echo after' '1\nafter\n' '' ''
+$BROKEN testing 'return needs function or source' \
+  'cat <(return 0 2>/dev/null; echo $?); echo after' '2\nafter\n' '' ''
 testing 'return nests' 'y(){ x; return $((3+$?));};x(){ return 5; };y;echo $?' \
   '8\n' '' ''
 
@@ -679,26 +680,26 @@ testing 'local replaces/preserves magic type' \
   'x() { local RANDOM=potato; echo $RANDOM;};x;echo -e "$RANDOM\n$RANDOM"|wc -l'\
   'potato\n2\n' '' ''
 
-testing '$$ is parent shell' \
+$BROKEN testing '$$ is parent shell' \
   '{ echo $$; (echo $$) } | sort -u | wc -l' "1\n" "" ""
-testing '$PPID is parent shell' \
+$BROKEN testing '$PPID is parent shell' \
   '{ echo $PPID; (echo $PPID) } | sort -u | wc -l' "1\n" "" ""
-testing '$BASHPID is current PID' \
+$BROKEN testing '$BASHPID is current PID' \
   '{ echo $BASHPID; (echo $BASHPID) } | sort -u | wc -l' "2\n" "" ""
 
 testing 'unexport supports +=' 'export -n ABC+=DEF; declare -p ABC' \
   'declare -- ABC="DEF"\n' '' ''
-testing 'unexport existing +=' \
+$BROKEN testing 'unexport existing +=' \
   'export ABC=XYZ; export -n ABC+=DEF; declare -p ABC' \
   'declare -- ABC="XYZDEF"\n' '' ''
 
-testing '$!' '{ echo $BASHPID & echo $!; echo ${!};} | sort -u | wc -l' '1\n' \
+$BROKEN testing '$!' '{ echo $BASHPID & echo $!; echo ${!};} | sort -u | wc -l' '1\n' \
   '' ''
 
 shxpect 'blank line preserves $?' \
   I$'false\n' E"$P" I$'\n' E"$P" I$'echo $?\n' O$'1\n'
 testing 'NOP line clears $?' 'false;$NOTHING;echo $?' '0\n' '' ''
-testing 'run "$@"' 'false;"$@";echo $?' '0\n' '' ''
+$BROKEN testing 'run "$@"' 'false;"$@";echo $?' '0\n' '' ''
 
 # "Word splitting... not performed on the words between the [[ and ]]"
 testing '[[split1]]' 'A="1 -lt 2"; [[ $A ]] && echo yes' 'yes\n' '' ''
@@ -710,7 +711,7 @@ rm -f '2 -lt 1'
 testing '[[split4]]' \
   '[[ $(cat) == "a b" ]] <<< "a b" > potato && rm potato && echo ok' \
   'ok\n' '' ''
-testing '[[split5]]' \
+$BROKEN testing '[[split5]]' \
   '[[ $(cat) == "a b" ]] < <(echo a b) > potato && rm potato && echo ok' \
   'ok\n' '' ''
 # And token parsing leaking through: 1>2 is an error, 1 >2 is not
@@ -722,9 +723,12 @@ testing '[[1<2]] is alphabetical, not numeric' '[[ 123 < 19 ]] && echo yes' \
   'yes\n' '' ''
 testing '[[~]]' '[[ ~ == $HOME ]] && echo yes' 'yes\n' '' ''
 
+# The trailing space is because the \n gets stripped off otherwise
 testing 'quoting contexts nest' \
-        $'echo -n "$(echo "hello $(eval $\'echo -\\\\\\ne \\\'world\\n \\\'\')")"' \
+  $'echo -n "$(echo "hello $(eval $\'echo -\\\\\\ne \\\'world\\n \\\'\')")"' \
   'hello world\n ' '' ''
+testing "\$'' suppresses variable expansion" \
+  $'echo $\'$(abc\'' '$(abc\n' '' ''
 
 testing 'if; is a syntax error but if $EMPTY; is not' \
   'if $NONE; then echo hello; fi' 'hello\n' '' ''
diff --git a/toys/lsb/mount.c b/toys/lsb/mount.c
index ff0b7e12..84d82e2a 100644
--- a/toys/lsb/mount.c
+++ b/toys/lsb/mount.c
@@ -37,7 +37,8 @@ config MOUNT
     Autodetects loopback mounts (a file on a directory) and bind mounts (file
     on file, directory on directory), so you don't need to say --bind or --loop.
     You can also "mount -a /path" to mount everything in /etc/fstab under /path,
-    even if it's noauto. DEVICE starting with UUID= is identified by blkid -U.
+    even if it's noauto. DEVICE starting with UUID= is identified by blkid -U,
+    and DEVICE starting with LABEL= is identified by blkid -L.
 
 #config SMBMOUNT
 #  bool "smbmount"
@@ -171,6 +172,12 @@ static void mount_filesystem(char *dev, char *dir, char *type,
     if (!s || strlen(s)>=sizeof(toybuf)) return error_msg("No uuid %s", dev);
     strcpy(dev = toybuf, s);
     free(s);
+  } else if (strstart(&dev, "LABEL=")) {
+    char *s = chomp(xrunread((char *[]){"blkid", "-L", dev, 0}, 0));
+
+    if (!s || strlen(s)>=sizeof(toybuf)) return error_msg("No label %s", dev);
+    strcpy(dev = toybuf, s);
+    free(s);
   }
 
   // Autodetect bind mount or filesystem type
diff --git a/toys/net/host.c b/toys/net/host.c
index 1d06159f..6ead0286 100644
--- a/toys/net/host.c
+++ b/toys/net/host.c
@@ -105,7 +105,7 @@ void host_main(void)
     }
     if (i == ARRAY_LEN(rrt)) error_exit("bad -t: %s", TT.t);
   }
-  qlen = res_mkquery(0, name, 1, type, 0, 0, 0, t2, 280); //t2len);
+  qlen = res_mkquery(0, name, 1, type, 0, 0, 0, t2, t2len);
   if (qlen<0) error_exit("bad NAME: %s", name);
 
   // Grab nameservers
@@ -122,9 +122,10 @@ void host_main(void)
     setsockopt(i, SOL_SOCKET, SO_RCVTIMEO, &(struct timeval){ .tv_sec = 5 },
       sizeof(struct timeval));
     send(i, t2, qlen, 0);
-    if (16 < (alen = recv(i, abuf, abuf_len, 0))) break;
-    if (!*++TT.nsname) error_exit("Host not found.");
+    alen = recv(i, abuf, abuf_len, 0);
     close(i);
+    if (16<alen) break;
+    if (!*++TT.nsname) error_exit("Host not found.");
   }
 
   // Did it error?
@@ -136,19 +137,20 @@ void host_main(void)
   if (rcode) error_exit("Host not found: %s",
     (char *[]){ "Format error", "Server failure",
     "Non-existant domain", "Not implemented", "Refused", ""}[rcode-1]);
+  if (abuf[2]&2) puts("Truncated");
 
   // Print the result
   p = abuf + 12;
   qlen = 0;
   for (sec = 0; sec<(2<<verbose); sec++) {
     count = peek_be(abuf+4+2*sec, 2);
-    if (verbose && count>0 && sec>1)
+    if (verbose && count && sec>1)
       puts(sec==2 ? "For authoritative answers, see:"
         : "Additional information:");
 
     for (; count--; p += pllen) {
-      p += xdn_expand(abuf, abuf+alen, p, toybuf, 4096-t2len);
-      if (alen-(p-abuf)<10) error_exit("tilt");
+      p += xdn_expand(abuf, abuf+alen, p, toybuf, sizeof(toybuf)-t2len);
+      if (alen-(p-abuf)<10) error_exit("bad header");
       type = peek_be(p, 2);
       p += 4;
       if (!sec) continue;
@@ -156,13 +158,14 @@ void host_main(void)
       p += 4;
       pllen = peek_be(p, 2);
       p += 2;
-      if ((p-abuf)+pllen>alen) error_exit("tilt");
+      if ((p-abuf)+pllen>alen) error_exit("bad header");
       if (type==1 || type == 28)
         inet_ntop(type==1 ? AF_INET : AF_INET6, p, t2, t2len);
       else if (type==2 || type==5) xdn_expand(abuf, abuf+alen, p, t2, t2len);
-      else if (type==13 || type==16)
+      else if (type==13 || type==16) {
+        if (pllen && pllen-1==*p) p++, pllen--;
         sprintf(t2, "\"%.*s\"", minof(pllen, t2len), p);
-      else if (type==6) {
+      } else if (type==6) {
         ss = p+xdn_expand(abuf, abuf+alen, p, t2, t2len-1);
         j = strlen(t2);
         t2[j++] = ' ';
diff --git a/toys/other/blkid.c b/toys/other/blkid.c
index f6502e7c..5a5726e9 100644
--- a/toys/other/blkid.c
+++ b/toys/other/blkid.c
@@ -168,7 +168,8 @@ static void do_blkid(int fd, char *name)
   if (!FLAG(U) && len) {
     s = toybuf+fstypes[i].label_off-off;
     if (!strcmp(type, "vfat") || !strcmp(type, "iso9660")) {
-      if (*type=='v') show_tag("SEC_TYPE", "msdos");
+      if (*type=='v' && fstypes[i].magic_len==4 && !FLAG(L))
+        show_tag("SEC_TYPE", "msdos");
       while (len && s[len-1]==' ') len--;
       if (strstart(&s, "NO NAME")) len=0;
     }
diff --git a/toys/other/devmem.c b/toys/other/devmem.c
index 9f9a9e03..90c25060 100644
--- a/toys/other/devmem.c
+++ b/toys/other/devmem.c
@@ -2,7 +2,7 @@
  *
  * Copyright 2019 The Android Open Source Project
 
-USE_DEVMEM(NEWTOY(devmem, "<1(no-sync)f:", TOYFLAG_USR|TOYFLAG_SBIN))
+USE_DEVMEM(NEWTOY(devmem, "<1(no-sync)(no-mmap)f:", TOYFLAG_USR|TOYFLAG_SBIN))
 
 config DEVMEM
   bool "devmem"
@@ -15,6 +15,7 @@ config DEVMEM
 
     -f FILE		File to operate on (default /dev/mem)
     --no-sync	Don't open the file with O_SYNC (for cached access)
+    --no-mmap	Don't mmap the file
 */
 
 #define FOR_devmem
@@ -41,53 +42,63 @@ unsigned long xatolu(char *str, int bytes)
 
 void devmem_main(void)
 {
-  int writing = toys.optc > 2, page_size = sysconf(_SC_PAGESIZE), bytes = 4, fd,
-    flags;
-  unsigned long data = 0, map_off, map_len,
+  int ii, writing = toys.optc > 2, bytes = 4, fd;
+  unsigned long data QUIET, map_len QUIET,
     addr = xatolu(*toys.optargs, sizeof(long));
-  char *sizes = sizeof(long)==8 ? "1248" : "124";
-  void *map, *p;
+  void *map QUIET, *p QUIET;
 
   // WIDTH?
   if (toys.optc>1) {
-    int i;
+    char *sizes = sizeof(long)==8 ? "1248" : "124";
 
-    if ((i=stridx(sizes, *toys.optargs[1]))==-1 || toys.optargs[1][1])
+    if ((ii = stridx(sizes, *toys.optargs[1]))==-1 || toys.optargs[1][1])
       error_exit("bad width: %s", toys.optargs[1]);
-    bytes = 1<<i;
+    bytes = 1<<ii;
   }
 
   // Map in just enough.
   if (CFG_TOYBOX_FORK) {
-    flags = writing ? O_RDWR : O_RDONLY;
-    if (!FLAG(no_sync)) flags |= O_SYNC;
-    fd = xopen(TT.f ?: "/dev/mem", flags);
-    map_off = addr & ~(page_size - 1ULL);
-    map_len = (addr+bytes-map_off);
-    map = xmmap(0, map_len, writing ? PROT_WRITE : PROT_READ, MAP_SHARED, fd,
-        map_off);
-    p = map + (addr & (page_size - 1));
-    close(fd);
+    fd = xopen(TT.f ? : "/dev/mem", O_RDWR*writing+O_SYNC*!FLAG(no_sync));
+    if (FLAG(no_mmap)) xlseek(fd, addr, SEEK_SET);
+    else {
+      unsigned long long page_size = sysconf(_SC_PAGESIZE)-1, map_off;
+
+      map_off = addr & ~page_size;
+      map_len = addr + (writing ? (toys.optc - 2) * bytes : bytes) - map_off;
+      map = xmmap(0, map_len, writing ? PROT_WRITE : PROT_READ, MAP_SHARED, fd,
+          map_off);
+      p = map+(addr&page_size);
+      close(fd);
+    }
   } else p = (void *)addr;
 
   // Not using peek()/poke() because registers care about size of read/write.
   if (writing) {
-    for (int i = 2; i < toys.optc; i++) {
-      data = xatolu(toys.optargs[i], bytes);
-      if (bytes==1) *(char *)p = data;
-      else if (bytes==2) *(unsigned short *)p = data;
-      else if (bytes==4) *(unsigned int *)p = data;
-      else if (sizeof(long)==8 && bytes==8) *(unsigned long *)p = data;
-      p += bytes;
+    for (ii = 2; ii<toys.optc; ii++) {
+      data = xatolu(toys.optargs[ii], bytes);
+      if (FLAG(no_mmap)) xwrite(fd, &data, bytes);
+      else {
+        if (bytes==1) *(char *)p = data;
+        else if (bytes==2) *(unsigned short *)p = data;
+        else if (bytes==4) *(unsigned int *)p = data;
+        else if (sizeof(long)==8 && bytes==8) *(unsigned long *)p = data;
+        p += bytes;
+      }
     }
   } else {
-    if (bytes==1) data = *(char *)p;
-    else if (bytes==2) data = *(unsigned short *)p;
-    else if (bytes==4) data = *(unsigned int *)p;
-    else if (sizeof(long)==8 && bytes==8) data = *(unsigned long *)p;
+    if (FLAG(no_mmap)) xread(fd, &data, bytes);
+    else {
+      if (bytes==1) data = *(char *)p;
+      else if (bytes==2) data = *(unsigned short *)p;
+      else if (bytes==4) data = *(unsigned int *)p;
+      else if (sizeof(long)==8 && bytes==8) data = *(unsigned long *)p;
+    }
     printf((!strchr(*toys.optargs, 'x')) ? "%0*ld\n" : "0x%0*lx\n",
       bytes*2, data);
   }
 
-  if (CFG_TOYBOX_FORK) munmap(map, map_len);
+  if (CFG_TOYBOX_FORK) {
+    if (FLAG(no_mmap)) close(fd);
+    else munmap(map, map_len);
+  }
 }
diff --git a/toys/other/lsusb.c b/toys/other/lsusb.c
index bf0f13f8..3abbe47b 100644
--- a/toys/other/lsusb.c
+++ b/toys/other/lsusb.c
@@ -110,7 +110,7 @@ static void get_names(struct dev_ids *ids, int id1, int id2,
 // Search for pci.ids or usb.ids and return parsed structure or NULL
 struct dev_ids *parse_dev_ids(char *name, struct dev_ids **and)
 {
-  char *path = "/etc:/vendor:/usr/share/misc";
+  char *path = "/etc:/vendor:/usr/share/hwdata:/usr/share/misc";
   struct string_list *sl = 0;
   FILE *fp;
   char *s, *ss, *sss;
diff --git a/toys/pending/awk.c b/toys/pending/awk.c
index fd7675ec..cfead8cc 100644
--- a/toys/pending/awk.c
+++ b/toys/pending/awk.c
@@ -3,7 +3,14 @@
  *
  * Copyright 2024 Ray Gardner <raygard@gmail.com>
  *
- * See https://pubs.opengroup.org/onlinepubs/9699919799/utilities/awk.html
+ * See https://pubs.opengroup.org/onlinepubs/9799919799/utilities/awk.html
+ *
+ * Deviations from posix: Don't handle LANG, LC_ALL, etc.
+ *   Accept regex for RS
+ *   Bitwise functions (from gawk): and, or, xor, lshift, rshift
+ *   Attempt to follow tradition (nawk, gawk) where it departs from posix
+ *
+ * TODO: Lazy field splitting; improve performance; more testing/debugging
 
 USE_AWK(NEWTOY(awk, "F:v*f*bc", TOYFLAG_USR|TOYFLAG_BIN|TOYFLAG_LINEBUF))
 
@@ -16,7 +23,7 @@ config AWK
             awk [-F sepstring] -f progfile [-f progfile]... [-v assignment]...
                   [argument...]
       also:
-      -b : use bytes, not characters
+      -b : count bytes, not characters (experimental)
       -c : compile only, do not run
 */
 
@@ -128,15 +135,10 @@ GLOBALS(
     FILE *fp;
     char mode;  // w, a, or r
     char file_or_pipe;  // 1 if file, 0 if pipe
-    char is_tty;
-    char is_std_file;
-    char *recbuf;
-    size_t recbufsize;
-    char *recbuf_multi;
-    size_t recbufsize_multi;
-    char *recbuf_multx;
-    size_t recbufsize_multx;
-    int recoffs, endoffs;
+    char is_tty, is_std_file;
+    char eof;
+    int ro, lim, buflen;
+    char *buf;
   } *zfiles, *cfile, *zstdout;
 )
 
@@ -300,9 +302,6 @@ struct zmap {
 
 #define NO_EXIT_STATUS  (9999987)  // value unlikely to appear in exit stmt
 
-ssize_t getline(char **lineptr, size_t *n, FILE *stream);
-ssize_t getdelim(char ** restrict lineptr, size_t * restrict n, int delimiter, FILE *stream);
-
 
 
 ////////////////////
@@ -750,8 +749,6 @@ static int get_char(void)
     if (TT.scs->line == nl) return EOF;
     if (!TT.scs->fp) {
       progfile_open();
-    // The "  " + 1 is to set p to null string but allow ref to prev char for
-    // "lastchar" test below.
     }
     // Save last char to allow faking final newline.
     int lastchar = (TT.scs->p)[-2];
@@ -989,7 +986,7 @@ static void ascan_opt_div(int div_op_allowed_here)
       TT.scs->toktype = BUILTIN;
       TT.scs->tok = tkbuiltin;
       TT.scs->tokbuiltin = n;
-    } else if ((TT.scs->ch == '(')) {
+    } else if (TT.scs->ch == '(') {
       TT.scs->toktype = USERFUNC;
       TT.scs->tok = tkfunc;
     } else {
@@ -2714,6 +2711,7 @@ static void set_zvalue_str(struct zvalue *v, char *s, size_t size)
 // All changes to NF go through here!
 static void set_nf(int nf)
 {
+  if (nf < 0) FATAL("NF set negative");
   STACK[NF].num = TT.nf_internal = nf;
   STACK[NF].flags = ZF_NUM;
 }
@@ -2737,10 +2735,14 @@ static int splitter(void (*setter)(struct zmap *, int, char *, size_t), struct z
   regex_t *rx;
   regoff_t offs, end;
   int multiline_null_rs = !ENSURE_STR(&STACK[RS])->vst->str[0];
-  if (!IS_RX(zvfs)) to_str(zvfs);
-  char *s0 = s, *fs = IS_STR(zvfs) ? zvfs->vst->str : "";
-  int one_char_fs = utf8cnt(zvfs->vst->str, zvfs->vst->size) == 1;
   int nf = 0, r = 0, eflag = 0;
+  int one_char_fs = 0;
+  char *s0 = s, *fs = "";
+  if (!IS_RX(zvfs)) {
+    to_str(zvfs);
+    fs = zvfs->vst->str;
+    one_char_fs = utf8cnt(zvfs->vst->str, zvfs->vst->size) == 1;
+  }
   // Empty string or empty fs (regex).
   // Need to include !*s b/c empty string, otherwise
   // split("", a, "x") splits to a 1-element (empty element) array
@@ -2751,7 +2753,7 @@ static int splitter(void (*setter)(struct zmap *, int, char *, size_t), struct z
         char cbuf[8];
         unsigned wc;
         int nc = utf8towc(&wc, s, strlen(s));
-        if (nc < 2) FATAL("bad string for split: \"%s\"\n", s0);
+        if (nc < 2) FFATAL("bad string for split: \"%s\"\n", s0);
         s += nc;
         nc = wctoutf8(cbuf, wc);
         setter(m, ++nf, cbuf, nc);
@@ -2766,7 +2768,7 @@ static int splitter(void (*setter)(struct zmap *, int, char *, size_t), struct z
     // rx_find_FS() returns 0 if found. If nonzero, the field will
     // be the rest of the record (all of it if first time through).
     if ((r = rx_find_FS(rx, s, &offs, &end, eflag))) offs = end = strlen(s);
-    else if (setter == set_field && multiline_null_rs && one_char_fs) {
+    if (setter == set_field && multiline_null_rs && one_char_fs) {
       // Contra POSIX, if RS=="" then newline is always also a
       // field separator only if FS is a single char (see gawk manual)
       int k = strcspn(s, "\n");
@@ -2797,6 +2799,10 @@ static void rebuild_field0(void)
 {
   struct zstring *s = FIELD[0].vst;
   int nf = TT.nf_internal;
+  if (!nf) {
+    zvalue_copy(&FIELD[0], &uninit_string_zvalue);
+    return;
+  }
   // uninit value needed for eventual reference to .vst in zstring_release()
   struct zvalue tempv = uninit_zvalue;
   zvalue_copy(&tempv, to_str(&STACK[OFS]));
@@ -3011,7 +3017,7 @@ static struct zfile *new_file(char *fn, FILE *fp, char mode, char file_or_pipe,
 {
   struct zfile *f = xzalloc(sizeof(struct zfile));
   *f = (struct zfile){TT.zfiles, xstrdup(fn), fp, mode, file_or_pipe,
-                isatty(fileno(fp)), is_std_file, 0, 0, 0, 0, 0, 0, 0, 0};
+                isatty(fileno(fp)), is_std_file, 0, 0, 0, 0, 0};
   return TT.zfiles = f;
 }
 
@@ -3046,9 +3052,7 @@ static int close_file(char *fn)
     np = p->next;   // save in case unlinking file (invalidates p->next)
     // Don't close std files -- wrecks print/printf (can be fixed though TODO)
     if ((!p->is_std_file) && (!fn || !strcmp(fn, p->fn))) {
-      xfree(p->recbuf);
-      xfree(p->recbuf_multi);
-      xfree(p->recbuf_multx);
+      xfree(p->buf);
       xfree(p->fn);
       r = (p->fp) ? (p->file_or_pipe ? fclose : pclose)(p->fp) : -1;
       *pp = p->next;
@@ -3292,11 +3296,15 @@ static int next_fp(void)
   char *fn = nextfilearg();
   if (TT.cfile->fp && TT.cfile->fp != stdin) fclose(TT.cfile->fp);
   if ((!fn && !TT.rgl.nfiles && TT.cfile->fp != stdin) || (fn && !strcmp(fn, "-"))) {
+    xfree(TT.cfile->buf);
+    *TT.cfile = (struct zfile){0};
     TT.cfile->fp = stdin;
-    TT.cfile->fn = "<stdin>";
+    TT.cfile->fn = "-";
     zvalue_release_zstring(&STACK[FILENAME]);
-    STACK[FILENAME].vst = new_zstring("<stdin>", 7);
+    STACK[FILENAME].vst = new_zstring("-", 1);
   } else if (fn) {
+    xfree(TT.cfile->buf);
+    *TT.cfile = (struct zfile){0};
     if (!(TT.cfile->fp = fopen(fn, "r"))) FFATAL("can't open %s\n", fn);
     TT.cfile->fn = fn;
     zvalue_copy(&STACK[FILENAME], &TT.rgl.cur_arg);
@@ -3305,107 +3313,123 @@ static int next_fp(void)
     return 0;
   }
   set_num(&STACK[FNR], 0);
-  TT.cfile->recoffs = TT.cfile->endoffs = 0;  // reset record buffer
   TT.cfile->is_tty = isatty(fileno(TT.cfile->fp));
   return 1;
 }
 
-static ssize_t getrec_multiline(struct zfile *zfp)
-{
-  ssize_t k, kk;
-  do {
-    k = getdelim(&zfp->recbuf_multi, &zfp->recbufsize_multi, '\n', zfp->fp);
-  } while (k > 0 && zfp->recbuf_multi[0] == '\n');
-  TT.rgl.recptr = zfp->recbuf_multi;
-  if (k < 0) return k;
-  // k > 0 and recbuf_multi is not only a \n. Prob. ends w/ \n
-  // but may not at EOF (last line w/o newline)
-  for (;;) {
-    kk = getdelim(&zfp->recbuf_multx, &zfp->recbufsize_multx, '\n', zfp->fp);
-    if (kk < 0 || zfp->recbuf_multx[0] == '\n') break;
-    // data is in zfp->recbuf_multi[0..k-1]; append to it
-    if ((size_t)(k + kk + 1) > zfp->recbufsize_multi)
-      zfp->recbuf_multi =
-          xrealloc(zfp->recbuf_multi, zfp->recbufsize_multi = k + kk + 1);
-    memmove(zfp->recbuf_multi + k, zfp->recbuf_multx, kk+1);
-    k += kk;
-  }
-  if (k > 1 && zfp->recbuf_multi[k-1] == '\n') zfp->recbuf_multi[--k] = 0;
-  TT.rgl.recptr = zfp->recbuf_multi;
-  return k;
-}
-
-static int rx_findx(regex_t *rx, char *s, long len, regoff_t *start, regoff_t *end, int eflags)
+static int rx_find_rs(regex_t *rx, char *s, long len,
+                      regoff_t *start, regoff_t *end, int one_byte_rs)
 {
   regmatch_t matches[1];
-  int r = regexec0(rx, s, len, 1, matches, eflags);
-  if (r == REG_NOMATCH) return r;
-  if (r) FATAL("regexec error");  // TODO ? use regerr() to meaningful msg
-  *start = matches[0].rm_so;
-  *end = matches[0].rm_eo;
+  if (one_byte_rs) {
+    char *p = memchr(s, one_byte_rs, len);
+    if (!p) return REG_NOMATCH;
+    *start = p - s;
+    *end = *start + 1;
+  } else {
+    int r = regexec0(rx, s, len, 1, matches, 0);
+    if (r == REG_NOMATCH) return r;
+    if (r) FATAL("regexec error");  // TODO ? use regerr() to meaningful msg
+    *start = matches[0].rm_so;
+    *end = matches[0].rm_eo;
+  }
   return 0;
 }
 
-// get a record; return length, or 0 at EOF
-static ssize_t getrec_f(struct zfile *zfp)
+// get a record; return length, or -1 at EOF
+// Does work for getrec_f() for regular RS or multiline
+static ssize_t getr(struct zfile *zfp, int rs_mode)
 {
-  int r = 0;
-  if (!ENSURE_STR(&STACK[RS])->vst->str[0]) return getrec_multiline(zfp);
-  regex_t rsrx, *rsrxp = &rsrx;
-  // TEMP!! FIXME Need to cache and avoid too-frequent rx compiles
-  rx_zvalue_compile(&rsrxp, &STACK[RS]);
-  regoff_t so = 0, eo = 0;
+  // zfp->buf (initially null) points to record buffer
+  // zfp->buflen -- size of allocated buf
+  // TT.rgl.recptr -- points to where record is being / has been read into
+  // zfp->ro -- offset in buf to record data
+  // zfp->lim -- offset to 1+last byte read in buffer
+  // rs_mode nonzero iff multiline mode; reused for one-byte RS
+
+  regex_t rsrx; // FIXME Need to cache and avoid rx compile on every record?
   long ret = -1;
+  int r = -REG_NOMATCH;   // r cannot have this value after rx_findx() below
+  regoff_t so = 0, eo = 0;
+  size_t m = 0, n = 0;
+
+  xregcomp(&rsrx, rs_mode ? "\n\n+" : fmt_one_char_fs(STACK[RS].vst->str),
+      REG_EXTENDED);
+  rs_mode = strlen(STACK[RS].vst->str) == 1 ? STACK[RS].vst->str[0] : 0;
   for ( ;; ) {
-    if (zfp->recoffs == zfp->endoffs) {
-#define INIT_RECBUF_LEN     8192
-#define RS_LENGTH_MARGIN    (INIT_RECBUF_LEN / 8)
-      if (!zfp->recbuf)
-        zfp->recbuf = xmalloc((zfp->recbufsize = INIT_RECBUF_LEN) + 1);
-      if (zfp->is_tty && !memcmp(STACK[RS].vst->str, "\n", 2)) {
-        zfp->endoffs = 0;
-        if (fgets(zfp->recbuf, zfp->recbufsize, zfp->fp))
-          zfp->endoffs = strlen(zfp->recbuf);
-      } else zfp->endoffs = fread(zfp->recbuf, 1, zfp->recbufsize, zfp->fp);
-      zfp->recoffs = 0;
-      zfp->recbuf[zfp->endoffs] = 0;
-      if (!zfp->endoffs) break;
+    if (zfp->ro == zfp->lim && zfp->eof) break; // EOF & last record; return -1
+
+    // Allocate initial buffer, and expand iff buffer holds one
+    //   possibly (probably) incomplete record.
+    if (zfp->ro == 0 && zfp->lim == zfp->buflen)
+      zfp->buf = xrealloc(zfp->buf,
+          (zfp->buflen = maxof(512, zfp->buflen * 2)) + 1);
+
+    if ((m = zfp->buflen - zfp->lim) && !zfp->eof) {
+      // Read iff space left in buffer
+      if (zfp->is_tty) m = 1;
+      n = fread(zfp->buf + zfp->lim, 1, m, zfp->fp);
+      if (n < m) {
+        if (ferror(zfp->fp)) FFATAL("i/o error %d on %s!", errno, zfp->fn);
+        zfp->eof = 1;
+        if (!n && r == -REG_NOMATCH) break; // catch empty file here
+      }
+      zfp->lim += n;
+      zfp->buf[zfp->lim] = 0;
     }
-    TT.rgl.recptr = zfp->recbuf + zfp->recoffs;
-    r = rx_findx(rsrxp, TT.rgl.recptr, zfp->endoffs - zfp->recoffs, &so, &eo, 0);
+    TT.rgl.recptr = zfp->buf + zfp->ro;
+    r = rx_find_rs(&rsrx, TT.rgl.recptr, zfp->lim - zfp->ro, &so, &eo, rs_mode);
     if (!r && so == eo) r = 1;  // RS was empty, so fake not found
-    if (r || zfp->recoffs + eo > (int)zfp->recbufsize - RS_LENGTH_MARGIN) {
-      // not found, or found "near" end of buffer...
-      if (zfp->endoffs < (int)zfp->recbufsize &&
-          (r || zfp->recoffs + eo == zfp->endoffs)) {
-        // at end of data, and (not found or found at end of data)
-        ret = zfp->endoffs - zfp->recoffs;
-        zfp->recoffs = zfp->endoffs;
-        break;
-      }
-      if (zfp->recoffs) {
-        // room to move data up: move remaining data in buffer to low end
-        memmove(zfp->recbuf, TT.rgl.recptr, zfp->endoffs - zfp->recoffs);
-        zfp->endoffs -= zfp->recoffs;
-        zfp->recoffs = 0;
-      } else zfp->recbuf =    // enlarge buffer
-        xrealloc(zfp->recbuf, (zfp->recbufsize = zfp->recbufsize * 3 / 2) + 1);
-      // try to read more into buffer past current data
-      zfp->endoffs += fread(zfp->recbuf + zfp->endoffs,
-                      1, zfp->recbufsize - zfp->endoffs, zfp->fp);
-      zfp->recbuf[zfp->endoffs] = 0;
-    } else {
-      // found and not too near end of data
-      ret = so;
-      TT.rgl.recptr[so] = 0;
-      zfp->recoffs += eo;
-      break;
+
+    if (!zfp->eof && (r
+          || (zfp->lim - (zfp->ro + eo)) < zfp->buflen / 4) && !zfp->is_tty) {
+      // RS not found, or found near lim. Slide up and try to get more data
+      // If recptr at start of buf and RS not found then expand buffer
+      memmove(zfp->buf, TT.rgl.recptr, zfp->lim - zfp->ro);
+      zfp->lim -= zfp->ro;
+      zfp->ro = 0;
+      continue;
     }
+    ret = so;   // If RS found, then 'so' is rec length
+    if (zfp->eof) {
+      if (r) {  // EOF and RS not found; rec is all data left in buf
+        ret = zfp->lim - zfp->ro;
+        zfp->ro = zfp->lim; // set ro for -1 return on next call
+      } else zfp->ro += eo; // RS found; advance ro
+    } else zfp->ro += eo; // Here only if RS found not near lim
+
+    if (!r || !zfp->is_tty) {
+      // If is_tty then RS found; reset buffer pointers;
+      // is_tty uses one rec per buffer load
+      if (zfp->is_tty) zfp->ro = zfp->lim = 0;
+      break;
+    } // RS not found AND is_tty; loop to keep reading
   }
-  regfree(rsrxp);
+  regfree(&rsrx);
   return ret;
 }
 
+// get a record; return length, or -1 at EOF
+static ssize_t getrec_f(struct zfile *zfp)
+{
+  int k;
+  if (ENSURE_STR(&STACK[RS])->vst->str[0]) return getr(zfp, 0);
+  // RS == "" so multiline read
+  // Passing 1 to getr() forces multiline mode, which uses regex "\n\n+" to
+  // split on sequences of 2 or more newlines. But that's not the same as
+  // multiline mode, which never returns empty records or records with leading
+  // or trailing newlines, which can occur with RS="\n\n+". So here we loop and
+  // strip leading/trailing newlines and discard empty lines. See gawk manual,
+  // "4.9 Multiple-Line Records" for info on this difference.
+  do {
+    k = getr(zfp, 1);
+    if (k < 0) break;
+    while (k && TT.rgl.recptr[k-1] == '\n') k--;
+    while (k && TT.rgl.recptr[0] == '\n') k--, TT.rgl.recptr++;
+  } while (!k);
+  return k;
+}
+
 static ssize_t getrec(void)
 {
   ssize_t k;
@@ -3631,18 +3655,19 @@ static int interpx(int start, int *status)
         break;
 
         // Comparisons (with the '<', "<=", "!=", "==", '>', and ">="
-        // operators) shall be made numerically if both operands are numeric,
-        // if one is numeric and the other has a string value that is a numeric
-        // string, or if one is numeric and the other has the uninitialized
-        // value. Otherwise, operands shall be converted to strings as required
-        // and a string comparison shall be made as follows:
-        //
-        // For the "!=" and "==" operators, the strings should be compared to
-        // check if they are identical but may be compared using the
-        // locale-specific collation sequence to check if they collate equally.
+        // operators) shall be made numerically:
+        // * if both operands are numeric,
+        // * if one is numeric and the other has a string value that is a
+        //   numeric string,
+        // * if both have string values that are numeric strings, or
+        // * if one is numeric and the other has the uninitialized value.
         //
-        // For the other operators, the strings shall be compared using the
-        // locale-specific collation sequence.
+        // Otherwise, operands shall be converted to strings as required and a
+        // string comparison shall be made as follows:
+        // * For the "!=" and "==" operators, the strings shall be compared to
+        //   check if they are identical (not to check if they collate equally).
+        // * For the other operators, the strings shall be compared using the
+        //   locale-specific collation sequence.
         //
         // The value of the comparison expression shall be 1 if the relation is
         // true, or 0 if the relation is false.
diff --git a/toys/pending/klogd.c b/toys/pending/klogd.c
index c888e9e7..fbc7e165 100644
--- a/toys/pending/klogd.c
+++ b/toys/pending/klogd.c
@@ -5,27 +5,23 @@
  *
  * No standard
 
-USE_KLOGD(NEWTOY(klogd, "c#<1>8n", TOYFLAG_SBIN))
+USE_KLOGD(NEWTOY(klogd, "c#<1>8ns", TOYFLAG_SBIN))
 
 config KLOGD
-    bool "klogd"
-    default n
-    help
-    usage: klogd [-n] [-c N]
+  bool "klogd"
+  default n
+  help
+  usage: klogd [-n] [-c PRIORITY]
 
-    -c  N   Print to console messages more urgent than prio N (1-8)"
-    -n    Run in foreground
-
-config KLOGD_SOURCE_RING_BUFFER
-    bool "enable kernel ring buffer as log source."
-    default n
-    depends on KLOGD
+  -c	Print to console messages more urgent than PRIORITY (1-8)"
+  -n	Run in foreground
+  -s	Use syscall instead of /proc
 */
 
 #define FOR_klogd
 #include "toys.h"
-#include <signal.h>
 #include <sys/klog.h>
+
 GLOBALS(
   long level;
 
@@ -34,73 +30,67 @@ GLOBALS(
 
 static void set_log_level(int level)
 {
-  if (CFG_KLOGD_SOURCE_RING_BUFFER)
-    klogctl(8, NULL, level);
+  if (FLAG(s)) klogctl(8, 0, level);
   else {
     FILE *fptr = xfopen("/proc/sys/kernel/printk", "w");
+
     fprintf(fptr, "%u\n", level);
     fclose(fptr);
-    fptr = NULL;
   }
 }
 
 static void handle_signal(int sig)
 {
-  if (CFG_KLOGD_SOURCE_RING_BUFFER) {
-    klogctl(7, NULL, 0);
-    klogctl(0, NULL, 0);
+  if (FLAG(s)) {
+    klogctl(7, 0, 0);
+    klogctl(0, 0, 0);
   } else {
-    set_log_level(7);
+    set_log_level(7); // TODO: hardwired? Old value...?
     xclose(TT.fd);
   }
-  syslog(LOG_NOTICE,"KLOGD: Daemon exiting......");
-  exit(1);
+  syslog(LOG_NOTICE, "KLOGD: Daemon exiting......");
+
+  toys.exitval = 1;
+  xexit();
 }
 
-/*
- * Read kernel ring buffer in local buff and keep track of
- * "used" amount to track next read to start.
- */
+// Read kernel ring buffer in local buff and keep track of
+// "used" amount to track next read to start.
 void klogd_main(void)
 {
   int prio, size, used = 0;
-  char *start, *line_start, msg_buffer[16348]; //LOG_LINE_LENGTH - Ring buffer size
+  char *start, *line_start;
 
+  if (!FLAG(n) xvdaemon();
   sigatexit(handle_signal);
-  if (toys.optflags & FLAG_c) set_log_level(TT.level);    //set log level
-  if (!(toys.optflags & FLAG_n)) daemon(0, 0);            //Make it daemon
+  if (FLAG(c)) set_log_level(TT.level);    //set log level
 
-  if (CFG_KLOGD_SOURCE_RING_BUFFER) {
-    syslog(LOG_NOTICE, "KLOGD: started with Kernel ring buffer as log source\n");
-    klogctl(1, NULL, 0);
-  } else {
-    TT.fd = xopenro("/proc/kmsg"); //_PATH_KLOG in paths.h
-    syslog(LOG_NOTICE, "KLOGD: started with /proc/kmsg as log source\n");
-  }
+  if (FLAG(s)) klogctl(1, 0, 0);
+  else TT.fd = xopenro("/proc/kmsg"); //_PATH_KLOG in paths.h
+  syslog(LOG_NOTICE, "KLOGD: started with %s as log source\n",
+    FLAG(s) ? "Kernel ring buffer" : "/proc/kmsg");
   openlog("Kernel", 0, LOG_KERN);    //open connection to system logger..
 
-  while(1) {
-    start = msg_buffer + used; //start updated for re-read.
-    if (CFG_KLOGD_SOURCE_RING_BUFFER) {
-      size = klogctl(2, start, sizeof(msg_buffer) - used - 1);
-    } else {
-      size = xread(TT.fd, start, sizeof(msg_buffer) - used - 1);
-    }
+  for (;;) {
+    start = toybuf + used; //start updated for re-read.
+    size = sizeof(toybuf)-used-1;
+    if (FLAG(s)) size = klogctl(2, start, size);
+    else size = xread(TT.fd, start, size);
     if (size < 0) perror_exit("error reading file:");
-    start[size] = '\0';  //Ensure last line to be NUL terminated.
-    if (used) start = msg_buffer;
-    while(start) {
-      if ((line_start = strsep(&start, "\n")) != NULL && start != NULL) used = 0;
-      else {                            //Incomplete line, copy it to start of buff.
+    start[size] = 0;
+    if (used) start = toybuf;
+    while (start) {
+      if ((line_start = strsep(&start, "\n")) && start) used = 0;
+      else {      //Incomplete line, copy it to start of buff.
         used = strlen(line_start);
-        strcpy(msg_buffer, line_start);
-        if (used < (sizeof(msg_buffer) - 1)) break;
+        strcpy(toybuf, line_start);
+        if (used < (sizeof(toybuf) - 1)) break;
         used = 0; //we have buffer full, log it as it is.
       }
       prio = LOG_INFO;  //we dont know priority, mark it INFO
       if (*line_start == '<') {  //we have new line to syslog
         line_start++;
-        if (line_start) prio = (int)strtoul(line_start, &line_start, 10);
+        if (line_start) prio = strtoul(line_start, &line_start, 10);
         if (*line_start == '>') line_start++;
       }
       if (*line_start) syslog(prio, "%s", line_start);
diff --git a/toys/pending/mke2fs.c b/toys/pending/mke2fs.c
deleted file mode 100644
index 0741157f..00000000
--- a/toys/pending/mke2fs.c
+++ /dev/null
@@ -1,766 +0,0 @@
-/* mke2fs.c - Create an ext2 filesystem image.
- *
- * Copyright 2006, 2007 Rob Landley <rob@landley.net>
-
-// Still to go: "E:jJ:L:m:O:"
-USE_MKE2FS(NEWTOY(mke2fs, "<1>2g:Fnqm#N#i#b#", TOYFLAG_SBIN))
-
-config MKE2FS
-  bool "mke2fs"
-  default n
-  help
-    usage: mke2fs [-Fnq] [-b ###] [-N|i ###] [-m ###] device
-
-    Create an ext2 filesystem on a block device or filesystem image.
-
-    -F         Force to run on a mounted device
-    -n         Don't write to device
-    -q         Quiet (no output)
-    -b size    Block size (1024, 2048, or 4096)
-    -N inodes  Allocate this many inodes
-    -i bytes   Allocate one inode for every XXX bytes of device
-    -m percent Reserve this percent of filesystem space for root user
-
-config MKE2FS_JOURNAL
-  bool "Journaling support (ext3)"
-  default n
-  depends on MKE2FS
-  help
-    usage: mke2fs [-j] [-J size=###,device=XXX]
-
-    -j         Create journal (ext3)
-    -J         Journal options
-               size: Number of blocks (1024-102400)
-               device: Specify an external journal
-
-config MKE2FS_GEN
-  bool "Generate (gene2fs)"
-  default n
-  depends on MKE2FS
-  help
-    usage: gene2fs [options] device filename
-
-    The [options] are the same as mke2fs.
-
-config MKE2FS_LABEL
-  bool "Label support"
-  default n
-  depends on MKE2FS
-  help
-    usage: mke2fs [-L label] [-M path] [-o string]
-
-    -L         Volume label
-    -M         Path to mount point
-    -o         Created by
-
-config MKE2FS_EXTENDED
-  bool "Extended options"
-  default n
-  depends on MKE2FS
-  help
-    usage: mke2fs [-E stride=###] [-O option[,option]]
-
-    -E stride= Set RAID stripe size (in blocks)
-    -O [opts]  Specify fewer ext2 option flags (for old kernels)
-               All of these are on by default (as appropriate)
-       none         Clear default options (all but journaling)
-       dir_index    Use htree indexes for large directories
-       filetype     Store file type info in directory entry
-       has_journal  Set by -j
-       journal_dev  Set by -J device=XXX
-       sparse_super Don't allocate huge numbers of redundant superblocks
-*/
-
-#define FOR_mke2fs
-#include "toys.h"
-
-GLOBALS(
-  // Command line arguments.
-  long blocksize;
-  long bytes_per_inode;
-  long inodes;           // Total inodes in filesystem.
-  long reserved_percent; // Integer precent of space to reserve for root.
-  char *gendir;          // Where to read dirtree from.
-
-  // Internal data.
-  struct dirtree *dt;    // Tree of files to copy into the new filesystem.
-  unsigned treeblocks;   // Blocks used by dt
-  unsigned treeinodes;   // Inodes used by dt
-
-  unsigned blocks;       // Total blocks in the filesystem.
-  unsigned freeblocks;   // Free blocks in the filesystem.
-  unsigned inodespg;     // Inodes per group
-  unsigned groups;       // Total number of block groups.
-  unsigned blockbits;    // Bits per block.  (Also blocks per group.)
-
-  // For gene2fs
-  unsigned nextblock;    // Next data block to allocate
-  unsigned nextgroup;    // Next group we'll be allocating from
-  int fsfd;              // File descriptor of filesystem (to output to).
-)
-
-// Stuff defined in linux/ext2_fs.h
-
-#define EXT2_SUPER_MAGIC  0xEF53
-
-struct ext2_superblock {
-  uint32_t inodes_count;      // Inodes count
-  uint32_t blocks_count;      // Blocks count
-  uint32_t r_blocks_count;    // Reserved blocks count
-  uint32_t free_blocks_count; // Free blocks count
-  uint32_t free_inodes_count; // Free inodes count
-  uint32_t first_data_block;  // First Data Block
-  uint32_t log_block_size;    // Block size
-  uint32_t log_frag_size;     // Fragment size
-  uint32_t blocks_per_group;  // Blocks per group
-  uint32_t frags_per_group;   // Fragments per group
-  uint32_t inodes_per_group;  // Inodes per group
-  uint32_t mtime;             // Mount time
-  uint32_t wtime;             // Write time
-  uint16_t mnt_count;         // Mount count
-  uint16_t max_mnt_count;     // Maximal mount count
-  uint16_t magic;             // Magic signature
-  uint16_t state;             // File system state
-  uint16_t errors;            // Behaviour when detecting errors
-  uint16_t minor_rev_level;   // minor revision level
-  uint32_t lastcheck;         // time of last check
-  uint32_t checkinterval;     // max. time between checks
-  uint32_t creator_os;        // OS
-  uint32_t rev_level;         // Revision level
-  uint16_t def_resuid;        // Default uid for reserved blocks
-  uint16_t def_resgid;        // Default gid for reserved blocks
-  uint32_t first_ino;         // First non-reserved inode
-  uint16_t inode_size;        // size of inode structure
-  uint16_t block_group_nr;    // block group # of this superblock
-  uint32_t feature_compat;    // compatible feature set
-  uint32_t feature_incompat;  // incompatible feature set
-  uint32_t feature_ro_compat; // readonly-compatible feature set
-  char     uuid[16];          // 128-bit uuid for volume
-  char     volume_name[16];   // volume name
-  char     last_mounted[64];  // directory where last mounted
-  uint32_t alg_usage_bitmap;  // For compression
-  // For EXT2_COMPAT_PREALLOC
-  uint8_t  prealloc_blocks;   // Nr of blocks to try to preallocate
-  uint8_t  prealloc_dir_blocks; //Nr to preallocate for dirs
-  uint16_t padding1;
-  // For EXT3_FEATURE_COMPAT_HAS_JOURNAL
-  uint8_t  journal_uuid[16];   // uuid of journal superblock
-  uint32_t journal_inum;       // inode number of journal file
-  uint32_t journal_dev;        // device number of journal file
-  uint32_t last_orphan;        // start of list of inodes to delete
-  uint32_t hash_seed[4];       // HTREE hash seed
-  uint8_t  def_hash_version;   // Default hash version to use
-  uint8_t  padding2[3];
-  uint32_t default_mount_opts;
-  uint32_t first_meta_bg;      // First metablock block group
-  uint32_t mkfs_time;          // Creation timestamp
-  uint32_t jnl_blocks[17];     // Backup of journal inode
-  // uint32_t reserved[172];      // Padding to the end of the block
-};
-
-struct ext2_group
-{
-  uint32_t block_bitmap;       // Block number of block bitmap
-  uint32_t inode_bitmap;       // Block number of inode bitmap
-  uint32_t inode_table;        // Block number of inode table
-  uint16_t free_blocks_count;  // How many free blocks in this group?
-  uint16_t free_inodes_count;  // How many free inodes in this group?
-  uint16_t used_dirs_count;    // How many directories?
-  uint16_t reserved[7];        // pad to 32 bytes
-};
-
-struct ext2_dentry {
-  uint32_t inode;         // Inode number
-  uint16_t rec_len;       // Directory entry length
-  uint8_t  name_len;      // Name length
-  uint8_t  file_type;
-  char     name[0];     // File name
-};
-
-struct ext2_inode {
-  uint16_t mode;        // File mode
-  uint16_t uid;         // Low 16 bits of Owner Uid
-  uint32_t size;        // Size in bytes
-  uint32_t atime;       // Access time
-  uint32_t ctime;       // Creation time
-  uint32_t mtime;       // Modification time
-  uint32_t dtime;       // Deletion Time
-  uint16_t gid;         // Low 16 bits of Group Id
-  uint16_t links_count; // Links count
-  uint32_t blocks;      // Blocks count
-  uint32_t flags;       // File flags
-  uint32_t reserved1;
-  uint32_t block[15];   // Pointers to blocks
-  uint32_t generation;  // File version (for NFS)
-  uint32_t file_acl;    // File ACL
-  uint32_t dir_acl;     // Directory ACL (or top bits of file length)
-  uint32_t faddr;       // Last block in file
-  uint8_t  frag;        // Fragment number
-  uint8_t  fsize;       // Fragment size
-  uint16_t pad1;
-  uint16_t uid_high;    // High bits of uid
-  uint16_t gid_high;    // High bits of gid
-  uint32_t reserved2;
-};
-
-#define EXT2_FEATURE_COMPAT_DIR_PREALLOC	0x0001
-#define EXT2_FEATURE_COMPAT_IMAGIC_INODES	0x0002
-#define EXT3_FEATURE_COMPAT_HAS_JOURNAL		0x0004
-#define EXT2_FEATURE_COMPAT_EXT_ATTR		0x0008
-#define EXT2_FEATURE_COMPAT_RESIZE_INO		0x0010
-#define EXT2_FEATURE_COMPAT_DIR_INDEX		0x0020
-
-#define EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER	0x0001
-#define EXT2_FEATURE_RO_COMPAT_LARGE_FILE	0x0002
-#define EXT2_FEATURE_RO_COMPAT_BTREE_DIR	0x0004
-
-#define EXT2_FEATURE_INCOMPAT_COMPRESSION	0x0001
-#define EXT2_FEATURE_INCOMPAT_FILETYPE		0x0002
-#define EXT3_FEATURE_INCOMPAT_RECOVER		0x0004
-#define EXT3_FEATURE_INCOMPAT_JOURNAL_DEV	0x0008
-#define EXT2_FEATURE_INCOMPAT_META_BG		0x0010
-
-#define EXT2_NAME_LEN 255
-
-// Ext2 directory file types.  Only the low 3 bits are used.  The
-// other bits are reserved for now.
-
-enum {
-  EXT2_FT_UNKNOWN,
-  EXT2_FT_REG_FILE,
-  EXT2_FT_DIR,
-  EXT2_FT_CHRDEV,
-  EXT2_FT_BLKDEV,
-  EXT2_FT_FIFO,
-  EXT2_FT_SOCK,
-  EXT2_FT_SYMLINK,
-  EXT2_FT_MAX
-};
-
-#define INODES_RESERVED 10
-
-static uint32_t div_round_up(uint32_t a, uint32_t b)
-{
-  uint32_t c = a/b;
-
-  if (a%b) c++;
-  return c;
-}
-
-// Calculate data blocks plus index blocks needed to hold a file.
-
-static uint32_t file_blocks_used(uint64_t size, uint32_t *blocklist)
-{
-  uint32_t dblocks = (uint32_t)((size+(TT.blocksize-1))/TT.blocksize);
-  uint32_t idx=TT.blocksize/4, iblocks=0, diblocks=0, tiblocks=0;
-
-  // Fill out index blocks in inode.
-
-  if (blocklist) {
-    int i;
-
-    // Direct index blocks
-    for (i=0; i<13 && i<dblocks; i++) blocklist[i] = i;
-    // Singly indirect index blocks
-    if (dblocks > 13+idx) blocklist[13] = 13+idx;
-    // Doubly indirect index blocks
-    idx = 13 + idx + (idx*idx);
-    if (dblocks > idx) blocklist[14] = idx;
-
-    return 0;
-  }
-
-  // Account for direct, singly, doubly, and triply indirect index blocks
-
-  if (dblocks > 12) {
-    iblocks = ((dblocks-13)/idx)+1;
-    if (iblocks > 1) {
-      diblocks = ((iblocks-2)/idx)+1;
-      if (diblocks > 1)
-        tiblocks = ((diblocks-2)/idx)+1;
-    }
-  }
-
-  return dblocks + iblocks + diblocks + tiblocks;
-}
-
-// Use the parent pointer to iterate through the tree non-recursively.
-static struct dirtree *treenext(struct dirtree *this)
-{
-  while (this && !this->next) this = this->parent;
-  if (this) this = this->next;
-
-  return this;
-}
-
-// Recursively calculate the number of blocks used by each inode in the tree.
-// Returns blocks used by this directory, assigns bytes used to *size.
-// Writes total block count to TT.treeblocks and inode count to TT.treeinodes.
-
-static long check_treesize(struct dirtree *that, off_t *size)
-{
-  long blocks;
-
-  while (that) {
-    *size += sizeof(struct ext2_dentry) + strlen(that->name);
-
-    if (that->child)
-      that->st.st_blocks = check_treesize(that->child, &that->st.st_size);
-    else if (S_ISREG(that->st.st_mode)) {
-       that->st.st_blocks = file_blocks_used(that->st.st_size, 0);
-       TT.treeblocks += that->st.st_blocks;
-    }
-    that = that->next;
-  }
-  TT.treeblocks += blocks = file_blocks_used(*size, 0);
-  TT.treeinodes++;
-
-  return blocks;
-}
-
-// Calculate inode numbers and link counts.
-//
-// To do this right I need to copy the tree and sort it, but here's a really
-// ugly n^2 way of dealing with the problem that doesn't scale well to large
-// numbers of files (> 100,000) but can be done in very little code.
-// This rewrites inode numbers to their final values, allocating depth first.
-
-static void check_treelinks(struct dirtree *tree)
-{
-  struct dirtree *current=tree, *that;
-  long inode = INODES_RESERVED;
-
-  while (current) {
-    ++inode;
-    // Since we can't hardlink to directories, we know their link count.
-    if (S_ISDIR(current->st.st_mode)) current->st.st_nlink = 2;
-    else {
-      dev_t new = current->st.st_dev;
-
-      if (!new) continue;
-
-      // Look for other copies of current node
-      current->st.st_nlink = 0;
-      for (that = tree; that; that = treenext(that)) {
-        if (same_file(current, that)) {
-          current->st.st_nlink++;
-          current->st.st_ino = inode;
-        }
-      }
-    }
-    current->st.st_ino = inode;
-    current = treenext(current);
-  }
-}
-
-// Calculate inodes per group from total inodes.
-static uint32_t get_inodespg(uint32_t inodes)
-{
-  uint32_t temp;
-
-  // Round up to fill complete inode blocks.
-  temp = (inodes + TT.groups - 1) / TT.groups;
-  inodes = TT.blocksize/sizeof(struct ext2_inode);
-  return ((temp + inodes - 1)/inodes)*inodes;
-}
-
-// Fill out superblock and TT structures.
-
-static void init_superblock(struct ext2_superblock *sb)
-{
-  uint32_t temp;
-
-  // Set log_block_size and log_frag_size.
-
-  for (temp = 0; temp < 4; temp++) if (TT.blocksize == 1024<<temp) break;
-  if (temp==4) error_exit("bad blocksize");
-  sb->log_block_size = sb->log_frag_size = SWAP_LE32(temp);
-
-  // Fill out blocks_count, r_blocks_count, first_data_block
-
-  sb->blocks_count = SWAP_LE32(TT.blocks);
-  sb->free_blocks_count = SWAP_LE32(TT.freeblocks);
-  temp = (TT.blocks * (uint64_t)TT.reserved_percent) / 100;
-  sb->r_blocks_count = SWAP_LE32(temp);
-
-  sb->first_data_block = SWAP_LE32(TT.blocksize == 1024 ? 1 : 0);
-
-  // Set blocks_per_group and frags_per_group, which is the size of an
-  // allocation bitmap that fits in one block (I.E. how many bits per block)?
-
-  sb->blocks_per_group = sb->frags_per_group = SWAP_LE32(TT.blockbits);
-
-  // Set inodes_per_group and total inodes_count
-  sb->inodes_per_group = SWAP_LE32(TT.inodespg);
-  sb->inodes_count = SWAP_LE32(TT.inodespg * TT.groups);
-
-  // Determine free inodes.
-  temp = TT.inodespg*TT.groups - INODES_RESERVED;
-  if (temp < TT.treeinodes) error_exit("Not enough inodes.\n");
-  sb->free_inodes_count = SWAP_LE32(temp - TT.treeinodes);
-
-  // Fill out the rest of the superblock.
-  sb->max_mnt_count=0xFFFF;
-  sb->wtime = sb->lastcheck = sb->mkfs_time = SWAP_LE32(time(NULL));
-  sb->magic = SWAP_LE32(0xEF53);
-  sb->state = sb->errors = SWAP_LE16(1);
-
-  sb->rev_level = SWAP_LE32(1);
-  sb->first_ino = SWAP_LE32(INODES_RESERVED+1);
-  sb->inode_size = SWAP_LE16(sizeof(struct ext2_inode));
-  sb->feature_incompat = SWAP_LE32(EXT2_FEATURE_INCOMPAT_FILETYPE);
-  sb->feature_ro_compat = SWAP_LE32(EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER);
-
-  create_uuid(sb->uuid);
-
-  // TODO If we're called as mke3fs or mkfs.ext3, do a journal.
-
-  //if (strchr(toys.which->name,'3'))
-  //	sb->feature_compat |= SWAP_LE32(EXT3_FEATURE_COMPAT_HAS_JOURNAL);
-}
-
-// Does this group contain a superblock backup (and group descriptor table)?
-static int is_sb_group(uint32_t group)
-{
-  int i;
-
-  // Superblock backups are on groups 0, 1, and powers of 3, 5, and 7.
-  if(!group || group==1) return 1;
-  for (i=3; i<9; i+=2) {
-    int j = i;
-    while (j<group) j*=i;
-    if (j==group) return 1;
-  }
-  return 0;
-}
-
-
-// Number of blocks used in group by optional superblock/group list backup.
-static int group_superblock_overhead(uint32_t group)
-{
-  int used;
-
-  if (!is_sb_group(group)) return 0;
-
-  // How many blocks does the group descriptor table take up?
-  used = TT.groups * sizeof(struct ext2_group);
-  used += TT.blocksize - 1;
-  used /= TT.blocksize;
-  // Plus the superblock itself.
-  used++;
-  // And a corner case.
-  if (!group && TT.blocksize == 1024) used++;
-
-  return used;
-}
-
-// Number of blocks used in group to store superblock/group/inode list
-static int group_overhead(uint32_t group)
-{
-  // Return superblock backup overhead (if any), plus block/inode
-  // allocation bitmaps, plus inode tables.
-  return group_superblock_overhead(group) + 2 + get_inodespg(TT.inodespg)
-        / (TT.blocksize/sizeof(struct ext2_inode));
-}
-
-// In bitmap "array" set "len" bits starting at position "start" (from 0).
-static void bits_set(char *array, int start, int len)
-{
-  while(len) {
-    if ((start&7) || len<8) {
-      array[start/8]|=(1<<(start&7));
-      start++;
-      len--;
-    } else {
-      array[start/8]=255;
-      start+=8;
-      len-=8;
-    }
-  }
-}
-
-// Seek past len bytes (to maintain sparse file), or write zeroes if output
-// not seekable
-static void put_zeroes(int len)
-{
-  if(-1 == lseek(TT.fsfd, len, SEEK_SET)) {
-    memset(toybuf, 0, sizeof(toybuf));
-    while (len) {
-      int out = len > sizeof(toybuf) ? sizeof(toybuf) : len;
-      xwrite(TT.fsfd, toybuf, out);
-      len -= out;
-    }
-  }
-}
-
-// Fill out an inode structure from struct stat info in dirtree.
-static void fill_inode(struct ext2_inode *in, struct dirtree *that)
-{
-  uint32_t fbu[15];
-  int temp;
-
-  file_blocks_used(that->st.st_size, fbu);
-
-  // If that inode needs data blocks allocated to it.
-  if (that->st.st_size) {
-    int i, group = TT.nextblock/TT.blockbits;
-
-    // TODO: teach this about indirect blocks.
-    for (i=0; i<15; i++) {
-      // If we just jumped into a new group, skip group overhead blocks.
-      while (group >= TT.nextgroup)
-        TT.nextblock += group_overhead(TT.nextgroup++);
-    }
-  }
-  // TODO :  S_ISREG/DIR/CHR/BLK/FIFO/LNK/SOCK(m)
-  in->mode = SWAP_LE32(that->st.st_mode);
-
-  in->uid = SWAP_LE16(that->st.st_uid & 0xFFFF);
-  in->uid_high = SWAP_LE16(that->st.st_uid >> 16);
-  in->gid = SWAP_LE16(that->st.st_gid & 0xFFFF);
-  in->gid_high = SWAP_LE16(that->st.st_gid >> 16);
-  in->size = SWAP_LE32(that->st.st_size & 0xFFFFFFFF);
-
-  // Contortions to make the compiler not generate a warning for x>>32
-  // when x is 32 bits.  The optimizer should clean this up.
-  if (sizeof(that->st.st_size) > 4) temp = 32;
-  else temp = 0;
-  if (temp) in->dir_acl = SWAP_LE32(that->st.st_size >> temp);
-
-  in->atime = SWAP_LE32(that->st.st_atime);
-  in->ctime = SWAP_LE32(that->st.st_ctime);
-  in->mtime = SWAP_LE32(that->st.st_mtime);
-
-  in->links_count = SWAP_LE16(that->st.st_nlink);
-  in->blocks = SWAP_LE32(that->st.st_blocks);
-  // in->faddr
-}
-
-// Works like an archiver.
-// The first argument is the name of the file to create.  If it already
-// exists, that size will be used.
-
-void mke2fs_main(void)
-{
-  int i, temp;
-  off_t length;
-  uint32_t usedblocks, usedinodes, dtbblk;
-  struct dirtree *dti, *dtb;
-  struct ext2_superblock sb;
-
-  // Handle command line arguments.
-
-  if (toys.optargs[1]) {
-    sscanf(toys.optargs[1], "%u", &TT.blocks);
-    temp = O_RDWR|O_CREAT;
-  } else temp = O_RDWR;
-  if (!TT.reserved_percent) TT.reserved_percent = 5;
-
-  // TODO: Check if filesystem is mounted here
-
-  // For mke?fs, open file.  For gene?fs, create file.
-  TT.fsfd = xcreate(*toys.optargs, temp, 0777);
-
-  // Determine appropriate block size and block count from file length.
-  // (If no length, default to 4k.  They can override it on the cmdline.)
-
-  length = fdlength(TT.fsfd);
-  if (!TT.blocksize) TT.blocksize = (length && length < 1<<29) ? 1024 : 4096;
-  TT.blockbits = 8*TT.blocksize;
-  if (!TT.blocks) TT.blocks = length/TT.blocksize;
-
-  // Collect gene2fs list or lost+found, calculate requirements.
-
-  if (TT.gendir) {
-    strncpy(toybuf, TT.gendir, sizeof(toybuf));
-    dti = dirtree_read(toybuf, dirtree_notdotdot);
-  } else {
-    dti = xzalloc(sizeof(struct dirtree)+11);
-    strcpy(dti->name, "lost+found");
-    dti->st.st_mode = S_IFDIR|0755;
-    dti->st.st_ctime = dti->st.st_mtime = time(NULL);
-  }
-
-  // Add root directory inode.  This is iterated through for when finding
-  // blocks, but not when finding inodes.  The tree's parent pointers don't
-  // point back into this.
-
-  dtb = xzalloc(sizeof(struct dirtree)+1);
-  dtb->st.st_mode = S_IFDIR|0755;
-  dtb->st.st_ctime = dtb->st.st_mtime = time(NULL);
-  dtb->child = dti;
-
-  // Figure out how much space is used by preset files
-  length = check_treesize(dtb, &(dtb->st.st_size));
-  check_treelinks(dtb);
-
-  // Figure out how many total inodes we need.
-
-  if (!TT.inodes) {
-    if (!TT.bytes_per_inode) TT.bytes_per_inode = 8192;
-    TT.inodes = (TT.blocks * (uint64_t)TT.blocksize) / TT.bytes_per_inode;
-  }
-
-  // If we're generating a filesystem and have no idea how many blocks it
-  // needs, start with a minimal guess, find the overhead of that many
-  // groups, and loop until this is enough groups to store this many blocks.
-  if (!TT.blocks) TT.groups = (TT.treeblocks/TT.blockbits)+1;
-  else TT.groups = div_round_up(TT.blocks, TT.blockbits);
-
-  for (;;) {
-    temp = TT.treeblocks;
-
-    for (i = 0; i<TT.groups; i++) temp += group_overhead(i);
-
-    if (TT.blocks) {
-      if (TT.blocks < temp) error_exit("Not enough space.\n");
-      break;
-    }
-    if (temp <= TT.groups * TT.blockbits) {
-      TT.blocks = temp;
-      break;
-    }
-    TT.groups++;
-  }
-  TT.freeblocks = TT.blocks - temp;
-
-  // Now we know all the TT data, initialize superblock structure.
-
-  init_superblock(&sb);
-
-  // Start writing.  Skip the first 1k to avoid the boot sector (if any).
-  put_zeroes(1024);
-
-  // Loop through block groups, write out each one.
-  dtbblk = usedblocks = usedinodes = 0;
-  for (i=0; i<TT.groups; i++) {
-    struct ext2_inode *in = (struct ext2_inode *)toybuf;
-    uint32_t start, itable, used, end;
-    int j, slot;
-
-    // Where does this group end?
-    end = TT.blockbits;
-    if ((i+1)*TT.blockbits > TT.blocks) end = TT.blocks & (TT.blockbits-1);
-
-    // Blocks used by inode table
-    itable = (TT.inodespg*sizeof(struct ext2_inode))/TT.blocksize;
-
-    // If a superblock goes here, write it out.
-    start = group_superblock_overhead(i);
-    if (start) {
-      struct ext2_group *bg = (struct ext2_group *)toybuf;
-      int treeblocks = TT.treeblocks, treeinodes = TT.treeinodes;
-
-      sb.block_group_nr = SWAP_LE16(i);
-
-      // Write superblock and pad it up to block size
-      xwrite(TT.fsfd, &sb, sizeof(struct ext2_superblock));
-      temp = TT.blocksize - sizeof(struct ext2_superblock);
-      if (!i && TT.blocksize > 1024) temp -= 1024;
-      memset(toybuf, 0, TT.blocksize);
-      xwrite(TT.fsfd, toybuf, temp);
-
-      // Loop through groups to write group descriptor table.
-      for(j=0; j<TT.groups; j++) {
-
-        // Figure out what sector this group starts in.
-        used = group_superblock_overhead(j);
-
-        // Find next array slot in this block (flush block if full).
-        slot = j % (TT.blocksize/sizeof(struct ext2_group));
-        if (!slot) {
-          if (j) xwrite(TT.fsfd, bg, TT.blocksize);
-          memset(bg, 0, TT.blocksize);
-        }
-
-        // How many free inodes in this group?
-        temp = TT.inodespg;
-        if (!i) temp -= INODES_RESERVED;
-        if (temp > treeinodes) {
-          treeinodes -= temp;
-          temp = 0;
-        } else {
-          temp -= treeinodes;
-          treeinodes = 0;
-        }
-        bg[slot].free_inodes_count = SWAP_LE16(temp);
-
-        // How many free blocks in this group?
-        temp = TT.inodespg/(TT.blocksize/sizeof(struct ext2_inode)) + 2;
-        temp = end-used-temp;
-        if (temp > treeblocks) {
-          treeblocks -= temp;
-          temp = 0;
-        } else {
-          temp -= treeblocks;
-          treeblocks = 0;
-        }
-        bg[slot].free_blocks_count = SWAP_LE32(temp);
-
-        // Fill out rest of group structure
-        used += j*TT.blockbits;
-        bg[slot].block_bitmap = SWAP_LE32(used++);
-        bg[slot].inode_bitmap = SWAP_LE32(used++);
-        bg[slot].inode_table = SWAP_LE32(used);
-        bg[slot].used_dirs_count = 0;  // (TODO)
-      }
-      xwrite(TT.fsfd, bg, TT.blocksize);
-    }
-
-    // Now write out stuff that every block group has.
-
-    // Write block usage bitmap
-
-    start += 2 + itable;
-    memset(toybuf, 0, TT.blocksize);
-    bits_set(toybuf, 0, start);
-    bits_set(toybuf, end, TT.blockbits-end);
-    temp = TT.treeblocks - usedblocks;
-    if (temp) {
-      if (end-start > temp) temp = end-start;
-      bits_set(toybuf, start, temp);
-    }
-    xwrite(TT.fsfd, toybuf, TT.blocksize);
-
-    // Write inode bitmap
-    memset(toybuf, 0, TT.blocksize);
-    j = 0;
-    if (!i) bits_set(toybuf, 0, j = INODES_RESERVED);
-    bits_set(toybuf, TT.inodespg, slot = TT.blockbits-TT.inodespg);
-    temp = TT.treeinodes - usedinodes;
-    if (temp) {
-      if (slot-j > temp) temp = slot-j;
-      bits_set(toybuf, j, temp);
-    }
-    xwrite(TT.fsfd, toybuf, TT.blocksize);
-
-    // Write inode table for this group (TODO)
-    for (j = 0; j<TT.inodespg; j++) {
-      slot = j % (TT.blocksize/sizeof(struct ext2_inode));
-      if (!slot) {
-        if (j) xwrite(TT.fsfd, in, TT.blocksize);
-        memset(in, 0, TT.blocksize);
-      }
-      if (!i && j<INODES_RESERVED) {
-        // Write root inode
-        if (j == 2) fill_inode(in+slot, dtb);
-      } else if (dti) {
-        fill_inode(in+slot, dti);
-        dti = treenext(dti);
-      }
-    }
-    xwrite(TT.fsfd, in, TT.blocksize);
-
-    while (dtb) {
-      // TODO write index data block
-      // TODO write root directory data block
-      // TODO write directory data block
-      // TODO write file data block
-      put_zeroes(TT.blocksize);
-      start++;
-      if (start == end) break;
-    }
-    // Write data blocks (TODO)
-    put_zeroes((end-start) * TT.blocksize);
-  }
-}
diff --git a/toys/pending/sh.c b/toys/pending/sh.c
index 87a4633a..1be952d0 100644
--- a/toys/pending/sh.c
+++ b/toys/pending/sh.c
@@ -44,7 +44,9 @@
  * if/then/elif/else/fi, for select while until/do/done, case/esac,
  * {/}, [[/]], (/), function assignment
 
+USE_SH(NEWTOY(break, ">1", TOYFLAG_NOFORK))
 USE_SH(NEWTOY(cd, ">1LP[-LP]", TOYFLAG_NOFORK))
+USE_SH(NEWTOY(continue, ">1", TOYFLAG_NOFORK))
 USE_SH(NEWTOY(declare, "pAailunxr", TOYFLAG_NOFORK))
  // TODO tpgfF
 USE_SH(NEWTOY(eval, 0, TOYFLAG_NOFORK))
@@ -134,6 +136,15 @@ config SH
     bg fg jobs kill
 
 # These are here for the help text, they're not selectable and control nothing
+config BREAK
+  bool
+  default n
+  depends on SH
+  help
+    usage: break [N]
+
+    End N levels of for/while/until loop immediately (default 1).
+
 config CD
   bool
   default n
@@ -147,6 +158,15 @@ config CD
     -P	Physical path: resolve symlinks in path
     -L	Local path: .. trims directories off $PWD (default)
 
+config CONTINUE
+  bool
+  default n
+  depends on SH
+  help
+    usage: continue [N]
+
+    Start next entry in for/while/until loop (or Nth outer loop, default 1).
+
 config DECLARE
   bool
   default n
@@ -381,6 +401,7 @@ GLOBALS(
 
   // job list, command line for $*, scratch space for do_wildcard_files()
   struct sh_arg jobs, *wcdeck;
+  FILE *script;
 )
 
 // Prototype because $($($(blah))) nests, leading to run->parse->run loop
@@ -554,7 +575,7 @@ static char *getvar(char *s)
 // Append variable to ff->vars, returning *struct. Does not check duplicates.
 static struct sh_vars *addvar(char *s, struct sh_fcall *ff)
 {
-  if (ff->varslen == ff->varscap && !(ff->varslen&31)) {
+  if (ff->varslen == ff->varscap) {
     ff->varscap += 32;
     ff->vars = xrealloc(ff->vars, (ff->varscap)*sizeof(*ff->vars));
   }
@@ -826,8 +847,8 @@ static int anystr(char *s, char **try)
 // Update $IFS cache in function call stack after variable assignment
 static void cache_ifs(char *s, struct sh_fcall *ff)
 {
-  if (!strncmp(s, "IFS=", 4))
-    do ff->ifs = s+4; while ((ff = ff->next) != TT.ff->prev);
+  if (strstart(&s, "IFS="))
+    do ff->ifs = s; while ((ff = ff->next) != TT.ff->prev);
 }
 
 // declare -aAilnrux
@@ -930,7 +951,7 @@ bad:
 }
 
 // Creates new variables (local or global) and handles +=
-// returns 0 on error, else sh_vars of new entry.
+// returns 0 on error, else sh_vars of new entry. Adds at ff if not found.
 static struct sh_vars *setvar_long(char *s, int freeable, struct sh_fcall *ff)
 {
   struct sh_vars *vv = 0, *was;
@@ -961,7 +982,7 @@ static struct sh_vars *setvar_long(char *s, int freeable, struct sh_fcall *ff)
 // Returns sh_vars * or 0 for failure (readonly, etc)
 static struct sh_vars *setvar(char *str)
 {
-  return setvar_long(str, 0, TT.ff->prev);
+  return setvar_long(str, 1, TT.ff->prev);
 }
 
 
@@ -983,7 +1004,7 @@ static int unsetvar(char *name)
     // free from global context
     } else {
       if (!(var->flags&VAR_NOFREE)) free(var->str);
-      memmove(var, var+1, sizeof(ff->vars)*(ff->varslen-(var-ff->vars)));
+      memmove(var, var+1, sizeof(ff->vars)*(ff->varslen-- -(var-ff->vars)));
     }
     if (!strcmp(name, "IFS"))
       do ff->ifs = " \t\n"; while ((ff = ff->next) != TT.ff->prev);
@@ -1107,7 +1128,7 @@ static char *parse_word(char *start, int early)
           else if (qq==254) return start+1;
           else if (qq==255) toybuf[quote-1] = ')';
         } else if (ii==')') quote--;
-      } else if (ii==qq) quote--;        // matching end quote
+      } else if (ii==(qq&127)) quote--;        // matching end quote
       else if (qq!='\'') end--, ii = 0;  // single quote claims everything
       if (ii) continue;                  // fall through for other quote types
 
@@ -1125,11 +1146,11 @@ static char *parse_word(char *start, int early)
 
     // \? $() ${} $[] ?() *() +() @() !()
     else {
-      if (ii=='$' && -1!=(qq = stridx("({[", *end))) {
+      if (ii=='$' && qq != 0247 && -1!=(qq = stridx("({['", *end))) {
         if (strstart(&end, "((")) {
           end--;
           toybuf[quote++] = 255;
-        } else toybuf[quote++] = ")}]"[qq];
+        } else toybuf[quote++] = ")}]\247"[qq]; // last is '+128
       } else if (*end=='(' && strchr("?*+@!", ii)) toybuf[quote++] = ')';
       else {
         if (ii!='\\') end--;
@@ -3637,7 +3658,6 @@ static char *get_next_line(FILE *ff, int prompt)
        probably have to inline run_command here to do that? Implicit ()
        also "X=42 | true; echo $X" doesn't get X.
        I.E. run_subshell() here sometimes? (But when?)
- TODO: bash supports "break &" and "break > file". No idea why.
  TODO If we just started a new pipeline, implicit parentheses (subshell)
  TODO can't free sh_process delete until ready to dispose else no debug output
  TODO: a | b | c needs subshell for builtins?
@@ -3736,32 +3756,12 @@ static void run_lines(void)
       }
     }
 
-    // Is this an executable segment?
-    if (!TT.ff->pl->type) {
-      // Is it a flow control jump? These aren't handled as normal builtins
-      // because they move *pl to other pipeline segments which is local here.
-      if (!strcmp(s, "break") || !strcmp(s, "continue")) {
-
-        // How many layers to peel off?
-        i = ss ? atol(ss) : 0;
-        if (i<1) i = 1;
-        if (TT.ff->blk->next && TT.ff->pl->arg->c<3
-            && (!ss || !ss[strspn(ss,"0123456789")]))
-        {
-          while (i && TT.ff->blk->next)
-            if (TT.ff->blk->middle && !strcmp(*TT.ff->blk->middle->arg->v, "do")
-              && !--i && *s=='c') TT.ff->pl = TT.ff->blk->start;
-            else TT.ff->pl = pop_block();
-        }
-        if (i) {
-          syntax_err(s);
-          break;
-        }
-      // Parse and run next command, saving resulting process
-      } else dlist_add_nomalloc((void *)&pplist, (void *)run_command());
+    // If executable segment parse and run next command saving resulting process
+    if (!TT.ff->pl->type) 
+      dlist_add_nomalloc((void *)&pplist, (void *)run_command());
 
     // Start of flow control block?
-    } else if (TT.ff->pl->type == 1) {
+    else if (TT.ff->pl->type == 1) {
 
 // TODO test cat | {thingy} is new PID: { is ( for |
 
@@ -4354,6 +4354,18 @@ void sh_main(void)
 
 /********************* shell builtin functions *************************/
 
+// Note: "break &" in bash breaks in the child, this breaks in the parent.
+void break_main(void)
+{
+  int i = *toys.optargs ? atolx_range(*toys.optargs, 1, INT_MAX) : 1;
+
+  // Peel off encosing do blocks
+  while (i && TT.ff->blk->next)
+    if (TT.ff->blk->middle && !strcmp(*TT.ff->blk->middle->arg->v, "do")
+        && !--i && *toys.which->name=='c') TT.ff->pl = TT.ff->blk->start;
+    else TT.ff->pl = pop_block();
+}
+
 #define FOR_cd
 #include "generated/flags.h"
 void cd_main(void)
@@ -4412,6 +4424,11 @@ void cd_main(void)
   }
 }
 
+void continue_main(void)
+{
+  break_main();
+}
+
 void exit_main(void)
 {
   toys.exitval = *toys.optargs ? atoi(*toys.optargs) : 0;
diff --git a/toys/posix/cp.c b/toys/posix/cp.c
index 449b5723..1f1816e5 100644
--- a/toys/posix/cp.c
+++ b/toys/posix/cp.c
@@ -154,9 +154,8 @@ void cp_xattr(int fdin, int fdout, char *file)
 static int cp_node(struct dirtree *try)
 {
   int fdout = -1, cfd = try->parent ? try->parent->extra : AT_FDCWD,
-      save = DIRTREE_SAVE*(CFG_MV && *toys.which->name == 'm'), rc = 0,
+      save = DIRTREE_SAVE*(CFG_MV && *toys.which->name == 'm'), rc = 0, rr = 0,
       tfd = dirtree_parentfd(try);
-  unsigned flags = toys.optflags;
   char *s = 0, *catch = try->parent ? try->name : TT.destname, *err = "%s";
   struct stat cst;
 
@@ -176,7 +175,7 @@ static int cp_node(struct dirtree *try)
     cp_xattr(try->dirfd, try->extra, catch);
   } else {
     // -d is only the same as -r for symlinks, not for directories
-    if (S_ISLNK(try->st.st_mode) && (flags & FLAG_d)) flags |= FLAG_r;
+    if (S_ISLNK(try->st.st_mode) && FLAG(d)) rr++;
 
     // Detect recursive copies via repeated top node (cp -R .. .) or
     // identical source/target (fun with hardlinks).
@@ -221,7 +220,7 @@ static int cp_node(struct dirtree *try)
       if (S_ISDIR(try->st.st_mode)) {
         struct stat st2;
 
-        if (!(flags & (FLAG_a|FLAG_r))) {
+        if (!FLAG(a) && !FLAG(r) && !rr) {
           err = "Skipped dir '%s'";
           catch = try->name;
           break;
@@ -241,13 +240,13 @@ static int cp_node(struct dirtree *try)
 
       // Hardlink
 
-      } else if (flags & FLAG_l) {
+      } else if (FLAG(l)) {
         if (!linkat(tfd, try->name, cfd, catch, 0)) err = 0;
 
       // Copy tree as symlinks. For non-absolute paths this involves
       // appending the right number of .. entries as you go down the tree.
 
-      } else if (flags & FLAG_s) {
+      } else if (FLAG(s)) {
         char *s, *s2;
         struct dirtree *or;
 
@@ -271,7 +270,7 @@ static int cp_node(struct dirtree *try)
 
       // Do something _other_ than copy contents of a file?
       } else if (!S_ISREG(try->st.st_mode)
-                 && (try->parent || (flags & (FLAG_a|FLAG_P|FLAG_r))))
+                 && (try->parent||FLAG(a)||FLAG(P)||FLAG(r)||rr))
       {
         // make symlink, or make block/char/fifo/socket
         if (S_ISLNK(try->st.st_mode)
@@ -303,7 +302,7 @@ static int cp_node(struct dirtree *try)
         cp_xattr(fdin, fdout, catch);
       }
       if (fdin != -1) close(fdin);
-    } while (err && (flags & (FLAG_f|FLAG_n)) && !unlinkat(cfd, catch, 0));
+    } while (err && (FLAG(f)||FLAG(n)) && !unlinkat(cfd, catch, 0));
   }
 
   // Did we make a thing?
diff --git a/toys/posix/grep.c b/toys/posix/grep.c
index afd07cf3..eeaff601 100644
--- a/toys/posix/grep.c
+++ b/toys/posix/grep.c
@@ -484,7 +484,7 @@ static int do_grep_r(struct dirtree *new)
   if (new->parent && !FLAG(h)) toys.optflags |= FLAG_H;
 
   name = dirtree_path(new, 0);
-  do_grep(openat(dirtree_parentfd(new), new->name, 0), name);
+  do_grep(openat(dirtree_parentfd(new), new->name, O_NONBLOCK|O_NOCTTY), name);
   free(name);
 
   return 0;
diff --git a/toys/posix/ls.c b/toys/posix/ls.c
index 3addd451..7a8dfd27 100644
--- a/toys/posix/ls.c
+++ b/toys/posix/ls.c
@@ -30,7 +30,7 @@ config LS
     -H  follow command line symlinks   -i  inode number
     -L  follow symlinks                -N  no escaping, even on tty
     -p  put '/' after dir names        -q  unprintable chars as '?'
-    -R  recursively list in subdirs    -s  storage used (in --block-size)
+    -R  recursively list in subdirs    -s  storage used (units of --block-size)
     -Z  security context
 
     output formats:
@@ -46,7 +46,7 @@ config LS
     -c  ctime      -r  reverse    -S  size     -t  time    -u  atime    -U  none
     -X  extension  -!  dirfirst   -~  nocase
 
-    --block-size N	block size (default 1024, -k resets to 1024)
+    --block-size N	block size for -s (default 1024, -k resets to 1024)
     --color  =always (default)  =auto (when stdout is tty) =never
         exe=green  suid=red  suidfile=redback  stickydir=greenback
         device=yellow  symlink=turquoise/red  dir=blue  socket=purple
diff --git a/toys/posix/patch.c b/toys/posix/patch.c
index bbc260fb..4030834d 100644
--- a/toys/posix/patch.c
+++ b/toys/posix/patch.c
@@ -59,7 +59,7 @@ GLOBALS(
 // TODO xgetline() instead, but replace_tempfile() wants fd...
 char *get_line(int fd)
 {
-  char c, *buf = NULL;
+  char c, *buf = 0;
   long len = 0;
 
   for (;;) {
@@ -113,7 +113,7 @@ static void fail_hunk(void)
 
   TT.state = 2;
   llist_traverse(TT.current_hunk, do_line);
-  TT.current_hunk = NULL;
+  TT.current_hunk = 0;
   if (!FLAG(dry_run)) delete_tempfile(TT.filein, TT.fileout, &TT.tempname);
   TT.state = 0;
 }
@@ -308,7 +308,7 @@ static char *unquote_file(char *filename)
 void patch_main(void)
 {
   int state = 0, patchlinenum = 0, strip = 0;
-  char *oldname = NULL, *newname = NULL;
+  char *oldname = 0, *newname = 0;
 
   if (toys.optc == 2) TT.i = toys.optargs[1];
   if (TT.i) TT.filepatch = xopenro(TT.i);
@@ -316,12 +316,11 @@ void patch_main(void)
 
   if (TT.d) xchdir(TT.d);
 
-  // Loop through the lines in the patch
+  // Loop through the lines in the patch file (-i or stdin) collecting hunks
   for (;;) {
     char *patchline;
 
-    patchline = get_line(TT.filepatch);
-    if (!patchline) break;
+    if (!(patchline = get_line(TT.filepatch))) break;
 
     // Other versions of patch accept damaged patches, so we need to also.
     if (strip || !patchlinenum++) {
@@ -329,7 +328,7 @@ void patch_main(void)
       if (len && patchline[len-1] == '\r') {
         if (!strip && !FLAG(s)) fprintf(stderr, "Removing DOS newlines\n");
         strip = 1;
-        patchline[len-1]=0;
+        patchline[len-1] = 0;
       }
     }
     if (!*patchline) {
@@ -351,11 +350,11 @@ void patch_main(void)
 
         // If we've consumed all expected hunk lines, apply the hunk.
         if (!TT.oldlen && !TT.newlen) state = apply_one_hunk();
-        continue;
+      } else {
+        dlist_terminate(TT.current_hunk);
+        fail_hunk();
+        state = 0;
       }
-      dlist_terminate(TT.current_hunk);
-      fail_hunk();
-      state = 0;
       continue;
     }
 
@@ -372,7 +371,7 @@ void patch_main(void)
       free(*name);
       finish_oldfile();
 
-      // Trim date from end of filename (if any).  We don't care.
+      // Trim date from end of filename (if any). Date<=epoch means delete.
       for (s = patchline+4; *s && *s!='\t'; s++);
       i = atoi(s);
       if (i>1900 && i<=1970) *name = xstrdup("/dev/null");
diff --git a/www/faq.html b/www/faq.html
index c39ae274..3640e82b 100644
--- a/www/faq.html
+++ b/www/faq.html
@@ -24,6 +24,8 @@
 <ul>
 <!-- get binaries -->
 <li><h2><a href="#install">How do I install toybox?</h2></li>
+<li><h2><a href="#standalone">How do I make individual/standalone toybox command binaries?</h2></li>
+<li><h2><a href="#hermetic">How do I build toybox on a system with a broken $PATH?</a></h2></li>
 <li><h2><a href="#cross">How do I cross compile toybox?</h2></li>
 <li><h2><a href="#targets">What architectures does toybox support?</li>
 <li><h2><a href="#system">What part of Linux/Android does toybox provide?</h2></li>
@@ -206,8 +208,8 @@ symlinks to toybox under the various command names. Toybox determines which
 command to run based on the filename, or you can use the "toybox" name in which case the first
 argument is the command to run (ala "toybox ls -l").</p>
 
-<p><u>You can also build
-individual commands as standalone executables</u>, ala "make sed cat ls".
+<p>You can also build individual commands as <a href="#standalone">standalone
+executables</a>, ala "make sed cat ls".
 The "make change" target builds all of them, as in "change for a $20".</p>
 
 <p><u>The main() function is in main.c</u> at the top level,
@@ -512,16 +514,74 @@ arbitrary file out of the filesystem and have it run that. You could
 
 <hr /><h2><a name="standalone" />Q: How do I make individual/standalone toybox command binaries?</h2>
 
-<p>After running the configure step (generally "make defconfig")
-you can "make list" to see available command names you can use as build
-targets to build just that command
-(ala "make sed"). Commands built this way do not contain a multiplexer and
-don't care what the command filename is.</p>
+<p>A: You can use almost<a href="#stand_foot"</a>*</a><a name="stand_back">
+any command name as a make target (ala "make sed") or test the standalone versions individually
+with the test_ prefix ("make test_sed"). You'll need to run the configure
+step first (generally "make defconfig") so the .config file exists for
+the build. For a list of currently available commands run
+"make list".</p>
 
 <p>The "make change" target (as in change for a $20) builds every command
 standalone (in the "change" subdirectory). Note that this is collectively
-about 10 times as large as the multiplexer version, both in disk space and
-runtime memory. (Even more when statically linked.)</p>
+about 10 times as large as the all-in-one multiplexer version (in disk space,
+runtime memory, how long the build takes...)</p>
+
+<p>As always, the Makefile is a thin wrapper around bash scripts actually
+doing the work, you can just all "scripts/single.sh cat ls mv" directly
+if you like.</p>
+
+<p><a name="stand_foot"><a href="#stand_back">*</a> A few command names, like "help" and "test" have
+other meanings to the Makefile, and you have to use scripts/single.sh or
+"make change" to build them standalone.</p>
+
+<hr /><h2><a name="hermetic">How do I build toybox on a system with a broken $PATH?</a></h2>
+
+<p>Toybox can provide its own build prerequisites (I.E
+perform a "hermetic" build) using the script <b>scripts/prereq/build.sh</b>
+which is a canned minimal toybox build that basically does "cc *.c" against
+saved headers to build the commands needed by the rest of the build.</p>
+
+<p>At the moment, building toybox on mac requires homebrew to get a .config
+file, ala:</p>
+
+<blockquote><pre>
+$ homebrew
+$ make macos_defconfig
+$ make clean
+$ exit
+</pre></blockquote>
+
+<p>But the rest of the hermetic build works without it:</p>
+
+<blockquote><pre>
+$ scripts/prereq/build.sh #ignoring SO many warnings
+$ mkdir prereq; mv toybox-prereq prereq/
+$ for i in $(prereq/toybox-prereq); do ln -s toybox-prereq prereq/$i; done
+$ PATH=$PWD/prereq:$PATH scripts/make.sh
+$ ./toybox
+</pre></blockquote>
+
+<p>If you already have an appropriate .config file you can copy in you
+don't need homebrew at all (and can skip the first section above).
+Editing one up by hand for qnx and similar is currently left as an exercise
+for the reader (but it's a fairly simple text file format).</p>
+
+<p>The files in the scripts/prereq directory were created by
+<b>scripts/recreate-prereq.sh</b> which records the commands used by
+a toybox build, harvests stripped down headers, and writes a build.sh
+to compile the appropriate source files. It's a couple dozen lines of
+bash if you're interested.</p>
+
+<p>At the moment toybox's full scripts/make.sh still requires bash
+(until toysh is finished and promoted out of pending). Freebsd users
+can invoke "/opt/usr/local/bin/bash scripts/make.sh" or similar
+to work around their distro's policy insisting that /bin/env can be
+trusted to live at a specific path but /bin/bash can't. (On Android both
+env and sh live in /system/bin, which is at least internally consistent.)</p>
+
+<p>Toybox does not yet provide "make" either. You can call scripts/make.sh
+directly (and scripts/test.sh and scripts/single.sh) if you've got a .config,
+but until kconfig/ is replaced defconfig/menuconfig still need gmake.</p>
 
 <hr /><h2><a name="cross" />Q: How do I cross compile toybox?</h2>
 
```

