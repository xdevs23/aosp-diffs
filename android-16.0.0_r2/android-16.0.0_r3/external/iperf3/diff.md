```diff
diff --git a/.github/CONTRIBUTING.md b/.github/CONTRIBUTING.md
index 275d26d..0227137 100644
--- a/.github/CONTRIBUTING.md
+++ b/.github/CONTRIBUTING.md
@@ -14,19 +14,20 @@ FreeBSD, and macOS.  Support may be provided on a best-effort basis to
 other UNIX-like platforms.  We cannot provide support for building
 and/or running iperf3 on Windows, iOS, or Android.
 
-Before asking for help, please use your favorite search engine or
-questions site (such as Stack Overflow) to see if your question might
-have been asked (and maybe even answered) before.
-https://fasterdata.es.net/ has some information on the use of various
-bandwidth measurement tools, including iperf3.  The iperf3
-documentation Web site at http://software.es.net/iperf/ contains
-various bits of helpful information, including a list of
+Before asking for help, please check with your favorite search engine
+or the
+[iperf3 Discussions site on GitHub](http://github.com/esnet/iperf/discussions)
+to see if your question might have been asked (and maybe even
+answered) before.  https://fasterdata.es.net/ has some information on
+the use of various bandwidth measurement tools, including iperf3.  The
+iperf3 documentation Web site at http://software.es.net/iperf/
+contains various bits of helpful information, including a list of
 [frequently-asked questions](http://software.es.net/iperf/faq.html).
 
 We specifically discourage the use of the issue tracker on the iperf3
 GitHub project page for asking questions.  Questions posted in the
-form of issues may go unanswered.  Please use a questions site
-such as [Stack Overflow](http://www.stackoverflow.com)
+form of issues may go unanswered.  Please use the
+[iperf3 Discussions site on GitHub](http://github.com/esnet/iperf/discussions)
 to ask questions of the community or
 alternatively use the iperf3 mailing list at
 iperf-dev@googlegroups.com (posting requires joining the list).
diff --git a/.github/ISSUE_TEMPLATE.md b/.github/ISSUE_TEMPLATE.md
index 359e1f8..9c75869 100644
--- a/.github/ISSUE_TEMPLATE.md
+++ b/.github/ISSUE_TEMPLATE.md
@@ -1,9 +1,10 @@
 _NOTE: The iperf3 issue tracker is for registering bugs, enhancement
 requests, or submissions of code.  It is not a means for asking
 questions about building or using iperf3.  Those are best directed
-towards the iperf3 mailing list at iperf-dev@googlegroups.com or
-question sites such as Stack Overflow
-(http://www.stackoverflow.com/).  A list of frequently-asked questions
+towards the Discussions section for this project at
+https://github.com/esnet/iperf/discussions
+or to the iperf3 mailing list at iperf-dev@googlegroups.com.
+A list of frequently-asked questions
 regarding iperf3 can be found at http://software.es.net/iperf/faq.html._
 
 # Context
@@ -23,7 +24,9 @@ iperf3 on Windows, iOS, or Android._
   libraries, cross-compiling, etc.):
 
 _Please fill out one of the "Bug Report" or "Enhancement Request"
-sections, as appropriate._
+sections, as appropriate. Note that submissions of bug fixes, new
+features, etc. should be done as a pull request at
+https://github.com/esnet/iperf/pulls_
 
 # Bug Report
 
@@ -35,8 +38,6 @@ sections, as appropriate._
 
 * Possible Solution
 
-_Please submit patches or code changes as a pull request._
-
 # Enhancement Request
 
 * Current behavior
@@ -45,5 +46,3 @@ _Please submit patches or code changes as a pull request._
 
 * Implementation notes
 
-_If submitting a proposed implementation of an enhancement request,
-please use the pull request mechanism._
diff --git a/.travis.yml b/.travis.yml
index f470b52..67ba082 100644
--- a/.travis.yml
+++ b/.travis.yml
@@ -5,7 +5,8 @@ compiler:
 os:
    - linux
    - osx
- 
+   - freebsd
+
 notifications:
   slack:
     secure: ImUmX7hcYotHWCDBfOcIvF6H7kkeGqiaUCy7SVPFtgPbz33ttpbRd94E7oxWVmZMLKb+i6+JCujTEWGwGBimzH+DjL0LLWs0ShzXZIUa1UzEPTc4hgV6VAxucYKFg2WrbXgOPWbulkMG1VZ6pX7GlAEGf0qyNqn44F7S2ay9m18=
diff --git a/Android.bp b/Android.bp
index bb58c72..02e4923 100644
--- a/Android.bp
+++ b/Android.bp
@@ -60,5 +60,6 @@ cc_binary {
         // https://github.com/esnet/iperf/pull/855
         "-Wno-constant-conversion",
         "-Wno-format",
+        "-DHAVE_SO_BINDTODEVICE"
     ],
 }
diff --git a/LICENSE b/LICENSE
index a9c2d92..6fa7f50 100644
--- a/LICENSE
+++ b/LICENSE
@@ -1,5 +1,5 @@
-"iperf, Copyright (c) 2014-2021, The Regents of the University of California,
-through Lawrence Berkeley National Laboratory (subject to receipt of any 
+"iperf, Copyright (c) 2014-2022, The Regents of the University of California,
+through Lawrence Berkeley National Laboratory (subject to receipt of any
 required approvals from the U.S. Dept. of Energy).  All rights reserved."
 
 Redistribution and use in source and binary forms, with or without
diff --git a/METADATA b/METADATA
index 69e6d39..db2e69e 100644
--- a/METADATA
+++ b/METADATA
@@ -9,12 +9,12 @@ third_party {
   last_upgrade_date {
     year: 2025
     month: 3
-    day: 10
+    day: 25
   }
   homepage: "https://iperf.fr/"
   identifier {
     type: "Git"
     value: "https://github.com/esnet/iperf.git"
-    version: "3.10"
+    version: "3.11"
   }
 }
diff --git a/Makefile.in b/Makefile.in
index bc62922..785288d 100644
--- a/Makefile.in
+++ b/Makefile.in
@@ -1,7 +1,7 @@
-# Makefile.in generated by automake 1.16.3 from Makefile.am.
+# Makefile.in generated by automake 1.16.5 from Makefile.am.
 # @configure_input@
 
-# Copyright (C) 1994-2020 Free Software Foundation, Inc.
+# Copyright (C) 1994-2021 Free Software Foundation, Inc.
 
 # This Makefile.in is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -154,18 +154,16 @@ am__define_uniq_tagged_files = \
   unique=`for i in $$list; do \
     if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
   done | $(am__uniquify_input)`
-ETAGS = etags
-CTAGS = ctags
-CSCOPE = cscope
 DIST_SUBDIRS = $(SUBDIRS)
 am__DIST_COMMON = $(srcdir)/Makefile.in $(srcdir)/iperf3.spec.in \
 	$(top_srcdir)/config/compile $(top_srcdir)/config/config.guess \
 	$(top_srcdir)/config/config.sub \
 	$(top_srcdir)/config/install-sh $(top_srcdir)/config/ltmain.sh \
 	$(top_srcdir)/config/missing \
-	$(top_srcdir)/config/mkinstalldirs INSTALL config/compile \
-	config/config.guess config/config.sub config/install-sh \
-	config/ltmain.sh config/missing config/mkinstalldirs
+	$(top_srcdir)/config/mkinstalldirs INSTALL README.md \
+	config/compile config/config.guess config/config.sub \
+	config/install-sh config/ltmain.sh config/missing \
+	config/mkinstalldirs
 DISTFILES = $(DIST_COMMON) $(DIST_SOURCES) $(TEXINFOS) $(EXTRA_DIST)
 distdir = $(PACKAGE)-$(VERSION)
 top_distdir = $(distdir)
@@ -221,8 +219,9 @@ AWK = @AWK@
 CC = @CC@
 CCDEPMODE = @CCDEPMODE@
 CFLAGS = @CFLAGS@
-CPP = @CPP@
 CPPFLAGS = @CPPFLAGS@
+CSCOPE = @CSCOPE@
+CTAGS = @CTAGS@
 CYGPATH_W = @CYGPATH_W@
 DEFS = @DEFS@
 DEPDIR = @DEPDIR@
@@ -233,6 +232,7 @@ ECHO_C = @ECHO_C@
 ECHO_N = @ECHO_N@
 ECHO_T = @ECHO_T@
 EGREP = @EGREP@
+ETAGS = @ETAGS@
 EXEEXT = @EXEEXT@
 FGREP = @FGREP@
 GREP = @GREP@
@@ -485,7 +485,6 @@ cscopelist-am: $(am__tagged_files)
 distclean-tags:
 	-rm -f TAGS ID GTAGS GRTAGS GSYMS GPATH tags
 	-rm -f cscope.out cscope.in.out cscope.po.out cscope.files
-
 distdir: $(BUILT_SOURCES)
 	$(MAKE) $(AM_MAKEFLAGS) distdir-am
 
diff --git a/README.md b/README.md
index 04f28b4..089cc01 100644
--- a/README.md
+++ b/README.md
@@ -30,6 +30,8 @@ For more information see: https://software.es.net/iperf
 
 Source code and issue tracker: https://github.com/esnet/iperf
 
+Discussion forums: https://github.com/esnet/iperf/discussions
+
 Obtaining iperf3
 ----------------
 
@@ -60,7 +62,7 @@ Invoking iperf3
 iperf3 includes a manual page listing all of the command-line options.
 The manual page is the most up-to-date reference to the various flags and parameters.
 
-For sample command line usage, see: 
+For sample command line usage, see:
 
 https://fasterdata.es.net/performance-testing/network-troubleshooting-tools/iperf/
 
@@ -100,11 +102,10 @@ submit an issue.  Please use one of the mailing lists for that.
 Relation to iperf 2.x
 ---------------------
 
-Note that iperf2 is no longer being developed by its original
-maintainers.  However, beginning in 2014, another developer began
-fixing bugs and enhancing functionality, and generating releases of
-iperf2.  Both projects (as of late 2017) are currently being developed
-actively, but independently.  The continuing iperf2 development
+Although iperf2 and iperf3 both measure network performance,
+they are not compatible with each other.
+The projects (as of mid-2021) are in active, but separate, development.
+The continuing iperf2 development
 project can be found at https://sourceforge.net/projects/iperf2/.
 
 iperf3 contains a number of options and functions not present in
@@ -120,7 +121,7 @@ Some iperf2 options are not available in iperf3:
 
     -r, --tradeoff           Do a bidirectional test individually
     -T, --ttl                time-to-live, for multicast (default 1)
-    -x, --reportexclude [CDMSV]   exclude C(connection) D(data) M(multicast) 
+    -x, --reportexclude [CDMSV]   exclude C(connection) D(data) M(multicast)
                                   S(settings) V(server) reports
     -y, --reportstyle C      report as a Comma-Separated Values
 
@@ -149,7 +150,7 @@ responsibility for the content of these pages.
 Copyright
 ---------
 
-iperf, Copyright (c) 2014-2021, The Regents of the University of
+iperf, Copyright (c) 2014-2022, The Regents of the University of
 California, through Lawrence Berkeley National Laboratory (subject
 to receipt of any required approvals from the U.S. Dept. of
 Energy).  All rights reserved.
diff --git a/RELNOTES.md b/RELNOTES.md
index 8bc5b33..81ad3dc 100644
--- a/RELNOTES.md
+++ b/RELNOTES.md
@@ -1,6 +1,52 @@
 iperf3 Release Notes
 ====================
 
+iperf-3.11 2022-01-31
+-----------------------
+
+* Notable user-visible changes
+
+  * Update links to Discussions in documentation
+
+  * Fix DSCP so that TOS = DSCP * 4 (#1162)
+
+  * Fix --bind-dev for TCP streams (#1153)
+
+  * Fix interface specification so doesn't overlap with IPv6 link-local addresses for -c and -B (#1157, #1180)
+
+  * Add get/set test_unit_format function declaration to iperf_api.h
+
+  * Auto adjustment of test-end condition for file transfers (-F), if no end condition is set, it will automatically adjust it to file size in bytes
+
+  * Exit if idle time expires waiting for a connection in one-off mode (#1187, #1197)
+
+  * Support zerocopy by reverse mode (#1204)
+
+  * Update help and manpage text for #1157, support bind device
+
+  * Consistently print target_bandwidth in JSON start section (#1177)
+
+  * Test bitrate added to JSON output (#1168)
+
+  * Remove fsync call after every write to receiving --file (#1176, #1159)
+
+  * Update documentation for -w (#1175)
+
+  * Fix for #952, different JSON object names for bidir reverse channel
+
+iperf-3.10.1 2021-06-03
+-----------------------
+
+* Notable user-visible changes
+
+  * Fixed a problem with autoconf scripts that made builds fail in
+    some environments (#1154 / #1155).
+
+* Developer-visible changes
+
+  * GNU autoconf 2.71 or newer is now required to regenerate iperf3's
+    configure scripts.
+
 iperf 3.10 2021-05-26
 ---------------------
 
@@ -353,7 +399,7 @@ iperf 3.2 2017-06-26
     is primarily a cosmetic change to prevent these fairly meaningless
     intervals from showing up in the output (#278).
 
-  * Compatiblity note: Users running iperf3 3.2 or newer from the
+  * Compatibility note: Users running iperf3 3.2 or newer from the
     bwctl utility will need to obtain version 1.6.3 or newer of bwctl.
     Note that bwctl, a component of the perfSONAR toolkit, has been
     deprecated in favor of pScheduler since the release of perfSONAR
@@ -858,7 +904,7 @@ iperf 3.0b3 2010-07-23
   * Better error handling
       * All errors now handled with iperf_error()
       * All functions that can return errors return NULL or -1 on error and set i_errno appropriately
-  * Iperf API intruduced
+  * Iperf API introduced
       * Support for adding new protocols
       * Added support for callback functions
           * on_connect - executes after a connection is made to the server
diff --git a/aclocal.m4 b/aclocal.m4
index 23fd689..dd8f70b 100644
--- a/aclocal.m4
+++ b/aclocal.m4
@@ -1,6 +1,6 @@
-# generated automatically by aclocal 1.16.3 -*- Autoconf -*-
+# generated automatically by aclocal 1.16.5 -*- Autoconf -*-
 
-# Copyright (C) 1996-2020 Free Software Foundation, Inc.
+# Copyright (C) 1996-2021 Free Software Foundation, Inc.
 
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9044,7 +9044,7 @@ m4_ifndef([_LT_PROG_F77],		[AC_DEFUN([_LT_PROG_F77])])
 m4_ifndef([_LT_PROG_FC],		[AC_DEFUN([_LT_PROG_FC])])
 m4_ifndef([_LT_PROG_CXX],		[AC_DEFUN([_LT_PROG_CXX])])
 
-# Copyright (C) 2002-2020 Free Software Foundation, Inc.
+# Copyright (C) 2002-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9059,7 +9059,7 @@ AC_DEFUN([AM_AUTOMAKE_VERSION],
 [am__api_version='1.16'
 dnl Some users find AM_AUTOMAKE_VERSION and mistake it for a way to
 dnl require some minimum version.  Point them to the right macro.
-m4_if([$1], [1.16.3], [],
+m4_if([$1], [1.16.5], [],
       [AC_FATAL([Do not call $0, use AM_INIT_AUTOMAKE([$1]).])])dnl
 ])
 
@@ -9075,14 +9075,14 @@ m4_define([_AM_AUTOCONF_VERSION], [])
 # Call AM_AUTOMAKE_VERSION and AM_AUTOMAKE_VERSION so they can be traced.
 # This function is AC_REQUIREd by AM_INIT_AUTOMAKE.
 AC_DEFUN([AM_SET_CURRENT_AUTOMAKE_VERSION],
-[AM_AUTOMAKE_VERSION([1.16.3])dnl
+[AM_AUTOMAKE_VERSION([1.16.5])dnl
 m4_ifndef([AC_AUTOCONF_VERSION],
   [m4_copy([m4_PACKAGE_VERSION], [AC_AUTOCONF_VERSION])])dnl
 _AM_AUTOCONF_VERSION(m4_defn([AC_AUTOCONF_VERSION]))])
 
 # AM_AUX_DIR_EXPAND                                         -*- Autoconf -*-
 
-# Copyright (C) 2001-2020 Free Software Foundation, Inc.
+# Copyright (C) 2001-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9134,7 +9134,7 @@ am_aux_dir=`cd "$ac_aux_dir" && pwd`
 
 # AM_CONDITIONAL                                            -*- Autoconf -*-
 
-# Copyright (C) 1997-2020 Free Software Foundation, Inc.
+# Copyright (C) 1997-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9165,7 +9165,7 @@ AC_CONFIG_COMMANDS_PRE(
 Usually this means the macro was only invoked conditionally.]])
 fi])])
 
-# Copyright (C) 1999-2020 Free Software Foundation, Inc.
+# Copyright (C) 1999-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9356,7 +9356,7 @@ _AM_SUBST_NOTMAKE([am__nodep])dnl
 
 # Generate code to set up dependency tracking.              -*- Autoconf -*-
 
-# Copyright (C) 1999-2020 Free Software Foundation, Inc.
+# Copyright (C) 1999-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9424,7 +9424,7 @@ AC_DEFUN([AM_OUTPUT_DEPENDENCY_COMMANDS],
 
 # Do all the work for Automake.                             -*- Autoconf -*-
 
-# Copyright (C) 1996-2020 Free Software Foundation, Inc.
+# Copyright (C) 1996-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9452,6 +9452,10 @@ m4_defn([AC_PROG_CC])
 # release and drop the old call support.
 AC_DEFUN([AM_INIT_AUTOMAKE],
 [AC_PREREQ([2.65])dnl
+m4_ifdef([_$0_ALREADY_INIT],
+  [m4_fatal([$0 expanded multiple times
+]m4_defn([_$0_ALREADY_INIT]))],
+  [m4_define([_$0_ALREADY_INIT], m4_expansion_stack)])dnl
 dnl Autoconf wants to disallow AM_ names.  We explicitly allow
 dnl the ones we care about.
 m4_pattern_allow([^AM_[A-Z]+FLAGS$])dnl
@@ -9488,7 +9492,7 @@ m4_ifval([$3], [_AM_SET_OPTION([no-define])])dnl
 [_AM_SET_OPTIONS([$1])dnl
 dnl Diagnose old-style AC_INIT with new-style AM_AUTOMAKE_INIT.
 m4_if(
-  m4_ifdef([AC_PACKAGE_NAME], [ok]):m4_ifdef([AC_PACKAGE_VERSION], [ok]),
+  m4_ifset([AC_PACKAGE_NAME], [ok]):m4_ifset([AC_PACKAGE_VERSION], [ok]),
   [ok:ok],,
   [m4_fatal([AC_INIT should be called with package and version arguments])])dnl
  AC_SUBST([PACKAGE], ['AC_PACKAGE_TARNAME'])dnl
@@ -9540,6 +9544,20 @@ AC_PROVIDE_IFELSE([AC_PROG_OBJCXX],
 		  [m4_define([AC_PROG_OBJCXX],
 			     m4_defn([AC_PROG_OBJCXX])[_AM_DEPENDENCIES([OBJCXX])])])dnl
 ])
+# Variables for tags utilities; see am/tags.am
+if test -z "$CTAGS"; then
+  CTAGS=ctags
+fi
+AC_SUBST([CTAGS])
+if test -z "$ETAGS"; then
+  ETAGS=etags
+fi
+AC_SUBST([ETAGS])
+if test -z "$CSCOPE"; then
+  CSCOPE=cscope
+fi
+AC_SUBST([CSCOPE])
+
 AC_REQUIRE([AM_SILENT_RULES])dnl
 dnl The testsuite driver may need to know about EXEEXT, so add the
 dnl 'am__EXEEXT' conditional if _AM_COMPILER_EXEEXT was seen.  This
@@ -9621,7 +9639,7 @@ for _am_header in $config_headers :; do
 done
 echo "timestamp for $_am_arg" >`AS_DIRNAME(["$_am_arg"])`/stamp-h[]$_am_stamp_count])
 
-# Copyright (C) 2001-2020 Free Software Foundation, Inc.
+# Copyright (C) 2001-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9642,7 +9660,7 @@ if test x"${install_sh+set}" != xset; then
 fi
 AC_SUBST([install_sh])])
 
-# Copyright (C) 2003-2020 Free Software Foundation, Inc.
+# Copyright (C) 2003-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9664,7 +9682,7 @@ AC_SUBST([am__leading_dot])])
 # Add --enable-maintainer-mode option to configure.         -*- Autoconf -*-
 # From Jim Meyering
 
-# Copyright (C) 1996-2020 Free Software Foundation, Inc.
+# Copyright (C) 1996-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9699,7 +9717,7 @@ AC_MSG_CHECKING([whether to enable maintainer-specific portions of Makefiles])
 
 # Check to see how 'make' treats includes.	            -*- Autoconf -*-
 
-# Copyright (C) 2001-2020 Free Software Foundation, Inc.
+# Copyright (C) 2001-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9742,7 +9760,7 @@ AC_SUBST([am__quote])])
 
 # Fake the existence of programs that GNU maintainers use.  -*- Autoconf -*-
 
-# Copyright (C) 1997-2020 Free Software Foundation, Inc.
+# Copyright (C) 1997-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9774,38 +9792,9 @@ else
 fi
 ])
 
-#  -*- Autoconf -*-
-# Obsolete and "removed" macros, that must however still report explicit
-# error messages when used, to smooth transition.
-#
-# Copyright (C) 1996-2020 Free Software Foundation, Inc.
-#
-# This file is free software; the Free Software Foundation
-# gives unlimited permission to copy and/or distribute it,
-# with or without modifications, as long as this notice is preserved.
-
-AC_DEFUN([AM_CONFIG_HEADER],
-[AC_DIAGNOSE([obsolete],
-['$0': this macro is obsolete.
-You should use the 'AC][_CONFIG_HEADERS' macro instead.])dnl
-AC_CONFIG_HEADERS($@)])
-
-AC_DEFUN([AM_PROG_CC_STDC],
-[AC_PROG_CC
-am_cv_prog_cc_stdc=$ac_cv_prog_cc_stdc
-AC_DIAGNOSE([obsolete],
-['$0': this macro is obsolete.
-You should simply use the 'AC][_PROG_CC' macro instead.
-Also, your code should no longer depend upon 'am_cv_prog_cc_stdc',
-but upon 'ac_cv_prog_cc_stdc'.])])
-
-AC_DEFUN([AM_C_PROTOTYPES],
-         [AC_FATAL([automatic de-ANSI-fication support has been removed])])
-AU_DEFUN([fp_C_PROTOTYPES], [AM_C_PROTOTYPES])
-
 # Helper functions for option handling.                     -*- Autoconf -*-
 
-# Copyright (C) 2001-2020 Free Software Foundation, Inc.
+# Copyright (C) 2001-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9834,7 +9823,7 @@ AC_DEFUN([_AM_SET_OPTIONS],
 AC_DEFUN([_AM_IF_OPTION],
 [m4_ifset(_AM_MANGLE_OPTION([$1]), [$2], [$3])])
 
-# Copyright (C) 1999-2020 Free Software Foundation, Inc.
+# Copyright (C) 1999-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9881,7 +9870,7 @@ AC_LANG_POP([C])])
 # For backward compatibility.
 AC_DEFUN_ONCE([AM_PROG_CC_C_O], [AC_REQUIRE([AC_PROG_CC])])
 
-# Copyright (C) 2001-2020 Free Software Foundation, Inc.
+# Copyright (C) 2001-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9900,7 +9889,7 @@ AC_DEFUN([AM_RUN_LOG],
 
 # Check to make sure that the build environment is sane.    -*- Autoconf -*-
 
-# Copyright (C) 1996-2020 Free Software Foundation, Inc.
+# Copyright (C) 1996-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -9981,7 +9970,7 @@ AC_CONFIG_COMMANDS_PRE(
 rm -f conftest.file
 ])
 
-# Copyright (C) 2009-2020 Free Software Foundation, Inc.
+# Copyright (C) 2009-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -10041,7 +10030,7 @@ AC_SUBST([AM_BACKSLASH])dnl
 _AM_SUBST_NOTMAKE([AM_BACKSLASH])dnl
 ])
 
-# Copyright (C) 2001-2020 Free Software Foundation, Inc.
+# Copyright (C) 2001-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -10069,7 +10058,7 @@ fi
 INSTALL_STRIP_PROGRAM="\$(install_sh) -c -s"
 AC_SUBST([INSTALL_STRIP_PROGRAM])])
 
-# Copyright (C) 2006-2020 Free Software Foundation, Inc.
+# Copyright (C) 2006-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -10088,7 +10077,7 @@ AC_DEFUN([AM_SUBST_NOTMAKE], [_AM_SUBST_NOTMAKE($@)])
 
 # Check how to create a tarball.                            -*- Autoconf -*-
 
-# Copyright (C) 2004-2020 Free Software Foundation, Inc.
+# Copyright (C) 2004-2021 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
diff --git a/config/compile b/config/compile
index 23fcba0..df363c8 100755
--- a/config/compile
+++ b/config/compile
@@ -3,7 +3,7 @@
 
 scriptversion=2018-03-07.03; # UTC
 
-# Copyright (C) 1999-2020 Free Software Foundation, Inc.
+# Copyright (C) 1999-2021 Free Software Foundation, Inc.
 # Written by Tom Tromey <tromey@cygnus.com>.
 #
 # This program is free software; you can redistribute it and/or modify
diff --git a/config/depcomp b/config/depcomp
index 6b39162..715e343 100755
--- a/config/depcomp
+++ b/config/depcomp
@@ -3,7 +3,7 @@
 
 scriptversion=2018-03-07.03; # UTC
 
-# Copyright (C) 1999-2020 Free Software Foundation, Inc.
+# Copyright (C) 1999-2021 Free Software Foundation, Inc.
 
 # This program is free software; you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
diff --git a/config/missing b/config/missing
index 8d0eaad..1fe1611 100755
--- a/config/missing
+++ b/config/missing
@@ -3,7 +3,7 @@
 
 scriptversion=2018-03-07.03; # UTC
 
-# Copyright (C) 1996-2020 Free Software Foundation, Inc.
+# Copyright (C) 1996-2021 Free Software Foundation, Inc.
 # Originally written by Fran,cois Pinard <pinard@iro.umontreal.ca>, 1996.
 
 # This program is free software; you can redistribute it and/or modify
diff --git a/configure b/configure
index eaf42a7..4f625fb 100755
--- a/configure
+++ b/configure
@@ -1,11 +1,11 @@
 #! /bin/sh
 # Guess values for system-dependent variables and create Makefiles.
-# Generated by GNU Autoconf 2.71 for iperf 3.10.
+# Generated by GNU Autoconf 2.71 for iperf 3.11.
 #
 # Report bugs to <https://github.com/esnet/iperf>.
 #
 #
-# Copyright (C) 1992-1996, 1998-2017, 2020-2021 Free Software Foundation,
+# Copyright (C) 1992-1996, 1998-2017, 2020-2022 Free Software Foundation,
 # Inc.
 #
 #
@@ -621,8 +621,8 @@ MAKEFLAGS=
 # Identity of this package.
 PACKAGE_NAME='iperf'
 PACKAGE_TARNAME='iperf'
-PACKAGE_VERSION='3.10'
-PACKAGE_STRING='iperf 3.10'
+PACKAGE_VERSION='3.11'
+PACKAGE_STRING='iperf 3.11'
 PACKAGE_BUGREPORT='https://github.com/esnet/iperf'
 PACKAGE_URL='https://software.es.net/iperf/'
 
@@ -662,7 +662,6 @@ ac_subst_vars='am__EXEEXT_FALSE
 am__EXEEXT_TRUE
 LTLIBOBJS
 LIBOBJS
-CPP
 OPENSSL_LDFLAGS
 OPENSSL_LIBS
 OPENSSL_INCLUDES
@@ -722,6 +721,9 @@ AM_BACKSLASH
 AM_DEFAULT_VERBOSITY
 AM_DEFAULT_V
 AM_V
+CSCOPE
+ETAGS
+CTAGS
 am__untar
 am__tar
 AMTAR
@@ -814,8 +816,7 @@ CFLAGS
 LDFLAGS
 LIBS
 CPPFLAGS
-LT_SYS_LIBRARY_PATH
-CPP'
+LT_SYS_LIBRARY_PATH'
 
 
 # Initialize some variables set by options.
@@ -1364,7 +1365,7 @@ if test "$ac_init_help" = "long"; then
   # Omit some internal or obsolete options to make the list less imposing.
   # This message is too long to be a string in the A/UX 3.1 sh.
   cat <<_ACEOF
-\`configure' configures iperf 3.10 to adapt to many kinds of systems.
+\`configure' configures iperf 3.11 to adapt to many kinds of systems.
 
 Usage: $0 [OPTION]... [VAR=VALUE]...
 
@@ -1435,7 +1436,7 @@ fi
 
 if test -n "$ac_init_help"; then
   case $ac_init_help in
-     short | recursive ) echo "Configuration of iperf 3.10:";;
+     short | recursive ) echo "Configuration of iperf 3.11:";;
    esac
   cat <<\_ACEOF
 
@@ -1553,7 +1554,7 @@ fi
 test -n "$ac_init_help" && exit $ac_status
 if $ac_init_version; then
   cat <<\_ACEOF
-iperf configure 3.10
+iperf configure 3.11
 generated by GNU Autoconf 2.71
 
 Copyright (C) 2021 Free Software Foundation, Inc.
@@ -1831,7 +1832,7 @@ cat >config.log <<_ACEOF
 This file contains any messages produced by compilers while
 running configure, to aid debugging if configure makes a mistake.
 
-It was created by iperf $as_me 3.10, which was
+It was created by iperf $as_me 3.11, which was
 generated by GNU Autoconf 2.71.  Invocation command line was
 
   $ $0$ac_configure_args_raw
@@ -3198,7 +3199,7 @@ fi
 
 # Define the identity of the package.
  PACKAGE='iperf'
- VERSION='3.10'
+ VERSION='3.11'
 
 
 printf "%s\n" "#define PACKAGE \"$PACKAGE\"" >>confdefs.h
@@ -3244,6 +3245,20 @@ am__tar='$${TAR-tar} chof - "$$tardir"' am__untar='$${TAR-tar} xf -'
 
 
 
+# Variables for tags utilities; see am/tags.am
+if test -z "$CTAGS"; then
+  CTAGS=ctags
+fi
+
+if test -z "$ETAGS"; then
+  ETAGS=etags
+fi
+
+if test -z "$CSCOPE"; then
+  CSCOPE=cscope
+fi
+
+
 
 # POSIX will say in a future version that running "rm -f" with no argument
 # is OK; and we want to be able to make that assumption in our Makefile
@@ -13690,88 +13705,6 @@ else
 fi
 
 
-# Checks for header files.
-# Autoupdate added the next two lines to ensure that your configure
-# script's behavior did not change.  They are probably safe to remove.
-
-{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking for egrep" >&5
-printf %s "checking for egrep... " >&6; }
-if test ${ac_cv_path_EGREP+y}
-then :
-  printf %s "(cached) " >&6
-else $as_nop
-  if echo a | $GREP -E '(a|b)' >/dev/null 2>&1
-   then ac_cv_path_EGREP="$GREP -E"
-   else
-     if test -z "$EGREP"; then
-  ac_path_EGREP_found=false
-  # Loop through the user's path and test for each of PROGNAME-LIST
-  as_save_IFS=$IFS; IFS=$PATH_SEPARATOR
-for as_dir in $PATH$PATH_SEPARATOR/usr/xpg4/bin
-do
-  IFS=$as_save_IFS
-  case $as_dir in #(((
-    '') as_dir=./ ;;
-    */) ;;
-    *) as_dir=$as_dir/ ;;
-  esac
-    for ac_prog in egrep
-   do
-    for ac_exec_ext in '' $ac_executable_extensions; do
-      ac_path_EGREP="$as_dir$ac_prog$ac_exec_ext"
-      as_fn_executable_p "$ac_path_EGREP" || continue
-# Check for GNU ac_path_EGREP and select it if it is found.
-  # Check for GNU $ac_path_EGREP
-case `"$ac_path_EGREP" --version 2>&1` in
-*GNU*)
-  ac_cv_path_EGREP="$ac_path_EGREP" ac_path_EGREP_found=:;;
-*)
-  ac_count=0
-  printf %s 0123456789 >"conftest.in"
-  while :
-  do
-    cat "conftest.in" "conftest.in" >"conftest.tmp"
-    mv "conftest.tmp" "conftest.in"
-    cp "conftest.in" "conftest.nl"
-    printf "%s\n" 'EGREP' >> "conftest.nl"
-    "$ac_path_EGREP" 'EGREP$' < "conftest.nl" >"conftest.out" 2>/dev/null || break
-    diff "conftest.out" "conftest.nl" >/dev/null 2>&1 || break
-    as_fn_arith $ac_count + 1 && ac_count=$as_val
-    if test $ac_count -gt ${ac_path_EGREP_max-0}; then
-      # Best one so far, save it but keep looking for a better one
-      ac_cv_path_EGREP="$ac_path_EGREP"
-      ac_path_EGREP_max=$ac_count
-    fi
-    # 10*(2^10) chars as input seems more than enough
-    test $ac_count -gt 10 && break
-  done
-  rm -f conftest.in conftest.tmp conftest.nl conftest.out;;
-esac
-
-      $ac_path_EGREP_found && break 3
-    done
-  done
-  done
-IFS=$as_save_IFS
-  if test -z "$ac_cv_path_EGREP"; then
-    as_fn_error $? "no acceptable egrep could be found in $PATH$PATH_SEPARATOR/usr/xpg4/bin" "$LINENO" 5
-  fi
-else
-  ac_cv_path_EGREP=$EGREP
-fi
-
-   fi
-fi
-{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $ac_cv_path_EGREP" >&5
-printf "%s\n" "$ac_cv_path_EGREP" >&6; }
- EGREP="$ac_cv_path_EGREP"
-
-
-
-
-# Check for systems which need -lsocket and -lnsl
-#AX_LIB_SOCKET_NSL
-
 # Check for the math library (needed by cjson on some platforms)
 { printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking for library containing floor" >&5
 printf %s "checking for library containing floor... " >&6; }
@@ -14524,195 +14457,24 @@ if test ${iperf3_cv_header_tcp_congestion+y}
 then :
   printf %s "(cached) " >&6
 else $as_nop
-    CPP         C preprocessor
-ac_ext=c
-ac_cpp='$CPP $CPPFLAGS'
-ac_compile='$CC -c $CFLAGS $CPPFLAGS conftest.$ac_ext >&5'
-ac_link='$CC -o conftest$ac_exeext $CFLAGS $CPPFLAGS $LDFLAGS conftest.$ac_ext $LIBS >&5'
-ac_compiler_gnu=$ac_cv_c_compiler_gnu
-{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking how to run the C preprocessor" >&5
-printf %s "checking how to run the C preprocessor... " >&6; }
-# On Suns, sometimes $CPP names a directory.
-if test -n "$CPP" && test -d "$CPP"; then
-  CPP=
-fi
-if test -z "$CPP"; then
-  if test ${ac_cv_prog_CPP+y}
-then :
-  printf %s "(cached) " >&6
-else $as_nop
-      # Double quotes because $CC needs to be expanded
-    for CPP in "$CC -E" "$CC -E -traditional-cpp" cpp /lib/cpp
-    do
-      ac_preproc_ok=false
-for ac_c_preproc_warn_flag in '' yes
-do
-  # Use a header file that comes with gcc, so configuring glibc
-  # with a fresh cross-compiler works.
-  # On the NeXT, cc -E runs the code through the compiler's parser,
-  # not just through cpp. "Syntax error" is here to catch this case.
-
-# ac_fn_c_try_cpp LINENO
-# ----------------------
-# Try to preprocess conftest.$ac_ext, and return whether this succeeded.
-ac_fn_c_try_cpp ()
-{
-  as_lineno=${as_lineno-"$1"} as_lineno_stack=as_lineno_stack=$as_lineno_stack
-  if { { ac_try="$ac_cpp conftest.$ac_ext"
-case "(($ac_try" in
-  *\"* | *\`* | *\\*) ac_try_echo=\$ac_try;;
-  *) ac_try_echo=$ac_try;;
-esac
-eval ac_try_echo="\"\$as_me:${as_lineno-$LINENO}: $ac_try_echo\""
-printf "%s\n" "$ac_try_echo"; } >&5
-  (eval "$ac_cpp conftest.$ac_ext") 2>conftest.err
-  ac_status=$?
-  if test -s conftest.err; then
-    grep -v '^ *+' conftest.err >conftest.er1
-    cat conftest.er1 >&5
-    mv -f conftest.er1 conftest.err
-  fi
-  printf "%s\n" "$as_me:${as_lineno-$LINENO}: \$? = $ac_status" >&5
-  test $ac_status = 0; } > conftest.i && {
-	 test -z "$ac_c_preproc_warn_flag$ac_c_werror_flag" ||
-	 test ! -s conftest.err
-       }
-then :
-  ac_retval=0
-else $as_nop
-  printf "%s\n" "$as_me: failed program was:" >&5
-sed 's/^/| /' conftest.$ac_ext >&5
-
-    ac_retval=1
-fi
-  eval $as_lineno_stack; ${as_lineno_stack:+:} unset as_lineno
-  as_fn_set_status $ac_retval
-
-} # ac_fn_c_try_cpp
-cat confdefs.h - <<_ACEOF >conftest.$ac_ext
-/* end confdefs.h.  */
-#include <limits.h>
-		     Syntax error
-_ACEOF
-if ac_fn_c_try_cpp "$LINENO"
-then :
-
-else $as_nop
-  # Broken: fails on valid input.
-continue
-fi
-rm -f conftest.err conftest.i conftest.$ac_ext
-
-  # OK, works on sane cases.  Now check whether nonexistent headers
-  # can be detected and how.
-  cat confdefs.h - <<_ACEOF >conftest.$ac_ext
-/* end confdefs.h.  */
-#include <ac_nonexistent.h>
-_ACEOF
-if ac_fn_c_try_cpp "$LINENO"
-then :
-  # Broken: success on invalid input.
-continue
-else $as_nop
-  # Passes both tests.
-ac_preproc_ok=:
-break
-fi
-rm -f conftest.err conftest.i conftest.$ac_ext
-
-done
-# Because of `break', _AC_PREPROC_IFELSE's cleaning code was skipped.
-rm -f conftest.i conftest.err conftest.$ac_ext
-if $ac_preproc_ok
-then :
-  break
-fi
-
-    done
-    ac_cv_prog_CPP=$CPP
-
-fi
-  CPP=$ac_cv_prog_CPP
-else
-  ac_cv_prog_CPP=$CPP
-fi
-{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $CPP" >&5
-printf "%s\n" "$CPP" >&6; }
-ac_preproc_ok=false
-for ac_c_preproc_warn_flag in '' yes
-do
-  # Use a header file that comes with gcc, so configuring glibc
-  # with a fresh cross-compiler works.
-  # On the NeXT, cc -E runs the code through the compiler's parser,
-  # not just through cpp. "Syntax error" is here to catch this case.
-  cat confdefs.h - <<_ACEOF >conftest.$ac_ext
-/* end confdefs.h.  */
-#include <limits.h>
-		     Syntax error
-_ACEOF
-if ac_fn_c_try_cpp "$LINENO"
-then :
-
-else $as_nop
-  # Broken: fails on valid input.
-continue
-fi
-rm -f conftest.err conftest.i conftest.$ac_ext
-
-  # OK, works on sane cases.  Now check whether nonexistent headers
-  # can be detected and how.
   cat confdefs.h - <<_ACEOF >conftest.$ac_ext
 /* end confdefs.h.  */
-#include <ac_nonexistent.h>
-_ACEOF
-if ac_fn_c_try_cpp "$LINENO"
-then :
-  # Broken: success on invalid input.
-continue
-else $as_nop
-  # Passes both tests.
-ac_preproc_ok=:
-break
-fi
-rm -f conftest.err conftest.i conftest.$ac_ext
-
-done
-# Because of `break', _AC_PREPROC_IFELSE's cleaning code was skipped.
-rm -f conftest.i conftest.err conftest.$ac_ext
-if $ac_preproc_ok
-then :
-
-else $as_nop
-  { { printf "%s\n" "$as_me:${as_lineno-$LINENO}: error: in \`$ac_pwd':" >&5
-printf "%s\n" "$as_me: error: in \`$ac_pwd':" >&2;}
-as_fn_error $? "C preprocessor \"$CPP\" fails sanity check
-See \`config.log' for more details" "$LINENO" 5; }
-fi
-
-ac_ext=c
-ac_cpp='$CPP $CPPFLAGS'
-ac_compile='$CC -c $CFLAGS $CPPFLAGS conftest.$ac_ext >&5'
-ac_link='$CC -o conftest$ac_exeext $CFLAGS $CPPFLAGS $LDFLAGS conftest.$ac_ext $LIBS >&5'
-ac_compiler_gnu=$ac_cv_c_compiler_gnu
-
-
-cat confdefs.h - <<_ACEOF >conftest.$ac_ext
-/* end confdefs.h.  */
 #include <netinet/tcp.h>
-#ifdef TCP_CONGESTION
-  yes
-#endif
-
+int
+main (void)
+{
+int foo = TCP_CONGESTION;
+  ;
+  return 0;
+}
 _ACEOF
-if (eval "$ac_cpp conftest.$ac_ext") 2>&5 |
-  $EGREP "yes" >/dev/null 2>&1
+if ac_fn_c_try_compile "$LINENO"
 then :
   iperf3_cv_header_tcp_congestion=yes
 else $as_nop
   iperf3_cv_header_tcp_congestion=no
 fi
-rm -rf conftest*
-
+rm -f core conftest.err conftest.$ac_objext conftest.beam conftest.$ac_ext
 fi
 { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $iperf3_cv_header_tcp_congestion" >&5
 printf "%s\n" "$iperf3_cv_header_tcp_congestion" >&6; }
@@ -14735,21 +14497,22 @@ else $as_nop
   cat confdefs.h - <<_ACEOF >conftest.$ac_ext
 /* end confdefs.h.  */
 #include <sys/types.h>
-#include <linux/in6.h>
-#ifdef IPV6_FLOWLABEL_MGR
-  yes
-#endif
-
+                     #include <linux/in6.h>
+int
+main (void)
+{
+int foo = IPV6_FLOWLABEL_MGR;
+  ;
+  return 0;
+}
 _ACEOF
-if (eval "$ac_cpp conftest.$ac_ext") 2>&5 |
-  $EGREP "yes" >/dev/null 2>&1
+if ac_fn_c_try_compile "$LINENO"
 then :
   iperf3_cv_header_flowlabel=yes
 else $as_nop
   iperf3_cv_header_flowlabel=no
 fi
-rm -rf conftest*
-
+rm -f core conftest.err conftest.$ac_objext conftest.beam conftest.$ac_ext
 fi
 { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $iperf3_cv_header_flowlabel" >&5
 printf "%s\n" "$iperf3_cv_header_flowlabel" >&6; }
@@ -14821,20 +14584,21 @@ else $as_nop
   cat confdefs.h - <<_ACEOF >conftest.$ac_ext
 /* end confdefs.h.  */
 #include <sys/socket.h>
-#ifdef SO_MAX_PACING_RATE
-  yes
-#endif
-
+int
+main (void)
+{
+int foo = SO_MAX_PACING_RATE;
+  ;
+  return 0;
+}
 _ACEOF
-if (eval "$ac_cpp conftest.$ac_ext") 2>&5 |
-  $EGREP "yes" >/dev/null 2>&1
+if ac_fn_c_try_compile "$LINENO"
 then :
   iperf3_cv_header_so_max_pacing_rate=yes
 else $as_nop
   iperf3_cv_header_so_max_pacing_rate=no
 fi
-rm -rf conftest*
-
+rm -f core conftest.err conftest.$ac_objext conftest.beam conftest.$ac_ext
 fi
 { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $iperf3_cv_header_so_max_pacing_rate" >&5
 printf "%s\n" "$iperf3_cv_header_so_max_pacing_rate" >&6; }
@@ -14854,20 +14618,21 @@ else $as_nop
   cat confdefs.h - <<_ACEOF >conftest.$ac_ext
 /* end confdefs.h.  */
 #include <sys/socket.h>
-#ifdef SO_BINDTODEVICE
-  yes
-#endif
-
+int
+main (void)
+{
+int foo = SO_BINDTODEVICE;
+  ;
+  return 0;
+}
 _ACEOF
-if (eval "$ac_cpp conftest.$ac_ext") 2>&5 |
-  $EGREP "yes" >/dev/null 2>&1
+if ac_fn_c_try_compile "$LINENO"
 then :
   iperf3_cv_header_so_bindtodevice=yes
 else $as_nop
   iperf3_cv_header_so_bindtodevice=no
 fi
-rm -rf conftest*
-
+rm -f core conftest.err conftest.$ac_objext conftest.beam conftest.$ac_ext
 fi
 { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $iperf3_cv_header_so_bindtodevice" >&5
 printf "%s\n" "$iperf3_cv_header_so_bindtodevice" >&6; }
@@ -14877,47 +14642,139 @@ printf "%s\n" "#define HAVE_SO_BINDTODEVICE 1" >>confdefs.h
 
 fi
 
-# Check for IP DF support
-{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking IP_MTU_DISCOVER or IP_DONTFRAG socket option" >&5
-printf %s "checking IP_MTU_DISCOVER or IP_DONTFRAG socket option... " >&6; }
-if test ${iperf3_cv_header_dontfragment+y}
+# Check for IP_MTU_DISCOVER (mostly on Linux)
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking IP_MTU_DISCOVER socket option" >&5
+printf %s "checking IP_MTU_DISCOVER socket option... " >&6; }
+if test ${iperf3_cv_header_ip_mtu_discover+y}
 then :
   printf %s "(cached) " >&6
 else $as_nop
   cat confdefs.h - <<_ACEOF >conftest.$ac_ext
 /* end confdefs.h.  */
-#include <sys/socket.h>
-#include <netinet/ip.h>
-#include <netinet/in.h>
-#ifdef IP_MTU_DISCOVER
-  yes
-#endif
-#ifdef IP_DONTFRAG
-  yes
-#endif
-#ifdef IP_DONTFRAGMENT
-  yes
-#endif
+#include <sys/types.h>
+                     #include <sys/socket.h>
+                     #include <netinet/in.h>
+int
+main (void)
+{
+int foo = IP_MTU_DISCOVER;
+  ;
+  return 0;
+}
+_ACEOF
+if ac_fn_c_try_compile "$LINENO"
+then :
+  iperf3_cv_header_ip_mtu_discover=yes
+else $as_nop
+  iperf3_cv_header_ip_mtu_discover=no
+fi
+rm -f core conftest.err conftest.$ac_objext conftest.beam conftest.$ac_ext
+fi
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $iperf3_cv_header_ip_mtu_discover" >&5
+printf "%s\n" "$iperf3_cv_header_ip_mtu_discover" >&6; }
+if test "x$iperf3_cv_header_ip_mtu_discover" = "xyes"; then
+
+printf "%s\n" "#define HAVE_IP_MTU_DISCOVER 1" >>confdefs.h
 
+fi
+
+# Check for IP_DONTFRAG (BSD?)
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking IP_DONTFRAG socket option" >&5
+printf %s "checking IP_DONTFRAG socket option... " >&6; }
+if test ${iperf3_cv_header_ip_dontfrag+y}
+then :
+  printf %s "(cached) " >&6
+else $as_nop
+  cat confdefs.h - <<_ACEOF >conftest.$ac_ext
+/* end confdefs.h.  */
+#include <sys/types.h>
+                     #include <sys/socket.h>
+                     #include <netinet/in.h>
+int
+main (void)
+{
+int foo = IP_DONTFRAG;
+  ;
+  return 0;
+}
 _ACEOF
-if (eval "$ac_cpp conftest.$ac_ext") 2>&5 |
-  $EGREP "yes" >/dev/null 2>&1
+if ac_fn_c_try_compile "$LINENO"
 then :
-  iperf3_cv_header_dontfragment=yes
+  iperf3_cv_header_ip_dontfrag=yes
 else $as_nop
-  iperf3_cv_header_dontfragment=no
+  iperf3_cv_header_ip_dontfrag=no
+fi
+rm -f core conftest.err conftest.$ac_objext conftest.beam conftest.$ac_ext
 fi
-rm -rf conftest*
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $iperf3_cv_header_ip_dontfrag" >&5
+printf "%s\n" "$iperf3_cv_header_ip_dontfrag" >&6; }
+if test "x$iperf3_cv_header_ip_dontfrag" = "xyes"; then
 
+printf "%s\n" "#define HAVE_IP_DONTFRAG 1" >>confdefs.h
+
+fi
+
+# Check for IP_DONTFRAGMENT (Windows?)
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking IP_DONTFRAGMENT socket option" >&5
+printf %s "checking IP_DONTFRAGMENT socket option... " >&6; }
+if test ${iperf3_cv_header_ip_dontfragment+y}
+then :
+  printf %s "(cached) " >&6
+else $as_nop
+  cat confdefs.h - <<_ACEOF >conftest.$ac_ext
+/* end confdefs.h.  */
+#include <sys/types.h>
+                     #include <sys/socket.h>
+                     #include <netinet/in.h>
+int
+main (void)
+{
+int foo = IP_DONTFRAGMENT;
+  ;
+  return 0;
+}
+_ACEOF
+if ac_fn_c_try_compile "$LINENO"
+then :
+  iperf3_cv_header_ip_dontfragment=yes
+else $as_nop
+  iperf3_cv_header_ip_dontfragment=no
+fi
+rm -f core conftest.err conftest.$ac_objext conftest.beam conftest.$ac_ext
+fi
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $iperf3_cv_header_ip_dontfragment" >&5
+printf "%s\n" "$iperf3_cv_header_ip_dontfragment" >&6; }
+if test "x$iperf3_cv_header_ip_dontfragment" = "xyes"; then
+
+printf "%s\n" "#define HAVE_IP_DONTFRAGMENT 1" >>confdefs.h
+
+fi
+
+# Check for IP DF support
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking any kind of DF socket option" >&5
+printf %s "checking any kind of DF socket option... " >&6; }
+if test ${iperf3_cv_header_dontfragment+y}
+then :
+  printf %s "(cached) " >&6
+else $as_nop
+  if test "x$iperf3_cv_header_ip_mtu_discover" = "xyes" -o "x$iperf3_cv_header_ip_dontfrag" = "xyes" -o "x$iperf3_cv_header_ip_dontfragment" = "xyes"; then
+  iperf3_cv_header_dontfragment=yes
+else
+  iperf3_cv_header_dontfragment=no
+fi
 fi
 { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $iperf3_cv_header_dontfragment" >&5
 printf "%s\n" "$iperf3_cv_header_dontfragment" >&6; }
+
 if test "x$iperf3_cv_header_dontfragment" = "xyes"; then
 
 printf "%s\n" "#define HAVE_DONT_FRAGMENT 1" >>confdefs.h
 
 fi
 
+#
+# Check for tcpi_snd_wnd in struct tcp_info
+#
 ac_fn_c_check_member "$LINENO" "struct tcp_info" "tcpi_snd_wnd" "ac_cv_member_struct_tcp_info_tcpi_snd_wnd" "#ifdef HAVE_LINUX_TCP_H
 #include <linux/tcp.h>
 #else
@@ -15104,6 +14961,7 @@ DEFS=-DHAVE_CONFIG_H
 
 ac_libobjs=
 ac_ltlibobjs=
+U=
 for ac_i in : $LIBOBJS; do test "x$ac_i" = x: && continue
   # 1. Remove the extension, and $U if already installed.
   ac_script='s/\$U\././;s/\.o$//;s/\.obj$//'
@@ -15548,7 +15406,7 @@ cat >>$CONFIG_STATUS <<\_ACEOF || ac_write_fail=1
 # report actual input values of CONFIG_FILES etc. instead of their
 # values after options handling.
 ac_log="
-This file was extended by iperf $as_me 3.10, which was
+This file was extended by iperf $as_me 3.11, which was
 generated by GNU Autoconf 2.71.  Invocation command line was
 
   CONFIG_FILES    = $CONFIG_FILES
@@ -15617,7 +15475,7 @@ ac_cs_config_escaped=`printf "%s\n" "$ac_cs_config" | sed "s/^ //; s/'/'\\\\\\\\
 cat >>$CONFIG_STATUS <<_ACEOF || ac_write_fail=1
 ac_cs_config='$ac_cs_config_escaped'
 ac_cs_version="\\
-iperf config.status 3.10
+iperf config.status 3.11
 configured by $0, generated by GNU Autoconf 2.71,
   with options \\"\$ac_cs_config\\"
 
diff --git a/configure.ac b/configure.ac
index 88c3b11..53a4db4 100644
--- a/configure.ac
+++ b/configure.ac
@@ -1,4 +1,4 @@
-# iperf, Copyright (c) 2014-2021, The Regents of the University of
+# iperf, Copyright (c) 2014-2022, The Regents of the University of
 # California, through Lawrence Berkeley National Laboratory (subject
 # to receipt of any required approvals from the U.S. Dept. of
 # Energy).  All rights reserved.
@@ -24,7 +24,8 @@
 # file for complete information.
 
 # Initialize the autoconf system for the specified tool, version and mailing list
-AC_INIT([iperf],[3.10],[https://github.com/esnet/iperf],[iperf],[https://software.es.net/iperf/])
+AC_PREREQ([2.71])
+AC_INIT([iperf],[3.11],[https://github.com/esnet/iperf],[iperf],[https://software.es.net/iperf/])
 m4_include([config/ax_check_openssl.m4])
 m4_include([config/iperf_config_static_bin.m4])
 AC_LANG(C)
@@ -40,7 +41,7 @@ m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
 LT_INIT
 
 AM_MAINTAINER_MODE
-AM_CONFIG_HEADER(src/iperf_config.h)
+AC_CONFIG_HEADERS(src/iperf_config.h)
 
 AC_CANONICAL_HOST
 
@@ -61,20 +62,6 @@ AC_ARG_ENABLE([profiling],
     AS_HELP_STRING([--enable-profiling], [Enable iperf3 profiling binary]))
 AM_CONDITIONAL([ENABLE_PROFILING], [test x$enable_profiling = xyes])
 
-# Checks for header files.
-m4_warn([obsolete],
-[The preprocessor macro `STDC_HEADERS' is obsolete.
-  Except in unusual embedded environments, you can safely include all
-  ISO C90 headers unconditionally.])dnl
-# Autoupdate added the next two lines to ensure that your configure
-# script's behavior did not change.  They are probably safe to remove.
-AC_CHECK_INCLUDES_DEFAULT
-AC_PROG_EGREP
-
-
-# Check for systems which need -lsocket and -lnsl
-#AX_LIB_SOCKET_NSL
-
 # Check for the math library (needed by cjson on some platforms)
 AC_SEARCH_LIBS(floor, [m], [], [
 echo "floor()"
@@ -173,12 +160,11 @@ fi
 # Check for TCP_CONGESTION sockopt (believed to be Linux and FreeBSD only)
 AC_CACHE_CHECK([TCP_CONGESTION socket option],
 [iperf3_cv_header_tcp_congestion],
-AC_EGREP_CPP(yes,
-[#include <netinet/tcp.h>
-#ifdef TCP_CONGESTION
-  yes
-#endif
-],iperf3_cv_header_tcp_congestion=yes,iperf3_cv_header_tcp_congestion=no))
+AC_COMPILE_IFELSE(
+  [AC_LANG_PROGRAM([[#include <netinet/tcp.h>]],
+                   [[int foo = TCP_CONGESTION;]])],
+  iperf3_cv_header_tcp_congestion=yes,
+  iperf3_cv_header_tcp_congestion=no))
 if test "x$iperf3_cv_header_tcp_congestion" = "xyes"; then
     AC_DEFINE([HAVE_TCP_CONGESTION], [1], [Have TCP_CONGESTION sockopt.])
 fi
@@ -189,13 +175,12 @@ fi
 # copy, see src/flowlabel.h for more details).
 AC_CACHE_CHECK([IPv6 flowlabel support],
 [iperf3_cv_header_flowlabel],
-AC_EGREP_CPP(yes,
-[#include <sys/types.h>
-#include <linux/in6.h>
-#ifdef IPV6_FLOWLABEL_MGR
-  yes
-#endif
-],iperf3_cv_header_flowlabel=yes,iperf3_cv_header_flowlabel=no))
+AC_COMPILE_IFELSE(
+  [AC_LANG_PROGRAM([[#include <sys/types.h>
+                     #include <linux/in6.h>]],
+                   [[int foo = IPV6_FLOWLABEL_MGR;]])],
+  iperf3_cv_header_flowlabel=yes,
+  iperf3_cv_header_flowlabel=no))
 if test "x$iperf3_cv_header_flowlabel" = "xyes"; then
     AC_DEFINE([HAVE_FLOWLABEL], [1], [Have IPv6 flowlabel support.])
 fi
@@ -224,12 +209,11 @@ AC_CHECK_FUNCS([getline])
 # Check for packet pacing socket option (Linux only for now).
 AC_CACHE_CHECK([SO_MAX_PACING_RATE socket option],
 [iperf3_cv_header_so_max_pacing_rate],
-AC_EGREP_CPP(yes,
-[#include <sys/socket.h>
-#ifdef SO_MAX_PACING_RATE
-  yes
-#endif
-],iperf3_cv_header_so_max_pacing_rate=yes,iperf3_cv_header_so_max_pacing_rate=no))
+AC_COMPILE_IFELSE(
+  [AC_LANG_PROGRAM([[#include <sys/socket.h>]],
+                   [[int foo = SO_MAX_PACING_RATE;]])],
+  iperf3_cv_header_so_max_pacing_rate=yes,
+  iperf3_cv_header_so_max_pacing_rate=no))
 if test "x$iperf3_cv_header_so_max_pacing_rate" = "xyes"; then
     AC_DEFINE([HAVE_SO_MAX_PACING_RATE], [1], [Have SO_MAX_PACING_RATE sockopt.])
 fi
@@ -237,37 +221,73 @@ fi
 # Check for SO_BINDTODEVICE sockopt (believed to be Linux only)
 AC_CACHE_CHECK([SO_BINDTODEVICE socket option],
 [iperf3_cv_header_so_bindtodevice],
-AC_EGREP_CPP(yes,
-[#include <sys/socket.h>
-#ifdef SO_BINDTODEVICE
-  yes
-#endif
-],iperf3_cv_header_so_bindtodevice=yes,iperf3_cv_header_so_bindtodevice=no))
+AC_COMPILE_IFELSE(
+  [AC_LANG_PROGRAM([[#include <sys/socket.h>]],
+                   [[int foo = SO_BINDTODEVICE;]])],
+  iperf3_cv_header_so_bindtodevice=yes,
+  iperf3_cv_header_so_bindtodevice=no))
 if test "x$iperf3_cv_header_so_bindtodevice" = "xyes"; then
     AC_DEFINE([HAVE_SO_BINDTODEVICE], [1], [Have SO_BINDTODEVICE sockopt.])
 fi
 
+# Check for IP_MTU_DISCOVER (mostly on Linux)
+AC_CACHE_CHECK([IP_MTU_DISCOVER socket option],
+[iperf3_cv_header_ip_mtu_discover],
+AC_COMPILE_IFELSE(
+  [AC_LANG_PROGRAM([[#include <sys/types.h>
+                     #include <sys/socket.h>
+                     #include <netinet/in.h>]],
+                   [[int foo = IP_MTU_DISCOVER;]])],
+  iperf3_cv_header_ip_mtu_discover=yes,
+  iperf3_cv_header_ip_mtu_discover=no))
+if test "x$iperf3_cv_header_ip_mtu_discover" = "xyes"; then
+    AC_DEFINE([HAVE_IP_MTU_DISCOVER], [1], [Have IP_MTU_DISCOVER sockopt.])
+fi
+
+# Check for IP_DONTFRAG (BSD?)
+AC_CACHE_CHECK([IP_DONTFRAG socket option],
+[iperf3_cv_header_ip_dontfrag],
+AC_COMPILE_IFELSE(
+  [AC_LANG_PROGRAM([[#include <sys/types.h>
+                     #include <sys/socket.h>
+                     #include <netinet/in.h>]],
+                   [[int foo = IP_DONTFRAG;]])],
+  iperf3_cv_header_ip_dontfrag=yes,
+  iperf3_cv_header_ip_dontfrag=no))
+if test "x$iperf3_cv_header_ip_dontfrag" = "xyes"; then
+    AC_DEFINE([HAVE_IP_DONTFRAG], [1], [Have IP_DONTFRAG sockopt.])
+fi
+
+# Check for IP_DONTFRAGMENT (Windows?)
+AC_CACHE_CHECK([IP_DONTFRAGMENT socket option],
+[iperf3_cv_header_ip_dontfragment],
+AC_COMPILE_IFELSE(
+  [AC_LANG_PROGRAM([[#include <sys/types.h>
+                     #include <sys/socket.h>
+                     #include <netinet/in.h>]],
+                   [[int foo = IP_DONTFRAGMENT;]])],
+  iperf3_cv_header_ip_dontfragment=yes,
+  iperf3_cv_header_ip_dontfragment=no))
+if test "x$iperf3_cv_header_ip_dontfragment" = "xyes"; then
+    AC_DEFINE([HAVE_IP_DONTFRAGMENT], [1], [Have IP_DONTFRAGMENT sockopt.])
+fi
+
 # Check for IP DF support
-AC_CACHE_CHECK([IP_MTU_DISCOVER or IP_DONTFRAG socket option],
+AC_CACHE_CHECK([any kind of DF socket option],
 [iperf3_cv_header_dontfragment],
-AC_EGREP_CPP(yes,
-[#include <sys/socket.h>
-#include <netinet/ip.h>
-#include <netinet/in.h>
-#ifdef IP_MTU_DISCOVER
-  yes
-#endif
-#ifdef IP_DONTFRAG
-  yes
-#endif
-#ifdef IP_DONTFRAGMENT
-  yes
-#endif
-],iperf3_cv_header_dontfragment=yes,iperf3_cv_header_dontfragment=no))
+[if test "x$iperf3_cv_header_ip_mtu_discover" = "xyes" -o "x$iperf3_cv_header_ip_dontfrag" = "xyes" -o "x$iperf3_cv_header_ip_dontfragment" = "xyes"; then
+  iperf3_cv_header_dontfragment=yes
+else
+  iperf3_cv_header_dontfragment=no
+fi])
+
 if test "x$iperf3_cv_header_dontfragment" = "xyes"; then
-    AC_DEFINE([HAVE_DONT_FRAGMENT], [1], [Have IP_MTU_DISCOVER/IP_DONTFRAG sockopt.])
+    AC_DEFINE([HAVE_DONT_FRAGMENT], [1], [Have IP_MTU_DISCOVER/IP_DONTFRAG/IP_DONTFRAGMENT sockopt.])
 fi
 
+#
+# Check for tcpi_snd_wnd in struct tcp_info
+#
 AC_CHECK_MEMBER([struct tcp_info.tcpi_snd_wnd],
 [iperf3_cv_header_tcp_info_snd_wnd=yes], [iperf3_cv_header_tcp_info_snd_wnd=no],
 [#ifdef HAVE_LINUX_TCP_H
diff --git a/contrib/iperf3.gp b/contrib/iperf3.gp
index 0bf49ea..898422c 100644
--- a/contrib/iperf3.gp
+++ b/contrib/iperf3.gp
@@ -1,7 +1,7 @@
 #
 # sample Gnuplot command file for iperf3 results
 set term x11
-#set term png 
+#set term png
 #set term postscript landscape color
 set key width -12
 
@@ -19,11 +19,11 @@ set grid linewidth 1
 set title "TCP performance: 40G to 10G host"
 set xlabel "time (seconds)"
 set ylabel "Bandwidth (Gbits/second)"
-set xrange [0:60] 
-set yrange [0:15] 
+set xrange [0:60]
+set yrange [0:15]
 set ytics nomirror
 set y2tics
-set y2range [0:2500] 
+set y2range [0:2500]
 # dont plot when retransmits = 0
 set datafile missing '0'
 set pointsize 1.6
@@ -34,4 +34,3 @@ plot "40Gto10G.old.dat" using 1:3 title '3.10 kernel' with linespoints lw 3 pt 5
 
 #plot "iperf3.old.dat" using 1:3 title '3.10 kernel' with linespoints lw 3 pt 5, \
 #	 "iperf3.new.dat" using 1:3 title '4.2 kernel' with linespoints lw 3 pt 7
-
diff --git a/docs/2017-04-27.txt b/docs/2017-04-27.txt
index 4bd4fcb..dc8206e 100644
--- a/docs/2017-04-27.txt
+++ b/docs/2017-04-27.txt
@@ -7,7 +7,7 @@ State of the iperf3 World, as seen from ESnet...
 ------------------------------------------------
 
 iperf3 was originally written to be a "better", more maintainable
-follow-on to iperf2.  This was seen to be necessary to fill the 
+follow-on to iperf2.  This was seen to be necessary to fill the
 requirements for the perfSONAR project (http://www.perfsonar.net).
 
 In the past few years, iperf2 development has been restarted by Bob
diff --git a/docs/building.rst b/docs/building.rst
index 6f6dab1..9494d00 100644
--- a/docs/building.rst
+++ b/docs/building.rst
@@ -24,4 +24,3 @@ help to run ``./bootstrap.sh`` first from the top-level directory.
 By default, the ``libiperf`` library is built in both shared and
 static forms.  Either can be suppressed by using the
 ``--disabled-shared`` or ``--disable-static`` configure-time options.
-
diff --git a/docs/conf.py b/docs/conf.py
index 7078c37..71faa54 100644
--- a/docs/conf.py
+++ b/docs/conf.py
@@ -45,17 +45,17 @@ master_doc = 'index'
 
 # General information about the project.
 project = u'iperf3'
-copyright = u'2014-2021, ESnet'
+copyright = u'2014-2022, ESnet'
 
 # The version info for the project you're documenting, acts as replacement for
 # |version| and |release|, also used in various other places throughout the
 # built documents.
 #
 # The short X.Y version.
-version = '3.9'
+version = '3.10.1'
 # The full version, including alpha/beta/rc tags.
 
-release = '3.9'
+release = '3.10.1'
 
 # The language for content autogenerated by Sphinx. Refer to documentation
 # for a list of supported languages.
diff --git a/docs/dev.rst b/docs/dev.rst
index a2ff60c..3cfab78 100644
--- a/docs/dev.rst
+++ b/docs/dev.rst
@@ -25,7 +25,7 @@ Bug Reports
 -----------
 
 Before submitting a bug report, try checking out the latest version of
-the code, and confirm that it's not already fixed. Also see the :doc:`faq`. 
+the code, and confirm that it's not already fixed. Also see the :doc:`faq`.
 Then submit to the iperf3 issue tracker on GitHub:
 
 https://github.com/esnet/iperf/issues
@@ -47,7 +47,7 @@ for a complete list of iperf3 options)::
     -T, --title str           prefix every output line with this string
     -F, --file name           xmit/recv the specified file
     -A, --affinity n/n,m      set CPU affinity (Linux and FreeBSD only)
-    -k, --blockcount #[KMG]   number of blocks (packets) to transmit (instead 
+    -k, --blockcount #[KMG]   number of blocks (packets) to transmit (instead
                               of -t or -n)
     -L, --flowlabel           set IPv6 flow label (Linux only)
 
@@ -62,7 +62,7 @@ Deprecated flags (currently no plans to support)::
     -d, --dualtest           Do a bidirectional test simultaneously
     -r, --tradeoff           Do a bidirectional test individually
     -T, --ttl                time-to-live, for multicast (default 1)
-    -x, --reportexclude [CDMSV]   exclude C(connection) D(data) M(multicast) 
+    -x, --reportexclude [CDMSV]   exclude C(connection) D(data) M(multicast)
                                   S(settings) V(server) reports
     -y, --reportstyle C      report as a Comma-Separated Values
 
@@ -176,7 +176,7 @@ Release Engineering Checklist
 7. For extra points, actually try downloading, compiling, and
    smoke-testing the results of the tarball on all supported
    platforms.
-   
+
 8. Plug the SHA256 checksum into the release announcement.
 
 9. PGP-sign the release announcement text using ``gpg --clearsign``.
@@ -233,7 +233,7 @@ Code Authors
 The main authors of iperf3 are (in alphabetical order):  Jon Dugan,
 Seth Elliott, Bruce A. Mah, Jeff Poskanzer, Kaustubh Prabhu.
 Additional code contributions have come from (also in alphabetical
-order):  Mark Ashley, Aaron Brown, Aeneas Jaißle, Susant Sahani, 
+order):  Mark Ashley, Aaron Brown, Aeneas Jaißle, Susant Sahani,
 Bruce Simpson, Brian Tierney.
 
 iperf3 contains some original code from iperf2.  The authors of iperf2
diff --git a/docs/faq.rst b/docs/faq.rst
index d7d182e..7b70026 100644
--- a/docs/faq.rst
+++ b/docs/faq.rst
@@ -13,27 +13,27 @@ What is the history of iperf3, and what is the difference between iperf2 and ipe
   threaded, and not worry about backwards compatibility with
   iperf2. Many of the feature requests for iperf3 came from the
   perfSONAR project (http://www.perfsonar.net).
- 
+
   Then in 2014, Bob (Robert) McMahon from Broadcom restarted
   development of iperf2 (See
   https://sourceforge.net/projects/iperf2/). He fixed many of the
   problems with iperf2, and added a number of new features similar to
-  iperf3. iperf2.0.8, released in 2015, made iperf2 a useful tool. iperf2's 
+  iperf3. iperf2.0.8, released in 2015, made iperf2 a useful tool. iperf2's
   current development is focused is on using UDP for latency testing, as well
   as broad platform support.
- 
+
   As of this writing (2017), both iperf2 and iperf3 are being actively
   (although independently) developed.  We recommend being familiar with
   both tools, and use whichever tool’s features best match your needs.
- 
+
   A feature comparison of iperf2, iperf3, and nuttcp is available at:
   https://fasterdata.es.net/performance-testing/network-troubleshooting-tools/throughput-tool-comparision/
- 
+
 iperf3 parallel stream performance is much less than iperf2. Why?
   iperf3 is single threaded, and iperf2 is multi-threaded. We
   recommend using iperf2 for parallel streams.
   If you want to use multiple iperf3 streams use the method described `here <https://fasterdata.es.net/performance-testing/network-troubleshooting-tools/iperf/multi-stream-iperf3/>`_.
- 
+
 I’m trying to use iperf3 on Windows, but having trouble. What should I do?
   iperf3 is not officially supported on Windows, but iperf2 is. We
   recommend you use iperf2.
@@ -41,7 +41,7 @@ I’m trying to use iperf3 on Windows, but having trouble. What should I do?
   Some people are using Cygwin to run iperf3 in Windows, but not all
   options will work.  Some community-provided binaries of iperf3 for
   Windows exist.
- 
+
 How can I build a statically-linked executable of iperf3?
   There are a number of reasons for building an iperf3 executable with
   no dependencies on any shared libraries.  Unfortunately this isn't
@@ -116,17 +116,17 @@ How can I build on a system that doesn't support profiled executables?
 
      And then run ``./bootstrap.sh``, that will regenerate the project
      Makefiles to make the exclusion of the profiled iperf3 executable
-     permanant (within that source tree).
+     permanent (within that source tree).
 
 I'm seeing quite a bit of unexpected UDP loss. Why?
   First, confirm you are using iperf 3.1.5 or higher. There was an
   issue with the default UDP send size that was fixed in
   3.1.5. Second, try adding the flag ``-w2M`` to increase the socket
   buffer sizes. That seems to make a big difference on some hosts.
- 
+
 iperf3 UDP does not seem to work at bandwidths less than 100Kbps. Why?
   You'll need to reduce the default packet length to get UDP rates of less that 100Kbps. Try ``-l100``.
- 
+
 TCP throughput drops to (almost) zero during a test, what's going on?
   A drop in throughput to almost zero, except maybe for the first
   reported interval(s), may be related to problems in NIC TCP Offload,
@@ -184,13 +184,13 @@ What congestion control algorithms are supported?
   On Linux, run this command to see the available congestion control
   algorithms (note that some algorithms are packaged as kernel
   modules, which must be loaded before they can be used)::
-    
+
     /sbin/sysctl net.ipv4.tcp_available_congestion_control
 
   On FreeBSD, the equivalent command is::
 
     /sbin/sysctl net.inet.tcp.cc.available
- 
+
 I’m using the ``--logfile`` option. How do I see file output in real time?
   Use the ``--forceflush`` flag.
 
@@ -252,5 +252,3 @@ I have a question regarding iperf3...what's the best way to get help?
   We discourage the use of the iperf3 issue tracker on GitHub for
   support questions.  Actual bug reports, enhancement requests, or
   pull requests are encouraged, however.
-
-
diff --git a/docs/index.rst b/docs/index.rst
index 1094028..0f4b4c6 100644
--- a/docs/index.rst
+++ b/docs/index.rst
@@ -68,4 +68,3 @@ Indices and tables
 * :ref:`genindex`
 * :ref:`modindex`
 * :ref:`search`
-
diff --git a/docs/invoking.rst b/docs/invoking.rst
index b1fc5c2..22cc48f 100644
--- a/docs/invoking.rst
+++ b/docs/invoking.rst
@@ -4,7 +4,7 @@ Invoking iperf3
 iperf3 includes a manual page listing all of the command-line options.
 The manual page is the most up-to-date reference to the various flags and parameters.
 
-For sample command line usage, see: 
+For sample command line usage, see:
 
 https://fasterdata.es.net/performance-testing/network-troubleshooting-tools/iperf/
 
@@ -28,72 +28,72 @@ the executable.
 ::
 
    IPERF3(1)                        User Manuals                        IPERF3(1)
-   
-   
-   
+
+
+
    NAME
           iperf3 - perform network throughput tests
-   
+
    SYNOPSIS
           iperf3 -s [ options ]
           iperf3 -c server [ options ]
-   
-   
+
+
    DESCRIPTION
           iperf3  is  a  tool for performing network throughput measurements.  It
           can test TCP, UDP, or SCTP throughput.  To perform an iperf3  test  the
           user must establish both a server and a client.
-   
+
           The  iperf3  executable  contains both client and server functionality.
           An iperf3 server can be started using either of the -s or --server com-
           mand-line parameters, for example:
-   
+
                  iperf3 -s
-   
+
                  iperf3 --server
-   
+
           Note  that  many  iperf3  parameters  have  both  short  (-s)  and long
           (--server) forms.  In this section we will generally use the short form
           of  command-line  flags,  unless only the long form of a flag is avail-
           able.
-   
+
           By default, the iperf3 server listens on TCP port 5201 for  connections
           from  an iperf3 client.  A custom port can be specified by using the -p
           flag, for example:
-   
+
                  iperf3 -s -p 5002
-   
+
           After the server is started, it will listen for connections from iperf3
           clients  (in  other words, the iperf3 program run in client mode).  The
           client mode can be started using the -c command-line option, which also
           requires a host to which iperf3 should connect.  The host can by speci-
           fied by hostname, IPv4 literal, or IPv6 literal:
-   
+
                  iperf3 -c iperf3.example.com
-   
+
                  iperf3 -c 192.0.2.1
-   
+
                  iperf3 -c 2001:db8::1
-   
+
           If the iperf3 server is running on a non-default TCP  port,  that  port
           number needs to be specified on the client as well:
-   
+
                  iperf3 -c iperf3.example.com -p 5002
-   
+
           The initial TCP connection is used to exchange test parameters, control
           the start and end of the test, and to exchange test results.   This  is
           sometimes  referred  to  as  the "control connection".  The actual test
           data is sent over a separate TCP connection, as a separate flow of  UDP
           packets, or as an independent SCTP connection, depending on what proto-
           col was specified by the client.
-   
+
           Normally, the test data is sent from the client to the server, and mea-
           sures  the  upload  speed  of the client.  Measuring the download speed
           from the server can be done by specifying the -R flag  on  the  client.
           This causes data to be sent from the server to the client.
-   
+
                  iperf3 -c iperf3.example.com -p 5202 -R
-   
+
           Results  are displayed on both the client and server.  There will be at
           least one line of output per measurement interval (by  default  a  mea-
           surement  interval lasts for one second, but this can be changed by the
@@ -103,136 +103,160 @@ the executable.
           measurement  interval  are taken from the point of view of the endpoint
           process emitting that output (in other words, the output on the  client
           shows the measurement interval data for the client.
-   
+
           At  the  end of the test is a set of statistics that shows (at least as
           much as possible) a summary of the test as seen by both the sender  and
           the  receiver,  with  lines tagged accordingly.  Recall that by default
           the client is the sender and the server is the  receiver,  although  as
           indicated above, use of the -R flag will reverse these roles.
-   
+
           The  client  can be made to retrieve the server-side output for a given
           test by specifying the --get-server-output flag.
-   
+
           Either the client or the server can produce its output in a JSON struc-
           ture,  useful for integration with other programs, by passing it the -J
           flag.  Because the contents of the JSON structure  are  only  competely
           known after the test has finished, no JSON output will be emitted until
           the end of the test.
-   
+
           iperf3 has a (overly) large set of command-line  options  that  can  be
           used  to  set the parameters of a test.  They are given in the "GENERAL
           OPTIONS" section of the manual page below, as  well  as  summarized  in
           iperf3's help output, which can be viewed by running iperf3 with the -h
           flag.
-   
+
    GENERAL OPTIONS
           -p, --port n
                  set server port to listen on/connect to to n (default 5201)
-   
+
           -f, --format
                  [kmgtKMGT]   format to report: Kbits/Mbits/Gbits/Tbits
-   
+
           -i, --interval n
                  pause n seconds between periodic throughput reports; default  is
                  1, use 0 to disable
-   
+
+          -I, --pidfile file
+                 write  a file with the process ID, most useful when running as a
+                 daemon.
+
           -F, --file name
-                 Use  a  file  as  the  source  (on  the  sender) or sink (on the
-                 receiver) of data, rather than just generating  random  data  or
-                 throwing  it  away.  This feature is used for finding whether or
-                 not the storage subsystem is the bottleneck for file  transfers.
-                 It  does not turn iperf3 into a file transfer tool.  The length,
-                 attributes, and in some cases contents of the received file  may
+                 Use a file as the  source  (on  the  sender)  or  sink  (on  the
+                 receiver)  of  data,  rather than just generating random data or
+                 throwing it away.  This feature is used for finding  whether  or
+                 not  the storage subsystem is the bottleneck for file transfers.
+                 It does not turn iperf3 into a file transfer tool.  The  length,
+                 attributes,  and in some cases contents of the received file may
                  not match those of the original file.
-   
+
           -A, --affinity n/n,m
-                 Set  the  CPU affinity, if possible (Linux, FreeBSD, and Windows
-                 only).  On both the client and server  you  can  set  the  local
-                 affinity  by using the n form of this argument (where n is a CPU
-                 number).  In addition, on the client side you can  override  the
-                 server's  affinity for just that one test, using the n,m form of
-                 argument.  Note that when using this  feature,  a  process  will
-                 only  be  bound  to a single CPU (as opposed to a set containing
+                 Set the CPU affinity, if possible (Linux, FreeBSD,  and  Windows
+                 only).   On  both  the  client  and server you can set the local
+                 affinity by using the n form of this argument (where n is a  CPU
+                 number).   In  addition, on the client side you can override the
+                 server's affinity for just that one test, using the n,m form  of
+                 argument.   Note  that  when  using this feature, a process will
+                 only be bound to a single CPU (as opposed to  a  set  containing
                  potentialy multiple CPUs).
-   
+
           -B, --bind host
-                 bind to the specific interface associated with address host.  If
-                 the  host  has multiple interfaces, it will use the first inter-
-                 face by default.
-   
+                 bind  to  the  specific  interface associated with address host.
+                 --bind-dev dev.ft R bind to  the  specified  network  interface.
+                 This  option  uses SO_BINDTODEVICE, and may require root permis-
+                 sions.  (Available on Linux and possibly other systems.)
+
           -V, --verbose
                  give more detailed output
-   
+
           -J, --json
                  output in JSON format
-   
+
           --logfile file
                  send output to a log file.
-   
+
           --forceflush
                  force flushing output at every interval.  Used to avoid  buffer-
                  ing when sending output to pipe.
-   
+
+          --timestamps[=format]
+                 prepend  a  timestamp  at  the  start  of  each output line.  By
+                 default,  timestamps  have  the  format  emitted  by   ctime(1).
+                 Optionally,  =  followed by a format specification can be passed
+                 to customize the timestamps, see strftime(3).  If this  optional
+                 format  is given, the = must immediately follow the --timestamps
+                 option with no whitespace intervening.
+
+          --rcv-timeout #
+                 set idle timeout for receiving data  during  active  tests.  The
+                 receiver will halt a test if no data is received from the sender
+                 for this number of ms (default to 12000 ms, or 2 minutes).
+
           -d, --debug
-                 emit  debugging  output.  Primarily (perhaps exclusively) of use
+                 emit debugging output.  Primarily (perhaps exclusively)  of  use
                  to developers.
-   
+
           -v, --version
                  show version information and quit
-   
+
           -h, --help
                  show a help synopsis
-   
-   
+
+
    SERVER SPECIFIC OPTIONS
           -s, --server
                  run in server mode
-   
+
           -D, --daemon
                  run the server in background as a daemon
-   
-          -I, --pidfile file
-                 write a file with the process ID, most useful when running as  a
-                 daemon.
-   
+
           -1, --one-off
                  handle one client connection, then exit.
-   
+
+          --server-bitrate-limit n[KMGT]
+                 set a limit on the server side, which will cause a test to abort
+                 if the client specifies a test of more than n bits  per  second,
+                 or if the average data sent or received by the client (including
+                 all data streams) is  greater  than  n  bits  per  second.   The
+                 default  limit  is  zero,  which implies no limit.  The interval
+                 over which to average the data rate is 5 seconds by default, but
+                 can  be  specified  by  adding a '/' and a number to the bitrate
+                 specifier.
+
           --rsa-private-key-path file
-                 path  to  the  RSA  private key (not password-protected) used to
-                 decrypt authentication credentials from  the  client  (if  built
+                 path to the RSA private key  (not  password-protected)  used  to
+                 decrypt  authentication  credentials  from  the client (if built
                  with OpenSSL support).
-   
+
           --authorized-users-path file
-                 path  to the configuration file containing authorized users cre-
-                 dentials to run iperf tests (if  built  with  OpenSSL  support).
-                 The  file  is  a  comma separated list of usernames and password
-                 hashes; more information on the structure of  the  file  can  be
+                 path to the configuration file containing authorized users  cre-
+                 dentials  to  run  iperf  tests (if built with OpenSSL support).
+                 The file is a comma separated list  of  usernames  and  password
+                 hashes;  more  information  on  the structure of the file can be
                  found in the EXAMPLES section.
 
-          --time-skew-threshold seconds
-                 time skew threshold (in seconds) between the server and client
+          --time-skew-thresholdsecond seconds
+                 time skew threshold (in seconds) between the server  and  client
                  during the authentication process.
-   
+
    CLIENT SPECIFIC OPTIONS
           -c, --client host
                  run  in  client  mode,  connecting  to the specified server.  By
                  default, a test consists of sending data from the client to  the
                  server, unless the -R flag is specified.
-   
+
           --sctp use SCTP rather than TCP (FreeBSD and Linux)
-   
+
           -u, --udp
                  use UDP rather than TCP
-   
+
           --connect-timeout n
                  set  timeout  for establishing the initial control connection to
                  the server, in milliseconds.  The default behavior is the  oper-
                  ating  system's  timeout for TCP connection establishment.  Pro-
                  viding a shorter value may speed up detection of a  down  iperf3
                  server.
-   
-          -b, --bitrate n[KM]
+
+          -b, --bitrate n[KMGT]
                  set  target  bitrate  to n bits/sec (default 1 Mbit/sec for UDP,
                  unlimited for TCP/SCTP).  If  there  are  multiple  streams  (-P
                  flag),  the  throughput  limit  is  applied  separately  to each
@@ -245,8 +269,8 @@ the executable.
                  inside iperf3, and is available on all platforms.  Compare  with
                  the  --fq-rate flag.  This option replaces the --bandwidth flag,
                  which is now deprecated but (at least for now) still accepted.
-   
-          --pacing-timer n[KMG]
+
+          --pacing-timer n[KMGT]
                  set  pacing  timer  interval  in  microseconds   (default   1000
                  microseconds,  or 1 ms).  This controls iperf3's internal pacing
                  timer for the -b/--bitrate  option.   The  timer  fires  at  the
@@ -254,8 +278,8 @@ the executable.
                  timer parameter smooth out the traffic emitted  by  iperf3,  but
                  potentially  at  the  cost  of  performance due to more frequent
                  timer processing.
-   
-          --fq-rate n[KM]
+
+          --fq-rate n[KMGT]
                  Set a rate to be used with fair-queueing based socket-level pac-
                  ing,  in bits per second.  This pacing (if specified) will be in
                  addition to any pacing due to iperf3's internal throughput  pac-
@@ -263,154 +287,169 @@ the executable.
                  test.  Only available on platforms  supporting  the  SO_MAX_PAC-
                  ING_RATE  socket  option (currently only Linux).  The default is
                  no fair-queueing based pacing.
-   
+
           --no-fq-socket-pacing
                  This option is deprecated and will be removed.  It is equivalent
                  to specifying --fq-rate=0.
-   
+
           -t, --time n
                  time in seconds to transmit for (default 10 secs)
-   
-          -n, --bytes n[KM]
+
+          -n, --bytes n[KMGT]
                  number of bytes to transmit (instead of -t)
-   
-          -k, --blockcount n[KM]
+
+          -k, --blockcount n[KMGT]
                  number of blocks (packets) to transmit (instead of -t or -n)
-   
-          -l, --length n[KM]
+
+          -l, --length n[KMGT]
                  length  of  buffer to read or write.  For TCP tests, the default
                  value is 128KB.  In the case of UDP, iperf3 tries to dynamically
                  determine  a  reasonable  sending size based on the path MTU; if
                  that cannot be determined it uses 1460 bytes as a sending  size.
                  For SCTP tests, the default size is 64KB.
-   
+
           --cport port
                  bind  data  streams  to  a specific client port (for TCP and UDP
                  only, default is to use an ephemeral port)
-   
+
           -P, --parallel n
                  number of parallel client streams to run. Note  that  iperf3  is
                  single  threaded,  so  if you are CPU bound, this will not yield
                  higher throughput.
-   
+
           -R, --reverse
                  reverse the direction of a test, so that the server  sends  data
                  to the client
 
           --bidir
-                 bidirectional mode, server and client send and receive data.
-   
-          -w, --window n[KM]
-                 window  size  / socket buffer size (this gets sent to the server
+                 test  in  both  directions  (normal  and reverse), with both the
+                 client and server sending and receiving data simultaneously
+
+          -w, --window n[KMGT]
+                 window size / socket buffer size (this gets sent to  the  server
                  and used on that side too)
-   
+
           -M, --set-mss n
                  set TCP/SCTP maximum segment size (MTU - 40 bytes)
-   
+
           -N, --no-delay
                  set TCP/SCTP no delay, disabling Nagle's Algorithm
-   
+
           -4, --version4
                  only use IPv4
-   
+
           -6, --version6
                  only use IPv6
-   
+
           -S, --tos n
                  set the IP type of service. The usual prefixes for octal and hex
                  can be used, i.e. 52, 064 and 0x34 all specify the same value.
-   
+
           --dscp dscp
-                 set  the  IP  DSCP  bits.   Both numeric and symbolic values are
-                 accepted. Numeric values can be specified in decimal, octal  and
+                 set the IP DSCP bits.  Both  numeric  and  symbolic  values  are
+                 accepted.  Numeric values can be specified in decimal, octal and
                  hex (see --tos above).
-   
+
           -L, --flowlabel n
                  set the IPv6 flow label (currently only supported on Linux)
-   
+
           -X, --xbind name
-                 Bind  SCTP  associations  to  a  specific  subset of links using
-                 sctp_bindx(3).  The --B flag will be ignored  if  this  flag  is
+                 Bind SCTP associations to  a  specific  subset  of  links  using
+                 sctp_bindx(3).   The  --B  flag  will be ignored if this flag is
                  specified.  Normally SCTP will include the protocol addresses of
-                 all active links on the local host when setting up  an  associa-
-                 tion.  Specifying at least one --X name will disable this behav-
-                 iour.  This flag must be specified for each link to be  included
-                 in  the association, and is supported for both iperf servers and
+                 all  active  links on the local host when setting up an associa-
+                 tion. Specifying at least one --X name will disable this  behav-
+                 iour.   This flag must be specified for each link to be included
+                 in the association, and is supported for both iperf servers  and
                  clients (the latter are supported by passing the first --X argu-
-                 ment  to  bind(2)).  Hostnames are accepted as arguments and are
-                 resolved using getaddrinfo(3).  If the  --4  or  --6  flags  are
-                 specified,  names  which  do not resolve to addresses within the
+                 ment to bind(2)).  Hostnames are accepted as arguments  and  are
+                 resolved  using  getaddrinfo(3).   If  the  --4 or --6 flags are
+                 specified, names which do not resolve to  addresses  within  the
                  specified protocol family will be ignored.
-   
+
           --nstreams n
                  Set number of SCTP streams.
-   
+
           -Z, --zerocopy
-                 Use a "zero copy" method of sending data, such  as  sendfile(2),
+                 Use  a  "zero copy" method of sending data, such as sendfile(2),
                  instead of the usual write(2).
-   
+
           -O, --omit n
                  Omit the first n seconds of the test, to skip past the TCP slow-
                  start period.
-   
+
           -T, --title str
                  Prefix every output line with this string.
-   
+
           --extra-data str
-                 Specify an extra data string field to be included in  JSON  out-
+                 Specify  an  extra data string field to be included in JSON out-
                  put.
-   
+
           -C, --congestion algo
-                 Set  the  congestion control algorithm (Linux and FreeBSD only).
-                 An older --linux-congestion synonym for this  flag  is  accepted
+                 Set the congestion control algorithm (Linux and  FreeBSD  only).
+                 An  older  --linux-congestion  synonym for this flag is accepted
                  but is deprecated.
-   
+
           --get-server-output
                  Get the output from the server.  The output format is determined
                  by the server (in particular, if the server was invoked with the
-                 --json  flag,  the  output  will be in JSON format, otherwise it
-                 will be in human-readable format).  If the client  is  run  with
-                 --json,  the  server output is included in a JSON object; other-
-                 wise it is appended at the bottom of the human-readable  output.
-   
+                 --json flag, the output will be in  JSON  format,  otherwise  it
+                 will  be  in  human-readable format).  If the client is run with
+                 --json, the server output is included in a JSON  object;  other-
+                 wise  it is appended at the bottom of the human-readable output.
+
+          --udp-counters-64bit
+                 Use 64-bit counters in UDP test packets.  The use of this option
+                 can  help  prevent counter overflows during long or high-bitrate
+                 UDP tests.  Both client and server need to be running  at  least
+                 version  3.1 for this option to work.  It may become the default
+                 behavior at some point in the future.
+
           --repeating-payload
-                 Use  repeating pattern in payload, instead of random bytes.  The
-                 same payload is used in iperf2  (ASCII  '0..9'  repeating).   It
-                 might  help  to test and reveal problems in networking gear with
-                 hardware compression (including some WiFi access points),  where
-                 iperf2  and  iperf3  perform  differently, just based on payload
+                 Use repeating pattern in payload, instead of random bytes.   The
+                 same  payload  is  used  in iperf2 (ASCII '0..9' repeating).  It
+                 might help to test and reveal problems in networking  gear  with
+                 hardware  compression (including some WiFi access points), where
+                 iperf2 and iperf3 perform differently,  just  based  on  payload
                  entropy.
-   
+
+          --dont-fragment
+                 Set  the IPv4 Don't Fragment (DF) bit on outgoing packets.  Only
+                 applicable to tests doing UDP over IPv4.
+
           --username username
                  username to use for authentication to the iperf server (if built
                  with OpenSSL support).  The password will be prompted for inter-
-                 actively when the test is run.  Note, the password to use can
-                 also be specified via the IPERF3_PASSWORD environment variable.
-                 If this variable is present, the password prompt will be
+                 actively when the test is run.  Note, the password  to  use  can
+                 also  be specified via the IPERF3_PASSWORD environment variable.
+                 If this  variable  is  present,  the  password  prompt  will  be
                  skipped.
 
           --rsa-public-key-path file
-                 path to the RSA public key used to encrypt  authentication  cre-
+                 path  to  the RSA public key used to encrypt authentication cre-
                  dentials (if built with OpenSSL support)
-   
-   
+
+
    EXAMPLES
       Authentication - RSA Keypair
-          The  authentication  feature  of iperf3 requires an RSA public keypair.
-          The public key is used to encrypt the authentication  token  containing
-          the  user  credentials,  while  the  private key is used to decrypt the
-          authentication token.  An example of a set of  UNIX/Linux  commands  to
-          generate correct keypair follows:
-   
+          The authentication feature of iperf3 requires an  RSA  public  keypair.
+          The  public  key is used to encrypt the authentication token containing
+          the user credentials, while the private key  is  used  to  decrypt  the
+          authentication  token.  The private key must be in PEM format and addi-
+          tionally must not have a password set.  The public key must be  in  PEM
+          format  and  use SubjectPrefixKeyInfo encoding.  An example of a set of
+          UNIX/Linux commands using OpenSSL to generate a  correctly-formed  key-
+          pair follows:
+
                > openssl genrsa -des3 -out private.pem 2048
                > openssl rsa -in private.pem -outform PEM -pubout -out public.pem
                > openssl rsa -in private.pem -out private_not_protected.pem -out-
                form PEM
-   
+
           After these commands, the public key will be contained in the file pub-
           lic.pem and the  private  key  will  be  contained  in  the  file  pri-
           vate_not_protected.pem.
-   
+
       Authentication - Authorized users configuration file
           A  simple plaintext file must be provided to the iperf3 server in order
           to specify the authorized user credentials.  The file is a simple  list
@@ -419,30 +458,30 @@ the executable.
           word".   The file can also contain commented lines (starting with the #
           character).  An example of commands to generate the password hash on  a
           UNIX/Linux system is given below:
-   
+
                > S_USER=mario S_PASSWD=rossi
                > echo -n "{$S_USER}$S_PASSWD" | sha256sum | awk '{ print $1 }'
-   
+
           An example of a password file (with an entry corresponding to the above
           username and password) is given below:
                > cat credentials.csv
                # file format: username,sha256
                mario,bf7a49a846d44b454a5d11e7acfaf13d138bbe0b7483aa3e050879700572709b
-   
-   
-   
+
+
+
    AUTHORS
           A list of the contributors to iperf3 can be found within the documenta-
           tion located at https://software.es.net/iperf/dev.html#authors.
-   
-   
+
+
    SEE ALSO
           libiperf(3), https://software.es.net/iperf
-   
-   
-   
-   ESnet                              June 2018                         IPERF3(1)
+
+
+
+   ESnet                            January 2022
+   IPERF3(1)
 
 The iperf3 manual page will typically be installed in manual
 section 1.
-
diff --git a/docs/news.rst b/docs/news.rst
index 846ef17..84513b6 100644
--- a/docs/news.rst
+++ b/docs/news.rst
@@ -1,6 +1,35 @@
 iperf3 Project News
 ===================
 
+2022-01-28:  iperf-3.11 released
+----------------------------------
+| URL:  https://downloads.es.net/pub/iperf/iperf-3.11.tar.gz
+
+iperf 3.11 is principally a bugfix release. Also GitHub
+Discussions are now supported.
+
+
+2021-06-02:  iperf-3.10.1 released
+----------------------------------
+
+| URL:  https://downloads.es.net/pub/iperf/iperf-3.10.1.tar.gz
+| SHA256:  ``03bc9760cc54a245191d46bfc8edaf8a4750f0e87abca6764486972044d6715a  iperf-3.10.1.tar.gz``
+
+iperf 3.10.1 fixes a problem with the configure script that made it
+make not work correctly in some circumstances. It is functionally
+identical to iperf 3.10.
+
+2021-05-26:  iperf-3.10 released
+--------------------------------
+
+| URL:  https://downloads.es.net/pub/iperf/iperf-3.10.tar.gz
+| SHA256:  ``4390982928542256c17d6dd1f56eede9092649ebfd8a97c8cecfad12d238ad57  iperf-3.10.tar.gz``
+
+iperf 3.10 is principally a bugfix release. A few new features have
+been added (``--time-skew-threshold``, ``--bind-dev``,
+``--rcv-timeout``, and ``--dont-fragment``).  More information on
+these new features can be found in the release notes.
+
 2020-08-17:  iperf-3.9 released
 ---------------------------------
 
@@ -389,6 +418,5 @@ https://github.com/esnet/iperf
 
 During development, there were various distributions of the source
 code unofficially released carrying a 3.0.0 version number.  Because
-of the possiblity for confusion, this first public release of iperf3
+of the possibility for confusion, this first public release of iperf3
 was numbered 3.0.1.
-
diff --git a/examples/Makefile.in b/examples/Makefile.in
index ffea8ef..554e75b 100644
--- a/examples/Makefile.in
+++ b/examples/Makefile.in
@@ -1,7 +1,7 @@
-# Makefile.in generated by automake 1.16.3 from Makefile.am.
+# Makefile.in generated by automake 1.16.5 from Makefile.am.
 # @configure_input@
 
-# Copyright (C) 1994-2020 Free Software Foundation, Inc.
+# Copyright (C) 1994-2021 Free Software Foundation, Inc.
 
 # This Makefile.in is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -177,8 +177,6 @@ am__define_uniq_tagged_files = \
   unique=`for i in $$list; do \
     if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
   done | $(am__uniquify_input)`
-ETAGS = etags
-CTAGS = ctags
 am__DIST_COMMON = $(srcdir)/Makefile.in $(top_srcdir)/config/depcomp \
 	$(top_srcdir)/config/mkinstalldirs
 DISTFILES = $(DIST_COMMON) $(DIST_SOURCES) $(TEXINFOS) $(EXTRA_DIST)
@@ -193,8 +191,9 @@ AWK = @AWK@
 CC = @CC@
 CCDEPMODE = @CCDEPMODE@
 CFLAGS = @CFLAGS@
-CPP = @CPP@
 CPPFLAGS = @CPPFLAGS@
+CSCOPE = @CSCOPE@
+CTAGS = @CTAGS@
 CYGPATH_W = @CYGPATH_W@
 DEFS = @DEFS@
 DEPDIR = @DEPDIR@
@@ -205,6 +204,7 @@ ECHO_C = @ECHO_C@
 ECHO_N = @ECHO_N@
 ECHO_T = @ECHO_T@
 EGREP = @EGREP@
+ETAGS = @ETAGS@
 EXEEXT = @EXEEXT@
 FGREP = @FGREP@
 GREP = @GREP@
@@ -484,7 +484,6 @@ cscopelist-am: $(am__tagged_files)
 
 distclean-tags:
 	-rm -f TAGS ID GTAGS GRTAGS GSYMS GPATH tags
-
 distdir: $(BUILT_SOURCES)
 	$(MAKE) $(AM_MAKEFLAGS) distdir-am
 
diff --git a/iperf3.spec.in b/iperf3.spec.in
index 602364d..ea63635 100644
--- a/iperf3.spec.in
+++ b/iperf3.spec.in
@@ -3,8 +3,8 @@ Version: @VERSION@
 Release:	1%{?dist}
 Summary: Measurement tool for TCP/UDP bandwidth performance
 
-Group:	 Applications/Internet	
-License: BSD	
+Group:	 Applications/Internet
+License: BSD
 URL:	 https://github.com/esnet/iperf
 Source0: https://downloads.es.net/pub/iperf/iperf-%{version}.tar.gz
 BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
@@ -98,9 +98,8 @@ rm -rf $RPM_BUILD_ROOT
 - Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild
 
 * Wed Apr 06 2011 G.Balaji <balajig81@gmail.com> 3.0b4-2
-- Changed the Spec name, removed static libs generation and devel 
+- Changed the Spec name, removed static libs generation and devel
 - package.
 
 * Sat Mar 26 2011 G.Balaji <balajig81@gmail.com> 3.0b4-1
 - Initial Version
-
diff --git a/make_release b/make_release
index 09c9374..54c43f0 100755
--- a/make_release
+++ b/make_release
@@ -10,25 +10,25 @@ tag=`awk '/IPERF_VERSION / {
   print $3 }' src/version.h`
 fi
 
-dirname=`echo $tag $proj | awk '{
+dirname=`echo "$tag $proj" | awk '{
   gsub(/-ALPHA/, "a", $1);
   gsub(/-BETA/, "b", $1);
   gsub(/-RELEASE/, "", $1);
   print $2"-"$1 }'`
 
-# echo tag $tag
-# echo dirname $dirname
+echo tag $tag
+echo dirname $dirname
 
 do_tag ()
 {
-    git tag -s -m "tagging $tag" $tag
+    git tag -s -m "tagging $tag" "$tag"
 }
 
 do_tar ()
 {
     tarball=${dirname}.tar.gz
-    rm -f ${tarball}
-    git archive --format=tar --prefix ${dirname}/ ${tag} | gzip -9 > ${tarball}
+    rm -f "${tarball}"
+    git archive --format=tar --prefix "${dirname}/" "${tag}" | gzip -9 > "${tarball}"
 
     # Compute SHA256 hash
     case `uname -s` in
@@ -37,7 +37,7 @@ do_tar ()
 	Darwin) sha="shasum -a 256" ;;
 	*) sha=echo ;;
     esac
-    ${sha} ${tarball} | tee ${tarball}.sha256
+    ${sha} "${tarball}" | tee "${tarball}.sha256"
 }
 
 usage ()
diff --git a/src/Makefile.in b/src/Makefile.in
index 2fd754e..b32e922 100644
--- a/src/Makefile.in
+++ b/src/Makefile.in
@@ -1,7 +1,7 @@
-# Makefile.in generated by automake 1.16.3 from Makefile.am.
+# Makefile.in generated by automake 1.16.5 from Makefile.am.
 # @configure_input@
 
-# Copyright (C) 1994-2020 Free Software Foundation, Inc.
+# Copyright (C) 1994-2021 Free Software Foundation, Inc.
 
 # This Makefile.in is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -322,8 +322,6 @@ am__define_uniq_tagged_files = \
   unique=`for i in $$list; do \
     if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
   done | $(am__uniquify_input)`
-ETAGS = etags
-CTAGS = ctags
 am__tty_colors_dummy = \
   mgn= red= grn= lgn= blu= brg= std=; \
   am__color_tests=no
@@ -519,8 +517,9 @@ AWK = @AWK@
 CC = @CC@
 CCDEPMODE = @CCDEPMODE@
 CFLAGS = @CFLAGS@
-CPP = @CPP@
 CPPFLAGS = @CPPFLAGS@
+CSCOPE = @CSCOPE@
+CTAGS = @CTAGS@
 CYGPATH_W = @CYGPATH_W@
 DEFS = @DEFS@
 DEPDIR = @DEPDIR@
@@ -531,6 +530,7 @@ ECHO_C = @ECHO_C@
 ECHO_N = @ECHO_N@
 ECHO_T = @ECHO_T@
 EGREP = @EGREP@
+ETAGS = @ETAGS@
 EXEEXT = @EXEEXT@
 FGREP = @FGREP@
 GREP = @GREP@
@@ -1650,7 +1650,6 @@ t_auth.log: t_auth$(EXEEXT)
 @am__EXEEXT_TRUE@	--log-file $$b.log --trs-file $$b.trs \
 @am__EXEEXT_TRUE@	$(am__common_driver_flags) $(AM_TEST_LOG_DRIVER_FLAGS) $(TEST_LOG_DRIVER_FLAGS) -- $(TEST_LOG_COMPILE) \
 @am__EXEEXT_TRUE@	"$$tst" $(AM_TESTS_FD_REDIRECT)
-
 distdir: $(BUILT_SOURCES)
 	$(MAKE) $(AM_MAKEFLAGS) distdir-am
 
diff --git a/src/dscp.c b/src/dscp.c
index d0c109b..79fcd49 100644
--- a/src/dscp.c
+++ b/src/dscp.c
@@ -136,10 +136,11 @@ parse_qos(const char *cp)
 			return ipqos[i].value;
 	}
 	/* Try parsing as an integer */
+    /* Max DSCP value is 2**6 - 1 */
 	val = strtol(cp, &ep, 0);
-	if (*cp == '\0' || *ep != '\0' || val < 0 || val > 255)
+	if (*cp == '\0' || *ep != '\0' || val < 0 || val > 63)
 		return -1;
-	return val;
+	return val << 2;
 }
 
 const char *
diff --git a/src/flowlabel.h b/src/flowlabel.h
index 1d5e013..df0a434 100644
--- a/src/flowlabel.h
+++ b/src/flowlabel.h
@@ -30,8 +30,8 @@
 
 #include <linux/types.h>
 
-/*                                                                                                                                                                             
-   It is just a stripped copy of the Linux kernel header "linux/in6.h" 
+/*
+   It is just a stripped copy of the Linux kernel header "linux/in6.h"
    "Flow label" things are still not defined in "netinet/in*.h" headers,
    but we cannot use "linux/in6.h" immediately because it currently
    conflicts with "netinet/in.h" .
diff --git a/src/iperf.h b/src/iperf.h
index 3fc91d0..6de2343 100644
--- a/src/iperf.h
+++ b/src/iperf.h
@@ -79,7 +79,7 @@ typedef uint64_t iperf_size_t;
 
 struct iperf_interval_results
 {
-    iperf_size_t bytes_transferred; /* bytes transfered in this interval */
+    iperf_size_t bytes_transferred; /* bytes transferred in this interval */
     struct iperf_time interval_start_time;
     struct iperf_time interval_end_time;
     float     interval_duration;
@@ -146,7 +146,7 @@ struct iperf_settings
     int       blksize;              /* size of read/writes (-l) */
     iperf_size_t  rate;                 /* target data rate for application pacing*/
     iperf_size_t  bitrate_limit;   /* server's maximum allowed total data rate for all streams*/
-    double        bitrate_limit_interval;  /* interval for avaraging total data rate */
+    double        bitrate_limit_interval;  /* interval for averaging total data rate */
     int           bitrate_limit_stats_per_interval;     /* calculated number of stats periods for averaging total data rate */
     uint64_t  fqrate;               /* target data rate for FQ pacing*/
     int	      pacing_timer;	    /* pacing timer in microseconds */
@@ -183,7 +183,7 @@ struct iperf_stream
     int       socket;
     int       id;
     int       sender;
-	/* XXX: is settings just a pointer to the same struct in iperf_test? if not, 
+	/* XXX: is settings just a pointer to the same struct in iperf_test? if not,
 		should it be? */
     struct iperf_settings *settings;	/* pointer to structure settings */
 
@@ -325,7 +325,7 @@ struct iperf_test
     fd_set    read_set;                         /* set of read sockets */
     fd_set    write_set;                        /* set of write sockets */
 
-    /* Interval related members */ 
+    /* Interval related members */
     int       omitting;
     double    stats_interval;
     double    reporter_interval;
@@ -350,7 +350,7 @@ struct iperf_test
 
     iperf_size_t bitrate_limit_stats_count;               /* Number of stats periods accumulated for server's total bitrate average */
     iperf_size_t *bitrate_limit_intervals_traffic_bytes;  /* Pointer to a cyclic array that includes the last interval's bytes transferred */
-    iperf_size_t bitrate_limit_last_interval_index;       /* Index of the last interval traffic insrted into the cyclic array */
+    iperf_size_t bitrate_limit_last_interval_index;       /* Index of the last interval traffic inserted into the cyclic array */
     int          bitrate_limit_exceeded;                  /* Set by callback routine when average data rate exceeded the server's bitrate limit */
 
     int server_last_run_rc;                      /* Save last server run rc for next test */
diff --git a/src/iperf3.1 b/src/iperf3.1
index f5eef6e..5fb7c93 100644
--- a/src/iperf3.1
+++ b/src/iperf3.1
@@ -1,4 +1,4 @@
-.TH IPERF3 1 "February 2021" ESnet "User Manuals"
+.TH IPERF3 1 "January 2022" ESnet "User Manuals"
 .SH NAME
 iperf3 \- perform network throughput tests
 .SH SYNOPSIS
@@ -6,7 +6,7 @@ iperf3 \- perform network throughput tests
 .I options
 .B ]
 .br
-.B iperf3 -c 
+.B iperf3 -c
 .I server
 .B [
 .I options
@@ -96,7 +96,7 @@ test by specifying the --get-server-output flag.
 Either the client or the server can produce its output in a JSON
 structure, useful for integration with other programs, by passing it
 the -J flag.
-Because the contents of the JSON structure are only competely known
+Because the contents of the JSON structure are only completely known
 after the test has finished, no JSON output will be emitted until the
 end of the test.
 .PP
@@ -137,18 +137,21 @@ In addition, on the client side you can override the server's
 affinity for just that one test, using the \fIn,m\fR form of
 argument.
 Note that when using this feature, a process will only be bound
-to a single CPU (as opposed to a set containing potentialy multiple
+to a single CPU (as opposed to a set containing potentially multiple
 CPUs).
 .TP
-.BR -B ", " --bind " \fIhost\fR"
+.BR -B ", " --bind " \fIhost\fR[\fB%\fIdev\fR]"
 bind to the specific interface associated with address \fIhost\fR.
-.BR --bind-dev " \fIdev\R"
+If an optional interface is specified, it is treated as a shortcut
+for \fB--bind-dev \fIdev\fR.
+Note that a percent sign and interface device name are required for IPv6 link-local address literals.
+.BR --bind-dev " \fIdev\fR"
 bind to the specified network interface.
 This option uses SO_BINDTODEVICE, and may require root permissions.
 (Available on Linux and possibly other systems.)
 .TP
 .BR -V ", " --verbose " "
-give more detailed output 
+give more detailed output
 .TP
 .BR -J ", " --json " "
 output in JSON format
@@ -195,7 +198,13 @@ run in server mode
 run the server in background as a daemon
 .TP
 .BR -1 ", " --one-off
-handle one client connection, then exit.
+handle one client connection, then exit.  If an idle time is set, the
+server will exit after that amount of time with no connection.
+.TP
+.BR --idle-timeout " \fIn\fR"
+restart the server after \fIn\fR seconds in case it gets stuck.  In
+one-off mode, this is the number of seconds the server will wait
+before exiting.
 .TP
 .BR --server-bitrate-limit " \fIn\fR[KMGT]"
 set a limit on the server side, which will cause a test to abort if
@@ -207,12 +216,12 @@ the data rate is 5 seconds by default, but can be specified by adding
 a '/' and a number to the bitrate specifier.
 .TP
 .BR --rsa-private-key-path " \fIfile\fR"
-path to the RSA private key (not password-protected) used to decrypt 
+path to the RSA private key (not password-protected) used to decrypt
 authentication credentials from the client (if built with OpenSSL
 support).
-.TP          
+.TP
 .BR --authorized-users-path " \fIfile\fR"
-path to the configuration file containing authorized users credentials to run 
+path to the configuration file containing authorized users credentials to run
 iperf tests (if built with OpenSSL support).
 The file is a comma separated list of usernames and password hashes;
 more information on the structure of the file can be found in the
@@ -223,10 +232,13 @@ time skew threshold (in seconds) between the server and client
 during the authentication process.
 .SH "CLIENT SPECIFIC OPTIONS"
 .TP
-.BR -c ", " --client " \fIhost\fR"
+.BR -c ", " --client " \fIhost\fR[\fB%\fIdev\fR]"
 run in client mode, connecting to the specified server.
 By default, a test consists of sending data from the client to the
 server, unless the \-R flag is specified.
+If an optional interface is specified, it is treated as a shortcut
+for \fB--bind-dev \fIdev\fR.
+Note that a percent sign and interface device name are required for IPv6 link-local address literals.
 .TP
 .BR --sctp
 use SCTP rather than TCP (FreeBSD and Linux)
@@ -316,7 +328,13 @@ test in both directions (normal and reverse), with both the client and
 server sending and receiving data simultaneously
 .TP
 .BR -w ", " --window " \fIn\fR[KMGT]"
-window size / socket buffer size (this gets sent to the server and used on that side too)
+set socket buffer size / window size.
+This value gets sent to the server and used on that side too; on both
+sides this option sets both the sending and receiving socket buffer sizes.
+This option can be used to set (indirectly) the maximum TCP window size.
+Note that on Linux systems, the effective maximum window size is approximately
+double what is specified by this option (this behavior is not a bug in iperf3
+but a "feature" of the Linux kernel, as documented by tcp(7) and socket(7)).
 .TP
 .BR -M ", " --set-mss " \fIn\fR"
 set TCP/SCTP maximum segment size (MTU - 40 bytes)
@@ -336,7 +354,8 @@ i.e. 52, 064 and 0x34 all specify the same value.
 .TP
 .BR "--dscp " \fIdscp\fR
 set the IP DSCP bits.  Both numeric and symbolic values are accepted. Numeric
-values can be specified in decimal, octal and hex (see --tos above).
+values can be specified in decimal, octal and hex (see --tos above). To set
+both the DSCP bits and the ECN bits, use --tos.
 .TP
 .BR -L ", " --flowlabel " \fIn\fR"
 set the IPv6 flow label (currently only supported on Linux)
@@ -406,41 +425,41 @@ perform differently, just based on payload entropy.
 Set the IPv4 Don't Fragment (DF) bit on outgoing packets.
 Only applicable to tests doing UDP over IPv4.
 .TP
-.BR --username " \fIusername\fR" 
+.BR --username " \fIusername\fR"
 username to use for authentication to the iperf server (if built with
 OpenSSL support).
 The password will be prompted for interactively when the test is run.  Note,
 the password to use can also be specified via the IPERF3_PASSWORD environment
 variable. If this variable is present, the password prompt will be skipped.
 .TP
-.BR --rsa-public-key-path " \fIfile\fR" 
+.BR --rsa-public-key-path " \fIfile\fR"
 path to the RSA public key used to encrypt authentication credentials
 (if built with OpenSSL support)
 
 .SH EXAMPLES
 .SS "Authentication - RSA Keypair"
 The authentication feature of iperf3 requires an RSA public keypair.
-The public key is used to encrypt the authentication token containing the 
+The public key is used to encrypt the authentication token containing the
 user credentials, while the private key is used to decrypt the authentication token.
 The private key must be in PEM format and additionally must not have a
 password set.
 The public key must be in PEM format and use SubjectPrefixKeyInfo encoding.
 An example of a set of UNIX/Linux commands using OpenSSL
 to generate a correctly-formed keypair follows:
-.sp 1 
+.sp 1
 .in +.5i
 > openssl genrsa -des3 -out private.pem 2048
 .sp 0
 > openssl rsa -in private.pem -outform PEM -pubout -out public.pem
 .sp 0
-> openssl rsa -in private.pem -out private_not_protected.pem -outform PEM  
+> openssl rsa -in private.pem -out private_not_protected.pem -outform PEM
 .in -.5i
 .sp 1
 After these commands, the public key will be contained in the file
 public.pem and the private key will be contained in the file
 private_not_protected.pem.
 .SS "Authentication - Authorized users configuration file"
-A simple plaintext file must be provided to the iperf3 server in order to specify 
+A simple plaintext file must be provided to the iperf3 server in order to specify
 the authorized user credentials.
 The file is a simple list of comma-separated pairs of a username and a
 corresponding password hash.
@@ -449,7 +468,7 @@ The file can also contain commented lines (starting with the \fC#\fR
 character).
 An example of commands to generate the password hash on a UNIX/Linux system
 is given below:
-.sp 1 
+.sp 1
 .in +.5i
 > S_USER=mario S_PASSWD=rossi
 .sp 0
diff --git a/src/iperf_api.c b/src/iperf_api.c
index f8f2321..b0ef508 100644
--- a/src/iperf_api.c
+++ b/src/iperf_api.c
@@ -1,5 +1,5 @@
 /*
- * iperf, Copyright (c) 2014-2021, The Regents of the University of
+ * iperf, Copyright (c) 2014-2022, The Regents of the University of
  * California, through Lawrence Berkeley National Laboratory (subject
  * to receipt of any required approvals from the U.S. Dept. of
  * Energy).  All rights reserved.
@@ -816,7 +816,7 @@ void
 iperf_on_test_start(struct iperf_test *test)
 {
     if (test->json_output) {
-	cJSON_AddItemToObject(test->json_start, "test_start", iperf_json_printf("protocol: %s  num_streams: %d  blksize: %d  omit: %d  duration: %d  bytes: %d  blocks: %d  reverse: %d  tos: %d", test->protocol->name, (int64_t) test->num_streams, (int64_t) test->settings->blksize, (int64_t) test->omit, (int64_t) test->duration, (int64_t) test->settings->bytes, (int64_t) test->settings->blocks, test->reverse?(int64_t)1:(int64_t)0, (int64_t) test->settings->tos));
+	cJSON_AddItemToObject(test->json_start, "test_start", iperf_json_printf("protocol: %s  num_streams: %d  blksize: %d  omit: %d  duration: %d  bytes: %d  blocks: %d  reverse: %d  tos: %d  target_bitrate: %d", test->protocol->name, (int64_t) test->num_streams, (int64_t) test->settings->blksize, (int64_t) test->omit, (int64_t) test->duration, (int64_t) test->settings->bytes, (int64_t) test->settings->blocks, test->reverse?(int64_t)1:(int64_t)0, (int64_t) test->settings->tos, (int64_t) test->settings->rate));
     } else {
 	if (test->verbose) {
 	    if (test->settings->bytes)
@@ -901,9 +901,8 @@ iperf_on_connect(struct iperf_test *test)
 	    else {
 		cJSON_AddNumberToObject(test->json_start, "tcp_mss_default", test->ctrl_sck_mss);
 	    }
-        if (test->settings->rate)
-            cJSON_AddNumberToObject(test->json_start, "target_bitrate", test->settings->rate);
         }
+        cJSON_AddNumberToObject(test->json_start, "target_bitrate", test->settings->rate);
     } else if (test->verbose) {
         iperf_printf(test, report_cookie, test->cookie);
         if (test->protocol->id == SOCK_STREAM) {
@@ -926,6 +925,54 @@ iperf_on_test_finish(struct iperf_test *test)
 
 /******************************************************************************/
 
+/*
+ * iperf_parse_hostname tries to split apart a string into hostname %
+ * interface parts, which are returned in **p and **p1, if they
+ * exist. If the %interface part is detected, and it's not an IPv6
+ * link local address, then returns 1, else returns 0.
+ *
+ * Modifies the string pointed to by spec in-place due to the use of
+ * strtok(3). The caller should strdup(3) or otherwise copy the string
+ * if an unmodified copy is needed.
+ */
+int
+iperf_parse_hostname(struct iperf_test *test, char *spec, char **p, char **p1) {
+    struct in6_addr ipv6_addr;
+
+    // Format is <addr>[%<device>]
+    if ((*p = strtok(spec, "%")) != NULL &&
+        (*p1 = strtok(NULL, "%")) != NULL) {
+
+        /*
+         * If an IPv6 literal for a link-local address, then
+         * tell the caller to leave the "%" in the hostname.
+         */
+        if (inet_pton(AF_INET6, *p, &ipv6_addr) == 1 &&
+            IN6_IS_ADDR_LINKLOCAL(&ipv6_addr)) {
+            if (test->debug) {
+                iperf_printf(test, "IPv6 link-local address literal detected\n");
+            }
+            return 0;
+        }
+        /*
+         * Other kind of address or FQDN. The interface name after
+         * "%" is a shorthand for --bind-dev.
+         */
+        else {
+            if (test->debug) {
+                iperf_printf(test, "p %s p1 %s\n", *p, *p1);
+            }
+            return 1;
+        }
+    }
+    else {
+        if (test->debug) {
+            iperf_printf(test, "noparse\n");
+        }
+        return 0;
+    }
+}
+
 int
 iperf_parse_arguments(struct iperf_test *test, int argc, char **argv)
 {
@@ -1020,6 +1067,7 @@ iperf_parse_arguments(struct iperf_test *test, int argc, char **argv)
     char* comma;
 #endif /* HAVE_CPU_AFFINITY */
     char* slash;
+    char *p, *p1;
     struct xbind_entry *xbe;
     double farg;
     int rcv_timeout_in = 0;
@@ -1102,6 +1150,18 @@ iperf_parse_arguments(struct iperf_test *test, int argc, char **argv)
                 }
 		iperf_set_test_role(test, 'c');
 		iperf_set_test_server_hostname(test, optarg);
+
+                if (iperf_parse_hostname(test, optarg, &p, &p1)) {
+#if defined(HAVE_SO_BINDTODEVICE)
+                    /* Get rid of the hostname we saved earlier. */
+                    free(iperf_get_test_server_hostname(test));
+                    iperf_set_test_server_hostname(test, p);
+                    iperf_set_test_bind_dev(test, p1);
+#else /* HAVE_SO_BINDTODEVICE */
+                    i_errno = IEBINDDEVNOSUPPORT;
+                    return -1;
+#endif /* HAVE_SO_BINDTODEVICE */
+                }
                 break;
             case 'u':
                 set_protocol(test, Pudp);
@@ -1203,7 +1263,7 @@ iperf_parse_arguments(struct iperf_test *test, int argc, char **argv)
                 break;
             case 'w':
                 // XXX: This is a socket buffer, not specific to TCP
-		// Do sanity checks as double-precision floating point 
+		// Do sanity checks as double-precision floating point
 		// to avoid possible integer overflows.
                 farg = unit_atof(optarg);
                 if (farg > (double) MAX_TCP_BUFFER) {
@@ -1213,12 +1273,25 @@ iperf_parse_arguments(struct iperf_test *test, int argc, char **argv)
                 test->settings->socket_bufsize = (int) farg;
 		client_flag = 1;
                 break;
+
             case 'B':
-                test->bind_address = strdup(optarg);
+                iperf_set_test_bind_address(test, optarg);
+
+                if (iperf_parse_hostname(test, optarg, &p, &p1)) {
+#if defined(HAVE_SO_BINDTODEVICE)
+                    /* Get rid of the hostname we saved earlier. */
+                    free(iperf_get_test_server_hostname(test));
+                    iperf_set_test_server_hostname(test, p);
+                    iperf_set_test_bind_dev(test, p1);
+#else /* HAVE_SO_BINDTODEVICE */
+                    i_errno = IEBINDDEVNOSUPPORT;
+                    return -1;
+#endif /* HAVE_SO_BINDTODEVICE */
+                }
                 break;
 #if defined (HAVE_SO_BINDTODEVICE)
             case OPT_BIND_DEV:
-                test->bind_dev = strdup(optarg);
+                iperf_set_test_bind_dev(test, optarg);
                 break;
 #endif /* HAVE_SO_BINDTODEVICE */
             case OPT_CLIENT_PORT:
@@ -1350,7 +1423,7 @@ iperf_parse_arguments(struct iperf_test *test, int argc, char **argv)
             case 'A':
 #if defined(HAVE_CPU_AFFINITY)
                 test->affinity = strtol(optarg, &endptr, 0);
-                if (endptr == optarg || 
+                if (endptr == optarg ||
 		    test->affinity < 0 || test->affinity > 1024) {
                     i_errno = IEAFFINITY;
                     return -1;
@@ -1479,7 +1552,7 @@ iperf_parse_arguments(struct iperf_test *test, int argc, char **argv)
     if (test->role == 's' && (client_username || client_rsa_public_key)){
         i_errno = IECLIENTONLY;
         return -1;
-    } else if (test->role == 'c' && (client_username || client_rsa_public_key) && 
+    } else if (test->role == 'c' && (client_username || client_rsa_public_key) &&
         !(client_username && client_rsa_public_key)) {
         i_errno = IESETCLIENTAUTH;
         return -1;
@@ -1493,7 +1566,7 @@ iperf_parse_arguments(struct iperf_test *test, int argc, char **argv)
         else if (iperf_getpass(&client_password, &s, stdin) < 0){
             i_errno = IESETCLIENTAUTH;
             return -1;
-        } 
+        }
         if (test_load_pubkey_from_file(client_rsa_public_key) < 0){
             iperf_err(test, "%s\n", ERR_error_string(ERR_get_error(), NULL));
             i_errno = IESETCLIENTAUTH;
@@ -1516,7 +1589,7 @@ iperf_parse_arguments(struct iperf_test *test, int argc, char **argv)
     } else if (test->role == 'c' && rcv_timeout_flag && test->mode == SENDER){
         i_errno = IERVRSONLYRCVTIMEOUT;
         return -1;
-    } else if (test->role == 's' && (server_rsa_private_key || test->server_authorized_users) && 
+    } else if (test->role == 's' && (server_rsa_private_key || test->server_authorized_users) &&
         !(server_rsa_private_key && test->server_authorized_users)) {
          i_errno = IESETSERVERAUTH;
         return -1;
@@ -1545,7 +1618,7 @@ iperf_parse_arguments(struct iperf_test *test, int argc, char **argv)
 	else
 	    blksize = DEFAULT_TCP_BLKSIZE;
     }
-    if ((test->protocol->id != Pudp && blksize <= 0) 
+    if ((test->protocol->id != Pudp && blksize <= 0)
 	|| blksize > MAX_BLOCKSIZE) {
 	i_errno = IEBLOCKSIZE;
 	return -1;
@@ -1561,6 +1634,25 @@ iperf_parse_arguments(struct iperf_test *test, int argc, char **argv)
     if (!rate_flag)
 	test->settings->rate = test->protocol->id == Pudp ? UDP_RATE : 0;
 
+    /* if no bytes or blocks specified, nor a duration_flag, and we have -F,
+    ** get the file-size as the bytes count to be transferred
+    */
+    if (test->settings->bytes == 0 &&
+        test->settings->blocks == 0 &&
+        ! duration_flag &&
+        test->diskfile_name != (char*) 0 &&
+        test->role == 'c'
+        ){
+        struct stat st;
+        if( stat(test->diskfile_name, &st) == 0 ){
+            iperf_size_t file_bytes = st.st_size;
+            test->settings->bytes = file_bytes;
+            if (test->debug)
+                printf("End condition set to file-size: %d bytes\n", test->settings->bytes);
+        }
+        // if failing to read file stat, it should fallback to default duration mode
+    }
+
     if ((test->settings->bytes != 0 || test->settings->blocks != 0) && ! duration_flag)
         test->duration = 0;
 
@@ -1658,7 +1750,7 @@ iperf_check_throttle(struct iperf_stream *sp, struct iperf_time *nowP)
     }
 }
 
-/* Verify that average traffic is not greater than the specifid limit */
+/* Verify that average traffic is not greater than the specified limit */
 void
 iperf_check_total_rate(struct iperf_test *test, iperf_size_t last_interval_bytes_transferred)
 {
@@ -1669,8 +1761,8 @@ iperf_check_total_rate(struct iperf_test *test, iperf_size_t last_interval_bytes
 
     if (test->done || test->settings->bitrate_limit == 0)    // Continue only if check should be done
         return;
-    
-    /* Add last inetrval's transffered bytes to the array */
+
+    /* Add last inetrval's transferred bytes to the array */
     if (++test->bitrate_limit_last_interval_index >= test->settings->bitrate_limit_stats_per_interval)
         test->bitrate_limit_last_interval_index = 0;
     test->bitrate_limit_intervals_traffic_bytes[test->bitrate_limit_last_interval_index] = last_interval_bytes_transferred;
@@ -1679,7 +1771,7 @@ iperf_check_total_rate(struct iperf_test *test, iperf_size_t last_interval_bytes
     test->bitrate_limit_stats_count += 1;
     if (test->bitrate_limit_stats_count < test->settings->bitrate_limit_stats_per_interval)
         return;
- 
+
      /* Calculating total bytes traffic to be averaged */
     for (total_bytes = 0, i = 0; i < test->settings->bitrate_limit_stats_per_interval; i++) {
         total_bytes += test->bitrate_limit_intervals_traffic_bytes[i];
@@ -2030,6 +2122,8 @@ send_parameters(struct iperf_test *test)
 	    cJSON_AddNumberToObject(j, "udp_counters_64bit", iperf_get_test_udp_counters_64bit(test));
 	if (test->repeating_payload)
 	    cJSON_AddNumberToObject(j, "repeating_payload", test->repeating_payload);
+	if (test->zerocopy)
+	    cJSON_AddNumberToObject(j, "zerocopy", test->zerocopy);
 #if defined(HAVE_DONT_FRAGMENT)
 	if (test->settings->dont_fragment)
 	    cJSON_AddNumberToObject(j, "dont_fragment", test->settings->dont_fragment);
@@ -2044,7 +2138,7 @@ send_parameters(struct iperf_test *test)
 		i_errno = IESENDPARAMS;
 		return -1;
 	    }
-	    
+
 	    cJSON_AddStringToObject(j, "authtoken", test->settings->authtoken);
 	}
 #endif // HAVE_SSL
@@ -2142,6 +2236,8 @@ get_parameters(struct iperf_test *test)
 	    iperf_set_test_udp_counters_64bit(test, 1);
 	if ((j_p = cJSON_GetObjectItem(j, "repeating_payload")) != NULL)
 	    test->repeating_payload = 1;
+	if ((j_p = cJSON_GetObjectItem(j, "zerocopy")) != NULL)
+	    test->zerocopy = j_p->valueint;
 #if defined(HAVE_DONT_FRAGMENT)
 	if ((j_p = cJSON_GetObjectItem(j, "dont_fragment")) != NULL)
 	    test->settings->dont_fragment = j_p->valueint;
@@ -2368,7 +2464,7 @@ get_results(struct iperf_test *test)
 				    sp->peer_packet_count = pcount;
 				    sp->result->bytes_received = bytes_transferred;
 				    /*
-				     * We have to handle the possibilty that
+				     * We have to handle the possibility that
 				     * start_time and end_time might not be
 				     * available; this is the case for older (pre-3.2)
 				     * servers.
@@ -2577,7 +2673,7 @@ iperf_new_test()
 	i_errno = IENEWTEST;
 	return NULL;
     }
-    memset(test->bitrate_limit_intervals_traffic_bytes, 0, sizeof(sizeof(iperf_size_t) * MAX_INTERVAL));   
+    memset(test->bitrate_limit_intervals_traffic_bytes, 0, sizeof(sizeof(iperf_size_t) * MAX_INTERVAL));
 
     /* By default all output goes to stdout */
     test->outfile = stdout;
@@ -2604,7 +2700,7 @@ protocol_new(void)
 void
 protocol_free(struct protocol *proto)
 {
-    free(proto); 
+    free(proto);
 }
 
 /**************************************************************************/
@@ -2658,6 +2754,7 @@ iperf_defaults(struct iperf_test *testp)
     testp->settings->connect_timeout = -1;
     testp->settings->rcv_timeout.secs = DEFAULT_NO_MSG_RCVD_TIMEOUT / SEC_TO_mS;
     testp->settings->rcv_timeout.usecs = (DEFAULT_NO_MSG_RCVD_TIMEOUT % SEC_TO_mS) * mS_TO_US;
+    testp->zerocopy = 0;
 
     memset(testp->cookie, 0, COOKIE_SIZE);
 
@@ -2809,14 +2906,14 @@ iperf_free_test(struct iperf_test *test)
     /* Free protocol list */
     while (!SLIST_EMPTY(&test->protocols)) {
         prot = SLIST_FIRST(&test->protocols);
-        SLIST_REMOVE_HEAD(&test->protocols, protocols);        
+        SLIST_REMOVE_HEAD(&test->protocols, protocols);
         free(prot);
     }
 
     if (test->logfile) {
 	free(test->logfile);
 	test->logfile = NULL;
-	if (test->outfile) {
+	if (test->outfile && test->outfile != stdout) {
 	    fclose(test->outfile);
 	    test->outfile = NULL;
 	}
@@ -2853,7 +2950,7 @@ iperf_free_test(struct iperf_test *test)
         }
     }
 
-    /* Free interval's traffic array for avrage rate calculations */
+    /* Free interval's traffic array for average rate calculations */
     if (test->bitrate_limit_intervals_traffic_bytes != NULL)
         free(test->bitrate_limit_intervals_traffic_bytes);
 
@@ -2911,7 +3008,7 @@ iperf_reset_test(struct iperf_test *test)
     CPU_ZERO(&test->cpumask);
 #endif /* HAVE_CPUSET_SETAFFINITY */
     test->state = 0;
-    
+
     test->ctrl_sck = -1;
     test->prot_listener = -1;
 
@@ -2936,7 +3033,7 @@ iperf_reset_test(struct iperf_test *test)
 
     FD_ZERO(&test->read_set);
     FD_ZERO(&test->write_set);
-    
+
     test->num_streams = 1;
     test->settings->socket_bufsize = 0;
     test->settings->blksize = DEFAULT_TCP_BLKSIZE;
@@ -2945,6 +3042,7 @@ iperf_reset_test(struct iperf_test *test)
     test->settings->mss = 0;
     test->settings->tos = 0;
     test->settings->dont_fragment = 0;
+    test->zerocopy = 0;
 
 #if defined(HAVE_SSL)
     if (test->settings->authtoken) {
@@ -3043,7 +3141,7 @@ iperf_stats_callback(struct iperf_test *test)
 
         // Total bytes transferred this interval
 	total_interval_bytes_transferred += rp->bytes_sent_this_interval + rp->bytes_received_this_interval;
-    
+
 	irp = TAILQ_LAST(&rp->interval_results, irlisthead);
         /* result->end_time contains timestamp of previous interval */
         if ( irp != NULL ) /* not the 1st interval */
@@ -3068,7 +3166,7 @@ iperf_stats_callback(struct iperf_test *test)
 		    if (temp.snd_cwnd > rp->stream_max_snd_cwnd) {
 			rp->stream_max_snd_cwnd = temp.snd_cwnd;
 		    }
-		    
+
 		    temp.snd_wnd = get_snd_wnd(&temp);
 		    if (temp.snd_wnd > rp->stream_max_snd_wnd) {
 			rp->stream_max_snd_wnd = temp.snd_wnd;
@@ -3157,7 +3255,7 @@ iperf_print_intermediate(struct iperf_test *test)
 
 	    /*
 	     * If the interval is at least 10% the normal interval
-	     * length, or if there were actual bytes transferrred,
+	     * length, or if there were actual bytes transferred,
 	     * then we want to keep this interval.
 	     */
 	    if (interval_len >= test->stats_interval * 0.10 ||
@@ -3228,6 +3326,8 @@ iperf_print_intermediate(struct iperf_test *test)
         double avg_jitter = 0.0, lost_percent;
         int stream_must_be_sender = current_mode * current_mode;
 
+        char *sum_name;
+
         /*  Print stream role just for bidirectional mode. */
 
         if (test->mode == BIDIRECTIONAL) {
@@ -3262,6 +3362,22 @@ iperf_print_intermediate(struct iperf_test *test)
 
         /* next build string with sum of all streams */
         if (test->num_streams > 1 || test->json_output) {
+            /*
+             * With BIDIR give a different JSON object name to the one sent/receive sums.
+             * The different name is given to the data sent from the server, which is
+             * the "reverse" channel.  This makes sure that the name reported on the server
+             * and client are compatible, and the names are the same as with non-bidir,
+             * except for when reverse is used.
+             */
+            sum_name = "sum";
+            if (test->mode == BIDIRECTIONAL) {
+                if ((test->role == 'c' && !stream_must_be_sender) ||
+                    (test->role != 'c' && stream_must_be_sender))
+                {
+                    sum_name = "sum_bidir_reverse";
+                }
+            }
+
             sp = SLIST_FIRST(&test->streams); /* reset back to 1st stream */
             /* Only do this of course if there was a first stream */
             if (sp) {
@@ -3279,13 +3395,13 @@ iperf_print_intermediate(struct iperf_test *test)
                     if (test->sender_has_retransmits == 1 && stream_must_be_sender) {
                         /* Interval sum, TCP with retransmits. */
                         if (test->json_output)
-                            cJSON_AddItemToObject(json_interval, "sum", iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f  retransmits: %d  omitted: %b sender: %b", (double) start_time, (double) end_time, (double) irp->interval_duration, (int64_t) bytes, bandwidth * 8, (int64_t) retransmits, irp->omitted, stream_must_be_sender)); /* XXX irp->omitted or test->omitting? */
+                            cJSON_AddItemToObject(json_interval, sum_name, iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f  retransmits: %d  omitted: %b sender: %b", (double) start_time, (double) end_time, (double) irp->interval_duration, (int64_t) bytes, bandwidth * 8, (int64_t) retransmits, irp->omitted, stream_must_be_sender)); /* XXX irp->omitted or test->omitting? */
                         else
                             iperf_printf(test, report_sum_bw_retrans_format, mbuf, start_time, end_time, ubuf, nbuf, retransmits, irp->omitted?report_omitted:""); /* XXX irp->omitted or test->omitting? */
                     } else {
                         /* Interval sum, TCP without retransmits. */
                         if (test->json_output)
-                            cJSON_AddItemToObject(json_interval, "sum", iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f  omitted: %b sender: %b", (double) start_time, (double) end_time, (double) irp->interval_duration, (int64_t) bytes, bandwidth * 8, test->omitting, stream_must_be_sender));
+                            cJSON_AddItemToObject(json_interval, sum_name, iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f  omitted: %b sender: %b", (double) start_time, (double) end_time, (double) irp->interval_duration, (int64_t) bytes, bandwidth * 8, test->omitting, stream_must_be_sender));
                         else
                             iperf_printf(test, report_sum_bw_format, mbuf, start_time, end_time, ubuf, nbuf, test->omitting?report_omitted:"");
                     }
@@ -3293,7 +3409,7 @@ iperf_print_intermediate(struct iperf_test *test)
                     /* Interval sum, UDP. */
                     if (stream_must_be_sender) {
                         if (test->json_output)
-                            cJSON_AddItemToObject(json_interval, "sum", iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f  packets: %d  omitted: %b sender: %b", (double) start_time, (double) end_time, (double) irp->interval_duration, (int64_t) bytes, bandwidth * 8, (int64_t) total_packets, test->omitting, stream_must_be_sender));
+                            cJSON_AddItemToObject(json_interval, sum_name, iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f  packets: %d  omitted: %b sender: %b", (double) start_time, (double) end_time, (double) irp->interval_duration, (int64_t) bytes, bandwidth * 8, (int64_t) total_packets, test->omitting, stream_must_be_sender));
                         else
                             iperf_printf(test, report_sum_bw_udp_sender_format, mbuf, start_time, end_time, ubuf, nbuf, zbuf, total_packets, test->omitting?report_omitted:"");
                     } else {
@@ -3305,7 +3421,7 @@ iperf_print_intermediate(struct iperf_test *test)
                             lost_percent = 0.0;
                         }
                         if (test->json_output)
-                            cJSON_AddItemToObject(json_interval, "sum", iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f  jitter_ms: %f  lost_packets: %d  packets: %d  lost_percent: %f  omitted: %b sender: %b", (double) start_time, (double) end_time, (double) irp->interval_duration, (int64_t) bytes, bandwidth * 8, (double) avg_jitter * 1000.0, (int64_t) lost_packets, (int64_t) total_packets, (double) lost_percent, test->omitting, stream_must_be_sender));
+                            cJSON_AddItemToObject(json_interval, sum_name, iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f  jitter_ms: %f  lost_packets: %d  packets: %d  lost_percent: %f  omitted: %b sender: %b", (double) start_time, (double) end_time, (double) irp->interval_duration, (int64_t) bytes, bandwidth * 8, (double) avg_jitter * 1000.0, (int64_t) lost_packets, (int64_t) total_packets, (double) lost_percent, test->omitting, stream_must_be_sender));
                         else
                             iperf_printf(test, report_sum_bw_udp_format, mbuf, start_time, end_time, ubuf, nbuf, avg_jitter * 1000.0, lost_packets, total_packets, lost_percent, test->omitting?report_omitted:"");
                     }
@@ -3327,6 +3443,8 @@ iperf_print_results(struct iperf_test *test)
     int lower_mode, upper_mode;
     int current_mode;
 
+    char *sum_sent_name, *sum_received_name, *sum_name;
+
     int tmp_sender_has_retransmits = test->sender_has_retransmits;
 
     /* print final summary for all intervals */
@@ -3429,7 +3547,7 @@ iperf_print_results(struct iperf_test *test)
          * the streams.  It's possible to not have any streams at all
          * if the client got interrupted before it got to do anything.
          *
-         * Also note that we try to keep seperate values for the sender
+         * Also note that we try to keep separate values for the sender
          * and receiver ending times.  Earlier iperf (3.1 and earlier)
          * servers didn't send that to the clients, so in this case we fall
          * back to using the client's ending timestamp.  The fallback is
@@ -3646,6 +3764,27 @@ iperf_print_results(struct iperf_test *test)
         }
 
         if (test->num_streams > 1 || test->json_output) {
+            /*
+             * With BIDIR give a different JSON object name to the one sent/receive sums.
+             * The different name is given to the data sent from the server, which is
+             * the "reverse" channel.  This makes sure that the name reported on the server
+             * and client are compatible, and the names are the same as with non-bidir,
+             * except for when reverse is used.
+             */
+            sum_name = "sum";
+            sum_sent_name = "sum_sent";
+            sum_received_name = "sum_received";
+            if (test->mode == BIDIRECTIONAL) {
+                if ((test->role == 'c' && !stream_must_be_sender) ||
+                    (test->role != 'c' && stream_must_be_sender))
+                {
+                    sum_name = "sum_bidir_reverse";
+                    sum_sent_name = "sum_sent_bidir_reverse";
+                    sum_received_name = "sum_received_bidir_reverse";
+                }
+
+            }
+
             unit_snprintf(ubuf, UNIT_LEN, (double) total_sent, 'A');
             /* If no tests were run, arbitrarily set bandwidth to 0. */
             if (sender_time > 0.0) {
@@ -3659,7 +3798,7 @@ iperf_print_results(struct iperf_test *test)
                 if (test->sender_has_retransmits) {
                     /* Summary sum, TCP with retransmits. */
                     if (test->json_output)
-                        cJSON_AddItemToObject(test->json_end, "sum_sent", iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f  retransmits: %d sender: %b", (double) start_time, (double) sender_time, (double) sender_time, (int64_t) total_sent, bandwidth * 8, (int64_t) total_retransmits, stream_must_be_sender));
+                        cJSON_AddItemToObject(test->json_end, sum_sent_name, iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f  retransmits: %d sender: %b", (double) start_time, (double) sender_time, (double) sender_time, (int64_t) total_sent, bandwidth * 8, (int64_t) total_retransmits, stream_must_be_sender));
                     else
                         if (test->role == 's' && !stream_must_be_sender) {
                             if (test->verbose)
@@ -3671,7 +3810,7 @@ iperf_print_results(struct iperf_test *test)
                 } else {
                     /* Summary sum, TCP without retransmits. */
                     if (test->json_output)
-                        cJSON_AddItemToObject(test->json_end, "sum_sent", iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f sender: %b", (double) start_time, (double) sender_time, (double) sender_time, (int64_t) total_sent, bandwidth * 8, stream_must_be_sender));
+                        cJSON_AddItemToObject(test->json_end, sum_sent_name, iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f sender: %b", (double) start_time, (double) sender_time, (double) sender_time, (int64_t) total_sent, bandwidth * 8, stream_must_be_sender));
                     else
                         if (test->role == 's' && !stream_must_be_sender) {
                             if (test->verbose)
@@ -3691,7 +3830,7 @@ iperf_print_results(struct iperf_test *test)
                 }
                 unit_snprintf(nbuf, UNIT_LEN, bandwidth, test->settings->unit_format);
                 if (test->json_output)
-                    cJSON_AddItemToObject(test->json_end, "sum_received", iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f sender: %b", (double) start_time, (double) receiver_time, (double) receiver_time, (int64_t) total_received, bandwidth * 8, stream_must_be_sender));
+                    cJSON_AddItemToObject(test->json_end, sum_received_name, iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f sender: %b", (double) start_time, (double) receiver_time, (double) receiver_time, (int64_t) total_received, bandwidth * 8, stream_must_be_sender));
                 else
                     if (test->role == 's' && stream_must_be_sender) {
                         if (test->verbose)
@@ -3710,9 +3849,21 @@ iperf_print_results(struct iperf_test *test)
                 else {
                     lost_percent = 0.0;
                 }
-                if (test->json_output)
-                    cJSON_AddItemToObject(test->json_end, "sum", iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f  jitter_ms: %f  lost_packets: %d  packets: %d  lost_percent: %f sender: %b", (double) start_time, (double) receiver_time, (double) receiver_time, (int64_t) total_sent, bandwidth * 8, (double) avg_jitter * 1000.0, (int64_t) lost_packets, (int64_t) total_packets, (double) lost_percent, stream_must_be_sender));
-                else {
+                if (test->json_output) {
+                    /*
+                     * Original, summary structure. Using this
+                     * structure is not recommended due to
+                     * ambiguities between the sender and receiver.
+                     */
+                    cJSON_AddItemToObject(test->json_end, sum_name, iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f  jitter_ms: %f  lost_packets: %d  packets: %d  lost_percent: %f sender: %b", (double) start_time, (double) receiver_time, (double) receiver_time, (int64_t) total_sent, bandwidth * 8, (double) avg_jitter * 1000.0, (int64_t) lost_packets, (int64_t) total_packets, (double) lost_percent, stream_must_be_sender));
+                    /*
+                     * Separate sum_sent and sum_received structures.
+                     * Using these structures to get the most complete
+                     * information about UDP transfer.
+                     */
+                    cJSON_AddItemToObject(test->json_end, sum_sent_name, iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f  jitter_ms: %f  lost_packets: %d  packets: %d  lost_percent: %f  sender: %b", (double) start_time, (double) sender_time, (double) sender_time, (int64_t) total_sent, (double) total_sent * 8 / sender_time, (double) 0.0, (int64_t) 0, (int64_t) sender_total_packets, (double) 0.0, 1));
+                    cJSON_AddItemToObject(test->json_end, sum_received_name, iperf_json_printf("start: %f  end: %f  seconds: %f  bytes: %d  bits_per_second: %f  jitter_ms: %f  lost_packets: %d  packets: %d  lost_percent: %f  sender: %b", (double) start_time, (double) receiver_time, (double) receiver_time, (int64_t) total_received, (double) total_received * 8 / receiver_time, (double) avg_jitter * 1000.0, (int64_t) lost_packets, (int64_t) receiver_total_packets, (double) lost_percent, 0));
+                } else {
                     /*
                      * On the client we have both sender and receiver overall summary
                      * stats.  On the server we have only the side that was on the
@@ -3813,8 +3964,8 @@ iperf_print_results(struct iperf_test *test)
 
 /**
  * Main report-printing callback.
- * Prints results either during a test (interval report only) or 
- * after the entire test has been run (last interval report plus 
+ * Prints results either during a test (interval report only) or
+ * after the entire test has been run (last interval report plus
  * overall summary).
  */
 void
@@ -3831,7 +3982,7 @@ iperf_reporter_callback(struct iperf_test *test)
             iperf_print_intermediate(test);
             iperf_print_results(test);
             break;
-    } 
+    }
 
 }
 
@@ -3909,12 +4060,12 @@ print_interval_results(struct iperf_test *test, struct iperf_stream *sp, cJSON *
 	bandwidth = 0.0;
     }
     unit_snprintf(nbuf, UNIT_LEN, bandwidth, test->settings->unit_format);
-    
+
     iperf_time_diff(&sp->result->start_time, &irp->interval_start_time, &temp_time);
     st = iperf_time_in_secs(&temp_time);
     iperf_time_diff(&sp->result->start_time, &irp->interval_end_time, &temp_time);
     et = iperf_time_in_secs(&temp_time);
-    
+
     if (test->protocol->id == Ptcp || test->protocol->id == Psctp) {
 	if (test->sender_has_retransmits == 1 && sp->sender) {
 	    /* Interval, TCP with retransmits. */
@@ -4022,7 +4173,7 @@ iperf_new_stream(struct iperf_test *test, int s, int sender)
 
     memset(sp->result, 0, sizeof(struct iperf_stream_result));
     TAILQ_INIT(&sp->result->interval_results);
-    
+
     /* Create and randomize the buffer */
     sp->buffer_fd = mkstemp(template);
     if (sp->buffer_fd == -1) {
@@ -4216,20 +4367,20 @@ diskfile_send(struct iperf_stream *sp)
         buffer_left += r;
     	rtot += r;
     	if (sp->test->debug) {
-    	    printf("read %d bytes from file, %d total\n", r, rtot);	    
+    	    printf("read %d bytes from file, %d total\n", r, rtot);
     	}
 
         // If the buffer doesn't contain a full buffer at this point,
         // adjust the size of the data to send.
         if (buffer_left != sp->test->settings->blksize) {
-            if (sp->test->debug) 
+            if (sp->test->debug)
                 printf("possible eof\n");
-            // setting data size to be sent, 
-            // which is less than full block/buffer size 
+            // setting data size to be sent,
+            // which is less than full block/buffer size
             // (to be used by iperf_tcp_send, etc.)
-            sp->pending_size = buffer_left; 
+            sp->pending_size = buffer_left;
         }
-    	
+
         // If there's no work left, we're done.
         if (buffer_left == 0) {
     	    sp->test->done = 1;
@@ -4238,9 +4389,9 @@ diskfile_send(struct iperf_stream *sp)
     	}
     }
 
-    // If there's no data left in the file or in the buffer, we're done. 
-    // No more data available to be sent.  
-    // Return without sending data to the network 
+    // If there's no data left in the file or in the buffer, we're done.
+    // No more data available to be sent.
+    // Return without sending data to the network
     if( sp->test->done || buffer_left == 0 ){
         if (sp->test->debug)
               printf("already done\n");
@@ -4277,7 +4428,6 @@ diskfile_recv(struct iperf_stream *sp)
     r = sp->rcv2(sp);
     if (r > 0) {
 	(void) write(sp->diskfile_fd, sp->buffer, r);
-	(void) fsync(sp->diskfile_fd);
     }
     return r;
 }
@@ -4362,10 +4512,10 @@ iperf_create_pidfile(struct iperf_test *test)
 		}
 	    }
 	}
-	
+
 	/*
-	 * File didn't exist, we couldn't read it, or it didn't correspond to 
-	 * a running process.  Try to create it. 
+	 * File didn't exist, we couldn't read it, or it didn't correspond to
+	 * a running process.  Try to create it.
 	 */
 	fd = open(test->pidfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR|S_IWUSR);
 	if (fd < 0) {
diff --git a/src/iperf_api.h b/src/iperf_api.h
index cb4a86d..7b6e5e5 100644
--- a/src/iperf_api.h
+++ b/src/iperf_api.h
@@ -1,5 +1,5 @@
 /*
- * iperf, Copyright (c) 2014-2020, The Regents of the University of
+ * iperf, Copyright (c) 2014-2022, The Regents of the University of
  * California, through Lawrence Berkeley National Laboratory (subject
  * to receipt of any required approvals from the U.S. Dept. of
  * Energy).  All rights reserved.
@@ -60,6 +60,8 @@ typedef uint64_t iperf_size_t;
 #define DEFAULT_NO_MSG_RCVD_TIMEOUT 120000
 #define MIN_NO_MSG_RCVD_TIMEOUT 100
 
+#define WARN_STR_LEN 128
+
 /* short option equivalents, used to support options that only have long form */
 #define OPT_SCTP 1
 #define OPT_LOGFILE 2
@@ -137,6 +139,7 @@ int	iperf_get_test_json_output( struct iperf_test* ipt );
 char*	iperf_get_test_json_output_string ( struct iperf_test* ipt );
 int	iperf_get_test_zerocopy( struct iperf_test* ipt );
 int	iperf_get_test_get_server_output( struct iperf_test* ipt );
+char	iperf_get_test_unit_format(struct iperf_test *ipt);
 char*	iperf_get_test_bind_address ( struct iperf_test* ipt );
 int	iperf_get_test_udp_counters_64bit( struct iperf_test* ipt );
 int	iperf_get_test_one_off( struct iperf_test* ipt );
@@ -177,6 +180,7 @@ void	iperf_set_test_json_output( struct iperf_test* ipt, int json_output );
 int	iperf_has_zerocopy( void );
 void	iperf_set_test_zerocopy( struct iperf_test* ipt, int zerocopy );
 void	iperf_set_test_get_server_output( struct iperf_test* ipt, int get_server_output );
+void	iperf_set_test_unit_format(struct iperf_test *ipt, char unit_format);
 void	iperf_set_test_bind_address( struct iperf_test* ipt, const char *bind_address );
 void	iperf_set_test_udp_counters_64bit( struct iperf_test* ipt, int udp_counters_64bit );
 void	iperf_set_test_one_off( struct iperf_test* ipt, int one_off );
@@ -425,11 +429,13 @@ enum {
     IEAUTHTEST = 142,       // Test authorization failed
     IEBINDDEV = 143,        // Unable to bind-to-device (check perror, maybe permissions?)
     IENOMSG = 144,          // No message was received for NO_MSG_RCVD_TIMEOUT time period
-    IESETDONTFRAGMENT = 145,    // Unable to set IP Do-Not-Fragment
+    IESETDONTFRAGMENT = 145,   // Unable to set IP Do-Not-Fragment
+    IEBINDDEVNOSUPPORT = 146,  // `ip%%dev` is not supported as system does not support bind to device
+    IEHOSTDEV = 147,        // host device name (ip%%<dev>) is supported (and required) only for IPv6 link-local address
     /* Stream errors */
     IECREATESTREAM = 200,   // Unable to create a new stream (check herror/perror)
     IEINITSTREAM = 201,     // Unable to initialize stream (check herror/perror)
-    IESTREAMLISTEN = 202,   // Unable to start stream listener (check perror) 
+    IESTREAMLISTEN = 202,   // Unable to start stream listener (check perror)
     IESTREAMCONNECT = 203,  // Unable to connect stream (check herror/perror)
     IESTREAMACCEPT = 204,   // Unable to accepte stream connection (check perror)
     IESTREAMWRITE = 205,    // Unable to write to stream socket (check perror)
diff --git a/src/iperf_auth.c b/src/iperf_auth.c
index 56b7382..867c55f 100644
--- a/src/iperf_auth.c
+++ b/src/iperf_auth.c
@@ -163,11 +163,11 @@ EVP_PKEY *load_pubkey_from_file(const char *file) {
     if (file) {
       key = BIO_new_file(file, "r");
       pkey = PEM_read_bio_PUBKEY(key, NULL, NULL, NULL);
- 
+
       BIO_free(key);
     }
     return (pkey);
-}   
+}
 
 EVP_PKEY *load_pubkey_from_base64(const char *buffer) {
     unsigned char *key = NULL;
@@ -246,18 +246,18 @@ int encrypt_rsa_message(const char *plaintext, EVP_PKEY *public_key, unsigned ch
     BIO_free(bioBuff);
 
     if (encryptedtext_len < 0) {
-      /* We probably shoudln't be printing stuff like this */
+      /* We probably shouldn't be printing stuff like this */
       fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
     }
 
-    return encryptedtext_len;  
+    return encryptedtext_len;
 }
 
 int decrypt_rsa_message(const unsigned char *encryptedtext, const int encryptedtext_len, EVP_PKEY *private_key, unsigned char **plaintext) {
     RSA *rsa = NULL;
     unsigned char *rsa_buffer = NULL, pad = RSA_PKCS1_PADDING;
     int plaintext_len, rsa_buffer_len, keysize;
-    
+
     rsa = EVP_PKEY_get1_RSA(private_key);
 
     keysize = RSA_size(rsa);
@@ -273,7 +273,7 @@ int decrypt_rsa_message(const unsigned char *encryptedtext, const int encryptedt
     BIO_free(bioBuff);
 
     if (plaintext_len < 0) {
-      /* We probably shoudln't be printing stuff like this */
+      /* We probably shouldn't be printing stuff like this */
       fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
     }
 
@@ -385,5 +385,3 @@ ssize_t iperf_getpass (char **lineptr, size_t *n, FILE *stream) {
 
     return nread;
 }
-
-
diff --git a/src/iperf_client_api.c b/src/iperf_client_api.c
index e7031b3..72699a3 100644
--- a/src/iperf_client_api.c
+++ b/src/iperf_client_api.c
@@ -1,5 +1,5 @@
 /*
- * iperf, Copyright (c) 2014-2021, The Regents of the University of
+ * iperf, Copyright (c) 2014-2022, The Regents of the University of
  * California, through Lawrence Berkeley National Laboratory (subject
  * to receipt of any required approvals from the U.S. Dept. of
  * Energy).  All rights reserved.
@@ -54,6 +54,11 @@
 int
 iperf_create_streams(struct iperf_test *test, int sender)
 {
+    if (NULL == test)
+    {
+        iperf_err(NULL, "No test\n");
+        return -1;
+    }
     int i, s;
 #if defined(HAVE_TCP_CONGESTION)
     int saved_errno;
@@ -78,7 +83,7 @@ iperf_create_streams(struct iperf_test *test, int sender)
 		    errno = saved_errno;
 		    i_errno = IESETCONGESTION;
 		    return -1;
-		} 
+		}
 	    }
 	    {
 		socklen_t len = TCP_CA_NAME_MAX;
@@ -158,6 +163,12 @@ create_client_timers(struct iperf_test * test)
 {
     struct iperf_time now;
     TimerClientData cd;
+    if (NULL == test)
+    {
+        iperf_err(NULL, "No test\n");
+        i_errno = IEINITTEST;
+        return -1;
+    }
 
     if (iperf_time_now(&now) < 0) {
 	i_errno = IEINITTEST;
@@ -172,7 +183,7 @@ create_client_timers(struct iperf_test * test)
             i_errno = IEINITTEST;
             return -1;
 	}
-    } 
+    }
     if (test->stats_interval != 0) {
         test->stats_timer = tmr_create(&now, client_stats_timer_proc, cd, test->stats_interval * SEC_TO_US, 1);
         if (test->stats_timer == NULL) {
@@ -213,6 +224,11 @@ create_client_omit_timer(struct iperf_test * test)
 {
     struct iperf_time now;
     TimerClientData cd;
+    if (NULL == test)
+    {
+        iperf_err(NULL, "No test\n");
+        return -1;
+    }
 
     if (test->omit == 0) {
 	test->omit_timer = NULL;
@@ -239,6 +255,12 @@ iperf_handle_message_client(struct iperf_test *test)
     int rval;
     int32_t err;
 
+    if (NULL == test)
+    {
+        iperf_err(NULL, "No test\n");
+	i_errno = IEINITTEST;
+        return -1;
+    }
     /*!!! Why is this read() and not Nread()? */
     if ((rval = read(test->ctrl_sck, (char*) &test->state, sizeof(signed char))) <= 0) {
         if (rval == 0) {
@@ -334,6 +356,11 @@ iperf_handle_message_client(struct iperf_test *test)
 int
 iperf_connect(struct iperf_test *test)
 {
+    if (NULL == test)
+    {
+        iperf_err(NULL, "No test\n");
+        return -1;
+    }
     FD_ZERO(&test->read_set);
     FD_ZERO(&test->write_set);
 
@@ -375,7 +402,7 @@ iperf_connect(struct iperf_test *test)
             test->ctrl_sck_mss = opt;
         }
         else {
-            char str[128];
+            char str[WARN_STR_LEN];
             snprintf(str, sizeof(str),
                      "Ignoring nonsense TCP MSS %d", opt);
             warning(str);
@@ -422,7 +449,7 @@ iperf_connect(struct iperf_test *test)
 	 */
 	if (test->ctrl_sck_mss > 0 &&
 	    test->settings->blksize > test->ctrl_sck_mss) {
-	    char str[128];
+	    char str[WARN_STR_LEN];
 	    snprintf(str, sizeof(str),
 		     "UDP block size %d exceeds TCP MSS %d, may result in fragmentation / drops", test->settings->blksize, test->ctrl_sck_mss);
 	    warning(str);
@@ -436,6 +463,11 @@ iperf_connect(struct iperf_test *test)
 int
 iperf_client_end(struct iperf_test *test)
 {
+    if (NULL == test)
+    {
+        iperf_err(NULL, "No test\n");
+        return -1;
+    }
     struct iperf_stream *sp;
 
     /* Close all stream sockets */
@@ -476,6 +508,12 @@ iperf_run_client(struct iperf_test * test)
     int64_t timeout_us;
     int64_t rcv_timeout_us;
 
+    if (NULL == test)
+    {
+        iperf_err(NULL, "No test\n");
+        return -1;
+    }
+
     if (test->logfile)
         if (iperf_open_logfile(test) < 0)
             return -1;
@@ -548,7 +586,7 @@ iperf_run_client(struct iperf_test * test)
 
             }
         }
-        
+
 	if (result > 0) {
             if (rcv_timeout_us > 0) {
                 iperf_time_now(&last_receive_time);
@@ -651,13 +689,15 @@ iperf_run_client(struct iperf_test * test)
     return 0;
 
   cleanup_and_fail:
-    iperf_errexit(test, "error - %s", iperf_strerror(i_errno));
     iperf_client_end(test);
     if (test->json_output) {
-	if (iperf_json_finish(test) < 0)
-	    return -1;  // It is o.k. that error will be logged later outside the JSON output since its creation failed
+        cJSON_AddStringToObject(test->json_top, "error", iperf_strerror(i_errno));
+        iperf_json_finish(test);
+        iflush(test);
+        // Return 0 and not -1 since all terminating function were done here.
+        // Also prevents error message logging outside the already closed JSON output.
+        return 0;
     }
     iflush(test);
-    return 0;   // Return 0 and not -1 since all terminating function were done here.
-                // Also prevents error message logging outside the already closed JSON output.
+    return -1;
 }
diff --git a/src/iperf_config.h.in b/src/iperf_config.h.in
index 7b98a59..0451269 100644
--- a/src/iperf_config.h.in
+++ b/src/iperf_config.h.in
@@ -15,7 +15,7 @@
 /* Define to 1 if you have the <dlfcn.h> header file. */
 #undef HAVE_DLFCN_H
 
-/* Have IP_MTU_DISCOVER/IP_DONTFRAG sockopt. */
+/* Have IP_MTU_DISCOVER/IP_DONTFRAG/IP_DONTFRAGMENT sockopt. */
 #undef HAVE_DONT_FRAGMENT
 
 /* Define to 1 if you have the <endian.h> header file. */
@@ -30,6 +30,15 @@
 /* Define to 1 if you have the <inttypes.h> header file. */
 #undef HAVE_INTTYPES_H
 
+/* Have IP_DONTFRAG sockopt. */
+#undef HAVE_IP_DONTFRAG
+
+/* Have IP_DONTFRAGMENT sockopt. */
+#undef HAVE_IP_DONTFRAGMENT
+
+/* Have IP_MTU_DISCOVER sockopt. */
+#undef HAVE_IP_MTU_DISCOVER
+
 /* Define to 1 if you have the <linux/tcp.h> header file. */
 #undef HAVE_LINUX_TCP_H
 
diff --git a/src/iperf_error.c b/src/iperf_error.c
index 1bcf8a8..faade90 100644
--- a/src/iperf_error.c
+++ b/src/iperf_error.c
@@ -1,5 +1,5 @@
 /*
- * iperf, Copyright (c) 2014-2021, The Regents of the University of
+ * iperf, Copyright (c) 2014-2022, The Regents of the University of
  * California, through Lawrence Berkeley National Laboratory (subject
  * to receipt of any required approvals from the U.S. Dept. of
  * Energy).  All rights reserved.
@@ -59,7 +59,7 @@ iperf_err(struct iperf_test *test, const char *format, ...)
     vsnprintf(str, sizeof(str), format, argp);
     if (test != NULL && test->json_output && test->json_top != NULL)
 	cJSON_AddStringToObject(test->json_top, "error", str);
-    else
+    else {
 	if (test && test->outfile && test->outfile != stdout) {
 	    if (ct) {
 		fprintf(test->outfile, "%s", ct);
@@ -72,6 +72,7 @@ iperf_err(struct iperf_test *test, const char *format, ...)
 	    }
 	    fprintf(stderr, "iperf3: %s\n", str);
 	}
+    }
     va_end(argp);
 }
 
@@ -400,7 +401,7 @@ iperf_strerror(int int_errno)
             perr = 1;
             break;
         case IESETCONGESTION:
-            snprintf(errstr, len, "unable to set TCP_CONGESTION: " 
+            snprintf(errstr, len, "unable to set TCP_CONGESTION: "
                                   "Supplied congestion control algorithm not supported on this host");
             break;
 	case IEPIDFILE:
@@ -436,8 +437,17 @@ iperf_strerror(int int_errno)
 	    snprintf(errstr, len, "skew threshold must be a positive number");
             break;
 	case IEIDLETIMEOUT:
-	    snprintf(errstr, len, "idle timeout parameter is not positive or larget then allowed limit");
+	    snprintf(errstr, len, "idle timeout parameter is not positive or larger than allowed limit");
+            break;
+	case IEBINDDEV:
+	    snprintf(errstr, len, "Unable to bind-to-device (check perror, maybe permissions?)");
+            break;
+    case IEBINDDEVNOSUPPORT:
+	    snprintf(errstr, len, "`<ip>%%<dev>` is not supported as system does not support bind to device");
             break;
+    case IEHOSTDEV:
+	    snprintf(errstr, len, "host device name (ip%%<dev>) is supported (and required) only for IPv6 link-local address");
+            break;        
 	case IENOMSG:
 	    snprintf(errstr, len, "idle timeout for receiving data");
             break;
diff --git a/src/iperf_locale.c b/src/iperf_locale.c
index e1e9dc5..58a6d77 100644
--- a/src/iperf_locale.c
+++ b/src/iperf_locale.c
@@ -1,5 +1,5 @@
-/*--------------------------------------------------------------- 
- * iperf, Copyright (c) 2014-2021, The Regents of the University of
+/*---------------------------------------------------------------
+ * iperf, Copyright (c) 2014-2022, The Regents of the University of
  * California, through Lawrence Berkeley National Laboratory (subject
  * to receipt of any required approvals from the U.S. Dept. of
  * Energy).  All rights reserved.
@@ -27,49 +27,49 @@
  * Based on code that is:
  *
  * Copyright (c) 1999,2000,2001,2002,2003
- * The Board of Trustees of the University of Illinois            
- * All Rights Reserved.                                           
- *--------------------------------------------------------------- 
- * Permission is hereby granted, free of charge, to any person    
- * obtaining a copy of this software (Iperf) and associated       
- * documentation files (the "Software"), to deal in the Software  
- * without restriction, including without limitation the          
- * rights to use, copy, modify, merge, publish, distribute,        
- * sublicense, and/or sell copies of the Software, and to permit     
+ * The Board of Trustees of the University of Illinois
+ * All Rights Reserved.
+ *---------------------------------------------------------------
+ * Permission is hereby granted, free of charge, to any person
+ * obtaining a copy of this software (Iperf) and associated
+ * documentation files (the "Software"), to deal in the Software
+ * without restriction, including without limitation the
+ * rights to use, copy, modify, merge, publish, distribute,
+ * sublicense, and/or sell copies of the Software, and to permit
  * persons to whom the Software is furnished to do
- * so, subject to the following conditions: 
+ * so, subject to the following conditions:
  *
- *     
- * Redistributions of source code must retain the above 
- * copyright notice, this list of conditions and 
- * the following disclaimers. 
  *
- *     
- * Redistributions in binary form must reproduce the above 
- * copyright notice, this list of conditions and the following 
- * disclaimers in the documentation and/or other materials 
- * provided with the distribution. 
- * 
- *     
- * Neither the names of the University of Illinois, NCSA, 
- * nor the names of its contributors may be used to endorse 
+ * Redistributions of source code must retain the above
+ * copyright notice, this list of conditions and
+ * the following disclaimers.
+ *
+ *
+ * Redistributions in binary form must reproduce the above
+ * copyright notice, this list of conditions and the following
+ * disclaimers in the documentation and/or other materials
+ * provided with the distribution.
+ *
+ *
+ * Neither the names of the University of Illinois, NCSA,
+ * nor the names of its contributors may be used to endorse
  * or promote products derived from this Software without
- * specific prior written permission. 
- * 
- * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
- * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
- * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
- * NONINFRINGEMENT. IN NO EVENT SHALL THE CONTIBUTORS OR COPYRIGHT 
- * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
- * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
+ * specific prior written permission.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+ * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
+ * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
+ * NONINFRINGEMENT. IN NO EVENT SHALL THE CONTIBUTORS OR COPYRIGHT
+ * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
+ * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
  * ARISING FROM, OUT OF OR IN CONNECTION WITH THE
- * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
+ * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  * ________________________________________________________________
- * National Laboratory for Applied Network Research 
- * National Center for Supercomputing Applications 
- * University of Illinois at Urbana-Champaign 
+ * National Laboratory for Applied Network Research
+ * National Center for Supercomputing Applications
+ * University of Illinois at Urbana-Champaign
  * http://www.ncsa.uiuc.edu
- * ________________________________________________________________ 
+ * ________________________________________________________________
  *
  * Locale.c
  * by Ajay Tirumala <tirumala@ncsa.uiuc.edu>
@@ -105,9 +105,12 @@ const char usage_longstr[] = "Usage: iperf3 [-s|-c host] [options]\n"
 #if defined(HAVE_CPU_AFFINITY)
                            "  -A, --affinity n/n,m      set CPU affinity\n"
 #endif /* HAVE_CPU_AFFINITY */
-                           "  -B, --bind      <host>    bind to the interface associated with the address <host>\n"
 #if defined(HAVE_SO_BINDTODEVICE)
-                           "  --bind-dev      <dev>     bind to the network interface with SO_BINDTODEVICE\n"
+                           "  -B, --bind <host>[%<dev>] bind to the interface associated with the address <host>\n"
+                           "                            (optional <dev> equivalent to `--bind-dev <dev>`)\n"
+                           "  --bind-dev <dev>          bind to the network interface with SO_BINDTODEVICE\n"
+#else /* HAVE_SO_BINDTODEVICE */
+                           "  -B, --bind      <host>    bind to the interface associated with the address <host>\n"
 #endif /* HAVE_SO_BINDTODEVICE */
                            "  -V, --verbose             more detailed output\n"
                            "  -J, --json                output in JSON format\n"
@@ -115,7 +118,7 @@ const char usage_longstr[] = "Usage: iperf3 [-s|-c host] [options]\n"
                            "  --forceflush              force flushing output at every interval\n"
                            "  --timestamps<=format>     emit a timestamp at the start of each output line\n"
                            "                            (optional \"=\" and format string as per strftime(3))\n"
-    
+
                            "  --rcv-timeout #           idle timeout for receiving data\n"
                            "                            (default %d ms)\n"
                            "  -d, --debug               emit debugging output\n"
@@ -139,7 +142,8 @@ const char usage_longstr[] = "Usage: iperf3 [-s|-c host] [options]\n"
                            "                            and client during the authentication process\n"
 #endif //HAVE_SSL
                            "Client specific:\n"
-                           "  -c, --client    <host>    run in client mode, connecting to <host>\n"
+                           "  -c, --client <host>[%<dev>] run in client mode, connecting to <host>\n"
+                           "                              (option <dev> equivalent to `--bind-dev <dev>`)\n"
 #if defined(HAVE_SCTP_H)
                            "  --sctp                    use SCTP rather than TCP\n"
                            "  -X, --xbind <name>        bind SCTP association to links\n"
@@ -165,7 +169,9 @@ const char usage_longstr[] = "Usage: iperf3 [-s|-c host] [options]\n"
                            "  -R, --reverse             run in reverse mode (server sends, client receives)\n"
                            "  --bidir                   run in bidirectional mode.\n"
                            "                            Client and server send and receive data.\n"
-                           "  -w, --window    #[KMG]    set window size / socket buffer size\n"
+                           "  -w, --window    #[KMG]    set send/receive socket buffer sizes\n"
+                           "                            (indirectly sets TCP window size)\n"
+
 #if defined(HAVE_TCP_CONGESTION)
                            "  -C, --congestion <algo>   set TCP congestion control algorithm (Linux and FreeBSD only)\n"
 #endif /* HAVE_TCP_CONGESTION */
@@ -199,7 +205,7 @@ const char usage_longstr[] = "Usage: iperf3 [-s|-c host] [options]\n"
                            "  --rsa-public-key-path     path to the RSA public key used to encrypt\n"
                            "                            authentication credentials\n"
 #endif //HAVESSL
-    
+
 #ifdef NOT_YET_SUPPORTED /* still working on these */
 #endif
 
diff --git a/src/iperf_sctp.c b/src/iperf_sctp.c
index 0686fd9..ceccdc1 100644
--- a/src/iperf_sctp.c
+++ b/src/iperf_sctp.c
@@ -82,7 +82,7 @@ iperf_sctp_recv(struct iperf_stream *sp)
 }
 
 
-/* iperf_sctp_send 
+/* iperf_sctp_send
  *
  * sends the data for SCTP
  */
@@ -94,7 +94,7 @@ iperf_sctp_send(struct iperf_stream *sp)
 
     r = Nwrite(sp->socket, sp->buffer, sp->settings->blksize, Psctp);
     if (r < 0)
-        return r;    
+        return r;
 
     sp->result->bytes_sent += r;
     sp->result->bytes_sent_this_interval += r;
@@ -165,7 +165,7 @@ iperf_sctp_listen(struct iperf_test *test)
     int s, opt, saved_errno;
 
     close(test->listener);
-   
+
     snprintf(portstr, 6, "%d", test->server_port);
     memset(&hints, 0, sizeof(hints));
     /*
@@ -227,13 +227,13 @@ iperf_sctp_listen(struct iperf_test *test)
     }
 
 #if defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
-    if (res->ai_family == AF_INET6 && (test->settings->domain == AF_UNSPEC || 
+    if (res->ai_family == AF_INET6 && (test->settings->domain == AF_UNSPEC ||
         test->settings->domain == AF_INET6)) {
         if (test->settings->domain == AF_UNSPEC)
             opt = 0;
         else
             opt = 1;
-        if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, 
+        if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
 		       (char *) &opt, sizeof(opt)) < 0) {
 	    saved_errno = errno;
 	    close(s);
@@ -280,7 +280,7 @@ iperf_sctp_listen(struct iperf_test *test)
     }
 
     test->listener = s;
-  
+
     return s;
 #else
     i_errno = IENOSCTP;
diff --git a/src/iperf_server_api.c b/src/iperf_server_api.c
index 500ff73..8bd7eec 100644
--- a/src/iperf_server_api.c
+++ b/src/iperf_server_api.c
@@ -1,5 +1,5 @@
 /*
- * iperf, Copyright (c) 2014-2021 The Regents of the University of
+ * iperf, Copyright (c) 2014-2022 The Regents of the University of
  * California, through Lawrence Berkeley National Laboratory (subject
  * to receipt of any required approvals from the U.S. Dept. of
  * Energy).  All rights reserved.
@@ -141,14 +141,14 @@ iperf_accept(struct iperf_test *test)
             return -1;
         if (iperf_exchange_parameters(test) < 0)
             return -1;
-	if (test->server_affinity != -1) 
+	if (test->server_affinity != -1)
 	    if (iperf_setaffinity(test, test->server_affinity) != 0)
 		return -1;
         if (test->on_connect)
             test->on_connect(test);
     } else {
 	/*
-	 * Don't try to read from the socket.  It could block an ongoing test. 
+	 * Don't try to read from the socket.  It could block an ongoing test.
 	 * Just send ACCESS_DENIED.
          * Also, if sending failed, don't return an error, as the request is not related
          * to the ongoing test, and returning an error will terminate the test.
@@ -325,7 +325,7 @@ create_server_timers(struct iperf_test * test)
 
 static void
 server_omit_timer_proc(TimerClientData client_data, struct iperf_time *nowP)
-{   
+{
     struct iperf_test *test = client_data.p;
 
     test->omit_timer = NULL;
@@ -345,7 +345,7 @@ static int
 create_server_omit_timer(struct iperf_test * test)
 {
     struct iperf_time now;
-    TimerClientData cd; 
+    TimerClientData cd;
 
     if (test->omit == 0) {
 	test->omit_timer = NULL;
@@ -353,11 +353,11 @@ create_server_omit_timer(struct iperf_test * test)
     } else {
 	if (iperf_time_now(&now) < 0) {
 	    i_errno = IEINITTEST;
-	    return -1; 
+	    return -1;
 	}
 	test->omitting = 1;
 	cd.p = test;
-	test->omit_timer = tmr_create(&now, server_omit_timer_proc, cd, test->omit * SEC_TO_US, 0); 
+	test->omit_timer = tmr_create(&now, server_omit_timer_proc, cd, test->omit * SEC_TO_US, 0);
 	if (test->omit_timer == NULL) {
 	    i_errno = IEINITTEST;
 	    return -1;
@@ -439,7 +439,7 @@ iperf_run_server(struct iperf_test *test)
         if (iperf_open_logfile(test) < 0)
             return -1;
 
-    if (test->affinity != -1) 
+    if (test->affinity != -1)
 	if (iperf_setaffinity(test, test->affinity) != 0)
 	    return -2;
 
@@ -475,7 +475,7 @@ iperf_run_server(struct iperf_test *test)
 	if (test->bitrate_limit_exceeded) {
 	    cleanup_server(test);
             i_errno = IETOTALRATE;
-            return -1;	
+            return -1;
 	}
 
         memcpy(&read_set, &test->read_set, sizeof(fd_set));
@@ -525,6 +525,13 @@ iperf_run_server(struct iperf_test *test)
                             printf("Server restart (#%d) in idle state as no connection request was received for %d sec\n",
                                 test->server_forced_idle_restarts_count, test->settings->idle_timeout);
                         cleanup_server(test);
+			if ( iperf_get_test_one_off(test) ) {
+			  if (test->debug)
+                            printf("No connection request was received for %d sec in one-off mode; exiting.\n",
+				   test->settings->idle_timeout);
+			  exit(0);
+			}
+
                         return 2;
                     }
                 }
@@ -569,12 +576,12 @@ iperf_run_server(struct iperf_test *test)
 		    cleanup_server(test);
                     return -1;
 		}
-                FD_CLR(test->ctrl_sck, &read_set);                
+                FD_CLR(test->ctrl_sck, &read_set);
             }
 
             if (test->state == CREATE_STREAMS) {
                 if (FD_ISSET(test->prot_listener, &read_set)) {
-    
+
                     if ((s = test->protocol->accept(test)) < 0) {
 			cleanup_server(test);
                         return -1;
@@ -606,7 +613,7 @@ iperf_run_server(struct iperf_test *test)
 				    i_errno = IESETCONGESTION;
 				    return -1;
 				}
-			    } 
+			    }
 			}
 			{
 			    socklen_t len = TCP_CA_NAME_MAX;
@@ -621,7 +628,7 @@ iperf_run_server(struct iperf_test *test)
 				i_errno = IESETCONGESTION;
 				return -1;
 			    }
-                            /* 
+                            /*
                              * If not the first connection, discard prior
                              * congestion algorithm name so we don't leak
                              * duplicated strings.  We probably don't need
@@ -689,7 +696,7 @@ iperf_run_server(struct iperf_test *test)
                     if (test->protocol->id != Ptcp) {
                         FD_CLR(test->prot_listener, &test->read_set);
                         close(test->prot_listener);
-                    } else { 
+                    } else {
                         if (test->no_delay || test->settings->mss || test->settings->socket_bufsize) {
                             FD_CLR(test->listener, &test->read_set);
                             close(test->listener);
@@ -787,11 +794,11 @@ iperf_run_server(struct iperf_test *test)
     if (test->json_output) {
 	if (iperf_json_finish(test) < 0)
 	    return -1;
-    } 
+    }
 
     iflush(test);
 
-    if (test->server_affinity != -1) 
+    if (test->server_affinity != -1)
 	if (iperf_clearaffinity(test) != 0)
 	    return -1;
 
diff --git a/src/iperf_tcp.c b/src/iperf_tcp.c
index c78f4f5..b914532 100644
--- a/src/iperf_tcp.c
+++ b/src/iperf_tcp.c
@@ -1,5 +1,5 @@
 /*
- * iperf, Copyright (c) 2014-2021, The Regents of the University of
+ * iperf, Copyright (c) 2014-2022, The Regents of the University of
  * California, through Lawrence Berkeley National Laboratory (subject
  * to receipt of any required approvals from the U.S. Dept. of
  * Energy).  All rights reserved.
@@ -76,7 +76,7 @@ iperf_tcp_recv(struct iperf_stream *sp)
 }
 
 
-/* iperf_tcp_send 
+/* iperf_tcp_send
  *
  * sends the data for TCP
  */
@@ -274,7 +274,7 @@ iperf_tcp_listen(struct iperf_test *test)
         }
 
 	/*
-	 * If we got an IPv6 socket, figure out if it shoudl accept IPv4
+	 * If we got an IPv6 socket, figure out if it should accept IPv4
 	 * connections as well.  See documentation in netannounce() for
 	 * more details.
 	 */
@@ -282,9 +282,9 @@ iperf_tcp_listen(struct iperf_test *test)
 	if (res->ai_family == AF_INET6 && (test->settings->domain == AF_UNSPEC || test->settings->domain == AF_INET)) {
 	    if (test->settings->domain == AF_UNSPEC)
 		opt = 0;
-	    else 
+	    else
 		opt = 1;
-	    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, 
+	    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
 			   (char *) &opt, sizeof(opt)) < 0) {
 		saved_errno = errno;
 		close(s);
@@ -314,7 +314,7 @@ iperf_tcp_listen(struct iperf_test *test)
 
         test->listener = s;
     }
-    
+
     /* Read back and verify the sender socket buffer size */
     optlen = sizeof(sndbuf_actual);
     if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf_actual, &optlen) < 0) {
@@ -369,101 +369,16 @@ iperf_tcp_listen(struct iperf_test *test)
 int
 iperf_tcp_connect(struct iperf_test *test)
 {
-    struct addrinfo hints, *local_res, *server_res;
-    char portstr[6];
+    struct addrinfo *server_res;
     int s, opt;
     socklen_t optlen;
     int saved_errno;
     int rcvbuf_actual, sndbuf_actual;
 
-    if (test->bind_address) {
-        memset(&hints, 0, sizeof(hints));
-        hints.ai_family = test->settings->domain;
-        hints.ai_socktype = SOCK_STREAM;
-        if ((gerror = getaddrinfo(test->bind_address, NULL, &hints, &local_res)) != 0) {
-            i_errno = IESTREAMCONNECT;
-            return -1;
-        }
-    }
-
-    memset(&hints, 0, sizeof(hints));
-    hints.ai_family = test->settings->domain;
-    hints.ai_socktype = SOCK_STREAM;
-    snprintf(portstr, sizeof(portstr), "%d", test->server_port);
-    if ((gerror = getaddrinfo(test->server_hostname, portstr, &hints, &server_res)) != 0) {
-	if (test->bind_address)
-	    freeaddrinfo(local_res);
-        i_errno = IESTREAMCONNECT;
-        return -1;
-    }
-
-    if ((s = socket(server_res->ai_family, SOCK_STREAM, 0)) < 0) {
-	if (test->bind_address)
-	    freeaddrinfo(local_res);
-	freeaddrinfo(server_res);
-        i_errno = IESTREAMCONNECT;
-        return -1;
-    }
-
-    /*
-     * Various ways to bind the local end of the connection.
-     * 1.  --bind (with or without --cport).
-     */
-    if (test->bind_address) {
-        struct sockaddr_in *lcladdr;
-        lcladdr = (struct sockaddr_in *)local_res->ai_addr;
-        lcladdr->sin_port = htons(test->bind_port);
-
-        if (bind(s, (struct sockaddr *) local_res->ai_addr, local_res->ai_addrlen) < 0) {
-	    saved_errno = errno;
-	    close(s);
-	    freeaddrinfo(local_res);
-	    freeaddrinfo(server_res);
-	    errno = saved_errno;
-            i_errno = IESTREAMCONNECT;
-            return -1;
-        }
-        freeaddrinfo(local_res);
-    }
-    /* --cport, no --bind */
-    else if (test->bind_port) {
-	size_t addrlen;
-	struct sockaddr_storage lcl;
-
-	/* IPv4 */
-	if (server_res->ai_family == AF_INET) {
-	    struct sockaddr_in *lcladdr = (struct sockaddr_in *) &lcl;
-	    lcladdr->sin_family = AF_INET;
-	    lcladdr->sin_port = htons(test->bind_port);
-	    lcladdr->sin_addr.s_addr = INADDR_ANY;
-	    addrlen = sizeof(struct sockaddr_in);
-	}
-	/* IPv6 */
-	else if (server_res->ai_family == AF_INET6) {
-	    struct sockaddr_in6 *lcladdr = (struct sockaddr_in6 *) &lcl;
-	    lcladdr->sin6_family = AF_INET6;
-	    lcladdr->sin6_port = htons(test->bind_port);
-	    lcladdr->sin6_addr = in6addr_any;
-	    addrlen = sizeof(struct sockaddr_in6);
-	}
-	/* Unknown protocol */
-	else {
-	    saved_errno = errno;
-	    close(s);
-	    freeaddrinfo(server_res);
-	    errno = saved_errno;
-            i_errno = IEPROTOCOL;
-            return -1;
-	}
-
-        if (bind(s, (struct sockaddr *) &lcl, addrlen) < 0) {
-	    saved_errno = errno;
-	    close(s);
-	    freeaddrinfo(server_res);
-	    errno = saved_errno;
-            i_errno = IESTREAMCONNECT;
-            return -1;
-        }
+    s = create_socket(test->settings->domain, SOCK_STREAM, test->bind_address, test->bind_dev, test->bind_port, test->server_hostname, test->server_port, &server_res);
+    if (s < 0) {
+	i_errno = IESTREAMCONNECT;
+	return -1;
     }
 
     /* Set socket options */
@@ -589,7 +504,7 @@ iperf_tcp_connect(struct iperf_test *test)
 		errno = saved_errno;
                 i_errno = IESETFLOW;
                 return -1;
-            } 
+            }
 	}
     }
 #endif /* HAVE_FLOWLABEL */
diff --git a/src/iperf_time.c b/src/iperf_time.c
index 5f94dc0..a435dd3 100644
--- a/src/iperf_time.c
+++ b/src/iperf_time.c
@@ -89,13 +89,13 @@ iperf_time_in_usecs(struct iperf_time *time)
 double
 iperf_time_in_secs(struct iperf_time *time)
 {
-    return time->secs + time->usecs / 1000000.0; 
+    return time->secs + time->usecs / 1000000.0;
 }
 
 /* iperf_time_compare
  *
  * Compare two timestamps
- * 
+ *
  * Returns -1 if time1 is earlier, 1 if time1 is later,
  * or 0 if the timestamps are equal.
  */
@@ -121,7 +121,7 @@ iperf_time_compare(struct iperf_time *time1, struct iperf_time *time2)
  *
  * Returns 1 if the time1 is less than or equal to time2, otherwise 0.
  */
-int 
+int
 iperf_time_diff(struct iperf_time *time1, struct iperf_time *time2, struct iperf_time *diff)
 {
     int past = 0;
@@ -132,7 +132,7 @@ iperf_time_diff(struct iperf_time *time1, struct iperf_time *time2, struct iperf
         diff->secs = 0;
         diff->usecs = 0;
         past = 1;
-    } 
+    }
     else if (cmp == 1) {
         diff->secs = time1->secs - time2->secs;
         diff->usecs = time1->usecs;
diff --git a/src/iperf_udp.c b/src/iperf_udp.c
index 126cd63..5bc7780 100644
--- a/src/iperf_udp.c
+++ b/src/iperf_udp.c
@@ -1,5 +1,5 @@
 /*
- * iperf, Copyright (c) 2014-2020, The Regents of the University of
+ * iperf, Copyright (c) 2014-2022, The Regents of the University of
  * California, through Lawrence Berkeley National Laboratory (subject
  * to receipt of any required approvals from the U.S. Dept. of
  * Energy).  All rights reserved.
@@ -150,7 +150,7 @@ iperf_udp_recv(struct iperf_stream *sp)
 	    sp->packet_count = pcount;
 	} else {
 
-	    /* 
+	    /*
 	     * Sequence number went backward (or was stationary?!?).
 	     * This counts as an out-of-order packet.
 	     */
@@ -164,9 +164,9 @@ iperf_udp_recv(struct iperf_stream *sp)
 	     */
 	    if (sp->cnt_error > 0)
 		sp->cnt_error--;
-	
+
 	    /* Log the out-of-order packet */
-	    if (sp->test->debug) 
+	    if (sp->test->debug)
 		fprintf(stderr, "OUT OF ORDER - incoming packet sequence %" PRIu64 " but expected sequence %d on stream %d", pcount, sp->packet_count + 1, sp->socket);
 	}
 
@@ -228,11 +228,11 @@ iperf_udp_send(struct iperf_stream *sp)
 	sec = htonl(before.secs);
 	usec = htonl(before.usecs);
 	pcount = htobe64(sp->packet_count);
-	
+
 	memcpy(sp->buffer, &sec, sizeof(sec));
 	memcpy(sp->buffer+4, &usec, sizeof(usec));
 	memcpy(sp->buffer+8, &pcount, sizeof(pcount));
-	
+
     }
     else {
 
@@ -241,11 +241,11 @@ iperf_udp_send(struct iperf_stream *sp)
 	sec = htonl(before.secs);
 	usec = htonl(before.usecs);
 	pcount = htonl(sp->packet_count);
-	
+
 	memcpy(sp->buffer, &sec, sizeof(sec));
 	memcpy(sp->buffer+4, &usec, sizeof(usec));
 	memcpy(sp->buffer+8, &pcount, sizeof(pcount));
-	
+
     }
 
     r = Nwrite(sp->socket, sp->buffer, size, Pudp);
@@ -291,7 +291,7 @@ iperf_udp_buffercheck(struct iperf_test *test, int s)
      */
     int opt;
     socklen_t optlen;
-    
+
     if ((opt = test->settings->socket_bufsize)) {
         if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
             i_errno = IESETBUF;
@@ -317,7 +317,7 @@ iperf_udp_buffercheck(struct iperf_test *test, int s)
 	return -1;
     }
     if (test->settings->blksize > sndbuf_actual) {
-	char str[80];
+	char str[WARN_STR_LEN];
 	snprintf(str, sizeof(str),
 		 "Block size %d > sending socket buffer size %d",
 		 test->settings->blksize, sndbuf_actual);
@@ -339,7 +339,7 @@ iperf_udp_buffercheck(struct iperf_test *test, int s)
 	return -1;
     }
     if (test->settings->blksize > rcvbuf_actual) {
-	char str[80];
+	char str[WARN_STR_LEN];
 	snprintf(str, sizeof(str),
 		 "Block size %d > receiving socket buffer size %d",
 		 test->settings->blksize, rcvbuf_actual);
@@ -403,16 +403,18 @@ iperf_udp_accept(struct iperf_test *test)
      */
     if (rc > 0) {
 	if (test->settings->socket_bufsize == 0) {
+            char str[WARN_STR_LEN];
 	    int bufsize = test->settings->blksize + UDP_BUFFER_EXTRA;
-	    printf("Increasing socket buffer size to %d\n",
-		bufsize);
+	    snprintf(str, sizeof(str), "Increasing socket buffer size to %d",
+	             bufsize);
+	    warning(str);
 	    test->settings->socket_bufsize = bufsize;
 	    rc = iperf_udp_buffercheck(test, s);
 	    if (rc < 0)
 		return rc;
 	}
     }
-	
+
 #if defined(HAVE_SO_MAX_PACING_RATE)
     /* If socket pacing is specified, try it. */
     if (test->settings->fqrate) {
@@ -515,16 +517,18 @@ iperf_udp_connect(struct iperf_test *test)
      */
     if (rc > 0) {
 	if (test->settings->socket_bufsize == 0) {
+            char str[WARN_STR_LEN];
 	    int bufsize = test->settings->blksize + UDP_BUFFER_EXTRA;
-	    printf("Increasing socket buffer size to %d\n",
-		bufsize);
+	    snprintf(str, sizeof(str), "Increasing socket buffer size to %d",
+	             bufsize);
+	    warning(str);
 	    test->settings->socket_bufsize = bufsize;
 	    rc = iperf_udp_buffercheck(test, s);
 	    if (rc < 0)
 		return rc;
 	}
     }
-	
+
 #if defined(HAVE_SO_MAX_PACING_RATE)
     /* If socket pacing is available and not disabled, try it. */
     if (test->settings->fqrate) {
@@ -562,7 +566,7 @@ iperf_udp_connect(struct iperf_test *test)
      */
     buf = 123456789;		/* this can be pretty much anything */
     if (write(s, &buf, sizeof(buf)) < 0) {
-        // XXX: Should this be changed to IESTREAMCONNECT? 
+        // XXX: Should this be changed to IESTREAMCONNECT?
         i_errno = IESTREAMWRITE;
         return -1;
     }
diff --git a/src/iperf_util.c b/src/iperf_util.c
index 8155270..d5795ee 100644
--- a/src/iperf_util.c
+++ b/src/iperf_util.c
@@ -128,7 +128,7 @@ make_cookie(const char *cookie)
 /* is_closed
  *
  * Test if the file descriptor fd is closed.
- * 
+ *
  * Iperf uses this function to test whether a TCP stream socket
  * is closed, because accepting and denying an invalid connection
  * in iperf_tcp_accept is not considered an error.
@@ -176,7 +176,7 @@ double
 timeval_diff(struct timeval * tv0, struct timeval * tv1)
 {
     double time1, time2;
-    
+
     time1 = tv0->tv_sec + (tv0->tv_usec / 1000000.0);
     time2 = tv1->tv_sec + (tv1->tv_usec / 1000000.0);
 
@@ -232,7 +232,7 @@ get_system_info(void)
     memset(buf, 0, 1024);
     uname(&uts);
 
-    snprintf(buf, sizeof(buf), "%s %s %s %s %s", uts.sysname, uts.nodename, 
+    snprintf(buf, sizeof(buf), "%s %s %s %s %s", uts.sysname, uts.nodename,
 	     uts.release, uts.version, uts.machine);
 
     return buf;
@@ -249,44 +249,44 @@ get_optional_features(void)
 
 #if defined(HAVE_CPU_AFFINITY)
     if (numfeatures > 0) {
-	strncat(features, ", ", 
+	strncat(features, ", ",
 		sizeof(features) - strlen(features) - 1);
     }
-    strncat(features, "CPU affinity setting", 
+    strncat(features, "CPU affinity setting",
 	sizeof(features) - strlen(features) - 1);
     numfeatures++;
 #endif /* HAVE_CPU_AFFINITY */
-    
+
 #if defined(HAVE_FLOWLABEL)
     if (numfeatures > 0) {
-	strncat(features, ", ", 
+	strncat(features, ", ",
 		sizeof(features) - strlen(features) - 1);
     }
-    strncat(features, "IPv6 flow label", 
+    strncat(features, "IPv6 flow label",
 	sizeof(features) - strlen(features) - 1);
     numfeatures++;
 #endif /* HAVE_FLOWLABEL */
-    
+
 #if defined(HAVE_SCTP_H)
     if (numfeatures > 0) {
-	strncat(features, ", ", 
+	strncat(features, ", ",
 		sizeof(features) - strlen(features) - 1);
     }
-    strncat(features, "SCTP", 
+    strncat(features, "SCTP",
 	sizeof(features) - strlen(features) - 1);
     numfeatures++;
 #endif /* HAVE_SCTP_H */
-    
+
 #if defined(HAVE_TCP_CONGESTION)
     if (numfeatures > 0) {
-	strncat(features, ", ", 
+	strncat(features, ", ",
 		sizeof(features) - strlen(features) - 1);
     }
-    strncat(features, "TCP congestion algorithm setting", 
+    strncat(features, "TCP congestion algorithm setting",
 	sizeof(features) - strlen(features) - 1);
     numfeatures++;
 #endif /* HAVE_TCP_CONGESTION */
-    
+
 #if defined(HAVE_SENDFILE)
     if (numfeatures > 0) {
 	strncat(features, ", ",
@@ -338,7 +338,7 @@ get_optional_features(void)
 #endif /* HAVE_DONT_FRAGMENT */
 
     if (numfeatures == 0) {
-	strncat(features, "None", 
+	strncat(features, "None",
 		sizeof(features) - strlen(features) - 1);
     }
 
@@ -476,8 +476,8 @@ int daemon(int nochdir, int noclose)
 
     /*
      * Fork again to avoid becoming a session leader.
-     * This might only matter on old SVr4-derived OSs. 
-     * Note in particular that glibc and FreeBSD libc 
+     * This might only matter on old SVr4-derived OSs.
+     * Note in particular that glibc and FreeBSD libc
      * only fork once.
      */
     pid = fork();
diff --git a/src/libiperf.3 b/src/libiperf.3
index 3155062..4b278e3 100644
--- a/src/libiperf.3
+++ b/src/libiperf.3
@@ -1,4 +1,4 @@
-.TH LIBIPERF 3 "December 2020" ESnet "User Manuals"
+.TH LIBIPERF 3 "January 2022" ESnet "User Manuals"
 .SH NAME
 libiperf \- API for iperf3 network throughput tester
 
diff --git a/src/main.c b/src/main.c
index 1580c35..e367b08 100644
--- a/src/main.c
+++ b/src/main.c
@@ -1,5 +1,5 @@
 /*
- * iperf, Copyright (c) 2014-2021, The Regents of the University of
+ * iperf, Copyright (c) 2014-2022, The Regents of the University of
  * California, through Lawrence Berkeley National Laboratory (subject
  * to receipt of any required approvals from the U.S. Dept. of
  * Energy).  All rights reserved.
@@ -62,7 +62,7 @@ main(int argc, char **argv)
     // XXX: Setting the process affinity requires root on most systems.
     //      Is this a feature we really need?
 #ifdef TEST_PROC_AFFINITY
-    /* didnt seem to work.... */
+    /* didn't seem to work.... */
     /*
      * increasing the priority of the process to minimise packet generation
      * delay
@@ -74,7 +74,7 @@ main(int argc, char **argv)
         fprintf(stderr, "setting priority to valid level\n");
         rc = setpriority(PRIO_PROCESS, 0, 0);
     }
-    
+
     /* setting the affinity of the process  */
     cpu_set_t cpu_set;
     int affinity = -1;
diff --git a/src/net.c b/src/net.c
index 2c3aaf3..05f17b3 100644
--- a/src/net.c
+++ b/src/net.c
@@ -119,12 +119,13 @@ timeout_connect(int s, const struct sockaddr *name, socklen_t namelen,
  * Copyright: http://swtch.com/libtask/COPYRIGHT
 */
 
-/* make connection to server */
+/* create a socket */
 int
-netdial(int domain, int proto, const char *local, const char *bind_dev, int local_port, const char *server, int port, int timeout)
+create_socket(int domain, int proto, const char *local, const char *bind_dev, int local_port, const char *server, int port, struct addrinfo **server_res_out)
 {
     struct addrinfo hints, *local_res = NULL, *server_res = NULL;
     int s, saved_errno;
+    char portstr[6];
 
     if (local) {
         memset(&hints, 0, sizeof(hints));
@@ -137,8 +138,12 @@ netdial(int domain, int proto, const char *local, const char *bind_dev, int loca
     memset(&hints, 0, sizeof(hints));
     hints.ai_family = domain;
     hints.ai_socktype = proto;
-    if ((gerror = getaddrinfo(server, NULL, &hints, &server_res)) != 0)
+    snprintf(portstr, sizeof(portstr), "%d", port);
+    if ((gerror = getaddrinfo(server, portstr, &hints, &server_res)) != 0) {
+	if (local)
+	    freeaddrinfo(local_res);
         return -1;
+    }
 
     s = socket(server_res->ai_family, proto, 0);
     if (s < 0) {
@@ -204,6 +209,8 @@ netdial(int domain, int proto, const char *local, const char *bind_dev, int loca
 	}
 	/* Unknown protocol */
 	else {
+	    close(s);
+	    freeaddrinfo(server_res);
 	    errno = EAFNOSUPPORT;
             return -1;
 	}
@@ -217,7 +224,22 @@ netdial(int domain, int proto, const char *local, const char *bind_dev, int loca
         }
     }
 
-    ((struct sockaddr_in *) server_res->ai_addr)->sin_port = htons(port);
+    *server_res_out = server_res;
+    return s;
+}
+
+/* make connection to server */
+int
+netdial(int domain, int proto, const char *local, const char *bind_dev, int local_port, const char *server, int port, int timeout)
+{
+    struct addrinfo *server_res = NULL;
+    int s, saved_errno;
+
+    s = create_socket(domain, proto, local, bind_dev, local_port, server, port, &server_res);
+    if (s < 0) {
+      return -1;
+    }
+
     if (timeout_connect(s, (struct sockaddr *) server_res->ai_addr, server_res->ai_addrlen, timeout) < 0 && errno != EINPROGRESS) {
 	saved_errno = errno;
 	close(s);
@@ -241,7 +263,7 @@ netannounce(int domain, int proto, const char *local, const char *bind_dev, int
 
     snprintf(portstr, 6, "%d", port);
     memset(&hints, 0, sizeof(hints));
-    /* 
+    /*
      * If binding to the wildcard address with no explicit address
      * family specified, then force us to get an AF_INET6 socket.  On
      * CentOS 6 and MacOS, getaddrinfo(3) with AF_UNSPEC in ai_family,
@@ -262,7 +284,7 @@ netannounce(int domain, int proto, const char *local, const char *bind_dev, int
     hints.ai_socktype = proto;
     hints.ai_flags = AI_PASSIVE;
     if ((gerror = getaddrinfo(local, portstr, &hints, &res)) != 0)
-        return -1; 
+        return -1;
 
     s = socket(res->ai_family, proto, 0);
     if (s < 0) {
@@ -285,7 +307,7 @@ netannounce(int domain, int proto, const char *local, const char *bind_dev, int
     }
 
     opt = 1;
-    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, 
+    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
 		   (char *) &opt, sizeof(opt)) < 0) {
 	saved_errno = errno;
 	close(s);
@@ -307,7 +329,7 @@ netannounce(int domain, int proto, const char *local, const char *bind_dev, int
 	    opt = 0;
 	else
 	    opt = 1;
-	if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, 
+	if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
 		       (char *) &opt, sizeof(opt)) < 0) {
 	    saved_errno = errno;
 	    close(s);
@@ -327,7 +349,7 @@ netannounce(int domain, int proto, const char *local, const char *bind_dev, int
     }
 
     freeaddrinfo(res);
-    
+
     if (proto == SOCK_STREAM) {
         if (listen(s, INT_MAX) < 0) {
 	    saved_errno = errno;
diff --git a/src/net.h b/src/net.h
index 44c0d7e..f0e1b4f 100644
--- a/src/net.h
+++ b/src/net.h
@@ -28,6 +28,7 @@
 #define __NET_H
 
 int timeout_connect(int s, const struct sockaddr *name, socklen_t namelen, int timeout);
+int create_socket(int domain, int proto, const char *local, const char *bind_dev, int local_port, const char *server, int port, struct addrinfo **server_res_out);
 int netdial(int domain, int proto, const char *local, const char *bind_dev, int local_port, const char *server, int port, int timeout);
 int netannounce(int domain, int proto, const char *local, const char *bind_dev, int port);
 int Nread(int fd, char *buf, size_t count, int prot);
diff --git a/src/portable_endian.h b/src/portable_endian.h
index 85a6147..6b996b3 100644
--- a/src/portable_endian.h
+++ b/src/portable_endian.h
@@ -49,12 +49,12 @@
 #	define htole16(x) OSSwapHostToLittleInt16(x)
 #	define be16toh(x) OSSwapBigToHostInt16(x)
 #	define le16toh(x) OSSwapLittleToHostInt16(x)
- 
+
 #	define htobe32(x) OSSwapHostToBigInt32(x)
 #	define htole32(x) OSSwapHostToLittleInt32(x)
 #	define be32toh(x) OSSwapBigToHostInt32(x)
 #	define le32toh(x) OSSwapLittleToHostInt32(x)
- 
+
 #	define htobe64(x) OSSwapHostToBigInt64(x)
 #	define htole64(x) OSSwapHostToLittleInt64(x)
 #	define be64toh(x) OSSwapBigToHostInt64(x)
@@ -95,12 +95,12 @@
 #		define htole16(x) (x)
 #		define be16toh(x) ntohs(x)
 #		define le16toh(x) (x)
- 
+
 #		define htobe32(x) htonl(x)
 #		define htole32(x) (x)
 #		define be32toh(x) ntohl(x)
 #		define le32toh(x) (x)
- 
+
 #		define htobe64(x) htonll(x)
 #		define htole64(x) (x)
 #		define be64toh(x) ntohll(x)
@@ -113,12 +113,12 @@
 #		define htole16(x) __builtin_bswap16(x)
 #		define be16toh(x) (x)
 #		define le16toh(x) __builtin_bswap16(x)
- 
+
 #		define htobe32(x) (x)
 #		define htole32(x) __builtin_bswap32(x)
 #		define be32toh(x) (x)
 #		define le32toh(x) __builtin_bswap32(x)
- 
+
 #		define htobe64(x) (x)
 #		define htole64(x) __builtin_bswap64(x)
 #		define be64toh(x) (x)
@@ -173,4 +173,3 @@
 #endif
 
 #endif
-
diff --git a/src/queue.h b/src/queue.h
index 38130e0..f741a4c 100644
--- a/src/queue.h
+++ b/src/queue.h
@@ -36,7 +36,7 @@
 #define	_SYS_QUEUE_H_
 
 /*
- * This file defines five types of data structures: singly-linked lists, 
+ * This file defines five types of data structures: singly-linked lists,
  * lists, simple queues, tail queues, and circular queues.
  *
  *
@@ -95,15 +95,15 @@
 struct name {								\
 	struct type *slh_first;	/* first element */			\
 }
- 
+
 #define	SLIST_HEAD_INITIALIZER(head)					\
 	{ NULL }
- 
+
 #define SLIST_ENTRY(type)						\
 struct {								\
 	struct type *sle_next;	/* next element */			\
 }
- 
+
 /*
  * Singly-linked List access methods.
  */
@@ -318,8 +318,8 @@ struct {								\
 	struct type **tqe_prev;	/* address of previous next element */	\
 }
 
-/* 
- * tail queue access methods 
+/*
+ * tail queue access methods
  */
 #define	TAILQ_FIRST(head)		((head)->tqh_first)
 #define	TAILQ_END(head)			NULL
@@ -426,7 +426,7 @@ struct {								\
 }
 
 /*
- * Circular queue access methods 
+ * Circular queue access methods
  */
 #define	CIRCLEQ_FIRST(head)		((head)->cqh_first)
 #define	CIRCLEQ_LAST(head)		((head)->cqh_last)
diff --git a/src/t_auth.c b/src/t_auth.c
index ff9cffe..22c78ae 100644
--- a/src/t_auth.c
+++ b/src/t_auth.c
@@ -54,7 +54,7 @@ main(int argc, char **argv)
     const char sha256String[] = "This is a SHA256 test.";
     const char sha256Digest[] = "4816482f8b4149f687a1a33d61a0de6b611364ec0fb7adffa59ff2af672f7232"; /* echo -n "This is a SHA256 test." | shasum -a256 */
     char sha256Output[65];
-    
+
     sha256(sha256String, sha256Output);
     assert(strcmp(sha256Output, sha256Digest) == 0);
 
diff --git a/src/t_timer.c b/src/t_timer.c
index 9598594..8eec7d8 100644
--- a/src/t_timer.c
+++ b/src/t_timer.c
@@ -48,7 +48,7 @@ timer_proc( TimerClientData client_data, struct iperf_time* nowP )
 }
 
 
-int 
+int
 main(int argc, char **argv)
 {
     Timer *tp;
diff --git a/src/t_units.c b/src/t_units.c
index 8fd8bd9..73f21a9 100644
--- a/src/t_units.c
+++ b/src/t_units.c
@@ -34,7 +34,7 @@
 #include "iperf.h"
 #include "units.h"
 
-int 
+int
 main(int argc, char **argv)
 {
     iperf_size_t llu;
diff --git a/src/tcp_info.c b/src/tcp_info.c
index 6fa1709..6b75384 100644
--- a/src/tcp_info.c
+++ b/src/tcp_info.c
@@ -27,13 +27,13 @@
 
 /*
  * routines related to collection TCP_INFO using getsockopt()
- * 
+ *
  * Brian Tierney, ESnet  (bltierney@es.net)
- * 
+ *
  * Note that this is only really useful on Linux.
  * XXX: only standard on linux versions 2.4 and later
  #
- * FreeBSD has a limitted implementation that only includes the following:
+ * FreeBSD has a limited implementation that only includes the following:
  *   tcpi_snd_ssthresh, tcpi_snd_cwnd, tcpi_rcv_space, tcpi_rtt
  * Based on information on http://wiki.freebsd.org/8.0TODO, I dont think this will be
  * fixed before v8.1 at the earliest.
@@ -75,7 +75,7 @@ has_tcpinfo_retransmits(void)
 #if defined(linux) && defined(TCP_MD5SIG)
     /* TCP_MD5SIG doesn't actually have anything to do with TCP
     ** retransmits, it just showed up in the same rev of the header
-    ** file.  If it's present then struct tcp_info has the 
+    ** file.  If it's present then struct tcp_info has the
     ** tcpi_total_retrans field that we need; if not, not.
     */
     return 1;
@@ -220,7 +220,7 @@ build_tcpinfo_message(struct iperf_interval_results *r, char *message)
 #if defined(linux) && defined(TCP_INFO)
     sprintf(message, report_tcpInfo, r->tcpInfo.tcpi_snd_cwnd, r->tcpInfo.tcpi_snd_ssthresh,
 	    r->tcpInfo.tcpi_rcv_ssthresh, r->tcpInfo.tcpi_unacked, r->tcpInfo.tcpi_sacked,
-	    r->tcpInfo.tcpi_lost, r->tcpInfo.tcpi_retrans, r->tcpInfo.tcpi_fackets, 
+	    r->tcpInfo.tcpi_lost, r->tcpInfo.tcpi_retrans, r->tcpInfo.tcpi_fackets,
 	    r->tcpInfo.tcpi_rtt, r->tcpInfo.tcpi_reordering);
 #endif
 #if defined(__FreeBSD__) && defined(TCP_INFO)
diff --git a/src/timer.c b/src/timer.c
index 33923c7..644eeab 100644
--- a/src/timer.c
+++ b/src/timer.c
@@ -203,7 +203,7 @@ void
 tmr_reset( struct iperf_time* nowP, Timer* t )
 {
     struct iperf_time now;
-    
+
     getnow( nowP, &now );
     t->time = now;
     iperf_time_add_usecs( &t->time, t->usecs );
diff --git a/test_commands.sh b/test_commands.sh
index 1cf2f43..4026ebd 100755
--- a/test_commands.sh
+++ b/test_commands.sh
@@ -1,14 +1,14 @@
 #!/bin/sh
 #
 # This is a set of commands to run and verify they work before doing a new release.
-# Eventually they should also use the -J flag to generate JSON output, and a program should 
+# Eventually they should also use the -J flag to generate JSON output, and a program should
 # be written to check the output.
 # Be sure to test both client and server on Linux, BSD, and OSX
 #
 
 if [ $# -ne 1 ]
 then
-  echo "Usage: `basename $0` hostname"
+  echo "Usage: `basename "$0"` hostname"
   exit $E_BADARGS
 fi
 
@@ -17,59 +17,57 @@ set -x
 host=$1
 
 # basic testing
-./src/iperf3 -c $host -V -t 5 -T "test1"
-./src/iperf3 -c $host -u -V -t 5
+./src/iperf3 -c "$host" -V -t 5 -T "test1"
+./src/iperf3 -c "$host" -u -V -t 5
 # omit mode
-./src/iperf3 -c $host -i .3 -O 2 -t 5
+./src/iperf3 -c "$host" -i .3 -O 2 -t 5
 # JSON mode
-./src/iperf3 -c $host -i 1 -J -t 5
+./src/iperf3 -c "$host" -i 1 -J -t 5
 # force V4
-./src/iperf3 -c $host -4 -t 5
-./src/iperf3 -c $host -4 -u -t 5
+./src/iperf3 -c "$host" -4 -t 5
+./src/iperf3 -c "$host" -4 -u -t 5
 # force V6
-./src/iperf3 -c $host -6 -t 5
-./src/iperf3 -c $host -6 -u -t 5
+./src/iperf3 -c "$host" -6 -t 5
+./src/iperf3 -c "$host" -6 -u -t 5
 # FQ rate
-./src/iperf3 -c $host -V -t 5 --fq-rate 5m
-./src/iperf3 -c $host -u -V -t 5 --fq-rate 5m
+./src/iperf3 -c "$host" -V -t 5 --fq-rate 5m
+./src/iperf3 -c "$host" -u -V -t 5 --fq-rate 5m
 # SCTP
-./src/iperf3 -c $host --sctp -V -t 5
+./src/iperf3 -c "$host" --sctp -V -t 5
 # parallel streams
-./src/iperf3 -c $host -P 3 -t 5 
-./src/iperf3 -c $host -u -P 3 -t 5
+./src/iperf3 -c "$host" -P 3 -t 5
+./src/iperf3 -c "$host" -u -P 3 -t 5
 # reverse mode
-./src/iperf3 -c $host -P 2 -t 5 -R
-./src/iperf3 -c $host -u -P 2 -t 5 -R
+./src/iperf3 -c "$host" -P 2 -t 5 -R
+./src/iperf3 -c "$host" -u -P 2 -t 5 -R
 # bidirectional mode
-./src/iperf3 -c $host -P 2 -t 5 --bidir
-./src/iperf3 -c $host -u -P 2 -t 5 --bidir
+./src/iperf3 -c "$host" -P 2 -t 5 --bidir
+./src/iperf3 -c "$host" -u -P 2 -t 5 --bidir
 # zero copy
-./src/iperf3 -c $host -Z -t 5 
-./src/iperf3 -c $host -Z -t 5 -R
+./src/iperf3 -c "$host" -Z -t 5
+./src/iperf3 -c "$host" -Z -t 5 -R
 # window size
-./src/iperf3 -c $host -t 5 -w 8M 
+./src/iperf3 -c "$host" -t 5 -w 8M
 # -n flag
-./src/iperf3 -c $host -n 5M  
-./src/iperf3 -c $host -n 5M -u -b1G
+./src/iperf3 -c "$host" -n 5M
+./src/iperf3 -c "$host" -n 5M -u -b1G
 # -n flag with -R
-./src/iperf3 -c $host -n 5M -R
-./src/iperf3 -c $host -n 5M -u -b1G -R
+./src/iperf3 -c "$host" -n 5M -R
+./src/iperf3 -c "$host" -n 5M -u -b1G -R
 # conflicting -n -t flags
-./src/iperf3 -c $host -n 5M -t 5
+./src/iperf3 -c "$host" -n 5M -t 5
 # -k mode
-./src/iperf3 -c $host -k 1K  
-./src/iperf3 -c $host -k 1K -u -b1G
+./src/iperf3 -c "$host" -k 1K
+./src/iperf3 -c "$host" -k 1K -u -b1G
 # -k mode with -R
-./src/iperf3 -c $host -k 1K -R
-./src/iperf3 -c $host -k 1K -u -b1G -R
+./src/iperf3 -c "$host" -k 1K -R
+./src/iperf3 -c "$host" -k 1K -u -b1G -R
 # CPU affinity
-./src/iperf3 -c $host -A 2/2
-./src/iperf3 -c $host -A 2/2 -u -b1G
+./src/iperf3 -c "$host" -A 2/2
+./src/iperf3 -c "$host" -A 2/2 -u -b1G
 # Burst mode
-./src/iperf3 -c $host -u -b1G/100
+./src/iperf3 -c "$host" -u -b1G/100
 # change MSS
-./src/iperf3 -c $host -M 1000 -V
+./src/iperf3 -c "$host" -M 1000 -V
 # test congestion control option (linux only)
-./src/iperf3 -c $host -C reno -V
-
-
+./src/iperf3 -c "$host" -C reno -V
```

