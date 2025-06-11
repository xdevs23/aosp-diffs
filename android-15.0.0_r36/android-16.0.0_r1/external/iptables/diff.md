```diff
diff --git a/METADATA b/METADATA
index 82462d16..d05d2550 100644
--- a/METADATA
+++ b/METADATA
@@ -11,7 +11,7 @@ third_party {
     type: GIT
     value: "git://git.netfilter.org/iptables"
   }
-  version: "v1.8.10"
-  last_upgrade_date { year: 2023 month: 10 day: 10 }
+  version: "v1.8.11"
+  last_upgrade_date { year: 2025 month: 3 day: 4 }
   license_type: RESTRICTED
 }
diff --git a/Makefile.am b/Makefile.am
index 299ab46d..d0ba059c 100644
--- a/Makefile.am
+++ b/Makefile.am
@@ -1,7 +1,7 @@
 # -*- Makefile -*-
 
 ACLOCAL_AMFLAGS  = -I m4
-AUTOMAKE_OPTIONS = foreign subdir-objects dist-xz no-dist-gzip
+AUTOMAKE_OPTIONS = foreign subdir-objects dist-xz no-dist-gzip serial-tests
 
 SUBDIRS          = libiptc libxtables
 if ENABLE_DEVEL
diff --git a/OWNERS b/OWNERS
index c24680e9..9310bff1 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 set noparent
 file:platform/packages/modules/Connectivity:main:/OWNERS_core_networking
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/config.h b/config.h
index c06a23a1..3c7057e6 100644
--- a/config.h
+++ b/config.h
@@ -62,7 +62,7 @@
 #define PACKAGE_NAME "iptables"
 
 /* Define to the full name and version of this package. */
-#define PACKAGE_STRING "iptables 1.8.10"
+#define PACKAGE_STRING "iptables 1.8.11"
 
 /* Define to the one symbol short name of this package. */
 #define PACKAGE_TARNAME "iptables"
@@ -71,7 +71,7 @@
 #define PACKAGE_URL ""
 
 /* Define to the version of this package. */
-#define PACKAGE_VERSION "1.8.10"
+#define PACKAGE_VERSION "1.8.11"
 
 /* The size of `struct ip6_hdr', as computed by sizeof. */
 #define SIZEOF_STRUCT_IP6_HDR 40
@@ -80,7 +80,7 @@
 #define STDC_HEADERS 1
 
 /* Version number of package */
-#define VERSION "1.8.10"
+#define VERSION "1.8.11"
 
 /* Location of the iptables lock file */
 #define XT_LOCK_NAME "/system/etc/xtables.lock"
diff --git a/configure.ac b/configure.ac
index d99fa3b9..0106b316 100644
--- a/configure.ac
+++ b/configure.ac
@@ -1,5 +1,5 @@
 
-AC_INIT([iptables], [1.8.10])
+AC_INIT([iptables], [1.8.11])
 
 # See libtool.info "Libtool's versioning system"
 libxtables_vcurrent=19
@@ -63,6 +63,9 @@ AC_ARG_WITH([pkgconfigdir], AS_HELP_STRING([--with-pkgconfigdir=PATH],
 AC_ARG_ENABLE([nftables],
 	AS_HELP_STRING([--disable-nftables], [Do not build nftables compat]),
 	[enable_nftables="$enableval"], [enable_nftables="yes"])
+AC_ARG_ENABLE([libnfnetlink],
+    AS_HELP_STRING([--disable-libnfnetlink], [Do not use netfilter netlink library]),
+    [enable_libnfnetlink="$enableval"], [enable_libnfnetlink="auto"])
 AC_ARG_ENABLE([connlabel],
 	AS_HELP_STRING([--disable-connlabel],
 	[Do not build libnetfilter_conntrack]),
@@ -113,8 +116,14 @@ AM_CONDITIONAL([ENABLE_SYNCONF], [test "$enable_nfsynproxy" = "yes"])
 AM_CONDITIONAL([ENABLE_NFTABLES], [test "$enable_nftables" = "yes"])
 AM_CONDITIONAL([ENABLE_CONNLABEL], [test "$enable_connlabel" = "yes"])
 
-PKG_CHECK_MODULES([libnfnetlink], [libnfnetlink >= 1.0],
-	[nfnetlink=1], [nfnetlink=0])
+# If specified explicitly on the command line, error out when library was not found
+# Otherwise, disable and continue
+AS_IF([test "x$enable_libnfnetlink" = "xyes"],
+	[PKG_CHECK_MODULES([libnfnetlink], [libnfnetlink >= 1.0],
+			   [nfnetlink=1])],
+      [test "x$enable_libnfnetlink" = "xauto"],
+	[PKG_CHECK_MODULES([libnfnetlink], [libnfnetlink >= 1.0],
+			   [nfnetlink=1], [nfnetlink=0])])
 AM_CONDITIONAL([HAVE_LIBNFNETLINK], [test "$nfnetlink" = 1])
 
 if test "x$enable_bpfc" = "xyes" || test "x$enable_nfsynproxy" = "xyes"; then
@@ -193,8 +202,27 @@ fi;
 pkgdatadir='${datadir}/xtables';
 
 if test "x$enable_profiling" = "xyes"; then
-	regular_CFLAGS+=" -fprofile-arcs -ftest-coverage"
-	regular_LDFLAGS+=" -lgcov --coverage"
+	regular_CFLAGS="$regular_CFLAGS -fprofile-arcs -ftest-coverage"
+	regular_LDFLAGS="$regular_LDFLAGS -lgcov --coverage"
+fi
+
+AC_MSG_CHECKING([whether the build is using musl-libc])
+enable_musl_build=""
+
+AC_COMPILE_IFELSE(
+	[AC_LANG_PROGRAM([[#include <netinet/if_ether.h>]],
+	[[
+	#if ! defined(__UAPI_DEF_ETHHDR) || __UAPI_DEF_ETHHDR != 0
+		#error error trying musl...
+	#endif
+	]]
+	)],
+	[enable_musl_build="yes"],[enable_musl_build="no"]
+)
+AC_MSG_RESULT([${enable_musl_build}])
+
+if test "x$enable_musl_build" = "xyes"; then
+	regular_CFLAGS="$regular_CFLAGS -D__UAPI_DEF_ETHHDR=0"
 fi
 
 define([EXPAND_VARIABLE],
@@ -268,7 +296,8 @@ Build parameters:
   Installation prefix (--prefix):	${prefix}
   Xtables extension directory:		${e_xtlibdir}
   Pkg-config directory:			${e_pkgconfigdir}
-  Xtables lock file:			${xt_lock_name}"
+  Xtables lock file:			${xt_lock_name}
+  Build against musl-libc:		${enable_musl_build}"
 
 if [[ -n "$ksourcedir" ]]; then
 	echo "  Kernel source directory:		${ksourcedir}"
diff --git a/extensions/GNUmakefile.in b/extensions/GNUmakefile.in
index e289adf0..20c2b7bc 100644
--- a/extensions/GNUmakefile.in
+++ b/extensions/GNUmakefile.in
@@ -22,19 +22,34 @@ regular_CPPFLAGS   = @regular_CPPFLAGS@
 kinclude_CPPFLAGS  = @kinclude_CPPFLAGS@
 
 AM_CFLAGS       = ${regular_CFLAGS}
-AM_CPPFLAGS     = ${regular_CPPFLAGS} -I${top_builddir}/include -I${top_builddir} -I${top_srcdir}/include -I${top_srcdir} ${kinclude_CPPFLAGS} ${CPPFLAGS} @libnetfilter_conntrack_CFLAGS@ @libnftnl_CFLAGS@
+AM_CPPFLAGS     = ${regular_CPPFLAGS} \
+                  -I${top_builddir}/include \
+                  -I${top_builddir} \
+                  -I${top_srcdir}/include \
+                  -I${top_srcdir} \
+                  ${kinclude_CPPFLAGS} \
+                  ${CPPFLAGS} \
+                  @libnetfilter_conntrack_CFLAGS@ \
+                  @libnftnl_CFLAGS@
 AM_DEPFLAGS     = -Wp,-MMD,$(@D)/.$(@F).d,-MT,$@
 AM_LDFLAGS      = @noundef_LDFLAGS@ @regular_LDFLAGS@
 
-ifeq (${V},)
-AM_LIBTOOL_SILENT = --silent
-AM_VERBOSE_CC     = @echo "  CC      " $@;
-AM_VERBOSE_CCLD   = @echo "  CCLD    " $@;
-AM_VERBOSE_CXX    = @echo "  CXX     " $@;
-AM_VERBOSE_CXXLD  = @echo "  CXXLD   " $@;
-AM_VERBOSE_AR     = @echo "  AR      " $@;
-AM_VERBOSE_GEN    = @echo "  GEN     " $@;
-endif
+AM_DEFAULT_VERBOSITY = @AM_DEFAULT_VERBOSITY@
+am__v_AR_0           = @echo "  AR      " $@;
+am__v_CC_0           = @echo "  CC      " $@;
+am__v_CCLD_0         = @echo "  CCLD    " $@;
+am__v_GEN_0          = @echo "  GEN     " $@;
+am__v_LN_0           = @echo "  LN      " $@;
+am__v_AR_            = ${am__v_AR_@AM_DEFAULT_V@}
+am__v_CC_            = ${am__v_CC_@AM_DEFAULT_V@}
+am__v_CCLD_          = ${am__v_CCLD_@AM_DEFAULT_V@}
+am__v_GEN_           = ${am__v_GEN_@AM_DEFAULT_V@}
+am__v_LN_            = ${am__v_LN_@AM_DEFAULT_V@}
+AM_V_AR              = ${am__v_AR_@AM_V@}
+AM_V_CC              = ${am__v_CC_@AM_V@}
+AM_V_CCLD            = ${am__v_CCLD_@AM_V@}
+AM_V_GEN             = ${am__v_GEN_@AM_V@}
+AM_V_LN              = ${am__v_LN_@AM_V@}
 
 #
 #	Wildcard module list
@@ -113,7 +128,7 @@ clean:
 distclean: clean
 
 init%.o: init%.c
-	${AM_VERBOSE_CC} ${CC} ${AM_CPPFLAGS} ${AM_DEPFLAGS} ${AM_CFLAGS} -D_INIT=$*_init ${CFLAGS} -o $@ -c $<;
+	${AM_V_CC} ${CC} ${AM_CPPFLAGS} ${AM_DEPFLAGS} ${AM_CFLAGS} -D_INIT=$*_init ${CFLAGS} -o $@ -c $<;
 
 -include .*.d
 
@@ -122,23 +137,23 @@ init%.o: init%.c
 #	Shared libraries
 #
 lib%.so: lib%.oo
-	${AM_VERBOSE_CCLD} ${CCLD} ${AM_LDFLAGS} ${LDFLAGS} -shared -o $@ $< -L../libxtables/.libs -lxtables ${$*_LIBADD};
+	${AM_V_CCLD} ${CCLD} ${AM_LDFLAGS} ${LDFLAGS} -shared -o $@ $< -L../libxtables/.libs -lxtables ${$*_LIBADD};
 
 lib%.oo: ${srcdir}/lib%.c
-	${AM_VERBOSE_CC} ${CC} ${AM_CPPFLAGS} ${AM_DEPFLAGS} ${AM_CFLAGS} -D_INIT=lib$*_init -DPIC -fPIC ${CFLAGS} -o $@ -c $<;
+	${AM_V_CC} ${CC} ${AM_CPPFLAGS} ${AM_DEPFLAGS} ${AM_CFLAGS} -D_INIT=lib$*_init -DPIC -fPIC ${CFLAGS} -o $@ -c $<;
 
 libxt_NOTRACK.so: libxt_CT.so
-	ln -fs $< $@
+	${AM_V_LN} ln -fs $< $@
 libxt_state.so: libxt_conntrack.so
-	ln -fs $< $@
+	${AM_V_LN} ln -fs $< $@
 libxt_REDIRECT.so: libxt_NAT.so
-	ln -fs $< $@
+	${AM_V_LN} ln -fs $< $@
 libxt_MASQUERADE.so: libxt_NAT.so
-	ln -fs $< $@
+	${AM_V_LN} ln -fs $< $@
 libxt_SNAT.so: libxt_NAT.so
-	ln -fs $< $@
+	${AM_V_LN} ln -fs $< $@
 libxt_DNAT.so: libxt_NAT.so
-	ln -fs $< $@
+	${AM_V_LN} ln -fs $< $@
 
 # Need the LIBADDs in iptables/Makefile.am too for libxtables_la_LIBADD
 xt_RATEEST_LIBADD   = -lm
@@ -153,22 +168,22 @@ xt_connlabel_LIBADD = @libnetfilter_conntrack_LIBS@
 #	handling code in the Makefiles.
 #
 lib%.o: ${srcdir}/lib%.c
-	${AM_VERBOSE_CC} ${CC} ${AM_CPPFLAGS} ${AM_DEPFLAGS} ${AM_CFLAGS} -DNO_SHARED_LIBS=1 -D_INIT=lib$*_init ${CFLAGS} -o $@ -c $<;
+	${AM_V_CC} ${CC} ${AM_CPPFLAGS} ${AM_DEPFLAGS} ${AM_CFLAGS} -DNO_SHARED_LIBS=1 -D_INIT=lib$*_init ${CFLAGS} -o $@ -c $<;
 
 libext.a: initext.o ${libext_objs}
-	${AM_VERBOSE_AR} ${AR} crs $@ $^;
+	${AM_V_AR} ${AR} crs $@ $^;
 
 libext_ebt.a: initextb.o ${libext_ebt_objs}
-	${AM_VERBOSE_AR} ${AR} crs $@ $^;
+	${AM_V_AR} ${AR} crs $@ $^;
 
 libext_arpt.a: initexta.o ${libext_arpt_objs}
-	${AM_VERBOSE_AR} ${AR} crs $@ $^;
+	${AM_V_AR} ${AR} crs $@ $^;
 
 libext4.a: initext4.o ${libext4_objs}
-	${AM_VERBOSE_AR} ${AR} crs $@ $^;
+	${AM_V_AR} ${AR} crs $@ $^;
 
 libext6.a: initext6.o ${libext6_objs}
-	${AM_VERBOSE_AR} ${AR} crs $@ $^;
+	${AM_V_AR} ${AR} crs $@ $^;
 
 initext_func  := $(addprefix xt_,${pfx_build_mod})
 initextb_func := $(addprefix ebt_,${pfb_build_mod})
@@ -186,7 +201,7 @@ ${initext_depfiles}: FORCE
 	rm -f $@.tmp;
 
 ${initext_sources}: %.c: .%.dd
-	${AM_VERBOSE_GEN}
+	${AM_V_GEN}
 	@( \
 	initext_func="$(value $(basename $@)_func)"; \
 	funcname="init_extensions$(patsubst initext%.c,%,$@)"; \
@@ -209,23 +224,23 @@ ${initext_sources}: %.c: .%.dd
 ex_matches = $(shell echo ${1} | LC_ALL=POSIX grep -Eo '\b[[:lower:][:digit:]_]+\b')
 ex_targets = $(shell echo ${1} | LC_ALL=POSIX grep -Eo '\b[[:upper:][:digit:]_]+\b')
 man_run    = \
-	${AM_VERBOSE_GEN} \
+	${AM_V_GEN} \
 	for ext in $(sort ${1}); do \
 		f="${srcdir}/libxt_$$ext.man"; \
 		if [ -f "$$f" ]; then \
-			echo -e "\t+ $$f" >&2; \
+			printf "\t+ $$f\n" >&2; \
 			echo ".SS $$ext"; \
 			cat "$$f" || exit $$?; \
 		fi; \
 		f="${srcdir}/libip6t_$$ext.man"; \
 		if [ -f "$$f" ]; then \
-			echo -e "\t+ $$f" >&2; \
+			printf "\t+ $$f\n" >&2; \
 			echo ".SS $$ext (IPv6-specific)"; \
 			cat "$$f" || exit $$?; \
 		fi; \
 		f="${srcdir}/libipt_$$ext.man"; \
 		if [ -f "$$f" ]; then \
-			echo -e "\t+ $$f" >&2; \
+			printf "\t+ $$f\n" >&2; \
 			echo ".SS $$ext (IPv4-specific)"; \
 			cat "$$f" || exit $$?; \
 		fi; \
diff --git a/extensions/generic.txlate b/extensions/generic.txlate
index c24ed156..64bc59a8 100644
--- a/extensions/generic.txlate
+++ b/extensions/generic.txlate
@@ -1,3 +1,9 @@
+arptables-translate -A OUTPUT --proto-type ipv4 -s 1.2.3.4 -j ACCEPT
+nft 'add rule arp filter OUTPUT arp htype 1 arp hlen 6 arp plen 4 arp ptype 0x800 arp saddr ip 1.2.3.4 counter accept'
+
+arptables-translate -I OUTPUT -o oifname
+nft 'insert rule arp filter OUTPUT oifname "oifname" arp htype 1 arp hlen 6 arp plen 4 counter'
+
 iptables-translate -I OUTPUT -p udp -d 8.8.8.8 -j ACCEPT
 nft 'insert rule ip filter OUTPUT ip protocol udp ip daddr 8.8.8.8 counter accept'
 
@@ -58,6 +64,36 @@ nft 'insert rule ip6 filter INPUT counter'
 ip6tables-translate -I INPUT ! -s ::/0
 nft 'insert rule ip6 filter INPUT ip6 saddr != ::/0 counter'
 
+iptables-translate -A FORWARD -p 132
+nft 'add rule ip filter FORWARD ip protocol sctp counter'
+
+ip6tables-translate -A FORWARD -p 132
+nft 'add rule ip6 filter FORWARD meta l4proto sctp counter'
+
+iptables-translate -A FORWARD ! -p 132
+nft 'add rule ip filter FORWARD ip protocol != sctp counter'
+
+ip6tables-translate -A FORWARD ! -p 132
+nft 'add rule ip6 filter FORWARD meta l4proto != sctp counter'
+
+iptables-translate -A FORWARD -p 253
+nft 'add rule ip filter FORWARD ip protocol 253 counter'
+
+ip6tables-translate -A FORWARD -p 253
+nft 'add rule ip6 filter FORWARD meta l4proto 253 counter'
+
+iptables-translate -A FORWARD ! -p 253
+nft 'add rule ip filter FORWARD ip protocol != 253 counter'
+
+ip6tables-translate -A FORWARD ! -p 253
+nft 'add rule ip6 filter FORWARD meta l4proto != 253 counter'
+
+iptables-translate -A FORWARD -m tcp --dport 22 -p tcp
+nft 'add rule ip filter FORWARD tcp dport 22 counter'
+
+ip6tables-translate -A FORWARD -m tcp --dport 22 -p tcp
+nft 'add rule ip6 filter FORWARD tcp dport 22 counter'
+
 ebtables-translate -I INPUT -i iname --logical-in ilogname -s 0:0:0:0:0:0
 nft 'insert rule bridge filter INPUT iifname "iname" meta ibrname "ilogname" ether saddr 00:00:00:00:00:00 counter'
 
diff --git a/extensions/iptables.t b/extensions/iptables.t
index b4b6d677..2817c3fb 100644
--- a/extensions/iptables.t
+++ b/extensions/iptables.t
@@ -4,3 +4,10 @@
 -i eth+ -o alongifacename+;=;OK
 ! -i eth0;=;OK
 ! -o eth+;=;OK
+-i + -j ACCEPT;-j ACCEPT;OK
+! -i +;=;OK
+-c "";;FAIL
+-c ,3;;FAIL
+-c 3,;;FAIL
+-c ,;;FAIL
+-c 2,3 -j ACCEPT;-j ACCEPT;OK
diff --git a/extensions/libarpt_mangle.c b/extensions/libarpt_mangle.c
index 765edf34..283bb132 100644
--- a/extensions/libarpt_mangle.c
+++ b/extensions/libarpt_mangle.c
@@ -25,19 +25,16 @@ static void arpmangle_print_help(void)
 	"--mangle-target target (DROP, CONTINUE or ACCEPT -- default is ACCEPT)\n");
 }
 
-#define MANGLE_IPS    '1'
-#define MANGLE_IPT    '2'
-#define MANGLE_DEVS   '3'
-#define MANGLE_DEVT   '4'
-#define MANGLE_TARGET '5'
-
-static const struct option arpmangle_opts[] = {
-	{ .name = "mangle-ip-s",	.has_arg = true, .val = MANGLE_IPS },
-	{ .name = "mangle-ip-d",	.has_arg = true, .val = MANGLE_IPT },
-	{ .name = "mangle-mac-s",	.has_arg = true, .val = MANGLE_DEVS },
-	{ .name = "mangle-mac-d",	.has_arg = true, .val = MANGLE_DEVT },
-	{ .name = "mangle-target",	.has_arg = true, .val = MANGLE_TARGET },
-	XT_GETOPT_TABLEEND,
+/* internal use only, explicitly not covered by ARPT_MANGLE_MASK */
+#define ARPT_MANGLE_TARGET	0x10
+
+static const struct xt_option_entry arpmangle_opts[] = {
+{ .name = "mangle-ip-s", .id = ARPT_MANGLE_SIP, .type = XTTYPE_HOSTMASK },
+{ .name = "mangle-ip-d", .id = ARPT_MANGLE_TIP, .type = XTTYPE_HOSTMASK },
+{ .name = "mangle-mac-s", .id = ARPT_MANGLE_SDEV, .type = XTTYPE_ETHERMAC },
+{ .name = "mangle-mac-d", .id = ARPT_MANGLE_TDEV, .type = XTTYPE_ETHERMAC },
+{ .name = "mangle-target", .id = ARPT_MANGLE_TARGET, .type = XTTYPE_STRING },
+XTOPT_TABLEEND,
 };
 
 static void arpmangle_init(struct xt_entry_target *target)
@@ -47,86 +44,50 @@ static void arpmangle_init(struct xt_entry_target *target)
 	mangle->target = NF_ACCEPT;
 }
 
-static int
-arpmangle_parse(int c, char **argv, int invert, unsigned int *flags,
-		const void *entry, struct xt_entry_target **target)
+static void assert_hopts(const struct arpt_entry *e, const char *optname)
 {
-	struct arpt_mangle *mangle = (struct arpt_mangle *)(*target)->data;
-	struct in_addr *ipaddr, mask;
-	struct ether_addr *macaddr;
-	const struct arpt_entry *e = (const struct arpt_entry *)entry;
-	unsigned int nr;
-	int ret = 1;
-
-	memset(&mask, 0, sizeof(mask));
-
-	switch (c) {
-	case MANGLE_IPS:
-		xtables_ipparse_any(optarg, &ipaddr, &mask, &nr);
-		mangle->u_s.src_ip.s_addr = ipaddr->s_addr;
-		free(ipaddr);
-		mangle->flags |= ARPT_MANGLE_SIP;
+	if (e->arp.arhln_mask == 0)
+		xtables_error(PARAMETER_PROBLEM, "no --h-length defined");
+	if (e->arp.invflags & IPT_INV_ARPHLN)
+		xtables_error(PARAMETER_PROBLEM,
+			      "! hln not allowed for --%s", optname);
+	if (e->arp.arhln != 6)
+		xtables_error(PARAMETER_PROBLEM, "only --h-length 6 supported");
+}
+
+static void arpmangle_parse(struct xt_option_call *cb)
+{
+	const struct arpt_entry *e = cb->xt_entry;
+	struct arpt_mangle *mangle = cb->data;
+
+	xtables_option_parse(cb);
+	mangle->flags |= (cb->entry->id & ARPT_MANGLE_MASK);
+	switch (cb->entry->id) {
+	case ARPT_MANGLE_SIP:
+		mangle->u_s.src_ip = cb->val.haddr.in;
 		break;
-	case MANGLE_IPT:
-		xtables_ipparse_any(optarg, &ipaddr, &mask, &nr);
-		mangle->u_t.tgt_ip.s_addr = ipaddr->s_addr;
-		free(ipaddr);
-		mangle->flags |= ARPT_MANGLE_TIP;
+	case ARPT_MANGLE_TIP:
+		mangle->u_t.tgt_ip = cb->val.haddr.in;
 		break;
-	case MANGLE_DEVS:
-		if (e->arp.arhln_mask == 0)
-			xtables_error(PARAMETER_PROBLEM,
-				      "no --h-length defined");
-		if (e->arp.invflags & ARPT_INV_ARPHLN)
-			xtables_error(PARAMETER_PROBLEM,
-				      "! --h-length not allowed for "
-				      "--mangle-mac-s");
-		if (e->arp.arhln != 6)
-			xtables_error(PARAMETER_PROBLEM,
-				      "only --h-length 6 supported");
-		macaddr = ether_aton(optarg);
-		if (macaddr == NULL)
-			xtables_error(PARAMETER_PROBLEM,
-				      "invalid source MAC");
-		memcpy(mangle->src_devaddr, macaddr, e->arp.arhln);
-		mangle->flags |= ARPT_MANGLE_SDEV;
+	case ARPT_MANGLE_SDEV:
+		assert_hopts(e, cb->entry->name);
+		memcpy(mangle->src_devaddr, cb->val.ethermac, ETH_ALEN);
+	case ARPT_MANGLE_TDEV:
+		assert_hopts(e, cb->entry->name);
+		memcpy(mangle->tgt_devaddr, cb->val.ethermac, ETH_ALEN);
 		break;
-	case MANGLE_DEVT:
-		if (e->arp.arhln_mask == 0)
-			xtables_error(PARAMETER_PROBLEM,
-				      "no --h-length defined");
-		if (e->arp.invflags & ARPT_INV_ARPHLN)
-			xtables_error(PARAMETER_PROBLEM,
-				      "! hln not allowed for --mangle-mac-d");
-		if (e->arp.arhln != 6)
-			xtables_error(PARAMETER_PROBLEM,
-				      "only --h-length 6 supported");
-		macaddr = ether_aton(optarg);
-		if (macaddr == NULL)
-			xtables_error(PARAMETER_PROBLEM, "invalid target MAC");
-		memcpy(mangle->tgt_devaddr, macaddr, e->arp.arhln);
-		mangle->flags |= ARPT_MANGLE_TDEV;
-		break;
-	case MANGLE_TARGET:
-		if (!strcmp(optarg, "DROP"))
+	case ARPT_MANGLE_TARGET:
+		if (!strcmp(cb->arg, "DROP"))
 			mangle->target = NF_DROP;
-		else if (!strcmp(optarg, "ACCEPT"))
+		else if (!strcmp(cb->arg, "ACCEPT"))
 			mangle->target = NF_ACCEPT;
-		else if (!strcmp(optarg, "CONTINUE"))
+		else if (!strcmp(cb->arg, "CONTINUE"))
 			mangle->target = XT_CONTINUE;
 		else
 			xtables_error(PARAMETER_PROBLEM,
 				      "bad target for --mangle-target");
 		break;
-	default:
-		ret = 0;
 	}
-
-	return ret;
-}
-
-static void arpmangle_final_check(unsigned int flags)
-{
 }
 
 static const char *ipaddr_to(const struct in_addr *addrp, int numeric)
@@ -170,6 +131,52 @@ static void arpmangle_save(const void *ip, const struct xt_entry_target *target)
 	arpmangle_print(ip, target, 0);
 }
 
+static void print_devaddr_xlate(const char *macaddress, struct xt_xlate *xl)
+{
+	unsigned int i;
+
+	xt_xlate_add(xl, "%02x", macaddress[0]);
+	for (i = 1; i < ETH_ALEN; ++i)
+		xt_xlate_add(xl, ":%02x", macaddress[i]);
+}
+
+static int arpmangle_xlate(struct xt_xlate *xl,
+			 const struct xt_xlate_tg_params *params)
+{
+	const struct arpt_mangle *m = (const void *)params->target->data;
+
+	if (m->flags & ARPT_MANGLE_SIP)
+		xt_xlate_add(xl, "arp saddr ip set %s ",
+			     xtables_ipaddr_to_numeric(&m->u_s.src_ip));
+
+	if (m->flags & ARPT_MANGLE_SDEV) {
+		xt_xlate_add(xl, "arp %caddr ether set ", 's');
+		print_devaddr_xlate(m->src_devaddr, xl);
+	}
+
+	if (m->flags & ARPT_MANGLE_TIP)
+		xt_xlate_add(xl, "arp daddr ip set %s ",
+			     xtables_ipaddr_to_numeric(&m->u_t.tgt_ip));
+
+	if (m->flags & ARPT_MANGLE_TDEV) {
+		xt_xlate_add(xl, "arp %caddr ether set ", 'd');
+		print_devaddr_xlate(m->tgt_devaddr, xl);
+	}
+
+	switch (m->target) {
+	case NF_ACCEPT:
+		xt_xlate_add(xl, "accept");
+		break;
+	case NF_DROP:
+		xt_xlate_add(xl, "drop");
+		break;
+	default:
+		break;
+	}
+
+	return 1;
+}
+
 static struct xtables_target arpmangle_target = {
 	.name		= "mangle",
 	.revision	= 0,
@@ -179,11 +186,11 @@ static struct xtables_target arpmangle_target = {
 	.userspacesize	= XT_ALIGN(sizeof(struct arpt_mangle)),
 	.help		= arpmangle_print_help,
 	.init		= arpmangle_init,
-	.parse		= arpmangle_parse,
-	.final_check	= arpmangle_final_check,
+	.x6_parse	= arpmangle_parse,
 	.print		= arpmangle_print,
 	.save		= arpmangle_save,
-	.extra_opts	= arpmangle_opts,
+	.x6_options	= arpmangle_opts,
+	.xlate		= arpmangle_xlate,
 };
 
 void _init(void)
diff --git a/extensions/libarpt_mangle.t b/extensions/libarpt_mangle.t
index da966948..7a639ee1 100644
--- a/extensions/libarpt_mangle.t
+++ b/extensions/libarpt_mangle.t
@@ -3,3 +3,7 @@
 -j mangle -d 1.2.3.4 --mangle-ip-d 1.2.3.5;=;OK
 -j mangle -d 1.2.3.4 --mangle-mac-d 00:01:02:03:04:05;=;OK
 -d 1.2.3.4 --h-length 5 -j mangle --mangle-mac-s 00:01:02:03:04:05;=;FAIL
+-j mangle --mangle-ip-s 1.2.3.4 --mangle-target DROP;=;OK
+-j mangle --mangle-ip-s 1.2.3.4 --mangle-target ACCEPT;-j mangle --mangle-ip-s 1.2.3.4;OK
+-j mangle --mangle-ip-s 1.2.3.4 --mangle-target CONTINUE;=;OK
+-j mangle --mangle-ip-s 1.2.3.4 --mangle-target FOO;=;FAIL
diff --git a/extensions/libarpt_mangle.txlate b/extensions/libarpt_mangle.txlate
new file mode 100644
index 00000000..e884d328
--- /dev/null
+++ b/extensions/libarpt_mangle.txlate
@@ -0,0 +1,6 @@
+arptables-translate -A OUTPUT -d 10.21.22.129 -j mangle --mangle-ip-s 10.21.22.161
+nft 'add rule arp filter OUTPUT arp htype 1 arp hlen 6 arp plen 4 arp daddr ip 10.21.22.129 counter arp saddr ip set 10.21.22.161 accept'
+arptables-translate -A OUTPUT -d 10.2.22.129/24 -j mangle --mangle-ip-d 10.2.22.1 --mangle-target CONTINUE
+nft 'add rule arp filter OUTPUT arp htype 1 arp hlen 6 arp plen 4 arp daddr ip 10.2.22.0/24 counter arp daddr ip set 10.2.22.1'
+arptables-translate -A OUTPUT -d 10.2.22.129/24 -j mangle --mangle-ip-d 10.2.22.1 --mangle-mac-d a:b:c:d:e:f
+nft 'add rule arp filter OUTPUT arp htype 1 arp hlen 6 arp plen 4 arp daddr ip 10.2.22.0/24 counter arp daddr ip set 10.2.22.1 arp daddr ether set 0a:0b:0c:0d:0e:0f accept'
diff --git a/extensions/libarpt_standard.t b/extensions/libarpt_standard.t
index 007fa2b8..d6eaced3 100644
--- a/extensions/libarpt_standard.t
+++ b/extensions/libarpt_standard.t
@@ -9,8 +9,17 @@
 -j ACCEPT ! -i lo;=;OK
 -i ppp+;=;OK
 ! -i ppp+;=;OK
+-i + -j ACCEPT;-j ACCEPT;OK
+! -i +;=;OK
 -i lo --destination-mac 11:22:33:44:55:66;-i lo --dst-mac 11:22:33:44:55:66;OK
 --source-mac Unicast;--src-mac 00:00:00:00:00:00/01:00:00:00:00:00;OK
 ! --src-mac Multicast;! --src-mac 01:00:00:00:00:00/01:00:00:00:00:00;OK
 --src-mac=01:02:03:04:05:06 --dst-mac=07:08:09:0A:0B:0C --h-length=6 --opcode=Request --h-type=Ethernet --proto-type=ipv4;--src-mac 01:02:03:04:05:06 --dst-mac 07:08:09:0a:0b:0c --opcode 1 --proto-type 0x800;OK
---src-mac ! 01:02:03:04:05:06 --dst-mac ! 07:08:09:0A:0B:0C --h-length ! 6 --opcode ! Request --h-type ! Ethernet --proto-type ! ipv4;! --src-mac 01:02:03:04:05:06 ! --dst-mac 07:08:09:0a:0b:0c ! --h-length 6 ! --opcode 1 ! --h-type 1 ! --proto-type 0x800;OK
+--src-mac ! 01:02:03:04:05:06 --dst-mac ! 07:08:09:0A:0B:0C --h-length ! 6 --opcode ! Request --h-type ! Ethernet --proto-type ! ipv4;! --src-mac 01:02:03:04:05:06 ! --dst-mac 07:08:09:0a:0b:0c ! --h-length 6 ! --opcode 1 ! --h-type 0x1 ! --proto-type 0x800;OK
+--h-type 10;--h-type 0x10;OK
+--h-type 0x10;=;OK
+--proto-type 10;--proto-type 0xa;OK
+--proto-type 10/10;--proto-type 0xa/0xa;OK
+--proto-type 0x10;=;OK
+--proto-type 0x10/0x10;=;OK
+--h-length 6/15 --opcode 1/235 --h-type 0x8/0xcf --proto-type 0x800/0xde00;=;OK
diff --git a/extensions/libebt_802_3.c b/extensions/libebt_802_3.c
index f05d02ea..489185e9 100644
--- a/extensions/libebt_802_3.c
+++ b/extensions/libebt_802_3.c
@@ -13,83 +13,40 @@
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
-#include <getopt.h>
 #include <xtables.h>
 #include <linux/netfilter_bridge/ebt_802_3.h>
 
-#define _802_3_SAP	'1'
-#define _802_3_TYPE	'2'
-
-static const struct option br802_3_opts[] = {
-	{ .name = "802_3-sap",	.has_arg = true, .val = _802_3_SAP },
-	{ .name = "802_3-type",	.has_arg = true, .val = _802_3_TYPE },
-	XT_GETOPT_TABLEEND,
+static const struct xt_option_entry br802_3_opts[] =
+{
+	{ .name = "802_3-sap", .id = EBT_802_3_SAP,
+	  .type = XTTYPE_UINT8, .base = 16,
+	  .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_802_3_info, sap) },
+	{ .name = "802_3-type", .id = EBT_802_3_TYPE,
+	  .type = XTTYPE_UINT16, .base = 16,
+	  .flags = XTOPT_INVERT | XTOPT_PUT | XTOPT_NBO,
+	  XTOPT_POINTER(struct ebt_802_3_info, type) },
+	XTOPT_TABLEEND,
 };
 
 static void br802_3_print_help(void)
 {
 	printf(
 "802_3 options:\n"
-"--802_3-sap [!] protocol       : 802.3 DSAP/SSAP- 1 byte value (hex)\n"
+"[!] --802_3-sap protocol       : 802.3 DSAP/SSAP- 1 byte value (hex)\n"
 "  DSAP and SSAP are always the same.  One SAP applies to both fields\n"
-"--802_3-type [!] protocol      : 802.3 SNAP Type- 2 byte value (hex)\n"
+"[!] --802_3-type protocol      : 802.3 SNAP Type- 2 byte value (hex)\n"
 "  Type implies SAP value 0xaa\n");
 }
 
-static void br802_3_init(struct xt_entry_match *match)
-{
-	struct ebt_802_3_info *info = (struct ebt_802_3_info *)match->data;
-
-	info->invflags = 0;
-	info->bitmask = 0;
-}
-
-static int
-br802_3_parse(int c, char **argv, int invert, unsigned int *flags,
-	      const void *entry, struct xt_entry_match **match)
+static void br802_3_parse(struct xt_option_call *cb)
 {
-	struct ebt_802_3_info *info = (struct ebt_802_3_info *) (*match)->data;
-	unsigned int i;
-	char *end;
-
-	switch (c) {
-	case _802_3_SAP:
-		if (invert)
-			info->invflags |= EBT_802_3_SAP;
-		i = strtoul(optarg, &end, 16);
-		if (i > 255 || *end != '\0')
-			xtables_error(PARAMETER_PROBLEM,
-				      "Problem with specified "
-					"sap hex value, %x",i);
-		info->sap = i; /* one byte, so no byte order worries */
-		info->bitmask |= EBT_802_3_SAP;
-		break;
-	case _802_3_TYPE:
-		if (invert)
-			info->invflags |= EBT_802_3_TYPE;
-		i = strtoul(optarg, &end, 16);
-		if (i > 65535 || *end != '\0') {
-			xtables_error(PARAMETER_PROBLEM,
-				      "Problem with the specified "
-					"type hex value, %x",i);
-		}
-		info->type = htons(i);
-		info->bitmask |= EBT_802_3_TYPE;
-		break;
-	default:
-		return 0;
-	}
+	struct ebt_802_3_info *info = cb->data;
 
-	*flags |= info->bitmask;
-	return 1;
-}
-
-static void
-br802_3_final_check(unsigned int flags)
-{
-	if (!flags)
-		xtables_error(PARAMETER_PROBLEM,
-			      "You must specify proper arguments");
+	xtables_option_parse(cb);
+	info->bitmask |= cb->entry->id;
+	if (cb->invert)
+		info->invflags |= cb->entry->id;
 }
 
 static void br802_3_print(const void *ip, const struct xt_entry_match *match,
@@ -98,16 +55,14 @@ static void br802_3_print(const void *ip, const struct xt_entry_match *match,
 	struct ebt_802_3_info *info = (struct ebt_802_3_info *)match->data;
 
 	if (info->bitmask & EBT_802_3_SAP) {
-		printf("--802_3-sap ");
 		if (info->invflags & EBT_802_3_SAP)
 			printf("! ");
-		printf("0x%.2x ", info->sap);
+		printf("--802_3-sap 0x%.2x ", info->sap);
 	}
 	if (info->bitmask & EBT_802_3_TYPE) {
-		printf("--802_3-type ");
 		if (info->invflags & EBT_802_3_TYPE)
 			printf("! ");
-		printf("0x%.4x ", ntohs(info->type));
+		printf("--802_3-type 0x%.4x ", ntohs(info->type));
 	}
 }
 
@@ -119,12 +74,10 @@ static struct xtables_match br802_3_match =
 	.family		= NFPROTO_BRIDGE,
 	.size		= XT_ALIGN(sizeof(struct ebt_802_3_info)),
 	.userspacesize	= XT_ALIGN(sizeof(struct ebt_802_3_info)),
-	.init		= br802_3_init,
 	.help		= br802_3_print_help,
-	.parse		= br802_3_parse,
-	.final_check	= br802_3_final_check,
+	.x6_parse	= br802_3_parse,
 	.print		= br802_3_print,
-	.extra_opts	= br802_3_opts,
+	.x6_options	= br802_3_opts,
 };
 
 void _init(void)
diff --git a/extensions/libebt_802_3.t b/extensions/libebt_802_3.t
index a138f35d..d1e19795 100644
--- a/extensions/libebt_802_3.t
+++ b/extensions/libebt_802_3.t
@@ -1,5 +1,7 @@
 :INPUT,FORWARD,OUTPUT
---802_3-sap ! 0x0a -j CONTINUE;=;FAIL
+! --802_3-sap 0x0a -j CONTINUE;=;FAIL
 --802_3-type 0x000a -j RETURN;=;FAIL
--p Length --802_3-sap ! 0x0a -j CONTINUE;=;OK
+-p Length --802_3-sap 0x0a -j CONTINUE;=;OK
+-p Length ! --802_3-sap 0x0a -j CONTINUE;=;OK
 -p Length --802_3-type 0x000a -j RETURN;=;OK
+-p Length ! --802_3-type 0x000a -j RETURN;=;OK
diff --git a/extensions/libebt_among.c b/extensions/libebt_among.c
index a80fb804..85f9bee4 100644
--- a/extensions/libebt_among.c
+++ b/extensions/libebt_among.c
@@ -43,10 +43,10 @@ static void bramong_print_help(void)
 {
 	printf(
 "`among' options:\n"
-"--among-dst      [!] list      : matches if ether dst is in list\n"
-"--among-src      [!] list      : matches if ether src is in list\n"
-"--among-dst-file [!] file      : obtain dst list from file\n"
-"--among-src-file [!] file      : obtain src list from file\n"
+"[!] --among-dst      list      : matches if ether dst is in list\n"
+"[!] --among-src      list      : matches if ether src is in list\n"
+"[!] --among-dst-file file      : obtain dst list from file\n"
+"[!] --among-src-file file      : obtain src list from file\n"
 "list has form:\n"
 " xx:xx:xx:xx:xx:xx[=ip.ip.ip.ip],yy:yy:yy:yy:yy:yy[=ip.ip.ip.ip]"
 ",...,zz:zz:zz:zz:zz:zz[=ip.ip.ip.ip][,]\n"
@@ -188,10 +188,10 @@ static int bramong_parse(int c, char **argv, int invert,
 }
 
 static void __bramong_print(struct nft_among_pair *pairs,
-			    int cnt, bool inv, bool have_ip)
+			    int cnt, bool have_ip)
 {
-	const char *isep = inv ? "! " : "";
 	char abuf[INET_ADDRSTRLEN];
+	const char *isep = "";
 	int i;
 
 	for (i = 0; i < cnt; i++) {
@@ -212,14 +212,13 @@ static void bramong_print(const void *ip, const struct xt_entry_match *match,
 	struct nft_among_data *data = (struct nft_among_data *)match->data;
 
 	if (data->src.cnt) {
-		printf("--among-src ");
-		__bramong_print(data->pairs,
-				data->src.cnt, data->src.inv, data->src.ip);
+		printf("%s--among-src ", data->src.inv ? "! " : "");
+		__bramong_print(data->pairs, data->src.cnt, data->src.ip);
 	}
 	if (data->dst.cnt) {
-		printf("--among-dst ");
+		printf("%s--among-dst ", data->dst.inv ? "! " : "");
 		__bramong_print(data->pairs + data->src.cnt,
-				data->dst.cnt, data->dst.inv, data->dst.ip);
+				data->dst.cnt, data->dst.ip);
 	}
 }
 
diff --git a/extensions/libebt_among.t b/extensions/libebt_among.t
index a02206f3..aef07acf 100644
--- a/extensions/libebt_among.t
+++ b/extensions/libebt_among.t
@@ -1,15 +1,15 @@
 :INPUT,FORWARD,OUTPUT
 --among-dst de:ad:0:be:ee:ff,c0:ff:ee:0:ba:be;--among-dst c0:ff:ee:0:ba:be,de:ad:0:be:ee:ff;OK
---among-dst ! c0:ff:ee:0:ba:be,de:ad:0:be:ee:ff;=;OK
+! --among-dst c0:ff:ee:0:ba:be,de:ad:0:be:ee:ff;=;OK
 --among-src be:ef:0:c0:ff:ee,c0:ff:ee:0:ba:be,de:ad:0:be:ee:ff;=;OK
 --among-src de:ad:0:be:ee:ff=10.0.0.1,c0:ff:ee:0:ba:be=192.168.1.1;--among-src c0:ff:ee:0:ba:be=192.168.1.1,de:ad:0:be:ee:ff=10.0.0.1;OK
---among-src ! c0:ff:ee:0:ba:be=192.168.1.1,de:ad:0:be:ee:ff=10.0.0.1;=;OK
+! --among-src c0:ff:ee:0:ba:be=192.168.1.1,de:ad:0:be:ee:ff=10.0.0.1;=;OK
 --among-src de:ad:0:be:ee:ff --among-dst c0:ff:ee:0:ba:be;=;OK
 --among-src de:ad:0:be:ee:ff=10.0.0.1 --among-dst c0:ff:ee:0:ba:be=192.168.1.1;=;OK
---among-src ! de:ad:0:be:ee:ff --among-dst c0:ff:ee:0:ba:be;=;OK
---among-src de:ad:0:be:ee:ff=10.0.0.1 --among-dst ! c0:ff:ee:0:ba:be=192.168.1.1;=;OK
---among-src ! de:ad:0:be:ee:ff --among-dst c0:ff:ee:0:ba:be=192.168.1.1;=;OK
---among-src de:ad:0:be:ee:ff=10.0.0.1 --among-dst ! c0:ff:ee:0:ba:be=192.168.1.1;=;OK
+! --among-src de:ad:0:be:ee:ff --among-dst c0:ff:ee:0:ba:be;=;OK
+--among-src de:ad:0:be:ee:ff=10.0.0.1 ! --among-dst c0:ff:ee:0:ba:be=192.168.1.1;=;OK
+! --among-src de:ad:0:be:ee:ff --among-dst c0:ff:ee:0:ba:be=192.168.1.1;=;OK
+--among-src de:ad:0:be:ee:ff=10.0.0.1 ! --among-dst c0:ff:ee:0:ba:be=192.168.1.1;=;OK
 --among-src;=;FAIL
 --among-src 00:11=10.0.0.1;=;FAIL
 --among-src de:ad:0:be:ee:ff=10.256.0.1;=;FAIL
diff --git a/extensions/libebt_arp.c b/extensions/libebt_arp.c
index 63a953d4..50ce32be 100644
--- a/extensions/libebt_arp.c
+++ b/extensions/libebt_arp.c
@@ -10,7 +10,6 @@
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
-#include <getopt.h>
 #include <xtables.h>
 #include <netinet/ether.h>
 
@@ -20,26 +19,31 @@
 #include "iptables/nft.h"
 #include "iptables/nft-bridge.h"
 
-#define ARP_OPCODE '1'
-#define ARP_HTYPE  '2'
-#define ARP_PTYPE  '3'
-#define ARP_IP_S   '4'
-#define ARP_IP_D   '5'
-#define ARP_MAC_S  '6'
-#define ARP_MAC_D  '7'
-#define ARP_GRAT   '8'
+/* values must correspond with EBT_ARP_* bit positions */
+enum {
+	O_OPCODE = 0,
+	O_HTYPE,
+	O_PTYPE,
+	O_SRC_IP,
+	O_DST_IP,
+	O_SRC_MAC,
+	O_DST_MAC,
+	O_GRAT,
+};
 
-static const struct option brarp_opts[] = {
-	{ "arp-opcode"    , required_argument, 0, ARP_OPCODE },
-	{ "arp-op"        , required_argument, 0, ARP_OPCODE },
-	{ "arp-htype"     , required_argument, 0, ARP_HTYPE  },
-	{ "arp-ptype"     , required_argument, 0, ARP_PTYPE  },
-	{ "arp-ip-src"    , required_argument, 0, ARP_IP_S   },
-	{ "arp-ip-dst"    , required_argument, 0, ARP_IP_D   },
-	{ "arp-mac-src"   , required_argument, 0, ARP_MAC_S  },
-	{ "arp-mac-dst"   , required_argument, 0, ARP_MAC_D  },
-	{ "arp-gratuitous",       no_argument, 0, ARP_GRAT   },
-	XT_GETOPT_TABLEEND,
+static const struct xt_option_entry brarp_opts[] = {
+#define ENTRY(n, i, t) { .name = n, .id = i, .type = t, .flags = XTOPT_INVERT }
+	ENTRY("arp-opcode",     O_OPCODE,  XTTYPE_STRING),
+	ENTRY("arp-op",         O_OPCODE,  XTTYPE_STRING),
+	ENTRY("arp-htype",      O_HTYPE,   XTTYPE_STRING),
+	ENTRY("arp-ptype",      O_PTYPE,   XTTYPE_STRING),
+	ENTRY("arp-ip-src",     O_SRC_IP,  XTTYPE_HOSTMASK),
+	ENTRY("arp-ip-dst",     O_DST_IP,  XTTYPE_HOSTMASK),
+	ENTRY("arp-mac-src",    O_SRC_MAC, XTTYPE_ETHERMACMASK),
+	ENTRY("arp-mac-dst",    O_DST_MAC, XTTYPE_ETHERMACMASK),
+	ENTRY("arp-gratuitous", O_GRAT,    XTTYPE_NONE),
+#undef ENTRY
+	XTOPT_TABLEEND
 };
 
 /* a few names */
@@ -62,13 +66,13 @@ static void brarp_print_help(void)
 
 	printf(
 "arp options:\n"
-"--arp-opcode  [!] opcode        : ARP opcode (integer or string)\n"
-"--arp-htype   [!] type          : ARP hardware type (integer or string)\n"
-"--arp-ptype   [!] type          : ARP protocol type (hexadecimal or string)\n"
-"--arp-ip-src  [!] address[/mask]: ARP IP source specification\n"
-"--arp-ip-dst  [!] address[/mask]: ARP IP target specification\n"
-"--arp-mac-src [!] address[/mask]: ARP MAC source specification\n"
-"--arp-mac-dst [!] address[/mask]: ARP MAC target specification\n"
+"[!] --arp-opcode  opcode        : ARP opcode (integer or string)\n"
+"[!] --arp-htype   type          : ARP hardware type (integer or string)\n"
+"[!] --arp-ptype   type          : ARP protocol type (hexadecimal or string)\n"
+"[!] --arp-ip-src  address[/mask]: ARP IP source specification\n"
+"[!] --arp-ip-dst  address[/mask]: ARP IP target specification\n"
+"[!] --arp-mac-src address[/mask]: ARP MAC source specification\n"
+"[!] --arp-mac-dst address[/mask]: ARP MAC target specification\n"
 "[!] --arp-gratuitous            : ARP gratuitous packet\n"
 " opcode strings: \n");
 	for (i = 0; i < ARRAY_SIZE(opcodes); i++)
@@ -78,137 +82,74 @@ static void brarp_print_help(void)
 " protocol type string: see "XT_PATH_ETHERTYPES"\n");
 }
 
-#define OPT_OPCODE 0x01
-#define OPT_HTYPE  0x02
-#define OPT_PTYPE  0x04
-#define OPT_IP_S   0x08
-#define OPT_IP_D   0x10
-#define OPT_MAC_S  0x20
-#define OPT_MAC_D  0x40
-#define OPT_GRAT   0x80
-
-static int
-brarp_parse(int c, char **argv, int invert, unsigned int *flags,
-	    const void *entry, struct xt_entry_match **match)
+static void brarp_parse(struct xt_option_call *cb)
 {
-	struct ebt_arp_info *arpinfo = (struct ebt_arp_info *)(*match)->data;
-	struct in_addr *ipaddr, ipmask;
+	struct ebt_arp_info *arpinfo = cb->data;
+	struct xt_ethertypeent *ent;
 	long int i;
 	char *end;
-	unsigned char *maddr;
-	unsigned char *mmask;
-	unsigned int ipnr;
 
-	switch (c) {
-	case ARP_OPCODE:
-		EBT_CHECK_OPTION(flags, OPT_OPCODE);
-		if (invert)
-			arpinfo->invflags |= EBT_ARP_OPCODE;
-		i = strtol(optarg, &end, 10);
+
+	xtables_option_parse(cb);
+
+	arpinfo->bitmask |= 1 << cb->entry->id;
+	if (cb->invert)
+		arpinfo->invflags |= 1 << cb->entry->id;
+
+	switch (cb->entry->id) {
+	case O_OPCODE:
+		i = strtol(cb->arg, &end, 10);
 		if (i < 0 || i >= (0x1 << 16) || *end !='\0') {
 			for (i = 0; i < ARRAY_SIZE(opcodes); i++)
-				if (!strcasecmp(opcodes[i], optarg))
+				if (!strcasecmp(opcodes[i], cb->arg))
 					break;
 			if (i == ARRAY_SIZE(opcodes))
-				xtables_error(PARAMETER_PROBLEM, "Problem with specified ARP opcode");
+				xtables_error(PARAMETER_PROBLEM,
+					      "Problem with specified ARP opcode");
 			i++;
 		}
 		arpinfo->opcode = htons(i);
-		arpinfo->bitmask |= EBT_ARP_OPCODE;
 		break;
-
-	case ARP_HTYPE:
-		EBT_CHECK_OPTION(flags, OPT_HTYPE);
-		if (invert)
-			arpinfo->invflags |= EBT_ARP_HTYPE;
-		i = strtol(optarg, &end, 10);
+	case O_HTYPE:
+		i = strtol(cb->arg, &end, 10);
 		if (i < 0 || i >= (0x1 << 16) || *end !='\0') {
-			if (!strcasecmp("Ethernet", argv[optind - 1]))
+			if (!strcasecmp("Ethernet", cb->arg))
 				i = 1;
 			else
-				xtables_error(PARAMETER_PROBLEM, "Problem with specified ARP hardware type");
+				xtables_error(PARAMETER_PROBLEM,
+					      "Problem with specified ARP hardware type");
 		}
 		arpinfo->htype = htons(i);
-		arpinfo->bitmask |= EBT_ARP_HTYPE;
-		break;
-	case ARP_PTYPE: {
-		uint16_t proto;
-
-		EBT_CHECK_OPTION(flags, OPT_PTYPE);
-		if (invert)
-			arpinfo->invflags |= EBT_ARP_PTYPE;
-
-		i = strtol(optarg, &end, 16);
-		if (i < 0 || i >= (0x1 << 16) || *end !='\0') {
-			struct xt_ethertypeent *ent;
-
-			ent = xtables_getethertypebyname(argv[optind - 1]);
-			if (!ent)
-				xtables_error(PARAMETER_PROBLEM, "Problem with specified ARP "
-								 "protocol type");
-			proto = ent->e_ethertype;
-
-		} else
-			proto = i;
-		arpinfo->ptype = htons(proto);
-		arpinfo->bitmask |= EBT_ARP_PTYPE;
 		break;
-	}
-
-	case ARP_IP_S:
-	case ARP_IP_D:
-		xtables_ipparse_any(optarg, &ipaddr, &ipmask, &ipnr);
-		if (c == ARP_IP_S) {
-			EBT_CHECK_OPTION(flags, OPT_IP_S);
-			arpinfo->saddr = ipaddr->s_addr;
-			arpinfo->smsk = ipmask.s_addr;
-			arpinfo->bitmask |= EBT_ARP_SRC_IP;
-		} else {
-			EBT_CHECK_OPTION(flags, OPT_IP_D);
-			arpinfo->daddr = ipaddr->s_addr;
-			arpinfo->dmsk = ipmask.s_addr;
-			arpinfo->bitmask |= EBT_ARP_DST_IP;
-		}
-		free(ipaddr);
-		if (invert) {
-			if (c == ARP_IP_S)
-				arpinfo->invflags |= EBT_ARP_SRC_IP;
-			else
-				arpinfo->invflags |= EBT_ARP_DST_IP;
+	case O_PTYPE:
+		i = strtol(cb->arg, &end, 16);
+		if (i >= 0 && i < (0x1 << 16) && *end == '\0') {
+			arpinfo->ptype = htons(i);
+			break;
 		}
+		ent = xtables_getethertypebyname(cb->arg);
+		if (!ent)
+			xtables_error(PARAMETER_PROBLEM,
+				      "Problem with specified ARP protocol type");
+		arpinfo->ptype = htons(ent->e_ethertype);
 		break;
-	case ARP_MAC_S:
-	case ARP_MAC_D:
-		if (c == ARP_MAC_S) {
-			EBT_CHECK_OPTION(flags, OPT_MAC_S);
-			maddr = arpinfo->smaddr;
-			mmask = arpinfo->smmsk;
-			arpinfo->bitmask |= EBT_ARP_SRC_MAC;
-		} else {
-			EBT_CHECK_OPTION(flags, OPT_MAC_D);
-			maddr = arpinfo->dmaddr;
-			mmask = arpinfo->dmmsk;
-			arpinfo->bitmask |= EBT_ARP_DST_MAC;
-		}
-		if (invert) {
-			if (c == ARP_MAC_S)
-				arpinfo->invflags |= EBT_ARP_SRC_MAC;
-			else
-				arpinfo->invflags |= EBT_ARP_DST_MAC;
-		}
-		if (xtables_parse_mac_and_mask(optarg, maddr, mmask))
-			xtables_error(PARAMETER_PROBLEM, "Problem with ARP MAC address argument");
+	case O_SRC_IP:
+		arpinfo->saddr = cb->val.haddr.ip & cb->val.hmask.ip;
+		arpinfo->smsk = cb->val.hmask.ip;
+		break;
+	case O_DST_IP:
+		arpinfo->daddr = cb->val.haddr.ip & cb->val.hmask.ip;
+		arpinfo->dmsk = cb->val.hmask.ip;
+		break;
+	case O_SRC_MAC:
+		memcpy(arpinfo->smaddr, cb->val.ethermac, ETH_ALEN);
+		memcpy(arpinfo->smmsk, cb->val.ethermacmask, ETH_ALEN);
 		break;
-	case ARP_GRAT:
-		EBT_CHECK_OPTION(flags, OPT_GRAT);
-		arpinfo->bitmask |= EBT_ARP_GRAT;
-		if (invert)
-			arpinfo->invflags |= EBT_ARP_GRAT;
+	case O_DST_MAC:
+		memcpy(arpinfo->dmaddr, cb->val.ethermac, ETH_ALEN);
+		memcpy(arpinfo->dmmsk, cb->val.ethermacmask, ETH_ALEN);
 		break;
-	default:
-		return 0;
 	}
-	return 1;
 }
 
 static void brarp_print(const void *ip, const struct xt_entry_match *match, int numeric)
@@ -217,51 +158,50 @@ static void brarp_print(const void *ip, const struct xt_entry_match *match, int
 
 	if (arpinfo->bitmask & EBT_ARP_OPCODE) {
 		int opcode = ntohs(arpinfo->opcode);
-		printf("--arp-op ");
+
 		if (arpinfo->invflags & EBT_ARP_OPCODE)
 			printf("! ");
+		printf("--arp-op ");
 		if (opcode > 0 && opcode <= ARRAY_SIZE(opcodes))
 			printf("%s ", opcodes[opcode - 1]);
 		else
 			printf("%d ", opcode);
 	}
 	if (arpinfo->bitmask & EBT_ARP_HTYPE) {
-		printf("--arp-htype ");
 		if (arpinfo->invflags & EBT_ARP_HTYPE)
 			printf("! ");
-		printf("%d ", ntohs(arpinfo->htype));
+		printf("--arp-htype %d ", ntohs(arpinfo->htype));
 	}
 	if (arpinfo->bitmask & EBT_ARP_PTYPE) {
-		printf("--arp-ptype ");
 		if (arpinfo->invflags & EBT_ARP_PTYPE)
 			printf("! ");
-		printf("0x%x ", ntohs(arpinfo->ptype));
+		printf("--arp-ptype 0x%x ", ntohs(arpinfo->ptype));
 	}
 	if (arpinfo->bitmask & EBT_ARP_SRC_IP) {
-		printf("--arp-ip-src ");
 		if (arpinfo->invflags & EBT_ARP_SRC_IP)
 			printf("! ");
-		printf("%s%s ", xtables_ipaddr_to_numeric((const struct in_addr*) &arpinfo->saddr),
-		       xtables_ipmask_to_numeric((const struct in_addr*)&arpinfo->smsk));
+		printf("--arp-ip-src %s%s ",
+		       xtables_ipaddr_to_numeric((void *)&arpinfo->saddr),
+		       xtables_ipmask_to_numeric((void *)&arpinfo->smsk));
 	}
 	if (arpinfo->bitmask & EBT_ARP_DST_IP) {
-		printf("--arp-ip-dst ");
 		if (arpinfo->invflags & EBT_ARP_DST_IP)
 			printf("! ");
-		printf("%s%s ", xtables_ipaddr_to_numeric((const struct in_addr*) &arpinfo->daddr),
-		       xtables_ipmask_to_numeric((const struct in_addr*)&arpinfo->dmsk));
+		printf("--arp-ip-dst %s%s ",
+		       xtables_ipaddr_to_numeric((void *)&arpinfo->daddr),
+		       xtables_ipmask_to_numeric((void *)&arpinfo->dmsk));
 	}
 	if (arpinfo->bitmask & EBT_ARP_SRC_MAC) {
-		printf("--arp-mac-src ");
 		if (arpinfo->invflags & EBT_ARP_SRC_MAC)
 			printf("! ");
+		printf("--arp-mac-src ");
 		xtables_print_mac_and_mask(arpinfo->smaddr, arpinfo->smmsk);
 		printf(" ");
 	}
 	if (arpinfo->bitmask & EBT_ARP_DST_MAC) {
-		printf("--arp-mac-dst ");
 		if (arpinfo->invflags & EBT_ARP_DST_MAC)
 			printf("! ");
+		printf("--arp-mac-dst ");
 		xtables_print_mac_and_mask(arpinfo->dmaddr, arpinfo->dmmsk);
 		printf(" ");
 	}
@@ -279,9 +219,9 @@ static struct xtables_match brarp_match = {
 	.size		= XT_ALIGN(sizeof(struct ebt_arp_info)),
 	.userspacesize	= XT_ALIGN(sizeof(struct ebt_arp_info)),
 	.help		= brarp_print_help,
-	.parse		= brarp_parse,
+	.x6_parse	= brarp_parse,
 	.print		= brarp_print,
-	.extra_opts	= brarp_opts,
+	.x6_options	= brarp_opts,
 };
 
 void _init(void)
diff --git a/extensions/libebt_arp.t b/extensions/libebt_arp.t
index 96fbce90..ea006f25 100644
--- a/extensions/libebt_arp.t
+++ b/extensions/libebt_arp.t
@@ -1,15 +1,22 @@
 :INPUT,FORWARD,OUTPUT
 -p ARP --arp-op Request;=;OK
--p ARP --arp-htype ! 1;=;OK
+-p ARP ! --arp-op Request;=;OK
+-p ARP --arp-htype Ethernet;-p ARP --arp-htype 1;OK
+-p ARP --arp-htype 1;=;OK
+-p ARP ! --arp-htype 1;=;OK
 -p ARP --arp-ptype 0x2;=;OK
+-p ARP ! --arp-ptype 0x2;=;OK
 -p ARP --arp-ip-src 1.2.3.4;=;OK
--p ARP ! --arp-ip-dst 1.2.3.4;-p ARP --arp-ip-dst ! 1.2.3.4 -j CONTINUE;OK
--p ARP --arp-ip-src ! 0.0.0.0;=;OK
--p ARP --arp-ip-dst ! 0.0.0.0/8;=;OK
--p ARP --arp-ip-src ! 1.2.3.4/32;-p ARP --arp-ip-src ! 1.2.3.4;OK
--p ARP --arp-ip-src ! 1.2.3.4/255.255.255.0;-p ARP --arp-ip-src ! 1.2.3.0/24;OK
--p ARP --arp-ip-src ! 1.2.3.4/255.0.255.255;-p ARP --arp-ip-src ! 1.0.3.4/255.0.255.255;OK
+-p ARP --arp-ip-dst ! 1.2.3.4;-p ARP ! --arp-ip-dst 1.2.3.4 -j CONTINUE;OK
+-p ARP ! --arp-ip-src 0.0.0.0;=;OK
+-p ARP ! --arp-ip-dst 0.0.0.0/8;=;OK
+-p ARP ! --arp-ip-src 1.2.3.4/32;-p ARP ! --arp-ip-src 1.2.3.4;OK
+-p ARP ! --arp-ip-src 1.2.3.4/255.255.255.0;-p ARP ! --arp-ip-src 1.2.3.0/24;OK
+-p ARP ! --arp-ip-src 1.2.3.4/255.0.255.255;-p ARP ! --arp-ip-src 1.0.3.4/255.0.255.255;OK
 -p ARP --arp-mac-src 00:de:ad:be:ef:00;=;OK
+-p ARP ! --arp-mac-src 00:de:ad:be:ef:00;=;OK
 -p ARP --arp-mac-dst de:ad:be:ef:00:00/ff:ff:ff:ff:00:00;=;OK
+-p ARP ! --arp-mac-dst de:ad:be:ef:00:00/ff:ff:ff:ff:00:00;=;OK
 -p ARP --arp-gratuitous;=;OK
+-p ARP ! --arp-gratuitous;=;OK
 --arp-htype 1;=;FAIL
diff --git a/extensions/libebt_arpreply.c b/extensions/libebt_arpreply.c
index 80ba2159..1d6ba36a 100644
--- a/extensions/libebt_arpreply.c
+++ b/extensions/libebt_arpreply.c
@@ -10,22 +10,22 @@
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
-#include <getopt.h>
 #include <xtables.h>
 #include <netinet/ether.h>
 #include <linux/netfilter_bridge/ebt_arpreply.h>
 #include "iptables/nft.h"
 #include "iptables/nft-bridge.h"
 
-#define OPT_REPLY_MAC     0x01
-#define OPT_REPLY_TARGET  0x02
+enum {
+	O_MAC,
+	O_TARGET,
+};
 
-#define REPLY_MAC '1'
-#define REPLY_TARGET '2'
-static const struct option brarpreply_opts[] = {
-	{ "arpreply-mac" ,    required_argument, 0, REPLY_MAC    },
-	{ "arpreply-target" , required_argument, 0, REPLY_TARGET },
-	XT_GETOPT_TABLEEND,
+static const struct xt_option_entry brarpreply_opts[] = {
+	{ .name = "arpreply-mac" ,    .id = O_MAC, .type = XTTYPE_ETHERMAC,
+	  .flags = XTOPT_PUT, XTOPT_POINTER(struct ebt_arpreply_info, mac) },
+	{ .name = "arpreply-target" , .id = O_TARGET, .type = XTTYPE_STRING },
+	XTOPT_TABLEEND,
 };
 
 static void brarpreply_print_help(void)
@@ -44,31 +44,15 @@ static void brarpreply_init(struct xt_entry_target *target)
 	replyinfo->target = EBT_DROP;
 }
 
-static int
-brarpreply_parse(int c, char **argv, int invert, unsigned int *flags,
-	    const void *entry, struct xt_entry_target **tg)
-
+static void brarpreply_parse(struct xt_option_call *cb)
 {
-	struct ebt_arpreply_info *replyinfo = (void *)(*tg)->data;
-	struct ether_addr *addr;
-
-	switch (c) {
-	case REPLY_MAC:
-		EBT_CHECK_OPTION(flags, OPT_REPLY_MAC);
-		if (!(addr = ether_aton(optarg)))
-			xtables_error(PARAMETER_PROBLEM, "Problem with specified --arpreply-mac mac");
-		memcpy(replyinfo->mac, addr, ETH_ALEN);
-		break;
-	case REPLY_TARGET:
-		EBT_CHECK_OPTION(flags, OPT_REPLY_TARGET);
-		if (ebt_fill_target(optarg, (unsigned int *)&replyinfo->target))
-			xtables_error(PARAMETER_PROBLEM, "Illegal --arpreply-target target");
-		break;
+	struct ebt_arpreply_info *replyinfo = cb->data;
 
-	default:
-		return 0;
-	}
-	return 1;
+	xtables_option_parse(cb);
+	if (cb->entry->id == O_TARGET &&
+	    ebt_fill_target(cb->arg, (unsigned int *)&replyinfo->target))
+		xtables_error(PARAMETER_PROBLEM,
+			      "Illegal --arpreply-target target");
 }
 
 static void brarpreply_print(const void *ip, const struct xt_entry_target *t, int numeric)
@@ -90,9 +74,9 @@ static struct xtables_target arpreply_target = {
 	.size		= XT_ALIGN(sizeof(struct ebt_arpreply_info)),
 	.userspacesize	= XT_ALIGN(sizeof(struct ebt_arpreply_info)),
 	.help		= brarpreply_print_help,
-	.parse		= brarpreply_parse,
+	.x6_parse	= brarpreply_parse,
 	.print		= brarpreply_print,
-	.extra_opts	= brarpreply_opts,
+	.x6_options	= brarpreply_opts,
 };
 
 void _init(void)
diff --git a/extensions/libebt_arpreply.t b/extensions/libebt_arpreply.t
index 6734501a..66103e16 100644
--- a/extensions/libebt_arpreply.t
+++ b/extensions/libebt_arpreply.t
@@ -1,4 +1,8 @@
 :PREROUTING
 *nat
+-j arpreply;=;FAIL
+-p ARP -i foo -j arpreply;-p ARP -i foo -j arpreply --arpreply-mac 00:00:00:00:00:00;OK
 -p ARP -i foo -j arpreply --arpreply-mac de:ad:00:be:ee:ff --arpreply-target ACCEPT;=;OK
 -p ARP -i foo -j arpreply --arpreply-mac de:ad:00:be:ee:ff;=;OK
+-p ARP -j arpreply ! --arpreply-mac de:ad:00:be:ee:ff;;FAIL
+-p ARP -j arpreply --arpreply-mac de:ad:00:be:ee:ff ! --arpreply-target ACCEPT;;FAIL
diff --git a/extensions/libebt_dnat.c b/extensions/libebt_dnat.c
index 9f5f721e..447ff105 100644
--- a/extensions/libebt_dnat.c
+++ b/extensions/libebt_dnat.c
@@ -9,21 +9,25 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
-#include <getopt.h>
 #include <netinet/ether.h>
 #include <xtables.h>
 #include <linux/netfilter_bridge/ebt_nat.h>
 #include "iptables/nft.h"
 #include "iptables/nft-bridge.h"
 
-#define NAT_D '1'
-#define NAT_D_TARGET '2'
-static const struct option brdnat_opts[] =
+enum {
+	O_DST,
+	O_TARGET,
+};
+
+static const struct xt_option_entry brdnat_opts[] =
 {
-	{ "to-destination", required_argument, 0, NAT_D },
-	{ "to-dst"        , required_argument, 0, NAT_D },
-	{ "dnat-target"   , required_argument, 0, NAT_D_TARGET },
-	{ 0 }
+	{ .name = "to-destination", .id = O_DST, .type = XTTYPE_ETHERMAC,
+	  .flags = XTOPT_PUT, XTOPT_POINTER(struct ebt_nat_info, mac) },
+	{ .name = "to-dst"        , .id = O_DST, .type = XTTYPE_ETHERMAC,
+	  .flags = XTOPT_PUT, XTOPT_POINTER(struct ebt_nat_info, mac) },
+	{ .name = "dnat-target"   , .id = O_TARGET, .type = XTTYPE_STRING },
+	XTOPT_TABLEEND,
 };
 
 static void brdnat_print_help(void)
@@ -31,7 +35,8 @@ static void brdnat_print_help(void)
 	printf(
 	"dnat options:\n"
 	" --to-dst address       : MAC address to map destination to\n"
-	" --dnat-target target   : ACCEPT, DROP, RETURN or CONTINUE\n");
+	" --dnat-target target   : ACCEPT, DROP, RETURN or CONTINUE\n"
+	"                          (standard target is ACCEPT)\n");
 }
 
 static void brdnat_init(struct xt_entry_target *target)
@@ -41,35 +46,20 @@ static void brdnat_init(struct xt_entry_target *target)
 	natinfo->target = EBT_ACCEPT;
 }
 
-#define OPT_DNAT        0x01
-#define OPT_DNAT_TARGET 0x02
-static int brdnat_parse(int c, char **argv, int invert, unsigned int *flags,
-			 const void *entry, struct xt_entry_target **target)
+static void brdnat_parse(struct xt_option_call *cb)
 {
-	struct ebt_nat_info *natinfo = (struct ebt_nat_info *)(*target)->data;
-	struct ether_addr *addr;
-
-	switch (c) {
-	case NAT_D:
-		EBT_CHECK_OPTION(flags, OPT_DNAT);
-		if (!(addr = ether_aton(optarg)))
-			xtables_error(PARAMETER_PROBLEM, "Problem with specified --to-destination mac");
-		memcpy(natinfo->mac, addr, ETH_ALEN);
-		break;
-	case NAT_D_TARGET:
-		EBT_CHECK_OPTION(flags, OPT_DNAT_TARGET);
-		if (ebt_fill_target(optarg, (unsigned int *)&natinfo->target))
-			xtables_error(PARAMETER_PROBLEM, "Illegal --dnat-target target");
-		break;
-	default:
-		return 0;
-	}
-	return 1;
+	struct ebt_nat_info *natinfo = cb->data;
+
+	xtables_option_parse(cb);
+	if (cb->entry->id == O_TARGET &&
+	    ebt_fill_target(cb->arg, (unsigned int *)&natinfo->target))
+		xtables_error(PARAMETER_PROBLEM,
+			      "Illegal --dnat-target target");
 }
 
-static void brdnat_final_check(unsigned int flags)
+static void brdnat_final_check(struct xt_fcheck_call *fc)
 {
-	if (!flags)
+	if (!fc->xflags)
 		xtables_error(PARAMETER_PROBLEM,
 			      "You must specify proper arguments");
 }
@@ -116,11 +106,11 @@ static struct xtables_target brdnat_target =
 	.userspacesize	= XT_ALIGN(sizeof(struct ebt_nat_info)),
 	.help		= brdnat_print_help,
 	.init		= brdnat_init,
-	.parse		= brdnat_parse,
-	.final_check	= brdnat_final_check,
+	.x6_parse	= brdnat_parse,
+	.x6_fcheck	= brdnat_final_check,
 	.print		= brdnat_print,
 	.xlate		= brdnat_xlate,
-	.extra_opts	= brdnat_opts,
+	.x6_options	= brdnat_opts,
 };
 
 void _init(void)
diff --git a/extensions/libebt_ip.c b/extensions/libebt_ip.c
index 68f34bff..3ed852ad 100644
--- a/extensions/libebt_ip.c
+++ b/extensions/libebt_ip.c
@@ -16,7 +16,6 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
-#include <getopt.h>
 #include <netdb.h>
 #include <inttypes.h>
 #include <xtables.h>
@@ -24,44 +23,70 @@
 
 #include "libxt_icmp.h"
 
-#define IP_SOURCE	'1'
-#define IP_DEST		'2'
-#define IP_EBT_TOS	'3' /* include/bits/in.h seems to already define IP_TOS */
-#define IP_PROTO	'4'
-#define IP_SPORT	'5'
-#define IP_DPORT	'6'
-#define IP_EBT_ICMP	'7'
-#define IP_EBT_IGMP	'8'
-
-static const struct option brip_opts[] = {
-	{ .name = "ip-source",		.has_arg = true, .val = IP_SOURCE },
-	{ .name = "ip-src",		.has_arg = true, .val = IP_SOURCE },
-	{ .name = "ip-destination",	.has_arg = true, .val = IP_DEST },
-	{ .name = "ip-dst",		.has_arg = true, .val = IP_DEST },
-	{ .name = "ip-tos",		.has_arg = true, .val = IP_EBT_TOS },
-	{ .name = "ip-protocol",	.has_arg = true, .val = IP_PROTO },
-	{ .name = "ip-proto",		.has_arg = true, .val = IP_PROTO },
-	{ .name = "ip-source-port",	.has_arg = true, .val = IP_SPORT },
-	{ .name = "ip-sport",		.has_arg = true, .val = IP_SPORT },
-	{ .name = "ip-destination-port",.has_arg = true, .val = IP_DPORT },
-	{ .name = "ip-dport",		.has_arg = true, .val = IP_DPORT },
-	{ .name = "ip-icmp-type",       .has_arg = true, .val = IP_EBT_ICMP },
-	{ .name = "ip-igmp-type",       .has_arg = true, .val = IP_EBT_IGMP },
-	XT_GETOPT_TABLEEND,
+/* must correspond to the bit position in EBT_IP6_* defines */
+enum {
+	O_SOURCE = 0,
+	O_DEST,
+	O_TOS,
+	O_PROTO,
+	O_SPORT,
+	O_DPORT,
+	O_ICMP,
+	O_IGMP,
+	F_PORT = 1 << O_ICMP | 1 << O_IGMP,
+	F_ICMP = 1 << O_SPORT | 1 << O_DPORT | 1 << O_IGMP,
+	F_IGMP = 1 << O_SPORT | 1 << O_DPORT | 1 << O_ICMP,
+};
+
+static const struct xt_option_entry brip_opts[] = {
+	{ .name = "ip-source",		.id = O_SOURCE, .type = XTTYPE_HOSTMASK,
+	  .flags = XTOPT_INVERT },
+	{ .name = "ip-src",		.id = O_SOURCE, .type = XTTYPE_HOSTMASK,
+	  .flags = XTOPT_INVERT },
+	{ .name = "ip-destination",	.id = O_DEST, .type = XTTYPE_HOSTMASK,
+	  .flags = XTOPT_INVERT },
+	{ .name = "ip-dst",		.id = O_DEST, .type = XTTYPE_HOSTMASK,
+	  .flags = XTOPT_INVERT },
+	{ .name = "ip-tos",		.id = O_TOS, .type = XTTYPE_UINT8,
+	  .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_ip_info, tos) },
+	{ .name = "ip-protocol",	.id = O_PROTO, .type = XTTYPE_PROTOCOL,
+	  .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_ip_info, protocol) },
+	{ .name = "ip-proto",		.id = O_PROTO, .type = XTTYPE_PROTOCOL,
+	  .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_ip_info, protocol) },
+	{ .name = "ip-source-port",	.id = O_SPORT, .type = XTTYPE_PORTRC,
+	  .excl = F_PORT, .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_ip_info, sport) },
+	{ .name = "ip-sport",		.id = O_SPORT, .type = XTTYPE_PORTRC,
+	  .excl = F_PORT, .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_ip_info, sport) },
+	{ .name = "ip-destination-port",.id = O_DPORT, .type = XTTYPE_PORTRC,
+	  .excl = F_PORT, .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_ip_info, dport) },
+	{ .name = "ip-dport",		.id = O_DPORT, .type = XTTYPE_PORTRC,
+	  .excl = F_PORT, .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_ip_info, dport) },
+	{ .name = "ip-icmp-type",       .id = O_ICMP, .type = XTTYPE_STRING,
+	  .excl = F_ICMP, .flags = XTOPT_INVERT },
+	{ .name = "ip-igmp-type",       .id = O_IGMP, .type = XTTYPE_STRING,
+	  .excl = F_IGMP, .flags = XTOPT_INVERT },
+	XTOPT_TABLEEND,
 };
 
 static void brip_print_help(void)
 {
 	printf(
 "ip options:\n"
-"--ip-src    [!] address[/mask]: ip source specification\n"
-"--ip-dst    [!] address[/mask]: ip destination specification\n"
-"--ip-tos    [!] tos           : ip tos specification\n"
-"--ip-proto  [!] protocol      : ip protocol specification\n"
-"--ip-sport  [!] port[:port]   : tcp/udp source port or port range\n"
-"--ip-dport  [!] port[:port]   : tcp/udp destination port or port range\n"
-"--ip-icmp-type [!] type[[:type]/code[:code]] : icmp type/code or type/code range\n"
-"--ip-igmp-type [!] type[:type]               : igmp type or type range\n");
+"[!] --ip-src    address[/mask]: ip source specification\n"
+"[!] --ip-dst    address[/mask]: ip destination specification\n"
+"[!] --ip-tos    tos           : ip tos specification\n"
+"[!] --ip-proto  protocol      : ip protocol specification\n"
+"[!] --ip-sport  port[:port]   : tcp/udp source port or port range\n"
+"[!] --ip-dport  port[:port]   : tcp/udp destination port or port range\n"
+"[!] --ip-icmp-type type[[:type]/code[:code]] : icmp type/code or type/code range\n"
+"[!] --ip-igmp-type type[:type]               : igmp type or type range\n");
 
 	printf("\nValid ICMP Types:\n");
 	xt_print_icmp_types(icmp_codes, ARRAY_SIZE(icmp_codes));
@@ -69,38 +94,6 @@ static void brip_print_help(void)
 	xt_print_icmp_types(igmp_types, ARRAY_SIZE(igmp_types));
 }
 
-static void brip_init(struct xt_entry_match *match)
-{
-	struct ebt_ip_info *info = (struct ebt_ip_info *)match->data;
-
-	info->invflags = 0;
-	info->bitmask = 0;
-}
-
-static void
-parse_port_range(const char *protocol, const char *portstring, uint16_t *ports)
-{
-	char *buffer;
-	char *cp;
-
-	buffer = xtables_strdup(portstring);
-
-	if ((cp = strchr(buffer, ':')) == NULL)
-		ports[0] = ports[1] = xtables_parse_port(buffer, NULL);
-	else {
-		*cp = '\0';
-		cp++;
-
-		ports[0] = buffer[0] ? xtables_parse_port(buffer, NULL) : 0;
-		ports[1] = cp[0] ? xtables_parse_port(cp, NULL) : 0xFFFF;
-
-		if (ports[0] > ports[1])
-			xtables_error(PARAMETER_PROBLEM,
-				      "invalid portrange (min > max)");
-	}
-	free(buffer);
-}
-
 /* original code from ebtables: useful_functions.c */
 static void print_icmp_code(uint8_t *code)
 {
@@ -138,86 +131,38 @@ static void ebt_print_icmp_type(const struct xt_icmp_names *codes,
 	print_icmp_code(code);
 }
 
-static int
-brip_parse(int c, char **argv, int invert, unsigned int *flags,
-	   const void *entry, struct xt_entry_match **match)
+static void brip_parse(struct xt_option_call *cb)
 {
-	struct ebt_ip_info *info = (struct ebt_ip_info *)(*match)->data;
-	struct in_addr *ipaddr, ipmask;
-	unsigned int ipnr;
-
-	switch (c) {
-	case IP_SOURCE:
-		if (invert)
-			info->invflags |= EBT_IP_SOURCE;
-		xtables_ipparse_any(optarg, &ipaddr, &ipmask, &ipnr);
-		info->saddr = ipaddr->s_addr;
-		info->smsk = ipmask.s_addr;
-		free(ipaddr);
-		info->bitmask |= EBT_IP_SOURCE;
-		break;
-	case IP_DEST:
-		if (invert)
-			info->invflags |= EBT_IP_DEST;
-		xtables_ipparse_any(optarg, &ipaddr, &ipmask, &ipnr);
-		info->daddr = ipaddr->s_addr;
-		info->dmsk = ipmask.s_addr;
-		free(ipaddr);
-		info->bitmask |= EBT_IP_DEST;
-		break;
-	case IP_SPORT:
-		if (invert)
-			info->invflags |= EBT_IP_SPORT;
-		parse_port_range(NULL, optarg, info->sport);
-		info->bitmask |= EBT_IP_SPORT;
-		break;
-	case IP_DPORT:
-		if (invert)
-			info->invflags |= EBT_IP_DPORT;
-		parse_port_range(NULL, optarg, info->dport);
-		info->bitmask |= EBT_IP_DPORT;
-		break;
-	case IP_EBT_ICMP:
-		if (invert)
-			info->invflags |= EBT_IP_ICMP;
-		ebt_parse_icmp(optarg, info->icmp_type, info->icmp_code);
-		info->bitmask |= EBT_IP_ICMP;
+	struct ebt_ip_info *info = cb->data;
+
+	xtables_option_parse(cb);
+
+	info->bitmask |= 1 << cb->entry->id;
+	info->invflags |= cb->invert ? 1 << cb->entry->id : 0;
+
+	switch (cb->entry->id) {
+	case O_SOURCE:
+		cb->val.haddr.all[0] &= cb->val.hmask.all[0];
+		info->saddr = cb->val.haddr.ip;
+		info->smsk = cb->val.hmask.ip;
 		break;
-	case IP_EBT_IGMP:
-		if (invert)
-			info->invflags |= EBT_IP_IGMP;
-		ebt_parse_igmp(optarg, info->igmp_type);
-		info->bitmask |= EBT_IP_IGMP;
+	case O_DEST:
+		cb->val.haddr.all[0] &= cb->val.hmask.all[0];
+		info->daddr = cb->val.haddr.ip;
+		info->dmsk = cb->val.hmask.ip;
 		break;
-	case IP_EBT_TOS: {
-		uintmax_t tosvalue;
-
-		if (invert)
-			info->invflags |= EBT_IP_TOS;
-		if (!xtables_strtoul(optarg, NULL, &tosvalue, 0, 255))
-			xtables_error(PARAMETER_PROBLEM,
-				      "Problem with specified IP tos");
-		info->tos = tosvalue;
-		info->bitmask |= EBT_IP_TOS;
-	}
+	case O_ICMP:
+		ebt_parse_icmp(cb->arg, info->icmp_type, info->icmp_code);
 		break;
-	case IP_PROTO:
-		if (invert)
-			info->invflags |= EBT_IP_PROTO;
-		info->protocol = xtables_parse_protocol(optarg);
-		info->bitmask |= EBT_IP_PROTO;
+	case O_IGMP:
+		ebt_parse_igmp(cb->arg, info->igmp_type);
 		break;
-	default:
-		return 0;
 	}
-
-	*flags |= info->bitmask;
-	return 1;
 }
 
-static void brip_final_check(unsigned int flags)
+static void brip_final_check(struct xt_fcheck_call *fc)
 {
-	if (!flags)
+	if (!fc->xflags)
 		xtables_error(PARAMETER_PROBLEM,
 			      "You must specify proper arguments");
 }
@@ -237,35 +182,34 @@ static void brip_print(const void *ip, const struct xt_entry_match *match,
 	struct in_addr *addrp, *maskp;
 
 	if (info->bitmask & EBT_IP_SOURCE) {
-		printf("--ip-src ");
 		if (info->invflags & EBT_IP_SOURCE)
 			printf("! ");
 		addrp = (struct in_addr *)&info->saddr;
 		maskp = (struct in_addr *)&info->smsk;
-		printf("%s%s ", xtables_ipaddr_to_numeric(addrp),
+		printf("--ip-src %s%s ",
+		       xtables_ipaddr_to_numeric(addrp),
 		       xtables_ipmask_to_numeric(maskp));
 	}
 	if (info->bitmask & EBT_IP_DEST) {
-		printf("--ip-dst ");
 		if (info->invflags & EBT_IP_DEST)
 			printf("! ");
 		addrp = (struct in_addr *)&info->daddr;
 		maskp = (struct in_addr *)&info->dmsk;
-		printf("%s%s ", xtables_ipaddr_to_numeric(addrp),
+		printf("--ip-dst %s%s ",
+		       xtables_ipaddr_to_numeric(addrp),
 		       xtables_ipmask_to_numeric(maskp));
 	}
 	if (info->bitmask & EBT_IP_TOS) {
-		printf("--ip-tos ");
 		if (info->invflags & EBT_IP_TOS)
 			printf("! ");
-		printf("0x%02X ", info->tos);
+		printf("--ip-tos 0x%02X ", info->tos);
 	}
 	if (info->bitmask & EBT_IP_PROTO) {
 		struct protoent *pe;
 
-		printf("--ip-proto ");
 		if (info->invflags & EBT_IP_PROTO)
 			printf("! ");
+		printf("--ip-proto ");
 		pe = getprotobynumber(info->protocol);
 		if (pe == NULL) {
 			printf("%d ", info->protocol);
@@ -274,28 +218,28 @@ static void brip_print(const void *ip, const struct xt_entry_match *match,
 		}
 	}
 	if (info->bitmask & EBT_IP_SPORT) {
-		printf("--ip-sport ");
 		if (info->invflags & EBT_IP_SPORT)
 			printf("! ");
+		printf("--ip-sport ");
 		print_port_range(info->sport);
 	}
 	if (info->bitmask & EBT_IP_DPORT) {
-		printf("--ip-dport ");
 		if (info->invflags & EBT_IP_DPORT)
 			printf("! ");
+		printf("--ip-dport ");
 		print_port_range(info->dport);
 	}
 	if (info->bitmask & EBT_IP_ICMP) {
-		printf("--ip-icmp-type ");
 		if (info->invflags & EBT_IP_ICMP)
 			printf("! ");
+		printf("--ip-icmp-type ");
 		ebt_print_icmp_type(icmp_codes, ARRAY_SIZE(icmp_codes),
 				    info->icmp_type, info->icmp_code);
 	}
 	if (info->bitmask & EBT_IP_IGMP) {
-		printf("--ip-igmp-type ");
 		if (info->invflags & EBT_IP_IGMP)
 			printf("! ");
+		printf("--ip-igmp-type ");
 		ebt_print_icmp_type(igmp_types, ARRAY_SIZE(igmp_types),
 				    info->igmp_type, NULL);
 	}
@@ -503,13 +447,12 @@ static struct xtables_match brip_match = {
 	.family		= NFPROTO_BRIDGE,
 	.size		= XT_ALIGN(sizeof(struct ebt_ip_info)),
 	.userspacesize	= XT_ALIGN(sizeof(struct ebt_ip_info)),
-	.init		= brip_init,
 	.help		= brip_print_help,
-	.parse		= brip_parse,
-	.final_check	= brip_final_check,
+	.x6_parse	= brip_parse,
+	.x6_fcheck	= brip_final_check,
 	.print		= brip_print,
 	.xlate		= brip_xlate,
-	.extra_opts	= brip_opts,
+	.x6_options	= brip_opts,
 };
 
 void _init(void)
diff --git a/extensions/libebt_ip.t b/extensions/libebt_ip.t
index 8be5dfbb..a9b5b8b5 100644
--- a/extensions/libebt_ip.t
+++ b/extensions/libebt_ip.t
@@ -1,13 +1,33 @@
 :INPUT,FORWARD,OUTPUT
--p ip --ip-src ! 192.168.0.0/24 -j ACCEPT;-p IPv4 --ip-src ! 192.168.0.0/24 -j ACCEPT;OK
+-p ip ! --ip-src 192.168.0.0/24 -j ACCEPT;-p IPv4 ! --ip-src 192.168.0.0/24 -j ACCEPT;OK
 -p IPv4 --ip-dst 10.0.0.1;=;OK
+-p IPv4 ! --ip-dst 10.0.0.1;=;OK
 -p IPv4 --ip-tos 0xFF;=;OK
--p IPv4 --ip-tos ! 0xFF;=;OK
+-p IPv4 ! --ip-tos 0xFF;=;OK
 -p IPv4 --ip-proto tcp --ip-dport 22;=;OK
 -p IPv4 --ip-proto udp --ip-sport 1024:65535;=;OK
+-p IPv4 --ip-proto udp --ip-sport :;-p IPv4 --ip-proto udp --ip-sport 0:65535;OK
+-p IPv4 --ip-proto udp --ip-sport :4;-p IPv4 --ip-proto udp --ip-sport 0:4;OK
+-p IPv4 --ip-proto udp --ip-sport 4:;-p IPv4 --ip-proto udp --ip-sport 4:65535;OK
+-p IPv4 --ip-proto udp --ip-sport 3:4;=;OK
+-p IPv4 --ip-proto udp --ip-sport 4:4;-p IPv4 --ip-proto udp --ip-sport 4;OK
+-p IPv4 --ip-proto udp --ip-sport 4:3;;FAIL
+-p IPv4 --ip-proto udp --ip-dport :;-p IPv4 --ip-proto udp --ip-dport 0:65535;OK
+-p IPv4 --ip-proto udp --ip-dport :4;-p IPv4 --ip-proto udp --ip-dport 0:4;OK
+-p IPv4 --ip-proto udp --ip-dport 4:;-p IPv4 --ip-proto udp --ip-dport 4:65535;OK
+-p IPv4 --ip-proto udp --ip-dport 3:4;=;OK
+-p IPv4 --ip-proto udp --ip-dport 4:4;-p IPv4 --ip-proto udp --ip-dport 4;OK
+-p IPv4 --ip-proto udp --ip-dport 4:3;;FAIL
 -p IPv4 --ip-proto 253;=;OK
+-p IPv4 ! --ip-proto 253;=;OK
 -p IPv4 --ip-proto icmp --ip-icmp-type echo-request;=;OK
 -p IPv4 --ip-proto icmp --ip-icmp-type 1/1;=;OK
--p ip --ip-protocol icmp --ip-icmp-type ! 1:10;-p IPv4 --ip-proto icmp --ip-icmp-type ! 1:10/0:255 -j CONTINUE;OK
+-p ip --ip-protocol icmp ! --ip-icmp-type 1:10;-p IPv4 --ip-proto icmp ! --ip-icmp-type 1:10/0:255 -j CONTINUE;OK
 --ip-proto icmp --ip-icmp-type 1/1;=;FAIL
 ! -p ip --ip-proto icmp --ip-icmp-type 1/1;=;FAIL
+! -p ip --ip-proto tcp --ip-sport 22 --ip-icmp-type echo-reply;;FAIL
+! -p ip --ip-proto tcp --ip-sport 22 --ip-igmp-type membership-query;;FAIL
+! -p ip --ip-proto tcp --ip-dport 22 --ip-icmp-type echo-reply;;FAIL
+! -p ip --ip-proto tcp --ip-dport 22 --ip-igmp-type membership-query;;FAIL
+! -p ip --ip-proto icmp --ip-icmp-type echo-reply --ip-igmp-type membership-query;;FAIL
+-p IPv4 --ip-proto icmp ! --ip-icmp-type echo-reply;=;OK
diff --git a/extensions/libebt_ip.txlate b/extensions/libebt_ip.txlate
index 44ce9276..712ba3d1 100644
--- a/extensions/libebt_ip.txlate
+++ b/extensions/libebt_ip.txlate
@@ -1,4 +1,4 @@
-ebtables-translate -A FORWARD -p ip --ip-src ! 192.168.0.0/24 -j ACCEPT
+ebtables-translate -A FORWARD -p ip ! --ip-src 192.168.0.0/24 -j ACCEPT
 nft 'add rule bridge filter FORWARD ip saddr != 192.168.0.0/24 counter accept'
 
 ebtables-translate -I FORWARD -p ip --ip-dst 10.0.0.1
@@ -22,5 +22,5 @@ nft 'add rule bridge filter FORWARD icmp type 8 counter'
 ebtables-translate -A FORWARD -p ip --ip-proto icmp --ip-icmp-type 1/1
 nft 'add rule bridge filter FORWARD icmp type 1 icmp code 1 counter'
 
-ebtables-translate -A FORWARD -p ip --ip-protocol icmp --ip-icmp-type ! 1:10
+ebtables-translate -A FORWARD -p ip --ip-protocol icmp ! --ip-icmp-type 1:10
 nft 'add rule bridge filter FORWARD icmp type != 1-10 counter'
diff --git a/extensions/libebt_ip6.c b/extensions/libebt_ip6.c
index 18bb2720..247a99eb 100644
--- a/extensions/libebt_ip6.c
+++ b/extensions/libebt_ip6.c
@@ -18,59 +18,59 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
-#include <getopt.h>
 #include <netdb.h>
 #include <xtables.h>
 #include <linux/netfilter_bridge/ebt_ip6.h>
 
 #include "libxt_icmp.h"
 
-#define IP_SOURCE '1'
-#define IP_DEST   '2'
-#define IP_TCLASS '3'
-#define IP_PROTO  '4'
-#define IP_SPORT  '5'
-#define IP_DPORT  '6'
-#define IP_ICMP6  '7'
-
-static const struct option brip6_opts[] = {
-	{ .name = "ip6-source",		.has_arg = true, .val = IP_SOURCE },
-	{ .name = "ip6-src",		.has_arg = true, .val = IP_SOURCE },
-	{ .name = "ip6-destination",	.has_arg = true, .val = IP_DEST },
-	{ .name = "ip6-dst",		.has_arg = true, .val = IP_DEST },
-	{ .name = "ip6-tclass",		.has_arg = true, .val = IP_TCLASS },
-	{ .name = "ip6-protocol",	.has_arg = true, .val = IP_PROTO },
-	{ .name = "ip6-proto",		.has_arg = true, .val = IP_PROTO },
-	{ .name = "ip6-source-port",	.has_arg = true, .val = IP_SPORT },
-	{ .name = "ip6-sport",		.has_arg = true, .val = IP_SPORT },
-	{ .name = "ip6-destination-port",.has_arg = true,.val = IP_DPORT },
-	{ .name = "ip6-dport",		.has_arg = true, .val = IP_DPORT },
-	{ .name = "ip6-icmp-type",	.has_arg = true, .val = IP_ICMP6 },
-	XT_GETOPT_TABLEEND,
+/* must correspond to the bit position in EBT_IP6_* defines */
+enum {
+	O_SOURCE = 0,
+	O_DEST,
+	O_TCLASS,
+	O_PROTO,
+	O_SPORT,
+	O_DPORT,
+	O_ICMP6,
+	F_PORT = 1 << O_ICMP6,
+	F_ICMP6 = 1 << O_SPORT | 1 << O_DPORT,
 };
 
-static void
-parse_port_range(const char *protocol, const char *portstring, uint16_t *ports)
-{
-	char *buffer;
-	char *cp;
-
-	buffer = xtables_strdup(portstring);
-	if ((cp = strchr(buffer, ':')) == NULL)
-		ports[0] = ports[1] = xtables_parse_port(buffer, NULL);
-	else {
-		*cp = '\0';
-		cp++;
-
-		ports[0] = buffer[0] ? xtables_parse_port(buffer, NULL) : 0;
-		ports[1] = cp[0] ? xtables_parse_port(cp, NULL) : 0xFFFF;
-
-		if (ports[0] > ports[1])
-			xtables_error(PARAMETER_PROBLEM,
-				      "invalid portrange (min > max)");
-	}
-	free(buffer);
-}
+static const struct xt_option_entry brip6_opts[] = {
+	{ .name = "ip6-source",		.id = O_SOURCE, .type = XTTYPE_HOSTMASK,
+	  .flags = XTOPT_INVERT },
+	{ .name = "ip6-src",		.id = O_SOURCE, .type = XTTYPE_HOSTMASK,
+	  .flags = XTOPT_INVERT },
+	{ .name = "ip6-destination",	.id = O_DEST, .type = XTTYPE_HOSTMASK,
+	  .flags = XTOPT_INVERT },
+	{ .name = "ip6-dst",		.id = O_DEST, .type = XTTYPE_HOSTMASK,
+	  .flags = XTOPT_INVERT },
+	{ .name = "ip6-tclass",		.id = O_TCLASS, .type = XTTYPE_UINT8,
+	  .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_ip6_info, tclass) },
+	{ .name = "ip6-protocol",	.id = O_PROTO, .type = XTTYPE_PROTOCOL,
+	  .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_ip6_info, protocol) },
+	{ .name = "ip6-proto",		.id = O_PROTO, .type = XTTYPE_PROTOCOL,
+	  .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_ip6_info, protocol) },
+	{ .name = "ip6-source-port",	.id = O_SPORT, .type = XTTYPE_PORTRC,
+	  .excl = F_PORT, .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_ip6_info, sport) },
+	{ .name = "ip6-sport",		.id = O_SPORT, .type = XTTYPE_PORTRC,
+	  .excl = F_PORT, .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_ip6_info, sport) },
+	{ .name = "ip6-destination-port",.id = O_DPORT, .type = XTTYPE_PORTRC,
+	  .excl = F_PORT, .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_ip6_info, dport) },
+	{ .name = "ip6-dport",		.id = O_DPORT, .type = XTTYPE_PORTRC,
+	  .excl = F_PORT, .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_ip6_info, dport) },
+	{ .name = "ip6-icmp-type",	.id = O_ICMP6, .type = XTTYPE_STRING,
+	  .excl = F_ICMP6, .flags = XTOPT_INVERT },
+	XTOPT_TABLEEND,
+};
 
 static void print_port_range(uint16_t *ports)
 {
@@ -116,114 +116,53 @@ static void brip6_print_help(void)
 {
 	printf(
 "ip6 options:\n"
-"--ip6-src    [!] address[/mask]: ipv6 source specification\n"
-"--ip6-dst    [!] address[/mask]: ipv6 destination specification\n"
-"--ip6-tclass [!] tclass        : ipv6 traffic class specification\n"
-"--ip6-proto  [!] protocol      : ipv6 protocol specification\n"
-"--ip6-sport  [!] port[:port]   : tcp/udp source port or port range\n"
-"--ip6-dport  [!] port[:port]   : tcp/udp destination port or port range\n"
-"--ip6-icmp-type [!] type[[:type]/code[:code]] : ipv6-icmp type/code or type/code range\n");
+"[!] --ip6-src    address[/mask]: ipv6 source specification\n"
+"[!] --ip6-dst    address[/mask]: ipv6 destination specification\n"
+"[!] --ip6-tclass tclass        : ipv6 traffic class specification\n"
+"[!] --ip6-proto  protocol      : ipv6 protocol specification\n"
+"[!] --ip6-sport  port[:port]   : tcp/udp source port or port range\n"
+"[!] --ip6-dport  port[:port]   : tcp/udp destination port or port range\n"
+"[!] --ip6-icmp-type type[[:type]/code[:code]] : ipv6-icmp type/code or type/code range\n");
 	printf("Valid ICMPv6 Types:");
 	xt_print_icmp_types(icmpv6_codes, ARRAY_SIZE(icmpv6_codes));
 }
 
-static void brip6_init(struct xt_entry_match *match)
-{
-	struct ebt_ip6_info *ipinfo = (struct ebt_ip6_info *)match->data;
-
-	ipinfo->invflags = 0;
-	ipinfo->bitmask = 0;
-	memset(ipinfo->saddr.s6_addr, 0, sizeof(ipinfo->saddr.s6_addr));
-	memset(ipinfo->smsk.s6_addr, 0, sizeof(ipinfo->smsk.s6_addr));
-	memset(ipinfo->daddr.s6_addr, 0, sizeof(ipinfo->daddr.s6_addr));
-	memset(ipinfo->dmsk.s6_addr, 0, sizeof(ipinfo->dmsk.s6_addr));
-}
-
-/* wrap xtables_ip6parse_any(), ignoring any but the first returned address */
-static void ebt_parse_ip6_address(char *address,
-				  struct in6_addr *addr, struct in6_addr *msk)
+static void brip6_parse(struct xt_option_call *cb)
 {
-	struct in6_addr *addrp;
-	unsigned int naddrs;
-
-	xtables_ip6parse_any(address, &addrp, msk, &naddrs);
-	if (naddrs != 1)
-		xtables_error(PARAMETER_PROBLEM,
-			      "Invalid IPv6 Address '%s' specified", address);
-	memcpy(addr, addrp, sizeof(*addr));
-	free(addrp);
-}
-
-#define OPT_SOURCE 0x01
-#define OPT_DEST   0x02
-#define OPT_TCLASS 0x04
-#define OPT_PROTO  0x08
-#define OPT_SPORT  0x10
-#define OPT_DPORT  0x20
-static int
-brip6_parse(int c, char **argv, int invert, unsigned int *flags,
-	   const void *entry, struct xt_entry_match **match)
-{
-	struct ebt_ip6_info *info = (struct ebt_ip6_info *)(*match)->data;
+	struct ebt_ip6_info *info = cb->data;
 	unsigned int i;
-	char *end;
-
-	switch (c) {
-	case IP_SOURCE:
-		if (invert)
-			info->invflags |= EBT_IP6_SOURCE;
-		ebt_parse_ip6_address(optarg, &info->saddr, &info->smsk);
-		info->bitmask |= EBT_IP6_SOURCE;
-		break;
-	case IP_DEST:
-		if (invert)
-			info->invflags |= EBT_IP6_DEST;
-		ebt_parse_ip6_address(optarg, &info->daddr, &info->dmsk);
-		info->bitmask |= EBT_IP6_DEST;
-		break;
-	case IP_SPORT:
-		if (invert)
-			info->invflags |= EBT_IP6_SPORT;
-		parse_port_range(NULL, optarg, info->sport);
-		info->bitmask |= EBT_IP6_SPORT;
-		break;
-	case IP_DPORT:
-		if (invert)
-			info->invflags |= EBT_IP6_DPORT;
-		parse_port_range(NULL, optarg, info->dport);
-		info->bitmask |= EBT_IP6_DPORT;
-		break;
-	case IP_ICMP6:
-		if (invert)
-			info->invflags |= EBT_IP6_ICMP6;
-		ebt_parse_icmpv6(optarg, info->icmpv6_type, info->icmpv6_code);
-		info->bitmask |= EBT_IP6_ICMP6;
+
+	/* XXX: overriding afinfo family is dangerous, but
+	 *      required for XTTYPE_HOSTMASK parsing */
+	xtables_set_nfproto(NFPROTO_IPV6);
+	xtables_option_parse(cb);
+	xtables_set_nfproto(NFPROTO_BRIDGE);
+
+	info->bitmask |= 1 << cb->entry->id;
+	info->invflags |= cb->invert ? 1 << cb->entry->id : 0;
+
+	switch (cb->entry->id) {
+	case O_SOURCE:
+		for (i = 0; i < ARRAY_SIZE(cb->val.haddr.all); i++)
+			cb->val.haddr.all[i] &= cb->val.hmask.all[i];
+		info->saddr = cb->val.haddr.in6;
+		info->smsk = cb->val.hmask.in6;
 		break;
-	case IP_TCLASS:
-		if (invert)
-			info->invflags |= EBT_IP6_TCLASS;
-		if (!xtables_strtoui(optarg, &end, &i, 0, 255))
-			xtables_error(PARAMETER_PROBLEM, "Problem with specified IPv6 traffic class '%s'", optarg);
-		info->tclass = i;
-		info->bitmask |= EBT_IP6_TCLASS;
+	case O_DEST:
+		for (i = 0; i < ARRAY_SIZE(cb->val.haddr.all); i++)
+			cb->val.haddr.all[i] &= cb->val.hmask.all[i];
+		info->daddr = cb->val.haddr.in6;
+		info->dmsk = cb->val.hmask.in6;
 		break;
-	case IP_PROTO:
-		if (invert)
-			info->invflags |= EBT_IP6_PROTO;
-		info->protocol = xtables_parse_protocol(optarg);
-		info->bitmask |= EBT_IP6_PROTO;
+	case O_ICMP6:
+		ebt_parse_icmpv6(cb->arg, info->icmpv6_type, info->icmpv6_code);
 		break;
-	default:
-		return 0;
 	}
-
-	*flags |= info->bitmask;
-	return 1;
 }
 
-static void brip6_final_check(unsigned int flags)
+static void brip6_final_check(struct xt_fcheck_call *fc)
 {
-	if (!flags)
+	if (!fc->xflags)
 		xtables_error(PARAMETER_PROBLEM,
 			      "You must specify proper arguments");
 }
@@ -234,31 +173,30 @@ static void brip6_print(const void *ip, const struct xt_entry_match *match,
 	struct ebt_ip6_info *ipinfo = (struct ebt_ip6_info *)match->data;
 
 	if (ipinfo->bitmask & EBT_IP6_SOURCE) {
-		printf("--ip6-src ");
 		if (ipinfo->invflags & EBT_IP6_SOURCE)
 			printf("! ");
+		printf("--ip6-src ");
 		printf("%s", xtables_ip6addr_to_numeric(&ipinfo->saddr));
 		printf("%s ", xtables_ip6mask_to_numeric(&ipinfo->smsk));
 	}
 	if (ipinfo->bitmask & EBT_IP6_DEST) {
-		printf("--ip6-dst ");
 		if (ipinfo->invflags & EBT_IP6_DEST)
 			printf("! ");
+		printf("--ip6-dst ");
 		printf("%s", xtables_ip6addr_to_numeric(&ipinfo->daddr));
 		printf("%s ", xtables_ip6mask_to_numeric(&ipinfo->dmsk));
 	}
 	if (ipinfo->bitmask & EBT_IP6_TCLASS) {
-		printf("--ip6-tclass ");
 		if (ipinfo->invflags & EBT_IP6_TCLASS)
 			printf("! ");
-		printf("0x%02X ", ipinfo->tclass);
+		printf("--ip6-tclass 0x%02X ", ipinfo->tclass);
 	}
 	if (ipinfo->bitmask & EBT_IP6_PROTO) {
 		struct protoent *pe;
 
-		printf("--ip6-proto ");
 		if (ipinfo->invflags & EBT_IP6_PROTO)
 			printf("! ");
+		printf("--ip6-proto ");
 		pe = getprotobynumber(ipinfo->protocol);
 		if (pe == NULL) {
 			printf("%d ", ipinfo->protocol);
@@ -267,21 +205,21 @@ static void brip6_print(const void *ip, const struct xt_entry_match *match,
 		}
 	}
 	if (ipinfo->bitmask & EBT_IP6_SPORT) {
-		printf("--ip6-sport ");
 		if (ipinfo->invflags & EBT_IP6_SPORT)
 			printf("! ");
+		printf("--ip6-sport ");
 		print_port_range(ipinfo->sport);
 	}
 	if (ipinfo->bitmask & EBT_IP6_DPORT) {
-		printf("--ip6-dport ");
 		if (ipinfo->invflags & EBT_IP6_DPORT)
 			printf("! ");
+		printf("--ip6-dport ");
 		print_port_range(ipinfo->dport);
 	}
 	if (ipinfo->bitmask & EBT_IP6_ICMP6) {
-		printf("--ip6-icmp-type ");
 		if (ipinfo->invflags & EBT_IP6_ICMP6)
 			printf("! ");
+		printf("--ip6-icmp-type ");
 		print_icmp_type(ipinfo->icmpv6_type, ipinfo->icmpv6_code);
 	}
 }
@@ -452,13 +390,12 @@ static struct xtables_match brip6_match = {
 	.family		= NFPROTO_BRIDGE,
 	.size		= XT_ALIGN(sizeof(struct ebt_ip6_info)),
 	.userspacesize	= XT_ALIGN(sizeof(struct ebt_ip6_info)),
-	.init		= brip6_init,
 	.help		= brip6_print_help,
-	.parse		= brip6_parse,
-	.final_check	= brip6_final_check,
+	.x6_parse	= brip6_parse,
+	.x6_fcheck	= brip6_final_check,
 	.print		= brip6_print,
 	.xlate		= brip6_xlate,
-	.extra_opts	= brip6_opts,
+	.x6_options	= brip6_opts,
 };
 
 void _init(void)
diff --git a/extensions/libebt_ip6.t b/extensions/libebt_ip6.t
index fa1038af..cb1be9e3 100644
--- a/extensions/libebt_ip6.t
+++ b/extensions/libebt_ip6.t
@@ -1,15 +1,35 @@
 :INPUT,FORWARD,OUTPUT
--p ip6 --ip6-src ! dead::beef/64 -j ACCEPT;-p IPv6 --ip6-src ! dead::/64 -j ACCEPT;OK
+-p ip6 ! --ip6-src dead::beef/64 -j ACCEPT;-p IPv6 ! --ip6-src dead::/64 -j ACCEPT;OK
 -p IPv6 --ip6-dst dead:beef::/64 -j ACCEPT;=;OK
 -p IPv6 --ip6-dst f00:ba::;=;OK
+-p IPv6 ! --ip6-dst f00:ba::;=;OK
+-p IPv6 --ip6-src 10.0.0.1;;FAIL
 -p IPv6 --ip6-tclass 0xFF;=;OK
+-p IPv6 ! --ip6-tclass 0xFF;=;OK
 -p IPv6 --ip6-proto tcp --ip6-dport 22;=;OK
--p IPv6 --ip6-proto tcp --ip6-dport ! 22;=;OK
+-p IPv6 --ip6-proto tcp ! --ip6-dport 22;=;OK
+-p IPv6 --ip6-proto tcp ! --ip6-sport 22 --ip6-dport 22;=;OK
 -p IPv6 --ip6-proto udp --ip6-sport 1024:65535;=;OK
+-p IPv6 --ip6-proto udp --ip6-sport :;-p IPv6 --ip6-proto udp --ip6-sport 0:65535;OK
+-p IPv6 --ip6-proto udp --ip6-sport :4;-p IPv6 --ip6-proto udp --ip6-sport 0:4;OK
+-p IPv6 --ip6-proto udp --ip6-sport 4:;-p IPv6 --ip6-proto udp --ip6-sport 4:65535;OK
+-p IPv6 --ip6-proto udp --ip6-sport 3:4;=;OK
+-p IPv6 --ip6-proto udp --ip6-sport 4:4;-p IPv6 --ip6-proto udp --ip6-sport 4;OK
+-p IPv6 --ip6-proto udp --ip6-sport 4:3;;FAIL
+-p IPv6 --ip6-proto udp --ip6-dport :;-p IPv6 --ip6-proto udp --ip6-dport 0:65535;OK
+-p IPv6 --ip6-proto udp --ip6-dport :4;-p IPv6 --ip6-proto udp --ip6-dport 0:4;OK
+-p IPv6 --ip6-proto udp --ip6-dport 4:;-p IPv6 --ip6-proto udp --ip6-dport 4:65535;OK
+-p IPv6 --ip6-proto udp --ip6-dport 3:4;=;OK
+-p IPv6 --ip6-proto udp --ip6-dport 4:4;-p IPv6 --ip6-proto udp --ip6-dport 4;OK
+-p IPv6 --ip6-proto udp --ip6-dport 4:3;;FAIL
 -p IPv6 --ip6-proto 253;=;OK
+-p IPv6 ! --ip6-proto 253;=;OK
 -p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type echo-request -j CONTINUE;=;OK
 -p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type echo-request;=;OK
+-p IPv6 --ip6-proto ipv6-icmp ! --ip6-icmp-type echo-request;=;OK
 -p ip6 --ip6-protocol icmpv6 --ip6-icmp-type 1/1;-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type communication-prohibited -j CONTINUE;OK
--p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type ! 1:10/0:255;=;OK
+-p IPv6 --ip6-proto ipv6-icmp ! --ip6-icmp-type 1:10/0:255;=;OK
 --ip6-proto ipv6-icmp ! --ip6-icmp-type 1:10/0:255;=;FAIL
 ! -p IPv6 --ip6-proto ipv6-icmp ! --ip6-icmp-type 1:10/0:255;=;FAIL
+-p IPv6 --ip6-proto tcp --ip6-sport 22 --ip6-icmp-type echo-request;;FAIL
+-p IPv6 --ip6-proto tcp --ip6-dport 22 --ip6-icmp-type echo-request;;FAIL
diff --git a/extensions/libebt_ip6.txlate b/extensions/libebt_ip6.txlate
index 0debbe12..13d57e3a 100644
--- a/extensions/libebt_ip6.txlate
+++ b/extensions/libebt_ip6.txlate
@@ -25,5 +25,5 @@ nft 'add rule bridge filter FORWARD icmpv6 type 128 counter'
 ebtables-translate -A FORWARD -p ip6 --ip6-protocol icmpv6  --ip6-icmp-type 1/1
 nft 'add rule bridge filter FORWARD icmpv6 type 1 icmpv6 code 1 counter'
 
-ebtables-translate -A FORWARD -p ip6 --ip6-protocol icmpv6 --ip6-icmp-type ! 1:10
+ebtables-translate -A FORWARD -p ip6 --ip6-protocol icmpv6 ! --ip6-icmp-type 1:10
 nft 'add rule bridge filter FORWARD icmpv6 type != 1-10 counter'
diff --git a/extensions/libebt_log.c b/extensions/libebt_log.c
index 9f8d1589..dc2357c0 100644
--- a/extensions/libebt_log.c
+++ b/extensions/libebt_log.c
@@ -14,19 +14,11 @@
 #include <stdlib.h>
 #include <syslog.h>
 #include <string.h>
-#include <getopt.h>
 #include <xtables.h>
 #include <linux/netfilter_bridge/ebt_log.h>
 
 #define LOG_DEFAULT_LEVEL LOG_INFO
 
-#define LOG_PREFIX '1'
-#define LOG_LEVEL  '2'
-#define LOG_ARP    '3'
-#define LOG_IP     '4'
-#define LOG_LOG    '5'
-#define LOG_IP6    '6'
-
 struct code {
 	char *c_name;
 	int c_val;
@@ -43,26 +35,26 @@ static struct code eight_priority[] = {
 	{ "debug", LOG_DEBUG }
 };
 
-static int name_to_loglevel(const char *arg)
-{
-	int i;
-
-	for (i = 0; i < 8; i++)
-		if (!strcmp(arg, eight_priority[i].c_name))
-			return eight_priority[i].c_val;
-
-	/* return bad loglevel */
-	return 9;
-}
+enum {
+	/* first three must correspond with bit pos in respective EBT_LOG_* */
+	O_LOG_IP = 0,
+	O_LOG_ARP = 1,
+	O_LOG_IP6 = 3,
+	O_LOG_PREFIX,
+	O_LOG_LEVEL,
+	O_LOG_LOG,
+};
 
-static const struct option brlog_opts[] = {
-	{ .name = "log-prefix",		.has_arg = true,  .val = LOG_PREFIX },
-	{ .name = "log-level",		.has_arg = true,  .val = LOG_LEVEL  },
-	{ .name = "log-arp",		.has_arg = false, .val = LOG_ARP    },
-	{ .name = "log-ip",		.has_arg = false, .val = LOG_IP     },
-	{ .name = "log",		.has_arg = false, .val = LOG_LOG    },
-	{ .name = "log-ip6",		.has_arg = false, .val = LOG_IP6    },
-	XT_GETOPT_TABLEEND,
+static const struct xt_option_entry brlog_opts[] = {
+	{ .name = "log-prefix", .id = O_LOG_PREFIX, .type = XTTYPE_STRING,
+	  .flags = XTOPT_PUT, XTOPT_POINTER(struct ebt_log_info, prefix) },
+	{ .name = "log-level", .id = O_LOG_LEVEL, .type = XTTYPE_SYSLOGLEVEL,
+	  .flags = XTOPT_PUT, XTOPT_POINTER(struct ebt_log_info, loglevel) },
+	{ .name = "log-arp",	.id = O_LOG_ARP,	.type = XTTYPE_NONE },
+	{ .name = "log-ip",	.id = O_LOG_IP,		.type = XTTYPE_NONE },
+	{ .name = "log",	.id = O_LOG_LOG,	.type = XTTYPE_NONE },
+	{ .name = "log-ip6",	.id = O_LOG_IP6,	.type = XTTYPE_NONE },
+	XTOPT_TABLEEND,
 };
 
 static void brlog_help(void)
@@ -87,73 +79,21 @@ static void brlog_init(struct xt_entry_target *t)
 {
 	struct ebt_log_info *loginfo = (struct ebt_log_info *)t->data;
 
-	loginfo->bitmask = 0;
-	loginfo->prefix[0] = '\0';
 	loginfo->loglevel = LOG_NOTICE;
 }
 
-static unsigned int log_chk_inv(int inv, unsigned int bit, const char *suffix)
-{
-	if (inv)
-		xtables_error(PARAMETER_PROBLEM,
-			      "Unexpected `!' after --log%s", suffix);
-	return bit;
-}
-
-static int brlog_parse(int c, char **argv, int invert, unsigned int *flags,
-		       const void *entry, struct xt_entry_target **target)
+static void brlog_parse(struct xt_option_call *cb)
 {
-	struct ebt_log_info *loginfo = (struct ebt_log_info *)(*target)->data;
-	long int i;
-	char *end;
-
-	switch (c) {
-	case LOG_PREFIX:
-		if (invert)
-			xtables_error(PARAMETER_PROBLEM,
-				      "Unexpected `!` after --log-prefix");
-		if (strlen(optarg) > sizeof(loginfo->prefix) - 1)
-			xtables_error(PARAMETER_PROBLEM,
-				      "Prefix too long");
-		if (strchr(optarg, '\"'))
-			xtables_error(PARAMETER_PROBLEM,
-				      "Use of \\\" is not allowed"
-				      " in the prefix");
-		strcpy((char *)loginfo->prefix, (char *)optarg);
+	struct ebt_log_info *loginfo = cb->data;
+
+	xtables_option_parse(cb);
+	switch (cb->entry->id) {
+	case O_LOG_IP:
+	case O_LOG_ARP:
+	case O_LOG_IP6:
+		loginfo->bitmask |= 1 << cb->entry->id;
 		break;
-	case LOG_LEVEL:
-		i = strtol(optarg, &end, 16);
-		if (*end != '\0' || i < 0 || i > 7)
-			loginfo->loglevel = name_to_loglevel(optarg);
-		else
-			loginfo->loglevel = i;
-
-		if (loginfo->loglevel == 9)
-			xtables_error(PARAMETER_PROBLEM,
-				      "Problem with the log-level");
-		break;
-	case LOG_IP:
-		loginfo->bitmask |= log_chk_inv(invert, EBT_LOG_IP, "-ip");
-		break;
-	case LOG_ARP:
-		loginfo->bitmask |= log_chk_inv(invert, EBT_LOG_ARP, "-arp");
-		break;
-	case LOG_LOG:
-		loginfo->bitmask |= log_chk_inv(invert, 0, "");
-		break;
-	case LOG_IP6:
-		loginfo->bitmask |= log_chk_inv(invert, EBT_LOG_IP6, "-ip6");
-		break;
-	default:
-		return 0;
 	}
-
-	*flags |= loginfo->bitmask;
-	return 1;
-}
-
-static void brlog_final_check(unsigned int flags)
-{
 }
 
 static void brlog_print(const void *ip, const struct xt_entry_target *target,
@@ -204,11 +144,10 @@ static struct xtables_target brlog_target = {
 	.userspacesize	= XT_ALIGN(sizeof(struct ebt_log_info)),
 	.init		= brlog_init,
 	.help		= brlog_help,
-	.parse		= brlog_parse,
-	.final_check	= brlog_final_check,
+	.x6_parse	= brlog_parse,
 	.print		= brlog_print,
 	.xlate		= brlog_xlate,
-	.extra_opts	= brlog_opts,
+	.x6_options	= brlog_opts,
 };
 
 void _init(void)
diff --git a/extensions/libebt_mark.c b/extensions/libebt_mark.c
index 40e49618..0dc598fe 100644
--- a/extensions/libebt_mark.c
+++ b/extensions/libebt_mark.c
@@ -12,27 +12,39 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
-#include <getopt.h>
 #include <xtables.h>
 #include <linux/netfilter_bridge/ebt_mark_t.h>
 #include "iptables/nft.h"
 #include "iptables/nft-bridge.h"
 
-#define MARK_TARGET  '1'
-#define MARK_SETMARK '2'
-#define MARK_ORMARK  '3'
-#define MARK_ANDMARK '4'
-#define MARK_XORMARK '5'
-static const struct option brmark_opts[] = {
-	{ .name = "mark-target",.has_arg = true,	.val = MARK_TARGET },
+enum {
+	O_SET_MARK = 0,
+	O_AND_MARK,
+	O_OR_MARK,
+	O_XOR_MARK,
+	O_MARK_TARGET,
+	F_SET_MARK  = 1 << O_SET_MARK,
+	F_AND_MARK  = 1 << O_AND_MARK,
+	F_OR_MARK   = 1 << O_OR_MARK,
+	F_XOR_MARK  = 1 << O_XOR_MARK,
+	F_ANY       = F_SET_MARK | F_AND_MARK | F_OR_MARK | F_XOR_MARK,
+};
+
+static const struct xt_option_entry brmark_opts[] = {
+	{ .name = "mark-target",.id = O_MARK_TARGET, .type = XTTYPE_STRING },
 	/* an oldtime messup, we should have always used the scheme
 	 * <extension-name>-<option> */
-	{ .name = "set-mark",	.has_arg = true,	.val = MARK_SETMARK },
-	{ .name = "mark-set",	.has_arg = true,	.val = MARK_SETMARK },
-	{ .name = "mark-or",	.has_arg = true,	.val = MARK_ORMARK },
-	{ .name = "mark-and",	.has_arg = true,	.val = MARK_ANDMARK },
-	{ .name = "mark-xor",	.has_arg = true,	.val = MARK_XORMARK },
-	XT_GETOPT_TABLEEND,
+	{ .name = "set-mark",	.id = O_SET_MARK, .type = XTTYPE_UINT32,
+	  .excl = F_ANY },
+	{ .name = "mark-set",	.id = O_SET_MARK, .type = XTTYPE_UINT32,
+	  .excl = F_ANY },
+	{ .name = "mark-or",	.id = O_OR_MARK, .type = XTTYPE_UINT32,
+	  .excl = F_ANY },
+	{ .name = "mark-and",	.id = O_AND_MARK, .type = XTTYPE_UINT32,
+	  .excl = F_ANY },
+	{ .name = "mark-xor",	.id = O_XOR_MARK, .type = XTTYPE_UINT32,
+	  .excl = F_ANY },
+	XTOPT_TABLEEND,
 };
 
 static void brmark_print_help(void)
@@ -54,83 +66,39 @@ static void brmark_init(struct xt_entry_target *target)
 	info->mark = 0;
 }
 
-#define OPT_MARK_TARGET   0x01
-#define OPT_MARK_SETMARK  0x02
-#define OPT_MARK_ORMARK   0x04
-#define OPT_MARK_ANDMARK  0x08
-#define OPT_MARK_XORMARK  0x10
-
-static int
-brmark_parse(int c, char **argv, int invert, unsigned int *flags,
-	     const void *entry, struct xt_entry_target **target)
+static void brmark_parse(struct xt_option_call *cb)
 {
-	struct ebt_mark_t_info *info = (struct ebt_mark_t_info *)
-				       (*target)->data;
-	char *end;
-	uint32_t mask;
-
-	switch (c) {
-	case MARK_TARGET:
-		{ unsigned int tmp;
-		EBT_CHECK_OPTION(flags, OPT_MARK_TARGET);
-		if (ebt_fill_target(optarg, &tmp))
+	static const unsigned long target_orval[] = {
+		[O_SET_MARK]	= MARK_SET_VALUE,
+		[O_AND_MARK]	= MARK_AND_VALUE,
+		[O_OR_MARK]	= MARK_OR_VALUE,
+		[O_XOR_MARK]	= MARK_XOR_VALUE,
+	};
+	struct ebt_mark_t_info *info = cb->data;
+	unsigned int tmp;
+
+	xtables_option_parse(cb);
+	switch (cb->entry->id) {
+	case O_MARK_TARGET:
+		if (ebt_fill_target(cb->arg, &tmp))
 			xtables_error(PARAMETER_PROBLEM,
 				      "Illegal --mark-target target");
 		/* the 4 lsb are left to designate the target */
 		info->target = (info->target & ~EBT_VERDICT_BITS) |
 			       (tmp & EBT_VERDICT_BITS);
-		}
-		return 1;
-	case MARK_SETMARK:
-		EBT_CHECK_OPTION(flags, OPT_MARK_SETMARK);
-		mask = (OPT_MARK_ORMARK|OPT_MARK_ANDMARK|OPT_MARK_XORMARK);
-		if (*flags & mask)
-			xtables_error(PARAMETER_PROBLEM,
-				      "--mark-set cannot be used together with"
-				      " specific --mark option");
-		info->target = (info->target & EBT_VERDICT_BITS) |
-			       MARK_SET_VALUE;
-		break;
-	case MARK_ORMARK:
-		EBT_CHECK_OPTION(flags, OPT_MARK_ORMARK);
-		mask = (OPT_MARK_SETMARK|OPT_MARK_ANDMARK|OPT_MARK_XORMARK);
-		if (*flags & mask)
-			xtables_error(PARAMETER_PROBLEM,
-				      "--mark-or cannot be used together with"
-				      " specific --mark option");
-		info->target = (info->target & EBT_VERDICT_BITS) |
-			       MARK_OR_VALUE;
-		break;
-	case MARK_ANDMARK:
-		EBT_CHECK_OPTION(flags, OPT_MARK_ANDMARK);
-		mask = (OPT_MARK_SETMARK|OPT_MARK_ORMARK|OPT_MARK_XORMARK);
-		if (*flags & mask)
-			xtables_error(PARAMETER_PROBLEM,
-				      "--mark-and cannot be used together with"
-				      " specific --mark option");
-		info->target = (info->target & EBT_VERDICT_BITS) |
-			       MARK_AND_VALUE;
-		break;
-	case MARK_XORMARK:
-		EBT_CHECK_OPTION(flags, OPT_MARK_XORMARK);
-		mask = (OPT_MARK_SETMARK|OPT_MARK_ANDMARK|OPT_MARK_ORMARK);
-		if (*flags & mask)
-			xtables_error(PARAMETER_PROBLEM,
-				      "--mark-xor cannot be used together with"
-				      " specific --mark option");
-		info->target = (info->target & EBT_VERDICT_BITS) |
-			       MARK_XOR_VALUE;
+		return;
+	case O_SET_MARK:
+	case O_OR_MARK:
+	case O_AND_MARK:
+	case O_XOR_MARK:
 		break;
 	default:
-		return 0;
+		return;
 	}
 	/* mutual code */
-	info->mark = strtoul(optarg, &end, 0);
-	if (*end != '\0' || end == optarg)
-		xtables_error(PARAMETER_PROBLEM, "Bad MARK value '%s'",
-			      optarg);
-
-	return 1;
+	info->mark = cb->val.u32;
+	info->target = (info->target & EBT_VERDICT_BITS) |
+		       target_orval[cb->entry->id];
 }
 
 static void brmark_print(const void *ip, const struct xt_entry_target *target,
@@ -156,9 +124,9 @@ static void brmark_print(const void *ip, const struct xt_entry_target *target,
 	printf(" --mark-target %s", ebt_target_name(tmp));
 }
 
-static void brmark_final_check(unsigned int flags)
+static void brmark_final_check(struct xt_fcheck_call *fc)
 {
-	if (!flags)
+	if (!fc->xflags)
 		xtables_error(PARAMETER_PROBLEM,
 			      "You must specify some option");
 }
@@ -215,11 +183,11 @@ static struct xtables_target brmark_target = {
 	.userspacesize	= XT_ALIGN(sizeof(struct ebt_mark_t_info)),
 	.help		= brmark_print_help,
 	.init		= brmark_init,
-	.parse		= brmark_parse,
-	.final_check	= brmark_final_check,
+	.x6_parse	= brmark_parse,
+	.x6_fcheck	= brmark_final_check,
 	.print		= brmark_print,
 	.xlate		= brmark_xlate,
-	.extra_opts	= brmark_opts,
+	.x6_options	= brmark_opts,
 };
 
 void _init(void)
diff --git a/extensions/libebt_mark_m.c b/extensions/libebt_mark_m.c
index 2462d0af..8ee17207 100644
--- a/extensions/libebt_mark_m.c
+++ b/extensions/libebt_mark_m.c
@@ -12,73 +12,50 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
-#include <getopt.h>
 #include <xtables.h>
 #include <linux/netfilter_bridge/ebt_mark_m.h>
 
-#define MARK '1'
+enum {
+	O_MARK = 0,
+};
 
-static const struct option brmark_m_opts[] = {
-	{ .name = "mark",	.has_arg = true, .val = MARK },
-	XT_GETOPT_TABLEEND,
+static const struct xt_option_entry brmark_m_opts[] = {
+	{ .name = "mark", .id = O_MARK, .type = XTTYPE_STRING,
+	  .flags = XTOPT_INVERT | XTOPT_MAND },
+	XTOPT_TABLEEND,
 };
 
 static void brmark_m_print_help(void)
 {
 	printf(
 "mark option:\n"
-"--mark    [!] [value][/mask]: Match nfmask value (see man page)\n");
+"[!] --mark    [value][/mask]: Match nfmask value (see man page)\n");
 }
 
-static void brmark_m_init(struct xt_entry_match *match)
+static void brmark_m_parse(struct xt_option_call *cb)
 {
-	struct ebt_mark_m_info *info = (struct ebt_mark_m_info *)match->data;
-
-	info->mark = 0;
-	info->mask = 0;
-	info->invert = 0;
-	info->bitmask = 0;
-}
-
-#define OPT_MARK 0x01
-static int
-brmark_m_parse(int c, char **argv, int invert, unsigned int *flags,
-	       const void *entry, struct xt_entry_match **match)
-{
-	struct ebt_mark_m_info *info = (struct ebt_mark_m_info *)
-				       (*match)->data;
+	struct ebt_mark_m_info *info = cb->data;
 	char *end;
 
-	switch (c) {
-	case MARK:
-		if (invert)
-			info->invert = 1;
-		info->mark = strtoul(optarg, &end, 0);
+	xtables_option_parse(cb);
+
+	switch (cb->entry->id) {
+	case O_MARK:
+		info->invert = cb->invert;
+		info->mark = strtoul(cb->arg, &end, 0);
 		info->bitmask = EBT_MARK_AND;
 		if (*end == '/') {
-			if (end == optarg)
+			if (end == cb->arg)
 				info->bitmask = EBT_MARK_OR;
 			info->mask = strtoul(end+1, &end, 0);
 		} else {
-			info->mask = 0xffffffff;
+			info->mask = UINT32_MAX;
 		}
-		if (*end != '\0' || end == optarg)
+		if (*end != '\0' || end == cb->arg)
 			xtables_error(PARAMETER_PROBLEM, "Bad mark value '%s'",
-				      optarg);
+				      cb->arg);
 		break;
-	default:
-		return 0;
 	}
-
-	*flags |= info->bitmask;
-	return 1;
-}
-
-static void brmark_m_final_check(unsigned int flags)
-{
-	if (!flags)
-		xtables_error(PARAMETER_PROBLEM,
-			      "You must specify proper arguments");
 }
 
 static void brmark_m_print(const void *ip, const struct xt_entry_match *match,
@@ -86,9 +63,9 @@ static void brmark_m_print(const void *ip, const struct xt_entry_match *match,
 {
 	struct ebt_mark_m_info *info = (struct ebt_mark_m_info *)match->data;
 
-	printf("--mark ");
 	if (info->invert)
 		printf("! ");
+	printf("--mark ");
 	if (info->bitmask == EBT_MARK_OR)
 		printf("/0x%lx ", info->mask);
 	else if (info->mask != 0xffffffff)
@@ -111,7 +88,7 @@ static int brmark_m_xlate(struct xt_xlate *xl,
 	if (info->bitmask == EBT_MARK_OR) {
 		xt_xlate_add(xl, "and 0x%x %s0 ", (uint32_t)info->mask,
 			     info->invert ? "" : "!= ");
-	} else if (info->mask != 0xffffffffU) {
+	} else if (info->mask != UINT32_MAX) {
 		xt_xlate_add(xl, "and 0x%x %s0x%x ", (uint32_t)info->mask,
 			   op == XT_OP_EQ ? "" : "!= ", (uint32_t)info->mark);
 	} else {
@@ -128,13 +105,11 @@ static struct xtables_match brmark_m_match = {
 	.family		= NFPROTO_BRIDGE,
 	.size		= XT_ALIGN(sizeof(struct ebt_mark_m_info)),
 	.userspacesize	= XT_ALIGN(sizeof(struct ebt_mark_m_info)),
-	.init		= brmark_m_init,
 	.help		= brmark_m_print_help,
-	.parse		= brmark_m_parse,
-	.final_check	= brmark_m_final_check,
+	.x6_parse	= brmark_m_parse,
 	.print		= brmark_m_print,
 	.xlate		= brmark_m_xlate,
-	.extra_opts	= brmark_m_opts,
+	.x6_options	= brmark_m_opts,
 };
 
 void _init(void)
diff --git a/extensions/libebt_mark_m.t b/extensions/libebt_mark_m.t
index 00035427..4de72bde 100644
--- a/extensions/libebt_mark_m.t
+++ b/extensions/libebt_mark_m.t
@@ -1,6 +1,6 @@
 :INPUT,FORWARD,OUTPUT
 --mark 42;--mark 0x2a;OK
---mark ! 42;--mark ! 0x2a;OK
+! --mark 42;! --mark 0x2a;OK
 --mark 42/0xff;--mark 0x2a/0xff;OK
---mark ! 0x1/0xff;=;OK
+! --mark 0x1/0xff;=;OK
 --mark /0x2;=;OK
diff --git a/extensions/libebt_mark_m.txlate b/extensions/libebt_mark_m.txlate
index 2981a564..9061adbf 100644
--- a/extensions/libebt_mark_m.txlate
+++ b/extensions/libebt_mark_m.txlate
@@ -7,7 +7,7 @@ nft 'add rule bridge filter INPUT meta mark != 0x2a counter'
 ebtables-translate -A INPUT --mark ! 42
 nft 'add rule bridge filter INPUT meta mark != 0x2a counter'
 
-ebtables-translate -A INPUT --mark ! 0x1/0xff
+ebtables-translate -A INPUT ! --mark 0x1/0xff
 nft 'add rule bridge filter INPUT meta mark and 0xff != 0x1 counter'
 
 ebtables-translate -A INPUT --mark /0x02
diff --git a/extensions/libebt_nflog.c b/extensions/libebt_nflog.c
index 762d6d5d..48cd5321 100644
--- a/extensions/libebt_nflog.c
+++ b/extensions/libebt_nflog.c
@@ -16,27 +16,30 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
-#include <getopt.h>
 #include <xtables.h>
 #include "iptables/nft.h"
 #include "iptables/nft-bridge.h"
 #include <linux/netfilter_bridge/ebt_nflog.h>
 
 enum {
-	NFLOG_GROUP	= 0x1,
-	NFLOG_PREFIX	= 0x2,
-	NFLOG_RANGE	= 0x4,
-	NFLOG_THRESHOLD	= 0x8,
-	NFLOG_NFLOG	= 0x16,
+	O_GROUP	= 0,
+	O_PREFIX,
+	O_RANGE,
+	O_THRESHOLD,
+	O_NFLOG,
 };
 
-static const struct option brnflog_opts[] = {
-	{ .name = "nflog-group",     .has_arg = true,  .val = NFLOG_GROUP},
-	{ .name = "nflog-prefix",    .has_arg = true,  .val = NFLOG_PREFIX},
-	{ .name = "nflog-range",     .has_arg = true,  .val = NFLOG_RANGE},
-	{ .name = "nflog-threshold", .has_arg = true,  .val = NFLOG_THRESHOLD},
-	{ .name = "nflog",           .has_arg = false, .val = NFLOG_NFLOG},
-	XT_GETOPT_TABLEEND,
+static const struct xt_option_entry brnflog_opts[] = {
+	{ .name = "nflog-group",     .id = O_GROUP, .type = XTTYPE_UINT16,
+	  .flags = XTOPT_PUT, XTOPT_POINTER(struct ebt_nflog_info, group) },
+	{ .name = "nflog-prefix",    .id = O_PREFIX, .type = XTTYPE_STRING,
+	  .flags = XTOPT_PUT, XTOPT_POINTER(struct ebt_nflog_info, prefix) },
+	{ .name = "nflog-range",     .id = O_RANGE, .type = XTTYPE_UINT32,
+	  .flags = XTOPT_PUT, XTOPT_POINTER(struct ebt_nflog_info, len) },
+	{ .name = "nflog-threshold", .id = O_THRESHOLD, .type = XTTYPE_UINT16,
+	  .flags = XTOPT_PUT, XTOPT_POINTER(struct ebt_nflog_info, threshold) },
+	{ .name = "nflog",           .id = O_NFLOG, .type = XTTYPE_NONE },
+	XTOPT_TABLEEND,
 };
 
 static void brnflog_help(void)
@@ -59,55 +62,6 @@ static void brnflog_init(struct xt_entry_target *t)
 	info->threshold = EBT_NFLOG_DEFAULT_THRESHOLD;
 }
 
-static int brnflog_parse(int c, char **argv, int invert, unsigned int *flags,
-			 const void *entry, struct xt_entry_target **target)
-{
-	struct ebt_nflog_info *info = (struct ebt_nflog_info *)(*target)->data;
-	unsigned int i;
-
-	if (invert)
-		xtables_error(PARAMETER_PROBLEM,
-			      "The use of '!' makes no sense for the"
-			      " nflog watcher");
-
-	switch (c) {
-	case NFLOG_PREFIX:
-		EBT_CHECK_OPTION(flags, NFLOG_PREFIX);
-		if (strlen(optarg) > EBT_NFLOG_PREFIX_SIZE - 1)
-			xtables_error(PARAMETER_PROBLEM,
-				      "Prefix too long for nflog-prefix");
-		strncpy(info->prefix, optarg, EBT_NFLOG_PREFIX_SIZE);
-		break;
-	case NFLOG_GROUP:
-		EBT_CHECK_OPTION(flags, NFLOG_GROUP);
-		if (!xtables_strtoui(optarg, NULL, &i, 1, UINT32_MAX))
-			xtables_error(PARAMETER_PROBLEM,
-				      "--nflog-group must be a number!");
-		info->group = i;
-		break;
-	case NFLOG_RANGE:
-		EBT_CHECK_OPTION(flags, NFLOG_RANGE);
-		if (!xtables_strtoui(optarg, NULL, &i, 1, UINT32_MAX))
-			xtables_error(PARAMETER_PROBLEM,
-				      "--nflog-range must be a number!");
-		info->len = i;
-		break;
-	case NFLOG_THRESHOLD:
-		EBT_CHECK_OPTION(flags, NFLOG_THRESHOLD);
-		if (!xtables_strtoui(optarg, NULL, &i, 1, UINT32_MAX))
-			xtables_error(PARAMETER_PROBLEM,
-				      "--nflog-threshold must be a number!");
-		info->threshold = i;
-		break;
-	case NFLOG_NFLOG:
-		EBT_CHECK_OPTION(flags, NFLOG_NFLOG);
-		break;
-	default:
-		return 0;
-	}
-	return 1;
-}
-
 static void
 brnflog_print(const void *ip, const struct xt_entry_target *target,
 	      int numeric)
@@ -153,10 +107,10 @@ static struct xtables_target brnflog_watcher = {
 	.userspacesize	= XT_ALIGN(sizeof(struct ebt_nflog_info)),
 	.init		= brnflog_init,
 	.help		= brnflog_help,
-	.parse		= brnflog_parse,
+	.x6_parse	= xtables_option_parse,
 	.print		= brnflog_print,
 	.xlate		= brnflog_xlate,
-	.extra_opts	= brnflog_opts,
+	.x6_options	= brnflog_opts,
 };
 
 void _init(void)
diff --git a/extensions/libebt_pkttype.c b/extensions/libebt_pkttype.c
index 4e2d19de..579e8fdb 100644
--- a/extensions/libebt_pkttype.c
+++ b/extensions/libebt_pkttype.c
@@ -9,7 +9,6 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
-#include <getopt.h>
 #include <netdb.h>
 #include <xtables.h>
 #include <linux/if_packet.h>
@@ -25,57 +24,59 @@ static const char *classes[] = {
 	"fastroute",
 };
 
-static const struct option brpkttype_opts[] =
-{
-	{ "pkttype-type"        , required_argument, 0, '1' },
-	{ 0 }
+enum {
+	O_TYPE,
+};
+
+static const struct xt_option_entry brpkttype_opts[] = {
+	{ .name = "pkttype-type", .id = O_TYPE, .type = XTTYPE_STRING,
+	  .flags = XTOPT_INVERT },
+	XTOPT_TABLEEND,
 };
 
 static void brpkttype_print_help(void)
 {
 	printf(
 "pkttype options:\n"
-"--pkttype-type    [!] type: class the packet belongs to\n"
+"[!] --pkttype-type    type: class the packet belongs to\n"
 "Possible values: broadcast, multicast, host, otherhost, or any other byte value (which would be pretty useless).\n");
 }
 
 
-static int brpkttype_parse(int c, char **argv, int invert, unsigned int *flags,
-			   const void *entry, struct xt_entry_match **match)
+static void brpkttype_parse(struct xt_option_call *cb)
 {
-	struct ebt_pkttype_info *ptinfo = (struct ebt_pkttype_info *)(*match)->data;
-	char *end;
+	struct ebt_pkttype_info *ptinfo = cb->data;
 	long int i;
+	char *end;
+
+	xtables_option_parse(cb);
 
-	switch (c) {
-	case '1':
-		if (invert)
-			ptinfo->invert = 1;
-		i = strtol(optarg, &end, 16);
+	switch (cb->entry->id) {
+	case O_TYPE:
+		ptinfo->invert = cb->invert;
+		i = strtol(cb->arg, &end, 16);
 		if (*end != '\0') {
 			for (i = 0; i < ARRAY_SIZE(classes); i++) {
-				if (!strcasecmp(optarg, classes[i]))
+				if (!strcasecmp(cb->arg, classes[i]))
 					break;
 			}
 			if (i >= ARRAY_SIZE(classes))
-				xtables_error(PARAMETER_PROBLEM, "Could not parse class '%s'", optarg);
+				xtables_error(PARAMETER_PROBLEM,
+					      "Could not parse class '%s'",
+					      cb->arg);
 		}
 		if (i < 0 || i > 255)
 			xtables_error(PARAMETER_PROBLEM, "Problem with specified pkttype class");
 		ptinfo->pkt_type = (uint8_t)i;
 		break;
-	default:
-		return 0;
 	}
-	return 1;
 }
 
-
 static void brpkttype_print(const void *ip, const struct xt_entry_match *match, int numeric)
 {
 	struct ebt_pkttype_info *pt = (struct ebt_pkttype_info *)match->data;
 
-	printf("--pkttype-type %s", pt->invert ? "! " : "");
+	printf("%s--pkttype-type ", pt->invert ? "! " : "");
 
 	if (pt->pkt_type < ARRAY_SIZE(classes))
 		printf("%s ", classes[pt->pkt_type]);
@@ -107,10 +108,10 @@ static struct xtables_match brpkttype_match = {
 	.size		= XT_ALIGN(sizeof(struct ebt_pkttype_info)),
 	.userspacesize	= XT_ALIGN(sizeof(struct ebt_pkttype_info)),
 	.help		= brpkttype_print_help,
-	.parse		= brpkttype_parse,
+	.x6_parse	= brpkttype_parse,
 	.print		= brpkttype_print,
 	.xlate		= brpkttype_xlate,
-	.extra_opts	= brpkttype_opts,
+	.x6_options	= brpkttype_opts,
 };
 
 void _init(void)
diff --git a/extensions/libebt_pkttype.t b/extensions/libebt_pkttype.t
index e3b95ded..f3cdc19d 100644
--- a/extensions/libebt_pkttype.t
+++ b/extensions/libebt_pkttype.t
@@ -1,14 +1,14 @@
 :INPUT,FORWARD,OUTPUT
-! --pkttype-type host;--pkttype-type ! host -j CONTINUE;OK
+--pkttype-type ! host;! --pkttype-type host -j CONTINUE;OK
 --pkttype-type host;=;OK
---pkttype-type ! host;=;OK
+! --pkttype-type host;=;OK
 --pkttype-type broadcast;=;OK
---pkttype-type ! broadcast;=;OK
+! --pkttype-type broadcast;=;OK
 --pkttype-type multicast;=;OK
---pkttype-type ! multicast;=;OK
+! --pkttype-type multicast;=;OK
 --pkttype-type otherhost;=;OK
---pkttype-type ! otherhost;=;OK
+! --pkttype-type otherhost;=;OK
 --pkttype-type outgoing;=;OK
---pkttype-type ! outgoing;=;OK
+! --pkttype-type outgoing;=;OK
 --pkttype-type loopback;=;OK
---pkttype-type ! loopback;=;OK
+! --pkttype-type loopback;=;OK
diff --git a/extensions/libebt_redirect.c b/extensions/libebt_redirect.c
index 7821935e..a44dbaec 100644
--- a/extensions/libebt_redirect.c
+++ b/extensions/libebt_redirect.c
@@ -9,17 +9,19 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
-#include <getopt.h>
 #include <xtables.h>
 #include <linux/netfilter_bridge/ebt_redirect.h>
 #include "iptables/nft.h"
 #include "iptables/nft-bridge.h"
 
-#define REDIRECT_TARGET '1'
-static const struct option brredir_opts[] =
+enum {
+	O_TARGET,
+};
+
+static const struct xt_option_entry brredir_opts[] =
 {
-	{ "redirect-target", required_argument, 0, REDIRECT_TARGET },
-	{ 0 }
+	{ .name = "redirect-target", .id = O_TARGET, .type = XTTYPE_STRING },
+	XTOPT_TABLEEND,
 };
 
 static void brredir_print_help(void)
@@ -37,23 +39,15 @@ static void brredir_init(struct xt_entry_target *target)
 	redirectinfo->target = EBT_ACCEPT;
 }
 
-#define OPT_REDIRECT_TARGET  0x01
-static int brredir_parse(int c, char **argv, int invert, unsigned int *flags,
-			 const void *entry, struct xt_entry_target **target)
+static void brredir_parse(struct xt_option_call *cb)
 {
-	struct ebt_redirect_info *redirectinfo =
-	   (struct ebt_redirect_info *)(*target)->data;
-
-	switch (c) {
-	case REDIRECT_TARGET:
-		EBT_CHECK_OPTION(flags, OPT_REDIRECT_TARGET);
-		if (ebt_fill_target(optarg, (unsigned int *)&redirectinfo->target))
-			xtables_error(PARAMETER_PROBLEM, "Illegal --redirect-target target");
-		break;
-	default:
-		return 0;
-	}
-	return 1;
+	struct ebt_redirect_info *redirectinfo = cb->data;
+
+	xtables_option_parse(cb);
+	if (cb->entry->id == O_TARGET &&
+	    ebt_fill_target(cb->arg, (unsigned int *)&redirectinfo->target))
+		xtables_error(PARAMETER_PROBLEM,
+			      "Illegal --redirect-target target");
 }
 
 static void brredir_print(const void *ip, const struct xt_entry_target *target, int numeric)
@@ -97,10 +91,10 @@ static struct xtables_target brredirect_target = {
 	.userspacesize	= XT_ALIGN(sizeof(struct ebt_redirect_info)),
 	.help		= brredir_print_help,
 	.init		= brredir_init,
-	.parse		= brredir_parse,
+	.x6_parse	= brredir_parse,
 	.print		= brredir_print,
 	.xlate		= brredir_xlate,
-	.extra_opts	= brredir_opts,
+	.x6_options	= brredir_opts,
 };
 
 void _init(void)
diff --git a/extensions/libebt_snat.c b/extensions/libebt_snat.c
index c1124bf3..1dc738fa 100644
--- a/extensions/libebt_snat.c
+++ b/extensions/libebt_snat.c
@@ -9,23 +9,27 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
-#include <getopt.h>
 #include <netinet/ether.h>
 #include <xtables.h>
 #include <linux/netfilter_bridge/ebt_nat.h>
 #include "iptables/nft.h"
 #include "iptables/nft-bridge.h"
 
-#define NAT_S '1'
-#define NAT_S_TARGET '2'
-#define NAT_S_ARP '3'
-static const struct option brsnat_opts[] =
+enum {
+	O_SRC,
+	O_TARGET,
+	O_ARP,
+};
+
+static const struct xt_option_entry brsnat_opts[] =
 {
-	{ "to-source"     , required_argument, 0, NAT_S },
-	{ "to-src"        , required_argument, 0, NAT_S },
-	{ "snat-target"   , required_argument, 0, NAT_S_TARGET },
-	{ "snat-arp"      ,       no_argument, 0, NAT_S_ARP },
-	{ 0 }
+	{ .name = "to-source", .id = O_SRC, .type = XTTYPE_ETHERMAC,
+	  .flags = XTOPT_PUT, XTOPT_POINTER(struct ebt_nat_info, mac) },
+	{ .name = "to-src",    .id = O_SRC, .type = XTTYPE_ETHERMAC,
+	  .flags = XTOPT_PUT, XTOPT_POINTER(struct ebt_nat_info, mac) },
+	{ .name = "snat-target", .id = O_TARGET, .type = XTTYPE_STRING },
+	{ .name = "snat-arp", .id = O_ARP, .type = XTTYPE_NONE },
+	XTOPT_TABLEEND,
 };
 
 static void brsnat_print_help(void)
@@ -44,43 +48,29 @@ static void brsnat_init(struct xt_entry_target *target)
 	natinfo->target = EBT_ACCEPT;
 }
 
-#define OPT_SNAT         0x01
-#define OPT_SNAT_TARGET  0x02
-#define OPT_SNAT_ARP     0x04
-static int brsnat_parse(int c, char **argv, int invert, unsigned int *flags,
-			 const void *entry, struct xt_entry_target **target)
+static void brsnat_parse(struct xt_option_call *cb)
 {
-	struct ebt_nat_info *natinfo = (struct ebt_nat_info *)(*target)->data;
-	struct ether_addr *addr;
-
-	switch (c) {
-	case NAT_S:
-		EBT_CHECK_OPTION(flags, OPT_SNAT);
-		if (!(addr = ether_aton(optarg)))
-			xtables_error(PARAMETER_PROBLEM, "Problem with specified --to-source mac");
-		memcpy(natinfo->mac, addr, ETH_ALEN);
-		break;
-	case NAT_S_TARGET:
-		{ unsigned int tmp;
-		EBT_CHECK_OPTION(flags, OPT_SNAT_TARGET);
-		if (ebt_fill_target(optarg, &tmp))
-			xtables_error(PARAMETER_PROBLEM, "Illegal --snat-target target");
-		natinfo->target = (natinfo->target & ~EBT_VERDICT_BITS) | (tmp & EBT_VERDICT_BITS);
-		}
+	struct ebt_nat_info *natinfo = cb->data;
+	unsigned int tmp;
+
+	xtables_option_parse(cb);
+	switch (cb->entry->id) {
+	case O_TARGET:
+		if (ebt_fill_target(cb->arg, &tmp))
+			xtables_error(PARAMETER_PROBLEM,
+				      "Illegal --snat-target target");
+		natinfo->target &= ~EBT_VERDICT_BITS;
+		natinfo->target |= tmp & EBT_VERDICT_BITS;
 		break;
-	case NAT_S_ARP:
-		EBT_CHECK_OPTION(flags, OPT_SNAT_ARP);
+	case O_ARP:
 		natinfo->target ^= NAT_ARP_BIT;
 		break;
-	default:
-		return 0;
 	}
-	return 1;
 }
 
-static void brsnat_final_check(unsigned int flags)
+static void brsnat_final_check(struct xt_fcheck_call *fc)
 {
-	if (!flags)
+	if (!fc->xflags)
 		xtables_error(PARAMETER_PROBLEM,
 			      "You must specify proper arguments");
 }
@@ -133,11 +123,11 @@ static struct xtables_target brsnat_target =
 	.userspacesize	= XT_ALIGN(sizeof(struct ebt_nat_info)),
 	.help		= brsnat_print_help,
 	.init		= brsnat_init,
-	.parse		= brsnat_parse,
-	.final_check	= brsnat_final_check,
+	.x6_parse	= brsnat_parse,
+	.x6_fcheck	= brsnat_final_check,
 	.print		= brsnat_print,
 	.xlate		= brsnat_xlate,
-	.extra_opts	= brsnat_opts,
+	.x6_options	= brsnat_opts,
 };
 
 void _init(void)
diff --git a/extensions/libebt_snat.t b/extensions/libebt_snat.t
index 639b13f3..f5d02340 100644
--- a/extensions/libebt_snat.t
+++ b/extensions/libebt_snat.t
@@ -2,3 +2,5 @@
 *nat
 -o someport -j snat --to-source a:b:c:d:e:f;-o someport -j snat --to-src 0a:0b:0c:0d:0e:0f --snat-target ACCEPT;OK
 -o someport+ -j snat --to-src de:ad:00:be:ee:ff --snat-target CONTINUE;=;OK
+-j snat;;FAIL
+-j snat --to-src de:ad:00:be:ee:ff;-j snat --to-src de:ad:00:be:ee:ff --snat-target ACCEPT;OK
diff --git a/extensions/libebt_standard.t b/extensions/libebt_standard.t
index 370a12f4..4cf1f4cf 100644
--- a/extensions/libebt_standard.t
+++ b/extensions/libebt_standard.t
@@ -6,7 +6,8 @@
 -d de:ad:be:ef:00:00 -j CONTINUE;=;OK
 -d de:ad:be:ef:0:00/ff:ff:ff:ff:0:0 -j DROP;-d de:ad:be:ef:00:00/ff:ff:ff:ff:00:00 -j DROP;OK
 -p ARP -j ACCEPT;=;OK
--p ! ARP -j ACCEPT;=;OK
+! -p ARP -j ACCEPT;=;OK
+-p ! ARP -j ACCEPT;! -p ARP -j ACCEPT;OK
 -p 0 -j ACCEPT;=;FAIL
 -p ! 0 -j ACCEPT;=;FAIL
 :INPUT
@@ -16,8 +17,10 @@
 --logical-out br1;=;FAIL
 -i + -d 00:0f:ee:d0:ba:be;-d 00:0f:ee:d0:ba:be;OK
 -i + -p ip;-p IPv4;OK
+! -i +;=;OK
 --logical-in + -d 00:0f:ee:d0:ba:be;-d 00:0f:ee:d0:ba:be;OK
 --logical-in + -p ip;-p IPv4;OK
+! --logical-in +;=;OK
 :FORWARD
 -i foobar;=;OK
 -o foobar;=;OK
diff --git a/extensions/libebt_stp.c b/extensions/libebt_stp.c
index 41059baa..189e36a5 100644
--- a/extensions/libebt_stp.c
+++ b/extensions/libebt_stp.c
@@ -9,7 +9,6 @@
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
-#include <getopt.h>
 #include <netinet/ether.h>
 #include <linux/netfilter_bridge/ebt_stp.h>
 #include <xtables.h>
@@ -17,35 +16,37 @@
 #include "iptables/nft.h"
 #include "iptables/nft-bridge.h"
 
-#define STP_TYPE	'a'
-#define STP_FLAGS	'b'
-#define STP_ROOTPRIO	'c'
-#define STP_ROOTADDR	'd'
-#define STP_ROOTCOST	'e'
-#define STP_SENDERPRIO	'f'
-#define STP_SENDERADDR	'g'
-#define STP_PORT	'h'
-#define STP_MSGAGE	'i'
-#define STP_MAXAGE	'j'
-#define STP_HELLOTIME	'k'
-#define STP_FWDD	'l'
-#define STP_NUMOPS 12
+/* These must correspond to the bit position in EBT_STP_* defines */
+enum {
+	O_TYPE = 0,
+	O_FLAGS,
+	O_RPRIO,
+	O_RADDR,
+	O_RCOST,
+	O_SPRIO,
+	O_SADDR,
+	O_PORT,
+	O_MSGAGE,
+	O_MAXAGE,
+	O_HTIME,
+	O_FWDD,
+};
 
-static const struct option brstp_opts[] =
-{
-	{ "stp-type"         , required_argument, 0, STP_TYPE},
-	{ "stp-flags"        , required_argument, 0, STP_FLAGS},
-	{ "stp-root-prio"    , required_argument, 0, STP_ROOTPRIO},
-	{ "stp-root-addr"    , required_argument, 0, STP_ROOTADDR},
-	{ "stp-root-cost"    , required_argument, 0, STP_ROOTCOST},
-	{ "stp-sender-prio"  , required_argument, 0, STP_SENDERPRIO},
-	{ "stp-sender-addr"  , required_argument, 0, STP_SENDERADDR},
-	{ "stp-port"         , required_argument, 0, STP_PORT},
-	{ "stp-msg-age"      , required_argument, 0, STP_MSGAGE},
-	{ "stp-max-age"      , required_argument, 0, STP_MAXAGE},
-	{ "stp-hello-time"   , required_argument, 0, STP_HELLOTIME},
-	{ "stp-forward-delay", required_argument, 0, STP_FWDD},
-	{ 0 }
+static const struct xt_option_entry brstp_opts[] = {
+#define ENTRY(n, i, t) { .name = n, .id = i, .type = t, .flags = XTOPT_INVERT }
+	ENTRY("stp-type",          O_TYPE,   XTTYPE_STRING),
+	ENTRY("stp-flags",         O_FLAGS,  XTTYPE_STRING),
+	ENTRY("stp-root-prio",     O_RPRIO,  XTTYPE_UINT16RC),
+	ENTRY("stp-root-addr",     O_RADDR,  XTTYPE_ETHERMACMASK),
+	ENTRY("stp-root-cost",     O_RCOST,  XTTYPE_UINT32RC),
+	ENTRY("stp-sender-prio",   O_SPRIO,  XTTYPE_UINT16RC),
+	ENTRY("stp-sender-addr",   O_SADDR,  XTTYPE_ETHERMACMASK),
+	ENTRY("stp-port",          O_PORT,   XTTYPE_UINT16RC),
+	ENTRY("stp-msg-age",       O_MSGAGE, XTTYPE_UINT16RC),
+	ENTRY("stp-max-age",       O_MAXAGE, XTTYPE_UINT16RC),
+	ENTRY("stp-hello-time",    O_HTIME,  XTTYPE_UINT16RC),
+	ENTRY("stp-forward-delay", O_FWDD,   XTTYPE_UINT16RC),
+	XTOPT_TABLEEND,
 };
 
 #define BPDU_TYPE_CONFIG 0
@@ -62,18 +63,18 @@ static void brstp_print_help(void)
 {
 	printf(
 "stp options:\n"
-"--stp-type type                  : BPDU type\n"
-"--stp-flags flag                 : control flag\n"
-"--stp-root-prio prio[:prio]      : root priority (16-bit) range\n"
-"--stp-root-addr address[/mask]   : MAC address of root\n"
-"--stp-root-cost cost[:cost]      : root cost (32-bit) range\n"
-"--stp-sender-prio prio[:prio]    : sender priority (16-bit) range\n"
-"--stp-sender-addr address[/mask] : MAC address of sender\n"
-"--stp-port port[:port]           : port id (16-bit) range\n"
-"--stp-msg-age age[:age]          : message age timer (16-bit) range\n"
-"--stp-max-age age[:age]          : maximum age timer (16-bit) range\n"
-"--stp-hello-time time[:time]     : hello time timer (16-bit) range\n"
-"--stp-forward-delay delay[:delay]: forward delay timer (16-bit) range\n"
+"[!] --stp-type type                  : BPDU type\n"
+"[!] --stp-flags flag                 : control flag\n"
+"[!] --stp-root-prio prio[:prio]      : root priority (16-bit) range\n"
+"[!] --stp-root-addr address[/mask]   : MAC address of root\n"
+"[!] --stp-root-cost cost[:cost]      : root cost (32-bit) range\n"
+"[!] --stp-sender-prio prio[:prio]    : sender priority (16-bit) range\n"
+"[!] --stp-sender-addr address[/mask] : MAC address of sender\n"
+"[!] --stp-port port[:port]           : port id (16-bit) range\n"
+"[!] --stp-msg-age age[:age]          : message age timer (16-bit) range\n"
+"[!] --stp-max-age age[:age]          : maximum age timer (16-bit) range\n"
+"[!] --stp-hello-time time[:time]     : hello time timer (16-bit) range\n"
+"[!] --stp-forward-delay delay[:delay]: forward delay timer (16-bit) range\n"
 " Recognized BPDU type strings:\n"
 "   \"config\": configuration BPDU (=0)\n"
 "   \"tcn\"   : topology change notification BPDU (=0x80)\n"
@@ -82,67 +83,6 @@ static void brstp_print_help(void)
 "   \"topology-change-ack\": topology change acknowledgement flag (0x80)");
 }
 
-static int parse_range(const char *portstring, void *lower, void *upper,
-   int bits, uint32_t min, uint32_t max)
-{
-	char *buffer;
-	char *cp, *end;
-	uint32_t low_nr, upp_nr;
-	int ret = 0;
-
-	buffer = xtables_strdup(portstring);
-
-	if ((cp = strchr(buffer, ':')) == NULL) {
-		low_nr = strtoul(buffer, &end, 10);
-		if (*end || low_nr < min || low_nr > max) {
-			ret = -1;
-			goto out;
-		}
-		if (bits == 2) {
-			*(uint16_t *)lower =  low_nr;
-			*(uint16_t *)upper =  low_nr;
-		} else {
-			*(uint32_t *)lower =  low_nr;
-			*(uint32_t *)upper =  low_nr;
-		}
-	} else {
-		*cp = '\0';
-		cp++;
-		if (!*buffer)
-			low_nr = min;
-		else {
-			low_nr = strtoul(buffer, &end, 10);
-			if (*end || low_nr < min) {
-				ret = -1;
-				goto out;
-			}
-		}
-		if (!*cp)
-			upp_nr = max;
-		else {
-			upp_nr = strtoul(cp, &end, 10);
-			if (*end || upp_nr > max) {
-				ret = -1;
-				goto out;
-			}
-		}
-		if (upp_nr < low_nr) {
-			ret = -1;
-			goto out;
-		}
-		if (bits == 2) {
-			*(uint16_t *)lower = low_nr;
-			*(uint16_t *)upper = upp_nr;
-		} else {
-			*(uint32_t *)lower = low_nr;
-			*(uint32_t *)upper = upp_nr;
-		}
-	}
-out:
-	free(buffer);
-	return ret;
-}
-
 static void print_range(unsigned int l, unsigned int u)
 {
 	if (l == u)
@@ -151,103 +91,84 @@ static void print_range(unsigned int l, unsigned int u)
 		printf("%u:%u", l, u);
 }
 
-static int
-brstp_parse(int c, char **argv, int invert, unsigned int *flags,
-	    const void *entry, struct xt_entry_match **match)
+static void brstp_parse(struct xt_option_call *cb)
 {
-	struct ebt_stp_info *stpinfo = (struct ebt_stp_info *)(*match)->data;
-	unsigned int flag;
-	long int i;
+	struct ebt_stp_info *stpinfo = cb->data;
 	char *end = NULL;
+	long int i;
+
+	xtables_option_parse(cb);
 
-	if (c < 'a' || c > ('a' + STP_NUMOPS - 1))
-		return 0;
-	flag = 1 << (c - 'a');
-	EBT_CHECK_OPTION(flags, flag);
-	if (invert)
-		stpinfo->invflags |= flag;
-	stpinfo->bitmask |= flag;
-	switch (flag) {
-	case EBT_STP_TYPE:
-		i = strtol(optarg, &end, 0);
+	stpinfo->bitmask |= 1 << cb->entry->id;
+	if (cb->invert)
+		stpinfo->invflags |= 1 << cb->entry->id;
+
+	switch (cb->entry->id) {
+	case O_TYPE:
+		i = strtol(cb->arg, &end, 0);
 		if (i < 0 || i > 255 || *end != '\0') {
-			if (!strcasecmp(optarg, BPDU_TYPE_CONFIG_STRING))
+			if (!strcasecmp(cb->arg, BPDU_TYPE_CONFIG_STRING))
 				stpinfo->type = BPDU_TYPE_CONFIG;
-			else if (!strcasecmp(optarg, BPDU_TYPE_TCN_STRING))
+			else if (!strcasecmp(cb->arg, BPDU_TYPE_TCN_STRING))
 				stpinfo->type = BPDU_TYPE_TCN;
 			else
 				xtables_error(PARAMETER_PROBLEM, "Bad --stp-type argument");
 		} else
 			stpinfo->type = i;
 		break;
-	case EBT_STP_FLAGS:
-		i = strtol(optarg, &end, 0);
+	case O_FLAGS:
+		i = strtol(cb->arg, &end, 0);
 		if (i < 0 || i > 255 || *end != '\0') {
-			if (!strcasecmp(optarg, FLAG_TC_STRING))
+			if (!strcasecmp(cb->arg, FLAG_TC_STRING))
 				stpinfo->config.flags = FLAG_TC;
-			else if (!strcasecmp(optarg, FLAG_TC_ACK_STRING))
+			else if (!strcasecmp(cb->arg, FLAG_TC_ACK_STRING))
 				stpinfo->config.flags = FLAG_TC_ACK;
 			else
 				xtables_error(PARAMETER_PROBLEM, "Bad --stp-flags argument");
 		} else
 			stpinfo->config.flags = i;
 		break;
-	case EBT_STP_ROOTPRIO:
-		if (parse_range(argv[optind-1], &(stpinfo->config.root_priol),
-		    &(stpinfo->config.root_priou), 2, 0, 0xffff))
-			xtables_error(PARAMETER_PROBLEM, "Bad --stp-root-prio range");
+	case O_RADDR:
+		memcpy(stpinfo->config.root_addr, cb->val.ethermac, ETH_ALEN);
+		memcpy(stpinfo->config.root_addrmsk,
+		       cb->val.ethermacmask, ETH_ALEN);
 		break;
-	case EBT_STP_ROOTCOST:
-		if (parse_range(argv[optind-1], &(stpinfo->config.root_costl),
-		    &(stpinfo->config.root_costu), 4, 0, 0xffffffff))
-			xtables_error(PARAMETER_PROBLEM, "Bad --stp-root-cost range");
+	case O_SADDR:
+		memcpy(stpinfo->config.sender_addr, cb->val.ethermac, ETH_ALEN);
+		memcpy(stpinfo->config.sender_addrmsk,
+		       cb->val.ethermacmask, ETH_ALEN);
 		break;
-	case EBT_STP_SENDERPRIO:
-		if (parse_range(argv[optind-1], &(stpinfo->config.sender_priol),
-		    &(stpinfo->config.sender_priou), 2, 0, 0xffff))
-			xtables_error(PARAMETER_PROBLEM, "Bad --stp-sender-prio range");
+
+#define RANGE_ASSIGN(fname, val) {				    \
+		stpinfo->config.fname##l = val[0];			    \
+		stpinfo->config.fname##u = cb->nvals > 1 ? val[1] : val[0]; \
+}
+	case O_RPRIO:
+		RANGE_ASSIGN(root_prio, cb->val.u16_range);
 		break;
-	case EBT_STP_PORT:
-		if (parse_range(argv[optind-1], &(stpinfo->config.portl),
-		    &(stpinfo->config.portu), 2, 0, 0xffff))
-			xtables_error(PARAMETER_PROBLEM, "Bad --stp-port-range");
+	case O_RCOST:
+		RANGE_ASSIGN(root_cost, cb->val.u32_range);
 		break;
-	case EBT_STP_MSGAGE:
-		if (parse_range(argv[optind-1], &(stpinfo->config.msg_agel),
-		    &(stpinfo->config.msg_ageu), 2, 0, 0xffff))
-			xtables_error(PARAMETER_PROBLEM, "Bad --stp-msg-age range");
+	case O_SPRIO:
+		RANGE_ASSIGN(sender_prio, cb->val.u16_range);
 		break;
-	case EBT_STP_MAXAGE:
-		if (parse_range(argv[optind-1], &(stpinfo->config.max_agel),
-		    &(stpinfo->config.max_ageu), 2, 0, 0xffff))
-			xtables_error(PARAMETER_PROBLEM, "Bad --stp-max-age range");
+	case O_PORT:
+		RANGE_ASSIGN(port, cb->val.u16_range);
 		break;
-	case EBT_STP_HELLOTIME:
-		if (parse_range(argv[optind-1], &(stpinfo->config.hello_timel),
-		    &(stpinfo->config.hello_timeu), 2, 0, 0xffff))
-			xtables_error(PARAMETER_PROBLEM, "Bad --stp-hello-time range");
+	case O_MSGAGE:
+		RANGE_ASSIGN(msg_age, cb->val.u16_range);
 		break;
-	case EBT_STP_FWDD:
-		if (parse_range(argv[optind-1], &(stpinfo->config.forward_delayl),
-		    &(stpinfo->config.forward_delayu), 2, 0, 0xffff))
-			xtables_error(PARAMETER_PROBLEM, "Bad --stp-forward-delay range");
+	case O_MAXAGE:
+		RANGE_ASSIGN(max_age, cb->val.u16_range);
 		break;
-	case EBT_STP_ROOTADDR:
-		if (xtables_parse_mac_and_mask(argv[optind-1],
-					       stpinfo->config.root_addr,
-					       stpinfo->config.root_addrmsk))
-			xtables_error(PARAMETER_PROBLEM, "Bad --stp-root-addr address");
+	case O_HTIME:
+		RANGE_ASSIGN(hello_time, cb->val.u16_range);
 		break;
-	case EBT_STP_SENDERADDR:
-		if (xtables_parse_mac_and_mask(argv[optind-1],
-					       stpinfo->config.sender_addr,
-					       stpinfo->config.sender_addrmsk))
-			xtables_error(PARAMETER_PROBLEM, "Bad --stp-sender-addr address");
+	case O_FWDD:
+		RANGE_ASSIGN(forward_delay, cb->val.u16_range);
 		break;
-	default:
-		xtables_error(PARAMETER_PROBLEM, "Unknown stp option");
+#undef RANGE_ASSIGN
 	}
-	return 1;
 }
 
 static void brstp_print(const void *ip, const struct xt_entry_match *match,
@@ -257,11 +178,12 @@ static void brstp_print(const void *ip, const struct xt_entry_match *match,
 	const struct ebt_stp_config_info *c = &(stpinfo->config);
 	int i;
 
-	for (i = 0; i < STP_NUMOPS; i++) {
+	for (i = 0; (1 << i) < EBT_STP_MASK; i++) {
 		if (!(stpinfo->bitmask & (1 << i)))
 			continue;
-		printf("--%s %s", brstp_opts[i].name,
-		       (stpinfo->invflags & (1 << i)) ? "! " : "");
+		printf("%s--%s ",
+		       (stpinfo->invflags & (1 << i)) ? "! " : "",
+		       brstp_opts[i].name);
 		if (EBT_STP_TYPE == (1 << i)) {
 			if (stpinfo->type == BPDU_TYPE_CONFIG)
 				printf("%s", BPDU_TYPE_CONFIG_STRING);
@@ -308,9 +230,9 @@ static struct xtables_match brstp_match = {
 	.family		= NFPROTO_BRIDGE,
 	.size		= sizeof(struct ebt_stp_info),
 	.help		= brstp_print_help,
-	.parse		= brstp_parse,
+	.x6_parse	= brstp_parse,
 	.print		= brstp_print,
-	.extra_opts	= brstp_opts,
+	.x6_options	= brstp_opts
 };
 
 void _init(void)
diff --git a/extensions/libebt_stp.t b/extensions/libebt_stp.t
index 17d6c1c0..f72051ac 100644
--- a/extensions/libebt_stp.t
+++ b/extensions/libebt_stp.t
@@ -1,13 +1,74 @@
 :INPUT,FORWARD,OUTPUT
 --stp-type 1;=;OK
+! --stp-type 1;=;OK
 --stp-flags 0x1;--stp-flags topology-change -j CONTINUE;OK
+! --stp-flags topology-change;=;OK
 --stp-root-prio 1 -j ACCEPT;=;OK
+! --stp-root-prio 1 -j ACCEPT;=;OK
 --stp-root-addr 0d:ea:d0:0b:ee:f0;=;OK
+! --stp-root-addr 0d:ea:d0:0b:ee:f0;=;OK
+--stp-root-addr 0d:ea:d0:00:00:00/ff:ff:ff:00:00:00;=;OK
+! --stp-root-addr 0d:ea:d0:00:00:00/ff:ff:ff:00:00:00;=;OK
 --stp-root-cost 1;=;OK
+! --stp-root-cost 1;=;OK
 --stp-sender-prio 1;=;OK
+! --stp-sender-prio 1;=;OK
 --stp-sender-addr de:ad:be:ef:00:00;=;OK
+! --stp-sender-addr de:ad:be:ef:00:00;=;OK
+--stp-sender-addr de:ad:be:ef:00:00/ff:ff:ff:ff:00:00;=;OK
+! --stp-sender-addr de:ad:be:ef:00:00/ff:ff:ff:ff:00:00;=;OK
 --stp-port 1;=;OK
+! --stp-port 1;=;OK
 --stp-msg-age 1;=;OK
+! --stp-msg-age 1;=;OK
 --stp-max-age 1;=;OK
+! --stp-max-age 1;=;OK
 --stp-hello-time 1;=;OK
+! --stp-hello-time 1;=;OK
 --stp-forward-delay 1;=;OK
+! --stp-forward-delay 1;=;OK
+--stp-root-prio :2;--stp-root-prio 0:2;OK
+--stp-root-prio 2:;--stp-root-prio 2:65535;OK
+--stp-root-prio 1:2;=;OK
+--stp-root-prio 1:1;--stp-root-prio 1;OK
+--stp-root-prio 2:1;;FAIL
+--stp-root-cost :2;--stp-root-cost 0:2;OK
+--stp-root-cost 2:;--stp-root-cost 2:4294967295;OK
+--stp-root-cost 1:2;=;OK
+--stp-root-cost 1:1;--stp-root-cost 1;OK
+--stp-root-cost 2:1;;FAIL
+--stp-sender-prio :2;--stp-sender-prio 0:2;OK
+--stp-sender-prio 2:;--stp-sender-prio 2:65535;OK
+--stp-sender-prio 1:2;=;OK
+--stp-sender-prio 1:1;--stp-sender-prio 1;OK
+--stp-sender-prio 2:1;;FAIL
+--stp-port :;--stp-port 0:65535;OK
+--stp-port :2;--stp-port 0:2;OK
+--stp-port 2:;--stp-port 2:65535;OK
+--stp-port 1:2;=;OK
+--stp-port 1:1;--stp-port 1;OK
+--stp-port 2:1;;FAIL
+--stp-msg-age :;--stp-msg-age 0:65535;OK
+--stp-msg-age :2;--stp-msg-age 0:2;OK
+--stp-msg-age 2:;--stp-msg-age 2:65535;OK
+--stp-msg-age 1:2;=;OK
+--stp-msg-age 1:1;--stp-msg-age 1;OK
+--stp-msg-age 2:1;;FAIL
+--stp-max-age :;--stp-max-age 0:65535;OK
+--stp-max-age :2;--stp-max-age 0:2;OK
+--stp-max-age 2:;--stp-max-age 2:65535;OK
+--stp-max-age 1:2;=;OK
+--stp-max-age 1:1;--stp-max-age 1;OK
+--stp-max-age 2:1;;FAIL
+--stp-hello-time :;--stp-hello-time 0:65535;OK
+--stp-hello-time :2;--stp-hello-time 0:2;OK
+--stp-hello-time 2:;--stp-hello-time 2:65535;OK
+--stp-hello-time 1:2;=;OK
+--stp-hello-time 1:1;--stp-hello-time 1;OK
+--stp-hello-time 2:1;;FAIL
+--stp-forward-delay :;--stp-forward-delay 0:65535;OK
+--stp-forward-delay :2;--stp-forward-delay 0:2;OK
+--stp-forward-delay 2:;--stp-forward-delay 2:65535;OK
+--stp-forward-delay 1:2;=;OK
+--stp-forward-delay 1:1;--stp-forward-delay 1;OK
+--stp-forward-delay 2:1;;FAIL
diff --git a/extensions/libebt_vlan.c b/extensions/libebt_vlan.c
index fa697921..b9f6c519 100644
--- a/extensions/libebt_vlan.c
+++ b/extensions/libebt_vlan.c
@@ -9,7 +9,6 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
-#include <getopt.h>
 #include <ctype.h>
 #include <xtables.h>
 #include <netinet/if_ether.h>
@@ -18,89 +17,56 @@
 #include "iptables/nft.h"
 #include "iptables/nft-bridge.h"
 
-#define NAME_VLAN_ID    "id"
-#define NAME_VLAN_PRIO  "prio"
-#define NAME_VLAN_ENCAP "encap"
-
-#define VLAN_ID    '1'
-#define VLAN_PRIO  '2'
-#define VLAN_ENCAP '3'
-
-static const struct option brvlan_opts[] = {
-	{"vlan-id"   , required_argument, NULL, VLAN_ID},
-	{"vlan-prio" , required_argument, NULL, VLAN_PRIO},
-	{"vlan-encap", required_argument, NULL, VLAN_ENCAP},
-	XT_GETOPT_TABLEEND,
+static const struct xt_option_entry brvlan_opts[] =
+{
+	{ .name = "vlan-id", .id = EBT_VLAN_ID, .type = XTTYPE_UINT16,
+	  .max = 4094, .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_vlan_info, id) },
+	{ .name = "vlan-prio", .id = EBT_VLAN_PRIO, .type = XTTYPE_UINT8,
+	  .max = 7, .flags = XTOPT_INVERT | XTOPT_PUT,
+	  XTOPT_POINTER(struct ebt_vlan_info, prio) },
+	{ .name = "vlan-encap", .id = EBT_VLAN_ENCAP, .type = XTTYPE_STRING,
+	  .flags = XTOPT_INVERT },
+	XTOPT_TABLEEND,
 };
 
-/*
- * option inverse flags definition
- */
-#define OPT_VLAN_ID     0x01
-#define OPT_VLAN_PRIO   0x02
-#define OPT_VLAN_ENCAP  0x04
-#define OPT_VLAN_FLAGS	(OPT_VLAN_ID | OPT_VLAN_PRIO | OPT_VLAN_ENCAP)
-
 static void brvlan_print_help(void)
 {
 	printf(
 "vlan options:\n"
-"--vlan-id [!] id       : vlan-tagged frame identifier, 0,1-4096 (integer)\n"
-"--vlan-prio [!] prio   : Priority-tagged frame's user priority, 0-7 (integer)\n"
-"--vlan-encap [!] encap : Encapsulated frame protocol (hexadecimal or name)\n");
+"[!] --vlan-id id       : vlan-tagged frame identifier, 0,1-4096 (integer)\n"
+"[!] --vlan-prio prio   : Priority-tagged frame's user priority, 0-7 (integer)\n"
+"[!] --vlan-encap encap : Encapsulated frame protocol (hexadecimal or name)\n");
 }
 
-static int
-brvlan_parse(int c, char **argv, int invert, unsigned int *flags,
-	       const void *entry, struct xt_entry_match **match)
+static void brvlan_parse(struct xt_option_call *cb)
 {
-	struct ebt_vlan_info *vlaninfo = (struct ebt_vlan_info *) (*match)->data;
+	struct ebt_vlan_info *vlaninfo = cb->data;
 	struct xt_ethertypeent *ethent;
 	char *end;
-	struct ebt_vlan_info local;
-
-	switch (c) {
-	case VLAN_ID:
-		EBT_CHECK_OPTION(flags, OPT_VLAN_ID);
-		if (invert)
-			vlaninfo->invflags |= EBT_VLAN_ID;
-		local.id = strtoul(optarg, &end, 10);
-		if (local.id > 4094 || *end != '\0')
-			xtables_error(PARAMETER_PROBLEM, "Invalid --vlan-id range ('%s')", optarg);
-		vlaninfo->id = local.id;
-		vlaninfo->bitmask |= EBT_VLAN_ID;
-		break;
-	case VLAN_PRIO:
-		EBT_CHECK_OPTION(flags, OPT_VLAN_PRIO);
-		if (invert)
-			vlaninfo->invflags |= EBT_VLAN_PRIO;
-		local.prio = strtoul(optarg, &end, 10);
-		if (local.prio >= 8 || *end != '\0')
-			xtables_error(PARAMETER_PROBLEM, "Invalid --vlan-prio range ('%s')", optarg);
-		vlaninfo->prio = local.prio;
-		vlaninfo->bitmask |= EBT_VLAN_PRIO;
-		break;
-	case VLAN_ENCAP:
-		EBT_CHECK_OPTION(flags, OPT_VLAN_ENCAP);
-		if (invert)
-			vlaninfo->invflags |= EBT_VLAN_ENCAP;
-		local.encap = strtoul(optarg, &end, 16);
+
+	xtables_option_parse(cb);
+
+	vlaninfo->bitmask |= cb->entry->id;
+	if (cb->invert)
+		vlaninfo->invflags |= cb->entry->id;
+
+	if (cb->entry->id == EBT_VLAN_ENCAP) {
+		vlaninfo->encap = strtoul(cb->arg, &end, 16);
 		if (*end != '\0') {
-			ethent = xtables_getethertypebyname(optarg);
+			ethent = xtables_getethertypebyname(cb->arg);
 			if (ethent == NULL)
-				xtables_error(PARAMETER_PROBLEM, "Unknown --vlan-encap value ('%s')", optarg);
-			local.encap = ethent->e_ethertype;
+				xtables_error(PARAMETER_PROBLEM,
+					      "Unknown --vlan-encap value ('%s')",
+					      cb->arg);
+			vlaninfo->encap = ethent->e_ethertype;
 		}
-		if (local.encap < ETH_ZLEN)
-			xtables_error(PARAMETER_PROBLEM, "Invalid --vlan-encap range ('%s')", optarg);
-		vlaninfo->encap = htons(local.encap);
-		vlaninfo->bitmask |= EBT_VLAN_ENCAP;
-		break;
-	default:
-		return 0;
-
+		if (vlaninfo->encap < ETH_ZLEN)
+			xtables_error(PARAMETER_PROBLEM,
+				      "Invalid --vlan-encap range ('%s')",
+				      cb->arg);
+		vlaninfo->encap = htons(vlaninfo->encap);
 	}
-	return 1;
 }
 
 static void brvlan_print(const void *ip, const struct xt_entry_match *match,
@@ -109,14 +75,19 @@ static void brvlan_print(const void *ip, const struct xt_entry_match *match,
 	struct ebt_vlan_info *vlaninfo = (struct ebt_vlan_info *) match->data;
 
 	if (vlaninfo->bitmask & EBT_VLAN_ID) {
-		printf("--vlan-id %s%d ", (vlaninfo->invflags & EBT_VLAN_ID) ? "! " : "", vlaninfo->id);
+		printf("%s--vlan-id %d ",
+		       (vlaninfo->invflags & EBT_VLAN_ID) ? "! " : "",
+		       vlaninfo->id);
 	}
 	if (vlaninfo->bitmask & EBT_VLAN_PRIO) {
-		printf("--vlan-prio %s%d ", (vlaninfo->invflags & EBT_VLAN_PRIO) ? "! " : "", vlaninfo->prio);
+		printf("%s--vlan-prio %d ",
+		       (vlaninfo->invflags & EBT_VLAN_PRIO) ? "! " : "",
+		       vlaninfo->prio);
 	}
 	if (vlaninfo->bitmask & EBT_VLAN_ENCAP) {
-		printf("--vlan-encap %s", (vlaninfo->invflags & EBT_VLAN_ENCAP) ? "! " : "");
-		printf("%4.4X ", ntohs(vlaninfo->encap));
+		printf("%s--vlan-encap %4.4X ",
+		       (vlaninfo->invflags & EBT_VLAN_ENCAP) ? "! " : "",
+		       ntohs(vlaninfo->encap));
 	}
 }
 
@@ -144,10 +115,10 @@ static struct xtables_match brvlan_match = {
 	.size		= XT_ALIGN(sizeof(struct ebt_vlan_info)),
 	.userspacesize	= XT_ALIGN(sizeof(struct ebt_vlan_info)),
 	.help		= brvlan_print_help,
-	.parse		= brvlan_parse,
+	.x6_parse	= brvlan_parse,
 	.print		= brvlan_print,
 	.xlate		= brvlan_xlate,
-	.extra_opts	= brvlan_opts,
+	.x6_options	= brvlan_opts,
 };
 
 void _init(void)
diff --git a/extensions/libebt_vlan.t b/extensions/libebt_vlan.t
index 3ec05599..e009ad71 100644
--- a/extensions/libebt_vlan.t
+++ b/extensions/libebt_vlan.t
@@ -1,13 +1,13 @@
 :INPUT,FORWARD,OUTPUT
 -p 802_1Q --vlan-id 42;=;OK
--p 802_1Q --vlan-id ! 42;=;OK
+-p 802_1Q ! --vlan-id 42;=;OK
 -p 802_1Q --vlan-prio 1;=;OK
--p 802_1Q --vlan-prio ! 1;=;OK
+-p 802_1Q ! --vlan-prio 1;=;OK
 -p 802_1Q --vlan-encap ip;-p 802_1Q --vlan-encap 0800 -j CONTINUE;OK
 -p 802_1Q --vlan-encap 0800;=;OK
--p 802_1Q --vlan-encap ! 0800;=;OK
--p 802_1Q --vlan-encap IPv6 ! --vlan-id 1;-p 802_1Q --vlan-id ! 1 --vlan-encap 86DD -j CONTINUE;OK
--p 802_1Q --vlan-id ! 1 --vlan-encap 86DD;=;OK
+-p 802_1Q ! --vlan-encap 0800;=;OK
+-p 802_1Q --vlan-encap IPv6 --vlan-id ! 1;-p 802_1Q ! --vlan-id 1 --vlan-encap 86DD -j CONTINUE;OK
+-p 802_1Q ! --vlan-id 1 --vlan-encap 86DD;=;OK
 --vlan-encap ip;=;FAIL
 --vlan-id 2;=;FAIL
 --vlan-prio 1;=;FAIL
diff --git a/extensions/libebt_vlan.txlate b/extensions/libebt_vlan.txlate
index 5d21e3eb..6e12e2d0 100644
--- a/extensions/libebt_vlan.txlate
+++ b/extensions/libebt_vlan.txlate
@@ -1,7 +1,7 @@
 ebtables-translate -A INPUT -p 802_1Q --vlan-id 42
 nft 'add rule bridge filter INPUT vlan id 42 counter'
 
-ebtables-translate -A INPUT -p 802_1Q --vlan-prio ! 1
+ebtables-translate -A INPUT -p 802_1Q ! --vlan-prio 1
 nft 'add rule bridge filter INPUT vlan pcp != 1 counter'
 
 ebtables-translate -A INPUT -p 802_1Q --vlan-encap ip
diff --git a/extensions/libip6t_DNPT.man b/extensions/libip6t_DNPT.man
index 9b060f5b..2c4ae61b 100644
--- a/extensions/libip6t_DNPT.man
+++ b/extensions/libip6t_DNPT.man
@@ -15,11 +15,11 @@ Set destination prefix that you want to use in the translation and length
 .PP
 You have to use the SNPT target to undo the translation. Example:
 .IP
-ip6tables \-t mangle \-I POSTROUTING \-s fd00::/64 \! \-o vboxnet0
+ip6tables \-t mangle \-I POSTROUTING \-s fd00::/64 ! \-o vboxnet0
 \-j SNPT \-\-src-pfx fd00::/64 \-\-dst-pfx 2001:e20:2000:40f::/64
 .IP
 ip6tables \-t mangle \-I PREROUTING \-i wlan0 \-d 2001:e20:2000:40f::/64
-\-j DNPT \-\-src-pfx 2001:e20:2000:40f::/64 \-\-dst-pfx fd00::/64
+\-j DNPT \-\-src-pfx 2001:e20:2000:40f::/64 \-\-dst\-pfx fd00::/64
 .PP
 You may need to enable IPv6 neighbor proxy:
 .IP
diff --git a/extensions/libip6t_REJECT.man b/extensions/libip6t_REJECT.man
index 3c42768e..e68d6f03 100644
--- a/extensions/libip6t_REJECT.man
+++ b/extensions/libip6t_REJECT.man
@@ -44,9 +44,10 @@ response for a packet so classed would then terminate the healthy connection.
 .PP
 So, instead of:
 .PP
--A INPUT ... -j REJECT
+\-A INPUT ... \-j REJECT
 .PP
 do consider using:
 .PP
--A INPUT ... -m conntrack --ctstate INVALID -j DROP
--A INPUT ... -j REJECT
+\-A INPUT ... \-m conntrack \-\-ctstate INVALID \-j DROP
+.br
+\-A INPUT ... \-j REJECT
diff --git a/extensions/libip6t_SNPT.man b/extensions/libip6t_SNPT.man
index 97e0071b..8741c648 100644
--- a/extensions/libip6t_SNPT.man
+++ b/extensions/libip6t_SNPT.man
@@ -15,11 +15,11 @@ Set destination prefix that you want to use in the translation and length
 .PP
 You have to use the DNPT target to undo the translation. Example:
 .IP
-ip6tables \-t mangle \-I POSTROUTING \-s fd00::/64 \! \-o vboxnet0
+ip6tables \-t mangle \-I POSTROUTING \-s fd00::/64 ! \-o vboxnet0
 \-j SNPT \-\-src-pfx fd00::/64 \-\-dst-pfx 2001:e20:2000:40f::/64
 .IP
 ip6tables \-t mangle \-I PREROUTING \-i wlan0 \-d 2001:e20:2000:40f::/64
-\-j DNPT \-\-src-pfx 2001:e20:2000:40f::/64 \-\-dst-pfx fd00::/64
+\-j DNPT \-\-src-pfx 2001:e20:2000:40f::/64 \-\-dst\-pfx fd00::/64
 .PP
 You may need to enable IPv6 neighbor proxy:
 .IP
diff --git a/extensions/libip6t_TEE.t b/extensions/libip6t_TEE.t
new file mode 100644
index 00000000..8e668290
--- /dev/null
+++ b/extensions/libip6t_TEE.t
@@ -0,0 +1,3 @@
+:INPUT,FORWARD,OUTPUT
+-j TEE --gateway 2001:db8::1;=;OK
+-j TEE ! --gateway 2001:db8::1;;FAIL
diff --git a/extensions/libip6t_TPROXY.t b/extensions/libip6t_TPROXY.t
new file mode 100644
index 00000000..5af67542
--- /dev/null
+++ b/extensions/libip6t_TPROXY.t
@@ -0,0 +1,5 @@
+:PREROUTING
+*mangle
+-j TPROXY --on-port 12345 --on-ip 2001:db8::1 --tproxy-mark 0x23/0xff;;FAIL
+-p udp -j TPROXY --on-port 12345 --on-ip 2001:db8::1 --tproxy-mark 0x23/0xff;=;OK
+-p tcp -m tcp --dport 2342 -j TPROXY --on-port 12345 --on-ip 2001:db8::1 --tproxy-mark 0x23/0xff;=;OK
diff --git a/extensions/libip6t_ah.c b/extensions/libip6t_ah.c
index f35982f3..0f95c473 100644
--- a/extensions/libip6t_ah.c
+++ b/extensions/libip6t_ah.c
@@ -58,13 +58,18 @@ static void ah_parse(struct xt_option_call *cb)
 	}
 }
 
+static bool skip_spi_match(uint32_t min, uint32_t max, bool inv)
+{
+	return min == 0 && max == UINT32_MAX && !inv;
+}
+
 static void
 print_spis(const char *name, uint32_t min, uint32_t max,
 	    int invert)
 {
 	const char *inv = invert ? "!" : "";
 
-	if (min != 0 || max != 0xFFFFFFFF || invert) {
+	if (!skip_spi_match(min, max, invert)) {
 		if (min == max)
 			printf("%s:%s%u", name, inv, min);
 		else
@@ -103,11 +108,10 @@ static void ah_print(const void *ip, const struct xt_entry_match *match,
 static void ah_save(const void *ip, const struct xt_entry_match *match)
 {
 	const struct ip6t_ah *ahinfo = (struct ip6t_ah *)match->data;
+	bool inv_spi = ahinfo->invflags & IP6T_AH_INV_SPI;
 
-	if (!(ahinfo->spis[0] == 0
-	    && ahinfo->spis[1] == 0xFFFFFFFF)) {
-		printf("%s --ahspi ",
-			(ahinfo->invflags & IP6T_AH_INV_SPI) ? " !" : "");
+	if (!skip_spi_match(ahinfo->spis[0], ahinfo->spis[1], inv_spi)) {
+		printf("%s --ahspi ", inv_spi ? " !" : "");
 		if (ahinfo->spis[0]
 		    != ahinfo->spis[1])
 			printf("%u:%u",
@@ -132,11 +136,11 @@ static int ah_xlate(struct xt_xlate *xl,
 		    const struct xt_xlate_mt_params *params)
 {
 	const struct ip6t_ah *ahinfo = (struct ip6t_ah *)params->match->data;
+	bool inv_spi = ahinfo->invflags & IP6T_AH_INV_SPI;
 	char *space = "";
 
-	if (!(ahinfo->spis[0] == 0 && ahinfo->spis[1] == 0xFFFFFFFF)) {
-		xt_xlate_add(xl, "ah spi%s ",
-			(ahinfo->invflags & IP6T_AH_INV_SPI) ? " !=" : "");
+	if (!skip_spi_match(ahinfo->spis[0], ahinfo->spis[1], inv_spi)) {
+		xt_xlate_add(xl, "ah spi%s ", inv_spi ? " !=" : "");
 		if (ahinfo->spis[0] != ahinfo->spis[1])
 			xt_xlate_add(xl, "%u-%u", ahinfo->spis[0],
 				     ahinfo->spis[1]);
@@ -158,7 +162,7 @@ static int ah_xlate(struct xt_xlate *xl,
 	}
 
 	if (!space[0]) /* plain '-m ah' */
-		xt_xlate_add(xl, "meta l4proto ah");
+		xt_xlate_add(xl, "exthdr ah exists");
 
 	return 1;
 }
diff --git a/extensions/libip6t_ah.t b/extensions/libip6t_ah.t
index c1898d44..19aa6f55 100644
--- a/extensions/libip6t_ah.t
+++ b/extensions/libip6t_ah.t
@@ -13,3 +13,9 @@
 -m ah --ahspi 0:invalid;;FAIL
 -m ah --ahspi;;FAIL
 -m ah;=;OK
+-m ah --ahspi :;-m ah;OK
+-m ah ! --ahspi :;-m ah ! --ahspi 0:4294967295;OK
+-m ah --ahspi :3;-m ah --ahspi 0:3;OK
+-m ah --ahspi 3:;-m ah --ahspi 3:4294967295;OK
+-m ah --ahspi 3:3;-m ah --ahspi 3;OK
+-m ah --ahspi 4:3;;FAIL
diff --git a/extensions/libip6t_ah.txlate b/extensions/libip6t_ah.txlate
index cc33ac27..32c6b7de 100644
--- a/extensions/libip6t_ah.txlate
+++ b/extensions/libip6t_ah.txlate
@@ -15,3 +15,9 @@ nft 'add rule ip6 filter INPUT ah spi 500 ah hdrlength != 120 counter drop'
 
 ip6tables-translate -A INPUT -m ah --ahspi 500 --ahlen 120 --ahres -j ACCEPT
 nft 'add rule ip6 filter INPUT ah spi 500 ah hdrlength 120 ah reserved 1 counter accept'
+
+ip6tables-translate -A INPUT -m ah --ahspi 0:4294967295
+nft 'add rule ip6 filter INPUT exthdr ah exists counter'
+
+ip6tables-translate -A INPUT -m ah ! --ahspi 0:4294967295
+nft 'add rule ip6 filter INPUT ah spi != 0-4294967295 counter'
diff --git a/extensions/libip6t_connlimit.t b/extensions/libip6t_connlimit.t
new file mode 100644
index 00000000..8b7b3677
--- /dev/null
+++ b/extensions/libip6t_connlimit.t
@@ -0,0 +1,16 @@
+:INPUT,FORWARD,OUTPUT
+-m connlimit --connlimit-upto 0;-m connlimit --connlimit-upto 0 --connlimit-mask 128 --connlimit-saddr;OK
+-m connlimit --connlimit-upto 4294967295 --connlimit-mask 128 --connlimit-saddr;=;OK
+-m connlimit --connlimit-upto 4294967296 --connlimit-mask 128 --connlimit-saddr;;FAIL
+-m connlimit --connlimit-upto -1;;FAIL
+-m connlimit --connlimit-above 0;-m connlimit --connlimit-above 0 --connlimit-mask 128 --connlimit-saddr;OK
+-m connlimit --connlimit-above 4294967295 --connlimit-mask 128 --connlimit-saddr;=;OK
+-m connlimit --connlimit-above 4294967296 --connlimit-mask 128 --connlimit-saddr;;FAIL
+-m connlimit --connlimit-above -1;;FAIL
+-m connlimit --connlimit-upto 1 --conlimit-above 1;;FAIL
+-m connlimit --connlimit-above 10 --connlimit-saddr;-m connlimit --connlimit-above 10 --connlimit-mask 128 --connlimit-saddr;OK
+-m connlimit --connlimit-above 10 --connlimit-daddr;-m connlimit --connlimit-above 10 --connlimit-mask 128 --connlimit-daddr;OK
+-m connlimit --connlimit-above 10 --connlimit-saddr --connlimit-daddr;;FAIL
+-m connlimit --connlimit-above 10 --connlimit-mask 128 --connlimit-saddr;=;OK
+-m connlimit --connlimit-above 10 --connlimit-mask 128 --connlimit-daddr;=;OK
+-m connlimit;;FAIL
diff --git a/extensions/libip6t_conntrack.t b/extensions/libip6t_conntrack.t
new file mode 100644
index 00000000..462d4e61
--- /dev/null
+++ b/extensions/libip6t_conntrack.t
@@ -0,0 +1,5 @@
+:INPUT,FORWARD,OUTPUT
+-m conntrack --ctorigsrc 2001:db8::1;=;OK
+-m conntrack --ctorigdst 2001:db8::1;=;OK
+-m conntrack --ctreplsrc 2001:db8::1;=;OK
+-m conntrack --ctrepldst 2001:db8::1;=;OK
diff --git a/extensions/libip6t_frag.c b/extensions/libip6t_frag.c
index 49c787e7..ed7fe10a 100644
--- a/extensions/libip6t_frag.c
+++ b/extensions/libip6t_frag.c
@@ -89,13 +89,18 @@ static void frag_parse(struct xt_option_call *cb)
 	}
 }
 
+static bool skip_ids_match(uint32_t min, uint32_t max, bool inv)
+{
+	return min == 0 && max == UINT32_MAX && !inv;
+}
+
 static void
 print_ids(const char *name, uint32_t min, uint32_t max,
 	    int invert)
 {
 	const char *inv = invert ? "!" : "";
 
-	if (min != 0 || max != 0xFFFFFFFF || invert) {
+	if (!skip_ids_match(min, max, invert)) {
 		printf("%s", name);
 		if (min == max)
 			printf(":%s%u", inv, min);
@@ -139,11 +144,10 @@ static void frag_print(const void *ip, const struct xt_entry_match *match,
 static void frag_save(const void *ip, const struct xt_entry_match *match)
 {
 	const struct ip6t_frag *fraginfo = (struct ip6t_frag *)match->data;
+	bool inv_ids = fraginfo->invflags & IP6T_FRAG_INV_IDS;
 
-	if (!(fraginfo->ids[0] == 0
-	    && fraginfo->ids[1] == 0xFFFFFFFF)) {
-		printf("%s --fragid ",
-			(fraginfo->invflags & IP6T_FRAG_INV_IDS) ? " !" : "");
+	if (!skip_ids_match(fraginfo->ids[0], fraginfo->ids[1], inv_ids)) {
+		printf("%s --fragid ", inv_ids ? " !" : "");
 		if (fraginfo->ids[0]
 		    != fraginfo->ids[1])
 			printf("%u:%u",
@@ -173,22 +177,27 @@ static void frag_save(const void *ip, const struct xt_entry_match *match)
 		printf(" --fraglast");
 }
 
+#define XLATE_FLAGS (IP6T_FRAG_RES | IP6T_FRAG_FST | \
+		     IP6T_FRAG_MF | IP6T_FRAG_NMF)
+
 static int frag_xlate(struct xt_xlate *xl,
 		      const struct xt_xlate_mt_params *params)
 {
 	const struct ip6t_frag *fraginfo =
 		(struct ip6t_frag *)params->match->data;
+	bool inv_ids = fraginfo->invflags & IP6T_FRAG_INV_IDS;
 
-	if (!(fraginfo->ids[0] == 0 && fraginfo->ids[1] == 0xFFFFFFFF)) {
-		xt_xlate_add(xl, "frag id %s",
-			     (fraginfo->invflags & IP6T_FRAG_INV_IDS) ?
-			     "!= " : "");
+	if (!skip_ids_match(fraginfo->ids[0], fraginfo->ids[1], inv_ids)) {
+		xt_xlate_add(xl, "frag id %s", inv_ids ?  "!= " : "");
 		if (fraginfo->ids[0] != fraginfo->ids[1])
 			xt_xlate_add(xl, "%u-%u", fraginfo->ids[0],
 				     fraginfo->ids[1]);
 		else
 			xt_xlate_add(xl, "%u", fraginfo->ids[0]);
 
+	} else if (!(fraginfo->flags & XLATE_FLAGS)) {
+		xt_xlate_add(xl, "exthdr frag exists");
+		return 1;
 	}
 
 	/* ignore ineffective IP6T_FRAG_LEN bit */
diff --git a/extensions/libip6t_frag.t b/extensions/libip6t_frag.t
index 299fa03f..ea7ac899 100644
--- a/extensions/libip6t_frag.t
+++ b/extensions/libip6t_frag.t
@@ -1,5 +1,11 @@
 :INPUT,FORWARD,OUTPUT
+-m frag --fragid :;-m frag;OK
+-m frag ! --fragid :;-m frag ! --fragid 0:4294967295;OK
+-m frag --fragid :42;-m frag --fragid 0:42;OK
+-m frag --fragid 42:;-m frag --fragid 42:4294967295;OK
 -m frag --fragid 1:42;=;OK
+-m frag --fragid 3:3;-m frag --fragid 3;OK
+-m frag --fragid 4:3;;FAIL
 -m frag --fraglen 42;=;OK
 -m frag --fragres;=;OK
 -m frag --fragfirst;=;OK
diff --git a/extensions/libip6t_frag.txlate b/extensions/libip6t_frag.txlate
index 33fc0631..e250587e 100644
--- a/extensions/libip6t_frag.txlate
+++ b/extensions/libip6t_frag.txlate
@@ -15,3 +15,9 @@ nft 'add rule ip6 filter INPUT frag id 100-200 frag frag-off 0 counter accept'
 
 ip6tables-translate -t filter -A INPUT -m frag --fraglast -j ACCEPT
 nft 'add rule ip6 filter INPUT frag more-fragments 0 counter accept'
+
+ip6tables-translate -t filter -A INPUT -m frag --fragid 0:4294967295
+nft 'add rule ip6 filter INPUT exthdr frag exists counter'
+
+ip6tables-translate -t filter -A INPUT -m frag ! --fragid 0:4294967295
+nft 'add rule ip6 filter INPUT frag id != 0-4294967295 counter'
diff --git a/extensions/libip6t_iprange.t b/extensions/libip6t_iprange.t
new file mode 100644
index 00000000..b98f2c29
--- /dev/null
+++ b/extensions/libip6t_iprange.t
@@ -0,0 +1,10 @@
+:INPUT,FORWARD,OUTPUT
+-m iprange --src-range 2001:db8::1-2001:db8::10;=;OK
+-m iprange ! --src-range 2001:db8::1-2001:db8::10;=;OK
+-m iprange --dst-range 2001:db8::1-2001:db8::10;=;OK
+-m iprange ! --dst-range 2001:db8::1-2001:db8::10;=;OK
+# it shows -A INPUT -m iprange --src-range 2001:db8::1-2001:db8::1, should we support this?
+# ERROR: should fail: ip6tables -A INPUT -m iprange --src-range 2001:db8::1
+# -m iprange --src-range 2001:db8::1;;FAIL
+# ERROR: should fail: ip6tables -A INPUT -m iprange --dst-range 2001:db8::1
+#-m iprange --dst-range 2001:db8::1;;FAIL
diff --git a/extensions/libip6t_ipvs.t b/extensions/libip6t_ipvs.t
new file mode 100644
index 00000000..ff7d9d81
--- /dev/null
+++ b/extensions/libip6t_ipvs.t
@@ -0,0 +1,4 @@
+:INPUT,FORWARD,OUTPUT
+-m ipvs --vaddr 2001:db8::1;=;OK
+-m ipvs ! --vaddr 2001:db8::/64;=;OK
+-m ipvs --vproto 6 --vaddr 2001:db8::/64 --vport 22 --vdir ORIGINAL --vmethod GATE;=;OK
diff --git a/extensions/libip6t_mh.c b/extensions/libip6t_mh.c
index 1410d324..1a1cee83 100644
--- a/extensions/libip6t_mh.c
+++ b/extensions/libip6t_mh.c
@@ -17,6 +17,7 @@
 #include <stdlib.h>
 #include <xtables.h>
 #include <linux/netfilter_ipv6/ip6t_mh.h>
+#include <linux/netfilter_ipv6/ip6_tables.h>
 
 enum {
 	O_MH_TYPE = 0,
@@ -154,11 +155,16 @@ static void print_type(uint8_t type, int numeric)
 		printf("%s", name);
 }
 
+static bool skip_types_match(uint8_t min, uint8_t max, bool inv)
+{
+	return min == 0 && max == UINT8_MAX && !inv;
+}
+
 static void print_types(uint8_t min, uint8_t max, int invert, int numeric)
 {
 	const char *inv = invert ? "!" : "";
 
-	if (min != 0 || max != 0xFF || invert) {
+	if (!skip_types_match(min, max, invert)) {
 		printf(" ");
 		if (min == max) {
 			printf("%s", inv);
@@ -189,11 +195,12 @@ static void mh_print(const void *ip, const struct xt_entry_match *match,
 static void mh_save(const void *ip, const struct xt_entry_match *match)
 {
 	const struct ip6t_mh *mhinfo = (struct ip6t_mh *)match->data;
+	bool inv_type = mhinfo->invflags & IP6T_MH_INV_TYPE;
 
-	if (mhinfo->types[0] == 0 && mhinfo->types[1] == 0xFF)
+	if (skip_types_match(mhinfo->types[0], mhinfo->types[1], inv_type))
 		return;
 
-	if (mhinfo->invflags & IP6T_MH_INV_TYPE)
+	if (inv_type)
 		printf(" !");
 
 	if (mhinfo->types[0] != mhinfo->types[1])
@@ -206,9 +213,12 @@ static int mh_xlate(struct xt_xlate *xl,
 		    const struct xt_xlate_mt_params *params)
 {
 	const struct ip6t_mh *mhinfo = (struct ip6t_mh *)params->match->data;
+	bool inv_type = mhinfo->invflags & IP6T_MH_INV_TYPE;
 
-	if (mhinfo->types[0] == 0 && mhinfo->types[1] == 0xff)
+	if (skip_types_match(mhinfo->types[0], mhinfo->types[1], inv_type)) {
+		xt_xlate_add(xl, "exthdr mh exists");
 		return 1;
+	}
 
 	if (mhinfo->types[0] != mhinfo->types[1])
 		xt_xlate_add(xl, "mh type %s%u-%u",
diff --git a/extensions/libip6t_mh.t b/extensions/libip6t_mh.t
index 6b76d13d..b628e9e3 100644
--- a/extensions/libip6t_mh.t
+++ b/extensions/libip6t_mh.t
@@ -4,3 +4,9 @@
 -p mobility-header -m mh --mh-type 1;=;OK
 -p mobility-header -m mh ! --mh-type 4;=;OK
 -p mobility-header -m mh --mh-type 4:123;=;OK
+-p mobility-header -m mh --mh-type :;-p mobility-header -m mh;OK
+-p mobility-header -m mh ! --mh-type :;-p mobility-header -m mh ! --mh-type 0:255;OK
+-p mobility-header -m mh --mh-type :3;-p mobility-header -m mh --mh-type 0:3;OK
+-p mobility-header -m mh --mh-type 3:;-p mobility-header -m mh --mh-type 3:255;OK
+-p mobility-header -m mh --mh-type 3:3;-p mobility-header -m mh --mh-type 3;OK
+-p mobility-header -m mh --mh-type 4:3;;FAIL
diff --git a/extensions/libip6t_mh.txlate b/extensions/libip6t_mh.txlate
index 4dfaf46a..13b4ba88 100644
--- a/extensions/libip6t_mh.txlate
+++ b/extensions/libip6t_mh.txlate
@@ -1,5 +1,14 @@
 ip6tables-translate -A INPUT -p mh --mh-type 1 -j ACCEPT
-nft 'add rule ip6 filter INPUT meta l4proto mobility-header mh type 1 counter accept'
+nft 'add rule ip6 filter INPUT mh type 1 counter accept'
 
 ip6tables-translate -A INPUT -p mh --mh-type 1:3 -j ACCEPT
-nft 'add rule ip6 filter INPUT meta l4proto mobility-header mh type 1-3 counter accept'
+nft 'add rule ip6 filter INPUT mh type 1-3 counter accept'
+
+ip6tables-translate -A INPUT -p mh --mh-type 0:255 -j ACCEPT
+nft 'add rule ip6 filter INPUT exthdr mh exists counter accept'
+
+ip6tables-translate -A INPUT -m mh --mh-type 0:255 -j ACCEPT
+nft 'add rule ip6 filter INPUT exthdr mh exists counter accept'
+
+ip6tables-translate -A INPUT -p mh ! --mh-type 0:255 -j ACCEPT
+nft 'add rule ip6 filter INPUT mh type != 0-255 counter accept'
diff --git a/extensions/libip6t_policy.t b/extensions/libip6t_policy.t
new file mode 100644
index 00000000..06ed71b5
--- /dev/null
+++ b/extensions/libip6t_policy.t
@@ -0,0 +1,4 @@
+:INPUT,FORWARD
+-m policy --dir in --pol ipsec --strict --reqid 1 --spi 0x1 --proto esp --mode tunnel --tunnel-dst 2001:db8::/32 --tunnel-src 2001:db8::/32 --next --reqid 2;=;OK
+-m policy --dir in --pol ipsec --strict --reqid 1 --spi 0x1 --proto esp --tunnel-dst 2001:db8::/32;;FAIL
+-m policy --dir in --pol ipsec --strict --reqid 1 --spi 0x1 --proto ipcomp --mode tunnel --tunnel-dst 2001:db8::/32 --tunnel-src 2001:db8::/32 --next --reqid 2;=;OK
diff --git a/extensions/libip6t_recent.t b/extensions/libip6t_recent.t
new file mode 100644
index 00000000..55ae8dd5
--- /dev/null
+++ b/extensions/libip6t_recent.t
@@ -0,0 +1,10 @@
+:INPUT,FORWARD,OUTPUT
+-m recent --set;-m recent --set --name DEFAULT --mask ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff --rsource;OK
+-m recent --rcheck --hitcount 8 --name foo --mask ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff --rsource;=;OK
+-m recent --rcheck --hitcount 12 --name foo --mask ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff --rsource;=;OK
+-m recent --update --rttl;-m recent --update --rttl --name DEFAULT --mask ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff --rsource;OK
+-m recent --rcheck --hitcount 65536 --name foo --mask ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff --rsource;;FAIL
+# nonsensical, but all should load successfully:
+-m recent --rcheck --hitcount 3 --name foo --mask ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff --rsource -m recent --rcheck --hitcount 4 --name foo --mask ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff --rsource;=;OK
+-m recent --rcheck --hitcount 4 --name foo --mask ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff --rsource -m recent --rcheck --hitcount 4 --name foo --mask ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff --rsource;=;OK
+-m recent --rcheck --hitcount 8 --name foo --mask ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff --rsource -m recent --rcheck --hitcount 12 --name foo --mask ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff --rsource;=;OK
diff --git a/extensions/libip6t_rt.c b/extensions/libip6t_rt.c
index d5b0458b..6db09f0b 100644
--- a/extensions/libip6t_rt.c
+++ b/extensions/libip6t_rt.c
@@ -152,13 +152,18 @@ static void rt_parse(struct xt_option_call *cb)
 	}
 }
 
+static bool skip_segsleft_match(uint32_t min, uint32_t max, bool inv)
+{
+	return min == 0 && max == UINT32_MAX && !inv;
+}
+
 static void
 print_nums(const char *name, uint32_t min, uint32_t max,
 	    int invert)
 {
 	const char *inv = invert ? "!" : "";
 
-	if (min != 0 || max != 0xFFFFFFFF || invert) {
+	if (!skip_segsleft_match(min, max, invert)) {
 		printf(" %s", name);
 		if (min == max) {
 			printf(":%s", inv);
@@ -210,6 +215,7 @@ static void rt_print(const void *ip, const struct xt_entry_match *match,
 static void rt_save(const void *ip, const struct xt_entry_match *match)
 {
 	const struct ip6t_rt *rtinfo = (struct ip6t_rt *)match->data;
+	bool inv_sgs = rtinfo->invflags & IP6T_RT_INV_SGS;
 
 	if (rtinfo->flags & IP6T_RT_TYP) {
 		printf("%s --rt-type %u",
@@ -217,10 +223,9 @@ static void rt_save(const void *ip, const struct xt_entry_match *match)
 			rtinfo->rt_type);
 	}
 
-	if (!(rtinfo->segsleft[0] == 0
-	    && rtinfo->segsleft[1] == 0xFFFFFFFF)) {
-		printf("%s --rt-segsleft ",
-			(rtinfo->invflags & IP6T_RT_INV_SGS) ? " !" : "");
+	if (!skip_segsleft_match(rtinfo->segsleft[0],
+				 rtinfo->segsleft[1], inv_sgs)) {
+		printf("%s --rt-segsleft ", inv_sgs ? " !" : "");
 		if (rtinfo->segsleft[0]
 		    != rtinfo->segsleft[1])
 			printf("%u:%u",
@@ -244,10 +249,14 @@ static void rt_save(const void *ip, const struct xt_entry_match *match)
 
 }
 
+#define XLATE_FLAGS (IP6T_RT_TYP | IP6T_RT_LEN | \
+		     IP6T_RT_RES | IP6T_RT_FST | IP6T_RT_FST_NSTRICT)
+
 static int rt_xlate(struct xt_xlate *xl,
 		    const struct xt_xlate_mt_params *params)
 {
 	const struct ip6t_rt *rtinfo = (struct ip6t_rt *)params->match->data;
+	bool inv_sgs = rtinfo->invflags & IP6T_RT_INV_SGS;
 
 	if (rtinfo->flags & IP6T_RT_TYP) {
 		xt_xlate_add(xl, "rt type%s %u",
@@ -255,15 +264,18 @@ static int rt_xlate(struct xt_xlate *xl,
 			      rtinfo->rt_type);
 	}
 
-	if (!(rtinfo->segsleft[0] == 0 && rtinfo->segsleft[1] == 0xFFFFFFFF)) {
-		xt_xlate_add(xl, "rt seg-left%s ",
-			     (rtinfo->invflags & IP6T_RT_INV_SGS) ? " !=" : "");
+	if (!skip_segsleft_match(rtinfo->segsleft[0],
+				 rtinfo->segsleft[1], inv_sgs)) {
+		xt_xlate_add(xl, "rt seg-left%s ", inv_sgs ? " !=" : "");
 
 		if (rtinfo->segsleft[0] != rtinfo->segsleft[1])
 			xt_xlate_add(xl, "%u-%u", rtinfo->segsleft[0],
 					rtinfo->segsleft[1]);
 		else
 			xt_xlate_add(xl, "%u", rtinfo->segsleft[0]);
+	} else if (!(rtinfo->flags & XLATE_FLAGS)) {
+		xt_xlate_add(xl, "exthdr rt exists");
+		return 1;
 	}
 
 	if (rtinfo->flags & IP6T_RT_LEN) {
diff --git a/extensions/libip6t_rt.t b/extensions/libip6t_rt.t
index 3c7b2d98..1c219d66 100644
--- a/extensions/libip6t_rt.t
+++ b/extensions/libip6t_rt.t
@@ -3,3 +3,9 @@
 -m rt --rt-type 0 ! --rt-segsleft 1:23 ! --rt-len 42 --rt-0-res;=;OK
 -m rt ! --rt-type 1 ! --rt-segsleft 12:23 ! --rt-len 42;=;OK
 -m rt;=;OK
+-m rt --rt-segsleft :;-m rt;OK
+-m rt ! --rt-segsleft :;-m rt ! --rt-segsleft 0:4294967295;OK
+-m rt --rt-segsleft :3;-m rt --rt-segsleft 0:3;OK
+-m rt --rt-segsleft 3:;-m rt --rt-segsleft 3:4294967295;OK
+-m rt --rt-segsleft 3:3;-m rt --rt-segsleft 3;OK
+-m rt --rt-segsleft 4:3;;FAIL
diff --git a/extensions/libip6t_rt.txlate b/extensions/libip6t_rt.txlate
index 3578bcba..1c2f74a5 100644
--- a/extensions/libip6t_rt.txlate
+++ b/extensions/libip6t_rt.txlate
@@ -12,3 +12,12 @@ nft 'add rule ip6 filter INPUT rt type 0 rt hdrlength 22 counter drop'
 
 ip6tables-translate -A INPUT -m rt --rt-type 0 --rt-len 22 ! --rt-segsleft 26 -j ACCEPT
 nft 'add rule ip6 filter INPUT rt type 0 rt seg-left != 26 rt hdrlength 22 counter accept'
+
+ip6tables-translate -A INPUT -m rt --rt-segsleft 13:42 -j ACCEPT
+nft 'add rule ip6 filter INPUT rt seg-left 13-42 counter accept'
+
+ip6tables-translate -A INPUT -m rt --rt-segsleft 0:4294967295 -j ACCEPT
+nft 'add rule ip6 filter INPUT exthdr rt exists counter accept'
+
+ip6tables-translate -A INPUT -m rt ! --rt-segsleft 0:4294967295 -j ACCEPT
+nft 'add rule ip6 filter INPUT rt seg-left != 0-4294967295 counter accept'
diff --git a/extensions/libipt_REJECT.man b/extensions/libipt_REJECT.man
index cc47aead..a7196cdc 100644
--- a/extensions/libipt_REJECT.man
+++ b/extensions/libipt_REJECT.man
@@ -44,9 +44,10 @@ response for a packet so classed would then terminate the healthy connection.
 .PP
 So, instead of:
 .PP
--A INPUT ... -j REJECT
+\-A INPUT ... \-j REJECT
 .PP
 do consider using:
 .PP
--A INPUT ... -m conntrack --ctstate INVALID -j DROP
--A INPUT ... -j REJECT
+\-A INPUT ... \-m conntrack \-\-ctstate INVALID \-j DROP
+.br
+\-A INPUT ... \-j REJECT
diff --git a/extensions/libipt_TEE.t b/extensions/libipt_TEE.t
new file mode 100644
index 00000000..23dceada
--- /dev/null
+++ b/extensions/libipt_TEE.t
@@ -0,0 +1,3 @@
+:INPUT,FORWARD,OUTPUT
+-j TEE --gateway 1.1.1.1;=;OK
+-j TEE ! --gateway 1.1.1.1;;FAIL
diff --git a/extensions/libxt_TPROXY.t b/extensions/libipt_TPROXY.t
similarity index 100%
rename from extensions/libxt_TPROXY.t
rename to extensions/libipt_TPROXY.t
diff --git a/extensions/libipt_ULOG.man b/extensions/libipt_ULOG.man
index c91f7764..eb37d4fb 100644
--- a/extensions/libipt_ULOG.man
+++ b/extensions/libipt_ULOG.man
@@ -1,4 +1,4 @@
-This is the deprecated ipv4-only predecessor of the NFLOG target.
+This is the deprecated IPv4-only predecessor of the NFLOG target.
 It provides userspace logging of matching packets.  When this
 target is set for a rule, the Linux kernel will multicast this packet
 through a
@@ -9,7 +9,7 @@ Like LOG, this is a "non-terminating target", i.e. rule traversal
 continues at the next rule.
 .TP
 \fB\-\-ulog\-nlgroup\fP \fInlgroup\fP
-This specifies the netlink group (1-32) to which the packet is sent.
+This specifies the netlink group (1\(en32) to which the packet is sent.
 Default value is 1.
 .TP
 \fB\-\-ulog\-prefix\fP \fIprefix\fP
diff --git a/extensions/libipt_ah.c b/extensions/libipt_ah.c
index fec5705c..39e3013d 100644
--- a/extensions/libipt_ah.c
+++ b/extensions/libipt_ah.c
@@ -39,13 +39,18 @@ static void ah_parse(struct xt_option_call *cb)
 		ahinfo->invflags |= IPT_AH_INV_SPI;
 }
 
+static bool skip_spi_match(uint32_t min, uint32_t max, bool inv)
+{
+	return min == 0 && max == UINT32_MAX && !inv;
+}
+
 static void
 print_spis(const char *name, uint32_t min, uint32_t max,
 	    int invert)
 {
 	const char *inv = invert ? "!" : "";
 
-	if (min != 0 || max != 0xFFFFFFFF || invert) {
+	if (!skip_spi_match(min, max, invert)) {
 		printf("%s", name);
 		if (min == max) {
 			printf(":%s", inv);
@@ -75,11 +80,10 @@ static void ah_print(const void *ip, const struct xt_entry_match *match,
 static void ah_save(const void *ip, const struct xt_entry_match *match)
 {
 	const struct ipt_ah *ahinfo = (struct ipt_ah *)match->data;
+	bool inv_spi = ahinfo->invflags & IPT_AH_INV_SPI;
 
-	if (!(ahinfo->spis[0] == 0
-	    && ahinfo->spis[1] == 0xFFFFFFFF)) {
-		printf("%s --ahspi ",
-			(ahinfo->invflags & IPT_AH_INV_SPI) ? " !" : "");
+	if (!skip_spi_match(ahinfo->spis[0], ahinfo->spis[1], inv_spi)) {
+		printf("%s --ahspi ", inv_spi ? " !" : "");
 		if (ahinfo->spis[0]
 		    != ahinfo->spis[1])
 			printf("%u:%u",
@@ -96,15 +100,17 @@ static int ah_xlate(struct xt_xlate *xl,
 		    const struct xt_xlate_mt_params *params)
 {
 	const struct ipt_ah *ahinfo = (struct ipt_ah *)params->match->data;
+	bool inv_spi = ahinfo->invflags & IPT_AH_INV_SPI;
 
-	if (!(ahinfo->spis[0] == 0 && ahinfo->spis[1] == 0xFFFFFFFF)) {
-		xt_xlate_add(xl, "ah spi%s ",
-			   (ahinfo->invflags & IPT_AH_INV_SPI) ? " !=" : "");
+	if (!skip_spi_match(ahinfo->spis[0], ahinfo->spis[1], inv_spi)) {
+		xt_xlate_add(xl, "ah spi%s ", inv_spi ? " !=" : "");
 		if (ahinfo->spis[0] != ahinfo->spis[1])
 			xt_xlate_add(xl, "%u-%u", ahinfo->spis[0],
 				   ahinfo->spis[1]);
 		else
 			xt_xlate_add(xl, "%u", ahinfo->spis[0]);
+	} else {
+		xt_xlate_add(xl, "meta l4proto ah");
 	}
 
 	return 1;
diff --git a/extensions/libipt_ah.t b/extensions/libipt_ah.t
index cd853865..60593660 100644
--- a/extensions/libipt_ah.t
+++ b/extensions/libipt_ah.t
@@ -11,3 +11,9 @@
 -m ah --ahspi;;FAIL
 -m ah;;FAIL
 -p ah -m ah;=;OK
+-p ah -m ah --ahspi :;-p ah -m ah;OK
+-p ah -m ah ! --ahspi :;-p ah -m ah ! --ahspi 0:4294967295;OK
+-p ah -m ah --ahspi :3;-p ah -m ah --ahspi 0:3;OK
+-p ah -m ah --ahspi 3:;-p ah -m ah --ahspi 3:4294967295;OK
+-p ah -m ah --ahspi 3:3;-p ah -m ah --ahspi 3;OK
+-p ah -m ah --ahspi 4:3;;FAIL
diff --git a/extensions/libipt_ah.txlate b/extensions/libipt_ah.txlate
index 897c82b5..baf5a0ae 100644
--- a/extensions/libipt_ah.txlate
+++ b/extensions/libipt_ah.txlate
@@ -6,3 +6,9 @@ nft 'add rule ip filter INPUT ah spi 500-600 counter drop'
 
 iptables-translate -A INPUT -p 51 -m ah ! --ahspi 50 -j DROP
 nft 'add rule ip filter INPUT ah spi != 50 counter drop'
+
+iptables-translate -A INPUT -p 51 -m ah --ahspi 0:4294967295 -j DROP
+nft 'add rule ip filter INPUT meta l4proto ah counter drop'
+
+iptables-translate -A INPUT -p 51 -m ah ! --ahspi 0:4294967295 -j DROP
+nft 'add rule ip filter INPUT ah spi != 0-4294967295 counter drop'
diff --git a/extensions/libipt_connlimit.t b/extensions/libipt_connlimit.t
new file mode 100644
index 00000000..245a4784
--- /dev/null
+++ b/extensions/libipt_connlimit.t
@@ -0,0 +1,11 @@
+:INPUT,FORWARD,OUTPUT
+-m connlimit --connlimit-upto 0;-m connlimit --connlimit-upto 0 --connlimit-mask 32 --connlimit-saddr;OK
+-m connlimit --connlimit-upto 4294967295 --connlimit-mask 32 --connlimit-saddr;=;OK
+-m connlimit --connlimit-upto 4294967296 --connlimit-mask 32 --connlimit-saddr;;FAIL
+-m connlimit --connlimit-above 0;-m connlimit --connlimit-above 0 --connlimit-mask 32 --connlimit-saddr;OK
+-m connlimit --connlimit-above 4294967295 --connlimit-mask 32 --connlimit-saddr;=;OK
+-m connlimit --connlimit-above 4294967296 --connlimit-mask 32 --connlimit-saddr;;FAIL
+-m connlimit --connlimit-above 10 --connlimit-saddr;-m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-saddr;OK
+-m connlimit --connlimit-above 10 --connlimit-daddr;-m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-daddr;OK
+-m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-saddr;=;OK
+-m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-daddr;=;OK
diff --git a/extensions/libipt_conntrack.t b/extensions/libipt_conntrack.t
new file mode 100644
index 00000000..d70ab71f
--- /dev/null
+++ b/extensions/libipt_conntrack.t
@@ -0,0 +1,5 @@
+:INPUT,FORWARD,OUTPUT
+-m conntrack --ctorigsrc 1.1.1.1;=;OK
+-m conntrack --ctorigdst 1.1.1.1;=;OK
+-m conntrack --ctreplsrc 1.1.1.1;=;OK
+-m conntrack --ctrepldst 1.1.1.1;=;OK
diff --git a/extensions/libipt_iprange.t b/extensions/libipt_iprange.t
new file mode 100644
index 00000000..8b443417
--- /dev/null
+++ b/extensions/libipt_iprange.t
@@ -0,0 +1,10 @@
+:INPUT,FORWARD,OUTPUT
+-m iprange --src-range 1.1.1.1-1.1.1.10;=;OK
+-m iprange ! --src-range 1.1.1.1-1.1.1.10;=;OK
+-m iprange --dst-range 1.1.1.1-1.1.1.10;=;OK
+-m iprange ! --dst-range 1.1.1.1-1.1.1.10;=;OK
+# it shows -A INPUT -m iprange --src-range 1.1.1.1-1.1.1.1, should we support this?
+# ERROR: should fail: iptables -A INPUT -m iprange --src-range 1.1.1.1
+# -m iprange --src-range 1.1.1.1;;FAIL
+# ERROR: should fail: iptables -A INPUT -m iprange --dst-range 1.1.1.1
+#-m iprange --dst-range 1.1.1.1;;FAIL
diff --git a/extensions/libipt_ipvs.t b/extensions/libipt_ipvs.t
new file mode 100644
index 00000000..bb23ccf2
--- /dev/null
+++ b/extensions/libipt_ipvs.t
@@ -0,0 +1,4 @@
+:INPUT,FORWARD,OUTPUT
+-m ipvs --vaddr 1.2.3.4;=;OK
+-m ipvs ! --vaddr 1.2.3.4/255.255.255.0;-m ipvs ! --vaddr 1.2.3.4/24;OK
+-m ipvs --vproto 6 --vaddr 1.2.3.4/16 --vport 22 --vdir ORIGINAL --vmethod GATE;=;OK
diff --git a/extensions/libxt_osf.t b/extensions/libipt_osf.t
similarity index 100%
rename from extensions/libxt_osf.t
rename to extensions/libipt_osf.t
diff --git a/extensions/libipt_policy.t b/extensions/libipt_policy.t
new file mode 100644
index 00000000..1fa3dcfd
--- /dev/null
+++ b/extensions/libipt_policy.t
@@ -0,0 +1,4 @@
+:INPUT,FORWARD
+-m policy --dir in --pol ipsec --strict --reqid 1 --spi 0x1 --proto esp --mode tunnel --tunnel-dst 10.0.0.0/8 --tunnel-src 10.0.0.0/8 --next --reqid 2;=;OK
+-m policy --dir in --pol ipsec --strict --reqid 1 --spi 0x1 --proto esp --tunnel-dst 10.0.0.0/8;;FAIL
+-m policy --dir in --pol ipsec --strict --reqid 1 --spi 0x1 --proto ipcomp --mode tunnel --tunnel-dst 10.0.0.0/8 --tunnel-src 10.0.0.0/8 --next --reqid 2;=;OK
diff --git a/extensions/libipt_recent.t b/extensions/libipt_recent.t
new file mode 100644
index 00000000..764a415d
--- /dev/null
+++ b/extensions/libipt_recent.t
@@ -0,0 +1,10 @@
+:INPUT,FORWARD,OUTPUT
+-m recent --set;-m recent --set --name DEFAULT --mask 255.255.255.255 --rsource;OK
+-m recent --rcheck --hitcount 8 --name foo --mask 255.255.255.255 --rsource;=;OK
+-m recent --rcheck --hitcount 12 --name foo --mask 255.255.255.255 --rsource;=;OK
+-m recent --update --rttl;-m recent --update --rttl --name DEFAULT --mask 255.255.255.255 --rsource;OK
+-m recent --rcheck --hitcount 65536 --name foo --mask 255.255.255.255 --rsource;;FAIL
+# nonsensical, but all should load successfully:
+-m recent --rcheck --hitcount 3 --name foo --mask 255.255.255.255 --rsource -m recent --rcheck --hitcount 4 --name foo --mask 255.255.255.255 --rsource;=;OK
+-m recent --rcheck --hitcount 4 --name foo --mask 255.255.255.255 --rsource -m recent --rcheck --hitcount 4 --name foo --mask 255.255.255.255 --rsource;=;OK
+-m recent --rcheck --hitcount 8 --name foo --mask 255.255.255.255 --rsource -m recent --rcheck --hitcount 12 --name foo --mask 255.255.255.255 --rsource;=;OK
diff --git a/extensions/libipt_standard.t b/extensions/libipt_standard.t
new file mode 100644
index 00000000..4eb144d1
--- /dev/null
+++ b/extensions/libipt_standard.t
@@ -0,0 +1,21 @@
+:INPUT,FORWARD,OUTPUT
+-s 127.0.0.1/32 -d 0.0.0.0/8 -j DROP;=;OK
+! -s 0.0.0.0 -j ACCEPT;! -s 0.0.0.0/32 -j ACCEPT;OK
+! -d 0.0.0.0/32 -j ACCEPT;=;OK
+-s 0.0.0.0/24 -j RETURN;=;OK
+-s 10.11.12.13/8;-s 10.0.0.0/8;OK
+-s 10.11.12.13/9;-s 10.0.0.0/9;OK
+-s 10.11.12.13/10;-s 10.0.0.0/10;OK
+-s 10.11.12.13/11;-s 10.0.0.0/11;OK
+-s 10.11.12.13/12;-s 10.0.0.0/12;OK
+-s 10.11.12.13/30;-s 10.11.12.12/30;OK
+-s 10.11.12.13/31;-s 10.11.12.12/31;OK
+-s 10.11.12.13/32;-s 10.11.12.13/32;OK
+-s 10.11.12.13/255.0.0.0;-s 10.0.0.0/8;OK
+-s 10.11.12.13/255.128.0.0;-s 10.0.0.0/9;OK
+-s 10.11.12.13/255.0.255.0;-s 10.0.12.0/255.0.255.0;OK
+-s 10.11.12.13/255.0.12.0;-s 10.0.12.0/255.0.12.0;OK
+:FORWARD
+--protocol=tcp --source=1.2.3.4 --destination=5.6.7.8/32 --in-interface=eth0 --out-interface=eth1 --jump=ACCEPT;-s 1.2.3.4/32 -d 5.6.7.8/32 -i eth0 -o eth1 -p tcp -j ACCEPT;OK
+-ptcp -s1.2.3.4 -d5.6.7.8/32 -ieth0 -oeth1 -jACCEPT;-s 1.2.3.4/32 -d 5.6.7.8/32 -i eth0 -o eth1 -p tcp -j ACCEPT;OK
+-i + -d 1.2.3.4;-d 1.2.3.4/32;OK
diff --git a/extensions/libxt_CONNMARK.c b/extensions/libxt_CONNMARK.c
index a6568c99..90a5abc0 100644
--- a/extensions/libxt_CONNMARK.c
+++ b/extensions/libxt_CONNMARK.c
@@ -31,11 +31,6 @@ struct xt_connmark_target_info {
 	uint8_t mode;
 };
 
-enum {
-	D_SHIFT_LEFT = 0,
-	D_SHIFT_RIGHT,
-};
-
 enum {
 	O_SET_MARK = 0,
 	O_SAVE_MARK,
diff --git a/extensions/libxt_CONNMARK.man b/extensions/libxt_CONNMARK.man
index 93179239..ccd7da61 100644
--- a/extensions/libxt_CONNMARK.man
+++ b/extensions/libxt_CONNMARK.man
@@ -8,7 +8,7 @@ Zero out the bits given by \fImask\fP and XOR \fIvalue\fP into the ctmark.
 Copy the packet mark (nfmark) to the connection mark (ctmark) using the given
 masks. The new nfmark value is determined as follows:
 .IP
-ctmark = (ctmark & ~ctmask) ^ (nfmark & nfmask)
+ctmark = (ctmark & \(tictmask) \(ha (nfmark & nfmask)
 .IP
 i.e. \fIctmask\fP defines what bits to clear and \fInfmask\fP what bits of the
 nfmark to XOR into the ctmark. \fIctmask\fP and \fInfmask\fP default to
@@ -18,7 +18,7 @@ nfmark to XOR into the ctmark. \fIctmask\fP and \fInfmask\fP default to
 Copy the connection mark (ctmark) to the packet mark (nfmark) using the given
 masks. The new ctmark value is determined as follows:
 .IP
-nfmark = (nfmark & ~\fInfmask\fP) ^ (ctmark & \fIctmask\fP);
+nfmark = (nfmark & \(ti\fInfmask\fP) \(ha (ctmark & \fIctmask\fP);
 .IP
 i.e. \fInfmask\fP defines what bits to clear and \fIctmask\fP what bits of the
 ctmark to XOR into the nfmark. \fIctmask\fP and \fInfmask\fP default to
diff --git a/extensions/libxt_CT.man b/extensions/libxt_CT.man
index fc692f9a..7523ead4 100644
--- a/extensions/libxt_CT.man
+++ b/extensions/libxt_CT.man
@@ -20,12 +20,12 @@ the ctmark, not nfmark), \fBnatseqinfo\fP, \fBsecmark\fP (ctsecmark).
 Only generate the specified expectation events for this connection.
 Possible event types are: \fBnew\fP.
 .TP
-\fB\-\-zone-orig\fP {\fIid\fP|\fBmark\fP}
+\fB\-\-zone\-orig\fP {\fIid\fP|\fBmark\fP}
 For traffic coming from ORIGINAL direction, assign this packet to zone
 \fIid\fP and only have lookups done in that zone. If \fBmark\fP is used
 instead of \fIid\fP, the zone is derived from the packet nfmark.
 .TP
-\fB\-\-zone-reply\fP {\fIid\fP|\fBmark\fP}
+\fB\-\-zone\-reply\fP {\fIid\fP|\fBmark\fP}
 For traffic coming from REPLY direction, assign this packet to zone
 \fIid\fP and only have lookups done in that zone. If \fBmark\fP is used
 instead of \fIid\fP, the zone is derived from the packet nfmark.
diff --git a/extensions/libxt_DNAT.man b/extensions/libxt_DNAT.man
index af9a3f06..090ecb42 100644
--- a/extensions/libxt_DNAT.man
+++ b/extensions/libxt_DNAT.man
@@ -19,7 +19,7 @@ If no port range is specified, then the destination port will never be
 modified. If no IP address is specified then only the destination port
 will be modified.
 If \fBbaseport\fP is given, the difference of the original destination port and
-its value is used as offset into the mapping port range. This allows to create
+its value is used as offset into the mapping port range. This allows one to create
 shifted portmap ranges and is available since kernel version 4.18.
 For a single port or \fIbaseport\fP, a service name as listed in
 \fB/etc/services\fP may be used.
diff --git a/extensions/libxt_HMARK.c b/extensions/libxt_HMARK.c
index 94aebe9a..83ce5003 100644
--- a/extensions/libxt_HMARK.c
+++ b/extensions/libxt_HMARK.c
@@ -41,6 +41,7 @@ static void HMARK_help(void)
 
 #define hi struct xt_hmark_info
 
+/* values must match XT_HMARK_* ones (apart from O_HMARK_TYPE) */
 enum {
 	O_HMARK_SADDR_MASK,
 	O_HMARK_DADDR_MASK,
@@ -88,32 +89,32 @@ static const struct xt_option_entry HMARK_opts[] = {
 	{ .name  = "hmark-sport-mask",
 	  .type  = XTTYPE_UINT16,
 	  .id	 = O_HMARK_SPORT_MASK,
-	  .flags = XTOPT_PUT, XTOPT_POINTER(hi, port_mask.p16.src)
+	  .flags = XTOPT_PUT | XTOPT_NBO, XTOPT_POINTER(hi, port_mask.p16.src)
 	},
 	{ .name  = "hmark-dport-mask",
 	  .type  = XTTYPE_UINT16,
 	  .id	 = O_HMARK_DPORT_MASK,
-	  .flags = XTOPT_PUT, XTOPT_POINTER(hi, port_mask.p16.dst)
+	  .flags = XTOPT_PUT | XTOPT_NBO, XTOPT_POINTER(hi, port_mask.p16.dst)
 	},
 	{ .name  = "hmark-spi-mask",
 	  .type  = XTTYPE_UINT32,
 	  .id	 = O_HMARK_SPI_MASK,
-	  .flags = XTOPT_PUT, XTOPT_POINTER(hi, port_mask.v32)
+	  .flags = XTOPT_PUT | XTOPT_NBO, XTOPT_POINTER(hi, port_mask.v32)
 	},
 	{ .name  = "hmark-sport",
 	  .type  = XTTYPE_UINT16,
 	  .id	 = O_HMARK_SPORT,
-	  .flags = XTOPT_PUT, XTOPT_POINTER(hi, port_set.p16.src)
+	  .flags = XTOPT_PUT | XTOPT_NBO, XTOPT_POINTER(hi, port_set.p16.src)
 	},
 	{ .name  = "hmark-dport",
 	  .type  = XTTYPE_UINT16,
 	  .id	 = O_HMARK_DPORT,
-	  .flags = XTOPT_PUT, XTOPT_POINTER(hi, port_set.p16.dst)
+	  .flags = XTOPT_PUT | XTOPT_NBO, XTOPT_POINTER(hi, port_set.p16.dst)
 	},
 	{ .name  = "hmark-spi",
 	  .type  = XTTYPE_UINT32,
 	  .id	 = O_HMARK_SPI,
-	  .flags = XTOPT_PUT, XTOPT_POINTER(hi, port_set.v32)
+	  .flags = XTOPT_PUT | XTOPT_NBO, XTOPT_POINTER(hi, port_set.v32)
 	},
 	{ .name  = "hmark-proto-mask",
 	  .type  = XTTYPE_UINT16,
@@ -211,53 +212,10 @@ static void HMARK_parse(struct xt_option_call *cb, int plen)
 	case O_HMARK_TYPE:
 		hmark_parse_type(cb);
 		break;
-	case O_HMARK_SADDR_MASK:
-		info->flags |= XT_HMARK_FLAG(XT_HMARK_SADDR_MASK);
-		break;
-	case O_HMARK_DADDR_MASK:
-		info->flags |= XT_HMARK_FLAG(XT_HMARK_DADDR_MASK);
-		break;
-	case O_HMARK_SPI:
-		info->port_set.v32 = htonl(cb->val.u32);
-		info->flags |= XT_HMARK_FLAG(XT_HMARK_SPI);
-		break;
-	case O_HMARK_SPORT:
-		info->port_set.p16.src = htons(cb->val.u16);
-		info->flags |= XT_HMARK_FLAG(XT_HMARK_SPORT);
-		break;
-	case O_HMARK_DPORT:
-		info->port_set.p16.dst = htons(cb->val.u16);
-		info->flags |= XT_HMARK_FLAG(XT_HMARK_DPORT);
-		break;
-	case O_HMARK_SPORT_MASK:
-		info->port_mask.p16.src = htons(cb->val.u16);
-		info->flags |= XT_HMARK_FLAG(XT_HMARK_SPORT_MASK);
-		break;
-	case O_HMARK_DPORT_MASK:
-		info->port_mask.p16.dst = htons(cb->val.u16);
-		info->flags |= XT_HMARK_FLAG(XT_HMARK_DPORT_MASK);
-		break;
-	case O_HMARK_SPI_MASK:
-		info->port_mask.v32 = htonl(cb->val.u32);
-		info->flags |= XT_HMARK_FLAG(XT_HMARK_SPI_MASK);
-		break;
-	case O_HMARK_PROTO_MASK:
-		info->flags |= XT_HMARK_FLAG(XT_HMARK_PROTO_MASK);
-		break;
-	case O_HMARK_RND:
-		info->flags |= XT_HMARK_FLAG(XT_HMARK_RND);
-		break;
-	case O_HMARK_MODULUS:
-		info->flags |= XT_HMARK_FLAG(XT_HMARK_MODULUS);
-		break;
-	case O_HMARK_OFFSET:
-		info->flags |= XT_HMARK_FLAG(XT_HMARK_OFFSET);
-		break;
-	case O_HMARK_CT:
-		info->flags |= XT_HMARK_FLAG(XT_HMARK_CT);
+	default:
+		info->flags |= XT_HMARK_FLAG(cb->entry->id);
 		break;
 	}
-	cb->xflags |= (1 << cb->entry->id);
 }
 
 static void HMARK_ip4_parse(struct xt_option_call *cb)
diff --git a/extensions/libxt_HMARK.man b/extensions/libxt_HMARK.man
index cd7ffd54..63d18cb5 100644
--- a/extensions/libxt_HMARK.man
+++ b/extensions/libxt_HMARK.man
@@ -53,7 +53,7 @@ A 32 bit random custom value to feed hash calculation.
 \fIExamples:\fP
 .PP
 iptables \-t mangle \-A PREROUTING \-m conntrack \-\-ctstate NEW
- \-j HMARK \-\-hmark-tuple ct,src,dst,proto \-\-hmark-offset 10000
+ \-j HMARK \-\-hmark-tuple ct,src,dst,proto \-\-hmark\-offset 10000
 \-\-hmark\-mod 10 \-\-hmark\-rnd 0xfeedcafe
 .PP
 iptables \-t mangle \-A PREROUTING \-j HMARK \-\-hmark\-offset 10000
diff --git a/extensions/libxt_LED.man b/extensions/libxt_LED.man
index 81c2f296..d92fd940 100644
--- a/extensions/libxt_LED.man
+++ b/extensions/libxt_LED.man
@@ -6,9 +6,9 @@ the trigger behavior:
 .TP
 \fB\-\-led\-trigger\-id\fP \fIname\fP
 This is the name given to the LED trigger. The actual name of the trigger
-will be prefixed with "netfilter-".
+will be prefixed with "netfilter\-".
 .TP
-\fB\-\-led-delay\fP \fIms\fP
+\fB\-\-led\-delay\fP \fIms\fP
 This indicates how long (in milliseconds) the LED should be left illuminated
 when a packet arrives before being switched off again. The default is 0
 (blink as fast as possible.) The special value \fIinf\fP can be given to
diff --git a/extensions/libxt_MARK.c b/extensions/libxt_MARK.c
index 100f6a38..703d894f 100644
--- a/extensions/libxt_MARK.c
+++ b/extensions/libxt_MARK.c
@@ -1,4 +1,3 @@
-#include <getopt.h>
 #include <stdbool.h>
 #include <stdio.h>
 #include <xtables.h>
@@ -69,6 +68,16 @@ static const struct xt_option_entry mark_tg_opts[] = {
 	XTOPT_TABLEEND,
 };
 
+static const struct xt_option_entry mark_tg_arp_opts[] = {
+	{.name = "set-mark", .id = O_SET_MARK, .type = XTTYPE_UINT32,
+	 .base = 16, .excl = F_ANY},
+	{.name = "and-mark", .id = O_AND_MARK, .type = XTTYPE_UINT32,
+	 .base = 16, .excl = F_ANY},
+	{.name = "or-mark", .id = O_OR_MARK, .type = XTTYPE_UINT32,
+	 .base = 16, .excl = F_ANY},
+	XTOPT_TABLEEND,
+};
+
 static void mark_tg_help(void)
 {
 	printf(
@@ -136,6 +145,8 @@ static void mark_tg_parse(struct xt_option_call *cb)
 	case O_SET_MARK:
 		info->mark = cb->val.mark;
 		info->mask = cb->val.mark | cb->val.mask;
+		if (cb->entry->type == XTTYPE_UINT32)
+			info->mask = UINT32_MAX;
 		break;
 	case O_AND_MARK:
 		info->mark = 0;
@@ -263,69 +274,6 @@ static void mark_tg_arp_print(const void *ip,
 	mark_tg_arp_save(ip, target);
 }
 
-#define MARK_OPT 1
-#define AND_MARK_OPT 2
-#define OR_MARK_OPT 3
-
-static struct option mark_tg_arp_opts[] = {
-	{ .name = "set-mark", .has_arg = required_argument, .flag = 0, .val = MARK_OPT },
-	{ .name = "and-mark", .has_arg = required_argument, .flag = 0, .val = AND_MARK_OPT },
-	{ .name = "or-mark", .has_arg = required_argument, .flag = 0, .val =  OR_MARK_OPT },
-	{ .name = NULL}
-};
-
-static int
-mark_tg_arp_parse(int c, char **argv, int invert, unsigned int *flags,
-		  const void *entry, struct xt_entry_target **target)
-{
-	struct xt_mark_tginfo2 *info =
-		(struct xt_mark_tginfo2 *)(*target)->data;
-	int i;
-
-	switch (c) {
-	case MARK_OPT:
-		if (sscanf(argv[optind-1], "%x", &i) != 1) {
-			xtables_error(PARAMETER_PROBLEM,
-				"Bad mark value `%s'", optarg);
-			return 0;
-		}
-		info->mark = i;
-		if (*flags)
-			xtables_error(PARAMETER_PROBLEM,
-				"MARK: Can't specify --set-mark twice");
-		*flags = 1;
-		break;
-	case AND_MARK_OPT:
-		if (sscanf(argv[optind-1], "%x", &i) != 1) {
-			xtables_error(PARAMETER_PROBLEM,
-				"Bad mark value `%s'", optarg);
-			return 0;
-		}
-		info->mark = 0;
-		info->mask = ~i;
-		if (*flags)
-			xtables_error(PARAMETER_PROBLEM,
-				"MARK: Can't specify --and-mark twice");
-		*flags = 1;
-		break;
-	case OR_MARK_OPT:
-		if (sscanf(argv[optind-1], "%x", &i) != 1) {
-			xtables_error(PARAMETER_PROBLEM,
-				"Bad mark value `%s'", optarg);
-			return 0;
-		}
-		info->mark = info->mask = i;
-		if (*flags)
-			xtables_error(PARAMETER_PROBLEM,
-				"MARK: Can't specify --or-mark twice");
-		*flags = 1;
-		break;
-	default:
-		return 0;
-	}
-	return 1;
-}
-
 static int mark_tg_xlate(struct xt_xlate *xl,
 			 const struct xt_xlate_tg_params *params)
 {
@@ -428,8 +376,10 @@ static struct xtables_target mark_tg_reg[] = {
 		.help          = mark_tg_help,
 		.print         = mark_tg_arp_print,
 		.save          = mark_tg_arp_save,
-		.parse         = mark_tg_arp_parse,
-		.extra_opts    = mark_tg_arp_opts,
+		.x6_parse      = mark_tg_parse,
+		.x6_fcheck     = mark_tg_check,
+		.x6_options    = mark_tg_arp_opts,
+		.xlate	       = mark_tg_xlate,
 	},
 };
 
diff --git a/extensions/libxt_MARK.txlate b/extensions/libxt_MARK.txlate
index 36ee7a3b..cef8239a 100644
--- a/extensions/libxt_MARK.txlate
+++ b/extensions/libxt_MARK.txlate
@@ -24,3 +24,12 @@ nft 'add rule ip mangle PREROUTING counter meta mark set mark and 0x64'
 
 iptables-translate -t mangle -A PREROUTING -j MARK --or-mark 0x64
 nft 'add rule ip mangle PREROUTING counter meta mark set mark or 0x64'
+
+arptables-translate -A OUTPUT -j MARK --set-mark 0x4
+nft 'add rule arp filter OUTPUT arp htype 1 arp hlen 6 arp plen 4 counter meta mark set 0x4'
+
+arptables-translate -I OUTPUT -o odev -j MARK --and-mark 0x8
+nft 'insert rule arp filter OUTPUT oifname "odev" arp htype 1 arp hlen 6 arp plen 4 counter meta mark set mark and 0x8'
+
+arptables-translate -t mangle -A OUTPUT -o odev -j MARK --or-mark 16
+nft 'add rule arp mangle OUTPUT oifname "odev" arp htype 1 arp hlen 6 arp plen 4 counter meta mark set mark or 0x16'
diff --git a/extensions/libxt_MASQUERADE.man b/extensions/libxt_MASQUERADE.man
index 26d91ddb..5c236447 100644
--- a/extensions/libxt_MASQUERADE.man
+++ b/extensions/libxt_MASQUERADE.man
@@ -15,15 +15,15 @@ any established connections are lost anyway).
 \fB\-\-to\-ports\fP \fIport\fP[\fB\-\fP\fIport\fP]
 This specifies a range of source ports to use, overriding the default
 .B SNAT
-source port-selection heuristics (see above).  This is only valid
+source port selection heuristics (see above). This is only valid
 if the rule also specifies one of the following protocols:
 \fBtcp\fP, \fBudp\fP, \fBdccp\fP or \fBsctp\fP.
 .TP
 \fB\-\-random\fP
 Randomize source port mapping (kernel >= 2.6.21).
-Since kernel 5.0, \fB\-\-random\fP is identical to \fB\-\-random-fully\fP.
+Since kernel 5.0, \fB\-\-random\fP is identical to \fB\-\-random\-fully\fP.
 .TP
-\fB\-\-random-fully\fP
+\fB\-\-random\-fully\fP
 Fully randomize source port mapping (kernel >= 3.13).
 .TP
 IPv6 support available since Linux kernels >= 3.7.
diff --git a/extensions/libxt_NFLOG.man b/extensions/libxt_NFLOG.man
index 318e6305..86ebb210 100644
--- a/extensions/libxt_NFLOG.man
+++ b/extensions/libxt_NFLOG.man
@@ -9,7 +9,7 @@ may subscribe to the group to receive the packets. Like LOG, this is a
 non-terminating target, i.e. rule traversal continues at the next rule.
 .TP
 \fB\-\-nflog\-group\fP \fInlgroup\fP
-The netlink group (0 - 2^16\-1) to which packets are (only applicable for
+The netlink group (0\(en2\(ha16\-1) to which packets are (only applicable for
 nfnetlink_log). The default value is 0.
 .TP
 \fB\-\-nflog\-prefix\fP \fIprefix\fP
@@ -17,7 +17,7 @@ A prefix string to include in the log message, up to 64 characters
 long, useful for distinguishing messages in the logs.
 .TP
 \fB\-\-nflog\-range\fP \fIsize\fP
-This option has never worked, use --nflog-size instead
+This option has never worked, use \-\-nflog\-size instead
 .TP
 \fB\-\-nflog\-size\fP \fIsize\fP
 The number of bytes to be copied to userspace (only applicable for
diff --git a/extensions/libxt_NFLOG.t b/extensions/libxt_NFLOG.t
index 25f332ae..0cd81c64 100644
--- a/extensions/libxt_NFLOG.t
+++ b/extensions/libxt_NFLOG.t
@@ -15,7 +15,7 @@
 -j NFLOG --nflog-size 4294967296;;FAIL
 -j NFLOG --nflog-size -1;;FAIL
 -j NFLOG --nflog-prefix xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;=;OK
--j NFLOG --nflog-prefix xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;-j NFLOG --nflog-prefix xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;OK
+-j NFLOG --nflog-prefix xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;-j NFLOG --nflog-prefix xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;OK;LEGACY;=
 -j NFLOG --nflog-threshold 1;=;OK
 # ERROR: line 13 (should fail: iptables -A INPUT -j NFLOG --nflog-threshold 0
 # -j NFLOG --nflog-threshold 0;;FAIL
diff --git a/extensions/libxt_NFQUEUE.man b/extensions/libxt_NFQUEUE.man
index 950b0d24..cb963bec 100644
--- a/extensions/libxt_NFQUEUE.man
+++ b/extensions/libxt_NFQUEUE.man
@@ -6,8 +6,9 @@ reinject the packet into the kernel.  Please see libnetfilter_queue
 for details.
 .B
 nfnetlink_queue
-was added in Linux 2.6.14. The \fBqueue-balance\fP option was added in Linux 2.6.31,
-\fBqueue-bypass\fP in 2.6.39.
+was added in Linux 2.6.14. The \fBqueue\-balance\fP option was added in Linux
+2.6.31,
+\fBqueue\-bypass\fP in 2.6.39.
 .TP
 \fB\-\-queue\-num\fP \fIvalue\fP
 This specifies the QUEUE number to use. Valid queue numbers are 0 to 65535. The default value is 0.
@@ -28,8 +29,8 @@ are dropped.  When this option is used, the NFQUEUE rule behaves like ACCEPT ins
 will move on to the next table.
 .PP
 .TP
-\fB\-\-queue\-cpu-fanout\fP
+\fB\-\-queue\-cpu\-fanout\fP
 Available starting Linux kernel 3.10. When used together with
-\fB--queue-balance\fP this will use the CPU ID as an index to map packets to
+\fB\-\-queue\-balance\fP this will use the CPU ID as an index to map packets to
 the queues. The idea is that you can improve performance if there's a queue
-per CPU. This requires \fB--queue-balance\fP to be specified.
+per CPU. This requires \fB\-\-queue\-balance\fP to be specified.
diff --git a/extensions/libxt_NFQUEUE.t b/extensions/libxt_NFQUEUE.t
index 8fb2b760..94050500 100644
--- a/extensions/libxt_NFQUEUE.t
+++ b/extensions/libxt_NFQUEUE.t
@@ -8,6 +8,13 @@
 -j NFQUEUE --queue-balance 0:65535;;FAIL
 -j NFQUEUE --queue-balance 0:65536;;FAIL
 -j NFQUEUE --queue-balance -1:65535;;FAIL
+-j NFQUEUE --queue-balance 4;;FAIL
+-j NFQUEUE --queue-balance :;-j NFQUEUE --queue-balance 0:65534;OK
+-j NFQUEUE --queue-balance :4;-j NFQUEUE --queue-balance 0:4;OK
+-j NFQUEUE --queue-balance 4:;-j NFQUEUE --queue-balance 4:65534;OK
+-j NFQUEUE --queue-balance 3:4;=;OK
+-j NFQUEUE --queue-balance 4:4;;FAIL
+-j NFQUEUE --queue-balance 4:3;;FAIL
 -j NFQUEUE --queue-num 10 --queue-bypass;=;OK
 -j NFQUEUE --queue-balance 0:6 --queue-cpu-fanout --queue-bypass;-j NFQUEUE --queue-balance 0:6 --queue-bypass --queue-cpu-fanout;OK
 -j NFQUEUE --queue-bypass --queue-balance 0:6 --queue-cpu-fanout;-j NFQUEUE --queue-balance 0:6 --queue-bypass --queue-cpu-fanout;OK
diff --git a/extensions/libxt_SET.man b/extensions/libxt_SET.man
index c4713378..7332acb0 100644
--- a/extensions/libxt_SET.man
+++ b/extensions/libxt_SET.man
@@ -25,8 +25,8 @@ one from the set definition
 when adding an entry if it already exists, reset the timeout value
 to the specified one or to the default from the set definition
 .TP
-\fB\-\-map\-set\fP \fIset\-name\fP
-the set-name should be created with --skbinfo option
+\fB\-\-map\-set\fP \fIset-name\fP
+the set-name should be created with \-\-skbinfo option
 \fB\-\-map\-mark\fP
 map firewall mark to packet by lookup of value in the set
 \fB\-\-map\-prio\fP
diff --git a/extensions/libxt_SNAT.man b/extensions/libxt_SNAT.man
index 80a698a6..d879c871 100644
--- a/extensions/libxt_SNAT.man
+++ b/extensions/libxt_SNAT.man
@@ -23,7 +23,7 @@ will be mapped to ports below 1024, and other ports will be mapped to
 \fB\-\-random\fP
 Randomize source port mapping through a hash-based algorithm (kernel >= 2.6.21).
 .TP
-\fB\-\-random-fully\fP
+\fB\-\-random\-fully\fP
 Fully randomize source port mapping through a PRNG (kernel >= 3.14).
 .TP
 \fB\-\-persistent\fP
diff --git a/extensions/libxt_SYNPROXY.man b/extensions/libxt_SYNPROXY.man
index 30a71ed2..04fffedb 100644
--- a/extensions/libxt_SYNPROXY.man
+++ b/extensions/libxt_SYNPROXY.man
@@ -22,7 +22,7 @@ Example:
 .PP
 Determine tcp options used by backend, from an external system
 .IP
-tcpdump -pni eth0 -c 1 'tcp[tcpflags] == (tcp-syn|tcp-ack)'
+tcpdump \-pni eth0 \-c 1 'tcp[tcpflags] == (tcp\-syn|tcp\-ack)'
 .br
     port 80 &
 .br
@@ -40,7 +40,7 @@ telnet 192.0.2.42 80
 .br
     length 0
 .PP
-Switch tcp_loose mode off, so conntrack will mark out\-of\-flow
+Switch tcp_loose mode off, so conntrack will mark out-of-flow
 packets as state INVALID.
 .IP
 echo 0 > /proc/sys/net/netfilter/nf_conntrack_tcp_loose
diff --git a/extensions/libxt_TCPMSS.t b/extensions/libxt_TCPMSS.t
index fbfbfcf8..b3639cc1 100644
--- a/extensions/libxt_TCPMSS.t
+++ b/extensions/libxt_TCPMSS.t
@@ -1,6 +1,6 @@
 :FORWARD,OUTPUT,POSTROUTING
 *mangle
 -j TCPMSS;;FAIL
--p tcp -j TCPMSS --set-mss 42;;FAIL;LEGACY
+-p tcp -j TCPMSS --set-mss 42;=;FAIL;LEGACY
 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j TCPMSS --set-mss 42;=;OK
 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j TCPMSS --clamp-mss-to-pmtu;=;OK
diff --git a/extensions/libxt_TEE.t b/extensions/libxt_TEE.t
index ce8b103e..3c7b929c 100644
--- a/extensions/libxt_TEE.t
+++ b/extensions/libxt_TEE.t
@@ -1,4 +1,2 @@
 :INPUT,FORWARD,OUTPUT
--j TEE --gateway 1.1.1.1;=;OK
--j TEE ! --gateway 1.1.1.1;;FAIL
 -j TEE;;FAIL
diff --git a/extensions/libxt_TOS.man b/extensions/libxt_TOS.man
index de2d22dc..2c8d4694 100644
--- a/extensions/libxt_TOS.man
+++ b/extensions/libxt_TOS.man
@@ -32,5 +32,5 @@ longterm releases 2.6.32 (>=.42), 2.6.33 (>=.15), and 2.6.35 (>=.14), there is
 a bug whereby IPv6 TOS mangling does not behave as documented and differs from
 the IPv4 version. The TOS mask indicates the bits one wants to zero out, so it
 needs to be inverted before applying it to the original TOS field. However, the
-aformentioned kernels forgo the inversion which breaks \-\-set\-tos and its
+aforementioned kernels forgo the inversion which breaks \-\-set\-tos and its
 mnemonics.
diff --git a/extensions/libxt_TPROXY.c b/extensions/libxt_TPROXY.c
index d13ec85f..5bdefee0 100644
--- a/extensions/libxt_TPROXY.c
+++ b/extensions/libxt_TPROXY.c
@@ -147,6 +147,64 @@ static void tproxy_tg1_parse(struct xt_option_call *cb)
 	}
 }
 
+static int tproxy_tg_xlate(struct xt_xlate *xl,
+			   const struct xt_tproxy_target_info_v1 *info)
+{
+	int family = xt_xlate_get_family(xl);
+	uint32_t mask = info->mark_mask;
+	bool port_mandatory = false;
+	char buf[INET6_ADDRSTRLEN];
+
+	xt_xlate_add(xl, "tproxy to");
+
+	inet_ntop(family, &info->laddr, buf, sizeof(buf));
+
+	if (family == AF_INET6 && !IN6_IS_ADDR_UNSPECIFIED(&info->laddr.in6))
+		xt_xlate_add(xl, "[%s]", buf);
+	else if (family == AF_INET && info->laddr.ip)
+		xt_xlate_add(xl, "%s", buf);
+	else
+		port_mandatory = true;
+
+	if (port_mandatory)
+		xt_xlate_add(xl, " :%d", ntohs(info->lport));
+	else if (info->lport)
+		xt_xlate_add(xl, ":%d", ntohs(info->lport));
+
+	/* xt_TPROXY.c does: skb->mark = (skb->mark & ~mark_mask) ^ mark_value */
+	if (mask == 0xffffffff)
+		xt_xlate_add(xl, "meta mark set 0x%x", info->mark_value);
+	else if (mask || info->mark_value)
+		xt_xlate_add(xl, "meta mark set meta mark & 0x%x xor 0x%x",
+			     ~mask, info->mark_value);
+
+	/* unlike TPROXY target, tproxy statement is non-terminal */
+	xt_xlate_add(xl, "accept");
+	return 1;
+}
+
+static int tproxy_tg_xlate_v1(struct xt_xlate *xl,
+			      const struct xt_xlate_tg_params *params)
+{
+	const struct xt_tproxy_target_info_v1 *data = (const void *)params->target->data;
+
+	return tproxy_tg_xlate(xl, data);
+}
+
+static int tproxy_tg_xlate_v0(struct xt_xlate *xl,
+			      const struct xt_xlate_tg_params *params)
+{
+	const struct xt_tproxy_target_info *info = (const void *)params->target->data;
+	struct xt_tproxy_target_info_v1 t = {
+		.mark_mask = info->mark_mask,
+		.mark_value = info->mark_value,
+		.laddr.ip = info->laddr,
+		.lport = info->lport,
+	};
+
+	return tproxy_tg_xlate(xl, &t);
+}
+
 static struct xtables_target tproxy_tg_reg[] = {
 	{
 		.name          = "TPROXY",
@@ -160,6 +218,7 @@ static struct xtables_target tproxy_tg_reg[] = {
 		.save          = tproxy_tg_save,
 		.x6_options    = tproxy_tg0_opts,
 		.x6_parse      = tproxy_tg0_parse,
+		.xlate	       = tproxy_tg_xlate_v0,
 	},
 	{
 		.name          = "TPROXY",
@@ -173,6 +232,7 @@ static struct xtables_target tproxy_tg_reg[] = {
 		.save          = tproxy_tg_save4,
 		.x6_options    = tproxy_tg1_opts,
 		.x6_parse      = tproxy_tg1_parse,
+		.xlate	       = tproxy_tg_xlate_v1,
 	},
 	{
 		.name          = "TPROXY",
@@ -186,6 +246,7 @@ static struct xtables_target tproxy_tg_reg[] = {
 		.save          = tproxy_tg_save6,
 		.x6_options    = tproxy_tg1_opts,
 		.x6_parse      = tproxy_tg1_parse,
+		.xlate	       = tproxy_tg_xlate_v1,
 	},
 };
 
diff --git a/extensions/libxt_TPROXY.txlate b/extensions/libxt_TPROXY.txlate
new file mode 100644
index 00000000..f000baab
--- /dev/null
+++ b/extensions/libxt_TPROXY.txlate
@@ -0,0 +1,20 @@
+iptables-translate -t mangle -A PREROUTING -p tcp -j TPROXY --on-port 12345 --on-ip 10.0.0.1 --tproxy-mark 0x23/0xff
+nft 'add rule ip mangle PREROUTING ip protocol tcp counter tproxy to 10.0.0.1:12345 meta mark set meta mark & 0xffffff00 xor 0x23 accept'
+
+iptables-translate -t mangle -A PREROUTING -p udp -j TPROXY --on-port 12345 --on-ip 10.0.0.1 --tproxy-mark 0x23
+nft 'add rule ip mangle PREROUTING ip protocol udp counter tproxy to 10.0.0.1:12345 meta mark set 0x23 accept'
+
+iptables-translate -t mangle -A PREROUTING -p udp -j TPROXY --on-port 12345 --on-ip 10.0.0.1
+nft 'add rule ip mangle PREROUTING ip protocol udp counter tproxy to 10.0.0.1:12345 accept'
+
+iptables-translate -t mangle -A PREROUTING -p udp -j TPROXY --on-ip 10.0.0.1 --on-port 0
+nft 'add rule ip mangle PREROUTING ip protocol udp counter tproxy to 10.0.0.1 accept'
+
+iptables-translate -t mangle -A PREROUTING -p tcp -j TPROXY --on-port 12345
+nft 'add rule ip mangle PREROUTING ip protocol tcp counter tproxy to :12345 accept'
+
+iptables-translate -t mangle -A PREROUTING -p tcp -j TPROXY --on-port 0
+nft 'add rule ip mangle PREROUTING ip protocol tcp counter tproxy to :0 accept'
+
+ip6tables-translate -t mangle -A PREROUTING -p tcp -j TPROXY --on-port 12345 --on-ip dead::beef --tproxy-mark 0x23/0xffff
+nft 'add rule ip6 mangle PREROUTING meta l4proto tcp counter tproxy to [dead::beef]:12345 meta mark set meta mark & 0xffff0000 xor 0x23 accept'
diff --git a/extensions/libxt_TRACE.man b/extensions/libxt_TRACE.man
index 5187a8d2..9cfa2711 100644
--- a/extensions/libxt_TRACE.man
+++ b/extensions/libxt_TRACE.man
@@ -15,6 +15,6 @@ With iptables-nft, the target is translated into nftables'
 .B "meta nftrace"
 expression. Hence the kernel sends trace events via netlink to userspace where
 they may be displayed using
-.B "xtables-monitor --trace"
+.B "xtables\-monitor \-\-trace"
 command. For details, refer to
-.BR xtables-monitor (8).
+.BR xtables\-monitor (8).
diff --git a/extensions/libxt_bpf.man b/extensions/libxt_bpf.man
index d6da2043..b79c21db 100644
--- a/extensions/libxt_bpf.man
+++ b/extensions/libxt_bpf.man
@@ -28,7 +28,7 @@ without the comments or trailing whitespace:
 .IP
 4               # number of instructions
 .br
-48 0 0 9        # load byte  ip->proto
+48 0 0 9        # load byte  ip\->proto
 .br
 21 0 1 6        # jump equal IPPROTO_TCP
 .br
@@ -44,7 +44,7 @@ Or instead, you can invoke the nfbpf_compile utility.
 .IP
 iptables \-A OUTPUT \-m bpf \-\-bytecode "`nfbpf_compile RAW 'ip proto 6'`" \-j ACCEPT
 .PP
-Or use tcpdump -ddd. In that case, generate BPF targeting a device with the
+Or use tcpdump \-ddd. In that case, generate BPF targeting a device with the
 same data link type as the xtables match. Iptables passes packets from the
 network layer up, without mac layer. Select a device with data link type RAW,
 such as a tun device:
@@ -53,8 +53,8 @@ ip tuntap add tun0 mode tun
 .br
 ip link set tun0 up
 .br
-tcpdump -ddd -i tun0 ip proto 6
+tcpdump \-ddd \-i tun0 ip proto 6
 .PP
-See tcpdump -L -i $dev for a list of known data link types for a given device.
+See tcpdump \-L \-i $dev for a list of known data link types for a given device.
 .PP
 You may want to learn more about BPF from FreeBSD's bpf(4) manpage.
diff --git a/extensions/libxt_cgroup.man b/extensions/libxt_cgroup.man
index 4d5d1d86..140afb48 100644
--- a/extensions/libxt_cgroup.man
+++ b/extensions/libxt_cgroup.man
@@ -15,7 +15,7 @@ option and \-\-path can't be used together.
 .PP
 Example:
 .IP
-iptables \-A OUTPUT \-p tcp \-\-sport 80 \-m cgroup ! \-\-path service/http-server \-j DROP
+iptables \-A OUTPUT \-p tcp \-\-sport 80 \-m cgroup ! \-\-path service/http\-server \-j DROP
 .IP
 iptables \-A OUTPUT \-p tcp \-\-sport 80 \-m cgroup ! \-\-cgroup 1
 \-j DROP
diff --git a/extensions/libxt_cluster.man b/extensions/libxt_cluster.man
index 23448e26..63054471 100644
--- a/extensions/libxt_cluster.man
+++ b/extensions/libxt_cluster.man
@@ -22,7 +22,7 @@ Example:
 iptables \-A PREROUTING \-t mangle \-i eth1 \-m cluster
 \-\-cluster\-total\-nodes 2 \-\-cluster\-local\-node 1
 \-\-cluster\-hash\-seed 0xdeadbeef
-\-j MARK \-\-set-mark 0xffff
+\-j MARK \-\-set\-mark 0xffff
 .IP
 iptables \-A PREROUTING \-t mangle \-i eth2 \-m cluster
 \-\-cluster\-total\-nodes 2 \-\-cluster\-local\-node 1
@@ -42,10 +42,10 @@ ip maddr add 01:00:5e:00:01:01 dev eth1
 ip maddr add 01:00:5e:00:01:02 dev eth2
 .IP
 arptables \-A OUTPUT \-o eth1 \-\-h\-length 6
-\-j mangle \-\-mangle-mac-s 01:00:5e:00:01:01
+\-j mangle \-\-mangle\-mac\-s 01:00:5e:00:01:01
 .IP
-arptables \-A INPUT \-i eth1 \-\-h-length 6
-\-\-destination-mac 01:00:5e:00:01:01
+arptables \-A INPUT \-i eth1 \-\-h\-length 6
+\-\-destination\-mac 01:00:5e:00:01:01
 \-j mangle \-\-mangle\-mac\-d 00:zz:yy:xx:5a:27
 .IP
 arptables \-A OUTPUT \-o eth2 \-\-h\-length 6
diff --git a/extensions/libxt_connbytes.c b/extensions/libxt_connbytes.c
index b57f0fc0..2f110857 100644
--- a/extensions/libxt_connbytes.c
+++ b/extensions/libxt_connbytes.c
@@ -41,10 +41,6 @@ static void connbytes_parse(struct xt_option_call *cb)
 		if (cb->nvals == 2)
 			sinfo->count.to = cb->val.u64_range[1];
 
-		if (sinfo->count.to < sinfo->count.from)
-			xtables_error(PARAMETER_PROBLEM, "%llu should be less than %llu",
-					(unsigned long long)sinfo->count.from,
-					(unsigned long long)sinfo->count.to);
 		if (cb->invert) {
 			i = sinfo->count.from;
 			sinfo->count.from = sinfo->count.to;
diff --git a/extensions/libxt_connbytes.t b/extensions/libxt_connbytes.t
index 6b24e266..60209c69 100644
--- a/extensions/libxt_connbytes.t
+++ b/extensions/libxt_connbytes.t
@@ -10,6 +10,12 @@
 -m connbytes --connbytes 0:1000 --connbytes-mode avgpkt --connbytes-dir both;=;OK
 -m connbytes --connbytes -1:0 --connbytes-mode packets --connbytes-dir original;;FAIL
 -m connbytes --connbytes 0:-1 --connbytes-mode packets --connbytes-dir original;;FAIL
+-m connbytes --connbytes : --connbytes-mode packets --connbytes-dir original;-m connbytes --connbytes 0 --connbytes-mode packets --connbytes-dir original;OK
+-m connbytes --connbytes :1000 --connbytes-mode packets --connbytes-dir original;-m connbytes --connbytes 0:1000 --connbytes-mode packets --connbytes-dir original;OK
+-m connbytes --connbytes 1000 --connbytes-mode packets --connbytes-dir original;=;OK
+-m connbytes --connbytes 1000: --connbytes-mode packets --connbytes-dir original;-m connbytes --connbytes 1000 --connbytes-mode packets --connbytes-dir original;OK
+-m connbytes --connbytes 1000:1000 --connbytes-mode packets --connbytes-dir original;=;OK
+-m connbytes --connbytes 1000:0 --connbytes-mode packets --connbytes-dir original;;FAIL
 # ERROR: cannot find: iptables -I INPUT -m connbytes --connbytes 0:18446744073709551615 --connbytes-mode avgpkt --connbytes-dir both
 # -m connbytes --connbytes 0:18446744073709551615 --connbytes-mode avgpkt --connbytes-dir both;=;OK
 -m connbytes --connbytes 0:18446744073709551616 --connbytes-mode avgpkt --connbytes-dir both;;FAIL
diff --git a/extensions/libxt_connlabel.man b/extensions/libxt_connlabel.man
index bdaa51e8..7ce18cf5 100644
--- a/extensions/libxt_connlabel.man
+++ b/extensions/libxt_connlabel.man
@@ -23,11 +23,11 @@ Label translation is done via the \fB/etc/xtables/connlabel.conf\fP configuratio
 Example:
 .IP
 .nf
-0	eth0-in
-1	eth0-out
-2	ppp-in
-3	ppp-out
-4	bulk-traffic
+0	eth0\-in
+1	eth0\-out
+2	ppp\-in
+3	ppp\-out
+4	bulk\-traffic
 5	interactive
 .fi
 .PP
diff --git a/extensions/libxt_connlimit.man b/extensions/libxt_connlimit.man
index ad9f40fa..aa7df2b2 100644
--- a/extensions/libxt_connlimit.man
+++ b/extensions/libxt_connlimit.man
@@ -20,23 +20,28 @@ Apply the limit onto the source group. This is the default if
 Apply the limit onto the destination group.
 .PP
 Examples:
-.TP
-# allow 2 telnet connections per client host
+.IP \(bu 4
+allow 2 telnet connections per client host:
+.br
 iptables \-A INPUT \-p tcp \-\-syn \-\-dport 23 \-m connlimit \-\-connlimit\-above 2 \-j REJECT
-.TP
-# you can also match the other way around:
+.IP \(bu 4
+you can also match the other way around:
+.br
 iptables \-A INPUT \-p tcp \-\-syn \-\-dport 23 \-m connlimit \-\-connlimit\-upto 2 \-j ACCEPT
-.TP
-# limit the number of parallel HTTP requests to 16 per class C sized \
-source network (24 bit netmask)
+.IP \(bu 4
+limit the number of parallel HTTP requests to 16 per class C sized \
+source network (24 bit netmask):
+.br
 iptables \-p tcp \-\-syn \-\-dport 80 \-m connlimit \-\-connlimit\-above 16
 \-\-connlimit\-mask 24 \-j REJECT
-.TP
-# limit the number of parallel HTTP requests to 16 for the link local network
-(ipv6)
+.IP \(bu 4
+limit the number of parallel HTTP requests to 16 for the link local network
+(IPv6):
+.br
 ip6tables \-p tcp \-\-syn \-\-dport 80 \-s fe80::/64 \-m connlimit \-\-connlimit\-above
 16 \-\-connlimit\-mask 64 \-j REJECT
-.TP
-# Limit the number of connections to a particular host:
+.IP \(bu 4
+Limit the number of connections to a particular host:
+.br
 ip6tables \-p tcp \-\-syn \-\-dport 49152:65535 \-d 2001:db8::1 \-m connlimit
-\-\-connlimit-above 100 \-j REJECT
+\-\-connlimit\-above 100 \-j REJECT
diff --git a/extensions/libxt_connlimit.t b/extensions/libxt_connlimit.t
index 366cea74..79d08748 100644
--- a/extensions/libxt_connlimit.t
+++ b/extensions/libxt_connlimit.t
@@ -1,16 +1,6 @@
 :INPUT,FORWARD,OUTPUT
--m connlimit --connlimit-upto 0;-m connlimit --connlimit-upto 0 --connlimit-mask 32 --connlimit-saddr;OK
--m connlimit --connlimit-upto 4294967295 --connlimit-mask 32 --connlimit-saddr;=;OK
--m connlimit --connlimit-upto 4294967296 --connlimit-mask 32 --connlimit-saddr;;FAIL
 -m connlimit --connlimit-upto -1;;FAIL
--m connlimit --connlimit-above 0;-m connlimit --connlimit-above 0 --connlimit-mask 32 --connlimit-saddr;OK
--m connlimit --connlimit-above 4294967295 --connlimit-mask 32 --connlimit-saddr;=;OK
--m connlimit --connlimit-above 4294967296 --connlimit-mask 32 --connlimit-saddr;;FAIL
 -m connlimit --connlimit-above -1;;FAIL
 -m connlimit --connlimit-upto 1 --conlimit-above 1;;FAIL
--m connlimit --connlimit-above 10 --connlimit-saddr;-m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-saddr;OK
--m connlimit --connlimit-above 10 --connlimit-daddr;-m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-daddr;OK
 -m connlimit --connlimit-above 10 --connlimit-saddr --connlimit-daddr;;FAIL
--m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-saddr;=;OK
--m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-daddr;=;OK
 -m connlimit;;FAIL
diff --git a/extensions/libxt_conntrack.c b/extensions/libxt_conntrack.c
index ffbc7467..04940154 100644
--- a/extensions/libxt_conntrack.c
+++ b/extensions/libxt_conntrack.c
@@ -1102,32 +1102,6 @@ static void state_ct23_parse(struct xt_option_call *cb)
 		sinfo->invert_flags |= XT_CONNTRACK_STATE;
 }
 
-static void state_print_state(unsigned int statemask)
-{
-	const char *sep = "";
-
-	if (statemask & XT_CONNTRACK_STATE_INVALID) {
-		printf("%sINVALID", sep);
-		sep = ",";
-	}
-	if (statemask & XT_CONNTRACK_STATE_BIT(IP_CT_NEW)) {
-		printf("%sNEW", sep);
-		sep = ",";
-	}
-	if (statemask & XT_CONNTRACK_STATE_BIT(IP_CT_RELATED)) {
-		printf("%sRELATED", sep);
-		sep = ",";
-	}
-	if (statemask & XT_CONNTRACK_STATE_BIT(IP_CT_ESTABLISHED)) {
-		printf("%sESTABLISHED", sep);
-		sep = ",";
-	}
-	if (statemask & XT_CONNTRACK_STATE_UNTRACKED) {
-		printf("%sUNTRACKED", sep);
-		sep = ",";
-	}
-}
-
 static void
 state_print(const void *ip,
       const struct xt_entry_match *match,
@@ -1135,16 +1109,16 @@ state_print(const void *ip,
 {
 	const struct xt_state_info *sinfo = (const void *)match->data;
 
-	printf(" state ");
-	state_print_state(sinfo->statemask);
+	printf(" state");
+	print_state(sinfo->statemask);
 }
 
 static void state_save(const void *ip, const struct xt_entry_match *match)
 {
 	const struct xt_state_info *sinfo = (const void *)match->data;
 
-	printf(" --state ");
-	state_print_state(sinfo->statemask);
+	printf(" --state");
+	print_state(sinfo->statemask);
 }
 
 static void state_xlate_print(struct xt_xlate *xl, unsigned int statemask, int inverted)
@@ -1502,8 +1476,8 @@ static struct xtables_match conntrack_mt_reg[] = {
 		.size          = XT_ALIGN(sizeof(struct xt_conntrack_mtinfo1)),
 		.userspacesize = XT_ALIGN(sizeof(struct xt_conntrack_mtinfo1)),
 		.help          = state_help,
-		.print         = state_print,
-		.save          = state_save,
+		.print         = conntrack1_mt4_print,
+		.save          = conntrack1_mt4_save,
 		.x6_parse      = state_ct1_parse,
 		.x6_options    = state_opts,
 	},
@@ -1517,8 +1491,8 @@ static struct xtables_match conntrack_mt_reg[] = {
 		.size          = XT_ALIGN(sizeof(struct xt_conntrack_mtinfo2)),
 		.userspacesize = XT_ALIGN(sizeof(struct xt_conntrack_mtinfo2)),
 		.help          = state_help,
-		.print         = state_print,
-		.save          = state_save,
+		.print         = conntrack2_mt_print,
+		.save          = conntrack2_mt_save,
 		.x6_parse      = state_ct23_parse,
 		.x6_options    = state_opts,
 	},
@@ -1532,8 +1506,8 @@ static struct xtables_match conntrack_mt_reg[] = {
 		.size          = XT_ALIGN(sizeof(struct xt_conntrack_mtinfo3)),
 		.userspacesize = XT_ALIGN(sizeof(struct xt_conntrack_mtinfo3)),
 		.help          = state_help,
-		.print         = state_print,
-		.save          = state_save,
+		.print         = conntrack3_mt_print,
+		.save          = conntrack3_mt_save,
 		.x6_parse      = state_ct23_parse,
 		.x6_options    = state_opts,
 		.xlate         = state_xlate,
diff --git a/extensions/libxt_conntrack.t b/extensions/libxt_conntrack.t
index 2b3c5de9..2377a016 100644
--- a/extensions/libxt_conntrack.t
+++ b/extensions/libxt_conntrack.t
@@ -8,15 +8,13 @@
 -m conntrack --ctstate wrong;;FAIL
 # should we convert this to output "tcp" instead of 6?
 -m conntrack --ctproto tcp;-m conntrack --ctproto 6;OK
--m conntrack --ctorigsrc 1.1.1.1;=;OK
--m conntrack --ctorigdst 1.1.1.1;=;OK
--m conntrack --ctreplsrc 1.1.1.1;=;OK
--m conntrack --ctrepldst 1.1.1.1;=;OK
 -m conntrack --ctexpire 0;=;OK
 -m conntrack --ctexpire 4294967295;=;OK
 -m conntrack --ctexpire 0:4294967295;=;OK
 -m conntrack --ctexpire 42949672956;;FAIL
 -m conntrack --ctexpire -1;;FAIL
+-m conntrack --ctexpire 3:3;-m conntrack --ctexpire 3;OK
+-m conntrack --ctexpire 4:3;;FAIL
 -m conntrack --ctdir ORIGINAL;=;OK
 -m conntrack --ctdir REPLY;=;OK
 -m conntrack --ctstatus NONE;=;OK
@@ -27,3 +25,27 @@
 -m conntrack;;FAIL
 -m conntrack --ctproto 0;;FAIL
 -m conntrack ! --ctproto 0;;FAIL
+-m conntrack --ctorigsrcport :;-m conntrack --ctorigsrcport 0:65535;OK
+-m conntrack --ctorigsrcport :4;-m conntrack --ctorigsrcport 0:4;OK
+-m conntrack --ctorigsrcport 4:;-m conntrack --ctorigsrcport 4:65535;OK
+-m conntrack --ctorigsrcport 3:4;=;OK
+-m conntrack --ctorigsrcport 4:4;-m conntrack --ctorigsrcport 4;OK
+-m conntrack --ctorigsrcport 4:3;;FAIL
+-m conntrack --ctreplsrcport :;-m conntrack --ctreplsrcport 0:65535;OK
+-m conntrack --ctreplsrcport :4;-m conntrack --ctreplsrcport 0:4;OK
+-m conntrack --ctreplsrcport 4:;-m conntrack --ctreplsrcport 4:65535;OK
+-m conntrack --ctreplsrcport 3:4;=;OK
+-m conntrack --ctreplsrcport 4:4;-m conntrack --ctreplsrcport 4;OK
+-m conntrack --ctreplsrcport 4:3;;FAIL
+-m conntrack --ctorigdstport :;-m conntrack --ctorigdstport 0:65535;OK
+-m conntrack --ctorigdstport :4;-m conntrack --ctorigdstport 0:4;OK
+-m conntrack --ctorigdstport 4:;-m conntrack --ctorigdstport 4:65535;OK
+-m conntrack --ctorigdstport 3:4;=;OK
+-m conntrack --ctorigdstport 4:4;-m conntrack --ctorigdstport 4;OK
+-m conntrack --ctorigdstport 4:3;;FAIL
+-m conntrack --ctrepldstport :;-m conntrack --ctrepldstport 0:65535;OK
+-m conntrack --ctrepldstport :4;-m conntrack --ctrepldstport 0:4;OK
+-m conntrack --ctrepldstport 4:;-m conntrack --ctrepldstport 4:65535;OK
+-m conntrack --ctrepldstport 3:4;=;OK
+-m conntrack --ctrepldstport 4:4;-m conntrack --ctrepldstport 4;OK
+-m conntrack --ctrepldstport 4:3;;FAIL
diff --git a/extensions/libxt_cpu.man b/extensions/libxt_cpu.man
index c89ef08a..158d50cb 100644
--- a/extensions/libxt_cpu.man
+++ b/extensions/libxt_cpu.man
@@ -1,6 +1,6 @@
 .TP
 [\fB!\fP] \fB\-\-cpu\fP \fInumber\fP
-Match cpu handling this packet. cpus are numbered from 0 to NR_CPUS-1
+Match cpu handling this packet. cpus are numbered from 0 to NR_CPUS\-1
 Can be used in combination with RPS (Remote Packet Steering) or
 multiqueue NICs to spread network traffic on different queues.
 .PP
diff --git a/extensions/libxt_dccp.t b/extensions/libxt_dccp.t
index f60b480f..3655ab6f 100644
--- a/extensions/libxt_dccp.t
+++ b/extensions/libxt_dccp.t
@@ -6,6 +6,16 @@
 -p dccp -m dccp --sport 1:1023;=;OK
 -p dccp -m dccp --sport 1024:65535;=;OK
 -p dccp -m dccp --sport 1024:;-p dccp -m dccp --sport 1024:65535;OK
+-p dccp -m dccp --sport :;-p dccp -m dccp --sport 0:65535;OK
+-p dccp -m dccp --sport :4;-p dccp -m dccp --sport 0:4;OK
+-p dccp -m dccp --sport 4:;-p dccp -m dccp --sport 4:65535;OK
+-p dccp -m dccp --sport 4:4;-p dccp -m dccp --sport 4;OK
+-p dccp -m dccp --sport 4:3;;FAIL
+-p dccp -m dccp --dport :;-p dccp -m dccp --dport 0:65535;OK
+-p dccp -m dccp --dport :4;-p dccp -m dccp --dport 0:4;OK
+-p dccp -m dccp --dport 4:;-p dccp -m dccp --dport 4:65535;OK
+-p dccp -m dccp --dport 4:4;-p dccp -m dccp --dport 4;OK
+-p dccp -m dccp --dport 4:3;;FAIL
 -p dccp -m dccp ! --sport 1;=;OK
 -p dccp -m dccp ! --sport 65535;=;OK
 -p dccp -m dccp ! --dport 1;=;OK
diff --git a/extensions/libxt_dscp.man b/extensions/libxt_dscp.man
index 63a17dac..ff4523fd 100644
--- a/extensions/libxt_dscp.man
+++ b/extensions/libxt_dscp.man
@@ -2,7 +2,7 @@ This module matches the 6 bit DSCP field within the TOS field in the
 IP header.  DSCP has superseded TOS within the IETF.
 .TP
 [\fB!\fP] \fB\-\-dscp\fP \fIvalue\fP
-Match against a numeric (decimal or hex) value [0-63].
+Match against a numeric (decimal or hex) value in the range 0\(en63.
 .TP
 [\fB!\fP] \fB\-\-dscp\-class\fP \fIclass\fP
 Match the DiffServ class. This value may be any of the
diff --git a/extensions/libxt_esp.c b/extensions/libxt_esp.c
index 2c7ff942..8e9766d7 100644
--- a/extensions/libxt_esp.c
+++ b/extensions/libxt_esp.c
@@ -39,13 +39,18 @@ static void esp_parse(struct xt_option_call *cb)
 		espinfo->invflags |= XT_ESP_INV_SPI;
 }
 
+static bool skip_spis_match(uint32_t min, uint32_t max, bool inv)
+{
+	return min == 0 && max == UINT32_MAX && !inv;
+}
+
 static void
 print_spis(const char *name, uint32_t min, uint32_t max,
 	    int invert)
 {
 	const char *inv = invert ? "!" : "";
 
-	if (min != 0 || max != 0xFFFFFFFF || invert) {
+	if (!skip_spis_match(min, max, invert)) {
 		if (min == max)
 			printf(" %s:%s%u", name, inv, min);
 		else
@@ -69,11 +74,10 @@ esp_print(const void *ip, const struct xt_entry_match *match, int numeric)
 static void esp_save(const void *ip, const struct xt_entry_match *match)
 {
 	const struct xt_esp *espinfo = (struct xt_esp *)match->data;
+	bool inv_spi = espinfo->invflags & XT_ESP_INV_SPI;
 
-	if (!(espinfo->spis[0] == 0
-	    && espinfo->spis[1] == 0xFFFFFFFF)) {
-		printf("%s --espspi ",
-			(espinfo->invflags & XT_ESP_INV_SPI) ? " !" : "");
+	if (!skip_spis_match(espinfo->spis[0], espinfo->spis[1], inv_spi)) {
+		printf("%s --espspi ", inv_spi ? " !" : "");
 		if (espinfo->spis[0]
 		    != espinfo->spis[1])
 			printf("%u:%u",
@@ -90,15 +94,21 @@ static int esp_xlate(struct xt_xlate *xl,
 		     const struct xt_xlate_mt_params *params)
 {
 	const struct xt_esp *espinfo = (struct xt_esp *)params->match->data;
+	bool inv_spi = espinfo->invflags & XT_ESP_INV_SPI;
 
-	if (!(espinfo->spis[0] == 0 && espinfo->spis[1] == 0xFFFFFFFF)) {
-		xt_xlate_add(xl, "esp spi%s",
-			   (espinfo->invflags & XT_ESP_INV_SPI) ? " !=" : "");
+	if (!skip_spis_match(espinfo->spis[0], espinfo->spis[1], inv_spi)) {
+		xt_xlate_add(xl, "esp spi%s", inv_spi ? " !=" : "");
 		if (espinfo->spis[0] != espinfo->spis[1])
 			xt_xlate_add(xl, " %u-%u", espinfo->spis[0],
 				   espinfo->spis[1]);
 		else
 			xt_xlate_add(xl, " %u", espinfo->spis[0]);
+	} else if (afinfo->family == NFPROTO_IPV4) {
+		xt_xlate_add(xl, "meta l4proto esp");
+	} else if (afinfo->family == NFPROTO_IPV6) {
+		xt_xlate_add(xl, "exthdr esp exists");
+	} else {
+		return 0;
 	}
 
 	return 1;
diff --git a/extensions/libxt_esp.t b/extensions/libxt_esp.t
index 92c5779f..ece131c9 100644
--- a/extensions/libxt_esp.t
+++ b/extensions/libxt_esp.t
@@ -4,5 +4,12 @@
 -p esp -m esp --espspi 0:4294967295;-p esp -m esp;OK
 -p esp -m esp ! --espspi 0:4294967294;=;OK
 -p esp -m esp --espspi -1;;FAIL
+-p esp -m esp --espspi :;-p esp -m esp;OK
+-p esp -m esp ! --espspi :;-p esp -m esp ! --espspi 0:4294967295;OK
+-p esp -m esp --espspi :4;-p esp -m esp --espspi 0:4;OK
+-p esp -m esp --espspi 4:;-p esp -m esp --espspi 4:4294967295;OK
+-p esp -m esp --espspi 3:4;=;OK
+-p esp -m esp --espspi 4:4;-p esp -m esp --espspi 4;OK
+-p esp -m esp --espspi 4:3;;FAIL
 -p esp -m esp;=;OK
 -m esp;;FAIL
diff --git a/extensions/libxt_esp.txlate b/extensions/libxt_esp.txlate
index f6aba52f..5e8fb241 100644
--- a/extensions/libxt_esp.txlate
+++ b/extensions/libxt_esp.txlate
@@ -9,3 +9,15 @@ nft 'add rule ip filter INPUT esp spi 500 counter drop'
 
 iptables-translate -A INPUT -p 50 -m esp --espspi 500:600 -j DROP
 nft 'add rule ip filter INPUT esp spi 500-600 counter drop'
+
+iptables-translate -A INPUT -p 50 -m esp --espspi 0:4294967295 -j DROP
+nft 'add rule ip filter INPUT meta l4proto esp counter drop'
+
+iptables-translate -A INPUT -p 50 -m esp ! --espspi 0:4294967295 -j DROP
+nft 'add rule ip filter INPUT esp spi != 0-4294967295 counter drop'
+
+ip6tables-translate -A INPUT -p 50 -m esp --espspi 0:4294967295 -j DROP
+nft 'add rule ip6 filter INPUT exthdr esp exists counter drop'
+
+ip6tables-translate -A INPUT -p 50 -m esp ! --espspi 0:4294967295 -j DROP
+nft 'add rule ip6 filter INPUT esp spi != 0-4294967295 counter drop'
diff --git a/extensions/libxt_hashlimit.man b/extensions/libxt_hashlimit.man
index 8a35d564..b95a52d2 100644
--- a/extensions/libxt_hashlimit.man
+++ b/extensions/libxt_hashlimit.man
@@ -20,7 +20,7 @@ Maximum initial number of packets to match: this number gets recharged by one
 every time the limit specified above is not reached, up to this number; the
 default is 5.  When byte-based rate matching is requested, this option specifies
 the amount of bytes that can exceed the given rate.  This option should be used
-with caution -- if the entry expires, the burst value is reset too.
+with caution \(em if the entry expires, the burst value is reset too.
 .TP
 \fB\-\-hashlimit\-mode\fP {\fBsrcip\fP|\fBsrcport\fP|\fBdstip\fP|\fBdstport\fP}\fB,\fP...
 A comma-separated list of objects to take into consideration. If no
@@ -77,8 +77,8 @@ in 10.0.0.0/8" =>
 .TP
 matching bytes per second
 "flows exceeding 512kbyte/s" =>
-\-\-hashlimit-mode srcip,dstip,srcport,dstport \-\-hashlimit\-above 512kb/s
+\-\-hashlimit\-mode srcip,dstip,srcport,dstport \-\-hashlimit\-above 512kb/s
 .TP
 matching bytes per second
 "hosts that exceed 512kbyte/s, but permit up to 1Megabytes without matching"
-\-\-hashlimit-mode dstip \-\-hashlimit\-above 512kb/s \-\-hashlimit-burst 1mb
+\-\-hashlimit\-mode dstip \-\-hashlimit\-above 512kb/s \-\-hashlimit\-burst 1mb
diff --git a/extensions/libxt_helper.man b/extensions/libxt_helper.man
index 772b1350..fb8a206c 100644
--- a/extensions/libxt_helper.man
+++ b/extensions/libxt_helper.man
@@ -1,11 +1,11 @@
-This module matches packets related to a specific conntrack-helper.
+This module matches packets related to a specific conntrack helper.
 .TP
 [\fB!\fP] \fB\-\-helper\fP \fIstring\fP
-Matches packets related to the specified conntrack-helper.
+Matches packets related to the specified conntrack helper.
 .RS
 .PP
-string can be "ftp" for packets related to a ftp-session on default port.
-For other ports append \-portnr to the value, ie. "ftp\-2121".
+string can be "ftp" for packets related to an FTP session on default port.
+For other ports, append \-\-portnr to the value, ie. "ftp\-2121".
 .PP
-Same rules apply for other conntrack-helpers.
+Same rules apply for other conntrack helpers.
 .RE
diff --git a/extensions/libxt_ipcomp.c b/extensions/libxt_ipcomp.c
index 4171c4a1..961c17e5 100644
--- a/extensions/libxt_ipcomp.c
+++ b/extensions/libxt_ipcomp.c
@@ -76,11 +76,12 @@ static void comp_print(const void *ip, const struct xt_entry_match *match,
 static void comp_save(const void *ip, const struct xt_entry_match *match)
 {
 	const struct xt_ipcomp *compinfo = (struct xt_ipcomp *)match->data;
+	bool inv_spi = compinfo->invflags & XT_IPCOMP_INV_SPI;
 
 	if (!(compinfo->spis[0] == 0
-	    && compinfo->spis[1] == 0xFFFFFFFF)) {
-		printf("%s --ipcompspi ",
-			(compinfo->invflags & XT_IPCOMP_INV_SPI) ? " !" : "");
+	    && compinfo->spis[1] == UINT32_MAX
+	    && !inv_spi)) {
+		printf("%s --ipcompspi ", inv_spi ? " !" : "");
 		if (compinfo->spis[0]
 		    != compinfo->spis[1])
 			printf("%u:%u",
diff --git a/extensions/libxt_ipcomp.t b/extensions/libxt_ipcomp.t
index 8546ba9c..e25695c6 100644
--- a/extensions/libxt_ipcomp.t
+++ b/extensions/libxt_ipcomp.t
@@ -1,3 +1,10 @@
 :INPUT,OUTPUT
 -p ipcomp -m ipcomp --ipcompspi 18 -j DROP;=;OK
 -p ipcomp -m ipcomp ! --ipcompspi 18 -j ACCEPT;=;OK
+-p ipcomp -m ipcomp --ipcompspi :;-p ipcomp -m ipcomp;OK
+-p ipcomp -m ipcomp ! --ipcompspi :;-p ipcomp -m ipcomp ! --ipcompspi 0:4294967295;OK
+-p ipcomp -m ipcomp --ipcompspi :4;-p ipcomp -m ipcomp --ipcompspi 0:4;OK
+-p ipcomp -m ipcomp --ipcompspi 4:;-p ipcomp -m ipcomp --ipcompspi 4:4294967295;OK
+-p ipcomp -m ipcomp --ipcompspi 3:4;=;OK
+-p ipcomp -m ipcomp --ipcompspi 4:4;-p ipcomp -m ipcomp --ipcompspi 4;OK
+-p ipcomp -m ipcomp --ipcompspi 4:3;;FAIL
diff --git a/extensions/libxt_iprange.t b/extensions/libxt_iprange.t
index 6fd98be6..83a67d11 100644
--- a/extensions/libxt_iprange.t
+++ b/extensions/libxt_iprange.t
@@ -1,11 +1,2 @@
 :INPUT,FORWARD,OUTPUT
--m iprange --src-range 1.1.1.1-1.1.1.10;=;OK
--m iprange ! --src-range 1.1.1.1-1.1.1.10;=;OK
--m iprange --dst-range 1.1.1.1-1.1.1.10;=;OK
--m iprange ! --dst-range 1.1.1.1-1.1.1.10;=;OK
-# it shows -A INPUT -m iprange --src-range 1.1.1.1-1.1.1.1, should we support this?
-# ERROR: should fail: iptables -A INPUT -m iprange --src-range 1.1.1.1
-# -m iprange --src-range 1.1.1.1;;FAIL
-# ERROR: should fail: iptables -A INPUT -m iprange --dst-range 1.1.1.1
-#-m iprange --dst-range 1.1.1.1;;FAIL
 -m iprange;;FAIL
diff --git a/extensions/libxt_ipvs.t b/extensions/libxt_ipvs.t
index c2acc666..a76a6967 100644
--- a/extensions/libxt_ipvs.t
+++ b/extensions/libxt_ipvs.t
@@ -4,8 +4,6 @@
 -m ipvs --vproto tcp;-m ipvs --vproto 6;OK
 -m ipvs ! --vproto TCP;-m ipvs ! --vproto 6;OK
 -m ipvs --vproto 23;=;OK
--m ipvs --vaddr 1.2.3.4;=;OK
--m ipvs ! --vaddr 1.2.3.4/255.255.255.0;-m ipvs ! --vaddr 1.2.3.4/24;OK
 -m ipvs --vport http;-m ipvs --vport 80;OK
 -m ipvs ! --vport ssh;-m ipvs ! --vport 22;OK
 -m ipvs --vport 22;=;OK
@@ -17,4 +15,3 @@
 -m ipvs --vmethod MASQ;=;OK
 -m ipvs --vportctl 21;=;OK
 -m ipvs ! --vportctl 21;=;OK
--m ipvs --vproto 6 --vaddr 1.2.3.4/16 --vport 22 --vdir ORIGINAL --vmethod GATE;=;OK
diff --git a/extensions/libxt_length.t b/extensions/libxt_length.t
index 8b70fc31..bae313b4 100644
--- a/extensions/libxt_length.t
+++ b/extensions/libxt_length.t
@@ -3,8 +3,11 @@
 -m length --length :2;-m length --length 0:2;OK
 -m length --length 0:3;=;OK
 -m length --length 4:;-m length --length 4:65535;OK
+-m length --length :;-m length --length 0:65535;OK
 -m length --length 0:65535;=;OK
 -m length ! --length 0:65535;=;OK
 -m length --length 0:65536;;FAIL
 -m length --length -1:65535;;FAIL
+-m length --length 4:4;-m length --length 4;OK
+-m length --length 4:3;;FAIL
 -m length;;FAIL
diff --git a/extensions/libxt_limit.c b/extensions/libxt_limit.c
index e6ec67f3..63f3289d 100644
--- a/extensions/libxt_limit.c
+++ b/extensions/libxt_limit.c
@@ -7,7 +7,6 @@
 #define _DEFAULT_SOURCE 1
 #define _ISOC99_SOURCE 1
 #include <errno.h>
-#include <getopt.h>
 #include <math.h>
 #include <stdio.h>
 #include <string.h>
@@ -202,44 +201,6 @@ static int limit_xlate_eb(struct xt_xlate *xl,
 	return 1;
 }
 
-#define FLAG_LIMIT		0x01
-#define FLAG_LIMIT_BURST	0x02
-#define ARG_LIMIT		'1'
-#define ARG_LIMIT_BURST		'2'
-
-static int brlimit_parse(int c, char **argv, int invert, unsigned int *flags,
-			 const void *entry, struct xt_entry_match **match)
-{
-	struct xt_rateinfo *r = (struct xt_rateinfo *)(*match)->data;
-	uintmax_t num;
-
-	switch (c) {
-	case ARG_LIMIT:
-		EBT_CHECK_OPTION(flags, FLAG_LIMIT);
-		if (invert)
-			xtables_error(PARAMETER_PROBLEM,
-				      "Unexpected `!' after --limit");
-		if (!parse_rate(optarg, &r->avg))
-			xtables_error(PARAMETER_PROBLEM,
-				      "bad rate `%s'", optarg);
-		break;
-	case ARG_LIMIT_BURST:
-		EBT_CHECK_OPTION(flags, FLAG_LIMIT_BURST);
-		if (invert)
-			xtables_error(PARAMETER_PROBLEM,
-				      "Unexpected `!' after --limit-burst");
-		if (!xtables_strtoul(optarg, NULL, &num, 0, 10000))
-			xtables_error(PARAMETER_PROBLEM,
-				      "bad --limit-burst `%s'", optarg);
-		r->burst = num;
-		break;
-	default:
-		return 0;
-	}
-
-	return 1;
-}
-
 static void brlimit_print(const void *ip, const struct xt_entry_match *match,
 			  int numeric)
 {
@@ -250,13 +211,6 @@ static void brlimit_print(const void *ip, const struct xt_entry_match *match,
 	printf(" --limit-burst %u ", r->burst);
 }
 
-static const struct option brlimit_opts[] =
-{
-	{ .name = "limit",	.has_arg = true,	.val = ARG_LIMIT },
-	{ .name = "limit-burst",.has_arg = true,	.val = ARG_LIMIT_BURST },
-	XT_GETOPT_TABLEEND,
-};
-
 static struct xtables_match limit_match[] = {
 	{
 		.family		= NFPROTO_UNSPEC,
@@ -280,9 +234,9 @@ static struct xtables_match limit_match[] = {
 		.userspacesize	= offsetof(struct xt_rateinfo, prev),
 		.help		= limit_help,
 		.init		= limit_init,
-		.parse		= brlimit_parse,
+		.x6_parse	= limit_parse,
 		.print		= brlimit_print,
-		.extra_opts	= brlimit_opts,
+		.x6_options	= limit_opts,
 		.xlate		= limit_xlate_eb,
 	},
 };
diff --git a/extensions/libxt_limit.man b/extensions/libxt_limit.man
index 6fb94ccf..b477dd94 100644
--- a/extensions/libxt_limit.man
+++ b/extensions/libxt_limit.man
@@ -4,7 +4,7 @@ It can be used in combination with the
 .B LOG
 target to give limited logging, for example.
 .PP
-xt_limit has no negation support - you will have to use \-m hashlimit !
+xt_limit has no negation support \(em you will have to use \-m hashlimit !
 \-\-hashlimit \fIrate\fP in this case whilst omitting \-\-hashlimit\-mode.
 .TP
 \fB\-\-limit\fP \fIrate\fP[\fB/second\fP|\fB/minute\fP|\fB/hour\fP|\fB/day\fP]
diff --git a/extensions/libxt_mark.t b/extensions/libxt_mark.t
index 12c05865..b8dc3cb3 100644
--- a/extensions/libxt_mark.t
+++ b/extensions/libxt_mark.t
@@ -5,4 +5,4 @@
 -m mark --mark 4294967296;;FAIL
 -m mark --mark -1;;FAIL
 -m mark;;FAIL
--s 1.2.0.0/15 -m mark --mark 0x0/0xff0;=;OK
+-m mark --mark 0x0/0xff0;=;OK
diff --git a/extensions/libxt_multiport.c b/extensions/libxt_multiport.c
index f3136d8a..813a3555 100644
--- a/extensions/libxt_multiport.c
+++ b/extensions/libxt_multiport.c
@@ -248,7 +248,7 @@ static void multiport_parse6_v1(struct xt_option_call *cb)
 static void multiport_check(struct xt_fcheck_call *cb)
 {
 	if (cb->xflags == 0)
-		xtables_error(PARAMETER_PROBLEM, "multiport expection an option");
+		xtables_error(PARAMETER_PROBLEM, "no ports specified");
 }
 
 static const char *
diff --git a/extensions/libxt_nfacct.man b/extensions/libxt_nfacct.man
index a818fedd..4e05891e 100644
--- a/extensions/libxt_nfacct.man
+++ b/extensions/libxt_nfacct.man
@@ -22,7 +22,7 @@ Then, you can check for the amount of traffic that the rules match:
 .IP
 nfacct get http\-traffic
 .IP
-{ pkts = 00000000000000000156, bytes = 00000000000000151786 } = http-traffic;
+{ pkts = 00000000000000000156, bytes = 00000000000000151786 } = http\-traffic;
 .PP
 You can obtain
 .B nfacct(8)
diff --git a/extensions/libxt_osf.man b/extensions/libxt_osf.man
index 41103f29..85c1a3b4 100644
--- a/extensions/libxt_osf.man
+++ b/extensions/libxt_osf.man
@@ -8,29 +8,39 @@ Match an operating system genre by using a passive fingerprinting.
 \fB\-\-ttl\fP \fIlevel\fP
 Do additional TTL checks on the packet to determine the operating system.
 \fIlevel\fP can be one of the following values:
-.IP \(bu 4
-0 - True IP address and fingerprint TTL comparison. This generally works for
+.RS
+.TP
+\fB0\fP
+True IP address and fingerprint TTL comparison. This generally works for
 LANs.
-.IP \(bu 4
-1 - Check if the IP header's TTL is less than the fingerprint one. Works for
+.TP
+\fB1\fP
+Check if the IP header's TTL is less than the fingerprint one. Works for
 globally-routable addresses.
-.IP \(bu 4
-2 - Do not compare the TTL at all.
+.TP
+\fB2\fP
+Do not compare the TTL at all.
+.RE
 .TP
 \fB\-\-log\fP \fIlevel\fP
 Log determined genres into dmesg even if they do not match the desired one.
 \fIlevel\fP can be one of the following values:
-.IP \(bu 4
-0 - Log all matched or unknown signatures
-.IP \(bu 4
-1 - Log only the first one
-.IP \(bu 4
-2 - Log all known matched signatures
+.RS
+.TP
+\fB0\fP
+Log all matched or unknown signatures
+.TP
+\fB1\fP
+Log only the first one
+.TP
+\fB2\fP
+Log all known matched signatures
+.RE
 .PP
 You may find something like this in syslog:
 .PP
-Windows [2000:SP3:Windows XP Pro SP1, 2000 SP3]: 11.22.33.55:4024 ->
-11.22.33.44:139 hops=3 Linux [2.5-2.6:] : 1.2.3.4:42624 -> 1.2.3.5:22 hops=4
+Windows [2000:SP3:Windows XP Pro SP1, 2000 SP3]: 11.22.33.55:4024 \->
+11.22.33.44:139 hops=3 Linux [2.5\-2.6:] : 1.2.3.4:42624 \-> 1.2.3.5:22 hops=4
 .PP
 OS fingerprints are loadable using the \fBnfnl_osf\fP program. To load
 fingerprints from a file, use:
@@ -42,4 +52,4 @@ To remove them again,
 \fBnfnl_osf \-f /usr/share/xtables/pf.os \-d\fP
 .PP
 The fingerprint database can be downloaded from
-http://www.openbsd.org/cgi-bin/cvsweb/src/etc/pf.os .
+http://www.openbsd.org/cgi\-bin/cvsweb/src/etc/pf.os .
diff --git a/extensions/libxt_owner.man b/extensions/libxt_owner.man
index e2479865..fd6fe190 100644
--- a/extensions/libxt_owner.man
+++ b/extensions/libxt_owner.man
@@ -16,7 +16,7 @@ Matches if the packet socket's file structure is owned by the given group.
 You may also specify a numerical GID, or a GID range.
 .TP
 \fB\-\-suppl\-groups\fP
-Causes group(s) specified with \fB\-\-gid-owner\fP to be also checked in the
+Causes group(s) specified with \fB\-\-gid\-owner\fP to be also checked in the
 supplementary groups of a process.
 .TP
 [\fB!\fP] \fB\-\-socket\-exists\fP
diff --git a/extensions/libxt_policy.t b/extensions/libxt_policy.t
index 6524122b..fea708bb 100644
--- a/extensions/libxt_policy.t
+++ b/extensions/libxt_policy.t
@@ -3,6 +3,3 @@
 -m policy --dir in --pol ipsec --proto ipcomp;=;OK
 -m policy --dir in --pol ipsec --strict;;FAIL
 -m policy --dir in --pol ipsec --strict --reqid 1 --spi 0x1 --proto ipcomp;=;OK
--m policy --dir in --pol ipsec --strict --reqid 1 --spi 0x1 --proto esp --mode tunnel --tunnel-dst 10.0.0.0/8 --tunnel-src 10.0.0.0/8 --next --reqid 2;=;OK
--m policy --dir in --pol ipsec --strict --reqid 1 --spi 0x1 --proto esp --tunnel-dst 10.0.0.0/8;;FAIL
--m policy --dir in --pol ipsec --strict --reqid 1 --spi 0x1 --proto ipcomp --mode tunnel --tunnel-dst 10.0.0.0/8 --tunnel-src 10.0.0.0/8 --next --reqid 2;=;OK
diff --git a/extensions/libxt_rateest.man b/extensions/libxt_rateest.man
index 42a82f32..b1779eb3 100644
--- a/extensions/libxt_rateest.man
+++ b/extensions/libxt_rateest.man
@@ -4,22 +4,26 @@ estimators and matching on the difference between two rate estimators.
 .PP
 For a better understanding of the available options, these are all possible
 combinations:
-.\" * Absolute:
+.TP
+Absolute:
 .IP \(bu 4
 \fBrateest\fP \fIoperator\fP \fBrateest-bps\fP
 .IP \(bu 4
 \fBrateest\fP \fIoperator\fP \fBrateest-pps\fP
-.\" * Absolute + Delta:
+.TP
+Absolute + Delta:
 .IP \(bu 4
 (\fBrateest\fP minus \fBrateest-bps1\fP) \fIoperator\fP \fBrateest-bps2\fP
 .IP \(bu 4
 (\fBrateest\fP minus \fBrateest-pps1\fP) \fIoperator\fP \fBrateest-pps2\fP
-.\" * Relative:
+.TP
+Relative:
 .IP \(bu 4
 \fBrateest1\fP \fIoperator\fP \fBrateest2\fP \fBrateest-bps\fP(without rate!)
 .IP \(bu 4
 \fBrateest1\fP \fIoperator\fP \fBrateest2\fP \fBrateest-pps\fP(without rate!)
-.\" * Relative + Delta:
+.TP
+Relative + Delta:
 .IP \(bu 4
 (\fBrateest1\fP minus \fBrateest-bps1\fP) \fIoperator\fP
 (\fBrateest2\fP minus \fBrateest-bps2\fP)
@@ -31,7 +35,7 @@ combinations:
 For each estimator (either absolute or relative mode), calculate the difference
 between the estimator-determined flow rate and the static value chosen with the
 BPS/PPS options. If the flow rate is higher than the specified BPS/PPS, 0 will
-be used instead of a negative value. In other words, "max(0, rateest#_rate -
+be used instead of a negative value. In other words, "max(0, rateest#_rate \-
 rateest#_bps)" is used.
 .TP
 [\fB!\fP] \fB\-\-rateest\-lt\fP
@@ -68,7 +72,7 @@ The names of the two rate estimators for relative mode.
 \fB\-\-rateest\-pps2\fP [\fIvalue\fP]
 Compare the estimator(s) by bytes or packets per second, and compare against
 the chosen value. See the above bullet list for which option is to be used in
-which case. A unit suffix may be used - available ones are: bit, [kmgt]bit,
+which case. A unit suffix may be used \(em available ones are: bit, [kmgt]bit,
 [KMGT]ibit, Bps, [KMGT]Bps, [KMGT]iBps.
 .PP
 Example: This is what can be used to route outgoing data connections from an
diff --git a/extensions/libxt_recent.c b/extensions/libxt_recent.c
index 055ae350..0221d446 100644
--- a/extensions/libxt_recent.c
+++ b/extensions/libxt_recent.c
@@ -193,10 +193,12 @@ static void recent_print(const void *ip, const struct xt_entry_match *match,
 		printf(" UPDATE");
 	if (info->check_set & XT_RECENT_REMOVE)
 		printf(" REMOVE");
-	if(info->seconds) printf(" seconds: %d", info->seconds);
+	if (info->seconds)
+		printf(" seconds: %u", info->seconds);
 	if (info->check_set & XT_RECENT_REAP)
 		printf(" reap");
-	if(info->hit_count) printf(" hit_count: %d", info->hit_count);
+	if (info->hit_count)
+		printf(" hit_count: %u", info->hit_count);
 	if (info->check_set & XT_RECENT_TTL)
 		printf(" TTL-Match");
 	printf(" name: %s", info->name);
@@ -233,10 +235,12 @@ static void recent_save(const void *ip, const struct xt_entry_match *match,
 		printf(" --update");
 	if (info->check_set & XT_RECENT_REMOVE)
 		printf(" --remove");
-	if(info->seconds) printf(" --seconds %d", info->seconds);
+	if (info->seconds)
+		printf(" --seconds %u", info->seconds);
 	if (info->check_set & XT_RECENT_REAP)
 		printf(" --reap");
-	if(info->hit_count) printf(" --hitcount %d", info->hit_count);
+	if (info->hit_count)
+		printf(" --hitcount %u", info->hit_count);
 	if (info->check_set & XT_RECENT_TTL)
 		printf(" --rttl");
 	printf(" --name %s",info->name);
diff --git a/extensions/libxt_recent.man b/extensions/libxt_recent.man
index 419be257..e0305f98 100644
--- a/extensions/libxt_recent.man
+++ b/extensions/libxt_recent.man
@@ -55,9 +55,7 @@ This option must be used in conjunction with one of \fB\-\-rcheck\fP or
 address is in the list and packets had been received greater than or equal to
 the given value. This option may be used along with \fB\-\-seconds\fP to create
 an even narrower match requiring a certain number of hits within a specific
-time frame. The maximum value for the hitcount parameter is given by the
-"ip_pkt_list_tot" parameter of the xt_recent kernel module. Exceeding this
-value on the command line will cause the rule to be rejected.
+time frame.
 .TP
 \fB\-\-rttl\fP
 This option may only be used in conjunction with one of \fB\-\-rcheck\fP or
@@ -93,11 +91,15 @@ The module itself accepts parameters, defaults shown:
 \fBip_list_tot\fP=\fI100\fP
 Number of addresses remembered per table.
 .TP
-\fBip_pkt_list_tot\fP=\fI20\fP
-Number of packets per address remembered.
+\fBip_pkt_list_tot\fP=\fI0\fP
+Number of packets per address remembered. This parameter is obsolete since
+kernel version 3.19 which started to calculate the table size based on given
+\fB\-\-hitcount\fP parameter.
 .TP
 \fBip_list_hash_size\fP=\fI0\fP
-Hash table size. 0 means to calculate it based on ip_list_tot, default: 512.
+Hash table size. 0 means to calculate it based on ip_list_tot by rounding it up
+to the next power of two (with \fBip_list_tot\fP defaulting to \fI100\fP,
+\fBip_list_hash_size\fP will calculate to \fI128\fP by default).
 .TP
 \fBip_list_perms\fP=\fI0644\fP
 Permissions for /proc/net/xt_recent/* files.
diff --git a/extensions/libxt_recent.t b/extensions/libxt_recent.t
index cf23aabc..6c2cbd23 100644
--- a/extensions/libxt_recent.t
+++ b/extensions/libxt_recent.t
@@ -1,11 +1,2 @@
 :INPUT,FORWARD,OUTPUT
--m recent --set;-m recent --set --name DEFAULT --mask 255.255.255.255 --rsource;OK
--m recent --rcheck --hitcount 8 --name foo --mask 255.255.255.255 --rsource;=;OK
--m recent --rcheck --hitcount 12 --name foo --mask 255.255.255.255 --rsource;=;OK
--m recent --update --rttl;-m recent --update --rttl --name DEFAULT --mask 255.255.255.255 --rsource;OK
 -m recent --set --rttl;;FAIL
--m recent --rcheck --hitcount 999 --name foo --mask 255.255.255.255 --rsource;;FAIL
-# nonsensical, but all should load successfully:
--m recent --rcheck --hitcount 3 --name foo --mask 255.255.255.255 --rsource -m recent --rcheck --hitcount 4 --name foo --mask 255.255.255.255 --rsource;=;OK
--m recent --rcheck --hitcount 4 --name foo --mask 255.255.255.255 --rsource -m recent --rcheck --hitcount 4 --name foo --mask 255.255.255.255 --rsource;=;OK
--m recent --rcheck --hitcount 8 --name foo --mask 255.255.255.255 --rsource -m recent --rcheck --hitcount 12 --name foo --mask 255.255.255.255 --rsource;=;OK
diff --git a/extensions/libxt_sctp.c b/extensions/libxt_sctp.c
index 6e2b2745..e8312f0c 100644
--- a/extensions/libxt_sctp.c
+++ b/extensions/libxt_sctp.c
@@ -7,6 +7,7 @@
  * libipt_ecn.c borrowed heavily from libipt_dscp.c
  *
  */
+#include <assert.h>
 #include <stdbool.h>
 #include <stdio.h>
 #include <string.h>
@@ -354,6 +355,7 @@ print_chunk_flags(uint32_t chunknum, uint8_t chunk_flags, uint8_t chunk_flags_ma
 
 	for (i = 7; i >= 0; i--) {
 		if (chunk_flags_mask & (1 << i)) {
+			assert(chunknum < ARRAY_SIZE(sctp_chunk_names));
 			if (chunk_flags & (1 << i)) {
 				printf("%c", sctp_chunk_names[chunknum].valid_flags[7-i]);
 			} else {
diff --git a/extensions/libxt_set.h b/extensions/libxt_set.h
index 685bfab9..b7de4cc4 100644
--- a/extensions/libxt_set.h
+++ b/extensions/libxt_set.h
@@ -146,7 +146,7 @@ parse_dirs_v0(const char *opt_arg, struct xt_set_info_v0 *info)
 			info->u.flags[i++] |= IPSET_DST;
 		else
 			xtables_error(PARAMETER_PROBLEM,
-				"You must spefify (the comma separated list of) 'src' or 'dst'.");
+				"You must specify (the comma separated list of) 'src' or 'dst'.");
 	}
 
 	if (tmp)
@@ -170,7 +170,7 @@ parse_dirs(const char *opt_arg, struct xt_set_info *info)
 			info->flags |= (1 << info->dim);
 		else if (strncmp(ptr, "dst", 3) != 0)
 			xtables_error(PARAMETER_PROBLEM,
-				"You must spefify (the comma separated list of) 'src' or 'dst'.");
+				"You must specify (the comma separated list of) 'src' or 'dst'.");
 	}
 
 	if (tmp)
diff --git a/extensions/libxt_socket.c b/extensions/libxt_socket.c
index a99135cd..2dcfa221 100644
--- a/extensions/libxt_socket.c
+++ b/extensions/libxt_socket.c
@@ -159,6 +159,37 @@ socket_mt_print_v3(const void *ip, const struct xt_entry_match *match,
 	socket_mt_save_v3(ip, match);
 }
 
+static int socket_mt_xlate(struct xt_xlate *xl, const struct xt_xlate_mt_params *params)
+{
+	const struct xt_socket_mtinfo3 *info = (const void *)params->match->data;
+
+	/* ONLY --nowildcard: match if socket exists. It does not matter
+	 * to which address it is bound.
+	 */
+	if (info->flags == XT_SOCKET_NOWILDCARD) {
+		xt_xlate_add(xl, "socket wildcard le 1");
+		return 1;
+	}
+
+	/* Without --nowildcard, restrict to sockets NOT bound to
+	 * the any address.
+	 */
+	if ((info->flags & XT_SOCKET_NOWILDCARD) == 0)
+		xt_xlate_add(xl, "socket wildcard 0");
+
+	if (info->flags & XT_SOCKET_TRANSPARENT)
+		xt_xlate_add(xl, "socket transparent 1");
+
+	/* If --nowildcard was given, -m socket should not test
+	 * the bound address.  We can simply ignore this; its
+	 * equal to "wildcard <= 1".
+	 */
+	if (info->flags & XT_SOCKET_RESTORESKMARK)
+		xt_xlate_add(xl, "meta mark set socket mark");
+
+	return 1;
+}
+
 static struct xtables_match socket_mt_reg[] = {
 	{
 		.name          = "socket",
@@ -180,6 +211,7 @@ static struct xtables_match socket_mt_reg[] = {
 		.save          = socket_mt_save,
 		.x6_parse      = socket_mt_parse,
 		.x6_options    = socket_mt_opts,
+		.xlate	       = socket_mt_xlate,
 	},
 	{
 		.name          = "socket",
@@ -193,6 +225,7 @@ static struct xtables_match socket_mt_reg[] = {
 		.save          = socket_mt_save_v2,
 		.x6_parse      = socket_mt_parse_v2,
 		.x6_options    = socket_mt_opts_v2,
+		.xlate	       = socket_mt_xlate,
 	},
 	{
 		.name          = "socket",
@@ -206,6 +239,7 @@ static struct xtables_match socket_mt_reg[] = {
 		.save          = socket_mt_save_v3,
 		.x6_parse      = socket_mt_parse_v3,
 		.x6_options    = socket_mt_opts_v3,
+		.xlate	       = socket_mt_xlate,
 	},
 };
 
diff --git a/extensions/libxt_socket.man b/extensions/libxt_socket.man
index f809df69..a268b443 100644
--- a/extensions/libxt_socket.man
+++ b/extensions/libxt_socket.man
@@ -29,7 +29,7 @@ to be matched when restoring the packet mark.
 Example: An application opens 2 transparent (\fBIP_TRANSPARENT\fP) sockets and
 sets a mark on them with \fBSO_MARK\fP socket option. We can filter matching packets:
 .IP
-\-t mangle \-I PREROUTING \-m socket \-\-transparent \-\-restore-skmark \-j action
+\-t mangle \-I PREROUTING \-m socket \-\-transparent \-\-restore\-skmark \-j action
 .IP
 \-t mangle \-A action \-m mark \-\-mark 10 \-j action2
 .IP
diff --git a/extensions/libxt_socket.txlate b/extensions/libxt_socket.txlate
new file mode 100644
index 00000000..7731e42e
--- /dev/null
+++ b/extensions/libxt_socket.txlate
@@ -0,0 +1,17 @@
+# old socket match, no options.  Matches if sk can be found and it is not bound to 0.0.0.0/::
+iptables-translate -A INPUT -m socket
+nft 'add rule ip filter INPUT socket wildcard 0 counter'
+
+iptables-translate -A INPUT -m socket --transparent
+nft 'add rule ip filter INPUT socket wildcard 0 socket transparent 1 counter'
+
+# Matches if sk can be found.  Doesn't matter as to what addess it is bound to.
+# therefore, emulate "exists".
+iptables-translate -A INPUT -m socket --nowildcard
+nft 'add rule ip filter INPUT socket wildcard le 1 counter'
+
+iptables-translate -A INPUT -m socket --restore-skmark
+nft 'add rule ip filter INPUT socket wildcard 0 meta mark set socket mark counter'
+
+iptables-translate -A INPUT -m socket --transparent --nowildcard --restore-skmark
+nft 'add rule ip filter INPUT socket transparent 1 meta mark set socket mark counter'
diff --git a/extensions/libxt_standard.t b/extensions/libxt_standard.t
index 7c83cfa3..947e92af 100644
--- a/extensions/libxt_standard.t
+++ b/extensions/libxt_standard.t
@@ -1,28 +1,9 @@
 :INPUT,FORWARD,OUTPUT
--s 127.0.0.1/32 -d 0.0.0.0/8 -j DROP;=;OK
-! -s 0.0.0.0 -j ACCEPT;! -s 0.0.0.0/32 -j ACCEPT;OK
-! -d 0.0.0.0/32 -j ACCEPT;=;OK
--s 0.0.0.0/24 -j RETURN;=;OK
 -p tcp -j ACCEPT;=;OK
 ! -p udp -j ACCEPT;=;OK
 -j DROP;=;OK
 -j ACCEPT;=;OK
 -j RETURN;=;OK
 ! -p 0 -j ACCEPT;=;FAIL
--s 10.11.12.13/8;-s 10.0.0.0/8;OK
--s 10.11.12.13/9;-s 10.0.0.0/9;OK
--s 10.11.12.13/10;-s 10.0.0.0/10;OK
--s 10.11.12.13/11;-s 10.0.0.0/11;OK
--s 10.11.12.13/12;-s 10.0.0.0/12;OK
--s 10.11.12.13/30;-s 10.11.12.12/30;OK
--s 10.11.12.13/31;-s 10.11.12.12/31;OK
--s 10.11.12.13/32;-s 10.11.12.13/32;OK
--s 10.11.12.13/255.0.0.0;-s 10.0.0.0/8;OK
--s 10.11.12.13/255.128.0.0;-s 10.0.0.0/9;OK
--s 10.11.12.13/255.0.255.0;-s 10.0.12.0/255.0.255.0;OK
--s 10.11.12.13/255.0.12.0;-s 10.0.12.0/255.0.12.0;OK
 :FORWARD
---protocol=tcp --source=1.2.3.4 --destination=5.6.7.8/32 --in-interface=eth0 --out-interface=eth1 --jump=ACCEPT;-s 1.2.3.4/32 -d 5.6.7.8/32 -i eth0 -o eth1 -p tcp -j ACCEPT;OK
--ptcp -s1.2.3.4 -d5.6.7.8/32 -ieth0 -oeth1 -jACCEPT;-s 1.2.3.4/32 -d 5.6.7.8/32 -i eth0 -o eth1 -p tcp -j ACCEPT;OK
--i + -d 1.2.3.4;-d 1.2.3.4/32;OK
 -i + -p tcp;-p tcp;OK
diff --git a/extensions/libxt_string.man b/extensions/libxt_string.man
index efdda492..bdeb0a62 100644
--- a/extensions/libxt_string.man
+++ b/extensions/libxt_string.man
@@ -7,13 +7,10 @@ Select the pattern matching strategy. (bm = Boyer-Moore, kmp = Knuth-Pratt-Morri
 Set the offset from which it starts looking for any matching. If not passed, default is 0.
 .TP
 \fB\-\-to\fP \fIoffset\fP
-Set the offset up to which should be scanned. If the pattern does not start
-within this offset, it is not considered a match.
+Set the offset up to which should be scanned. That is, byte \fIoffset\fP
+(counting from 0) is the last one that is scanned and the maximum position of
+\fIpattern\fP's last character.
 If not passed, default is the packet size.
-A second function of this parameter is instructing the kernel how much data
-from the packet should be provided. With non-linear skbuffs (e.g. due to
-fragmentation), a pattern extending past this offset may not be found. Also see
-the related note below about Boyer-Moore algorithm in these cases.
 .TP
 [\fB!\fP] \fB\-\-string\fP \fIpattern\fP
 Matches the given pattern.
diff --git a/extensions/libxt_tcp.c b/extensions/libxt_tcp.c
index f8257282..32bbd684 100644
--- a/extensions/libxt_tcp.c
+++ b/extensions/libxt_tcp.c
@@ -225,13 +225,18 @@ print_port(uint16_t port, int numeric)
 		printf("%s", service);
 }
 
+static bool skip_ports_match(uint16_t min, uint16_t max, bool inv)
+{
+	return min == 0 && max == UINT16_MAX && !inv;
+}
+
 static void
 print_ports(const char *name, uint16_t min, uint16_t max,
 	    int invert, int numeric)
 {
 	const char *inv = invert ? "!" : "";
 
-	if (min != 0 || max != 0xFFFF || invert) {
+	if (!skip_ports_match(min, max, invert)) {
 		printf(" %s", name);
 		if (min == max) {
 			printf(":%s", inv);
@@ -315,10 +320,11 @@ tcp_print(const void *ip, const struct xt_entry_match *match, int numeric)
 static void tcp_save(const void *ip, const struct xt_entry_match *match)
 {
 	const struct xt_tcp *tcpinfo = (struct xt_tcp *)match->data;
+	bool inv_srcpt = tcpinfo->invflags & XT_TCP_INV_SRCPT;
+	bool inv_dstpt = tcpinfo->invflags & XT_TCP_INV_DSTPT;
 
-	if (tcpinfo->spts[0] != 0
-	    || tcpinfo->spts[1] != 0xFFFF) {
-		if (tcpinfo->invflags & XT_TCP_INV_SRCPT)
+	if (!skip_ports_match(tcpinfo->spts[0], tcpinfo->spts[1], inv_srcpt)) {
+		if (inv_srcpt)
 			printf(" !");
 		if (tcpinfo->spts[0]
 		    != tcpinfo->spts[1])
@@ -330,9 +336,8 @@ static void tcp_save(const void *ip, const struct xt_entry_match *match)
 			       tcpinfo->spts[0]);
 	}
 
-	if (tcpinfo->dpts[0] != 0
-	    || tcpinfo->dpts[1] != 0xFFFF) {
-		if (tcpinfo->invflags & XT_TCP_INV_DSTPT)
+	if (!skip_ports_match(tcpinfo->dpts[0], tcpinfo->dpts[1], inv_dstpt)) {
+		if (inv_dstpt)
 			printf(" !");
 		if (tcpinfo->dpts[0]
 		    != tcpinfo->dpts[1])
@@ -397,39 +402,42 @@ static int tcp_xlate(struct xt_xlate *xl,
 {
 	const struct xt_tcp *tcpinfo =
 		(const struct xt_tcp *)params->match->data;
+	bool inv_srcpt = tcpinfo->invflags & XT_TCP_INV_SRCPT;
+	bool inv_dstpt = tcpinfo->invflags & XT_TCP_INV_DSTPT;
+	bool xlated = false;
 
-	if (tcpinfo->spts[0] != 0 || tcpinfo->spts[1] != 0xffff) {
+	if (!skip_ports_match(tcpinfo->spts[0], tcpinfo->spts[1], inv_srcpt)) {
 		if (tcpinfo->spts[0] != tcpinfo->spts[1]) {
 			xt_xlate_add(xl, "tcp sport %s%u-%u",
-				   tcpinfo->invflags & XT_TCP_INV_SRCPT ?
-					"!= " : "",
+				   inv_srcpt ? "!= " : "",
 				   tcpinfo->spts[0], tcpinfo->spts[1]);
 		} else {
 			xt_xlate_add(xl, "tcp sport %s%u",
-				   tcpinfo->invflags & XT_TCP_INV_SRCPT ?
-					"!= " : "",
+				   inv_srcpt ? "!= " : "",
 				   tcpinfo->spts[0]);
 		}
+		xlated = true;
 	}
 
-	if (tcpinfo->dpts[0] != 0 || tcpinfo->dpts[1] != 0xffff) {
+	if (!skip_ports_match(tcpinfo->dpts[0], tcpinfo->dpts[1], inv_dstpt)) {
 		if (tcpinfo->dpts[0] != tcpinfo->dpts[1]) {
 			xt_xlate_add(xl, "tcp dport %s%u-%u",
-				   tcpinfo->invflags & XT_TCP_INV_DSTPT ?
-					"!= " : "",
+				   inv_dstpt ? "!= " : "",
 				   tcpinfo->dpts[0], tcpinfo->dpts[1]);
 		} else {
 			xt_xlate_add(xl, "tcp dport %s%u",
-				   tcpinfo->invflags & XT_TCP_INV_DSTPT ?
-					"!= " : "",
+				   inv_dstpt ? "!= " : "",
 				   tcpinfo->dpts[0]);
 		}
+		xlated = true;
 	}
 
-	if (tcpinfo->option)
+	if (tcpinfo->option) {
 		xt_xlate_add(xl, "tcp option %u %s", tcpinfo->option,
 			     tcpinfo->invflags & XT_TCP_INV_OPTION ?
 			     "missing" : "exists");
+		xlated = true;
+	}
 
 	if (tcpinfo->flg_mask || (tcpinfo->invflags & XT_TCP_INV_FLAGS)) {
 		xt_xlate_add(xl, "tcp flags %s",
@@ -437,8 +445,12 @@ static int tcp_xlate(struct xt_xlate *xl,
 		print_tcp_xlate(xl, tcpinfo->flg_cmp);
 		xt_xlate_add(xl, " / ");
 		print_tcp_xlate(xl, tcpinfo->flg_mask);
+		xlated = true;
 	}
 
+	if (!xlated)
+		xt_xlate_add(xl, "meta l4proto tcp");
+
 	return 1;
 }
 
diff --git a/extensions/libxt_tcp.t b/extensions/libxt_tcp.t
index 7a3bbd08..75d5b1ed 100644
--- a/extensions/libxt_tcp.t
+++ b/extensions/libxt_tcp.t
@@ -6,6 +6,18 @@
 -p tcp -m tcp --sport 1:1023;=;OK
 -p tcp -m tcp --sport 1024:65535;=;OK
 -p tcp -m tcp --sport 1024:;-p tcp -m tcp --sport 1024:65535;OK
+-p tcp -m tcp --sport :;-p tcp -m tcp;OK
+-p tcp -m tcp ! --sport :;-p tcp -m tcp ! --sport 0:65535;OK
+-p tcp -m tcp --sport :4;-p tcp -m tcp --sport 0:4;OK
+-p tcp -m tcp --sport 4:;-p tcp -m tcp --sport 4:65535;OK
+-p tcp -m tcp --sport 4:4;-p tcp -m tcp --sport 4;OK
+-p tcp -m tcp --sport 4:3;;FAIL
+-p tcp -m tcp --dport :;-p tcp -m tcp;OK
+-p tcp -m tcp ! --dport :;-p tcp -m tcp ! --dport 0:65535;OK
+-p tcp -m tcp --dport :4;-p tcp -m tcp --dport 0:4;OK
+-p tcp -m tcp --dport 4:;-p tcp -m tcp --dport 4:65535;OK
+-p tcp -m tcp --dport 4:4;-p tcp -m tcp --dport 4;OK
+-p tcp -m tcp --dport 4:3;;FAIL
 -p tcp -m tcp ! --sport 1;=;OK
 -p tcp -m tcp ! --sport 65535;=;OK
 -p tcp -m tcp ! --dport 1;=;OK
diff --git a/extensions/libxt_tcp.txlate b/extensions/libxt_tcp.txlate
index 9802ddfe..b3ddcc15 100644
--- a/extensions/libxt_tcp.txlate
+++ b/extensions/libxt_tcp.txlate
@@ -30,3 +30,9 @@ nft 'add rule ip filter INPUT tcp option 23 exists counter'
 
 iptables-translate -A INPUT -p tcp ! --tcp-option 23
 nft 'add rule ip filter INPUT tcp option 23 missing counter'
+
+iptables-translate -I OUTPUT -p tcp --sport 0:65535 -j ACCEPT
+nft 'insert rule ip filter OUTPUT meta l4proto tcp counter accept'
+
+iptables-translate -I OUTPUT -p tcp ! --sport 0:65535 -j ACCEPT
+nft 'insert rule ip filter OUTPUT tcp sport != 0-65535 counter accept'
diff --git a/extensions/libxt_tcpmss.t b/extensions/libxt_tcpmss.t
index 2b415957..d0fb52fa 100644
--- a/extensions/libxt_tcpmss.t
+++ b/extensions/libxt_tcpmss.t
@@ -1,6 +1,10 @@
 :INPUT,FORWARD,OUTPUT
 -m tcpmss --mss 42;;FAIL
 -p tcp -m tcpmss --mss 42;=;OK
+-p tcp -m tcpmss --mss :;-p tcp -m tcpmss --mss 0:65535;OK
+-p tcp -m tcpmss --mss :42;-p tcp -m tcpmss --mss 0:42;OK
+-p tcp -m tcpmss --mss 42:;-p tcp -m tcpmss --mss 42:65535;OK
+-p tcp -m tcpmss --mss 42:42;-p tcp -m tcpmss --mss 42;OK
 -p tcp -m tcpmss --mss 42:12345;=;OK
 -p tcp -m tcpmss --mss 42:65536;;FAIL
 -p tcp -m tcpmss --mss 65535:1000;;FAIL
diff --git a/extensions/libxt_time.man b/extensions/libxt_time.man
index 4c0cae06..5b749a48 100644
--- a/extensions/libxt_time.man
+++ b/extensions/libxt_time.man
@@ -58,7 +58,7 @@ rest of the system uses).
 The caveat with the kernel timezone is that Linux distributions may ignore to
 set the kernel timezone, and instead only set the system time. Even if a
 particular distribution does set the timezone at boot, it is usually does not
-keep the kernel timezone offset - which is what changes on DST - up to date.
+keep the kernel timezone offset \(em which is what changes on DST \(em up to date.
 ntpd will not touch the kernel timezone, so running it will not resolve the
 issue. As such, one may encounter a timezone that is always +0000, or one that
 is wrong half of the time of the year. As such, \fBusing \-\-kerneltz is highly
diff --git a/extensions/libxt_u32.man b/extensions/libxt_u32.man
index 40a69f8e..183a63f7 100644
--- a/extensions/libxt_u32.man
+++ b/extensions/libxt_u32.man
@@ -69,13 +69,13 @@ Example:
 .IP
 match IP packets with total length >= 256
 .IP
-The IP header contains a total length field in bytes 2-3.
+The IP header contains a total length field in bytes 2\(en3.
 .IP
 \-\-u32 "\fB0 & 0xFFFF = 0x100:0xFFFF\fP"
 .IP
-read bytes 0-3
+read bytes 0\(en3
 .IP
-AND that with 0xFFFF (giving bytes 2-3), and test whether that is in the range
+AND that with 0xFFFF (giving bytes 2\(en3), and test whether that is in the range
 [0x100:0xFFFF]
 .PP
 Example: (more realistic, hence more complicated)
@@ -86,7 +86,7 @@ First test that it is an ICMP packet, true iff byte 9 (protocol) = 1
 .IP
 \-\-u32 "\fB6 & 0xFF = 1 &&\fP ...
 .IP
-read bytes 6-9, use \fB&\fP to throw away bytes 6-8 and compare the result to
+read bytes 6\(en9, use \fB&\fP to throw away bytes 6\(en8 and compare the result to
 1. Next test that it is not a fragment. (If so, it might be part of such a
 packet but we cannot always tell.) N.B.: This test is generally needed if you
 want to match anything beyond the IP header. The last 6 bits of byte 6 and all
@@ -101,11 +101,11 @@ stored in the right half of byte 0 of the IP header itself.
 .IP
  ... \fB0 >> 22 & 0x3C @ 0 >> 24 = 0\fP"
 .IP
-The first 0 means read bytes 0-3, \fB>>22\fP means shift that 22 bits to the
+The first 0 means read bytes 0\(en3, \fB>>22\fP means shift that 22 bits to the
 right. Shifting 24 bits would give the first byte, so only 22 bits is four
 times that plus a few more bits. \fB&3C\fP then eliminates the two extra bits
 on the right and the first four bits of the first byte. For instance, if IHL=5,
-then the IP header is 20 (4 x 5) bytes long. In this case, bytes 0-1 are (in
+then the IP header is 20 (4 x 5) bytes long. In this case, bytes 0\(en1 are (in
 binary) xxxx0101 yyzzzzzz, \fB>>22\fP gives the 10 bit value xxxx0101yy and
 \fB&3C\fP gives 010100. \fB@\fP means to use this number as a new offset into
 the packet, and read four bytes starting from there. This is the first 4 bytes
@@ -115,7 +115,7 @@ the result with 0.
 .PP
 Example:
 .IP
-TCP payload bytes 8-12 is any of 1, 2, 5 or 8
+TCP payload bytes 8\(en12 is any of 1, 2, 5 or 8
 .IP
 First we test that the packet is a tcp packet (similar to ICMP).
 .IP
@@ -130,5 +130,5 @@ makes this the new offset into the packet, which is the start of the TCP
 header. The length of the TCP header (again in 32 bit words) is the left half
 of byte 12 of the TCP header. The \fB12>>26&3C\fP computes this length in bytes
 (similar to the IP header before). "@" makes this the new offset, which is the
-start of the TCP payload. Finally, 8 reads bytes 8-12 of the payload and
+start of the TCP payload. Finally, 8 reads bytes 8\(en12 of the payload and
 \fB=\fP checks whether the result is any of 1, 2, 5 or 8.
diff --git a/extensions/libxt_udp.c b/extensions/libxt_udp.c
index ba1c3eb7..748d4180 100644
--- a/extensions/libxt_udp.c
+++ b/extensions/libxt_udp.c
@@ -82,13 +82,18 @@ print_port(uint16_t port, int numeric)
 		printf("%s", service);
 }
 
+static bool skip_ports_match(uint16_t min, uint16_t max, bool inv)
+{
+	return min == 0 && max == UINT16_MAX && !inv;
+}
+
 static void
 print_ports(const char *name, uint16_t min, uint16_t max,
 	    int invert, int numeric)
 {
 	const char *inv = invert ? "!" : "";
 
-	if (min != 0 || max != 0xFFFF || invert) {
+	if (!skip_ports_match(min, max, invert)) {
 		printf(" %s", name);
 		if (min == max) {
 			printf(":%s", inv);
@@ -122,10 +127,11 @@ udp_print(const void *ip, const struct xt_entry_match *match, int numeric)
 static void udp_save(const void *ip, const struct xt_entry_match *match)
 {
 	const struct xt_udp *udpinfo = (struct xt_udp *)match->data;
+	bool inv_srcpt = udpinfo->invflags & XT_UDP_INV_SRCPT;
+	bool inv_dstpt = udpinfo->invflags & XT_UDP_INV_DSTPT;
 
-	if (udpinfo->spts[0] != 0
-	    || udpinfo->spts[1] != 0xFFFF) {
-		if (udpinfo->invflags & XT_UDP_INV_SRCPT)
+	if (!skip_ports_match(udpinfo->spts[0], udpinfo->spts[1], inv_srcpt)) {
+		if (inv_srcpt)
 			printf(" !");
 		if (udpinfo->spts[0]
 		    != udpinfo->spts[1])
@@ -137,9 +143,8 @@ static void udp_save(const void *ip, const struct xt_entry_match *match)
 			       udpinfo->spts[0]);
 	}
 
-	if (udpinfo->dpts[0] != 0
-	    || udpinfo->dpts[1] != 0xFFFF) {
-		if (udpinfo->invflags & XT_UDP_INV_DSTPT)
+	if (!skip_ports_match(udpinfo->dpts[0], udpinfo->dpts[1], inv_dstpt)) {
+		if (inv_dstpt)
 			printf(" !");
 		if (udpinfo->dpts[0]
 		    != udpinfo->dpts[1])
@@ -156,35 +161,39 @@ static int udp_xlate(struct xt_xlate *xl,
 		     const struct xt_xlate_mt_params *params)
 {
 	const struct xt_udp *udpinfo = (struct xt_udp *)params->match->data;
+	bool inv_srcpt = udpinfo->invflags & XT_UDP_INV_SRCPT;
+	bool inv_dstpt = udpinfo->invflags & XT_UDP_INV_DSTPT;
+	bool xlated = false;
 
-	if (udpinfo->spts[0] != 0 || udpinfo->spts[1] != 0xFFFF) {
+	if (!skip_ports_match(udpinfo->spts[0], udpinfo->spts[1], inv_srcpt)) {
 		if (udpinfo->spts[0] != udpinfo->spts[1]) {
 			xt_xlate_add(xl,"udp sport %s%u-%u",
-				   udpinfo->invflags & XT_UDP_INV_SRCPT ?
-					 "!= ": "",
+				   inv_srcpt ? "!= ": "",
 				   udpinfo->spts[0], udpinfo->spts[1]);
 		} else {
 			xt_xlate_add(xl, "udp sport %s%u",
-				   udpinfo->invflags & XT_UDP_INV_SRCPT ?
-					 "!= ": "",
+				   inv_srcpt ? "!= ": "",
 				   udpinfo->spts[0]);
 		}
+		xlated = true;
 	}
 
-	if (udpinfo->dpts[0] != 0 || udpinfo->dpts[1] != 0xFFFF) {
+	if (!skip_ports_match(udpinfo->dpts[0], udpinfo->dpts[1], inv_dstpt)) {
 		if (udpinfo->dpts[0]  != udpinfo->dpts[1]) {
 			xt_xlate_add(xl,"udp dport %s%u-%u",
-				   udpinfo->invflags & XT_UDP_INV_SRCPT ?
-					 "!= ": "",
+				   inv_dstpt ? "!= ": "",
 				   udpinfo->dpts[0], udpinfo->dpts[1]);
 		} else {
 			xt_xlate_add(xl,"udp dport %s%u",
-				   udpinfo->invflags & XT_UDP_INV_SRCPT ?
-					 "!= ": "",
+				   inv_dstpt ? "!= ": "",
 				   udpinfo->dpts[0]);
 		}
+		xlated = true;
 	}
 
+	if (!xlated)
+		xt_xlate_add(xl, "meta l4proto udp");
+
 	return 1;
 }
 
diff --git a/extensions/libxt_udp.t b/extensions/libxt_udp.t
index f5347701..6a2c9d07 100644
--- a/extensions/libxt_udp.t
+++ b/extensions/libxt_udp.t
@@ -6,6 +6,18 @@
 -p udp -m udp --sport 1:1023;=;OK
 -p udp -m udp --sport 1024:65535;=;OK
 -p udp -m udp --sport 1024:;-p udp -m udp --sport 1024:65535;OK
+-p udp -m udp --sport :;-p udp -m udp;OK
+-p udp -m udp ! --sport :;-p udp -m udp ! --sport 0:65535;OK
+-p udp -m udp --sport :4;-p udp -m udp --sport 0:4;OK
+-p udp -m udp --sport 4:;-p udp -m udp --sport 4:65535;OK
+-p udp -m udp --sport 4:4;-p udp -m udp --sport 4;OK
+-p udp -m udp --sport 4:3;;FAIL
+-p udp -m udp --dport :;-p udp -m udp;OK
+-p udp -m udp ! --dport :;-p udp -m udp ! --dport 0:65535;OK
+-p udp -m udp --dport :4;-p udp -m udp --dport 0:4;OK
+-p udp -m udp --dport 4:;-p udp -m udp --dport 4:65535;OK
+-p udp -m udp --dport 4:4;-p udp -m udp --dport 4;OK
+-p udp -m udp --dport 4:3;;FAIL
 -p udp -m udp ! --sport 1;=;OK
 -p udp -m udp ! --sport 65535;=;OK
 -p udp -m udp ! --dport 1;=;OK
diff --git a/extensions/libxt_udp.txlate b/extensions/libxt_udp.txlate
index 28e7ca20..d6bbb96f 100644
--- a/extensions/libxt_udp.txlate
+++ b/extensions/libxt_udp.txlate
@@ -9,3 +9,9 @@ nft 'insert rule ip filter OUTPUT ip protocol udp ip daddr 8.8.8.8 counter accep
 
 iptables-translate -I OUTPUT -p udp --dport 1020:1023 --sport 53 -j ACCEPT
 nft 'insert rule ip filter OUTPUT udp sport 53 udp dport 1020-1023 counter accept'
+
+iptables-translate -I OUTPUT -p udp --sport 0:65535 -j ACCEPT
+nft 'insert rule ip filter OUTPUT meta l4proto udp counter accept'
+
+iptables-translate -I OUTPUT -p udp ! --sport 0:65535 -j ACCEPT
+nft 'insert rule ip filter OUTPUT udp sport != 0-65535 counter accept'
diff --git a/include/Makefile.am b/include/Makefile.am
index 07c88b90..f3e480f7 100644
--- a/include/Makefile.am
+++ b/include/Makefile.am
@@ -11,7 +11,7 @@ nobase_include_HEADERS = \
 	libiptc/ipt_kernel_headers.h libiptc/libiptc.h \
 	libiptc/libip6tc.h libiptc/libxtc.h libiptc/xtcshared.h
 
-EXTRA_DIST = iptables linux iptables.h ip6tables.h
+EXTRA_DIST = iptables linux iptables.h ip6tables.h xtables_internal.h
 
 uninstall-hook:
 	dir=${includedir}/libiptc; { \
diff --git a/include/linux/netfilter/xt_CONNMARK.h b/include/linux/netfilter/xt_CONNMARK.h
index 2f2e48ec..36cc956e 100644
--- a/include/linux/netfilter/xt_CONNMARK.h
+++ b/include/linux/netfilter/xt_CONNMARK.h
@@ -1,3 +1,4 @@
+/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
 #ifndef _XT_CONNMARK_H_target
 #define _XT_CONNMARK_H_target
 
diff --git a/include/linux/netfilter/xt_connmark.h b/include/linux/netfilter/xt_connmark.h
index bbf2acc9..41b578cc 100644
--- a/include/linux/netfilter/xt_connmark.h
+++ b/include/linux/netfilter/xt_connmark.h
@@ -1,23 +1,24 @@
+/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
+/* Copyright (C) 2002,2004 MARA Systems AB <https://www.marasystems.com>
+ * by Henrik Nordstrom <hno@marasystems.com>
+ */
+
 #ifndef _XT_CONNMARK_H
 #define _XT_CONNMARK_H
 
 #include <linux/types.h>
 
-/* Copyright (C) 2002,2004 MARA Systems AB <http://www.marasystems.com>
- * by Henrik Nordstrom <hno@marasystems.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License as published by
- * the Free Software Foundation; either version 2 of the License, or
- * (at your option) any later version.
- */
-
 enum {
 	XT_CONNMARK_SET = 0,
 	XT_CONNMARK_SAVE,
 	XT_CONNMARK_RESTORE
 };
 
+enum {
+	D_SHIFT_LEFT = 0,
+	D_SHIFT_RIGHT,
+};
+
 struct xt_connmark_tginfo1 {
 	__u32 ctmark, ctmask, nfmask;
 	__u8 mode;
diff --git a/include/xtables.h b/include/xtables.h
index 087a1d60..c78c6923 100644
--- a/include/xtables.h
+++ b/include/xtables.h
@@ -12,6 +12,7 @@
 #include <stdbool.h>
 #include <stddef.h>
 #include <stdint.h>
+#include <netinet/ether.h>
 #include <netinet/in.h>
 #include <net/if.h>
 #include <linux/types.h>
@@ -31,6 +32,10 @@
 #define IPPROTO_UDPLITE	136
 #endif
 
+#ifndef ETH_ALEN
+#define ETH_ALEN 6
+#endif
+
 #include <xtables-version.h>
 
 struct in_addr;
@@ -61,7 +66,6 @@ struct in_addr;
  * %XTTYPE_SYSLOGLEVEL:	syslog level by name or number
  * %XTTYPE_HOST:	one host or address (ptr: union nf_inet_addr)
  * %XTTYPE_HOSTMASK:	one host or address, with an optional prefix length
- * 			(ptr: union nf_inet_addr; only host portion is stored)
  * %XTTYPE_PROTOCOL:	protocol number/name from /etc/protocols (ptr: uint8_t)
  * %XTTYPE_PORT:	16-bit port name or number (supports %XTOPT_NBO)
  * %XTTYPE_PORTRC:	colon-separated port range (names acceptable),
@@ -69,6 +73,7 @@ struct in_addr;
  * %XTTYPE_PLEN:	prefix length
  * %XTTYPE_PLENMASK:	prefix length (ptr: union nf_inet_addr)
  * %XTTYPE_ETHERMAC:	Ethernet MAC address in hex form
+ * %XTTYPE_ETHERMACMASK: Ethernet MAC address in hex form with optional mask
  */
 enum xt_option_type {
 	XTTYPE_NONE,
@@ -93,6 +98,7 @@ enum xt_option_type {
 	XTTYPE_PLEN,
 	XTTYPE_PLENMASK,
 	XTTYPE_ETHERMAC,
+	XTTYPE_ETHERMACMASK,
 };
 
 /**
@@ -122,6 +128,7 @@ enum xt_option_flags {
  * @size:	size of the item pointed to by @ptroff; this is a safeguard
  * @min:	lowest allowed value (for singular integral types)
  * @max:	highest allowed value (for singular integral types)
+ * @base:	assumed base of parsed value for integer types (default 0)
  */
 struct xt_option_entry {
 	const char *name;
@@ -129,7 +136,7 @@ struct xt_option_entry {
 	unsigned int id, excl, also, flags;
 	unsigned int ptroff;
 	size_t size;
-	unsigned int min, max;
+	unsigned int min, max, base;
 };
 
 /**
@@ -167,7 +174,9 @@ struct xt_option_call {
 		struct {
 			uint32_t mark, mask;
 		};
-		uint8_t ethermac[6];
+		struct {
+			uint8_t ethermac[ETH_ALEN], ethermacmask[ETH_ALEN];
+		};
 	} val;
 	/* Wished for a world where the ones below were gone: */
 	union {
diff --git a/include/xtables_internal.h b/include/xtables_internal.h
new file mode 100644
index 00000000..a87a40cc
--- /dev/null
+++ b/include/xtables_internal.h
@@ -0,0 +1,7 @@
+#ifndef XTABLES_INTERNAL_H
+#define XTABLES_INTERNAL_H 1
+
+extern bool xtables_strtoul_base(const char *, char **, uintmax_t *,
+	uintmax_t, uintmax_t, unsigned int);
+
+#endif /* XTABLES_INTERNAL_H */
diff --git a/iptables-test.py b/iptables-test.py
index 6f63cdbe..66db5521 100755
--- a/iptables-test.py
+++ b/iptables-test.py
@@ -15,6 +15,7 @@ import sys
 import os
 import subprocess
 import argparse
+from difflib import unified_diff
 
 IPTABLES = "iptables"
 IP6TABLES = "ip6tables"
@@ -29,6 +30,7 @@ EBTABLES_SAVE = "ebtables-save"
 #IP6TABLES_SAVE = ['xtables-save','-6']
 
 EXTENSIONS_PATH = "extensions"
+TESTS_PATH = os.path.join(os.path.dirname(sys.argv[0]), "extensions")
 LOGFILE="/tmp/iptables-test.log"
 log_file = None
 
@@ -46,21 +48,34 @@ def maybe_colored(color, text, isatty):
     )
 
 
-def print_error(reason, filename=None, lineno=None):
+def print_error(reason, filename=None, lineno=None, log_file=sys.stderr):
     '''
     Prints an error with nice colors, indicating file and line number.
     '''
-    print(filename + ": " + maybe_colored('red', "ERROR", STDERR_IS_TTY) +
-        ": line %d (%s)" % (lineno, reason), file=sys.stderr)
+    print(filename + ": " + maybe_colored('red', "ERROR", log_file.isatty()) +
+        ": line %d (%s)" % (lineno, reason), file=log_file)
 
 
 def delete_rule(iptables, rule, filename, lineno, netns = None):
     '''
     Removes an iptables rule
+
+    Remove any --set-counters arguments, --delete rejects them.
     '''
+    delrule = rule.split()
+    for i in range(len(delrule)):
+        if delrule[i] in ['-c', '--set-counters']:
+            delrule.pop(i)
+            if ',' in delrule.pop(i):
+                break
+            if len(delrule) > i and delrule[i].isnumeric():
+                delrule.pop(i)
+            break
+    rule = " ".join(delrule)
+
     cmd = iptables + " -D " + rule
     ret = execute_cmd(cmd, filename, lineno, netns)
-    if ret == 1:
+    if ret != 0:
         reason = "cannot delete: " + iptables + " -I " + rule
         print_error(reason, filename, lineno)
         return -1
@@ -68,7 +83,7 @@ def delete_rule(iptables, rule, filename, lineno, netns = None):
     return 0
 
 
-def run_test(iptables, rule, rule_save, res, filename, lineno, netns):
+def run_test(iptables, rule, rule_save, res, filename, lineno, netns, stderr=sys.stderr):
     '''
     Executes an unit test. Returns the output of delete_rule().
 
@@ -92,7 +107,7 @@ def run_test(iptables, rule, rule_save, res, filename, lineno, netns):
     if ret:
         if res != "FAIL":
             reason = "cannot load: " + cmd
-            print_error(reason, filename, lineno)
+            print_error(reason, filename, lineno, stderr)
             return -1
         else:
             # do not report this error
@@ -100,7 +115,7 @@ def run_test(iptables, rule, rule_save, res, filename, lineno, netns):
     else:
         if res == "FAIL":
             reason = "should fail: " + cmd
-            print_error(reason, filename, lineno)
+            print_error(reason, filename, lineno, stderr)
             delete_rule(iptables, rule, filename, lineno, netns)
             return -1
 
@@ -131,22 +146,25 @@ def run_test(iptables, rule, rule_save, res, filename, lineno, netns):
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
     out, err = proc.communicate()
+    if len(err):
+        print(err, file=log_file)
 
     #
     # check for segfaults
     #
     if proc.returncode == -11:
         reason = command + " segfaults!"
-        print_error(reason, filename, lineno)
+        print_error(reason, filename, lineno, stderr)
         delete_rule(iptables, rule, filename, lineno, netns)
         return -1
 
     # find the rule
-    matching = out.find(rule_save.encode('utf-8'))
+    matching = out.find("\n-A {}\n".format(rule_save).encode('utf-8'))
+
     if matching < 0:
         if res == "OK":
             reason = "cannot find: " + iptables + " -I " + rule
-            print_error(reason, filename, lineno)
+            print_error(reason, filename, lineno, stderr)
             delete_rule(iptables, rule, filename, lineno, netns)
             return -1
         else:
@@ -155,7 +173,7 @@ def run_test(iptables, rule, rule_save, res, filename, lineno, netns):
     else:
         if res != "OK":
             reason = "should not match: " + cmd
-            print_error(reason, filename, lineno)
+            print_error(reason, filename, lineno, stderr)
             delete_rule(iptables, rule, filename, lineno, netns)
             return -1
 
@@ -224,10 +242,14 @@ def variant_res(res, variant, alt_res=None):
 
 def fast_run_possible(filename):
     '''
-    Keep things simple, run only for simple test files:
+    Return true if fast test run is possible.
+
+    To keep things simple, run only for simple test files:
     - no external commands
     - no multiple tables
     - no variant-specific results
+
+    :param filename: test file to inspect
     '''
     table = None
     rulecount = 0
@@ -250,6 +272,9 @@ def run_test_file_fast(iptables, filename, netns):
     '''
     Run a test file, but fast
 
+    Add all non-failing rules at once by use of iptables-restore, then check
+    all rules' listing at once by use of iptables-save.
+
     :param filename: name of the file with the test rules
     :param netns: network namespace to perform test run in
     '''
@@ -294,7 +319,7 @@ def run_test_file_fast(iptables, filename, netns):
             if res != "OK":
                 rule = chain + " -t " + table + " " + item[0]
                 ret = run_test(iptables, rule, rule_save,
-                               res, filename, lineno + 1, netns)
+                               res, filename, lineno + 1, netns, log_file)
 
                 if ret < 0:
                     return -1
@@ -331,6 +356,8 @@ def run_test_file_fast(iptables, filename, netns):
                             stderr = subprocess.PIPE)
     restore_data = "\n".join(restore_data) + "\n"
     out, err = proc.communicate(input = restore_data)
+    if len(err):
+        print(err, file=log_file)
 
     if proc.returncode == -11:
         reason = iptables + "-restore segfaults!"
@@ -356,6 +383,8 @@ def run_test_file_fast(iptables, filename, netns):
                             stdout = subprocess.PIPE,
                             stderr = subprocess.PIPE)
     out, err = proc.communicate()
+    if len(err):
+        print(err, file=log_file)
 
     if proc.returncode == -11:
         reason = iptables + "-save segfaults!"
@@ -367,53 +396,30 @@ def run_test_file_fast(iptables, filename, netns):
 
     out = out.decode('utf-8').rstrip()
     if out.find(out_expect) < 0:
-        msg = ["dumps differ!"]
-        msg.extend(["expect: " + l for l in out_expect.split("\n")])
-        msg.extend(["got: " + l for l in out.split("\n")
-                                if not l[0] in ['*', ':', '#']])
-        print("\n".join(msg), file=log_file)
+        print("dumps differ!", file=log_file)
+        out_clean = [ l for l in out.split("\n")
+                        if not l[0] in ['*', ':', '#']]
+        diff = unified_diff(out_expect.split("\n"), out_clean,
+                            fromfile="expect", tofile="got", lineterm='')
+        print("\n".join(diff), file=log_file)
         return -1
 
     return tests
 
-def run_test_file(filename, netns):
+def _run_test_file(iptables, filename, netns, suffix):
     '''
     Runs a test file
 
+    :param iptables: string with the iptables command to execute
     :param filename: name of the file with the test rules
     :param netns: network namespace to perform test run in
     '''
-    #
-    # if this is not a test file, skip.
-    #
-    if not filename.endswith(".t"):
-        return 0, 0
-
-    if "libipt_" in filename:
-        iptables = IPTABLES
-    elif "libip6t_" in filename:
-        iptables = IP6TABLES
-    elif "libxt_"  in filename:
-        iptables = IPTABLES
-    elif "libarpt_" in filename:
-        # only supported with nf_tables backend
-        if EXECUTABLE != "xtables-nft-multi":
-           return 0, 0
-        iptables = ARPTABLES
-    elif "libebt_" in filename:
-        # only supported with nf_tables backend
-        if EXECUTABLE != "xtables-nft-multi":
-           return 0, 0
-        iptables = EBTABLES
-    else:
-        # default to iptables if not known prefix
-        iptables = IPTABLES
 
     fast_failed = False
     if fast_run_possible(filename):
         tests = run_test_file_fast(iptables, filename, netns)
         if tests > 0:
-            print(filename + ": " + maybe_colored('green', "OK", STDOUT_IS_TTY))
+            print(filename + ": " + maybe_colored('green', "OK", STDOUT_IS_TTY) + suffix)
             return tests, tests
         fast_failed = True
 
@@ -468,6 +474,9 @@ def run_test_file(filename, netns):
             else:
                 rule_save = chain + " " + item[1]
 
+            if iptables == EBTABLES and rule_save.find('-j') < 0:
+                rule_save += " -j CONTINUE"
+
             res = item[2].rstrip()
             if len(item) > 3:
                 variant = item[3].rstrip()
@@ -491,20 +500,66 @@ def run_test_file(filename, netns):
     if netns:
         execute_cmd("ip netns del " + netns, filename)
     if total_test_passed:
-        suffix = ""
         if fast_failed:
-            suffix = maybe_colored('red', " but fast mode failed!", STDOUT_IS_TTY)
+            suffix += maybe_colored('red', " but fast mode failed!", STDOUT_IS_TTY)
         print(filename + ": " + maybe_colored('green', "OK", STDOUT_IS_TTY) + suffix)
 
     f.close()
     return tests, passed
 
+def run_test_file(filename, netns):
+    '''
+    Runs a test file
+
+    :param filename: name of the file with the test rules
+    :param netns: network namespace to perform test run in
+    '''
+    #
+    # if this is not a test file, skip.
+    #
+    if not filename.endswith(".t"):
+        return 0, 0
+
+    if "libipt_" in filename:
+        xtables = [ IPTABLES ]
+    elif "libip6t_" in filename:
+        xtables = [ IP6TABLES ]
+    elif "libxt_"  in filename:
+        xtables = [ IPTABLES, IP6TABLES ]
+    elif "libarpt_" in filename:
+        # only supported with nf_tables backend
+        if EXECUTABLE != "xtables-nft-multi":
+           return 0, 0
+        xtables = [ ARPTABLES ]
+    elif "libebt_" in filename:
+        # only supported with nf_tables backend
+        if EXECUTABLE != "xtables-nft-multi":
+           return 0, 0
+        xtables = [ EBTABLES ]
+    else:
+        # default to iptables if not known prefix
+        xtables = [ IPTABLES ]
+
+    tests = 0
+    passed = 0
+    print_result = False
+    suffix = ""
+    for iptables in xtables:
+        if len(xtables) > 1:
+            suffix = "({})".format(iptables)
+
+        file_tests, file_passed = _run_test_file(iptables, filename, netns, suffix)
+        if file_tests:
+            tests += file_tests
+            passed += file_passed
+
+    return tests, passed
 
 def show_missing():
     '''
     Show the list of missing test files
     '''
-    file_list = os.listdir(EXTENSIONS_PATH)
+    file_list = os.listdir(TESTS_PATH)
     testfiles = [i for i in file_list if i.endswith('.t')]
     libfiles = [i for i in file_list
                 if i.startswith('lib') and i.endswith('.c')]
@@ -615,8 +670,8 @@ def main():
         if args.filename:
             file_list = args.filename
         else:
-            file_list = [os.path.join(EXTENSIONS_PATH, i)
-                         for i in os.listdir(EXTENSIONS_PATH)
+            file_list = [os.path.join(TESTS_PATH, i)
+                         for i in os.listdir(TESTS_PATH)
                          if i.endswith('.t')]
             file_list.sort()
 
diff --git a/iptables/.gitignore b/iptables/.gitignore
index 8141e34d..b9222392 100644
--- a/iptables/.gitignore
+++ b/iptables/.gitignore
@@ -1,3 +1,4 @@
+/arptables-translate.8
 /ebtables-translate.8
 /ip6tables
 /ip6tables.8
diff --git a/iptables/Makefile.am b/iptables/Makefile.am
index 8a722702..2007cd10 100644
--- a/iptables/Makefile.am
+++ b/iptables/Makefile.am
@@ -1,7 +1,14 @@
 # -*- Makefile -*-
 
 AM_CFLAGS        = ${regular_CFLAGS}
-AM_CPPFLAGS      = ${regular_CPPFLAGS} -I${top_builddir}/include -I${top_srcdir}/include -I${top_srcdir} ${kinclude_CPPFLAGS} ${libmnl_CFLAGS} ${libnftnl_CFLAGS} ${libnetfilter_conntrack_CFLAGS}
+AM_CPPFLAGS      = ${regular_CPPFLAGS} \
+                   -I${top_builddir}/include \
+                   -I${top_srcdir}/include \
+                   -I${top_srcdir} \
+                   ${kinclude_CPPFLAGS} \
+                   ${libmnl_CFLAGS} \
+                   ${libnftnl_CFLAGS} \
+                   ${libnetfilter_conntrack_CFLAGS}
 AM_LDFLAGS       = ${regular_LDFLAGS}
 
 BUILT_SOURCES =
@@ -69,10 +76,12 @@ man_MANS         = iptables.8 iptables-restore.8 iptables-save.8 \
 dist_sbin_SCRIPTS = iptables-apply
 dist_pkgdata_DATA = iptables.xslt
 
+xlate_man_links = iptables-translate.8 ip6tables-translate.8 \
+		  iptables-restore-translate.8 ip6tables-restore-translate.8 \
+		  ebtables-translate.8 arptables-translate.8
+
 if ENABLE_NFTABLES
-man_MANS	+= iptables-translate.8 ip6tables-translate.8 \
-		   iptables-restore-translate.8 ip6tables-restore-translate.8 \
-		   xtables-monitor.8 ebtables-translate.8
+man_MANS	+= ${xlate_man_links} xtables-monitor.8
 
 dist_man_MANS	 = xtables-nft.8 xtables-translate.8 xtables-legacy.8 \
 		   arptables-nft.8 arptables-nft-restore.8 arptables-nft-save.8 \
@@ -97,6 +106,7 @@ x_sbin_links  = iptables-nft iptables-nft-restore iptables-nft-save \
 		arptables-nft arptables \
 		arptables-nft-restore arptables-restore \
 		arptables-nft-save arptables-save \
+		arptables-translate \
 		ebtables-nft ebtables \
 		ebtables-nft-restore ebtables-restore \
 		ebtables-nft-save ebtables-save \
@@ -104,15 +114,15 @@ x_sbin_links  = iptables-nft iptables-nft-restore iptables-nft-save \
 endif
 
 iptables-extensions.8: iptables-extensions.8.tmpl ../extensions/matches.man ../extensions/targets.man
-	${AM_VERBOSE_GEN} sed \
+	${AM_V_GEN} sed \
 		-e '/@MATCH@/ r ../extensions/matches.man' \
 		-e '/@TARGET@/ r ../extensions/targets.man' $< >$@;
 
-iptables-translate.8 ip6tables-translate.8 iptables-restore-translate.8 ip6tables-restore-translate.8 ebtables-translate.8:
-	${AM_VERBOSE_GEN} echo '.so man8/xtables-translate.8' >$@
+${xlate_man_links}:
+	${AM_V_GEN} echo '.so man8/xtables-translate.8' >$@
 
 ip6tables.8 ip6tables-apply.8 ip6tables-restore.8 ip6tables-save.8:
-	${AM_VERBOSE_GEN} echo "$@" | sed 's|^ip6|.so man8/ip|' >$@
+	${AM_V_GEN} echo "$@" | sed 's|^ip6|.so man8/ip|' >$@
 
 pkgconfig_DATA = xtables.pc
 
diff --git a/iptables/arptables-nft-restore.8 b/iptables/arptables-nft-restore.8
index 09d9082c..596ca1c9 100644
--- a/iptables/arptables-nft-restore.8
+++ b/iptables/arptables-nft-restore.8
@@ -20,9 +20,9 @@
 .\"
 .\"
 .SH NAME
-arptables-restore \- Restore ARP Tables (nft-based)
+arptables-restore \(em Restore ARP Tables (nft-based)
 .SH SYNOPSIS
-\fBarptables\-restore
+\fBarptables\-restore\fP
 .SH DESCRIPTION
 .PP
 .B arptables-restore
diff --git a/iptables/arptables-nft-save.8 b/iptables/arptables-nft-save.8
index 905e5985..e9171d5d 100644
--- a/iptables/arptables-nft-save.8
+++ b/iptables/arptables-nft-save.8
@@ -20,7 +20,7 @@
 .\"
 .\"
 .SH NAME
-arptables-save \- dump arptables rules to stdout (nft-based)
+arptables-save \(em dump arptables rules to stdout (nft-based)
 .SH SYNOPSIS
 \fBarptables\-save\fP [\fB\-M\fP \fImodprobe\fP] [\fB\-c\fP]
 .P
diff --git a/iptables/arptables-nft.8 b/iptables/arptables-nft.8
index ea31e084..c48a2cc2 100644
--- a/iptables/arptables-nft.8
+++ b/iptables/arptables-nft.8
@@ -22,22 +22,36 @@
 .\"
 .\"
 .SH NAME
-arptables \- ARP table administration (nft-based)
+arptables \(em ARP table administration (nft-based)
 .SH SYNOPSIS
-.BR "arptables " [ "-t table" ] " -" [ AD ] " chain rule-specification " [ options ]
-.br
-.BR "arptables " [ "-t table" ] " -" [ RI ] " chain rulenum rule-specification " [ options ]
-.br
-.BR "arptables " [ "-t table" ] " -D chain rulenum " [ options ]
-.br
-.BR "arptables " [ "-t table" ] " -" [ "LFZ" ] " " [ chain ] " " [ options ]
-.br
-.BR "arptables " [ "-t table" ] " -" [ "NX" ] " chain"
-.br
-.BR "arptables " [ "-t table" ] " -E old-chain-name new-chain-name"
-.br
-.BR "arptables " [ "-t table" ] " -P chain target " [ options ]
-
+\fBarptables\fP [\fB\-t\fP \fItable\fP] {\fB\-A|\-D\fP} \fIchain\fP
+\fIrule-specification\fP [options...]
+.PP
+\fBarptables\fP [\fB\-t\fP \fItable\fP] \fB\-I\fP \fIchain\fP [\fIrulenum\fP]
+\fIrule-specification\fP
+.PP
+\fBarptables\fP [\fB\-t\fP \fItable\fP] \fB\-R\fP \fIchain rulenum
+rule-specification\fP
+.PP
+\fBarptables\fP [\fB\-t\fP \fItable\fP] \fB\-D\fP \fIchain rulenum\fP
+.PP
+\fBarptables\fP [\fB\-t\fP \fItable\fP] {\fB\-F\fP|\fB\-L\fP|\fB\-Z\fP}
+[\fIchain\fP [\fIrulenum\fP]] [\fIoptions...\fP]
+.PP
+\fBarptables\fP [\fB\-t\fP \fItable\fP] \fB\-N\fP \fIchain\fP
+.PP
+\fBarptables\fP [\fB\-t\fP \fItable\fP] \fB\-X\fP [\fIchain\fP]
+.PP
+\fBarptables\fP [\fB\-t\fP \fItable\fP] \fB\-P\fP \fIchain policy\fP
+.PP
+\fBarptables\fP [\fB\-t\fP \fItable\fP] \fB\-E\fP \fIold-chain-name
+new-chain-name\fP
+.PP
+rule-specification := [matches...] [target]
+.PP
+match := \fB\-m\fP \fImatchname\fP [per-match-options]
+.PP
+target := \fB\-j\fP \fItargetname\fP [per-target-options]
 .SH DESCRIPTION
 .B arptables
 is a user space tool, it is used to set up and maintain the
@@ -88,11 +102,11 @@ section of this man page.
 There is only one ARP table in the Linux
 kernel.  The table is
 .BR filter.
-You can drop the '-t filter' argument to the arptables command.
-The -t argument must be the
+You can drop the '\-t filter' argument to the arptables command.
+The \-t argument must be the
 first argument on the arptables command line, if used.
 .TP
-.B "-t, --table"
+.B "\-t, \-\-table"
 .br
 .BR filter ,
 is the only table and contains two built-in chains:
@@ -109,79 +123,79 @@ are commands, miscellaneous commands, rule-specifications, match-extensions,
 and watcher-extensions.
 .SS COMMANDS
 The arptables command arguments specify the actions to perform on the table
-defined with the -t argument.  If you do not use the -t argument to name
+defined with the \-t argument. If you do not use the \-t argument to name
 a table, the commands apply to the default filter table.
 With the exception of the
-.B "-Z"
+.B "\-Z"
 command, only one command may be used on the command line at a time.
 .TP
-.B "-A, --append"
+.B "\-A, \-\-append"
 Append a rule to the end of the selected chain.
 .TP
-.B "-D, --delete"
+.B "\-D, \-\-delete"
 Delete the specified rule from the selected chain. There are two ways to
 use this command. The first is by specifying an interval of rule numbers
 to delete, syntax: start_nr[:end_nr]. Using negative numbers is allowed, for more
-details about using negative numbers, see the -I command. The second usage is by
+details about using negative numbers, see the \-I command. The second usage is by
 specifying the complete rule as it would have been specified when it was added.
 .TP
-.B "-I, --insert"
+.B "\-I, \-\-insert"
 Insert the specified rule into the selected chain at the specified rule number.
 If the current number of rules equals N, then the specified number can be
-between -N and N+1. For a positive number i, it holds that i and i-N-1 specify the
+between \-N and N+1. For a positive number i, it holds that i and i\-N\-1 specify the
 same place in the chain where the rule should be inserted. The number 0 specifies
 the place past the last rule in the chain and using this number is therefore
-equivalent with using the -A command.
+equivalent with using the \-A command.
 .TP
-.B "-R, --replace"
+.B "\-R, \-\-replace"
 Replaces the specified rule into the selected chain at the specified rule number.
 If the current number of rules equals N, then the specified number can be
 between 1 and N. i specifies the place in the chain where the rule should be replaced.
 .TP
-.B "-P, --policy"
+.B "\-P, \-\-policy"
 Set the policy for the chain to the given target. The policy can be
 .BR ACCEPT ", " DROP " or " RETURN .
 .TP
-.B "-F, --flush"
+.B "\-F, \-\-flush"
 Flush the selected chain. If no chain is selected, then every chain will be
 flushed. Flushing the chain does not change the policy of the
 chain, however.
 .TP
-.B "-Z, --zero"
+.B "\-Z, \-\-zero"
 Set the counters of the selected chain to zero. If no chain is selected, all the counters
 are set to zero. The
-.B "-Z"
+.B "\-Z"
 command can be used in conjunction with the 
-.B "-L"
+.B "\-L"
 command.
 When both the
-.B "-Z"
+.B "\-Z"
 and
-.B "-L"
+.B "\-L"
 commands are used together in this way, the rule counters are printed on the screen
 before they are set to zero.
 .TP
-.B "-L, --list"
+.B "\-L, \-\-list"
 List all rules in the selected chain. If no chain is selected, all chains
 are listed.
 .TP
-.B "-N, --new-chain"
+.B "\-N, \-\-new-chain"
 Create a new user-defined chain with the given name. The number of
 user-defined chains is unlimited. A user-defined chain name has maximum
 length of 31 characters.
 .TP
-.B "-X, --delete-chain"
+.B "\-X, \-\-delete-chain"
 Delete the specified user-defined chain. There must be no remaining references
 to the specified chain, otherwise
 .B arptables
 will refuse to delete it. If no chain is specified, all user-defined
 chains that aren't referenced will be removed.
 .TP
-.B "-E, --rename-chain"
+.B "\-E, \-\-rename\-chain"
 Rename the specified chain to a new name.  Besides renaming a user-defined
 chain, you may rename a standard chain name to a name that suits your
 taste. For example, if you like PREBRIDGING more than PREROUTING,
-then you can use the -E command to rename the PREROUTING chain. If you do
+then you can use the \-E command to rename the PREROUTING chain. If you do
 rename one of the standard
 .B arptables
 chain names, please be sure to mention
@@ -195,15 +209,15 @@ of the
 .B arptables
 kernel table.
 
-.SS MISCELLANOUS COMMANDS
+.SS MISCELLANEOUS COMMANDS
 .TP
-.B "-V, --version"
+.B "\-V, \-\-version"
 Show the version of the arptables userspace program.
 .TP
-.B "-h, --help"
+.B "\-h, \-\-help"
 Give a brief description of the command syntax.
 .TP
-.BR "-j, --jump " "\fItarget\fP"
+.BR "\-j, \-\-jump " "\fItarget\fP"
 The target of the rule. This is one of the following values:
 .BR ACCEPT ,
 .BR DROP ,
@@ -213,7 +227,7 @@ a target extension (see
 .BR "TARGET EXTENSIONS" ")"
 or a user-defined chain name.
 .TP
-.BI "-c, --set-counters " "PKTS BYTES"
+.BI "\-c, \-\-set-counters " "PKTS BYTES"
 This enables the administrator to initialize the packet and byte
 counters of a rule (during
 .B INSERT,
@@ -227,38 +241,38 @@ in the add and delete commands). A "!" option before the specification
 inverts the test for that specification. Apart from these standard rule 
 specifications there are some other command line arguments of interest.
 .TP
-.BR "-s, --source-ip " "[!] \fIaddress\fP[/\fImask]\fP"
+.BR "\-s, \-\-source\-ip " "[!] \fIaddress\fP[/\fImask]\fP"
 The Source IP specification.
 .TP 
-.BR "-d, --destination-ip " "[!] \fIaddress\fP[/\fImask]\fP"
+.BR "\-d, \-\-destination\-ip " "[!] \fIaddress\fP[/\fImask]\fP"
 The Destination IP specification.
 .TP 
-.BR "--source-mac " "[!] \fIaddress\fP[/\fImask\fP]"
+.BR "\-\-source\-mac " "[!] \fIaddress\fP[/\fImask\fP]"
 The source mac address. Both mask and address are written as 6 hexadecimal
 numbers separated by colons.
 .TP
-.BR "--destination-mac " "[!] \fIaddress\fP[/\fImask\fP]"
+.BR "\-\-destination\-mac " "[!] \fIaddress\fP[/\fImask\fP]"
 The destination mac address. Both mask and address are written as 6 hexadecimal
 numbers separated by colons.
 .TP 
-.BR "-i, --in-interface " "[!] \fIname\fP"
+.BR "\-i, \-\-in\-interface " "[!] \fIname\fP"
 The interface via which a frame is received (for the
 .B INPUT
 chain). The flag
-.B --in-if
+.B \-\-in\-if
 is an alias for this option.
 .TP
-.BR "-o, --out-interface " "[!] \fIname\fP"
+.BR "\-o, \-\-out-interface " "[!] \fIname\fP"
 The interface via which a frame is going to be sent (for the
 .B OUTPUT
 chain). The flag
-.B --out-if
+.B \-\-out\-if
 is an alias for this option.
 .TP
-.BR "-l, --h-length " "\fIlength\fP[/\fImask\fP]"
+.BR "\-l, \-\-h\-length " "\fIlength\fP[/\fImask\fP]"
 The hardware length (nr of bytes)
 .TP
-.BR "--opcode " "\fIcode\fP[/\fImask\fP]
+.BR "\-\-opcode " "\fIcode\fP[/\fImask\fP]
 The operation code (2 bytes). Available values are:
 .BR 1 = Request
 .BR 2 = Reply
@@ -270,63 +284,63 @@ The operation code (2 bytes). Available values are:
 .BR 8 = InARP_Request
 .BR 9 = ARP_NAK .
 .TP
-.BR "--h-type " "\fItype\fP[/\fImask\fP]"
+.BR "\-\-h\-type " "\fItype\fP[/\fImask\fP]"
 The hardware type (2 bytes, hexadecimal). Available values are:
 .BR 1 = Ethernet .
 .TP
-.BR "--proto-type " "\fItype\fP[/\fImask\fP]"
+.BR "\-\-proto\-type " "\fItype\fP[/\fImask\fP]"
 The protocol type (2 bytes). Available values are:
 .BR 0x800 = IPv4 .
 
 .SS TARGET-EXTENSIONS
 .B arptables
 extensions are precompiled into the userspace tool. So there is no need
-to explicitly load them with a -m option like in
+to explicitly load them with a \-m option like in
 .BR iptables .
 However, these
 extensions deal with functionality supported by supplemental kernel modules.
 .SS mangle
 .TP
-.BR "--mangle-ip-s IP address"
+.BR "\-\-mangle\-ip\-s IP address"
 Mangles Source IP Address to given value.
 .TP
-.BR "--mangle-ip-d IP address"
+.BR "\-\-mangle\-ip\-d IP address"
 Mangles Destination IP Address to given value.
 .TP
-.BR "--mangle-mac-s MAC address"
+.BR "\-\-mangle\-mac\-s MAC address"
 Mangles Source MAC Address to given value.
 .TP
-.BR "--mangle-mac-d MAC address"
+.BR "\-\-mangle\-mac\-d MAC address"
 Mangles Destination MAC Address to given value.
 .TP
-.BR "--mangle-target target "
+.BR "\-\-mangle\-target target "
 Target of ARP mangle operation
-.BR "" ( DROP ", " CONTINUE " or " ACCEPT " -- default is " ACCEPT ).
+.BR "" ( DROP ", " CONTINUE " or " ACCEPT " \(em default is " ACCEPT ).
 .SS CLASSIFY
-This  module  allows you to set the skb->priority value (and thus clas-
-sify the packet into a specific CBQ class).
+This module allows you to set the skb\->priority value (and thus
+classify the packet into a specific CBQ class).
 
 .TP
-.BR "--set-class major:minor"
+.BR "\-\-set\-class major:minor"
 
 Set the major and minor  class  value.  The  values  are  always
 interpreted as hexadecimal even if no 0x prefix is given.
 
 .SS MARK
-This  module  allows you to set the skb->mark value (and thus classify
+This  module  allows you to set the skb\->mark value (and thus classify
 the packet by the mark in u32)
 
 .TP
-.BR "--set-mark mark"
+.BR "\-\-set\-mark mark"
 Set the mark value. The  values  are  always
 interpreted as hexadecimal even if no 0x prefix is given
 
 .TP
-.BR "--and-mark mark"
+.BR "\-\-and\-mark mark"
 Binary AND the mark with bits.
 
 .TP
-.BR "--or-mark mark"
+.BR "\-\-or\-mark mark"
 Binary OR the mark with bits.
 
 .SH NOTES
@@ -343,6 +357,6 @@ chain in
 .SH MAILINGLISTS
 .BR "" "See " http://netfilter.org/mailinglists.html
 .SH SEE ALSO
-.BR xtables-nft "(8), " iptables "(8), " ebtables "(8), " ip (8)
+.BR xtables\-nft "(8), " iptables "(8), " ebtables "(8), " ip (8)
 .PP
 .BR "" "See " https://wiki.nftables.org
diff --git a/iptables/ebtables-nft.8 b/iptables/ebtables-nft.8
index 0304b508..86981650 100644
--- a/iptables/ebtables-nft.8
+++ b/iptables/ebtables-nft.8
@@ -24,7 +24,7 @@
 .\"     
 .\"
 .SH NAME
-ebtables \- Ethernet bridge frame table administration (nft-based)
+ebtables \(em Ethernet bridge frame table administration (nft-based)
 .SH SYNOPSIS
 .BR "ebtables " [ -t " table ] " - [ ACDI "] chain rule specification [match extensions] [watcher extensions] target"
 .br
@@ -321,7 +321,7 @@ of the ebtables kernel table.
 .TP
 .B "--init-table"
 Replace the current table data by the initial table data.
-.SS MISCELLANOUS COMMANDS
+.SS MISCELLANEOUS COMMANDS
 .TP
 .B "-v, --verbose"
 Verbose mode.
@@ -358,7 +358,8 @@ When talking to the kernel, use this
 to try to automatically load missing kernel modules.
 .TP
 .B --concurrent
-Use a file lock to support concurrent scripts updating the ebtables kernel tables.
+This would use a file lock to support concurrent scripts updating the ebtables
+kernel tables. It is not needed with \fBebtables-nft\fP though and thus ignored.
 
 .SS
 RULE SPECIFICATIONS
@@ -372,7 +373,7 @@ and the
 .BR "WATCHER EXTENSIONS" 
 below.
 .TP
-.BR "-p, --protocol " "[!] \fIprotocol\fP"
+.RB [ ! ] " -p" , " --protocol " \fIprotocol\fP
 The protocol that was responsible for creating the frame. This can be a
 hexadecimal number, above 
 .IR 0x0600 ,
@@ -402,7 +403,7 @@ See that file for more information. The flag
 .B --proto
 is an alias for this option.
 .TP 
-.BR "-i, --in-interface " "[!] \fIname\fP"
+.RB [ ! ] " -i" , " --in-interface " \fIname\fP
 The interface (bridge port) via which a frame is received (this option is useful in the
 .BR INPUT ,
 .BR FORWARD ,
@@ -413,7 +414,7 @@ The flag
 .B --in-if
 is an alias for this option.
 .TP
-.BR "--logical-in " "[!] \fIname\fP"
+.RB [ ! ] " --logical-in " \fIname\fP
 The (logical) bridge interface via which a frame is received (this option is useful in the
 .BR INPUT ,
 .BR FORWARD ,
@@ -422,7 +423,7 @@ chains).
 If the interface name ends with '+', then
 any interface name that begins with this name (disregarding '+') will match.
 .TP
-.BR "-o, --out-interface " "[!] \fIname\fP"
+.RB [ ! ] " -o" , " --out-interface " \fIname\fP
 The interface (bridge port) via which a frame is going to be sent (this option is useful in the
 .BR OUTPUT ,
 .B FORWARD
@@ -434,7 +435,7 @@ The flag
 .B --out-if
 is an alias for this option.
 .TP
-.BR "--logical-out " "[!] \fIname\fP"
+.RB [ ! ] " --logical-out " \fIname\fP
 The (logical) bridge interface via which a frame is going to be sent (this option
 is useful in the
 .BR OUTPUT ,
@@ -445,7 +446,7 @@ chains).
 If the interface name ends with '+', then
 any interface name that begins with this name (disregarding '+') will match.
 .TP
-.BR "-s, --source " "[!] \fIaddress\fP[/\fImask\fP]"
+.RB [ ! ] " -s" , " --source " \fIaddress\fP[ / \fImask\fP]
 The source MAC address. Both mask and address are written as 6 hexadecimal
 numbers separated by colons. Alternatively one can specify Unicast,
 Multicast, Broadcast or BGA (Bridge Group Address):
@@ -459,7 +460,7 @@ address will also match the multicast specification. The flag
 .B --src
 is an alias for this option.
 .TP
-.BR "-d, --destination " "[!] \fIaddress\fP[/\fImask\fP]"
+.RB [ ! ] " -d" , " --destination " \fIaddress\fP[ / \fImask\fP]
 The destination MAC address. See
 .B -s
 (above) for more details on MAC addresses. The flag
@@ -484,11 +485,11 @@ the core ebtables code.
 Specify 802.3 DSAP/SSAP fields or SNAP type.  The protocol must be specified as
 .IR "LENGTH " "(see the option " " -p " above).
 .TP
-.BR "--802_3-sap " "[!] \fIsap\fP"
+.RB [ ! ] " --802_3-sap " \fIsap\fP
 DSAP and SSAP are two one byte 802.3 fields.  The bytes are always
 equal, so only one byte (hexadecimal) is needed as an argument.
 .TP
-.BR "--802_3-type " "[!] \fItype\fP"
+.RB [ ! ] " --802_3-type " \fItype\fP
 If the 802.3 DSAP and SSAP values are 0xaa then the SNAP type field must
 be consulted to determine the payload protocol.  This is a two byte
 (hexadecimal) argument.  Only 802.3 frames with DSAP/SSAP 0xaa are
@@ -503,88 +504,88 @@ the MAC address is optional. Multiple MAC/IP address pairs with the same MAC add
 but different IP address (and vice versa) can be specified. If the MAC address doesn't
 match any entry from the list, the frame doesn't match the rule (unless "!" was used).
 .TP
-.BR "--among-dst " "[!] \fIlist\fP"
+.RB [ ! ] " --among-dst " \fIlist\fP
 Compare the MAC destination to the given list. If the Ethernet frame has type
 .IR IPv4 " or " ARP ,
 then comparison with MAC/IP destination address pairs from the
 list is possible.
 .TP
-.BR "--among-src " "[!] \fIlist\fP"
+.RB [ ! ] " --among-src " \fIlist\fP
 Compare the MAC source to the given list. If the Ethernet frame has type
 .IR IPv4 " or " ARP ,
 then comparison with MAC/IP source address pairs from the list
 is possible.
 .TP
-.BR "--among-dst-file " "[!] \fIfile\fP"
+.RB [ ! ] " --among-dst-file " \fIfile\fP
 Same as
 .BR --among-dst " but the list is read in from the specified file."
 .TP
-.BR "--among-src-file " "[!] \fIfile\fP"
+.RB [ ! ] " --among-src-file " \fIfile\fP
 Same as
 .BR --among-src " but the list is read in from the specified file."
 .SS arp
 Specify (R)ARP fields. The protocol must be specified as
 .IR ARP " or " RARP .
 .TP
-.BR "--arp-opcode " "[!] \fIopcode\fP"
+.RB [ ! ] " --arp-opcode " \fIopcode\fP
 The (R)ARP opcode (decimal or a string, for more details see
 .BR "ebtables -h arp" ).
 .TP
-.BR "--arp-htype " "[!] \fIhardware type\fP"
+.RB [ ! ] " --arp-htype " \fIhardware-type\fP
 The hardware type, this can be a decimal or the string
 .I Ethernet
 (which sets
 .I type
 to 1). Most (R)ARP packets have Eternet as hardware type.
 .TP
-.BR "--arp-ptype " "[!] \fIprotocol type\fP"
+.RB [ ! ] " --arp-ptype " \fIprotocol-type\fP
 The protocol type for which the (r)arp is used (hexadecimal or the string
 .IR IPv4 ,
 denoting 0x0800).
 Most (R)ARP packets have protocol type IPv4.
 .TP
-.BR "--arp-ip-src " "[!] \fIaddress\fP[/\fImask\fP]"
+.RB [ ! ] " --arp-ip-src " \fIaddress\fP[ / \fImask\fP]
 The (R)ARP IP source address specification.
 .TP
-.BR "--arp-ip-dst " "[!] \fIaddress\fP[/\fImask\fP]"
+.RB [ ! ] " --arp-ip-dst " \fIaddress\fP[ / \fImask\fP]
 The (R)ARP IP destination address specification.
 .TP
-.BR "--arp-mac-src " "[!] \fIaddress\fP[/\fImask\fP]"
+.RB [ ! ] " --arp-mac-src " \fIaddress\fP[ / \fImask\fP]
 The (R)ARP MAC source address specification.
 .TP
-.BR "--arp-mac-dst " "[!] \fIaddress\fP[/\fImask\fP]"
+.RB [ ! ] " --arp-mac-dst " \fIaddress\fP[ / \fImask\fP]
 The (R)ARP MAC destination address specification.
 .TP
-.BR "" "[!]" " --arp-gratuitous"
+.RB [ ! ] " --arp-gratuitous"
 Checks for ARP gratuitous packets: checks equality of IPv4 source
 address and IPv4 destination address inside the ARP header.
 .SS ip
 Specify IPv4 fields. The protocol must be specified as
 .IR IPv4 .
 .TP
-.BR "--ip-source " "[!] \fIaddress\fP[/\fImask\fP]"
+.RB [ ! ] " --ip-source " \fIaddress\fP[ / \fImask\fP]
 The source IP address.
 The flag
 .B --ip-src
 is an alias for this option.
 .TP
-.BR "--ip-destination " "[!] \fIaddress\fP[/\fImask\fP]"
+.RB [ ! ] " --ip-destination " \fIaddress\fP[ / \fImask\fP]
 The destination IP address.
 The flag
 .B --ip-dst
 is an alias for this option.
 .TP
-.BR "--ip-tos " "[!] \fItos\fP"
+.RB [ ! ] " --ip-tos " \fItos\fP
 The IP type of service, in hexadecimal numbers.
 .BR IPv4 .
 .TP
-.BR "--ip-protocol " "[!] \fIprotocol\fP"
+.RB [ ! ] " --ip-protocol " \fIprotocol\fP
 The IP protocol.
 The flag
 .B --ip-proto
 is an alias for this option.
 .TP
-.BR "--ip-source-port " "[!] \fIport1\fP[:\fIport2\fP]"
+.RB [ ! ] " --ip-source-port " \fIport1\fP[ : \fIport2\fP]
 The source port or port range for the IP protocols 6 (TCP), 17
 (UDP), 33 (DCCP) or 132 (SCTP). The
 .B --ip-protocol
@@ -596,7 +597,7 @@ The flag
 .B --ip-sport
 is an alias for this option.
 .TP
-.BR "--ip-destination-port " "[!] \fIport1\fP[:\fIport2\fP]"
+.RB [ ! ] " --ip-destination-port " \fIport1\fP[ : \fIport2\fP]
 The destination port or port range for ip protocols 6 (TCP), 17
 (UDP), 33 (DCCP) or 132 (SCTP). The
 .B --ip-protocol
@@ -611,28 +612,28 @@ is an alias for this option.
 Specify IPv6 fields. The protocol must be specified as
 .IR IPv6 .
 .TP
-.BR "--ip6-source " "[!] \fIaddress\fP[/\fImask\fP]"
+.RB [ ! ] " --ip6-source " \fIaddress\fP[ / \fImask\fP]
 The source IPv6 address.
 The flag
 .B --ip6-src
 is an alias for this option.
 .TP
-.BR "--ip6-destination " "[!] \fIaddress\fP[/\fImask\fP]"
+.RB [ ! ] " --ip6-destination " \fIaddress\fP[ / \fImask\fP]
 The destination IPv6 address.
 The flag
 .B --ip6-dst
 is an alias for this option.
 .TP
-.BR "--ip6-tclass " "[!] \fItclass\fP"
+.RB [ ! ] " --ip6-tclass " \fItclass\fP
 The IPv6 traffic class, in hexadecimal numbers.
 .TP
-.BR "--ip6-protocol " "[!] \fIprotocol\fP"
+.RB [ ! ] " --ip6-protocol " \fIprotocol\fP
 The IP protocol.
 The flag
 .B --ip6-proto
 is an alias for this option.
 .TP
-.BR "--ip6-source-port " "[!] \fIport1\fP[:\fIport2\fP]"
+.RB [ ! ] " --ip6-source-port " \fIport1\fP[ : \fIport2\fP]
 The source port or port range for the IPv6 protocols 6 (TCP), 17
 (UDP), 33 (DCCP) or 132 (SCTP). The
 .B --ip6-protocol
@@ -644,7 +645,7 @@ The flag
 .B --ip6-sport
 is an alias for this option.
 .TP
-.BR "--ip6-destination-port " "[!] \fIport1\fP[:\fIport2\fP]"
+.RB [ ! ] " --ip6-destination-port " \fIport1\fP[ : \fIport2\fP]
 The destination port or port range for IPv6 protocols 6 (TCP), 17
 (UDP), 33 (DCCP) or 132 (SCTP). The
 .B --ip6-protocol
@@ -656,7 +657,7 @@ The flag
 .B --ip6-dport
 is an alias for this option.
 .TP
-.BR "--ip6-icmp-type " "[!] {\fItype\fP[:\fItype\fP]/\fIcode\fP[:\fIcode\fP]|\fItypename\fP}"
+.RB [ ! ] " --ip6-icmp-type " {\fItype\fP[ : \fItype\fP] / \fIcode\fP[ : \fIcode\fP]|\fItypename\fP}
 Specify ipv6\-icmp type and code to match.
 Ranges for both type and code are supported. Type and code are
 separated by a slash. Valid numbers for type and range are 0 to 255.
@@ -685,7 +686,7 @@ number; the default is
 .IR 5 .
 .SS mark_m
 .TP
-.BR "--mark " "[!] [\fIvalue\fP][/\fImask\fP]"
+.RB [ ! ] " --mark " [\fIvalue\fP][ / \fImask\fP]
 Matches frames with the given unsigned mark value. If a
 .IR value " and " mask " are specified, the logical AND of the mark value of the frame and"
 the user-specified
@@ -704,7 +705,7 @@ non-zero. Only specifying a
 .IR mask " is useful to match multiple mark values."
 .SS pkttype
 .TP
-.BR "--pkttype-type " "[!] \fItype\fP"
+.RB [ ! ] " --pkttype-type " \fItype\fP
 Matches on the Ethernet "class" of the frame, which is determined by the
 generic networking code. Possible values:
 .IR broadcast " (MAC destination is the broadcast address),"
@@ -721,47 +722,47 @@ if the lower bound is omitted (but the colon is not), then the lowest possible l
 for that option is used, while if the upper bound is omitted (but the colon again is not), the
 highest possible upper bound for that option is used.
 .TP
-.BR "--stp-type " "[!] \fItype\fP"
-The BPDU type (0-255), recognized non-numerical types are
+.RB [ ! ] " --stp-type " \fItype\fP
+The BPDU type (0\(en255), recognized non-numerical types are
 .IR config ", denoting a configuration BPDU (=0), and"
 .IR tcn ", denothing a topology change notification BPDU (=128)."
 .TP
-.BR "--stp-flags " "[!] \fIflag\fP"
-The BPDU flag (0-255), recognized non-numerical flags are
+.RB [ ! ] " --stp-flags " \fIflag\fP
+The BPDU flag (0\(en255), recognized non-numerical flags are
 .IR topology-change ", denoting the topology change flag (=1), and"
 .IR topology-change-ack ", denoting the topology change acknowledgement flag (=128)."
 .TP
-.BR "--stp-root-prio " "[!] [\fIprio\fP][:\fIprio\fP]"
-The root priority (0-65535) range.
+.RB [ ! ] " --stp-root-prio " [\fIprio\fP][ : \fIprio\fP]
+The root priority (0\(en65535) range.
 .TP
-.BR "--stp-root-addr " "[!] [\fIaddress\fP][/\fImask\fP]"
+.RB [ ! ] " --stp-root-addr " [\fIaddress\fP][ / \fImask\fP]
 The root mac address, see the option
 .BR -s " for more details."
 .TP
-.BR "--stp-root-cost " "[!] [\fIcost\fP][:\fIcost\fP]"
-The root path cost (0-4294967295) range.
+.RB [ ! ] " --stp-root-cost " [\fIcost\fP][ : \fIcost\fP]
+The root path cost (0\(en4294967295) range.
 .TP
-.BR "--stp-sender-prio " "[!] [\fIprio\fP][:\fIprio\fP]"
-The BPDU's sender priority (0-65535) range.
+.RB [ ! ] " --stp-sender-prio " [\fIprio\fP][ : \fIprio\fP]
+The BPDU's sender priority (0\(en65535) range.
 .TP
-.BR "--stp-sender-addr " "[!] [\fIaddress\fP][/\fImask\fP]"
+.RB [ ! ] " --stp-sender-addr " [\fIaddress\fP][ / \fImask\fP]
 The BPDU's sender mac address, see the option
 .BR -s " for more details."
 .TP
-.BR "--stp-port " "[!] [\fIport\fP][:\fIport\fP]"
-The port identifier (0-65535) range.
+.RB [ ! ] " --stp-port " [\fIport\fP][ : \fIport\fP]
+The port identifier (0\(en65535) range.
 .TP
-.BR "--stp-msg-age " "[!] [\fIage\fP][:\fIage\fP]"
-The message age timer (0-65535) range.
+.RB [ ! ] " --stp-msg-age " [\fIage\fP][ : \fIage\fP]
+The message age timer (0\(en65535) range.
 .TP
-.BR "--stp-max-age " "[!] [\fIage\fP][:\fIage\fP]"
-The max age timer (0-65535) range.
+.RB [ ! ] " --stp-max-age " [\fIage\fP][ : \fIage\fP]
+The max age timer (0\(en65535) range.
 .TP
-.BR "--stp-hello-time " "[!] [\fItime\fP][:\fItime\fP]"
-The hello time timer (0-65535) range.
+.RB [ ! ] " --stp-hello-time " [\fItime\fP][ : \fItime\fP]
+The hello time timer (0\(en65535) range.
 .TP
-.BR "--stp-forward-delay " "[!] [\fIdelay\fP][:\fIdelay\fP]"
-The forward delay timer (0-65535) range.
+.RB [ ! ] " --stp-forward-delay " [\fIdelay\fP][ : \fIdelay\fP]
+The forward delay timer (0\(en65535) range.
 .\" .SS string
 .\" This module matches on a given string using some pattern matching strategy.
 .\" .TP
@@ -774,10 +775,10 @@ The forward delay timer (0-65535) range.
 .\" .BR "--string-to " "\fIoffset\fP"
 .\" The highest offset from which a match can start. (default: size of frame)
 .\" .TP
-.\" .BR "--string " "[!] \fIpattern\fP"
+.\" .RB [ ! ] " --string " \fIpattern\fP
 .\" Matches the given pattern.
 .\" .TP
-.\" .BR "--string-hex " "[!] \fIpattern\fP"
+.\" .RB [ ! ] " --string-hex " \fIpattern\fP
 .\" Matches the given pattern in hex notation, e.g. '|0D 0A|', '|0D0A|', 'www|09|netfilter|03|org|00|'
 .\" .TP
 .\" .BR "--string-icase"
@@ -787,15 +788,15 @@ Specify 802.1Q Tag Control Information fields.
 The protocol must be specified as
 .IR 802_1Q " (0x8100)."
 .TP
-.BR "--vlan-id " "[!] \fIid\fP"
+.RB [ ! ] " --vlan-id " \fIid\fP
 The VLAN identifier field (VID). Decimal number from 0 to 4095.
 .TP
-.BR "--vlan-prio " "[!] \fIprio\fP"
+.RB [ ! ] " --vlan-prio " \fIprio\fP
 The user priority field, a decimal number from 0 to 7.
 The VID should be set to 0 ("null VID") or unspecified
 (in the latter case the VID is deliberately set to 0).
 .TP
-.BR "--vlan-encap " "[!] \fItype\fP"
+.RB [ ! ] " --vlan-encap " \fItype\fP
 The encapsulated Ethernet frame type/length.
 Specified as a hexadecimal
 number from 0x0000 to 0xFFFF or as a symbolic name
@@ -812,7 +813,7 @@ The log watcher writes descriptive data about a frame to the syslog.
 .TP
 .B "--log"
 .br
-Log with the default loggin options: log-level=
+Log with the default logging options: log-level=
 .IR info ,
 log-prefix="", no ip logging, no arp logging.
 .TP
@@ -858,7 +859,7 @@ Log with the default logging options
 .TP
 .B --nflog-group "\fInlgroup\fP"
 .br
-The netlink group (1 - 2^32-1) to which packets are (only applicable for
+The netlink group (1\(en2\(ha32\-1) to which packets are (only applicable for
 nfnetlink_log). The default value is 1.
 .TP
 .B --nflog-prefix "\fIprefix\fP"
diff --git a/iptables/ip6tables.c b/iptables/ip6tables.c
index 9afc32c1..f9ae18ae 100644
--- a/iptables/ip6tables.c
+++ b/iptables/ip6tables.c
@@ -509,8 +509,7 @@ void print_rule6(const struct ip6t_entry *e,
 	save_ipv6_addr('d', &e->ipv6.dst, &e->ipv6.dmsk,
 		       e->ipv6.invflags & IP6T_INV_DSTIP);
 
-	save_rule_details(e->ipv6.iniface, e->ipv6.iniface_mask,
-			  e->ipv6.outiface, e->ipv6.outiface_mask,
+	save_rule_details(e->ipv6.iniface, e->ipv6.outiface,
 			  e->ipv6.proto, 0, e->ipv6.invflags);
 
 #if 0
@@ -669,6 +668,10 @@ int do_command6(int argc, char *argv[], char **table,
 	struct xt_cmd_parse_ops cmd_parse_ops = {
 		.proto_parse	= ipv6_proto_parse,
 		.post_parse	= ipv6_post_parse,
+		.option_name	= ip46t_option_name,
+		.option_invert	= ip46t_option_invert,
+		.command_default = command_default,
+		.print_help	= xtables_printhelp,
 	};
 	struct xt_cmd_parse p = {
 		.table		= *table,
@@ -712,6 +715,9 @@ int do_command6(int argc, char *argv[], char **table,
 	smasks		= args.s.mask.v6;
 	dmasks		= args.d.mask.v6;
 
+	iface_to_mask(cs.fw6.ipv6.iniface, cs.fw6.ipv6.iniface_mask);
+	iface_to_mask(cs.fw6.ipv6.outiface, cs.fw6.ipv6.outiface_mask);
+
 	/* Attempt to acquire the xtables lock */
 	if (!restore)
 		xtables_lock_or_exit(wait);
@@ -886,10 +892,7 @@ int do_command6(int argc, char *argv[], char **table,
 		e = NULL;
 	}
 
-	free(saddrs);
-	free(smasks);
-	free(daddrs);
-	free(dmasks);
+	xtables_clear_args(&args);
 	xtables_free_opts(1);
 
 	return ret;
diff --git a/iptables/iptables-apply.8.in b/iptables/iptables-apply.8.in
index f0ed4e5f..33fd79fe 100644
--- a/iptables/iptables-apply.8.in
+++ b/iptables/iptables-apply.8.in
@@ -3,10 +3,8 @@
 .\"      Date: May 10, 2010
 .\"
 .TH IPTABLES\-APPLY 8 "" "@PACKAGE_STRING@" "@PACKAGE_STRING@"
-.\" disable hyphenation
-.nh
 .SH NAME
-iptables-apply \- a safer way to update iptables remotely
+iptables-apply \(em a safer way to update iptables remotely
 .SH SYNOPSIS
 \fBiptables\-apply\fP [\-\fBhV\fP] [\fB-t\fP \fItimeout\fP] [\fB-w\fP \fIsavefile\fP] {[\fIrulesfile]|-c [runcmd]}\fP
 .SH "DESCRIPTION"
diff --git a/iptables/iptables.8.in b/iptables/iptables.8.in
index ecaa5553..21fb891d 100644
--- a/iptables/iptables.8.in
+++ b/iptables/iptables.8.in
@@ -45,15 +45,15 @@ iptables/ip6tables \(em administration tool for IPv4/IPv6 packet filtering and N
 .PP
 \fBiptables\fP [\fB\-t\fP \fItable\fP] \fB\-X\fP [\fIchain\fP]
 .PP
-\fBiptables\fP [\fB\-t\fP \fItable\fP] \fB\-P\fP \fIchain target\fP
+\fBiptables\fP [\fB\-t\fP \fItable\fP] \fB\-P\fP \fIchain policy\fP
 .PP
 \fBiptables\fP [\fB\-t\fP \fItable\fP] \fB\-E\fP \fIold-chain-name new-chain-name\fP
 .PP
-rule-specification = [\fImatches...\fP] [\fItarget\fP]
+rule-specification := [matches...] [target]
 .PP
-match = \fB\-m\fP \fImatchname\fP [\fIper-match-options\fP]
+match := \fB\-m\fP \fImatchname\fP [per-match-options]
 .PP
-target = \fB\-j\fP \fItargetname\fP [\fIper\-target\-options\fP]
+target := \fB\-j\fP \fItargetname\fP [per-target-options]
 .SH DESCRIPTION
 \fBIptables\fP and \fBip6tables\fP are used to set up, maintain, and inspect the
 tables of IPv4 and IPv6 packet
diff --git a/iptables/iptables.c b/iptables/iptables.c
index 6f7b3476..8eb043e9 100644
--- a/iptables/iptables.c
+++ b/iptables/iptables.c
@@ -516,8 +516,7 @@ void print_rule4(const struct ipt_entry *e,
 	save_ipv4_addr('d', &e->ip.dst, &e->ip.dmsk,
 			e->ip.invflags & IPT_INV_DSTIP);
 
-	save_rule_details(e->ip.iniface, e->ip.iniface_mask,
-			  e->ip.outiface, e->ip.outiface_mask,
+	save_rule_details(e->ip.iniface, e->ip.outiface,
 			  e->ip.proto, e->ip.flags & IPT_F_FRAG,
 			  e->ip.invflags);
 
@@ -663,6 +662,10 @@ int do_command4(int argc, char *argv[], char **table,
 	struct xt_cmd_parse_ops cmd_parse_ops = {
 		.proto_parse	= ipv4_proto_parse,
 		.post_parse	= ipv4_post_parse,
+		.option_name	= ip46t_option_name,
+		.option_invert	= ip46t_option_invert,
+		.command_default = command_default,
+		.print_help	= xtables_printhelp,
 	};
 	struct xt_cmd_parse p = {
 		.table		= *table,
@@ -705,6 +708,9 @@ int do_command4(int argc, char *argv[], char **table,
 	smasks		= args.s.mask.v4;
 	dmasks		= args.d.mask.v4;
 
+	iface_to_mask(cs.fw.ip.iniface, cs.fw.ip.iniface_mask);
+	iface_to_mask(cs.fw.ip.outiface, cs.fw.ip.outiface_mask);
+
 	/* Attempt to acquire the xtables lock */
 	if (!restore)
 		xtables_lock_or_exit(wait);
@@ -881,10 +887,7 @@ int do_command4(int argc, char *argv[], char **table,
 		e = NULL;
 	}
 
-	free(saddrs);
-	free(smasks);
-	free(daddrs);
-	free(dmasks);
+	xtables_clear_args(&args);
 	xtables_free_opts(1);
 
 	return ret;
diff --git a/iptables/nft-arp.c b/iptables/nft-arp.c
index aed39ebd..fa2dd558 100644
--- a/iptables/nft-arp.c
+++ b/iptables/nft-arp.c
@@ -18,6 +18,7 @@
 
 #include <xtables.h>
 #include <libiptc/libxtc.h>
+#include <arpa/inet.h>
 #include <net/if_arp.h>
 #include <netinet/if_ether.h>
 
@@ -58,41 +59,56 @@ static int nft_arp_add(struct nft_handle *h, struct nft_rule_ctx *ctx,
 	}
 
 	if (fw->arp.arhrd != 0 ||
+	    fw->arp.arhrd_mask != 0xffff ||
 	    fw->arp.invflags & IPT_INV_ARPHRD) {
 		uint8_t reg;
 
 		op = nft_invflags2cmp(fw->arp.invflags, IPT_INV_ARPHRD);
 		add_payload(h, r, offsetof(struct arphdr, ar_hrd), 2,
 			    NFT_PAYLOAD_NETWORK_HEADER, &reg);
+		if (fw->arp.arhrd_mask != 0xffff)
+			add_bitwise_u16(h, r, fw->arp.arhrd_mask, 0, reg, &reg);
 		add_cmp_u16(r, fw->arp.arhrd, op, reg);
 	}
 
 	if (fw->arp.arpro != 0 ||
+	    fw->arp.arpro_mask != 0xffff ||
 	    fw->arp.invflags & IPT_INV_PROTO) {
 		uint8_t reg;
 
 		op = nft_invflags2cmp(fw->arp.invflags, IPT_INV_PROTO);
 	        add_payload(h, r, offsetof(struct arphdr, ar_pro), 2,
 			    NFT_PAYLOAD_NETWORK_HEADER, &reg);
+		if (fw->arp.arpro_mask != 0xffff)
+			add_bitwise_u16(h, r, fw->arp.arpro_mask, 0, reg, &reg);
 		add_cmp_u16(r, fw->arp.arpro, op, reg);
 	}
 
 	if (fw->arp.arhln != 0 ||
+	    fw->arp.arhln_mask != 255 ||
 	    fw->arp.invflags & IPT_INV_ARPHLN) {
+		uint8_t reg;
+
 		op = nft_invflags2cmp(fw->arp.invflags, IPT_INV_ARPHLN);
-		add_proto(h, r, offsetof(struct arphdr, ar_hln), 1,
-			  fw->arp.arhln, op);
+		add_payload(h, r, offsetof(struct arphdr, ar_hln), 1,
+			    NFT_PAYLOAD_NETWORK_HEADER, &reg);
+		if (fw->arp.arhln_mask != 255)
+			add_bitwise(h, r, &fw->arp.arhln_mask, 1, reg, &reg);
+		add_cmp_u8(r, fw->arp.arhln, op, reg);
 	}
 
 	add_proto(h, r, offsetof(struct arphdr, ar_pln), 1, 4, NFT_CMP_EQ);
 
 	if (fw->arp.arpop != 0 ||
+	    fw->arp.arpop_mask != 0xffff ||
 	    fw->arp.invflags & IPT_INV_ARPOP) {
 		uint8_t reg;
 
 		op = nft_invflags2cmp(fw->arp.invflags, IPT_INV_ARPOP);
 		add_payload(h, r, offsetof(struct arphdr, ar_op), 2,
 			    NFT_PAYLOAD_NETWORK_HEADER, &reg);
+		if (fw->arp.arpop_mask != 0xffff)
+			add_bitwise_u16(h, r, fw->arp.arpop_mask, 0, reg, &reg);
 		add_cmp_u16(r, fw->arp.arpop, op, reg);
 	}
 
@@ -181,13 +197,23 @@ static void nft_arp_print_header(unsigned int format, const char *chain,
 	}
 }
 
+static void print_iface(char letter, const char *iface,
+			unsigned int format, bool invert, const char **sep)
+{
+	if (iface[0] == '\0' || (!strcmp(iface, "+") && !invert)) {
+		if (!(format & FMT_VIA))
+			return;
+		iface = (format & FMT_NUMERIC) ? "*" : "any";
+	}
+	printf("%s%s-%c %s", *sep, invert ? "! " : "", letter, iface);
+	*sep = " ";
+}
+
 static void nft_arp_print_rule_details(const struct iptables_command_state *cs,
 				       unsigned int format)
 {
 	const struct arpt_entry *fw = &cs->arp;
-	char iface[IFNAMSIZ+2];
 	const char *sep = "";
-	int print_iface = 0;
 	int i;
 
 	if (strlen(cs->jumpto)) {
@@ -195,40 +221,10 @@ static void nft_arp_print_rule_details(const struct iptables_command_state *cs,
 		sep = " ";
 	}
 
-	iface[0] = '\0';
-
-	if (fw->arp.iniface[0] != '\0') {
-		strcat(iface, fw->arp.iniface);
-		print_iface = 1;
-	}
-	else if (format & FMT_VIA) {
-		print_iface = 1;
-		if (format & FMT_NUMERIC) strcat(iface, "*");
-		else strcat(iface, "any");
-	}
-	if (print_iface) {
-		printf("%s%s-i %s", sep, fw->arp.invflags & IPT_INV_VIA_IN ?
-				   "! " : "", iface);
-		sep = " ";
-	}
-
-	print_iface = 0;
-	iface[0] = '\0';
-
-	if (fw->arp.outiface[0] != '\0') {
-		strcat(iface, fw->arp.outiface);
-		print_iface = 1;
-	}
-	else if (format & FMT_VIA) {
-		print_iface = 1;
-		if (format & FMT_NUMERIC) strcat(iface, "*");
-		else strcat(iface, "any");
-	}
-	if (print_iface) {
-		printf("%s%s-o %s", sep, fw->arp.invflags & IPT_INV_VIA_OUT ?
-				   "! " : "", iface);
-		sep = " ";
-	}
+	print_iface('i', fw->arp.iniface, format,
+		    fw->arp.invflags & IPT_INV_VIA_IN, &sep);
+	print_iface('o', fw->arp.outiface, format,
+		    fw->arp.invflags & IPT_INV_VIA_OUT, &sep);
 
 	if (fw->arp.smsk.s_addr != 0L) {
 		printf("%s%s-s %s", sep,
@@ -283,7 +279,8 @@ after_devdst:
 		sep = " ";
 	}
 
-	if (fw->arp.arpop_mask != 0) {
+	if (fw->arp.arpop_mask != 65535 || fw->arp.arpop != 0 ||
+	    fw->arp.invflags & IPT_INV_ARPOP) {
 		int tmp = ntohs(fw->arp.arpop);
 
 		printf("%s%s", sep, fw->arp.invflags & IPT_INV_ARPOP
@@ -307,13 +304,14 @@ after_devdst:
 		if (tmp == 1 && !(format & FMT_NUMERIC))
 			printf("--h-type %s", "Ethernet");
 		else
-			printf("--h-type %u", tmp);
+			printf("--h-type 0x%x", tmp);
 		if (fw->arp.arhrd_mask != 65535)
-			printf("/%d", ntohs(fw->arp.arhrd_mask));
+			printf("/0x%x", ntohs(fw->arp.arhrd_mask));
 		sep = " ";
 	}
 
-	if (fw->arp.arpro_mask != 0) {
+	if (fw->arp.arpro_mask != 65535 || fw->arp.arpro != 0 ||
+	    fw->arp.invflags & IPT_INV_PROTO) {
 		int tmp = ntohs(fw->arp.arpro);
 
 		printf("%s%s", sep, fw->arp.invflags & IPT_INV_PROTO
@@ -323,7 +321,7 @@ after_devdst:
 		else
 			printf("--proto-type 0x%x", tmp);
 		if (fw->arp.arpro_mask != 65535)
-			printf("/%x", ntohs(fw->arp.arpro_mask));
+			printf("/0x%x", ntohs(fw->arp.arpro_mask));
 		sep = " ";
 	}
 }
@@ -340,6 +338,8 @@ nft_arp_save_rule(const struct iptables_command_state *cs, unsigned int format)
 	printf("\n");
 }
 
+static void nft_arp_init_cs(struct iptables_command_state *cs);
+
 static void
 nft_arp_print_rule(struct nft_handle *h, struct nftnl_rule *r,
 		   unsigned int num, unsigned int format)
@@ -349,6 +349,7 @@ nft_arp_print_rule(struct nft_handle *h, struct nftnl_rule *r,
 	if (format & FMT_LINENUMBERS)
 		printf("%u ", num);
 
+	nft_arp_init_cs(&cs);
 	nft_rule_to_iptables_command_state(h, r, &cs);
 
 	nft_arp_print_rule_details(&cs, format);
@@ -384,14 +385,8 @@ static bool nft_arp_is_same(const struct iptables_command_state *cs_a,
 		return false;
 	}
 
-	return is_same_interfaces(a->arp.iniface,
-				  a->arp.outiface,
-				  (unsigned char *)a->arp.iniface_mask,
-				  (unsigned char *)a->arp.outiface_mask,
-				  b->arp.iniface,
-				  b->arp.outiface,
-				  (unsigned char *)b->arp.iniface_mask,
-				  (unsigned char *)b->arp.outiface_mask);
+	return is_same_interfaces(a->arp.iniface, a->arp.outiface,
+				  b->arp.iniface, b->arp.outiface);
 }
 
 static void nft_arp_save_chain(const struct nftnl_chain *c, const char *policy)
@@ -464,10 +459,7 @@ static void nft_arp_post_parse(int command,
 	cs->arp.arp.invflags = args->invflags;
 
 	memcpy(cs->arp.arp.iniface, args->iniface, IFNAMSIZ);
-	memcpy(cs->arp.arp.iniface_mask, args->iniface_mask, IFNAMSIZ);
-
 	memcpy(cs->arp.arp.outiface, args->outiface, IFNAMSIZ);
-	memcpy(cs->arp.arp.outiface_mask, args->outiface_mask, IFNAMSIZ);
 
 	cs->arp.counters.pcnt = args->pcnt_cnt;
 	cs->arp.counters.bcnt = args->bcnt_cnt;
@@ -490,7 +482,7 @@ static void nft_arp_post_parse(int command,
 					 &args->d.naddrs);
 
 	if ((args->s.naddrs > 1 || args->d.naddrs > 1) &&
-	    (cs->arp.arp.invflags & (ARPT_INV_SRCIP | ARPT_INV_TGTIP)))
+	    (cs->arp.arp.invflags & (IPT_INV_SRCIP | IPT_INV_DSTIP)))
 		xtables_error(PARAMETER_PROBLEM,
 			      "! not allowed with multiple"
 			      " source or destination IP addresses");
@@ -513,7 +505,7 @@ static void nft_arp_post_parse(int command,
 
 		if (cs->arp.arp.arhln != 6)
 			xtables_error(PARAMETER_PROBLEM,
-				      "Only harware address length of 6 is supported currently.");
+				      "Only hardware address length of 6 is supported currently.");
 	}
 	if (args->arp_opcode) {
 		if (get16_and_mask(args->arp_opcode, &cs->arp.arp.arpop,
@@ -556,6 +548,8 @@ static void nft_arp_init_cs(struct iptables_command_state *cs)
 	cs->arp.arp.arhln_mask = 255;
 	cs->arp.arp.arhrd = htons(ARPHRD_ETHER);
 	cs->arp.arp.arhrd_mask = 65535;
+	cs->arp.arp.arpop_mask = 65535;
+	cs->arp.arp.arpro_mask = 65535;
 }
 
 static int
@@ -646,6 +640,187 @@ nft_arp_replace_entry(struct nft_handle *h,
 	return nft_cmd_rule_replace(h, chain, table, cs, rulenum, verbose);
 }
 
+static void nft_arp_xlate_mac_and_mask(const struct arpt_devaddr_info *devaddr,
+				       const char *addr,
+				       bool invert,
+				       struct xt_xlate *xl)
+{
+	unsigned int i;
+
+	for (i = 0; i < 6; ++i) {
+		if (devaddr->mask[i])
+			break;
+	}
+
+	if (i == 6)
+		return;
+
+	xt_xlate_add(xl, "arp %s ether ", addr);
+	if (invert)
+		xt_xlate_add(xl, "!= ");
+
+	xt_xlate_add(xl, "%02x", (uint8_t)devaddr->addr[0]);
+	for (i = 1; i < 6; ++i)
+		xt_xlate_add(xl, ":%02x", (uint8_t)devaddr->addr[i]);
+
+	for (i = 0; i < 6; ++i) {
+		int j;
+
+		if ((uint8_t)devaddr->mask[i] == 0xff)
+			continue;
+
+		xt_xlate_add(xl, "/%02x", (uint8_t)devaddr->mask[0]);
+
+		for (j = 1; j < 6; ++j)
+			xt_xlate_add(xl, ":%02x", (uint8_t)devaddr->mask[j]);
+		return;
+	}
+}
+
+static void nft_arp_xlate16(uint16_t v, uint16_t m, const char *what,
+			    bool hex, bool inverse,
+			    struct xt_xlate *xl)
+{
+	const char *fmt = hex ? "0x%x " : "%d ";
+
+	if (m) {
+		xt_xlate_add(xl, "arp %s ", what);
+		if (inverse)
+			xt_xlate_add(xl, " !=");
+		if (m != 0xffff) {
+			xt_xlate_add(xl, "& ");
+			xt_xlate_add(xl, fmt, ntohs(m));;
+
+		}
+		xt_xlate_add(xl, fmt, ntohs(v));
+	}
+}
+
+static void nft_arp_xlate_ipv4_addr(const char *what, const struct in_addr *addr,
+				    const struct in_addr *mask,
+				    bool inv, struct xt_xlate *xl)
+{
+	char mbuf[INET_ADDRSTRLEN], abuf[INET_ADDRSTRLEN];
+	const char *op = inv ? "!= " : "";
+	int cidr;
+
+	if (!inv && !addr->s_addr && !mask->s_addr)
+		return;
+
+	inet_ntop(AF_INET, addr, abuf, sizeof(abuf));
+
+	cidr = xtables_ipmask_to_cidr(mask);
+	switch (cidr) {
+	case -1:
+		xt_xlate_add(xl, "arp %s ip & %s %s %s ", what,
+			     inet_ntop(AF_INET, mask, mbuf, sizeof(mbuf)),
+			     inv ? "!=" : "==", abuf);
+		break;
+	case 32:
+		xt_xlate_add(xl, "arp %s ip %s%s ", what, op, abuf);
+		break;
+	default:
+		xt_xlate_add(xl, "arp %s ip %s%s/%d ", what, op, abuf, cidr);
+	}
+}
+
+static int nft_arp_xlate(const struct iptables_command_state *cs,
+			 struct xt_xlate *xl)
+{
+	const struct arpt_entry *fw = &cs->arp;
+	int ret;
+
+	xlate_ifname(xl, "iifname", fw->arp.iniface,
+		     fw->arp.invflags & IPT_INV_VIA_IN);
+	xlate_ifname(xl, "oifname", fw->arp.outiface,
+		     fw->arp.invflags & IPT_INV_VIA_OUT);
+
+	if (fw->arp.arhrd ||
+	    fw->arp.arhrd_mask != 0xffff ||
+	    fw->arp.invflags & IPT_INV_ARPHRD)
+		nft_arp_xlate16(fw->arp.arhrd, fw->arp.arhrd_mask,
+				"htype", false,
+				 fw->arp.invflags & IPT_INV_ARPHRD, xl);
+
+	if (fw->arp.arhln_mask != 255 || fw->arp.arhln ||
+	    fw->arp.invflags & IPT_INV_ARPHLN) {
+		xt_xlate_add(xl, "arp hlen ");
+		if (fw->arp.invflags & IPT_INV_ARPHLN)
+			xt_xlate_add(xl, " !=");
+		if (fw->arp.arhln_mask != 255)
+			xt_xlate_add(xl, "& %d ", fw->arp.arhln_mask);
+		xt_xlate_add(xl, "%d ", fw->arp.arhln);
+	}
+
+	/* added implicitly by arptables-nft */
+	xt_xlate_add(xl, "arp plen %d", 4);
+
+	if (fw->arp.arpop_mask != 65535 ||
+	    fw->arp.arpop != 0 ||
+	    fw->arp.invflags & IPT_INV_ARPOP)
+		nft_arp_xlate16(fw->arp.arpop, fw->arp.arpop_mask,
+				"operation", false,
+				fw->arp.invflags & IPT_INV_ARPOP, xl);
+
+	if (fw->arp.arpro_mask != 65535 ||
+	    fw->arp.invflags & IPT_INV_PROTO ||
+	    fw->arp.arpro)
+		nft_arp_xlate16(fw->arp.arpro, fw->arp.arpro_mask,
+				"ptype", true,
+				fw->arp.invflags & IPT_INV_PROTO, xl);
+
+	if (fw->arp.smsk.s_addr != 0L)
+		nft_arp_xlate_ipv4_addr("saddr", &fw->arp.src, &fw->arp.smsk,
+					fw->arp.invflags & IPT_INV_SRCIP, xl);
+
+	if (fw->arp.tmsk.s_addr != 0L)
+		nft_arp_xlate_ipv4_addr("daddr", &fw->arp.tgt, &fw->arp.tmsk,
+					fw->arp.invflags & IPT_INV_DSTIP, xl);
+
+	nft_arp_xlate_mac_and_mask(&fw->arp.src_devaddr, "saddr",
+				   fw->arp.invflags & IPT_INV_SRCDEVADDR, xl);
+	nft_arp_xlate_mac_and_mask(&fw->arp.tgt_devaddr, "daddr",
+				   fw->arp.invflags & IPT_INV_TGTDEVADDR, xl);
+
+	ret = xlate_matches(cs, xl);
+	if (!ret)
+		return ret;
+
+	/* Always add counters per rule, as in iptables */
+	xt_xlate_add(xl, "counter");
+	return xlate_action(cs, false, xl);
+}
+
+static const char *nft_arp_option_name(int option)
+{
+	switch (option) {
+	default:		return ip46t_option_name(option);
+	/* different name than iptables */
+	case OPT_SOURCE:	return "--source-ip";
+	case OPT_DESTINATION:	return "--destination-ip";
+	/* arptables specific ones */
+	case OPT_S_MAC:		return "--source-mac";
+	case OPT_D_MAC:		return "--destination-mac";
+	case OPT_H_LENGTH:	return "--h-length";
+	case OPT_OPCODE:	return "--opcode";
+	case OPT_H_TYPE:	return "--h-type";
+	case OPT_P_TYPE:	return "--proto-type";
+	}
+}
+
+static int nft_arp_option_invert(int option)
+{
+	switch (option) {
+	case OPT_S_MAC:		return IPT_INV_SRCDEVADDR;
+	case OPT_D_MAC:		return IPT_INV_TGTDEVADDR;
+	case OPT_H_LENGTH:	return IPT_INV_ARPHLN;
+	case OPT_OPCODE:	return IPT_INV_ARPOP;
+	case OPT_H_TYPE:	return IPT_INV_ARPHRD;
+	case OPT_P_TYPE:	return IPT_INV_PROTO;
+	default:		return ip46t_option_invert(option);
+	}
+}
+
 struct nft_family_ops nft_family_ops_arp = {
 	.add			= nft_arp_add,
 	.is_same		= nft_arp_is_same,
@@ -657,10 +832,15 @@ struct nft_family_ops nft_family_ops_arp = {
 	.rule_parse		= &nft_ruleparse_ops_arp,
 	.cmd_parse		= {
 		.post_parse	= nft_arp_post_parse,
+		.option_name	= nft_arp_option_name,
+		.option_invert	= nft_arp_option_invert,
+		.command_default = command_default,
+		.print_help	= xtables_printhelp,
 	},
 	.rule_to_cs		= nft_rule_to_iptables_command_state,
 	.init_cs		= nft_arp_init_cs,
 	.clear_cs		= xtables_clear_iptables_command_state,
+	.xlate			= nft_arp_xlate,
 	.add_entry		= nft_arp_add_entry,
 	.delete_entry		= nft_arp_delete_entry,
 	.check_entry		= nft_arp_check_entry,
diff --git a/iptables/nft-bridge.c b/iptables/nft-bridge.c
index d9a8ad2b..1623acba 100644
--- a/iptables/nft-bridge.c
+++ b/iptables/nft-bridge.c
@@ -46,6 +46,7 @@ void ebt_cs_clean(struct iptables_command_state *cs)
 		free(m);
 		m = nm;
 	}
+	cs->match_list = NULL;
 
 	if (cs->target) {
 		free(cs->target->t);
@@ -134,14 +135,14 @@ static int nft_bridge_add(struct nft_handle *h, struct nft_rule_ctx *ctx,
 	struct ebt_entry *fw = &cs->eb;
 	uint32_t op;
 
-	if (fw->bitmask & EBT_ISOURCE) {
+	if (fw->bitmask & EBT_SOURCEMAC) {
 		op = nft_invflags2cmp(fw->invflags, EBT_ISOURCE);
 		add_addr(h, r, NFT_PAYLOAD_LL_HEADER,
 			 offsetof(struct ethhdr, h_source),
 			 fw->sourcemac, fw->sourcemsk, ETH_ALEN, op);
 	}
 
-	if (fw->bitmask & EBT_IDEST) {
+	if (fw->bitmask & EBT_DESTMAC) {
 		op = nft_invflags2cmp(fw->invflags, EBT_IDEST);
 		add_addr(h, r, NFT_PAYLOAD_LL_HEADER,
 			 offsetof(struct ethhdr, h_dest),
@@ -202,18 +203,15 @@ static int nft_bridge_add(struct nft_handle *h, struct nft_rule_ctx *ctx,
 	return _add_action(r, cs);
 }
 
-static bool nft_rule_to_ebtables_command_state(struct nft_handle *h,
-					       const struct nftnl_rule *r,
-					       struct iptables_command_state *cs)
+static void nft_bridge_init_cs(struct iptables_command_state *cs)
 {
 	cs->eb.bitmask = EBT_NOPROTO;
-	return nft_rule_to_iptables_command_state(h, r, cs);
 }
 
 static void print_iface(const char *option, const char *name, bool invert)
 {
-	if (*name)
-		printf("%s%s %s ", option, invert ? " !" : "", name);
+	if (*name && (strcmp(name, "+") || invert))
+		printf("%s%s %s ", invert ? "! " : "", option, name);
 }
 
 static void nft_bridge_print_table_header(const char *tablename)
@@ -258,9 +256,7 @@ static void print_mac(char option, const unsigned char *mac,
 		      const unsigned char *mask,
 		      bool invert)
 {
-	printf("-%c ", option);
-	if (invert)
-		printf("! ");
+	printf("%s-%c ", invert ? "! " : "", option);
 	ebt_print_mac_and_mask(mac, mask);
 	printf(" ");
 }
@@ -275,9 +271,7 @@ static void print_protocol(uint16_t ethproto, bool invert, unsigned int bitmask)
 	if (bitmask & EBT_NOPROTO)
 		return;
 
-	printf("-p ");
-	if (invert)
-		printf("! ");
+	printf("%s-p ", invert ? "! " : "");
 
 	if (bitmask & EBT_802_3) {
 		printf("Length ");
@@ -354,9 +348,10 @@ static void nft_bridge_print_rule(struct nft_handle *h, struct nftnl_rule *r,
 	struct iptables_command_state cs = {};
 
 	if (format & FMT_LINENUMBERS)
-		printf("%d ", num);
+		printf("%d. ", num);
 
-	nft_rule_to_ebtables_command_state(h, r, &cs);
+	nft_bridge_init_cs(&cs);
+	nft_rule_to_iptables_command_state(h, r, &cs);
 	__nft_bridge_save_rule(&cs, format);
 	ebt_cs_clean(&cs);
 }
@@ -377,9 +372,9 @@ static bool nft_bridge_is_same(const struct iptables_command_state *cs_a,
 	int i;
 
 	if (a->ethproto != b->ethproto ||
-	    /* FIXME: a->flags != b->flags || */
+	    a->bitmask != b->bitmask ||
 	    a->invflags != b->invflags) {
-		DEBUGP("different proto/flags/invflags\n");
+		DEBUGP("different proto/bitmask/invflags\n");
 		return false;
 	}
 
@@ -571,17 +566,139 @@ static int nft_bridge_xlate(const struct iptables_command_state *cs,
 	return ret;
 }
 
+static const char *nft_bridge_option_name(int option)
+{
+	switch (option) {
+	/* ebtables specific ones */
+	case OPT_LOGICALIN:	return "--logical-in";
+	case OPT_LOGICALOUT:	return "--logical-out";
+	case OPT_LINENUMBERS:	return "--Ln";
+	case OPT_LIST_C:	return "--Lc";
+	case OPT_LIST_X:	return "--Lx";
+	case OPT_LIST_MAC2:	return "--Lmac2";
+	default:		return ip46t_option_name(option);
+	}
+}
+
+static int nft_bridge_option_invert(int option)
+{
+	switch (option) {
+	case OPT_SOURCE:	return EBT_ISOURCE;
+	case OPT_DESTINATION:	return EBT_IDEST;
+	case OPT_PROTOCOL:	return EBT_IPROTO;
+	case OPT_VIANAMEIN:	return EBT_IIN;
+	case OPT_VIANAMEOUT:	return EBT_IOUT;
+	case OPT_LOGICALIN:	return EBT_ILOGICALIN;
+	case OPT_LOGICALOUT:	return EBT_ILOGICALOUT;
+	default:		return -1;
+	}
+}
+
+static void nft_bridge_proto_parse(struct iptables_command_state *cs,
+				   struct xtables_args *args)
+{
+	char *buffer;
+	int i;
+
+	cs->eb.bitmask &= ~((unsigned int)EBT_NOPROTO);
+
+	i = strtol(cs->protocol, &buffer, 16);
+	if (*buffer == '\0' && (i < 0 || i > 0xFFFF))
+		xtables_error(PARAMETER_PROBLEM,
+			      "Problem with the specified protocol");
+	if (*buffer != '\0') {
+		struct xt_ethertypeent *ent;
+
+		if (!strcmp(cs->protocol, "length")) {
+			cs->eb.bitmask |= EBT_802_3;
+			return;
+		}
+		ent = xtables_getethertypebyname(cs->protocol);
+		if (!ent)
+			xtables_error(PARAMETER_PROBLEM,
+				      "Problem with the specified Ethernet protocol '%s', perhaps "XT_PATH_ETHERTYPES " is missing",
+				      cs->protocol);
+		cs->eb.ethproto = ent->e_ethertype;
+	} else
+		cs->eb.ethproto = i;
+
+	if (cs->eb.ethproto < 0x0600)
+		xtables_error(PARAMETER_PROBLEM,
+			      "Sorry, protocols have values above or equal to 0x0600");
+}
+
+static void nft_bridge_post_parse(int command,
+				  struct iptables_command_state *cs,
+				  struct xtables_args *args)
+{
+	struct ebt_match *match;
+
+	cs->eb.invflags = args->invflags;
+
+	memcpy(cs->eb.in, args->iniface, IFNAMSIZ);
+	memcpy(cs->eb.out, args->outiface, IFNAMSIZ);
+	memcpy(cs->eb.logical_in, args->bri_iniface, IFNAMSIZ);
+	memcpy(cs->eb.logical_out, args->bri_outiface, IFNAMSIZ);
+
+	cs->counters.pcnt = args->pcnt_cnt;
+	cs->counters.bcnt = args->bcnt_cnt;
+
+	if (args->shostnetworkmask) {
+		if (xtables_parse_mac_and_mask(args->shostnetworkmask,
+					       cs->eb.sourcemac,
+					       cs->eb.sourcemsk))
+			xtables_error(PARAMETER_PROBLEM,
+				      "Problem with specified source mac '%s'",
+				      args->shostnetworkmask);
+		cs->eb.bitmask |= EBT_SOURCEMAC;
+	}
+	if (args->dhostnetworkmask) {
+		if (xtables_parse_mac_and_mask(args->dhostnetworkmask,
+					       cs->eb.destmac,
+					       cs->eb.destmsk))
+			xtables_error(PARAMETER_PROBLEM,
+				      "Problem with specified destination mac '%s'",
+				      args->dhostnetworkmask);
+		cs->eb.bitmask |= EBT_DESTMAC;
+	}
+
+	if ((cs->options & (OPT_LIST_X | OPT_LINENUMBERS)) ==
+			(OPT_LIST_X | OPT_LINENUMBERS))
+		xtables_error(PARAMETER_PROBLEM,
+			      "--Lx is not compatible with --Ln");
+
+	/* So, the extensions can work with the host endian.
+	 * The kernel does not have to do this of course */
+	cs->eb.ethproto = htons(cs->eb.ethproto);
+
+	for (match = cs->match_list; match; match = match->next) {
+		if (match->ismatch)
+			continue;
+
+		xtables_option_tfcall(match->u.watcher);
+	}
+}
+
 struct nft_family_ops nft_family_ops_bridge = {
 	.add			= nft_bridge_add,
 	.is_same		= nft_bridge_is_same,
 	.print_payload		= NULL,
 	.rule_parse		= &nft_ruleparse_ops_bridge,
+	.cmd_parse		= {
+		.proto_parse	= nft_bridge_proto_parse,
+		.post_parse	= nft_bridge_post_parse,
+		.option_name	= nft_bridge_option_name,
+		.option_invert	= nft_bridge_option_invert,
+		.command_default = ebt_command_default,
+		.print_help	= nft_bridge_print_help,
+	},
 	.print_table_header	= nft_bridge_print_table_header,
 	.print_header		= nft_bridge_print_header,
 	.print_rule		= nft_bridge_print_rule,
 	.save_rule		= nft_bridge_save_rule,
 	.save_chain		= nft_bridge_save_chain,
-	.rule_to_cs		= nft_rule_to_ebtables_command_state,
+	.rule_to_cs		= nft_rule_to_iptables_command_state,
+	.init_cs		= nft_bridge_init_cs,
 	.clear_cs		= ebt_cs_clean,
 	.xlate			= nft_bridge_xlate,
 };
diff --git a/iptables/nft-bridge.h b/iptables/nft-bridge.h
index eb1b3928..54b473eb 100644
--- a/iptables/nft-bridge.h
+++ b/iptables/nft-bridge.h
@@ -8,13 +8,6 @@
 #include <net/ethernet.h>
 #include <libiptc/libxtc.h>
 
-/* We use replace->flags, so we can't use the following values:
- * 0x01 == OPT_COMMAND, 0x02 == OPT_TABLE, 0x100 == OPT_ZERO */
-#define LIST_N	  0x04
-#define LIST_C	  0x08
-#define LIST_X	  0x10
-#define LIST_MAC2 0x20
-
 extern unsigned char eb_mac_type_unicast[ETH_ALEN];
 extern unsigned char eb_msk_type_unicast[ETH_ALEN];
 extern unsigned char eb_mac_type_multicast[ETH_ALEN];
@@ -115,12 +108,12 @@ static inline const char *ebt_target_name(unsigned int verdict)
 })								\
 
 void ebt_cs_clean(struct iptables_command_state *cs);
-void ebt_load_match_extensions(void);
-void ebt_add_match(struct xtables_match *m,
-			  struct iptables_command_state *cs);
-void ebt_add_watcher(struct xtables_target *watcher,
-                     struct iptables_command_state *cs);
-int ebt_command_default(struct iptables_command_state *cs);
+struct xtables_match *ebt_add_match(struct xtables_match *m,
+				    struct iptables_command_state *cs);
+struct xtables_target *ebt_add_watcher(struct xtables_target *watcher,
+				       struct iptables_command_state *cs);
+int ebt_command_default(struct iptables_command_state *cs,
+			struct xtables_globals *unused, bool ebt_invert);
 
 struct nft_among_pair {
 	struct ether_addr ether;
@@ -178,4 +171,7 @@ nft_among_insert_pair(struct nft_among_pair *pairs,
 	(*pcount)++;
 }
 
+/* from xtables-eb.c */
+void nft_bridge_print_help(struct iptables_command_state *cs);
+
 #endif
diff --git a/iptables/nft-cache.c b/iptables/nft-cache.c
index 91d29670..da2d4d7f 100644
--- a/iptables/nft-cache.c
+++ b/iptables/nft-cache.c
@@ -244,10 +244,10 @@ nft_cache_add_base_chain(struct nft_handle *h, const struct builtin_table *t,
 }
 
 int nft_cache_add_chain(struct nft_handle *h, const struct builtin_table *t,
-			struct nftnl_chain *c)
+			struct nftnl_chain *c, bool fake)
 {
 	const char *cname = nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);
-	struct nft_chain *nc = nft_chain_alloc(c);
+	struct nft_chain *nc = nft_chain_alloc(c, fake);
 	int ret;
 
 	if (nftnl_chain_is_set(c, NFTNL_CHAIN_HOOKNUM)) {
@@ -349,7 +349,7 @@ static int nftnl_chain_list_cb(const struct nlmsghdr *nlh, void *data)
 		goto out;
 	}
 
-	nft_cache_add_chain(h, t, c);
+	nft_cache_add_chain(h, t, c, false);
 	return MNL_CB_OK;
 out:
 	nftnl_chain_free(c);
diff --git a/iptables/nft-cache.h b/iptables/nft-cache.h
index 29ec6b5c..e9f5755c 100644
--- a/iptables/nft-cache.h
+++ b/iptables/nft-cache.h
@@ -17,7 +17,7 @@ int flush_rule_cache(struct nft_handle *h, const char *table,
 		     struct nft_chain *c);
 void nft_cache_build(struct nft_handle *h);
 int nft_cache_add_chain(struct nft_handle *h, const struct builtin_table *t,
-			struct nftnl_chain *c);
+			struct nftnl_chain *c, bool fake);
 int nft_cache_sort_chains(struct nft_handle *h, const char *table);
 
 struct nft_chain *
diff --git a/iptables/nft-chain.c b/iptables/nft-chain.c
index e954170f..c24e6c9b 100644
--- a/iptables/nft-chain.c
+++ b/iptables/nft-chain.c
@@ -12,12 +12,13 @@
 
 #include "nft-chain.h"
 
-struct nft_chain *nft_chain_alloc(struct nftnl_chain *nftnl)
+struct nft_chain *nft_chain_alloc(struct nftnl_chain *nftnl, bool fake)
 {
 	struct nft_chain *c = xtables_malloc(sizeof(*c));
 
 	INIT_LIST_HEAD(&c->head);
 	c->nftnl = nftnl;
+	c->fake = fake;
 
 	return c;
 }
diff --git a/iptables/nft-chain.h b/iptables/nft-chain.h
index 9adf1738..166504c0 100644
--- a/iptables/nft-chain.h
+++ b/iptables/nft-chain.h
@@ -11,6 +11,7 @@ struct nft_chain {
 	struct hlist_node	hnode;
 	struct nft_chain	**base_slot;
 	struct nftnl_chain	*nftnl;
+	bool			fake;
 };
 
 #define CHAIN_NAME_HSIZE	512
@@ -20,7 +21,7 @@ struct nft_chain_list {
 	struct hlist_head	names[CHAIN_NAME_HSIZE];
 };
 
-struct nft_chain *nft_chain_alloc(struct nftnl_chain *nftnl);
+struct nft_chain *nft_chain_alloc(struct nftnl_chain *nftnl, bool fake);
 void nft_chain_free(struct nft_chain *c);
 
 struct nft_chain_list *nft_chain_list_alloc(void);
diff --git a/iptables/nft-cmd.c b/iptables/nft-cmd.c
index 8a824586..58d5aa11 100644
--- a/iptables/nft-cmd.c
+++ b/iptables/nft-cmd.c
@@ -28,6 +28,7 @@ struct nft_cmd *nft_cmd_new(struct nft_handle *h, int command,
 	struct nft_cmd *cmd;
 
 	cmd = xtables_calloc(1, sizeof(struct nft_cmd));
+	INIT_LIST_HEAD(&cmd->head);
 	cmd->error.lineno = h->error.lineno;
 	cmd->command = command;
 	cmd->table = xtables_strdup(table);
@@ -65,6 +66,7 @@ void nft_cmd_free(struct nft_cmd *cmd)
 	switch (cmd->command) {
 	case NFT_COMPAT_RULE_CHECK:
 	case NFT_COMPAT_RULE_DELETE:
+	case NFT_COMPAT_RULE_CHANGE_COUNTERS:
 		if (cmd->obj.rule)
 			nftnl_rule_free(cmd->obj.rule);
 		break;
@@ -400,3 +402,23 @@ int ebt_cmd_user_chain_policy(struct nft_handle *h, const char *table,
 
 	return 1;
 }
+
+int nft_cmd_rule_change_counters(struct nft_handle *h,
+				 const char *chain, const char *table,
+				 struct iptables_command_state *cs,
+				 int rule_nr, uint8_t counter_op, bool verbose)
+{
+	struct nft_cmd *cmd;
+
+	cmd = nft_cmd_new(h, NFT_COMPAT_RULE_CHANGE_COUNTERS, table, chain,
+			  rule_nr == -1 ? cs : NULL, rule_nr, verbose);
+	if (!cmd)
+		return 0;
+
+	cmd->counter_op = counter_op;
+	cmd->counters = cs->counters;
+
+	nft_cache_level_set(h, NFT_CL_RULES, cmd);
+
+	return 1;
+}
diff --git a/iptables/nft-cmd.h b/iptables/nft-cmd.h
index ae5908d8..00ecc802 100644
--- a/iptables/nft-cmd.h
+++ b/iptables/nft-cmd.h
@@ -22,6 +22,7 @@ struct nft_cmd {
 	} obj;
 	const char			*policy;
 	struct xt_counters		counters;
+	uint8_t				counter_op;
 	const char			*rename;
 	int				counters_save;
 	struct {
@@ -77,6 +78,10 @@ int nft_cmd_rule_list_save(struct nft_handle *h, const char *chain,
 			   const char *table, int rulenum, int counters);
 int ebt_cmd_user_chain_policy(struct nft_handle *h, const char *table,
 			      const char *chain, const char *policy);
+int nft_cmd_rule_change_counters(struct nft_handle *h,
+				 const char *chain, const char *table,
+				 struct iptables_command_state *cs,
+				 int rule_nr, uint8_t counter_op, bool verbose);
 void nft_cmd_table_new(struct nft_handle *h, const char *table);
 
 #endif /* _NFT_CMD_H_ */
diff --git a/iptables/nft-ipv4.c b/iptables/nft-ipv4.c
index 75912847..0c8bd291 100644
--- a/iptables/nft-ipv4.c
+++ b/iptables/nft-ipv4.c
@@ -113,9 +113,7 @@ static bool nft_ipv4_is_same(const struct iptables_command_state *a,
 	}
 
 	return is_same_interfaces(a->fw.ip.iniface, a->fw.ip.outiface,
-				  a->fw.ip.iniface_mask, a->fw.ip.outiface_mask,
-				  b->fw.ip.iniface, b->fw.ip.outiface,
-				  b->fw.ip.iniface_mask, b->fw.ip.outiface_mask);
+				  b->fw.ip.iniface, b->fw.ip.outiface);
 }
 
 static void nft_ipv4_set_goto_flag(struct iptables_command_state *cs)
@@ -161,8 +159,7 @@ static void nft_ipv4_save_rule(const struct iptables_command_state *cs,
 	save_ipv4_addr('d', &cs->fw.ip.dst, &cs->fw.ip.dmsk,
 		       cs->fw.ip.invflags & IPT_INV_DSTIP);
 
-	save_rule_details(cs->fw.ip.iniface, cs->fw.ip.iniface_mask,
-			  cs->fw.ip.outiface, cs->fw.ip.outiface_mask,
+	save_rule_details(cs->fw.ip.iniface, cs->fw.ip.outiface,
 			  cs->fw.ip.proto, cs->fw.ip.flags & IPT_F_FRAG,
 			  cs->fw.ip.invflags);
 
@@ -201,6 +198,7 @@ static void xlate_ipv4_addr(const char *selector, const struct in_addr *addr,
 static int nft_ipv4_xlate(const struct iptables_command_state *cs,
 			  struct xt_xlate *xl)
 {
+	uint16_t proto = cs->fw.ip.proto;
 	const char *comment;
 	int ret;
 
@@ -214,22 +212,16 @@ static int nft_ipv4_xlate(const struct iptables_command_state *cs,
 			   cs->fw.ip.invflags & IPT_INV_FRAG? "" : "!= ", 0);
 	}
 
-	if (cs->fw.ip.proto != 0) {
-		const struct protoent *pent =
-			getprotobynumber(cs->fw.ip.proto);
-		char protonum[sizeof("65535")];
-		const char *name = protonum;
-
-		snprintf(protonum, sizeof(protonum), "%u",
-			 cs->fw.ip.proto);
-
-		if (!pent || !xlate_find_match(cs, pent->p_name)) {
-			if (pent)
-				name = pent->p_name;
-			xt_xlate_add(xl, "ip protocol %s%s ",
-				   cs->fw.ip.invflags & IPT_INV_PROTO ?
-					"!= " : "", name);
-		}
+	if (proto != 0 && !xlate_find_protomatch(cs, proto)) {
+		const char *pname = proto_to_name(proto, 0);
+
+		xt_xlate_add(xl, "ip protocol");
+		if (cs->fw.ip.invflags & IPT_INV_PROTO)
+			xt_xlate_add(xl, " !=");
+		if (pname)
+			xt_xlate_add(xl, "%s", pname);
+		else
+			xt_xlate_add(xl, "%hu", proto);
 	}
 
 	xlate_ipv4_addr("ip saddr", &cs->fw.ip.src, &cs->fw.ip.smsk,
@@ -353,6 +345,10 @@ struct nft_family_ops nft_family_ops_ipv4 = {
 	.cmd_parse		= {
 		.proto_parse	= ipv4_proto_parse,
 		.post_parse	= ipv4_post_parse,
+		.option_name	= ip46t_option_name,
+		.option_invert	= ip46t_option_invert,
+		.command_default = command_default,
+		.print_help	= xtables_printhelp,
 	},
 	.rule_to_cs		= nft_rule_to_iptables_command_state,
 	.clear_cs		= xtables_clear_iptables_command_state,
diff --git a/iptables/nft-ipv6.c b/iptables/nft-ipv6.c
index 5aef365b..4dbb2af2 100644
--- a/iptables/nft-ipv6.c
+++ b/iptables/nft-ipv6.c
@@ -99,11 +99,7 @@ static bool nft_ipv6_is_same(const struct iptables_command_state *a,
 	}
 
 	return is_same_interfaces(a->fw6.ipv6.iniface, a->fw6.ipv6.outiface,
-				  a->fw6.ipv6.iniface_mask,
-				  a->fw6.ipv6.outiface_mask,
-				  b->fw6.ipv6.iniface, b->fw6.ipv6.outiface,
-				  b->fw6.ipv6.iniface_mask,
-				  b->fw6.ipv6.outiface_mask);
+				  b->fw6.ipv6.iniface, b->fw6.ipv6.outiface);
 }
 
 static void nft_ipv6_set_goto_flag(struct iptables_command_state *cs)
@@ -147,8 +143,7 @@ static void nft_ipv6_save_rule(const struct iptables_command_state *cs,
 	save_ipv6_addr('d', &cs->fw6.ipv6.dst, &cs->fw6.ipv6.dmsk,
 		       cs->fw6.ipv6.invflags & IP6T_INV_DSTIP);
 
-	save_rule_details(cs->fw6.ipv6.iniface, cs->fw6.ipv6.iniface_mask,
-			  cs->fw6.ipv6.outiface, cs->fw6.ipv6.outiface_mask,
+	save_rule_details(cs->fw6.ipv6.iniface, cs->fw6.ipv6.outiface,
 			  cs->fw6.ipv6.proto, 0, cs->fw6.ipv6.invflags);
 
 	save_matches_and_target(cs, cs->fw6.ipv6.flags & IP6T_F_GOTO,
@@ -185,6 +180,7 @@ static void xlate_ipv6_addr(const char *selector, const struct in6_addr *addr,
 static int nft_ipv6_xlate(const struct iptables_command_state *cs,
 			  struct xt_xlate *xl)
 {
+	uint16_t proto = cs->fw6.ipv6.proto;
 	const char *comment;
 	int ret;
 
@@ -193,23 +189,16 @@ static int nft_ipv6_xlate(const struct iptables_command_state *cs,
 	xlate_ifname(xl, "oifname", cs->fw6.ipv6.outiface,
 		     cs->fw6.ipv6.invflags & IP6T_INV_VIA_OUT);
 
-	if (cs->fw6.ipv6.proto != 0) {
-		const struct protoent *pent =
-			getprotobynumber(cs->fw6.ipv6.proto);
-		char protonum[sizeof("65535")];
-		const char *name = protonum;
-
-		snprintf(protonum, sizeof(protonum), "%u",
-			 cs->fw6.ipv6.proto);
-
-		if (!pent || !xlate_find_match(cs, pent->p_name)) {
-			if (pent)
-				name = pent->p_name;
-			xt_xlate_add(xl, "meta l4proto %s%s ",
-				   cs->fw6.ipv6.invflags & IP6T_INV_PROTO ?
-					"!= " : "", name);
-		}
+	if (proto != 0 && !xlate_find_protomatch(cs, proto)) {
+		const char *pname = proto_to_name(proto, 0);
 
+		xt_xlate_add(xl, "meta l4proto");
+		if (cs->fw6.ipv6.invflags & IP6T_INV_PROTO)
+			xt_xlate_add(xl, " !=");
+		if (pname)
+			xt_xlate_add(xl, "%s", pname);
+		else
+			xt_xlate_add(xl, "%hu", proto);
 	}
 
 	xlate_ipv6_addr("ip6 saddr", &cs->fw6.ipv6.src, &cs->fw6.ipv6.smsk,
@@ -344,6 +333,10 @@ struct nft_family_ops nft_family_ops_ipv6 = {
 	.cmd_parse		= {
 		.proto_parse	= ipv6_proto_parse,
 		.post_parse	= ipv6_post_parse,
+		.option_name	= ip46t_option_name,
+		.option_invert	= ip46t_option_invert,
+		.command_default = command_default,
+		.print_help	= xtables_printhelp,
 	},
 	.rule_to_cs		= nft_rule_to_iptables_command_state,
 	.clear_cs		= xtables_clear_iptables_command_state,
diff --git a/iptables/nft-ruleparse-arp.c b/iptables/nft-ruleparse-arp.c
index d80ca922..b0671cb0 100644
--- a/iptables/nft-ruleparse-arp.c
+++ b/iptables/nft-ruleparse-arp.c
@@ -34,9 +34,8 @@ static void nft_arp_parse_meta(struct nft_xt_ctx *ctx,
 	struct arpt_entry *fw = &cs->arp;
 	uint8_t flags = 0;
 
-	if (parse_meta(ctx, e, reg->meta_dreg.key, fw->arp.iniface, fw->arp.iniface_mask,
-		   fw->arp.outiface, fw->arp.outiface_mask,
-		   &flags) == 0) {
+	if (parse_meta(ctx, e, reg->meta_dreg.key, fw->arp.iniface,
+		       fw->arp.outiface, &flags) == 0) {
 		fw->arp.invflags |= flags;
 		return;
 	}
@@ -90,6 +89,8 @@ static void nft_arp_parse_payload(struct nft_xt_ctx *ctx,
 		fw->arp.arhrd_mask = 0xffff;
 		if (inv)
 			fw->arp.invflags |= IPT_INV_ARPHRD;
+		if (reg->bitwise.set)
+			fw->arp.arhrd_mask = reg->bitwise.mask[0];
 		break;
 	case offsetof(struct arphdr, ar_pro):
 		get_cmp_data(e, &ar_pro, sizeof(ar_pro), &inv);
@@ -97,6 +98,8 @@ static void nft_arp_parse_payload(struct nft_xt_ctx *ctx,
 		fw->arp.arpro_mask = 0xffff;
 		if (inv)
 			fw->arp.invflags |= IPT_INV_PROTO;
+		if (reg->bitwise.set)
+			fw->arp.arpro_mask = reg->bitwise.mask[0];
 		break;
 	case offsetof(struct arphdr, ar_op):
 		get_cmp_data(e, &ar_op, sizeof(ar_op), &inv);
@@ -104,6 +107,8 @@ static void nft_arp_parse_payload(struct nft_xt_ctx *ctx,
 		fw->arp.arpop_mask = 0xffff;
 		if (inv)
 			fw->arp.invflags |= IPT_INV_ARPOP;
+		if (reg->bitwise.set)
+			fw->arp.arpop_mask = reg->bitwise.mask[0];
 		break;
 	case offsetof(struct arphdr, ar_hln):
 		get_cmp_data(e, &ar_hln, sizeof(ar_hln), &inv);
@@ -111,6 +116,8 @@ static void nft_arp_parse_payload(struct nft_xt_ctx *ctx,
 		fw->arp.arhln_mask = 0xff;
 		if (inv)
 			fw->arp.invflags |= IPT_INV_ARPHLN;
+		if (reg->bitwise.set)
+			fw->arp.arhln_mask = reg->bitwise.mask[0];
 		break;
 	case offsetof(struct arphdr, ar_pln):
 		get_cmp_data(e, &ar_pln, sizeof(ar_pln), &inv);
diff --git a/iptables/nft-ruleparse-bridge.c b/iptables/nft-ruleparse-bridge.c
index c6cc9af5..aee08b13 100644
--- a/iptables/nft-ruleparse-bridge.c
+++ b/iptables/nft-ruleparse-bridge.c
@@ -43,7 +43,8 @@ static void nft_bridge_parse_meta(struct nft_xt_ctx *ctx,
 		return;
 	}
 
-	if (parse_meta(ctx, e, reg->meta_dreg.key, iifname, NULL, oifname, NULL, &invflags) < 0) {
+	if (parse_meta(ctx, e, reg->meta_dreg.key,
+		       iifname, oifname, &invflags) < 0) {
 		ctx->errmsg = "unknown meta key";
 		return;
 	}
diff --git a/iptables/nft-ruleparse-ipv4.c b/iptables/nft-ruleparse-ipv4.c
index 491cbf42..fe65b33c 100644
--- a/iptables/nft-ruleparse-ipv4.c
+++ b/iptables/nft-ruleparse-ipv4.c
@@ -41,9 +41,8 @@ static void nft_ipv4_parse_meta(struct nft_xt_ctx *ctx,
 		break;
 	}
 
-	if (parse_meta(ctx, e, reg->meta_dreg.key, cs->fw.ip.iniface, cs->fw.ip.iniface_mask,
-		   cs->fw.ip.outiface, cs->fw.ip.outiface_mask,
-		   &cs->fw.ip.invflags) == 0)
+	if (parse_meta(ctx, e, reg->meta_dreg.key, cs->fw.ip.iniface,
+		       cs->fw.ip.outiface, &cs->fw.ip.invflags) == 0)
 		return;
 
 	ctx->errmsg = "unknown ipv4 meta key";
diff --git a/iptables/nft-ruleparse-ipv6.c b/iptables/nft-ruleparse-ipv6.c
index 7581b863..29b08580 100644
--- a/iptables/nft-ruleparse-ipv6.c
+++ b/iptables/nft-ruleparse-ipv6.c
@@ -42,8 +42,7 @@ static void nft_ipv6_parse_meta(struct nft_xt_ctx *ctx,
 	}
 
 	if (parse_meta(ctx, e, reg->meta_dreg.key, cs->fw6.ipv6.iniface,
-		   cs->fw6.ipv6.iniface_mask, cs->fw6.ipv6.outiface,
-		   cs->fw6.ipv6.outiface_mask, &cs->fw6.ipv6.invflags) == 0)
+		       cs->fw6.ipv6.outiface, &cs->fw6.ipv6.invflags) == 0)
 		return;
 
 	ctx->errmsg = "unknown ipv6 meta key";
diff --git a/iptables/nft-ruleparse.c b/iptables/nft-ruleparse.c
index c8322f93..1ee7a94d 100644
--- a/iptables/nft-ruleparse.c
+++ b/iptables/nft-ruleparse.c
@@ -94,7 +94,7 @@ __nft_create_target(struct nft_xt_ctx *ctx, const char *name, size_t tgsize)
 	if (!target)
 		return NULL;
 
-	size = XT_ALIGN(sizeof(*target->t)) + tgsize ?: target->size;
+	size = XT_ALIGN(sizeof(*target->t)) + (tgsize ?: target->size);
 
 	target->t = xtables_calloc(1, size);
 	target->t->u.target_size = size;
@@ -891,7 +891,6 @@ bool nft_rule_to_iptables_command_state(struct nft_handle *h,
 					const struct nftnl_rule *r,
 					struct iptables_command_state *cs)
 {
-	struct nftnl_expr_iter *iter;
 	struct nftnl_expr *expr;
 	struct nft_xt_ctx ctx = {
 		.cs = cs,
@@ -900,12 +899,11 @@ bool nft_rule_to_iptables_command_state(struct nft_handle *h,
 	};
 	bool ret = true;
 
-	iter = nftnl_expr_iter_create(r);
-	if (iter == NULL)
+	ctx.iter = nftnl_expr_iter_create(r);
+	if (ctx.iter == NULL)
 		return false;
 
-	ctx.iter = iter;
-	expr = nftnl_expr_iter_next(iter);
+	expr = nftnl_expr_iter_next(ctx.iter);
 	while (expr != NULL) {
 		const char *name =
 			nftnl_expr_get_str(expr, NFTNL_EXPR_NAME);
@@ -941,10 +939,10 @@ bool nft_rule_to_iptables_command_state(struct nft_handle *h,
 			ret = false;
 		}
 
-		expr = nftnl_expr_iter_next(iter);
+		expr = nftnl_expr_iter_next(ctx.iter);
 	}
 
-	nftnl_expr_iter_destroy(iter);
+	nftnl_expr_iter_destroy(ctx.iter);
 
 	if (nftnl_rule_is_set(r, NFTNL_RULE_USERDATA)) {
 		const void *data;
@@ -983,18 +981,14 @@ bool nft_rule_to_iptables_command_state(struct nft_handle *h,
 	return ret;
 }
 
-static void parse_ifname(const char *name, unsigned int len,
-			 char *dst, unsigned char *mask)
+static void parse_ifname(const char *name, unsigned int len, char *dst)
 {
 	if (len == 0)
 		return;
 
 	memcpy(dst, name, len);
-	if (name[len - 1] == '\0') {
-		if (mask)
-			memset(mask, 0xff, strlen(name) + 1);
+	if (name[len - 1] == '\0')
 		return;
-	}
 
 	if (len >= IFNAMSIZ)
 		return;
@@ -1004,12 +998,9 @@ static void parse_ifname(const char *name, unsigned int len,
 	if (len >= IFNAMSIZ)
 		return;
 	dst[len++] = 0;
-	if (mask)
-		memset(mask, 0xff, len - 2);
 }
 
-static void parse_invalid_iface(char *iface, unsigned char *mask,
-				uint8_t *invflags, uint8_t invbit)
+static void parse_invalid_iface(char *iface, uint8_t *invflags, uint8_t invbit)
 {
 	if (*invflags & invbit || strcmp(iface, "INVAL/D"))
 		return;
@@ -1018,9 +1009,6 @@ static void parse_invalid_iface(char *iface, unsigned char *mask,
 	*invflags |= invbit;
 	iface[0] = '+';
 	iface[1] = '\0';
-	mask[0] = 0xff;
-	mask[1] = 0xff;
-	memset(mask + 2, 0, IFNAMSIZ - 2);
 }
 
 static uint32_t get_meta_mask(struct nft_xt_ctx *ctx, enum nft_registers sreg)
@@ -1071,8 +1059,7 @@ static int parse_meta_pkttype(struct nft_xt_ctx *ctx, struct nftnl_expr *e)
 }
 
 int parse_meta(struct nft_xt_ctx *ctx, struct nftnl_expr *e, uint8_t key,
-	       char *iniface, unsigned char *iniface_mask,
-	       char *outiface, unsigned char *outiface_mask, uint8_t *invflags)
+	       char *iniface, char *outiface, uint8_t *invflags)
 {
 	uint32_t value;
 	const void *ifname;
@@ -1085,8 +1072,6 @@ int parse_meta(struct nft_xt_ctx *ctx, struct nftnl_expr *e, uint8_t key,
 			*invflags |= IPT_INV_VIA_IN;
 
 		if_indextoname(value, iniface);
-
-		memset(iniface_mask, 0xff, strlen(iniface)+1);
 		break;
 	case NFT_META_OIF:
 		value = nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_DATA);
@@ -1094,8 +1079,6 @@ int parse_meta(struct nft_xt_ctx *ctx, struct nftnl_expr *e, uint8_t key,
 			*invflags |= IPT_INV_VIA_OUT;
 
 		if_indextoname(value, outiface);
-
-		memset(outiface_mask, 0xff, strlen(outiface)+1);
 		break;
 	case NFT_META_BRI_IIFNAME:
 	case NFT_META_IIFNAME:
@@ -1103,9 +1086,8 @@ int parse_meta(struct nft_xt_ctx *ctx, struct nftnl_expr *e, uint8_t key,
 		if (nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_OP) == NFT_CMP_NEQ)
 			*invflags |= IPT_INV_VIA_IN;
 
-		parse_ifname(ifname, len, iniface, iniface_mask);
-		parse_invalid_iface(iniface, iniface_mask,
-				    invflags, IPT_INV_VIA_IN);
+		parse_ifname(ifname, len, iniface);
+		parse_invalid_iface(iniface, invflags, IPT_INV_VIA_IN);
 		break;
 	case NFT_META_BRI_OIFNAME:
 	case NFT_META_OIFNAME:
@@ -1113,9 +1095,8 @@ int parse_meta(struct nft_xt_ctx *ctx, struct nftnl_expr *e, uint8_t key,
 		if (nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_OP) == NFT_CMP_NEQ)
 			*invflags |= IPT_INV_VIA_OUT;
 
-		parse_ifname(ifname, len, outiface, outiface_mask);
-		parse_invalid_iface(outiface, outiface_mask,
-				    invflags, IPT_INV_VIA_OUT);
+		parse_ifname(ifname, len, outiface);
+		parse_invalid_iface(outiface, invflags, IPT_INV_VIA_OUT);
 		break;
 	case NFT_META_MARK:
 		parse_meta_mark(ctx, e);
diff --git a/iptables/nft-ruleparse.h b/iptables/nft-ruleparse.h
index 25ce05d2..62c9160d 100644
--- a/iptables/nft-ruleparse.h
+++ b/iptables/nft-ruleparse.h
@@ -128,8 +128,7 @@ bool nft_rule_to_iptables_command_state(struct nft_handle *h,
 #define max(x, y) ((x) > (y) ? (x) : (y))
 
 int parse_meta(struct nft_xt_ctx *ctx, struct nftnl_expr *e, uint8_t key,
-	       char *iniface, unsigned char *iniface_mask, char *outiface,
-	       unsigned char *outiface_mask, uint8_t *invflags);
+	       char *iniface, char *outiface, uint8_t *invflags);
 
 int nft_parse_hl(struct nft_xt_ctx *ctx, struct nftnl_expr *e,
 		 struct iptables_command_state *cs);
diff --git a/iptables/nft-shared.c b/iptables/nft-shared.c
index 6775578b..2c29e68f 100644
--- a/iptables/nft-shared.c
+++ b/iptables/nft-shared.c
@@ -220,36 +220,16 @@ void add_l4proto(struct nft_handle *h, struct nftnl_rule *r,
 }
 
 bool is_same_interfaces(const char *a_iniface, const char *a_outiface,
-			unsigned const char *a_iniface_mask,
-			unsigned const char *a_outiface_mask,
-			const char *b_iniface, const char *b_outiface,
-			unsigned const char *b_iniface_mask,
-			unsigned const char *b_outiface_mask)
+			const char *b_iniface, const char *b_outiface)
 {
-	int i;
-
-	for (i = 0; i < IFNAMSIZ; i++) {
-		if (a_iniface_mask[i] != b_iniface_mask[i]) {
-			DEBUGP("different iniface mask %x, %x (%d)\n",
-			a_iniface_mask[i] & 0xff, b_iniface_mask[i] & 0xff, i);
-			return false;
-		}
-		if ((a_iniface[i] & a_iniface_mask[i])
-		    != (b_iniface[i] & b_iniface_mask[i])) {
-			DEBUGP("different iniface\n");
-			return false;
-		}
-		if (a_outiface_mask[i] != b_outiface_mask[i]) {
-			DEBUGP("different outiface mask\n");
-			return false;
-		}
-		if ((a_outiface[i] & a_outiface_mask[i])
-		    != (b_outiface[i] & b_outiface_mask[i])) {
-			DEBUGP("different outiface\n");
-			return false;
-		}
+	if (strncmp(a_iniface, b_iniface, IFNAMSIZ)) {
+		DEBUGP("different iniface\n");
+		return false;
+	}
+	if (strncmp(a_outiface, b_outiface, IFNAMSIZ)) {
+		DEBUGP("different outiface\n");
+		return false;
 	}
-
 	return true;
 }
 
diff --git a/iptables/nft-shared.h b/iptables/nft-shared.h
index 51d1e460..b57aee1f 100644
--- a/iptables/nft-shared.h
+++ b/iptables/nft-shared.h
@@ -105,11 +105,7 @@ void add_l4proto(struct nft_handle *h, struct nftnl_rule *r, uint8_t proto, uint
 void add_compat(struct nftnl_rule *r, uint32_t proto, bool inv);
 
 bool is_same_interfaces(const char *a_iniface, const char *a_outiface,
-			unsigned const char *a_iniface_mask,
-			unsigned const char *a_outiface_mask,
-			const char *b_iniface, const char *b_outiface,
-			unsigned const char *b_iniface_mask,
-			unsigned const char *b_outiface_mask);
+			const char *b_iniface, const char *b_outiface);
 
 void __get_cmp_data(struct nftnl_expr *e, void *data, size_t dlen, uint8_t *op);
 void get_cmp_data(struct nftnl_expr *e, void *data, size_t dlen, bool *inv);
diff --git a/iptables/nft.c b/iptables/nft.c
index 97fd4f49..21a7e211 100644
--- a/iptables/nft.c
+++ b/iptables/nft.c
@@ -337,6 +337,7 @@ static int mnl_append_error(const struct nft_handle *h,
 	case NFT_COMPAT_RULE_REPLACE:
 	case NFT_COMPAT_RULE_DELETE:
 	case NFT_COMPAT_RULE_FLUSH:
+	case NFT_COMPAT_RULE_CHANGE_COUNTERS:
 		snprintf(tcr, sizeof(tcr), "rule in chain %s",
 			 nftnl_rule_get_str(o->rule, NFTNL_RULE_CHAIN));
 #if 0
@@ -720,7 +721,7 @@ static void nft_chain_builtin_add(struct nft_handle *h,
 
 	if (!fake)
 		batch_chain_add(h, NFT_COMPAT_CHAIN_ADD, c);
-	nft_cache_add_chain(h, table, c);
+	nft_cache_add_chain(h, table, c, fake);
 }
 
 /* find if built-in table already exists */
@@ -764,14 +765,19 @@ nft_chain_builtin_find(const struct builtin_table *t, const char *chain)
 static void nft_chain_builtin_init(struct nft_handle *h,
 				   const struct builtin_table *table)
 {
+	struct nft_chain *c;
 	int i;
 
 	/* Initialize built-in chains if they don't exist yet */
 	for (i=0; i < NF_INET_NUMHOOKS && table->chains[i].name != NULL; i++) {
-		if (nft_chain_find(h, table->name, table->chains[i].name))
-			continue;
-
-		nft_chain_builtin_add(h, table, &table->chains[i], false);
+		c = nft_chain_find(h, table->name, table->chains[i].name);
+		if (!c) {
+			nft_chain_builtin_add(h, table,
+					      &table->chains[i], false);
+		} else if (c->fake) {
+			batch_chain_add(h, NFT_COMPAT_CHAIN_ADD, c->nftnl);
+			c->fake = false;
+		}
 	}
 }
 
@@ -798,6 +804,7 @@ static int nft_xt_builtin_init(struct nft_handle *h, const char *table,
 {
 	const struct builtin_table *t;
 	const struct builtin_chain *c;
+	struct nft_chain *nc;
 
 	if (!h->cache_init)
 		return 0;
@@ -818,10 +825,13 @@ static int nft_xt_builtin_init(struct nft_handle *h, const char *table,
 	if (!c)
 		return -1;
 
-	if (h->cache->table[t->type].base_chains[c->hook])
-		return 0;
-
-	nft_chain_builtin_add(h, t, c, false);
+	nc = h->cache->table[t->type].base_chains[c->hook];
+	if (!nc) {
+		nft_chain_builtin_add(h, t, c, false);
+	} else if (nc->fake) {
+		batch_chain_add(h, NFT_COMPAT_CHAIN_ADD, nc->nftnl);
+		nc->fake = false;
+	}
 	return 0;
 }
 
@@ -1306,14 +1316,12 @@ static int add_nft_tcpudp(struct nft_handle *h,struct nftnl_rule *r,
 	uint8_t reg;
 	int ret;
 
-	if (src[0] && src[0] == src[1] &&
+	if (!invert_src &&
+	    src[0] && src[0] == src[1] &&
 	    dst[0] && dst[0] == dst[1] &&
 	    invert_src == invert_dst) {
 		uint32_t combined = dst[0] | (src[0] << 16);
 
-		if (invert_src)
-			op = NFT_CMP_NEQ;
-
 		expr = gen_payload(h, NFT_PAYLOAD_TRANSPORT_HEADER, 0, 4, &reg);
 		if (!expr)
 			return -ENOMEM;
@@ -1323,7 +1331,7 @@ static int add_nft_tcpudp(struct nft_handle *h,struct nftnl_rule *r,
 		return 0;
 	}
 
-	if (src[0] || src[1] < 0xffff) {
+	if (src[0] || src[1] < UINT16_MAX || invert_src) {
 		expr = gen_payload(h, NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, &reg);
 		if (!expr)
 			return -ENOMEM;
@@ -1334,7 +1342,7 @@ static int add_nft_tcpudp(struct nft_handle *h,struct nftnl_rule *r,
 			return ret;
 	}
 
-	if (dst[0] || dst[1] < 0xffff) {
+	if (dst[0] || dst[1] < UINT16_MAX || invert_dst) {
 		expr = gen_payload(h, NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, &reg);
 		if (!expr)
 			return -ENOMEM;
@@ -1789,6 +1797,8 @@ nft_rule_print_save(struct nft_handle *h, const struct nftnl_rule *r,
 	struct nft_family_ops *ops = h->ops;
 	bool ret;
 
+	if (ops->init_cs)
+		ops->init_cs(&cs);
 	ret = ops->rule_to_cs(h, r, &cs);
 
 	if (!(format & (FMT_NOCOUNTS | FMT_C_COUNTS)))
@@ -1814,7 +1824,7 @@ nft_rule_print_save(struct nft_handle *h, const struct nftnl_rule *r,
 	return ret;
 }
 
-static bool nft_rule_is_policy_rule(struct nftnl_rule *r)
+bool nft_rule_is_policy_rule(struct nftnl_rule *r)
 {
 	const struct nftnl_udata *tb[UDATA_TYPE_MAX + 1] = {};
 	const void *data;
@@ -2092,7 +2102,7 @@ int nft_chain_user_add(struct nft_handle *h, const char *chain, const char *tabl
 	if (!batch_chain_add(h, NFT_COMPAT_CHAIN_USER_ADD, c))
 		return 0;
 
-	nft_cache_add_chain(h, t, c);
+	nft_cache_add_chain(h, t, c, false);
 
 	/* the core expects 1 for success and 0 for error */
 	return 1;
@@ -2119,7 +2129,7 @@ int nft_chain_restore(struct nft_handle *h, const char *chain, const char *table
 		nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, chain);
 		created = true;
 
-		nft_cache_add_chain(h, t, c);
+		nft_cache_add_chain(h, t, c, false);
 	} else {
 		c = nc->nftnl;
 
@@ -2382,20 +2392,22 @@ static int __nft_rule_del(struct nft_handle *h, struct nftnl_rule *r)
 }
 
 static bool nft_rule_cmp(struct nft_handle *h, struct nftnl_rule *r,
-			 struct nftnl_rule *rule)
+			 struct iptables_command_state *cs)
 {
-	struct iptables_command_state _cs = {}, this = {}, *cs = &_cs;
-	bool ret = false, ret_this, ret_that;
+	struct iptables_command_state this = {};
+	bool ret = false, ret_this;
+
+	if (h->ops->init_cs)
+		h->ops->init_cs(&this);
 
 	ret_this = h->ops->rule_to_cs(h, r, &this);
-	ret_that = h->ops->rule_to_cs(h, rule, cs);
 
-	DEBUGP("comparing with... ");
+	DEBUGP("with ... ");
 #ifdef DEBUG_DEL
 	nft_rule_print_save(h, r, NFT_RULE_APPEND, 0);
 #endif
-	if (!ret_this || !ret_that)
-		DEBUGP("Cannot convert rules: %d %d\n", ret_this, ret_that);
+	if (!ret_this)
+		DEBUGP("Cannot convert rule: %d\n", ret_this);
 
 	if (!h->ops->is_same(cs, &this))
 		goto out;
@@ -2419,7 +2431,6 @@ static bool nft_rule_cmp(struct nft_handle *h, struct nftnl_rule *r,
 	ret = true;
 out:
 	h->ops->clear_cs(&this);
-	h->ops->clear_cs(cs);
 	return ret;
 }
 
@@ -2427,6 +2438,7 @@ static struct nftnl_rule *
 nft_rule_find(struct nft_handle *h, struct nft_chain *nc,
 	      struct nftnl_rule *rule, int rulenum)
 {
+	struct iptables_command_state cs = {};
 	struct nftnl_chain *c = nc->nftnl;
 	struct nftnl_rule *r;
 	struct nftnl_rule_iter *iter;
@@ -2440,9 +2452,20 @@ nft_rule_find(struct nft_handle *h, struct nft_chain *nc,
 	if (iter == NULL)
 		return 0;
 
+	if (h->ops->init_cs)
+		h->ops->init_cs(&cs);
+
+	if (!h->ops->rule_to_cs(h, rule, &cs))
+		return NULL;
+
+	DEBUGP("comparing ... ");
+#ifdef DEBUG_DEL
+	nft_rule_print_save(h, rule, NFT_RULE_APPEND, 0);
+#endif
+
 	r = nftnl_rule_iter_next(iter);
 	while (r != NULL) {
-		found = nft_rule_cmp(h, r, rule);
+		found = nft_rule_cmp(h, r, &cs);
 		if (found)
 			break;
 		r = nftnl_rule_iter_next(iter);
@@ -2450,6 +2473,8 @@ nft_rule_find(struct nft_handle *h, struct nft_chain *nc,
 
 	nftnl_rule_iter_destroy(iter);
 
+	h->ops->clear_cs(&cs);
+
 	return found ? r : NULL;
 }
 
@@ -2641,6 +2666,60 @@ int nft_rule_replace(struct nft_handle *h, const char *chain,
 	return ret;
 }
 
+static int nft_rule_change_counters(struct nft_handle *h, const char *table,
+				    const char *chain, struct nftnl_rule *rule,
+				    int rulenum, struct xt_counters *counters,
+				    uint8_t counter_op, bool verbose)
+{
+	struct iptables_command_state cs = {};
+	struct nftnl_rule *r, *new_rule;
+	struct nft_rule_ctx ctx = {
+		.command = NFT_COMPAT_RULE_APPEND,
+	};
+	struct nft_chain *c;
+
+	nft_fn = nft_rule_change_counters;
+
+	c = nft_chain_find(h, table, chain);
+	if (!c) {
+		errno = ENOENT;
+		return 0;
+	}
+
+	r = nft_rule_find(h, c, rule, rulenum);
+	if (!r) {
+		errno = E2BIG;
+		return 0;
+	}
+
+	DEBUGP("changing counters of rule with handle=%llu\n",
+		(unsigned long long)
+		nftnl_rule_get_u64(r, NFTNL_RULE_HANDLE));
+
+	if (h->ops->init_cs)
+		h->ops->init_cs(&cs);
+	h->ops->rule_to_cs(h, r, &cs);
+
+	if (counter_op & CTR_OP_INC_PKTS)
+		cs.counters.pcnt += counters->pcnt;
+	else if (counter_op & CTR_OP_DEC_PKTS)
+		cs.counters.pcnt -= counters->pcnt;
+	else
+		cs.counters.pcnt = counters->pcnt;
+
+	if (counter_op & CTR_OP_INC_BYTES)
+		cs.counters.bcnt += counters->bcnt;
+	else if (counter_op & CTR_OP_DEC_BYTES)
+		cs.counters.bcnt -= counters->bcnt;
+	else
+		cs.counters.bcnt = counters->bcnt;
+
+	new_rule = nft_rule_new(h, &ctx, chain, table, &cs);
+	h->ops->clear_cs(&cs);
+
+	return nft_rule_append(h, chain, table, new_rule, r, verbose);
+}
+
 static int
 __nft_rule_list(struct nft_handle *h, struct nftnl_chain *c,
 		int rulenum, unsigned int format,
@@ -2759,8 +2838,10 @@ int nft_rule_list(struct nft_handle *h, const char *chain, const char *table,
 
 	if (chain) {
 		c = nft_chain_find(h, table, chain);
-		if (!c)
+		if (!c) {
+			errno = ENOENT;
 			return 0;
+		}
 
 		if (rulenum)
 			d.save_fmt = true;	/* skip header printing */
@@ -2867,8 +2948,10 @@ int nft_rule_list_save(struct nft_handle *h, const char *chain,
 
 	if (chain) {
 		c = nft_chain_find(h, table, chain);
-		if (!c)
+		if (!c) {
+			errno = ENOENT;
 			return 0;
+		}
 
 		if (!rulenum)
 			nft_rule_list_chain_save(c, &counters);
@@ -2895,21 +2978,23 @@ int nft_rule_zero_counters(struct nft_handle *h, const char *chain,
 		.command = NFT_COMPAT_RULE_APPEND,
 	};
 	struct nft_chain *c;
-	int ret = 0;
 
 	nft_fn = nft_rule_delete;
 
 	c = nft_chain_find(h, table, chain);
-	if (!c)
+	if (!c) {
+		errno = ENOENT;
 		return 0;
+	}
 
 	r = nft_rule_find(h, c, NULL, rulenum);
 	if (r == NULL) {
 		errno = ENOENT;
-		ret = 1;
-		goto error;
+		return 0;
 	}
 
+	if (h->ops->init_cs)
+		h->ops->init_cs(&cs);
 	h->ops->rule_to_cs(h, r, &cs);
 	cs.counters.pcnt = cs.counters.bcnt = 0;
 	new_rule = nft_rule_new(h, &ctx, chain, table, &cs);
@@ -2918,10 +3003,7 @@ int nft_rule_zero_counters(struct nft_handle *h, const char *chain,
 	if (!new_rule)
 		return 1;
 
-	ret = nft_rule_append(h, chain, table, new_rule, r, false);
-
-error:
-	return ret;
+	return nft_rule_append(h, chain, table, new_rule, r, false);
 }
 
 static void nft_table_print_debug(struct nft_handle *h,
@@ -3031,6 +3113,7 @@ static void batch_obj_del(struct nft_handle *h, struct obj_update *o)
 	case NFT_COMPAT_RULE_APPEND:
 	case NFT_COMPAT_RULE_INSERT:
 	case NFT_COMPAT_RULE_REPLACE:
+	case NFT_COMPAT_RULE_CHANGE_COUNTERS:
 		break;
 	case NFT_COMPAT_RULE_DELETE:
 	case NFT_COMPAT_RULE_FLUSH:
@@ -3109,15 +3192,28 @@ static void nft_refresh_transaction(struct nft_handle *h)
 				break;
 			n->skip = !nft_may_delete_chain(n->chain);
 			break;
+		case NFT_COMPAT_CHAIN_ZERO:
+			tablename = nftnl_chain_get_str(n->chain, NFTNL_CHAIN_TABLE);
+			if (!tablename)
+				continue;
+
+			chainname = nftnl_chain_get_str(n->chain, NFTNL_CHAIN_NAME);
+			if (!chainname)
+				continue;
+
+			n->skip = nftnl_chain_is_set(n->chain,
+						     NFTNL_CHAIN_HOOKNUM) &&
+				  !nft_chain_find(h, tablename, chainname);
+			break;
 		case NFT_COMPAT_TABLE_ADD:
 		case NFT_COMPAT_CHAIN_ADD:
-		case NFT_COMPAT_CHAIN_ZERO:
 		case NFT_COMPAT_CHAIN_USER_FLUSH:
 		case NFT_COMPAT_CHAIN_UPDATE:
 		case NFT_COMPAT_CHAIN_RENAME:
 		case NFT_COMPAT_RULE_APPEND:
 		case NFT_COMPAT_RULE_INSERT:
 		case NFT_COMPAT_RULE_REPLACE:
+		case NFT_COMPAT_RULE_CHANGE_COUNTERS:
 		case NFT_COMPAT_RULE_DELETE:
 		case NFT_COMPAT_SET_ADD:
 		case NFT_COMPAT_RULE_LIST:
@@ -3208,6 +3304,7 @@ retry:
 						  n->rule);
 			break;
 		case NFT_COMPAT_RULE_REPLACE:
+		case NFT_COMPAT_RULE_CHANGE_COUNTERS:
 			nft_compat_rule_batch_add(h, NFT_MSG_NEWRULE,
 						  NLM_F_CREATE | NLM_F_REPLACE,
 						  n->seq, n->rule);
@@ -3510,6 +3607,15 @@ static int nft_prepare(struct nft_handle *h)
 		case NFT_COMPAT_CHAIN_ADD:
 			assert(0);
 			return 0;
+		case NFT_COMPAT_RULE_CHANGE_COUNTERS:
+			ret = nft_rule_change_counters(h, cmd->table,
+						       cmd->chain,
+						       cmd->obj.rule,
+						       cmd->rulenum,
+						       &cmd->counters,
+						       cmd->counter_op,
+						       cmd->verbose);
+			break;
 		}
 
 		nft_cmd_free(cmd);
@@ -3679,6 +3785,27 @@ const char *nft_strerror(int err)
 	return strerror(err);
 }
 
+static int l4proto_expr_get_dreg(struct nftnl_expr *e, uint32_t *dregp)
+{
+	const char *name = nftnl_expr_get_str(e, NFTNL_EXPR_NAME);
+	uint32_t poff = offsetof(struct iphdr, protocol);
+	uint32_t pbase = NFT_PAYLOAD_NETWORK_HEADER;
+
+	if (!strcmp(name, "payload") &&
+	    nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_BASE) == pbase &&
+	    nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET) == poff &&
+	    nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_LEN) == sizeof(uint8_t)) {
+		*dregp = nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_DREG);
+		return 0;
+	}
+	if (!strcmp(name, "meta") &&
+	    nftnl_expr_get_u32(e, NFTNL_EXPR_META_KEY) == NFT_META_L4PROTO) {
+		*dregp = nftnl_expr_get_u32(e, NFTNL_EXPR_META_DREG);
+		return 0;
+	}
+	return -1;
+}
+
 static int recover_rule_compat(struct nftnl_rule *r)
 {
 	struct nftnl_expr_iter *iter;
@@ -3695,12 +3822,10 @@ next_expr:
 	if (!e)
 		goto out;
 
-	if (strcmp("meta", nftnl_expr_get_str(e, NFTNL_EXPR_NAME)) ||
-	    nftnl_expr_get_u32(e, NFTNL_EXPR_META_KEY) != NFT_META_L4PROTO)
+	/* may be 'ip protocol' or 'meta l4proto' with identical RHS */
+	if (l4proto_expr_get_dreg(e, &reg) < 0)
 		goto next_expr;
 
-	reg = nftnl_expr_get_u32(e, NFTNL_EXPR_META_DREG);
-
 	e = nftnl_expr_iter_next(iter);
 	if (!e)
 		goto out;
@@ -3729,6 +3854,7 @@ static int __nft_chain_zero_counters(struct nft_chain *nc, void *data)
 	struct nft_handle *h = d->handle;
 	struct nftnl_rule_iter *iter;
 	struct nftnl_rule *r;
+	struct obj_update *o;
 
 	if (d->verbose)
 		fprintf(stdout, "Zeroing chain `%s'\n",
@@ -3739,8 +3865,11 @@ static int __nft_chain_zero_counters(struct nft_chain *nc, void *data)
 		nftnl_chain_set_u64(c, NFTNL_CHAIN_PACKETS, 0);
 		nftnl_chain_set_u64(c, NFTNL_CHAIN_BYTES, 0);
 		nftnl_chain_unset(c, NFTNL_CHAIN_HANDLE);
-		if (!batch_chain_add(h, NFT_COMPAT_CHAIN_ZERO, c))
+		o = batch_chain_add(h, NFT_COMPAT_CHAIN_ZERO, c);
+		if (!o)
 			return -1;
+		/* may skip if it is a fake entry */
+		o->skip = nc->fake;
 	}
 
 	iter = nftnl_rule_iter_create(c);
@@ -3804,6 +3933,8 @@ int nft_chain_zero_counters(struct nft_handle *h, const char *chain,
 	struct nft_chain *c;
 	int ret = 0;
 
+	nft_xt_fake_builtin_chains(h, table, chain);
+
 	if (chain) {
 		c = nft_chain_find(h, table, chain);
 		if (!c) {
diff --git a/iptables/nft.h b/iptables/nft.h
index 5acbbf82..8f17f310 100644
--- a/iptables/nft.h
+++ b/iptables/nft.h
@@ -72,6 +72,7 @@ enum obj_update_type {
 	NFT_COMPAT_RULE_SAVE,
 	NFT_COMPAT_RULE_ZERO,
 	NFT_COMPAT_BRIDGE_USER_CHAIN_UPDATE,
+	NFT_COMPAT_RULE_CHANGE_COUNTERS,
 };
 
 struct cache_chain {
@@ -184,6 +185,7 @@ int nft_rule_list_save(struct nft_handle *h, const char *chain, const char *tabl
 int nft_rule_save(struct nft_handle *h, const char *table, unsigned int format);
 int nft_rule_flush(struct nft_handle *h, const char *chain, const char *table, bool verbose);
 int nft_rule_zero_counters(struct nft_handle *h, const char *chain, const char *table, int rulenum);
+bool nft_rule_is_policy_rule(struct nftnl_rule *r);
 
 /*
  * Operations used in userspace tools
@@ -233,7 +235,6 @@ int do_commandarp(struct nft_handle *h, int argc, char *argv[], char **table, bo
 /* For xtables-eb.c */
 int nft_init_eb(struct nft_handle *h, const char *pname);
 void nft_fini_eb(struct nft_handle *h);
-int ebt_get_current_chain(const char *chain);
 int do_commandeb(struct nft_handle *h, int argc, char *argv[], char **table, bool restore);
 
 /*
@@ -242,6 +243,7 @@ int do_commandeb(struct nft_handle *h, int argc, char *argv[], char **table, boo
 struct xt_buf;
 
 bool xlate_find_match(const struct iptables_command_state *cs, const char *p_name);
+bool xlate_find_protomatch(const struct iptables_command_state *cs, uint16_t proto);
 int xlate_matches(const struct iptables_command_state *cs, struct xt_xlate *xl);
 int xlate_action(const struct iptables_command_state *cs, bool goto_set,
 		 struct xt_xlate *xl);
diff --git a/iptables/tests/shell/run-tests.sh b/iptables/tests/shell/run-tests.sh
index 11256905..565b654e 100755
--- a/iptables/tests/shell/run-tests.sh
+++ b/iptables/tests/shell/run-tests.sh
@@ -87,6 +87,17 @@ if [ "$HOST" != "y" ]; then
 	XTABLES_LEGACY_MULTI="$(dirname $0)/../../xtables-legacy-multi"
 
 	export XTABLES_LIBDIR=${TESTDIR}/../../../extensions
+
+	# maybe this is 'make distcheck' calling us from a build tree
+	if [ ! -e "$XTABLES_NFT_MULTI" -a \
+	     ! -e "$XTABLES_LEGACY_MULTI" -a \
+	     -e "./iptables/xtables-nft-multi" -a \
+	     -e "./iptables/xtables-legacy-multi" ]; then
+		msg_warn "Running in separate build-tree, using binaries from $PWD/iptables"
+		XTABLES_NFT_MULTI="$PWD/iptables/xtables-nft-multi"
+		XTABLES_LEGACY_MULTI="$PWD/iptables/xtables-legacy-multi"
+		export XTABLES_LIBDIR="$PWD/extensions"
+	fi
 else
 	XTABLES_NFT_MULTI="xtables-nft-multi"
 	XTABLES_LEGACY_MULTI="xtables-legacy-multi"
@@ -154,7 +165,7 @@ do_test() {
 
 	rc_spec=`echo $(basename ${testfile}) | cut -d _ -f2-`
 
-	msg_info "[EXECUTING]   $testfile"
+	[ -t 1 ] && msg_info "[EXECUTING]   $testfile"
 
 	if [ "$VERBOSE" = "y" ]; then
 		XT_MULTI=$xtables_multi unshare -n ${testfile}
@@ -162,7 +173,7 @@ do_test() {
 	else
 		XT_MULTI=$xtables_multi unshare -n ${testfile} > /dev/null 2>&1
 		rc_got=$?
-		echo -en "\033[1A\033[K" # clean the [EXECUTING] foobar line
+		[ -t 1 ] && echo -en "\033[1A\033[K" # clean the [EXECUTING] foobar line
 	fi
 
 	if [ "$rc_got" == "$rc_spec" ] ; then
diff --git a/iptables/tests/shell/testcases/ebtables/0008-ebtables-among_0 b/iptables/tests/shell/testcases/ebtables/0008-ebtables-among_0
index b5df9725..962b1e03 100755
--- a/iptables/tests/shell/testcases/ebtables/0008-ebtables-among_0
+++ b/iptables/tests/shell/testcases/ebtables/0008-ebtables-among_0
@@ -71,27 +71,35 @@ bf_client_ip1="10.167.11.2"
 pktsize=64
 
 # --among-src [mac,IP]
+among="$bf_bridge_mac0=$bf_bridge_ip0,$bf_client_mac1=$bf_client_ip1"
 ip netns exec "$nsb" $XT_MULTI ebtables -F
-ip netns exec "$nsb" $XT_MULTI ebtables -A FORWARD -p ip --ip-dst $bf_server_ip1 --among-src $bf_bridge_mac0=$bf_bridge_ip0,$bf_client_mac1=$bf_client_ip1 -j DROP > /dev/null
+ip netns exec "$nsb" $XT_MULTI ebtables -A FORWARD \
+	-p ip --ip-dst $bf_server_ip1 --among-src "$among" -j DROP > /dev/null
 ip netns exec "$nsc" ping -q $bf_server_ip1 -c 1 -s $pktsize -W 1 >/dev/null
 assert_fail $? "--among-src [match]"
 
 # ip netns exec "$nsb" $XT_MULTI ebtables -L --Ln --Lc
 
+among="$bf_bridge_mac0=$bf_bridge_ip0,$bf_client_mac1=$bf_client_ip1"
 ip netns exec "$nsb" $XT_MULTI ebtables -F
-ip netns exec "$nsb" $XT_MULTI ebtables -A FORWARD -p ip --ip-dst $bf_server_ip1 --among-src ! $bf_bridge_mac0=$bf_bridge_ip0,$bf_client_mac1=$bf_client_ip1 -j DROP > /dev/null
+ip netns exec "$nsb" $XT_MULTI ebtables -A FORWARD \
+	-p ip --ip-dst $bf_server_ip1 ! --among-src "$among" -j DROP > /dev/null
 ip netns exec "$nsc" ping $bf_server_ip1 -c 1 -s $pktsize -W 1 >/dev/null
 assert_pass $? "--among-src [not match]"
 
 # --among-dst [mac,IP]
+among="$bf_client_mac1=$bf_client_ip1,$bf_server_mac1=$bf_server_ip1"
 ip netns exec "$nsb" $XT_MULTI ebtables -F
-ip netns exec "$nsb" $XT_MULTI ebtables -A FORWARD -p ip --ip-src $bf_client_ip1 --among-dst $bf_client_mac1=$bf_client_ip1,$bf_server_mac1=$bf_server_ip1 -j DROP > /dev/null
+ip netns exec "$nsb" $XT_MULTI ebtables -A FORWARD \
+	-p ip --ip-src $bf_client_ip1 --among-dst "$among" -j DROP > /dev/null
 ip netns exec "$nsc" ping -q $bf_server_ip1 -c 1 -s $pktsize -W 1 > /dev/null
 assert_fail $? "--among-dst [match]"
 
-# --among-dst ! [mac,IP]
+# ! --among-dst [mac,IP]
+among="$bf_client_mac1=$bf_client_ip1,$bf_server_mac1=$bf_server_ip1"
 ip netns exec "$nsb" $XT_MULTI ebtables -F
-ip netns exec "$nsb" $XT_MULTI ebtables -A FORWARD -p ip --ip-src $bf_client_ip1 --among-dst ! $bf_client_mac1=$bf_client_ip1,$bf_server_mac1=$bf_server_ip1 -j DROP > /dev/null
+ip netns exec "$nsb" $XT_MULTI ebtables -A FORWARD \
+	-p ip --ip-src $bf_client_ip1 ! --among-dst "$among" -j DROP > /dev/null
 ip netns exec "$nsc" ping -q $bf_server_ip1 -c 1 -s $pktsize -W 1 > /dev/null
 assert_pass $? "--among-dst [not match]"
 
diff --git a/iptables/tests/shell/testcases/ebtables/0009-broute-bug_0 b/iptables/tests/shell/testcases/ebtables/0009-broute-bug_0
new file mode 100755
index 00000000..0def0ac5
--- /dev/null
+++ b/iptables/tests/shell/testcases/ebtables/0009-broute-bug_0
@@ -0,0 +1,25 @@
+#!/bin/sh
+#
+# Missing BROUTING-awareness in ebt_get_current_chain() caused an odd caching bug when restoring:
+# - with --noflush
+# - a second table after the broute one
+# - A policy command but no chain line for BROUTING chain
+
+set -e
+
+case "$XT_MULTI" in
+*xtables-nft-multi)
+	;;
+*)
+	echo "skip $XT_MULTI"
+	exit 0
+	;;
+esac
+
+$XT_MULTI ebtables-restore --noflush <<EOF
+*broute
+-P BROUTING ACCEPT
+*nat
+-P PREROUTING ACCEPT
+COMMIT
+EOF
diff --git a/iptables/tests/shell/testcases/ebtables/0010-change-counters_0 b/iptables/tests/shell/testcases/ebtables/0010-change-counters_0
new file mode 100755
index 00000000..65068289
--- /dev/null
+++ b/iptables/tests/shell/testcases/ebtables/0010-change-counters_0
@@ -0,0 +1,45 @@
+#!/bin/bash
+
+case "$XT_MULTI" in
+*xtables-nft-multi)
+	;;
+*)
+	echo "skip $XT_MULTI"
+	exit 0
+	;;
+esac
+
+set -e
+set -x
+
+check_rule() { # (pcnt, bcnt)
+	$XT_MULTI ebtables -L FORWARD --Lc --Ln | \
+		grep -q "^1. -o eth0 -j CONTINUE , pcnt = $1 -- bcnt = $2$"
+}
+
+$XT_MULTI ebtables -A FORWARD -o eth0 -c 10 20
+check_rule 10 20
+
+$XT_MULTI ebtables -C FORWARD 1 100 200
+check_rule 100 200
+
+$XT_MULTI ebtables -C FORWARD 101 201 -o eth0
+check_rule 101 201
+
+$XT_MULTI ebtables -C FORWARD 1 +10 -20
+check_rule 111 181
+
+$XT_MULTI ebtables -C FORWARD -10 +20 -o eth0
+check_rule 101 201
+
+$XT_MULTI ebtables -A FORWARD -o eth1 -c 111 211
+$XT_MULTI ebtables -A FORWARD -o eth2 -c 121 221
+
+$XT_MULTI ebtables -C FORWARD 2:3 +100 -200
+
+EXPECT='1. -o eth0 -j CONTINUE , pcnt = 101 -- bcnt = 201
+2. -o eth1 -j CONTINUE , pcnt = 211 -- bcnt = 11
+3. -o eth2 -j CONTINUE , pcnt = 221 -- bcnt = 21'
+diff -u <(echo "$EXPECT") \
+	<($XT_MULTI ebtables -L FORWARD --Lc --Ln | grep -- '-o eth')
+
diff --git a/iptables/tests/shell/testcases/ebtables/0011-rulenum_0 b/iptables/tests/shell/testcases/ebtables/0011-rulenum_0
new file mode 100755
index 00000000..51302f34
--- /dev/null
+++ b/iptables/tests/shell/testcases/ebtables/0011-rulenum_0
@@ -0,0 +1,104 @@
+#!/bin/bash -x
+
+case "$XT_MULTI" in
+*xtables-nft-multi)
+	;;
+*)
+	echo "skip $XT_MULTI"
+	exit 0
+	;;
+esac
+
+set -e
+
+load_ruleset() {
+	$XT_MULTI ebtables-restore <<EOF
+*filter
+-A FORWARD --mark 0x1 -c 1 2
+-A FORWARD --mark 0x2 -c 2 3
+EOF
+}
+
+load_ruleset
+
+$XT_MULTI ebtables -L 0 && exit 1
+
+EXPECT='--mark 0x1 -j CONTINUE , pcnt = 1 -- bcnt = 2'
+diff -u -b <(echo -e "$EXPECT") <($XT_MULTI ebtables -L FORWARD 1 --Lc)
+
+EXPECT='--mark 0x2 -j CONTINUE , pcnt = 2 -- bcnt = 3'
+diff -u -b <(echo -e "$EXPECT") <($XT_MULTI ebtables -v -L FORWARD 2 --Lc)
+
+[[ -z $($XT_MULTI ebtables -L FORWARD 3) ]]
+
+$XT_MULTI ebtables -S FORWARD 0 && exit 1
+
+EXPECT='[1:2] -A FORWARD --mark 0x1 -j CONTINUE'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI ebtables -v -S FORWARD 1)
+
+EXPECT='[2:3] -A FORWARD --mark 0x2 -j CONTINUE'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI ebtables -v -S FORWARD 2)
+
+[[ -z $($XT_MULTI ebtables -S FORWARD 3) ]]
+
+$XT_MULTI ebtables -v -Z FORWARD 0 && exit 1
+
+[[ -z $($XT_MULTI ebtables -v -Z FORWARD 1) ]]
+EXPECT='[0:0] -A FORWARD --mark 0x1 -j CONTINUE
+[2:3] -A FORWARD --mark 0x2 -j CONTINUE'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI ebtables -v -S | grep -v '^-P')
+
+[[ -z $($XT_MULTI ebtables -v -Z FORWARD 2) ]]
+EXPECT='[0:0] -A FORWARD --mark 0x1 -j CONTINUE
+[0:0] -A FORWARD --mark 0x2 -j CONTINUE'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI ebtables -v -S | grep -v '^-P')
+
+$XT_MULTI ebtables -v -Z FORWARD 3 && exit 1
+
+load_ruleset
+
+[[ -z $($XT_MULTI ebtables -v -L -Z FORWARD 1) ]]
+EXPECT='[0:0] -A FORWARD --mark 0x1 -j CONTINUE
+[2:3] -A FORWARD --mark 0x2 -j CONTINUE'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI ebtables -v -S | grep -v '^-P')
+
+[[ -z $($XT_MULTI ebtables -v -L -Z FORWARD 2) ]]
+EXPECT='[0:0] -A FORWARD --mark 0x1 -j CONTINUE
+[0:0] -A FORWARD --mark 0x2 -j CONTINUE'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI ebtables -v -S | grep -v '^-P')
+
+load_ruleset
+
+$XT_MULTI ebtables -v -Z -L FORWARD 0 && exit 1
+
+EXPECT='--mark 0x1 -j CONTINUE
+Zeroing chain `FORWARD'\'
+diff -u -b <(echo -e "$EXPECT") <($XT_MULTI ebtables -v -Z -L FORWARD 1)
+EXPECT='[0:0] -A FORWARD --mark 0x1 -j CONTINUE
+[0:0] -A FORWARD --mark 0x2 -j CONTINUE'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI ebtables -v -S | grep -v '^-P')
+
+EXPECT='--mark 0x2 -j CONTINUE
+Zeroing chain `FORWARD'\'
+diff -u -b <(echo -e "$EXPECT") <($XT_MULTI ebtables -v -Z -L FORWARD 2)
+
+$XT_MULTI ebtables -v -Z -L FORWARD 0 && exit 1
+
+EXPECT='Zeroing chain `FORWARD'\'
+diff -u -b <(echo -e "$EXPECT") <($XT_MULTI ebtables -v -Z -L FORWARD 3)
+
+load_ruleset
+
+[[ -z $($XT_MULTI ebtables -v -D FORWARD 1) ]]
+EXPECT='[2:3] -A FORWARD --mark 0x2 -j CONTINUE'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI ebtables -v -S | grep -v '^-P')
+
+load_ruleset
+
+[[ -z $($XT_MULTI ebtables -v -D FORWARD 2) ]]
+EXPECT='[1:2] -A FORWARD --mark 0x1 -j CONTINUE'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI ebtables -v -S | grep -v '^-P')
+
+$XT_MULTI ebtables -v -D FORWARD 3 && exit 1
+
+exit 0
diff --git a/iptables/tests/shell/testcases/ebtables/0012-restore-delete-among_0 b/iptables/tests/shell/testcases/ebtables/0012-restore-delete-among_0
new file mode 100755
index 00000000..165745e1
--- /dev/null
+++ b/iptables/tests/shell/testcases/ebtables/0012-restore-delete-among_0
@@ -0,0 +1,18 @@
+#!/bin/bash -e
+
+case "$XT_MULTI" in
+*xtables-nft-multi)
+	;;
+*)
+	echo "skip $XT_MULTI"
+	exit 0
+	;;
+esac
+
+RULESET='*filter
+-A FORWARD --among-dst de:ad:0:be:ee:ff,c0:ff:ee:0:ba:be
+-A FORWARD --among-dst de:ad:0:be:ee:ff'
+
+$XT_MULTI ebtables-restore <<< "$RULESET"
+echo "$RULESET" | sed -e 's/-A/-D/' | $XT_MULTI ebtables-restore --noflush
+
diff --git a/iptables/tests/shell/testcases/ip6tables/0002-verbose-output_0 b/iptables/tests/shell/testcases/ip6tables/0002-verbose-output_0
index 7ecfa718..45fab830 100755
--- a/iptables/tests/shell/testcases/ip6tables/0002-verbose-output_0
+++ b/iptables/tests/shell/testcases/ip6tables/0002-verbose-output_0
@@ -35,7 +35,7 @@ Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
  pkts bytes target     prot opt in     out     source               destination
     0     0 ACCEPT     all  --  eth2   eth3    feed:babe::1         feed:babe::2
     0     0 ACCEPT     all  --  eth2   eth3    feed:babe::4         feed:babe::5
-    0     0            58   --  *      *       ::/0                 ::/0                 ipv6-icmptype 1 code 0
+    0     0            ipv6-icmp --  *      *       ::/0                 ::/0                 ipv6-icmptype 1 code 0
     0     0            all  --  *      *       ::/0                 ::/0                 dst length:42 rt type:23
     0     0 LOG        all  --  *      *       ::/0                 ::/0                 frag id:1337 LOG flags 0 level 4
 
diff --git a/iptables/tests/shell/testcases/ipt-save/0001load-dumps_0 b/iptables/tests/shell/testcases/ipt-save/0001load-dumps_0
index 4e0be51c..48f5f7b4 100755
--- a/iptables/tests/shell/testcases/ipt-save/0001load-dumps_0
+++ b/iptables/tests/shell/testcases/ipt-save/0001load-dumps_0
@@ -39,6 +39,7 @@ do_simple()
 
 	$XT_MULTI ${iptables}-restore < "$dumpfile"
 	$XT_MULTI ${iptables}-save | grep -v "^#" > "$tmpfile"
+	sed -i -e 's/-p 47 /-p gre /' "$tmpfile"
 	do_diff $dumpfile "$tmpfile"
 	if [ $? -ne 0 ]; then
 		# cp "$tmpfile" "$dumpfile.got"
diff --git a/iptables/tests/shell/testcases/ipt-save/0003save-restore_0 b/iptables/tests/shell/testcases/ipt-save/0003save-restore_0
old mode 100644
new mode 100755
diff --git a/iptables/tests/shell/testcases/iptables/0010-wait_0 b/iptables/tests/shell/testcases/iptables/0010-wait_0
new file mode 100755
index 00000000..37a7a58f
--- /dev/null
+++ b/iptables/tests/shell/testcases/iptables/0010-wait_0
@@ -0,0 +1,55 @@
+#!/bin/bash
+
+case "$XT_MULTI" in
+*xtables-legacy-multi)
+	;;
+*)
+	echo skip $XT_MULTI
+	exit 0
+	;;
+esac
+
+coproc RESTORE { $XT_MULTI iptables-restore; }
+echo "*filter" >&${RESTORE[1]}
+sleep 0.5
+
+$XT_MULTI iptables -A FORWARD -j ACCEPT &
+ipt_pid=$!
+
+waitpid -t 1 $ipt_pid
+[[ $? -eq 3 ]] && {
+	echo "process waits when it should not"
+	exit 1
+}
+wait $ipt_pid
+[[ $? -eq 0 ]] && {
+	echo "process exited 0 despite busy lock"
+	exit 1
+}
+
+t0=$(date +%s)
+$XT_MULTI iptables -w 3 -A FORWARD -j ACCEPT
+t1=$(date +%s)
+[[ $((t1 - t0)) -ge 3 ]] || {
+	echo "wait time not expired"
+	exit 1
+}
+
+$XT_MULTI iptables -w -A FORWARD -j ACCEPT &
+ipt_pid=$!
+
+waitpid -t 3 $ipt_pid
+[[ $? -eq 3 ]] || {
+	echo "no indefinite wait"
+	exit 1
+}
+kill $ipt_pid
+waitpid -t 3 $ipt_pid
+[[ $? -eq 3 ]] && {
+	echo "killed waiting iptables call did not exit in time"
+	exit 1
+}
+
+kill $RESTORE_PID
+wait
+exit 0
diff --git a/iptables/tests/shell/testcases/iptables/0011-rulenum_0 b/iptables/tests/shell/testcases/iptables/0011-rulenum_0
new file mode 100755
index 00000000..4f973cdc
--- /dev/null
+++ b/iptables/tests/shell/testcases/iptables/0011-rulenum_0
@@ -0,0 +1,93 @@
+#!/bin/bash -x
+
+set -e
+
+load_ruleset() {
+	$XT_MULTI iptables-restore <<EOF
+*filter
+-A FORWARD -m mark --mark 0x1 -c 1 2
+-A FORWARD -m mark --mark 0x2 -c 2 3
+COMMIT
+EOF
+}
+
+load_ruleset
+
+$XT_MULTI iptables -L 0 && exit 1
+
+EXPECT=' 1 2 all -- any any anywhere anywhere mark match 0x1'
+diff -u -b <(echo -e "$EXPECT") <($XT_MULTI iptables -v -L FORWARD 1)
+
+EXPECT=' 2 3 all -- any any anywhere anywhere mark match 0x2'
+diff -u -b <(echo -e "$EXPECT") <($XT_MULTI iptables -v -L FORWARD 2)
+
+[[ -z $($XT_MULTI iptables -L FORWARD 3) ]]
+
+$XT_MULTI iptables -S FORWARD 0 && exit 1
+
+EXPECT='-A FORWARD -m mark --mark 0x1 -c 1 2'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI iptables -v -S FORWARD 1)
+
+EXPECT='-A FORWARD -m mark --mark 0x2 -c 2 3'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI iptables -v -S FORWARD 2)
+
+[[ -z $($XT_MULTI iptables -S FORWARD 3) ]]
+
+$XT_MULTI iptables -v -Z FORWARD 0 && exit 1
+
+[[ -z $($XT_MULTI iptables -v -Z FORWARD 1) ]]
+EXPECT='-A FORWARD -m mark --mark 0x1 -c 0 0
+-A FORWARD -m mark --mark 0x2 -c 2 3'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI iptables -v -S | grep -v '^-P')
+
+[[ -z $($XT_MULTI iptables -v -Z FORWARD 2) ]]
+EXPECT='-A FORWARD -m mark --mark 0x1 -c 0 0
+-A FORWARD -m mark --mark 0x2 -c 0 0'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI iptables -v -S | grep -v '^-P')
+
+$XT_MULTI iptables -v -Z FORWARD 3 && exit 1
+
+load_ruleset
+
+[[ -z $($XT_MULTI iptables -v -L -Z FORWARD 1) ]]
+EXPECT='-A FORWARD -m mark --mark 0x1 -c 0 0
+-A FORWARD -m mark --mark 0x2 -c 2 3'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI iptables -v -S | grep -v '^-P')
+
+[[ -z $($XT_MULTI iptables -v -L -Z FORWARD 2) ]]
+EXPECT='-A FORWARD -m mark --mark 0x1 -c 0 0
+-A FORWARD -m mark --mark 0x2 -c 0 0'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI iptables -v -S | grep -v '^-P')
+
+load_ruleset
+
+$XT_MULTI iptables -v -Z -L FORWARD 0 && exit 1
+
+EXPECT=' 1 2 all -- any any anywhere anywhere mark match 0x1
+Zeroing chain `FORWARD'\'
+diff -u -b <(echo -e "$EXPECT") <($XT_MULTI iptables -v -Z -L FORWARD 1)
+
+EXPECT=' 0 0 all -- any any anywhere anywhere mark match 0x2
+Zeroing chain `FORWARD'\'
+diff -u -b <(echo -e "$EXPECT") <($XT_MULTI iptables -v -Z -L FORWARD 2)
+
+$XT_MULTI iptables -v -Z -L FORWARD 0 && exit 1
+
+EXPECT='Zeroing chain `FORWARD'\'
+diff -u -b <(echo -e "$EXPECT") <($XT_MULTI iptables -v -Z -L FORWARD 3)
+
+load_ruleset
+
+[[ -z $($XT_MULTI iptables -v -D FORWARD 1) ]]
+EXPECT='-A FORWARD -m mark --mark 0x2 -c 2 3'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI iptables -v -S | grep -v '^-P')
+
+load_ruleset
+
+[[ -z $($XT_MULTI iptables -v -D FORWARD 2) ]]
+EXPECT='-A FORWARD -m mark --mark 0x1 -c 1 2'
+diff -u <(echo -e "$EXPECT") <($XT_MULTI iptables -v -S | grep -v '^-P')
+
+$XT_MULTI iptables -v -D FORWARD 3 && exit 1
+
+exit 0
diff --git a/iptables/tests/shell/testcases/nft-only/0009-needless-bitwise_0 b/iptables/tests/shell/testcases/nft-only/0009-needless-bitwise_0
index 34802cc2..bfceed49 100755
--- a/iptables/tests/shell/testcases/nft-only/0009-needless-bitwise_0
+++ b/iptables/tests/shell/testcases/nft-only/0009-needless-bitwise_0
@@ -343,4 +343,4 @@ filter() {
 	awk '/^table /{exit} /^(  \[|$)/{print}'
 }
 
-diff -u -Z <(filter <<< "$EXPECT") <(nft --debug=netlink list ruleset | filter)
+diff -u -Z -B <(filter <<< "$EXPECT") <(nft --debug=netlink list ruleset | filter)
diff --git a/iptables/tests/shell/testcases/nft-only/0011-zero-needs-compat_0 b/iptables/tests/shell/testcases/nft-only/0011-zero-needs-compat_0
new file mode 100755
index 00000000..e276a953
--- /dev/null
+++ b/iptables/tests/shell/testcases/nft-only/0011-zero-needs-compat_0
@@ -0,0 +1,12 @@
+#!/bin/bash
+
+[[ $XT_MULTI == *xtables-nft-multi ]] || { echo "skip $XT_MULTI"; exit 0; }
+
+set -e
+
+rule="-p tcp -m tcp --dport 27374 -c 23 42 -j TPROXY --on-port 50080"
+for cmd in iptables ip6tables; do
+	$XT_MULTI $cmd -t mangle -A PREROUTING $rule
+	$XT_MULTI $cmd -t mangle -Z
+	$XT_MULTI $cmd -t mangle -v -S | grep -q -- "${rule/23 42/0 0}"
+done
diff --git a/iptables/tests/shell/testcases/nft-only/0012-xtables-monitor_0 b/iptables/tests/shell/testcases/nft-only/0012-xtables-monitor_0
new file mode 100755
index 00000000..c49b7ccd
--- /dev/null
+++ b/iptables/tests/shell/testcases/nft-only/0012-xtables-monitor_0
@@ -0,0 +1,139 @@
+#!/bin/bash
+
+[[ $XT_MULTI == *xtables-nft-multi ]] || { echo "skip $XT_MULTI"; exit 0; }
+
+log=$(mktemp)
+trap "rm -f $log" EXIT
+echo "logging into file $log"
+rc=0
+
+# Filter monitor output:
+# - NEWGEN event is moot:
+#   - GENID/PID are arbitrary,
+#   - NAME always "xtables-nft-mul"
+# - handle is arbitrary as well
+logfilter() { # (logfile)
+	grep -v '^NEWGEN:' "$1" | sed -e 's/handle [0-9]\+/handle 0/'
+}
+
+# Compare monitor output for given command against content of the global $EXP
+monitorcheck() { # (cmd ...)
+	$XT_MULTI xtables-monitor -e >"$log"&
+	monpid=$!
+	sleep 0.5
+
+	$XT_MULTI "$@" || {
+		echo "Error: command failed: $@"
+		let "rc++"
+		kill $monpid
+		wait
+		return
+	}
+	sleep 0.5
+	kill $monpid
+	wait
+	diffout=$(diff -u <(echo "$EXP") <(logfilter "$log")) || {
+		echo "Fail: unexpected result for command: '$@':"
+		grep -v '^\(---\|+++\|@@\)' <<< "$diffout"
+		let "rc++"
+	}
+}
+
+EXP="\
+ EVENT: nft: NEW table: table filter ip flags 0 use 1 handle 0
+ EVENT: nft: NEW chain: ip filter FORWARD use 1 type filter hook forward prio 0 policy accept packets 0 bytes 0 flags 1
+ EVENT: iptables -t filter -A FORWARD -j ACCEPT"
+monitorcheck iptables -A FORWARD -j ACCEPT
+
+EXP="\
+ EVENT: nft: NEW table: table filter ip6 flags 0 use 1 handle 0
+ EVENT: nft: NEW chain: ip6 filter FORWARD use 1 type filter hook forward prio 0 policy accept packets 0 bytes 0 flags 1
+ EVENT: ip6tables -t filter -A FORWARD -j ACCEPT"
+monitorcheck ip6tables -A FORWARD -j ACCEPT
+
+EXP="\
+ EVENT: nft: NEW table: table filter bridge flags 0 use 1 handle 0
+ EVENT: nft: NEW chain: bridge filter FORWARD use 1 type filter hook forward prio -200 policy accept packets 0 bytes 0 flags 1
+ EVENT: ebtables -t filter -A FORWARD -j ACCEPT"
+monitorcheck ebtables -A FORWARD -j ACCEPT
+
+EXP="\
+ EVENT: nft: NEW table: table filter arp flags 0 use 1 handle 0
+ EVENT: nft: NEW chain: arp filter INPUT use 1 type filter hook input prio 0 policy accept packets 0 bytes 0 flags 1
+ EVENT: arptables -t filter -A INPUT -j ACCEPT"
+monitorcheck arptables -A INPUT -j ACCEPT
+
+EXP=" EVENT: iptables -t filter -N foo"
+monitorcheck iptables -N foo
+
+EXP=" EVENT: ip6tables -t filter -N foo"
+monitorcheck ip6tables -N foo
+
+EXP=" EVENT: ebtables -t filter -N foo"
+monitorcheck ebtables -N foo
+
+EXP=" EVENT: arptables -t filter -N foo"
+monitorcheck arptables -N foo
+
+# meta l4proto matches require proper nft_handle:family value
+EXP=" EVENT: iptables -t filter -A FORWARD -i eth1 -o eth2 -p tcp -m tcp --dport 22 -j ACCEPT"
+monitorcheck iptables -A FORWARD -i eth1 -o eth2 -p tcp --dport 22 -j ACCEPT
+
+EXP=" EVENT: ip6tables -t filter -A FORWARD -i eth1 -o eth2 -p udp -m udp --sport 1337 -j ACCEPT"
+monitorcheck ip6tables -A FORWARD -i eth1 -o eth2 -p udp --sport 1337 -j ACCEPT
+
+EXP=" EVENT: ebtables -t filter -A FORWARD -p IPv4 -i eth1 -o eth2 --ip-proto udp --ip-sport 1337 -j ACCEPT"
+monitorcheck ebtables -A FORWARD -i eth1 -o eth2 -p ip --ip-protocol udp --ip-source-port 1337 -j ACCEPT
+
+EXP=" EVENT: arptables -t filter -A INPUT -j ACCEPT -i eth1 -s 1.2.3.4 --src-mac 01:02:03:04:05:06"
+monitorcheck arptables -A INPUT -i eth1 -s 1.2.3.4 --src-mac 01:02:03:04:05:06 -j ACCEPT
+
+EXP=" EVENT: iptables -t filter -D FORWARD -i eth1 -o eth2 -p tcp -m tcp --dport 22 -j ACCEPT"
+monitorcheck iptables -D FORWARD -i eth1 -o eth2 -p tcp --dport 22 -j ACCEPT
+
+EXP=" EVENT: ip6tables -t filter -D FORWARD -i eth1 -o eth2 -p udp -m udp --sport 1337 -j ACCEPT"
+monitorcheck ip6tables -D FORWARD -i eth1 -o eth2 -p udp --sport 1337 -j ACCEPT
+
+EXP=" EVENT: ebtables -t filter -D FORWARD -p IPv4 -i eth1 -o eth2 --ip-proto udp --ip-sport 1337 -j ACCEPT"
+monitorcheck ebtables -D FORWARD -i eth1 -o eth2 -p ip --ip-protocol udp --ip-source-port 1337 -j ACCEPT
+
+EXP=" EVENT: arptables -t filter -D INPUT -j ACCEPT -i eth1 -s 1.2.3.4 --src-mac 01:02:03:04:05:06"
+monitorcheck arptables -D INPUT -i eth1 -s 1.2.3.4 --src-mac 01:02:03:04:05:06 -j ACCEPT
+
+EXP=" EVENT: iptables -t filter -X foo"
+monitorcheck iptables -X foo
+
+EXP=" EVENT: ip6tables -t filter -X foo"
+monitorcheck ip6tables -X foo
+
+EXP=" EVENT: ebtables -t filter -X foo"
+monitorcheck ebtables -X foo
+
+EXP=" EVENT: arptables -t filter -X foo"
+monitorcheck arptables -X foo
+
+EXP=" EVENT: iptables -t filter -D FORWARD -j ACCEPT"
+monitorcheck iptables -F FORWARD
+
+EXP=" EVENT: ip6tables -t filter -D FORWARD -j ACCEPT"
+monitorcheck ip6tables -F FORWARD
+
+EXP=" EVENT: ebtables -t filter -D FORWARD -j ACCEPT"
+monitorcheck ebtables -F FORWARD
+
+EXP=" EVENT: arptables -t filter -D INPUT -j ACCEPT"
+monitorcheck arptables -F INPUT
+
+EXP=" EVENT: nft: DEL chain: ip filter FORWARD use 0 type filter hook forward prio 0 policy accept packets 0 bytes 0 flags 1"
+monitorcheck iptables -X FORWARD
+
+EXP=" EVENT: nft: DEL chain: ip6 filter FORWARD use 0 type filter hook forward prio 0 policy accept packets 0 bytes 0 flags 1"
+monitorcheck ip6tables -X FORWARD
+
+EXP=" EVENT: nft: DEL chain: bridge filter FORWARD use 0 type filter hook forward prio -200 policy accept packets 0 bytes 0 flags 1"
+monitorcheck ebtables -X FORWARD
+
+EXP=" EVENT: nft: DEL chain: arp filter INPUT use 0 type filter hook input prio 0 policy accept packets 0 bytes 0 flags 1"
+monitorcheck arptables -X INPUT
+
+exit $rc
diff --git a/iptables/tests/shell/testcases/nft-only/0013-zero-non-existent_0 b/iptables/tests/shell/testcases/nft-only/0013-zero-non-existent_0
new file mode 100755
index 00000000..bbf1af76
--- /dev/null
+++ b/iptables/tests/shell/testcases/nft-only/0013-zero-non-existent_0
@@ -0,0 +1,17 @@
+#!/bin/bash
+
+[[ $XT_MULTI == *xtables-nft-multi ]] || { echo "skip $XT_MULTI"; exit 0; }
+nft --version >/dev/null 2>&1 || { echo "skip nft"; exit 0; }
+
+set -e
+
+nft flush ruleset
+$XT_MULTI iptables -Z INPUT
+
+EXP="Zeroing chain \`INPUT'"
+diff -u <(echo "$EXP") <($XT_MULTI iptables -v -Z INPUT)
+
+EXP="Zeroing chain \`INPUT'
+Zeroing chain \`FORWARD'
+Zeroing chain \`OUTPUT'"
+diff -u <(echo "$EXP") <($XT_MULTI iptables -v -Z)
diff --git a/iptables/tests/shell/testcases/nft-only/0020-compare-interfaces_0 b/iptables/tests/shell/testcases/nft-only/0020-compare-interfaces_0
new file mode 100755
index 00000000..278cd648
--- /dev/null
+++ b/iptables/tests/shell/testcases/nft-only/0020-compare-interfaces_0
@@ -0,0 +1,9 @@
+#!/bin/bash
+
+[[ $XT_MULTI == *xtables-nft-multi ]] || { echo "skip $XT_MULTI"; exit 0; }
+
+$XT_MULTI iptables -N test
+$XT_MULTI iptables -A test -i lo \! -o lo -j REJECT
+$XT_MULTI iptables -C test -i abcdefgh \! -o abcdefgh -j REJECT 2>/dev/null && exit 1
+
+exit 0
diff --git a/iptables/xshared.c b/iptables/xshared.c
index 67fa2cfa..2f663f97 100644
--- a/iptables/xshared.c
+++ b/iptables/xshared.c
@@ -62,7 +62,7 @@ static void print_extension_helps(const struct xtables_target *t,
 	}
 }
 
-static const char *
+const char *
 proto_to_name(uint16_t proto, int nolookup)
 {
 	unsigned int i;
@@ -122,8 +122,8 @@ static struct xtables_match *load_proto(struct iptables_command_state *cs)
 			  cs->options & OPT_NUMERIC, &cs->matches);
 }
 
-static int command_default(struct iptables_command_state *cs,
-			   struct xtables_globals *gl, bool invert)
+int command_default(struct iptables_command_state *cs,
+		    struct xtables_globals *gl, bool invert)
 {
 	struct xtables_rule_match *matchp;
 	struct xtables_match *m;
@@ -270,7 +270,7 @@ static int xtables_lock(int wait)
 		return XT_LOCK_FAILED;
 	}
 
-	if (wait != -1) {
+	if (wait > 0) {
 		sigact_alarm.sa_handler = alarm_ignore;
 		sigact_alarm.sa_flags = SA_RESETHAND;
 		sigemptyset(&sigact_alarm.sa_mask);
@@ -278,7 +278,7 @@ static int xtables_lock(int wait)
 		alarm(wait);
 	}
 
-	if (flock(fd, LOCK_EX) == 0)
+	if (flock(fd, LOCK_EX | (wait ? 0 : LOCK_NB)) == 0)
 		return fd;
 
 	if (errno == EINTR) {
@@ -757,29 +757,10 @@ void print_ifaces(const char *iniface, const char *outiface, uint8_t invflags,
 	printf(FMT("%-6s ", "out %s "), iface);
 }
 
-/* This assumes that mask is contiguous, and byte-bounded. */
-void save_iface(char letter, const char *iface,
-		const unsigned char *mask, int invert)
+static void save_iface(char letter, const char *iface, int invert)
 {
-	unsigned int i;
-
-	if (mask[0] == 0)
-		return;
-
-	printf("%s -%c ", invert ? " !" : "", letter);
-
-	for (i = 0; i < IFNAMSIZ; i++) {
-		if (mask[i] != 0) {
-			if (iface[i] != '\0')
-				printf("%c", iface[i]);
-		} else {
-			/* we can access iface[i-1] here, because
-			 * a few lines above we make sure that mask[0] != 0 */
-			if (iface[i-1] != '\0')
-				printf("+");
-			break;
-		}
-	}
+	if (iface && strlen(iface) && (strcmp(iface, "+") || invert))
+		printf("%s -%c %s", invert ? " !" : "", letter, iface);
 }
 
 static void command_match(struct iptables_command_state *cs, bool invert)
@@ -815,6 +796,9 @@ static void command_match(struct iptables_command_state *cs, bool invert)
 	else if (m->extra_opts != NULL)
 		opts = xtables_merge_options(xt_params->orig_opts, opts,
 					     m->extra_opts, &m->option_offset);
+	else
+		return;
+
 	if (opts == NULL)
 		xtables_error(OTHER_PROBLEM, "can't alloc memory!");
 	xt_params->opts = opts;
@@ -873,10 +857,13 @@ void command_jump(struct iptables_command_state *cs, const char *jumpto)
 		opts = xtables_options_xfrm(xt_params->orig_opts, opts,
 					    cs->target->x6_options,
 					    &cs->target->option_offset);
-	else
+	else if (cs->target->extra_opts != NULL)
 		opts = xtables_merge_options(xt_params->orig_opts, opts,
 					     cs->target->extra_opts,
 					     &cs->target->option_offset);
+	else
+		return;
+
 	if (opts == NULL)
 		xtables_error(OTHER_PROBLEM, "can't alloc memory!");
 	xt_params->opts = opts;
@@ -920,123 +907,137 @@ static int parse_rulenumber(const char *rule)
 	return rulenum;
 }
 
-#define NUMBER_OF_OPT	ARRAY_SIZE(optflags)
-static const char optflags[]
-= { 'n', 's', 'd', 'p', 'j', 'v', 'x', 'i', 'o', '0', 'c', 'f', 2, 3, 'l', 4, 5, 6 };
+static void parse_rule_range(struct xt_cmd_parse *p, const char *argv)
+{
+	char *colon = strchr(argv, ':'), *buffer;
 
-/* Table of legal combinations of commands and options.  If any of the
- * given commands make an option legal, that option is legal (applies to
- * CMD_LIST and CMD_ZERO only).
- * Key:
- *  +  compulsory
- *  x  illegal
- *     optional
- */
-static const char commands_v_options[NUMBER_OF_CMD][NUMBER_OF_OPT] =
-/* Well, it's better than "Re: Linux vs FreeBSD" */
-{
-	/*     -n  -s  -d  -p  -j  -v  -x  -i  -o --line -c -f 2 3 l 4 5 6 */
-/*INSERT*/    {'x',' ',' ',' ',' ',' ','x',' ',' ','x',' ',' ',' ',' ',' ',' ',' ',' '},
-/*DELETE*/    {'x',' ',' ',' ',' ',' ','x',' ',' ','x','x',' ',' ',' ',' ',' ',' ',' '},
-/*DELETE_NUM*/{'x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x','x','x','x'},
-/*REPLACE*/   {'x',' ',' ',' ',' ',' ','x',' ',' ','x',' ',' ',' ',' ',' ',' ',' ',' '},
-/*APPEND*/    {'x',' ',' ',' ',' ',' ','x',' ',' ','x',' ',' ',' ',' ',' ',' ',' ',' '},
-/*LIST*/      {' ','x','x','x','x',' ',' ','x','x',' ','x','x','x','x','x','x','x','x'},
-/*FLUSH*/     {'x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x','x','x','x'},
-/*ZERO*/      {'x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x','x','x','x'},
-/*NEW_CHAIN*/ {'x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x','x','x','x'},
-/*DEL_CHAIN*/ {'x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x','x','x','x'},
-/*SET_POLICY*/{'x','x','x','x','x',' ','x','x','x','x',' ','x','x','x','x','x','x','x'},
-/*RENAME*/    {'x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x','x','x','x'},
-/*LIST_RULES*/{'x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x','x','x','x'},
-/*ZERO_NUM*/  {'x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x','x','x','x'},
-/*CHECK*/     {'x',' ',' ',' ',' ',' ','x',' ',' ','x','x',' ',' ',' ',' ',' ',' ',' '},
+	if (colon) {
+		if (!p->rule_ranges)
+			xtables_error(PARAMETER_PROBLEM,
+				      "Rule ranges are not supported");
+
+		*colon = '\0';
+		if (*(colon + 1) == '\0')
+			p->rulenum_end = -1; /* Until the last rule */
+		else {
+			p->rulenum_end = strtol(colon + 1, &buffer, 10);
+			if (*buffer != '\0' || p->rulenum_end == 0)
+				xtables_error(PARAMETER_PROBLEM,
+					      "Invalid rule range end`%s'",
+					      colon + 1);
+		}
+	}
+	if (colon == argv)
+		p->rulenum = 1; /* Beginning with the first rule */
+	else {
+		p->rulenum = strtol(argv, &buffer, 10);
+		if (*buffer != '\0' || p->rulenum == 0)
+			xtables_error(PARAMETER_PROBLEM,
+				      "Invalid rule number `%s'", argv);
+	}
+	if (!colon)
+		p->rulenum_end = p->rulenum;
+}
+
+/* list the commands an option is allowed with */
+#define CMD_IDRAC	CMD_INSERT | CMD_DELETE | CMD_REPLACE | \
+			CMD_APPEND | CMD_CHECK | CMD_CHANGE_COUNTERS
+static const unsigned int options_v_commands[NUMBER_OF_OPT] = {
+/*OPT_NUMERIC*/		CMD_LIST,
+/*OPT_SOURCE*/		CMD_IDRAC,
+/*OPT_DESTINATION*/	CMD_IDRAC,
+/*OPT_PROTOCOL*/	CMD_IDRAC,
+/*OPT_JUMP*/		CMD_IDRAC,
+/*OPT_VERBOSE*/		UINT_MAX,
+/*OPT_EXPANDED*/	CMD_LIST,
+/*OPT_VIANAMEIN*/	CMD_IDRAC,
+/*OPT_VIANAMEOUT*/	CMD_IDRAC,
+/*OPT_LINENUMBERS*/	CMD_LIST,
+/*OPT_COUNTERS*/	CMD_INSERT | CMD_REPLACE | CMD_APPEND | CMD_SET_POLICY,
+/*OPT_FRAGMENT*/	CMD_IDRAC,
+/*OPT_S_MAC*/		CMD_IDRAC,
+/*OPT_D_MAC*/		CMD_IDRAC,
+/*OPT_H_LENGTH*/	CMD_IDRAC,
+/*OPT_OPCODE*/		CMD_IDRAC,
+/*OPT_H_TYPE*/		CMD_IDRAC,
+/*OPT_P_TYPE*/		CMD_IDRAC,
+/*OPT_LOGICALIN*/	CMD_IDRAC,
+/*OPT_LOGICALOUT*/	CMD_IDRAC,
+/*OPT_LIST_C*/		CMD_LIST,
+/*OPT_LIST_X*/		CMD_LIST,
+/*OPT_LIST_MAC2*/	CMD_LIST,
 };
+#undef CMD_IDRAC
 
-static void generic_opt_check(int command, int options)
+static void generic_opt_check(struct xt_cmd_parse_ops *ops,
+			      int command, int options)
 {
-	int i, j, legal = 0;
+	int i, optval;
 
 	/* Check that commands are valid with options. Complicated by the
 	 * fact that if an option is legal with *any* command given, it is
 	 * legal overall (ie. -z and -l).
 	 */
-	for (i = 0; i < NUMBER_OF_OPT; i++) {
-		legal = 0; /* -1 => illegal, 1 => legal, 0 => undecided. */
-
-		for (j = 0; j < NUMBER_OF_CMD; j++) {
-			if (!(command & (1<<j)))
-				continue;
-
-			if (!(options & (1<<i))) {
-				if (commands_v_options[j][i] == '+')
-					xtables_error(PARAMETER_PROBLEM,
-						      "You need to supply the `-%c' option for this command",
-						      optflags[i]);
-			} else {
-				if (commands_v_options[j][i] != 'x')
-					legal = 1;
-				else if (legal == 0)
-					legal = -1;
-			}
-		}
-		if (legal == -1)
+	for (i = 0, optval = 1; i < NUMBER_OF_OPT; optval = (1 << ++i)) {
+		if ((options & optval) &&
+		    (options_v_commands[i] & command) != command)
 			xtables_error(PARAMETER_PROBLEM,
-				      "Illegal option `-%c' with this command",
-				      optflags[i]);
+				      "Illegal option `%s' with this command",
+				      ops->option_name(optval));
 	}
 }
 
-static char opt2char(int option)
+const char *ip46t_option_name(int option)
 {
-	const char *ptr;
-
-	for (ptr = optflags; option > 1; option >>= 1, ptr++)
-		;
+	switch (option) {
+	case OPT_NUMERIC:	return "--numeric";
+	case OPT_SOURCE:	return "--source";
+	case OPT_DESTINATION:	return "--destination";
+	case OPT_PROTOCOL:	return "--protocol";
+	case OPT_JUMP:		return "--jump";
+	case OPT_VERBOSE:	return "--verbose";
+	case OPT_EXPANDED:	return "--exact";
+	case OPT_VIANAMEIN:	return "--in-interface";
+	case OPT_VIANAMEOUT:	return "--out-interface";
+	case OPT_LINENUMBERS:	return "--line-numbers";
+	case OPT_COUNTERS:	return "--set-counters";
+	case OPT_FRAGMENT:	return "--fragments";
+	default:		return "unknown option";
+	}
+}
 
-	return *ptr;
-}
-
-static const int inverse_for_options[NUMBER_OF_OPT] =
-{
-/* -n */ 0,
-/* -s */ IPT_INV_SRCIP,
-/* -d */ IPT_INV_DSTIP,
-/* -p */ XT_INV_PROTO,
-/* -j */ 0,
-/* -v */ 0,
-/* -x */ 0,
-/* -i */ IPT_INV_VIA_IN,
-/* -o */ IPT_INV_VIA_OUT,
-/*--line*/ 0,
-/* -c */ 0,
-/* -f */ IPT_INV_FRAG,
-/* 2 */ IPT_INV_SRCDEVADDR,
-/* 3 */ IPT_INV_TGTDEVADDR,
-/* -l */ IPT_INV_ARPHLN,
-/* 4 */ IPT_INV_ARPOP,
-/* 5 */ IPT_INV_ARPHRD,
-/* 6 */ IPT_INV_PROTO,
-};
+int ip46t_option_invert(int option)
+{
+	switch (option) {
+	case OPT_SOURCE:	return IPT_INV_SRCIP;
+	case OPT_DESTINATION:	return IPT_INV_DSTIP;
+	case OPT_PROTOCOL:	return XT_INV_PROTO;
+	case OPT_VIANAMEIN:	return IPT_INV_VIA_IN;
+	case OPT_VIANAMEOUT:	return IPT_INV_VIA_OUT;
+	case OPT_FRAGMENT:	return IPT_INV_FRAG;
+	default:		return -1;
+	}
+}
 
 static void
-set_option(unsigned int *options, unsigned int option, uint16_t *invflg,
-	   bool invert)
+set_option(struct xt_cmd_parse_ops *ops,
+	   unsigned int *options, unsigned int option,
+	   uint16_t *invflg, bool invert)
 {
 	if (*options & option)
-		xtables_error(PARAMETER_PROBLEM, "multiple -%c flags not allowed",
-			   opt2char(option));
+		xtables_error(PARAMETER_PROBLEM,
+			      "multiple %s options not allowed",
+			      ops->option_name(option));
 	*options |= option;
 
 	if (invert) {
-		unsigned int i;
-		for (i = 0; 1 << i != option; i++);
+		int invopt = ops->option_invert(option);
 
-		if (!inverse_for_options[i])
+		if (invopt < 0)
 			xtables_error(PARAMETER_PROBLEM,
-				   "cannot have ! before -%c",
-				   opt2char(option));
-		*invflg |= inverse_for_options[i];
+				      "cannot have ! before %s",
+				      ops->option_name(option));
+		*invflg |= invopt;
 	}
 }
 
@@ -1083,29 +1084,20 @@ void print_rule_details(unsigned int linenum, const struct xt_counters *ctrs,
 
 	fputc(invflags & XT_INV_PROTO ? '!' : ' ', stdout);
 
-	if (!proto)
-		printf(FMT("%-4s ", "%s "), "all");
-	else if (((format & (FMT_NUMERIC | FMT_NOTABLE)) == FMT_NUMERIC) || !pname)
-		printf(FMT("%-4hu ", "%hu "), proto);
-	else
+	if (pname)
 		printf(FMT("%-4s ", "%s "), pname);
+	else
+		printf(FMT("%-4hu ", "%hu "), proto);
 }
 
-void save_rule_details(const char *iniface, unsigned const char *iniface_mask,
-		       const char *outiface, unsigned const char *outiface_mask,
+void save_rule_details(const char *iniface, const char *outiface,
 		       uint16_t proto, int frag, uint8_t invflags)
 {
-	if (iniface != NULL) {
-		save_iface('i', iniface, iniface_mask,
-			    invflags & IPT_INV_VIA_IN);
-	}
-	if (outiface != NULL) {
-		save_iface('o', outiface, outiface_mask,
-			    invflags & IPT_INV_VIA_OUT);
-	}
+	save_iface('i', iniface, invflags & IPT_INV_VIA_IN);
+	save_iface('o', outiface, invflags & IPT_INV_VIA_OUT);
 
 	if (proto > 0) {
-		const char *pname = proto_to_name(proto, 0);
+		const char *pname = proto_to_name(proto, true);
 
 		if (invflags & XT_INV_PROTO)
 			printf(" !");
@@ -1153,9 +1145,9 @@ int print_match_save(const struct xt_entry_match *e, const void *ip)
 	return 0;
 }
 
-static void
-xtables_printhelp(const struct xtables_rule_match *matches)
+void xtables_printhelp(struct iptables_command_state *cs)
 {
+	const struct xtables_rule_match *matches = cs->matches;
 	const char *prog_name = xt_params->program_name;
 	const char *prog_vers = xt_params->program_version;
 
@@ -1314,6 +1306,7 @@ static void check_inverse(struct xtables_args *args, const char option[],
 {
 	switch (args->family) {
 	case NFPROTO_ARP:
+	case NFPROTO_BRIDGE:
 		break;
 	default:
 		return;
@@ -1367,10 +1360,105 @@ void xtables_clear_iptables_command_state(struct iptables_command_state *cs)
 	}
 }
 
+void iface_to_mask(const char *iface, unsigned char *mask)
+{
+	unsigned int len = strlen(iface);
+
+	memset(mask, 0, IFNAMSIZ);
+
+	if (!len) {
+		return;
+	} else if (iface[len - 1] == '+') {
+		memset(mask, 0xff, len - 1);
+		/* Don't remove `+' here! -HW */
+	} else {
+		/* Include nul-terminator in match */
+		memset(mask, 0xff, len + 1);
+	}
+}
+
+static void parse_interface(const char *arg, char *iface)
+{
+	unsigned int len = strlen(arg);
+
+	memset(iface, 0, IFNAMSIZ);
+
+	if (!len)
+		return;
+	if (len >= IFNAMSIZ)
+		xtables_error(PARAMETER_PROBLEM,
+			      "interface name `%s' must be shorter than %d characters",
+			      arg, IFNAMSIZ);
+
+	if (strchr(arg, '/') || strchr(arg, ' '))
+		fprintf(stderr,
+			"Warning: weird character in interface `%s' ('/' and ' ' are not allowed by the kernel).\n",
+			arg);
+
+	strcpy(iface, arg);
+}
+
+static bool
+parse_signed_counter(char *argv, unsigned long long *val, uint8_t *ctr_op,
+		     uint8_t flag_inc, uint8_t flag_dec)
+{
+	char *endptr, *p = argv;
+
+	switch (*p) {
+	case '+':
+		*ctr_op |= flag_inc;
+		p++;
+		break;
+	case '-':
+		*ctr_op |= flag_dec;
+		p++;
+		break;
+	}
+	*val = strtoull(p, &endptr, 10);
+	return *endptr == '\0';
+}
+
+static void parse_change_counters_rule(int argc, char **argv,
+				       struct xt_cmd_parse *p,
+				       struct xtables_args *args)
+{
+	if (optind + 1 >= argc ||
+	    (argv[optind][0] == '-' && !isdigit(argv[optind][1])) ||
+	    (argv[optind + 1][0] == '-' && !isdigit(argv[optind + 1][1])))
+		xtables_error(PARAMETER_PROBLEM,
+			      "The command -C needs at least 2 arguments");
+	if (optind + 2 < argc &&
+	    (argv[optind + 2][0] != '-' || isdigit(argv[optind + 2][1]))) {
+		if (optind + 3 != argc)
+			xtables_error(PARAMETER_PROBLEM,
+				      "No extra options allowed with -C start_nr[:end_nr] pcnt bcnt");
+		parse_rule_range(p, argv[optind++]);
+	}
+
+	if (!parse_signed_counter(argv[optind++], &args->pcnt_cnt,
+				  &args->counter_op,
+				  CTR_OP_INC_PKTS, CTR_OP_DEC_PKTS) ||
+	    !parse_signed_counter(argv[optind++], &args->bcnt_cnt,
+				  &args->counter_op,
+				  CTR_OP_INC_BYTES, CTR_OP_DEC_BYTES))
+		xtables_error(PARAMETER_PROBLEM,
+			      "Packet counter '%s' invalid", argv[optind - 1]);
+}
+
+static void option_test_and_reject(struct xt_cmd_parse *p,
+				   struct iptables_command_state *cs,
+				   unsigned int option)
+{
+	if (cs->options & option)
+		xtables_error(PARAMETER_PROBLEM, "Can't use %s with %s",
+			      p->ops->option_name(option), p->chain);
+}
+
 void do_parse(int argc, char *argv[],
 	      struct xt_cmd_parse *p, struct iptables_command_state *cs,
 	      struct xtables_args *args)
 {
+	bool family_is_bridge = args->family == NFPROTO_BRIDGE;
 	struct xtables_match *m;
 	struct xtables_rule_match *matchp;
 	bool wait_interval_set = false;
@@ -1396,10 +1484,10 @@ void do_parse(int argc, char *argv[],
 	   demand-load a protocol. */
 	opterr = 0;
 
-	xt_params->opts = xt_params->orig_opts;
 	while ((cs->c = getopt_long(argc, argv,
 				    optstring_lookup(afinfo->family),
-				    xt_params->opts, NULL)) != -1) {
+				    xt_params->opts ?: xt_params->orig_opts,
+				    NULL)) != -1) {
 		switch (cs->c) {
 			/*
 			 * Command selection
@@ -1410,6 +1498,15 @@ void do_parse(int argc, char *argv[],
 			break;
 
 		case 'C':
+			if (family_is_bridge) {
+				add_command(&p->command, CMD_CHANGE_COUNTERS,
+					    CMD_NONE, invert);
+				p->chain = optarg;
+				parse_change_counters_rule(argc, argv, p, args);
+				break;
+			}
+			/* fall through */
+		case 14: /* ebtables --check */
 			add_command(&p->command, CMD_CHECK, CMD_NONE, invert);
 			p->chain = optarg;
 			break;
@@ -1418,7 +1515,7 @@ void do_parse(int argc, char *argv[],
 			add_command(&p->command, CMD_DELETE, CMD_NONE, invert);
 			p->chain = optarg;
 			if (xs_has_arg(argc, argv)) {
-				p->rulenum = parse_rulenumber(argv[optind++]);
+				parse_rule_range(p, argv[optind++]);
 				p->command = CMD_DELETE_NUM;
 			}
 			break;
@@ -1517,27 +1614,28 @@ void do_parse(int argc, char *argv[],
 			break;
 
 		case 'P':
-			add_command(&p->command, CMD_SET_POLICY, CMD_NONE,
+			add_command(&p->command, CMD_SET_POLICY,
+				    family_is_bridge ? CMD_NEW_CHAIN : CMD_NONE,
 				    invert);
-			p->chain = optarg;
-			if (xs_has_arg(argc, argv))
+			if (p->command & CMD_NEW_CHAIN) {
+				p->policy = optarg;
+			} else if (xs_has_arg(argc, argv)) {
+				p->chain = optarg;
 				p->policy = argv[optind++];
-			else
+			} else {
 				xtables_error(PARAMETER_PROBLEM,
 					   "-%c requires a chain and a policy",
 					   cmd2char(CMD_SET_POLICY));
+			}
 			break;
 
 		case 'h':
-			if (!optarg)
-				optarg = argv[optind];
-
 			/* iptables -p icmp -h */
 			if (!cs->matches && cs->protocol)
 				xtables_find_match(cs->protocol,
 					XTF_TRY_LOAD, &cs->matches);
 
-			xtables_printhelp(cs->matches);
+			p->ops->print_help(cs);
 			xtables_clear_iptables_command_state(cs);
 			xtables_free_opts(1);
 			xtables_fini();
@@ -1548,7 +1646,7 @@ void do_parse(int argc, char *argv[],
 			 */
 		case 'p':
 			check_inverse(args, optarg, &invert, argc, argv);
-			set_option(&cs->options, OPT_PROTOCOL,
+			set_option(p->ops, &cs->options, OPT_PROTOCOL,
 				   &args->invflags, invert);
 
 			/* Canonicalize into lower case */
@@ -1557,12 +1655,6 @@ void do_parse(int argc, char *argv[],
 				*cs->protocol = tolower(*cs->protocol);
 
 			cs->protocol = optarg;
-			args->proto = xtables_parse_protocol(cs->protocol);
-
-			if (args->proto == 0 &&
-			    (args->invflags & XT_INV_PROTO))
-				xtables_error(PARAMETER_PROBLEM,
-					   "rule would never match protocol");
 
 			/* This needs to happen here to parse extensions */
 			if (p->ops->proto_parse)
@@ -1571,22 +1663,22 @@ void do_parse(int argc, char *argv[],
 
 		case 's':
 			check_inverse(args, optarg, &invert, argc, argv);
-			set_option(&cs->options, OPT_SOURCE,
+			set_option(p->ops, &cs->options, OPT_SOURCE,
 				   &args->invflags, invert);
 			args->shostnetworkmask = optarg;
 			break;
 
 		case 'd':
 			check_inverse(args, optarg, &invert, argc, argv);
-			set_option(&cs->options, OPT_DESTINATION,
+			set_option(p->ops, &cs->options, OPT_DESTINATION,
 				   &args->invflags, invert);
 			args->dhostnetworkmask = optarg;
 			break;
 
 #ifdef IPT_F_GOTO
 		case 'g':
-			set_option(&cs->options, OPT_JUMP, &args->invflags,
-				   invert);
+			set_option(p->ops, &cs->options, OPT_JUMP,
+				   &args->invflags, invert);
 			args->goto_set = true;
 			cs->jumpto = xt_parse_target(optarg);
 			break;
@@ -1594,22 +1686,22 @@ void do_parse(int argc, char *argv[],
 
 		case 2:/* src-mac */
 			check_inverse(args, optarg, &invert, argc, argv);
-			set_option(&cs->options, OPT_S_MAC, &args->invflags,
-				   invert);
+			set_option(p->ops, &cs->options, OPT_S_MAC,
+				   &args->invflags, invert);
 			args->src_mac = optarg;
 			break;
 
 		case 3:/* dst-mac */
 			check_inverse(args, optarg, &invert, argc, argv);
-			set_option(&cs->options, OPT_D_MAC, &args->invflags,
-				   invert);
+			set_option(p->ops, &cs->options, OPT_D_MAC,
+				   &args->invflags, invert);
 			args->dst_mac = optarg;
 			break;
 
 		case 'l':/* hardware length */
 			check_inverse(args, optarg, &invert, argc, argv);
-			set_option(&cs->options, OPT_H_LENGTH, &args->invflags,
-				   invert);
+			set_option(p->ops, &cs->options, OPT_H_LENGTH,
+				   &args->invflags, invert);
 			args->arp_hlen = optarg;
 			break;
 
@@ -1617,49 +1709,85 @@ void do_parse(int argc, char *argv[],
 			xtables_error(PARAMETER_PROBLEM, "not supported");
 		case 4:/* opcode */
 			check_inverse(args, optarg, &invert, argc, argv);
-			set_option(&cs->options, OPT_OPCODE, &args->invflags,
-				   invert);
+			set_option(p->ops, &cs->options, OPT_OPCODE,
+				   &args->invflags, invert);
 			args->arp_opcode = optarg;
 			break;
 
 		case 5:/* h-type */
 			check_inverse(args, optarg, &invert, argc, argv);
-			set_option(&cs->options, OPT_H_TYPE, &args->invflags,
-				   invert);
+			set_option(p->ops, &cs->options, OPT_H_TYPE,
+				   &args->invflags, invert);
 			args->arp_htype = optarg;
 			break;
 
 		case 6:/* proto-type */
 			check_inverse(args, optarg, &invert, argc, argv);
-			set_option(&cs->options, OPT_P_TYPE, &args->invflags,
-				   invert);
+			set_option(p->ops, &cs->options, OPT_P_TYPE,
+				   &args->invflags, invert);
 			args->arp_ptype = optarg;
 			break;
 
+		case 11: /* ebtables --init-table */
+			if (p->restore)
+				xtables_error(PARAMETER_PROBLEM,
+					      "--init-table is not supported in daemon mode");
+			add_command(&p->command, CMD_INIT_TABLE, CMD_NONE, invert);
+			break;
+
+		case 12 : /* ebtables --Lmac2 */
+			set_option(p->ops, &cs->options, OPT_LIST_MAC2,
+				   &args->invflags, invert);
+			break;
+
+		case 13 : /* ebtables --concurrent */
+			break;
+
+		case 15 : /* ebtables --logical-in */
+			check_inverse(args, optarg, &invert, argc, argv);
+			set_option(p->ops, &cs->options, OPT_LOGICALIN,
+				   &args->invflags, invert);
+			parse_interface(optarg, args->bri_iniface);
+			break;
+
+		case 16 : /* ebtables --logical-out */
+			check_inverse(args, optarg, &invert, argc, argv);
+			set_option(p->ops, &cs->options, OPT_LOGICALOUT,
+				   &args->invflags, invert);
+			parse_interface(optarg, args->bri_outiface);
+			break;
+
+		case 17 : /* ebtables --Lc */
+			set_option(p->ops, &cs->options, OPT_LIST_C,
+				   &args->invflags, invert);
+			break;
+
+		case 19 : /* ebtables --Lx */
+			set_option(p->ops, &cs->options, OPT_LIST_X,
+				   &args->invflags, invert);
+			break;
+
 		case 'j':
-			set_option(&cs->options, OPT_JUMP, &args->invflags,
-				   invert);
-			command_jump(cs, optarg);
+			set_option(p->ops, &cs->options, OPT_JUMP,
+				   &args->invflags, invert);
+			if (strcmp(optarg, "CONTINUE"))
+				command_jump(cs, optarg);
 			break;
 
 		case 'i':
 			check_empty_interface(args, optarg);
 			check_inverse(args, optarg, &invert, argc, argv);
-			set_option(&cs->options, OPT_VIANAMEIN,
+			set_option(p->ops, &cs->options, OPT_VIANAMEIN,
 				   &args->invflags, invert);
-			xtables_parse_interface(optarg,
-						args->iniface,
-						args->iniface_mask);
+			parse_interface(optarg, args->iniface);
 			break;
 
 		case 'o':
 			check_empty_interface(args, optarg);
 			check_inverse(args, optarg, &invert, argc, argv);
-			set_option(&cs->options, OPT_VIANAMEOUT,
+			set_option(p->ops, &cs->options, OPT_VIANAMEOUT,
 				   &args->invflags, invert);
-			xtables_parse_interface(optarg,
-						args->outiface,
-						args->outiface_mask);
+			parse_interface(optarg, args->outiface);
 			break;
 
 		case 'f':
@@ -1668,14 +1796,14 @@ void do_parse(int argc, char *argv[],
 					"`-f' is not supported in IPv6, "
 					"use -m frag instead");
 			}
-			set_option(&cs->options, OPT_FRAGMENT, &args->invflags,
-				   invert);
+			set_option(p->ops, &cs->options, OPT_FRAGMENT,
+				   &args->invflags, invert);
 			args->flags |= IPT_F_FRAG;
 			break;
 
 		case 'v':
 			if (!p->verbose)
-				set_option(&cs->options, OPT_VERBOSE,
+				set_option(p->ops, &cs->options, OPT_VERBOSE,
 					   &args->invflags, invert);
 			p->verbose++;
 			break;
@@ -1685,8 +1813,8 @@ void do_parse(int argc, char *argv[],
 			break;
 
 		case 'n':
-			set_option(&cs->options, OPT_NUMERIC, &args->invflags,
-				   invert);
+			set_option(p->ops, &cs->options, OPT_NUMERIC,
+				   &args->invflags, invert);
 			break;
 
 		case 't':
@@ -1702,8 +1830,8 @@ void do_parse(int argc, char *argv[],
 			break;
 
 		case 'x':
-			set_option(&cs->options, OPT_EXPANDED, &args->invflags,
-				   invert);
+			set_option(p->ops, &cs->options, OPT_EXPANDED,
+				   &args->invflags, invert);
 			break;
 
 		case 'V':
@@ -1738,7 +1866,8 @@ void do_parse(int argc, char *argv[],
 			break;
 
 		case '0':
-			set_option(&cs->options, OPT_LINENUMBERS,
+		case 18 : /* ebtables --Ln */
+			set_option(p->ops, &cs->options, OPT_LINENUMBERS,
 				   &args->invflags, invert);
 			break;
 
@@ -1747,28 +1876,28 @@ void do_parse(int argc, char *argv[],
 			break;
 
 		case 'c':
-			set_option(&cs->options, OPT_COUNTERS, &args->invflags,
-				   invert);
+			set_option(p->ops, &cs->options, OPT_COUNTERS,
+				   &args->invflags, invert);
 			args->pcnt = optarg;
-			args->bcnt = strchr(args->pcnt + 1, ',');
+			args->bcnt = strchr(args->pcnt, ',');
 			if (args->bcnt)
 			    args->bcnt++;
 			if (!args->bcnt && xs_has_arg(argc, argv))
 				args->bcnt = argv[optind++];
 			if (!args->bcnt)
 				xtables_error(PARAMETER_PROBLEM,
-					"-%c requires packet and byte counter",
-					opt2char(OPT_COUNTERS));
+					      "%s requires packet and byte counter",
+					      p->ops->option_name(OPT_COUNTERS));
 
 			if (sscanf(args->pcnt, "%llu", &args->pcnt_cnt) != 1)
 				xtables_error(PARAMETER_PROBLEM,
-					"-%c packet counter not numeric",
-					opt2char(OPT_COUNTERS));
+					      "%s packet counter not numeric",
+					      p->ops->option_name(OPT_COUNTERS));
 
 			if (sscanf(args->bcnt, "%llu", &args->bcnt_cnt) != 1)
 				xtables_error(PARAMETER_PROBLEM,
-					"-%c byte counter not numeric",
-					opt2char(OPT_COUNTERS));
+					      "%s byte counter not numeric",
+					      p->ops->option_name(OPT_COUNTERS));
 			break;
 
 		case '4':
@@ -1803,7 +1932,8 @@ void do_parse(int argc, char *argv[],
 			exit_tryhelp(2, p->line);
 
 		default:
-			if (command_default(cs, xt_params, invert))
+			check_inverse(args, optarg, &invert, argc, argv);
+			if (p->ops->command_default(cs, xt_params, invert))
 				/* cf. ip6tables.c */
 				continue;
 			break;
@@ -1811,7 +1941,8 @@ void do_parse(int argc, char *argv[],
 		invert = false;
 	}
 
-	if (strcmp(p->table, "nat") == 0 &&
+	if (!family_is_bridge &&
+	    strcmp(p->table, "nat") == 0 &&
 	    ((p->policy != NULL && strcmp(p->policy, "DROP") == 0) ||
 	    (cs->jumpto != NULL && strcmp(cs->jumpto, "DROP") == 0)))
 		xtables_error(PARAMETER_PROBLEM,
@@ -1841,12 +1972,7 @@ void do_parse(int argc, char *argv[],
 	if (p->ops->post_parse)
 		p->ops->post_parse(p->command, cs, args);
 
-	if (p->command == CMD_REPLACE &&
-	    (args->s.naddrs != 1 || args->d.naddrs != 1))
-		xtables_error(PARAMETER_PROBLEM, "Replacement rule does not "
-			   "specify a unique address");
-
-	generic_opt_check(p->command, cs->options);
+	generic_opt_check(p->ops, p->command, cs->options);
 
 	if (p->chain != NULL && strlen(p->chain) >= XT_EXTENSION_MAXNAMELEN)
 		xtables_error(PARAMETER_PROBLEM,
@@ -1855,28 +1981,24 @@ void do_parse(int argc, char *argv[],
 
 	if (p->command == CMD_APPEND ||
 	    p->command == CMD_DELETE ||
-	    p->command == CMD_DELETE_NUM ||
 	    p->command == CMD_CHECK ||
 	    p->command == CMD_INSERT ||
-	    p->command == CMD_REPLACE) {
+	    p->command == CMD_REPLACE ||
+	    p->command == CMD_CHANGE_COUNTERS) {
 		if (strcmp(p->chain, "PREROUTING") == 0
 		    || strcmp(p->chain, "INPUT") == 0) {
 			/* -o not valid with incoming packets. */
-			if (cs->options & OPT_VIANAMEOUT)
-				xtables_error(PARAMETER_PROBLEM,
-					   "Can't use -%c with %s\n",
-					   opt2char(OPT_VIANAMEOUT),
-					   p->chain);
+			option_test_and_reject(p, cs, OPT_VIANAMEOUT);
+			/* same with --logical-out */
+			option_test_and_reject(p, cs, OPT_LOGICALOUT);
 		}
 
 		if (strcmp(p->chain, "POSTROUTING") == 0
 		    || strcmp(p->chain, "OUTPUT") == 0) {
 			/* -i not valid with outgoing packets */
-			if (cs->options & OPT_VIANAMEIN)
-				xtables_error(PARAMETER_PROBLEM,
-					   "Can't use -%c with %s\n",
-					   opt2char(OPT_VIANAMEIN),
-					   p->chain);
+			option_test_and_reject(p, cs, OPT_VIANAMEIN);
+			/* same with --logical-in */
+			option_test_and_reject(p, cs, OPT_LOGICALIN);
 		}
 	}
 }
@@ -1884,7 +2006,13 @@ void do_parse(int argc, char *argv[],
 void ipv4_proto_parse(struct iptables_command_state *cs,
 		      struct xtables_args *args)
 {
-	cs->fw.ip.proto = args->proto;
+	cs->fw.ip.proto = xtables_parse_protocol(cs->protocol);
+
+	if (cs->fw.ip.proto == 0 &&
+	    (args->invflags & XT_INV_PROTO))
+		xtables_error(PARAMETER_PROBLEM,
+			      "rule would never match protocol");
+
 	cs->fw.ip.invflags = args->invflags;
 }
 
@@ -1900,7 +2028,13 @@ static int is_exthdr(uint16_t proto)
 void ipv6_proto_parse(struct iptables_command_state *cs,
 		      struct xtables_args *args)
 {
-	cs->fw6.ipv6.proto = args->proto;
+	cs->fw6.ipv6.proto = xtables_parse_protocol(cs->protocol);
+
+	if (cs->fw6.ipv6.proto == 0 &&
+	    (args->invflags & XT_INV_PROTO))
+		xtables_error(PARAMETER_PROBLEM,
+			      "rule would never match protocol");
+
 	cs->fw6.ipv6.invflags = args->invflags;
 
 	/* this is needed for ip6tables-legacy only */
@@ -1925,12 +2059,7 @@ void ipv4_post_parse(int command, struct iptables_command_state *cs,
 	cs->fw.ip.invflags = args->invflags;
 
 	memcpy(cs->fw.ip.iniface, args->iniface, IFNAMSIZ);
-	memcpy(cs->fw.ip.iniface_mask,
-	       args->iniface_mask, IFNAMSIZ*sizeof(unsigned char));
-
 	memcpy(cs->fw.ip.outiface, args->outiface, IFNAMSIZ);
-	memcpy(cs->fw.ip.outiface_mask,
-	       args->outiface_mask, IFNAMSIZ*sizeof(unsigned char));
 
 	if (args->goto_set)
 		cs->fw.ip.flags |= IPT_F_GOTO;
@@ -1975,12 +2104,7 @@ void ipv6_post_parse(int command, struct iptables_command_state *cs,
 	cs->fw6.ipv6.invflags = args->invflags;
 
 	memcpy(cs->fw6.ipv6.iniface, args->iniface, IFNAMSIZ);
-	memcpy(cs->fw6.ipv6.iniface_mask,
-	       args->iniface_mask, IFNAMSIZ*sizeof(unsigned char));
-
 	memcpy(cs->fw6.ipv6.outiface, args->outiface, IFNAMSIZ);
-	memcpy(cs->fw6.ipv6.outiface_mask,
-	       args->outiface_mask, IFNAMSIZ*sizeof(unsigned char));
 
 	if (args->goto_set)
 		cs->fw6.ipv6.flags |= IP6T_F_GOTO;
@@ -2050,3 +2174,11 @@ make_delete_mask(const struct xtables_rule_match *matches,
 
 	return mask;
 }
+
+void xtables_clear_args(struct xtables_args *args)
+{
+	free(args->s.addr.ptr);
+	free(args->s.mask.ptr);
+	free(args->d.addr.ptr);
+	free(args->d.mask.ptr);
+}
diff --git a/iptables/xshared.h b/iptables/xshared.h
index a200e0d6..af756738 100644
--- a/iptables/xshared.h
+++ b/iptables/xshared.h
@@ -47,9 +47,11 @@ enum {
 	/* below are for ebtables only */
 	OPT_LOGICALIN	= 1 << 18,
 	OPT_LOGICALOUT	= 1 << 19,
-	OPT_COMMAND	= 1 << 20,
-	OPT_ZERO	= 1 << 21,
+	OPT_LIST_C	= 1 << 20,
+	OPT_LIST_X	= 1 << 21,
+	OPT_LIST_MAC2	= 1 << 22,
 };
+#define NUMBER_OF_OPT	24
 
 enum {
 	CMD_NONE		= 0,
@@ -68,19 +70,23 @@ enum {
 	CMD_LIST_RULES		= 1 << 12,
 	CMD_ZERO_NUM		= 1 << 13,
 	CMD_CHECK		= 1 << 14,
+	CMD_CHANGE_COUNTERS	= 1 << 15, /* ebtables only */
+	CMD_INIT_TABLE		= 1 << 16, /* ebtables only */
 };
-#define NUMBER_OF_CMD		16
+#define NUMBER_OF_CMD		18
 
 struct xtables_globals;
 struct xtables_rule_match;
 struct xtables_target;
 
-#define OPTSTRING_COMMON "-:A:C:D:E:F::I:L::M:N:P:VX::Z::" "c:d:i:j:o:p:s:t:"
-#define IPT_OPTSTRING	OPTSTRING_COMMON "R:S::W::" "46bfg:h::m:nvw::x"
-#define ARPT_OPTSTRING	OPTSTRING_COMMON "R:S::" "h::l:nvx" /* "m:" */
-#define EBT_OPTSTRING	OPTSTRING_COMMON "hv"
+#define OPTSTRING_COMMON "-:A:C:D:E:F::I:L::M:N:P:R:S::VX::Z::" "c:d:i:j:o:p:s:t:v"
+#define IPT_OPTSTRING	OPTSTRING_COMMON "W::" "46fg:h::m:nw::x"
+#define ARPT_OPTSTRING	OPTSTRING_COMMON "h::l:nx" /* "m:" */
+#define EBT_OPTSTRING	OPTSTRING_COMMON "h"
 
-/* define invflags which won't collide with IPT ones */
+/* define invflags which won't collide with IPT ones.
+ * arptables-nft does NOT use the legacy ARPT_INV_* defines.
+ */
 #define IPT_INV_SRCDEVADDR	0x0080
 #define IPT_INV_TGTDEVADDR	0x0100
 #define IPT_INV_ARPHLN		0x0200
@@ -133,6 +139,7 @@ struct iptables_command_state {
 	char *protocol;
 	int proto_used;
 	const char *jumpto;
+	int argc;
 	char **argv;
 	bool restore;
 };
@@ -209,8 +216,6 @@ void save_ipv6_addr(char letter, const struct in6_addr *addr,
 
 void print_ifaces(const char *iniface, const char *outiface, uint8_t invflags,
 		  unsigned int format);
-void save_iface(char letter, const char *iface,
-		const unsigned char *mask, int invert);
 
 void print_fragment(unsigned int flags, unsigned int invflags,
 		    unsigned int format, bool fake);
@@ -222,8 +227,7 @@ void assert_valid_chain_name(const char *chainname);
 void print_rule_details(unsigned int linenum, const struct xt_counters *ctrs,
 			const char *targname, uint8_t proto, uint8_t flags,
 			uint8_t invflags, unsigned int format);
-void save_rule_details(const char *iniface, unsigned const char *iniface_mask,
-		       const char *outiface, unsigned const char *outiface_mask,
+void save_rule_details(const char *iniface, const char *outiface,
 		       uint16_t proto, int frag, uint8_t invflags);
 
 int print_match_save(const struct xt_entry_match *e, const void *ip);
@@ -246,13 +250,19 @@ struct addr_mask {
 	} mask;
 };
 
+enum {
+	CTR_OP_INC_PKTS = 1 << 0,
+	CTR_OP_DEC_PKTS = 1 << 1,
+	CTR_OP_INC_BYTES = 1 << 2,
+	CTR_OP_DEC_BYTES = 1 << 3,
+};
+
 struct xtables_args {
 	int		family;
-	uint16_t	proto;
 	uint8_t		flags;
 	uint16_t	invflags;
 	char		iniface[IFNAMSIZ], outiface[IFNAMSIZ];
-	unsigned char	iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];
+	char		bri_iniface[IFNAMSIZ], bri_outiface[IFNAMSIZ];
 	bool		goto_set;
 	const char	*shostnetworkmask, *dhostnetworkmask;
 	const char	*pcnt, *bcnt;
@@ -261,6 +271,7 @@ struct xtables_args {
 	const char	*arp_hlen, *arp_opcode;
 	const char	*arp_htype, *arp_ptype;
 	unsigned long long pcnt_cnt, bcnt_cnt;
+	uint8_t		counter_op;
 	int		wait;
 };
 
@@ -270,11 +281,17 @@ struct xt_cmd_parse_ops {
 	void	(*post_parse)(int command,
 			      struct iptables_command_state *cs,
 			      struct xtables_args *args);
+	const char *(*option_name)(int option);
+	int	(*option_invert)(int option);
+	int	(*command_default)(struct iptables_command_state *cs,
+				   struct xtables_globals *gl, bool invert);
+	void	(*print_help)(struct iptables_command_state *cs);
 };
 
 struct xt_cmd_parse {
 	unsigned int			command;
 	unsigned int			rulenum;
+	unsigned int			rulenum_end;
 	char				*table;
 	const char			*chain;
 	const char			*newname;
@@ -282,10 +299,16 @@ struct xt_cmd_parse {
 	bool				restore;
 	int				line;
 	int				verbose;
-	bool				xlate;
+	bool				rule_ranges;
 	struct xt_cmd_parse_ops		*ops;
 };
 
+void xtables_printhelp(struct iptables_command_state *cs);
+const char *ip46t_option_name(int option);
+int ip46t_option_invert(int option);
+int command_default(struct iptables_command_state *cs,
+		    struct xtables_globals *gl, bool invert);
+
 void do_parse(int argc, char *argv[],
 	      struct xt_cmd_parse *p, struct iptables_command_state *cs,
 	      struct xtables_args *args);
@@ -306,4 +329,10 @@ unsigned char *make_delete_mask(const struct xtables_rule_match *matches,
 				const struct xtables_target *target,
 				size_t entry_size);
 
+void iface_to_mask(const char *ifname, unsigned char *mask);
+
+void xtables_clear_args(struct xtables_args *args);
+
+const char *proto_to_name(uint16_t proto, int nolookup);
+
 #endif /* IPTABLES_XSHARED_H */
diff --git a/iptables/xtables-eb-translate.c b/iptables/xtables-eb-translate.c
index da7e5e3d..fbeff74f 100644
--- a/iptables/xtables-eb-translate.c
+++ b/iptables/xtables-eb-translate.c
@@ -21,61 +21,10 @@
 #include "nft-bridge.h"
 #include "nft.h"
 #include "nft-shared.h"
-/*
- * From include/ebtables_u.h
- */
-#define ebt_check_option2(flags, mask) EBT_CHECK_OPTION(flags, mask)
 
-extern int ebt_invert;
-
-static int ebt_check_inverse2(const char option[], int argc, char **argv)
-{
-	if (!option)
-		return ebt_invert;
-	if (strcmp(option, "!") == 0) {
-		if (ebt_invert == 1)
-			xtables_error(PARAMETER_PROBLEM,
-				      "Double use of '!' not allowed");
-		if (optind >= argc)
-			optarg = NULL;
-		else
-			optarg = argv[optind];
-		optind++;
-		ebt_invert = 1;
-		return 1;
-	}
-	return ebt_invert;
-}
-
-/*
- * Glue code to use libxtables
- */
-static int parse_rule_number(const char *rule)
-{
-	unsigned int rule_nr;
-
-	if (!xtables_strtoui(rule, NULL, &rule_nr, 1, INT_MAX))
-		xtables_error(PARAMETER_PROBLEM,
-			      "Invalid rule number `%s'", rule);
-
-	return rule_nr;
-}
-
-/*
- * The original ebtables parser
- */
-
-/* Checks whether a command has already been specified */
-#define OPT_COMMANDS (flags & OPT_COMMAND || flags & OPT_ZERO)
-
-/* Default command line options. Do not mess around with the already
- * assigned numbers unless you know what you are doing */
-extern struct option ebt_original_options[];
-#define opts ebtables_globals.opts
 #define prog_name ebtables_globals.program_name
-#define prog_vers ebtables_globals.program_version
 
-static void print_help(void)
+static void print_help(struct iptables_command_state *cs)
 {
 	fprintf(stderr, "%s: Translate ebtables command to nft syntax\n"
 			"no side effects occur, the translated command is written "
@@ -85,46 +34,6 @@ static void print_help(void)
 	exit(0);
 }
 
-static int parse_rule_range(const char *argv, int *rule_nr, int *rule_nr_end)
-{
-	char *colon = strchr(argv, ':'), *buffer;
-
-	if (colon) {
-		*colon = '\0';
-		if (*(colon + 1) == '\0')
-			*rule_nr_end = -1; /* Until the last rule */
-		else {
-			*rule_nr_end = strtol(colon + 1, &buffer, 10);
-			if (*buffer != '\0' || *rule_nr_end == 0)
-				return -1;
-		}
-	}
-	if (colon == argv)
-		*rule_nr = 1; /* Beginning with the first rule */
-	else {
-		*rule_nr = strtol(argv, &buffer, 10);
-		if (*buffer != '\0' || *rule_nr == 0)
-			return -1;
-	}
-	if (!colon)
-		*rule_nr_end = *rule_nr;
-	return 0;
-}
-
-static void ebtables_parse_interface(const char *arg, char *vianame)
-{
-	unsigned char mask[IFNAMSIZ];
-	char *c;
-
-	xtables_parse_interface(arg, vianame, mask);
-
-	if ((c = strchr(vianame, '+'))) {
-		if (*(c + 1) != '\0')
-			xtables_error(PARAMETER_PROBLEM,
-				      "Spurious characters after '+' wildcard");
-	}
-}
-
 static void print_ebt_cmd(int argc, char *argv[])
 {
 	int i;
@@ -158,362 +67,88 @@ static int nft_rule_eb_xlate_add(struct nft_handle *h, const struct xt_cmd_parse
 
 static int do_commandeb_xlate(struct nft_handle *h, int argc, char *argv[], char **table)
 {
-	char *buffer;
-	int c, i;
-	int rule_nr = 0;
-	int rule_nr_end = 0;
-	int ret = 0;
-	unsigned int flags = 0;
 	struct iptables_command_state cs = {
 		.argv		= argv,
+		.jumpto		= "",
 		.eb.bitmask	= EBT_NOPROTO,
 	};
-	char command = 'h';
-	const char *chain = NULL;
-	int selected_chain = -1;
-	struct xtables_rule_match *xtrm_i;
-	struct ebt_match *match;
 	struct xt_cmd_parse p = {
 		.table          = *table,
+		.rule_ranges	= true,
+		.ops		= &h->ops->cmd_parse,
         };
-	bool table_set = false;
-
-	/* prevent getopt to spoil our error reporting */
-	opterr = false;
-
-	printf("nft ");
-	/* Getopt saves the day */
-	while ((c = getopt_long(argc, argv,
-	   "-:A:D:I:N:E:X::L::Z::F::P:Vhi:o:j:c:p:s:d:t:M:", opts, NULL)) != -1) {
-		cs.c = c;
-		switch (c) {
-		case 'A': /* Add a rule */
-		case 'D': /* Delete a rule */
-		case 'P': /* Define policy */
-		case 'I': /* Insert a rule */
-		case 'N': /* Make a user defined chain */
-		case 'E': /* Rename chain */
-		case 'X': /* Delete chain */
-			/* We allow -N chainname -P policy */
-			/* XXX: Not in ebtables-compat */
-			if (command == 'N' && c == 'P') {
-				command = c;
-				optind--; /* No table specified */
-				break;
-			}
-			if (OPT_COMMANDS)
-				xtables_error(PARAMETER_PROBLEM,
-					      "Multiple commands are not allowed");
-			command = c;
-			chain = optarg;
-			selected_chain = ebt_get_current_chain(chain);
-			p.chain = chain;
-			flags |= OPT_COMMAND;
-
-			if (c == 'N') {
-				printf("add chain bridge %s %s\n", p.table, p.chain);
-				ret = 1;
-				break;
-			} else if (c == 'X') {
-				printf("delete chain bridge %s %s\n", p.table, p.chain);
-				ret = 1;
-				break;
-			}
-
-			if (c == 'E') {
-				break;
-			} else if (c == 'D' && optind < argc && (argv[optind][0] != '-' || (argv[optind][1] >= '0' && argv[optind][1] <= '9'))) {
-				if (optind != argc - 1)
-					xtables_error(PARAMETER_PROBLEM,
-							 "No extra options allowed with -D start_nr[:end_nr]");
-				if (parse_rule_range(argv[optind], &rule_nr, &rule_nr_end))
-					xtables_error(PARAMETER_PROBLEM,
-							 "Problem with the specified rule number(s) '%s'", argv[optind]);
-				optind++;
-			} else if (c == 'I') {
-				if (optind >= argc || (argv[optind][0] == '-' && (argv[optind][1] < '0' || argv[optind][1] > '9')))
-					rule_nr = 1;
-				else {
-					rule_nr = parse_rule_number(argv[optind]);
-					optind++;
-				}
-				p.rulenum = rule_nr;
-			} else if (c == 'P') {
-				break;
-			}
-			break;
-		case 'L': /* List */
-			printf("list table bridge %s\n", p.table);
-			ret = 1;
-			break;
-		case 'F': /* Flush */
-		case 'Z': /* Zero counters */
-			if (c == 'Z') {
-				if ((flags & OPT_ZERO) || (flags & OPT_COMMAND && command != 'L'))
-print_zero:
-					xtables_error(PARAMETER_PROBLEM,
-						      "Command -Z only allowed together with command -L");
-				flags |= OPT_ZERO;
-			} else {
-				if (flags & OPT_COMMAND)
-					xtables_error(PARAMETER_PROBLEM,
-						      "Multiple commands are not allowed");
-				command = c;
-				flags |= OPT_COMMAND;
-				if (flags & OPT_ZERO && c != 'L')
-					goto print_zero;
-			}
-			break;
-		case 'V': /* Version */
-			if (OPT_COMMANDS)
-				xtables_error(PARAMETER_PROBLEM,
-					      "Multiple commands are not allowed");
-			printf("%s %s\n", prog_name, prog_vers);
-			exit(0);
-		case 'h':
-			if (OPT_COMMANDS)
-				xtables_error(PARAMETER_PROBLEM,
-					      "Multiple commands are not allowed");
-			print_help();
-			break;
-		case 't': /* Table */
-			if (OPT_COMMANDS)
-				xtables_error(PARAMETER_PROBLEM,
-					      "Please put the -t option first");
-			if (table_set)
-				xtables_error(PARAMETER_PROBLEM,
-					      "Multiple use of same option not allowed");
-			if (strlen(optarg) > EBT_TABLE_MAXNAMELEN - 1)
-				xtables_error(PARAMETER_PROBLEM,
-					      "Table name length cannot exceed %d characters",
-					      EBT_TABLE_MAXNAMELEN - 1);
-			*table = optarg;
-			p.table = optarg;
-			table_set = true;
-			break;
-		case 'i': /* Input interface */
-		case 2  : /* Logical input interface */
-		case 'o': /* Output interface */
-		case 3  : /* Logical output interface */
-		case 'j': /* Target */
-		case 'p': /* Net family protocol */
-		case 's': /* Source mac */
-		case 'd': /* Destination mac */
-		case 'c': /* Set counters */
-			if (!OPT_COMMANDS)
-				xtables_error(PARAMETER_PROBLEM,
-					      "No command specified");
-			if (command != 'A' && command != 'D' && command != 'I')
-				xtables_error(PARAMETER_PROBLEM,
-					      "Command and option do not match");
-			if (c == 'i') {
-				ebt_check_option2(&flags, OPT_VIANAMEIN);
-				if (selected_chain > 2 && selected_chain < NF_BR_BROUTING)
-					xtables_error(PARAMETER_PROBLEM,
-						      "Use -i only in INPUT, FORWARD, PREROUTING and BROUTING chains");
-				if (ebt_check_inverse2(optarg, argc, argv))
-					cs.eb.invflags |= EBT_IIN;
-
-				ebtables_parse_interface(optarg, cs.eb.in);
-				break;
-			} else if (c == 2) {
-				ebt_check_option2(&flags, OPT_LOGICALIN);
-				if (selected_chain > 2 && selected_chain < NF_BR_BROUTING)
-					xtables_error(PARAMETER_PROBLEM,
-						      "Use --logical-in only in INPUT, FORWARD, PREROUTING and BROUTING chains");
-				if (ebt_check_inverse2(optarg, argc, argv))
-					cs.eb.invflags |= EBT_ILOGICALIN;
-
-				ebtables_parse_interface(optarg, cs.eb.logical_in);
-				break;
-			} else if (c == 'o') {
-				ebt_check_option2(&flags, OPT_VIANAMEOUT);
-				if (selected_chain < 2 || selected_chain == NF_BR_BROUTING)
-					xtables_error(PARAMETER_PROBLEM,
-						      "Use -o only in OUTPUT, FORWARD and POSTROUTING chains");
-				if (ebt_check_inverse2(optarg, argc, argv))
-					cs.eb.invflags |= EBT_IOUT;
-
-				ebtables_parse_interface(optarg, cs.eb.out);
-				break;
-			} else if (c == 3) {
-				ebt_check_option2(&flags, OPT_LOGICALOUT);
-				if (selected_chain < 2 || selected_chain == NF_BR_BROUTING)
-					xtables_error(PARAMETER_PROBLEM,
-						      "Use --logical-out only in OUTPUT, FORWARD and POSTROUTING chains");
-				if (ebt_check_inverse2(optarg, argc, argv))
-					cs.eb.invflags |= EBT_ILOGICALOUT;
-
-				ebtables_parse_interface(optarg, cs.eb.logical_out);
-				break;
-			} else if (c == 'j') {
-				ebt_check_option2(&flags, OPT_JUMP);
-				if (strcmp(optarg, "CONTINUE") != 0) {
-					command_jump(&cs, optarg);
-				}
-				break;
-			} else if (c == 's') {
-				ebt_check_option2(&flags, OPT_SOURCE);
-				if (ebt_check_inverse2(optarg, argc, argv))
-					cs.eb.invflags |= EBT_ISOURCE;
-
-				if (xtables_parse_mac_and_mask(optarg,
-							       cs.eb.sourcemac,
-							       cs.eb.sourcemsk))
-					xtables_error(PARAMETER_PROBLEM, "Problem with specified source mac '%s'", optarg);
-				cs.eb.bitmask |= EBT_SOURCEMAC;
-				break;
-			} else if (c == 'd') {
-				ebt_check_option2(&flags, OPT_DESTINATION);
-				if (ebt_check_inverse2(optarg, argc, argv))
-					cs.eb.invflags |= EBT_IDEST;
-
-				if (xtables_parse_mac_and_mask(optarg,
-							       cs.eb.destmac,
-							       cs.eb.destmsk))
-					xtables_error(PARAMETER_PROBLEM, "Problem with specified destination mac '%s'", optarg);
-				cs.eb.bitmask |= EBT_DESTMAC;
-				break;
-			} else if (c == 'c') {
-				ebt_check_option2(&flags, OPT_COUNTERS);
-				if (ebt_check_inverse2(optarg, argc, argv))
-					xtables_error(PARAMETER_PROBLEM,
-						      "Unexpected '!' after -c");
-				if (optind >= argc || optarg[0] == '-' || argv[optind][0] == '-')
-					xtables_error(PARAMETER_PROBLEM,
-						      "Option -c needs 2 arguments");
-
-				cs.counters.pcnt = strtoull(optarg, &buffer, 10);
-				if (*buffer != '\0')
-					xtables_error(PARAMETER_PROBLEM,
-						      "Packet counter '%s' invalid",
-						      optarg);
-				cs.counters.bcnt = strtoull(argv[optind], &buffer, 10);
-				if (*buffer != '\0')
-					xtables_error(PARAMETER_PROBLEM,
-						      "Packet counter '%s' invalid",
-						      argv[optind]);
-				optind++;
-				break;
-			}
-			ebt_check_option2(&flags, OPT_PROTOCOL);
-			if (ebt_check_inverse2(optarg, argc, argv))
-				cs.eb.invflags |= EBT_IPROTO;
-
-			cs.eb.bitmask &= ~((unsigned int)EBT_NOPROTO);
-			i = strtol(optarg, &buffer, 16);
-			if (*buffer == '\0' && (i < 0 || i > 0xFFFF))
-				xtables_error(PARAMETER_PROBLEM,
-					      "Problem with the specified protocol");
-			if (*buffer != '\0') {
-				struct xt_ethertypeent *ent;
+	struct xtables_args args = {
+		.family	= h->family,
+	};
+	int ret = 0;
 
-				if (!strcasecmp(optarg, "LENGTH")) {
-					cs.eb.bitmask |= EBT_802_3;
-					break;
-				}
-				ent = xtables_getethertypebyname(optarg);
-				if (!ent)
-					xtables_error(PARAMETER_PROBLEM,
-						      "Problem with the specified Ethernet protocol '%s', perhaps "XT_PATH_ETHERTYPES " is missing", optarg);
-				cs.eb.ethproto = ent->e_ethertype;
-			} else
-				cs.eb.ethproto = i;
+	p.ops->print_help = print_help;
 
-			if (cs.eb.ethproto < 0x0600)
-				xtables_error(PARAMETER_PROBLEM,
-					      "Sorry, protocols have values above or equal to 0x0600");
-			break;
-		case 4  : /* Lc */
-			ebt_check_option2(&flags, LIST_C);
-			if (command != 'L')
-				xtables_error(PARAMETER_PROBLEM,
-					      "Use --Lc with -L");
-			flags |= LIST_C;
-			break;
-		case 5  : /* Ln */
-			ebt_check_option2(&flags, LIST_N);
-			if (command != 'L')
-				xtables_error(PARAMETER_PROBLEM,
-					      "Use --Ln with -L");
-			if (flags & LIST_X)
-				xtables_error(PARAMETER_PROBLEM,
-					      "--Lx is not compatible with --Ln");
-			flags |= LIST_N;
-			break;
-		case 6  : /* Lx */
-			ebt_check_option2(&flags, LIST_X);
-			if (command != 'L')
-				xtables_error(PARAMETER_PROBLEM,
-					      "Use --Lx with -L");
-			if (flags & LIST_N)
-				xtables_error(PARAMETER_PROBLEM,
-					      "--Lx is not compatible with --Ln");
-			flags |= LIST_X;
-			break;
-		case 12 : /* Lmac2 */
-			ebt_check_option2(&flags, LIST_MAC2);
-			if (command != 'L')
-				xtables_error(PARAMETER_PROBLEM,
-					       "Use --Lmac2 with -L");
-			flags |= LIST_MAC2;
-			break;
-		case 1 :
-			if (!strcmp(optarg, "!"))
-				ebt_check_inverse2(optarg, argc, argv);
-			else
-				xtables_error(PARAMETER_PROBLEM,
-					      "Bad argument : '%s'", optarg);
-			/* ebt_ebt_check_inverse2() did optind++ */
-			optind--;
-			continue;
-		default:
-			ebt_check_inverse2(optarg, argc, argv);
-			ebt_command_default(&cs);
+	do_parse(argc, argv, &p, &cs, &args);
 
-			if (command != 'A' && command != 'I' &&
-			    command != 'D')
-				xtables_error(PARAMETER_PROBLEM,
-					      "Extensions only for -A, -I, -D");
-		}
-		ebt_invert = 0;
-	}
+	h->verbose	= p.verbose;
 
 	/* Do the final checks */
-	if (command == 'A' || command == 'I' || command == 'D') {
-		for (xtrm_i = cs.matches; xtrm_i; xtrm_i = xtrm_i->next)
-			xtables_option_mfcall(xtrm_i->match);
+	if (!nft_table_builtin_find(h, p.table))
+		xtables_error(VERSION_PROBLEM,
+			      "table '%s' does not exist", p.table);
 
-		for (match = cs.match_list; match; match = match->next) {
-			if (match->ismatch)
-				continue;
-
-			xtables_option_tfcall(match->u.watcher);
+	printf("nft ");
+	switch (p.command) {
+	case CMD_FLUSH:
+		if (p.chain) {
+			printf("flush chain bridge %s %s\n", p.table, p.chain);
+		} else {
+			printf("flush table bridge %s\n", p.table);
 		}
-
-		if (cs.target != NULL)
-			xtables_option_tfcall(cs.target);
-	}
-
-	cs.eb.ethproto = htons(cs.eb.ethproto);
-
-	if (command == 'P') {
-		return 0;
-	} else if (command == 'F') {
-			if (p.chain) {
-				printf("flush chain bridge %s %s\n", p.table, p.chain);
-			} else {
-				printf("flush table bridge %s\n", p.table);
-			}
-			ret = 1;
-	} else if (command == 'A') {
+		ret = 1;
+		break;
+	case CMD_APPEND:
 		ret = nft_rule_eb_xlate_add(h, &p, &cs, true);
 		if (!ret)
 			print_ebt_cmd(argc, argv);
-	} else if (command == 'I') {
+		break;
+	case CMD_INSERT:
 		ret = nft_rule_eb_xlate_add(h, &p, &cs, false);
 		if (!ret)
 			print_ebt_cmd(argc, argv);
+		break;
+	case CMD_LIST:
+		printf("list table bridge %s\n", p.table);
+		ret = 1;
+		break;
+	case CMD_NEW_CHAIN:
+		printf("add chain bridge %s %s\n", p.table, p.chain);
+		ret = 1;
+		break;
+	case CMD_DELETE_CHAIN:
+		printf("delete chain bridge %s %s\n", p.table, p.chain);
+		ret = 1;
+		break;
+	case CMD_INIT_TABLE:
+		printf("flush table bridge %s\n", p.table);
+		ret = 1;
+		break;
+	case CMD_DELETE:
+	case CMD_DELETE_NUM:
+	case CMD_CHECK:
+	case CMD_REPLACE:
+	case CMD_ZERO:
+	case CMD_ZERO_NUM:
+	case CMD_LIST|CMD_ZERO:
+	case CMD_LIST|CMD_ZERO_NUM:
+	case CMD_LIST_RULES:
+	case CMD_LIST_RULES|CMD_ZERO:
+	case CMD_LIST_RULES|CMD_ZERO_NUM:
+	case CMD_NEW_CHAIN|CMD_SET_POLICY:
+	case CMD_SET_POLICY:
+	case CMD_RENAME_CHAIN:
+	case CMD_CHANGE_COUNTERS:
+		break;
+	default:
+		/* We should never reach this... */
+		printf("Unsupported command?\n");
+		exit(1);
 	}
 
 	ebt_cs_clean(&cs);
diff --git a/iptables/xtables-eb.c b/iptables/xtables-eb.c
index 08eec79d..86c33b4e 100644
--- a/iptables/xtables-eb.c
+++ b/iptables/xtables-eb.c
@@ -42,94 +42,6 @@
 #include "nft.h"
 #include "nft-bridge.h"
 
-/* from linux/netfilter_bridge/ebtables.h */
-#define EBT_TABLE_MAXNAMELEN 32
-#define EBT_CHAIN_MAXNAMELEN EBT_TABLE_MAXNAMELEN
-
-/*
- * From include/ebtables_u.h
- */
-#define ebt_check_option2(flags, mask) EBT_CHECK_OPTION(flags, mask)
-
-/*
- * From useful_functions.c
- */
-
-/* 0: default
- * 1: the inverse '!' of the option has already been specified */
-int ebt_invert = 0;
-
-static int ebt_check_inverse2(const char option[], int argc, char **argv)
-{
-	if (!option)
-		return ebt_invert;
-	if (strcmp(option, "!") == 0) {
-		if (ebt_invert == 1)
-			xtables_error(PARAMETER_PROBLEM,
-				      "Double use of '!' not allowed");
-		if (optind >= argc)
-			optarg = NULL;
-		else
-			optarg = argv[optind];
-		optind++;
-		ebt_invert = 1;
-		return 1;
-	}
-	return ebt_invert;
-}
-
-/* XXX: merge with assert_valid_chain_name()? */
-static void ebt_assert_valid_chain_name(const char *chainname)
-{
-	if (strlen(chainname) >= EBT_CHAIN_MAXNAMELEN)
-		xtables_error(PARAMETER_PROBLEM,
-			      "Chain name length can't exceed %d",
-			      EBT_CHAIN_MAXNAMELEN - 1);
-
-	if (*chainname == '-' || *chainname == '!')
-		xtables_error(PARAMETER_PROBLEM, "No chain name specified");
-
-	if (xtables_find_target(chainname, XTF_TRY_LOAD))
-		xtables_error(PARAMETER_PROBLEM,
-			      "Target with name %s exists", chainname);
-
-	if (strchr(chainname, ' ') != NULL)
-		xtables_error(PARAMETER_PROBLEM,
-			      "Use of ' ' not allowed in chain names");
-}
-
-/*
- * Glue code to use libxtables
- */
-static int parse_rule_number(const char *rule)
-{
-	unsigned int rule_nr;
-
-	if (!xtables_strtoui(rule, NULL, &rule_nr, 1, INT_MAX))
-		xtables_error(PARAMETER_PROBLEM,
-			      "Invalid rule number `%s'", rule);
-
-	return rule_nr;
-}
-
-static int
-append_entry(struct nft_handle *h,
-	     const char *chain,
-	     const char *table,
-	     struct iptables_command_state *cs,
-	     int rule_nr,
-	     bool verbose, bool append)
-{
-	int ret = 1;
-
-	if (append)
-		ret = nft_cmd_rule_append(h, chain, table, cs, verbose);
-	else
-		ret = nft_cmd_rule_insert(h, chain, table, cs, rule_nr, verbose);
-
-	return ret;
-}
-
 static int
 delete_entry(struct nft_handle *h,
 	     const char *chain,
@@ -154,32 +66,28 @@ delete_entry(struct nft_handle *h,
 	return ret;
 }
 
-int ebt_get_current_chain(const char *chain)
+static int
+change_entry_counters(struct nft_handle *h,
+		      const char *chain, const char *table,
+		      struct iptables_command_state *cs,
+		      int rule_nr, int rule_nr_end, uint8_t counter_op,
+		      bool verbose)
 {
-	if (!chain)
-		return -1;
-
-	if (strcmp(chain, "PREROUTING") == 0)
-		return NF_BR_PRE_ROUTING;
-	else if (strcmp(chain, "INPUT") == 0)
-		return NF_BR_LOCAL_IN;
-	else if (strcmp(chain, "FORWARD") == 0)
-		return NF_BR_FORWARD;
-	else if (strcmp(chain, "OUTPUT") == 0)
-		return NF_BR_LOCAL_OUT;
-	else if (strcmp(chain, "POSTROUTING") == 0)
-		return NF_BR_POST_ROUTING;
-
-	/* placeholder for user defined chain */
-	return NF_BR_NUMHOOKS;
-}
+	int ret = 1;
 
-/*
- * The original ebtables parser
- */
+	if (rule_nr == -1)
+		return nft_cmd_rule_change_counters(h, chain, table, cs,
+						    rule_nr, counter_op,
+						    verbose);
+	do {
+		ret = nft_cmd_rule_change_counters(h, chain, table, cs,
+						   rule_nr, counter_op,
+						   verbose);
+		rule_nr++;
+	} while (rule_nr < rule_nr_end);
 
-/* Checks whether a command has already been specified */
-#define OPT_COMMANDS (flags & OPT_COMMAND || flags & OPT_ZERO)
+	return ret;
+}
 
 /* Default command line options. Do not mess around with the already
  * assigned numbers unless you know what you are doing */
@@ -189,17 +97,17 @@ struct option ebt_original_options[] =
 	{ "insert"         , required_argument, 0, 'I' },
 	{ "delete"         , required_argument, 0, 'D' },
 	{ "list"           , optional_argument, 0, 'L' },
-	{ "Lc"             , no_argument      , 0, 4   },
-	{ "Ln"             , no_argument      , 0, 5   },
-	{ "Lx"             , no_argument      , 0, 6   },
+	{ "Lc"             , no_argument      , 0, 17  },
+	{ "Ln"             , no_argument      , 0, 18  },
+	{ "Lx"             , no_argument      , 0, 19  },
 	{ "Lmac2"          , no_argument      , 0, 12  },
 	{ "zero"           , optional_argument, 0, 'Z' },
 	{ "flush"          , optional_argument, 0, 'F' },
 	{ "policy"         , required_argument, 0, 'P' },
 	{ "in-interface"   , required_argument, 0, 'i' },
 	{ "in-if"          , required_argument, 0, 'i' },
-	{ "logical-in"     , required_argument, 0, 2   },
-	{ "logical-out"    , required_argument, 0, 3   },
+	{ "logical-in"     , required_argument, 0, 15  },
+	{ "logical-out"    , required_argument, 0, 16  },
 	{ "out-interface"  , required_argument, 0, 'o' },
 	{ "out-if"         , required_argument, 0, 'o' },
 	{ "version"        , no_argument      , 0, 'V' },
@@ -233,14 +141,9 @@ struct xtables_globals ebtables_globals = {
 	.compat_rev		= nft_compatible_revision,
 };
 
-#define opts ebtables_globals.opts
 #define prog_name ebtables_globals.program_name
 #define prog_vers ebtables_globals.program_version
 
-/*
- * From libebtc.c
- */
-
 /* Prints all registered extensions */
 static void ebt_list_extensions(const struct xtables_target *t,
 				const struct xtables_rule_match *m)
@@ -266,39 +169,38 @@ static void ebt_list_extensions(const struct xtables_target *t,
 	}*/
 }
 
-#define OPTION_OFFSET 256
-static struct option *merge_options(struct option *oldopts,
-				    const struct option *newopts,
-				    unsigned int *options_offset)
+void nft_bridge_print_help(struct iptables_command_state *cs)
 {
-	unsigned int num_old, num_new, i;
-	struct option *merge;
-
-	if (!newopts || !oldopts || !options_offset)
-		return oldopts;
-	for (num_old = 0; oldopts[num_old].name; num_old++);
-	for (num_new = 0; newopts[num_new].name; num_new++);
-
-	ebtables_globals.option_offset += OPTION_OFFSET;
-	*options_offset = ebtables_globals.option_offset;
-
-	merge = xtables_malloc(sizeof(struct option) * (num_new + num_old + 1));
-	memcpy(merge, oldopts, num_old * sizeof(struct option));
-	for (i = 0; i < num_new; i++) {
-		merge[num_old + i] = newopts[i];
-		merge[num_old + i].val += *options_offset;
-	}
-	memset(merge + num_old + num_new, 0, sizeof(struct option));
-	/* Only free dynamically allocated stuff */
-	if (oldopts != ebt_original_options)
-		free(oldopts);
+	const struct xtables_rule_match *m = cs->matches;
+	struct xtables_target *t = cs->target;
 
-	return merge;
-}
+	while (optind < cs->argc) {
+		/*struct ebt_u_match *m;
+		struct ebt_u_watcher *w;*/
+
+		if (!strcasecmp("list_extensions", cs->argv[optind])) {
+			ebt_list_extensions(xtables_targets, cs->matches);
+			exit(0);
+		}
+		/*if ((m = ebt_find_match(cs->argv[optind])))
+			ebt_add_match(new_entry, m);
+		else if ((w = ebt_find_watcher(cs->argv[optind])))
+			ebt_add_watcher(new_entry, w);
+		else {*/
+			if (!(t = xtables_find_target(cs->argv[optind],
+						      XTF_TRY_LOAD)))
+				xtables_error(PARAMETER_PROBLEM,
+					      "Extension '%s' not found",
+					      cs->argv[optind]);
+			if (cs->options & OPT_JUMP)
+				xtables_error(PARAMETER_PROBLEM,
+					      "Sorry, you can only see help for one target extension at a time");
+			cs->options |= OPT_JUMP;
+			cs->target = t;
+		//}
+		optind++;
+	}
 
-static void print_help(const struct xtables_target *t,
-		       const struct xtables_rule_match *m, const char *table)
-{
 	printf("%s %s\n", prog_name, prog_vers);
 	printf(
 "Usage:\n"
@@ -323,13 +225,13 @@ static void print_help(const struct xtables_target *t,
 "--rename-chain -E old new     : rename a chain\n"
 "--delete-chain -X [chain]     : delete a user defined chain\n"
 "Options:\n"
-"--proto  -p [!] proto         : protocol hexadecimal, by name or LENGTH\n"
-"--src    -s [!] address[/mask]: source mac address\n"
-"--dst    -d [!] address[/mask]: destination mac address\n"
-"--in-if  -i [!] name[+]       : network input interface name\n"
-"--out-if -o [!] name[+]       : network output interface name\n"
-"--logical-in  [!] name[+]     : logical bridge input interface name\n"
-"--logical-out [!] name[+]     : logical bridge output interface name\n"
+"[!] --proto  -p proto         : protocol hexadecimal, by name or LENGTH\n"
+"[!] --src    -s address[/mask]: source mac address\n"
+"[!] --dst    -d address[/mask]: destination mac address\n"
+"[!] --in-if  -i name[+]       : network input interface name\n"
+"[!] --out-if -o name[+]       : network output interface name\n"
+"[!] --logical-in  name[+]     : logical bridge input interface name\n"
+"[!] --logical-out name[+]     : logical bridge output interface name\n"
 "--set-counters -c chain\n"
 "          pcnt bcnt           : set the counters of the to be added rule\n"
 "--modprobe -M program         : try to insert modules using this program\n"
@@ -347,9 +249,6 @@ static void print_help(const struct xtables_target *t,
 		printf("\n");
 		t->help();
 	}
-
-//	if (table->help)
-//		table->help(ebt_hooknames);
 }
 
 /* Execute command L */
@@ -378,99 +277,10 @@ static int list_rules(struct nft_handle *h, const char *chain, const char *table
 	return nft_cmd_rule_list(h, chain, table, rule_nr, format);
 }
 
-static int parse_rule_range(const char *argv, int *rule_nr, int *rule_nr_end)
-{
-	char *colon = strchr(argv, ':'), *buffer;
-
-	if (colon) {
-		*colon = '\0';
-		if (*(colon + 1) == '\0')
-			*rule_nr_end = -1; /* Until the last rule */
-		else {
-			*rule_nr_end = strtol(colon + 1, &buffer, 10);
-			if (*buffer != '\0' || *rule_nr_end == 0)
-				return -1;
-		}
-	}
-	if (colon == argv)
-		*rule_nr = 1; /* Beginning with the first rule */
-	else {
-		*rule_nr = strtol(argv, &buffer, 10);
-		if (*buffer != '\0' || *rule_nr == 0)
-			return -1;
-	}
-	if (!colon)
-		*rule_nr_end = *rule_nr;
-	return 0;
-}
-
-/* Incrementing or decrementing rules in daemon mode is not supported as the
- * involved code overload is not worth it (too annoying to take the increased
- * counters in the kernel into account). */
-static int parse_change_counters_rule(int argc, char **argv, int *rule_nr, int *rule_nr_end, struct iptables_command_state *cs)
-{
-	char *buffer;
-	int ret = 0;
-
-	if (optind + 1 >= argc || argv[optind][0] == '-' || argv[optind + 1][0] == '-')
-		xtables_error(PARAMETER_PROBLEM,
-			      "The command -C needs at least 2 arguments");
-	if (optind + 2 < argc && (argv[optind + 2][0] != '-' || (argv[optind + 2][1] >= '0' && argv[optind + 2][1] <= '9'))) {
-		if (optind + 3 != argc)
-			xtables_error(PARAMETER_PROBLEM,
-				      "No extra options allowed with -C start_nr[:end_nr] pcnt bcnt");
-		if (parse_rule_range(argv[optind], rule_nr, rule_nr_end))
-			xtables_error(PARAMETER_PROBLEM,
-				      "Something is wrong with the rule number specification '%s'", argv[optind]);
-		optind++;
-	}
-
-	if (argv[optind][0] == '+') {
-		ret += 1;
-		cs->counters.pcnt = strtoull(argv[optind] + 1, &buffer, 10);
-	} else if (argv[optind][0] == '-') {
-		ret += 2;
-		cs->counters.pcnt = strtoull(argv[optind] + 1, &buffer, 10);
-	} else
-		cs->counters.pcnt = strtoull(argv[optind], &buffer, 10);
-
-	if (*buffer != '\0')
-		goto invalid;
-	optind++;
-	if (argv[optind][0] == '+') {
-		ret += 3;
-		cs->counters.bcnt = strtoull(argv[optind] + 1, &buffer, 10);
-	} else if (argv[optind][0] == '-') {
-		ret += 6;
-		cs->counters.bcnt = strtoull(argv[optind] + 1, &buffer, 10);
-	} else
-		cs->counters.bcnt = strtoull(argv[optind], &buffer, 10);
-
-	if (*buffer != '\0')
-		goto invalid;
-	optind++;
-	return ret;
-invalid:
-	xtables_error(PARAMETER_PROBLEM,"Packet counter '%s' invalid", argv[optind]);
-}
-
-static void ebtables_parse_interface(const char *arg, char *vianame)
-{
-	unsigned char mask[IFNAMSIZ];
-	char *c;
-
-	xtables_parse_interface(arg, vianame, mask);
-
-	if ((c = strchr(vianame, '+'))) {
-		if (*(c + 1) != '\0')
-			xtables_error(PARAMETER_PROBLEM,
-				      "Spurious characters after '+' wildcard");
-	}
-}
-
 /* This code is very similar to iptables/xtables.c:command_match() */
 static void ebt_load_match(const char *name)
 {
+	struct option *opts = xt_params->opts;
 	struct xtables_match *m;
 	size_t size;
 
@@ -487,13 +297,23 @@ static void ebt_load_match(const char *name)
 	m->m->u.user.revision = m->revision;
 	xs_init_match(m);
 
-	opts = merge_options(opts, m->extra_opts, &m->option_offset);
+	if (m->x6_options != NULL)
+		opts = xtables_options_xfrm(xt_params->orig_opts, opts,
+					    m->x6_options, &m->option_offset);
+	else if (m->extra_opts != NULL)
+		opts = xtables_merge_options(xt_params->orig_opts, opts,
+					     m->extra_opts, &m->option_offset);
+	else
+		return;
+
 	if (opts == NULL)
 		xtables_error(OTHER_PROBLEM, "Can't alloc memory");
+	xt_params->opts = opts;
 }
 
 static void ebt_load_watcher(const char *name)
 {
+	struct option *opts = xt_params->opts;
 	struct xtables_target *watcher;
 	size_t size;
 
@@ -514,15 +334,24 @@ static void ebt_load_watcher(const char *name)
 
 	xs_init_target(watcher);
 
-	opts = merge_options(opts, watcher->extra_opts,
-			     &watcher->option_offset);
+	if (watcher->x6_options != NULL)
+		opts = xtables_options_xfrm(xt_params->orig_opts, opts,
+					    watcher->x6_options,
+					    &watcher->option_offset);
+	else if (watcher->extra_opts != NULL)
+		opts = xtables_merge_options(xt_params->orig_opts, opts,
+					     watcher->extra_opts,
+					     &watcher->option_offset);
+	else
+		return;
+
 	if (opts == NULL)
 		xtables_error(OTHER_PROBLEM, "Can't alloc memory");
+	xt_params->opts = opts;
 }
 
-void ebt_load_match_extensions(void)
+static void ebt_load_match_extensions(void)
 {
-	opts = ebt_original_options;
 	ebt_load_match("802_3");
 	ebt_load_match("arp");
 	ebt_load_match("ip");
@@ -538,27 +367,21 @@ void ebt_load_match_extensions(void)
 	ebt_load_watcher("nflog");
 }
 
-void ebt_add_match(struct xtables_match *m,
-		   struct iptables_command_state *cs)
+struct xtables_match *ebt_add_match(struct xtables_match *m,
+				    struct iptables_command_state *cs)
 {
 	struct xtables_rule_match **rule_matches = &cs->matches;
-	struct xtables_match *newm;
 	struct ebt_match *newnode, **matchp;
-	struct xt_entry_match *m2;
+	struct xtables_match *newm;
 
 	newm = xtables_find_match(m->name, XTF_LOAD_MUST_SUCCEED, rule_matches);
 	if (newm == NULL)
 		xtables_error(OTHER_PROBLEM,
 			      "Unable to add match %s", m->name);
 
-	m2 = xtables_calloc(1, newm->m->u.match_size);
-	memcpy(m2, newm->m, newm->m->u.match_size);
-	memset(newm->m->data, 0, newm->size);
+	newm->m = xtables_calloc(1, m->m->u.match_size);
+	memcpy(newm->m, m->m, m->m->u.match_size);
 	xs_init_match(newm);
-	newm->m = m2;
-
-	newm->mflags = m->mflags;
-	m->mflags = 0;
 
 	/* glue code for watchers */
 	newnode = xtables_calloc(1, sizeof(struct ebt_match));
@@ -568,27 +391,25 @@ void ebt_add_match(struct xtables_match *m,
 	for (matchp = &cs->match_list; *matchp; matchp = &(*matchp)->next)
 		;
 	*matchp = newnode;
+
+	return newm;
 }
 
-void ebt_add_watcher(struct xtables_target *watcher,
-		     struct iptables_command_state *cs)
+struct xtables_target *ebt_add_watcher(struct xtables_target *watcher,
+				       struct iptables_command_state *cs)
 {
 	struct ebt_match *newnode, **matchp;
 	struct xtables_target *clone;
 
 	clone = xtables_malloc(sizeof(struct xtables_target));
 	memcpy(clone, watcher, sizeof(struct xtables_target));
-	clone->udata = NULL;
-	clone->tflags = watcher->tflags;
 	clone->next = clone;
+	clone->udata = NULL;
+	xs_init_target(clone);
 
 	clone->t = xtables_calloc(1, watcher->t->u.target_size);
 	memcpy(clone->t, watcher->t, watcher->t->u.target_size);
 
-	memset(watcher->t->data, 0, watcher->size);
-	xs_init_target(watcher);
-	watcher->tflags = 0;
-
 
 	newnode = xtables_calloc(1, sizeof(struct ebt_match));
 	newnode->u.watcher = clone;
@@ -596,46 +417,62 @@ void ebt_add_watcher(struct xtables_target *watcher,
 	for (matchp = &cs->match_list; *matchp; matchp = &(*matchp)->next)
 		;
 	*matchp = newnode;
+
+	return clone;
 }
 
-int ebt_command_default(struct iptables_command_state *cs)
+int ebt_command_default(struct iptables_command_state *cs,
+			struct xtables_globals *unused, bool ebt_invert)
 {
 	struct xtables_target *t = cs->target;
 	struct xtables_match *m;
 	struct ebt_match *matchp;
 
 	/* Is it a target option? */
-	if (t && t->parse) {
-		if (t->parse(cs->c - t->option_offset, cs->argv,
-			     ebt_invert, &t->tflags, NULL, &t->t))
-			return 0;
+	if (cs->target != NULL &&
+	    (cs->target->parse != NULL || cs->target->x6_parse != NULL) &&
+	    cs->c >= cs->target->option_offset &&
+	    cs->c < cs->target->option_offset + XT_OPTION_OFFSET_SCALE) {
+		xtables_option_tpcall(cs->c, cs->argv, ebt_invert,
+				      cs->target, &cs->eb);
+		return 0;
 	}
 
 	/* check previously added matches/watchers to this rule first */
 	for (matchp = cs->match_list; matchp; matchp = matchp->next) {
 		if (matchp->ismatch) {
 			m = matchp->u.match;
-			if (m->parse &&
-			    m->parse(cs->c - m->option_offset, cs->argv,
-				     ebt_invert, &m->mflags, NULL, &m->m))
-				return 0;
+			if (!m->parse && !m->x6_parse)
+				continue;
+			if (cs->c < m->option_offset ||
+			    cs->c >= m->option_offset + XT_OPTION_OFFSET_SCALE)
+				continue;
+			xtables_option_mpcall(cs->c, cs->argv, ebt_invert,
+					      m, &cs->eb);
+			return 0;
 		} else {
 			t = matchp->u.watcher;
-			if (t->parse &&
-			    t->parse(cs->c - t->option_offset, cs->argv,
-				     ebt_invert, &t->tflags, NULL, &t->t))
-				return 0;
+			if (!t->parse && !t->x6_parse)
+				continue;
+			if (cs->c < t->option_offset ||
+			    cs->c >= t->option_offset + XT_OPTION_OFFSET_SCALE)
+				continue;
+			xtables_option_tpcall(cs->c, cs->argv, ebt_invert,
+					      t, &cs->eb);
+			return 0;
 		}
 	}
 
 	/* Is it a match_option? */
 	for (m = xtables_matches; m; m = m->next) {
-		if (m->parse &&
-		    m->parse(cs->c - m->option_offset, cs->argv,
-			     ebt_invert, &m->mflags, NULL, &m->m)) {
-			ebt_add_match(m, cs);
-			return 0;
-		}
+		if (!m->parse && !m->x6_parse)
+			continue;
+		if (cs->c < m->option_offset ||
+		    cs->c >= m->option_offset + XT_OPTION_OFFSET_SCALE)
+			continue;
+		m = ebt_add_match(m, cs);
+		xtables_option_mpcall(cs->c, cs->argv, ebt_invert, m, &cs->eb);
+		return 0;
 	}
 
 	/* Is it a watcher option? */
@@ -643,12 +480,14 @@ int ebt_command_default(struct iptables_command_state *cs)
 		if (!(t->ext_flags & XTABLES_EXT_WATCHER))
 			continue;
 
-		if (t->parse &&
-		    t->parse(cs->c - t->option_offset, cs->argv,
-			     ebt_invert, &t->tflags, NULL, &t->t)) {
-			ebt_add_watcher(t, cs);
-			return 0;
-		}
+		if (!t->parse && !t->x6_parse)
+			continue;
+		if (cs->c < t->option_offset ||
+		    cs->c >= t->option_offset + XT_OPTION_OFFSET_SCALE)
+			continue;
+		t = ebt_add_watcher(t, cs);
+		xtables_option_tpcall(cs->c, cs->argv, ebt_invert, t, &cs->eb);
+		return 0;
 	}
 	if (cs->c == ':')
 		xtables_error(PARAMETER_PROBLEM, "option \"%s\" "
@@ -699,8 +538,7 @@ void nft_fini_eb(struct nft_handle *h)
 		free(target->t);
 	}
 
-	if (opts != ebt_original_options)
-		free(opts);
+	free(xt_params->opts);
 
 	nft_fini(h);
 	xtables_fini();
@@ -709,489 +547,135 @@ void nft_fini_eb(struct nft_handle *h)
 int do_commandeb(struct nft_handle *h, int argc, char *argv[], char **table,
 		 bool restore)
 {
-	char *buffer;
-	int c, i;
-	int chcounter = 0; /* Needed for -C */
-	int rule_nr = 0;
-	int rule_nr_end = 0;
-	int ret = 0;
-	unsigned int flags = 0;
-	struct xtables_target *t;
 	struct iptables_command_state cs = {
+		.argc = argc,
 		.argv = argv,
 		.jumpto	= "",
-		.eb.bitmask = EBT_NOPROTO,
 	};
-	char command = 'h';
-	const char *chain = NULL;
-	const char *policy = NULL;
-	int selected_chain = -1;
-	struct xtables_rule_match *xtrm_i;
-	struct ebt_match *match;
-	bool table_set = false;
+	const struct builtin_table *t;
+	struct xtables_args args = {
+		.family	= h->family,
+	};
+	struct xt_cmd_parse p = {
+		.table		= *table,
+		.restore	= restore,
+		.line		= line,
+		.rule_ranges	= true,
+		.ops		= &h->ops->cmd_parse,
+	};
+	int ret = 0;
 
-	/* avoid cumulating verbosity with ebtables-restore */
-	h->verbose = 0;
+	if (h->ops->init_cs)
+		h->ops->init_cs(&cs);
 
-	/* prevent getopt to spoil our error reporting */
-	optind = 0;
-	opterr = false;
+	do_parse(argc, argv, &p, &cs, &args);
 
-	for (t = xtables_targets; t; t = t->next) {
-		t->tflags = 0;
-		t->used = 0;
-	}
+	h->verbose	= p.verbose;
 
-	/* Getopt saves the day */
-	while ((c = getopt_long(argc, argv, EBT_OPTSTRING,
-					opts, NULL)) != -1) {
-		cs.c = c;
-		switch (c) {
-
-		case 'A': /* Add a rule */
-		case 'D': /* Delete a rule */
-		case 'C': /* Change counters */
-		case 'P': /* Define policy */
-		case 'I': /* Insert a rule */
-		case 'N': /* Make a user defined chain */
-		case 'E': /* Rename chain */
-		case 'X': /* Delete chain */
-		case 14:  /* check a rule */
-			/* We allow -N chainname -P policy */
-			if (command == 'N' && c == 'P') {
-				command = c;
-				optind--; /* No table specified */
-				goto handle_P;
-			}
-			if (OPT_COMMANDS)
-				xtables_error(PARAMETER_PROBLEM,
-					      "Multiple commands are not allowed");
-
-			command = c;
-			if (optarg && (optarg[0] == '-' || !strcmp(optarg, "!")))
-				xtables_error(PARAMETER_PROBLEM, "No chain name specified");
-			chain = optarg;
-			selected_chain = ebt_get_current_chain(chain);
-			flags |= OPT_COMMAND;
-
-			if (c == 'N') {
-				ebt_assert_valid_chain_name(chain);
-				ret = nft_cmd_chain_user_add(h, chain, *table);
-				break;
-			} else if (c == 'X') {
-				/* X arg is optional, optarg is NULL */
-				if (!chain && optind < argc && argv[optind][0] != '-') {
-					chain = argv[optind];
-					optind++;
-				}
-				ret = nft_cmd_chain_del(h, chain, *table, 0);
-				break;
-			}
-
-			if (c == 'E') {
-				if (!xs_has_arg(argc, argv))
-					xtables_error(PARAMETER_PROBLEM, "No new chain name specified");
-				else if (optind < argc - 1)
-					xtables_error(PARAMETER_PROBLEM, "No extra options allowed with -E");
-
-				ebt_assert_valid_chain_name(argv[optind]);
-
-				errno = 0;
-				ret = nft_cmd_chain_user_rename(h, chain, *table,
-							    argv[optind]);
-				if (ret != 0 && errno == ENOENT)
-					xtables_error(PARAMETER_PROBLEM, "Chain '%s' doesn't exists", chain);
-
-				optind++;
-				break;
-			} else if (c == 'D' && optind < argc && (argv[optind][0] != '-' || (argv[optind][1] >= '0' && argv[optind][1] <= '9'))) {
-				if (optind != argc - 1)
-					xtables_error(PARAMETER_PROBLEM,
-							 "No extra options allowed with -D start_nr[:end_nr]");
-				if (parse_rule_range(argv[optind], &rule_nr, &rule_nr_end))
-					xtables_error(PARAMETER_PROBLEM,
-							 "Problem with the specified rule number(s) '%s'", argv[optind]);
-				optind++;
-			} else if (c == 'C') {
-				if ((chcounter = parse_change_counters_rule(argc, argv, &rule_nr, &rule_nr_end, &cs)) == -1)
-					return -1;
-			} else if (c == 'I') {
-				if (optind >= argc || (argv[optind][0] == '-' && (argv[optind][1] < '0' || argv[optind][1] > '9')))
-					rule_nr = 1;
-				else {
-					rule_nr = parse_rule_number(argv[optind]);
-					optind++;
-				}
-			} else if (c == 'P') {
-handle_P:
-				if (optind >= argc)
-					xtables_error(PARAMETER_PROBLEM,
-						      "No policy specified");
-				for (i = 0; i < NUM_STANDARD_TARGETS; i++)
-					if (!strcmp(argv[optind], nft_ebt_standard_target(i))) {
-						policy = argv[optind];
-						if (-i-1 == EBT_CONTINUE)
-							xtables_error(PARAMETER_PROBLEM,
-								      "Wrong policy '%s'",
-								      argv[optind]);
-						break;
-					}
-				if (i == NUM_STANDARD_TARGETS)
-					xtables_error(PARAMETER_PROBLEM,
-						      "Unknown policy '%s'", argv[optind]);
-				optind++;
-			}
-			break;
-		case 'L': /* List */
-		case 'F': /* Flush */
-		case 'Z': /* Zero counters */
-			if (c == 'Z') {
-				if ((flags & OPT_ZERO) || (flags & OPT_COMMAND && command != 'L'))
-print_zero:
-					xtables_error(PARAMETER_PROBLEM,
-						      "Command -Z only allowed together with command -L");
-				flags |= OPT_ZERO;
-			} else {
-				if (flags & OPT_COMMAND)
-					xtables_error(PARAMETER_PROBLEM,
-						      "Multiple commands are not allowed");
-				command = c;
-				flags |= OPT_COMMAND;
-				if (flags & OPT_ZERO && c != 'L')
-					goto print_zero;
-			}
-
-			if (optind < argc && argv[optind][0] != '-') {
-				chain = argv[optind];
-				optind++;
-			}
-			break;
-		case 'v': /* verbose */
-			flags |= OPT_VERBOSE;
-			h->verbose++;
-			break;
-		case 'V': /* Version */
-			if (OPT_COMMANDS)
-				xtables_error(PARAMETER_PROBLEM,
-					      "Multiple commands are not allowed");
-			printf("%s %s\n", prog_name, prog_vers);
-			exit(0);
-		case 'h': /* Help */
-			if (OPT_COMMANDS)
-				xtables_error(PARAMETER_PROBLEM,
-					      "Multiple commands are not allowed");
-			command = 'h';
-
-			/* All other arguments should be extension names */
-			while (optind < argc) {
-				/*struct ebt_u_match *m;
-				struct ebt_u_watcher *w;*/
-
-				if (!strcasecmp("list_extensions", argv[optind])) {
-					ebt_list_extensions(xtables_targets, cs.matches);
-					exit(0);
-				}
-				/*if ((m = ebt_find_match(argv[optind])))
-					ebt_add_match(new_entry, m);
-				else if ((w = ebt_find_watcher(argv[optind])))
-					ebt_add_watcher(new_entry, w);
-				else {*/
-					if (!(t = xtables_find_target(argv[optind], XTF_TRY_LOAD)))
-						xtables_error(PARAMETER_PROBLEM,"Extension '%s' not found", argv[optind]);
-					if (flags & OPT_JUMP)
-						xtables_error(PARAMETER_PROBLEM,"Sorry, you can only see help for one target extension at a time");
-					flags |= OPT_JUMP;
-					cs.target = t;
-				//}
-				optind++;
-			}
-			break;
-		case 't': /* Table */
-			if (restore && table_set)
-				xtables_error(PARAMETER_PROBLEM,
-					      "The -t option cannot be used in %s.",
-					      xt_params->program_name);
-			else if (table_set)
-				xtables_error(PARAMETER_PROBLEM,
-					      "Multiple use of same option not allowed");
-			if (!nft_table_builtin_find(h, optarg))
-				xtables_error(VERSION_PROBLEM,
-					      "table '%s' does not exist",
-					      optarg);
-			*table = optarg;
-			table_set = true;
-			break;
-		case 'i': /* Input interface */
-		case 2  : /* Logical input interface */
-		case 'o': /* Output interface */
-		case 3  : /* Logical output interface */
-		case 'j': /* Target */
-		case 'p': /* Net family protocol */
-		case 's': /* Source mac */
-		case 'd': /* Destination mac */
-		case 'c': /* Set counters */
-			if (!OPT_COMMANDS)
-				xtables_error(PARAMETER_PROBLEM,
-					      "No command specified");
-			if (command != 'A' && command != 'D' &&
-			    command != 'I' && command != 'C' && command != 14)
-				xtables_error(PARAMETER_PROBLEM,
-					      "Command and option do not match");
-			if (c == 'i') {
-				ebt_check_option2(&flags, OPT_VIANAMEIN);
-				if (selected_chain > 2 && selected_chain < NF_BR_BROUTING)
-					xtables_error(PARAMETER_PROBLEM,
-						      "Use -i only in INPUT, FORWARD, PREROUTING and BROUTING chains");
-				if (ebt_check_inverse2(optarg, argc, argv))
-					cs.eb.invflags |= EBT_IIN;
-
-				ebtables_parse_interface(optarg, cs.eb.in);
-				break;
-			} else if (c == 2) {
-				ebt_check_option2(&flags, OPT_LOGICALIN);
-				if (selected_chain > 2 && selected_chain < NF_BR_BROUTING)
-					xtables_error(PARAMETER_PROBLEM,
-						      "Use --logical-in only in INPUT, FORWARD, PREROUTING and BROUTING chains");
-				if (ebt_check_inverse2(optarg, argc, argv))
-					cs.eb.invflags |= EBT_ILOGICALIN;
-
-				ebtables_parse_interface(optarg, cs.eb.logical_in);
-				break;
-			} else if (c == 'o') {
-				ebt_check_option2(&flags, OPT_VIANAMEOUT);
-				if (selected_chain < 2 || selected_chain == NF_BR_BROUTING)
-					xtables_error(PARAMETER_PROBLEM,
-						      "Use -o only in OUTPUT, FORWARD and POSTROUTING chains");
-				if (ebt_check_inverse2(optarg, argc, argv))
-					cs.eb.invflags |= EBT_IOUT;
-
-				ebtables_parse_interface(optarg, cs.eb.out);
-				break;
-			} else if (c == 3) {
-				ebt_check_option2(&flags, OPT_LOGICALOUT);
-				if (selected_chain < 2 || selected_chain == NF_BR_BROUTING)
-					xtables_error(PARAMETER_PROBLEM,
-						      "Use --logical-out only in OUTPUT, FORWARD and POSTROUTING chains");
-				if (ebt_check_inverse2(optarg, argc, argv))
-					cs.eb.invflags |= EBT_ILOGICALOUT;
-
-				ebtables_parse_interface(optarg, cs.eb.logical_out);
-				break;
-			} else if (c == 'j') {
-				ebt_check_option2(&flags, OPT_JUMP);
-				if (strcmp(optarg, "CONTINUE") != 0) {
-					command_jump(&cs, optarg);
-				}
-				break;
-			} else if (c == 's') {
-				ebt_check_option2(&flags, OPT_SOURCE);
-				if (ebt_check_inverse2(optarg, argc, argv))
-					cs.eb.invflags |= EBT_ISOURCE;
-
-				if (xtables_parse_mac_and_mask(optarg,
-							       cs.eb.sourcemac,
-							       cs.eb.sourcemsk))
-					xtables_error(PARAMETER_PROBLEM, "Problem with specified source mac '%s'", optarg);
-				cs.eb.bitmask |= EBT_SOURCEMAC;
-				break;
-			} else if (c == 'd') {
-				ebt_check_option2(&flags, OPT_DESTINATION);
-				if (ebt_check_inverse2(optarg, argc, argv))
-					cs.eb.invflags |= EBT_IDEST;
-
-				if (xtables_parse_mac_and_mask(optarg,
-							       cs.eb.destmac,
-							       cs.eb.destmsk))
-					xtables_error(PARAMETER_PROBLEM, "Problem with specified destination mac '%s'", optarg);
-				cs.eb.bitmask |= EBT_DESTMAC;
-				break;
-			} else if (c == 'c') {
-				ebt_check_option2(&flags, OPT_COUNTERS);
-				if (ebt_check_inverse2(optarg, argc, argv))
-					xtables_error(PARAMETER_PROBLEM,
-						      "Unexpected '!' after -c");
-				if (optind >= argc || optarg[0] == '-' || argv[optind][0] == '-')
-					xtables_error(PARAMETER_PROBLEM,
-						      "Option -c needs 2 arguments");
-
-				cs.counters.pcnt = strtoull(optarg, &buffer, 10);
-				if (*buffer != '\0')
-					xtables_error(PARAMETER_PROBLEM,
-						      "Packet counter '%s' invalid",
-						      optarg);
-				cs.counters.bcnt = strtoull(argv[optind], &buffer, 10);
-				if (*buffer != '\0')
-					xtables_error(PARAMETER_PROBLEM,
-						      "Packet counter '%s' invalid",
-						      argv[optind]);
-				optind++;
-				break;
-			}
-			ebt_check_option2(&flags, OPT_PROTOCOL);
-			if (ebt_check_inverse2(optarg, argc, argv))
-				cs.eb.invflags |= EBT_IPROTO;
-
-			cs.eb.bitmask &= ~((unsigned int)EBT_NOPROTO);
-			i = strtol(optarg, &buffer, 16);
-			if (*buffer == '\0' && (i < 0 || i > 0xFFFF))
-				xtables_error(PARAMETER_PROBLEM,
-					      "Problem with the specified protocol");
-			if (*buffer != '\0') {
-				struct xt_ethertypeent *ent;
-
-				if (!strcasecmp(optarg, "LENGTH")) {
-					cs.eb.bitmask |= EBT_802_3;
-					break;
-				}
-				ent = xtables_getethertypebyname(optarg);
-				if (!ent)
-					xtables_error(PARAMETER_PROBLEM,
-						      "Problem with the specified Ethernet protocol '%s', perhaps "XT_PATH_ETHERTYPES " is missing", optarg);
-				cs.eb.ethproto = ent->e_ethertype;
-			} else
-				cs.eb.ethproto = i;
-
-			if (cs.eb.ethproto < 0x0600)
-				xtables_error(PARAMETER_PROBLEM,
-					      "Sorry, protocols have values above or equal to 0x0600");
-			break;
-		case 4  : /* Lc */
-			ebt_check_option2(&flags, LIST_C);
-			if (command != 'L')
-				xtables_error(PARAMETER_PROBLEM,
-					      "Use --Lc with -L");
-			flags |= LIST_C;
-			break;
-		case 5  : /* Ln */
-			ebt_check_option2(&flags, LIST_N);
-			if (command != 'L')
-				xtables_error(PARAMETER_PROBLEM,
-					      "Use --Ln with -L");
-			if (flags & LIST_X)
-				xtables_error(PARAMETER_PROBLEM,
-					      "--Lx is not compatible with --Ln");
-			flags |= LIST_N;
-			break;
-		case 6  : /* Lx */
-			ebt_check_option2(&flags, LIST_X);
-			if (command != 'L')
-				xtables_error(PARAMETER_PROBLEM,
-					      "Use --Lx with -L");
-			if (flags & LIST_N)
-				xtables_error(PARAMETER_PROBLEM,
-					      "--Lx is not compatible with --Ln");
-			flags |= LIST_X;
-			break;
-		case 12 : /* Lmac2 */
-			ebt_check_option2(&flags, LIST_MAC2);
-			if (command != 'L')
-				xtables_error(PARAMETER_PROBLEM,
-					       "Use --Lmac2 with -L");
-			flags |= LIST_MAC2;
+	t = nft_table_builtin_find(h, p.table);
+	if (!t)
+		xtables_error(VERSION_PROBLEM,
+			      "table '%s' does not exist", p.table);
+
+	switch (p.command) {
+	case CMD_NEW_CHAIN:
+	case CMD_NEW_CHAIN | CMD_SET_POLICY:
+		ret = nft_cmd_chain_user_add(h, p.chain, p.table);
+		if (!ret || !(p.command & CMD_SET_POLICY))
 			break;
-		case 11: /* init-table */
-			if (restore)
-				xtables_error(PARAMETER_PROBLEM,
-					      "--init-table is not supported in daemon mode");
-			nft_cmd_table_flush(h, *table, false);
-			return 1;
-		case 13 :
+		/* fall through */
+	case CMD_SET_POLICY:
+		if (!nft_chain_builtin_find(t, p.chain)) {
+			ret = ebt_cmd_user_chain_policy(h, p.table, p.chain,
+							p.policy);
 			break;
-		case 1 :
-			if (!strcmp(optarg, "!"))
-				ebt_check_inverse2(optarg, argc, argv);
-			else
-				xtables_error(PARAMETER_PROBLEM,
-					      "Bad argument : '%s'", optarg);
-			/* ebt_ebt_check_inverse2() did optind++ */
-			optind--;
-			continue;
-		default:
-			ebt_check_inverse2(optarg, argc, argv);
-			ebt_command_default(&cs);
-
-			if (command != 'A' && command != 'I' &&
-			    command != 'D' && command != 'C' && command != 14)
-				xtables_error(PARAMETER_PROBLEM,
-					      "Extensions only for -A, -I, -D and -C");
 		}
-		ebt_invert = 0;
-	}
-
-	/* Just in case we didn't catch an error */
-	/*if (ebt_errormsg[0] != '\0')
-		return -1;
-
-	if (!(table = ebt_find_table(replace->name)))
-		ebt_print_error2("Bad table name");*/
-
-	if (command == 'h' && !(flags & OPT_ZERO)) {
-		print_help(cs.target, cs.matches, *table);
-		ret = 1;
-	}
-
-	/* Do the final checks */
-	if (command == 'A' || command == 'I' ||
-	    command == 'D' || command == 'C' || command == 14) {
-		for (xtrm_i = cs.matches; xtrm_i; xtrm_i = xtrm_i->next)
-			xtables_option_mfcall(xtrm_i->match);
-
-		for (match = cs.match_list; match; match = match->next) {
-			if (match->ismatch)
-				continue;
-
-			xtables_option_tfcall(match->u.watcher);
-		}
-
-		if (cs.target != NULL)
-			xtables_option_tfcall(cs.target);
-	}
-	/* So, the extensions can work with the host endian.
-	 * The kernel does not have to do this of course */
-	cs.eb.ethproto = htons(cs.eb.ethproto);
-
-	if (command == 'P') {
-		if (selected_chain >= NF_BR_NUMHOOKS) {
-			ret = ebt_cmd_user_chain_policy(h, *table, chain, policy);
-		} else {
-			if (strcmp(policy, "RETURN") == 0) {
-				xtables_error(PARAMETER_PROBLEM,
-					      "Policy RETURN only allowed for user defined chains");
-			}
-			ret = nft_cmd_chain_set(h, *table, chain, policy, NULL);
-			if (ret < 0)
-				xtables_error(PARAMETER_PROBLEM, "Wrong policy");
+		if (strcmp(p.policy, "RETURN") == 0) {
+			xtables_error(PARAMETER_PROBLEM,
+				      "Policy RETURN only allowed for user defined chains");
 		}
-	} else if (command == 'L') {
-		ret = list_rules(h, chain, *table, rule_nr,
-				 flags & OPT_VERBOSE,
-				 0,
-				 /*flags&OPT_EXPANDED*/0,
-				 flags&LIST_N,
-				 flags&LIST_C);
+		ret = nft_cmd_chain_set(h, p.table, p.chain, p.policy, NULL);
+		if (ret < 0)
+			xtables_error(PARAMETER_PROBLEM, "Wrong policy");
+		break;
+	case CMD_LIST:
+	case CMD_LIST | CMD_ZERO:
+	case CMD_LIST | CMD_ZERO_NUM:
+	case CMD_LIST_RULES:
+	case CMD_LIST_RULES | CMD_ZERO:
+	case CMD_LIST_RULES | CMD_ZERO_NUM:
+		if (p.command & CMD_LIST)
+			ret = list_rules(h, p.chain, p.table, p.rulenum,
+					 cs.options & OPT_VERBOSE,
+					 0,
+					 /*cs.options&OPT_EXPANDED*/0,
+					 cs.options&OPT_LINENUMBERS,
+					 cs.options&OPT_LIST_C);
+		else if (p.command & CMD_LIST_RULES)
+			ret = nft_cmd_rule_list_save(h, p.chain, p.table,
+						     p.rulenum,
+						     cs.options & OPT_VERBOSE);
+		if (ret && (p.command & CMD_ZERO))
+			ret = nft_cmd_chain_zero_counters(h, p.chain, p.table,
+							  cs.options & OPT_VERBOSE);
+		if (ret && (p.command & CMD_ZERO_NUM))
+			ret = nft_cmd_rule_zero_counters(h, p.chain, p.table,
+							 p.rulenum - 1);
+		break;
+	case CMD_ZERO:
+		ret = nft_cmd_chain_zero_counters(h, p.chain, p.table,
+						  cs.options & OPT_VERBOSE);
+		break;
+	case CMD_ZERO_NUM:
+		ret = nft_cmd_rule_zero_counters(h, p.chain, p.table,
+						 p.rulenum - 1);
+		break;
+	case CMD_FLUSH:
+		ret = nft_cmd_rule_flush(h, p.chain, p.table,
+					 cs.options & OPT_VERBOSE);
+		break;
+	case CMD_APPEND:
+		ret = nft_cmd_rule_append(h, p.chain, p.table, &cs,
+					  cs.options & OPT_VERBOSE);
+		break;
+	case CMD_INSERT:
+		ret = nft_cmd_rule_insert(h, p.chain, p.table, &cs,
+					  p.rulenum - 1,
+					  cs.options & OPT_VERBOSE);
+		break;
+	case CMD_DELETE:
+	case CMD_DELETE_NUM:
+		ret = delete_entry(h, p.chain, p.table, &cs, p.rulenum - 1,
+				   p.rulenum_end, cs.options & OPT_VERBOSE);
+		break;
+	case CMD_DELETE_CHAIN:
+		ret = nft_cmd_chain_del(h, p.chain, p.table, 0);
+		break;
+	case CMD_RENAME_CHAIN:
+		ret = nft_cmd_chain_user_rename(h, p.chain, p.table, p.newname);
+		break;
+	case CMD_INIT_TABLE:
+		ret = nft_cmd_table_flush(h, p.table, false);
+		break;
+	case CMD_CHECK:
+		ret = nft_cmd_rule_check(h, p.chain, p.table,
+					 &cs, cs.options & OPT_VERBOSE);
+		break;
+	case CMD_CHANGE_COUNTERS:
+		ret = change_entry_counters(h, p.chain, p.table, &cs,
+					    p.rulenum - 1, p.rulenum_end,
+					    args.counter_op,
+					    cs.options & OPT_VERBOSE);
+		break;
+	case CMD_REPLACE:
+		ret = nft_cmd_rule_replace(h, p.chain, p.table, &cs,
+					   p.rulenum - 1,
+					   cs.options & OPT_VERBOSE);
+		break;
+	default:
+		/* We should never reach this... */
+		exit_tryhelp(2, line);
 	}
-	if (flags & OPT_ZERO) {
-		ret = nft_cmd_chain_zero_counters(h, chain, *table,
-						  flags & OPT_VERBOSE);
-	} else if (command == 'F') {
-		ret = nft_cmd_rule_flush(h, chain, *table, flags & OPT_VERBOSE);
-	} else if (command == 'A') {
-		ret = append_entry(h, chain, *table, &cs, 0,
-				   flags & OPT_VERBOSE, true);
-	} else if (command == 'I') {
-		ret = append_entry(h, chain, *table, &cs, rule_nr - 1,
-				   flags & OPT_VERBOSE, false);
-	} else if (command == 'D') {
-		ret = delete_entry(h, chain, *table, &cs, rule_nr - 1,
-				   rule_nr_end, flags & OPT_VERBOSE);
-	} else if (command == 14) {
-		ret = nft_cmd_rule_check(h, chain, *table,
-					 &cs, flags & OPT_VERBOSE);
-	} /*else if (replace->command == 'C') {
-		ebt_change_counters(replace, new_entry, rule_nr, rule_nr_end, &(new_entry->cnt_surplus), chcounter);
-		if (ebt_errormsg[0] != '\0')
-			return -1;
-	}*/
 
 	ebt_cs_clean(&cs);
 	return ret;
diff --git a/iptables/xtables-legacy.8 b/iptables/xtables-legacy.8
index 6db7d2cb..fa26a555 100644
--- a/iptables/xtables-legacy.8
+++ b/iptables/xtables-legacy.8
@@ -63,7 +63,6 @@ updates might be lost.  This can be worked around partially with the \-\-wait op
 
 There is also no method to monitor changes to the ruleset, except periodically calling
 iptables-legacy-save and checking for any differences in output.
-
 .B xtables\-monitor(8)
 will need the
 .B xtables\-nft(8)
diff --git a/iptables/xtables-monitor.8.in b/iptables/xtables-monitor.8.in
index a7f22c0d..ed2c5fb4 100644
--- a/iptables/xtables-monitor.8.in
+++ b/iptables/xtables-monitor.8.in
@@ -43,7 +43,7 @@ Restrict output to IPv6.
 .PP
 The first line shows a packet entering rule set evaluation.
 The protocol number is shown (AF_INET in this case), then a packet
-identifier number that allows to correlate messages coming from rule set evaluation of
+identifier number that allows one to correlate messages coming from rule set evaluation of
 this packet.  After this, the rule that was matched by the packet is shown.
 This is the TRACE rule that turns on tracing events for this packet.
 
diff --git a/iptables/xtables-monitor.c b/iptables/xtables-monitor.c
index cf2729d8..9561bd17 100644
--- a/iptables/xtables-monitor.c
+++ b/iptables/xtables-monitor.c
@@ -70,6 +70,22 @@ err:
 	return MNL_CB_OK;
 }
 
+static const char *family_cmd(int family)
+{
+	switch (family) {
+	case NFPROTO_IPV4:
+		return "iptables";
+	case NFPROTO_IPV6:
+		return "ip6tables";
+	case NFPROTO_ARP:
+		return "arptables";
+	case NFPROTO_BRIDGE:
+		return "ebtables";
+	default:
+		return NULL;
+	}
+}
+
 static bool counters;
 static bool trace;
 static bool events;
@@ -92,26 +108,27 @@ static int rule_cb(const struct nlmsghdr *nlh, void *data)
 	if (arg->nfproto && arg->nfproto != family)
 		goto err_free;
 
+	xtables_set_nfproto(family);
 	arg->h->ops = nft_family_ops_lookup(family);
+	arg->h->family = family;
 
-	if (arg->is_event)
-		printf(" EVENT: ");
-	switch (family) {
-	case AF_INET:
-	case AF_INET6:
-		printf("-%c ", family == AF_INET ? '4' : '6');
-		break;
-	case NFPROTO_ARP:
-		printf("-0 ");
-		break;
-	default:
-		puts("");
+	/* ignore policy rules unless tracing,
+	 * they are reported when deleting user-defined chains */
+	if (family == NFPROTO_BRIDGE &&
+	    arg->is_event &&
+	    nft_rule_is_policy_rule(r))
+		goto err_free;
+
+	if (!family_cmd(family))
 		goto err_free;
-	}
 
-	printf("-t %s ", nftnl_rule_get_str(r, NFTNL_RULE_TABLE));
-	nft_rule_print_save(arg->h, r, type == NFT_MSG_NEWRULE ? NFT_RULE_APPEND :
-							   NFT_RULE_DEL,
+	printf("%s%s -t %s ",
+	       arg->is_event ? " EVENT: " : "",
+	       family_cmd(family),
+	       nftnl_rule_get_str(r, NFTNL_RULE_TABLE));
+	nft_rule_print_save(arg->h, r,
+			    type == NFT_MSG_NEWRULE ? NFT_RULE_APPEND
+						    : NFT_RULE_DEL,
 			    counters ? 0 : FMT_NOCOUNTS);
 err_free:
 	nftnl_rule_free(r);
@@ -138,25 +155,18 @@ static int chain_cb(const struct nlmsghdr *nlh, void *data)
 	if (arg->nfproto && arg->nfproto != family)
 		goto err_free;
 
-	if (nftnl_chain_is_set(c, NFTNL_CHAIN_PRIO))
-		family = -1;
-
 	printf(" EVENT: ");
-	switch (family) {
-	case NFPROTO_IPV4:
-		family = 4;
-		break;
-	case NFPROTO_IPV6:
-		family = 6;
-		break;
-	default:
-		nftnl_chain_snprintf(buf, sizeof(buf), c, NFTNL_OUTPUT_DEFAULT, 0);
-		printf("# nft: %s\n", buf);
+
+	if (nftnl_chain_is_set(c, NFTNL_CHAIN_PRIO) || !family_cmd(family)) {
+		nftnl_chain_snprintf(buf, sizeof(buf),
+				     c, NFTNL_OUTPUT_DEFAULT, 0);
+		printf("nft: %s chain: %s\n",
+		       type == NFT_MSG_NEWCHAIN ? "NEW" : "DEL", buf);
 		goto err_free;
 	}
 
-	printf("-%d -t %s -%c %s\n",
-			family,
+	printf("%s -t %s -%c %s\n",
+			family_cmd(family),
 			nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE),
 			type == NFT_MSG_NEWCHAIN ? 'N' : 'X',
 			nftnl_chain_get_str(c, NFTNL_CHAIN_NAME));
@@ -542,7 +552,6 @@ static int trace_cb(const struct nlmsghdr *nlh, struct cb_arg *arg)
 err_free:
 	nftnl_trace_free(nlt);
 err:
-	fflush(stdout);
 	return MNL_CB_OK;
 }
 
@@ -574,6 +583,7 @@ static int monitor_cb(const struct nlmsghdr *nlh, void *data)
 		break;
 	}
 
+	fflush(stdout);
 	return ret;
 }
 
diff --git a/iptables/xtables-multi.h b/iptables/xtables-multi.h
index 833c11a2..760d3e4f 100644
--- a/iptables/xtables-multi.h
+++ b/iptables/xtables-multi.h
@@ -9,6 +9,7 @@ extern int xtables_ip4_restore_main(int, char **);
 extern int xtables_ip6_main(int, char **);
 extern int xtables_ip6_save_main(int, char **);
 extern int xtables_ip6_restore_main(int, char **);
+extern int xtables_arp_xlate_main(int, char **);
 extern int xtables_ip4_xlate_main(int, char **);
 extern int xtables_ip6_xlate_main(int, char **);
 extern int xtables_eb_xlate_main(int, char **);
diff --git a/iptables/xtables-nft-multi.c b/iptables/xtables-nft-multi.c
index e2b7c641..48265d8e 100644
--- a/iptables/xtables-nft-multi.c
+++ b/iptables/xtables-nft-multi.c
@@ -30,6 +30,7 @@ static const struct subcommand multi_subcommands[] = {
 	{"ip6tables-translate",		xtables_ip6_xlate_main},
 	{"iptables-restore-translate",	xtables_ip4_xlate_restore_main},
 	{"ip6tables-restore-translate",	xtables_ip6_xlate_restore_main},
+	{"arptables-translate",		xtables_arp_xlate_main},
 	{"arptables",			xtables_arp_main},
 	{"arptables-nft",		xtables_arp_main},
 	{"arptables-restore",		xtables_arp_restore_main},
diff --git a/iptables/xtables-nft.8 b/iptables/xtables-nft.8
index 702bf954..ae54476c 100644
--- a/iptables/xtables-nft.8
+++ b/iptables/xtables-nft.8
@@ -105,15 +105,15 @@ One basic example is creating the skeleton ruleset in nf_tables from the
 xtables-nft tools, in a fresh machine:
 
 .nf
-	root@machine:~# iptables\-nft \-L
+	root@machine:\(ti# iptables\-nft \-L
 	[...]
-	root@machine:~# ip6tables\-nft \-L
+	root@machine:\(ti# ip6tables\-nft \-L
 	[...]
-	root@machine:~# arptables\-nft \-L
+	root@machine:\(ti# arptables\-nft \-L
 	[...]
-	root@machine:~# ebtables\-nft \-L
+	root@machine:\(ti# ebtables\-nft \-L
 	[...]
-	root@machine:~# nft list ruleset
+	root@machine:\(ti# nft list ruleset
 	table ip filter {
 		chain INPUT {
 			type filter hook input priority 0; policy accept;
@@ -175,12 +175,12 @@ To migrate your complete filter ruleset, in the case of \fBiptables(8)\fP,
 you would use:
 
 .nf
-	root@machine:~# iptables\-legacy\-save > myruleset # reads from x_tables
-	root@machine:~# iptables\-nft\-restore myruleset   # writes to nf_tables
+	root@machine:\(ti# iptables\-legacy\-save > myruleset # reads from x_tables
+	root@machine:\(ti# iptables\-nft\-restore myruleset   # writes to nf_tables
 .fi
 or
 .nf
-	root@machine:~# iptables\-legacy\-save | iptables-translate-restore | less
+	root@machine:\(ti# iptables\-legacy\-save | iptables\-translate\-restore | less
 .fi
 
 to see how rules would look like in the nft
diff --git a/iptables/xtables-translate.8 b/iptables/xtables-translate.8
index a048e8c9..6fbbd617 100644
--- a/iptables/xtables-translate.8
+++ b/iptables/xtables-translate.8
@@ -30,28 +30,32 @@ iptables-translate \(em translation tool to migrate from iptables to nftables
 ip6tables-translate \(em translation tool to migrate from ip6tables to nftables
 .P
 ebtables-translate \(em translation tool to migrate from ebtables to nftables
+.P
+arptables-translate \(em translation tool to migrate from arptables to nftables
 .SH DESCRIPTION
 There is a set of tools to help the system administrator translate a given
-ruleset from \fBiptables(8)\fP, \fBip6tables(8)\fP and \fBebtables(8)\fP to
-\fBnftables(8)\fP.
+ruleset from \fBiptables(8)\fP, \fBip6tables(8)\fP, \fBebtables(8)\fP and
+\fBarptables(8)\fP to \fBnftables(8)\fP.
 
 The available commands are:
 
 .IP \[bu] 2
-iptables-translate
+iptables\-translate
 .IP \[bu]
-iptables-restore-translate
+iptables\-restore\-translate
 .IP \[bu] 2
-ip6tables-translate
+ip6tables\-translate
 .IP \[bu]
-ip6tables-restore-translate
+ip6tables\-restore\-translate
+.IP \[bu] 2
+ebtables\-translate
 .IP \[bu] 2
-ebtables-translate
+arptables\-translate
 
 .SH USAGE
 They take as input the original
-\fBiptables(8)\fP/\fBip6tables(8)\fP/\fBebtables(8)\fP syntax and
-output the native \fBnftables(8)\fP syntax.
+\fBiptables(8)\fP/\fBip6tables(8)\fP/\fBebtables(8)\fP/\fBarptables(8)\fP
+syntax and output the native \fBnftables(8)\fP syntax.
 
 The \fBiptables-restore-translate\fP tool reads a ruleset in the syntax
 produced by \fBiptables-save(8)\fP. Likewise, the
@@ -69,38 +73,38 @@ Basic operation examples.
 Single command translation:
 
 .nf
-root@machine:~# iptables-translate -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
+root@machine:\(ti# iptables\-translate \-A INPUT \-p tcp \-\-dport 22 \-m conntrack \-\-ctstate NEW \-j ACCEPT
 nft add rule ip filter INPUT tcp dport 22 ct state new counter accept
 
-root@machine:~# ip6tables-translate -A FORWARD -i eth0 -o eth3 -p udp -m multiport --dports 111,222 -j ACCEPT
+root@machine:\(ti# ip6tables\-translate \-A FORWARD \-i eth0 \-o eth3 \-p udp \-m multiport \-\-dports 111,222 \-j ACCEPT
 nft add rule ip6 filter FORWARD iifname eth0 oifname eth3 meta l4proto udp udp dport { 111,222} counter accept
 .fi
 
 Whole ruleset translation:
 
 .nf
-root@machine:~# iptables-save > save.txt
-root@machine:~# cat save.txt
-# Generated by iptables-save v1.6.0 on Sat Dec 24 14:26:40 2016
+root@machine:\(ti# iptables\-save > save.txt
+root@machine:\(ti# cat save.txt
+# Generated by iptables\-save v1.6.0 on Sat Dec 24 14:26:40 2016
 *filter
 :INPUT ACCEPT [5166:1752111]
 :FORWARD ACCEPT [0:0]
 :OUTPUT ACCEPT [5058:628693]
--A FORWARD -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
+\-A FORWARD \-p tcp \-m tcp \-\-dport 22 \-m conntrack \-\-ctstate NEW \-j ACCEPT
 COMMIT
 # Completed on Sat Dec 24 14:26:40 2016
 
-root@machine:~# iptables-restore-translate -f save.txt
-# Translated by iptables-restore-translate v1.6.0 on Sat Dec 24 14:26:59 2016
+root@machine:\(ti# iptables\-restore\-translate \-f save.txt
+# Translated by iptables\-restore\-translate v1.6.0 on Sat Dec 24 14:26:59 2016
 add table ip filter
 add chain ip filter INPUT { type filter hook input priority 0; }
 add chain ip filter FORWARD { type filter hook forward priority 0; }
 add chain ip filter OUTPUT { type filter hook output priority 0; }
 add rule ip filter FORWARD tcp dport 22 ct state new counter accept
 
-root@machine:~# iptables-restore-translate -f save.txt > ruleset.nft
-root@machine:~# nft -f ruleset.nft
-root@machine:~# nft list ruleset
+root@machine:\(ti# iptables\-restore\-translate \-f save.txt > ruleset.nft
+root@machine:\(ti# nft \-f ruleset.nft
+root@machine:\(ti# nft list ruleset
 table ip filter {
 	chain INPUT {
 		type filter hook input priority 0; policy accept;
diff --git a/iptables/xtables-translate.c b/iptables/xtables-translate.c
index 88e0a6b6..3d8617f0 100644
--- a/iptables/xtables-translate.c
+++ b/iptables/xtables-translate.c
@@ -131,7 +131,6 @@ bool xlate_find_match(const struct iptables_command_state *cs, const char *p_nam
 {
 	struct xtables_rule_match *matchp;
 
-	/* Skip redundant protocol, eg. ip protocol tcp tcp dport */
 	for (matchp = cs->matches; matchp; matchp = matchp->next) {
 		if (strcmp(matchp->match->name, p_name) == 0)
 			return true;
@@ -139,7 +138,24 @@ bool xlate_find_match(const struct iptables_command_state *cs, const char *p_nam
 	return false;
 }
 
+bool xlate_find_protomatch(const struct iptables_command_state *cs,
+			   uint16_t proto)
+{
+	struct protoent *pent;
+	int i;
+
+	/* Skip redundant protocol, eg. ip protocol tcp tcp dport */
+	for (i = 0; xtables_chain_protos[i].name != NULL; i++) {
+		if (xtables_chain_protos[i].num == proto &&
+		    xlate_find_match(cs, xtables_chain_protos[i].name))
+			return true;
+	}
+	pent = getprotobynumber(proto);
+	return pent && xlate_find_match(cs, pent->p_name);
+}
+
 const char *family2str[] = {
+	[NFPROTO_ARP]	= "arp",
 	[NFPROTO_IPV4]	= "ip",
 	[NFPROTO_IPV6]	= "ip6",
 };
@@ -196,6 +212,15 @@ static int xlate(struct nft_handle *h, struct xt_cmd_parse *p,
 
 	for (i = 0; i < args->s.naddrs; i++) {
 		switch (h->family) {
+		case NFPROTO_ARP:
+			cs->arp.arp.src.s_addr = args->s.addr.v4[i].s_addr;
+			cs->arp.arp.smsk.s_addr = args->s.mask.v4[i].s_addr;
+			for (j = 0; j < args->d.naddrs; j++) {
+				cs->arp.arp.tgt.s_addr = args->d.addr.v4[j].s_addr;
+				cs->arp.arp.tmsk.s_addr = args->d.mask.v4[j].s_addr;
+				ret = cb(h, p, cs, append);
+			}
+			break;
 		case AF_INET:
 			cs->fw.ip.src.s_addr = args->s.addr.v4[i].s_addr;
 			cs->fw.ip.smsk.s_addr = args->s.mask.v4[i].s_addr;
@@ -249,7 +274,6 @@ static int do_command_xlate(struct nft_handle *h, int argc, char *argv[],
 		.table		= *table,
 		.restore	= restore,
 		.line		= line,
-		.xlate		= true,
 		.ops		= &h->ops->cmd_parse,
 	};
 	struct iptables_command_state cs = {
@@ -340,17 +364,7 @@ static int do_command_xlate(struct nft_handle *h, int argc, char *argv[],
 
 	h->ops->clear_cs(&cs);
 
-	if (h->family == AF_INET) {
-		free(args.s.addr.v4);
-		free(args.s.mask.v4);
-		free(args.d.addr.v4);
-		free(args.d.mask.v4);
-	} else if (h->family == AF_INET6) {
-		free(args.s.addr.v6);
-		free(args.s.mask.v6);
-		free(args.d.addr.v6);
-		free(args.d.mask.v6);
-	}
+	xtables_clear_args(&args);
 	xtables_free_opts(1);
 
 	return ret;
@@ -475,7 +489,24 @@ static int xtables_xlate_main_common(struct nft_handle *h,
 
 	xtables_globals.program_name = progname;
 	xtables_globals.compat_rev = dummy_compat_rev;
-	ret = xtables_init_all(&xtables_globals, family);
+
+	switch (family) {
+	case NFPROTO_IPV4:
+		ret = xtables_init_all(&xtables_globals, family);
+		break;
+	case NFPROTO_IPV6:
+		ret = xtables_init_all(&xtables_globals, family);
+		break;
+	case NFPROTO_ARP:
+		arptables_globals.program_name = progname;
+		arptables_globals.compat_rev = dummy_compat_rev;
+		ret = xtables_init_all(&arptables_globals, family);
+		break;
+	default:
+		ret = -1;
+		break;
+	}
+
 	if (ret < 0) {
 		fprintf(stderr, "%s/%s Failed to initialize xtables\n",
 			xtables_globals.program_name,
@@ -590,6 +621,12 @@ static int xtables_restore_xlate_main(int family, const char *progname,
 	exit(0);
 }
 
+int xtables_arp_xlate_main(int argc, char *argv[])
+{
+	return xtables_xlate_main(NFPROTO_ARP, "arptables-translate",
+				  argc, argv);
+}
+
 int xtables_ip4_xlate_main(int argc, char *argv[])
 {
 	return xtables_xlate_main(NFPROTO_IPV4, "iptables-translate",
diff --git a/iptables/xtables.c b/iptables/xtables.c
index 22d6ea58..5d73481c 100644
--- a/iptables/xtables.c
+++ b/iptables/xtables.c
@@ -264,10 +264,7 @@ int do_commandx(struct nft_handle *h, int argc, char *argv[], char **table,
 
 	h->ops->clear_cs(&cs);
 
-	free(args.s.addr.ptr);
-	free(args.s.mask.ptr);
-	free(args.d.addr.ptr);
-	free(args.d.mask.ptr);
+	xtables_clear_args(&args);
 	xtables_free_opts(1);
 
 	return ret;
diff --git a/libxtables/xtables.c b/libxtables/xtables.c
index c8ddadec..d1d80928 100644
--- a/libxtables/xtables.c
+++ b/libxtables/xtables.c
@@ -64,6 +64,7 @@
 #endif
 #include <getopt.h>
 #include "iptables/internal.h"
+#include "xtables_internal.h"
 
 #define NPROTO	255
 
@@ -111,10 +112,8 @@ void basic_exit_err(enum xtables_exittype status, const char *msg, ...)
 
 void xtables_free_opts(int unused)
 {
-	if (xt_params->opts != xt_params->orig_opts) {
-		free(xt_params->opts);
-		xt_params->opts = NULL;
-	}
+	free(xt_params->opts);
+	xt_params->opts = NULL;
 }
 
 struct option *xtables_merge_options(struct option *orig_opts,
@@ -580,23 +579,23 @@ int xtables_load_ko(const char *modprobe, bool quiet)
 }
 
 /**
- * xtables_strtou{i,l} - string to number conversion
+ * xtables_strtoul_base - string to number conversion
  * @s:	input string
  * @end:	like strtoul's "end" pointer
  * @value:	pointer for result
  * @min:	minimum accepted value
  * @max:	maximum accepted value
+ * @base:	assumed base of value
  *
  * If @end is NULL, we assume the caller wants a "strict strtoul", and hence
  * "15a" is rejected.
  * In either case, the value obtained is compared for min-max compliance.
- * Base is always 0, i.e. autodetect depending on @s.
  *
  * Returns true/false whether number was accepted. On failure, *value has
  * undefined contents.
  */
-bool xtables_strtoul(const char *s, char **end, uintmax_t *value,
-                     uintmax_t min, uintmax_t max)
+bool xtables_strtoul_base(const char *s, char **end, uintmax_t *value,
+			  uintmax_t min, uintmax_t max, unsigned int base)
 {
 	uintmax_t v;
 	const char *p;
@@ -608,7 +607,7 @@ bool xtables_strtoul(const char *s, char **end, uintmax_t *value,
 		;
 	if (*p == '-')
 		return false;
-	v = strtoumax(s, &my_end, 0);
+	v = strtoumax(s, &my_end, base);
 	if (my_end == s)
 		return false;
 	if (end != NULL)
@@ -625,6 +624,12 @@ bool xtables_strtoul(const char *s, char **end, uintmax_t *value,
 	return false;
 }
 
+bool xtables_strtoul(const char *s, char **end, uintmax_t *value,
+		     uintmax_t min, uintmax_t max)
+{
+	return xtables_strtoul_base(s, end, value, min, max, 0);
+}
+
 bool xtables_strtoui(const char *s, char **end, unsigned int *value,
                      unsigned int min, unsigned int max)
 {
@@ -1169,11 +1174,21 @@ void xtables_register_match(struct xtables_match *me)
 	me->next = *pos;
 	*pos = me;
 #ifdef DEBUG
-	printf("%s: inserted match %s (family %d, revision %d):\n",
-			__func__, me->name, me->family, me->revision);
-	for (pos = &xtables_pending_matches; *pos; pos = &(*pos)->next) {
-		printf("%s:\tmatch %s (family %d, revision %d)\n", __func__,
-		       (*pos)->name, (*pos)->family, (*pos)->revision);
+#define printmatch(m, sfx)						\
+	printf("match %s (", (m)->name);				\
+	if ((m)->real_name)						\
+		printf("alias %s, ", (m)->real_name);			\
+	printf("family %d, revision %d)%s", (m)->family, (m)->revision, sfx);
+
+	{
+		int i = 1;
+
+		printf("%s: inserted ", __func__);
+		printmatch(me, ":\n");
+		for (pos = &xtables_pending_matches; *pos; pos = &(*pos)->next) {
+			printf("pos %d:\t", i++);
+			printmatch(*pos, "\n");
+		}
 	}
 #endif
 }
@@ -1416,6 +1431,10 @@ void xtables_rule_matches_free(struct xtables_rule_match **matches)
 			free(matchp->match->m);
 			matchp->match->m = NULL;
 		}
+		if (matchp->match->udata_size) {
+			free(matchp->match->udata);
+			matchp->match->udata = NULL;
+		}
 		if (matchp->match == matchp->match->next) {
 			free(matchp->match);
 			matchp->match = NULL;
@@ -1507,11 +1526,9 @@ void xtables_param_act(unsigned int status, const char *p1, ...)
 
 const char *xtables_ipaddr_to_numeric(const struct in_addr *addrp)
 {
-	static char buf[16];
-	const unsigned char *bytep = (const void *)&addrp->s_addr;
+	static char buf[INET_ADDRSTRLEN];
 
-	sprintf(buf, "%u.%u.%u.%u", bytep[0], bytep[1], bytep[2], bytep[3]);
-	return buf;
+	return inet_ntop(AF_INET, addrp, buf, sizeof(buf));
 }
 
 static const char *ipaddr_to_host(const struct in_addr *addr)
@@ -1571,13 +1588,14 @@ int xtables_ipmask_to_cidr(const struct in_addr *mask)
 
 const char *xtables_ipmask_to_numeric(const struct in_addr *mask)
 {
-	static char buf[20];
+	static char buf[INET_ADDRSTRLEN + 1];
 	uint32_t cidr;
 
 	cidr = xtables_ipmask_to_cidr(mask);
 	if (cidr == (unsigned int)-1) {
 		/* mask was not a decent combination of 1's and 0's */
-		sprintf(buf, "/%s", xtables_ipaddr_to_numeric(mask));
+		buf[0] = '/';
+		inet_ntop(AF_INET, mask, buf + 1, sizeof(buf) - 1);
 		return buf;
 	} else if (cidr == 32) {
 		/* we don't want to see "/32" */
@@ -1857,9 +1875,8 @@ void xtables_ipparse_any(const char *name, struct in_addr **addrpp,
 
 const char *xtables_ip6addr_to_numeric(const struct in6_addr *addrp)
 {
-	/* 0000:0000:0000:0000:0000:0000:000.000.000.000
-	 * 0000:0000:0000:0000:0000:0000:0000:0000 */
-	static char buf[50+1];
+	static char buf[INET6_ADDRSTRLEN];
+
 	return inet_ntop(AF_INET6, addrp, buf, sizeof(buf));
 }
 
@@ -1917,12 +1934,12 @@ int xtables_ip6mask_to_cidr(const struct in6_addr *k)
 
 const char *xtables_ip6mask_to_numeric(const struct in6_addr *addrp)
 {
-	static char buf[50+2];
+	static char buf[INET6_ADDRSTRLEN + 1];
 	int l = xtables_ip6mask_to_cidr(addrp);
 
 	if (l == -1) {
 		strcpy(buf, "/");
-		strcat(buf, xtables_ip6addr_to_numeric(addrp));
+		inet_ntop(AF_INET6, addrp, buf + 1, sizeof(buf) - 1);
 		return buf;
 	}
 	/* we don't want to see "/128" */
@@ -2197,6 +2214,8 @@ const struct xtables_pprot xtables_chain_protos[] = {
 	{"mobility-header", IPPROTO_MH},
 	{"ipv6-mh",   IPPROTO_MH},
 	{"mh",        IPPROTO_MH},
+	{"dccp",      IPPROTO_DCCP},
+	{"ipcomp",    IPPROTO_COMP},
 	{"all",       0},
 	{NULL},
 };
diff --git a/libxtables/xtoptions.c b/libxtables/xtoptions.c
index b16bbfbe..64d6599a 100644
--- a/libxtables/xtoptions.c
+++ b/libxtables/xtoptions.c
@@ -21,6 +21,7 @@
 #include <arpa/inet.h>
 #include <netinet/ip.h>
 #include "xtables.h"
+#include "xtables_internal.h"
 #ifndef IPTOS_NORMALSVC
 #	define IPTOS_NORMALSVC 0
 #endif
@@ -57,7 +58,6 @@ static const size_t xtopt_psize[] = {
 	[XTTYPE_STRING]      = -1,
 	[XTTYPE_SYSLOGLEVEL] = sizeof(uint8_t),
 	[XTTYPE_HOST]        = sizeof(union nf_inet_addr),
-	[XTTYPE_HOSTMASK]    = sizeof(union nf_inet_addr),
 	[XTTYPE_PROTOCOL]    = sizeof(uint8_t),
 	[XTTYPE_PORT]        = sizeof(uint16_t),
 	[XTTYPE_PORTRC]      = sizeof(uint16_t[2]),
@@ -65,6 +65,20 @@ static const size_t xtopt_psize[] = {
 	[XTTYPE_ETHERMAC]    = sizeof(uint8_t[6]),
 };
 
+/**
+ * Return a sanitized afinfo->family value, covering for NFPROTO_ARP
+ */
+static uint8_t afinfo_family(void)
+{
+	switch (afinfo->family) {
+	case NFPROTO_ARP:
+	case NFPROTO_BRIDGE:
+		return NFPROTO_IPV4;
+	default:
+		return afinfo->family;
+	}
+}
+
 /**
  * Creates getopt options from the x6-style option map, and assigns each a
  * getopt id.
@@ -73,56 +87,22 @@ struct option *
 xtables_options_xfrm(struct option *orig_opts, struct option *oldopts,
 		     const struct xt_option_entry *entry, unsigned int *offset)
 {
-	unsigned int num_orig, num_old = 0, num_new, i;
+	int num_new, i;
 	struct option *merge, *mp;
 
-	if (entry == NULL)
-		return oldopts;
-	for (num_orig = 0; orig_opts[num_orig].name != NULL; ++num_orig)
-		;
-	if (oldopts != NULL)
-		for (num_old = 0; oldopts[num_old].name != NULL; ++num_old)
-			;
 	for (num_new = 0; entry[num_new].name != NULL; ++num_new)
 		;
 
-	/*
-	 * Since @oldopts also has @orig_opts already (and does so at the
-	 * start), skip these entries.
-	 */
-	if (oldopts != NULL) {
-		oldopts += num_orig;
-		num_old -= num_orig;
-	}
-
-	merge = malloc(sizeof(*mp) * (num_orig + num_old + num_new + 1));
-	if (merge == NULL)
-		return NULL;
-
-	/* Let the base options -[ADI...] have precedence over everything */
-	memcpy(merge, orig_opts, sizeof(*mp) * num_orig);
-	mp = merge + num_orig;
-
-	/* Second, the new options */
-	xt_params->option_offset += XT_OPTION_OFFSET_SCALE;
-	*offset = xt_params->option_offset;
-
-	for (i = 0; i < num_new; ++i, ++mp, ++entry) {
-		mp->name         = entry->name;
-		mp->has_arg      = entry->type != XTTYPE_NONE;
-		mp->flag         = NULL;
-		mp->val          = entry->id + *offset;
+	mp = xtables_calloc(num_new + 1, sizeof(*mp));
+	for (i = 0; i < num_new; i++) {
+		mp[i].name	= entry[i].name;
+		mp[i].has_arg	= entry[i].type != XTTYPE_NONE;
+		mp[i].val	= entry[i].id;
 	}
 
-	/* Third, the old options */
-	if (oldopts != NULL) {
-		memcpy(mp, oldopts, sizeof(*mp) * num_old);
-		mp += num_old;
-	}
-	xtables_free_opts(0);
+	merge = xtables_merge_options(orig_opts, oldopts, mp, offset);
 
-	/* Clear trailing entry */
-	memset(mp, 0, sizeof(*mp));
+	free(mp);
 	return merge;
 }
 
@@ -169,6 +149,14 @@ static size_t xtopt_esize_by_type(enum xt_option_type type)
 	}
 }
 
+static uint64_t htonll(uint64_t val)
+{
+	uint32_t high = val >> 32;
+	uint32_t low = val & UINT32_MAX;
+
+	return (uint64_t)htonl(low) << 32 | htonl(high);
+}
+
 /**
  * Require a simple integer.
  */
@@ -183,7 +171,8 @@ static void xtopt_parse_int(struct xt_option_call *cb)
 	if (cb->entry->max != 0)
 		lmax = cb->entry->max;
 
-	if (!xtables_strtoul(cb->arg, NULL, &value, lmin, lmax))
+	if (!xtables_strtoul_base(cb->arg, NULL, &value,
+				  lmin, lmax, cb->entry->base))
 		xt_params->exit_err(PARAMETER_PROBLEM,
 			"%s: bad value for option \"--%s\", "
 			"or out of range (%ju-%ju).\n",
@@ -195,14 +184,20 @@ static void xtopt_parse_int(struct xt_option_call *cb)
 			*(uint8_t *)XTOPT_MKPTR(cb) = cb->val.u8;
 	} else if (entry->type == XTTYPE_UINT16) {
 		cb->val.u16 = value;
+		if (entry->flags & XTOPT_NBO)
+			cb->val.u16 = htons(cb->val.u16);
 		if (entry->flags & XTOPT_PUT)
 			*(uint16_t *)XTOPT_MKPTR(cb) = cb->val.u16;
 	} else if (entry->type == XTTYPE_UINT32) {
 		cb->val.u32 = value;
+		if (entry->flags & XTOPT_NBO)
+			cb->val.u32 = htonl(cb->val.u32);
 		if (entry->flags & XTOPT_PUT)
 			*(uint32_t *)XTOPT_MKPTR(cb) = cb->val.u32;
 	} else if (entry->type == XTTYPE_UINT64) {
 		cb->val.u64 = value;
+		if (entry->flags & XTOPT_NBO)
+			cb->val.u64 = htonll(cb->val.u64);
 		if (entry->flags & XTOPT_PUT)
 			*(uint64_t *)XTOPT_MKPTR(cb) = cb->val.u64;
 	}
@@ -237,17 +232,25 @@ static void xtopt_parse_float(struct xt_option_call *cb)
 static void xtopt_mint_value_to_cb(struct xt_option_call *cb, uintmax_t value)
 {
 	const struct xt_option_entry *entry = cb->entry;
+	uint8_t i = cb->nvals;
 
-	if (cb->nvals >= ARRAY_SIZE(cb->val.u32_range))
+	if (i >= ARRAY_SIZE(cb->val.u32_range))
 		return;
-	if (entry->type == XTTYPE_UINT8RC)
-		cb->val.u8_range[cb->nvals] = value;
-	else if (entry->type == XTTYPE_UINT16RC)
-		cb->val.u16_range[cb->nvals] = value;
-	else if (entry->type == XTTYPE_UINT32RC)
-		cb->val.u32_range[cb->nvals] = value;
-	else if (entry->type == XTTYPE_UINT64RC)
-		cb->val.u64_range[cb->nvals] = value;
+	if (entry->type == XTTYPE_UINT8RC) {
+		cb->val.u8_range[i] = value;
+	} else if (entry->type == XTTYPE_UINT16RC) {
+		cb->val.u16_range[i] = value;
+		if (entry->flags & XTOPT_NBO)
+			cb->val.u16_range[i] = htons(cb->val.u16_range[i]);
+	} else if (entry->type == XTTYPE_UINT32RC) {
+		cb->val.u32_range[i] = value;
+		if (entry->flags & XTOPT_NBO)
+			cb->val.u32_range[i] = htonl(cb->val.u32_range[i]);
+	} else if (entry->type == XTTYPE_UINT64RC) {
+		cb->val.u64_range[i] = value;
+		if (entry->flags & XTOPT_NBO)
+			cb->val.u64_range[i] = htonll(cb->val.u64_range[i]);
+	}
 }
 
 /**
@@ -287,13 +290,16 @@ static void xtopt_parse_mint(struct xt_option_call *cb)
 	const struct xt_option_entry *entry = cb->entry;
 	const char *arg;
 	size_t esize = xtopt_esize_by_type(entry->type);
-	const uintmax_t lmax = xtopt_max_by_type(entry->type);
+	uintmax_t lmax = xtopt_max_by_type(entry->type);
+	uintmax_t value, lmin = entry->min;
 	void *put = XTOPT_MKPTR(cb);
 	unsigned int maxiter;
-	uintmax_t value;
 	char *end = "";
 	char sep = ':';
 
+	if (entry->max && entry->max < lmax)
+		lmax = entry->max;
+
 	maxiter = entry->size / esize;
 	if (maxiter == 0)
 		maxiter = ARRAY_SIZE(cb->val.u32_range);
@@ -310,18 +316,19 @@ static void xtopt_parse_mint(struct xt_option_call *cb)
 		if (*arg == '\0' || *arg == sep) {
 			/* Default range components when field not spec'd. */
 			end = (char *)arg;
-			value = (cb->nvals == 1) ? lmax : 0;
+			value = (cb->nvals == 1) ? lmax : lmin;
 		} else {
-			if (!xtables_strtoul(arg, &end, &value, 0, lmax))
+			if (!xtables_strtoul(arg, &end, &value, lmin, lmax))
 				xt_params->exit_err(PARAMETER_PROBLEM,
 					"%s: bad value for option \"--%s\" near "
-					"\"%s\", or out of range (0-%ju).\n",
-					cb->ext_name, entry->name, arg, lmax);
+					"\"%s\", or out of range (%ju-%ju).\n",
+					cb->ext_name, entry->name, arg, lmin, lmax);
 			if (*end != '\0' && *end != sep)
 				xt_params->exit_err(PARAMETER_PROBLEM,
 					"%s: Argument to \"--%s\" has "
 					"unexpected characters near \"%s\".\n",
 					cb->ext_name, entry->name, end);
+			lmin = value;
 		}
 		xtopt_mint_value_to_cb(cb, value);
 		++cb->nvals;
@@ -496,7 +503,7 @@ static socklen_t xtables_sa_hostlen(unsigned int afproto)
  */
 static void xtopt_parse_host(struct xt_option_call *cb)
 {
-	struct addrinfo hints = {.ai_family = afinfo->family};
+	struct addrinfo hints = {.ai_family = afinfo_family()};
 	unsigned int adcount = 0;
 	struct addrinfo *res, *p;
 	int ret;
@@ -507,7 +514,7 @@ static void xtopt_parse_host(struct xt_option_call *cb)
 			"getaddrinfo: %s\n", gai_strerror(ret));
 
 	memset(&cb->val.hmask, 0xFF, sizeof(cb->val.hmask));
-	cb->val.hlen = (afinfo->family == NFPROTO_IPV4) ? 32 : 128;
+	cb->val.hlen = (afinfo_family() == NFPROTO_IPV4) ? 32 : 128;
 
 	for (p = res; p != NULL; p = p->ai_next) {
 		if (adcount == 0) {
@@ -601,7 +608,7 @@ static void xtopt_parse_mport(struct xt_option_call *cb)
 	const struct xt_option_entry *entry = cb->entry;
 	char *lo_arg, *wp_arg, *arg;
 	unsigned int maxiter;
-	int value;
+	int value, prev = 0;
 
 	wp_arg = lo_arg = xtables_strdup(cb->arg);
 
@@ -631,6 +638,11 @@ static void xtopt_parse_mport(struct xt_option_call *cb)
 			xt_params->exit_err(PARAMETER_PROBLEM,
 				"Port \"%s\" does not resolve to "
 				"anything.\n", arg);
+		if (value < prev)
+			xt_params->exit_err(PARAMETER_PROBLEM,
+				"Port range %d-%d is negative.\n",
+				prev, value);
+		prev = value;
 		if (entry->flags & XTOPT_NBO)
 			value = htons(value);
 		if (cb->nvals < ARRAY_SIZE(cb->val.port_range))
@@ -650,7 +662,7 @@ static void xtopt_parse_mport(struct xt_option_call *cb)
 
 static int xtopt_parse_mask(struct xt_option_call *cb)
 {
-	struct addrinfo hints = {.ai_family = afinfo->family,
+	struct addrinfo hints = {.ai_family = afinfo_family(),
 				 .ai_flags = AI_NUMERICHOST };
 	struct addrinfo *res;
 	int ret;
@@ -662,7 +674,7 @@ static int xtopt_parse_mask(struct xt_option_call *cb)
 	memcpy(&cb->val.hmask, xtables_sa_host(res->ai_addr, res->ai_family),
 	       xtables_sa_hostlen(res->ai_family));
 
-	switch(afinfo->family) {
+	switch(afinfo_family()) {
 	case AF_INET:
 		cb->val.hlen = xtables_ipmask_to_cidr(&cb->val.hmask.in);
 		break;
@@ -684,7 +696,7 @@ static void xtopt_parse_plen(struct xt_option_call *cb)
 	const struct xt_option_entry *entry = cb->entry;
 	unsigned int prefix_len = 128; /* happiness is a warm gcc */
 
-	cb->val.hlen = (afinfo->family == NFPROTO_IPV4) ? 32 : 128;
+	cb->val.hlen = (afinfo_family() == NFPROTO_IPV4) ? 32 : 128;
 	if (!xtables_strtoui(cb->arg, NULL, &prefix_len, 0, cb->val.hlen)) {
 		/* Is this mask expressed in full format? e.g. 255.255.255.0 */
 		if (xtopt_parse_mask(cb))
@@ -711,6 +723,10 @@ static void xtopt_parse_plenmask(struct xt_option_call *cb)
 
 	xtopt_parse_plen(cb);
 
+	/* may not be convertible to CIDR notation */
+	if (cb->val.hlen == (uint8_t)-1)
+		goto out_put;
+
 	memset(mask, 0xFF, sizeof(union nf_inet_addr));
 	/* This shifting is AF-independent. */
 	if (cb->val.hlen == 0) {
@@ -731,6 +747,7 @@ static void xtopt_parse_plenmask(struct xt_option_call *cb)
 	mask[1] = htonl(mask[1]);
 	mask[2] = htonl(mask[2]);
 	mask[3] = htonl(mask[3]);
+out_put:
 	if (entry->flags & XTOPT_PUT)
 		memcpy(XTOPT_MKPTR(cb), mask, sizeof(union nf_inet_addr));
 }
@@ -785,6 +802,15 @@ static void xtopt_parse_ethermac(struct xt_option_call *cb)
 	xt_params->exit_err(PARAMETER_PROBLEM, "Invalid MAC address specified.");
 }
 
+static void xtopt_parse_ethermacmask(struct xt_option_call *cb)
+{
+	memset(cb->val.ethermacmask, 0xff, ETH_ALEN);
+	if (xtables_parse_mac_and_mask(cb->arg, cb->val.ethermac,
+				       cb->val.ethermacmask))
+		xt_params->exit_err(PARAMETER_PROBLEM,
+				    "Invalid MAC/mask address specified.");
+}
+
 static void (*const xtopt_subparse[])(struct xt_option_call *) = {
 	[XTTYPE_UINT8]       = xtopt_parse_int,
 	[XTTYPE_UINT16]      = xtopt_parse_int,
@@ -807,6 +833,7 @@ static void (*const xtopt_subparse[])(struct xt_option_call *) = {
 	[XTTYPE_PLEN]        = xtopt_parse_plen,
 	[XTTYPE_PLENMASK]    = xtopt_parse_plenmask,
 	[XTTYPE_ETHERMAC]    = xtopt_parse_ethermac,
+	[XTTYPE_ETHERMACMASK]= xtopt_parse_ethermacmask,
 };
 
 /**
diff --git a/utils/nfbpf_compile.8.in b/utils/nfbpf_compile.8.in
index d02979a5..b19d4fbb 100644
--- a/utils/nfbpf_compile.8.in
+++ b/utils/nfbpf_compile.8.in
@@ -1,7 +1,7 @@
 .TH NFBPF_COMPILE 8 "" "@PACKAGE_STRING@" "@PACKAGE_STRING@"
 
 .SH NAME
-nfbpf_compile \- generate bytecode for use with xt_bpf
+nfbpf_compile \(em generate bytecode for use with xt_bpf
 .SH SYNOPSIS
 
 .ad l
diff --git a/utils/nfnl_osf.8.in b/utils/nfnl_osf.8.in
index 140b5c3f..1ef0c387 100644
--- a/utils/nfnl_osf.8.in
+++ b/utils/nfnl_osf.8.in
@@ -1,7 +1,7 @@
 .TH NFNL_OSF 8 "" "@PACKAGE_STRING@" "@PACKAGE_STRING@"
 
 .SH NAME
-nfnl_osf \- OS fingerprint loader utility
+nfnl_osf \(em OS fingerprint loader utility
 .SH SYNOPSIS
 
 .ad l
@@ -16,7 +16,7 @@ nfnl_osf \- OS fingerprint loader utility
 .SH DESCRIPTION
 The
 .B nfnl_osf
-utility allows to load a set of operating system signatures into the kernel for
+utility allows one to load a set of operating system signatures into the kernel for
 later matching against using iptables'
 .B osf
 match.
diff --git a/xlate-test.py b/xlate-test.py
index 6a116598..1c8cfe71 100755
--- a/xlate-test.py
+++ b/xlate-test.py
@@ -14,7 +14,7 @@ def run_proc(args, shell = False, input = None):
     output, error = process.communicate(input)
     return (process.returncode, output, error)
 
-keywords = ("iptables-translate", "ip6tables-translate", "ebtables-translate")
+keywords = ("iptables-translate", "ip6tables-translate", "arptables-translate", "ebtables-translate")
 xtables_nft_multi = 'xtables-nft-multi'
 
 if sys.stdout.isatty():
@@ -41,9 +41,10 @@ def green(string):
 
 
 def test_one_xlate(name, sourceline, expected, result):
-    rc, output, error = run_proc([xtables_nft_multi] + shlex.split(sourceline))
+    cmd = [xtables_nft_multi] + shlex.split(sourceline)
+    rc, output, error = run_proc(cmd)
     if rc != 0:
-        result.append(name + ": " + red("Error: ") + "iptables-translate failure")
+        result.append(name + ": " + red("Error: ") + "Call failed: " + " ".join(cmd))
         result.append(error)
         return False
 
@@ -95,6 +96,8 @@ def test_one_replay(name, sourceline, expected, result):
     fam = ""
     if srccmd.startswith("ip6"):
         fam = "ip6 "
+    elif srccmd.startswith("arp"):
+        fam = "arp "
     elif srccmd.startswith("ebt"):
         fam = "bridge "
 
@@ -185,8 +188,10 @@ def run_test(name, payload):
 
 def load_test_files():
     test_files = total_tests = total_passed = total_error = total_failed = 0
-    tests = sorted(os.listdir("extensions"))
-    for test in ['extensions/' + f for f in tests if f.endswith(".txlate")]:
+    tests_path = os.path.join(os.path.dirname(sys.argv[0]), "extensions")
+    tests = sorted(os.listdir(tests_path))
+    for test in [os.path.join(tests_path, f)
+                 for f in tests if f.endswith(".txlate")]:
         with open(test, "r") as payload:
             tests, passed, failed, errors = run_test(test, payload)
             test_files += 1
```

