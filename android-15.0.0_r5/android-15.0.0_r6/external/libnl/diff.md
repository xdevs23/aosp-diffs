```diff
diff --git a/Android.bp b/Android.bp
index 3752cf33..e711be01 100644
--- a/Android.bp
+++ b/Android.bp
@@ -40,6 +40,7 @@ cc_library {
     host_supported: true,
     vendor_available: true,
     product_available: true,
+    recovery_available: true,
 
     target: {
         darwin: {
diff --git a/METADATA b/METADATA
index 8b03e004..386cee34 100644
--- a/METADATA
+++ b/METADATA
@@ -8,13 +8,13 @@ third_party {
   license_type: RESTRICTED
   last_upgrade_date {
     year: 2024
-    month: 6
-    day: 4
+    month: 7
+    day: 19
   }
   homepage: "https://github.com/thom311/libnl"
   identifier {
     type: "Git"
     value: "https://github.com/thom311/libnl.git"
-    version: "5248e1a45576617b349465997822cef34cbc5053"
+    version: "libnl3_10_0"
   }
 }
diff --git a/configure.ac b/configure.ac
index 4db43859..91d4ae34 100644
--- a/configure.ac
+++ b/configure.ac
@@ -6,7 +6,7 @@
 
 # copied from glib
 m4_define([libnl_major_version], [3])
-m4_define([libnl_minor_version], [9])
+m4_define([libnl_minor_version], [10])
 m4_define([libnl_micro_version], [0])
 m4_define([libnl_git_sha], [m4_esyscmd([ ( [ -d ./.git/ ] && [ "$(readlink -f ./.git/)" = "$(readlink -f "$(git rev-parse --git-dir 2>/dev/null)" 2>/dev/null)" ] && git rev-parse --verify -q HEAD 2>/dev/null ) || true ])])
 
diff --git a/doc/configure.ac b/doc/configure.ac
index c16e20ef..5b4fd4ee 100644
--- a/doc/configure.ac
+++ b/doc/configure.ac
@@ -3,7 +3,7 @@
 # Copyright (c) 2003-2013 Thomas Graf <tgraf@suug.ch>
 #
 
-AC_INIT(libnl-doc, [3.9.0], [http://www.infradead.org/~tgr/libnl/])
+AC_INIT(libnl-doc, [3.10.0], [http://www.infradead.org/~tgr/libnl/])
 AC_CONFIG_MACRO_DIR([../m4])
 AC_CONFIG_AUX_DIR([build-aux])
 AM_INIT_AUTOMAKE([foreign])
diff --git a/doc/doxygen-link.py b/doc/doxygen-link.py
index 2dcd5f0c..1f424fca 100755
--- a/doc/doxygen-link.py
+++ b/doc/doxygen-link.py
@@ -43,4 +43,6 @@ def translate(match):
 rc = re.compile(r"\b(" + "|".join(map(re.escape, sorted(links, reverse=True))) + r")\b")
 
 for line in open(sys.argv[2], "r"):
-    print(rc.sub(translate, line), end="")
+    if links:
+        line = rc.sub(translate, line)
+    print(line, end="")
diff --git a/include/netlink/utils.h b/include/netlink/utils.h
index b3a59516..ac91d4c6 100644
--- a/include/netlink/utils.h
+++ b/include/netlink/utils.h
@@ -349,6 +349,12 @@ enum {
 	NL_CAPABILITY_VERSION_3_12_0 = 38,
 #define NL_CAPABILITY_VERSION_3_12_0 NL_CAPABILITY_VERSION_3_12_0
 
+	/**
+	 * The library version is libnl3 3.13.0 or newer. This capability should never be backported.
+	 */
+	NL_CAPABILITY_VERSION_3_13_0 = 39,
+#define NL_CAPABILITY_VERSION_3_13_0 NL_CAPABILITY_VERSION_3_13_0
+
 	__NL_CAPABILITY_MAX,
 	NL_CAPABILITY_MAX = (__NL_CAPABILITY_MAX - 1),
 #define NL_CAPABILITY_MAX NL_CAPABILITY_MAX
diff --git a/lib/nl.c b/lib/nl.c
index a24c0260..1225ebaa 100644
--- a/lib/nl.c
+++ b/lib/nl.c
@@ -486,7 +486,7 @@ void nl_complete_msg(struct nl_sock *sk, struct nl_msg *msg)
 		nlh->nlmsg_pid = nl_socket_get_local_port(sk);
 
 	if (nlh->nlmsg_seq == NL_AUTO_SEQ)
-		nlh->nlmsg_seq = sk->s_seq_next++;
+		nlh->nlmsg_seq = nl_socket_use_seq(sk);
 
 	if (msg->nm_protocol == -1)
 		msg->nm_protocol = sk->s_proto;
diff --git a/lib/socket.c b/lib/socket.c
index 742cdace..4e64cbb3 100644
--- a/lib/socket.c
+++ b/lib/socket.c
@@ -24,6 +24,7 @@
 #include "nl-default.h"
 
 #include <fcntl.h>
+#include <limits.h>
 #include <sys/socket.h>
 
 #include <netlink/netlink.h>
@@ -316,6 +317,10 @@ void nl_socket_disable_seq_check(struct nl_sock *sk)
  */
 unsigned int nl_socket_use_seq(struct nl_sock *sk)
 {
+	if (sk->s_seq_next == UINT_MAX) {
+		sk->s_seq_next = 0;
+		return UINT_MAX;
+	}
 	return sk->s_seq_next++;
 }
 
diff --git a/lib/utils.c b/lib/utils.c
index 679078e7..41ff8eb5 100644
--- a/lib/utils.c
+++ b/lib/utils.c
@@ -1284,10 +1284,10 @@ int nl_has_capability (int capability)
 			NL_CAPABILITY_VERSION_3_7_0,
 			NL_CAPABILITY_VERSION_3_8_0,
 			NL_CAPABILITY_VERSION_3_9_0,
-			0, /* NL_CAPABILITY_VERSION_3_10_0 */
+			NL_CAPABILITY_VERSION_3_10_0,
 			0, /* NL_CAPABILITY_VERSION_3_11_0 */
 			0, /* NL_CAPABILITY_VERSION_3_12_0 */
-			0,
+			0, /* NL_CAPABILITY_VERSION_3_13_0 */
 			0),
 		/* IMPORTANT: these capability numbers are intended to be universal and stable
 		 * for libnl3. Don't allocate new numbers on your own that differ from upstream
diff --git a/python/netlink/route/tc.py b/python/netlink/route/tc.py
index daad6972..eb0037e2 100644
--- a/python/netlink/route/tc.py
+++ b/python/netlink/route/tc.py
@@ -596,7 +596,7 @@ _cls_cache = {}
 
 def get_cls(ifindex, parent, handle=None):
 
-    chain = _cls_cache.get(ifindex, dict())
+    chain = _cls_cache.get(ifindex, {})
 
     try:
         cache = chain[parent]
@@ -607,6 +607,6 @@ def get_cls(ifindex, parent, handle=None):
     cache.refill()
 
     if handle is None:
-        return [cls for cls in cache]
+        return list(cache)
 
     return [cls for cls in cache if cls.handle == handle]
diff --git a/python/netlink/util.py b/python/netlink/util.py
index afe7ef04..3adc509b 100644
--- a/python/netlink/util.py
+++ b/python/netlink/util.py
@@ -103,7 +103,7 @@ class MyFormatter(Formatter):
         if not isinstance(value, property):
             raise ValueError("Invalid formatting string {0}".format(key))
 
-        d = getattr(value.fget, "formatinfo", dict())
+        d = getattr(value.fget, "formatinfo", {})
 
         # value = value.fget() is exactly the same
         value = getattr(self._obj, key)
```

