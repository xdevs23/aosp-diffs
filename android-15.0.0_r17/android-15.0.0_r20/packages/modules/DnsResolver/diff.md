```diff
diff --git a/apex/OWNERS b/apex/OWNERS
deleted file mode 100644
index bc97a1bb..00000000
--- a/apex/OWNERS
+++ /dev/null
@@ -1,4 +0,0 @@
-chenbruce@google.com
-codewiz@google.com
-martinwu@google.com
-
diff --git a/res_cache.cpp b/res_cache.cpp
index 05064a30..66053737 100644
--- a/res_cache.cpp
+++ b/res_cache.cpp
@@ -32,6 +32,7 @@
 
 #include <resolv.h>
 #include <stdarg.h>
+#include <stdint.h>
 #include <stdlib.h>
 #include <string.h>
 #include <time.h>
@@ -253,14 +254,6 @@ static time_t _time_now(void) {
 
 #define DNS_HEADER_SIZE 12
 
-#define DNS_TYPE_A "\00\01"     /* big-endian decimal 1 */
-#define DNS_TYPE_PTR "\00\014"  /* big-endian decimal 12 */
-#define DNS_TYPE_MX "\00\017"   /* big-endian decimal 15 */
-#define DNS_TYPE_AAAA "\00\034" /* big-endian decimal 28 */
-#define DNS_TYPE_ALL "\00\0377" /* big-endian decimal 255 */
-
-#define DNS_CLASS_IN "\00\01" /* big-endian decimal 1 */
-
 struct DnsPacket {
     const uint8_t* base;
     const uint8_t* end;
@@ -326,6 +319,11 @@ static int _dnsPacket_checkBytes(DnsPacket* packet, int numBytes, const void* by
     return 1;
 }
 
+static int _dnsPacket_checkBE16(DnsPacket* packet, uint16_t v) {
+    uint16_t be16 = htons(v);
+    return _dnsPacket_checkBytes(packet, sizeof(be16), &be16);
+}
+
 /* parse and skip a given QNAME stored in a query packet,
  * from the current cursor position. returns 1 on success,
  * or 0 for malformed data.
@@ -365,16 +363,16 @@ static int _dnsPacket_checkQR(DnsPacket* packet) {
     if (!_dnsPacket_checkQName(packet)) return 0;
 
     /* TYPE must be one of the things we support */
-    if (!_dnsPacket_checkBytes(packet, 2, DNS_TYPE_A) &&
-        !_dnsPacket_checkBytes(packet, 2, DNS_TYPE_PTR) &&
-        !_dnsPacket_checkBytes(packet, 2, DNS_TYPE_MX) &&
-        !_dnsPacket_checkBytes(packet, 2, DNS_TYPE_AAAA) &&
-        !_dnsPacket_checkBytes(packet, 2, DNS_TYPE_ALL)) {
+    if (!_dnsPacket_checkBE16(packet, ns_type::ns_t_a) &&
+        !_dnsPacket_checkBE16(packet, ns_type::ns_t_ptr) &&
+        !_dnsPacket_checkBE16(packet, ns_type::ns_t_mx) &&
+        !_dnsPacket_checkBE16(packet, ns_type::ns_t_aaaa) &&
+        !_dnsPacket_checkBE16(packet, ns_type::ns_t_any /*all*/)) {
         LOG(INFO) << __func__ << ": unsupported TYPE";
         return 0;
     }
     /* CLASS must be IN */
-    if (!_dnsPacket_checkBytes(packet, 2, DNS_CLASS_IN)) {
+    if (!_dnsPacket_checkBE16(packet, ns_class::ns_c_in)) {
         LOG(INFO) << __func__ << ": unsupported CLASS";
         return 0;
     }
```

