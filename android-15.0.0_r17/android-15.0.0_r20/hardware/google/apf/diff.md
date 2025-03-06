```diff
diff --git a/apf_run.c b/apf_run.c
index c2df5c1..2495547 100644
--- a/apf_run.c
+++ b/apf_run.c
@@ -160,10 +160,15 @@ void maybe_print_tracing_header() {
 
 }
 
-void print_transmitted_packet() {
-    printf("transmitted packet: ");
-    print_hex(apf_test_buffer, (int) apf_test_tx_packet_len);
-    printf("\n");
+void print_all_transmitted_packets() {
+    printf("transmitted packet: \n");
+    packet_buffer* current = head;
+    while (current) {
+        printf("\t");
+        print_hex(current->data, (int) current->len);
+        printf("\n");
+        current = current->next;
+    }
 }
 
 // Process packet through APF filter
@@ -395,8 +400,8 @@ int main(int argc, char* argv[]) {
         }
     }
 
-    if (use_apf_v6_interpreter && apf_test_tx_packet_len != 0) {
-        print_transmitted_packet();
+    if (use_apf_v6_interpreter && head != NULL) {
+        print_all_transmitted_packets();
     }
 
     free(program);
diff --git a/disassembler.c b/disassembler.c
index 2e93c3c..9417466 100644
--- a/disassembler.c
+++ b/disassembler.c
@@ -14,12 +14,11 @@
  * limitations under the License.
  */
 
+#include <stdbool.h>
 #include <stdint.h>
 #include <stdio.h>
 #include <stdarg.h>
 
-typedef enum { false, true } bool;
-
 #include "v7/apf_defs.h"
 #include "v7/apf.h"
 #include "disassembler.h"
diff --git a/samples/mdns_offload_program_gen.py b/samples/mdns_offload_program_gen.py
new file mode 100644
index 0000000..5f5dbea
--- /dev/null
+++ b/samples/mdns_offload_program_gen.py
@@ -0,0 +1,92 @@
+import argparse
+import binascii
+
+def generate_apf_program(device_name, mac_raw, ip_raw):
+    """
+    Generates an APF program that supports mDNS offload.
+
+    Args:
+      device_name: The device name.
+      mac_raw: The MAC address in raw string format (e.g., "00:11:22:33:44:55").
+      ip_raw: The IPv4 address in raw string format (e.g., "192.168.1.100").
+
+    Returns:
+      The generated APF program as a hex string.
+    """
+    mac_list = mac_raw.split(":")
+    ip_list = ip_raw.split(".")
+
+    ip_addr = "".join([f"{int(i):02x}" for i in ip_list])
+    mac_addr = "".join(mac_list)
+
+    device_name_hex = binascii.hexlify(device_name.encode()).decode()
+
+    program = (
+        "7501430203040506070806000108000604000201005E0000FB0203040506"
+        "070800450000000000401100000A000001E00000FB14E914E90000840000"
+        "000004000000000B5F676F6F676C6563617374045F746370056C6F63616C"
+        "00000C000100000078001F066161616161610B5F676F6F676C6563617374"
+        "045F746370056C6F63616C00066161616161610B5F676F6F676C65636173"
+        "74045F746370056C6F63616C0000210001000000780015000000001F4907"
+        "416E64726F6964056C6F63616C00066161616161610B5F676F6F676C6563"
+        "617374045F746370056C6F63616C000010000100000078000605656D7074"
+        "7907416E64726F6964056C6F63616C000001000100000078000401010101"
+        "3333000000FB02030405060786DD600000001140FE800000000000000000"
+        "000000000003FF0200000000000000000000000000FB14E914E9AA3009E5"
+        "AA0FBA06AA09BA07AA08BA086A03BA096A06A20206020304050607021112"
+        "0CAA2F021A888E080686DD88B40800033484006F08066A0EA30206000108"
+        "000604033B12147A27017A020203401A1C820200033D68A30206FFFFFFFF"
+        "FFFF020E1A267E000000020A000001033C020B1A267E000000020A000001"
+        "033CAB24003CCA0606CB0306CB090ACB0306C60A000001CA0606CA1C04AA"
+        "0A3A12AA1AAA25FFFF033F020D68A40130100602030405060701005E0000"
+        "FB3333000000FB120C8400290800AA0E8A023502121A14563FFF00FF8401"
+        "1600111A1E860000010BE00000FB122484010414E96A2A722A120C8400F9"
+        "86DD0A1482F4116A26A2DF10FF0200000000000000000000000000FB1238"
+        "8400D814E96A3EAB2B720C0B5F474F4F474C4543415354045F544350054C"
+        "4F43414C0000AB2B4E21064141414141410B5F474F4F474C454341535404"
+        "5F544350054C4F43414C0000AB2B2A10064141414141410B5F474F4F474C"
+        "4543415354045F544350054C4F43414C0000AB2B160107414E44524F4944"
+        "054C4F43414C0000AB2B021C07414E44524F4944054C4F43414C00007245"
+        "120C84001E0800AB240101CB1310C400F3CB2314C600DF0000CB37D7AB25"
+        "0E281A00F00339AB240115CD010E12C400DFCD012026C600DF0000CB37D7"
+        "AB250E3C1600F003390338120C84006508001A14563FFF00FF821511AB0D"
+        "2A10820E446A3238A2020602030405060702100A1E52F08202E003271A1E"
+        "8600000002FFFFFFFF032586000000020A0000FF03260A1782100612149C"
+        "00091FFFAB0D2A10820207033A68A30206FFFFFFFFFFFF0214032402127C"
+        "000E86DD68A30206FFFFFFFFFFFF021C031F0A14820200021E7A093A0A26"
+        "8202FF032E021B0A36840125008768A5000228063333000000013333FF44"
+        "11223333FF5566773333FFBBCCDD020304050607FFFFFFFFFFFF03306A26"
+        "A2110DFF0200000000000000000001FF3A0DA500020803000003BBCCDD03"
+        "307227A500020810FE800000000000000000000000000003200100000000"
+        "00000100001BAABBCCDD03300A157A02FF032F12128A0217032F0A377A02"
+        "00032F6A3EA500020810FE80000000000000000000000000000320010000"
+        "000000000100001BAABBCCDD03306A16A202100000000000000000000000"
+        "0000000000021712128A021F02190A4E7A020102190A16AA2F0201FF0003"
+        "2F0A509A02017202032FAB240056CA5006CB0306C486DDC660000000C600"
+        "203AFFCA3E10CA1610C688000020C6E0000000CA3E10C40201CB0306AA25"
+        "0E3816003A0331820285032A8216886A26A2020FFF020000000000000000"
+        "0000000000032B0215"
+    )
+    program = program.replace("020304050607", mac_addr)
+    program = program.replace("0A000001", ip_addr)
+    program = program.replace("01010101", ip_addr)
+    program = program.replace("616161616161", device_name_hex)
+    return program
+
+def main():
+    """
+    The main method.
+    """
+    parser = argparse.ArgumentParser(description="Generate an mDNS offload APF program.")
+    parser.add_argument("device_name", help="The DUT's device name, length must be 6 (e.g., 'gambit')")
+    parser.add_argument("mac", help="The DUT's MAC address (e.g., '00:11:22:33:44:55')")
+    parser.add_argument("ip", help="The DUT's IPv4 address (e.g., '192.168.1.100')")
+    args = parser.parse_args()
+    if len(args.device_name) != 6:
+        raise ValueError(f"Invalid input length: expected 6, got {len(args.device_name)}")
+    out_program = generate_apf_program(args.device_name, args.mac, args.ip)
+    print("APF Program:\n", out_program)
+
+
+if __name__ == '__main__':
+    main()
diff --git a/v7/test_buf_allocator.c b/v7/test_buf_allocator.c
index e30815e..2f98d17 100644
--- a/v7/test_buf_allocator.c
+++ b/v7/test_buf_allocator.c
@@ -14,37 +14,65 @@
  * limitations under the License.
  */
 
+#include <stdio.h>
+#include <stdlib.h>
 #include <string.h>
 
 #include "apf_interpreter.h"
 #include "test_buf_allocator.h"
 
-uint8_t apf_test_buffer[sizeof(apf_test_buffer)];
-uint32_t apf_test_tx_packet_len;
+packet_buffer *head = NULL;
+packet_buffer *tail = NULL;
 uint8_t apf_test_tx_dscp;
 
 /**
  * Test implementation of apf_allocate_buffer()
  *
- * Clean up the apf_test_buffer and return the pointer to beginning of the buffer region.
+ * This is a reference apf_allocate_buffer() implementation for testing purpose.
+ * It supports being called multiple times for each apf_run().
+ * Allocate a new buffer and attach next to the current buffer, then move the current to it.
+ * Return the pointer to beginning of the allocated buffer region.
  */
 uint8_t* apf_allocate_buffer(__attribute__ ((unused)) void* ctx, uint32_t size) {
-  if (size > sizeof(apf_test_buffer)) {
+  if (size > BUFFER_SIZE) {
     return NULL;
   }
-  return apf_test_buffer;
+
+  packet_buffer* ptr = (packet_buffer *) malloc(sizeof(packet_buffer));
+  if (!ptr) {
+    fprintf(stderr, "failed to allocate buffer!\n");
+    return NULL;
+  }
+
+  memset(ptr->data, 0xff, sizeof(ptr->data));
+  ptr->next = NULL;
+  ptr->len = 0;
+
+  if (!head) {
+    // the first buffer allocated
+    head = ptr;
+    tail = head;
+  } else {
+    // append allocated buffer, and move current to the next
+    tail->next = ptr;
+    tail = tail->next;
+  }
+
+  return ptr->data;
 }
 
 /**
  * Test implementation of apf_transmit_buffer()
  *
- * Copy the content of allocated buffer to the apf_test_tx_packet region.
+ * This is a reference apf_transmit_buffer() implementation for testing purpose.
+ * Update the buffer length and dscp value from the transmit packet.
  */
 int apf_transmit_buffer(__attribute__((unused)) void* ctx, uint8_t* ptr,
                         uint32_t len, uint8_t dscp) {
   if (len && len < ETH_HLEN) return -1;
-  if (ptr != apf_test_buffer) return -1;
-  apf_test_tx_packet_len = len;
+  if (!tail || (ptr != tail->data)) return -1;
+
+  tail->len = len;
   apf_test_tx_dscp = dscp;
   return 0;
 }
diff --git a/v7/test_buf_allocator.h b/v7/test_buf_allocator.h
index c5fa5c4..6ac81ec 100644
--- a/v7/test_buf_allocator.h
+++ b/v7/test_buf_allocator.h
@@ -20,8 +20,16 @@
 #include <stdint.h>
 #include <linux/if_ether.h>
 
-extern uint8_t apf_test_buffer[1514];
-extern uint32_t apf_test_tx_packet_len;
+#define BUFFER_SIZE 1514
+
+typedef struct packet_buffer {
+    uint8_t data[BUFFER_SIZE];
+    uint32_t len;
+    struct packet_buffer *next;
+} packet_buffer;
+
+extern packet_buffer *head;
+extern packet_buffer *tail;
 extern uint8_t apf_test_tx_dscp;
 
 #endif  // TEST_BUF_ALLOCATOR
```

