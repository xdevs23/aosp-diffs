```diff
diff --git a/samples/arp_offload_program_gen.py b/samples/arp_offload_program_gen.py
new file mode 100644
index 0000000..b88a4c6
--- /dev/null
+++ b/samples/arp_offload_program_gen.py
@@ -0,0 +1,36 @@
+import argparse
+
+PROGRAM_TEMPLATE = "750010{}08060001080006040002AA300E3CAA0FBA06AA09BA07AA08BA086A01BA09120C84006F08066A0EA30206000108000604032B12147A27017A020203301A1C820200032D68A30206FFFFFFFFFFFF020E1A267E00000002{}032C020B1A267E00000002{}032CAB24003CCA0606CB0306CB090ACB0306C6{}CA0606CA1C04AA0A3A12AA1AAA25FFFF032F020D120C84001708000A1782100612149C00091FFFAB0D2A10820207032A02117C000E86DD68A30206FFFFFFFFFFFF021603190A1482020002187A023A02120A36820285031F8216886A26A2020FFF020000000000000000000000000003200214"
+
+def generate_apf_program(mac_raw, ip_raw):
+    """
+    Generates an APF program that support ARP offload
+
+    Args:
+        mac_raw (str): The MAC address (colon-separated hexadecimal values).
+        ip_raw (str): The IPv4 address (dot-separated decimal values).
+
+    Returns:
+        str: The generated APF program hex string.
+    """
+    mac_list = mac_raw.split(":")
+    ip_list = ip_raw.split(".")
+
+    ip_addr = "".join(["{:02x}".format(int(i)) for i in ip_list])
+    mac_addr = "".join(mac_list)
+
+    return PROGRAM_TEMPLATE.format(mac_addr, ip_addr, ip_addr, ip_addr)
+
+
+def main():
+    parser = argparse.ArgumentParser(description="Generate an ARP offload APF program.")
+    parser.add_argument("mac", help="The DUT's MAC address (e.g., '00:11:22:33:44:55')")
+    parser.add_argument("ip", help="The DUT's IPv4 address (e.g., '192.168.1.100')")
+    args = parser.parse_args()
+
+    out_program = generate_apf_program(args.mac, args.ip)
+    print("APF Program:\n", out_program)
+
+
+if __name__ == '__main__':
+    main()
diff --git a/v7/apf_interpreter.c b/v7/apf_interpreter.c
index c4ef59e..635ee3e 100644
--- a/v7/apf_interpreter.c
+++ b/v7/apf_interpreter.c
@@ -789,6 +789,7 @@ static int do_apf_run(apf_context* ctx) {
                 /* Catch overflow/wrap-around. */
                 ASSERT_RETURN(end_offs >= offs);
                 ASSERT_IN_PACKET_BOUNDS(end_offs);
+                /* load_size underflow on final iteration not an issue as not used after loop. */
                 while (load_size--) val = (val << 8) | read_packet_u8(ctx, offs++);
                 REG = val;
             }
@@ -846,6 +847,7 @@ static int do_apf_run(apf_context* ctx) {
             /* Note: this will return EXCEPTION (due to wrap) if imm_len (ie. len) is 0 */
             ASSERT_RETURN(last_packet_offs >= ctx->R[0]);
             ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
+            /* cnt underflow on final iteration not an issue as not used after loop. */
             while (cnt--) {
                 matched |= !memcmp(ctx->program + ctx->pc, ctx->packet + ctx->R[0], len);
                 /* skip past comparison bytes */
@@ -1022,6 +1024,7 @@ static int do_apf_run(apf_context* ctx) {
                 u8 len = ((imm3 >> 1) & 3) + 1;  /* size [1..4] in bytes of an element */
                 u8 cnt = (imm3 >> 3) + 2;  /* number [2..33] of elements in set */
                 if (ctx->pc + cnt * len > ctx->program_len) return EXCEPTION;
+                /* cnt underflow on final iteration not an issue as not used after loop. */
                 while (cnt--) {
                     u32 v = 0;
                     int i;
@@ -1060,10 +1063,12 @@ static int do_apf_run(apf_context* ctx) {
                 ASSERT_IN_DATA_BOUNDS(offs, size);
                 if (opcode == LDDW_OPCODE) {
                     u32 val = 0;
+                    /* size underflow on final iteration not an issue as not used after loop. */
                     while (size--) val = (val << 8) | ctx->program[offs++];
                     REG = val;
                 } else {
                     u32 val = REG;
+                    /* size underflow on final iteration not an issue as not used after loop. */
                     while (size--) {
                         ctx->program[offs++] = (val >> 24);
                         val <<= 8;
@@ -1089,6 +1094,7 @@ static int do_apf_run(apf_context* ctx) {
             return EXCEPTION;  /* Bail out */
         }
       }
+    /* instructions_remaining underflow on final iteration not an issue as not used after loop. */
     } while (instructions_remaining--);
     return EXCEPTION;
 }
diff --git a/v7/apf_interpreter_source.c b/v7/apf_interpreter_source.c
index a36a4ee..6a70472 100644
--- a/v7/apf_interpreter_source.c
+++ b/v7/apf_interpreter_source.c
@@ -243,6 +243,7 @@ static int do_apf_run(apf_context* ctx) {
                 // Catch overflow/wrap-around.
                 ASSERT_RETURN(end_offs >= offs);
                 ASSERT_IN_PACKET_BOUNDS(end_offs);
+                // load_size underflow on final iteration not an issue as not used after loop.
                 while (load_size--) val = (val << 8) | read_packet_u8(ctx, offs++);
                 REG = val;
             }
@@ -300,6 +301,7 @@ static int do_apf_run(apf_context* ctx) {
             // Note: this will return EXCEPTION (due to wrap) if imm_len (ie. len) is 0
             ASSERT_RETURN(last_packet_offs >= ctx->R[0]);
             ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
+            // cnt underflow on final iteration not an issue as not used after loop.
             while (cnt--) {
                 matched |= !memcmp(ctx->program + ctx->pc, ctx->packet + ctx->R[0], len);
                 // skip past comparison bytes
@@ -476,6 +478,7 @@ static int do_apf_run(apf_context* ctx) {
                 u8 len = ((imm3 >> 1) & 3) + 1;  // size [1..4] in bytes of an element
                 u8 cnt = (imm3 >> 3) + 2;  // number [2..33] of elements in set
                 if (ctx->pc + cnt * len > ctx->program_len) return EXCEPTION;
+                // cnt underflow on final iteration not an issue as not used after loop.
                 while (cnt--) {
                     u32 v = 0;
                     int i;
@@ -514,10 +517,12 @@ static int do_apf_run(apf_context* ctx) {
                 ASSERT_IN_DATA_BOUNDS(offs, size);
                 if (opcode == LDDW_OPCODE) {
                     u32 val = 0;
+                    // size underflow on final iteration not an issue as not used after loop.
                     while (size--) val = (val << 8) | ctx->program[offs++];
                     REG = val;
                 } else {
                     u32 val = REG;
+                    // size underflow on final iteration not an issue as not used after loop.
                     while (size--) {
                         ctx->program[offs++] = (val >> 24);
                         val <<= 8;
@@ -543,6 +548,7 @@ static int do_apf_run(apf_context* ctx) {
             return EXCEPTION;  // Bail out
         }
       }
+    // instructions_remaining underflow on final iteration not an issue as not used after loop.
     } while (instructions_remaining--);
     return EXCEPTION;
 }
```

