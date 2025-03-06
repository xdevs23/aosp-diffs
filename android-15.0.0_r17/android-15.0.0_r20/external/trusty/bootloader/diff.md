```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..98ad440
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_external_trusty_bootloader",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/interface/include/interface/secretkeeper/secretkeeper.h b/interface/include/interface/secretkeeper/secretkeeper.h
index f8dd3d6..7164f21 100644
--- a/interface/include/interface/secretkeeper/secretkeeper.h
+++ b/interface/include/interface/secretkeeper/secretkeeper.h
@@ -34,7 +34,7 @@
  *                                 Secretkeeper.
  */
 enum secretkeeper_cmd {
-    SECRETKEEPER_RESPONSE_MARKER = 0x1 << 31,
+    SECRETKEEPER_RESPONSE_MARKER = 0x1u << 31,
     SECRETKEEPER_CMD_GET_IDENTITY = 1,
 };
 
diff --git a/ql-tipc/include/trusty/trusty_dev.h b/ql-tipc/include/trusty/trusty_dev.h
index 733261c..5e91170 100644
--- a/ql-tipc/include/trusty/trusty_dev.h
+++ b/ql-tipc/include/trusty/trusty_dev.h
@@ -60,6 +60,11 @@ int trusty_dev_shutdown(struct trusty_dev* dev);
  */
 int trusty_dev_nop(struct trusty_dev* dev);
 
+/*
+ * Initialize the interrupt controller
+ */
+int arch_gic_init(int cpu);
+
 /*
  * Invokes creation of queueless Trusty IPC device on the secure side.
  * @buf will be mapped into Trusty's address space.
diff --git a/test-runner/arm64/arch.c b/test-runner/arm64/arch.c
index 0077c26..41b4278 100644
--- a/test-runner/arm64/arch.c
+++ b/test-runner/arm64/arch.c
@@ -24,6 +24,7 @@
 
 #include <test-runner-arch.h>
 
+#include <assert.h>
 #include <stdbool.h>
 #include <stddef.h>
 #include <stdint.h>
@@ -50,7 +51,7 @@
 static uint32_t doorbell_irq;
 #endif
 
-void boot_arm64(int cpu) {
+int arch_gic_init(int cpu) {
 #if GIC_VERSION > 2
     if (!cpu) {
         GICDREG_WRITE(GICD_CTLR, 2); /* Enable Non-secure group 1 interrupt */
@@ -61,11 +62,12 @@ void boot_arm64(int cpu) {
          * We only support per-cpu doorbell interrupts which are all enabled by
          * GICR_ISENABLER0.
          */
-        return;
+        return -1;
     }
     GICRREG_WRITE(cpu, GICR_ISENABLER0, 1U << doorbell_irq);
     GICRREG_WRITE(cpu, GICR_ISENABLER0, 1U << 0); /* skip_cpu0_wfi interrupt */
     __asm__ volatile("msr icc_igrpen1_el1, %0" ::"r"(1UL));
 #endif
-    boot(cpu);
+
+    return 0;
 }
diff --git a/test-runner/arm64/asm.S b/test-runner/arm64/asm.S
index e038968..ce85cf9 100644
--- a/test-runner/arm64/asm.S
+++ b/test-runner/arm64/asm.S
@@ -75,7 +75,7 @@ vbar_setup_done:
     mov sp, x2
 
     /* Jump to c-code */
-    bl boot_arm64
+    bl boot
     /* fall-through */
 
 error:
diff --git a/test-runner/test-runner.c b/test-runner/test-runner.c
index 9ef66b8..48063b0 100644
--- a/test-runner/test-runner.c
+++ b/test-runner/test-runner.c
@@ -81,6 +81,11 @@ void boot(int cpu) {
     struct virtio_console* console;
 
     if (cpu) {
+        ret = arch_gic_init(cpu);
+        if (ret != 0) {
+            return;
+        }
+
         while (true) {
             ret = trusty_dev_nop(&trusty_dev);
             if (ret >= 0) {
@@ -123,6 +128,11 @@ void boot(int cpu) {
         return;
     }
 
+    ret = arch_gic_init(cpu);
+    if (ret != 0) {
+        return;
+    }
+
     /* Create Trusty IPC device */
     ret = trusty_ipc_dev_create(&ipc_dev, &trusty_dev, PAGE_SIZE);
     if (ret != 0) {
```

