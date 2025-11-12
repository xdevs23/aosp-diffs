```diff
diff --git a/plat/qemu/common/common.mk b/plat/qemu/common/common.mk
index 45129d0b6..ba0079e12 100644
--- a/plat/qemu/common/common.mk
+++ b/plat/qemu/common/common.mk
@@ -73,6 +73,7 @@ BL31_SOURCES		+=	${QEMU_CPU_LIBS}				\
 				plat/common/plat_psci_common.c			\
 				${PLAT_QEMU_COMMON_PATH}/aarch64/plat_helpers.S	\
 				${PLAT_QEMU_COMMON_PATH}/qemu_bl31_setup.c	\
+				${PLAT_QEMU_COMMON_PATH}/qemu_trng.c		\
 				common/fdt_fixup.c				\
 				${QEMU_GIC_SOURCES}
 
@@ -110,6 +111,7 @@ ENABLE_TRF_FOR_NS	:=	2
 
 # 8.5
 ENABLE_FEAT_RNG		:=	2
+TRNG_SUPPORT		:=	1
 # TF-A currently does not do dynamic detection of FEAT_SB.
 # Compiler puts SB instruction when it is enabled.
 ENABLE_FEAT_SB		:=	0
diff --git a/plat/qemu/common/qemu_trng.c b/plat/qemu/common/qemu_trng.c
new file mode 100644
index 000000000..5af23fcea
--- /dev/null
+++ b/plat/qemu/common/qemu_trng.c
@@ -0,0 +1,43 @@
+/*
+ * Copyright (c) 2025, ARM Limited and Contributors. All rights reserved.
+ *
+ * SPDX-License-Identifier: BSD-3-Clause
+ */
+
+#include <assert.h>
+#include <stdbool.h>
+#include <stdint.h>
+
+#include <arch_features.h>
+#include <arch_helpers.h>
+#include <plat/common/platform.h>
+#include <services/trng_svc.h>
+
+__attribute__((target("arch=armv8.5-a+rng")))
+bool plat_get_entropy(uint64_t *out)
+{
+	/*
+	 * Read entropy from a freshly seeded RNDRRS register.
+	 * WARNING!!! You SHOULD NOT use this on any platform other than qemu.
+	 * The qemu implementation of RNDRRS pulls entropy from either
+	 * getrandom or /dev/urandom which is secure, but actual hardware
+	 * might use less secure randomness sources.
+	 *
+	 * The builtin returns 1 on failure and 0 on success.
+	 */
+	return !__builtin_arm_rndrrs(out);
+}
+
+DEFINE_SVC_UUID2(qemu_trng_uuid,
+		 0xaa767875, 0xe700, 0x4d66, 0xbf, 0xb0,
+		 0xdb, 0x35, 0xb4, 0xdf, 0x73, 0x25
+);
+uuid_t plat_trng_uuid;
+
+void plat_entropy_setup(void)
+{
+	/* Use the RNDRRS instruction if the CPU supports it */
+	if (is_feat_rng_supported()) {
+		plat_trng_uuid = qemu_trng_uuid;
+	}
+}
```

