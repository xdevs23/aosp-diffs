```diff
diff --git a/lib/el3_runtime/aarch64/context_mgmt.c b/lib/el3_runtime/aarch64/context_mgmt.c
index fdd1388cb..efae4c52f 100644
--- a/lib/el3_runtime/aarch64/context_mgmt.c
+++ b/lib/el3_runtime/aarch64/context_mgmt.c
@@ -753,6 +753,10 @@ static void manage_extensions_nonsecure_el2_unused(void)
 		sme_init_el2_unused();
 	}
 
+	if (is_feat_hcx_supported()) {
+		write_hcrx_el2(HCRX_EL2_INIT_VAL | HCRX_EL2_MSCEn_BIT);
+	}
+
 #if ENABLE_PAUTH
 	enable_pauth_el2();
 #endif /* ENABLE_PAUTH */
diff --git a/plat/qemu/common/common.mk b/plat/qemu/common/common.mk
index 7041073f1..3f3a010b4 100644
--- a/plat/qemu/common/common.mk
+++ b/plat/qemu/common/common.mk
@@ -131,6 +131,7 @@ ifeq (${ENABLE_SVE},0)
 	ENABLE_SME_FOR_NS	:= 0
 else
 	ENABLE_SVE_FOR_NS	:= 2
+	ENABLE_SVE_FOR_SWD	:= 1
 	ENABLE_SME_FOR_NS	:= 2
 endif
 
diff --git a/plat/qemu/common/qemu_bl2_setup.c b/plat/qemu/common/qemu_bl2_setup.c
index e8e79fa7a..f2344f9f2 100644
--- a/plat/qemu/common/qemu_bl2_setup.c
+++ b/plat/qemu/common/qemu_bl2_setup.c
@@ -77,7 +77,7 @@ static void security_setup(void)
 	 */
 }
 
-#ifdef SPD_trusty
+#if defined (SPD_trusty) || defined(SPD_spmd)
 
 #define GIC_SPI 0
 #define GIC_PPI 1
diff --git a/plat/qemu/common/qemu_io_storage.c b/plat/qemu/common/qemu_io_storage.c
index 4c61b1466..ca4006326 100644
--- a/plat/qemu/common/qemu_io_storage.c
+++ b/plat/qemu/common/qemu_io_storage.c
@@ -374,7 +374,7 @@ int qemu_io_register_sp_pkg(const char *name, const char *uuid,
 	pkg->sh_file_spec.mode = FOPEN_MODE_RB;
 
 	mem_params->image_info.image_base = load_addr;
-	mem_params->image_info.image_max_size = SZ_4M;
+	mem_params->image_info.image_max_size = SZ_128M;
 	mem_params->image_info.h.attr &= ~IMAGE_ATTRIB_SKIP_LOADING;
 
 	sp_pkg_count++;
```

