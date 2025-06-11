```diff
diff --git a/Android.bp b/Android.bp
index 61c63ebb..c8a26d7f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -100,14 +100,6 @@ filegroup {
     ],
 }
 
-cc_library_static {
-    name: "tlcl",
-    defaults: ["vboot_defaults"],
-    host_supported: true,
-    vendor_available: true,
-    srcs: [":tlcl_srcs"],
-}
-
 filegroup {
     name: "vboot_fw_srcs",
     srcs: [
@@ -153,14 +145,6 @@ filegroup {
     ],
 }
 
-cc_library_static {
-    name: "vboot_fw",
-    defaults: ["vboot_defaults"],
-    host_supported: true,
-    vendor_available: true,
-    srcs: [":vboot_fw_srcs"],
-}
-
 cc_defaults {
     name: "libvboot_defaults",
     defaults: ["vboot_defaults"],
@@ -415,8 +399,7 @@ cc_binary {
 cc_binary {
     name: "crossystem",
     defaults: ["vboot_defaults"],
-    host_supported: true,
-    vendor_available: true,
+    vendor: true,
 
     srcs: ["utility/crossystem.c"],
     static_libs: ["libvboot_util"],
diff --git a/METADATA b/METADATA
index 3693fb56..cc9bf53d 100644
--- a/METADATA
+++ b/METADATA
@@ -8,14 +8,14 @@ third_party {
   license_type: RESTRICTED
   license_note: "would be NOTICE save for scripts/image_signing/lib/shflags/shflags"
   last_upgrade_date {
-    year: 2024
-    month: 11
-    day: 13
+    year: 2025
+    month: 2
+    day: 19
   }
   identifier {
     type: "Git"
     value: "https://chromium.googlesource.com/chromiumos/platform/vboot_reference"
-    version: "0d49b8fdf002fa9cfa573ca1509ed8a1a0cf26d5"
+    version: "ae6ceb20d5e2938a366e22c2a550a02772788825"
     primary_source: true
   }
 }
diff --git a/Makefile b/Makefile
index 1bb6d35e..e974e2a1 100644
--- a/Makefile
+++ b/Makefile
@@ -160,6 +160,8 @@ CFLAGS ?= -fvisibility=hidden -fomit-frame-pointer \
 else ifeq (${FIRMWARE_ARCH},x86_64)
 CFLAGS ?= ${FIRMWARE_FLAGS} ${COMMON_FLAGS} -fvisibility=hidden \
 	-fomit-frame-pointer
+else ifeq (${FIRMWARE_ARCH},riscv)
+CC ?= riscv64-linux-gnu-gcc
 else ifeq (${FIRMWARE_ARCH},mock)
 FIRMWARE_STUB := 1
 CFLAGS += ${TEST_FLAGS}
@@ -281,26 +283,30 @@ endif
 LIBZIP_VERSION := $(shell ${PKG_CONFIG} --modversion libzip 2>/dev/null)
 HAVE_LIBZIP := $(if ${LIBZIP_VERSION},1)
 ifneq ($(filter-out 0,${HAVE_LIBZIP}),)
-  CFLAGS += -DHAVE_LIBZIP $(shell ${PKG_CONFIG} --cflags libzip)
+  LIBZIP_CFLAGS := $(shell ${PKG_CONFIG} --cflags libzip)
+  CFLAGS += -DHAVE_LIBZIP $(LIBZIP_CFLAGS)
   LIBZIP_LIBS := $(shell ${PKG_CONFIG} --libs libzip)
 endif
 
 LIBARCHIVE_VERSION := $(shell ${PKG_CONFIG} --modversion libarchive 2>/dev/null)
 HAVE_LIBARCHIVE := $(if ${LIBARCHIVE_VERSION},1)
 ifneq ($(filter-out 0,${HAVE_LIBARCHIVE}),)
-  CFLAGS += -DHAVE_LIBARCHIVE $(shell ${PKG_CONFIG} --cflags libarchive)
+  LIBARCHIVE_CFLAGS := $(shell ${PKG_CONFIG} --cflags libarchive)
+  CFLAGS += -DHAVE_LIBARCHIVE $(LIBARCHIVE_CFLAGS)
   LIBARCHIVE_LIBS := $(shell ${PKG_CONFIG} --libs libarchive)
 endif
 
 HAVE_CROSID := $(shell ${PKG_CONFIG} --exists crosid && echo 1)
 ifeq ($(HAVE_CROSID),1)
-  CFLAGS += -DHAVE_CROSID $(shell ${PKG_CONFIG} --cflags crosid)
+  CROSID_CFLAGS := $(shell ${PKG_CONFIG} --cflags crosid)
+  CFLAGS += -DHAVE_CROSID $(CROSID_CFLAGS)
   CROSID_LIBS := $(shell ${PKG_CONFIG} --libs crosid)
 endif
 
 HAVE_NSS := $(shell ${PKG_CONFIG} --exists nss && echo 1)
 ifeq ($(HAVE_NSS),1)
-  CFLAGS += -DHAVE_NSS $(shell ${PKG_CONFIG} --cflags nss)
+  NSS_CFLAGS := $(shell ${PKG_CONFIG} --cflags nss)
+  CFLAGS += -DHAVE_NSS $(NSS_CFLAGS)
   # The LIBS is not needed because we only use the header.
 else
   $(warning Missing NSS. PKCS11 signing not supported. Install libnss3 to enable this feature.)
@@ -674,6 +680,7 @@ SIGNING_SCRIPTS_BOARD = \
 	scripts/image_signing/make_dev_firmware.sh \
 	scripts/image_signing/make_dev_ssd.sh \
 	scripts/image_signing/resign_firmwarefd.sh \
+	scripts/image_signing/swap_ec_rw \
 	scripts/image_signing/common_minimal.sh
 
 # SDK installations have some extra scripts.
@@ -900,7 +907,7 @@ FUZZ_TEST_BINS = $(addprefix ${BUILD}/,${FUZZ_TEST_NAMES})
 # so it happens before trying to generate/include dependencies.
 SUBDIRS := firmware host cgpt utility futility tests tests/tpm_lite
 _dir_create := $(foreach d, \
-	$(shell find ${SUBDIRS} -name '*.c' -exec  dirname {} \; | sort -u), \
+	$(shell find ${SUBDIRS} -name '*.c' -exec  dirname {} + | sort -u), \
 	$(shell [ -d ${BUILD}/${d} ] || mkdir -p ${BUILD}/${d}))
 
 .PHONY: clean
@@ -1149,7 +1156,7 @@ FUTIL_LIBS = ${CROSID_LIBS} ${CRYPTO_LIBS} ${LIBZIP_LIBS} ${LIBARCHIVE_LIBS} \
 	${FLASHROM_LIBS}
 
 ${FUTIL_BIN}: LDLIBS += ${FUTIL_LIBS}
-${FUTIL_BIN}: ${FUTIL_OBJS} ${UTILLIB} ${FWLIB}
+${FUTIL_BIN}: ${FUTIL_OBJS} ${UTILLIB}
 	@${PRINTF} "    LD            $(subst ${BUILD}/,,$@)\n"
 	${Q}${LD} -o $@ ${LDFLAGS} $^ ${LDLIBS}
 
diff --git a/OWNERS b/OWNERS
index 76c3e8a0..ee750964 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,3 +3,4 @@ yupingso@chromium.org
 hungte@chromium.org
 roccochen@chromium.org
 czapiga@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/cgpt/cgpt.h b/cgpt/cgpt.h
index b584dc02..7f9276fc 100644
--- a/cgpt/cgpt.h
+++ b/cgpt/cgpt.h
@@ -99,6 +99,7 @@ int Save(struct drive *drive, const uint8_t *buf,
 extern const Guid guid_chromeos_firmware;
 extern const Guid guid_chromeos_kernel;
 extern const Guid guid_chromeos_rootfs;
+extern const Guid guid_android_vbmeta;
 extern const Guid guid_linux_data;
 extern const Guid guid_chromeos_reserved;
 extern const Guid guid_efi;
@@ -165,7 +166,9 @@ void UpdateCrc(GptData *gpt);
 int IsSynonymous(const GptHeader* a, const GptHeader* b);
 
 int IsUnused(struct drive *drive, int secondary, uint32_t index);
-int IsKernel(struct drive *drive, int secondary, uint32_t index);
+int IsBootable(struct drive *drive, int secondary, uint32_t index);
+
+uint64_t DriveLastUsableLBA(const struct drive *drive);
 
 // Optional. Applications that need this must provide an implementation.
 //
diff --git a/cgpt/cgpt_common.c b/cgpt/cgpt_common.c
index b7366fc8..e4629236 100644
--- a/cgpt/cgpt_common.c
+++ b/cgpt/cgpt_common.c
@@ -392,6 +392,15 @@ int DriveClose(struct drive *drive, int update_as_needed) {
   return errors ? CGPT_FAILED : CGPT_OK;
 }
 
+uint64_t DriveLastUsableLBA(const struct drive *drive) {
+  GptHeader *h = (GptHeader *)drive->gpt.primary_header;
+
+  if (!(drive->gpt.flags & GPT_FLAG_EXTERNAL))
+    return (drive->gpt.streaming_drive_sectors - GPT_HEADER_SECTORS
+            - CalculateEntriesSectors(h, drive->gpt.sector_bytes) - 1);
+
+  return (drive->gpt.streaming_drive_sectors - 1);
+}
 
 /* GUID conversion functions. Accepted format:
  *
@@ -667,6 +676,7 @@ int UTF8ToUTF16(const uint8_t *utf8, uint16_t *utf16, unsigned int maxoutput)
 const Guid guid_chromeos_firmware = GPT_ENT_TYPE_CHROMEOS_FIRMWARE;
 const Guid guid_chromeos_kernel =   GPT_ENT_TYPE_CHROMEOS_KERNEL;
 const Guid guid_chromeos_rootfs =   GPT_ENT_TYPE_CHROMEOS_ROOTFS;
+const Guid guid_android_vbmeta =    GPT_ENT_TYPE_ANDROID_VBMETA;
 const Guid guid_basic_data =        GPT_ENT_TYPE_BASIC_DATA;
 const Guid guid_linux_data =        GPT_ENT_TYPE_LINUX_FS;
 const Guid guid_chromeos_reserved = GPT_ENT_TYPE_CHROMEOS_RESERVED;
@@ -683,6 +693,7 @@ static const struct {
   {&guid_chromeos_firmware, "firmware", "ChromeOS firmware"},
   {&guid_chromeos_kernel, "kernel", "ChromeOS kernel"},
   {&guid_chromeos_rootfs, "rootfs", "ChromeOS rootfs"},
+  {&guid_android_vbmeta, "vbmeta", "Android vbmeta"},
   {&guid_linux_data, "data", "Linux data"},
   {&guid_basic_data, "basicdata", "Basic data"},
   {&guid_chromeos_reserved, "reserved", "ChromeOS reserved"},
@@ -875,10 +886,11 @@ int IsUnused(struct drive *drive, int secondary, uint32_t index) {
   return GuidIsZero(&entry->type);
 }
 
-int IsKernel(struct drive *drive, int secondary, uint32_t index) {
+int IsBootable(struct drive *drive, int secondary, uint32_t index) {
   GptEntry *entry;
   entry = GetEntry(&drive->gpt, secondary, index);
-  return GuidEqual(&entry->type, &guid_chromeos_kernel);
+  return (GuidEqual(&entry->type, &guid_chromeos_kernel) ||
+	  GuidEqual(&entry->type, &guid_android_vbmeta));
 }
 
 
diff --git a/cgpt/cgpt_create.c b/cgpt/cgpt_create.c
index 696a9c24..0d5ef8bc 100644
--- a/cgpt/cgpt_create.c
+++ b/cgpt/cgpt_create.c
@@ -96,13 +96,10 @@ static int GptCreate(struct drive *drive, CgptCreateParams *params) {
       h->entries_lba += params->padding;
       h->first_usable_lba = h->entries_lba + CalculateEntriesSectors(h,
                                                drive->gpt.sector_bytes);
-      h->last_usable_lba =
-        (drive->gpt.streaming_drive_sectors - GPT_HEADER_SECTORS -
-          CalculateEntriesSectors(h, drive->gpt.sector_bytes) - 1);
     } else {
       h->first_usable_lba = params->padding;
-      h->last_usable_lba = (drive->gpt.streaming_drive_sectors - 1);
     }
+    h->last_usable_lba = DriveLastUsableLBA(drive);
 
     size_t entries_size = h->number_of_entries * h->size_of_entry;
     AllocAndClear(&drive->gpt.primary_entries, entries_size);
diff --git a/cgpt/cgpt_prioritize.c b/cgpt/cgpt_prioritize.c
index 3883be5c..d80e4bdd 100644
--- a/cgpt/cgpt_prioritize.c
+++ b/cgpt/cgpt_prioritize.c
@@ -133,7 +133,7 @@ int CgptPrioritize(CgptPrioritizeParams *params) {
     }
     index = params->set_partition - 1;
     // it must be a kernel
-    if (!IsKernel(&drive, PRIMARY, index)) {
+    if (!IsBootable(&drive, PRIMARY, index)) {
       Error("partition %d is not a ChromeOS kernel\n", params->set_partition);
       goto bad;
     }
@@ -142,7 +142,7 @@ int CgptPrioritize(CgptPrioritizeParams *params) {
   // How many kernel partitions do I have?
   num_kernels = 0;
   for (i = 0; i < max_part; i++) {
-    if (IsKernel(&drive, PRIMARY, i))
+    if (IsBootable(&drive, PRIMARY, i))
       num_kernels++;
   }
 
@@ -150,7 +150,7 @@ int CgptPrioritize(CgptPrioritizeParams *params) {
     // Determine the current priority groups
     groups = NewGroupList(num_kernels);
     for (i = 0; i < max_part; i++) {
-      if (!IsKernel(&drive, PRIMARY, i))
+      if (!IsBootable(&drive, PRIMARY, i))
         continue;
 
       priority = GetPriority(&drive, PRIMARY, i);
diff --git a/cgpt/cgpt_repair.c b/cgpt/cgpt_repair.c
index 05537709..b8af65f7 100644
--- a/cgpt/cgpt_repair.c
+++ b/cgpt/cgpt_repair.c
@@ -34,5 +34,40 @@ int CgptRepair(CgptRepairParams *params) {
   if (drive.gpt.modified & GPT_MODIFIED_HEADER2)
     printf("Secondary Header is updated.\n");
 
+  /*
+   * If the drive size increased (say, volume expansion),
+   * the secondary header/entries moved to end of drive,
+   * but both headers do not reflect the new drive size
+   * (Alternate LBA in primary; Last Usable LBA in both).
+   *
+   * Per the UEFI spec, first move the secondary header
+   * to the end of drive (done above), and later update
+   * primary/secondary headers to reflect the new size.
+   *
+   * Note: do not check for last_usable_lba, as it does
+   * not change if '-D' is specified (run_cgpt_tests.sh).
+   */
+  GptHeader *primary = (GptHeader *)(drive.gpt.primary_header);
+  GptHeader *secondary = (GptHeader *)(drive.gpt.secondary_header);
+  if ((primary->alternate_lba < secondary->my_lba) &&
+      drive.gpt.modified == (GPT_MODIFIED_HEADER2 | GPT_MODIFIED_ENTRIES2)) {
+    printf("Drive size expansion detected; headers update required.\n");
+
+    if (CGPT_OK != DriveClose(&drive, 1))
+      return CGPT_FAILED;
+    if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR,
+                             params->drive_size))
+      return CGPT_FAILED;
+
+    primary = (GptHeader *)(drive.gpt.primary_header);
+    secondary = (GptHeader *)(drive.gpt.secondary_header);
+    primary->alternate_lba = secondary->my_lba;
+    primary->last_usable_lba = secondary->last_usable_lba
+                             = DriveLastUsableLBA(&drive);
+    drive.gpt.modified = GPT_MODIFIED_HEADER1 | GPT_MODIFIED_HEADER2;
+    UpdateCrc(&drive.gpt);
+    printf("Primary Header updated.\n");
+    printf("Secondary Header updated.\n");
+  }
   return DriveClose(&drive, 1);
 }
diff --git a/cgpt/cgpt_show.c b/cgpt/cgpt_show.c
index 7d481e95..fc1e3de5 100644
--- a/cgpt/cgpt_show.c
+++ b/cgpt/cgpt_show.c
@@ -123,7 +123,8 @@ void EntryDetails(GptEntry *entry, uint32_t index, int raw) {
 
   clen = 0;
   if (!raw) {
-    if (GuidEqual(&guid_chromeos_kernel, &entry->type)) {
+    if (GuidEqual(&guid_chromeos_kernel, &entry->type) ||
+        GuidEqual(&guid_android_vbmeta, &entry->type)) {
       int tries = (entry->attrs.fields.gpt_att &
                    CGPT_ATTRIBUTE_TRIES_MASK) >>
           CGPT_ATTRIBUTE_TRIES_OFFSET;
diff --git a/firmware/2lib/2ec_sync.c b/firmware/2lib/2ec_sync.c
index 6475dc45..84a5dbee 100644
--- a/firmware/2lib/2ec_sync.c
+++ b/firmware/2lib/2ec_sync.c
@@ -243,6 +243,26 @@ static vb2_error_t sync_ec(struct vb2_context *ctx)
 	return VB2_SUCCESS;
 }
 
+/**
+ * determine if we can update the EC
+ *
+ * @param ctx		Vboot2 context
+ * @return boolean (true iff we can update the EC)
+ */
+
+static int ec_sync_allowed(struct vb2_context *ctx)
+{
+	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);
+
+	/* Reasons not to do sync at all */
+	if (!(ctx->flags & VB2_CONTEXT_EC_SYNC_SUPPORTED))
+		return 0;
+	if (gbb->flags & VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC)
+		return 0;
+
+	return 1;
+}
+
 /**
  * EC sync, phase 1
  *
@@ -256,12 +276,9 @@ static vb2_error_t sync_ec(struct vb2_context *ctx)
 static vb2_error_t ec_sync_phase1(struct vb2_context *ctx)
 {
 	struct vb2_shared_data *sd = vb2_get_sd(ctx);
-	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);
 
 	/* Reasons not to do sync at all */
-	if (!(ctx->flags & VB2_CONTEXT_EC_SYNC_SUPPORTED))
-		return VB2_SUCCESS;
-	if (gbb->flags & VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC)
+	if (!ec_sync_allowed(ctx))
 		return VB2_SUCCESS;
 
 	/* Set VB2_SD_FLAG_ECSYNC_EC_IN_RW flag */
@@ -297,27 +314,6 @@ static vb2_error_t ec_sync_phase1(struct vb2_context *ctx)
 	return VB2_SUCCESS;
 }
 
-/**
- * determine if we can update the EC
- *
- * @param ctx		Vboot2 context
- * @return boolean (true iff we can update the EC)
- */
-
-static int ec_sync_allowed(struct vb2_context *ctx)
-{
-	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);
-
-	/* Reasons not to do sync at all */
-	if (!(ctx->flags & VB2_CONTEXT_EC_SYNC_SUPPORTED))
-		return 0;
-	if (gbb->flags & VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC)
-		return 0;
-	if (ctx->flags & VB2_CONTEXT_RECOVERY_MODE)
-		return 0;
-	return 1;
-}
-
 /**
  * EC sync, phase 2
  *
diff --git a/firmware/2lib/2load_kernel.c b/firmware/2lib/2load_kernel.c
index fcc09c57..40b9499f 100644
--- a/firmware/2lib/2load_kernel.c
+++ b/firmware/2lib/2load_kernel.c
@@ -15,6 +15,7 @@
 #include "2sysincludes.h"
 #include "cgptlib.h"
 #include "cgptlib_internal.h"
+#include "gpt.h"
 #include "gpt_misc.h"
 #include "vboot_api.h"
 
@@ -640,9 +641,10 @@ vb2_error_t vb2api_load_kernel(struct vb2_context *ctx,
 	}
 
 	/* Loop over candidate kernel partitions */
-	uint64_t part_start, part_size;
-	while (GptNextKernelEntry(&gpt, &part_start, &part_size) ==
-	       GPT_SUCCESS) {
+	GptEntry *entry;
+	while ((entry = GptNextKernelEntry(&gpt))) {
+		uint64_t part_start = entry->starting_lba;
+		uint64_t part_size = GptGetEntrySizeLba(entry);
 
 		VB2_DEBUG("Found kernel entry at %"
 			  PRIu64 " size %" PRIu64 "\n",
diff --git a/firmware/2lib/2misc.c b/firmware/2lib/2misc.c
index 77ff3994..ab6b3e7d 100644
--- a/firmware/2lib/2misc.c
+++ b/firmware/2lib/2misc.c
@@ -406,6 +406,8 @@ vb2_error_t vb2_select_fw_slot(struct vb2_context *ctx)
 		 */
 		sd->fw_slot = 1 - sd->fw_slot;
 		vb2_nv_set(ctx, VB2_NV_TRY_NEXT, sd->fw_slot);
+		VB2_DEBUG("try_count used up; falling back to slot %s\n",
+			  vb2_slot_string(sd->fw_slot));
 	}
 
 	if (tries > 0) {
diff --git a/firmware/include/gpt.h b/firmware/include/gpt.h
index 4f4c245d..912ea508 100644
--- a/firmware/include/gpt.h
+++ b/firmware/include/gpt.h
@@ -57,6 +57,8 @@ extern "C" {
 	{{{0x09845860,0x705f,0x4bb5,0xb1,0x6c,{0x8a,0x8a,0x09,0x9c,0xaf,0x52}}}}
 #define GPT_ENT_TYPE_CHROMEOS_HIBERNATE \
 	{{{0x3f0f8318,0xf146,0x4e6b,0x82,0x22,{0xc2,0x8c,0x8f,0x02,0xe0,0xd5}}}}
+#define GPT_ENT_TYPE_ANDROID_VBMETA \
+	{{{0x88434509,0xd9d1,0x487d,0xb8,0x2c,{0x15,0xef,0x96,0x4c,0xbd,0x4b}}}}
 
 #define UUID_NODE_LEN 6
 #define GUID_SIZE 16
diff --git a/firmware/lib/cgptlib/cgptlib.c b/firmware/lib/cgptlib/cgptlib.c
index ccae204b..c6fd5f8b 100644
--- a/firmware/lib/cgptlib/cgptlib.c
+++ b/firmware/lib/cgptlib/cgptlib.c
@@ -29,7 +29,7 @@ int GptInit(GptData *gpt)
 	return GPT_SUCCESS;
 }
 
-int GptNextKernelEntry(GptData *gpt, uint64_t *start_sector, uint64_t *size)
+GptEntry *GptNextKernelEntry(GptData *gpt)
 {
 	GptHeader *header = (GptHeader *)gpt->primary_header;
 	GptEntry *entries = (GptEntry *)gpt->primary_entries;
@@ -58,10 +58,8 @@ int GptNextKernelEntry(GptData *gpt, uint64_t *start_sector, uint64_t *size)
 				continue;
 			if (GetEntryPriority(e) == gpt->current_priority) {
 				gpt->current_kernel = i;
-				*start_sector = e->starting_lba;
-				*size = e->ending_lba - e->starting_lba + 1;
 				VB2_DEBUG("GptNextKernelEntry likes it\n");
-				return GPT_SUCCESS;
+				return e;
 			}
 		}
 	}
@@ -101,14 +99,12 @@ int GptNextKernelEntry(GptData *gpt, uint64_t *start_sector, uint64_t *size)
 
 	if (CGPT_KERNEL_ENTRY_NOT_FOUND == new_kernel) {
 		VB2_DEBUG("GptNextKernelEntry no more kernels\n");
-		return GPT_ERROR_NO_VALID_KERNEL;
+		return NULL;
 	}
 
 	VB2_DEBUG("GptNextKernelEntry likes partition %d\n", new_kernel + 1);
 	e = entries + new_kernel;
-	*start_sector = e->starting_lba;
-	*size = e->ending_lba - e->starting_lba + 1;
-	return GPT_SUCCESS;
+	return e;
 }
 
 /*
diff --git a/firmware/lib/cgptlib/include/cgptlib.h b/firmware/lib/cgptlib/include/cgptlib.h
index 6561ccb5..e2f5d34b 100644
--- a/firmware/lib/cgptlib/include/cgptlib.h
+++ b/firmware/lib/cgptlib/include/cgptlib.h
@@ -10,16 +10,14 @@
 #include "gpt_misc.h"
 
 /**
- * Provides the location of the next kernel partition, in order of decreasing
+ * Provides the location of the next bootable partition, in order of decreasing
  * priority.
  *
- * On return the start_sector parameter contains the LBA sector for the start
- * of the kernel partition, and the size parameter contains the size of the
- * kernel partition in LBA sectors.  gpt.current_kernel contains the partition
- * index of the current chromeos kernel partition.
+ * On return gpt.current_kernel contains the partition index of the current
+ * bootable partition.
  *
- * Returns GPT_SUCCESS if successful, else
- *   GPT_ERROR_NO_VALID_KERNEL, no avaliable kernel, enters recovery mode */
-int GptNextKernelEntry(GptData *gpt, uint64_t *start_sector, uint64_t *size);
+ * Returns gpt entry of partition to boot if successful, else NULL
+ */
+GptEntry *GptNextKernelEntry(GptData *gpt);
 
 #endif  /* VBOOT_REFERENCE_CGPTLIB_H_ */
diff --git a/futility/cmd_update.c b/futility/cmd_update.c
index c000e70e..b9f542e3 100644
--- a/futility/cmd_update.c
+++ b/futility/cmd_update.c
@@ -24,6 +24,7 @@ enum {
 	OPT_GBB_FLAGS,
 	OPT_HOST_ONLY,
 	OPT_MANIFEST,
+	OPT_PARSEABLE_MANIFEST,
 	OPT_MODEL,
 	OPT_OUTPUT_DIR,
 	OPT_QUIRKS,
@@ -60,6 +61,7 @@ static struct option const long_opts[] = {
 	{"quirks", 1, NULL, OPT_QUIRKS},
 	{"list-quirks", 0, NULL, OPT_QUIRKS_LIST},
 	{"manifest", 0, NULL, OPT_MANIFEST},
+	{"parseable-manifest", 0, NULL, OPT_PARSEABLE_MANIFEST},
 	{"model", 1, NULL, OPT_MODEL},
 	{"output_dir", 1, NULL, OPT_OUTPUT_DIR},
 	{"repack", 1, NULL, OPT_REPACK},
@@ -108,6 +110,9 @@ static void print_help(int argc, char *argv[])
 		"    --list-quirks   \tPrint all available quirks\n"
 		"-m, --mode=MODE     \tRun updater in the specified mode\n"
 		"    --manifest      \tScan the archive to print a manifest in JSON\n"
+		"    --parseable-manifest\n"
+		"                    \tScan the archive to print a manifest\n"
+		"                    \tin shell-parseable format\n"
 		SHARED_FLASH_ARGS_HELP
 		"\n"
 		" * Option --manifest requires either -a,--archive or -i,--image\n"
@@ -241,6 +246,11 @@ static int do_update(int argc, char *argv[])
 			break;
 		case OPT_MANIFEST:
 			args.do_manifest = 1;
+			args.manifest_format = MANIFEST_PRINT_FORMAT_JSON;
+			break;
+		case OPT_PARSEABLE_MANIFEST:
+			args.do_manifest = 1;
+			args.manifest_format = MANIFEST_PRINT_FORMAT_PARSEABLE;
 			break;
 		case OPT_FACTORY:
 			args.is_factory = 1;
diff --git a/futility/updater.c b/futility/updater.c
index b958f435..7511b3d0 100644
--- a/futility/updater.c
+++ b/futility/updater.c
@@ -17,8 +17,6 @@
 #include "updater.h"
 #include "util_misc.h"
 
-#define REMOVE_WP_URL "https://goo.gl/ces83U"
-
 static const char ROOTKEY_HASH_DEV[] =
 		"b11d74edd286c144e1135b49e7f0bc20cf041f10";
 
@@ -266,7 +264,7 @@ static const char *decide_rw_target(struct updater_config *cfg,
 static int set_try_cookies(struct updater_config *cfg, const char *target,
 			   int has_update)
 {
-	int tries = 13;
+	int tries = 17;
 	const char *slot;
 
 	if (!has_update)
@@ -1247,7 +1245,7 @@ enum updater_error_codes update_firmware(struct updater_config *cfg)
 	/* Providing more hints for what to do on failure. */
 	if (r == UPDATE_ERR_ROOT_KEY && wp_enabled)
 		ERROR("To change keys in RO area, you must first remove "
-		      "write protection ( " REMOVE_WP_URL " ).\n");
+		      "write protection.\n");
 
 	return r;
 }
@@ -1475,7 +1473,7 @@ static int check_arg_compatibility(
 	 */
 	if (arg->detect_model_only) {
 		if (arg->do_manifest || arg->repack || arg->unpack) {
-			ERROR("--manifest/--repack/--unpack"
+			ERROR("--manifest/--parseable-manifest/--repack/--unpack"
 			      " is not compatible with --detect-model-only.\n");
 			return -1;
 		}
@@ -1486,7 +1484,7 @@ static int check_arg_compatibility(
 	} else if (arg->do_manifest) {
 		if (arg->repack || arg->unpack) {
 			ERROR("--repack/--unpack"
-			      " is not compatible with --manifest.\n");
+			      " is not compatible with --manifest/--parseable-manifest.\n");
 			return -1;
 		}
 		if (!arg->archive && !(arg->image || arg->ec_image)) {
@@ -1621,7 +1619,14 @@ static int print_manifest(const struct updater_config_arguments *arg)
 			.num = 1,
 			.models = &model,
 		};
-		print_json_manifest(&manifest);
+		if (arg->manifest_format == MANIFEST_PRINT_FORMAT_JSON) {
+			print_json_manifest(&manifest);
+		} else if (arg->manifest_format == MANIFEST_PRINT_FORMAT_PARSEABLE) {
+			print_parseable_manifest(&manifest);
+		} else {
+			ERROR("Unknown manifest format requested: %d", arg->manifest_format);
+			return 1;
+		}
 		return 0;
 	}
 
@@ -1637,6 +1642,11 @@ static int print_manifest(const struct updater_config_arguments *arg)
 		uint8_t *data = NULL;
 		uint32_t size = 0;
 
+		if (arg->manifest_format != MANIFEST_PRINT_FORMAT_JSON) {
+			ERROR("Only manifest format supported in fast mode is JSON.\n");
+			return 1;
+		}
+
 		if (!archive_has_entry(archive, manifest_name) ||
 		    archive_read_file(archive, manifest_name, &data, &size,
 				      NULL)) {
@@ -1655,7 +1665,15 @@ static int print_manifest(const struct updater_config_arguments *arg)
 			      arg->archive);
 			return 1;
 		}
-		print_json_manifest(manifest);
+		if (arg->manifest_format == MANIFEST_PRINT_FORMAT_JSON) {
+			print_json_manifest(manifest);
+		} else if (arg->manifest_format == MANIFEST_PRINT_FORMAT_PARSEABLE) {
+			print_parseable_manifest(manifest);
+		} else {
+			ERROR("Unknown manifest format requested: %d", arg->manifest_format);
+			delete_manifest(manifest);
+			return 1;
+		}
 		delete_manifest(manifest);
 	}
 
@@ -1787,8 +1805,7 @@ int updater_setup_config(struct updater_config *cfg,
 	}
 	if (check_wp_disabled && is_ap_write_protection_enabled(cfg)) {
 		errorcnt++;
-		ERROR("Please remove write protection for factory mode \n"
-		      "( " REMOVE_WP_URL " ).");
+		ERROR("Please remove write protection for factory mode\n");
 	}
 
 	if (cfg->image.data) {
diff --git a/futility/updater.h b/futility/updater.h
index 00f2c46b..f936dac0 100644
--- a/futility/updater.h
+++ b/futility/updater.h
@@ -104,6 +104,11 @@ struct updater_config {
 	bool output_only;
 };
 
+enum manifest_print_format {
+	MANIFEST_PRINT_FORMAT_JSON = 0,
+	MANIFEST_PRINT_FORMAT_PARSEABLE,
+};
+
 struct updater_config_arguments {
 	char *image, *ec_image;
 	char *archive, *quirks, *mode;
@@ -113,6 +118,7 @@ struct updater_config_arguments {
 	char *output_dir;
 	char *repack, *unpack;
 	int is_factory, try_update, force_update, do_manifest, host_only;
+	enum manifest_print_format manifest_format;
 	int fast_update;
 	int verbosity;
 	int override_gbb_flags;
@@ -341,6 +347,9 @@ void delete_manifest(struct manifest *manifest);
 /* Prints the information of objects in manifest (models and images) in JSON. */
 void print_json_manifest(const struct manifest *manifest);
 
+/* Prints the manifest in parseable double-colon-separated tokens format. */
+void print_parseable_manifest(const struct manifest *manifest);
+
 /*
  * Modifies a firmware image from patch information specified in model config.
  * Returns 0 on success, otherwise number of failures.
diff --git a/futility/updater_manifest.c b/futility/updater_manifest.c
index c9d8c509..f8b1ce42 100644
--- a/futility/updater_manifest.c
+++ b/futility/updater_manifest.c
@@ -819,3 +819,62 @@ void print_json_manifest(const struct manifest *manifest)
 	}
 	printf("\n}\n");
 }
+
+static void print_parseable_image(const char *name, const char *fpath, struct model_config *m,
+				 struct u_archive *archive, bool is_host)
+{
+	struct firmware_image image = {0};
+	const struct vb2_gbb_header *gbb = NULL;
+
+	if (!fpath)
+		return;
+	if (load_firmware_image(&image, fpath, archive))
+		return;
+
+	printf("%s::%s::versions::ro::%s\n", m->name, name, image.ro_version);
+	printf("%s::%s::versions::rw::%s\n", m->name, name, image.rw_version_a);
+	if (is_host) {
+		if (image.ecrw_version_a[0] != '\0')
+			printf("%s::%s::versions::ecrw::%s\n", m->name, name,
+			       image.ecrw_version_a);
+
+		if (patch_image_by_model(&image, m, archive))
+			ERROR("Failed to patch images by model: %s\n", m->name);
+		else
+			gbb = find_gbb(&image);
+
+		if (gbb != NULL) {
+			printf("%s::%s::keys::root::%s\n", m->name, name,
+			       get_gbb_key_hash(gbb, gbb->rootkey_offset, gbb->rootkey_size));
+			printf("%s::%s::keys::recovery::%s\n", m->name, name,
+			       get_gbb_key_hash(gbb, gbb->recovery_key_offset,
+						gbb->recovery_key_size));
+		}
+	}
+	printf("%s::%s::image::%s\n", m->name, name, fpath);
+	check_firmware_versions(&image);
+	free_firmware_image(&image);
+}
+
+void print_parseable_manifest(const struct manifest *manifest)
+{
+	struct u_archive *ar = manifest->archive;
+
+	for (int i = 0; i < manifest->num; ++i) {
+		struct model_config *m = &manifest->models[i];
+		if (m->image)
+			print_parseable_image("host", m->image, m, ar, true);
+
+		if (m->ec_image)
+			print_parseable_image("ec", m->ec_image, m, ar, false);
+
+		if (m->patches.rootkey) {
+			struct patch_config *p = &m->patches;
+			printf("%s::patches::rootkey::%s\n", m->name, p->rootkey);
+			printf("%s::patches::vblock_a::%s\n", m->name, p->vblock_a);
+			printf("%s::patches::vblock_b::%s\n", m->name, p->vblock_b);
+			if (p->gscvd)
+				printf("%s::gscvd::%s\n", m->name, p->gscvd);
+		}
+	}
+}
diff --git a/host/lib/crossystem.c b/host/lib/crossystem.c
index 7a19c779..6706f577 100644
--- a/host/lib/crossystem.c
+++ b/host/lib/crossystem.c
@@ -270,8 +270,11 @@ static int VbGetCrosDebug(void)
 		return 0;
 	}
 
-	/* Command line is silent; allow debug if the dev switch is on. */
-	if (1 == VbGetSystemPropertyInt("devsw_boot"))
+	/* Command line is silent; allow debug if this was a developer boot.
+	 * NOTE: This should intentionally never be true in recovery mode,
+	 * since the recovery initramfs is supposed to remain trusted even when
+	 * the developer switch is on. */
+	if (CheckFwType("developer"))
 		return 1;
 
 	/* All other cases disallow debug. */
diff --git a/scripts/image_signing/sign_official_build.sh b/scripts/image_signing/sign_official_build.sh
index 1616d68e..27d6c238 100755
--- a/scripts/image_signing/sign_official_build.sh
+++ b/scripts/image_signing/sign_official_build.sh
@@ -1483,7 +1483,7 @@ main() {
   elif [[ "${TYPE}" == "hps_firmware" ]]; then
     hps-sign-rom --input "${INPUT_IMAGE}" --output "${OUTPUT_IMAGE}" \
       --private-key "${KEY_DIR}/key_hps.priv.pem"
-  elif [[ "${TYPE}" == "uefi_kernel" ]]; then
+  elif [[ "${TYPE}" == "uefi_kernel" || "${TYPE}" == "flexor_kernel" ]]; then
       sign_uefi_kernel "${INPUT_IMAGE}" "${OUTPUT_IMAGE}"
   elif [[ "${TYPE}" == "recovery_kernel" ]]; then
     cp "${INPUT_IMAGE}" "${OUTPUT_IMAGE}"
diff --git a/scripts/image_signing/sign_uefi.py b/scripts/image_signing/sign_uefi.py
index 6d4549fb..e387fe78 100755
--- a/scripts/image_signing/sign_uefi.py
+++ b/scripts/image_signing/sign_uefi.py
@@ -235,9 +235,12 @@ def sign_target_dir(target_dir: os.PathLike, keys: Keys, efi_glob: str):
 
         for efi_file in sorted(bootloader_dir.glob("crdyboot*.efi")):
             # This key is required to create the detached signature.
-            ensure_file_exists(
-                keys.crdyshim_private_key, "No crdyshim private key"
-            )
+            # Only check the private keys if they are local paths rather than a
+            # PKCS#11 URI.
+            if not is_pkcs11_key_path(keys.crdyshim_private_key):
+                ensure_file_exists(
+                    keys.crdyshim_private_key, "No crdyshim private key"
+                )
 
             if efi_file.is_file():
                 inject_vbpubk(efi_file, keys)
diff --git a/scripts/image_signing/swap_ec_rw b/scripts/image_signing/swap_ec_rw
index b57bd81a..202e868c 100755
--- a/scripts/image_signing/swap_ec_rw
+++ b/scripts/image_signing/swap_ec_rw
@@ -37,9 +37,11 @@ swap_ecrw() {
   local info
   local ecrw_file
   local ecrw_hash_file
-  local ecrw_version_file
+  local ecrw_ver_file
   local ecrw_comp_type
-  local ecrw_version
+  local ecrw_ver
+  local apro_ver
+  local aprw_ver
   temp_dir=$(mktemp -d)
   ecrw_file="${temp_dir}/ecrw"
   futility dump_fmap -x "${ec_file}" "RW_FW:${ecrw_file}" >/dev/null
@@ -49,8 +51,8 @@ swap_ecrw() {
   openssl dgst -sha256 -binary "${ecrw_file}" > "${ecrw_hash_file}"
   info "EC RW hash saved to ${ecrw_hash_file}"
 
-  ecrw_version_file="${temp_dir}/ecrw.version"
-  futility dump_fmap -x "${ec_file}" "RW_FWID:${ecrw_version_file}" >/dev/null
+  ecrw_ver_file="${temp_dir}/ecrw.version"
+  futility dump_fmap -x "${ec_file}" "RW_FWID:${ecrw_ver_file}" >/dev/null
 
   for region in "${FMAP_REGIONS[@]}"
   do
@@ -73,7 +75,7 @@ swap_ecrw() {
     cbfstool "${ap_file}" add -r "${region}" -t raw \
       -c none -f "${ecrw_hash_file}" -n "${CBFS_ECRW_HASH_NAME}"
     cbfstool "${ap_file}" add -r "${region}" -t raw \
-      -c none -f "${ecrw_version_file}" -n "${CBFS_ECRW_VERSION_NAME}"
+      -c none -f "${ecrw_ver_file}" -n "${CBFS_ECRW_VERSION_NAME}"
   done
 
   local keyset
@@ -84,9 +86,13 @@ swap_ecrw() {
   # 'futility sign' will call 'cbfstool truncate' if needed
   futility sign "${ap_file}" --keyset "${keyset}"
 
-  ecrw_version=$(futility update --manifest -e "${ec_file}" \
+  ecrw_ver=$(futility update --manifest -e "${ec_file}" \
     | jq -r '.default.ec.versions.rw')
-  info "${CBFS_ECRW_NAME} (${ecrw_version}) swapped in ${ap_file}"
+  apro_ver=$(futility update --manifest -i "${ap_file}" \
+    | jq -r '.default.host.versions.ro')
+  aprw_ver=$(futility update --manifest -i "${ap_file}" \
+    | jq -r '.default.host.versions.rw')
+  info "${CBFS_ECRW_NAME} (${ecrw_ver}) swapped in ${ap_file} (RO:${apro_ver}, RW:${aprw_ver})"
   info "Done"
 }
 
diff --git a/tests/cgpt_fuzzer.c b/tests/cgpt_fuzzer.c
index 3d0857d0..e56e522f 100644
--- a/tests/cgpt_fuzzer.c
+++ b/tests/cgpt_fuzzer.c
@@ -72,11 +72,11 @@ int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
 	gpt.flags = params.flags;
 
 	if (0 == AllocAndReadGptData(0, &gpt)) {
-		int result = GptInit(&gpt);
-		while (GPT_SUCCESS == result) {
-			uint64_t part_start, part_size;
-			result = GptNextKernelEntry(&gpt, &part_start,
-						    &part_size);
+		if (GptInit(&gpt) == GPT_SUCCESS) {
+			GptEntry *entry = NULL;
+			do {
+				entry = GptNextKernelEntry(&gpt);
+			} while (entry);
 		}
 	}
 
diff --git a/tests/cgptlib_test.c b/tests/cgptlib_test.c
index 91fe320f..4a6355c5 100644
--- a/tests/cgptlib_test.c
+++ b/tests/cgptlib_test.c
@@ -1251,8 +1251,7 @@ static int NoValidKernelEntryTest(void)
 	SetEntryPriority(e1 + KERNEL_A, 0);
 	FreeEntry(e1 + KERNEL_B);
 	RefreshCrc32(gpt);
-	EXPECT(GPT_ERROR_NO_VALID_KERNEL ==
-	       GptNextKernelEntry(gpt, NULL, NULL));
+	EXPECT(NULL == GptNextKernelEntry(gpt));
 
 	return TEST_OK;
 }
@@ -1261,7 +1260,7 @@ static int GetNextNormalTest(void)
 {
 	GptData *gpt = GetEmptyGptData();
 	GptEntry *e1 = (GptEntry *)(gpt->primary_entries);
-	uint64_t start, size;
+	GptEntry *entry;
 
 	/* Normal case - both kernels successful */
 	BuildTestGptData(gpt);
@@ -1270,23 +1269,23 @@ static int GetNextNormalTest(void)
 	RefreshCrc32(gpt);
 	GptInit(gpt);
 
-	EXPECT(GPT_SUCCESS == GptNextKernelEntry(gpt, &start, &size));
+	entry = GptNextKernelEntry(gpt);
+	EXPECT(entry);
 	EXPECT(KERNEL_A == gpt->current_kernel);
-	EXPECT(34 == start);
-	EXPECT(100 == size);
+	EXPECT(34 == entry->starting_lba);
+	EXPECT(100 == GptGetEntrySizeLba(entry));
 
-	EXPECT(GPT_SUCCESS == GptNextKernelEntry(gpt, &start, &size));
+	entry = GptNextKernelEntry(gpt);
+	EXPECT(entry);
 	EXPECT(KERNEL_B == gpt->current_kernel);
-	EXPECT(134 == start);
-	EXPECT(99 == size);
+	EXPECT(134 == entry->starting_lba);
+	EXPECT(99 == GptGetEntrySizeLba(entry));
 
-	EXPECT(GPT_ERROR_NO_VALID_KERNEL ==
-	       GptNextKernelEntry(gpt, &start, &size));
+	EXPECT(NULL == GptNextKernelEntry(gpt));
 	EXPECT(-1 == gpt->current_kernel);
 
 	/* Call as many times as you want; you won't get another kernel... */
-	EXPECT(GPT_ERROR_NO_VALID_KERNEL ==
-	       GptNextKernelEntry(gpt, &start, &size));
+	EXPECT(NULL == GptNextKernelEntry(gpt));
 	EXPECT(-1 == gpt->current_kernel);
 
 	return TEST_OK;
@@ -1296,7 +1295,6 @@ static int GetNextPrioTest(void)
 {
 	GptData *gpt = GetEmptyGptData();
 	GptEntry *e1 = (GptEntry *)(gpt->primary_entries);
-	uint64_t start, size;
 
 	/* Priority 3, 4, 0, 4 - should boot order B, Y, A */
 	BuildTestGptData(gpt);
@@ -1307,14 +1305,13 @@ static int GetNextPrioTest(void)
 	RefreshCrc32(gpt);
 	GptInit(gpt);
 
-	EXPECT(GPT_SUCCESS == GptNextKernelEntry(gpt, &start, &size));
+	EXPECT(GptNextKernelEntry(gpt));
 	EXPECT(KERNEL_B == gpt->current_kernel);
-	EXPECT(GPT_SUCCESS == GptNextKernelEntry(gpt, &start, &size));
+	EXPECT(GptNextKernelEntry(gpt));
 	EXPECT(KERNEL_Y == gpt->current_kernel);
-	EXPECT(GPT_SUCCESS == GptNextKernelEntry(gpt, &start, &size));
+	EXPECT(GptNextKernelEntry(gpt));
 	EXPECT(KERNEL_A == gpt->current_kernel);
-	EXPECT(GPT_ERROR_NO_VALID_KERNEL ==
-	       GptNextKernelEntry(gpt, &start, &size));
+	EXPECT(NULL == GptNextKernelEntry(gpt));
 
 	return TEST_OK;
 }
@@ -1323,7 +1320,6 @@ static int GetNextTriesTest(void)
 {
 	GptData *gpt = GetEmptyGptData();
 	GptEntry *e1 = (GptEntry *)(gpt->primary_entries);
-	uint64_t start, size;
 
 	/* Tries=nonzero is attempted just like success, but tries=0 isn't */
 	BuildTestGptData(gpt);
@@ -1334,12 +1330,11 @@ static int GetNextTriesTest(void)
 	RefreshCrc32(gpt);
 	GptInit(gpt);
 
-	EXPECT(GPT_SUCCESS == GptNextKernelEntry(gpt, &start, &size));
+	EXPECT(GptNextKernelEntry(gpt));
 	EXPECT(KERNEL_X == gpt->current_kernel);
-	EXPECT(GPT_SUCCESS == GptNextKernelEntry(gpt, &start, &size));
+	EXPECT(GptNextKernelEntry(gpt));
 	EXPECT(KERNEL_A == gpt->current_kernel);
-	EXPECT(GPT_ERROR_NO_VALID_KERNEL ==
-	       GptNextKernelEntry(gpt, &start, &size));
+	EXPECT(NULL == GptNextKernelEntry(gpt));
 
 	return TEST_OK;
 }
@@ -1349,7 +1344,7 @@ static int GptUpdateTest(void)
 	GptData *gpt = GetEmptyGptData();
 	GptEntry *e = (GptEntry *)(gpt->primary_entries);
 	GptEntry *e2 = (GptEntry *)(gpt->secondary_entries);
-	uint64_t start, size;
+	GptEntry *boot;
 
 	/* Tries=nonzero is attempted just like success, but tries=0 isn't */
 	BuildTestGptData(gpt);
@@ -1361,38 +1356,42 @@ static int GptUpdateTest(void)
 	gpt->modified = 0;  /* Nothing modified yet */
 
 	/* Successful kernel */
-	EXPECT(GPT_SUCCESS == GptNextKernelEntry(gpt, &start, &size));
+	boot = GptNextKernelEntry(gpt);
+	EXPECT(NULL != boot);
 	EXPECT(KERNEL_A == gpt->current_kernel);
-	EXPECT(1 == GetEntrySuccessful(e + KERNEL_A));
-	EXPECT(4 == GetEntryPriority(e + KERNEL_A));
-	EXPECT(0 == GetEntryTries(e + KERNEL_A));
+	EXPECT(1 == GetEntrySuccessful(boot));
+	EXPECT(4 == GetEntryPriority(boot));
+	EXPECT(0 == GetEntryTries(boot));
+	/* Check secondary entries */
 	EXPECT(1 == GetEntrySuccessful(e2 + KERNEL_A));
 	EXPECT(4 == GetEntryPriority(e2 + KERNEL_A));
 	EXPECT(0 == GetEntryTries(e2 + KERNEL_A));
+
 	/* Trying successful kernel changes nothing */
 	EXPECT(GPT_SUCCESS == GptUpdateKernelEntry(gpt, GPT_UPDATE_ENTRY_TRY));
-	EXPECT(1 == GetEntrySuccessful(e + KERNEL_A));
-	EXPECT(4 == GetEntryPriority(e + KERNEL_A));
-	EXPECT(0 == GetEntryTries(e + KERNEL_A));
+	EXPECT(1 == GetEntrySuccessful(boot));
+	EXPECT(4 == GetEntryPriority(boot));
+	EXPECT(0 == GetEntryTries(boot));
 	EXPECT(0 == gpt->modified);
 	/* Marking it bad also does not update it. */
 	EXPECT(GPT_SUCCESS == GptUpdateKernelEntry(gpt, GPT_UPDATE_ENTRY_BAD));
-	EXPECT(1 == GetEntrySuccessful(e + KERNEL_A));
-	EXPECT(4 == GetEntryPriority(e + KERNEL_A));
-	EXPECT(0 == GetEntryTries(e + KERNEL_A));
+	EXPECT(1 == GetEntrySuccessful(boot + KERNEL_A));
+	EXPECT(4 == GetEntryPriority(boot + KERNEL_A));
+	EXPECT(0 == GetEntryTries(boot + KERNEL_A));
 	EXPECT(0 == gpt->modified);
 
 	/* Kernel with tries */
-	EXPECT(GPT_SUCCESS == GptNextKernelEntry(gpt, &start, &size));
+	boot = GptNextKernelEntry(gpt);
+	EXPECT(NULL != boot);
 	EXPECT(KERNEL_B == gpt->current_kernel);
-	EXPECT(0 == GetEntrySuccessful(e + KERNEL_B));
-	EXPECT(3 == GetEntryPriority(e + KERNEL_B));
-	EXPECT(2 == GetEntryTries(e + KERNEL_B));
+	EXPECT(0 == GetEntrySuccessful(boot));
+	EXPECT(3 == GetEntryPriority(boot));
+	EXPECT(2 == GetEntryTries(boot));
 	/* Marking it bad clears it */
 	EXPECT(GPT_SUCCESS == GptUpdateKernelEntry(gpt, GPT_UPDATE_ENTRY_BAD));
-	EXPECT(0 == GetEntrySuccessful(e + KERNEL_B));
-	EXPECT(0 == GetEntryPriority(e + KERNEL_B));
-	EXPECT(0 == GetEntryTries(e + KERNEL_B));
+	EXPECT(0 == GetEntrySuccessful(boot));
+	EXPECT(0 == GetEntryPriority(boot));
+	EXPECT(0 == GetEntryTries(boot));
 	/* Which affects both copies of the partition entries */
 	EXPECT(0 == GetEntrySuccessful(e2 + KERNEL_B));
 	EXPECT(0 == GetEntryPriority(e2 + KERNEL_B));
@@ -1401,24 +1400,25 @@ static int GptUpdateTest(void)
 	EXPECT(0x0F == gpt->modified);
 
 	/* Another kernel with tries */
-	EXPECT(GPT_SUCCESS == GptNextKernelEntry(gpt, &start, &size));
+	boot = GptNextKernelEntry(gpt);
+	EXPECT(NULL != boot);
 	EXPECT(KERNEL_X == gpt->current_kernel);
-	EXPECT(0 == GetEntrySuccessful(e + KERNEL_X));
-	EXPECT(2 == GetEntryPriority(e + KERNEL_X));
-	EXPECT(2 == GetEntryTries(e + KERNEL_X));
+	EXPECT(0 == GetEntrySuccessful(boot));
+	EXPECT(2 == GetEntryPriority(boot));
+	EXPECT(2 == GetEntryTries(boot));
 	/* Trying it uses up a try */
 	EXPECT(GPT_SUCCESS == GptUpdateKernelEntry(gpt, GPT_UPDATE_ENTRY_TRY));
-	EXPECT(0 == GetEntrySuccessful(e + KERNEL_X));
-	EXPECT(2 == GetEntryPriority(e + KERNEL_X));
-	EXPECT(1 == GetEntryTries(e + KERNEL_X));
+	EXPECT(0 == GetEntrySuccessful(boot));
+	EXPECT(2 == GetEntryPriority(boot));
+	EXPECT(1 == GetEntryTries(boot));
 	EXPECT(0 == GetEntrySuccessful(e2 + KERNEL_X));
 	EXPECT(2 == GetEntryPriority(e2 + KERNEL_X));
 	EXPECT(1 == GetEntryTries(e2 + KERNEL_X));
 	/* Trying it again marks it inactive */
 	EXPECT(GPT_SUCCESS == GptUpdateKernelEntry(gpt, GPT_UPDATE_ENTRY_TRY));
-	EXPECT(0 == GetEntrySuccessful(e + KERNEL_X));
-	EXPECT(0 == GetEntryPriority(e + KERNEL_X));
-	EXPECT(0 == GetEntryTries(e + KERNEL_X));
+	EXPECT(0 == GetEntrySuccessful(boot));
+	EXPECT(0 == GetEntryPriority(boot));
+	EXPECT(0 == GetEntryTries(boot));
 
 	/* Can't update if entry isn't a kernel, or there isn't an entry */
 	memcpy(&e[KERNEL_X].type, &guid_rootfs, sizeof(guid_rootfs));
diff --git a/tests/futility/bios_geralt_cbfs.manifest.parseable b/tests/futility/bios_geralt_cbfs.manifest.parseable
new file mode 100644
index 00000000..d109c567
--- /dev/null
+++ b/tests/futility/bios_geralt_cbfs.manifest.parseable
@@ -0,0 +1,6 @@
+default::host::versions::ro::Google_Geralt.15635.0.0
+default::host::versions::rw::Google_Geralt.15635.0.0
+default::host::versions::ecrw::geralt-15857.0.0
+default::host::keys::root::b11d74edd286c144e1135b49e7f0bc20cf041f10
+default::host::keys::recovery::c14bd720b70d97394257e3e826bd8f43de48d4ed
+default::host::image::image.bin
diff --git a/tests/futility/link_bios.manifest.parseable b/tests/futility/link_bios.manifest.parseable
new file mode 100644
index 00000000..ae5e8f6a
--- /dev/null
+++ b/tests/futility/link_bios.manifest.parseable
@@ -0,0 +1,5 @@
+link::host::image::bios.bin
+link::host::versions::ro::Google_Link.2695.1.133
+link::host::versions::rw::Google_Link.2695.1.133
+link::host::keys::recovery::7e74cd6d66f361da068c0419d2e0946b4d091e1c
+link::host::keys::root::7b5c520ceabce86f13e02b7ca363cfb509fc5b98
diff --git a/tests/futility/link_image.manifest.parseable b/tests/futility/link_image.manifest.parseable
new file mode 100644
index 00000000..c86a24fb
--- /dev/null
+++ b/tests/futility/link_image.manifest.parseable
@@ -0,0 +1,5 @@
+link::host::image::image.bin
+link::host::versions::ro::Google_Link.2695.1.133
+link::host::versions::rw::Google_Link.2695.1.133
+link::host::keys::recovery::7e74cd6d66f361da068c0419d2e0946b4d091e1c
+link::host::keys::root::7b5c520ceabce86f13e02b7ca363cfb509fc5b98
diff --git a/tests/futility/test_update.sh b/tests/futility/test_update.sh
index edea233b..8d8bcced 100755
--- a/tests/futility/test_update.sh
+++ b/tests/futility/test_update.sh
@@ -506,6 +506,14 @@ cmp \
   <(jq -S <"${TMP_JSON_OUT}") \
   <(jq -S <"${SCRIPT_DIR}/futility/bios_geralt_cbfs.manifest.json")
 
+TMP_PARSEABLE_OUT="${TMP}/manifest.parseable"
+echo "TEST: Manifest parseable (--parseable-manifest, --image)"
+(cd "${TMP}" &&
+ "${FUTILITY}" update -i image.bin --parseable-manifest) >"${TMP_PARSEABLE_OUT}"
+cmp \
+  <(sort "${TMP_PARSEABLE_OUT}") \
+  <(sort "${SCRIPT_DIR}/futility/bios_geralt_cbfs.manifest.parseable")
+
 # Test archive and manifest. CL_TAG is for custom_label_tag.
 A="${TMP}/archive"
 mkdir -p "${A}/bin"
@@ -519,6 +527,12 @@ cmp \
   <(jq -S <"${TMP_JSON_OUT}") \
   <(jq -S <"${SCRIPT_DIR}/futility/link_bios.manifest.json")
 
+echo "TEST: Manifest parseable (--parseable-manifest, -a, bios.bin)"
+"${FUTILITY}" update -a "${A}" --parseable-manifest >"${TMP_PARSEABLE_OUT}"
+diff -u \
+  <(sort "${TMP_PARSEABLE_OUT}") \
+  <(sort "${SCRIPT_DIR}/futility/link_bios.manifest.parseable")
+
 mv -f "${A}/bios.bin" "${A}/image.bin"
 echo "TEST: Manifest (--manifest, -a, image.bin)"
 "${FUTILITY}" update -a "${A}" --manifest >"${TMP_JSON_OUT}"
@@ -526,6 +540,11 @@ cmp \
   <(jq -S <"${TMP_JSON_OUT}") \
   <(jq -S <"${SCRIPT_DIR}/futility/link_image.manifest.json")
 
+echo "TEST: Manifest parseable (--parseable-manifest, -a, image.bin)"
+"${FUTILITY}" update -a "${A}" --parseable-manifest >"${TMP_PARSEABLE_OUT}"
+diff -u \
+  <(sort "${TMP_PARSEABLE_OUT}") \
+  <(sort "${SCRIPT_DIR}/futility/link_image.manifest.parseable")
 
 cp -f "${TO_IMAGE}" "${A}/image.bin"
 test_update "Full update (--archive, single package)" \
diff --git a/tests/run_cgpt_tests.sh b/tests/run_cgpt_tests.sh
index daf758c2..3099250d 100755
--- a/tests/run_cgpt_tests.sh
+++ b/tests/run_cgpt_tests.sh
@@ -320,6 +320,17 @@ dd if=/dev/zero of=${DEV} seek=$((NUM_SECTORS - 33)) conv=notrunc bs=512 \
 "${CGPT}" repair "${MTD[@]}" ${DEV}
 ("${CGPT}" show "${MTD[@]}" ${DEV} | grep -q INVALID) && error
 
+# Double size. Check without|with MTD "-D 358400' (1000->2000|700->700 sectors).
+"${CGPT}" create "${MTD[@]}" ${DEV}
+"${CGPT}" show -v "${MTD[@]}" ${DEV} | grep -q -E 'Alternate LBA: 999' || error
+"${CGPT}" show -v "${MTD[@]}" ${DEV} | grep -q -E 'Last LBA: (966|699)' || error
+dd if=/dev/zero of=${DEV} bs=512 seek=$((2 * NUM_SECTORS)) count=0 2>/dev/null
+"${CGPT}" repair "${MTD[@]}" ${DEV}
+"${CGPT}" show -v "${MTD[@]}" ${DEV} | grep -q -E 'Alternate LBA: 1999' || error
+"${CGPT}" show -v "${MTD[@]}" ${DEV} | grep -q -E 'Last LBA: (1966|699)' || error
+# Restore size (truncate).
+dd if=/dev/zero of=${DEV} bs=512 count=${NUM_SECTORS} 2>/dev/null
+
 echo "Test with IGNOREME primary GPT..."
 "${CGPT}" create "${MTD[@]}" ${DEV}
 "${CGPT}" legacy "${MTD[@]}" -p ${DEV}
diff --git a/tests/vb2_inject_kernel_subkey_tests.c b/tests/vb2_inject_kernel_subkey_tests.c
index ba2eafa4..88e126ab 100644
--- a/tests/vb2_inject_kernel_subkey_tests.c
+++ b/tests/vb2_inject_kernel_subkey_tests.c
@@ -17,15 +17,9 @@
 #include "gpt.h"
 #include "vboot_api.h"
 
-/* Mock kernel partition */
-struct mock_part {
-	uint32_t start;
-	uint32_t size;
-};
-
 /* Partition list; ends with a 0-size partition. */
 #define MOCK_PART_COUNT 8
-static struct mock_part mock_parts[MOCK_PART_COUNT];
+static GptEntry mock_parts[MOCK_PART_COUNT];
 static int mock_part_next;
 
 /* Mock data */
@@ -86,8 +80,8 @@ static void ResetMocks(void)
 	kph.bootloader_size = 0x1234;
 
 	memset(mock_parts, 0, sizeof(mock_parts));
-	mock_parts[0].start = 100;
-	mock_parts[0].size = 150;  /* 75 KB */
+	mock_parts[0].starting_lba = 100;
+	mock_parts[0].ending_lba = 249;  /* 75 KB */
 	mock_part_next = 0;
 
 	memset(&kernel_packed_key_data, 0, sizeof(kernel_packed_key_data));
@@ -114,6 +108,11 @@ vb2_error_t VbExDiskRead(vb2ex_disk_handle_t h, uint64_t lba_start,
 	return VB2_SUCCESS;
 }
 
+uint64_t GptGetEntrySizeLba(const GptEntry *e)
+{
+	return (e->ending_lba - e->starting_lba + 1);
+}
+
 int AllocAndReadGptData(vb2ex_disk_handle_t disk_handle, GptData *gptdata)
 {
 	return GPT_SUCCESS;
@@ -124,21 +123,19 @@ int GptInit(GptData *gpt)
 	return GPT_SUCCESS;
 }
 
-int GptNextKernelEntry(GptData *gpt, uint64_t *start_sector, uint64_t *size)
+GptEntry *GptNextKernelEntry(GptData *gpt)
 {
-	struct mock_part *p = mock_parts + mock_part_next;
+	GptEntry *e = mock_parts + mock_part_next;
 
-	if (!p->size)
-		return GPT_ERROR_NO_VALID_KERNEL;
+	if (!e->ending_lba)
+		return NULL;
 
 	if (gpt->flags & GPT_FLAG_EXTERNAL)
 		gpt_flag_external++;
 
 	gpt->current_kernel = mock_part_next;
-	*start_sector = p->start;
-	*size = p->size;
 	mock_part_next++;
-	return GPT_SUCCESS;
+	return e;
 }
 
 int GptUpdateKernelEntry(GptData *gpt, uint32_t update_type)
@@ -252,20 +249,20 @@ static void load_kernel_tests(void)
 	   search stops at the first valid partition. */
 	kbh.data_key.key_version = 0;
 	kph.kernel_version = 0;
-	mock_parts[1].start = 300;
-	mock_parts[1].size = 150;
+	mock_parts[1].starting_lba = 300;
+	mock_parts[1].ending_lba = 449;
 	test_load_kernel(VB2_SUCCESS, "Two good kernels");
 	TEST_EQ(lkp.partition_number, 1, "  part num");
 	TEST_EQ(mock_part_next, 1, "  didn't read second one");
 
 	/* Fail if no kernels found */
 	ResetMocks();
-	mock_parts[0].size = 0;
+	mock_parts[0].ending_lba = 0;
 	test_load_kernel(VB2_ERROR_LK_NO_KERNEL_FOUND, "No kernels");
 
 	/* Skip kernels which are too small */
 	ResetMocks();
-	mock_parts[0].size = 10;
+	mock_parts[0].ending_lba = 109;
 	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND, "Too small");
 
 	ResetMocks();
@@ -312,8 +309,8 @@ static void load_kernel_tests(void)
 
 	ResetMocks();
 	kbh.data_key.key_version = 3;
-	mock_parts[1].start = 300;
-	mock_parts[1].size = 150;
+	mock_parts[1].starting_lba = 300;
+	mock_parts[1].ending_lba = 449;
 	test_load_kernel(VB2_SUCCESS, "Two kernels roll forward");
 	TEST_EQ(mock_part_next, 2, "  read both");
 	TEST_EQ(sd->kernel_version, 0x30001, "  SD version");
@@ -351,7 +348,7 @@ static void load_kernel_tests(void)
 			 "Kernel too big for buffer");
 
 	ResetMocks();
-	mock_parts[0].size = 130;
+	mock_parts[0].ending_lba = 229;
 	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
 			 "Kernel too big for partition");
 
diff --git a/tests/vb2_load_kernel_tests.c b/tests/vb2_load_kernel_tests.c
index ea796a3c..e28a0481 100644
--- a/tests/vb2_load_kernel_tests.c
+++ b/tests/vb2_load_kernel_tests.c
@@ -20,8 +20,7 @@
 
 /* Mock kernel partition */
 struct mock_part {
-	uint32_t start;
-	uint32_t size;
+	GptEntry e;
 	struct vb2_keyblock kbh;
 };
 
@@ -84,8 +83,8 @@ static void ResetMocks(void)
 	disk_info.handle = (vb2ex_disk_handle_t)1;
 
 	memset(mock_parts, 0, sizeof(mock_parts));
-	mock_parts[0].start = 100;
-	mock_parts[0].size = 150; /* 75 KB */
+	mock_parts[0].e.starting_lba = 100;
+	mock_parts[0].e.ending_lba = 249; /* 75 KB */
 	mock_parts[0].kbh = (struct vb2_keyblock){
 		.data_key.key_version = 2,
 		.keyblock_flags = -1,
@@ -175,12 +174,17 @@ int GptInit(GptData *gpt)
 	return gpt_init_fail;
 }
 
-int GptNextKernelEntry(GptData *gpt, uint64_t *start_sector, uint64_t *size)
+uint64_t GptGetEntrySizeLba(const GptEntry *e)
+{
+	return (e->ending_lba - e->starting_lba + 1);
+}
+
+GptEntry *GptNextKernelEntry(GptData *gpt)
 {
 	struct mock_part *p = mock_parts + mock_part_next;
 
-	if (!p->size)
-		return GPT_ERROR_NO_VALID_KERNEL;
+	if (!p->e.ending_lba)
+		return NULL;
 
 	if (gpt->flags & GPT_FLAG_EXTERNAL)
 		gpt_flag_external++;
@@ -188,10 +192,8 @@ int GptNextKernelEntry(GptData *gpt, uint64_t *start_sector, uint64_t *size)
 	memcpy(&cur_kbh, &mock_parts[mock_part_next].kbh, sizeof(cur_kbh));
 
 	gpt->current_kernel = mock_part_next;
-	*start_sector = p->start;
-	*size = p->size;
 	mock_part_next++;
-	return GPT_SUCCESS;
+	return &p->e;
 }
 
 int GptUpdateKernelEntry(GptData *gpt, uint32_t update_type)
@@ -323,20 +325,20 @@ static void load_kernel_tests(void)
 	ResetMocks();
 	memcpy(&mock_parts[1].kbh, &mock_parts[0].kbh,
 	       sizeof(mock_parts[0].kbh));
-	mock_parts[1].start = 300;
-	mock_parts[1].size = 150;
+	mock_parts[1].e.starting_lba = 300;
+	mock_parts[1].e.ending_lba = 449;
 	test_load_kernel(VB2_SUCCESS, "Two good kernels");
 	TEST_EQ(lkp.partition_number, 1, "  part num");
 	TEST_EQ(mock_part_next, 1, "  didn't read second one");
 
 	/* Fail if no kernels found */
 	ResetMocks();
-	mock_parts[0].size = 0;
+	mock_parts[0].e.ending_lba = 0;
 	test_load_kernel(VB2_ERROR_LK_NO_KERNEL_FOUND, "No kernels");
 
 	/* Skip kernels which are too small */
 	ResetMocks();
-	mock_parts[0].size = 10;
+	mock_parts[0].e.ending_lba = 109;
 	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND, "Too small");
 
 	ResetMocks();
@@ -494,8 +496,8 @@ static void load_kernel_tests(void)
 	memcpy(&mock_parts[1].kbh, &mock_parts[0].kbh,
 	       sizeof(mock_parts[0].kbh));
 	mock_parts[0].kbh.data_key.key_version = 4;
-	mock_parts[1].start = 300;
-	mock_parts[1].size = 150;
+	mock_parts[1].e.starting_lba = 300;
+	mock_parts[1].e.ending_lba = 449;
 	mock_parts[1].kbh.data_key.key_version = 3;
 	test_load_kernel(VB2_SUCCESS, "Two kernels roll forward");
 	TEST_EQ(mock_part_next, 2, "  read both");
@@ -605,7 +607,7 @@ static void load_kernel_tests(void)
 			 "Kernel too big for buffer");
 
 	ResetMocks();
-	mock_parts[0].size = 130;
+	mock_parts[0].e.ending_lba = 229;
 	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
 			 "Kernel too big for partition");
 
diff --git a/vboot.rc b/vboot.rc
index 959ac808..96a20323 100644
--- a/vboot.rc
+++ b/vboot.rc
@@ -2,5 +2,5 @@
 on post-fs-data-checkpointed
     mkdir /data/vendor/vboot
     mkdir /data/vendor/vboot/tmp
-    mount tmpfs tmpfs /data/vendor/vboot/tmp nosuid nodev noexec rw
+    mount tmpfs tmpfs /data/vendor/vboot/tmp nosuid nodev noexec rw context=u:object_r:firmware_tool_data_file:s0
     restorecon /data/vendor/vboot
```

