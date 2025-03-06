```diff
diff --git a/Android.bp b/Android.bp
index 8e08185e..61c63ebb 100644
--- a/Android.bp
+++ b/Android.bp
@@ -5,6 +5,7 @@
 cc_defaults {
     name: "vboot_defaults",
     visibility: ["//visibility:public"],
+    init_rc: ["vboot.rc"],
 
     cflags: [
         "-Wall",
@@ -63,8 +64,30 @@ cc_defaults {
     ],
 
     target: {
+        android: {
+            cflags: [
+                "-DCROSSYSTEM_LOCK_DIR=\"/data/vendor/vboot/tmp\"",
+                "-DVBOOT_TMP_DIR=\"/data/vendor/vboot/tmp\"",
+            ],
+        },
         darwin: {
-            cflags: ["-DHAVE_MACOS"],
+            cflags: [
+                "-DHAVE_MACOS",
+                "-DCROSSYSTEM_LOCK_DIR=\"/tmp\"",
+                "-DVBOOT_TMP_DIR=\"/tmp\"",
+            ],
+        },
+        linux: {
+            cflags: [
+                "-DCROSSYSTEM_LOCK_DIR=\"/run/lock\"",
+                "-DVBOOT_TMP_DIR=\"/tmp\"",
+            ],
+        },
+        windows: {
+            cflags: [
+                "-DCROSSYSTEM_LOCK_DIR=\"c:\\windows\\temp\"",
+                "-DVBOOT_TMP_DIR=\"c:\\windows\\temp\"",
+            ],
         },
     },
 }
@@ -393,7 +416,7 @@ cc_binary {
     name: "crossystem",
     defaults: ["vboot_defaults"],
     host_supported: true,
-    vendor: true,
+    vendor_available: true,
 
     srcs: ["utility/crossystem.c"],
     static_libs: ["libvboot_util"],
diff --git a/METADATA b/METADATA
index ffd1616a..3693fb56 100644
--- a/METADATA
+++ b/METADATA
@@ -1,17 +1,21 @@
-name: "vboot_reference"
-description:
-    "Google's Verified Boot reference implementation (versions 1.x & 2.x) and "
-    "helper tools"
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/vboot_reference
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "vboot_reference"
+description: "Google\'s Verified Boot reference implementation (versions 1.x & 2.x) and helper tools"
 third_party {
+  license_type: RESTRICTED
+  license_note: "would be NOTICE save for scripts/image_signing/lib/shflags/shflags"
+  last_upgrade_date {
+    year: 2024
+    month: 11
+    day: 13
+  }
   identifier {
     type: "Git"
     value: "https://chromium.googlesource.com/chromiumos/platform/vboot_reference"
+    version: "0d49b8fdf002fa9cfa573ca1509ed8a1a0cf26d5"
     primary_source: true
-    version: "4b12d392e5b12de29c582df4e717b1228e9f1594"
   }
-  version: "4b12d392e5b12de29c582df4e717b1228e9f1594"
-  last_upgrade_date { year: 2024 month: 7 day: 22 }
-  license_note: "would be NOTICE save for scripts/image_signing/lib/shflags/shflags"
-  license_type: RESTRICTED
 }
diff --git a/Makefile b/Makefile
index 76149d6c..1bb6d35e 100644
--- a/Makefile
+++ b/Makefile
@@ -183,10 +183,6 @@ ifneq ($(filter-out 0,${NDEBUG}),)
 CFLAGS += -DNDEBUG
 endif
 
-ifneq ($(filter-out 0,${FORCE_LOGGING_ON}),)
-CFLAGS += -DFORCE_LOGGING_ON=${FORCE_LOGGING_ON}
-endif
-
 ifneq ($(filter-out 0,${TPM2_MODE}),)
 CFLAGS += -DTPM2_MODE
 endif
@@ -217,6 +213,14 @@ else
 CFLAGS += -DEXTERNAL_TPM_CLEAR_REQUEST=0
 endif
 
+# Configurable temporary directory for host tools
+VBOOT_TMP_DIR := /tmp
+CFLAGS += -DVBOOT_TMP_DIR=\"${VBOOT_TMP_DIR}\"
+
+# Directory used by crossystem to create a lock file
+CROSSYSTEM_LOCK_DIR := /run/lock
+CFLAGS += -DCROSSYSTEM_LOCK_DIR=\"${CROSSYSTEM_LOCK_DIR}\"
+
 # NOTE: We don't use these files but they are useful for other packages to
 # query about required compiling/linking flags.
 PC_IN_FILES = vboot_host.pc.in
@@ -966,7 +970,7 @@ ${FWLIB}: ${FWLIB_OBJS}
 	@${PRINTF} "    RM            $(subst ${BUILD}/,,$@)\n"
 	${Q}rm -f $@
 	@${PRINTF} "    AR            $(subst ${BUILD}/,,$@)\n"
-	${Q}ar qc $@ $^
+	${Q}ar qcT $@ $^
 
 .PHONY: tlcl
 tlcl: ${TLCL}
@@ -975,7 +979,7 @@ ${TLCL}: ${TLCL_OBJS}
 	@${PRINTF} "    RM            $(subst ${BUILD}/,,$@)\n"
 	${Q}rm -f $@
 	@${PRINTF} "    AR            $(subst ${BUILD}/,,$@)\n"
-	${Q}ar qc $@ $^
+	${Q}ar qcT $@ $^
 
 # ----------------------------------------------------------------------------
 # Host library(s)
@@ -994,7 +998,7 @@ ${UTILLIB}: ${UTILLIB_OBJS} ${FWLIB_OBJS} ${TLCL_OBJS}
 	@${PRINTF} "    RM            $(subst ${BUILD}/,,$@)\n"
 	${Q}rm -f $@
 	@${PRINTF} "    AR            $(subst ${BUILD}/,,$@)\n"
-	${Q}ar qc $@ $^
+	${Q}ar qcT $@ $^
 
 .PHONY: hostlib
 hostlib: ${HOSTLIB} ${HOSTLIB_STATIC}
@@ -1004,7 +1008,7 @@ ${HOSTLIB_STATIC}: ${HOSTLIB_OBJS}
 	@${PRINTF} "    RM            $(subst ${BUILD}/,,$@)\n"
 	${Q}rm -f $@
 	@${PRINTF} "    AR            $(subst ${BUILD}/,,$@)\n"
-	${Q}ar qc $@ $^
+	${Q}ar qcT $@ $^
 
 ${HOSTLIB}: ${HOSTLIB_OBJS}
 	@${PRINTF} "    RM            $(subst ${BUILD}/,,$@)\n"
@@ -1200,7 +1204,7 @@ ${TESTLIB}: ${TESTLIB_OBJS}
 	@${PRINTF} "    RM            $(subst ${BUILD}/,,$@)\n"
 	${Q}rm -f $@
 	@${PRINTF} "    AR            $(subst ${BUILD}/,,$@)\n"
-	${Q}ar qc $@ $^
+	${Q}ar qcT $@ $^
 
 DUT_TEST_BINS = $(addprefix ${BUILD}/,${DUT_TEST_NAMES})
 
diff --git a/OWNERS.android b/OWNERS.android
index 8ad63046..2fa961b8 100644
--- a/OWNERS.android
+++ b/OWNERS.android
@@ -1,2 +1,3 @@
 include platform/system/core:main:/janitors/OWNERS
 czapiga@google.com
+bernacki@google.com
diff --git a/cgpt/cgpt_find.c b/cgpt/cgpt_find.c
index d807215e..258afc57 100644
--- a/cgpt/cgpt_find.c
+++ b/cgpt/cgpt_find.c
@@ -236,7 +236,7 @@ static int scan_spi_gpt(CgptFindParams *params) {
                partname, &sz, &erasesz, name) != 4)
       continue;
     if (strcmp(partname, "mtd0") == 0) {
-      char temp_dir[] = "/tmp/cgpt_find.XXXXXX";
+      char temp_dir[] = VBOOT_TMP_DIR "/cgpt_find.XXXXXX";
       if (params->drive_size == 0) {
         if (GetMtdSize("/dev/mtd0", &params->drive_size) != 0) {
           perror("GetMtdSize");
diff --git a/cgpt/cgpt_wrapper.c b/cgpt/cgpt_wrapper.c
index afa4940e..0fe76dd3 100644
--- a/cgpt/cgpt_wrapper.c
+++ b/cgpt/cgpt_wrapper.c
@@ -81,7 +81,7 @@ static int wrap_cgpt(int argc,
 
   // Create a temp dir to work in.
   ret++;
-  char temp_dir[] = "/tmp/cgpt_wrapper.XXXXXX";
+  char temp_dir[] = VBOOT_TMP_DIR "/cgpt_wrapper.XXXXXX";
   if (mkdtemp(temp_dir_template) == NULL) {
     Error("Cannot create a temporary directory.\n");
     return ret;
diff --git a/firmware/2lib/2gbb.c b/firmware/2lib/2gbb.c
index d5c46dce..1c7b4e0e 100644
--- a/firmware/2lib/2gbb.c
+++ b/firmware/2lib/2gbb.c
@@ -156,9 +156,9 @@ vb2_error_t vb2_get_gbb_flag_description(enum vb2_gbb_flag flag,
 		*description =
 			"Allow booting Legacy OSes even if dev_boot_altfw=0.";
 		break;
-	case VB2_GBB_FLAG_RUNNING_FAFT:
-		*name = "VB2_GBB_FLAG_RUNNING_FAFT";
-		*description = "Currently running FAFT tests.";
+	case VB2_GBB_FLAG_DEPRECATED_RUNNING_FAFT:
+		*name = "VB2_GBB_FLAG_DEPRECATED_RUNNING_FAFT";
+		*description = "Deprecated, do not use.";
 		break;
 	case VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC:
 		*name = "VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC";
@@ -193,6 +193,10 @@ vb2_error_t vb2_get_gbb_flag_description(enum vb2_gbb_flag flag,
 		*name = "VB2_GBB_FLAG_ENABLE_UDC";
 		*description = "Enable USB Device Controller.";
 		break;
+	case VB2_GBB_FLAG_FORCE_CSE_SYNC:
+		*name = "VB2_GBB_FLAG_FORCE_CSE_SYNC";
+		*description = "Always sync CSE, even if it is same as CBFS CSE";
+		break;
 	default:
 		*name = NULL;
 		*description = NULL;
diff --git a/firmware/2lib/2load_kernel.c b/firmware/2lib/2load_kernel.c
index 8c17b839..fcc09c57 100644
--- a/firmware/2lib/2load_kernel.c
+++ b/firmware/2lib/2load_kernel.c
@@ -25,10 +25,6 @@ enum vb2_load_partition_flags {
 
 #define KBUF_SIZE 65536  /* Bytes to read at start of kernel partition */
 
-/* Minimum context work buffer size needed for vb2_load_partition() */
-#define VB2_LOAD_PARTITION_WORKBUF_BYTES	\
-	(VB2_VERIFY_KERNEL_PREAMBLE_WORKBUF_BYTES + KBUF_SIZE)
-
 #define LOWEST_TPM_VERSION 0xffffffff
 
 /**
diff --git a/firmware/2lib/include/2gbb_flags.h b/firmware/2lib/include/2gbb_flags.h
index 5c92950b..df17633a 100644
--- a/firmware/2lib/include/2gbb_flags.h
+++ b/firmware/2lib/include/2gbb_flags.h
@@ -59,12 +59,13 @@ enum vb2_gbb_flag {
 	VB2_GBB_FLAG_FORCE_DEV_BOOT_ALTFW = 1 << 7,
 
 	/*
-	 * Currently running FAFT tests.  May be used as a hint to disable
-	 * other debug features which may interfere with tests.  However, this
-	 * should never be used to modify Chrome OS behaviour on specific
-	 * devices with the goal of passing a test.  See chromium:965914 for
-	 * more information.
+	 * This flag must never be used by anyone for any reason. It was created to
+	 * disable certain debugging features in vendor provided blobs so that they
+	 * could be used while running FAFT, but the flag has been misused elsewhere
+	 * and is now deprecated.
+	 * TODO: Remove VB2_GBB_FLAG_RUNNING_FAFT
 	 */
+	VB2_GBB_FLAG_DEPRECATED_RUNNING_FAFT = 1 << 8,
 	VB2_GBB_FLAG_RUNNING_FAFT = 1 << 8,
 
 	/* Disable EC software sync */
@@ -93,6 +94,9 @@ enum vb2_gbb_flag {
 
 	/* Enable USB Device Controller */
 	VB2_GBB_FLAG_ENABLE_UDC = 1 << 16,
+
+	/* Enforce CSE SYNC, even if current CSE is same as CBFS CSE */
+	VB2_GBB_FLAG_FORCE_CSE_SYNC = 1 << 17,
 };
 
 vb2_error_t vb2_get_gbb_flag_description(enum vb2_gbb_flag flag,
diff --git a/firmware/include/gpt_misc.h b/firmware/include/gpt_misc.h
index 776ed230..b2deb7ac 100644
--- a/firmware/include/gpt_misc.h
+++ b/firmware/include/gpt_misc.h
@@ -171,12 +171,12 @@ int IsUnusedEntry(const GptEntry *e);
 /**
  * Return size(in lba) of a partition represented by given GPT entry.
  */
-size_t GptGetEntrySizeLba(const GptEntry *e);
+uint64_t GptGetEntrySizeLba(const GptEntry *e);
 
 /**
  * Return size(in bytes) of a partition represented by given GPT entry.
  */
-size_t GptGetEntrySizeBytes(const GptData *gpt, const GptEntry *e);
+uint64_t GptGetEntrySizeBytes(const GptData *gpt, const GptEntry *e);
 
 /**
  * Updates the kernel entry with the specified index, using the specified type
diff --git a/firmware/lib/gpt_misc.c b/firmware/lib/gpt_misc.c
index e11dd2da..79ff6cde 100644
--- a/firmware/lib/gpt_misc.c
+++ b/firmware/lib/gpt_misc.c
@@ -233,7 +233,7 @@ int IsUnusedEntry(const GptEntry *e)
  * Desc: This function returns size(in lba) of a partition represented by
  * given GPT entry.
  */
-size_t GptGetEntrySizeLba(const GptEntry *e)
+uint64_t GptGetEntrySizeLba(const GptEntry *e)
 {
 	return (e->ending_lba - e->starting_lba + 1);
 }
@@ -243,7 +243,7 @@ size_t GptGetEntrySizeLba(const GptEntry *e)
  * Desc: This function returns size(in bytes) of a partition represented by
  * given GPT entry.
  */
-size_t GptGetEntrySizeBytes(const GptData *gpt, const GptEntry *e)
+uint64_t GptGetEntrySizeBytes(const GptData *gpt, const GptEntry *e)
 {
 	return GptGetEntrySizeLba(e) * gpt->sector_bytes;
 }
diff --git a/futility/cmd_load_fmap.c b/futility/cmd_load_fmap.c
index 9aaebb78..4578e413 100644
--- a/futility/cmd_load_fmap.c
+++ b/futility/cmd_load_fmap.c
@@ -75,8 +75,10 @@ static int copy_to_area(const char *file, uint8_t *buf,
 				area, file, strerror(errno));
 		retval = 1;
 	} else if (n < len) {
-		ERROR("Warning on area %s: only read %zu "
-			"(not %d) from %s\n", area, n, len, file);
+		WARN("area %s: %s size (%zu) smaller than area size %u; "
+		     "erasing remaining data to 0xff\n",
+		     area, file, n, len);
+		memset(buf + n, 0xff, len - n);
 	}
 
 	if (fclose(fp)) {
diff --git a/futility/cmd_update.c b/futility/cmd_update.c
index 77df9e1a..c000e70e 100644
--- a/futility/cmd_update.c
+++ b/futility/cmd_update.c
@@ -118,11 +118,10 @@ static void print_help(int argc, char *argv[])
 		"   cached manifest (may be out-dated) from the archive.\n"
 		"   Works only with -a,--archive option.\n"
 		" * Use of -p,--programmer with option other than '%s',\n"
-		"   or with --ccd effectively disables ability to update EC and PD\n"
+		"   or with --ccd effectively disables ability to update EC\n"
 		"   firmware images.\n"
-		" * Emulation works only with AP (host) firmware image, and does\n"
-		"   not accept EC or PD firmware image, and does not work\n"
-		"   with --mode=output\n"
+		" * Emulation works only with the AP (host) firmware image, and\n"
+		"   does not support the EC firmware image.\n"
 		" * Model detection with option --detect-model-only requires\n"
 		"   archive path -a,--archive\n"
 		" * The --quirks provides a set of options to override the\n"
@@ -136,6 +135,7 @@ static void print_help(int argc, char *argv[])
 		"    --force         \tForce update (skip checking contents)\n"
 		"    --output_dir=DIR\tSpecify the target for --mode=output\n"
 		"    --unlock_me     \t(deprecated) Unlock the Intel ME before flashing\n"
+		"    --signature_id=S\t(deprecated) Same as --model\n"
 		"\n"
 		"Debugging and testing options:\n"
 		"    --wp=1|0        \tSpecify write protection status\n"
@@ -143,7 +143,6 @@ static void print_help(int argc, char *argv[])
 		"    --model=MODEL   \tOverride system model for images\n"
 		"    --detect-model-only\tDetect model by reading the FRID and exit\n"
 		"    --gbb_flags=FLAG\tOverride new GBB flags\n"
-		"    --signature_id=S\tOverride signature ID for key files\n"
 		"    --sys_props=LIST\tList of system properties to override\n"
 		"-d, --debug         \tPrint debugging messages\n"
 		"-v, --verbose       \tPrint verbose messages\n"
@@ -158,6 +157,7 @@ static int do_update(int argc, char *argv[])
 	const char *prepare_ctrl_name = NULL;
 	char *servo_programmer = NULL;
 	char *endptr;
+	const char *sig = NULL;
 
 	struct updater_config *cfg = updater_new_config();
 	assert(cfg);
@@ -217,14 +217,22 @@ static int do_update(int argc, char *argv[])
 			args.output_dir = optarg;
 			break;
 		case OPT_MODEL:
+			if (sig) {
+				WARN("Ignore --model=%s because --signature_id=%s is already specified.\n", optarg, sig);
+			} else {
+				args.model = optarg;
+			}
+			break;
+		case OPT_SIGNATURE:
+			WARN("--signature_id is deprecated by --model. "
+			      "Please change to `--model=%s` in future.\n",
+			      optarg);
+			sig = optarg;
 			args.model = optarg;
 			break;
 		case OPT_DETECT_MODEL_ONLY:
 			args.detect_model_only = true;
 			break;
-		case OPT_SIGNATURE:
-			args.signature_id = optarg;
-			break;
 		case OPT_WRITE_PROTECTION:
 			args.write_protection = optarg;
 			break;
diff --git a/futility/file_type_bios.c b/futility/file_type_bios.c
index c4da9a19..6cb3d731 100644
--- a/futility/file_type_bios.c
+++ b/futility/file_type_bios.c
@@ -409,6 +409,11 @@ static int prepare_slot(uint8_t *buf, uint32_t len, enum bios_component fw_c,
 		(struct vb2_keyblock *)state->area[vblock_c].buf;
 	int vblock_valid = 0;
 
+	if (keyblock->magic[0] == 0xff) {
+		/* Keyblock does not exist yet. Skip directly to creating a new one. */
+		goto end;
+	}
+
 	if (vb2_verify_keyblock_hash(keyblock, state->area[vblock_c].len,
 				     &wb) != VB2_SUCCESS) {
 		WARN("%s keyblock is invalid.\n", vblock_name);
diff --git a/futility/futility.c b/futility/futility.c
index 1dbded06..8bc1820c 100644
--- a/futility/futility.c
+++ b/futility/futility.c
@@ -16,164 +16,9 @@
 
 #include "futility.h"
 
-/******************************************************************************/
-/* Logging stuff */
-
-/* File to use for logging, if present */
-#define LOGFILE "/tmp/futility.log"
-
-/* Normally logging will only happen if the logfile already exists. Uncomment
- * this to force log file creation (and thus logging) always. */
-
-/* #define FORCE_LOGGING_ON */
-
-static int log_fd = -1;
 const char *ft_print_header = NULL;
 const char *ft_print_header2 = NULL;
 
-/* Write the string and a newline. Silently give up on errors */
-static void log_str(const char *prefix, const char *str)
-{
-	int len, done, n;
-
-	if (log_fd < 0)
-		return;
-
-	if (!str)
-		str = "(NULL)";
-
-	if (prefix && *prefix) {
-		len = strlen(prefix);
-		for (done = 0; done < len; done += n) {
-			n = write(log_fd, prefix + done, len - done);
-			if (n < 0)
-				return;
-		}
-	}
-
-	len = strlen(str);
-	if (len == 0) {
-		str = "(EMPTY)";
-		len = strlen(str);
-	}
-
-	for (done = 0; done < len; done += n) {
-		n = write(log_fd, str + done, len - done);
-		if (n < 0)
-			return;
-	}
-
-	if (write(log_fd, "\n", 1) < 0)
-		return;
-}
-
-static void log_close(void)
-{
-	struct flock lock;
-
-	if (log_fd >= 0) {
-		memset(&lock, 0, sizeof(lock));
-		lock.l_type = F_UNLCK;
-		lock.l_whence = SEEK_SET;
-		if (fcntl(log_fd, F_SETLKW, &lock))
-			perror("Unable to unlock log file");
-
-		close(log_fd);
-		log_fd = -1;
-	}
-}
-
-static void log_open(void)
-{
-	struct flock lock;
-	int ret;
-
-#ifdef FORCE_LOGGING_ON
-	log_fd = open(LOGFILE, O_WRONLY | O_APPEND | O_CREAT, 0666);
-#else
-	log_fd = open(LOGFILE, O_WRONLY | O_APPEND);
-#endif
-	if (log_fd < 0) {
-
-		if (errno != EACCES)
-			return;
-
-		/* Permission problems should improve shortly ... */
-		sleep(1);
-		log_fd = open(LOGFILE, O_WRONLY | O_APPEND | O_CREAT, 0666);
-		if (log_fd < 0)	/* Nope, they didn't */
-			return;
-	}
-
-	/* Let anyone have a turn */
-	fchmod(log_fd, 0666);
-
-	/* But only one at a time */
-	memset(&lock, 0, sizeof(lock));
-	lock.l_type = F_WRLCK;
-	lock.l_whence = SEEK_END;
-
-	ret = fcntl(log_fd, F_SETLKW, &lock);	/* this blocks */
-	if (ret < 0)
-		log_close();
-}
-
-static void log_args(int argc, char *argv[])
-{
-	int i;
-	ssize_t r;
-	pid_t parent;
-	char buf[80];
-	FILE *fp;
-	char caller_buf[PATH_MAX];
-
-	log_open();
-
-	/* delimiter */
-	log_str(NULL, "##### LOG #####");
-
-	/* Can we tell who called us? */
-	parent = getppid();
-	snprintf(buf, sizeof(buf), "/proc/%d/exe", parent);
-	r = readlink(buf, caller_buf, sizeof(caller_buf) - 1);
-	if (r >= 0) {
-		caller_buf[r] = '\0';
-		log_str("CALLER:", caller_buf);
-	}
-
-	/* From where? */
-	snprintf(buf, sizeof(buf), "/proc/%d/cwd", parent);
-	r = readlink(buf, caller_buf, sizeof(caller_buf) - 1);
-	if (r >= 0) {
-		caller_buf[r] = '\0';
-		log_str("DIR:", caller_buf);
-	}
-
-	/* And maybe the args? */
-	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", parent);
-	fp = fopen(buf, "r");
-	if (fp) {
-		memset(caller_buf, 0, sizeof(caller_buf));
-		r = fread(caller_buf, 1, sizeof(caller_buf) - 1, fp);
-		if (r > 0) {
-			char *s = caller_buf;
-			for (i = 0; i < r && *s; ) {
-				log_str("CMDLINE:", s);
-				while (i < r && *s)
-					i++, s++;
-				i++, s++;
-			}
-		}
-		fclose(fp);
-	}
-
-	/* Now log the stuff about ourselves */
-	for (i = 0; i < argc; i++)
-		log_str(NULL, argv[i]);
-
-	log_close();
-}
-
 /******************************************************************************/
 
 static const char *const usage = "\n"
@@ -308,8 +153,6 @@ int main(int argc, char *argv[], char *envp[])
 		{ 0, 0, 0, 0},
 	};
 
-	log_args(argc, argv);
-
 	/* How were we invoked? */
 	progname = simple_basename(argv[0]);
 
diff --git a/futility/updater.c b/futility/updater.c
index 31de6ef7..b958f435 100644
--- a/futility/updater.c
+++ b/futility/updater.c
@@ -70,6 +70,24 @@ static void override_dut_property(enum dut_property_type property_type,
 	prop->value = value;
 }
 
+/*
+ * Overrides DUT properties with default values.
+ * With emulation, dut_get_property() calls would fail without specifying the
+ * fake DUT properties via --sys_props. Therefore, this function provides
+ * reasonable default values for emulation.
+ */
+static void override_properties_with_default(struct updater_config *cfg)
+{
+	assert(cfg->emulation);
+
+	override_dut_property(DUT_PROP_MAINFW_ACT, cfg, SLOT_A);
+	override_dut_property(DUT_PROP_TPM_FWVER, cfg, 0x10001);
+	override_dut_property(DUT_PROP_PLATFORM_VER, cfg, 0);
+	override_dut_property(DUT_PROP_WP_HW, cfg, 0);
+	override_dut_property(DUT_PROP_WP_SW_AP, cfg, 0);
+	override_dut_property(DUT_PROP_WP_SW_EC, cfg, 0);
+}
+
 /*
  * Overrides DUT properties from a given list.
  * The list should be string of integers eliminated by comma and/or space.
@@ -113,14 +131,12 @@ static void override_properties_from_list(const char *override_list,
 	}
 }
 
-/* Gets the value (setting) of specified quirks from updater configuration. */
 int get_config_quirk(enum quirk_types quirk, const struct updater_config *cfg)
 {
 	assert(quirk < QUIRK_MAX);
 	return cfg->quirks[quirk].value;
 }
 
-/* Prints the name and description from all supported quirks. */
 void updater_list_config_quirks(const struct updater_config *cfg)
 {
 	const struct quirk_entry *entry = cfg->quirks;
@@ -250,7 +266,7 @@ static const char *decide_rw_target(struct updater_config *cfg,
 static int set_try_cookies(struct updater_config *cfg, const char *target,
 			   int has_update)
 {
-	int tries = 11;
+	int tries = 13;
 	const char *slot;
 
 	if (!has_update)
@@ -580,9 +596,6 @@ static int check_compatible_platform(struct updater_config *cfg)
 	return strncasecmp(image_from->ro_version, image_to->ro_version, len);
 }
 
-/*
- * Returns a valid root key from GBB header, or NULL on failure.
- */
 const struct vb2_packed_key *get_rootkey(
 		const struct vb2_gbb_header *gbb)
 {
@@ -1132,10 +1145,6 @@ static enum updater_error_codes update_whole_firmware(
 	return UPDATE_ERR_DONE;
 }
 
-/*
- * The main updater to update system firmware using the configuration parameter.
- * Returns UPDATE_ERR_DONE if success, otherwise failure.
- */
 enum updater_error_codes update_firmware(struct updater_config *cfg)
 {
 	bool done = false;
@@ -1243,10 +1252,6 @@ enum updater_error_codes update_firmware(struct updater_config *cfg)
 	return r;
 }
 
-/*
- * Allocates and initializes a updater_config object with default values.
- * Returns the newly allocated object, or NULL on error.
- */
 struct updater_config *updater_new_config(void)
 {
 	struct updater_config *cfg = (struct updater_config *)calloc(
@@ -1317,11 +1322,17 @@ static int updater_load_images(struct updater_config *cfg,
 		if (!errorcnt)
 			errorcnt += updater_setup_quirks(cfg, arg);
 	}
-	if (arg->host_only || arg->emulation)
+
+	/*
+	 * In emulation mode, we want to prevent unexpected writing to EC
+	 * so we should not load EC; however in output mode that is fine.
+	 */
+	if (arg->host_only || (arg->emulation && !cfg->output_only))
 		return errorcnt;
 
 	if (!cfg->ec_image.data && ec_image)
 		errorcnt += !!load_firmware_image(&cfg->ec_image, ec_image, ar);
+
 	return errorcnt;
 }
 
@@ -1349,37 +1360,6 @@ static int updater_output_image(const struct firmware_image *image,
 	return !!r;
 }
 
-/*
- * Applies custom label information to an existing model config.
- * Returns 0 on success, otherwise failure.
- */
-static int updater_apply_custom_label(struct updater_config *cfg,
-				     struct model_config *model,
-				     const char *signature_id)
-{
-	const char *tmp_image = NULL;
-
-	assert(model->is_custom_label);
-	if (!signature_id) {
-		if (!cfg->image_current.data) {
-			INFO("Loading system firmware for custom label...\n");
-			load_system_firmware(cfg, &cfg->image_current);
-		}
-		tmp_image = get_firmware_image_temp_file(
-				&cfg->image_current, &cfg->tempfiles);
-		if (!tmp_image) {
-			ERROR("Failed to get system current firmware\n");
-			return 1;
-		}
-		if (get_config_quirk(QUIRK_OVERRIDE_SIGNATURE_ID, cfg) &&
-		    is_ap_write_protection_enabled(cfg))
-			quirk_override_signature_id(
-					cfg, model, &signature_id);
-	}
-	return !!model_apply_custom_label(
-			model, cfg->archive, signature_id, tmp_image);
-}
-
 /*
  * Setup what the updater has to do against an archive.
  * Returns number of failures, or 0 on success.
@@ -1412,29 +1392,69 @@ static int updater_setup_archive(
 	errorcnt += updater_load_images(
 			cfg, arg, model->image, model->ec_image);
 
-	if (model->is_custom_label && !manifest->has_keyset) {
+	/*
+	 * For custom label devices, we have to read the system firmware
+	 * (image_current) to get the tag from VPD. Some quirks may also need
+	 * the system firmware to identify if they should override the tags.
+	 *
+	 * The only exception is `--mode=output` (cfg->output_only), which we
+	 * usually add `--model=MODEL` to specify the target model (note some
+	 * people may still run without `--model` to get "the image to update
+	 * when running on this device"). The MODEL can be either the BASEMODEL
+	 * (has_custom_label=true) or BASEMODEL-TAG (has_custom_label=false).
+	 * So the only case we have to warn the user that they may forget to
+	 * provide the TAG is when has_custom_label=true (only BASEMODEL).
+	 */
+	if (cfg->output_only && arg->model && model->has_custom_label) {
+		printf(">> Generating output for a custom label device without tags (e.g., base model). "
+		       "The firmware images will be signed using the base model (or DEFAULT) keys. "
+		       "To get the images signed by the LOEM keys, "
+		       "add the corresponding tag from one of the following list: \n");
+
+		size_t len = strlen(arg->model);
+		bool printed = false;
+		int i;
+
+		for (i = 0; i < manifest->num; i++) {
+			const struct model_config *m = &manifest->models[i];
+			if (strncmp(m->name, arg->model, len) || m->name[len] != '-')
+				continue;
+			printf("%s `--model=%s`", printed ? "," : "", m->name);
+			printed = true;
+		}
+		printf("\n\n");
+	} else if (model->has_custom_label) {
+		if (!cfg->image_current.data) {
+			INFO("Loading system firmware for custom label...\n");
+			load_system_firmware(cfg, &cfg->image_current);
+		}
+
+		if (!cfg->image_current.data) {
+			ERROR("Cannot read the system firmware for tags.\n");
+			return ++errorcnt;
+		}
 		/*
-		 * Developers running unsigned updaters (usually local build)
-		 * won't be able match any custom label tags.
+		 * For custom label devices, manifest_find_model may return the
+		 * base model instead of the custom label ones so we have to
+		 * look up again.
 		 */
-		WARN("No keysets found - this is probably a local build of \n"
-		     "unsigned firmware updater. Skip applying custom label.");
-	} else if (model->is_custom_label) {
+		const struct model_config *base_model = model;
+		model = manifest_find_custom_label_model(cfg, manifest, base_model);
+		if (!model)
+			return ++errorcnt;
 		/*
-		 * It is fine to fail in updater_apply_custom_label for factory
-		 * mode so we are not checking the return value; instead we
-		 * verify if the patches do contain new root key.
+		 * All custom label models should share the same image, so we
+		 * don't need to reload again - just pick up the new config and
+		 * patch later. We don't care about EC images because that will
+		 * be updated by software sync in the end.
+		 * Here we want to double check if that assumption is correct.
 		 */
-		updater_apply_custom_label(cfg, (struct model_config *)model,
-					  arg->signature_id);
-		if (!model->patches.rootkey) {
-			if (is_factory ||
-			    is_ap_write_protection_enabled(cfg) ||
-			    get_config_quirk(QUIRK_ALLOW_EMPTY_CUSTOM_LABEL_TAG,
-					     cfg)) {
-				WARN("No VPD for custom label.\n");
-			} else {
-				ERROR("Need VPD set for custom label.\n");
+		if (base_model->image) {
+			if (!model->image ||
+			    strcmp(base_model->image, model->image)) {
+				ERROR("The firmware image for custom label [%s] "
+				      "does not match its base model [%s]\n",
+				      base_model->name, model->name);
 				return ++errorcnt;
 			}
 		}
@@ -1492,8 +1512,7 @@ static int check_arg_compatibility(
 }
 
 static int parse_arg_mode(struct updater_config *cfg,
-			  const struct updater_config_arguments *arg,
-			  bool *do_output)
+			  const struct updater_config_arguments *arg)
 {
 	if (!arg->mode)
 		return 0;
@@ -1512,7 +1531,7 @@ static int parse_arg_mode(struct updater_config *cfg,
 		   strcmp(arg->mode, "factory_install") == 0) {
 		cfg->factory_update = 1;
 	} else if (strcmp(arg->mode, "output") == 0) {
-		*do_output = 1;
+		cfg->output_only = true;
 	} else {
 		ERROR("Invalid mode: %s\n", arg->mode);
 		return -1;
@@ -1649,7 +1668,6 @@ int updater_setup_config(struct updater_config *cfg,
 	int errorcnt = 0;
 	int check_wp_disabled = 0;
 	bool check_single_image = false;
-	bool do_output = false;
 	const char *archive_path = arg->archive;
 
 	/* Setup values that may change output or decision of other argument. */
@@ -1672,7 +1690,7 @@ int updater_setup_config(struct updater_config *cfg,
 	if (arg->try_update)
 		cfg->try_update = TRY_UPDATE_AUTO;
 
-	if (parse_arg_mode(cfg, arg, &do_output) < 0)
+	if (parse_arg_mode(cfg, arg) < 0)
 		return 1;
 
 	if (cfg->factory_update) {
@@ -1688,6 +1706,8 @@ int updater_setup_config(struct updater_config *cfg,
 	if (prog_arg_emulation(cfg, arg, &check_single_image) < 0)
 		return 1;
 
+	if (arg->emulation)
+		override_properties_with_default(cfg);
 	if (arg->sys_props)
 		override_properties_from_list(arg->sys_props, cfg);
 	if (arg->write_protection) {
@@ -1761,7 +1781,7 @@ int updater_setup_config(struct updater_config *cfg,
 		errorcnt += !!setup_config_quirks(arg->quirks, cfg);
 
 	/* Additional checks. */
-	if (check_single_image && !do_output && cfg->ec_image.data) {
+	if (check_single_image && !cfg->output_only && cfg->ec_image.data) {
 		errorcnt++;
 		ERROR("EC/PD images are not supported in current mode.\n");
 	}
@@ -1780,7 +1800,7 @@ int updater_setup_config(struct updater_config *cfg,
 	}
 
 	/* The images are ready for updating. Output if needed. */
-	if (!errorcnt && do_output) {
+	if (!errorcnt && cfg->output_only) {
 		const char *r = arg->output_dir;
 		if (!r)
 			r = ".";
@@ -1846,9 +1866,6 @@ int handle_flash_argument(struct updater_config_arguments *args, int opt,
 	return 1;
 }
 
-/*
- * Releases all resources in an updater configuration object.
- */
 void updater_delete_config(struct updater_config *cfg)
 {
 	assert(cfg);
diff --git a/futility/updater.h b/futility/updater.h
index d4a7f0fa..00f2c46b 100644
--- a/futility/updater.h
+++ b/futility/updater.h
@@ -32,6 +32,7 @@ static const char * const FMAP_RO = "WP_RO",
 		  * const FMAP_RW_SHARED = "RW_SHARED",
 		  * const FMAP_RW_LEGACY = "RW_LEGACY",
 		  * const FMAP_RW_VPD = "RW_VPD",
+		  * const FMAP_RW_DIAG_NVRAM = "DIAG_NVRAM",
 		  * const FMAP_SI_DESC = "SI_DESC",
 		  * const FMAP_SI_ME = "SI_ME";
 
@@ -55,8 +56,7 @@ enum quirk_types {
 	QUIRK_CLEAR_MRC_DATA,
 	QUIRK_PRESERVE_ME,
 	/* Platform-specific quirks (removed after AUE) */
-	QUIRK_ALLOW_EMPTY_CUSTOM_LABEL_TAG,
-	QUIRK_OVERRIDE_SIGNATURE_ID,
+	QUIRK_OVERRIDE_CUSTOM_LABEL,
 	QUIRK_EVE_SMM_STORE,
 	QUIRK_UNLOCK_CSME_EVE,
 	QUIRK_UNLOCK_CSME,
@@ -101,13 +101,14 @@ struct updater_config {
 	uint32_t gbb_flags;
 	bool detect_model;
 	bool dut_is_remote;
+	bool output_only;
 };
 
 struct updater_config_arguments {
 	char *image, *ec_image;
 	char *archive, *quirks, *mode;
 	const char *programmer, *write_protection;
-	char *model, *signature_id;
+	char *model;
 	char *emulation, *sys_props;
 	char *output_dir;
 	char *repack, *unpack;
@@ -166,8 +167,7 @@ struct model_config {
 	char *name;
 	char *image, *ec_image;
 	struct patch_config patches;
-	char *signature_id;
-	int is_custom_label;
+	bool has_custom_label;
 };
 
 struct manifest {
@@ -175,7 +175,6 @@ struct manifest {
 	struct model_config *models;
 	struct u_archive *archive;
 	int default_model;
-	int has_keyset;
 };
 
 enum updater_error_codes {
@@ -267,12 +266,13 @@ const char * const updater_get_model_quirks(struct updater_config *cfg);
 char * updater_get_cbfs_quirks(struct updater_config *cfg);
 
 /*
- * Overrides signature id if the device was shipped with known
+ * Overrides the custom label config if the device was shipped with known
  * special rootkey.
  */
-int quirk_override_signature_id(struct updater_config *cfg,
-				struct model_config *model,
-				const char **signature_id);
+const struct model_config *quirk_override_custom_label(
+		struct updater_config *cfg,
+		const struct manifest *manifest,
+		const struct model_config *model);
 
 /* Functions from updater_archive.c */
 
@@ -368,15 +368,14 @@ manifest_detect_model_from_frid(struct updater_config *cfg,
 				struct manifest *manifest);
 
 /*
- * Applies custom label information to an existing model configuration.
- * Collects signature ID information from either parameter signature_id or
- * image file (via VPD) and updates model.patches for key files.
- * Returns 0 on success, otherwise failure.
+ * Finds the custom label model config from the base model + system tag.
+ * The system tag came from the firmware VPD section.
+ * Returns the matched model_config, base if no applicable custom label data,
+ * or NULL for any critical error.
  */
-int model_apply_custom_label(
-		struct model_config *model,
-		struct u_archive *archive,
-		const char *signature_id,
-		const char *image);
+const struct model_config *manifest_find_custom_label_model(
+		struct updater_config *cfg,
+		const struct manifest *manifest,
+		const struct model_config *base_model);
 
 #endif  /* VBOOT_REFERENCE_FUTILITY_UPDATER_H_ */
diff --git a/futility/updater_archive.c b/futility/updater_archive.c
index 4f472e07..3d22cc5b 100644
--- a/futility/updater_archive.c
+++ b/futility/updater_archive.c
@@ -540,12 +540,6 @@ static int archive_zip_write_file(void *handle, const char *fname,
  * -- The public functions for using u_archive. --
  */
 
-/*
- * Opens an archive from given path.
- * The type of archive will be determined automatically.
- * Returns a pointer to reference to archive (must be released by archive_close
- * when not used), otherwise NULL on error.
- */
 struct u_archive *archive_open(const char *path)
 {
 	struct stat path_stat;
@@ -622,10 +616,6 @@ struct u_archive *archive_open(const char *path)
 	return ar;
 }
 
-/*
- * Closes an archive reference.
- * Returns 0 on success, otherwise non-zero as failure.
- */
 int archive_close(struct u_archive *ar)
 {
 	int r = ar->close(ar->handle);
@@ -633,12 +623,6 @@ int archive_close(struct u_archive *ar)
 	return r;
 }
 
-/*
- * Checks if an entry (either file or directory) exists in archive.
- * If entry name (fname) is an absolute path (/file), always check
- * with real file system.
- * Returns 1 if exists, otherwise 0
- */
 int archive_has_entry(struct u_archive *ar, const char *name)
 {
 	if (!ar || *name == '/')
@@ -646,13 +630,6 @@ int archive_has_entry(struct u_archive *ar, const char *name)
 	return ar->has_entry(ar->handle, name);
 }
 
-/*
- * Traverses all files within archive (directories are ignored).
- * For every entry, the path (relative the archive root) will be passed to
- * callback function, until the callback returns non-zero.
- * The arg argument will also be passed to callback.
- * Returns 0 on success otherwise non-zero as failure.
- */
 int archive_walk(struct u_archive *ar, void *arg,
 		 int (*callback)(const char *path, void *arg))
 {
@@ -661,15 +638,6 @@ int archive_walk(struct u_archive *ar, void *arg,
 	return ar->walk(ar->handle, arg, callback);
 }
 
-/*
- * Reads a file from archive.
- * If entry name (fname) is an absolute path (/file), always read
- * from real file system.
- * The returned data must always have one extra (not included by size) '\0' in
- * the end of the allocated buffer for C string processing.
- * Returns 0 on success (data and size reflects the file content),
- * otherwise non-zero as failure.
- */
 int archive_read_file(struct u_archive *ar, const char *fname,
 		      uint8_t **data, uint32_t *size, int64_t *mtime)
 {
@@ -678,12 +646,6 @@ int archive_read_file(struct u_archive *ar, const char *fname,
 	return ar->read_file(ar->handle, fname, data, size, mtime);
 }
 
-/*
- * Writes a file into archive.
- * If entry name (fname) is an absolute path (/file), always write into real
- * file system.
- * Returns 0 on success, otherwise non-zero as failure.
- */
 int archive_write_file(struct u_archive *ar, const char *fname,
 		       uint8_t *data, uint32_t size, int64_t mtime)
 {
@@ -716,10 +678,6 @@ static int archive_copy_callback(const char *path, void *_arg)
 	return r;
 }
 
-/*
- * Copies all entries from one archive to another.
- * Returns 0 on success, otherwise non-zero as failure.
- */
 int archive_copy(struct u_archive *from, struct u_archive *to)
 {
 	struct _copy_arg arg = { .from = from, .to = to };
diff --git a/futility/updater_dut.c b/futility/updater_dut.c
index dd2e7310..5179481f 100644
--- a/futility/updater_dut.c
+++ b/futility/updater_dut.c
@@ -13,16 +13,6 @@
 #include "crossystem.h"
 #include "updater.h"
 
-/**
- * dut_get_manifest_key() - Wrapper to get the firmware manifest key from crosid
- *
- * @manifest_key_out - Output parameter of the firmware manifest key.
- *
- * Returns:
- * - <0 if libcrosid is unavailable or there was an error reading
- *   device data
- * - >=0 (the matched device index) success
- */
 int dut_get_manifest_key(char **manifest_key_out, struct updater_config *cfg)
 {
 	if (cfg->dut_is_remote) {
@@ -148,12 +138,6 @@ static inline int dut_get_wp_sw_ec(struct updater_config *cfg)
 
 /* Helper functions to use or configure the DUT properties. */
 
-/*
- * Gets the DUT system property by given type.
- * If the property was not loaded yet, invoke the property getter function
- * and cache the result.
- * Returns the property value.
- */
 int dut_get_property(enum dut_property_type property_type,
 		     struct updater_config *cfg)
 {
diff --git a/futility/updater_manifest.c b/futility/updater_manifest.c
index 30edacfc..c9d8c509 100644
--- a/futility/updater_manifest.c
+++ b/futility/updater_manifest.c
@@ -22,55 +22,44 @@
  * image files in the top folder:
  *  - host: 'image.bin'
  *  - ec: 'ec.bin'
- *  - pd: 'pd.bin'
  *
- * If custom label is supported, a 'keyset/' folder will be available, with key
- * files in it:
- *  - rootkey.$CLTAG
- *  - vblock_A.$CLTAG
- *  - vblock_B.$CLTAG
+ * A package for Unified Build is more complicated.
  *
- * The $CLTAG should come from VPD value 'custom_label_tag'. For legacy devices,
- * the VPD name may be 'whitelabel_tag', or 'customization_id'.
- * The 'customization_id' has a different format: LOEM[-VARIANT] and we can only
- * take LOEM as $CLTAG, for example A-B => $CLTAG=A.
+ * You need to look at the signer_config.csv file to find the columns of
+ * model_name, image files (firmware_image, ec_image) and then search for
+ * patch files (root key, vblock files, GSC verification data, ...) in the
+ * keyset/ folder:
  *
- * A package for Unified Build is more complicated.
+ *  - rootkey.$MODEL_NAME
+ *  - vblock_A.$MODEL_NAME
+ *  - vblock_B.$MODEL_NAME
+ *  - gscvd.$MODEL_NAME
  *
- * You need to look at the signer_config.csv file to find image files and their
- * firmware manifest key (usually the same as the model name), then search for
- * patch files in the keyset/ folder.
+ * In the runtime, the updater should query for firmware manifest key (
+ * `crosid -f FIRMWARE_MANIFEST_KEY`) and use that to match the 'model_name'
+ * in the manifest database.
  *
- * Similar to custom label in non-Unified-Build, the keys and vblock files will
- * be available in the 'keyset/' folder:
- *  - rootkey.$MANIFEST_KEY
- *  - vblock_A.$MANIFEST_KEY
- *  - vblock_B.$MANIFEST_KEY
+ * If the model_name in `signer_config.csv` contains '-' then it is a custom
+ * label device. Today the FIRMWARE_MANIFEST_KEY from crosid won't handle custom
+ * label information and we have to add the custom label tag in the matching
+ * process.
  *
- * Historically (the original design in Unified Build) there should also be a
- * models/ folder, and each model should appear as a sub folder, with
- * a 'setvars.sh' file inside. The 'setvars.sh' is a shell script
- * describing what files should be used and the signature ID ($SIGID) to
- * use as firmware manifest key. If $SIGID starts with 'sig-id-in-*' then we
- * have to replace it by VPD value 'custom_label_tag' as '$MODEL-$CLTAG'.
+ * To do that, find the custom label tag from the VPD.
+ * - Newer devices: model_name = FIRMWARE_MANIFEST_KEY-$custom_label_tag
+ * - Old devices: model_name = FIRMWARE_MANIFEST_KEY-$whitelabel_tag
  *
- * The current implementation is to try `signer_config.csv` approach first, and
- * then fallback to `setvars.sh` on failure.
+ * For legacy devices manufactured before Unified Build, they have the VPD
+ * 'customization_id' in a special format: LOEM[-VARIANT].
+ * For example: "A-B" => LOEM="A".
+ * - Legacy devices: model_name = FIRMWARE_MANIFEST_KEY-$LOEM
  */
 
-static const char * const SETVARS_IMAGE_MAIN = "IMAGE_MAIN",
-		  * const SETVARS_IMAGE_EC = "IMAGE_EC",
-		  * const SETVARS_SIGNATURE_ID = "SIGNATURE_ID",
-		  * const SIG_ID_IN_VPD_PREFIX = "sig-id-in",
-		  * const DIR_MODELS = "models",
-		  * const DEFAULT_MODEL_NAME = "default",
+static const char * const DEFAULT_MODEL_NAME = "default",
 		  * const VPD_CUSTOM_LABEL_TAG = "custom_label_tag",
 		  * const VPD_CUSTOM_LABEL_TAG_LEGACY = "whitelabel_tag",
 		  * const VPD_CUSTOMIZATION_ID = "customization_id",
-		  * const ENV_VAR_MODEL_DIR = "${MODEL_DIR}",
 		  * const PATH_KEYSET_FOLDER = "keyset/",
-		  * const PATH_SIGNER_CONFIG = "signer_config.csv",
-		  * const PATH_ENDSWITH_SETVARS = "/setvars.sh";
+		  * const PATH_SIGNER_CONFIG = "signer_config.csv";
 
 /* Utility function to convert a string. */
 static void str_convert(char *s, int (*convert)(int c))
@@ -85,21 +74,6 @@ static void str_convert(char *s, int (*convert)(int c))
 	}
 }
 
-/* Returns 1 if name ends by given pattern, otherwise 0. */
-static int str_endswith(const char *name, const char *pattern)
-{
-	size_t name_len = strlen(name), pattern_len = strlen(pattern);
-	if (name_len < pattern_len)
-		return 0;
-	return strcmp(name + name_len - pattern_len, pattern) == 0;
-}
-
-/* Returns 1 if name starts by given pattern, otherwise 0. */
-static int str_startswith(const char *name, const char *pattern)
-{
-	return strncmp(name, pattern, strlen(pattern)) == 0;
-}
-
 /* Returns the VPD value by given key name, or NULL on error (or no value). */
 static char *vpd_get_value(const char *fpath, const char *key)
 {
@@ -117,66 +91,6 @@ static char *vpd_get_value(const char *fpath, const char *key)
 	return result;
 }
 
-/*
- * Reads and parses a setvars type file from archive, then stores into config.
- * Returns 0 on success (at least one entry found), otherwise failure.
- */
-static int model_config_parse_setvars_file(
-		struct model_config *cfg, struct u_archive *archive,
-		const char *fpath)
-{
-	uint8_t *data;
-	uint32_t len;
-
-	char *ptr_line = NULL, *ptr_token = NULL;
-	char *line, *k, *v;
-	int valid = 0;
-
-	if (archive_read_file(archive, fpath, &data, &len, NULL) != 0) {
-		ERROR("Failed reading: %s\n", fpath);
-		return -1;
-	}
-
-	/* Valid content should end with \n, or \"; ensure ASCIIZ for parsing */
-	if (len)
-		data[len - 1] = '\0';
-
-	for (line = strtok_r((char *)data, "\n\r", &ptr_line); line;
-	     line = strtok_r(NULL, "\n\r", &ptr_line)) {
-		char *expand_path = NULL;
-		int found_valid = 1;
-
-		/* Format: KEY="value" */
-		k = strtok_r(line, "=", &ptr_token);
-		if (!k)
-			continue;
-		v = strtok_r(NULL, "\"", &ptr_token);
-		if (!v)
-			continue;
-
-		/* Some legacy updaters may be still using ${MODEL_DIR}. */
-		if (str_startswith(v, ENV_VAR_MODEL_DIR)) {
-			ASPRINTF(&expand_path, "%s/%s%s", DIR_MODELS, cfg->name,
-				 v + strlen(ENV_VAR_MODEL_DIR));
-		}
-
-		if (strcmp(k, SETVARS_IMAGE_MAIN) == 0)
-			cfg->image = strdup(v);
-		else if (strcmp(k, SETVARS_IMAGE_EC) == 0)
-			cfg->ec_image = strdup(v);
-		else if (strcmp(k, SETVARS_SIGNATURE_ID) == 0) {
-			cfg->signature_id = strdup(v);
-			if (str_startswith(v, SIG_ID_IN_VPD_PREFIX))
-				cfg->is_custom_label = 1;
-		} else
-			found_valid = 0;
-		free(expand_path);
-		valid += found_valid;
-	}
-	free(data);
-	return valid == 0;
-}
-
 /*
  * Changes the rootkey in firmware GBB to given new key.
  * Returns 0 on success, otherwise failure.
@@ -291,8 +205,7 @@ int patch_image_by_model(
  * Updates `model` argument with path of patch files.
  */
 static void find_patches_for_model(struct model_config *model,
-				   struct u_archive *archive,
-				   const char *signature_id)
+				   struct u_archive *archive)
 {
 	char *path;
 	int i;
@@ -313,7 +226,7 @@ static void find_patches_for_model(struct model_config *model,
 
 	assert(ARRAY_SIZE(names) == ARRAY_SIZE(targets));
 	for (i = 0; i < ARRAY_SIZE(names); i++) {
-		ASPRINTF(&path, "%s%s.%s", PATH_KEYSET_FOLDER, names[i], signature_id);
+		ASPRINTF(&path, "%s%s.%s", PATH_KEYSET_FOLDER, names[i], model->name);
 		if (archive_has_entry(archive, path))
 			*targets[i] = path;
 		else
@@ -342,46 +255,6 @@ static struct model_config *manifest_add_model(
 	return model;
 }
 
-/*
- * A callback function for manifest to scan files in archive.
- * Returns 0 to keep scanning, or non-zero to stop.
- */
-static int manifest_scan_entries(const char *name, void *arg)
-{
-	struct manifest *manifest = (struct manifest *)arg;
-	struct u_archive *archive = manifest->archive;
-	struct model_config model = {0};
-	char *slash;
-
-	if (!str_endswith(name, PATH_ENDSWITH_SETVARS))
-		return 0;
-
-	/* name: models/$MODEL/setvars.sh */
-	model.name = strdup(strchr(name, '/') + 1);
-	slash = strchr(model.name, '/');
-	if (slash)
-		*slash = '\0';
-
-	VB2_DEBUG("Found model <%s> setvars: %s\n", model.name, name);
-	if (model_config_parse_setvars_file(&model, archive, name)) {
-		ERROR("Invalid setvars file: %s\n", name);
-		return 0;
-	}
-
-	/* In legacy setvars.sh, the ec_image may not exist. */
-	if (model.ec_image && !archive_has_entry(archive, model.ec_image)) {
-		VB2_DEBUG("Ignore non-exist EC image: %s\n", model.ec_image);
-		free(model.ec_image);
-		model.ec_image = NULL;
-	}
-
-	/* Find patch files. */
-	if (model.signature_id)
-		find_patches_for_model(&model, archive, model.signature_id);
-
-	return !manifest_add_model(manifest, &model);
-}
-
 /*
  * A callback function for manifest to scan files in raw /firmware archive.
  * Returns 0 to keep scanning, or non-zero to stop.
@@ -462,8 +335,8 @@ static int manifest_from_signer_config(struct manifest *manifest)
 	/*
 	 * CSV format: model_name,firmware_image,key_id,ec_image
 	 *
-	 * Note the key_id is not signature_id and won't be used, and ec_image
-	 * may be optional (for example sarien).
+	 * Note the key_id is for signer and won't be used by the updater,
+	 * and ec_image may be optional (for example sarien).
 	 */
 
 	if (archive_read_file(archive, PATH_SIGNER_CONFIG, &data, &size,NULL)) {
@@ -483,7 +356,6 @@ static int manifest_from_signer_config(struct manifest *manifest)
 	     s = strtok_r(NULL, "\n", &tok_ptr)) {
 
 		struct model_config model = {0};
-		int discard_model = 0;
 
 		/*
 		 * Both keyid (%3) and ec_image (%4) are optional so we want to
@@ -492,63 +364,42 @@ static int manifest_from_signer_config(struct manifest *manifest)
 		if (sscanf(s, "%m[^,],%m[^,],%*[^,],%m[^,]",
 		    &model.name, &model.image, &model.ec_image) < 2) {
 			ERROR("Invalid entry(%s): %s\n", PATH_SIGNER_CONFIG, s);
-			discard_model = 1;
-		} else if (strchr(model.name, '-')) {
-			/* format: BaseModel-CustomLabel */
+			free(model.name);
+			free(model.image);
+			free(model.ec_image);
+			continue;
+		}
+
+		if (strchr(model.name, '-')) {
+			/* format: BaseModelName-CustomLabelTag */
+			struct model_config *base_model;
 			char *tok_dash;
-			char *base_model;
-			struct model_config *base_model_config;
+			char *base_name = strdup(model.name);
 
 			VB2_DEBUG("Found custom-label: %s\n", model.name);
-			discard_model = 1;
-			base_model = strtok_r(model.name, "-", &tok_dash);
-			assert(base_model);
+			base_name = strtok_r(base_name, "-", &tok_dash);
+			assert(base_name);
 
 			/*
-			 * Currently we assume the base model (e.g., base_model)
+			 * Currently we assume the base model (e.g., base_name)
 			 * is always listed before CL models in the CSV file -
 			 * this is based on how the signerbot and the
 			 * chromeos-config works today (validated on octopus).
 			 */
-			base_model_config = manifest_get_model_config(
-					manifest, base_model);
-
-			if (!base_model_config) {
-				ERROR("Invalid CL-model: %s\n", base_model);
-			} else if (!base_model_config->is_custom_label) {
-				base_model_config->is_custom_label = 1;
-				/*
-				 * Rewriting signature_id is not necessary,
-				 * but in order to generate the same manifest
-				 * from setvars, we want to temporarily use
-				 * the special value.
-				 */
-				free(base_model_config->signature_id);
-				base_model_config->signature_id = strdup(
-						"sig-id-in-customization-id");
-				/*
-				 * Historically (e.g., setvars.sh), custom label
-				 * devices will have signature ID set to
-				 * 'sig-id-in-*' so the patch files will be
-				 * discovered later from VPD. We want to
-				 * follow that behavior until fully migrated.
-				 */
-				clear_patch_config(
-						&base_model_config->patches);
+			base_model = manifest_get_model_config(manifest, base_name);
+
+			if (!base_model) {
+				ERROR("Invalid base model for custom label: %s\n", base_name);
+			} else if (!base_model->has_custom_label) {
+				base_model->has_custom_label = true;
 			}
-		}
 
-		if (discard_model) {
-			free(model.name);
-			free(model.image);
-			free(model.ec_image);
-			continue;
+			free(base_name);
 		}
 
 		/* Find patch files. */
-		find_patches_for_model(&model, archive, model.name);
+		find_patches_for_model(&model, archive);
 
-		model.signature_id = strdup(model.name);
 		if (!manifest_add_model(manifest, &model))
 			break;
 	}
@@ -597,8 +448,6 @@ static int manifest_from_simple_folder(struct manifest *manifest)
 	}
 	if (!model.name)
 		model.name = strdup(DEFAULT_MODEL_NAME);
-	if (manifest->has_keyset)
-		model.is_custom_label = 1;
 	manifest_add_model(manifest, &model);
 	manifest->default_model = manifest->num - 1;
 
@@ -722,119 +571,86 @@ cleanup:
 }
 
 /*
- * Determines the signature ID to use for custom label.
- * Returns the signature ID for looking up rootkey and vblock files.
+ * Determines the custom label tag.
+ * Returns the tag string, or NULL if not found.
  * Caller must free the returned string.
  */
-static char *resolve_signature_id(struct model_config *model, const char *image)
+static char *get_custom_label_tag(const char *image_file)
 {
-	int is_unibuild = model->signature_id ? 1 : 0;
-	char *tag = vpd_get_value(image, VPD_CUSTOM_LABEL_TAG);
-	char *sig_id = NULL;
-
-	if (tag == NULL)
-		tag = vpd_get_value(image, VPD_CUSTOM_LABEL_TAG_LEGACY);
+	/* TODO(hungte) Switch to look at /sys/firmware/vpd/ro/$KEY. */
+	char *tag;
 
-	/*
-	 * All active non-unibuild devices have now migrated to run unibuild
-	 * software, so we have to check customization_id first for those
-	 * devices (in particular, 'haha').
-	 */
-	/* The tag should be the LOEM part of the customization_id. */
-	if (!tag) {
-		char *cid = vpd_get_value(image, VPD_CUSTOMIZATION_ID);
-		if (cid) {
-			/* customization_id in format LOEM[-VARIANT]. */
-			char *dash = strchr(cid, '-');
-			if (dash)
-				*dash = '\0';
-			tag = cid;
-			WARN("From %s: tag=%s\n", VPD_CUSTOMIZATION_ID, tag);
-		}
-	}
+	tag = vpd_get_value(image_file, VPD_CUSTOM_LABEL_TAG);
+	if (tag)
+		return tag;
 
-	/* Unified build: $model.$tag, or $model (b/126800200). */
-	if (is_unibuild) {
-		if (!tag) {
-			WARN("No VPD '%s' set for custom label. "
-			     "Use model name '%s' as default.\n",
-			     VPD_CUSTOM_LABEL_TAG, model->name);
-			return strdup(model->name);
-		}
+	tag = vpd_get_value(image_file, VPD_CUSTOM_LABEL_TAG_LEGACY);
+	if (tag)
+		return tag;
 
-		ASPRINTF(&sig_id, "%s-%s", model->name, tag);
-		free(tag);
-		return sig_id;
-	}
+	tag = vpd_get_value(image_file, VPD_CUSTOMIZATION_ID);
+	/* VPD_CUSTOMIZATION_ID is complicated and can't be returned directly. */
+	if (!tag)
+		return NULL;
 
-	/* Non-unibuilds are always upper cased. */
-	if (tag)
-		str_convert(tag, toupper);
+	/* For VPD_CUSTOMIZATION_ID=LOEM[-VARIANT], we need only capitalized LOEM. */
+	INFO("Using deprecated custom label tag: %s=%s\n", VPD_CUSTOMIZATION_ID, tag);
+	char *dash = strchr(tag, '-');
+	if (dash)
+		*dash = '\0';
+	str_convert(tag, toupper);
+	VB2_DEBUG("Applied tag from %s: %s\n", tag, VPD_CUSTOMIZATION_ID);
 	return tag;
 }
 
-/*
- * Applies custom label information to an existing model configuration.
- * Collects signature ID information from either parameter signature_id or
- * image file (via VPD) and updates model.patches for key files.
- * Returns 0 on success, otherwise failure.
- */
-int model_apply_custom_label(
-		struct model_config *model,
-		struct u_archive *archive,
-		const char *signature_id,
-		const char *image)
+const struct model_config *manifest_find_custom_label_model(
+		struct updater_config *cfg,
+		const struct manifest *manifest,
+		const struct model_config *base_model)
 {
-	char *sig_id = NULL;
-	int r = 0;
+	const struct model_config *model;
 
-	if (!signature_id) {
-		sig_id = resolve_signature_id(model, image);
-		signature_id = sig_id;
+	/*
+	 * Some custom label devices shipped with wrong key and must change
+	 * their model names to match the right data.
+	 */
+	if (get_config_quirk(QUIRK_OVERRIDE_CUSTOM_LABEL, cfg)) {
+		model = quirk_override_custom_label(cfg, manifest, base_model);
+		if (model)
+			return model;
 	}
 
-	if (signature_id) {
-		VB2_DEBUG("Find custom label patches by signature ID: '%s'.\n",
-		      signature_id);
-		find_patches_for_model(model, archive, signature_id);
-	} else {
-		signature_id = "";
-		WARN("No VPD '%s' set for custom label - use default keys.\n",
-		     VPD_CUSTOM_LABEL_TAG);
+	assert(cfg->image_current.data);
+	const char *tmp_image = get_firmware_image_temp_file(
+			&cfg->image_current, &cfg->tempfiles);
+	if (!tmp_image) {
+		ERROR("Failed to save the system firmware to a file.\n");
+		return NULL;
 	}
-	if (!model->patches.rootkey) {
-		ERROR("No keys found for signature_id: '%s'\n", signature_id);
-		r = 1;
-	} else {
-		INFO("Applied for custom label: %s\n", signature_id);
+
+	char *tag = get_custom_label_tag(tmp_image);
+	if (!tag) {
+		WARN("No custom label tag (VPD '%s'). "
+		     "Use default keys from the base model '%s'.\n",
+		     VPD_CUSTOM_LABEL_TAG, base_model->name);
+		return base_model;
 	}
-	free(sig_id);
-	return r;
-}
 
-/*
- * b/251040363: Checks if the archive must be parsed using setvars.sh.
- */
-static bool manifest_must_enforce_setvars(struct manifest *manifest)
-{
-	int i;
-	const char *setvars_list[] = {
-		"setvars_sh_only",
-	};
+	VB2_DEBUG("Found custom label tag: %s (base=%s)\n", tag, base_model->name);
+	char *name;
+	ASPRINTF(&name, "%s-%s", base_model->name, tag);
+	free(tag);
 
-	for (i = 0; i < ARRAY_SIZE(setvars_list); i++) {
-		if (archive_has_entry(manifest->archive, setvars_list[i])) {
-			INFO("Detected %s, will use *%s.\n",
-			     setvars_list[i], PATH_ENDSWITH_SETVARS);
-			return true;
-		}
-	}
-	return false;
-}
+	INFO("Find custom label model info using '%s'...\n", name);
+	model = manifest_find_model(cfg, manifest, name);
 
-static int manifest_from_setvars_sh(struct manifest *manifest) {
-	VB2_DEBUG("Try to build the manifest from *%s\n", PATH_ENDSWITH_SETVARS);
-	return archive_walk(manifest->archive, manifest, manifest_scan_entries);
+	if (model) {
+		INFO("Applied custom label model: %s\n", name);
+	} else {
+		ERROR("Invalid custom label model: %s\n", name);
+	}
+	free(name);
+	return model;
 }
 
 static int manifest_from_build_artifacts(struct manifest *manifest) {
@@ -850,26 +666,16 @@ struct manifest *new_manifest_from_archive(struct u_archive *archive)
 {
 	int i;
 	struct manifest manifest = {0}, *new_manifest;
-	bool try_builders = true;
 	int (*manifest_builders[])(struct manifest *) = {
 		manifest_from_signer_config,
-		manifest_from_setvars_sh,
 		manifest_from_build_artifacts,
 		manifest_from_simple_folder,
 	};
 
 	manifest.archive = archive;
 	manifest.default_model = -1;
-	if (archive_has_entry(archive, PATH_KEYSET_FOLDER))
-		manifest.has_keyset = 1;
-	VB2_DEBUG("Has keyset: %s\n", manifest.has_keyset ? "True" : "False");
-
-	if (manifest_must_enforce_setvars(&manifest)) {
-		try_builders = false;
-		manifest_from_setvars_sh(&manifest);
-	}
 
-	for (i = 0; try_builders && i < ARRAY_SIZE(manifest_builders); i++) {
+	for (i = 0; !manifest.num && i < ARRAY_SIZE(manifest_builders); i++) {
 		/*
 		 * For archives manually updated (for testing), it is possible a
 		 * builder can successfully scan the archive but no valid models
@@ -877,8 +683,6 @@ struct manifest *new_manifest_from_archive(struct u_archive *archive)
 		 * Only stop when manifest.num is non-zero.
 		 */
 		(void) manifest_builders[i](&manifest);
-		if (manifest.num)
-			try_builders = false;
 	}
 
 	VB2_DEBUG("%d model(s) loaded.\n", manifest.num);
@@ -904,7 +708,6 @@ void delete_manifest(struct manifest *manifest)
 	for (i = 0; i < manifest->num; i++) {
 		struct model_config *model = &manifest->models[i];
 		free(model->name);
-		free(model->signature_id);
 		free(model->image);
 		free(model->ec_image);
 		clear_patch_config(&model->patches);
@@ -1010,9 +813,6 @@ void print_json_manifest(const struct manifest *manifest)
 				printf(", \"gscvd\": \"%s\"", p->gscvd);
 			printf(" }");
 		}
-		if (m->signature_id)
-			printf(",\n%*s\"signature_id\": \"%s\"", indent, "",
-			       m->signature_id);
 		printf("\n  }");
 		indent -= 2;
 		assert(indent == 2);
diff --git a/futility/updater_quirks.c b/futility/updater_quirks.c
index 24a4aa60..c31361dd 100644
--- a/futility/updater_quirks.c
+++ b/futility/updater_quirks.c
@@ -40,11 +40,9 @@ static const struct quirks_record quirks_records[] = {
 	{ .match = "Google_Trogdor.", .quirks = "min_platform_version=2" },
 
         /* Legacy custom label units. */
-	/* reference design: oak */
-	{ .match = "Google_Hana.", .quirks = "allow_empty_custom_label_tag" },
 
 	/* reference design: octopus */
-	{ .match = "Google_Phaser.", .quirks = "override_signature_id" },
+	{ .match = "Google_Phaser.", .quirks = "override_custom_label" },
 };
 
 /*
@@ -422,9 +420,6 @@ static int quirk_no_verify(struct updater_config *cfg)
 	return 0;
 }
 
-/*
- * Registers known quirks to a updater_config object.
- */
 void updater_register_quirks(struct updater_config *cfg)
 {
 	struct quirk_entry *quirks;
@@ -458,20 +453,14 @@ void updater_register_quirks(struct updater_config *cfg)
 		       "dedicated FMAP section.";
 	quirks->apply = quirk_eve_smm_store;
 
-	quirks = &cfg->quirks[QUIRK_ALLOW_EMPTY_CUSTOM_LABEL_TAG];
-	quirks->name = "allow_empty_custom_label_tag";
-	quirks->help = "chromium/906962; allow devices without custom label "
-		       "tags set to use default keys.";
-	quirks->apply = NULL;  /* Simple config. */
-
 	quirks = &cfg->quirks[QUIRK_EC_PARTIAL_RECOVERY];
 	quirks->name = "ec_partial_recovery";
 	quirks->help = "chromium/1024401; recover EC by partial RO update.";
 	quirks->apply = quirk_ec_partial_recovery;
 
-	quirks = &cfg->quirks[QUIRK_OVERRIDE_SIGNATURE_ID];
-	quirks->name = "override_signature_id";
-	quirks->help = "chromium/146876241; override signature id for "
+	quirks = &cfg->quirks[QUIRK_OVERRIDE_CUSTOM_LABEL];
+	quirks->name = "override_custom_label";
+	quirks->help = "b/146876241; override custom label name for "
 			"devices shipped with different root key.";
 	quirks->apply = NULL; /* Simple config. */
 
@@ -502,10 +491,6 @@ void updater_register_quirks(struct updater_config *cfg)
 	quirks->apply = quirk_clear_mrc_data;
 }
 
-/*
- * Gets the default quirk config string from target image name.
- * Returns a string (in same format as --quirks) to load or NULL if no quirks.
- */
 const char * const updater_get_model_quirks(struct updater_config *cfg)
 {
 	const char *pattern = cfg->image.ro_version;
@@ -526,10 +511,6 @@ const char * const updater_get_model_quirks(struct updater_config *cfg)
 	return NULL;
 }
 
-/*
- * Gets the quirk config string from target image CBFS.
- * Returns a string (in same format as --quirks) to load or NULL if no quirks.
- */
 char *updater_get_cbfs_quirks(struct updater_config *cfg)
 {
 	const char *entry_name = "updater_quirks";
@@ -575,29 +556,38 @@ char *updater_get_cbfs_quirks(struct updater_config *cfg)
 	return (char *)data;
 }
 
-/*
- * Overrides signature id if the device was shipped with known
- * special rootkey.
- */
-int quirk_override_signature_id(struct updater_config *cfg,
-				struct model_config *model,
-				const char **signature_id)
+const struct model_config *quirk_override_custom_label(
+		struct updater_config *cfg,
+		const struct manifest *manifest,
+		const struct model_config *model)
 {
-	const char * const DOPEFISH_KEY_HASH =
-				"9a1f2cc319e2f2e61237dc51125e35ddd4d20984";
+	/* If not write protected, no need to apply the hack. */
+	if (!is_ap_write_protection_enabled(cfg)) {
+		VB2_DEBUG("Skipped because AP not write protected.\n");
+		return NULL;
+	}
+
+	const struct firmware_image *image = &cfg->image_current;
+	assert(image && image->data);
 
-	/* b/146876241 */
-	assert(model);
 	if (strcmp(model->name, "phaser360") == 0) {
-		struct firmware_image *image = &cfg->image_current;
+		/* b/146876241 */
 		const char *key_hash = get_firmware_rootkey_hash(image);
+		const char * const DOPEFISH_KEY_HASH =
+				"9a1f2cc319e2f2e61237dc51125e35ddd4d20984";
+
 		if (key_hash && strcmp(key_hash, DOPEFISH_KEY_HASH) == 0) {
-			const char * const sig_dopefish = "phaser360-dopefish";
+			const char * const dopefish = "phaser360-dopefish";
 			WARN("A Phaser360 with Dopefish rootkey - "
-			     "override signature_id to '%s'.\n", sig_dopefish);
-			*signature_id = sig_dopefish;
+			     "override custom label to '%s'.\n", dopefish);
+			model = manifest_find_model(cfg, manifest, dopefish);
+			if (model)
+				INFO("Model changed to '%s'.\n", model->name);
+			else
+				ERROR("No model defined for '%s'.\n", dopefish);
+
+			return model;
 		}
 	}
-
-	return 0;
+	return NULL;
 }
diff --git a/futility/updater_utils.c b/futility/updater_utils.c
index 02a30125..493d195e 100644
--- a/futility/updater_utils.c
+++ b/futility/updater_utils.c
@@ -7,6 +7,7 @@
 
 #include <assert.h>
 #include <limits.h>
+#include <stdbool.h>
 #include <sys/stat.h>
 #include <sys/types.h>
 #include <string.h>
@@ -23,11 +24,6 @@
 
 #define COMMAND_BUFFER_SIZE 256
 
-/*
- * Strips a string (usually from shell execution output) by removing all the
- * trailing characters in pattern. If pattern is NULL, match by space type
- * characters (space, new line, tab, ... etc).
- */
 void strip_string(char *s, const char *pattern)
 {
 	int len;
@@ -46,10 +42,6 @@ void strip_string(char *s, const char *pattern)
 	}
 }
 
-/*
- * Saves everything from stdin to given output file.
- * Returns 0 on success, otherwise failure.
- */
 int save_file_from_stdin(const char *output)
 {
 	FILE *in = stdin, *out = fopen(output, "wb");
@@ -111,6 +103,16 @@ static int load_firmware_version(struct firmware_image *image,
 	return 0;
 }
 
+static bool has_printable_ecrw_version(const struct firmware_image *image)
+{
+	/*
+	 * Wilco family (sarien & drallion) has binary ecrw version which may
+	 * contain non-printable characters. Those images can be identified by
+	 * checking if the DIAG_NVRAM FMAP section exists or not.
+	 */
+	return !firmware_section_exists(image, FMAP_RW_DIAG_NVRAM);
+}
+
 /*
  * Loads the version of "ecrw" CBFS file within `section_name` of `image_file`.
  * Returns the version string on success; otherwise an empty string.
@@ -126,6 +128,9 @@ static char *load_ecrw_version(const struct firmware_image *image,
 	if (!firmware_section_exists(image, section_name))
 		goto done;
 
+	if (!has_printable_ecrw_version(image))
+		goto done;
+
 	const char *ecrw_version_file = create_temp_file(&tempfile_head);
 	if (!ecrw_version_file)
 		goto done;
@@ -256,11 +261,6 @@ void check_firmware_versions(const struct firmware_image *image)
 		     FMAP_RW_FW_MAIN_B, image->ecrw_version_b);
 }
 
-/*
- * Generates a temporary file for snapshot of firmware image contents.
- *
- * Returns a file path if success, otherwise NULL.
- */
 const char *get_firmware_image_temp_file(const struct firmware_image *image,
 					 struct tempfile *tempfiles)
 {
@@ -277,9 +277,6 @@ const char *get_firmware_image_temp_file(const struct firmware_image *image,
 	return tmp_path;
 }
 
-/*
- * Frees the allocated resource from a firmware image object.
- */
 void free_firmware_image(struct firmware_image *image)
 {
 	/*
@@ -305,11 +302,6 @@ int reload_firmware_image(const char *file_path, struct firmware_image *image)
 	return load_firmware_image(image, file_path, NULL);
 }
 
-/*
- * Finds a firmware section by given name in the firmware image.
- * If successful, return zero and *section argument contains the address and
- * size of the section; otherwise failure.
- */
 int find_firmware_section(struct firmware_section *section,
 			  const struct firmware_image *image,
 			  const char *section_name)
@@ -329,9 +321,6 @@ int find_firmware_section(struct firmware_section *section,
 	return 0;
 }
 
-/*
- * Returns true if the given FMAP section exists in the firmware image.
- */
 int firmware_section_exists(const struct firmware_image *image,
 			    const char *section_name)
 {
@@ -340,14 +329,6 @@ int firmware_section_exists(const struct firmware_image *image,
 	return section.data != NULL;
 }
 
-/*
- * Preserves (copies) the given section (by name) from image_from to image_to.
- * The offset may be different, and the section data will be directly copied.
- * If the section does not exist on either images, return as failure.
- * If the source section is larger, contents on destination be truncated.
- * If the source section is smaller, the remaining area is not modified.
- * Returns 0 if success, non-zero if error.
- */
 int preserve_firmware_section(const struct firmware_image *image_from,
 			      struct firmware_image *image_to,
 			      const char *section_name)
@@ -370,10 +351,6 @@ int preserve_firmware_section(const struct firmware_image *image_from,
 	return 0;
 }
 
-/*
- * Finds the GBB (Google Binary Block) header on a given firmware image.
- * Returns a pointer to valid GBB header, or NULL on not found.
- */
 const struct vb2_gbb_header *find_gbb(const struct firmware_image *image)
 {
 	struct firmware_section section;
@@ -404,27 +381,16 @@ static bool is_write_protection_enabled(struct updater_config *cfg,
 	return wp_enabled;
 }
 
-/*
- * Returns true if the AP write protection is enabled on current system.
- */
 inline bool is_ap_write_protection_enabled(struct updater_config *cfg)
 {
 	return is_write_protection_enabled(cfg, cfg->image.programmer, DUT_PROP_WP_SW_AP);
 }
 
-/*
- * Returns true if the EC write protection is enabled on current system.
- */
 inline bool is_ec_write_protection_enabled(struct updater_config *cfg)
 {
 	return is_write_protection_enabled(cfg, cfg->ec_image.programmer, DUT_PROP_WP_SW_EC);
 }
 
-/*
- * Executes a command on current host and returns stripped command output.
- * If the command has failed (exit code is not zero), returns an empty string.
- * The caller is responsible for releasing the returned string.
- */
 char *host_shell(const char *command)
 {
 	/* Currently all commands we use do not have large output. */
@@ -466,10 +432,6 @@ void prepare_servo_control(const char *control_name, bool on)
 	free(cmd);
 }
 
-/*
- * Helper function to detect type of Servo board attached to host.
- * Returns a string as programmer parameter on success, otherwise NULL.
- */
 char *host_detect_servo(const char **prepare_ctrl_name)
 {
 	const char *servo_port = getenv(ENV_SERVOD_PORT);
@@ -562,6 +524,7 @@ char *host_detect_servo(const char **prepare_ctrl_name)
 
 	return ret;
 }
+
 /*
  * Returns 1 if the programmers in image1 and image2 are the same.
  */
@@ -598,17 +561,21 @@ int load_system_firmware(struct updater_config *cfg,
 		INFO("Reading SPI Flash..\n");
 		r = flashrom_read_image(image, NULL, 0, verbose);
 	}
-	if (!r)
+	if (r) {
+		/* Read failure, the content cannot be trusted. */
+		free_firmware_image(image);
+	} else {
+		/*
+		 * Parse the contents. Note the image->data will remain even
+		 * if parsing failed - this is important for system firmware
+		 * because we may be trying to recover a device with corrupted
+		 * firmware.
+		 */
 		r = parse_firmware_image(image);
+	}
 	return r;
 }
 
-/*
- * Writes sections from a given firmware image to the system firmware.
- * Regions should be NULL for writing the whole image, or a list of
- * FMAP section names (and ended with a NULL).
- * Returns 0 if success, non-zero if error.
- */
 int write_system_firmware(struct updater_config *cfg,
 			  const struct firmware_image *image,
 			  const char * const regions[],
@@ -645,15 +612,11 @@ int write_system_firmware(struct updater_config *cfg,
 	return r;
 }
 
-/*
- * Helper function to create a new temporary file.
- * All files created will be removed remove_all_temp_files().
- * Returns the path of new file, or NULL on failure.
- */
 const char *create_temp_file(struct tempfile *head)
 {
 	struct tempfile *new_temp;
-	char new_path[] = P_tmpdir "/fwupdater.XXXXXX";
+	char new_path[] = VBOOT_TMP_DIR "/fwupdater.XXXXXX";
+
 	int fd;
 	mode_t umask_save;
 
@@ -683,10 +646,6 @@ const char *create_temp_file(struct tempfile *head)
 	return new_temp->filepath;
 }
 
-/*
- * Helper function to remove all files created by create_temp_file().
- * This is intended to be called only once at end of program execution.
- */
 void remove_all_temp_files(struct tempfile *head)
 {
 	/* head itself is dummy and should not be removed. */
@@ -704,9 +663,6 @@ void remove_all_temp_files(struct tempfile *head)
 	}
 }
 
-/*
- * Returns rootkey hash of firmware image, or NULL on failure.
- */
 const char *get_firmware_rootkey_hash(const struct firmware_image *image)
 {
 	const struct vb2_gbb_header *gbb = NULL;
@@ -729,11 +685,6 @@ const char *get_firmware_rootkey_hash(const struct firmware_image *image)
 	return packed_key_sha1_string(rootkey);
 }
 
-/*
- * Overwrite the given offset of a section in the firmware image with the
- * given values.
- * Returns 0 on success, otherwise failure.
- */
 int overwrite_section(struct firmware_image *image,
 			     const char *fmap_section, size_t offset,
 			     size_t size, const uint8_t *new_values)
diff --git a/host/lib/crossystem.c b/host/lib/crossystem.c
index 740834af..7a19c779 100644
--- a/host/lib/crossystem.c
+++ b/host/lib/crossystem.c
@@ -25,7 +25,7 @@
 #include "vboot_struct.h"
 
 /* Filename for crossystem lock */
-#define CROSSYSTEM_LOCK_PATH "/run/lock/crossystem.lock"
+#define CROSSYSTEM_LOCK_PATH (CROSSYSTEM_LOCK_DIR "/crossystem.lock")
 
 /* Filename for kernel command line */
 #define KERNEL_CMDLINE_PATH "/proc/cmdline"
@@ -119,6 +119,21 @@ static int ReleaseCrossystemLock(int lock_fd)
 	return 0;
 }
 
+/* Check if system FW type is equivalent to a given name */
+static bool CheckFwType(const char *name)
+{
+	char fwtype_buf[VB_MAX_STRING_PROPERTY];
+	int fwtype_ret;
+
+	fwtype_ret = VbGetSystemPropertyString("mainfw_type",
+		fwtype_buf, sizeof(fwtype_buf));
+
+	if (fwtype_ret == 0 && !strcasecmp(fwtype_buf, name))
+		return true;
+
+	return false;
+}
+
 static struct vb2_context *get_fake_context(void)
 {
 	static uint8_t fake_workbuf[sizeof(struct vb2_shared_data) + 16]
@@ -444,7 +459,7 @@ int VbGetSystemPropertyInt(const char *name)
 	} else if (!strcasecmp(name,"disable_dev_request")) {
 		value = vb2_get_nv_storage(VB2_NV_DISABLE_DEV_REQUEST);
 	} else if (!strcasecmp(name,"clear_tpm_owner_request")) {
-		if (EXTERNAL_TPM_CLEAR_REQUEST) {
+		if (EXTERNAL_TPM_CLEAR_REQUEST && CheckFwType("nonchrome")) {
 			const char *const argv[] = {
 				TPM_CLEAR_REQUEST_EXEC_NAME,
 				NULL,
@@ -666,7 +681,7 @@ static int VbSetSystemPropertyIntInternal(const char *name, int value)
 	} else if (!strcasecmp(name,"disable_dev_request")) {
 		return vb2_set_nv_storage(VB2_NV_DISABLE_DEV_REQUEST, value);
 	} else if (!strcasecmp(name,"clear_tpm_owner_request")) {
-		if (EXTERNAL_TPM_CLEAR_REQUEST) {
+		if (EXTERNAL_TPM_CLEAR_REQUEST && CheckFwType("nonchrome")) {
 			const char *const argv[] = {
 				TPM_CLEAR_REQUEST_EXEC_NAME,
 				value ? "1" : "0",
diff --git a/host/lib/flashrom.c b/host/lib/flashrom.c
index 8f0d4f91..d3b44f46 100644
--- a/host/lib/flashrom.c
+++ b/host/lib/flashrom.c
@@ -23,7 +23,7 @@
 #include "flashrom.h"
 #include "subprocess.h"
 
-#define FLASHROM_EXEC_NAME "/usr/sbin/flashrom"
+#define FLASHROM_EXEC_NAME "flashrom"
 
 /**
  * Helper to create a temporary file, and optionally write some data
@@ -47,12 +47,9 @@ static vb2_error_t write_temp_file(const uint8_t *data, uint32_t data_size,
 	char *path;
 	mode_t umask_save;
 
-#if defined(__FreeBSD__)
-#define P_tmpdir "/tmp"
-#endif
-
 	*path_out = NULL;
-	path = strdup(P_tmpdir "/vb2_flashrom.XXXXXX");
+
+	path = strdup(VBOOT_TMP_DIR "/vb2_flashrom.XXXXXX");
 
 	/* Set the umask before mkstemp for security considerations. */
 	umask_save = umask(077);
diff --git a/rust/OWNERS b/rust/OWNERS
index fe3921f7..268d92ef 100644
--- a/rust/OWNERS
+++ b/rust/OWNERS
@@ -1 +1,3 @@
-allenwebb@chromium.org
+allenwebb@google.com
+
+include chromiumos/platform2:/libchromeos-rs/OWNERS
diff --git a/scripts/image_signing/make_dev_ssd.sh b/scripts/image_signing/make_dev_ssd.sh
index 49d4215b..5c453d03 100755
--- a/scripts/image_signing/make_dev_ssd.sh
+++ b/scripts/image_signing/make_dev_ssd.sh
@@ -99,7 +99,10 @@ remove_rootfs_verification() {
     rw_root_opt="s| rw | ro |"
   fi
 
-  local ptracer_opt="proc_mem.restrict_write=ptracer proc_mem.restrict_foll_force=ptracer"
+  local ptracer_opt="proc_mem.restrict_write=ptracer proc_mem.force_override=ptrace"
+  # This is kept for compatibility with ChromeOS kernels until all of them
+  # are up-to-date with the corresponding stable branch.
+  ptracer_opt="${ptracer_opt} proc_mem.restrict_foll_force=ptracer"
   if [ "${FLAGS_enable_proc_mem_ptrace}" = "${FLAGS_FALSE}" ]; then
     # we could set proc_mem.restrict_write=all, however that's already default
     # via Kconfig and we don't want to clutter the cmdline with redundant params
@@ -203,6 +206,14 @@ resign_ssd_kernel() {
   local ssd_device="$1"
   local bs="$(blocksize "${ssd_device}")"
 
+  # `fflash` and `cros flash` write their updates to block device partitions,
+  # while this script uses the parent block device plus a block offset.
+  # Sync and flush the page cache to avoid cache aliasing issues.
+  sync; sync; sync
+  if [ -w /proc/sys/vm/drop_caches ]; then
+    echo 1 > /proc/sys/vm/drop_caches
+  fi
+
   # reasonable size for current kernel partition
   local min_kernel_size=$((8000 * 1024 / bs))
   local resigned_kernels=0
@@ -385,10 +396,13 @@ resign_ssd_kernel() {
       fi
     fi
 
-    # Sometimes doing "dump_kernel_config" or other I/O now (or after return to
-    # shell) will get the data before modification. Not a problem now, but for
-    # safety, let's try to sync more.
+    # `fflash` and `cros flash` write their updates to block device partitions,
+    # while this script uses the parent block device plus a block offset.
+    # Sync and flush the page cache to avoid cache aliasing issues.
     sync; sync; sync
+    if [ -w /proc/sys/vm/drop_caches ]; then
+      echo 1 > /proc/sys/vm/drop_caches
+    fi
 
     info "${name}: Re-signed with developer keys successfully."
   done
diff --git a/scripts/image_signing/sign_android_image.sh b/scripts/image_signing/sign_android_image.sh
index 1d2d9dea..48793765 100755
--- a/scripts/image_signing/sign_android_image.sh
+++ b/scripts/image_signing/sign_android_image.sh
@@ -417,6 +417,57 @@ list_files_in_squashfs_image() {
   "${unsquashfs}" -l "${system_img}" | grep ^squashfs-root
 }
 
+# This function is needed to set the VB meta digest parameter for
+# Verified Boot. The value is calculated by calculating the hash
+# of hashes of the system and vendor images. It will be written
+# to a file in the same directory as the system image and will be
+# read by ARC Keymint. See ​​go/arc-vboot-param-design for more details.
+write_arcvm_vbmeta_digest() {
+  local android_dir=$1
+  local system_img_path=$2
+  local vendor_img_path=$3
+
+  local vbmeta_digest_path="${android_dir}/arcvm_vbmeta_digest.sha256"
+
+  # Calculate hashes of the system and vendor images.
+  local system_img_hash vendor_img_hash combined_hash vbmeta_digest
+  if ! system_img_hash=$(sha256sum -b "${system_img_path}"); then
+    warn "Error calculating system image hash"
+    return 1
+  fi
+  if ! vendor_img_hash=$(sha256sum -b "${vendor_img_path}"); then
+    warn "Error calculating vendor image hash"
+    return 1
+  fi
+
+  # Cut off the end of sha256sum output since it includes the file name.
+  system_img_hash="$(echo -n "${system_img_hash}" | awk '{print $1}')"
+  vendor_img_hash="$(echo -n "${vendor_img_hash}" | awk '{print $1}')"
+
+  # Combine the two hashes and calculate the hash of that value.
+  combined_hash=$(printf "%s%s" "${system_img_hash}" "${vendor_img_hash}")
+  if ! vbmeta_digest=$(echo -n "${combined_hash}" | sha256sum -b); then
+    warn "Error calculating the hash of the combined hash of the images"
+    return 1
+  fi
+
+  vbmeta_digest="$(echo -n "${vbmeta_digest}" | awk '{print $1}')"
+
+  # If there is an existing digest, compare the two values.
+  if [[ -f "${vbmeta_digest_path}" ]]; then
+    local prev_vbmeta_digest
+    prev_vbmeta_digest=$(cat "${vbmeta_digest_path}")
+    if [[ "${vbmeta_digest}" == "${prev_vbmeta_digest}" ]]; then
+      warn "Error: existing and re-calculated digests are the same"
+      return 1
+    fi
+  fi
+
+  info "Writing re-calculated VB meta digest to arcvm_vbmeta_digest.sha256"
+  echo -n "${vbmeta_digest}" > "${vbmeta_digest_path}"
+  return 0
+}
+
 sign_android_internal() {
   local root_fs_dir=$1
   local key_dir=$2
@@ -691,6 +742,15 @@ sign_android_internal() {
   new_size=$(stat -c '%s' "${system_img}")
   info "Android system image size change: ${old_size} -> ${new_size}"
 
+  # Calculate the hash of the system and vendor images and store the value
+  # in a file. The digest was initially calculated and written when the
+  # image was built. This recalculates the digest of the signed image and
+  # replaces the original value.
+  # Any changes to the images must occur before this method.
+  if ! write_arcvm_vbmeta_digest "${android_dir}" "${system_img}" "${vendor_img}"; then
+    warn "ARCVM vbmeta digest was not overwritten"
+  fi
+
   if d=$(grep -v -F -x -f "${working_dir}"/image_file_list.{new,orig}); then
     # If we have a line in image_file_list.orig which does not appear in
     # image_file_list.new, it means some files are removed during signing
diff --git a/scripts/image_signing/sign_official_build.sh b/scripts/image_signing/sign_official_build.sh
index c9251fb4..1616d68e 100755
--- a/scripts/image_signing/sign_official_build.sh
+++ b/scripts/image_signing/sign_official_build.sh
@@ -23,9 +23,10 @@
 set -e
 
 # Our random local constants.
-MINIOS_KERNEL_GUID="09845860-705f-4bb5-b16c-8a8a099caf52"
+MINIOS_KERNEL_GUID="09845860-705F-4BB5-B16C-8A8A099CAF52"
 FIRMWARE_VERSION=1
 KERNEL_VERSION=1
+V1_SUFFIX=".v1"
 
 # Print usage string
 usage() {
@@ -557,7 +558,7 @@ resign_firmware_shellball() {
 
           # loem.ini has the format KEY_ID_VALUE = KEY_INDEX
           if ! match="$(grep -E "^[0-9]+ *= *${key_id}$" "${KEY_DIR}/loem.ini")"; then
-            die "The loem key_id ${key_id} not found in loem.ini!"
+            die "The loem key_id ${key_id} not found in loem.ini! (${KEY_DIR}/loem.ini)"
           fi
 
           # shellcheck disable=SC2001
@@ -1038,53 +1039,24 @@ update_recovery_kernel_hash() {
     --config "${new_kernel_config}"
 }
 
-# Re-sign miniOS kernels with new keys.
-# Args: LOOPDEV MINIOS_A_KEYBLOCK MINIOS_B_KEYBLOCK PRIVKEY
-resign_minios_kernels() {
-  local loopdev="$1"
-  local minios_a_keyblock="$2"
-  local minios_b_keyblock="$3"
-  local priv_key="$4"
-
-  info "Searching for miniOS kernels to resign..."
-
-  local loop_minios
-  for loop_minios in "${loopdev}p"*; do
-    local part_type_guid
-    part_type_guid=$(sudo lsblk -rnb -o PARTTYPE "${loop_minios}")
-    if [[ "${part_type_guid}" != "${MINIOS_KERNEL_GUID}" ]]; then
-      continue
-    fi
-
-    local keyblock
-    if [[ "${loop_minios}" == "${loopdev}p9" ]]; then
-      keyblock="${minios_a_keyblock}"
-    elif [[ "${loop_minios}" == "${loopdev}p10" ]]; then
-      keyblock="${minios_b_keyblock}"
-    else
-      error "Unexpected miniOS partition ${loop_minios}"
-      return 1
-    fi
-
-    # Skip miniOS partitions which are empty. This happens when miniOS
-    # kernels aren't written to the partitions because the feature is not
-    # enabled.
-    if ! sudo_futility dump_kernel_config "${loop_minios}"; then
-      info "Skipping empty miniOS partition ${loop_minios}."
-      continue
-    fi
-
-    # Delay checking that keyblock and private key exist until we are certain
-    # of a valid miniOS partition.  Images that don't support miniOS might not
-    # provide these.  (This check is repeated twice, but that's okay.)
+# Resign a single miniOS kernel partition.
+# Args: LOOP_MINIOS KEYBLOCK PRIVKEY
+resign_minios_kernel() {
+  local loop_minios="$1"
+  local keyblock="$2"
+  local priv_key="$3"
+
+  if sudo_futility dump_kernel_config "${loop_minios}"; then
+    # Delay checking that keyblock exists until we are certain of a valid miniOS
+    # partition. Images that don't support miniOS might not provide these.
+    # (This check is repeated twice, but that's okay.)
+    # Update (9/3/24): we no longer check if the private key exists on disk
+    # because it may live in Cloud KMS instead, opting instead to let futility
+    # below fail if the key is missing.
     if [[ ! -e "${keyblock}" ]]; then
       error "Resign miniOS: keyblock doesn't exist: ${keyblock}"
       return 1
     fi
-    if [[ ! -e "${priv_key}" ]]; then
-      error "Resign miniOS: private key doesn't exist: ${priv_key}"
-      return 1
-    fi
 
     # Assume this is a miniOS kernel.
     local minios_kernel_version=$((KERNEL_VERSION >> 24))
@@ -1093,12 +1065,60 @@ resign_minios_kernels() {
         --signprivate "${priv_key}" \
         --version "${minios_kernel_version}" \
         --oldblob "${loop_minios}"; then
+      echo
       info "Resign miniOS ${loop_minios}: done"
     else
       error "Resign miniOS ${loop_minios}: failed"
       return 1
     fi
-  done
+  else
+    info "Skipping empty miniOS partition ${loop_minios}."
+  fi
+}
+
+# Get the partition type of the loop device.
+get_partition_type() {
+  local loopdev=$1
+  local device=$2
+  # Prefer cgpt, fall back on lsblk.
+  if command -v cgpt &> /dev/null; then
+    echo "$(cgpt show -i "${device}" -t "${loopdev}")"
+  else
+    echo "$(sudo lsblk -rnb -o PARTTYPE "${loopdev}p${device}")"
+  fi
+}
+
+# Re-sign miniOS kernels with new keys.
+# Args: LOOPDEV MINIOS_A_KEYBLOCK MINIOS_B_KEYBLOCK PRIVKEY
+resign_minios_kernels() {
+  local loopdev="$1"
+  local minios_a_keyblock="$2"
+  local minios_b_keyblock="$3"
+  local priv_key="$4"
+
+  info "Searching for miniOS kernels to resign..."
+
+  # Attempt to sign miniOS A and miniOS B partitions, one at a time.
+  # miniOS A - loop device 9.
+  local loop_minios_a="${loopdev}p9"
+  local part_type_a
+  part_type_a="$(get_partition_type "${loopdev}" 9)"
+  # miniOS B - loop device 10.
+  local loop_minios_b="${loopdev}p10"
+  local part_type_b
+  part_type_b="$(get_partition_type "${loopdev}" 10)"
+
+  # Make sure the loop devices have a miniOS partition type.
+  if [[ "${part_type_a^^}" == "${MINIOS_KERNEL_GUID}" ]]; then
+    if ! resign_minios_kernel "${loop_minios_a}" "${minios_a_keyblock}" "${priv_key}"; then
+      return 1
+    fi
+  fi
+  if [[ "${part_type_b^^}" == "${MINIOS_KERNEL_GUID}" ]]; then
+    if ! resign_minios_kernel "${loop_minios_b}" "${minios_b_keyblock}" "${priv_key}"; then
+      return 1
+    fi
+  fi
 }
 
 # Update the legacy bootloader templates in EFI partition if available.
@@ -1465,6 +1485,16 @@ main() {
       --private-key "${KEY_DIR}/key_hps.priv.pem"
   elif [[ "${TYPE}" == "uefi_kernel" ]]; then
       sign_uefi_kernel "${INPUT_IMAGE}" "${OUTPUT_IMAGE}"
+  elif [[ "${TYPE}" == "recovery_kernel" ]]; then
+    cp "${INPUT_IMAGE}" "${OUTPUT_IMAGE}"
+    if [[ -f "${KEYCFG_RECOVERY_KERNEL_V1_KEYBLOCK}" ]]; then
+      local output_image_v1="${OUTPUT_IMAGE}${V1_SUFFIX}"
+      cp "${OUTPUT_IMAGE}" "${output_image_v1}"
+      do_futility sign -b "${KEYCFG_RECOVERY_KERNEL_V1_KEYBLOCK}" -s \
+        "${KEYCFG_RECOVERY_KERNEL_VBPRIVK}" "${output_image_v1}"
+    fi
+    do_futility sign -b "${KEYCFG_RECOVERY_KERNEL_KEYBLOCK}" -s \
+      "${KEYCFG_RECOVERY_KERNEL_VBPRIVK}" "${OUTPUT_IMAGE}"
   else
     die "Invalid type ${TYPE}"
   fi
diff --git a/scripts/image_signing/swap_ec_rw b/scripts/image_signing/swap_ec_rw
index fd570ecc..b57bd81a 100755
--- a/scripts/image_signing/swap_ec_rw
+++ b/scripts/image_signing/swap_ec_rw
@@ -76,8 +76,13 @@ swap_ecrw() {
       -c none -f "${ecrw_version_file}" -n "${CBFS_ECRW_VERSION_NAME}"
   done
 
+  local keyset
+  for keyset in /usr/share/vboot/devkeys "${SCRIPT_BASE}/../../tests/devkeys"; do
+    [[ -d "${keyset}" ]] && break
+  done
+
   # 'futility sign' will call 'cbfstool truncate' if needed
-  futility sign "${ap_file}"
+  futility sign "${ap_file}" --keyset "${keyset}"
 
   ecrw_version=$(futility update --manifest -e "${ec_file}" \
     | jq -r '.default.ec.versions.rw')
diff --git a/tests/futility/data/signer_config.csv b/tests/futility/data/signer_config.csv
index d232073a..b2602fd0 100644
--- a/tests/futility/data/signer_config.csv
+++ b/tests/futility/data/signer_config.csv
@@ -1,5 +1,6 @@
 model_name,firmware_image,key_id,ec_image,brand_code
 customtip,images/bios_coral.bin,DEFAULT,,ZZCR
 customtip-cl,images/bios_coral.bin,CL,,ZZCR
+customtip-bad,images/bios_link.bin,CL,,ZZCR
 link,images/bios_link.bin,LINK,images/ec_link.bin,ZZCR
 peppy,images/bios_peppy.bin,PEPPY,images/ec_peppy.bin,ZZCR
diff --git a/tests/futility/test_load_fmap.sh b/tests/futility/test_load_fmap.sh
index dabd46d4..3ae30c55 100755
--- a/tests/futility/test_load_fmap.sh
+++ b/tests/futility/test_load_fmap.sh
@@ -38,6 +38,18 @@ for a in "${AREAS[@]}"; do
   cmp "$a" "$a.rand"
 done
 
+# File size smaller than area size
+cp -f "${IN}" "${BIOS}"
+"${FUTILITY}" dump_fmap -x "${BIOS}" VBLOCK_A
+cp -f VBLOCK_A VBLOCK_A.truncated
+truncate --size=-5 VBLOCK_A.truncated
+cp -f VBLOCK_A.truncated VBLOCK_A.new
+printf '\xFF%.s' {1..5} >> VBLOCK_A.new
+cmp -s VBLOCK_A.new VBLOCK_A && error "VBLOCK_A.new is the same as VBLOCK_A"
+"${FUTILITY}" load_fmap "${BIOS}" VBLOCK_A:VBLOCK_A.truncated
+"${FUTILITY}" dump_fmap -x "${BIOS}" VBLOCK_A:VBLOCK_A.readback
+cmp VBLOCK_A.readback VBLOCK_A.new
+
 # cleanup
 rm -f "${TMP}"* "${AREAS[@]}" ./*.rand ./*.good
 exit 0
diff --git a/tests/futility/test_main.sh b/tests/futility/test_main.sh
index 3cfee6d6..df2a8aba 100755
--- a/tests/futility/test_main.sh
+++ b/tests/futility/test_main.sh
@@ -16,15 +16,6 @@ cd "$OUTDIR"
 "${FUTILITY}" /fake/path/to/help  > "$TMP"
 grep Usage "$TMP"
 
-# Make sure logging does something.
-LOG="/tmp/futility.log"
-[ -f "${LOG}" ] && mv "${LOG}" "${LOG}.backup"
-touch "${LOG}"
-"${FUTILITY}" help
-grep "${FUTILITY}" "${LOG}"
-rm -f "${LOG}"
-[ -f "${LOG}.backup" ] && mv "${LOG}.backup" "${LOG}"
-
 # Use some known digests to verify that things work...
 DEVKEYS="${SRCDIR}/tests/devkeys"
 SHA=e78ce746a037837155388a1096212ded04fb86eb
diff --git a/tests/futility/test_update.sh b/tests/futility/test_update.sh
index 4337141a..edea233b 100755
--- a/tests/futility/test_update.sh
+++ b/tests/futility/test_update.sh
@@ -40,12 +40,19 @@ RO_VPD_BLOB="${DATA_DIR}/ro_vpd.bin"
 SIGNER_CONFIG="${DATA_DIR}/signer_config.csv"
 
 # Work in scratch directory
-cd "$OUTDIR"
+cd "${OUTDIR}"
 set -o pipefail
 
+# Re-create the temp folders
+TMP_FROM="${TMP}/from"
+TMP_TO="${TMP}/to"
+EXPECTED="${TMP}/expected"
+rm -rf "${TMP}"
+mkdir -p "${TMP_FROM}" "${TMP_TO}" "${EXPECTED}"
+
 # In all the test scenario, we want to test "updating from PEPPY to LINK".
-TO_IMAGE="${TMP}.src.link"
-FROM_IMAGE="${TMP}.src.peppy"
+TO_IMAGE="${TMP}/src.link"
+FROM_IMAGE="${TMP}/src.peppy"
 TO_HWID="X86 LINK TEST 6638"
 FROM_HWID="X86 PEPPY TEST 4211"
 cp -f "${LINK_BIOS}" "${TO_IMAGE}"
@@ -84,10 +91,10 @@ patch_file "${FROM_IMAGE}" RW_FWID_B 0 Google.
 patch_file "${FROM_IMAGE}" RO_FRID 0 Google.
 
 unpack_image() {
-  local folder="${TMP}.$1"
+  local folder="${TMP}/$1"
   local image="$2"
   mkdir -p "${folder}"
-  (cd "${folder}" && "${FUTILITY}" dump_fmap -x "../${image}")
+  (cd "${folder}" && "${FUTILITY}" dump_fmap -x "../../${image}")
   "${FUTILITY}" gbb -g --rootkey="${folder}/rootkey" "${image}"
 }
 
@@ -98,12 +105,18 @@ unpack_image "from" "${FROM_IMAGE}"
 # Hack FROM_IMAGE so it has same root key as TO_IMAGE (for RW update).
 FROM_DIFFERENT_ROOTKEY_IMAGE="${FROM_IMAGE}2"
 cp -f "${FROM_IMAGE}" "${FROM_DIFFERENT_ROOTKEY_IMAGE}"
-"${FUTILITY}" gbb -s --rootkey="${TMP}.to/rootkey" "${FROM_IMAGE}"
+"${FUTILITY}" gbb -s --rootkey="${TMP_TO}/rootkey" "${FROM_IMAGE}"
 
 # Hack for quirks
 cp -f "${FROM_IMAGE}" "${FROM_IMAGE}.large"
 truncate -s $((8388608 * 2)) "${FROM_IMAGE}.large"
 
+# Create the FROM_SAME_RO_IMAGE using the RO from TO_IMAGE."
+FROM_SAME_RO_IMAGE="${FROM_IMAGE}.same_ro"
+cp -f "${FROM_IMAGE}" "${FROM_SAME_RO_IMAGE}"
+"${FUTILITY}" load_fmap "${FROM_SAME_RO_IMAGE}" \
+  "RO_SECTION:${TMP_TO}/RO_SECTION"
+
 # Create GBB v1.2 images (for checking digest)
 GBB_OUTPUT="$("${FUTILITY}" gbb --digest "${TO_IMAGE}")"
 [ "${GBB_OUTPUT}" = "digest: <none>" ]
@@ -124,58 +137,61 @@ cp -f "${FROM_IMAGE}.locked" "${FROM_IMAGE}.unlocked"
 patch_file "${FROM_IMAGE}.unlocked" SI_DESC 0x60 \
   "\x00\xff\xff\xff\x00\xff\xff\xff\x00\xff\xff\xff"
 "${FUTILITY}" load_fmap "${FROM_IMAGE}.locked_same_desc" \
-  "SI_DESC:${TMP}.to/SI_DESC"
+  "SI_DESC:${TMP_TO}/SI_DESC"
 
 # Generate expected results.
-cp -f "${TO_IMAGE}" "${TMP}.expected.full"
-cp -f "${FROM_IMAGE}" "${TMP}.expected.rw"
-cp -f "${FROM_IMAGE}" "${TMP}.expected.a"
-cp -f "${FROM_IMAGE}" "${TMP}.expected.b"
-cp -f "${FROM_IMAGE}" "${TMP}.expected.legacy"
-"${FUTILITY}" gbb -s --hwid="${FROM_HWID}" "${TMP}.expected.full"
-"${FUTILITY}" load_fmap "${TMP}.expected.full" \
-  "RW_VPD:${TMP}.from/RW_VPD" \
-  "RO_VPD:${TMP}.from/RO_VPD"
-"${FUTILITY}" load_fmap "${TMP}.expected.rw" \
-  "RW_SECTION_A:${TMP}.to/RW_SECTION_A" \
-  "RW_SECTION_B:${TMP}.to/RW_SECTION_B" \
-  "RW_SHARED:${TMP}.to/RW_SHARED" \
-  "RW_LEGACY:${TMP}.to/RW_LEGACY"
-"${FUTILITY}" load_fmap "${TMP}.expected.a" \
-  "RW_SECTION_A:${TMP}.to/RW_SECTION_A"
-"${FUTILITY}" load_fmap "${TMP}.expected.b" \
-  "RW_SECTION_B:${TMP}.to/RW_SECTION_B"
-"${FUTILITY}" load_fmap "${TMP}.expected.legacy" \
-  "RW_LEGACY:${TMP}.to/RW_LEGACY"
-cp -f "${TMP}.expected.full" "${TMP}.expected.full.gbb12"
-patch_file "${TMP}.expected.full.gbb12" GBB 6 "\x02"
-"${FUTILITY}" gbb -s --hwid="${FROM_HWID}" "${TMP}.expected.full.gbb12"
-cp -f "${TMP}.expected.full" "${TMP}.expected.full.gbb0"
-"${FUTILITY}" gbb -s --flags=0 "${TMP}.expected.full.gbb0"
+cp -f "${TO_IMAGE}" "${EXPECTED}/full"
+cp -f "${FROM_IMAGE}" "${EXPECTED}/rw"
+cp -f "${FROM_IMAGE}" "${EXPECTED}/a"
+cp -f "${FROM_IMAGE}" "${EXPECTED}/b"
+cp -f "${FROM_SAME_RO_IMAGE}" "${EXPECTED}/FROM_SAME_RO_IMAGE.b"
+cp -f "${FROM_IMAGE}" "${EXPECTED}/legacy"
+"${FUTILITY}" gbb -s --hwid="${FROM_HWID}" "${EXPECTED}/full"
+"${FUTILITY}" load_fmap "${EXPECTED}/full" \
+  "RW_VPD:${TMP_FROM}/RW_VPD" \
+  "RO_VPD:${TMP_FROM}/RO_VPD"
+"${FUTILITY}" load_fmap "${EXPECTED}/rw" \
+  "RW_SECTION_A:${TMP_TO}/RW_SECTION_A" \
+  "RW_SECTION_B:${TMP_TO}/RW_SECTION_B" \
+  "RW_SHARED:${TMP_TO}/RW_SHARED" \
+  "RW_LEGACY:${TMP_TO}/RW_LEGACY"
+"${FUTILITY}" load_fmap "${EXPECTED}/a" \
+  "RW_SECTION_A:${TMP_TO}/RW_SECTION_A"
+"${FUTILITY}" load_fmap "${EXPECTED}/b" \
+  "RW_SECTION_B:${TMP_TO}/RW_SECTION_B"
+"${FUTILITY}" load_fmap "${EXPECTED}/FROM_SAME_RO_IMAGE.b" \
+  "RW_SECTION_B:${TMP_TO}/RW_SECTION_B"
+"${FUTILITY}" load_fmap "${EXPECTED}/legacy" \
+  "RW_LEGACY:${TMP_TO}/RW_LEGACY"
+cp -f "${EXPECTED}/full" "${EXPECTED}/full.gbb12"
+patch_file "${EXPECTED}/full.gbb12" GBB 6 "\x02"
+"${FUTILITY}" gbb -s --hwid="${FROM_HWID}" "${EXPECTED}/full.gbb12"
+cp -f "${EXPECTED}/full" "${EXPECTED}/full.gbb0"
+"${FUTILITY}" gbb -s --flags=0 "${EXPECTED}/full.gbb0"
 cp -f "${FROM_IMAGE}" "${FROM_IMAGE}.gbb0"
 "${FUTILITY}" gbb -s --flags=0 "${FROM_IMAGE}.gbb0"
-cp -f "${TMP}.expected.full" "${TMP}.expected.full.gbb0x27"
-"${FUTILITY}" gbb -s --flags=0x27 "${TMP}.expected.full.gbb0x27"
-cp -f "${TMP}.expected.full" "${TMP}.expected.large"
-dd if=/dev/zero bs=8388608 count=1 | tr '\000' '\377' >>"${TMP}.expected.large"
-cp -f "${TMP}.expected.full" "${TMP}.expected.me_unlocked_eve"
-patch_file "${TMP}.expected.me_unlocked_eve" SI_DESC 0x60 \
+cp -f "${EXPECTED}/full" "${EXPECTED}/full.gbb0x27"
+"${FUTILITY}" gbb -s --flags=0x27 "${EXPECTED}/full.gbb0x27"
+cp -f "${EXPECTED}/full" "${EXPECTED}/large"
+dd if=/dev/zero bs=8388608 count=1 | tr '\000' '\377' >>"${EXPECTED}/large"
+cp -f "${EXPECTED}/full" "${EXPECTED}/me_unlocked_eve"
+patch_file "${EXPECTED}/me_unlocked_eve" SI_DESC 0x60 \
   "\x00\xff\xff\xff\x00\xff\xff\xff\x00\xff\xff\xff"
-cp -f "${TMP}.expected.full" "${TMP}.expected.me_preserved"
-"${FUTILITY}" load_fmap "${TMP}.expected.me_preserved" \
-  "SI_ME:${TMP}.from/SI_ME"
-cp -f "${TMP}.expected.rw" "${TMP}.expected.rw.locked"
-patch_file "${TMP}.expected.rw.locked" FMAP 0x0430 "RO_GSCVD\x00"
+cp -f "${EXPECTED}/full" "${EXPECTED}/me_preserved"
+"${FUTILITY}" load_fmap "${EXPECTED}/me_preserved" \
+  "SI_ME:${TMP_FROM}/SI_ME"
+cp -f "${EXPECTED}/rw" "${EXPECTED}/rw.locked"
+patch_file "${EXPECTED}/rw.locked" FMAP 0x0430 "RO_GSCVD\x00"
 
 # A special set of images that only RO_VPD is preserved (RW_VPD is wiped) using
 # FMAP_AREA_PRESERVE (\010=0x08).
 TO_IMAGE_WIPE_RW_VPD="${TO_IMAGE}.wipe_rw_vpd"
 cp -f "${TO_IMAGE}" "${TO_IMAGE_WIPE_RW_VPD}"
 patch_file "${TO_IMAGE_WIPE_RW_VPD}" FMAP 0x3fc "$(printf '\010')"
-cp -f "${TMP}.expected.full" "${TMP}.expected.full.empty_rw_vpd"
-"${FUTILITY}" load_fmap "${TMP}.expected.full.empty_rw_vpd" \
-  RW_VPD:"${TMP}.to/RW_VPD"
-patch_file "${TMP}.expected.full.empty_rw_vpd" FMAP 0x3fc "$(printf '\010')"
+cp -f "${EXPECTED}/full" "${EXPECTED}/full.empty_rw_vpd"
+"${FUTILITY}" load_fmap "${EXPECTED}/full.empty_rw_vpd" \
+  RW_VPD:"${TMP_TO}/RW_VPD"
+patch_file "${EXPECTED}/full.empty_rw_vpd" FMAP 0x3fc "$(printf '\010')"
 
 # Generate images for testing --unlock_me.
 # There are two ways to detect the platform:
@@ -185,23 +201,25 @@ patch_file "${TMP}.expected.full.empty_rw_vpd" FMAP 0x3fc "$(printf '\010')"
 # Rename BOOT_STUB to COREBOOT, which is the default region used by cbfstool.
 rename_boot_stub() {
   local image="$1"
+  local fmap_file="${TMP}/fmap"
 
-  "${FUTILITY}" dump_fmap "${image}" -x "FMAP:${TMP}.fmap"
-  sed -i 's/BOOT_STUB/COREBOOT\x00/g' "${TMP}.fmap"
-  "${FUTILITY}" load_fmap "${image}" "FMAP:${TMP}.fmap"
+  "${FUTILITY}" dump_fmap "${image}" -x "FMAP:${fmap_file}"
+  sed -i 's/BOOT_STUB/COREBOOT\x00/g' "${fmap_file}"
+  "${FUTILITY}" load_fmap "${image}" "FMAP:${fmap_file}"
 }
 
 # Add the given line to the config file in CBFS.
 add_config() {
   local image="$1"
   local config_line="$2"
+  local config_file="${TMP}/config"
 
   rename_boot_stub "${image}"
 
-  cbfstool "${image}" extract -n config -f "${TMP}.config"
-  echo "${config_line}" >> "${TMP}.config"
+  cbfstool "${image}" extract -n config -f "${config_file}"
+  echo "${config_line}" >>"${config_file}"
   cbfstool "${image}" remove -n config
-  cbfstool "${image}" add -n config -f "${TMP}.config" -t raw
+  cbfstool "${image}" add -n config -f "${config_file}" -t raw
 }
 
 unlock_me() {
@@ -213,21 +231,21 @@ unlock_me() {
     "\x00\x00\x00\x00"
 }
 
-IFD_CHIPSET="CONFIG_IFD_CHIPSET=\"adl\""
-IFD_PATH="CONFIG_IFD_BIN_PATH=\"3rdparty/blobs/mainboard/google/nissa/descriptor-craask.bin\""
+IFD_CHIPSET='CONFIG_IFD_CHIPSET="adl"'
+IFD_PATH='CONFIG_IFD_BIN_PATH="3rdparty/blobs/mainboard/google/nissa/descriptor-craask.bin"'
 cp -f "${TO_IMAGE}" "${TO_IMAGE}.ifd_chipset"
 cp -f "${TO_IMAGE}" "${TO_IMAGE}.ifd_path"
-cp -f "${TMP}.expected.full" "${TMP}.expected.ifd_chipset"
-cp -f "${TMP}.expected.full" "${TMP}.expected.ifd_path"
+cp -f "${EXPECTED}/full" "${EXPECTED}/ifd_chipset"
+cp -f "${EXPECTED}/full" "${EXPECTED}/ifd_path"
 add_config "${TO_IMAGE}.ifd_chipset" "${IFD_CHIPSET}"
 add_config "${TO_IMAGE}.ifd_path" "${IFD_PATH}"
-add_config "${TMP}.expected.ifd_chipset" "${IFD_CHIPSET}"
-add_config "${TMP}.expected.ifd_path" "${IFD_PATH}"
+add_config "${EXPECTED}/ifd_chipset" "${IFD_CHIPSET}"
+add_config "${EXPECTED}/ifd_path" "${IFD_PATH}"
 
-cp -f "${TMP}.expected.ifd_chipset" "${TMP}.expected.me_unlocked.ifd_chipset"
-cp -f "${TMP}.expected.ifd_path" "${TMP}.expected.me_unlocked.ifd_path"
-unlock_me "${TMP}.expected.me_unlocked.ifd_chipset"
-unlock_me "${TMP}.expected.me_unlocked.ifd_path"
+cp -f "${EXPECTED}/ifd_chipset" "${EXPECTED}/me_unlocked.ifd_chipset"
+cp -f "${EXPECTED}/ifd_path" "${EXPECTED}/me_unlocked.ifd_path"
+unlock_me "${EXPECTED}/me_unlocked.ifd_chipset"
+unlock_me "${EXPECTED}/me_unlocked.ifd_path"
 
 # Has 3 modes:
 # 1. $3 = "!something", run command, expect failure,
@@ -240,17 +258,18 @@ test_update() {
   local emu_src="$2"
   local expected="$3"
   local error_msg="${expected#!}"
+  local emu="${TMP}/emu"
   local msg
 
   shift 3
-  cp -f "${emu_src}" "${TMP}.emu"
+  cp -f "${emu_src}" "${emu}"
   echo "*** Test Item: ${test_name}"
   if [ "${error_msg}" != "${expected}" ] && [ -n "${error_msg}" ]; then
-    msg="$(! "${FUTILITY}" update --emulate "${TMP}.emu" "$@" 2>&1)"
+    msg="$(! "${FUTILITY}" update --emulate "${emu}" "$@" 2>&1)"
     grep -qF -- "${error_msg}" <<<"${msg}"
   else
-    "${FUTILITY}" update --emulate "${TMP}.emu" "$@"
-    cmp "${TMP}.emu" "${expected}"
+    "${FUTILITY}" update --emulate "${emu}" "$@"
+    cmp "${emu}" "${expected}"
   fi
 }
 
@@ -260,12 +279,12 @@ test_update() {
 
 # Test Full update.
 test_update "Full update" \
-  "${FROM_IMAGE}" "${TMP}.expected.full" \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001
+  "${FROM_IMAGE}" "${EXPECTED}/full" \
+  -i "${TO_IMAGE}" --wp=0
 
 test_update "Full update (incompatible platform)" \
   "${FROM_IMAGE}" "!platform is not compatible" \
-  -i "${LINK_BIOS}" --wp=0 --sys_props 0,0x10001
+  -i "${LINK_BIOS}" --wp=0
 
 test_update "Full update (TPM Anti-rollback: data key)" \
   "${FROM_IMAGE}" "!Data key version rollback detected (2->1)" \
@@ -276,55 +295,54 @@ test_update "Full update (TPM Anti-rollback: kernel key)" \
   -i "${TO_IMAGE}" --wp=0 --sys_props 1,0x10005
 
 test_update "Full update (TPM Anti-rollback: 0 as tpm_fwver)" \
-  "${FROM_IMAGE}" "${TMP}.expected.full" \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x0
+  "${FROM_IMAGE}" "${EXPECTED}/full" \
+  -i "${TO_IMAGE}" --wp=0 --sys_props ,0x0
 
 test_update "Full update (TPM check failure due to invalid tpm_fwver)" \
   "${FROM_IMAGE}" "!Invalid tpm_fwver: -1" \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,-1
+  -i "${TO_IMAGE}" --wp=0 --sys_props ,-1
 
 test_update "Full update (Skip TPM check with --force)" \
-  "${FROM_IMAGE}" "${TMP}.expected.full" \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,-1 --force
+  "${FROM_IMAGE}" "${EXPECTED}/full" \
+  -i "${TO_IMAGE}" --wp=0 --sys_props ,-1 --force
 
 test_update "Full update (from stdin)" \
-  "${FROM_IMAGE}" "${TMP}.expected.full" \
-  -i - --wp=0 --sys_props 0,-1 --force <"${TO_IMAGE}"
+  "${FROM_IMAGE}" "${EXPECTED}/full" \
+  -i - --wp=0 --sys_props ,-1 --force <"${TO_IMAGE}"
 
 test_update "Full update (GBB=0 -> 0)" \
-  "${FROM_IMAGE}.gbb0" "${TMP}.expected.full.gbb0" \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001
+  "${FROM_IMAGE}.gbb0" "${EXPECTED}/full.gbb0" \
+  -i "${TO_IMAGE}" --wp=0
 
 test_update "Full update (GBB flags -> 0x27)" \
-  "${FROM_IMAGE}" "${TMP}.expected.full.gbb0x27" \
-  -i "${TO_IMAGE}" --gbb_flags=0x27 --wp=0 --sys_props 0,0x10001
+  "${FROM_IMAGE}" "${EXPECTED}/full.gbb0x27" \
+  -i "${TO_IMAGE}" --gbb_flags=0x27 --wp=0
 
 test_update "Full update (--host_only)" \
-  "${FROM_IMAGE}" "${TMP}.expected.full" \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001 \
-  --host_only --ec_image non-exist.bin
+  "${FROM_IMAGE}" "${EXPECTED}/full" \
+  -i "${TO_IMAGE}" --wp=0 --host_only --ec_image non-exist.bin
 
 test_update "Full update (GBB1.2 hwid digest)" \
-  "${FROM_IMAGE}" "${TMP}.expected.full.gbb12" \
-  -i "${TO_IMAGE_GBB12}" --wp=0 --sys_props 0,0x10001
+  "${FROM_IMAGE}" "${EXPECTED}/full.gbb12" \
+  -i "${TO_IMAGE_GBB12}" --wp=0
 
 test_update "Full update (Preserve VPD using FMAP_AREA_PRESERVE)" \
-  "${FROM_IMAGE}" "${TMP}.expected.full.empty_rw_vpd" \
-  -i "${TO_IMAGE_WIPE_RW_VPD}" --wp=0 --sys_props 0,0x10001
+  "${FROM_IMAGE}" "${EXPECTED}/full.empty_rw_vpd" \
+  -i "${TO_IMAGE_WIPE_RW_VPD}" --wp=0
 
 
 # Test RW-only update.
 test_update "RW update" \
-  "${FROM_IMAGE}" "${TMP}.expected.rw" \
-  -i "${TO_IMAGE}" --wp=1 --sys_props 0,0x10001
+  "${FROM_IMAGE}" "${EXPECTED}/rw" \
+  -i "${TO_IMAGE}" --wp=1
 
 test_update "RW update (incompatible platform)" \
   "${FROM_IMAGE}" "!platform is not compatible" \
-  -i "${LINK_BIOS}" --wp=1 --sys_props 0,0x10001
+  -i "${LINK_BIOS}" --wp=1
 
 test_update "RW update (incompatible rootkey)" \
   "${FROM_DIFFERENT_ROOTKEY_IMAGE}" "!RW signed by incompatible root key" \
-  -i "${TO_IMAGE}" --wp=1 --sys_props 0,0x10001
+  -i "${TO_IMAGE}" --wp=1
 
 test_update "RW update (TPM Anti-rollback: data key)" \
   "${FROM_IMAGE}" "!Data key version rollback detected (2->1)" \
@@ -336,23 +354,31 @@ test_update "RW update (TPM Anti-rollback: kernel key)" \
 
 # Test Try-RW update (vboot2).
 test_update "RW update (A->B)" \
-  "${FROM_IMAGE}" "${TMP}.expected.b" \
-  -i "${TO_IMAGE}" -t --wp=1 --sys_props 0,0x10001
+  "${FROM_IMAGE}" "${EXPECTED}/b" \
+  -i "${TO_IMAGE}" -t --wp=1 --sys_props 0
 
 test_update "RW update (B->A)" \
-  "${FROM_IMAGE}" "${TMP}.expected.a" \
-  -i "${TO_IMAGE}" -t --wp=1 --sys_props 1,0x10001
+  "${FROM_IMAGE}" "${EXPECTED}/a" \
+  -i "${TO_IMAGE}" -t --wp=1 --sys_props 1
+
+test_update "RW update, same RO, wp=0 (A->B)" \
+  "${FROM_SAME_RO_IMAGE}" "${EXPECTED}/FROM_SAME_RO_IMAGE.b" \
+  -i "${TO_IMAGE}" -t --wp=0 --sys_props 0
+
+test_update "RW update, same RO, wp=1 (A->B)" \
+  "${FROM_SAME_RO_IMAGE}" "${EXPECTED}/FROM_SAME_RO_IMAGE.b" \
+  -i "${TO_IMAGE}" -t --wp=1 --sys_props 0
 
 test_update "RW update -> fallback to RO+RW Full update" \
-  "${FROM_IMAGE}" "${TMP}.expected.full" \
+  "${FROM_IMAGE}" "${EXPECTED}/full" \
   -i "${TO_IMAGE}" -t --wp=0 --sys_props 1,0x10002
 test_update "RW update (incompatible platform)" \
   "${FROM_IMAGE}" "!platform is not compatible" \
-  -i "${LINK_BIOS}" -t --wp=1 --sys_props 0x10001
+  -i "${LINK_BIOS}" -t --wp=1
 
 test_update "RW update (incompatible rootkey)" \
   "${FROM_DIFFERENT_ROOTKEY_IMAGE}" "!RW signed by incompatible root key" \
-  -i "${TO_IMAGE}" -t --wp=1 --sys_props 0,0x10001
+  -i "${TO_IMAGE}" -t --wp=1
 
 test_update "RW update (TPM Anti-rollback: data key)" \
   "${FROM_IMAGE}" "!Data key version rollback detected (2->1)" \
@@ -368,196 +394,163 @@ test_update "RW update -> fallback to RO+RW Full update (TPM Anti-rollback)" \
 
 # Test 'factory mode'
 test_update "Factory mode update (WP=0)" \
-  "${FROM_IMAGE}" "${TMP}.expected.full" \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001 --mode=factory
+  "${FROM_IMAGE}" "${EXPECTED}/full" \
+  -i "${TO_IMAGE}" --wp=0 --mode=factory
 
 test_update "Factory mode update (WP=0)" \
-  "${FROM_IMAGE}" "${TMP}.expected.full" \
-  --factory -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001
+  "${FROM_IMAGE}" "${EXPECTED}/full" \
+  --factory -i "${TO_IMAGE}" --wp=0
 
 test_update "Factory mode update (WP=1)" \
   "${FROM_IMAGE}" "!remove write protection for factory mode" \
-  -i "${TO_IMAGE}" --wp=1 --sys_props 0,0x10001 --mode=factory
+  -i "${TO_IMAGE}" --wp=1 --mode=factory
 
 test_update "Factory mode update (WP=1)" \
   "${FROM_IMAGE}" "!remove write protection for factory mode" \
-  --factory -i "${TO_IMAGE}" --wp=1 --sys_props 0,0x10001
+  --factory -i "${TO_IMAGE}" --wp=1
 
 test_update "Factory mode update (GBB=0 -> 0x39)" \
-  "${FROM_IMAGE}.gbb0" "${TMP}.expected.full" \
-  --factory -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001
+  "${FROM_IMAGE}.gbb0" "${EXPECTED}/full" \
+  --factory -i "${TO_IMAGE}" --wp=0
 
 # Test 'AP RO locked with verification turned on'
 test_update "AP RO locked update (locked, SI_DESC is different)" \
-  "${FROM_IMAGE}.locked" "${TMP}.expected.rw.locked" \
-  -i "${TO_IMAGE}" --wp=0 --debug --sys_props 0,0x10001
+  "${FROM_IMAGE}.locked" "${EXPECTED}/rw.locked" \
+  -i "${TO_IMAGE}" --wp=0 --debug
 
 test_update "AP RO locked update (locked, SI_DESC is the same)" \
-  "${FROM_IMAGE}.locked_same_desc" "${TMP}.expected.full" \
-  -i "${TO_IMAGE}" --wp=0 --debug --sys_props 0,0x10001
+  "${FROM_IMAGE}.locked_same_desc" "${EXPECTED}/full" \
+  -i "${TO_IMAGE}" --wp=0 --debug
 
 test_update "AP RO locked update (unlocked)" \
-  "${FROM_IMAGE}.unlocked" "${TMP}.expected.full" \
-  -i "${TO_IMAGE}" --wp=0 --debug --sys_props 0,0x10001
+  "${FROM_IMAGE}.unlocked" "${EXPECTED}/full" \
+  -i "${TO_IMAGE}" --wp=0 --debug
 
 # Test legacy update
 test_update "Legacy update" \
-  "${FROM_IMAGE}" "${TMP}.expected.legacy" \
+  "${FROM_IMAGE}" "${EXPECTED}/legacy" \
   -i "${TO_IMAGE}" --mode=legacy
 
 # Test quirks
 test_update "Full update (wrong size)" \
   "${FROM_IMAGE}.large" "!Failed writing firmware" \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001 \
+  -i "${TO_IMAGE}" --wp=0 \
   --quirks unlock_csme_eve,eve_smm_store
 
 test_update "Full update (--quirks enlarge_image)" \
-  "${FROM_IMAGE}.large" "${TMP}.expected.large" --quirks enlarge_image \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001
+  "${FROM_IMAGE}.large" "${EXPECTED}/large" --quirks enlarge_image \
+  -i "${TO_IMAGE}" --wp=0
 
 test_update "Full update (multi-line --quirks enlarge_image)" \
-  "${FROM_IMAGE}.large" "${TMP}.expected.large" --quirks '
+  "${FROM_IMAGE}.large" "${EXPECTED}/large" --quirks '
   enlarge_image
-  ' -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001
+  ' -i "${TO_IMAGE}" --wp=0
 
 test_update "Full update (--quirks unlock_csme_eve)" \
-  "${FROM_IMAGE}" "${TMP}.expected.me_unlocked_eve" \
+  "${FROM_IMAGE}" "${EXPECTED}/me_unlocked_eve" \
   --quirks unlock_csme_eve \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001
+  -i "${TO_IMAGE}" --wp=0
 
 test_update "Full update (failure by --quirks min_platform_version)" \
   "${FROM_IMAGE}" "!Need platform version >= 3 (current is 2)" \
   --quirks min_platform_version=3 \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001,2
+  -i "${TO_IMAGE}" --wp=0 --sys_props ,,2
 
 test_update "Full update (--quirks min_platform_version)" \
-  "${FROM_IMAGE}" "${TMP}.expected.full" \
+  "${FROM_IMAGE}" "${EXPECTED}/full" \
   --quirks min_platform_version=3 \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001,3
+  -i "${TO_IMAGE}" --wp=0 --sys_props ,,3
 
 test_update "Full update (incompatible platform)" \
   "${FROM_IMAGE}".unpatched "!platform is not compatible" \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001
+  -i "${TO_IMAGE}" --wp=0
 
 test_update "Full update (--quirks no_check_platform)" \
-  "${FROM_IMAGE}".unpatched "${TMP}.expected.full" \
+  "${FROM_IMAGE}".unpatched "${EXPECTED}/full" \
   --quirks no_check_platform \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001
+  -i "${TO_IMAGE}" --wp=0
 
 test_update "Full update (--quirks preserve_me with non-host programmer)" \
-  "${FROM_IMAGE}" "${TMP}.expected.full" \
+  "${FROM_IMAGE}" "${EXPECTED}/full" \
   --quirks preserve_me \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001 \
+  -i "${TO_IMAGE}" --wp=0 \
   -p raiden_debug_spi:target=AP
 
 test_update "Full update (--quirks preserve_me)" \
-  "${FROM_IMAGE}" "${TMP}.expected.full" \
+  "${FROM_IMAGE}" "${EXPECTED}/full" \
   --quirks preserve_me \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001
+  -i "${TO_IMAGE}" --wp=0
 
 test_update "Full update (--quirks preserve_me, autoupdate)" \
-  "${FROM_IMAGE}" "${TMP}.expected.me_preserved" \
+  "${FROM_IMAGE}" "${EXPECTED}/me_preserved" \
   --quirks preserve_me -m autoupdate \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001
+  -i "${TO_IMAGE}" --wp=0
 
 test_update "Full update (--quirks preserve_me, deferupdate_hold)" \
-  "${FROM_IMAGE}" "${TMP}.expected.me_preserved" \
+  "${FROM_IMAGE}" "${EXPECTED}/me_preserved" \
   --quirks preserve_me -m deferupdate_hold \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001
+  -i "${TO_IMAGE}" --wp=0
 
 test_update "Full update (--quirks preserve_me, factory)" \
-  "${FROM_IMAGE}" "${TMP}.expected.full" \
+  "${FROM_IMAGE}" "${EXPECTED}/full" \
   --quirks preserve_me -m factory \
-  -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001
+  -i "${TO_IMAGE}" --wp=0
 
 # Test manifest.
-echo "TEST: Manifest (--manifest, -i, image.bin)"
-cp -f "${GERALT_BIOS}" image.bin
-"${FUTILITY}" update -i image.bin --manifest >"${TMP}.json.out"
+TMP_JSON_OUT="${TMP}/json.out"
+echo "TEST: Manifest (--manifest, --image)"
+cp -f "${GERALT_BIOS}" "${TMP}/image.bin"
+(cd "${TMP}" &&
+ "${FUTILITY}" update -i image.bin --manifest) >"${TMP_JSON_OUT}"
 cmp \
-  <(jq -S <"${TMP}.json.out") \
+  <(jq -S <"${TMP_JSON_OUT}") \
   <(jq -S <"${SCRIPT_DIR}/futility/bios_geralt_cbfs.manifest.json")
 
 # Test archive and manifest. CL_TAG is for custom_label_tag.
-A="${TMP}.archive"
+A="${TMP}/archive"
 mkdir -p "${A}/bin"
-echo "echo \"\${CL_TAG}\"" >"${A}/bin/vpd"
+echo 'echo "${CL_TAG}"' >"${A}/bin/vpd"
 chmod +x "${A}/bin/vpd"
 
 cp -f "${LINK_BIOS}" "${A}/bios.bin"
 echo "TEST: Manifest (--manifest, -a, bios.bin)"
-"${FUTILITY}" update -a "${A}" --manifest >"${TMP}.json.out"
+"${FUTILITY}" update -a "${A}" --manifest >"${TMP_JSON_OUT}"
 cmp \
-  <(jq -S <"${TMP}.json.out") \
+  <(jq -S <"${TMP_JSON_OUT}") \
   <(jq -S <"${SCRIPT_DIR}/futility/link_bios.manifest.json")
 
 mv -f "${A}/bios.bin" "${A}/image.bin"
 echo "TEST: Manifest (--manifest, -a, image.bin)"
-"${FUTILITY}" update -a "${A}" --manifest >"${TMP}.json.out"
+"${FUTILITY}" update -a "${A}" --manifest >"${TMP_JSON_OUT}"
 cmp \
-  <(jq -S <"${TMP}.json.out") \
+  <(jq -S <"${TMP_JSON_OUT}") \
   <(jq -S <"${SCRIPT_DIR}/futility/link_image.manifest.json")
 
 
 cp -f "${TO_IMAGE}" "${A}/image.bin"
 test_update "Full update (--archive, single package)" \
-  "${FROM_IMAGE}" "${TMP}.expected.full" \
-  -a "${A}" --wp=0 --sys_props 0,0x10001,3
+  "${FROM_IMAGE}" "${EXPECTED}/full" \
+  -a "${A}" --wp=0 --sys_props ,,3
 
-echo "TEST: Output (--mode=output)"
-mkdir -p "${TMP}.output"
-"${FUTILITY}" update -i "${LINK_BIOS}" --mode=output \
-  --output_dir="${TMP}.output"
-cmp "${LINK_BIOS}" "${TMP}.output/image.bin"
+echo "TEST: Output (--archive, --mode=output)"
+TMP_OUTPUT="${TMP}/out_archive" && mkdir -p "${TMP_OUTPUT}"
+"${FUTILITY}" update -a "${A}" --mode=output \
+  --output_dir="${TMP_OUTPUT}"
+cmp "${TMP_OUTPUT}/image.bin" "${TO_IMAGE}"
 
-mkdir -p "${A}/keyset"
-cp -f "${LINK_BIOS}" "${A}/image.bin"
-cp -f "${TMP}.to/rootkey" "${A}/keyset/rootkey.CL"
-cp -f "${TMP}.to/VBLOCK_A" "${A}/keyset/vblock_A.CL"
-cp -f "${TMP}.to/VBLOCK_B" "${A}/keyset/vblock_B.CL"
-"${FUTILITY}" gbb -s --rootkey="${TMP}.from/rootkey" "${A}/image.bin"
-"${FUTILITY}" load_fmap "${A}/image.bin" VBLOCK_A:"${TMP}.from/VBLOCK_A"
-"${FUTILITY}" load_fmap "${A}/image.bin" VBLOCK_B:"${TMP}.from/VBLOCK_B"
-
-test_update "Full update (--archive, custom label, no VPD)" \
-  "${A}/image.bin" "!Need VPD set for custom" \
-  -a "${A}" --wp=0 --sys_props 0,0x10001,3
-
-test_update "Full update (--archive, custom label, no VPD - factory mode)" \
-  "${LINK_BIOS}" "${A}/image.bin" \
-  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --mode=factory
-
-test_update "Full update (--archive, custom label, no VPD - quirk mode)" \
-  "${LINK_BIOS}" "${A}/image.bin" \
-  -a "${A}" --wp=0 --sys_props 0,0x10001,3 \
-  --quirks=allow_empty_custom_label_tag
-
-test_update "Full update (--archive, custom label, single package)" \
-  "${A}/image.bin" "${LINK_BIOS}" \
-  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --signature_id=CL
-
-CL_TAG="CL" PATH="${A}/bin:${PATH}" \
-  test_update "Full update (--archive, custom label, fake vpd)" \
-  "${A}/image.bin" "${LINK_BIOS}" \
-  -a "${A}" --wp=0 --sys_props 0,0x10001,3
-
-echo "TEST: Output (-a, --mode=output)"
-mkdir -p "${TMP}.outa"
-cp -f "${A}/image.bin" "${TMP}.emu"
-CL_TAG="CL" PATH="${A}/bin:${PATH}" \
-  "${FUTILITY}" update -a "${A}" --mode=output --emu="${TMP}.emu" \
-  --output_dir="${TMP}.outa"
-cmp "${LINK_BIOS}" "${TMP}.outa/image.bin"
-
-# Test archive with Unified Build contents.
+# Test Unified Build archives.
+mkdir -p "${A}/keyset" "${A}/images"
 cp -f "${SIGNER_CONFIG}" "${A}/"
-mkdir -p "${A}/images"
-mv "${A}/image.bin" "${A}/images/bios_coral.bin"
+cp -f "${LINK_BIOS}" "${A}/image.bin"
+"${FUTILITY}" gbb -s --rootkey="${TMP_FROM}/rootkey" "${A}/image.bin"
+"${FUTILITY}" load_fmap "${A}/image.bin" VBLOCK_A:"${TMP_FROM}/VBLOCK_A"
+"${FUTILITY}" load_fmap "${A}/image.bin" VBLOCK_B:"${TMP_FROM}/VBLOCK_B"
+mv -f "${A}/image.bin" "${A}/images/bios_coral.bin"
 cp -f "${PEPPY_BIOS}" "${A}/images/bios_peppy.bin"
 cp -f "${LINK_BIOS}" "${A}/images/bios_link.bin"
-cp -f "${TMP}.to/rootkey" "${A}/keyset/rootkey.customtip-cl"
-cp -f "${TMP}.to/VBLOCK_A" "${A}/keyset/vblock_A.customtip-cl"
-cp -f "${TMP}.to/VBLOCK_B" "${A}/keyset/vblock_B.customtip-cl"
+cp -f "${TMP_TO}/rootkey" "${A}/keyset/rootkey.customtip-cl"
+cp -f "${TMP_TO}/VBLOCK_A" "${A}/keyset/vblock_A.customtip-cl"
+cp -f "${TMP_TO}/VBLOCK_B" "${A}/keyset/vblock_B.customtip-cl"
 cp -f "${PEPPY_BIOS}" "${FROM_IMAGE}.ap"
 cp -f "${LINK_BIOS}" "${FROM_IMAGE}.al"
 cp -f "${VOXEL_BIOS}" "${FROM_IMAGE}.av"
@@ -573,10 +566,6 @@ test_update "Full update (--archive, model=peppy)" \
 test_update "Full update (--archive, model=unknown)" \
   "${FROM_IMAGE}.ap" "!Unsupported model: 'unknown'" \
   -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=unknown
-test_update "Full update (--archive, model=customtip, signature_id=CL)" \
-  "${FROM_IMAGE}.al" "${LINK_BIOS}" \
-  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=customtip \
-  --signature_id=customtip-cl
 
 test_update "Full update (--archive, detect-model)" \
   "${FROM_IMAGE}.ap" "${PEPPY_BIOS}" \
@@ -589,84 +578,103 @@ test_update "Full update (--archive, detect-model, unsupported FRID)" \
 
 echo "*** Test Item: Detect model (--archive, --detect-model-only)"
 "${FUTILITY}" update -a "${A}" \
-  --emulate "${FROM_IMAGE}.ap" --detect-model-only >"${TMP}.model.out"
-cmp "${TMP}.model.out" <(echo peppy)
+  --emulate "${FROM_IMAGE}.ap" --detect-model-only >"${TMP}/model.out"
+cmp "${TMP}/model.out" <(echo peppy)
 
+test_update "Full update (--archive, custom label with tag specified)" \
+  "${FROM_IMAGE}.al" "${LINK_BIOS}" \
+  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=customtip-cl
+CL_TAG="bad" PATH="${A}/bin:${PATH}" \
+  test_update "Full update (--archive, custom label, wrong image)" \
+  "${FROM_IMAGE}.al" "!The firmware image for custom label" \
+  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --debug --model=customtip
 CL_TAG="cl" PATH="${A}/bin:${PATH}" \
-  test_update "Full update (-a, model=customtip, fake VPD)" \
+  test_update "Full update (--archive, custom label, fake VPD)" \
   "${FROM_IMAGE}.al" "${LINK_BIOS}" \
   -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=customtip
 
-# Custom label + Unibuild without default keys
-test_update "Full update (--a, model=customtip, no VPD, no default keys)" \
-  "${FROM_IMAGE}.al" "!Need VPD set for custom" \
-  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=customtip
+# The output mode (without specifying signature id) for custom label would still
+# need a source (emulate) image to decide the VPD, which is not a real use case.
+echo "TEST: Output (--archive, --mode=output, custom label with tag specified)"
+TMP_OUTPUT="${TMP}/out_custom_label" && mkdir -p "${TMP_OUTPUT}"
+"${FUTILITY}" update -a "${A}" --mode=output \
+  --output_dir="${TMP_OUTPUT}" --model=customtip-cl
+cmp "${TMP_OUTPUT}/image.bin" "${LINK_BIOS}"
 
 # Custom label + Unibuild with default keys as model name
-cp -f "${TMP}.to/rootkey" "${A}/keyset/rootkey.customtip"
-cp -f "${TMP}.to/VBLOCK_A" "${A}/keyset/vblock_A.customtip"
-cp -f "${TMP}.to/VBLOCK_B" "${A}/keyset/vblock_B.customtip"
-test_update "Full update (-a, model=customtip, no VPD, default keys)" \
+cp -f "${TMP_TO}/rootkey" "${A}/keyset/rootkey.customtip"
+cp -f "${TMP_TO}/VBLOCK_A" "${A}/keyset/vblock_A.customtip"
+cp -f "${TMP_TO}/VBLOCK_B" "${A}/keyset/vblock_B.customtip"
+test_update "Full update (--archive, custom label, no VPD, default keys)" \
   "${FROM_IMAGE}.al" "${LINK_BIOS}" \
   -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=customtip
 
 # Test special programmer
-if type flashrom >/dev/null 2>&1; then
+test_flashrom() {
   echo "TEST: Full update (dummy programmer)"
-  cp -f "${FROM_IMAGE}" "${TMP}.emu"
+  local emu="${TMP}/emu"
+  cp -f "${FROM_IMAGE}" "${emu}"
   "${FUTILITY}" update --programmer \
-    dummy:emulate=VARIABLE_SIZE,image="${TMP}".emu,size=8388608 \
+    dummy:emulate=VARIABLE_SIZE,image="${emu}",size=8388608 \
     -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001,3 >&2
-  cmp "${TMP}.emu" "${TMP}.expected.full"
-fi
-
-if type cbfstool >/dev/null 2>&1; then
-  echo "SMM STORE" >"${TMP}.smm"
-  truncate -s 262144 "${TMP}.smm"
-  cp -f "${FROM_IMAGE}" "${TMP}.from.smm"
-  cp -f "${TMP}.expected.full" "${TMP}.expected.full_smm"
-  cbfstool "${TMP}.from.smm" add -r RW_LEGACY -n "smm_store" \
-    -f "${TMP}.smm" -t raw
-  cbfstool "${TMP}.expected.full_smm" add -r RW_LEGACY -n "smm_store" \
-    -f "${TMP}.smm" -t raw -b 0x1bf000
+  cmp "${emu}" "${EXPECTED}/full"
+}
+type flashrom >/dev/null 2>&1 && test_flashrom
+
+test_cbfstool() {
+  echo "TEST: Update with cbsfstool"
+  local smm="${TMP}/smm"
+  local cbfs="${TMP}/cbfs"
+  local quirk="${TMP}/quirk"
+
+  echo "SMM STORE" >"${smm}"
+  truncate -s 262144 "${smm}"
+  cp -f "${FROM_IMAGE}" "${TMP_FROM}.smm"
+  cp -f "${EXPECTED}/full" "${EXPECTED}/full_smm"
+  cbfstool "${TMP_FROM}.smm" add -r RW_LEGACY -n "smm_store" \
+    -f "${smm}" -t raw
+  cbfstool "${EXPECTED}/full_smm" add -r RW_LEGACY -n "smm_store" \
+    -f "${smm}" -t raw -b 0x1bf000
   test_update "Legacy update (--quirks eve_smm_store)" \
-    "${TMP}.from.smm" "${TMP}.expected.full_smm" \
-    -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001 \
+    "${TMP_FROM}.smm" "${EXPECTED}/full_smm" \
+    -i "${TO_IMAGE}" --wp=0 \
     --quirks eve_smm_store
 
-  echo "min_platform_version=3" >"${TMP}.quirk"
+  echo "min_platform_version=3" >"${quirk}"
   cp -f "${TO_IMAGE}" "${TO_IMAGE}.quirk"
-  "${FUTILITY}" dump_fmap -x "${TO_IMAGE}" "BOOT_STUB:${TMP}.cbfs"
+  "${FUTILITY}" dump_fmap -x "${TO_IMAGE}" "BOOT_STUB:${cbfs}"
   # Create a fake CBFS using FW_MAIN_A size.
-  truncate -s $((0x000dffc0)) "${TMP}.cbfs"
-  "${FUTILITY}" load_fmap "${TO_IMAGE}.quirk" "FW_MAIN_A:${TMP}.cbfs"
+  truncate -s $((0x000dffc0)) "${cbfs}"
+  "${FUTILITY}" load_fmap "${TO_IMAGE}.quirk" "FW_MAIN_A:${cbfs}"
   cbfstool "${TO_IMAGE}.quirk" add -r FW_MAIN_A -n updater_quirks \
-    -f "${TMP}.quirk" -t raw
+    -f "${quirk}" -t raw
   test_update "Full update (failure by CBFS quirks)" \
     "${FROM_IMAGE}" "!Need platform version >= 3 (current is 2)" \
     -i "${TO_IMAGE}.quirk" --wp=0 --sys_props 0,0x10001,2
-fi
+}
+type cbfstool >/dev/null 2>&1 && test_cbfstool
 
-if type ifdtool >/dev/null 2>&1; then
+test_ifdtool() {
   test_update "Full update (--quirks unlock_csme, IFD chipset)" \
-    "${FROM_IMAGE}" "${TMP}.expected.me_unlocked.ifd_chipset" \
-    --quirks unlock_csme -i "${TO_IMAGE}.ifd_chipset" \
-    --wp=0 --sys_props 0,0x10001
+    "${FROM_IMAGE}" "${EXPECTED}/me_unlocked.ifd_chipset" \
+    --quirks unlock_csme -i "${TO_IMAGE}.ifd_chipset" --wp=0
 
   test_update "Full update (--quirks unlock_csme, IFD bin path)" \
-    "${FROM_IMAGE}" "${TMP}.expected.me_unlocked.ifd_path" \
-    --quirks unlock_csme -i "${TO_IMAGE}.ifd_path" \
-    --wp=0 --sys_props 0,0x10001
+    "${FROM_IMAGE}" "${EXPECTED}/me_unlocked.ifd_path" \
+    --quirks unlock_csme -i "${TO_IMAGE}.ifd_path" --wp=0
 
   test_update "Full update (--unlock_me)" \
-    "${FROM_IMAGE}" "${TMP}.expected.me_unlocked.ifd_chipset" \
-    --unlock_me -i "${TO_IMAGE}.ifd_chipset" --wp=0 --sys_props 0,0x10001
+    "${FROM_IMAGE}" "${EXPECTED}/me_unlocked.ifd_chipset" \
+    --unlock_me -i "${TO_IMAGE}.ifd_chipset" --wp=0
 
   echo "TEST: Output (--mode=output, --quirks unlock_csme)"
-  "${FUTILITY}" update -i "${TMP}.expected.ifd_chipset" --mode=output \
-    --output_dir="${TMP}.output" --quirks unlock_csme
-  cmp "${TMP}.expected.me_unlocked.ifd_chipset" "${TMP}.output/image.bin"
-fi
+  TMP_OUTPUT="${TMP}/out_csme" && mkdir -p "${TMP_OUTPUT}"
+  mkdir -p "${TMP_OUTPUT}"
+  "${FUTILITY}" update -i "${EXPECTED}/ifd_chipset" --mode=output \
+    --output_dir="${TMP_OUTPUT}" --quirks unlock_csme
+  cmp "${TMP_OUTPUT}/image.bin" "${EXPECTED}/me_unlocked.ifd_chipset"
+}
+type ifdtool >/dev/null 2>&1 && test_ifdtool
 
-rm -rf "${TMP}"*
+rm -rf "${TMP}"
 exit 0
diff --git a/vboot.rc b/vboot.rc
new file mode 100644
index 00000000..959ac808
--- /dev/null
+++ b/vboot.rc
@@ -0,0 +1,6 @@
+# Create and mount working paths for vboot tools.
+on post-fs-data-checkpointed
+    mkdir /data/vendor/vboot
+    mkdir /data/vendor/vboot/tmp
+    mount tmpfs tmpfs /data/vendor/vboot/tmp nosuid nodev noexec rw
+    restorecon /data/vendor/vboot
```

