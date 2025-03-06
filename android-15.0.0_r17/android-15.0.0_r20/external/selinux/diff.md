```diff
diff --git a/checkpolicy/fuzz/checkpolicy-fuzzer.c b/checkpolicy/fuzz/checkpolicy-fuzzer.c
index ddb43260..331201c0 100644
--- a/checkpolicy/fuzz/checkpolicy-fuzzer.c
+++ b/checkpolicy/fuzz/checkpolicy-fuzzer.c
@@ -101,7 +101,7 @@ static int read_source_policy(policydb_t *p, const uint8_t *data, size_t size)
 
 	init_parser(1);
 
-	if (!setjmp(fuzzing_pre_parse_stack_state)) {
+	if (setjmp(fuzzing_pre_parse_stack_state) != 0) {
 		queue_destroy(id_queue);
 		fclose(yyin);
 		yylex_destroy();
diff --git a/checkpolicy/policy_define.c b/checkpolicy/policy_define.c
index 4931f23d..f8a10154 100644
--- a/checkpolicy/policy_define.c
+++ b/checkpolicy/policy_define.c
@@ -1874,27 +1874,27 @@ avrule_t *define_cond_pol_list(avrule_t * avlist, avrule_t * sl)
 	return sl;
 }
 
-typedef struct av_ioctl_range {
+typedef struct av_xperm_range {
 	uint16_t low;
 	uint16_t high;
-} av_ioctl_range_t;
+} av_xperm_range_t;
 
-struct av_ioctl_range_list {
+struct av_xperm_range_list {
 	uint8_t omit;
-	av_ioctl_range_t range;
-	struct av_ioctl_range_list *next;
+	av_xperm_range_t range;
+	struct av_xperm_range_list *next;
 };
 
-static int avrule_sort_ioctls(struct av_ioctl_range_list **rangehead)
+static int avrule_sort_xperms(struct av_xperm_range_list **rangehead)
 {
-	struct av_ioctl_range_list *r, *r2, *sorted, *sortedhead = NULL;
+	struct av_xperm_range_list *r, *r2, *sorted, *sortedhead = NULL;
 
 	/* order list by range.low */
 	for (r = *rangehead; r != NULL; r = r->next) {
-		sorted = malloc(sizeof(struct av_ioctl_range_list));
+		sorted = malloc(sizeof(struct av_xperm_range_list));
 		if (sorted == NULL)
 			goto error;
-		memcpy(sorted, r, sizeof(struct av_ioctl_range_list));
+		memcpy(sorted, r, sizeof(struct av_xperm_range_list));
 		sorted->next = NULL;
 		if (sortedhead == NULL) {
 			sortedhead = sorted;
@@ -1933,9 +1933,9 @@ error:
 	return -1;
 }
 
-static void avrule_merge_ioctls(struct av_ioctl_range_list **rangehead)
+static void avrule_merge_xperms(struct av_xperm_range_list **rangehead)
 {
-	struct av_ioctl_range_list *r, *tmp;
+	struct av_xperm_range_list *r, *tmp;
 	r = *rangehead;
 	while (r != NULL && r->next != NULL) {
 		/* merge */
@@ -1952,15 +1952,15 @@ static void avrule_merge_ioctls(struct av_ioctl_range_list **rangehead)
 	}
 }
 
-static int avrule_read_ioctls(struct av_ioctl_range_list **rangehead)
+static int avrule_read_xperm_ranges(struct av_xperm_range_list **rangehead)
 {
 	char *id;
-	struct av_ioctl_range_list *rnew, *r = NULL;
+	struct av_xperm_range_list *rnew, *r = NULL;
 	uint8_t omit = 0;
 
 	*rangehead = NULL;
 
-	/* read in all the ioctl commands */
+	/* read in all the ioctl/netlink commands */
 	while ((id = queue_remove(id_queue))) {
 		if (strcmp(id,"~") == 0) {
 			/* these are values to be omitted */
@@ -1979,7 +1979,7 @@ static int avrule_read_ioctls(struct av_ioctl_range_list **rangehead)
 			free(id);
 		} else {
 			/* read in new low value */
-			rnew = malloc(sizeof(struct av_ioctl_range_list));
+			rnew = malloc(sizeof(struct av_xperm_range_list));
 			if (rnew == NULL)
 				goto error;
 			rnew->next = NULL;
@@ -2006,11 +2006,11 @@ error:
 }
 
 /* flip to included ranges */
-static int avrule_omit_ioctls(struct av_ioctl_range_list **rangehead)
+static int avrule_omit_xperms(struct av_xperm_range_list **rangehead)
 {
-	struct av_ioctl_range_list *rnew, *r, *newhead, *r2;
+	struct av_xperm_range_list *rnew, *r, *newhead, *r2;
 
-	rnew = calloc(1, sizeof(struct av_ioctl_range_list));
+	rnew = calloc(1, sizeof(struct av_xperm_range_list));
 	if (!rnew)
 		goto error;
 
@@ -2028,7 +2028,7 @@ static int avrule_omit_ioctls(struct av_ioctl_range_list **rangehead)
 
 	while (r) {
 		r2->range.high = r->range.low - 1;
-		rnew = calloc(1, sizeof(struct av_ioctl_range_list));
+		rnew = calloc(1, sizeof(struct av_xperm_range_list));
 		if (!rnew)
 			goto error;
 		r2->next = rnew;
@@ -2054,26 +2054,26 @@ error:
 	return -1;
 }
 
-static int avrule_ioctl_ranges(struct av_ioctl_range_list **rangelist)
+static int avrule_xperm_ranges(struct av_xperm_range_list **rangelist)
 {
-	struct av_ioctl_range_list *rangehead;
+	struct av_xperm_range_list *rangehead;
 	uint8_t omit;
 
 	/* read in ranges to include and omit */
-	if (avrule_read_ioctls(&rangehead))
+	if (avrule_read_xperm_ranges(&rangehead))
 		return -1;
 	if (rangehead == NULL) {
-		yyerror("error processing ioctl commands");
+		yyerror("error processing ioctl/netlink commands");
 		return -1;
 	}
 	omit = rangehead->omit;
-	/* sort and merge the input ioctls */
-	if (avrule_sort_ioctls(&rangehead))
+	/* sort and merge the input ranges */
+	if (avrule_sort_xperms(&rangehead))
 		return -1;
-	avrule_merge_ioctls(&rangehead);
+	avrule_merge_xperms(&rangehead);
 	/* flip ranges if these are omitted */
 	if (omit) {
-		if (avrule_omit_ioctls(&rangehead))
+		if (avrule_omit_xperms(&rangehead))
 			return -1;
 	}
 
@@ -2261,11 +2261,11 @@ static int avrule_xperms_used(const av_extended_perms_t *xperms)
 #define IOC_DRIV(x) ((x) >> 8)
 #define IOC_FUNC(x) ((x) & 0xff)
 #define IOC_CMD(driver, func) (((driver) << 8) + (func))
-static int avrule_ioctl_partialdriver(struct av_ioctl_range_list *rangelist,
+static int avrule_xperm_partialdriver(struct av_xperm_range_list *rangelist,
 				av_extended_perms_t *complete_driver,
 				av_extended_perms_t **extended_perms)
 {
-	struct av_ioctl_range_list *r;
+	struct av_xperm_range_list *r;
 	av_extended_perms_t *xperms;
 	uint8_t low, high;
 
@@ -2300,10 +2300,10 @@ static int avrule_ioctl_partialdriver(struct av_ioctl_range_list *rangelist,
 
 }
 
-static int avrule_ioctl_completedriver(struct av_ioctl_range_list *rangelist,
+static int avrule_ioctl_completedriver(struct av_xperm_range_list *rangelist,
 			av_extended_perms_t **extended_perms)
 {
-	struct av_ioctl_range_list *r;
+	struct av_xperm_range_list *r;
 	av_extended_perms_t *xperms;
 	uint16_t low, high;
 	xperms = calloc(1, sizeof(av_extended_perms_t));
@@ -2342,10 +2342,10 @@ static int avrule_ioctl_completedriver(struct av_ioctl_range_list *rangelist,
 	return 0;
 }
 
-static int avrule_ioctl_func(struct av_ioctl_range_list *rangelist,
-		av_extended_perms_t **extended_perms, unsigned int driver)
+static int avrule_xperm_func(struct av_xperm_range_list *rangelist,
+		av_extended_perms_t **extended_perms, unsigned int driver, uint8_t specified)
 {
-	struct av_ioctl_range_list *r;
+	struct av_xperm_range_list *r;
 	av_extended_perms_t *xperms;
 	uint16_t low, high;
 
@@ -2379,7 +2379,7 @@ static int avrule_ioctl_func(struct av_ioctl_range_list *rangelist,
 		high = IOC_FUNC(high);
 		avrule_xperm_setrangebits(low, high, xperms);
 		xperms->driver = driver;
-		xperms->specified = AVRULE_XPERMS_IOCTLFUNCTION;
+		xperms->specified = specified;
 		r = r->next;
 	}
 
@@ -2457,13 +2457,13 @@ static int avrule_cpy(avrule_t *dest, const avrule_t *src)
 static int define_te_avtab_ioctl(const avrule_t *avrule_template)
 {
 	avrule_t *avrule;
-	struct av_ioctl_range_list *rangelist, *r;
+	struct av_xperm_range_list *rangelist, *r;
 	av_extended_perms_t *complete_driver, *partial_driver, *xperms;
 	unsigned int i;
 
 
 	/* organize ioctl ranges */
-	if (avrule_ioctl_ranges(&rangelist))
+	if (avrule_xperm_ranges(&rangelist))
 		return -1;
 
 	/* create rule for ioctl driver types that are entirely enabled */
@@ -2482,7 +2482,7 @@ static int define_te_avtab_ioctl(const avrule_t *avrule_template)
 	}
 
 	/* flag ioctl driver codes that are partially enabled */
-	if (avrule_ioctl_partialdriver(rangelist, complete_driver, &partial_driver))
+	if (avrule_xperm_partialdriver(rangelist, complete_driver, &partial_driver))
 		return -1;
 
 	if (!partial_driver || !avrule_xperms_used(partial_driver))
@@ -2495,7 +2495,61 @@ static int define_te_avtab_ioctl(const avrule_t *avrule_template)
 	 */
 	i = 0;
 	while (xperms_for_each_bit(&i, partial_driver)) {
-		if (avrule_ioctl_func(rangelist, &xperms, i))
+		if (avrule_xperm_func(rangelist, &xperms, i, AVRULE_XPERMS_IOCTLFUNCTION))
+			return -1;
+
+		if (xperms) {
+			avrule = (avrule_t *) calloc(1, sizeof(avrule_t));
+			if (!avrule) {
+				yyerror("out of memory");
+				return -1;
+			}
+			if (avrule_cpy(avrule, avrule_template))
+				return -1;
+			avrule->xperms = xperms;
+			append_avrule(avrule);
+		}
+	}
+
+done:
+	if (partial_driver)
+		free(partial_driver);
+
+	while (rangelist != NULL) {
+		r = rangelist;
+		rangelist = rangelist->next;
+		free(r);
+	}
+
+	return 0;
+}
+
+static int define_te_avtab_netlink(const avrule_t *avrule_template)
+{
+	avrule_t *avrule;
+	struct av_xperm_range_list *rangelist, *r;
+	av_extended_perms_t *partial_driver, *xperms;
+	unsigned int i;
+
+	/* organize ranges */
+	if (avrule_xperm_ranges(&rangelist))
+		return -1;
+
+	/* flag driver codes that are partially enabled */
+	if (avrule_xperm_partialdriver(rangelist, NULL, &partial_driver))
+		return -1;
+
+	if (!partial_driver || !avrule_xperms_used(partial_driver))
+		goto done;
+
+	/*
+	 * create rule for each partially used driver codes
+	 * "partially used" meaning that the code number e.g. socket 0x89
+	 * has some permission bits set and others not set.
+	 */
+	i = 0;
+	while (xperms_for_each_bit(&i, partial_driver)) {
+		if (avrule_xperm_func(rangelist, &xperms, i, AVRULE_XPERMS_NLMSG))
 			return -1;
 
 		if (xperms) {
@@ -2546,6 +2600,8 @@ int define_te_avtab_extended_perms(int which)
 	id = queue_remove(id_queue);
 	if (strcmp(id,"ioctl") == 0) {
 		rc = define_te_avtab_ioctl(avrule_template);
+	} else if (strcmp(id,"nlmsg") == 0) {
+		rc = define_te_avtab_netlink(avrule_template);
 	} else {
 		yyerror2("only ioctl extended permissions are supported, found %s", id);
 		rc = -1;
@@ -5036,7 +5092,7 @@ int define_ibpkey_context(unsigned int low, unsigned int high)
 		goto out;
 	}
 
-	if (subnet_prefix.s6_addr[2] || subnet_prefix.s6_addr[3]) {
+	if (subnet_prefix.s6_addr32[2] || subnet_prefix.s6_addr32[3]) {
 		yyerror("subnet prefix should be 0's in the low order 64 bits.");
 		rc = -1;
 		goto out;
diff --git a/checkpolicy/test/dismod.c b/checkpolicy/test/dismod.c
index bd45c95e..4868190f 100644
--- a/checkpolicy/test/dismod.c
+++ b/checkpolicy/test/dismod.c
@@ -353,6 +353,8 @@ static int display_avrule(avrule_t * avrule, policydb_t * policy,
 			xperms.specified = AVTAB_XPERMS_IOCTLFUNCTION;
 		else if (avrule->xperms->specified == AVRULE_XPERMS_IOCTLDRIVER)
 			xperms.specified = AVTAB_XPERMS_IOCTLDRIVER;
+		else if (avrule->xperms->specified == AVRULE_XPERMS_NLMSG)
+			xperms.specified = AVTAB_XPERMS_NLMSG;
 		else {
 			fprintf(fp, "     ERROR: no valid xperms specified\n");
 			return -1;
diff --git a/libselinux/Android.bp b/libselinux/Android.bp
index 05952f81..cc63b565 100644
--- a/libselinux/Android.bp
+++ b/libselinux/Android.bp
@@ -254,6 +254,7 @@ rust_bindgen {
         "//frameworks/native/libs/binder/rust/tests",
         "//system/security/keystore2:__subpackages__",
         "//packages/modules/Virtualization:__subpackages__",
+        "//system/software_defined_vehicle:__subpackages__",
     ],
     source_stem: "bindings",
     local_include_dirs: ["include"],
@@ -270,6 +271,7 @@ rust_bindgen {
         "--allowlist-function=getfilecon",
         "--allowlist-function=getpeercon",
         "--allowlist-function=getpidcon",
+        "--allowlist-function=getprevcon",
         "--allowlist-function=is_selinux_enabled",
         "--allowlist-function=lgetfilecon",
         "--allowlist-function=lsetfilecon",
@@ -311,6 +313,7 @@ rust_bindgen {
         "--allowlist-function=string_to_security_class",
         "--allowlist-function=selinux_android_context_with_level",
         "--allowlist-function=selinux_android_keystore2_key_context_handle",
+        "--allowlist-function=selinux_android_tee_service_context_handle",
 
         // We also need some constants in addition to the functions.
         "--allowlist-var=SELABEL_.*",
diff --git a/libselinux/exported.map.txt b/libselinux/exported.map.txt
index 104d6daa..4cd1961d 100644
--- a/libselinux/exported.map.txt
+++ b/libselinux/exported.map.txt
@@ -54,3 +54,8 @@ LIBSELINUX_S { # introduced=S
     selinux_android_context_with_level; # llndk systemapi
     selinux_android_keystore2_key_context_handle; # llndk systemapi
 };
+
+LIBSELINUX_36 { # introduced=36
+    getprevcon; # systemapi
+    selinux_android_tee_service_context_handle; # systemapi
+};
diff --git a/libselinux/include/selinux/android.h b/libselinux/include/selinux/android.h
index edfd4c2e..8c3d6d45 100644
--- a/libselinux/include/selinux/android.h
+++ b/libselinux/include/selinux/android.h
@@ -26,6 +26,12 @@ extern struct selabel_handle* selinux_android_vendor_service_context_handle(void
 /* Returns the keystore2 context handle */
 extern struct selabel_handle* selinux_android_keystore2_key_context_handle(void);
 
+/* Returns the tee_service context handle.
+ * These handle can be used as a paramter of selabel_lookup function to resolve
+ * the provided trusted execution environment (tee) service to the corresponding
+ * selinux context. */
+extern struct selabel_handle* selinux_android_tee_service_context_handle(void);
+
 /* Sets the file context handle. Must be called using the output of
  * selinux_android_file_context_handle. This function can be used to preload
  * the file_contexts files and speed up later calls to
diff --git a/libselinux/include/selinux/restorecon.h b/libselinux/include/selinux/restorecon.h
index b10fe684..5be6542c 100644
--- a/libselinux/include/selinux/restorecon.h
+++ b/libselinux/include/selinux/restorecon.h
@@ -1,6 +1,8 @@
 #ifndef _RESTORECON_H_
 #define _RESTORECON_H_
 
+#include <selinux/label.h>
+
 #include <sys/types.h>
 #include <stddef.h>
 #include <stdarg.h>
diff --git a/libselinux/include/selinux/selinux.h b/libselinux/include/selinux/selinux.h
index 61c1422b..50419a7c 100644
--- a/libselinux/include/selinux/selinux.h
+++ b/libselinux/include/selinux/selinux.h
@@ -263,9 +263,15 @@ extern int security_compute_member_raw(const char * scon,
  * These interfaces are deprecated.  Use get_ordered_context_list() or
  * one of its variant interfaces instead.
  */
+#ifdef __GNUC__
+__attribute__ ((deprecated))
+#endif
 extern int security_compute_user(const char * scon,
 				 const char *username,
 				 char *** con);
+#ifdef __GNUC__
+__attribute__ ((deprecated))
+#endif
 extern int security_compute_user_raw(const char * scon,
 				     const char *username,
 				     char *** con);
@@ -367,7 +373,11 @@ extern int security_deny_unknown(void);
 /* Get the checkreqprot value */
 extern int security_get_checkreqprot(void);
 
-/* Disable SELinux at runtime (must be done prior to initial policy load). */
+/* Disable SELinux at runtime (must be done prior to initial policy load).
+   Unsupported since Linux 6.4. */
+#ifdef __GNUC__
+__attribute__ ((deprecated))
+#endif
 extern int security_disable(void);
 
 /* Get the policy version number. */
diff --git a/libselinux/man/man3/security_disable.3 b/libselinux/man/man3/security_disable.3
index 072923ce..5ad8b778 100644
--- a/libselinux/man/man3/security_disable.3
+++ b/libselinux/man/man3/security_disable.3
@@ -14,7 +14,8 @@ disables the SELinux kernel code, unregisters selinuxfs from
 and then unmounts
 .IR /sys/fs/selinux .
 .sp
-This function can only be called at runtime and prior to the initial policy
+This function is only supported on Linux 6.3 and earlier, and can only be
+called at runtime and prior to the initial policy
 load. After the initial policy load, the SELinux kernel code cannot be disabled,
 but only placed in "permissive" mode by using
 .BR security_setenforce(3).
diff --git a/libselinux/src/android/android.c b/libselinux/src/android/android.c
index 1b78c8f1..66bec392 100644
--- a/libselinux/src/android/android.c
+++ b/libselinux/src/android/android.c
@@ -88,6 +88,25 @@ static const path_alts_t keystore2_context_paths = { .paths = {
 	}
 }};
 
+static const path_alts_t tee_service_context_paths = { .paths = {
+	{
+		"/system/etc/selinux/plat_tee_service_contexts",
+		"/plat_tee_service_contexts"
+	},
+	{
+		"/system_ext/etc/selinux/system_ext_tee_service_contexts",
+		"/system_ext_tee_service_contexts"
+	},
+	{
+		"/product/etc/selinux/product_tee_service_contexts",
+		"/product_tee_service_contexts"
+	},
+	{
+		"/vendor/etc/selinux/vendor_tee_service_contexts",
+		"/vendor_tee_service_contexts"
+	}
+}};
+
 size_t find_existing_files(
 		const path_alts_t *path_sets,
 		const char* paths[MAX_CONTEXT_PATHS])
@@ -189,6 +208,11 @@ struct selabel_handle* selinux_android_keystore2_key_context_handle(void)
 	return context_handle(SELABEL_CTX_ANDROID_KEYSTORE2_KEY, &keystore2_context_paths, "keystore2");
 }
 
+struct selabel_handle* selinux_android_tee_service_context_handle(void)
+{
+	return context_handle(SELABEL_CTX_ANDROID_SERVICE, &tee_service_context_paths, "tee_service");
+}
+
 /* The contents of these paths are encrypted on FBE devices until user
  * credentials are presented (filenames inside are mangled), so we need
  * to delay restorecon of those until vold explicitly requests it. */
diff --git a/libselinux/src/android/android_seapp.c b/libselinux/src/android/android_seapp.c
index e04dc083..44a90128 100644
--- a/libselinux/src/android/android_seapp.c
+++ b/libselinux/src/android/android_seapp.c
@@ -82,9 +82,10 @@ static const path_alts_t seapp_context_paths = { .paths = {
 	"odm"
 }};
 
-/* Returns a handle for the file contexts backend, initialized with the Android
- * configuration */
-struct selabel_handle* selinux_android_file_context_handle(void)
+static pthread_once_t fc_once = PTHREAD_ONCE_INIT;
+static struct selabel_handle* seapp_fc_sehandle = NULL;
+
+void selinux_android_file_context_handle_init(void)
 {
 	const char* file_contexts[MAX_CONTEXT_PATHS];
 	struct selinux_opt opts[MAX_CONTEXT_PATHS + 1];
@@ -97,7 +98,15 @@ struct selabel_handle* selinux_android_file_context_handle(void)
 	opts[npaths].value = (char *) 1;
 	nopts = npaths + 1;
 
-	return initialize_backend(SELABEL_CTX_FILE, "file", opts, nopts);
+	seapp_fc_sehandle = initialize_backend(SELABEL_CTX_FILE, "file", opts, nopts);
+}
+
+/* Returns a handle for the file contexts backend, initialized with the Android
+ * configuration */
+struct selabel_handle* selinux_android_file_context_handle(void)
+{
+	__selinux_once(fc_once, selinux_android_file_context_handle_init);
+	return seapp_fc_sehandle;
 }
 
 #if DEBUG
diff --git a/libselinux/src/compute_user.c b/libselinux/src/compute_user.c
index f55f945a..d4387aed 100644
--- a/libselinux/src/compute_user.c
+++ b/libselinux/src/compute_user.c
@@ -96,7 +96,9 @@ int security_compute_user(const char * scon,
 	if (selinux_trans_to_raw_context(scon, &rscon))
 		return -1;
 
+	IGNORE_DEPRECATED_DECLARATION_BEGIN
 	ret = security_compute_user_raw(rscon, user, con);
+	IGNORE_DEPRECATED_DECLARATION_END
 
 	freecon(rscon);
 	if (!ret) {
diff --git a/libselinux/src/get_context_list.c b/libselinux/src/get_context_list.c
index 0ad24654..222b54c1 100644
--- a/libselinux/src/get_context_list.c
+++ b/libselinux/src/get_context_list.c
@@ -438,7 +438,7 @@ int get_ordered_context_list(const char *user,
 		__fsetlocking(fp, FSETLOCKING_BYCALLER);
 		rc = get_context_user(fp, con, user, &reachable, &nreachable);
 
-		fclose(fp);
+		fclose_errno_safe(fp);
 		if (rc < 0 && errno != ENOENT) {
 			selinux_log(SELINUX_ERROR,
 				"%s:  error in processing configuration file %s\n",
@@ -451,7 +451,7 @@ int get_ordered_context_list(const char *user,
 	if (fp) {
 		__fsetlocking(fp, FSETLOCKING_BYCALLER);
 		rc = get_context_user(fp, con, user, &reachable, &nreachable);
-		fclose(fp);
+		fclose_errno_safe(fp);
 		if (rc < 0 && errno != ENOENT) {
 			selinux_log(SELINUX_ERROR,
 				"%s:  error in processing configuration file %s\n",
diff --git a/libselinux/src/label_backends_android.c b/libselinux/src/label_backends_android.c
index ca0fd5da..13354cde 100644
--- a/libselinux/src/label_backends_android.c
+++ b/libselinux/src/label_backends_android.c
@@ -299,6 +299,7 @@ static void closef(struct selabel_handle *rec)
 	}
 
 	free(data);
+	rec->data = NULL;
 }
 
 static struct selabel_lookup_rec *property_lookup(struct selabel_handle *rec,
diff --git a/libselinux/src/label_file.c b/libselinux/src/label_file.c
index 0c27e00f..ad9a5429 100644
--- a/libselinux/src/label_file.c
+++ b/libselinux/src/label_file.c
@@ -563,8 +563,10 @@ static FILE *open_file(const char *path, const char *suffix,
 		/* This handles the case if suffix is null */
 		path = rolling_append(stack_path, fdetails[i].suffix,
 				      sizeof(stack_path));
-		if (!path)
+		if (!path) {
+			errno = ENOMEM;
 			return NULL;
+		}
 
 		rc = stat(path, &fdetails[i].sb);
 		if (rc)
@@ -628,7 +630,7 @@ static int process_file(const char *path, const char *suffix,
 
 		rc = fcontext_is_binary(fp);
 		if (rc < 0) {
-			(void) fclose(fp);
+			fclose_errno_safe(fp);
 			return -1;
 		}
 
@@ -639,7 +641,7 @@ static int process_file(const char *path, const char *suffix,
 			rc = digest_add_specfile(digest, fp, NULL, sb.st_size,
 				found_path);
 
-		fclose(fp);
+		fclose_errno_safe(fp);
 
 		if (!rc)
 			return 0;
@@ -982,6 +984,7 @@ static void closef(struct selabel_handle *rec)
 		free(last_area);
 	}
 	free(data);
+	rec->data = NULL;
 }
 
 // Finds all the matches of |key| in the given context. Returns the result in
diff --git a/libselinux/src/label_media.c b/libselinux/src/label_media.c
index 852aeada..d535ef86 100644
--- a/libselinux/src/label_media.c
+++ b/libselinux/src/label_media.c
@@ -30,12 +30,12 @@ struct saved_data {
 	spec_t *spec_arr;
 };
 
-static int process_line(const char *path, char *line_buf, int pass,
+static int process_line(const char *path, const char *line_buf, int pass,
 			unsigned lineno, struct selabel_handle *rec)
 {
 	struct saved_data *data = (struct saved_data *)rec->data;
 	int items;
-	char *buf_p;
+	const char *buf_p;
 	char *key, *context;
 
 	buf_p = line_buf;
@@ -145,7 +145,6 @@ static int init(struct selabel_handle *rec, const struct selinux_opt *opts,
 				goto finish;
 		}
 	}
-	free(line_buf);
 
 	status = digest_add_specfile(rec->digest, fp, NULL, sb.st_size, path);
 	if (status)
@@ -154,6 +153,7 @@ static int init(struct selabel_handle *rec, const struct selinux_opt *opts,
 	digest_gen_hash(rec->digest);
 
 finish:
+	free(line_buf);
 	fclose(fp);
 	return status;
 }
@@ -183,6 +183,7 @@ static void close(struct selabel_handle *rec)
 	    free(spec_arr);
 
 	free(data);
+	rec->data = NULL;
 }
 
 static struct selabel_lookup_rec *lookup(struct selabel_handle *rec,
diff --git a/libselinux/src/label_x.c b/libselinux/src/label_x.c
index a8decc7a..c0d1d475 100644
--- a/libselinux/src/label_x.c
+++ b/libselinux/src/label_x.c
@@ -32,12 +32,12 @@ struct saved_data {
 	spec_t *spec_arr;
 };
 
-static int process_line(const char *path, char *line_buf, int pass,
+static int process_line(const char *path, const char *line_buf, int pass,
 			unsigned lineno, struct selabel_handle *rec)
 {
 	struct saved_data *data = (struct saved_data *)rec->data;
 	int items;
-	char *buf_p;
+	const char *buf_p;
 	char *type, *key, *context;
 
 	buf_p = line_buf;
@@ -172,7 +172,6 @@ static int init(struct selabel_handle *rec, const struct selinux_opt *opts,
 				goto finish;
 		}
 	}
-	free(line_buf);
 
 	status = digest_add_specfile(rec->digest, fp, NULL, sb.st_size, path);
 	if (status)
@@ -181,6 +180,7 @@ static int init(struct selabel_handle *rec, const struct selinux_opt *opts,
 	digest_gen_hash(rec->digest);
 
 finish:
+	free(line_buf);
 	fclose(fp);
 	return status;
 }
@@ -210,6 +210,7 @@ static void close(struct selabel_handle *rec)
 	    free(spec_arr);
 
 	free(data);
+	rec->data = NULL;
 }
 
 static struct selabel_lookup_rec *lookup(struct selabel_handle *rec,
diff --git a/libselinux/src/load_policy.c b/libselinux/src/load_policy.c
index 57d7aaef..dc1e4b6e 100644
--- a/libselinux/src/load_policy.c
+++ b/libselinux/src/load_policy.c
@@ -326,7 +326,9 @@ int selinux_init_load_policy(int *enforce)
 
 	if (seconfig == -1) {
 		/* Runtime disable of SELinux. */
+		IGNORE_DEPRECATED_DECLARATION_BEGIN
 		rc = security_disable();
+		IGNORE_DEPRECATED_DECLARATION_END
 		if (rc == 0) {
 			/* Successfully disabled, so umount selinuxfs too. */
 			umount(selinux_mnt);
diff --git a/libselinux/src/matchpathcon.c b/libselinux/src/matchpathcon.c
index e44734c3..967520e4 100644
--- a/libselinux/src/matchpathcon.c
+++ b/libselinux/src/matchpathcon.c
@@ -524,8 +524,10 @@ int selinux_file_context_verify(const char *path, mode_t mode)
 			return 0;
 	}
 	
-	if (!hnd && (matchpathcon_init_prefix(NULL, NULL) < 0))
+	if (!hnd && (matchpathcon_init_prefix(NULL, NULL) < 0)){
+			freecon(con);
 			return -1;
+	}
 
 	if (selabel_lookup_raw(hnd, &fcontext, path, mode) != 0) {
 		if (errno != ENOENT)
diff --git a/libselinux/src/selinux_internal.h b/libselinux/src/selinux_internal.h
index 0ba7a93d..e4d4b484 100644
--- a/libselinux/src/selinux_internal.h
+++ b/libselinux/src/selinux_internal.h
@@ -2,7 +2,9 @@
 #define SELINUX_INTERNAL_H_
 
 #include <selinux/selinux.h>
+#include <errno.h>
 #include <pthread.h>
+#include <stdio.h>
 
 
 extern int require_seusers ;
@@ -117,4 +119,31 @@ void *reallocarray(void *ptr, size_t nmemb, size_t size);
 #define ignore_unsigned_overflow_
 #endif
 
+/* Ignore usage of deprecated declaration */
+#ifdef __clang__
+#define IGNORE_DEPRECATED_DECLARATION_BEGIN \
+	_Pragma("clang diagnostic push") \
+	_Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")
+#define IGNORE_DEPRECATED_DECLARATION_END \
+	_Pragma("clang diagnostic pop")
+#elif defined __GNUC__
+#define IGNORE_DEPRECATED_DECLARATION_BEGIN \
+	_Pragma("GCC diagnostic push") \
+	_Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
+#define IGNORE_DEPRECATED_DECLARATION_END \
+	_Pragma("GCC diagnostic pop")
+#else
+#define IGNORE_DEPRECATED_DECLARATION_BEGIN
+#define IGNORE_DEPRECATED_DECLARATION_END
+#endif
+
+static inline void fclose_errno_safe(FILE *stream)
+{
+	int saved_errno;
+
+	saved_errno = errno;
+	(void) fclose(stream);
+	errno = saved_errno;
+}
+
 #endif /* SELINUX_INTERNAL_H_ */
diff --git a/libselinux/src/selinux_restorecon.c b/libselinux/src/selinux_restorecon.c
index acb729c8..bc6ed935 100644
--- a/libselinux/src/selinux_restorecon.c
+++ b/libselinux/src/selinux_restorecon.c
@@ -1191,8 +1191,8 @@ static int selinux_restorecon_common(const char *pathname_orig,
 	}
 
 	/* Skip digest on in-memory filesystems and /sys */
-	if (state.sfsb.f_type == RAMFS_MAGIC || state.sfsb.f_type == TMPFS_MAGIC ||
-	    state.sfsb.f_type == SYSFS_MAGIC)
+	if ((uint32_t)state.sfsb.f_type == (uint32_t)RAMFS_MAGIC ||
+		state.sfsb.f_type == TMPFS_MAGIC || state.sfsb.f_type == SYSFS_MAGIC)
 		state.setrestorecondigest = false;
 
 	if (state.flags.set_xdev)
@@ -1490,7 +1490,7 @@ int selinux_restorecon_xattr(const char *pathname, unsigned int xattr_flags,
 
 	if (!recurse) {
 		if (statfs(pathname, &sfsb) == 0) {
-			if (sfsb.f_type == RAMFS_MAGIC ||
+			if ((uint32_t)sfsb.f_type == (uint32_t)RAMFS_MAGIC ||
 			    sfsb.f_type == TMPFS_MAGIC)
 				return 0;
 		}
@@ -1525,7 +1525,7 @@ int selinux_restorecon_xattr(const char *pathname, unsigned int xattr_flags,
 			continue;
 		case FTS_D:
 			if (statfs(ftsent->fts_path, &sfsb) == 0) {
-				if (sfsb.f_type == RAMFS_MAGIC ||
+				if ((uint32_t)sfsb.f_type == (uint32_t)RAMFS_MAGIC ||
 				    sfsb.f_type == TMPFS_MAGIC)
 					continue;
 			}
diff --git a/libselinux/src/selinuxswig_python.i b/libselinux/src/selinuxswig_python.i
index 17e03b9e..03ed296d 100644
--- a/libselinux/src/selinuxswig_python.i
+++ b/libselinux/src/selinuxswig_python.i
@@ -71,7 +71,7 @@ def install(src, dest):
 	for (i = 0; i < *$2; i++) {
 		PyList_SetItem(list, i, PyString_FromString((*$1)[i]));
 	}
-	$result = SWIG_Python_AppendOutput($result, list);
+	$result = SWIG_AppendOutput($result, list);
 }
 
 /* return a sid along with the result */
@@ -108,7 +108,7 @@ def install(src, dest):
 		plist = PyList_New(0);
 	}
 
-	$result = SWIG_Python_AppendOutput($result, plist);
+	$result = SWIG_AppendOutput($result, plist);
 }
 
 /* Makes functions in get_context_list.h return a Python list of contexts */
diff --git a/libselinux/src/setexecfilecon.c b/libselinux/src/setexecfilecon.c
index 2c6505a9..4b31e775 100644
--- a/libselinux/src/setexecfilecon.c
+++ b/libselinux/src/setexecfilecon.c
@@ -40,8 +40,6 @@ int setexecfilecon(const char *filename, const char *fallback_type)
 	}
 
 	rc = setexeccon(newcon);
-	if (rc < 0)
-		goto out;
       out:
 
 	if (rc < 0 && security_getenforce() == 0)
diff --git a/libsemanage/src/compressed_file.c b/libsemanage/src/compressed_file.c
index 5546b830..e230a70b 100644
--- a/libsemanage/src/compressed_file.c
+++ b/libsemanage/src/compressed_file.c
@@ -114,7 +114,12 @@ static ssize_t bunzip(semanage_handle_t *sh, FILE *f, void **data)
 
 	/* Check if the file is bzipped */
 	bzerror = fread(buf, 1, BZ2_MAGICLEN, f);
-	rewind(f);
+
+	if (fseek(f, 0L, SEEK_SET) == -1) {
+		ERR(sh, "Failure rewinding file.");
+		goto exit;
+	}
+
 	if ((bzerror != BZ2_MAGICLEN) || memcmp(buf, BZ2_MAGICSTR, BZ2_MAGICLEN)) {
 		goto exit;
 	}
diff --git a/libsemanage/src/direct_api.c b/libsemanage/src/direct_api.c
index d740070d..7631c7bf 100644
--- a/libsemanage/src/direct_api.c
+++ b/libsemanage/src/direct_api.c
@@ -582,7 +582,7 @@ cleanup:
 static int read_from_pipe_to_data(semanage_handle_t *sh, size_t initial_len, int fd, char **out_data_read, size_t *out_read_len)
 {
 	size_t max_len = initial_len;
-	size_t read_len = 0;
+	ssize_t read_len = 0;
 	size_t data_read_len = 0;
 	char *data_read = NULL;
 
diff --git a/libsemanage/src/semanage_store.c b/libsemanage/src/semanage_store.c
index 27c5d349..0ac2e5b2 100644
--- a/libsemanage/src/semanage_store.c
+++ b/libsemanage/src/semanage_store.c
@@ -36,6 +36,7 @@ typedef struct dbase_policydb dbase_t;
 #include "database_policydb.h"
 #include "handle.h"
 
+#include <selinux/restorecon.h>
 #include <selinux/selinux.h>
 #include <sepol/policydb.h>
 #include <sepol/module.h>
@@ -767,6 +768,7 @@ int semanage_copy_file(const char *src, const char *dst, mode_t mode,
 	if (!retval && rename(tmp, dst) == -1)
 		return -1;
 
+	semanage_setfiles(dst);
 out:
 	errno = errsv;
 	return retval;
@@ -819,6 +821,8 @@ static int semanage_copy_dir_flags(const char *src, const char *dst, int flag)
 			goto cleanup;
 		}
 		umask(mask);
+
+		semanage_setfiles(dst);
 	}
 
 	for (i = 0; i < len; i++) {
@@ -837,6 +841,7 @@ static int semanage_copy_dir_flags(const char *src, const char *dst, int flag)
 				goto cleanup;
 			}
 			umask(mask);
+			semanage_setfiles(path2);
 		} else if (S_ISREG(sb.st_mode) && flag == 1) {
 			mask = umask(0077);
 			if (semanage_copy_file(path, path2, sb.st_mode,
@@ -938,6 +943,7 @@ int semanage_mkdir(semanage_handle_t *sh, const char *path)
 
 		}
 		umask(mask);
+		semanage_setfiles(path);
 	}
 	else {
 		/* check that it really is a directory */
@@ -1614,16 +1620,19 @@ static int semanage_validate_and_compile_fcontexts(semanage_handle_t * sh)
 		    semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_FC)) != 0) {
 		goto cleanup;
 	}
+	semanage_setfiles(semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_FC_BIN));
 
 	if (sefcontext_compile(sh,
 		    semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_FC_LOCAL)) != 0) {
 		goto cleanup;
 	}
+	semanage_setfiles(semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_FC_LOCAL_BIN));
 
 	if (sefcontext_compile(sh,
 		    semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_FC_HOMEDIRS)) != 0) {
 		goto cleanup;
 	}
+	semanage_setfiles(semanage_final_path(SEMANAGE_FINAL_TMP, SEMANAGE_FC_HOMEDIRS_BIN));
 
 	status = 0;
 cleanup:
@@ -3018,3 +3027,26 @@ int semanage_nc_sort(semanage_handle_t * sh, const char *buf, size_t buf_len,
 
 	return 0;
 }
+
+/* Make sure the file context and ownership of files in the policy
+ * store does not change */
+void semanage_setfiles(const char *path){
+	struct stat sb;
+	int fd;
+	/* Fix the user and role portions of the context, ignore errors
+	 * since this is not a critical operation */
+	selinux_restorecon(path, SELINUX_RESTORECON_SET_SPECFILE_CTX | SELINUX_RESTORECON_IGNORE_NOENTRY);
+
+	/* Make sure "path" is owned by root */
+	if ((geteuid() != 0 || getegid() != 0) &&
+	    ((fd = open(path, O_RDONLY)) != -1)){
+		/* Skip files with the SUID or SGID bit set -- abuse protection */
+		if ((fstat(fd, &sb) != -1) &&
+		    !(S_ISREG(sb.st_mode) &&
+		      (sb.st_mode & (S_ISUID | S_ISGID))) &&
+		    (fchown(fd, 0, 0) == -1))
+			fprintf(stderr, "Warning! Could not set ownership of %s to root\n", path);
+
+		close(fd);
+	}
+}
diff --git a/libsemanage/src/semanage_store.h b/libsemanage/src/semanage_store.h
index 1fc77da8..e21dadeb 100644
--- a/libsemanage/src/semanage_store.h
+++ b/libsemanage/src/semanage_store.h
@@ -124,6 +124,7 @@ int semanage_get_cil_paths(semanage_handle_t * sh, semanage_module_info_t *modin
 int semanage_get_active_modules(semanage_handle_t *sh,
 			       semanage_module_info_t **modinfo, int *num_modules);
 
+void semanage_setfiles(const char *path);
 
 /* lock file routines */
 int semanage_get_trans_lock(semanage_handle_t * sh);
diff --git a/libsemanage/src/semanageswig_python.i b/libsemanage/src/semanageswig_python.i
index 5f011396..0e27424f 100644
--- a/libsemanage/src/semanageswig_python.i
+++ b/libsemanage/src/semanageswig_python.i
@@ -111,7 +111,7 @@
 }
 
 %typemap(argout) char** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_FromCharPtr(*$1));
+	$result = SWIG_AppendOutput($result, SWIG_FromCharPtr(*$1));
 	free(*$1);
 }
 
@@ -134,7 +134,7 @@
                         	NULL, NULL, &plist) < 0)
 				$result = SWIG_From_int(STATUS_ERR);
 			else
-				$result = SWIG_Python_AppendOutput($result, plist);
+				$result = SWIG_AppendOutput($result, plist);
 		}
 	}
 }
@@ -148,7 +148,7 @@
 }
 
 %typemap(argout) semanage_module_info_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 /** module key typemaps **/
@@ -160,7 +160,7 @@
 }
 
 %typemap(argout) semanage_module_key_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 /** context typemaps **/
@@ -172,7 +172,7 @@
 }
 
 %typemap(argout) semanage_context_t** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 /** boolean typemaps **/
@@ -197,7 +197,7 @@
 				(void (*) (void*)) &semanage_bool_free, &plist) < 0)
 				$result = SWIG_From_int(STATUS_ERR);
 			else
-		   	        $result = SWIG_Python_AppendOutput($result, plist);
+				$result = SWIG_AppendOutput($result, plist);
 		}
 	}
 }
@@ -207,11 +207,11 @@
 }
 
 %typemap(argout) semanage_bool_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(argout) semanage_bool_key_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_bool_key_t **(semanage_bool_key_t *temp=NULL) {
@@ -240,7 +240,7 @@
 				(void (*) (void*)) &semanage_fcontext_free, &plist) < 0)
 				$result = SWIG_From_int(STATUS_ERR);
 			else
-				$result = SWIG_Python_AppendOutput($result, plist);
+				$result = SWIG_AppendOutput($result, plist);
 		}
 	}
 }
@@ -250,11 +250,11 @@
 }
 
 %typemap(argout) semanage_fcontext_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(argout) semanage_fcontext_key_t ** {
-        $result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_fcontext_key_t **(semanage_fcontext_key_t *temp=NULL) {
@@ -284,7 +284,7 @@
 				(void (*) (void*)) &semanage_iface_free, &plist) < 0)
 				$result = SWIG_From_int(STATUS_ERR);
 			else
-				$result = SWIG_Python_AppendOutput($result, plist);
+				$result = SWIG_AppendOutput($result, plist);
 		}
 	}
 }
@@ -294,11 +294,11 @@
 }
 
 %typemap(argout) semanage_iface_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(argout) semanage_iface_key_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_iface_key_t **(semanage_iface_key_t *temp=NULL) {
@@ -328,7 +328,7 @@
 				(void (*) (void*)) &semanage_seuser_free, &plist) < 0)
 				$result = SWIG_From_int(STATUS_ERR);
 			else
-				$result = SWIG_Python_AppendOutput($result, plist);
+				$result = SWIG_AppendOutput($result, plist);
 		}
 	}
 }
@@ -338,11 +338,11 @@
 }
 
 %typemap(argout) semanage_seuser_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(argout) semanage_seuser_key_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_seuser_key_t **(semanage_seuser_key_t *temp=NULL) {
@@ -371,7 +371,7 @@
 				(void (*) (void*)) &semanage_user_free, &plist) < 0)
 				$result = SWIG_From_int(STATUS_ERR);
 			else
-				$result = SWIG_Python_AppendOutput($result, plist);
+				$result = SWIG_AppendOutput($result, plist);
 		}
 	}
 }
@@ -381,11 +381,11 @@
 }
 
 %typemap(argout) semanage_user_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(argout) semanage_user_key_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_user_key_t **(semanage_user_key_t *temp=NULL) {
@@ -414,7 +414,7 @@
 				(void (*) (void*)) &semanage_port_free, &plist) < 0)
 				$result = SWIG_From_int(STATUS_ERR);
 			else
-				$result = SWIG_Python_AppendOutput($result, plist);
+				$result = SWIG_AppendOutput($result, plist);
 		}
 	}
 }
@@ -424,11 +424,11 @@
 }
 
 %typemap(argout) semanage_port_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(argout) semanage_port_key_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_port_key_t **(semanage_port_key_t *temp=NULL) {
@@ -457,7 +457,7 @@
 				(void (*) (void*)) &semanage_ibpkey_free, &plist) < 0)
 				$result = SWIG_From_int(STATUS_ERR);
 			else
-				$result = SWIG_Python_AppendOutput($result, plist);
+				$result = SWIG_AppendOutput($result, plist);
 		}
 	}
 }
@@ -467,11 +467,11 @@
 }
 
 %typemap(argout) semanage_ibpkey_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(argout) semanage_ibpkey_key_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_ibpkey_key_t **(semanage_ibpkey_key_t *temp=NULL) {
@@ -500,7 +500,7 @@
 				(void (*) (void*)) &semanage_ibendport_free, &plist) < 0)
 				$result = SWIG_From_int(STATUS_ERR);
 			else
-				$result = SWIG_Python_AppendOutput($result, plist);
+				$result = SWIG_AppendOutput($result, plist);
 		}
 	}
 }
@@ -510,11 +510,11 @@
 }
 
 %typemap(argout) semanage_ibendport_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(argout) semanage_ibendport_key_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_ibendport_key_t **(semanage_ibendport_key_t *temp=NULL) {
@@ -543,7 +543,7 @@
 				(void (*) (void*)) &semanage_node_free, &plist) < 0)
 				$result = SWIG_From_int(STATUS_ERR);
 			else
-				$result = SWIG_Python_AppendOutput($result, plist);
+				$result = SWIG_AppendOutput($result, plist);
 		}
 	}
 }
@@ -553,12 +553,12 @@
 }
 
 %typemap(argout) semanage_node_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 
 %typemap(argout) semanage_node_key_t ** {
-	$result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+	$result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_node_key_t **(semanage_node_key_t *temp=NULL) {
diff --git a/libsemanage/src/semanageswig_ruby.i b/libsemanage/src/semanageswig_ruby.i
index e030e4ae..9010b545 100644
--- a/libsemanage/src/semanageswig_ruby.i
+++ b/libsemanage/src/semanageswig_ruby.i
@@ -38,7 +38,7 @@
 }
 
 %typemap(argout) semanage_module_info_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 /** context typemaps **/
@@ -50,7 +50,7 @@
 }
 
 %typemap(argout) semanage_context_t** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 /** boolean typemaps **/
@@ -66,11 +66,11 @@
 }
 
 %typemap(argout) semanage_bool_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(argout) semanage_bool_key_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_bool_key_t **(semanage_bool_key_t *temp=NULL) {
@@ -90,11 +90,11 @@
 }
 
 %typemap(argout) semanage_fcontext_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(argout) semanage_fcontext_key_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_fcontext_key_t **(semanage_fcontext_key_t *temp=NULL) {
@@ -114,11 +114,11 @@
 }
 
 %typemap(argout) semanage_iface_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(argout) semanage_iface_key_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_iface_key_t **(semanage_iface_key_t *temp=NULL) {
@@ -138,11 +138,11 @@
 }
 
 %typemap(argout) semanage_seuser_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(argout) semanage_seuser_key_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_seuser_key_t **(semanage_seuser_key_t *temp=NULL) {
@@ -162,11 +162,11 @@
 }
 
 %typemap(argout) semanage_user_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(argout) semanage_user_key_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_user_key_t **(semanage_user_key_t *temp=NULL) {
@@ -186,11 +186,11 @@
 }
 
 %typemap(argout) semanage_port_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(argout) semanage_port_key_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_port_key_t **(semanage_port_key_t *temp=NULL) {
@@ -210,12 +210,12 @@
 }
 
 %typemap(argout) semanage_node_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 
 %typemap(argout) semanage_node_key_t ** {
-        $result = SWIG_Ruby_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
+        $result = SWIG_AppendOutput($result, SWIG_NewPointerObj(*$1, $*1_descriptor, 0));
 }
 
 %typemap(in, numinputs=0) semanage_node_key_t **(semanage_node_key_t *temp=NULL) {
diff --git a/libsepol/cil/src/cil.c b/libsepol/cil/src/cil.c
index 067e28a6..5521c7ea 100644
--- a/libsepol/cil/src/cil.c
+++ b/libsepol/cil/src/cil.c
@@ -221,6 +221,7 @@ char *CIL_KEY_DONTAUDITX;
 char *CIL_KEY_NEVERALLOWX;
 char *CIL_KEY_PERMISSIONX;
 char *CIL_KEY_IOCTL;
+char *CIL_KEY_NLMSG;
 char *CIL_KEY_UNORDERED;
 char *CIL_KEY_SRC_INFO;
 char *CIL_KEY_SRC_CIL;
@@ -393,6 +394,7 @@ static void cil_init_keys(void)
 	CIL_KEY_NEVERALLOWX = cil_strpool_add("neverallowx");
 	CIL_KEY_PERMISSIONX = cil_strpool_add("permissionx");
 	CIL_KEY_IOCTL = cil_strpool_add("ioctl");
+	CIL_KEY_NLMSG = cil_strpool_add("nlmsg");
 	CIL_KEY_UNORDERED = cil_strpool_add("unordered");
 	CIL_KEY_SRC_INFO = cil_strpool_add("<src_info>");
 	CIL_KEY_SRC_CIL = cil_strpool_add("cil");
diff --git a/libsepol/cil/src/cil_binary.c b/libsepol/cil/src/cil_binary.c
index c8144a5a..3d920182 100644
--- a/libsepol/cil/src/cil_binary.c
+++ b/libsepol/cil/src/cil_binary.c
@@ -66,6 +66,7 @@ struct cil_args_binary {
 	int pass;
 	hashtab_t role_trans_table;
 	hashtab_t avrulex_ioctl_table;
+	hashtab_t avrulex_nlmsg_table;
 	void **type_value_to_cil;
 };
 
@@ -974,7 +975,7 @@ static int __cil_insert_type_rule(policydb_t *pdb, uint32_t kind, uint32_t src,
 {
 	int rc = SEPOL_OK;
 	avtab_key_t avtab_key;
-	avtab_datum_t avtab_datum;
+	avtab_datum_t avtab_datum = { .data = res, .xperms = NULL };
 	avtab_ptr_t existing;	
 
 	avtab_key.source_type = src;
@@ -996,8 +997,6 @@ static int __cil_insert_type_rule(policydb_t *pdb, uint32_t kind, uint32_t src,
 		goto exit;
 	}
 
-	avtab_datum.data = res;
-	
 	existing = avtab_search_node(&pdb->te_avtab, &avtab_key);
 	if (existing) {
 		/* Don't add duplicate type rule and warn if they conflict.
@@ -1345,7 +1344,7 @@ static int __cil_insert_avrule(policydb_t *pdb, uint32_t kind, uint32_t src, uin
 {
 	int rc = SEPOL_OK;
 	avtab_key_t avtab_key;
-	avtab_datum_t avtab_datum;
+	avtab_datum_t avtab_datum = { .data = data, .xperms = NULL };
 	avtab_datum_t *avtab_dup = NULL;
 
 	avtab_key.source_type = src;
@@ -1371,7 +1370,6 @@ static int __cil_insert_avrule(policydb_t *pdb, uint32_t kind, uint32_t src, uin
 	if (!cond_node) {
 		avtab_dup = avtab_search(&pdb->te_avtab, &avtab_key);
 		if (!avtab_dup) {
-			avtab_datum.data = data;
 			rc = avtab_insert(&pdb->te_avtab, &avtab_key, &avtab_datum);
 		} else {
 			if (kind == CIL_AVRULE_DONTAUDIT)
@@ -1380,7 +1378,6 @@ static int __cil_insert_avrule(policydb_t *pdb, uint32_t kind, uint32_t src, uin
 				avtab_dup->data |= data;
 		}
 	} else {
-		avtab_datum.data = data;
 		rc = __cil_cond_insert_rule(&pdb->te_cond_avtab, &avtab_key, &avtab_datum, cond_node, cond_flavor);
 	}
 
@@ -1671,11 +1668,22 @@ static void __avrule_xperm_setrangebits(uint16_t low, uint16_t high, struct avta
 	}
 }
 
+static char* __cil_xperm_kind_to_str(uint32_t xperm_kind)
+{
+	switch (xperm_kind) {
+		case CIL_PERMX_KIND_IOCTL:
+			return CIL_KEY_IOCTL;
+		case CIL_PERMX_KIND_NLMSG:
+			return CIL_KEY_NLMSG;
+		default:
+			return (char *) "unknown";
+	}
+}
 
 #define IOC_DRIV(x) (x >> 8)
 #define IOC_FUNC(x) (x & 0xff)
 
-static int __cil_permx_bitmap_to_sepol_xperms_list(ebitmap_t *xperms, struct cil_list **xperms_list)
+static int __cil_permx_bitmap_to_sepol_xperms_list(uint32_t kind, ebitmap_t *xperms, struct cil_list **xperms_list)
 {
 	ebitmap_node_t *node;
 	unsigned int i;
@@ -1705,7 +1713,7 @@ static int __cil_permx_bitmap_to_sepol_xperms_list(ebitmap_t *xperms, struct cil
 		high = i;
 		start_new_range = 1;
 
-		if (IOC_FUNC(low) == 0x00 && IOC_FUNC(high) == 0xff) {
+		if (kind == CIL_PERMX_KIND_IOCTL && IOC_FUNC(low) == 0x00 && IOC_FUNC(high) == 0xff) {
 			if (!complete) {
 				complete = cil_calloc(1, sizeof(*complete));
 				complete->driver = 0x0;
@@ -1722,7 +1730,14 @@ static int __cil_permx_bitmap_to_sepol_xperms_list(ebitmap_t *xperms, struct cil
 			if (!partial) {
 				partial = cil_calloc(1, sizeof(*partial));
 				partial->driver = IOC_DRIV(low);
-				partial->specified = AVTAB_XPERMS_IOCTLFUNCTION;
+				switch (kind) {
+				case CIL_PERMX_KIND_IOCTL:
+					partial->specified = AVTAB_XPERMS_IOCTLFUNCTION;
+					break;
+				case CIL_PERMX_KIND_NLMSG:
+					partial->specified = AVTAB_XPERMS_NLMSG;
+					break;
+				}
 			}
 
 			__avrule_xperm_setrangebits(IOC_FUNC(low), IOC_FUNC(high), partial);
@@ -1740,7 +1755,7 @@ static int __cil_permx_bitmap_to_sepol_xperms_list(ebitmap_t *xperms, struct cil
 	return SEPOL_OK;
 }
 
-static int __cil_avrulex_ioctl_to_policydb(hashtab_key_t k, hashtab_datum_t datum, void *args)
+static int __cil_avrulex_xperm_to_policydb(hashtab_key_t k, hashtab_datum_t datum, uint32_t xperm_kind, void *args)
 {
 	int rc = SEPOL_OK;
 	struct policydb *pdb;
@@ -1750,6 +1765,7 @@ static int __cil_avrulex_ioctl_to_policydb(hashtab_key_t k, hashtab_datum_t datu
 	struct cil_list_item *item;
 	class_datum_t *sepol_obj;
 	uint32_t data = 0;
+	char *kind = NULL;
 
 	avtab_key = (avtab_key_t *)k;
 	pdb = args;
@@ -1759,13 +1775,14 @@ static int __cil_avrulex_ioctl_to_policydb(hashtab_key_t k, hashtab_datum_t datu
 	// setting the data for an extended avtab isn't really necessary because
 	// it is ignored by the kernel. However, neverallow checking requires that
 	// the data value be set, so set it for that to work.
-	rc = __perm_str_to_datum(CIL_KEY_IOCTL, sepol_obj, &data);
+	kind = __cil_xperm_kind_to_str(xperm_kind);
+	rc = __perm_str_to_datum(kind, sepol_obj, &data);
 	if (rc != SEPOL_OK) {
 		goto exit;
 	}
 	avtab_datum.data = data;
 
-	rc = __cil_permx_bitmap_to_sepol_xperms_list(datum, &xperms_list);
+	rc = __cil_permx_bitmap_to_sepol_xperms_list(xperm_kind, datum, &xperms_list);
 	if (rc != SEPOL_OK) {
 		goto exit;
 	}
@@ -1790,7 +1807,15 @@ exit:
 	return rc;
 }
 
-static int __cil_avrulex_ioctl_to_hashtable(hashtab_t h, uint16_t kind, uint32_t src, uint32_t tgt, uint32_t obj, ebitmap_t *xperms)
+static int __cil_avrulex_ioctl_to_policydb(hashtab_key_t k, hashtab_datum_t datum, void *args) {
+	return __cil_avrulex_xperm_to_policydb(k, datum, CIL_PERMX_KIND_IOCTL, args);
+}
+
+static int __cil_avrulex_nlmsg_to_policydb(hashtab_key_t k, hashtab_datum_t datum, void *args) {
+	return __cil_avrulex_xperm_to_policydb(k, datum, CIL_PERMX_KIND_NLMSG, args);
+}
+
+static int __cil_avrulex_xperm_to_hashtable(hashtab_t h, uint16_t kind, uint32_t src, uint32_t tgt, uint32_t obj, ebitmap_t *xperms)
 {
 	uint16_t specified;
 	avtab_key_t *avtab_key;
@@ -1870,7 +1895,11 @@ static int __cil_avrulex_to_hashtable_helper(policydb_t *pdb, uint16_t kind, str
 
 		switch (permx->kind) {
 		case  CIL_PERMX_KIND_IOCTL:
-			rc = __cil_avrulex_ioctl_to_hashtable(args->avrulex_ioctl_table, kind, sepol_src->s.value, sepol_tgt->s.value, sepol_obj->s.value, permx->perms);
+			rc = __cil_avrulex_xperm_to_hashtable(args->avrulex_ioctl_table, kind, sepol_src->s.value, sepol_tgt->s.value, sepol_obj->s.value, permx->perms);
+			if (rc != SEPOL_OK) goto exit;
+			break;
+		case  CIL_PERMX_KIND_NLMSG:
+			rc = __cil_avrulex_xperm_to_hashtable(args->avrulex_nlmsg_table, kind, sepol_src->s.value, sepol_tgt->s.value, sepol_obj->s.value, permx->perms);
 			if (rc != SEPOL_OK) goto exit;
 			break;
 		default:
@@ -2037,7 +2066,7 @@ exit:
 	return rc;
 }
 
-static int __cil_avrulex_ioctl_destroy(hashtab_key_t k, hashtab_datum_t datum, __attribute__((unused)) void *args)
+static int __cil_avrulex_xperm_destroy(hashtab_key_t k, hashtab_datum_t datum, __attribute__((unused)) void *args)
 {
 	free(k);
 	ebitmap_destroy(datum);
@@ -4630,6 +4659,9 @@ static int __cil_permx_to_sepol_class_perms(policydb_t *pdb, struct cil_permissi
 			case CIL_PERMX_KIND_IOCTL:
 				perm_str = CIL_KEY_IOCTL;
 				break;
+			case CIL_PERMX_KIND_NLMSG:
+				perm_str = CIL_KEY_NLMSG;
+				break;
 			default:
 				rc = SEPOL_ERR;
 				goto exit;
@@ -4769,17 +4801,10 @@ static void __cil_print_classperm(struct cil_list *cp_list)
 
 static void __cil_print_permissionx(struct cil_permissionx *px)
 {
-	const char *kind_str = "";
+	const char *kind_str = NULL;
 	char *expr_str;
 
-	switch (px->kind) {
-		case CIL_PERMX_KIND_IOCTL:
-			kind_str = CIL_KEY_IOCTL;
-			break;
-		default:
-			kind_str = "unknown";
-			break;
-	}
+	kind_str = __cil_xperm_kind_to_str(px->kind);
 
 	__cil_expr_to_string(px->expr_str, CIL_PERMISSIONX, &expr_str);
 
@@ -4928,7 +4953,7 @@ static int cil_check_neverallow(const struct cil_db *db, policydb_t *pdb, struct
 			goto exit;
 		}
 
-		rc = __cil_permx_bitmap_to_sepol_xperms_list(cil_rule->perms.x.permx->perms, &xperms);
+		rc = __cil_permx_bitmap_to_sepol_xperms_list(cil_rule->perms.x.permx->kind, cil_rule->perms.x.permx->perms, &xperms);
 		if (rc != SEPOL_OK) {
 			goto exit;
 		}
@@ -5137,6 +5162,7 @@ int cil_binary_create_allocated_pdb(const struct cil_db *db, sepol_policydb_t *p
 	struct cil_list *neverallows = NULL;
 	hashtab_t role_trans_table = NULL;
 	hashtab_t avrulex_ioctl_table = NULL;
+	hashtab_t avrulex_nlmsg_table = NULL;
 	void **type_value_to_cil = NULL;
 	struct cil_class **class_value_to_cil = NULL;
 	struct cil_perm ***perm_value_to_cil = NULL;
@@ -5184,6 +5210,12 @@ int cil_binary_create_allocated_pdb(const struct cil_db *db, sepol_policydb_t *p
 		goto exit;
 	}
 
+	avrulex_nlmsg_table = hashtab_create(avrulex_hash, avrulex_compare, AVRULEX_TABLE_SIZE);
+	if (!avrulex_nlmsg_table) {
+		cil_log(CIL_INFO, "Failure to create hashtab for avrulex\n");
+		goto exit;
+	}
+
 	cil_list_init(&neverallows, CIL_LIST_ITEM);
 
 	extra_args.db = db;
@@ -5191,6 +5223,7 @@ int cil_binary_create_allocated_pdb(const struct cil_db *db, sepol_policydb_t *p
 	extra_args.neverallows = neverallows;
 	extra_args.role_trans_table = role_trans_table;
 	extra_args.avrulex_ioctl_table = avrulex_ioctl_table;
+	extra_args.avrulex_nlmsg_table = avrulex_nlmsg_table;
 	extra_args.type_value_to_cil = type_value_to_cil;
 
 	for (i = 1; i <= 3; i++) {
@@ -5216,6 +5249,11 @@ int cil_binary_create_allocated_pdb(const struct cil_db *db, sepol_policydb_t *p
 				cil_log(CIL_INFO, "Failure creating avrulex rules\n");
 				goto exit;
 			}
+			rc = hashtab_map(avrulex_nlmsg_table, __cil_avrulex_nlmsg_to_policydb, pdb);
+			if (rc != SEPOL_OK) {
+				cil_log(CIL_INFO, "Failure creating avrulex rules\n");
+				goto exit;
+			}
 		}
 	}
 
@@ -5287,8 +5325,10 @@ int cil_binary_create_allocated_pdb(const struct cil_db *db, sepol_policydb_t *p
 
 exit:
 	hashtab_destroy(role_trans_table);
-	hashtab_map(avrulex_ioctl_table, __cil_avrulex_ioctl_destroy, NULL);
+	hashtab_map(avrulex_ioctl_table, __cil_avrulex_xperm_destroy, NULL);
 	hashtab_destroy(avrulex_ioctl_table);
+	hashtab_map(avrulex_nlmsg_table, __cil_avrulex_xperm_destroy, NULL);
+	hashtab_destroy(avrulex_nlmsg_table);
 	free(type_value_to_cil);
 	free(class_value_to_cil);
 	if (perm_value_to_cil != NULL) {
diff --git a/libsepol/cil/src/cil_build_ast.c b/libsepol/cil/src/cil_build_ast.c
index 56dac891..19fbb04e 100644
--- a/libsepol/cil/src/cil_build_ast.c
+++ b/libsepol/cil/src/cil_build_ast.c
@@ -2153,8 +2153,10 @@ static int cil_fill_permissionx(struct cil_tree_node *parse_current, struct cil_
 
 	if (parse_current->data == CIL_KEY_IOCTL) {
 		permx->kind = CIL_PERMX_KIND_IOCTL;
+	} else if (parse_current->data == CIL_KEY_NLMSG) {
+		permx->kind = CIL_PERMX_KIND_NLMSG;
 	} else {
-		cil_log(CIL_ERR, "Unknown permissionx kind, %s. Must be \"ioctl\"\n", (char *)parse_current->data);
+		cil_log(CIL_ERR, "Unknown permissionx kind, %s. Must be \"ioctl\" or \"nlmsg\"\n", (char *)parse_current->data);
 		rc = SEPOL_ERR;
 		goto exit;
 	}
@@ -3174,16 +3176,6 @@ int cil_gen_aliasactual(struct cil_db *db, struct cil_tree_node *parse_current,
 		goto exit;
 	}
 
-	rc = cil_verify_name(db, parse_current->next->data, flavor);
-	if (rc != SEPOL_OK) {
-		goto exit;
-	}
-
-	rc = cil_verify_name(db, parse_current->next->next->data, flavor);
-	if (rc != SEPOL_OK) {
-		goto exit;
-	}
-
 	cil_aliasactual_init(&aliasactual);
 
 	aliasactual->alias_str = parse_current->next->data;
diff --git a/libsepol/cil/src/cil_internal.h b/libsepol/cil/src/cil_internal.h
index 47b67c89..959b31e3 100644
--- a/libsepol/cil/src/cil_internal.h
+++ b/libsepol/cil/src/cil_internal.h
@@ -238,6 +238,7 @@ extern char *CIL_KEY_DONTAUDITX;
 extern char *CIL_KEY_NEVERALLOWX;
 extern char *CIL_KEY_PERMISSIONX;
 extern char *CIL_KEY_IOCTL;
+extern char *CIL_KEY_NLMSG;
 extern char *CIL_KEY_UNORDERED;
 extern char *CIL_KEY_SRC_INFO;
 extern char *CIL_KEY_SRC_CIL;
@@ -636,6 +637,7 @@ struct cil_avrule {
 };
 
 #define CIL_PERMX_KIND_IOCTL 1
+#define CIL_PERMX_KIND_NLMSG 2
 struct cil_permissionx {
 	struct cil_symtab_datum datum;
 	uint32_t kind;
diff --git a/libsepol/cil/src/cil_policy.c b/libsepol/cil/src/cil_policy.c
index e9a8f75d..c497c8ab 100644
--- a/libsepol/cil/src/cil_policy.c
+++ b/libsepol/cil/src/cil_policy.c
@@ -1112,6 +1112,8 @@ static void cil_xperms_to_policy(FILE *out, struct cil_permissionx *permx)
 
 	if (permx->kind == CIL_PERMX_KIND_IOCTL) {
 		kind = "ioctl";
+	} else if (permx->kind == CIL_PERMX_KIND_NLMSG) {
+		kind = "nlmsg";
 	} else {
 		kind = "???";
 	}
diff --git a/libsepol/cil/src/cil_post.c b/libsepol/cil/src/cil_post.c
index ac99997f..d63a5496 100644
--- a/libsepol/cil/src/cil_post.c
+++ b/libsepol/cil/src/cil_post.c
@@ -1315,6 +1315,8 @@ static int __cil_expr_to_bitmap(struct cil_list *expr, ebitmap_t *out, int max,
 	curr = expr->head;
 	flavor = expr->flavor;
 
+	ebitmap_init(&tmp);
+
 	if (curr->flavor == CIL_OP) {
 		enum cil_flavor op = (enum cil_flavor)(uintptr_t)curr->data;
 
diff --git a/libsepol/cil/src/cil_resolve_ast.c b/libsepol/cil/src/cil_resolve_ast.c
index 427a320c..da8863c4 100644
--- a/libsepol/cil/src/cil_resolve_ast.c
+++ b/libsepol/cil/src/cil_resolve_ast.c
@@ -4291,7 +4291,7 @@ int cil_resolve_name_keep_aliases(struct cil_tree_node *ast_node, char *name, en
 	int rc = SEPOL_ERR;
 	struct cil_tree_node *node = NULL;
 
-	if (name == NULL) {
+	if (name == NULL || sym_index >= CIL_SYM_NUM) {
 		cil_log(CIL_ERR, "Invalid call to cil_resolve_name\n");
 		goto exit;
 	}
diff --git a/libsepol/cil/src/cil_verify.c b/libsepol/cil/src/cil_verify.c
index 4ef2cbab..9621a247 100644
--- a/libsepol/cil/src/cil_verify.c
+++ b/libsepol/cil/src/cil_verify.c
@@ -1513,6 +1513,9 @@ static int __cil_verify_permissionx(struct cil_permissionx *permx, struct cil_tr
 		case CIL_PERMX_KIND_IOCTL:
 			kind_str = CIL_KEY_IOCTL;
 			break;
+		case CIL_PERMX_KIND_NLMSG:
+			kind_str = CIL_KEY_NLMSG;
+			break;
 		default:
 			cil_tree_log(node, CIL_ERR, "Invalid permissionx kind (%d)", permx->kind);
 			rc = SEPOL_ERR;
diff --git a/libsepol/cil/src/cil_write_ast.c b/libsepol/cil/src/cil_write_ast.c
index 46bd84db..cd1b6e6c 100644
--- a/libsepol/cil/src/cil_write_ast.c
+++ b/libsepol/cil/src/cil_write_ast.c
@@ -303,7 +303,13 @@ static void write_permx(FILE *out, struct cil_permissionx *permx)
 		fprintf(out, "%s", datum_to_str(DATUM(permx)));
 	} else {
 		fprintf(out, "(");
-		fprintf(out, "%s ", permx->kind == CIL_PERMX_KIND_IOCTL ? "ioctl" : "<?KIND>");
+		if (permx->kind == CIL_PERMX_KIND_IOCTL) {
+			fprintf(out, "ioctl ");
+		} else if (permx->kind == CIL_PERMX_KIND_NLMSG) {
+			fprintf(out, "nlmsg ");
+		} else {
+			fprintf(out, "<?KIND> ");
+		}
 		fprintf(out, "%s ", datum_or_str(DATUM(permx->obj), permx->obj_str));
 		write_expr(out, permx->expr_str);
 		fprintf(out, ")");
@@ -825,7 +831,13 @@ void cil_write_ast_node(FILE *out, struct cil_tree_node *node)
 	case CIL_PERMISSIONX: {
 		struct cil_permissionx *permx = node->data;
 		fprintf(out, "(permissionx %s (", datum_to_str(DATUM(permx)));
-		fprintf(out, "%s ", permx->kind == CIL_PERMX_KIND_IOCTL ? "ioctl" : "<?KIND>");
+		if (permx->kind == CIL_PERMX_KIND_IOCTL) {
+			fprintf(out, "ioctl ");
+		} else if (permx->kind == CIL_PERMX_KIND_NLMSG) {
+			fprintf(out, "nlmsg ");
+		} else {
+			fprintf(out, "<?KIND> ");
+		}
 		fprintf(out, "%s ", datum_or_str(DATUM(permx->obj), permx->obj_str));
 		write_expr(out, permx->expr_str);
 		fprintf(out, "))\n");
diff --git a/libsepol/include/sepol/policydb/avtab.h b/libsepol/include/sepol/policydb/avtab.h
index 2ab99c39..6e154cfe 100644
--- a/libsepol/include/sepol/policydb/avtab.h
+++ b/libsepol/include/sepol/policydb/avtab.h
@@ -74,6 +74,7 @@ typedef struct avtab_extended_perms {
 
 #define AVTAB_XPERMS_IOCTLFUNCTION	0x01
 #define AVTAB_XPERMS_IOCTLDRIVER	0x02
+#define AVTAB_XPERMS_NLMSG	0x03
 	/* extension of the avtab_key specified */
 	uint8_t specified;
 	uint8_t driver;
diff --git a/libsepol/include/sepol/policydb/polcaps.h b/libsepol/include/sepol/policydb/polcaps.h
index 14bcc6cb..1aa9b30a 100644
--- a/libsepol/include/sepol/policydb/polcaps.h
+++ b/libsepol/include/sepol/policydb/polcaps.h
@@ -16,6 +16,7 @@ enum {
 	POLICYDB_CAP_GENFS_SECLABEL_SYMLINKS,
 	POLICYDB_CAP_IOCTL_SKIP_CLOEXEC,
 	POLICYDB_CAP_USERSPACE_INITIAL_CONTEXT,
+	POLICYDB_CAP_NETLINK_XPERM,
 	__POLICYDB_CAP_MAX
 };
 #define POLICYDB_CAP_MAX (__POLICYDB_CAP_MAX - 1)
diff --git a/libsepol/include/sepol/policydb/policydb.h b/libsepol/include/sepol/policydb/policydb.h
index 856faeb7..104a7dc8 100644
--- a/libsepol/include/sepol/policydb/policydb.h
+++ b/libsepol/include/sepol/policydb/policydb.h
@@ -259,6 +259,7 @@ typedef struct class_perm_node {
 typedef struct av_extended_perms {
 #define AVRULE_XPERMS_IOCTLFUNCTION	0x01
 #define AVRULE_XPERMS_IOCTLDRIVER	0x02
+#define AVRULE_XPERMS_NLMSG	0x03
 	uint8_t specified;
 	uint8_t driver;
 	/* 256 bits of permissions */
diff --git a/libsepol/src/assertion.c b/libsepol/src/assertion.c
index 3076babe..5e129883 100644
--- a/libsepol/src/assertion.c
+++ b/libsepol/src/assertion.c
@@ -110,6 +110,10 @@ static int check_extended_permissions(av_extended_perms_t *neverallow, avtab_ext
 	} else if ((neverallow->specified == AVRULE_XPERMS_IOCTLDRIVER)
 			&& (allow->specified == AVTAB_XPERMS_IOCTLDRIVER)) {
 		rc = extended_permissions_and(neverallow->perms, allow->perms);
+	} else if ((neverallow->specified == AVRULE_XPERMS_NLMSG)
+			&& (allow->specified == AVTAB_XPERMS_NLMSG)) {
+		if (neverallow->driver == allow->driver)
+			rc = extended_permissions_and(neverallow->perms, allow->perms);
 	}
 
 	return rc;
@@ -142,6 +146,12 @@ static void extended_permissions_violated(avtab_extended_perms_t *result,
 		result->specified = AVTAB_XPERMS_IOCTLDRIVER;
 		for (i = 0; i < EXTENDED_PERMS_LEN; i++)
 			result->perms[i] = neverallow->perms[i] & allow->perms[i];
+	} else if ((neverallow->specified == AVRULE_XPERMS_NLMSG)
+			&& (allow->specified == AVTAB_XPERMS_NLMSG)) {
+		result->specified = AVTAB_XPERMS_NLMSG;
+		result->driver = allow->driver;
+		for (i = 0; i < EXTENDED_PERMS_LEN; i++)
+			result->perms[i] = neverallow->perms[i] & allow->perms[i];
 	}
 }
 
@@ -176,7 +186,8 @@ static int report_assertion_extended_permissions(sepol_handle_t *handle,
 			     node = avtab_search_node_next(node, tmp_key.specified)) {
 				xperms = node->datum.xperms;
 				if ((xperms->specified != AVTAB_XPERMS_IOCTLFUNCTION)
-						&& (xperms->specified != AVTAB_XPERMS_IOCTLDRIVER))
+						&& (xperms->specified != AVTAB_XPERMS_IOCTLDRIVER)
+						&& (xperms->specified != AVTAB_XPERMS_NLMSG))
 					continue;
 				found_xperm = 1;
 				rc = check_extended_permissions(avrule->xperms, xperms);
@@ -376,7 +387,8 @@ static int check_assertion_extended_permissions_avtab(avrule_t *avrule, avtab_t
 				xperms = node->datum.xperms;
 
 				if ((xperms->specified != AVTAB_XPERMS_IOCTLFUNCTION)
-						&& (xperms->specified != AVTAB_XPERMS_IOCTLDRIVER))
+						&& (xperms->specified != AVTAB_XPERMS_IOCTLDRIVER)
+						&& (xperms->specified != AVTAB_XPERMS_NLMSG))
 					continue;
 				rc = check_extended_permissions(neverallow_xperms, xperms);
 				if (rc)
diff --git a/libsepol/src/expand.c b/libsepol/src/expand.c
index e63414b1..7032a83f 100644
--- a/libsepol/src/expand.c
+++ b/libsepol/src/expand.c
@@ -1821,6 +1821,9 @@ static int allocate_xperms(sepol_handle_t * handle, avtab_datum_t * avdatump,
 	case AVRULE_XPERMS_IOCTLDRIVER:
 		xperms->specified = AVTAB_XPERMS_IOCTLDRIVER;
 		break;
+	case AVRULE_XPERMS_NLMSG:
+		xperms->specified = AVTAB_XPERMS_NLMSG;
+		break;
 	default:
 		return -1;
 	}
diff --git a/libsepol/src/kernel_to_cil.c b/libsepol/src/kernel_to_cil.c
index f94cb245..2d563e7d 100644
--- a/libsepol/src/kernel_to_cil.c
+++ b/libsepol/src/kernel_to_cil.c
@@ -1436,7 +1436,7 @@ static int map_type_aliases_to_strs(char *key, void *data, void *args)
 static int write_type_alias_rules_to_cil(FILE *out, struct policydb *pdb)
 {
 	type_datum_t *alias;
-	struct strs *strs;
+	struct strs *strs = NULL;
 	char *name;
 	char *type;
 	unsigned i, num = 0;
@@ -1651,7 +1651,8 @@ static char *xperms_to_str(const avtab_extended_perms_t *xperms)
 	size_t remaining, size = 128;
 
 	if ((xperms->specified != AVTAB_XPERMS_IOCTLFUNCTION)
-		&& (xperms->specified != AVTAB_XPERMS_IOCTLDRIVER)) {
+		&& (xperms->specified != AVTAB_XPERMS_IOCTLDRIVER)
+		&& (xperms->specified != AVTAB_XPERMS_NLMSG)) {
 		return NULL;
 	}
 
@@ -1681,7 +1682,8 @@ retry:
 			continue;
 		}
 
-		if (xperms->specified & AVTAB_XPERMS_IOCTLFUNCTION) {
+		if ((xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION)
+		 || (xperms->specified == AVTAB_XPERMS_NLMSG)) {
 			value = xperms->driver<<8 | bit;
 			if (in_range) {
 				low_value = xperms->driver<<8 | low_bit;
@@ -1690,7 +1692,7 @@ retry:
 			} else {
 				len = snprintf(p, remaining, " 0x%hx", value);
 			}
-		} else if (xperms->specified & AVTAB_XPERMS_IOCTLDRIVER) {
+		} else if (xperms->specified == AVTAB_XPERMS_IOCTLDRIVER) {
 			value = bit << 8;
 			if (in_range) {
 				low_value = low_bit << 8;
@@ -1728,7 +1730,7 @@ static char *avtab_node_to_str(struct policydb *pdb, avtab_key_t *key, avtab_dat
 	uint32_t data = datum->data;
 	type_datum_t *type;
 	const char *flavor, *tgt;
-	char *src, *class, *perms, *new;
+	char *src, *class, *perms, *new, *xperm;
 	char *rule = NULL;
 
 	switch (0xFFF & key->specified) {
@@ -1795,9 +1797,16 @@ static char *avtab_node_to_str(struct policydb *pdb, avtab_key_t *key, avtab_dat
 			ERR(NULL, "Failed to generate extended permission string");
 			goto exit;
 		}
-
+		if (datum->xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION || datum->xperms->specified == AVTAB_XPERMS_IOCTLDRIVER) {
+			xperm = (char *) "ioctl";
+		} else if (datum->xperms->specified == AVTAB_XPERMS_NLMSG) {
+			xperm = (char *) "nlmsg";
+		} else {
+			ERR(NULL, "Unknown extended permssion");
+			goto exit;
+		}
 		rule = create_str("(%s %s %s (%s %s (%s)))",
-				  flavor, src, tgt, "ioctl", class, perms);
+				  flavor, src, tgt, xperm, class, perms);
 		free(perms);
 	} else {
 		new = pdb->p_type_val_to_name[data - 1];
diff --git a/libsepol/src/kernel_to_conf.c b/libsepol/src/kernel_to_conf.c
index ca91ffae..661546af 100644
--- a/libsepol/src/kernel_to_conf.c
+++ b/libsepol/src/kernel_to_conf.c
@@ -1419,7 +1419,7 @@ static int map_type_aliases_to_strs(char *key, void *data, void *args)
 static int write_type_alias_rules_to_conf(FILE *out, struct policydb *pdb)
 {
 	type_datum_t *alias;
-	struct strs *strs;
+	struct strs *strs = NULL;
 	char *name;
 	char *type;
 	unsigned i, num = 0;
diff --git a/libsepol/src/mls.c b/libsepol/src/mls.c
index 45db8920..a37405d1 100644
--- a/libsepol/src/mls.c
+++ b/libsepol/src/mls.c
@@ -672,8 +672,10 @@ int sepol_mls_contains(sepol_handle_t * handle,
 	context_struct_t *ctx1 = NULL, *ctx2 = NULL;
 	ctx1 = malloc(sizeof(context_struct_t));
 	ctx2 = malloc(sizeof(context_struct_t));
-	if (ctx1 == NULL || ctx2 == NULL)
+	if (ctx1 == NULL || ctx2 == NULL){
+		ERR(handle, "out of memory");
 		goto omem;
+	}
 	context_init(ctx1);
 	context_init(ctx2);
 
@@ -690,16 +692,14 @@ int sepol_mls_contains(sepol_handle_t * handle,
 	free(ctx2);
 	return STATUS_SUCCESS;
 
-      omem:
-	ERR(handle, "out of memory");
-
       err:
-	ERR(handle, "could not check if mls context %s contains %s",
-	    mls1, mls2);
 	context_destroy(ctx1);
 	context_destroy(ctx2);
+      omem:
 	free(ctx1);
 	free(ctx2);
+	ERR(handle, "could not check if mls context %s contains %s",
+	    mls1, mls2);
 	return STATUS_ERR;
 }
 
diff --git a/libsepol/src/module_to_cil.c b/libsepol/src/module_to_cil.c
index 2dbf137e..79636897 100644
--- a/libsepol/src/module_to_cil.c
+++ b/libsepol/src/module_to_cil.c
@@ -630,7 +630,8 @@ static int xperms_to_cil(const av_extended_perms_t *xperms)
 	int first = 1;
 
 	if ((xperms->specified != AVTAB_XPERMS_IOCTLFUNCTION)
-		&& (xperms->specified != AVTAB_XPERMS_IOCTLDRIVER))
+		&& (xperms->specified != AVTAB_XPERMS_IOCTLDRIVER)
+		&& (xperms->specified != AVTAB_XPERMS_NLMSG))
 		return -1;
 
 	for (bit = 0; bit < sizeof(xperms->perms)*8; bit++) {
@@ -652,7 +653,8 @@ static int xperms_to_cil(const av_extended_perms_t *xperms)
 		else
 			first = 0;
 
-		if (xperms->specified & AVTAB_XPERMS_IOCTLFUNCTION) {
+		if ((xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION)
+		 || (xperms->specified == AVTAB_XPERMS_NLMSG)) {
 			value = xperms->driver<<8 | bit;
 			if (in_range) {
 				low_value = xperms->driver<<8 | low_bit;
@@ -661,7 +663,7 @@ static int xperms_to_cil(const av_extended_perms_t *xperms)
 			} else {
 				cil_printf("0x%hx", value);
 			}
-		} else if (xperms->specified & AVTAB_XPERMS_IOCTLDRIVER) {
+		} else if (xperms->specified == AVTAB_XPERMS_IOCTLDRIVER) {
 			value = bit << 8;
 			if (in_range) {
 				low_value = low_bit << 8;
@@ -680,6 +682,7 @@ static int avrulex_to_cil(int indent, struct policydb *pdb, uint32_t type, const
 {
 	int rc = -1;
 	const char *rule;
+	const char *xperm;
 	const struct class_perm_node *classperm;
 
 	switch (type) {
@@ -701,10 +704,19 @@ static int avrulex_to_cil(int indent, struct policydb *pdb, uint32_t type, const
 		goto exit;
 	}
 
+	if (xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION || xperms->specified == AVTAB_XPERMS_IOCTLDRIVER) {
+		xperm = "ioctl";
+	} else if (xperms->specified == AVTAB_XPERMS_NLMSG) {
+		xperm = "nlmsg";
+	} else {
+		ERR(NULL, "Unkown avrule xperms->specified: %i", xperms->specified);
+		rc = -1;
+		goto exit;
+	}
 	for (classperm = classperms; classperm != NULL; classperm = classperm->next) {
 		cil_indent(indent);
 		cil_printf("(%s %s %s (%s %s (", rule, src, tgt,
-			   "ioctl", pdb->p_class_val_to_name[classperm->tclass - 1]);
+			   xperm, pdb->p_class_val_to_name[classperm->tclass - 1]);
 		xperms_to_cil(xperms);
 		cil_printf(")))\n");
 	}
diff --git a/libsepol/src/optimize.c b/libsepol/src/optimize.c
index a38025ec..8a0b70fe 100644
--- a/libsepol/src/optimize.c
+++ b/libsepol/src/optimize.c
@@ -189,6 +189,11 @@ static int process_avtab_datum(uint16_t specified,
 
 			if (x2->specified == AVTAB_XPERMS_IOCTLDRIVER)
 				return process_xperms(x1->perms, x2->perms);
+		} else if (x1->specified == AVTAB_XPERMS_NLMSG
+				&& x2->specified == AVTAB_XPERMS_NLMSG) {
+			if (x1->driver != x2->driver)
+				return 0;
+			return process_xperms(x1->perms, x2->perms);
 		}
 		return 0;
 	}
diff --git a/libsepol/src/polcaps.c b/libsepol/src/polcaps.c
index 8289443a..6b28c84e 100644
--- a/libsepol/src/polcaps.c
+++ b/libsepol/src/polcaps.c
@@ -15,6 +15,7 @@ static const char * const polcap_names[POLICYDB_CAP_MAX + 1] = {
 	[POLICYDB_CAP_GENFS_SECLABEL_SYMLINKS]		= "genfs_seclabel_symlinks",
 	[POLICYDB_CAP_IOCTL_SKIP_CLOEXEC]		= "ioctl_skip_cloexec",
 	[POLICYDB_CAP_USERSPACE_INITIAL_CONTEXT]	= "userspace_initial_context",
+	[POLICYDB_CAP_NETLINK_XPERM]			= "netlink_xperm",
 };
 
 int sepol_polcap_getnum(const char *name)
diff --git a/libsepol/src/policydb_validate.c b/libsepol/src/policydb_validate.c
index 121fd46c..5035313b 100644
--- a/libsepol/src/policydb_validate.c
+++ b/libsepol/src/policydb_validate.c
@@ -921,6 +921,7 @@ static int validate_xperms(const avtab_extended_perms_t *xperms)
 	switch (xperms->specified) {
 	case AVTAB_XPERMS_IOCTLDRIVER:
 	case AVTAB_XPERMS_IOCTLFUNCTION:
+	case AVTAB_XPERMS_NLMSG:
 		break;
 	default:
 		goto bad;
@@ -1067,6 +1068,7 @@ static int validate_avrules(sepol_handle_t *handle, const avrule_t *avrule, int
 			switch (avrule->xperms->specified) {
 			case AVRULE_XPERMS_IOCTLFUNCTION:
 			case AVRULE_XPERMS_IOCTLDRIVER:
+			case AVRULE_XPERMS_NLMSG:
 				break;
 			default:
 				goto bad;
diff --git a/libsepol/src/services.c b/libsepol/src/services.c
index 36e2368f..f3231f17 100644
--- a/libsepol/src/services.c
+++ b/libsepol/src/services.c
@@ -1362,14 +1362,12 @@ static int sepol_compute_sid(sepol_security_id_t ssid,
 	scontext = sepol_sidtab_search(sidtab, ssid);
 	if (!scontext) {
 		ERR(NULL, "unrecognized SID %d", ssid);
-		rc = -EINVAL;
-		goto out;
+		return -EINVAL;
 	}
 	tcontext = sepol_sidtab_search(sidtab, tsid);
 	if (!tcontext) {
 		ERR(NULL, "unrecognized SID %d", tsid);
-		rc = -EINVAL;
-		goto out;
+		return -EINVAL;
 	}
 
 	if (tclass && tclass <= policydb->p_classes.nprim)
diff --git a/libsepol/src/util.c b/libsepol/src/util.c
index b1eb9b38..a4befbd9 100644
--- a/libsepol/src/util.c
+++ b/libsepol/src/util.c
@@ -146,7 +146,8 @@ char *sepol_extended_perms_to_string(const avtab_extended_perms_t *xperms)
 	size_t remaining, size = 128;
 
 	if ((xperms->specified != AVTAB_XPERMS_IOCTLFUNCTION)
-		&& (xperms->specified != AVTAB_XPERMS_IOCTLDRIVER))
+		&& (xperms->specified != AVTAB_XPERMS_IOCTLDRIVER)
+		&& (xperms->specified != AVTAB_XPERMS_NLMSG))
 		return NULL;
 
 retry:
@@ -158,7 +159,12 @@ retry:
 	buffer = p;
 	remaining = size;
 
-	len = snprintf(p, remaining, "ioctl { ");
+	if ((xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION)
+		|| (xperms->specified == AVTAB_XPERMS_IOCTLDRIVER)) {
+		len = snprintf(p, remaining, "ioctl { ");
+	} else {
+		len = snprintf(p, remaining, "nlmsg { ");
+	}
 	if (len < 0 || (size_t)len >= remaining)
 		goto err;
 	p += len;
@@ -179,7 +185,7 @@ retry:
 			continue;
 		}
 
-		if (xperms->specified & AVTAB_XPERMS_IOCTLFUNCTION) {
+		if (xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION || xperms->specified == AVTAB_XPERMS_NLMSG) {
 			value = xperms->driver<<8 | bit;
 			if (in_range) {
 				low_value = xperms->driver<<8 | low_bit;
@@ -187,7 +193,7 @@ retry:
 			} else {
 				len = snprintf(p, remaining, "0x%hx ", value);
 			}
-		} else if (xperms->specified & AVTAB_XPERMS_IOCTLDRIVER) {
+		} else if (xperms->specified == AVTAB_XPERMS_IOCTLDRIVER) {
 			value = bit << 8;
 			if (in_range) {
 				low_value = low_bit << 8;
diff --git a/python/sepolgen/src/sepolgen/policygen.py b/python/sepolgen/src/sepolgen/policygen.py
index 5d59dad7..7715bed5 100644
--- a/python/sepolgen/src/sepolgen/policygen.py
+++ b/python/sepolgen/src/sepolgen/policygen.py
@@ -179,7 +179,9 @@ class PolicyGenerator:
             rule.rule_type = rule.DONTAUDIT
         rule.comment = ""
         if self.explain:
-            rule.comment = str(refpolicy.Comment(explain_access(av, verbosity=self.explain)))
+            comment = refpolicy.Comment(explain_access(av, verbosity=self.explain))
+            comment.set_gen_cil(self.gen_cil)
+            rule.comment = str(comment)
 
         if av.type == audit2why.ALLOW:
             rule.comment += "\n%s!!!! This avc is allowed in the current policy" % self.comment_start
diff --git a/python/sepolgen/src/sepolgen/refpolicy.py b/python/sepolgen/src/sepolgen/refpolicy.py
index 2ec75fba..32278896 100644
--- a/python/sepolgen/src/sepolgen/refpolicy.py
+++ b/python/sepolgen/src/sepolgen/refpolicy.py
@@ -1217,6 +1217,7 @@ class Comment:
             self.lines = l
         else:
             self.lines = []
+        self.gen_cil = False
 
     def to_string(self):
         # If there are no lines, treat this as a spacer between
```

