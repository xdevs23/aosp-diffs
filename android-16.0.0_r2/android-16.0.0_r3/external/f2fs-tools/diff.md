```diff
diff --git a/Android.bp b/Android.bp
index 0d758fd..082fa8e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -294,11 +294,19 @@ cc_binary {
         "fsck.f2fs_partition_common_defaults",
     ],
     host_supported: true,
-    vendor_available: true,
     vendor_ramdisk_available: true,
     bootstrap: true,
 }
 
+cc_binary {
+    name: "fsck.f2fs.vendor",
+    defaults: [
+        "fsck.f2fs_partition_common_defaults",
+    ],
+    vendor: true,
+    stem: "fsck.f2fs",
+}
+
 cc_binary {
     name: "fsck.f2fs.recovery",
     defaults: [
diff --git a/METADATA b/METADATA
index 413e3d7..964561a 100644
--- a/METADATA
+++ b/METADATA
@@ -8,13 +8,13 @@ third_party {
   license_type: RESTRICTED
   last_upgrade_date {
     year: 2025
-    month: 3
-    day: 20
+    month: 5
+    day: 7
   }
   homepage: "https://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/f2fs-tools.git/"
   identifier {
     type: "Git"
     value: "https://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/f2fs-tools.git"
-    version: "33c5b9539af24468b4eb9493f7a9eb2ab7e98b64"
+    version: "d8eac1f8699541416afdf93333772ef2e0509773"
   }
 }
diff --git a/fsck/dump.c b/fsck/dump.c
index dc3c199..66d6c79 100644
--- a/fsck/dump.c
+++ b/fsck/dump.c
@@ -937,7 +937,7 @@ static void dump_dirent(u32 blk_addr, int is_inline, int enc_name)
 {
 	struct f2fs_dentry_ptr d;
 	void *inline_dentry, *blk;
-	int ret, i = 0;
+	int ret, i = 0, j;
 
 	blk = calloc(F2FS_BLKSIZE, 1);
 	ASSERT(blk);
@@ -992,6 +992,11 @@ static void dump_dirent(u32 blk_addr, int is_inline, int enc_name)
 				le32_to_cpu(de->ino),
 				de->file_type);
 
+		DBG(1, "%s", "name(hex)[");
+		for (j = 0; j < F2FS_NAME_LEN && en[j]; j++)
+			MSG(1, "0x%x ", (unsigned char)en[j]);
+		MSG(1, "0x%x]\n", (unsigned char)en[j]);
+
 		i += GET_DENTRY_SLOTS(name_len);
 	}
 
diff --git a/fsck/fsck.c b/fsck/fsck.c
index 8155cbd..893eea7 100644
--- a/fsck/fsck.c
+++ b/fsck/fsck.c
@@ -16,6 +16,20 @@
 char *tree_mark;
 uint32_t tree_mark_size = 256;
 
+const char *f2fs_fault_name[FAULT_MAX] = {
+	[FAULT_SEG_TYPE]	= "FAULT_SEG_TYPE",
+	[FAULT_SUM_TYPE]	= "FAULT_SUM_TYPE",
+	[FAULT_SUM_ENT]		= "FAULT_SUM_ENTRY",
+	[FAULT_NAT]		= "FAULT_NAT_ENTRY",
+	[FAULT_NODE]		= "FAULT_NODE_BLOCK",
+	[FAULT_XATTR_ENT]	= "FAULT_XATTR_ENTRY",
+	[FAULT_COMPR]		= "FAULT_COMPR_TYPE",
+	[FAULT_INODE]		= "FAULT_INODE_ENTRY",
+	[FAULT_DENTRY]		= "FAULT_DENTRY_BLOCK",
+	[FAULT_DATA]		= "FAULT_DATA_BLOCK",
+	[FAULT_QUOTA]		= "FAULT_QUOTA",
+};
+
 int f2fs_set_main_bitmap(struct f2fs_sb_info *sbi, u32 blk, int type)
 {
 	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
@@ -23,9 +37,9 @@ int f2fs_set_main_bitmap(struct f2fs_sb_info *sbi, u32 blk, int type)
 	int fix = 0;
 
 	se = get_seg_entry(sbi, GET_SEGNO(sbi, blk));
-	if (se->type >= NO_CHECK_TYPE)
-		fix = 1;
-	else if (IS_DATASEG(se->type) != IS_DATASEG(type))
+	if (time_to_inject(FAULT_SEG_TYPE) ||
+			(se->type >= NO_CHECK_TYPE) ||
+			(IS_DATASEG(se->type) != IS_DATASEG(type)))
 		fix = 1;
 
 	/* just check data and node types */
@@ -168,7 +182,8 @@ static int is_valid_ssa_node_blk(struct f2fs_sb_info *sbi, u32 nid,
 
 	sum_blk = get_sum_block(sbi, segno, &type);
 
-	if (type != SEG_TYPE_NODE && type != SEG_TYPE_CUR_NODE) {
+	if (time_to_inject(FAULT_SUM_TYPE) ||
+			(type != SEG_TYPE_NODE && type != SEG_TYPE_CUR_NODE)) {
 		/* can't fix current summary, then drop the block */
 		if (!c.fix_on || type < 0) {
 			ASSERT_MSG("Summary footer is not for node segment");
@@ -189,7 +204,8 @@ static int is_valid_ssa_node_blk(struct f2fs_sb_info *sbi, u32 nid,
 
 	sum_entry = &(sum_blk->entries[offset]);
 
-	if (le32_to_cpu(sum_entry->nid) != nid) {
+	if (time_to_inject(FAULT_SUM_ENT) ||
+			(le32_to_cpu(sum_entry->nid) != nid)) {
 		if (!c.fix_on || type < 0) {
 			DBG(0, "nid                       [0x%x]\n", nid);
 			DBG(0, "target blk_addr           [0x%x]\n", blk_addr);
@@ -282,7 +298,7 @@ static int is_valid_ssa_data_blk(struct f2fs_sb_info *sbi, u32 blk_addr,
 	struct f2fs_summary *sum_entry;
 	struct seg_entry * se;
 	u32 segno, offset;
-	int need_fix = 0, ret = 0;
+	int need_fix = 0, ret = 0, fault_sum_ent = 0;
 	int type;
 
 	if (get_sb(feature) & F2FS_FEATURE_RO)
@@ -293,7 +309,8 @@ static int is_valid_ssa_data_blk(struct f2fs_sb_info *sbi, u32 blk_addr,
 
 	sum_blk = get_sum_block(sbi, segno, &type);
 
-	if (type != SEG_TYPE_DATA && type != SEG_TYPE_CUR_DATA) {
+	if (time_to_inject(FAULT_SUM_TYPE) ||
+			(type != SEG_TYPE_DATA && type != SEG_TYPE_CUR_DATA)) {
 		/* can't fix current summary, then drop the block */
 		if (!c.fix_on || type < 0) {
 			ASSERT_MSG("Summary footer is not for data segment");
@@ -314,7 +331,10 @@ static int is_valid_ssa_data_blk(struct f2fs_sb_info *sbi, u32 blk_addr,
 
 	sum_entry = &(sum_blk->entries[offset]);
 
-	if (le32_to_cpu(sum_entry->nid) != parent_nid ||
+	if (time_to_inject(FAULT_SUM_ENT))
+		fault_sum_ent = 1;
+
+	if (fault_sum_ent || le32_to_cpu(sum_entry->nid) != parent_nid ||
 			sum_entry->version != version ||
 			le16_to_cpu(sum_entry->ofs_in_node) != idx_in_node) {
 		if (!c.fix_on || type < 0) {
@@ -333,7 +353,8 @@ static int is_valid_ssa_data_blk(struct f2fs_sb_info *sbi, u32 blk_addr,
 			DBG(0, "Target data block addr    [0x%x]\n", blk_addr);
 			ASSERT_MSG("Invalid data seg summary\n");
 			ret = -EINVAL;
-		} else if (is_valid_summary(sbi, sum_entry, blk_addr)) {
+		} else if (!fault_sum_ent &&
+				is_valid_summary(sbi, sum_entry, blk_addr)) {
 			/* delete wrong index */
 			ret = -EINVAL;
 		} else {
@@ -397,6 +418,11 @@ err:
 static int sanity_check_nat(struct f2fs_sb_info *sbi, u32 nid,
 						struct node_info *ni)
 {
+	if (time_to_inject(FAULT_NAT)) {
+		ASSERT_MSG("%s is injected.", f2fs_fault_name[FAULT_NAT]);
+		return -EINVAL;
+	}
+
 	if (!IS_VALID_NID(sbi, nid)) {
 		ASSERT_MSG("nid is not valid. [0x%x]", nid);
 		return -EINVAL;
@@ -436,6 +462,11 @@ static int sanity_check_nid(struct f2fs_sb_info *sbi, u32 nid,
 	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
 	int ret;
 
+	if (time_to_inject(FAULT_NODE)) {
+		ASSERT_MSG("%s is injected.", f2fs_fault_name[FAULT_NODE]);
+		return -EINVAL;
+	}
+
 	ret = sanity_check_nat(sbi, nid, ni);
 	if (ret)
 		return ret;
@@ -865,7 +896,7 @@ int chk_extended_attributes(struct f2fs_sb_info *sbi, u32 nid,
 				"end of list", nid);
 		need_fix = true;
 	}
-	if (need_fix && c.fix_on) {
+	if ((time_to_inject(FAULT_XATTR_ENT) || need_fix) && c.fix_on) {
 		memset(ent, 0, (u8 *)last_base_addr - (u8 *)ent);
 		write_all_xattrs(sbi, inode, xattr_size, xattr);
 		FIX_MSG("[0x%x] nullify wrong xattr entries", nid);
@@ -907,7 +938,8 @@ void fsck_chk_inode_blk(struct f2fs_sb_info *sbi, u32 nid,
 	if (!compressed)
 		goto check_next;
 
-	if (!compr_supported || (node_blk->i.i_inline & F2FS_INLINE_DATA)) {
+	if (time_to_inject(FAULT_COMPR) || !compr_supported ||
+			(node_blk->i.i_inline & F2FS_INLINE_DATA)) {
 		/*
 		 * The 'compression' flag in i_flags affects the traverse of
 		 * the node tree.  Thus, it must be fixed unconditionally
@@ -943,12 +975,13 @@ check_next:
 			f2fs_set_main_bitmap(sbi, ni->blk_addr,
 							CURSEG_WARM_NODE);
 
-			if (i_links == 0 && (ftype == F2FS_FT_CHRDEV ||
+			if (time_to_inject(FAULT_INODE) ||
+				(i_links == 0 && (ftype == F2FS_FT_CHRDEV ||
 				ftype == F2FS_FT_BLKDEV ||
 				ftype == F2FS_FT_FIFO ||
 				ftype == F2FS_FT_SOCK ||
 				ftype == F2FS_FT_SYMLINK ||
-				ftype == F2FS_FT_REG_FILE)) {
+				ftype == F2FS_FT_REG_FILE))) {
 				ASSERT_MSG("ino: 0x%x ftype: %d has i_links: %u",
 							nid, ftype, i_links);
 				if (c.fix_on) {
@@ -1008,7 +1041,8 @@ check_next:
 		if (c.feature & F2FS_FEATURE_EXTRA_ATTR) {
 			unsigned int isize =
 				le16_to_cpu(node_blk->i.i_extra_isize);
-			if (isize > 4 * DEF_ADDRS_PER_INODE) {
+			if (time_to_inject(FAULT_INODE) ||
+					(isize > 4 * DEF_ADDRS_PER_INODE)) {
 				ASSERT_MSG("[0x%x] wrong i_extra_isize=0x%x",
 						nid, isize);
 				if (c.fix_on) {
@@ -1038,8 +1072,9 @@ check_next:
 			unsigned int inline_size =
 				le16_to_cpu(node_blk->i.i_inline_xattr_size);
 
-			if (!inline_size ||
-					inline_size > MAX_INLINE_XATTR_SIZE) {
+			if (time_to_inject(FAULT_INODE) ||
+					(!inline_size ||
+					inline_size > MAX_INLINE_XATTR_SIZE)) {
 				ASSERT_MSG("[0x%x] wrong inline_xattr_size:%u",
 						nid, inline_size);
 				if (c.fix_on) {
@@ -1056,9 +1091,10 @@ check_next:
 	}
 	ofs = get_extra_isize(node_blk);
 
-	if ((node_blk->i.i_flags & cpu_to_le32(F2FS_CASEFOLD_FL)) &&
-	    (!S_ISDIR(le16_to_cpu(node_blk->i.i_mode)) ||
-	     !(c.feature & F2FS_FEATURE_CASEFOLD))) {
+	if (time_to_inject(FAULT_INODE) ||
+		 ((node_blk->i.i_flags & cpu_to_le32(F2FS_CASEFOLD_FL)) &&
+		  (!S_ISDIR(le16_to_cpu(node_blk->i.i_mode)) ||
+		   !(c.feature & F2FS_FEATURE_CASEFOLD)))) {
 		ASSERT_MSG("[0x%x] unexpected casefold flag", nid);
 		if (c.fix_on) {
 			FIX_MSG("ino[0x%x] clear casefold flag", nid);
@@ -1077,7 +1113,8 @@ check_next:
 			qf_szchk_type[cur_qtype] = QF_SZCHK_INLINE;
 		block_t blkaddr = le32_to_cpu(node_blk->i.i_addr[ofs]);
 
-		if (blkaddr != NULL_ADDR) {
+		if (time_to_inject(FAULT_INODE) ||
+				(blkaddr != NULL_ADDR)) {
 			ASSERT_MSG("[0x%x] wrong inline reserve blkaddr:%u",
 					nid, blkaddr);
 			if (c.fix_on) {
@@ -1088,7 +1125,8 @@ check_next:
 				need_fix = 1;
 			}
 		}
-		if (i_size > inline_size) {
+		if (time_to_inject(FAULT_INODE) ||
+				(i_size > inline_size)) {
 			ASSERT_MSG("[0x%x] wrong inline size:%lu",
 					nid, (unsigned long)i_size);
 			if (c.fix_on) {
@@ -1118,7 +1156,7 @@ check_next:
 		block_t blkaddr = le32_to_cpu(node_blk->i.i_addr[ofs]);
 
 		DBG(3, "ino[0x%x] has inline dentry!\n", nid);
-		if (blkaddr != 0) {
+		if (time_to_inject(FAULT_INODE) || (blkaddr != 0)) {
 			ASSERT_MSG("[0x%x] wrong inline reserve blkaddr:%u",
 								nid, blkaddr);
 			if (c.fix_on) {
@@ -1728,6 +1766,11 @@ static int f2fs_check_hash_code(int encoding, int casefolded,
 			struct f2fs_dir_entry *dentry,
 			const unsigned char *name, u32 len, int enc_name)
 {
+	if (time_to_inject(FAULT_DENTRY)) {
+		ASSERT_MSG("%s is injected.", f2fs_fault_name[FAULT_DENTRY]);
+		return 1;
+	}
+
 	/* Casefolded Encrypted names require a key to compute siphash */
 	if (enc_name && casefolded)
 		return 0;
@@ -1738,11 +1781,18 @@ static int f2fs_check_hash_code(int encoding, int casefolded,
 		char new[F2FS_PRINT_NAMELEN];
 
 		pretty_print_filename(name, len, new, enc_name);
-		FIX_MSG("Mismatch hash_code for \"%s\" [%x:%x]",
-				new, le32_to_cpu(dentry->hash_code),
-				hash_code);
-		dentry->hash_code = cpu_to_le32(hash_code);
-		return 1;
+
+		ASSERT_MSG("Mismatch hash_code for \"%s\" [%x:%x]",
+					new, le32_to_cpu(dentry->hash_code),
+					hash_code);
+		if (c.fix_on) {
+			FIX_MSG("Fix hash_code for \"%s\" from %x to %x",
+					new, le32_to_cpu(dentry->hash_code),
+					hash_code);
+			dentry->hash_code = cpu_to_le32(hash_code);
+			return 1;
+		}
+		return 0;
 	}
 	return 0;
 }
@@ -1799,7 +1849,8 @@ static int __chk_dots_dentries(struct f2fs_sb_info *sbi,
 	int fixed = 0;
 
 	if ((name[0] == '.' && len == 1)) {
-		if (le32_to_cpu(dentry->ino) != child->p_ino) {
+		if (time_to_inject(FAULT_DENTRY) ||
+				(le32_to_cpu(dentry->ino) != child->p_ino)) {
 			ASSERT_MSG("Bad inode number[0x%x] for '.', parent_ino is [0x%x]\n",
 				le32_to_cpu(dentry->ino), child->p_ino);
 			dentry->ino = cpu_to_le32(child->p_ino);
@@ -1809,13 +1860,16 @@ static int __chk_dots_dentries(struct f2fs_sb_info *sbi,
 
 	if (name[0] == '.' && name[1] == '.' && len == 2) {
 		if (child->p_ino == F2FS_ROOT_INO(sbi)) {
-			if (le32_to_cpu(dentry->ino) != F2FS_ROOT_INO(sbi)) {
+			if (time_to_inject(FAULT_DENTRY) ||
+					(le32_to_cpu(dentry->ino) !=
+					 F2FS_ROOT_INO(sbi))) {
 				ASSERT_MSG("Bad inode number[0x%x] for '..'\n",
 					le32_to_cpu(dentry->ino));
 				dentry->ino = cpu_to_le32(F2FS_ROOT_INO(sbi));
 				fixed = 1;
 			}
-		} else if (le32_to_cpu(dentry->ino) != child->pp_ino) {
+		} else if (time_to_inject(FAULT_DENTRY) ||
+				(le32_to_cpu(dentry->ino) != child->pp_ino)) {
 			ASSERT_MSG("Bad inode number[0x%x] for '..', parent parent ino is [0x%x]\n",
 				le32_to_cpu(dentry->ino), child->pp_ino);
 			dentry->ino = cpu_to_le32(child->pp_ino);
@@ -1826,7 +1880,7 @@ static int __chk_dots_dentries(struct f2fs_sb_info *sbi,
 	if (f2fs_check_hash_code(get_encoding(sbi), casefolded, dentry, name, len, enc_name))
 		fixed = 1;
 
-	if (name[len] != '\0') {
+	if (time_to_inject(FAULT_DENTRY) || (name[len] != '\0')) {
 		ASSERT_MSG("'.' is not NULL terminated\n");
 		name[len] = '\0';
 		memcpy(*filename, name, len);
@@ -1889,7 +1943,8 @@ static int __chk_dentries(struct f2fs_sb_info *sbi, int casefolded,
 			i++;
 			continue;
 		}
-		if (!IS_VALID_NID(sbi, le32_to_cpu(dentry[i].ino))) {
+		if (time_to_inject(FAULT_DENTRY) ||
+				!IS_VALID_NID(sbi, le32_to_cpu(dentry[i].ino))) {
 			ASSERT_MSG("Bad dentry 0x%x with invalid NID/ino 0x%x",
 				    i, le32_to_cpu(dentry[i].ino));
 			if (c.fix_on) {
@@ -1903,7 +1958,9 @@ static int __chk_dentries(struct f2fs_sb_info *sbi, int casefolded,
 		}
 
 		ftype = dentry[i].file_type;
-		if ((ftype <= F2FS_FT_UNKNOWN || ftype > F2FS_FT_LAST_FILE_TYPE)) {
+		if (time_to_inject(FAULT_DENTRY) ||
+				(ftype <= F2FS_FT_UNKNOWN ||
+				 ftype > F2FS_FT_LAST_FILE_TYPE)) {
 			ASSERT_MSG("Bad dentry 0x%x with unexpected ftype 0x%x",
 						le32_to_cpu(dentry[i].ino), ftype);
 			if (c.fix_on) {
@@ -1918,7 +1975,8 @@ static int __chk_dentries(struct f2fs_sb_info *sbi, int casefolded,
 
 		name_len = le16_to_cpu(dentry[i].name_len);
 
-		if (name_len == 0 || name_len > F2FS_NAME_LEN) {
+		if (time_to_inject(FAULT_DENTRY) ||
+				(name_len == 0 || name_len > F2FS_NAME_LEN)) {
 			ASSERT_MSG("Bad dentry 0x%x with invalid name_len", i);
 			if (c.fix_on) {
 				FIX_MSG("Clear bad dentry 0x%x", i);
@@ -2153,6 +2211,11 @@ int fsck_chk_data_blk(struct f2fs_sb_info *sbi, struct f2fs_inode *inode,
 		return 0;
 	}
 
+	if (time_to_inject(FAULT_DATA)) {
+		ASSERT_MSG("%s is injected.", f2fs_fault_name[FAULT_DATA]);
+		return -EINVAL;
+	}
+
 	if (!f2fs_is_valid_blkaddr(sbi, blk_addr, DATA_GENERIC)) {
 		ASSERT_MSG("blkaddress is not valid. [0x%x]", blk_addr);
 		return -EINVAL;
@@ -2357,6 +2420,44 @@ int fsck_chk_quota_files(struct f2fs_sb_info *sbi)
 	return ret;
 }
 
+void fsck_update_sb_flags(struct f2fs_sb_info *sbi)
+{
+	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
+	u16 flags = get_sb(s_encoding_flags);
+
+	if (c.nolinear_lookup == LINEAR_LOOKUP_DEFAULT) {
+		MSG(0, "Info: Casefold: linear_lookup [%s]\n",
+			get_sb(s_encoding_flags) & F2FS_ENC_NO_COMPAT_FALLBACK_FL ?
+			"disable" : "enable");
+		return;
+	}
+
+	MSG(0, "Info: linear_lookup option: %s\n",
+			c.nolinear_lookup == LINEAR_LOOKUP_DISABLE ?
+			"disable" : "enable");
+
+	if (!(get_sb(feature) & F2FS_FEATURE_CASEFOLD)) {
+		MSG(0, "Info: Not support Casefold feature\n");
+		return;
+	}
+
+	if (c.nolinear_lookup == LINEAR_LOOKUP_DISABLE) {
+		if (!(flags & F2FS_ENC_NO_COMPAT_FALLBACK_FL)) {
+			flags |= F2FS_ENC_NO_COMPAT_FALLBACK_FL;
+			set_sb(s_encoding_flags, flags);
+			MSG(0, "Info: Casefold: disable linear lookup\n");
+			update_superblock(sbi->raw_super, SB_MASK_ALL);
+		}
+	} else if (c.nolinear_lookup == LINEAR_LOOKUP_ENABLE) {
+		if (flags & F2FS_ENC_NO_COMPAT_FALLBACK_FL) {
+			flags &= ~F2FS_ENC_NO_COMPAT_FALLBACK_FL;
+			set_sb(s_encoding_flags, flags);
+			MSG(0, "Info: Casefold: enable linear lookup\n");
+			update_superblock(sbi->raw_super, SB_MASK_ALL);
+		}
+	}
+}
+
 int fsck_chk_meta(struct f2fs_sb_info *sbi)
 {
 	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
@@ -3540,6 +3641,19 @@ int fsck_chk_curseg_info(struct f2fs_sb_info *sbi)
 	return ret;
 }
 
+void print_fault_cnt(struct f2fs_fault_info *ffi)
+{
+	int i;
+
+	printf("[Fault injection result]\n");
+	for (i = 0; i < FAULT_MAX; i++) {
+		printf("%s: %u", f2fs_fault_name[i], ffi->fault_cnt[i]);
+		if (i < FAULT_MAX - 1)
+			printf(", ");
+	}
+	printf("\n");
+}
+
 int fsck_verify(struct f2fs_sb_info *sbi)
 {
 	unsigned int i = 0;
@@ -3548,12 +3662,16 @@ int fsck_verify(struct f2fs_sb_info *sbi)
 	u32 nr_unref_nid = 0;
 	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
 	struct hard_link_node *node = NULL;
+	struct f2fs_fault_info *ffi = &c.fault_info;
 	bool verify_failed = false;
 	uint64_t max_blks, data_secs, node_secs, free_blks;
 
 	if (c.show_file_map)
 		return 0;
 
+	if (ffi->inject_rate)
+		print_fault_cnt(ffi);
+
 	printf("\n");
 
 	if (c.zoned_model == F2FS_ZONED_HM) {
@@ -3770,7 +3888,7 @@ int fsck_verify(struct f2fs_sb_info *sbi)
 		if (c.invalid_sb & SB_FS_ERRORS)
 			memset(sb->s_errors, 0, MAX_F2FS_ERRORS);
 
-		if (c.invalid_sb & SB_NEED_FIX)
+		if (c.invalid_sb & (SB_NEED_FIX | SB_ENCODE_FLAG))
 			update_superblock(sb, SB_MASK_ALL);
 
 		/* to return FSCK_ERROR_CORRECTED */
diff --git a/fsck/fsck.h b/fsck/fsck.h
index b581d3e..40cb6d9 100644
--- a/fsck/fsck.h
+++ b/fsck/fsck.h
@@ -188,6 +188,7 @@ extern int fsck_chk_dentry_blk(struct f2fs_sb_info *, int,
 int fsck_chk_inline_dentries(struct f2fs_sb_info *, struct f2fs_node *,
 		struct child_info *);
 void fsck_chk_checkpoint(struct f2fs_sb_info *sbi);
+void fsck_update_sb_flags(struct f2fs_sb_info *sbi);
 int fsck_chk_meta(struct f2fs_sb_info *sbi);
 void fsck_chk_and_fix_write_pointers(struct f2fs_sb_info *);
 int fsck_chk_curseg_info(struct f2fs_sb_info *);
diff --git a/fsck/main.c b/fsck/main.c
index 47ba6c9..c5d4159 100644
--- a/fsck/main.c
+++ b/fsck/main.c
@@ -91,6 +91,9 @@ void fsck_usage()
 	MSG(0, "  --no-kernel-check skips detecting kernel change\n");
 	MSG(0, "  --kernel-check checks kernel change\n");
 	MSG(0, "  --debug-cache to debug cache when -c is used\n");
+	MSG(0, "  --nolinear-lookup=X X=1: disable linear lookup, X=0: enable linear lookup\n");
+	MSG(0, "  --fault_injection=%%d to enable fault injection with specified injection rate\n");
+	MSG(0, "  --fault_type=%%d to configure enabled fault injection type\n");
 	exit(1);
 }
 
@@ -140,7 +143,6 @@ void resize_usage()
 	MSG(0, "[options]:\n");
 	MSG(0, "  -d debug level [default:0]\n");
 	MSG(0, "  -H support write hint\n");
-	MSG(0, "  -i extended node bitmap, node ratio is 20%% by default\n");
 	MSG(0, "  -o overprovision percentage [default:auto]\n");
 	MSG(0, "  -s safe resize (Does not resize metadata)\n");
 	MSG(0, "  -t target sectors [default: device size]\n");
@@ -222,6 +224,8 @@ static void add_default_options(void)
 		if (c.func == FSCK) {
 			/* -a */
 			c.auto_fix = 1;
+		} else if (c.func == RESIZE) {
+			c.force = 1;
 		}
 
 		/*
@@ -231,6 +235,10 @@ static void add_default_options(void)
 
 		/* disable nat_bits feature by default */
 		c.disabled_feature |= F2FS_FEATURE_NAT_BITS;
+
+		/* enable write hitn by default */
+		c.need_whint = true;
+		c.whint = WRITE_LIFE_NOT_SET;
 	}
 	c.quota_fix = 1;
 }
@@ -263,6 +271,9 @@ void f2fs_parse_options(int argc, char *argv[])
 			{"no-kernel-check", no_argument, 0, 2},
 			{"kernel-check", no_argument, 0, 3},
 			{"debug-cache", no_argument, 0, 4},
+			{"nolinear-lookup", required_argument, 0, 5},
+			{"fault_injection", required_argument, 0, 6},
+			{"fault_type", required_argument, 0, 7},
 			{0, 0, 0, 0}
 		};
 
@@ -287,6 +298,30 @@ void f2fs_parse_options(int argc, char *argv[])
 			case 4:
 				c.cache_config.dbg_en = true;
 				break;
+			case 5:
+				if (!optarg || !strcmp(optarg, "0"))
+					c.nolinear_lookup = LINEAR_LOOKUP_ENABLE;
+				else
+					c.nolinear_lookup = LINEAR_LOOKUP_DISABLE;
+				break;
+			case 6:
+				val = atoi(optarg);
+				if ((unsigned int)val <= 1) {
+					MSG(0, "\tError: injection rate must be larger "
+							"than 1: %d\n", val);
+					fsck_usage();
+				}
+				c.fault_info.inject_rate = val;
+				c.fault_info.inject_type = F2FS_ALL_FAULT_TYPE;
+				break;
+			case 7:
+				val = atoi(optarg);
+				if (val >= (1UL << (FAULT_MAX))) {
+					MSG(0, "\tError: Invalid inject type: %x\n", val);
+					fsck_usage();
+				}
+				c.fault_info.inject_type = val;
+				break;
 			case 'a':
 				c.auto_fix = 1;
 				MSG(0, "Info: Automatic fix mode enabled.\n");
@@ -594,7 +629,7 @@ void f2fs_parse_options(int argc, char *argv[])
 #endif
 	} else if (!strcmp("resize.f2fs", prog)) {
 #ifdef WITH_RESIZE
-		const char *option_string = "d:fHst:io:V";
+		const char *option_string = "d:fFHst:o:V";
 
 		c.func = RESIZE;
 		while ((option = getopt(argc, argv, option_string)) != EOF) {
@@ -611,6 +646,10 @@ void f2fs_parse_options(int argc, char *argv[])
 							c.dbg_lv);
 				break;
 			case 'f':
+				c.ignore_error = 1;
+				MSG(0, "Info: Ignore errors during resize\n");
+				break;
+			case 'F':
 				c.force = 1;
 				MSG(0, "Info: Force to resize\n");
 				break;
@@ -629,9 +668,6 @@ void f2fs_parse_options(int argc, char *argv[])
 					ret = sscanf(optarg, "%"PRIx64"",
 							&c.target_sectors);
 				break;
-			case 'i':
-				c.large_nat_bitmap = 1;
-				break;
 			case 'o':
 				c.new_overprovision = atof(optarg);
 				break;
@@ -1098,6 +1134,23 @@ out_range:
 #ifdef WITH_RESIZE
 static int do_resize(struct f2fs_sb_info *sbi)
 {
+	char answer[255] = {0};
+	int ret;
+
+	if (!c.force) {
+retry:
+		printf("\nResize operation is currently experimental, please "
+			"backup your data.\nDo you want to continue? [y/n]");
+		ret = scanf("%s", answer);
+		ASSERT(ret >= 0);
+		if (!strcasecmp(answer, "y"))
+			printf("Proceeding to resize\n");
+		else if (!strcasecmp(answer, "n"))
+			return 0;
+		else
+			goto retry;
+	}
+
 	if (!c.target_sectors)
 		c.target_sectors = c.total_sectors;
 
diff --git a/fsck/mkquota.c b/fsck/mkquota.c
index 2451b58..3f491d7 100644
--- a/fsck/mkquota.c
+++ b/fsck/mkquota.c
@@ -372,6 +372,11 @@ errcode_t quota_compare_and_update(struct f2fs_sb_info *sbi,
 	dict_t *dict = qctx->quota_dict[qtype];
 	errcode_t err = 0;
 
+	if (time_to_inject(FAULT_QUOTA)) {
+		ASSERT_MSG("%s is injected.", f2fs_fault_name[FAULT_QUOTA]);
+		return -EINVAL;
+	}
+
 	if (!dict)
 		goto out;
 
diff --git a/fsck/mount.c b/fsck/mount.c
index 0b05f00..a7f16e7 100644
--- a/fsck/mount.c
+++ b/fsck/mount.c
@@ -555,6 +555,7 @@ printout:
 	DISP_u32(sb, qf_ino[PRJQUOTA]);
 
 	DISP_u16(sb, s_encoding);
+	DISP_u16(sb, s_encoding_flags);
 	DISP_u32(sb, crc);
 
 	print_sb_debug_info(sb);
@@ -562,6 +563,33 @@ printout:
 	printf("\n");
 }
 
+void print_chksum(struct f2fs_checkpoint *cp)
+{
+	unsigned int crc = le32_to_cpu(*(__le32 *)((unsigned char *)cp +
+						get_cp(checksum_offset)));
+
+	printf("%-30s" "\t\t[0x%8x : %u]\n", "checksum", crc, crc);
+}
+
+void print_version_bitmap(struct f2fs_sb_info *sbi)
+{
+	char str[41];
+	int i, j;
+
+	for (i = NAT_BITMAP; i <= SIT_BITMAP; i++) {
+		unsigned int *bitmap = __bitmap_ptr(sbi, i);
+		unsigned int size = round_up(__bitmap_size(sbi, i), 4);
+
+		for (j = 0; j < size; j++) {
+			snprintf(str, 40, "%s[%d]", i == NAT_BITMAP ?
+						"nat_version_bitmap" :
+						"sit_version_bitmap", j);
+			printf("%-30s" "\t\t[0x%8x : %u]\n", str,
+						bitmap[i], bitmap[i]);
+		}
+	}
+}
+
 void print_ckpt_info(struct f2fs_sb_info *sbi)
 {
 	struct f2fs_checkpoint *cp = F2FS_CKPT(sbi);
@@ -617,7 +645,9 @@ printout:
 	DISP_u32(cp, checksum_offset);
 	DISP_u64(cp, elapsed_time);
 
-	DISP_u32(cp, sit_nat_version_bitmap[0]);
+	print_chksum(cp);
+	print_version_bitmap(sbi);
+
 	printf("\n\n");
 }
 
@@ -699,6 +729,7 @@ static char *stop_reason_str[] = {
 	[STOP_CP_REASON_UPDATE_INODE]		= "update_inode",
 	[STOP_CP_REASON_FLUSH_FAIL]		= "flush_fail",
 	[STOP_CP_REASON_NO_SEGMENT]		= "no_segment",
+	[STOP_CP_REASON_CORRUPTED_FREE_BITMAP]	= "corrupted_free_bitmap",
 };
 
 void print_sb_stop_reason(struct f2fs_super_block *sb)
@@ -4086,6 +4117,8 @@ int f2fs_do_mount(struct f2fs_sb_info *sbi)
 			update_superblock(sbi->raw_super, SB_MASK_ALL);
 		}
 #else
+		fsck_update_sb_flags(sbi);
+
 		if (!c.no_kernel_check) {
 			u32 prev_time, cur_time, time_diff;
 			__le32 *ver_ts_ptr = (__le32 *)(sbi->raw_super->version
diff --git a/fsck/resize.c b/fsck/resize.c
index 9b3b071..58914ec 100644
--- a/fsck/resize.c
+++ b/fsck/resize.c
@@ -531,9 +531,6 @@ static void rebuild_checkpoint(struct f2fs_sb_info *sbi,
 
 	/* update nat_bits flag */
 	flags = update_nat_bits_flags(new_sb, cp, get_cp(ckpt_flags));
-	if (c.large_nat_bitmap)
-		flags |= CP_LARGE_NAT_BITMAP_FLAG;
-
 	if (flags & CP_COMPACT_SUM_FLAG)
 		flags &= ~CP_COMPACT_SUM_FLAG;
 	if (flags & CP_LARGE_NAT_BITMAP_FLAG)
@@ -759,18 +756,22 @@ int f2fs_resize(struct f2fs_sb_info *sbi)
 
 	/* may different sector size */
 	if ((c.target_sectors * c.sector_size >>
-			get_sb(log_blocksize)) < get_sb(block_count))
+			get_sb(log_blocksize)) < get_sb(block_count)) {
 		if (!c.safe_resize) {
 			ASSERT_MSG("Nothing to resize, now only supports resizing with safe resize flag\n");
 			return -1;
 		} else {
 			return f2fs_resize_shrink(sbi);
 		}
-	else if (((c.target_sectors * c.sector_size >>
+	} else if (((c.target_sectors * c.sector_size >>
 			get_sb(log_blocksize)) > get_sb(block_count)) ||
-			c.force)
+			c.ignore_error) {
+		if (c.safe_resize) {
+			ASSERT_MSG("Expanding resize doesn't support safe resize flag");
+			return -1;
+		}
 		return f2fs_resize_grow(sbi);
-	else {
+	} else {
 		MSG(0, "Nothing to resize.\n");
 		return 0;
 	}
diff --git a/include/f2fs_fs.h b/include/f2fs_fs.h
index bb40adc..f7268d1 100644
--- a/include/f2fs_fs.h
+++ b/include/f2fs_fs.h
@@ -29,6 +29,7 @@
 #include <string.h>
 #include <time.h>
 #include <stdbool.h>
+#include <limits.h>
 
 #ifdef HAVE_CONFIG_H
 #include <config.h>
@@ -682,7 +683,8 @@ enum {
 #define IS_DEVICE_ALIASING(fi)	((fi)->i_flags & cpu_to_le32(F2FS_DEVICE_ALIAS_FL))
 
 #define F2FS_ENC_UTF8_12_1	1
-#define F2FS_ENC_STRICT_MODE_FL	(1 << 0)
+#define F2FS_ENC_STRICT_MODE_FL		(1 << 0)
+#define F2FS_ENC_NO_COMPAT_FALLBACK_FL	(1 << 1)
 
 /* This flag is used by node and meta inodes, and by recovery */
 #define GFP_F2FS_ZERO	(GFP_NOFS | __GFP_ZERO)
@@ -738,6 +740,7 @@ enum stop_cp_reason {
 	STOP_CP_REASON_UPDATE_INODE,
 	STOP_CP_REASON_FLUSH_FAIL,
 	STOP_CP_REASON_NO_SEGMENT,
+	STOP_CP_REASON_CORRUPTED_FREE_BITMAP,
 	STOP_CP_REASON_MAX,
 };
 
@@ -1467,7 +1470,9 @@ enum {
 #define SB_ABNORMAL_STOP	0x2	/* s_stop_reason is set except shutdown */
 #define SB_FS_ERRORS		0x4	/* s_erros is set */
 #define SB_INVALID		0x8	/* sb is invalid */
-#define SB_NEED_FIX (SB_ABNORMAL_STOP | SB_FS_ERRORS | SB_INVALID)
+#define SB_ENCODE_FLAG		0x16	/* encode_flag */
+#define SB_NEED_FIX		(SB_ABNORMAL_STOP | SB_FS_ERRORS |	\
+				SB_INVALID | SB_ENCODE_FLAG)
 
 #define MAX_CACHE_SUMS			8
 
@@ -1476,6 +1481,41 @@ enum {
 	F2FS_FEATURE_NAT_BITS = 0x0001,
 };
 
+/* nolinear lookup tune */
+enum {
+	LINEAR_LOOKUP_DEFAULT = 0,
+	LINEAR_LOOKUP_ENABLE,
+	LINEAR_LOOKUP_DISABLE,
+};
+
+/* Fault inject control */
+enum {
+	FAULT_SEG_TYPE,
+	FAULT_SUM_TYPE,
+	FAULT_SUM_ENT,
+	FAULT_NAT,
+	FAULT_NODE,
+	FAULT_XATTR_ENT,
+	FAULT_COMPR,
+	FAULT_INODE,
+	FAULT_DENTRY,
+	FAULT_DATA,
+	FAULT_QUOTA,
+	FAULT_MAX
+};
+
+#define F2FS_ALL_FAULT_TYPE	((1UL << (FAULT_MAX)) - 1)
+
+struct f2fs_fault_info {
+	int inject_ops;
+	int inject_rate;
+	unsigned int inject_type;
+	unsigned int fault_cnt[FAULT_MAX];
+};
+
+extern const char *f2fs_fault_name[FAULT_MAX];
+#define IS_FAULT_SET(fi, type) ((fi)->inject_type & (1UL << (type)))
+
 struct f2fs_configuration {
 	uint32_t conf_reserved_sections;
 	uint32_t reserved_segments;
@@ -1525,6 +1565,7 @@ struct f2fs_configuration {
 	int no_kernel_check;
 	int fix_on;
 	int force;
+	int ignore_error;
 	int defset;
 	int bug_on;
 	unsigned int invalid_sb;
@@ -1541,6 +1582,7 @@ struct f2fs_configuration {
 	int preserve_limits;		/* preserve quota limits */
 	int large_nat_bitmap;
 	int fix_chksum;			/* fix old cp.chksum position */
+	int nolinear_lookup;		/* disable linear lookup */
 	unsigned int feature;			/* defined features */
 	unsigned int disabled_feature;	/* disabled feature, used for Android only */
 	unsigned int quota_bits;	/* quota bits */
@@ -1604,13 +1646,16 @@ struct f2fs_configuration {
 		struct f2fs_journal nat_jnl;
 		char nat_bytes[F2FS_MAX_BLKSIZE];
 	};
+
+	/* Fault injection control */
+	struct f2fs_fault_info fault_info;
 };
 
 extern int utf8_to_utf16(char *, const char *, size_t, size_t);
 extern int utf16_to_utf8(char *, const char *, size_t, size_t);
 extern int log_base_2(uint32_t);
 extern unsigned int addrs_per_page(struct f2fs_inode *, bool);
-extern unsigned int f2fs_max_file_offset(struct f2fs_inode *);
+extern u64 f2fs_max_file_offset(struct f2fs_inode *);
 extern __u32 f2fs_inode_chksum(struct f2fs_node *);
 extern __u32 f2fs_checkpoint_chksum(struct f2fs_checkpoint *);
 extern int write_inode(struct f2fs_node *, u64, enum rw_hint);
@@ -2131,4 +2176,30 @@ static inline void check_block_struct_sizes(void)
 			+ NR_DENTRY_IN_BLOCK * F2FS_SLOT_LEN * sizeof(u8) == F2FS_BLKSIZE);
 }
 
+/* Fault inject control */
+#define time_to_inject(type) __time_to_inject(type, __func__, \
+					__builtin_return_address(0))
+static inline bool __time_to_inject(int type, const char *func,
+		const char *parent_func)
+{
+	struct f2fs_fault_info *ffi = &c.fault_info;
+
+	if (!ffi->inject_rate)
+		return false;
+
+	if (!IS_FAULT_SET(ffi, type))
+		return false;
+
+	ffi->inject_ops++;
+	if (ffi->inject_ops >= ffi->inject_rate) {
+		ffi->inject_ops = 0;
+		if (ffi->fault_cnt[type] != UINT_MAX)
+			ffi->fault_cnt[type]++;
+		MSG(0, "inject %s in %s of %p\n",
+				f2fs_fault_name[type], func, parent_func);
+		return true;
+	}
+	return false;
+}
+
 #endif	/*__F2FS_FS_H */
diff --git a/lib/libf2fs.c b/lib/libf2fs.c
index ecd22d4..d2579d7 100644
--- a/lib/libf2fs.c
+++ b/lib/libf2fs.c
@@ -527,7 +527,7 @@ unsigned int addrs_per_page(struct f2fs_inode *i, bool is_inode)
 	return ALIGN_DOWN(addrs, 1 << i->i_log_cluster_size);
 }
 
-unsigned int f2fs_max_file_offset(struct f2fs_inode *i)
+u64 f2fs_max_file_offset(struct f2fs_inode *i)
 {
 	if (!LINUX_S_ISREG(le16_to_cpu(i->i_mode)) ||
 			!(le32_to_cpu(i->i_flags) & F2FS_COMPR_FL))
diff --git a/lib/libf2fs_zoned.c b/lib/libf2fs_zoned.c
index 89ba5ad..6730bba 100644
--- a/lib/libf2fs_zoned.c
+++ b/lib/libf2fs_zoned.c
@@ -539,6 +539,14 @@ uint32_t f2fs_get_usable_segments(struct f2fs_super_block *sb)
 		return get_sb(segment_count_main);
 
 	for (i = 0; i < c.ndevs; i++) {
+		/*
+		 * for the case: there is only one host managed device, and
+		 * the device has both convential zones and sequential zones.
+		 */
+		if (c.ndevs == 1) {
+			usable_segs += c.devices[i].total_segments;
+			break;
+		}
 		if (c.devices[i].zoned_model != F2FS_ZONED_HM) {
 			usable_segs += c.devices[i].total_segments;
 			continue;
diff --git a/man/fsck.f2fs.8 b/man/fsck.f2fs.8
index e39a846..89cc455 100644
--- a/man/fsck.f2fs.8
+++ b/man/fsck.f2fs.8
@@ -67,6 +67,45 @@ Enable to show every directory entries in the partition.
 Specify the level of debugging options.
 The default number is 0, which shows basic debugging messages.
 .TP
+.BI \--nolinear-lookup
+Tune linear lookup fallback, must specify an argument, 0: enable linear lookup, 1: disable linear lookup.
+.TP
+.BI \-\-fault_injection=%d " enable fault injection"
+Enable fault injection in all supported types with specified injection rate.
+.TP
+.BI \-\-fault_type=%d " configure fault injection type"
+Support configuring fault injection type, should be enabled with
+fault_injection option, fault type value is shown below, it supports
+single or combined type.
+.br
+===========================      ===========
+.br
+Type_Name                        Type_Value
+.br
+===========================      ===========
+.br
+FAULT_SEG_TYPE                   0x00000001
+.br
+FAULT_SUM_TYPE                   0x00000002
+.br
+FAULT_SUM_ENT                    0x00000004
+.br
+FAULT_NAT                        0x00000008
+.br
+FAULT_NODE                       0x00000010
+.br
+FAULT_XATTR_ENT                  0x00000020
+.br
+FAULT_COMPR                      0x00000040
+.br
+FAULT_INODE                      0x00000080
+.br
+FAULT_DENTRY                     0x00000100
+.br
+FAULT_DATA                       0x00000200
+.br
+FAULT_QUOTA                      0x00000400
+.TP
 .SH AUTHOR
 Initial checking code was written by Byoung Geun Kim <bgbg.kim@samsung.com>.
 Jaegeuk Kim <jaegeuk@kernel.org> reworked most parts of the codes to support
diff --git a/man/resize.f2fs.8 b/man/resize.f2fs.8
index d41ad79..5b6daf5 100644
--- a/man/resize.f2fs.8
+++ b/man/resize.f2fs.8
@@ -18,10 +18,13 @@ resize.f2fs \- resize filesystem size
 .I overprovision-ratio-percentage
 ]
 [
-.B \-H
+.B \-f
+]
+[
+.B \-F
 ]
 [
-.B \-i
+.B \-H
 ]
 [
 .B \-s
@@ -56,14 +59,17 @@ Specify the percentage of the volume that will be used as overprovision area.
 This area is hidden to users, and utilized by F2FS cleaner. If not specified, the
 best number will be assigned automatically according to the partition size.
 .TP
+.BI \-f
+Force to fix any inconsistent data during resize.
+.TP
+.BI \-F
+Skip caution dialogue and resize partition directly.
+.TP
 .BI \-H
 Specify support write hint.
 .TP
-.BI \-i
-Enable extended node bitmap.
-.TP
 .BI \-s
-Enable safe resize.
+Enable safe resize, it can only be used w/ shrink resize.
 .TP
 .BI \-V
 Print the version number and exit.
diff --git a/mkfs/f2fs_format.c b/mkfs/f2fs_format.c
index c28ebb0..2680bd3 100644
--- a/mkfs/f2fs_format.c
+++ b/mkfs/f2fs_format.c
@@ -1012,10 +1012,9 @@ static int f2fs_write_check_point_pack(void)
 	memcpy(sum_compact_p, &journal->n_sits, SUM_JOURNAL_SIZE);
 	sum_compact_p += SUM_JOURNAL_SIZE;
 
-	/* hot data summary */
-	memset(sum, 0, F2FS_BLKSIZE);
-	SET_SUM_TYPE(sum, SUM_TYPE_DATA);
+	SET_SUM_TYPE((struct f2fs_summary_block *)sum_compact, SUM_TYPE_DATA);
 
+	/* hot data summary */
 	sum_entry = (struct f2fs_summary *)sum_compact_p;
 	memcpy(sum_entry, c.sum[CURSEG_HOT_DATA],
 			sizeof(struct f2fs_summary) * MAX_CACHE_SUMS);
diff --git a/mkfs/f2fs_format_main.c b/mkfs/f2fs_format_main.c
index 5b4569d..3a8fde0 100644
--- a/mkfs/f2fs_format_main.c
+++ b/mkfs/f2fs_format_main.c
@@ -156,6 +156,10 @@ static void add_default_options(void)
 		c.feature |= F2FS_FEATURE_PRJQUOTA;
 		c.feature |= F2FS_FEATURE_EXTRA_ATTR;
 		c.feature |= F2FS_FEATURE_VERITY;
+
+		/* enable write hitn by default */
+		c.need_whint = true;
+		c.whint = WRITE_LIFE_NOT_SET;
 		break;
 	}
 #ifdef CONF_CASEFOLD
diff --git a/tools/f2fs_io/f2fs_io.c b/tools/f2fs_io/f2fs_io.c
index 57a931d..292dcb3 100644
--- a/tools/f2fs_io/f2fs_io.c
+++ b/tools/f2fs_io/f2fs_io.c
@@ -769,24 +769,30 @@ static void do_write_with_advice(int argc, char **argv,
 		}
 	}
 
+	total_time = get_current_us();
 	if (atomic_commit || atomic_abort) {
 		int ret;
 
 		if (argc == 8)
-			useconds = atoi(argv[7]) * 1000;
+			useconds = atoi(argv[7]) * 1000 / (count + 2);
+
+		if (useconds)
+			usleep(useconds);
 
 		if (replace)
 			ret = ioctl(fd, F2FS_IOC_START_ATOMIC_REPLACE);
 		else
 			ret = ioctl(fd, F2FS_IOC_START_ATOMIC_WRITE);
 
+		if (useconds)
+			usleep(useconds);
+
 		if (ret < 0) {
 			fputs("setting atomic file mode failed\n", stderr);
 			exit(1);
 		}
 	}
 
-	total_time = get_current_us();
 	for (i = 0; i < count; i++) {
 		uint64_t ret;
 
@@ -804,10 +810,10 @@ static void do_write_with_advice(int argc, char **argv,
 		if (ret != buf_size)
 			break;
 		written += ret;
-	}
 
-	if (useconds)
-		usleep(useconds);
+		if (useconds)
+			usleep(useconds);
+	}
 
 	if (atomic_commit) {
 		int ret;
```

